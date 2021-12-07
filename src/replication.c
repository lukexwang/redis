/* Asynchronous replication implementation.
 *
 * Copyright (c) 2009-2012, Salvatore Sanfilippo <antirez at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */


#include "server.h"
#include "cluster.h"
#include "bio.h"

#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>

void replicationDiscardCachedMaster(void);
void replicationResurrectCachedMaster(connection *conn);
void replicationSendAck(void);
void putSlaveOnline(client *slave);
int cancelReplicationHandshake(int reconnect);

/* We take a global flag to remember if this instance generated an RDB
 * because of replication, so that we can remove the RDB file in case
 * the instance is configured to have no persistence. */
int RDBGeneratedByReplication = 0;

/* --------------------------- Utility functions ---------------------------- */

/* Return the pointer to a string representing the slave ip:listening_port
 * pair. Mostly useful for logging, since we want to log a slave using its
 * IP address and its listening port which is more clear for the user, for
 * example: "Closing connection with replica 10.1.2.3:6380". */
char *replicationGetSlaveName(client *c) {
    static char buf[NET_HOST_PORT_STR_LEN];
    char ip[NET_IP_STR_LEN];

    ip[0] = '\0';
    buf[0] = '\0';
    if (c->slave_addr ||
        connPeerToString(c->conn,ip,sizeof(ip),NULL) != -1)
    {
        char *addr = c->slave_addr ? c->slave_addr : ip;
        if (c->slave_listening_port)
            anetFormatAddr(buf,sizeof(buf),addr,c->slave_listening_port);
        else
            snprintf(buf,sizeof(buf),"%s:<unknown-replica-port>",addr);
    } else {
        snprintf(buf,sizeof(buf),"client id #%llu",
            (unsigned long long) c->id);
    }
    return buf;
}

/* Plain unlink() can block for quite some time in order to actually apply
 * the file deletion to the filesystem. This call removes the file in a
 * background thread instead. We actually just do close() in the thread,
 * by using the fact that if there is another instance of the same file open,
 * the foreground unlink() will only remove the fs name, and deleting the
 * file's storage space will only happen once the last reference is lost. */
int bg_unlink(const char *filename) {
    int fd = open(filename,O_RDONLY|O_NONBLOCK);
    if (fd == -1) {
        /* Can't open the file? Fall back to unlinking in the main thread. */
        return unlink(filename);
    } else {
        /* The following unlink() removes the name but doesn't free the
         * file contents because a process still has it open. */
        int retval = unlink(filename);
        if (retval == -1) {
            /* If we got an unlink error, we just return it, closing the
             * new reference we have to the file. */
            int old_errno = errno;
            close(fd);  /* This would overwrite our errno. So we saved it. */
            errno = old_errno;
            return -1;
        }
        bioCreateCloseJob(fd);
        return 0; /* Success. */
    }
}

/* ---------------------------------- MASTER -------------------------------- */

void createReplicationBacklog(void) {
    serverAssert(server.repl_backlog == NULL);
    server.repl_backlog = zmalloc(server.cfg_repl_backlog_size);
    server.repl_backlog_size = zmalloc_usable_size(server.repl_backlog);
    server.repl_backlog_histlen = 0;
    server.repl_backlog_idx = 0;

    /* We don't have any data inside our buffer, but virtually the first
     * byte we have is the next byte that will be generated for the
     * replication stream. */
    server.repl_backlog_off = server.master_repl_offset+1;
}

/* This function is called when the user modifies the replication backlog
 * size at runtime. It is up to the function to both update the
 * server.cfg_repl_backlog_size and to resize the buffer and setup it so that
 * it contains the same data as the previous one (possibly less data, but
 * the most recent bytes, or the same data and more free space in case the
 * buffer is enlarged). */
void resizeReplicationBacklog(long long newsize) {
    if (newsize < CONFIG_REPL_BACKLOG_MIN_SIZE)
        newsize = CONFIG_REPL_BACKLOG_MIN_SIZE;
    if (server.cfg_repl_backlog_size == newsize) return;

    server.cfg_repl_backlog_size = newsize;
    if (server.repl_backlog != NULL) {
        /* What we actually do is to flush the old buffer and realloc a new
         * empty one. It will refill with new data incrementally.
         * The reason is that copying a few gigabytes adds latency and even
         * worse often we need to alloc additional space before freeing the
         * old buffer. */
        zfree(server.repl_backlog);
        server.repl_backlog = zmalloc(server.cfg_repl_backlog_size);
        server.repl_backlog_size = zmalloc_usable_size(server.repl_backlog);
        server.repl_backlog_histlen = 0;
        server.repl_backlog_idx = 0;
        /* Next byte we have is... the next since the buffer is empty. */
        server.repl_backlog_off = server.master_repl_offset+1;
    }
}

void freeReplicationBacklog(void) {
    serverAssert(listLength(server.slaves) == 0);
    zfree(server.repl_backlog);
    server.repl_backlog = NULL;
}

/* Add data to the replication backlog.
 * This function also increments the global replication offset stored at
 * server.master_repl_offset, because there is no case where we want to feed
 * the backlog without incrementing the offset. */
void feedReplicationBacklog(void *ptr, size_t len) {
    unsigned char *p = ptr;

    server.master_repl_offset += len;

    /* This is a circular buffer, so write as much data we can at every
     * iteration and rewind the "idx" index if we reach the limit. 
     * server.repl_backlog是一个循环缓存. 所以每次轮询都尽可能多的写数据 同时 轮询idx;
     * 
     * server.master_repl_offset 只会一直不断增,master的复制偏移量;
     * server.repl_backlog_off 代表repl_backlog缓冲区保存数据的最小的offset,这里是offset的最小值,server.master_repl_offset是最大值;
     *  随着server.master_repl_offset一起持续增大,repl_backlog[server.repl_backlog_off]是没意义的;
     * server.repl_backlog_size 代表repl_backlog缓冲区的大小;
     * server.repl_backlog_histlen 代表repl_backlog缓冲区中保存的数据大小;
     * server.repl_backlog_idx 代表repl_backlog缓冲区中下一个字节的存储位置;
     * 
     * server.repl_backlog_off=server.master_repl_offset-server.repl_backlog_histlen+1;
     */
    while(len) {
        size_t thislen = server.repl_backlog_size - server.repl_backlog_idx;
        if (thislen > len) thislen = len;
        memcpy(server.repl_backlog+server.repl_backlog_idx,p,thislen);
        server.repl_backlog_idx += thislen;
        if (server.repl_backlog_idx == server.repl_backlog_size)
            server.repl_backlog_idx = 0;
        len -= thislen;
        p += thislen;
        server.repl_backlog_histlen += thislen;
    }
    if (server.repl_backlog_histlen > server.repl_backlog_size)
        server.repl_backlog_histlen = server.repl_backlog_size;
    /* Set the offset of the first byte we have in the backlog. */
    server.repl_backlog_off = server.master_repl_offset -
                              server.repl_backlog_histlen + 1;
}

/* Wrapper for feedReplicationBacklog() that takes Redis string objects
 * as input. */
void feedReplicationBacklogWithObject(robj *o) {
    char llstr[LONG_STR_SIZE];
    void *p;
    size_t len;

    if (o->encoding == OBJ_ENCODING_INT) {
        len = ll2string(llstr,sizeof(llstr),(long)o->ptr);
        p = llstr;
    } else {
        len = sdslen(o->ptr);
        p = o->ptr;
    }
    feedReplicationBacklog(p,len);
}

int canFeedReplicaReplBuffer(client *replica) {
    /* Don't feed replicas that only want the RDB. */
    if (replica->flags & CLIENT_REPL_RDBONLY) return 0;

    /* Don't feed replicas that are still waiting for BGSAVE to start. */
    if (replica->replstate == SLAVE_STATE_WAIT_BGSAVE_START) return 0;

    return 1;
}

/* Propagate write commands to slaves, and populate the replication backlog
 * as well. This function is used if the instance is a master: we use
 * the commands received by our clients in order to create the replication
 * stream. Instead if the instance is a slave and has sub-slaves attached,
 * we use replicationFeedSlavesFromMasterStream() 
 * 将写命令传播给slaves 或者 填充到 replication backlog.
 * 如果当前实例是master,该函数将被使用: 从clients接收命令,并创建复制流.
 * 如果当前实例是一个有sub-slaves的slave,我们使用 replicationFeedSlavesFromMasterStream()
 */
void replicationFeedSlaves(list *slaves, int dictid, robj **argv, int argc) {
    listNode *ln;
    listIter li;
    int j, len;
    char llstr[LONG_STR_SIZE];

    /* If the instance is not a top level master, return ASAP: we'll just proxy
     * the stream of data we receive from our master instead, in order to
     * propagate *identical* replication stream. In this way this slave can
     * advertise the same replication ID as the master (since it shares the
     * master replication history and has the same backlog and offsets). 
     * 如果实例不是top level master,尽快返回: 我们将只proxy从master接收的数据流, 以便传播 *相同的* 复制流.
     * 通过这种方式,slave可以通告master相同的replication id(共享master replication历史并具有相同的backlog 和 offset)
     */
    if (server.masterhost != NULL) return;

    /* If there aren't slaves, and there is no backlog buffer to populate,
     * we can return ASAP. 
     * 没有slave 也没用backlog,尽快返回
     */
    if (server.repl_backlog == NULL && listLength(slaves) == 0) return;

    /* We can't have slaves attached and no backlog. */
    serverAssert(!(listLength(slaves) != 0 && server.repl_backlog == NULL));

    /* Send SELECT command to every slave if needed. 如有必要,给所有slave发送SELECT命令*/
    if (server.slaveseldb != dictid) {
        robj *selectcmd;

        /* For a few DBs we have pre-computed SELECT command. */
        if (dictid >= 0 && dictid < PROTO_SHARED_SELECT_CMDS) {
            selectcmd = shared.select[dictid];
        } else {
            int dictid_len;

            dictid_len = ll2string(llstr,sizeof(llstr),dictid);
            selectcmd = createObject(OBJ_STRING,
                sdscatprintf(sdsempty(),
                "*2\r\n$6\r\nSELECT\r\n$%d\r\n%s\r\n",
                dictid_len, llstr));
        }

        /* Add the SELECT command into the backlog. */
        if (server.repl_backlog) feedReplicationBacklogWithObject(selectcmd);

        /* Send it to slaves. */
        listRewind(slaves,&li);
        while((ln = listNext(&li))) {
            client *slave = ln->value;

            if (!canFeedReplicaReplBuffer(slave)) continue;
            addReply(slave,selectcmd);
        }

        if (dictid < 0 || dictid >= PROTO_SHARED_SELECT_CMDS)
            decrRefCount(selectcmd);
    }
    server.slaveseldb = dictid;

    /* Write the command to the replication backlog if any. */
    if (server.repl_backlog) {
        char aux[LONG_STR_SIZE+3];

        /* Add the multi bulk reply length. */
        aux[0] = '*';
        len = ll2string(aux+1,sizeof(aux)-1,argc);
        aux[len+1] = '\r';
        aux[len+2] = '\n';
        feedReplicationBacklog(aux,len+3);

        for (j = 0; j < argc; j++) {
            long objlen = stringObjectLen(argv[j]);

            /* We need to feed the buffer with the object as a bulk reply
             * not just as a plain string, so create the $..CRLF payload len
             * and add the final CRLF */
            aux[0] = '$';
            len = ll2string(aux+1,sizeof(aux)-1,objlen);
            aux[len+1] = '\r';
            aux[len+2] = '\n';
            feedReplicationBacklog(aux,len+3);
            feedReplicationBacklogWithObject(argv[j]);
            feedReplicationBacklog(aux+len+1,2);
        }
    }

    /* Write the command to every slave. */
    listRewind(slaves,&li);
    while((ln = listNext(&li))) {
        client *slave = ln->value;

        if (!canFeedReplicaReplBuffer(slave)) continue;

        /* Feed slaves that are waiting for the initial SYNC (so these commands
         * are queued in the output buffer until the initial SYNC completes),
         * or are already in sync with the master. */

        /* Add the multi bulk length. */
        addReplyArrayLen(slave,argc);

        /* Finally any additional argument that was not stored inside the
         * static buffer if any (from j to argc). */
        for (j = 0; j < argc; j++)
            addReplyBulk(slave,argv[j]);
    }
}

/* This is a debugging function that gets called when we detect something
 * wrong with the replication protocol: the goal is to peek into the
 * replication backlog and show a few final bytes to make simpler to
 * guess what kind of bug it could be. */
void showLatestBacklog(void) {
    if (server.repl_backlog == NULL) return;

    long long dumplen = 256;
    if (server.repl_backlog_histlen < dumplen)
        dumplen = server.repl_backlog_histlen;

    /* Identify the first byte to dump. */
    long long idx =
      (server.repl_backlog_idx + (server.repl_backlog_size - dumplen)) %
       server.repl_backlog_size;

    /* Scan the circular buffer to collect 'dumplen' bytes. */
    sds dump = sdsempty();
    while(dumplen) {
        long long thislen =
            ((server.repl_backlog_size - idx) < dumplen) ?
            (server.repl_backlog_size - idx) : dumplen;

        dump = sdscatrepr(dump,server.repl_backlog+idx,thislen);
        dumplen -= thislen;
        idx = 0;
    }

    /* Finally log such bytes: this is vital debugging info to
     * understand what happened. */
    serverLog(LL_WARNING,"Latest backlog is: '%s'", dump);
    sdsfree(dump);
}

/* This function is used in order to proxy what we receive from our master
 * to our sub-slaves. */
#include <ctype.h>
void replicationFeedSlavesFromMasterStream(list *slaves, char *buf, size_t buflen) {
    listNode *ln;
    listIter li;

    /* Debugging: this is handy to see the stream sent from master
     * to slaves. Disabled with if(0). */
    if (0) {
        printf("%zu:",buflen);
        for (size_t j = 0; j < buflen; j++) {
            printf("%c", isprint(buf[j]) ? buf[j] : '.');
        }
        printf("\n");
    }

    if (server.repl_backlog) feedReplicationBacklog(buf,buflen);
    listRewind(slaves,&li);
    while((ln = listNext(&li))) {
        client *slave = ln->value;

        if (!canFeedReplicaReplBuffer(slave)) continue;
        addReplyProto(slave,buf,buflen);
    }
}

void replicationFeedMonitors(client *c, list *monitors, int dictid, robj **argv, int argc) {
    if (!(listLength(server.monitors) && !server.loading)) return;
    listNode *ln;
    listIter li;
    int j;
    sds cmdrepr = sdsnew("+");
    robj *cmdobj;
    struct timeval tv;

    gettimeofday(&tv,NULL);
    cmdrepr = sdscatprintf(cmdrepr,"%ld.%06ld ",(long)tv.tv_sec,(long)tv.tv_usec);
    if (c->flags & CLIENT_LUA) {
        cmdrepr = sdscatprintf(cmdrepr,"[%d lua] ",dictid);
    } else if (c->flags & CLIENT_UNIX_SOCKET) {
        cmdrepr = sdscatprintf(cmdrepr,"[%d unix:%s] ",dictid,server.unixsocket);
    } else {
        cmdrepr = sdscatprintf(cmdrepr,"[%d %s] ",dictid,getClientPeerId(c));
    }

    for (j = 0; j < argc; j++) {
        if (argv[j]->encoding == OBJ_ENCODING_INT) {
            cmdrepr = sdscatprintf(cmdrepr, "\"%ld\"", (long)argv[j]->ptr);
        } else {
            cmdrepr = sdscatrepr(cmdrepr,(char*)argv[j]->ptr,
                        sdslen(argv[j]->ptr));
        }
        if (j != argc-1)
            cmdrepr = sdscatlen(cmdrepr," ",1);
    }
    cmdrepr = sdscatlen(cmdrepr,"\r\n",2);
    cmdobj = createObject(OBJ_STRING,cmdrepr);

    listRewind(monitors,&li);
    while((ln = listNext(&li))) {
        client *monitor = ln->value;
        addReply(monitor,cmdobj);
    }
    decrRefCount(cmdobj);
}

/* Feed the slave 'c' with the replication backlog starting from the
 * specified 'offset' up to the end of the backlog. 
 * 向slave 发送repl backlog中从 'offset'开始直到 backlog 最后的数据
 * 
 * server.master_repl_offset 只会一直不断增,master的复制偏移量;
 * server.repl_backlog_off 代表repl_backlog缓冲区保存数据的最小的offset,这里是offset的最小值,server.master_repl_offset是最大值;
 *  随着server.master_repl_offset一起持续增大,repl_backlog[server.repl_backlog_off]是没意义的;
 * server.repl_backlog_size 代表repl_backlog缓冲区的大小;
 * server.repl_backlog_histlen 代表repl_backlog缓冲区中保存的数据大小;
 * server.repl_backlog_idx 代表repl_backlog缓冲区中下一个字节的存储位置;
 * 
 * server.repl_backlog_off=server.master_repl_offset-server.repl_backlog_histlen+1;
 */
long long addReplyReplicationBacklog(client *c, long long offset) {
    long long j, skip, len;

    serverLog(LL_DEBUG, "[PSYNC] Replica request offset: %lld", offset);

    if (server.repl_backlog_histlen == 0) {
        serverLog(LL_DEBUG, "[PSYNC] Backlog history len is zero");
        return 0;
    }

    serverLog(LL_DEBUG, "[PSYNC] Backlog size: %lld",
             server.repl_backlog_size);
    serverLog(LL_DEBUG, "[PSYNC] First byte: %lld",
             server.repl_backlog_off);
    serverLog(LL_DEBUG, "[PSYNC] History len: %lld",
             server.repl_backlog_histlen);
    serverLog(LL_DEBUG, "[PSYNC] Current index: %lld",
             server.repl_backlog_idx);

    /* Compute the amount of bytes we need to discard. 需要丢弃的字节数(offset之前的数据当然要丢弃) */
    skip = offset - server.repl_backlog_off;
    serverLog(LL_DEBUG, "[PSYNC] Skipping: %lld", skip);

    /* Point j to the oldest byte, that is actually our
     * server.repl_backlog_off byte.  
     * 缓冲区保存数据 的起始idx.
     * server.repl_backlog_size-server.repl_backlog_histlen 代表缓冲区空闲空间的大小;
     * server.repl_backlog_idx(下一个存储数据位置) + 空闲空间大小 等于 保存数据的起始idx
     */
    j = (server.repl_backlog_idx +
        (server.repl_backlog_size-server.repl_backlog_histlen)) %
        server.repl_backlog_size;
    serverLog(LL_DEBUG, "[PSYNC] Index of first byte: %lld", j);

    /* Discard the amount of data to seek to the specified 'offset'. 跳过需要丢弃的数据(offset 之前的数据),找到正确的起始位置 */
    j = (j + skip) % server.repl_backlog_size;

    /* Feed slave with data. Since it is a circular buffer we have to
     * split the reply in two parts if we are cross-boundary. 
     * 需要发送给slave的数据量 = 总数据量 - 需要跳过的数据量
     * 因为是循环列表,所以需要分两部分发送
     */
    len = server.repl_backlog_histlen - skip;
    serverLog(LL_DEBUG, "[PSYNC] Reply total length: %lld", len);
    while(len) {
        long long thislen =
            ((server.repl_backlog_size - j) < len) ?
            (server.repl_backlog_size - j) : len;

        serverLog(LL_DEBUG, "[PSYNC] addReply() length: %lld", thislen);
        addReplyProto(c,server.repl_backlog + j, thislen);
        len -= thislen;
        j = 0;
    }
    //返回发送成功的数据量大小
    return server.repl_backlog_histlen - skip;
}

/* Return the offset to provide as reply to the PSYNC command received
 * from the slave. The returned value is only valid immediately after
 * the BGSAVE process started and before executing any other command
 * from clients. 
 * 返回offset 用在slave PSYNC命令的回复中.
 * 该返回值在 BGSAVE进程发起后,同时在没有执行任何client命令之前 是有效的.
 */
long long getPsyncInitialOffset(void) {
    return server.master_repl_offset;
}

/* Send a FULLRESYNC reply in the specific case of a full resynchronization,
 * as a side effect setup the slave for a full sync in different ways:
 * 在全量重同步的特定情况下(full resynchronization)发送FULLRESYNC回复, 以不同方式设置slave进行全量重同步:
 *
 * 1) Remember, into the slave client structure, the replication offset
 *    we sent here, so that if new slaves will later attach to the same
 *    background RDB saving process (by duplicating this client output
 *    buffer), we can get the right offset from this slave.
 *  记住,在slave客户端结构中,我们保存复制偏移量.
 *  目的是如果(BGSAVE成功前)又有新的slave来到,那么稍后会将其附加到同一个后台RDB保存过程中(通过copy当前slave client的output buffer)。
 *  我们就可以从这个slave中获取正确的offset.
 * 2) Set the replication state of the slave to WAIT_BGSAVE_END so that
 *    we start accumulating differences from this point.
 *  将slave的复制状态设置为 WAIT_BGSAVE_END, 这样我们就从这一点开始积累差异.
 * 
 * 3) Force the replication stream to re-emit a SELECT statement so
 *    the new slave incremental differences will start selecting the
 *    right database number.
 * 强制复制流重新发出SELECT语句, 以便新的slave增量差异将开始选择正确的数据库编号.
 *
 * Normally this function should be called immediately after a successful
 * BGSAVE for replication was started, or when there is one already in
 * progress that we attached our slave to.
 * 通常这个函数在一个复制成功开启bgsave后 或者 已经有一个slave在bgsave中，我们将自己的slave附加到他后面, 立马被调用
 */
int replicationSetupSlaveForFullResync(client *slave, long long offset) {
    char buf[128];
    int buflen;

    slave->psync_initial_offset = offset;
    slave->replstate = SLAVE_STATE_WAIT_BGSAVE_END;
    /* We are going to accumulate the incremental changes for this
     * slave as well. Set slaveseldb to -1 in order to force to re-emit
     * a SELECT statement in the replication stream. 
     * 增量更新强制发送 SELECT 语句
     */
    server.slaveseldb = -1;

    /* Don't send this reply to slaves that approached us with
     * the old SYNC command. 
     * 别将这个命令发送给 那些通过老的SYNC命令以和我们建立联系的slave
     */
    if (!(slave->flags & CLIENT_PRE_PSYNC)) {
        buflen = snprintf(buf,sizeof(buf),"+FULLRESYNC %s %lld\r\n",
                          server.replid,offset);
        if (connWrite(slave->conn,buf,buflen) != buflen) {
            freeClientAsync(slave);
            return C_ERR;
        }
    }
    return C_OK;
}

/* This function handles the PSYNC command from the point of view of a
 * master receiving a request for partial resynchronization.
 * 该函数将从一个master(接收到部分重同步请求)的视角处理PSYNC命令
 *
 * On success return C_OK, otherwise C_ERR is returned and we proceed
 * with the usual full resync. 
 * 成功,则返回 C_OK. 否则返回 C_ERR 同时 我们执行全量同步
 */
int masterTryPartialResynchronization(client *c) {
    long long psync_offset, psync_len;
    char *master_replid = c->argv[1]->ptr;
    char buf[128];
    int buflen;

    /* Parse the replication offset asked by the slave. Go to full sync
     * on parse error: this should never happen but we try to handle
     * it in a robust way compared to aborting.
     * 解析slave发送过来的replication offset. 如果解析失败,则走全量同步.
     */
    if (getLongLongFromObjectOrReply(c,c->argv[2],&psync_offset,NULL) !=
       C_OK) goto need_full_resync;

    /* Is the replication ID of this master the same advertised by the wannabe
     * slave via PSYNC? If the replication ID changed this master has a
     * different replication history, and there is no way to continue.
     * master的replid/replid2是否和 slave通过PSYNC 传过来的ID相同?
     * 如果两者不同,则不再继续走(部分同步)
     *
     * Note that there are two potentially valid replication IDs: the ID1
     * and the ID2. The ID2 however is only valid up to a specific offset. 
     * 注意 replid/replid2都是有效的. replid2 仅在特定offset内有效.
     */
    if (strcasecmp(master_replid, server.replid) &&
        (strcasecmp(master_replid, server.replid2) ||
         psync_offset > server.second_replid_offset))
    {
        /* Replid "?" is used by slaves that want to force a full resync. 
        *  slave强制执行全量重同步时,Replid='?'
        */
        if (master_replid[0] != '?') {
            if (strcasecmp(master_replid, server.replid) &&
                strcasecmp(master_replid, server.replid2))
            {
                serverLog(LL_NOTICE,"Partial resynchronization not accepted: "
                    "Replication ID mismatch (Replica asked for '%s', my "
                    "replication IDs are '%s' and '%s')",
                    master_replid, server.replid, server.replid2);
            } else {
                serverLog(LL_NOTICE,"Partial resynchronization not accepted: "
                    "Requested offset for second ID was %lld, but I can reply "
                    "up to %lld", psync_offset, server.second_replid_offset);
            }
        } else {
            serverLog(LL_NOTICE,"Full resync requested by replica %s",
                replicationGetSlaveName(c));
        }
        goto need_full_resync;
    }

    /* We still have the data our slave is asking for? 我们是否还有slave请求的数据?*/
    if (!server.repl_backlog ||
        psync_offset < server.repl_backlog_off ||
        psync_offset > (server.repl_backlog_off + server.repl_backlog_histlen))
    {
        serverLog(LL_NOTICE,
            "Unable to partial resync with replica %s for lack of backlog (Replica request was: %lld).", replicationGetSlaveName(c), psync_offset);
        if (psync_offset > server.master_repl_offset) {
            serverLog(LL_WARNING,
                "Warning: replica %s tried to PSYNC with an offset that is greater than the master replication offset.", replicationGetSlaveName(c));
        }
        goto need_full_resync;
    }

    /* If we reached this point, we are able to perform a partial resync:
     * 1) Set client state to make it a slave.
     * 2) Inform the client we can continue with +CONTINUE
     * 3) Send the backlog data (from the offset to the end) to the slave. 
     * 如果走到这一步,表示我们能够做部分重同步了:
     * 1) 设置client状态为一个slave;
     * 2) 通知client, 我们可以继续(向其回复 +CONTINUE)
     * 3）向slave发送backlog中的数据(offset to end);
     */
    c->flags |= CLIENT_SLAVE;
    c->replstate = SLAVE_STATE_ONLINE;
    c->repl_ack_time = server.unixtime;
    c->repl_put_online_on_ack = 0;
    listAddNodeTail(server.slaves,c);
    /* We can't use the connection buffers since they are used to accumulate
     * new commands at this stage. But we are sure the socket send buffer is
     * empty so this write will never fail actually. 
     * 我们无法使用connection buffer,既然他们在这个阶段被用于收集新命令.
     * 不过我们确认socket buffer是空的,所以这个写入永远不会失败.
     */
    if (c->slave_capa & SLAVE_CAPA_PSYNC2) {
        buflen = snprintf(buf,sizeof(buf),"+CONTINUE %s\r\n", server.replid);
    } else {
        buflen = snprintf(buf,sizeof(buf),"+CONTINUE\r\n");
    }
    if (connWrite(c->conn,buf,buflen) != buflen) {
        freeClientAsync(c);
        return C_OK;
    }
    //给slave发送对应数据
    psync_len = addReplyReplicationBacklog(c,psync_offset);
    serverLog(LL_NOTICE,
        "Partial resynchronization request from %s accepted. Sending %lld bytes of backlog starting from offset %lld.",
            replicationGetSlaveName(c),
            psync_len, psync_offset);
    /* Note that we don't need to set the selected DB at server.slaveseldb
     * to -1 to force the master to emit SELECT, since the slave already
     * has this state from the previous connection with the master. 
     * 注意 既然slave保留着前面和master的连接状态, 我们不需要设置 server.slaveseldb=-1, 强迫master发送SELECT
     */

    refreshGoodSlavesCount();

    /* Fire the replica change modules event. */
    moduleFireServerEvent(REDISMODULE_EVENT_REPLICA_CHANGE,
                          REDISMODULE_SUBEVENT_REPLICA_CHANGE_ONLINE,
                          NULL);

    return C_OK; /* The caller can return, no full resync needed. */

need_full_resync:
    /* We need a full resync for some reason... Note that we can't
     * reply to PSYNC right now if a full SYNC is needed. The reply
     * must include the master offset at the time the RDB file we transfer
     * is generated, so we need to delay the reply to that moment. */
    return C_ERR;
}

/* Start a BGSAVE for replication goals, which is, selecting the disk or
 * socket target depending on the configuration, and making sure that
 * the script cache is flushed before to start.
 * 为复制目标开启一个BGSAVE, 选择disk or socket方式取决于配置. 在开始前确保script cache被flush
 *
 * The mincapa argument is the bitwise AND among all the slaves capabilities
 * of the slaves waiting for this BGSAVE, so represents the slave capabilities
 * all the slaves support. Can be tested via SLAVE_CAPA_* macros.
 *
 * Side effects, other than starting a BGSAVE:
 *
 * 1) Handle the slaves in WAIT_START state, by preparing them for a full
 *    sync if the BGSAVE was successfully started, or sending them an error
 *    and dropping them from the list of slaves.
 *   处理WAIT_START状态的slaves: 如果BGSAVE成功发起,则准备让他们执行一次全量同步.
 *   或者向他们发送一个错误 并 将他们从 server.slaves 列表中剔除;
 *
 * 2) Flush the Lua scripting script cache if the BGSAVE was actually
 *    started.
 * 如果BGSAVE成功启动,则flush lua 脚本缓存.
 *
 * Returns C_OK on success or C_ERR otherwise. */
int startBgsaveForReplication(int mincapa) {
    int retval;
    int socket_target = server.repl_diskless_sync && (mincapa & SLAVE_CAPA_EOF);
    listIter li;
    listNode *ln;

    serverLog(LL_NOTICE,"Starting BGSAVE for SYNC with target: %s",
        socket_target ? "replicas sockets" : "disk");

    rdbSaveInfo rsi, *rsiptr;
    rsiptr = rdbPopulateSaveInfo(&rsi);
    /* Only do rdbSave* when rsiptr is not NULL,
     * otherwise slave will miss repl-stream-db. */
    if (rsiptr) {
        if (socket_target)
            retval = rdbSaveToSlavesSockets(rsiptr);
        else
            retval = rdbSaveBackground(server.rdb_filename,rsiptr);
    } else {
        serverLog(LL_WARNING,"BGSAVE for replication: replication information not available, can't generate the RDB file right now. Try later.");
        retval = C_ERR;
    }

    /* If we succeeded to start a BGSAVE with disk target, let's remember
     * this fact, so that we can later delete the file if needed. Note
     * that we don't set the flag to 1 if the feature is disabled, otherwise
     * it would never be cleared: the file is not deleted. This way if
     * the user enables it later with CONFIG SET, we are fine. */
    if (retval == C_OK && !socket_target && server.rdb_del_sync_files)
        RDBGeneratedByReplication = 1;

    /* If we failed to BGSAVE, remove the slaves waiting for a full
     * resynchronization from the list of slaves, inform them with
     * an error about what happened, close the connection ASAP. 
     * 如果我们执行BGSAVE失败, 则将所有server.slaves中slave全部移除并给这些slave发送错误信息,尽快关闭连接
     */
    if (retval == C_ERR) {
        serverLog(LL_WARNING,"BGSAVE for replication failed");
        listRewind(server.slaves,&li);
        while((ln = listNext(&li))) {
            client *slave = ln->value;

            if (slave->replstate == SLAVE_STATE_WAIT_BGSAVE_START) {
                slave->replstate = REPL_STATE_NONE;
                slave->flags &= ~CLIENT_SLAVE;
                listDelNode(server.slaves,ln);
                addReplyError(slave,
                    "BGSAVE failed, replication can't continue");
                slave->flags |= CLIENT_CLOSE_AFTER_REPLY;
            }
        }
        return retval;
    }

    /* If the target is socket, rdbSaveToSlavesSockets() already setup
     * the slaves for a full resync. Otherwise for disk target do it now.
     * 将disk-based类型复制的slave设置为等待 全量同步 状态.
     * socket类型复制的slave在rdbSaveToSlavesSockets()中已经设置过状态
     */
    if (!socket_target) {
        listRewind(server.slaves,&li);
        while((ln = listNext(&li))) {
            client *slave = ln->value;

            if (slave->replstate == SLAVE_STATE_WAIT_BGSAVE_START) {
                    replicationSetupSlaveForFullResync(slave,
                            getPsyncInitialOffset());
            }
        }
    }

    /* Flush the script cache, since we need that slave differences are
     * accumulated without requiring slaves to match our cached scripts.
     * flush脚本cache,
    */
    if (retval == C_OK) replicationScriptCacheFlush();
    return retval;
}

/* SYNC and PSYNC command implementation. */
void syncCommand(client *c) {
    /* ignore SYNC if already slave or in monitor mode */
    if (c->flags & CLIENT_SLAVE) return;

    /* Check if this is a failover request to a replica with the same replid and
     * become a master if so. 
     * 检查这是否是对slave的一个failover请求, 如果请求中replid和自己的replid相同, 如果是则将自己提升为master
     */
    if (c->argc > 3 && !strcasecmp(c->argv[0]->ptr,"psync") && 
        !strcasecmp(c->argv[3]->ptr,"failover"))
    {
        serverLog(LL_WARNING, "Failover request received for replid %s.",
            (unsigned char *)c->argv[1]->ptr);
        if (!server.masterhost) {
            addReplyError(c, "PSYNC FAILOVER can't be sent to a master.");
            return;
        }

        if (!strcasecmp(c->argv[1]->ptr,server.replid)) {
            replicationUnsetMaster();
            sds client = catClientInfoString(sdsempty(),c);
            serverLog(LL_NOTICE,
                "MASTER MODE enabled (failover request from '%s')",client);
            sdsfree(client);
        } else {
            addReplyError(c, "PSYNC FAILOVER replid must match my replid.");
            return;            
        }
    }

    /* Don't let replicas sync with us while we're failing over 如果我正在进行failover,则不要让slave和我们执行同步*/
    if (server.failover_state != NO_FAILOVER) {
        addReplyError(c,"-NOMASTERLINK Can't SYNC while failing over");
        return;
    }

    /* Refuse SYNC requests if we are a slave but the link with our master
     * is not ok... 
     * 如果我们是slave,但是和master的连接状态not ok,则拒绝其他实例的SYNC请求
     */
    if (server.masterhost && server.repl_state != REPL_STATE_CONNECTED) {
        addReplyError(c,"-NOMASTERLINK Can't SYNC while not connected with my master");
        return;
    }

    /* SYNC can't be issued when the server has pending data to send to
     * the client about already issued commands. We need a fresh reply
     * buffer registering the differences between the BGSAVE and the current
     * dataset, so that we can copy to other slaves if needed. 
     * 如果这个client还有一些待发送出去的数据(reply buffer), 那么无法执行SYNC请求.
     * 我们需要刷新reply buffer(或者说需要conn的reply buffer为空),reply buffer后续将保存 BGSAVE开始 到 '当前'的数据集;
     * 以便后续BGSAVE期间,如果有new slave达到,我们可以将当前conn的 reply buffer拷贝给他.
     */
    if (clientHasPendingReplies(c)) {
        addReplyError(c,"SYNC and PSYNC are invalid with pending output");
        return;
    }

    serverLog(LL_NOTICE,"Replica %s asks for synchronization",
        replicationGetSlaveName(c));

    /* Try a partial resynchronization if this is a PSYNC command.
     * If it fails, we continue with usual full resynchronization, however
     * when this happens replicationSetupSlaveForFullResync will replied
     * with:
     * 如果这是一个PSYNC命令,先尝试部分重同步.
     * 如果 部分重同步失败, 我们继续用 全量重同步. 当发生这种情况时,replicationSetupSlaveForFullResync 将回复
     *
     * +FULLRESYNC <replid> <offset>
     *
     * So the slave knows the new replid and offset to try a PSYNC later
     * if the connection with the master is lost.
     * 所以slave知道新的replid 和offset 并(在master连接丢失后)随后尝试PSYNC
     */
    if (!strcasecmp(c->argv[0]->ptr,"psync")) {
        if (masterTryPartialResynchronization(c) == C_OK) {
            server.stat_sync_partial_ok++;
            return; /* No full resync needed, return. */
        } else {
            char *master_replid = c->argv[1]->ptr;

            /* Increment stats for failed PSYNCs, but only if the
             * replid is not "?", as this is used by slaves to force a full
             * resync on purpose when they are not able to partially
             * resync. */
            if (master_replid[0] != '?') server.stat_sync_partial_err++;
        }
    } else {
        /* If a slave uses SYNC, we are dealing with an old implementation
         * of the replication protocol (like redis-cli --slave). Flag the client
         * so that we don't expect to receive REPLCONF ACK feedbacks. 
         * 如果slave使用SYNC(而不是PSYNC),那么我们使用旧的复制协议处理(像 redis-cli --slave).
         * 标识该client, 以便我们不会期望从改client接收到 REPLCONF ACK 回复
         */
        c->flags |= CLIENT_PRE_PSYNC;
    }

    /* Full resynchronization. 准备做全量复制 */
    server.stat_sync_full++;

    /* Setup the slave as one waiting for BGSAVE to start. The following code
     * paths will change the state if we handle the slave differently.
     * 设置slave为等待BGSAVE 开始状态
     */
    c->replstate = SLAVE_STATE_WAIT_BGSAVE_START;
    if (server.repl_disable_tcp_nodelay)
        connDisableTcpNoDelay(c->conn); /* Non critical if it fails. */
    c->repldbfd = -1;
    c->flags |= CLIENT_SLAVE;
    listAddNodeTail(server.slaves,c);

    /* Create the replication backlog if needed. 创建repl_backlog */
    if (listLength(server.slaves) == 1 && server.repl_backlog == NULL) {
        /* When we create the backlog from scratch, we always use a new
         * replication ID and clear the ID2, since there is no valid
         * past history. 
         * 当我们创建backlog(代表以前我们没有slave),我们已经使用了一个新的 replid, 可以清空replid2.
         * 因为replid2已经无效了.
         */
        changeReplicationId();
        clearReplicationId2();
        createReplicationBacklog();
        serverLog(LL_NOTICE,"Replication backlog created, my new "
                            "replication IDs are '%s' and '%s'",
                            server.replid, server.replid2);
    }

    /* CASE 1: BGSAVE is in progress, with disk target. BGSAVE已经在执行中,同时RDB需要保存到disk*/
    if (server.child_type == CHILD_TYPE_RDB &&
        server.rdb_child_type == RDB_CHILD_TYPE_DISK)
    {
        /* Ok a background save is in progress. Let's check if it is a good
         * one for replication, i.e. if there is another slave that is
         * registering differences since the server forked to save. 
         * 有一个bgsave正在执行中,我们检查它是否适合复制.
         * 即是否已经有一个slave保存了差异, 如果已经有这么个slave=>slave01
         * 那么现在(执行SYNC命令)新slave 完全可以直接使用当前bgsavee中的RDB,同时从slave01中拷贝差异即可
         */
        client *slave;
        listNode *ln;
        listIter li;

        listRewind(server.slaves,&li);
        while((ln = listNext(&li))) {
            slave = ln->value;
            /* If the client needs a buffer of commands, we can't use
             * a replica without replication buffer. 
             * 如果client(new slave)需要 缓存的commands,那么对于没有 replication buffer的slave,我们是无法使用的
             */
            if (slave->replstate == SLAVE_STATE_WAIT_BGSAVE_END &&
                (!(slave->flags & CLIENT_REPL_RDBONLY) ||
                 (c->flags & CLIENT_REPL_RDBONLY)))
                break;
        }
        /* To attach this slave, we check that it has at least all the
         * capabilities of the slave that triggered the current BGSAVE. 
         * 确实找到了 这么一个可以复用差异的slave01,那么检查new slave检查和他的兼容性
         */
        if (ln && ((c->slave_capa & slave->slave_capa) == slave->slave_capa)) {
            /* Perfect, the server is already registering differences for
             * another slave. Set the right state, and copy the buffer.
             * We don't copy buffer if clients don't want. 
             * 兼容性检查ok,那么(执行SYNC命令的)新slave开始修改状态,同时拷贝slave01的outputbuffer
             */
            if (!(c->flags & CLIENT_REPL_RDBONLY)) copyClientOutputBuffer(c,slave);
            replicationSetupSlaveForFullResync(c,slave->psync_initial_offset);
            serverLog(LL_NOTICE,"Waiting for end of BGSAVE for SYNC");
        } else {
            /* No way, we need to wait for the next BGSAVE in order to
             * register differences. */
            serverLog(LL_NOTICE,"Can't attach the replica to the current BGSAVE. Waiting for next BGSAVE for SYNC");
        }

    /* CASE 2: BGSAVE is in progress, with socket target. 
    * BGSAVE已经在执行中了,使用的是diskless的方式,(执行SYNC命令的)新slave只能等下次bgsave
    */
    } else if (server.child_type == CHILD_TYPE_RDB &&
               server.rdb_child_type == RDB_CHILD_TYPE_SOCKET)
    {
        /* There is an RDB child process but it is writing directly to
         * children sockets. We need to wait for the next BGSAVE
         * in order to synchronize. */
        serverLog(LL_NOTICE,"Current BGSAVE has socket target. Waiting for next BGSAVE for SYNC");

    /* CASE 3: There is no BGSAVE is in progress. 
    * 没有bgsave在执行中,那就执行bgsave罗
    */
    } else {
        if (server.repl_diskless_sync && (c->slave_capa & SLAVE_CAPA_EOF) &&
            server.repl_diskless_sync_delay)
        {
            /* Diskless replication RDB child is created inside
             * replicationCron() since we want to delay its start a
             * few seconds to wait for more slaves to arrive. 
             * diskless 复制的RDB子任务 是在 replicationCron()中被创建的,因为我们希望delay一段时间等待更多slave到达
             */
            serverLog(LL_NOTICE,"Delay next BGSAVE for diskless SYNC");
        } else {
            /* We don't have a BGSAVE in progress, let's start one. Diskless
             * or disk-based mode is determined by replica's capacity. */
            if (!hasActiveChildProcess()) {
                startBgsaveForReplication(c->slave_capa);
            } else {
                serverLog(LL_NOTICE,
                    "No BGSAVE in progress, but another BG operation is active. "
                    "BGSAVE for replication delayed");
            }
        }
    }
    return;
}

/* REPLCONF <option> <value> <option> <value> ...
 * This command is used by a replica in order to configure the replication
 * process before starting it with the SYNC command.
 * This command is also used by a master in order to get the replication
 * offset from a replica.
 *
 * Currently we support these options:
 *
 * - listening-port <port>
 * - ip-address <ip>
 * What is the listening ip and port of the Replica redis instance, so that
 * the master can accurately lists replicas and their listening ports in the
 * INFO output.
 *
 * - capa <eof|psync2>
 * What is the capabilities of this instance.
 * eof: supports EOF-style RDB transfer for diskless replication.
 * psync2: supports PSYNC v2, so understands +CONTINUE <new repl ID>.
 *
 * - ack <offset>
 * Replica informs the master the amount of replication stream that it
 * processed so far.
 *
 * - getack
 * Unlike other subcommands, this is used by master to get the replication
 * offset from a replica.
 *
 * - rdb-only
 * Only wants RDB snapshot without replication buffer. */
void replconfCommand(client *c) {
    int j;

    if ((c->argc % 2) == 0) {
        /* Number of arguments must be odd to make sure that every
         * option has a corresponding value. */
        addReplyErrorObject(c,shared.syntaxerr);
        return;
    }

    /* Process every option-value pair. */
    for (j = 1; j < c->argc; j+=2) {
        if (!strcasecmp(c->argv[j]->ptr,"listening-port")) {
            long port;

            if ((getLongFromObjectOrReply(c,c->argv[j+1],
                    &port,NULL) != C_OK))
                return;
            c->slave_listening_port = port;
        } else if (!strcasecmp(c->argv[j]->ptr,"ip-address")) {
            sds addr = c->argv[j+1]->ptr;
            if (sdslen(addr) < NET_HOST_STR_LEN) {
                if (c->slave_addr) sdsfree(c->slave_addr);
                c->slave_addr = sdsdup(addr);
            } else {
                addReplyErrorFormat(c,"REPLCONF ip-address provided by "
                    "replica instance is too long: %zd bytes", sdslen(addr));
                return;
            }
        } else if (!strcasecmp(c->argv[j]->ptr,"capa")) {
            /* Ignore capabilities not understood by this master. */
            if (!strcasecmp(c->argv[j+1]->ptr,"eof"))
                c->slave_capa |= SLAVE_CAPA_EOF;
            else if (!strcasecmp(c->argv[j+1]->ptr,"psync2"))
                c->slave_capa |= SLAVE_CAPA_PSYNC2;
        } else if (!strcasecmp(c->argv[j]->ptr,"ack")) {
            /* REPLCONF ACK is used by slave to inform the master the amount
             * of replication stream that it processed so far. It is an
             * internal only command that normal clients should never use. */
            long long offset;

            if (!(c->flags & CLIENT_SLAVE)) return;
            if ((getLongLongFromObject(c->argv[j+1], &offset) != C_OK))
                return;
            if (offset > c->repl_ack_off)
                c->repl_ack_off = offset;
            c->repl_ack_time = server.unixtime;
            /* If this was a diskless replication, we need to really put
             * the slave online when the first ACK is received (which
             * confirms slave is online and ready to get more data). This
             * allows for simpler and less CPU intensive EOF detection
             * when streaming RDB files.
             * There's a chance the ACK got to us before we detected that the
             * bgsave is done (since that depends on cron ticks), so run a
             * quick check first (instead of waiting for the next ACK. */
            if (server.child_type == CHILD_TYPE_RDB && c->replstate == SLAVE_STATE_WAIT_BGSAVE_END)
                checkChildrenDone();
            if (c->repl_put_online_on_ack && c->replstate == SLAVE_STATE_ONLINE)
                putSlaveOnline(c);
            /* Note: this command does not reply anything! */
            return;
        } else if (!strcasecmp(c->argv[j]->ptr,"getack")) {
            /* REPLCONF GETACK is used in order to request an ACK ASAP
             * to the slave. */
            if (server.masterhost && server.master) replicationSendAck();
            return;
        } else if (!strcasecmp(c->argv[j]->ptr,"rdb-only")) {
           /* REPLCONF RDB-ONLY is used to identify the client only wants
            * RDB snapshot without replication buffer. */
            long rdb_only = 0;
            if (getRangeLongFromObjectOrReply(c,c->argv[j+1],
                    0,1,&rdb_only,NULL) != C_OK)
                return;
            if (rdb_only == 1) c->flags |= CLIENT_REPL_RDBONLY;
            else c->flags &= ~CLIENT_REPL_RDBONLY;
        } else {
            addReplyErrorFormat(c,"Unrecognized REPLCONF option: %s",
                (char*)c->argv[j]->ptr);
            return;
        }
    }
    addReply(c,shared.ok);
}

/* This function puts a replica in the online state, and should be called just
 * after a replica received the RDB file for the initial synchronization, and
 * we are finally ready to send the incremental stream of commands.
 * 该函数将slave设置为online状态,在slave 接收完RDB文件数据后立即调用,稍后我们准备给slave发送增量数据
 *
 * It does a few things:
 * 1) Close the replica's connection async if it doesn't need replication
 *    commands buffer stream, since it actually isn't a valid replica.
 * 2) Put the slave in ONLINE state. Note that the function may also be called
 *    for a replicas that are already in ONLINE state, but having the flag
 *    repl_put_online_on_ack set to true: we still have to install the write
 *    handler in that case. This function will take care of that.
 * 3) Make sure the writable event is re-installed, since calling the SYNC
 *    command disables it, so that we can accumulate output buffer without
 *    sending it to the replica.
 * 4) Update the count of "good replicas". 
 * 该函数做如下几个事情:
 * 1) 如果slave不需要增量数据,那么我们就关闭与slave的连接(这实际上不是一个有效的replica)
 * 2) 将slave设置为online状态. 注意该函数可能被 已经 处于online状态但是repl_put_online_on_ack=1 的slave再次调用,此时我们需要为其设置write handler;
 * 3) 确保writeable event handler重新安装, 因为执行SYNC命令禁用了slave的writable handler, 以便我们可以累积output buffer而无需将其发送给slave;
 * 4) 更新 good replicas 的个数;
 */
void putSlaveOnline(client *slave) {
    slave->replstate = SLAVE_STATE_ONLINE;
    slave->repl_put_online_on_ack = 0;
    slave->repl_ack_time = server.unixtime; /* Prevent false timeout. */

    if (slave->flags & CLIENT_REPL_RDBONLY) {
        serverLog(LL_NOTICE,
            "Close the connection with replica %s as RDB transfer is complete",
            replicationGetSlaveName(slave));
        freeClientAsync(slave);
        return;
    }
    if (connSetWriteHandler(slave->conn, sendReplyToClient) == C_ERR) {
        serverLog(LL_WARNING,"Unable to register writable event for replica bulk transfer: %s", strerror(errno));
        freeClient(slave);
        return;
    }
    refreshGoodSlavesCount();
    /* Fire the replica change modules event. */
    moduleFireServerEvent(REDISMODULE_EVENT_REPLICA_CHANGE,
                          REDISMODULE_SUBEVENT_REPLICA_CHANGE_ONLINE,
                          NULL);
    serverLog(LL_NOTICE,"Synchronization with replica %s succeeded",
        replicationGetSlaveName(slave));
}

/* We call this function periodically to remove an RDB file that was
 * generated because of replication, in an instance that is otherwise
 * without any persistence. We don't want instances without persistence
 * to take RDB files around, this violates certain policies in certain
 * environments. 
 * 我们定期调用该函数删除因复制而生成的RDB文件,否则实例将不再具有任何持久性.
 * 我们不希望没有持久性的实例携带RDB文件, 这违反了某些环境的某些策略.
 */
void removeRDBUsedToSyncReplicas(void) {
    /* If the feature is disabled, return ASAP but also clear the
     * RDBGeneratedByReplication flag in case it was set. Otherwise if the
     * feature was enabled, but gets disabled later with CONFIG SET, the
     * flag may remain set to one: then next time the feature is re-enabled
     * via CONFIG SET we have it set even if no RDB was generated
     * because of replication recently. */
    if (!server.rdb_del_sync_files) {
        //rdb_del_sync_files 这是一个配置,可以设置为启用 or 不启用
        RDBGeneratedByReplication = 0;
        return;
    }

    if (allPersistenceDisabled() && RDBGeneratedByReplication) {
        client *slave;
        listNode *ln;
        listIter li;

        int delrdb = 1;
        listRewind(server.slaves,&li);
        while((ln = listNext(&li))) {
            slave = ln->value;
            if (slave->replstate == SLAVE_STATE_WAIT_BGSAVE_START ||
                slave->replstate == SLAVE_STATE_WAIT_BGSAVE_END ||
                slave->replstate == SLAVE_STATE_SEND_BULK)
            {
                delrdb = 0;
                break; /* No need to check the other replicas. */
            }
        }
        if (delrdb) {
            struct stat sb;
            if (lstat(server.rdb_filename,&sb) != -1) {
                RDBGeneratedByReplication = 0;
                serverLog(LL_NOTICE,
                    "Removing the RDB file used to feed replicas "
                    "in a persistence-less instance");
                bg_unlink(server.rdb_filename);
            }
        }
    }
}

void sendBulkToSlave(connection *conn) {
    client *slave = connGetPrivateData(conn);
    char buf[PROTO_IOBUF_LEN];
    ssize_t nwritten, buflen;

    /* Before sending the RDB file, we send the preamble as configured by the
     * replication process. Currently the preamble is just the bulk count of
     * the file in the form "$<length>\r\n". 
     * 在发送RDB文件之前,我们发送preamble, 该信息将被slave处理.
     * preamble中主要保存 RDB文件的大小,格式 "$<length>\r\n"
     */
    if (slave->replpreamble) {
        nwritten = connWrite(conn,slave->replpreamble,sdslen(slave->replpreamble));
        if (nwritten == -1) {
            serverLog(LL_VERBOSE,
                "Write error sending RDB preamble to replica: %s",
                connGetLastError(conn));
            freeClient(slave);
            return;
        }
        atomicIncr(server.stat_net_output_bytes, nwritten);
        sdsrange(slave->replpreamble,nwritten,-1);
        if (sdslen(slave->replpreamble) == 0) {
            sdsfree(slave->replpreamble);
            slave->replpreamble = NULL; //preamble置空,避免再次传输
            /* fall through sending data. */
        } else {
            return;
        }
    }

    /* If the preamble was already transferred, send the RDB bulk data. 
    * preamble数据传输完成后,开始传输RDB数据. 每次传输 16KB
    * - 传输发生任何错误,我们都会主动断开与 slave的连接;
    * - slave->repldboff 保存了当前slave接收到的数据offset(这个信心很重要,特别是我们有多个slaves需要传输RDB数据时)
    */
    lseek(slave->repldbfd,slave->repldboff,SEEK_SET);
    buflen = read(slave->repldbfd,buf,PROTO_IOBUF_LEN);
    if (buflen <= 0) {
        serverLog(LL_WARNING,"Read error sending DB to replica: %s",
            (buflen == 0) ? "premature EOF" : strerror(errno));
        freeClient(slave);
        return;
    }
    if ((nwritten = connWrite(conn,buf,buflen)) == -1) {
        if (connGetState(conn) != CONN_STATE_CONNECTED) {
            serverLog(LL_WARNING,"Write error sending DB to replica: %s",
                connGetLastError(conn));
            freeClient(slave);
        }
        return;
    }
    slave->repldboff += nwritten;
    atomicIncr(server.stat_net_output_bytes, nwritten);
    if (slave->repldboff == slave->repldbsize) {
        // RDB 数据传输完成,关闭slave RDB文件fd. 同时slave 设置为online状态
        close(slave->repldbfd);
        slave->repldbfd = -1;
        connSetWriteHandler(slave->conn,NULL);
        putSlaveOnline(slave);
    }
}

/* Remove one write handler from the list of connections waiting to be writable
 * during rdb pipe transfer. 
 * 等待可写的 connections list中,删除其中一个的write handler
 */
void rdbPipeWriteHandlerConnRemoved(struct connection *conn) {
    if (!connHasWriteHandler(conn))
        return;
    connSetWriteHandler(conn, NULL);
    client *slave = connGetPrivateData(conn);
    slave->repl_last_partial_write = 0;
    server.rdb_pipe_numconns_writing--;
    /* if there are no more writes for now for this conn, or write error: */
    if (server.rdb_pipe_numconns_writing == 0) {
        if (aeCreateFileEvent(server.el, server.rdb_pipe_read, AE_READABLE, rdbPipeReadHandler,NULL) == AE_ERR) {
            serverPanic("Unrecoverable error creating server.rdb_pipe_read file event.");
        }
    }
}

/* Called in diskless master during transfer of data from the rdb pipe, when
 * the replica becomes writable again. 
 * 在给某个slave发送buffer数据,如果只发送了部分. 等待该slave可写的时再次发送剩余部分
 */
void rdbPipeWriteHandler(struct connection *conn) {
    serverAssert(server.rdb_pipe_bufflen>0);
    client *slave = connGetPrivateData(conn);
    int nwritten;
    if ((nwritten = connWrite(conn, server.rdb_pipe_buff + slave->repldboff,
                              server.rdb_pipe_bufflen - slave->repldboff)) == -1)
    {
        if (connGetState(conn) == CONN_STATE_CONNECTED)
            return; /* equivalent to EAGAIN */
        serverLog(LL_WARNING,"Write error sending DB to replica: %s",
            connGetLastError(conn));
        freeClient(slave);
        return;
    } else {
        slave->repldboff += nwritten;
        atomicIncr(server.stat_net_output_bytes, nwritten);
        if (slave->repldboff < server.rdb_pipe_bufflen) {
            slave->repl_last_partial_write = server.unixtime;
            return; /* more data to write.. */
        }
    }
    rdbPipeWriteHandlerConnRemoved(conn);
}

/* Called in diskless master, when there's data to read from the child's rdb pipe 
* 当child的rdb pipe有数据可以读取时, 该函数被diskless master调用
*/
void rdbPipeReadHandler(struct aeEventLoop *eventLoop, int fd, void *clientData, int mask) {
    UNUSED(mask);
    UNUSED(clientData);
    UNUSED(eventLoop);
    int i;
    if (!server.rdb_pipe_buff)
        server.rdb_pipe_buff = zmalloc(PROTO_IOBUF_LEN);
    serverAssert(server.rdb_pipe_numconns_writing==0);

    while (1) {
        server.rdb_pipe_bufflen = read(fd, server.rdb_pipe_buff, PROTO_IOBUF_LEN);
        if (server.rdb_pipe_bufflen < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            serverLog(LL_WARNING,"Diskless rdb transfer, read error sending DB to replicas: %s", strerror(errno));
            for (i=0; i < server.rdb_pipe_numconns; i++) {
                connection *conn = server.rdb_pipe_conns[i];
                if (!conn)
                    continue;
                client *slave = connGetPrivateData(conn);
                freeClient(slave);
                server.rdb_pipe_conns[i] = NULL;
            }
            killRDBChild();
            return;
        }

        if (server.rdb_pipe_bufflen == 0) {
            /* EOF - write end was closed. 读取到最后*/
            int stillUp = 0;
            aeDeleteFileEvent(server.el, server.rdb_pipe_read, AE_READABLE);
            for (i=0; i < server.rdb_pipe_numconns; i++)
            {
                connection *conn = server.rdb_pipe_conns[i];
                if (!conn)
                    continue;
                stillUp++;
            }
            serverLog(LL_WARNING,"Diskless rdb transfer, done reading from pipe, %d replicas still up.", stillUp);
            /* Now that the replicas have finished reading, notify the child that it's safe to exit. 
             * When the server detects the child has exited, it can mark the replica as online, and
             * start streaming the replication buffers. 
             * 既然已经完成rdb数据读取,则通知child 进程可以安全退出.
             * 当master检测到child已经退出,则可以标记slave已上线,同时开始传输增量数据.
             */
            close(server.rdb_child_exit_pipe);
            server.rdb_child_exit_pipe = -1;
            return;
        }

        int stillAlive = 0;
        for (i=0; i < server.rdb_pipe_numconns; i++)
        {
            int nwritten;
            connection *conn = server.rdb_pipe_conns[i];
            if (!conn)
                continue;

            client *slave = connGetPrivateData(conn);
            if ((nwritten = connWrite(conn, server.rdb_pipe_buff, server.rdb_pipe_bufflen)) == -1) {
                if (connGetState(conn) != CONN_STATE_CONNECTED) {
                    serverLog(LL_WARNING,"Diskless rdb transfer, write error sending DB to replica: %s",
                        connGetLastError(conn));
                    freeClient(slave);
                    server.rdb_pipe_conns[i] = NULL;
                    continue;
                }
                /* An error and still in connected state, is equivalent to EAGAIN */
                slave->repldboff = 0;
            } else {
                /* Note: when use diskless replication, 'repldboff' is the offset
                 * of 'rdb_pipe_buff' sent rather than the offset of entire RDB. 
                 * 注意: diskless复制模式, repldboff是 rdb_pipe_buff 已发送的offset,而不是整个RDB的offset
                 * slave->repldboff的目的是记住 本次buff中已经发送多少给 slave了,剩余多少.便于 rdbPipeWriteHandler() 使用
                 */
                slave->repldboff = nwritten;
                atomicIncr(server.stat_net_output_bytes, nwritten);
            }
            /* If we were unable to write all the data to one of the replicas,
             * setup write handler (and disable pipe read handler, below) 
             * 如果我们无法将buffer中的所有数据发送给 某些slave
             * 给这些slave 设置write handler:rdbPipeWriteHandler() 回调, rdbPipeWriteHandler()中我们将继续给这些slave写入buffer剩余部分.
             * buffer剩余部分给这个slave发送成功后,继续前面步骤.给所有slave发送剩余的rdb数据.
             */
            if (nwritten != server.rdb_pipe_bufflen) {
                slave->repl_last_partial_write = server.unixtime;
                server.rdb_pipe_numconns_writing++;
                connSetWriteHandler(conn, rdbPipeWriteHandler);
            }
            stillAlive++;
        }

        if (stillAlive == 0) {
            serverLog(LL_WARNING,"Diskless rdb transfer, last replica dropped, killing fork child.");
            killRDBChild();
        }
        /*  Remove the pipe read handler if at least one write handler was set. 
        * 如果存在某些slave出现部分写的情况,那么就终止继续发送.
        * 同时给这些slave writeable事件添加 rdbPipeWriteHandler() 回调, rdbPipeWriteHandler()中我们将继续给这个slave写入buffer剩余部分.
        * buffer剩余部分给这个slave发送成功后,继续前面步骤.给所有slave发送剩余的rdb数据.
        */
        if (server.rdb_pipe_numconns_writing || stillAlive == 0) {
            aeDeleteFileEvent(server.el, server.rdb_pipe_read, AE_READABLE);
            break;
        }
    }
}

/* This function is called at the end of every background saving,
 * or when the replication RDB transfer strategy is modified from
 * disk to socket or the other way around.
 * 该函数在每次bgsave成功后会被调用 或 在RDB传输方法从 disk 变化为socket 时
 *
 * The goal of this function is to handle slaves waiting for a successful
 * background saving in order to perform non-blocking synchronization, and
 * to schedule a new BGSAVE if there are slaves that attached while a
 * BGSAVE was in progress, but it was not a good one for replication (no
 * other slave was accumulating differences).
 * 该函数目标是 为那些等待bgsave成功执行的slaves 执行一次非阻塞的传输. 
 * 而后如果 BGSAVE期间有其他new slave连接过来,则尽快执行一次新的BGSAVE
 *
 * The argument bgsaveerr is C_OK if the background saving succeeded
 * otherwise C_ERR is passed to the function.
 * The 'type' argument is the type of the child that terminated
 * (if it had a disk or socket target). 
 * 参数 bgsaveerr 代表bgsave成功 还是 失败. type 则表示disk or socket
 */
void updateSlavesWaitingBgsave(int bgsaveerr, int type) {
    listNode *ln;
    listIter li;

    listRewind(server.slaves,&li);
    while((ln = listNext(&li))) {
        client *slave = ln->value;

        if (slave->replstate == SLAVE_STATE_WAIT_BGSAVE_END) {
            struct redis_stat buf;

            if (bgsaveerr != C_OK) {
                freeClient(slave);
                serverLog(LL_WARNING,"SYNC failed. BGSAVE child returned an error");
                continue;
            }

            /* If this was an RDB on disk save, we have to prepare to send
             * the RDB from disk to the slave socket. Otherwise if this was
             * already an RDB -> Slaves socket transfer, used in the case of
             * diskless replication, our work is trivial, we can just put
             * the slave online. 
             * 如果RDB是disk保存的, 那么我们需要给slave socket传输RDB数据.
             * 否则对于diskless复制来说,我们的工作无所谓,直接将slave置为online
             */
            if (type == RDB_CHILD_TYPE_SOCKET) {
                serverLog(LL_NOTICE,
                    "Streamed RDB transfer with replica %s succeeded (socket). Waiting for REPLCONF ACK from slave to enable streaming",
                        replicationGetSlaveName(slave));
                /* Note: we wait for a REPLCONF ACK message from the replica in
                 * order to really put it online (install the write handler
                 * so that the accumulated data can be transferred). However
                 * we change the replication state ASAP, since our slave
                 * is technically online now.
                 *
                 * So things work like that:
                 *
                 * 1. We end transferring the RDB file via socket.
                 * 2. The replica is put ONLINE but the write handler
                 *    is not installed.
                 * 3. The replica however goes really online, and pings us
                 *    back via REPLCONF ACK commands.
                 * 4. Now we finally install the write handler, and send
                 *    the buffers accumulated so far to the replica.
                 *
                 * But why we do that? Because the replica, when we stream
                 * the RDB directly via the socket, must detect the RDB
                 * EOF (end of file), that is a special random string at the
                 * end of the RDB (for streamed RDBs we don't know the length
                 * in advance). Detecting such final EOF string is much
                 * simpler and less CPU intensive if no more data is sent
                 * after such final EOF. So we don't want to glue the end of
                 * the RDB transfer with the start of the other replication
                 * data. */
                slave->replstate = SLAVE_STATE_ONLINE;
                slave->repl_put_online_on_ack = 1;
                slave->repl_ack_time = server.unixtime; /* Timeout otherwise. */
            } else {
                if ((slave->repldbfd = open(server.rdb_filename,O_RDONLY)) == -1 ||
                    redis_fstat(slave->repldbfd,&buf) == -1) {
                    freeClient(slave);
                    serverLog(LL_WARNING,"SYNC failed. Can't open/stat DB after BGSAVE: %s", strerror(errno));
                    continue;
                }
                slave->repldboff = 0;
                slave->repldbsize = buf.st_size;
                slave->replstate = SLAVE_STATE_SEND_BULK;
                slave->replpreamble = sdscatprintf(sdsempty(),"$%lld\r\n",
                    (unsigned long long) slave->repldbsize);

                connSetWriteHandler(slave->conn,NULL);
                if (connSetWriteHandler(slave->conn,sendBulkToSlave) == C_ERR) {
                    freeClient(slave);
                    continue;
                }
            }
        }
    }
}

/* Change the current instance replication ID with a new, random one.
 * This will prevent successful PSYNCs between this master and other
 * slaves, so the command should be called when something happens that
 * alters the current story of the dataset. */
//修改server.repid为一个新的. 该函数将阻止当前master 与 其他slave的PSYNCs
void changeReplicationId(void) {
    getRandomHexChars(server.replid,CONFIG_RUN_ID_SIZE);
    server.replid[CONFIG_RUN_ID_SIZE] = '\0';
}

/* Clear (invalidate) the secondary replication ID. This happens, for
 * example, after a full resynchronization, when we start a new replication
 * history. */
void clearReplicationId2(void) {
    memset(server.replid2,'0',sizeof(server.replid));
    server.replid2[CONFIG_RUN_ID_SIZE] = '\0';
    server.second_replid_offset = -1;
}

/* Use the current replication ID / offset as secondary replication
 * ID, and change the current one in order to start a new history.
 * This should be used when an instance is switched from slave to master
 * so that it can serve PSYNC requests performed using the master
 * replication ID. 
 * 将当前replication ID/offset 作为 second replication ID/offset
 * 同时修改当前实例的replication ID/offset.
 * 该函数在实例从slave切换为master时 用到,以便它能服务 PSYNC请求中使用了'我的'master replication ID的slave
 */
void shiftReplicationId(void) {
    memcpy(server.replid2,server.replid,sizeof(server.replid));
    /* We set the second replid offset to the master offset + 1, since
     * the slave will ask for the first byte it has not yet received, so
     * we need to add one to the offset: for example if, as a slave, we are
     * sure we have the same history as the master for 50 bytes, after we
     * are turned into a master, we can accept a PSYNC request with offset
     * 51, since the slave asking has the same history up to the 50th
     * byte, and is asking for the new bytes starting at offset 51. */
    server.second_replid_offset = server.master_repl_offset+1;
    changeReplicationId();
    serverLog(LL_WARNING,"Setting secondary replication ID to %s, valid up to offset: %lld. New replication ID is %s", server.replid2, server.second_replid_offset, server.replid);
}

/* ----------------------------------- SLAVE -------------------------------- */

/* Returns 1 if the given replication state is a handshake state,
 * 0 otherwise. */
int slaveIsInHandshakeState(void) {
    return server.repl_state >= REPL_STATE_RECEIVE_PING_REPLY &&
           server.repl_state <= REPL_STATE_RECEIVE_PSYNC_REPLY;
}

/* Avoid the master to detect the slave is timing out while loading the
 * RDB file in initial synchronization. We send a single newline character
 * that is valid protocol but is guaranteed to either be sent entirely or
 * not, since the byte is indivisible.
 *
 * The function is called in two contexts: while we flush the current
 * data with emptyDb(), and while we load the new data received as an
 * RDB file from the master. */
void replicationSendNewlineToMaster(void) {
    static time_t newline_sent;
    if (time(NULL) != newline_sent) {
        newline_sent = time(NULL);
        /* Pinging back in this stage is best-effort. */
        if (server.repl_transfer_s) connWrite(server.repl_transfer_s, "\n", 1);
    }
}

/* Callback used by emptyDb() while flushing away old data to load
 * the new dataset received by the master. */
void replicationEmptyDbCallback(void *privdata) {
    UNUSED(privdata);
    if (server.repl_state == REPL_STATE_TRANSFER)
        replicationSendNewlineToMaster();
}

/* Once we have a link with the master and the synchronization was
 * performed, this function materializes the master client we store
 * at server.master, starting from the specified file descriptor. 
 * 实例化server.master中的client,从具体化文件描述符开始.
 */
void replicationCreateMasterClient(connection *conn, int dbid) {
    server.master = createClient(conn);
    if (conn)
        connSetReadHandler(server.master->conn, readQueryFromClient);

    /**
     * Important note:
     * The CLIENT_DENY_BLOCKING flag is not, and should not, be set here.
     * For commands like BLPOP, it makes no sense to block the master
     * connection, and such blocking attempt will probably cause deadlock and
     * break the replication. We consider such a thing as a bug because
     * commands as BLPOP should never be sent on the replication link.
     * A possible use-case for blocking the replication link is if a module wants
     * to pass the execution to a background thread and unblock after the
     * execution is done. This is the reason why we allow blocking the replication
     * connection. */
    server.master->flags |= CLIENT_MASTER;

    server.master->authenticated = 1;
    server.master->reploff = server.master_initial_offset;
    server.master->read_reploff = server.master->reploff;
    server.master->user = NULL; /* This client can do everything. */
    memcpy(server.master->replid, server.master_replid,
        sizeof(server.master_replid));
    /* If master offset is set to -1, this master is old and is not
     * PSYNC capable, so we flag it accordingly. */
    if (server.master->reploff == -1)
        server.master->flags |= CLIENT_PRE_PSYNC;
    if (dbid != -1) selectDb(server.master,dbid);
}

/* This function will try to re-enable the AOF file after the
 * master-replica synchronization: if it fails after multiple attempts
 * the replica cannot be considered reliable and exists with an
 * error. */
void restartAOFAfterSYNC() {
    unsigned int tries, max_tries = 10;
    for (tries = 0; tries < max_tries; ++tries) {
        if (startAppendOnly() == C_OK) break;
        serverLog(LL_WARNING,
            "Failed enabling the AOF after successful master synchronization! "
            "Trying it again in one second.");
        sleep(1);
    }
    if (tries == max_tries) {
        serverLog(LL_WARNING,
            "FATAL: this replica instance finished the synchronization with "
            "its master, but the AOF can't be turned on. Exiting now.");
        exit(1);
    }
}

static int useDisklessLoad() {
    /* compute boolean decision to use diskless load */
    int enabled = server.repl_diskless_load == REPL_DISKLESS_LOAD_SWAPDB ||
           (server.repl_diskless_load == REPL_DISKLESS_LOAD_WHEN_DB_EMPTY && dbTotalServerKeyCount()==0);
    /* Check all modules handle read errors, otherwise it's not safe to use diskless load. */
    if (enabled && !moduleAllDatatypesHandleErrors()) {
        serverLog(LL_WARNING,
            "Skipping diskless-load because there are modules that don't handle read errors.");
        enabled = 0;
    }
    return enabled;
}

/* Helper function for readSyncBulkPayload() to make backups of the current
 * databases before socket-loading the new ones. The backups may be restored
 * by disklessLoadRestoreBackup or freed by disklessLoadDiscardBackup later. */
dbBackup *disklessLoadMakeBackup(void) {
    return backupDb();
}

/* Helper function for readSyncBulkPayload(): when replica-side diskless
 * database loading is used, Redis makes a backup of the existing databases
 * before loading the new ones from the socket.
 *
 * If the socket loading went wrong, we want to restore the old backups
 * into the server databases. */
void disklessLoadRestoreBackup(dbBackup *backup) {
    restoreDbBackup(backup);
}

/* Helper function for readSyncBulkPayload() to discard our old backups
 * when the loading succeeded. */
void disklessLoadDiscardBackup(dbBackup *backup, int flag) {
    discardDbBackup(backup, flag, replicationEmptyDbCallback);
}

/* Asynchronously read the SYNC payload we receive from a master 
* 从master异步接收全量数据
*/
#define REPL_MAX_WRITTEN_BEFORE_FSYNC (1024*1024*8) /* 8 MB */
void readSyncBulkPayload(connection *conn) {
    char buf[PROTO_IOBUF_LEN];
    ssize_t nread, readlen, nwritten;
    int use_diskless_load = useDisklessLoad();
    dbBackup *diskless_load_backup = NULL;
    int empty_db_flags = server.repl_slave_lazy_flush ? EMPTYDB_ASYNC :
                                                        EMPTYDB_NO_FLAGS;
    off_t left;

    /* Static vars used to hold the EOF mark, and the last bytes received
     * from the server: when they match, we reached the end of the transfer.
     * 静态变量用于保存EOF标记 和 从server接收到的最后几个字节: 当他们匹配，意味着我们传输结束了 
     */
    static char eofmark[CONFIG_RUN_ID_SIZE];
    static char lastbytes[CONFIG_RUN_ID_SIZE];
    static int usemark = 0;

    /* If repl_transfer_size == -1 we still have to read the bulk length
     * from the master reply. 
     * 如果 repl_transfer_size==-1,我们依然必须从master的回复中读取bulk length
     */
    if (server.repl_transfer_size == -1) {
        if (connSyncReadLine(conn,buf,1024,server.repl_syncio_timeout*1000) == -1) {
            serverLog(LL_WARNING,
                "I/O error reading bulk count from MASTER: %s",
                strerror(errno));
            goto error;
        }

        if (buf[0] == '-') {
            serverLog(LL_WARNING,
                "MASTER aborted replication with an error: %s",
                buf+1);
            goto error;
        } else if (buf[0] == '\0') {
            /* At this stage just a newline works as a PING in order to take
             * the connection live. So we refresh our last interaction
             * timestamp. */
            server.repl_transfer_lastio = server.unixtime;
            return;
        } else if (buf[0] != '$') {
            serverLog(LL_WARNING,"Bad protocol from MASTER, the first byte is not '$' (we received '%s'), are you sure the host and port are right?", buf);
            goto error;
        }

        /* There are two possible forms for the bulk payload. One is the
         * usual $<count> bulk format. The other is used for diskless transfers
         * when the master does not know beforehand the size of the file to
         * transfer. In the latter case, the following format is used:
         *
         * $EOF:<40 bytes delimiter>
         *
         * At the end of the file the announced delimiter is transmitted. The
         * delimiter is long and random enough that the probability of a
         * collision with the actual file content can be ignored. 
         * 
         * 对批量payload来说，这里有两种可能的格式:
         * 一种是常规的 $<count> 批量格式;
         * 另一种用于diskless传输,因为master并不知道传输文件的大小,在这种情况下,如下格式会被使用: $EOF:<40 bytes delimiteer>
         * 在文件数据传输的最后,end file delimiter会被传输.
         */
        if (strncmp(buf+1,"EOF:",4) == 0 && strlen(buf+5) >= CONFIG_RUN_ID_SIZE) {
            usemark = 1;
            memcpy(eofmark,buf+5,CONFIG_RUN_ID_SIZE);
            memset(lastbytes,0,CONFIG_RUN_ID_SIZE);
            /* Set any repl_transfer_size to avoid entering this code path
             * at the next call. */
            server.repl_transfer_size = 0;
            serverLog(LL_NOTICE,
                "MASTER <-> REPLICA sync: receiving streamed RDB from master with EOF %s",
                use_diskless_load? "to parser":"to disk");
        } else {
            usemark = 0;
            server.repl_transfer_size = strtol(buf+1,NULL,10);
            serverLog(LL_NOTICE,
                "MASTER <-> REPLICA sync: receiving %lld bytes from master %s",
                (long long) server.repl_transfer_size,
                use_diskless_load? "to parser":"to disk");
        }
        return;
    }

    if (!use_diskless_load) {
        /* Read the data from the socket, store it to a file and search
         * for the EOF. 
         * 从master socket中读取数据,将其保存到文件中 同时搜寻文件 结束标识
         */
        if (usemark) {
            readlen = sizeof(buf); //diskless模式,读满buff
        } else {
            //disk模式,要么读满buff 要么读取剩余读取个数
            left = server.repl_transfer_size - server.repl_transfer_read;
            readlen = (left < (signed)sizeof(buf)) ? left : (signed)sizeof(buf);
        }

        nread = connRead(conn,buf,readlen);
        if (nread <= 0) {
            if (connGetState(conn) == CONN_STATE_CONNECTED) {
                /* equivalent to EAGAIN */
                return;
            }
            serverLog(LL_WARNING,"I/O error trying to sync with MASTER: %s",
                (nread == -1) ? strerror(errno) : "connection lost");
            cancelReplicationHandshake(1);
            return;
        }
        atomicIncr(server.stat_net_input_bytes, nread);

        /* When a mark is used, we want to detect EOF asap in order to avoid
         * writing the EOF mark into the file... 
         * 当文件标识被使用时,我们希望尽快探测EOF标识,避免EOF标识被写入到文件中
         */
        int eof_reached = 0;

        if (usemark) {
            /* Update the last bytes array, and check if it matches our
             * delimiter. */
            if (nread >= CONFIG_RUN_ID_SIZE) {
                memcpy(lastbytes,buf+nread-CONFIG_RUN_ID_SIZE,
                       CONFIG_RUN_ID_SIZE);
            } else {
                int rem = CONFIG_RUN_ID_SIZE-nread;
                memmove(lastbytes,lastbytes+nread,rem);
                memcpy(lastbytes+rem,buf,nread);
            }
            if (memcmp(lastbytes,eofmark,CONFIG_RUN_ID_SIZE) == 0)
                eof_reached = 1;
        }

        /* Update the last I/O time for the replication transfer (used in
         * order to detect timeouts during replication), and write what we
         * got from the socket to the dump file on disk. 
         * 更新server.repl_transfer_lastio复制传输流时间 以便判断复制超时时间
         * 并将从socket中获取到的数据写入到 disk dump file中
         */
        server.repl_transfer_lastio = server.unixtime;
        if ((nwritten = write(server.repl_transfer_fd,buf,nread)) != nread) {
            serverLog(LL_WARNING,
                "Write error or short write writing to the DB dump file "
                "needed for MASTER <-> REPLICA synchronization: %s",
                (nwritten == -1) ? strerror(errno) : "short write");
            goto error;
        }
        server.repl_transfer_read += nread;

        /* Delete the last 40 bytes from the file if we reached EOF. 达到文件最后后删除文件最后的40bytes*/
        if (usemark && eof_reached) {
            if (ftruncate(server.repl_transfer_fd,
                server.repl_transfer_read - CONFIG_RUN_ID_SIZE) == -1)
            {
                serverLog(LL_WARNING,
                    "Error truncating the RDB file received from the master "
                    "for SYNC: %s", strerror(errno));
                goto error;
            }
        }

        /* Sync data on disk from time to time, otherwise at the end of the
         * transfer we may suffer a big delay as the memory buffers are copied
         * into the actual disk. 
         * 将接收到的数据偶尔fsync到disk,否则等我们最后再执行fsync,我们会可能会遇到一个很大的延迟
         */
        if (server.repl_transfer_read >=
            server.repl_transfer_last_fsync_off + REPL_MAX_WRITTEN_BEFORE_FSYNC)
        {
            off_t sync_size = server.repl_transfer_read -
                              server.repl_transfer_last_fsync_off;
            rdb_fsync_range(server.repl_transfer_fd,
                server.repl_transfer_last_fsync_off, sync_size);
            server.repl_transfer_last_fsync_off += sync_size;
        }

        /* Check if the transfer is now complete */
        if (!usemark) {
            if (server.repl_transfer_read == server.repl_transfer_size)
                eof_reached = 1;
        }

        /* If the transfer is yet not complete, we need to read more, so
         * return ASAP and wait for the handler to be called again. 
         * 如果还没接收完成,我们则需要读取更多,所以尽快return 以便尽快下一次调用
         */
        if (!eof_reached) return;
    }

    /* We reach this point in one of the following cases:
     * 下面情况下我们会到达这里:
     *
     * 1. The replica is using diskless replication, that is, it reads data
     *    directly from the socket to the Redis memory, without using
     *    a temporary RDB file on disk. In that case we just block and
     *    read everything from the socket.
     * 1. diskless 复制模式, 直接从socket中读取数据到redis memmory,不使用磁盘临时RDB文件.
     * 这种情况下,我们会阻塞并从socket中读取所有数据.
     *
     * 2. Or when we are done reading from the socket to the RDB file, in
     *    such case we want just to read the RDB file in memory. 
     * 2. 非diskless模式,我们已经从socket中将数据读取到RDB文件中,这种情况下我们将RDB文件中数据读取到内存中?
     */
    serverLog(LL_NOTICE, "MASTER <-> REPLICA sync: Flushing old data");

    /* We need to stop any AOF rewriting child before flushing and parsing
     * the RDB, otherwise we'll create a copy-on-write disaster. 
     * 在flush当前数据 和 解析RDB文件前, 我们需要stop AOF rewrite.
     * 否则可能会造成 copy-on-write 灾难
     */
    if (server.aof_state != AOF_OFF) stopAppendOnly();

    /* When diskless RDB loading is used by replicas, it may be configured
     * in order to save the current DB instead of throwing it away,
     * so that we can restore it in case of failed transfer. 
     * 当slave使用diskless 加载RDB文件时,它可能会被配置保存当前DB而不是直接将其丢弃.
     * 以便我们在传输失败时,恢复数据.
     */
    if (use_diskless_load &&
        server.repl_diskless_load == REPL_DISKLESS_LOAD_SWAPDB)
    {
        /* Create a backup of server.db[] and initialize to empty
         * dictionaries. */
        diskless_load_backup = disklessLoadMakeBackup();
    }
    /* We call to emptyDb even in case of REPL_DISKLESS_LOAD_SWAPDB
     * (Where disklessLoadMakeBackup left server.db empty) because we
     * want to execute all the auxiliary logic of emptyDb (Namely,
     * fire module events) 
     * 即使在 REPL_DISKLESS_LOAD_SWAPDB（其中 disklessLoadMakeBackup 使 server.db 为空）的情况下，
     * 我们也会调用 emptyDb，因为我们要执行 emptyDb 的所有辅助逻辑（即触发module events）
     */
    emptyDb(-1,empty_db_flags,replicationEmptyDbCallback);

    /* Before loading the DB into memory we need to delete the readable
     * handler, otherwise it will get called recursively since
     * rdbLoad() will call the event loop to process events from time to
     * time for non blocking loading. 
     * 在将DB数据加载到内存中之前,我们需要删除 readable handler.
     * 否则它将被递归调用,因为 rdbLoad()会不时调用event loop来处理events以便进行非阻塞加载.
     */
    connSetReadHandler(conn, NULL);
    serverLog(LL_NOTICE, "MASTER <-> REPLICA sync: Loading DB in memory");
    rdbSaveInfo rsi = RDB_SAVE_INFO_INIT;
    if (use_diskless_load) {
        //diskless模式,将socket中接收到的数据直接加载到内存中
        rio rdb;
        rioInitWithConn(&rdb,conn,server.repl_transfer_size);

        /* Put the socket in blocking mode to simplify RDB transfer.
         * We'll restore it when the RDB is received. 
         * 将conn设置为阻塞模式，我们会从接收到的数据中直接进行恢复
         */
        connBlock(conn);
        connRecvTimeout(conn, server.repl_timeout*1000);
        startLoading(server.repl_transfer_size, RDBFLAGS_REPLICATION);

        if (rdbLoadRio(&rdb,RDBFLAGS_REPLICATION,&rsi) != C_OK) {
            /* RDB loading failed. */
            stopLoading(0);
            serverLog(LL_WARNING,
                "Failed trying to load the MASTER synchronization DB "
                "from socket");
            cancelReplicationHandshake(1);
            rioFreeConn(&rdb, NULL);

            /* Remove the half-loaded data in case we started with
             * an empty replica. */
            emptyDb(-1,empty_db_flags,replicationEmptyDbCallback);

            if (server.repl_diskless_load == REPL_DISKLESS_LOAD_SWAPDB) {
                /* Restore the backed up databases. */
                disklessLoadRestoreBackup(diskless_load_backup);
            }

            /* Note that there's no point in restarting the AOF on SYNC
             * failure, it'll be restarted when sync succeeds or the replica
             * gets promoted. */
            return;
        }

        /* RDB loading succeeded if we reach this point. */
        if (server.repl_diskless_load == REPL_DISKLESS_LOAD_SWAPDB) {
            /* Delete the backup databases we created before starting to load
             * the new RDB. Now the RDB was loaded with success so the old
             * data is useless. 
             * 
             */
            disklessLoadDiscardBackup(diskless_load_backup, empty_db_flags);
        }

        /* Verify the end mark is correct. */
        if (usemark) {
            if (!rioRead(&rdb,buf,CONFIG_RUN_ID_SIZE) ||
                memcmp(buf,eofmark,CONFIG_RUN_ID_SIZE) != 0)
            {
                stopLoading(0);
                serverLog(LL_WARNING,"Replication stream EOF marker is broken");
                cancelReplicationHandshake(1);
                rioFreeConn(&rdb, NULL);
                return;
            }
        }

        stopLoading(1);

        /* Cleanup and restore the socket to the original state to continue
         * with the normal replication. */
        rioFreeConn(&rdb, NULL);
        connNonBlock(conn);
        connRecvTimeout(conn,0);
    } else {
        //开始加载RDB文件
        /* Ensure background save doesn't overwrite synced data */
        if (server.child_type == CHILD_TYPE_RDB) {
            serverLog(LL_NOTICE,
                "Replica is about to load the RDB file received from the "
                "master, but there is a pending RDB child running. "
                "Killing process %ld and removing its temp file to avoid "
                "any race",
                (long) server.child_pid);
            killRDBChild();
        }

        /* Make sure the new file (also used for persistence) is fully synced
         * (not covered by earlier calls to rdb_fsync_range). */
        if (fsync(server.repl_transfer_fd) == -1) {
            serverLog(LL_WARNING,
                "Failed trying to sync the temp DB to disk in "
                "MASTER <-> REPLICA synchronization: %s",
                strerror(errno));
            cancelReplicationHandshake(1);
            return;
        }

        /* Rename rdb like renaming rewrite aof asynchronously. 将rdb临时文件 rename为正常的rdb文件 */
        int old_rdb_fd = open(server.rdb_filename,O_RDONLY|O_NONBLOCK);
        if (rename(server.repl_transfer_tmpfile,server.rdb_filename) == -1) {
            serverLog(LL_WARNING,
                "Failed trying to rename the temp DB into %s in "
                "MASTER <-> REPLICA synchronization: %s",
                server.rdb_filename, strerror(errno));
            cancelReplicationHandshake(1);
            if (old_rdb_fd != -1) close(old_rdb_fd);
            return;
        }
        /* Close old rdb asynchronously. 异步关闭旧的rdb文件 */
        if (old_rdb_fd != -1) bioCreateCloseJob(old_rdb_fd);

        if (rdbLoad(server.rdb_filename,&rsi,RDBFLAGS_REPLICATION) != C_OK) {
            serverLog(LL_WARNING,
                "Failed trying to load the MASTER synchronization "
                "DB from disk");
            cancelReplicationHandshake(1);
            if (server.rdb_del_sync_files && allPersistenceDisabled()) {
                serverLog(LL_NOTICE,"Removing the RDB file obtained from "
                                    "the master. This replica has persistence "
                                    "disabled");
                bg_unlink(server.rdb_filename);
            }
            /* Note that there's no point in restarting the AOF on sync failure,
               it'll be restarted when sync succeeds or replica promoted. */
            return;
        }

        /* Cleanup. */
        if (server.rdb_del_sync_files && allPersistenceDisabled()) {
            serverLog(LL_NOTICE,"Removing the RDB file obtained from "
                                "the master. This replica has persistence "
                                "disabled");
            bg_unlink(server.rdb_filename);
        }

        zfree(server.repl_transfer_tmpfile);
        close(server.repl_transfer_fd);
        server.repl_transfer_fd = -1;
        server.repl_transfer_tmpfile = NULL;
    }

    /* Final setup of the connected slave <- master link */
    replicationCreateMasterClient(server.repl_transfer_s,rsi.repl_stream_db);
    server.repl_state = REPL_STATE_CONNECTED;
    server.repl_down_since = 0;

    /* Fire the master link modules event. */
    moduleFireServerEvent(REDISMODULE_EVENT_MASTER_LINK_CHANGE,
                          REDISMODULE_SUBEVENT_MASTER_LINK_UP,
                          NULL);

    /* After a full resynchronization we use the replication ID and
     * offset of the master. The secondary ID / offset are cleared since
     * we are starting a new history. 
     * 全量重同步完成后,我们使用 master的repl id 和 repl offset作为自己的repl id和 offset.
     * 同时清空 replid2/repl2-offset
     */
    memcpy(server.replid,server.master->replid,sizeof(server.replid));
    server.master_repl_offset = server.master->reploff;
    clearReplicationId2();

    /* Let's create the replication backlog if needed. Slaves need to
     * accumulate the backlog regardless of the fact they have sub-slaves
     * or not, in order to behave correctly if they are promoted to
     * masters after a failover. 
     * 创建replication backlog, slave无论是否有sub-slaves 都应该创建backlog.
     * 以便在failover时,slave能提升为master
     */
    if (server.repl_backlog == NULL) createReplicationBacklog();
    serverLog(LL_NOTICE, "MASTER <-> REPLICA sync: Finished with success");

    if (server.supervised_mode == SUPERVISED_SYSTEMD) {
        redisCommunicateSystemd("STATUS=MASTER <-> REPLICA sync: Finished with success. Ready to accept connections in read-write mode.\n");
    }

    /* Send the initial ACK immediately to put this replica in online state. */
    if (usemark) replicationSendAck();

    /* Restart the AOF subsystem now that we finished the sync. This
     * will trigger an AOF rewrite, and when done will start appending
     * to the new file. 
     * sync完成后,重启AOF. 这会触发aof rewrite,同时aof rewrite完成后继续追加到新文件.
     */
    if (server.aof_enabled) restartAOFAfterSYNC();
    return;

error:
    cancelReplicationHandshake(1);
    return;
}

char *receiveSynchronousResponse(connection *conn) {
    char buf[256];
    /* Read the reply from the server. */
    if (connSyncReadLine(conn,buf,sizeof(buf),server.repl_syncio_timeout*1000) == -1)
    {
        return sdscatprintf(sdsempty(),"-Reading from master: %s",
                strerror(errno));
    }
    server.repl_transfer_lastio = server.unixtime;
    return sdsnew(buf);
}

/* Send a pre-formatted multi-bulk command to the connection. */
char* sendCommandRaw(connection *conn, sds cmd) {
    if (connSyncWrite(conn,cmd,sdslen(cmd),server.repl_syncio_timeout*1000) == -1) {
        return sdscatprintf(sdsempty(),"-Writing to master: %s",
                connGetLastError(conn));
    }
    return NULL;
}

/* Compose a multi-bulk command and send it to the connection.
 * Used to send AUTH and REPLCONF commands to the master before starting the
 * replication.
 *
 * Takes a list of char* arguments, terminated by a NULL argument.
 *
 * The command returns an sds string representing the result of the
 * operation. On error the first byte is a "-".
 */
char *sendCommand(connection *conn, ...) {
    va_list ap;
    sds cmd = sdsempty();
    sds cmdargs = sdsempty();
    size_t argslen = 0;
    char *arg;

    /* Create the command to send to the master, we use redis binary
     * protocol to make sure correct arguments are sent. This function
     * is not safe for all binary data. */
    va_start(ap,conn);
    while(1) {
        arg = va_arg(ap, char*);
        if (arg == NULL) break;
        cmdargs = sdscatprintf(cmdargs,"$%zu\r\n%s\r\n",strlen(arg),arg);
        argslen++;
    }

    cmd = sdscatprintf(cmd,"*%zu\r\n",argslen);
    cmd = sdscatsds(cmd,cmdargs);
    sdsfree(cmdargs);

    va_end(ap);
    char* err = sendCommandRaw(conn, cmd);
    sdsfree(cmd);
    if(err)
        return err;
    return NULL;
}

/* Compose a multi-bulk command and send it to the connection. 
 * Used to send AUTH and REPLCONF commands to the master before starting the
 * replication.
 *
 * argv_lens is optional, when NULL, strlen is used.
 *
 * The command returns an sds string representing the result of the
 * operation. On error the first byte is a "-".
 */
char *sendCommandArgv(connection *conn, int argc, char **argv, size_t *argv_lens) {
    sds cmd = sdsempty();
    char *arg;
    int i;

    /* Create the command to send to the master. */
    cmd = sdscatfmt(cmd,"*%i\r\n",argc);
    for (i=0; i<argc; i++) {
        int len;
        arg = argv[i];
        len = argv_lens ? argv_lens[i] : strlen(arg);
        cmd = sdscatfmt(cmd,"$%i\r\n",len);
        cmd = sdscatlen(cmd,arg,len);
        cmd = sdscatlen(cmd,"\r\n",2);
    }
    char* err = sendCommandRaw(conn, cmd);
    sdsfree(cmd);
    if (err)
        return err;
    return NULL;
}

/* Try a partial resynchronization with the master if we are about to reconnect.
 * If there is no cached master structure, at least try to issue a
 * "PSYNC ? -1" command in order to trigger a full resync using the PSYNC
 * command in order to obtain the master replid and the master replication
 * global offset.
 * 如果我们即将重新连接, 先尝试与master进行部分重新同步. 如果没有cached master结构,
 * 至少尝试发出 PSYNC ? -1命令触发完全重新同步以获得 master replid 和 master replication offset
 *
 * This function is designed to be called from syncWithMaster(), so the
 * following assumptions are made:
 * 该函数设计为从 syncWithMaster()中调用, 所以做如下假设:
 *
 * 1) We pass the function an already connected socket "fd". 
 * 传递给函数的是一个已连接的socket fd
 * 2) This function does not close the file descriptor "fd". However in case
 *    of successful partial resynchronization, the function will reuse
 *    'fd' as file descriptor of the server.master client structure.
 * 该函数不会关闭文件描述符 fd. 然而在部分重同步成功的场景中,函数会复用'fd'作为server.mater 客户端结构中的文件描述符.
 *
 * The function is split in two halves: if read_reply is 0, the function
 * writes the PSYNC command on the socket, and a new function call is
 * needed, with read_reply set to 1, in order to read the reply of the
 * command. This is useful in order to support non blocking operations, so
 * that we write, return into the event loop, and read when there are data.
 * 该函数分为两部分: 
 * 如果read_reply=0,则函数将PSYNC命令写入socket,并且需要一次新的函数调用(调用时read_reply=1,以便读取这个命令的结果)
 * 这个是非常有用的,目的是非阻塞操作,所以我们write => return into event loop=> 当有数据时read
 *
 * When read_reply is 0 the function returns PSYNC_WRITE_ERR if there
 * was a write error, or PSYNC_WAIT_REPLY to signal we need another call
 * with read_reply set to 1. However even when read_reply is set to 1
 * the function may return PSYNC_WAIT_REPLY again to signal there were
 * insufficient data to read to complete its work. We should re-enter
 * into the event loop and wait in such a case.
 * 当read_reply==0时,如果写发生了错误返回 PSYNC_WRITE_ERR, 或者返回 PSYNC_WAIT_REPLY去告诉下一次调用 read_reply应该设置为1.
 * 尽管 read_reply=1, 函数可能再次返回 PSYNC_WAIT_REPLY 以便通知没有完整数据供读取. 所以我们需要再次进入
 *
 * The function returns 函数返回值:
 *
 * PSYNC_CONTINUE: If the PSYNC command succeeded and we can continue.
 * PSYNC_FULLRESYNC: If PSYNC is supported but a full resync is needed.
 *                   In this case the master replid and global replication
 *                   offset is saved.
 * PSYNC_NOT_SUPPORTED: If the server does not understand PSYNC at all and
 *                      the caller should fall back to SYNC.
 * PSYNC_WRITE_ERROR: There was an error writing the command to the socket.
 * PSYNC_WAIT_REPLY: Call again the function with read_reply set to 1.
 * PSYNC_TRY_LATER: Master is currently in a transient error condition.
 * 
 * PSYNC_CONTINUE: PSYNC命令成功了,我们可以继续;
 * PSYNC_FULLRESYNC: PSYNC命令是支持的，不过需要resync. 这种情况下, master replid 和 replication offset会被保存起来
 * PSYNC_NOT_SUPPORTED: 如果server不认识PSYNC命令，那么调用者应该回退到SYNC
 * PSYNC_WRITE_ERROR: 将命令写到socket过程中,发生了错误;
 * PSYNC_WAIT_REPLY: 将read_reply设置为1,再次调用该函数;
 * PSYNC_TRY_LATER: 主机当前处于transient error状态
 * 
 * Notable side effects:
 *
 * 1) As a side effect of the function call the function removes the readable
 *    event handler from "fd", unless the return value is PSYNC_WAIT_REPLY.
 *    副作用一:函数后调用会删除 fd 上面的readable event handler, 除非返回值是 PSYNC_WAIT_REPLY
 * 2) server.master_initial_offset is set to the right value according
 *    to the master reply. This will be used to populate the 'server.master'
 *    structure replication offset.
 *    根据master的回复,server.master_initial_offset 会被设置上正确的值.
 *    这将用于填充 server.master 结构的replication offset.
 */

#define PSYNC_WRITE_ERROR 0
#define PSYNC_WAIT_REPLY 1
#define PSYNC_CONTINUE 2
#define PSYNC_FULLRESYNC 3
#define PSYNC_NOT_SUPPORTED 4
#define PSYNC_TRY_LATER 5
int slaveTryPartialResynchronization(connection *conn, int read_reply) {
    char *psync_replid;
    char psync_offset[32];
    sds reply;

    /* Writing half */
    if (!read_reply) {
        /* Initially set master_initial_offset to -1 to mark the current
         * master replid and offset as not valid. Later if we'll be able to do
         * a FULL resync using the PSYNC command we'll set the offset at the
         * right value, so that this information will be propagated to the
         * client structure representing the master into server.master. 
         * 最初我们将 master_initial_offset 设置为 -1 以便标记当前master的 replid 和 offset是无效的
         * 而后,我们将能够使用PSYNC命令进行完全重同步,我们会将偏移设置为正确值.
         * 以便将此信息传播到 代表master的client的 server.master中
         */
        server.master_initial_offset = -1;

        if (server.cached_master) {
            psync_replid = server.cached_master->replid;
            snprintf(psync_offset,sizeof(psync_offset),"%lld", server.cached_master->reploff+1);
            serverLog(LL_NOTICE,"Trying a partial resynchronization (request %s:%s).", psync_replid, psync_offset);
        } else {
            serverLog(LL_NOTICE,"Partial resynchronization not possible (no cached master)");
            psync_replid = "?";
            memcpy(psync_offset,"-1",3);
        }

        /* Issue the PSYNC command, if this is a master with a failover in
         * progress then send the failover argument to the replica to cause it
         * to become a master 
         * 发送PSYNC命令，如果这是一个正在进行failover的master,则将failover参数发送给slave 使其变成master
         */
        if (server.failover_state == FAILOVER_IN_PROGRESS) {
            reply = sendCommand(conn,"PSYNC",psync_replid,psync_offset,"FAILOVER",NULL);
        } else {
            reply = sendCommand(conn,"PSYNC",psync_replid,psync_offset,NULL);
        }

        if (reply != NULL) {
            serverLog(LL_WARNING,"Unable to send PSYNC to master: %s",reply);
            sdsfree(reply);
            connSetReadHandler(conn, NULL);
            return PSYNC_WRITE_ERROR;
        }
        return PSYNC_WAIT_REPLY;
    }

    /* Reading half */
    reply = receiveSynchronousResponse(conn);
    if (sdslen(reply) == 0) {
        /* The master may send empty newlines after it receives PSYNC
         * and before to reply, just to keep the connection alive. 
         * 在接收到PSYNC后,在回复前,master可能会发送空行,此时只需要保持连接活着就好
         */
        sdsfree(reply);
        return PSYNC_WAIT_REPLY;
    }

    //conn置空ReadHandler,
    connSetReadHandler(conn, NULL);

    if (!strncmp(reply,"+FULLRESYNC",11)) {
        char *replid = NULL, *offset = NULL;

        /* FULL RESYNC, parse the reply in order to extract the replid
         * and the replication offset. 
         * FULL RESYNC,解析回复并从中提取出 replid 和 replication offset
         */
        replid = strchr(reply,' ');
        if (replid) {
            replid++;
            offset = strchr(replid,' ');
            if (offset) offset++;
        }
        if (!replid || !offset || (offset-replid-1) != CONFIG_RUN_ID_SIZE) {
            serverLog(LL_WARNING,
                "Master replied with wrong +FULLRESYNC syntax.");
            /* This is an unexpected condition, actually the +FULLRESYNC
             * reply means that the master supports PSYNC, but the reply
             * format seems wrong. To stay safe we blank the master
             * replid to make sure next PSYNCs will fail. */
            memset(server.master_replid,0,CONFIG_RUN_ID_SIZE+1);
        } else {
            memcpy(server.master_replid, replid, offset-replid-1);
            server.master_replid[CONFIG_RUN_ID_SIZE] = '\0';
            server.master_initial_offset = strtoll(offset,NULL,10);
            serverLog(LL_NOTICE,"Full resync from master: %s:%lld",
                server.master_replid,
                server.master_initial_offset);
        }
        /* We are going to full resync, discard the cached master structure. 
        * 释放cached master
        */
        replicationDiscardCachedMaster();
        sdsfree(reply);
        return PSYNC_FULLRESYNC;
    }

    if (!strncmp(reply,"+CONTINUE",9)) {
        /* Partial resync was accepted. 可以继续部分重同步 */
        serverLog(LL_NOTICE,
            "Successful partial resynchronization with master.");

        /* Check the new replication ID advertised by the master. If it
         * changed, we need to set the new ID as primary ID, and set
         * secondary ID as the old master ID up to the current offset, so
         * that our sub-slaves will be able to PSYNC with us after a
         * disconnection. 
         * 检查master返回的 new replication ID. 如果发生了变化,我们需要new replication ID作为primary ID,
         * 同时设置 old master ID为 secondary ID. 直到当前的offset(我的理解offset是不变的)
         * 以便我们 sub-slaves 在断开连接后能与我们进行 PSYNC
         */
        char *start = reply+10;
        char *end = reply+9;
        while(end[0] != '\r' && end[0] != '\n' && end[0] != '\0') end++;
        if (end-start == CONFIG_RUN_ID_SIZE) {
            char new[CONFIG_RUN_ID_SIZE+1];
            memcpy(new,start,CONFIG_RUN_ID_SIZE);
            new[CONFIG_RUN_ID_SIZE] = '\0';

            if (strcmp(new,server.cached_master->replid)) {
                /* Master ID changed. */
                serverLog(LL_WARNING,"Master replication ID changed to %s",new);

                /* Set the old ID as our ID2, up to the current offset+1. */
                memcpy(server.replid2,server.cached_master->replid,
                    sizeof(server.replid2));
                server.second_replid_offset = server.master_repl_offset+1;

                /* Update the cached master ID and our own primary ID to the
                 * new one. */
                memcpy(server.replid,new,sizeof(server.replid));
                memcpy(server.cached_master->replid,new,sizeof(server.replid));

                /* Disconnect all the sub-slaves: they need to be notified. 断开所有子slave的连接*/
                disconnectSlaves();
            }
        }

        /* Setup the replication to continue. */
        sdsfree(reply);
        replicationResurrectCachedMaster(conn);

        /* If this instance was restarted and we read the metadata to
         * PSYNC from the persistence file, our replication backlog could
         * be still not initialized. Create it. */
        if (server.repl_backlog == NULL) createReplicationBacklog();
        return PSYNC_CONTINUE;
    }

    /* If we reach this point we received either an error (since the master does
     * not understand PSYNC or because it is in a special state and cannot
     * serve our request), or an unexpected reply from the master.
     *
     * Return PSYNC_NOT_SUPPORTED on errors we don't understand, otherwise
     * return PSYNC_TRY_LATER if we believe this is a transient error. */

    if (!strncmp(reply,"-NOMASTERLINK",13) ||
        !strncmp(reply,"-LOADING",8))
    {
        serverLog(LL_NOTICE,
            "Master is currently unable to PSYNC "
            "but should be in the future: %s", reply);
        sdsfree(reply);
        return PSYNC_TRY_LATER;
    }

    if (strncmp(reply,"-ERR",4)) {
        /* If it's not an error, log the unexpected event. */
        serverLog(LL_WARNING,
            "Unexpected reply to PSYNC from master: %s", reply);
    } else {
        serverLog(LL_NOTICE,
            "Master does not support PSYNC or is in "
            "error state (reply: %s)", reply);
    }
    sdsfree(reply);
    replicationDiscardCachedMaster();
    return PSYNC_NOT_SUPPORTED;
}

/* This handler fires when the non blocking connect was able to
 * establish a connection with the master. 
 * 当non blocking的conn能和master建立连接时,此函数会被触发
 */
void syncWithMaster(connection *conn) {
    char tmpfile[256], *err = NULL;
    int dfd = -1, maxtries = 5;
    int psync_result;

    /* If this event fired after the user turned the instance into a master
     * with SLAVEOF NO ONE we must just return ASAP. 
     * 如果用户通过slaveof no one命令将实例转变为master, 该事件就会触发,我们需要尽快return
     */
    if (server.repl_state == REPL_STATE_NONE) {
        connClose(conn);
        return;
    }

    /* Check for errors in the socket: after a non blocking connect() we
     * may find that the socket is in error state. 
     * 检查连接状态是否是ok的
     */
    if (connGetState(conn) != CONN_STATE_CONNECTED) {
        serverLog(LL_WARNING,"Error condition on socket for SYNC: %s",
                connGetLastError(conn));
        goto error;
    }

    /* Send a PING to check the master is able to reply without errors. 发送 PING 命令*/
    if (server.repl_state == REPL_STATE_CONNECTING) {
        serverLog(LL_NOTICE,"Non blocking connect for SYNC fired the event.");
        /* Delete the writable event so that the readable event remains
         * registered and we can wait for the PONG reply. 
         * 删除 可写事件 回调,保留 可读事件 回调. 我们等待 PONG 回复
         */
        connSetReadHandler(conn, syncWithMaster);
        connSetWriteHandler(conn, NULL);
        server.repl_state = REPL_STATE_RECEIVE_PING_REPLY;
        /* Send the PING, don't check for errors at all, we have the timeout
         * that will take care about this. */
        err = sendCommand(conn,"PING",NULL);
        if (err) goto write_error;
        return;
    }

    /* Receive the PONG command. 接收到PONG回复*/
    if (server.repl_state == REPL_STATE_RECEIVE_PING_REPLY) {
        err = receiveSynchronousResponse(conn);

        /* We accept only two replies as valid, a positive +PONG reply
         * (we just check for "+") or an authentication error.
         * 我们接收到两个有效回复: +PONG 回复 or 登录错误 都是ok的,如果是其他回复,则表示出错了
         * Note that older versions of Redis replied with "operation not
         * permitted" instead of using a proper error code, so we test
         * both. */
        if (err[0] != '+' &&
            strncmp(err,"-NOAUTH",7) != 0 &&
            strncmp(err,"-NOPERM",7) != 0 &&
            strncmp(err,"-ERR operation not permitted",28) != 0)
        {
            serverLog(LL_WARNING,"Error reply to PING from master: '%s'",err);
            sdsfree(err);
            goto error;
        } else {
            serverLog(LL_NOTICE,
                "Master replied to PING, replication can continue...");
        }
        sdsfree(err);
        err = NULL;
        server.repl_state = REPL_STATE_SEND_HANDSHAKE;
    }

    if (server.repl_state == REPL_STATE_SEND_HANDSHAKE) {
        /* AUTH with the master if required.  向master发送AUTH 命令*/
        if (server.masterauth) {
            char *args[3] = {"AUTH",NULL,NULL};
            size_t lens[3] = {4,0,0};
            int argc = 1;
            if (server.masteruser) {
                args[argc] = server.masteruser;
                lens[argc] = strlen(server.masteruser);
                argc++;
            }
            args[argc] = server.masterauth;
            lens[argc] = sdslen(server.masterauth);
            argc++;
            err = sendCommandArgv(conn, argc, args, lens);
            if (err) goto write_error;
        }

        /* Set the slave port, so that Master's INFO command can list the
         * slave listening port correctly. 
         * 向master发送 REPLCONF listening-port $slaveport 命令,便于master知道slave的端口
         */
        {
            int port;
            if (server.slave_announce_port)
                port = server.slave_announce_port;
            else if (server.tls_replication && server.tls_port)
                port = server.tls_port;
            else
                port = server.port;
            sds portstr = sdsfromlonglong(port);
            err = sendCommand(conn,"REPLCONF",
                    "listening-port",portstr, NULL);
            sdsfree(portstr);
            if (err) goto write_error;
        }

        /* Set the slave ip, so that Master's INFO command can list the
         * slave IP address port correctly in case of port forwarding or NAT.
         * Skip REPLCONF ip-address if there is no slave-announce-ip option set. 
         * 向master发送 REPLCONF ip-address $slaveip 命令,便于master知道slave的ip
         */
        if (server.slave_announce_ip) {
            err = sendCommand(conn,"REPLCONF",
                    "ip-address",server.slave_announce_ip, NULL);
            if (err) goto write_error;
        }

        /* Inform the master of our (slave) capabilities.
         *
         * EOF: supports EOF-style RDB transfer for diskless replication.
         * PSYNC2: supports PSYNC v2, so understands +CONTINUE <new repl ID>.
         *
         * The master will ignore capabilities it does not understand. */
        err = sendCommand(conn,"REPLCONF",
                "capa","eof","capa","psync2",NULL);
        if (err) goto write_error;

        server.repl_state = REPL_STATE_RECEIVE_AUTH_REPLY;
        return;
    }

    if (server.repl_state == REPL_STATE_RECEIVE_AUTH_REPLY && !server.masterauth)
        server.repl_state = REPL_STATE_RECEIVE_PORT_REPLY;

    /* Receive AUTH reply. 接收到AUTH命令的回复*/
    if (server.repl_state == REPL_STATE_RECEIVE_AUTH_REPLY) {
        err = receiveSynchronousResponse(conn);
        if (err[0] == '-') {
            serverLog(LL_WARNING,"Unable to AUTH to MASTER: %s",err);
            sdsfree(err);
            goto error;
        }
        sdsfree(err);
        err = NULL;
        server.repl_state = REPL_STATE_RECEIVE_PORT_REPLY;
        return;
    }

    /* Receive REPLCONF listening-port reply.  接收到REPLCONF listening-port回复 */
    if (server.repl_state == REPL_STATE_RECEIVE_PORT_REPLY) {
        err = receiveSynchronousResponse(conn);
        /* Ignore the error if any, not all the Redis versions support
         * REPLCONF listening-port. */
        if (err[0] == '-') {
            serverLog(LL_NOTICE,"(Non critical) Master does not understand "
                                "REPLCONF listening-port: %s", err);
        }
        sdsfree(err);
        server.repl_state = REPL_STATE_RECEIVE_IP_REPLY;
        return;
    }

    if (server.repl_state == REPL_STATE_RECEIVE_IP_REPLY && !server.slave_announce_ip)
        server.repl_state = REPL_STATE_RECEIVE_CAPA_REPLY;

    /* Receive REPLCONF ip-address reply. */
    if (server.repl_state == REPL_STATE_RECEIVE_IP_REPLY) {
        err = receiveSynchronousResponse(conn);
        /* Ignore the error if any, not all the Redis versions support
         * REPLCONF listening-port. */
        if (err[0] == '-') {
            serverLog(LL_NOTICE,"(Non critical) Master does not understand "
                                "REPLCONF ip-address: %s", err);
        }
        sdsfree(err);
        server.repl_state = REPL_STATE_RECEIVE_CAPA_REPLY;
        return;
    }

    /* Receive CAPA reply. */
    if (server.repl_state == REPL_STATE_RECEIVE_CAPA_REPLY) {
        err = receiveSynchronousResponse(conn);
        /* Ignore the error if any, not all the Redis versions support
         * REPLCONF capa. */
        if (err[0] == '-') {
            serverLog(LL_NOTICE,"(Non critical) Master does not understand "
                                  "REPLCONF capa: %s", err);
        }
        sdsfree(err);
        err = NULL;
        server.repl_state = REPL_STATE_SEND_PSYNC;
    }

    /* Try a partial resynchronization. If we don't have a cached master
     * slaveTryPartialResynchronization() will at least try to use PSYNC
     * to start a full resynchronization so that we get the master replid
     * and the global offset, to try a partial resync at the next
     * reconnection attempt. 
     * 尝试做部分重同步.如果我们没有cached master,slaveTryPartialResynchronization()会尝试用PSYNC ? -1开始一个全量重同步.
     * 以便我们能获得master的replid + global offset.
     */
    if (server.repl_state == REPL_STATE_SEND_PSYNC) {
        if (slaveTryPartialResynchronization(conn,0) == PSYNC_WRITE_ERROR) {
            err = sdsnew("Write error sending the PSYNC command.");
            abortFailover("Write error to failover target");
            goto write_error;
        }
        server.repl_state = REPL_STATE_RECEIVE_PSYNC_REPLY;
        return;
    }

    /* If reached this point, we should be in REPL_STATE_RECEIVE_PSYNC. */
    if (server.repl_state != REPL_STATE_RECEIVE_PSYNC_REPLY) {
        serverLog(LL_WARNING,"syncWithMaster(): state machine error, "
                             "state should be RECEIVE_PSYNC but is %d",
                             server.repl_state);
        goto error;
    }

    psync_result = slaveTryPartialResynchronization(conn,1);
    if (psync_result == PSYNC_WAIT_REPLY) return; /* Try again later... */

    /* Check the status of the planned failover. We expect PSYNC_CONTINUE,
     * but there is nothing technically wrong with a full resync which
     * could happen in edge cases. 
     * 检查failover的状态.
     */
    if (server.failover_state == FAILOVER_IN_PROGRESS) {
        if (psync_result == PSYNC_CONTINUE || psync_result == PSYNC_FULLRESYNC) {
            clearFailoverState();
        } else {
            abortFailover("Failover target rejected psync request");
            return;
        }
    }

    /* If the master is in an transient error, we should try to PSYNC
     * from scratch later, so go to the error path. This happens when
     * the server is loading the dataset or is not connected with its
     * master and so forth. 
     * 如果master发送暂时的错误,我们应该稍后再尝试PSYNC.
     * 这一般发生在server正在加载数据集 or 没有连上其master时
     */
    if (psync_result == PSYNC_TRY_LATER) goto error;

    /* Note: if PSYNC does not return WAIT_REPLY, it will take care of
     * uninstalling the read handler from the file descriptor. */

    if (psync_result == PSYNC_CONTINUE) {
        //可以部分重同步,打印日志后返回
        serverLog(LL_NOTICE, "MASTER <-> REPLICA sync: Master accepted a Partial Resynchronization.");
        if (server.supervised_mode == SUPERVISED_SYSTEMD) {
            redisCommunicateSystemd("STATUS=MASTER <-> REPLICA sync: Partial Resynchronization accepted. Ready to accept connections in read-write mode.\n");
        }
        return;
    }
    //到这里意味着,必须全量重同步 or PSYNC失败

    /* PSYNC failed or is not supported: we want our slaves to resync with us
     * as well, if we have any sub-slaves. The master may transfer us an
     * entirely different data set and we have no way to incrementally feed
     * our slaves after that. 
     * PSYNC失败 or 不支持: 我们都希望我们的slave和我们进行resync. mastere可能传输给我们完全不同的数据集;
     */
    disconnectSlaves(); /* Force our slaves to resync with us as well. */
    freeReplicationBacklog(); /* Don't allow our chained slaves to PSYNC. 释放replbacklog,不允许我们的slave进行PSYNC*/

    /* Fall back to SYNC if needed. Otherwise psync_result == PSYNC_FULLRESYNC
     * and the server.master_replid and master_initial_offset are
     * already populated. */
    if (psync_result == PSYNC_NOT_SUPPORTED) {
        serverLog(LL_NOTICE,"Retrying with SYNC...");
        if (connSyncWrite(conn,"SYNC\r\n",6,server.repl_syncio_timeout*1000) == -1) {
            serverLog(LL_WARNING,"I/O error writing to MASTER: %s",
                strerror(errno));
            goto error;
        }
    }

    /* Prepare a suitable temp file for bulk transfer 为全量数据传输准备合适的temp文件*/
    if (!useDisklessLoad()) {
        while(maxtries--) {
            snprintf(tmpfile,256,
                "temp-%d.%ld.rdb",(int)server.unixtime,(long int)getpid());
            dfd = open(tmpfile,O_CREAT|O_WRONLY|O_EXCL,0644);
            if (dfd != -1) break;
            sleep(1);
        }
        if (dfd == -1) {
            serverLog(LL_WARNING,"Opening the temp file needed for MASTER <-> REPLICA synchronization: %s",strerror(errno));
            goto error;
        }
        server.repl_transfer_tmpfile = zstrdup(tmpfile);
        server.repl_transfer_fd = dfd;
    }

    /* Setup the non blocking download of the bulk file. */
    if (connSetReadHandler(conn, readSyncBulkPayload)
            == C_ERR)
    {
        char conninfo[CONN_INFO_LEN];
        serverLog(LL_WARNING,
            "Can't create readable event for SYNC: %s (%s)",
            strerror(errno), connGetInfo(conn, conninfo, sizeof(conninfo)));
        goto error;
    }

    server.repl_state = REPL_STATE_TRANSFER;
    server.repl_transfer_size = -1;
    server.repl_transfer_read = 0;
    server.repl_transfer_last_fsync_off = 0;
    server.repl_transfer_lastio = server.unixtime;
    return;

error:
    if (dfd != -1) close(dfd);
    connClose(conn);
    server.repl_transfer_s = NULL;
    if (server.repl_transfer_fd != -1)
        close(server.repl_transfer_fd);
    if (server.repl_transfer_tmpfile)
        zfree(server.repl_transfer_tmpfile);
    server.repl_transfer_tmpfile = NULL;
    server.repl_transfer_fd = -1;
    server.repl_state = REPL_STATE_CONNECT;
    return;

write_error: /* Handle sendCommand() errors. */
    serverLog(LL_WARNING,"Sending command to master in replication handshake: %s", err);
    sdsfree(err);
    goto error;
}

int connectWithMaster(void) {
    server.repl_transfer_s = server.tls_replication ? connCreateTLS() : connCreateSocket();
    if (connConnect(server.repl_transfer_s, server.masterhost, server.masterport,
                server.bind_source_addr, syncWithMaster) == C_ERR) {
        serverLog(LL_WARNING,"Unable to connect to MASTER: %s",
                connGetLastError(server.repl_transfer_s));
        connClose(server.repl_transfer_s);
        server.repl_transfer_s = NULL;
        return C_ERR;
    }


    server.repl_transfer_lastio = server.unixtime;
    server.repl_state = REPL_STATE_CONNECTING;
    serverLog(LL_NOTICE,"MASTER <-> REPLICA sync started");
    return C_OK;
}

/* This function can be called when a non blocking connection is currently
 * in progress to undo it.
 * 当需要对一个非阻塞连接进行撤掉时,该函数被调用
 * 
 * Never call this function directly, use cancelReplicationHandshake() instead.
 */
void undoConnectWithMaster(void) {
    connClose(server.repl_transfer_s);
    server.repl_transfer_s = NULL;
}

/* Abort the async download of the bulk dataset while SYNC-ing with master.
 * 在与master SYNC时,终止bulk dataset的异步下载.
 * Never call this function directly, use cancelReplicationHandshake() instead.
 */
void replicationAbortSyncTransfer(void) {
    serverAssert(server.repl_state == REPL_STATE_TRANSFER);
    undoConnectWithMaster();
    if (server.repl_transfer_fd!=-1) {
        close(server.repl_transfer_fd);
        bg_unlink(server.repl_transfer_tmpfile);
        zfree(server.repl_transfer_tmpfile);
        server.repl_transfer_tmpfile = NULL;
        server.repl_transfer_fd = -1;
    }
}

/* This function aborts a non blocking replication attempt if there is one
 * in progress, by canceling the non-blocking connect attempt or
 * the initial bulk transfer.
 * 如果正在进行replication 尝试,此函数会通过 终止连接 or 终止bulk数据传输的方式终止 replication 尝试.
 *
 * If there was a replication handshake in progress 1 is returned and
 * the replication state (server.repl_state) set to REPL_STATE_CONNECT.
 *
 * Otherwise zero is returned and no operation is performed at all. */
int cancelReplicationHandshake(int reconnect) {
    if (server.repl_state == REPL_STATE_TRANSFER) {
        replicationAbortSyncTransfer();
        server.repl_state = REPL_STATE_CONNECT;
    } else if (server.repl_state == REPL_STATE_CONNECTING ||
               slaveIsInHandshakeState())
    {
        undoConnectWithMaster();
        server.repl_state = REPL_STATE_CONNECT;
    } else {
        return 0;
    }

    if (!reconnect)
        return 1;

    /* try to re-connect without waiting for replicationCron, this is needed
     * for the "diskless loading short read" test. */
    serverLog(LL_NOTICE,"Reconnecting to MASTER %s:%d after failure",
        server.masterhost, server.masterport);
    connectWithMaster();

    return 1;
}

/* Set replication to the specified master address and port. 与指定的master地址建立复制关系 */
void replicationSetMaster(char *ip, int port) {
    int was_master = server.masterhost == NULL;

    sdsfree(server.masterhost);
    server.masterhost = NULL;
    if (server.master) {
        freeClient(server.master);
    }
    disconnectAllBlockedClients(); /* Clients blocked in master, now slave. */

    /* Setting masterhost only after the call to freeClient since it calls
     * replicationHandleMasterDisconnection which can trigger a re-connect
     * directly from within that call. */
    server.masterhost = sdsnew(ip);
    server.masterport = port;

    /* Update oom_score_adj */
    setOOMScoreAdj(-1);

    /* Force our slaves to resync with us as well. They may hopefully be able
     * to partially resync with us, but we can notify the replid change. 
     * 强迫我们的slave与我们重新同步. 他们可能希望能够与我们做部分重同步.
     * 但是我们会通知replid已经修改.
     */
    disconnectSlaves();
    cancelReplicationHandshake(0);
    /* Before destroying our master state, create a cached master using
     * our own parameters, to later PSYNC with the new master. 
     * 在销毁我们的master状态前,用我们自己的参数创建cached master,以便PSYNC new master.
     */
    if (was_master) {
        replicationDiscardCachedMaster();
        replicationCacheMasterUsingMyself();
    }

    /* Fire the role change modules event. */
    moduleFireServerEvent(REDISMODULE_EVENT_REPLICATION_ROLE_CHANGED,
                          REDISMODULE_EVENT_REPLROLECHANGED_NOW_REPLICA,
                          NULL);

    /* Fire the master link modules event. */
    if (server.repl_state == REPL_STATE_CONNECTED)
        moduleFireServerEvent(REDISMODULE_EVENT_MASTER_LINK_CHANGE,
                              REDISMODULE_SUBEVENT_MASTER_LINK_DOWN,
                              NULL);

    server.repl_state = REPL_STATE_CONNECT;
    serverLog(LL_NOTICE,"Connecting to MASTER %s:%d",
        server.masterhost, server.masterport);
    connectWithMaster();
}

/* Cancel replication, setting the instance as a master itself. 
 * 取消复制,设置实例自己为master
*/
void replicationUnsetMaster(void) {
    if (server.masterhost == NULL) return; /* Nothing to do. */

    /* Fire the master link modules event. 触发 master link模块事件*/
    if (server.repl_state == REPL_STATE_CONNECTED)
        moduleFireServerEvent(REDISMODULE_EVENT_MASTER_LINK_CHANGE,
                              REDISMODULE_SUBEVENT_MASTER_LINK_DOWN,
                              NULL);

    /* Clear masterhost first, since the freeClient calls
     * replicationHandleMasterDisconnection which can attempt to re-connect. 
     * 先清理 server.masterhost,因为 freeClient() 函数会调用 replicationHandleMasterDisconnection()
     * replicationHandleMasterDisconnection()函数中可能会尝试重连
     */
    sdsfree(server.masterhost);
    server.masterhost = NULL;
    if (server.master) freeClient(server.master);
    replicationDiscardCachedMaster();
    cancelReplicationHandshake(0);
    /* When a slave is turned into a master, the current replication ID
     * (that was inherited from the master at synchronization time) is
     * used as secondary ID up to the current offset, and a new replication
     * ID is created to continue with a new replication history. */
    shiftReplicationId();
    /* Disconnecting all the slaves is required: we need to inform slaves
     * of the replication ID change (see shiftReplicationId() call). However
     * the slaves will be able to partially resync with us, so it will be
     * a very fast reconnection. 
     * 断开所有slave的连接是必须的: 我们需要通知所有slaves replication ID已经变了.
     * 不过所有slaves都能够和我们执行部分重同步, 所以将会是一个很快的reconnection()
     */
    disconnectSlaves();
    server.repl_state = REPL_STATE_NONE;

    /* We need to make sure the new master will start the replication stream
     * with a SELECT statement. This is forced after a full resync, but
     * with PSYNC version 2, there is no need for full resync after a
     * master switch. 
     * 我们需要确保new master的复制流以SELECT 命令开始.
     * 这在全量同步后是必须的,不过在PSYNC2 中,master切换后没有必要全量重同步.
     */
    server.slaveseldb = -1;

    /* Update oom_score_adj */
    setOOMScoreAdj(-1);

    /* Once we turn from slave to master, we consider the starting time without
     * slaves (that is used to count the replication backlog time to live) as
     * starting from now. Otherwise the backlog will be freed after a
     * failover if slaves do not connect immediately. */
    server.repl_no_slaves_since = server.unixtime;
    
    /* Reset down time so it'll be ready for when we turn into replica again. */
    server.repl_down_since = 0;

    /* Fire the role change modules event. */
    moduleFireServerEvent(REDISMODULE_EVENT_REPLICATION_ROLE_CHANGED,
                          REDISMODULE_EVENT_REPLROLECHANGED_NOW_MASTER,
                          NULL);

    /* Restart the AOF subsystem in case we shut it down during a sync when
     * we were still a slave. */
    if (server.aof_enabled && server.aof_state == AOF_OFF) restartAOFAfterSYNC();
}

/* This function is called when the slave lose the connection with the
 * master into an unexpected way. 
 * 该函数在 slave因未知原因丢失和master的连接后,会被调用
 */
void replicationHandleMasterDisconnection(void) {
    /* Fire the master link modules event. */
    if (server.repl_state == REPL_STATE_CONNECTED)
        moduleFireServerEvent(REDISMODULE_EVENT_MASTER_LINK_CHANGE,
                              REDISMODULE_SUBEVENT_MASTER_LINK_DOWN,
                              NULL);

    server.master = NULL;
    server.repl_state = REPL_STATE_CONNECT;
    server.repl_down_since = server.unixtime;
    /* We lost connection with our master, don't disconnect slaves yet,
     * maybe we'll be able to PSYNC with our master later. We'll disconnect
     * the slaves only if we'll have to do a full resync with our master. 
     * 我们丢失和master的连接, 不用现在就和我们的slave断开连接.
     * 我们也许可恶意通过PSYNC命令，和我们的master再次连上, 执行重同步.
     * 只有我们和master执行全量重同步,才会和我们的slaves断开连接
     */

    /* Try to re-connect immediately rather than wait for replicationCron
     * waiting 1 second may risk backlog being recycled. */
    if (server.masterhost) {
        serverLog(LL_NOTICE,"Reconnecting to MASTER %s:%d",
            server.masterhost, server.masterport);
        connectWithMaster();
    }
}

void replicaofCommand(client *c) {
    /* SLAVEOF is not allowed in cluster mode as replication is automatically
     * configured using the current address of the master node. 
     * 集群模式下 不允许使用slaveof命令
     */
    if (server.cluster_enabled) {
        addReplyError(c,"REPLICAOF not allowed in cluster mode.");
        return;
    }

    if (server.failover_state != NO_FAILOVER) {
        addReplyError(c,"REPLICAOF not allowed while failing over.");
        return;
    }

    /* The special host/port combination "NO" "ONE" turns the instance
     * into a master. Otherwise the new master address is set. */
    if (!strcasecmp(c->argv[1]->ptr,"no") &&
        !strcasecmp(c->argv[2]->ptr,"one")) {
        if (server.masterhost) {
            replicationUnsetMaster();
            sds client = catClientInfoString(sdsempty(),c);
            serverLog(LL_NOTICE,"MASTER MODE enabled (user request from '%s')",
                client);
            sdsfree(client);
        }
    } else {
        long port;

        if (c->flags & CLIENT_SLAVE)
        {
            /* If a client is already a replica they cannot run this command,
             * because it involves flushing all replicas (including this
             * client) */
            addReplyError(c, "Command is not valid when client is a replica.");
            return;
        }

        if (getRangeLongFromObjectOrReply(c, c->argv[2], 0, 65535, &port,
                                          "Invalid master port") != C_OK)
            return;

        /* Check if we are already attached to the specified master */
        if (server.masterhost && !strcasecmp(server.masterhost,c->argv[1]->ptr)
            && server.masterport == port) {
            serverLog(LL_NOTICE,"REPLICAOF would result into synchronization "
                                "with the master we are already connected "
                                "with. No operation performed.");
            addReplySds(c,sdsnew("+OK Already connected to specified "
                                 "master\r\n"));
            return;
        }
        /* There was no previous master or the user specified a different one,
         * we can continue. */
        replicationSetMaster(c->argv[1]->ptr, port);
        sds client = catClientInfoString(sdsempty(),c);
        serverLog(LL_NOTICE,"REPLICAOF %s:%d enabled (user request from '%s')",
            server.masterhost, server.masterport, client);
        sdsfree(client);
    }
    addReply(c,shared.ok);
}

/* ROLE command: provide information about the role of the instance
 * (master or slave) and additional information related to replication
 * in an easy to process format. */
void roleCommand(client *c) {
    if (server.masterhost == NULL) {
        listIter li;
        listNode *ln;
        void *mbcount;
        int slaves = 0;

        addReplyArrayLen(c,3);
        addReplyBulkCBuffer(c,"master",6);
        addReplyLongLong(c,server.master_repl_offset);
        mbcount = addReplyDeferredLen(c);
        listRewind(server.slaves,&li);
        while((ln = listNext(&li))) {
            client *slave = ln->value;
            char ip[NET_IP_STR_LEN], *slaveaddr = slave->slave_addr;

            if (!slaveaddr) {
                if (connPeerToString(slave->conn,ip,sizeof(ip),NULL) == -1)
                    continue;
                slaveaddr = ip;
            }
            if (slave->replstate != SLAVE_STATE_ONLINE) continue;
            addReplyArrayLen(c,3);
            addReplyBulkCString(c,slaveaddr);
            addReplyBulkLongLong(c,slave->slave_listening_port);
            addReplyBulkLongLong(c,slave->repl_ack_off);
            slaves++;
        }
        setDeferredArrayLen(c,mbcount,slaves);
    } else {
        char *slavestate = NULL;

        addReplyArrayLen(c,5);
        addReplyBulkCBuffer(c,"slave",5);
        addReplyBulkCString(c,server.masterhost);
        addReplyLongLong(c,server.masterport);
        if (slaveIsInHandshakeState()) {
            slavestate = "handshake";
        } else {
            switch(server.repl_state) {
            case REPL_STATE_NONE: slavestate = "none"; break;
            case REPL_STATE_CONNECT: slavestate = "connect"; break;
            case REPL_STATE_CONNECTING: slavestate = "connecting"; break;
            case REPL_STATE_TRANSFER: slavestate = "sync"; break;
            case REPL_STATE_CONNECTED: slavestate = "connected"; break;
            default: slavestate = "unknown"; break;
            }
        }
        addReplyBulkCString(c,slavestate);
        addReplyLongLong(c,server.master ? server.master->reploff : -1);
    }
}

/* Send a REPLCONF ACK command to the master to inform it about the current
 * processed offset. If we are not connected with a master, the command has
 * no effects. 
 * 向master发送 REPLCONF ACK 命令通知master当前已处理的offset.
 */
void replicationSendAck(void) {
    client *c = server.master;

    if (c != NULL) {
        c->flags |= CLIENT_MASTER_FORCE_REPLY;
        addReplyArrayLen(c,3);
        addReplyBulkCString(c,"REPLCONF");
        addReplyBulkCString(c,"ACK");
        addReplyBulkLongLong(c,c->reploff);
        c->flags &= ~CLIENT_MASTER_FORCE_REPLY;
    }
}

/* ---------------------- MASTER CACHING FOR PSYNC -------------------------- */

/* In order to implement partial synchronization we need to be able to cache
 * our master's client structure after a transient disconnection.
 * It is cached into server.cached_master and flushed away using the following
 * functions. 
 * 为了实现部分同步, 我们需要能够短暂断开连接后缓存我们master client结构.
 * 它被缓存到 server.cached_master 并使用下面这些函数刷新
 */

/* This function is called by freeClient() in order to cache the master
 * client structure instead of destroying it. freeClient() will return
 * ASAP after this function returns, so every action needed to avoid problems
 * with a client that is really "suspended" has to be done by this function.
 * 该函数被freeClient()调用以缓存master client结构而不是破坏他.
 * freeClient()将在此函数返回后尽快返回，因此避免真正"挂起"client"出现问题所需的所有操作都必须有此函数完成.
 * 
 * The other functions that will deal with the cached master are:
 * 其他的将会处理 cache master的函数是:
 *
 * replicationDiscardCachedMaster() that will make sure to kill the client
 * as for some reason we don't want to use it in the future.
 * replicationDiscardCachedMaster() 因为某些原因我们在未来不想在用master client,该函数会kill 该client;
 *
 * replicationResurrectCachedMaster() that is used after a successful PSYNC
 * handshake in order to reactivate the cached master.
 * replicationResurrectCachedMaster() 用于在PSYNC成功握手后,重新激活cached master
 * 
 */
void replicationCacheMaster(client *c) {
    serverAssert(server.master != NULL && server.cached_master == NULL);
    serverLog(LL_NOTICE,"Caching the disconnected master state.");

    /* Unlink the client from the server structures. */
    unlinkClient(c);

    /* Reset the master client so that's ready to accept new commands:
     * we want to discard the non processed query buffers and non processed
     * offsets, including pending transactions, already populated arguments,
     * pending outputs to the master.
     * 重置master client,将其保存到 server.cached_master中,以便准备接收新的命令:
     * 丢弃没有处理的query buffers 和 offset,包括待处理的事务等 
     */
    sdsclear(server.master->querybuf);
    sdsclear(server.master->pending_querybuf);
    server.master->read_reploff = server.master->reploff;
    if (c->flags & CLIENT_MULTI) discardTransaction(c);
    listEmpty(c->reply);
    c->sentlen = 0;
    c->reply_bytes = 0;
    c->bufpos = 0;
    resetClient(c);

    /* Save the master. Server.master will be set to null later by
     * replicationHandleMasterDisconnection(). */
    server.cached_master = server.master;

    /* Invalidate the Peer ID cache. */
    if (c->peerid) {
        sdsfree(c->peerid);
        c->peerid = NULL;
    }
    /* Invalidate the Sock Name cache. */
    if (c->sockname) {
        sdsfree(c->sockname);
        c->sockname = NULL;
    }

    /* Caching the master happens instead of the actual freeClient() call,
     * so make sure to adjust the replication state. This function will
     * also set server.master to NULL. */
    replicationHandleMasterDisconnection();
}

/* This function is called when a master is turned into a slave, in order to
 * create from scratch a cached master for the new client, that will allow
 * to PSYNC with the slave that was promoted as the new master after a
 * failover.
 * 该函数在master变为slave时调用, 为cached master创建一个新的client, 这将允许在slave提升为new master后, old master执行PSYNC
 *
 * Assuming this instance was previously the master instance of the new master,
 * the new master will accept its replication ID, and potential also the
 * current offset if no data was lost during the failover. So we use our
 * current replication ID and offset in order to synthesize a cached master. 
 * 假设当前redis是new master以前的master(也就是我以前是master,发生failover了,我其中的一个slave变成了new master,现在我需要和new master建立联系)
 * 那么在failover没丢失数据的情况下, new master会接收我的 replication id/offset.
 * 所以我可以使用我当前的replication id/offset 来sync(synthesize)一个 cached master
 */
void replicationCacheMasterUsingMyself(void) {
    serverLog(LL_NOTICE,
        "Before turning into a replica, using my own master parameters "
        "to synthesize a cached master: I may be able to synchronize with "
        "the new master with just a partial transfer.");

    /* This will be used to populate the field server.master->reploff
     * by replicationCreateMasterClient(). We'll later set the created
     * master as server.cached_master, so the replica will use such
     * offset for PSYNC. 
     * 这将被 replicationCreateMasterClient() 用于填充 server.master->reploff 字段.
     * 稍后将创建的master设置为 server.cached_master, 所以slave将使用该offset 执行PSYNC
     */
    server.master_initial_offset = server.master_repl_offset;

    /* The master client we create can be set to any DBID, because
     * the new master will start its replication stream with SELECT. 
     * 实例化server.master中的client,
     */
    replicationCreateMasterClient(NULL,-1);

    /* Use our own ID / offset. */
    memcpy(server.master->replid, server.replid, sizeof(server.replid));

    /* Set as cached master. */
    unlinkClient(server.master);
    server.cached_master = server.master;
    server.master = NULL;
}

/* Free a cached master, called when there are no longer the conditions for
 * a partial resync on reconnection. 
 * 释放cached master,当不再有部分重同步条件时调用
 */
void replicationDiscardCachedMaster(void) {
    if (server.cached_master == NULL) return;

    serverLog(LL_NOTICE,"Discarding previously cached master state.");
    server.cached_master->flags &= ~CLIENT_MASTER;
    freeClient(server.cached_master);
    server.cached_master = NULL;
}

/* Turn the cached master into the current master, using the file descriptor
 * passed as argument as the socket for the new master.
 * server.master=server.cached_master,用参数中的文件描述符 作为 new master的socket
 *
 * This function is called when successfully setup a partial resynchronization
 * so the stream of data that we'll receive will start from were this
 * master left. 
 * 当部分重同步成功建立后,该函数会被调用. 所以后面我们会从这个master接收剩余的数据.
 */
void replicationResurrectCachedMaster(connection *conn) {
    server.master = server.cached_master;
    server.cached_master = NULL;
    server.master->conn = conn;
    connSetPrivateData(server.master->conn, server.master);
    server.master->flags &= ~(CLIENT_CLOSE_AFTER_REPLY|CLIENT_CLOSE_ASAP);
    server.master->authenticated = 1;
    server.master->lastinteraction = server.unixtime;
    server.repl_state = REPL_STATE_CONNECTED;
    server.repl_down_since = 0;

    /* Fire the master link modules event. */
    moduleFireServerEvent(REDISMODULE_EVENT_MASTER_LINK_CHANGE,
                          REDISMODULE_SUBEVENT_MASTER_LINK_UP,
                          NULL);

    /* Re-add to the list of clients. */
    linkClient(server.master);
    if (connSetReadHandler(server.master->conn, readQueryFromClient)) {
        serverLog(LL_WARNING,"Error resurrecting the cached master, impossible to add the readable handler: %s", strerror(errno));
        freeClientAsync(server.master); /* Close ASAP. */
    }

    /* We may also need to install the write handler as well if there is
     * pending data in the write buffers. */
    if (clientHasPendingReplies(server.master)) {
        if (connSetWriteHandler(server.master->conn, sendReplyToClient)) {
            serverLog(LL_WARNING,"Error resurrecting the cached master, impossible to add the writable handler: %s", strerror(errno));
            freeClientAsync(server.master); /* Close ASAP. */
        }
    }
}

/* ------------------------- MIN-SLAVES-TO-WRITE  --------------------------- */

/* This function counts the number of slaves with lag <= min-slaves-max-lag.
 * If the option is active, the server will prevent writes if there are not
 * enough connected slaves with the specified lag (or less). */
void refreshGoodSlavesCount(void) {
    listIter li;
    listNode *ln;
    int good = 0;

    if (!server.repl_min_slaves_to_write ||
        !server.repl_min_slaves_max_lag) return;

    listRewind(server.slaves,&li);
    while((ln = listNext(&li))) {
        client *slave = ln->value;
        time_t lag = server.unixtime - slave->repl_ack_time;

        if (slave->replstate == SLAVE_STATE_ONLINE &&
            lag <= server.repl_min_slaves_max_lag) good++;
    }
    server.repl_good_slaves_count = good;
}

/* ----------------------- REPLICATION SCRIPT CACHE --------------------------
 * The goal of this code is to keep track of scripts already sent to every
 * connected slave, in order to be able to replicate EVALSHA as it is without
 * translating it to EVAL every time it is possible.
 * 该代码目的是追踪已发送到 connected slave的脚本, 以便能够按照原样复制 EVALSHA,而无需每次都将其转换为 EVAL.
 *
 * We use a capped collection implemented by a hash table for fast lookup
 * of scripts we can send as EVALSHA, plus a linked list that is used for
 * eviction of the oldest entry when the max number of items is reached.
 * 我们使用hash表作为一个 集合(collection) 来快速查找我们发送为EVALSHA的脚本,
 * 同时添加一个链表 用于在max number of items达到时, 驱逐最旧的一个Item.
 *
 * We don't care about taking a different cache for every different slave
 * since to fill the cache again is not very costly, the goal of this code
 * is to avoid that the same big script is transmitted a big number of times
 * per second wasting bandwidth and processor speed, but it is not a problem
 * if we need to rebuild the cache from scratch from time to time, every used
 * script will need to be transmitted a single time to reappear in the cache.
 * 我们并不关心不同slave使用不同的缓存,因为填充缓存的成本并不是很高. 这段代码目的是避免每秒传输大量相同的脚本浪费带宽 和 处理器的速度.
 * 如果我们需要不时重建缓存,这不是问题, 每个使用过的脚本都需要传输一次才能出现在缓存中.
 *
 * This is how the system works:
 *
 * 1) Every time a new slave connects, we flush the whole script cache.
 * 每次有新的slave连接时,我们都会flush 整个脚本缓存
 * 2) We only send as EVALSHA what was sent to the master as EVALSHA, without
 *    trying to convert EVAL into EVALSHA specifically for slaves.
 * 我们知会将master接收到的EVALSHA 以 EVALSHA 方式发送, 而不会尝试将EVAL 转换为 (专门针对slaves的)EVALSHA.
 * 3) Every time we transmit a script as EVAL to the slaves, we also add the
 *    corresponding SHA1 of the script into the cache as we are sure every
 *    slave knows about the script starting from now.
 * 每次我们将脚本作为EVAL发送给slaves时，我们还将脚本对应的SHA1 保存在Cache中.因为我们确信从现在开始每个slaves都知道该脚本.
 * 4) On SCRIPT FLUSH command, we replicate the command to all the slaves
 *    and at the same time flush the script cache.
 * 在SCRIPT FLUSH命令上, 我们将命令复制到所有slaves上，同时flush 左右脚本缓存
 * 5) When the last slave disconnects, flush the cache.
 * 当最后一个slave端口链接时,flush 缓存
 * 6) We handle SCRIPT LOAD as well since that's how scripts are loaded
 *    in the master sometimes.
 * 我们也处理SCRIPT LOAD,因为这是master load脚本的方式
 */

/* Initialize the script cache, only called at startup. */
void replicationScriptCacheInit(void) {
    server.repl_scriptcache_size = 10000;
    server.repl_scriptcache_dict = dictCreate(&replScriptCacheDictType,NULL);
    server.repl_scriptcache_fifo = listCreate();
}

/* Empty the script cache. Should be called every time we are no longer sure
 * that every slave knows about all the scripts in our set, or when the
 * current AOF "context" is no longer aware of the script. In general we
 * should flush the cache:
 *
 * 1) Every time a new slave reconnects to this master and performs a
 *    full SYNC (PSYNC does not require flushing).
 * 2) Every time an AOF rewrite is performed.
 * 3) Every time we are left without slaves at all, and AOF is off, in order
 *    to reclaim otherwise unused memory.
 */
void replicationScriptCacheFlush(void) {
    dictEmpty(server.repl_scriptcache_dict,NULL);
    listRelease(server.repl_scriptcache_fifo);
    server.repl_scriptcache_fifo = listCreate();
}

/* Add an entry into the script cache, if we reach max number of entries the
 * oldest is removed from the list. */
void replicationScriptCacheAdd(sds sha1) {
    int retval;
    sds key = sdsdup(sha1);

    /* Evict oldest. */
    if (listLength(server.repl_scriptcache_fifo) == server.repl_scriptcache_size)
    {
        listNode *ln = listLast(server.repl_scriptcache_fifo);
        sds oldest = listNodeValue(ln);

        retval = dictDelete(server.repl_scriptcache_dict,oldest);
        serverAssert(retval == DICT_OK);
        listDelNode(server.repl_scriptcache_fifo,ln);
    }

    /* Add current. */
    retval = dictAdd(server.repl_scriptcache_dict,key,NULL);
    listAddNodeHead(server.repl_scriptcache_fifo,key);
    serverAssert(retval == DICT_OK);
}

/* Returns non-zero if the specified entry exists inside the cache, that is,
 * if all the slaves are aware of this script SHA1. */
int replicationScriptCacheExists(sds sha1) {
    return dictFind(server.repl_scriptcache_dict,sha1) != NULL;
}

/* ----------------------- SYNCHRONOUS REPLICATION --------------------------
 * Redis synchronous replication design can be summarized in points:
 * Redis 同步复制设置总结起来有以下几点:
 *
 * - Redis masters have a global replication offset, used by PSYNC.
 * master 有一个全局replication offset, PSYNC 命令时使用;
 * - Master increment the offset every time new commands are sent to slaves.
 * master 给slave发送新命令则会增加offset;
 * - Slaves ping back masters with the offset processed so far.
 * slave执行到哪个offset了,会通过ping命令发送给master.(到底是master ping slave？还是slave ping master?)
 *
 * So synchronous replication adds a new WAIT command in the form:
 * 所以同步复制增加了一个WAIT命令
 *
 *   WAIT <num_replicas> <milliseconds_timeout>
 *
 * That returns the number of replicas that processed the query when
 * we finally have at least num_replicas, or when the timeout was
 * reached.
 * 该命令返回 client'我自己'所有(写)请求 的slaves个数(至少是num_replicas个),或者timeout到达后返回
 *
 * The command is implemented in this way:
 *
 * - Every time a client processes a command, we remember the replication
 *   offset after sending that command to the slaves.
 * 每次一个client处理一个(写)命令,在将命令发送给slaves后,我们都会记住该命令的replication offset;
 * - When WAIT is called, we ask slaves to send an acknowledgement ASAP.
 *   The client is blocked at the same time (see blocked.c).
 * client发送WAIT命令请求,我们要求所有slave尽快发送已知的offset. 此时client会被阻塞住;
 * - Once we receive enough ACKs for a given offset or when the timeout
 *   is reached, the WAIT command is unblocked and the reply sent to the
 *   client.
 * 一旦我们接收到 指定offset 足够 的ACKs or 超时时间到,则 WAIT 命令unblock 并给客户端发送回复
 */

/* This just set a flag so that we broadcast a REPLCONF GETACK command
 * to all the slaves in the beforeSleep() function. Note that this way
 * we "group" all the clients that want to wait for synchronous replication
 * in a given event loop iteration, and send a single GETACK for them all. */
// 设置该标记,则我们会在beforeSleep()函数中给所有slaves广播一个 REPLCONF GETACK命令
void replicationRequestAckFromSlaves(void) {
    server.get_ack_from_slaves = 1;
}

/* Return the number of slaves that already acknowledged the specified
 * replication offset. */
//返回满足指定复制偏移(repl offset)的 slaves的个数
int replicationCountAcksByOffset(long long offset) {
    listIter li;
    listNode *ln;
    int count = 0;

    listRewind(server.slaves,&li);
    while((ln = listNext(&li))) {
        client *slave = ln->value;

        if (slave->replstate != SLAVE_STATE_ONLINE) continue;
        if (slave->repl_ack_off >= offset) count++;
    }
    return count;
}

/* WAIT for N replicas to acknowledge the processing of our latest
 * write command (and all the previous commands). */
void waitCommand(client *c) {
    mstime_t timeout;
    long numreplicas, ackreplicas;
    long long offset = c->woff;

    if (server.masterhost) {
        addReplyError(c,"WAIT cannot be used with replica instances. Please also note that since Redis 4.0 if a replica is configured to be writable (which is not the default) writes to replicas are just local and are not propagated.");
        return;
    }

    /* Argument parsing. */
    if (getLongFromObjectOrReply(c,c->argv[1],&numreplicas,NULL) != C_OK)
        return;
    if (getTimeoutFromObjectOrReply(c,c->argv[2],&timeout,UNIT_MILLISECONDS)
        != C_OK) return;

    /* First try without blocking at all. */
    ackreplicas = replicationCountAcksByOffset(c->woff);
    if (ackreplicas >= numreplicas || c->flags & CLIENT_MULTI) {
        addReplyLongLong(c,ackreplicas);
        return;
    }

    /* Otherwise block the client and put it into our list of clients
     * waiting for ack from slaves. */
    c->bpop.timeout = timeout;
    c->bpop.reploffset = offset;
    c->bpop.numreplicas = numreplicas;
    listAddNodeHead(server.clients_waiting_acks,c);
    blockClient(c,BLOCKED_WAIT);

    /* Make sure that the server will send an ACK request to all the slaves
     * before returning to the event loop. */
    replicationRequestAckFromSlaves();
}

/* This is called by unblockClient() to perform the blocking op type
 * specific cleanup. We just remove the client from the list of clients
 * waiting for replica acks. Never call it directly, call unblockClient()
 * instead. */
void unblockClientWaitingReplicas(client *c) {
    listNode *ln = listSearchKey(server.clients_waiting_acks,c);
    serverAssert(ln != NULL);
    listDelNode(server.clients_waiting_acks,ln);
}

/* Check if there are clients blocked in WAIT that can be unblocked since
 * we received enough ACKs from slaves. */
//既然我们从slaves收到了足够多的ACKs,所以我们检查是否有 因等待同步复制而被block的客户端 能否unblock( WAIT 命令)
//unblock后,添加回复;
void processClientsWaitingReplicas(void) {
    long long last_offset = 0;
    int last_numreplicas = 0;

    listIter li;
    listNode *ln;

    listRewind(server.clients_waiting_acks,&li);
    while((ln = listNext(&li))) {
        client *c = ln->value;

        /* Every time we find a client that is satisfied for a given
         * offset and number of replicas, we remember it so the next client
         * may be unblocked without calling replicationCountAcksByOffset()
         * if the requested offset / replicas were equal or less. */
        if (last_offset && last_offset >= c->bpop.reploffset &&
                           last_numreplicas >= c->bpop.numreplicas)
        {
            unblockClient(c);
            addReplyLongLong(c,last_numreplicas);
        } else {
            //返回满足指定复制偏移(repl offset)的 slaves的个数
            int numreplicas = replicationCountAcksByOffset(c->bpop.reploffset);

            if (numreplicas >= c->bpop.numreplicas) {
                last_offset = c->bpop.reploffset;
                last_numreplicas = numreplicas;
                unblockClient(c);
                addReplyLongLong(c,numreplicas);
            }
        }
    }
}

/* Return the slave replication offset for this instance, that is
 * the offset for which we already processed the master replication stream. 
 * 返回当前节点(slave)的复制偏移, 也就是其已处理的master的复制偏移量
*/
long long replicationGetSlaveOffset(void) {
    long long offset = 0;

    if (server.masterhost != NULL) {
        if (server.master) {
            offset = server.master->reploff;
        } else if (server.cached_master) {
            offset = server.cached_master->reploff;
        }
    }
    /* offset may be -1 when the master does not support it at all, however
     * this function is designed to return an offset that can express the
     * amount of data processed by the master, so we return a positive
     * integer. 
     * 当master根本不支持offset时, offset 可能是 -1. 然而这个函数被设计成表示master处理数据的偏移量,因此我们返回一个正整数
     */
    if (offset < 0) offset = 0;
    return offset;
}

/* --------------------------- REPLICATION CRON  ---------------------------- */

/* Replication cron function, called 1 time per second. */
void replicationCron(void) {
    static long long replication_cron_loops = 0;

    /* Check failover status first, to see if we need to start
     * handling the failover. */
    updateFailoverStatus();

    /* Non blocking connection timeout? 建立连接超时? */
    if (server.masterhost &&
        (server.repl_state == REPL_STATE_CONNECTING ||
         slaveIsInHandshakeState()) &&
         (time(NULL)-server.repl_transfer_lastio) > server.repl_timeout)
    {
        serverLog(LL_WARNING,"Timeout connecting to the MASTER...");
        cancelReplicationHandshake(1);
    }

    /* Bulk transfer I/O timeout? slave接收master rdb数据超时 */
    if (server.masterhost && server.repl_state == REPL_STATE_TRANSFER &&
        (time(NULL)-server.repl_transfer_lastio) > server.repl_timeout)
    {
        serverLog(LL_WARNING,"Timeout receiving bulk data from MASTER... If the problem persists try to set the 'repl-timeout' parameter in redis.conf to a larger value.");
        cancelReplicationHandshake(1);
    }

    /* Timed out master when we are an already connected slave? 已经很久没和(已建立连接的)master有交互了 */
    if (server.masterhost && server.repl_state == REPL_STATE_CONNECTED &&
        (time(NULL)-server.master->lastinteraction) > server.repl_timeout)
    {
        serverLog(LL_WARNING,"MASTER timeout: no data nor PING received...");
        freeClient(server.master);
    }

    /* Check if we should connect to a MASTER 尝试和master重新建立连接 */
    if (server.repl_state == REPL_STATE_CONNECT) {
        serverLog(LL_NOTICE,"Connecting to MASTER %s:%d",
            server.masterhost, server.masterport);
        connectWithMaster();
    }

    /* Send ACK to master from time to time.
     * Note that we do not send periodic acks to masters that don't
     * support PSYNC and replication offsets. 
     * 向master发送ACK命令,告诉自己已处理的offset
     */
    if (server.masterhost && server.master &&
        !(server.master->flags & CLIENT_PRE_PSYNC))
        replicationSendAck();

    /* If we have attached slaves, PING them from time to time.
     * So slaves can implement an explicit timeout to masters, and will
     * be able to detect a link disconnection even if the TCP connection
     * will not actually go down. 
     * 如果我们有slaves,向他们发送ping命令
     * 所以slave可能已超时, 同时能探测连接是否已断开
     */
    listIter li;
    listNode *ln;
    robj *ping_argv[1];

    /* First, send PING according to ping_slave_period. */
    if ((replication_cron_loops % server.repl_ping_slave_period) == 0 &&
        listLength(server.slaves))
    {
        /* Note that we don't send the PING if the clients are paused during
         * a Redis Cluster manual failover: the PING we send will otherwise
         * alter the replication offsets of master and slave, and will no longer
         * match the one stored into 'mf_master_offset' state. 
         * 请注意: 如果clients在Redis集群manual failover时间paused状态, 我们不会发送PING:
         * 否则我们发送的PING将改变主从的replication offset,并且将不再匹配存储 mf_master_offset 状态的偏移量.
         */
        int manual_failover_in_progress =
            ((server.cluster_enabled &&
              server.cluster->mf_end) ||
            server.failover_end_time) &&
            checkClientPauseTimeoutAndReturnIfPaused();

        if (!manual_failover_in_progress) {
            ping_argv[0] = shared.ping;
            replicationFeedSlaves(server.slaves, server.slaveseldb,
                ping_argv, 1);
        }
    }

    /* Second, send a newline to all the slaves in pre-synchronization
     * stage, that is, slaves waiting for the master to create the RDB file.
     * 其次,在预同步阶段给所有slave的发送换行符,即slave等待master创建RDB文件.
     *
     * Also send the a newline to all the chained slaves we have, if we lost
     * connection from our master, to keep the slaves aware that their
     * master is online. This is needed since sub-slaves only receive proxied
     * data from top-level masters, so there is no explicit pinging in order
     * to avoid altering the replication offsets. This special out of band
     * pings (newlines) can be sent, they will have no effect in the offset.
     * 同时如果我们失去了和master的连接,我们向我们拥有的所有链式slave发送换行符,以便slave知道master还在线.
     * 这是必须的,既然sub-slaves仅从top-level master接收到proxied data,所以没有显式的ping 避免更改replication offset.
     * 发送换行符,不会对offset有影响.
     *
     * The newline will be ignored by the slave but will refresh the
     * last interaction timer preventing a timeout. In this case we ignore the
     * ping period and refresh the connection once per second since certain
     * timeouts are set at a few seconds (example: PSYNC response). 
     * 换行符会被slave忽略,不过slave会刷新最后和master的交互时间,这样避免timeout.
     * 这种情况下,我们忽略ping周期并每秒刷新一次连接
     */
    listRewind(server.slaves,&li);
    while((ln = listNext(&li))) {
        client *slave = ln->value;

        int is_presync =
            (slave->replstate == SLAVE_STATE_WAIT_BGSAVE_START ||
            (slave->replstate == SLAVE_STATE_WAIT_BGSAVE_END &&
             server.rdb_child_type != RDB_CHILD_TYPE_SOCKET));

        if (is_presync) {
            connWrite(slave->conn, "\n", 1);
        }
    }

    /* Disconnect timedout slaves. 与超时的slaves断开连接*/
    if (listLength(server.slaves)) {
        listIter li;
        listNode *ln;

        listRewind(server.slaves,&li);
        while((ln = listNext(&li))) {
            client *slave = ln->value;

            if (slave->replstate == SLAVE_STATE_ONLINE) {
                if (slave->flags & CLIENT_PRE_PSYNC)
                    continue;
                if ((server.unixtime - slave->repl_ack_time) > server.repl_timeout) {
                    serverLog(LL_WARNING, "Disconnecting timedout replica (streaming sync): %s",
                          replicationGetSlaveName(slave));
                    freeClient(slave);
                    continue;
                }
            }
            /* We consider disconnecting only diskless replicas because disk-based replicas aren't fed
             * by the fork child so if a disk-based replica is stuck it doesn't prevent the fork child
             * from terminating. 
             * 我们只考了断开diskless的slaves,因为 disk-based的slaves 的数据不是由child进程提供的.(diskless的slave的全量数据确实是 child进程=>rdb_pipe_write=>server.rdb_pipe_read=>slave socket)
             * 所以disk-based的slave卡住了,它不会阻止 child进程退出
             */
            if (slave->replstate == SLAVE_STATE_WAIT_BGSAVE_END && server.rdb_child_type == RDB_CHILD_TYPE_SOCKET) {
                if (slave->repl_last_partial_write != 0 &&
                    (server.unixtime - slave->repl_last_partial_write) > server.repl_timeout)
                {
                    serverLog(LL_WARNING, "Disconnecting timedout replica (full sync): %s",
                          replicationGetSlaveName(slave));
                    freeClient(slave);
                    continue;
                }
            }
        }
    }

    /* If this is a master without attached slaves and there is a replication
     * backlog active, in order to reclaim memory we can free it after some
     * (configured) time. Note that this cannot be done for slaves: slaves
     * without sub-slaves attached should still accumulate data into the
     * backlog, in order to reply to PSYNC queries if they are turned into
     * masters after a failover. 
     * 如果这是一个不带slave的master,同时其replcation backlog是启用的. 我们先释放他以便后续能重新申请内存.
     * 注意slave不会执行该操作: slave没有sub-slave但是依然会收集数据到backlog中,目的是这个改slave通过failover提升为master,能准确回复PSYNC请求
     */
    if (listLength(server.slaves) == 0 && server.repl_backlog_time_limit &&
        server.repl_backlog && server.masterhost == NULL)
    {
        time_t idle = server.unixtime - server.repl_no_slaves_since;

        if (idle > server.repl_backlog_time_limit) {
            /* When we free the backlog, we always use a new
             * replication ID and clear the ID2. This is needed
             * because when there is no backlog, the master_repl_offset
             * is not updated, but we would still retain our replication
             * ID, leading to the following problem:
             * 当我们释放backlog空间时,我们会使用一个新的replication ID 并清空 replication ID2
             * 这是很必要的,因为没有了backlog后,master_repl_offset也不会更新.
             * 但是我们依然保留replication ID,或导致下面的问题:
             *
             * 1. We are a master instance.
             *  我们是一个master实例
             * 2. Our slave is promoted to master. It's repl-id-2 will
             *    be the same as our repl-id.
             *  我们的slave提升为master, repl-id2 会和我们现有的repl-id相同
             * 3. We, yet as master, receive some updates, that will not
             *    increment the master_repl_offset.
             *  我们依然是一个master,收到更新后,不会增加我们的 master_repl_offset
             * 4. Later we are turned into a slave, connect to the new
             *    master that will accept our PSYNC request by second
             *    replication ID, but there will be data inconsistency
             *    because we received writes. 
             *  后续如果我们转为一个slave,连接到new master,new master会收到我们的PSYNC请求(居然是来自于自己replid2的psync请求)
             *  但是这样会导致数据不一致,因为我们收到了write
             */
            changeReplicationId();
            clearReplicationId2();
            freeReplicationBacklog();
            serverLog(LL_NOTICE,
                "Replication backlog freed after %d seconds "
                "without connected replicas.",
                (int) server.repl_backlog_time_limit);
        }
    }

    /* If AOF is disabled and we no longer have attached slaves, we can
     * free our Replication Script Cache as there is no need to propagate
     * EVALSHA at all. 
     * 如果AOF没有启用,同时我们没有slave.则我们释放 replication_script_cachee的内存.
     */
    if (listLength(server.slaves) == 0 &&
        server.aof_state == AOF_OFF &&
        listLength(server.repl_scriptcache_fifo) != 0)
    {
        replicationScriptCacheFlush();
    }

    replicationStartPendingFork();

    /* Remove the RDB file used for replication if Redis is not running
     * with any persistence. 
     * 删除用于复制的RDB文件
     */
    removeRDBUsedToSyncReplicas();

    /* Refresh the number of slaves with lag <= min-slaves-max-lag. 
    * 更新延迟 <= min-slaves-max-lag的slave个数 
    */
    refreshGoodSlavesCount();
    replication_cron_loops++; /* Incremented with frequency 1 HZ. */
}

void replicationStartPendingFork(void) {
    /* Start a BGSAVE good for replication if we have slaves in
     * WAIT_BGSAVE_START state.
     * 如果我们有slave处于 WAIT_BGSAVE_START 状态,则开始一个BGSAVE
     *
     * In case of diskless replication, we make sure to wait the specified
     * number of seconds (according to configuration) so that other slaves
     * have the time to arrive before we start streaming. 
     * 在diskless replication场景中，我们需要等几秒钟，以便其他的slave在我们开始传输数据流之前达到
     */
    if (!hasActiveChildProcess()) {
        time_t idle, max_idle = 0;//max_idle中是'slave等待执行bgsave的 的最大值',如果等的时间够长了,就开始执行bgsave
        int slaves_waiting = 0;
        int mincapa = -1;
        listNode *ln;
        listIter li;

        listRewind(server.slaves,&li);
        while((ln = listNext(&li))) {
            client *slave = ln->value;
            if (slave->replstate == SLAVE_STATE_WAIT_BGSAVE_START) {
                idle = server.unixtime - slave->lastinteraction;
                if (idle > max_idle) max_idle = idle;
                slaves_waiting++;
                mincapa = (mincapa == -1) ? slave->slave_capa :
                                            (mincapa & slave->slave_capa);
            }
        }

        if (slaves_waiting &&
            (!server.repl_diskless_sync ||
             max_idle >= server.repl_diskless_sync_delay))
        {
            /* Start the BGSAVE. The called function may start a
             * BGSAVE with socket target or disk target depending on the
             * configuration and slaves capabilities. 
             * 开始执行BGSAVE
             */
            startBgsaveForReplication(mincapa);
        }
    }
}

/* Find replica at IP:PORT from replica list */
static client *findReplica(char *host, int port) {
    listIter li;
    listNode *ln;
    client *replica;

    listRewind(server.slaves,&li);
    while((ln = listNext(&li))) {
        replica = ln->value;
        char ip[NET_IP_STR_LEN], *replicaip = replica->slave_addr;

        if (!replicaip) {
            if (connPeerToString(replica->conn, ip, sizeof(ip), NULL) == -1)
                continue;
            replicaip = ip;
        }

        if (!strcasecmp(host, replicaip) &&
                (port == replica->slave_listening_port))
            return replica;
    }

    return NULL;
}

const char *getFailoverStateString() {
    switch(server.failover_state) {
        case NO_FAILOVER: return "no-failover";
        case FAILOVER_IN_PROGRESS: return "failover-in-progress";
        case FAILOVER_WAIT_FOR_SYNC: return "waiting-for-sync";
        default: return "unknown";
    }
}

/* Resets the internal failover configuration, this needs
 * to be called after a failover either succeeds or fails
 * as it includes the client unpause. */
void clearFailoverState() {
    server.failover_end_time = 0;
    server.force_failover = 0;
    zfree(server.target_replica_host);
    server.target_replica_host = NULL;
    server.target_replica_port = 0;
    server.failover_state = NO_FAILOVER;
    unpauseClients();
}

/* Abort an ongoing failover if one is going on. */
void abortFailover(const char *err) {
    if (server.failover_state == NO_FAILOVER) return;

    if (server.target_replica_host) {
        serverLog(LL_NOTICE,"FAILOVER to %s:%d aborted: %s",
            server.target_replica_host,server.target_replica_port,err);  
    } else {
        serverLog(LL_NOTICE,"FAILOVER to any replica aborted: %s",err);  
    }
    if (server.failover_state == FAILOVER_IN_PROGRESS) {
        replicationUnsetMaster();
    }
    clearFailoverState();
}

/* 
 * FAILOVER [TO <HOST> <PORT> [FORCE]] [ABORT] [TIMEOUT <timeout>]
 * 
 * This command will coordinate a failover between the master and one
 * of its replicas. The happy path contains the following steps:
 * 1) The master will initiate a client pause write, to stop replication
 * traffic.
 * 2) The master will periodically check if any of its replicas has
 * consumed the entire replication stream through acks. 
 * 3) Once any replica has caught up, the master will itself become a replica.
 * 4) The master will send a PSYNC FAILOVER request to the target replica, which
 * if accepted will cause the replica to become the new master and start a sync.
 * 
 * FAILOVER ABORT is the only way to abort a failover command, as replicaof
 * will be disabled. This may be needed if the failover is unable to progress. 
 * 
 * The optional arguments [TO <HOST> <IP>] allows designating a specific replica
 * to be failed over to.
 * 
 * FORCE flag indicates that even if the target replica is not caught up,
 * failover to it anyway. This must be specified with a timeout and a target
 * HOST and IP.
 * 
 * TIMEOUT <timeout> indicates how long should the primary wait for 
 * a replica to sync up before aborting. If not specified, the failover
 * will attempt forever and must be manually aborted.
 */
void failoverCommand(client *c) {
    if (server.cluster_enabled) {
        addReplyError(c,"FAILOVER not allowed in cluster mode. "
                        "Use CLUSTER FAILOVER command instead.");
        return;
    }
    
    /* Handle special case for abort */
    if ((c->argc == 2) && !strcasecmp(c->argv[1]->ptr,"abort")) {
        if (server.failover_state == NO_FAILOVER) {
            addReplyError(c, "No failover in progress.");
            return;
        }

        abortFailover("Failover manually aborted");
        addReply(c,shared.ok);
        return;
    }

    long timeout_in_ms = 0;
    int force_flag = 0;
    long port = 0;
    char *host = NULL;

    /* Parse the command for syntax and arguments. */
    for (int j = 1; j < c->argc; j++) {
        if (!strcasecmp(c->argv[j]->ptr,"timeout") && (j + 1 < c->argc) &&
            timeout_in_ms == 0)
        {
            if (getLongFromObjectOrReply(c,c->argv[j + 1],
                        &timeout_in_ms,NULL) != C_OK) return;
            if (timeout_in_ms <= 0) {
                addReplyError(c,"FAILOVER timeout must be greater than 0");
                return;
            }
            j++;
        } else if (!strcasecmp(c->argv[j]->ptr,"to") && (j + 2 < c->argc) &&
            !host) 
        {
            if (getLongFromObjectOrReply(c,c->argv[j + 2],&port,NULL) != C_OK)
                return;
            host = c->argv[j + 1]->ptr;
            j += 2;
        } else if (!strcasecmp(c->argv[j]->ptr,"force") && !force_flag) {
            force_flag = 1;
        } else {
            addReplyErrorObject(c,shared.syntaxerr);
            return;
        }
    }

    if (server.failover_state != NO_FAILOVER) {
        addReplyError(c,"FAILOVER already in progress.");
        return;
    }

    if (server.masterhost) {
        addReplyError(c,"FAILOVER is not valid when server is a replica.");
        return;
    }

    if (listLength(server.slaves) == 0) {
        addReplyError(c,"FAILOVER requires connected replicas.");
        return; 
    }

    if (force_flag && (!timeout_in_ms || !host)) {
        addReplyError(c,"FAILOVER with force option requires both a timeout "
            "and target HOST and IP.");
        return;     
    }

    /* If a replica address was provided, validate that it is connected. */
    if (host) {
        client *replica = findReplica(host, port);

        if (replica == NULL) {
            addReplyError(c,"FAILOVER target HOST and PORT is not "
                            "a replica.");
            return;
        }

        /* Check if requested replica is online */
        if (replica->replstate != SLAVE_STATE_ONLINE) {
            addReplyError(c,"FAILOVER target replica is not online.");
            return;
        }

        server.target_replica_host = zstrdup(host);
        server.target_replica_port = port;
        serverLog(LL_NOTICE,"FAILOVER requested to %s:%ld.",host,port);
    } else {
        serverLog(LL_NOTICE,"FAILOVER requested to any replica.");
    }

    mstime_t now = mstime();
    if (timeout_in_ms) {
        server.failover_end_time = now + timeout_in_ms;
    }
    
    server.force_failover = force_flag;
    server.failover_state = FAILOVER_WAIT_FOR_SYNC;
    /* Cluster failover will unpause eventually */
    pauseClients(LLONG_MAX,CLIENT_PAUSE_WRITE);
    addReply(c,shared.ok);
}

/* Failover cron function, checks coordinated failover state. 
 *
 * Implementation note: The current implementation calls replicationSetMaster()
 * to start the failover request, this has some unintended side effects if the
 * failover doesn't work like blocked clients will be unblocked and replicas will
 * be disconnected. This could be optimized further.
 */
void updateFailoverStatus(void) {
    if (server.failover_state != FAILOVER_WAIT_FOR_SYNC) return;
    mstime_t now = server.mstime;

    /* Check if failover operation has timed out */
    if (server.failover_end_time && server.failover_end_time <= now) {
        if (server.force_failover) {
            serverLog(LL_NOTICE,
                "FAILOVER to %s:%d time out exceeded, failing over.",
                server.target_replica_host, server.target_replica_port);
            server.failover_state = FAILOVER_IN_PROGRESS;
            /* If timeout has expired force a failover if requested. */
            replicationSetMaster(server.target_replica_host,
                server.target_replica_port);
            return;
        } else {
            /* Force was not requested, so timeout. */
            abortFailover("Replica never caught up before timeout");
            return;
        }
    }

    /* Check to see if the replica has caught up so failover can start */
    client *replica = NULL;
    if (server.target_replica_host) {
        replica = findReplica(server.target_replica_host, 
            server.target_replica_port);
    } else {
        listIter li;
        listNode *ln;

        listRewind(server.slaves,&li);
        /* Find any replica that has matched our repl_offset */
        while((ln = listNext(&li))) {
            replica = ln->value;
            if (replica->repl_ack_off == server.master_repl_offset) {
                char ip[NET_IP_STR_LEN], *replicaaddr = replica->slave_addr;

                if (!replicaaddr) {
                    if (connPeerToString(replica->conn,ip,sizeof(ip),NULL) == -1)
                        continue;
                    replicaaddr = ip;
                }

                /* We are now failing over to this specific node */
                server.target_replica_host = zstrdup(replicaaddr);
                server.target_replica_port = replica->slave_listening_port;
                break;
            }
        }
    }

    /* We've found a replica that is caught up */
    if (replica && (replica->repl_ack_off == server.master_repl_offset)) {
        server.failover_state = FAILOVER_IN_PROGRESS;
        serverLog(LL_NOTICE,
                "Failover target %s:%d is synced, failing over.",
                server.target_replica_host, server.target_replica_port);
        /* Designated replica is caught up, failover to it. */
        replicationSetMaster(server.target_replica_host,
            server.target_replica_port);
    }
}
