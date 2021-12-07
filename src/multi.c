/*
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

/* ================================ MULTI/EXEC ============================== */

/* Client state initialization for MULTI/EXEC */
void initClientMultiState(client *c) {
    c->mstate.commands = NULL;
    c->mstate.count = 0;
    c->mstate.cmd_flags = 0;
    c->mstate.cmd_inv_flags = 0;
}

/* Release all the resources associated with MULTI/EXEC state */
void freeClientMultiState(client *c) {
    int j;

    for (j = 0; j < c->mstate.count; j++) {
        int i;
        multiCmd *mc = c->mstate.commands+j;

        for (i = 0; i < mc->argc; i++)
            decrRefCount(mc->argv[i]);
        zfree(mc->argv);
    }
    zfree(c->mstate.commands);
}

/* Add a new command into the MULTI commands queue */
//添加新命令到 MULTI 命令队列中
void queueMultiCommand(client *c) {
    multiCmd *mc;
    int j;

    /* No sense to waste memory if the transaction is already aborted.
     * this is useful in case client sends these in a pipeline, or doesn't
     * bother to read previous responses and didn't notice the multi was already
     * aborted. */
    if (c->flags & (CLIENT_DIRTY_CAS|CLIENT_DIRTY_EXEC))
        return;

    c->mstate.commands = zrealloc(c->mstate.commands,
            sizeof(multiCmd)*(c->mstate.count+1));
    mc = c->mstate.commands+c->mstate.count;
    mc->cmd = c->cmd;
    mc->argc = c->argc;
    mc->argv = zmalloc(sizeof(robj*)*c->argc);
    memcpy(mc->argv,c->argv,sizeof(robj*)*c->argc);
    for (j = 0; j < c->argc; j++)
        incrRefCount(mc->argv[j]);
    c->mstate.count++;
    c->mstate.cmd_flags |= c->cmd->flags;
    c->mstate.cmd_inv_flags |= ~c->cmd->flags;
}

//比如执行 discard 命令
void discardTransaction(client *c) {
    freeClientMultiState(c);
    initClientMultiState(c);
    c->flags &= ~(CLIENT_MULTI|CLIENT_DIRTY_CAS|CLIENT_DIRTY_EXEC);
    unwatchAllKeys(c);
}

/* Flag the transaction as DIRTY_EXEC so that EXEC will fail.
 * Should be called every time there is an error while queueing a command. 
 * 将事务打上 DIRTY_EXEC 标记 以便 执行 EXEC 命令时，事务会失败.
 * 事务中，将命令入队时 如果发生错误，都需要执行该函数
 */
void flagTransaction(client *c) {
    if (c->flags & CLIENT_MULTI)
        c->flags |= CLIENT_DIRTY_EXEC;
}

void multiCommand(client *c) {
    // 不能在事务中嵌套事务
    if (c->flags & CLIENT_MULTI) {
        addReplyError(c,"MULTI calls can not be nested");
        return;
    }
    // 打开事务 FLAG
    c->flags |= CLIENT_MULTI;

    addReply(c,shared.ok);
}

void discardCommand(client *c) {
    // 不能在客户端未进行事务状态下 执行DISCARD
    if (!(c->flags & CLIENT_MULTI)) {
        addReplyError(c,"DISCARD without MULTI");
        return;
    }
    discardTransaction(c);
    addReply(c,shared.ok);
}

void beforePropagateMulti() {
    /* Propagating MULTI */
    serverAssert(!server.propagate_in_transaction);
    server.propagate_in_transaction = 1;
}

void afterPropagateExec() {
    /* Propagating EXEC */
    serverAssert(server.propagate_in_transaction == 1);
    server.propagate_in_transaction = 0;
}

/* Send a MULTI command to all the slaves and AOF file. Check the execCommand
 * implementation for more information. 
 * 向所有附属节点和 AOF 文件传播 MULTI 命令。
 */
void execCommandPropagateMulti(int dbid) {
    beforePropagateMulti();
    propagate(server.multiCommand,dbid,&shared.multi,1,
              PROPAGATE_AOF|PROPAGATE_REPL);
}

void execCommandPropagateExec(int dbid) {
    propagate(server.execCommand,dbid,&shared.exec,1,
              PROPAGATE_AOF|PROPAGATE_REPL);
    afterPropagateExec();
}

/* Aborts a transaction, with a specific error message.
 * The transaction is always aborted with -EXECABORT so that the client knows
 * the server exited the multi state, but the actual reason for the abort is
 * included too.
 * Note: 'error' may or may not end with \r\n. see addReplyErrorFormat. 
 * 终止事务,并返回 特定error 信息
 * 事务被终止后总是 伴随着 -EXECABORT 信息, 以便client知道server 退出了MULTI状态. 同时返回给client的信息中 实际终止的原因 也会包含.
 */
void execCommandAbort(client *c, sds error) {
    discardTransaction(c);

    if (error[0] == '-') error++;
    addReplyErrorFormat(c, "-EXECABORT Transaction discarded because of: %s", error);

    /* Send EXEC to clients waiting data from MONITOR. We did send a MULTI
     * already, and didn't send any of the queued commands, now we'll just send
     * EXEC so it is clear that the transaction is over. */
    replicationFeedMonitors(c,server.monitors,c->db->id,c->argv,c->argc);
}

//执行EXEC 命令
void execCommand(client *c) {
    int j;
    robj **orig_argv;
    int orig_argc;
    struct redisCommand *orig_cmd;
    int was_master = server.masterhost == NULL;

    if (!(c->flags & CLIENT_MULTI)) {
        addReplyError(c,"EXEC without MULTI");
        return;
    }

    /* EXEC with expired watched key is disallowed*/
    if (isWatchedKeyExpired(c)) {
        c->flags |= (CLIENT_DIRTY_CAS);
    }

    /* Check if we need to abort the EXEC because: 检查我们是否需要abort EXEC
     * 1) Some WATCHed key was touched. 存在watch的key被更新了?
     * 2) There was a previous error while queueing commands. 将命令加入队列时发生了错误
     * A failed EXEC in the first case returns a multi bulk nil object 
     * (technically it is not an error but a special behavior), while
     * in the second an EXECABORT error is returned.
     * 第一种情况下失败的 EXEC 返回一个多块 nil 对象（从技术上讲，它不是错误而是一种特殊行为），而在第二种情况下返回 EXECABORT 错误。
     */
    if (c->flags & (CLIENT_DIRTY_CAS|CLIENT_DIRTY_EXEC)) {
        addReply(c, c->flags & CLIENT_DIRTY_EXEC ? shared.execaborterr :
                                                   shared.nullarray[c->resp]);
        discardTransaction(c);
        return;
    }

    uint64_t old_flags = c->flags;

    /* we do not want to allow blocking commands inside multi. 事务中拒绝会阻塞的命令 */
    c->flags |= CLIENT_DENY_BLOCKING;

    /* Exec all the queued commands */
    // 已经可以保证安全性了，取消客户端对所有键的监视
    unwatchAllKeys(c); /* Unwatch ASAP otherwise we'll waste CPU cycles */

    server.in_exec = 1;

    orig_argv = c->argv;
    orig_argc = c->argc;
    orig_cmd = c->cmd;
    addReplyArrayLen(c,c->mstate.count);
    // 执行事务中的命令
    for (j = 0; j < c->mstate.count; j++) {
        // 因为 Redis 的命令必须在客户端的上下文中执行
        // 所以要将事务队列中的命令、命令参数等设置给客户端
        c->argc = c->mstate.commands[j].argc;
        c->argv = c->mstate.commands[j].argv;
        c->cmd = c->mstate.commands[j].cmd;

        /* ACL permissions are also checked at the time of execution in case
         * they were changed after the commands were queued. */
        int acl_errpos;
        int acl_retval = ACLCheckAllPerm(c,&acl_errpos);
        if (acl_retval != ACL_OK) {
            char *reason;
            switch (acl_retval) {
            case ACL_DENIED_CMD:
                reason = "no permission to execute the command or subcommand";
                break;
            case ACL_DENIED_KEY:
                reason = "no permission to touch the specified keys";
                break;
            case ACL_DENIED_CHANNEL:
                reason = "no permission to access one of the channels used "
                         "as arguments";
                break;
            default:
                reason = "no permission";
                break;
            }
            addACLLogEntry(c,acl_retval,acl_errpos,NULL);
            addReplyErrorFormat(c,
                "-NOPERM ACLs rules changed between the moment the "
                "transaction was accumulated and the EXEC call. "
                "This command is no longer allowed for the "
                "following reason: %s", reason);
        } else {
            //执行命令
            call(c,server.loading ? CMD_CALL_NONE : CMD_CALL_FULL);
            serverAssert((c->flags & CLIENT_BLOCKED) == 0);
        }

        /* Commands may alter argc/argv, restore mstate. */
        // 因为执行后命令、命令参数可能会被改变
        // 比如 SPOP 会被改写为 SREM
        // 所以这里需要更新事务队列中的命令和参数
        // 确保附属节点和 AOF 的数据一致性
        c->mstate.commands[j].argc = c->argc;
        c->mstate.commands[j].argv = c->argv;
        c->mstate.commands[j].cmd = c->cmd;
    }

    // restore old DENY_BLOCKING value
    if (!(old_flags & CLIENT_DENY_BLOCKING))
        c->flags &= ~CLIENT_DENY_BLOCKING;

    // 还原命令、命令参数
    c->argv = orig_argv;
    c->argc = orig_argc;
    c->cmd = orig_cmd;
    discardTransaction(c);// 清理事务状态

    /* Make sure the EXEC command will be propagated as well if MULTI
     * was already propagated. 确保EXEC命令也会传播,既然 MULTI 已经传播到 slave or monitor client了 */
    if (server.propagate_in_transaction) {
        int is_master = server.masterhost == NULL;
        server.dirty++;
        /* If inside the MULTI/EXEC block this instance was suddenly
         * switched from master to slave (using the SLAVEOF command), the
         * initial MULTI was propagated into the replication backlog, but the
         * rest was not. We need to make sure to at least terminate the
         * backlog with the final EXEC. */
        if (server.repl_backlog && was_master && !is_master) {
            char *execcmd = "*1\r\n$4\r\nEXEC\r\n";
            feedReplicationBacklog(execcmd,strlen(execcmd));
        }
        afterPropagateExec();
    }

    server.in_exec = 0;
}

/* ===================== WATCH (CAS alike for MULTI/EXEC) ===================
 *
 * The implementation uses a per-DB hash table mapping keys to list of clients
 * WATCHing those keys, so that given a key that is going to be modified
 * we can mark all the associated clients as dirty.
 *
 * Also every client contains a list of WATCHed keys so that's possible to
 * un-watch such keys when the client is freed or when UNWATCH is called. */

/* In the client->watched_keys list we need to use watchedKey structures
 * as in order to identify a key in Redis we need both the key name and the
 * DB */
typedef struct watchedKey {
    robj *key;
    redisDb *db;
} watchedKey;

/* Watch for the specified key */
void watchForKey(client *c, robj *key) {
    list *clients = NULL;
    listIter li;
    listNode *ln;
    watchedKey *wk;

    /* Check if we are already watching for this key */
    listRewind(c->watched_keys,&li);
    while((ln = listNext(&li))) {
        wk = listNodeValue(ln);
        if (wk->db == c->db && equalStringObjects(key,wk->key))
            return; /* Key already watched */
    }
    /* This key is not already watched in this DB. Let's add it */
    clients = dictFetchValue(c->db->watched_keys,key);
    if (!clients) {
        clients = listCreate();
        dictAdd(c->db->watched_keys,key,clients);
        incrRefCount(key);
    }
    listAddNodeTail(clients,c);
    /* Add the new key to the list of keys watched by this client */
    wk = zmalloc(sizeof(*wk));
    wk->key = key;
    wk->db = c->db;
    incrRefCount(key);
    listAddNodeTail(c->watched_keys,wk);
}

/* Unwatch all the keys watched by this client. To clean the EXEC dirty
 * flag is up to the caller. */
void unwatchAllKeys(client *c) {
    listIter li;
    listNode *ln;

    if (listLength(c->watched_keys) == 0) return;
    listRewind(c->watched_keys,&li);
    while((ln = listNext(&li))) {
        list *clients;
        watchedKey *wk;

        /* Lookup the watched key -> clients list and remove the client
         * from the list */
        wk = listNodeValue(ln);
        clients = dictFetchValue(wk->db->watched_keys, wk->key);
        serverAssertWithInfo(c,NULL,clients != NULL);
        listDelNode(clients,listSearchKey(clients,c));
        /* Kill the entry at all if this was the only client */
        if (listLength(clients) == 0)
            dictDelete(wk->db->watched_keys, wk->key);
        /* Remove this watched key from the client->watched list */
        listDelNode(c->watched_keys,ln);
        decrRefCount(wk->key);
        zfree(wk);
    }
}

/* iterates over the watched_keys list and
 * look for an expired key . */
int isWatchedKeyExpired(client *c) {
    listIter li;
    listNode *ln;
    watchedKey *wk;
    if (listLength(c->watched_keys) == 0) return 0;
    listRewind(c->watched_keys,&li);
    while ((ln = listNext(&li))) {
        wk = listNodeValue(ln);
        if (keyIsExpired(wk->db, wk->key)) return 1;
    }

    return 0;
}

/* "Touch" a key, so that if this key is being WATCHed by some client the
 * next EXEC will fail. */
void touchWatchedKey(redisDb *db, robj *key) {
    list *clients;
    listIter li;
    listNode *ln;

    if (dictSize(db->watched_keys) == 0) return;
    clients = dictFetchValue(db->watched_keys, key);
    if (!clients) return;

    /* Mark all the clients watching this key as CLIENT_DIRTY_CAS */
    /* Check if we are already watching for this key */
    listRewind(clients,&li);
    while((ln = listNext(&li))) {
        client *c = listNodeValue(ln);

        c->flags |= CLIENT_DIRTY_CAS;
    }
}

/* Set CLIENT_DIRTY_CAS to all clients of DB when DB is dirty.
 * It may happen in the following situations:
 * FLUSHDB, FLUSHALL, SWAPDB
 *
 * replaced_with: for SWAPDB, the WATCH should be invalidated if
 * the key exists in either of them, and skipped only if it
 * doesn't exist in both. */
void touchAllWatchedKeysInDb(redisDb *emptied, redisDb *replaced_with) {
    listIter li;
    listNode *ln;
    dictEntry *de;

    if (dictSize(emptied->watched_keys) == 0) return;

    dictIterator *di = dictGetSafeIterator(emptied->watched_keys);
    while((de = dictNext(di)) != NULL) {
        robj *key = dictGetKey(de);
        if (dictFind(emptied->dict, key->ptr) ||
            (replaced_with && dictFind(replaced_with->dict, key->ptr)))
        {
            list *clients = dictGetVal(de);
            if (!clients) continue;
            listRewind(clients,&li);
            while((ln = listNext(&li))) {
                client *c = listNodeValue(ln);
                c->flags |= CLIENT_DIRTY_CAS;
            }
        }
    }
    dictReleaseIterator(di);
}

void watchCommand(client *c) {
    int j;

    if (c->flags & CLIENT_MULTI) {
        addReplyError(c,"WATCH inside MULTI is not allowed");
        return;
    }
    for (j = 1; j < c->argc; j++)
        watchForKey(c,c->argv[j]);
    addReply(c,shared.ok);
}

void unwatchCommand(client *c) {
    unwatchAllKeys(c);
    c->flags &= (~CLIENT_DIRTY_CAS);
    addReply(c,shared.ok);
}
