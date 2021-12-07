#ifndef __CLUSTER_H
#define __CLUSTER_H

/*-----------------------------------------------------------------------------
 * Redis cluster data structures, defines, exported API.
 *----------------------------------------------------------------------------*/

#define CLUSTER_SLOTS 16384
#define CLUSTER_OK 0          /* Everything looks ok */
#define CLUSTER_FAIL 1        /* The cluster can't work */
#define CLUSTER_NAMELEN 40    /* sha1 hex length */
#define CLUSTER_PORT_INCR 10000 /* Cluster port = baseport + PORT_INCR */

/* The following defines are amount of time, sometimes expressed as
 * multiplicators of the node timeout value (when ending with MULT). */
#define CLUSTER_FAIL_REPORT_VALIDITY_MULT 2 /* Fail report validity. */
#define CLUSTER_FAIL_UNDO_TIME_MULT 2 /* Undo fail if master is back. */
#define CLUSTER_MF_TIMEOUT 5000 /* Milliseconds to do a manual failover. */
#define CLUSTER_MF_PAUSE_MULT 2 /* Master pause manual failover mult. */
#define CLUSTER_SLAVE_MIGRATION_DELAY 5000 /* Delay for slave migration. */

/* Redirection errors returned by getNodeByQuery(). */
#define CLUSTER_REDIR_NONE 0          /* Node can serve the request. */
#define CLUSTER_REDIR_CROSS_SLOT 1    /* -CROSSSLOT request. */
#define CLUSTER_REDIR_UNSTABLE 2      /* -TRYAGAIN redirection required */
#define CLUSTER_REDIR_ASK 3           /* -ASK redirection required. */
#define CLUSTER_REDIR_MOVED 4         /* -MOVED redirection required. */
#define CLUSTER_REDIR_DOWN_STATE 5    /* -CLUSTERDOWN, global state. */
#define CLUSTER_REDIR_DOWN_UNBOUND 6  /* -CLUSTERDOWN, unbound slot. */
#define CLUSTER_REDIR_DOWN_RO_STATE 7 /* -CLUSTERDOWN, allow reads. */

struct clusterNode;

/* clusterLink encapsulates everything needed to talk with a remote node. */
// clusterLink 包含了与一个remote node进行通讯所需的全部信息
typedef struct clusterLink {
    mstime_t ctime;             /* Link creation time 连接的创建时间 */
    connection *conn;           /* Connection to remote node TCP套接字描述符 */
    sds sndbuf;                 /* Packet send buffer 发送缓冲区,保存着等待发送给 该连接对应node 的message  */
    char *rcvbuf;               /* Packet reception buffer  接收缓冲区,保存着 该连接对应node 发送给我们的数据 */
    size_t rcvbuf_len;          /* Used size of rcvbuf 接收缓冲区的使用大小 */
    size_t rcvbuf_alloc;        /* Allocated size of rcvbuf 接收缓冲区分配的大小 */
    struct clusterNode *node;   /* Node related to this link if any, or NULL 与该连接对应的node */
} clusterLink;

/* Cluster node flags and macros. */
#define CLUSTER_NODE_MASTER 1     /* The node is a master */
#define CLUSTER_NODE_SLAVE 2      /* The node is a slave */
#define CLUSTER_NODE_PFAIL 4      /* Failure? Need acknowledge */
#define CLUSTER_NODE_FAIL 8       /* The node is believed to be malfunctioning */
#define CLUSTER_NODE_MYSELF 16    /* This node is myself */
#define CLUSTER_NODE_HANDSHAKE 32 /* We have still to exchange the first ping */
#define CLUSTER_NODE_NOADDR   64  /* We don't know the address of this node */
#define CLUSTER_NODE_MEET 128     /* Send a MEET message to this node */
#define CLUSTER_NODE_MIGRATE_TO 256 /* Master eligible for replica migration. Master 有资格进行副本迁移*/
#define CLUSTER_NODE_NOFAILOVER 512 /* Slave will not try to failover. slave不会尝试failover */
#define CLUSTER_NODE_NULL_NAME "\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"

#define nodeIsMaster(n) ((n)->flags & CLUSTER_NODE_MASTER)
#define nodeIsSlave(n) ((n)->flags & CLUSTER_NODE_SLAVE)
#define nodeInHandshake(n) ((n)->flags & CLUSTER_NODE_HANDSHAKE)
#define nodeHasAddr(n) (!((n)->flags & CLUSTER_NODE_NOADDR))
#define nodeWithoutAddr(n) ((n)->flags & CLUSTER_NODE_NOADDR)
#define nodeTimedOut(n) ((n)->flags & CLUSTER_NODE_PFAIL)
#define nodeFailed(n) ((n)->flags & CLUSTER_NODE_FAIL)
#define nodeCantFailover(n) ((n)->flags & CLUSTER_NODE_NOFAILOVER)

/* Reasons why a slave is not able to failover. slave无法执行failover的原因 */
#define CLUSTER_CANT_FAILOVER_NONE 0
#define CLUSTER_CANT_FAILOVER_DATA_AGE 1 //slave数据太老了
#define CLUSTER_CANT_FAILOVER_WAITING_DELAY 2 //执行failover的时间还没到
#define CLUSTER_CANT_FAILOVER_EXPIRED 3 //本轮failover已经过期
#define CLUSTER_CANT_FAILOVER_WAITING_VOTES 4 //没有得到足够多的投票
#define CLUSTER_CANT_FAILOVER_RELOG_PERIOD (60*5) /* seconds. */

/* clusterState todo_before_sleep flags. 以下每个flag代表server在开始下一个event loop前,要做的事情 */
#define CLUSTER_TODO_HANDLE_FAILOVER (1<<0)
#define CLUSTER_TODO_UPDATE_STATE (1<<1)
#define CLUSTER_TODO_SAVE_CONFIG (1<<2)
#define CLUSTER_TODO_FSYNC_CONFIG (1<<3)
#define CLUSTER_TODO_HANDLE_MANUALFAILOVER (1<<4)

/* Message types. 消息类型
 *
 * Note that the PING, PONG and MEET messages are actually the same exact
 * kind of packet. PONG is the reply to ping, in the exact format as a PING,
 * while MEET is a special PING that forces the receiver to add the sender
 * as a node (if it is not already in the list). 
 * 注意 PING PONG 和MEET 实际上是同一种消息.
 * PONG是对PIING的回复,它的实际格式也是PING消息,
 * 而MEET是一种特殊的PING消息, 用于强制消息接收者将消息发送者当做一个node(如果其实际并不在server.cluster->nodes中的话)
 */
#define CLUSTERMSG_TYPE_PING 0          /* Ping */
#define CLUSTERMSG_TYPE_PONG 1          /* Pong (reply to Ping) */
#define CLUSTERMSG_TYPE_MEET 2          /* Meet "let's join" message 请求将某个节点添加到集群中 */
#define CLUSTERMSG_TYPE_FAIL 3          /* Mark node xxx as failing 将某个节点标记为 FAIL */
#define CLUSTERMSG_TYPE_PUBLISH 4       /* Pub/Sub Publish propagation 通过发布与订阅功能广播消息 */
#define CLUSTERMSG_TYPE_FAILOVER_AUTH_REQUEST 5 /* May I failover?  请求进行故障转移操作，要求消息的接收者通过投票来支持消息的发送者 */
#define CLUSTERMSG_TYPE_FAILOVER_AUTH_ACK 6     /* Yes, you have my vote  消息的接收者同意向消息的发送者投票 */
#define CLUSTERMSG_TYPE_UPDATE 7        /* Another node slots configuration, slot布局已经发生变化，消息发送者要求消息接收者进行相应的更新 */
#define CLUSTERMSG_TYPE_MFSTART 8       /* Pause clients for manual failover, 为了进行手动故障转移，暂停各个客户端 */
#define CLUSTERMSG_TYPE_MODULE 9        /* Module cluster API message. */
#define CLUSTERMSG_TYPE_COUNT 10        /* Total number of message types. */

/* Flags that a module can set in order to prevent certain Redis Cluster
 * features to be enabled. Useful when implementing a different distributed
 * system on top of Redis Cluster message bus, using modules. 
 * 下面这些flag用于一个module阻止某个Redis Cluster特性启动.
 */
#define CLUSTER_MODULE_FLAG_NONE 0
#define CLUSTER_MODULE_FLAG_NO_FAILOVER (1<<1)
#define CLUSTER_MODULE_FLAG_NO_REDIRECTION (1<<2)

/* This structure represent elements of node->fail_reports. 该结构代表node->fail_reports中的元素 */
typedef struct clusterNodeFailReport {
    struct clusterNode *node;  /* Node reporting the failure condition. 报告FAIL的node */
    mstime_t time;             /* Time of the last report from this node. 该node最后报告的时间,程序使用这个时间戳来检查下线报告是否过期 */
} clusterNodeFailReport;

typedef struct clusterNode {
    mstime_t ctime; /* Node object creation time. 创建node的时间 */
    char name[CLUSTER_NAMELEN]; /* Node name, hex string, sha1-size. 节点的名字，由 40 个十六进制字符组成 */
    int flags;      /* CLUSTER_NODE_... 节点的标识,使用各种不同的标识值记录node的角色(如master or slave),以及节点目前所处的状态(比如在线或者下线) */
    // 节点当前的配置纪元，用于实现故障转移
    uint64_t configEpoch; /* Last configEpoch observed for this node */

    // 由这个节点负责处理的槽
    // 一共有 REDIS_CLUSTER_SLOTS / 8 个字节长
    // 每个字节的每个位记录了一个槽的保存状态
    // 位的值为 1 表示slot正由本节点处理，值为 0 则表示slot并非本节点处理
    // 比如 slots[0] 的第一个位保存了slot 0 的保存情况
    // slots[0] 的第二个位保存了slot 1 的保存情况，以此类推
    unsigned char slots[CLUSTER_SLOTS/8]; /* slots handled by this node */

    // 该节点负责处理的slot数量
    sds slots_info; /* Slots info represented by string. */

    //该node负责的slot个数
    int numslots;   /* Number of slots handled by this node */

    //如果我是一个master,我下面的slave nodes个数
    int numslaves;  /* Number of slave nodes, if this is a master */

    //如果我是一个master,指向我下面的slave nodes
    struct clusterNode **slaves; /* pointers to slave nodes */
    //如果我是一个slave,指向我的master node
    struct clusterNode *slaveof; /* pointer to the master node. Note that it
                                    may be NULL even if the node is a slave
                                    if we don't have the master node in our
                                    tables. */
    //我们最后向该node发送PING消息的时间
    mstime_t ping_sent;      /* Unix time we sent latest ping */
    //我们最后从该node接收到PONG消息的时间
    mstime_t pong_received;  /* Unix time we received the pong */
    //我们最后从该node接收到任何数据的时间
    mstime_t data_received;  /* Unix time we received any data */
    //该node被标记为 FAIL 的时间
    mstime_t fail_time;      /* Unix time when FAIL flag was set */
    //我们为这个master下的slave 最后投票的时间
    mstime_t voted_time;     /* Last time we voted for a slave of this master */
    //我们接收到该node的offset的时间
    mstime_t repl_offset_time;  /* Unix time we received offset for this node */
    //该node开始成为orphaned master的时间
    mstime_t orphaned_time;     /* Starting time of orphaned master condition */
    //该node最后已知的repl offset
    long long repl_offset;      /* Last known repl offset for this node. */
    //该node的IP地址
    char ip[NET_IP_STR_LEN];  /* Latest known IP address of this node */
    //该node的Port
    int port;                   /* Latest known clients port (TLS or plain). */
    int pport;                  /* Latest known clients plaintext port. Only used
                                   if the main clients port is for TLS. */
    int cport;                  /* Latest known cluster port of this node. */
    //该node的连接
    clusterLink *link;          /* TCP/IP link with this node */
    //一个链表,记录下所有FAIL状态的nodes
    list *fail_reports;         /* List of nodes signaling this as failing */
} clusterNode;

// 集群状态，每个节点都保存着一个这样的状态，记录了它们眼中的集群的样子。
// 另外，虽然这个结构主要用于记录集群的属性，但是为了节约资源，
// 有些与节点有关的属性，比如 slots_to_keys 、 failover_auth_count 
// 也被放到了这个结构里面。
typedef struct clusterState {
    // 指向当前节点的指针
    clusterNode *myself;  /* This node */
    // 集群当前的config epoch,用于实现failover
    uint64_t currentEpoch;
    
    // 集群当前的状态：是OK 还是 FAIL
    int state;            /* CLUSTER_OK, CLUSTER_FAIL, ... */

    // 集群中至少处理着一个slot的master node的数量。
    int size;             /* Num of master nodes with at least one slot */

    // 集群nodes的字典,字典的键是node的名字, 字典的值是ClusterNode结构
    dict *nodes;          /* Hash table of name -> clusterNode structures */

    //nodes很名单, 用于CLUSTER FORGET命令,防止 FORGET的node重新加入到集群中
    dict *nodes_black_list; /* Nodes we don't re-add for a few seconds. */
    //当前node将slot迁移到目标node,对应slot信息.
    //migrating_slots_to[i] = NULL 表示slot i 未被迁移
    //migrating_slots_to[i] = clusterNode_A 表示slot i 要从本node迁移至node A
    clusterNode *migrating_slots_to[CLUSTER_SLOTS];
    //记录要从源节点迁移到本节点的槽，以及进行迁移的源节点
    // importing_slots_from[i] = NULL 表示槽 i 未进行导入
    // importing_slots_from[i] = clusterNode_A 表示正从节点 A 中导入槽 i
    clusterNode *importing_slots_from[CLUSTER_SLOTS];

    // 负责处理各个槽的节点
    // 例如 slots[i] = clusterNode_A 表示槽 i 由节点 A 处理
    clusterNode *slots[CLUSTER_SLOTS];

    //记录每个slot包含的key个数
    uint64_t slots_keys_count[CLUSTER_SLOTS];
    // 当需要对某些槽进行区间（range）操作时，这个跳跃表可以提供方便
    rax *slots_to_keys;

    /* The following fields are used to take the slave state on elections. */
    // 以下这些字段被用于表示failover选举过程中 slave的状态

    mstime_t failover_auth_time; /* Time of previous or next election. 上一次 or 下一次选举开始时间*/
    int failover_auth_count;    /* Number of votes received so far. 截至目前收到的投票数 */
    int failover_auth_sent;     /* True if we already asked for votes. 如果我们发出投票请求,则设置为true */
    int failover_auth_rank;     /* This slave rank for current auth request. 当前failover请求的 slave排名?*/
    uint64_t failover_auth_epoch; /* Epoch of the current election. 当前选举的Epoch? */
    //记录一个slave当前为啥无法执行failover,可以看 CANT_FAILOVER_* 部分
    int cant_failover_reason;   /* Why a slave is currently not able to
                                   failover. See the CANT_FAILOVER_* macros. */
    /* Manual failover state in common. manual failover的状态 */
    mstime_t mf_end;            /* Manual failover time limit (ms unixtime).
                                   It is zero if there is no MF in progress. manual failover的时间限制, 如果为0代表没有manual failover*/
    /* Manual failover state of master. */
    //master的manual failovere状态
    //执行manual failover的slave
    clusterNode *mf_slave;      /* Slave performing the manual failover. */

    /* Manual failover state of slave. */
    //slave的manual failover状态
    //slave开始manual failovere需要的的master offset, 为-1 代表没收到 master offset
    long long mf_master_offset; /* Master offset the slave needs to start MF
                                   or -1 if still not received. */
    //如果非0代表manual failover可以请求master投票了
    int mf_can_start;           /* If non-zero signal that the manual failover
                                   can start requesting masters vote.*/

    /* The following fields are used by masters to take state on elections. */
    //以下这些域由master器使用，用于记录选举时的状态

    //最后一次进行投票的epoch
    uint64_t lastVoteEpoch;     /* Epoch of the last vote granted. */

    //在进入下个event loop之前要做的事情，以各个 flag 来记录
    int todo_before_sleep; /* Things to do in clusterBeforeSleep(). */

    /* Messages received and sent by type. */
    //通过 cluster 发送or 接收到的消息数量
    long long stats_bus_messages_sent[CLUSTERMSG_TYPE_COUNT];
    long long stats_bus_messages_received[CLUSTERMSG_TYPE_COUNT];
    long long stats_pfail_nodes;    /* Number of nodes in PFAIL status,
                                       excluding nodes without address. */
} clusterState;

/* Redis cluster messages header */

/* Initially we don't know our "name", but we'll find it once we connect
 * to the first node, using the getsockname() function. Then we'll use this
 * address for all the next messages. */
typedef struct {
    // 节点的名字
    // 在刚开始的时候，节点的名字会是随机的
    // 当 MEET 信息发送并得到回复之后，集群就会为节点设置正式的名字
    char nodename[CLUSTER_NAMELEN];

    // 最后一次向该节点发送 PING 消息的时间戳
    uint32_t ping_sent;
    // 最后一次从该节点接收到 PONG 消息的时间戳
    uint32_t pong_received;
    // 节点的IP地址
    char ip[NET_IP_STR_LEN];  /* IP address last time it was seen */
    // 节点的端口
    uint16_t port;              /* base port last time it was seen */
    uint16_t cport;             /* cluster port last time it was seen */
    //节点的标识
    uint16_t flags;             /* node->flags copy */
    uint16_t pport;             /* plaintext-port, when base port is TLS */
    uint16_t notused1;
} clusterMsgDataGossip;

typedef struct {
    //下线node的名字
    char nodename[CLUSTER_NAMELEN];
} clusterMsgDataFail;

typedef struct {
    //频道名长度
    uint32_t channel_len;
    //消息长度
    uint32_t message_len;
    //8字节作为占位符
    unsigned char bulk_data[8]; /* 8 bytes just as placeholder. */
} clusterMsgDataPublish;

typedef struct {
    //指定node的config epoch
    uint64_t configEpoch; /* Config epoch of the specified instance. */
    //node的名字
    char nodename[CLUSTER_NAMELEN]; /* Name of the slots owner. */
    //node的slot分布
    unsigned char slots[CLUSTER_SLOTS/8]; /* Slots bitmap. */
} clusterMsgDataUpdate;

typedef struct {
    uint64_t module_id;     /* ID of the sender module. */
    uint32_t len;           /* ID of the sender module. */
    uint8_t type;           /* Type from 0 to 255. */
    unsigned char bulk_data[3]; /* 3 bytes just as placeholder. */
} clusterMsgModule;

union clusterMsgData {
    /* PING, MEET and PONG */
    struct {
        /* Array of N clusterMsgDataGossip structures */
        clusterMsgDataGossip gossip[1];
    } ping;

    /* FAIL */
    struct {
        clusterMsgDataFail about;
    } fail;

    /* PUBLISH */
    struct {
        clusterMsgDataPublish msg;
    } publish;

    /* UPDATE */
    struct {
        clusterMsgDataUpdate nodecfg;
    } update;

    /* MODULE */
    struct {
        clusterMsgModule msg;
    } module;
};

#define CLUSTER_PROTO_VER 1 /* Cluster bus protocol version. */

typedef struct {
    char sig[4];        /* Signature "RCmb" (Redis Cluster message bus). */
    //消息的长度(包括消息头长度和消息正文长度)
    uint32_t totlen;    /* Total length of this message */
    //协议版本
    uint16_t ver;       /* Protocol version, currently set to 1. */
    //TCP端口
    uint16_t port;      /* TCP base port number. */
    //消息类型
    uint16_t type;      /* Message type */
    // 消息正文包含的节点信息数量
    // 只在发送 MEET 、 PING 和 PONG 这三种 Gossip 协议消息时使用
    uint16_t count;     /* Only used for some kind of messages. */
    //发送者当前config epoch
    uint64_t currentEpoch;  /* The epoch accordingly to the sending node. */
    // 如果消息发送者是一个master，那么这里记录的是消息发送者的配置纪元
    // 如果消息发送者是一个slave，那么这里记录的是消息发送者正在复制的master的配置纪元
    uint64_t configEpoch;   /* The config epoch if it's a master, or the last
                               epoch advertised by its master if it is a
                               slave. */
    //如果消息发送者是一个master,则代表master replication offset
    //如果消息发送者是一个slave,则代表 replication offset
    uint64_t offset;    /* Master replication offset if node is a master or
                           processed replication offset if node is a slave. */
    //发送者而名字(ID)
    char sender[CLUSTER_NAMELEN]; /* Name of the sender node */
    //发送者负责的slot信息(如果我是slave,则这里设置是我的master负责的slot)
    unsigned char myslots[CLUSTER_SLOTS/8];
    // 如果消息发送者是一个slave，那么这里记录的是消息发送者正在复制的master的名字
    // 如果消息发送者是一个master，那么这里记录的是 CLUSTER_NODE_NULL_NAME
    // （一个 40 字节长，值全为 0 的字节数组）
    char slaveof[CLUSTER_NAMELEN];
    //发送者的IP
    char myip[NET_IP_STR_LEN];    /* Sender IP, if not all zeroed. */
    //留作未来使用的32字节
    char notused1[32];  /* 32 bytes reserved for future usage. */
    //消息发送者端口号
    uint16_t pport;      /* Sender TCP plaintext port, if base port is TLS */
    uint16_t cport;      /* Sender TCP cluster bus port */
    //消息发送者flag
    uint16_t flags;      /* Sender node flags */
    //消息发送者集群状态
    unsigned char state; /* Cluster state from the POV of the sender */
    //消息标识
    unsigned char mflags[3]; /* Message flags: CLUSTERMSG_FLAG[012]_... */
    // 消息的正文（或者说，内容）
    union clusterMsgData data;
} clusterMsg;

#define CLUSTERMSG_MIN_LEN (sizeof(clusterMsg)-sizeof(union clusterMsgData))

/* Message flags better specify the packet content or are used to
 * provide some information about the node state. */
#define CLUSTERMSG_FLAG0_PAUSED (1<<0) /* Master paused for manual failover. */
#define CLUSTERMSG_FLAG0_FORCEACK (1<<1) /* Give ACK to AUTH_REQUEST even if
                                            master is up. */

/* ---------------------- API exported outside cluster.c -------------------- */
void clusterInit(void);
void clusterCron(void);
void clusterBeforeSleep(void);
clusterNode *getNodeByQuery(client *c, struct redisCommand *cmd, robj **argv, int argc, int *hashslot, int *ask);
clusterNode *clusterLookupNode(const char *name);
int clusterRedirectBlockedClientIfNeeded(client *c);
void clusterRedirectClient(client *c, clusterNode *n, int hashslot, int error_code);
void migrateCloseTimedoutSockets(void);
int verifyClusterConfigWithData(void);
unsigned long getClusterConnectionsCount(void);
int clusterSendModuleMessageToTarget(const char *target, uint64_t module_id, uint8_t type, unsigned char *payload, uint32_t len);
void clusterPropagatePublish(robj *channel, robj *message);
unsigned int keyHashSlot(char *key, int keylen);

#endif /* __CLUSTER_H */
