#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sds.h"
#include "dict.h"
#include "adlist.h"


static uint64_t dictSdsHash(const void *key);
static int dictSdsKeyCompare(void *privdata, const void *key1,
    const void *key2);
static void dictSdsDestructor(void *privdata, void *val);


static uint64_t dictSdsHash(const void *key) {
    return dictGenHashFunction((unsigned char*)key, sdslen((char*)key));
}

static int dictSdsKeyCompare(void *privdata, const void *key1,
        const void *key2)
{
    int l1,l2;
    DICT_NOTUSED(privdata);

    l1 = sdslen((sds)key1);
    l2 = sdslen((sds)key2);
    if (l1 != l2) return 0;
    return memcmp(key1, key2, l1) == 0;
}

static void dictSdsDestructor(void *privdata, void *val)
{
    DICT_NOTUSED(privdata);
    sdsfree(val);
}


/* Db->dict, keys are sds strings, vals are Redis objects. */
static dictType dbDictType = {
    dictSdsHash,                /* hash function */
    NULL,                       /* key dup */
    NULL,                       /* val dup */
    dictSdsKeyCompare,          /* key compare */
    dictSdsDestructor,          /* key destructor */
    NULL,       /* val destructor */
	NULL
};

int main(int argc,char **argv){
	sds x = sdsnew("foo");
	x=sdscat(x," cat");
	printf("x=>%s\n",x);
	sds x1=sdscpy(x,"a");
	printf("x=>%s x1=>%s\n",x,x1);
	
	x1=sdscatprintf(x1," nice to meet you,%d",100);
	printf("x1=>%s\n",x1);

	// sds s = sdsnew("AA...AA.a.aa.aHelloWorld     :::");
	sds s = sdsnew("abc");
	s = sdstrim(s,"aa");
	printf("s=>%s\n",s);

	const char *ip="127.0.0.1";
	int retCnt=0;
	sds *lines=sdssplitlen(ip,strlen(ip),".",strlen("."),&retCnt);
	for (int i = 0; i < retCnt; i++)
	{
		printf("idx=%d,item=>%s\n",i,lines[i]);
	}
	printf("split count:%d\n",retCnt);

	dict *d01=dictCreate(&dbDictType,NULL);
	printf("create hash success\n");
	//add
	sds k=sdsnew("a");
	sds v=sdsnew("1");
	dictAdd(d01,k,v);

	k=sdsnew("b");
	v=sdsnew("2");
	dictAdd(d01,k,v);
	//find
	dictEntry *r01=dictFind(d01,k);
	sds v01=dictGetVal(r01);
	printf("key:%s value:%s\n",k,v01);

	//loop
	dictIterator *di=dictGetIterator(d01);
	dictEntry *de;
	while((de=dictNext(di))!=NULL){
		sds eleK=dictGetKey(de);
		sds eleV=dictGetVal(de);
		printf("k:%s v:%s\n",eleK,eleV);
	}

	//release dictIterator
	dictReleaseIterator(di);
	dictRelease(d01);


	//create list
	list *l01=listCreate();
	sds item01=sdsnew("a");
	sds item02=sdsnew("b");
	sds item002=sdsnew("B");
	sds item03=sdsnew("c");
	sds item04=sdsnew("01");
	listAddNodeTail(l01,item01);
	listAddNodeTail(l01,item02);
	listAddNodeTail(l01,item03);
	listAddNodeHead(l01,item04);
	
	listNode *dstItem=listSearchKey(l01,item02);
	sds dstStr=listNodeValue(dstItem);
	printf("dstItem.value=%s\n",dstStr);
	l01=listInsertNode(l01,dstItem,item002,1);

	// //loop
	listIter li;
	listNode *ln;
	listRewind(l01,&li);
	while((ln = listNext(&li))) {
		sds myitem=listNodeValue(ln);
		printf("list item:%s\n",myitem);
	}

	// //relase
	listRelease(l01);

	return 0;
}