# rq_hash

源码基于5.10
## 1. elv_rqhash_reposition
```c
void elv_rqhash_reposition(struct request_queue *q, struct request *rq)
{
	// 从哈希表里删除
	__elv_rqhash_del(rq);

	// 重新加入哈希表
	elv_rqhash_add(q, rq);
}

static inline void __elv_rqhash_del(struct request *rq)
{
	// 从哈希表里删除这一项
	hash_del(&rq->hash);
	// 取消已经哈希的标志
	rq->rq_flags &= ~RQF_HASHED;
}

void elv_rqhash_add(struct request_queue *q, struct request *rq)
{
	struct elevator_queue *e = q->elevator;

	// 判断是否有RQF_HASHED标志
	BUG_ON(ELV_ON_HASH(rq));

	// key是请求扇区的数量
	hash_add(e->hash, &rq->hash, rq_hash_key(rq));
	// 标记已经哈希
	rq->rq_flags |= RQF_HASHED;
}

#define rq_hash_key(rq)		(blk_rq_pos(rq) + blk_rq_sectors(rq))
```