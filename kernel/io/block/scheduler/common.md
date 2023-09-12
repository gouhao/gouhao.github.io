# 调度器共用
源码基于5.10

## 1. 注册
```c
int elv_register(struct elevator_type *e)
{
	// 有icq_size则创建之.todo: 后面再看
	if (e->icq_size) {
		if (WARN_ON(e->icq_size < sizeof(struct io_cq)) ||
		    WARN_ON(e->icq_align < __alignof__(struct io_cq)))
			return -EINVAL;

		snprintf(e->icq_cache_name, sizeof(e->icq_cache_name),
			 "%s_io_cq", e->elevator_name);
		e->icq_cache = kmem_cache_create(e->icq_cache_name, e->icq_size,
						 e->icq_align, 0, NULL);
		if (!e->icq_cache)
			return -ENOMEM;
	}

	spin_lock(&elv_list_lock);
	
	// 先找看是不是已经注册过了
	if (elevator_find(e->elevator_name, 0)) {
		spin_unlock(&elv_list_lock);
		kmem_cache_destroy(e->icq_cache);
		// 如果已注册了返回忙, 为什么不是EEXIST
		return -EBUSY;
	}
	// 添加到elv_列表
	list_add_tail(&e->list, &elv_list);
	spin_unlock(&elv_list_lock);

	printk(KERN_INFO "io scheduler %s registered\n", e->elevator_name);

	return 0;
}
```

## 2. 查找
```c
static struct elevator_type *elevator_find(const char *name,
					   unsigned int required_features)
{
	struct elevator_type *e;

	// 遍历elv列表
	list_for_each_entry(e, &elv_list, list) {
		// 匹配名称与特征,如果获取的话返回对象
		if (elevator_match(e, name, required_features))
			return e;
	}

	return NULL;
}

static bool elevator_match(const struct elevator_type *e, const char *name,
			   unsigned int required_features)
{
	// 先比较特征, 不支持这个特征,不匹配
	if (!elv_support_features(e->elevator_features, required_features))
		return false;
	// 再比较名字,名称特征都相同则匹配
	if (!strcmp(e->elevator_name, name))
		return true;
	// 走到这儿表示,支持这个特征,但名称不匹配,如果有别名的话比较别名
	if (e->elevator_alias && !strcmp(e->elevator_alias, name))
		return true;

	return false;
}

static inline bool elv_support_features(unsigned int elv_features,
					unsigned int required_features)
{
	// 判断调度器的特性里是否包含此特性
	return (required_features & elv_features) == required_features;
}
```

## 3. 反注册
```c
void elv_unregister(struct elevator_type *e)
{
	spin_lock(&elv_list_lock);
	// 先从列表里删除
	list_del_init(&e->list);
	spin_unlock(&elv_list_lock);

	// 如果有icq缓存则释放之
	if (e->icq_cache) {
		rcu_barrier();
		kmem_cache_destroy(e->icq_cache);
		e->icq_cache = NULL;
	}
}
```

## 4. 合并
```c
bool blk_mq_sched_try_merge(struct request_queue *q, struct bio *bio,
		unsigned int nr_segs, struct request **merged_request)
{
	struct request *rq;

	// 判断合并类型
	switch (elv_merge(q, &rq, bio)) {
	case ELEVATOR_BACK_MERGE:
		// 后向合并

		// 调用调度器的allow_merge
		if (!blk_mq_sched_allow_merge(q, rq, bio))
			return false;
		// 是否能向后合并
		if (bio_attempt_back_merge(rq, bio, nr_segs) != BIO_MERGE_OK)
			return false;
		// 尝试合并请滶，返回值是被合并的请求
		*merged_request = attempt_back_merge(q, rq);

		// 如果没有合并，则调用调度器的合并
		if (!*merged_request)
			elv_merged_request(q, rq, ELEVATOR_BACK_MERGE);
		return true;
	case ELEVATOR_FRONT_MERGE:
		// 前向合并

		// 调用调度器的allow_merge
		if (!blk_mq_sched_allow_merge(q, rq, bio))
			return false;
		// 是否能向前合并
		if (bio_attempt_front_merge(rq, bio, nr_segs) != BIO_MERGE_OK)
			return false;
		// 尝试向前合并
		*merged_request = attempt_front_merge(q, rq);
		// 如果合并失败，则调用调度器的合并
		if (!*merged_request)
			elv_merged_request(q, rq, ELEVATOR_FRONT_MERGE);
		return true;
	case ELEVATOR_DISCARD_MERGE:
		// 丢弃合并
		return bio_attempt_discard_merge(q, rq, bio) == BIO_MERGE_OK;
	default:
		return false;
	}
}

enum elv_merge elv_merge(struct request_queue *q, struct request **req,
		struct bio *bio)
{
	struct elevator_queue *e = q->elevator;
	struct request *__rq;

	// 队列或bio不允许合并
	if (blk_queue_nomerges(q) || !bio_mergeable(bio))
		return ELEVATOR_NO_MERGE;

	// 以前有合并的 && 能否和上次的合并
	if (q->last_merge && elv_bio_merge_ok(q->last_merge, bio)) {
		// 计算合并类型
		enum elv_merge ret = blk_try_merge(q->last_merge, bio);

		// 可以合并,则使用上次合并的请求
		if (ret != ELEVATOR_NO_MERGE) {
			*req = q->last_merge;
			return ret;
		}
	}

	// 走到这儿表示不能和上次的合并

	// 测试QUEUE_FLAG_NOXMERGES,是否禁用了扩展合并
	if (blk_queue_noxmerges(q))
		return ELEVATOR_NO_MERGE;

	// 找到bi_sector之前的一个rq,尝试后向合并
	__rq = elv_rqhash_find(q, bio->bi_iter.bi_sector);

	// 如果找到了判断是否能合并
	if (__rq && elv_bio_merge_ok(__rq, bio)) {
		// 可以合并
		*req = __rq;

		// 判断丢弃操作
		if (blk_discard_mergable(__rq))
			return ELEVATOR_DISCARD_MERGE;
		// 返回后向合并
		return ELEVATOR_BACK_MERGE;
	}

	// 走到这儿表示后向合并不行,则调用调度器尝试前向合并
	if (e->type->ops.request_merge)
		return e->type->ops.request_merge(q, req, bio);

	return ELEVATOR_NO_MERGE;
}

bool elv_bio_merge_ok(struct request *rq, struct bio *bio)
{
	// 请求不能合并
	if (!blk_rq_merge_ok(rq, bio))
		return false;

	// 调用调度器的allow_merge函数(如果有的话),看其是否允许合并
	if (!elv_iosched_allow_bio_merge(rq, bio))
		return false;

	return true;
}

struct request *elv_rqhash_find(struct request_queue *q, sector_t offset)
{
	struct elevator_queue *e = q->elevator;
	struct hlist_node *next;
	struct request *rq;

	hash_for_each_possible_safe(e->hash, rq, next, hash, offset) {
		BUG_ON(!ELV_ON_HASH(rq));

		// 请求不能合并,则从哈希表里把它删除
		if (unlikely(!rq_mergeable(rq))) {
			__elv_rqhash_del(rq);
			continue;
		}

		// 如果rq的结束点刚好是bio的起点,则返回rq
		// rq_hash_key是计算请求的扇区长度
		if (rq_hash_key(rq) == offset)
			return rq;
	}

	return NULL;
}

#define rq_hash_key(rq)		(blk_rq_pos(rq) + blk_rq_sectors(rq))

static struct request *attempt_back_merge(struct request_queue *q,
		struct request *rq)
{
	// 调用调度器的next_request函数
	struct request *next = elv_latter_request(q, rq);

	// 如果有下个请求,则尝试合并请求
	if (next)
		return attempt_merge(q, rq, next);

	return NULL;
}

void elv_merged_request(struct request_queue *q, struct request *rq,
		enum elv_merge type)
{
	struct elevator_queue *e = q->elevator;

	// 调request_merged函数
	if (e->type->ops.request_merged)
		e->type->ops.request_merged(q, rq, type);

	// 如果是后向合并,重新计算哈希值,并加入哈希表
	if (type == ELEVATOR_BACK_MERGE)
		elv_rqhash_reposition(q, rq);

	// 设置最后一次合并的请求
	q->last_merge = rq;
}

```
### 4.1. 尝试合并请求
```c
static struct request *attempt_merge(struct request_queue *q,
				     struct request *req, struct request *next)
{
	// 请求不允许合并
	if (!rq_mergeable(req) || !rq_mergeable(next))
		return NULL;

	// 2个请求的操作不同
	if (req_op(req) != req_op(next))
		return NULL;

	// 数据传输方向不同 || 请求的磁盘不同
	if (rq_data_dir(req) != rq_data_dir(next)
	    || req->rq_disk != next->rq_disk)
		return NULL;
	
	// 不允许writesame
	if (req_op(req) == REQ_OP_WRITE_SAME &&
	    !blk_write_same_mergeable(req->bio, next->bio))
		return NULL;

	// write_hint不同
	if (req->write_hint != next->write_hint)
		return NULL;

	// io优先级不相同
	if (req->ioprio != next->ioprio)
		return NULL;

	// 计算合并类型
	switch (blk_try_req_merge(req, next)) {
	case ELEVATOR_DISCARD_MERGE:
		// 丢弃合并
		if (!req_attempt_discard_merge(q, req, next))
			return NULL;
		break;
	case ELEVATOR_BACK_MERGE:
		// 后项合并
		if (!ll_merge_requests_fn(q, req, next))
			return NULL;
		break;
	default:
		return NULL;
	}

	// 如果其中有已经合并的请求，或者有快点失败的请求
	if (((req->rq_flags | next->rq_flags) & RQF_MIXED_MERGE) ||
	    (req->cmd_flags & REQ_FAILFAST_MASK) !=
	    (next->cmd_flags & REQ_FAILFAST_MASK)) {
		// 设置2个请求都是混合
		blk_rq_set_mixed_merge(req);
		blk_rq_set_mixed_merge(next);
	}

	// 统一start_time
	if (next->start_time_ns < req->start_time_ns)
		req->start_time_ns = next->start_time_ns;

	// 把next合并到req里
	req->biotail->bi_next = next->bio;
	req->biotail = next->biotail;

	// 增加req的长度
	req->__data_len += blk_rq_bytes(next);

	// 如果不是丢弃合并，则调用调度器合并
	if (!blk_discard_mergable(req))
		elv_merge_requests(q, req, next);

	// 统计相关
	blk_account_io_merge_request(next);

	trace_block_rq_merge(q, next);

	// 清除next里的bio
	next->bio = NULL;
	return next;
}

static enum elv_merge blk_try_req_merge(struct request *req,
					struct request *next)
{
	// 先判断丢弃操作
	if (blk_discard_mergable(req))
		return ELEVATOR_DISCARD_MERGE;
	// 请求起点+长度 == 下一请求的起点，可以后向合并
	else if (blk_rq_pos(req) + blk_rq_sectors(req) == blk_rq_pos(next))
		return ELEVATOR_BACK_MERGE;

	// 不能合并。todo 为什么不判断前向合并
	return ELEVATOR_NO_MERGE;
}

void elv_merge_requests(struct request_queue *q, struct request *rq,
			     struct request *next)
{
	struct elevator_queue *e = q->elevator;

	// 调用调度器函数
	if (e->type->ops.requests_merged)
		e->type->ops.requests_merged(q, rq, next);

	// 重新生成rq的位置
	elv_rqhash_reposition(q, rq);
	// 设置最后一次合并的
	q->last_merge = rq;
}
```

### 4.3. 前向合并
```c
static struct request *attempt_front_merge(struct request_queue *q,
		struct request *rq)
{
	// 获取前面的请求
	struct request *prev = elv_former_request(q, rq);

	// 如果有前向的请求，那尝试合并
	if (prev)
		return attempt_merge(q, prev, rq);

	return NULL;
}
```

### 4.4. 插入时的合并
```c
bool elv_attempt_insert_merge(struct request_queue *q, struct request *rq)
{
	struct request *__rq;
	bool ret;

	if (blk_queue_nomerges(q))
		return false;

	/*
	 * First try one-hit cache.
	 */
	if (q->last_merge && blk_attempt_req_merge(q, q->last_merge, rq))
		return true;

	if (blk_queue_noxmerges(q))
		return false;

	ret = false;
	/*
	 * See if our hash lookup can find a potential backmerge.
	 */
	while (1) {
		__rq = elv_rqhash_find(q, blk_rq_pos(rq));
		if (!__rq || !blk_attempt_req_merge(q, __rq, rq))
			break;

		/* The merged request could be merged with others, try again */
		ret = true;
		rq = __rq;
	}

	return ret;
}
```
 
### 4.5 blk_mq_sched_try_insert_merge
```c
bool blk_mq_sched_try_insert_merge(struct request_queue *q, struct request *rq)
{
	return rq_mergeable(rq) && elv_attempt_insert_merge(q, rq);
}
```