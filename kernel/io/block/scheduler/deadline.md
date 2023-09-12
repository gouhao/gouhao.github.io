# deadline
源码基于5.10

## 0. 私有数据
```c
struct deadline_data {
	/*
	 * run time data
	 */

	/*
	 * requests (deadline_rq s) are present on both sort_list and fifo_list
	 */
	struct rb_root sort_list[2];
	struct list_head fifo_list[2];

	/*
	 * next in sort order. read, write or both are NULL
	 */
	struct request *next_rq[2];
	unsigned int batching;		/* number of sequential requests made */
	unsigned int starved;		/* times reads have starved writes */

	/*
	 * settings that change how the i/o scheduler behaves
	 */
	int fifo_expire[2];
	int fifo_batch;
	int writes_starved;
	int front_merges;

	spinlock_t lock;
	spinlock_t zone_lock;
	struct list_head dispatch;
};
```
## 1. 函数表
```c
static struct elevator_type mq_deadline = {
	.ops = {
		.insert_requests	= dd_insert_requests,
		.dispatch_request	= dd_dispatch_request,
		.prepare_request	= dd_prepare_request,
		.finish_request		= dd_finish_request,
		.next_request		= elv_rb_latter_request,
		.former_request		= elv_rb_former_request,
		.bio_merge		= dd_bio_merge,
		.request_merge		= dd_request_merge,
		.requests_merged	= dd_merged_requests,
		.request_merged		= dd_request_merged,
		.has_work		= dd_has_work,
		.init_sched		= dd_init_queue,
		.exit_sched		= dd_exit_queue,
	},

#ifdef CONFIG_BLK_DEBUG_FS
	.queue_debugfs_attrs = deadline_queue_debugfs_attrs,
#endif
	.elevator_attrs = deadline_attrs,
	.elevator_name = "mq-deadline",
	.elevator_alias = "deadline",
	// 支持zone设备顺序写
	.elevator_features = ELEVATOR_F_ZBD_SEQ_WRITE,
	.elevator_owner = THIS_MODULE,
};
```

### 1.1. 属性
```c
#define DD_ATTR(name) \
	__ATTR(name, 0644, deadline_##name##_show, deadline_##name##_store)

static struct elv_fs_entry deadline_attrs[] = {
	DD_ATTR(read_expire), // 提交读取之前最长时间，默认HZ/2（半秒）
	DD_ATTR(write_expire), // 写入的最大起时时间，默认5*HZ（5秒）
	DD_ATTR(writes_starved), // 最大的读取次数会导致写饥饿，默认是2次
	DD_ATTR(front_merges), // 是否开启前向合并，0/1，默认开
	DD_ATTR(fifo_batch), // 顺序请求批量最大值，默认16
	__ATTR_NULL
};
```

## 2. 初始化及退出

### 2.1. 初始化
```c
static int dd_init_queue(struct request_queue *q, struct elevator_type *e)
{
	struct deadline_data *dd;
	struct elevator_queue *eq;

	//　分配一个queue对象
	eq = elevator_alloc(q, e);
	if (!eq)
		return -ENOMEM;

	// 分配deadline对象
	dd = kzalloc_node(sizeof(*dd), GFP_KERNEL, q->node);
	if (!dd) {
		kobject_put(&eq->kobj);
		return -ENOMEM;
	}
	// 与eq建立关联
	eq->elevator_data = dd;

	// 各种初始化
	INIT_LIST_HEAD(&dd->fifo_list[READ]);
	INIT_LIST_HEAD(&dd->fifo_list[WRITE]);
	dd->sort_list[READ] = RB_ROOT;
	dd->sort_list[WRITE] = RB_ROOT;
	dd->fifo_expire[READ] = read_expire;
	dd->fifo_expire[WRITE] = write_expire;
	// writes_starved，默认为0
	dd->writes_starved = writes_starved;
	// 默认打开前向合并
	dd->front_merges = 1;
	// fifo里最大的请求数，默认16
	dd->fifo_batch = fifo_batch;
	spin_lock_init(&dd->lock);
	spin_lock_init(&dd->zone_lock);
	INIT_LIST_HEAD(&dd->dispatch);

	// 设置到请求队列里
	q->elevator = eq;
	return 0;
}

struct elevator_queue *elevator_alloc(struct request_queue *q,
				  struct elevator_type *e)
{
	struct elevator_queue *eq;

	// 分配一个对象
	eq = kzalloc_node(sizeof(*eq), GFP_KERNEL, q->node);
	if (unlikely(!eq))
		return NULL;

	// 关联到调度器的函数表
	eq->type = e;

	// 一些基本初始化
	kobject_init(&eq->kobj, &elv_ktype);
	mutex_init(&eq->sysfs_lock);
	hash_init(eq->hash);

	return eq;
}
```

### 2.2. 退出
```c
static void dd_exit_queue(struct elevator_queue *e)
{
	struct deadline_data *dd = e->elevator_data;

	// 这2个列表必须为空
	BUG_ON(!list_empty(&dd->fifo_list[READ]));
	BUG_ON(!list_empty(&dd->fifo_list[WRITE]));

	// 直接释放dd
	kfree(dd);
}
```

## 3. 合并
```c
static bool dd_bio_merge(struct request_queue *q, struct bio *bio,
		unsigned int nr_segs)
{
	struct deadline_data *dd = q->elevator->elevator_data;
	struct request *free = NULL;
	bool ret;

	spin_lock(&dd->lock);
	// 尝试合并, free 会带回被合并的请求
	ret = blk_mq_sched_try_merge(q, bio, nr_segs, &free);
	spin_unlock(&dd->lock);

	// 释放被合并的请求
	if (free)
		blk_mq_free_request(free);

	return ret;
}


static int dd_request_merge(struct request_queue *q, struct request **rq,
			    struct bio *bio)
{
	struct deadline_data *dd = q->elevator->elevator_data;
	// 结束的扇区
	sector_t sector = bio_end_sector(bio);
	struct request *__rq;

	// 不允许前向合并
	if (!dd->front_merges)
		return ELEVATOR_NO_MERGE;

	// 根据数据方向,找到起点为bio结束扇区的rq
	__rq = elv_rb_find(&dd->sort_list[bio_data_dir(bio)], sector);
	if (__rq) {
		// 找到一个rq

		BUG_ON(sector != blk_rq_pos(__rq));

		// 是否可以合并
		if (elv_bio_merge_ok(__rq, bio)) {
			*rq = __rq;
			// 判断丢弃合并
			if (blk_discard_mergable(__rq))
				return ELEVATOR_DISCARD_MERGE;
			// 返回前向合并
			return ELEVATOR_FRONT_MERGE;
		}
	}

	return ELEVATOR_NO_MERGE;
}

static void dd_merged_requests(struct request_queue *q, struct request *req,
			       struct request *next)
{
	if (!list_empty(&req->queuelist) && !list_empty(&next->queuelist)) {
		// next的过期时间比req短
		if (time_before((unsigned long)next->fifo_time,
				(unsigned long)req->fifo_time)) {
			// 把req移到next后面
			list_move(&req->queuelist, &next->queuelist);
			// 并设置成next的到期时间
			req->fifo_time = next->fifo_time;
		}
	}

	// 删除next请求
	deadline_remove_request(q, next);
}

static void deadline_remove_request(struct request_queue *q, struct request *rq)
{
	struct deadline_data *dd = q->elevator->elevator_data;

	// 删除请求从sort列表里
	list_del_init(&rq->queuelist);

	// 如果在红黑树上，则删除它
	if (!RB_EMPTY_NODE(&rq->rb_node))
		deadline_del_rq_rb(dd, rq);

	// 从哈希表里删除
	elv_rqhash_del(q, rq);
	// 置空最后合并的请求，如果它等于rq
	if (q->last_merge == rq)
		q->last_merge = NULL;
}
```

## 4. 插入请求
```c
static void dd_insert_requests(struct blk_mq_hw_ctx *hctx,
			       struct list_head *list, bool at_head)
{
	struct request_queue *q = hctx->queue;
	struct deadline_data *dd = q->elevator->elevator_data;

	spin_lock(&dd->lock);
	// list里放的是待插入的请求
	while (!list_empty(list)) {
		struct request *rq;

		rq = list_first_entry(list, struct request, queuelist);
		// 先从list里删除
		list_del_init(&rq->queuelist);
		// 插入请求
		dd_insert_request(hctx, rq, at_head);

		// 增加调度器插入的数量
		atomic_inc(&hctx->elevator_queued);
	}
	spin_unlock(&dd->lock);
}

static void dd_insert_request(struct blk_mq_hw_ctx *hctx, struct request *rq,
			      bool at_head)
{
	struct request_queue *q = hctx->queue;
	struct deadline_data *dd = q->elevator->elevator_data;
	const int data_dir = rq_data_dir(rq);

	// zone设备解锁
	blk_req_zone_write_unlock(rq);

	// 先尝试合并,如果可以合并则直接返回
	if (blk_mq_sched_try_insert_merge(q, rq))
		return;

	// 这里面只打印了insert的trace日志
	blk_mq_sched_request_inserted(rq);

	// 插入队前 || 是直通请求
	if (at_head || blk_rq_is_passthrough(rq)) {
		// 插在派发队列的前面或后面
		if (at_head)
			list_add(&rq->queuelist, &dd->dispatch);
		else
			list_add_tail(&rq->queuelist, &dd->dispatch);
	} else {
		// 普通插入

		// 把请求加入对应读写方向的红黑树,这个红黑树按照扇区起点排序
		deadline_add_rq_rb(dd, rq);

		// 如果该请求是可以合并的
		// 能走到这里表示在上面合并时没有合并
		if (rq_mergeable(rq)) {
			// 则把它加到哈希表里,key是扇区请求数量
			elv_rqhash_add(q, rq);
			// 如果last_merge没值,则把rq设为它
			if (!q->last_merge)
				q->last_merge = rq;
		}

		// 设置过期时间
		rq->fifo_time = jiffies + dd->fifo_expire[data_dir];

		// 加到fifo_list里
		list_add_tail(&rq->queuelist, &dd->fifo_list[data_dir]);
	}
}

static void
deadline_add_rq_rb(struct deadline_data *dd, struct request *rq)
{
	// 根据请求方向,获取根节点
	struct rb_root *root = deadline_rb_root(dd, rq);

	// 把请求加到红黑树里
	elv_rb_add(root, rq);
}

static inline struct rb_root *
deadline_rb_root(struct deadline_data *dd, struct request *rq)
{
	// 根据请求方向,获取根节点
	return &dd->sort_list[rq_data_dir(rq)];
}

void elv_rb_add(struct rb_root *root, struct request *rq)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	struct request *__rq;

	// 按照请求扇区的起点,找到需要插入的位置
	while (*p) {
		parent = *p;
		__rq = rb_entry(parent, struct request, rb_node);

		if (blk_rq_pos(rq) < blk_rq_pos(__rq))
			p = &(*p)->rb_left;
		else if (blk_rq_pos(rq) >= blk_rq_pos(__rq))
			p = &(*p)->rb_right;
	}

	// 插入结点
	rb_link_node(&rq->rb_node, parent, p);
	// 插入颜色?
	rb_insert_color(&rq->rb_node, root);
}
```

## 5. 派发
```c
static bool dd_has_work(struct blk_mq_hw_ctx *hctx)
{
	struct deadline_data *dd = hctx->queue->elevator->elevator_data;

	// 没有入队的直接返回
	if (!atomic_read(&hctx->elevator_queued))
		return false;

	// 这3个队列有1个不空就表示有任务
	return !list_empty_careful(&dd->dispatch) ||
		!list_empty_careful(&dd->fifo_list[0]) ||
		!list_empty_careful(&dd->fifo_list[1]);
}

static struct request *dd_dispatch_request(struct blk_mq_hw_ctx *hctx)
{
	struct deadline_data *dd = hctx->queue->elevator->elevator_data;
	struct request *rq;

	spin_lock(&dd->lock);
	// 取出一个待派发的请求
	rq = __dd_dispatch_request(dd);
	spin_unlock(&dd->lock);
	// 如果取出一个,则减少调度器的计数
	if (rq)
		atomic_dec(&rq->mq_hctx->elevator_queued);

	return rq;
}

static struct request *__dd_dispatch_request(struct deadline_data *dd)
{
	struct request *rq, *next_rq;
	bool reads, writes;
	int data_dir;

	// 派发列表不为空,则直接取出一个请求
	if (!list_empty(&dd->dispatch)) {
		rq = list_first_entry(&dd->dispatch, struct request, queuelist);
		list_del_init(&rq->queuelist);
		goto done;
	}

	// 读写里是否有请求
	reads = !list_empty(&dd->fifo_list[READ]);
	writes = !list_empty(&dd->fifo_list[WRITE]);

	// 获取下一个写请求
	rq = deadline_next_request(dd, WRITE);
	// 如果没获取到,则获取下一个读请求
	if (!rq)
		rq = deadline_next_request(dd, READ);

	// 有请求 && 发出的连续请求数量 < fifo的最大批量, 则派发
	if (rq && dd->batching < dd->fifo_batch)
		/* we have a next request are still entitled to batch */
		goto dispatch_request;

	/*
	 * 走到这儿表示rq为空或者batching已经到达限制
	 */

	// 有读的请求
	if (reads) {
		// 怎么会为空?
		BUG_ON(RB_EMPTY_ROOT(&dd->sort_list[READ]));

		// 如果有写请求 && 写饥饿超过了限制值
		if (deadline_fifo_request(dd, WRITE) &&
		    (dd->starved++ >= dd->writes_starved))
		    	// 派发写请求
			goto dispatch_writes;

		// 走到这儿表示写不饥饿

		// 数据方向为读
		data_dir = READ;

		// 找一个请求派发
		goto dispatch_find_request;
	}

	// 走到这儿表示没有读请求,或者写饥饿

	if (writes) {
dispatch_writes:
		BUG_ON(RB_EMPTY_ROOT(&dd->sort_list[WRITE]));

		// 重置饥饿值
		dd->starved = 0;

		// 方向为写
		data_dir = WRITE;

		// 找一个请求派发
		goto dispatch_find_request;
	}

	// 走到这儿表示即没有写,与没有读
	return NULL;

dispatch_find_request:
	// 根据操作方向找一个请求
	next_rq = deadline_next_request(dd, data_dir);

	// 在data_dir上有请求过期 || 没有下一个请求
	if (deadline_check_fifo(dd, data_dir) || !next_rq) {
		// 重新取一个rq
		rq = deadline_fifo_request(dd, data_dir);
	} else {
		// 没有过期的请求,继续派发next_rq
		rq = next_rq;
	}

	/*
	 * 对于zoned设备来说,如果我们只有写请求入队,它们不能被派发,rq将是NULL
	 */
	if (!rq)
		return NULL;

	// batch重置
	dd->batching = 0;

dispatch_request:
	dd->batching++;
	// 从各种列表里删除rq请求, 并设置next请求
	deadline_move_request(dd, rq);
done:
	// 如果是zone设备需要加锁
	blk_req_zone_write_lock(rq);

	// 标记请求已开始
	rq->rq_flags |= RQF_STARTED;
	return rq;
}

static struct request *
deadline_next_request(struct deadline_data *dd, int data_dir)
{
	struct request *rq;
	unsigned long flags;

	// 只处理读写
	if (WARN_ON_ONCE(data_dir != READ && data_dir != WRITE))
		return NULL;

	// 获取下一个请求
	rq = dd->next_rq[data_dir];
	// 下一请求为空
	if (!rq)
		return NULL;

	// 请求是读 || 是写但是不是zone设备
	if (data_dir == READ || !blk_queue_is_zoned(rq->q))
		return rq;

	// 处理zone设备.todo: zone设备相关看面再看
	spin_lock_irqsave(&dd->zone_lock, flags);
	while (rq) {
		if (blk_req_can_dispatch_to_zone(rq))
			break;
		rq = deadline_latter_request(rq);
	}
	spin_unlock_irqrestore(&dd->zone_lock, flags);

	return rq;
}

static struct request *
deadline_fifo_request(struct deadline_data *dd, int data_dir)
{
	struct request *rq;
	unsigned long flags;

	// 只处理读或写
	if (WARN_ON_ONCE(data_dir != READ && data_dir != WRITE))
		return NULL;

	// 对应的列表为空
	if (list_empty(&dd->fifo_list[data_dir]))
		return NULL;

	// 取出第1个元素
	rq = rq_entry_fifo(dd->fifo_list[data_dir].next);

	// 方向是读 || 方向是写但是不是zoned请求
	if (data_dir == READ || !blk_queue_is_zoned(rq->q))
		return rq;

	// 走到这儿表示方向是写的zone设备. todo: zone设备后面再看
	spin_lock_irqsave(&dd->zone_lock, flags);
	list_for_each_entry(rq, &dd->fifo_list[WRITE], queuelist) {
		if (blk_req_can_dispatch_to_zone(rq))
			goto out;
	}
	rq = NULL;
out:
	spin_unlock_irqrestore(&dd->zone_lock, flags);

	return rq;
}

static inline int deadline_check_fifo(struct deadline_data *dd, int ddir)
{
	// 获取下一个请求
	struct request *rq = rq_entry_fifo(dd->fifo_list[ddir].next);

	// 如果rq达到了过期时间返回1
	if (time_after_eq(jiffies, (unsigned long)rq->fifo_time))
		return 1;

	return 0;
}

static void
deadline_move_request(struct deadline_data *dd, struct request *rq)
{
	const int data_dir = rq_data_dir(rq);

	// 先把读写全置空
	dd->next_rq[READ] = NULL;
	dd->next_rq[WRITE] = NULL;

	// 在红黑树上获取rq的下一个节点,根据扇区号
	dd->next_rq[data_dir] = deadline_latter_request(rq);

	// 从排序列表和fifo列表,哈希表里删除此请求
	deadline_remove_request(rq->q, rq);
}

static inline struct request *
deadline_latter_request(struct request *rq)
{
	// 获取下一个结点
	struct rb_node *node = rb_next(&rq->rb_node);

	if (node)
		return rb_entry_rq(node);

	return NULL;
}
```
假设在初始状态下,所有列表全空, writes_starved=2, fifo_batch=3:
1. 插入请求顺序如下:r1 r2 w1 w2 w3 r3 w4 r4 w5 w6 w7 r5 r6
2. w1派发, next_rq[write]=w2,batching=1
3. w2派发, next_rq[write]=w3,batching=2
4. w3派发, next_rq[write]=w4,batching=3
5. 触发fifo_batch限制, next_rq[read]是NULL,派发r1, next_rq[read]=r2,next_rq[write]=NULL,batching=1
6. r2派发, next_rq[read]=r3,batching=2
7. r3派发, next_rq[read]=r4,batching=3
8. 触发writes_starved限制,派发写请求w4,next_rq[read]=NULL,next_rq[write]=w5