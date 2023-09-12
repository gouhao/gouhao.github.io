# 请求相关
源码基于5.10

## 1. 分配请求
```c
static struct request *__blk_mq_alloc_request(struct blk_mq_alloc_data *data)
{
	// 请求队列
	struct request_queue *q = data->q;
	// 电梯
	struct elevator_queue *e = q->elevator;
	u64 alloc_time_ns = 0;
	unsigned int tag;

	// 判断有无QUEUE_FLAG_RQ_ALLOC_TIME标志
	// 有的话记录分配的时间
	if (blk_queue_rq_alloc_time(q))
		alloc_time_ns = ktime_get_ns();

	// 不等待
	if (data->cmd_flags & REQ_NOWAIT)
		data->flags |= BLK_MQ_REQ_NOWAIT;

	// 有电梯
	if (e) {
		// 非刷新请求 && 调度器有limit_depth && 使用保留tag, 则调用调度器的限制队列深度的方法
		if (!op_is_flush(data->cmd_flags) &&
		    e->type->ops.limit_depth &&
		    !(data->flags & BLK_MQ_REQ_RESERVED))
			e->type->ops.limit_depth(data->cmd_flags, data);
	}

retry:
	// 获取ctx
	data->ctx = blk_mq_get_ctx(q);
	// 根据不同的请求返回hctx
	data->hctx = blk_mq_map_queue(q, data->cmd_flags, data->ctx);
	// 没有调度器，则给hctx->state标记 BLK_MQ_S_TAG_ACTIVE
	if (!e)
		blk_mq_tag_busy(data->hctx);

	// 获取一个tag
	tag = blk_mq_get_tag(data);

	// 没tag了
	if (tag == BLK_MQ_NO_TAG) {

		// 不等待，直接返回NULL
		if (data->flags & BLK_MQ_REQ_NOWAIT)
			return NULL;

		// 睡3秒再重试
		msleep(3);
		goto retry;
	}
	// 初始化tag对应的请求
	return blk_mq_rq_ctx_init(data, tag, alloc_time_ns);
}

static struct request *blk_mq_rq_ctx_init(struct blk_mq_alloc_data *data,
		unsigned int tag, u64 alloc_time_ns)
{
	// 获取data里的tags
	struct blk_mq_tags *tags = blk_mq_tags_from_data(data);
	// 取tag的静态请求
	struct request *rq = tags->static_rqs[tag];

	// 根据是否有电梯在不同的字段记录tag
	// todo: 有电梯时为啥要在internal_tag里记录
	if (data->q->elevator) {
		rq->tag = BLK_MQ_NO_TAG;
		rq->internal_tag = tag;
	} else {
		rq->tag = tag;
		rq->internal_tag = BLK_MQ_NO_TAG;
	}

	// 请求队列
	rq->q = data->q;
	// 软件队列
	rq->mq_ctx = data->ctx;
	// 硬件队列
	rq->mq_hctx = data->hctx;
	rq->rq_flags = 0;
	// 命令标志
	rq->cmd_flags = data->cmd_flags;
	// 运行时电源管理请求？
	if (data->flags & BLK_MQ_REQ_PM)
		rq->rq_flags |= RQF_PM;
	// 有io统计需要
	if (blk_queue_io_stat(data->q))
		rq->rq_flags |= RQF_IO_STAT;
	// 一些初始化
	INIT_LIST_HEAD(&rq->queuelist);
	INIT_HLIST_NODE(&rq->hash);
	RB_CLEAR_NODE(&rq->rb_node);
	rq->rq_disk = NULL;
	rq->part = NULL;
#ifdef CONFIG_BLK_RQ_ALLOC_TIME
	// 开始分配请求时的时间戳
	rq->alloc_time_ns = alloc_time_ns;
#endif
	// 需要记录请求开始时时间戳
	if (blk_mq_need_time_stamp(rq))
		rq->start_time_ns = ktime_get_ns();
	else
		rq->start_time_ns = 0;

	rq->io_start_time_ns = 0;
	rq->stats_sectors = 0;
	rq->nr_phys_segments = 0;
#if defined(CONFIG_BLK_DEV_INTEGRITY)
	rq->nr_integrity_segments = 0;
#endif
	// 加密
	blk_crypto_rq_set_defaults(rq);
	// deadline设置为0
	WRITE_ONCE(rq->deadline, 0);

	rq->timeout = 0;

	rq->end_io = NULL;
	rq->end_io_data = NULL;

	// ctx里请求派发的计数
	data->ctx->rq_dispatched[op_is_sync(data->cmd_flags)]++;
	// 引用置1
	refcount_set(&rq->ref, 1);

	// 如果不是刷新请求
	if (!op_is_flush(data->cmd_flags)) {
		struct elevator_queue *e = data->q->elevator;

		rq->elv.icq = NULL;
		// 如果电梯有prepare_request，则调用之
		if (e && e->type->ops.prepare_request) {
			// 如果有icq缓存,则创建icq
			if (e->type->icq_cache)
				blk_mq_sched_assign_ioc(rq);

			// 调度器的准备请求方法
			e->type->ops.prepare_request(rq);
			// rq有调度器的私有数据
			rq->rq_flags |= RQF_ELVPRIV;
		}
	}

	// 已入队的请求数加1
	data->hctx->queued++;
	return rq;
}

static inline bool blk_mq_need_time_stamp(struct request *rq)
{
	// 有统计需要 || 有调度器
	return (rq->rq_flags & (RQF_IO_STAT | RQF_STATS)) || rq->q->elevator;
}
```



## request_to_qc_t
```c
static inline blk_qc_t request_to_qc_t(struct blk_mq_hw_ctx *hctx,
		struct request *rq)
{
	// queue_num是队列编号
	// BLK_QC_T_SHIFT是16
	// 无调度器时rq->tag != -1，用低16位存tag，高16位存队列数量
	if (rq->tag != -1)
		return rq->tag | (hctx->queue_num << BLK_QC_T_SHIFT);

	// BLK_QC_T_INTERNAL = (1U << 31)，
	// 有调度器时tag保存在internal_tag里，和上面类似，低16位存tag，高16位存队列数量，
	// 在第32位保存internal的标志
	return rq->internal_tag | (hctx->queue_num << BLK_QC_T_SHIFT) |
			BLK_QC_T_INTERNAL;
}
```

## 把bio转换成请求
```c
static void blk_mq_bio_to_request(struct request *rq, struct bio *bio,
		unsigned int nr_segs)
{
	int err;

	// 如果是预读的话，加上快速失败标志
	if (bio->bi_opf & REQ_RAHEAD)
		rq->cmd_flags |= REQ_FAILFAST_MASK;

	// 请求扇区的起点设置为bio的扇区起点
	rq->__sector = bio->bi_iter.bi_sector;
	// todo: what?
	rq->write_hint = bio->bi_write_hint;

	// 把bio里的一些读写信息写到请求里
	blk_rq_bio_prep(rq, bio, nr_segs);

	// todo: 加密相关后面再看
	err = blk_crypto_rq_bio_prep(rq, bio, GFP_NOIO);
	WARN_ON_ONCE(err);

	// 统计相关
	blk_account_io_start(rq);
}

static inline void blk_rq_bio_prep(struct request *rq, struct bio *bio,
		unsigned int nr_segs)
{
	// 段数
	rq->nr_phys_segments = nr_segs;
	// 请求的数据长度
	rq->__data_len = bio->bi_iter.bi_size;
	// 请求的头、尾bio都指向这个bio
	rq->bio = rq->biotail = bio;
	// 设置io优先级？
	rq->ioprio = bio_prio(bio);

	// 设置请求的磁盘
	if (bio->bi_disk)
		rq->rq_disk = bio->bi_disk;
}

void blk_account_io_start(struct request *rq)
{
	// 没有统计io的需要直接返回
	if (!blk_do_io_stat(rq))
		return;

	// 把扇区转换成对应的分区
	rq->part = disk_map_sector_rcu(rq->rq_disk, blk_rq_pos(rq));

	part_stat_lock();
	update_io_ticks(rq->part, jiffies, false);
	part_stat_unlock();
}

static inline bool blk_do_io_stat(struct request *rq)
{
	return rq->rq_disk && (rq->rq_flags & RQF_IO_STAT);
}

static void update_io_ticks(struct hd_struct *part, unsigned long now, bool end)
{
	unsigned long stamp;
again:
	// 分区时间戳
	stamp = READ_ONCE(part->stamp);

	// 更新分区时间戳
	if (unlikely(stamp != now)) {
		if (likely(cmpxchg(&part->stamp, stamp, now) == stamp))
			__part_stat_add(part, io_ticks, end ? now - stamp : 1);
	}
	// 更新0号分区时间戳
	if (part->partno) {
		part = &part_to_disk(part)->part0;
		goto again;
	}
}
```

## 插入请求
插入请求是给调度器或者ctx里插入

### 插入刷新请求
```c
void blk_insert_flush(struct request *rq)
{
	struct request_queue *q = rq->q;
	// 队列标志
	unsigned long fflags = q->queue_flags;
	// 刷新策略
	unsigned int policy = blk_flush_policy(fflags, rq);
	// 获取hctx对应的flush_queue
	struct blk_flush_queue *fq = blk_get_flush_queue(q, rq->mq_ctx);

	// 清除REQ_PREFLUSH和REQ_FUA标志,因为policy里已经记录了
	rq->cmd_flags &= ~REQ_PREFLUSH;
	if (!(fflags & (1UL << QUEUE_FLAG_FUA)))
		rq->cmd_flags &= ~REQ_FUA;

	// 刷新请求是同步的
	rq->cmd_flags |= REQ_SYNC;

	// 没有策略的直接结束请求
	if (!policy) {
		blk_mq_end_request(rq, 0);
		return;
	}

	// 没有bio或者只能有一个
	BUG_ON(rq->bio != rq->biotail);

	// 如果有数据，没有刷新需求。这个请求就可以直接处理不用经过刷新机制。
	if ((policy & REQ_FSEQ_DATA) &&
	    !(policy & (REQ_FSEQ_PREFLUSH | REQ_FSEQ_POSTFLUSH))) {
		// 绕过插入
		blk_mq_request_bypass_insert(rq, false, false);
		return;
	}

	/*
	 * @rq should go through flush machinery.  Mark it part of flush
	 * sequence and submit for further processing.
	 */
	// 初始化请求的刷新对象
	memset(&rq->flush, 0, sizeof(rq->flush));
	INIT_LIST_HEAD(&rq->flush.list);
	// 顺序刷新？
	rq->rq_flags |= RQF_FLUSH_SEQ;
	// 保存endio
	rq->flush.saved_end_io = rq->end_io;

	// 设置flush的回调
	rq->end_io = mq_flush_data_end_io;

	spin_lock_irq(&fq->mq_flush_lock);

	// 刷出请求, REQ_FSEQ_ACTIONS = REQ_FSEQ_PREFLUSH | REQ_FSEQ_DATA | REQ_FSEQ_POSTFLUSH
	blk_flush_complete_seq(rq, fq, REQ_FSEQ_ACTIONS & ~policy, 0);
	spin_unlock_irq(&fq->mq_flush_lock);
}

static unsigned int blk_flush_policy(unsigned long fflags, struct request *rq)
{
	unsigned int policy = 0;

	// 请求里有数据，这个获取的是数据长度对应的扇区数
	if (blk_rq_sectors(rq))
		policy |= REQ_FSEQ_DATA;

	// 如果有writeback caching
	if (fflags & (1UL << QUEUE_FLAG_WC)) {
		// 预刷新？
		if (rq->cmd_flags & REQ_PREFLUSH)
			policy |= REQ_FSEQ_PREFLUSH;
		
		// flag没有fua, 但是cmd有fua
		if (!(fflags & (1UL << QUEUE_FLAG_FUA)) &&
		    (rq->cmd_flags & REQ_FUA))
			policy |= REQ_FSEQ_POSTFLUSH;
	}
	return policy;
}
static void blk_flush_complete_seq(struct request *rq,
				   struct blk_flush_queue *fq,
				   unsigned int seq, blk_status_t error)
{
	struct request_queue *q = rq->q;
	struct list_head *pending = &fq->flush_queue[fq->flush_pending_idx];
	unsigned int cmd_flags;

	BUG_ON(rq->flush.seq & seq);
	// 设置seq?
	rq->flush.seq |= seq;
	// 命令标志
	cmd_flags = rq->cmd_flags;

	if (likely(!error))
		// 计算rq的顺序
		seq = blk_flush_cur_seq(rq);
	else
		seq = REQ_FSEQ_DONE;

	switch (seq) {
	case REQ_FSEQ_PREFLUSH:
	case REQ_FSEQ_POSTFLUSH:
		// 预刷出或已经刷出

		// 如果pending是空的，则记录pending时间
		if (list_empty(pending))
			fq->flush_pending_since = jiffies;
		// 把rq移到pending末尾
		list_move_tail(&rq->flush.list, pending);
		break;

	case REQ_FSEQ_DATA:
		// 有数据刷出

		// 把rq移到 flush_data_in_flight 队列
		list_move_tail(&rq->flush.list, &fq->flush_data_in_flight);

		// 添加到运行队列里
		blk_flush_queue_rq(rq, true);
		break;

	case REQ_FSEQ_DONE:
		// 请求已经执行完了
		BUG_ON(!list_empty(&rq->queuelist));

		// 从flush里删除
		list_del_init(&rq->flush.list);
		// 先还原成正常请求之前的数据
		blk_flush_restore_request(rq);

		// 结束请求
		blk_mq_end_request(rq, error);
		break;

	default:
		BUG();
	}
	
	// 刷出请求
	blk_kick_flush(q, fq, cmd_flags);
}

static unsigned int blk_flush_cur_seq(struct request *rq)
{
	// ffz是找第一个0的位置
	return 1 << ffz(rq->flush.seq);
}

static void blk_flush_queue_rq(struct request *rq, bool add_front)
{
	// 添加到队列里
	blk_mq_add_to_requeue_list(rq, add_front, true);
}

void blk_mq_add_to_requeue_list(struct request *rq, bool at_head,
				bool kick_requeue_list)
{
	struct request_queue *q = rq->q;
	unsigned long flags;

	// 不能有这个标志
	BUG_ON(rq->rq_flags & RQF_SOFTBARRIER);

	spin_lock_irqsave(&q->requeue_lock, flags);
	if (at_head) {
		// 添加在头部，设置这个标志，这个标志是:io调度器可能无法传递
		rq->rq_flags |= RQF_SOFTBARRIER;
		// 加到队列前面
		list_add(&rq->queuelist, &q->requeue_list);
	} else {
		// 加到队列末尾
		list_add_tail(&rq->queuelist, &q->requeue_list);
	}
	spin_unlock_irqrestore(&q->requeue_lock, flags);

	// 如果需要唤醒队列，则唤醒之
	if (kick_requeue_list)
		blk_mq_kick_requeue_list(q);
}

void blk_mq_kick_requeue_list(struct request_queue *q)
{
	// 运行kblockd_workqueue。第1个参数是指定cpu，最后一个参数是延迟时间
	// 延迟为0表示立即开始
	kblockd_mod_delayed_work_on(WORK_CPU_UNBOUND, &q->requeue_work, 0);
}

static void blk_flush_restore_request(struct request *rq)
{
	// 刷新完bio是NULL，我们应该还原它
	rq->bio = rq->biotail;

	// 去除刷出请求
	rq->rq_flags &= ~RQF_FLUSH_SEQ;
	// 还原之前的回调函数
	rq->end_io = rq->flush.saved_end_io;
}

static void blk_kick_flush(struct request_queue *q, struct blk_flush_queue *fq,
			   unsigned int flags)
{
	// 待刷出请求队列？
	struct list_head *pending = &fq->flush_queue[fq->flush_pending_idx];
	// 第1个请求
	struct request *first_rq =
		list_first_entry(pending, struct request, flush.list);
	struct request *flush_rq = fq->flush_rq;

	// 同时只能有一个运行或者待刷出队列是空的
	if (fq->flush_pending_idx != fq->flush_running_idx || list_empty(pending))
		return;

	// 有正在运行的，并且没有超过5秒
	if (!list_empty(&fq->flush_data_in_flight) &&
	    time_before(jiffies,
	    		// FLUSH_PENDING_TIMEOUT是5秒
			fq->flush_pending_since + FLUSH_PENDING_TIMEOUT))
		return;

	// 切换pending_idx
	fq->flush_pending_idx ^= 1;

	// 初始化flush_rq请求
	blk_rq_init(q, flush_rq);

	// 使用第1个请求的上下文
	flush_rq->mq_ctx = first_rq->mq_ctx;
	flush_rq->mq_hctx = first_rq->mq_hctx;

	if (!q->elevator) {
		// 没有调度器
		flush_rq->tag = first_rq->tag;

		/*
		 * 这个标记防止多次统计
		 */
		flush_rq->rq_flags |= RQF_MQ_INFLIGHT;
	} else
		// 有调度器
		flush_rq->internal_tag = first_rq->internal_tag;

	// REQ_OP_FLUSH：刷出易失缓存
	flush_rq->cmd_flags = REQ_OP_FLUSH | REQ_PREFLUSH;
	// REQ_DRV：需要驱动？ REQ_FAILFAST_MASK： 快速结束
	flush_rq->cmd_flags |= (flags & REQ_DRV) | (flags & REQ_FAILFAST_MASK);
	// 顺序刷出
	flush_rq->rq_flags |= RQF_FLUSH_SEQ;
	// 磁盘
	flush_rq->rq_disk = first_rq->rq_disk;
	// 结束回调
	flush_rq->end_io = flush_end_io;
	
	smp_wmb();
	// 设引用为1
	refcount_set(&flush_rq->ref, 1);

	// 刷出，把请求添加列队列里
	blk_flush_queue_rq(flush_rq, false);
}

void blk_rq_init(struct request_queue *q, struct request *rq)
{
	memset(rq, 0, sizeof(*rq));

	INIT_LIST_HEAD(&rq->queuelist);
	// 设置队列
	rq->q = q;
	rq->__sector = (sector_t) -1;
	INIT_HLIST_NODE(&rq->hash);
	RB_CLEAR_NODE(&rq->rb_node);
	// 没有tag
	rq->tag = BLK_MQ_NO_TAG;
	rq->internal_tag = BLK_MQ_NO_TAG;
	// 开始时间
	rq->start_time_ns = ktime_get_ns();

	rq->part = NULL;
	// 加密
	blk_crypto_rq_set_defaults(rq);
}
```

### 批量插入
这个函数主要在flush_plug时调用,它会把plug里的请求,按hctx排序来按hctx刷出.

```c
void blk_mq_sched_insert_requests(struct blk_mq_hw_ctx *hctx,
				  struct blk_mq_ctx *ctx,
				  struct list_head *list, bool run_queue_async)
{
	struct elevator_queue *e;
	struct request_queue *q = hctx->queue;

	// 增加引用计数，怕在使用期间队列被释放了
	percpu_ref_get(&q->q_usage_counter);

	// 获取调度器
	e = hctx->queue->elevator;
	if (e && e->type->ops.insert_requests)
		// 有电梯 && 有插入请求函数，则调用之
		e->type->ops.insert_requests(hctx, list, false);
	else {
		// 没有调度器或者调度器没有insert函数的话就调用通用函数
	
		// 队列不忙 && 没有电梯 && 不是异步,直接发布
		// 这样能给软队列节省一个入队或出队请求
		if (!hctx->dispatch_busy && !e && !run_queue_async) {
			// 直接发布请求
			blk_mq_try_issue_list_directly(hctx, list);
			// 链表空了，则退出
			if (list_empty(list))
				goto out;
		}
		// 把list里剩余的元素插入队列
		blk_mq_insert_requests(hctx, ctx, list);
	}

	// 运行队列
	blk_mq_run_hw_queue(hctx, run_queue_async);
 out:
	// 减少引用
	percpu_ref_put(&q->q_usage_counter);
}

void blk_mq_insert_requests(struct blk_mq_hw_ctx *hctx, struct blk_mq_ctx *ctx,
			    struct list_head *list)

{
	struct request *rq;
	enum hctx_type type = hctx->type;

	// 这个打印插入的trace
	list_for_each_entry(rq, list, queuelist) {
		// 原注释：抢占不会刷新列表头，所以ctx->cpu可能已经下线？
		BUG_ON(rq->mq_ctx != ctx);
		trace_block_rq_insert(hctx->queue, rq);
	}

	spin_lock(&ctx->lock);
	// 把list添加到软队列的末尾
	list_splice_tail_init(list, &ctx->rq_lists[type]);
	// 标记软队列有准备提交的请求
	blk_mq_hctx_mark_pending(hctx, ctx);
	spin_unlock(&ctx->lock);
}

static void blk_mq_hctx_mark_pending(struct blk_mq_hw_ctx *hctx,
				     struct blk_mq_ctx *ctx)
{
	const int bit = ctx->index_hw[hctx->type];

	// 标记软位图，这个标记之后就表示有准备提交的请求
	if (!sbitmap_test_bit(&hctx->ctx_map, bit))
		sbitmap_set_bit(&hctx->ctx_map, bit);
}
```
批量插入的主要流程很简单：
1. 把list里的请求全部加到软队列里
2. 标记软队列对应hctx的位图，表示这个软队列有请求需要提交
3. 运行队列

### 调度器插入请求
```c
void blk_mq_sched_insert_request(struct request *rq, bool at_head,
				 bool run_queue, bool async)
{
	struct request_queue *q = rq->q;
	struct elevator_queue *e = q->elevator;
	struct blk_mq_ctx *ctx = rq->mq_ctx;
	struct blk_mq_hw_ctx *hctx = rq->mq_hctx;

	// 有调度器时，rq->tag应该为空，tag在internal_tag里保存
	WARN_ON(e && (rq->tag != BLK_MQ_NO_TAG));

	// 判断是否要绕过插入直接发布, bypass的条件是flush或passthrough请求
	if (blk_mq_sched_bypass_insert(hctx, !!e, rq)) {
		// 如果是刷新请求则放到队头
		at_head = (rq->rq_flags & RQF_FLUSH_SEQ) ? true : at_head;
		// 直接插入到hctx的派发队列里，最后一个参数表示是否运行队列
		blk_mq_request_bypass_insert(rq, at_head, false);
		goto run;
	}

	// 如果没有直接发布就加到软队列里
	if (e && e->type->ops.insert_requests) {
		// 有调度器 && 有insert_requests方法，则调用之
		LIST_HEAD(list);

		list_add(&rq->queuelist, &list);
		e->type->ops.insert_requests(hctx, &list, at_head);
	} else {
		// 否则调用通用方法插入请求
		spin_lock(&ctx->lock);
		// 这个会把请求插到软队列里
		__blk_mq_insert_request(hctx, rq, at_head);
		spin_unlock(&ctx->lock);
	}

run:
	// 若需运行，则执行请求
	if (run_queue)
		blk_mq_run_hw_queue(hctx, async);
}
```

#### 直接发布 
```c
static bool blk_mq_sched_bypass_insert(struct blk_mq_hw_ctx *hctx,
				       bool has_sched,
				       struct request *rq)
{
	// RQF_FLUSH_SEQ是顺序刷出
	// blk_rq_is_passthrough判断是否是REQ_OP_SCSI_IN/OUT，REQ_OP_DRV_IN/OUT这4种之一的请求
	// 这2种情况绕过插入，直接发出请求
	if ((rq->rq_flags & RQF_FLUSH_SEQ) || blk_rq_is_passthrough(rq))
		return true;

	// 有调度器，则需要排序
	if (has_sched)
		rq->rq_flags |= RQF_SORTED;

	return false;
}

void blk_mq_request_bypass_insert(struct request *rq, bool at_head,
				  bool run_queue)
{
	struct blk_mq_hw_ctx *hctx = rq->mq_hctx;

	spin_lock(&hctx->lock);

	// 添加到硬件队列的派发队列,
	// 加到dispatch队列后，在运行队列时，会优先处理
	if (at_head)
		list_add(&rq->queuelist, &hctx->dispatch);
	else
		list_add_tail(&rq->queuelist, &hctx->dispatch);
	spin_unlock(&hctx->lock);

	// 如需运行硬件队列，则运行之
	if (run_queue)
		blk_mq_run_hw_queue(hctx, false);
}
```
#### 插入软队列
```c
void __blk_mq_insert_request(struct blk_mq_hw_ctx *hctx, struct request *rq,
			     bool at_head)
{
	struct blk_mq_ctx *ctx = rq->mq_ctx;

	lockdep_assert_held(&ctx->lock);

	// 把请求插到队列里
	__blk_mq_insert_req_list(hctx, rq, at_head);
	// 标记hctx有待处理的请求
	blk_mq_hctx_mark_pending(hctx, ctx);
}

static inline void __blk_mq_insert_req_list(struct blk_mq_hw_ctx *hctx,
					    struct request *rq,
					    bool at_head)
{
	struct blk_mq_ctx *ctx = rq->mq_ctx;
	enum hctx_type type = hctx->type;

	lockdep_assert_held(&ctx->lock);

	trace_block_rq_insert(hctx->queue, rq);

	// 根据at_head的值，加到软队列头或者队列尾
	if (at_head)
		list_add(&rq->queuelist, &ctx->rq_lists[type]);
	else
		list_add_tail(&rq->queuelist, &ctx->rq_lists[type]);
}
```