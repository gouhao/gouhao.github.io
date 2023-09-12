# 结束请求

## 1. endio
```c
void bio_endio(struct bio *bio)
{
again:
	// 处理链式请求
	if (!bio_remaining_done(bio))
		return;
	// 完整性
	if (!bio_integrity_endio(bio))
		return;

	// qos
	if (bio->bi_disk)
		rq_qos_done_bio(bio->bi_disk->queue, bio);

	// 链式请求
	if (bio->bi_end_io == bio_chain_endio) {
		// 返回的是bio的父类
		bio = __bio_chain_endio(bio);
		goto again;
	}

	// 有磁盘 && 需要在完成的时候trace, trace完之后清除标志
	if (bio->bi_disk && bio_flagged(bio, BIO_TRACE_COMPLETION)) {
		trace_block_bio_complete(bio->bi_disk->queue, bio);
		bio_clear_flag(bio, BIO_TRACE_COMPLETION);
	}

	// 限流
	blk_throtl_bio_endio(bio);
	// 释放cgroup的信息
	bio_uninit(bio);
	// 调用endio
	if (bio->bi_end_io)
		bio->bi_end_io(bio);
}

static inline bool bio_remaining_done(struct bio *bio)
{
	// 不是链式，直接完成
	if (!bio_flagged(bio, BIO_CHAIN))
		return true;

	// remain怎么会小于0
	BUG_ON(atomic_read(&bio->__bi_remaining) <= 0);

	// 递减remain, 如果减完为0则清除标志
	if (atomic_dec_and_test(&bio->__bi_remaining)) {
		bio_clear_flag(bio, BIO_CHAIN);
		return true;
	}

	return false;
}

static struct bio *__bio_chain_endio(struct bio *bio)
{
	struct bio *parent = bio->bi_private;

	// 设置parent的状态为bio状态
	if (bio->bi_status && !parent->bi_status)
		parent->bi_status = bio->bi_status;
	// 释放bio
	bio_put(bio);
	return parent;
}
```

## 2. 结束请求
```c
void blk_mq_end_request(struct request *rq, blk_status_t error)
{
	// 更新请求状态, 返回true表示这个请求还有数据
	if (blk_update_request(rq, error, blk_rq_bytes(rq)))
		BUG();
	// 调用其它结束回调
	__blk_mq_end_request(rq, error);
}

bool blk_update_request(struct request *req, blk_status_t error,
		unsigned int nr_bytes)
{
	int total_bytes;

	// trace 完成
	trace_block_rq_complete(req, blk_status_to_errno(error), nr_bytes);

	// 没有bio, 则不需要处理
	if (!req->bio)
		return false;

#ifdef CONFIG_BLK_DEV_INTEGRITY
	// 度量相关
	if (blk_integrity_rq(req) && req_op(req) == REQ_OP_READ &&
	    error == BLK_STS_OK)
		req->q->integrity.profile->complete_fn(req, nr_bytes);
#endif

	// 有错误 && 不是直通请求 && 非静默, 则打印错误
	if (unlikely(error && !blk_rq_is_passthrough(req) &&
		     !(req->rq_flags & RQF_QUIET)))
		print_req_error(req, error, __func__);

	// 统计相关
	blk_account_io_completion(req, nr_bytes);

	total_bytes = 0;
	// 遍历请求里的bio
	while (req->bio) {
		struct bio *bio = req->bio;
		// nr_bytes是最终io的数据, bi_size是bio里的数据
		unsigned bio_bytes = min(bio->bi_iter.bi_size, nr_bytes);

		// 如果是全部处理了,则设置bio为下一个请求
		if (bio_bytes == bio->bi_iter.bi_size)
			req->bio = bio->bi_next;

		// 清除bio的trace标志
		bio_clear_flag(bio, BIO_TRACE_COMPLETION);
		// 调用bio的end
		req_bio_endio(req, bio, bio_bytes, error);

		// 处理byte计数
		total_bytes += bio_bytes;
		nr_bytes -= bio_bytes;

		// byte处理完了
		if (!nr_bytes)
			break;
	}

	// bio为NULL,表示请求里的所有bio都处理了
	if (!req->bio) {
		// 重置数据长度
		req->__data_len = 0;
		// 返回false表示没有剩余数据了
		return false;
	}

	// 减去已经io的数据
	req->__data_len -= total_bytes;

	// 不是直通,则把扇区前进到total_bytes的位置
	if (!blk_rq_is_passthrough(req))
		req->__sector += total_bytes >> 9;

	// 如果是合并的请求,则跟随第1个bio的标志
	if (req->rq_flags & RQF_MIXED_MERGE) {
		req->cmd_flags &= ~REQ_FAILFAST_MASK;
		req->cmd_flags |= req->bio->bi_opf & REQ_FAILFAST_MASK;
	}

	// 没有特殊的负载. todo: what is special-payload?
	if (!(req->rq_flags & RQF_SPECIAL_PAYLOAD)) {
		// blk_rq_bytes是req->__data_len, 请求里剩余的数据
		// blk_rq_cur_bytes是请求里bio剩余的数据
		// 如果连一个bio也没处理,则是有问题的
		if (blk_rq_bytes(req) < blk_rq_cur_bytes(req)) {
			// 打印dev, sector, bio的相关数据
			blk_dump_rq_flags(req, "request botched");
			// 重置req数据为当前bytes
			req->__data_len = blk_rq_cur_bytes(req);
		}

		// 重新计算segments数量
		req->nr_phys_segments = blk_recalc_rq_segments(req);
	}

	// 返回true表示req里的数据没处理完
	return true;
}

static void print_req_error(struct request *req, blk_status_t status,
		const char *caller)
{
	int idx = (__force int)status;

	// blk_errors里存的是错误号及错误名称
	if (WARN_ON_ONCE(idx >= ARRAY_SIZE(blk_errors)))
		return;

	printk_ratelimited(KERN_ERR
		"%s: %s error, dev %s, sector %llu op 0x%x:(%s) flags 0x%x "
		"phys_seg %u prio class %u\n",
		// 调用者, 错误名
		caller, blk_errors[idx].name,
		// 磁盘名
		req->rq_disk ? req->rq_disk->disk_name : "?",
		// 请求的扇区号, 操作, 操作名称
		blk_rq_pos(req), req_op(req), blk_op_str(req_op(req)),
		// 去除op的flag
		req->cmd_flags & ~REQ_OP_MASK,
		// 段数量
		req->nr_phys_segments,
		// 请求优先级
		IOPRIO_PRIO_CLASS(req->ioprio));
}

static void blk_account_io_completion(struct request *req, unsigned int bytes)
{
	// 请求的分区 && 请求要求统计
	if (req->part && blk_do_io_stat(req)) {
		// 请求的组, 0读1写
		const int sgrp = op_stat_group(req_op(req));
		struct hd_struct *part;

		part_stat_lock();
		part = req->part;
		// 在分区里统计io数,把bytes转换成扇区
		part_stat_add(part, sectors[sgrp], bytes >> 9);
		part_stat_unlock();
	}
}

#define part_stat_add(part, field, addnd)	do {			\
	// 先加到磁盘统计里
	__part_stat_add((part), field, addnd);				\
	// 如果有分区的话,再加到分区里
	if ((part)->partno)						\
		__part_stat_add(&part_to_disk((part))->part0,		\
				field, addnd);				\
} while (0)

#define __part_stat_add(part, field, addnd)				\
	__this_cpu_add((part)->dkstats->field, addnd)

static void req_bio_endio(struct request *rq, struct bio *bio,
			  unsigned int nbytes, blk_status_t error)
{
	// 有错误，设置错误状态
	if (error)
		bio->bi_status = error;

	// 有安静标志？
	if (unlikely(rq->rq_flags & RQF_QUIET))
		bio_set_flag(bio, BIO_QUIET);

	// bio前进nbytes
	bio_advance(bio, nbytes);

	// todo: zone后面再看。
	if (req_op(rq) == REQ_OP_ZONE_APPEND && error == BLK_STS_OK) {
		/*
		 * Partial zone append completions cannot be supported as the
		 * BIO fragments may end up not being written sequentially.
		 */
		if (bio->bi_iter.bi_size)
			bio->bi_status = BLK_STS_IOERR;
		else
			bio->bi_iter.bi_sector = rq->__sector;
	}

	// bio里没有剩余的数据 && 不是flush请求
	if (bio->bi_iter.bi_size == 0 && !(rq->rq_flags & RQF_FLUSH_SEQ))
		// 结束bio
		bio_endio(bio);
}

unsigned int blk_recalc_rq_segments(struct request *rq)
{
	unsigned int nr_phys_segs = 0;
	unsigned int nr_sectors = 0;
	struct req_iterator iter;
	struct bio_vec bv;

	// 没有bio
	if (!rq->bio)
		return 0;

	// 处理不同操作
	switch (bio_op(rq->bio)) {
	case REQ_OP_DISCARD:
	case REQ_OP_SECURE_ERASE:
		// 允许discard操作
		if (queue_max_discard_segments(rq->q) > 1) {
			struct bio *bio = rq->bio;

			// 统计所有bio的段
			for_each_bio(bio)
				nr_phys_segs++;
			return nr_phys_segs;
		}
		return 1;
	case REQ_OP_WRITE_ZEROES:
		return 0;
	case REQ_OP_WRITE_SAME:
		return 1;
	}

	// 遍历rq, 统计所有segs的数量
	rq_for_each_bvec(bv, rq, iter)
		// 这里并不是要裁剪,只是借助这个函数来统计段数
		bvec_split_segs(rq->q, &bv, &nr_phys_segs, &nr_sectors,
				UINT_MAX, UINT_MAX);
	return nr_phys_segs;
}

inline void __blk_mq_end_request(struct request *rq, blk_status_t error)
{
	u64 now = 0;

	// 需要记录时间
	if (blk_mq_need_time_stamp(rq))
		now = ktime_get_ns();

	// 统计
	if (rq->rq_flags & RQF_STATS) {
		blk_mq_poll_stats_start(rq->q);
		blk_stat_add(rq, now);
	}

	// 调用调度器的completed_request函数
	blk_mq_sched_completed_request(rq, now);

	blk_account_io_done(rq, now);

	if (rq->end_io) {
		// qos相关
		rq_qos_done(rq->q, rq);
		// 调用endio
		rq->end_io(rq, error);
	} else {
		blk_mq_free_request(rq);
	}
}

void blk_stat_add(struct request *rq, u64 now)
{
	struct request_queue *q = rq->q;
	struct blk_stat_callback *cb;
	struct blk_rq_stat *stat;
	int bucket, cpu;
	u64 value;

	value = (now >= rq->io_start_time_ns) ? now - rq->io_start_time_ns : 0;

	blk_throtl_stat_add(rq, value);

	rcu_read_lock();
	cpu = get_cpu();
	list_for_each_entry_rcu(cb, &q->stats->callbacks, list) {
		if (!blk_stat_is_active(cb))
			continue;

		bucket = cb->bucket_fn(rq);
		if (bucket < 0)
			continue;

		stat = &per_cpu_ptr(cb->cpu_stat, cpu)[bucket];
		blk_rq_stat_add(stat, value);
	}
	put_cpu();
	rcu_read_unlock();
}

void blk_account_io_done(struct request *req, u64 now)
{
	/*
	 * Account IO completion.  flush_rq isn't accounted as a
	 * normal IO on queueing nor completion.  Accounting the
	 * containing request is enough.
	 */
	if (req->part && blk_do_io_stat(req) &&
	    !(req->rq_flags & RQF_FLUSH_SEQ)) {
		const int sgrp = op_stat_group(req_op(req));
		struct hd_struct *part;

		part_stat_lock();
		part = req->part;

		update_io_ticks(part, jiffies, true);
		part_stat_inc(part, ios[sgrp]);
		part_stat_add(part, nsecs[sgrp], now - req->start_time_ns);
		part_stat_unlock();

		hd_struct_put(part);
	}
}


void blk_mq_free_request(struct request *rq)
{
	struct request_queue *q = rq->q;
	struct elevator_queue *e = q->elevator;
	struct blk_mq_ctx *ctx = rq->mq_ctx;
	struct blk_mq_hw_ctx *hctx = rq->mq_hctx;

	// 有调度器私有数据
	if (rq->rq_flags & RQF_ELVPRIV) {
		// 调用结束请求
		if (e && e->type->ops.finish_request)
			e->type->ops.finish_request(rq);
		// 如果有icq,则释放之
		if (rq->elv.icq) {
			put_io_context(rq->elv.icq->ioc);
			rq->elv.icq = NULL;
		}
	}

	// 完成计数
	ctx->rq_completed[rq_is_sync(rq)]++;
	// 递减请求活跃数
	if (rq->rq_flags & RQF_MQ_INFLIGHT)
		__blk_mq_dec_active_requests(hctx);

	// 笔记本电脑的处理
	if (unlikely(laptop_mode && !blk_rq_is_passthrough(rq)))
		laptop_io_completion(q->backing_dev_info);

	// qos
	rq_qos_done(q, rq);

	// 设置 rq状态
	WRITE_ONCE(rq->state, MQ_RQ_IDLE);
	// 减少引用
	if (refcount_dec_and_test(&rq->ref))
		__blk_mq_free_request(rq);
}

static void __blk_mq_free_request(struct request *rq)
{
	struct request_queue *q = rq->q;
	struct blk_mq_ctx *ctx = rq->mq_ctx;
	struct blk_mq_hw_ctx *hctx = rq->mq_hctx;
	const int sched_tag = rq->internal_tag;

	// 加密上下文
	blk_crypto_free_request(rq);
	// 记录上次访问设备的时间
	blk_pm_mark_last_busy(rq);
	// 置hctx
	rq->mq_hctx = NULL;
	// 释放tag, 如果有的话
	if (rq->tag != BLK_MQ_NO_TAG)
		blk_mq_put_tag(hctx->tags, ctx, rq->tag);
	// 释放internal tag
	if (sched_tag != BLK_MQ_NO_TAG)
		blk_mq_put_tag(hctx->sched_tags, ctx, sched_tag);
	// 如果hctx需要重启, 则重启之
	blk_mq_sched_restart(hctx);

	// 减少 q->q_usage_counter	
	blk_queue_exit(q);
}

void blk_mq_sched_restart(struct blk_mq_hw_ctx *hctx)
{
	// 没有重新调度
	if (!test_bit(BLK_MQ_S_SCHED_RESTART, &hctx->state))
		return;
	// 清除标志位
	clear_bit(BLK_MQ_S_SCHED_RESTART, &hctx->state);

	/*
	 * Order clearing SCHED_RESTART and list_empty_careful(&hctx->dispatch)
	 * in blk_mq_run_hw_queue(). Its pair is the barrier in
	 * blk_mq_dispatch_rq_list(). So dispatch code won't see SCHED_RESTART,
	 * meantime new request added to hctx->dispatch is missed to check in
	 * blk_mq_run_hw_queue().
	 */
	smp_mb();

	// 重启
	blk_mq_run_hw_queue(hctx, true);
}
```

## 3. end_bio_bh_io_sync 
bio分配时的回调是这个
```c
static void end_bio_bh_io_sync(struct bio *bio)
{
	struct buffer_head *bh = bio->bi_private;

	// bio安静，则bh也安静
	if (unlikely(bio_flagged(bio, BIO_QUIET)))
		set_bit(BH_Quiet, &bh->b_state);

	// 调用bh的函数, 第2个参数是bh是否是最新的
	bh->b_end_io(bh, !bio->bi_status);
	// 释放bio
	bio_put(bio);
}
```

## 4. end_buffer_read_sync
```c
void end_buffer_read_sync(struct buffer_head *bh, int uptodate)
{
	// 更新bh的最新标志
	__end_buffer_read_notouch(bh, uptodate);
	// 释放bh
	put_bh(bh);
}
```