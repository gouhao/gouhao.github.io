# 队列相关
源码基于5.10

## 1. 运行队列
```c
void blk_mq_run_hw_queue(struct blk_mq_hw_ctx *hctx, bool async)
{
	int srcu_idx;
	bool need_run;

	/*
	 * 当队列被停止时，我们可能在切换io调度器或者更新nr_hw_queues，或者其他什么时
	 * 并且我们不能再运行队列，甚至__blk_mq_hctx_has_pending也不能安全的调用
	 *
	 * 如果队列停止了，它会在blk_mq_unquiesce_queue里重新运行
	 */
	hctx_lock(hctx, &srcu_idx);
	// 队列没有停止 && hctx有待处理的任务
	need_run = !blk_queue_quiesced(hctx->queue) &&
		blk_mq_hctx_has_pending(hctx);
	hctx_unlock(hctx, srcu_idx);

	// 如果需要，则重新运行
	if (need_run)
		// 这里超时时间用的是0
		__blk_mq_delay_run_hw_queue(hctx, async, 0);
}

static bool blk_mq_hctx_has_pending(struct blk_mq_hw_ctx *hctx)
{
	// 派发队列不空 || ctx_map有设置的位 || 看电梯里有没有工作
	return !list_empty_careful(&hctx->dispatch) ||
		sbitmap_any_bit_set(&hctx->ctx_map) ||
			blk_mq_sched_has_work(hctx);
}

static inline bool blk_mq_sched_has_work(struct blk_mq_hw_ctx *hctx)
{
	struct elevator_queue *e = hctx->queue->elevator;

	if (e && e->type->ops.has_work)
		return e->type->ops.has_work(hctx);

	return false;
}

static void __blk_mq_delay_run_hw_queue(struct blk_mq_hw_ctx *hctx, bool async,
					unsigned long msecs)
{
	// 队列已经停止
	if (unlikely(blk_mq_hctx_stopped(hctx)))
		return;

	// 不是异步 && 队列没阻塞
	if (!async && !(hctx->flags & BLK_MQ_F_BLOCKING)) {
		int cpu = get_cpu();
		// 队列允许在当前cpu运行
		if (cpumask_test_cpu(cpu, hctx->cpumask)) {
			// 运行队列
			__blk_mq_run_hw_queue(hctx);
			put_cpu();
			return;
		}

		put_cpu();
	}

	// 异步执行或队列已阻塞，选择下一个cpu，延迟执行
	// run_work是blk_mq_run_work_fn
	kblockd_mod_delayed_work_on(blk_mq_hctx_next_cpu(hctx), &hctx->run_work,
				    msecs_to_jiffies(msecs));
}

static void blk_mq_run_work_fn(struct work_struct *work)
{
	struct blk_mq_hw_ctx *hctx;

	hctx = container_of(work, struct blk_mq_hw_ctx, run_work.work);

	// 队列已经停止则返回
	if (blk_mq_hctx_stopped(hctx))
		return;

	// 真正的运行队列
	__blk_mq_run_hw_queue(hctx);
}

static void __blk_mq_run_hw_queue(struct blk_mq_hw_ctx *hctx)
{
	int srcu_idx;

	/*
	 * 我们应该从这个队列映射的其中一个cpu来运行它
	 *
	 * 现在至少有2种竞争关系在从 blk_mq_hctx_next_cpu 里
	 * 调用hctx->next_cpu和运行__blk_mq_run_hw_queue
	 * - hctx->next_cpu 在 blk_mq_hctx_next_cpu 里发现是离线，但随后变成上线
	 *   这个警告是无害的
	 *
	 * - hctx->next_cpu 在 blk_mq_hctx_next_cpu 里发现是在线，但随后变成离线
	 *   这个警告不会触发，我们依靠blk-mq的超时处理器来处理把请求派发到这个hctx里
	 */
	// 如果hctx有可用的在线cpu，且当前运行的cpu不在hctx的mask里，则警告
	if (!cpumask_test_cpu(raw_smp_processor_id(), hctx->cpumask) &&
		cpu_online(hctx->next_cpu)) {
		printk(KERN_WARNING "run queue from wrong CPU %d, hctx %s\n",
			raw_smp_processor_id(),
			cpumask_empty(hctx->cpumask) ? "inactive": "active");
		dump_stack();
	}

	/*
	 * 我们不能在中断上下文运行队列，这里打警告
	 */
	WARN_ON_ONCE(in_interrupt());

	// 如果hctx是可阻塞的，则下面的派发函数可能阻塞
	might_sleep_if(hctx->flags & BLK_MQ_F_BLOCKING);

	hctx_lock(hctx, &srcu_idx);
	// 派发请求
	blk_mq_sched_dispatch_requests(hctx);
	hctx_unlock(hctx, srcu_idx);
}
```

## 2. 运行多个队列
```c
void blk_mq_run_hw_queues(struct request_queue *q, bool async)
{
	struct blk_mq_hw_ctx *hctx;
	int i;

	// 遍历每个hctx
	queue_for_each_hw_ctx(q, hctx, i) {
		// 队列已停止
		if (blk_mq_hctx_stopped(hctx))
			continue;

		// 运行队列
		blk_mq_run_hw_queue(hctx, async);
	}
}
```

## 3. blk_mq_requeue_work
```c
static void blk_mq_requeue_work(struct work_struct *work)
{
	struct request_queue *q =
		container_of(work, struct request_queue, requeue_work.work);
	LIST_HEAD(rq_list);
	struct request *rq, *next;

	// 取出requeue_list
	spin_lock_irq(&q->requeue_lock);
	list_splice_init(&q->requeue_list, &rq_list);
	spin_unlock_irq(&q->requeue_lock);

	list_for_each_entry_safe(rq, next, &rq_list, queuelist) {
		// ?
		if (!(rq->rq_flags & (RQF_SOFTBARRIER | RQF_DONTPREP)))
			continue;

		rq->rq_flags &= ~RQF_SOFTBARRIER;
		// 删除
		list_del_init(&rq->queuelist);

		// 有这个标志,表示rq有设备的特殊数据,绕过插入,直接加到dispatch列表
		if (rq->rq_flags & RQF_DONTPREP)
			blk_mq_request_bypass_insert(rq, false/*不加到表头*/, false/*不运行队列*/);
		elsef
			// 普通插入请求
			blk_mq_sched_insert_request(rq, true/*加到表头*/, false/*不运行队列*/, false/*异步*/);
	}

	// 遍历rq_list, 这些请求直接调用插入请求.
	// 为啥不把上面那个循环和这个循环合并
	while (!list_empty(&rq_list)) {
		rq = list_entry(rq_list.next, struct request, queuelist);
		list_del_init(&rq->queuelist);
		blk_mq_sched_insert_request(rq, false, false, false);
	}

	// 运行队列
	blk_mq_run_hw_queues(q, false/*是否异步*/);
}
```

## 4. 延迟运行所有队列
```c
void blk_mq_delay_run_hw_queues(struct request_queue *q, unsigned long msecs)
{
	struct blk_mq_hw_ctx *hctx;
	int i;

	// 遍历所有hctx
	queue_for_each_hw_ctx(q, hctx, i) {
		if (blk_mq_hctx_stopped(hctx))
			continue;

		// 这个直接调用__blk_mq_delay_run_hw_queue
		blk_mq_delay_run_hw_queue(hctx, msecs);
	}
}
```