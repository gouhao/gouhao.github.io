# blk_dispatch
源码基于5.10

## 1. blk_mq_sched_dispatch_requests
```c
void blk_mq_sched_dispatch_requests(struct blk_mq_hw_ctx *hctx)
{
	// 队列
	struct request_queue *q = hctx->queue;

	// 队列已停止或者被暂停
	if (unlikely(blk_mq_hctx_stopped(hctx) || blk_queue_quiesced(q)))
		return;

	// 运行次数统计
	hctx->run++;

	/*
	 * 返回-EAGAIN表示hctx->dispatch不空，我们必须再次运行为了防止饥饿刷出
	 */
	if (__blk_mq_sched_dispatch_requests(hctx) == -EAGAIN) {
		if (__blk_mq_sched_dispatch_requests(hctx) == -EAGAIN)
			// 如果第2次还是失败，则使用异步派发,再重试
			blk_mq_run_hw_queue(hctx, true);
	}
}

static int __blk_mq_sched_dispatch_requests(struct blk_mq_hw_ctx *hctx)
{
	struct request_queue *q = hctx->queue;
	struct elevator_queue *e = q->elevator;
	// 有无调度派发
	const bool has_sched_dispatch = e && e->type->ops.dispatch_request;
	int ret = 0;
	LIST_HEAD(rq_list);

	/*
	 * 如果之前有请求在派发列表上，则先把它们放在rq列表里，为了公平的派发
	 */
	if (!list_empty_careful(&hctx->dispatch)) {
		spin_lock(&hctx->lock);
		if (!list_empty(&hctx->dispatch))
			list_splice_init(&hctx->dispatch, &rq_list);
		spin_unlock(&hctx->lock);
	}

	// rq_list不空，表示从dispatch里获取了之前的请求
	if (!list_empty(&rq_list)) {
		// 设置BLK_MQ_S_SCHED_RESTART标志
		blk_mq_sched_mark_restart_hctx(hctx);
		// 先把rq_list里的直接派发了
		if (blk_mq_dispatch_rq_list(hctx, &rq_list, 0)) {
			// 派发成功后，再派发新增的请求
			
			// 看有无调度器然后走不同的派发路径
			if (has_sched_dispatch)
				// 从调度器派发
				ret = blk_mq_do_dispatch_sched(hctx);
			else
				// 从ctx里派发
				ret = blk_mq_do_dispatch_ctx(hctx);
		}
	
	// 走到这儿表示dispatch里之前没有请求

	} else if (has_sched_dispatch) {
		// 如果有调度器，则使用调度器派发派发
		ret = blk_mq_do_dispatch_sched(hctx);

	// 走到这儿表示没有调度器

	} else if (hctx->dispatch_busy) {
		// 队列忙，说明队列正在运行，这时候从hctx里派发
		ret = blk_mq_do_dispatch_ctx(hctx);
	
	// 走到这儿表示调度器不忙

	} else {
		// 普通场景

		// 把ctx里的请求都放到rq_list上
		blk_mq_flush_busy_ctxs(hctx, &rq_list);
		// 派发请求
		blk_mq_dispatch_rq_list(hctx, &rq_list, 0);
	}

	return ret;
}
```

## 2. 普通场景
在普通场景里，先把所有ctx里的请求放在一个列表rq_list上，然后再派发rq_list上的请求。
```c
void blk_mq_flush_busy_ctxs(struct blk_mq_hw_ctx *hctx, struct list_head *list)
{
	struct flush_busy_ctx_data data = {
		.hctx = hctx,
		.list = list,
	};

	// 遍历ctx映射里设置的位，调用flush_busy_ctx
	sbitmap_for_each_set(&hctx->ctx_map, flush_busy_ctx, &data);
}

static bool flush_busy_ctx(struct sbitmap *sb, unsigned int bitnr, void *data)
{
	struct flush_busy_ctx_data *flush_data = data;
	// 硬队列
	struct blk_mq_hw_ctx *hctx = flush_data->hctx;
	// 软队列
	struct blk_mq_ctx *ctx = hctx->ctxs[bitnr];
	enum hctx_type type = hctx->type;

	spin_lock(&ctx->lock);
	// 把请求链到list后面，这个list就是从派发里传过来的
	list_splice_tail_init(&ctx->rq_lists[type], flush_data->list);
	// 清除对应的比特位
	sbitmap_clear_bit(sb, bitnr);
	spin_unlock(&ctx->lock);
	return true;
}
```



## 3. 有调度器的派发
```c
static int blk_mq_do_dispatch_sched(struct blk_mq_hw_ctx *hctx)
{
	int ret;

	do {
		// 派发
		ret = __blk_mq_do_dispatch_sched(hctx);
		// 返回1表示派发成功了，则继续
	} while (ret == 1);

	return ret;
}

static int __blk_mq_do_dispatch_sched(struct blk_mq_hw_ctx *hctx)
{
	struct request_queue *q = hctx->queue;
	struct elevator_queue *e = q->elevator;
	bool multi_hctxs = false, run_queue = false;
	bool dispatched = false, busy = false;
	unsigned int max_dispatch;
	// 记录需要派发的rq
	LIST_HEAD(rq_list);
	// 记录需要派发的数量
	int count = 0;

	if (hctx->dispatch_busy)
		// 派发忙，则最大只派发一个
		max_dispatch = 1;
	else
		// 否则可以派发最大的请求数
		max_dispatch = hctx->queue->nr_requests;

	do {
		struct request *rq;

		// 没有需要做的工作了，退出
		if (e->type->ops.has_work && !e->type->ops.has_work(hctx))
			break;

		// 派发列表里没有任务时，返回忙，不派发。
		if (!list_empty_careful(&hctx->dispatch)) {
			busy = true;
			break;
		}

		// 获取budget
		if (!blk_mq_get_dispatch_budget(q))
			break;

		// 获取需要派发的请求
		rq = e->type->ops.dispatch_request(hctx);

		// 获取失败，或者没有rq了
		if (!rq) {
			// 释放 budget
			blk_mq_put_dispatch_budget(q);
			// 需要运行队列
			run_queue = true;
			break;
		}

		// 走到这儿表示获取成功

		// 添加到rq_list里
		list_add_tail(&rq->queuelist, &rq_list);

		// 有多个队列
		if (rq->mq_hctx != hctx)
			multi_hctxs = true;
	} while (++count < max_dispatch);

	if (!count) {
		// 一个请求都没有入队，但是需要运行队列，则延迟再运行队列
		// 这种情况只有调度器里请求为空了
		if (run_queue)
			// 运行所有的硬件队列,BLK_MQ_BUDGET_DELAY=3毫秒
			blk_mq_delay_run_hw_queues(q, BLK_MQ_BUDGET_DELAY);
	} else if (multi_hctxs) {
		// 如果有多个hctx，先按hctx来排序
		list_sort(NULL, &rq_list, sched_rq_cmp);
		do {
			// 真正的派发请求
			dispatched |= blk_mq_dispatch_hctx_list(&rq_list);
			
			// 这里需要循环派发，因为 blk_mq_dispatch_hctx_list只派发一个hctx的请求
		} while (!list_empty(&rq_list));
	} else {
		// 只有一个hctx，则派发请求
		dispatched = blk_mq_dispatch_rq_list(hctx, &rq_list, count);
	}

	// 忙的话返回重试
	if (busy)
		return -EAGAIN;
	// 返回是否派发
	return !!dispatched;
}

static int sched_rq_cmp(void *priv, const struct list_head *a,
			const struct list_head *b)
{
	struct request *rqa = container_of(a, struct request, queuelist);
	struct request *rqb = container_of(b, struct request, queuelist);

	// 按hctx的地址排序
	return rqa->mq_hctx > rqb->mq_hctx;
}
```

### 3.1 blk_mq_dispatch_hctx_list
```c
static bool blk_mq_dispatch_hctx_list(struct list_head *rq_list)
{
	// 第一个请求的hctx
	struct blk_mq_hw_ctx *hctx =
		list_first_entry(rq_list, struct request, queuelist)->mq_hctx;
	struct request *rq;
	LIST_HEAD(hctx_list);
	unsigned int count = 0;

	// 遍历需要派发的请求列表
	list_for_each_entry(rq, rq_list, queuelist) {
		// 因为列表已经按hctx排序了，所以遇到第一个hctx不同时，就派发它前面的
		if (rq->mq_hctx != hctx) {
			// 把rq_list到rq->queuelist之间的元素放到hctx_list上，然后派发
			list_cut_before(&hctx_list, rq_list, &rq->queuelist);
			goto dispatch;
		}
		
		// 记录将要放入hctx_list里请求的数量
		count++;
	}
	// 走到这儿表示rq_list里只有一个hctx，所以把rq_list整个列表都放到hctx里，
	// 然后把rq_list初始化
	list_splice_tail_init(rq_list, &hctx_list);

dispatch:
	// 派发
	return blk_mq_dispatch_rq_list(hctx, &hctx_list, count);
}
```

## 4. 忙时的派发
hctx->dispatch_busy 是一个表示队列忙或空闲的状态，它使用ewma(指数加权移动平均法)来记录忙或空闲。ewma可以使这2种状态平滑的过度，不至于来回变。  
dispatch_ctx会循环遍历所有ctx里的请求,每次派发一个,直到ctx里的所有请求被派发
```c
static int blk_mq_do_dispatch_ctx(struct blk_mq_hw_ctx *hctx)
{
	struct request_queue *q = hctx->queue;
	LIST_HEAD(rq_list);
	// 从上次派发的ctx开始
	struct blk_mq_ctx *ctx = READ_ONCE(hctx->dispatch_from);
	int ret = 0;
	struct request *rq;

	do {
		// dispatch队列不为空，表示有待派发的请求
		if (!list_empty_careful(&hctx->dispatch)) {
			ret = -EAGAIN;
			break;
		}

		// hctx的ctx没有一个置位的，那就不用派发了
		if (!sbitmap_any_bit_set(&hctx->ctx_map))
			break;

		// 获取budget，获取失败也返回
		if (!blk_mq_get_dispatch_budget(q))
			break;

		// 从一个ctx里取出请求
		rq = blk_mq_dequeue_from_ctx(hctx, ctx);

		// 没取到请求
		if (!rq) {
			blk_mq_put_dispatch_budget(q);
			
			// 延迟3毫秒再重新运行
			blk_mq_delay_run_hw_queues(q, BLK_MQ_BUDGET_DELAY);
			break;
		}

		// 把取出的请求加到rq_list里
		list_add(&rq->queuelist, &rq_list);

		// 下一个ctx
		ctx = blk_mq_next_ctx(hctx, rq->mq_ctx);

	// 派发rq_list上的请求，如果派发成功，则继续循环
	// 软队列里每次只派发一个?
	} while (blk_mq_dispatch_rq_list(rq->mq_hctx, &rq_list, 1));

	// 写入最后一个派发的ctx
	WRITE_ONCE(hctx->dispatch_from, ctx);
	return ret;
}

struct request *blk_mq_dequeue_from_ctx(struct blk_mq_hw_ctx *hctx,
					struct blk_mq_ctx *start)
{
	// 队列起点，如果start为0, 则从0开始，否则从start的hctx序号开始
	unsigned off = start ? start->index_hw[hctx->type] : 0;
	struct dispatch_rq_data data = {
		.hctx = hctx,
		.rq   = NULL,
	};

	// 遍历ctx上的每个映射，从ctx里取请求，取到了就放到data.rq里，
	// 每成功取出一个ctx就会退出
	__sbitmap_for_each_set(&hctx->ctx_map, off,
			       dispatch_rq_from_ctx, &data);

	// 返回从ctx里是否取到了请求
	return data.rq;
}

static bool dispatch_rq_from_ctx(struct sbitmap *sb, unsigned int bitnr,
		void *data)
{
	struct dispatch_rq_data *dispatch_data = data;
	// 硬件队列
	struct blk_mq_hw_ctx *hctx = dispatch_data->hctx;
	// 对应的软队列
	struct blk_mq_ctx *ctx = hctx->ctxs[bitnr];
	// 类型
	enum hctx_type type = hctx->type;

	spin_lock(&ctx->lock);
	// 软队列里有请求
	if (!list_empty(&ctx->rq_lists[type])) {
		// 从ctx列表上取一个请求
		dispatch_data->rq = list_entry_rq(ctx->rq_lists[type].next);
		// 将请求从列表上删了,注意,这里是每次只取一个请求
		list_del_init(&dispatch_data->rq->queuelist);
		// 如果列表上空了，则清除对应的位图
		if (list_empty(&ctx->rq_lists[type]))
			sbitmap_clear_bit(sb, bitnr);
	}
	spin_unlock(&ctx->lock);

	// 返回false表示不再循环，如果rq取到了值就返回false，退出__sbitmap_for_each_set的循环
	return !dispatch_data->rq;
}

static struct blk_mq_ctx *blk_mq_next_ctx(struct blk_mq_hw_ctx *hctx,
					  struct blk_mq_ctx *ctx)
{
	// 当前hctx里ctx的序号
	unsigned short idx = ctx->index_hw[hctx->type];

	// 如果超过了最大值，则从0开始
	if (++idx == hctx->nr_ctx)
		idx = 0;

	// 返回下一个ctx
	return hctx->ctxs[idx];
}
```

### 5. blk_mq_dispatch_rq_list
所有的派发路径最终都会汇集到这个函数里来，这个是最终给驱动层派发的函数。
```c
bool blk_mq_dispatch_rq_list(struct blk_mq_hw_ctx *hctx, struct list_head *list,
			     unsigned int nr_budgets)
{
	enum prep_dispatch prep;
	// 硬件队列
	struct request_queue *q = hctx->queue;
	struct request *rq, *nxt;
	int errors, queued;
	blk_status_t ret = BLK_STS_OK;
	LIST_HEAD(zone_list);
	bool needs_resource = false;

	// list为空
	if (list_empty(list))
		return false;

	errors = queued = 0;
	// 处理所有的请求，把它们发给驱动
	do {
		struct blk_mq_queue_data bd;

		// 取出一个请求
		rq = list_first_entry(list, struct request, queuelist);

		// rq的hctx发生了变化
		WARN_ON_ONCE(hctx != rq->mq_hctx);

		// 准备派发
		prep = blk_mq_prep_dispatch_rq(rq, !nr_budgets);
		// 准备失败，退出
		if (prep != PREP_DISPATCH_OK)
			break;

		// 走到这儿表示准备成功，可以派发

		// 从list里删除
		list_del_init(&rq->queuelist);

		bd.rq = rq;

		if (list_empty(list))
			// 列表为空了，则是最后一个请求
			bd.last = true;
		else {
			// 在list不为空的时候，尝试为下一个请求获取driver tag，如果获取失败，
			// 那么当前请求也是最后一个请求

			// 获取下一个请求
			nxt = list_first_entry(list, struct request, queuelist);
			// 如果不能为下一个请求获取driver tag，那也是最后一个请求，否则，则不是最后一个
			bd.last = !blk_mq_get_driver_tag(nxt);
		}

		// 只要调用入队就减1,不管成功或失败
		if (nr_budgets)
			nr_budgets--;
		// 调用设备的queue_rq，如果是scsi就会调用到scsi_queue_rq
		ret = q->mq_ops->queue_rq(hctx, &bd);
		switch (ret) {
		case BLK_STS_OK:
			// 入队成功，queued记录入队成功的数量
			queued++;
			break;
		case BLK_STS_RESOURCE:
			// 资源忙
			needs_resource = true;
			fallthrough;
		case BLK_STS_DEV_RESOURCE:
			// 设备资源忙
			blk_mq_handle_dev_resource(rq, list);
			goto out;
		case BLK_STS_ZONE_RESOURCE:
			// zone设备资源忙
			blk_mq_handle_zone_resource(rq, &zone_list);
			needs_resource = true;
			break;
		default:
			// 出错，结束请求
			errors++;
			blk_mq_end_request(rq, BLK_STS_IOERR);
		}
	// 直到所有的列表派发完
	} while (!list_empty(list));
out:
	// zoned_list不空，则把它再加到list上
	if (!list_empty(&zone_list))
		list_splice_tail_init(&zone_list, list);

	// 已派发统计
	hctx->dispatched[queued_to_index(queued)]++;

	// (list里还有请求 || 有错误) && 驱动有commit_rqs函数 && 有派发成功的
	if ((!list_empty(list) || errors) && q->mq_ops->commit_rqs && queued)
		// 先之前派发的请求先提交
		q->mq_ops->commit_rqs(hctx);

	// 如果列表里还有请求，就把它们加到dispatch里，会在下一次运行queue的时候再派发它们
	if (!list_empty(list)) {
		bool needs_restart;
		// 没有共享的tag了
		bool no_tag = prep == PREP_DISPATCH_NO_TAG &&
			(hctx->flags & BLK_MQ_F_TAG_QUEUE_SHARED);

		// 先释放budgets
		blk_mq_release_budgets(q, nr_budgets);

		spin_lock(&hctx->lock);
		// 把list里的加到派发列表里
		list_splice_tail_init(list, &hctx->dispatch);
		spin_unlock(&hctx->lock);

		smp_mb();

		// 需要重新启动
		needs_restart = blk_mq_sched_needs_restart(hctx);
		// 如果之前没有budget了，则是需要资源
		if (prep == PREP_DISPATCH_NO_BUDGET)
			needs_resource = true;
		
		// 不需要重启 || (没tag了 && 没有人在等待？)
		if (!needs_restart ||
		    (no_tag && list_empty_careful(&hctx->dispatch_wait.entry)))
		    	// (不用重启 || (没有tag && 没有等待的))

		    	// 异步运行
			blk_mq_run_hw_queue(hctx, true);
		
		// 走到这儿表示： 需要重启 && (有tag || 有人在等待)

		else if (needs_restart && needs_resource)
			// 需要重启 && 需要资源

			// 延迟3毫秒运行。BLK_MQ_RESOURCE_DELAY = 3
			blk_mq_delay_run_hw_queue(hctx, BLK_MQ_RESOURCE_DELAY);

		// 标记hctx忙
		blk_mq_update_dispatch_busy(hctx, true);
		return false;
	} else
		// 请求全部提交，标记hctx不忙
		blk_mq_update_dispatch_busy(hctx, false);

	// 返回值是有无处理的，成功/失败都算
	return (queued + errors) != 0;
}

static inline unsigned int queued_to_index(unsigned int queued)
{
	if (!queued)
		return 0;

	// BLK_MQ_MAX_DISPATCH_ORDER=7
	// ilog2(queued)算出派发成功的数量的对数
	return min(BLK_MQ_MAX_DISPATCH_ORDER - 1, ilog2(queued) + 1);
}

```

### 5.1 blk_mq_prep_dispatch_rq
```c
static enum prep_dispatch blk_mq_prep_dispatch_rq(struct request *rq,
						  bool need_budget)
{
	struct blk_mq_hw_ctx *hctx = rq->mq_hctx;

	// 如果需要预算，则获取一个
	if (need_budget && !blk_mq_get_dispatch_budget(rq->q)) {
		// 获取失败释放driver tag
		blk_mq_put_driver_tag(rq);
		return PREP_DISPATCH_NO_BUDGET;
	}

	// 获取driver tag,这个函数主要把请求放到tag对应的数组里
	if (!blk_mq_get_driver_tag(rq)) {
		// 获取失败
		
		// 等一个tag
		if (!blk_mq_mark_tag_wait(hctx, rq)) {
			// 等tag失败
			
			// 如果上面分配了budget，则释放之
			if (need_budget)
				blk_mq_put_dispatch_budget(rq->q);
			return PREP_DISPATCH_NO_TAG;
		}
	}

	// 返回成功
	return PREP_DISPATCH_OK;
}
```

#### 5.1.1 budget
```c
static inline bool blk_mq_get_dispatch_budget(struct request_queue *q)
{
	// 从驱动里获取budget
	if (q->mq_ops->get_budget)
		return q->mq_ops->get_budget(q);
	// 如果驱动不支持这个函数，直接返回true
	return true;
}

static inline void blk_mq_put_dispatch_budget(struct request_queue *q)
{
	if (q->mq_ops->put_budget)
		q->mq_ops->put_budget(q);
}
```

## 6. 直接发布
### 6.1 入口
直接发布的2个入口: blk_mq_try_issue_directly, blk_mq_request_issue_directly, 这2个入口最终都会调到同一函数.

#### 6.1.1 blk_mq_try_issue_directly
```c
static void blk_mq_try_issue_directly(struct blk_mq_hw_ctx *hctx,
		struct request *rq, blk_qc_t *cookie)
{
	blk_status_t ret;
	int srcu_idx;

	// 硬件允许阻塞的话可能会阻塞
	might_sleep_if(hctx->flags & BLK_MQ_F_BLOCKING);

	hctx_lock(hctx, &srcu_idx);

	// 发布请求
	ret = __blk_mq_try_issue_directly(hctx, rq, cookie, false, true);

	if (ret == BLK_STS_RESOURCE || ret == BLK_STS_DEV_RESOURCE)
		// 因为资源忙而失败，则先插入队列？
		blk_mq_request_bypass_insert(rq, false, true);
	else if (ret != BLK_STS_OK)
		// 其它原因直接结束请求
		blk_mq_end_request(rq, ret);

	hctx_unlock(hctx, srcu_idx);
}
```

#### 6.1.2 blk_mq_try_issue_list_directly
这个函数目前只有一个调用的地方: finish_plug -> blk_mq_sched_insert_requests -> blk_mq_try_issue_list_directly
```c
void blk_mq_try_issue_list_directly(struct blk_mq_hw_ctx *hctx,
		struct list_head *list)
{
	int queued = 0;
	int errors = 0;

	// 遍历链表
	while (!list_empty(list)) {
		blk_status_t ret;
		// 获取请求
		struct request *rq = list_first_entry(list, struct request,
				queuelist);

		// 从队列里删除请求
		list_del_init(&rq->queuelist);
		// 发布请求,这个函数会直接调用驱动的发布函数
		ret = blk_mq_request_issue_directly(rq, list_empty(list));
		
		// 没发布成功
		if (ret != BLK_STS_OK) {
			// 错误增加
			errors++;
			// 如果是因为资源问题失败了，插入到队列晨
			if (ret == BLK_STS_RESOURCE ||
					ret == BLK_STS_DEV_RESOURCE) {
				// 加到派发队列, 
				blk_mq_request_bypass_insert(rq, false,
							// 最后一个值是否运行队列
							list_empty(list));
				break;
			}
			
			// 如果是其它错误，则结束这个请求
			blk_mq_end_request(rq, ret);
		} else
			// 发布成功
			queued++;
	}

	// list不为空或者有错误 && queued: 则表示只发布了一部分
	// 如果队列有commit_rqs的话，则调用之
	if ((!list_empty(list) || errors) &&
	     hctx->queue->mq_ops->commit_rqs && queued)
		hctx->queue->mq_ops->commit_rqs(hctx);
}
```

#### 6.1.3 blk_mq_request_issue_directly
```c
blk_status_t blk_mq_request_issue_directly(struct request *rq, bool last)
{
	blk_status_t ret;
	int srcu_idx;
	blk_qc_t unused_cookie;
	struct blk_mq_hw_ctx *hctx = rq->mq_hctx;

	// 锁硬件队列
	hctx_lock(hctx, &srcu_idx);
	// 发布请求
	ret = __blk_mq_try_issue_directly(hctx, rq, &unused_cookie, true, last);
	hctx_unlock(hctx, srcu_idx);

	return ret;
}
```

### 6.2 __blk_mq_try_issue_directly
```c
## __blk_mq_try_issue_directly
```c
static blk_status_t __blk_mq_try_issue_directly(struct blk_mq_hw_ctx *hctx,
						struct request *rq,
						blk_qc_t *cookie,
						bool bypass_insert, bool last)
{
	struct request_queue *q = rq->q;
	bool run_queue = true;

	// 如果队列是停止状态或静默状态，则先插入请求，不能直接发布
	// blk_mq_hctx_stopped:检查hctx的状态有无BLK_MQ_S_STOPPED
	// blk_queue_quiesced检查队列的状态有无QUEUE_FLAG_QUIESCED
	if (blk_mq_hctx_stopped(hctx) || blk_queue_quiesced(q)) {
		run_queue = false;
		bypass_insert = false;
		goto insert;
	}

	// 有电梯，不是bypass，则先插入
	if (q->elevator && !bypass_insert)
		goto insert;

	// 不能获取budget也先插入
	if (!blk_mq_get_dispatch_budget(q))
		goto insert;

	// 不能获取驱动tag直接插入
	if (!blk_mq_get_driver_tag(rq)) {
		// 插入前放弃budget
		blk_mq_put_dispatch_budget(q);
		goto insert;
	}

	return __blk_mq_issue_directly(hctx, rq, cookie, last);

	// 走到这儿表示不能直接发布请求
insert:
	// 如果需要绕过调度器插入，则返回资源忙
	if (bypass_insert)
		return BLK_STS_RESOURCE;

	// 调度器插入
	blk_mq_sched_insert_request(rq, false, run_queue, false);

	return BLK_STS_OK;
}

static blk_status_t __blk_mq_issue_directly(struct blk_mq_hw_ctx *hctx,
					    struct request *rq,
					    blk_qc_t *cookie, bool last)
{
	struct request_queue *q = rq->q;
	// 入队数据
	struct blk_mq_queue_data bd = {
		.rq = rq,
		.last = last,
	};
	blk_qc_t new_cookie;
	blk_status_t ret;

	// 生成rq的cookie
	new_cookie = request_to_qc_t(hctx, rq);

	// 调用队列的操作入队
	ret = q->mq_ops->queue_rq(hctx, &bd);
	switch (ret) {
	case BLK_STS_OK:
		// 成功

		// 更新状态不忙
		blk_mq_update_dispatch_busy(hctx, false);
		// 设置新的cookie
		*cookie = new_cookie;
		break;
	case BLK_STS_RESOURCE:
	case BLK_STS_DEV_RESOURCE:
		// 资源忙

		// 更新状态为忙
		blk_mq_update_dispatch_busy(hctx, true);

		// 重新加入到请求队列
		__blk_mq_requeue_request(rq);
		break;
	default:
		// 其它失败的情况
		blk_mq_update_dispatch_busy(hctx, false);
		*cookie = BLK_QC_T_NONE;
		break;
	}

	return ret;
}

static void blk_mq_update_dispatch_busy(struct blk_mq_hw_ctx *hctx, bool busy)
{
	/* ewma: 指数加权移动平均法。
	公式：EWMA(t) = λY(t) + (1-λ)EWMA(t-1)
	对应到这里busy就是Y(t),
	*/
	unsigned int ewma;

	// 当前的状态
	ewma = hctx->dispatch_busy;

	// 当前不忙 && 要设置的也不忙，不用更新了
	if (!ewma && !busy)
		return;

	/* BLK_MQ_DISPATCH_BUSY_EWMA_WEIGHT = 8，所以λ=1/8
	 按上面公式把下面的计算展开:
	 	ewma = 1/8 * busy + (1 - 1/8) * ewma
		     = 1/8 * busy + (ewma*7)/8
		
		busy=0: ewma = (ewma*7)/8
		busy=1: ewma = 1/8 + (ewma*7)/8
			     = 16 / 8 + (ewma*7)/8
		也就是每当忙的时候给ewma+2。

		真值表如下：
		   busy	   dispatch_busy
		     0		 0
		     1		 2
		     0		 1
		     0		 0

		     1		 2
		     1		 3
		     1		 4
		     0		 3
		     0		 2
		     0		 1
		     0		 0
			
	*/

	ewma *= BLK_MQ_DISPATCH_BUSY_EWMA_WEIGHT - 1;
	
	// BLK_MQ_DISPATCH_BUSY_EWMA_FACTOR = 4
	if (busy)	
		ewma += 1 << BLK_MQ_DISPATCH_BUSY_EWMA_FACTOR;
	ewma /= BLK_MQ_DISPATCH_BUSY_EWMA_WEIGHT;

	// 设置ewma
	hctx->dispatch_busy = ewma;
}

static void __blk_mq_requeue_request(struct request *rq)
{
	struct request_queue *q = rq->q;

	// 释放driver的tag
	blk_mq_put_driver_tag(rq);

	trace_block_rq_requeue(rq);
	// todo: qos?
	rq_qos_requeue(q, rq);

	// 把rq的状态标记为MQ_RQ_IDLE
	if (blk_mq_request_started(rq)) {
		WRITE_ONCE(rq->state, MQ_RQ_IDLE);
		rq->rq_flags &= ~RQF_TIMED_OUT;
	}
}

static inline int blk_mq_request_started(struct request *rq)
{
	return blk_mq_rq_state(rq) != MQ_RQ_IDLE;
}
```