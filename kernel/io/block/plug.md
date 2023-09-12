# plug 机制
源码基于5.10

## blk_start_plug
```c
void blk_start_plug(struct blk_plug *plug)
{
	struct task_struct *tsk = current;

	// 该进程已经有了plug
	if (tsk->plug)
		return;

	// 一些基本的初始化
	INIT_LIST_HEAD(&plug->mq_list);
	INIT_LIST_HEAD(&plug->cb_list);
	plug->rq_count = 0;
	plug->multiple_queues = false;
	plug->nowait = false;

	// 设置值
	tsk->plug = plug;
}
```

## blk_finish_plug
```c
void blk_finish_plug(struct blk_plug *plug)
{
	// 当前进程没有plug
	if (plug != current->plug)
		return;
	// 刷出plug
	blk_flush_plug_list(plug, false);

	// 当前进程plug置空
	current->plug = NULL;
}
```

## blk_mq_plug
```c
static inline struct blk_plug *blk_mq_plug(struct request_queue *q,
					   struct bio *bio)
{
	/*
	 * 对于普通块设备和读请求使用current->plug，如果blk_start_plug()还没执
	 * 行时它是NULL
	 */
	if (!blk_queue_is_zoned(q) || !op_is_write(bio_op(bio)))
		return current->plug;

	/* Zoned block device write operation case: do not plug the BIO */
	return NULL;
}
```

## blk_add_rq_to_plug
```c
static void blk_add_rq_to_plug(struct blk_plug *plug, struct request *rq)
{
	// 把请求加到末尾
	list_add_tail(&rq->queuelist, &plug->mq_list);
	// 请求数量增加
	plug->rq_count++;
	// 当前plug没有多个队列的请求 && 有多个请求
	if (!plug->multiple_queues && !list_is_singular(&plug->mq_list)) {
		struct request *tmp;

		// 第一个请求
		tmp = list_first_entry(&plug->mq_list, struct request,
						queuelist);
		// 如果rq的队列和第1个请求不是一个队列，则标记plug里的请求有多个队列
		if (tmp->q != rq->q)
			plug->multiple_queues = true;
	}
}
```

## blk_flush_plug_list
```c
void blk_flush_plug_list(struct blk_plug *plug, bool from_schedule)
{
	// 先调用回调列表
	flush_plug_callbacks(plug, from_schedule);

	// 请求列表不为空，则刷出请求
	if (!list_empty(&plug->mq_list))
		blk_mq_flush_plug_list(plug, from_schedule);
}

static void flush_plug_callbacks(struct blk_plug *plug, bool from_schedule)
{
	LIST_HEAD(callbacks);

	// 遍历plug的回调函数列表，这个循环主要是怕在调用回调期间再往回调链表上加回调
	while (!list_empty(&plug->cb_list)) {
		// 把plug的回调列表链到callbacks上，然后初始化cb_list
		// 这样做主要是为了在调用回调期间再往上加新的回调？
		list_splice_init(&plug->cb_list, &callbacks);

		// 遍历每个回调
		while (!list_empty(&callbacks)) {
			// 取出回调
			struct blk_plug_cb *cb = list_first_entry(&callbacks,
							  struct blk_plug_cb,
							  list);
			// 从callbacks列表上删除回调
			list_del(&cb->list);
			// 调用回调
			cb->callback(cb, from_schedule);
		}
	}
}

void blk_mq_flush_plug_list(struct blk_plug *plug, bool from_schedule)
{
	LIST_HEAD(list);

	// 请求列表为空
	if (list_empty(&plug->mq_list))
		return;
	// 把请求放到临时列表上，并初始化mq_list
	list_splice_init(&plug->mq_list, &list);

	// 请求数大于2 && plug里的请求有多个队列
	if (plug->rq_count > 2 && plug->multiple_queues)
		// 给链表排序，plug_rq_cmp是按照请求的ctx, hctx来排序
		// 这样能优化效率
		list_sort(NULL, &list, plug_rq_cmp);

	// 请求数量置0
	plug->rq_count = 0;

	do {
		struct list_head rq_list;
		// head_rq:请求头
		struct request *rq, *head_rq = list_entry_rq(list.next);
		struct list_head *pos = &head_rq->queuelist; /* skip first */
		// 硬上下文
		struct blk_mq_hw_ctx *this_hctx = head_rq->mq_hctx;
		// 软上下文
		struct blk_mq_ctx *this_ctx = head_rq->mq_ctx;
		// depth是给一个队列里插入请求的数量
		unsigned int depth = 1;

		// 遍历plug里的请求队列，算出同一个队列里要插入请求的数量
		// 因为depth刚开始是1，所以从第2个开始遍历
		list_for_each_continue(pos, &list) {
			// 获取请求
			rq = list_entry_rq(pos);

			// 请求的队列为空，什么情况？
			BUG_ON(!rq->q);
			// 上下文不一致，退出
			if (rq->mq_hctx != this_hctx || rq->mq_ctx != this_ctx)
				break;
			// 请求数量加1
			depth++;
		}

		// 这个函数会把[list, pos)的元素放到rq_list里，然后把list指向pos
		list_cut_before(&rq_list, &list, pos);
		trace_block_unplug(head_rq->q, depth, !from_schedule);
		// 给队列里插入list里的请求
		blk_mq_sched_insert_requests(this_hctx, this_ctx, &rq_list,
						from_schedule);
	} while(!list_empty(&list));
}

static int plug_rq_cmp(void *priv, const struct list_head *a,
		       const struct list_head *b)
{
	struct request *rqa = container_of(a, struct request, queuelist);
	struct request *rqb = container_of(b, struct request, queuelist);
	// 先比软队列
	if (rqa->mq_ctx != rqb->mq_ctx)
		return rqa->mq_ctx > rqb->mq_ctx;
	// 再比硬队列
	if (rqa->mq_hctx != rqb->mq_hctx)
		return rqa->mq_hctx > rqb->mq_hctx;

	// 软硬都相同，再比qos
	return blk_rq_pos(rqa) > blk_rq_pos(rqb);
}
```