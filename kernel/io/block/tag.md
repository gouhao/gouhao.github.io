# tag
源码基于5.10

## 1. 获取tag
```c
unsigned int blk_mq_get_tag(struct blk_mq_alloc_data *data)
{
	// 获取hctx或者调度器里的tags
	struct blk_mq_tags *tags = blk_mq_tags_from_data(data);
	struct sbitmap_queue *bt;
	struct sbq_wait_state *ws;
	DEFINE_SBQ_WAIT(wait);
	unsigned int tag_offset;
	int tag;

	if (data->flags & BLK_MQ_REQ_RESERVED) {
		// 请求的是保留的tag

		// 没有保留的tag了，返回失败
		if (unlikely(!tags->nr_reserved_tags)) {	
			WARN_ON_ONCE(1);
			return BLK_MQ_NO_TAG;
		}
		// 使用保留tag的位图
		bt = tags->breserved_tags;
		// 起点从0开始
		tag_offset = 0;
	} else {
		// 使用正常的tag位图
		bt = tags->bitmap_tags;
		// 起点从保留tag开始
		tag_offset = tags->nr_reserved_tags;
	}

	// 获取一个tag
	tag = __blk_mq_get_tag(data, bt);
	
	// 如果找到了一个tag，分配成功，一般情况下在这都会分配成功，直接返回
	if (tag != BLK_MQ_NO_TAG)
		goto found_tag;

	// 走到这儿是分配tag失败，分配失败后，需要运行当前请求释放tag

	// 如果请求不想等，则直接返回no_tag
	if (data->flags & BLK_MQ_REQ_NOWAIT)
		return BLK_MQ_NO_TAG;

	// 获取一个等待状态
	ws = bt_wait_ptr(bt, data->hctx);
	
	// 下面是个死循环，除非获取tag成功才会退出
	do {
		struct sbitmap_queue *bt_prev;

		// 运行对应的hctx，把准备好的请求发送出去
		blk_mq_run_hw_queue(data->hctx, false);

		// 经过上面run_hw_queue后，再尝试获取tag
		tag = __blk_mq_get_tag(data, bt);
		// 分配成功退出
		if (tag != BLK_MQ_NO_TAG)
			break;

		// 在位图上等待，这是不可中断等待，必须等到谁释放一个tag？
		sbitmap_prepare_to_wait(bt, ws, &wait, TASK_UNINTERRUPTIBLE);

		// 走到这儿表示等待结束

		// 再获取一次tag
		tag = __blk_mq_get_tag(data, bt);
		// 如果获取到了直接退出循环
		if (tag != BLK_MQ_NO_TAG)
			break;

		// 走到这儿表示没获取成功
	
		bt_prev = bt;

		// 这个会把目前plug上的请求提交，好让出tag
		io_schedule();

		// 结束等待
		sbitmap_finish_wait(bt, ws, &wait);

		// 因为上面重新调度了,所以要重新获取ctx, hctx,它们可以已经变了
		data->ctx = blk_mq_get_ctx(data->q);
		data->hctx = blk_mq_map_queue(data->q, data->cmd_flags,
						data->ctx);
		// 重新获取tags
		tags = blk_mq_tags_from_data(data);

		// 重新计算要使用的位图
		if (data->flags & BLK_MQ_REQ_RESERVED)
			bt = tags->breserved_tags;
		else
			bt = tags->bitmap_tags;

		// 如果bt变了,唤醒prev_bt
		if (bt != bt_prev)
			sbitmap_queue_wake_up(bt_prev);

		// 重新获取ws
		ws = bt_wait_ptr(bt, data->hctx);
	} while (1);

	// 走到这儿肯定是获取tag成功了

	//结束等待
	sbitmap_finish_wait(bt, ws, &wait);

found_tag:
	// 如果hctx不活跃了，则把这个tag还回去，返回no_tag
	if (unlikely(test_bit(BLK_MQ_S_INACTIVE, &data->hctx->state))) {
		blk_mq_put_tag(tags, data->ctx, tag + tag_offset);
		return BLK_MQ_NO_TAG;
	}
	// 加上tag的起点，因为位图里的index都是从0开始的，
	// tag_offset只会在获取保留tag时有时，所以如果分配的是保留的要加上保留的偏移
	return tag + tag_offset;
}

static inline struct blk_mq_tags *blk_mq_tags_from_data(struct blk_mq_alloc_data *data)
{
	// 有电梯，则返回电梯的tags
	if (data->q->elevator)
		return data->hctx->sched_tags;

	// 否则返回hctx的tags
	return data->hctx->tags;
}

static int __blk_mq_get_tag(struct blk_mq_alloc_data *data,
			    struct sbitmap_queue *bt)
{
	// 没有电梯 && 不是请求保留的  && 不能入队
	// hctx_may_queue: 是判断还能否分配tag的核心
	if (!data->q->elevator && !(data->flags & BLK_MQ_REQ_RESERVED) &&
			!hctx_may_queue(data->hctx, bt))
		return BLK_MQ_NO_TAG;

	// todo: what is shallow_depth?
	if (data->shallow_depth)
		// 这个条件一般不走
		return __sbitmap_queue_get_shallow(bt, data->shallow_depth);
	else
		// 在位图里分配一个空闲位
		return __sbitmap_queue_get(bt);
}
```

### 1.1. io_schedule
```c
void __sched io_schedule(void)
{
	int token;

	// 这个函数会刷出plug里的请求,返回一个token
	token = io_schedule_prepare();
	// 调度其它进程
	schedule();
	// 这个主要是把token设置进去
	io_schedule_finish(token);
}


int io_schedule_prepare(void)
{
	// 之前io_wait状态
	int old_iowait = current->in_iowait;

	// 设置io_wait为1.
	// todo: in_iowait有什么用
	current->in_iowait = 1;

	// 刷出当前进程的请求
	blk_schedule_flush_plug(current);

	// 返回旧的iowait状态
	return old_iowait;
}

static inline void blk_schedule_flush_plug(struct task_struct *tsk)
{
	// 获取进程的plug
	struct blk_plug *plug = tsk->plug;

	// 刷出plug上的请求
	if (plug)
		blk_flush_plug_list(plug, true);
}

void io_schedule_finish(int token)
{
	current->in_iowait = token;
}
```

### 1.2. hctx_may_queue
是否允许入队
```c
static inline bool hctx_may_queue(struct blk_mq_hw_ctx *hctx,
				  struct sbitmap_queue *bt)
{
	unsigned int depth, users;

	// 没有hctx或者在队列之间不共享，则返回true。
	// 在多队列的时候有这个标志
	if (!hctx || !(hctx->flags & BLK_MQ_F_TAG_QUEUE_SHARED))
		return true;

	// 位图只有一个tag，也返回true
	if (bt->sb.depth == 1)
		return true;

	// 判断 BLK_MQ_F_TAG_HCTX_SHARED 标志
	if (blk_mq_is_sbitmap_shared(hctx->flags)) {
		// hctx之间共享. 

		struct request_queue *q = hctx->queue;
		struct blk_mq_tag_set *set = q->tag_set;

		// 队列不活跃，则肯定没有共享
		if (!test_bit(QUEUE_FLAG_HCTX_ACTIVE, &q->queue_flags))
			return true;
		// 读出set里所有用户的使用量
		users = atomic_read(&set->active_queues_shared_sbitmap);
	} else {
		// hctx不共享

		// 如果hctx不活跃说明肯定没人用
		if (!test_bit(BLK_MQ_S_TAG_ACTIVE, &hctx->state))
			return true;
		
		// 读出使用人数
		users = atomic_read(&hctx->tags->active_queues);
	}


	// 如果没人同时用，肯定能用
	if (!users)
		return true;

	// 算出每个人最多使用的tag数量,最大为4个
	// todo: 因为depth是int, 4个depth就是32, 目前深度最大为32 ??(好像有点不对)
	depth = max((bt->sb.depth + users - 1) / users, 4U);

	// 已经分配的小于深度,则可以入队.表示还有空闲的位
	return __blk_mq_active_requests(hctx) < depth;
}

static inline int __blk_mq_active_requests(struct blk_mq_hw_ctx *hctx)
{
	if (blk_mq_is_sbitmap_shared(hctx->flags))
		// 返回已经分配的共享的请求数量
		return atomic_read(&hctx->queue->nr_active_requests_shared_sbitmap);
	// 返回当前队列活跃的请求数量
	return atomic_read(&hctx->nr_active);
}

static inline struct sbq_wait_state *bt_wait_ptr(struct sbitmap_queue *bt,
						 struct blk_mq_hw_ctx *hctx)
{
	if (!hctx)
		return &bt->ws[0];
	return sbq_wait_ptr(bt, &hctx->wait_index);
}
```


## 2. get_drvier_tag
```c
static bool blk_mq_get_driver_tag(struct request *rq)
{
	struct blk_mq_hw_ctx *hctx = rq->mq_hctx;

	// rq没有tag && 获取driver tag, 这个条件只有调度器才会走，因为无调度器时把rq的tag保存在rq->tag里，
	// 有调度器时把rq的tag保存在rq->internal_tag里
	if (rq->tag == BLK_MQ_NO_TAG && !__blk_mq_get_driver_tag(rq))
		// 获取失败
		return false;

	// 走到这儿表示获取成功或者是无调度器的情况

	// 硬件队列是共享的 && 请求不是飞行状态
	if ((hctx->flags & BLK_MQ_F_TAG_QUEUE_SHARED) &&
			!(rq->rq_flags & RQF_MQ_INFLIGHT)) {
		// 设置其飞行状态
		rq->rq_flags |= RQF_MQ_INFLIGHT;
		// 增加活跃的数量
		__blk_mq_inc_active_requests(hctx);
	}
	// 放入tag位对应的请求
	hctx->tags->rqs[rq->tag] = rq;
	return true;
}

static inline void __blk_mq_inc_active_requests(struct blk_mq_hw_ctx *hctx)
{
	// 根据是否共享增加活跃的数量,这个是判断BLK_MQ_F_TAG_HCTX_SHARED标志
	if (blk_mq_is_sbitmap_shared(hctx->flags))
		atomic_inc(&hctx->queue->nr_active_requests_shared_sbitmap);
	else
		atomic_inc(&hctx->nr_active);
}

static bool __blk_mq_get_driver_tag(struct request *rq)
{
	// hctx tag位图
	struct sbitmap_queue *bt = rq->mq_hctx->tags->bitmap_tags;
	// 保留tag的数量就是一般tag的起点
	unsigned int tag_offset = rq->mq_hctx->tags->nr_reserved_tags;
	int tag;

	// 标记硬件活跃
	blk_mq_tag_busy(rq->mq_hctx);

	if (blk_mq_tag_is_reserved(rq->mq_hctx->sched_tags, rq->internal_tag)) {
		// 请求使用的是保留tag

		// 位图使用保留的
		bt = rq->mq_hctx->tags->breserved_tags;
		// 保留的起点从0开始
		tag_offset = 0;
	} else {
		// 请求使用的不是保留tag

		// 如果不可入队，则返回false
		if (!hctx_may_queue(rq->mq_hctx, bt))
			return false;
	}

	// 获取一个tag
	tag = __sbitmap_queue_get(bt);
	if (tag == BLK_MQ_NO_TAG)
		return false;

	// tag要加上偏移
	rq->tag = tag + tag_offset;
	return true;
}

static bool blk_mq_mark_tag_wait(struct blk_mq_hw_ctx *hctx,
				 struct request *rq)
{
	struct sbitmap_queue *sbq = hctx->tags->bitmap_tags;
	struct wait_queue_head *wq;
	wait_queue_entry_t *wait;
	bool ret;

	if (!(hctx->flags & BLK_MQ_F_TAG_QUEUE_SHARED)) {
		blk_mq_sched_mark_restart_hctx(hctx);

		/*
		 * It's possible that a tag was freed in the window between the
		 * allocation failure and adding the hardware queue to the wait
		 * queue.
		 *
		 * Don't clear RESTART here, someone else could have set it.
		 * At most this will cost an extra queue run.
		 */
		return blk_mq_get_driver_tag(rq);
	}

	wait = &hctx->dispatch_wait;
	if (!list_empty_careful(&wait->entry))
		return false;

	wq = &bt_wait_ptr(sbq, hctx)->wait;

	spin_lock_irq(&wq->lock);
	spin_lock(&hctx->dispatch_wait_lock);
	if (!list_empty(&wait->entry)) {
		spin_unlock(&hctx->dispatch_wait_lock);
		spin_unlock_irq(&wq->lock);
		return false;
	}

	atomic_inc(&sbq->ws_active);
	wait->flags &= ~WQ_FLAG_EXCLUSIVE;
	__add_wait_queue(wq, wait);

	/*
	 * It's possible that a tag was freed in the window between the
	 * allocation failure and adding the hardware queue to the wait
	 * queue.
	 */
	ret = blk_mq_get_driver_tag(rq);
	if (!ret) {
		spin_unlock(&hctx->dispatch_wait_lock);
		spin_unlock_irq(&wq->lock);
		return false;
	}

	/*
	 * We got a tag, remove ourselves from the wait queue to ensure
	 * someone else gets the wakeup.
	 */
	list_del_init(&wait->entry);
	atomic_dec(&sbq->ws_active);
	spin_unlock(&hctx->dispatch_wait_lock);
	spin_unlock_irq(&wq->lock);

	return true;
}
```

## 3. put_driver_tag
```c
static inline void blk_mq_put_driver_tag(struct request *rq)
{
	// 没有获取到tag直接返回
	if (rq->tag == BLK_MQ_NO_TAG || rq->internal_tag == BLK_MQ_NO_TAG)
		return;

	// 释放tag. 
	// todo: 这个函数里好像没有处理internal_tag?
	__blk_mq_put_driver_tag(rq->mq_hctx, rq);
}

static inline void __blk_mq_put_driver_tag(struct blk_mq_hw_ctx *hctx,
					   struct request *rq)
{
	// 清除bitmap里对应的位
	blk_mq_put_tag(hctx->tags, rq->mq_ctx, rq->tag);
	// 设置为notag
	rq->tag = BLK_MQ_NO_TAG;

	// 如果请求正在飞行,则去掉这个标志
	if (rq->rq_flags & RQF_MQ_INFLIGHT) {
		rq->rq_flags &= ~RQF_MQ_INFLIGHT;
		// 递减活跃计数
		__blk_mq_dec_active_requests(hctx);
	}
}

void blk_mq_put_tag(struct blk_mq_tags *tags, struct blk_mq_ctx *ctx,
		    unsigned int tag)
{
	if (!blk_mq_tag_is_reserved(tags, tag)) {
		// 不是保留tag

		// 算出在非保留tag里的位置
		const int real_tag = tag - tags->nr_reserved_tags;

		BUG_ON(real_tag >= tags->nr_tags);
		// 清除对应位
		sbitmap_queue_clear(tags->bitmap_tags, real_tag, ctx->cpu);
	} else {
		// 是保留tag
		BUG_ON(tag >= tags->nr_reserved_tags);
		// 请除保留的对应位
		sbitmap_queue_clear(tags->breserved_tags, tag, ctx->cpu);
	}
}

static inline void __blk_mq_dec_active_requests(struct blk_mq_hw_ctx *hctx)
{
	// 根据hctx是否共享,减少对应的计数器
	if (blk_mq_is_sbitmap_shared(hctx->flags))
		atomic_dec(&hctx->queue->nr_active_requests_shared_sbitmap);
	else
		atomic_dec(&hctx->nr_active);
}
```

## 4. 标记 tag 忙
```c
static inline bool blk_mq_tag_busy(struct blk_mq_hw_ctx *hctx)
{
	// 没有共享特性也就不用标记了
	if (!(hctx->flags & BLK_MQ_F_TAG_QUEUE_SHARED))
		return false;

	// 设置忙标志
	return __blk_mq_tag_busy(hctx);
}

bool __blk_mq_tag_busy(struct blk_mq_hw_ctx *hctx)
{
	// 判断有无BLK_MQ_F_TAG_HCTX_SHARED标志
	// todo: 这2种标志什么意思?
	if (blk_mq_is_sbitmap_shared(hctx->flags)) {
		struct request_queue *q = hctx->queue;
		struct blk_mq_tag_set *set = q->tag_set;

		// 给queue设置QUEUE_FLAG_HCTX_ACTIVE标志
		if (!test_bit(QUEUE_FLAG_HCTX_ACTIVE, &q->queue_flags) &&
		    !test_and_set_bit(QUEUE_FLAG_HCTX_ACTIVE, &q->queue_flags))
		    	// 第一次设置成功之后，递增active_queues_shared_sbitmap计数
			atomic_inc(&set->active_queues_shared_sbitmap);
	} else {
		// 没有共享标志的话只设置硬件状态的BLK_MQ_S_TAG_ACTIVE就行了
		if (!test_bit(BLK_MQ_S_TAG_ACTIVE, &hctx->state) &&
		    !test_and_set_bit(BLK_MQ_S_TAG_ACTIVE, &hctx->state))
		    	// 递增活跃队列计数
			atomic_inc(&hctx->tags->active_queues);
	}

	return true;
}
```