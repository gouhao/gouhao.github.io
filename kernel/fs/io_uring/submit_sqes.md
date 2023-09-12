# io_submit_sqes
源码基于5.10

## 主流程
```c
static int io_submit_sqes(struct io_ring_ctx *ctx, unsigned int nr)
{
	struct io_submit_state state;
	struct io_kiocb *link = NULL;
	int i, submitted = 0;

	// 判断cq是否已经溢出
	if (test_bit(0, &ctx->sq_check_overflow)) {
		// 如果已经溢出，需要从溢出列表转移
		// 这个函数如果返回0,说明溢出列表没有转移完，cqe还是满的，所以就直接返回 忙
		if (!__io_cqring_overflow_flush(ctx, false, NULL, NULL))
			return -EBUSY;
	}

	// 可以提交的数量，io_sqring_entries是队列里剩余可提交的数量
	// 可提交数量是这3个的最小值
	nr = min3(nr, ctx->sq_entries, io_sqring_entries(ctx));

	// 增加nr个引用
	if (!percpu_ref_tryget_many(&ctx->refs, nr))
		return -EAGAIN;

	// 增加正在进行中的引用
	percpu_counter_add(&current->io_uring->inflight, nr);
	// 增加当前进程计数
	refcount_add(nr, &current->usage);

	// 开始提交，初始化state变量
	io_submit_state_start(&state, ctx, nr);

	for (i = 0; i < nr; i++) {
		const struct io_uring_sqe *sqe;
		struct io_kiocb *req;
		int err;

		// 从sq的头取出一个se
		sqe = io_get_sqe(ctx);
		if (unlikely(!sqe)) {
			// sqe为空，则直接增加cached_sq_head计数
			io_consume_sqe(ctx);
			break;
		}
		// 获取一个请求
		req = io_alloc_req(ctx, &state);
		if (unlikely(!req)) {
			// 如果一个都没提交，则需要重新请求
			if (!submitted)
				submitted = -EAGAIN;
			break;
		}
		// 递增 ctx->cached_sq_head，cached_sq_head是内核侧用来跟踪sq环的计数器
		io_consume_sqe(ctx);
		/* will complete beyond this point, count as submitted */
		submitted++;

		// 根据sqe信息初始化req
		err = io_init_req(ctx, req, sqe, &state);
		if (unlikely(err)) {
fail_req:
			io_put_req(req);
			io_req_complete(req, err);
			break;
		}

		trace_io_uring_submit_sqe(ctx, req->opcode, req->user_data,
						true, io_async_submit(ctx));
		// 提交se
		err = io_submit_sqe(req, sqe, &link, &state.comp);
		if (err)
			goto fail_req;
	}

	if (unlikely(submitted != nr)) {
		// 已提交的与预期的不相符
		int ref_used = (submitted == -EAGAIN) ? 0 : submitted;
		struct io_uring_task *tctx = current->io_uring;
		// 未用的引用数量
		int unused = nr - ref_used;

		// 把未用的引用数量从这些计数器里取掉
		percpu_ref_put_many(&ctx->refs, unused);
		percpu_counter_sub(&tctx->inflight, unused);
		put_task_struct_many(current, unused);
	}
	if (link)
		io_queue_link_head(link, &state.comp);
	io_submit_state_end(&state);

	// 同步sq头指针
	io_commit_sqring(ctx);

	return submitted;
}
```
提交的主流程：
1. 检查溢出列表是否有完成的cqe
2. 根据需要提交的最小数量，从sq里取出一个sqe,初始化req对象,进行提交
3. 如果所提交的与期望提交的数量不相等，则修改相关引用计数
4. 同步sq队列的头指针

## state的初始化
state用来跟踪这次提交的状态.
```c
static void io_submit_state_start(struct io_submit_state *state,
				  struct io_ring_ctx *ctx, unsigned int max_ios)
{
	// 初始化进程的plug
	blk_start_plug(&state->plug);
	state->comp.nr = 0;
	INIT_LIST_HEAD(&state->comp.list);
	state->comp.ctx = ctx;
	state->free_reqs = 0;
	state->file = NULL;
	// max_ios就是要提交的数量
	state->ios_left = max_ios;
}
```

## io_get_sqe
```c
static const struct io_uring_sqe *io_get_sqe(struct io_ring_ctx *ctx)
{
	u32 *sq_array = ctx->sq_array;
	unsigned head;

	/*
	原文注释：
	 缓存的sq头（或cq尾）有两个目的：
		1）允许我们批量更新用户可见头部更新的成本。
		2）允许内核端自己跟踪头部，即使应用程序正在更新头部。
	 */
	// ctx->cached_sq_head是内核里用于跟踪sq头的指针，
	// 因为sq_array是一个环，所以要和mask相与
	head = READ_ONCE(sq_array[ctx->cached_sq_head & ctx->sq_mask]);

	// 这里表示还没到达环尾，一般情况都走这里，
	// 没到达环尾，就直接返回head对应的sqe
	if (likely(head < ctx->sq_entries))
		return &ctx->sq_sqes[head];

	// 走到这儿表示已经到达环尾
	// 丢弃无效的sq
	ctx->cached_sq_dropped++;
	WRITE_ONCE(ctx->rings->sq_dropped, ctx->cached_sq_dropped);
	return NULL;
}
```
sq队列和cq的存储不同，cq直接在cqe里存储，而sqe是通过间接的方式保存，先通过ctx->sq_array来获取sqe的下标，然后再去ctx->sq_sqes数组里找到真正的sqe。（todo: 为什么用这种方式存储，暂时还没看明白）

## 请求的分配和初始化
分配一个请求对象。
```c
static struct io_kiocb *io_alloc_req(struct io_ring_ctx *ctx,
				     struct io_submit_state *state)
{
	// free_reqs是一个struct io_kiocb数组，里面存储的是空闲的请求
	if (!state->free_reqs) { // 第一次进入或者空闲数组用完，会走这个分支
		gfp_t gfp = GFP_KERNEL | __GFP_NOWARN;
		size_t sz;
		int ret;

		// ios_left是剩余要提交的数量，reqs数组的大小是8
		sz = min_t(size_t, state->ios_left, ARRAY_SIZE(state->reqs));

		// 从req_cachep批量分配
		ret = kmem_cache_alloc_bulk(req_cachep, gfp, sz, state->reqs);

		// 如果批量分配失败，则只尝试分配一个，
		if (unlikely(ret <= 0)) {
			state->reqs[0] = kmem_cache_alloc(req_cachep, gfp);
			if (!state->reqs[0])
				// 如果连一个都分配不下，那就尝试使用fallback_req，
				// 这个是在io_uring初始化的时候就分配的
				goto fallback;
			ret = 1;
		}
		state->free_reqs = ret;
	}

	// 分配成功，或者还有没用完的req，则直接从数组里获取一个请求返回
	state->free_reqs--;
	return state->reqs[state->free_reqs];
fallback:
	return io_get_fallback_req(ctx);
}

static struct io_kiocb *io_get_fallback_req(struct io_ring_ctx *ctx)
{
	struct io_kiocb *req;

	req = ctx->fallback_req;

	// 设置fallback_req为空，如果设置成功，说明没有人用它，如果设置失败说明已经有别人在用了
	if (!test_and_set_bit_lock(0, (unsigned long *) &ctx->fallback_req))
		return req;

	// 连fallback_req都申请不到那只能返回NULL
	return NULL;
}
```
第一次分配请求空间会尝试3次：1.批量分配; 2.只分配1个; 3.尝试使用fallbackreq。如果这3种方式都分配不下那就出错了。

```c
static int io_init_req(struct io_ring_ctx *ctx, struct io_kiocb *req,
		       const struct io_uring_sqe *sqe,
		       struct io_submit_state *state)
{
	unsigned int sqe_flags;
	int id, ret;

	// 操作码
	req->opcode = READ_ONCE(sqe->opcode);
	// 用户数据
	req->user_data = READ_ONCE(sqe->user_data);
	// 异步数据
	req->async_data = NULL;
	req->file = NULL;
	// io_uring上下文
	req->ctx = ctx;
	req->flags = 0;

	// 引用先设成2，一个是提交队列引用，一个是完成队列
	refcount_set(&req->refs, 2);
	// 进程
	req->task = current;

	// 请求结果默认初始化成0
	req->result = 0;

	// 请求码错误
	if (unlikely(req->opcode >= IORING_OP_LAST))
		return -EINVAL;

	// 获取对应进程的mm失败
	if (unlikely(io_sq_thread_acquire_mm(ctx, req)))
		return -EFAULT;

	sqe_flags = READ_ONCE(sqe->flags);

	// 有非法标志
	if (unlikely(sqe_flags & ~SQE_VALID_FLAGS))
		return -EINVAL;

	// 检查上下文对io_uring是否有限制
	if (unlikely(!io_check_restriction(ctx, req, sqe_flags)))
		return -EACCES;

	// 判断当前操作是否支持buffer_select
	if ((sqe_flags & IOSQE_BUFFER_SELECT) &&
	    !io_op_defs[req->opcode].buffer_select)
		return -EOPNOTSUPP;

	id = READ_ONCE(sqe->personality);
	if (id) {
		struct io_identity *iod;

		// 从ctx里查找id对应的iod
		iod = xa_load(&ctx->personalities, id);
		if (unlikely(!iod))
			return -EINVAL;
		// 递增引用
		refcount_inc(&iod->count);

		// 初始化异步请求。这个函数只是把req->work清空，然后设置REQ_F_WORK_INITIALIZED标志
		__io_req_init_async(req);
		get_cred(iod->creds);
		req->work.identity = iod;
		req->work.flags |= IO_WQ_WORK_CREDS;
	}

	// 设置请求标志
	req->flags |= sqe_flags;

	// op请求不需要文件
	if (!io_op_defs[req->opcode].needs_file)
		return 0;

	// 获取fd对应的文件
	ret = io_req_set_file(state, req, READ_ONCE(sqe->fd));

	// 递减还要提交的请求数量
	state->ios_left--;
	return ret;
}
```
初始化的主要流程：
1. 复制sqe里的opcode, user_data等数据
2. 对opcode的正确性做校验
3. 根据操作是否需要文件，来设置相关的文件

## 真正的提交动作
io_submit_sqe主要处理链接的情况。

```c
static int io_submit_sqe(struct io_kiocb *req, const struct io_uring_sqe *sqe,
			 struct io_kiocb **link, struct io_comp_state *cs)
{
	struct io_ring_ctx *ctx = req->ctx;
	int ret;

	// link表示请求之间按顺序，第一次进来是空的
	if (*link) {
		struct io_kiocb *head = *link;

		/*
		 * Taking sequential execution of a link, draining both sides
		 * of the link also fullfils IOSQE_IO_DRAIN semantics for all
		 * requests in the link. So, it drains the head and the
		 * next after the link request. The last one is done via
		 * drain_next flag to persist the effect across calls.
		 */
		if (req->flags & REQ_F_IO_DRAIN) {
			head->flags |= REQ_F_IO_DRAIN;
			ctx->drain_next = 1;
		}
		ret = io_req_defer_prep(req, sqe);
		if (unlikely(ret)) {
			/* fail even hard links since we don't submit */
			head->flags |= REQ_F_FAIL_LINK;
			return ret;
		}
		trace_io_uring_link(ctx, req, head);
		list_add_tail(&req->link_list, &head->link_list);

		/* last request of a link, enqueue the link */
		if (!(req->flags & (REQ_F_LINK | REQ_F_HARDLINK))) {
			io_queue_link_head(head, cs);
			*link = NULL;
		}
	} else {
		// drain_next表示要跳过下一个请求，
		// 如果要跳过，则给这个请求设置相关标志.
		// 一般情况都不走这个分支
		if (unlikely(ctx->drain_next)) {
			req->flags |= REQ_F_IO_DRAIN;
			ctx->drain_next = 0;
		}

		if (req->flags & (REQ_F_LINK | REQ_F_HARDLINK)) {
			// todo: link后面再看
			req->flags |= REQ_F_LINK_HEAD;
			INIT_LIST_HEAD(&req->link_list);

			ret = io_req_defer_prep(req, sqe);
			if (unlikely(ret))
				req->flags |= REQ_F_FAIL_LINK;
			// 设置link的值
			*link = req;
		} else {
			// 一般的走这里
			io_queue_sqe(req, sqe, cs);
		}
	}

	return 0;
}
```

```c
static void io_queue_sqe(struct io_kiocb *req, const struct io_uring_sqe *sqe,
			 struct io_comp_state *cs)
{
	int ret;

	// 判断当前请求是否要被延迟处理
	ret = io_req_defer(req, sqe);
	if (ret) {
		// 如果ret不是-EIOCBQUEUED，那就是出现其它错误，
		// 直接让请求出错完成
		if (ret != -EIOCBQUEUED) {
fail_req:
			req_set_fail_links(req);
			io_put_req(req);
			io_req_complete(req, ret);
		}
	} else if (req->flags & REQ_F_FORCE_ASYNC) {
		// 异步请求
		if (!req->async_data) {
			// 准备异步数据
			ret = io_req_defer_prep(req, sqe);
			if (unlikely(ret))
				goto fail_req;
		}
		// 把请求入队列
		io_queue_async_work(req);
	} else {
		// 同步请求
		if (sqe) {
			// 调用相应的prep方法
			ret = io_req_prep(req, sqe);
			if (unlikely(ret))
				goto fail_req;
		}
		// 执行具体的请求
		__io_queue_sqe(req, cs);
	}
}


static int io_req_defer(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct io_defer_entry *de;
	int ret;
	u32 seq;

	// REQ_F_IO_DRAIN是要被排出的req
	// defer_list是被延迟请求的列表
	if (likely(list_empty_careful(&ctx->defer_list) &&
		!(req->flags & REQ_F_IO_DRAIN)))
		return 0;

	// 走到这儿，说明defer_list不为空，或者req有REQ_F_IO_DRAIN标志

	// 提交的序号，递增的
	seq = io_get_sequence(req);

	// 如果该请求不需要延迟，而且延迟列表为空
	if (!req_need_defer(req, seq) && list_empty_careful(&ctx->defer_list))
		// 走到这儿，说明req有REQ_F_IO_DRAIN标志
		return 0;

	// 走到这儿说明req需要延迟或者defer_list不为空

	// 走到这说明请求需要延迟

	// 如果没有异步数据，则分配之
	if (!req->async_data) {
		ret = io_req_defer_prep(req, sqe);
		if (ret)
			return ret;
	}
	// todo: 后面再看
	io_prep_async_link(req);

	de = kmalloc(sizeof(*de), GFP_KERNEL);
	if (!de)
		return -ENOMEM;

	spin_lock_irq(&ctx->completion_lock);
	if (!req_need_defer(req, seq) && list_empty(&ctx->defer_list)) {
		// todo: 走到这儿，说明不需要要延迟req，为什么和上面的处理不一样
		// 上面直接返回0, 而这里是加入到异步请求work
		spin_unlock_irq(&ctx->completion_lock);
		kfree(de);
		io_queue_async_work(req);
		return -EIOCBQUEUED;
	}

	trace_io_uring_defer(ctx, req, req->user_data);

	// 把请求和序号分配给de
	de->req = req;
	de->seq = seq;

	// 把de挂到延迟列表上
	list_add_tail(&de->list, &ctx->defer_list);
	spin_unlock_irq(&ctx->completion_lock);
	return -EIOCBQUEUED;
}


static u32 io_get_sequence(struct io_kiocb *req)
{
	struct io_kiocb *pos;
	struct io_ring_ctx *ctx = req->ctx;
	u32 total_submitted, nr_reqs = 1;

	// 如果当前请求是链表的头，则统计链内所有请求数
	if (req->flags & REQ_F_LINK_HEAD)
		list_for_each_entry(pos, &req->link_list, link_list)
			nr_reqs++;

	// cached_sq_head是内核消费sqe的位置
	// cached_sq_dropped是被放弃的sqe数量
	total_submitted = ctx->cached_sq_head - ctx->cached_sq_dropped;

	// 算出当前sqe的序号
	return total_submitted - nr_reqs;
}

static bool req_need_defer(struct io_kiocb *req, u32 seq)
{
	// 如果当前请求要被排出
	if (unlikely(req->flags & REQ_F_IO_DRAIN)) {
		struct io_ring_ctx *ctx = req->ctx;
		
		// cq_tail+cq_overflow是cq列表上总共的cqe数量，
		// todo: 这个判断的逻辑？？
		return seq != ctx->cached_cq_tail
				+ READ_ONCE(ctx->cached_cq_overflow);
	}

	// 不需要排出，就不延迟
	return false;
}
```
io_queue_sqe主流程：
1. 判断是否要延迟请求，如果要延迟则挂入defer_list。
2. 根据是否有异步标志，来分别处理请求


## 异步提交
```c
static int io_req_defer_prep(struct io_kiocb *req,
			     const struct io_uring_sqe *sqe)
{
	if (!sqe)
		return 0;
	// 分配异步数据
	if (io_alloc_async_data(req))
		return -EAGAIN;.
	// 调用对应操作的prep方法
	return io_req_prep(req, sqe);
}


static int io_alloc_async_data(struct io_kiocb *req)
{
	// 如果该操作不需要异步数据，则直接返回
	if (!io_op_defs[req->opcode].needs_async_data)
		return 0;

	return  __io_alloc_async_data(req);
}

static inline int __io_alloc_async_data(struct io_kiocb *req)
{
	// 如果异步数据大小为0，那为啥还要数据？
	WARN_ON_ONCE(!io_op_defs[req->opcode].async_size);
	// 分配操作对应异步数据内存
	req->async_data = kmalloc(io_op_defs[req->opcode].async_size, GFP_KERNEL);
	return req->async_data == NULL;
}

static void io_queue_async_work(struct io_kiocb *req)
{
	struct io_kiocb *link;

	// 加入队列
	link = __io_queue_async_work(req);

	// 如果link有值，则设置超时
	if (link)
		io_queue_linked_timeout(link);
}

static struct io_kiocb *__io_queue_async_work(struct io_kiocb *req)
{
	struct io_ring_ctx *ctx = req->ctx;
	// 如果链表的第一个元素的操作是IORING_OP_LINK_TIMEOUT，则这个link有值，反之没值
	// 这个link为什么要放在这个函数里，这个函数又没有用
	struct io_kiocb *link = io_prep_linked_timeout(req);

	trace_io_uring_queue_async_work(ctx, io_wq_is_hashed(&req->work), req,
					&req->work, req->flags);
	// 把work加入io_wq队列
	io_wq_enqueue(ctx->io_wq, &req->work);
	return link;
}

static struct io_kiocb *io_prep_linked_timeout(struct io_kiocb *req)
{
	struct io_kiocb *nxt;

	// 没有链接标志
	if (!(req->flags & REQ_F_LINK_HEAD))
		return NULL;
	// 有链接超时标志
	if (req->flags & REQ_F_LINK_TIMEOUT)
		return NULL;

	// 链表第一个元素
	nxt = list_first_entry_or_null(&req->link_list, struct io_kiocb,
					link_list);
	// 不是链接超时操作,直接返回
	if (!nxt || nxt->opcode != IORING_OP_LINK_TIMEOUT)
		return NULL;

	// 启用超时
	nxt->flags |= REQ_F_LTIMEOUT_ACTIVE;
	req->flags |= REQ_F_LINK_TIMEOUT;
	return nxt;
}

static void io_queue_linked_timeout(struct io_kiocb *req)
{
	struct io_ring_ctx *ctx = req->ctx;

	spin_lock_irq(&ctx->completion_lock);
	// 设置超时
	__io_queue_linked_timeout(req);
	spin_unlock_irq(&ctx->completion_lock);

	// 丢弃这个req，因为这个req只是用来做超时的
	io_put_req(req);
}

static void __io_queue_linked_timeout(struct io_kiocb *req)
{
	/*
	 * If the list is now empty, then our linked request finished before
	 * we got a chance to setup the timer
	 */
	if (!list_empty(&req->link_list)) {
		struct io_timeout_data *data = req->async_data;

		// 设置超时函数，
		data->timer.function = io_link_timeout_fn;

		// 启动计时器。
		hrtimer_start(&data->timer, timespec64_to_ktime(data->ts),
				data->mode);
	}
}
```
异步提交主要有4个流程：
1. 分配异步数据
2. 把req挂入io_wq的队列
3. 如果需要设置超时，则设置之
4. 调用对应操作的prep方法

## 同步提交
同步提交的第1步，也是调用各个操作的prep方法，然后再调用__io_queue_sqe，进行真正提交。异步任务到最后，也是调用__io_queue_sqe来执行真正的io操作。
```c
static void __io_queue_sqe(struct io_kiocb *req, struct io_comp_state *cs)
{
	struct io_kiocb *linked_timeout;
	const struct cred *old_creds = NULL;
	int ret;

again:
	// 链式请求，第1个是超时req
	linked_timeout = io_prep_linked_timeout(req);

	// 切换请求的cred ?
	if ((req->flags & REQ_F_WORK_INITIALIZED) &&
	    (req->work.flags & IO_WQ_WORK_CREDS) &&
	    req->work.identity->creds != current_cred()) {
		if (old_creds)
			revert_creds(old_creds);
		if (old_creds == req->work.identity->creds)
			old_creds = NULL; /* restored original creds */
		else
			old_creds = override_creds(req->work.identity->creds);
	}

	// 调用具体操作对应的函数，执行对应操作
	ret = io_issue_sqe(req, true, cs);

	// 如果需要重试，但是请求不允许等待，则执行异步操作
	if (ret == -EAGAIN && !(req->flags & REQ_F_NOWAIT)) {
		// 先无法执行poll
		if (!io_arm_poll_handler(req)) {
			// 如果poll执行失败，则放到异步任务队列里
			io_queue_async_work(req);
		}

		// 设置超时，如果需要的话
		if (linked_timeout)
			io_queue_linked_timeout(linked_timeout);
	} else if (likely(!ret)) {
		// put当前请求，然后再找到链式请求的下一个请求，
		// 对于一般的请求req都为NULL
		req = io_put_req_find_next(req);

		// 重新设置超时
		if (linked_timeout)
			io_queue_linked_timeout(linked_timeout);

		if (req) {
			if (!(req->flags & REQ_F_FORCE_ASYNC))
				// 如果请求不需要异步，则继续处理
				goto again;
			// 不是异步请求，就放入队列
			io_queue_async_work(req);
		}
	} else {
		// 其它情况就是出错了，就直接设置出错标志，把请求结果放入cq就行了
		req->flags &= ~REQ_F_LINK_TIMEOUT;
		// 如果有link标志，则设置REQ_F_FAIL_LINK标志
		req_set_fail_links(req);
		// 释放请求
		io_put_req(req);

		io_req_complete(req, ret);
	}

	// 还原cred
	if (old_creds)
		revert_creds(old_creds);
}
```
同步提交流程：
1. 切换cred
2. 调用具体操作的io函数
3. 执行操作失败，处理EAGAIN情况，这个情况会调用poll或者执行异步请求
4. 执行操作成功，如果是链式调用，则处理下一个请求，根据请求是异步还是同步来进行处理
5. 处理其它失败情况
6. 还原cred

## io_req_complete

```c
static void io_req_complete(struct io_kiocb *req, long res)
{
	__io_req_complete(req, res, 0, NULL);
}

static void __io_req_complete(struct io_kiocb *req, long res, unsigned cflags,
			      struct io_comp_state *cs)
{
	if (!cs) {
		io_cqring_add_event(req, res, cflags);
		// 释放请求，上面不是释放过了吗？
		io_put_req(req);
	} else {
		io_clean_op(req);
		req->result = res;
		req->compl.cflags = cflags;
		list_add_tail(&req->compl.list, &cs->list);
		if (++cs->nr >= 32)
			io_submit_flush_completions(cs);
	}
}

static void io_cqring_add_event(struct io_kiocb *req, long res, long cflags)
{
	struct io_ring_ctx *ctx = req->ctx;
	unsigned long flags;

	// 上锁完成量
	spin_lock_irqsave(&ctx->completion_lock, flags);
	__io_cqring_fill_event(req, res, cflags);
	io_commit_cqring(ctx);
	spin_unlock_irqrestore(&ctx->completion_lock, flags);

	io_cqring_ev_posted(ctx);
}

static void __io_cqring_fill_event(struct io_kiocb *req, long res,
				   unsigned int cflags)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct io_uring_cqe *cqe;

	trace_io_uring_complete(ctx, req->user_data, res);

	// 获取一个cqe
	cqe = io_get_cqring(ctx);
	if (likely(cqe)) {
		// 给cqe里设置各个数据
		WRITE_ONCE(cqe->user_data, req->user_data);
		WRITE_ONCE(cqe->res, res);
		WRITE_ONCE(cqe->flags, cflags);
	} else if (ctx->cq_overflow_flushed ||
		   atomic_read(&req->task->io_uring->in_idle)) {
		// todo: 这个条件没看懂

		// 如果获取不到cqe，则增加overflow计数
		ctx->cached_cq_overflow++;
		WRITE_ONCE(ctx->rings->cq_overflow, ctx->cached_cq_overflow);
	} else {
		// 如果当前溢出列表是空的，现在要增加一个溢出节点，所以要清空检查溢出的状态
		// 并且设置sq, cq的溢出标志
		if (list_empty(&ctx->cq_overflow_list)) {
			set_bit(0, &ctx->sq_check_overflow);
			set_bit(0, &ctx->cq_check_overflow);
			ctx->rings->sq_flags |= IORING_SQ_CQ_OVERFLOW;
		}
		// 如果需要，则清理各个操作
		io_clean_op(req);
		// 设置请求的状态和标示
		req->result = res;
		req->compl.cflags = cflags;
		// 递增引用
		refcount_inc(&req->refs);
		// 加到溢出列表
		list_add_tail(&req->compl.list, &ctx->cq_overflow_list);
	}
}

static struct io_uring_cqe *io_get_cqring(struct io_ring_ctx *ctx)
{
	struct io_rings *rings = ctx->rings;
	unsigned tail;

	// cq末尾
	tail = ctx->cached_cq_tail;
	// cq队列已经满了
	if (tail - READ_ONCE(rings->cq.head) == rings->cq_ring_entries)
		return NULL;

	// 从cqes里取出一个元素
	ctx->cached_cq_tail++;
	return &rings->cqes[tail & ctx->cq_mask];
}
```