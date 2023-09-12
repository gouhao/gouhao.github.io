## io_uring_enter
源码基于5.10

```c
SYSCALL_DEFINE6(io_uring_enter, unsigned int, fd, u32, to_submit,
		u32, min_complete, u32, flags, const sigset_t __user *, sig,
		size_t, sigsz)
{
	struct io_ring_ctx *ctx;
	long ret = -EBADF;
	int submitted = 0;
	struct fd f;

	// 运行task->task_works里的work，如果有的话
	io_run_task_work();

	/* enter只支持这3种操作:
	IORING_ENTER_GETEVENTS: 获取完成的事件
	IORING_ENTER_SQ_WAKEUP： 唤醒线程
	IORING_ENTER_SQ_WAIT： 等待完成队列
	*/
	if (flags & ~(IORING_ENTER_GETEVENTS | IORING_ENTER_SQ_WAKEUP |
			IORING_ENTER_SQ_WAIT))
		return -EINVAL;

	// 获取fd对应的文件
	f = fdget(fd);
	if (!f.file)
		return -EBADF;

	// 文件的操作表不是io_uring_fops，那肯定出错了
	ret = -EOPNOTSUPP;
	if (f.file->f_op != &io_uring_fops)
		goto out_fput;

	ret = -ENXIO;
	// 获取上下文，这个fd的主要作用就是用来获取上下文
	ctx = f.file->private_data;
	if (!percpu_ref_tryget(&ctx->refs))
		goto out_fput;

	// 还有io_workqueue没有启动
	ret = -EBADFD;
	if (ctx->flags & IORING_SETUP_R_DISABLED)
		goto out;

	ret = 0;
	if (ctx->flags & IORING_SETUP_SQPOLL) {
		// SQPOLL模式

		// 刷出cq的溢出列表
		io_cqring_overflow_flush(ctx, false, NULL, NULL);

		// 创建io_uring的进程已死
		if (unlikely(ctx->sqo_dead)) {
			ret = -EOWNERDEAD;
			goto out;
		}

		// 唤醒poll线程，poll线程在提交队列为空的时候，会在sq_data->wait上等待
		if (flags & IORING_ENTER_SQ_WAKEUP)
			wake_up(&ctx->sq_data->wait);

		// 这个标志是等待sq有空闲的sqe
		if (flags & IORING_ENTER_SQ_WAIT) {
			ret = io_sqpoll_wait_sq(ctx);
			if (ret)
				goto out;
		}

		// poll模式下由内核线程处理，相当于全部提交
		submitted = to_submit;
	} else if (to_submit) {
		// 一般情况

		// 如果没添加的话，把文件添加到current->io_uring里
		ret = io_uring_add_task_file(ctx, f.file);
		if (unlikely(ret))
			goto out;
		
		// 提交请求期间要用uring_lock
		mutex_lock(&ctx->uring_lock);
		// 提交to_submit个文件请求
		submitted = io_submit_sqes(ctx, to_submit);
		mutex_unlock(&ctx->uring_lock);

		// 已经提交的和需要提交的数量不一致
		if (submitted != to_submit)
			goto out;
	}
	// 需要获取结果
	if (flags & IORING_ENTER_GETEVENTS) {
		// 最小完成数量是需要的数量和cq长度的较小值
		min_complete = min(min_complete, ctx->cq_entries);

		if (ctx->flags & IORING_SETUP_IOPOLL &&
		    !(ctx->flags & IORING_SETUP_SQPOLL)) {
			// 等待io poll完成
			ret = io_iopoll_check(ctx, min_complete);
		} else {
			// 如果不是io_poll就等待min_complete个任务完成，一般走这个
			ret = io_cqring_wait(ctx, min_complete, sig, sigsz);
		}
	}

out:
	percpu_ref_put(&ctx->refs);
out_fput:
	fdput(f);

	// 有提交的就返回提交的数量，没有提交的就返回错误码
	return submitted ? submitted : ret;
}
```
io_uring_enter的主流程:
1. 根据传入的fd获取对应的文件,从文件里要取出io_uring的上下文
2. 提交sqe.如果是sqpoll模式那只需唤醒相应的worker线程就可以;如果是普通模式,就直接提交sq里的sqe
3. 如果需要等待特定数量的任务完成,那就等待

提交sqe流程在另一篇文章里单独写。

## 非io_poll模式下等待完成结果
如果不是iopoll模式启动的io_uring,那就走io_cqring_wait,这个函数主要是等io worker的执行完成:
```c
static int io_cqring_wait(struct io_ring_ctx *ctx, int min_events,
			  const sigset_t __user *sig, size_t sigsz)
{
	struct io_wait_queue iowq = {
		.wq = {
			.private	= current,
			.func		= io_wake_function,
			.entry		= LIST_HEAD_INIT(iowq.wq.entry),
		},
		.ctx		= ctx,
		.to_wait	= min_events, // 最小等待数量
	};
	struct io_rings *rings = ctx->rings;
	int ret = 0;

	do {
		// 刷出cq的溢出
		io_cqring_overflow_flush(ctx, false, NULL, NULL);

		// 已经完成的cqe大于需要的数量
		if (io_cqring_events(ctx) >= min_events)
			return 0;
		// 运行task work，如果没有task work则退出循环
		if (!io_run_task_work())
			break;
	} while (1);

	// 经过上面的循环，要不已经达到 min_events，要不已经运行完了所有的task work

	// 处理 sig, 设置用户设置的信号
	if (sig) {
#ifdef CONFIG_COMPAT
		if (in_compat_syscall())
			ret = set_compat_user_sigmask((const compat_sigset_t __user *)sig,
						      sigsz);
		else
#endif
			ret = set_user_sigmask(sig, sigsz);

		if (ret)
			return ret;
	}

	// 超时时间
	iowq.nr_timeouts = atomic_read(&ctx->cq_timeouts);
	trace_io_uring_cqring_wait(ctx, min_events);
	do {
		io_cqring_overflow_flush(ctx, false, NULL, NULL);

		// 在ctx->wait上等待,每完成一个cqe就会唤醒ctx->wait
		prepare_to_wait_exclusive(&ctx->wait, &iowq.wq,
						TASK_INTERRUPTIBLE);

		// 到这里是被唤醒后

		// 这个函数返回0就表示,没有其他任务或者信号要处理
		ret = io_run_task_work_sig();

		// 大于0表示有进程work正在运行
		if (ret > 0) {
			finish_wait(&ctx->wait, &iowq.wq);
			continue;
		}
		else if (ret < 0)
		// 小于0，表示出错
			break;

		// 检查已经完成的数量大于需要的数量，或者已经超时
		if (io_should_wake(&iowq))
			break;

		// 不需要检查溢出
		if (test_bit(0, &ctx->cq_check_overflow)) {
			finish_wait(&ctx->wait, &iowq.wq);
			continue;
		}

		// 让出cpu
		schedule();
	} while (1);
	finish_wait(&ctx->wait, &iowq.wq);

	restore_saved_sigmask_unless(ret == -EINTR);

	// head == tail 就表示队列为空
	return READ_ONCE(rings->cq.head) == READ_ONCE(rings->cq.tail) ? ret : 0;
}

static int io_run_task_work_sig(void)
{
	// 运行进程的work
	if (io_run_task_work())
		return 1;

	// 没有要处理的信号
	if (!signal_pending(current))
		return 0;

	// JOB控制相关?
	if (current->jobctl & JOBCTL_TASK_WORK) {
		spin_lock_irq(&current->sighand->siglock);
		current->jobctl &= ~JOBCTL_TASK_WORK;
		recalc_sigpending();
		spin_unlock_irq(&current->sighand->siglock);
		return 1;
	}
	return -EINTR;
}

static inline bool io_should_wake(struct io_wait_queue *iowq)
{
	struct io_ring_ctx *ctx = iowq->ctx;

	// io_cqring_events是获取已经完成的cqe数量,如果已完成的数量达到了需要的数量就不用再等了
	// cq_timeouts是在iowq等待之前就记录的超时时间,如果这2个超时时间不相等,说明已经超时了,
	// 因为io woker在超时之后会更新这个时间
	return io_cqring_events(ctx) >= iowq->to_wait ||
			atomic_read(&ctx->cq_timeouts) != iowq->nr_timeouts;
}
```
一般等待的流程:
1. 刷出在溢出列表上的cqe.如果cq队列满了,但是还有完成的cqe,这时会把cqe先放到一个临时的溢出列表,等到有空闲的cqe时,再把溢出列表里完成的请求放到cq队列,如果溢出列表的数量已经达到了需求,就不用等待了.
2. 处理信号相关
3. 等待io worker处理异步任务完成,直到需要的数量

## io poll等待
```c
static int io_iopoll_check(struct io_ring_ctx *ctx, long min)
{
	unsigned int nr_events = 0;
	int iters = 0, ret = 0;

	mutex_lock(&ctx->uring_lock);
	do {
		// 如果溢出列表里元素，则把溢出元素刷出到完成队列里
		if (test_bit(0, &ctx->cq_check_overflow))
			__io_cqring_overflow_flush(ctx, false, NULL, NULL);

		// 有完成的cqe
		if (io_cqring_events(ctx))
			break;

		// 走到这儿说明没有完成的cqe

		// 如果循环了7次的倍数，然后运行进程的work?
		if (!(++iters & 7)) {
			mutex_unlock(&ctx->uring_lock);
			io_run_task_work();
			mutex_lock(&ctx->uring_lock);
		}

		// 处理io poll,等待min个cqe完成
		ret = io_iopoll_getevents(ctx, &nr_events, min);
		if (ret <= 0)
			break;
		ret = 0;
	// 循环条件：min不为0, nr_events为0, 不需要调度
	} while (min && !nr_events && !need_resched());

	mutex_unlock(&ctx->uring_lock);
	return ret;
}
```
io-poll的等待也很简单:
1. 先把溢出列表刷出到完成列表
2. 如果没有完成的cqe,就处理io-poll,直到有完成的cqe

##
```c
static int io_iopoll_getevents(struct io_ring_ctx *ctx, unsigned int *nr_events,
				long min)
{
	// iopoll_list不为空，也不需要调度
	while (!list_empty(&ctx->iopoll_list) && !need_resched()) {
		int ret;

		ret = io_do_iopoll(ctx, nr_events, min);
		// 出错，直接返回
		if (ret < 0)
			return ret;
		// 必须要等到min个io完成，返回0表示完成
		if (*nr_events >= min)
			return 0;
	}

	return 1;
}

static int io_do_iopoll(struct io_ring_ctx *ctx, unsigned int *nr_events,
			long min)
{
	struct io_kiocb *req, *tmp;
	LIST_HEAD(done);
	bool spin;
	int ret;

	/*
	 * Only spin for completions if we don't have multiple devices hanging
	 * off our complete list, and we're under the requested amount.
	 */
	spin = !ctx->poll_multi_file && *nr_events < min;

	ret = 0;
	// 遍历io_poll列表，取出请求
	list_for_each_entry_safe(req, tmp, &ctx->iopoll_list, inflight_entry) {
		struct kiocb *kiocb = &req->rw.kiocb;

		// 请求已经完成，移到done列表
		if (READ_ONCE(req->iopoll_completed)) {
			list_move_tail(&req->inflight_entry, &done);
			continue;
		}

		// 走到这儿说明请求没完成

		// done列表不为空，退出循环？
		if (!list_empty(&done))
			break;

		// 调用具体文件系统的iopoll接口
		ret = kiocb->ki_filp->f_op->iopoll(kiocb, spin);
		// 出错返回
		if (ret < 0)
			break;

		// 调用完iopoll，再检查一遍
		if (READ_ONCE(req->iopoll_completed))
			list_move_tail(&req->inflight_entry, &done);

		// 如果iopoll返回成功，则置spin为tr
		if (ret && spin)
			spin = false;
		
		// 重置ret
		ret = 0;
	}

	if (!list_empty(&done))
		io_iopoll_complete(ctx, nr_events, &done);

	return ret;
}

static void io_iopoll_complete(struct io_ring_ctx *ctx, unsigned int *nr_events,
			       struct list_head *done)
{
	struct req_batch rb;
	struct io_kiocb *req;
	LIST_HEAD(again);

	/* order with ->result store in io_complete_rw_iopoll() */
	smp_rmb();

	// 把rb里的成员设为0
	io_init_req_batch(&rb);

	// 遍历done列表
	while (!list_empty(done)) {
		int cflags = 0;

		// 取出请求
		req = list_first_entry(done, struct io_kiocb, inflight_entry);

		// 如果请求的结果是重试，重置结果和完成状态，再次加到again末尾
		if (READ_ONCE(req->result) == -EAGAIN) {
			req->result = 0;
			req->iopoll_completed = 0;
			list_move_tail(&req->inflight_entry, &again);
			continue;
		}
		// 先把元素从done列表删除
		list_del(&req->inflight_entry);

		// 选择了buffer，先释放。todo:?
		if (req->flags & REQ_F_BUFFER_SELECTED)
			cflags = io_put_rw_kbuf(req);

		// 把请求结果插到完成队列
		__io_cqring_fill_event(req, req->result, cflags);

		(*nr_events)++;

		// 如果请求没人再引用，则加到批量释放里
		if (refcount_dec_and_test(&req->refs))
			io_req_free_batch(&rb, req);
	}

	// 处理cq的完成流程
	io_commit_cqring(ctx);

	// 如果是sqpoll，则唤醒一些等待队列
	if (ctx->flags & IORING_SETUP_SQPOLL)
		io_cqring_ev_posted(ctx);
	
	// 释放批量释放列表里的请求
	io_req_free_batch_finish(ctx, &rb);

	// 如果重试列表不为空，则把重试列表里的元素再次加到iopoll列表里
	if (!list_empty(&again))
		io_iopoll_queue(&again);
}

static void io_iopoll_queue(struct list_head *again)
{
	struct io_kiocb *req;

	do {
		req = list_first_entry(again, struct io_kiocb, inflight_entry);
		// 先把请求从飞行列表里删掉
		list_del(&req->inflight_entry);
		__io_complete_rw(req, -EAGAIN, 0, NULL);
	} while (!list_empty(again));
}

static void __io_complete_rw(struct io_kiocb *req, long res, long res2,
			     struct io_comp_state *cs)
{
	// 重新提交请求
	if (!io_rw_reissue(req, res))
		// 如果失败了，就直接完成
		io_complete_rw_common(&req->rw.kiocb, res, cs);
}

static bool io_rw_reissue(struct io_kiocb *req, long res)
{
#ifdef CONFIG_BLOCK
	umode_t mode = file_inode(req->file)->i_mode;
	int ret;

	if (!S_ISBLK(mode) && !S_ISREG(mode))
		return false;
	if ((res != -EAGAIN && res != -EOPNOTSUPP) || io_wq_current_is_worker())
		return false;
	/*
	 * If ref is dying, we might be running poll reap from the exit work.
	 * Don't attempt to reissue from that path, just let it fail with
	 * -EAGAIN.
	 */
	if (percpu_ref_is_dying(&req->ctx->refs))
		return false;

	ret = io_sq_thread_acquire_mm(req->ctx, req);

	if (io_resubmit_prep(req, ret)) {
		refcount_inc(&req->refs);
		io_queue_async_work(req);
		return true;
	}

#endif
	return false;
}

static void io_complete_rw_common(struct kiocb *kiocb, long res,
				  struct io_comp_state *cs)
{
	struct io_kiocb *req = container_of(kiocb, struct io_kiocb, rw.kiocb);
	int cflags = 0;

	if (kiocb->ki_flags & IOCB_WRITE)
		kiocb_end_write(req);

	if (res != req->result)
		req_set_fail_links(req);
	if (req->flags & REQ_F_BUFFER_SELECTED)
		cflags = io_put_rw_kbuf(req);
	__io_req_complete(req, res, cflags, cs);
}
```
## 刷新溢出列表
```c
static void io_cqring_overflow_flush(struct io_ring_ctx *ctx, bool force,
				     struct task_struct *tsk,
				     struct files_struct *files)
{
	// cq_check_overflow是一个标志，它的第0位表示是否已经溢出
	if (test_bit(0, &ctx->cq_check_overflow)) {
		if (ctx->flags & IORING_SETUP_IOPOLL)
			// iopoll需要单独加锁
			mutex_lock(&ctx->uring_lock);
		// 刷出cq的溢出
		__io_cqring_overflow_flush(ctx, force, tsk, files);
		if (ctx->flags & IORING_SETUP_IOPOLL)
			mutex_unlock(&ctx->uring_lock);
	}
}

static bool __io_cqring_overflow_flush(struct io_ring_ctx *ctx, bool force,
				       struct task_struct *tsk,
				       struct files_struct *files)
{
	struct io_rings *rings = ctx->rings;
	struct io_kiocb *req, *tmp;
	struct io_uring_cqe *cqe;
	unsigned long flags;
	LIST_HEAD(list);

	// 非强制刷新
	if (!force) {
		// 完成队列已经满了，就直接返回false
		if ((ctx->cached_cq_tail - READ_ONCE(rings->cq.head) ==
		    rings->cq_ring_entries))
			return false;
	}

	spin_lock_irqsave(&ctx->completion_lock, flags);

	cqe = NULL;

	// 遍历溢出列表
	list_for_each_entry_safe(req, tmp, &ctx->cq_overflow_list, compl.list) {
		// 先判断req是不是当前文件的
		if (!io_match_task(req, tsk, files))
			continue;

		// 获取一个cqe
		cqe = io_get_cqring(ctx);

		// cqe为空，说明完成队列已满，如果不是强制刷新，就直接退出循环
		if (!cqe && !force)
			break;
		// 把请求移动到临时列表
		list_move(&req->compl.list, &list);
		if (cqe) {
			// 把溢出列表的一个元素的值放到cqe里
			WRITE_ONCE(cqe->user_data, req->user_data);
			WRITE_ONCE(cqe->res, req->result);
			WRITE_ONCE(cqe->flags, req->compl.cflags);
		} else {
			// 如果没有cqe了,又是强制刷新,那就是放弃这个完成结果了。
			// 只是增加溢出计数器
			ctx->cached_cq_overflow++;
			// 把两个溢出计数器进行同步
			WRITE_ONCE(ctx->rings->cq_overflow,
				   ctx->cached_cq_overflow);
		}
	}

	// 完成cqring的提交
	io_commit_cqring(ctx);

	// 如果溢出列表为空的话,清除sq, cq的溢出标志
	io_cqring_mark_overflow(ctx);

	spin_unlock_irqrestore(&ctx->completion_lock, flags);

	// 唤醒在cq_wait, sq_data->wait, ctx->waitt上等待的人，
	// 还要发送一个event事件
	io_cqring_ev_posted(ctx);

	// list里保存的是上面从溢出列表里取出的元素，如果这个列表不为空，
	// 需要释放里面的req，因为req的结果已经被放到cqe里了，或者强制刷新已被放弃
	while (!list_empty(&list)) {
		req = list_first_entry(&list, struct io_kiocb, compl.list);
		list_del(&req->compl.list);
		io_put_req(req);
	}

	// cqe不等于NULL,说明cq队列有空闲，也就是说overflow列表里没有溢出的cqe
	return cqe != NULL;
}

static void io_commit_cqring(struct io_ring_ctx *ctx)
{
	// todo: 没太看懂，刷出超时的？
	io_flush_timeouts(ctx);
	// 把cached_cq_tail的值更新到cq_tail里
	__io_commit_cqring(ctx);

	// 如果延迟列表不为空，把延迟列表里的加到wq队列
	if (unlikely(!list_empty(&ctx->defer_list)))
		__io_queue_deferred(ctx);
}

static void io_flush_timeouts(struct io_ring_ctx *ctx)
{
	u32 seq;

	if (list_empty(&ctx->timeout_list))
		return;

	seq = ctx->cached_cq_tail - atomic_read(&ctx->cq_timeouts);

	do {
		u32 events_needed, events_got;
		struct io_kiocb *req = list_first_entry(&ctx->timeout_list,
						struct io_kiocb, timeout.list);

		if (io_is_timeout_noseq(req))
			break;

		/*
		 * Since seq can easily wrap around over time, subtract
		 * the last seq at which timeouts were flushed before comparing.
		 * Assuming not more than 2^31-1 events have happened since,
		 * these subtractions won't have wrapped, so we can check if
		 * target is in [last_seq, current_seq] by comparing the two.
		 */
		events_needed = req->timeout.target_seq - ctx->cq_last_tm_flush;
		events_got = seq - ctx->cq_last_tm_flush;
		if (events_got < events_needed)
			break;

		list_del_init(&req->timeout.list);
		io_kill_timeout(req, 0);
	} while (!list_empty(&ctx->timeout_list));

	ctx->cq_last_tm_flush = seq;
}

static void io_cqring_ev_posted(struct io_ring_ctx *ctx)
{
	// 有在cq_wait上等待的，唤醒cq_wait，并发送SIGIO信号
	if (wq_has_sleeper(&ctx->cq_wait)) {
		wake_up_interruptible(&ctx->cq_wait);
		kill_fasync(&ctx->cq_fasync, SIGIO, POLL_IN);
	}
	// 唤醒ctx->wait
	if (waitqueue_active(&ctx->wait))
		wake_up(&ctx->wait);

	// 唤醒sq_data->wait
	if (ctx->sq_data && waitqueue_active(&ctx->sq_data->wait))
		wake_up(&ctx->sq_data->wait);

	// 给eventfd发信号?
	if (io_should_trigger_evfd(ctx))
		eventfd_signal(ctx->cq_ev_fd, 1);
}
```