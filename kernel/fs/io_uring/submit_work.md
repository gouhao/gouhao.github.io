# io_wq_submit_work
源码基于5.10

```c
static struct io_wq_work *io_wq_submit_work(struct io_wq_work *work)
{
	struct io_kiocb *req = container_of(work, struct io_kiocb, work);
	struct io_kiocb *timeout;
	int ret = 0;

	timeout = io_prep_linked_timeout(req);
	if (timeout)
		io_queue_linked_timeout(timeout);

	// 如果已经设置了取消标志，还是要继续工作
	if ((work->flags & (IO_WQ_WORK_CANCEL|IO_WQ_WORK_NO_CANCEL)) ==
				IO_WQ_WORK_CANCEL) {
		ret = -ECANCELED;
	}

	if (!ret) {
		do {
			// 调用具体的操作函数
			ret = io_issue_sqe(req, false, NULL);

			/*
			 * 即使我们在处理一个强制同步提交，也有可能从io-poll里获取一个EAGAIN,
			 * 我们不能等待slots, 所以直接返回
			 */
			if (ret != -EAGAIN)
				break;
			cond_resched();
		} while (1);
	}

	if (ret) {
		struct io_ring_ctx *lock_ctx = NULL;

		// io-poll
		if (req->ctx->flags & IORING_SETUP_IOPOLL)
			lock_ctx = req->ctx;

		// 只有iopoll需要加锁
		if (lock_ctx)
			mutex_lock(&lock_ctx->uring_lock);

		req_set_fail_links(req);
		io_req_complete(req, ret);

		if (lock_ctx)
			mutex_unlock(&lock_ctx->uring_lock);
	}

	return io_steal_work(req);
}
```