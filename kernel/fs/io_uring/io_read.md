# io_read
源码基于5.10

## io_read_prep
在调用io_read之前，会首先调用io_read_prep。
```c
static int io_read_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	ssize_t ret;

	// 主要设置了req->rw里面的数据
	ret = io_prep_rw(req, sqe);
	if (ret)
		return ret;

	// 文件没有读权限，直接退出
	if (unlikely(!(req->file->f_mode & FMODE_READ)))
		return -EBADF;

	// 没有异步数据，直接返回
	if (!req->async_data)
		return 0;
	// 如果有异步数据，还要调用异步数据的准备函数
	return io_rw_prep_async(req, READ);
}

static int io_prep_rw(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct kiocb *kiocb = &req->rw.kiocb;
	unsigned ioprio;
	int ret;

	// 普通文件
	if (S_ISREG(file_inode(req->file)->i_mode))
		req->flags |= REQ_F_ISREG;

	// 文件偏移
	kiocb->ki_pos = READ_ONCE(sqe->off);
	// 没有指定pos，并且不是FMODE_STREAM文件时，把offset设置为文件当前的offset
	if (kiocb->ki_pos == -1 && !(req->file->f_mode & FMODE_STREAM)) {
		req->flags |= REQ_F_CUR_POS;
		kiocb->ki_pos = req->file->f_pos;
	}
	kiocb->ki_hint = ki_hint_validate(file_write_hint(kiocb->ki_filp));
	// 把O_***开头的flag，转换成IOCB_***
	kiocb->ki_flags = iocb_flags(kiocb->ki_filp);
	// 设置读写方向相关的标志
	ret = kiocb_set_rw_flags(kiocb, READ_ONCE(sqe->rw_flags));
	if (unlikely(ret))
		return ret;
	// io优先级？
	ioprio = READ_ONCE(sqe->ioprio);
	if (ioprio) {
		// 用户自指定优先级
		
		// 检查权限
		ret = ioprio_check_cap(ioprio);
		if (ret)
			return ret;

		kiocb->ki_ioprio = ioprio;
	} else
		// 一般都走这个分支
		kiocb->ki_ioprio = get_current_ioprio();

	// 设置等等待标志
	if (kiocb->ki_flags & IOCB_NOWAIT)
		req->flags |= REQ_F_NOWAIT;

	if (ctx->flags & IORING_SETUP_IOPOLL) {
		// io-poll 模式

		// io-poll只支持derect，并且文件要支持iopoll接口
		if (!(kiocb->ki_flags & IOCB_DIRECT) ||
		    !kiocb->ki_filp->f_op->iopoll)
			return -EOPNOTSUPP;

		kiocb->ki_flags |= IOCB_HIPRI;
		// io完成成调用的函数
		kiocb->ki_complete = io_complete_rw_iopoll;
		req->iopoll_completed = 0;
	} else {
		// 一般都走这个

		// 在非iopoll模式下，不能有IOCB_HIPRI
		if (kiocb->ki_flags & IOCB_HIPRI)
			return -EINVAL;
		kiocb->ki_complete = io_complete_rw;
	}

	// addr是用户空间的buffer地址
	req->rw.addr = READ_ONCE(sqe->addr);
	// 读写长度
	req->rw.len = READ_ONCE(sqe->len);
	// buffer的下标
	req->buf_index = READ_ONCE(sqe->buf_index);
	return 0;
}

static inline int io_rw_prep_async(struct io_kiocb *req, int rw)
{
	struct io_async_rw *iorw = req->async_data;
	struct iovec *iov = iorw->fast_iov;
	ssize_t ret;

	// 设置iov的buffer, count, 初始化iter等
	ret = __io_import_iovec(rw, req, &iov, &iorw->iter, false);
	if (unlikely(ret < 0))
		return ret;

	// 完成的数据
	iorw->bytes_done = 0;

	// read/write情况下，iov一般返回是空
	iorw->free_iovec = iov;
	// 如果这个值不空的话，需要清理
	if (iov)
		req->flags |= REQ_F_NEED_CLEANUP;
	return 0;
}
```

```c
static int io_read(struct io_kiocb *req, bool force_nonblock,
		   struct io_comp_state *cs)
{
	struct iovec inline_vecs[UIO_FASTIOV], *iovec = inline_vecs;
	struct kiocb *kiocb = &req->rw.kiocb;
	struct iov_iter __iter, *iter = &__iter;
	struct iov_iter iter_cp;
	struct io_async_rw *rw = req->async_data;
	ssize_t io_size, ret, ret2;
	bool no_async;

	// 异步？
	if (rw)
		iter = &rw->iter;


	// 这个函数在req->async_data没有初始化的时候，执行初始化。设置iov的buffer, count, 初始化iter等
	ret = io_import_iovec(READ, req, &iovec, iter, !force_nonblock);
	if (ret < 0)
		return ret;
	iter_cp = *iter;
	// 读写数据的数量
	io_size = iov_iter_count(iter);
	req->result = io_size;
	ret = 0;

	// 设置是否阻塞读取的标志
	if (!force_nonblock)
		kiocb->ki_flags &= ~IOCB_NOWAIT;
	else
		kiocb->ki_flags |= IOCB_NOWAIT;


	// 在强制不阻塞时，判断当前文件是否支持异步
	no_async = force_nonblock && !io_file_supports_async(req->file, READ);
	if (no_async)
		goto copy_iov;

	// 检查所要读取的文件范围是否合法
	ret = rw_verify_area(READ, req->file, io_kiocb_ppos(kiocb), io_size);
	if (unlikely(ret))
		goto out_free;

	// 调用文件的读接口
	ret = io_iter_do_read(req, iter);

	if (!ret) {
		// 读取成功
		goto done;
	} else if (ret == -EIOCBQUEUED) {
		// 请求已入队
		ret = 0;
		goto out_free;
	} else if (ret == -EAGAIN) {
		// 阻塞调用，而且不是io_poll模式，直接完成？
		if (!force_nonblock && !(req->ctx->flags & IORING_SETUP_IOPOLL))
			goto done;
		// 文件本身要求不阻塞，直接完成
		if (req->file->f_flags & O_NONBLOCK)
			goto done;

		// 走到这儿表示可以重试
		// 此时迭代器里的状态可能不对了，所以要重置迭代器
		*iter = iter_cp;
		ret = 0;
		
		goto copy_iov;
	} else if (ret < 0) {
		// 其它情况直接done
		goto done;
	}

	/* read it all, or we did blocking attempt. no retry. */
	if (!iov_iter_count(iter) || !force_nonblock ||
	    (req->file->f_flags & O_NONBLOCK) || !(req->flags & REQ_F_ISREG))
		goto done;

	io_size -= ret;
copy_iov:
	// 设置异步读写所需的数据？
	ret2 = io_setup_async_rw(req, iovec, inline_vecs, iter, true);
	if (ret2) {
		ret = ret2;
		goto out_free;
	}

	// 文件不支持异步读，直接返回
	if (no_async)
		return -EAGAIN;
	rw = req->async_data;
	/* it's copied and will be cleaned with ->io */
	iovec = NULL;
	/* now use our persistent iterator, if we aren't already */
	iter = &rw->iter;
retry:
	// 加上已经完成的数量
	rw->bytes_done += ret;
	
	// 检查是否不支持重试
	if (!io_rw_should_retry(req)) {
		kiocb->ki_flags &= ~IOCB_WAITQ;
		return -EAGAIN;
	}

	// 重新再读一次
	ret = io_iter_do_read(req, iter);
	if (ret == -EIOCBQUEUED) {
		// 已入队，就返回
		ret = 0;
		goto out_free;
	} else if (ret > 0 && ret < io_size) {
		// 这个分支表示没有读够，那就继续读
		kiocb->ki_flags &= ~IOCB_WAITQ;
		goto retry;
	}
done:
	// 设置迭代器完成
	kiocb_done(kiocb, ret, cs);
	ret = 0;
out_free:
	if (iovec)
		kfree(iovec);
	return ret;
}

static bool io_file_supports_async(struct file *file, int rw)
{
	umode_t mode = file_inode(file)->i_mode;

	// 如果是块设备，需要块设备支持不等待
	if (S_ISBLK(mode)) {
		if (io_bdev_nowait(file->f_inode->i_bdev))
			return true;
		return false;
	}
	// socket一直支持异步
	if (S_ISSOCK(mode))
		return true;
	
	// 普通文件时，除非所在的块设备支持不等待或者是io_uring文件支持异步，
	// 其他情况都不支持异步
	if (S_ISREG(mode)) {
		if (io_bdev_nowait(file->f_inode->i_sb->s_bdev) &&
		    file->f_op != &io_uring_fops)
			return true;
		return false;
	}

	// 文件以不阻塞的方式打开，肯定支持异步
	if (file->f_flags & O_NONBLOCK)
		return true;

	// 文件模式不是不等待的也不支持异步
	if (!(file->f_mode & FMODE_NOWAIT))
		return false;

	// 支持异步，必须实现read/write_iter
	if (rw == READ)
		return file->f_op->read_iter != NULL;

	return file->f_op->write_iter != NULL;
}

static int io_setup_async_rw(struct io_kiocb *req, const struct iovec *iovec,
			     const struct iovec *fast_iov,
			     struct iov_iter *iter, bool force)
{
	// 不是强制，而且操作本身不需要异步数据，直接返回
	if (!force && !io_op_defs[req->opcode].needs_async_data)
		return 0;
	// 没有异步数据，然后分配
	if (!req->async_data) {
		if (__io_alloc_async_data(req))
			return -ENOMEM;

		io_req_map_rw(req, iovec, fast_iov, iter);
	}
	return 0;
}

static bool io_rw_should_retry(struct io_kiocb *req)
{
	struct io_async_rw *rw = req->async_data;
	struct wait_page_queue *wait = &rw->wpq;
	struct kiocb *kiocb = &req->rw.kiocb;

	// 不等待的，不能重试
	if (req->flags & REQ_F_NOWAIT)
		return false;

	// 对于dio也不重试，只针对buffed-io
	if (kiocb->ki_flags & (IOCB_DIRECT | IOCB_HIPRI))
		return false;

	// 文件支持poll时，不用重试，用poll就够了
	// 文件不支持异步缓冲读时，也不能重试
	if (file_can_poll(req->file) || !(req->file->f_mode & FMODE_BUF_RASYNC))
		return false;

	// 设置等待的回调函数
	wait->wait.func = io_async_buf_func;
	// 私有数据
	wait->wait.private = req;
	wait->wait.flags = 0;
	INIT_LIST_HEAD(&wait->wait.entry);
	// IOCB_WAITQ表示waitq可用
	kiocb->ki_flags |= IOCB_WAITQ;
	// 去除不等待标志。这里已经等待了
	kiocb->ki_flags &= ~IOCB_NOWAIT;
	kiocb->ki_waitq = wait;
	return true;
}

static void kiocb_done(struct kiocb *kiocb, ssize_t ret,
		       struct io_comp_state *cs)
{
	struct io_kiocb *req = container_of(kiocb, struct io_kiocb, rw.kiocb);
	struct io_async_rw *io = req->async_data;

	/* add previously done IO, if any */
	if (io && io->bytes_done > 0) {
		if (ret < 0)
			ret = io->bytes_done;
		else
			ret += io->bytes_done;
	}

	if (req->flags & REQ_F_CUR_POS)
		req->file->f_pos = kiocb->ki_pos;
	if (ret >= 0 && kiocb->ki_complete == io_complete_rw)
		__io_complete_rw(req, ret, 0, cs);
	else
		io_rw_done(kiocb, ret);
}
```