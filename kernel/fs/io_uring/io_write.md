# io_write
源码基于5.10

io_write里的很多流程和io_read里类似，建议先看io_read。

## io_write_prep
在调用io_write之前，会首先调用io_write_prep。
```c
static int io_write_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	ssize_t ret;

	// 主要设置了req->rw里面的数据
	ret = io_prep_rw(req, sqe);
	if (ret)
		return ret;

	// 文件不可写，那肯定不能继续了
	if (unlikely(!(req->file->f_mode & FMODE_WRITE)))
		return -EBADF;

	// 和io_read一样，如果需要的话，初始化异步数据
	if (!req->async_data)
		return 0;
	return io_rw_prep_async(req, WRITE);
}
```

## io_write
```c
static int io_write(struct io_kiocb *req, bool force_nonblock,
		    struct io_comp_state *cs)
{
	struct iovec inline_vecs[UIO_FASTIOV], *iovec = inline_vecs;
	struct kiocb *kiocb = &req->rw.kiocb;
	struct iov_iter __iter, *iter = &__iter;
	struct io_async_rw *rw = req->async_data;
	ssize_t ret, ret2, io_size;

	if (rw)
		iter = &rw->iter;

	// 这个函数在req->async_data没有初始化的时候，执行初始化。设置iov的buffer, count, 初始化iter等
	ret = io_import_iovec(WRITE, req, &iovec, iter, !force_nonblock);
	if (ret < 0)
		return ret;
	// 读写数据的数量
	io_size = iov_iter_count(iter);
	req->result = io_size;

	// 设置是否阻塞读取的标志
	if (!force_nonblock)
		kiocb->ki_flags &= ~IOCB_NOWAIT;
	else
		kiocb->ki_flags |= IOCB_NOWAIT;

	// 在强制不阻塞时，判断当前文件是否支持异步
	if (force_nonblock && !io_file_supports_async(req->file, WRITE))
		goto copy_iov;

	// 对于普通文件，强制不阻塞的，就执行异步路径
	if (force_nonblock && !(kiocb->ki_flags & IOCB_DIRECT) &&
	    (req->flags & REQ_F_ISREG))
		goto copy_iov;

	// 检查所要写的文件范围是否合法
	ret = rw_verify_area(WRITE, req->file, io_kiocb_ppos(kiocb), io_size);
	if (unlikely(ret))
		goto out_free;

	if (req->flags & REQ_F_ISREG) {
		// 对sb->s_writers.rw_sem里相应的锁加锁
		sb_start_write(file_inode(req->file)->i_sb);
		// todo: 这里再释放锁？？
		__sb_writers_release(file_inode(req->file)->i_sb,
					SB_FREEZE_WRITE);
	}
	// 设置写标志
	kiocb->ki_flags |= IOCB_WRITE;

	// 调用写接口
	if (req->file->f_op->write_iter)
		ret2 = call_write_iter(req->file, kiocb, iter);
	else if (req->file->f_op->write)
		ret2 = loop_rw_iter(WRITE, req, iter);
	else
		ret2 = -EINVAL;

	// 底层设备不支持，就重试
	if (ret2 == -EOPNOTSUPP && (kiocb->ki_flags & IOCB_NOWAIT))
		ret2 = -EAGAIN;
	// 如果是重试，但是文件不能阻塞，直接完成
	if (ret2 == -EAGAIN && (req->file->f_flags & O_NONBLOCK))
		goto done;

	// 可以阻塞，但是错误不是重试
	if (!force_nonblock || ret2 != -EAGAIN) {
		// 如果是iopoll模式，则执行异步清求
		if ((req->ctx->flags & IORING_SETUP_IOPOLL) && ret2 == -EAGAIN)
			goto copy_iov;
done:
		// 其它情况就直接调用完成
		kiocb_done(kiocb, ret2, cs);
	} else {
copy_iov:
		// 先把iov里的数据还原
		iov_iter_revert(iter, io_size - iov_iter_count(iter));
		// 设置异步读写
		ret = io_setup_async_rw(req, iovec, inline_vecs, iter, false);
		if (!ret)
			return -EAGAIN;
	}
out_free:
	/* it's reportedly faster than delegating the null check to kfree() */
	if (iovec)
		kfree(iovec);
	return ret;
}
```

