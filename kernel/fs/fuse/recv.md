# fusefs接收应答
这里以/dev/fuse的write接口为例，用户层通过write接口给内核传递应答。
```c
static ssize_t fuse_dev_write(struct kiocb *iocb, struct iov_iter *from)
{
	struct fuse_copy_state cs;
	struct fuse_dev *fud = fuse_get_dev(iocb->ki_filp);

	// 这个函数和fuse_dev_read做的工作差不多。

	if (!fud)
		return -EPERM;

	if (!iter_is_iovec(from))
		return -EINVAL;

	fuse_copy_init(&cs, 0, from);

	return fuse_dev_do_write(fud, &cs, iov_iter_count(from));
}


struct fuse_out_header {
	uint32_t	len;
	int32_t		error;
	uint64_t	unique;
};

static ssize_t fuse_dev_do_write(struct fuse_dev *fud,
				 struct fuse_copy_state *cs, size_t nbytes)
{
	int err;
	struct fuse_conn *fc = fud->fc;
	struct fuse_pqueue *fpq = &fud->pq;
	struct fuse_req *req;
	struct fuse_out_header oh;

	err = -EINVAL;
	if (nbytes < sizeof(struct fuse_out_header))
		goto out;

	// 先把出参头读出来
	err = fuse_copy_one(cs, &oh, sizeof(oh));
	if (err)
		goto copy_finish;

	// 想写的数据量与出参头里的数据量不同
	err = -EINVAL;
	if (oh.len != nbytes)
		goto copy_finish;

	/*
	 * 原文注释：unique为0表示未经允许的请求，error里有错误码
	 */
	if (!oh.unique) {
		err = fuse_notify(fc, oh.error, nbytes - sizeof(oh), cs);
		goto out;
	}

	err = -EINVAL;

	// 错误码的范围是 [-512,0)
	if (oh.error <= -512 || oh.error > 0)
		goto copy_finish;

	spin_lock(&fpq->lock);
	req = NULL;
	if (fpq->connected)
		// 根据unique号找到原始请求
		// FUSE_INT_REQ_BIT是1
		req = request_find(fpq, oh.unique & ~FUSE_INT_REQ_BIT);

	// 没找到请求
	err = -ENOENT;
	if (!req) {
		spin_unlock(&fpq->lock);
		goto copy_finish;
	}

	// 是一个中断请求，有错误则处理之，没错误就处理完成
	if (oh.unique & FUSE_INT_REQ_BIT) {
		__fuse_get_request(req);
		spin_unlock(&fpq->lock);
		
		err = 0;
		if (nbytes != sizeof(struct fuse_out_header))
			err = -EINVAL;
		else if (oh.error == -ENOSYS)
			fc->no_interrupt = 1;
		else if (oh.error == -EAGAIN)
			err = queue_interrupt(req);

		fuse_put_request(req);

		goto copy_finish;
	}

	// 走到这里表示是一个普通请求

	// 先清除sent标志, todo: why?
	clear_bit(FR_SENT, &req->flags);
	// 从io列表移除
	list_move(&req->list, &fpq->io);
	// 把出参值设置到请求里
	req->out.h = oh;
	set_bit(FR_LOCKED, &req->flags);
	spin_unlock(&fpq->lock);
	cs->req = req;

	// todo: what?
	if (!req->args->page_replace)
		cs->move_pages = 0;

	if (oh.error)
		// 有错误
		err = nbytes != sizeof(oh) ? -EINVAL : 0;
	else
		// 没错误，就复制出参
		err = copy_out_args(cs, req->args, nbytes);
	fuse_copy_finish(cs);

	spin_lock(&fpq->lock);
	clear_bit(FR_LOCKED, &req->flags);

	if (!fpq->connected)
		err = -ENOENT;
	else if (err)
		req->out.h.error = -EIO;

	// 如果不是私有请求，则从所有列表里删除请求
	if (!test_bit(FR_PRIVATE, &req->flags))
		list_del_init(&req->list);
	spin_unlock(&fpq->lock);

	// 在这个函数里，如果是后台请求，会调用end函数
	fuse_request_end(req);
out:
	return err ? err : nbytes;

copy_finish:
	fuse_copy_finish(cs);
	goto out;
}



static struct fuse_req *request_find(struct fuse_pqueue *fpq, u64 unique)
{
	// 根据序号找到哈希头
	unsigned int hash = fuse_req_hash(unique);
	struct fuse_req *req;

	// 找对应的请求
	list_for_each_entry(req, &fpq->processing[hash], list) {
		if (req->in.h.unique == unique)
			return req;
	}
	return NULL;
}

static int copy_out_args(struct fuse_copy_state *cs, struct fuse_args *args,
			 unsigned nbytes)
{
	// 请求头的长度
	unsigned reqsize = sizeof(struct fuse_out_header);

	// 出参的长度
	reqsize += fuse_len_args(args->out_numargs, args->out_args);

	if (reqsize < nbytes || (reqsize > nbytes && !args->out_argvar))
		return -EINVAL;
	else if (reqsize > nbytes) { // 整个出参的长度大于写入的长度
		// 最后一个出参
		struct fuse_arg *lastarg = &args->out_args[args->out_numargs-1];
		// 差了多少
		unsigned diffsize = reqsize - nbytes;

		// 如果差的长度比最后一个参数长度大，则出错
		if (diffsize > lastarg->size)
			return -EINVAL;
		// 否则，最后一个参数只复制一部分
		lastarg->size -= diffsize;

		// todo: 为啥可以允许最后一个参数只复制一部分？
	}

	// 把出参复制出来
	return fuse_copy_args(cs, args->out_numargs, args->out_pages,
			      args->out_args, args->page_zeroing);
}

```