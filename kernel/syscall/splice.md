# splice
splice系统调用，把一个文件描述符的数据移到到另一个文件描述符里，其中至少有一个得是pipe。

```c
/*
fd_in: 读 文件描述符
off_in: 读 偏移
fd_out: 写 文件描述符
off_out: 写 偏移
len: 要移动数据的长度
flags: 标志

返回值：
> 0: 移动数据的字节数。移动数据成功后，off_in, off_out会指向文件最新的偏移值
= 0: 没有移动数据
< 0: 出错

fd_in/fd_out: 如果有pipe类型的fd, 则相应的offset对象必须是NULL。

标志支持以下几种:
SPLICE_F_MOVE	按整页内存移动数据。
SPLICE_F_NONBLOCK 不阻塞 
SPLICE_F_MORE	提示内核：后续splice将调用更多数据。
SPLICE_F_GIFT	未知
*/
SYSCALL_DEFINE6(splice, int, fd_in, loff_t __user *, off_in,
		int, fd_out, loff_t __user *, off_out,
		size_t, len, unsigned int, flags)
{
	struct fd in, out;
	long error;

	// 不移动数据， 你调它干啥！
	if (unlikely(!len))
		return 0;

	// flags里不能有除上面4种flag以外的flag
	if (unlikely(flags & ~SPLICE_F_ALL))
		return -EINVAL;

	error = -EBADF;

	// 找到输入文件
	in = fdget(fd_in);
	if (in.file) {

		// 找到输出文件
		out = fdget(fd_out);
		if (out.file) {
			// 真正的移动数据
			error = __do_splice(in.file, off_in, out.file, off_out,
						len, flags);
			fdput(out);
		}
		fdput(in);
	}
	return error;
}

static long __do_splice(struct file *in, loff_t __user *off_in,
			struct file *out, loff_t __user *off_out,
			size_t len, unsigned int flags)
{
	struct pipe_inode_info *ipipe;
	struct pipe_inode_info *opipe;
	loff_t offset, *__off_in = NULL, *__off_out = NULL;
	long ret;

	// 找到输入／输出pipe的inode对象
	ipipe = get_pipe_info(in, true);
	opipe = get_pipe_info(out, true);

	// 如果是pipe，则偏移必须是0
	if (ipipe && off_in)
		return -ESPIPE;
	if (opipe && off_out)
		return -ESPIPE;

	// 如果in/out的偏移对象有值，则从用户空间把值复制过来
	if (off_out) {
		if (copy_from_user(&offset, off_out, sizeof(loff_t)))
			return -EFAULT;
		__off_out = &offset;
	}
	if (off_in) {
		if (copy_from_user(&offset, off_in, sizeof(loff_t)))
			return -EFAULT;
		__off_in = &offset;
	}

	// 根据不同情况来移动数据
	ret = do_splice(in, __off_in, out, __off_out, len, flags);
	if (ret < 0)
		return ret;

	// 向用户空间复制相应的偏移值，因为在上面do_splice里，这个偏移值可能已经更改
	if (__off_out && copy_to_user(off_out, __off_out, sizeof(loff_t)))
		return -EFAULT;
	if (__off_in && copy_to_user(off_in, __off_in, sizeof(loff_t)))
		return -EFAULT;

	return ret;
}

struct pipe_inode_info *get_pipe_info(struct file *file, bool for_splice)
{
	// 这个是pipe inode的内存对象
	struct pipe_inode_info *pipe = file->private_data;

	// pipe文件的f_op必须是pipefifo_fops
	if (file->f_op != &pipefifo_fops || !pipe)
		return NULL;

#ifdef CONFIG_WATCH_QUEUE
	// 如果是splice系统调用，则pipe不能有watch_queue
	// todo: watch_queue是啥？
	if (for_splice && pipe->watch_queue)
		return NULL;
#endif
	return pipe;
}


long do_splice(struct file *in, loff_t *off_in, struct file *out,
	       loff_t *off_out, size_t len, unsigned int flags)
{
	struct pipe_inode_info *ipipe;
	struct pipe_inode_info *opipe;
	loff_t offset;
	long ret;

	// 输入文件必须要有读权限，输出要有写权限
	if (unlikely(!(in->f_mode & FMODE_READ) ||
		     !(out->f_mode & FMODE_WRITE)))
		return -EBADF;

	ipipe = get_pipe_info(in, true);
	opipe = get_pipe_info(out, true);

	if (ipipe && opipe) {
		// 如果io都是pipe，那偏移值都必须是空
		if (off_in || off_out)
			return -ESPIPE;

		// 把自己的数据给自己移动！！
		if (ipipe == opipe)
			return -EINVAL;

		// io文件任意一个有不阻塞的标志，则本次splice操作就是不阻塞
		if ((in->f_flags | out->f_flags) & O_NONBLOCK)
			flags |= SPLICE_F_NONBLOCK;

		// 移动pipe数据
		return splice_pipe_to_pipe(ipipe, opipe, len, flags);
	}

	if (ipipe) {
		// 这个分支表示输入是pipe, 输出是其它文件

		// 输入不能有偏移
		if (off_in)
			return -ESPIPE;

		if (off_out) {
			// 如果有指定的输出偏移，文件必须支持pwrite
			if (!(out->f_mode & FMODE_PWRITE))
				return -EINVAL;
			offset = *off_out;
		} else {
			// 没有指定，就取文件当前偏移值
			offset = out->f_pos;
		}

		// 输入文件不能有追加
		if (unlikely(out->f_flags & O_APPEND))
			return -EINVAL;

		// 判断要操作的offset+len是否合法，这个区域有没有加文件锁，
		// 以及调用安全相关的接口
		ret = rw_verify_area(WRITE, out, &offset, len);
		if (unlikely(ret < 0))
			return ret;

		// 输入文件不阻塞，那就是不阻塞
		if (in->f_flags & O_NONBLOCK)
			flags |= SPLICE_F_NONBLOCK;

		// 给 sb->s_writers.rw_sem里对应的锁 加写锁
		file_start_write(out);
		// 从管道给文件写数据
		ret = do_splice_from(ipipe, out, &offset, len, flags);
		// 给 sb->s_writers.rw_sem里对应的锁 解除写锁
		file_end_write(out);

		// 向对应的地方写入新的偏移值
		if (!off_out)
			out->f_pos = offset;
		else
			*off_out = offset;

		return ret;
	}

	if (opipe) {
		// 这个分支表示输出是pipe, 输入是其它文件

		// 输出不能有偏移
		if (off_out)
			return -ESPIPE;
		
		if (off_in) {
			// 如果指定了偏移值，则该文件要支持pread
			if (!(in->f_mode & FMODE_PREAD))
				return -EINVAL;
			offset = *off_in;
		} else {
			// 没有指定，就取文件当前偏移值
			offset = in->f_pos;
		}

		// 输入有不阻塞，本次操作就不阻塞
		if (out->f_flags & O_NONBLOCK)
			flags |= SPLICE_F_NONBLOCK;

		pipe_lock(opipe);
		// 等待pipe可写
		ret = wait_for_space(opipe, flags);
		if (!ret) {
			unsigned int p_space;

			// 算出pipe剩余空间
			p_space = opipe->max_usage - pipe_occupancy(opipe->head, opipe->tail);

			// 剩余空间和len较小的
			len = min_t(size_t, len, p_space << PAGE_SHIFT);

			// 从文件给管道读数据
			ret = do_splice_to(in, &offset, opipe, len, flags);
		}
		pipe_unlock(opipe);
		
		// 成功了移出了数据，唤醒读者
		if (ret > 0)
			wakeup_pipe_readers(opipe);
		
		// 设置输入文件的新偏移值
		if (!off_in)
			in->f_pos = offset;
		else
			*off_in = offset;

		return ret;
	}

	return -EINVAL;
}
```

## splice_pipe_to_pipe
```c
static int splice_pipe_to_pipe(struct pipe_inode_info *ipipe,
			       struct pipe_inode_info *opipe,
			       size_t len, unsigned int flags)
{
	struct pipe_buffer *ibuf, *obuf;
	unsigned int i_head, o_head;
	unsigned int i_tail, o_tail;
	unsigned int i_mask, o_mask;
	int ret = 0;
	bool input_wakeup = false;


retry:
	// 判断输入是否可读，如果不可读，则等待
	ret = ipipe_prep(ipipe, flags);
	if (ret)
		return ret;

	// 等待输出可写
	ret = opipe_prep(opipe, flags);
	if (ret)
		return ret;

	// 以相同的顺序，同时锁住io，防止锁顺序死锁
	pipe_double_lock(ipipe, opipe);

	// 输入从尾部开始读
	i_tail = ipipe->tail;
	i_mask = ipipe->ring_size - 1;

	// 输出从头开始写
	o_head = opipe->head;
	o_mask = opipe->ring_size - 1;

	do {
		size_t o_len;

		// 没有读者，发送SIGPIPE
		if (!opipe->readers) {
			send_sig(SIGPIPE, current, 0);
			if (!ret)
				ret = -EPIPE;
			break;
		}

		i_head = ipipe->head;
		o_tail = opipe->tail;
		
		// 如果输入已经空了，而且没有写者，则退出
		if (pipe_empty(i_head, i_tail) && !ipipe->writers)
			break;

		// 输入空了或者输出满了
		if (pipe_empty(i_head, i_tail) ||
		    pipe_full(o_head, o_tail, opipe->max_usage)) {
			// 如果已经处理了一些数据，则退出
			if (ret)
				break;

			// splice要求不阻塞，则退出
			if (flags & SPLICE_F_NONBLOCK) {
				ret = -EAGAIN;
				break;
			}

			// 去上面重试
			pipe_unlock(ipipe);
			pipe_unlock(opipe);
			goto retry;
		}

		// 取出io的缓冲区
		ibuf = &ipipe->bufs[i_tail & i_mask];
		obuf = &opipe->bufs[o_head & o_mask];

		if (len >= ibuf->len) {
			// 直接让obuf指向ibuf
			*obuf = *ibuf;
			ibuf->ops = NULL;
			
			// pipe初始时，tail和head指向同一个地方，写的时候递增head, 读的时候递增tail


			// 递增输入的尾部，
			i_tail++;
			ipipe->tail = i_tail;
			input_wakeup = true;

			// 递增输出的头
			o_len = obuf->len;
			o_head++;
			opipe->head = o_head;
		} else {
			// 获取buf的一个引用，其实就是递增buf对应页的引用计数，
			// 因为这时有两个pipe共用一个页，
			// 上面len>=ibuf->len的情况不用增加引用，因为只有输出引用页
			if (!pipe_buf_get(ipipe, ibuf)) {
				if (ret == 0)
					ret = -EFAULT;
				break;
			}

			// 让obuf指向ibuf
			*obuf = *ibuf;

			// todo: 没看懂
			obuf->flags &= ~PIPE_BUF_FLAG_GIFT;
			obuf->flags &= ~PIPE_BUF_FLAG_CAN_MERGE;

			obuf->len = len;

			// 修改ibuf的偏移，意味着后面从offset地方开始写
			ibuf->offset += len;
			ibuf->len -= len;
			o_len = len;
			o_head++;
			opipe->head = o_head;
		}
		ret += o_len;
		len -= o_len;
	} while (len);

	pipe_unlock(ipipe);
	pipe_unlock(opipe);

	// 给输出写了一些数据，就唤醒输出的读者
	if (ret > 0)
		wakeup_pipe_readers(opipe);

	// 从输入读了数据，就唤醒输入的写者
	// todo: input_wakeup为啥只在len >= ibuf->len置true
	if (input_wakeup)
		wakeup_pipe_writers(ipipe);

	return ret;
}
static int ipipe_prep(struct pipe_inode_info *pipe, unsigned int flags)
{
	int ret;

	// pipe 不为空直接返回 0
	if (!pipe_empty(pipe->head, pipe->tail))
		return 0;

	ret = 0;
	pipe_lock(pipe);

	while (pipe_empty(pipe->head, pipe->tail)) {
		// 有信号需要处理
		if (signal_pending(current)) {
			ret = -ERESTARTSYS;
			break;
		}
		// 没有写者
		if (!pipe->writers)
			break;
		// slice调用，不需要阻塞
		if (flags & SPLICE_F_NONBLOCK) {
			ret = -EAGAIN;
			break;
		}
		// 等待可读
		pipe_wait_readable(pipe);
	}

	pipe_unlock(pipe);
	return ret;
}

static int opipe_prep(struct pipe_inode_info *pipe, unsigned int flags)
{
	int ret;

	// 判断pipe有没有满
	if (!pipe_full(pipe->head, pipe->tail, pipe->max_usage))
		return 0;

	ret = 0;
	pipe_lock(pipe);

	while (pipe_full(pipe->head, pipe->tail, pipe->max_usage)) {
		// 没有读者，发送错误信号
		if (!pipe->readers) {
			send_sig(SIGPIPE, current, 0);
			ret = -EPIPE;
			break;
		}
		// 如果splice不等待
		if (flags & SPLICE_F_NONBLOCK) {
			ret = -EAGAIN;
			break;
		}
		// 有信号需要处理
		if (signal_pending(current)) {
			ret = -ERESTARTSYS;
			break;
		}
		// 等待可写
		pipe_wait_writable(pipe);
	}

	pipe_unlock(pipe);
	return ret;
}
```

## do_splice_from
```c
static long do_splice_from(struct pipe_inode_info *pipe, struct file *out,
			   loff_t *ppos, size_t len, unsigned int flags)
{
	// 从管道读，就是给本文件写，所以调用splice_write

	// 不支持splice_write，打印警告
	if (unlikely(!out->f_op->splice_write))
		return warn_unsupported(out, "write");
	// 调用具体文件系统的splice_write
	return out->f_op->splice_write(pipe, out, ppos, len, flags);
}

// 大多数文件系统的splice_write是这个函数
ssize_t
iter_file_splice_write(struct pipe_inode_info *pipe, struct file *out,
			  loff_t *ppos, size_t len, unsigned int flags)
{
	struct splice_desc sd = {
		.total_len = len,
		.flags = flags,
		.pos = *ppos,
		.u.file = out,
	};
	int nbufs = pipe->max_usage;
	struct bio_vec *array = kcalloc(nbufs, sizeof(struct bio_vec),
					GFP_KERNEL);
	ssize_t ret;

	if (unlikely(!array))
		return -ENOMEM;

	pipe_lock(pipe);

	// 把num_spliced，need_wakeup置0
	splice_from_pipe_begin(&sd);
	while (sd.total_len) {
		struct iov_iter from;
		unsigned int head, tail, mask;
		size_t left;
		int n;

		// 这个函数主要是等待有可读的数据
		ret = splice_from_pipe_next(pipe, &sd);
		if (ret <= 0)
			break;

		// 如果可读数据变了，要重新申请内存
		if (unlikely(nbufs < pipe->max_usage)) {
			kfree(array);
			nbufs = pipe->max_usage;
			array = kcalloc(nbufs, sizeof(struct bio_vec),
					GFP_KERNEL);
			if (!array) {
				ret = -ENOMEM;
				break;
			}
		}

		head = pipe->head;
		tail = pipe->tail;
		mask = pipe->ring_size - 1;

		/* build the vector */
		left = sd.total_len;
		for (n = 0; !pipe_empty(head, tail) && left && n < nbufs; tail++, n++) {
			// 要读的pipe的buf
			struct pipe_buffer *buf = &pipe->bufs[tail & mask];
			// buf的可读长度
			size_t this_len = buf->len;

			// 计数最大读的数量
			if (this_len > left)
				this_len = left;

			// 调用buf的confirm，如果有的话
			ret = pipe_buf_confirm(pipe, buf);
			if (unlikely(ret)) {
				if (ret == -ENODATA)
					ret = 0;
				goto done;
			}
			
			// 初始化各个array的页数，长度等信息
			array[n].bv_page = buf->page;
			array[n].bv_len = this_len;
			array[n].bv_offset = buf->offset;
			left -= this_len;
		}
		
		// 初始化iov
		iov_iter_bvec(&from, WRITE, array, n, sd.total_len - left);
		// 调用具体文件系统的write接口给out写数据
		ret = vfs_iter_write(out, &from, &sd.pos, 0);
		if (ret <= 0)
			break;

		// 递增sd相关的计数器
		sd.num_spliced += ret;
		sd.total_len -= ret;

		*ppos = sd.pos;

		// 修改pipe的计数器
		tail = pipe->tail;
		while (ret) {
			struct pipe_buffer *buf = &pipe->bufs[tail & mask];
			if (ret >= buf->len) {
				// 把整个buf全读了，就重置相关的buf
				ret -= buf->len;
				buf->len = 0;
				pipe_buf_release(pipe, buf);
				tail++;
				pipe->tail = tail;
				if (pipe->files)
					sd.need_wakeup = true;
			} else {
				// 否则，只修改偏移和长度
				buf->offset += ret;
				buf->len -= ret;
				ret = 0;
			}
		}
	}
done:
	kfree(array);
	// 如果需要，唤醒写者
	splice_from_pipe_end(pipe, &sd);

	pipe_unlock(pipe);

	if (sd.num_spliced)
		ret = sd.num_spliced;

	return ret;
}

ssize_t vfs_iter_write(struct file *file, struct iov_iter *iter, loff_t *ppos,
		rwf_t flags)
{
	if (!file->f_op->write_iter)
		return -EINVAL;
	return do_iter_write(file, iter, ppos, flags);
}

static ssize_t do_iter_write(struct file *file, struct iov_iter *iter,
		loff_t *pos, rwf_t flags)
{
	size_t tot_len;
	ssize_t ret = 0;

	// 文件不是以写打开
	if (!(file->f_mode & FMODE_WRITE))
		return -EBADF;
	
	// 文件没有write或write_iter函数
	if (!(file->f_mode & FMODE_CAN_WRITE))
		return -EINVAL;

	// 要写的数量
	tot_len = iov_iter_count(iter);
	if (!tot_len)
		return 0;
	// 判断要写的位置是否可写
	ret = rw_verify_area(WRITE, file, pos, tot_len);
	if (ret < 0)
		return ret;

	// 根据有无write_iter接口调用相关函数
	if (file->f_op->write_iter)
		ret = do_iter_readv_writev(file, iter, pos, WRITE, flags);
	else
		ret = do_loop_readv_writev(file, iter, pos, WRITE, flags);
	if (ret > 0)
		fsnotify_modify(file);
	return ret;
}

static ssize_t do_iter_readv_writev(struct file *filp, struct iov_iter *iter,
		loff_t *ppos, int type, rwf_t flags)
{
	struct kiocb kiocb;
	ssize_t ret;
	// 初始化kiocb
	init_sync_kiocb(&kiocb, filp);
	ret = kiocb_set_rw_flags(&kiocb, flags);
	if (ret)
		return ret;
	// 设置要写的位置
	kiocb.ki_pos = (ppos ? *ppos : 0);

	// 根据读写类型调用不同的数据
	if (type == READ)
		ret = call_read_iter(filp, &kiocb, iter);
	else
		ret = call_write_iter(filp, &kiocb, iter);
	BUG_ON(ret == -EIOCBQUEUED);

	// 设置pos
	if (ppos)
		*ppos = kiocb.ki_pos;
	return ret;
}

static ssize_t do_loop_readv_writev(struct file *filp, struct iov_iter *iter,
		loff_t *ppos, int type, rwf_t flags)
{
	ssize_t ret = 0;

	// 不支持高优先级请求
	if (flags & ~RWF_HIPRI)
		return -EOPNOTSUPP;

	while (iov_iter_count(iter)) {
		struct iovec iovec = iov_iter_iovec(iter);
		ssize_t nr;

		// 根据读/写循环调用具体文件系统的接口
		if (type == READ) {
			nr = filp->f_op->read(filp, iovec.iov_base,
					      iovec.iov_len, ppos);
		} else {
			nr = filp->f_op->write(filp, iovec.iov_base,
					       iovec.iov_len, ppos);
		}

		if (nr < 0) {
			if (!ret)
				ret = nr;
			break;
		}
		ret += nr;
		if (nr != iovec.iov_len)
			break;
		// 把迭代器向前推进nr个长度
		iov_iter_advance(iter, nr);
	}

	return ret;
}
```
## do_splice_to
```
static long do_splice_to(struct file *in, loff_t *ppos,
			 struct pipe_inode_info *pipe, size_t len,
			 unsigned int flags)
{
	int ret;

	// 给管道写，就是从本文件读，所以要判断in的读权限
	if (unlikely(!(in->f_mode & FMODE_READ)))
		return -EBADF;

	// 确定文件在该位置上能否正确读写
	ret = rw_verify_area(READ, in, ppos, len);
	if (unlikely(ret < 0))
		return ret;

	// MAX_RW_COUNT 是一页的大小，如果长度超过一页，那最多操作一页内容
	if (unlikely(len > MAX_RW_COUNT))
		len = MAX_RW_COUNT;

	// 文件系统不支持splice_read
	// 为什么不放在开头就检查呢？
	if (unlikely(!in->f_op->splice_read))
		return warn_unsupported(in, "read");
	// 调用具体文件系统
	return in->f_op->splice_read(in, ppos, pipe, len, flags);
}

// 大多数文件系统的splice_read是这个函数
ssize_t generic_file_splice_read(struct file *in, loff_t *ppos,
				 struct pipe_inode_info *pipe, size_t len,
				 unsigned int flags)
{
	struct iov_iter to;
	struct kiocb kiocb;
	unsigned int i_head;
	int ret;

	// 初始化iov
	iov_iter_pipe(&to, READ, pipe, len);

	// 指向pipe写端的头
	i_head = to.head;

	// 初始化io块
	init_sync_kiocb(&kiocb, in);
	kiocb.ki_pos = *ppos;

	// 调用具体文件系统的read_iter给pipe里读数据
	ret = call_read_iter(in, &kiocb, &to);
	if (ret > 0) {
		// 修改in的位置
		*ppos = kiocb.ki_pos;

		// 修改atime
		file_accessed(in);
	} else if (ret < 0) {
		to.head = i_head;
		to.iov_offset = 0;
		iov_iter_advance(&to, 0); /* to free what was emitted */
		/*
		 * callers of ->splice_read() expect -EAGAIN on
		 * "can't put anything in there", rather than -EFAULT.
		 */
		if (ret == -EFAULT)
			ret = -EAGAIN;
	}

	return ret;
}
```