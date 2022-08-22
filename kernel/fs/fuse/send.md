# fusefs发送消息
以fuse_simple_background为例，这是异步发送。

```c
/** One input argument of a request */
struct fuse_in_arg {
	unsigned size;
	const void *value;
};

/** One output argument of a request */
struct fuse_arg {
	unsigned size;
	void *value;
};

struct fuse_args {
	uint64_t nodeid;
	uint32_t opcode; // 操作码
	unsigned short in_numargs; // 入参数量
	unsigned short out_numargs; // 出参数量
	bool force:1; // 强制
	bool noreply:1; // 不需要回复
	bool nocreds:1; // 没有cred
	bool in_pages:1;
	bool out_pages:1;
	bool out_argvar:1;
	bool page_zeroing:1; 
	bool page_replace:1;
	bool may_block:1; // 可能会阻塞
	struct fuse_in_arg in_args[3]; // 入参
	struct fuse_arg out_args[2]; // 出参
	// 请求完时执行的回调函数
	void (*end)(struct fuse_mount *fm, struct fuse_args *args, int error);
};

int fuse_simple_background(struct fuse_mount *fm, struct fuse_args *args,
			    gfp_t gfp_flags)
{
	struct fuse_req *req;

	if (args->force) {
		// 强制请求必须有creds?
		WARN_ON(!args->nocreds);

		// 从fuse_req_cachep内存缓存里申请一个对象，并初始化
		req = fuse_request_alloc(fm, gfp_flags);
		if (!req)
			return -ENOMEM;
		// 设置后台标志
		__set_bit(FR_BACKGROUND, &req->flags);
	} else {
		// 非强制请求没有cred
		WARN_ON(args->nocreds);

		// 获取一个请求
		req = fuse_get_req(fm, true);
		if (IS_ERR(req))
			return PTR_ERR(req);
	}

	// 把 arg 转换成请求对象
	fuse_args_to_req(req, args);

	// 把请求入队列
	if (!fuse_request_queue_background(req)) {
		fuse_put_request(req);
		return -ENOTCONN;
	}

	return 0;
}

struct fuse_in_header {
	// 长度
	uint32_t	len;
	// 操作码
	uint32_t	opcode;
	// 请求号
	uint64_t	unique;

	// todo: nodeid是啥
	uint64_t	nodeid;
	uint32_t	uid;
	uint32_t	gid;
	uint32_t	pid;
	uint32_t	padding;
};

struct fuse_req {
	// 处理列表或io列表
	struct list_head list;

	// 中断列表
	struct list_head intr_entry;

	// io参数
	struct fuse_args *args;

	// 引用计数
	refcount_t count;

	// 标志位
	unsigned long flags;

	// 输入头
	struct {
		struct fuse_in_header h;
	} in;

	// 输出头
	struct {
		struct fuse_out_header h;
	} out;

	// 等待完成的请求
	wait_queue_head_t waitq;

#if IS_ENABLED(CONFIG_VIRTIO_FS)
	/** virtio-fs's physically contiguous buffer for in and out args */
	void *argbuf;
#endif
	struct fuse_mount *fm;
};

static struct fuse_req *fuse_get_req(struct fuse_mount *fm, bool for_background)
{
	struct fuse_conn *fc = fm->fc;
	struct fuse_req *req;
	int err;
	atomic_inc(&fc->num_waiting);

	// 判断fc是否已经阻塞
	if (fuse_block_alloc(fc, for_background)) {
		err = -EINTR;

		// 如果fc已经阻塞，则等待其变成不阻塞
		if (wait_event_killable_exclusive(fc->blocked_waitq,
				!fuse_block_alloc(fc, for_background)))
			goto out;
	}
	/* Matches smp_wmb() in fuse_set_initialized() */
	smp_rmb();

	// 还没连接
	err = -ENOTCONN;
	if (!fc->connected)
		goto out;

	// 连接错误
	err = -ECONNREFUSED;
	if (fc->conn_error)
		goto out;

	// 从fuse_req_cachep内存缓存里申请一个对象，并初始化
	req = fuse_request_alloc(fm, GFP_KERNEL);
	err = -ENOMEM;
	if (!req) {
		// 如果申请失败，则唤醒blocked_waitq等待队列
		if (for_background)
			wake_up(&fc->blocked_waitq);
		goto out;
	}

	// 设置uid, gid, pid
	req->in.h.uid = from_kuid(fc->user_ns, current_fsuid());
	req->in.h.gid = from_kgid(fc->user_ns, current_fsgid());
	req->in.h.pid = pid_nr_ns(task_pid(current), fc->pid_ns);

	// 设置FR_WAITING状态
	__set_bit(FR_WAITING, &req->flags);
	// 如果是后台请求，则设置标志
	if (for_background)
		__set_bit(FR_BACKGROUND, &req->flags);

	// uid/gid溢出？
	if (unlikely(req->in.h.uid == ((uid_t)-1) ||
		     req->in.h.gid == ((gid_t)-1))) {
		fuse_put_request(req);
		return ERR_PTR(-EOVERFLOW);
	}
	return req;

 out:
	fuse_drop_waiting(fc);
	return ERR_PTR(err);
}

static bool fuse_block_alloc(struct fuse_conn *fc, bool for_background)
{
	// fc阻塞有2种情况：1.fc还没初始化完成；2.后台请求数量太大，已阻塞
	return !fc->initialized || (for_background && fc->blocked);
}

static void fuse_args_to_req(struct fuse_req *req, struct fuse_args *args)
{
	// 请求码
	req->in.h.opcode = args->opcode;
	// 文件id
	req->in.h.nodeid = args->nodeid;
	req->args = args;
	// 如果有end回调，设置异步标志
	if (args->end)
		__set_bit(FR_ASYNC, &req->flags);
}

static struct fuse_req *fuse_request_alloc(struct fuse_mount *fm, gfp_t flags)
{
	// 从内存缓存申请内存，并初始化
	struct fuse_req *req = kmem_cache_zalloc(fuse_req_cachep, flags);
	if (req)
		// 初始化请求
		fuse_request_init(fm, req);

	return req;
}

static void fuse_request_init(struct fuse_mount *fm, struct fuse_req *req)
{
	INIT_LIST_HEAD(&req->list);
	INIT_LIST_HEAD(&req->intr_entry);
	init_waitqueue_head(&req->waitq);
	refcount_set(&req->count, 1);
	__set_bit(FR_PENDING, &req->flags);
	req->fm = fm;
}

static bool fuse_request_queue_background(struct fuse_req *req)
{
	// 挂载对象
	struct fuse_mount *fm = req->fm;
	// 连接对象
	struct fuse_conn *fc = fm->fc;
	bool queued = false;

	// 标志中没有 FR_BACKGROUND 则报警
	WARN_ON(!test_bit(FR_BACKGROUND, &req->flags));

	// 增加waiting计数
	if (!test_bit(FR_WAITING, &req->flags)) {
		__set_bit(FR_WAITING, &req->flags);
		atomic_inc(&fc->num_waiting);
	}
	// 设置请求需要回复
	__set_bit(FR_ISREPLY, &req->flags);
	spin_lock(&fc->bg_lock);
	if (likely(fc->connected)) {
		// num_background是后台进行任务的数量
		fc->num_background++;
		// 如果后台任务数量已经到了最大值，则设置fc的阻塞标志
		if (fc->num_background == fc->max_background)
			fc->blocked = 1;
		// 如果已经到了阻塞的阈值，则设置同步，异步都阻塞
		if (fc->num_background == fc->congestion_threshold && fm->sb) {
			// 这个函数设置相应位置的congested标志，并增加统计计数
			// todo: 这些标志在哪里起作用
			set_bdi_congested(fm->sb->s_bdi, BLK_RW_SYNC);
			set_bdi_congested(fm->sb->s_bdi, BLK_RW_ASYNC);
		}
		// 添加到fc的后台请求队列里
		list_add_tail(&req->list, &fc->bg_queue);
		// 刷新队列，这个函数会取出一个请求来执行
		flush_bg_queue(fc);
		queued = true;
	}
	spin_unlock(&fc->bg_lock);

	return queued;
}

static void flush_bg_queue(struct fuse_conn *fc)
{
	struct fuse_iqueue *fiq = &fc->iq;

	// active_background是后台正在进行的请求数量
	// max_background默认设置的是12
	while (fc->active_background < fc->max_background &&
	       !list_empty(&fc->bg_queue)) {
		struct fuse_req *req;

		// 取出一个请求
		req = list_first_entry(&fc->bg_queue, struct fuse_req, list);
		list_del(&req->list);

		// 增加活跃请求计数
		fc->active_background++;
		spin_lock(&fiq->lock);
		// 获取一个唯一序号
		req->in.h.unique = fuse_get_unique(fiq);
		queue_request_and_unlock(fiq, req);
	}
}

static void queue_request_and_unlock(struct fuse_iqueue *fiq,
				     struct fuse_req *req)
__releases(fiq->lock)
{
	// 入参总长度=入参头+每个参数的长度
	req->in.h.len = sizeof(struct fuse_in_header) +
		fuse_len_args(req->args->in_numargs,
			      (struct fuse_arg *) req->args->in_args);
	// 加到fiq的pending表尾
	list_add_tail(&req->list, &fiq->pending);
	// fiq的ops默认是fuse_dev_fiq_ops
	fiq->ops->wake_pending_and_unlock(fiq);
}
```
发送消息的流程到这里就完了，把请求放到队列里，然后调用fiq->ops->wake_pending_and_unlock。这个ops默认是fuse_dev_fiq_ops。
```c
const struct fuse_iqueue_ops fuse_dev_fiq_ops = {
	.wake_forget_and_unlock		= fuse_dev_wake_and_unlock,
	.wake_interrupt_and_unlock	= fuse_dev_wake_and_unlock,
	.wake_pending_and_unlock	= fuse_dev_wake_and_unlock,
};

static void fuse_dev_wake_and_unlock(struct fuse_iqueue *fiq)
__releases(fiq->lock)
{
	// 唤醒waitq等待队列
	wake_up(&fiq->waitq);

	// 如果有fasync，则向他发送POLL_IN信号
	kill_fasync(&fiq->fasync, SIGIO, POLL_IN);
	spin_unlock(&fiq->lock);
}
```
fuse_dev_wake_and_unlock也比较简单，直接唤醒waitq, 发送poll_in信号就完了。在waitq上等待的地方较多，这里以/dev/fuse的read函数为例。
```c
struct fuse_copy_state {
	int write; // 是否写入
	struct fuse_req *req; // 请求
	struct iov_iter *iter; // 游标
	// 下面3个是pipe相关
	struct pipe_buffer *pipebufs;
	struct pipe_buffer *currbuf;
	struct pipe_inode_info *pipe;
	unsigned long nr_segs;
	// 页
	struct page *pg;
	// 页大小
	unsigned len;
	// 页偏移
	unsigned offset;
	unsigned move_pages:1;
};

static ssize_t fuse_dev_read(struct kiocb *iocb, struct iov_iter *to)
{
	struct fuse_copy_state cs;
	struct file *file = iocb->ki_filp;
	struct fuse_dev *fud = fuse_get_dev(file);

	// 没有fud对象，则不合法，这个对象是在mount时创建的
	if (!fud)
		return -EPERM;

	// 只支持iovec
	if (!iter_is_iovec(to))
		return -EINVAL;

	// 这里第二个参数是write的参数，这里传,表示写
	// 注意：fuse_copy_init的write是从内核的角度来看，而并不是从系统调用的角度
	fuse_copy_init(&cs, 1, to);

	return fuse_dev_do_read(fud, file, &cs, iov_iter_count(to));
}

static ssize_t fuse_dev_do_read(struct fuse_dev *fud, struct file *file,
				struct fuse_copy_state *cs, size_t nbytes)
{
	ssize_t err;
	struct fuse_conn *fc = fud->fc;
	struct fuse_iqueue *fiq = &fc->iq;
	struct fuse_pqueue *fpq = &fud->pq;
	struct fuse_req *req;
	struct fuse_args *args;
	unsigned reqsize;
	unsigned int hash;

	// 检查最小需要的buf容量
	if (nbytes < max_t(size_t, FUSE_MIN_READ_BUFFER,
			   sizeof(struct fuse_in_header) +
			   sizeof(struct fuse_write_in) +
			   fc->max_write))
		return -EINVAL;

 restart:
	for (;;) {
		spin_lock(&fiq->lock);
		// request_pending 是检查fiq的pending,interrupts,
		// forget_list_head这三个表不为空，如果这三个表不空，说明
		// 有请求需要处理
		if (!fiq->connected || request_pending(fiq))
			break;
		spin_unlock(&fiq->lock);

		// 如果文件不能阻塞，则返回重试
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;
		// 在waitq队列上等待
		err = wait_event_interruptible_exclusive(fiq->waitq,
				!fiq->connected || request_pending(fiq));
		if (err)
			return err;
	}

	// 已经断开连接
	if (!fiq->connected) {
		err = fc->aborted ? -ECONNABORTED : -ENODEV;
		goto err_unlock;
	}

	// 中断列表不为空，则给用户层读一个中断请求
	if (!list_empty(&fiq->interrupts)) {
		req = list_entry(fiq->interrupts.next, struct fuse_req,
				 intr_entry);
		return fuse_read_interrupt(fiq, cs, nbytes, req);
	}

	// forget_list_head列表不为空
	// todo: forget_list_head是啥？
	if (forget_pending(fiq)) {
		if (list_empty(&fiq->pending) || fiq->forget_batch-- > 0)
			// todo?
			return fuse_read_forget(fc, fiq, cs, nbytes);
		// todo: ?
		if (fiq->forget_batch <= -8)
			fiq->forget_batch = 16;
	}

	// 这里就是一般的请求，从pending列表取下一个请求
	req = list_entry(fiq->pending.next, struct fuse_req, list);

	// 清除它的pending标志
	clear_bit(FR_PENDING, &req->flags);

	// 从列表删除并重置list结点
	list_del_init(&req->list);
	spin_unlock(&fiq->lock);

	// 参数及入参的长度
	args = req->args;
	reqsize = req->in.h.len;

	// 用户缓冲区太小，就丢弃这个请求？
	if (nbytes < reqsize) {
		req->out.h.error = -EIO;
		if (args->opcode == FUSE_SETXATTR)
			req->out.h.error = -E2BIG;
		// 调用end函数
		fuse_request_end(req);

		// 再次重新等待
		goto restart;
	}
	spin_lock(&fpq->lock);
	
	// 处理队列已断开连接
	if (!fpq->connected) {
		req->out.h.error = err = -ECONNABORTED;
		goto out_end;

	}
	// 把请求挂到fpq的io列表上
	list_add(&req->list, &fpq->io);
	spin_unlock(&fpq->lock);
	cs->req = req;
	// 复制请求头
	err = fuse_copy_one(cs, &req->in.h, sizeof(req->in.h));
	if (!err)
		// 复制入参
		err = fuse_copy_args(cs, args->in_numargs, args->in_pages,
				     (struct fuse_arg *) args->in_args, 0);
	fuse_copy_finish(cs);
	spin_lock(&fpq->lock);
	clear_bit(FR_LOCKED, &req->flags);

	// 已经断开连接
	if (!fpq->connected) {
		err = fc->aborted ? -ECONNABORTED : -ENODEV;
		goto out_end;
	}
	// 出错
	if (err) {
		req->out.h.error = -EIO;
		goto out_end;
	}
	// 不需要回复
	if (!test_bit(FR_ISREPLY, &req->flags)) {
		err = reqsize;
		goto out_end;
	}
	// 请求哈希值
	hash = fuse_req_hash(req->in.h.unique);

	// 把请求挂到处理列表
	list_move_tail(&req->list, &fpq->processing[hash]);
	// 增加请求的引用计数
	__fuse_get_request(req);
	// 设置请求的已发送标志
	set_bit(FR_SENT, &req->flags);
	spin_unlock(&fpq->lock);

	smp_mb__after_atomic();
	// 如果是中断，则加到中断队列
	if (test_bit(FR_INTERRUPTED, &req->flags))
		queue_interrupt(req);
	// 释放请求
	fuse_put_request(req);

	return reqsize;

out_end:
	if (!test_bit(FR_PRIVATE, &req->flags))
		list_del_init(&req->list);
	spin_unlock(&fpq->lock);
	fuse_request_end(req);
	return err;

 err_unlock:
	spin_unlock(&fiq->lock);
	return err;
}

static int fuse_copy_one(struct fuse_copy_state *cs, void *val, unsigned size)
{
	while (size) {
		// 如果cs里没空间了，先准备空间
		if (!cs->len) {
			int err = fuse_copy_fill(cs);
			if (err)
				return err;
		}
		// 给cs里复制数据
		fuse_copy_do(cs, &val, &size);
	}
	return 0;
}

static int fuse_copy_fill(struct fuse_copy_state *cs)
{
	struct page *page;
	int err;

	err = unlock_request(cs->req);
	if (err)
		return err;

	fuse_copy_finish(cs);
	if (cs->pipebufs) {
		// todo: pipebuf是什么时候创建
		struct pipe_buffer *buf = cs->pipebufs;

		if (!cs->write) {
			// 读
			err = pipe_buf_confirm(cs->pipe, buf);
			if (err)
				return err;

			BUG_ON(!cs->nr_segs);
			cs->currbuf = buf;
			cs->pg = buf->page;
			cs->offset = buf->offset;
			cs->len = buf->len;
			cs->pipebufs++;
			cs->nr_segs--;
		} else {
			// 写
			if (cs->nr_segs >= cs->pipe->max_usage)
				return -EIO;

			page = alloc_page(GFP_HIGHUSER);
			if (!page)
				return -ENOMEM;

			buf->page = page;
			buf->offset = 0;
			buf->len = 0;

			cs->currbuf = buf;
			cs->pg = page;
			cs->offset = 0;
			cs->len = PAGE_SIZE;
			cs->pipebufs++;
			cs->nr_segs++;
		}
	} else {
		// 一般的读写走这个
		size_t off;
		// 从iov里获取一页
		err = iov_iter_get_pages(cs->iter, &page, PAGE_SIZE, 1, &off);
		if (err < 0)
			return err;
		BUG_ON(!err);
		cs->len = err;
		cs->offset = off;
		cs->pg = page;
		// iov递增
		iov_iter_advance(cs->iter, err);
	}

	return lock_request(cs->req);
}

static int fuse_copy_do(struct fuse_copy_state *cs, void **val, unsigned *size)
{
	unsigned ncpy = min(*size, cs->len);
	if (val) {
		// 先把页映射到内存
		void *pgaddr = kmap_atomic(cs->pg);
		void *buf = pgaddr + cs->offset;

		// 根据读/写方向来复制数据
		if (cs->write)
			memcpy(buf, *val, ncpy);
		else
			memcpy(*val, buf, ncpy);

		kunmap_atomic(pgaddr);
		*val += ncpy;
	}
	*size -= ncpy;
	cs->len -= ncpy;
	cs->offset += ncpy;
	return ncpy;
}


static int fuse_copy_args(struct fuse_copy_state *cs, unsigned numargs,
			  unsigned argpages, struct fuse_arg *args,
			  int zeroing)
{
	int err = 0;
	unsigned i;

	// numargs是共有多少个参数
	for (i = 0; !err && i < numargs; i++)  {
		struct fuse_arg *arg = &args[i];

		// 复制每个参数的数据
		if (i == numargs - 1 && argpages)
			err = fuse_copy_pages(cs, arg->size, zeroing);
		else
			err = fuse_copy_one(cs, arg->value, arg->size);
	}
	return err;
}

static void fuse_copy_finish(struct fuse_copy_state *cs)
{
	// todo: 为什么只处理写的情况
	if (cs->currbuf) {
		// 设置buf的升序
		struct pipe_buffer *buf = cs->currbuf;

		if (cs->write)
			buf->len = PAGE_SIZE - cs->len;
		cs->currbuf = NULL;
	} else if (cs->pg) {
		// 如果是page的话，把page标脏
		if (cs->write) {
			flush_dcache_page(cs->pg);
			set_page_dirty_lock(cs->pg);
		}
		put_page(cs->pg);
	}
	cs->pg = NULL;
}

static int queue_interrupt(struct fuse_req *req)
{
	struct fuse_iqueue *fiq = &req->fm->fc->iq;

	spin_lock(&fiq->lock);
	
	// 检查这个请求是否有FR_INTERRUPTED标志
	// todo: 什么时候会没有这个标志
	if (unlikely(!test_bit(FR_INTERRUPTED, &req->flags))) {
		spin_unlock(&fiq->lock);
		return -EINVAL;
	}

	if (list_empty(&req->intr_entry)) {
		// 加到中断列表
		list_add_tail(&req->intr_entry, &fiq->interrupts);
		/*
		 * Pairs with smp_mb() implied by test_and_set_bit()
		 * from fuse_request_end().
		 */
		smp_mb();
		// 如果已经完成，则删除之
		if (test_bit(FR_FINISHED, &req->flags)) {
			list_del_init(&req->intr_entry);
			spin_unlock(&fiq->lock);
			return 0;
		}
		// 这个ops默认是fuse_dev_fiq_ops， 调用的函数也是fuse_dev_wake_and_unlock
		fiq->ops->wake_interrupt_and_unlock(fiq);
	} else {
		spin_unlock(&fiq->lock);
	}
	return 0;
}

static void fuse_put_request(struct fuse_req *req)
{
	struct fuse_conn *fc = req->fm->fc;

	if (refcount_dec_and_test(&req->count)) {
		// 如果是后台请求，则唤醒blocked_waitq
		if (test_bit(FR_BACKGROUND, &req->flags)) {
			/*
			 * We get here in the unlikely case that a background
			 * request was allocated but not sent
			 */
			spin_lock(&fc->bg_lock);
			if (!fc->blocked)
				wake_up(&fc->blocked_waitq);
			spin_unlock(&fc->bg_lock);
		}

		// 如果是等待请求，则清除标志
		if (test_bit(FR_WAITING, &req->flags)) {
			__clear_bit(FR_WAITING, &req->flags);
			// 递减fc->num_waiting
			fuse_drop_waiting(fc);
		}
		// 释放 fuse_req_cachep 内存缓存
		fuse_request_free(req);
	}
}

static void fuse_drop_waiting(struct fuse_conn *fc)
{
	// 如果num_waiting为0,且断开连接，则唤醒blocked_waitq
	if (atomic_dec_and_test(&fc->num_waiting) &&
	    !READ_ONCE(fc->connected)) {
		/* wake up aborters */
		wake_up_all(&fc->blocked_waitq);
	}
}

void fuse_request_end(struct fuse_req *req)
{
	struct fuse_mount *fm = req->fm;
	struct fuse_conn *fc = fm->fc;
	struct fuse_iqueue *fiq = &fc->iq;

	// 如果请求已经完成，直接释放
	if (test_and_set_bit(FR_FINISHED, &req->flags))
		goto put_request;

	// 中断请求，直接删除
	if (test_bit(FR_INTERRUPTED, &req->flags)) {
		spin_lock(&fiq->lock);
		list_del_init(&req->intr_entry);
		spin_unlock(&fiq->lock);
	}
	WARN_ON(test_bit(FR_PENDING, &req->flags));
	WARN_ON(test_bit(FR_SENT, &req->flags));

	if (test_bit(FR_BACKGROUND, &req->flags)) {
		// 后台请求
		spin_lock(&fc->bg_lock);
		// 清除标志
		clear_bit(FR_BACKGROUND, &req->flags);
	
		if (fc->num_background == fc->max_background) {
			// 如果已经阻塞了，则清除阻塞状态，并唤醒blocked_waitq
			fc->blocked = 0;
			wake_up(&fc->blocked_waitq);
		} else if (!fc->blocked) {
			// 这个等待队列不为空时，唤醒blocked_waitq
			if (waitqueue_active(&fc->blocked_waitq))
				wake_up(&fc->blocked_waitq);
		}

		// 如果后台请求数量已经到了阻塞阈值，则清除相应状态
		if (fc->num_background == fc->congestion_threshold && fm->sb) {
			clear_bdi_congested(fm->sb->s_bdi, BLK_RW_SYNC);
			clear_bdi_congested(fm->sb->s_bdi, BLK_RW_ASYNC);
		}
		fc->num_background--;
		fc->active_background--;
		// 取出一个请求执行
		flush_bg_queue(fc);
		spin_unlock(&fc->bg_lock);
	} else {
		// 不是后台请求就简单的唤醒waitq
		wake_up(&req->waitq);
	}

	// 如果是异步请求，则调用它的end回调
	if (test_bit(FR_ASYNC, &req->flags))
		req->args->end(fm, req->args, req->out.h.error);
put_request:
	// 释放请求
	fuse_put_request(req);
}
```

## 同步发送消息
```c
ssize_t fuse_simple_request(struct fuse_mount *fm, struct fuse_args *args)
{
	struct fuse_conn *fc = fm->fc;
	struct fuse_req *req;
	ssize_t ret;

	// 根据是否强制，来分配req
	if (args->force) {
		atomic_inc(&fc->num_waiting);
		req = fuse_request_alloc(fm, GFP_KERNEL | __GFP_NOFAIL);

		if (!args->nocreds)
			fuse_force_creds(req);

		__set_bit(FR_WAITING, &req->flags);
		__set_bit(FR_FORCE, &req->flags);
	} else {
		WARN_ON(args->nocreds);
		req = fuse_get_req(fm, false);
		if (IS_ERR(req))
			return PTR_ERR(req);
	}

	// 根据兼容性，设置不同的标志
	fuse_adjust_compat(fc, args);

	// 把参数转换成请求
	fuse_args_to_req(req, args);

	// 设置是否需要回复标志
	if (!args->noreply)
		__set_bit(FR_ISREPLY, &req->flags);
	// 发送消息
	__fuse_request_send(req);
	ret = req->out.h.error;
	if (!ret && args->out_argvar) {
		// 请求成功，并且有出参
		BUG_ON(args->out_numargs == 0);
		ret = args->out_args[args->out_numargs - 1].size;
	}
	// 释放请求
	fuse_put_request(req);

	return ret;
}

static void fuse_adjust_compat(struct fuse_conn *fc, struct fuse_args *args)
{
	if (fc->minor < 4 && args->opcode == FUSE_STATFS)
		args->out_args[0].size = FUSE_COMPAT_STATFS_SIZE;

	if (fc->minor < 9) {
		switch (args->opcode) {
		case FUSE_LOOKUP:
		case FUSE_CREATE:
		case FUSE_MKNOD:
		case FUSE_MKDIR:
		case FUSE_SYMLINK:
		case FUSE_LINK:
			args->out_args[0].size = FUSE_COMPAT_ENTRY_OUT_SIZE;
			break;
		case FUSE_GETATTR:
		case FUSE_SETATTR:
			args->out_args[0].size = FUSE_COMPAT_ATTR_OUT_SIZE;
			break;
		}
	}
	if (fc->minor < 12) {
		switch (args->opcode) {
		case FUSE_CREATE:
			args->in_args[0].size = sizeof(struct fuse_open_in);
			break;
		case FUSE_MKNOD:
			args->in_args[0].size = FUSE_COMPAT_MKNOD_IN_SIZE;
			break;
		}
	}
}

static void __fuse_request_send(struct fuse_req *req)
{
	struct fuse_iqueue *fiq = &req->fm->fc->iq;

	// 同步请求肯定不能有后台标志
	BUG_ON(test_bit(FR_BACKGROUND, &req->flags));
	spin_lock(&fiq->lock);
	if (!fiq->connected) {
		// 连接断开
		spin_unlock(&fiq->lock);
		req->out.h.error = -ENOTCONN;
	} else {
		// 获取一个请求序号
		req->in.h.unique = fuse_get_unique(fiq);
		// 增加引用计数
		__fuse_get_request(req);
		// 加入pending表尾
		queue_request_and_unlock(fiq, req);

		request_wait_answer(req);
		/* Pairs with smp_wmb() in fuse_request_end() */
		smp_rmb();
	}
}

static void request_wait_answer(struct fuse_req *req)
{
	struct fuse_conn *fc = req->fm->fc;
	struct fuse_iqueue *fiq = &fc->iq;
	int err;

	if (!fc->no_interrupt) {
		// 是中断

		// 等待请求完成
		err = wait_event_interruptible(req->waitq,
					test_bit(FR_FINISHED, &req->flags));
		if (!err)
			return;

		// 走到这里表示是被中断唤醒的

		// 设置被中断标志
		set_bit(FR_INTERRUPTED, &req->flags);
		/* matches barrier in fuse_dev_do_read() */
		smp_mb__after_atomic();
		if (test_bit(FR_SENT, &req->flags))
			// 再次加到中断表尾
			queue_interrupt(req);
	}

	// 走到这里表示一般请求

	if (!test_bit(FR_FORCE, &req->flags)) {
		// 不是强制的，

		// 等待请求完成
		err = wait_event_killable(req->waitq,
					test_bit(FR_FINISHED, &req->flags));
		if (!err)
			return;

		// 走到这儿表示被中断
		spin_lock(&fiq->lock);
		
		// 如果请求还没发出去，则从pending表里删除，并释放请求
		if (test_bit(FR_PENDING, &req->flags)) {
			list_del(&req->list);
			spin_unlock(&fiq->lock);
			__fuse_put_request(req);
			req->out.h.error = -EINTR;
			return;
		}
		spin_unlock(&fiq->lock);
	}

	// 强制请求/已经到用户空间的请求，就一直等待
	wait_event(req->waitq, test_bit(FR_FINISHED, &req->flags));
}
```