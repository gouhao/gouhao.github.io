# io_uring_setup
源码基于5.10

io_uring_setup系统调用主要创建一个io_uring的上下文，这个上下文里包含提交，完成队列，创始io_wq worker线程，用于异步执行任务，如果指定了sq-poll, 还会创建相应的内核线程。

## io_uring_setup系统调用
```c
/*
entries: 要创建的sqe的数量
params: 用户层指定的参数
*/
static long io_uring_setup(u32 entries, struct io_uring_params __user *params)
{
	struct io_uring_params p;
	int i;

    	// 把用户空间的params复制到内核空间
	if (copy_from_user(&p, params, sizeof(p)))
		return -EFAULT;

    	// resv是保留的空间，所以不能用
	for (i = 0; i < ARRAY_SIZE(p.resv); i++) {
		if (p.resv[i])
			return -EINVAL;
	}

	/* 
		flags只支持这些标志，如果有其它标志都会报错
		#define IORING_SETUP_IOPOLL	(1U << 0)	// io poll 模式
		#define IORING_SETUP_SQPOLL	(1U << 1)	// sq poll 模式
		#define IORING_SETUP_SQ_AFF	(1U << 2)	// 在sq poll模式下，指定线程运行的cpu
		#define IORING_SETUP_CQSIZE	(1U << 3)	// 指定完成队列大小
		#define IORING_SETUP_CLAMP	(1U << 4)	// 当用户指定的entries太大时，可以把值改小
		#define IORING_SETUP_ATTACH_WQ	(1U << 5)	// 添加到当前已经存在的wq里
		#define IORING_SETUP_R_DISABLED	(1U << 6)	// 如果是sq-poll模式，一开始不启动sq-thread
	 */
	if (p.flags & ~(IORING_SETUP_IOPOLL | IORING_SETUP_SQPOLL |
			IORING_SETUP_SQ_AFF | IORING_SETUP_CQSIZE |
			IORING_SETUP_CLAMP | IORING_SETUP_ATTACH_WQ |
			IORING_SETUP_R_DISABLED))
		return -EINVAL;

	return  io_uring_create(entries, &p, params);
}
```
在io_uring_setup系统调用接口里，主要检查了用户空间传来参数的合法性，然后调用io_uring_create来创建io_uring。

## io_uring_create
```c
static int io_uring_create(unsigned entries, struct io_uring_params *p,
			   struct io_uring_params __user *params)
{
	struct user_struct *user = NULL;
	struct io_ring_ctx *ctx;
	struct file *file;
	bool limit_mem;
	int ret;

    	// entry数量不能为0
	if (!entries)
		return -EINVAL;
   	// IORING_MAX_ENTRIES最大是32768
	if (entries > IORING_MAX_ENTRIES) {
        	// 如果用户不允许缩小entry数量，出错返回
		if (!(p->flags & IORING_SETUP_CLAMP))
			return -EINVAL;

        	// 允许缩小，就设置成最大值
		entries = IORING_MAX_ENTRIES;
	}

	// 提交队列大小向上舍入到2次幂
	p->sq_entries = roundup_pow_of_two(entries);

    	// 如果设置了完成队列的大小，和提交队列的处理一样
	if (p->flags & IORING_SETUP_CQSIZE) {
		if (!p->cq_entries)
			return -EINVAL;
		if (p->cq_entries > IORING_MAX_CQ_ENTRIES) {
			if (!(p->flags & IORING_SETUP_CLAMP))
				return -EINVAL;
			p->cq_entries = IORING_MAX_CQ_ENTRIES;
		}
		p->cq_entries = roundup_pow_of_two(p->cq_entries);
		// 完成队列大小不能小于提交队列大小
		if (p->cq_entries < p->sq_entries)
			return -EINVAL;
	} else {
        	// 如果不设置，完成队列默认是提交队列大小的2倍
		p->cq_entries = 2 * p->sq_entries;
	}

	// 获取当前进程的user引用
	user = get_uid(current_user());

	// 没有IPC_LOCK的权能，就要限制内存
	// CAP_IPC_LOCK：是否允许锁定共享内存
	limit_mem = !capable(CAP_IPC_LOCK);

	if (limit_mem) {
		// ring_pages会算出这两个队列的entryies所占的页面的总数，这里也会修改当前占用页的数量
		// 如果超过了限制，则返回错误
		ret = __io_account_mem(user,
				ring_pages(p->sq_entries, p->cq_entries));
		if (ret) {
			free_uid(user);
			return ret;
		}
	}

    	// 创建io_uring上下文对象，这个函数里只是分配了一个对象并进行基本的初始化
	ctx = io_ring_ctx_alloc(p);
	if (!ctx) {
		// 申请失败，要把限制再回退
		if (limit_mem)
			__io_unaccount_mem(user, ring_pages(p->sq_entries,
								p->cq_entries));
		free_uid(user);
		return -ENOMEM;
	}

    	// 初始化ctx
	ctx->compat = in_compat_syscall();
	ctx->user = user;
	ctx->creds = get_current_cred();
#ifdef CONFIG_AUDIT
	ctx->loginuid = current->loginuid;
	ctx->sessionid = current->sessionid;
#endif
	// 引用创建io_uring的进程
	ctx->sqo_task = get_task_struct(current);

	// 增加内存引用计数
	mmgrab(current->mm);
	ctx->mm_account = current->mm;

#ifdef CONFIG_BLK_CGROUP

    	// blk-cgp相关，不太懂
	/*
	 * The sq thread will belong to the original cgroup it was inited in.
	 * If the cgroup goes offline (e.g. disabling the io controller), then
	 * issued bios will be associated with the closest cgroup later in the
	 * block layer.
	 */
	rcu_read_lock();
	ctx->sqo_blkcg_css = blkcg_css();
	ret = css_tryget_online(ctx->sqo_blkcg_css);
	rcu_read_unlock();
	if (!ret) {
		/* don't init against a dying cgroup, have the user try again */
		ctx->sqo_blkcg_css = NULL;
		ret = -ENODEV;
		goto err;
	}
#endif

	// 这里的io_account_mem主要是把cq, sq所需要的页数加到mm_account->locked_vm
	io_account_mem(ctx, ring_pages(p->sq_entries, p->cq_entries),
		       ACCT_LOCKED);
	// 设置内存限制的标记
	ctx->limit_mem = limit_mem;

    	// 申请提交，完成队列，及sqe
	ret = io_allocate_scq_urings(ctx, p);
	if (ret)
		goto err;

    	// 如果指定了IORING_SETUP_SQPOLL，则创建相应内核线程，否则只创建io_wq
	ret = io_sq_offload_create(ctx, p);
	if (ret)
		goto err;

	// 如果没有指定IORING_SETUP_R_DISABLED时，并且创建了sqd时，启动sqd线程
	if (!(p->flags & IORING_SETUP_R_DISABLED))
		io_sq_offload_start(ctx);

    	// 设置用户参数里的sq_off,设置p->sq_off里的偏移为stuct io_rings里的相关偏移
	memset(&p->sq_off, 0, sizeof(p->sq_off));
	// 提交队列的头,尾
	p->sq_off.head = offsetof(struct io_rings, sq.head);
	p->sq_off.tail = offsetof(struct io_rings, sq.tail);
	p->sq_off.ring_mask = offsetof(struct io_rings, sq_ring_mask);
	p->sq_off.ring_entries = offsetof(struct io_rings, sq_ring_entries);
	p->sq_off.flags = offsetof(struct io_rings, sq_flags);
	p->sq_off.dropped = offsetof(struct io_rings, sq_dropped);

	// sq array的偏移
	// sq_array是紧跟在rings后面的,方便用户层映射
	p->sq_off.array = (char *)ctx->sq_array - (char *)ctx->rings;

    	// 设置用户参数里的cq_off，cq与io_rings里的cq相关偏移一样
	memset(&p->cq_off, 0, sizeof(p->cq_off));

	// 完成队列的头,尾
	p->cq_off.head = offsetof(struct io_rings, cq.head);
	p->cq_off.tail = offsetof(struct io_rings, cq.tail);
	p->cq_off.ring_mask = offsetof(struct io_rings, cq_ring_mask);
	p->cq_off.ring_entries = offsetof(struct io_rings, cq_ring_entries);
	p->cq_off.overflow = offsetof(struct io_rings, cq_overflow);

	// cqes是直接在io_rings结构体末尾的
	p->cq_off.cqes = offsetof(struct io_rings, cqes);
	p->cq_off.flags = offsetof(struct io_rings, cq_flags);

    	// 设置特性
	p->features = IORING_FEAT_SINGLE_MMAP | IORING_FEAT_NODROP |
			IORING_FEAT_SUBMIT_STABLE | IORING_FEAT_RW_CUR_POS |
			IORING_FEAT_CUR_PERSONALITY | IORING_FEAT_FAST_POLL |
			IORING_FEAT_POLL_32BITS;

    	// 把设置完成的p再复制到用户空间的参数
	if (copy_to_user(params, p, sizeof(*p))) {
		ret = -EFAULT;
		goto err;
	}

    	// 创建一个socket，再创建一个file
	file = io_uring_get_file(ctx);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		goto err;
	}

	// 把文件及fd安装到本进程
	ret = io_uring_install_fd(ctx, file);
	if (ret < 0) {
		io_disable_sqo_submit(ctx);
		/* fput will clean it up */
		fput(file);
		return ret;
	}

    	// 调用trace接口
	trace_io_uring_create(ret, ctx, p->sq_entries, p->cq_entries, p->flags);
	return ret;
err:
	io_disable_sqo_submit(ctx);
	io_ring_ctx_wait_and_kill(ctx);
	return ret;
}
```
io_uring_create是setup的主流程:
1. 计算sq_entries, cq_entries的大小
2. 分配io_ring_ctx对象,这是io_uring运行过程的上下文
3. 分配sqe, cqe这些数组空间
4. 如果是sq-poll模式则创建内核线程
5. 创建io_wq对象及相应的worker
6. 如果是sq-poll,且需要启动线程,则启动之
7. 把sq, cq的一些信息写到用户空间的params里,这些信息用来在setup成功后,映射内核内存
8. 创建io_uring对应的文件及socket,这个文件的fd用来与用户空间通信

## 分配io_uring_ctx对象
分配io_uring_ctx很简单,仅仅是分配内存之后,对一些成员进行初始化.
```c
static struct io_ring_ctx *io_ring_ctx_alloc(struct io_uring_params *p)
{
	struct io_ring_ctx *ctx;
	int hash_bits;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	// 创建一个回退请求
	ctx->fallback_req = kmem_cache_alloc(req_cachep, GFP_KERNEL);
	if (!ctx->fallback_req)
		goto err;

	/*
	 * 原文注释：使用比最大cq条目少5位的值，如果完全且均匀分布，则每个哈希列表应提供大约32个条目。
	 */
	// hash_bit是完成队列长度的对数
	hash_bits = ilog2(p->cq_entries);
	hash_bits -= 5;
	if (hash_bits <= 0)
		hash_bits = 1;
	// 取消队列
	ctx->cancel_hash_bits = hash_bits;
	// 分配取消队列的内存
	ctx->cancel_hash = kmalloc((1U << hash_bits) * sizeof(struct hlist_head),
					GFP_KERNEL);
	if (!ctx->cancel_hash)
		goto err;
	// 初始化每个cancel_hash哈希表
	__hash_init(ctx->cancel_hash, 1U << hash_bits);

	// 初始化refs
	if (percpu_ref_init(&ctx->refs, io_ring_ctx_ref_free,
			    PERCPU_REF_ALLOW_REINIT, GFP_KERNEL))
		goto err;

	// 初始化各种列表和锁
	ctx->flags = p->flags;
	init_waitqueue_head(&ctx->sqo_sq_wait);
	INIT_LIST_HEAD(&ctx->sqd_list);
	init_waitqueue_head(&ctx->cq_wait);
	INIT_LIST_HEAD(&ctx->cq_overflow_list);
	init_completion(&ctx->ref_comp);
	init_completion(&ctx->sq_thread_comp);
	xa_init_flags(&ctx->io_buffers, XA_FLAGS_ALLOC1);
	xa_init_flags(&ctx->personalities, XA_FLAGS_ALLOC1);
	mutex_init(&ctx->uring_lock);
	init_waitqueue_head(&ctx->wait);
	spin_lock_init(&ctx->completion_lock);
	INIT_LIST_HEAD(&ctx->iopoll_list);
	INIT_LIST_HEAD(&ctx->defer_list);
	INIT_LIST_HEAD(&ctx->timeout_list);
	spin_lock_init(&ctx->inflight_lock);
	INIT_LIST_HEAD(&ctx->inflight_list);
	INIT_DELAYED_WORK(&ctx->file_put_work, io_file_put_work);
	init_llist_head(&ctx->file_put_llist);
	return ctx;
err:
	if (ctx->fallback_req)
		kmem_cache_free(req_cachep, ctx->fallback_req);
	kfree(ctx->cancel_hash);
	kfree(ctx);
	return NULL;
}
```
## 分配sq, cq内存
这里主要分配ctx->rings内存,然后再分配sqe, sq_array对应的内存.
```c
static int io_allocate_scq_urings(struct io_ring_ctx *ctx,
				  struct io_uring_params *p)
{
	struct io_rings *rings;
	size_t size, sq_array_offset;

	// 分别设置sq, cq的大小
	ctx->sq_entries = p->sq_entries;
	ctx->cq_entries = p->cq_entries;

	// struct io_urings的末尾是cqes数组, cqes紧接着就是sq_array, sqes数组在ctx里

	// 算出出提交，完成队列总共占用空间大小
	// sq_array_offset返回的是sq_array的起点
	// 这里返回的size是io_rings的大小 + p->cq_entries + p->sq_entries
	size = rings_size(p->sq_entries, p->cq_entries, &sq_array_offset);
	if (size == SIZE_MAX)
		return -EOVERFLOW;

	// io_mem_alloc直接调用的alloc_page，分配size对应的页的数量
	rings = io_mem_alloc(size);
	if (!rings)
		return -ENOMEM;

	ctx->rings = rings;
	// sq数组的起点就紧跟在cqes后面
	ctx->sq_array = (u32 *)((char *)rings + sq_array_offset);

	// sq, cq环长度的掩码
	rings->sq_ring_mask = p->sq_entries - 1;
	rings->cq_ring_mask = p->cq_entries - 1;

	// sq, cq entry的数量
	rings->sq_ring_entries = p->sq_entries;
	rings->cq_ring_entries = p->cq_entries;

	ctx->sq_mask = rings->sq_ring_mask;
	ctx->cq_mask = rings->cq_ring_mask;

	// sqes的大小
	size = array_size(sizeof(struct io_uring_sqe), p->sq_entries);
	// SIZE_MAX是size_t的最大值
	if (size == SIZE_MAX) {
		io_mem_free(ctx->rings);
		ctx->rings = NULL;
		return -EOVERFLOW;
	}

	// 给sqes申请内存
	ctx->sq_sqes = io_mem_alloc(size);
	if (!ctx->sq_sqes) {
		io_mem_free(ctx->rings);
		ctx->rings = NULL;
		return -ENOMEM;
	}

	return 0;
}

static unsigned long rings_size(unsigned sq_entries, unsigned cq_entries,
				size_t *sq_offset)
{
	struct io_rings *rings;
	size_t off, sq_array_size;

	// struct_size会计算出包含末尾数组的大小
	off = struct_size(rings, cqes, cq_entries);
	if (off == SIZE_MAX)
		return SIZE_MAX;

#ifdef CONFIG_SMP
	// 对齐到cache大小
	off = ALIGN(off, SMP_CACHE_BYTES);
	if (off == 0)
		return SIZE_MAX;
#endif

	// 提交队列的偏移
	if (sq_offset)
		*sq_offset = off;

	// sq是一个二维数据，它的大小是sizeof(u32) * sq_entries
	sq_array_size = array_size(sizeof(u32), sq_entries);
	if (sq_array_size == SIZE_MAX)
		return SIZE_MAX;

	// 这个相当于off += sq_array_size
	if (check_add_overflow(off, sq_array_size, &off))
		return SIZE_MAX;

	return off;
}
```
主要是给struct io_rings分配内存,以及sqe, cqe, sq_array等.


## 创建sq-poll线程
```
static int io_sq_offload_create(struct io_ring_ctx *ctx,
				struct io_uring_params *p)
{
	int ret;

	if (ctx->flags & IORING_SETUP_SQPOLL) {
		// 有这个标志的创建线程
		struct io_sq_data *sqd;

		ret = -EPERM;
		// 使用sqpoll模式，需要root权限
		if (!capable(CAP_SYS_ADMIN))
			goto err;

		// 创建或使用已有的sqd
		// 使用已有的sqd需要IORING_SETUP_ATTACH_WQ标志
		sqd = io_get_sq_data(p);
		if (IS_ERR(sqd)) {
			ret = PTR_ERR(sqd);
			goto err;
		}

		ctx->sq_data = sqd;
		// 暂停当前线程。park/unpark是精确的阻塞/启动当前线程
		io_sq_thread_park(sqd);
		mutex_lock(&sqd->ctx_lock);
		// 把ctx加到sqd的ctx_new_list列表
		list_add(&ctx->sqd_list, &sqd->ctx_new_list);
		mutex_unlock(&sqd->ctx_lock);
		// 恢复当前线程
		io_sq_thread_unpark(sqd);

		// 线程空闲时间，如果没设置，默认是1秒
		ctx->sq_thread_idle = msecs_to_jiffies(p->sq_thread_idle);
		if (!ctx->sq_thread_idle)
			ctx->sq_thread_idle = HZ;

		// 如果已经创建了thread，就直接完成
		if (sqd->thread)
			goto done;

		// 走到这里表示还没创建线程

		if (p->flags & IORING_SETUP_SQ_AFF) {
			// IORING_SETUP_SQ_AFF表示在特定的cpu上执行

			// 用户指定的cpu
			int cpu = p->sq_thread_cpu;

			ret = -EINVAL;
			// cpu下标错误
			if (cpu >= nr_cpu_ids)
				goto err;
			// cpu不在线
			if (!cpu_online(cpu))
				goto err;

			sqd->thread = kthread_create_on_cpu(io_sq_thread, sqd,
							cpu, "io_uring-sq");
		} else {
			sqd->thread = kthread_create(io_sq_thread, sqd,
							"io_uring-sq");
		}
		if (IS_ERR(sqd->thread)) {
			ret = PTR_ERR(sqd->thread);
			sqd->thread = NULL;
			goto err;
		}
		// 创建当前线程的io_uring上下文
		ret = io_uring_alloc_task_context(sqd->thread);
		if (ret)
			goto err;
	} else if (p->flags & IORING_SETUP_SQ_AFF) {
		// 非SQPOLL模式下，不能使用这个标志
		ret = -EINVAL;
		goto err;
	}

done:
	// 创建io_wq
	ret = io_init_wq_offload(ctx, p);
	if (ret)
		goto err;

	return 0;
err:
	io_finish_async(ctx);
	return ret;
}
```
在指定了IORING_SETUP_SQPOLL标志时,会创建相应的内核线程.主流程如下：
1. 判断是否有root权限
2. 创建或使用已有sq_data
3. 把ctx上下文加到sqd列表
4. 创建内核线程
5. 创建内核线程的io_uring_task

## 创建io_wq
不管有没有指定sq-poll模式,都要创建io_wq,io_wq这个是用来做异步任务的.
```c
static int io_init_wq_offload(struct io_ring_ctx *ctx,
			      struct io_uring_params *p)
{
	struct io_wq_data data;
	struct fd f;
	struct io_ring_ctx *ctx_attach;
	unsigned int concurrency;
	int ret = 0;

	data.user = ctx->user;
	// 释放任务回调
	data.free_work = io_free_work;
	// 提交任务回调
	data.do_work = io_wq_submit_work;

	// IORING_SETUP_ATTACH_WQ是要使用已有的io_uring的wq里，也就是
	// 使用wq_fd的所指定的已经创建了的文件
	if (!(p->flags & IORING_SETUP_ATTACH_WQ)) {
		// 没指定的话就新创建一个io_wq

		// 并发数量是: sqe数量和4倍在线cpu的最小值
		concurrency = min(ctx->sq_entries, 4 * num_online_cpus());

		// 创建 io_wq，执行异步任务的wq
		ctx->io_wq = io_wq_create(concurrency, &data);
		if (IS_ERR(ctx->io_wq)) {
			ret = PTR_ERR(ctx->io_wq);
			ctx->io_wq = NULL;
		}
		return ret;
	}

	// 走到这里说明要与当前已有的io_uring使用相同的io_wq

	// 获取要添加的io_uring对应的文件
	f = fdget(p->wq_fd);
	if (!f.file)
		return -EBADF;

	// 必须是io_uring文件
	if (f.file->f_op != &io_uring_fops) {
		ret = -EINVAL;
		goto out_fput;
	}

	// 要添加的io_uring上下文
	ctx_attach = f.file->private_data;

	// 在这里面会判断:要添加的io_uring必须和data里的do_work, free_work是一个函数,
	// 要就是必须要在同一个进程里才能用这种模式,因为不同进程里这2个函数的地址肯定是不一样的
	if (!io_wq_get(ctx_attach->io_wq, &data)) {
		ret = -EINVAL;
		goto out_fput;
	}

	// 使用wq_fd对应的io_wq
	ctx->io_wq = ctx_attach->io_wq;
out_fput:
	fdput(f);
	return ret;
}
```

## 创建,安装文件
```c
static struct file *io_uring_get_file(struct io_ring_ctx *ctx)
{
	struct file *file;
#if defined(CONFIG_UNIX)
	int ret;
	// 创建一个unix sockets
	ret = sock_create_kern(&init_net, PF_UNIX, SOCK_RAW, IPPROTO_IP,
				&ctx->ring_sock);
	if (ret)
		return ERR_PTR(ret);
#endif

	// 创建一个io_uring的匿名文件
	// 文件的操作函数表是io_uring_fops, 在io_uring里用这个来识别是否是io_uring文件
	// 这个文件是可读写, 并且在exec时会自动关闭
	file = anon_inode_getfile("[io_uring]", &io_uring_fops, ctx,
					O_RDWR | O_CLOEXEC);
#if defined(CONFIG_UNIX)
	if (IS_ERR(file)) {
		sock_release(ctx->ring_sock);
		ctx->ring_sock = NULL;
	} else {
		// 设置socket文件?
		ctx->ring_sock->file = file;
	}
#endif
	return file;
}

static int io_uring_install_fd(struct io_ring_ctx *ctx, struct file *file)
{
	int ret, fd;

	//  获取未使用的fd
	fd = get_unused_fd_flags(O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return fd;

	// 把文件加到task的io_uring列表
	ret = io_uring_add_task_file(ctx, file);
	if (ret) {
		put_unused_fd(fd);
		return ret;
	}
	// 把文件加到进程文件表里
	fd_install(fd, file);
	return fd;
}

static int io_uring_add_task_file(struct io_ring_ctx *ctx, struct file *file)
{
	struct io_uring_task *tctx = current->io_uring;
	int ret;

	// 当前进程还没创建io_uring_task上下文，则创建之
	if (unlikely(!tctx)) {
		ret = io_uring_alloc_task_context(current);
		if (unlikely(ret))
			return ret;
		tctx = current->io_uring;
	}

	// 上次使用的io_uring是不是当前文件, 如果是的话就不用设置了
	if (tctx->last != file) {

		// 先从基数树里找file
		void *old = xa_load(&tctx->xa, (unsigned long)file);

		// 文件还没有添加，则添加到基数树里
		if (!old) {
			get_file(file);
			ret = xa_err(xa_store(&tctx->xa, (unsigned long)file,
						file, GFP_KERNEL));
			if (ret) {
				fput(file);
				return ret;
			}
		}
		// 设置最后使用的file
		tctx->last = file;
	}

	// 设置sq poll状态
	if (!tctx->sqpoll && (ctx->flags & IORING_SETUP_SQPOLL))
		tctx->sqpoll = true;

	return 0;
}

static int io_uring_alloc_task_context(struct task_struct *task)
{
	struct io_uring_task *tctx;
	int ret;

	// 分配内存
	tctx = kmalloc(sizeof(*tctx), GFP_KERNEL);
	if (unlikely(!tctx))
		return -ENOMEM;

	// 初始化inflight percpu
	ret = percpu_counter_init(&tctx->inflight, 0, GFP_KERNEL);
	if (unlikely(ret)) {
		kfree(tctx);
		return ret;
	}

	// 初始化基数树
	xa_init(&tctx->xa);
	init_waitqueue_head(&tctx->wait);
	tctx->last = NULL;
	atomic_set(&tctx->in_idle, 0);
	tctx->sqpoll = false;

	// 初始化进程相关的数据
	io_init_identity(&tctx->__identity);
	tctx->identity = &tctx->__identity;
	task->io_uring = tctx;
	return 0;
}
```
该流程比较简单,主要是创建一个普通文件和一个socket文件,并把普通文件安装在进程的文件列表和进程的io_uring_task的基数树里.