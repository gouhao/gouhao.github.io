# file.c源码阅读

1. 数据结构
```c
struct fdtable {
	unsigned int max_fds; // fd数组最多能存的file数组
	struct file __rcu **fd; // struct file数组数量
	unsigned long *close_on_exec; // 执行时关闭位图
	unsigned long *open_fds; // 已打开文件位图
	unsigned long *full_fds_bits; // 一个long全部打开的位图, 每1位代表一个long数量的文件是否打开
	struct rcu_head rcu;
};
```

2. 源码
```c
// 打开文件数量:默认1048576
unsigned int sysctl_nr_open __read_mostly = 1024*1024;
// 最小打开数量:64个
unsigned int sysctl_nr_open_min = BITS_PER_LONG;
/* our min() is unusable in constant expressions ;-/ */
#define __const_min(x, y) ((x) < (y) ? (x) : (y))
// 最大能打开的数量是int的最大值
unsigned int sysctl_nr_open_max =
	__const_min(INT_MAX, ~(size_t)0/sizeof(void *)) & -BITS_PER_LONG;

// 释放fd表
static void __free_fdtable(struct fdtable *fdt)
{
	// 释放file数组
	kvfree(fdt->fd);
	// 释放位图. 这里释放的是close_on_exec, open_fds, full_fds_bits
	// 因为在分配内存的时候这三个内存是连续的,open_fds使用的是分配内存的第一块内存,
	// 所以只需要释放open_fds
	kvfree(fdt->open_fds);
	// 释放fdt本身
	kfree(fdt);
}

// rcu释放回调
static void free_fdtable_rcu(struct rcu_head *rcu)
{
	__free_fdtable(container_of(rcu, struct fdtable, rcu));
}

// 有多少个long的bit, 一个bit代表一个long
#define BITBIT_NR(nr)	BITS_TO_LONGS(BITS_TO_LONGS(nr))
// bitbit对应的内存大小
#define BITBIT_SIZE(nr)	(BITBIT_NR(nr) * sizeof(long))

/*
 * 从旧表向新表复制count个fd数量,并清除多余空间,如果有的话. 这里不复制file指针.
 * 调用的时候需要files的spinlock.
 */
static void copy_fd_bitmaps(struct fdtable *nfdt, struct fdtable *ofdt,
			    unsigned int count)
{
	unsigned int cpy, set;

	// 把count转成字节数量.这里count表示要复制多少个fd, 也就是多少位
	cpy = count / BITS_PER_BYTE;
	// 需要清0的字节数量
	set = (nfdt->max_fds - count) / BITS_PER_BYTE;

	// 复制老数据,并清空多余的数据
	memcpy(nfdt->open_fds, ofdt->open_fds, cpy);
	memset((char *)nfdt->open_fds + cpy, 0, set);
	memcpy(nfdt->close_on_exec, ofdt->close_on_exec, cpy);
	memset((char *)nfdt->close_on_exec + cpy, 0, set);

	// count对应的long-bit的数量
	cpy = BITBIT_SIZE(count);
	// 需要清空的long-bit数量
	set = BITBIT_SIZE(nfdt->max_fds) - cpy;
	// 同上, 复制+清空
	memcpy(nfdt->full_fds_bits, ofdt->full_fds_bits, cpy);
	memset((char *)nfdt->full_fds_bits + cpy, 0, set);
}

/*
 * 从旧表向新表复制所有的文件描述符, 扩展表并且清除多余空间. 调用时需要files->spinlock
 */
static void copy_fdtable(struct fdtable *nfdt, struct fdtable *ofdt)
{
	size_t cpy, set;

	// 新表的最大值小于旧表的最大值, 怎么可能呢?
	BUG_ON(nfdt->max_fds < ofdt->max_fds);

	// 把要复制的file结构数量,转成字节
	cpy = ofdt->max_fds * sizeof(struct file *);
	// 需要清空的多余数量
	set = (nfdt->max_fds - ofdt->max_fds) * sizeof(struct file *);

	// 复制并清除
	memcpy(nfdt->fd, ofdt->fd, cpy);
	memset((char *)nfdt->fd + cpy, 0, set);

	// 复制位图
	copy_fd_bitmaps(nfdt, ofdt, ofdt->max_fds);
}

// 分配fd表
static struct fdtable * alloc_fdtable(unsigned int nr)
{
	struct fdtable *fdt;
	void *data;

	/*
	 * 计算出多少在这个fdtable里我们想要支持多少个fd, 分配步骤取决于fdarray的大小, 因为它
	 * 的增长远快于其他动态数据.我们试图装fdarray放入合适的page块里: 从1024B开始, 然后以2
	 * 的幂增长.
	 */
	// todo: 没太看懂
	nr /= (1024 / sizeof(struct file *));
	nr = roundup_pow_of_two(nr + 1);
	nr *= (1024 / sizeof(struct file *));

	/*
	 * 注意: 如果 sysctl_nr_open 被设置的低于expand_files和这里的值, 上面算出来的nr可能会低
	 * 于传进来的值. 在caller那里处理会更方便
	 *
	 * 我们要确保nr保持为BITS_PER_LONG的倍数, 否则下面的位图会不好处理
	 */
	// 把nr的值限制到sysctl_nr_open范围内
	if (unlikely(nr > sysctl_nr_open))
		nr = ((sysctl_nr_open - 1) | (BITS_PER_LONG - 1)) + 1;

	// 分配 fdt
	fdt = kmalloc(sizeof(struct fdtable), GFP_KERNEL_ACCOUNT);
	if (!fdt)
		goto out;
	// 设置新的最大fd值
	fdt->max_fds = nr;

	// 分配fdarray
	data = kvmalloc_array(nr, sizeof(struct file *), GFP_KERNEL_ACCOUNT);
	if (!data)
		goto out_fdt;
	fdt->fd = data;

	// 分配位图数据块, 这里分配的数量是2个nr的字节再加上bitbit-nr.前两个是给open_fds, close_on_exec用的
	// 最后的bitbit-nr是给full_fds_bits用的
	data = kvmalloc(max_t(size_t,
				 2 * nr / BITS_PER_BYTE + BITBIT_SIZE(nr), L1_CACHE_BYTES),
				 GFP_KERNEL_ACCOUNT);
	if (!data)
		goto out_arr;
	
	// 设置3个位图地址, 依次为: open_fds, close_on_exec, full_fds_bits
	fdt->open_fds = data;
	data += nr / BITS_PER_BYTE;
	fdt->close_on_exec = data;
	data += nr / BITS_PER_BYTE;
	fdt->full_fds_bits = data;

	return fdt;

out_arr:
	kvfree(fdt->fd);
out_fdt:
	kfree(fdt);
out:
	return NULL;
}

/*
 * 扩展文件描述符表
 * 这个函数将会分配一个新的fdtable, 以及给定大小的fd数组和fdset
 * 出错返回小于0的错误码, 1表示成功完成
 * 进这个函数的时候应该锁files->file_lock, 退出时也持有
 */
static int expand_fdtable(struct files_struct *files, unsigned int nr)
	__releases(files->file_lock)
	__acquires(files->file_lock)
{
	struct fdtable *new_fdt, *cur_fdt;

	spin_unlock(&files->file_lock);
	// 分配一个fdtable对象, 及里面的数组, 位图
	new_fdt = alloc_fdtable(nr);

	/* 确保所有的__fd_install()能看见resize_in_progress
	 * 或者已经完成了他们的 rcu_read_lock_sched() 代码区间
	 */
	if (atomic_read(&files->count) > 1)
		synchronize_rcu();

	// 加锁
	spin_lock(&files->file_lock);
	// todo: 为啥加锁之后才叛空
	if (!new_fdt)
		return -ENOMEM;
	/*
	 * 极端情况下不太可能的竞争 - sysctl_nr_open 在caller调用时和
	 * alloc_fdtable之间被减小, 简单的处理它...
	 */
	if (unlikely(new_fdt->max_fds <= nr)) {
		__free_fdtable(new_fdt);
		return -EMFILE;
	}
	// 获取老的fdt
	cur_fdt = files_fdtable(files);
	// nr不可能小于之前的老的max_fds
	BUG_ON(nr < cur_fdt->max_fds);

	// 从老的fdt给新的fdt复制数据
	copy_fdtable(new_fdt, cur_fdt);
	// 设置新表
	rcu_assign_pointer(files->fdt, new_fdt);

	// fdtab是静态数据, 如果是新分配的数据,才调用free_fdtable_rcu来释放内存
	if (cur_fdt != &files->fdtab)
		call_rcu(&cur_fdt->rcu, free_fdtable_rcu);
	/* 与__fd_install()里的smp_rmb()对应的 */
	smp_wmb();
	return 1;
}

/*
 * 扩展文件
 * 这个函数将扩展file数据结构, 如果需要的大小超过了当前的容量就扩展空间
 * 如果出错返回小于0的错误码, 0表示什么都没做, 1表示文件被扩展了而且程序可能会被阻塞
 * 进这个函数应该锁files->file_lock, 一直到退出也会持有锁
 */
static int expand_files(struct files_struct *files, unsigned int nr)
	__releases(files->file_lock)
	__acquires(files->file_lock)
{
	struct fdtable *fdt;
	int expanded = 0;

repeat:
	// 获取fdt
	fdt = files_fdtable(files);

	/* 小于max_fds就不用扩展了, 返回0 */
	if (nr < fdt->max_fds)
		return expanded;

	/* 超过了最大打开数量, 也不能扩展 */
	if (nr >= sysctl_nr_open)
		return -EMFILE;

	// 当前文件正在扩展中
	if (unlikely(files->resize_in_progress)) {
		// 先释放锁
		spin_unlock(&files->file_lock);
		expanded = 1;

		// 等待扩展结束
		wait_event(files->resize_wait, !files->resize_in_progress);
		// 加锁之后再重试.
		spin_lock(&files->file_lock);
		goto repeat;
	}

	// 正在扩展标志
	files->resize_in_progress = true;
	// 扩展表
	expanded = expand_fdtable(files, nr);
	// 取消标志
	files->resize_in_progress = false;

	// 唤醒所有等待的人, 与上面的等待对应
	wake_up_all(&files->resize_wait);
	return expanded;
}

// 设置执行时关闭位
static inline void __set_close_on_exec(unsigned int fd, struct fdtable *fdt)
{
	__set_bit(fd, fdt->close_on_exec);
}

// 清除执行时关闭位
static inline void __clear_close_on_exec(unsigned int fd, struct fdtable *fdt)
{
	if (test_bit(fd, fdt->close_on_exec))
		__clear_bit(fd, fdt->close_on_exec);
}

// 设置打开文件位
static inline void __set_open_fd(unsigned int fd, struct fdtable *fdt)
{
	// 先设置打开文件位
	__set_bit(fd, fdt->open_fds);
	// 该位对应的long
	fd /= BITS_PER_LONG;

	// full_fds_bits里的每1位表示 open_fds 里的一整个long是否被设置,
	// 在查找fd时,可以加速查找
	// 如果整个long都被设置了,则设置full_fds
	if (!~fdt->open_fds[fd])
		__set_bit(fd, fdt->full_fds_bits);
}

// 清除打开文件位
static inline void __clear_open_fd(unsigned int fd, struct fdtable *fdt)
{
	// 清除已打开位
	__clear_bit(fd, fdt->open_fds);
	// 直接清除对应的full_fds, 因为其中1位置空, full_fds肯定不会是全1
	__clear_bit(fd / BITS_PER_LONG, fdt->full_fds_bits);
}

// 统计打开文件数量
static unsigned int count_open_files(struct fdtable *fdt)
{
	// 最大的fds
	unsigned int size = fdt->max_fds;
	unsigned int i;

	// 找到最后被设置的fd
	for (i = size / BITS_PER_LONG; i > 0; ) {
		if (fdt->open_fds[--i])
			break;
	}
	// 总的已打开文件数
	// todo: 这个判断好像不准吧，并不是每个long全设置
	i = (i + 1) * BITS_PER_LONG;
	return i;
}

// 检查fdtable的大小
static unsigned int sane_fdtable_size(struct fdtable *fdt, unsigned int max_fds)
{
	unsigned int count;

	// 已打开文件数量
	count = count_open_files(fdt);

	// NR_OPEN_DEFAULT 是 64
	if (max_fds < NR_OPEN_DEFAULT)
		max_fds = NR_OPEN_DEFAULT;
	// 选一个较小值
	return min(count, max_fds);
}

/*
 * 分配一个新的files_struct结构，并从传进来的老的files_struct结构里复制
 * 内容到新分配的结构里.
 * 当返回NULL时, errorp里会有值
 */
struct files_struct *dup_fd(struct files_struct *oldf, unsigned int max_fds, int *errorp)
{
	struct files_struct *newf;
	struct file **old_fds, **new_fds;
	unsigned int open_files, i;
	struct fdtable *old_fdt, *new_fdt;

	*errorp = -ENOMEM;
	// 分配一个新的files_struct
	newf = kmem_cache_alloc(files_cachep, GFP_KERNEL);
	if (!newf)
		goto out;

	// 设置引用为1
	atomic_set(&newf->count, 1);

	// 初始化newf里的各种字段
	spin_lock_init(&newf->file_lock);
	newf->resize_in_progress = false;
	init_waitqueue_head(&newf->resize_wait);
	newf->next_fd = 0;
	new_fdt = &newf->fdtab;
	new_fdt->max_fds = NR_OPEN_DEFAULT;
	new_fdt->close_on_exec = newf->close_on_exec_init;
	new_fdt->open_fds = newf->open_fds_init;
	new_fdt->full_fds_bits = newf->full_fds_bits_init;
	new_fdt->fd = &newf->fd_array[0];

	// 注意:这里加的是oldf的锁
	spin_lock(&oldf->file_lock);


	// 这个是使用rcu获取old_fdt
	old_fdt = files_fdtable(oldf);
	
	// old_fdt里已打开的文件数量
	open_files = sane_fdtable_size(old_fdt, max_fds);

	/*
	 * 检查我们是否需要分配一个新的更大的fd数组和fd集合
	 */
	// 已打开的文件数量大于新的max_fds才会分配, 因为上面是刚分配的, 所以max_fds是64
	// 这个循环只有在非常极端的情况下才会走, 在调用这个函数期间, old_fdt发生了改变
	while (unlikely(open_files > new_fdt->max_fds)) {
		// 因为new_fdt还没用,所以不用加锁
		spin_unlock(&oldf->file_lock);

		// 如果new_fdt是动态分配的,则释放它的内存
		if (new_fdt != &newf->fdtab)
			__free_fdtable(new_fdt);

		// 新分配一个fdt, todo: 为什么要open_files - 1 ?
		new_fdt = alloc_fdtable(open_files - 1);
		// 分配失败
		if (!new_fdt) {
			*errorp = -ENOMEM;
			goto out_release;
		}

		/* 超过了 sysctl_nr_open 的数量, 直接返回 */
		if (unlikely(new_fdt->max_fds < open_files)) {
			__free_fdtable(new_fdt);
			*errorp = -EMFILE;
			goto out_release;
		}

		/*
		 * 重新获取oldf的锁, 因为我们要用oldf的fdtable, 因为fdt里的文件数
		 * 可能已经变了, 我们需要最新的指针
		 */
		spin_lock(&oldf->file_lock);
		old_fdt = files_fdtable(oldf);
		// 再获取已打开文件的数量
		open_files = sane_fdtable_size(old_fdt, max_fds);
	}

	// 走到这儿的时候, oldf的锁还在

	// 复制位图数据
	copy_fd_bitmaps(new_fdt, old_fdt, open_files);

	// 新旧老的fd数组
	old_fds = old_fdt->fd;
	new_fds = new_fdt->fd;

	// 复制file指针
	for (i = open_files; i != 0; i--) {
		struct file *f = *old_fds++;

		// 如果file有值,就增加它的指针
		if (f) {
			get_file(f);
		} else {
			/*
			 * 有可能位图上有值, 但数组里却是空的, 有可能并发线程只到达了
			 * open的一半,if a sibling thread 所以确保在新的进程里fd
			 * 是可用的.
			 * todo: 不用并发,这里也有可能是空呀!!
			 */
			__clear_open_fd(open_files - i, new_fdt);
		}
		// 给新的数组里设置文件的指针, 有可能是NULL
		rcu_assign_pointer(*new_fds++, f);
	}
	spin_unlock(&oldf->file_lock);

	// 清除其余的字节
	memset(new_fds, 0, (new_fdt->max_fds - open_files) * sizeof(struct file *));

	// 重新设置newf的fdt
	rcu_assign_pointer(newf->fdt, new_fdt);

	return newf;

out_release:
	kmem_cache_free(files_cachep, newf);
out:
	return NULL;
}

// 关闭fdt里的所有文件
static struct fdtable *close_files(struct files_struct * files)
{
	/*
	 * 在这里不用rcu lock和file_lock是安全的, 因为这里是最后一次引用
	 * files这个结构
	 */
	struct fdtable *fdt = rcu_dereference_raw(files->fdt);
	unsigned int i, j = 0;

	// 遍历每一个位, 然后关闭文件
	for (;;) {
		unsigned long set;

		// i保存的是fd, j保存的是第几个long
		i = j * BITS_PER_LONG;
		// 大于max则退出
		if (i >= fdt->max_fds)
			break;
		// 取出第j个long
		set = fdt->open_fds[j++];

		// 遍历该long里每一位
		while (set) {
			// 如果这一位上有值
			if (set & 1) {
				// 给fd[i]设置NULL, 并返回file
				struct file * file = xchg(&fdt->fd[i], NULL);
				// 关闭文件
				if (file) {
					filp_close(file, files);
					cond_resched();
				}
			}
			// fd递增
			i++;
			// 位图右移
			set >>= 1;
		}
	}

	return fdt;
}

// 获取进程的files_struct
struct files_struct *get_files_struct(struct task_struct *task)
{
	struct files_struct *files;

	// 锁的是task->alloc_lock
	task_lock(task);

	// 递增引用计数
	files = task->files;
	if (files)
		atomic_inc(&files->count);
	task_unlock(task);

	return files;
}

// 释放进程的files_struct
void put_files_struct(struct files_struct *files)
{
	// 减少文件引用,如果达到0, 则释放
	if (atomic_dec_and_test(&files->count)) {
		// 关闭所有文件
		struct fdtable *fdt = close_files(files);

		// 如果不是数据结构里内置的fdt, 则释放其内存
		if (fdt != &files->fdtab)
			__free_fdtable(fdt);
		// 释放files内存
		kmem_cache_free(files_cachep, files);
	}
}

// 替换进程里的files结构
void reset_files_struct(struct files_struct *files)
{
	struct task_struct *tsk = current;
	struct files_struct *old;

	// 老的files
	old = tsk->files;
	// 锁住进程
	task_lock(tsk);
	// 设置新的files
	tsk->files = files;
	task_unlock(tsk);
	// 释放老的files
	put_files_struct(old);
}

// 退出进程的files
void exit_files(struct task_struct *tsk)
{
	// 进程的files
	struct files_struct * files = tsk->files;

	if (files) {
		// 锁住进程
		task_lock(tsk);
		// 进程的file置空
		tsk->files = NULL;
		task_unlock(tsk);
		// 释放files
		put_files_struct(files);
	}
}

// init进程用的, 设置了fdt指向内部的数据, 初始化一些锁
struct files_struct init_files = {
	.count		= ATOMIC_INIT(1),
	.fdt		= &init_files.fdtab,
	.fdtab		= {
		.max_fds	= NR_OPEN_DEFAULT,
		.fd		= &init_files.fd_array[0],
		.close_on_exec	= init_files.close_on_exec_init,
		.open_fds	= init_files.open_fds_init,
		.full_fds_bits	= init_files.full_fds_bits_init,
	},
	.file_lock	= __SPIN_LOCK_UNLOCKED(init_files.file_lock),
	.resize_wait	= __WAIT_QUEUE_HEAD_INITIALIZER(init_files.resize_wait),
};

// 找下一个fd, start是起点
static unsigned int find_next_fd(struct fdtable *fdt, unsigned int start)
{
	// 当前fdt最大支持的fd
	unsigned int maxfd = fdt->max_fds;
	// 有多少个long
	unsigned int maxbit = maxfd / BITS_PER_LONG;
	// 起点所在的long
	unsigned int bitbit = start / BITS_PER_LONG;

	// 先从full里找一个空的位, full里一个位为0, 说明整个long还没有分配完
	// full里一位代表一个long, 所以最后乘以 BITS_PER_LONG
	bitbit = find_next_zero_bit(fdt->full_fds_bits, maxbit, bitbit) * BITS_PER_LONG;
	// 大于maxfd说明所有位都用了
	if (bitbit > maxfd)
		return maxfd;
	// 如果大于start, 则从bitbit开始. 说明start已经被用了
	if (bitbit > start)
		start = bitbit;
	// 在open里从start开始找一个空闲的位
	return find_next_zero_bit(fdt->open_fds, maxfd, start);
}

/*
 * 分配一个文件描述符并置位
 */
int __alloc_fd(struct files_struct *files,
	       unsigned start, unsigned end, unsigned flags)
{
	unsigned int fd;
	int error;
	struct fdtable *fdt;

	spin_lock(&files->file_lock);
repeat:
	fdt = files_fdtable(files);
	// 从start开始找
	fd = start;
	// 如果小于next, 则从next开始找
	// next里放的是下一个待分配的fd, 加速查找
	if (fd < files->next_fd)
		fd = files->next_fd;

	// 找下一个fd
	if (fd < fdt->max_fds)
		fd = find_next_fd(fdt, fd);

	/*
	 * 注意: 对于clone的任务共享files结构, 这个测试将会
	 * 限制总的打开文件的数量
	 */
	error = -EMFILE;
	if (fd >= end)
		goto out;

	// 扩展files结构
	error = expand_files(files, fd);
	// 小于0表示出错了
	if (error < 0)
		goto out;

	/*
	 * 大于0说明扩展了, 有可能会阻塞, 需要重试
	 * 因为fdt有可能已经变了
	 */
	if (error)
		goto repeat;

	// next_fd置为start的下一位, 当然下一位有可能已经用了
	if (start <= files->next_fd)
		files->next_fd = fd + 1;

	// 在open位图上设置fd为1
	__set_open_fd(fd, fdt);

	// 根据是否有执行时关闭, 在相应位图上执行操作
	if (flags & O_CLOEXEC)
		__set_close_on_exec(fd, fdt);
	else
		__clear_close_on_exec(fd, fdt);
	// 设置结果
	error = fd;

	// 如果不为空, 则强制置空
#if 1
	/* Sanity check */
	if (rcu_access_pointer(fdt->fd[fd]) != NULL) {
		printk(KERN_WARNING "alloc_fd: slot %d not NULL!\n", fd);
		rcu_assign_pointer(fdt->fd[fd], NULL);
	}
#endif

out:
	spin_unlock(&files->file_lock);
	return error;
}

// 分配fd, 这个可以指定搜索的起点
static int alloc_fd(unsigned start, unsigned flags)
{
	// 限制值为rlimit(RLIMIT_NOFILE): 进程可打开的文件数量
	return __alloc_fd(current->files, start, rlimit(RLIMIT_NOFILE), flags);
}

// 获取未使用的fd, 这个从0开始搜索
int __get_unused_fd_flags(unsigned flags, unsigned long nofile)
{
	return __alloc_fd(current->files, 0, nofile, flags);
}

// 获取未使用的fd, 这个从0开始搜索, 限制是rlimit(RLIMIT_NOFILE), 
int get_unused_fd_flags(unsigned flags)
{
	return __get_unused_fd_flags(flags, rlimit(RLIMIT_NOFILE));
}
EXPORT_SYMBOL(get_unused_fd_flags);

// 释放未使用的fd
static void __put_unused_fd(struct files_struct *files, unsigned int fd)
{
	// 获取fdt, 使用files_fdtable必须持有file_lock锁
	struct fdtable *fdt = files_fdtable(files);

	// 清除open和full上的位图
	__clear_open_fd(fd, fdt);
	// 设置next_fd, 如果小于next的话
	if (fd < files->next_fd)
		files->next_fd = fd;
}

// 导出接口
void put_unused_fd(unsigned int fd)
{
	struct files_struct *files = current->files;
	// 加锁之后直接调用上面的函数
	spin_lock(&files->file_lock);
	__put_unused_fd(files, fd);
	spin_unlock(&files->file_lock);
}
EXPORT_SYMBOL(put_unused_fd);

/*
 * 在fd数组安装一个文件指针
 *
 * vfs里充满了在设置位图和安装文件之间不持有files_lock的地方.
 * 在任何一点, 我们都很容易受到dup2在我们之间安装一个文件到数组里.
 * 此时,我们需要检测这种情况, 并且要fput file结构
 *
 * 它应该永远不发生. 如果我们允许dup2这样做, 糟糕的事将会发生.
 *
 * 注意: __fd_install()是非常低级的函数; 不要用它, 除非API不好用.
 * files必须是current->files或者是别人从get_files_struct(current)获取的
 * 否则将会发生不好的事. 通常你应该使用fd_install()来代替.
 */

void __fd_install(struct files_struct *files, unsigned int fd,
		struct file *file)
{
	struct fdtable *fdt;

	// rcu锁, 禁用了中断
	rcu_read_lock_sched();

	// 如果files正在扩容
	if (unlikely(files->resize_in_progress)) {
		// 释放rcu锁
		rcu_read_unlock_sched();

		// 锁住file_lock. 因为扩容时会上锁, 所以这里也要上锁
		spin_lock(&files->file_lock);
		// 获取新的fdt
		fdt = files_fdtable(files);
		// fd应该是空的, 否则就出错了
		BUG_ON(fdt->fd[fd] != NULL);
		// 设置file到fd位置
		rcu_assign_pointer(fdt->fd[fd], file);
		spin_unlock(&files->file_lock);
		return;
	}
	// 一般情况用, rcu就够了

	/* 与 expand_fdtable() 里的smp_wmb() 对应 */
	smp_rmb();

	// 取出fdt
	fdt = rcu_dereference_sched(files->fdt);
	// 必须是NULL
	BUG_ON(fdt->fd[fd] != NULL);
	// 设置对应指针
	rcu_assign_pointer(fdt->fd[fd], file);
	rcu_read_unlock_sched();
}

/*
 * 这个将会消耗文件的引用计数, 所以调用者应该将其视为调用了fput(file)
 * This consumes the "file" refcount, so callers should treat it
 * as if they had called fput(file).
 */
void fd_install(unsigned int fd, struct file *file)
{
	__fd_install(current->files, fd, file);
}

EXPORT_SYMBOL(fd_install);

// 根据fd获取一个文件, 并将fd的位置置空
static struct file *pick_file(struct files_struct *files, unsigned fd)
{
	struct file *file = NULL;
	struct fdtable *fdt;

	// 上锁, 修改fd数组的都要上锁
	spin_lock(&files->file_lock);
	
	// 获取fdt
	fdt = files_fdtable(files);
	// 大于max出错
	if (fd >= fdt->max_fds)
		goto out_unlock;
	// 获取文件
	file = fdt->fd[fd];
	// 文件为空
	if (!file)
		goto out_unlock;
	// 把fd置空
	rcu_assign_pointer(fdt->fd[fd], NULL);
	// 释放fd
	__put_unused_fd(files, fd);

out_unlock:
	spin_unlock(&files->file_lock);
	return file;
}

/*
 * 与 __alloc_fd()/__fd_install() 的警告相同
 */
int __close_fd(struct files_struct *files, unsigned fd)
{
	struct file *file;

	// 先pick文件, pick的同时会释放fd和置空数组
	file = pick_file(files, fd);
	// 文件为空返回BADF
	if (!file)
		return -EBADF;

	// 关闭文件
	return filp_close(file, files);
}
EXPORT_SYMBOL(__close_fd); /* 给 ksys_close() 用*/

/**
 * __close_range() - 关闭指定范围的文件描述符, close_range syscall
 *
 * @fd:     要关闭的开始fd
 * @max_fd: 最后一个fd (包含)
 *
 * 此函数关闭指定范围内的fd. 从start到max_fd(包含)都会被关闭
 */
int __close_range(unsigned fd, unsigned max_fd, unsigned int flags)
{
	unsigned int cur_max;
	struct task_struct *me = current;
	struct files_struct *cur_fds = me->files, *fds = NULL;

	// flags如果有除CLOSE_RANGE_UNSHARE的标志都会报错,
	// 这个标志只有测试用例用到
	if (flags & ~CLOSE_RANGE_UNSHARE)
		return -EINVAL;

	// 起点不能大于结尾
	if (fd > max_fd)
		return -EINVAL;

	// 获取当前fd最大值
	rcu_read_lock();
	cur_max = files_fdtable(cur_fds)->max_fds;
	rcu_read_unlock();

	// 最大的大效fd, 因为fd是从0开始
	cur_max--;

	// todo: unshare后面看
	if (flags & CLOSE_RANGE_UNSHARE) {
		int ret;
		unsigned int max_unshare_fds = NR_OPEN_MAX;

		/*
		 * If the requested range is greater than the current maximum,
		 * we're closing everything so only copy all file descriptors
		 * beneath the lowest file descriptor.
		 */
		if (max_fd >= cur_max)
			max_unshare_fds = fd;

		ret = unshare_fd(CLONE_FILES, max_unshare_fds, &fds);
		if (ret)
			return ret;

		/*
		 * We used to share our file descriptor table, and have now
		 * created a private one, make sure we're using it below.
		 */
		if (fds)
			swap(cur_fds, fds);
	}

	// 将max_fd规范化
	max_fd = min(max_fd, cur_max);

	// 从起点到终点关闭文件
	while (fd <= max_fd) {
		struct file *file;

		// 取出一个文件,并把数组里置空
		file = pick_file(cur_fds, fd++);
		if (!file)
			continue;

		// 关闭文件
		filp_close(file, cur_fds);
		cond_resched();
	}

	// 恢复fds, 这个只有testing用到
	if (fds) {
		/*
		 * We're done closing the files we were supposed to. Time to install
		 * the new file descriptor table and drop the old one.
		 */
		task_lock(me);
		me->files = cur_fds;
		task_unlock(me);
		put_files_struct(fds);
	}

	return 0;
}

/*
 * __close_fd的变体, 会获取文件一个引用
 *
 * 调用者必须确保filp_close()被调用, 然后fput
 */
int __close_fd_get_file(unsigned int fd, struct file **res)
{
	struct files_struct *files = current->files;
	struct file *file;
	struct fdtable *fdt;

	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	// fd值无效
	if (fd >= fdt->max_fds)
		goto out_unlock;
	// 取出文件
	file = fdt->fd[fd];
	if (!file)
		goto out_unlock;
	// 数组置空
	rcu_assign_pointer(fdt->fd[fd], NULL);
	// 释放fd
	__put_unused_fd(files, fd);
	spin_unlock(&files->file_lock);
	// 获取文件引用
	get_file(file);
	*res = file;
	return 0;

out_unlock:
	spin_unlock(&files->file_lock);
	*res = NULL;
	return -ENOENT;
}

void do_close_on_exec(struct files_struct *files)
{
	unsigned i;
	struct fdtable *fdt;

	// 加锁
	spin_lock(&files->file_lock);
	for (i = 0; ; i++) {
		unsigned long set;
		unsigned fd = i * BITS_PER_LONG;
		
		fdt = files_fdtable(files);
		// fd越界
		if (fd >= fdt->max_fds)
			break;
		// 取出一个long
		set = fdt->close_on_exec[i];
		if (!set)
			continue;
		// 然后把这个long置0
		fdt->close_on_exec[i] = 0;
		// 关闭这个long里的文件
		for ( ; set ; fd++, set >>= 1) {
			struct file *file;

			// 这一位没有刚退出
			if (!(set & 1))
				continue;
			// 取出文件
			file = fdt->fd[fd];
			if (!file)
				continue;
			// 该位置空
			rcu_assign_pointer(fdt->fd[fd], NULL);
			// 释放fd
			__put_unused_fd(files, fd);

			// 关闭文件要释放锁
			spin_unlock(&files->file_lock);
			// 关闭文件
			filp_close(file, files);
			cond_resched();
			// 调度之后重新加锁
			spin_lock(&files->file_lock);
		}

	}
	spin_unlock(&files->file_lock);
}

// 获取file并增加引用, 全使用的rcu操作
static inline struct file *__fget_files_rcu(struct files_struct *files,
	unsigned int fd, fmode_t mask, unsigned int refs)
{
	for (;;) {
		struct file *file;
		// 取出fdt
		struct fdtable *fdt = rcu_dereference_raw(files->fdt);
		struct file __rcu **fdentry;

		// fd越界
		if (unlikely(fd >= fdt->max_fds))
			return NULL;

		// 获取存放file的数组地址, array_index_nospec是把fd规范到max_fds
		fdentry = fdt->fd + array_index_nospec(fd, fdt->max_fds);
		// 取出file
		file = rcu_dereference_raw(*fdentry);
		// 为空直接返回
		if (unlikely(!file))
			return NULL;

		// 有掩码的值, 也返回
		if (unlikely(file->f_mode & mask))
			return NULL;

		/*
		 * 我们有了一个文件指针. 然而,因为我们用的是rcu无锁, 可能会与
		 * 已关闭的文件产生竞争.
		 *
		 * 有下面2种竞争情况:
		 *
		 *  (a) 文件指针已经到0, get_file_rcu_many() 会失败, 
		 *	则继续重试
		 */
		if (unlikely(!get_file_rcu_many(file, refs)))
			continue;

		/*
		 *  (b) fdtable或者file entry已经变了.
		 *       注意: 我们不用重新检查fdt->fd指针有没有变, 因为它和
		 *	fdt相关
		 *
		 * 如果是这样,我们需要释放引用然后重试
		 */
		if (unlikely(rcu_dereference_raw(files->fdt) != fdt) ||
		    unlikely(rcu_dereference_raw(*fdentry) != file)) {
			fput_many(file, refs);
			continue;
		}

		// 文件正常, 返回之
		return file;
	}
}

static struct file *__fget_files(struct files_struct *files, unsigned int fd,
				 fmode_t mask, unsigned int refs)
{
	struct file *file;

	// 加rcu锁之后获取引用
	rcu_read_lock();
	file = __fget_files_rcu(files, fd, mask, refs);
	rcu_read_unlock();

	return file;
}

// 从当前进程获取fd 文件, 并增加refs指针
static inline struct file *__fget(unsigned int fd, fmode_t mask,
				  unsigned int refs)
{
	return __fget_files(current->files, fd, mask, refs);
}

// 掩码值传的是FMODE_PATH
struct file *fget_many(unsigned int fd, unsigned int refs)
{
	return __fget(fd, FMODE_PATH, refs);
}

// 只获取file引用一次
struct file *fget(unsigned int fd)
{
	return __fget(fd, FMODE_PATH, 1);
}
EXPORT_SYMBOL(fget);

// 只获取file引用一次, mode是0
struct file *fget_raw(unsigned int fd)
{
	return __fget(fd, 0, 1);
}
EXPORT_SYMBOL(fget_raw);

// 从指定进程获取fd对应的文件
struct file *fget_task(struct task_struct *task, unsigned int fd)
{
	struct file *file = NULL;

	// 锁住task并获取文件, mode是0, 引用是1
	task_lock(task);
	if (task->files)
		file = __fget_files(task->files, fd, 0, 1);
	task_unlock(task);

	return file;
}

/*
 * Lightweight file lookup - no refcnt increment if fd table isn't shared.
 *
 * You can use this instead of fget if you satisfy all of the following
 * conditions:
 * 1) You must call fput_light before exiting the syscall and returning control
 *    to userspace (i.e. you cannot remember the returned struct file * after
 *    returning to userspace).
 * 2) You must not call filp_close on the returned struct file * in between
 *    calls to fget_light and fput_light.
 * 3) You must not clone the current task in between the calls to fget_light
 *    and fput_light.
 *
 * The fput_needed flag returned by fget_light should be passed to the
 * corresponding fput_light.
 */
static unsigned long __fget_light(unsigned int fd, fmode_t mask)
{
	struct files_struct *files = current->files;
	struct file *file;

	if (atomic_read(&files->count) == 1) {
		file = __fcheck_files(files, fd);
		if (!file || unlikely(file->f_mode & mask))
			return 0;
		return (unsigned long)file;
	} else {
		file = __fget(fd, mask, 1);
		if (!file)
			return 0;
		return FDPUT_FPUT | (unsigned long)file;
	}
}
unsigned long __fdget(unsigned int fd)
{
	return __fget_light(fd, FMODE_PATH);
}
EXPORT_SYMBOL(__fdget);

unsigned long __fdget_raw(unsigned int fd)
{
	return __fget_light(fd, 0);
}

unsigned long __fdget_pos(unsigned int fd)
{
	unsigned long v = __fdget(fd);
	struct file *file = (struct file *)(v & ~3);

	if (file && (file->f_mode & FMODE_ATOMIC_POS)) {
		if (file_count(file) > 1) {
			v |= FDPUT_POS_UNLOCK;
			mutex_lock(&file->f_pos_lock);
		}
	}
	return v;
}

void __f_unlock_pos(struct file *f)
{
	mutex_unlock(&f->f_pos_lock);
}

/*
 * We only lock f_pos if we have threads or if the file might be
 * shared with another process. In both cases we'll have an elevated
 * file count (done either by fdget() or by fork()).
 */

void set_close_on_exec(unsigned int fd, int flag)
{
	struct files_struct *files = current->files;
	struct fdtable *fdt;
	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	if (flag)
		__set_close_on_exec(fd, fdt);
	else
		__clear_close_on_exec(fd, fdt);
	spin_unlock(&files->file_lock);
}

bool get_close_on_exec(unsigned int fd)
{
	struct files_struct *files = current->files;
	struct fdtable *fdt;
	bool res;
	rcu_read_lock();
	fdt = files_fdtable(files);
	res = close_on_exec(fd, fdt);
	rcu_read_unlock();
	return res;
}

static int do_dup2(struct files_struct *files,
	struct file *file, unsigned fd, unsigned flags)
__releases(&files->file_lock)
{
	struct file *tofree;
	struct fdtable *fdt;

	/*
	 * We need to detect attempts to do dup2() over allocated but still
	 * not finished descriptor.  NB: OpenBSD avoids that at the price of
	 * extra work in their equivalent of fget() - they insert struct
	 * file immediately after grabbing descriptor, mark it larval if
	 * more work (e.g. actual opening) is needed and make sure that
	 * fget() treats larval files as absent.  Potentially interesting,
	 * but while extra work in fget() is trivial, locking implications
	 * and amount of surgery on open()-related paths in VFS are not.
	 * FreeBSD fails with -EBADF in the same situation, NetBSD "solution"
	 * deadlocks in rather amusing ways, AFAICS.  All of that is out of
	 * scope of POSIX or SUS, since neither considers shared descriptor
	 * tables and this condition does not arise without those.
	 */
	fdt = files_fdtable(files);
	tofree = fdt->fd[fd];
	if (!tofree && fd_is_open(fd, fdt))
		goto Ebusy;
	get_file(file);
	rcu_assign_pointer(fdt->fd[fd], file);
	__set_open_fd(fd, fdt);
	if (flags & O_CLOEXEC)
		__set_close_on_exec(fd, fdt);
	else
		__clear_close_on_exec(fd, fdt);
	spin_unlock(&files->file_lock);

	if (tofree)
		filp_close(tofree, files);

	return fd;

Ebusy:
	spin_unlock(&files->file_lock);
	return -EBUSY;
}

int replace_fd(unsigned fd, struct file *file, unsigned flags)
{
	int err;
	struct files_struct *files = current->files;

	if (!file)
		return __close_fd(files, fd);

	if (fd >= rlimit(RLIMIT_NOFILE))
		return -EBADF;

	spin_lock(&files->file_lock);
	err = expand_files(files, fd);
	if (unlikely(err < 0))
		goto out_unlock;
	return do_dup2(files, file, fd, flags);

out_unlock:
	spin_unlock(&files->file_lock);
	return err;
}

/**
 * __receive_fd() - Install received file into file descriptor table
 *
 * @fd: fd to install into (if negative, a new fd will be allocated)
 * @file: struct file that was received from another process
 * @ufd: __user pointer to write new fd number to
 * @o_flags: the O_* flags to apply to the new fd entry
 *
 * Installs a received file into the file descriptor table, with appropriate
 * checks and count updates. Optionally writes the fd number to userspace, if
 * @ufd is non-NULL.
 *
 * This helper handles its own reference counting of the incoming
 * struct file.
 *
 * Returns newly install fd or -ve on error.
 */
int __receive_fd(int fd, struct file *file, int __user *ufd, unsigned int o_flags)
{
	int new_fd;
	int error;

	error = security_file_receive(file);
	if (error)
		return error;

	if (fd < 0) {
		new_fd = get_unused_fd_flags(o_flags);
		if (new_fd < 0)
			return new_fd;
	} else {
		new_fd = fd;
	}

	if (ufd) {
		error = put_user(new_fd, ufd);
		if (error) {
			if (fd < 0)
				put_unused_fd(new_fd);
			return error;
		}
	}

	if (fd < 0) {
		fd_install(new_fd, get_file(file));
	} else {
		error = replace_fd(new_fd, file, o_flags);
		if (error)
			return error;
	}

	/* Bump the sock usage counts, if any. */
	__receive_sock(file);
	return new_fd;
}

static int ksys_dup3(unsigned int oldfd, unsigned int newfd, int flags)
{
	int err = -EBADF;
	struct file *file;
	struct files_struct *files = current->files;

	if ((flags & ~O_CLOEXEC) != 0)
		return -EINVAL;

	if (unlikely(oldfd == newfd))
		return -EINVAL;

	if (newfd >= rlimit(RLIMIT_NOFILE))
		return -EBADF;

	spin_lock(&files->file_lock);
	err = expand_files(files, newfd);
	file = fcheck(oldfd);
	if (unlikely(!file))
		goto Ebadf;
	if (unlikely(err < 0)) {
		if (err == -EMFILE)
			goto Ebadf;
		goto out_unlock;
	}
	return do_dup2(files, file, newfd, flags);

Ebadf:
	err = -EBADF;
out_unlock:
	spin_unlock(&files->file_lock);
	return err;
}

SYSCALL_DEFINE3(dup3, unsigned int, oldfd, unsigned int, newfd, int, flags)
{
	return ksys_dup3(oldfd, newfd, flags);
}

SYSCALL_DEFINE2(dup2, unsigned int, oldfd, unsigned int, newfd)
{
	if (unlikely(newfd == oldfd)) { /* corner case */
		struct files_struct *files = current->files;
		int retval = oldfd;

		rcu_read_lock();
		if (!fcheck_files(files, oldfd))
			retval = -EBADF;
		rcu_read_unlock();
		return retval;
	}
	return ksys_dup3(oldfd, newfd, 0);
}

SYSCALL_DEFINE1(dup, unsigned int, fildes)
{
	int ret = -EBADF;
	struct file *file = fget_raw(fildes);

	if (file) {
		ret = get_unused_fd_flags(0);
		if (ret >= 0)
			fd_install(ret, file);
		else
			fput(file);
	}
	return ret;
}

int f_dupfd(unsigned int from, struct file *file, unsigned flags)
{
	int err;
	if (from >= rlimit(RLIMIT_NOFILE))
		return -EINVAL;
	err = alloc_fd(from, flags);
	if (err >= 0) {
		get_file(file);
		fd_install(err, file);
	}
	return err;
}

int iterate_fd(struct files_struct *files, unsigned n,
		int (*f)(const void *, struct file *, unsigned),
		const void *p)
{
	struct fdtable *fdt;
	int res = 0;
	if (!files)
		return 0;
	spin_lock(&files->file_lock);
	for (fdt = files_fdtable(files); n < fdt->max_fds; n++) {
		struct file *file;
		file = rcu_dereference_check_fdtable(files, fdt->fd[n]);
		if (!file)
			continue;
		res = f(p, file, n);
		if (res)
			break;
	}
	spin_unlock(&files->file_lock);
	return res;
}
EXPORT_SYMBOL(iterate_fd);

```
