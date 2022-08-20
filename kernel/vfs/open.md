# 打开文件

## 简介
打开文件主要是建立file, dentry, inode这三个数据结构，以及将它们三个关联起来。如果文件不存在的话，还要新建inode对象。

打开文件主要有下面几个过程：
1. 根据用户层传下来的标志，做一些检查和转换；
2. 获取一个没有使用的fd，fd是一个整数，对应的是file在数组里的下标及几个位标志里的第几位。在这个过程中，如果进程打开的文件数量太多，还要对这些数组，位标志进行扩容；
3. 遍历路径，调用具体文件系统打开或者创建inode, dentry;
4. 创建file对象，把file对象和dentry, 具体文件系统操作函数表等关联；
5. 把file设置到数组里fd对应的位置。

## open系统调用
```c
SYSCALL_DEFINE3(open, const char __user *, filename, int, flags, umode_t, mode)
{
    // 如果CONFIG_ARCH_32BIT_OFF_T这个配置没打开，则force_o_largefile返回true
    // 这个标志一般都没开
	if (force_o_largefile())
		flags |= O_LARGEFILE;
    // 打开文件
    // AT_FDCWD表示从当前目录开始查找
	return do_sys_open(AT_FDCWD, filename, flags, mode);
}

long do_sys_open(int dfd, const char __user *filename, int flags, umode_t mode)
{
    // build_open_how把flags和mode打包到open_how这个结构体里，并且做了一些简单的处理
	struct open_how how = build_open_how(flags, mode);
	return do_sys_openat2(dfd, filename, &how);
}

inline struct open_how build_open_how(int flags, umode_t mode)
{
	/**
	#define VALID_OPEN_FLAGS \
	(O_RDONLY | O_WRONLY | O_RDWR | O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC | \
	 O_APPEND | O_NDELAY | O_NONBLOCK | __O_SYNC | O_DSYNC | \
	 FASYNC	| O_DIRECT | O_LARGEFILE | O_DIRECTORY | O_NOFOLLOW | \
	 O_NOATIME | O_CLOEXEC | O_PATH | __O_TMPFILE)
	**/

	/**
 	#define S_IALLUGO	(S_ISUID|S_ISGID|S_ISVTX|S_IRWXUGO)
	**/
	struct open_how how = {
		// VALID_OPEN_FLAGS是目前open支持的所有标志，
		// 这里是将用户层传下来的flags做过滤，只保留支持的标志
		.flags = flags & VALID_OPEN_FLAGS,
		// mode用在创建文件时，S_IALLUGO是文件的所有权限，
		// 这里将用户层传下来的创建模式做过滤
		.mode = mode & S_IALLUGO,
	};

	// O_PATH是只打开目录路径，不跟踪链接
	if (how.flags & O_PATH)
		// #define O_PATH_FLAGS		(O_DIRECTORY | O_NOFOLLOW | O_PATH | O_CLOEXEC)
		how.flags &= O_PATH_FLAGS;

	// 如果不是创建文件就把mode置0，
	// #define WILL_CREATE(flags)	(flags & (O_CREAT | __O_TMPFILE))
	// __O_TMPFILE是创建临时文件
	if (!WILL_CREATE(how.flags))
		how.mode = 0;
	return how;
}

static long do_sys_openat2(int dfd, const char __user *filename,
			   struct open_how *how)
{
	struct open_flags op;
    // 对flags进行处理，并转换成open_flags
	int fd = build_open_flags(how, &op);
	struct filename *tmp;

    // 如果检查标志出错，直接返回
	if (fd)
		return fd;

    // 把文件名从用户空间复制到内核空间
	tmp = getname(filename);
	if (IS_ERR(tmp))
		return PTR_ERR(tmp);
    // 获取一个未使用的文件描述符
	// 在进程里有个数组，里面放的是已打开的文件，fd实际上就是数组的下标
	fd = get_unused_fd_flags(how->flags);

	if (fd >= 0) {
        // 打开文件，并创建一个file对象
		struct file *f = do_filp_open(dfd, tmp, &op);
		if (IS_ERR(f)) {
            // 如果失败，则释放fd
			put_unused_fd(fd);
			fd = PTR_ERR(f);
		} else {
            // 通知有文件打开
			fsnotify_open(f);
            // 把文件描述符和file对象关联，并设置到进程的相关结构中
			fd_install(fd, f);
		}
	}
	// 释放文件名占用的内存
	putname(tmp);
	return fd;
}
```
open是打开文件的入口，当然还有其它类似的接口，但是都差不多。主要函数是do_sys_openat2，它执行打开的主要流程。 

## 转换用户层的flags
用户层使用的flag和内核里用到的有些区别，要对其进行检查、转换、补充。

```c
inline int build_open_flags(const struct open_how *how, struct open_flags *op)
{
	u64 flags = how->flags;
	// FMODE_NONOTIFY是做文件操作时不通知，内核里有个notify的文件系统
	// O_CLOEXEC是在exec时关闭文件，主要用于父子进程共享文件
	u64 strip = FMODE_NONOTIFY | O_CLOEXEC;
	int lookup_flags = 0;

	/**
	#define O_ACCMODE	00000003
	#define O_RDONLY	00000000
	#define O_WRONLY	00000001
	#define O_RDWR		00000002

	#define ACC_MODE(x) ("\004\002\006\006"[(x)&O_ACCMODE])
	这个ACC_MODE等价于：
	a[4]={4,2,6,6}
	#define ACC_MODE(x) a[x & 0x11]

	这里主要对用户层访问模式进行转换：
	user_flag     acc_mode
	0(只读)				4 ( r-- )
	1(只写)				2 ( -w- )
	2(读写)				6 ( rw- )
	**/
	int acc_mode = ACC_MODE(flags);

	// VALID_OPEN_FLAGS超过32位，编译报警？
	BUILD_BUG_ON_MSG(upper_32_bits(VALID_OPEN_FLAGS),
			 "struct open_flags doesn't yet handle flags > 32 bits");

    /**
	 去掉FMODE_NONOTIFY | O_CLOEXEC这两个标志
	 todo: 为啥要去掉
    **/
	flags &= ~strip;

    // 如果flags里有不允许的打开标志，则返回错误
	if (flags & ~VALID_OPEN_FLAGS)
		return -EINVAL;
    
    // todo: resolve是啥标志？
	if (how->resolve & ~VALID_RESOLVE_FLAGS)
		return -EINVAL;

	if ((how->resolve & RESOLVE_BENEATH) && (how->resolve & RESOLVE_IN_ROOT))
		return -EINVAL;

	if (WILL_CREATE(flags)) { // 有创建文件的需求
        // 创建文件时，如果有除了S_IALLUGO的其它标志，则返回错误
		if (how->mode & ~S_IALLUGO)
			return -EINVAL;

        // S_IFREG是普通文件，用open只能创建普通文件
		// 目录或者其它文件有专门的系统调用，比如:mkdir, mknod等等
		op->mode = how->mode | S_IFREG;
	} else {
        // 如果不是创建文件，就不能指定mode，否则出错
		if (how->mode != 0)
			return -EINVAL;
		op->mode = 0;
	}

	if (flags & __O_TMPFILE) { // 创建临时文件
        /**
        #define O_TMPFILE (__O_TMPFILE | O_DIRECTORY)
        #define O_TMPFILE_MASK (__O_TMPFILE | O_DIRECTORY | O_CREAT)      

		创建临时文件不能有O_CREAT标志
        **/
		if ((flags & O_TMPFILE_MASK) != O_TMPFILE)
			return -EINVAL;
		/**
		#define MAY_WRITE		0x00000002
		创建临时文件如果没有写标志，则出错
		**/
		if (!(acc_mode & MAY_WRITE))
			return -EINVAL;
	}
	if (flags & O_PATH) {
		// 检查只打开路径时，是否有非法标志
		if (flags & ~O_PATH_FLAGS)
			return -EINVAL;
		// 只找开路径时，将acc_mode置0
		acc_mode = 0;
	}

	// 如果有同步的标志，则把元数据同步标志也设置上
	if (flags & __O_SYNC)
		flags |= O_DSYNC;

	op->open_flag = flags;

	// 截断文件时需要写权限
	if (flags & O_TRUNC)
		acc_mode |= MAY_WRITE;

	// 追加文件时需要追加权限
	if (flags & O_APPEND)
		acc_mode |= MAY_APPEND;

	op->acc_mode = acc_mode;

    /**
	 intent表示本次open的意图
	 如果有O_PATH只找到路径，则设0
	 否则设置成普通打开文件
	todo: 
	**/
	op->intent = flags & O_PATH ? 0 : LOOKUP_OPEN;

	if (flags & O_CREAT) {
        // 设置创建意图
		op->intent |= LOOKUP_CREATE;

		// O_EXCL表示创建文件时，文件不能存在，
		// 这种情况下不跟随软链接
		if (flags & O_EXCL) {
			op->intent |= LOOKUP_EXCL;
			flags |= O_NOFOLLOW;
		}
	}

    // O_DIRECTORY表示目标必须是一个目录
	if (flags & O_DIRECTORY)
		lookup_flags |= LOOKUP_DIRECTORY;

    // 如果需要跟踪链接，则设置标志
	if (!(flags & O_NOFOLLOW))
		lookup_flags |= LOOKUP_FOLLOW;

    // 设置resolve的标志
	// todo: 何为resolve
	if (how->resolve & RESOLVE_NO_XDEV)
		lookup_flags |= LOOKUP_NO_XDEV;
	if (how->resolve & RESOLVE_NO_MAGICLINKS)
		lookup_flags |= LOOKUP_NO_MAGICLINKS;
	if (how->resolve & RESOLVE_NO_SYMLINKS)
		lookup_flags |= LOOKUP_NO_SYMLINKS;
	if (how->resolve & RESOLVE_BENEATH)
		lookup_flags |= LOOKUP_BENEATH;
	if (how->resolve & RESOLVE_IN_ROOT)
		lookup_flags |= LOOKUP_IN_ROOT;

	op->lookup_flags = lookup_flags;
	return 0;
}
```

## 获取一个未使用的fd
进程主要用下面数据结构来管理一个进程与文件相关的东西。
```c
// 进程里用于管理已打开文件的结构是struct files_struct
struct files_struct {
	atomic_t count;
	bool resize_in_progress;
	wait_queue_head_t resize_wait;

	struct fdtable __rcu *fdt; // 指向文件描述表
	struct fdtable fdtab; 
  /*
   * written part on a separate cache line in SMP
   */
	spinlock_t file_lock ____cacheline_aligned_in_smp;
	unsigned int next_fd; // 下一个分配的fd
	
	// 下面这三个变量都是按位记录相应fd
	unsigned long close_on_exec_init[1]; // exec时需要关闭的fd
	unsigned long open_fds_init[1]; // 已经打开的fd
	unsigned long full_fds_bits_init[1]; // 这里面的每一位表示一个32位是不是已经全打开了

	// 保存已打开的file实例，fd就是这个数组的下标
	// NR_OPEN_DEFAULT = BITS_PER_LONG
	struct file __rcu * fd_array[NR_OPEN_DEFAULT];
};

// 这个结构主要用来动态扩展可打开文件数量
struct fdtable {
	// 最大可打开文件的数量
	unsigned int max_fds;
	/**
	 刚开始指向files_struct->fd_array，如果打开的文件数量超过NR_OPEN_DEFAULT，
	 就给fd申请内存，让他指向新申请内存，来扩展已打开文件的数量
	 **/
	struct file __rcu **fd;  
	unsigned long *close_on_exec; // 刚开始指向files_struct->close_on_exec_init，后面再扩展
	unsigned long *open_fds; // 刚开始指向files_struct->open_fds_init，后面再扩展
	unsigned long *full_fds_bits; // 刚开始指向files_struct->full_fds_bits_init，后面再扩展
	struct rcu_head rcu;
};
```
因为以前内核只支持最大打开NR_OPEN_DEFAULT个文件，为了打开大量文件，就采用了这种动态扩展的方式。fd实际上就是fdtable->fd数组的下标。

```c
int get_unused_fd_flags(unsigned flags)
{
	// RLIMIT_NOFILE是一个进程打开文件的限制数量
	// 默认限制为1024个文件，如果有root权限，可以修改限制，但最大不超过4096
	return __get_unused_fd_flags(flags, rlimit(RLIMIT_NOFILE));
}

int __get_unused_fd_flags(unsigned flags, unsigned long nofile)
{
	// current->files是当前进程已打开文件的管理结构
	return __alloc_fd(current->files, 0, nofile, flags);
}

int __alloc_fd(struct files_struct *files,
	       unsigned start, unsigned end, unsigned flags)
{
	unsigned int fd;
	int error;
	struct fdtable *fdt;

	spin_lock(&files->file_lock);
repeat:
	// 获取文件表
	fdt = files_fdtable(files);

	// start是0
	fd = start;

	// next_fd是下一个应该分配的fd号
	if (fd < files->next_fd)
		fd = files->next_fd;

	if (fd < fdt->max_fds)
		// 找到下一个没有分配的fd
		fd = find_next_fd(fdt, fd);

	error = -EMFILE;
	// 如果fd比限制的打开文件数量多，则出错
	if (fd >= end)
		goto out;

	/**
	 根据需要扩展fdtable中相应的变量
	 返回值：
	 1－已扩展
	 0－未扩展
	 <0－出错
	 **/

	error = expand_files(files, fd);
	if (error < 0)
		goto out;

	// 如果已经扩展了列表，则再重新去上面找一遍
	if (error)
		goto repeat;

	// 重新设置next_fd
	if (start <= files->next_fd)
		files->next_fd = fd + 1;

	// 设置fd对应位的标志
	__set_open_fd(fd, fdt);

	// 根据是否有O_CLOEXEC，设置对应的标志位
	if (flags & O_CLOEXEC)
		__set_close_on_exec(fd, fdt);
	else
		__clear_close_on_exec(fd, fdt);
	error = fd;
#if 1
	// 检查fdt->fd[fd]是否为空，一般都会为空，如果不为空，则强行设为空
	if (rcu_access_pointer(fdt->fd[fd]) != NULL) {
		printk(KERN_WARNING "alloc_fd: slot %d not NULL!\n", fd);
		rcu_assign_pointer(fdt->fd[fd], NULL);
	}
#endif

out:
	spin_unlock(&files->file_lock);
	return error;
}

static unsigned int find_next_fd(struct fdtable *fdt, unsigned int start)
{
	// 最大可以分配的fd
	unsigned int maxfd = fdt->max_fds;
	// 下面2个是标志位的标志位
	unsigned int maxbit = maxfd / BITS_PER_LONG;
	unsigned int bitbit = start / BITS_PER_LONG;

	/**
	 full_fds_bits里保存的是已分配标志位的标志位，如果它为1，就表示open_fds里某个32位已经合部分配，
	 先找出没有分配完的标志位的标志位，然后再乘以BITS_PER_LONG，就得到了对应标志位开始的位置，
	 因为每个标志位存储BITS_PER_LONG个标志
	 **/
	bitbit = find_next_zero_bit(fdt->full_fds_bits, maxbit, bitbit) * BITS_PER_LONG;

	// 如果标志位全部已经分配了，则返回
	if (bitbit > maxfd)
		return maxfd;
	// 让start指向开始分配的标志位
	if (bitbit > start)
		start = bitbit;
	// 找出start中一个空闲位
	return find_next_zero_bit(fdt->open_fds, maxfd, start);
}

static int expand_files(struct files_struct *files, unsigned int nr)
	__releases(files->file_lock)
	__acquires(files->file_lock)
{
	struct fdtable *fdt;
	int expanded = 0;

repeat:
	fdt = files_fdtable(files);

	// 如果要分配的fd比最大可分配fd小，则不用扩展，直接返回
	if (nr < fdt->max_fds)
		return expanded;

	// 如果超过了用户设置的最大打开文件数量，则出错返回
	if (nr >= sysctl_nr_open)
		return -EMFILE;

	if (unlikely(files->resize_in_progress)) {
		// 如果正在扩充files的容量，则等他扩充完了再上去测试一下相关条件
		spin_unlock(&files->file_lock);
		expanded = 1;
		wait_event(files->resize_wait, !files->resize_in_progress);
		spin_lock(&files->file_lock);
		goto repeat;
	}

	// 设置正在扩充的标志
	files->resize_in_progress = true;

	// 真正的扩展
	expanded = expand_fdtable(files, nr);

	// 取消正在扩充的标志
	files->resize_in_progress = false;

	// 唤醒所有在resize_wait上等待的进程，就是上面等待的地方
	wake_up_all(&files->resize_wait);
	return expanded;
}

static int expand_fdtable(struct files_struct *files, unsigned int nr)
	__releases(files->file_lock)
	__acquires(files->file_lock)
{
	struct fdtable *new_fdt, *cur_fdt;

	spin_unlock(&files->file_lock);

	// 申请新内存，并重新设置相关变量
	new_fdt = alloc_fdtable(nr);

	// 如果还有其他人也在使用文件，则要确保其它人读结束，因为下面要设置fdt
	if (atomic_read(&files->count) > 1)
		synchronize_rcu();

	spin_lock(&files->file_lock);
	if (!new_fdt)
		return -ENOMEM;
	// 如果没申请到足够的内存则退出
	if (unlikely(new_fdt->max_fds <= nr)) {
		__free_fdtable(new_fdt);
		return -EMFILE;
	}
	cur_fdt = files_fdtable(files);

	// 上面不是已经判断了吗？什么情况会走到这种情况
	BUG_ON(nr < cur_fdt->max_fds);

	// 把以前fdt中的open_fds， close_on_exec， full_fds_bits
	// 复制到新申请的内存中去
	copy_fdtable(new_fdt, cur_fdt);

	// 设置新的fdt
	rcu_assign_pointer(files->fdt, new_fdt);

	// 等rcu结束后释放旧的fdt
	if (cur_fdt != &files->fdtab)
		call_rcu(&cur_fdt->rcu, free_fdtable_rcu);
	/* coupled with smp_rmb() in __fd_install() */
	smp_wmb();
	return 1;
}
```

## 创建file
找到了fd之后，下一步就是要创建file。  

```c
struct file *do_filp_open(int dfd, struct filename *pathname,
		const struct open_flags *op)
{
	struct nameidata nd;
	int flags = op->lookup_flags;
	struct file *filp;

	// 设置nameidata相关的数据
	set_nameidata(&nd, dfd, pathname);

	// 打开文件
	filp = path_openat(&nd, op, flags | LOOKUP_RCU);

	// todo: 这些失败情况是什么？
	if (unlikely(filp == ERR_PTR(-ECHILD)))
		filp = path_openat(&nd, op, flags);
	if (unlikely(filp == ERR_PTR(-ESTALE)))
		filp = path_openat(&nd, op, flags | LOOKUP_REVAL);
	
	// 释放nameidata里的相关数据
	restore_nameidata();
	return filp;
}

static void set_nameidata(struct nameidata *p, int dfd, struct filename *name)
{
	// todo: 上一次使用的nameidata？
	struct nameidata *old = current->nameidata;
	// 先让stack指向internal, internal数组大小为2
	p->stack = p->internal;
	// 设置目录的文件描述符
	p->dfd = dfd;
	// 要查找的路径
	p->name = name;
	// 内核对链接的层次数有限制，如果一次遍历的层次太多就会被限制
	p->total_link_count = old ? old->total_link_count : 0;
	// 保存上一次使用的nd
	p->saved = old;
	// 设置进程当前的nd
	current->nameidata = p;
}

static struct file *path_openat(struct nameidata *nd,
			const struct open_flags *op, unsigned flags)
{
	struct file *file;
	int error;

	// 这个函数会在filp_cachep申请一个file结构体
	file = alloc_empty_file(op->open_flag, current_cred());
	if (IS_ERR(file))
		return file;

	if (unlikely(file->f_flags & __O_TMPFILE)) {
		// 如果要求临时文件，则创建一个临时文件
		error = do_tmpfile(nd, flags, op, file);
	} else if (unlikely(file->f_flags & O_PATH)) {
		// todo: O_PATH是什么
		error = do_o_path(nd, flags, file);
	} else {
		// path_init和link_path_walk和遍历路径那一节的逻辑差不多，
        // 但是这里找的是目标节点的父目录，因为在前面设置了flags有LOOKUP_DICTIONARY
		const char *s = path_init(nd, flags);
		while (!(error = link_path_walk(s, nd)) &&
                // 对目标节点进行处理,上面的path_walk找的是父目录
		       (s = open_last_lookups(nd, file, op)) != NULL)
			;
		if (!error)
			// 如果不出错就把file和具体的dentry关联
			error = do_open(nd, file, op);
		// 释放遍历过程中的变量
		terminate_walk(nd);
	}
	if (likely(!error)) {
		if (likely(file->f_mode & FMODE_OPENED))
			return file;
		WARN_ON(1);
		error = -EINVAL;
	}
	fput(file);
	if (error == -EOPENSTALE) {
		if (flags & LOOKUP_RCU)
			error = -ECHILD;
		else
			error = -ESTALE;
	}
	return ERR_PTR(error);
}

struct file *alloc_empty_file(int flags, const struct cred *cred)
{
	static long old_max;
	struct file *f;

	/*
	 * files_stat.max_files是8192,是系统限制的总共文件数量，如果超过了这个数量，
	 */
	if (get_nr_files() >= files_stat.max_files && !capable(CAP_SYS_ADMIN)) {
		/*
		 percpu_counter_sum_positive是get_nr_files的一个精确慢速版本，在这里再判断一次,
		 如果确实超过了最大文件，则退出
		 */
		if (percpu_counter_sum_positive(&nr_files) >= files_stat.max_files)
			goto over;
	}

	// 如果没有超过限制，或者是root用户，则创建文件
	f = __alloc_file(flags, cred);
	// 如果创建文件成功，则递增nr_files
	if (!IS_ERR(f))
		percpu_counter_inc(&nr_files);

	return f;

over:
	// 保存 old_max的值，old_max是个静态变量
	if (get_nr_files() > old_max) {
		// get_max_files就是files_stat.max_files
		pr_info("VFS: file-max limit %lu reached\n", get_max_files());
		old_max = get_nr_files();
	}
	return ERR_PTR(-ENFILE);
}

static struct file *__alloc_file(int flags, const struct cred *cred)
{
	struct file *f;
	int error;

	// 申请一个file
	f = kmem_cache_zalloc(filp_cachep, GFP_KERNEL);
	if (unlikely(!f))
		return ERR_PTR(-ENOMEM);

	// 设置进程的安全上下文
	f->f_cred = get_cred(cred);

	// 调用安全钩子函数
	error = security_file_alloc(f);
	if (unlikely(error)) {
		file_free_rcu(&f->f_u.fu_rcuhead);
		return ERR_PTR(error);
	}

	// 设置使用数量为1
	atomic_long_set(&f->f_count, 1);

	// 初始化锁
	rwlock_init(&f->f_owner.lock);
	spin_lock_init(&f->f_lock);
	mutex_init(&f->f_pos_lock);
	eventpoll_init_file(f);
	f->f_flags = flags;

	// 设置 文件读写模式
	f->f_mode = OPEN_FMODE(flags);
	/* f->f_version: 0 */

	return f;
}
```

## 打开或创建目标文件
打开目标文件是根据在父目录里查找或创建文件。
```
static const char *open_last_lookups(struct nameidata *nd,
		   struct file *file, const struct open_flags *op)
{
    // 父目录
	struct dentry *dir = nd->path.dentry;

    // 打开时的标志
	int open_flag = op->open_flag;
	bool got_write = false;
	unsigned seq;
	struct inode *inode;
	struct dentry *dentry;
	const char *res;

	// 给flags里写入open的目标是打开还是创建文件
	nd->flags |= op->intent;

    // 如果最后节点是 '.', '..', 则找到'.', '..'对应的
    // dentry和文件系统后，再返回重新查找
	if (nd->last_type != LAST_NORM) {
		if (nd->depth)
			put_link(nd);
		return handle_dots(nd, nd->last_type);
	}

	if (!(open_flag & O_CREAT)) { // 不是创建文件
		if (nd->last.name[nd->last.len])
			nd->flags |= LOOKUP_FOLLOW | LOOKUP_DIRECTORY;
		// 去内存里找，找到就返回
		dentry = lookup_fast(nd, &inode, &seq);
		if (IS_ERR(dentry))
			return ERR_CAST(dentry);
		if (likely(dentry))
			goto finish_lookup;

		BUG_ON(nd->flags & LOOKUP_RCU);
	} else { // 需要创建文件
		/* create side of things */
		if (nd->flags & LOOKUP_RCU) {
			if (!try_to_unlazy(nd))
				return ERR_PTR(-ECHILD);
		}
        // 先打一条审计日志
		audit_inode(nd->name, dir, AUDIT_INODE_PARENT);
		// 如果目标节点不是路径的终点，则表示这是中间的一个目录，出错返回
		if (unlikely(nd->last.name[nd->last.len]))
			return ERR_PTR(-EISDIR);
	}

	if (open_flag & (O_CREAT | O_TRUNC | O_WRONLY | O_RDWR)) {
        // 如果有写文件需求,mnt_want_write里会增加mnt的写入计数
		got_write = !mnt_want_write(nd->path.mnt);
		/*
		 * do _not_ fail yet - we might not need that or fail with
		 * a different error; let lookup_open() decide; we'll be
		 * dropping this one anyway.
		 */
	}
	if (open_flag & O_CREAT)
        // 获取 i_rwsem 的写锁
		inode_lock(dir->d_inode);
	else
        // 获取 i_rwsem 的读锁
		inode_lock_shared(dir->d_inode);
	
	// 查找或者创建dentry, inode
	dentry = lookup_open(nd, file, op, got_write);
	if (!IS_ERR(dentry) && (file->f_mode & FMODE_CREATED))
        // 如果没有失败，且创建文件成功，则发送创建文件通知
		fsnotify_create(dir->d_inode, dentry);
    // 释放上面对应的锁
	if (open_flag & O_CREAT)
		inode_unlock(dir->d_inode);
	else
		inode_unlock_shared(dir->d_inode);

    // 递减mnt的计数器
	if (got_write)
		mnt_drop_write(nd->path.mnt);

	if (IS_ERR(dentry))
		return ERR_CAST(dentry);

	if (file->f_mode & (FMODE_OPENED | FMODE_CREATED)) {
        // 操作成功，就释放老的dentry，再把新的dentry设置到nd里
		dput(nd->path.dentry);
		nd->path.dentry = dentry;
		return NULL;
	}

finish_lookup:
	if (nd->depth)
		put_link(nd);
    // 跟踪挂载点和软链接
	res = step_into(nd, WALK_TRAILING, dentry, inode, seq);
    // res不为空表示还要没找完，返回上级函数继续查找
	if (unlikely(res))
		nd->flags &= ~(LOOKUP_OPEN|LOOKUP_CREATE|LOOKUP_EXCL);
	return res;
}

static struct dentry *lookup_open(struct nameidata *nd, struct file *file,
				  const struct open_flags *op,
				  bool got_write)
{
    // 父目录的dentry
	struct dentry *dir = nd->path.dentry;
    // 父目录的inode
	struct inode *dir_inode = dir->d_inode;
	int open_flag = op->open_flag;
	struct dentry *dentry;
	int error, create_error = 0;
	umode_t mode = op->mode;
	DECLARE_WAIT_QUEUE_HEAD_ONSTACK(wq);

    // 如果父目录被删除，则返回错误
	// 删除的时候会先设置dead标志,然后等没人用了再释放结构
	if (unlikely(IS_DEADDIR(dir_inode)))
		return ERR_PTR(-ENOENT);

    // 先删除已创建的标志，因为下面可能要创建文件
	file->f_mode &= ~FMODE_CREATED;
    // 在内存里再查找一遍，避免并发
	dentry = d_lookup(dir, &nd->last);
	for (;;) {
		if (!dentry) {
			dentry = d_alloc_parallel(dir, &nd->last, &wq);
			if (IS_ERR(dentry))
				return dentry;
		}
        /**
            这个函数是检查有无DCACHE_PAR_LOOKUP标志
            这个标志表示dentry是新建立的，如果dentry是新建立的就不用再做
            下面的检查，直接退出循环
        **/
		if (d_in_lookup(dentry))
			break;

        // 走到这儿说明dentry是在内存里找的，就要检查dentry的有效性
        
        // d_revalidate直接调用具体文件系统的d_op的d_revalidate函数去验证
		error = d_revalidate(dentry, nd->flags);
        
		// dentry有效就直接退出循环
		if (likely(error > 0))
			break;
		
		// 如果出错就让dentry无效
		if (error)
			goto out_dput;
		d_invalidate(dentry);
		dput(dentry);
		dentry = NULL;
	}

	// 如果有inode，说明文件已经打开，直接返回
	// 因为inode是共用的
	if (dentry->d_inode) {
		/* Cached positive dentry: will open in f_op->open */
		return dentry;
	}

	// 走到这儿就是在内存里没找到,下面就要去具体的文件系统查找或者创建
	if (unlikely(!got_write)) // 如果不是创建文件就删除截断标志
		open_flag &= ~O_TRUNC;

	if (open_flag & O_CREAT) { // 创建文件
		// 如果是检查文件是否存在，则不截断
		if (open_flag & O_EXCL)
			open_flag &= ~O_TRUNC;
		
		// 如果文件系统不支持acl，就去除文件的umask设置的权限
		if (!IS_POSIXACL(dir->d_inode))
			mode &= ~current_umask();
		if (likely(got_write))
			// 检查写权限
			create_error = may_o_create(&nd->path, dentry, mode);
		else
			create_error = -EROFS;
	}
	// 权限出错则不创建
	if (create_error)
		open_flag &= ~O_CREAT;

	// todo: 原子打开文件？
	if (dir_inode->i_op->atomic_open) {
		dentry = atomic_open(nd, dentry, file, open_flag, mode);
		if (unlikely(create_error) && dentry == ERR_PTR(-ENOENT))
			dentry = ERR_PTR(create_error);
		return dentry;
	}

	if (d_in_lookup(dentry)) { // 新创建的dentry
		
		// 调用具体文件系统来查找文件的inode
		struct dentry *res = dir_inode->i_op->lookup(dir_inode, dentry,
							     nd->flags);
		// 去除DCACHE_PAR_LOOKUP标志，以及其它操作
		d_lookup_done(dentry);

		// 出错
		if (unlikely(res)) {
			if (IS_ERR(res)) {
				error = PTR_ERR(res);
				goto out_dput;
			}
			dput(dentry);
			dentry = res;
		}
	}

	/* Negative dentry, just create the file */
	if (!dentry->d_inode && (open_flag & O_CREAT)) {
		// 这个分支是inode不存在，需要创建
		file->f_mode |= FMODE_CREATED;

		// 打一条审计日志
		audit_inode_child(dir_inode, dentry, AUDIT_TYPE_CHILD_CREATE);

		if (!dir_inode->i_op->create) {
			error = -EACCES;
			goto out_dput;
		}

		// 调用具体文件系统创建一个inode
		error = dir_inode->i_op->create(dir_inode, dentry, mode,
						open_flag & O_EXCL);
		if (error)
			goto out_dput;
	}

	// 出错
	if (unlikely(create_error) && !dentry->d_inode) {
		error = create_error;
		goto out_dput;
	}

	// 读取inode成功，返回dentry
	return dentry;

out_dput:
	dput(dentry);
	return ERR_PTR(error);
}
```

## 创建文件的权限检查
```c
static int may_o_create(const struct path *dir, struct dentry *dentry, umode_t mode)
{
	struct user_namespace *s_user_ns;

	// 回调 path_mknod 钩子函数
	int error = security_path_mknod(dir, dentry, mode, 0);
	if (error)
		return error;

	s_user_ns = dir->dentry->d_sb->s_user_ns;
	// 检查uid, gid合法性
	if (!kuid_has_mapping(s_user_ns, current_fsuid()) ||
	    !kgid_has_mapping(s_user_ns, current_fsgid()))
		return -EOVERFLOW;

	// 检查当前进程在目标目录的权限
	error = inode_permission(dir->dentry->d_inode, MAY_WRITE | MAY_EXEC);
	if (error)
		return error;

	// 调用 inode_create 钩子函数
	return security_inode_create(dir->dentry->d_inode, dentry, mode);
}

int inode_permission(struct inode *inode, int mask)
{
	int retval;

	// 检查超级块上的权限
	retval = sb_permission(inode->i_sb, inode, mask);
	if (retval)
		return retval;

	if (unlikely(mask & MAY_WRITE)) {
		// 当前目录不可修改
		if (IS_IMMUTABLE(inode))
			return -EPERM;

		// uid或者gid无效
		if (HAS_UNMAPPED_ID(inode))
			return -EACCES;
	}

	retval = do_inode_permission(inode, mask);
	if (retval)
		return retval;

	// todo: cgroup不懂
	retval = devcgroup_inode_permission(inode, mask);
	if (retval)
		return retval;

	// 调用 inode_permission 钩子函数
	return security_inode_permission(inode, mask);
}

static int sb_permission(struct super_block *sb, struct inode *inode, int mask)
{
	if (unlikely(mask & MAY_WRITE)) {
		umode_t mode = inode->i_mode;

		// 如果是只读文件系统,则不允许创建普通文件,目录,软链接
		if (sb_rdonly(sb) && (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode)))
			return -EROFS;
	}
	return 0;
}

static inline int do_inode_permission(struct inode *inode, int mask)
{
	if (unlikely(!(inode->i_opflags & IOP_FASTPERM))) {
		// 先调用具体文件系统检查权限, 只检查一次
		if (likely(inode->i_op->permission))
			return inode->i_op->permission(inode, mask);

		/* This gets set once for the inode lifetime */
		spin_lock(&inode->i_lock);
		// 写入已检查标志
		inode->i_opflags |= IOP_FASTPERM;
		spin_unlock(&inode->i_lock);
	}
	// 通用权限检查
	return generic_permission(inode, mask);
}

int generic_permission(struct inode *inode, int mask)
{
	int ret;

	// 检查acl权限,一般是selinux
	ret = acl_permission_check(inode, mask);
	if (ret != -EACCES)
		return ret;

	if (S_ISDIR(inode->i_mode)) { // 目录
		// 如果是读,要求有读取,搜索权限
		if (!(mask & MAY_WRITE))
			if (capable_wrt_inode_uidgid(inode,
						     CAP_DAC_READ_SEARCH))
				return 0;
		// todo: 没看懂
		if (capable_wrt_inode_uidgid(inode, CAP_DAC_OVERRIDE))
			return 0;
		// 上面的权限通不过就报错了
		return -EACCES;
	}

	// 下面是普通文件的权限检查

	// 过滤除了读,写,执行的权限
	mask &= MAY_READ | MAY_WRITE | MAY_EXEC;

	// 读 要求有读,执行权能
	if (mask == MAY_READ)
		if (capable_wrt_inode_uidgid(inode, CAP_DAC_READ_SEARCH))
			return 0;
	
	// 下面是写权限检查

	// 如果没有执行标志,或者目录本身对所有人都是可执行的,那要有CAP_DAC_OVERRIDE权能
	if (!(mask & MAY_EXEC) || (inode->i_mode & S_IXUGO))
		if (capable_wrt_inode_uidgid(inode, CAP_DAC_OVERRIDE))
			return 0;

	return -EACCES;
}
```
## 与file关联
```c
static int do_open(struct nameidata *nd,
		   struct file *file, const struct open_flags *op)
{
	int open_flag = op->open_flag;
	bool do_truncate;
	int acc_mode;
	int error;

	// 如果没有FMODE_OPENED， FMODE_CREATED标志，则通过complete_walk
	// 完成路径遍历，如果有错误则返回
	if (!(file->f_mode & (FMODE_OPENED | FMODE_CREATED))) {
		error = complete_walk(nd);
		if (error)
			return error;
	}
	// 审计信息
	if (!(file->f_mode & FMODE_CREATED))
		audit_inode(nd->name, nd->path.dentry, 0);
	
	if (open_flag & O_CREAT) { // 如果有创建文件
		// O_EXCL表示检查文件是否存在，如果文件不是新建的,那就表示已经存在,出返回出错
		if ((open_flag & O_EXCL) && !(file->f_mode & FMODE_CREATED))
			return -EEXIST;
		// 如果目标结点是目录，出错。创建目录有专门的系统调用
		if (d_is_dir(nd->path.dentry))
			return -EISDIR;
		// 如果是创建，则检查相应权限
		error = may_create_in_sticky(nd->dir_mode, nd->dir_uid,
					     d_backing_inode(nd->path.dentry));
		if (unlikely(error))
			return error;
	}
	// 如果要求找目录，但是没找到目录，则出错
	if ((nd->flags & LOOKUP_DIRECTORY) && !d_can_lookup(nd->path.dentry))
		return -ENOTDIR;

	do_truncate = false;
	acc_mode = op->acc_mode;
	if (file->f_mode & FMODE_CREATED) {
		// 如果文件已经创建就不再执行O_TRUNC操作
		open_flag &= ~O_TRUNC;
		acc_mode = 0;
	} else if (d_is_reg(nd->path.dentry) && open_flag & O_TRUNC) {
		// 这个分支表示目标是普通文件，而且要求截断

		// 截断时要检查写权限
		error = mnt_want_write(nd->path.mnt);
		if (error)
			return error;
		do_truncate = true;
	}

	// 根据访问文件的要求检查文件权限
	error = may_open(&nd->path, acc_mode, open_flag);
	if (!error && !(file->f_mode & FMODE_OPENED))
		// 如果没有错误，则打开文件，这里打开文件是将file主具体文件系统关联
		error = vfs_open(&nd->path, file);
	if (!error)
		// 静态度量相关检查
		error = ima_file_check(file, op->acc_mode);
	if (!error && do_truncate)
		// 处理截断文件
		error = handle_truncate(file);
	if (unlikely(error > 0)) {
		WARN_ON(1);
		error = -EINVAL;
	}
	// 如果截断了，通知文件系统，丢弃写操作？
	if (do_truncate)
		mnt_drop_write(nd->path.mnt);
	return error;
}

int vfs_open(const struct path *path, struct file *file)
{
	// 设置f_patch，path里有dentry, vfsmount信息
	file->f_path = *path;

	// d_backing_inode实际上获取的就是dentry的inode
	return do_dentry_open(file, d_backing_inode(path->dentry), NULL);
}

static int do_dentry_open(struct file *f,
			  struct inode *inode,
			  int (*open)(struct inode *, struct file *))
{
	static const struct file_operations empty_fops = {};
	int error;

	// 增加path的引用计数
	path_get(&f->f_path);
	
	// 设置inode, i_mapping函数表等信息
	f->f_inode = inode;
	f->f_mapping = inode->i_mapping;
	f->f_wb_err = filemap_sample_wb_err(f->f_mapping);
	f->f_sb_err = file_sample_sb_err(f);

	// todo: 如果是O_PATH，刚直接返回?
	if (unlikely(f->f_flags & O_PATH)) {
		f->f_mode = FMODE_PATH | FMODE_OPENED;
		f->f_op = &empty_fops;
		return 0;
	}

	// 如果要求写，不是特殊文件，则检查用户和文件系统的可写权限
	// 特殊文件指: 字符设备， 块设备， 命名管道，socket
	if (f->f_mode & FMODE_WRITE && !special_file(inode->i_mode)) {
		error = get_write_access(inode);
		if (unlikely(error))
			goto cleanup_file;
		error = __mnt_want_write(f->f_path.mnt);
		if (unlikely(error)) {
			put_write_access(inode);
			goto cleanup_file;
		}
		f->f_mode |= FMODE_WRITER;
	}

	/* POSIX.1-2008/SUSv4 Section XSI 2.9.7 */
	if (S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode))
		f->f_mode |= FMODE_ATOMIC_POS;

	// 将具体文件系统的操作函数指针与文件关联
	// 这里面就是有open, release, read, write那些函数
	f->f_op = fops_get(inode->i_fop);
	if (WARN_ON(!f->f_op)) {
		error = -ENODEV;
		goto cleanup_all;
	}

	// 调用安全钩子函数
	error = security_file_open(f);
	if (error)
		goto cleanup_all;

	error = break_lease(locks_inode(f), f->f_flags);
	if (error)
		goto cleanup_all;

	// 设置文件的读，写，定位标志
	f->f_mode |= FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE;

	// 调用具体文件系统的open函数
	if (!open)
		open = f->f_op->open;
	if (open) {
		error = open(inode, f);
		if (error)
			goto cleanup_all;
	}

	// 设置文件已打开标志
	f->f_mode |= FMODE_OPENED;
	// 如果文件只读，增加相应计数器
	if ((f->f_mode & (FMODE_READ | FMODE_WRITE)) == FMODE_READ)
		i_readcount_inc(inode);
	
	// 根据有无读写指针，设置相应的读写标志
	if ((f->f_mode & FMODE_READ) &&
	     likely(f->f_op->read || f->f_op->read_iter))
		f->f_mode |= FMODE_CAN_READ;
	if ((f->f_mode & FMODE_WRITE) &&
	     likely(f->f_op->write || f->f_op->write_iter))
		f->f_mode |= FMODE_CAN_WRITE;

	// todo: write_hint是啥？
	f->f_write_hint = WRITE_LIFE_NOT_SET;

	// 清除文件中的这些标志，这些标志已经没用了
	f->f_flags &= ~(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);

	// 初始化预读变量
	file_ra_state_init(&f->f_ra, f->f_mapping->host->i_mapping);

	// 如果是以O_DIRECT打开，但是具体文件系统又不支持这个操作，则出错
	if (f->f_flags & O_DIRECT) {
		if (!f->f_mapping->a_ops || !f->f_mapping->a_ops->direct_IO)
			return -EINVAL;
	}

	// 大页目前还不支持文件写，所以如果是写文件，则丢弃大页里的数据
	if ((f->f_mode & FMODE_WRITE) && filemap_nr_thps(inode->i_mapping))
		truncate_pagecache(inode, 0);

	return 0;

cleanup_all:
	if (WARN_ON_ONCE(error > 0))
		error = -EINVAL;
	fops_put(f->f_op);
	if (f->f_mode & FMODE_WRITER) {
		put_write_access(inode);
		__mnt_drop_write(f->f_path.mnt);
	}
cleanup_file:
	path_put(&f->f_path);
	f->f_path.mnt = NULL;
	f->f_path.dentry = NULL;
	f->f_inode = NULL;
	return error;
}

```

## 创建临时文件
```c
static int do_tmpfile(struct nameidata *nd, unsigned flags,
		const struct open_flags *op,
		struct file *file)
{
	struct dentry *child;
	struct path path;
	// 找到父目录
	int error = path_lookupat(nd, flags | LOOKUP_DIRECTORY, &path);
	if (unlikely(error))
		return error;
	// 检查父目录写权限
	error = mnt_want_write(path.mnt);
	if (unlikely(error))
		goto out;
	// 创建dentry, inode
	child = vfs_tmpfile(path.dentry, op->mode, op->open_flag);
	error = PTR_ERR(child);
	if (IS_ERR(child))
		goto out2;
	dput(path.dentry);

	// 设置成刚创建的文件
	path.dentry = child;

	// 打印审计日志
	audit_inode(nd->name, child, 0);
	/* Don't check for other permissions, the inode was just created */

	// 检查打开权限
	error = may_open(&path, 0, op->open_flag);
	if (error)
		goto out2;
	// 设置文件的挂载点指针
	file->f_path.mnt = path.mnt;
	// finish_open 与上面的vfs_open差不多
	error = finish_open(file, child, NULL);
out2:
	mnt_drop_write(path.mnt);
out:
	path_put(&path);
	return error;
}

struct dentry *vfs_tmpfile(struct dentry *dentry, umode_t mode, int open_flag)
{
	struct dentry *child = NULL;
	struct inode *dir = dentry->d_inode;
	struct inode *inode;
	int error;

	// 因为要创建文件，所以要检查在这个目录的写，执行权限
	error = inode_permission(dir, MAY_WRITE | MAY_EXEC);
	if (error)
		goto out_err;
	error = -EOPNOTSUPP;
	// 如果文件系统没有tmpfile这个指针，则不支持临时文件
	if (!dir->i_op->tmpfile)
		goto out_err;
	error = -ENOMEM;

	// 申请一个dentry
	child = d_alloc(dentry, &slash_name);
	if (unlikely(!child))
		goto out_err;
	// 调用具体文件系统创建临时文件
	error = dir->i_op->tmpfile(dir, child, mode);
	if (error)
		goto out_err;
	error = -ENOENT;
	inode = child->d_inode;
	// 创建失败，返回
	if (unlikely(!inode))
		goto out_err;
	// 如果没有O_EXCL标志，则表示文件是可链接的
	if (!(open_flag & O_EXCL)) {
		spin_lock(&inode->i_lock);
		inode->i_state |= I_LINKABLE;
		spin_unlock(&inode->i_lock);
	}
	// 静态度量？
	ima_post_create_tmpfile(inode);
	return child;

out_err:
	dput(child);
	return ERR_PTR(error);
}
```

## 用O_PATH方式打开
```c
static int do_o_path(struct nameidata *nd, unsigned flags, struct file *file)
{
	struct path path;
	// 找到父目录dentry
	int error = path_lookupat(nd, flags, &path);
	if (!error) {
		// 审计
		audit_inode(nd->name, path.dentry, 0);
		// 将file与dentry关联
		error = vfs_open(&path, file);
		path_put(&path);
	}
	return error;
}
```

## 将file与fd关联
```c
void fd_install(unsigned int fd, struct file *file)
{
	__fd_install(current->files, fd, file);
}

void __fd_install(struct files_struct *files, unsigned int fd,
		struct file *file)
{
	struct fdtable *fdt;

	rcu_read_lock_sched();

	if (unlikely(files->resize_in_progress)) { // files正在扩容
		rcu_read_unlock_sched();
		spin_lock(&files->file_lock);
		fdt = files_fdtable(files);

		// 如果fd对应的文件不为空，那系统就出bug，oops
		BUG_ON(fdt->fd[fd] != NULL);
		// 将file设置为fd对应的位置
		rcu_assign_pointer(fdt->fd[fd], file);
		spin_unlock(&files->file_lock);
		return;
	}
	// 下面是没有扩容的正常路径，大多数情况下走这个路径
	// 将file设置到fd对应的位置
	smp_rmb();
	fdt = rcu_dereference_sched(files->fdt);
	BUG_ON(fdt->fd[fd] != NULL);
	rcu_assign_pointer(fdt->fd[fd], file);
	rcu_read_unlock_sched();
}
```