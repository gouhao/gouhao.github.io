# 数据结构: 文件相关
本文从进程的视角来查看文件相关的数据结构。

## 1. struct task_struct
```c
// include/linux/sched.h

struct task_struct {
	...

	/* Filesystem information: */
	struct fs_struct		*fs;

	/* Open file information: */
	struct files_struct		*files;
	...
};
```
在进程与文件相关的2个主要的字段是`fs`，`files`。其中`fs`是进程所在文件系统的相关信息，`files`是进程打开文件的信息。

## 2. struct fs_struct
先来看`fs`，也就是`struct fs_struct`。
```c
// include/linux/fs_struct.h

struct fs_struct {
	int users; // 使用的用户数
	spinlock_t lock; // 锁，保护此结构
	seqcount_spinlock_t seq; // 顺序锁，保护此结构
	int umask; // 创建文件时的掩码
	int in_exec; // 是否正在执行exec
	struct path root, pwd; // 根目录和工作目录
} __randomize_layout;
```
主要字段：  
`umask`：创建文件时的掩码。可以用`umask`系统调用修改此值（展示`umask`代码，kernel/sys.c:1822）。比如：掩码是0002，我们创建一个文件权限为`777`时，最终文件的权限是`775`（演示`demo01.c`）。  
`root`：进程的根目录。可以用`chroot`系统调用修改此值（展示`chroot`代码，fs/open.c:533），在遍历路径的时候，如果写的是绝对路径，从这个目录开始查找。  
`pwd`：进程工作目录。可以用`chdir`系统调用修改此值（展示`chdir`代码，fs/open.c:485）。在遍历路径的时候，如果写的是相对路径，则从这个目录开始查找。

### 2.1 struct path
```c
// include/linux/path.h

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
} __randomize_layout;
```
patch由只有2个字段：
`mnt`： 所属的文件系统。
`dentry`：所在目录/文件和dentry结构。

## 3. struct files_struct
```c
struct files_struct {
	/*
	* read mostly part
	*/
	atomic_t count; // 已打开文件数量
	bool resize_in_progress;
	wait_queue_head_t resize_wait;

	struct fdtable __rcu *fdt; // 文件表
	struct fdtable fdtab;
	/*
	* written part on a separate cache line in SMP
	*/
	spinlock_t file_lock ____cacheline_aligned_in_smp;
	unsigned int next_fd; // 下一次分配的fd

	unsigned long close_on_exec_init[1]; // exec时要关闭的fd位图
	unsigned long open_fds_init[1]; // 已打开的fd位图
	unsigned long full_fds_bits_init[1]; // 已满的fd位图

	// #define NR_OPEN_DEFAULT BITS_PER_LONG
	struct file __rcu * fd_array[NR_OPEN_DEFAULT]; // 文件数组
};

struct fdtable {
	unsigned int max_fds; // 最大的fd数量
	struct file __rcu **fd; // 文件数组指针
	unsigned long *close_on_exec; // 执行时关闭位图指针
	unsigned long *open_fds; // 已打开的fd位图指针
	unsigned long *full_fds_bits; // 已满的fd位图指针
	struct rcu_head rcu;
};
```
`struct files_struct`主要记录着进程已打开文件的一些信息，主要有：打开文件的数量、指向文件的指针、fd的相关信息。  
在`struct files_struct`里有一些看似重复的字段，比如：有2个`struct fdtable`字段，分别是：`fdt`和`fdtab`，`struct files_struct`和`struct fdtable`里都有: `close_on_exec[_init]`， `open_fds[_init]`, `full_fds_bits[_init]`，以及`struct files_struct->fd_array`和`struct fdtable->fd`。以前Unix可打开文件数量是固定的：32，所以早期的`fd_array`，以及各个位图都是32位，显然32个文件对于今天的系统肯定是不够用的，为了克服这个缺陷，就新增加了一些类似的指针。刚开始`struct files_struct->fdtab`里的`fd`，`close_on_exec`，`open_fds`, `full_fds_bits`，分别指向`struct files_struct`里的`fd_array`，`close_on_exec_init`，`open_fds_init`，`full_fds_bits_init`，然后让`struct files_struct->fdt`指向`struct files_struct->fdtab`；如果进程打开的文件数量超过了32个，则动态分配一个`struct fdtable`以及`struct fdtable`里的`fd`，`close_on_exec`，`open_fds`，`full_fds_bits`，把原来`struct files_struct`里的相关字段的值再复制过去，然后让`struct files_struct->fdt`指向新分配的`struct fdtable`。  
`fd_array`：这个数组里存放的是进程打开的文件指针，`open`系统调用返回的fd就是这个数组的下标。  
`next_fd`：下一次打开文件时使用的fd，也就是下一个文件要存放在`fd_array`的什么位置。
`close_on_exec`：执行时关闭位图。在使用`open`系统调用或者动态修改文件标志为`O_CLOEXEC`，
`open_fds`：已打开的fd在`open_fds`里对应的位置1
`full_fds_bits`：这个字段也是记录已打开的fd，不过这里的每一位对应着BITS_PER_LONG，比如前64个fd都打开了，则`full_fds_bits`的第0位会置1。

## 4. struct file
```c
struct file {
	...
	struct path		f_path;	// 包含dentry与文件系统
	struct inode		*f_inode; // 对应的inode
	const struct file_operations	*f_op; // 文件操作指针

	...
	atomic_long_t		f_count; // 引用计数
	...
	loff_t			f_pos; // 读写的位置
	...
	struct file_ra_state	f_ra; // 预读相关

	...
	struct address_space	*f_mapping; // 映射
	...
} __randomize_layout
  __attribute__((aligned(4)));	/* lest something weird decides that 2 is OK */
```
`struct file`对象主要包含了进程对文件操作的上下文，比如当前的读写位置`f_pos`，预读状态`f_ra`。`struct file`通过`f_path`与具体的文件关联。同一个文件如果打开多次，也会有多个`struct file`对象存放在`struct files_struct->fd_array`里。

### 4.1 struct file_operations
文件操作表，很多同名的系统调用最终会通过这个函数表与具体文件系统里的文件通信。
```c
struct file_operations {
	struct module *owner;
	// seek
	loff_t (*llseek) (struct file *, loff_t, int);

	// 读写
	ssize_t (*read) (struct file *, char __user *, size_t, loff_t *);
	ssize_t (*write) (struct file *, const char __user *, size_t, loff_t *);
	ssize_t (*read_iter) (struct kiocb *, struct iov_iter *);
	ssize_t (*write_iter) (struct kiocb *, struct iov_iter *);

	int (*iopoll)(struct kiocb *kiocb, bool spin);
	int (*iterate) (struct file *, struct dir_context *);
	int (*iterate_shared) (struct file *, struct dir_context *);
	
	// poll
	__poll_t (*poll) (struct file *, struct poll_table_struct *);

	// ioctl
	long (*unlocked_ioctl) (struct file *, unsigned int, unsigned long);
	long (*compat_ioctl) (struct file *, unsigned int, unsigned long);

	// mmap
	int (*mmap) (struct file *, struct vm_area_struct *);
	unsigned long mmap_supported_flags;

	// 打开
	int (*open) (struct inode *, struct file *);
	int (*flush) (struct file *, fl_owner_t id);

	// close时，如果文件没人再用，会调用这个接口
	int (*release) (struct inode *, struct file *);

	// 同步
	int (*fsync) (struct file *, loff_t, loff_t, int datasync);
	int (*fasync) (int, struct file *, int);

	// 锁
	int (*lock) (struct file *, int, struct file_lock *);
	ssize_t (*sendpage) (struct file *, struct page *, int, size_t, loff_t *, int);

	// 获取未映射vma
	unsigned long (*get_unmapped_area)(struct file *, unsigned long, unsigned long, unsigned long, unsigned long);
	int (*check_flags)(int);

	// 锁
	int (*flock) (struct file *, int, struct file_lock *);

	// splice
	ssize_t (*splice_write)(struct pipe_inode_info *, struct file *, loff_t *, size_t, unsigned int);
	ssize_t (*splice_read)(struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
	int (*setlease)(struct file *, long, struct file_lock **, void **);
	// 预分配空间
	long (*fallocate)(struct file *file, int mode, loff_t offset,
			  loff_t len);
	void (*show_fdinfo)(struct seq_file *m, struct file *f);
#ifndef CONFIG_MMU
	unsigned (*mmap_capabilities)(struct file *);
#endif

	// 复制/映射文件范围
	ssize_t (*copy_file_range)(struct file *, loff_t, struct file *,
			loff_t, size_t, unsigned int);
	loff_t (*remap_file_range)(struct file *file_in, loff_t pos_in,
				   struct file *file_out, loff_t pos_out,
				   loff_t len, unsigned int remap_flags);
	// advise
	int (*fadvise)(struct file *, loff_t, loff_t, int);
	bool may_pollfree;
} __randomize_layout;
```

## 5. struct dentry
> 注意：本小节中所说的文件均指目录或文件，因为目录也是一种文件。

```c
struct dentry {
	...
	struct hlist_bl_node d_hash;	/* 哈希表，加速查找 */
	struct dentry *d_parent;	/* 父目录 */
	struct qstr d_name; // 文件名
	struct inode *d_inode;		/* 文件对应的inode*/
	unsigned char d_iname[DNAME_INLINE_LEN]; // 文件名较短时用这个存储，DNAME_INLINE_LEN(32)

	/* Ref lookup also touches following */
	struct lockref d_lockref;	/* per-dentry lock and refcount */
	const struct dentry_operations *d_op; // dentry 操作函数表
	struct super_block *d_sb;	// 超级块
	... 
	struct list_head d_child;	// 子结点头指针，用来挂入父目录的d_subdirs链表
	struct list_head d_subdirs;	// 子结点列表
	/*
	 * d_alias and d_rcu can share memory
	 */
	union {
		struct hlist_node d_alias;	// 链入inode的
		struct hlist_bl_node d_in_lookup_hash;	/* only for in-lookup ones */
	 	struct rcu_head d_rcu;
	} d_u;
} __randomize_layout;

struct qstr {
	union {
		struct {
			// #define HASH_LEN_DECLARE u32 hash; u32 len
			HASH_LEN_DECLARE; // 分开保存
		};
		u64 hash_len; // 哈希值和长度保存在一起
	};
	const unsigned char *name; // 文件名指针
};
```
主要字段：
`d_hash`：这个是链入到缓存里的哈希表`dentry_hashtable`里，用来加速查找。
`d_parent`：指向父节点。
`d_name`：保存文件名和哈希值。哈希值就是`d_hash`表里的key。`d_name->name`是文件名指针，如果文件名长度小于32则，它指向`struct dentry->d_iname`，否则，指向动态分配的内存。
`d_inode`：与dentry关联的inode。
`d_op`：dentry相关的操作函数表。
`d_sb`：所在文件系统的超级块。
`d_child`、`d_subdirs`：子节点的头指针与链表，子节点通过`d_child`挂到父节点的`d_subdirs`。
`d_alias`：链表`struct inode->i_dentry`链表，`dentry`与`inode`是多对一的关系。

### 5.1 struct dentry_operations
```c
struct dentry_operations {
	// 判断是否有效
	int (*d_revalidate)(struct dentry *, unsigned int);
	int (*d_weak_revalidate)(struct dentry *, unsigned int);
	// 哈希值
	int (*d_hash)(const struct dentry *, struct qstr *);
	// 名称比较
	int (*d_compare)(const struct dentry *,
			unsigned int, const char *, const struct qstr *);
	int (*d_delete)(const struct dentry *);
	int (*d_init)(struct dentry *);
	void (*d_release)(struct dentry *);
	void (*d_prune)(struct dentry *);
	void (*d_iput)(struct dentry *, struct inode *);
	char *(*d_dname)(struct dentry *, char *, int);
	struct vfsmount *(*d_automount)(struct path *);
	int (*d_manage)(const struct path *, bool);
	struct dentry *(*d_real)(struct dentry *, const struct inode *);
} ____cacheline_aligned;
```

## 6. struct inode
```c
struct inode {
	umode_t			i_mode; // 文件模式
	...
	kuid_t			i_uid; // 所属用户id
	kgid_t			i_gid; // 所属组id
	unsigned int		i_flags;

	...

	const struct inode_operations	*i_op; // inode函数表
	struct super_block	*i_sb; // 超级块
	struct address_space	*i_mapping; // 地址映射相关操作

	...

	dev_t			i_rdev; // 所在设备的设备号
	loff_t			i_size; // 文件大小
	struct timespec64	i_atime; // 访问时间
	struct timespec64	i_mtime; // 内容修改时间
	struct timespec64	i_ctime; // 元数据修改时间？元数据就是inode自己的一些标志，id等等那些东西
	...
	u8			i_blkbits; // 块大小，2的幂
	...
	blkcnt_t		i_blocks; // 有多少个块

	...

	struct hlist_node	i_hash; // 缓存哈希表
	...

	union {
		struct hlist_head	i_dentry; // dentry链表
		struct rcu_head		i_rcu;
	};
	...
	
	union {
		const struct file_operations	*i_fop; // 文件操作
		void (*free_inode)(struct inode *);
	};

	struct address_space	i_data; // i_mapping一般指向这个字段
	
	...
} __randomize_layout;

struct inode_operations {
	// 查找文件
	struct dentry * (*lookup) (struct inode *,struct dentry *, unsigned int);
	const char * (*get_link) (struct dentry *, struct inode *, struct delayed_call *);
	int (*permission) (struct inode *, int);
	// 获取acl
	struct posix_acl * (*get_acl)(struct inode *, int);

	int (*readlink) (struct dentry *, char __user *,int);

	// 创建文件
	int (*create) (struct inode *,struct dentry *, umode_t, bool);
	// 建链接
	int (*link) (struct dentry *,struct inode *,struct dentry *);
	// 删链接
	int (*unlink) (struct inode *,struct dentry *);
	// 符号链接
	int (*symlink) (struct inode *,struct dentry *,const char *);
	// 创建/删除目录
	int (*mkdir) (struct inode *,struct dentry *,umode_t);
	int (*rmdir) (struct inode *,struct dentry *);
	// 创建节点
	int (*mknod) (struct inode *,struct dentry *,umode_t,dev_t);
	// 重命名
	int (*rename) (struct inode *, struct dentry *,
			struct inode *, struct dentry *, unsigned int);
	// 设置/获取/遍历扩展属性
	int (*setattr) (struct dentry *, struct iattr *);
	int (*getattr) (const struct path *, struct kstat *, u32, unsigned int);
	ssize_t (*listxattr) (struct dentry *, char *, size_t);
	int (*fiemap)(struct inode *, struct fiemap_extent_info *, u64 start,
		      u64 len);
	int (*update_time)(struct inode *, struct timespec64 *, int);
	int (*atomic_open)(struct inode *, struct dentry *,
			   struct file *, unsigned open_flag,
			   umode_t create_mode);
	int (*tmpfile) (struct inode *, struct dentry *, umode_t);
	// 设置acl
	int (*set_acl)(struct inode *, struct posix_acl *, int);
} ____cacheline_aligned;
```
主要字段：
`i_mode`：这个字段里包含了文件的权限和文件类型。0～8位存放权限，9～11位存放suid，sgid，svtx标志，12~15位存放文件类型（详见：include/uapi/linux/stat.h）  
`i_u/gid`：所属的用户及组  
`i_flags`：存放着文件所用到的各种标志  
`i_op`：inode函数操作表  
`i_sb`：inode所属的超级块  
`i_mapping`：地址映射及page-cache  
`i_size`：文件大小  
`i_a/m/ctime`：相关的时间   
`i_blocks`：所占用的块数  
`i_hash`：inode缓存，加还查找  
`i_dentry`：dentry的链表  
`i_fop`：文件操作函数表，`struct file->f_op`一般来自这个`i_fop`



