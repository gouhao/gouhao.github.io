# 文件系统相关数据结构
源码基于5.10
## 1. file_system_type
```c
struct file_system_type {
	// 文件系统名
	const char *name;
	// 该文件系统的标志
	int fs_flags;
#define FS_REQUIRES_DEV		1  // 需要真实设备
#define FS_BINARY_MOUNTDATA	2
#define FS_HAS_SUBTYPE		4  // 有子类？
#define FS_USERNS_MOUNT		8	/* Can be mounted by userns root */
#define FS_DISALLOW_NOTIFY_PERM	16	/* Disable fanotify permission events */
#define FS_THP_SUPPORT		8192	/* Remove once all fs converted */
#define FS_RENAME_DOES_D_MOVE	32768	/* FS will handle d_move() during rename() internally. */

	// 初始化fs_context的指针（新代码大多用这个）
	int (*init_fs_context)(struct fs_context *);
	const struct fs_parameter_spec *parameters;
	// 挂载函数，老代码用这个的多，现在推荐用init_fs_context
	struct dentry *(*mount) (struct file_system_type *, int,
			const char *, void *);
	// 释放超级块的回调
	void (*kill_sb) (struct super_block *);
	struct module *owner; // 如果是模块，则这里指向模块的引用
	struct file_system_type * next; // 下一个fs的指针
	struct hlist_head fs_supers; // 已挂载文件系统的超级块哈希链表
	...
};
```
每个具体的文件系统都会向系统注册file_system_type结构，内核里`file_systems`的链表用来记录内核里所有已注册的文件系统结构。  
这个结构里的`init_fs_context`是新的挂载接口，新的文件系统应该使用这个接口，而`mount`是老的接口。现有代码里对使用`mount`接口的做了兼容，会把mount也转换成使用context的形式。  
`parameters`是挂载时的选项。  
`kill_sb`是在释放超级块的时候调用，当前文件系统的超级块也保存在`fs_supers`里。  
标志里比较常用的就是`FS_REQUIRES_DEV`，表示此文件系统是建立在真实设备上的，这样在挂载的时候就会打开设备。

## 2. struct fs_context
```c
struct fs_context {
	const struct fs_context_operations *ops; // 操作函数表
	struct mutex		uapi_mutex;	/* Userspace access mutex */
	struct file_system_type	*fs_type; // 文件系统类型
	void			*fs_private;	// 存储各文件系统的私有数据
	void			*sget_key;
	struct dentry		*root;		// 根结点
	struct user_namespace	*user_ns;	/* The user namespace for this mount */
	struct net		*net_ns;	/* The network namespace for this mount */
	const struct cred	*cred;		/* The mounter's credentials */
	struct p_log		log;		/* Logging buffer */
	const char		*source;	/* The source name (eg. dev path) */
	void			*security;	/* Linux S&M options */
	void			*s_fs_info;	// 存储各文件系统的私有数据，大多数用来fs存储超级块信息
	unsigned int		sb_flags;	/* Proposed superblock flags (SB_*) */
	unsigned int		sb_flags_mask;	/* Superblock flags that were changed */
	unsigned int		s_iflags;	/* OR'd with sb->s_iflags */
	unsigned int		lsm_flags;	/* Information flags from the fs to the LSM */
	enum fs_context_purpose	purpose:8;
	enum fs_context_phase	phase:8;	/* The phase the context is in */
	bool			need_free:1;	/* Need to call ops->free() */
	bool			global:1;	/* Goes into &init_user_ns */
	bool			oldapi:1;	/* Coming from mount(2) */
};

struct fs_context_operations {
	void (*free)(struct fs_context *fc); // 一般在umount时调用
	int (*dup)(struct fs_context *fc, struct fs_context *src_fc);
	int (*parse_param)(struct fs_context *fc, struct fs_parameter *param); // 解析参数，这是一个一个解析
	int (*parse_monolithic)(struct fs_context *fc, void *data); // 解析参数，解析用户层传来的整个参数
	int (*get_tree)(struct fs_context *fc); // 获取文件系统树结构
	int (*reconfigure)(struct fs_context *fc); // 重新配置
};
```
常用的字段有：
`ops`：挂载时用的函数表。这个函数表里最重要的就是`get_tree`，这相当于每次挂载的入口，在这里面会读取超级块，根结点等重要信息。  
`root`：挂载成功的文件系统都要设置这个字段，只有读出了根节点，文件树才能识别这个文件系统。  
`fs_private`, `s_fs_info`：都可以保存私有数据。

## 3. struct super_block
```c
struct super_block {
	struct list_head	s_list;		// 链入 super_blocks
	dev_t			s_dev;		/* search index; _not_ kdev_t */
	unsigned char		s_blocksize_bits; // 块大小，2次幂
	unsigned long		s_blocksize; // 块大小，单位是byte
	loff_t			s_maxbytes;	// 最大文件大小
	struct file_system_type	*s_type; // fs类型

	// 各种函数操作表
	const struct super_operations	*s_op;
	const struct dquot_operations	*dq_op;
	const struct quotactl_ops	*s_qcop;
	const struct export_operations *s_export_op;

	unsigned long		s_flags;
	unsigned long		s_iflags;	/* internal SB_I_* flags */
	unsigned long		s_magic; // 魔数
	struct dentry		*s_root; // 根结点
	struct rw_semaphore	s_umount;
	int			s_count; // 引用计数
	atomic_t		s_active;
#ifdef CONFIG_SECURITY
	void                    *s_security;
#endif
	const struct xattr_handler **s_xattr; // 扩展属性处理
#ifdef CONFIG_FS_ENCRYPTION
	const struct fscrypt_operations	*s_cop;
	struct fscrypt_keyring	*s_master_keys; /* master crypto keys in use */
#endif
#ifdef CONFIG_FS_VERITY
	const struct fsverity_operations *s_vop;
#endif
#ifdef CONFIG_UNICODE
	struct unicode_map *s_encoding;
	__u16 s_encoding_flags;
#endif
	struct hlist_bl_head	s_roots;	/* alternate root dentries for NFS */
	struct list_head	s_mounts;	// struct mount的列表
	struct block_device	*s_bdev; 	// 块设备
	struct backing_dev_info *s_bdi;		// 块设备信息，回写就是由它管理
	struct mtd_info		*s_mtd;
	struct hlist_node	s_instances; // 挂到file_system_type->fs_supers列表
	unsigned int		s_quota_types;	/* Bitmask of supported quota types */
	struct quota_info	s_dquot;	/* Diskquota specific options */

	struct sb_writers	s_writers;

	/*
	 * Keep s_fs_info, s_time_gran, s_fsnotify_mask, and
	 * s_fsnotify_marks together for cache efficiency. They are frequently
	 * accessed and rarely modified.
	 */
	void			*s_fs_info;	// 文件系统么有数据

	/* c/m/atime的时间间隔，单位是ns (cannot be worse than a second) */
	u32			s_time_gran;
	/*c/m/atime的最大最小值，单位是秒 */
	time64_t		   s_time_min;
	time64_t		   s_time_max;
#ifdef CONFIG_FSNOTIFY
	__u32			s_fsnotify_mask;
	struct fsnotify_mark_connector __rcu	*s_fsnotify_marks;
#endif

	char			s_id[32];	// 设备名？
	uuid_t			s_uuid;		/* UUID */

	unsigned int		s_max_links;
	fmode_t			s_mode;

	/*
	 * The next field is for VFS *only*. No filesystems have any business
	 * even looking at it. You had been warned.
	 */
	struct mutex s_vfs_rename_mutex;	/* Kludge */

	/*
	 * Filesystem subtype.  If non-empty the filesystem type field
	 * in /proc/mounts will be "type.subtype"
	 */
	const char *s_subtype;

	const struct dentry_operations *s_d_op; /* default d_op for dentries */

	/*
	 * Saved pool identifier for cleancache (-1 means none)
	 */
	int cleancache_poolid;

	struct shrinker s_shrink; // 内存回收器

	/* Number of inodes with nlink == 0 but still referenced */
	atomic_long_t s_remove_count;

	/* Pending fsnotify inode refs */
	atomic_long_t s_fsnotify_inode_refs;

	int s_readonly_remount;	// 只读挂载

	/* per-sb errseq_t for reporting writeback errors via syncfs */
	errseq_t s_wb_err;

	/* AIO completions deferred from interrupt context */
	struct workqueue_struct *s_dio_done_wq;
	struct hlist_head s_pins;

	/*
	 * Owning user namespace and default context in which to
	 * interpret filesystem uids, gids, quotas, device nodes,
	 * xattrs and security labels.
	 */
	struct user_namespace *s_user_ns;

	/*
	 * The list_lru structure is essentially just a pointer to a table
	 * of per-node lru lists, each of which has its own spinlock.
	 * There is no need to put them into separate cachelines.
	 */
	struct list_lru		s_dentry_lru; // dentry lru
	struct list_lru		s_inode_lru; // inode lru
	struct rcu_head		rcu;
	struct work_struct	destroy_work;

	struct mutex		s_sync_lock;	/* sync serialisation lock */

	/*
	 * Indicates how deep in a filesystem stack this SB is
	 */
	int s_stack_depth;

	/* s_inode_list_lock protects s_inodes */
	spinlock_t		s_inode_list_lock ____cacheline_aligned_in_smp;
	struct list_head	s_inodes;	// inode链表

	spinlock_t		s_inode_wblist_lock;
	struct list_head	s_inodes_wb;	// 需要回写的inode列表
} __randomize_layout;
```

## 4. vfsmount
```c
struct vfsmount {
    // 文件系统的根目录。
    // 这个根目录并不是我们平时说的 "/"，我们平时说的"/"目录是针对进程的，
    // 这里说的根目录是针对文件系统，每个文件系统都有自己的根目录，
    // 所谓的挂载就是把具体文件系统的根目录挂在现有文件系统的某个目录上
	struct dentry *mnt_root;

    // 具体文件系统超级块指针
	struct super_block *mnt_sb;

    // 挂载标志
	int mnt_flags;
} __randomize_layout;
```
vfsmount里保存了具体文件系统相关的信息，将dentry和具体文件系统的根目录，超级块连接起来。

## 5. struct mount
```c
struct mount {
	struct hlist_node mnt_hash; // 挂到mount_hashtable
	struct mount *mnt_parent; // 父mount
	struct dentry *mnt_mountpoint; // 挂载点dentry
	struct vfsmount mnt; // vfsmount
	union {
		struct rcu_head mnt_rcu;
		struct llist_node mnt_llist;
	};
#ifdef CONFIG_SMP
	struct mnt_pcp __percpu *mnt_pcp;
#else
	int mnt_count;
	int mnt_writers;
#endif
	struct list_head mnt_mounts;	// 子mount列表
	struct list_head mnt_child;	// 挂入父结点的mnt_mounts列表
	struct list_head mnt_instance;	// 挂入 sb->s_mounts 列表
	const char *mnt_devname;	/* 设备名，例如： /dev/dsk/hda1 */
	struct list_head mnt_list;
	struct list_head mnt_expire;	/* link in fs-specific expiry list */
	struct list_head mnt_share;	/* circular list of shared mounts */
	struct list_head mnt_slave_list;/* list of slave mounts */
	struct list_head mnt_slave;	/* slave list entry */
	struct mount *mnt_master;	/* slave is on master->mnt_slave_list */
	struct mnt_namespace *mnt_ns;	/* containing namespace */
	struct mountpoint *mnt_mp;	// 挂载点
	union {
		struct hlist_node mnt_mp_list;	/* list mounts with the same mountpoint */
		struct hlist_node mnt_umount;
	};
	struct list_head mnt_umounting; /* list entry for umount propagation */
#ifdef CONFIG_FSNOTIFY
	struct fsnotify_mark_connector __rcu *mnt_fsnotify_marks;
	__u32 mnt_fsnotify_mask;
#endif
	int mnt_id;			// 挂载的uid
	int mnt_group_id;		// 挂载的组id
	int mnt_expiry_mark;		/* true if marked for expiry */
	struct hlist_head mnt_pins;
	struct hlist_head mnt_stuck_children;
} __randomize_layout;
```

## 6. struct mountpoint
```c
struct mountpoint {
	struct hlist_node m_hash; // 挂到哈希表里
	struct dentry *m_dentry; // 挂载目录
	struct hlist_head m_list; // mnt链表
	int m_count; // 挂载点的引用计数
};
```
把一个目录的`dentry`变成`mountpoint`对象（详见 get_mountpoint 函数）。
