# fusefs挂载

## 1. fuse_init_fs_context
```c
static int fuse_init_fs_context(struct fs_context *fc)
{
	struct fuse_fs_context *ctx;

	// 创建一个上下文对象
	ctx = kzalloc(sizeof(struct fuse_fs_context), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	// 设置为最大值
	ctx->max_read = ~0;
	// FUSE_DEFAULT_BLKSIZE为512
	ctx->blksize = FUSE_DEFAULT_BLKSIZE;
	// 显示选项？
	ctx->legacy_opts_show = true;

#ifdef CONFIG_BLOCK
	// 如果是fuseblk_fs_type文件系统，则需要打开设备
	if (fc->fs_type == &fuseblk_fs_type) {
		ctx->is_bdev = true;
		ctx->destroy = true;
	}
#endif

	fc->fs_private = ctx;

	// 设置操作函数
	fc->ops = &fuse_context_ops;
	return 0;
}

static const struct fs_context_operations fuse_context_ops = {
	.free		= fuse_free_fc,
	.parse_param	= fuse_parse_param,
	.reconfigure	= fuse_reconfigure,
	.get_tree	= fuse_get_tree,
};
```
初始化函数里，主要创建了fuse_fs_context对象，每个挂载的上下文对象。


## 2. fuse_get_tree
```c
static int fuse_get_tree(struct fs_context *fc)
{
	struct fuse_fs_context *ctx = fc->fs_private;

	// fd, rootmode, user_id, group_id这4个参数必须要有
	if (!ctx->fd_present || !ctx->rootmode_present ||
	    !ctx->user_id_present || !ctx->group_id_present)
		return -EINVAL;

	// 根据是否是块设备分别调用不同的vfs函数，这两个函数的差异是
	// 是否需要打开设备。它们的填充函数都是一样的
#ifdef CONFIG_BLOCK
	if (ctx->is_bdev)
		return get_tree_bdev(fc, fuse_fill_super);
#endif

	return get_tree_nodev(fc, fuse_fill_super);
}
```
在挂载fusefs的时候，必须要传fd, rootmod, user_id, group_id，这4个参数。然后就根据是否有设备，调用不同的vfs函数，核心工作都在fuse_fill_super里。

### 2.1 fuse_fill_super
```c
static int fuse_fill_super(struct super_block *sb, struct fs_context *fsc)
{
	struct fuse_fs_context *ctx = fsc->fs_private;
	struct file *file;
	int err;
	struct fuse_conn *fc;
	struct fuse_mount *fm;

	err = -EINVAL;

	// fd一般是/dev/fuse
	file = fget(ctx->fd);
	if (!file)
		goto err;

	// 判断是否是文件的操作函数表是不是fuse_dev_operations，这个opts是fuse和cuse这两个设备的，
	// 所以打开的文件必须是/dev/fuse或/dev/cuse
	// 而且这个文件打开的用户空间和当前用户空间必须一致，原文注释说是为了防止攻击
	if ((file->f_op != &fuse_dev_operations) ||
	    (file->f_cred->user_ns != sb->s_user_ns))
		goto err_fput;
	// fuse_dev pointer
	ctx->fudptr = &file->private_data;

	// 创建链接对象
	fc = kmalloc(sizeof(*fc), GFP_KERNEL);
	err = -ENOMEM;
	if (!fc)
		goto err_fput;

	// 创建mount对象
	fm = kzalloc(sizeof(*fm), GFP_KERNEL);
	if (!fm) {
		kfree(fc);
		goto err_fput;
	}
	
	// 初始化链接对象
	fuse_conn_init(fc, fm, sb->s_user_ns, &fuse_dev_fiq_ops, NULL);
	// 释放链接函数
	fc->release = fuse_free_conn;

	// mount信息
	sb->s_fs_info = fm;

	// 填充超级块
	err = fuse_fill_super_common(sb, ctx);
	if (err)
		goto err_put_conn;
	/*
	 * atomic_dec_and_test() in fput() provides the necessary
	 * memory barrier for file->private_data to be visible on all
	 * CPUs after this
	 */
	fput(file);

	// 发送初始化请求
	fuse_send_init(get_fuse_mount_super(sb));
	return 0;

 err_put_conn:
	fuse_mount_put(fm);
	sb->s_fs_info = NULL;
 err_fput:
	fput(file);
 err:
	return err;
}
```
在fuse_fill_super主要流程：
1. 创建了fuse_conn对象，对其初始化
2. fuse_fill_super_common进一步对fuse_conn对象进行相关设置
3. 向用户空间发送FUSE_INIT消息

下面是参数解析的相关代码:
```c
static const struct fs_parameter_spec fuse_fs_parameters[] = {
	fsparam_string	("source",		OPT_SOURCE),
	fsparam_u32	("fd",			OPT_FD),
	fsparam_u32oct	("rootmode",		OPT_ROOTMODE),
	fsparam_u32	("user_id",		OPT_USER_ID),
	fsparam_u32	("group_id",		OPT_GROUP_ID),
	fsparam_flag	("default_permissions",	OPT_DEFAULT_PERMISSIONS),
	fsparam_flag	("allow_other",		OPT_ALLOW_OTHER),
	fsparam_u32	("max_read",		OPT_MAX_READ),
	fsparam_u32	("blksize",		OPT_BLKSIZE),
	fsparam_string	("subtype",		OPT_SUBTYPE),
	{}
};
static int fuse_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
	struct fs_parse_result result;
	struct fuse_fs_context *ctx = fc->fs_private;
	int opt;

	if (fc->purpose == FS_CONTEXT_FOR_RECONFIGURE) {
		/*
		 * Ignore options coming from mount(MS_REMOUNT) for backward
		 * compatibility.
		 */
		if (fc->oldapi)
			return 0;

		return invalfc(fc, "No changes allowed in reconfigure");
	}

	opt = fs_parse(fc, fuse_fs_parameters, param, &result);
	if (opt < 0)
		return opt;

	switch (opt) {
	case OPT_SOURCE:
		if (fc->source)
			return invalfc(fc, "Multiple sources specified");
		fc->source = param->string;
		param->string = NULL;
		break;

	case OPT_SUBTYPE:
		if (ctx->subtype)
			return invalfc(fc, "Multiple subtypes specified");
		ctx->subtype = param->string;
		param->string = NULL;
		return 0;

	case OPT_FD:
		ctx->fd = result.uint_32;
		ctx->fd_present = true;
		break;

	case OPT_ROOTMODE:
		if (!fuse_valid_type(result.uint_32))
			return invalfc(fc, "Invalid rootmode");
		ctx->rootmode = result.uint_32;
		ctx->rootmode_present = true;
		break;

	case OPT_USER_ID:
		ctx->user_id = make_kuid(fc->user_ns, result.uint_32);
		if (!uid_valid(ctx->user_id))
			return invalfc(fc, "Invalid user_id");
		ctx->user_id_present = true;
		break;

	case OPT_GROUP_ID:
		ctx->group_id = make_kgid(fc->user_ns, result.uint_32);
		if (!gid_valid(ctx->group_id))
			return invalfc(fc, "Invalid group_id");
		ctx->group_id_present = true;
		break;

	case OPT_DEFAULT_PERMISSIONS:
		ctx->default_permissions = true;
		break;

	case OPT_ALLOW_OTHER:
		ctx->allow_other = true;
		break;

	case OPT_MAX_READ:
		ctx->max_read = result.uint_32;
		break;

	case OPT_BLKSIZE:
		if (!ctx->is_bdev)
			return invalfc(fc, "blksize only supported for fuseblk");
		ctx->blksize = result.uint_32;
		break;

	default:
		return -EINVAL;
	}

	return 0;
}
```

## fuse_conn_init
```c
void fuse_conn_init(struct fuse_conn *fc, struct fuse_mount *fm,
		    struct user_namespace *user_ns,
		    const struct fuse_iqueue_ops *fiq_ops, void *fiq_priv)
{
	memset(fc, 0, sizeof(*fc));
	spin_lock_init(&fc->lock);
	spin_lock_init(&fc->bg_lock);
	init_rwsem(&fc->killsb);
	refcount_set(&fc->count, 1);
	atomic_set(&fc->dev_count, 1);
	init_waitqueue_head(&fc->blocked_waitq);
	// 初始化队列，并设置请求的操作函数
	fuse_iqueue_init(&fc->iq, fiq_ops, fiq_priv);

	INIT_LIST_HEAD(&fc->bg_queue);
	INIT_LIST_HEAD(&fc->entry);
	INIT_LIST_HEAD(&fc->devices);
	atomic_set(&fc->num_waiting, 0);
	// 最大后台请求 12
	fc->max_background = FUSE_DEFAULT_MAX_BACKGROUND;
	// 默认拥塞限制 9
	fc->congestion_threshold = FUSE_DEFAULT_CONGESTION_THRESHOLD;
	atomic64_set(&fc->khctr, 0);
	fc->polled_files = RB_ROOT;
	fc->blocked = 0;
	fc->initialized = 0;
	// 设置fc已连接
	fc->connected = 1;

	// 属性的版本号
	atomic64_set(&fc->attr_version, 1);
	get_random_bytes(&fc->scramble_key, sizeof(fc->scramble_key));
	fc->pid_ns = get_pid_ns(task_active_pid_ns(current));
	fc->user_ns = get_user_ns(user_ns);
	// 一个请求最多可用32个页
	fc->max_pages = FUSE_DEFAULT_MAX_PAGES_PER_REQ;

	INIT_LIST_HEAD(&fc->mounts);
	list_add(&fm->fc_entry, &fc->mounts);
	fm->fc = fc;
	refcount_set(&fm->count, 1);
}

static void fuse_iqueue_init(struct fuse_iqueue *fiq,
			     const struct fuse_iqueue_ops *ops,
			     void *priv)
{
	memset(fiq, 0, sizeof(struct fuse_iqueue));
	spin_lock_init(&fiq->lock);
	init_waitqueue_head(&fiq->waitq);
	INIT_LIST_HEAD(&fiq->pending);
	INIT_LIST_HEAD(&fiq->interrupts);
	fiq->forget_list_tail = &fiq->forget_list_head;
	// 已连接
	fiq->connected = 1;
	fiq->ops = ops;
	fiq->priv = priv;
}
```
在fuse_conn_init设置了已连接状态和fiq->ops，这个ops默认是fuse_dev_operations，处理与用户空间的交互。

## fuse_fill_super_common
```c
int fuse_fill_super_common(struct super_block *sb, struct fuse_fs_context *ctx)
{
	struct fuse_dev *fud = NULL;
	struct fuse_mount *fm = get_fuse_mount_super(sb);
	struct fuse_conn *fc = fm->fc;
	struct inode *root;
	struct dentry *root_dentry;
	int err;

	err = -EINVAL;

	// 不支持强制锁
	if (sb->s_flags & SB_MANDLOCK)
		goto err;

	// 设置fuse超级块的一些默认配置
	fuse_sb_defaults(sb);

	if (ctx->is_bdev) {
#ifdef CONFIG_BLOCK
		// 如果是块设备，则设置块大小
		err = -EINVAL;
		// 如果有设备，要设置块大小
		if (!sb_set_blocksize(sb, ctx->blksize))
			goto err;
#endif
	} else {

		// 否则设置块大小为页大小
		sb->s_blocksize = PAGE_SIZE;
		sb->s_blocksize_bits = PAGE_SHIFT;
	}

	// 子类型？
	sb->s_subtype = ctx->subtype;
	ctx->subtype = NULL;

	// 如果使能了dax，则
	if (IS_ENABLED(CONFIG_FUSE_DAX)) {
		// 如果配置了dax设备，则初始化dax设备
		err = fuse_dax_conn_alloc(fc, ctx->dax_dev);
		if (err)
			goto err;
	}

	if (ctx->fudptr) {
		err = -ENOMEM;
		// 初始化fuse_dev
		fud = fuse_dev_alloc_install(fc);
		if (!fud)
			goto err_free_dax;
	}

	fc->dev = sb->s_dev;
	fm->sb = sb;
	// 初始化bdi
	err = fuse_bdi_init(fc, sb);
	if (err)
		goto err_dev_free;

	if (sb->s_flags & SB_POSIXACL)
		fc->dont_mask = 1;
	sb->s_flags |= SB_POSIXACL;

	fc->default_permissions = ctx->default_permissions;
	fc->allow_other = ctx->allow_other;
	fc->user_id = ctx->user_id;
	fc->group_id = ctx->group_id;
	fc->legacy_opts_show = ctx->legacy_opts_show;
	fc->max_read = max_t(unsigned int, 4096, ctx->max_read);
	fc->destroy = ctx->destroy;
	fc->no_control = ctx->no_control;
	fc->no_force_umount = ctx->no_force_umount;

	err = -ENOMEM;

	// 下面三行是初始化根节点
	root = fuse_get_root_inode(sb, ctx->rootmode);
	sb->s_d_op = &fuse_root_dentry_operations;

	// 根dentry
	root_dentry = d_make_root(root);
	if (!root_dentry)
		goto err_dev_free;
	/* Root dentry doesn't have .d_revalidate */
	sb->s_d_op = &fuse_dentry_operations;


	mutex_lock(&fuse_mutex);
	err = -EINVAL;
	if (ctx->fudptr && *ctx->fudptr)
		goto err_unlock;

	// 把fc添加到控制文件系统
	err = fuse_ctl_add_conn(fc);
	if (err)
		goto err_unlock;

	// 把fc加到fuse_conn_list
	list_add_tail(&fc->entry, &fuse_conn_list);
	sb->s_root = root_dentry;
	if (ctx->fudptr)
		*ctx->fudptr = fud;
	mutex_unlock(&fuse_mutex);
	return 0;

 err_unlock:
	mutex_unlock(&fuse_mutex);
	dput(root_dentry);
 err_dev_free:
	if (fud)
		fuse_dev_free(fud);
 err_free_dax:
	if (IS_ENABLED(CONFIG_FUSE_DAX))
		fuse_dax_conn_free(fc);
 err:
	return err;
}
```
在这个函数里设置
1. vfs超级块的一些属性
2. 初始化fuse_dev的一些设置
3. 进一步对fc进行设置
4. 生成根结点的inode及dentry
5. 初始化控制文件系统相关接口文件

## fuse_dev_alloc_install
```c
struct fuse_dev *fuse_dev_alloc_install(struct fuse_conn *fc)
{
	struct fuse_dev *fud;

	// 主要初始化了pq
	fud = fuse_dev_alloc();
	if (!fud)
		return NULL;

	// 加到fc的devices表里
	fuse_dev_install(fud, fc);
	return fud;
}

struct fuse_dev *fuse_dev_alloc(void)
{
	struct fuse_dev *fud;
	struct list_head *pq;

	fud = kzalloc(sizeof(struct fuse_dev), GFP_KERNEL);
	if (!fud)
		return NULL;

	// 请求处理队列 FUSE_PQ_HASH_SIZE 256
	pq = kcalloc(FUSE_PQ_HASH_SIZE, sizeof(struct list_head), GFP_KERNEL);
	if (!pq) {
		kfree(fud);
		return NULL;
	}

	// 设置处理队列
	fud->pq.processing = pq;

	// 初始化处理队列，主要初始化了哈希表头
	fuse_pqueue_init(&fud->pq);

	return fud;
}

static void fuse_pqueue_init(struct fuse_pqueue *fpq)
{
	unsigned int i;

	spin_lock_init(&fpq->lock);
	// 初始化每个哈希表头
	for (i = 0; i < FUSE_PQ_HASH_SIZE; i++)
		INIT_LIST_HEAD(&fpq->processing[i]);
	// 输出请求列表
	INIT_LIST_HEAD(&fpq->io);
	// 设置已连接
	fpq->connected = 1;
}

void fuse_dev_install(struct fuse_dev *fud, struct fuse_conn *fc)
{
	// 增加fc->count的引用计数
	fud->fc = fuse_conn_get(fc);
	spin_lock(&fc->lock);
	// 把fud加到设备表里
	list_add_tail(&fud->entry, &fc->devices);
	spin_unlock(&fc->lock);
}
```
设备初始化里，主要初始化了请求队列的哈希表

## fuse_ctl_add_conn
```c
int fuse_ctl_add_conn(struct fuse_conn *fc)
{
	struct dentry *parent;
	char name[32];

	// fuse_control_sb 是在挂载fusectl文件系统时被初始化，
	// 如果没有挂载控制系统，则直接退出
	if (!fuse_control_sb)
		return 0;

	// 获取父目录
	parent = fuse_control_sb->s_root;
	inc_nlink(d_inode(parent));

	// 设备名
	sprintf(name, "%u", fc->dev);

	// 在父目录底下创建一个以设备名命名的目录
	parent = fuse_ctl_add_dentry(parent, fc, name, S_IFDIR | 0500, 2,
				     &simple_dir_inode_operations,
				     &simple_dir_operations);
	if (!parent)
		goto err;

	// 分别创建4个控制文件
	if (!fuse_ctl_add_dentry(parent, fc, "waiting", S_IFREG | 0400, 1,
				 NULL, &fuse_ctl_waiting_ops) ||
	    !fuse_ctl_add_dentry(parent, fc, "abort", S_IFREG | 0200, 1,
				 NULL, &fuse_ctl_abort_ops) ||
	    !fuse_ctl_add_dentry(parent, fc, "max_background", S_IFREG | 0600,
				 1, NULL, &fuse_conn_max_background_ops) ||
	    !fuse_ctl_add_dentry(parent, fc, "congestion_threshold",
				 S_IFREG | 0600, 1, NULL,
				 &fuse_conn_congestion_threshold_ops))
		goto err;

	return 0;

 err:
	fuse_ctl_remove_conn(fc);
	return -ENOMEM;
}

static struct dentry *fuse_ctl_add_dentry(struct dentry *parent,
					  struct fuse_conn *fc,
					  const char *name,
					  int mode, int nlink,
					  const struct inode_operations *iop,
					  const struct file_operations *fop)
{
	struct dentry *dentry;
	struct inode *inode;

	// FUSE_CTL_NUM_DENTRIES是5，意思是一个fc的控制对象不能超过5个
	BUG_ON(fc->ctl_ndents >= FUSE_CTL_NUM_DENTRIES);


	// 创建dentry
	dentry = d_alloc_name(parent, name);
	if (!dentry)
		return NULL;

	// 创建inode
	inode = new_inode(fuse_control_sb);
	if (!inode) {
		dput(dentry);
		return NULL;
	}

	// 调用vfs的方法，获取一个ino,这个是顺序递增的
	inode->i_ino = get_next_ino();
	inode->i_mode = mode;
	inode->i_uid = fc->user_id;
	inode->i_gid = fc->group_id;
	inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);

	// 设置inode操作函数
	// 原文注释说这里不能设置为NULL，但这里又没有强制判断
	if (iop)
		inode->i_op = iop;
	// 文件系统函数
	inode->i_fop = fop;

	// 链接数
	set_nlink(inode, nlink);
	inode->i_private = fc;

	// 把dentry和inode绑定
	d_add(dentry, inode);

	// 加到控制数组里
	fc->ctl_dentry[fc->ctl_ndents++] = dentry;

	return dentry;
}
```

## fuse_sb_defaults
```c
static void fuse_sb_defaults(struct super_block *sb)
{
	sb->s_magic = FUSE_SUPER_MAGIC;
	sb->s_op = &fuse_super_operations;
	sb->s_xattr = fuse_xattr_handlers;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_time_gran = 1;
	sb->s_export_op = &fuse_export_operations;
	sb->s_iflags |= SB_I_IMA_UNVERIFIABLE_SIGNATURE;
	if (sb->s_user_ns != &init_user_ns)
		sb->s_iflags |= SB_I_UNTRUSTED_MOUNTER;
	sb->s_flags &= ~(SB_NOSEC | SB_I_VERSION);

	/*
	 * If we are not in the initial user namespace posix
	 * acls must be translated.
	 */
	if (sb->s_user_ns != &init_user_ns)
		sb->s_xattr = fuse_no_acl_xattr_handlers;
}
```
fuse_sb_defaults设置了vfs超级块的一些主要信息

## fuse_send_init
```c
void fuse_send_init(struct fuse_mount *fm)
{
	struct fuse_init_args *ia;

	ia = kzalloc(sizeof(*ia), GFP_KERNEL | __GFP_NOFAIL);
	// 7
	ia->in.major = FUSE_KERNEL_VERSION;
	// 32
	ia->in.minor = FUSE_KERNEL_MINOR_VERSION;
	// 最大预读量
	ia->in.max_readahead = fm->sb->s_bdi->ra_pages * PAGE_SIZE;
	ia->in.flags |=
		FUSE_ASYNC_READ | FUSE_POSIX_LOCKS | FUSE_ATOMIC_O_TRUNC |
		FUSE_EXPORT_SUPPORT | FUSE_BIG_WRITES | FUSE_DONT_MASK |
		FUSE_SPLICE_WRITE | FUSE_SPLICE_MOVE | FUSE_SPLICE_READ |
		FUSE_FLOCK_LOCKS | FUSE_HAS_IOCTL_DIR | FUSE_AUTO_INVAL_DATA |
		FUSE_DO_READDIRPLUS | FUSE_READDIRPLUS_AUTO | FUSE_ASYNC_DIO |
		FUSE_WRITEBACK_CACHE | FUSE_NO_OPEN_SUPPORT |
		FUSE_PARALLEL_DIROPS | FUSE_HANDLE_KILLPRIV | FUSE_POSIX_ACL |
		FUSE_ABORT_ERROR | FUSE_MAX_PAGES | FUSE_CACHE_SYMLINKS |
		FUSE_NO_OPENDIR_SUPPORT | FUSE_EXPLICIT_INVAL_DATA;
#ifdef CONFIG_FUSE_DAX
	if (fm->fc->dax)
		ia->in.flags |= FUSE_MAP_ALIGNMENT;
#endif
	if (fm->fc->auto_submounts)
		ia->in.flags |= FUSE_SUBMOUNTS;

	// 入参
	ia->args.opcode = FUSE_INIT;

	// 入参
	ia->args.in_numargs = 1;
	ia->args.in_args[0].size = sizeof(ia->in);
	ia->args.in_args[0].value = &ia->in;
	ia->args.out_numargs = 1;
	/* Variable length argument used for backward compatibility
	   with interface version < 7.5.  Rest of init_out is zeroed
	   by do_get_request(), so a short reply is not a problem */
	// 出参
	ia->args.out_argvar = true;
	ia->args.out_args[0].size = sizeof(ia->out);
	ia->args.out_args[0].value = &ia->out;

	// 强制
	ia->args.force = true;
	ia->args.nocreds = true;
	// 结束时的回调函数
	ia->args.end = process_init_reply;

	// 发送请求
	if (fuse_simple_background(fm, &ia->args, GFP_KERNEL) != 0)
		process_init_reply(fm, &ia->args, -ENOTCONN);
}
```
向用户层发送FUSE_INIT命令，让用户层文件系统初始化。
