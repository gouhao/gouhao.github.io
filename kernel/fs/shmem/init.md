# init
源码基于5.10

shmem_init有2种实现分为是否打开了CONFIG_SHMEM
## 打开了CONFIG_SHMEM的实现
```c
static struct file_system_type shmem_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "tmpfs",
	.init_fs_context = shmem_init_fs_context,
#ifdef CONFIG_TMPFS
	.parameters	= shmem_fs_parameters,
#endif
	.kill_sb	= kill_litter_super,
	.fs_flags	= FS_USERNS_MOUNT | FS_THP_SUPPORT,
};

int __init shmem_init(void)
{
	int error;

	// 创建 shmem_inode_cache slab
	shmem_init_inodecache();

	// 注册文件系统
	error = register_filesystem(&shmem_fs_type);
	if (error) {
		pr_err("Could not register tmpfs\n");
		goto out2;
	}

	// 挂载文件系统，挂载时会调用 init_fs_context
	shm_mnt = kern_mount(&shmem_fs_type);
	if (IS_ERR(shm_mnt)) {
		error = PTR_ERR(shm_mnt);
		pr_err("Could not kern_mount tmpfs\n");
		goto out1;
	}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	if (has_transparent_hugepage() && shmem_huge > SHMEM_HUGE_DENY)
		SHMEM_SB(shm_mnt->mnt_sb)->huge = shmem_huge;
	else
		shmem_huge = 0; /* just in case it was patched */
#endif
	return 0;

out1:
	unregister_filesystem(&shmem_fs_type);
out2:
	shmem_destroy_inodecache();
	shm_mnt = ERR_PTR(error);
	return error;
}

static const struct fs_context_operations shmem_fs_context_ops = {
	.free			= shmem_free_fc,
	.get_tree		= shmem_get_tree,
#ifdef CONFIG_TMPFS
	.parse_monolithic	= shmem_parse_options,
	.parse_param		= shmem_parse_one,
	.reconfigure		= shmem_reconfigure,
#endif
};

int shmem_init_fs_context(struct fs_context *fc)
{
	struct shmem_options *ctx;

	// 分配上下文 
	ctx = kzalloc(sizeof(struct shmem_options), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	// 设置模式，uid, gid
	// 因为shmem_init是在系统初始化的时候就挂载，所以 uid, gid都是0 (猜的)
	ctx->mode = 0777 | S_ISVTX;
	ctx->uid = current_fsuid();
	ctx->gid = current_fsgid();

	fc->fs_private = ctx;
	fc->ops = &shmem_fs_context_ops;
	return 0;
}

static int shmem_get_tree(struct fs_context *fc)
{
	return get_tree_nodev(fc, shmem_fill_super);
}

static int shmem_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct shmem_options *ctx = fc->fs_private;
	struct inode *inode;
	struct shmem_sb_info *sbinfo;
	int err = -ENOMEM;

	// 分配对象，对齐到L1_CACHE_BYTES
	sbinfo = kzalloc(max((int)sizeof(struct shmem_sb_info),
				L1_CACHE_BYTES), GFP_KERNEL);
	if (!sbinfo)
		return -ENOMEM;

	sb->s_fs_info = sbinfo;

	// CONFIG_TMPFS一般是打开的
#ifdef CONFIG_TMPFS
	// 调用kern_mount时，会有这个标志，表示是内核内部挂载的
	if (!(sb->s_flags & SB_KERNMOUNT)) {
		if (!(ctx->seen & SHMEM_SEEN_BLOCKS))
			ctx->blocks = shmem_default_max_blocks();
		if (!(ctx->seen & SHMEM_SEEN_INODES))
			ctx->inodes = shmem_default_max_inodes();
		if (!(ctx->seen & SHMEM_SEEN_INUMS))
			ctx->full_inums = IS_ENABLED(CONFIG_TMPFS_INODE64);
	} else {
		// NOUSER表示不能从用户空间挂载？
		sb->s_flags |= SB_NOUSER;
	}
	sb->s_export_op = &shmem_export_ops;
	sb->s_flags |= SB_NOSEC;
#else
	sb->s_flags |= SB_NOUSER;
#endif
	// 设置最大块数
	sbinfo->max_blocks = ctx->blocks;
	// 设置最大inode数
	sbinfo->free_inodes = sbinfo->max_inodes = ctx->inodes;

	if (sb->s_flags & SB_KERNMOUNT) {
		// todo: what？
		sbinfo->ino_batch = alloc_percpu(ino_t);
		if (!sbinfo->ino_batch)
			goto failed;
	}
	sbinfo->uid = ctx->uid;
	sbinfo->gid = ctx->gid;
	sbinfo->full_inums = ctx->full_inums;
	sbinfo->mode = ctx->mode;
	sbinfo->huge = ctx->huge;
	sbinfo->mpol = ctx->mpol;
	ctx->mpol = NULL;

	spin_lock_init(&sbinfo->stat_lock);
	if (percpu_counter_init(&sbinfo->used_blocks, 0, GFP_KERNEL))
		goto failed;
	spin_lock_init(&sbinfo->shrinklist_lock);
	INIT_LIST_HEAD(&sbinfo->shrinklist);

	// 最大io字节数，ULONG_MAX << PAGE_SHIFT
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	// 块大小一页
	sb->s_blocksize = PAGE_SIZE;
	sb->s_blocksize_bits = PAGE_SHIFT;
	sb->s_magic = TMPFS_MAGIC;
	sb->s_op = &shmem_ops;
	sb->s_time_gran = 1;
#ifdef CONFIG_TMPFS_XATTR
	// 支持扩展属性
	sb->s_xattr = shmem_xattr_handlers;
#endif
#ifdef CONFIG_TMPFS_POSIX_ACL
	sb->s_flags |= SB_POSIXACL;
#endif
	// 生成uuid
	uuid_gen(&sb->s_uuid);

	// 生成一个inode
	inode = shmem_get_inode(sb, NULL, S_IFDIR | sbinfo->mode, 0, VM_NORESERVE);
	if (!inode)
		goto failed;
	inode->i_uid = sbinfo->uid;
	inode->i_gid = sbinfo->gid;
	// 创建根目录
	sb->s_root = d_make_root(inode);
	if (!sb->s_root)
		goto failed;
	return 0;

failed:
	shmem_put_super(sb);
	return err;
}

static struct inode *shmem_get_inode(struct super_block *sb, const struct inode *dir,
				     umode_t mode, dev_t dev, unsigned long flags)
{
	struct inode *inode;
	struct shmem_inode_info *info;
	struct shmem_sb_info *sbinfo = SHMEM_SB(sb);
	ino_t ino;

	if (shmem_reserve_inode(sb, &ino))
		return NULL;

	// 生成inode，
	// 这个会调用shmem_ops->alloc_inode，在这个函数里只是调用slab分配了一个对象没做别的
	inode = new_inode(sb);
	if (inode) {
		// 对inode的基本信息做各种初始化
		inode->i_ino = ino;
		inode_init_owner(inode, dir, mode);
		inode->i_blocks = 0;
		inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);
		inode->i_generation = prandom_u32();
		info = SHMEM_I(inode);
		memset(info, 0, (char *)inode - (char *)info);
		spin_lock_init(&info->lock);
		atomic_set(&info->stop_eviction, 0);
		info->seals = F_SEAL_SEAL;
		info->flags = flags & VM_NORESERVE;
		INIT_LIST_HEAD(&info->shrinklist);
		INIT_LIST_HEAD(&info->swaplist);
		simple_xattrs_init(&info->xattrs);
		cache_no_acl(inode);

		// 根据不同类型，初始化操作列表
		switch (mode & S_IFMT) {
		default:
			inode->i_op = &shmem_special_inode_operations;
			init_special_inode(inode, mode, dev);
			break;
		case S_IFREG:
			inode->i_mapping->a_ops = &shmem_aops;
			inode->i_op = &shmem_inode_operations;
			inode->i_fop = &shmem_file_operations;
			mpol_shared_policy_init(&info->policy,
						 shmem_get_sbmpol(sbinfo));
			break;
		case S_IFDIR:
			inc_nlink(inode);
			/* Some things misbehave if size == 0 on a directory */
			inode->i_size = 2 * BOGO_DIRENT_SIZE;
			inode->i_op = &shmem_dir_inode_operations;
			inode->i_fop = &simple_dir_operations;
			break;
		case S_IFLNK:
			/*
			 * Must not load anything in the rbtree,
			 * mpol_free_shared_policy will not be called.
			 */
			mpol_shared_policy_init(&info->policy, NULL);
			break;
		}

		lockdep_annotate_inode_mutex_key(inode);
	} else
		shmem_free_inode(sb);
	return inode;
}

```
## 没有打开CONFIG_SHMEM的实现
```c
static struct file_system_type shmem_fs_type = {
	.name		= "tmpfs",
	.init_fs_context = ramfs_init_fs_context,
	.parameters	= ramfs_fs_parameters,
	.kill_sb	= kill_litter_super,
	.fs_flags	= FS_USERNS_MOUNT,
};

int __init shmem_init(void)
{
	// 注册文件系统
	BUG_ON(register_filesystem(&shmem_fs_type) != 0);

	// 挂载tmpfs
	shm_mnt = kern_mount(&shmem_fs_type);
	BUG_ON(IS_ERR(shm_mnt));

	return 0;
}

int ramfs_init_fs_context(struct fs_context *fc)
{
	struct ramfs_fs_info *fsi;

	// 分配一个文件系统实例
	fsi = kzalloc(sizeof(*fsi), GFP_KERNEL);
	if (!fsi)
		return -ENOMEM;

	fsi->mount_opts.mode = RAMFS_DEFAULT_MODE;
	fc->s_fs_info = fsi;
	fc->ops = &ramfs_context_ops;
	return 0;
}

static const struct fs_context_operations ramfs_context_ops = {
	.free		= ramfs_free_fc,
	.parse_param	= ramfs_parse_param,
	.get_tree	= ramfs_get_tree,
};

static int ramfs_get_tree(struct fs_context *fc)
{
	// 这里调用的是nodev，表示没设置
	return get_tree_nodev(fc, ramfs_fill_super);
}

static int ramfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct ramfs_fs_info *fsi = sb->s_fs_info;
	struct inode *inode;

	sb->s_maxbytes		= MAX_LFS_FILESIZE;
	// 块大小是页大小
	sb->s_blocksize		= PAGE_SIZE;
	sb->s_blocksize_bits	= PAGE_SHIFT;
	sb->s_magic		= RAMFS_MAGIC;
	sb->s_op		= &ramfs_ops;
	sb->s_time_gran		= 1;

	inode = ramfs_get_inode(sb, NULL, S_IFDIR | fsi->mount_opts.mode, 0);
	// 生成根结点
	sb->s_root = d_make_root(inode);
	if (!sb->s_root)
		return -ENOMEM;

	return 0;
}

struct inode *ramfs_get_inode(struct super_block *sb,
				const struct inode *dir, umode_t mode, dev_t dev)
{
	// 分配一个inode
	struct inode * inode = new_inode(sb);

	if (inode) {
		// 初始化ino
		inode->i_ino = get_next_ino();
		// 初始化owner
		inode_init_owner(inode, dir, mode);
		// 映射操作
		inode->i_mapping->a_ops = &ramfs_aops;
		// highuser?
		mapping_set_gfp_mask(inode->i_mapping, GFP_HIGHUSER);
		// 给mapping->flags里设置不可回收标志
		mapping_set_unevictable(inode->i_mapping);
		// 设置3个时间
		inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);
		// 根据创建模式设置不同的操作
		switch (mode & S_IFMT) {
		default:
			init_special_inode(inode, mode, dev);
			break;
		case S_IFREG:
			inode->i_op = &ramfs_file_inode_operations;
			inode->i_fop = &ramfs_file_operations;
			break;
		case S_IFDIR:
			inode->i_op = &ramfs_dir_inode_operations;
			inode->i_fop = &simple_dir_operations;

			/* directory inodes start off with i_nlink == 2 (for "." entry) */
			inc_nlink(inode);
			break;
		case S_IFLNK:
			inode->i_op = &page_symlink_inode_operations;
			inode_nohighmem(inode);
			break;
		}
	}
	return inode;
}
```