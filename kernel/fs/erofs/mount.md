# mount

## erofs_mount
```c
static struct dentry *erofs_mount(struct file_system_type *fs_type, int flags,
				  const char *dev_name, void *data)
{
	// 判断是否是rafs挂载。rafs挂载就是判断有无bootstrap_path参数。
	// todo: 这个函数里把所有的参数复制了一遍，这个函数可以优化
	if (erofs_mount_is_rafs_v6(data))
		return mount_nodev(fs_type, flags, data, erofs_fill_super);
	return mount_bdev(fs_type, flags, dev_name, data, erofs_fill_super);
}

static int erofs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct inode *inode;
	struct erofs_sb_info *sbi;
	int err;

	// 先设置魔数？
	sb->s_magic = EROFS_SUPER_MAGIC;

	// EROFS_BLKSIZ是页大小：一般是4096
	// LOG_BLOCK_SIZE是页大小的对数：如果页是4096，就是12
	if (sb->s_bdev && !sb_set_blocksize(sb, EROFS_BLKSIZ)) {
		erofs_err(sb, "failed to set erofs blksize");
		return -EINVAL;
	} else {
		sb->s_blocksize = EROFS_BLKSIZ;
		sb->s_blocksize_bits = LOG_BLOCK_SIZE;
	}

	// 分配一个超级块
	sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;

	// 设置到vfs超级块里
	sb->s_fs_info = sbi;

	// 分配上下文
	sbi->devs = kzalloc(sizeof(struct erofs_dev_context), GFP_KERNEL);
	if (!sbi->devs)
		return -ENOMEM;

	idr_init(&sbi->devs->tree);
	init_rwsem(&sbi->devs->rwsem);

	// 该文件系统 只读，没有访问时间
	sb->s_flags |= SB_RDONLY | SB_NOATIME;
	// 支持的最大文件大小是最大的long long值
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_time_gran = 1;

	// 超级块函数表
	sb->s_op = &erofs_sops;
	// 扩展属性函数表
	sb->s_xattr = erofs_xattr_handlers;

	// 设置默认参数
	erofs_default_options(sbi);

	// 解析挂载参数
	err = erofs_parse_options(sb, data);
	if (err)
		return err;

	// 如果是rafs挂载，则打开rafs文件
	err = rafs_v6_fill_super(sb, data);
	if (err)
		return err;

	// 读超级块
	err = erofs_read_superblock(sb);
	if (err)
		return err;

	// 设置 acl 标志
	if (test_opt(sbi, POSIX_ACL))
		sb->s_flags |= SB_POSIXACL;
	else
		sb->s_flags &= ~SB_POSIXACL;

#ifdef CONFIG_EROFS_FS_ZIP
	// 初始化基数树
	INIT_RADIX_TREE(&sbi->workstn_tree, GFP_ATOMIC);
#endif

	// 获取root节点
	inode = erofs_iget(sb, ROOT_NID(sbi), true);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	// root必须是目录
	if (!S_ISDIR(inode->i_mode)) {
		erofs_err(sb, "rootino(nid %llu) is not a directory(i_mode %o)",
			  ROOT_NID(sbi), inode->i_mode);
		iput(inode);
		return -EINVAL;
	}

	// 生成root的dentry
	sb->s_root = d_make_root(inode);
	if (!sb->s_root)
		return -ENOMEM;

	erofs_shrinker_register(sb);
	/* sb->s_umount is already locked, SB_ACTIVE and SB_BORN are not set */
	err = erofs_init_managed_cache(sb);
	if (err)
		return err;

	erofs_info(sb, "mounted with opts: %s, root inode @ nid %llu.",
		   (char *)data, ROOT_NID(sbi));
	return 0;
}

static void erofs_default_options(struct erofs_sb_info *sbi)
{
// 设置zip压缩
#ifdef CONFIG_EROFS_FS_ZIP
	sbi->cache_strategy = EROFS_ZIP_CACHE_READAROUND;
	sbi->max_sync_decompress_pages = 3;
#endif
// 设置扩展属性
#ifdef CONFIG_EROFS_FS_XATTR
	set_opt(sbi, XATTR_USER);
#endif
// 设置acl
#ifdef CONFIG_EROFS_FS_POSIX_ACL
	set_opt(sbi, POSIX_ACL);
#endif
}

static match_table_t erofs_tokens = {
	{Opt_user_xattr, "user_xattr"},
	{Opt_nouser_xattr, "nouser_xattr"}, // 没有扩展属性
	{Opt_acl, "acl"},
	{Opt_noacl, "noacl"}, // 没有acl
	{Opt_cache_strategy, "cache_strategy=%s"},
	{Opt_device, "device=%s"},
	{Opt_bootstrap_path, "bootstrap_path=%s"}, // rafs文件路径
	{Opt_err, NULL}
};

static int erofs_parse_options(struct super_block *sb, char *options)
{
	struct erofs_sb_info *sbi = EROFS_SB(sb);
	substring_t args[MAX_OPT_ARGS];
	char *p;
	int err;

	if (!options)
		return 0;

	while ((p = strsep(&options, ","))) {
		int token;
		struct erofs_device_info *dif;

		if (!*p)
			continue;

		args[0].to = args[0].from = NULL;
		token = match_token(p, erofs_tokens, args);

		switch (token) {
#ifdef CONFIG_EROFS_FS_XATTR
		case Opt_user_xattr:
			set_opt(EROFS_SB(sb), XATTR_USER);
			break;
		case Opt_nouser_xattr:
			clear_opt(EROFS_SB(sb), XATTR_USER);
			break;
#else
		case Opt_user_xattr:
			erofs_info(sb, "user_xattr options not supported");
			break;
		case Opt_nouser_xattr:
			erofs_info(sb, "nouser_xattr options not supported");
			break;
#endif
#ifdef CONFIG_EROFS_FS_POSIX_ACL
		case Opt_acl:
			set_opt(EROFS_SB(sb), POSIX_ACL);
			break;
		case Opt_noacl:
			clear_opt(EROFS_SB(sb), POSIX_ACL);
			break;
#else
		case Opt_acl:
			erofs_info(sb, "acl options not supported");
			break;
		case Opt_noacl:
			erofs_info(sb, "noacl options not supported");
			break;
#endif
		case Opt_cache_strategy:
			err = erofs_build_cache_strategy(sb, args);
			if (err)
				return err;
			break;
		case Opt_device:
			dif = kzalloc(sizeof(*dif), GFP_KERNEL);
			if (!dif)
				return -ENOMEM;
			dif->path = match_strdup(&args[0]);
			if (!dif->path) {
				kfree(dif);
				return -ENOMEM;
			}
			down_write(&sbi->devs->rwsem);
			err = idr_alloc(&sbi->devs->tree, dif, 0, 0, GFP_KERNEL);
			up_write(&sbi->devs->rwsem);
			if (err < 0) {
				kfree(dif->path);
				kfree(dif);
				return err;
			}
			++sbi->devs->extra_devices;
			break;
		case Opt_bootstrap_path:
			kfree(sbi->bootstrap_path);
			sbi->bootstrap_path = match_strdup(&args[0]);
			if (!sbi->bootstrap_path)
				return -ENOMEM;
			erofs_info(sb, "RAFS bootstrap_path %s",
				   sbi->bootstrap_path);
			break;
		default:
			erofs_err(sb, "Unrecognized mount option \"%s\" or missing value", p);
			return -EINVAL;
		}
	}
	return 0;
}

static int rafs_v6_fill_super(struct super_block *sb, void *data)
{
	struct erofs_sb_info *sbi = EROFS_SB(sb);

	if (sbi->bootstrap_path) {
		struct file *f;
		// 如果是rafs挂载，就打开rafs文件
		f = filp_open(sbi->bootstrap_path, O_RDONLY | O_LARGEFILE, 0);
		if (IS_ERR(f))
			return PTR_ERR(f);
		sbi->bootstrap = f;
	}
	/* TODO: open each blobfiles */
	return 0;
}
```