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

	sb->s_flags |= SB_RDONLY | SB_NOATIME;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_time_gran = 1;

	sb->s_op = &erofs_sops;
	sb->s_xattr = erofs_xattr_handlers;

	/* set erofs default mount options */
	erofs_default_options(sbi);

	err = erofs_parse_options(sb, data);
	if (err)
		return err;

	err = rafs_v6_fill_super(sb, data);
	if (err)
		return err;

	err = erofs_read_superblock(sb);
	if (err)
		return err;

	if (test_opt(sbi, POSIX_ACL))
		sb->s_flags |= SB_POSIXACL;
	else
		sb->s_flags &= ~SB_POSIXACL;

#ifdef CONFIG_EROFS_FS_ZIP
	INIT_RADIX_TREE(&sbi->workstn_tree, GFP_ATOMIC);
#endif

	/* get the root inode */
	inode = erofs_iget(sb, ROOT_NID(sbi), true);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	if (!S_ISDIR(inode->i_mode)) {
		erofs_err(sb, "rootino(nid %llu) is not a directory(i_mode %o)",
			  ROOT_NID(sbi), inode->i_mode);
		iput(inode);
		return -EINVAL;
	}

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
```