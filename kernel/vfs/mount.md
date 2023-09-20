# 挂载
源码基于5.10.102

## 简介
挂载就是把设备上的根目录与系统中现有的目录关联，这样在访问挂载点时，就会通过挂载点目录进入设备上的文件系统。

## mount
```c
SYSCALL_DEFINE5(mount, char __user *, dev_name, char __user *, dir_name,
		char __user *, type, unsigned long, flags, void __user *, data)
{
	int ret;
	char *kernel_type;
	char *kernel_dev;
	void *options;

	// 从用户空间复制类型
	kernel_type = copy_mount_string(type);
	ret = PTR_ERR(kernel_type);
	if (IS_ERR(kernel_type))
		goto out_type;

	// 复制设备名
	kernel_dev = copy_mount_string(dev_name);
	ret = PTR_ERR(kernel_dev);
	if (IS_ERR(kernel_dev))
		goto out_dev;

	// 复制挂载选项
	options = copy_mount_options(data);
	ret = PTR_ERR(options);
	if (IS_ERR(options))
		goto out_data;

	// 正式挂载
	ret = do_mount(kernel_dev, dir_name, kernel_type, flags, options);

	kfree(options);
out_data:
	kfree(kernel_dev);
out_dev:
	kfree(kernel_type);
out_type:
	return ret;
}

long do_mount(const char *dev_name, const char __user *dir_name,
		const char *type_page, unsigned long flags, void *data_page)
{
	struct path path;
	int ret;

	// 获取目录的路径
	ret = user_path_at(AT_FDCWD, dir_name, LOOKUP_FOLLOW, &path);
	if (ret)
		return ret;
	// 挂载
	ret = path_mount(dev_name, &path, type_page, flags, data_page);
	path_put(&path);
	return ret;
}

int path_mount(const char *dev_name, struct path *path,
		const char *type_page, unsigned long flags, void *data_page)
{
	unsigned int mnt_flags = 0, sb_flags;
	int ret;

	// 先去掉魔数：0xC0ED0000
	if ((flags & MS_MGC_MSK) == MS_MGC_VAL)
		flags &= ~MS_MGC_MSK;

	// 截断data数据到4096
	if (data_page)
		((char *)data_page)[PAGE_SIZE - 1] = 0;

	// 不允许user挂载？
	if (flags & MS_NOUSER)
		return -EINVAL;

	// 安全检查
	ret = security_sb_mount(dev_name, path, type_page, flags, data_page);
	if (ret)
		return ret;
	// 挂载需要CAP_SYS_ADMIN权限
	if (!may_mount())
		return -EPERM;
	
	// 强制锁也需要CAP_SYS_ADMIN权限
	if ((flags & SB_MANDLOCK) && !may_mandlock())
		return -EPERM;

	// 下面都是标志转换
	/* Default to relatime unless overriden */
	if (!(flags & MS_NOATIME))
		mnt_flags |= MNT_RELATIME;

	/* Separate the per-mountpoint flags */
	if (flags & MS_NOSUID)
		mnt_flags |= MNT_NOSUID;
	if (flags & MS_NODEV)
		mnt_flags |= MNT_NODEV;
	if (flags & MS_NOEXEC)
		mnt_flags |= MNT_NOEXEC;
	if (flags & MS_NOATIME)
		mnt_flags |= MNT_NOATIME;
	if (flags & MS_NODIRATIME)
		mnt_flags |= MNT_NODIRATIME;
	if (flags & MS_STRICTATIME)
		mnt_flags &= ~(MNT_RELATIME | MNT_NOATIME);
	if (flags & MS_RDONLY)
		mnt_flags |= MNT_READONLY;
	if (flags & MS_NOSYMFOLLOW)
		mnt_flags |= MNT_NOSYMFOLLOW;

	/* The default atime for remount is preservation */
	if ((flags & MS_REMOUNT) &&
	    ((flags & (MS_NOATIME | MS_NODIRATIME | MS_RELATIME |
		       MS_STRICTATIME)) == 0)) {
		mnt_flags &= ~MNT_ATIME_MASK;
		mnt_flags |= path->mnt->mnt_flags & MNT_ATIME_MASK;
	}

	// 超级块标志参数？
	sb_flags = flags & (SB_RDONLY |
			    SB_SYNCHRONOUS |
			    SB_MANDLOCK |
			    SB_DIRSYNC |
			    SB_SILENT |
			    SB_POSIXACL |
			    SB_LAZYTIME |
			    SB_I_VERSION);

	// 需要标志选择不同挂载类型
	if ((flags & (MS_REMOUNT | MS_BIND)) == (MS_REMOUNT | MS_BIND))
		return do_reconfigure_mnt(path, mnt_flags);
	if (flags & MS_REMOUNT)
		return do_remount(path, flags, sb_flags, mnt_flags, data_page);
	if (flags & MS_BIND)
		return do_loopback(path, dev_name, flags & MS_REC);
	if (flags & (MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE))
		return do_change_type(path, flags);
	if (flags & MS_MOVE)
		return do_move_mount_old(path, dev_name);

	// 一般新挂载走这个流程
	return do_new_mount(path, type_page, sb_flags, mnt_flags, dev_name,
			    data_page);
}

static int do_new_mount(struct path *path, const char *fstype, int sb_flags,
			int mnt_flags, const char *name, void *data)
{
	struct file_system_type *type;
	struct fs_context *fc;
	const char *subtype = NULL;
	int err = 0;

	// 类型名不能为空
	if (!fstype)
		return -EINVAL;

	// 通过类型名找类型结构，如果当前还没注册，可能加载对应的模块
	type = get_fs_type(fstype);
	// 不支持这种fs
	if (!type)
		return -ENODEV;

	// 需要子类型
	if (type->fs_flags & FS_HAS_SUBTYPE) {
		subtype = strchr(fstype, '.');
		if (subtype) {
			subtype++;
			if (!*subtype) {
				put_filesystem(type);
				return -EINVAL;
			}
		}
	}

	// 分配fs_context
	fc = fs_context_for_mount(type, sb_flags);
	put_filesystem(type);
	if (IS_ERR(fc))
		return PTR_ERR(fc);

	if (subtype)
		err = vfs_parse_fs_string(fc, "subtype",
					  subtype, strlen(subtype));
	if (!err && name)
		err = vfs_parse_fs_string(fc, "source", name, strlen(name));
	if (!err)
		err = parse_monolithic_mount_data(fc, data);
	if (!err && !mount_capable(fc))
		err = -EPERM;
	if (!err)
		err = vfs_get_tree(fc);
	if (!err)
		err = do_new_mount_fc(fc, path, mnt_flags);

	put_fs_context(fc);
	return err;
}

struct fs_context *fs_context_for_mount(struct file_system_type *fs_type,
					unsigned int sb_flags)
{
	return alloc_fs_context(fs_type, NULL, sb_flags, 0,
					// mount类型
					FS_CONTEXT_FOR_MOUNT);
}

static struct fs_context *alloc_fs_context(struct file_system_type *fs_type,
				      struct dentry *reference,
				      unsigned int sb_flags,
				      unsigned int sb_flags_mask,
				      enum fs_context_purpose purpose)
{
	int (*init_fs_context)(struct fs_context *);
	struct fs_context *fc;
	int ret = -ENOMEM;

	// 分配一个对象
	fc = kzalloc(sizeof(struct fs_context), GFP_KERNEL_ACCOUNT);
	if (!fc)
		return ERR_PTR(-ENOMEM);

	fc->purpose	= purpose;
	fc->sb_flags	= sb_flags;
	fc->sb_flags_mask = sb_flags_mask;
	// 如果fs是模块，则会增加模块的引用计数
	fc->fs_type	= get_filesystem(fs_type);
	// 证书
	fc->cred	= get_current_cred();
	// 网络ns ?
	fc->net_ns	= get_net(current->nsproxy->net_ns);
	// 日志前缀，就是fs的名字
	fc->log.prefix	= fs_type->name;

	mutex_init(&fc->uapi_mutex);

	// 根据目的选择不同的user_ns
	switch (purpose) {
	case FS_CONTEXT_FOR_MOUNT:
		fc->user_ns = get_user_ns(fc->cred->user_ns);
		break;
	case FS_CONTEXT_FOR_SUBMOUNT:
		fc->user_ns = get_user_ns(reference->d_sb->s_user_ns);
		break;
	case FS_CONTEXT_FOR_RECONFIGURE:
		atomic_inc(&reference->d_sb->s_active);
		fc->user_ns = get_user_ns(reference->d_sb->s_user_ns);
		fc->root = dget(reference);
		break;
	}

	// 获取fs的init_fs_context函数
	init_fs_context = fc->fs_type->init_fs_context;

	// 如果fs没有指定init_fs_context，则使用老的
	if (!init_fs_context)
		init_fs_context = legacy_init_fs_context;

	// 初始化上下文
	ret = init_fs_context(fc);
	if (ret < 0)
		goto err_fc;
	fc->need_free = true;
	return fc;

err_fc:
	put_fs_context(fc);
	return ERR_PTR(ret);
}

```
## mount_bdev
mount_bdev是挂载需要硬盘的文件系统。

```c
struct dentry *mount_bdev(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data,
	int (*fill_super)(struct super_block *, void *, int))
{
	struct block_device *bdev;
	struct super_block *s;
    // 初始模式为读，执行
	fmode_t mode = FMODE_READ | FMODE_EXCL;
	int error = 0;

    // 如果不是只读就加入写标志
	if (!(flags & SB_RDONLY))
		mode |= FMODE_WRITE;

    // 获取块设备
	bdev = blkdev_get_by_path(dev_name, mode, fs_type);
	if (IS_ERR(bdev))
		return ERR_CAST(bdev);

	/*
	 * once the super is inserted into the list by sget, s_umount
	 * will protect the lockfs code from trying to start a snapshot
	 * while we are mounting
	 */
    // todo: 没看懂
	mutex_lock(&bdev->bd_fsfreeze_mutex);
	if (bdev->bd_fsfreeze_count > 0) {
		mutex_unlock(&bdev->bd_fsfreeze_mutex);
		error = -EBUSY;
		goto error_bdev;
	}

    // 获取/创建超级块
	s = sget(fs_type, test_bdev_super, set_bdev_super, flags | SB_NOSEC,
		 bdev);
	mutex_unlock(&bdev->bd_fsfreeze_mutex);
	if (IS_ERR(s))
		goto error_s;

	if (s->s_root) { // 这个分支是设备已经挂载
        
        // 如果已挂载的模块和要求的模式不一样，则返回EBUSY
		if ((flags ^ s->s_flags) & SB_RDONLY) {
			deactivate_locked_super(s);
			error = -EBUSY;
			goto error_bdev;
		}

		/*
		 * s_umount nests inside bd_mutex during
		 * __invalidate_device().  blkdev_put() acquires
		 * bd_mutex and can't be called under s_umount.  Drop
		 * s_umount temporarily.  This is safe as we're
		 * holding an active reference.
		 */
        // todo: 没看懂，为要先释放锁，再加锁
		up_write(&s->s_umount);
		blkdev_put(bdev, mode);
		down_write(&s->s_umount);
	} else { // 这个分支是设备没有挂载
		s->s_mode = mode; // 设置超级块模式
		snprintf(s->s_id, sizeof(s->s_id), "%pg", bdev);
        // 设置超级块大小
		sb_set_blocksize(s, block_size(bdev));

        // 调用特定文件系统的fill_super来填充超级块
		error = fill_super(s, data, flags & SB_SILENT ? 1 : 0);
		if (error) {
			deactivate_locked_super(s);
			goto error;
		}

        // 激活超级块
		s->s_flags |= SB_ACTIVE;
        // 设置块设备的超级块指针
		bdev->bd_super = s;
	}

    // 返回根节点dentry
	return dget(s->s_root);

error_s:
	error = PTR_ERR(s);
error_bdev:
	blkdev_put(bdev, mode);
error:
	return ERR_PTR(error);
}

// holder参数传的是具体文件系统的结构struct file_system_type
struct block_device *blkdev_get_by_path(const char *path, fmode_t mode,
					void *holder)
{
	struct block_device *bdev;
	int err;

    // 根据路径打开设备文件
	bdev = lookup_bdev(path);
	if (IS_ERR(bdev))
		return bdev;

    // 打开真正的硬件设备
    // todo: 没太看懂
	err = blkdev_get(bdev, mode, holder);
	if (err)
		return ERR_PTR(err);

    // 如果要求以写模式挂载，但是块设备是只读的，则返回错误
	if ((mode & FMODE_WRITE) && bdev_read_only(bdev)) {
		blkdev_put(bdev, mode);
		return ERR_PTR(-EACCES);
	}

	return bdev;
}


static int test_bdev_super(struct super_block *s, void *data)
{
	return (void *)s->s_bdev == data;
}

static int set_bdev_super(struct super_block *s, void *data)
{
	s->s_bdev = data;
	s->s_dev = s->s_bdev->bd_dev;
	s->s_bdi = bdi_get(s->s_bdev->bd_bdi);

	if (blk_queue_stable_writes(s->s_bdev->bd_disk->queue))
		s->s_iflags |= SB_I_STABLE_WRITES;
	return 0;
}

// 传进来的test, set参数是上面两个函数
// data传的是bdev
struct super_block *sget(struct file_system_type *type,
			int (*test)(struct super_block *,void *),
			int (*set)(struct super_block *,void *),
			int flags,
			void *data)
{
	struct user_namespace *user_ns = current_user_ns();
	struct super_block *s = NULL;
	struct super_block *old;
	int err;

	/* We don't yet pass the user namespace of the parent
	 * mount through to here so always use &init_user_ns
	 * until that changes.
	 */
    // todo: 没看懂，挂载子节点？
	if (flags & SB_SUBMOUNT)
		user_ns = &init_user_ns;

retry:
	spin_lock(&sb_lock);
	if (test) {
        // 超级块可能已经挂载，这里遍历具体文件系统的fs_supers结构，
        // 比对每个超级块与传进来的bdev进行对比，如果已经挂载过，就直接返回
		hlist_for_each_entry(old, &type->fs_supers, s_instances) {
			if (!test(old, data))
				continue;
			if (user_ns != old->s_user_ns) {
				spin_unlock(&sb_lock);
				destroy_unused_super(s);
				return ERR_PTR(-EBUSY);
			}
			if (!grab_super(old))
				goto retry;
			destroy_unused_super(s);
			return old;
		}
	}

    // 走到这儿，表示在上面没有找到对应的超级块，从这里开始就新建超级块
	if (!s) {
		spin_unlock(&sb_lock);
        // 申请一个超级块对象，做了一些初始化
		s = alloc_super(type, (flags & ~SB_SUBMOUNT), user_ns);
		if (!s)
			return ERR_PTR(-ENOMEM);
        
        // 上面的分配可能会睡眠，有可能在睡眠的过程中其他人已经申请了超级块，
        // 所以在这里还要去上面再找一次
		goto retry;
	}

    // 上面的set函数，主要设置了test块设备的相关数据
	err = set(s, data);
	if (err) {
		spin_unlock(&sb_lock);
		destroy_unused_super(s);
		return ERR_PTR(err);
	}

    // 设置文件系统指针
	s->s_type = type;
    // 复制文件系统名称
	strlcpy(s->s_id, type->name, sizeof(s->s_id));
    // 回到超级块表末尾，所有的超级块都要加到这个表
	list_add_tail(&s->s_list, &super_blocks);
    // 把超级块挂加到文件系统的fs_supers表里，就是上面retry那个检测的那个表
	hlist_add_head(&s->s_instances, &type->fs_supers);
	spin_unlock(&sb_lock);
    // 增加模块引用计数
	get_filesystem(type);
    // 把该超级块加到压缩器表里。todo: 压缩器是啥？
	register_shrinker_prepared(&s->s_shrink);
	return s;
}
```

## mount_nodev
mount_nodev主要是不需要设备的文件系统，像voerlayfs，coda等文件系统。它和mount_bdev主要的区别是没有获取设备，打开设备那些步骤，直接生成一个超级块的对象，然后调用具体文件系统的fill_super方法来填充超级块。
```c
struct dentry *mount_nodev(struct file_system_type *fs_type,
	int flags, void *data,
	int (*fill_super)(struct super_block *, void *, int))
{
	int error;
	struct super_block *s = sget(fs_type, NULL, set_anon_super, flags, NULL);

	if (IS_ERR(s))
		return ERR_CAST(s);

	error = fill_super(s, data, flags & SB_SILENT ? 1 : 0);
	if (error) {
		deactivate_locked_super(s);
		return ERR_PTR(error);
	}
	s->s_flags |= SB_ACTIVE;
	return dget(s->s_root);
}
EXPORT_SYMBOL(mount_nodev);
```

## mount_single
mount_single主要用于挂载单例的文件系统，像debugfs, tracefs等，在系统中只有一个超级块，所有挂载该文件系统的节点都共享这个超级块。mount_single也不需要获取设备打开设备的过程，直接生成超级块后，就判断超级块里的根结点是否已经生成，如果已经生成的话就不再调用具体文件系统的fill_super方法。
```c
struct dentry *mount_single(struct file_system_type *fs_type,
	int flags, void *data,
	int (*fill_super)(struct super_block *, void *, int))
{
	struct super_block *s;
	int error;

	s = sget(fs_type, compare_single, set_anon_super, flags, NULL);
	if (IS_ERR(s))
		return ERR_CAST(s);
	if (!s->s_root) {
		error = fill_super(s, data, flags & SB_SILENT ? 1 : 0);
		if (!error)
			s->s_flags |= SB_ACTIVE;
	} else {
		error = reconfigure_single(s, flags, data);
	}
	if (unlikely(error)) {
		deactivate_locked_super(s);
		return ERR_PTR(error);
	}
	return dget(s->s_root);
}
```