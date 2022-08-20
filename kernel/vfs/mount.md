# 挂载
源码基于5.10.102

## 简介
挂载就是把设备上的根目录与系统中现有的目录关联，这样在访问挂载点时，就会通过挂载点目录进入设备上的文件系统。

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