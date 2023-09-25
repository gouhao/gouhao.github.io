# 挂载

## mount
```c
// mount img mp/
// mount("/dev/loop9", "/home/gouhao/tmp/ext4test/mp", "ext4", 0, NULL) = 0
SYSCALL_DEFINE5(mount, char __user *, dev_name, char __user *, dir_name,
		char __user *, type, unsigned long, flags, void __user *, data)
{
	int ret;
	char *kernel_type;
	char *kernel_dev;
	void *options;

	// 从用户空间复制类型, 如果为空,返回NULL
	kernel_type = copy_mount_string(type);
	ret = PTR_ERR(kernel_type);
	// 这里只判断错误,没有判断空
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

	...
	// 挂载需要CAP_SYS_ADMIN权限
	if (!may_mount())
		return -EPERM;

	.. // flag转换

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

	...

	// 分配fs_context,然后初始化里面的一些字段,主要是调用了init_fs_context
	fc = fs_context_for_mount(type, sb_flags);
	// 这个put对应的是最上面的get_fs_type, 在fs_context_for_mount里也会get一次.
	put_filesystem(type);
	if (IS_ERR(fc))
		return PTR_ERR(fc);

	...
	// 解析设备名, 会设置到fc->source里
	if (!err && name)
		err = vfs_parse_fs_string(fc, "source", name, strlen(name));

	// 解析挂载选项,就是 -o 
	if (!err)
		err = parse_monolithic_mount_data(fc, data);
	// 如果没出错的话,检查是否有CAP_SYS_ADMIN权限
	if (!err && !mount_capable(fc))
		err = -EPERM;

	// 获取目录树,fs一般在这里面做fs的初始化,获取根节点等
	// 具体文件系统在get_tree必须要设置fc->root
	if (!err)
		err = vfs_get_tree(fc);

	// 创建挂载相关的联系, path是挂载点
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

	...
	// 获取fs的init_fs_context函数
	init_fs_context = fc->fs_type->init_fs_context;

	// 如果fs没有指定init_fs_context，则使用老的兼容老的接口
	if (!init_fs_context)
		init_fs_context = legacy_init_fs_context;

	// 初始化上下文
	ret = init_fs_context(fc);
	if (ret < 0)
		goto err_fc;
	// 需要释放
	fc->need_free = true;
	return fc;

err_fc:
	put_fs_context(fc);
	return ERR_PTR(ret);
}

static int legacy_init_fs_context(struct fs_context *fc)
{
	// 分配一个legacy_fs_context
	fc->fs_private = kzalloc(sizeof(struct legacy_fs_context), GFP_KERNEL);
	if (!fc->fs_private)
		return -ENOMEM;
	// 操作函数,这个在后面会调用
	fc->ops = &legacy_fs_context_ops;
	return 0;
}

const struct fs_context_operations legacy_fs_context_ops = {
	.free			= legacy_fs_context_free,
	.dup			= legacy_fs_context_dup,
	.parse_param		= legacy_parse_param,
	.parse_monolithic	= legacy_parse_monolithic,
	.get_tree		= legacy_get_tree,
	.reconfigure		= legacy_reconfigure,
};
```
## 获取树
```c
int vfs_get_tree(struct fs_context *fc)
{
	struct super_block *sb;
	int error;

	// 已经读取根节点
	if (fc->root)
		return -EBUSY;

	// 调用具体文件系统的get_tree
	error = fc->ops->get_tree(fc);
	if (error < 0)
		return error;

	// 没获取到根目录,正常文件系统不会的
	if (!fc->root) {
		pr_err("Filesystem %s get_tree() didn't set fc->root\n",
		       fc->fs_type->name);
		/* We don't know what the locking state of the superblock is -
		 * if there is a superblock.
		 */
		BUG();
	}

	// 超级块
	sb = fc->root->d_sb;

	// bdi是后端设备
	WARN_ON(!sb->s_bdi);

	...
	return 0;
}

static int legacy_get_tree(struct fs_context *fc)
{
	struct legacy_fs_context *ctx = fc->fs_private;
	struct super_block *sb;
	struct dentry *root;

	// 调用老的mount接口
	root = fc->fs_type->mount(fc->fs_type, fc->sb_flags,
				      fc->source, ctx->legacy_data);
	// 获取root出错
	if (IS_ERR(root))
		return PTR_ERR(root);

	// 超级块不能为空
	sb = root->d_sb;
	BUG_ON(!sb);

	// 设置fc的根节点
	fc->root = root;
	return 0;
}
```

## do_new_mount_fc
```c
static int do_new_mount_fc(struct fs_context *fc, struct path *mountpoint,
			   unsigned int mnt_flags)
{
	struct vfsmount *mnt;
	struct mountpoint *mp;
	struct super_block *sb = fc->root->d_sb;
	int error;

	...
	up_write(&sb->s_umount);
	// 创建sruct mount结构, 最终返回的vfsmount是mount->mnt
	mnt = vfs_create_mount(fc);
	if (IS_ERR(mnt))
		return PTR_ERR(mnt);

	// 检查时间是否过了最大值
	mnt_warn_timestamp_expiry(mountpoint, mnt);

	// 找path对应的mountpint, 如果没有会创建一个新的
	// 注意:这里传的mountpoint是path,这命名真是混乱
	mp = lock_mount(mountpoint);
	if (IS_ERR(mp)) {
		mntput(mnt);
		return PTR_ERR(mp);
	}
	// 添加到mount的各种数据结构网中
	// real_mount是返回vfsmnt对应的mount结构
	error = do_add_mount(real_mount(mnt), mp, mountpoint, mnt_flags);
	unlock_mount(mp);
	if (error < 0)
		mntput(mnt);
	return error;
}

struct vfsmount *vfs_create_mount(struct fs_context *fc)
{
	struct mount *mnt;

	// 没根结点肯定错了
	if (!fc->root)
		return ERR_PTR(-EINVAL);

	// 分配一个mount对象, 并初始化
	mnt = alloc_vfsmnt(fc->source ?: "none");
	if (!mnt)
		return ERR_PTR(-ENOMEM);

	// 在内核里调用kern_mount的挂载
	if (fc->sb_flags & SB_KERNMOUNT)
		mnt->mnt.mnt_flags = MNT_INTERNAL;

	// 递增超级块的活跃计数
	atomic_inc(&fc->root->d_sb->s_active);
	// 设置超级块
	mnt->mnt.mnt_sb		= fc->root->d_sb;
	// 根结点
	mnt->mnt.mnt_root	= dget(fc->root);
	// 挂载点先设置成自己的根
	mnt->mnt_mountpoint	= mnt->mnt.mnt_root;
	// 父目录先设置成自己
	mnt->mnt_parent		= mnt;

	// 加入超级块的s_mounts列表
	lock_mount_hash();
	list_add_tail(&mnt->mnt_instance, &mnt->mnt.mnt_sb->s_mounts);
	unlock_mount_hash();
	return &mnt->mnt;
}


static struct mount *alloc_vfsmnt(const char *name)
{
	struct mount *mnt = kmem_cache_zalloc(mnt_cache, GFP_KERNEL);
	if (mnt) {
		int err;

		// 分配一个id, 并设置到mnt->mnt_id里
		err = mnt_alloc_id(mnt);
		if (err)
			goto out_free_cache;

		// 设置 设备名
		if (name) {
			mnt->mnt_devname = kstrdup_const(name, GFP_KERNEL);
			if (!mnt->mnt_devname)
				goto out_free_id;
		}

		// 初始化引用计数相关, smp使用percpu
#ifdef CONFIG_SMP
		mnt->mnt_pcp = alloc_percpu(struct mnt_pcp);
		if (!mnt->mnt_pcp)
			goto out_free_devname;

		this_cpu_add(mnt->mnt_pcp->mnt_count, 1);
#else
		mnt->mnt_count = 1;
		mnt->mnt_writers = 0;
#endif

		// 初始化各种链表
		INIT_HLIST_NODE(&mnt->mnt_hash);
		INIT_LIST_HEAD(&mnt->mnt_child);
		INIT_LIST_HEAD(&mnt->mnt_mounts);
		INIT_LIST_HEAD(&mnt->mnt_list);
		INIT_LIST_HEAD(&mnt->mnt_expire);
		INIT_LIST_HEAD(&mnt->mnt_share);
		INIT_LIST_HEAD(&mnt->mnt_slave_list);
		INIT_LIST_HEAD(&mnt->mnt_slave);
		INIT_HLIST_NODE(&mnt->mnt_mp_list);
		INIT_LIST_HEAD(&mnt->mnt_umounting);
		INIT_HLIST_HEAD(&mnt->mnt_stuck_children);
	}
	return mnt;

#ifdef CONFIG_SMP
out_free_devname:
	kfree_const(mnt->mnt_devname);
#endif
out_free_id:
	mnt_free_id(mnt);
out_free_cache:
	kmem_cache_free(mnt_cache, mnt);
	return NULL;
}


static struct mountpoint *lock_mount(struct path *path)
{
	struct vfsmount *mnt;
	// 目录项
	struct dentry *dentry = path->dentry;
retry:
	inode_lock(dentry->d_inode);
	...
	// 找到path是第1个挂载的mnt
	mnt = lookup_mnt(path);
	// 一般情况下目录上都没有挂载,所以是空的
	if (likely(!mnt)) {
		// 给dentry创建一个mountpoint对象
		struct mountpoint *mp = get_mountpoint(dentry);
		if (IS_ERR(mp)) {
			namespace_unlock();
			inode_unlock(dentry->d_inode);
			return mp;
		}
		return mp;
	}

	...

	// 设置为找到的mnt
	path->mnt = mnt;
	// 把dentry设置为找到的根
	dentry = path->dentry = dget(mnt->mnt_root);
	// 继续找, 因为要一直前进到最后一个挂载的
	goto retry;
}

static struct mountpoint *get_mountpoint(struct dentry *dentry)
{
	struct mountpoint *mp, *new = NULL;
	int ret;

	// 已有挂载, 判断dentry有无DCACHE_MOUNTED标志
	if (d_mountpoint(dentry)) {
		// dentry没有被链接到vfs系统里,出错?
		if (d_unlinked(dentry))
			return ERR_PTR(-ENOENT);
mountpoint:
		read_seqlock_excl(&mount_lock);
		// 在缓存里再查找
		mp = lookup_mountpoint(dentry);
		read_sequnlock_excl(&mount_lock);
		// 找到了
		if (mp)
			goto done;
	}
	// 走到这儿是没找到对应的mountpoint对象
	// 分配一个新的
	if (!new)
		new = kmalloc(sizeof(struct mountpoint), GFP_KERNEL);
	if (!new)
		return ERR_PTR(-ENOMEM);


	// 设置DCACHE_MOUNTED标志
	ret = d_set_mounted(dentry);

	// 其它进程已经设置了标志, 则又去缓存里找
	if (ret == -EBUSY)
		goto mountpoint;

	// 其它错误
	mp = ERR_PTR(ret);
	if (ret)
		goto done;

	/* Add the new mountpoint to the hash table */
	read_seqlock_excl(&mount_lock);
	// 设置dentry和数量
	new->m_dentry = dget(dentry);
	new->m_count = 1;
	// 添加到mountpoint的哈希表里
	hlist_add_head(&new->m_hash, mp_hash(dentry));
	INIT_HLIST_HEAD(&new->m_list);
	read_sequnlock_excl(&mount_lock);

	mp = new;
	new = NULL;
done:
	kfree(new);
	return mp;
}

struct vfsmount *lookup_mnt(const struct path *path)
{
	struct mount *child_mnt;
	struct vfsmount *m;
	unsigned seq;

	rcu_read_lock();
	do {
		seq = read_seqbegin(&mount_lock);
		// 找到path上的第1个挂载的mnt
		child_mnt = __lookup_mnt(path->mnt, path->dentry);
		m = child_mnt ? &child_mnt->mnt : NULL;
		// 递增m的引用计数, 递增成功返回true
	} while (!legitimize_mnt(m, seq));
	rcu_read_unlock();
	return m;
}

struct mount *__lookup_mnt(struct vfsmount *mnt, struct dentry *dentry)
{
	// 以mnt, dentry估key进行哈希, 表里存的都是 struct mount
	struct hlist_head *head = m_hash(mnt, dentry);
	struct mount *p;

	// 找到dentry上的第1个挂载的mnt
	hlist_for_each_entry_rcu(p, head, mnt_hash)
		if (&p->mnt_parent->mnt == mnt && p->mnt_mountpoint == dentry)
			return p;
	return NULL;
}
```

## do_add_mount
```c
static int do_add_mount(struct mount *newmnt, struct mountpoint *mp /*挂载点结构*/,
			struct path *path /*挂载点信息*/, int mnt_flags)
{
	...

	// 一个文件系统不能在自己的根上挂载挂多次
	if (path->mnt->mnt_sb == newmnt->mnt.mnt_sb &&
	    path->mnt->mnt_root == path->dentry)
		return -EBUSY;

	// 根节点不能是软链接
	if (d_is_symlink(newmnt->mnt.mnt_root))
		return -EINVAL;

	newmnt->mnt.mnt_flags = mnt_flags;
	return graft_tree(newmnt, parent, mp);
}

static int graft_tree(struct mount *mnt, struct mount *p, struct mountpoint *mp)
{
	// 用户层不能挂载则出错
	if (mnt->mnt.mnt_sb->s_flags & SB_NOUSER)
		return -EINVAL;
	
	// 挂载点和fs根目录必需都是目录
	if (d_is_dir(mp->m_dentry) !=
	      d_is_dir(mnt->mnt.mnt_root))
		return -ENOTDIR;

	// 递规添加,这个是真正添加到挂载相关的结构里的
	return attach_recursive_mnt(mnt, p, mp, false);
}

static int attach_recursive_mnt(struct mount *source_mnt,
			struct mount *dest_mnt,
			struct mountpoint *dest_mp,
			bool moving)
{
	// 进行命名空间
	struct user_namespace *user_ns = current->nsproxy->mnt_ns->user_ns;
	HLIST_HEAD(tree_list);
	// 父mount的命名空间
	struct mnt_namespace *ns = dest_mnt->mnt_ns;
	struct mountpoint *smp;
	struct mount *child, *p;
	struct hlist_node *n;
	int err;

	...
	if (moving) {
		...
	} else {
		// 若有已挂载的ns,则先删除
		if (source_mnt->mnt_ns) {
			list_del_init(&source_mnt->mnt_ns->list);
		}
		// mnt设置挂载点
		mnt_set_mountpoint(dest_mnt, dest_mp, source_mnt);
		// 提交树
		commit_tree(source_mnt);
	}

	...
	return err;
}



static struct mountpoint *lookup_mountpoint(struct dentry *dentry)
{
	// 这个是mountpoint的哈希表
	struct hlist_head *chain = mp_hash(dentry);
	struct mountpoint *mp;

	// 返回dentry对应的mountpoint
	hlist_for_each_entry(mp, chain, m_hash) {
		if (mp->m_dentry == dentry) {
			mp->m_count++;
			return mp;
		}
	}
	return NULL;
}

void mnt_set_mountpoint(struct mount *mnt,
			struct mountpoint *mp,
			struct mount *child_mnt)
{
	// 挂载点挂载数量增加
	mp->m_count++;
	// mnt->mnt_count += 1
	mnt_add_count(mnt, 1);
	// 设置挂载点的dentry
	child_mnt->mnt_mountpoint = mp->m_dentry;
	// 设置父mnt
	child_mnt->mnt_parent = mnt;
	// 设置mountpoint
	child_mnt->mnt_mp = mp;
	// 添加到挂载点的列表里
	hlist_add_head(&child_mnt->mnt_mp_list, &mp->m_list);
}

static void commit_tree(struct mount *mnt/*新挂载 mnt*/)
{
	// 父mnt
	struct mount *parent = mnt->mnt_parent;
	struct mount *m;
	LIST_HEAD(head);
	// 父ns
	struct mnt_namespace *n = parent->mnt_ns;

	// parent不能和mnt相等
	BUG_ON(parent == mnt);
	// 先把mnt_list添加到head里
	list_add_tail(&head, &mnt->mnt_list);
	// 遍历mnt里所有子结点,设置mnt_ns为父节点
	list_for_each_entry(m, &head, mnt_list)
		m->mnt_ns = n;

	// 把这些转到父ns的列表
	list_splice(&head, n->list.prev);

	// 递增之前待挂载数据
	n->mounts += n->pending_mounts;
	// 待挂载置0
	n->pending_mounts = 0;

	// 添加mnt到哈希表和父mnt的列表
	__attach_mnt(mnt, parent);
	// 递增ns->event, 然后唤醒等待poll的人
	touch_mnt_namespace(n);
}

static void __attach_mnt(struct mount *mnt, struct mount *parent)
{
	// 挂到相应的哈希表上
	hlist_add_head_rcu(&mnt->mnt_hash,
				// 这里以parent和挂载点的地址做哈希
			   m_hash(&parent->mnt, mnt->mnt_mountpoint));
	// 添加到父目录的mounts里
	list_add_tail(&mnt->mnt_child, &parent->mnt_mounts);
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