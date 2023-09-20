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

	// 子类解析
	if (subtype)
		err = vfs_parse_fs_string(fc, "subtype",
					  subtype, strlen(subtype));
	// todo: what is source?
	if (!err && name)
		err = vfs_parse_fs_string(fc, "source", name, strlen(name));
	// 解析选项
	if (!err)
		err = parse_monolithic_mount_data(fc, data);
	if (!err && !mount_capable(fc))
		err = -EPERM;

	// 获取目录树,fs一般在这里面做fs的初始化,获取根节点等
	if (!err)
		err = vfs_get_tree(fc);

	// 创建挂载相关的联系
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

	/*
	 * Write barrier is for super_cache_count(). We place it before setting
	 * SB_BORN as the data dependency between the two functions is the
	 * superblock structure contents that we just set up, not the SB_BORN
	 * flag.
	 */
	smp_wmb();
	sb->s_flags |= SB_BORN;

	// 安全相关检查
	error = security_sb_set_mnt_opts(sb, fc->security, 0, NULL);
	if (unlikely(error)) {
		fc_drop_locked(fc);
		return error;
	}

	/*
	 * 文件系统应该永远不设置s_maxbytes大于MAX_LFS_FILESIZE,大多数发行版的s_maxbytes是
	 * unsigned long long, 打印异常对于一些违反规则的文件系统.
	 */
	WARN((sb->s_maxbytes < 0), "%s set sb->s_maxbytes to "
		"negative value (%lld)\n", fc->fs_type->name, sb->s_maxbytes);

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
## 参数解析
```c
int parse_monolithic_mount_data(struct fs_context *fc, void *data)
{
	int (*monolithic_mount_data)(struct fs_context *, void *);

	// parse_monolithic是fs自己全部解析参数
	monolithic_mount_data = fc->ops->parse_monolithic;
	if (!monolithic_mount_data)
		// 没有指定,就使用通用的解析
		monolithic_mount_data = generic_parse_monolithic;

	return monolithic_mount_data(fc, data);
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

	// 安全检查
	error = security_sb_kern_mount(sb);
	// todo: mount_too_revealing?
	if (!error && mount_too_revealing(sb, &mnt_flags))
		error = -EPERM;

	if (unlikely(error)) {
		fc_drop_locked(fc);
		return error;
	}

	up_write(&sb->s_umount);
	// 创建sruct mount结构, 最终返回的是mount->mnt
	mnt = vfs_create_mount(fc);
	if (IS_ERR(mnt))
		return PTR_ERR(mnt);

	// 检查时间是否过了最大值
	mnt_warn_timestamp_expiry(mountpoint, mnt);

	// 找mnt, 
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

	if (!fc->root)
		return ERR_PTR(-EINVAL);

	mnt = alloc_vfsmnt(fc->source ?: "none");
	if (!mnt)
		return ERR_PTR(-ENOMEM);

	if (fc->sb_flags & SB_KERNMOUNT)
		mnt->mnt.mnt_flags = MNT_INTERNAL;

	atomic_inc(&fc->root->d_sb->s_active);
	mnt->mnt.mnt_sb		= fc->root->d_sb;
	mnt->mnt.mnt_root	= dget(fc->root);
	mnt->mnt_mountpoint	= mnt->mnt.mnt_root;
	mnt->mnt_parent		= mnt;

	lock_mount_hash();
	list_add_tail(&mnt->mnt_instance, &mnt->mnt.mnt_sb->s_mounts);
	unlock_mount_hash();
	return &mnt->mnt;
}

static struct mountpoint *lock_mount(struct path *path)
{
	struct vfsmount *mnt;
	// 目录项
	struct dentry *dentry = path->dentry;
retry:
	inode_lock(dentry->d_inode);
	// 判断目录是否不能挂载,若是直接报错
	if (unlikely(cant_mount(dentry))) {
		inode_unlock(dentry->d_inode);
		return ERR_PTR(-ENOENT);
	}
	namespace_lock();
	mnt = lookup_mnt(path);
	if (likely(!mnt)) {
		struct mountpoint *mp = get_mountpoint(dentry);
		if (IS_ERR(mp)) {
			namespace_unlock();
			inode_unlock(dentry->d_inode);
			return mp;
		}
		return mp;
	}
	namespace_unlock();
	inode_unlock(path->dentry->d_inode);
	path_put(path);
	path->mnt = mnt;
	dentry = path->dentry = dget(mnt->mnt_root);
	goto retry;
}
```

## do_add_mount
```c
static int do_add_mount(struct mount *newmnt, struct mountpoint *mp /*挂载点结构*/,
			struct path *path /*挂载点信息*/, int mnt_flags)
{
	// 挂载点的mount结构
	struct mount *parent = real_mount(path->mnt);

	// 删除挂载时内部用到的标志
	mnt_flags &= ~MNT_INTERNAL_FLAGS;

	// 检查当前进程的命名空间与父空间是否相等
	if (unlikely(!check_mnt(parent))) {
		/* that's acceptable only for automounts done in private ns */
		if (!(mnt_flags & MNT_SHRINKABLE))
			return -EINVAL;
		/* ... and for those we'd better have mountpoint still alive */
		if (!parent->mnt_ns)
			return -EINVAL;
	}

	// 一个文件系统不能在同一个挂载点上挂多次
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

	/* 
	 * 先分配一个mountpint,因为有时一个新的挂载要放到其他挂载下面
	 * 正常情况下用不到
	 */
	smp = get_mountpoint(source_mnt->mnt.mnt_root);
	if (IS_ERR(smp))
		return PTR_ERR(smp);

	// 如果不可移动要统计当前ns里是否还有空闲容纳新挂载
	if (!moving) {
		err = count_mounts(ns, source_mnt);
		if (err)
			goto out;
	}

	// 有无shared标志
	if (IS_MNT_SHARED(dest_mnt)) {
		err = invent_group_ids(source_mnt, true);
		if (err)
			goto out;
		err = propagate_mnt(dest_mnt, dest_mp, source_mnt, &tree_list);
		lock_mount_hash();
		if (err)
			goto out_cleanup_ids;
		for (p = source_mnt; p; p = next_mnt(p, source_mnt))
			set_mnt_shared(p);
	} else {
		// 获取mount_lock写顺序锁
		lock_mount_hash();
	}
	if (moving) {
		unhash_mnt(source_mnt);
		attach_mnt(source_mnt, dest_mnt, dest_mp);
		touch_mnt_namespace(source_mnt->mnt_ns);
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

	// 没有share时,tree_list是空的.todo:后面再分析
	hlist_for_each_entry_safe(child, n, &tree_list, mnt_hash) {
		struct mount *q;
		hlist_del_init(&child->mnt_hash);
		q = __lookup_mnt(&child->mnt_parent->mnt,
				 child->mnt_mountpoint);
		if (q)
			mnt_change_mountpoint(child, smp, q);
		/* Notice when we are propagating across user namespaces */
		if (child->mnt_parent->mnt_ns->user_ns != user_ns)
			lock_mnt_tree(child);
		child->mnt.mnt_flags &= ~MNT_LOCKED;
		commit_tree(child);
	}
	put_mountpoint(smp);
	unlock_mount_hash();

	return 0;

 out_cleanup_ids:
	while (!hlist_empty(&tree_list)) {
		child = hlist_entry(tree_list.first, struct mount, mnt_hash);
		child->mnt_parent->mnt_ns->pending_mounts = 0;
		umount_tree(child, UMOUNT_SYNC);
	}
	unlock_mount_hash();
	cleanup_group_ids(source_mnt, NULL);
 out:
	ns->pending_mounts = 0;

	read_seqlock_excl(&mount_lock);
	put_mountpoint(smp);
	read_sequnlock_excl(&mount_lock);

	return err;
}

static struct mountpoint *get_mountpoint(struct dentry *dentry)
{
	struct mountpoint *mp, *new = NULL;
	int ret;

	// 已有挂载
	if (d_mountpoint(dentry)) {
		/* might be worth a WARN_ON() */
		if (d_unlinked(dentry))
			return ERR_PTR(-ENOENT);
mountpoint:
		read_seqlock_excl(&mount_lock);
		// 在缓存里再查找
		mp = lookup_mountpoint(dentry);
		read_sequnlock_excl(&mount_lock);
		if (mp)
			goto done;
	}

	// 分配一个新mountpoint
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

static struct mountpoint *lookup_mountpoint(struct dentry *dentry)
{
	struct hlist_head *chain = mp_hash(dentry);
	struct mountpoint *mp;

	hlist_for_each_entry(mp, chain, m_hash) {
		if (mp->m_dentry == dentry) {
			mp->m_count++;
			return mp;
		}
	}
	return NULL;
}

int count_mounts(struct mnt_namespace *ns, struct mount *mnt)
{
	unsigned int max = READ_ONCE(sysctl_mount_max);
	unsigned int mounts = 0, old, pending, sum;
	struct mount *p;

	for (p = mnt; p; p = next_mnt(p, mnt))
		mounts++;

	old = ns->mounts;
	pending = ns->pending_mounts;
	sum = old + pending;
	if ((old > sum) ||
	    (pending > sum) ||
	    (max < sum) ||
	    (mounts > (max - sum)))
		return -ENOSPC;

	ns->pending_mounts = pending + mounts;
	return 0;
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

	// 遍历mnt里所有子结点,设置mnt_ns为父节点
	list_add_tail(&head, &mnt->mnt_list);
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