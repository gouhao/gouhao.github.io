```c
SYSCALL_DEFINE2(mkdir, const char __user *, pathname, umode_t, mode)
{
	return do_mkdirat(AT_FDCWD, pathname, mode);
}

static long do_mkdirat(int dfd, const char __user *pathname, umode_t mode)
{
	struct dentry *dentry;
	struct path path;
	int error;
	unsigned int lookup_flags = LOOKUP_DIRECTORY;

retry:
	// 找到路径对应的dentry
	dentry = user_path_create(dfd, pathname, &path, lookup_flags);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	if (!IS_POSIXACL(path.dentry->d_inode))
		mode &= ~current_umask();
	// 安全相关
	error = security_path_mkdir(&path, dentry, mode);
	if (!error)
		error = vfs_mkdir(path.dentry->d_inode, dentry, mode);
	done_path_create(&path, dentry);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	return error;
}

inline struct dentry *user_path_create(int dfd, const char __user *pathname,
				struct path *path, unsigned int lookup_flags)
{
	return filename_create(dfd, getname(pathname), path, lookup_flags);
}

static struct dentry *filename_create(int dfd, struct filename *name,
				struct path *path, unsigned int lookup_flags)
{
	struct dentry *dentry = ERR_PTR(-EEXIST);
	struct qstr last;
	int type;
	int err2;
	int error;
	// 是否是目录
	bool is_dir = (lookup_flags & LOOKUP_DIRECTORY);

	// 设置 LOOKUP_REVAL 标志
	lookup_flags &= LOOKUP_REVAL;

	// 只找到父目录
	name = filename_parentat(dfd, name, lookup_flags, path, &last, &type);
	if (IS_ERR(name))
		return ERR_CAST(name);

	// 最后一个节点不是正常路径名(., .., ///)
	if (unlikely(type != LAST_NORM))
		goto out;

	// 判断写权限,因为下面可能要创建目录
	err2 = mnt_want_write(path->mnt);
	/*
	 * Do the final lookup.
	 */
	lookup_flags |= LOOKUP_CREATE | LOOKUP_EXCL;
	inode_lock_nested(path->dentry->d_inode, I_MUTEX_PARENT);
	// 调用文件系统的lookup来查找对应的目录
	dentry = __lookup_hash(&last, path->dentry, lookup_flags);
	if (IS_ERR(dentry))
		goto unlock;

	// 如果已经存在,不创建
	error = -EEXIST;
	if (d_is_positive(dentry))
		goto fail;

	/*
	 * Special case - lookup gave negative, but... we had foo/bar/
	 * From the vfs_mknod() POV we just have a negative dentry -
	 * all is fine. Let's be bastards - you had / on the end, you've
	 * been asking for (non-existent) directory. -ENOENT for you.
	 */
	if (unlikely(!is_dir && last.name[last.len])) {
		error = -ENOENT;
		goto fail;
	}
	if (unlikely(err2)) {
		error = err2;
		goto fail;
	}
	putname(name);
	return dentry;
fail:
	dput(dentry);
	dentry = ERR_PTR(error);
unlock:
	inode_unlock(path->dentry->d_inode);
	if (!err2)
		mnt_drop_write(path->mnt);
out:
	path_put(path);
	putname(name);
	return dentry;
}
```

## vfs_mkdir
```c
int vfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	// 创建目录检查权限
	int error = may_create(dir, dentry);
	unsigned max_links = dir->i_sb->s_max_links;

	if (error)
		return error;

	if (!dir->i_op->mkdir)
		return -EPERM;

	mode &= (S_IRWXUGO|S_ISVTX);
	// 安全检查
	error = security_inode_mkdir(dir, dentry, mode);
	if (error)
		return error;

	// 链接数超过限制
	if (max_links && dir->i_nlink >= max_links)
		return -EMLINK;
	// 调用文件系统的mkdir
	error = dir->i_op->mkdir(dir, dentry, mode);
	if (!error)
		fsnotify_mkdir(dir, dentry);
	return error;
}
```

// 以xfs为例
```c
STATIC int
xfs_vn_mkdir(
	struct inode	*dir,
	struct dentry	*dentry,
	umode_t		mode)
{
	return xfs_generic_create(dir, dentry, mode | S_IFDIR, 0, false);
}

STATIC int
xfs_generic_create(
	struct inode	*dir,
	struct dentry	*dentry,
	umode_t		mode,
	dev_t		rdev,
	bool		tmpfile)	/* unnamed file */
{
	struct inode	*inode;
	struct xfs_inode *ip = NULL;
	struct posix_acl *default_acl, *acl;
	struct xfs_name	name;
	int		error;

	// 字符/块设备的特殊判断
	if (S_ISCHR(mode) || S_ISBLK(mode)) {
		if (unlikely(!sysv_valid_dev(rdev) || MAJOR(rdev) & ~0x1ff))
			return -EINVAL;
	} else {
		rdev = 0;
	}

	// acl检查
	error = posix_acl_create(dir, &mode, &default_acl, &acl);
	if (error)
		return error;

	// 把dentry里的dentry->name, mode全放到name对象里
	error = xfs_dentry_mode_to_name(&name, dentry, mode);
	if (unlikely(error))
		goto out_free_acl;

	if (!tmpfile) {
		// 创建文件
		error = xfs_create(XFS_I(dir), &name, mode, rdev, &ip);
	} else {
		error = xfs_create_tmpfile(XFS_I(dir), mode, &ip);
	}
	if (unlikely(error))
		goto out_free_acl;

	// 把xfs的inode转成vfs的inode
	inode = VFS_I(ip);

	// 初始化安全相关
	error = xfs_init_security(inode, dir, &dentry->d_name);
	if (unlikely(error))
		goto out_cleanup_inode;

	// acl相关
#ifdef CONFIG_XFS_POSIX_ACL
	if (default_acl) {
		error = __xfs_set_acl(inode, default_acl, ACL_TYPE_DEFAULT);
		if (error)
			goto out_cleanup_inode;
	}
	if (acl) {
		error = __xfs_set_acl(inode, acl, ACL_TYPE_ACCESS);
		if (error)
			goto out_cleanup_inode;
	}
#endif

	// 根据文件类型设置不同的函数操作表(iop, fop, address_space)
	xfs_setup_iops(ip);

	if (tmpfile) {
		/*
		 * The VFS requires that any inode fed to d_tmpfile must have
		 * nlink == 1 so that it can decrement the nlink in d_tmpfile.
		 * However, we created the temp file with nlink == 0 because
		 * we're not allowed to put an inode with nlink > 0 on the
		 * unlinked list.  Therefore we have to set nlink to 1 so that
		 * d_tmpfile can immediately set it back to zero.
		 */
		set_nlink(inode, 1);
		d_tmpfile(dentry, inode);
	} else
		// 把dentry和inode绑定
		d_instantiate(dentry, inode);

	xfs_finish_inode_setup(ip);

 out_free_acl:
	if (default_acl)
		posix_acl_release(default_acl);
	if (acl)
		posix_acl_release(acl);
	return error;

 out_cleanup_inode:
	xfs_finish_inode_setup(ip);
	if (!tmpfile)
		xfs_cleanup_inode(dir, inode, dentry);
	xfs_irele(ip);
	goto out_free_acl;
}

int
xfs_create(
	xfs_inode_t		*dp,
	struct xfs_name		*name,
	umode_t			mode,
	dev_t			rdev,
	xfs_inode_t		**ipp)
{
	int			is_dir = S_ISDIR(mode);
	struct xfs_mount	*mp = dp->i_mount;
	struct xfs_inode	*ip = NULL;
	struct xfs_trans	*tp = NULL;
	int			error;
	bool                    unlock_dp_on_error = false;
	prid_t			prid;
	struct xfs_dquot	*udqp = NULL;
	struct xfs_dquot	*gdqp = NULL;
	struct xfs_dquot	*pdqp = NULL;
	struct xfs_trans_res	*tres;
	uint			resblks;

	trace_xfs_create(dp, name);

	if (XFS_FORCED_SHUTDOWN(mp))
		return -EIO;

	prid = xfs_get_initial_prid(dp);

	// 磁盘配额相关
	error = xfs_qm_vop_dqalloc(dp, current_fsuid(), current_fsgid(), prid,
					XFS_QMOPT_QUOTALL | XFS_QMOPT_INHERIT,
					&udqp, &gdqp, &pdqp);
	if (error)
		return error;

	if (is_dir) {
		resblks = XFS_MKDIR_SPACE_RES(mp, name->len);
		tres = &M_RES(mp)->tr_mkdir;
	} else {
		resblks = XFS_CREATE_SPACE_RES(mp, name->len);
		tres = &M_RES(mp)->tr_create;
	}

	// 分配一个事务
	error = xfs_trans_alloc(mp, tres, resblks, 0, 0, &tp);
	if (error == -ENOSPC) {
		/* flush outstanding delalloc blocks and retry */
		xfs_flush_inodes(mp);
		error = xfs_trans_alloc(mp, tres, resblks, 0, 0, &tp);
	}
	if (error)
		goto out_release_inode;

	xfs_ilock(dp, XFS_ILOCK_EXCL | XFS_ILOCK_PARENT);
	unlock_dp_on_error = true;

	// ??
	error = xfs_trans_reserve_quota(tp, mp, udqp, gdqp,
						pdqp, resblks, 1, 0);
	if (error)
		goto out_trans_cancel;

	// 分配一个inode
	error = xfs_dir_ialloc(&tp, dp, mode, is_dir ? 2 : 1, rdev, prid, &ip);
	if (error)
		goto out_trans_cancel;

	/*
	 * Now we join the directory inode to the transaction.  We do not do it
	 * earlier because xfs_dir_ialloc might commit the previous transaction
	 * (and release all the locks).  An error from here on will result in
	 * the transaction cancel unlocking dp so don't do it explicitly in the
	 * error path.
	 */
	xfs_trans_ijoin(tp, dp, XFS_ILOCK_EXCL);
	unlock_dp_on_error = false;

	// 在父目录里创建文件
	error = xfs_dir_createname(tp, dp, name, ip->i_ino,
					resblks - XFS_IALLOC_SPACE_RES(mp));
	if (error) {
		ASSERT(error != -ENOSPC);
		goto out_trans_cancel;
	}
	xfs_trans_ichgtime(tp, dp, XFS_ICHGTIME_MOD | XFS_ICHGTIME_CHG);
	xfs_trans_log_inode(tp, dp, XFS_ILOG_CORE);

	// 初始化目录
	if (is_dir) {
		error = xfs_dir_init(tp, ip, dp);
		if (error)
			goto out_trans_cancel;

		xfs_bumplink(tp, dp);
	}

	// 事务同步
	if (mp->m_flags & (XFS_MOUNT_WSYNC|XFS_MOUNT_DIRSYNC))
		xfs_trans_set_sync(tp);

	xfs_qm_vop_create_dqattach(tp, ip, udqp, gdqp, pdqp);

	// 提交事务
	error = xfs_trans_commit(tp);
	if (error)
		goto out_release_inode;

	xfs_qm_dqrele(udqp);
	xfs_qm_dqrele(gdqp);
	xfs_qm_dqrele(pdqp);

	*ipp = ip;
	return 0;

 out_trans_cancel:
	xfs_trans_cancel(tp);
 out_release_inode:
	/*
	 * Wait until after the current transaction is aborted to finish the
	 * setup of the inode and release the inode.  This prevents recursive
	 * transactions and deadlocks from xfs_inactive.
	 */
	if (ip) {
		xfs_finish_inode_setup(ip);
		xfs_irele(ip);
	}

	xfs_qm_dqrele(udqp);
	xfs_qm_dqrele(gdqp);
	xfs_qm_dqrele(pdqp);

	if (unlock_dp_on_error)
		xfs_iunlock(dp, XFS_ILOCK_EXCL);
	return error;
}
```