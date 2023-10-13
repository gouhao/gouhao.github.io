# create
源码基于5.10

## 1. create
```c
/*
dir: 父目录
dentry: 新文件的dentry
mode: 新文件模式
excl: 判断是否存在？
*/
static int ext4_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		       bool excl)
{
	handle_t *handle;
	struct inode *inode;
	int err, credits, retries = 0;

	// todo: 配额后面看
	err = dquot_initialize(dir);
	if (err)
		return err;

	// what?
	credits = (EXT4_DATA_TRANS_BLOCKS(dir->i_sb) +
		   EXT4_INDEX_EXTRA_TRANS_BLOCKS + 3);
retry:
	// 创建inode
	inode = ext4_new_inode_start_handle(dir, mode, &dentry->d_name, 0,
					    NULL, EXT4_HT_DIR, credits);
	// 获取日志handle
	handle = ext4_journal_current_handle();
	err = PTR_ERR(inode);
	if (!IS_ERR(inode)) {
		// 创建成功，设置各种函数表
		inode->i_op = &ext4_file_inode_operations;
		inode->i_fop = &ext4_file_operations;
		// 设置mapping函数
		ext4_set_aops(inode);
		// 添加到目录
		err = ext4_add_nondir(handle, dentry, &inode);
	}
	if (handle)
		ext4_journal_stop(handle);
	if (!IS_ERR_OR_NULL(inode))
		iput(inode);
	
	// 如果是空间了，再重试
	if (err == -ENOSPC && ext4_should_retry_alloc(dir->i_sb, &retries))
		goto retry;
	return err;
}
```

## 2. ext4_new_inode_start_handle
```c
#define ext4_new_inode_start_handle(dir, mode, qstr, goal, owner, \
				    type, nblocks)		    \
	__ext4_new_inode(NULL, (dir), (mode), (qstr), (goal), (owner), \
			 0, (type), __LINE__, (nblocks))

struct inode *__ext4_new_inode(handle_t *handle, struct inode *dir,
			       umode_t mode, const struct qstr *qstr,
			       __u32 goal, uid_t *owner, __u32 i_flags,
			       int handle_type, unsigned int line_no,
			       int nblocks)
{
	struct super_block *sb;
	struct buffer_head *inode_bitmap_bh = NULL;
	struct buffer_head *group_desc_bh;
	ext4_group_t ngroups, group = 0;
	unsigned long ino = 0;
	struct inode *inode;
	struct ext4_group_desc *gdp = NULL;
	struct ext4_inode_info *ei;
	struct ext4_sb_info *sbi;
	int ret2, err;
	struct inode *ret;
	ext4_group_t i;
	ext4_group_t flex_group;
	struct ext4_group_info *grp;
	int encrypt = 0;

	// 目录已经被删除
	if (!dir || !dir->i_nlink)
		return ERR_PTR(-EPERM);

	// 超级块信息
	sb = dir->i_sb;
	sbi = EXT4_SB(sb);

	// 有强制关闭的标志，则直接退出
	if (unlikely(ext4_forced_shutdown(sbi)))
		return ERR_PTR(-EIO);

	// 加密相关，后面再看
	if ((ext4_encrypted_inode(dir) || DUMMY_ENCRYPTION_ENABLED(sbi)) &&
	    (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode)) &&
	    !(i_flags & EXT4_EA_INODE_FL)) {
		err = fscrypt_get_encryption_info(dir);
		if (err)
			return ERR_PTR(err);
		if (!fscrypt_has_encryption_key(dir))
			return ERR_PTR(-ENOKEY);
		encrypt = 1;
	}

	// 没有handle && 有日志 && 不是扩展属性inode?
	// todo: 这里面是算什么？
	if (!handle && sbi->s_journal && !(i_flags & EXT4_EA_INODE_FL)) {
		// todo: 这是计算什么？
#ifdef CONFIG_EXT4_FS_POSIX_ACL
		struct posix_acl *p = get_acl(dir, ACL_TYPE_DEFAULT);

		if (IS_ERR(p))
			return ERR_CAST(p);
		if (p) {
			int acl_size = p->a_count * sizeof(ext4_acl_entry);

			nblocks += (S_ISDIR(mode) ? 2 : 1) *
				__ext4_xattr_set_credits(sb, NULL /* inode */,
					NULL /* block_bh */, acl_size,
					true /* is_create */);
			posix_acl_release(p);
		}
#endif

#ifdef CONFIG_SECURITY
		{
			// 安全
			int num_security_xattrs = 1;

#ifdef CONFIG_INTEGRITY
			// 度量
			num_security_xattrs++;
#endif
			/*
			 * We assume that security xattrs are never
			 * more than 1k.  In practice they are under
			 * 128 bytes.
			 */
			nblocks += num_security_xattrs *
				__ext4_xattr_set_credits(sb, NULL /* inode */,
					NULL /* block_bh */, 1024,
					true /* is_create */);
		}
#endif
		// 加密
		if (encrypt)
			nblocks += __ext4_xattr_set_credits(sb,
					NULL /* inode */, NULL /* block_bh */,
					FSCRYPT_SET_CONTEXT_MAX_SIZE,
					true /* is_create */);
	}

	// 组数
	ngroups = ext4_get_groups_count(sb);
	trace_ext4_request_inode(dir, mode);

	// 这个会调到ext4_alloc_inode
	inode = new_inode(sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	// ext4-inode信息
	ei = EXT4_I(inode);

	if (owner) {
		// 指定了属主
		inode->i_mode = mode;
		// 设置uid/gid
		i_uid_write(inode, owner[0]);
		i_gid_write(inode, owner[1]);
	} else if (test_opt(sb, GRPID)) {
		// 如果没指定，超级块有GRPID标志时才指定
		inode->i_mode = mode;
		// uid为当前进程的uid
		inode->i_uid = current_fsuid();
		// 组id是父目录的id
		inode->i_gid = dir->i_gid;
	} else
		// 这个和上面test_opt分支的差不多，只不过在设置组id时，考虑了set-gid
		inode_init_owner(inode, dir, mode);

	// todo: 什么是投影特性？
	if (ext4_has_feature_project(sb) &&
	    ext4_test_inode_flag(dir, EXT4_INODE_PROJINHERIT))
		ei->i_projid = EXT4_I(dir)->i_projid;
	else
		ei->i_projid = make_kprojid(&init_user_ns, EXT4_DEF_PROJID);

	// 初始化inode的配额
	err = dquot_initialize(inode);
	if (err)
		goto out;

	// 没有指定目标，则默认是s_inode_goal，这个值是在sysfs里用户可以指定，如果没指定，则为0
	if (!goal)
		goal = sbi->s_inode_goal;

	// 有目标 && 小于inode的数量
	if (goal && goal <= le32_to_cpu(sbi->s_es->s_inodes_count)) {
		// 算出inode所在的组
		group = (goal - 1) / EXT4_INODES_PER_GROUP(sb);
		// 算出所在组的inode号
		ino = (goal - 1) % EXT4_INODES_PER_GROUP(sb);
		ret2 = 0;
		// 跳到找到组
		goto got_group;
	}

	// 如果上面没有指定goal，则根据目录/文件使用下面方法继续找
	// todo: 后面看
	if (S_ISDIR(mode))
		ret2 = find_group_orlov(sb, dir, &group, mode, qstr);
	else
		ret2 = find_group_other(sb, dir, &group, mode);

got_group:
	// 设置目录里最后一次分配的组
	EXT4_I(dir)->i_last_alloc_group = group;
	err = -ENOSPC;
	// 没空间了
	if (ret2 == -1)
		goto out;

	// 通常情况下一次循环就能搞定
	for (i = 0; i < ngroups; i++, ino = 0) {
		err = -EIO;

		// 获取组描述符
		gdp = ext4_get_group_desc(sb, group, &group_desc_bh);
		if (!gdp)
			goto out;

		// 组的空闲inode数量为0
		if (ext4_free_inodes_count(sb, gdp) == 0)
			goto next_group;

		// 组信息
		grp = ext4_get_group_info(sb, group);
		// 有不正确的、可疑的inode表，则跳过
		if (EXT4_MB_GRP_IBITMAP_CORRUPT(grp))
			goto next_group;
		// 释放之前的inode表
		brelse(inode_bitmap_bh);
		// 读入当前表的inode位图
		inode_bitmap_bh = ext4_read_inode_bitmap(sb, group);
		// 为什么这里还要判断一次corrupt(grp)，难道是因为read_inodebitmap是个耗时操作？
		// 如果位图读取失败，则遍历下个组
		if (EXT4_MB_GRP_IBITMAP_CORRUPT(grp) ||
		    IS_ERR(inode_bitmap_bh)) {
			inode_bitmap_bh = NULL;
			goto next_group;
		}

repeat_in_this_group:
		// 找一个空闲的inode号
		ret2 = find_inode_bit(sb, group, inode_bitmap_bh, &ino);
		if (!ret2)
			goto next_group;
		
		// 找到是保留的inode号，则错了，去下个组找
		if (group == 0 && (ino + 1) < EXT4_FIRST_INO(sb)) {
			ext4_error(sb, "reserved inode found cleared - "
				   "inode=%lu", ino + 1);
			ext4_mark_group_bitmap_corrupted(sb, group,
					EXT4_GROUP_INFO_IBITMAP_CORRUPT);
			goto next_group;
		}

		// 走到这儿表示找inode号成功了

		// 如果没有日志，则分配一个日志handle
		if (!handle) {
			BUG_ON(nblocks <= 0);
			handle = __ext4_journal_start_sb(dir->i_sb, line_no,
				 handle_type, nblocks, 0,
				 ext4_trans_default_revoke_credits(sb));
			if (IS_ERR(handle)) {
				err = PTR_ERR(handle);
				ext4_std_error(sb, err);
				goto out;
			}
		}
		BUFFER_TRACE(inode_bitmap_bh, "get_write_access");
		// 获取写权限
		err = ext4_journal_get_write_access(handle, inode_bitmap_bh);
		if (err) {
			ext4_std_error(sb, err);
			goto out;
		}
		ext4_lock_group(sb, group);
		// 设置位图里相应的位
		ret2 = ext4_test_and_set_bit(ino, inode_bitmap_bh->b_data);

		// 如果设置失败，则再到这个bh里重新找一次
		if (ret2) {
			ret2 = find_inode_bit(sb, group, inode_bitmap_bh, &ino);
			if (ret2) {
				ext4_set_bit(ino, inode_bitmap_bh->b_data);
				ret2 = 0;
			} else {
				ret2 = 1; /* we didn't grab the inode */
			}
		}
		ext4_unlock_group(sb, group);

		// inode号递增
		ino++;		/* the inode bitmap is zero-based */

		// 为0，说明设置成功
		if (!ret2)
			goto got; /* we grabbed the inode! */

		// 走到这儿说明没有找到ino，或者设置ino失败

		// 如果小于这组的inode，则继续在这个组里找
		if (ino < EXT4_INODES_PER_GROUP(sb))
			goto repeat_in_this_group;
next_group:
		// 在下个组里继续试，如果走到最后一组，则继续从0号组继续试
		if (++group == ngroups)
			group = 0;
	}

	// 走到这儿表示失败了
	err = -ENOSPC;
	goto out;

got:
	BUFFER_TRACE(inode_bitmap_bh, "call ext4_handle_dirty_metadata");
	// todo: 元数据同步相关？
	err = ext4_handle_dirty_metadata(handle, NULL, inode_bitmap_bh);
	if (err) {
		ext4_std_error(sb, err);
		goto out;
	}

	BUFFER_TRACE(group_desc_bh, "get_write_access");
	// 获取group_desc_bh的写访问
	err = ext4_journal_get_write_access(handle, group_desc_bh);
	if (err) {
		ext4_std_error(sb, err);
		goto out;
	}

	// 组描述符需要校验 && 没有初始化过block
	if (ext4_has_group_desc_csum(sb) &&
	    gdp->bg_flags & cpu_to_le16(EXT4_BG_BLOCK_UNINIT)) {
		struct buffer_head *block_bitmap_bh;

		// 读块位图
		block_bitmap_bh = ext4_read_block_bitmap(sb, group);
		if (IS_ERR(block_bitmap_bh)) {
			err = PTR_ERR(block_bitmap_bh);
			goto out;
		}
		BUFFER_TRACE(block_bitmap_bh, "get block bitmap access");
		// 获取块位图的写访问
		err = ext4_journal_get_write_access(handle, block_bitmap_bh);
		if (err) {
			brelse(block_bitmap_bh);
			ext4_std_error(sb, err);
			goto out;
		}

		BUFFER_TRACE(block_bitmap_bh, "dirty block bitmap");
		// todo: what ?
		err = ext4_handle_dirty_metadata(handle, NULL, block_bitmap_bh);

		/* recheck and clear flag under lock if we still need to */
		ext4_lock_group(sb, group);
		// 加锁之后，可能会变，所以再判断一次
		if (ext4_has_group_desc_csum(sb) &&
		    (gdp->bg_flags & cpu_to_le16(EXT4_BG_BLOCK_UNINIT))) {
			// 清除 EXT4_BG_BLOCK_UNINIT 位
			gdp->bg_flags &= cpu_to_le16(~EXT4_BG_BLOCK_UNINIT);
			// todo: what？
			ext4_free_group_clusters_set(sb, gdp,
				ext4_free_clusters_after_init(sb, group, gdp));
			// 设置块位图校验和
			ext4_block_bitmap_csum_set(sb, group, gdp,
						   block_bitmap_bh);
			// 设置组校验和
			ext4_group_desc_csum_set(sb, group, gdp);
		}
		ext4_unlock_group(sb, group);
		brelse(block_bitmap_bh);

		// 出错
		if (err) {
			ext4_std_error(sb, err);
			goto out;
		}
	}

	// 更新相关的组校验和
	if (ext4_has_group_desc_csum(sb)) {
		int free;
		struct ext4_group_info *grp = ext4_get_group_info(sb, group);

		down_read(&grp->alloc_sem); /* protect vs itable lazyinit */
		ext4_lock_group(sb, group); /* while we modify the bg desc */
		free = EXT4_INODES_PER_GROUP(sb) -
			ext4_itable_unused_count(sb, gdp);
		// 需要初始化inode
		if (gdp->bg_flags & cpu_to_le16(EXT4_BG_INODE_UNINIT)) {
			gdp->bg_flags &= cpu_to_le16(~EXT4_BG_INODE_UNINIT);
			free = 0;
		}
		// todo?
		if (ino > free)
			ext4_itable_unused_set(sb, gdp,
					(EXT4_INODES_PER_GROUP(sb) - ino));
		up_read(&grp->alloc_sem);
	} else {
		ext4_lock_group(sb, group);
	}

	// 空闲inode数减1
	ext4_free_inodes_set(sb, gdp, ext4_free_inodes_count(sb, gdp) - 1);
	if (S_ISDIR(mode)) {
		// 目录

		// 目录使用数+1
		ext4_used_dirs_set(sb, gdp, ext4_used_dirs_count(sb, gdp) + 1);

		// todo: flex_bg后面再看
		if (sbi->s_log_groups_per_flex) {
			ext4_group_t f = ext4_flex_group(sbi, group);

			atomic_inc(&sbi_array_rcu_deref(sbi, s_flex_groups,
							f)->used_dirs);
		}
	}

	// 设置相关组描述符校验和
	if (ext4_has_group_desc_csum(sb)) {
		ext4_inode_bitmap_csum_set(sb, group, gdp, inode_bitmap_bh,
					   EXT4_INODES_PER_GROUP(sb) / 8);
		ext4_group_desc_csum_set(sb, group, gdp);
	}
	ext4_unlock_group(sb, group);

	BUFFER_TRACE(group_desc_bh, "call ext4_handle_dirty_metadata");
	// 同步组描述符
	err = ext4_handle_dirty_metadata(handle, NULL, group_desc_bh);
	if (err) {
		ext4_std_error(sb, err);
		goto out;
	}

	// 递减空闲inode数量
	percpu_counter_dec(&sbi->s_freeinodes_counter);
	// 若是目录，递增目录的数量
	if (S_ISDIR(mode))
		percpu_counter_inc(&sbi->s_dirs_counter);

	if (sbi->s_log_groups_per_flex) {
		flex_group = ext4_flex_group(sbi, group);
		atomic_dec(&sbi_array_rcu_deref(sbi, s_flex_groups,
						flex_group)->free_inodes);
	}

	// 算出最终的ino
	inode->i_ino = ino + group * EXT4_INODES_PER_GROUP(sb);
	// 块数为0
	inode->i_blocks = 0;
	// 各时间设为当前时间
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	ei->i_crtime = inode->i_mtime;

	// i_data清0
	memset(ei->i_data, 0, sizeof(ei->i_data));
	ei->i_dir_start_lookup = 0;
	ei->i_disksize = 0;

	/* Don't inherit extent flag from directory, amongst others. */
	ei->i_flags =
		ext4_mask_flags(mode, EXT4_I(dir)->i_flags & EXT4_FL_INHERITED);
	ei->i_flags |= i_flags;
	ei->i_file_acl = 0;
	ei->i_dtime = 0;
	// 所在块组
	ei->i_block_group = group;
	ei->i_last_alloc_group = ~0;

	ext4_set_inode_flags(inode);

	// 目录同步
	if (IS_DIRSYNC(inode))
		ext4_handle_sync(handle);
	
	// 插入inode到vfs的各种表
	if (insert_inode_locked(inode) < 0) {
		// 插入出错，设置bitmap错误
		err = -EIO;
		ext4_error(sb, "failed to insert inode %lu: doubly allocated?",
			   inode->i_ino);
		ext4_mark_group_bitmap_corrupted(sb, group,
					EXT4_GROUP_INFO_IBITMAP_CORRUPT);
		goto out;
	}
	// 年龄
	inode->i_generation = prandom_u32();

	// 元数据校验
	if (ext4_has_metadata_csum(sb)) {
		// 生成校验种子？
		__u32 csum;
		__le32 inum = cpu_to_le32(inode->i_ino);
		__le32 gen = cpu_to_le32(inode->i_generation);
		csum = ext4_chksum(sbi, sbi->s_csum_seed, (__u8 *)&inum,
				   sizeof(inum));
		ei->i_csum_seed = ext4_chksum(sbi, csum, (__u8 *)&gen,
					      sizeof(gen));
	}

	// 清除所有状态
	ext4_clear_state_flags(ei); /* Only relevant on 32-bit archs */
	// 设置状态为新
	ext4_set_inode_state(inode, EXT4_STATE_NEW);

	// 额外大小
	ei->i_extra_isize = sbi->s_want_extra_isize;
	ei->i_inline_off = 0;
	// 有内部数据
	if (ext4_has_feature_inline_data(sb))
		ext4_set_inode_state(inode, EXT4_STATE_MAY_INLINE_DATA);
	ret = inode;
	// 配额？
	err = dquot_alloc_inode(inode);
	if (err)
		goto fail_drop;

	// 加密相关
	if (encrypt) {
		err = fscrypt_inherit_context(dir, inode, handle, true);
		if (err)
			goto fail_free_drop;
	}

	// 初始化acl，扩展属性相关
	if (!(ei->i_flags & EXT4_EA_INODE_FL)) {
		err = ext4_init_acl(handle, inode, dir);
		if (err)
			goto fail_free_drop;

		err = ext4_init_security(handle, inode, dir, qstr);
		if (err)
			goto fail_free_drop;
	}

	// 如果有extent特性
	if (ext4_has_feature_extents(sb)) {
		// 只对这3种类型的文件设置extent
		if (S_ISDIR(mode) || S_ISREG(mode) || S_ISLNK(mode)) {
			// 设置标志
			ext4_set_inode_flag(inode, EXT4_INODE_EXTENTS);
			// 初始化
			ext4_ext_tree_init(handle, inode);
		}
	}

	// 有效性判断？
	if (ext4_handle_valid(handle)) {
		ei->i_sync_tid = handle->h_transaction->t_tid;
		ei->i_datasync_tid = handle->h_transaction->t_tid;
	}

	// 标记inode为脏
	err = ext4_mark_inode_dirty(handle, inode);
	if (err) {
		ext4_std_error(sb, err);
		goto fail_free_drop;
	}

	ext4_debug("allocating inode %lu\n", inode->i_ino);
	trace_ext4_allocate_inode(inode, dir, mode);
	brelse(inode_bitmap_bh);
	return ret;

fail_free_drop:
	dquot_free_inode(inode);
fail_drop:
	clear_nlink(inode);
	unlock_new_inode(inode);
out:
	dquot_drop(inode);
	inode->i_flags |= S_NOQUOTA;
	iput(inode);
	brelse(inode_bitmap_bh);
	return ERR_PTR(err);
}
```
### 2.1 ext4_alloc_inode
```c
static struct inode *ext4_alloc_inode(struct super_block *sb)
{
	struct ext4_inode_info *ei;

	// 分配内部inode
	ei = kmem_cache_alloc(ext4_inode_cachep, GFP_NOFS);
	if (!ei)
		return NULL;

	// 版本号
	inode_set_iversion(&ei->vfs_inode, 1);
	spin_lock_init(&ei->i_raw_lock);
	INIT_LIST_HEAD(&ei->i_prealloc_list);
	atomic_set(&ei->i_prealloc_active, 0);
	spin_lock_init(&ei->i_prealloc_lock);
	ext4_es_init_tree(&ei->i_es_tree);
	rwlock_init(&ei->i_es_lock);
	INIT_LIST_HEAD(&ei->i_es_list);
	ei->i_es_all_nr = 0;
	ei->i_es_shk_nr = 0;
	ei->i_es_shrink_lblk = 0;
	ei->i_reserved_data_blocks = 0;
	spin_lock_init(&(ei->i_block_reservation_lock));
	ext4_init_pending_tree(&ei->i_pending_tree);
#ifdef CONFIG_QUOTA
	ei->i_reserved_quota = 0;
	memset(&ei->i_dquot, 0, sizeof(ei->i_dquot));
#endif
	ei->jinode = NULL;
	INIT_LIST_HEAD(&ei->i_rsv_conversion_list);
	spin_lock_init(&ei->i_completed_io_lock);
	ei->i_sync_tid = 0;
	ei->i_datasync_tid = 0;
	atomic_set(&ei->i_unwritten, 0);
	INIT_WORK(&ei->i_rsv_conversion_work, ext4_end_io_rsv_work);
	// 初始化fast commit相关
	ext4_fc_init_inode(&ei->vfs_inode);
	mutex_init(&ei->i_fc_lock);
	// 返回内部的vfsinode
	return &ei->vfs_inode;
}
```

### 2.2 find_group_orlov
```c
static int find_group_orlov(struct super_block *sb, struct inode *parent,
			    ext4_group_t *group, umode_t mode,
			    const struct qstr *qstr)
{
	// 父目录
	ext4_group_t parent_group = EXT4_I(parent)->i_block_group;
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	// 组数
	ext4_group_t real_ngroups = ext4_get_groups_count(sb);
	// 每组inode数
	int inodes_per_group = EXT4_INODES_PER_GROUP(sb);
	unsigned int freei, avefreei, grp_free;
	ext4_fsblk_t freec, avefreec;
	unsigned int ndirs;
	int max_dirs, min_inodes;
	ext4_grpblk_t min_clusters;
	ext4_group_t i, grp, g, ngroups;
	struct ext4_group_desc *desc;
	struct orlov_stats stats;
	// flex大小
	int flex_size = ext4_flex_bg_size(sbi);
	struct dx_hash_info hinfo;

	ngroups = real_ngroups;
	// 关于灵活组的计算
	if (flex_size > 1) {
		ngroups = (real_ngroups + flex_size - 1) >>
			sbi->s_log_groups_per_flex;
		parent_group >>= sbi->s_log_groups_per_flex;
	}

	// 空闲inode数量
	freei = percpu_counter_read_positive(&sbi->s_freeinodes_counter);
	// 平均空闲数量
	avefreei = freei / ngroups;
	// 空闲组数
	freec = percpu_counter_read_positive(&sbi->s_freeclusters_counter);
	// 平均空闲组数
	avefreec = freec;
	do_div(avefreec, ngroups);
	// 目录数量
	ndirs = percpu_counter_read_positive(&sbi->s_dirs_counter);

	if (S_ISDIR(mode) &&
	    ((parent == d_inode(sb->s_root)) ||
	     (ext4_test_inode_flag(parent, EXT4_INODE_TOPDIR)))) {
		int best_ndir = inodes_per_group;
		int ret = -1;

		if (qstr) {
			hinfo.hash_version = DX_HASH_HALF_MD4;
			hinfo.seed = sbi->s_hash_seed;
			ext4fs_dirhash(parent, qstr->name, qstr->len, &hinfo);
			grp = hinfo.hash;
		} else
			grp = prandom_u32();
		parent_group = (unsigned)grp % ngroups;
		for (i = 0; i < ngroups; i++) {
			g = (parent_group + i) % ngroups;
			get_orlov_stats(sb, g, flex_size, &stats);
			if (!stats.free_inodes)
				continue;
			if (stats.used_dirs >= best_ndir)
				continue;
			if (stats.free_inodes < avefreei)
				continue;
			if (stats.free_clusters < avefreec)
				continue;
			grp = g;
			ret = 0;
			best_ndir = stats.used_dirs;
		}
		if (ret)
			goto fallback;
	found_flex_bg:
		if (flex_size == 1) {
			*group = grp;
			return 0;
		}

		/*
		 * We pack inodes at the beginning of the flexgroup's
		 * inode tables.  Block allocation decisions will do
		 * something similar, although regular files will
		 * start at 2nd block group of the flexgroup.  See
		 * ext4_ext_find_goal() and ext4_find_near().
		 */
		grp *= flex_size;
		for (i = 0; i < flex_size; i++) {
			if (grp+i >= real_ngroups)
				break;
			desc = ext4_get_group_desc(sb, grp+i, NULL);
			if (desc && ext4_free_inodes_count(sb, desc)) {
				*group = grp+i;
				return 0;
			}
		}
		goto fallback;
	}

	max_dirs = ndirs / ngroups + inodes_per_group / 16;
	min_inodes = avefreei - inodes_per_group*flex_size / 4;
	if (min_inodes < 1)
		min_inodes = 1;
	min_clusters = avefreec - EXT4_CLUSTERS_PER_GROUP(sb)*flex_size / 4;

	/*
	 * Start looking in the flex group where we last allocated an
	 * inode for this parent directory
	 */
	if (EXT4_I(parent)->i_last_alloc_group != ~0) {
		parent_group = EXT4_I(parent)->i_last_alloc_group;
		if (flex_size > 1)
			parent_group >>= sbi->s_log_groups_per_flex;
	}

	for (i = 0; i < ngroups; i++) {
		grp = (parent_group + i) % ngroups;
		get_orlov_stats(sb, grp, flex_size, &stats);
		if (stats.used_dirs >= max_dirs)
			continue;
		if (stats.free_inodes < min_inodes)
			continue;
		if (stats.free_clusters < min_clusters)
			continue;
		goto found_flex_bg;
	}

fallback:
	ngroups = real_ngroups;
	avefreei = freei / ngroups;
fallback_retry:
	parent_group = EXT4_I(parent)->i_block_group;
	for (i = 0; i < ngroups; i++) {
		grp = (parent_group + i) % ngroups;
		desc = ext4_get_group_desc(sb, grp, NULL);
		if (desc) {
			grp_free = ext4_free_inodes_count(sb, desc);
			if (grp_free && grp_free >= avefreei) {
				*group = grp;
				return 0;
			}
		}
	}

	if (avefreei) {
		/*
		 * The free-inodes counter is approximate, and for really small
		 * filesystems the above test can fail to find any blockgroups
		 */
		avefreei = 0;
		goto fallback_retry;
	}

	return -1;
}
```

### 2.3 find_group_other
```c
static int find_group_other(struct super_block *sb, struct inode *parent,
			    ext4_group_t *group, umode_t mode)
{
	// 父目录所在组
	ext4_group_t parent_group = EXT4_I(parent)->i_block_group;
	// ngroups：组数
	ext4_group_t i, last, ngroups = ext4_get_groups_count(sb);
	struct ext4_group_desc *desc;
	int flex_size = ext4_flex_bg_size(EXT4_SB(sb));

	/*
	 * Try to place the inode is the same flex group as its
	 * parent.  If we can't find space, use the Orlov algorithm to
	 * find another flex group, and store that information in the
	 * parent directory's inode information so that use that flex
	 * group for future allocations.
	 */
	// 如果有flex_group特性
	if (flex_size > 1) {
		int retry = 0;

	try_again:
		parent_group &= ~(flex_size-1);
		last = parent_group + flex_size;
		if (last > ngroups)
			last = ngroups;
		
		// 找一个有空闲的组
		for  (i = parent_group; i < last; i++) {
			desc = ext4_get_group_desc(sb, i, NULL);
			if (desc && ext4_free_inodes_count(sb, desc)) {
				*group = i;
				return 0;
			}
		}

		// 如果没找到，从上次分配过的再找？
		if (!retry && EXT4_I(parent)->i_last_alloc_group != ~0) {
			retry = 1;
			parent_group = EXT4_I(parent)->i_last_alloc_group;
			goto try_again;
		}
		// 如果还是没找到，则使用orlov算法查找
		*group = parent_group + flex_size;
		if (*group > ngroups)
			*group = 0;
		return find_group_orlov(sb, parent, group, mode, NULL);
	}

	// 尽量放到父目录的组
	*group = parent_group;
	desc = ext4_get_group_desc(sb, *group, NULL);
	// 如果父目录所在的组还有空闲inode和空闲块，则直接用这个组
	if (desc && ext4_free_inodes_count(sb, desc) &&
	    ext4_free_group_clusters(sb, desc))
		return 0;

	/*
	 * We're going to place this inode in a different blockgroup from its
	 * parent.  We want to cause files in a common directory to all land in
	 * the same blockgroup.  But we want files which are in a different
	 * directory which shares a blockgroup with our parent to land in a
	 * different blockgroup.
	 *
	 * So add our directory's i_ino into the starting point for the hash.
	 */
	// 加上ino进行哈希，来选一个新组.
	// todo: 为啥加上ino没看懂
	*group = (*group + parent->i_ino) % ngroups;

	// 进行二次哈希，找一个有空闲的块
	// todo: 为啥i每次要增大2倍
	for (i = 1; i < ngroups; i <<= 1) {
		*group += i;
		// 如果达到最大值，则从头开始
		if (*group >= ngroups)
			*group -= ngroups;
		desc = ext4_get_group_desc(sb, *group, NULL);
		if (desc && ext4_free_inodes_count(sb, desc) &&
		    ext4_free_group_clusters(sb, desc))
			return 0;
	}

	// 上面还是失败，则从父目录所在块开始，遍历所有的块
	*group = parent_group;
	for (i = 0; i < ngroups; i++) {
		// 如果到了最大值，则从头开始
		if (++*group >= ngroups)
			*group = 0;
		desc = ext4_get_group_desc(sb, *group, NULL);
		// 这次只判断有空闲inode就行
		if (desc && ext4_free_inodes_count(sb, desc))
			return 0;
	}

	return -1;
}
```

## 3. ext4_add_nondir
```c
static int ext4_add_nondir(handle_t *handle,
		struct dentry *dentry, struct inode **inodep)
{
	// 父目录
	struct inode *dir = d_inode(dentry->d_parent);
	struct inode *inode = *inodep;
	// 添加到dentry
	int err = ext4_add_entry(handle, dentry, inode);

	// 添加成功
	if (!err) {
		// 标记inode为脏
		err = ext4_mark_inode_dirty(handle, inode);
		// 如果目录需要同步，则同步之
		if (IS_DIRSYNC(dir))
			ext4_handle_sync(handle);
		// 把dentry和inode关联起来
		d_instantiate_new(dentry, inode);
		*inodep = NULL;
		return err;
	}

	// 走到这儿表示出错了，要释放资源

	drop_nlink(inode);
	ext4_orphan_add(handle, inode);
	unlock_new_inode(inode);
	return err;
}
```

## 4. ext4_add_entry
```c
static int ext4_add_entry(handle_t *handle, struct dentry *dentry,
			  struct inode *inode)
{
	// 父目录
	struct inode *dir = d_inode(dentry->d_parent);
	struct buffer_head *bh = NULL;
	struct ext4_dir_entry_2 *de;
	struct super_block *sb;
	struct ext4_filename fname;
	int	retval;
	int	dx_fallback=0;
	unsigned blocksize;
	ext4_lblk_t block, blocks;
	int	csum_size = 0;

	// 校验和大小
	if (ext4_has_metadata_csum(inode->i_sb))
		csum_size = sizeof(struct ext4_dir_entry_tail);

	sb = dir->i_sb;
	blocksize = sb->s_blocksize;
	// 文件名不能为空
	if (!dentry->d_name.len)
		return -EINVAL;

	// 加密相关
	if (fscrypt_is_nokey_name(dentry))
		return -ENOKEY;

	// unicode相关
#ifdef CONFIG_UNICODE
	if (sb_has_strict_encoding(sb) && IS_CASEFOLDED(dir) &&
	    sb->s_encoding && utf8_validate(sb->s_encoding, &dentry->d_name))
		return -EINVAL;
#endif

	// 把文件名相关的内容设置到fname里
	retval = ext4_fname_setup_filename(dir, &dentry->d_name, 0, &fname);
	if (retval)
		return retval;

	// 有内联数据, 则先尝试加到内联数据里，todo: 内联数据后面再看
	if (ext4_has_inline_data(dir)) {
		retval = ext4_try_add_inline_entry(handle, &fname, dir, inode);
		if (retval < 0)
			goto out;
		if (retval == 1) {
			retval = 0;
			goto out;
		}
	}

	// 如果当前目录是dir_index
	if (is_dx(dir)) {
		// 添加目录
		retval = ext4_dx_add_entry(handle, &fname, dir, inode);
		if (!retval || (retval != ERR_BAD_DX_DIR))
			goto out;
		
		// 走到这儿表示哈希树有问题

		// 如果有校验和就错了
		if (ext4_has_metadata_csum(sb)) {
			EXT4_ERROR_INODE(dir,
				"Directory has corrupted htree index.");
			retval = -EFSCORRUPTED;
			goto out;
		}
		// 清除inode的index标志
		ext4_clear_inode_flag(dir, EXT4_INODE_INDEX);
		// dx需要回退
		dx_fallback++;
		// 父目录inode标脏
		retval = ext4_mark_inode_dirty(handle, dir);
		if (unlikely(retval))
			goto out;
	}
	// 目录当前块数
	blocks = dir->i_size >> sb->s_blocksize_bits;
	for (block = 0; block < blocks; block++) {
		// 读取目录数据块, 这个函数在读块时,还会对块的校验和进行校验
		bh = ext4_read_dirblock(dir, block, DIRENT);

		// 如果块为空，分配一个块。todo: bh为什么会为NULL?
		if (bh == NULL) {
			bh = ext4_bread(handle, dir, block,
					EXT4_GET_BLOCKS_CREATE);
			goto add_to_new_block;
		}
		if (IS_ERR(bh)) {
			retval = PTR_ERR(bh);
			bh = NULL;
			goto out;
		}
		// 添加到数据块里
		retval = add_dirent_to_buf(handle, &fname, dir, inode,
					   NULL, bh);
		// 除了没空间之外，不管是错误还是成功都直接返回
		if (retval != -ENOSPC)
			goto out;

		// 走到这儿说明没空间了,
		// 没空间且只有一个块时, 如果dx没有回退且dir_index打开,转换成dir_index，这个if应该放到循环外面
		if (blocks == 1 && !dx_fallback &&
		    ext4_has_feature_dir_index(sb)) {
			retval = make_indexed_dir(handle, &fname, dir,
						  inode, bh);
			bh = NULL; /* make_indexed_dir releases bh */
			goto out;
		}
		brelse(bh);
	}
	// 走到这儿表示当前目录的数据块都没空间, 非dix_index的流程

	// 添加一个新块
	bh = ext4_append(handle, dir, &block);
add_to_new_block:
	if (IS_ERR(bh)) {
		retval = PTR_ERR(bh);
		bh = NULL;
		goto out;
	}

	de = (struct ext4_dir_entry_2 *) bh->b_data;
	// 新块inode数为0
	de->inode = 0;
	// 因为是新块,所以rec_len是整个块的长度(不包括校验和)
	de->rec_len = ext4_rec_len_to_disk(blocksize - csum_size, blocksize);

	// 如果开启校验和的话, 则初始化校验和
	if (csum_size)
		ext4_initialize_dirent_tail(bh, blocksize);

	// 添加到数据块里
	retval = add_dirent_to_buf(handle, &fname, dir, inode, de, bh);
out:
	ext4_fname_free_filename(&fname);
	brelse(bh);
	// 添加成功，修改inode状态
	if (retval == 0)
		ext4_set_inode_state(inode, EXT4_STATE_NEWENTRY);
	return retval;
}
```
主流程：  
1. 尝试内联存储  
2. 如果是dir_index，则添加，如果添加失败，则需要回退到普通存储  
3. 普通存储：先在现在数据块里存储  
4. 第3步如果失败，则判断当前是否只有一个数据块，如果是，且没有dir_index回退，则把普通存储转换成dir_index  
5. 如果普通存储失败且是没空闲，则分配一个新块来存储


## 把entry添加到数据块里
```c
static int add_dirent_to_buf(handle_t *handle, struct ext4_filename *fname,
			     struct inode *dir,
			     struct inode *inode, struct ext4_dir_entry_2 *de,
			     struct buffer_head *bh)
{
	unsigned int	blocksize = dir->i_sb->s_blocksize;
	int		csum_size = 0;
	int		err, err2;

	// 有元数据校验和
	if (ext4_has_metadata_csum(inode->i_sb))
		csum_size = sizeof(struct ext4_dir_entry_tail);

	// de为空, 找目标de
	if (!de) {
		err = ext4_find_dest_de(dir, inode, bh, bh->b_data,
					blocksize - csum_size, fname, &de);
		if (err)
			return err;
	}
	BUFFER_TRACE(bh, "get_write_access");
	// 获取写权限
	err = ext4_journal_get_write_access(handle, bh);
	if (err) {
		ext4_std_error(dir->i_sb, err);
		return err;
	}

	// 插入dentry到de的位置
	ext4_insert_dentry(inode, de, blocksize, fname);

	// 先更新时间
	dir->i_mtime = dir->i_ctime = current_time(dir);
	// 如果没有dir_index特性, 则清除父目录EXT4_INODE_INDEX标志，
	// todo: 为什么每次添加entry都要执行这个操作
	ext4_update_dx_flag(dir);
	// 更新版本号 todo: what
	inode_inc_iversion(dir);
	// 父目录标脏
	err2 = ext4_mark_inode_dirty(handle, dir);
	BUFFER_TRACE(bh, "call ext4_handle_dirty_metadata");
	// bh标脏
	err = ext4_handle_dirty_dirblock(handle, dir, bh);
	if (err)
		ext4_std_error(dir->i_sb, err);
	return err ? err : err2;
}

int ext4_find_dest_de(struct inode *dir, struct inode *inode,
		      struct buffer_head *bh,
		      void *buf, int buf_size,
		      struct ext4_filename *fname,
		      struct ext4_dir_entry_2 **dest_de)
{
	struct ext4_dir_entry_2 *de;
	// 文件名对应的entry长度
	unsigned short reclen = EXT4_DIR_REC_LEN(fname_len(fname));
	int nlen, rlen;
	unsigned int offset = 0;
	char *top;

	// 头entry
	de = (struct ext4_dir_entry_2 *)buf;

	// 末尾
	top = buf + buf_size - reclen;
	while ((char *) de <= top) {
		// 检查de是否合法
		if (ext4_check_dir_entry(dir, NULL, de, bh,
					 buf, buf_size, offset))
			return -EFSCORRUPTED;
		// 该文件已存在
		if (ext4_match(dir, fname, de))
			return -EEXIST;
		// de结构长度
		nlen = EXT4_DIR_REC_LEN(de->name_len);
		// 剩余空间长度
		rlen = ext4_rec_len_from_disk(de->rec_len, buf_size);
		// 如果inode为空,表示这个entry被删了, 如果文件被删了, de的rlen可以全部使用
		// 如果inode不为空, (rlen - nlen)就表示这个de还剩的空间, 如果还能放下新entry, 则存之.
		if ((de->inode ? rlen - nlen : rlen) >= reclen)
			// 进到这里表示能存下，直接退出
			break;
		// 下一个结点
		de = (struct ext4_dir_entry_2 *)((char *)de + rlen);
		offset += rlen;
	}
	// de最多就等于top, 大于top肯定就错了，说明没空间了
	if ((char *) de > top)
		return -ENOSPC;
	// 目标位置
	*dest_de = de;
	return 0;
}

void ext4_insert_dentry(struct inode *inode,
			struct ext4_dir_entry_2 *de,
			int buf_size,
			struct ext4_filename *fname)
{

	int nlen, rlen;

	// de已使用长度
	nlen = EXT4_DIR_REC_LEN(de->name_len);
	// de总共的长度
	rlen = ext4_rec_len_from_disk(de->rec_len, buf_size);

	// 如果de现在有文件，则在当前de后面存
	if (de->inode) {
		// 原来de的长度是nlen, 前进nlen个长度就是下一个entry
		struct ext4_dir_entry_2 *de1 =
			(struct ext4_dir_entry_2 *)((char *)de + nlen);
		// 新de1的盘上空间为原来de,剩余的空闲
		de1->rec_len = ext4_rec_len_to_disk(rlen - nlen, buf_size);
		// 修改原de的rec_len空间
		de->rec_len = ext4_rec_len_to_disk(nlen, buf_size);
		// 使用de1存放
		de = de1;
	}
	// 类型暂设为未知
	de->file_type = EXT4_FT_UNKNOWN;
	// 设置inode号
	de->inode = cpu_to_le32(inode->i_ino);
	// 根据mode设置文件类型，这里面设置的就是file_type
	ext4_set_de_type(inode->i_sb, de, inode->i_mode);
	// 文件名长度
	de->name_len = fname_len(fname);
	// 把文件名复制到de->name里
	memcpy(de->name, fname_name(fname), fname_len(fname));
}

static inline void ext4_update_dx_flag(struct inode *inode)
{
	// 如果没有index特性, 但是有EXT4_INODE_INDEX标志
	if (!ext4_has_feature_dir_index(inode->i_sb) &&
	    ext4_test_inode_flag(inode, EXT4_INODE_INDEX)) {
		// 有dir_index就必须要有元数据校验和吗?
		WARN_ON_ONCE(ext4_has_feature_metadata_csum(inode->i_sb));
		// 清除标志
		ext4_clear_inode_flag(inode, EXT4_INODE_INDEX);
	}
}

int ext4_handle_dirty_dirblock(handle_t *handle,
			       struct inode *inode,
			       struct buffer_head *bh)
{
	// 给dir_block设置校验值
	ext4_dirblock_csum_set(inode, bh);
	// 日志相关, 标脏元数据
	return ext4_handle_dirty_metadata(handle, inode, bh);
}
```

```c
static struct buffer_head *ext4_append(handle_t *handle,
					struct inode *inode,
					ext4_lblk_t *block)
{
	struct buffer_head *bh;
	int err;

	// 超过最大的目录大小
	if (unlikely(EXT4_SB(inode->i_sb)->s_max_dir_size_kb &&
		     ((inode->i_size >> 10) >=
		      EXT4_SB(inode->i_sb)->s_max_dir_size_kb)))
		return ERR_PTR(-ENOSPC);

	// 文件大小转换成块号, 因为块是从0开始的,所以这个刚好是新块的块号
	*block = inode->i_size >> inode->i_sb->s_blocksize_bits;

	// 读块,如果块不存在,则分配新块
	bh = ext4_bread(handle, inode, *block, EXT4_GET_BLOCKS_CREATE);
	if (IS_ERR(bh))
		return bh;
	// 目录大小加一个块的大小
	inode->i_size += inode->i_sb->s_blocksize;
	// 设置盘上大小
	EXT4_I(inode)->i_disksize = inode->i_size;
	BUFFER_TRACE(bh, "get_write_access");
	// 获取bh的写权限
	err = ext4_journal_get_write_access(handle, bh);
	if (err) {
		brelse(bh);
		ext4_std_error(inode->i_sb, err);
		return ERR_PTR(err);
	}
	return bh;
}

void ext4_initialize_dirent_tail(struct buffer_head *bh,
				 unsigned int blocksize)
{
	// 找到末尾的校验和空间
	struct ext4_dir_entry_tail *t = EXT4_DIRENT_TAIL(bh->b_data, blocksize);

	// 清0
	memset(t, 0, sizeof(struct ext4_dir_entry_tail));
	// 设置rec长度
	t->det_rec_len = ext4_rec_len_to_disk(
			sizeof(struct ext4_dir_entry_tail), blocksize);
	// 保留类型是校验和
	t->det_reserved_ft = EXT4_FT_DIR_CSUM;
}
```