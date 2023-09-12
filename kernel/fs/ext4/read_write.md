# 读文件
源码基于5.10

## 1. ext4_file_read_iter
```c
static ssize_t ext4_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = file_inode(iocb->ki_filp);

	// 文件系统已经关闭
	if (unlikely(ext4_forced_shutdown(EXT4_SB(inode->i_sb))))
		return -EIO;

	// 读的数量为0
	if (!iov_iter_count(to))
		return 0; /* skip atime */

#ifdef CONFIG_FS_DAX
	// todo: dax 后面看
	if (IS_DAX(inode))
		return ext4_dax_read_iter(iocb, to);
#endif
	// 直接读。todo: 后面看
	if (iocb->ki_flags & IOCB_DIRECT)
		return ext4_dio_read_iter(iocb, to);

	// 大部都是buffer read，这个直接调用vfs的读方法
	return generic_file_read_iter(iocb, to);
}
```
## 2. ext4_file_write_iter
```c
static ssize_t
ext4_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct inode *inode = file_inode(iocb->ki_filp);

	// 文件系统已经关闭
	if (unlikely(ext4_forced_shutdown(EXT4_SB(inode->i_sb))))
		return -EIO;

	// 这里为什么不像读一样，判断写的数量为0？？

#ifdef CONFIG_FS_DAX
	if (IS_DAX(inode))
		return ext4_dax_write_iter(iocb, from);
#endif
	if (iocb->ki_flags & IOCB_DIRECT)
		// 直接读
		return ext4_dio_write_iter(iocb, from);
	else
		// buffer write
		return ext4_buffered_write_iter(iocb, from);
}

static ssize_t ext4_buffered_write_iter(struct kiocb *iocb,
					struct iov_iter *from)
{
	ssize_t ret;
	struct inode *inode = file_inode(iocb->ki_filp);

	// 不支持不等待
	if (iocb->ki_flags & IOCB_NOWAIT)
		return -EOPNOTSUPP;

	// todo: fast commit后面看
	ext4_fc_start_update(inode);
	inode_lock(inode);

	// 检查和确定写入起点、数量，更新时间等，若出错，返回负数
	ret = ext4_write_checks(iocb, from);
	if (ret <= 0)
		goto out;

	current->backing_dev_info = inode_to_bdi(inode);
	// 调用vfs的写函数
	ret = generic_perform_write(iocb->ki_filp, from, iocb->ki_pos);
	current->backing_dev_info = NULL;

out:
	inode_unlock(inode);
	ext4_fc_stop_update(inode);
	// ret > 0，说明有写入的数据
	if (likely(ret > 0)) {
		iocb->ki_pos += ret;
		// 同步
		ret = generic_write_sync(iocb, ret);
	}

	return ret;
}
```

### 2.1 ext4_write_checks
```c
static ssize_t ext4_write_checks(struct kiocb *iocb, struct iov_iter *from)
{
	ssize_t ret, count;

	// 主要确认写入数量及写入起点
	count = ext4_generic_write_checks(iocb, from);
	if (count <= 0)
		return count;

	// 移除文件特权，更新时间等
	ret = file_modified(iocb->ki_filp);
	if (ret)
		return ret;
	return count;
}

static ssize_t ext4_generic_write_checks(struct kiocb *iocb,
					 struct iov_iter *from)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	ssize_t ret;

	// 是不可修改的
	if (unlikely(IS_IMMUTABLE(inode)))
		return -EPERM;

	// 调用vfs的检查，这个检查返回值是要写入的数量及写入的起点
	ret = generic_write_checks(iocb, from);
	if (ret <= 0)
		return ret;

	// 没有extents特性
	if (!(ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS))) {
		struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);

		// 起点大于位图限制的最大值
		if (iocb->ki_pos >= sbi->s_bitmap_maxbytes)
			return -EFBIG;
		// 对最终写入数量限制到最大值
		iov_iter_truncate(from, sbi->s_bitmap_maxbytes - iocb->ki_pos);
	}

	// 如果有extent特性，则位图的数量是不限制的？

	// 返回最终的写入数量
	return iov_iter_count(from);
}

ssize_t generic_write_checks(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	loff_t count;
	int ret;

	// 不能写交换文件
	if (IS_SWAPFILE(inode))
		return -ETXTBSY;

	// 写的数量是0
	if (!iov_iter_count(from))
		return 0;

	// 如果是追加，写入的起点为文件末尾
	if (iocb->ki_flags & IOCB_APPEND)
		iocb->ki_pos = i_size_read(inode);

	// 不等待io只能用来，direct-io
	if ((iocb->ki_flags & IOCB_NOWAIT) && !(iocb->ki_flags & IOCB_DIRECT))
		return -EINVAL;

	// 要写入的数量
	count = iov_iter_count(from);

	// 检查要写入的限制值，大小会随count返回
	ret = generic_write_check_limits(file, iocb->ki_pos, &count);
	if (ret)
		return ret;

	// 设置from->count = count;
	iov_iter_truncate(from, count);
	// 返回from->count
	return iov_iter_count(from);
}

int generic_write_check_limits(struct file *file, loff_t pos, loff_t *count)
{
	struct inode *inode = file->f_mapping->host;
	loff_t max_size = inode->i_sb->s_maxbytes;
	// 进程对文件大小的限制
	loff_t limit = rlimit(RLIMIT_FSIZE);

	// RLIM_INFINITY表示不限制，如果不是不限制
	if (limit != RLIM_INFINITY) {
		// 如果起点超过了限制值，则发送错误信号
		if (pos >= limit) {
			send_sig(SIGXFSZ, current, 0);
			return -EFBIG;
		}
		// 取与限制的较小值
		*count = min(*count, limit - pos);
	}

	// 如果没有大文件标志，则最大size是MAX_NON_LFS((1UL<<31) - 1)
	if (!(file->f_flags & O_LARGEFILE))
		max_size = MAX_NON_LFS;

	// 超过了最大值
	if (unlikely(pos >= max_size))
		return -EFBIG;

	// 和最大值再取较小值
	*count = min(*count, max_size - pos);

	return 0;
}

int file_modified(struct file *file)
{
	int err;

	// 移除特权
	err = file_remove_privs(file);
	if (err)
		return err;

	// 如果文件没有记录时间，则跳过
	if (unlikely(file->f_mode & FMODE_NOCMTIME))
		return 0;

	// 更新时间
	return file_update_time(file);
}

int file_remove_privs(struct file *file)
{
	struct dentry *dentry = file_dentry(file);
	struct inode *inode = file_inode(file);
	int kill;
	int error = 0;

	// 没有安全 || 不是普通文件
	if (IS_NOSEC(inode) || !S_ISREG(inode->i_mode))
		return 0;

	// 计算要清除的标志
	kill = dentry_needs_remove_privs(dentry);
	if (kill < 0)
		return kill;
	
	// 清除特权
	if (kill)
		error = __remove_privs(dentry, kill);
	// 如果没错误，则设置 S_NOSEC 标志
	if (!error)
		inode_has_no_xattr(inode);

	return error;
}


int dentry_needs_remove_privs(struct dentry *dentry)
{
	struct inode *inode = d_inode(dentry);
	int mask = 0;
	int ret;

	// 没有安全标志
	if (IS_NOSEC(inode))
		return 0;

	// 返回需要清除的id
	mask = should_remove_suid(dentry);
	// 调用安全hook
	ret = security_inode_need_killpriv(dentry);
	if (ret < 0)
		return ret;
	// 清除特权
	if (ret)
		mask |= ATTR_KILL_PRIV;
	return mask;
}

int should_remove_suid(struct dentry *dentry)
{
	umode_t mode = d_inode(dentry)->i_mode;
	int kill = 0;

	// 清除suid
	if (unlikely(mode & S_ISUID))
		kill = ATTR_KILL_SUID;

	/*
	 * sgid如果有没执行标记，则只是一个强制锁标志。这2个标志同时有，才是真正的sgid，
	 */
	if (unlikely((mode & S_ISGID) && (mode & S_IXGRP)))
		kill |= ATTR_KILL_SGID;

	// kill && 无设置id的权限 && 普通文件，则返回kill。
	// 也就是如果用户有setid的权限，则不清除这些权限？
	if (unlikely(kill && !capable(CAP_FSETID) && S_ISREG(mode)))
		return kill;

	return 0;
}

static int __remove_privs(struct dentry *dentry, int kill)
{
	struct iattr newattrs;

	// 设置要清除的特权
	newattrs.ia_valid = ATTR_FORCE | kill;
	// 设置文件属性，并发出通知
	return notify_change(dentry, &newattrs, NULL);
}

int notify_change(struct dentry * dentry, struct iattr * attr, struct inode **delegated_inode)
{
	struct inode *inode = dentry->d_inode;
	umode_t mode = inode->i_mode;
	int error;
	struct timespec64 now;
	unsigned int ia_valid = attr->ia_valid;

	// inode没锁
	WARN_ON_ONCE(!inode_is_locked(inode));

	// 这些标记不能在不可修改的文件和追加模式下修改
	if (ia_valid & (ATTR_MODE | ATTR_UID | ATTR_GID | ATTR_TIMES_SET)) {
		if (IS_IMMUTABLE(inode) || IS_APPEND(inode))
			return -EPERM;
	}

	/*
	 * If utimes(2) and friends are called with times == NULL (or both
	 * times are UTIME_NOW), then we need to check for write permission
	 */
	if (ia_valid & ATTR_TOUCH) {
		if (IS_IMMUTABLE(inode))
			return -EPERM;

		if (!inode_owner_or_capable(inode)) {
			error = inode_permission(inode, MAY_WRITE);
			if (error)
				return error;
		}
	}

	if ((ia_valid & ATTR_MODE)) {
		umode_t amode = attr->ia_mode;
		/* Flag setting protected by i_mutex */
		if (is_sxid(amode))
			inode->i_flags &= ~S_NOSEC;
	}

	now = current_time(inode);

	attr->ia_ctime = now;
	if (!(ia_valid & ATTR_ATIME_SET))
		attr->ia_atime = now;
	else
		attr->ia_atime = timestamp_truncate(attr->ia_atime, inode);
	if (!(ia_valid & ATTR_MTIME_SET))
		attr->ia_mtime = now;
	else
		attr->ia_mtime = timestamp_truncate(attr->ia_mtime, inode);

	if (ia_valid & ATTR_KILL_PRIV) {
		// 调用一遍hook，这个在上面不是调过了吗？
		error = security_inode_need_killpriv(dentry);
		if (error < 0)
			return error;
		// 清除杀死特权的标志
		if (error == 0)
			ia_valid = attr->ia_valid &= ~ATTR_KILL_PRIV;
	}

	// mode和kill*不能同时设置
	if ((ia_valid & (ATTR_KILL_SUID|ATTR_KILL_SGID)) &&
	    (ia_valid & ATTR_MODE))
		BUG();

	// 清除suid标志
	if (ia_valid & ATTR_KILL_SUID) {
		if (mode & S_ISUID) {
			ia_valid = attr->ia_valid |= ATTR_MODE;
			attr->ia_mode = (inode->i_mode & ~S_ISUID);
		}
	}
	// 清除sgid
	if (ia_valid & ATTR_KILL_SGID) {
		if ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP)) {
			if (!(ia_valid & ATTR_MODE)) {
				ia_valid = attr->ia_valid |= ATTR_MODE;
				attr->ia_mode = inode->i_mode;
			}
			attr->ia_mode &= ~S_ISGID;
		}
	}
	if (!(attr->ia_valid & ~(ATTR_KILL_SUID | ATTR_KILL_SGID)))
		return 0;

	/*
	 * Verify that uid/gid changes are valid in the target
	 * namespace of the superblock.
	 */
	if (ia_valid & ATTR_UID &&
	    !kuid_has_mapping(inode->i_sb->s_user_ns, attr->ia_uid))
		return -EOVERFLOW;
	if (ia_valid & ATTR_GID &&
	    !kgid_has_mapping(inode->i_sb->s_user_ns, attr->ia_gid))
		return -EOVERFLOW;

	/* Don't allow modifications of files with invalid uids or
	 * gids unless those uids & gids are being made valid.
	 */
	if (!(ia_valid & ATTR_UID) && !uid_valid(inode->i_uid))
		return -EOVERFLOW;
	if (!(ia_valid & ATTR_GID) && !gid_valid(inode->i_gid))
		return -EOVERFLOW;

	error = security_inode_setattr(dentry, attr);
	if (error)
		return error;
	error = try_break_deleg(inode, delegated_inode);
	if (error)
		return error;

	// 调用设置属性的函数
	if (inode->i_op->setattr)
		error = inode->i_op->setattr(dentry, attr);
	else
		// 通用设置属性的方法
		error = simple_setattr(dentry, attr);

	// 如果没错误，则发送通知
	if (!error) {
		fsnotify_change(dentry, ia_valid);
		ima_inode_post_setattr(dentry);
		evm_inode_post_setattr(dentry, ia_valid);
	}

	return error;
}

int file_update_time(struct file *file)
{
	struct inode *inode = file_inode(file);
	struct timespec64 now;
	int sync_it = 0;
	int ret;

	// 不用记录时间
	if (IS_NOCMTIME(inode))
		return 0;

	// 当前时间
	now = current_time(inode);

	// mtime是否相同
	if (!timespec64_equal(&inode->i_mtime, &now))
		sync_it = S_MTIME;

	// ctime是否相同
	if (!timespec64_equal(&inode->i_ctime, &now))
		sync_it |= S_CTIME;

	// 如果是版本inode，则递增版本号
	if (IS_I_VERSION(inode) && inode_iversion_need_inc(inode))
		sync_it |= S_VERSION;

	// 不需要同步
	if (!sync_it)
		return 0;

	// 获取fs级的写权限
	if (__mnt_want_write_file(file))
		return 0;

	// 更新时间
	ret = inode_update_time(inode, &now, sync_it);
	// 放弃权限
	__mnt_drop_write_file(file);

	return ret;
}
```

### 2.2 generic_write_sync
```c
static inline ssize_t generic_write_sync(struct kiocb *iocb, ssize_t count)
{
	// 如果是以同步打开的，才进行同步数据
	if (iocb->ki_flags & IOCB_DSYNC) {
		// 同步写入的数据范围
		int ret = vfs_fsync_range(iocb->ki_filp,
				iocb->ki_pos - count, iocb->ki_pos - 1,
				// 最后一个参数表示是否只同步元数据
				(iocb->ki_flags & IOCB_SYNC) ? 0 : 1);
		if (ret)
			return ret;
	}

	return count;
}

int vfs_fsync_range(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct inode *inode = file->f_mapping->host;

	// 文件没有同步函数，出错
	if (!file->f_op->fsync)
		return -EINVAL;
	// 不是数据同步，只是时间脏了，则把inode标脏
	if (!datasync && (inode->i_state & I_DIRTY_TIME))
		mark_inode_dirty_sync(inode);
	// 调用具体文件系统的同步
	return file->f_op->fsync(file, start, end, datasync);
}
```


generic_perform_write写文件时，按如下步骤：  
1. call a_ops->write_begin  
2. copy data from user's iocb to page-cache  
3. call a_ops->write_end  


## 3. write_begin
```c
static int ext4_write_begin(struct file *file, struct address_space *mapping,
			    loff_t pos, unsigned len, unsigned flags,
			    struct page **pagep, void **fsdata)
{
	struct inode *inode = mapping->host;
	int ret, needed_blocks;
	handle_t *handle;
	int retries = 0;
	struct page *page;
	pgoff_t index;
	unsigned from, to;

	// 文件系统已死机
	if (unlikely(ext4_forced_shutdown(EXT4_SB(inode->i_sb))))
		return -EIO;

	// trace一下
	trace_ext4_write_begin(inode, pos, len, flags);
	
	// 算出需要的block? todo: 没太看懂
	needed_blocks = ext4_writepage_trans_blocks(inode) + 1;

	// 要写入的页号
	index = pos >> PAGE_SHIFT;
	// 写入的偏移
	from = pos & (PAGE_SIZE - 1);
	// 写入的结尾
	to = from + len;

	// 如果inode有EXT4_STATE_MAY_INLINE_DATA标志，则写入内部数据？
	// todo: 后面再看
	if (ext4_test_inode_state(inode, EXT4_STATE_MAY_INLINE_DATA)) {
		ret = ext4_try_to_write_inline_data(mapping, inode, pos, len,
						    flags, pagep);
		if (ret < 0)
			return ret;
		if (ret == 1)
			return 0;
	}

retry_grab:
	// 先获取或者分配一个页面
	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		return -ENOMEM;
	unlock_page(page);

retry_journal:
	// 开始日志
	handle = ext4_journal_start(inode, EXT4_HT_WRITE_PAGE, needed_blocks);
	if (IS_ERR(handle)) {
		put_page(page);
		return PTR_ERR(handle);
	}

	lock_page(page);
	// 页面的mapping不一样了，说明被别人占用了，则重新分配一个
	if (page->mapping != mapping) {
		/* The page got truncated from under us */
		unlock_page(page);
		put_page(page);
		ext4_journal_stop(handle);
		goto retry_grab;
	}
	// 如果页面正在回写，要等回写结束
	wait_for_stable_page(page);

	// 准备块.
#ifdef CONFIG_FS_ENCRYPTION
	if (ext4_should_dioread_nolock(inode))
		ret = ext4_block_write_begin(page, pos, len,
					     ext4_get_block_unwritten);
	else
		ret = ext4_block_write_begin(page, pos, len,
					     ext4_get_block);
#else
	if (ext4_should_dioread_nolock(inode))
		//__block_write_begin 是vfs，最终会使用 ext4_get_block 与bh建立映射
		ret = __block_write_begin(page, pos, len,
					  ext4_get_block_unwritten);
	else
		ret = __block_write_begin(page, pos, len, ext4_get_block);
#endif
	// 获取块成功，则对每个page获取日志写权限
	if (!ret && ext4_should_journal_data(inode)) {
		ret = ext4_walk_page_buffers(handle, page_buffers(page),
					     from, to, NULL,
					     do_journal_get_write_access);
	}

	if (ret) {
		// 写入的位置是否大于文件长度
		bool extended = (pos + len > inode->i_size) &&
				!ext4_verity_in_progress(inode);

		unlock_page(page);
		/*
		 * __block_write_begin may have instantiated a few blocks
		 * outside i_size.  Trim these off again. Don't need
		 * i_size_read because we hold i_mutex.
		 *
		 * Add inode to orphan list in case we crash before
		 * truncate finishes
		 */
		// 如果需要扩展 && 可以截断，先加到孤儿列表？
		if (extended && ext4_can_truncate(inode))
			ext4_orphan_add(handle, inode);

		// 停止日志
		ext4_journal_stop(handle);
		// 再从孤儿列表里删了
		if (extended) {
			ext4_truncate_failed_write(inode);
			/*
			 * If truncate failed early the inode might
			 * still be on the orphan list; we need to
			 * make sure the inode is removed from the
			 * orphan list in that case.
			 */
			if (inode->i_nlink)
				ext4_orphan_del(NULL, inode);
		}

		// 如果没有空闲了，则需要重新分配
		if (ret == -ENOSPC &&
		    ext4_should_retry_alloc(inode->i_sb, &retries))
			goto retry_journal;
		put_page(page);
		return ret;
	}
	*pagep = page;
	return ret;
}

static struct extent_status *__es_tree_search(struct rb_root *root,
					      ext4_lblk_t lblk)
{
	struct rb_node *node = root->rb_node;
	struct extent_status *es = NULL;

	while (node) {
		es = rb_entry(node, struct extent_status, rb_node);
		if (lblk < es->es_lblk)
			node = node->rb_left;
		else if (lblk > ext4_es_end(es))
			node = node->rb_right;
		else
			// 如果找到，返回es
			return es;
	}

	// todo: why ?
	if (es && lblk < es->es_lblk)
		return es;

	// lblk大于es的结束位置
	if (es && lblk > ext4_es_end(es)) {
		// 获取es的下一个结点
		node = rb_next(&es->rb_node);
		return node ? rb_entry(node, struct extent_status, rb_node) :
			      NULL;
	}

	return NULL;
}

static int __es_insert_extent(struct inode *inode, struct extent_status *newes)
{
	// 树根
	struct ext4_es_tree *tree = &EXT4_I(inode)->i_es_tree;
	struct rb_node **p = &tree->root.rb_node;
	struct rb_node *parent = NULL;
	struct extent_status *es;

	while (*p) {
		parent = *p;
		es = rb_entry(parent, struct extent_status, rb_node);

		// 左子树
		if (newes->es_lblk < es->es_lblk) {
			// 合并的条件：状态相同、newes在左边紧挨着es
			if (ext4_es_can_be_merged(newes, es)) {
				// 新起点
				es->es_lblk = newes->es_lblk;
				// 长度和
				es->es_len += newes->es_len;
				// 物理块数相加
				if (ext4_es_is_written(es) ||
				    ext4_es_is_unwritten(es))
					ext4_es_store_pblock(es,
							     newes->es_pblk);
				// 再尝试把es向左边合并
				es = ext4_es_try_to_merge_left(inode, es);
				goto out;
			}
			p = &(*p)->rb_left;
		
		// 右子树，新的逻辑块必须大于es
		} else if (newes->es_lblk > ext4_es_end(es)) {
			// 判断是否能向右合并
			if (ext4_es_can_be_merged(es, newes)) {
				// 右边只要递增长度即可
				es->es_len += newes->es_len;
				// 再尝试向最右边合并
				es = ext4_es_try_to_merge_right(inode, es);
				goto out;
			}
			p = &(*p)->rb_right;
		
		// 因为这里是插入，所以如果树里已存在，即有bug
		} else {
			BUG();
			return -EINVAL;
		}
	}

	// 走到这里说明不能合并

	// 新分配一个es
	es = ext4_es_alloc_extent(inode, newes->es_lblk, newes->es_len,
				  newes->es_pblk);
	if (!es)
		return -ENOMEM;
	// 链表p的位置
	rb_link_node(&es->rb_node, parent, p);
	// 着色
	rb_insert_color(&es->rb_node, &tree->root);

out:
	// 把当前es设置为cache
	tree->cache_es = es;
	return 0;
}
```

## 4. ext4_write_end
```c
static int ext4_write_end(struct file *file,
			  struct address_space *mapping,
			  loff_t pos, unsigned len, unsigned copied,
			  struct page *page, void *fsdata)
{
	handle_t *handle = ext4_journal_current_handle();
	struct inode *inode = mapping->host;
	loff_t old_size = inode->i_size;
	int ret = 0, ret2;
	int i_size_changed = 0;
	// 有无内联数据
	int inline_data = ext4_has_inline_data(inode);
	// 是否正在验证
	bool verity = ext4_verity_in_progress(inode);

	trace_ext4_write_end(inode, pos, len, copied);
	if (inline_data) {
		// todo: 内联数据后面再看
		ret = ext4_write_inline_data_end(inode, pos, len,
						 copied, page);
		if (ret < 0) {
			unlock_page(page);
			put_page(page);
			goto errout;
		}
		copied = ret;
		ret = 0;
	} else
		// 这里面主要把page, bh标脏, 之后定期的writeback就会回写
		copied = block_write_end(file, mapping, pos,
					 len, copied, page, fsdata);
	// 更新文件大小写
	if (!verity)
		i_size_changed = ext4_update_inode_size(inode, pos + copied);
	unlock_page(page);
	put_page(page);

	// size 大小变了之后，改变pagecache的相关页状态
	if (old_size < pos && !verity)
		pagecache_isize_extended(inode, old_size, pos);

	// inode标脏
	if (i_size_changed || inline_data)
		ret = ext4_mark_inode_dirty(handle, inode);

errout:
	// 先加到孤儿列表？
	if (pos + len > inode->i_size && !verity && ext4_can_truncate(inode))
		/* if we have allocated more blocks and copied
		 * less. We will have blocks allocated outside
		 * inode->i_size. So truncate them
		 */
		ext4_orphan_add(handle, inode);

	// 日志完了
	ret2 = ext4_journal_stop(handle);
	if (!ret)
		ret = ret2;

	// todo: what?
	if (pos + len > inode->i_size && !verity) {
		ext4_truncate_failed_write(inode);
		/*
		 * If truncate failed early the inode might still be
		 * on the orphan list; we need to make sure the inode
		 * is removed from the orphan list in that case.
		 */
		if (inode->i_nlink)
			ext4_orphan_del(NULL, inode);
	}

	return ret ? ret : copied;
}


void pagecache_isize_extended(struct inode *inode, loff_t from, loff_t to)
{
	int bsize = i_blocksize(inode);
	loff_t rounded_from;
	struct page *page;
	pgoff_t index;

	WARN_ON(to > inode->i_size);

	if (from >= to || bsize == PAGE_SIZE)
		return;
	/* Page straddling @from will not have any hole block created? */
	rounded_from = round_up(from, bsize);
	if (to <= rounded_from || !(rounded_from & (PAGE_SIZE - 1)))
		return;

	index = from >> PAGE_SHIFT;
	page = find_lock_page(inode->i_mapping, index);
	/* Page not cached? Nothing to do */
	if (!page)
		return;
	/*
	 * See clear_page_dirty_for_io() for details why set_page_dirty()
	 * is needed.
	 */
	if (page_mkclean(page))
		set_page_dirty(page);
	unlock_page(page);
	put_page(page);
}

int ext4_write_inline_data_end(struct inode *inode, loff_t pos, unsigned len,
			       unsigned copied, struct page *page)
{
	int ret, no_expand;
	void *kaddr;
	struct ext4_iloc iloc;

	if (unlikely(copied < len) && !PageUptodate(page))
		return 0;

	ret = ext4_get_inode_loc(inode, &iloc);
	if (ret) {
		ext4_std_error(inode->i_sb, ret);
		return ret;
	}

	ext4_write_lock_xattr(inode, &no_expand);
	BUG_ON(!ext4_has_inline_data(inode));

	/*
	 * ei->i_inline_off may have changed since ext4_write_begin()
	 * called ext4_try_to_write_inline_data()
	 */
	(void) ext4_find_inline_data_nolock(inode);

	kaddr = kmap_atomic(page);
	ext4_write_inline_data(inode, &iloc, kaddr, pos, copied);
	kunmap_atomic(kaddr);
	SetPageUptodate(page);
	/* clear page dirty so that writepages wouldn't work for us. */
	ClearPageDirty(page);

	ext4_write_unlock_xattr(inode, &no_expand);
	brelse(iloc.bh);
	mark_inode_dirty(inode);

	return copied;
}
```