# 关闭文件
源码基于stable-5.10.102

```c
SYSCALL_DEFINE1(close, unsigned int, fd)
{
	int retval = __close_fd(current->files, fd);

	/*
	原文注释说close系统调用不能重启，因为在file table中的项已经被清除了
	*/
	if (unlikely(retval == -ERESTARTSYS ||
		     retval == -ERESTARTNOINTR ||
		     retval == -ERESTARTNOHAND ||
		     retval == -ERESTART_RESTARTBLOCK))
		retval = -EINTR;

	return retval;
}

int __close_fd(struct files_struct *files, unsigned fd)
{
	struct file *file;

	// 通过fd找到file
	file = pick_file(files, fd);
	if (!file)
		return -EBADF;

	// 执行真下的关闭
	return filp_close(file, files);
}

static struct file *pick_file(struct files_struct *files, unsigned fd)
{
	struct file *file = NULL;
	struct fdtable *fdt;

	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	// fd不能超过最大的fd序号
	if (fd >= fdt->max_fds)
		goto out_unlock;
	// 直接从数组里取出文件
	file = fdt->fd[fd];
	if (!file)
		goto out_unlock;
	// 用rcu机制更新fd对应的数组项为NULL
	// todo: 这里为啥不等待rcu宽限期结束
	rcu_assign_pointer(fdt->fd[fd], NULL);

	// 释放fd，将fdt中相关的位清零
	__put_unused_fd(files, fd);

out_unlock:
	spin_unlock(&files->file_lock);
	return file;
}

static void __put_unused_fd(struct files_struct *files, unsigned int fd)
{
	struct fdtable *fdt = files_fdtable(files);
	// 在这个函数里主要清除了 fdt->open_fds, fdt->full_fds_bits对应的位
	__clear_open_fd(fd, fdt);

	// 如果fd比下次将要分配的fd小，则将下一次要分配的设置成fd
	if (fd < files->next_fd)
		files->next_fd = fd;
}

int filp_close(struct file *filp, fl_owner_t id)
{
	int retval = 0;

	// 如果f_count是0，表示这个文件已经关闭了，所以直接返回
	if (!file_count(filp)) {
		printk(KERN_ERR "VFS: Close: file count is 0\n");
		return 0;
	}

	// 调用具体文件系统的冲洗接口
	// 很多磁盘类型的文件系统都没有提供这个接口，伪文件系统大多提供了这个接口
	if (filp->f_op->flush)
		retval = filp->f_op->flush(filp, id);

	// 大多数文件都不是用O_PATH打开的
	if (likely(!(filp->f_mode & FMODE_PATH))) {
		// 调用notify相关的接口
		dnotify_flush(filp, id);
		// 如果对文件加了锁，在这里会移除对应的锁
		// todo: 文件锁相关的代码后面再看
		locks_remove_posix(filp, id);
	}
	// 递减引用计数，如果没人用了，就释放或缓存相关结构
	fput(filp);
	return retval;
}

// fput直接调用的fput_many, refs传的是1
void fput_many(struct file *file, unsigned int refs)
{
	// atomic_long_sub_and_test是先用file->f_count减去ref，
	// 如果f_count结果为0则返回1；否则返回0。
	// 也就是: !(file->f_count - refs)
	if (atomic_long_sub_and_test(refs, &file->f_count)) {
		// 走到这儿表示已经没有人用这个文件了，可以释放了

		struct task_struct *task = current;

		// 如果不是在中断上下文并且不是内核线程
		if (likely(!in_interrupt() && !(task->flags & PF_KTHREAD))) {

			// 初始化一个task_work, 最终会调用到 ____fput 函数
			// todo: task_work机制？？
			init_task_work(&file->f_u.fu_rcuhead, ____fput);
			if (!task_work_add(task, &file->f_u.fu_rcuhead, TWA_RESUME))
				return;
			/*
			 * After this task has run exit_task_work(),
			 * task_work_add() will fail.  Fall through to delayed
			 * fput to avoid leaking *file.
			 */
		}

		// 如果是中断或者内核线程，就加到一个延迟队列中，稍后再执行释放？
		if (llist_add(&file->f_u.fu_llist, &delayed_fput_list))
			schedule_delayed_work(&delayed_fput_work, 1);
	}
}

// ____fput会直接调到这个函数
static void __fput(struct file *file)
{
	struct dentry *dentry = file->f_path.dentry;
	struct vfsmount *mnt = file->f_path.mnt;
	struct inode *inode = file->f_inode;
	fmode_t mode = file->f_mode;

	// 这个文件没有打开？
	if (unlikely(!(file->f_mode & FMODE_OPENED)))
		goto out;

	might_sleep();

	// 通知文件已经关装
	fsnotify_close(file);
	/*
	原注释说: 要先调用eventpoll_release
	*/
	eventpoll_release(file);

	// 释放文件锁相关
	locks_remove_file(file);

	// 静态度量
	ima_file_free(file);

	// 如果文件需要同步，则调用具体文件系统的接口来同步到磁盘
	if (unlikely(file->f_flags & FASYNC)) {
		if (file->f_op->fasync)
			file->f_op->fasync(-1, file, 0);
	}

	// 调用具体文件系统的release接口
	if (file->f_op->release)
		file->f_op->release(inode, file);

	// 如果是字符设备，则调用字符设备的释放接口
	if (unlikely(S_ISCHR(inode->i_mode) && inode->i_cdev != NULL &&
		     !(mode & FMODE_PATH))) {
		cdev_put(inode->i_cdev);
	}

	// 递减f_op的引用计数
	fops_put(file->f_op);
	// 递减pid的引用计数
	put_pid(file->f_owner.pid);

	// 如果是只读，递减inode引用计数
	if ((mode & (FMODE_READ | FMODE_WRITE)) == FMODE_READ)
		i_readcount_dec(inode);

	// 这个应该是如果有创建文件之类的操作，则释放相关资源
	if (mode & FMODE_WRITER) {
		put_write_access(inode);
		__mnt_drop_write(mnt);
	}

	// 减少dentry引用计数，有可能释放或者缓存dentry
	dput(dentry);

	// todo: 需要卸载文件系统？
	if (unlikely(mode & FMODE_NEED_UNMOUNT))
		dissolve_on_fput(mnt);

	// 释放文件系统的引用计数
	mntput(mnt);
out:
	// 调用kmem_cache_free释放file结构，把内存退还给file缓存
	file_free(file);
}

void dput(struct dentry *dentry)
{
	while (dentry) {

		// 如果没释放掉，就睡一会
		might_sleep();

		rcu_read_lock();

		// 这是个利用rcu机制，没有加锁的快速路径
		if (likely(fast_dput(dentry))) {
			rcu_read_unlock();
			return;
		}

		rcu_read_unlock();

		/* 如果需要保留dentry，则直接返回.
		 一般都要保留，因为建立一个dentry是比较费劲的，保留它以便下次可以再复用
		*/
		if (likely(retain_dentry(dentry))) {
			spin_unlock(&dentry->d_lock);
			return;
		}

		// 真的释放dentry
		dentry = dentry_kill(dentry);
	}
}

static inline bool fast_dput(struct dentry *dentry)
{
	int ret;
	unsigned int d_flags;

	/* 具体文件系统的dentry有删除接口就需要由文件系统来判断 */
	if (unlikely(dentry->d_flags & DCACHE_OP_DELETE))
		return lockref_put_or_lock(&dentry->d_lockref);

	/* 递减引用计数 */
	ret = lockref_put_return(&dentry->d_lockref);

	
	if (unlikely(ret < 0)) {
		spin_lock(&dentry->d_lock);
		if (dentry->d_lockref.count > 1) {
			dentry->d_lockref.count--;
			spin_unlock(&dentry->d_lock);
			return true;
		}
		return false;
	}


	if (ret)
		return true;

	smp_rmb();
	d_flags = READ_ONCE(dentry->d_flags);
	d_flags &= DCACHE_REFERENCED | DCACHE_LRU_LIST | DCACHE_DISCONNECTED;

	/* 如果该dentry最后用过，而且在超级块的lru列表中，并且挂到hash表里，要保留 */
	if (d_flags == (DCACHE_REFERENCED | DCACHE_LRU_LIST) && !d_unhashed(dentry))
		return true;

	
	spin_lock(&dentry->d_lock);

	/* 如果引用计数是1，说明还有别人用，要保留 */
	if (dentry->d_lockref.count) {
		spin_unlock(&dentry->d_lock);
		return true;
	}

	/* 走到这儿，说明这个dentry没人用了，设置引用计数为1，别人再减1就到0，释放了 */
	dentry->d_lockref.count = 1;
	return false;
}

static inline bool retain_dentry(struct dentry *dentry)
{
	// d_in_lookup判断DCACHE_PAR_LOOKUP标志，
	// 在刚申请到dentry时会有这个标志
	WARN_ON(d_in_lookup(dentry));

	// 如果这个dentry还没有链到hash表上，则不保留
	if (unlikely(d_unhashed(dentry)))
		return false;
	/*
	有DCACHE_DISCONNECTED也不保留
	todo: DCACHE_DISCONNECTED没看懂，应该是给网络文件系统用的
	*/
	if (unlikely(dentry->d_flags & DCACHE_DISCONNECTED))
		return false;

	/* 如果具体文件系统有dentry的delete函数，则调用之
	if (unlikely(dentry->d_flags & DCACHE_OP_DELETE)) {
		// 如果具体文件系统需要删除它，也不保留
		if (dentry->d_op->d_delete(dentry))
			return false;
	}

	/* 如果明确要求不缓存，不保留 */
	if (unlikely(dentry->d_flags & DCACHE_DONTCACHE))
		return false;

	/* 走到这儿就表示要保留这个dentry */

	/* todo: lockref是个啥？ */
	dentry->d_lockref.count--;

	/* 如果dentry还没有挂到超级块的lru列表里，则挂之，并设置DCACHE_LRU_LIST标志 */
	if (unlikely(!(dentry->d_flags & DCACHE_LRU_LIST)))
		d_lru_add(dentry);
	else if (unlikely(!(dentry->d_flags & DCACHE_REFERENCED)))
		// DCACHE_REFERENCED表示最后使用过，不要释放它
		dentry->d_flags |= DCACHE_REFERENCED;
	return true;
}

static struct dentry *dentry_kill(struct dentry *dentry)
	__releases(dentry->d_lock)
{
	struct inode *inode = dentry->d_inode;
	struct dentry *parent = NULL;

	// 没有获取到锁，就走慢路径
	if (inode && unlikely(!spin_trylock(&inode->i_lock)))
		goto slow_positive;

	if (!IS_ROOT(dentry)) { // 不是文件系统的根目录

		// 获取父dentry
		parent = dentry->d_parent;

		/* 这个if是处理没有获取到父dentry的锁 */
		if (unlikely(!spin_trylock(&parent->d_lock))) {
			parent = __lock_parent(dentry);
			if (likely(inode || !dentry->d_inode))
				goto got_locks;
			/* negative that became positive */
			if (parent)
				spin_unlock(&parent->d_lock);
			inode = dentry->d_inode;
			goto slow_positive;
		}
	}
	/* 真正执行释放的函数 */
	__dentry_kill(dentry);
	return parent;

slow_positive:
	spin_unlock(&dentry->d_lock);
	spin_lock(&inode->i_lock);
	spin_lock(&dentry->d_lock);
	parent = lock_parent(dentry);
got_locks:
	if (unlikely(dentry->d_lockref.count != 1)) {
		dentry->d_lockref.count--;
	} else if (likely(!retain_dentry(dentry))) {
		__dentry_kill(dentry);
		return parent;
	}
	/* we are keeping it, after all */
	if (inode)
		spin_unlock(&inode->i_lock);
	if (parent)
		spin_unlock(&parent->d_lock);
	spin_unlock(&dentry->d_lock);
	return NULL;
}

static void __dentry_kill(struct dentry *dentry)
{
	struct dentry *parent = NULL;
	bool can_free = true;

	/* 不是文件系统的根目录就获取它的父结点 */
	if (!IS_ROOT(dentry))
		parent = dentry->d_parent;

	/* 设置lockref的dead标志，等于：lockref->count = -128 */
	lockref_mark_dead(&dentry->d_lockref);

	/* 具体文件系统有d_prune接口，则调用之 */
	if (dentry->d_flags & DCACHE_OP_PRUNE)
		dentry->d_op->d_prune(dentry);

	/* dentry 在lru表中，而且没有收缩列表中，则从lru
	 表中删除它。收缩列表是系统在执行内存回收的时候会
	 将dentry加到一个shrink表里
	 */
	if (dentry->d_flags & DCACHE_LRU_LIST) {
		if (!(dentry->d_flags & DCACHE_SHRINK_LIST))
			d_lru_del(dentry);
	}
	
	/* 把dentry从内存的哈希表里移除 */
	__d_drop(dentry);

	/* 把它从父结点移除，并且把它的子结点都移除,
	  因为dentry可能是一个目录，它也有自己的子结点 */
	dentry_unlist(dentry, parent);
	if (parent)
		spin_unlock(&parent->d_lock);
	
	/* 将dentry与inode断开连接，这里inode并不释放，
	因为可能还有其它dentry使用这个inode，这里只是把dentry从
	inode的i_alias表里移除 */
	if (dentry->d_inode)
		dentry_unlink_inode(dentry);
	else
		spin_unlock(&dentry->d_lock);
	this_cpu_dec(nr_dentry);
	/* 如果文件系统有d_release函数，调用它 */
	if (dentry->d_op && dentry->d_op->d_release)
		dentry->d_op->d_release(dentry);

	spin_lock(&dentry->d_lock);
	/* 如果在shrink列表中，则在这里不能释放 */
	if (dentry->d_flags & DCACHE_SHRINK_LIST) {
		dentry->d_flags |= DCACHE_MAY_FREE;
		can_free = false;
	}
	spin_unlock(&dentry->d_lock);
	if (likely(can_free))
		/* 释放dentry，最终会调用kmem_cache_free来释放 */
		dentry_free(dentry);
	/* 如果需要调度，就让出cpu*/
	cond_resched();
}

static void dentry_unlink_inode(struct dentry * dentry)
	__releases(dentry->d_lock)
	__releases(dentry->d_inode->i_lock)
{
	struct inode *inode = dentry->d_inode;

	raw_write_seqcount_begin(&dentry->d_seq);
	/* 这个函数里会清除 dentry里的inode指针
	__d_clear_type_and_inode(dentry);
	/* 从inode的i_alias表里删除 */
	hlist_del_init(&dentry->d_u.d_alias);
	raw_write_seqcount_end(&dentry->d_seq);
	spin_unlock(&dentry->d_lock);
	spin_unlock(&inode->i_lock);
	if (!inode->i_nlink)
		/* 通知inode将要删除 */
		fsnotify_inoderemove(inode);
	/* 如果文件系统有d_input，则调用它，否则调用iput */
	if (dentry->d_op && dentry->d_op->d_iput)
		dentry->d_op->d_iput(dentry, inode);
	else
		iput(inode);
}

void iput(struct inode *inode)
{
	if (!inode)
		return;
	BUG_ON(inode->i_state & I_CLEAR);
retry:
	/* 递减i_count计数，如果i_count为0，则进入 */
	if (atomic_dec_and_lock(&inode->i_count, &inode->i_lock)) {

		/* 如果inode正在标脏，则增加它的引用计数，然后再去retry重试一次 */
		if (inode->i_nlink && (inode->i_state & I_DIRTY_TIME)) {
			atomic_inc(&inode->i_count);
			spin_unlock(&inode->i_lock);
			trace_writeback_lazytime_iput(inode);
			mark_inode_dirty_sync(inode);
			goto retry;
		}

		/* 释放inode */
		iput_final(inode);
	}
}

static void iput_final(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;

	/* op 是超级块的操作函数表 */
	const struct super_operations *op = inode->i_sb->s_op;
	unsigned long state;
	int drop;

	WARN_ON(inode->i_state & I_NEW);

	/* 如果超级块定义了drop_inode，则调用它，否则调用通用方法.
		返回 1, 表示丢弃内容，反之，返回0 */
	if (op->drop_inode)
		drop = op->drop_inode(inode);
	else
		/* 如果inode的i_nlink为0，或者没有挂在内存hash表*/
		drop = generic_drop_inode(inode);

	/* 如果不释放，而且超级块缓存inode，并且超级块已激活，则把它加到
		超级块的inode缓存列表，直接返回 */
	if (!drop &&
	    !(inode->i_state & I_DONTCACHE) &&
	    (sb->s_flags & SB_ACTIVE)) {
		inode_add_lru(inode);
		spin_unlock(&inode->i_lock);
		return;
	}

	state = inode->i_state;

	/* 如果不丢弃它的内容，则调write_inode_now把inode写入磁盘 */
	if (!drop) {
		WRITE_ONCE(inode->i_state, state | I_WILL_FREE);
		spin_unlock(&inode->i_lock);

		write_inode_now(inode, 1);

		spin_lock(&inode->i_lock);
		state = inode->i_state;
		WARN_ON(state & I_NEW);
		state &= ~I_WILL_FREE;
	}

	WRITE_ONCE(inode->i_state, state | I_FREEING);
	/* 把inode从lru列表移除 */
	if (!list_empty(&inode->i_lru))
		inode_lru_list_del(inode);
	spin_unlock(&inode->i_lock);

	/* 释放inode */
	evict(inode);
}

static void evict(struct inode *inode)
{
	const struct super_operations *op = inode->i_sb->s_op;

	/* 下面这两个BUG_ON的条件，已经在上面写入了 */
	BUG_ON(!(inode->i_state & I_FREEING));
	BUG_ON(!list_empty(&inode->i_lru));

	/* 删除io_list */
	if (!list_empty(&inode->i_io_list))
		inode_io_list_del(inode);

	/* 从超级块的缓存列表移除 */
	inode_sb_list_del(inode);

	/* 如果有回写，则等待回写结束
	inode_wait_for_writeback(inode);

	/* 如果文件系统有evict_inode，则调用它，否则调用通用方法 */
	if (op->evict_inode) {
		op->evict_inode(inode);
	} else {
		truncate_inode_pages_final(&inode->i_data);
		clear_inode(inode);
	}

	/* 如果是块设备，字符设备，则调用相关的方法 */
	if (S_ISBLK(inode->i_mode) && inode->i_bdev)
		bd_forget(inode);
	if (S_ISCHR(inode->i_mode) && inode->i_cdev)
		cd_forget(inode);

	/* 从哈希表中移除 */
	remove_inode_hash(inode);

	spin_lock(&inode->i_lock);
	/* 唤醒在__I_NEW位上等待的人 */
	wake_up_bit(&inode->i_state, __I_NEW);
	BUG_ON(inode->i_state != (I_FREEING | I_CLEAR));
	spin_unlock(&inode->i_lock);

	/* 释放inode */
	destroy_inode(inode);
}

static void destroy_inode(struct inode *inode)
{
	const struct super_operations *ops = inode->i_sb->s_op;

	BUG_ON(!list_empty(&inode->i_lru));
	/* 调用一些回调函数 */
	__destroy_inode(inode);

	/* 调用具体文件系统的destroy_inode接口 */
	if (ops->destroy_inode) {
		ops->destroy_inode(inode);
		if (!ops->free_inode)
			return;
	}
	/* 调用文件系统的free_inode接口,用的是rcu机制 */
	inode->free_inode = ops->free_inode;
	call_rcu(&inode->i_rcu, i_callback);
}

void __destroy_inode(struct inode *inode)
{
	BUG_ON(inode_has_buffers(inode));
	/* todo: wb是bdi_writeback，没看代码 */
	inode_detach_wb(inode);
	/* 调用inode_free 钩子函数 */
	security_inode_free(inode);
	/* 调用通知接口，通知inode删除 */
	fsnotify_inode_delete(inode);
	/* 释放 锁 ？ */
	locks_free_lock_context(inode);
	/* 递减超级块的remove_count */
	if (!inode->i_nlink) {
		WARN_ON(atomic_long_read(&inode->i_sb->s_remove_count) == 0);
		atomic_long_dec(&inode->i_sb->s_remove_count);
	}

#ifdef CONFIG_FS_POSIX_ACL
	/* acl相关，代码没看 */
	if (inode->i_acl && !is_uncached_acl(inode->i_acl))
		posix_acl_release(inode->i_acl);
	if (inode->i_default_acl && !is_uncached_acl(inode->i_default_acl))
		posix_acl_release(inode->i_default_acl);
#endif
	/* 递减nr_inodes计数器 */
	this_cpu_dec(nr_inodes);
}
EXPORT_SYMBOL(__destroy_inode);



static void i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	/* 调用文件系统方法，如果没有，则调用通用方法 */
	if (inode->free_inode)
		inode->free_inode(inode);
	else
		/* 这个方法里就是调用kmem_cache_free来释放inode */
		free_inode_nonrcu(inode);
}

```