# 关闭文件
源码基于stable-5.10.102

## 1. close
```c
SYSCALL_DEFINE1(close, unsigned int, fd)
{
	int retval = __close_fd(current->files, fd);

	/*
	close系统调用不能重启，因为在file table中的项已经被清除了
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
```

## 2. pick_file
```c
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

static inline void __clear_open_fd(unsigned int fd, struct fdtable *fdt)
{
	__clear_bit(fd, fdt->open_fds);
	__clear_bit(fd / BITS_PER_LONG, fdt->full_fds_bits);
}
```

## 3. filp_close
```c 
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
		locks_remove_posix(filp, id);
	}
	// 递减引用计数，如果没人用了，就释放或缓存相关结构
	fput(filp);
	return retval;
}

void fput(struct file *file)
{
	fput_many(file, 1);
}

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
			init_task_work(&file->f_u.fu_rcuhead, ____fput);
			if (!task_work_add(task, &file->f_u.fu_rcuhead, TWA_RESUME))
				return;

			// 走到这儿表示添加task_work失败
			/*
			 * After this task has run exit_task_work(),
			 * task_work_add() will fail.  Fall through to delayed
			 * fput to avoid leaking *file.
			 */
		}

		// 如果是中断或者内核线程，就加到一个延迟队列中，稍后执行释放
		if (llist_add(&file->f_u.fu_llist, &delayed_fput_list))
			// delayed_fput调用的是delayed_fput，第2个参数的单位是 jiffies
			schedule_delayed_work(&delayed_fput_work, 1);
	}
}

static void ____fput(struct callback_head *work)
{
	__fput(container_of(work, struct file, f_u.fu_rcuhead));
}

// ____fput会直接调到这个函数
static void __fput(struct file *file)
{
	struct dentry *dentry = file->f_path.dentry;
	struct vfsmount *mnt = file->f_path.mnt;
	struct inode *inode = file->f_inode;
	fmode_t mode = file->f_mode;

	// 这个文件没有打开
	if (unlikely(!(file->f_mode & FMODE_OPENED)))
		goto out;

	might_sleep();

	// 通知文件已经关闭
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
```