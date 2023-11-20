1. read
```c
/*
fd: 文件描述符
buf: 缓冲区
count: 要读入的数量

要读取的位置在file的f_pos里
*/
SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)
{
	return ksys_read(fd, buf, count);
}

ssize_t ksys_read(unsigned int fd, char __user *buf, size_t count)
{
	/* fdget_pos返回值是file对象与标志位.低2位存储标志位,其余位是file指针*/
	struct fd f = fdget_pos(fd);
	ssize_t ret = -EBADF;

	/* 如果没找到文件就出错了 */
	if (f.file) {
		/* 如果是FMODE_STREAM格式返回NULL, 否则返回文件当前读写位置 */
		loff_t pos, *ppos = file_ppos(f.file);
		if (ppos) {
			pos = *ppos;
			ppos = &pos;
		}
		/* ret返回的是读取到的数量 */
		ret = vfs_read(f.file, buf, count, ppos);

		/* 如果读取到了数据,则更新文件的f_pos值*/
		if (ret >= 0 && ppos)
			f.file->f_pos = pos;
		/* 刚才在fdget_pos里增加了引用计数,所以这里要递减 */
		fdput_pos(f);
	}
	return ret;
}

ssize_t vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	ssize_t ret;

	/* 如果没有读标志或者不能读,则出错返回 */
	if (!(file->f_mode & FMODE_READ))
		return -EBADF;
	if (!(file->f_mode & FMODE_CAN_READ))
		return -EINVAL;
	/* 判断用户空间的buf地址是否合法 */
	if (unlikely(!access_ok(buf, count)))
		return -EFAULT;
	/* 检查要读取的位置是否合法 */
	ret = rw_verify_area(READ, file, pos, count);
	if (ret)
		return ret;
	/* 
		调整最大读取值为MAX_RW_COUNT
	#define MAX_RW_COUNT (INT_MAX & PAGE_MASK)
		将INT_MAX页对齐.
	*/
	if (count > MAX_RW_COUNT)
		count =  MAX_RW_COUNT;

	/* 文件系统必须提供read或read_iter指针 */
	if (file->f_op->read)
		ret = file->f_op->read(file, buf, count, pos);
	else if (file->f_op->read_iter)
		/* new_sync_read会创建一个iov来读取 */
		ret = new_sync_read(file, buf, count, pos);
	else
		ret = -EINVAL;
	if (ret > 0) {
		/* 通知文件被访问 */
		fsnotify_access(file);
		/* 统计进程的rchar */
		add_rchar(current, ret);
	}
	/* syscr统计 */
	inc_syscr(current);
	return ret;
}

static ssize_t new_sync_read(struct file *filp, char __user *buf, size_t len, loff_t *ppos)
{
	struct iovec iov = { .iov_base = buf, .iov_len = len };
	struct kiocb kiocb;
	struct iov_iter iter;
	ssize_t ret;

	/* 初始化一个kiocb结构体 */
	init_sync_kiocb(&kiocb, filp);
	kiocb.ki_pos = (ppos ? *ppos : 0);

	/* 初始化 iov_iter */
	iov_iter_init(&iter, READ, &iov, 1, len);

	/* 直接调用文件系统的read_iter方法 */
	ret = call_read_iter(filp, &kiocb, &iter);
	BUG_ON(ret == -EIOCBQUEUED);
	if (ppos)
		*ppos = kiocb.ki_pos;
	return ret;
}
```

2. write
```c
SYSCALL_DEFINE3(write, unsigned int, fd, const char __user *, buf,
		size_t, count)
{
	return ksys_write(fd, buf, count);
}

ssize_t ksys_write(unsigned int fd, const char __user *buf, size_t count)
{
	struct fd f = fdget_pos(fd);
	ssize_t ret = -EBADF;

	if (f.file) {
		loff_t pos, *ppos = file_ppos(f.file);
		if (ppos) {
			pos = *ppos;
			ppos = &pos;
		}
		ret = vfs_write(f.file, buf, count, ppos);
		if (ret >= 0 && ppos)
			f.file->f_pos = pos;
		fdput_pos(f);
	}

	return ret;
}

ssize_t vfs_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
	ssize_t ret;

	if (!(file->f_mode & FMODE_WRITE))
		return -EBADF;
	if (!(file->f_mode & FMODE_CAN_WRITE))
		return -EINVAL;
	if (unlikely(!access_ok(buf, count)))
		return -EFAULT;

	ret = rw_verify_area(WRITE, file, pos, count);
	if (ret)
		return ret;
	if (count > MAX_RW_COUNT)
		count =  MAX_RW_COUNT;
	file_start_write(file);
	if (file->f_op->write)
		ret = file->f_op->write(file, buf, count, pos);
	else if (file->f_op->write_iter)
		ret = new_sync_write(file, buf, count, pos);
	else
		ret = -EINVAL;
	if (ret > 0) {
		fsnotify_modify(file);
		add_wchar(current, ret);
	}
	inc_syscw(current);
	file_end_write(file);
	return ret;
}
```

3. generic_file_read_iter
```c
ssize_t
generic_file_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	/* 要读取的数量 */
	size_t count = iov_iter_count(iter);
	ssize_t retval = 0;

	/* 读取的数量为0,退出 */
	if (!count)
		goto out; /* skip atime */

	if (iocb->ki_flags & IOCB_DIRECT) { // 直接读取,不经过页缓存
		...
	}
	
	/* 普通读取,大多数走这个函数, 这个函数带有页缓存*/
	retval = generic_file_buffered_read(iocb, iter, retval);
out:
	return retval;
}

ssize_t generic_file_buffered_read(struct kiocb *iocb,
		struct iov_iter *iter, ssize_t written)
{
	/* 文件指针 */
	struct file *filp = iocb->ki_filp;

	/* 映射函数表 */
	struct address_space *mapping = filp->f_mapping;

	/* inode */
	struct inode *inode = mapping->host;

	/* 预读上下文 */
	struct file_ra_state *ra = &filp->f_ra;

	/* 读的起点 */
	loff_t *ppos = &iocb->ki_pos;
	pgoff_t index;
	pgoff_t last_index;
	pgoff_t prev_index;
	unsigned long offset;      /* offset into pagecache page */
	unsigned int prev_offset;
	int error = 0;

	/* 如果读的起点超过了超级块最大字符数 ? */
	if (unlikely(*ppos >= inode->i_sb->s_maxbytes))
		return 0;

	/* 将count限制为超级块规定的最大字节数*/
	iov_iter_truncate(iter, inode->i_sb->s_maxbytes);

	/* 页面索引 */
	index = *ppos >> PAGE_SHIFT;
	/* 之前预读索引 */
	prev_index = ra->prev_pos >> PAGE_SHIFT;
	/* 预读偏移 */
	prev_offset = ra->prev_pos & (PAGE_SIZE-1);
	/* 上次访问的页索引 */
	last_index = (*ppos + iter->count + PAGE_SIZE-1) >> PAGE_SHIFT;

	/* 本次读取在页内的偏移 */
	offset = *ppos & ~PAGE_MASK;

	/* 原注释: 当我们已经复制了一些数据,就不能再安全的返回 -EIOCBQUEUED, 需要
		把文件标志改成IOCB_NOWAIT
	 */
	if (written && (iocb->ki_flags & IOCB_WAITQ))
		iocb->ki_flags |= IOCB_NOWAIT;

	/* 从这里就开始读取了 */
	for (;;) {
		struct page *page;
		pgoff_t end_index;
		loff_t isize;
		unsigned long nr, ret;

		/* 让出cpu调度其它进程,转为io操作可能要读磁盘,是个耗时操作 */
		cond_resched();
find_page:
		/* 如果有信号要处理,就退出,先处理信号 */
		if (fatal_signal_pending(current)) {
			error = -EINTR;
			goto out;
		}

		/* 从缓存里找目标页面 */
		page = find_get_page(mapping, index);
		if (!page) { // 目标页面还没有缓存

			// 没找到目标页就要做IO操作，如果用户不允许IO，直接退出
			if (iocb->ki_flags & IOCB_NOIO)
				goto would_block;
			// 开始同步预读, 这里面会调用read_page
			page_cache_sync_readahead(mapping,
					ra, filp,
					index, last_index - index);
			// 再找一次
			page = find_get_page(mapping, index);

			// 如果还没找到,就去no_cached_page处理,在这里面可能会从磁盘上读页面
			if (unlikely(page == NULL))
				goto no_cached_page;
		}

		// PG_Readahead标志，表示读到这一页时，要开始异步预读
		if (PageReadahead(page)) {
			// 不允许IO
			if (iocb->ki_flags & IOCB_NOIO) {
				put_page(page);
				goto out;
			}

			// 启动异步预读
			page_cache_async_readahead(mapping,
					ra, filp, page,
					index, last_index - index);
		}

		/* 如果当前缓存的页面不是最新的 */
		if (!PageUptodate(page)) { 
			if (iocb->ki_flags & IOCB_WAITQ) {
				if (written) {
					put_page(page);
					goto out;
				}
				error = wait_on_page_locked_async(page,
								iocb->ki_waitq);
			} else {
				if (iocb->ki_flags & IOCB_NOWAIT) {
					put_page(page);
					goto would_block;
				}
				error = wait_on_page_locked_killable(page);
			}
			if (unlikely(error))
				goto readpage_error;
			if (PageUptodate(page))
				goto page_ok;

			...
		}
page_ok:
		/* 文件大小,文件大小必须要等页更新了之后再获取*/
		isize = i_size_read(inode);

		/* 数据最后一页 */
		end_index = (isize - 1) >> PAGE_SHIFT;

		/* 如果文件为0, 或者要读的页超过了文件大小,则退出 */
		if (unlikely(!isize || index > end_index)) {
			put_page(page);
			goto out;
		}

		/* 一次最大复制的数据量为1页, 因为是数据是页缓存的 */
		nr = PAGE_SIZE;

		/* 如果读的是最后一页,则要修改最大可读数据量 */
		if (index == end_index) {

			/* 这句相当于: nr = isize % PAGE_SIZE,
				就是最后一页可读的数据量 */
			nr = ((isize - 1) & ~PAGE_MASK) + 1;

			/* 偏移超出了可读的数据,肯定是错了 */
			if (nr <= offset) {
				put_page(page);
				goto out;
			}
		}

		/* 减去offset就是本次可读的数据量 */
		nr = nr - offset;

		...

		prev_index = index;

		/* 向用户空间复制数据*/
		ret = copy_page_to_iter(page, offset, nr, iter);

		/* 增加offset */
		offset += ret;

		/* 计算下次要读的页索引, offset+ret可能会到下一页,
		相当于: index += offset / PAGE_SIZE */
		index += offset >> PAGE_SHIFT;

		/* 计算下次读的偏移: 相当于 offset %= PAGE_SIZE */
		offset &= ~PAGE_MASK;
		prev_offset = offset;

		/* 减少页引用计数 */
		put_page(page);

		/* 统计已读取的数据,
			这里之所以用written是因为读是向用户的缓冲区里写 */
		written += ret;

		/* 如果已经读够了,就退出, iter的count在copy_page_to_iter里被修改*/
		if (!iov_iter_count(iter))
			goto out;
		/* 如果读出的数据小于应该读的数据,则退出 */
		if (ret < nr) {
			error = -EFAULT;
			goto out;
		}
		continue; // 注意从这里就continue了

		... // page not uptodate

readpage:
		... // 预读失败，再次读页

		// 读页面成功,再去page_ok,读一次
		goto page_ok;

readpage_error:
		/* UHHUH! A synchronous read error occurred. Report it */
		put_page(page);
		goto out;

no_cached_page:
		
		.. 内存分配失败

		// 去读页面, 这个代码写的真是绕,不知道为啥这样写
		goto readpage;
	}

would_block:
	error = -EAGAIN;
out:
	// 更新预读指针
	ra->prev_pos = prev_index;
	ra->prev_pos <<= PAGE_SHIFT;
	ra->prev_pos |= prev_offset;

	// 增加iov_iter的走点指针
	*ppos = ((loff_t)index << PAGE_SHIFT) + offset;
	// 更新文件的atime
	file_accessed(filp);
	// 返回已写入的数据量
	return written ? written : error;
}
```

4. generic_perform_write
```c
ssize_t generic_perform_write(struct file *file,
				struct iov_iter *i, loff_t pos)
{
	struct address_space *mapping = file->f_mapping;
	const struct address_space_operations *a_ops = mapping->a_ops;
	long status = 0;
	ssize_t written = 0;
	unsigned int flags = 0;

	do {
		struct page *page;
		unsigned long offset;	/* Offset into pagecache page */
		unsigned long bytes;	/* Bytes to write to page */
		size_t copied;		/* Bytes copied from user */
		void *fsdata;

        	// 算出pos在页内的偏移，相当于 offset = pos % PAGE_SIZE
		offset = (pos & (PAGE_SIZE - 1));

        	// 可写的数据量
		bytes = min_t(unsigned long, PAGE_SIZE - offset,
						iov_iter_count(i));

again:
		... // 信号处理

        	// 为写做准备,主要是把需要写的页面准备好,如果内存里还没有,就要从磁盘上读
		status = a_ops->write_begin(file, mapping, pos, bytes, flags,
						&page, &fsdata);
		if (unlikely(status < 0))
			break;

		if (mapping_writably_mapped(mapping))
			flush_dcache_page(page);

        	// 从用户空间向页里写数据
		copied = iov_iter_copy_from_user_atomic(page, i, offset, bytes);
		flush_dcache_page(page);

        	// 写结束
		status = a_ops->write_end(file, mapping, pos, bytes, copied,
						page, fsdata);
		if (unlikely(status < 0))
			break;

        	// 写入的数量
		copied = status;

        	// 检查是否需要调度,则让出cpu
		cond_resched();

        	// 从count里减去已经复制的数据,里面写的比较复杂,不知道为啥要这么写
		iov_iter_advance(i, copied);
		if (unlikely(copied == 0)) {
			// 如果没有复制到数据,重新计算bytes?
			bytes = min_t(unsigned long, PAGE_SIZE - offset,
						iov_iter_single_seg_count(i));
			goto again;
		}

        	// 累加相关计数器
		pos += copied;
		written += copied;

       		// 刷新脏页,如果脏页太多,就会写磁盘
		balance_dirty_pages_ratelimited(mapping);
	} while (iov_iter_count(i));

	return written ? written : status;
}

int block_write_begin(struct address_space *mapping, loff_t pos, unsigned len,
		unsigned flags, struct page **pagep, get_block_t *get_block)
{
	// 计算pos对应的页序号,相当于: index = pos / PAGE_SIZE
	pgoff_t index = pos >> PAGE_SHIFT;
	struct page *page;
	int status;

	// 获取index对应的页面，会调用read_page
	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		return -ENOMEM;

	// 与块设备上的页面进行映射
	status = __block_write_begin(page, pos, len, get_block);
	if (unlikely(status)) {
		unlock_page(page);
		put_page(page);
		page = NULL;
	}

	// 用pagep返回找到的page
	*pagep = page;
	return status;
}
```