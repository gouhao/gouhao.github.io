# 读文件
源码基于stable-5.10.102

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
    /* fdget_pos返回值是file对象与标志位.低2位存储标志位,其余位是file指针
		todo: 为什么file低2位是0 */
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

int rw_verify_area(int read_write, struct file *file, const loff_t *ppos, size_t count)
{
	struct inode *inode;
	int retval = -EINVAL;

	inode = file_inode(file);

	/* 如果要读取的小于0, 则退出 */
	if (unlikely((ssize_t) count < 0))
		return retval;

	if (ppos) {
		loff_t pos = *ppos;

		/* todo: pos怎么会小于0 ? */
		if (unlikely(pos < 0)) {
			/* unsigned_offsets判断file是不是大文件 */
			if (!unsigned_offsets(file))
				return retval;
			if (count >= -pos) /* both values are in 0..LLONG_MAX */
				return -EOVERFLOW;
		} else if (unlikely((loff_t) (pos + count) < 0)) {
			/* 前面已经判断了pos, count小于0的情况,所以走到这里,肯定是pos+count越界了,
			如果不是大文件就出错了.
			*/
			if (!unsigned_offsets(file))
				return retval;
		}

		/* 判断要读的区域是否加了锁,如果加了锁,这个进程必须持有锁,否则访问出错 */
		if (unlikely(inode->i_flctx && mandatory_lock(inode))) {
			retval = locks_mandatory_area(inode, file, pos, pos + count - 1,
					read_write == READ ? F_RDLCK : F_WRLCK);
			if (retval < 0)
				return retval;
		}
	}

	/* 调用 file_permission 钩子函数 */
	return security_file_permission(file,
				read_write == READ ? MAY_READ : MAY_WRITE);
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

void iov_iter_init(struct iov_iter *i, unsigned int direction,
			const struct iovec *iov, unsigned long nr_segs,
			size_t count)
{
	WARN_ON(direction & ~(READ | WRITE));
	direction &= READ | WRITE;

	if (uaccess_kernel()) { // 内核上下文访问
		i->type = ITER_KVEC | direction;
		i->kvec = (struct kvec *)iov;
	} else {
		i->type = ITER_IOVEC | direction;
		i->iov = iov;
	}
	/* nr_segs在这里传的是1*/
	i->nr_segs = nr_segs;
	i->iov_offset = 0;
	/* 要读取的数量 */
	i->count = count;
}
```
现在的文件系统提供的读文件函数指针一般都是generic_file_read_iter.
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
		struct file *file = iocb->ki_filp;
		struct address_space *mapping = file->f_mapping;
		struct inode *inode = mapping->host;
		loff_t size;

		size = i_size_read(inode);
		if (iocb->ki_flags & IOCB_NOWAIT) {
			if (filemap_range_has_page(mapping, iocb->ki_pos,
						   iocb->ki_pos + count - 1))
				return -EAGAIN;
		} else {
			retval = filemap_write_and_wait_range(mapping,
						iocb->ki_pos,
					        iocb->ki_pos + count - 1);
			if (retval < 0)
				goto out;
		}

		file_accessed(file);

		retval = mapping->a_ops->direct_IO(iocb, iter);
		if (retval >= 0) {
			iocb->ki_pos += retval;
			count -= retval;
		}
		iov_iter_revert(iter, count - iov_iter_count(iter));

		if (retval < 0 || !count || iocb->ki_pos >= size ||
		    IS_DAX(inode))
			goto out;
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
			// 开始同步预读
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

			if (inode->i_blkbits == PAGE_SHIFT ||
					!mapping->a_ops->is_partially_uptodate)
				goto page_not_up_to_date;
			/* pipes can't handle partially uptodate pages */
			if (unlikely(iov_iter_is_pipe(iter)))
				goto page_not_up_to_date;
			if (!trylock_page(page))
				goto page_not_up_to_date;
			/* Did it get truncated before we got the lock? */
			if (!page->mapping)
				goto page_not_up_to_date_locked;
			if (!mapping->a_ops->is_partially_uptodate(page,
							offset, iter->count))
				goto page_not_up_to_date_locked;
			unlock_page(page);
		}
page_ok:
		/* 文件大小,
			文件大小必须要等页更新了之后再获取*/
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

		/* 如果用户可以写入此页,需要刷新dcache ? */
		if (mapping_writably_mapped(mapping))
			flush_dcache_page(page);

		/* 标记此页已访问 */
		if (prev_index != index || offset != prev_offset)
			mark_page_accessed(page);
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
		continue;

page_not_up_to_date:
		// 页面不是最新的,锁定页面
		if (iocb->ki_flags & IOCB_WAITQ) {
			if (written) {
				put_page(page);
				goto out;
			}
			error = lock_page_async(page, iocb->ki_waitq);
		} else {
			error = lock_page_killable(page);
		}
		if (unlikely(error))
			goto readpage_error;

page_not_up_to_date_locked:
		// 如果页面没有映射,重新再找一下
		if (!page->mapping) {
			unlock_page(page);
			put_page(page);
			continue;
		}

		// 如果内容是最新的,再去page_ok重新读页面
		if (PageUptodate(page)) {
			unlock_page(page);
			goto page_ok;
		}

readpage:
		// 如果用户要求读的时候不做IO操作,或者不等待,则退出
		if (iocb->ki_flags & (IOCB_NOIO | IOCB_NOWAIT)) {
			unlock_page(page);
			put_page(page);
			goto would_block;
		}
		// 清除页面的错误标记
		ClearPageError(page);
		// 调用文件系统的读页面函数
		error = mapping->a_ops->readpage(filp, page);

		// 如果出错了,则退出
		if (unlikely(error)) {

			// todo: AOP_TRUNCATED_PAGE是啥?
			if (error == AOP_TRUNCATED_PAGE) {
				put_page(page);
				error = 0;
				goto find_page;
			}
			goto readpage_error;
		}

		// 如果页不是最新的,则要等待更新
		if (!PageUptodate(page)) {

			// 锁定页面
			if (iocb->ki_flags & IOCB_WAITQ) {
				if (written) {
					put_page(page);
					goto out;
				}
				error = lock_page_async(page, iocb->ki_waitq);
			} else {
				error = lock_page_killable(page);
			}
			// 锁页面出错
			if (unlikely(error))
				goto readpage_error;
			
			// 再判断一下是不是最新的,因为上锁的过程中可能会阻塞,进程会被调度出去
			if (!PageUptodate(page)) {
				
				// todo: 页面没有映射,再读一次??
				if (page->mapping == NULL) {
					unlock_page(page);
					put_page(page);
					goto find_page;
				}

				unlock_page(page);
				
				// 把预读页面减少4倍
				shrink_readahead_size_eio(ra);
				error = -EIO;
				goto readpage_error;
			}
			unlock_page(page);
		}

		// 读页面成功,再去page_ok,读一次
		goto page_ok;

readpage_error:
		/* UHHUH! A synchronous read error occurred. Report it */
		put_page(page);
		goto out;

no_cached_page:
		
		// 申请一页内存
		page = page_cache_alloc(mapping);
		if (!page) {
			error = -ENOMEM;
			goto out;
		}

		// 把新申请的页加到页缓存中
		error = add_to_page_cache_lru(page, mapping, index,
				mapping_gfp_constraint(mapping, GFP_KERNEL));

		// 如果出错了就释放页
		if (error) {
			put_page(page);
			if (error == -EEXIST) {
				error = 0;
				goto find_page;
			}
			goto out;
		}

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
// find_get_page 直接调用 pagecache_get_page(mapping, offset, 0, 0)
struct page *pagecache_get_page(struct address_space *mapping, pgoff_t index,
		int fgp_flags, gfp_t gfp_mask)
{
	struct page *page;

repeat:
	// 找目标页,这里面主要是调用xa的接口来查找页
	page = find_get_entry(mapping, index);
	// xa_is_value判断是指针还是值
	// 在这里如果是值就是没找到
	if (xa_is_value(page))
		page = NULL;

	if (!page)
		goto no_page;

	// 走到这里就是找到页了

	// 判断是否要加锁
	if (fgp_flags & FGP_LOCK) {
		if (fgp_flags & FGP_NOWAIT) {
			if (!trylock_page(page)) {
				put_page(page);
				return NULL;
			}
		} else {
			lock_page(page);
		}

		/* Has the page been truncated? */
		if (unlikely(page->mapping != mapping)) {
			unlock_page(page);
			put_page(page);
			goto repeat;
		}
		VM_BUG_ON_PAGE(!thp_contains(page, index), page);
	}

	// 判断已访问, 写标志
	if (fgp_flags & FGP_ACCESSED)
		mark_page_accessed(page);
	else if (fgp_flags & FGP_WRITE) {
		/* Clear idle flag for buffer write */
		if (page_is_idle(page))
			clear_page_idle(page);
	}
	// todo: 找子页?
	if (!(fgp_flags & FGP_HEAD))
		page = find_subpage(page, index);

no_page:
	// 如果没找到页,而且需要创建
	if (!page && (fgp_flags & FGP_CREAT)) {
		int err;
		if ((fgp_flags & FGP_WRITE) && mapping_can_writeback(mapping))
			gfp_mask |= __GFP_WRITE;
		if (fgp_flags & FGP_NOFS)
			gfp_mask &= ~__GFP_FS;

		// 申请一页
		page = __page_cache_alloc(gfp_mask);
		if (!page)
			return NULL;

		if (WARN_ON_ONCE(!(fgp_flags & (FGP_LOCK | FGP_FOR_MMAP))))
			fgp_flags |= FGP_LOCK;

		/* Init accessed so avoid atomic mark_page_accessed later */
		if (fgp_flags & FGP_ACCESSED)
			__SetPageReferenced(page);

		// 加入lru中
		err = add_to_page_cache_lru(page, mapping, index, gfp_mask);
		if (unlikely(err)) {
			put_page(page);
			page = NULL;
			if (err == -EEXIST)
				goto repeat;
		}

		/*
		 * add_to_page_cache_lru locks the page, and for mmap we expect
		 * an unlocked page.
		 */
		if (page && (fgp_flags & FGP_FOR_MMAP))
			unlock_page(page);
	}

	return page;
}

int add_to_page_cache_lru(struct page *page, struct address_space *mapping,
				pgoff_t offset, gfp_t gfp_mask)
{
	void *shadow = NULL;
	int ret;

	// 设置页的锁标志
	__SetPageLocked(page);

	// 加入缓存
	ret = __add_to_page_cache_locked(page, mapping, offset,
					 gfp_mask, &shadow);
	if (unlikely(ret))
		// 添加出错清除锁标志
		__ClearPageLocked(page);
	else {
		WARN_ON_ONCE(PageActive(page));
		if (!(gfp_mask & __GFP_WRITE) && shadow)
			workingset_refault(page, shadow);
		// 添加到lru里
		lru_cache_add(page);
	}
	return ret;
}



void lru_cache_add(struct page *page)
{
	// 一个pagevec可能保存15个页
	struct pagevec *pvec;

	VM_BUG_ON_PAGE(PageActive(page) && PageUnevictable(page), page);
	VM_BUG_ON_PAGE(PageLRU(page), page);

	get_page(page);

	/*
	lru_pvecs里面存放了各个页的列表
	struct lru_pvecs {
		local_lock_t lock;
		struct pagevec lru_add; // lru列表
		struct pagevec lru_deactivate_file; // 不活跃的文件页
		struct pagevec lru_deactivate; // 不活跃
		struct pagevec lru_lazyfree; // 延迟释放
	#ifdef CONFIG_SMP
		struct pagevec activate_page; // 活跃页
	#endif
	};
	*/
	local_lock(&lru_pvecs.lock);
	pvec = this_cpu_ptr(&lru_pvecs.lru_add);

	// pagevec_add把页添加到pvec里,返回值是pvec的剩余容量
	if (!pagevec_add(pvec, page) || PageCompound(page))
		// 如果pvec没有容量了,
		__pagevec_lru_add(pvec);
	local_unlock(&lru_pvecs.lock);
}

void __pagevec_lru_add(struct pagevec *pvec)
{
	pagevec_lru_move_fn(pvec, __pagevec_lru_add_fn, NULL);
}

static void pagevec_lru_move_fn(struct pagevec *pvec,
	void (*move_fn)(struct page *page, struct lruvec *lruvec, void *arg),
	void *arg)
{
	int i;
	struct pglist_data *pgdat = NULL;
	struct lruvec *lruvec;
	unsigned long flags = 0;

	// 遍历 pvec
	for (i = 0; i < pagevec_count(pvec); i++) {
		struct page *page = pvec->pages[i];

		// 页对应的 numa节点
		struct pglist_data *pagepgdat = page_pgdat(page);

		// 记录并锁住numa节点
		if (pagepgdat != pgdat) {
			if (pgdat)
				spin_unlock_irqrestore(&pgdat->lru_lock, flags);
			pgdat = pagepgdat;
			spin_lock_irqsave(&pgdat->lru_lock, flags);
		}

		lruvec = mem_cgroup_page_lruvec(page, pgdat);

		// 调用函数转移page
		(*move_fn)(page, lruvec, arg);
	}
	if (pgdat)
		spin_unlock_irqrestore(&pgdat->lru_lock, flags);
	release_pages(pvec->pages, pvec->nr);
	pagevec_reinit(pvec);
}

static void __pagevec_lru_add_fn(struct page *page, struct lruvec *lruvec,
				 void *arg)
{
	/*
	enum lru_list {
		LRU_INACTIVE_ANON = LRU_BASE,
		LRU_ACTIVE_ANON = LRU_BASE + LRU_ACTIVE,
		LRU_INACTIVE_FILE = LRU_BASE + LRU_FILE,
		LRU_ACTIVE_FILE = LRU_BASE + LRU_FILE + LRU_ACTIVE,
		LRU_UNEVICTABLE,
		NR_LRU_LISTS
	};

	*/
	enum lru_list lru;
	int was_unevictable = TestClearPageUnevictable(page);
	int nr_pages = thp_nr_pages(page);

	VM_BUG_ON_PAGE(PageLRU(page), page);

	// 设置page的lru标志
	SetPageLRU(page);
	smp_mb__after_atomic();

	// 根据page是不是evictable，然后选择合适的lru列表
	if (page_evictable(page)) {
		lru = page_lru(page);
		if (was_unevictable)
			__count_vm_events(UNEVICTABLE_PGRESCUED, nr_pages);
	} else {
		lru = LRU_UNEVICTABLE;
		ClearPageActive(page);
		SetPageUnevictable(page);
		if (!was_unevictable)
			__count_vm_events(UNEVICTABLE_PGCULLED, nr_pages);
	}

	// 添加到节点的lru列表中
	add_page_to_lru_list(page, lruvec, lru);
	trace_mm_lru_insertion(page, lru);
}

size_t copy_page_to_iter(struct page *page, size_t offset, size_t bytes,
			 struct iov_iter *i)
{
	// 检查复制的各种参数是否合法
	if (unlikely(!page_copy_sane(page, offset, bytes)))
		return 0;
	if (i->type & (ITER_BVEC|ITER_KVEC)) { // 内核调用的读
		void *kaddr = kmap_atomic(page);
		size_t wanted = copy_to_iter(kaddr + offset, bytes, i);
		kunmap_atomic(kaddr);
		return wanted;
	} else if (unlikely(iov_iter_is_discard(i))) { // 读操作取消
		if (unlikely(i->count < bytes))
			bytes = i->count;
		i->count -= bytes;
		return bytes;
	} else if (likely(!iov_iter_is_pipe(i))) // 一般的读
		// 这个函数向iov里的buf复制数据，并修改iov-count, 等相关变量
		return copy_page_to_iter_iovec(page, offset, bytes, i);
	else // pipe的读
		return copy_page_to_iter_pipe(page, offset, bytes, i);
}
```