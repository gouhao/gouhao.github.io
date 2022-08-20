# 写文件

源码基于stable-5.10.102

写文件的系统调用，以及前面几个函数和读文件差不多，我们直接从generic_perform_write开始看
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
		// 检查用户空间地址可读? todo: 没太看懂
		if (unlikely(iov_iter_fault_in_readable(i, bytes))) {
			status = -EFAULT;
			break;
		}

        // 有信号要处理
		if (fatal_signal_pending(current)) {
			status = -EINTR;
			break;
		}

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
```
write_begin函数, 大多数文件系统都会调用到block_write_begin.
```c
int block_write_begin(struct address_space *mapping, loff_t pos, unsigned len,
		unsigned flags, struct page **pagep, get_block_t *get_block)
{
    // 计算pos对应的页序号,相当于: index = pos / PAGE_SIZE
	pgoff_t index = pos >> PAGE_SHIFT;
	struct page *page;
	int status;

    // 获取index对应的页面
	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		return -ENOMEM;

    // 与块设备上的页面同步
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
struct page *grab_cache_page_write_begin(struct address_space *mapping,
					pgoff_t index, unsigned flags)
{
	struct page *page;
	int fgp_flags = FGP_LOCK|FGP_WRITE|FGP_CREAT;

	if (flags & AOP_FLAG_NOFS)
		fgp_flags |= FGP_NOFS;

    // pagecache_get_page用来查找/创建对应的页面，如果缓存里有页面，就
    // 直接返回，否则就创建一个并加入对缓存里
    // 这个代码详见读文件的解释
	page = pagecache_get_page(mapping, index, fgp_flags,
			mapping_gfp_mask(mapping));
	if (page)
        // 如果需要就等待页写回完成
		wait_for_stable_page(page);

	return page;
}

// __block_write_begin直接调用 __block_write_begin_int(page, pos, len, get_block, NULL)
int __block_write_begin_int(struct page *page, loff_t pos, unsigned len,
		get_block_t *get_block, struct iomap *iomap)
{
    // 算出页内偏移, 相当于: from = pos % PAGE_SIZE
	unsigned from = pos & (PAGE_SIZE - 1);

    // 数据终点
	unsigned to = from + len;
	struct inode *inode = page->mapping->host;
	unsigned block_start, block_end;
	sector_t block;
	int err = 0;
	unsigned blocksize, bbits;
	struct buffer_head *bh, *head, *wait[2], **wait_bh=wait;

	BUG_ON(!PageLocked(page));
	BUG_ON(from > PAGE_SIZE);
	BUG_ON(to > PAGE_SIZE);
	BUG_ON(from > to);

    // 获取/创建页的buffer_head, 存在page->private里
	head = create_page_buffers(page, inode, 0);

    // 块大小
	blocksize = head->b_size;

    // 块大小对应的位
	bbits = block_size_bits(blocksize);

    // 对应的块号
	block = (sector_t)page->index << (PAGE_SHIFT - bbits);

    // 遍历页缓冲区所有的页,bh->b_this_page存储着下一页的指针
	for(bh = head, block_start = 0; bh != head || !block_start;
	    block++, block_start=block_end, bh = bh->b_this_page) {
        
        // 一块数据的终点
		block_end = block_start + blocksize;

        // 如果这块数据不在页的范围内,继续循环
		if (block_end <= from || block_start >= to) {
            // 如果页和buffer_head的最新标志不同,则把buffer_head改成和页相同的
            // todo: 为什么要在这里判断??
			if (PageUptodate(page)) {
				if (!buffer_uptodate(bh))
					set_buffer_uptodate(bh);
			}
			continue;
		}
        // 清除new标志
		if (buffer_new(bh))
			clear_buffer_new(bh);

        // 如果bh还没映射,则映射之
		if (!buffer_mapped(bh)) {
			WARN_ON(bh->b_size != blocksize);

            // get_block是各个文件系统传进来用于获取块的函数,
            // 将块上的内容,填到页面上
			if (get_block) {
				err = get_block(inode, block, bh, 1);
				if (err)
					break;
			} else {
				iomap_to_bh(inode, block, bh, iomap);
			}

			if (buffer_new(bh)) { // 如果是新映射的
				clean_bdev_bh_alias(bh);

				if (PageUptodate(page)) {
                    // 如果页内容是新的,则清除相应标志,继续循环
					clear_buffer_new(bh);
					set_buffer_uptodate(bh);
					mark_buffer_dirty(bh);
					continue;
				}

                // 如果块的起始点和页的起始点重合,则把不需要的位置都清0
				if (block_end > to || block_start < from)
					zero_user_segments(page,
						to, block_end,
						block_start, from);
				continue;
			}
		}
        // 同步bh和页面的uptodate标志, 继续循环
		if (PageUptodate(page)) {
			if (!buffer_uptodate(bh))
				set_buffer_uptodate(bh);
			continue; 
		}

        // 如果数据不是最新的,发起读操作
		if (!buffer_uptodate(bh) && !buffer_delay(bh) &&
		    !buffer_unwritten(bh) &&
		     (block_start < from || block_end > to)) {
            // 这个从磁盘上直接读
			ll_rw_block(REQ_OP_READ, 0, 1, &bh);
			*wait_bh++=bh;
		}
	}
	
    // 有等待读盘的buffer,要等他们完成
	while(wait_bh > wait) {
		wait_on_buffer(*--wait_bh);
        // 如果读完,数据还不是最新的,那就出错了
		if (!buffer_uptodate(*wait_bh))
			err = -EIO;
	}
    // 如果有错误,就把各个页面清0
	if (unlikely(err))
		page_zero_new_buffers(page, from, to);
	return err;
}

int generic_write_end(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned copied,
			struct page *page, void *fsdata)
{
	struct inode *inode = mapping->host;
	loff_t old_size = inode->i_size;
	bool i_size_changed = false;

    // 向磁盘提交写请求
	copied = block_write_end(file, mapping, pos, len, copied, page, fsdata);

    // 如果写入的数据超过了原来的大小,则修改inode->i_size
	if (pos + copied > inode->i_size) {
		i_size_write(inode, pos + copied);
		i_size_changed = true;
	}

	unlock_page(page);
	put_page(page);

    // 把页标脏
	if (old_size < pos)
		pagecache_isize_extended(inode, old_size, pos);
	
    // 如果大小改变了,把inode标脏
	if (i_size_changed)
		mark_inode_dirty(inode);
	return copied;
}

int block_write_end(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned copied,
			struct page *page, void *fsdata)
{
	struct inode *inode = mapping->host;
	unsigned start;

    // 数据起点
	start = pos & (PAGE_SIZE - 1);

    // 如果复制数据失败,则把已经复制的清0
	if (unlikely(copied < len)) {
		if (!PageUptodate(page))
			copied = 0;

		page_zero_new_buffers(page, start+copied, start+len);
	}

    // 刷新dcache缓存??
	flush_dcache_page(page);

	__block_commit_write(inode, page, start, start+copied);

	return copied;
}

static int __block_commit_write(struct inode *inode, struct page *page,
		unsigned from, unsigned to)
{
	unsigned block_start, block_end;
	int partial = 0;
	unsigned blocksize;
	struct buffer_head *bh, *head;

	bh = head = page_buffers(page);
	blocksize = bh->b_size;

	block_start = 0;
	do {
		block_end = block_start + blocksize;
		if (block_end <= from || block_start >= to) {
			if (!buffer_uptodate(bh))
				partial = 1;
		} else {
			set_buffer_uptodate(bh);
			mark_buffer_dirty(bh);
		}
		clear_buffer_new(bh);

		block_start = block_end;
		bh = bh->b_this_page;
	} while (bh != head);

	/*
	 * If this is a partial write which happened to make all buffers
	 * uptodate then we can optimize away a bogus readpage() for
	 * the next read(). Here we 'discover' whether the page went
	 * uptodate as a result of this (potentially partial) write.
	 */
	if (!partial)
		SetPageUptodate(page);
	return 0;
}
```