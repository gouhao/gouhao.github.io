```c
static int ext4_writepage(struct page *page,
			  struct writeback_control *wbc)
{
	int ret = 0;
	loff_t size;
	unsigned int len;
	struct buffer_head *page_bufs = NULL;
	struct inode *inode = page->mapping->host;
	struct ext4_io_submit io_submit;
	bool keep_towrite = false;

	// 文件系统已关闭
	if (unlikely(ext4_forced_shutdown(EXT4_SB(inode->i_sb)))) {
		inode->i_mapping->a_ops->invalidatepage(page, 0, PAGE_SIZE);
		unlock_page(page);
		return -EIO;
	}

	trace_ext4_writepage(page);
	// inode大小
	size = i_size_read(inode);
	// 最大写一页
	if (page->index == size >> PAGE_SHIFT &&
	    !ext4_verity_in_progress(inode))
		len = size & ~PAGE_MASK;
	else
		len = PAGE_SIZE;

	// 若不是其它内核子系统的bug, 这个应该永远不会发生
	if (!page_has_buffers(page)) {
		ext4_warning_inode(inode,
		   "page %lu does not have buffers attached", page->index);
		ClearPageDirty(page);
		unlock_page(page);
		return 0;
	}

	// 获取页的buffer
	page_bufs = page_buffers(page);
	/*
	 * We cannot do block allocation or other extent handling in this
	 * function. If there are buffers needing that, we have to redirty
	 * the page. But we may reach here when we do a journal commit via
	 * journal_submit_inode_data_buffers() and in that case we must write
	 * allocated buffers to achieve data=ordered mode guarantees.
	 *
	 * Also, if there is only one buffer per page (the fs block
	 * size == the page size), if one buffer needs block
	 * allocation or needs to modify the extent tree to clear the
	 * unwritten flag, we know that the page can't be written at
	 * all, so we might as well refuse the write immediately.
	 * Unfortunately if the block size != page size, we can't as
	 * easily detect this case using ext4_walk_page_buffers(), but
	 * for the extremely common case, this is an optimization that
	 * skips a useless round trip through ext4_bio_write_page().
	 */
	// 遍历内核所有的页, 延迟写?
	if (ext4_walk_page_buffers(NULL, page_bufs, 0, len, NULL,
				   ext4_bh_delay_or_unwritten)) {
		redirty_page_for_writepage(wbc, page);
		if ((current->flags & PF_MEMALLOC) ||
		    (inode->i_sb->s_blocksize == PAGE_SIZE)) {
			/*
			 * For memory cleaning there's no point in writing only
			 * some buffers. So just bail out. Warn if we came here
			 * from direct reclaim.
			 */
			WARN_ON_ONCE((current->flags & (PF_MEMALLOC|PF_KSWAPD))
							== PF_MEMALLOC);
			unlock_page(page);
			return 0;
		}
		keep_towrite = true;
	}

	// journal模式
	if (PageChecked(page) && ext4_should_journal_data(inode))
		/*
		 * It's mmapped pagecache.  Add buffers and journal it.  There
		 * doesn't seem much point in redirtying the page here.
		 */
		return __ext4_journalled_writepage(page, len);

	// 初始化io_submit
	ext4_io_submit_init(&io_submit, wbc);
	// 分配io_end对象
	io_submit.io_end = ext4_init_io_end(inode, GFP_NOFS);
	if (!io_submit.io_end) {
		redirty_page_for_writepage(wbc, page);
		unlock_page(page);
		return -ENOMEM;
	}
	ret = ext4_bio_write_page(&io_submit, page, len, wbc, keep_towrite);
	ext4_io_submit(&io_submit);
	/* Drop io_end reference we got from init */
	ext4_put_io_end_defer(io_submit.io_end);
	return ret;
}

void ext4_io_submit_init(struct ext4_io_submit *io,
			 struct writeback_control *wbc)
{
	io->io_wbc = wbc;
	io->io_bio = NULL;
	io->io_end = NULL;
}

ext4_io_end_t *ext4_init_io_end(struct inode *inode, gfp_t flags)
{
	// 分配io_end对象
	ext4_io_end_t *io_end = kmem_cache_zalloc(io_end_cachep, flags);

	// 初始之
	if (io_end) {
		// inode
		io_end->inode = inode;
		INIT_LIST_HEAD(&io_end->list);
		INIT_LIST_HEAD(&io_end->list_vec);
		// 引用计数
		atomic_set(&io_end->count, 1);
	}
	return io_end;
}

int ext4_bio_write_page(struct ext4_io_submit *io,
			struct page *page,
			int len,
			struct writeback_control *wbc,
			bool keep_towrite)
{
	struct page *bounce_page = NULL;
	struct inode *inode = page->mapping->host;
	unsigned block_start;
	struct buffer_head *bh, *head;
	int ret = 0;
	int nr_submitted = 0;
	int nr_to_submit = 0;

	// page没有锁
	BUG_ON(!PageLocked(page));
	// page正在回写
	BUG_ON(PageWriteback(page));

	// what?
	if (keep_towrite)
		set_page_writeback_keepwrite(page);
	else
		set_page_writeback(page);
	// 清除页错误状态
	ClearPageError(page);

	/*
	 * Comments copied from block_write_full_page:
	 *
	 * The page straddles i_size.  It must be zeroed out on each and every
	 * writepage invocation because it may be mmapped.  "A file is mapped
	 * in multiples of the page size.  For a file that is not a multiple of
	 * the page size, the remaining memory is zeroed when mapped, and
	 * writes to that region are not written out to the file."
	 */
	// 把page清0
	if (len < PAGE_SIZE)
		zero_user_segment(page, len, PAGE_SIZE);
	/*
	 * In the first loop we prepare and mark buffers to submit. We have to
	 * mark all buffers in the page before submitting so that
	 * end_page_writeback() cannot be called from ext4_bio_end_io() when IO
	 * on the first buffer finishes and we are still working on submitting
	 * the second buffer.
	 */
	// 取出bh
	bh = head = page_buffers(page);
	do {
		block_start = bh_offset(bh);
		// what ?
		if (block_start >= len) {
			clear_buffer_dirty(bh);
			set_buffer_uptodate(bh);
			continue;
		}
		// buffer没脏?
		if (!buffer_dirty(bh) || buffer_delay(bh) ||
		    !buffer_mapped(bh) || buffer_unwritten(bh)) {
			/* A hole? We can safely clear the dirty bit */
			if (!buffer_mapped(bh))
				clear_buffer_dirty(bh);
			if (io->io_bio)
				ext4_io_submit(io);
			continue;
		}
		// 清除新标志
		if (buffer_new(bh))
			clear_buffer_new(bh);
		// 设置异步写
		set_buffer_async_write(bh);
		nr_to_submit++;
	} while ((bh = bh->b_this_page) != head);

	bh = head = page_buffers(page);

	/*
	 * If any blocks are being written to an encrypted file, encrypt them
	 * into a bounce page.  For simplicity, just encrypt until the last
	 * block which might be needed.  This may cause some unneeded blocks
	 * (e.g. holes) to be unnecessarily encrypted, but this is rare and
	 * can't happen in the common case of blocksize == PAGE_SIZE.
	 */
	// 加密相关, 后面看
	if (fscrypt_inode_uses_fs_layer_crypto(inode) && nr_to_submit) {
		gfp_t gfp_flags = GFP_NOFS;
		unsigned int enc_bytes = round_up(len, i_blocksize(inode));

		/*
		 * Since bounce page allocation uses a mempool, we can only use
		 * a waiting mask (i.e. request guaranteed allocation) on the
		 * first page of the bio.  Otherwise it can deadlock.
		 */
		if (io->io_bio)
			gfp_flags = GFP_NOWAIT | __GFP_NOWARN;
	retry_encrypt:
		bounce_page = fscrypt_encrypt_pagecache_blocks(page, enc_bytes,
							       0, gfp_flags);
		if (IS_ERR(bounce_page)) {
			ret = PTR_ERR(bounce_page);
			if (ret == -ENOMEM &&
			    (io->io_bio || wbc->sync_mode == WB_SYNC_ALL)) {
				gfp_flags = GFP_NOFS;
				if (io->io_bio)
					ext4_io_submit(io);
				else
					gfp_flags |= __GFP_NOFAIL;
				congestion_wait(BLK_RW_ASYNC, HZ/50);
				goto retry_encrypt;
			}

			printk_ratelimited(KERN_ERR "%s: ret = %d\n", __func__, ret);
			redirty_page_for_writepage(wbc, page);
			do {
				clear_buffer_async_write(bh);
				bh = bh->b_this_page;
			} while (bh != head);
			goto unlock;
		}
	}

	// 提交buffer
	do {
		if (!buffer_async_write(bh))
			continue;
		io_submit_add_bh(io, inode,
				 bounce_page ? bounce_page : page, bh);
		nr_submitted++;
		clear_buffer_dirty(bh);
	} while ((bh = bh->b_this_page) != head);

unlock:
	unlock_page(page);
	/* Nothing submitted - we have to end page writeback */
	if (!nr_submitted)
		end_page_writeback(page);
	return ret;
}

static void io_submit_add_bh(struct ext4_io_submit *io,
			     struct inode *inode,
			     struct page *page,
			     struct buffer_head *bh)
{
	int ret;

	// 块号不连续,则直接提交
	if (io->io_bio && (bh->b_blocknr != io->io_next_block ||
			   !fscrypt_mergeable_bio_bh(io->io_bio, bh))) {
submit_and_retry:
		ext4_io_submit(io);
	}
	// 分配一个新的io_bio
	if (io->io_bio == NULL) {
		io_submit_init_bio(io, bh);
		io->io_bio->bi_write_hint = inode->i_write_hint;
	}
	ret = bio_add_page(io->io_bio, page, bh->b_size, bh_offset(bh));
	if (ret != bh->b_size)
		goto submit_and_retry;
	wbc_account_cgroup_owner(io->io_wbc, page, bh->b_size);
	io->io_next_block++;
}

static void io_submit_init_bio(struct ext4_io_submit *io,
			       struct buffer_head *bh)
{
	struct bio *bio;

	/*
	 * 当设置__GFP_DIRECT_RECLAIM时, bio_alloc总会成功
	 * #define GFP_NOIO	(__GFP_RECLAIM)
	 * #define __GFP_RECLAIM ((__force gfp_t)(___GFP_DIRECT_RECLAIM|___GFP_KSWAPD_RECLAIM))
	 * BIO_MAX_PAGES: 256
	 * 
	 */
	bio = bio_alloc(GFP_NOIO, BIO_MAX_PAGES);
	fscrypt_set_bio_crypt_ctx_bh(bio, bh, GFP_NOIO);
	bio->bi_iter.bi_sector = bh->b_blocknr * (bh->b_size >> 9);
	bio_set_dev(bio, bh->b_bdev);
	bio->bi_end_io = ext4_end_bio;
	bio->bi_private = ext4_get_io_end(io->io_end);
	io->io_bio = bio;
	io->io_next_block = bh->b_blocknr;
	wbc_init_bio(io->io_wbc, bio);
}

void ext4_io_submit(struct ext4_io_submit *io)
{
	struct bio *bio = io->io_bio;

	if (bio) {
		int io_op_flags = io->io_wbc->sync_mode == WB_SYNC_ALL ?
				  REQ_SYNC : 0;
		io->io_bio->bi_write_hint = io->io_end->inode->i_write_hint;
		bio_set_op_attrs(io->io_bio, REQ_OP_WRITE, io_op_flags);
		submit_bio(io->io_bio);
	}
	io->io_bio = NULL;
}
```