# 块分配器
源码基于5.10

## 1. ext4_mb_new_blocks
```c
ext4_fsblk_t ext4_mb_new_blocks(handle_t *handle,
				struct ext4_allocation_request *ar, int *errp)
{
	struct ext4_allocation_context *ac = NULL;
	struct ext4_sb_info *sbi;
	struct super_block *sb;
	ext4_fsblk_t block = 0;
	unsigned int inquota = 0;
	unsigned int reserv_clstrs = 0;
	u64 seq;

	might_sleep();
	// 超级块
	sb = ar->inode->i_sb;
	sbi = EXT4_SB(sb);

	trace_ext4_request_blocks(ar);

	// 如果是在replay阶段, 就从块位图里简单的找一个块.
	if (sbi->s_mount_state & EXT4_FC_REPLAY)
		return ext4_mb_new_blocks_simple(handle, ar, errp);

	/* 如果是quota文件，则允许使用用户保留的 */
	if (ext4_is_quota_file(ar->inode))
		ar->flags |= EXT4_MB_USE_ROOT_BLOCKS;

	// 不使用保留的. todo: 没太看懂
	if ((ar->flags & EXT4_MB_DELALLOC_RESERVED) == 0) {
		// 检查是否有len的空闲块,
		while (ar->len &&
			// ext4_claim_free_clusters返回非0表示没有空闲块
			ext4_claim_free_clusters(sbi, ar->len, ar->flags)) {

			// 让出cpu让别人释放一会
			cond_resched();
			// 长度减半
			ar->len = ar->len >> 1;
		}
		
		// 走到这儿如果长度为0, 则表示没有空间了,分配失败
		if (!ar->len) {
			ext4_mb_show_pa(sb);
			*errp = -ENOSPC;
			return 0;
		}

		reserv_clstrs = ar->len;
		
		if (ar->flags & EXT4_MB_USE_ROOT_BLOCKS) {
			// 有使用根块的权限
			dquot_alloc_block_nofail(ar->inode,
						 EXT4_C2B(sbi, ar->len));
		} else {
			// 用限额分配块
			while (ar->len &&
				dquot_alloc_block(ar->inode,
						// EXT4_C2B是把cluster转换成块号
						  EXT4_C2B(sbi, ar->len))) {

				ar->flags |= EXT4_MB_HINT_NOPREALLOC;
				ar->len--;
			}
		}
		inquota = ar->len;
		if (ar->len == 0) {
			*errp = -EDQUOT;
			goto out;
		}
	}

	// 分配上下文
	ac = kmem_cache_zalloc(ext4_ac_cachep, GFP_NOFS);
	if (!ac) {
		ar->len = 0;
		*errp = -ENOMEM;
		goto out;
	}

	// 初始化分配上下文
	*errp = ext4_mb_initialize_context(ac, ar);
	if (*errp) {
		ar->len = 0;
		goto out;
	}

	// 使用预分配的?
	ac->ac_op = EXT4_MB_HISTORY_PREALLOC;
	seq = this_cpu_read(discard_pa_seq);

	// 如果不使用预分配
	if (!ext4_mb_use_preallocated(ac)) {
		// 普通分配
		ac->ac_op = EXT4_MB_HISTORY_ALLOC;
		// 把请求标准化
		ext4_mb_normalize_request(ac, ar);

		// 给ac分配一个ext4_prealloc_space对象
		*errp = ext4_mb_pa_alloc(ac);
		if (*errp)
			goto errout;
repeat:
		// 终于要分配了
		*errp = ext4_mb_regular_allocator(ac);

		// 有错误，释放ac，丢弃已分配的块
		if (*errp) {
			ext4_mb_pa_free(ac);
			ext4_discard_allocated_blocks(ac);
			goto errout;
		}
		// todo: what?
		if (ac->ac_status == AC_STATUS_FOUND &&
			ac->ac_o_ex.fe_len >= ac->ac_f_ex.fe_len)
			ext4_mb_pa_free(ac);
	}
	if (likely(ac->ac_status == AC_STATUS_FOUND)) {
		// 分配块成功

		// 在位图里标记这些块已经被使用
		*errp = ext4_mb_mark_diskspace_used(ac, handle, reserv_clstrs);
		if (*errp) {
			// 出错，丢弃已分配的块
			ext4_discard_allocated_blocks(ac);
			goto errout;
		} else {
			// 把组内的偏移转成全局的块号
			block = ext4_grp_offs_to_block(sb, &ac->ac_b_ex);
			// 最终分配的长度
			ar->len = ac->ac_b_ex.fe_len;
		}
	} else {
		// 分配块失败

		// 丢弃掉预分配的,如果需要重试,则重试
		if (ext4_mb_discard_preallocations_should_retry(sb, ac, &seq))
			goto repeat;
		// 释放ac
		ext4_mb_pa_free(ac);
		*errp = -ENOSPC;
	}

errout:
	// 有错误
	if (*errp) {
		ac->ac_b_ex.fe_len = 0;
		ar->len = 0;
		ext4_mb_show_ac(ac);
	}
	ext4_mb_release_context(ac);
out:
	if (ac)
		kmem_cache_free(ext4_ac_cachep, ac);
	if (inquota && ar->len < inquota)
		dquot_free_block(ar->inode, EXT4_C2B(sbi, inquota - ar->len));
	if (!ar->len) {
		if ((ar->flags & EXT4_MB_DELALLOC_RESERVED) == 0)
			/* release all the reserved blocks if non delalloc */
			percpu_counter_sub(&sbi->s_dirtyclusters_counter,
						reserv_clstrs);
	}

	trace_ext4_allocate_blocks(ar, (unsigned long long)block);

	return block;
}

static int ext4_mb_pa_alloc(struct ext4_allocation_context *ac)
{
	struct ext4_prealloc_space *pa;

	BUG_ON(ext4_pspace_cachep == NULL);
	// 分配pa
	pa = kmem_cache_zalloc(ext4_pspace_cachep, GFP_NOFS);
	if (!pa)
		return -ENOMEM;
	// 引用数量设置为1
	atomic_set(&pa->pa_count, 1);
	ac->ac_pa = pa;
	return 0;
}
```

## 11. ext4_mb_regular_allocator
```c
static noinline_for_stack int
ext4_mb_regular_allocator(struct ext4_allocation_context *ac)
{
	ext4_group_t prefetch_grp = 0, ngroups, group, i;
	int cr = -1;
	int err = 0, first_err = 0;
	unsigned int nr = 0, prefetch_ios = 0;
	struct ext4_sb_info *sbi;
	struct super_block *sb;
	struct ext4_buddy e4b;
	int lost;

	// 超级块信息
	sb = ac->ac_sb;
	sbi = EXT4_SB(sb);
	// 有多少个组
	ngroups = ext4_get_groups_count(sb);
	
	// 非extent限制到blockfile_groups
	if (!(ext4_test_inode_flag(ac->ac_inode, EXT4_INODE_EXTENTS)))
		ngroups = sbi->s_blockfile_groups;

	// 已经找到了不应该走这个函数
	BUG_ON(ac->ac_status == AC_STATUS_FOUND);

	// 先试一下目标块
	err = ext4_mb_find_by_goal(ac, &e4b);
	// 出错或者找到了
	if (err || ac->ac_status == AC_STATUS_FOUND)
		goto out;

	// 只找目标块, 则退出. 这个标志应该很少用吧
	if (unlikely(ac->ac_flags & EXT4_MB_HINT_GOAL_ONLY))
		goto out;

	// 把长度转换成2的幂
	i = fls(ac->ac_g_ex.fe_len);
	ac->ac_2order = 0;
	// todo: ?
	if (i >= sbi->s_mb_order2_reqs && i <= sb->s_blocksize_bits + 2) {
		/*
		 * This should tell if fe_len is exactly power of 2
		 */
		if ((ac->ac_g_ex.fe_len & (~(1 << (i - 1)))) == 0)
			ac->ac_2order = array_index_nospec(i - 1,
							   sb->s_blocksize_bits + 2);
	}

	// 流式分配
	if (ac->ac_flags & EXT4_MB_STREAM_ALLOC) {
		spin_lock(&sbi->s_md_lock);
		// 使用上次的组
		ac->ac_g_ex.fe_group = sbi->s_mb_last_group;
		// 从上次开始的地方分配
		ac->ac_g_ex.fe_start = sbi->s_mb_last_start;
		spin_unlock(&sbi->s_md_lock);
	}

	// todo: cr?
	cr = ac->ac_2order ? 0 : 1;
	/*
	 * cr == 0 try to get exact allocation,
	 * cr == 3  try to get anything
	 */
repeat:
	for (; cr < 4 && ac->ac_status == AC_STATUS_CONTINUE; cr++) {
		ac->ac_criteria = cr;
		// 从目标组开始
		group = ac->ac_g_ex.fe_group;
		prefetch_grp = group;

		for (i = 0; i < ngroups; group++, i++) {
			int ret = 0;
			cond_resched();
			// 到了最大组再从头开始
			if (group >= ngroups)
				group = 0;

			// 当前组到了预读点 && (cr > 1 || 预取次数没有超过限制)
			if ((prefetch_grp == group) &&
			    (cr > 1 ||
			     prefetch_ios < sbi->s_mb_prefetch_limit)) {
				unsigned int curr_ios = prefetch_ios;

				// 预取数量
				nr = sbi->s_mb_prefetch;

				// 有灵活组特性
				if (ext4_has_feature_flex_bg(sb)) {
					// 每个灵活组几个组
					nr = 1 << sbi->s_log_groups_per_flex;
					// what ?
					nr -= group & (nr - 1);
					// 预取组的最小值
					nr = min(nr, sbi->s_mb_prefetch);
				}
				// 预读组, 返回值是下次预取的位置, prefetch_ios返回的是
				// 提交io的数量
				prefetch_grp = ext4_mb_prefetch(sb, group,
							nr, &prefetch_ios);
				if (prefetch_ios == curr_ios)
					nr = 0;
			}

			// 检查这个组是不是适合分配
			ret = ext4_mb_good_group_nolock(ac, group, cr);
			if (ret <= 0) {
				// 不适合
				if (!first_err)
					first_err = ret;
				continue;
			}
			// 加载兄弟的block位图。todo: what is buddy bitmap
			err = ext4_mb_load_buddy(sb, group, &e4b);
			if (err)
				goto out;

			ext4_lock_group(sb, group);

			// 再检查一次group是否有空闲的块适合分配, 因为上面加锁了, 获得锁后情况可能变了
			ret = ext4_mb_good_group(ac, group, cr);
			if (ret == 0) {
				ext4_unlock_group(sb, group);
				ext4_mb_unload_buddy(&e4b);
				continue;
			}

			// 扫描次数
			ac->ac_groups_scanned++;

			// 根据cr走不同的扫描
			if (cr == 0)
				ext4_mb_simple_scan_group(ac, &e4b);
			else if (cr == 1 && sbi->s_stripe &&
					!(ac->ac_g_ex.fe_len % sbi->s_stripe))
				ext4_mb_scan_aligned(ac, &e4b);
			else
				ext4_mb_complex_scan_group(ac, &e4b);

			ext4_unlock_group(sb, group);
			ext4_mb_unload_buddy(&e4b);

			// 不等于continue就是找到或出错了
			if (ac->ac_status != AC_STATUS_CONTINUE)
				break;
		}
	}

	// todo: what?
	if (ac->ac_b_ex.fe_len > 0 && ac->ac_status != AC_STATUS_FOUND &&
	    !(ac->ac_flags & EXT4_MB_HINT_FIRST)) {
		/*
		 * We've been searching too long. Let's try to allocate
		 * the best chunk we've found so far
		 */
		ext4_mb_try_best_found(ac, &e4b);
		if (ac->ac_status != AC_STATUS_FOUND) {
			/*
			 * Someone more lucky has already allocated it.
			 * The only thing we can do is just take first
			 * found block(s)
			 */
			lost = atomic_inc_return(&sbi->s_mb_lost_chunks);
			mb_debug(sb, "lost chunk, group: %u, start: %d, len: %d, lost: %d\n",
				 ac->ac_b_ex.fe_group, ac->ac_b_ex.fe_start,
				 ac->ac_b_ex.fe_len, lost);

			ac->ac_b_ex.fe_group = 0;
			ac->ac_b_ex.fe_start = 0;
			ac->ac_b_ex.fe_len = 0;
			ac->ac_status = AC_STATUS_CONTINUE;
			ac->ac_flags |= EXT4_MB_HINT_FIRST;
			cr = 3;
			goto repeat;
		}
	}
out:
	// 有错误
	if (!err && ac->ac_status != AC_STATUS_FOUND && first_err)
		err = first_err;

	mb_debug(sb, "Best len %d, origin len %d, ac_status %u, ac_flags 0x%x, cr %d ret %d\n",
		 ac->ac_b_ex.fe_len, ac->ac_o_ex.fe_len, ac->ac_status,
		 ac->ac_flags, cr, err);

	if (nr)
		ext4_mb_prefetch_fini(sb, prefetch_grp, nr);

	return err;
}

static noinline_for_stack
int ext4_mb_find_by_goal(struct ext4_allocation_context *ac,
				struct ext4_buddy *e4b)
{
	ext4_group_t group = ac->ac_g_ex.fe_group;
	int max;
	int err;
	struct ext4_sb_info *sbi = EXT4_SB(ac->ac_sb);
	struct ext4_group_info *grp = ext4_get_group_info(ac->ac_sb, group);
	struct ext4_free_extent ex;

	// 没有找目标块退出
	if (!(ac->ac_flags & EXT4_MB_HINT_TRY_GOAL))
		return 0;
	// 该组的空闲块为0
	if (grp->bb_free == 0)
		return 0;

	err = ext4_mb_load_buddy(ac->ac_sb, group, e4b);
	if (err)
		return err;

	if (unlikely(EXT4_MB_GRP_BBITMAP_CORRUPT(e4b->bd_info))) {
		ext4_mb_unload_buddy(e4b);
		return 0;
	}

	ext4_lock_group(ac->ac_sb, group);
	max = mb_find_extent(e4b, ac->ac_g_ex.fe_start,
			     ac->ac_g_ex.fe_len, &ex);
	ex.fe_logical = 0xDEADFA11; /* debug value */

	if (max >= ac->ac_g_ex.fe_len && ac->ac_g_ex.fe_len == sbi->s_stripe) {
		ext4_fsblk_t start;

		start = ext4_group_first_block_no(ac->ac_sb, e4b->bd_group) +
			ex.fe_start;
		/* use do_div to get remainder (would be 64-bit modulo) */
		if (do_div(start, sbi->s_stripe) == 0) {
			ac->ac_found++;
			ac->ac_b_ex = ex;
			ext4_mb_use_best_found(ac, e4b);
		}
	} else if (max >= ac->ac_g_ex.fe_len) {
		BUG_ON(ex.fe_len <= 0);
		BUG_ON(ex.fe_group != ac->ac_g_ex.fe_group);
		BUG_ON(ex.fe_start != ac->ac_g_ex.fe_start);
		ac->ac_found++;
		ac->ac_b_ex = ex;
		ext4_mb_use_best_found(ac, e4b);
	} else if (max > 0 && (ac->ac_flags & EXT4_MB_HINT_MERGE)) {
		/* Sometimes, caller may want to merge even small
		 * number of blocks to an existing extent */
		BUG_ON(ex.fe_len <= 0);
		BUG_ON(ex.fe_group != ac->ac_g_ex.fe_group);
		BUG_ON(ex.fe_start != ac->ac_g_ex.fe_start);
		ac->ac_found++;
		ac->ac_b_ex = ex;
		ext4_mb_use_best_found(ac, e4b);
	}
	ext4_unlock_group(ac->ac_sb, group);
	ext4_mb_unload_buddy(e4b);

	return 0;
}

static int ext4_mb_load_buddy(struct super_block *sb, ext4_group_t group,
			      struct ext4_buddy *e4b)
{
	return ext4_mb_load_buddy_gfp(sb, group, e4b, GFP_NOFS);
}

static noinline_for_stack int
ext4_mb_load_buddy_gfp(struct super_block *sb, ext4_group_t group,
		       struct ext4_buddy *e4b, gfp_t gfp)
{
	int blocks_per_page;
	int block;
	int pnum;
	int poff;
	struct page *page;
	int ret;
	struct ext4_group_info *grp;
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	// buddy信息存储在专门的inode里
	struct inode *inode = sbi->s_buddy_cache;

	might_sleep();
	mb_debug(sb, "load group %u\n", group);

	// 每页的块数
	blocks_per_page = PAGE_SIZE / sb->s_blocksize;
	// 组信息
	grp = ext4_get_group_info(sb, group);

	// 块大小
	e4b->bd_blkbits = sb->s_blocksize_bits;
	// group info
	e4b->bd_info = grp;
	// 超级块
	e4b->bd_sb = sb;
	// 组号
	e4b->bd_group = group;
	e4b->bd_buddy_page = NULL;
	e4b->bd_bitmap_page = NULL;

	// 组需要先初始化
	if (unlikely(EXT4_MB_GRP_NEED_INIT(grp))) {
		/*
		 * we need full data about the group
		 * to make a good selection
		 */
		ret = ext4_mb_init_group(sb, group, gfp);
		if (ret)
			return ret;
	}

	/*
	 * buddy缓存节点存储块位图和块信息在连续的块里，所以每个组
	 * 我们需要2个块
	 */
	block = group * 2;
	// 页号
	pnum = block / blocks_per_page;
	// 页内偏移
	poff = block % blocks_per_page;

	// 获取对应的页
	page = find_get_page_flags(inode->i_mapping, pnum, FGP_ACCESSED);
	if (page == NULL || !PageUptodate(page)) {
		// 如果page为空或者不是最新的，则重新创建一个
		if (page)
			/*
			 * drop the page reference and try
			 * to get the page with lock. If we
			 * are not uptodate that implies
			 * somebody just created the page but
			 * is yet to initialize the same. So
			 * wait for it to initialize.
			 */
			put_page(page);
		page = find_or_create_page(inode->i_mapping, pnum, gfp);
		if (page) {
			BUG_ON(page->mapping != inode->i_mapping);
			if (!PageUptodate(page)) {
				ret = ext4_mb_init_cache(page, NULL, gfp);
				if (ret) {
					unlock_page(page);
					goto err;
				}
				mb_cmp_bitmaps(e4b, page_address(page) +
					       (poff * sb->s_blocksize));
			}
			unlock_page(page);
		}
	}
	if (page == NULL) {
		ret = -ENOMEM;
		goto err;
	}
	// 还不是最新的那就出错了
	if (!PageUptodate(page)) {
		ret = -EIO;
		goto err;
	}

	// 记录页和位图的起点
	e4b->bd_bitmap_page = page;
	e4b->bd_bitmap = page_address(page) + (poff * sb->s_blocksize);

	// 兄弟块的页及偏移
	block++;
	pnum = block / blocks_per_page;
	poff = block % blocks_per_page;

	// 和上面类似，找页，如果没找到就创建
	page = find_get_page_flags(inode->i_mapping, pnum, FGP_ACCESSED);
	if (page == NULL || !PageUptodate(page)) {
		if (page)
			put_page(page);
		page = find_or_create_page(inode->i_mapping, pnum, gfp);
		if (page) {
			BUG_ON(page->mapping != inode->i_mapping);
			if (!PageUptodate(page)) {
				ret = ext4_mb_init_cache(page, e4b->bd_bitmap,
							 gfp);
				if (ret) {
					unlock_page(page);
					goto err;
				}
			}
			unlock_page(page);
		}
	}
	if (page == NULL) {
		ret = -ENOMEM;
		goto err;
	}
	if (!PageUptodate(page)) {
		ret = -EIO;
		goto err;
	}

	// 设置 buddy 页的地址和偏移
	e4b->bd_buddy_page = page;
	e4b->bd_buddy = page_address(page) + (poff * sb->s_blocksize);

	return 0;

err:
	if (page)
		put_page(page);
	if (e4b->bd_bitmap_page)
		put_page(e4b->bd_bitmap_page);
	if (e4b->bd_buddy_page)
		put_page(e4b->bd_buddy_page);
	e4b->bd_buddy = NULL;
	e4b->bd_bitmap = NULL;
	return ret;
}

/* The buddy information is attached the buddy cache inode
 * for convenience. The information regarding each group
 * is loaded via ext4_mb_load_buddy. The information involve
 * block bitmap and buddy information. The information are
 * stored in the inode as
 *
 * {                        page                        }
 * [ group 0 bitmap][ group 0 buddy] [group 1][ group 1]...
 *
 *
 * one block each for bitmap and buddy information.
 * So for each group we take up 2 blocks. A page can
 * contain blocks_per_page (PAGE_SIZE / blocksize)  blocks.
 * So it can have information regarding groups_per_page which
 * is blocks_per_page/2
 *
 * Locking note:  This routine takes the block group lock of all groups
 * for this page; do not hold this lock when calling this routine!
 */
static int ext4_mb_init_cache(struct page *page, char *incore, gfp_t gfp)
{
	ext4_group_t ngroups;
	int blocksize;
	int blocks_per_page;
	int groups_per_page;
	int err = 0;
	int i;
	ext4_group_t first_group, group;
	int first_block;
	struct super_block *sb;
	struct buffer_head *bhs;
	struct buffer_head **bh = NULL;
	struct inode *inode;
	char *data;
	char *bitmap;
	struct ext4_group_info *grinfo;

	inode = page->mapping->host;
	sb = inode->i_sb;
	// 组数
	ngroups = ext4_get_groups_count(sb);
	// 块大小
	blocksize = i_blocksize(inode);
	// 每页存的块数
	blocks_per_page = PAGE_SIZE / blocksize;

	mb_debug(sb, "init page %lu\n", page->index);

	// 每页能放几个组的buddy信息，如上注释是 blocks_per_page/2
	groups_per_page = blocks_per_page >> 1;
	// 如果块大小和页大小相同时, 经过上面计算groups_per_page是0, 所以最小为1
	if (groups_per_page == 0)
		groups_per_page = 1;

	if (groups_per_page > 1) {
		// 如果每页存多个组, 则要动态分配bh指针数组
		i = sizeof(struct buffer_head *) * groups_per_page;
		bh = kzalloc(i, gfp);
		if (bh == NULL) {
			err = -ENOMEM;
			goto out;
		}
	} else
		bh = &bhs;

	// page里的第一个组号
	first_group = page->index * blocks_per_page / 2;

	// 遍历页里面的每个组
	for (i = 0, group = first_group; i < groups_per_page; i++, group++) {
		// 超过最后一个组
		if (group >= ngroups)
			break;

		// 获取组信息
		grinfo = ext4_get_group_info(sb, group);
		/*
		 * If page is uptodate then we came here after online resize
		 * which added some new uninitialized group info structs, so
		 * we must skip all initialized uptodate buddies on the page,
		 * which may be currently in use by an allocating task.
		 */
		// 页是最新的，且当前group不需要初始化，则继续
		if (PageUptodate(page) && !EXT4_MB_GRP_NEED_INIT(grinfo)) {
			bh[i] = NULL;
			continue;
		}
		// 读组的位图
		bh[i] = ext4_read_block_bitmap_nowait(sb, group, false);
		if (IS_ERR(bh[i])) {
			err = PTR_ERR(bh[i]);
			bh[i] = NULL;
			goto out;
		}
		mb_debug(sb, "read bitmap for group %u\n", group);
	}

	// 等上面位图读完，上面用的是nowait，非阻塞的
	for (i = 0, group = first_group; i < groups_per_page; i++, group++) {
		int err2;

		if (!bh[i])
			continue;
		err2 = ext4_wait_block_bitmap(sb, group, bh[i]);
		if (!err)
			err = err2;
	}

	// 页里面第一个块号
	first_block = page->index * blocks_per_page;
	for (i = 0; i < blocks_per_page; i++) {
		// 块号对应的组
		group = (first_block + i) >> 1;
		// 超过最大组
		if (group >= ngroups)
			break;

		// 当前组不需要初始化
		if (!bh[group - first_group])
			continue;

		// bh有问题，则跳过
		if (!buffer_verified(bh[group - first_group]))
			continue;
		err = 0;

		// 对应块地址
		data = page_address(page) + (i * blocksize);
		// 第1个块是位图
		bitmap = bh[group - first_group]->b_data;

		// (first_block + i) & 1 是buddy块，因为buddy是在位图后面，所以奇数的块号是buddy
		if ((first_block + i) & 1) {
			// 初始化buddy时必须有incore
			BUG_ON(incore == NULL);
			mb_debug(sb, "put buddy for group %u in page %lu/%x\n",
				group, page->index, i * blocksize);
			trace_ext4_mb_buddy_bitmap_load(sb, group);
			// 组信息
			grinfo = ext4_get_group_info(sb, group);
			grinfo->bb_fragments = 0;

			// todo: what is bb_counter?
			memset(grinfo->bb_counters, 0,
			       sizeof(*grinfo->bb_counters) *
				(sb->s_blocksize_bits+2));
			
			ext4_lock_group(sb, group);
			// 把块全部设成1
			memset(data, 0xff, blocksize);
			// 生成buddy信息
			ext4_mb_generate_buddy(sb, data, incore, group);
			ext4_unlock_group(sb, group);
			incore = NULL;
		} else {
			// 位图块
			BUG_ON(incore != NULL);
			mb_debug(sb, "put bitmap for group %u in page %lu/%x\n",
				group, page->index, i * blocksize);
			trace_ext4_mb_bitmap_load(sb, group);

			/* see comments in ext4_mb_put_pa() */
			ext4_lock_group(sb, group);
			// 把位图复制到bh里
			memcpy(data, bitmap, blocksize);

			// 把预分配的标记为使用
			ext4_mb_generate_from_pa(sb, data, group);
			ext4_mb_generate_from_freelist(sb, data, group);
			ext4_unlock_group(sb, group);

			// 设置incore,buddy会用这个位图来初始化
			incore = data;
		}
	}
	SetPageUptodate(page);

out:
	if (bh) {
		for (i = 0; i < groups_per_page; i++)
			brelse(bh[i]);
		if (bh != &bhs)
			kfree(bh);
	}
	return err;
}

static noinline_for_stack
void ext4_mb_generate_from_pa(struct super_block *sb, void *bitmap,
					ext4_group_t group)
{
	// 块组信息
	struct ext4_group_info *grp = ext4_get_group_info(sb, group);
	struct ext4_prealloc_space *pa;
	struct list_head *cur;
	ext4_group_t groupnr;
	ext4_grpblk_t start;
	int preallocated = 0;
	int len;

	/* all form of preallocation discards first load group,
	 * so the only competing code is preallocation use.
	 * we don't need any locking here
	 * notice we do NOT ignore preallocations with pa_deleted
	 * otherwise we could leave used blocks available for
	 * allocation in buddy when concurrent ext4_mb_put_pa()
	 * is dropping preallocation
	 */
	// 遍历预分配列表
	list_for_each(cur, &grp->bb_prealloc_list) {
		// 预分配空间
		pa = list_entry(cur, struct ext4_prealloc_space, pa_group_list);
		spin_lock(&pa->pa_lock);
		// 获取pa对应的组号和偏移
		ext4_get_group_no_and_offset(sb, pa->pa_pstart,
					     &groupnr, &start);
		len = pa->pa_len;
		spin_unlock(&pa->pa_lock);
		// 长度为0就不用标记了
		if (unlikely(len == 0))
			continue;
		// 怎么会组号不相等？？
		BUG_ON(groupnr != group);
		//标记这些预分配的正在使用
		ext4_set_bits(bitmap, start, len);
		preallocated += len;
	}
	mb_debug(sb, "preallocated %d for group %u\n", preallocated, group);
}

static void ext4_mb_generate_from_freelist(struct super_block *sb, void *bitmap,
						ext4_group_t group)
{
	struct rb_node *n;
	struct ext4_group_info *grp;
	struct ext4_free_data *entry;

	// 组信息
	grp = ext4_get_group_info(sb, group);
	// 空闲块
	n = rb_first(&(grp->bb_free_root));

	// 在位图上设置所有空闲块
	while (n) {
		entry = rb_entry(n, struct ext4_free_data, efd_node);
		ext4_set_bits(bitmap, entry->efd_start_cluster, entry->efd_count);
		n = rb_next(n);
	}
	return;
}

static noinline_for_stack
void ext4_mb_generate_buddy(struct super_block *sb,
				void *buddy, void *bitmap, ext4_group_t group)
{
	struct ext4_group_info *grp = ext4_get_group_info(sb, group);
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	// 组里最大的cluster数
	ext4_grpblk_t max = EXT4_CLUSTERS_PER_GROUP(sb);
	ext4_grpblk_t i = 0;
	ext4_grpblk_t first;
	ext4_grpblk_t len;
	unsigned free = 0;
	unsigned fragments = 0;
	// 当前时间？
	unsigned long long period = get_cycles();

	// 找第1个未使用的块
	i = mb_find_next_zero_bit(bitmap, max, 0);
	
	// 设置之
	grp->bb_first_free = i;
	while (i < max) {
		fragments++;
		first = i;
		// 找下在已设置的位
		i = mb_find_next_bit(bitmap, max, i);
		// 空闲长度
		len = i - first;
		// 编译空闲总量
		free += len;
		if (len > 1)
			ext4_mb_mark_free_simple(sb, buddy, first, len, grp);
		else
			// 只有1个页，统计之
			grp->bb_counters[0]++;
		if (i < max)
			i = mb_find_next_zero_bit(bitmap, max, i);
	}
	grp->bb_fragments = fragments;

	if (free != grp->bb_free) {
		ext4_grp_locked_error(sb, group, 0, 0,
				      "block bitmap and bg descriptor "
				      "inconsistent: %u vs %u free clusters",
				      free, grp->bb_free);
		/*
		 * If we intend to continue, we consider group descriptor
		 * corrupt and update bb_free using bitmap value
		 */
		grp->bb_free = free;
		ext4_mark_group_bitmap_corrupted(sb, group,
					EXT4_GROUP_INFO_BBITMAP_CORRUPT);
	}
	mb_set_largest_free_order(sb, grp);

	clear_bit(EXT4_GROUP_INFO_NEED_INIT_BIT, &(grp->bb_state));

	period = get_cycles() - period;
	spin_lock(&sbi->s_bal_lock);
	sbi->s_mb_buddies_generated++;
	sbi->s_mb_generation_time += period;
	spin_unlock(&sbi->s_bal_lock);
}

static noinline_for_stack
void ext4_mb_simple_scan_group(struct ext4_allocation_context *ac,
					struct ext4_buddy *e4b)
{
	struct super_block *sb = ac->ac_sb;
	struct ext4_group_info *grp = e4b->bd_info;
	void *buddy;
	int i;
	int k;
	int max;

	BUG_ON(ac->ac_2order <= 0);
	for (i = ac->ac_2order; i <= sb->s_blocksize_bits + 1; i++) {
		if (grp->bb_counters[i] == 0)
			continue;

		buddy = mb_find_buddy(e4b, i, &max);
		BUG_ON(buddy == NULL);

		k = mb_find_next_zero_bit(buddy, max, 0);
		if (k >= max) {
			ext4_grp_locked_error(ac->ac_sb, e4b->bd_group, 0, 0,
				"%d free clusters of order %d. But found 0",
				grp->bb_counters[i], i);
			ext4_mark_group_bitmap_corrupted(ac->ac_sb,
					 e4b->bd_group,
					EXT4_GROUP_INFO_BBITMAP_CORRUPT);
			break;
		}
		ac->ac_found++;

		ac->ac_b_ex.fe_len = 1 << i;
		ac->ac_b_ex.fe_start = k << i;
		ac->ac_b_ex.fe_group = e4b->bd_group;

		ext4_mb_use_best_found(ac, e4b);

		BUG_ON(ac->ac_f_ex.fe_len != ac->ac_g_ex.fe_len);

		if (EXT4_SB(sb)->s_mb_stats)
			atomic_inc(&EXT4_SB(sb)->s_bal_2orders);

		break;
	}
}
```

### 1.1 ext4_mb_initialize_context
```c
static noinline_for_stack int
ext4_mb_initialize_context(struct ext4_allocation_context *ac,
				struct ext4_allocation_request *ar)
{
	struct super_block *sb = ar->inode->i_sb;
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	struct ext4_super_block *es = sbi->s_es;
	ext4_group_t group;
	unsigned int len;
	ext4_fsblk_t goal;
	ext4_grpblk_t block;

	// 想要的块长度
	len = ar->len;

	// 一次最大只能分配cluster的数量
	if (len >= EXT4_CLUSTERS_PER_GROUP(sb))
		len = EXT4_CLUSTERS_PER_GROUP(sb);

	// 建议目标
	goal = ar->goal;
	// 如果目标不合法, 则使用设备的第一个数据块
	if (goal < le32_to_cpu(es->s_first_data_block) ||
			goal >= ext4_blocks_count(es))
		goal = le32_to_cpu(es->s_first_data_block);
	// 找到目标所在的组和偏移
	ext4_get_group_no_and_offset(sb, goal, &group, &block);

	// 最好的逻辑块
	ac->ac_b_ex.fe_logical = EXT4_LBLK_CMASK(sbi, ar->logical);

	// 意思是还没分配, 继续查找?
	ac->ac_status = AC_STATUS_CONTINUE;
	ac->ac_sb = sb;
	ac->ac_inode = ar->inode;

	// 设置块的原始ex
	ac->ac_o_ex.fe_logical = ac->ac_b_ex.fe_logical;
	ac->ac_o_ex.fe_group = group;
	ac->ac_o_ex.fe_start = block;
	ac->ac_o_ex.fe_len = len;

	// 把原始ex复制到目标ex里
	ac->ac_g_ex = ac->ac_o_ex;

	ac->ac_flags = ar->flags;

	/* 我们必須定义一个上下文, 我们将工作在文件或一个组, 实际上这是一个策略*/
	ext4_mb_group_or_file(ac);

	mb_debug(sb, "init ac: %u blocks @ %u, goal %u, flags 0x%x, 2^%d, "
			"left: %u/%u, right %u/%u to %swritable\n",
			(unsigned) ar->len, (unsigned) ar->logical,
			(unsigned) ar->goal, ac->ac_flags, ac->ac_2order,
			(unsigned) ar->lleft, (unsigned) ar->pleft,
			(unsigned) ar->lright, (unsigned) ar->pright,
			inode_is_open_for_write(ar->inode) ? "" : "non-");
	return 0;

}

static void ext4_mb_group_or_file(struct ext4_allocation_context *ac)
{
	struct ext4_sb_info *sbi = EXT4_SB(ac->ac_sb);
	int bsbits = ac->ac_sb->s_blocksize_bits;
	loff_t size, isize;

	if (!(ac->ac_flags & EXT4_MB_HINT_DATA))
		return;

	if (unlikely(ac->ac_flags & EXT4_MB_HINT_GOAL_ONLY))
		return;

	size = ac->ac_o_ex.fe_logical + EXT4_C2B(sbi, ac->ac_o_ex.fe_len);
	isize = (i_size_read(ac->ac_inode) + ac->ac_sb->s_blocksize - 1)
		>> bsbits;

	if ((size == isize) && !ext4_fs_is_busy(sbi) &&
	    !inode_is_open_for_write(ac->ac_inode)) {
		ac->ac_flags |= EXT4_MB_HINT_NOPREALLOC;
		return;
	}

	if (sbi->s_mb_group_prealloc <= 0) {
		ac->ac_flags |= EXT4_MB_STREAM_ALLOC;
		return;
	}

	/* don't use group allocation for large files */
	size = max(size, isize);
	if (size > sbi->s_mb_stream_request) {
		ac->ac_flags |= EXT4_MB_STREAM_ALLOC;
		return;
	}

	BUG_ON(ac->ac_lg != NULL);
	/*
	 * locality group prealloc space are per cpu. The reason for having
	 * per cpu locality group is to reduce the contention between block
	 * request from multiple CPUs.
	 */
	ac->ac_lg = raw_cpu_ptr(sbi->s_locality_groups);

	/* we're going to use group allocation */
	ac->ac_flags |= EXT4_MB_HINT_GROUP_ALLOC;

	/* serialize all allocations in the group */
	mutex_lock(&ac->ac_lg->lg_mutex);
}
```
### 10.1 ext4_mb_new_blocks_simple
```c
static ext4_fsblk_t ext4_mb_new_blocks_simple(handle_t *handle,
				struct ext4_allocation_request *ar, int *errp)
{
	struct buffer_head *bitmap_bh;
	struct super_block *sb = ar->inode->i_sb;
	ext4_group_t group;
	ext4_grpblk_t blkoff;
	// 每个组的cluster数量
	ext4_grpblk_t max = EXT4_CLUSTERS_PER_GROUP(sb);
	ext4_grpblk_t i = 0;
	ext4_fsblk_t goal, block;
	struct ext4_super_block *es = EXT4_SB(sb)->s_es;

	goal = ar->goal;

	// 把目标限制到合法范围内, 不能比第1个数据块小, 也不能比总块数大
	if (goal < le32_to_cpu(es->s_first_data_block) ||
			goal >= ext4_blocks_count(es))
		goal = le32_to_cpu(es->s_first_data_block);

	ar->len = 0;
	// 计算目标所在组和组内的偏移, 先以建议的目标块为准
	ext4_get_group_no_and_offset(sb, goal, &group, &blkoff);
	for (; group < ext4_get_groups_count(sb); group++) {
		// 读组位图所在的块, 这个是同步的
		bitmap_bh = ext4_read_block_bitmap(sb, group);
		if (IS_ERR(bitmap_bh)) {
			*errp = PTR_ERR(bitmap_bh);
			pr_warn("Failed to read block bitmap\n");
			return 0;
		}

		// goal有可能比组第1个数据块小, 这种情况下就要以组的第1个数据块为准
		ext4_get_group_no_and_offset(sb,
			max(ext4_group_first_block_no(sb, group), goal),
			NULL, &blkoff);
		while (1) {
			// 从blkoff开始,在位图里找一位为0的
			i = mb_find_next_zero_bit(bitmap_bh->b_data, max,
						blkoff);
			// 超过最大值,表示这组位图已经满了
			if (i >= max)
				break;
			// 检查这个块是不是在fc范围里, 如果在则从它后面重找一个位
			if (ext4_fc_replay_check_excluded(sb,
				ext4_group_first_block_no(sb, group) + i)) {
				blkoff = i + 1;
			} else
				// 没在fc范围,说明这个块可用
				break;
		}
		brelse(bitmap_bh);
		// i比max小,说明找到了目标
		if (i < max)
			break;
	}

	// 已经到了最大组 || 没有找到合适的i, 那就是没有空间了.
	if (group >= ext4_get_groups_count(sb) || i >= max) {
		*errp = -ENOSPC;
		return 0;
	}

	// 找到了合适的块
	block = ext4_group_first_block_no(sb, group) + i;
	// 标记对应的位图
	ext4_mb_mark_bb(sb, block, 1, 1);
	ar->len = 1;

	return block;
}
```

#### 10.1.1 ext4_get_group_no_and_offset
```c
void ext4_get_group_no_and_offset(struct super_block *sb, ext4_fsblk_t blocknr,
		ext4_group_t *blockgrpp, ext4_grpblk_t *offsetp)
{
	struct ext4_super_block *es = EXT4_SB(sb)->s_es;
	ext4_grpblk_t offset;

	// 距离第1个数据块的偏移
	blocknr = blocknr - le32_to_cpu(es->s_first_data_block);
	// do_div的效果: blocknr/=blocks_per_group, offset=blocknr % blocks_per_group
	offset = do_div(blocknr, EXT4_BLOCKS_PER_GROUP(sb)) >>
		// todo: cluster暂还没看明白
		EXT4_SB(sb)->s_cluster_bits;
	if (offsetp)
		*offsetp = offset;
	if (blockgrpp)
		*blockgrpp = blocknr;

}

static inline ext4_fsblk_t
ext4_group_first_block_no(struct super_block *sb, ext4_group_t group_no)
{
	// 组数*每组块数+设备的第1个数据块=组第1个数据块
	return group_no * (ext4_fsblk_t)EXT4_BLOCKS_PER_GROUP(sb) +
		le32_to_cpu(EXT4_SB(sb)->s_es->s_first_data_block);
}
```

#### 10.1.2 ext4_mb_mark_bb
```c
void ext4_mb_mark_bb(struct super_block *sb, ext4_fsblk_t block,
			int len, int state)
{
	struct buffer_head *bitmap_bh = NULL;
	struct ext4_group_desc *gdp;
	struct buffer_head *gdp_bh;
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	ext4_group_t group;
	ext4_grpblk_t blkoff;
	int i, clen, err;
	int already;

	// 把块号转成cluster_no
	clen = EXT4_B2C(sbi, len);

	// 算出组和偏移
	ext4_get_group_no_and_offset(sb, block, &group, &blkoff);
	// 读组bh
	bitmap_bh = ext4_read_block_bitmap(sb, group);
	if (IS_ERR(bitmap_bh)) {
		err = PTR_ERR(bitmap_bh);
		bitmap_bh = NULL;
		goto out_err;
	}

	err = -EIO;
	// 超级块描述符
	gdp = ext4_get_group_desc(sb, group, &gdp_bh);
	if (!gdp)
		goto out_err;

	ext4_lock_group(sb, group);

	// 测试是否已经标记?
	already = 0;
	for (i = 0; i < clen; i++)
		if (!mb_test_bit(blkoff + i, bitmap_bh->b_data) == !state)
			already++;

	// 标记或清除对应的位
	if (state)
		ext4_set_bits(bitmap_bh->b_data, blkoff, clen);
	else
		mb_test_and_clear_bits(bitmap_bh->b_data, blkoff, clen);
	// 校验和
	if (ext4_has_group_desc_csum(sb) &&
	    (gdp->bg_flags & cpu_to_le16(EXT4_BG_BLOCK_UNINIT))) {
		gdp->bg_flags &= cpu_to_le16(~EXT4_BG_BLOCK_UNINIT);
		ext4_free_group_clusters_set(sb, gdp,
					     ext4_free_clusters_after_init(sb,
						group, gdp));
	}
	// 计算空闲块的数量?
	if (state)
		clen = ext4_free_group_clusters(sb, gdp) - clen + already;
	else
		clen = ext4_free_group_clusters(sb, gdp) + clen - already;

	// 设置空闲块数量
	ext4_free_group_clusters_set(sb, gdp, clen);
	// 设置块校验和
	ext4_block_bitmap_csum_set(sb, group, gdp, bitmap_bh);
	// 设置组校验和
	ext4_group_desc_csum_set(sb, group, gdp);

	ext4_unlock_group(sb, group);

	// what 
	if (sbi->s_log_groups_per_flex) {
		ext4_group_t flex_group = ext4_flex_group(sbi, group);

		atomic64_sub(len,
			     &sbi_array_rcu_deref(sbi, s_flex_groups,
						  flex_group)->free_clusters);
	}

	// 位图变脏
	err = ext4_handle_dirty_metadata(NULL, NULL, bitmap_bh);
	if (err)
		goto out_err;
	sync_dirty_buffer(bitmap_bh);

	// 组描述符变脏
	err = ext4_handle_dirty_metadata(NULL, NULL, gdp_bh);
	// 这些都是立即同步?
	sync_dirty_buffer(gdp_bh);

out_err:
	brelse(bitmap_bh);
}
```

### 10.2 ext4_mb_use_preallocated
```c
static noinline_for_stack bool
ext4_mb_use_preallocated(struct ext4_allocation_context *ac)
{
	struct ext4_sb_info *sbi = EXT4_SB(ac->ac_sb);
	int order, i;
	struct ext4_inode_info *ei = EXT4_I(ac->ac_inode);
	struct ext4_locality_group *lg;
	struct ext4_prealloc_space *pa, *cpa = NULL;
	ext4_fsblk_t goal_block;

	// 只有数据才能预分配
	if (!(ac->ac_flags & EXT4_MB_HINT_DATA))
		return false;

	
	rcu_read_lock();
	list_for_each_entry_rcu(pa, &ei->i_prealloc_list, pa_inode_list) {

		// 不在pa范围
		if (ac->ac_o_ex.fe_logical < pa->pa_lstart ||
		    ac->ac_o_ex.fe_logical >= (pa->pa_lstart +
					       EXT4_C2B(sbi, pa->pa_len)))
			continue;

		/* 非extent文件物理块不能超过 2^32 */
		if (!(ext4_test_inode_flag(ac->ac_inode, EXT4_INODE_EXTENTS)) &&
		    (pa->pa_pstart + EXT4_C2B(sbi, pa->pa_len) >
		     EXT4_MAX_BLOCK_FILE_PHYS))
			continue;

		spin_lock(&pa->pa_lock);
		// 没有被删, 有空闲的, 则使用它们
		if (pa->pa_deleted == 0 && pa->pa_free) {
			atomic_inc(&pa->pa_count);
			ext4_mb_use_inode_pa(ac, pa);
			spin_unlock(&pa->pa_lock);
			ac->ac_criteria = 10;
			rcu_read_unlock();
			return true;
		}
		spin_unlock(&pa->pa_lock);
	}
	rcu_read_unlock();

	// 走到这儿表示没找到

	// 不能使用组预分配, 直接返回
	if (!(ac->ac_flags & EXT4_MB_HINT_GROUP_ALLOC))
		return false;

	// inode可能没有locate组. todo: what?
	lg = ac->ac_lg;
	if (lg == NULL)
		return false;
	// fls是找最后一个被设置的位的下标, 也就是把长度转成2的幂
	order  = fls(ac->ac_o_ex.fe_len) - 1;

	// 限制到最大值
	// PREALLOC_TB_SIZE 是 10
	if (order > PREALLOC_TB_SIZE - 1)
		/* The max size of hash table is PREALLOC_TB_SIZE */
		order = PREALLOC_TB_SIZE - 1;

	// todo: what ?
	goal_block = ext4_grp_offs_to_block(ac->ac_sb, &ac->ac_g_ex);
	// 找一个离目标块最近的pa
	for (i = order; i < PREALLOC_TB_SIZE; i++) {
		rcu_read_lock();
		list_for_each_entry_rcu(pa, &lg->lg_prealloc_list[i],
					pa_inode_list) {
			spin_lock(&pa->pa_lock);
			// pa没有删除 && 空闲的大于需要的长度
			if (pa->pa_deleted == 0 &&
					pa->pa_free >= ac->ac_o_ex.fe_len) {

				cpa = ext4_mb_check_group_pa(goal_block,
								pa, cpa);
			}
			spin_unlock(&pa->pa_lock);
		}
		rcu_read_unlock();
	}
	// 找到了
	if (cpa) {
		ext4_mb_use_group_pa(ac, cpa);
		ac->ac_criteria = 20;
		return true;
	}
	return false;
}
```

## 1.3 ext4_mb_normalize_request
```c
static noinline_for_stack void
ext4_mb_normalize_request(struct ext4_allocation_context *ac,
				struct ext4_allocation_request *ar)
{
	struct ext4_sb_info *sbi = EXT4_SB(ac->ac_sb);
	int bsbits, max;
	ext4_lblk_t end;
	loff_t size, start_off;
	loff_t orig_size __maybe_unused;
	ext4_lblk_t start;
	struct ext4_inode_info *ei = EXT4_I(ac->ac_inode);
	struct ext4_prealloc_space *pa;

	/* 只对数据请求进行标准化, 元数据请求不需要 */
	if (!(ac->ac_flags & EXT4_MB_HINT_DATA))
		return;

	/* 调用者只想要精确的块 */
	if (unlikely(ac->ac_flags & EXT4_MB_HINT_GOAL_ONLY))
		return;

	/* 调用者不想要预分配 (比如结尾) */
	if (ac->ac_flags & EXT4_MB_HINT_NOPREALLOC)
		return;

	// 标准化组分配. todo: 后面看
	if (ac->ac_flags & EXT4_MB_HINT_GROUP_ALLOC) {
		ext4_mb_normalize_group_request(ac);
		return ;
	}

	// 块大小
	bsbits = ac->ac_sb->s_blocksize_bits;

	/* 首先, 我们来当前请求需要分配的大小 */
	size = ac->ac_o_ex.fe_logical + EXT4_C2B(sbi, ac->ac_o_ex.fe_len);
	size = size << bsbits;
	// todo: what
	if (size < i_size_read(ac->ac_inode))
		size = i_size_read(ac->ac_inode);
	orig_size = size;

	/* max size of free chunks */
	max = 2 << bsbits;

#define NRL_CHECK_SIZE(req, size, max, chunk_size)	\
		(req <= (size) || max <= (chunk_size))

	/* 首先, 预言文件大小
	/* XXX: 这个表应该可调节吗? */
	start_off = 0;

	// 规范文件大小??
	if (size <= 16 * 1024) {
		size = 16 * 1024;
	} else if (size <= 32 * 1024) {
		size = 32 * 1024;
	} else if (size <= 64 * 1024) {
		size = 64 * 1024;
	} else if (size <= 128 * 1024) {
		size = 128 * 1024;
	} else if (size <= 256 * 1024) {
		size = 256 * 1024;
	} else if (size <= 512 * 1024) {
		size = 512 * 1024;
	} else if (size <= 1024 * 1024) {
		size = 1024 * 1024;
	} else if (NRL_CHECK_SIZE(size, 4 * 1024 * 1024, max, 2 * 1024)) {
		start_off = ((loff_t)ac->ac_o_ex.fe_logical >>
						(21 - bsbits)) << 21;
		size = 2 * 1024 * 1024;
	} else if (NRL_CHECK_SIZE(size, 8 * 1024 * 1024, max, 4 * 1024)) {
		start_off = ((loff_t)ac->ac_o_ex.fe_logical >>
							(22 - bsbits)) << 22;
		size = 4 * 1024 * 1024;
	} else if (NRL_CHECK_SIZE(ac->ac_o_ex.fe_len,
					(8<<20)>>bsbits, max, 8 * 1024)) {
		start_off = ((loff_t)ac->ac_o_ex.fe_logical >>
							(23 - bsbits)) << 23;
		size = 8 * 1024 * 1024;
	} else {
		start_off = (loff_t) ac->ac_o_ex.fe_logical << bsbits;
		size	  = (loff_t) EXT4_C2B(EXT4_SB(ac->ac_sb),
					      ac->ac_o_ex.fe_len) << bsbits;
	}
	size = size >> bsbits;
	start = start_off >> bsbits;

	/* 在选择的范围内不要覆盖已经配的块 */
	// 把start限制在left的左边
	if (ar->pleft && start <= ar->lleft) {
		size -= ar->lleft + 1 - start;
		start = ar->lleft + 1;
	}

	// size限制到start的右边
	if (ar->pright && start + size - 1 >= ar->lright)
		size -= start + size - ar->lright;

	/*
	 * 把请求规范到组大小里
	 */
	if (size > EXT4_BLOCKS_PER_GROUP(ac->ac_sb))
		size = EXT4_BLOCKS_PER_GROUP(ac->ac_sb);

	// 最终的节点
	end = start + size;

	/* 先检查已分配的块 */
	rcu_read_lock();
	list_for_each_entry_rcu(pa, &ei->i_prealloc_list, pa_inode_list) {
		ext4_lblk_t pa_end;

		// 已删除
		if (pa->pa_deleted)
			continue;

		spin_lock(&pa->pa_lock);
		// 加锁之后情况可能改变, 所以再判断一次
		if (pa->pa_deleted) {
			spin_unlock(&pa->pa_lock);
			continue;
		}

		// 物理结束块
		pa_end = pa->pa_lstart + EXT4_C2B(EXT4_SB(ac->ac_sb),
						  pa->pa_len);

		// pa不应该与原始请求重叠
		BUG_ON(!(ac->ac_o_ex.fe_logical >= pa_end ||
			ac->ac_o_ex.fe_logical < pa->pa_lstart));

		/* 物理块不在想要的范围内 */
		if (pa->pa_lstart >= end || pa_end <= start) {
			spin_unlock(&pa->pa_lock);
			continue;
		}
		// 怎么会发生这种情况
		BUG_ON(pa->pa_lstart <= start && pa_end >= end);

		/* 把start或end限制到这个pa的位置 */
		if (pa_end <= ac->ac_o_ex.fe_logical) {
			BUG_ON(pa_end < start);
			start = pa_end;
		} else if (pa->pa_lstart > ac->ac_o_ex.fe_logical) {
			BUG_ON(pa->pa_lstart > end);
			end = pa->pa_lstart;
		}
		spin_unlock(&pa->pa_lock);
	}
	rcu_read_unlock();

	// 最终大小
	size = end - start;

	/* XXX: 再循环一遍检查我们真的没有重叠 */
	rcu_read_lock();
	list_for_each_entry_rcu(pa, &ei->i_prealloc_list, pa_inode_list) {
		ext4_lblk_t pa_end;

		spin_lock(&pa->pa_lock);
		// pa没有删除
		if (pa->pa_deleted == 0) {
			pa_end = pa->pa_lstart + EXT4_C2B(EXT4_SB(ac->ac_sb),
							  pa->pa_len);
			BUG_ON(!(start >= pa_end || end <= pa->pa_lstart));
		}
		spin_unlock(&pa->pa_lock);
	}
	rcu_read_unlock();

	// size为负
	if (start + size <= ac->ac_o_ex.fe_logical &&
			start > ac->ac_o_ex.fe_logical) {
		ext4_msg(ac->ac_sb, KERN_ERR,
			 "start %lu, size %lu, fe_logical %lu",
			 (unsigned long) start, (unsigned long) size,
			 (unsigned long) ac->ac_o_ex.fe_logical);
		BUG();
	}

	// size不能为0
	BUG_ON(size <= 0 || size > EXT4_BLOCKS_PER_GROUP(ac->ac_sb));

	/* 准备目标请求 */

	/* XXX: 尽量对齐块或范围大分配的请求 */
	ac->ac_g_ex.fe_logical = start;
	ac->ac_g_ex.fe_len = EXT4_NUM_B2C(sbi, size);

	// 把目标对齐到右边界上方便合并
	if (ar->pright && (ar->lright == (start + size))) {
		/* merge to the right */
		ext4_get_group_no_and_offset(ac->ac_sb, ar->pright - size,
						&ac->ac_f_ex.fe_group,
						&ac->ac_f_ex.fe_start);
		ac->ac_flags |= EXT4_MB_HINT_TRY_GOAL;
	}

	// 把目标对齐到左边界上方便合并
	if (ar->pleft && (ar->lleft + 1 == start)) {
		/* merge to the left */
		ext4_get_group_no_and_offset(ac->ac_sb, ar->pleft + 1,
						&ac->ac_f_ex.fe_group,
						&ac->ac_f_ex.fe_start);
		ac->ac_flags |= EXT4_MB_HINT_TRY_GOAL;
	}

	mb_debug(ac->ac_sb, "goal: %lld(was %lld) blocks at %u\n", size,
		 orig_size, start);
}
```


## ext4_mb_init_group
```c

struct ext4_buddy {
	struct page *bd_buddy_page; // buddy所在的页
	void *bd_buddy; // buddy所在的地址
	struct page *bd_bitmap_page; // 位图所在的页
	void *bd_bitmap; // 位图所在地址
	struct ext4_group_info *bd_info; // 组信息
	struct super_block *bd_sb; // 超级块
	__u16 bd_blkbits; // 块大小，2的幂
	ext4_group_t bd_group; // 组号
};

static noinline_for_stack
int ext4_mb_init_group(struct super_block *sb, ext4_group_t group, gfp_t gfp)
{

	struct ext4_group_info *this_grp;
	struct ext4_buddy e4b;
	struct page *page;
	int ret = 0;

	might_sleep();
	mb_debug(sb, "init group %u\n", group);
	// 获取组信息
	this_grp = ext4_get_group_info(sb, group);
	/*
	 * This ensures that we don't reinit the buddy cache
	 * page which map to the group from which we are already
	 * allocating. If we are looking at the buddy cache we would
	 * have taken a reference using ext4_mb_load_buddy and that
	 * would have pinned buddy page to page cache.
	 * The call to ext4_mb_get_buddy_page_lock will mark the
	 * page accessed.
	 */
	// 获取/分配 buddy页和位图页
	ret = ext4_mb_get_buddy_page_lock(sb, group, &e4b, gfp);
	if (ret || !EXT4_MB_GRP_NEED_INIT(this_grp)) {
		/*
		 * somebody initialized the group
		 * return without doing anything
		 */
		goto err;
	}

	// 位图页
	page = e4b.bd_bitmap_page;
	// 初始化位图
	ret = ext4_mb_init_cache(page, NULL, gfp);
	if (ret)
		goto err;
	// 页不是最新则出错
	if (!PageUptodate(page)) {
		ret = -EIO;
		goto err;
	}

	// buddy 页有可能和位图页的块，在一个page里，如果是这样就不用再初始化位图页，因为在上面的ext4_mb_init_cache已经初始化了
	if (e4b.bd_buddy_page == NULL) {
		ret = 0;
		goto err;
	}
	
	// 走到这儿说明位图和buddy在两个页里，这里需要再初始化buddy页，这里incore传的是位图所有的块数据 
	page = e4b.bd_buddy_page;
	// 初始化buddy所在的页
	ret = ext4_mb_init_cache(page, e4b.bd_bitmap, gfp);
	if (ret)
		goto err;
	// 页不是最新
	if (!PageUptodate(page)) {
		ret = -EIO;
		goto err;
	}
err:
	ext4_mb_put_buddy_page_lock(&e4b);
	return ret;
}

static int ext4_mb_get_buddy_page_lock(struct super_block *sb,
		ext4_group_t group, struct ext4_buddy *e4b, gfp_t gfp)
{
	// ext4专门用一个inode来管理buddy-cache，这个inode是内存里的，并不在磁盘上存储
	// inode号是EXT4_BAD_INO，这个inode是在文件系统挂载时生成的
	struct inode *inode = EXT4_SB(sb)->s_buddy_cache;
	int block, pnum, poff;
	int blocks_per_page;
	struct page *page;

	e4b->bd_buddy_page = NULL;
	e4b->bd_bitmap_page = NULL;

	// 每页存的块，比如64k页，块大小4k，则一页里可以放16个块。通常页大小是4k
	blocks_per_page = PAGE_SIZE / sb->s_blocksize;
	/*
	 * buddy缓存存储块位图和buddy信息在连续的块上。所以每个组需要2个块。
	 */
	block = group * 2;

	// 根据块号算出页号
	pnum = block / blocks_per_page;
	// 块所在页内偏移
	poff = block % blocks_per_page;

	// 获取/分配pnum对应的页
	page = find_or_create_page(inode->i_mapping, pnum, gfp);
	if (!page)
		return -ENOMEM;
	BUG_ON(page->mapping != inode->i_mapping);

	e4b->bd_bitmap_page = page;
	// 位图对应的内存，因为一个页可能存多个块，所以要加上偏移
	e4b->bd_bitmap = page_address(page) + (poff * sb->s_blocksize);

	// 如果一页里存的块大于2, 说明位图和buddy在一个页里存着, 就不用下面的计算了
	if (blocks_per_page >= 2) {
		return 0;
	}

	// 走到这儿说明一页里只存一个块

	// 第二个块是buddy
	block++;
	// 块所在的页, 这个页号和块号是一样的
	pnum = block / blocks_per_page;
	// 找到buddy页
	page = find_or_create_page(inode->i_mapping, pnum, gfp);
	if (!page)
		return -ENOMEM;
	BUG_ON(page->mapping != inode->i_mapping);
	// 记录buddy页
	e4b->bd_buddy_page = page;
	return 0;
}
```

