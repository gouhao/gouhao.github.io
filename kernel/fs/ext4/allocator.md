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

		// 分配一个ext4_prealloc_space对象
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