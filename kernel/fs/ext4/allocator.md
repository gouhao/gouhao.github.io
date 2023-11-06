# 块分配器
源码基于5.10

## 1. ext4_mb_init
```c
int ext4_mb_init(struct super_block *sb)
{
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	unsigned i, j;
	unsigned offset, offset_incr;
	unsigned max;
	int ret;

	// s_mb_offsets是unsigned short *
	// s_mb_offsets是4倍块大小？
	i = (sb->s_blocksize_bits + 2) * sizeof(*sbi->s_mb_offsets);

	// 分配空间
	sbi->s_mb_offsets = kmalloc(i, GFP_KERNEL);
	if (sbi->s_mb_offsets == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	// s_mb_maxs是unsigned int *
	// max的数量
	i = (sb->s_blocksize_bits + 2) * sizeof(*sbi->s_mb_maxs);
	sbi->s_mb_maxs = kmalloc(i, GFP_KERNEL);
	if (sbi->s_mb_maxs == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	// 创建块大小的slab
	ret = ext4_groupinfo_create_slab(sb->s_blocksize);
	if (ret < 0)
		goto out;

	// order-0是常规的bitmap，最大值是块大小的8倍
	// 用一个块来存储order-0的块，因为一字节是8位
	sbi->s_mb_maxs[0] = sb->s_blocksize << 3;
	sbi->s_mb_offsets[0] = 0;

	// 从order1开始
	i = 1;
	offset = 0;
	// order1的空间为块大小一半
	offset_incr = 1 << (sb->s_blocksize_bits - 1);
	// order1的空间只占块的一半，一字节有8位，所以最大值为块大小的4倍
	max = sb->s_blocksize << 2;

	
	do {
		//  每个order的偏移
		sbi->s_mb_offsets[i] = offset;
		// 每个order最朋值
		sbi->s_mb_maxs[i] = max;
		// 增加偏移
		offset += offset_incr;
		// 偏移值再减半
		offset_incr = offset_incr >> 1;
		// 最大值也减半
		max = max >> 1;
		// order递增
		i++;
		
		// order的不能大于块大小的幂
	} while (i <= sb->s_blocksize_bits + 1);

	spin_lock_init(&sbi->s_md_lock);
	spin_lock_init(&sbi->s_bal_lock);
	sbi->s_mb_free_pending = 0;
	INIT_LIST_HEAD(&sbi->s_freed_data_list);

	sbi->s_mb_max_to_scan = MB_DEFAULT_MAX_TO_SCAN;
	sbi->s_mb_min_to_scan = MB_DEFAULT_MIN_TO_SCAN;
	sbi->s_mb_stats = MB_DEFAULT_STATS;
	sbi->s_mb_stream_request = MB_DEFAULT_STREAM_THRESHOLD;
	sbi->s_mb_order2_reqs = MB_DEFAULT_ORDER2_REQS;
	sbi->s_mb_max_inode_prealloc = MB_DEFAULT_MAX_INODE_PREALLOC;
	/*
	 * The default group preallocation is 512, which for 4k block
	 * sizes translates to 2 megabytes.  However for bigalloc file
	 * systems, this is probably too big (i.e, if the cluster size
	 * is 1 megabyte, then group preallocation size becomes half a
	 * gigabyte!).  As a default, we will keep a two megabyte
	 * group pralloc size for cluster sizes up to 64k, and after
	 * that, we will force a minimum group preallocation size of
	 * 32 clusters.  This translates to 8 megs when the cluster
	 * size is 256k, and 32 megs when the cluster size is 1 meg,
	 * which seems reasonable as a default.
	 */
	// MB_DEFAULT_GROUP_PREALLOC=512
	// 预分配
	sbi->s_mb_group_prealloc = max(MB_DEFAULT_GROUP_PREALLOC >>
				       sbi->s_cluster_bits, 32);
	/*
	 * If there is a s_stripe > 1, then we set the s_mb_group_prealloc
	 * to the lowest multiple of s_stripe which is bigger than
	 * the s_mb_group_prealloc as determined above. We want
	 * the preallocation size to be an exact multiple of the
	 * RAID stripe size so that preallocations don't fragment
	 * the stripes.
	 */
	// 条带，对raid的优化
	if (sbi->s_stripe > 1) {
		sbi->s_mb_group_prealloc = roundup(
			sbi->s_mb_group_prealloc, sbi->s_stripe);
	}

	// s_locality_groups是作预分配的
	sbi->s_locality_groups = alloc_percpu(struct ext4_locality_group);
	if (sbi->s_locality_groups == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	// 初始化每个cpu的s_locality_groups
	for_each_possible_cpu(i) {
		struct ext4_locality_group *lg;
		lg = per_cpu_ptr(sbi->s_locality_groups, i);
		mutex_init(&lg->lg_mutex);
		for (j = 0; j < PREALLOC_TB_SIZE; j++)
			INIT_LIST_HEAD(&lg->lg_prealloc_list[j]);
		spin_lock_init(&lg->lg_prealloc_lock);
	}

	// 初始化group-info, 及buddy inode
	ret = ext4_mb_init_backend(sb);
	if (ret != 0)
		goto out_free_locality_groups;

	return 0;

out_free_locality_groups:
	free_percpu(sbi->s_locality_groups);
	sbi->s_locality_groups = NULL;
out:
	kfree(sbi->s_mb_offsets);
	sbi->s_mb_offsets = NULL;
	kfree(sbi->s_mb_maxs);
	sbi->s_mb_maxs = NULL;
	return ret;
}

static int ext4_groupinfo_create_slab(size_t size)
{
	static DEFINE_MUTEX(ext4_grpinfo_slab_create_mutex);
	int slab_size;
	// 把块大小转成bit
	int blocksize_bits = order_base_2(size);

	// EXT4_MIN_BLOCK_LOG_SIZE=10
	// todo: what is cache_index?
	int cache_index = blocksize_bits - EXT4_MIN_BLOCK_LOG_SIZE;
	struct kmem_cache *cachep;

	// NR_GRPINFO_CACHES = 8
	if (cache_index >= NR_GRPINFO_CACHES)
		return -EINVAL;

	if (unlikely(cache_index < 0))
		cache_index = 0;

	mutex_lock(&ext4_grpinfo_slab_create_mutex);
	// 已经创建了组缓存
	if (ext4_groupinfo_caches[cache_index]) {
		mutex_unlock(&ext4_grpinfo_slab_create_mutex);
		return 0;	/* Already created */
	}

	// bb_counters是以order为下标的空闲块数量
	// 数量就是slab的大小
	slab_size = offsetof(struct ext4_group_info,
				bb_counters[blocksize_bits + 2]);

	cachep = kmem_cache_create(ext4_groupinfo_slab_names[cache_index],
					slab_size, 0, SLAB_RECLAIM_ACCOUNT,
					NULL);

	ext4_groupinfo_caches[cache_index] = cachep;

	mutex_unlock(&ext4_grpinfo_slab_create_mutex);
	if (!cachep) {
		printk(KERN_EMERG
		       "EXT4-fs: no memory for groupinfo slab cache\n");
		return -ENOMEM;
	}

	return 0;
}

static int ext4_mb_init_backend(struct super_block *sb)
{
	// 组数
	ext4_group_t ngroups = ext4_get_groups_count(sb);
	ext4_group_t i;
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	int err;
	struct ext4_group_desc *desc;
	struct ext4_group_info ***group_info;
	struct kmem_cache *cachep;

	// 分配组信息
	err = ext4_mb_alloc_groupinfo(sb, ngroups);
	if (err)
		return err;

	// 分配一个inode用作buddy-cache，用于块分配
	sbi->s_buddy_cache = new_inode(sb);
	if (sbi->s_buddy_cache == NULL) {
		ext4_msg(sb, KERN_ERR, "can't get new inode");
		goto err_freesgi;
	}
	// 设置inode号
	sbi->s_buddy_cache->i_ino = EXT4_BAD_INO;
	// buddy inode不占用磁盘空间
	EXT4_I(sbi->s_buddy_cache)->i_disksize = 0;

	// 遍历所有组，添加组信息
	for (i = 0; i < ngroups; i++) {
		cond_resched();
		// 组描述符
		desc = ext4_get_group_desc(sb, i, NULL);
		if (desc == NULL) {
			ext4_msg(sb, KERN_ERR, "can't read descriptor %u", i);
			goto err_freebuddy;
		}
		// 添加并初始化组相关信息
		if (ext4_mb_add_groupinfo(sb, i, desc) != 0)
			goto err_freebuddy;
	}

	// 初始化块预取?
	if (ext4_has_feature_flex_bg(sb)) {
		/* a single flex group is supposed to be read by a single IO.
		 * 2 ^ s_log_groups_per_flex != UINT_MAX as s_mb_prefetch is
		 * unsigned integer, so the maximum shift is 32.
		 */
		// 灵活组不能大于32
		if (sbi->s_es->s_log_groups_per_flex >= 32) {
			ext4_msg(sb, KERN_ERR, "too many log groups per flexible block group");
			goto err_freebuddy;
		}
		sbi->s_mb_prefetch = min_t(uint, 1 << sbi->s_es->s_log_groups_per_flex,
			BLK_MAX_SEGMENT_SIZE >> (sb->s_blocksize_bits - 9));
		sbi->s_mb_prefetch *= 8; /* 8 prefetch IOs in flight at most */
	} else {
		sbi->s_mb_prefetch = 32;
	}

	// 预取最大只能大于组数量
	if (sbi->s_mb_prefetch > ext4_get_groups_count(sb))
		sbi->s_mb_prefetch = ext4_get_groups_count(sb);
	/* now many real IOs to prefetch within a single allocation at cr=0
	 * given cr=0 is an CPU-related optimization we shouldn't try to
	 * load too many groups, at some point we should start to use what
	 * we've got in memory.
	 * with an average random access time 5ms, it'd take a second to get
	 * 200 groups (* N with flex_bg), so let's make this limit 4
	 */
	// 设置预取限制,最大为组数量
	sbi->s_mb_prefetch_limit = sbi->s_mb_prefetch * 4;
	if (sbi->s_mb_prefetch_limit > ext4_get_groups_count(sb))
		sbi->s_mb_prefetch_limit = ext4_get_groups_count(sb);

	return 0;

err_freebuddy:
	cachep = get_groupinfo_cache(sb->s_blocksize_bits);
	while (i-- > 0)
		kmem_cache_free(cachep, ext4_get_group_info(sb, i));
	i = sbi->s_group_info_size;
	rcu_read_lock();
	group_info = rcu_dereference(sbi->s_group_info);
	while (i-- > 0)
		kfree(group_info[i]);
	rcu_read_unlock();
	iput(sbi->s_buddy_cache);
err_freesgi:
	rcu_read_lock();
	kvfree(rcu_dereference(sbi->s_group_info));
	rcu_read_unlock();
	return -ENOMEM;
}

int ext4_mb_alloc_groupinfo(struct super_block *sb, ext4_group_t ngroups)
{
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	unsigned size;
	struct ext4_group_info ***old_groupinfo, ***new_groupinfo;

	// 组的数量
	size = (ngroups + EXT4_DESC_PER_BLOCK(sb) - 1) >>
		EXT4_DESC_PER_BLOCK_BITS(sb);
	// 如果大小给以前的组小，那就不用分配了，直接返回
	if (size <= sbi->s_group_info_size)
		return 0;

	// 需要的字节数，2次幂
	size = roundup_pow_of_two(sizeof(*sbi->s_group_info) * size);
	// 分配一个组
	new_groupinfo = kvzalloc(size, GFP_KERNEL);
	if (!new_groupinfo) {
		ext4_msg(sb, KERN_ERR, "can't allocate buddy meta group");
		return -ENOMEM;
	}
	rcu_read_lock();
	// 旧组
	old_groupinfo = rcu_dereference(sbi->s_group_info);
	// 把旧组信息复制到新组
	if (old_groupinfo)
		memcpy(new_groupinfo, old_groupinfo,
		       sbi->s_group_info_size * sizeof(*sbi->s_group_info));
	rcu_read_unlock();
	// 设置到sbi里
	rcu_assign_pointer(sbi->s_group_info, new_groupinfo);
	// 更新组大小
	sbi->s_group_info_size = size / sizeof(*sbi->s_group_info);
	// 释放老的组信息
	if (old_groupinfo)
		ext4_kvfree_array_rcu(old_groupinfo);
	ext4_debug("allocated s_groupinfo array for %d meta_bg's\n", 
		   sbi->s_group_info_size);
	return 0;
}

int ext4_mb_add_groupinfo(struct super_block *sb, ext4_group_t group,
			  struct ext4_group_desc *desc)
{
	int i;
	int metalen = 0;
	// 组所在的块
	int idx = group >> EXT4_DESC_PER_BLOCK_BITS(sb);
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	struct ext4_group_info **meta_group_info;
	// 获取块大小对应的slab?
	struct kmem_cache *cachep = get_groupinfo_cache(sb->s_blocksize_bits);

	/*
	 * First check if this group is the first of a reserved block.
	 * If it's true, we have to allocate a new table of pointers
	 * to ext4_group_info structures
	 */
	// 如果是第0个组,则分配组元数据
	if (group % EXT4_DESC_PER_BLOCK(sb) == 0) {
		// 元数据大小,为块上所有组的大小
		metalen = sizeof(*meta_group_info) <<
			EXT4_DESC_PER_BLOCK_BITS(sb);
		// 分配空间
		meta_group_info = kmalloc(metalen, GFP_NOFS);
		if (meta_group_info == NULL) {
			ext4_msg(sb, KERN_ERR, "can't allocate mem "
				 "for a buddy group");
			goto exit_meta_group_info;
		}
		rcu_read_lock();
		// 设置组元数据?
		rcu_dereference(sbi->s_group_info)[idx] = meta_group_info;
		rcu_read_unlock();
	}

	// 获取idx对应的元数据
	meta_group_info = sbi_array_rcu_deref(sbi, s_group_info, idx);

	// 块内偏移
	i = group & (EXT4_DESC_PER_BLOCK(sb) - 1);

	// 分配元数据信息
	meta_group_info[i] = kmem_cache_zalloc(cachep, GFP_NOFS);
	if (meta_group_info[i] == NULL) {
		ext4_msg(sb, KERN_ERR, "can't allocate buddy mem");
		goto exit_group_info;
	}
	// 设置需要初始化标志
	set_bit(EXT4_GROUP_INFO_NEED_INIT_BIT,
		&(meta_group_info[i]->bb_state));

	/*
	 * initialize bb_free to be able to skip
	 * empty groups without initialization
	 */
	// 初始化bb_free
	if (ext4_has_group_desc_csum(sb) &&
	    (desc->bg_flags & cpu_to_le16(EXT4_BG_BLOCK_UNINIT))) {
		
		meta_group_info[i]->bb_free =
			ext4_free_clusters_after_init(sb, group, desc);
	} else {
		meta_group_info[i]->bb_free =
			ext4_free_group_clusters(sb, desc);
	}

	// 预分配表
	INIT_LIST_HEAD(&meta_group_info[i]->bb_prealloc_list);
	init_rwsem(&meta_group_info[i]->alloc_sem);

	// #define RB_ROOT	(struct rb_root) { NULL, }
	meta_group_info[i]->bb_free_root = RB_ROOT;
	meta_group_info[i]->bb_largest_free_order = -1;  /* uninit */

	// 调试用
	mb_group_bb_bitmap_alloc(sb, meta_group_info[i], group);
	return 0;

exit_group_info:
	/* If a meta_group_info table has been allocated, release it now */
	if (group % EXT4_DESC_PER_BLOCK(sb) == 0) {
		struct ext4_group_info ***group_info;

		rcu_read_lock();
		group_info = rcu_dereference(sbi->s_group_info);
		kfree(group_info[idx]);
		group_info[idx] = NULL;
		rcu_read_unlock();
	}
exit_meta_group_info:
	return -ENOMEM;
}

static struct kmem_cache *get_groupinfo_cache(int blocksize_bits)
{
	// EXT4_MIN_BLOCK_LOG_SIZE=10. todo: why?
	int cache_index = blocksize_bits - EXT4_MIN_BLOCK_LOG_SIZE;
	// 获取对应的slab
	struct kmem_cache *cachep = ext4_groupinfo_caches[cache_index];

	BUG_ON(!cachep);
	return cachep;
}
```

## 1. ext4_mb_init_group
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
		// 找下一个在已设置的位
		i = mb_find_next_bit(bitmap, max, i);
		// 空闲长度
		len = i - first;
		// 编译空闲总量
		free += len;
		if (len > 1)
			// 在buddy里标志空闲块
			ext4_mb_mark_free_simple(sb, buddy, first, len, grp);
		else
			// 只有1个页，统计之
			grp->bb_counters[0]++;
		
		// 在位图里找下一个未使用的块
		if (i < max)
			i = mb_find_next_zero_bit(bitmap, max, i);
	}

	// todo: what?
	grp->bb_fragments = fragments;

	// 经过上面循环统计的空闲块数量与组描述符里记录的空闲数量不一致,这肯定是哪出问题了
	if (free != grp->bb_free) {
		ext4_grp_locked_error(sb, group, 0, 0,
				      "block bitmap and bg descriptor "
				      "inconsistent: %u vs %u free clusters",
				      free, grp->bb_free);
		/*
		 * 如果我们假装继续,我们要考虑组描述符已经损坏,并且使用位图里的值更新bb_free
		 */
		grp->bb_free = free;
		// 标记文件系统位图损坏
		ext4_mark_group_bitmap_corrupted(sb, group,
					EXT4_GROUP_INFO_BBITMAP_CORRUPT);
	}

	// 记录最大的空闲块数量
	mb_set_largest_free_order(sb, grp);

	// 清除组需要初始化位图的标志
	clear_bit(EXT4_GROUP_INFO_NEED_INIT_BIT, &(grp->bb_state));

	// 下面这些统计数据,只在调试时打印

	// 上面生成的时间
	period = get_cycles() - period;
	spin_lock(&sbi->s_bal_lock);
	// 已生成的buddy数量
	sbi->s_mb_buddies_generated++;

	// 记录生成时间
	sbi->s_mb_generation_time += period;
	spin_unlock(&sbi->s_bal_lock);
}

static void
mb_set_largest_free_order(struct super_block *sb, struct ext4_group_info *grp)
{
	int i;
	int bits;

	// 先标记为-1, -1表示未初始化
	grp->bb_largest_free_order = -1;

	// 最大的块大小
	bits = sb->s_blocksize_bits + 1;
	// 从后往前遍历找到最大的buddy块, 并记录之
	for (i = bits; i >= 0; i--) {
		if (grp->bb_counters[i] > 0) {
			grp->bb_largest_free_order = i;
			break;
		}
	}
}

static void ext4_mb_mark_free_simple(struct super_block *sb,
				void *buddy, ext4_grpblk_t first, ext4_grpblk_t len,
					struct ext4_group_info *grp)
{
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	ext4_grpblk_t min;
	ext4_grpblk_t max;
	ext4_grpblk_t chunk;
	unsigned int border;

	// 长度怎么会大于组的cluster数量?
	BUG_ON(len > EXT4_CLUSTERS_PER_GROUP(sb));

	// 边界是2倍块大小?
	border = 2 << sb->s_blocksize_bits;

	while (len > 0) {
		// 开始的块的位, 返回值从1开始,所以要减去1才是块号,下同
		max = ffs(first | border) - 1;

		// 块数量的位
		min = fls(len) - 1;

		if (max < min)
			min = max;
		
		// buddy块的大小
		chunk = 1 << min;

		// 记录对应buddy块的数量
		grp->bb_counters[min]++;

		// min=0,是只有一个块.
		if (min > 0)
			// 清除buddy上对应的位, buddy位图在初始化的时候设置成了全1
			// first >> min = first/min, 也就是first在min里的index
			// s_mb_offsets[min]: min这个长度的块在buddy里位图的开始处
			mb_clear_bit(first >> min,
				     buddy + sbi->s_mb_offsets[min]);

		// 长度减块的数量
		len -= chunk;
		// 递增起点
		first += chunk;

		// todo: 为什么不是直接存一个大块, 而是要分成这么多的小块来记录
	}
}
```

## 2. ext4_mb_new_blocks
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

	// 不使用保留的. todo: quota相关没太看懂
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

	// 初始化分配上下文，主要初始化了origin, goal, 将best的起点设置为目标块
	// 并决定了使用预分配的方式
	*errp = ext4_mb_initialize_context(ac, ar);
	if (*errp) {
		ar->len = 0;
		goto out;
	}

	// 使用预分配
	ac->ac_op = EXT4_MB_HISTORY_PREALLOC;
	seq = this_cpu_read(discard_pa_seq);

	// 如果不使用预分配。todo: 预分配后面看
	if (!ext4_mb_use_preallocated(ac)) {
		// 正常分配操作
		ac->ac_op = EXT4_MB_HISTORY_ALLOC;
		// 把请求大小标准化，并且还有可能合并，只对预分配进行处理
		ext4_mb_normalize_request(ac, ar);

		// 给ac分配一个预分配对象
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
		// 分配到了块，但是分配到的块不够，释放pa对象
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
	// fs共有多少个组
	ngroups = ext4_get_groups_count(sb);
	
	// 非extent限制到blockfile_groups
	if (!(ext4_test_inode_flag(ac->ac_inode, EXT4_INODE_EXTENTS)))
		ngroups = sbi->s_blockfile_groups;

	// 已经找到了不应该走这个函数
	BUG_ON(ac->ac_status == AC_STATUS_FOUND);

	// 先试一下goal能否分配
	err = ext4_mb_find_by_goal(ac, &e4b);
	// 出错或者找到了, 大多数情况都能成功分配，从这返回
	if (err || ac->ac_status == AC_STATUS_FOUND)
		goto out;

	// 走到这儿说明没找到

	// 只找goal, 则退出. 
	if (unlikely(ac->ac_flags & EXT4_MB_HINT_GOAL_ONLY))
		goto out;

	// 把长度转换成2的幂
	i = fls(ac->ac_g_ex.fe_len);
	ac->ac_2order = 0;

	// s_mb_order2_reqs默认是2
	// s_mb_order2_reqs对应的是sysfs的mb_order2_req接口
	// i 大于s_mb_order2_reqs且没有超过最大可分配块数时
	if (i >= sbi->s_mb_order2_reqs && i <= sb->s_blocksize_bits + 2) {
		// 长度与2对齐，ac_2order设置为较小的一阶
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

		// 遍历所有组
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
					// 对齐到灵活组
					nr -= group & (nr - 1);
					// 预取组的最小值
					nr = min(nr, sbi->s_mb_prefetch);
				}
				// 预读组的块的位图, 返回值是下次预取的位置, prefetch_ios返回的是
				// 提交io的数量
				prefetch_grp = ext4_mb_prefetch(sb, group,
							nr, &prefetch_ios);
				// 如果等于当前说明没有预取的了
				if (prefetch_ios == curr_ios)
					nr = 0;
			}

			// 检查这个组是不是适合分配
			ret = ext4_mb_good_group_nolock(ac, group, cr);
			if (ret <= 0) {
				// 不适合
				if (!first_err)
					first_err = ret;
				// 继续尝试下一个组
				continue;
			}

			// 走到这儿表示当前组可以分配

			// 加载buddy位图
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
				// 当ac_2order有值时才会走这里
				// 扫描ac_2order对应的buddy位图
				ext4_mb_simple_scan_group(ac, &e4b);
			else if (cr == 1 && sbi->s_stripe &&
					!(ac->ac_g_ex.fe_len % sbi->s_stripe))
				// raid. 后面看
				ext4_mb_scan_aligned(ac, &e4b);
			else
				// 扫描所有组
				ext4_mb_complex_scan_group(ac, &e4b);

			ext4_unlock_group(sb, group);
			ext4_mb_unload_buddy(&e4b);

			// 不等于continue就是找到或出错了
			if (ac->ac_status != AC_STATUS_CONTINUE)
				break;
		}
	}

	// fe_len>0说明已经分配了一些，如果还没分配够
	if (ac->ac_b_ex.fe_len > 0 && ac->ac_status != AC_STATUS_FOUND &&
	    !(ac->ac_flags & EXT4_MB_HINT_FIRST)) {
		// 从best里尝试分配
		ext4_mb_try_best_found(ac, &e4b);
		if (ac->ac_status != AC_STATUS_FOUND) {
			// 还是没找到,增加错误次数
			lost = atomic_inc_return(&sbi->s_mb_lost_chunks);
			mb_debug(sb, "lost chunk, group: %u, start: %d, len: %d, lost: %d\n",
				 ac->ac_b_ex.fe_group, ac->ac_b_ex.fe_start,
				 ac->ac_b_ex.fe_len, lost);

			// 重置数据
			ac->ac_b_ex.fe_group = 0;
			ac->ac_b_ex.fe_start = 0;
			ac->ac_b_ex.fe_len = 0;
			ac->ac_status = AC_STATUS_CONTINUE;
			ac->ac_flags |= EXT4_MB_HINT_FIRST;
			// 设置cr=3, 搜索所有的组
			cr = 3;
			// 重新搜索
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
void ext4_mb_scan_aligned(struct ext4_allocation_context *ac,
				 struct ext4_buddy *e4b)
{
	struct super_block *sb = ac->ac_sb;
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	// 块位图
	void *bitmap = e4b->bd_bitmap;
	struct ext4_free_extent ex;
	ext4_fsblk_t first_group_block;
	ext4_fsblk_t a;
	ext4_grpblk_t i;
	int max;

	// 没有打开stripe特性
	BUG_ON(sbi->s_stripe == 0);

	// 组内第一块
	first_group_block = ext4_group_first_block_no(sb, e4b->bd_group);

	// 第一个块对齐到stipe大小
	a = first_group_block + sbi->s_stripe - 1;
	do_div(a, sbi->s_stripe);
	// i是对齐之后的值
	i = (a * sbi->s_stripe) - first_group_block;

	// 在组内所有cluster里寻找
	while (i < EXT4_CLUSTERS_PER_GROUP(sb)) {
		// 这个cluster空闲
		if (!mb_test_bit(i, bitmap)) {
			// 从i开始找s_stripe个块
			max = mb_find_extent(e4b, i, sbi->s_stripe, &ex);

			// max大于stripe，说明找到的order足够分配
			if (max >= sbi->s_stripe) {
				ac->ac_found++;
				ex.fe_logical = 0xDEADF00D; /* debug value */
				// 复制ex到best
				ac->ac_b_ex = ex;
				// 标记best使用
				ext4_mb_use_best_found(ac, e4b);
				break;
			}
		}
		// 递增stipe个长度
		i += sbi->s_stripe;
	}
}

static noinline_for_stack
int ext4_mb_try_best_found(struct ext4_allocation_context *ac,
					struct ext4_buddy *e4b)
{
	// 把ex里的值复制到ex里
	struct ext4_free_extent ex = ac->ac_b_ex;
	ext4_group_t group = ex.fe_group;
	int max;
	int err;

	BUG_ON(ex.fe_len <= 0);
	// 加载buddy
	err = ext4_mb_load_buddy(ac->ac_sb, group, e4b);
	if (err)
		return err;

	ext4_lock_group(ac->ac_sb, group);
	// 找适当的extent
	max = mb_find_extent(e4b, ex.fe_start, ex.fe_len, &ex);

	// 如果找到就用它
	if (max > 0) {
		ac->ac_b_ex = ex;
		ext4_mb_use_best_found(ac, e4b);
	}

	ext4_unlock_group(ac->ac_sb, group);
	ext4_mb_unload_buddy(e4b);

	return 0;
}

static noinline_for_stack
void ext4_mb_complex_scan_group(struct ext4_allocation_context *ac,
					struct ext4_buddy *e4b)
{
	struct super_block *sb = ac->ac_sb;
	// buddy对应的位图
	void *bitmap = e4b->bd_bitmap;
	struct ext4_free_extent ex;
	int i;
	int free;

	// 空闲数量
	free = e4b->bd_info->bb_free;
	// 没有空闲了
	if (WARN_ON(free <= 0))
		return;

	// 第一个空闲的
	i = e4b->bd_info->bb_first_free;


	// 有空闲而且需要继续查找
	while (free && ac->ac_status == AC_STATUS_CONTINUE) {
		// 找位图上一个空闲的位置
		i = mb_find_next_zero_bit(bitmap,
						EXT4_CLUSTERS_PER_GROUP(sb), i);
		// 上面的free说明有空闲块,可是这里却找不到,说明位图出现了错误
		if (i >= EXT4_CLUSTERS_PER_GROUP(sb)) {
			ext4_grp_locked_error(sb, e4b->bd_group, 0, 0,
					"%d free clusters as per "
					"group info. But bitmap says 0",
					free);
			ext4_mark_group_bitmap_corrupted(sb, e4b->bd_group,
					EXT4_GROUP_INFO_BBITMAP_CORRUPT);
			break;
		}

		// 找能容的下fe_len的块
		mb_find_extent(e4b, i, ac->ac_g_ex.fe_len, &ex);
		// 没找到
		if (WARN_ON(ex.fe_len <= 0))
			break;
		// 位图又坏了
		if (free < ex.fe_len) {
			ext4_grp_locked_error(sb, e4b->bd_group, 0, 0,
					"%d free clusters as per "
					"group info. But got %d blocks",
					free, ex.fe_len);
			ext4_mark_group_bitmap_corrupted(sb, e4b->bd_group,
					EXT4_GROUP_INFO_BBITMAP_CORRUPT);
			/*
			 * The number of free blocks differs. This mostly
			 * indicate that the bitmap is corrupt. So exit
			 * without claiming the space.
			 */
			break;
		}
		ex.fe_logical = 0xDEADC0DE; /* debug value */
		// 检查是不是最好的exntent. todo: 后面看
		ext4_mb_measure_extent(ac, &ex, e4b);

		// 继续找空闲块
		i += ex.fe_len;
		free -= ex.fe_len;
	}

	ext4_mb_check_limits(ac, e4b, 1);
}

tatic void ext4_mb_measure_extent(struct ext4_allocation_context *ac,
					struct ext4_free_extent *ex,
					struct ext4_buddy *e4b)
{
	struct ext4_free_extent *bex = &ac->ac_b_ex;
	struct ext4_free_extent *gex = &ac->ac_g_ex;

	BUG_ON(ex->fe_len <= 0);
	BUG_ON(ex->fe_len > EXT4_CLUSTERS_PER_GROUP(ac->ac_sb));
	BUG_ON(ex->fe_start >= EXT4_CLUSTERS_PER_GROUP(ac->ac_sb));
	BUG_ON(ac->ac_status != AC_STATUS_CONTINUE);

	ac->ac_found++;

	/*
	 * The special case - take what you catch first
	 */
	if (unlikely(ac->ac_flags & EXT4_MB_HINT_FIRST)) {
		*bex = *ex;
		ext4_mb_use_best_found(ac, e4b);
		return;
	}

	/*
	 * Let's check whether the chuck is good enough
	 */
	if (ex->fe_len == gex->fe_len) {
		*bex = *ex;
		ext4_mb_use_best_found(ac, e4b);
		return;
	}

	/*
	 * If this is first found extent, just store it in the context
	 */
	if (bex->fe_len == 0) {
		*bex = *ex;
		return;
	}

	/*
	 * If new found extent is better, store it in the context
	 */
	if (bex->fe_len < gex->fe_len) {
		/* if the request isn't satisfied, any found extent
		 * larger than previous best one is better */
		if (ex->fe_len > bex->fe_len)
			*bex = *ex;
	} else if (ex->fe_len > gex->fe_len) {
		/* if the request is satisfied, then we try to find
		 * an extent that still satisfy the request, but is
		 * smaller than previous one */
		if (ex->fe_len < bex->fe_len)
			*bex = *ex;
	}

	ext4_mb_check_limits(ac, e4b, 0);
}

static int ext4_mb_good_group_nolock(struct ext4_allocation_context *ac,
				     ext4_group_t group, int cr)
{
	// 组信息
	struct ext4_group_info *grp = ext4_get_group_info(ac->ac_sb, group);
	struct super_block *sb = ac->ac_sb;
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	// 是不是应该加锁
	bool should_lock = ac->ac_flags & EXT4_MB_STRICT_CHECK;
	ext4_grpblk_t free;
	int ret = 0;

	if (should_lock)
		ext4_lock_group(sb, group);
	
	// 组的空闲块数
	free = grp->bb_free;
	// 这个组没有空闲的了
	if (free == 0)
		goto out;
	// cr=3可以随意分配，小于3都需要精确分配，所以不符合长度的就退出
	if (cr <= 2 && free < ac->ac_g_ex.fe_len)
		goto out;
	
	// 走到这儿 cr > 2 || free >= fe_len

	// 当前组的位图坏了，这个是不是应该放到前面判断？？
	if (unlikely(EXT4_MB_GRP_BBITMAP_CORRUPT(grp)))
		goto out;
	if (should_lock)
		ext4_unlock_group(sb, group);

	// 当前组还没初始化，则初始之
	if (unlikely(EXT4_MB_GRP_NEED_INIT(grp))) {
		struct ext4_group_desc *gdp =
			ext4_get_group_desc(sb, group, NULL);
		int ret;

		/* cr=0/1 is a very optimistic search to find large
		 * good chunks almost for free.  If buddy data is not
		 * ready, then this optimization makes no sense.  But
		 * we never skip the first block group in a flex_bg,
		 * since this gets used for metadata block allocation,
		 * and we want to make sure we locate metadata blocks
		 * in the first block group in the flex_bg if possible.
		 */
		if (cr < 2 &&
		    (!sbi->s_log_groups_per_flex ||
		     ((group & ((1 << sbi->s_log_groups_per_flex) - 1)) != 0)) &&
		    !(ext4_has_group_desc_csum(sb) &&
		      (gdp->bg_flags & cpu_to_le16(EXT4_BG_BLOCK_UNINIT))))
			return 0;
		// 初始化组
		ret = ext4_mb_init_group(sb, group, GFP_NOFS);
		if (ret)
			return ret;
	}

	if (should_lock)
		ext4_lock_group(sb, group);
	// 判断当前组是否适合分配
	ret = ext4_mb_good_group(ac, group, cr);
out:
	if (should_lock)
		ext4_unlock_group(sb, group);
	return ret;
}

static bool ext4_mb_good_group(struct ext4_allocation_context *ac,
				ext4_group_t group, int cr)
{
	ext4_grpblk_t free, fragments;
	int flex_size = ext4_flex_bg_size(EXT4_SB(ac->ac_sb));
	struct ext4_group_info *grp = ext4_get_group_info(ac->ac_sb, group);

	// cr什么时候会有这些值？
	BUG_ON(cr < 0 || cr >= 4);

	// 位图错误直接返回
	if (unlikely(EXT4_MB_GRP_BBITMAP_CORRUPT(grp)))
		return false;

	// 没有空间了
	free = grp->bb_free;
	if (free == 0)
		return false;

	// 没有空闲段了
	fragments = grp->bb_fragments;
	if (fragments == 0)
		return false;

	switch (cr) {
	case 0:
		BUG_ON(ac->ac_2order == 0);

		// 如果是文件的话，避免在灵活组的第一个组里分配
		if ((ac->ac_flags & EXT4_MB_HINT_DATA) &&
		    (flex_size >= EXT4_FLEX_SIZE_DIR_ALLOC_SCHEME) &&
		    ((group % flex_size) == 0))
			return false;

		// 长度不够
		if (free < ac->ac_g_ex.fe_len)
			return false;

		// 超过了一次可分配的最大值
		if (ac->ac_2order > ac->ac_sb->s_blocksize_bits+1)
			return true;

		// 当前组最大空闲块，小于要求的块长度
		if (grp->bb_largest_free_order < ac->ac_2order)
			return false;

		return true;
	case 1:
		// todo: 空闲/段数=每段平均块数？
		if ((free / fragments) >= ac->ac_g_ex.fe_len)
			return true;
		break;
	case 2:
		// 组内空闲空间够就可以分配
		if (free >= ac->ac_g_ex.fe_len)
			return true;
		break;
	case 3:
		// 任意分配
		return true;
	default:
		BUG();
	}

	return false;
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

	// 不需要找目标块，退出
	if (!(ac->ac_flags & EXT4_MB_HINT_TRY_GOAL))
		return 0;
	// 该组的空闲块为0
	if (grp->bb_free == 0)
		return 0;

	// 加载buddy
	err = ext4_mb_load_buddy(ac->ac_sb, group, e4b);
	if (err)
		return err;

	// 加载位图错误，直接返回
	if (unlikely(EXT4_MB_GRP_BBITMAP_CORRUPT(e4b->bd_info))) {
		ext4_mb_unload_buddy(e4b);
		return 0;
	}

	ext4_lock_group(ac->ac_sb, group);
	// 计算从fe_start开始，可以分配多少个连续块，分配的起点在ex里
	// max返回的是可分配连续块
	max = mb_find_extent(e4b, ac->ac_g_ex.fe_start,
			     ac->ac_g_ex.fe_len, &ex);
	// what?
	ex.fe_logical = 0xDEADFA11; /* debug value */

	
	if (max >= ac->ac_g_ex.fe_len && ac->ac_g_ex.fe_len == sbi->s_stripe) {
		// 对raid的优化. todo: raid后面看	
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
		// 可分配块数量满足需要的长度, 大多都会走这

		// 这些BUG_ON在什么条件下产生的？？
		BUG_ON(ex.fe_len <= 0);
		BUG_ON(ex.fe_group != ac->ac_g_ex.fe_group);
		BUG_ON(ex.fe_start != ac->ac_g_ex.fe_start);
		// 找到了
		ac->ac_found++;
		// 把ex的值复制到b_ex里
		ac->ac_b_ex = ex;
		// 标记best已使用
		ext4_mb_use_best_found(ac, e4b);
	} else if (max > 0 && (ac->ac_flags & EXT4_MB_HINT_MERGE)) {
		// 可分配块小于需要的长度, 有merge标志

		/* 有时候，调用者想合并一些小的块到已有的extent*/
		BUG_ON(ex.fe_len <= 0);
		BUG_ON(ex.fe_group != ac->ac_g_ex.fe_group);
		BUG_ON(ex.fe_start != ac->ac_g_ex.fe_start);

		ac->ac_found++;
		ac->ac_b_ex = ex;
		ext4_mb_use_best_found(ac, e4b);
	}

	// 解锁group
	ext4_unlock_group(ac->ac_sb, group);
	// 释放page引用
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
	 * 位图块
	 */
	block = group * 2;
	// 页号
	pnum = block / blocks_per_page;
	// 块在页内偏移
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
				// 调试相关
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

	// 位图页的page
	e4b->bd_bitmap_page = page;
	// 位图页的地址起点
	e4b->bd_bitmap = page_address(page) + (poff * sb->s_blocksize);

	// buddy信息页
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
				// 注意：这里初始化第二个参数传的是位图
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


static int mb_find_extent(struct ext4_buddy *e4b, int block,
				int needed, struct ext4_free_extent *ex)
{
	int next = block;
	int max, order;
	void *buddy;

	assert_spin_locked(ext4_group_lock_ptr(e4b->bd_sb, e4b->bd_group));
	BUG_ON(ex == NULL);

	// 获取最大可分配的值
	// 因为这里传的是0, 所以返回的是位图
	buddy = mb_find_buddy(e4b, 0, &max);
	BUG_ON(buddy == NULL);
	BUG_ON(block >= max);
	// 如果当前块已经初始分配,则直接返回
	if (mb_test_bit(block, buddy)) {
		ex->fe_len = 0;
		ex->fe_start = 0;
		ex->fe_group = 0;
		return 0;
	}

	// 找从block开始的位置有空闲块的order，这里的block表示要分配的块号
	order = mb_find_order_for_block(e4b, block);
	// 把起始块转换成order对应的buddy里的位图下标
	block = block >> order;


	// 从这里开始把block 当做在buddy位图里的下标看

	// 已经分配的长度
	ex->fe_len = 1 << order;
	// 起点
	ex->fe_start = block << order;
	// 所分配的组
	ex->fe_group = e4b->bd_group;

	// 原来的分配起点与现在分配起点的距离. 因为上面把block对齐到了order, 所以
	// 这里fe_start肯定小于next
	next = next - ex->fe_start;
	// 真正需要的长度
	ex->fe_len -= next;
	// 真正长度的起点
	ex->fe_start += next;

	// 如果已分配的不够需要的长度,则递规查找
	while (needed > ex->fe_len &&
		// 找order的可以分配的最大值
	       mb_find_buddy(e4b, order, &max)) {

		// 超过最大值,退出
		if (block + 1 >= max)
			break;

		/* next设置为以上次order为步进的下一个块的块号

		1<<order: 上次order有多少块
		上面把block已经转成了order对应的位图下标，
		这里 (block+1)就是下一个位，再乘以 1<<order，就又把块
		下标还原成以1<<order为单位的下一个块的块号
		*/
		next = (block + 1) * (1 << order);
		// 直接在位图里测试这个块是否已分配，若已分配则退出. todo: 为什么退出，空间不连续？
		if (mb_test_bit(next, e4b->bd_bitmap))
			break;
		// 如果空闲,则以next块号再开始找连续空间
		order = mb_find_order_for_block(e4b, next);

		// next对齐到order，即转成order所在位图的下标
		block = next >> order;

		// 加上分配了的长度
		ex->fe_len += 1 << order;
	}

	// 要分配的长度,超过了每组最大的cluster数量
	if (ex->fe_start + ex->fe_len > EXT4_CLUSTERS_PER_GROUP(e4b->bd_sb)) {
		// 这种情况不应该发生, 但是有时确实发生了. 就返回分配失败
		WARN_ON(1);
		ext4_grp_locked_error(e4b->bd_sb, e4b->bd_group, 0, 0,
			"corruption or bug in mb_find_extent "
			"block=%d, order=%d needed=%d ex=%u/%d/%d@%u",
			block, order, needed, ex->fe_group, ex->fe_start,
			ex->fe_len, ex->fe_logical);
		ex->fe_len = 0;
		ex->fe_start = 0;
		ex->fe_group = 0;
	}
	return ex->fe_len;
}

static void *mb_find_buddy(struct ext4_buddy *e4b, int order, int *max)
{
	char *bb;

	// 位图地址怎么会和buddy地址一样？
	BUG_ON(e4b->bd_bitmap == e4b->bd_buddy);
	BUG_ON(max == NULL);

	// order最大只能是块大小+1次幂，why?
	if (order > e4b->bd_blkbits + 1) {
		*max = 0;
		return NULL;
	}

	// 0阶时可以分配所有的块
	if (order == 0) {
		// blkbits是块大小, +3是一字节有8位, 这样算出来就是一个块能存多少位
		// 如果块大小是4k, 则max是32768
		*max = 1 << (e4b->bd_blkbits + 3);
		// 返回的是位图地址. 因为只需要一个块,所以从位图里直接分配就好了
		return e4b->bd_bitmap;
	}

	// bb为对应阶数的buddy地址
	bb = e4b->bd_buddy + EXT4_SB(e4b->bd_sb)->s_mb_offsets[order];
	// 最大可分配数量
	*max = EXT4_SB(e4b->bd_sb)->s_mb_maxs[order];

	return bb;
}

// block为要分配的位的起点
static int mb_find_order_for_block(struct ext4_buddy *e4b, int block)
{
	// 从order-1开始找
	int order = 1;
	// 步长为块长度一半，因为开始是从1开始找
	int bb_incr = 1 << (e4b->bd_blkbits - 1);
	void *bb;

	BUG_ON(e4b->bd_bitmap == e4b->bd_buddy);
	// 块号超过了本组最大的块数
	BUG_ON(block >= (1 << (e4b->bd_blkbits + 3)));

	// buddy起点
	bb = e4b->bd_buddy;

	// order的阶必须小于块大小的一半，因为order是从1开始的
	while (order <= e4b->bd_blkbits + 1) {
		// 这里的block当做buddy位图里的下标看，
		// 每上升一个阶，位图里的1位所表示的块长度就增加1倍，所对应的在位图里的下标就减半
		block = block >> 1;
		// 当前位没设置，则返回这个order
		if (!mb_test_bit(block, bb)) {
			return order;
		}
		// 位图起点增加到下一阶
		bb += bb_incr;
		// 高阶位图长度是低阶的一半
		bb_incr >>= 1;
		// 阶数递增
		order++;
	}
	return 0;
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

	// 小于0怎么会走这里
	BUG_ON(ac->ac_2order <= 0);
	for (i = ac->ac_2order; i <= sb->s_blocksize_bits + 1; i++) {

		// 当前阶的空闲块为0
		if (grp->bb_counters[i] == 0)
			continue;

		// 找到order对应的buddy
		buddy = mb_find_buddy(e4b, i, &max);
		BUG_ON(buddy == NULL);

		// 在buddy里找一个没有用的位
		k = mb_find_next_zero_bit(buddy, max, 0);

		// 走到这里不可能找不到, 如果找不到就是位图错了
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

		// 找到的长度
		ac->ac_b_ex.fe_len = 1 << i;
		// 块起点
		ac->ac_b_ex.fe_start = k << i;
		// 在哪个组找的
		ac->ac_b_ex.fe_group = e4b->bd_group;

		// 标记使用
		ext4_mb_use_best_found(ac, e4b);

		BUG_ON(ac->ac_f_ex.fe_len != ac->ac_g_ex.fe_len);

		// 统计
		if (EXT4_SB(sb)->s_mb_stats)
			atomic_inc(&EXT4_SB(sb)->s_bal_2orders);

		break;
	}
}

static void ext4_mb_use_best_found(struct ext4_allocation_context *ac,
					struct ext4_buddy *e4b)
{
	struct ext4_sb_info *sbi = EXT4_SB(ac->ac_sb);
	int ret;

	// 与所需的组不一样
	BUG_ON(ac->ac_b_ex.fe_group != e4b->bd_group);
	// 已经找到怎么会走到这儿
	BUG_ON(ac->ac_status == AC_STATUS_FOUND);

	// 长度取最小值
	ac->ac_b_ex.fe_len = min(ac->ac_b_ex.fe_len, ac->ac_g_ex.fe_len);
	// 起始逻辑块
	ac->ac_b_ex.fe_logical = ac->ac_g_ex.fe_logical;
	// 标记ex里的块已在使用, 并且处理buddy位图相关
	ret = mb_mark_used(e4b, &ac->ac_b_ex);

	/* 预分配会改变ac_b_ex, 因此我们把已经分配的块存储起来，作为历史 */
	ac->ac_f_ex = ac->ac_b_ex;

	// 已找到
	ac->ac_status = AC_STATUS_FOUND;
	// ret的低16位存的是,未全分配的块长度
	ac->ac_tail = ret & 0xffff;
	// ret的高16位存的是,未全分配的块order
	ac->ac_buddy = ret >> 16;

	// 获取bitmap/buddy_page的引用
	ac->ac_bitmap_page = e4b->bd_bitmap_page;
	get_page(ac->ac_bitmap_page);
	ac->ac_buddy_page = e4b->bd_buddy_page;
	get_page(ac->ac_buddy_page);

	// 如果是流分配，则存储本次分配的组和起点，下次从这儿开始分配
	if (ac->ac_flags & EXT4_MB_STREAM_ALLOC) {
		spin_lock(&sbi->s_md_lock);
		sbi->s_mb_last_group = ac->ac_f_ex.fe_group;
		sbi->s_mb_last_start = ac->ac_f_ex.fe_start;
		spin_unlock(&sbi->s_md_lock);
	}
	// 需要的空间小于已分配的空间,则把多余空间放到预分配里
	if (ac->ac_o_ex.fe_len < ac->ac_b_ex.fe_len)
		ext4_mb_new_preallocation(ac);

}

static int mb_mark_used(struct ext4_buddy *e4b, struct ext4_free_extent *ex)
{
	int ord;
	int mlen = 0;
	int max = 0;
	int cur;
	// 起点
	int start = ex->fe_start;
	// 长度
	int len = ex->fe_len;
	unsigned ret = 0;
	int len0 = len;
	void *buddy;

	// 超过最大可分配大小
	BUG_ON(start + len > (e4b->bd_sb->s_blocksize << 3));
	BUG_ON(e4b->bd_group != ex->fe_group);
	assert_spin_locked(ext4_group_lock_ptr(e4b->bd_sb, e4b->bd_group));
	// buddy一致性检查,调试用的
	mb_check_buddy(e4b);
	// 在位图里设置这些位已经使用
	mb_mark_used_double(e4b, start, len);

	// what?
	this_cpu_inc(discard_pa_seq);

	// 空闲块数减少
	e4b->bd_info->bb_free -= len;
	// 如果start是第一个空闲的块,则重新设置它
	if (e4b->bd_info->bb_first_free == start)
		e4b->bd_info->bb_first_free += len;

	// 计算碎片数量
	
	// 已分配区间左边的块是否设置
	if (start != 0)
		mlen = !mb_test_bit(start - 1, e4b->bd_bitmap);

	// 已分配区间右边是否设置
	if (start + len < EXT4_SB(e4b->bd_sb)->s_mb_maxs[0])
		max = !mb_test_bit(start + len, e4b->bd_bitmap);
	// 如果两边都没设置,则递增碎片数量
	if (mlen && max)
		e4b->bd_info->bb_fragments++;
	// 反之,若2边都设置了，则减少碎片数量
	else if (!mlen && !max)
		e4b->bd_info->bb_fragments--;

	/* let's maintain buddy itself */
	while (len) {
		// 找到start对应的阶
		ord = mb_find_order_for_block(e4b, start);

		// start刚好就是order阶对应的起点，且已分配的长度比order大
		// 这个表示，把整个order对应的块都已经分配了，直接标记对应的位就行了
		if (((start >> ord) << ord) == start && len >= (1 << ord)) {
			// order的长度
			mlen = 1 << ord;
			// 找到order对应的buddy起点
			buddy = mb_find_buddy(e4b, ord, &max);
			BUG_ON((start >> ord) >= max);
			// 标记start对应的位
			mb_set_bit(start >> ord, buddy);
			// 减少order对应的统计
			e4b->bd_info->bb_counters[ord]--;
			// 增加start
			start += mlen;
			// 长度减少
			len -= mlen;
			BUG_ON(len < 0);
			continue;
		}

		// 走到这儿表示, start和order没有对齐, 或者分配的长度小于order的块

		// 保存原始的长度和order
		if (ret == 0)
			ret = len | (ord << 16);

		// 把大的buddy分割, 放到小一些的块里

		// order-0表示一个块,连一个块都没分配下,怎么会走到这儿来...
		BUG_ON(ord <= 0);

		// 找到order的buddy地址
		buddy = mb_find_buddy(e4b, ord, &max);
		// 设置该buddy为使用
		mb_set_bit(start >> ord, buddy);
		// 减少相关buddy的块数量
		e4b->bd_info->bb_counters[ord]--;

		// 因为起始长度和order没对齐,所以要把多余的空间转到更低一阶的空间里
		// 阶减1
		ord--;

		// 当前地址对齐到阶. todo: 为啥与非1?
		cur = (start >> ord) & ~1U;

		// 找到order的buddy
		buddy = mb_find_buddy(e4b, ord, &max);

		// 清除低阶的2个位, 因为高阶的一块对应低阶的2块
		mb_clear_bit(cur, buddy);
		mb_clear_bit(cur + 1, buddy);

		// 对应的order+1
		e4b->bd_info->bb_counters[ord]++;
		e4b->bd_info->bb_counters[ord]++;
	}
	// 设置最大的空闲order
	mb_set_largest_free_order(e4b->bd_sb, e4b->bd_info);

	// 在块位图上设置区间已使用.
	ext4_set_bits(e4b->bd_bitmap, ex->fe_start, len0);
	mb_check_buddy(e4b);

	return ret;
}

void ext4_set_bits(void *bm, int cur, int len)
{
	__u32 *addr;

	// 终点
	len = cur + len;
	while (cur < len) {
		// 快速路径.cur与32对齐
		if ((cur & 31) == 0 && (len - cur) >= 32) {
			addr = bm + (cur >> 3);
			// 直接设置一个32的值
			*addr = 0xffffffff;
			cur += 32;
			continue;
		}
		mb_set_bit(cur, bm);
		cur++;
	}
}

static void mb_mark_used_double(struct ext4_buddy *e4b, int first, int count)
{
	int i;

	// 没有位图
	if (unlikely(e4b->bd_info->bb_bitmap == NULL))
		return;
	assert_spin_locked(ext4_group_lock_ptr(e4b->bd_sb, e4b->bd_group));
	for (i = 0; i < count; i++) {
		// 该位置已被标记
		BUG_ON(mb_test_bit(first + i, e4b->bd_info->bb_bitmap));
		// 在位图里设置这些位已使用
		mb_set_bit(first + i, e4b->bd_info->bb_bitmap);
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

	// 一次最大只能分配本组的cluster的数量
	if (len >= EXT4_CLUSTERS_PER_GROUP(sb))
		len = EXT4_CLUSTERS_PER_GROUP(sb);

	// 建议目标
	goal = ar->goal;
	// 如果目标不合法, 则使用设备的第一个数据块
	if (goal < le32_to_cpu(es->s_first_data_block) ||
			goal >= ext4_blocks_count(es))
		goal = le32_to_cpu(es->s_first_data_block);
	// 找到goal所在的组及组内块偏移
	ext4_get_group_no_and_offset(sb, goal, &group, &block);

	// 最好的逻辑块就是要求的逻辑块
	ac->ac_b_ex.fe_logical = EXT4_LBLK_CMASK(sbi, ar->logical);

	// 意思是还没分配, 继续查找?
	ac->ac_status = AC_STATUS_CONTINUE;
	ac->ac_sb = sb;
	ac->ac_inode = ar->inode;

	// 设置原始请求
	ac->ac_o_ex.fe_logical = ac->ac_b_ex.fe_logical;
	ac->ac_o_ex.fe_group = group;
	ac->ac_o_ex.fe_start = block;
	ac->ac_o_ex.fe_len = len;

	// 把origin复制到goal里
	ac->ac_g_ex = ac->ac_o_ex;

	ac->ac_flags = ar->flags;

	// 决定使用lg或per-inode预分配
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

	// 文件没有数据则返回, 一般文件会有这个标志
	if (!(ac->ac_flags & EXT4_MB_HINT_DATA))
		return;

	// 只分配目标块,也返回
	if (unlikely(ac->ac_flags & EXT4_MB_HINT_GOAL_ONLY))
		return;

	// 新的结尾，单位是块数
	size = ac->ac_o_ex.fe_logical + EXT4_C2B(sbi, ac->ac_o_ex.fe_len);
	// 当前文件块数 
	isize = (i_size_read(ac->ac_inode) + ac->ac_sb->s_blocksize - 1)
		>> bsbits;

	// 分配之后的文件块数 == 原文件的块数 && 文件系统不忙 && 不是为了写打开
	// 则不使用预分配。 todo: why?
	if ((size == isize) && !ext4_fs_is_busy(sbi) &&
	    !inode_is_open_for_write(ac->ac_inode)) {
		ac->ac_flags |= EXT4_MB_HINT_NOPREALLOC;
		return;
	}

	// 不支持预分配
	if (sbi->s_mb_group_prealloc <= 0) {
		ac->ac_flags |= EXT4_MB_STREAM_ALLOC;
		return;
	}

	size = max(size, isize);

	// s_mb_stream_request是区分大文件与小文件的界线,单位是块
	// 如果大于这个值,说明是大文件，大文件使用stream
	if (size > sbi->s_mb_stream_request) {
		ac->ac_flags |= EXT4_MB_STREAM_ALLOC;
		return;
	}

	// 走到这里表示小文件

	// 小文件使用lg分配,所以它必须为空
	BUG_ON(ac->ac_lg != NULL);
	// 取出s_locality_groups
	ac->ac_lg = raw_cpu_ptr(sbi->s_locality_groups);

	// 使用组预分配标志
	ac->ac_flags |= EXT4_MB_HINT_GROUP_ALLOC;

	// 使用组分配的话，会给组上锁
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
	// 并将找到的块号对齐到cluster
	offset = do_div(blocknr, EXT4_BLOCKS_PER_GROUP(sb)) >>
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

struct ext4_prealloc_space {
	struct list_head	pa_inode_list; // inode预分配表
	struct list_head	pa_group_list; // 组预分配表
	union {
		struct list_head pa_tmp_list;
		struct rcu_head	pa_rcu;
	} u;
	spinlock_t		pa_lock;
	atomic_t		pa_count;
	unsigned		pa_deleted; // 是否已删除
	ext4_fsblk_t		pa_pstart;	/* 物理块起点 */
	ext4_lblk_t		pa_lstart;	/* 逻辑块起点 */
	ext4_grpblk_t		pa_len;		/* 预分配长度 */
	ext4_grpblk_t		pa_free;	/* 空闲块数量 */
	unsigned short		pa_type;	/* 预分配类型 inode or group */
	spinlock_t		*pa_obj_lock;
	struct inode		*pa_inode;	/* hack, for history only */
};

/*
 * Locality group:
 *   we try to group all related changes together
 *   so that writeback can flush/allocate them together as well
 *   Size of lg_prealloc_list hash is determined by MB_DEFAULT_GROUP_PREALLOC
 *   (512). We store prealloc space into the hash based on the pa_free blocks
 *   order value.ie, fls(pa_free)-1;
 */
#define PREALLOC_TB_SIZE 10
struct ext4_locality_group {
	/* for allocator */
	/* to serialize allocates */
	struct mutex		lg_mutex;
	/* list of preallocations */
	struct list_head	lg_prealloc_list[PREALLOC_TB_SIZE];
	spinlock_t		lg_prealloc_lock;
};

static noinline_for_stack bool
ext4_mb_use_preallocated(struct ext4_allocation_context *ac)
{
	struct ext4_sb_info *sbi = EXT4_SB(ac->ac_sb);
	int order, i;
	struct ext4_inode_info *ei = EXT4_I(ac->ac_inode);
	struct ext4_locality_group *lg;
	struct ext4_prealloc_space *pa, *cpa = NULL;
	ext4_fsblk_t goal_block;

	// 只有文件数据才能预分配
	if (!(ac->ac_flags & EXT4_MB_HINT_DATA))
		return false;

	
	rcu_read_lock();

	// 遍历inode的per-inode表
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

		// 走到这儿表求这个pa可以用
		spin_lock(&pa->pa_lock);

		// 没有被删, 有空闲的, 则使用它们
		if (pa->pa_deleted == 0 && pa->pa_free) {
			atomic_inc(&pa->pa_count);
			// 使用这个pa里的块
			ext4_mb_use_inode_pa(ac, pa);
			spin_unlock(&pa->pa_lock);
			// todo: what is this?
			ac->ac_criteria = 10;
			rcu_read_unlock();
			return true;
		}
		spin_unlock(&pa->pa_lock);
	}
	rcu_read_unlock();

	// 走到这儿表示在pa-inode里没找到

	// 不能使用组预分配, 直接返回
	if (!(ac->ac_flags & EXT4_MB_HINT_GROUP_ALLOC))
		return false;

	// inode可能没有locate组, 没有组的也返回
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

	// 找到对应的块
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

				// 选一个离目标最近的pa
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

static inline ext4_fsblk_t ext4_grp_offs_to_block(struct super_block *sb,
					struct ext4_free_extent *fex)
{
	// 最终要转成cluster
	return ext4_group_first_block_no(sb, fex->fe_group) +
		(fex->fe_start << EXT4_SB(sb)->s_cluster_bits);
}

static struct ext4_prealloc_space *
ext4_mb_check_group_pa(ext4_fsblk_t goal_block,
			struct ext4_prealloc_space *pa,
			struct ext4_prealloc_space *cpa)
{
	ext4_fsblk_t cur_distance, new_distance;

	// cpa没有值,就直接用这个pa
	if (cpa == NULL) {
		atomic_inc(&pa->pa_count);
		return pa;
	}
	// 到cpa的距离
	cur_distance = abs(goal_block - cpa->pa_pstart);
	// 到新pa的距离
	new_distance = abs(goal_block - pa->pa_pstart);

	// 如果当前距离小, 则使用cpa
	if (cur_distance <= new_distance)
		return cpa;

	// 否则使用pa
	atomic_dec(&cpa->pa_count);
	atomic_inc(&pa->pa_count);
	return pa;
}

static void ext4_mb_use_inode_pa(struct ext4_allocation_context *ac,
				struct ext4_prealloc_space *pa)
{
	struct ext4_sb_info *sbi = EXT4_SB(ac->ac_sb);
	ext4_fsblk_t start;
	ext4_fsblk_t end;
	int len;

	// 目标起点
	start = pa->pa_pstart + (ac->ac_o_ex.fe_logical - pa->pa_lstart);
	// 如果超过pa的长度,则以pa为终点, 否则以fe_len为终点
	end = min(pa->pa_pstart + EXT4_C2B(sbi, pa->pa_len),
		  start + EXT4_C2B(sbi, ac->ac_o_ex.fe_len));
	// 块数量(以cluster为单位)
	len = EXT4_NUM_B2C(sbi, end - start);

	// 再获取start所在的组和在组内的偏移
	ext4_get_group_no_and_offset(ac->ac_sb, start, &ac->ac_b_ex.fe_group,
					&ac->ac_b_ex.fe_start);
	// 已经找到,设置相关变量
	ac->ac_b_ex.fe_len = len;
	ac->ac_status = AC_STATUS_FOUND;
	ac->ac_pa = pa;

	// 健康检查
	BUG_ON(start < pa->pa_pstart);
	BUG_ON(end > pa->pa_pstart + EXT4_C2B(sbi, pa->pa_len));
	BUG_ON(pa->pa_free < len);

	// 从pa里减去已分配的长度
	pa->pa_free -= len;

	mb_debug(ac->ac_sb, "use %llu/%d from inode pa %p\n", start, len, pa);
}

static void ext4_mb_use_group_pa(struct ext4_allocation_context *ac,
				struct ext4_prealloc_space *pa)
{
	unsigned int len = ac->ac_o_ex.fe_len;

	// 获取pa_start所在的组和偏移
	ext4_get_group_no_and_offset(ac->ac_sb, pa->pa_pstart,
					&ac->ac_b_ex.fe_group,
					&ac->ac_b_ex.fe_start);
	// 已找到,设置相关变量
	ac->ac_b_ex.fe_len = len;
	ac->ac_status = AC_STATUS_FOUND;
	ac->ac_pa = pa;

	// 这里并没有减小pa的长度. todo: 什么时候减小?
	/* we don't correct pa_pstart or pa_plen here to avoid
	 * possible race when the group is being loaded concurrently
	 * instead we correct pa later, after blocks are marked
	 * in on-disk bitmap -- see ext4_mb_release_context()
	 * Other CPUs are prevented from allocating from this pa by lg_mutex
	 */
	mb_debug(ac->ac_sb, "use %u/%u from group pa %p\n",
		 pa->pa_lstart-len, len, pa);
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

	// 使用组分配，则进行组标准化
	if (ac->ac_flags & EXT4_MB_HINT_GROUP_ALLOC) {
		ext4_mb_normalize_group_request(ac);
		return ;
	}

	// 走到这儿就是使用stream预分配

	// 块大小
	bsbits = ac->ac_sb->s_blocksize_bits;

	// 分配后文件大小（以块为单位）
	size = ac->ac_o_ex.fe_logical + EXT4_C2B(sbi, ac->ac_o_ex.fe_len);
	// 转成byte
	size = size << bsbits;
	// 如果比当前文件小，则以当前文件大小为准
	if (size < i_size_read(ac->ac_inode))
		size = i_size_read(ac->ac_inode);
	orig_size = size;

	// 一次分配的最大为块大小4倍
	max = 2 << bsbits;

#define NRL_CHECK_SIZE(req, size, max, chunk_size)	\
		(req <= (size) || max <= (chunk_size))

	start_off = 0;

	// 这是干什么？
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

	// 把规范后的size转成块
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

	// start是标准化后的起点
	end = start + size;

	
	rcu_read_lock();

	/* 先检查预分配的块 */
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
		// todo： 为什么不能在pa的范围内
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
	// cluster数量
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

## 预分配
```c
static void ext4_mb_new_preallocation(struct ext4_allocation_context *ac)
{
	if (ac->ac_flags & EXT4_MB_HINT_GROUP_ALLOC)
		// 组预分配
		ext4_mb_new_group_pa(ac);
	else
		// inode预分配
		ext4_mb_new_inode_pa(ac);
}

static noinline_for_stack void
ext4_mb_new_group_pa(struct ext4_allocation_context *ac)
{
	struct super_block *sb = ac->ac_sb;
	struct ext4_locality_group *lg;
	struct ext4_prealloc_space *pa;
	struct ext4_group_info *grp;

	/* preallocate only when found space is larger then requested */
	BUG_ON(ac->ac_o_ex.fe_len >= ac->ac_b_ex.fe_len);
	BUG_ON(ac->ac_status != AC_STATUS_FOUND);
	BUG_ON(!S_ISREG(ac->ac_inode->i_mode));
	BUG_ON(ac->ac_pa == NULL);

	pa = ac->ac_pa;

	/* preallocation can change ac_b_ex, thus we store actually
	 * allocated blocks for history */
	ac->ac_f_ex = ac->ac_b_ex;

	pa->pa_pstart = ext4_grp_offs_to_block(sb, &ac->ac_b_ex);
	pa->pa_lstart = pa->pa_pstart;
	pa->pa_len = ac->ac_b_ex.fe_len;
	pa->pa_free = pa->pa_len;
	spin_lock_init(&pa->pa_lock);
	INIT_LIST_HEAD(&pa->pa_inode_list);
	INIT_LIST_HEAD(&pa->pa_group_list);
	pa->pa_deleted = 0;
	pa->pa_type = MB_GROUP_PA;

	mb_debug(sb, "new group pa %p: %llu/%d for %u\n", pa, pa->pa_pstart,
		 pa->pa_len, pa->pa_lstart);
	trace_ext4_mb_new_group_pa(ac, pa);

	ext4_mb_use_group_pa(ac, pa);
	atomic_add(pa->pa_free, &EXT4_SB(sb)->s_mb_preallocated);

	grp = ext4_get_group_info(sb, ac->ac_b_ex.fe_group);
	lg = ac->ac_lg;
	BUG_ON(lg == NULL);

	pa->pa_obj_lock = &lg->lg_prealloc_lock;
	pa->pa_inode = NULL;

	list_add(&pa->pa_group_list, &grp->bb_prealloc_list);

	/*
	 * We will later add the new pa to the right bucket
	 * after updating the pa_free in ext4_mb_release_context
	 */
}

static noinline_for_stack void
ext4_mb_new_inode_pa(struct ext4_allocation_context *ac)
{
	struct super_block *sb = ac->ac_sb;
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	struct ext4_prealloc_space *pa;
	struct ext4_group_info *grp;
	struct ext4_inode_info *ei;

	/* preallocate only when found space is larger then requested */
	BUG_ON(ac->ac_o_ex.fe_len >= ac->ac_b_ex.fe_len);
	BUG_ON(ac->ac_status != AC_STATUS_FOUND);
	BUG_ON(!S_ISREG(ac->ac_inode->i_mode));
	BUG_ON(ac->ac_pa == NULL);

	pa = ac->ac_pa;

	if (ac->ac_b_ex.fe_len < ac->ac_g_ex.fe_len) {
		int winl;
		int wins;
		int win;
		int offs;

		/* we can't allocate as much as normalizer wants.
		 * so, found space must get proper lstart
		 * to cover original request */
		BUG_ON(ac->ac_g_ex.fe_logical > ac->ac_o_ex.fe_logical);
		BUG_ON(ac->ac_g_ex.fe_len < ac->ac_o_ex.fe_len);

		/* we're limited by original request in that
		 * logical block must be covered any way
		 * winl is window we can move our chunk within */
		winl = ac->ac_o_ex.fe_logical - ac->ac_g_ex.fe_logical;

		/* also, we should cover whole original request */
		wins = EXT4_C2B(sbi, ac->ac_b_ex.fe_len - ac->ac_o_ex.fe_len);

		/* the smallest one defines real window */
		win = min(winl, wins);

		offs = ac->ac_o_ex.fe_logical %
			EXT4_C2B(sbi, ac->ac_b_ex.fe_len);
		if (offs && offs < win)
			win = offs;

		ac->ac_b_ex.fe_logical = ac->ac_o_ex.fe_logical -
			EXT4_NUM_B2C(sbi, win);
		BUG_ON(ac->ac_o_ex.fe_logical < ac->ac_b_ex.fe_logical);
		BUG_ON(ac->ac_o_ex.fe_len > ac->ac_b_ex.fe_len);
	}

	/* preallocation can change ac_b_ex, thus we store actually
	 * allocated blocks for history */
	ac->ac_f_ex = ac->ac_b_ex;

	pa->pa_lstart = ac->ac_b_ex.fe_logical;
	pa->pa_pstart = ext4_grp_offs_to_block(sb, &ac->ac_b_ex);
	pa->pa_len = ac->ac_b_ex.fe_len;
	pa->pa_free = pa->pa_len;
	spin_lock_init(&pa->pa_lock);
	INIT_LIST_HEAD(&pa->pa_inode_list);
	INIT_LIST_HEAD(&pa->pa_group_list);
	pa->pa_deleted = 0;
	pa->pa_type = MB_INODE_PA;

	mb_debug(sb, "new inode pa %p: %llu/%d for %u\n", pa, pa->pa_pstart,
		 pa->pa_len, pa->pa_lstart);
	trace_ext4_mb_new_inode_pa(ac, pa);

	ext4_mb_use_inode_pa(ac, pa);
	atomic_add(pa->pa_free, &sbi->s_mb_preallocated);

	ei = EXT4_I(ac->ac_inode);
	grp = ext4_get_group_info(sb, ac->ac_b_ex.fe_group);

	pa->pa_obj_lock = &ei->i_prealloc_lock;
	pa->pa_inode = ac->ac_inode;

	list_add(&pa->pa_group_list, &grp->bb_prealloc_list);

	spin_lock(pa->pa_obj_lock);
	list_add_rcu(&pa->pa_inode_list, &ei->i_prealloc_list);
	spin_unlock(pa->pa_obj_lock);
	atomic_inc(&ei->i_prealloc_active);
}
```