# paging_init

源码基于5.10，本文里的代码都是在CONFIG_NUMA打开的情景里，现在内核这个选项都是打开的，即使电脑没有numa结构。

架构是x86的代码。
```c
void __init paging_init(void)
{
	// 没看懂
	sparse_init();

	// 清除node0的状态？
	node_clear_state(0, N_MEMORY);
	node_clear_state(0, N_NORMAL_MEMORY);

	// 这里面会初始化zone的free_area
	zone_sizes_init();
}


void __init zone_sizes_init(void)
{
	unsigned long max_zone_pfns[MAX_NR_ZONES];

	memset(max_zone_pfns, 0, sizeof(max_zone_pfns));

	// 设置各个区的最大值
#ifdef CONFIG_ZONE_DMA
	max_zone_pfns[ZONE_DMA]		= min(MAX_DMA_PFN, max_low_pfn);
#endif
#ifdef CONFIG_ZONE_DMA32
	max_zone_pfns[ZONE_DMA32]	= min(MAX_DMA32_PFN, max_low_pfn);
#endif
	max_zone_pfns[ZONE_NORMAL]	= max_low_pfn;
#ifdef CONFIG_HIGHMEM
	max_zone_pfns[ZONE_HIGHMEM]	= max_pfn;
#endif

	// 初始化空闲区
	free_area_init(max_zone_pfns);
}

void __init free_area_init(unsigned long *max_zone_pfn)
{
	unsigned long start_pfn, end_pfn;
	int i, nid, zone;
	bool descending;

	// 记录各个区间的边界
	memset(arch_zone_lowest_possible_pfn, 0,
				sizeof(arch_zone_lowest_possible_pfn));
	memset(arch_zone_highest_possible_pfn, 0,
				sizeof(arch_zone_highest_possible_pfn));

	// 物理地址的最小地址
	start_pfn = find_min_pfn_with_active_regions();
	// 对一些特殊的架构high-memory在normal下面？
	// 这个值一般都是false
	descending = arch_has_descending_max_zone_pfns();

	// 这个循环是算出每个区的开始和结束的地址
	for (i = 0; i < MAX_NR_ZONES; i++) {
		if (descending)
			zone = MAX_NR_ZONES - i - 1;
		else
			zone = i;

		// 移动区是个虚拟的，并不在这里初始化
		if (zone == ZONE_MOVABLE)
			continue;

		// 本区域的结束位置
		end_pfn = max(max_zone_pfn[zone], start_pfn);
		arch_zone_lowest_possible_pfn[zone] = start_pfn;
		arch_zone_highest_possible_pfn[zone] = end_pfn;

		// 一个区域的结束位置是下个区域的开始位置
		start_pfn = end_pfn;
	}

	// zone_movable只有在指定了kernelcore或movablecore时才会存在
	memset(zone_movable_pfn, 0, sizeof(zone_movable_pfn));
	// 计算zone_movable的页帧号
	find_zone_movable_pfns_for_nodes();

	// 打印每个区的最大最小地址
	pr_info("Zone ranges:\n");
	for (i = 0; i < MAX_NR_ZONES; i++) {
		if (i == ZONE_MOVABLE)
			continue;
		pr_info("  %-8s ", zone_names[i]);
		// 区域没有内存
		if (arch_zone_lowest_possible_pfn[i] ==
				arch_zone_highest_possible_pfn[i])
			pr_cont("empty\n");
		else
			pr_cont("[mem %#018Lx-%#018Lx]\n",
				(u64)arch_zone_lowest_possible_pfn[i]
					<< PAGE_SHIFT,
				((u64)arch_zone_highest_possible_pfn[i]
					<< PAGE_SHIFT) - 1);
	}

	// 打印每个node里的可移动区
	pr_info("Movable zone start for each node\n");
	for (i = 0; i < MAX_NUMNODES; i++) {
		if (zone_movable_pfn[i])
			pr_info("  Node %d: %#018Lx\n", i,
			       (u64)zone_movable_pfn[i] << PAGE_SHIFT);
	}

	// 打印每个node的内存范围
	// 并且初始化subsection_map。todo: what？
	pr_info("Early memory node ranges\n");
	for_each_mem_pfn_range(i, MAX_NUMNODES, &start_pfn, &end_pfn, &nid) {
		pr_info("  node %3d: [mem %#018Lx-%#018Lx]\n", nid,
			(u64)start_pfn << PAGE_SHIFT,
			((u64)end_pfn << PAGE_SHIFT) - 1);
		subsection_map_init(start_pfn, end_pfn - start_pfn);
	}

	// 调试相关
	mminit_verify_pageflags_layout();
	// 当node大于1时，这个函数才有效，设置nr_node_ids为最大node下标+1
	setup_nr_node_ids();

	// 遍历每个在线node，初始化free area
	for_each_online_node(nid) {
		pg_data_t *pgdat = NODE_DATA(nid);

		// 初始化空闲内存
		free_area_init_node(nid);

		// node_present_pages表示可用页的数量，当有可用的页时，
		// 设置node的状态为N_MEMORY，这个表示当前node有内存
		if (pgdat->node_present_pages)
			node_set_state(nid, N_MEMORY);
		check_for_memory(pgdat, nid);
	}

	memmap_init();
}

static void __init free_area_init_node(int nid)
{
	pg_data_t *pgdat = NODE_DATA(nid);
	unsigned long start_pfn = 0;
	unsigned long end_pfn = 0;

	// 初始化的时候这2个值都应该是0
	WARN_ON(pgdat->nr_zones || pgdat->kswapd_highest_zoneidx);

	// 找出node上的最大，最小地址
	get_pfn_range_for_nid(nid, &start_pfn, &end_pfn);

	// 设置nid
	pgdat->node_id = nid;
	// 设置开始地址
	pgdat->node_start_pfn = start_pfn;

	// todo: what ?
	pgdat->per_cpu_nodestats = NULL;

	pr_info("Initmem setup node %d [mem %#018Lx-%#018Lx]\n", nid,
		(u64)start_pfn << PAGE_SHIFT,
		end_pfn ? ((u64)end_pfn << PAGE_SHIFT) - 1 : 0);
	// 计算结点上的总页数、可用页数与节点内每个区域的总页数与可用页数
	calculate_node_totalpages(pgdat, start_pfn, end_pfn);

	// 这个函数在打开CONFIG_FLAT_NODE_MEM_MAP时才有效，现代内核这个选项一般不开
	alloc_node_mem_map(pgdat);
	// 这个函数在打开CONFIG_DEFERRED_STRUCT_PAGE_INIT才有效
	pgdat_set_deferred_range(pgdat);

	// free_area的核心初始化函数
	free_area_init_core(pgdat);
}

void __init get_pfn_range_for_nid(unsigned int nid,
			unsigned long *start_pfn, unsigned long *end_pfn)
{
	unsigned long this_start_pfn, this_end_pfn;
	int i;

	// -1UL表示设置成了最大值
	*start_pfn = -1UL;
	*end_pfn = 0;

	// 遍历node上的区域，找到最小地址与最大地址
	for_each_mem_pfn_range(i, nid, &this_start_pfn, &this_end_pfn, NULL) {
		*start_pfn = min(*start_pfn, this_start_pfn);
		*end_pfn = max(*end_pfn, this_end_pfn);
	}

	if (*start_pfn == -1UL)
		*start_pfn = 0;
}

#define for_each_mem_pfn_range(i, nid, p_start, p_end, p_nid)		\
	for (i = -1, __next_mem_pfn_range(&i, nid, p_start, p_end, p_nid); \
	     i >= 0; __next_mem_pfn_range(&i, nid, p_start, p_end, p_nid))

void __init_memblock __next_mem_pfn_range(int *idx, int nid,
				unsigned long *out_start_pfn,
				unsigned long *out_end_pfn, int *out_nid)
{
	// todo: what ?
	struct memblock_type *type = &memblock.memory;
	struct memblock_region *r;
	int r_nid;

	while (++*idx < type->cnt) {
		// 获取一个区域
		r = &type->regions[*idx];
		// 获取这个区域对应的nodeid
		r_nid = memblock_get_region_node(r);

		// 地址错误，或者长度为0
		if (PFN_UP(r->base) >= PFN_DOWN(r->base + r->size))
			continue;
		// 该区域在目标node上
		if (nid == MAX_NUMNODES || nid == r_nid)
			break;
	}

	// 下标越界
	if (*idx >= type->cnt) {
		*idx = -1;
		return;
	}

	// 设置开始地址
	if (out_start_pfn)
		*out_start_pfn = PFN_UP(r->base);
	// 设置结束地址
	if (out_end_pfn)
		*out_end_pfn = PFN_DOWN(r->base + r->size);
	// 设置该区域的id
	if (out_nid)
		*out_nid = r_nid;
}

static void __init calculate_node_totalpages(struct pglist_data *pgdat,
						unsigned long node_start_pfn,
						unsigned long node_end_pfn)
{
	unsigned long realtotalpages = 0, totalpages = 0;
	enum zone_type i;

	for (i = 0; i < MAX_NR_ZONES; i++) {
		// 获取一个区域
		struct zone *zone = pgdat->node_zones + i;
		unsigned long zone_start_pfn, zone_end_pfn;
		unsigned long spanned, absent;
		unsigned long size, real_size;

		// 计算区域里总共的页数，包括洞
		spanned = zone_spanned_pages_in_node(pgdat->node_id, i,
						     node_start_pfn,
						     node_end_pfn,
						     &zone_start_pfn,
						     &zone_end_pfn);
		// 计算区域里不可用的页数
		absent = zone_absent_pages_in_node(pgdat->node_id, i,
						   node_start_pfn,
						   node_end_pfn);
		
		// 总页数
		size = spanned;
		// 可用页数
		real_size = size - absent;

		// 设置区域的起始地址
		if (size)
			zone->zone_start_pfn = zone_start_pfn;
		else
			zone->zone_start_pfn = 0;
		// 设置区域的总页数与可用页数
		zone->spanned_pages = size;
		zone->present_pages = real_size;

		// 节点上的总页数与可用页数计数
		totalpages += size;
		realtotalpages += real_size;
	}

	// 设置节点上的总页数与可用页数
	pgdat->node_spanned_pages = totalpages;
	pgdat->node_present_pages = realtotalpages;
	printk(KERN_DEBUG "On node %d totalpages: %lu\n", pgdat->node_id,
							realtotalpages);
}

static unsigned long __init zone_spanned_pages_in_node(int nid,
					unsigned long zone_type,
					unsigned long node_start_pfn,
					unsigned long node_end_pfn,
					unsigned long *zone_start_pfn,
					unsigned long *zone_end_pfn)
{
	// 区域最低地址
	unsigned long zone_low = arch_zone_lowest_possible_pfn[zone_type];
	// 区域最高地址
	unsigned long zone_high = arch_zone_highest_possible_pfn[zone_type];
	
	// 这种是出现在热插拔的时候，开始地址和结束地址都是0
	if (!node_start_pfn && !node_end_pfn)
		return 0;

	// clamp是返回靠近一个范围的值。这里是将开始和结束值都固定在区域允许的值的范围内
	*zone_start_pfn = clamp(node_start_pfn, zone_low, zone_high);
	*zone_end_pfn = clamp(node_end_pfn, zone_low, zone_high);

	// todo: 可移动区后面再看
	// 没有可移动区时这个函数什么也不做
	adjust_zone_range_for_zone_movable(nid, zone_type,
				node_start_pfn, node_end_pfn,
				zone_start_pfn, zone_end_pfn);

	// 计算出来的值与给定的值 非法
	if (*zone_end_pfn < node_start_pfn || *zone_start_pfn > node_end_pfn)
		return 0;

	// 如果如果的值较小，则以node的值为准
	*zone_end_pfn = min(*zone_end_pfn, node_end_pfn);
	*zone_start_pfn = max(*zone_start_pfn, node_start_pfn);

	// 返回区间之间的页数
	return *zone_end_pfn - *zone_start_pfn;
}

static unsigned long __init zone_absent_pages_in_node(int nid,
					unsigned long zone_type,
					unsigned long node_start_pfn,
					unsigned long node_end_pfn)
{
	unsigned long zone_low = arch_zone_lowest_possible_pfn[zone_type];
	unsigned long zone_high = arch_zone_highest_possible_pfn[zone_type];
	unsigned long zone_start_pfn, zone_end_pfn;
	unsigned long nr_absent;

	if (!node_start_pfn && !node_end_pfn)
		return 0;

	zone_start_pfn = clamp(node_start_pfn, zone_low, zone_high);
	zone_end_pfn = clamp(node_end_pfn, zone_low, zone_high);

	adjust_zone_range_for_zone_movable(nid, zone_type,
			node_start_pfn, node_end_pfn,
			&zone_start_pfn, &zone_end_pfn);
	// 前面的这些计算和zone_spanned_pages_in_node里的一样

	// 计算不可用的页数
	nr_absent = __absent_pages_in_range(nid, zone_start_pfn, zone_end_pfn);

	// todo: 可移动区后面再看
	if (mirrored_kernelcore && zone_movable_pfn[nid]) {
		unsigned long start_pfn, end_pfn;
		struct memblock_region *r;

		for_each_mem_region(r) {
			start_pfn = clamp(memblock_region_memory_base_pfn(r),
					  zone_start_pfn, zone_end_pfn);
			end_pfn = clamp(memblock_region_memory_end_pfn(r),
					zone_start_pfn, zone_end_pfn);

			if (zone_type == ZONE_MOVABLE &&
			    memblock_is_mirror(r))
				nr_absent += end_pfn - start_pfn;

			if (zone_type == ZONE_NORMAL &&
			    !memblock_is_mirror(r))
				nr_absent += end_pfn - start_pfn;
		}
	}

	return nr_absent;
}

unsigned long __init __absent_pages_in_range(int nid,
				unsigned long range_start_pfn,
				unsigned long range_end_pfn)
{
	// 区域内所有的页数
	unsigned long nr_absent = range_end_pfn - range_start_pfn;
	unsigned long start_pfn, end_pfn;
	int i;

	// 遍历node上的所有range
	for_each_mem_pfn_range(i, nid, &start_pfn, &end_pfn, NULL) {

		// range的起始，结束
		start_pfn = clamp(start_pfn, range_start_pfn, range_end_pfn);
		end_pfn = clamp(end_pfn, range_start_pfn, range_end_pfn);

		// end_pfn - start_pfn就是这个range里的页数，从总页数里减去可用页数，
		// 剩下的就是不可用页数
		nr_absent -= end_pfn - start_pfn;
	}
	return nr_absent;
}

static void __init adjust_zone_range_for_zone_movable(int nid,
					unsigned long zone_type,
					unsigned long node_start_pfn,
					unsigned long node_end_pfn,
					unsigned long *zone_start_pfn,
					unsigned long *zone_end_pfn)
{
	/* Only adjust if ZONE_MOVABLE is on this node */
	if (zone_movable_pfn[nid]) {
		/* Size ZONE_MOVABLE */
		if (zone_type == ZONE_MOVABLE) {
			*zone_start_pfn = zone_movable_pfn[nid];
			*zone_end_pfn = min(node_end_pfn,
				arch_zone_highest_possible_pfn[movable_zone]);

		/* Adjust for ZONE_MOVABLE starting within this range */
		} else if (!mirrored_kernelcore &&
			*zone_start_pfn < zone_movable_pfn[nid] &&
			*zone_end_pfn > zone_movable_pfn[nid]) {
			*zone_end_pfn = zone_movable_pfn[nid];

		/* Check if this whole range is within ZONE_MOVABLE */
		} else if (*zone_start_pfn >= zone_movable_pfn[nid])
			*zone_start_pfn = *zone_end_pfn;
	}
}

static void check_for_memory(pg_data_t *pgdat, int nid)
{
	enum zone_type zone_type;

	for (zone_type = 0; zone_type <= ZONE_MOVABLE - 1; zone_type++) {
		struct zone *zone = &pgdat->node_zones[zone_type];
		if (populated_zone(zone)) {
			if (IS_ENABLED(CONFIG_HIGHMEM))
				node_set_state(nid, N_HIGH_MEMORY);
			if (zone_type <= ZONE_NORMAL)
				node_set_state(nid, N_NORMAL_MEMORY);
			break;
		}
	}
}
```

## memmap_init
```c
void __init __weak memmap_init(void)
{
	unsigned long start_pfn, end_pfn;
	unsigned long hole_pfn = 0;
	int i, j, zone_id, nid;

	// 这里传的是MAX_NUMNODES，表示遍历所有内存域
	for_each_mem_pfn_range(i, MAX_NUMNODES, &start_pfn, &end_pfn, &nid) {
		// 获取node对应的pglist
		struct pglist_data *node = NODE_DATA(nid);

		// 遍历node里的每个域
		for (j = 0; j < MAX_NR_ZONES; j++) {
			struct zone *zone = node->node_zones + j;

			// zone里没有可用页，则继续循环
			if (!populated_zone(zone))
				continue;

			memmap_init_zone_range(zone, start_pfn, end_pfn,
					       &hole_pfn);
			zone_id = j;
		}
	}

#ifdef CONFIG_SPARSEMEM
	/*
	 * Initialize the memory map for hole in the range [memory_end,
	 * section_end].
	 * Append the pages in this hole to the highest zone in the last
	 * node.
	 * The call to init_unavailable_range() is outside the ifdef to
	 * silence the compiler warining about zone_id set but not used;
	 * for FLATMEM it is a nop anyway
	 */
	end_pfn = round_up(end_pfn, PAGES_PER_SECTION);
	if (hole_pfn < end_pfn)
#endif
		init_unavailable_range(hole_pfn, end_pfn, zone_id, nid);
}

static void __init memmap_init_zone_range(struct zone *zone,
					  unsigned long start_pfn,
					  unsigned long end_pfn,
					  unsigned long *hole_pfn)
{
	unsigned long zone_start_pfn = zone->zone_start_pfn;

	// 结束地址是包含洞的
	unsigned long zone_end_pfn = zone_start_pfn + zone->spanned_pages;
	int nid = zone_to_nid(zone), zone_id = zone_idx(zone);

	// 将地址固定到zone的地址范围里
	start_pfn = clamp(start_pfn, zone_start_pfn, zone_end_pfn);
	end_pfn = clamp(end_pfn, zone_start_pfn, zone_end_pfn);

	// 错误的区间
	if (start_pfn >= end_pfn)
		return;

	// 初始化区间
	memmap_init_zone(end_pfn - start_pfn, nid, zone_id, start_pfn,
			  zone_end_pfn, MEMINIT_EARLY, NULL, MIGRATE_MOVABLE);

	// 初始化不可用的区间？
	if (*hole_pfn < start_pfn)
		init_unavailable_range(*hole_pfn, start_pfn, zone_id, nid);

	*hole_pfn = end_pfn;
}

void __meminit memmap_init_zone(unsigned long size, int nid, unsigned long zone,
		unsigned long start_pfn, unsigned long zone_end_pfn,
		enum meminit_context context,
		struct vmem_altmap *altmap, int migratetype)
{
	unsigned long pfn, end_pfn = start_pfn + size;
	struct page *page;

	if (highest_memmap_pfn < end_pfn - 1)
		highest_memmap_pfn = end_pfn - 1;

#ifdef CONFIG_ZONE_DEVICE
	/*
	 * Honor reservation requested by the driver for this ZONE_DEVICE
	 * memory. We limit the total number of pages to initialize to just
	 * those that might contain the memory mapping. We will defer the
	 * ZONE_DEVICE page initialization until after we have released
	 * the hotplug lock.
	 */
	if (zone == ZONE_DEVICE) {
		if (!altmap)
			return;

		if (start_pfn == altmap->base_pfn)
			start_pfn += altmap->reserve;
		end_pfn = altmap->base_pfn + vmem_altmap_offset(altmap);
	}
#endif

	for (pfn = start_pfn; pfn < end_pfn; ) {
		// 初始化的时这个条件成立，热插拔时不成立
		if (context == MEMINIT_EARLY) {
			// 当cmd参数里有mirror时，这个函数才有用，否则返回false。暂时不看
			if (overlap_memmap_init(zone, &pfn))
				continue;
			// 当CONFIG_DEFERRED_STRUCT_PAGE_INIT这个条件打开的时候才有用
			if (defer_init(nid, pfn, zone_end_pfn))
				break;
		}

		// 根据物理地址转换成page结构
		page = pfn_to_page(pfn);
		// 设置page的一些基础数据
		__init_single_page(page, pfn, zone, nid);

		// 热插拔
		if (context == MEMINIT_HOTPLUG)
			__SetPageReserved(page);

		// 和大块页对齐时
		if (IS_ALIGNED(pfn, pageblock_nr_pages)) {
			// 设置页的迁移类型，从上面传下来的类型是可移动的
			set_pageblock_migratetype(page, migratetype);
			cond_resched();
		}
		pfn++;
	}
}

void set_pageblock_migratetype(struct page *page, int migratetype)
{
	// 如果迁移性禁用时，如果不是pcp类型，都设置为不可移动
	if (unlikely(page_group_by_mobility_disabled &&
		     migratetype < MIGRATE_PCPTYPES))
		migratetype = MIGRATE_UNMOVABLE;

	// 在pageblock_flags里设置对应的位
	set_pfnblock_flags_mask(page, (unsigned long)migratetype,
				page_to_pfn(page), MIGRATETYPE_MASK);
}

void set_pfnblock_flags_mask(struct page *page, unsigned long flags,
					unsigned long pfn,
					unsigned long mask)
{
	unsigned long *bitmap;
	unsigned long bitidx, word_bitidx;
	unsigned long old_word, word;

	BUILD_BUG_ON(NR_PAGEBLOCK_BITS != 4);
	BUILD_BUG_ON(MIGRATE_TYPES > (1 << PB_migratetype_bits));

	// 获取对应zone上的pageblock_flags
	bitmap = get_pageblock_bitmap(page, pfn);
	// 对应的位
	bitidx = pfn_to_bitidx(page, pfn);
	// 第几个long
	word_bitidx = bitidx / BITS_PER_LONG;
	// long里面的offset
	bitidx &= (BITS_PER_LONG-1);

	VM_BUG_ON_PAGE(!zone_spans_pfn(page_zone(page), pfn), page);

	mask <<= bitidx;
	flags <<= bitidx;

	// 读出对应位置上的long
	word = READ_ONCE(bitmap[word_bitidx]);
	for (;;) {
		// 把新值写到对应的bitmap里
		old_word = cmpxchg(&bitmap[word_bitidx], word, (word & ~mask) | flags);
		// 在写入期间没有竞争则退出，这是无锁并发
		if (word == old_word)
			break;
		word = old_word;
	}
}

static inline unsigned long *get_pageblock_bitmap(struct page *page,
							unsigned long pfn)
{
#ifdef CONFIG_SPARSEMEM
	return section_to_usemap(__pfn_to_section(pfn));
#else
	return page_zone(page)->pageblock_flags;
#endif /* CONFIG_SPARSEMEM */
}

static void __meminit __init_single_page(struct page *page, unsigned long pfn,
				unsigned long zone, int nid)
{
	// 把page结构清0
	mm_zero_struct_page(page);
	// 设置page的zone类型和nid号。这2个数据都保存在page->flags里
	set_page_links(page, zone, nid, pfn);
	// 设置page->_refcount为1
	init_page_count(page);
	// 把page->_mapcount设置成-1
	page_mapcount_reset(page);
	// 清除page->flags里的LAST_CPUPID_MASK
	page_cpupid_reset_last(page);
	// kasan相关
	page_kasan_tag_reset(page);

	// 初始化lru表头
	INIT_LIST_HEAD(&page->lru);
	// 这个只在一些特殊的架构里定义了，暂时不看
#ifdef WANT_PAGE_VIRTUAL
	/* The shift won't overflow because ZONE_NORMAL is below 4G. */
	if (!is_highmem_idx(zone))
		set_page_address(page, __va(pfn << PAGE_SHIFT));
#endif
}

static inline void set_page_links(struct page *page, enum zone_type zone,
	unsigned long node, unsigned long pfn)
{
	// 设置zone类型
	set_page_zone(page, zone);
	// 设置node号
	set_page_node(page, node);
	// 这个配置一般不开
#ifdef SECTION_IN_PAGE_FLAGS
	set_page_section(page, pfn_to_section_nr(pfn));
#endif
}

static inline void set_page_zone(struct page *page, enum zone_type zone)
{
	// 清除ZONES_MASK位上的数据
	page->flags &= ~(ZONES_MASK << ZONES_PGSHIFT);
	// 把zone类型写到对应的位上
	page->flags |= (zone & ZONES_MASK) << ZONES_PGSHIFT;
}

static inline void set_page_node(struct page *page, unsigned long node)
{
	// 清除NODES_MASK位上的数据
	page->flags &= ~(NODES_MASK << NODES_PGSHIFT);
	// 把node节点号写到对应的位上
	page->flags |= (node & NODES_MASK) << NODES_PGSHIFT;
}

#if BITS_PER_LONG == 64
// 注释里说，在一些架构里,memset开销较大，所以采用这种方式来对page进行清0，
// 这种格式在经过编译器优化以后，也会变成mov指令
#define	mm_zero_struct_page(pp) __mm_zero_struct_page(pp)
static inline void __mm_zero_struct_page(struct page *page)
{
	unsigned long *_pp = (void *)page;

	 /* Check that struct page is either 56, 64, 72, or 80 bytes */
	BUILD_BUG_ON(sizeof(struct page) & 7);
	BUILD_BUG_ON(sizeof(struct page) < 56);
	BUILD_BUG_ON(sizeof(struct page) > 80);

	switch (sizeof(struct page)) {
	case 80:
		_pp[9] = 0;
		fallthrough;
	case 72:
		_pp[8] = 0;
		fallthrough;
	case 64:
		_pp[7] = 0;
		fallthrough;
	case 56:
		_pp[6] = 0;
		_pp[5] = 0;
		_pp[4] = 0;
		_pp[3] = 0;
		_pp[2] = 0;
		_pp[1] = 0;
		_pp[0] = 0;
	}
}
#else
#define mm_zero_struct_page(pp)  ((void)memset((pp), 0, sizeof(struct page)))
#endif

```

## free_area_init_core
```c
static void __init free_area_init_core(struct pglist_data *pgdat)
{
	enum zone_type j;
	int nid = pgdat->node_id;

	// 初始化pgdat内部的一些变量 
	pgdat_init_internals(pgdat);
	// todo: percpu的状态和boot_nodestats的状态相同?
	pgdat->per_cpu_nodestats = &boot_nodestats;

	for (j = 0; j < MAX_NR_ZONES; j++) {
		struct zone *zone = pgdat->node_zones + j;
		unsigned long size, freesize, memmap_pages;
		// zone的开始地址 
		unsigned long zone_start_pfn = zone->zone_start_pfn;

		// 所有页面数量
		size = zone->spanned_pages;
		// 可用页面数量
		freesize = zone->present_pages;

		// 计算可直接映射的页的数量
		memmap_pages = calc_memmap_size(size, freesize);
		// is_highmem_idx判断是否是高端内存，
		// 在x86_64上没有高端内存，所以这个函数返回0
		if (!is_highmem_idx(j)) {
			if (freesize >= memmap_pages) {
				// 从空闲页里减去直接映射的页
				freesize -= memmap_pages;
				if (memmap_pages)
					printk(KERN_DEBUG
					       "  %s zone: %lu pages used for memmap\n",
					       zone_names[j], memmap_pages);
			} else
				pr_warn("  %s zone: %lu pages exceeds freesize %lu\n",
					zone_names[j], memmap_pages, freesize);
		}

		// 第一个区域是dma，所以从空闲列表里先把为dma保留的去掉
		if (j == 0 && freesize > dma_reserve) {
			freesize -= dma_reserve;
			printk(KERN_DEBUG "  %s zone: %lu pages reserved\n",
					zone_names[0], dma_reserve);
		}

		if (!is_highmem_idx(j))
			// nr_kernel_pages统计所有直接映射的页
			nr_kernel_pages += freesize;
		else if (nr_kernel_pages > memmap_pages * 2)
			// 高端内存暂不看
			nr_kernel_pages -= memmap_pages;
		// nr_all_pages统计所有的页包括高端内存
		nr_all_pages += freesize;

		// 区域的一些初始化
		zone_init_internals(zone, j, nid, freesize);

		// 区域页面数量为0？
		if (!size)
			continue;

		// 这个在打开CONFIG_HUGETLB_PAGE_SIZE_VARIABLE时才有效，暂不看
		set_pageblock_order();
		// 这个在没打开CONFIG_SPARSEMEM时才有效，暂不看
		setup_usemap(pgdat, zone, zone_start_pfn, size);
		// 主要初始化了zone里的空闲列表
		init_currently_empty_zone(zone, zone_start_pfn, size);
		// 这个函数默认为空，x86没有提供
		arch_memmap_init(size, nid, j, zone_start_pfn);
	}
}

void __meminit init_currently_empty_zone(struct zone *zone,
					unsigned long zone_start_pfn,
					unsigned long size)
{
	struct pglist_data *pgdat = zone->zone_pgdat;
	int zone_idx = zone_idx(zone) + 1;

	// 调整pgdat里zone最大下标的计算
	if (zone_idx > pgdat->nr_zones)
		pgdat->nr_zones = zone_idx;

	// zone的起始地址
	zone->zone_start_pfn = zone_start_pfn;

	mminit_dprintk(MMINIT_TRACE, "memmap_init",
			"Initialising map node %d zone %lu pfns %lu -> %lu\n",
			pgdat->node_id,
			(unsigned long)zone_idx(zone),
			zone_start_pfn, (zone_start_pfn + size));
	// 初始化每个空闲列表
	zone_init_free_lists(zone);
	zone->initialized = 1;
}

static void __meminit zone_init_free_lists(struct zone *zone)
{
	unsigned int order, t;
	// 遍历每个order的每个迁移类型
	for_each_migratetype_order(order, t) {
		INIT_LIST_HEAD(&zone->free_area[order].free_list[t]);
		// 现在先把它设置为0，等到boot分配器停用后，才会设置真正的值
		zone->free_area[order].nr_free = 0;
	}
}

#define for_each_migratetype_order(order, type) \
	for (order = 0; order < MAX_ORDER; order++) \
		for (type = 0; type < MIGRATE_TYPES; type++)

static void __meminit zone_init_internals(struct zone *zone, enum zone_type idx, int nid,
							unsigned long remaining_pages)
{
	// managed_pages是未直接映射的页面？
	atomic_long_set(&zone->managed_pages, remaining_pages);
	// 设置zone的nid
	zone_set_nid(zone, nid);
	// 区域名。DMA,DMA32,NORMAL....
	zone->name = zone_names[idx];
	// 设置pgdat引用
	zone->zone_pgdat = NODE_DATA(nid);
	// 锁的初始化
	spin_lock_init(&zone->lock);
	zone_seqlock_init(zone);
	// 初始化percpu-set
	zone_pcp_init(zone);
}

static __meminit void zone_pcp_init(struct zone *zone)
{
	// 先让它等于启动时的set，因为其它的还没准备好
	zone->pageset = &boot_pageset;

	// 区域里是否有可用页
	if (populated_zone(zone))
		printk(KERN_DEBUG "  %s zone: %lu pages, LIFO batch:%u\n",
			zone->name, zone->present_pages,
					 zone_batchsize(zone));
}

static unsigned long __init calc_memmap_size(unsigned long spanned_pages,
						unsigned long present_pages)
{
	unsigned long pages = spanned_pages;

	// 洞的数量如果大于可用数量的 1/16，则只能映射可用页面数量
	if (spanned_pages > present_pages + (present_pages >> 4) &&
	    IS_ENABLED(CONFIG_SPARSEMEM))
		pages = present_pages;

	// 否则，可以映射所有page。todo: why?
	return PAGE_ALIGN(pages * sizeof(struct page)) >> PAGE_SHIFT;
}

static void __meminit pgdat_init_internals(struct pglist_data *pgdat)
{
	// 初始化node_size_lock
	pgdat_resize_init(pgdat);

	// 延迟分割队列？todo：这个队列是干什么的
	pgdat_init_split_queue(pgdat);
	// 初始化kcompactd_wait
	pgdat_init_kcompactd(pgdat);

	// kswapd的等待队列头
	init_waitqueue_head(&pgdat->kswapd_wait);
	// todo: pfmemalloc是什么？
	init_waitqueue_head(&pgdat->pfmemalloc_wait);

	// 这个在CONFIG_PAGE_EXTENSION打开时才有用，一般这个选项没开
	pgdat_page_ext_init(pgdat);
	// lru列表的保护锁
	spin_lock_init(&pgdat->lru_lock);
	// 初始化lru向量数组
	lruvec_init(&pgdat->__lruvec);
}
```