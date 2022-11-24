# 内存管理

源码基于5.10

假设CONFIG_NUMA打开

## 数据结构
```c

// include/linux/mm_types.h
// 页
struct page {
	unsigned long flags; // 一组标志，也对页框的管理区进行编号
	/*
	 * Five words (20/40 bytes) are available in this union.
	 * WARNING: bit 0 of the first word is used for PageTail(). That
	 * means the other users of this union MUST NOT use the bit to
	 * avoid collision and false-positive PageTail().
	 */
	union {
		struct {	/* 页高速缓存和匿名页使用 */
			/**
			 * @lru: Pageout list, eg. active_list protected by
			 * zone_lru_lock.  Sometimes used as a generic list
			 * by the page owner.

			 * lru 链表指针
			 */
			struct list_head lru;
			/* See page-flags.h for PAGE_MAPPING_FLAGS */
			struct address_space *mapping; // 属于页高速缓存或者匿名页时使用
			pgoff_t index;	// 在映射中的偏移量
			/**
			 * @private: 映射私有数据
			 * 在PagePrivate时用做buffer_head
			 * 在PageSwapCache时用做swp_entry_t
			 * 在PageBuddy时指向buddy的阶数
			 */
			unsigned long private;
		};
		struct {	/* slab, slob and slub */
			union {
				struct list_head slab_list;	/* uses lru */
				struct {	/* Partial pages */
					struct page *next;
#ifdef CONFIG_64BIT
					int pages;	/* Nr of pages left */
					int pobjects;	/* Approximate count */
#else
					short int pages;
					short int pobjects;
#endif
				};
			};
			struct kmem_cache *slab_cache; /* not slob */
			/* Double-word boundary */
			void *freelist;		/* first free object */
			union {
				void *s_mem;	/* slab: first object */
				unsigned long counters;		/* SLUB */
				struct {			/* SLUB */
					unsigned inuse:16;
					unsigned objects:15;
					unsigned frozen:1;
				};
			};
		};
		struct {	/* Tail pages of compound page */
			unsigned long compound_head;	/* Bit zero is set */

			/* First tail page only */
			unsigned char compound_dtor;
			unsigned char compound_order;
			atomic_t compound_mapcount;
		};
		struct {	/* Second tail page of compound page */
			unsigned long _compound_pad_1;	/* compound_head */
			unsigned long _compound_pad_2;
			struct list_head deferred_list;
		};
		struct {	/* Page table pages */
			unsigned long _pt_pad_1;	/* compound_head */
			pgtable_t pmd_huge_pte; /* protected by page->ptl */
			unsigned long _pt_pad_2;	/* mapping */
			union {
				struct mm_struct *pt_mm; /* x86 pgds only */
				atomic_t pt_frag_refcount; /* powerpc */
			};
#if ALLOC_SPLIT_PTLOCKS
			spinlock_t *ptl;
#else
			spinlock_t ptl;
#endif
		};
		struct {	/* ZONE_DEVICE pages */
			/** @pgmap: Points to the hosting device page map. */
			struct dev_pagemap *pgmap;
			unsigned long hmm_data;
			unsigned long _zd_pad_1;	/* uses mapping */
		};

		/** @rcu_head: You can use this to free a page by RCU. */
		struct rcu_head rcu_head;
	};

	union {		/* This union is 4 bytes in size. */
		/*
		 * If the page can be mapped to userspace, encodes the number
		 * of times this page is referenced by a page table.
		 */
		atomic_t _mapcount; // 页框中页表项的数目

		/*
		 * If the page is neither PageSlab nor mappable to userspace,
		 * the value stored here may help determine what this page
		 * is used for.  See page-flags.h for a list of page types
		 * which are currently stored here.
		 */
		unsigned int page_type;

		unsigned int active;		/* SLAB */
		int units;			/* SLOB */
	};

	/* Usage count. *DO NOT USE DIRECTLY*. See page_ref.h 
	 * 页框的引用计数
	 * 如果该字段为1，则页框空闲
	 * 如果大于或等于0，则说明该页已分配
	*/
	atomic_t _refcount;

#ifdef CONFIG_MEMCG
	struct mem_cgroup *mem_cgroup;
#endif

	/*
	 * On machines where all RAM is mapped into kernel address space,
	 * we can simply calculate the virtual address. On machines with
	 * highmem some memory is mapped into kernel virtual memory
	 * dynamically, so we need a place to store that address.
	 * Note that this field could be 16 bits on x86 ... ;)
	 *
	 * Architectures with slow multiplication can define
	 * WANT_PAGE_VIRTUAL in asm/page.h
	 */
#if defined(WANT_PAGE_VIRTUAL)
	void *virtual;			/* Kernel virtual address (NULL if
					   not kmapped, ie. highmem) */
#endif /* WANT_PAGE_VIRTUAL */

#ifdef LAST_CPUPID_NOT_IN_PAGE_FLAGS
	int _last_cpupid;
#endif
} _struct_page_alignment;


enum pageflags {
	PG_locked,		/* 页被锁定 */
	PG_referenced,		/* 刚刚访问过的页 */
	PG_uptodate,		/* 页里的数据与磁盘保持一致 */
	PG_dirty,		/* 页已被修改 */
	PG_lru,			/* 页在活动或非活动链表中 */
	PG_active,		/* 页在活动页链表中 */
	PG_workingset,
	PG_waiters,		/* Page has waiters, check its waitqueue. Must be bit #7 and in the same byte as "PG_locked" */
	PG_error,		/* 在传输页时发生io错误 */
	PG_slab,		/* 页被slab使用 */
	PG_owner_priv_1,	/* Owner use. If pagecache, fs may use*/
	PG_arch_1,
	PG_reserved,		/* 页留给内核代码或没有使用 */
	PG_private,		/* page->private存放了数据。If pagecache, has fs-private data */
	PG_private_2,		/* 同上，If pagecache, has fs aux data */
	PG_writeback,		/* 正在使用将页写加磁盘 */
	PG_head,		/* A head page */
	PG_mappedtodisk,	/* Has blocks allocated on-disk */
	PG_reclaim,		/* 页正在被回收 */
	PG_swapbacked,		/* Page is backed by RAM/swap */
	PG_unevictable,		/* Page is "unevictable"  */
#ifdef CONFIG_MMU
	PG_mlocked,		/* Page is vma mlocked */
#endif
#ifdef CONFIG_ARCH_USES_PG_UNCACHED
	PG_uncached,		/* Page has been mapped as uncached */
#endif
#ifdef CONFIG_MEMORY_FAILURE
	PG_hwpoison,		/* hardware poisoned page. Don't touch */
#endif
#if defined(CONFIG_IDLE_PAGE_TRACKING) && defined(CONFIG_64BIT)
	PG_young,
	PG_idle,
#endif
#ifdef CONFIG_64BIT
	PG_arch_2,
#endif
	__NR_PAGEFLAGS,

	/* Filesystems */
	PG_checked = PG_owner_priv_1,	/* 由一些文件系统（ext2/3）使用 */

	/* 页属于页交换缓存 */
	PG_swapcache = PG_owner_priv_1,	/* Swap page: swp_entry_t in private */

	/* Two page bits are conscripted by FS-Cache to maintain local caching
	 * state.  These bits are set on pages belonging to the netfs's inodes
	 * when those inodes are being locally cached.
	 */
	PG_fscache = PG_private_2,	/* page backed by cache */

	/* XEN */
	/* Pinned in Xen as a read-only pagetable page. */
	PG_pinned = PG_owner_priv_1,
	/* Pinned as part of domain save (see xen_mm_pin_all()). */
	PG_savepinned = PG_dirty,
	/* Has a grant mapping of another (foreign) domain's page. */
	PG_foreign = PG_owner_priv_1,
	/* Remapped by swiotlb-xen. */
	PG_xen_remapped = PG_owner_priv_1,

	/* SLOB */
	PG_slob_free = PG_private,

	/* Compound pages. Stored in first tail page's flags */
	PG_double_map = PG_workingset,

	/* non-lru isolated movable page */
	PG_isolated = PG_reclaim,

	/* Only valid for buddy pages. Used to track pages that are reported */
	PG_reported = PG_uptodate,
};

// include/linux/mmzone.h
// 区域。页被分在不同的区
struct zone {
	/* Read-mostly fields */

	/* zone watermarks, access with *_wmark_pages(zone) macros */
	/*
	enum zone_watermarks {
		WMARK_MIN,	// zone保留的最小数目
		WMARK_LOW,	// 回收页框的下界
		WMARK_HIGH,	// 回收页框的上界
		NR_WMARK
	};
	*/
	unsigned long watermark[NR_WMARK];

	unsigned long nr_reserved_highatomic;

	/*
	 * 保留的内存 
	 This array is
	 * recalculated at runtime if the sysctl_lowmem_reserve_ratio sysctl
	 * changes.
	 */
	long lowmem_reserve[MAX_NR_ZONES];

#ifdef CONFIG_NUMA
	int node;
#endif
	struct pglist_data	*zone_pgdat;	// 指向节点的指针
	struct per_cpu_pageset __percpu *pageset;	// 单个页的per-cpu缓存

#ifndef CONFIG_SPARSEMEM
	/*
	 * Flags for a pageblock_nr_pages block. See pageblock-flags.h.
	 * In SPARSEMEM, this map is stored in struct mem_section
	 */
	unsigned long		*pageblock_flags;
#endif /* CONFIG_SPARSEMEM */

	/* zone_start_pfn == zone_start_paddr >> PAGE_SHIFT */
	unsigned long		zone_start_pfn;	// 管理区第一个页框下标

	/*
	 * spanned_pages is the total pages spanned by the zone, including
	 * holes, which is calculated as:
	 * 	spanned_pages = zone_end_pfn - zone_start_pfn;
	 *
	 * present_pages is physical pages existing within the zone, which
	 * is calculated as:
	 *	present_pages = spanned_pages - absent_pages(pages in holes);
	 *
	 * managed_pages is present pages managed by the buddy system, which
	 * is calculated as (reserved_pages includes pages allocated by the
	 * bootmem allocator):
	 *	managed_pages = present_pages - reserved_pages;
	 *
	 * So present_pages may be used by memory hotplug or memory power
	 * management logic to figure out unmanaged pages by checking
	 * (present_pages - managed_pages). And managed_pages should be used
	 * by page allocator and vm scanner to calculate all kinds of watermarks
	 * and thresholds.
	 *
	 * Locking rules:
	 *
	 * zone_start_pfn and spanned_pages are protected by span_seqlock.
	 * It is a seqlock because it has to be read outside of zone->lock,
	 * and it is done in the main allocator path.  But, it is written
	 * quite infrequently.
	 *
	 * The span_seq lock is declared along with zone->lock because it is
	 * frequently read in proximity to zone->lock.  It's good to
	 * give them a chance of being in the same cacheline.
	 *
	 * Write access to present_pages at runtime should be protected by
	 * mem_hotplug_begin/end(). Any reader who can't tolerant drift of
	 * present_pages should get_online_mems() to get a stable value.
	 *
	 * Read access to managed_pages should be safe because it's unsigned
	 * long. Write access to zone->managed_pages and totalram_pages are
	 * protected by managed_page_count_lock at runtime. Idealy only
	 * adjust_managed_page_count() should be used instead of directly
	 * touching zone->managed_pages and totalram_pages.
	 */
	unsigned long		managed_pages;	// buddy管理的页
	unsigned long		spanned_pages;	// 所有页，包括洞
	unsigned long		present_pages;	// 所有页不包括洞

	const char		*name;	// 区域名

#ifdef CONFIG_MEMORY_ISOLATION
	/*
	 * Number of isolated pageblock. It is used to solve incorrect
	 * freepage counting problem due to racy retrieving migratetype
	 * of pageblock. Protected by zone->lock.
	 */
	unsigned long		nr_isolate_pageblock;
#endif

#ifdef CONFIG_MEMORY_HOTPLUG
	/* 保护 spanned/present_pages 页 */
	seqlock_t		span_seqlock;
#endif

	int initialized;

	/* Write-intensive fields used from the page allocator */
	ZONE_PADDING(_pad1_)

	/* 不同阶数的空闲页 */
	struct free_area	free_area[MAX_ORDER];

	/* zone 标志 */
	unsigned long		flags;

	/* 主要保护 free_area */
	spinlock_t		lock;

	/* Write-intensive fields used by compaction and vmstats. */
	ZONE_PADDING(_pad2_)

	/*
	 * When free pages are below this point, additional steps are taken
	 * when reading the number of free pages to avoid per-cpu counter
	 * drift allowing watermarks to be breached
	 */
	unsigned long percpu_drift_mark;

#if defined CONFIG_COMPACTION || defined CONFIG_CMA
	/* pfn where compaction free scanner should start */
	unsigned long		compact_cached_free_pfn;
	/* pfn where async and sync compaction migration scanner should start */
	unsigned long		compact_cached_migrate_pfn[2];
#endif

#ifdef CONFIG_COMPACTION
	/*
	 * On compaction failure, 1<<compact_defer_shift compactions
	 * are skipped before trying again. The number attempted since
	 * last failure is tracked with compact_considered.
	 */
	unsigned int		compact_considered;
	unsigned int		compact_defer_shift;
	int			compact_order_failed;
#endif

#if defined CONFIG_COMPACTION || defined CONFIG_CMA
	/* Set to true when the PG_migrate_skip bits should be cleared */
	bool			compact_blockskip_flush;
#endif

	bool			contiguous;

	ZONE_PADDING(_pad3_)
	/* Zone 统计相关 */
	atomic_long_t		vm_stat[NR_VM_ZONE_STAT_ITEMS];
	atomic_long_t		vm_numa_stat[NR_VM_NUMA_STAT_ITEMS];
} ____cacheline_internodealigned_in_smp;

// node节点。一个node节点里有多个区
typedef struct pglist_data {
	struct zone node_zones[MAX_NR_ZONES]; // 节点中的管理区数组
	struct zonelist node_zonelists[MAX_ZONELISTS]; // 页分配器使用
	int nr_zones; // node_zones的大小
#ifdef CONFIG_FLAT_NODE_MEM_MAP	/* means !SPARSEMEM */
	struct page *node_mem_map; // 页描述符数组
#ifdef CONFIG_PAGE_EXTENSION
	struct page_ext *node_page_ext;
#endif
#endif
#ifndef CONFIG_NO_BOOTMEM
	struct bootmem_data *bdata; // 内核初始化阶段使用
#endif
#if defined(CONFIG_MEMORY_HOTPLUG) || defined(CONFIG_DEFERRED_STRUCT_PAGE_INIT)
	/*
	 * Must be held any time you expect node_start_pfn, node_present_pages
	 * or node_spanned_pages stay constant.  Holding this will also
	 * guarantee that any pfn_valid() stays that way.
	 *
	 * pgdat_resize_lock() and pgdat_resize_unlock() are provided to
	 * manipulate node_size_lock without checking for CONFIG_MEMORY_HOTPLUG
	 * or CONFIG_DEFERRED_STRUCT_PAGE_INIT.
	 *
	 * Nests above zone->lock and zone->span_seqlock
	 */
	spinlock_t node_size_lock;
#endif
	unsigned long node_start_pfn; // 第一个页框的序号
	unsigned long node_present_pages; /* 可用物理页的数量，不包括洞 */
	unsigned long node_spanned_pages; /* 可用物理页的数量，包括洞 */
	int node_id; // 节点id
	wait_queue_head_t kswapd_wait; // kswapd使用的等待队列
	wait_queue_head_t pfmemalloc_wait;
	struct task_struct *kswapd;	/* 内存回收线程 Protected by mem_hotplug_begin/end() */
	int kswapd_order; // kswapd要创建的空闲块大小的阶数
	enum zone_type kswapd_classzone_idx;

	int kswapd_failures;		/* Number of 'reclaimed == 0' runs */

#ifdef CONFIG_COMPACTION
	int kcompactd_max_order;
	enum zone_type kcompactd_classzone_idx;
	wait_queue_head_t kcompactd_wait;
	struct task_struct *kcompactd;
#endif
	/*
	 * This is a per-node reserve of pages that are not available
	 * to userspace allocations.
	 */
	unsigned long		totalreserve_pages;

#ifdef CONFIG_NUMA
	/*
	 * zone reclaim becomes active if more unmapped pages exist.
	 */
	unsigned long		min_unmapped_pages;
	unsigned long		min_slab_pages;
#endif /* CONFIG_NUMA */

	/* Write-intensive fields used by page reclaim */
	ZONE_PADDING(_pad1_)
	spinlock_t		lru_lock;

#ifdef CONFIG_DEFERRED_STRUCT_PAGE_INIT
	/*
	 * If memory initialisation on large machines is deferred then this
	 * is the first PFN that needs to be initialised.
	 */
	unsigned long first_deferred_pfn;
	/* Number of non-deferred pages */
	unsigned long static_init_pgcnt;
#endif /* CONFIG_DEFERRED_STRUCT_PAGE_INIT */

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	spinlock_t split_queue_lock;
	struct list_head split_queue;
	unsigned long split_queue_len;
#endif

	/* Fields commonly accessed by the page reclaim scanner */
	struct lruvec		lruvec;

	unsigned long		flags;

	ZONE_PADDING(_pad2_)

	/* Per-node vmstats */
	struct per_cpu_nodestat __percpu *per_cpu_nodestats;
	atomic_long_t		vm_stat[NR_VM_NODE_STAT_ITEMS];
} pg_data_t;

```
## 申请一页
```c
// mm/mempolicy.c

/**
gfp: 分配标志
order: 分配页的数量。数量是２的order次幂

返回：分析的页对象或者NULL
**/
struct page *alloc_pages_current(gfp_t gfp, unsigned order)
{
	// 内存策略。default_policy是默认分配策略
    /**
    static struct mempolicy default_policy = {
        .refcnt = ATOMIC_INIT(1), // never free it
        .mode = MPOL_LOCAL,
    };
    **/
	struct mempolicy *pol = &default_policy;
	struct page *page;

	// 如果不是在中断上下文并且分配标志没有设置只在当前节点分配，
    // 则获取进程的内存分配策略
	if (!in_interrupt() && !(gfp & __GFP_THISNODE))
		// get_task_policy先获取进程的策略，如果进程没有策略，则获取
        // 当前节点的分配策略，如果当前节点策略mode为０，则返回default_policy
		pol = get_task_policy(current);
	
	if (pol->mode == MPOL_INTERLEAVE) // 交叉分配
		// alloc_page_interleave直接调用__alloc_pages, 并做了些统计相关的操作。
		// __alloc_pages会直接调用__alloc_pages_nodemask

		// interleave_nodes会在policy所允许的节点中按顺序在节点中分配，如果到最后一个
		// 再从第一个开始，如此反复。
		page = alloc_page_interleave(gfp, order, interleave_nodes(pol));
	else　// 普通分配
		page = __alloc_pages_nodemask(gfp, order,
				policy_node(gfp, pol, numa_node_id()),
				policy_nodemask(gfp, pol));

	return page;
}

// mm/page_alloc.c

// 内存分配的核心函数
struct page * __alloc_pages_nodemask(gfp_t gfp_mask, unsigned int order, int 						preferred_nid,　nodemask_t *nodemask)
{
	struct page *page;
	unsigned int alloc_flags = ALLOC_WMARK_LOW;
	gfp_t alloc_mask; 

	// 申请上下文
	struct alloc_context ac = { };

	// 先去除一些不允许的标志
	gfp_mask &= gfp_allowed_mask;
	alloc_mask = gfp_mask;

	// 初始化分配上下文，以及提前判断此次分配是否会失败
	if (!prepare_alloc_pages(gfp_mask, order, preferred_nid, nodemask, &ac, &alloc_mask, &alloc_flags))
		return NULL;

	finalise_ac(gfp_mask, &ac);

	// 从空闲列表中分配页。
	// 大多数情况下在这一步都会分配成功
	page = get_page_from_freelist(alloc_mask, order, alloc_flags, &ac);
	if (likely(page))
		goto out;

	alloc_mask = current_gfp_context(gfp_mask);
	ac.spread_dirty_pages = false;

	if (unlikely(ac.nodemask != nodemask))
		ac.nodemask = nodemask;

	// 慢速分配路径
	page = __alloc_pages_slowpath(alloc_mask, order, &ac);

out:
	// todo: memcg_kmem_charge是什么？
	if (memcg_kmem_enabled() && (gfp_mask & __GFP_ACCOUNT) && page &&
	    unlikely(memcg_kmem_charge(page, gfp_mask, order) != 0)) {
		__free_pages(page, order);
		page = NULL;
	}

	// 调用trace事件接口
	trace_mm_page_alloc(page, order, alloc_mask, ac.migratetype);

	return page;
}
EXPORT_SYMBOL(__alloc_pages_nodemask);

static inline bool prepare_alloc_pages(gfp_t gfp_mask, unsigned int order,
		int preferred_nid, nodemask_t *nodemask,
		struct alloc_context *ac, gfp_t *alloc_mask,
		unsigned int *alloc_flags)
{
	// 取出zone
	ac->high_zoneidx = gfp_zone(gfp_mask);
	// 对应的zone_list，从node->zone_list的第0个或第1个开始
	ac->zonelist = node_zonelist(preferred_nid, gfp_mask);
	// 允许的node
	ac->nodemask = nodemask;
	// 迁移类型
	ac->migratetype = gfpflags_to_migratetype(gfp_mask);

	// todo:?
	if (cpusets_enabled()) {
		*alloc_mask |= __GFP_HARDWALL;
		if (!ac->nodemask)
			ac->nodemask = &cpuset_current_mems_allowed;
		else
			*alloc_flags |= ALLOC_CPUSET;
	}

	fs_reclaim_acquire(gfp_mask);
	fs_reclaim_release(gfp_mask);

	// 有直接回收标志，则可能睡眠？
	might_sleep_if(gfp_mask & __GFP_DIRECT_RECLAIM);

	// 这个需要打开 CONFIG_FAIL_PAGE_ALLOC
	if (should_fail_alloc_page(gfp_mask, order))
		return false;

	// 如果cma打开，且页可以迁移，则给标志里加cma标志
	if (IS_ENABLED(CONFIG_CMA) && ac->migratetype == MIGRATE_MOVABLE)
		*alloc_flags |= ALLOC_CMA;

	return true;
}

static inline void finalise_ac(gfp_t gfp_mask, struct alloc_context *ac)
{
	/* Dirty zone balancing only done in the fast path */
	ac->spread_dirty_pages = (gfp_mask & __GFP_WRITE);

	/*
	 * The preferred zone is used for statistics but crucially it is
	 * also used as the starting point for the zonelist iterator. It
	 * may get reset for allocations that ignore memory policies.
	 */
	ac->preferred_zoneref = first_zones_zonelist(ac->zonelist,
					ac->high_zoneidx, ac->nodemask);
}
```