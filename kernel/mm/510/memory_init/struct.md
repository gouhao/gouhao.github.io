# 内存结构体
源码基于5.10，本文里的代码都是在CONFIG_NUMA打开的情景里，现在内核这个选项都是打开的，即使电脑没有numa结构。

```c
struct zone {
	unsigned long _watermark[NR_WMARK]; // 水印，用于判断回收页
	unsigned long watermark_boost;

	unsigned long nr_reserved_highatomic;

	long lowmem_reserve[MAX_NR_ZONES]; // 保留区域

#ifdef CONFIG_NEED_MULTIPLE_NODES
	int node; // 节点编号
#endif
	struct pglist_data	*zone_pgdat; // 指向node结构
	struct per_cpu_pageset __percpu *pageset; // percpu-set

#ifndef CONFIG_SPARSEMEM
	/*
	 * Flags for a pageblock_nr_pages block. See pageblock-flags.h.
	 * In SPARSEMEM, this map is stored in struct mem_section
	 */
	unsigned long		*pageblock_flags;
#endif /* CONFIG_SPARSEMEM */

	/* zone_start_pfn == zone_start_paddr >> PAGE_SHIFT */
	unsigned long		zone_start_pfn; // 区域起始地址，对齐到页

	atomic_long_t		managed_pages; // buddy系统管理的页，可用页减去保留页
	unsigned long		spanned_pages; // 总共页面
	unsigned long		present_pages; // 可用页面

	const char		*name; // 区域名称

#ifdef CONFIG_MEMORY_ISOLATION
	unsigned long		nr_isolate_pageblock; // 隔离页面的数量
#endif

#ifdef CONFIG_MEMORY_HOTPLUG
	/* see spanned/present_pages for more description */
	seqlock_t		span_seqlock;
#endif

	int initialized; // 是否已经初始化

	/* Write-intensive fields used from the page allocator */
	ZONE_PADDING(_pad1_)

	struct free_area	free_area[MAX_ORDER]; //按order分类的列表

	unsigned long		flags;

	spinlock_t		lock; // 保护free_area的锁

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
	/* pfn where compaction migration scanner should start */
	unsigned long		compact_cached_migrate_pfn[ASYNC_AND_SYNC];
	unsigned long		compact_init_migrate_pfn;
	unsigned long		compact_init_free_pfn;
#endif

#ifdef CONFIG_COMPACTION
	/*
	 * On compaction failure, 1<<compact_defer_shift compactions
	 * are skipped before trying again. The number attempted since
	 * last failure is tracked with compact_considered.
	 * compact_order_failed is the minimum compaction failed order.
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
	
	// 内存使用的统计情况
	atomic_long_t		vm_stat[NR_VM_ZONE_STAT_ITEMS];
	atomic_long_t		vm_numa_stat[NR_VM_NUMA_STAT_ITEMS];
} ____cacheline_internodealigned_in_smp;

struct free_area {
	// 空闲列表，以迁移类型进行分类
	struct list_head	free_list[MIGRATE_TYPES];
	// 空闲页的数量，不以order分类
	unsigned long		nr_free;
};
```