# alloc_page
源码基于5.10， CONFIG_NUMA 打开

```c
#define alloc_page(gfp_mask) alloc_pages(gfp_mask, 0)

static inline struct page *
alloc_pages(gfp_t gfp_mask, unsigned int order)
{
	return alloc_pages_current(gfp_mask, order);
}

/**
 * 	alloc_pages_current - Allocate pages.
 *
 *	@gfp:
 *		%GFP_USER   user allocation,
 *      	%GFP_KERNEL kernel allocation,
 *      	%GFP_HIGHMEM highmem allocation,
 *      	%GFP_FS     don't call back into a file system.
 *      	%GFP_ATOMIC don't sleep.
 *	@order: Power of two of allocation size in pages. 0 is a single page.
 *
 *	Allocate a page from the kernel page pool.  When not in
 *	interrupt context and apply the current process NUMA policy.
 *	Returns NULL when no page can be allocated.
 */
struct page *alloc_pages_current(gfp_t gfp, unsigned order)
{
	struct mempolicy *pol = &default_policy;
	struct page *page;

	// 如果不在中断上下文，而且分配标志没有指定__GFP_THISNODE
    	// __GFP_THISNODE的意思是只在当前cpu的节点分配
	if (!in_interrupt() && !(gfp & __GFP_THISNODE))
		// get_task_policy先获取进程的策略，如果进程没有策略，则获取
        	// 当前节点的分配策略，如果当前节点策略mode为０，则返回default_policy
		pol = get_task_policy(current);

	// 区分交叉分配和普通分配
	if (pol->mode == MPOL_INTERLEAVE)
		// alloc_page_interleave直接调用__alloc_pages, 并做了些统计相关的操作。
		// __alloc_pages会直接调用__alloc_pages_nodemask

		// interleave_nodes会在policy所允许的节点中按顺序在节点中分配，如果到最后一个
		// 再从第一个开始，如此反复。
		page = alloc_page_interleave(gfp, order, interleave_nodes(pol));
	else
		// 普通分配
		page = __alloc_pages_nodemask(gfp, order,
				policy_node(gfp, pol, numa_node_id()),
				policy_nodemask(gfp, pol));

	return page;
}

struct page *
__alloc_pages_nodemask(gfp_t gfp_mask, unsigned int order, int preferred_nid,
							nodemask_t *nodemask)
{
	struct page *page;
	unsigned int alloc_flags = ALLOC_WMARK_LOW;
	gfp_t alloc_mask; /* The gfp_t that was actually used for allocation */
	// 分配上下文 
	struct alloc_context ac = { };

	// 阶数不能太大，MAX_ORDER可以在编译的时候设置，如果没有设置默认是11
	if (unlikely(order >= MAX_ORDER)) {
		WARN_ON_ONCE(!(gfp_mask & __GFP_NOWARN));
		return NULL;
	}

	// gfp_allowed_mask是系统中允许的gfp标志，和传进来的标志相与，
	// 可以去除系统不允许的标志。
	gfp_mask &= gfp_allowed_mask;
	// gfp_t实际上就是unsigned
	alloc_mask = gfp_mask;
	// prepare_alloc_pages主要是初始化alloc_context, 判断本次申请会不会失败，
	// 如果会失败，则返回false
	if (!prepare_alloc_pages(gfp_mask, order, preferred_nid, nodemask, &ac, &alloc_mask, &alloc_flags))
		return NULL;

	// 对flag做一些处理。todo: ?
	alloc_flags |= alloc_flags_nofragment(ac.preferred_zoneref->zone, gfp_mask);

	// 第一次尝试：从空闲列表里分配页。
	page = get_page_from_freelist(alloc_mask, order, alloc_flags, &ac);
	// 大多数情况，在这一步就会分配成功
	if (likely(page))
		goto out;

	/*
	 * Apply scoped allocation constraints. This is mainly about GFP_NOFS
	 * resp. GFP_NOIO which has to be inherited for all allocation requests
	 * from a particular context which has been marked by
	 * memalloc_no{fs,io}_{save,restore}.
	 */
	// todo: ?
	alloc_mask = current_gfp_context(gfp_mask);
	ac.spread_dirty_pages = false;

	/*
	 * Restore the original nodemask if it was potentially replaced with
	 * &cpuset_current_mems_allowed to optimize the fast-path attempt.
	 */
	// todo: ?
	ac.nodemask = nodemask;

	// 从这里进入慢速路径分配
	page = __alloc_pages_slowpath(alloc_mask, order, &ac);

out:
	// 这个if好像是cgroup的计费功能
	if (memcg_kmem_enabled() && (gfp_mask & __GFP_ACCOUNT) && page &&
	    unlikely(__memcg_kmem_charge_page(page, gfp_mask, order) != 0)) {
		// 超过了cgroup的限制，则释放页？
		__free_pages(page, order);
		page = NULL;
	}

	// alloc的trace桩
	trace_mm_page_alloc(page, order, alloc_mask, ac.migratetype);

	return page;
}
```

## 快速路径
```c
static struct page *
get_page_from_freelist(gfp_t gfp_mask, unsigned int order, int alloc_flags,
						const struct alloc_context *ac)
{
	struct zoneref *z;
	struct zone *zone;
	struct pglist_data *last_pgdat_dirty_limit = NULL;
	bool no_fallback;

retry:
	no_fallback = alloc_flags & ALLOC_NOFRAGMENT;
	z = ac->preferred_zoneref;
	// 遍历允许的所有zone
	for_next_zone_zonelist_nodemask(zone, z, ac->highest_zoneidx,
					ac->nodemask) {
		struct page *page;
		unsigned long mark;

		// 如果cpuset使能，则判断当前zone是否包括在允许的cpuset中。todo:?
		if (cpusets_enabled() &&
			(alloc_flags & ALLOC_CPUSET) &&
			!__cpuset_zone_allowed(zone, gfp_mask))
				continue;
		// 对脏页的处理。todo:?
		if (ac->spread_dirty_pages) {
			if (last_pgdat_dirty_limit == zone->zone_pgdat)
				continue;

			if (!node_dirty_ok(zone->zone_pgdat)) {
				last_pgdat_dirty_limit = zone->zone_pgdat;
				continue;
			}
		}

		// 在远程node上分配内存
		if (no_fallback && nr_online_nodes > 1 &&
		    zone != ac->preferred_zoneref->zone) {
			int local_nid;

			local_nid = zone_to_nid(ac->preferred_zoneref->zone);
			if (zone_to_nid(zone) != local_nid) {
				alloc_flags &= ~ALLOC_NOFRAGMENT;
				goto retry;
			}
		}

		// 取出限制水印的值
		mark = wmark_pages(zone, alloc_flags & ALLOC_WMARK_MASK);

		// 这个函数里会对水印进行判断，返回false表示出错
		// todo: 这里后面再看
		if (!zone_watermark_fast(zone, order, mark,
				       ac->highest_zoneidx, alloc_flags,
				       gfp_mask)) {
			int ret;

#ifdef CONFIG_DEFERRED_STRUCT_PAGE_INIT
			/*
			 * Watermark failed for this zone, but see if we can
			 * grow this zone if it contains deferred pages.
			 */
			if (static_branch_unlikely(&deferred_pages)) {
				if (_deferred_grow_zone(zone, order))
					goto try_this_zone;
			}
#endif
			/* Checked here to keep the fast path fast */
			BUILD_BUG_ON(ALLOC_NO_WATERMARKS < NR_WMARK);
			if (alloc_flags & ALLOC_NO_WATERMARKS)
				goto try_this_zone;

			if (node_reclaim_mode == 0 ||
			    !zone_allows_reclaim(ac->preferred_zoneref->zone, zone))
				continue;

			ret = node_reclaim(zone->zone_pgdat, gfp_mask, order);
			switch (ret) {
			case NODE_RECLAIM_NOSCAN:
				/* did not scan */
				continue;
			case NODE_RECLAIM_FULL:
				/* scanned but unreclaimable */
				continue;
			default:
				/* did we reclaim enough */
				if (zone_watermark_ok(zone, order, mark,
					ac->highest_zoneidx, alloc_flags))
					goto try_this_zone;

				continue;
			}
		}

try_this_zone:
		// 从当前节点分配一页。rmqueue是buddy算法的核心
		page = rmqueue(ac->preferred_zoneref->zone, zone, order,
				gfp_mask, alloc_flags, ac->migratetype);
		if (page) {
			// 分配成功
			prep_new_page(page, order, gfp_mask, alloc_flags);

			/*
			 * If this is a high-order atomic allocation then check
			 * if the pageblock should be reserved for the future
			 */
			if (unlikely(order && (alloc_flags & ALLOC_HARDER)))
				reserve_highatomic_pageblock(page, zone, order);

			return page;
		} else {
			// todo: 对延迟page的处理
#ifdef CONFIG_DEFERRED_STRUCT_PAGE_INIT
			/* Try again if zone has deferred pages */
			if (static_branch_unlikely(&deferred_pages)) {
				if (_deferred_grow_zone(zone, order))
					goto try_this_zone;
			}
#endif
		}
	} // 这是最开始的大循环

	/*
	 * It's possible on a UMA machine to get through all zones that are
	 * fragmented. If avoiding fragmentation, reset and try again.
	 */
	if (no_fallback) {
		alloc_flags &= ~ALLOC_NOFRAGMENT;
		goto retry;
	}

	return NULL;
}

static inline
struct page *rmqueue(struct zone *preferred_zone,
			struct zone *zone, unsigned int order,
			gfp_t gfp_flags, unsigned int alloc_flags,
			int migratetype)
{
	unsigned long flags;
	struct page *page;

	// order等于0也就是分配一页，这里对分配一页的情况进行了优化
	if (likely(order == 0)) {
		// 从per-cpu缓存里分配一页

		// 当迁移类型为MIGRATE_MOVABLE时，要跳过CMA()。todo: why?
		if (!IS_ENABLED(CONFIG_CMA) || alloc_flags & ALLOC_CMA ||
				migratetype != MIGRATE_MOVABLE) {
			page = rmqueue_pcplist(preferred_zone, zone, gfp_flags,
					migratetype, alloc_flags);
			goto out;
		}
	}

	// 不希望用户用__GFP_NOFAIL标志分配大于1阶的页数。
	// 也就是说，caller要求本次分配不能失败时，所分配的页数最好不要超过2页
	WARN_ON_ONCE((gfp_flags & __GFP_NOFAIL) && (order > 1));

	// 给zone上锁，同时关中断
	spin_lock_irqsave(&zone->lock, flags);

	do {
		page = NULL;
		// todo: ? 
		if (order > 0 && alloc_flags & ALLOC_HARDER) {
			page = __rmqueue_smallest(zone, order, MIGRATE_HIGHATOMIC);
			if (page)
				trace_mm_page_alloc_zone_locked(page, order, migratetype);
		}
		if (!page)
			// 分配一页
			page = __rmqueue(zone, order, migratetype, alloc_flags);
		// 在check_new_pages里会检查当前所分配的页数是不是够了
	} while (page && check_new_pages(page, order));

	// 这里只是解锁了，但并没有恢复中断
	spin_unlock(&zone->lock);

	// 分配失败
	if (!page)
		goto failed;
	
	// todo: ?
	__mod_zone_freepage_state(zone, -(1 << order),
				  get_pcppage_migratetype(page));

	// vm计数相关
	__count_zid_vm_events(PGALLOC, page_zonenum(page), 1 << order);
	zone_statistics(preferred_zone, zone);

	// 直到这里才恢复了中断
	local_irq_restore(flags);

out:
	// 如果水印值有升高，就唤醒kswapd
	// 原文注释：把test和clear分开，避免了不必要的指令
	if (test_bit(ZONE_BOOSTED_WATERMARK, &zone->flags)) {
		clear_bit(ZONE_BOOSTED_WATERMARK, &zone->flags);
		wakeup_kswapd(zone, 0, 0, zone_idx(zone));
	}

	// 页有问题，则报BUG
	VM_BUG_ON_PAGE(page && bad_range(zone, page), page);
	return page;

failed:
	local_irq_restore(flags);
	return NULL;
}

static __always_inline struct page *
__rmqueue(struct zone *zone, unsigned int order, int migratetype,
						unsigned int alloc_flags)
{
	struct page *page;

	// todo: CMA后面再看
	if (IS_ENABLED(CONFIG_CMA)) {
		/*
		 * Balance movable allocations between regular and CMA areas by
		 * allocating from CMA when over half of the zone's free memory
		 * is in the CMA area.
		 */
		if (alloc_flags & ALLOC_CMA &&
		    zone_page_state(zone, NR_FREE_CMA_PAGES) >
		    zone_page_state(zone, NR_FREE_PAGES) / 2) {
			page = __rmqueue_cma_fallback(zone, order);
			if (page)
				goto out;
		}
	}
retry:
	page = __rmqueue_smallest(zone, order, migratetype);
	if (unlikely(!page)) {
		if (alloc_flags & ALLOC_CMA)
			page = __rmqueue_cma_fallback(zone, order);

		if (!page && __rmqueue_fallback(zone, order, migratetype,
								alloc_flags))
			goto retry;
	}
out:
	if (page)
		trace_mm_page_alloc_zone_locked(page, order, migratetype);
	return page;
}

static __always_inline
struct page *__rmqueue_smallest(struct zone *zone, unsigned int order,
						int migratetype)
{
	unsigned int current_order;
	struct free_area *area;
	struct page *page;

	for (current_order = order; current_order < MAX_ORDER; ++current_order) {
		// 取出阶数对应的area
		area = &(zone->free_area[current_order]);
		// 取出空闲列表的对应类型的第一个元素
		page = get_page_from_free_area(area, migratetype);

		// 当前阶已没有空闲，则继续循环，增加order，增加order也就是从分配更大的块
		if (!page)
			continue;
		// 从空闲列表把这一页删除
		del_page_from_free_list(page, zone, current_order);
		// 分配的页可能大于需要的数量，则把其它数量放在其它阶的队列里
		expand(zone, page, order, current_order, migratetype);
		// 把迁移类型保存在page->index里
		set_pcppage_migratetype(page, migratetype);
		return page;
	}

	return NULL;
}

static inline struct page *get_page_from_free_area(struct free_area *area,
					    int migratetype)
{
	return list_first_entry_or_null(&area->free_list[migratetype],
					struct page, lru);
}

static inline void del_page_from_free_list(struct page *page, struct zone *zone,
					   unsigned int order)
{
	// todo: what is report?
	if (page_reported(page))
		__ClearPageReported(page);

	// 删除页，页是用lru指针挂到free_list里的
	list_del(&page->lru);
	// 清除buddy标志，buddy标志表示这一页目录由buddy系统管理
	__ClearPageBuddy(page);
	// 清除private
	set_page_private(page, 0);
	// 减少对应order的页的数量
	zone->free_area[order].nr_free--;
}

static inline void expand(struct zone *zone, struct page *page,
	int low, int high, int migratetype)
{
	unsigned long size = 1 << high;

	// low: caller需要的order
	// high: 当前分配的order
	// high > low 表示是从大块上分配的page，要把多余的链表buddy系统的其它order列表里
	while (high > low) {
		// 小一阶
		high--;

		// 小一阶的大小减半
		size >>= 1;

		// bad_range是调试相关, todo: 后面看
		VM_BUG_ON_PAGE(bad_range(zone, &page[size]), &page[size]);

		// 调试相关，todo: 后面看
		if (set_page_guard(zone, &page[size], high, migratetype))
			continue;

		// 把size数量的页，添加到对应order对应类型的列表里
		add_to_free_list(&page[size], zone, high, migratetype);
		// 在page->private里存储order
		set_buddy_order(&page[size], high);
	}
}

static inline void add_to_free_list(struct page *page, struct zone *zone,
				    unsigned int order, int migratetype)
{
	// order对应的area
	struct free_area *area = &zone->free_area[order];

	// 加到类型对应的列表
	list_add(&page->lru, &area->free_list[migratetype]);

	// 空闲块计数增加
	area->nr_free++;
}

static inline void set_buddy_order(struct page *page, unsigned int order)
{
	// 在private字段存储order
	set_page_private(page, order);
	// 设置buddy标志
	__SetPageBuddy(page);
}

```
## per-cpu分配
```c
static struct page *rmqueue_pcplist(struct zone *preferred_zone,
			struct zone *zone, gfp_t gfp_flags,
			int migratetype, unsigned int alloc_flags)
{
	struct per_cpu_pages *pcp;
	struct list_head *list;
	struct page *page;
	unsigned long flags;

	local_irq_save(flags);
	pcp = &this_cpu_ptr(zone->pageset)->pcp;
	list = &pcp->lists[migratetype];
	page = __rmqueue_pcplist(zone,  migratetype, alloc_flags, pcp, list);
	if (page) {
		__count_zid_vm_events(PGALLOC, page_zonenum(page), 1);
		zone_statistics(preferred_zone, zone);
	}
	local_irq_restore(flags);
	return page;
}
```

## 慢速路径
```c
static inline struct page *
__alloc_pages_slowpath(gfp_t gfp_mask, unsigned int order,
						struct alloc_context *ac)
{
	bool can_direct_reclaim = gfp_mask & __GFP_DIRECT_RECLAIM;
	const bool costly_order = order > PAGE_ALLOC_COSTLY_ORDER;
	struct page *page = NULL;
	unsigned int alloc_flags;
	unsigned long did_some_progress;
	enum compact_priority compact_priority;
	enum compact_result compact_result;
	int compaction_retries;
	int no_progress_loops;
	unsigned int cpuset_mems_cookie;
	int reserve_flags;

	/*
	 * We also sanity check to catch abuse of atomic reserves being used by
	 * callers that are not in atomic context.
	 */
	if (WARN_ON_ONCE((gfp_mask & (__GFP_ATOMIC|__GFP_DIRECT_RECLAIM)) ==
				(__GFP_ATOMIC|__GFP_DIRECT_RECLAIM)))
		gfp_mask &= ~__GFP_ATOMIC;

retry_cpuset:
	compaction_retries = 0;
	no_progress_loops = 0;
	compact_priority = DEF_COMPACT_PRIORITY;
	cpuset_mems_cookie = read_mems_allowed_begin();

	/*
	 * The fast path uses conservative alloc_flags to succeed only until
	 * kswapd needs to be woken up, and to avoid the cost of setting up
	 * alloc_flags precisely. So we do that now.
	 */
	alloc_flags = gfp_to_alloc_flags(gfp_mask);

	/*
	 * We need to recalculate the starting point for the zonelist iterator
	 * because we might have used different nodemask in the fast path, or
	 * there was a cpuset modification and we are retrying - otherwise we
	 * could end up iterating over non-eligible zones endlessly.
	 */
	ac->preferred_zoneref = first_zones_zonelist(ac->zonelist,
					ac->highest_zoneidx, ac->nodemask);
	if (!ac->preferred_zoneref->zone)
		goto nopage;

	if (alloc_flags & ALLOC_KSWAPD)
		wake_all_kswapds(order, gfp_mask, ac);

	/*
	 * The adjusted alloc_flags might result in immediate success, so try
	 * that first
	 */
	page = get_page_from_freelist(gfp_mask, order, alloc_flags, ac);
	if (page)
		goto got_pg;

	/*
	 * For costly allocations, try direct compaction first, as it's likely
	 * that we have enough base pages and don't need to reclaim. For non-
	 * movable high-order allocations, do that as well, as compaction will
	 * try prevent permanent fragmentation by migrating from blocks of the
	 * same migratetype.
	 * Don't try this for allocations that are allowed to ignore
	 * watermarks, as the ALLOC_NO_WATERMARKS attempt didn't yet happen.
	 */
	if (can_direct_reclaim &&
			(costly_order ||
			   (order > 0 && ac->migratetype != MIGRATE_MOVABLE))
			&& !gfp_pfmemalloc_allowed(gfp_mask)) {
		page = __alloc_pages_direct_compact(gfp_mask, order,
						alloc_flags, ac,
						INIT_COMPACT_PRIORITY,
						&compact_result);
		if (page)
			goto got_pg;

		/*
		 * Checks for costly allocations with __GFP_NORETRY, which
		 * includes some THP page fault allocations
		 */
		if (costly_order && (gfp_mask & __GFP_NORETRY)) {
			/*
			 * If allocating entire pageblock(s) and compaction
			 * failed because all zones are below low watermarks
			 * or is prohibited because it recently failed at this
			 * order, fail immediately unless the allocator has
			 * requested compaction and reclaim retry.
			 *
			 * Reclaim is
			 *  - potentially very expensive because zones are far
			 *    below their low watermarks or this is part of very
			 *    bursty high order allocations,
			 *  - not guaranteed to help because isolate_freepages()
			 *    may not iterate over freed pages as part of its
			 *    linear scan, and
			 *  - unlikely to make entire pageblocks free on its
			 *    own.
			 */
			if (compact_result == COMPACT_SKIPPED ||
			    compact_result == COMPACT_DEFERRED)
				goto nopage;

			/*
			 * Looks like reclaim/compaction is worth trying, but
			 * sync compaction could be very expensive, so keep
			 * using async compaction.
			 */
			compact_priority = INIT_COMPACT_PRIORITY;
		}
	}

retry:
	/* Ensure kswapd doesn't accidentally go to sleep as long as we loop */
	if (alloc_flags & ALLOC_KSWAPD)
		wake_all_kswapds(order, gfp_mask, ac);

	reserve_flags = __gfp_pfmemalloc_flags(gfp_mask);
	if (reserve_flags)
		alloc_flags = current_alloc_flags(gfp_mask, reserve_flags);

	/*
	 * Reset the nodemask and zonelist iterators if memory policies can be
	 * ignored. These allocations are high priority and system rather than
	 * user oriented.
	 */
	if (!(alloc_flags & ALLOC_CPUSET) || reserve_flags) {
		ac->nodemask = NULL;
		ac->preferred_zoneref = first_zones_zonelist(ac->zonelist,
					ac->highest_zoneidx, ac->nodemask);
	}

	/* Attempt with potentially adjusted zonelist and alloc_flags */
	page = get_page_from_freelist(gfp_mask, order, alloc_flags, ac);
	if (page)
		goto got_pg;

	/* Caller is not willing to reclaim, we can't balance anything */
	if (!can_direct_reclaim)
		goto nopage;

	/* Avoid recursion of direct reclaim */
	if (current->flags & PF_MEMALLOC)
		goto nopage;

	/* Try direct reclaim and then allocating */
	page = __alloc_pages_direct_reclaim(gfp_mask, order, alloc_flags, ac,
							&did_some_progress);
	if (page)
		goto got_pg;

	/* Try direct compaction and then allocating */
	page = __alloc_pages_direct_compact(gfp_mask, order, alloc_flags, ac,
					compact_priority, &compact_result);
	if (page)
		goto got_pg;

	/* Do not loop if specifically requested */
	if (gfp_mask & __GFP_NORETRY)
		goto nopage;

	/*
	 * Do not retry costly high order allocations unless they are
	 * __GFP_RETRY_MAYFAIL
	 */
	if (costly_order && !(gfp_mask & __GFP_RETRY_MAYFAIL))
		goto nopage;

	if (should_reclaim_retry(gfp_mask, order, ac, alloc_flags,
				 did_some_progress > 0, &no_progress_loops))
		goto retry;

	/*
	 * It doesn't make any sense to retry for the compaction if the order-0
	 * reclaim is not able to make any progress because the current
	 * implementation of the compaction depends on the sufficient amount
	 * of free memory (see __compaction_suitable)
	 */
	if (did_some_progress > 0 &&
			should_compact_retry(ac, order, alloc_flags,
				compact_result, &compact_priority,
				&compaction_retries))
		goto retry;


	/* Deal with possible cpuset update races before we start OOM killing */
	if (check_retry_cpuset(cpuset_mems_cookie, ac))
		goto retry_cpuset;

	/* Reclaim has failed us, start killing things */
	page = __alloc_pages_may_oom(gfp_mask, order, ac, &did_some_progress);
	if (page)
		goto got_pg;

	/* Avoid allocations with no watermarks from looping endlessly */
	if (tsk_is_oom_victim(current) &&
	    (alloc_flags & ALLOC_OOM ||
	     (gfp_mask & __GFP_NOMEMALLOC)))
		goto nopage;

	/* Retry as long as the OOM killer is making progress */
	if (did_some_progress) {
		no_progress_loops = 0;
		goto retry;
	}

nopage:
	/* Deal with possible cpuset update races before we fail */
	if (check_retry_cpuset(cpuset_mems_cookie, ac))
		goto retry_cpuset;

	/*
	 * Make sure that __GFP_NOFAIL request doesn't leak out and make sure
	 * we always retry
	 */
	if (gfp_mask & __GFP_NOFAIL) {
		/*
		 * All existing users of the __GFP_NOFAIL are blockable, so warn
		 * of any new users that actually require GFP_NOWAIT
		 */
		if (WARN_ON_ONCE(!can_direct_reclaim))
			goto fail;

		/*
		 * PF_MEMALLOC request from this context is rather bizarre
		 * because we cannot reclaim anything and only can loop waiting
		 * for somebody to do a work for us
		 */
		WARN_ON_ONCE(current->flags & PF_MEMALLOC);

		/*
		 * non failing costly orders are a hard requirement which we
		 * are not prepared for much so let's warn about these users
		 * so that we can identify them and convert them to something
		 * else.
		 */
		WARN_ON_ONCE(order > PAGE_ALLOC_COSTLY_ORDER);

		/*
		 * Help non-failing allocations by giving them access to memory
		 * reserves but do not use ALLOC_NO_WATERMARKS because this
		 * could deplete whole memory reserves which would just make
		 * the situation worse
		 */
		page = __alloc_pages_cpuset_fallback(gfp_mask, order, ALLOC_HARDER, ac);
		if (page)
			goto got_pg;

		cond_resched();
		goto retry;
	}
fail:
	warn_alloc(gfp_mask, ac->nodemask,
			"page allocation failure: order:%u", order);
got_pg:
	return page;
}
```
