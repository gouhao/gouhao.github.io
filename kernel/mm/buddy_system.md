# 伙伴系统

```c
// include/linux/gfp.h (get free page)

#ifdef CONFIG_NUMA
extern struct page *alloc_pages_current(gfp_t gfp_mask, unsigned order);

static inline struct page *
alloc_pages(gfp_t gfp_mask, unsigned int order)
{
	return alloc_pages_current(gfp_mask, order);
}
#else
#define alloc_pages(gfp_mask, order) \
		alloc_pages_node(numa_node_id(), gfp_mask, order)
#endif
```

```c
// mm/mempolicy.c

/**
各种分配策略：
    MPOL_DEFAULT 默认策略。todo:什么意思
	MPOL_PREFERRED 首先在进程的preferred节点上分配内存，如果失败再在别的节点上分配
	MPOL_BIND 在指定的节点上进行分配
	MPOL_INTERLEAVE 在指定的几个可选节点集上，进行分配
	MPOL_LOCAL 在当前运行的节点上进行分配
**/
// NUMA分配的默认策略
static struct mempolicy default_policy = {
	.refcnt = ATOMIC_INIT(1), /* never free it */
	.mode = MPOL_PREFERRED,
	.flags = MPOL_F_LOCAL, // MPOL_F_LOCAL更愿意在本地分配
};

/**
 *  分配页
 *	@gfp:
 *		%GFP_USER   用户空间分配,
 *      %GFP_KERNEL 内核空间分配,
 *      %GFP_HIGHMEM 高端内存分配,
 *      %GFP_FS     不要回调到文件系统中. // todo: 啥意思
 *      %GFP_ATOMIC 不能眨眼.
 *	@order: 以2的幂为大小来分配。0是一页.
 *  
 *  从内核的内存池里分配页。
 *  当不在中断上下文时，使用当前进程的NUMA策略。
 *  如果没有页可以分配时，返回NULL。
 */
struct page *alloc_pages_current(gfp_t gfp, unsigned order)
{
    // NUMA策略
	struct mempolicy *pol = &default_policy;
	struct page *page;

    	// 如果不在中断上下文，而且分配标志没有指定__GFP_THISNODE
    	// __GFP_THISNODE的意思是只在当前cpu的节点分配
	if (!in_interrupt() && !(gfp & __GFP_THISNODE))
		pol = get_task_policy(current);

    	// 区分交叉分配和普通分配
	if (pol->mode == MPOL_INTERLEAVE)
		page = alloc_page_interleave(gfp, order, interleave_nodes(pol));
	else
		// numa_node_id返回的是当前运行cpu所在的numa节点
		// policy_nodemask一般情况下都返回NULL
		page = __alloc_pages_nodemask(gfp, order,
				policy_node(gfp, pol, numa_node_id()),
				policy_nodemask(gfp, pol));

	return page;
}

// 路径1：interleave

static struct page *alloc_page_interleave(gfp_t gfp, unsigned order,
					unsigned nid)
{
	struct page *page;

	// 分配内核
	page = __alloc_pages(gfp, order, nid);
	
	// 如果numa状态统计没有使能，则直接返回page
	if (!static_branch_likely(&vm_numa_stat_key))
		return page;
	
	// 如果在指定节点上成功分配了内核，则增加内存域的相关统计数据
	// NUMA_INTERLEAVE_HIT=3
	if (page && page_to_nid(page) == nid) {
		preempt_disable();
		__inc_numa_state(page_zone(page), NUMA_INTERLEAVE_HIT);
		preempt_enable();
	}
	return page;
}

// 获取下一个interleave的节点
// interleave模式是按顺序从允许的节点中分配内存，如果是最后一个节点，
// 则从头开始循环分配
static unsigned interleave_nodes(struct mempolicy *policy)
{
	unsigned next;
	struct task_struct *me = current;

    // policy->v.nodes是bind/interleave模式下可分配的节点集
    // il_prev是之前分配过的节点
	next = next_node_in(me->il_prev, policy->v.nodes);
	if (next < MAX_NUMNODES)
		me->il_prev = next;
	return next;
}

// 在srcp里从n+1的位开始，搜索第一个置位的，最大搜索到MAX_NUMNODES，
// 如果没有搜索到，则返回MAX_NUMNODES，否则返回第一个找到的序号
static inline int __next_node(int n, const nodemask_t *srcp)
{
	return min_t(int,MAX_NUMNODES,find_next_bit(srcp->bits, MAX_NUMNODES, n+1));
}

#define next_node_in(n, src) __next_node_in((n), &(src))
int __next_node_in(int node, const nodemask_t *srcp)
{
	// 获取node之后的下一个结点
	int ret = __next_node(node, srcp);

	// 如果node之后没有节点可用，则从头开始找一个节点
	if (ret == MAX_NUMNODES)
		ret = __first_node(srcp);
	return ret;
}

static inline struct page *
__alloc_pages(gfp_t gfp_mask, unsigned int order, int preferred_nid)
{
	return __alloc_pages_nodemask(gfp_mask, order, preferred_nid, NULL);
}


路径2：普通分配

/* Return the node id preferred by the given mempolicy, or the given id */
static int policy_node(gfp_t gfp, struct mempolicy *policy,
								int nd)
{
	// 如果模式是MPOL_PREFERRED，且没有指定本地标志，则返回preferred_node节点
	if (policy->mode == MPOL_PREFERRED && !(policy->flags & MPOL_F_LOCAL))
		nd = policy->v.preferred_node;
	else {
		 // __GFP_THISNODE不应该和MPOL_BIND一起使用，系统会更倾向于根据MPOL_BIND中
		 // 的节点来分配内存，从而忽略__GFP_THISNODE标志
		WARN_ON_ONCE(policy->mode == MPOL_BIND && (gfp & __GFP_THISNODE));
	}

	return nd;
}

static nodemask_t *policy_nodemask(gfp_t gfp, struct mempolicy *policy)
{
	// 如果策略是MPOL_BIND并且当前进程允许在策略上的这些节点运行
	// 则返回指定的节点集
	if (unlikely(policy->mode == MPOL_BIND) &&
			apply_policy_zone(policy, gfp_zone(gfp)) &&
			cpuset_nodemask_valid_mems_allowed(&policy->v.nodes))
		return &policy->v.nodes;

	// 大概率返回NULL
	return NULL;
}

// todo: 没看懂
static int apply_policy_zone(struct mempolicy *policy, enum zone_type zone)
{
	enum zone_type dynamic_policy_zone = policy_zone;

	BUG_ON(dynamic_policy_zone == ZONE_MOVABLE);

	/*
	 * if policy->v.nodes has movable memory only,
	 * we apply policy when gfp_zone(gfp) = ZONE_MOVABLE only.
	 *
	 * policy->v.nodes is intersect with node_states[N_MEMORY].
	 * so if the following test faile, it implies
	 * policy->v.nodes has movable memory only.
	 */
	if (!nodes_intersects(policy->v.nodes, node_states[N_HIGH_MEMORY]))
		dynamic_policy_zone = ZONE_MOVABLE;

	return zone >= dynamic_policy_zone;
}

```

```c
// mm/page_alloc.c

// 伙伴系统的核心分配函数
struct page *__alloc_pages_nodemask(gfp_t gfp_mask, unsigned int order, int preferred_nid,
							nodemask_t *nodemask)
{
	struct page *page;
	unsigned int alloc_flags = ALLOC_WMARK_LOW;
	gfp_t alloc_mask;
	struct alloc_context ac = { };

	// gfp_allowed_mask是系统中允许的gfp标志，和传进来的标志相与，
	// 可以去除系统不允许的标志。
	gfp_mask &= gfp_allowed_mask;

	// gfp_t实际上就是unsigned
	alloc_mask = gfp_mask;

	// prepare_alloc_pages主要是初始化alloc_context, 判断本次申请会不会失败，
	// 如果会失败，则返回false
	if (!prepare_alloc_pages(gfp_mask, order, preferred_nid, nodemask, &ac, &alloc_mask, &alloc_flags))
		return NULL;

	// 确定是否传播赃页，以及找第一个可用分配区域
	finalise_ac(gfp_mask, &ac);

	// 首先，在空闲列表中尝试分配
	// 这个应该大概率会成功
	page = get_page_from_freelist(alloc_mask, order, alloc_flags, &ac);
	if (likely(page))
		goto out;

	/*
	 * Apply scoped allocation constraints. This is mainly about GFP_NOFS
	 * resp. GFP_NOIO which has to be inherited for all allocation requests
	 * from a particular context which has been marked by
	 * memalloc_no{fs,io}_{save,restore}.
	 */
	alloc_mask = current_gfp_context(gfp_mask);
	ac.spread_dirty_pages = false;

	/*
	 * Restore the original nodemask if it was potentially replaced with
	 * &cpuset_current_mems_allowed to optimize the fast-path attempt.
	 */
	if (unlikely(ac.nodemask != nodemask))
		ac.nodemask = nodemask;

	page = __alloc_pages_slowpath(alloc_mask, order, &ac);

out:
	if (memcg_kmem_enabled() && (gfp_mask & __GFP_ACCOUNT) && page &&
	    unlikely(memcg_kmem_charge(page, gfp_mask, order) != 0)) {
		__free_pages(page, order);
		page = NULL;
	}

	trace_mm_page_alloc(page, order, alloc_mask, ac.migratetype);

	return page;
}

static inline bool prepare_alloc_pages(gfp_t gfp_mask, unsigned int order,
		int preferred_nid, nodemask_t *nodemask,
		struct alloc_context *ac, gfp_t *alloc_mask,
		unsigned int *alloc_flags)
{
	ac->high_zoneidx = gfp_zone(gfp_mask);
	ac->zonelist = node_zonelist(preferred_nid, gfp_mask);
	ac->nodemask = nodemask;
	ac->migratetype = gfpflags_to_migratetype(gfp_mask);

	if (cpusets_enabled()) {
		*alloc_mask |= __GFP_HARDWALL;
		if (!ac->nodemask)
			ac->nodemask = &cpuset_current_mems_allowed;
		else
			*alloc_flags |= ALLOC_CPUSET;
	}

	fs_reclaim_acquire(gfp_mask);
	fs_reclaim_release(gfp_mask);

	might_sleep_if(gfp_mask & __GFP_DIRECT_RECLAIM);

	if (should_fail_alloc_page(gfp_mask, order))
		return false;

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

static struct page *
get_page_from_freelist(gfp_t gfp_mask, unsigned int order, int alloc_flags,
						const struct alloc_context *ac)
{
	struct zoneref *z = ac->preferred_zoneref;
	struct zone *zone;
	struct pglist_data *last_pgdat_dirty_limit = NULL;

	/*
	 * Scan zonelist, looking for a zone with enough free.
	 * See also __cpuset_node_allowed() comment in kernel/cpuset.c.
	 */
	for_next_zone_zonelist_nodemask(zone, z, ac->zonelist, ac->high_zoneidx,
								ac->nodemask) {
		struct page *page;
		unsigned long mark;

		// 不允许在这个zone上分配
		if (cpusets_enabled() &&
			(alloc_flags & ALLOC_CPUSET) &&
			!__cpuset_zone_allowed(zone, gfp_mask))
				continue;
		/*
		 * When allocating a page cache page for writing, we
		 * want to get it from a node that is within its dirty
		 * limit, such that no single node holds more than its
		 * proportional share of globally allowed dirty pages.
		 * The dirty limits take into account the node's
		 * lowmem reserves and high watermark so that kswapd
		 * should be able to balance it without having to
		 * write pages from its LRU list.
		 *
		 * XXX: For now, allow allocations to potentially
		 * exceed the per-node dirty limit in the slowpath
		 * (spread_dirty_pages unset) before going into reclaim,
		 * which is important when on a NUMA setup the allowed
		 * nodes are together not big enough to reach the
		 * global limit.  The proper fix for these situations
		 * will require awareness of nodes in the
		 * dirty-throttling and the flusher threads.
		 */
		if (ac->spread_dirty_pages) {
			if (last_pgdat_dirty_limit == zone->zone_pgdat)
				continue;

			if (!node_dirty_ok(zone->zone_pgdat)) {
				last_pgdat_dirty_limit = zone->zone_pgdat;
				continue;
			}
		}

		mark = zone->watermark[alloc_flags & ALLOC_WMARK_MASK];
		if (!zone_watermark_fast(zone, order, mark,
				       ac_classzone_idx(ac), alloc_flags)) {
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
						ac_classzone_idx(ac), alloc_flags))
					goto try_this_zone;

				continue;
			}
		}

try_this_zone:
		page = rmqueue(ac->preferred_zoneref->zone, zone, order,
				gfp_mask, alloc_flags, ac->migratetype);
		if (page) {
			prep_new_page(page, order, gfp_mask, alloc_flags);

			/*
			 * If this is a high-order atomic allocation then check
			 * if the pageblock should be reserved for the future
			 */
			if (unlikely(order && (alloc_flags & ALLOC_HARDER)))
				reserve_highatomic_pageblock(page, zone, order);

			return page;
		} else {
#ifdef CONFIG_DEFERRED_STRUCT_PAGE_INIT
			/* Try again if zone has deferred pages */
			if (static_branch_unlikely(&deferred_pages)) {
				if (_deferred_grow_zone(zone, order))
					goto try_this_zone;
			}
#endif
		}
	}

	return NULL;
}
```