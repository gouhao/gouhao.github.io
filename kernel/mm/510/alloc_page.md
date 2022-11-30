# alloc_pages
源码基于5.10， CONFIG_NUMA 打开，x86_64平台

```c
// 申请一页内存，order传的是0，对alloc_pages的包装
#define alloc_page(gfp_mask) alloc_pages(gfp_mask, 0)

static inline struct page *
alloc_pages(gfp_t gfp_mask, unsigned int order)
{
	// 默认在当前node上分配内存
	return alloc_pages_current(gfp_mask, order);
}
// mm/mempolicy.c

/**
各种分配策略：
	MPOL_DEFAULT 默认策略。
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
 * 	alloc_pages_current - Allocate pages.
 *
 *	@gfp:
 *		%GFP_USER   用户分配,
 *      	%GFP_KERNEL 内核分配,
 *      	%GFP_HIGHMEM 高端内存分配,
 *      	%GFP_FS     文件系统分配，不允许在分配过程中做文件系统的操作.
 *      	%GFP_ATOMIC 原子分配不允许睡眠.
 *	@order: order是2的幂
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
    	// __GFP_THISNODE：用户指定了分配的node，必须在用户指定的node上分配
	if (!in_interrupt() && !(gfp & __GFP_THISNODE))
		// 一般情况都没有指定__GFP_THISNODE，所以都会进到这里
		// get_task_policy先获取进程的策略，如果进程没有策略，则获取
        	// 当前节点的分配策略，如果当前节点策略mode为０，则返回default_policy
		pol = get_task_policy(current);

	
	// 区分交叉分配和普通分配
	if (pol->mode == MPOL_INTERLEAVE)
		// alloc_page_interleave直接调用__alloc_pages, 并做了些统计相关的操作。
		// __alloc_pages会直接调用__alloc_pages_nodemask

		// interleave_nodes会在policy所允许的节点中，从前到后
		//按顺序在节点中分配，如果到最后一个再从第一个开始，如此反复。
		page = alloc_page_interleave(gfp, order, interleave_nodes(pol));
	else
		// 普通分配
		page = __alloc_pages_nodemask(gfp, order,
				// numa_node_id返回当前有numa结点序号

				policy_node(gfp, pol, numa_node_id()),
				policy_nodemask(gfp, pol));

	return page;
}
```
## 路径1：alloc_page_interleave
```c
// 获取下一个interleave的节点
// interleave模式是按顺序从允许的节点中分配内存，如果是最后一个节点，
// 则从头开始循环分配
static unsigned interleave_nodes(struct mempolicy *policy)
{
	unsigned next;
	struct task_struct *me = current;

	// policy->v.nodes是bind/interleave模式下可分配的节点集
    	// il_prev是之前分配过的节点，next_node_in从
	// 允许的节点集里循环找下一个节点
	next = next_node_in(me->il_prev, policy->v.nodes);
	// 如果在正常范围内，则修改il_prev的值
	if (next < MAX_NUMNODES)
		me->il_prev = next;
	return next;
}

#define next_node_in(n, src) __next_node_in((n), &(src))
int __next_node_in(int node, const nodemask_t *srcp)
{
	// 获取node之后的下一个结点
	int ret = __next_node(node, srcp);

	// 如果找到的节点是MAX_NUMNODES说明已经到可选集的末尾了，
	// 则从头开始找一个节点
	if (ret == MAX_NUMNODES)
		ret = __first_node(srcp);
	return ret;
}

// 在srcp里从n+1的位开始，搜索第一个置位的，最大搜索到MAX_NUMNODES，
// 如果没有搜索到，则返回MAX_NUMNODES，否则返回第一个找到的序号
static inline int __next_node(int n, const nodemask_t *srcp)
{
	return min_t(int,MAX_NUMNODES,find_next_bit(srcp->bits, MAX_NUMNODES, n+1));
}

static struct page *alloc_page_interleave(gfp_t gfp, unsigned order,
					unsigned nid)
{
	struct page *page;

	// 分配内存，这个函数直接调用
	// __alloc_pages_nodemask，最后一个参数是NULL
	page = __alloc_pages(gfp, order, nid);
	
	// vm_numa_stat_key一般都是开着的，如果关了就不用下面统计了
	if (!static_branch_likely(&vm_numa_stat_key))
		return page;
	// 如果在指定的node上成功分配了页
	if (page && page_to_nid(page) == nid) {
		// 关抢占
		preempt_disable();
		// vmstat统计相关,NUMA_INTERLEAVE_HIT=3
		__inc_numa_state(page_zone(page), NUMA_INTERLEAVE_HIT);
		preempt_enable();
	}
	return page;
}
```
## 普通分配
```c
static int policy_node(gfp_t gfp, struct mempolicy *policy, int nd)
{
	// MPOL_PREFERRED表示在preferred_node上分配，MPOL_F_LOCAL表示在当前节点分配
	if (policy->mode == MPOL_PREFERRED && !(policy->flags & MPOL_F_LOCAL))
		// 大多数情况都走这里
		nd = policy->v.preferred_node;
	else {
		// MPOL_BIND和__GFP_THISNODE不要一起用。，系统会更倾向于根据MPOL_BIND中
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
```
## 内存分配的核心函数
```c
struct page *
__alloc_pages_nodemask(gfp_t gfp_mask, unsigned int order, int preferred_nid,
							nodemask_t *nodemask)
{
	struct page *page;
	// 默认分配的水位线是在低水位
	unsigned int alloc_flags = ALLOC_WMARK_LOW;
	gfp_t alloc_mask;
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

	// 这里面主要处理DMA32的情况。普通分配时，只是返回是否需要唤醒kswapd
	alloc_flags |= alloc_flags_nofragment(ac.preferred_zoneref->zone, gfp_mask);

	// 第一次尝试：从空闲列表里分配页。这个大概率分成功
	page = get_page_from_freelist(alloc_mask, order, alloc_flags, &ac);
	// 大多数情况，在这一步就会分配成功
	if (likely(page))
		goto out;

	// 走到这里说明分配失败了
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

static inline bool prepare_alloc_pages(gfp_t gfp_mask, unsigned int order,
		int preferred_nid, nodemask_t *nodemask,
		struct alloc_context *ac, gfp_t *alloc_mask,
		unsigned int *alloc_flags)
{
	// 算出gpf_mask里的zone类型，这里算出来的是最后考虑的zone
	ac->highest_zoneidx = gfp_zone(gfp_mask);
	// preferred_nid是首选的zone节点，这个算出zone节点对应的zonelist
	ac->zonelist = node_zonelist(preferred_nid, gfp_mask);
	ac->nodemask = nodemask;

	// 获取迁移类型
	ac->migratetype = gfp_migratetype(gfp_mask);

	// todo: 后面再看这个路径，这个一般是false
	if (cpusets_enabled()) {
		*alloc_mask |= __GFP_HARDWALL;
		/*
		 * When we are in the interrupt context, it is irrelevant
		 * to the current task context. It means that any node ok.
		 */
		if (!in_interrupt() && !ac->nodemask)
			ac->nodemask = &cpuset_current_mems_allowed;
		else
			*alloc_flags |= ALLOC_CPUSET;
	}

	// 这个在CONFIG_LOCKDEP没打开时，是空语句
	fs_reclaim_acquire(gfp_mask);
	fs_reclaim_release(gfp_mask);

	// 这个函数在CONFIG_PREEMPT_VOLUNTARY打开时，如果条件成立会调用_cond_resched()
	// 如果没打开配置，是空语句。
	// 这里的意思是，如果分配时要求回收内存，则先让出cpu，让kswapd有机会执行（猜的）
	might_sleep_if(gfp_mask & __GFP_DIRECT_RECLAIM);

	// 这个在CONFIG_FAIL_PAGE_ALLOC打开时才有用，否则返回false。
	// todo: 这个路径后面再看
	if (should_fail_alloc_page(gfp_mask, order))
		return false;

	// 这个在CONFIG_CMA打开时才有用，否则直接返回*alloc_flags的值
	// todo: cma相关的后面再看
	*alloc_flags = current_alloc_flags(gfp_mask, *alloc_flags);

	// 分配请求是为了写，则展开脏页
	ac->spread_dirty_pages = (gfp_mask & __GFP_WRITE);

	// 找一个合适的zone
	ac->preferred_zoneref = first_zones_zonelist(ac->zonelist,
					ac->highest_zoneidx, ac->nodemask);

	return true;
}

static inline struct zoneref *first_zones_zonelist(struct zonelist *zonelist,
					enum zone_type highest_zoneidx,
					nodemask_t *nodes)
{
	return next_zones_zonelist(zonelist->_zonerefs,
							highest_zoneidx, nodes);
}

static __always_inline struct zoneref *next_zones_zonelist(struct zoneref *z,
					enum zone_type highest_zoneidx,
					nodemask_t *nodes)
{
	// 没有指定nodes时，而且z的zoneid没有超过最大的zoneid，则直接返回zone_id
	// 一般都会走这个路径，一般传进来的都是首选id
	if (likely(!nodes && zonelist_zone_idx(z) <= highest_zoneidx))
		return z;
	// 如果上面没到，或者规定了nodes，则要去找一个最合适的
	return __next_zones_zonelist(z, highest_zoneidx, nodes);
}

struct zoneref *__next_zones_zonelist(struct zoneref *z,
					enum zone_type highest_zoneidx,
					nodemask_t *nodes)
{
	if (unlikely(nodes == NULL))
		// 在next_zones_zonelist里已经处理了nodes为NULL的情况，能走到
		// 这里，说明传进来的zoneid已经大于了最大值，这里就要循环找出一个
		// 最小zoneid，因为zone是环链表，所以一定会找出一个合适的值
		while (zonelist_zone_idx(z) > highest_zoneidx)
			z++;
	else
		// 走到这里说明用户规定的node_mask
		while (zonelist_zone_idx(z) > highest_zoneidx ||
				(z->zone && !zref_in_nodemask(z, nodes)))
			// 能走到这里面，说明zoneid大于最大值，或者zone不在用户规定的node_mask里,
			// 这里就要循环找出一个合适的zone
			z++;

	return z;
}

static inline unsigned int
alloc_flags_nofragment(struct zone *zone, gfp_t gfp_mask)
{
	unsigned int alloc_flags;

	// __GFP_KSWAPD_RECLAIM表示，如果到达了low水位，则希望唤醒kswapd回收内存，
	// 直到内存水位到high，有这个标志表示可以唤醒kswapd
	alloc_flags = (__force int) (gfp_mask & __GFP_KSWAPD_RECLAIM);

#ifdef CONFIG_ZONE_DMA32
	// 这里处理dma相关

	if (!zone)
		return alloc_flags;

	// ZONE_NORMAL表示正常的zone，如果是正常的zone，就不用下面处理了
	if (zone_idx(zone) != ZONE_NORMAL)
		return alloc_flags;

	BUILD_BUG_ON(ZONE_NORMAL - ZONE_DMA32 != 1);

	// populated_zone返回的是zone->present_pages，如果当前页没有zone，就直接返回？
	// --zone表示是ZONE_NORMAL，因为ZONE_DMA32是排在NORMAL区后面
	if (nr_online_nodes > 1 && !populated_zone(--zone))
		return alloc_flags;
	// 如果normal没有页，则不允许混合页类型
	alloc_flags |= ALLOC_NOFRAGMENT;
#endif /* CONFIG_ZONE_DMA32 */
	return alloc_flags;
}

static inline enum zone_type gfp_zone(gfp_t flags)
{
	enum zone_type z;
	// 这一步可以算出来，flags里包含的zone类型位
	int bit = (__force int) (flags & GFP_ZONEMASK);

	// GFP_ZONES_SHIFT是个动态值，根据zone类型的大小有不同的shift
	// 这一步可以算出来zone的类型
	z = (GFP_ZONE_TABLE >> (bit * GFP_ZONES_SHIFT)) &
					 ((1 << GFP_ZONES_SHIFT) - 1);
	// 调试，这里面主要判断一些不能同时用的zone类型
	VM_BUG_ON((GFP_ZONE_BAD >> bit) & 1);
	return z;
}

// zone只有这4种类型。分配dma专用，高端内存（在64位系统上已经没有高端内存了），可移动内存
// 一般分配的都是__GFP_MOVABLE
#define GFP_ZONEMASK	(__GFP_DMA|__GFP_HIGHMEM|__GFP_DMA32|__GFP_MOVABLE)

#define GFP_ZONE_TABLE ( \
	(ZONE_NORMAL << 0 * GFP_ZONES_SHIFT)				       \
	| (OPT_ZONE_DMA << ___GFP_DMA * GFP_ZONES_SHIFT)		       \
	| (OPT_ZONE_HIGHMEM << ___GFP_HIGHMEM * GFP_ZONES_SHIFT)	       \
	| (OPT_ZONE_DMA32 << ___GFP_DMA32 * GFP_ZONES_SHIFT)		       \
	| (ZONE_NORMAL << ___GFP_MOVABLE * GFP_ZONES_SHIFT)		       \
	| (OPT_ZONE_DMA << (___GFP_MOVABLE | ___GFP_DMA) * GFP_ZONES_SHIFT)    \
	| (ZONE_MOVABLE << (___GFP_MOVABLE | ___GFP_HIGHMEM) * GFP_ZONES_SHIFT)\
	| (OPT_ZONE_DMA32 << (___GFP_MOVABLE | ___GFP_DMA32) * GFP_ZONES_SHIFT)\
)

static inline struct zonelist *node_zonelist(int nid, gfp_t flags)
{
	// 每个pglist_data->node_zonelists里存放的是系统里所有numa节点上的zone
	// 第0个元素是本节点的zone
	// 一般都是返回第0个元素也就是本节点的zone，指定__GFP_THISNODE时会返回第1个元素
	return NODE_DATA(nid)->node_zonelists + gfp_zonelist(flags);
}

static inline int gfp_zonelist(gfp_t flags)
{
	// ZONELIST_FALLBACK: 0
	// ZONELIST_NOFALLBACK:1
#ifdef CONFIG_NUMA
	// 指定在特定的节点上分配
	if (unlikely(flags & __GFP_THISNODE))
		return ZONELIST_NOFALLBACK;
#endif
	// 一般都走这个路径
	return ZONELIST_FALLBACK;
}

static inline int gfp_migratetype(const gfp_t gfp_flags)
{
	// 不能同时指定所有的移动标志
	VM_WARN_ON((gfp_flags & GFP_MOVABLE_MASK) == GFP_MOVABLE_MASK);

	// GFP_MOVABLE_SHIFT是3, ___GFP_MOVABLE是8
	BUILD_BUG_ON((1UL << GFP_MOVABLE_SHIFT) != ___GFP_MOVABLE);
	// MIGRATE_MOVABLE是1， 8 >> 3 = 1
	BUILD_BUG_ON((___GFP_MOVABLE >> GFP_MOVABLE_SHIFT) != MIGRATE_MOVABLE);

	// 一般不会走这个分支
	if (unlikely(page_group_by_mobility_disabled))
		return MIGRATE_UNMOVABLE;

	// 算出迁移类型
	return (gfp_flags & GFP_MOVABLE_MASK) >> GFP_MOVABLE_SHIFT;
}

// __GFP_RECLAIMABLE：页可以被回收
// __GFP_MOVABLE：页可以被迁移也可以被回收
#define ___GFP_MOVABLE		0x08u
#define ___GFP_RECLAIMABLE	0x10u
#define GFP_MOVABLE_MASK (__GFP_RECLAIMABLE|__GFP_MOVABLE)

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

		// 这个函数里会对水印进行判断，返回false表示已经达到水印
		// todo: 这里后面再看
		if (!zone_watermark_fast(zone, order, mark,
				       ac->highest_zoneidx, alloc_flags,
				       gfp_mask)) {
			int ret;

#ifdef CONFIG_DEFERRED_STRUCT_PAGE_INIT
			// 如果有延迟page的话，可以增加这个zone
			if (static_branch_unlikely(&deferred_pages)) {
				if (_deferred_grow_zone(zone, order))
					goto try_this_zone;
			}
#endif
			BUILD_BUG_ON(ALLOC_NO_WATERMARKS < NR_WMARK);

			// ALLOC_NO_WATERMARKS表示完成不检查水印
			if (alloc_flags & ALLOC_NO_WATERMARKS)
				goto try_this_zone;

			// todo: ?
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

			// 设置页的一些标志，及引用计数
			prep_new_page(page, order, gfp_mask, alloc_flags);

			// todo: ？？
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

static void prep_new_page(struct page *page, unsigned int order, gfp_t gfp_flags,
							unsigned int alloc_flags)
{
	// 这个里面主要设置了private为0， _refcount=1
	post_alloc_hook(page, order, gfp_flags);

	// kasan相关
	if (!free_pages_prezeroed() && want_init_on_alloc(gfp_flags))
		kernel_init_free_pages(page, 1 << order);

	// 设置组合页
	if (order && (gfp_flags & __GFP_COMP))
		prep_compound_page(page, order);

	// todo: why?
	if (alloc_flags & ALLOC_NO_WATERMARKS)
		// 这个是把page->index = -1
		set_page_pfmemalloc(page);
	else
		// page->index = 0
		clear_page_pfmemalloc(page);
}

inline void post_alloc_hook(struct page *page, unsigned int order,
				gfp_t gfp_flags)
{
	// 设置page->private = 0
	set_page_private(page, 0);
	// 设置 page->_refcount = 1
	set_page_refcounted(page);

	// 下面都是一些调试或构架处理

	// 各个架构的处理
	arch_alloc_page(page, order);

	if (debug_pagealloc_enabled_static())
		kernel_map_pages(page, 1 << order, 1);
	// kasan 相关
	kasan_alloc_pages(page, order);
	// posion 相关
	kernel_poison_pages(page, 1 << order, 1);
	// page_owner 相关
	set_page_owner(page, order, gfp_flags);
}

void prep_compound_page(struct page *page, unsigned int order)
{
	int i;
	// 组合页里页面的数量
	int nr_pages = 1 << order;

	// 设置页面头标志
	__SetPageHead(page);

	// 因为第一个页面已经在post_alloc_hook里处理了，
	// 所以这里从第1个页面开始
	for (i = 1; i < nr_pages; i++) {
		struct page *p = page + i;
		// 设置_refcount=0
		set_page_count(p, 0);
		// todo: ? 
		p->mapping = TAIL_MAPPING;
		// 设置compound_head为(unsigned long)page+1
		// todo: 这里为什么要加1
		set_compound_head(p, page);
	}

	// 设置page[1]的compound_dtor析构函数id
	set_compound_page_dtor(page, COMPOUND_PAGE_DTOR);
	// 在page[1]上保存compound_order和compound_nr（页面数量）
	set_compound_order(page, order);
	// page[1].compound_mapcount = -1
	atomic_set(compound_mapcount_ptr(page), -1);

	// 这个条件在order > 1时成立
	if (hpage_pincount_available(page))
		// page[2].hpage_pinned_refcount = 0
		atomic_set(compound_pincount_ptr(page), 0);
	
	// todo: 为什么上面有的在page[1], 有的在page[2]上保存数据
}
```
快速路径里大的流程就是遍历zone，然后尝试从zone里分配对应数量的页。在《深入理解Linux内核》里，把这个叫管理区分配器，其实就是分配器的前端。

## buddy系统
真正分配页的是rmqueue。分配页也有2个方式，每个zone加了一个percpu cache, 专门用来分配一页(order=0)，因为大多数分配是一页，所以能加速分配。如果order > 0，那就从order对应的空闲列表里分配，如果order对应的空闲列表没有空闲页，就增加order，如此反复，直接分配成功，或者所有列表都无空闲。如果分配成功，就把这个页多出的拆开，挂到对应order的列表里。
```c
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
		// 有HARDER标志，直接从空闲列表里分配分配。todo: ? 
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
	// 从空闲链表里分配页
	page = __rmqueue_smallest(zone, order, migratetype);

	// 分配失败
	if (unlikely(!page)) {
		// todo: fallback机制后面再看
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

	// 本地关中断
	local_irq_save(flags);

	// pageset就是percpu cache
	pcp = &this_cpu_ptr(zone->pageset)->pcp;
	// 对应迁移类型的列表
	list = &pcp->lists[migratetype];

	// 取出一页
	page = __rmqueue_pcplist(zone,  migratetype, alloc_flags, pcp, list);
	if (page) {
		// 这都是统计相关
		__count_zid_vm_events(PGALLOC, page_zonenum(page), 1);
		zone_statistics(preferred_zone, zone);
	}
	// 开中
	local_irq_restore(flags);
	return page;
}

static struct page *__rmqueue_pcplist(struct zone *zone, int migratetype,
			unsigned int alloc_flags,
			struct per_cpu_pages *pcp,
			struct list_head *list)
{
	struct page *page;

	do {
		// 如果cpu-cache空了，则尝试分配pcp->batch数量的页，但并不一定能分到这么多
		if (list_empty(list)) {
			// 返回值是实际分到的页数
			pcp->count += rmqueue_bulk(zone, 0,
					pcp->batch, list,
					migratetype, alloc_flags);
			// 如果列表还空，说明上面分配失败了
			if (unlikely(list_empty(list)))
				return NULL;
		}

		// 取出队列的第1个元素
		page = list_first_entry(list, struct page, lru);
		list_del(&page->lru);
		// 递减cpu-cache中的数量
		pcp->count--;
	} while (check_new_pcp(page));

	return page;
}

// 这里 order＝0， count是percpu-cache一次分配的数量，list是percpu的列表
static int rmqueue_bulk(struct zone *zone, unsigned int order,
			unsigned long count, struct list_head *list,
			int migratetype, unsigned int alloc_flags)
{
	int i, alloced = 0;

	// 锁住zone
	spin_lock(&zone->lock);

	// count是需要分配的页数，但是这里并不一定会分配这么多页
	// 这个count只是循环的次数
	for (i = 0; i < count; ++i) {
		// 由于order是0，所以每次去分配一页
		// 这里直接调用的是__rmqueue，只会在这个zone里分配，而不会去其他zone
		struct page *page = __rmqueue(zone, order, migratetype,
								alloc_flags);
		
		// 没有分配到，那直接退出，因为这时肯定内存不足了
		if (unlikely(page == NULL))
			break;

		// 这个是debug相关
		if (unlikely(check_pcp_refill(page)))
			continue;

		// 加到percpu列表里
		list_add_tail(&page->lru, list);
		alloced++;

		// todo: cma后面再看
		if (is_migrate_cma(get_pcppage_migratetype(page)))
			__mod_zone_page_state(zone, NR_FREE_CMA_PAGES,
					      -(1 << order));
	}

	// 统计相关
	__mod_zone_page_state(zone, NR_FREE_PAGES, -(i << order));
	spin_unlock(&zone->lock);
	return alloced;
}
```
从percpu-cache里分配比较简单，一共2个流程：1. percpu列表空了，则先给列表填充一定数量的页。 2. 从列表里分配一定数量的页。

## 慢速路径
```c
static inline struct page *
__alloc_pages_slowpath(gfp_t gfp_mask, unsigned int order,
						struct alloc_context *ac)
{
	bool can_direct_reclaim = gfp_mask & __GFP_DIRECT_RECLAIM;
	// PAGE_ALLOC_COSTLY_ORDER 
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

	// 如果mask同时有__GFP_ATOMIC|__GFP_DIRECT_RECLAIM，则要去除__GFP_ATOMIC，
	// 因为回收需要切换，所以与原子操作冲突
	if (WARN_ON_ONCE((gfp_mask & (__GFP_ATOMIC|__GFP_DIRECT_RECLAIM)) ==
				(__GFP_ATOMIC|__GFP_DIRECT_RECLAIM)))
		gfp_mask &= ~__GFP_ATOMIC;

retry_cpuset:
	compaction_retries = 0;
	no_progress_loops = 0;
	compact_priority = DEF_COMPACT_PRIORITY;
	cpuset_mems_cookie = read_mems_allowed_begin();

	
	alloc_flags = gfp_to_alloc_flags(gfp_mask);

	// 重新计算最适合的zone
	ac->preferred_zoneref = first_zones_zonelist(ac->zonelist,
					ac->highest_zoneidx, ac->nodemask);
	if (!ac->preferred_zoneref->zone)
		goto nopage;

	// 允许唤醒kswapd
	if (alloc_flags & ALLOC_KSWAPD)
		wake_all_kswapds(order, gfp_mask, ac);

	// 原文注释：调整了分配标志，说不定能成功，再试一次    
	page = get_page_from_freelist(gfp_mask, order, alloc_flags, ac);
	if (page)
		goto got_pg;   

	// todo: 没太看懂
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
	// 原文注释：再唤醒一次，避免因长时间循环而睡眠
	if (alloc_flags & ALLOC_KSWAPD)
		wake_all_kswapds(order, gfp_mask, ac);

	// 区别保留标志
	reserve_flags = __gfp_pfmemalloc_flags(gfp_mask);
	if (reserve_flags)
		alloc_flags = current_alloc_flags(gfp_mask, reserve_flags);

	// 调整可分配的zone
	if (!(alloc_flags & ALLOC_CPUSET) || reserve_flags) {
		ac->nodemask = NULL;
		ac->preferred_zoneref = first_zones_zonelist(ac->zonelist,
					ac->highest_zoneidx, ac->nodemask);
	}

	// 把zone调整完了再试一次
	page = get_page_from_freelist(gfp_mask, order, alloc_flags, ac);
	if (page)
		goto got_pg;

	/* Caller 不需要回收 */
	if (!can_direct_reclaim)
		goto nopage;

	// PF_MEMALLOC表示当前进程是内存管理相关的进程，比如kswapd等，这些进程需要退出，
	// 否则会造成无限递规
	if (current->flags & PF_MEMALLOC)
		goto nopage;

	// 回收页面，然后尝试回收。todo: 这里回收什么？
	page = __alloc_pages_direct_reclaim(gfp_mask, order, alloc_flags, ac,
							&did_some_progress);
	if (page)
		goto got_pg;

	// 尝试压缩再回收。todo: 这里回收什么？
	page = __alloc_pages_direct_compact(gfp_mask, order, alloc_flags, ac,
					compact_priority, &compact_result);
	if (page)
		goto got_pg;

	// 不需要重试
	if (gfp_mask & __GFP_NORETRY)
		goto nopage;

	// 如果order太高，那可能会失败，所以除非有__GFP_RETRY_MAYFAIL，则会继续循环
	if (costly_order && !(gfp_mask & __GFP_RETRY_MAYFAIL))
		goto nopage;

	// 是否需要重试。todo: 判断流程没看
	if (should_reclaim_retry(gfp_mask, order, ac, alloc_flags,
				 did_some_progress > 0, &no_progress_loops))
		goto retry;

	// todo: ?
	if (did_some_progress > 0 &&
			should_compact_retry(ac, order, alloc_flags,
				compact_result, &compact_priority,
				&compaction_retries))
		goto retry;


	// 有可能cpuset会变，再判断一次
	if (check_retry_cpuset(cpuset_mems_cookie, ac))
		goto retry_cpuset;

	// oom流程。上面所有的回收都失败了，那就走oom流程
	page = __alloc_pages_may_oom(gfp_mask, order, ac, &did_some_progress);
	if (page)
		goto got_pg;

	// 防止不受水印限制的进程，在这里递规
	if (tsk_is_oom_victim(current) &&
	    (alloc_flags & ALLOC_OOM ||
	     (gfp_mask & __GFP_NOMEMALLOC)))
		goto nopage;

	// 因为上面的oom可能正在释放内存，所以再试一次，
	// did_some_progress是正在进行oom ?
	if (did_some_progress) {
		no_progress_loops = 0;
		goto retry;
	}

nopage:
	// cpuset可能改变，再试一次
	if (check_retry_cpuset(cpuset_mems_cookie, ac))
		goto retry_cpuset;

	// 不允许失败
	if (gfp_mask & __GFP_NOFAIL) {
		// 不允许回收，意味着不能等待，这样肯定回收不了，直接走失败流程
		if (WARN_ON_ONCE(!can_direct_reclaim))
			goto fail;

		// PF_MEMALLOC是内存分配管理进程的，不应该出现在这里
		WARN_ON_ONCE(current->flags & PF_MEMALLOC);

		/*
		 * non failing costly orders are a hard requirement which we
		 * are not prepared for much so let's warn about these users
		 * so that we can identify them and convert them to something
		 * else.
		 */
		WARN_ON_ONCE(order > PAGE_ALLOC_COSTLY_ORDER);

		// 再尝试一下
		page = __alloc_pages_cpuset_fallback(gfp_mask, order, ALLOC_HARDER, ac);
		if (page)
			goto got_pg;

		// 还是失败，让出cpu，让其它回收进程有机会执行
		cond_resched();

		// 再重试，因为不允许回收，那就不管重试
		goto retry;
	}
fail:
	// 走到这儿，就是真的分配不到内存了，无能为力！
	warn_alloc(gfp_mask, ac->nodemask,
			"page allocation failure: order:%u", order);
got_pg:
	return page;
}

static inline unsigned int
gfp_to_alloc_flags(gfp_t gfp_mask)
{
	unsigned int alloc_flags = ALLOC_WMARK_MIN | ALLOC_CPUSET;

	/*
	 * __GFP_HIGH is assumed to be the same as ALLOC_HIGH
	 * and __GFP_KSWAPD_RECLAIM is assumed to be the same as ALLOC_KSWAPD
	 * to save two branches.
	 */
	BUILD_BUG_ON(__GFP_HIGH != (__force gfp_t) ALLOC_HIGH);
	BUILD_BUG_ON(__GFP_KSWAPD_RECLAIM != (__force gfp_t) ALLOC_KSWAPD);

	/*
	 * The caller may dip into page reserves a bit more if the caller
	 * cannot run direct reclaim, or if the caller has realtime scheduling
	 * policy or is asking for __GFP_HIGH memory.  GFP_ATOMIC requests will
	 * set both ALLOC_HARDER (__GFP_ATOMIC) and ALLOC_HIGH (__GFP_HIGH).
	 */
	alloc_flags |= (__force int)
		(gfp_mask & (__GFP_HIGH | __GFP_KSWAPD_RECLAIM));

	if (gfp_mask & __GFP_ATOMIC) {
		/*
		 * Not worth trying to allocate harder for __GFP_NOMEMALLOC even
		 * if it can't schedule.
		 */
		if (!(gfp_mask & __GFP_NOMEMALLOC))
			alloc_flags |= ALLOC_HARDER;
		/*
		 * Ignore cpuset mems for GFP_ATOMIC rather than fail, see the
		 * comment for __cpuset_node_allowed().
		 */
		alloc_flags &= ~ALLOC_CPUSET;
	} else if (unlikely(rt_task(current)) && !in_interrupt())
		alloc_flags |= ALLOC_HARDER;

	alloc_flags = current_alloc_flags(gfp_mask, alloc_flags);

	return alloc_flags;
}

static inline int __gfp_pfmemalloc_flags(gfp_t gfp_mask)
{
	if (unlikely(gfp_mask & __GFP_NOMEMALLOC))
		return 0;
	if (gfp_mask & __GFP_MEMALLOC)
		return ALLOC_NO_WATERMARKS;
	if (in_serving_softirq() && (current->flags & PF_MEMALLOC))
		return ALLOC_NO_WATERMARKS;
	if (!in_interrupt()) {
		if (current->flags & PF_MEMALLOC)
			return ALLOC_NO_WATERMARKS;
		else if (oom_reserves_allowed(current))
			return ALLOC_OOM;
	}

	return 0;
}
```
