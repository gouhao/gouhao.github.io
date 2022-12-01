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
	// prepare_alloc_pages主要是初始化alloc_context, 计算迁移类型，首选zone,node_mask, alloc_flag等
	// 如果打开CONFIG_FAIL_PAGE_ALLOC还会判断分配是否会失败，失败则返回false
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
	
	// 这个函数主要是对进程的进程中有NOIO或NOFS的标志进行处理
	alloc_mask = current_gfp_context(gfp_mask);
	// todo: 这里为什么把展开脏页关了？这个标志是在prepare里设置的
	ac.spread_dirty_pages = false;

	// 还原最初的nodemask，ac.nodemask可能在prepare里被
	// 替换成cpuset_current_mems_allowed，这是在快速路径里尝试的，
	// 这里需要把它还原
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

static inline gfp_t current_gfp_context(gfp_t flags)
{
	// 进程的flags
	unsigned int pflags = READ_ONCE(current->flags);

	// PF_MEMALLOC_NOIO：不允许io
	// PF_MEMALLOC_NOFS：没有fs
	// 如果进程有这2个标志任意一个
	if (unlikely(pflags & (PF_MEMALLOC_NOIO | PF_MEMALLOC_NOFS))) {
		if (pflags & PF_MEMALLOC_NOIO)
			// NOIO就把IO和FS标志去了
			flags &= ~(__GFP_IO | __GFP_FS);
		else if (pflags & PF_MEMALLOC_NOFS)
			// NOFS只去fs
			flags &= ~__GFP_FS;
	}
	return flags;
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
	// 允许回收
	bool can_direct_reclaim = gfp_mask & __GFP_DIRECT_RECLAIM;
	// PAGE_ALLOC_COSTLY_ORDER是3，大于这个的order被认为是分配代价高的
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
	// 压缩优先级是用来在回收的时候计算本次回收页数的，
	// 计算公式为：需要回收的页 ＝  1 / 2^compact_priority
	// DEF_COMPACT_PRIORITY＝2，
	compact_priority = DEF_COMPACT_PRIORITY;
	// 这个大数返回0。todo: 大多数情况返回0
	cpuset_mems_cookie = read_mems_allowed_begin();

	
	alloc_flags = gfp_to_alloc_flags(gfp_mask);

	// 因为nodemask在分配失败后被还原成原始的nodemask,所以这里要重新计算最适合的zone
	ac->preferred_zoneref = first_zones_zonelist(ac->zonelist,
					ac->highest_zoneidx, ac->nodemask);
	if (!ac->preferred_zoneref->zone)
		goto nopage;

	// 允许唤醒kswapd
	if (alloc_flags & ALLOC_KSWAPD)
		wake_all_kswapds(order, gfp_mask, ac);

	// 原文注释：调整了分配标志，说不定能成功，再试一次
	// 这里调整了2个值：gfp_mask和alloc_flags
	page = get_page_from_freelist(gfp_mask, order, alloc_flags, ac);
	if (page)
		goto got_pg;   

	// 允许回收 && (分配阶数大于3 || (分配大于1页 && 要求的页类型是不可移动的)) && 不允许忽略水位）
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

	// 这个函数根据当前进程是否是分配器进程而计算是否要忽略水印
	// 返回0表示不忽略
	reserve_flags = __gfp_pfmemalloc_flags(gfp_mask);
	if (reserve_flags)
		// 这个函数是判断是否需要CMA标志
		alloc_flags = current_alloc_flags(gfp_mask, reserve_flags);

	// ALLOC_CPUSET表示要检查进程的cpuset，要在可允许的cpu上分配,
	// 如果不检查cpuset，那就可以忽略nodemask的限制。
	// 忽略水位时，也忽略nodemask
	if (!(alloc_flags & ALLOC_CPUSET) || reserve_flags) {
		ac->nodemask = NULL;
		// 这里把nodemask设为null，再找首选zone的时候，就不再受nodemask的限制
		// 只受highest_zoneidx的限制
		ac->preferred_zoneref = first_zones_zonelist(ac->zonelist,
					ac->highest_zoneidx, ac->nodemask);
	}

	// 把上述的flag，mask, ac都调整完了再试一下
	page = get_page_from_freelist(gfp_mask, order, alloc_flags, ac);
	if (page)
		goto got_pg;

	// 不能回收就直接返回
	if (!can_direct_reclaim)
		goto nopage;

	// PF_MEMALLOC表示当前进程是内存管理相关的进程，比如kswapd等，这些进程需要退出，
	// 否则会造成无限递规
	if (current->flags & PF_MEMALLOC)
		goto nopage;

	// 回收页面，然后尝试分配。todo: 这里回收什么？
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

static inline struct page *
__alloc_pages_direct_reclaim(gfp_t gfp_mask, unsigned int order,
		unsigned int alloc_flags, const struct alloc_context *ac,
		unsigned long *did_some_progress)
{
	struct page *page = NULL;
	bool drained = false;

	// 开始回收，返回值表示有没有回收进程
	// 这个页面回收是同步的
	*did_some_progress = __perform_reclaim(gfp_mask, order, ac);
	// 如果没有回收就直接返回null，因为没有释放内存，也就不可能有内存回收
	if (unlikely(!(*did_some_progress)))
		return NULL;

retry:
	// 如果上面有一些回收，就再从freelist里再试着分配一次
	page = get_page_from_freelist(gfp_mask, order, alloc_flags, ac);

	/* 原文注释：在直接回收之后分配失败，可能是因为页面在percpu列表里被钉住了，或者保留的页面太多
	   收缩了这些再试一下
	*/
	if (!page && !drained) {
		unreserve_highatomic_pageblock(ac, false);
		drain_all_pages(NULL);
		drained = true;
		goto retry;
	}

	return page;
}

static unsigned long
__perform_reclaim(gfp_t gfp_mask, unsigned int order,
					const struct alloc_context *ac)
{
	unsigned int noreclaim_flag;
	unsigned long pflags, progress;

	// 先让出cpu，看有没有别人需要调度。因为下面是同步回收，可能比较慢，所以先让出去
	cond_resched();

	// 这个主要是统计每个cpu的回收计数
	cpuset_memory_pressure_bump();
	// 让进程进程stalled状态。主要是把进程的current->in_memstall设为1
	// todo: 没太看懂
	psi_memstall_enter(&pflags);
	// 这个只在CONFIG_LOCKDEP打开时才有意义，是获取一把锁，todo: 没太看懂
	fs_reclaim_acquire(gfp_mask);

	// 设置进程的PF_MEMALLOC标志，并返回以前的标志
	noreclaim_flag = memalloc_noreclaim_save();

	// 这个是回收页的核心函数
	progress = try_to_free_pages(ac->zonelist, order, gfp_mask,
								ac->nodemask);

	// 与上面的3个锁的顺序相反，还原各个锁，标志等
	memalloc_noreclaim_restore(noreclaim_flag);
	fs_reclaim_release(gfp_mask);
	psi_memstall_leave(&pflags);

	// 再让出cpu，因为上面可能做了一些回收，调度出去，让别人有机会运行
	cond_resched();

	return progress;
}

static inline unsigned int memalloc_noreclaim_save(void)
{
	// 获取进程之前的PF_MEMALLOC状态
	unsigned int flags = current->flags & PF_MEMALLOC;
	// 设置进程的PF_MEMALLOC标志
	current->flags |= PF_MEMALLOC;
	// 返回以前的标志
	return flags;
}

static inline void memalloc_noreclaim_restore(unsigned int flags)
{
	current->flags = (current->flags & ~PF_MEMALLOC) | flags;
}

unsigned long try_to_free_pages(struct zonelist *zonelist, int order,
				gfp_t gfp_mask, nodemask_t *nodemask)
{
	unsigned long nr_reclaimed;
	struct scan_control sc = {
		.nr_to_reclaim = SWAP_CLUSTER_MAX,
		.gfp_mask = current_gfp_context(gfp_mask),
		.reclaim_idx = gfp_zone(gfp_mask),
		.order = order,
		.nodemask = nodemask,
		.priority = DEF_PRIORITY,
		.may_writepage = !laptop_mode,
		.may_unmap = 1,
		.may_swap = 1,
	};

	/*
	 * scan_control uses s8 fields for order, priority, and reclaim_idx.
	 * Confirm they are large enough for max values.
	 */
	BUILD_BUG_ON(MAX_ORDER > S8_MAX);
	BUILD_BUG_ON(DEF_PRIORITY > S8_MAX);
	BUILD_BUG_ON(MAX_NR_ZONES > S8_MAX);

	/*
	 * Do not enter reclaim if fatal signal was delivered while throttled.
	 * 1 is returned so that the page allocator does not OOM kill at this
	 * point.
	 */
	if (throttle_direct_reclaim(sc.gfp_mask, zonelist, nodemask))
		return 1;

	set_task_reclaim_state(current, &sc.reclaim_state);
	trace_mm_vmscan_direct_reclaim_begin(order, sc.gfp_mask);

	nr_reclaimed = do_try_to_free_pages(zonelist, &sc);

	trace_mm_vmscan_direct_reclaim_end(nr_reclaimed);
	set_task_reclaim_state(current, NULL);

	return nr_reclaimed;
}

static unsigned long do_try_to_free_pages(struct zonelist *zonelist,
					  struct scan_control *sc)
{
	int initial_priority = sc->priority;
	pg_data_t *last_pgdat;
	struct zoneref *z;
	struct zone *zone;
retry:
	delayacct_freepages_start();

	if (!cgroup_reclaim(sc))
		__count_zid_vm_events(ALLOCSTALL, sc->reclaim_idx, 1);

	do {
		vmpressure_prio(sc->gfp_mask, sc->target_mem_cgroup,
				sc->priority);
		sc->nr_scanned = 0;
		shrink_zones(zonelist, sc);

		if (sc->nr_reclaimed >= sc->nr_to_reclaim)
			break;

		if (sc->compaction_ready)
			break;

		/*
		 * If we're getting trouble reclaiming, start doing
		 * writepage even in laptop mode.
		 */
		if (sc->priority < DEF_PRIORITY - 2)
			sc->may_writepage = 1;
	} while (--sc->priority >= 0);

	last_pgdat = NULL;
	for_each_zone_zonelist_nodemask(zone, z, zonelist, sc->reclaim_idx,
					sc->nodemask) {
		if (zone->zone_pgdat == last_pgdat)
			continue;
		last_pgdat = zone->zone_pgdat;

		snapshot_refaults(sc->target_mem_cgroup, zone->zone_pgdat);

		if (cgroup_reclaim(sc)) {
			struct lruvec *lruvec;

			lruvec = mem_cgroup_lruvec(sc->target_mem_cgroup,
						   zone->zone_pgdat);
			clear_bit(LRUVEC_CONGESTED, &lruvec->flags);
		}
	}

	delayacct_freepages_end();

	if (sc->nr_reclaimed)
		return sc->nr_reclaimed;

	/* Aborted reclaim to try compaction? don't OOM, then */
	if (sc->compaction_ready)
		return 1;

	/*
	 * We make inactive:active ratio decisions based on the node's
	 * composition of memory, but a restrictive reclaim_idx or a
	 * memory.low cgroup setting can exempt large amounts of
	 * memory from reclaim. Neither of which are very common, so
	 * instead of doing costly eligibility calculations of the
	 * entire cgroup subtree up front, we assume the estimates are
	 * good, and retry with forcible deactivation if that fails.
	 */
	if (sc->skipped_deactivate) {
		sc->priority = initial_priority;
		sc->force_deactivate = 1;
		sc->skipped_deactivate = 0;
		goto retry;
	}

	/* Untapped cgroup reserves?  Don't OOM, retry. */
	if (sc->memcg_low_skipped) {
		sc->priority = initial_priority;
		sc->force_deactivate = 0;
		sc->memcg_low_reclaim = 1;
		sc->memcg_low_skipped = 0;
		goto retry;
	}

	return 0;
}

static void shrink_zones(struct zonelist *zonelist, struct scan_control *sc)
{
	struct zoneref *z;
	struct zone *zone;
	unsigned long nr_soft_reclaimed;
	unsigned long nr_soft_scanned;
	gfp_t orig_mask;
	pg_data_t *last_pgdat = NULL;

	/*
	 * If the number of buffer_heads in the machine exceeds the maximum
	 * allowed level, force direct reclaim to scan the highmem zone as
	 * highmem pages could be pinning lowmem pages storing buffer_heads
	 */
	orig_mask = sc->gfp_mask;
	if (buffer_heads_over_limit) {
		sc->gfp_mask |= __GFP_HIGHMEM;
		sc->reclaim_idx = gfp_zone(sc->gfp_mask);
	}

	for_each_zone_zonelist_nodemask(zone, z, zonelist,
					sc->reclaim_idx, sc->nodemask) {
		/*
		 * Take care memory controller reclaiming has small influence
		 * to global LRU.
		 */
		if (!cgroup_reclaim(sc)) {
			if (!cpuset_zone_allowed(zone,
						 GFP_KERNEL | __GFP_HARDWALL))
				continue;

			/*
			 * If we already have plenty of memory free for
			 * compaction in this zone, don't free any more.
			 * Even though compaction is invoked for any
			 * non-zero order, only frequent costly order
			 * reclamation is disruptive enough to become a
			 * noticeable problem, like transparent huge
			 * page allocations.
			 */
			if (IS_ENABLED(CONFIG_COMPACTION) &&
			    sc->order > PAGE_ALLOC_COSTLY_ORDER &&
			    compaction_ready(zone, sc)) {
				sc->compaction_ready = true;
				continue;
			}

			/*
			 * Shrink each node in the zonelist once. If the
			 * zonelist is ordered by zone (not the default) then a
			 * node may be shrunk multiple times but in that case
			 * the user prefers lower zones being preserved.
			 */
			if (zone->zone_pgdat == last_pgdat)
				continue;

			/*
			 * This steals pages from memory cgroups over softlimit
			 * and returns the number of reclaimed pages and
			 * scanned pages. This works for global memory pressure
			 * and balancing, not for a memcg's limit.
			 */
			nr_soft_scanned = 0;
			nr_soft_reclaimed = mem_cgroup_soft_limit_reclaim(zone->zone_pgdat,
						sc->order, sc->gfp_mask,
						&nr_soft_scanned);
			sc->nr_reclaimed += nr_soft_reclaimed;
			sc->nr_scanned += nr_soft_scanned;
			/* need some check for avoid more shrink_zone() */
		}

		/* See comment about same check for global reclaim above */
		if (zone->zone_pgdat == last_pgdat)
			continue;
		last_pgdat = zone->zone_pgdat;
		shrink_node(zone->zone_pgdat, sc);
	}

	/*
	 * Restore to original mask to avoid the impact on the caller if we
	 * promoted it to __GFP_HIGHMEM.
	 */
	sc->gfp_mask = orig_mask;
}

static void shrink_node(pg_data_t *pgdat, struct scan_control *sc)
{
	struct reclaim_state *reclaim_state = current->reclaim_state;
	unsigned long nr_reclaimed, nr_scanned;
	struct lruvec *target_lruvec;
	bool reclaimable = false;
	unsigned long file;

	target_lruvec = mem_cgroup_lruvec(sc->target_mem_cgroup, pgdat);

again:
	memset(&sc->nr, 0, sizeof(sc->nr));

	nr_reclaimed = sc->nr_reclaimed;
	nr_scanned = sc->nr_scanned;

	/*
	 * Determine the scan balance between anon and file LRUs.
	 */
	spin_lock_irq(&pgdat->lru_lock);
	sc->anon_cost = target_lruvec->anon_cost;
	sc->file_cost = target_lruvec->file_cost;
	spin_unlock_irq(&pgdat->lru_lock);

	/*
	 * Target desirable inactive:active list ratios for the anon
	 * and file LRU lists.
	 */
	if (!sc->force_deactivate) {
		unsigned long refaults;

		refaults = lruvec_page_state(target_lruvec,
				WORKINGSET_ACTIVATE_ANON);
		if (refaults != target_lruvec->refaults[0] ||
			inactive_is_low(target_lruvec, LRU_INACTIVE_ANON))
			sc->may_deactivate |= DEACTIVATE_ANON;
		else
			sc->may_deactivate &= ~DEACTIVATE_ANON;

		/*
		 * When refaults are being observed, it means a new
		 * workingset is being established. Deactivate to get
		 * rid of any stale active pages quickly.
		 */
		refaults = lruvec_page_state(target_lruvec,
				WORKINGSET_ACTIVATE_FILE);
		if (refaults != target_lruvec->refaults[1] ||
		    inactive_is_low(target_lruvec, LRU_INACTIVE_FILE))
			sc->may_deactivate |= DEACTIVATE_FILE;
		else
			sc->may_deactivate &= ~DEACTIVATE_FILE;
	} else
		sc->may_deactivate = DEACTIVATE_ANON | DEACTIVATE_FILE;

	/*
	 * If we have plenty of inactive file pages that aren't
	 * thrashing, try to reclaim those first before touching
	 * anonymous pages.
	 */
	file = lruvec_page_state(target_lruvec, NR_INACTIVE_FILE);
	if (file >> sc->priority && !(sc->may_deactivate & DEACTIVATE_FILE))
		sc->cache_trim_mode = 1;
	else
		sc->cache_trim_mode = 0;

	/*
	 * Prevent the reclaimer from falling into the cache trap: as
	 * cache pages start out inactive, every cache fault will tip
	 * the scan balance towards the file LRU.  And as the file LRU
	 * shrinks, so does the window for rotation from references.
	 * This means we have a runaway feedback loop where a tiny
	 * thrashing file LRU becomes infinitely more attractive than
	 * anon pages.  Try to detect this based on file LRU size.
	 */
	if (!cgroup_reclaim(sc)) {
		unsigned long total_high_wmark = 0;
		unsigned long free, anon;
		int z;

		free = sum_zone_node_page_state(pgdat->node_id, NR_FREE_PAGES);
		file = node_page_state(pgdat, NR_ACTIVE_FILE) +
			   node_page_state(pgdat, NR_INACTIVE_FILE);

		for (z = 0; z < MAX_NR_ZONES; z++) {
			struct zone *zone = &pgdat->node_zones[z];
			if (!managed_zone(zone))
				continue;

			total_high_wmark += high_wmark_pages(zone);
		}

		/*
		 * Consider anon: if that's low too, this isn't a
		 * runaway file reclaim problem, but rather just
		 * extreme pressure. Reclaim as per usual then.
		 */
		anon = node_page_state(pgdat, NR_INACTIVE_ANON);

		sc->file_is_tiny =
			file + free <= total_high_wmark &&
			!(sc->may_deactivate & DEACTIVATE_ANON) &&
			anon >> sc->priority;
	}

	shrink_node_memcgs(pgdat, sc);

	if (reclaim_state) {
		sc->nr_reclaimed += reclaim_state->reclaimed_slab;
		reclaim_state->reclaimed_slab = 0;
	}

	/* Record the subtree's reclaim efficiency */
	vmpressure(sc->gfp_mask, sc->target_mem_cgroup, true,
		   sc->nr_scanned - nr_scanned,
		   sc->nr_reclaimed - nr_reclaimed);

	if (sc->nr_reclaimed - nr_reclaimed)
		reclaimable = true;

	if (current_is_kswapd()) {
		/*
		 * If reclaim is isolating dirty pages under writeback,
		 * it implies that the long-lived page allocation rate
		 * is exceeding the page laundering rate. Either the
		 * global limits are not being effective at throttling
		 * processes due to the page distribution throughout
		 * zones or there is heavy usage of a slow backing
		 * device. The only option is to throttle from reclaim
		 * context which is not ideal as there is no guarantee
		 * the dirtying process is throttled in the same way
		 * balance_dirty_pages() manages.
		 *
		 * Once a node is flagged PGDAT_WRITEBACK, kswapd will
		 * count the number of pages under pages flagged for
		 * immediate reclaim and stall if any are encountered
		 * in the nr_immediate check below.
		 */
		if (sc->nr.writeback && sc->nr.writeback == sc->nr.taken)
			set_bit(PGDAT_WRITEBACK, &pgdat->flags);

		/* Allow kswapd to start writing pages during reclaim.*/
		if (sc->nr.unqueued_dirty == sc->nr.file_taken)
			set_bit(PGDAT_DIRTY, &pgdat->flags);

		/*
		 * If kswapd scans pages marked for immediate
		 * reclaim and under writeback (nr_immediate), it
		 * implies that pages are cycling through the LRU
		 * faster than they are written so also forcibly stall.
		 */
		if (sc->nr.immediate)
			congestion_wait(BLK_RW_ASYNC, HZ/10);
	}

	/*
	 * Tag a node/memcg as congested if all the dirty pages
	 * scanned were backed by a congested BDI and
	 * wait_iff_congested will stall.
	 *
	 * Legacy memcg will stall in page writeback so avoid forcibly
	 * stalling in wait_iff_congested().
	 */
	if ((current_is_kswapd() ||
	     (cgroup_reclaim(sc) && writeback_throttling_sane(sc))) &&
	    sc->nr.dirty && sc->nr.dirty == sc->nr.congested)
		set_bit(LRUVEC_CONGESTED, &target_lruvec->flags);

	/*
	 * Stall direct reclaim for IO completions if underlying BDIs
	 * and node is congested. Allow kswapd to continue until it
	 * starts encountering unqueued dirty pages or cycling through
	 * the LRU too quickly.
	 */
	if (!current_is_kswapd() && current_may_throttle() &&
	    !sc->hibernation_mode &&
	    test_bit(LRUVEC_CONGESTED, &target_lruvec->flags))
		wait_iff_congested(BLK_RW_ASYNC, HZ/10);

	if (should_continue_reclaim(pgdat, sc->nr_reclaimed - nr_reclaimed,
				    sc))
		goto again;

	/*
	 * Kswapd gives up on balancing particular nodes after too
	 * many failures to reclaim anything from them and goes to
	 * sleep. On reclaim progress, reset the failure counter. A
	 * successful direct reclaim run will revive a dormant kswapd.
	 */
	if (reclaimable)
		pgdat->kswapd_failures = 0;
}

static void shrink_node_memcgs(pg_data_t *pgdat, struct scan_control *sc)
{
	struct mem_cgroup *target_memcg = sc->target_mem_cgroup;
	struct mem_cgroup *memcg;

	memcg = mem_cgroup_iter(target_memcg, NULL, NULL);
	do {
		struct lruvec *lruvec = mem_cgroup_lruvec(memcg, pgdat);
		unsigned long reclaimed;
		unsigned long scanned;

		/*
		 * This loop can become CPU-bound when target memcgs
		 * aren't eligible for reclaim - either because they
		 * don't have any reclaimable pages, or because their
		 * memory is explicitly protected. Avoid soft lockups.
		 */
		cond_resched();

		mem_cgroup_calculate_protection(target_memcg, memcg);

		if (mem_cgroup_below_min(memcg)) {
			/*
			 * Hard protection.
			 * If there is no reclaimable memory, OOM.
			 */
			continue;
		} else if (mem_cgroup_below_low(memcg)) {
			/*
			 * Soft protection.
			 * Respect the protection only as long as
			 * there is an unprotected supply
			 * of reclaimable memory from other cgroups.
			 */
			if (!sc->memcg_low_reclaim) {
				sc->memcg_low_skipped = 1;
				continue;
			}
			memcg_memory_event(memcg, MEMCG_LOW);
		}

		reclaimed = sc->nr_reclaimed;
		scanned = sc->nr_scanned;

		shrink_lruvec(lruvec, sc);

		shrink_slab(sc->gfp_mask, pgdat->node_id, memcg,
			    sc->priority);

		/* Record the group's reclaim efficiency */
		vmpressure(sc->gfp_mask, memcg, false,
			   sc->nr_scanned - scanned,
			   sc->nr_reclaimed - reclaimed);

	} while ((memcg = mem_cgroup_iter(target_memcg, memcg, NULL)));
}

static void shrink_lruvec(struct lruvec *lruvec, struct scan_control *sc)
{
	unsigned long nr[NR_LRU_LISTS];
	unsigned long targets[NR_LRU_LISTS];
	unsigned long nr_to_scan;
	enum lru_list lru;
	unsigned long nr_reclaimed = 0;
	unsigned long nr_to_reclaim = sc->nr_to_reclaim;
	struct blk_plug plug;
	bool scan_adjusted;

	get_scan_count(lruvec, sc, nr);

	/* Record the original scan target for proportional adjustments later */
	memcpy(targets, nr, sizeof(nr));

	/*
	 * Global reclaiming within direct reclaim at DEF_PRIORITY is a normal
	 * event that can occur when there is little memory pressure e.g.
	 * multiple streaming readers/writers. Hence, we do not abort scanning
	 * when the requested number of pages are reclaimed when scanning at
	 * DEF_PRIORITY on the assumption that the fact we are direct
	 * reclaiming implies that kswapd is not keeping up and it is best to
	 * do a batch of work at once. For memcg reclaim one check is made to
	 * abort proportional reclaim if either the file or anon lru has already
	 * dropped to zero at the first pass.
	 */
	scan_adjusted = (!cgroup_reclaim(sc) && !current_is_kswapd() &&
			 sc->priority == DEF_PRIORITY);

	blk_start_plug(&plug);
	while (nr[LRU_INACTIVE_ANON] || nr[LRU_ACTIVE_FILE] ||
					nr[LRU_INACTIVE_FILE]) {
		unsigned long nr_anon, nr_file, percentage;
		unsigned long nr_scanned;

		for_each_evictable_lru(lru) {
			if (nr[lru]) {
				nr_to_scan = min(nr[lru], SWAP_CLUSTER_MAX);
				nr[lru] -= nr_to_scan;

				nr_reclaimed += shrink_list(lru, nr_to_scan,
							    lruvec, sc);
			}
		}

		cond_resched();

		if (nr_reclaimed < nr_to_reclaim || scan_adjusted)
			continue;

		/*
		 * For kswapd and memcg, reclaim at least the number of pages
		 * requested. Ensure that the anon and file LRUs are scanned
		 * proportionally what was requested by get_scan_count(). We
		 * stop reclaiming one LRU and reduce the amount scanning
		 * proportional to the original scan target.
		 */
		nr_file = nr[LRU_INACTIVE_FILE] + nr[LRU_ACTIVE_FILE];
		nr_anon = nr[LRU_INACTIVE_ANON] + nr[LRU_ACTIVE_ANON];

		/*
		 * It's just vindictive to attack the larger once the smaller
		 * has gone to zero.  And given the way we stop scanning the
		 * smaller below, this makes sure that we only make one nudge
		 * towards proportionality once we've got nr_to_reclaim.
		 */
		if (!nr_file || !nr_anon)
			break;

		if (nr_file > nr_anon) {
			unsigned long scan_target = targets[LRU_INACTIVE_ANON] +
						targets[LRU_ACTIVE_ANON] + 1;
			lru = LRU_BASE;
			percentage = nr_anon * 100 / scan_target;
		} else {
			unsigned long scan_target = targets[LRU_INACTIVE_FILE] +
						targets[LRU_ACTIVE_FILE] + 1;
			lru = LRU_FILE;
			percentage = nr_file * 100 / scan_target;
		}

		/* Stop scanning the smaller of the LRU */
		nr[lru] = 0;
		nr[lru + LRU_ACTIVE] = 0;

		/*
		 * Recalculate the other LRU scan count based on its original
		 * scan target and the percentage scanning already complete
		 */
		lru = (lru == LRU_FILE) ? LRU_BASE : LRU_FILE;
		nr_scanned = targets[lru] - nr[lru];
		nr[lru] = targets[lru] * (100 - percentage) / 100;
		nr[lru] -= min(nr[lru], nr_scanned);

		lru += LRU_ACTIVE;
		nr_scanned = targets[lru] - nr[lru];
		nr[lru] = targets[lru] * (100 - percentage) / 100;
		nr[lru] -= min(nr[lru], nr_scanned);

		scan_adjusted = true;
	}
	blk_finish_plug(&plug);
	sc->nr_reclaimed += nr_reclaimed;

	/*
	 * Even if we did not try to evict anon pages at all, we want to
	 * rebalance the anon lru active/inactive ratio.
	 */
	if (total_swap_pages && inactive_is_low(lruvec, LRU_INACTIVE_ANON))
		shrink_active_list(SWAP_CLUSTER_MAX, lruvec,
				   sc, LRU_ACTIVE_ANON);
}

static void shrink_active_list(unsigned long nr_to_scan,
			       struct lruvec *lruvec,
			       struct scan_control *sc,
			       enum lru_list lru)
{
	unsigned long nr_taken;
	unsigned long nr_scanned;
	unsigned long vm_flags;
	LIST_HEAD(l_hold);	/* The pages which were snipped off */
	LIST_HEAD(l_active);
	LIST_HEAD(l_inactive);
	struct page *page;
	unsigned nr_deactivate, nr_activate;
	unsigned nr_rotated = 0;
	int file = is_file_lru(lru);
	struct pglist_data *pgdat = lruvec_pgdat(lruvec);

	lru_add_drain();

	spin_lock_irq(&pgdat->lru_lock);

	nr_taken = isolate_lru_pages(nr_to_scan, lruvec, &l_hold,
				     &nr_scanned, sc, lru);

	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, nr_taken);

	if (!cgroup_reclaim(sc))
		__count_vm_events(PGREFILL, nr_scanned);
	__count_memcg_events(lruvec_memcg(lruvec), PGREFILL, nr_scanned);

	spin_unlock_irq(&pgdat->lru_lock);

	while (!list_empty(&l_hold)) {
		cond_resched();
		page = lru_to_page(&l_hold);
		list_del(&page->lru);

		if (unlikely(!page_evictable(page))) {
			putback_lru_page(page);
			continue;
		}

		if (unlikely(buffer_heads_over_limit)) {
			if (page_has_private(page) && trylock_page(page)) {
				if (page_has_private(page))
					try_to_release_page(page, 0);
				unlock_page(page);
			}
		}

		if (page_referenced(page, 0, sc->target_mem_cgroup,
				    &vm_flags)) {
			/*
			 * Identify referenced, file-backed active pages and
			 * give them one more trip around the active list. So
			 * that executable code get better chances to stay in
			 * memory under moderate memory pressure.  Anon pages
			 * are not likely to be evicted by use-once streaming
			 * IO, plus JVM can create lots of anon VM_EXEC pages,
			 * so we ignore them here.
			 */
			if ((vm_flags & VM_EXEC) && page_is_file_lru(page)) {
				nr_rotated += thp_nr_pages(page);
				list_add(&page->lru, &l_active);
				continue;
			}
		}

		ClearPageActive(page);	/* we are de-activating */
		SetPageWorkingset(page);
		list_add(&page->lru, &l_inactive);
	}

	/*
	 * Move pages back to the lru list.
	 */
	spin_lock_irq(&pgdat->lru_lock);

	nr_activate = move_pages_to_lru(lruvec, &l_active);
	nr_deactivate = move_pages_to_lru(lruvec, &l_inactive);
	/* Keep all free pages in l_active list */
	list_splice(&l_inactive, &l_active);

	__count_vm_events(PGDEACTIVATE, nr_deactivate);
	__count_memcg_events(lruvec_memcg(lruvec), PGDEACTIVATE, nr_deactivate);

	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, -nr_taken);
	spin_unlock_irq(&pgdat->lru_lock);

	mem_cgroup_uncharge_list(&l_active);
	free_unref_page_list(&l_active);
	trace_mm_vmscan_lru_shrink_active(pgdat->node_id, nr_taken, nr_activate,
			nr_deactivate, nr_rotated, sc->priority, file);
}

static unsigned long shrink_slab(gfp_t gfp_mask, int nid,
				 struct mem_cgroup *memcg,
				 int priority)
{
	unsigned long ret, freed = 0;
	struct shrinker *shrinker;

	/*
	 * The root memcg might be allocated even though memcg is disabled
	 * via "cgroup_disable=memory" boot parameter.  This could make
	 * mem_cgroup_is_root() return false, then just run memcg slab
	 * shrink, but skip global shrink.  This may result in premature
	 * oom.
	 */
	if (!mem_cgroup_disabled() && !mem_cgroup_is_root(memcg))
		return shrink_slab_memcg(gfp_mask, nid, memcg, priority);

	if (!down_read_trylock(&shrinker_rwsem))
		goto out;

	list_for_each_entry(shrinker, &shrinker_list, list) {
		struct shrink_control sc = {
			.gfp_mask = gfp_mask,
			.nid = nid,
			.memcg = memcg,
		};

		ret = do_shrink_slab(&sc, shrinker, priority);
		if (ret == SHRINK_EMPTY)
			ret = 0;
		freed += ret;
		/*
		 * Bail out if someone want to register a new shrinker to
		 * prevent the registration from being stalled for long periods
		 * by parallel ongoing shrinking.
		 */
		if (rwsem_is_contended(&shrinker_rwsem)) {
			freed = freed ? : 1;
			break;
		}
	}

	up_read(&shrinker_rwsem);
out:
	cond_resched();
	return freed;
}

static unsigned long do_shrink_slab(struct shrink_control *shrinkctl,
				    struct shrinker *shrinker, int priority)
{
	unsigned long freed = 0;
	unsigned long long delta;
	long total_scan;
	long freeable;
	long nr;
	long new_nr;
	int nid = shrinkctl->nid;
	long batch_size = shrinker->batch ? shrinker->batch
					  : SHRINK_BATCH;
	long scanned = 0, next_deferred;

	if (!(shrinker->flags & SHRINKER_NUMA_AWARE))
		nid = 0;

	freeable = shrinker->count_objects(shrinker, shrinkctl);
	if (freeable == 0 || freeable == SHRINK_EMPTY)
		return freeable;

	/*
	 * copy the current shrinker scan count into a local variable
	 * and zero it so that other concurrent shrinker invocations
	 * don't also do this scanning work.
	 */
	nr = atomic_long_xchg(&shrinker->nr_deferred[nid], 0);

	total_scan = nr;
	if (shrinker->seeks) {
		delta = freeable >> priority;
		delta *= 4;
		do_div(delta, shrinker->seeks);
	} else {
		/*
		 * These objects don't require any IO to create. Trim
		 * them aggressively under memory pressure to keep
		 * them from causing refetches in the IO caches.
		 */
		delta = freeable / 2;
	}

	total_scan += delta;
	if (total_scan < 0) {
		pr_err("shrink_slab: %pS negative objects to delete nr=%ld\n",
		       shrinker->scan_objects, total_scan);
		total_scan = freeable;
		next_deferred = nr;
	} else
		next_deferred = total_scan;

	/*
	 * We need to avoid excessive windup on filesystem shrinkers
	 * due to large numbers of GFP_NOFS allocations causing the
	 * shrinkers to return -1 all the time. This results in a large
	 * nr being built up so when a shrink that can do some work
	 * comes along it empties the entire cache due to nr >>>
	 * freeable. This is bad for sustaining a working set in
	 * memory.
	 *
	 * Hence only allow the shrinker to scan the entire cache when
	 * a large delta change is calculated directly.
	 */
	if (delta < freeable / 4)
		total_scan = min(total_scan, freeable / 2);

	/*
	 * Avoid risking looping forever due to too large nr value:
	 * never try to free more than twice the estimate number of
	 * freeable entries.
	 */
	if (total_scan > freeable * 2)
		total_scan = freeable * 2;

	trace_mm_shrink_slab_start(shrinker, shrinkctl, nr,
				   freeable, delta, total_scan, priority);

	/*
	 * Normally, we should not scan less than batch_size objects in one
	 * pass to avoid too frequent shrinker calls, but if the slab has less
	 * than batch_size objects in total and we are really tight on memory,
	 * we will try to reclaim all available objects, otherwise we can end
	 * up failing allocations although there are plenty of reclaimable
	 * objects spread over several slabs with usage less than the
	 * batch_size.
	 *
	 * We detect the "tight on memory" situations by looking at the total
	 * number of objects we want to scan (total_scan). If it is greater
	 * than the total number of objects on slab (freeable), we must be
	 * scanning at high prio and therefore should try to reclaim as much as
	 * possible.
	 */
	while (total_scan >= batch_size ||
	       total_scan >= freeable) {
		unsigned long ret;
		unsigned long nr_to_scan = min(batch_size, total_scan);

		shrinkctl->nr_to_scan = nr_to_scan;
		shrinkctl->nr_scanned = nr_to_scan;
		ret = shrinker->scan_objects(shrinker, shrinkctl);
		if (ret == SHRINK_STOP)
			break;
		freed += ret;

		count_vm_events(SLABS_SCANNED, shrinkctl->nr_scanned);
		total_scan -= shrinkctl->nr_scanned;
		scanned += shrinkctl->nr_scanned;

		cond_resched();
	}

	if (next_deferred >= scanned)
		next_deferred -= scanned;
	else
		next_deferred = 0;
	/*
	 * move the unused scan count back into the shrinker in a
	 * manner that handles concurrent updates. If we exhausted the
	 * scan, there is no need to do an update.
	 */
	if (next_deferred > 0)
		new_nr = atomic_long_add_return(next_deferred,
						&shrinker->nr_deferred[nid]);
	else
		new_nr = atomic_long_read(&shrinker->nr_deferred[nid]);

	trace_mm_shrink_slab_end(shrinker, nid, freed, nr, new_nr, total_scan);
	return freed;
}

bool gfp_pfmemalloc_allowed(gfp_t gfp_mask)
{
	// 这里 !! 的意思就是把返回值转换成0或1
	return !!__gfp_pfmemalloc_flags(gfp_mask);
}

static inline int __gfp_pfmemalloc_flags(gfp_t gfp_mask)
{
	// 不是分配器程序
	if (unlikely(gfp_mask & __GFP_NOMEMALLOC))
		return 0;
	// 是分配器程序
	if (gfp_mask & __GFP_MEMALLOC)
		// 这个是忽略水位线
		return ALLOC_NO_WATERMARKS;
	// 在软中断环境里的进程有PF_MEMALLOC，也忽略水位线
	if (in_serving_softirq() && (current->flags & PF_MEMALLOC))
		return ALLOC_NO_WATERMARKS;

	// 不是中断上下文
	if (!in_interrupt()) {
		// 当前进程有PF_MEMALLOC，则忽略水位线
		if (current->flags & PF_MEMALLOC)
			return ALLOC_NO_WATERMARKS;
		// 这个是判断是否允许使用保留的内存，主要判断了2种情况：
		// 进程是否被杀，进程是否正在终止，这2种情况不用使用保留资源
		else if (oom_reserves_allowed(current))
			return ALLOC_OOM;
	}

	return 0;
}

static bool oom_reserves_allowed(struct task_struct *tsk)
{
	// oom受害者：表示正在被 oom 杀
	// 主要是判断tsk->signal->oom_mm是否为空
	if (!tsk_is_oom_victim(tsk))
		return false;

	// MMU一般都是打开的。TIF_MEMDIE表示进程正在终止
	if (!IS_ENABLED(CONFIG_MMU) && !test_thread_flag(TIF_MEMDIE))
		return false;

	return true;
}
static inline unsigned int
gfp_to_alloc_flags(gfp_t gfp_mask)
{
	// 因为分配失败了，所以尝试使用min水位
	unsigned int alloc_flags = ALLOC_WMARK_MIN | ALLOC_CPUSET;

	BUILD_BUG_ON(__GFP_HIGH != (__force gfp_t) ALLOC_HIGH);
	BUILD_BUG_ON(__GFP_KSWAPD_RECLAIM != (__force gfp_t) ALLOC_KSWAPD);

	/*
	 * The caller may dip into page reserves a bit more if the caller
	 * cannot run direct reclaim, or if the caller has realtime scheduling
	 * policy or is asking for __GFP_HIGH memory.  GFP_ATOMIC requests will
	 * set both ALLOC_HARDER (__GFP_ATOMIC) and ALLOC_HIGH (__GFP_HIGH).
	 */
	// todo:?
	alloc_flags |= (__force int)
		(gfp_mask & (__GFP_HIGH | __GFP_KSWAPD_RECLAIM));

	if (gfp_mask & __GFP_ATOMIC) {
		// 原子分配
		// __GFP_NOMEMALLOC是分配器相关的线程设置的标志
		// 这里只对非分配器设置ALLOC_HARDER标志
		// todo: 这个标志对分配起什么作用
		if (!(gfp_mask & __GFP_NOMEMALLOC))
			alloc_flags |= ALLOC_HARDER;
		// ALLOC_CPUSET是检查正确的CPU集合
		// 原子分配不需要这个, todo: why?
		alloc_flags &= ~ALLOC_CPUSET;
	} else if (unlikely(rt_task(current)) && !in_interrupt())
		// 如果是实时进程，也需要harder标志
		alloc_flags |= ALLOC_HARDER;

	// 这个函数主要根据进程进否禁用了CMA而计算是否在分配标志里增加ALLOC_CMA
	alloc_flags = current_alloc_flags(gfp_mask, alloc_flags);

	return alloc_flags;
}

static inline unsigned int current_alloc_flags(gfp_t gfp_mask,
					unsigned int alloc_flags)
{
#ifdef CONFIG_CMA
	unsigned int pflags = current->flags;

	// 当前进程没有禁用CMA，要分配的页也是可移动的，就可以在CMA分配
	if (!(pflags & PF_MEMALLOC_NOCMA) &&
			gfp_migratetype(gfp_mask) == MIGRATE_MOVABLE)
		alloc_flags |= ALLOC_CMA;

#endif
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

static inline unsigned int read_mems_allowed_begin(void)
{
	if (!static_branch_unlikely(&cpusets_pre_enable_key))
		return 0;

	return read_seqcount_begin(&current->mems_allowed_seq);
}
```
