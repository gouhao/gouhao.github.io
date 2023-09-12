# 初始化内存管理

源码基于5.10，本文里的代码都是在CONFIG_NUMA打开的情景里，现在内核这个选项都是打开的，即使电脑没有numa结构。


## build_all_zonelists
```c
void __ref build_all_zonelists(pg_data_t *pgdat)
{
	unsigned long vm_total_pages;

	if (system_state == SYSTEM_BOOTING) {
		// 启动阶段
		build_all_zonelists_init();
	} else {
		// 热插拔好像会走这里？
		__build_all_zonelists(pgdat);
		/* cpuset refresh routine should be here */
	}
	/* Get the number of free pages beyond high watermark in all zones. */
	vm_total_pages = nr_free_zone_pages(gfp_zone(GFP_HIGHUSER_MOVABLE));

	// pageblock_nr_pages表示大的分配阶对应的页数
	if (vm_total_pages < (pageblock_nr_pages * MIGRATE_TYPES))
		page_group_by_mobility_disabled = 1;
	else
		// 当内存较少时，关闭可移动特性
		page_group_by_mobility_disabled = 0;

	pr_info("Built %u zonelists, mobility grouping %s.  Total pages: %ld\n",
		nr_online_nodes,
		page_group_by_mobility_disabled ? "off" : "on",
		vm_total_pages);
#ifdef CONFIG_NUMA
	pr_info("Policy zone: %s\n", zone_names[policy_zone]);
#endif
}

static noinline void __init
build_all_zonelists_init(void)
{
	int cpu;

	// 主要初始化了备用列表
	__build_all_zonelists(NULL);

	// 初始percpuset
	for_each_possible_cpu(cpu)
		setup_pageset(&per_cpu(boot_pageset, cpu), 0);

	// debug相关
	mminit_verify_zonelist();
	// 设置current->mems_allowed
	cpuset_init_current_mems_allowed();
}

static void setup_pageset(struct per_cpu_pageset *p, unsigned long batch)
{
	// 初始化pageset
	pageset_init(p);
	// 计算批量大小
	pageset_set_batch(p, batch);
}

static void pageset_init(struct per_cpu_pageset *p)
{
	struct per_cpu_pages *pcp;
	int migratetype;

	memset(p, 0, sizeof(*p));

	pcp = &p->pcp;
	// 初始化每个迁移类型里的表头
	for (migratetype = 0; migratetype < MIGRATE_PCPTYPES; migratetype++)
		INIT_LIST_HEAD(&pcp->lists[migratetype]);
}

static void pageset_set_batch(struct per_cpu_pageset *p, unsigned long batch)
{
	// 设置pageset里的batch数量
	// 这里batch传下来的是0，所以后面两个参数，是 0, 1
	pageset_update(&p->pcp, 6 * batch, max(1UL, 1 * batch));
}

static void pageset_update(struct per_cpu_pages *pcp, unsigned long high,
		unsigned long batch)
{
	// todo: 为啥要这么设置？？？

       /* start with a fail safe value for batch */
	pcp->batch = 1;
	smp_wmb();

	// 设置fjb ymk r 
       /* Update high, then batch, in order */
	pcp->high = high;
	smp_wmb();

	pcp->batch = batch;
}

static void __build_all_zonelists(void *data)
{
	int nid;
	int __maybe_unused cpu;
	// 传进来的data是NULL
	pg_data_t *self = data;

	// 这个锁是static的，所以对所有调用__build_all_zonelists的
	// 地方都进行串行
	static DEFINE_SPINLOCK(lock);

	spin_lock(&lock);

#ifdef CONFIG_NUMA
	// 设置所有node未加载
	memset(node_load, 0, sizeof(node_load));
#endif

	if (self && !node_online(self->node_id)) {
		// 这个是热插拔的路径，暂时不看
		build_zonelists(self);
	} else {
		// 在启动期间走这个路径，遍历所有node
		// 初始化每个node上面的域表
		for_each_online_node(nid) {
			pg_data_t *pgdat = NODE_DATA(nid);

			build_zonelists(pgdat);
		}

#ifdef CONFIG_HAVE_MEMORYLESS_NODES
		// 这个配置只有ia64和powerpc才有，暂时不看
		for_each_online_cpu(cpu)
			set_cpu_numa_mem(cpu, local_memory_node(cpu_to_node(cpu)));
#endif
	}

	spin_unlock(&lock);
}

static void build_zonelists(pg_data_t *pgdat)
{
	// 存放与本节点距离最近的node
	static int node_order[MAX_NUMNODES];
	int node, load, nr_nodes = 0;
	// NODE_MASK_NONE是每个node结点对应的位上都是0
	nodemask_t used_mask = NODE_MASK_NONE;
	int local_node, prev_node;

	// 在numa系统里，当前所在的node叫本地结点，其它numa叫远程结点
	local_node = pgdat->node_id;

	// 已经在线的node数量
	load = nr_online_nodes;

	// prev里保存的是
	prev_node = local_node;

	// 把node_order置空。todo: 既然每次都置空，为什么还要用static? 
	memset(node_order, 0, sizeof(node_order));
	// find_next_best_node:找一个最好的备用结点，首先找的是当前节点
	while ((node = find_next_best_node(local_node, &used_mask)) >= 0) {
		/*
		 * todo: 没看懂
		 * We don't want to pressure a particular node.
		 * So adding penalty to the first node in same
		 * distance group to make it round-robin.
		 */
		if (node_distance(local_node, node) !=
		    node_distance(local_node, prev_node))
			node_load[node] = load;

		// 设置node
		node_order[nr_nodes++] = node;
		prev_node = node;
		//todo: 这个负载是什么？
		load--;
	}

	// 经过上面的while循环，node_order里放的都是备用的结点

	// 设置ZONELIST_FALLBACK回退列表
	build_zonelists_in_node_order(pgdat, node_order, nr_nodes);
	// 这个函数初始化ZONELIST_NOFALLBACK类型的列表，这个列表是给__GFP_THISNODE
	// 标志用的。
	build_thisnode_zonelists(pgdat);
}

static int find_next_best_node(int node, nodemask_t *used_node_mask)
{
	int n, val;
	int min_val = INT_MAX;
	// NUMA_NO_NODE是-1
	int best_node = NUMA_NO_NODE;

	// 如果本地结点还没用，先用本地结点
	if (!node_isset(node, *used_node_mask)) {
		node_set(node, *used_node_mask);
		return node;
	}

	// 遍历具有N_MEMORY的状态，这个状态表示结点有可用内存
	for_each_node_state(n, N_MEMORY) {

		// 当前结点已经使用
		if (node_isset(n, *used_node_mask))
			continue;

		// 找到两个结点之间的距离。todo: 距离没太看懂
		val = node_distance(node, n);

		// 原注释：对前一个结点进行处罚，因为更希望下一个结点
		val += (n < node);

		// 如果node上没有cpu，也进行处罚
		if (!cpumask_empty(cpumask_of_node(n)))
			val += PENALTY_FOR_NODE_WITH_CPUS;

		// 再加上目标node的负载
		val *= (MAX_NODE_LOAD*MAX_NUMNODES);
		val += node_load[n];

		// 记录最合适的node，因为要选距离最近的
		if (val < min_val) {
			min_val = val;
			best_node = n;
		}
	}

	// 如果找到了一个node，就在掩码里设置
	if (best_node >= 0)
		node_set(best_node, *used_node_mask);

	return best_node;
}

#define node_distance(a, b) __node_distance(a, b)

int __node_distance(int from, int to)
{
	if (from >= numa_distance_cnt || to >= numa_distance_cnt)
		return from == to ? LOCAL_DISTANCE : REMOTE_DISTANCE;
	return numa_distance[from * numa_distance_cnt + to];
}

static void build_thisnode_zonelists(pg_data_t *pgdat)
{
	struct zoneref *zonerefs;
	int nr_zones;

	// 取出ZONELIST_NOFALLBACK列表
	zonerefs = pgdat->node_zonelists[ZONELIST_NOFALLBACK]._zonerefs;
	// ZONELIST_NOFALLBACK列表只设置成当前的node
	nr_zones = build_zonerefs_node(pgdat, zonerefs);
	zonerefs += nr_zones;
	// 把最后一个元素置空
	zonerefs->zone = NULL;
	zonerefs->zone_idx = 0;
}

static void build_zonelists_in_node_order(pg_data_t *pgdat, int *node_order,
		unsigned nr_nodes)
{
	struct zoneref *zonerefs;
	int i;

	zonerefs = pgdat->node_zonelists[ZONELIST_FALLBACK]._zonerefs;

	// 遍历所有node
	for (i = 0; i < nr_nodes; i++) {
		int nr_zones;

		pg_data_t *node = NODE_DATA(node_order[i]);

		// 设置zonerefs对应的回退列表为当前node，返回值是设置了多少个zone
		nr_zones = build_zonerefs_node(node, zonerefs);
		// 让zonerefs指针前进nr_zones，用来设置下一个node里的zone
		zonerefs += nr_zones;
	}

	// 把最后一个元素置空
	zonerefs->zone = NULL;
	zonerefs->zone_idx = 0;
}

static int build_zonerefs_node(pg_data_t *pgdat, struct zoneref *zonerefs)
{
	struct zone *zone;
	// type先设置成最大值
	enum zone_type zone_type = MAX_NR_ZONES;
	int nr_zones = 0;

	do {
		// 从高到低设置域
		zone_type--;
		// 获取对应域的列表
		zone = pgdat->node_zones + zone_type;
		// populated_zone返回当前可用页面数
		if (populated_zone(zone)) {
			// 设置对应位置为zone
			zoneref_set_zone(zone, &zonerefs[nr_zones++]);
			// todo: 没太看懂，policy zone相关的
			check_highest_zone(zone_type);
		}
	} while (zone_type);

	return nr_zones;
}

static void zoneref_set_zone(struct zone *zone, struct zoneref *zoneref)
{
	zoneref->zone = zone;
	// zone_idx返回zone的类型，ZONE_DMA，ZONE_NORMAL等
	zoneref->zone_idx = zone_idx(zone);
}
```