# slub初始化
slub的实现，源码基于5.10。  

## kmem_cache_init
这是初始化的入口。

```c
void __init kmem_cache_init(void)
{
	// 静态变量，解决了鸡与蛋的问题
	static __initdata struct kmem_cache boot_kmem_cache,
		boot_kmem_cache_node;

	// 调试相关
	if (debug_guardpage_minorder())
		slub_max_order = 0;

	// 初始化kmem_cache和kmem_cache_node，这是2个静态变量，全被初始化成0
	kmem_cache_node = &boot_kmem_cache_node;
	kmem_cache = &boot_kmem_cache;

	// 先创建kmem_cache_node的slab
	create_boot_cache(kmem_cache_node, "kmem_cache_node",
		sizeof(struct kmem_cache_node), SLAB_HWCACHE_ALIGN, 0, 0);

	// 注册内存热插拔回调
	register_hotmemory_notifier(&slab_memory_callback_nb);

	// kmem_cache_node已经初始化完成
	slab_state = PARTIAL;

	// 再创建kmem_cache的slab，每个kmem_cache里对象大小是：
	// struct kmem_cache的大小 + kmem_cache_node数组的长度
	create_boot_cache(kmem_cache, "kmem_cache",
			offsetof(struct kmem_cache, node) +
				nr_node_ids * sizeof(struct kmem_cache_node *),
		       SLAB_HWCACHE_ALIGN, 0, 0);

	// bootstrap从kmem_cache里分配新对象，再把原来的静态对象的值复制进去
	// 相当于替换原来的静态对象
	kmem_cache = bootstrap(&boot_kmem_cache);
	kmem_cache_node = bootstrap(&boot_kmem_cache_node);

	// 初始化size_index表
	setup_kmalloc_cache_index_table();
	// 初始化所有的kmalloc-size slab，这个函数执行完后，slab_state就是UP了
	create_kmalloc_caches(0);

	// 初始化所有slab的随机化
	init_freelist_randomization();

	// 注册cpu热插拔事件，这里注册的是dead事件
	cpuhp_setup_state_nocalls(CPUHP_SLUB_DEAD, "slub:dead", NULL,
				  slub_cpu_dead);

	pr_info("SLUB: HWalign=%d, Order=%u-%u, MinObjects=%u, CPUs=%u, Nodes=%u\n",
		cache_line_size(),
		slub_min_order, slub_max_order, slub_min_objects,
		nr_cpu_ids, nr_node_ids);
}
```
在初始化时，先用2个静态变量boot_kmem_cache, boot_kmem_cache_node做引子，把kmem_cache和kmem_cache_node这2个slab先初始化，这就解决了鸡与蛋的问题。在后面把kmem_cache初始化完了之后，再用kmem_cache的slab分配2个struct kmem_cache对象，用这2个动态分配的对象替换boot_kmem_cache, boot_kmem_cache_node对象。

kmem_cache_init主要工作如下：
1. 创建kmem_cache_node slab缓存
2. 创建kmem_cache slab缓存
3. 初始化kmalloc-size slab缓存
4. 注册一些hotplug相关的内存，cpu事件
5. 做slab随机化

## create_boot_cache
这是创建kmem_cache_node, kmem_cache的共用函数，也是在初始化期间创建kmalloc-size相关slab的通用函数。
```c
void __init create_boot_cache(struct kmem_cache *s, const char *name,
		unsigned int size, slab_flags_t flags,
		unsigned int useroffset, unsigned int usersize)
{
	int err;
	// ARCH_KMALLOC_MINALIGN没定义时，默认是__alignof__(unsigned long long)
	// unsigned long long是8字节
	unsigned int align = ARCH_KMALLOC_MINALIGN;

	// 名称
	s->name = name;

	// 先把对象大小设成一样。这两个大小一般情况下都是一样的，除非打开调试时，size会加上调试相关的东西
	s->size = s->object_size = size;

	// 如果对象大小是2的幂，并且大于最小的对齐值时，可以用obj的大小来做对齐
	if (is_power_of_2(size))
		align = max(align, size);
	// 计算最终对齐的值，这个函数和slab共用
	s->align = calculate_alignment(flags, align, size);

	// todo: useroffset/size是什么？
	s->useroffset = useroffset;
	s->usersize = usersize;

	// 真正的创建cache
	err = __kmem_cache_create(s, flags);

	// 如果在初始化期间创建slab失败，就直接panic
	if (err)
		panic("Creation of kmalloc slab %s size=%u failed. Reason %d\n",
					name, size, err);

	// todo: 这里的refcount为什么设成-1
	s->refcount = -1;	/* Exempt from merging for now */
}

```

## init_kmem_cache_nodes
init_kmem_cache_nodes的主要任务是遍历所有node结点，然后创建对应的kmem_cache_node.
```c
static int init_kmem_cache_nodes(struct kmem_cache *s)
{
	int node;

	// 遍历正常的内存结点
	for_each_node_state(node, N_NORMAL_MEMORY) {
		struct kmem_cache_node *n;

		// 早期的slub初始化，初始化kmem_cache_node时，走这个分支，
		// slab_state == DOWN只能是初始化kmem_cache_node，这时kmem_cache_node还不能用，
		// 所以要手动分配kmem_cache_node缓存里对应的slab
		if (slab_state == DOWN) {
			early_kmem_cache_node_alloc(node);
			continue;
		}
		// 其它情况直接分配node对象
		n = kmem_cache_alloc_node(kmem_cache_node,
						GFP_KERNEL, node);

		if (!n) {
			free_kmem_cache_nodes(s);
			return 0;
		}

		// 初始化node
		init_kmem_cache_node(n);
		// 加到缓存的node数组
		s->node[node] = n;
	}
	return 1;
}

// 早期初始化
static void early_kmem_cache_node_alloc(int node)
{
	struct page *page;
	struct kmem_cache_node *n;

	// kmem_cache_node的大小怎么会小于它
	BUG_ON(kmem_cache_node->size < sizeof(struct kmem_cache_node));

	// 分配一个slab，其实就是分配对应数量的页
	page = new_slab(kmem_cache_node, GFP_NOWAIT, node);

	// early时，如果分配失败，就直接crash了
	BUG_ON(!page);

	// 和希望分配的node不一样，但是在初始化阶段还是要继续
	if (page_to_nid(page) != node) {
		pr_err("SLUB: Unable to allocate memory from node %d\n", node);
		pr_err("SLUB: Allocating a useless per node structure in order to be able to continue\n");
	}

	// 取出第1个对象
	n = page->freelist;
	// early时空闲列表肯定不能分配失败
	BUG_ON(!n);
#ifdef CONFIG_SLUB_DEBUG
	init_object(kmem_cache_node, n, SLUB_RED_ACTIVE);
	init_tracking(kmem_cache_node, n);
#endif
	// kasan没打开时，直接返回n
	n = kasan_kmalloc(kmem_cache_node, n, sizeof(struct kmem_cache_node),
		      GFP_KERNEL);
	// get_freepointer里把n的值还加上了kmem_cache_node->offset，
	// 设置空闲列表为n的下一个值，因为n要用做node
	page->freelist = get_freepointer(kmem_cache_node, n);
	// 在使用的对象有1个
	page->inuse = 1;
	// 没冻结。todo: 冻结是干什么的？
	page->frozen = 0;
	// 把n做为node对应的结构设置到kmem_cache_node里。
	kmem_cache_node->node[node] = n;
	// 对n里面的数据做一些基本初始化
	init_kmem_cache_node(n);
	// 没打开调试时，这是个空语句。递增slab数量和对象数量
	inc_slabs_node(kmem_cache_node, node, page->objects);

	// 把page加到node的部分列表里，
	// 最后一个参数是决定是否要加到末尾，这里是要加到头
	__add_partial(n, page, DEACTIVATE_TO_HEAD);
}

static void
init_kmem_cache_node(struct kmem_cache_node *n)
{
	// 一些变量的基本初始化
	n->nr_partial = 0;
	spin_lock_init(&n->list_lock);
	INIT_LIST_HEAD(&n->partial);
#ifdef CONFIG_SLUB_DEBUG
	atomic_long_set(&n->nr_slabs, 0);
	atomic_long_set(&n->total_objects, 0);
	INIT_LIST_HEAD(&n->full);
#endif
}

static inline void
__add_partial(struct kmem_cache_node *n, struct page *page, int tail)
{
	// slub的cache_node比较简单，只有这2个元素


	// nr_partial: 列表的统计计数
	n->nr_partial++;

	// 加到末尾，或加到头
	if (tail == DEACTIVATE_TO_TAIL)
		list_add_tail(&page->slab_list, &n->partial);
	else
		list_add(&page->slab_list, &n->partial);
}
```
init_kmem_cache_nodes里面主要有2个流程：
1. 早期的初始化，也就是在状态<=DOWN时的初始化，这时主要初始化kmem_cache_node slab。在这里直接分配了一个slab缓存，提前做好初始化，因为在下面创建kmalloc-size的slab里要用到kmem_cache_node。
2. 一般的初始化，在状态>DOWN时，表示kmem_cache_node已经初始化好了，这时就直接从kmem_cache_node里分配一个kmem_cache_node对象，添加到对应slab的node数组。

## bootstrap
bootstrap是替换早期初始化时使用的静态变量。
```c
static struct kmem_cache * __init bootstrap(struct kmem_cache *static_cache)
{
	int node;
	// 分配一个新对象
	struct kmem_cache *s = kmem_cache_zalloc(kmem_cache, GFP_NOWAIT);
	struct kmem_cache_node *n;

	// 把静态对象复制到新对象里
	memcpy(s, static_cache, kmem_cache->object_size);

	// 释放当前的cpu slab
	__flush_cpu_slab(s, smp_processor_id());

	// 遍历每个node节点，设置每个slub的slab_cache指针到新对象
	for_each_kmem_cache_node(s, node, n) {
		struct page *p;

		list_for_each_entry(p, &n->partial, slab_list)
			p->slab_cache = s;

#ifdef CONFIG_SLUB_DEBUG
		list_for_each_entry(p, &n->full, slab_list)
			p->slab_cache = s;
#endif
	}
	// 添加到slab列表里
	list_add(&s->list, &slab_caches);
	return s;
}

static inline void __flush_cpu_slab(struct kmem_cache *s, int cpu)
{
	// 取出本cpu的slab
	struct kmem_cache_cpu *c = per_cpu_ptr(s->cpu_slab, cpu);

	// 有正在分配的页，就释放该slab
	if (c->page)
		flush_slab(s, c);
	// 解冻所有部分缓存
	unfreeze_partials(s, c);
}
```

## init_freelist_randomization
随机化空闲列表
```c
static void __init init_freelist_randomization(void)
{
	struct kmem_cache *s;

	mutex_lock(&slab_mutex);

	// 创建每个slab的随机数组
	list_for_each_entry(s, &slab_caches, list)
		init_cache_random_seq(s);

	mutex_unlock(&slab_mutex);
}

static int init_cache_random_seq(struct kmem_cache *s)
{
	// slab里的对象数
	unsigned int count = oo_objects(s->oo);
	int err;

	// 如果已经初始化，则返回0
	if (s->random_seq)
		return 0;

	// 这个和slab一样，初始化随机数组
	err = cache_random_seq_create(s, count, GFP_KERNEL);
	if (err) {
		pr_err("SLUB: Unable to initialize free list for %s\n",
			s->name);
		return err;
	}

	if (s->random_seq) {
		unsigned int i;
		// 在每个随机值上又乘以对象大小, why?
		for (i = 0; i < count; i++)
			s->random_seq[i] *= s->size;
	}
	return 0;
}
```