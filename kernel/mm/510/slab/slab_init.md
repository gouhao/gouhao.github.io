# slab系统初始化
源码基于5.10

slab系统的初始化分为2部分：kmem_cache_init和kmem_cache_init_late。

## slab系统初始化第1部分
```c
// 这是静态分配的一个实例，解决‘先有鸡还是先有蛋’的问题
static struct kmem_cache kmem_cache_boot = {
	// 批量操作的数据量
	.batchcount = 1,
	// BOOT_CPUCACHE_ENTRIES是1
	.limit = BOOT_CPUCACHE_ENTRIES,
	// 可以共享1个
	.shared = 1,
	// 每个对象的大小
	.size = sizeof(struct kmem_cache),
	// 缓存名称
	.name = "kmem_cache",
};

// 这个函数由 mm_init 调用，是slab系统初始化的第一部分
void __init kmem_cache_init(void)
{
	int i;

	// 把静态分配的实例复制到kmem_cache
	kmem_cache = &kmem_cache_boot;

	//  如果不是numa或者只有一个cpu，就不用外面的缓存，
	if (!IS_ENABLED(CONFIG_NUMA) || num_possible_nodes() == 1)
		use_alien_caches = 0;

	/*
	 NUM_INIT_LISTS是2 * MAX_NUMNODES，这个MAX_NUMNODES是可以在
	 配置文件里配的，由CONFIG_NODES_SHIFT配置。
	 init_kmem_cache_node的数组，第0～MAX_NUMNODES是给
	 CACHE_CACHE（slab对象自身的cache）用的，
	 MAX_NUMNODES ~  2 * MAX_NUMNODES是给kmalloc-SIZE_NODE用的
	*/
	for (i = 0; i < NUM_INIT_LISTS; i++)
		// init_kmem_cache_node是struct kmem_cache_node类型

		// 初始化每个node对象，这里面只是对对象做了基本的数据初始化，
		// 如：初始化链表关，初始化锁等
		kmem_cache_node_init(&init_kmem_cache_node[i]);

	// slab_max_order可以从命令行设置，
	// ！slab_max_order_set表示slab_max_order还没有设置，
	// 如果没设置，当内存里的页数>32M时，设置slab_max_order为1, todo: why?
	// SLAB_MAX_ORDER_HI是1
	if (!slab_max_order_set && totalram_pages() > (32 << 20) >> PAGE_SHIFT)
		slab_max_order = SLAB_MAX_ORDER_HI;

	// 创建根kmem_cache，这个slab是缓存slab的头
	// offsetof(struct kmem_cache, node) + nr_node_ids * sizeof(struct kmem_cache_node *)`算出来的就是一个kmem_cache结构的总长度，
	// 因为kmem_cache缓存里放的也是kmem_cache本身，所以算出的大小就是slab缓存里对象的大小。
	create_boot_cache(kmem_cache, "kmem_cache",
		// 因为kmem_cache->node是一个可变数组，所以要动态计算它的长度
		offsetof(struct kmem_cache, node) +
				// 这个大小是每个node都有一个struct kmem_cache_node
				  nr_node_ids * sizeof(struct kmem_cache_node *),
				  // 缓存行对齐
				  SLAB_HWCACHE_ALIGN, 0, 0);

	// 把kmem_cache加到slab_caches链表，这是系统里初始化的第1个slab
	list_add(&kmem_cache->list, &slab_caches);

	/*
	// 这是slab的状态，一个4个：
	DOWN // slab功能不可用
	PARTIAL, //kmem_cache可用
	PARTIAL_NODE, // kmalloc-sizeof(struct kmem_cache_node)的大小可用
	UP, // kmalloc array可以用了，也就是kmalloc函数可以用了
	FULL // 功能全部可用，这一阶段之后，percpu-cache使能
	*/
	slab_state = PARTIAL;

	/* 
	kmalloc_caches的定义：

	缓存的类型，每个kmalloc-size都有这3个类型
	enum kmalloc_cache_type {
		KMALLOC_NORMAL = 0, // 一般缓存是这个
		KMALLOC_RECLAIM, // 回收
	#ifdef CONFIG_ZONE_DMA
		KMALLOC_DMA,	// DMA
	#endif
		NR_KMALLOC_TYPES
	};

	KMALLOC_SHIFT_HIGH最大是25，也就是32M,
	MAX_ORDER是buddy分配最大物理页的阶数，如果没有在config里指定，默认是11.
	PAGE_SHIFT是页大小
	#define KMALLOC_SHIFT_HIGH	((MAX_ORDER + PAGE_SHIFT - 1) <= 25 ? \
			(MAX_ORDER + PAGE_SHIFT - 1) : 25)

	extern struct kmem_cache * kmalloc_caches[NR_KMALLOC_TYPES][KMALLOC_SHIFT_HIGH + 1];

	kmalloc_caches是一个缓存数组，第一个下标是缓存的类型，一般用NORMAL比较多，第2个下标是大小，最大是25，也就是 1<<25=32M.就是我们平时使用的kmalloc对应的各个slab缓存
	
	假设页大小是4K,则PAGE_SHIFT是12，那KMALLOC_SHIFT_HIGH就是 11+12-1=22，也就是4M.当页大小为4K时,kmalloc最大支持4M的缓存
	*/

	/*
	kmalloc_info的定义：

	extern const struct kmalloc_info_struct {
		const char *name[NR_KMALLOC_TYPES]; // 3种类型的名字
		unsigned int size;
	} kmalloc_info[];

	#define INIT_KMALLOC_INFO(__size, __short_size)			\
	{								\
		// 先初始化3个名字。原来c语言还可以这样初始化数组，长见识了。。。
		.name[KMALLOC_NORMAL]  = "kmalloc-" #__short_size,	\
		.name[KMALLOC_RECLAIM] = "kmalloc-rcl-" #__short_size,	\
		.name[KMALLOC_DMA]     = "dma-kmalloc-" #__short_size,	\
		// 最后初始化大小
		.size = __size,						\
	}
	这个数组的下标是通过kmalloc_index来获取的，不是按由小到大排序的。
	todo: 为什么这么排序
	const struct kmalloc_info_struct kmalloc_info[] __initconst = {
		INIT_KMALLOC_INFO(0, 0),
		INIT_KMALLOC_INFO(96, 96),
		INIT_KMALLOC_INFO(192, 192),
		...
	};
	*/

	// 创建第2个cache，第2个cache是kmalloc-SIZENODE，这里的size是struct kmem_cache_node的大小
	// KMALLOC_NORMAL=0, INDEX_NODE＝kmalloc_index(sizeof(struct kmem_cache_node))
	// 这个就是创建kmem_cache_node大小的kmalloc，因为下面要用kmem_cache_node，
	// 所以先把它创建出来，这里面分配slab是在kmem_cache上分配，因为上面已经把kmem_cache初始化
	// 好了，所以这里可以从kmem_cache里分配kmalloc-SIZENODE所需的slab头
	kmalloc_caches[KMALLOC_NORMAL][INDEX_NODE] = create_kmalloc_cache(
				kmalloc_info[INDEX_NODE].name[KMALLOC_NORMAL],
				kmalloc_info[INDEX_NODE].size,
				ARCH_KMALLOC_FLAGS, 0,
				// todo: 这里usersize传的是index_node对应的size
				kmalloc_info[INDEX_NODE].size);
	// kmalloc-SIZENODE可用了
	slab_state = PARTIAL_NODE;

	// 初始化size_index数组。size_index是对 <= 192字节的kmalloc-size所在kmalloc_caches序号的
	// 一个快速查找表。kmalloc_caches数组并不是按内存大小对各个kmem_cache进行排序
	setup_kmalloc_cache_index_table();

	// 早期初始化结束？
	// 在510代码里这个变量已经没有人在用，是不是可以删掉了！！
	slab_early_init = 0;

	// 初始化kmem_cache和kmalloc-SIZENODE对应的各个node节点
	{
		int nid;

		// 遍历在线node
		for_each_online_node(nid) {
			// init_list会重新调用kmalloc分配一个kmem_cache_node对象，再把init_kmem_cache_node里对应节点的复制过去，再设置各个cachep的node对象

			// 初始化每个节点的kmem_cache的node结点。
			init_list(kmem_cache, &init_kmem_cache_node[CACHE_CACHE + nid], nid);

			// 初始kmalloc_caches[KMALLOC_NORMAL][INDEX_NODE]对象的各node结点
			init_list(kmalloc_caches[KMALLOC_NORMAL][INDEX_NODE],
					  &init_kmem_cache_node[SIZE_NODE + nid], nid);
		}
	}

	// 初始化其它kmalloc size
	create_kmalloc_caches(ARCH_KMALLOC_FLAGS);
}

static void kmem_cache_node_init(struct kmem_cache_node *parent)
{
	// 初始化3个链表头
	// slab里的对象已全部使用
	INIT_LIST_HEAD(&parent->slabs_full);
	// slab里的对象部分使用
	INIT_LIST_HEAD(&parent->slabs_partial);
	// slab里的对象全部空闲
	INIT_LIST_HEAD(&parent->slabs_free);
	// slab总数
	parent->total_slabs = 0;
	// 空闲slab数
	parent->free_slabs = 0;
	// todo: 共享数量？
	parent->shared = NULL;
	// todo: 从外部获取的数量？
	parent->alien = NULL;
	// 下一个着色的值
	parent->colour_next = 0;
	// 保护上面3个list的锁
	spin_lock_init(&parent->list_lock);
	// 空闲对象为0
	parent->free_objects = 0;
	// 从空闲列表上分配一个slab时，这个值被置1
	parent->free_touched = 0;
}

static void __init init_list(struct kmem_cache *cachep, struct kmem_cache_node *list,
				int nodeid)
{
	struct kmem_cache_node *ptr;

	// 分配一个node，kmalloc是在kmalloc-size上分配
	ptr = kmalloc_node(sizeof(struct kmem_cache_node), GFP_NOWAIT, nodeid);
	BUG_ON(!ptr);

	// 把list数据直接复制过来
	memcpy(ptr, list, sizeof(struct kmem_cache_node));
	// 初始化锁
	spin_lock_init(&ptr->list_lock);

	// 初始化新slab的full, partial, free链表
	MAKE_ALL_LISTS(cachep, ptr, nodeid);
	// 设置到cachep里。
	cachep->node[nodeid] = ptr;
}

void __init setup_kmalloc_cache_index_table(void)
{
	unsigned int i;

	// 在slab时KMALLOC_MIN_SIZE是1<<5=32
	BUILD_BUG_ON(KMALLOC_MIN_SIZE > 256 ||
		(KMALLOC_MIN_SIZE & (KMALLOC_MIN_SIZE - 1)));

	// KMALLOC_MIN_SIZE对应在kmalloc-size的shift就是KMALLOC_SHIFT_LOW,
	// 所以小于它大小的都按最小size分。也就是最小分配32字节？
	for (i = 8; i < KMALLOC_MIN_SIZE; i += 8) {
		// 取出i对应的index
		unsigned int elem = size_index_elem(i);

		// 判断index是否越界
		if (elem >= ARRAY_SIZE(size_index))
			break;
		size_index[elem] = KMALLOC_SHIFT_LOW;
	}

	// todo: 下面没太看懂
	if (KMALLOC_MIN_SIZE >= 64) {
		// 这里最大可以对齐到64byte，所以要把96的分配到7，7是128byte
		for (i = 64 + 8; i <= 96; i += 8)
			size_index[size_index_elem(i)] = 7;

	}

	if (KMALLOC_MIN_SIZE >= 128) {
		// 这里同上，如果对齐到128时，把小于192的分到8,8是256
		for (i = 128 + 8; i <= 192; i += 8)
			size_index[size_index_elem(i)] = 8;
	}
}

static inline unsigned int size_index_elem(unsigned int bytes)
{
	// 向下以8对齐
	return (bytes - 1) / 8;
}
```

kmem_cache_init是slab系统初始化第一阶段的主函数，主要做了下面这些事：
1. 初始化kmem_cache，它本身也是一个slab缓存。它的slab里保存的结构也是struct kmem_cache，主要是为了给其它slab缓存的结构提供缓存。为了解决‘鸡与蛋‘的问题，kmem_cache是一个静态结构。

2. 初始化kmalloc-INODESIZE，这是kmalloc-size中的一个缓存。其slab对象的大小是sizeof(struct kmem_cache_node)，因为在初始化过程中，要分配这些对象。

3. 初始化其它kmalloc-size的slab对象。这个数组里保存了一些不同大小的slab缓存。

## create_boot_cache
```c
void __init create_boot_cache(struct kmem_cache *s, const char *name,
		unsigned int size, slab_flags_t flags,
		unsigned int useroffset, unsigned int usersize)
{
	int err;
	// ARCH_KMALLOC_MINALIGN没定义时，默认是__alignof__(unsigned long long)
	// unsigned long long是8字节
	unsigned int align = ARCH_KMALLOC_MINALIGN;

	s->name = name;

	// size和object_size都是对象大小，
	// object_size是对象的原始大小，包含了对齐用的padding
	// size是对象的最终大小，因为有可能打开debug选项，在padding的基础上给对象再填充，比如：redzone,poison
	// 没开启调试时，这2个值是相等的
	s->size = s->object_size = size;

	// 如果对象大小是2的幂，并且大于最小的对齐值时，用obj的大小来做对齐
	if (is_power_of_2(size))
		align = max(align, size);
	// 计算最终对齐的值
	s->align = calculate_alignment(flags, align, size);

	// todo: useroffset/size是什么？
	s->useroffset = useroffset;
	s->usersize = usersize;

	// 真正的创建cache，详见slab_create
	err = __kmem_cache_create(s, flags);

	if (err)
		panic("Creation of kmalloc slab %s size=%u failed. Reason %d\n",
					name, size, err);

	// todo: 这里的refcount为什么设成-1
	s->refcount = -1;	/* Exempt from merging for now */
}

static unsigned int calculate_alignment(slab_flags_t flags,
		unsigned int align, unsigned int size)
{
	// 硬件缓存对齐
	if (flags & SLAB_HWCACHE_ALIGN) {
		unsigned int ralign;

		// 缓存行大小
		ralign = cache_line_size();
		// 算出size在缓存行内占的最少大小，ralign是2的幂
		while (size <= ralign / 2)
			ralign /= 2;
		// 取对齐值较大的值
		align = max(align, ralign);
	}

	// 不能小于架构规定的最小对齐值，x86上ARCH_SLAB_MINALIGN 64 字节
	if (align < ARCH_SLAB_MINALIGN)
		align = ARCH_SLAB_MINALIGN;

	// 最终还要和指针的大小对齐
	return ALIGN(align, sizeof(void *));
}


```

## 情景2：kmalloc-INDEX_NODE的初始化

### 初始化的入口
```c
kmalloc_caches[KMALLOC_NORMAL][INDEX_NODE] = create_kmalloc_cache(
				kmalloc_info[INDEX_NODE].name[KMALLOC_NORMAL],
				kmalloc_info[INDEX_NODE].size,
				ARCH_KMALLOC_FLAGS, 0,
				// todo: 这里usersize传的是index_node对应的size
				kmalloc_info[INDEX_NODE].size);

// INDEX_NODE的计数如下：

// struct kmem_cache_node是112个字节
#define INDEX_NODE kmalloc_index(sizeof(struct kmem_cache_node))

// 假设size就是112
static __always_inline unsigned int kmalloc_index(size_t size)
{
	if (!size)
		return 0;
	// KMALLOC_MIN_SIZE是32
	if (size <= KMALLOC_MIN_SIZE)
		return KMALLOC_SHIFT_LOW;

	if (KMALLOC_MIN_SIZE <= 32 && size > 64 && size <= 96)
		return 1;
	if (KMALLOC_MIN_SIZE <= 64 && size > 128 && size <= 192)
		return 2;
	
	// 上面4个条件都不符合
	if (size <=          8) return 3;
	if (size <=         16) return 4;
	if (size <=         32) return 5;
	if (size <=         64) return 6;

	// 在这里会返回，所以INDEX_NODE的值是7
	if (size <=        128) return 7;
	if (size <=        256) return 8;
	if (size <=        512) return 9;
	if (size <=       1024) return 10;
	if (size <=   2 * 1024) return 11;
	if (size <=   4 * 1024) return 12;
	if (size <=   8 * 1024) return 13;
	if (size <=  16 * 1024) return 14;
	if (size <=  32 * 1024) return 15;
	if (size <=  64 * 1024) return 16;
	if (size <= 128 * 1024) return 17;
	if (size <= 256 * 1024) return 18;
	if (size <= 512 * 1024) return 19;
	if (size <= 1024 * 1024) return 20;
	if (size <=  2 * 1024 * 1024) return 21;
	if (size <=  4 * 1024 * 1024) return 22;
	if (size <=  8 * 1024 * 1024) return 23;
	if (size <=  16 * 1024 * 1024) return 24;
	if (size <=  32 * 1024 * 1024) return 25;
	if (size <=  64 * 1024 * 1024) return 26;
	BUG();

	/* Will never be reached. Needed because the compiler may complain */
	return -1;
}

kmalloc_info[7] = INIT_KMALLOC_INFO(128, 128)

#define INIT_KMALLOC_INFO(__size, __short_size)			\
	{								\
		// 先初始化3个名字。原来c语言还可以这样初始化数组，长见识了。。。
		.name[KMALLOC_NORMAL]  = "kmalloc-" #__short_size,	\
		.name[KMALLOC_RECLAIM] = "kmalloc-rcl-" #__short_size,	\
		.name[KMALLOC_DMA]     = "dma-kmalloc-" #__short_size,	\
		// 最后初始化大小
		.size = __size,						\
	}
kmalloc_info[7] = {
	.name[KMALLOC_NORMAL]  = "kmalloc-128",
	.name[KMALLOC_RECLAIM] = "kmalloc-rcl-128",
	.name[KMALLOC_DMA]     = "dma-kmalloc-128",
	.size = 128
}

// KMALLOC_NORMAL是0，最终的入口展开的如下：
kmalloc_caches[0][7] = create_kmalloc_cache(
				"kmalloc-128",
				128,
				ARCH_KMALLOC_FLAGS, 0,
				128);

struct kmem_cache *__init create_kmalloc_cache(const char *name,
		unsigned int size, slab_flags_t flags,
		unsigned int useroffset, unsigned int usersize)
{
	// 从kmem_cache分配一个对象
	struct kmem_cache *s = kmem_cache_zalloc(kmem_cache, GFP_NOWAIT);

	if (!s)
		panic("Out of memory when creating slab %s\n", name);

	// 创建缓存
	create_boot_cache(s, name, size, flags, useroffset, usersize);
	// 把kmalloc slab加到链表缓存里
	list_add(&s->list, &slab_caches);
	// 引用计数为1
	s->refcount = 1;
	return s;
}
```
创建kmalloc_cache和创建kmem_cache的流程差不多，区别在于kmem_cache是从kmem_cache_boot对象复制而来，kmem_cache_boot是个静态对象。而kmalloc_cache对象是从kmem_cache这个slab里分配的，这就解决了“先有鸡先有蛋”的问题。所以最终都会调到create_boot_cache里，这个流程已经在kmem_cache里介绍过，所以不再赘述。

## 情景3：创建其它kmalloc-size
```c
void __init create_kmalloc_caches(slab_flags_t flags)
{
	int i;
	enum kmalloc_cache_type type;

	// 这里只初始化normal和reclaim类型的kmalloc
	// 第一个循环遍历每个类型
	for (type = KMALLOC_NORMAL; type <= KMALLOC_RECLAIM; type++) {
		// 第二个循环遍历所有的大小
		for (i = KMALLOC_SHIFT_LOW; i <= KMALLOC_SHIFT_HIGH; i++) {
			// 如果还没有创建，则先创建对应的缓存
			if (!kmalloc_caches[type][i])
				new_kmalloc_cache(i, type, flags);

			// todo: 下面没太看懂
			/*
			 * Caches that are not of the two-to-the-power-of size.
			 * These have to be created immediately after the
			 * earlier power of two caches
			 */
			if (KMALLOC_MIN_SIZE <= 32 && i == 6 &&
					!kmalloc_caches[type][1])
				new_kmalloc_cache(1, type, flags);
			if (KMALLOC_MIN_SIZE <= 64 && i == 7 &&
					!kmalloc_caches[type][2])
				new_kmalloc_cache(2, type, flags);
		}
	}

	// kmalloc-size可用
	slab_state = UP;

	// 初始化dma使用的kmalloc-size
#ifdef CONFIG_ZONE_DMA
	for (i = 0; i <= KMALLOC_SHIFT_HIGH; i++) {
		struct kmem_cache *s = kmalloc_caches[KMALLOC_NORMAL][i];

		// 只有normal分配了，才分配dma。todo: why ?
		if (s) {
			kmalloc_caches[KMALLOC_DMA][i] = create_kmalloc_cache(
				kmalloc_info[i].name[KMALLOC_DMA],
				kmalloc_info[i].size,
				SLAB_CACHE_DMA | flags, 0,
				kmalloc_info[i].size);
		}
	}
#endif
}

static void __init
new_kmalloc_cache(int idx, enum kmalloc_cache_type type, slab_flags_t flags)
{
	if (type == KMALLOC_RECLAIM)
		flags |= SLAB_RECLAIM_ACCOUNT;

	// 这个和上面创建kmalloc-INDEX_NODE差不多，最终都会调到create_boot_cache里
	kmalloc_caches[type][idx] = create_kmalloc_cache(
					kmalloc_info[idx].name[type],
					kmalloc_info[idx].size, flags, 0,
					kmalloc_info[idx].size);
}
```

## slab系统初始化第2部分
在第一部分初始化结束以后，slab_state的状态是UP，表示大部分功能已经可用了，但是还没有完全初始化完，还有cpu_cache没初始化完。之所以要分成2部分初始化，是因为在初始化内核一些核心子系统时，他们可以也要使用slab，但是那时cpucache可能还不具备初始化的条件，所以分成2部分来初始化。cpucache是属于对分配的优化，所以可以放在后面来进行。
```c
// 这个函数在start_kernel里调用，会完成最后的slab初始化
void __init kmem_cache_init_late(void)
{
	struct kmem_cache *cachep;

	mutex_lock(&slab_mutex);
	// 遍历slab_caches里的所有的kmem_cache对象
	list_for_each_entry(cachep, &slab_caches, list)
		// 使能每个kmem_cache的cpucache
		if (enable_cpucache(cachep, GFP_NOWAIT))
			BUG();
	mutex_unlock(&slab_mutex);

	// slab已经完全初始化了
	slab_state = FULL;

#ifdef CONFIG_NUMA
	// 注册一个numa监听器，这个是支持mem上下线的，动态创建或销毁slab
	hotplug_memory_notifier(slab_memory_callback, SLAB_CALLBACK_PRI);
#endif

	/*
	 * The reap timers are started later, with a module init call: That part
	 * of the kernel is not yet operational.
	 */
}

static int __meminit slab_memory_callback(struct notifier_block *self,
					unsigned long action, void *arg)
{
	struct memory_notify *mnb = arg;
	int ret = 0;
	int nid;

	nid = mnb->status_change_nid;
	if (nid < 0)
		goto out;

	switch (action) {
	case MEM_GOING_ONLINE:
		// 内存将要上线，就创建一个cache node
		mutex_lock(&slab_mutex);
		ret = init_cache_node_node(nid);
		mutex_unlock(&slab_mutex);
		break;
	case MEM_GOING_OFFLINE:
		// 内存将要下线，就销毁一个cache node
		mutex_lock(&slab_mutex);
		ret = drain_cache_node_node(nid);
		mutex_unlock(&slab_mutex);
		break;
	case MEM_ONLINE:
	case MEM_OFFLINE:
	case MEM_CANCEL_ONLINE:
	case MEM_CANCEL_OFFLINE:
		break;
	}
out:
	return notifier_from_errno(ret);
}
```
