# slub-create
源码基于5.10.

slub的创建从kmem_cache_create->kmem_cache_create_usercopy和slab都是一样的，从__kmem_cache_create开始区分。

slub的创建，相对于slab来说要简单的多。

## __kmem_cache_create
```c
// __kmem_cache_create是个创建slab的核心函数，不光在初始化期间调用。在初始化完成后，创建普通的slab也会调用。
int __kmem_cache_create(struct kmem_cache *s, slab_flags_t flags)
{
	int err;

	// 创建kmem_cache
	err = kmem_cache_open(s, flags);
	if (err)
		return err;

	// sysfs在boot期间还没有准备好，所以直接返回。
	// slab_state在slab初始化的第2阶段才会被设为FULL，所以在初始化第一阶段，
	// 肯定是小于UP的
	if (slab_state <= UP)
		return 0;

	// 添加sysfs
	err = sysfs_slab_add(s);
	if (err)
		__kmem_cache_release(s);

	return err;
}

static int kmem_cache_open(struct kmem_cache *s, slab_flags_t flags)
{
	// 没打开CONFIG_SLUB_DEBUG时，这个直接返回flags
	s->flags = kmem_cache_flags(s->size, flags, s->name);

	// 初始化随机种子
#ifdef CONFIG_SLAB_FREELIST_HARDENED
	s->random = get_random_long();
#endif

	// 计算阶数和一个slub里对象的数量
	if (!calculate_sizes(s, -1))
		goto error;
	
	// 调试相关，这个一般是0
	if (disable_higher_order_debug) {
		/*
		 * Disable debugging flags that store metadata if the min slab
		 * order increased.
		 */
		if (get_order(s->size) > get_order(s->object_size)) {
			s->flags &= ~DEBUG_METADATA_FLAGS;
			s->offset = 0;
			if (!calculate_sizes(s, -1))
				goto error;
		}
	}

#if defined(CONFIG_HAVE_CMPXCHG_DOUBLE) && \
    defined(CONFIG_HAVE_ALIGNED_STRUCT_PAGE)
	// 原子交换double是否可用？
	if (system_has_cmpxchg_double() && (s->flags & SLAB_NO_CMPXCHG) == 0)
		/* Enable fast mode */
		s->flags |= __CMPXCHG_DOUBLE;
#endif

	//设置s->min_partial的数量，建议最小值为对象大小阶数的一半?
	// 这个函数会把值限制在[5,10]之间
	set_min_partial(s, ilog2(s->size) / 2);

	// 根据slab的大小设置s->cpu_partial的数量
	// 注意这个值和上面值的区别，这个是percpu，上面是针对整个cache
	set_cpu_partial(s);

#ifdef CONFIG_NUMA
	// 从远端分配的数量？
	s->remote_node_defrag_ratio = 1000;
#endif

	// 如果slab状态大于UP，则随机化序号数组
	// 大于UP，表示slub子系统已经初始化完成
	if (slab_state >= UP) {
		if (init_cache_random_seq(s))
			goto error;
	}

	// 初始化slub的node
	if (!init_kmem_cache_nodes(s))
		goto error;

	// 分配cpu_slab变量
	if (alloc_kmem_cache_cpus(s))
                // 分配cache成功，会返回0，也就是slub创建成功
		return 0;

error:
	__kmem_cache_release(s);
	return -EINVAL;
}

static void set_min_partial(struct kmem_cache *s, unsigned long min)
{
	// MIN_PARTIAL = 5
	if (min < MIN_PARTIAL)
		min = MIN_PARTIAL;

	// MAX_PARTIAL = 10
	else if (min > MAX_PARTIAL)
		min = MAX_PARTIAL;
	s->min_partial = min;
}

static void set_cpu_partial(struct kmem_cache *s)
{
#ifdef CONFIG_SLUB_CPU_PARTIAL
	/*
	 * cpu_partial决定了一个percpu partial列表里保存的最大数量的对象数
	 */
	// slub_set_cpu_partial是设置cpu_partial的值为第2个参数
	// kmem_cache_has_cpu_partial在debug打开时返回false，一般情况都返回true
	if (!kmem_cache_has_cpu_partial(s))
		slub_set_cpu_partial(s, 0);
	
	// 下面就根据slab的大小，设置cpu部分缓存的数量
	else if (s->size >= PAGE_SIZE)
		slub_set_cpu_partial(s, 2);
	else if (s->size >= 1024)
		slub_set_cpu_partial(s, 6);
	else if (s->size >= 256)
		slub_set_cpu_partial(s, 13);
	else
		slub_set_cpu_partial(s, 30);
#endif
}

static inline bool kmem_cache_has_cpu_partial(struct kmem_cache *s)
{
#ifdef CONFIG_SLUB_CPU_PARTIAL
	return !kmem_cache_debug(s);
#else
	return false;
#endif
}
```
__kmem_cache_create的主要调用了kmem_cache_open来创建应的slab.

kmem_cache_open的主流程如下：
1. 计算slab大小和一个slab里应该保存几个对象
2. 设置partial缓存的数量
3. 根据numa的数量，生成kmem_cache里的kmem_cache_node对象，并初始化它
4. 创建cpu_slab对象


## calculate_sizes
这个函数主要做的事就是计算order和offset
```c
static int calculate_sizes(struct kmem_cache *s, int forced_order)
{
	slab_flags_t flags = s->flags;
	// 对象大小
	unsigned int size = s->object_size;
	unsigned int order;
	
	// 对象大小对齐到指针值
	size = ALIGN(size, sizeof(void *));

#ifdef CONFIG_SLUB_DEBUG
	...
#endif

	// todo: what is inuse?
	s->inuse = size;

	// 计算offset，offset就是对象保存下一个空闲值的位置
	if ((flags & (SLAB_TYPESAFE_BY_RCU | SLAB_POISON)) ||
	    ((flags & SLAB_RED_ZONE) && s->object_size < sizeof(void *)) ||
	    s->ctor) {
                // 这个分支大多是调试相关，一般情况下很少走，除了有构造函数
                
                // 空闲对象的指针保存在对象的末尾
		s->offset = size;

		// 因为每个对象末尾加了一个指针，所以size要增加一个指针的大小
		size += sizeof(void *);
	} else {
		// 一般情况都走这里

		// 对象的空闲指针保存在对象中间，且以指针向下对齐
                // 原文注释：把空闲指针保存在这里，避免被其它slab越界覆盖
		s->offset = ALIGN_DOWN(s->object_size / 2, sizeof(void *));
	}

#ifdef CONFIG_SLUB_DEBUG
	...
#endif
        // kasan调试相关
	kasan_cache_create(s, &size, &s->flags);
#ifdef CONFIG_SLUB_DEBUG
	...
#endif

	// 对齐到align
	size = ALIGN(size, s->align);
	// 最终对象的大小，这个大小里包括填充
	s->size = size;
	// slab大小的倒数
	s->reciprocal_size = reciprocal_value(size);

        // 在创建的时候forced_order是－1
	if (forced_order >= 0)
		order = forced_order;
	else
		// 一般走这个分支，不会指定forced_order
		// 计算出合适的order
		order = calculate_order(size);

	// order小于0表示计算order失败
	if ((int)order < 0)
		return 0;

	// 下面是计算分配一个新slab页时使用的标志
	s->allocflags = 0;
        
        // __GFP_COMP表示地址里面混合了页的一些元数据
	if (order)
		s->allocflags |= __GFP_COMP;

	if (s->flags & SLAB_CACHE_DMA)
		s->allocflags |= GFP_DMA;

	if (s->flags & SLAB_CACHE_DMA32)
		s->allocflags |= GFP_DMA32;

	if (s->flags & SLAB_RECLAIM_ACCOUNT)
		s->allocflags |= __GFP_RECLAIMABLE;

	// oo_make是把order和一个slub存储的数量打包到一个值里
	s->oo = oo_make(order, size);

	// min表示保存一个对象的order，get_order最小值为0,也就是一页
	s->min = oo_make(get_order(size), size);

	// oo_objects是order存储对象的数量
	// 在创建的时候max是0，所以这个if总是成立的，max的值在slub运行期间也没用过，
	// max字段在最新的内核里已经删了
	if (oo_objects(s->oo) > oo_objects(s->max))
		s->max = s->oo;

	// 返回对象数量是否计算成功
	// !!是把一个数值转换成0或1
	return !!oo_objects(s->oo);
}

static inline int calculate_order(unsigned int size)
{
	unsigned int order;
	unsigned int min_objects;
	unsigned int max_objects;

	// slub_min_objects可以在命令行里配置，如果没配置时，为0
	min_objects = slub_min_objects;
	if (!min_objects)
		// 最小数量默认为cpu数量的4倍
		// fls是计算整数里第一个置位的位置
		min_objects = 4 * (fls(nr_cpu_ids) + 1);

	// slub_max_order可以在命令行指定，默认为3，也就是8个页
	// 计算出slub_max_order可以存储的对象数量
	max_objects = order_objects(slub_max_order, size);
	// 取2者较小值
	// 如果指定了最小数量，说不定比最大数量还大？
	min_objects = min(min_objects, max_objects);

        // 找到一个合适的order
	while (min_objects > 1) {
		unsigned int fraction;

		// 表示剩余空间可以为1/16大小
		fraction = 16;
		// fraction不能小于4，表示一个slub的浪费空间不能超过1/4
		while (fraction >= 4) {
			// 计算满足slab_size/fraction的order
			order = slab_order(size, min_objects,
					slub_max_order, fraction);
			// 如果没超过最大order，则这个order满足要求
			if (order <= slub_max_order)
				return order;
			// 如果没有合适的，则剩余空间减小2倍
			fraction /= 2;
		}
		// 如果没有合适的order，则减小最小对象的数量。
		// 没有合适的order说明对象比较大，这里要减小存储的数量
		min_objects--;
	}

	// 走到这儿还没算出order，就表示不能把多个对象放到一个slab里，说明对象比较大
	// 后面这2个情况都不常见

	// 这里尝试只把一个对象放到slab里，最后一个参数传1,表示可以容忍一倍的空间浪费
	order = slab_order(size, 1, slub_max_order, 1);
	if (order <= slub_max_order)
		return order;

	// 如果一页都放不下一个对象，就使用MAX_ORDER来计算
	// MAX_ORDER表示buddy系统能分配的最大页的order
	order = slab_order(size, 1, MAX_ORDER, 1);
	if (order < MAX_ORDER)
		return order;
	// 如果这样还不行，就出错了。
	return -ENOSYS;
}

// 计算order阶对应的页，能保存几个对象
static inline unsigned int order_objects(unsigned int order, unsigned int size)
{
	return ((unsigned int)PAGE_SIZE << order) / size;
}

// 计算一个合适的order，这个order要满足：一个slab要存储min_objects个对象，
// 空闲空间不能大于一个slub空间的1/fract_leftover，不能大于max_order
static inline unsigned int slab_order(unsigned int size,
		unsigned int min_objects, unsigned int max_order,
		unsigned int fract_leftover)
{
        // slub_min_order：没有在命令行指定时，是0，也就是一页
	unsigned int min_order = slub_min_order;
	unsigned int order;

	// order_objects是计算order可以存储size的数量，
	// MAX_OBJS_PER_PAGE是32767，每个slub可存储对象的数量，这个名字有点歧义，应该叫MAX_OBJS_PER_SLUB
	// 如果最小的order可以存储的对象数量都大于了每个slab可存储数量的最大值，那就使用最大对象数对应的order
	// todo: 为什么要做这个限制？
	if (order_objects(min_order, size) > MAX_OBJS_PER_PAGE)
                // get_order是计算size对应的阶
		return get_order(size * MAX_OBJS_PER_PAGE) - 1;

	// 从最小对象数对应的order和最小order的最小值开始遍历。
	for (order = max(min_order, (unsigned int)get_order(min_objects * size));
			order <= max_order; order++) {

		// slub的大小
		unsigned int slab_size = (unsigned int)PAGE_SIZE << order;
		unsigned int rem;

		// 不足一个对象的大小
		rem = slab_size % size;

		// 如果剩余的空间小于指定的值，则这个order合适
		if (rem <= slab_size / fract_leftover)
			break;
	}

	return order;
}

static inline struct kmem_cache_order_objects oo_make(unsigned int order,
		unsigned int size)
{
	// OO_SHIFT是16
	// kmem_cache_order_objects 是unsigned int
	// 把slub对应的order存在高16位，slub存储的对象的数量存在低16位
	struct kmem_cache_order_objects x = {
		(order << OO_SHIFT) + order_objects(order, size)
	};

	return x;
}
```
calculate_sizes主要做了这几件事：
1. 计算offset，offset是存储下一个空闲对象的指针的位置
2. 计算order，order是一个slab需要多少页
3. 计算oo，oo里面保存的是order及object数量的值

## 初始化percpu缓存
```c
static inline int alloc_kmem_cache_cpus(struct kmem_cache *s)
{
	BUILD_BUG_ON(PERCPU_DYNAMIC_EARLY_SIZE <
			KMALLOC_SHIFT_HIGH * sizeof(struct kmem_cache_cpu));

	// 分配percpu内存。第1个参数是大小，第2个是对齐
	s->cpu_slab = __alloc_percpu(sizeof(struct kmem_cache_cpu),
				     2 * sizeof(void *));

	if (!s->cpu_slab)
		return 0;

	// 分配每个cpu的tid值
	init_kmem_cache_cpus(s);

	return 1;
}

static void init_kmem_cache_cpus(struct kmem_cache *s)
{
	int cpu;

	for_each_possible_cpu(cpu)
		// init_tid返回的就是cpu的值
		per_cpu_ptr(s->cpu_slab, cpu)->tid = init_tid(cpu);
}
```