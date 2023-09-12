# slab create
源码基于5.10

```c
struct kmem_cache *
kmem_cache_create(const char *name, unsigned int size, unsigned int align,
		slab_flags_t flags, void (*ctor)(void *))
{
	return kmem_cache_create_usercopy(name, size, align, flags, 0, 0,
					  ctor);
}

struct kmem_cache *
kmem_cache_create_usercopy(const char *name,
		  unsigned int size, unsigned int align,
		  slab_flags_t flags,
		  unsigned int useroffset, unsigned int usersize,
		  void (*ctor)(void *))
{
	struct kmem_cache *s = NULL;
	const char *cache_name;
	int err;

	// 给cpu上锁
	get_online_cpus();
	// 给内存上锁
	get_online_mems();

	// 对slab的修改都要这个锁
	mutex_lock(&slab_mutex);

	// 调试相关，调试没开的时候返回0
	err = kmem_cache_sanity_check(name, size);
	if (err) {
		goto out_unlock;
	}

	// 有不允许的flag
	if (flags & ~SLAB_FLAGS_PERMITTED) {
		err = -EINVAL;
		goto out_unlock;
	}

	// 过滤flag
	flags &= CACHE_CREATE_MASK;

	// 对usersize和useroffset的处理。
	// todo: 这个后面再看
	if (WARN_ON(!usersize && useroffset) ||
	    WARN_ON(size < usersize || size - usersize < useroffset))
		usersize = useroffset = 0;

	// 一般的分配slab都走这个分支
	if (!usersize)
		// 先尝试与已有的slab做合并
		s = __kmem_cache_alias(name, size, align, flags, ctor);
	// 如果合并成功就直接退出
	if (s)
		goto out_unlock;

	// 走到这儿就是要重新分配一个slab了，一般情况都走这里

	// 复制名称
	cache_name = kstrdup_const(name, GFP_KERNEL);
	if (!cache_name) {
		err = -ENOMEM;
		goto out_unlock;
	}

	// 创建新的slab
	s = create_cache(cache_name, size, // 这个size是对象本身的大小
			 // 这个size是对齐之后的值
			 calculate_alignment(flags, align, size),
			 flags, useroffset, usersize, ctor, NULL);
	if (IS_ERR(s)) {
		err = PTR_ERR(s);
		kfree_const(cache_name);
	}

out_unlock:
	mutex_unlock(&slab_mutex);

	put_online_mems();
	put_online_cpus();

	if (err) {
		if (flags & SLAB_PANIC)
			panic("kmem_cache_create: Failed to create slab '%s'. Error %d\n",
				name, err);
		else {
			pr_warn("kmem_cache_create(%s) failed with error %d\n",
				name, err);
			dump_stack();
		}
		return NULL;
	}
	return s;
}
```

## __kmem_cache_alias
```c
struct kmem_cache *
__kmem_cache_alias(const char *name, unsigned int size, unsigned int align,
		   slab_flags_t flags, void (*ctor)(void *))
{
	struct kmem_cache *cachep;

	// 找一个可以合并的
	cachep = find_mergeable(size, align, flags, name, ctor);
	if (cachep) {
		// 找到了

		// 增加引用
		cachep->refcount++;

		// 修改原始对象的大小，使用较大的size
		cachep->object_size = max_t(int, cachep->object_size, size);
	}
	return cachep;
}

struct kmem_cache *find_mergeable(unsigned int size, unsigned int align,
		slab_flags_t flags, const char *name, void (*ctor)(void *))
{
	struct kmem_cache *s;

	// 没有打开merge特性
	if (slab_nomerge)
		return NULL;

	// 有构造函数
	if (ctor)
		return NULL;

	// 对齐到指针
	size = ALIGN(size, sizeof(void *));
	// 计算对齐值
	align = calculate_alignment(flags, align, size);
	// size再次对齐
	size = ALIGN(size, align);
	flags = kmem_cache_flags(size, flags, name);

	// 要创建的slab不允许合并
	if (flags & SLAB_NEVER_MERGE)
		return NULL;

	list_for_each_entry_reverse(s, &slab_caches, list) {
		// 现有slab不允许合并
		if (slab_unmergeable(s))
			continue;

		// 比现有slab大
		if (size > s->size)
			continue;

		// merge_same的值不同
		if ((flags & SLAB_MERGE_SAME) != (s->flags & SLAB_MERGE_SAME))
			continue;
		// 对齐值要兼容
		if ((s->size & ~(align - 1)) != s->size)
			continue;

		// todo: 大小相差不能超过一个指针，why?
		if (s->size - size >= sizeof(void *))
			continue;

		if (IS_ENABLED(CONFIG_SLAB) && align &&
			(align > s->align || s->align % align))
			continue;

		return s;
	}
	return NULL;
}
```

## create_cache
```c
static struct kmem_cache *create_cache(const char *name,
		unsigned int object_size, unsigned int align,
		slab_flags_t flags, unsigned int useroffset,
		unsigned int usersize, void (*ctor)(void *),
		struct kmem_cache *root_cache)
{
	struct kmem_cache *s;
	int err;

	if (WARN_ON(useroffset + usersize > object_size))
		useroffset = usersize = 0;

	err = -ENOMEM;
	// 分配一个kmem_cache结构。kmem_cache是kmem_cache结构的缓存 
	s = kmem_cache_zalloc(kmem_cache, GFP_KERNEL);
	if (!s)
		goto out;

	s->name = name;
	//这2个size一般都是相同的，只有在打开了调试选项之后，s->size才不同
	// object_size里是真实对象的大小
	s->size = s->object_size = object_size;
	s->align = align;
	s->ctor = ctor;
	s->useroffset = useroffset;
	s->usersize = usersize;

	// 真正的创建slab
	err = __kmem_cache_create(s, flags);
	if (err)
		goto out_free_cache;

	s->refcount = 1;

	// 加到全局的slab列表里
	list_add(&s->list, &slab_caches);
out:
	if (err)
		return ERR_PTR(err);
	return s;

out_free_cache:
	kmem_cache_free(kmem_cache, s);
	goto out;
}

// 下面函数里去除了debug相关的东西
int __kmem_cache_create(struct kmem_cache *cachep, slab_flags_t flags)
{
	// BYTES_PER_WORD: sizeof(void *)
	size_t ralign = BYTES_PER_WORD;
	gfp_t gfp;
	int err;
	// slab大小
	unsigned int size = cachep->size;

	// 对齐size到BYTES_PER_WORD，64位上是8字节
	size = ALIGN(size, BYTES_PER_WORD);

	// SLAB_RED_ZONE是调试用的，这个情景里flags只有SLAB_HWCACHE_ALIGN，所以这里不会走
	if (flags & SLAB_RED_ZONE) {
		ralign = REDZONE_ALIGN;
		/* If redzoning, ensure that the second redzone is suitably
		 * aligned, by adjusting the object size accordingly. */
		size = ALIGN(size, REDZONE_ALIGN);
	}

	// 对齐值始终取较大的
	if (ralign < cachep->align) {
		ralign = cachep->align;
	}
	// 在这个情景里，这个条件成立。todo: 这是什么意思？
	if (ralign > __alignof__(unsigned long long))
		flags &= ~(SLAB_RED_ZONE | SLAB_STORE_USER);
	// 保存最终的对齐值
	cachep->align = ralign;
	// 着色偏移单位缓存行大小
	cachep->colour_off = cache_line_size();
	// 着色偏移必须大于等于对齐值。否则，连第一个对象都对不齐
	if (cachep->colour_off < cachep->align)
		cachep->colour_off = cachep->align;

	if (slab_is_available())
		// 正常情况下走这个分支
		gfp = GFP_KERNEL;
	else
		// 初始化时，slab的状态还是DOWN，所以走这个分支，
		// GFP_NOWAIT就是__GFP_KSWAPD_RECLAIM，不能等待
		gfp = GFP_NOWAIT;

	// kasan没打开时这是空语句
	kasan_cache_create(cachep, &size, &flags);

	// 这里的size还要再跟align对齐，因为经过上面时cachep->align可能会变
	size = ALIGN(size, cachep->align);
	// SLAB_OBJ_MIN_SIZE是16, 如果size小于最小值，就要以最小值重新计算对齐
	if (FREELIST_BYTE_INDEX && size < SLAB_OBJ_MIN_SIZE)
		size = ALIGN(SLAB_OBJ_MIN_SIZE, cachep->align);

	// 下面这3个函数都是计算order, num和空闲列表应该存在哪, 只要一个设置成功就算成功

	// 先用slab里的对象保存freelist
	if (set_objfreelist_slab_cache(cachep, size, flags)) {
		flags |= CFLGS_OBJFREELIST_SLAB;
		goto done;
	}

	// 再尝试把freelist保存在外部
	if (set_off_slab_cache(cachep, size, flags)) {
		flags |= CFLGS_OFF_SLAB;
		goto done;
	}

	// 最后尝试在slab内存区来保存空闲列表
	if (set_on_slab_cache(cachep, size, flags))
		goto done;

	return -E2BIG;

done:
	// 空闲列表大小
	cachep->freelist_size = cachep->num * sizeof(freelist_idx_t);
	// slab标志
	cachep->flags = flags;
	// 根据flag设置分配标志，分配标志是在slab无可用时，重新分配页时，使用的标志
	cachep->allocflags = __GFP_COMP;

	// 根据slab的特点，确定分配新内存时的标志
	if (flags & SLAB_CACHE_DMA)
		cachep->allocflags |= GFP_DMA;
	if (flags & SLAB_CACHE_DMA32)
		cachep->allocflags |= GFP_DMA32;
	if (flags & SLAB_RECLAIM_ACCOUNT)
		cachep->allocflags |= __GFP_RECLAIMABLE;

	// 设置最终slab对象的大小
	cachep->size = size;
	// 算出size的倒数。这个方便算对象的坐标，把除法转换成乘法
	cachep->reciprocal_buffer_size = reciprocal_value(size);

	// 如果slab对象是在外面保存，记录分配空闲列表的那个cache对象
	if (OFF_SLAB(cachep)) {
		cachep->freelist_cache =
			kmalloc_slab(cachep->freelist_size, 0u);
	}
	// 这个主要设置percpu-cache里node的值，和对当前cpu上的node的初始化
	// 这个在和init里的流程一样，最终调用的是enable_cpucache
	err = setup_cpu_cache(cachep, gfp);
	if (err) {
		// todo: 为什么cpu缓存设置失败，就算创建失败，必须要有cpu_cache?
		__kmem_cache_release(cachep);
		return err;
	}

	return 0;
}

static bool set_objfreelist_slab_cache(struct kmem_cache *cachep,
			size_t size, slab_flags_t flags)
{
	size_t left;

	cachep->num = 0;

	// 判断是否需要上释放时重新初始化。
	// todo: 为什么对象要在释放时初始化，就不适合用objfreelist?
	if (unlikely(slab_want_init_on_free(cachep)))
		return false;

	// 有构造函数或者是rcu，也返回false。todo: why?
	if (cachep->ctor || flags & SLAB_TYPESAFE_BY_RCU)
		return false;

	// 走到这里一般是没有构造函数的

	// 计算每个slab里的对象数，和对应的order
	left = calculate_slab_order(cachep, size,
			flags | CFLGS_OBJFREELIST_SLAB);
	// slab的对象还是为0，说明不能用这个方式
	if (!cachep->num)
		return false;

	// cachep->num * sizeof(freelist_idx_t)是空闲列表的大小．
	// 因为空闲列表要保存在一个对象里，所以总长度肯定不能大于一个对象
	// 如果超过的对象的大小，就需要在外面保存
	if (cachep->num * sizeof(freelist_idx_t) > cachep->object_size)
		return false;

	// 走到这儿说明可以用这种方式

	// 算出共有几种着色方式
	// colour_off一般是缓存行大小，也是每个着色偏移的长度
	cachep->colour = left / cachep->colour_off;

	return true;
}

static size_t calculate_slab_order(struct kmem_cache *cachep,
				size_t size, slab_flags_t flags)
{
	size_t left_over = 0;
	int gfporder;
	// KMALLOC_SHIFT_MAX与配置有关，最大是25，也就是32M
	for (gfporder = 0; gfporder <= KMALLOC_MAX_ORDER; gfporder++) {
		unsigned int num;
		size_t remainder;

		// 计算当前order可以保存的对象数量和剩余的空间
		num = cache_estimate(gfporder, size, flags, &remainder);

		// 一个对象都保存不了？
		if (!num)
			continue;

		// #define SLAB_OBJ_MAX_NUM ((1 << sizeof(freelist_idx_t) * BITS_PER_BYTE) - 1)
		// freelist_idx_t一般情况下是char，所以上面宏展开就是：SLAB_OBJ_MAX_NUM=((1 << 1 * 8) - 1)=255
		// 所以slab最大的对象数一般是255
		if (num > SLAB_OBJ_MAX_NUM)
			break;

		// flags里有这个标志，表示用户强制把slab头保存到slab外部
		// 这个在初始化创建kmem_cache时，不可能走到这个分支，因为kmalloc-size还没有准备好
		if (flags & CFLGS_OFF_SLAB) {
			// CFLGS_OFF_SLAB时，需要在外部分配空闲列表，所以要判断当前
			// 分配freelist的cache是否合适
			struct kmem_cache *freelist_cache;
			size_t freelist_size;

			// freelist的总长度
			freelist_size = num * sizeof(freelist_idx_t);
			// 找到freelist_size对应的kmalloc-size的缓存对象
			freelist_cache = kmalloc_slab(freelist_size, 0u);
			// 如果没有这个对象肯定不行
			if (!freelist_cache)
				continue;

			/*
			 * 防止在cache_grow_begin时循环
			 */
			if (OFF_SLAB(freelist_cache))
				continue;

			// todo: 为啥分配freelist的对象的大小要大于cachep大小的一半
			if (freelist_cache->size > cachep->size / 2)
				continue;
		}

		// 先保存num和gfporder
		cachep->num = num;
		cachep->gfporder = gfporder;
		// 保存num个对象之后剩余的空间
		left_over = remainder;

		/*
		 * 原文注释:
		 * 一个vfs可回收的slab倾向于有大量可分配的GFP_NOFS，我们也不想去分配
		 * 太多的page，当我们不能回收dcache时。
		 */
		if (flags & SLAB_RECLAIM_ACCOUNT)
			break;

		// gfp太大了也不行
		if (gfporder >= slab_max_order)
			break;

		// 剩余空闲小于总空间的1/8就可以了
		if (left_over * 8 <= (PAGE_SIZE << gfporder))
			break;
	}
	return left_over;
}

static unsigned int cache_estimate(unsigned long gfporder, size_t buffer_size,
		slab_flags_t flags, size_t *left_over)
{
	unsigned int num;
	// order对应的slab的大小
	size_t slab_size = PAGE_SIZE << gfporder;

	if (flags & (CFLGS_OBJFREELIST_SLAB | CFLGS_OFF_SLAB)) {
		// 用slab对象保存空闲列表或者空闲列表在外保存

		// 可以存多少个对象
		num = slab_size / buffer_size;
		// 还剩多少空间
		*left_over = slab_size % buffer_size;
	} else {
		// freelist保存在slab本身

		// 除了对象本身外，每个对象还需要一个freelist_idx_t
		num = slab_size / (buffer_size + sizeof(freelist_idx_t));
		*left_over = slab_size %
			(buffer_size + sizeof(freelist_idx_t));
	}

	return num;
}

static inline bool slab_want_init_on_free(struct kmem_cache *c)
{
	// init_on_free由CONFIG_INIT_ON_FREE_DEFAULT_ON配置决定，如果没有打开这个配置就是false，
	// 或者在命令行指定init_on_free参数
	if (static_branch_unlikely(&init_on_free))
		// 在没有构造函数时，还需要这2个标志，才返回true
		return !(c->ctor ||
			 (c->flags & (SLAB_TYPESAFE_BY_RCU | SLAB_POISON)));
	return false;
}

static bool set_off_slab_cache(struct kmem_cache *cachep,
			size_t size, slab_flags_t flags)
{
	size_t left;

	cachep->num = 0;

	// 调试相关的选项
	if (flags & SLAB_NOLEAKTRACE)
		return false;

	// 用带CFLGS_OFF_SLAB来计算order，CFLGS_OFF_SLAB表示slab和管理数据不在slab内
	left = calculate_slab_order(cachep, size, flags | CFLGS_OFF_SLAB);
	if (!cachep->num)
		return false;

	// 剩余的空间如果大于空闲列表的长度，那肯定不能用这种方式，
	// 应该使用第3种方式，即把空闲列表保存存slab的末尾
	if (left >= cachep->num * sizeof(freelist_idx_t))
		return false;

	// 走到这儿说明可以用这种方式
	// 算出有几种着色方式
	cachep->colour = left / cachep->colour_off;

	return true;
}

static bool set_on_slab_cache(struct kmem_cache *cachep,
			size_t size, slab_flags_t flags)
{
	size_t left;

	cachep->num = 0;

	// 直接计算order
	left = calculate_slab_order(cachep, size, flags);
	if (!cachep->num)
		return false;

	// 计算颜色数量
	cachep->colour = left / cachep->colour_off;

	return true;
}

static int __ref setup_cpu_cache(struct kmem_cache *cachep, gfp_t gfp)
{
	// 这个条件表示slab已经初始化完了，则使能cpucache
	if (slab_state >= FULL)
		return enable_cpucache(cachep, gfp);

	// 走到这里表示slab还没有初始化完成？

	// 分配并初始化cpu_cache
	cachep->cpu_cache = alloc_kmem_cache_cpus(cachep, 1, 1);
	if (!cachep->cpu_cache)
		return 1;

	// DOWN表示slab功能不可用
	if (slab_state == DOWN) {
		// 在我们在这个情景里，走这个条件
		// CACHE_CACHE=0
		// set_up_node是用init_kmem_cache_node里对应的元素来初始化cachep里每个node
		set_up_node(kmem_cache, CACHE_CACHE);
	} else if (slab_state == PARTIAL) {
		// kmem_cache_node可用
		// SIZE_NODE＝MAX_NUMNODES
		set_up_node(cachep, SIZE_NODE);
	
	// 在DOWN, UP这2个条件里，因为kmalloc-size还没有完成初始化，
	// 所以得用init_kmem_cache_node元素，解决鸡与蛋的问题

	} else { 
		// 这个分支表示PARTIAL_NODE，UP状态
		// 在这个状态时kmalloc已经可以用了，所以可以直接使用
		int node;
		// 这里初始化每个node
		for_each_online_node(node) {
			cachep->node[node] = kmalloc_node(
				sizeof(struct kmem_cache_node), gfp, node);
			BUG_ON(!cachep->node[node]);
			// 这里面是node缓存的基本初始化
			kmem_cache_node_init(cachep->node[node]);
		}
	}

	// 把当前numa上的回收时间再计算一下。
	cachep->node[numa_mem_id()]->next_reap =
			jiffies + REAPTIMEOUT_NODE +
			((unsigned long)cachep) % REAPTIMEOUT_NODE;

	// 下面是设置了当前cpu的一些值

	// cpu_cache_get获取的是本cpu对应的percpu cache
	cpu_cache_get(cachep)->avail = 0;
	// BOOT_CPUCACHE_ENTRIES是1
	cpu_cache_get(cachep)->limit = BOOT_CPUCACHE_ENTRIES;
	// 默认cpu-cache是1个
	cpu_cache_get(cachep)->batchcount = 1;
	cpu_cache_get(cachep)->touched = 0;

	// 初始化cachep的batchcount和limit
	cachep->batchcount = 1;
	cachep->limit = BOOT_CPUCACHE_ENTRIES;
	return 0;
}

static void __init set_up_node(struct kmem_cache *cachep, int index)
{
	int node;

	// 初始化每个cache node
	// init_kmem_cache_node保存的是初始化的对象，这个数组大小是 2 * MAX_NUMNODES
	// CACHE_CACHE： 0～MAX_NUMNODES
	// SIZE_NODE: MAX_NUMNODES ~  2 * MAX_NUMNODES
	for_each_online_node(node) {
		// 把init_kmem_cache_node里的数据全部复制过去，这是个静态数组
		cachep->node[node] = &init_kmem_cache_node[index + node];
		// 计算下一次回收的时间
		cachep->node[node]->next_reap = jiffies +
		    REAPTIMEOUT_NODE +
		    ((unsigned long)cachep) % REAPTIMEOUT_NODE;
	}
}

static struct array_cache __percpu *alloc_kmem_cache_cpus(
		struct kmem_cache *cachep, int entries, int batchcount)
{
	int cpu;
	size_t size;
	struct array_cache __percpu *cpu_cache;

	// 一个array_cache的大小，因为array_cache->entry是一个变长数组，所以要动态计算
	// 它的长度，entries就是cpucache的限制大小
	size = sizeof(void *) * entries + sizeof(struct array_cache);

	// 分配percpu变量
	cpu_cache = __alloc_percpu(size, sizeof(void *));

	if (!cpu_cache)
		return NULL;

	for_each_possible_cpu(cpu) {
		// 初始化每个cpucache，主要设置了limit和batch的大小
		init_arraycache(per_cpu_ptr(cpu_cache, cpu),
				entries, batchcount);
	}

	return cpu_cache;
}

static void init_arraycache(struct array_cache *ac, int limit, int batch)
{
	if (ac) {
		ac->avail = 0;
		ac->limit = limit;
		ac->batchcount = batch;
		ac->touched = 0;
	}
}
```

## enable_cpucache
```c
static int enable_cpucache(struct kmem_cache *cachep, gfp_t gfp)
{
	int err;
	int limit = 0;
	int shared = 0;
	int batchcount = 0;

	// 创建random_seq随机数组
	err = cache_random_seq_create(cachep, cachep->num, gfp);
	if (err)
		goto end;

	// 走到这儿，limit=0，这个条件恒为false呀！！
	if (limit && shared && batchcount)
		goto skip_setup;

	// 计算limit, limit是cpucache里缓存的对象数量,
	// 对象越小，缓存的对象越多
	if (cachep->size > 131072)
		limit = 1;
	else if (cachep->size > PAGE_SIZE)
		limit = 8;
	else if (cachep->size > 1024)
		limit = 24;
	else if (cachep->size > 256)
		limit = 54;
	else
		limit = 120;

	// 默认禁用共享，共享用于在不同的cpu之间共享对象
	shared = 0;

	// 对象小于页大小，而且cpu数量大于1，则会开启共享，默认共享8个对象
	// 在numa机器上一般这个机器都成立
	if (cachep->size <= PAGE_SIZE && num_possible_cpus() > 1)
		shared = 8;

	// 批量数量为limit的一半，并以2向上对齐
	batchcount = (limit + 1) / 2;
skip_setup:

	// 设置cpu缓存
	err = do_tune_cpucache(cachep, limit, batchcount, shared, gfp);
end:
	if (err)
		pr_err("enable_cpucache failed for %s, error %d\n",
		       cachep->name, -err);
	return err;
}

int cache_random_seq_create(struct kmem_cache *cachep, unsigned int count,
				    gfp_t gfp)
{
	struct rnd_state state;
	
	// slab里只有一个对象没有必要随机化
	// 或者random_seq已经分配
	if (count < 2 || cachep->random_seq)
		return 0;

	// 分配random_seq数组
	cachep->random_seq = kcalloc(count, sizeof(unsigned int), gfp);
	if (!cachep->random_seq)
		return -ENOMEM;

	// 设置随机数种子
	prandom_seed_state(&state, get_random_long());

	// 把random_seq数组里的元素随机化
	freelist_randomize(&state, cachep->random_seq, count);
	return 0;
}

static void freelist_randomize(struct rnd_state *state, unsigned int *list,
			       unsigned int count)
{
	unsigned int rand;
	unsigned int i;

	// 初始化列表里的每个值为序号值
	for (i = 0; i < count; i++)
		list[i] = i;

	// 随机化列表里的值
	for (i = count - 1; i > 0; i--) {
		// 产生一个随机值
		rand = prandom_u32_state(state);
		// 因为是从后往前遍历，之所以要取余，是为了不再与后面的值交换，只与
		// 前面的值交换，否则，这些值来回交换就乱了。
		rand %= (i + 1);

		// 交换随机值和当前的位置
		swap(list[i], list[rand]);
	}
}

static int do_tune_cpucache(struct kmem_cache *cachep, int limit,
			    int batchcount, int shared, gfp_t gfp)
{
	struct array_cache __percpu *cpu_cache, *prev;
	int cpu;

	// 分配并初始化cpu_cache
	cpu_cache = alloc_kmem_cache_cpus(cachep, limit, batchcount);
	if (!cpu_cache)
		return -ENOMEM;

	// 先保存之前的
	prev = cachep->cpu_cache;
	// 然后设置新的cache
	cachep->cpu_cache = cpu_cache;
	
	// 如果prev有值，则激活所有cpu todo: 为啥要激活？
	if (prev)
		kick_all_cpus_sync();

	// todo: 这里为什么要检查中断是开的？
	check_irq_on();
	// 每次新增或销毁的批数量
	cachep->batchcount = batchcount;
	// 缓存限制
	cachep->limit = limit;
	// 本percpu缓存可以共享的数量
	cachep->shared = shared;

	// prev为NULL，表示是第一次分配cache，则直接调到设置
	if (!prev)
		goto setup_node;

	// 走到这里表示prev不为null, 要先把之前的cache释放掉
	// todo: 什么情况下才会走到这里？内存hotplug?
	// 释放每个prev里的cpucache
	for_each_online_cpu(cpu) {
		LIST_HEAD(list);
		int node;
		struct kmem_cache_node *n;
		// 取出每个cpu的ac
		struct array_cache *ac = per_cpu_ptr(prev, cpu);

		// 把cpu号转成nodeid
		node = cpu_to_mem(cpu);
		// 获取cachep里对应的node 
		n = get_node(cachep, node);
		spin_lock_irq(&n->list_lock);
		// 把整个ac里的缓存全都释放
		free_block(cachep, ac->entry, ac->avail, node, &list);
		spin_unlock_irq(&n->list_lock);

		// 在free_block里，会把需要释放的页链到list里，
		// 在slabs_destroy里真正释放，把内存还给buddy系统
		slabs_destroy(cachep, &list);
	}
	// 释放prev结构
	free_percpu(prev);

setup_node:
	// 真正的设置缓存
	return setup_kmem_cache_nodes(cachep, gfp);
}


static int setup_kmem_cache_nodes(struct kmem_cache *cachep, gfp_t gfp)
{
	int ret;
	int node;
	struct kmem_cache_node *n;

	// 遍历每个节点，设置percpu
	for_each_online_node(node) {
		// 这个函数里主要设置了cachep里node对应的kmem_cache_node对象，并没有真正的分配内存。
		// 其他还分配了shared, alien相应的内存，如果有的话。
		ret = setup_kmem_cache_node(cachep, node, gfp, true);
		if (ret)
			goto fail;

	}

	return 0;

fail:
	// 如果有失败的情况，就释放每个节点
	if (!cachep->list.next) {
		/* Cache is not active yet. Roll back what we did */
		node--;
		while (node >= 0) {
			n = get_node(cachep, node);
			if (n) {
				kfree(n->shared);
				free_alien_cache(n->alien);
				kfree(n);
				cachep->node[node] = NULL;
			}
			node--;
		}
	}
	return -ENOMEM;
}

static int setup_kmem_cache_node(struct kmem_cache *cachep,
				int node, gfp_t gfp, bool force_change)
{
	int ret = -ENOMEM;
	struct kmem_cache_node *n;
	struct array_cache *old_shared = NULL;
	struct array_cache *new_shared = NULL;
	struct alien_cache **new_alien = NULL;
	LIST_HEAD(list);

	// 这个一般都是1，只有在没有打开numa或者只有1个cpu时才为0
	if (use_alien_caches) {
		new_alien = alloc_alien_cache(node, cachep->limit, gfp);
		if (!new_alien)
			goto fail;
	}

	// 需要共享
	if (cachep->shared) {
		// 分配share需要的内存，shared一般是8
		// 第3个参数是shared的batch，这是一个很大的数字
		new_shared = alloc_arraycache(node,
			cachep->shared * cachep->batchcount, 0xbaadf00d, gfp);
		if (!new_shared)
			goto fail;
	}
	// 初始化缓存node
	ret = init_cache_node(cachep, node, gfp);
	if (ret)
		goto fail;

	// 获得node对应的结构
	n = get_node(cachep, node);
	spin_lock_irq(&n->list_lock);

	// 如果当前node的shared已有共享，并且是强制改变，就先释放原来shared里的对象
	// 在初始化的时候force_change是true
	if (n->shared && force_change) {
		free_block(cachep, n->shared->entry,
				n->shared->avail, node, &list);
		n->shared->avail = 0;
	}

	// 如果之前没有共享，或者强制改变，就设置新的共享对象
	// 从上个函数里传过来的force_change是true，
	if (!n->shared || force_change) {
		old_shared = n->shared;
		n->shared = new_shared;
		new_shared = NULL;
	}

	// 如果原来没有alien，则设置新的alien
	if (!n->alien) {
		n->alien = new_alien;
		new_alien = NULL;
	}

	spin_unlock_irq(&n->list_lock);
	// 如果上面freelock有释放的内存，就在这里销毁
	slabs_destroy(cachep, &list);

	// 这是为了保护在中断关闭时，无锁访问oldshared的情况，所以需要进入宽限期
	if (old_shared && force_change)
		synchronize_rcu();

fail:
	// 走到这里 {old|new}_shared只能有一个有值而另一个为NULL
	kfree(old_shared);
	kfree(new_shared);
	// new_alien如果原来没有的话是NULL, 如果原来有的话，就把刚分配的释放掉
	free_alien_cache(new_alien);

	return ret;
}

static struct array_cache *alloc_arraycache(int node, int entries,
					    int batchcount, gfp_t gfp)
{
	size_t memsize = sizeof(void *) * entries + sizeof(struct array_cache);
	struct array_cache *ac = NULL;

	// 分配一个array缓存
	ac = kmalloc_node(memsize, gfp, node);
	/*
	 * The array_cache structures contain pointers to free object.
	 * However, when such objects are allocated or transferred to another
	 * cache the pointers are not cleared and they could be counted as
	 * valid references during a kmemleak scan. Therefore, kmemleak must
	 * not scan such objects.
	 */
	kmemleak_no_scan(ac);
	// 初始化ac的一些变量，entries就是limit
	init_arraycache(ac, entries, batchcount);
	return ac;
}

static int init_cache_node(struct kmem_cache *cachep, int node, gfp_t gfp)
{
	struct kmem_cache_node *n;

	// 获取node对象
	n = get_node(cachep, node);
	if (n) {
		// 如果之前已经分配过了，就只计算空闲的限制，如果slab超过了这个空闲值，就归还相应的内存
		spin_lock_irq(&n->list_lock);
		// todo: 为什么node序号越大，空闲限制越大？
		n->free_limit = (1 + nr_cpus_node(node)) * cachep->batchcount +
				cachep->num;
		spin_unlock_irq(&n->list_lock);

		return 0;
	}

	// 下面是cachep对应node的初始化，和上面所看到其他node初始化类似

	// 分配一个node对象
	n = kmalloc_node(sizeof(struct kmem_cache_node), gfp, node);
	if (!n)
		return -ENOMEM;

	// 这里面是对象的一些初始化，比如初始化列表，设置常量为0，指针为NULL.
	kmem_cache_node_init(n);

	// 下一次回收的时间，REAPTIMEOUT_NODE是4秒
	// todo: cachp%REAPTIMEOUT_NODE是什么？地址越大超时时间越长？
	n->next_reap = jiffies + REAPTIMEOUT_NODE +
		    ((unsigned long)cachep) % REAPTIMEOUT_NODE;

	// 计算一下free_limit
	n->free_limit =
		(1 + nr_cpus_node(node)) * cachep->batchcount + cachep->num;
	
	// 上面的get_node就是获取的cachep->node[node]
	cachep->node[node] = n;

	return 0;
}

static struct alien_cache **alloc_alien_cache(int node, int limit, gfp_t gfp)
{
	struct alien_cache **alc_ptr;
	int i;

	if (limit > 1)
		limit = 12;
	// nr_node_ids是node的数量
	alc_ptr = kcalloc_node(nr_node_ids, sizeof(void *), gfp, node);
	if (!alc_ptr)
		return NULL;

	// 遍历每个节点，给除了本节点之外的其他节点分配percpu-cache
	for_each_node(i) {
		if (i == node || !node_online(i))
			continue;
		// 分配缓存，这里分配的数量是cachep的限制数量
		alc_ptr[i] = __alloc_alien_cache(node, limit, 0xbaadf00d, gfp);

		// 如果一个分配失败了，其它的也要
		if (!alc_ptr[i]) {
			for (i--; i >= 0; i--)
				kfree(alc_ptr[i]);
			kfree(alc_ptr);
			return NULL;
		}
	}
	return alc_ptr;
}

static struct alien_cache *__alloc_alien_cache(int node, int entries,
						int batch, gfp_t gfp)
{
	// 结构的大小
	size_t memsize = sizeof(void *) * entries + sizeof(struct alien_cache);
	struct alien_cache *alc = NULL;

	alc = kmalloc_node(memsize, gfp, node);
	if (alc) {
		kmemleak_no_scan(alc);
		// 初始化percpu
		init_arraycache(&alc->ac, entries, batch);
		spin_lock_init(&alc->lock);
	}
	return alc;
}
```