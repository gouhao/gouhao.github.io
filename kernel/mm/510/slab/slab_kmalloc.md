# kmalloc
源码基于5.10

## 前端接口
```c
/**
 * kmalloc - allocate memory
 * @size: 需要多少字节内存
 * @flags: 分配类型标志
 *
 * kmalloc是用来在内核里分配比一页内存小的通用方法
 *
 * 分配的对象地址至少会对齐到ARCH_KMALLOC_MINALIGN字节，对于大小是2的幂字节，对齐也会
 * 保证至少是size.
 *
 * flags是在include/linux/gfp.h里描述的一些标志， and 在这个文档里也有描述
 * :ref:`Documentation/core-api/mm-api.rst <mm-api-gfp-flags>`
 *
 * 推荐的标志在这个文档里
 * :ref:`Documentation/core-api/memory-allocation.rst <memory_allocation>`
 *
 * 下面是一些常用flag的简单介绍：
 *
 * %GFP_KERNEL
 *	分配普通内存，会睡眠
 *
 * %GFP_NOWAIT
 *	同上，但不睡眠
 *
 * %GFP_ATOMIC
 *	同上，可能使用紧急池
 *
 * %GFP_HIGHUSER
 *	从高端内存分配？
 *
 * 下面是一些附加标志:
 *
 * %__GFP_HIGH
 *	高优先级分配，可能使用紧急池
 *
 * %__GFP_NOFAIL
 *	这次分配不允许失败（使用这个标志请三思而后行）
 *	(think twice before using).
 *
 * %__GFP_NORETRY
 *	如果不能立刻分配内存，则放弃
 *
 * %__GFP_NOWARN
 *	如果分配失败，不要产生警告
 *
 * %__GFP_RETRY_MAYFAIL
 *	尽量去成功分配，但是失败也是允许的
 */
static __always_inline void *kmalloc(size_t size, gfp_t flags)
{
	// __builtin_constant_p表示：如果值能在编译时确定就返回1，比如：常量或者sizeof(struct ...)
	if (__builtin_constant_p(size)) {
#ifndef CONFIG_SLOB
		unsigned int index;
#endif
		// KMALLOC_MAX_CACHE_SIZE在slab里最大表示4M，
		// 如果超过这个值，会走buddy系统去分配
		if (size > KMALLOC_MAX_CACHE_SIZE)
			return kmalloc_large(size, flags);
#ifndef CONFIG_SLOB
		// 根据size找到kmalloc-size对应的下标
		index = kmalloc_index(size);

		// 0size会返回ZERO_SIZE_PTR: (void *)16，
		// 访问(void*)16会触发page_fault
		if (!index)
			return ZERO_SIZE_PTR;

		// 这个函数最终也会调用到slab_alloc
		return kmem_cache_alloc_trace(
				kmalloc_caches[kmalloc_type(flags)][index],
				flags, size);
#endif
	}

	// 一般的分配都走这个
	return __kmalloc(size, flags);
}
```

## 普通分配
```c
void *__kmalloc(size_t size, gfp_t flags)
{
	// _RET_IP_: 当前函数的返回地址，也就是调用者的地址
	return __do_kmalloc(size, flags, _RET_IP_);
}

static __always_inline void *__do_kmalloc(size_t size, gfp_t flags,
					  unsigned long caller)
{
	struct kmem_cache *cachep;
	void *ret;

	// 超过了kmalloc的最大分配大小，返回NULL
	// KMALLOC_MAX_CACHE_SIZE最大为4M
	if (unlikely(size > KMALLOC_MAX_CACHE_SIZE))
		return NULL;
	// 根据flag和size，找到对应的kmalloc-size对应的slab
	cachep = kmalloc_slab(size, flags);
	if (unlikely(ZERO_OR_NULL_PTR(cachep)))
		return cachep;
	// 从slab里分配内存
	ret = slab_alloc(cachep, flags, caller);

	// kasan没打开时还是会返回cachep
	ret = kasan_kmalloc(cachep, ret, size, flags);
	// trace相关
	trace_kmalloc(caller, ret,
		      size, cachep->size, flags);

	return ret;
}
```

## 找到size对应的slab-cache
```c
struct kmem_cache *kmalloc_slab(size_t size, gfp_t flags)
{
	unsigned int index;

	// kmalloc_caches里各个大小的顺序是被精心设计的，对于小于和大于192
	// 大小的都有不同的计算方法
	if (size <= 192) {
		// size为0，返回 ((void*) 16)
		if (!size)
			return ZERO_SIZE_PTR;
		/*
		size_index里保存的是kmall_caches对应的下标，它只保存了小于
		等于192的下标。计算公式如下：
		index = size_index[(size - 1) / 8]
		*/
		index = size_index[size_index_elem(size)];
	} else {
		// 超过了最大值
		if (WARN_ON_ONCE(size > KMALLOC_MAX_CACHE_SIZE))
			return NULL;
		/* fls：find last set bit。返回最后一位被设置的位置。
		
		 比如分配256字节，256是1<<8=0001 0000 0000, 而256-1=1111 1111.
		 所以fls就会返回8，而kmalloc_caches[][8]的大小就是256.
		*/
		index = fls(size - 1);
	}

	/* kmalloc_type会根据flags来计算分配的类型，目前有3种:
	KMALLOC_NORMAL（一般分配）,KMALLOC_RECLAIM（回收内存？）,KMALLOC_DMA（dma分配）。大多数都是KMALLOC_NORMAL
	*/
	return kmalloc_caches[kmalloc_type(flags)][index];
}

static __always_inline enum kmalloc_cache_type kmalloc_type(gfp_t flags)
{
#ifdef CONFIG_ZONE_DMA
	// 大多数情况下这个if都会成立：没有DMA和RECLAIMABLE标志。
	if (likely((flags & (__GFP_DMA | __GFP_RECLAIMABLE)) == 0))
		return KMALLOC_NORMAL;

	// 根据flags来判断类型，如果dma和reclaim都设置了，则dma类型更重要些
	return flags & __GFP_DMA ? KMALLOC_DMA : KMALLOC_RECLAIM;
#else
	// 同上
	return flags & __GFP_RECLAIMABLE ? KMALLOC_RECLAIM : KMALLOC_NORMAL;
#endif
}
```

## 真正的分配
```c
static __always_inline void *
slab_alloc(struct kmem_cache *cachep, gfp_t flags, unsigned long caller)
{
	unsigned long save_flags;
	void *objp;
	struct obj_cgroup *objcg = NULL;

	// 过滤掉不允许的flag
	flags &= gfp_allowed_mask;
	// 分配之前的hook
	cachep = slab_pre_alloc_hook(cachep, &objcg, 1, flags);
	if (unlikely(!cachep))
		return NULL;

	// 这个是判断是否有其他进程需要调度，因为下面就要关中断了
	cache_alloc_debugcheck_before(cachep, flags);

	// 关中断
	local_irq_save(save_flags);

	// 真正的分配内存
	objp = __do_cache_alloc(cachep, flags);
	// 开中断
	local_irq_restore(save_flags);
	// 这个在没有打开CONFIG_DEBUG_SLAB时，直接返回objp
	objp = cache_alloc_debugcheck_after(cachep, flags, objp, caller);
	
	// 预取分配的内存。因为分配的内存大概率马上就要用，
	// 所以预取可以提高性能吧
	prefetchw(objp);

	// 如果需要清零，就把刚分配的内存里的内容清零
	if (unlikely(slab_want_init_on_alloc(flags, cachep)) && objp)
		memset(objp, 0, cachep->object_size);

	// 分配完成后的hook
	slab_post_alloc_hook(cachep, objcg, flags, 1, &objp);
	return objp;
}

static inline void slab_post_alloc_hook(struct kmem_cache *s,
					struct obj_cgroup *objcg,
					gfp_t flags, size_t size, void **p)
{
	size_t i;

	flags &= gfp_allowed_mask;

	// kasan相关
	for (i = 0; i < size; i++) {
		p[i] = kasan_slab_alloc(s, p[i], flags);
		/* As p[i] might get tagged, call kmemleak hook after KASAN. */
		kmemleak_alloc_recursive(p[i], s->object_size, 1,
					 s->flags, flags);
	}

	// cgroup相关
	memcg_slab_post_alloc_hook(s, objcg, flags, size, p);
}


static inline bool slab_want_init_on_alloc(gfp_t flags, struct kmem_cache *c)
{
	if (static_branch_unlikely(&init_on_alloc)) {
		if (c->ctor)
			return false;
		if (c->flags & (SLAB_TYPESAFE_BY_RCU | SLAB_POISON))
			return flags & __GFP_ZERO;
		return true;
	}
	return flags & __GFP_ZERO;
}

static inline void cache_alloc_debugcheck_before(struct kmem_cache *cachep,
						gfp_t flags)
{
	might_sleep_if(gfpflags_allow_blocking(flags));
}

static inline struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s,
						     struct obj_cgroup **objcgp,
						     size_t size, gfp_t flags)
{
	flags &= gfp_allowed_mask;

	// todo: 避免死锁，等待锁释放？？
	fs_reclaim_acquire(flags);
	fs_reclaim_release(flags);

	// 是否要睡眠
	might_sleep_if(gfpflags_allow_blocking(flags));

	// 这个需要打开CONFIG_FAILSLAB才有意义，一般都返回false
	if (should_failslab(s, flags))
		return NULL;

	// cgroup计费相关
	if (!memcg_slab_pre_alloc_hook(s, objcgp, size, flags))
		return NULL;

	return s;
}
```

## 分配核心函数
```c
static __always_inline void *
__do_cache_alloc(struct kmem_cache *cache, gfp_t flags)
{
	void *objp;

	// mempolicy是进程的内存策略，这个一般为空
	// cpuset_do_slab_mem_spread是测试current->atomic_flags
	// 里的PFA_spread_slab有没有被设置，所以这个条件一般也不成立
	// todo: 后面有时间再看
	if (current->mempolicy || cpuset_do_slab_mem_spread()) {
		objp = alternate_node_alloc(cache, flags);
		if (objp)
			goto out;
	}
	// 首先在percpu-cache里分配
	objp = ____cache_alloc(cache, flags);

	// 如果percpu分配失败，则要去slab里分配
	if (!objp)
		objp = ____cache_alloc_node(cache, flags, numa_mem_id());

  out:
	return objp;
}
```
### percpu分配
```c
static inline void *____cache_alloc(struct kmem_cache *cachep, gfp_t flags)
{
	void *objp;
	struct array_cache *ac;

	//检查中断是否已关
	check_irq_off();

	// 获取本cpu的cpu-cache
	ac = cpu_cache_get(cachep);

	// 如果cpu缓存里有可用的
	if (likely(ac->avail)) {

		// touched是标记当前ac是否被用过
		ac->touched = 1;
		// 从ac的entry里分配一个对象
		objp = ac->entry[--ac->avail];

		// 统计ac缓存合
		STATS_INC_ALLOCHIT(cachep);
		goto out;
	}

	// 走到这里说明ac里的缓存用完了

	// 统计缓存未命中
	STATS_INC_ALLOCMISS(cachep);

	// 重新填充缓存，填充的同时会返回一个分配的对象
	objp = cache_alloc_refill(cachep, flags);
	
	// 在cache_alloc_refill里，缓存有可能被更新了，所以这里要重新获取
	ac = cpu_cache_get(cachep);

out:
	/*
	 * To avoid a false negative, if an object that is in one of the
	 * per-CPU caches is leaked, we need to make sure kmemleak doesn't
	 * treat the array pointers as a reference to the object.
	 */
	if (objp)
		kmemleak_erase(&ac->entry[ac->avail]);
	return objp;
}

static void *cache_alloc_refill(struct kmem_cache *cachep, gfp_t flags)
{
	int batchcount;
	struct kmem_cache_node *n;
	struct array_cache *ac, *shared;
	int node;
	void *list = NULL;
	struct page *page;

	// 检查中断是否已关
	check_irq_off();

	// 获取当前node-id
	node = numa_mem_id();

	// 获取当前ac
	ac = cpu_cache_get(cachep);

	// 一次批量分配的数量
	batchcount = ac->batchcount;

	// BATCHREFILL_LIMIT是16，如果这个ac最近都没有被访问，那需要限制
	// 批量分配的数量，否则可能造成抖动，一会填充一会又释放？
	if (!ac->touched && batchcount > BATCHREFILL_LIMIT) {
		batchcount = BATCHREFILL_LIMIT;
	}

	// 获取cachep对应的node结构
	n = get_node(cachep, node);

	// 什么情况下会走到这个BUG？
	BUG_ON(ac->avail > 0 || !n);

	// 这个node的共享内存
	shared = READ_ONCE(n->shared);

	// 当前node没有空闲对象 && (没有共享 || 有共享，但共享不可用)
	if (!n->free_objects && (!shared || !shared->avail))
		// 直接去分配内存
		goto direct_grow;

	// 走到这里表示：node里有空尊重对象，或者有共享可用

	spin_lock(&n->list_lock);

	// 之所以要再读一次，是因为上面的spin_lock可能阻塞，
	// n->shared的值可能已经变了
	shared = READ_ONCE(n->shared);

	// 如果共享可用，则尝试从共享里转移一些对象
	if (shared && transfer_objects(ac, shared, batchcount)) {
		// 转移成功，设置share被用过，然后跳转到完成
		shared->touched = 1;
		goto alloc_done;
	}

	// 走到这里表示从共享里没有转移成功
	while (batchcount > 0) {
		// 从slab里获取一页内存
		page = get_first_slab(n, false);
		if (!page)
			// 如果slab里也空了，则直接分配
			goto must_grow;

		// 这个在debug没开时，是空语句
		check_spinlock_acquired(cachep);

		// 从一页里分配对应的对象，返回值为还需要再分配的数量
		batchcount = alloc_block(cachep, ac, page, batchcount);
		// 将page添加到适当的列表里，slab有3个列表：完全使用，部分使用，空闲
		fixup_slab_list(cachep, n, page, &list);
	}

	// 走到这里表示是从slab里分配的内存
must_grow:
	// 所以node上的空闲数量要减去ac里可用的数量
	n->free_objects -= ac->avail;
alloc_done:
	spin_unlock(&n->list_lock);
	// 调试
	fixup_objfreelist_debug(cachep, &list);

direct_grow:
	// 如果走到这里ac里还是没有可用的，那就是slab里也没分到，
	// 需要去buddy系统里分配
	if (unlikely(!ac->avail)) {
		// 从pfmemalloc里获取，这个分支一般不会走
		// todo:后面看
		if (sk_memalloc_socks()) {
			void *obj = cache_alloc_pfmemalloc(cachep, n, flags);

			if (obj)
				return obj;
		}

		// 从buddy系统里分配页，然后初始化slab的freelist及对象等
		page = cache_grow_begin(cachep, gfp_exact_node(flags), node);

		// cache_grow_begin可能会重新打开中断，ac可能会改变，
		// 所以这里要重新获取ac
		ac = cpu_cache_get(cachep);

		// 所以这里也要重新判断ac里可用的对象数，如果还是没有可用的，
		// 而且也正常分配了页，则从slab里给ac填充缓存
		if (!ac->avail && page)
			alloc_block(cachep, ac, page, batchcount);

		// 这个里面把slab放到合适的列表，并且修改一些node和cachep的计数
		cache_grow_end(cachep, page);

		// ac还是没有可用，那只好返回NULL了
		if (!ac->avail)
			return NULL;
	}

	// 走到这里说明ac重新填充成功了，所以设置touched标志
	ac->touched = 1;

	// 返回一个对象
	return ac->entry[--ac->avail];
}

static int transfer_objects(struct array_cache *to,
		struct array_cache *from, unsigned int max)
{
	// 三者的最小值：源可用数量，传送最大值，目标需要的最大值
	int nr = min3(from->avail, max, to->limit - to->avail);

	// 为0当然啥都不干
	if (!nr)
		return 0;

	// to->entry + to->avail：目标的末尾
	// from->entry + from->avail -nr：源的末尾向左偏移nr。todo: 这里为什么不从前面移动，因为后面的缓存是热的，这不就破坏缓存了？
	memcpy(to->entry + to->avail, from->entry + from->avail -nr,
			// 每个对象都是void *类型
			sizeof(void *) *nr);

	// 重新计算各自的avail的值
	from->avail -= nr;
	to->avail += nr;
	return nr;
}

static struct page *get_first_slab(struct kmem_cache_node *n, bool pfmemalloc)
{
	struct page *page;

	// 这个函数要求list_lock已被上锁，所以在这里断言
	assert_spin_locked(&n->list_lock);

	// 从node的部分使用列表里取出一页
	page = list_first_entry_or_null(&n->slabs_partial, struct page,
					slab_list);
	if (!page) {
		// 走到这里表示部分列表里没页了，要从free列表里来分配

		// 标记空闲列表被访问
		n->free_touched = 1;

		// 从free列表里取出一个
		page = list_first_entry_or_null(&n->slabs_free, struct page,
						slab_list);
		// 获取页成功，递减空闲页计数
		if (page)
			n->free_slabs--;
	}

	// 这个分支一般不会走。todo: 后面看。
	if (sk_memalloc_socks())
		page = get_valid_first_slab(n, page, pfmemalloc);

	return page;
}

static __always_inline int alloc_block(struct kmem_cache *cachep,
		struct array_cache *ac, struct page *page, int batchcount)
{
	// active表示页里面活跃对象的数量。
	// 如果一个page里的对象数量已经大于等于一个slab里规定的数量，那肯定哪里出BUG了。
	BUG_ON(page->active >= cachep->num);

	while (page->active < cachep->num && batchcount--) {

		// 这3个宏是调试相关，没开DEBUG时，是空语句。
		STATS_INC_ALLOCED(cachep);
		STATS_INC_ACTIVE(cachep);
		STATS_SET_HIGH(cachep);

		// 从page里获取一个对象放到ac->entry里，这里的获取对象其实就是
		// 一页内存里的一个地址
		ac->entry[ac->avail++] = slab_get_obj(cachep, page);
	}

	return batchcount;
}

static void *slab_get_obj(struct kmem_cache *cachep, struct page *page)
{
	void *objp;

	// get_free_obj：获取空闲对象的序号
	// index_to_obj：计算序号在页里对应的地址
	// 展开后： objp = page->s_mem + cache->size * ((freelist_idx_t *)page->freelist)[page->active]
	objp = index_to_obj(cachep, page, get_free_obj(page, page->active));

	// 每获取一个对象就递增active
	page->active++;

	return objp;
}

static inline freelist_idx_t get_free_obj(struct page *page, unsigned int idx)
{
	// freelist数组里保存的是下一个空闲对象的序号
	return ((freelist_idx_t *)page->freelist)[idx];
}

static inline void *index_to_obj(struct kmem_cache *cache, struct page *page,
				 unsigned int idx)
{
	// 计算下标对应页里的地址。
	// page->s_mem: 第一个对象的偏移
	// cache->size: 对象的大小
	return page->s_mem + cache->size * idx;
}

static inline void fixup_slab_list(struct kmem_cache *cachep,
				struct kmem_cache_node *n, struct page *page,
				void **list)
{
	// 先把page从原来的列表删除，是为了后面加到正确的列表
	list_del(&page->slab_list);

	// page里的对象达到了slab里规定的对象数量
	if (page->active == cachep->num) {

		// 加入到完成使用列表里
		list_add(&page->slab_list, &n->slabs_full);

		// OBJFREELIST_SLAB表示空闲列表在对象里？
		if (OBJFREELIST_SLAB(cachep)) {
#if DEBUG
			/* Poisoning will be done without holding the lock */
			if (cachep->flags & SLAB_POISON) {
				void **objp = page->freelist;

				*objp = *list;
				*list = objp;
			}
#endif
			// 页已经全用了，就清除空闲对象数组指针
			page->freelist = NULL;
		}
	} else
		// 如果还没完全使用，就加入到slab的部分使用列表里
		list_add(&page->slab_list, &n->slabs_partial);
}


static struct page *cache_grow_begin(struct kmem_cache *cachep,
				gfp_t flags, int nodeid)
{
	void *freelist;
	size_t offset;
	gfp_t local_flags;
	int page_node;
	struct kmem_cache_node *n;
	struct page *page;

	 // 使用了slab不允许的flag，就要把这些标志去掉
	if (unlikely(flags & GFP_SLAB_BUG_MASK))
		flags = kmalloc_fix_flags(flags);

	// 有构造函数时还要清零，会发出警告
	WARN_ON_ONCE(cachep->ctor && (flags & __GFP_ZERO));
	// GFP_CONSTRAINT_MASK：控制cpuset和node的约束
	// GFP_RECLAIM_MASK: 会影响水印的检查和回收行为
	local_flags = flags & (GFP_CONSTRAINT_MASK|GFP_RECLAIM_MASK);

	// 这里中断也要关。。
	check_irq_off();

	// 这个是检测有没有__GFP_DIRECT_RECLAIM标志，
	// 如果允许睡眠就把中断打开。
	if (gfpflags_allow_blocking(local_flags))
		local_irq_enable();

	// 从buddy分配一页内存
	page = kmem_getpages(cachep, local_flags, nodeid);
	if (!page)
		goto failed;

	// 获取页所在的node，因为这一页并不一定是从当前node分配出来的
	page_node = page_to_nid(page);
	// 获取页所有node对应的slab里的node
	n = get_node(cachep, page_node);

	// 递增着色值，着色其实就是偏移量
	n->colour_next++;
	// cachep->colour是偏移量的最大值，如果达到最大值，则又从0开始
	if (n->colour_next >= cachep->colour)
		n->colour_next = 0;

	// 计算当前的偏移量，如果偏移量达到最大，也设成0
	offset = n->colour_next;

	// todo: 这里的比较是不是重复了？
	if (offset >= cachep->colour)
		offset = 0;

	// 计算最终的偏移值，cachep->colour_off是一个偏移单位
	offset *= cachep->colour_off;

	// kasan略过
	kasan_poison_slab(page);

	// 初始化page->s_mem，并根据slab的配置，计算／分配freelist
	freelist = alloc_slabmgmt(cachep, page, offset,
			local_flags & ~GFP_CONSTRAINT_MASK, page_node);
	// 如果slab头保存在外面，却没有分配到freelist，就是出错了
	if (OFF_SLAB(cachep) && !freelist)
		goto opps1;

	// 设置page的slab_cache和freelist
	slab_map_pages(cachep, page, freelist);

	// 主要初始化freelist及各个对象
	cache_init_objs(cachep, page);

	// 允许阻塞时开中断，因为前面把中断关了。
	if (gfpflags_allow_blocking(local_flags))
		local_irq_disable();

	return page;

opps1:
	// 出错，释放刚才分配的页
	kmem_freepages(cachep, page);
failed:
	// 关中断。对应上面的开中断
	if (gfpflags_allow_blocking(local_flags))
		local_irq_disable();
	return NULL;
}

static void cache_init_objs(struct kmem_cache *cachep,
			    struct page *page)
{
	int i;
	void *objp;
	bool shuffled;

	// 没开调试时为空
	cache_init_objs_debug(cachep, page);

	// 随机化空闲列表，一般都会随机化，只有在对象数小于2时才不进行随机化
	shuffled = shuffle_freelist(cachep, page);

	// OBJFREELIST_SLAB: 使用slab对象存储freelist
	// 如果不随机化且slab头在slab对象内
	if (!shuffled && OBJFREELIST_SLAB(cachep)) {
		// obj_offset在DEBUG没开的时候是0，
		// 所以使用最后一个对象保存freelist
		page->freelist = index_to_obj(cachep, page, cachep->num - 1) +
						obj_offset(cachep);
	}

	// 遍历slab里的每个对象
	for (i = 0; i < cachep->num; i++) {
		// 获取i对应的对象
		objp = index_to_obj(cachep, page, i);

		// kasan没打开时为空语句
		objp = kasan_init_slab_obj(cachep, objp);

		// 有构造函数的调用构造函数		
		if (DEBUG == 0 && cachep->ctor) {
			kasan_unpoison_object_data(cachep, objp);
			cachep->ctor(objp);
			kasan_poison_object_data(cachep, objp);
		}

		// 如果没有随机化空闲列表里的下标和对象的下标是对应的
		if (!shuffled)
			set_free_obj(page, i, i);
	}
}

static inline void set_free_obj(struct page *page,
					unsigned int idx, freelist_idx_t val)
{
	((freelist_idx_t *)(page->freelist))[idx] = val;
}

static bool shuffle_freelist(struct kmem_cache *cachep, struct page *page)
{
	unsigned int objfreelist = 0, i, rand, count = cachep->num;
	union freelist_init_state state;
	bool precomputed;

	// 只有2个对象就不用乱序了
	if (count < 2)
		return false;

	// 初始化state
	precomputed = freelist_state_initialize(&state, cachep, count);

	// 使用slab对象来存储freelist
	if (OBJFREELIST_SLAB(cachep)) {
		if (!precomputed)
			// 如果没有提前计算，使用最后一个对象来存储
			objfreelist = count - 1;
		else
			// 随机已经初始化，则随便选一个对象
			objfreelist = next_random_slot(&state);
		// 使用这个对象作为空闲列表
		page->freelist = index_to_obj(cachep, page, objfreelist) +
						obj_offset(cachep);
		count--;
	}

	if (!precomputed) {
		// 在启动期间会走这个分支

		// 设置每个对象空闲
		for (i = 0; i < count; i++)
			set_free_obj(page, i, i);

		// 随机交换进行乱序
		for (i = count - 1; i > 0; i--) {
			rand = prandom_u32_state(&state.rnd_state);
			rand %= (i + 1);
			swap_free_obj(page, i, rand);
		}
	} else {
		// 乱序已经提前计算好了，就直接设置随机的空闲对象
		for (i = 0; i < count; i++)
			set_free_obj(page, i, next_random_slot(&state));
	}

	// 如果空闲列表存储在slab对象里，则让最后一个元素的空闲元素指稿空闲列表的位置
	// 这样就构成了一个环，freelist指向第一个空闲的列表，最后一个元素指向freelist
	if (OBJFREELIST_SLAB(cachep))
		set_free_obj(page, cachep->num - 1, objfreelist);

	return true;
}

static freelist_idx_t next_random_slot(union freelist_init_state *state)
{
	if (state->pos >= state->count)
		state->pos = 0;
	return state->list[state->pos++];
}

static bool freelist_state_initialize(union freelist_init_state *state,
				struct kmem_cache *cachep,
				unsigned int count)
{
	bool ret;
	unsigned int rand;

	// 获取一个随机数
	rand = get_random_int();

	// random_seq一般都会在cachep初始化的时候分配好
	if (!cachep->random_seq) {
		prandom_seed_state(&state->rnd_state, rand);
		ret = false;
	} else {
		// state的列表，对象数，起始坐标
		state->list = cachep->random_seq;
		state->count = count;
		state->pos = rand % count;
		ret = true;
	}
	return ret;
}


static void slab_map_pages(struct kmem_cache *cache, struct page *page,
			   void *freelist)
{
	page->slab_cache = cache;
	page->freelist = freelist;
}

static void *alloc_slabmgmt(struct kmem_cache *cachep,
				   struct page *page, int colour_off,
				   gfp_t local_flags, int nodeid)
{
	void *freelist;
	// 这个获取的物理地址
	void *addr = page_address(page);

	// s_mem是对象开始的地址，开始的地址需要在页的地址上偏移着色值
	page->s_mem = addr + colour_off;

	// 还没有分配对象，所以active为0
	page->active = 0;

	// 下面是计算slab的freelist放在哪，有3种：
	// 1. 放到slab内部；2. 放到slab外；3.放到page末尾
	// 至于放到哪，是在slab初始化的时候算好的，这里直接用

	// 这个表示freelist在slab对象内保存
	if (OBJFREELIST_SLAB(cachep))
		freelist = NULL;
	
	// 这个表示slab头在页外保存
	else if (OFF_SLAB(cachep)) {
		// 在页外保存需要分配一个空闲列表
		freelist = kmem_cache_alloc_node(cachep->freelist_cache,
					      local_flags, nodeid);
	} else {
		// 如果上面2者都不是，则在页的最后面保存空闲列表。
		freelist = addr + (PAGE_SIZE << cachep->gfporder) -
				cachep->freelist_size;
	}

	return freelist;
}

static struct page *kmem_getpages(struct kmem_cache *cachep, gfp_t flags,
								int nodeid)
{
	struct page *page;

	// 或上分配的标志
	flags |= cachep->allocflags;

	// 从buddy分配内存
	page = __alloc_pages_node(nodeid, flags, cachep->gfporder);

	if (!page) {
		// 分配失败时打印一些调试信息，只在调试开关打开时有效
		slab_out_of_memory(cachep, flags, nodeid);
		return NULL;
	}

	// 统计相关
	account_slab_page(page, cachep->gfporder, cachep);
	// 设置page的PageSlab标志
	__SetPageSlab(page);
	
	// pfmemalloc后面再看
	if (sk_memalloc_socks() && page_is_pfmemalloc(page))
		SetPageSlabPfmemalloc(page);

	return page;
}

static void cache_grow_end(struct kmem_cache *cachep, struct page *page)
{
	struct kmem_cache_node *n;
	void *list = NULL;

	// 检查关中断
	check_irq_off();

	// 页为空！
	if (!page)
		return;

	// 初始化页的slab指针
	INIT_LIST_HEAD(&page->slab_list);
	// 获取slab里页对应的node
	n = get_node(cachep, page_to_nid(page));

	spin_lock(&n->list_lock);
	// 递增slab总数
	n->total_slabs++;

	if (!page->active) {
		// 页的active还是0说明还没用，加到空闲列表
		list_add_tail(&page->slab_list, &n->slabs_free);
		// 空闲数目递增
		n->free_slabs++;
	} else
		// 如果active不为0，有可能有部分使用，也有可能全部使用了，所以把它放到正确的列表里
		fixup_slab_list(cachep, n, page, &list);

	// 统计相关，递增grown
	STATS_INC_GROWN(cachep);

	// 统计结点内总的空闲对象数，一个slab里有num个对象，
	// active是使用掉的数量，两个一减就是slab里空闲对象的数量
	n->free_objects += cachep->num - page->active;
	spin_unlock(&n->list_lock);

	// 调试相关，设置poison
	fixup_objfreelist_debug(cachep, &list);
}
```

### 慢速路径
```c

static void *____cache_alloc_node(struct kmem_cache *cachep, gfp_t flags,
				int nodeid)
{
	struct page *page;
	struct kmem_cache_node *n;
	void *obj = NULL;
	void *list = NULL;

	// 什么时候会有这种nodeid？
	VM_BUG_ON(nodeid < 0 || nodeid >= MAX_NUMNODES);

	// 获取相应的node对象
	n = get_node(cachep, nodeid);
	BUG_ON(!n);

	// 检查是否关中断
	check_irq_off();
	spin_lock(&n->list_lock);
	// 获取一个slab对象，因为上面加过锁，所以这里还要再尝试一遍，
	// 说不定在等待锁的过程中slab里已经有了对象，这样就不用分配了
	page = get_first_slab(n, false);
	if (!page)
		goto must_grow;

	// 走到这里说明slab里已经有空闲的slab了

	// 检查中断是否已关，nodeid对应的node是否已经给list_lock上锁
	check_spinlock_acquired_node(cachep, nodeid);

	// 统计相关
	STATS_INC_NODEALLOCS(cachep);
	STATS_INC_ACTIVE(cachep);
	STATS_SET_HIGH(cachep);

	// active如果等于num，说明page里的对象已经用完了，不应该走到这里，
	// 所以产生bug
	BUG_ON(page->active == cachep->num);

	// 获取一个空闲对象
	obj = slab_get_obj(cachep, page);
	// 空闲对象递减
	n->free_objects--;

	// 根据slab里空闲对象的情况，把页挂在相应的列表上
	fixup_slab_list(cachep, n, page, &list);

	spin_unlock(&n->list_lock);
	// 调试
	fixup_objfreelist_debug(cachep, &list);
	return obj;

must_grow:

	// 走到这儿，说明没有空闲slab了，需要分配新的页来当slab

	spin_unlock(&n->list_lock);
	// 这里的流程和上面的____cache_alloc类似，也是分配一页内存作为slab，然后加到cachep的对应列表里
	page = cache_grow_begin(cachep, gfp_exact_node(flags), nodeid);
	if (page) {
		/* This slab isn't counted yet so don't update free_objects */
		obj = slab_get_obj(cachep, page);
	}
	cache_grow_end(cachep, page);

	// 如果到这里还是没有分配到对象，说明这个node上已经分配不到内存了，需要回退，从其它node上分配
	return obj ? obj : fallback_alloc(cachep, flags);
}

/* 原文注释：
 * 如果在一个node上没有可用内存和对象，回退是允许的。首先在所有可用的node上扫描所有可用的对象。
 * 如果还是失败了，就在其他node上尝试分配，这允许页分配器做回收和回滚逻辑。然后将slab插入到合适
 * 的node列表。
 */
static void *fallback_alloc(struct kmem_cache *cache, gfp_t flags)
{
	struct zonelist *zonelist;
	struct zoneref *z;
	struct zone *zone;
	// 最大允许的zoneid
	enum zone_type highest_zoneidx = gfp_zone(flags);
	void *obj = NULL;
	struct page *page;
	int nid;
	unsigned int cpuset_mems_cookie;

	if (flags & __GFP_THISNODE)
		return NULL;

retry_cpuset:
	// 允许的cpu集合
	cpuset_mems_cookie = read_mems_allowed_begin();
	// 根据slab的策略计算相应的zone列表
	zonelist = node_zonelist(mempolicy_slab_node(), flags);

retry:
	// 遍历zone列表
	for_each_zone_zonelist(zone, z, zonelist, highest_zoneidx) {
		// 计算zone对应的node-id
		nid = zone_to_nid(zone);

		// 如果允许在这个zone上分配且如果cachep相应的node上，有空闲对象，则分配一个
		if (cpuset_zone_allowed(zone, flags) &&
			get_node(cache, nid) &&
			get_node(cache, nid)->free_objects) {
				// 在其他node上分配
				obj = ____cache_alloc_node(cache,
					gfp_exact_node(flags), nid);
				if (obj)
					break;
		}
	}

	if (!obj) {
		// 走到这儿表示还是没分配到，可能cachep里所有node里的对象都被分配了
		
		// 如果还是没分到，再次尝试先从当前节点分配，这里面会调用buddy系统，
		// 可能会触发加收逻辑
		page = cache_grow_begin(cache, flags, numa_mem_id());
		// 放入相应列表
		cache_grow_end(cache, page);

		if (page) {
			// 如果分配新页成功，则从相应node里分配一个对象
			nid = page_to_nid(page);
			obj = ____cache_alloc_node(cache,
				gfp_exact_node(flags), nid);

			// 因为走到这里没有拿锁，所以可能会被别人把页里的对象用完了，
			// 虽然极不可能发生，但确实存在这种情况
			if (!obj)
				goto retry;
		}
	}

	// 如果允许，再去重试一次。
	if (unlikely(!obj && read_mems_allowed_retry(cpuset_mems_cookie)))
		goto retry_cpuset;
	return obj;
}
```
在慢速路径里会再次尝试从当前节点分配内存，类似于cache_alloc_refill里的流程，但是这个如果分配失败的话，会尝试从其它结点分配。在内存不足的情况下调用buddy系统会触发回收机制，如果这个再分配失败的话，那说明系统里面真的是没有内存了。