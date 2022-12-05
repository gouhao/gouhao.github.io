# slab
源码基于5.10，x86架构，NUMA打开，具体实现使用slab，其他的slub,slab实现差不多。

## 数据结构
```c
struct kmem_cache {
	// 每cpu指针，指向包含空闲对象的本地高速缓存
	struct array_cache __percpu *cpu_cache;

/* 1) Cache tunables. Protected by slab_mutex */
	unsigned int batchcount; // 每次转移/转出本地高速缓存的对象数量
	unsigned int limit; // 本地高速缓存的最大数目
	unsigned int shared;

	unsigned int size; //每个slab的大小
	struct reciprocal_value reciprocal_buffer_size;
/* 2) touched by every alloc & free from the backend */

	slab_flags_t flags;		/* 标志 */
	unsigned int num;		/* 每个slab里对象的个数 */

/* 3) cache_grow/shrink */
	/* order of pgs per slab (2^n) */
	unsigned int gfporder; // 一个slab里页框的个数的对象

	/* force GFP flags, e.g. GFP_DMA */
	gfp_t allocflags; // 分配页框时传给伙伴系统的标志

	size_t colour;			/* 使用的颜色个数 */
	unsigned int colour_off;	/* 颜色对象偏移 */
	struct kmem_cache *freelist_cache;
	unsigned int freelist_size; // 空闲对象的上限

	/* constructor func */
	void (*ctor)(void *obj); // 构造函数

/* 4) cache creation/removal */
	const char *name; // 高还缓存名字
	struct list_head list; // slab链表头指针
	int refcount;
	int object_size; // 对象大小
	int align;

/* 5) statistics */
#ifdef CONFIG_DEBUG_SLAB
	unsigned long num_active;
	unsigned long num_allocations;
	unsigned long high_mark;
	unsigned long grown;
	unsigned long reaped;
	unsigned long errors;
	unsigned long max_freeable;
	unsigned long node_allocs;
	unsigned long node_frees;
	unsigned long node_overflow;
	atomic_t allochit;
	atomic_t allocmiss;
	atomic_t freehit;
	atomic_t freemiss;

	/*
	 * If debugging is enabled, then the allocator can add additional
	 * fields and/or padding to every object. 'size' contains the total
	 * object size including these internal fields, while 'obj_offset'
	 * and 'object_size' contain the offset to the user object and its
	 * size.
	 */
	int obj_offset;
#endif /* CONFIG_DEBUG_SLAB */

#ifdef CONFIG_KASAN
	struct kasan_cache kasan_info;
#endif

#ifdef CONFIG_SLAB_FREELIST_RANDOM
	unsigned int *random_seq;
#endif

	unsigned int useroffset;	/* Usercopy region offset */
	unsigned int usersize;		/* Usercopy region size */

	struct kmem_cache_node *node[MAX_NUMNODES];
};

struct kmem_cache_node {
	spinlock_t list_lock;

#ifdef CONFIG_SLAB
	struct list_head slabs_partial;	/* partial list first, better asm code */
	struct list_head slabs_full;
	struct list_head slabs_free;
	unsigned long total_slabs;	/* length of all slab lists */
	unsigned long free_slabs;	/* length of free slab list only */
	unsigned long free_objects;
	unsigned int free_limit;
	unsigned int colour_next;	/* Per-node cache coloring */
	struct array_cache *shared;	/* shared per node */
	struct alien_cache **alien;	/* on other nodes */
	unsigned long next_reap;	/* updated without locking */
	int free_touched;		/* updated without locking */
#endif

#ifdef CONFIG_SLUB
	unsigned long nr_partial;
	struct list_head partial;
#ifdef CONFIG_SLUB_DEBUG
	atomic_long_t nr_slabs;
	atomic_long_t total_objects;
	struct list_head full;
#endif
#endif

};

struct array_cache {
	unsigned int avail; // 本地高速缓存可用个数，同时也指向第一个可用下标
	unsigned int limit; // 本地高速缓存大小
	unsigned int batchcount; // 重新填充或腾空时使用的块大小
	unsigned int touched; // 如果本地高速缓存最近使用过，标为1
	void *entry[];
};
```

## 创建slab
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

	// 在cpu hotplug打开的时候，给cpu_hotplug_lock加读锁
	get_online_cpus();
	// 同上，在memory hotplug打开的时候，给mem_hotplug_lock加读锁
	get_online_mems();

	// slab加全局锁
	mutex_lock(&slab_mutex);

	// 这个在CONFIG_DEBUG_VM打开时检查，否则返回0
	err = kmem_cache_sanity_check(name, size);
	if (err) {
		goto out_unlock;
	}

	// 有slab不允许的操作，则返回EINVAL
	if (flags & ~SLAB_FLAGS_PERMITTED) {
		err = -EINVAL;
		goto out_unlock;
	}

	// 用CACHE_CREATE_MASK过滤标志
	flags &= CACHE_CREATE_MASK;

	// 检查usersize和useroffset的合法性
	if (WARN_ON(!usersize && useroffset) ||
	    WARN_ON(size < usersize || size - usersize < useroffset))
		usersize = useroffset = 0;

	// 找一个struct kmem_cache结构
	// todo: 这个流程没太看懂，普通创建kmem_cache应该不会走这个流程
	if (!usersize)
		s = __kmem_cache_alias(name, size, align, flags, ctor);
	if (s)
		goto out_unlock;

	// 复制名称
	cache_name = kstrdup_const(name, GFP_KERNEL);
	if (!cache_name) {
		err = -ENOMEM;
		goto out_unlock;
	}

	// 真正创建kmem_cache
	// calculate_alignment是计算出对齐需要的大小
	s = create_cache(cache_name, size,
			 calculate_alignment(flags, align, size),
			 flags, useroffset, usersize, ctor, NULL);
	if (IS_ERR(s)) {
		err = PTR_ERR(s);
		kfree_const(cache_name);
	}

out_unlock:
	mutex_unlock(&slab_mutex);

	// 释放mem, cpu的读锁
	put_online_mems();
	put_online_cpus();

	if (err) {
		// 创建错误时，如果有SLAB_PANIC，则要crash
		if (flags & SLAB_PANIC)
			panic("kmem_cache_create: Failed to create slab '%s'. Error %d\n",
				name, err);
		else {	// 否则的话只打印一下调用栈
			pr_warn("kmem_cache_create(%s) failed with error %d\n",
				name, err);
			dump_stack();
		}
		return NULL;
	}
	return s;
}

struct kmem_cache *
__kmem_cache_alias(const char *name, unsigned int size, unsigned int align,
		   slab_flags_t flags, void (*ctor)(void *))
{
	struct kmem_cache *cachep;

	cachep = find_mergeable(size, align, flags, name, ctor);
	if (cachep) {
		cachep->refcount++;

		/*
		 * Adjust the object sizes so that we clear
		 * the complete object on kzalloc.
		 */
		cachep->object_size = max_t(int, cachep->object_size, size);
	}
	return cachep;
}

struct kmem_cache *find_mergeable(unsigned int size, unsigned int align,
		slab_flags_t flags, const char *name, void (*ctor)(void *))
{
	struct kmem_cache *s;

	// 这个值在CONFIG_SLAB_MERGE_DEFAULT打开时为false，也可以通过命令行参数slab_nomerge来设置
	// 一般情况下这个值都是falsefalse
	if (slab_nomerge)
		return NULL;

	// 有ctor为什么直接返回NULL?
	if (ctor)
		return NULL;

	size = ALIGN(size, sizeof(void *));
	align = calculate_alignment(flags, align, size);
	size = ALIGN(size, align);
	flags = kmem_cache_flags(size, flags, name);

	if (flags & SLAB_NEVER_MERGE)
		return NULL;

	list_for_each_entry_reverse(s, &slab_caches, list) {
		if (slab_unmergeable(s))
			continue;

		if (size > s->size)
			continue;

		if ((flags & SLAB_MERGE_SAME) != (s->flags & SLAB_MERGE_SAME))
			continue;
		/*
		 * Check if alignment is compatible.
		 * Courtesy of Adrian Drzewiecki
		 */
		if ((s->size & ~(align - 1)) != s->size)
			continue;

		if (s->size - size >= sizeof(void *))
			continue;

		if (IS_ENABLED(CONFIG_SLAB) && align &&
			(align > s->align || s->align % align))
			continue;

		return s;
	}
	return NULL;
}

static unsigned int calculate_alignment(slab_flags_t flags,
		unsigned int align, unsigned int size)
{
	/*
	 * If the user wants hardware cache aligned objects then follow that
	 * suggestion if the object is sufficiently large.
	 *
	 * The hardware cache alignment cannot override the specified
	 * alignment though. If that is greater then use it.
	 */
	if (flags & SLAB_HWCACHE_ALIGN) {
		unsigned int ralign;

		// 行缓存
		ralign = cache_line_size();

		// size是对象的大小，这个循环计算在行缓存对齐时的大小
		while (size <= ralign / 2)
			ralign /= 2;
		// 选用户指定和计算的较大值
		align = max(align, ralign);
	}

	// x86没有定义ARCH_SLAB_MINALIGN，默认定义为对齐到unsigned long long，
	// 对齐值不能小于这个值
	if (align < ARCH_SLAB_MINALIGN)
		align = ARCH_SLAB_MINALIGN;

	// 最后还要和指针值对齐
	return ALIGN(align, sizeof(void *));
}

static struct kmem_cache *create_cache(const char *name,
		unsigned int object_size, unsigned int align,
		slab_flags_t flags, unsigned int useroffset,
		unsigned int usersize, void (*ctor)(void *),
		struct kmem_cache *root_cache)
{
	struct kmem_cache *s;
	int err;

	// todo: what?
	if (WARN_ON(useroffset + usersize > object_size))
		useroffset = usersize = 0;

	err = -ENOMEM;
	// 分配一个kmem_cache结构，这里的kmem_cache是一个全局变量，它本身也一个struct kmem_cache
	// 对象，里面保存的都是各个slab
	s = kmem_cache_zalloc(kmem_cache, GFP_KERNEL);
	if (!s)
		goto out;

	// 设置slab的一些基础值
	s->name = name;
	s->size = s->object_size = object_size;
	s->align = align;
	s->ctor = ctor;
	s->useroffset = useroffset;
	s->usersize = usersize;

	// 创建kmem_cache结构
	err = __kmem_cache_create(s, flags);
	if (err)
		goto out_free_cache;

	s->refcount = 1;
	// 加到slab_caches队列
	list_add(&s->list, &slab_caches);
out:
	if (err)
		return ERR_PTR(err);
	return s;

out_free_cache:
	kmem_cache_free(kmem_cache, s);
	goto out;
}
```

## 分配kmem_cache
```c
static inline void *kmem_cache_zalloc(struct kmem_cache *k, gfp_t flags)
{
	return kmem_cache_alloc(k, flags | __GFP_ZERO);
}

void *kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags)
{
	void *ret = slab_alloc(cachep, flags, _RET_IP_);

	trace_kmem_cache_alloc(_RET_IP_, ret,
			       cachep->object_size, cachep->size, flags);

	return ret;
}

static __always_inline void *
slab_alloc(struct kmem_cache *cachep, gfp_t flags, unsigned long caller)
{
	unsigned long save_flags;
	void *objp;
	struct obj_cgroup *objcg = NULL;

	// 屏蔽掉不允许的标志
	flags &= gfp_allowed_mask;

	// 这个函数里调用一些hook，判断本次创建slab是否需要失败
	cachep = slab_pre_alloc_hook(cachep, &objcg, 1, flags);
	if (unlikely(!cachep))
		return NULL;
	// 判断有没有__GFP_DIRECT_RECLAIM标志，如果有，可能需要睡眠，
	// 因为下面关中断了，所以在这里再试一次
	cache_alloc_debugcheck_before(cachep, flags);
	
	// 分配前要关中断
	local_irq_save(save_flags);
	// 真正的分配缓存对象
	objp = __do_cache_alloc(cachep, flags);
	// 恢复中断
	local_irq_restore(save_flags);

	// 调试，只在CONFIG_DEBUG_SLAB打开时有效
	objp = cache_alloc_debugcheck_after(cachep, flags, objp, caller);

	// 调用预取指令，把这个对象从内存读到缓存里
	prefetchw(objp);

	// 里面主要判断了flags有无__GFP_ZERO标志
	if (unlikely(slab_want_init_on_alloc(flags, cachep)) && objp)
		memset(objp, 0, cachep->object_size);
	// kasan, kmemleak相关
	slab_post_alloc_hook(cachep, objcg, flags, 1, &objp);
	return objp;
}

static __always_inline void *
__do_cache_alloc(struct kmem_cache *cache, gfp_t flags)
{
	void *objp;

	// todo: 后面看
	if (current->mempolicy || cpuset_do_slab_mem_spread()) {
		objp = alternate_node_alloc(cache, flags);
		if (objp)
			goto out;
	}
	// 从percpu缓存里分配一个对象
	objp = ____cache_alloc(cache, flags);

	// 本地内存可能已经满了，尝试在其他node上分配内存
	if (!objp)
		objp = ____cache_alloc_node(cache, flags, numa_mem_id());

  out:
	return objp;
}

static void *____cache_alloc_node(struct kmem_cache *cachep, gfp_t flags,
				int nodeid)
{
	struct page *page;
	struct kmem_cache_node *n;
	void *obj = NULL;
	void *list = NULL;

	VM_BUG_ON(nodeid < 0 || nodeid >= MAX_NUMNODES);
	n = get_node(cachep, nodeid);
	BUG_ON(!n);

	check_irq_off();
	spin_lock(&n->list_lock);
	page = get_first_slab(n, false);
	if (!page)
		goto must_grow;

	check_spinlock_acquired_node(cachep, nodeid);

	STATS_INC_NODEALLOCS(cachep);
	STATS_INC_ACTIVE(cachep);
	STATS_SET_HIGH(cachep);

	BUG_ON(page->active == cachep->num);

	obj = slab_get_obj(cachep, page);
	n->free_objects--;

	fixup_slab_list(cachep, n, page, &list);

	spin_unlock(&n->list_lock);
	fixup_objfreelist_debug(cachep, &list);
	return obj;

must_grow:
	spin_unlock(&n->list_lock);
	page = cache_grow_begin(cachep, gfp_exact_node(flags), nodeid);
	if (page) {
		/* This slab isn't counted yet so don't update free_objects */
		obj = slab_get_obj(cachep, page);
	}
	cache_grow_end(cachep, page);

	return obj ? obj : fallback_alloc(cachep, flags);
}

static inline void *____cache_alloc(struct kmem_cache *cachep, gfp_t flags)
{
	void *objp;
	struct array_cache *ac;

	// 这个在CONFIG_DEBUG_SLAB开的时候，用于判断中断是否关闭，
	// 如果配置没开，是空语句
	check_irq_off();

	// 获取percpu缓存
	ac = cpu_cache_get(cachep);

	// 缓存可用
	if (likely(ac->avail)) {
		ac->touched = 1;
		// 取出一个对象
		objp = ac->entry[--ac->avail];

		// 这个是增加slab percpu缓存的命中计数
		STATS_INC_ALLOCHIT(cachep);
		goto out;
	}

	// 走到这里说明缓存未命中
	// 增加缓存未命中计数
	STATS_INC_ALLOCMISS(cachep);

	// 重新填充cpu缓存
	objp = cache_alloc_refill(cachep, flags);
	// cachep里的ac，有可能被cache_alloc_refill更新了，所以这里重新获取一次
	ac = cpu_cache_get(cachep);

out:
	// 与kmemleak有关

	// 设置&ac->entry[ac->avail] = NULL。也就是设置
	// 已分配出去的objp在slab里对应位置为NULL。这个函数在CONFIG_DEBUG_KMEMLEAK
	// 打开的时候才有效。
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
	// DEBUG时检查中断是否关
	check_irq_off();

	// 获取当前运行cpu对应的node-id
	node = numa_mem_id();
	// 获取percpu 缓存对象
	ac = cpu_cache_get(cachep);
	// 一次批量填充的数量
	batchcount = ac->batchcount;
	// touched是如果最近用过，则标为1。
	// BATCHREFILL_LIMIT是16
	// 这里的意思是，如果缓存最近没用过，那最多分配16个对象
	if (!ac->touched && batchcount > BATCHREFILL_LIMIT) {
		batchcount = BATCHREFILL_LIMIT;
	}

	// get_node: s->node[node];
	n = get_node(cachep, node);

	// ac里还有可用的，或者n为NULL则出现bug。
	// todo: 什么时候会出现这种情况
	BUG_ON(ac->avail > 0 || !n);
	shared = READ_ONCE(n->shared);

	// 没有空闲的对象 && (没有共享对象 || 共享对象也没有可用)
	// 如果没有共享了就直接去分配新内存
	if (!n->free_objects && (!shared || !shared->avail))
		goto direct_grow;

	// 走到这里要处理共享
	spin_lock(&n->list_lock);
	// share对象
	shared = READ_ONCE(n->shared);

	// 从共享的percpu转移batchcount个对象过来
	if (shared && transfer_objects(ac, shared, batchcount)) {
		// 走到这里是成功转移了batchcount个对象

		// 标志shared对象被访问过
		shared->touched = 1;
		// 分配完成
		goto alloc_done;
	}

	// 走到这里说明上面的转移失败，有可以转移
	while (batchcount > 0) {
		// 获取一个slab，因为上面有可能已经分配到了
		page = get_first_slab(n, false);
		// 如果一个都没分配到，那就直接增长
		if (!page)
			goto must_grow;

		// 检查cachep锁是不是已经获取
		check_spinlock_acquired(cachep);

		// todo: what ?
		batchcount = alloc_block(cachep, ac, page, batchcount);
		fixup_slab_list(cachep, n, page, &list);
	}

must_grow:
	// todo: ?
	n->free_objects -= ac->avail;
alloc_done:
	spin_unlock(&n->list_lock);
	// todo: 调试相关，后面再看
	fixup_objfreelist_debug(cachep, &list);

direct_grow:
	// todo: 这里为什么要用unlikely，很少走到这里？
	if (unlikely(!ac->avail)) {
		/* Check if we can use obj in pfmemalloc slab */
		// todo: 后面再看
		if (sk_memalloc_socks()) {
			void *obj = cache_alloc_pfmemalloc(cachep, n, flags);

			if (obj)
				return obj;
		}

		// todo: ?
		page = cache_grow_begin(cachep, gfp_exact_node(flags), node);

		/*
		 * cache_grow_begin() can reenable interrupts,
		 * then ac could change.
		 */
		ac = cpu_cache_get(cachep);
		if (!ac->avail && page)
			alloc_block(cachep, ac, page, batchcount);
		cache_grow_end(cachep, page);
		
		// 如果还是没分配成功，返回NULL
		if (!ac->avail)
			return NULL;
	}

	// 走到这里肯定是ac增长成功了，所以标记touched
	ac->touched = 1;

	// 返回一个slab对象
	return ac->entry[--ac->avail];
}

static struct page *get_first_slab(struct kmem_cache_node *n, bool pfmemalloc)
{
	struct page *page;

	assert_spin_locked(&n->list_lock);
	page = list_first_entry_or_null(&n->slabs_partial, struct page,
					slab_list);
	if (!page) {
		n->free_touched = 1;
		page = list_first_entry_or_null(&n->slabs_free, struct page,
						slab_list);
		if (page)
			n->free_slabs--;
	}

	if (sk_memalloc_socks())
		page = get_valid_first_slab(n, page, pfmemalloc);

	return page;
}

static inline struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s,
						     struct obj_cgroup **objcgp,
						     size_t size, gfp_t flags)
{
	flags &= gfp_allowed_mask;

	fs_reclaim_acquire(flags);
	fs_reclaim_release(flags);

	// 这个就是判断有没有__GFP_DIRECT_RECLAIM标志，如果有这个标志的话，
	// 查看其它进程是否需要调度
	might_sleep_if(gfpflags_allow_blocking(flags));

	// 判断是否应该失败。todo: 后面再看
	if (should_failslab(s, flags))
		return NULL;

	// todo: cgroup后面再看
	if (!memcg_slab_pre_alloc_hook(s, objcgp, size, flags))
		return NULL;

	return s;
}
```

## 创建kmem_cache
```c
int __kmem_cache_create(struct kmem_cache *cachep, slab_flags_t flags)
{
	// BYTES_PER_WORD: sizeof(void *)
	size_t ralign = BYTES_PER_WORD;
	gfp_t gfp;
	int err;
	// slab大小
	unsigned int size = cachep->size;

	// 调试相关。todo: 后面再看
#if DEBUG
#if FORCED_DEBUG
	/*
	 * Enable redzoning and last user accounting, except for caches with
	 * large objects, if the increased size would increase the object size
	 * above the next power of two: caches with object sizes just above a
	 * power of two have a significant amount of internal fragmentation.
	 */
	if (size < 4096 || fls(size - 1) == fls(size-1 + REDZONE_ALIGN +
						2 * sizeof(unsigned long long)))
		flags |= SLAB_RED_ZONE | SLAB_STORE_USER;
	if (!(flags & SLAB_TYPESAFE_BY_RCU))
		flags |= SLAB_POISON;
#endif
#endif

	// 对齐size
	size = ALIGN(size, BYTES_PER_WORD);

	// todo:?
	if (flags & SLAB_RED_ZONE) {
		ralign = REDZONE_ALIGN;
		/* If redzoning, ensure that the second redzone is suitably
		 * aligned, by adjusting the object size accordingly. */
		size = ALIGN(size, REDZONE_ALIGN);
	}

	// 默认的对象小于cachep指定的对齐
	if (ralign < cachep->align) {
		ralign = cachep->align;
	}
	// todo: what ?
	if (ralign > __alignof__(unsigned long long))
		flags &= ~(SLAB_RED_ZONE | SLAB_STORE_USER);
	// 保存最终的对齐值
	cachep->align = ralign;
	// 缓存行大小
	cachep->colour_off = cache_line_size();
	// 着色偏移必须大于等于对齐值。否则，连第一个对象都对不齐
	if (cachep->colour_off < cachep->align)
		cachep->colour_off = cachep->align;

	// 判断slab是否完全可用，这个判断是slab_state >= UP
	// 可用的时候就正常分配，不可用的时候不等待。
	if (slab_is_available())
		gfp = GFP_KERNEL;
	else
		gfp = GFP_NOWAIT;

	// todo: debug?
#if DEBUG

	/*
	 * Both debugging options require word-alignment which is calculated
	 * into align above.
	 */
	if (flags & SLAB_RED_ZONE) {
		/* add space for red zone words */
		cachep->obj_offset += sizeof(unsigned long long);
		size += 2 * sizeof(unsigned long long);
	}
	if (flags & SLAB_STORE_USER) {
		/* user store requires one word storage behind the end of
		 * the real object. But if the second red zone needs to be
		 * aligned to 64 bits, we must allow that much space.
		 */
		if (flags & SLAB_RED_ZONE)
			size += REDZONE_ALIGN;
		else
			size += BYTES_PER_WORD;
	}
#endif

	// todo: kasan相关
	kasan_cache_create(cachep, &size, &flags);

	// 这里的size还要再跟align对齐，因为align可能已经变了
	size = ALIGN(size, cachep->align);
	/*
	 * We should restrict the number of objects in a slab to implement
	 * byte sized index. Refer comment on SLAB_OBJ_MIN_SIZE definition.
	 */
	// todo: what?
	if (FREELIST_BYTE_INDEX && size < SLAB_OBJ_MIN_SIZE)
		size = ALIGN(SLAB_OBJ_MIN_SIZE, cachep->align);

	// todo: debug ?
#if DEBUG
	/*
	 * To activate debug pagealloc, off-slab management is necessary
	 * requirement. In early phase of initialization, small sized slab
	 * doesn't get initialized so it would not be possible. So, we need
	 * to check size >= 256. It guarantees that all necessary small
	 * sized slab is initialized in current slab initialization sequence.
	 */
	if (debug_pagealloc_enabled_static() && (flags & SLAB_POISON) &&
		size >= 256 && cachep->object_size > cache_line_size()) {
		if (size < PAGE_SIZE || size % PAGE_SIZE == 0) {
			size_t tmp_size = ALIGN(size, PAGE_SIZE);

			if (set_off_slab_cache(cachep, tmp_size, flags)) {
				flags |= CFLGS_OFF_SLAB;
				cachep->obj_offset += tmp_size - size;
				size = tmp_size;
				goto done;
			}
		}
	}
#endif

	// 下面这3个函数都是设置着色相关，只要一个设置成功就算成功
	if (set_objfreelist_slab_cache(cachep, size, flags)) {
		flags |= CFLGS_OBJFREELIST_SLAB;
		goto done;
	}

	if (set_off_slab_cache(cachep, size, flags)) {
		flags |= CFLGS_OFF_SLAB;
		goto done;
	}

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
	if (flags & SLAB_CACHE_DMA)
		cachep->allocflags |= GFP_DMA;
	if (flags & SLAB_CACHE_DMA32)
		cachep->allocflags |= GFP_DMA32;
	if (flags & SLAB_RECLAIM_ACCOUNT)
		cachep->allocflags |= __GFP_RECLAIMABLE;
	// 设置对象大小
	cachep->size = size;
	// todo: ?
	cachep->reciprocal_buffer_size = reciprocal_value(size);

	// todo:?
#if DEBUG
	/*
	 * If we're going to use the generic kernel_map_pages()
	 * poisoning, then it's going to smash the contents of
	 * the redzone and userword anyhow, so switch them off.
	 */
	if (IS_ENABLED(CONFIG_PAGE_POISONING) &&
		(cachep->flags & SLAB_POISON) &&
		is_debug_pagealloc_cache(cachep))
		cachep->flags &= ~(SLAB_RED_ZONE | SLAB_STORE_USER);
#endif

	// 如果slab对象是在外面保存，还得分配一个freelist_cache
	if (OFF_SLAB(cachep)) {
		cachep->freelist_cache =
			kmalloc_slab(cachep->freelist_size, 0u);
	}
	// 设置percpu缓存
	err = setup_cpu_cache(cachep, gfp);
	if (err) {
		__kmem_cache_release(cachep);
		return err;
	}

	return 0;
}

static int __ref setup_cpu_cache(struct kmem_cache *cachep, gfp_t gfp)
{
	if (slab_state >= FULL)
		return enable_cpucache(cachep, gfp);

	cachep->cpu_cache = alloc_kmem_cache_cpus(cachep, 1, 1);
	if (!cachep->cpu_cache)
		return 1;

	if (slab_state == DOWN) {
		/* Creation of first cache (kmem_cache). */
		set_up_node(kmem_cache, CACHE_CACHE);
	} else if (slab_state == PARTIAL) {
		/* For kmem_cache_node */
		set_up_node(cachep, SIZE_NODE);
	} else {
		int node;

		for_each_online_node(node) {
			cachep->node[node] = kmalloc_node(
				sizeof(struct kmem_cache_node), gfp, node);
			BUG_ON(!cachep->node[node]);
			kmem_cache_node_init(cachep->node[node]);
		}
	}

	cachep->node[numa_mem_id()]->next_reap =
			jiffies + REAPTIMEOUT_NODE +
			((unsigned long)cachep) % REAPTIMEOUT_NODE;

	cpu_cache_get(cachep)->avail = 0;
	cpu_cache_get(cachep)->limit = BOOT_CPUCACHE_ENTRIES;
	cpu_cache_get(cachep)->batchcount = 1;
	cpu_cache_get(cachep)->touched = 0;
	cachep->batchcount = 1;
	cachep->limit = BOOT_CPUCACHE_ENTRIES;
	return 0;
}

static bool set_objfreelist_slab_cache(struct kmem_cache *cachep,
			size_t size, slab_flags_t flags)
{
	size_t left;

	cachep->num = 0;

	/*
	 * If slab auto-initialization on free is enabled, store the freelist
	 * off-slab, so that its contents don't end up in one of the allocated
	 * objects.
	 */
	if (unlikely(slab_want_init_on_free(cachep)))
		return false;

	if (cachep->ctor || flags & SLAB_TYPESAFE_BY_RCU)
		return false;

	left = calculate_slab_order(cachep, size,
			flags | CFLGS_OBJFREELIST_SLAB);
	if (!cachep->num)
		return false;

	if (cachep->num * sizeof(freelist_idx_t) > cachep->object_size)
		return false;

	cachep->colour = left / cachep->colour_off;

	return true;
}

static bool set_off_slab_cache(struct kmem_cache *cachep,
			size_t size, slab_flags_t flags)
{
	size_t left;

	cachep->num = 0;

	/*
	 * Always use on-slab management when SLAB_NOLEAKTRACE
	 * to avoid recursive calls into kmemleak.
	 */
	if (flags & SLAB_NOLEAKTRACE)
		return false;

	/*
	 * Size is large, assume best to place the slab management obj
	 * off-slab (should allow better packing of objs).
	 */
	left = calculate_slab_order(cachep, size, flags | CFLGS_OFF_SLAB);
	if (!cachep->num)
		return false;

	/*
	 * If the slab has been placed off-slab, and we have enough space then
	 * move it on-slab. This is at the expense of any extra colouring.
	 */
	if (left >= cachep->num * sizeof(freelist_idx_t))
		return false;

	cachep->colour = left / cachep->colour_off;

	return true;
}

static bool set_on_slab_cache(struct kmem_cache *cachep,
			size_t size, slab_flags_t flags)
{
	size_t left;

	cachep->num = 0;

	left = calculate_slab_order(cachep, size, flags);
	if (!cachep->num)
		return false;

	cachep->colour = left / cachep->colour_off;

	return true;
}
```