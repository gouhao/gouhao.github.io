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

	flags &= gfp_allowed_mask;
	cachep = slab_pre_alloc_hook(cachep, &objcg, 1, flags);
	if (unlikely(!cachep))
		return NULL;

	cache_alloc_debugcheck_before(cachep, flags);
	local_irq_save(save_flags);
	objp = __do_cache_alloc(cachep, flags);
	local_irq_restore(save_flags);
	objp = cache_alloc_debugcheck_after(cachep, flags, objp, caller);
	prefetchw(objp);

	if (unlikely(slab_want_init_on_alloc(flags, cachep)) && objp)
		memset(objp, 0, cachep->object_size);

	slab_post_alloc_hook(cachep, objcg, flags, 1, &objp);
	return objp;
}
```

## 创建kmem_cache
```c
int __kmem_cache_create(struct kmem_cache *cachep, slab_flags_t flags)
{
	size_t ralign = BYTES_PER_WORD;
	gfp_t gfp;
	int err;
	unsigned int size = cachep->size;

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

	/*
	 * Check that size is in terms of words.  This is needed to avoid
	 * unaligned accesses for some archs when redzoning is used, and makes
	 * sure any on-slab bufctl's are also correctly aligned.
	 */
	size = ALIGN(size, BYTES_PER_WORD);

	if (flags & SLAB_RED_ZONE) {
		ralign = REDZONE_ALIGN;
		/* If redzoning, ensure that the second redzone is suitably
		 * aligned, by adjusting the object size accordingly. */
		size = ALIGN(size, REDZONE_ALIGN);
	}

	/* 3) caller mandated alignment */
	if (ralign < cachep->align) {
		ralign = cachep->align;
	}
	/* disable debug if necessary */
	if (ralign > __alignof__(unsigned long long))
		flags &= ~(SLAB_RED_ZONE | SLAB_STORE_USER);
	/*
	 * 4) Store it.
	 */
	cachep->align = ralign;
	cachep->colour_off = cache_line_size();
	/* Offset must be a multiple of the alignment. */
	if (cachep->colour_off < cachep->align)
		cachep->colour_off = cachep->align;

	if (slab_is_available())
		gfp = GFP_KERNEL;
	else
		gfp = GFP_NOWAIT;

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

	kasan_cache_create(cachep, &size, &flags);

	size = ALIGN(size, cachep->align);
	/*
	 * We should restrict the number of objects in a slab to implement
	 * byte sized index. Refer comment on SLAB_OBJ_MIN_SIZE definition.
	 */
	if (FREELIST_BYTE_INDEX && size < SLAB_OBJ_MIN_SIZE)
		size = ALIGN(SLAB_OBJ_MIN_SIZE, cachep->align);

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
	cachep->freelist_size = cachep->num * sizeof(freelist_idx_t);
	cachep->flags = flags;
	cachep->allocflags = __GFP_COMP;
	if (flags & SLAB_CACHE_DMA)
		cachep->allocflags |= GFP_DMA;
	if (flags & SLAB_CACHE_DMA32)
		cachep->allocflags |= GFP_DMA32;
	if (flags & SLAB_RECLAIM_ACCOUNT)
		cachep->allocflags |= __GFP_RECLAIMABLE;
	cachep->size = size;
	cachep->reciprocal_buffer_size = reciprocal_value(size);

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

	if (OFF_SLAB(cachep)) {
		cachep->freelist_cache =
			kmalloc_slab(cachep->freelist_size, 0u);
	}

	err = setup_cpu_cache(cachep, gfp);
	if (err) {
		__kmem_cache_release(cachep);
		return err;
	}

	return 0;
}
```