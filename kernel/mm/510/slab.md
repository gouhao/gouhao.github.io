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
	if (!usersize)
		s = __kmem_cache_alias(name, size, align, flags, ctor);
	if (s)
		goto out_unlock;

	cache_name = kstrdup_const(name, GFP_KERNEL);
	if (!cache_name) {
		err = -ENOMEM;
		goto out_unlock;
	}

	s = create_cache(cache_name, size,
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
```