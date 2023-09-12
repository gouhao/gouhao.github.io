# 数据结构
```c
struct kmem_cache {
	// 每cpu指针，指向包含空闲对象的本地高速缓存
	struct array_cache __percpu *cpu_cache;

/* 1) Cache tunables. Protected by slab_mutex */
	unsigned int batchcount; // 每次转移/转出本地高速缓存的对象数量
	unsigned int limit; // 本地高速缓存的最大数目
	unsigned int shared;

	unsigned int size; //对象大小，如果打开调试选项，这里面还包括调试相关的长度，真正对象长度由object_size表示
	struct reciprocal_value reciprocal_buffer_size; // 对象的倒数，用于求解对象的是slab里第几个对象
/* 2) touched by every alloc & free from the backend */

	slab_flags_t flags;		/* 标志 ，管理结构在外部时CFLGS_OFF_SLAB置位*/
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
	int object_size; // 对象大小，包括了左右两边填充的长度
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

	struct kmem_cache_node *node[MAX_NUMNODES]; // 对应于系统里的每个内存结点
};

struct kmem_cache_node {
	spinlock_t list_lock;

#ifdef CONFIG_SLAB
	struct list_head slabs_partial;	// 部分使用的slab
	struct list_head slabs_full; // 完全使用的slab
	struct list_head slabs_free; // 完全空闲的slab
	unsigned long total_slabs; // slab总数
	unsigned long free_slabs; // 空闲slab总数
	unsigned long free_objects; // 空闲对象总数
	unsigned int free_limit; // 空闲限制总数，如果空闲对象超过这个值，就释放？
	unsigned int colour_next; // 下一个着色值
	struct array_cache *shared; // 结点内共享缓存
	struct alien_cache **alien; // 外部缓存
	unsigned long next_reap; // 下一次回收的时间
	int free_touched; // 从空闲列表取出一个slab时，这个值置1，缓存收缩时该值置0
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
	void *entry[];	// percpu缓存的各个对象
};
```