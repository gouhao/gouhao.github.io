# slub结构体
源码基于5.10

```c
struct kmem_cache {
	struct kmem_cache_cpu __percpu *cpu_slab; // percpu slub
	/* Used for retrieving partial slabs, etc. */
	slab_flags_t flags;
	unsigned long min_partial;
	unsigned int size;	// 对象的大小，包含填充和调试
	unsigned int object_size; // 对象的大小，只包含填充
	struct reciprocal_value reciprocal_size; // 大小的倒数，方便计算一个slab里能存几个对象
	unsigned int offset;	// 空闲指针偏移量
#ifdef CONFIG_SLUB_CPU_PARTIAL
	// cpu部分缓存数量
	unsigned int cpu_partial;
#endif
	// 对象数量的阶数，kmem_cache_order_objects是个int
	struct kmem_cache_order_objects oo;

	// 最大对象数量的阶数
	struct kmem_cache_order_objects max;
	// 最小对象数量的阶数
	struct kmem_cache_order_objects min;
	gfp_t allocflags;	// 分配对象的标志
	int refcount;		// 引用计数
	void (*ctor)(void *);	// 构造函数
	unsigned int inuse;	// 正在使用的数量？
	unsigned int align;	// 对齐值
	unsigned int red_left_pad;// 红区填充数量，调试用的
	const char *name;	// slub名称
	struct list_head list;	// 队列指针

	// sys相关
#ifdef CONFIG_SYSFS
	struct kobject kobj;	/* For sysfs */
#endif
#ifdef CONFIG_SLAB_FREELIST_HARDENED
	unsigned long random;
#endif

#ifdef CONFIG_NUMA
	// 从远程结点分配碎片
	unsigned int remote_node_defrag_ratio;
#endif

#ifdef CONFIG_SLAB_FREELIST_RANDOM
	// 空闲列表随机
	unsigned int *random_seq;
#endif

#ifdef CONFIG_KASAN
	// kasan相关
	struct kasan_cache kasan_info;
#endif

	unsigned int useroffset;	/* Usercopy region offset */
	unsigned int usersize;		/* Usercopy region size */

	// node结点
	struct kmem_cache_node *node[MAX_NUMNODES];
};

struct kmem_cache_cpu {
	void **freelist; // 指向下一个可用的对象
	unsigned long tid; // 全局唯一事务id
	struct page *page; // 正在分配的slub页
#ifdef CONFIG_SLUB_CPU_PARTIAL
	struct page *partial; // 部分被分配的slub页
#endif
#ifdef CONFIG_SLUB_STATS
	unsigned stat[NR_SLUB_STAT_ITEMS]; // 统计相关
#endif
};

struct kmem_cache_node {
	spinlock_t list_lock;
	// 这里的成员和slab一样
...

#ifdef CONFIG_SLUB
	unsigned long nr_partial; // 部分缓存数量
	struct list_head partial; // 部分缓存列表
#ifdef CONFIG_SLUB_DEBUG
	atomic_long_t nr_slabs;
	atomic_long_t total_objects;
	struct list_head full;
#endif
#endif

};
```