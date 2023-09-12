# slub-kmalloc
slub的实现，源码基于5.10。  

slab和slub由于共用一些函数，所以有些共用的函数我会指出来，不会在此在写一遍。

## kmalloc
slub和slab的kmalloc函数是一样的，调用到__kmalloc开始区分，所以这里从kmalloc开始看
```c
void *__kmalloc(size_t size, gfp_t flags)
{
	struct kmem_cache *s;
	void *ret;

	// 超过最大值。在slub时KMALLOC_MAX_CACHE_SIZE为 1<<(PAGE_SHIFT + 1)
	// 也就是大于一页的值直接调用buddy分配
	if (unlikely(size > KMALLOC_MAX_CACHE_SIZE))
		return kmalloc_large(size, flags);

	// 找到size对应的cache，这个函数和slab共用的
	s = kmalloc_slab(size, flags);

	if (unlikely(ZERO_OR_NULL_PTR(s)))
		return s;

	// 分配对象
	ret = slab_alloc(s, flags, _RET_IP_);

	trace_kmalloc(_RET_IP_, ret, size, s->size, flags);

	ret = kasan_kmalloc(s, ret, size, flags);

	return ret;
}

static __always_inline void *slab_alloc(struct kmem_cache *s,
		gfp_t gfpflags, unsigned long addr)
{
	// NUMA_NO_NODE表示不限制node
	return slab_alloc_node(s, gfpflags, NUMA_NO_NODE, addr);
}

static __always_inline void *slab_alloc_node(struct kmem_cache *s,
		gfp_t gfpflags, int node, unsigned long addr)
{
	void *object;
	struct kmem_cache_cpu *c;
	struct page *page;
	unsigned long tid;
	struct obj_cgroup *objcg = NULL;

	// hook相关，主要是提前判断本次分配是否会失败，
	// 一般都会返回s。todo: hook后面再看
	s = slab_pre_alloc_hook(s, &objcg, 1, gfpflags);
	if (!s)
		return NULL;
redo:
	// 获取当前percpu对象
	// 这是无锁并发，用循环是在抢占过程中，对象可能会变
	do {
		tid = this_cpu_read(s->cpu_slab->tid);
		c = raw_cpu_ptr(s->cpu_slab);
	} while (IS_ENABLED(CONFIG_PREEMPTION) &&
		 unlikely(tid != READ_ONCE(c->tid)));

	// 内在栅栏，确保不会乱序
	barrier();

	// 取一个空闲对象
	object = c->freelist;
	// 对象所在的页
	page = c->page;

	// (obj为空 || page为空 || 与期望分配的node不匹配)成立时，会走慢速路径
	if (unlikely(!object || !page || !node_match(page, node))) {
		// 慢速路径。分配失败，从slab里分配？
		object = __slab_alloc(s, gfpflags, node, addr, c);
	} else {
		// 走到这儿，表示可以从快速路径分配。一般情况下，都会走这儿

		// 下一个对象的指针，get_freepointer_safe就是object + s->offset
		void *next_object = get_freepointer_safe(s, object);

		// 把freelist和tid分配设置为next_object， next_tid(tid)
		// cmpxchg返回0,表示没有设置成功，出现了并发情况，需要重新分配
		if (unlikely(!this_cpu_cmpxchg_double(
				s->cpu_slab->freelist, s->cpu_slab->tid,
				object, tid,
				next_object, next_tid(tid)))) {

			note_cmpxchg_failure("slab_alloc", s, tid);
			goto redo;
		}
		// 这个函数只有一句代码，prefetch(object + s->offset);
		// 预取next_object的下一个对象
		prefetch_freepointer(s, next_object);
		// 统计从快速路径获取成功
		stat(s, ALLOC_FASTPATH);
	}

	// 清除对象的next指针，如果需要的话
	maybe_wipe_obj_freeptr(s, object);

	// 对象需要被初始化。todo: 这里为什么不用s->size，因为size才是包括填充的真实大小
	if (unlikely(slab_want_init_on_alloc(gfpflags, s)) && object)
		memset(object, 0, s->object_size);

	// 分配完的hook，todo：这个hook没太看懂
	slab_post_alloc_hook(s, objcg, gfpflags, 1, &object);

	return object;
}

static inline void *get_freepointer_safe(struct kmem_cache *s, void *object)
{
	unsigned long freepointer_addr;
	void *p;

	if (!debug_pagealloc_enabled_static())
		return get_freepointer(s, object);

	freepointer_addr = (unsigned long)object + s->offset;
	copy_from_kernel_nofault(&p, (void **)freepointer_addr, sizeof(p));
	return freelist_ptr(s, p, freepointer_addr);
}

static inline void *get_freepointer(struct kmem_cache *s, void *object)
{
	return freelist_dereference(s, object + s->offset);
}

static inline void *freelist_dereference(const struct kmem_cache *s,
					 void *ptr_addr)
{
	return freelist_ptr(s, (void *)*(unsigned long *)(ptr_addr),
			    (unsigned long)ptr_addr);
}

static inline void *freelist_ptr(const struct kmem_cache *s, void *ptr,
				 unsigned long ptr_addr)
{
#ifdef CONFIG_SLAB_FREELIST_HARDENED
	/*
	 * When CONFIG_KASAN_SW_TAGS is enabled, ptr_addr might be tagged.
	 * Normally, this doesn't cause any issues, as both set_freepointer()
	 * and get_freepointer() are called with a pointer with the same tag.
	 * However, there are some issues with CONFIG_SLUB_DEBUG code. For
	 * example, when __free_slub() iterates over objects in a cache, it
	 * passes untagged pointers to check_object(). check_object() in turns
	 * calls get_freepointer() with an untagged pointer, which causes the
	 * freepointer to be restored incorrectly.
	 */
	return (void *)((unsigned long)ptr ^ s->random ^
			swab((unsigned long)kasan_reset_tag((void *)ptr_addr)));
#else
	return ptr;
#endif
}


static __always_inline void maybe_wipe_obj_freeptr(struct kmem_cache *s,
						   void *obj)
{
	// 清除对象的空闲指针位置上的数据，直接就把offset上的值置为0
	if (unlikely(slab_want_init_on_free(s)) && obj)
		memset((void *)((char *)obj + s->offset), 0, sizeof(void *));
}
```
分配内存分为快速和慢速路径。快速路径直接从percpu里分配，slub的percpu缓存是struct kmem_cache_cpu对象，这个对象里保存有freelist，这个是指向下一个空闲的对象。如果percpu可用，就直接从它里面分配，然后再修改freelist指针就返回。

## 慢速路径
慢速路径可能要经过buddy系统，也有可能要睡眠。
```c
static void *__slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
			  unsigned long addr, struct kmem_cache_cpu *c)
{
	void *p;
	unsigned long flags;

	// 关中断
	local_irq_save(flags);
#ifdef CONFIG_PREEMPTION
	// 在禁用中断之前，可能被抢占，所以这里要重新获取cpu指针
	c = this_cpu_ptr(s->cpu_slab);
#endif

	// 真正的分配
	p = ___slab_alloc(s, gfpflags, node, addr, c);

	// 开中断
	local_irq_restore(flags);
	return p;
}

static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
			  unsigned long addr, struct kmem_cache_cpu *c)
{
	void *freelist;
	struct page *page;

	// 统计慢速路径
	stat(s, ALLOC_SLOWPATH);

	page = c->page;

	// 如果page为空，需要新分配一个slab
	if (!page) {
		// 如果要求的node不是正常状态的内存，则忽略限制
		if (unlikely(node != NUMA_NO_NODE &&
			     !node_state(node, N_NORMAL_MEMORY)))
			node = NUMA_NO_NODE;
		goto new_slab;
	}

redo:
	// 走到这儿表示percpu里的page不为空，因为经过前面的关中断有可能其他人已经分配了page

	// page所在的node与期望的node不一致
	if (unlikely(!node_match(page, node))) {
		if (!node_state(node, N_NORMAL_MEMORY)) {
			// 所期望的node不正常，则忽略node限制
			node = NUMA_NO_NODE;
			// 去redo从来一遍，第2次就走到了后面了
			goto redo;
		} else {
			// 走到这里，说明当前percpu里的page与要求的node不同
			stat(s, ALLOC_NODE_MISMATCH);
			// 把当前percpu里的slub移动部分缓存列表，
			// 或者如果没有人用了就释放掉该slab
			deactivate_slab(s, page, c->freelist, c);
			// 然后重新分配一个
			goto new_slab;
		}
	}

	// 走到这儿表示page是合适的，可以直接在上面分配

	// todo: pfmemalloc后面再看
	// 这个分支大多数情况都不会走
	if (unlikely(!pfmemalloc_match(page, gfpflags))) {
		deactivate_slab(s, page, c->freelist, c);
		goto new_slab;
	}

	// 获取percpu的空闲列表
	freelist = c->freelist;

	// 如果已经有空闲对象，则直接加载
	if (freelist)
		goto load_freelist;

	// 走到这儿，表示percpu的空闲列表为NULL或者不可用，需要获取page的freelist

	// 获取page的freelist
	freelist = get_freelist(s, page);

	// 如果freelist为空，重新分配一个slab
	if (!freelist) {
		c->page = NULL;
		stat(s, DEACTIVATE_BYPASS);
		goto new_slab;
	}

	// 走到这儿表示freelist不为空

	// 统计重新填充
	stat(s, ALLOC_REFILL);

load_freelist:
	// 页必须是冻结的？
	VM_BUG_ON(!c->page->frozen);

	// 下面两个赋值与快速路径里的不同，快速路径里用的是原子操作, 这里之所以可以这样
	// 赋值，是因为前面已经关了中断，且这是percpu变量，所以不会有并行的情况

	// 设置percpu的空闲对象列表为下一个对象，因为当前这个对象要被用了
	c->freelist = get_freepointer(s, freelist);
	// 设置tid为下一个id
	c->tid = next_tid(c->tid);

	// 分配成功，返回该对象
	return freelist;

new_slab:

	// 如果cpu有部分使用的slub，则优先用它
	if (slub_percpu_partial(c)) {
		// 如果有部分使用的页，就优先使用该页
		page = c->page = slub_percpu_partial(c);

		// 设置c->partial为部分使用列表的下一个结点
		slub_set_percpu_partial(c, page);

		// 统计从partial分配
		stat(s, CPU_PARTIAL_ALLOC);

		// 再重新获取
		goto redo;
	}

	// 走到这儿表示部分列表为空或才部分列表不可用

	// 新分配一个slab对象
	freelist = new_slab_objects(s, gfpflags, node, &c);

	// 没有分配到新对象，那就是内存不够用了
	if (unlikely(!freelist)) {
		slab_out_of_memory(s, gfpflags, node);
		return NULL;
	}

	page = c->page;

	// 分配页成功，重新加载空闲列表
	if (likely(!kmem_cache_debug(s) && pfmemalloc_match(page, gfpflags)))
		goto load_freelist;

	// 如果走到这儿，那就是哪儿出错了。一般不会走这儿

	// 调试相关
	if (kmem_cache_debug(s) &&
			!alloc_debug_processing(s, page, freelist, addr))
		goto new_slab;	/* Slab failed checks. Next slab needed */

	// 走到这儿就是哪儿出错了，要释放slab
	deactivate_slab(s, page, get_freepointer(s, freelist), c);
	return freelist;
}
```
慢速路径主要流程是：
1. 判断percpu缓存是否可用
2. 如果percpu缓存不可用的话，重新分配一个slab对象。在重新分配slab时，如果开启的部分缓存，会优先从部分缓存里面分配可用对象
3. 如果1或2成功，则分配一个对象返回

假设percpu里的page是空的，先走new_slab的处理流程。在new_slab里会先判断percpu的部分缓存，这里假设部分缓存也是空的，就走到了真正分配slab对象的new_slab_objects函数。

## new_slab_objects

```c
static inline void *new_slab_objects(struct kmem_cache *s, gfp_t flags,
			int node, struct kmem_cache_cpu **pc)
{
	void *freelist;
	struct kmem_cache_cpu *c = *pc;
	struct page *page;

	// 有构造函数还清空，打印警告
	WARN_ON_ONCE(s->ctor && (flags & __GFP_ZERO));

	// 获取partial，如果分配到了，就直接返回
	// 注意：这里的partial是从kmem_cache_node里获取，和上面的percpu partial不同
	freelist = get_partial(s, flags, node, c);

	// 从部分缓存获取成功，就直接返回
	if (freelist)
		return freelist;

	// 走到这儿，就要从buddy系统分配一个slab
	page = new_slab(s, flags, node);
	if (page) {
		c = raw_cpu_ptr(s->cpu_slab);
		// 如果c->page已经有值，先释放它？
		if (c->page)
			flush_slab(s, c);

		freelist = page->freelist;
		// 把page的freelist设为NULL，因为返回之后要使用cpu_slab的freelist
		page->freelist = NULL;

		stat(s, ALLOC_SLAB);
		// 设置新的page对象
		c->page = page;
		*pc = c;
	}

	return freelist;
}
```
new_slab_objects是要分配一个新的slab对象，这个函数里有2个主要的流程：
1. 从kmem_cache_node的部分缓存里分配
2. 如果第1步失败，从buddy系统里分配一个slab

### 从partial里分配
```c
static void *get_partial(struct kmem_cache *s, gfp_t flags, int node,
		struct kmem_cache_cpu *c)
{
	void *object;
	int searchnode = node;

	// 如果不限制node，就把node设置成当前节点
	if (node == NUMA_NO_NODE)
		searchnode = numa_mem_id();

	// get_node是获取第2个参数对应的node对象
	object = get_partial_node(s, get_node(s, searchnode), c, flags);
	if (object || node != NUMA_NO_NODE)
		return object;

	// 走到这儿，说明在当前node上对象获取失败，但是允许在其它node上获取部分缓存
	return get_any_partial(s, flags, c);
}

static void *get_partial_node(struct kmem_cache *s, struct kmem_cache_node *n,
				struct kmem_cache_cpu *c, gfp_t flags)
{
	struct page *page, *page2;
	void *object = NULL;
	unsigned int available = 0;
	int objects;

	// 没有partial，直接返回
	if (!n || !n->nr_partial)
		return NULL;

	spin_lock(&n->list_lock);
	// 遍历部分列表里的slab，从node的部分列表里，给cpu的部分列表里转移一些对象
	list_for_each_entry_safe(page, page2, &n->partial, slab_list) {
		void *t;

		// todo: pfmemalloc后面看，一般都会返回成功
		if (!pfmemalloc_match(page, flags))
			continue;

		// 获取partial里的一个slab, objects带回可用对象数
		t = acquire_slab(s, n, page, object == NULL, &objects);
		if (!t)
			break;

		// 总的可用数量
		available += objects;

		// object为空，表示需要分配一个对象
		if (!object) {
			// 能走到这个函数，percpu肯定是空的，所以设置percpu使用该slab
			c->page = page;
			// 统计从部分里分配
			stat(s, ALLOC_FROM_PARTIAL);
			// 使用第1个对象做为object
			object = t;
		} else {
			// 对象已经分配了，则把它放到cpu部分列表里，
			// 注意最后一个参数是0,表示如果不合适，则不排出slub对象
			put_cpu_partial(s, page, 0);
			stat(s, CPU_PARTIAL_NODE);
		}
		// 当可用对象大于percpu部分缓存限制的一半时退出循环
		if (!kmem_cache_has_cpu_partial(s)
			|| available > slub_cpu_partial(s) / 2)
			break;

	}
	spin_unlock(&n->list_lock);
	return object;
}

static inline void *acquire_slab(struct kmem_cache *s,
		struct kmem_cache_node *n, struct page *page,
		int mode, int *objects)
{
	void *freelist;
	unsigned long counters;
	struct page new;

	lockdep_assert_held(&n->list_lock);

	freelist = page->freelist;
	counters = page->counters;
	new.counters = counters;

	// 总数量减去正在使用的就是剩余对象数
	*objects = new.objects - new.inuse;

	// mode表示上面的object是否为空，也就是是否要分配一个新的对象
	// mode为1，表示需要分配
	if (mode) {
		new.inuse = page->objects;
		new.freelist = NULL;
	} else {
		// 不分配的话，还是把freelist放到page里
		new.freelist = freelist;
	}

	// 放到node里的page应该是没有冻住的
	VM_BUG_ON(new.frozen);
	// 冻结
	new.frozen = 1;

	// 设置page->freelist为new.freelist，和counters
	if (!__cmpxchg_double_slab(s, page,
			freelist, counters,
			new.freelist, new.counters,
			"acquire_slab"))
		return NULL;

	// 把page从node的partial里删除
	remove_partial(n, page);
	WARN_ON(!freelist);
	return freelist;
}

static inline void remove_partial(struct kmem_cache_node *n,
					struct page *page)
{
	lockdep_assert_held(&n->list_lock);
	// 把page从slab列表删除
	list_del(&page->slab_list);
	// 递减计数
	n->nr_partial--;
}

static void *get_any_partial(struct kmem_cache *s, gfp_t flags,
		struct kmem_cache_cpu *c)
{
#ifdef CONFIG_NUMA
	struct zonelist *zonelist;
	struct zoneref *z;
	struct zone *zone;
	// 最高可用的zone
	enum zone_type highest_zoneidx = gfp_zone(flags);
	void *object;
	unsigned int cpuset_mems_cookie;

	// remote_node_defrag_ratio是限制从其它结点分配的配置
	if (!s->remote_node_defrag_ratio ||
			get_cycles() % 1024 > s->remote_node_defrag_ratio)
		return NULL;

	do {
		cpuset_mems_cookie = read_mems_allowed_begin();
		zonelist = node_zonelist(mempolicy_slab_node(), flags);
		for_each_zone_zonelist(zone, z, zonelist, highest_zoneidx) {
			struct kmem_cache_node *n;

			// 获取zone对应的结点
			n = get_node(s, zone_to_nid(zone));

			// 如果该node上的部分缓存比最小的部分缓存大
			if (n && cpuset_zone_allowed(zone, flags) &&
					n->nr_partial > s->min_partial) {
				// 从该node上的部分缓存给percpu部分缓存转移一些slub对象
				object = get_partial_node(s, n, c, flags);
				// 如果分配成功，则返回对象
				if (object) {
					return object;
				}
			}
		}
	} while (read_mems_allowed_retry(cpuset_mems_cookie));
#endif	/* CONFIG_NUMA */
	return NULL;
}
```

### 从buddy系统里分配
```c
static struct page *new_slab(struct kmem_cache *s, gfp_t flags, int node)
{
	// 调试相关
	if (unlikely(flags & GFP_SLAB_BUG_MASK))
		flags = kmalloc_fix_flags(flags);

	// 真正分配一个slab
	return allocate_slab(s,
		flags & (GFP_RECLAIM_MASK | GFP_CONSTRAINT_MASK), node);
}


static struct page *allocate_slab(struct kmem_cache *s, gfp_t flags, int node)
{
	struct page *page;
	struct kmem_cache_order_objects oo = s->oo;
	gfp_t alloc_gfp;
	void *start, *p, *next;
	int idx;
	bool shuffle;

	// 过滤flag
	flags &= gfp_allowed_mask;

	// 是否有__GFP_DIRECT_RECLAIM标志，有此标志，则开中断
	if (gfpflags_allow_blocking(flags))
		local_irq_enable();

	flags |= s->allocflags;

	// 不警告，不重试，允许失败
	alloc_gfp = (flags | __GFP_NOWARN | __GFP_NORETRY) & ~__GFP_NOFAIL;
	if ((alloc_gfp & __GFP_DIRECT_RECLAIM) && oo_order(oo) > oo_order(s->min))
		alloc_gfp = (alloc_gfp | __GFP_NOMEMALLOC) & ~(__GFP_RECLAIM|__GFP_NOFAIL);

	// 调用buddy系统的接口分配oo_order(oo)阶数的页面
	page = alloc_slab_page(s, alloc_gfp, node, oo);
	if (unlikely(!page)) {
		// 如果分配失败了，则使用min order再尝试分配页
		// min是容纳一个对象的order
		oo = s->min;
		alloc_gfp = flags;
		// 分配页
		page = alloc_slab_page(s, alloc_gfp, node, oo);
		if (unlikely(!page))
			// 还是分配失败就退出
			goto out;
		
		// 统计
		stat(s, ORDER_FALLBACK);
	}

	// oo_objects返回的是oo里可以存储的对象数
	page->objects = oo_objects(oo);

	// 设置slab_cache的反引用
	page->slab_cache = s;
	// 设置页的slab标志
	__SetPageSlab(page);

	// 如果page->index == -1
	if (page_is_pfmemalloc(page))
		SetPageSlabPfmemalloc(page);

	// kasan没开时，是空语句
	kasan_poison_slab(page);

	// 页的地址
	start = page_address(page);

	// 调试
	setup_page_debug(s, page, start);

	// 如果需要，则把freelist打乱
	shuffle = shuffle_freelist(s, page);

	// 如果没有打乱，就按正常的顺序排序
	if (!shuffle) {

		// 没打开调试时，还是返回start
		start = fixup_red_left(s, start);
		// setup_object里最主要的是，调用构造函数，如果有的话。以及调用kasan相关,
		// 可以认为返回的还是start
		start = setup_object(s, page, start);
		page->freelist = start;
		// 下面这个循环是设置page的freelist
		for (idx = 0, p = start; idx < page->objects - 1; idx++) {
			// 下一个对象的位置
			next = p + s->size;
			next = setup_object(s, page, next);
			// 设置p的next指针为next
			set_freepointer(s, p, next);
			p = next;
		}
		// 设置最后的next指针为NULL
		set_freepointer(s, p, NULL);
	}

	// 可使用的对象数
	page->inuse = page->objects;
	// 页冻住
	page->frozen = 1;

out:
	// 关中断，和上面对应
	if (gfpflags_allow_blocking(flags))
		local_irq_disable();
	// 没分配到page，返回空
	if (!page)
		return NULL;

	// 统计slab数量和总共对象数
	inc_slabs_node(s, page_to_nid(page), page->objects);

	return page;
}

static inline struct page *alloc_slab_page(struct kmem_cache *s,
		gfp_t flags, int node, struct kmem_cache_order_objects oo)
{
	struct page *page;
	unsigned int order = oo_order(oo);

	if (node == NUMA_NO_NODE)
		page = alloc_pages(flags, order);
	else
		page = __alloc_pages_node(node, flags, order);

	if (page)
		account_slab_page(page, order, s);

	return page;
}

static bool shuffle_freelist(struct kmem_cache *s, struct page *page)
{
	void *start;
	void *cur;
	void *next;
	unsigned long idx, pos, page_limit, freelist_count;

	// 如果只有一个元素或者随机数组没有初始化，则直接退出
	if (page->objects < 2 || !s->random_seq)
		return false;

	// 对象数量
	freelist_count = oo_objects(s->oo);
	// 随机数
	pos = get_random_int() % freelist_count;

	// 对象总大小？
	page_limit = page->objects * s->size;
	// 调试，相当于空语句
	start = fixup_red_left(s, page_address(page));

	// 第一个对象被用作slab的基址
	cur = next_freelist_entry(s, page, &pos, start, page_limit,
				freelist_count);
	// 调用构造函数
	cur = setup_object(s, page, cur);
	// 设置freelist指针
	page->freelist = cur;

	// 初始化其余对象，并链成表
	for (idx = 1; idx < page->objects; idx++) {
		next = next_freelist_entry(s, page, &pos, start, page_limit,
			freelist_count);
		next = setup_object(s, page, next);
		set_freepointer(s, cur, next);
		cur = next;
	}
	// 最后指针指向NULL
	set_freepointer(s, cur, NULL);

	return true;
}

static void *next_freelist_entry(struct kmem_cache *s, struct page *page,
				unsigned long *pos, void *start,
				unsigned long page_limit,
				unsigned long freelist_count)
{
	unsigned int idx;

	// 获取下一个随机值
	do {
		idx = s->random_seq[*pos];
		*pos += 1;
		if (*pos >= freelist_count)
			*pos = 0;
	} while (unlikely(idx >= page_limit));

	// 获取下一个对象
	return (char *)start + idx;
}

static inline void set_freepointer(struct kmem_cache *s, void *object, void *fp)
{
	unsigned long freeptr_addr = (unsigned long)object + s->offset;

#ifdef CONFIG_SLAB_FREELIST_HARDENED
	BUG_ON(object == fp); /* naive detection of double free or corruption */
#endif

	// 没有调试时，freelist_ptr返回fp
	*(void **)freeptr_addr = freelist_ptr(s, fp, freeptr_addr);
}

```

## get_freelist
```c
static inline void *get_freelist(struct kmem_cache *s, struct page *page)
{
	struct page new;
	unsigned long counters;
	void *freelist;

	// 下面这个循环是无锁并发，大多数情况只执行一次
	do {
		// page里保存的空闲列表
		freelist = page->freelist;
		// 计数
		counters = page->counters;

		new.counters = counters;

		/*
		union {
			void *s_mem;	
			unsigned long counters;		
			struct {			
				unsigned inuse:16;
				unsigned objects:15;
				unsigned frozen:1;
			};
		};
		counters和frozen是一个联合，frozen是在最高位。这里要求frozen必须为1
		*/
		VM_BUG_ON(!new.frozen);

		// 可使用的是对象数
		new.inuse = page->objects;
		// freelist不为空说明是冻结的？
		new.frozen = freelist != NULL;

	// 把page->freelist = NULL, page->counters = new.counters
	} while (!__cmpxchg_double_slab(s, page,
		freelist, counters,
		NULL, new.counters,
		"get_freelist"));

	return freelist;
}
```

## deactivate_slab
```c
static void deactivate_slab(struct kmem_cache *s, struct page *page,
				void *freelist, struct kmem_cache_cpu *c)
{
	enum slab_modes { M_NONE, M_PARTIAL, M_FULL, M_FREE };
	struct kmem_cache_node *n = get_node(s, page_to_nid(page));
	int lock = 0;
	enum slab_modes l = M_NONE, m = M_NONE;
	void *nextfree;
	int tail = DEACTIVATE_TO_HEAD;
	struct page new;
	struct page old;

	// 如果page的空闲列表有值，说明当前这个page还在用
	if (page->freelist) {
		stat(s, DEACTIVATE_REMOTE_FREES);
		// todo: 为什么要加到尾部
		tail = DEACTIVATE_TO_TAIL;
	}

	// 下面这个循环会把freelist列表，复制到page的freelist里
	// freelist里存的是还没用的对象，这一页里可能有对象还在使用，所以把没用的先放到page的freelist里
	while (freelist && (nextfree = get_freepointer(s, freelist))) {
		void *prior;
		unsigned long counters;

		// 如果空闲列表错误，直接跳出
		if (freelist_corrupted(s, page, &freelist, nextfree))
			break;

		do {
			prior = page->freelist;
			counters = page->counters;
			// 把freelist链到prior前面
			set_freepointer(s, freelist, prior);
			new.counters = counters;
			// 正在使用的对象减１。todo: why?
			new.inuse--;
			VM_BUG_ON(!new.frozen);

		} while (!__cmpxchg_double_slab(s, page,
			prior, counters,
			freelist, new.counters,
			"drain percpu freelist"));

		freelist = nextfree;
	}

redo:

	old.freelist = page->freelist;
	old.counters = page->counters;
	VM_BUG_ON(!old.frozen);

	new.counters = old.counters;
	if (freelist) {
		// freelist不空，则说明是原来freelist里的最后一个对象
		// 把最后一个对象加到page->freelist前面
		new.inuse--;
		set_freepointer(s, freelist, old.freelist);
		new.freelist = freelist;
	} else
		// freelist为空，说明上面的循环就没有走
		// 假设freelist是最后一个对象，nextfree就是NULL, 上面的循环不会走，也不会走这个分支
		// 所以只有freelist为空才会走到这里
		new.freelist = old.freelist;

	// 解冻
	new.frozen = 0;

	if (!new.inuse && n->nr_partial >= s->min_partial)
		// 如果已经没有在用的对象，而且部分slub已经超过限制值，则释放
		m = M_FREE;
	
	// 如果上面if不成立，说明 有对象在用 || 部分page没有超过限制
	else if (new.freelist) {
		// 空闲列表有值，证明一部分在用，先加到部分列表里
		m = M_PARTIAL;
		// 加锁
		if (!lock) {
			lock = 1;
			spin_lock(&n->list_lock);
		}
	} else {
		// 空闲列表没有值，说明全部在用
		m = M_FULL;
#ifdef CONFIG_SLUB_DEBUG
		// SLAB_STORE_USER：保存最后一个用户，为了捕获bug
		// 加锁
		if ((s->flags & SLAB_STORE_USER) && !lock) {
			lock = 1;
			spin_lock(&n->list_lock);
		}
#endif
	}

	// 状态不一样，则根据不同状态执行不同操作
	// 第一次进来时l是M_NONE, m的状态肯定和l不一样，因为在经过上面的if块后，最少m也会等于M_FULL,
	// 在冲突时，l记录的是m的状态，用来把之前执行的操作先回退，再重新执行
	if (l != m) {
		
		if (l == M_PARTIAL)
			remove_partial(n, page);
		else if (l == M_FULL)
			remove_full(s, n, page);

		if (m == M_PARTIAL)
			// 加到node的部分slub
			add_partial(n, page, tail);
		else if (m == M_FULL)
			// 加到full列表，这个是打开SLUB_DEBUG时才有用
			add_full(s, n, page);
	}

	l = m;
	// old记录的是page的值，所以这里是给原来的page设置值，
	// 如果设置失败，说明冲突了，再重新设置一次
	if (!__cmpxchg_double_slab(s, page,
				old.freelist, old.counters,
				new.freelist, new.counters,
				"unfreezing slab"))
		goto redo;

	if (lock)
		spin_unlock(&n->list_lock);

	// 对各种状态执行统计
	if (m == M_PARTIAL)
		stat(s, tail);
	else if (m == M_FULL)
		stat(s, DEACTIVATE_FULL);
	else if (m == M_FREE) {
		stat(s, DEACTIVATE_EMPTY);
		// 如果需要释放，才把page最终还给buddy系统
		discard_slab(s, page);
		stat(s, FREE_SLAB);
	}

	// 重置cpucache的各个值
	c->page = NULL;
	c->freelist = NULL;
	c->tid = next_tid(c->tid);
}

static bool freelist_corrupted(struct kmem_cache *s, struct page *page,
			       void **freelist, void *nextfree)
{
	if ((s->flags & SLAB_CONSISTENCY_CHECKS) &&
	    !check_valid_pointer(s, page, nextfree) && freelist) {
		object_err(s, page, *freelist, "Freechain corrupt");
		*freelist = NULL;
		// 这是打印日志
		slab_fix(s, "Isolate corrupted freechain");
		return true;
	}

	return false;
}

static inline int check_valid_pointer(struct kmem_cache *s,
				struct page *page, void *object)
{
	void *base;

	if (!object)
		return 1;

	base = page_address(page);
	object = kasan_reset_tag(object);
	object = restore_red_left(s, object);

	// obj小于页的地址　|| obj大于slub的最大地址 || obj没有对齐到size的长度
	// 上面这３种情况都是地址非法的
	if (object < base || object >= base + page->objects * s->size ||
		(object - base) % s->size) {
		return 0;
	}

	return 1;
}

static inline void add_partial(struct kmem_cache_node *n,
				struct page *page, int tail)
{
	lockdep_assert_held(&n->list_lock);
	__add_partial(n, page, tail);
}

static inline void
__add_partial(struct kmem_cache_node *n, struct page *page, int tail)
{
	// 加到部分列表
	n->nr_partial++;
	if (tail == DEACTIVATE_TO_TAIL)
		list_add_tail(&page->slab_list, &n->partial);
	else
		list_add(&page->slab_list, &n->partial);
}

static void add_full(struct kmem_cache *s,
	struct kmem_cache_node *n, struct page *page)
{
	if (!(s->flags & SLAB_STORE_USER))
		return;

	lockdep_assert_held(&n->list_lock);
	list_add(&page->slab_list, &n->full);
}
```