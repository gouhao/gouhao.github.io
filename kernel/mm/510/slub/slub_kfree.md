# slub释放内存
slub的实现，源码基于5.10。  
因为在代码里没有区分slab, slub这些名称，所以在本文中也不区分slab, slub，两个都指的是slub的实现。

```c
void kfree(const void *x)
{
	struct page *page;
	void *object = (void *)x;

	// trace
	trace_kfree(_RET_IP_, x);

	// 空指针检查
	if (unlikely(ZERO_OR_NULL_PTR(x)))
		return;

	// 获取地址对象的页
	page = virt_to_head_page(x);

	// 如果不是slab的page
	if (unlikely(!PageSlab(page))) {
		// 获取组合页的order
		unsigned int order = compound_order(page);

		// 不是组合页就报bug
		BUG_ON(!PageCompound(page));
		// 释放的hook
		kfree_hook(object);
		mod_lruvec_page_state(page, NR_SLAB_UNRECLAIMABLE_B,
				      -(PAGE_SIZE << order));
		// 调用buddy系统释放对应的页
		__free_pages(page, order);
		return;
	}
	// 这里是一般情况下slub的释放
	slab_free(page->slab_cache, page, object, NULL, 1, _RET_IP_);
}

static __always_inline void slab_free(struct kmem_cache *s, struct page *page,
				      void *head, void *tail, int cnt,
				      unsigned long addr)
{
	// 调用一些hook处理
	if (slab_free_freelist_hook(s, &head, &tail, &cnt))
		// 进行释放
		do_slab_free(s, page, head, tail, cnt, addr);
}

static __always_inline void do_slab_free(struct kmem_cache *s,
				struct page *page, void *head, void *tail,
				int cnt, unsigned long addr)
{
	// 从上面传下来的tail是空，所以这里tail_obj也是head
	void *tail_obj = tail ? : head;
	struct kmem_cache_cpu *c;
	unsigned long tid;

	/* memcg_slab_free_hook() is already called for bulk free. */
	if (!tail)
		memcg_slab_free_hook(s, &head, 1);
redo:
	// 获取当前的percpu
	do {
		tid = this_cpu_read(s->cpu_slab->tid);
		c = raw_cpu_ptr(s->cpu_slab);
	} while (IS_ENABLED(CONFIG_PREEMPTION) &&
		 unlikely(tid != READ_ONCE(c->tid)));

	// 内存栅栏
	barrier();

	if (likely(page == c->page)) {
		// 快速路径，要释放的对象所在的page就是当前percpu的
		// 获取c的空闲列表
		void **freelist = READ_ONCE(c->freelist);

		// 设置tail_obj的next为freelist，也就是把刚释放的对象放在空闲列表头
		set_freepointer(s, tail_obj, freelist);

		// 设置cpu_slab->freelist为head和相应的tid
		if (unlikely(!this_cpu_cmpxchg_double(
				s->cpu_slab->freelist, s->cpu_slab->tid,
				freelist, tid,
				head, next_tid(tid)))) {

			note_cmpxchg_failure("slab_free", s, tid);
			goto redo;
		}
		// 统计快速路径释放
		stat(s, FREE_FASTPATH);
	} else
		// 要释放的对象对应的page不是当前percpu里的
		__slab_free(s, page, head, tail_obj, cnt, addr);

}

static inline bool slab_free_freelist_hook(struct kmem_cache *s,
					   void **head, void **tail,
					   int *cnt)
{

	void *object;
	// next就是要释放的对象
	void *next = *head;
	// 这里tail传的是NULL
	void *old_tail = *tail ? *tail : *head;
	int rsize;

	/* Head and tail of the reconstructed freelist */
	*head = NULL;
	*tail = NULL;

	do {
		// obj是要释放的对象
		object = next;
		// obj的下一个对象
		next = get_freepointer(s, object);

		// 是否需要在释放的时候初始化，一般都返回false
		if (slab_want_init_on_free(s)) {
			// 重置对象和元数据，但是跳过红区
			memset(object, 0, s->object_size);
			rsize = (s->flags & SLAB_RED_ZONE) ? s->red_left_pad
							   : 0;
			memset((char *)object + s->inuse, 0,
			       s->size - s->inuse - rsize);

		}
		// kasan和调试相关，一般返回false
		if (!slab_free_hook(s, object)) {
			// 把object移到空闲列表
			set_freepointer(s, object, *head);
			*head = object;
			if (!*tail)
				*tail = object;
		} else {
			/*
			 * Adjust the reconstructed freelist depth
			 * accordingly if object's reuse is delayed.
			 */
			--(*cnt);
		}
		// 这里是处理释放多个对象，只释放一个对象的话，只执行一次
	} while (object != old_tail);

	if (*head == *tail)
		*tail = NULL;

	return *head != NULL;
}
```

## 慢速路径
释放同样也有慢速路径
```c
static void __slab_free(struct kmem_cache *s, struct page *page,
			void *head, void *tail, int cnt,
			unsigned long addr)

{
	void *prior;
	int was_frozen;
	struct page new;
	unsigned long counters;
	struct kmem_cache_node *n = NULL;
	unsigned long flags;

	stat(s, FREE_SLOWPATH);

	// debug相关
	if (kmem_cache_debug(s) &&
	    !free_debug_processing(s, page, head, tail, cnt, addr))
		return;

	do {
		// 刚进来的时候n为NULL
		if (unlikely(n)) {
			spin_unlock_irqrestore(&n->list_lock, flags);
			n = NULL;
		}

		// page的空闲列表
		prior = page->freelist;

		// 获取counters是为了把inuse, frozen, objects一次性读进来？
		counters = page->counters;
		// 设置tail的next为prior，也就是把tail加到page的空闲列表前
		set_freepointer(s, tail, prior);

		new.counters = counters;
		was_frozen = new.frozen;
		// 递减正在用数量
		new.inuse -= cnt;

		// (没有正在用的对象 || 之前空闲列表为空) && 没有冻结
		// todo: 什么情况下会符合这个条件？
		if ((!new.inuse || !prior) && !was_frozen) {
			// kmem_cache_has_cpu_partial一般返回true
			if (kmem_cache_has_cpu_partial(s) && !prior) {
				// page的空闲列表为空，说明slub里有的对象还在用，所以先冻住
				new.frozen = 1;

			} else {
				// 这个是!new.inuse的情况，说明没有正在用的对象

				n = get_node(s, page_to_nid(page));
				// 给page对应的node上锁，解锁在上面循环开始的地方
				// 之锁以要上锁，因为后面有可能要释放？
				spin_lock_irqsave(&n->list_lock, flags);

			}
		}

		// 设置page的空闲列表头为head，这个循环大多数情况下只执行一遍，
		// 之所以用循环是为了无锁并发
	} while (!cmpxchg_double_slab(s, page,
		prior, counters,
		head, new.counters,
		"__slab_free"));

	// 大多数情况下n都是NULL, 表示这个slab还在用
	if (likely(!n)) {

		if (likely(was_frozen)) {
			stat(s, FREE_FROZEN);
		} else if (new.frozen) {
			// new.frozen为1，表示还在用，但是之前的frozen为0
			// 所以把它放到cpu的部分使用列表里
			put_cpu_partial(s, page, 1);
			stat(s, CPU_PARTIAL_FREE);
		}

		return;
	}

	// 走到这儿，表示n不为空，说明slab不再使用

	// new 如果没有使用的，就需要把整个new加到部分缓存里，
	// 但是如果部分缓存的数量超过了限制，就释放
	if (unlikely(!new.inuse && n->nr_partial >= s->min_partial))
		goto slab_empty;

	// 如果prior则把它加到部分列表，todo: 没太看懂这个条件
	if (!kmem_cache_has_cpu_partial(s) && unlikely(!prior)) {
		// 调试相关先从full列表移除
		remove_full(s, n, page);
		// 加到部分列表的末尾。todo: 新加入的为什么要放到末尾？
		add_partial(n, page, DEACTIVATE_TO_TAIL);
		stat(s, FREE_ADD_PARTIAL);
	}
	spin_unlock_irqrestore(&n->list_lock, flags);
	return;

slab_empty:

	if (prior) {
		// freelist不为空，说明有部分在用，把page从部分列表删除
		remove_partial(n, page);
		stat(s, FREE_REMOVE_PARTIAL);
	} else {
		// freelist为空，说明整个slab没有在用。把slab从full列表删除
		remove_full(s, n, page);
	}

	spin_unlock_irqrestore(&n->list_lock, flags);
	stat(s, FREE_SLAB);
	// 释放slab
	discard_slab(s, page);
}

static void put_cpu_partial(struct kmem_cache *s, struct page *page, int drain)
{
#ifdef CONFIG_SLUB_CPU_PARTIAL
	struct page *oldpage;
	int pages;
	int pobjects;

	preempt_disable();
	do {
		pages = 0;
		pobjects = 0;

		// 老的部分使用的列表
		oldpage = this_cpu_read(s->cpu_slab->partial);

		// 有老的，先释放老的
		if (oldpage) {

			// 部分列表里对象数的总里
			pobjects = oldpage->pobjects;
			// 以前pages里的数量
			pages = oldpage->pages;
			
			// 需要排出，且对象数量大于部分列表的限制
			if (drain && pobjects > slub_cpu_partial(s)) {
				unsigned long flags;
				// 解冻部分列表，并释放
				local_irq_save(flags);
				unfreeze_partials(s, this_cpu_ptr(s->cpu_slab));
				local_irq_restore(flags);

				// 上面的unfreeze_partials会把所有的page都丢弃或者存到node里
				// 所以这里会把所有的计数对象置空
				oldpage = NULL;
				pobjects = 0;
				pages = 0;
				stat(s, CPU_PARTIAL_DRAIN);
			}
		}

		// 现在要新加一页了，所以递增
		pages++;
		
		// 再加上page没有用的对象
		pobjects += page->objects - page->inuse;

		// 设置pages的数量
		page->pages = pages;
		// 总对象数
		page->pobjects = pobjects;
		// 把page放到表头
		page->next = oldpage;

		// 设置partial的值为page
	} while (this_cpu_cmpxchg(s->cpu_slab->partial, oldpage, page)
								!= oldpage);
	
	// 如果不支持cpu部分缓存，直接解冻：有可能加到node的部分列表里也有可能会丢弃
	if (unlikely(!slub_cpu_partial(s))) {
		unsigned long flags;

		local_irq_save(flags);
		unfreeze_partials(s, this_cpu_ptr(s->cpu_slab));
		local_irq_restore(flags);
	}
	preempt_enable();
#endif	/* CONFIG_SLUB_CPU_PARTIAL */
}

static void unfreeze_partials(struct kmem_cache *s,
		struct kmem_cache_cpu *c)
{
#ifdef CONFIG_SLUB_CPU_PARTIAL
	struct kmem_cache_node *n = NULL, *n2 = NULL;
	struct page *page, *discard_page = NULL;

	// 遍历percpu 部分列表，这个循环主要是把当前的
	// slub从percpu部分列表里加到node的部分列表（先解冻），或者丢弃
	while ((page = slub_percpu_partial(c))) {
		struct page new;
		struct page old;

		// 这里实际上是设置c->partial = page->next
		slub_set_percpu_partial(c, page);

		// 获取page对应的node
		n2 = get_node(s, page_to_nid(page));
		
		// 把 n 先锁上，n不同的话就替换锁
		if (n != n2) {
			if (n)
				spin_unlock(&n->list_lock);

			n = n2;
			spin_lock(&n->list_lock);
		}

		do {

			old.freelist = page->freelist;
			old.counters = page->counters;

			// 必须被冻住
			VM_BUG_ON(!old.frozen);

			new.counters = old.counters;
			new.freelist = old.freelist;

			// 解冻
			new.frozen = 0;
			// 把freelist和count的值设置到page相应的成员里
		} while (!__cmpxchg_double_slab(s, page,
				old.freelist, old.counters,
				new.freelist, new.counters,
				"unfreezing slab"));

		if (unlikely(!new.inuse && n->nr_partial >= s->min_partial)) {
			// 没有正在用的对象，而且node的部分数量大于cache的限制

			// 把page链接到丢弃列表里
			page->next = discard_page;
			discard_page = page;
		} else {
			// 否则的话加到node的部分列表
			add_partial(n, page, DEACTIVATE_TO_TAIL);
			stat(s, FREE_ADD_PARTIAL);
		}
	}

	if (n)
		spin_unlock(&n->list_lock);

	// 如果有需要丢弃的页，就释放它
	while (discard_page) {
		page = discard_page;
		discard_page = discard_page->next;

		stat(s, DEACTIVATE_EMPTY);
		discard_slab(s, page);
		stat(s, FREE_SLAB);
	}
#endif	/* CONFIG_SLUB_CPU_PARTIAL */
}


static void discard_slab(struct kmem_cache *s, struct page *page)
{
	// 递减slab里的node对应的相关计数
	dec_slabs_node(s, page_to_nid(page), page->objects);
	free_slab(s, page);
}

static inline void dec_slabs_node(struct kmem_cache *s, int node, int objects)
{
	struct kmem_cache_node *n = get_node(s, node);

	// slub计数
	atomic_long_dec(&n->nr_slabs);
	// 总对象数
	atomic_long_sub(objects, &n->total_objects);
}

static void free_slab(struct kmem_cache *s, struct page *page)
{
	if (unlikely(s->flags & SLAB_TYPESAFE_BY_RCU)) {
		call_rcu(&page->rcu_head, rcu_free_slab);
	} else
		// 普通路径，rcu最终也会调到这儿
		__free_slab(s, page);
}

static void __free_slab(struct kmem_cache *s, struct page *page)
{
	// 页的阶
	int order = compound_order(page);
	// 页的数量
	int pages = 1 << order;

	// 调试
	if (kmem_cache_debug_flags(s, SLAB_CONSISTENCY_CHECKS)) {
		void *p;

		slab_pad_check(s, page);
		for_each_object(p, s, page_address(page),
						page->objects)
			check_object(s, page, p, SLUB_RED_INACTIVE);
	}

	// 清除相关标志
	__ClearPageSlabPfmemalloc(page);

	// 清除slab标志
	__ClearPageSlab(page);

	page->mapping = NULL;
	if (current->reclaim_state)
		current->reclaim_state->reclaimed_slab += pages;
	
	// 统计相关
	unaccount_slab_page(page, order, s);

	// 调用buddy系统释放页
	__free_pages(page, order);
}
```