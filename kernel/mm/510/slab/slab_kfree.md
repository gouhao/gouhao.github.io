# kfree
源码基于5.10

```c
void kfree(const void *objp)
{
	struct kmem_cache *c;
	unsigned long flags;

	// 先trace一下
	trace_kfree(_RET_IP_, objp);

	// 空指针的话直接返回，这里判断空指针是判断objp <= (void*)16
	if (unlikely(ZERO_OR_NULL_PTR(objp)))
		return;
	// 关中断
	local_irq_save(flags);
	// 没开调试是空语句
	kfree_debugcheck(objp);

	// 根据地址找到对应的cache
	c = virt_to_cache(objp);
	if (!c) {
		local_irq_restore(flags);
		return;
	}
	
	// 下面这2个debug在CONFIG_LOCKDEP没开的时候是空语句
	debug_check_no_locks_freed(objp, c->object_size);
	debug_check_no_obj_freed(objp, c->object_size);

	// 真正的释放内存
	__cache_free(c, (void *)objp, _RET_IP_);

	// 释放完了再开中断
	local_irq_restore(flags);
}

static inline struct kmem_cache *virt_to_cache(const void *obj)
{
	struct page *page;

	// 根据虚拟地址找到所在页指针
	page = virt_to_head_page(obj);

	// PageSlab是判断page->flags里有没有slab标志
	// todo: 如果没有的话，怎么会走到这里来？
	if (WARN_ONCE(!PageSlab(page), "%s: Object is not a Slab page!\n",
					__func__))
		return NULL;
	// 根据page可以找到slab所在的kmem_cache指针
	return page->slab_cache;
}

static inline struct page *virt_to_head_page(const void *x)
{
	// 根据虚拟地址找到页对象
	struct page *page = virt_to_page(x);

	// 还要判断是否是组合页
	return compound_head(page);
}

static inline struct page *compound_head(struct page *page)
{
	// 取出组合页的头
	unsigned long head = READ_ONCE(page->compound_head);

	// 末尾是1表示组合页？
	if (unlikely(head & 1))
		// 返回组合页指针
		return (struct page *) (head - 1);
	// 如果不是组合页，就返回普通页指针
	return page;
}
```
kfree前端接口里根据要释放的内存地址，找到对应的kmem_cache。然后调用__cache_free进行内在释放

## __cache_free
```c
static __always_inline void __cache_free(struct kmem_cache *cachep, void *objp,
					 unsigned long caller)
{
	// kasan没开时直接返回false
	if (kasan_slab_free(cachep, objp, _RET_IP_))
		return;

	// kcsan根据名字就知道和kasan差不多
	if (!(cachep->flags & SLAB_TYPESAFE_BY_RCU))
		__kcsan_check_access(objp, cachep->object_size,
				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT);

	// 真正的释放函数
	___cache_free(cachep, objp, caller);
}

void ___cache_free(struct kmem_cache *cachep, void *objp,
		unsigned long caller)
{
	// 获取ac指针
	struct array_cache *ac = cpu_cache_get(cachep);

	// 检查中断是否关闭
	check_irq_off();
	// 这个一般会返回false，除非init_on_free打开，
	// 如果这个标志打开，那就会把objp对应的那一段内存清0
	// 注意这里是object_size，不是cachep->size，是真正对象的大小（包括填充）
	if (unlikely(slab_want_init_on_free(cachep)))
		memset(objp, 0, cachep->object_size);
	// 调试相关，没开调试是空语句
	kmemleak_free_recursive(objp, cachep->flags);
	// 也是调试相关，调试没开时返回原对象
	objp = cache_free_debugcheck(cachep, objp, caller);
	// cgroup的计费相关
	memcg_slab_free_hook(cachep, &objp, 1);

	// 在numa系统里，有可能这个obj的内存不是当前这个节点的，这种情况下
	// 就要把内存分给obj所在的node
	if (nr_online_nodes > 1 && cache_free_alien(cachep, objp))
		return;

	// ac可用对象数量有没有超过限制
	if (ac->avail < ac->limit) {
		STATS_INC_FREEHIT(cachep);
	} else {
		STATS_INC_FREEMISS(cachep);
		// 如果ac里空闲数量超过了限制，则需要给slab返回一些
		cache_flusharray(cachep, ac);
	}

	// 网络相关，暂不看
	if (sk_memalloc_socks()) {
		struct page *page = virt_to_head_page(objp);

		if (unlikely(PageSlabPfmemalloc(page))) {
			cache_free_pfmemalloc(cachep, page, objp);
			return;
		}
	}

	// 大多数情况都走这里，真正释放一个对象
	__free_one(ac, objp);
}
```
__cache_free里主要根据percpu里可用数量与限制数量的关系来决定对应的操作。如果没超过perpuc的限制，就直接对象释放到percpu缓存里。如果percpu里空闲数量太多，就把空闲的对象归还给kmem_cahce_node或者buddy系统。

## cache_free_alien
```c
static inline int cache_free_alien(struct kmem_cache *cachep, void *objp)
{
	// page对应的node
	int page_node = page_to_nid(virt_to_page(objp));
	// 当前node
	int node = numa_mem_id();
	// 页就是当前node的，当然不用再释放
	if (likely(node == page_node))
		return 0;

	// 要释放的对象所在的页在其它node，就要把内存归还给其它node
	// 这种情况不常见
	return __cache_free_alien(cachep, objp, node, page_node);
}

static int __cache_free_alien(struct kmem_cache *cachep, void *objp,
				int node, int page_node)
{
	struct kmem_cache_node *n;
	struct alien_cache *alien = NULL;
	struct array_cache *ac;
	LIST_HEAD(list);

	n = get_node(cachep, node);
	STATS_INC_NODEFREES(cachep);
	if (n->alien && n->alien[page_node]) {
		// 在外部缓存里
		alien = n->alien[page_node];
		ac = &alien->ac;
		spin_lock(&alien->lock);

		// 如果外部缓存的对象数达到了限制，就把对象全给释放，或者给shared
		if (unlikely(ac->avail == ac->limit)) {
			STATS_INC_ACOVERFLOW(cachep);
			__drain_alien_cache(cachep, ac, page_node, &list);
		}

		// 释放一个对象
		__free_one(ac, objp);
		spin_unlock(&alien->lock);

		// 如果list里有页，就释放之
		slabs_destroy(cachep, &list);
	} else {
		// 这个分支表示，确实是从外面node分配的
		n = get_node(cachep, page_node);
		spin_lock(&n->list_lock);
		// 释放objp对象的内存
		free_block(cachep, &objp, 1, page_node, &list);
		spin_unlock(&n->list_lock);
		slabs_destroy(cachep, &list);
	}
	return 1;
}

static void __drain_alien_cache(struct kmem_cache *cachep,
				struct array_cache *ac, int node,
				struct list_head *list)
{
	struct kmem_cache_node *n = get_node(cachep, node);

	if (ac->avail) {
		spin_lock(&n->list_lock);
		// 如果node有shared，就先给shared传送一些
		if (n->shared)
			transfer_objects(n->shared, ac, ac->limit);

		// 给shared传一些之后，如果还有剩余就释放给slab
		free_block(cachep, ac->entry, ac->avail, node, list);

		// 要把对象全部清空
		ac->avail = 0;
		spin_unlock(&n->list_lock);
	}
}
```
## __free_one
释放到percpu里。
```c
static __always_inline void __free_one(struct array_cache *ac, void *objp)
{
	// 如果这个开关打开，可以避免多重释放
	if (IS_ENABLED(CONFIG_SLAB_FREELIST_HARDENED) &&
		// 如果最后一个对象就是要释放的，则认为是多重释放，这里只是打印了一个警告
	    WARN_ON_ONCE(ac->avail > 0 && ac->entry[ac->avail - 1] == objp))
		return;
	// 把objp加到可用的数组里，下次分配也是从avail这分配，
	// 所以下次分配首先分配objp，因为它是刚释放的，
	// cache可能还是热的，先分配它可以提高效率
	ac->entry[ac->avail++] = objp;
}
```
释放到percpu里很简单，直接把对象存到percpu数组里，然后递增avail计数器即可。

## cache_flusharray
percpu里空闲对象太多，需要归还给kmem_cache_node或者buddy系统。

```c
static void cache_flusharray(struct kmem_cache *cachep, struct array_cache *ac)
{
	int batchcount;
	struct kmem_cache_node *n;
	// 当前numa序号
	int node = numa_mem_id();

	// 这个list是个临时变量，里面放的是需要释放的page
	LIST_HEAD(list);

	// 批量释放的数量
	batchcount = ac->batchcount;

	check_irq_off();

	// 获取对应的node对象
	n = get_node(cachep, node);
	spin_lock(&n->list_lock);

	// 如果节点有相互共享的结点
	if (n->shared) {
		struct array_cache *shared_array = n->shared;

		// 计算目前共享对象数量到限制数量的大小，也就是需要释放的数量
		int max = shared_array->limit - shared_array->avail;
		// 向给共享对象里转移一些
		if (max) {
			
			// 根据max，修改batchcount
			if (batchcount > max)
				batchcount = max;
			// 给shared数据移动一定量的对象，注意这里是从ac的前面开始移动，因为后面的缓存是热的
			memcpy(&(shared_array->entry[shared_array->avail]),
			       ac->entry, sizeof(void *) * batchcount);

			// 增加share的数量
			shared_array->avail += batchcount;
			goto free_done;
		}
	}

	// 走到这儿说没有有共享对象，或者没有给共享转移对象

	// 释放一些对象到node里，这个释放归还给buddy系统，而是释放到kmem_cache_node里
	free_block(cachep, ac->entry, batchcount, node, &list);
free_done:
#if STATS
	// 调试相关
	{
		int i = 0;
		struct page *page;

		list_for_each_entry(page, &n->slabs_free, slab_list) {
			BUG_ON(page->active);

			i++;
		}
		STATS_SET_FREEABLE(cachep, i);
	}
#endif
	spin_unlock(&n->list_lock);

	// 从ac可用数量里减去释放掉的数量
	ac->avail -= batchcount;

	// 把后面的数据往前移
	memmove(ac->entry, &(ac->entry[batchcount]), sizeof(void *)*ac->avail);

	// 如果上面从free_block里释放掉了内存，并且空闲的数量太多，
	// 就把list里的slab释放，然后销毁，把内存还给buddy系统
	slabs_destroy(cachep, &list);
}

static void free_block(struct kmem_cache *cachep, void **objpp,
			int nr_objects, int node, struct list_head *list)
{
	int i;
	// 获取对应的node
	struct kmem_cache_node *n = get_node(cachep, node);
	struct page *page;

	// 先递增空闲对象数量
	n->free_objects += nr_objects;

	for (i = 0; i < nr_objects; i++) {
		void *objp;
		struct page *page;

		// 对象
		objp = objpp[i];

		// 获取对象获取页指针
		page = virt_to_head_page(objp);

		// 把页从slab列表先删除
		list_del(&page->slab_list);

		// 检查是否给node->list_lock上锁
		check_spinlock_acquired_node(cachep, node);
		// 把对象标为空闲，及修改page->active数量
		slab_put_obj(cachep, page, objp);
		// cachep的活跃数量递减
		STATS_DEC_ACTIVE(cachep);

		if (page->active == 0) {
			// 如果页没有活跃数量，则把该页加到free列表里
			list_add(&page->slab_list, &n->slabs_free);
			// 递增空闲slab
			n->free_slabs++;
		} else {
			// 否则把它加到部分空闲列表的末尾
			list_add_tail(&page->slab_list, &n->slabs_partial);
		}
	}

	// 如果node里的空闲对象超过了限制数量，而且有空闲的slab，则需要释放一些页，
	// 这里的释放就是把page挂到list列表，在返回以后，会在它函数里释放list里的页
	while (n->free_objects > n->free_limit && !list_empty(&n->slabs_free)) {
		// 每个slab都有num个对象，所以先从node的空闲对象里减去num
		n->free_objects -= cachep->num;

		// 从空闲slab里取出一个页
		page = list_last_entry(&n->slabs_free, struct page, slab_list);

		// 把这一页加到临时列表里
		list_move(&page->slab_list, list);

		// 空闲和总的slab数量都减少
		n->free_slabs--;
		n->total_slabs--;
	}
}

static void slab_put_obj(struct kmem_cache *cachep,
			struct page *page, void *objp)
{
	// 计算对象在page里的序号
	unsigned int objnr = obj_to_index(cachep, page, objp);
#if DEBUG
	unsigned int i;

	/* Verify double free bug */
	for (i = page->active; i < cachep->num; i++) {
		if (get_free_obj(page, i) == objnr) {
			pr_err("slab: double free detected in cache '%s', objp %px\n",
			       cachep->name, objp);
			BUG();
		}
	}
#endif
	// 活跃数递减
	page->active--;

	// freelist指针为空，说明slab头在slab对象上保存
	// 现在释放了一个，就可以用这个对象做freelist了
	if (!page->freelist)
		page->freelist = objp + obj_offset(cachep);

	// 设置对应active上的空闲对象序号
	// 如果是上面的!freelist的情况，就会这最后一个地址指向空闲列表
	// 展开：((freelist_idx_t *)(page->freelist))[page->active] = (objp - page->s_mem)/cache->size
	set_free_obj(page, page->active, objnr);
}

static inline void set_free_obj(struct page *page,
					unsigned int idx, freelist_idx_t val)
{
	((freelist_idx_t *)(page->freelist))[idx] = val;
}

static inline unsigned int obj_to_index(const struct kmem_cache *cache,
					const struct page *page, void *obj)
{
	u32 offset = (obj - page->s_mem);
	return reciprocal_divide(offset, cache->reciprocal_buffer_size);
}

static void slabs_destroy(struct kmem_cache *cachep, struct list_head *list)
{
	struct page *page, *n;

	// 遍历list列表
	list_for_each_entry_safe(page, n, list, slab_list) {
		// 先解链
		list_del(&page->slab_list);

		// 销毁一个slab
		slab_destroy(cachep, page);
	}
}

static void slab_destroy(struct kmem_cache *cachep, struct page *page)
{
	void *freelist;

	// page的空闲列表指针
	freelist = page->freelist;
	// 调试相关
	slab_destroy_debugcheck(cachep, page);
	if (unlikely(cachep->flags & SLAB_TYPESAFE_BY_RCU))
		// 这个rcu机制，最终也会调到kmem_freepages里
		call_rcu(&page->rcu_head, kmem_rcu_free);
	else
		// 释放一页内存，这个会把page还给buddy系统
		kmem_freepages(cachep, page);

	// 如果slab头在外部保存，还要从freelist_cache中释放freelist
	if (OFF_SLAB(cachep))
		kmem_cache_free(cachep->freelist_cache, freelist);
}

static void kmem_freepages(struct kmem_cache *cachep, struct page *page)
{
	// 这是cache里一个slab占用的阶数，也就是将要释放的内存阶数
	int order = cachep->gfporder;

	// 没个slab标志，怎么会走到这个函数？？
	BUG_ON(!PageSlab(page));

	// 清除相应的标志
	__ClearPageSlabPfmemalloc(page);
	__ClearPageSlab(page);

	// page->_mapcount设为-1
	page_mapcount_reset(page);
	// 清除映射指针
	page->mapping = NULL;

	// 进程里slab加收相关的统计？？
	if (current->reclaim_state)
		current->reclaim_state->reclaimed_slab += 1 << order;
	// 删除一些统计信息？
	unaccount_slab_page(page, order, cachep);
	// 调用buddy系统释放页
	__free_pages(page, order);
}
```