# alloc_page
源码基于5.10， CONFIG_NUMA 打开

```c
void free_pages(unsigned long addr, unsigned int order)
{
	if (addr != 0) {
		// 调试相关
		VM_BUG_ON(!virt_addr_valid((void *)addr));
		// 真正的释放
		// virt_to_page:把一个线性地址转换成页描述符，order是要释放页的阶数
		__free_pages(virt_to_page((void *)addr), order);
	}
}

void __free_pages(struct page *page, unsigned int order)
{
	// 这个就是递减page->_refcount，递减完为0时，则返回true
	if (put_page_testzero(page))
		// 释放对应的页
		free_the_page(page, order);
	// 走到这儿，refcount不为1
	// 如果这个页是大页的第1页话，PageHead为true
	else if (!PageHead(page))
		// todo: 不是大页的第一页为啥要释放？
		while (order-- > 0)
			free_the_page(page + (1 << order), order);
}

static inline void free_the_page(struct page *page, unsigned int order)
{
	if (order == 0)
		// 释放一页
		free_unref_page(page);
	else
		// 释放多页
		__free_pages_ok(page, order, FPI_NONE);
}
```

## 释放一页
```c
void free_unref_page(struct page *page)
{
	unsigned long flags;

	// 把页转换成物理地址
	unsigned long pfn = page_to_pfn(page);

	// 为释放页面做准备。todo: 还没看
	if (!free_unref_page_prepare(page, pfn))
		return;
	// 释放页时要关中断
	local_irq_save(flags);
	free_unref_page_commit(page, pfn);
	// 释放完页再开中断
	local_irq_restore(flags);
}

static bool free_unref_page_prepare(struct page *page, unsigned long pfn)
{
	int migratetype;

	if (!free_pcp_prepare(page))
		return false;

	migratetype = get_pfnblock_migratetype(page, pfn);
	set_pcppage_migratetype(page, migratetype);
	return true;
}

static bool free_pcp_prepare(struct page *page)static void free_pcppages_bulk(struct zone *zone, int count,
					struct per_cpu_pages *pcp)
{
	int migratetype = 0;
	int batch_free = 0;
	int prefetch_nr = 0;
	bool isolated_pageblocks;
	struct page *page, *tmp;
	LIST_HEAD(head);

	/*
	 * Ensure proper count is passed which otherwise would stuck in the
	 * below while (list_empty(list)) loop.
	 */
	count = min(pcp->count, count);
	while (count) {
		struct list_head *list;

		/*
		 * Remove pages from lists in a round-robin fashion. A
		 * batch_free count is maintained that is incremented when an
		 * empty list is encountered.  This is so more pages are freed
		 * off fuller lists instead of spinning excessively around empty
		 * lists
		 */
		do {
			batch_free++;
			if (++migratetype == MIGRATE_PCPTYPES)
				migratetype = 0;
			list = &pcp->lists[migratetype];
		} while (list_empty(list));

		/* This is the only non-empty list. Free them all. */
		if (batch_free == MIGRATE_PCPTYPES)
			batch_free = count;

		do {
			page = list_last_entry(list, struct page, lru);
			/* must delete to avoid corrupting pcp list */
			list_del(&page->lru);
			pcp->count--;

			if (bulkfree_pcp_prepare(page))
				continue;

			list_add_tail(&page->lru, &head);

			/*
			 * We are going to put the page back to the global
			 * pool, prefetch its buddy to speed up later access
			 * under zone->lock. It is believed the overhead of
			 * an additional test and calculating buddy_pfn here
			 * can be offset by reduced memory latency later. To
			 * avoid excessive prefetching due to large count, only
			 * prefetch buddy for the first pcp->batch nr of pages.
			 */
			if (prefetch_nr++ < pcp->batch)
				prefetch_buddy(page);
		} while (--count && --batch_free && !list_empty(list));
	}

	spin_lock(&zone->lock);
	isolated_pageblocks = has_isolate_pageblock(zone);

	/*
	 * Use safe version since after __free_one_page(),
	 * page->lru.next will not point to original list.
	 */
	list_for_each_entry_safe(page, tmp, &head, lru) {
		int mt = get_pcppage_migratetype(page);
		/* MIGRATE_ISOLATE page should not go to pcplists */
		VM_BUG_ON_PAGE(is_migrate_isolate(mt), page);
		/* Pageblock could have been isolated meanwhile */
		if (unlikely(isolated_pageblocks))
			mt = get_pageblock_migratetype(page);

		__free_one_page(page, page_to_pfn(page), zone, 0, mt, FPI_NONE);
		trace_mm_page_pcpu_drain(page, 0, mt);
	}
	spin_unlock(&zone->lock);
}
{
	if (debug_pagealloc_enabled_static())
		return free_pages_prepare(page, 0, true);
	else
		return free_pages_prepare(page, 0, false);
}

static __always_inline bool free_pages_prepare(struct page *page,
					unsigned int order, bool check_free)
{
	int bad = 0;

	VM_BUG_ON_PAGE(PageTail(page), page);

	trace_mm_page_free(page, order);

	if (unlikely(PageHWPoison(page)) && !order) {
		/*
		 * Do not let hwpoison pages hit pcplists/buddy
		 * Untie memcg state and reset page's owner
		 */
		if (memcg_kmem_enabled() && PageKmemcg(page))
			__memcg_kmem_uncharge_page(page, order);
		reset_page_owner(page, order);
		return false;
	}

	/*
	 * Check tail pages before head page information is cleared to
	 * avoid checking PageCompound for order-0 pages.
	 */
	if (unlikely(order)) {
		bool compound = PageCompound(page);
		int i;

		VM_BUG_ON_PAGE(compound && compound_order(page) != order, page);

		if (compound)
			ClearPageDoubleMap(page);
		for (i = 1; i < (1 << order); i++) {
			if (compound)
				bad += free_tail_pages_check(page, page + i);
			if (unlikely(check_free_page(page + i))) {
				bad++;
				continue;
			}
			(page + i)->flags &= ~PAGE_FLAGS_CHECK_AT_PREP;
		}
	}
	if (PageMappingFlags(page))
		page->mapping = NULL;
	if (memcg_kmem_enabled() && PageKmemcg(page))
		__memcg_kmem_uncharge_page(page, order);
	if (check_free)
		bad += check_free_page(page);
	if (bad)
		return false;

	page_cpupid_reset_last(page);
	page->flags &= ~PAGE_FLAGS_CHECK_AT_PREP;
	reset_page_owner(page, order);

	if (!PageHighMem(page)) {
		debug_check_no_locks_freed(page_address(page),
					   PAGE_SIZE << order);
		debug_check_no_obj_freed(page_address(page),
					   PAGE_SIZE << order);
	}
	if (want_init_on_free())
		kernel_init_free_pages(page, 1 << order);

	kernel_poison_pages(page, 1 << order, 0);
	/*
	 * arch_free_page() can make the page's contents inaccessible.  s390
	 * does this.  So nothing which can access the page's contents should
	 * happen after this.
	 */
	arch_free_page(page, order);

	if (debug_pagealloc_enabled_static())
		kernel_map_pages(page, 1 << order, 0);

	kasan_free_nondeferred_pages(page, order);

	return true;
}

static void free_unref_page_commit(struct page *page, unsigned long pfn)
{
	// 取出page对应的zone
	struct zone *zone = page_zone(page);
	struct per_cpu_pages *pcp;
	int migratetype;

	// 获取的是page->index
	migratetype = get_pcppage_migratetype(page);
	// vm event 统计相关
	__count_vm_event(PGFREE);

	// 这里主要是处理isolate页，这种页要还给buddy系统调用，这种页是不在线的
	if (migratetype >= MIGRATE_PCPTYPES) {
		if (unlikely(is_migrate_isolate(migratetype))) {
			free_one_page(zone, page, pfn, 0, migratetype,
				      FPI_NONE);
			return;
		}
		// 对于除了isolate的页，都把它标记为可移动页
		migratetype = MIGRATE_MOVABLE;
	}

	// 取出per-cpu头指针
	pcp = &this_cpu_ptr(zone->pageset)->pcp;
	// 把页添加到对应迁移类型的头结点上
	list_add(&page->lru, &pcp->lists[migratetype]);
	// pcp上的页数量加1
	pcp->count++;

	// 如果pcp里的页达到了最高点，则释放出一批页
	if (pcp->count >= pcp->high) {
		// 这个batch就是每次释放或者新增页的数量
		unsigned long batch = READ_ONCE(pcp->batch);
		// 释放一批页
		free_pcppages_bulk(zone, batch, pcp);
	}
}


static void free_pcppages_bulk(struct zone *zone, int count,
					struct per_cpu_pages *pcp)
{
	int migratetype = 0;
	int batch_free = 0;
	int prefetch_nr = 0;
	bool isolated_pageblocks;
	struct page *page, *tmp;
	LIST_HEAD(head);

	/*
	 * Ensure proper count is passed which otherwise would stuck in the
	 * below while (list_empty(list)) loop.
	 */
	count = min(pcp->count, count);
	while (count) {
		struct list_head *list;

		/*
		 * Remove pages from lists in a round-robin fashion. A
		 * batch_free count is maintained that is incremented when an
		 * empty list is encountered.  This is so more pages are freed
		 * off fuller lists instead of spinning excessively around empty
		 * lists
		 */
		do {
			batch_free++;
			if (++migratetype == MIGRATE_PCPTYPES)
				migratetype = 0;
			list = &pcp->lists[migratetype];
		} while (list_empty(list));

		/* This is the only non-empty list. Free them all. */
		if (batch_free == MIGRATE_PCPTYPES)
			batch_free = count;

		do {
			page = list_last_entry(list, struct page, lru);
			/* must delete to avoid corrupting pcp list */
			list_del(&page->lru);
			pcp->count--;

			if (bulkfree_pcp_prepare(page))
				continue;

			list_add_tail(&page->lru, &head);

			/*
			 * We are going to put the page back to the global
			 * pool, prefetch its buddy to speed up later access
			 * under zone->lock. It is believed the overhead of
			 * an additional test and calculating buddy_pfn here
			 * can be offset by reduced memory latency later. To
			 * avoid excessive prefetching due to large count, only
			 * prefetch buddy for the first pcp->batch nr of pages.
			 */
			if (prefetch_nr++ < pcp->batch)
				prefetch_buddy(page);
		} while (--count && --batch_free && !list_empty(list));
	}

	spin_lock(&zone->lock);
	isolated_pageblocks = has_isolate_pageblock(zone);

	/*
	 * Use safe version since after __free_one_page(),
	 * page->lru.next will not point to original list.
	 */
	list_for_each_entry_safe(page, tmp, &head, lru) {
		int mt = get_pcppage_migratetype(page);
		/* MIGRATE_ISOLATE page should not go to pcplists */
		VM_BUG_ON_PAGE(is_migrate_isolate(mt), page);
		/* Pageblock could have been isolated meanwhile */
		if (unlikely(isolated_pageblocks))
			mt = get_pageblock_migratetype(page);

		__free_one_page(page, page_to_pfn(page), zone, 0, mt, FPI_NONE);
		trace_mm_page_pcpu_drain(page, 0, mt);
	}
	spin_unlock(&zone->lock);
}
```

## 释放多页
```c
static void __free_pages_ok(struct page *page, unsigned int order,
			    fpi_t fpi_flags)
{
	unsigned long flags;
	int migratetype;
	unsigned long pfn = page_to_pfn(page);

	if (!free_pages_prepare(page, order, true))
		return;

	migratetype = get_pfnblock_migratetype(page, pfn);
	local_irq_save(flags);
	__count_vm_events(PGFREE, 1 << order);
	free_one_page(page_zone(page), page, pfn, order, migratetype,
		      fpi_flags);
	local_irq_restore(flags);
}
```

## 线性地址与page的相互转换

### 线性地址转换成页
```c
下面这些宏是在x86平台，CONFIG_SPARSEMEM，CONFIG_SPARSEMEM_VMEMMAP打开时。

#define virt_to_page(kaddr)	pfn_to_page(__pa(kaddr) >> PAGE_SHIFT)

#define pfn_to_page __pfn_to_page

#define __pfn_to_page(pfn)	(vmemmap + (pfn))


#define vmemmap ((struct page *)VMEMMAP_START)

# define VMEMMAP_START		__VMEMMAP_BASE_L4

#define __VMEMMAP_BASE_L4	0xffffea0000000000UL

#define __pa(x)		__phys_addr((unsigned long)(x))

#define __phys_addr(x)		__phys_addr_nodebug(x)

static inline unsigned long __phys_addr_nodebug(unsigned long x)
{
	// 内核里的物理地址与线性地址是固定的偏移
	// 这个值在32位时，就是我们常说的3G，因为内核空间是从3G开始的，
	// 而物理地址是从0开始的，所以用线性地址减一个偏移就是物理地址
	unsigned long y = x - __START_KERNEL_map;

	// todo: 下面这个不知道啥意思！
	/* use the carry flag to determine if x was < __START_KERNEL_map */
	x = y + ((x > y) ? phys_base : (__START_KERNEL_map - PAGE_OFFSET));

	return x;
}
```
### 页转换成物理地址
```c
```
