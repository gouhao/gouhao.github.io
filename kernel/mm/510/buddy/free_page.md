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
	// 把这一页加到pcp list里
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
	// 页的物理地址
	unsigned long pfn = page_to_pfn(page);

	// 做准备。todo: 还没看
	if (!free_pages_prepare(page, order, true))
		return;

	// 获取迁移类型
	migratetype = get_pfnblock_migratetype(page, pfn);

	// 关中断，避免并发
	local_irq_save(flags);
	// vm event统计
	__count_vm_events(PGFREE, 1 << order);

	// 释放页
	free_one_page(page_zone(page), page, pfn, order, migratetype,
		      fpi_flags);
	local_irq_restore(flags);
}

static void free_one_page(struct zone *zone,
				struct page *page, unsigned long pfn,
				unsigned int order,
				int migratetype, fpi_t fpi_flags)
{
	// 在这之前已经关中断，这里还要加锁
	spin_lock(&zone->lock);
	// 处理隔离页
	if (unlikely(has_isolate_pageblock(zone) ||
		is_migrate_isolate(migratetype))) {
		migratetype = get_pfnblock_migratetype(page, pfn);
	}
	__free_one_page(page, pfn, zone, order, migratetype, fpi_flags);
	// 解锁
	spin_unlock(&zone->lock);
}

static inline void __free_one_page(struct page *page,
		unsigned long pfn,
		struct zone *zone, unsigned int order,
		int migratetype, fpi_t fpi_flags)
{
	struct capture_control *capc = task_capc(zone);
	unsigned long buddy_pfn;
	unsigned long combined_pfn;
	unsigned int max_order;
	struct page *buddy;
	bool to_tail;

	max_order = min_t(unsigned int, MAX_ORDER - 1, pageblock_order);

	// VM_BUG开头的全是调试相关，忽略
	VM_BUG_ON(!zone_is_initialized(zone));
	VM_BUG_ON_PAGE(page->flags & PAGE_FLAGS_CHECK_AT_PREP, page);

	VM_BUG_ON(migratetype == -1);

	// 这个是vm统计相关的
	if (likely(!is_migrate_isolate(migratetype)))
		__mod_zone_freepage_state(zone, 1 << order, migratetype);

	VM_BUG_ON_PAGE(pfn & ((1 << order) - 1), page);
	VM_BUG_ON_PAGE(bad_range(zone, page), page);

continue_merging:
	while (order < max_order) {
		// vm统计
		if (compaction_capture(capc, page, order, migratetype)) {
			__mod_zone_freepage_state(zone, -(1 << order),
								migratetype);
			return;
		}
		// 获取buddy的地址
		buddy_pfn = __find_buddy_pfn(pfn, order);
		// 获取buddy的页，因为物理地址都是连续的，所以buddy_pfn-pfn就是buddy页与page的偏移
		buddy = page + (buddy_pfn - pfn);

		// 这个在CONFIG_HOLES_IN_ZONE没打开时，恒为1
		if (!pfn_valid_within(buddy_pfn))
			goto done_merging;
		// 判断这2个页是不是buddy
		if (!page_is_buddy(page, buddy, order))
			goto done_merging;
		// page_is_guard是调试相关，没打开CONFIG_DEBUG_PAGEALLOC时，为false
		if (page_is_guard(buddy))
			clear_page_guard(zone, buddy, order, migratetype);
		else
			// 从zone的空闲列表里删除buddy
			del_page_from_free_list(buddy, zone, order);

		// 合并之后的pfn
		combined_pfn = buddy_pfn & pfn;
		// 合并之后的page
		page = page + (combined_pfn - pfn);
		pfn = combined_pfn;
		// 因为合并了，所以order递增1
		order++;

		// 在这里不停的循环，直到不能合并为止
	}

	// 走到这里只能是order >= max_order
	// todo: 这个流程是什么意思，后面看
	if (order < MAX_ORDER - 1) {
		/* If we are here, it means order is >= pageblock_order.
		 * We want to prevent merge between freepages on isolate
		 * pageblock and normal pageblock. Without this, pageblock
		 * isolation could cause incorrect freepage or CMA accounting.
		 *
		 * We don't want to hit this code for the more frequent
		 * low-order merging.
		 */
		if (unlikely(has_isolate_pageblock(zone))) {
			int buddy_mt;

			buddy_pfn = __find_buddy_pfn(pfn, order);
			buddy = page + (buddy_pfn - pfn);
			buddy_mt = get_pageblock_migratetype(buddy);

			if (migratetype != buddy_mt
					&& (is_migrate_isolate(migratetype) ||
						is_migrate_isolate(buddy_mt)))
				goto done_merging;
		}
		max_order = order + 1;
		goto continue_merging;
	}

done_merging:
	// 走到这里就是真正的进行页的合并

	// 把 order保存到private里，并设置 buddy标志
	set_buddy_order(page, order);

	// FPI_TO_TAIL:把页放到末尾
	// 在此情景里，传下来的标志是FPI_NONE
	if (fpi_flags & FPI_TO_TAIL)
		to_tail = true;
	// 这个在order>=MAX_ORDER-1时才为true
	else if (is_shuffle_order(order))
		to_tail = shuffle_pick_tail();
	else // 大多数情况走这个分支
		
		// 这个函数判断要合并的页和比它更高一级的页是不是buddy，如果是则返回true，
		// 这里返回true，意味着把页加到列表尾，
		// 之所以加到列表尾，在下一次会被继续合并，如果放在列表头，很可能被分配出去。（这个原因是我猜的）
		to_tail = buddy_merge_likely(pfn, buddy_pfn, page, order);

	if (to_tail)
		// 这个是加到空闲列表头结点之前，也就是加到整个列表末尾
		add_to_free_list_tail(page, zone, order, migratetype);
	else
		// 加到空闲列表头结点之后
		add_to_free_list(page, zone, order, migratetype);

	// todo: reporting notify相关
	if (!(fpi_flags & FPI_SKIP_REPORT_NOTIFY))
		page_reporting_notify_free(order);
}

static inline unsigned long
__find_buddy_pfn(unsigned long page_pfn, unsigned int order)
{
	// 如果page_pfn对应的order位是0，相关于加上1 << order,
	// 反之，则减去 1 << order
	return page_pfn ^ (1 << order);
}

static inline bool page_is_buddy(struct page *page, struct page *buddy,
							unsigned int order)
{
	// page_is_guard只有在CONFIG_DEBUG_PAGEALLOC打开时才有效，否则为false
	// PageBuddy判断有无buddy标志
	if (!page_is_guard(buddy) && !PageBuddy(buddy))
		return false;

	// order在page->private里保存
	if (buddy_order(buddy) != order)
		return false;

	// 两个页不在同一node，肯定不是buddy
	if (page_zone_id(page) != page_zone_id(buddy))
		return false;

	VM_BUG_ON_PAGE(page_count(buddy) != 0, buddy);

	return true;
}

static inline bool is_shuffle_order(int order)
{
	if (!static_branch_unlikely(&page_alloc_shuffle_key))
		return false;
	// #define SHUFFLE_ORDER (MAX_ORDER-1)
	return order >= SHUFFLE_ORDER;
}

static inline bool
buddy_merge_likely(unsigned long pfn, unsigned long buddy_pfn,
		   struct page *page, unsigned int order)
{
	struct page *higher_page, *higher_buddy;
	unsigned long combined_pfn;

	// 因为这里要合并，所以order不能超过MAX_ORDER - 2，否则就不能合并了
	if (order >= MAX_ORDER - 2)
		return false;

	if (!pfn_valid_within(buddy_pfn))
		return false;

	// 这个函数里传进来的是找到的最高可以合并的页，
	// 这里还要再找一下，更高的能不能合并。
	combined_pfn = buddy_pfn & pfn;
	higher_page = page + (combined_pfn - pfn);
	buddy_pfn = __find_buddy_pfn(combined_pfn, order + 1);
	higher_buddy = higher_page + (buddy_pfn - combined_pfn);

	// pfn_valid_within在CONFIG_HOLES_IN_ZONE没打开时，恒为1
	return pfn_valid_within(buddy_pfn) &&
		// 判断和它更高一级的页是不是buddy
	       page_is_buddy(higher_page, higher_buddy, order + 1);
}
```

## 线性地址与page的相互转换

### 线性地址转换成页
```c
下面这些宏是在x86平台，CONFIG_SPARSEMEM，CONFIG_SPARSEMEM_VMEMMAP打开时。

// __pa(kaddr) >> PAGE_SHIFT是算出页的序号
#define virt_to_page(kaddr)	pfn_to_page(__pa(kaddr) >> PAGE_SHIFT)

#define pfn_to_page __pfn_to_page

// vmemmap是page的起点，所以加上页号就是页面的起点
#define __pfn_to_page(pfn)	(vmemmap + (pfn))

#define vmemmap ((struct page *)VMEMMAP_START)

# define VMEMMAP_START		__VMEMMAP_BASE_L4

#define __VMEMMAP_BASE_L4	0xffffea0000000000UL

#define __pa(x)		__phys_addr((unsigned long)(x))

#define __phys_addr(x)		__phys_addr_nodebug(x)

static inline unsigned long __phys_addr_nodebug(unsigned long x)
{
	// 内核里的物理地址与线性地址是固定的偏移
	// __START_KERNEL_map在32位时，就是我们常说的3G，因为内核空间是从3G开始的，
	// 在64位时是0xffffffff80000000。
	// 而物理地址是从0开始的，所以用线性地址减一个偏移就是物理地址
	unsigned long y = x - __START_KERNEL_map;

	// 大多数情况 x > y, todo: x < y 是什么意思？下面这个不知道啥意思！
	// 可以看成: x = y + phys_base
	x = y + ((x > y) ? phys_base : (__START_KERNEL_map - PAGE_OFFSET));

	return x;
}

#define PAGE_OFFSET		((unsigned long)__PAGE_OFFSET)

// 假设CONFIG_DYNAMIC_MEMORY_LAYOUT打开
#define __PAGE_OFFSET           page_offset_base

// 在4级页表时是这个
unsigned long page_offset_base __ro_after_init = __PAGE_OFFSET_BASE_L4;

#define __PAGE_OFFSET_BASE_L4	_AC(0xffff888000000000, UL)
```
### 页转换成物理地址
```c
```
