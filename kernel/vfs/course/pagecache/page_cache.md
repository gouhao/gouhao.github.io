## 1. pagecache_get_page
```c
// 查找缓存页的函数最终都使用这个函数
struct page *pagecache_get_page(struct address_space *mapping, pgoff_t index,
		int fgp_flags, gfp_t gfp_mask)
{
	struct page *page;

repeat:
	// 找到index对应的页
	page = find_get_entry(mapping, index);
	// page应该是指针，如果是数值就出错了
	if (xa_is_value(page))
		page = NULL;
	// 没找到页
	if (!page)
		goto no_page;

	// 走到这儿就表示找到了页

	// 有FGP_LOCK标志，要在返回之前锁住该页
	if (fgp_flags & FGP_LOCK) {
		// 获取锁
		if (fgp_flags & FGP_NOWAIT) {
			if (!trylock_page(page)) {
				put_page(page);
				return NULL;
			}
		} else {
			lock_page(page);
		}

		// page的mapping变了，就再找一次
		if (unlikely(page->mapping != mapping)) {
			unlock_page(page);
			put_page(page);
			goto repeat;
		}

		// todo: what?
		VM_BUG_ON_PAGE(!thp_contains(page, index), page);
	}
	
	if (fgp_flags & FGP_ACCESSED)
		// 标记为已访问
		mark_page_accessed(page);
	else if (fgp_flags & FGP_WRITE) {
		// 写的时候先清除idle标志
		if (page_is_idle(page))
			clear_page_idle(page);
	}

	// 如果不是找头页
	if (!(fgp_flags & FGP_HEAD))
		// 如果是大页，find_subpage可以根据index找到相应的子页
		page = find_subpage(page, index);

no_page:

	// 没找到页时，如果有创建标志，则创建之
	if (!page && (fgp_flags & FGP_CREAT)) {
		int err;

		// mapping_can_writeback是看后备缓冲设备有无回写的能力
		if ((fgp_flags & FGP_WRITE) && mapping_can_writeback(mapping))
			gfp_mask |= __GFP_WRITE;
		
		// 不允许fs操作
		if (fgp_flags & FGP_NOFS)
			gfp_mask &= ~__GFP_FS;

		// 从buddy系统分配一页
		page = __page_cache_alloc(gfp_mask);
		if (!page)
			return NULL;

		// 要lock
		if (WARN_ON_ONCE(!(fgp_flags & (FGP_LOCK | FGP_FOR_MMAP))))
			fgp_flags |= FGP_LOCK;

		// 已经访问，则设置referece标志
		if (fgp_flags & FGP_ACCESSED)
			__SetPageReferenced(page);

		// 加到对应的lru列表
		err = add_to_page_cache_lru(page, mapping, index, gfp_mask);
		if (unlikely(err)) {
			put_page(page);
			page = NULL;
			if (err == -EEXIST)
				goto repeat;
		}

		// add_to_page_cache_lru会锁住锁，但是对于MMAP需要解锁页
		if (page && (fgp_flags & FGP_FOR_MMAP))
			unlock_page(page);
	}

	return page;
}
```

## add_to_page_cache_lru
```c
int add_to_page_cache_lru(struct page *page, struct address_space *mapping,
				pgoff_t offset, gfp_t gfp_mask)
{
	void *shadow = NULL;
	int ret;

	// 锁住页
	__SetPageLocked(page);

	// 先加到缓存
	ret = __add_to_page_cache_locked(page, mapping, offset,
					 gfp_mask, &shadow);
	if (unlikely(ret))
		__ClearPageLocked(page);
	else {
		// 页不能是活跃的
		WARN_ON_ONCE(PageActive(page));

		if (!(gfp_mask & __GFP_WRITE) && shadow)
			workingset_refault(page, shadow);
		lru_cache_add(page);
	}
	return ret;
}

noinline int __add_to_page_cache_locked(struct page *page,
					struct address_space *mapping,
					pgoff_t offset, gfp_t gfp,
					void **shadowp)
{
	// mapping->i_pages是xarray
	// offset是页在缓存里的偏移
	XA_STATE(xas, &mapping->i_pages, offset);

	// 是否是大页
	int huge = PageHuge(page);
	int error;
	bool charged = false;

	// 没有锁页
	VM_BUG_ON_PAGE(!PageLocked(page), page);

	// 页正在进行回写
	VM_BUG_ON_PAGE(PageSwapBacked(page), page);

	// 设置xas->xa_update 为 workingset_update_node
	mapping_set_update(&xas, mapping);

	// 增加page->_refcount
	get_page(page);
	
	page->mapping = mapping;
	page->index = offset;

	if (!huge) {
		// cgroup计费相关
		error = mem_cgroup_charge(page, current->mm, gfp);
		if (error)
			goto error;
		charged = true;
	}

	gfp &= GFP_RECLAIM_MASK;

	// 把 page插入 address_space的xarray中
	// todo: xarray没仔细研究
	do {
		// 页大小的order
		unsigned int order = xa_get_order(xas.xa, xas.xa_index);
		void *entry, *old = NULL;

		// 如果比大页还大，需要分成2个
		if (order > thp_order(page))
			xas_split_alloc(&xas, xa_load(xas.xa, xas.xa_index),
					order, gfp);
		xas_lock_irq(&xas);

		// 查找是否有重复的
		xas_for_each_conflict(&xas, entry) {
			old = entry;
			if (!xa_is_value(entry)) {
				xas_set_err(&xas, -EEXIST);
				goto unlock;
			}
		}

		// 把老的页分割
		if (old) {
			if (shadowp)
				*shadowp = old;
			order = xa_get_order(xas.xa, xas.xa_index);
			if (order > thp_order(page)) {
				xas_split(&xas, old, order);
				xas_reset(&xas);
			}
		}

		// 保存页
		xas_store(&xas, page);
		if (xas_error(&xas))
			goto unlock;

		if (old)
			mapping->nrexceptional--;
		// 增加page计数
		mapping->nrpages++;

		if (!huge)
			// cgroup相关？
			__inc_lruvec_page_state(page, NR_FILE_PAGES);
unlock:
		xas_unlock_irq(&xas);
	} while (xas_nomem(&xas, gfp));

	if (xas_error(&xas)) {
		error = xas_error(&xas);
		if (charged)
			mem_cgroup_uncharge(page);
		goto error;
	}

	trace_mm_filemap_add_to_page_cache(page);
	return 0;
error:
	page->mapping = NULL;
	/* Leave page->index set: truncation relies upon it */
	put_page(page);
	return error;
}

void lru_cache_add(struct page *page)
{
	struct pagevec *pvec;

	// 页不能是活跃的
	VM_BUG_ON_PAGE(PageActive(page) && PageUnevictable(page), page);

	// 页已经在lru列表，就出错了
	VM_BUG_ON_PAGE(PageLRU(page), page);

	// 增加引用计数
	get_page(page);
	
	local_lock(&lru_pvecs.lock);
	// todo: lru_add列表是什么？
	pvec = this_cpu_ptr(&lru_pvecs.lru_add);

	// pagevec_add返回0, 说明数组里没空间了
	// 没空间 || 是组合页,则添加到全局lru列表
	if (!pagevec_add(pvec, page) || PageCompound(page))
		__pagevec_lru_add(pvec);
	local_unlock(&lru_pvecs.lock);
}
static inline unsigned pagevec_add(struct pagevec *pvec, struct page *page)
{
	// 把页存在数组里
	pvec->pages[pvec->nr++] = page;
	// 返回数组剩余的数量
	return pagevec_space(pvec);
}

static inline unsigned pagevec_space(struct pagevec *pvec)
{
	// 数组剩余的数量
	return PAGEVEC_SIZE - pvec->nr;
}

void __pagevec_lru_add(struct pagevec *pvec)
{
	pagevec_lru_move_fn(pvec, __pagevec_lru_add_fn, NULL);
}

static void pagevec_lru_move_fn(struct pagevec *pvec,
	void (*move_fn)(struct page *page, struct lruvec *lruvec, void *arg),
	void *arg)
{
	int i;
	struct pglist_data *pgdat = NULL;
	struct lruvec *lruvec;
	unsigned long flags = 0;

	// 遍历page里的每个页
	for (i = 0; i < pagevec_count(pvec); i++) {
		struct page *page = pvec->pages[i];
		// page对应的numa
		struct pglist_data *pagepgdat = page_pgdat(page);

		// 如果结点实例变化，给新的上锁，解锁旧的
		if (pagepgdat != pgdat) {
			if (pgdat)
				spin_unlock_irqrestore(&pgdat->lru_lock, flags);
			pgdat = pagepgdat;
			spin_lock_irqsave(&pgdat->lru_lock, flags);
		}

		// 这里面涉及cgroup的操作，简单来说就是返回pgdat->__lruvec
		lruvec = mem_cgroup_page_lruvec(page, pgdat);

		// 给pgdat里转移页
		(*move_fn)(page, lruvec, arg);
	}
	if (pgdat)
		spin_unlock_irqrestore(&pgdat->lru_lock, flags);
	// 如果页的引用为0，会把页添加到free列表
	release_pages(pvec->pages, pvec->nr);

	// 只有一行代码：pvec->nr = 0;
	pagevec_reinit(pvec);
}

static void __pagevec_lru_add_fn(struct page *page, struct lruvec *lruvec,
				 void *arg)
{
	enum lru_list lru;
	// 是否不可回收
	int was_unevictable = TestClearPageUnevictable(page);
	// 如果是大页，则计算页的数量
	int nr_pages = thp_nr_pages(page);

	// page不能在lru列表
	VM_BUG_ON_PAGE(PageLRU(page), page);

	// 设置page lru标志
	SetPageLRU(page);

	// 内存栅栏
	smp_mb__after_atomic();

	if (page_evictable(page)) {
		// 页是可回收的

		// 根据页的状态，获取lru列表的索引
		lru = page_lru(page);

		// 统计不可回收
		if (was_unevictable)
			__count_vm_events(UNEVICTABLE_PGRESCUED, nr_pages);
	} else {
		// lru不可回收
		lru = LRU_UNEVICTABLE;
		// 清除活跃状态
		ClearPageActive(page);

		// 设置页不可回收
		SetPageUnevictable(page);

		// 相关统计
		if (!was_unevictable)
			__count_vm_events(UNEVICTABLE_PGCULLED, nr_pages);
	}
	// 添加到lru列表
	add_page_to_lru_list(page, lruvec, lru);
	trace_mm_lru_insertion(page, lru);
}

static __always_inline void add_page_to_lru_list(struct page *page,
				struct lruvec *lruvec, enum lru_list lru)
{
	// 更新统计状态。todo: 后面看
	update_lru_size(lruvec, lru, page_zonenum(page), thp_nr_pages(page));
	// 把page挂到lru对应的列表
	list_add(&page->lru, &lruvec->lists[lru]);
}

static __always_inline enum lru_list page_lru(struct page *page)
{
	enum lru_list lru;

	if (PageUnevictable(page))
		// page不可回收
		lru = LRU_UNEVICTABLE;
	else {
		// page可回收

		// 返回lru的基础类型，基础类型返回的都是不活跃的
		lru = page_lru_base_type(page);

		// 如果是活跃，则转为活跃类型
		// 不活跃类型与活跃类型之间差LRU_ACTIVE
		if (PageActive(page))
			lru += LRU_ACTIVE;
	}
	return lru;
}
```

## delete_from_page_cache
```c
void delete_from_page_cache(struct page *page)
{
	struct address_space *mapping = page_mapping(page);
	unsigned long flags;

	// 页必须被锁
	BUG_ON(!PageLocked(page));
	// 加锁
	xa_lock_irqsave(&mapping->i_pages, flags);
	// 从page_cache里删除
	__delete_from_page_cache(page, NULL/*这个值是shadow*/);
	xa_unlock_irqrestore(&mapping->i_pages, flags);

	// 释放页, 如果没人用的话
	page_cache_free_page(mapping, page);
}

void __delete_from_page_cache(struct page *page, void *shadow)
{
	struct address_space *mapping = page->mapping;

	trace_mm_filemap_delete_from_page_cache(page);

	// 统计相关
	unaccount_page_cache_page(mapping, page);

	// 从基数树里删除
	page_cache_delete(mapping, page, shadow);
}

static void page_cache_delete(struct address_space *mapping,
				   struct page *page, void *shadow)
{
	XA_STATE(xas, &mapping->i_pages, page->index);
	unsigned int nr = 1;

	// 设置更新函数
	mapping_set_update(&xas, mapping);

	// 不是大页的话,设置页的order, 大页只保存一个值.
	if (!PageHuge(page)) {
		xas_set_order(&xas, page->index, compound_order(page));
		nr = compound_nr(page);
	}

	// 错误判断
	VM_BUG_ON_PAGE(!PageLocked(page), page);
	VM_BUG_ON_PAGE(PageTail(page), page);
	VM_BUG_ON_PAGE(nr != 1 && shadow, page);

	// 保存shadow值
	xas_store(&xas, shadow);
	xas_init_marks(&xas);

	// 取消mapping引用
	page->mapping = NULL;
	/* Leave page->index set: truncation lookup relies upon it */

	if (shadow) {
		mapping->nrexceptional += nr;
		/*
		 * Make sure the nrexceptional update is committed before
		 * the nrpages update so that final truncate racing
		 * with reclaim does not see both counters 0 at the
		 * same time and miss a shadow entry.
		 */
		smp_wmb();
	}

	// 减少mapping里的页数
	mapping->nrpages -= nr;
}

static void page_cache_free_page(struct address_space *mapping,
				struct page *page)
{
	void (*freepage)(struct page *);

	// 调用具体文件系统的指针来释放
	freepage = mapping->a_ops->freepage;
	if (freepage)
		freepage(page);

	// 是透明大页 && 不是大页, 减少page引用
	if (PageTransHuge(page) && !PageHuge(page)) {
		page_ref_sub(page, thp_nr_pages(page));
		VM_BUG_ON_PAGE(page_count(page) <= 0, page);
	} else {
		// 普通页, 直接释放引用, 如果引用为0, 会归还给buddy
		put_page(page);
	}
}
```