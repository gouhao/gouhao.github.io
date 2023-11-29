# page-cache 分配
源码基于5.10

## page_cache_alloc
```c
static inline struct page *page_cache_alloc(struct address_space *x)
{
	// mapping_gfp_mask返回mapping->gfp_mask
	return __page_cache_alloc(mapping_gfp_mask(x));
}

struct page *__page_cache_alloc(gfp_t gfp)
{
	int n;
	struct page *page;

	// 进程有稀疏内存？
	if (cpuset_do_page_mem_spread()) {
		unsigned int cpuset_mems_cookie;
		do {
			cpuset_mems_cookie = read_mems_allowed_begin();
			n = cpuset_mem_spread_node();
			page = __alloc_pages_node(n, gfp, 0);
		} while (!page && read_mems_allowed_retry(cpuset_mems_cookie));

		return page;
	}
	// 分配一页内存
	return alloc_pages(gfp, 0);
}
```

## add_to_page_cache
```c
static inline int add_to_page_cache(struct page *page,
		struct address_space *mapping, pgoff_t offset, gfp_t gfp_mask)
{
	int error;

	// 设置锁标志
	__SetPageLocked(page);
	error = add_to_page_cache_locked(page, mapping, offset, gfp_mask);
	if (unlikely(error))
		// 只有发生错误时才解锁？
		__ClearPageLocked(page);
	return error;
}

int add_to_page_cache_locked(struct page *page, struct address_space *mapping,
		pgoff_t offset, gfp_t gfp_mask)
{
	return __add_to_page_cache_locked(page, mapping, offset,
					  gfp_mask, NULL);
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
	do {
		// 页大小的order
		unsigned int order = xa_get_order(xas.xa, xas.xa_index);
		void *entry, *old = NULL;

		// 如果比大页还大，需要分成2个？
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

		// 分割老的页
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
			// cgroup相关
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

#define XA_STATE(name, array, index)				\
	struct xa_state name = __XA_STATE(array, index, 0, 0)

#define __XA_STATE(array, index, shift, sibs)  {	\
	.xa = array,					\
	.xa_index = index,				\
	.xa_shift = shift,				\
	.xa_sibs = sibs,				\
	.xa_offset = 0,					\
	.xa_pad = 0,					\
	.xa_node = XAS_RESTART,				\
	.xa_alloc = NULL,				\
	.xa_update = NULL				\
}

#define mapping_set_update(xas, mapping) do {				\
	if (!dax_mapping(mapping) && !shmem_mapping(mapping))		\
		xas_set_update(xas, workingset_update_node);		\
} while (0)
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

		// todo: 没看懂
		if (!(gfp_mask & __GFP_WRITE) && shadow)
			workingset_refault(page, shadow);
		lru_cache_add(page);
	}
	return ret;
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
	// todo: 释放页引用？
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

static inline enum lru_list page_lru_base_type(struct page *page)
{
	if (page_is_file_lru(page))
		// 不活跃文件页
		return LRU_INACTIVE_FILE;
	// 不活跃匿名页
	return LRU_INACTIVE_ANON;
}

static inline int page_is_file_lru(struct page *page)
{
	// todo: page正在交换？
	return !PageSwapBacked(page);
}

void release_pages(struct page **pages, int nr)
{
	int i;
	LIST_HEAD(pages_to_free);
	struct pglist_data *locked_pgdat = NULL;
	struct lruvec *lruvec;
	unsigned long flags;
	unsigned int lock_batch;

	// 遍历所有页
	for (i = 0; i < nr; i++) {
		struct page *page = pages[i];

		// SWAP_CLUSTER_MAX好像是一次聚集写最大的数量
		if (locked_pgdat && ++lock_batch == SWAP_CLUSTER_MAX) {
			spin_unlock_irqrestore(&locked_pgdat->lru_lock, flags);
			locked_pgdat = NULL;
		}

		page = compound_head(page);
		// 0个页
		if (is_huge_zero_page(page))
			continue;

		// zone_device的页。todo: 这种类型不常用，后面再看
		if (is_zone_device_page(page)) {
			if (locked_pgdat) {
				spin_unlock_irqrestore(&locked_pgdat->lru_lock,
						       flags);
				locked_pgdat = NULL;
			}
			/*
			 * ZONE_DEVICE pages that return 'false' from
			 * page_is_devmap_managed() do not require special
			 * processing, and instead, expect a call to
			 * put_page_testzero().
			 */
			if (page_is_devmap_managed(page)) {
				put_devmap_managed_page(page);
				continue;
			}
		}

		// 递减page->_refcount，并测试是否为0, 为0的话返回true
		if (!put_page_testzero(page))
			continue;

		// 走到这儿, page的引用就是0了

		// page是组合页，则减少引用
		if (PageCompound(page)) {
			if (locked_pgdat) {
				spin_unlock_irqrestore(&locked_pgdat->lru_lock, flags);
				locked_pgdat = NULL;
			}
			__put_compound_page(page);
			continue;
		}

		// 走到这儿，表示不是组合页

		// 处理挂在lru列表上的页
		if (PageLRU(page)) {
			struct pglist_data *pgdat = page_pgdat(page);

			// 先给pgdat加锁
			if (pgdat != locked_pgdat) {
				if (locked_pgdat)
					spin_unlock_irqrestore(&locked_pgdat->lru_lock,
									flags);
				lock_batch = 0;
				locked_pgdat = pgdat;
				spin_lock_irqsave(&locked_pgdat->lru_lock, flags);
			}

			// 返回locked_pgdat->__lruvec
			lruvec = mem_cgroup_page_lruvec(page, locked_pgdat);

			// 加完锁之后，page又不在lru上了，todo: 什么情况下会发生这种
			VM_BUG_ON_PAGE(!PageLRU(page), page);
			// 删除lru标志
			__ClearPageLRU(page);
			// page_off_lru类似page_lru，但是前者会清除页的Unevictable/Active标志
			del_page_from_lru_list(page, lruvec, page_off_lru(page));
		}

		// 清除writes标志
		__ClearPageWaiters(page);

		// 加到要释放的列表
		list_add(&page->lru, &pages_to_free);
	}
	if (locked_pgdat)
		spin_unlock_irqrestore(&locked_pgdat->lru_lock, flags);

	// cgroup计费相关，要释放了，就减少对应的计费
	mem_cgroup_uncharge_list(&pages_to_free);
	// 释放页面，归还给buddy系统
	free_unref_page_list(&pages_to_free);
}

static __always_inline void del_page_from_lru_list(struct page *page,
				struct lruvec *lruvec, enum lru_list lru)
{
	// 把page从lru列表解链
	list_del(&page->lru);

	// 更新统计相关
	update_lru_size(lruvec, lru, page_zonenum(page), -thp_nr_pages(page));
}

```

## pagecache_get_page
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

struct page *find_get_entry(struct address_space *mapping, pgoff_t index)
{
	XA_STATE(xas, &mapping->i_pages, index);
	struct page *page;

	rcu_read_lock();
repeat:
	xas_reset(&xas);

	// 获取page
	page = xas_load(&xas);
	if (xas_retry(&xas, page))
		goto repeat;
	/*
	 * A shadow entry of a recently evicted page, or a swap entry from
	 * shmem/tmpfs.  Return it without attempting to raise page count.
	 */
	if (!page || xa_is_value(page))
		goto out;

	// 增加引用
	if (!page_cache_get_speculative(page))
		goto repeat;

	/*
	 * Has the page moved or been split?
	 * This is part of the lockless pagecache protocol. See
	 * include/linux/pagemap.h for details.
	 */
	// page变了
	if (unlikely(page != xas_reload(&xas))) {
		put_page(page);
		goto repeat;
	}
out:
	rcu_read_unlock();

	return page;
}

```

## wait_on_page_writeback
```c
void wait_on_page_writeback(struct page *page)
{
	// 当page有writeback标志时循环
	while (PageWriteback(page)) {
		// trace
		trace_wait_on_page_writeback(page, page_mapping(page));
		// 等待PG_writeback位被清除
		wait_on_page_bit(page, PG_writeback);
	}
}

void wait_on_page_bit(struct page *page, int bit_nr)
{
	// 根据page的hash值获取对应的等待队列
	wait_queue_head_t *q = page_waitqueue(page);
	wait_on_page_bit_common(q, page, bit_nr, TASK_UNINTERRUPTIBLE, SHARED);
}

static wait_queue_head_t *page_waitqueue(struct page *page)
{
	return &page_wait_table[hash_ptr(page, PAGE_WAIT_TABLE_BITS)];
}

static inline int wait_on_page_bit_common(wait_queue_head_t *q,
	struct page *page, int bit_nr, int state, enum behavior behavior)
{
	int unfairness = sysctl_page_lock_unfairness;
	struct wait_page_queue wait_page;
	wait_queue_entry_t *wait = &wait_page.wait;
	bool thrashing = false;
	bool delayacct = false;
	unsigned long pflags;

	// 等待PG_locked的情形
	if (bit_nr == PG_locked &&
	    !PageUptodate(page) && PageWorkingset(page)) {
		if (!PageSwapBacked(page)) {
			delayacct_thrashing_start();
			delayacct = true;
		}
		psi_memstall_enter(&pflags);
		thrashing = true;
	}

	// 初始化wait_page相关
	init_wait(wait);
	wait->func = wake_page_function;
	wait_page.page = page;
	wait_page.bit_nr = bit_nr;

repeat:
	wait->flags = 0;

	// 互斥的情形
	if (behavior == EXCLUSIVE) {
		wait->flags = WQ_FLAG_EXCLUSIVE;
		if (--unfairness < 0)
			wait->flags |= WQ_FLAG_CUSTOM;
	}

	
	spin_lock_irq(&q->lock);
	// 设置wait标志
	SetPageWaiters(page);
	// 测试对应的位是否已经设置，如果设置了，这个函数返回false
	if (!trylock_page_bit_common(page, bit_nr, wait))
		// 如果已经设置了，就加到等待队列末尾
		__add_wait_queue_entry_tail(q, wait);
	spin_unlock_irq(&q->lock);

	/*
	 * From now on, all the logic will be based on
	 * the WQ_FLAG_WOKEN and WQ_FLAG_DONE flag, to
	 * see whether the page bit testing has already
	 * been done by the wake function.
	 *
	 * We can drop our reference to the page.
	 */
	if (behavior == DROP)
		put_page(page);

	/*
	 * Note that until the "finish_wait()", or until
	 * we see the WQ_FLAG_WOKEN flag, we need to
	 * be very careful with the 'wait->flags', because
	 * we may race with a waker that sets them.
	 */
	for (;;) {
		unsigned int flags;

		// 设置状态
		set_current_state(state);

		/* Loop until we've been woken or interrupted */
		flags = smp_load_acquire(&wait->flags);

		// 进行等待
		if (!(flags & WQ_FLAG_WOKEN)) {
			if (signal_pending_state(state, current))
				break;

			io_schedule();
			continue;
		}

		// 走到这儿表示对应的位已经符合条件

		// 不是互斥，退出循环
		if (behavior != EXCLUSIVE)
			break;

		/* If the waker got the lock for us, we're done */
		if (flags & WQ_FLAG_DONE)
			break;

		/*
		 * Otherwise, if we're getting the lock, we need to
		 * try to get it ourselves.
		 *
		 * And if that fails, we'll have to retry this all.
		 */
		if (unlikely(test_and_set_bit(bit_nr, &page->flags)))
			goto repeat;

		wait->flags |= WQ_FLAG_DONE;
		break;
	}

	finish_wait(q, wait);

	if (thrashing) {
		if (delayacct)
			delayacct_thrashing_end();
		psi_memstall_leave(&pflags);
	}

	if (behavior == EXCLUSIVE)
		return wait->flags & WQ_FLAG_DONE ? 0 : -EINTR;

	return wait->flags & WQ_FLAG_WOKEN ? 0 : -EINTR;
}

static inline bool trylock_page_bit_common(struct page *page, int bit_nr,
					struct wait_queue_entry *wait)
{
	if (wait->flags & WQ_FLAG_EXCLUSIVE) {
		// 互斥的话，测试并设置
		if (test_and_set_bit(bit_nr, &page->flags))
			return false;
		// 否则只测试是否设置对应的位
	} else if (test_bit(bit_nr, &page->flags))
		return false;

	wait->flags |= WQ_FLAG_WOKEN | WQ_FLAG_DONE;
	return true;
}
```

## mpage_readpage
```c

struct mpage_readpage_args {
	struct bio *bio; // bio列表
	struct page *page; // page列表
	unsigned int nr_pages; // 有几页
	bool is_readahead; // 是否预读
	sector_t last_block_in_bio; // bio里的最后一个block
	struct buffer_head map_bh; // buffer_head头？
	unsigned long first_logical_block; // 第1个逻辑块
	get_block_t *get_block; // 读取block的函数
};

int mpage_readpage(struct page *page, get_block_t get_block)
{
	struct mpage_readpage_args args = {
		.page = page,
		.nr_pages = 1,
		.get_block = get_block,
	};

	// 创建bio请求
	args.bio = do_mpage_readpage(&args);

	// 如果还有遗留的bio，则提交之
	if (args.bio)
		mpage_bio_submit(REQ_OP_READ, 0, args.bio);
	return 0;
}

static struct bio *do_mpage_readpage(struct mpage_readpage_args *args)
{
	struct page *page = args->page;
	struct inode *inode = page->mapping->host;
	// 块大小的阶数
	const unsigned blkbits = inode->i_blkbits;

	// 每页可以放的块数
	const unsigned blocks_per_page = PAGE_SIZE >> blkbits;

	// 块大小
	const unsigned blocksize = 1 << blkbits;
	
	// 映射头
	struct buffer_head *map_bh = &args->map_bh;
	sector_t block_in_file;
	sector_t last_block;
	sector_t last_block_in_file;
	sector_t blocks[MAX_BUF_PER_PAGE];
	unsigned page_block;
	unsigned first_hole = blocks_per_page;
	struct block_device *bdev = NULL;
	int length;
	int fully_mapped = 1;
	int op_flags;
	unsigned nblocks;
	unsigned relative_block;
	gfp_t gfp;

	if (args->is_readahead) {
		// todo: 预读后面再看
		op_flags = REQ_RAHEAD;
		gfp = readahead_gfp_mask(page->mapping);
	} else {
		op_flags = 0;
		gfp = mapping_gfp_constraint(page->mapping, GFP_KERNEL);
	}

	// page不应该有buffer，如果有了就单独处理
	if (page_has_buffers(page))
		goto confused;

	// 根据page->index算出块在文件中的起始块号？
	block_in_file = (sector_t)page->index << (PAGE_SHIFT - blkbits);
	// 最后一个块号
	last_block = block_in_file + args->nr_pages * blocks_per_page;
	// 文件大小对应的最后一个块
	last_block_in_file = (i_size_read(inode) + blocksize - 1) >> blkbits;

	// 如果要读的最后一个块大于文件的最后一块，则修改为文件的最后一块
	if (last_block > last_block_in_file)
		last_block = last_block_in_file;
	page_block = 0;

	// buffer_head对应的块数？
	nblocks = map_bh->b_size >> blkbits;

	// 已经映射。todo：后面看
	if (buffer_mapped(map_bh) &&
			block_in_file > args->first_logical_block &&
			block_in_file < (args->first_logical_block + nblocks)) {
		unsigned map_offset = block_in_file - args->first_logical_block;
		unsigned last = nblocks - map_offset;

		for (relative_block = 0; ; relative_block++) {
			if (relative_block == last) {
				clear_buffer_mapped(map_bh);
				break;
			}
			if (page_block == blocks_per_page)
				break;
			blocks[page_block] = map_bh->b_blocknr + map_offset +
						relative_block;
			page_block++;
			block_in_file++;
		}
		bdev = map_bh->b_bdev;
	}

	// 设置要读的页
	map_bh->b_page = page;
	while (page_block < blocks_per_page) {
		map_bh->b_state = 0;
		map_bh->b_size = 0;

		// 要读的页 < 最后一个页
		if (block_in_file < last_block) {
			// 设置bh本次要读的大小
			map_bh->b_size = (last_block-block_in_file) << blkbits;
			// 读取块
			if (args->get_block(inode, block_in_file, map_bh, 0))
				goto confused;
			// 设置第1个逻辑块？
			args->first_logical_block = block_in_file;
		}

		// todo: 如果还没映射表示有洞？
		if (!buffer_mapped(map_bh)) {
			fully_mapped = 0;
			// 记录第1个洞
			if (first_hole == blocks_per_page)
				first_hole = page_block;
			// 递增块
			page_block++;
			block_in_file++;
			// 重新读取
			continue;
		}

		// bh已经最新的
		if (buffer_uptodate(map_bh)) {
			// 把bh和page关联
			map_buffer_to_page(page, map_bh, page_block);
			goto confused;
		}
	
		// 如果有洞，直接退出？
		if (first_hole != blocks_per_page)
			goto confused;		/* hole -> non-hole */

		// 这是已经映射的情况
		if (page_block && blocks[page_block-1] != map_bh->b_blocknr-1)
			goto confused;
		
		// 已读取的块数
		nblocks = map_bh->b_size >> blkbits;
		// todo: ??
		for (relative_block = 0; ; relative_block++) {
			if (relative_block == nblocks) {
				clear_buffer_mapped(map_bh);
				break;
			} else if (page_block == blocks_per_page)
				break;
			blocks[page_block] = map_bh->b_blocknr+relative_block;
			page_block++;
			block_in_file++;
		}
		bdev = map_bh->b_bdev;
	}

	if (first_hole != blocks_per_page) {
		// 这个分支表示有洞

		// 填充第一个洞
		zero_user_segment(page, first_hole << blkbits, PAGE_SIZE);

		if (first_hole == 0) {
			// 如果没洞，则设置页最新
			SetPageUptodate(page);
			unlock_page(page);
			goto out;
		}
	} else if (fully_mapped) {
		// 全部映射，设置已映射到磁盘
		SetPageMappedToDisk(page);
	}

	// todo: ?
	if (fully_mapped && blocks_per_page == 1 && !PageUptodate(page) &&
	    cleancache_get_page(page) == 0) {
		SetPageUptodate(page);
		goto confused;
	}

	/*
	 * This page will go to BIO.  Do we need to send this BIO off first?
	 */
	if (args->bio && (args->last_block_in_bio != blocks[0] - 1))
		args->bio = mpage_bio_submit(REQ_OP_READ, op_flags, args->bio);

alloc_new:
	if (args->bio == NULL) {
		if (first_hole == blocks_per_page) {
			if (!bdev_read_page(bdev, blocks[0] << (blkbits - 9),
								page))
				goto out;
		}
		args->bio = mpage_alloc(bdev, blocks[0] << (blkbits - 9),
					min_t(int, args->nr_pages,
					      BIO_MAX_PAGES),
					gfp);
		if (args->bio == NULL)
			goto confused;
	}

	length = first_hole << blkbits;
	if (bio_add_page(args->bio, page, length, 0) < length) {
		args->bio = mpage_bio_submit(REQ_OP_READ, op_flags, args->bio);
		goto alloc_new;
	}

	relative_block = block_in_file - args->first_logical_block;
	nblocks = map_bh->b_size >> blkbits;
	if ((buffer_boundary(map_bh) && relative_block == nblocks) ||
	    (first_hole != blocks_per_page))
		args->bio = mpage_bio_submit(REQ_OP_READ, op_flags, args->bio);
	else
		args->last_block_in_bio = blocks[blocks_per_page - 1];
out:
	return args->bio;

confused:
	// 提交bio
	if (args->bio)
		args->bio = mpage_bio_submit(REQ_OP_READ, op_flags, args->bio);
	if (!PageUptodate(page))
		// 如果page不是最新的，则读所有的块？
		block_read_full_page(page, args->get_block);
	else
		unlock_page(page);
	goto out;
}

static void 
map_buffer_to_page(struct page *page, struct buffer_head *bh, int page_block) 
{
	struct inode *inode = page->mapping->host;
	struct buffer_head *page_bh, *head;
	int block = 0;

	if (!page_has_buffers(page)) {
		/*
		 * don't make any buffers if there is only one buffer on
		 * the page and the page just needs to be set up to date
		 */
		if (inode->i_blkbits == PAGE_SHIFT &&
		    buffer_uptodate(bh)) {
			SetPageUptodate(page);    
			return;
		}
		create_empty_buffers(page, i_blocksize(inode), 0);
	}
	head = page_buffers(page);
	page_bh = head;
	do {
		if (block == page_block) {
			page_bh->b_state = bh->b_state;
			page_bh->b_bdev = bh->b_bdev;
			page_bh->b_blocknr = bh->b_blocknr;
			break;
		}
		page_bh = page_bh->b_this_page;
		block++;
	} while (page_bh != head);
}

static struct bio *mpage_bio_submit(int op, int op_flags, struct bio *bio)
{
	bio->bi_end_io = mpage_end_io;
	bio_set_op_attrs(bio, op, op_flags);
	guard_bio_eod(bio);
	submit_bio(bio);
	return NULL;
}
```

## page_cache_sync_readahead
```c
// 同步预读
// index是本次需要读的页面，req_count是需要本次要读的页数
static inline
void page_cache_sync_readahead(struct address_space *mapping,
		struct file_ra_state *ra, struct file *file, pgoff_t index,
		unsigned long req_count)
{
	
	// 定义一个预读控制结构
	/*

	#define DEFINE_READAHEAD(rac, f, m, i)					\
		struct readahead_control rac = {				\
			.file = f,						\
			.mapping = m,						\
			._index = i,						\
		}
	*/
	DEFINE_READAHEAD(ractl, file, mapping, index);

	// 同步预读
	page_cache_sync_ra(&ractl, ra, req_count);
}

void page_cache_sync_ra(struct readahead_control *ractl,
		struct file_ra_state *ra, unsigned long req_count)
{
	// 强制预读
	// todo: 随机存储不是应该关闭预读吗，为什么还要强制预读
	bool do_forced_ra = ractl->file && (ractl->file->f_mode & FMODE_RANDOM);

	// 如果没有预读 || 块层拥塞
	// ra_pages是预读窗口的最大值，todo: 什么时候预读窗口最大值是0？它初始化是32页
	if (!ra->ra_pages || blk_cgroup_congested()) {
		// 文件为空直接返回？todo: 什么时候会为空
		if (!ractl->file)
			return;
		// 把读的页数改成1
		req_count = 1;
		do_forced_ra = true;
	}

	/* be dumb */
	if (do_forced_ra) { // 强制预读
		force_page_cache_ra(ractl, ra, req_count);
		return;
	}

	// 大多数情况都走这个分支
	ondemand_readahead(ractl, ra, false, req_count);
}

// 强制预读
void force_page_cache_ra(struct readahead_control *ractl,
		struct file_ra_state *ra, unsigned long nr_to_read)
{
	struct address_space *mapping = ractl->mapping;
	// 设备
	struct backing_dev_info *bdi = inode_to_bdi(mapping->host);
	unsigned long max_pages, index;

	// 预读必须要实现这3个函数，否则不支持预读
	if (unlikely(!mapping->a_ops->readpage && !mapping->a_ops->readpages &&
			!mapping->a_ops->readahead))
		return;

	index = readahead_index(ractl);
	// io_pages是最大允许的io数量
	max_pages = max_t(unsigned long, bdi->io_pages, ra->ra_pages);
	// 最多读的数量
	nr_to_read = min_t(unsigned long, nr_to_read, max_pages);
	while (nr_to_read) {
		// 一次预读2M的数据，再换算成页数
		unsigned long this_chunk = (2 * 1024 * 1024) / PAGE_SIZE;

		// 如果太多，则减少页数，按要求的数量读
		if (this_chunk > nr_to_read)
			this_chunk = nr_to_read;
		ractl->_index = index;
		// 开始预读
		do_page_cache_ra(ractl, this_chunk, 0);

		index += this_chunk;
		nr_to_read -= this_chunk;
	}
}


void do_page_cache_ra(struct readahead_control *ractl,
		unsigned long nr_to_read, unsigned long lookahead_size)
{
	struct inode *inode = ractl->mapping->host;
	// 开始预读的页号
	unsigned long index = readahead_index(ractl);

	// 文件大小
	loff_t isize = i_size_read(inode);
	pgoff_t end_index;	/* The last page we want to read */

	// 文件大小是0
	if (isize == 0)
		return;

	// 最大能读的页号
	end_index = (isize - 1) >> PAGE_SHIFT;

	// 预读超过最大的页
	if (index > end_index)
		return;
	// 限制最大读的页数
	if (nr_to_read > end_index - index)
		nr_to_read = end_index - index + 1;

	// 主要调用文件系统的readahead函数来预读页面
	page_cache_ra_unbounded(ractl, nr_to_read, lookahead_size);
}

void page_cache_ra_unbounded(struct readahead_control *ractl,
		unsigned long nr_to_read, unsigned long lookahead_size)
{
	struct address_space *mapping = ractl->mapping;
	unsigned long index = readahead_index(ractl);
	LIST_HEAD(page_pool);
	gfp_t gfp_mask = readahead_gfp_mask(mapping);
	unsigned long i;
	
	// 给current->flags | PF_MEMALLOC_NOFS，然后返回旧值
	unsigned int nofs = memalloc_nofs_save();

	/*
	 * Preallocate as many pages as we will need.
	 */
	for (i = 0; i < nr_to_read; i++) {
		// 取出一页
		struct page *page = xa_load(&mapping->i_pages, index + i);

		// index+1, nr_pages必须加1
		BUG_ON(index + i != ractl->_index + ractl->_nr_pages);

		// page有值，说明别人已经分配了，直接读页
		if (page && !xa_is_value(page)) {
			/*
			 * Page already present?  Kick off the current batch
			 * of contiguous pages before continuing with the
			 * next batch.  This page may be the one we would
			 * have intended to mark as Readahead, but we don't
			 * have a stable reference to this page, and it's
			 * not worth getting one just for that.
			 */
			read_pages(ractl, &page_pool, true);
			continue;
		}

		// 分配一页
		page = __page_cache_alloc(gfp_mask);
		if (!page)
			break;
		if (mapping->a_ops->readpages) {
			// 有readpages函数的，先加到列表里
			page->index = index + i;
			list_add(&page->lru, &page_pool);
		// 没有readpages的，先加到lru里
		} else if (add_to_page_cache_lru(page, mapping, index + i,
					gfp_mask) < 0) {
			// 小于0,表示出错。如果出错，就把之前分配成功的页先预读
			put_page(page);
			read_pages(ractl, &page_pool, true);
			continue;
		}
		// lookahead_size是需要标记预读标志页的页数
		if (i == nr_to_read - lookahead_size)
			SetPageReadahead(page);
		// 递增要预读的页数
		ractl->_nr_pages++;
	}
	
	// 如果不出意外，一般都会走到这里来预读页
	read_pages(ractl, &page_pool, false);
	// 还原current->flags的标志
	memalloc_nofs_restore(nofs);
}

static void read_pages(struct readahead_control *rac, struct list_head *pages,
		bool skip_page)
{
	const struct address_space_operations *aops = rac->mapping->a_ops;
	struct page *page;
	struct blk_plug plug;

	// 没有需要预读的页，直接返回
	if (!readahead_count(rac))
		goto out;

	// todo:?
	blk_start_plug(&plug);

	if (aops->readahead) {
		// mapping里有预读函数，则直接调用
		aops->readahead(rac);
		// 预读完之后，如果还有没读的页，就把那些页释放掉？
		while ((page = readahead_page(rac))) {
			unlock_page(page);
			put_page(page);
		}
	} else if (aops->readpages) {
		// 有读取页的函数，则调用之
		aops->readpages(rac->file, rac->mapping, pages,
				readahead_count(rac));
		// 从readpages里返回后，如果pages列表里还有没有读的，就释放pages里的页？
		put_pages_list(pages);
		// 读完了，就递增index
		rac->_index += rac->_nr_pages;
		// 预读控制结构里的pages置0
		rac->_nr_pages = 0;
	} else {
		// 如果没有上面的2个函数就调用readpage一页一页的读
		// readahead_page主要获取下一个要预读的页，并设置rac相关
		while ((page = readahead_page(rac))) {
			aops->readpage(rac->file, page);
			put_page(page);
		}
	}

	blk_finish_plug(&plug);

	// pages里的页都要读取完，或者被释放
	BUG_ON(!list_empty(pages));

	// 需要预读的数量也得为0
	BUG_ON(readahead_count(rac));

out:
	// todo: ?
	if (skip_page)
		rac->_index++;
}

static inline struct page *readahead_page(struct readahead_control *rac)
{
	struct page *page;

	BUG_ON(rac->_batch_count > rac->_nr_pages);
	// 需要读的页数减去一批的数量
	rac->_nr_pages -= rac->_batch_count;
	// index前进batch
	rac->_index += rac->_batch_count;

	// 没有需要读的页，直接返回
	if (!rac->_nr_pages) {
		rac->_batch_count = 0;
		return NULL;
	}

	// 加载mapping里的page
	page = xa_load(&rac->mapping->i_pages, rac->_index);
	// page必须要上锁
	VM_BUG_ON_PAGE(!PageLocked(page), page);
	// 如果是大页，则是大页的数量
	rac->_batch_count = thp_nr_pages(page);

	return page;
}

static void ondemand_readahead(struct readahead_control *ractl,
		struct file_ra_state *ra, bool hit_readahead_marker,
		unsigned long req_size)
{
	struct backing_dev_info *bdi = inode_to_bdi(ractl->mapping->host);
	unsigned long max_pages = ra->ra_pages;
	unsigned long add_pages;
	unsigned long index = readahead_index(ractl);
	pgoff_t prev_index;

	// 如果是从第0页读，则初始化预读
	if (!index)
		goto initial_readahead;

	// 要读的是异步预读页 || 要读的是窗口的最后一页
	if ((index == (ra->start + ra->size - ra->async_size) ||
	     index == (ra->start + ra->size))) {
		// 预读窗口起点为上次窗口结尾开始
		ra->start += ra->size;
		// 获取下一个窗口大小，会对当前窗口进行增加，最大不超过max_pages（一般为32页）
		ra->size = get_next_ra_size(ra, max_pages);
		// 异步大小为上一个窗口的大小
		ra->async_size = ra->size;
		goto readit;
	}

	// 异步预读的分支
	if (hit_readahead_marker) {
		pgoff_t start;

		rcu_read_lock();
		// 找到page_page的下一个洞
		start = page_cache_next_miss(ractl->mapping, index + 1,
				max_pages);
		rcu_read_unlock();

		// 如果没找到。
		if (!start || start - index > max_pages)
			return;

		ra->start = start;
		// todo: ?
		ra->size = start - index;	/* old async_size */
		ra->size += req_size;

		// 计算下一个窗口大小
		ra->size = get_next_ra_size(ra, max_pages);
		// 异步窗口和异读窗口大小相同？
		ra->async_size = ra->size;
		goto readit;
	}

	// 要读的数量大于预读的最大值，则重新初始化预读窗口
	if (req_size > max_pages)
		goto initial_readahead;

	/*
	 * sequential cache miss
	 * trivial case: (index - prev_index) == 1
	 * unaligned reads: (index - prev_index) == 0
	 */
	// 之前读的位置
	prev_index = (unsigned long long)ra->prev_pos >> PAGE_SHIFT;
	// 如果符合上面的miss情况，需要重新初始化
	if (index - prev_index <= 1UL)
		goto initial_readahead;

	/*
	 * Query the page cache and look for the traces(cached history pages)
	 * that a sequential stream would leave behind.
	 */
	if (try_context_readahead(ractl->mapping, ra, index, req_size,
			max_pages))
		goto readit;

	/*
	 * standalone, small random read
	 * Read as is, and do not pollute the readahead state.
	 */
	do_page_cache_ra(ractl, req_size, 0);
	return;

initial_readahead:
	// 预读开始的位置
	ra->start = index;
	// 预读窗口大小
	ra->size = get_init_ra_size(req_size, max_pages);

	// 在读的时候，如果剩余的预读页只有async_size，则启动异步预读
	ra->async_size = ra->size > req_size ? ra->size - req_size : ra->size;

readit:
	// 读到了窗口的起点 && 窗口大小和异步预读窗口相同
	if (index == ra->start && ra->size == ra->async_size) {
		// 获取下一个窗口的大小
		add_pages = get_next_ra_size(ra, max_pages);
		if (ra->size + add_pages <= max_pages) {
			// 设置异步读的窗口
			ra->async_size = add_pages;
			// 总窗口大小
			ra->size += add_pages;
		} else {
			// 窗口设为最大值
			ra->size = max_pages;
			// 异步窗口为最大值的一半
			ra->async_size = max_pages >> 1;
		}
	}

	ractl->_index = ra->start;
	do_page_cache_ra(ractl, ra->size, ra->async_size);
}

static int try_context_readahead(struct address_space *mapping,
				 struct file_ra_state *ra,
				 pgoff_t index,
				 unsigned long req_size,
				 unsigned long max)
{
	pgoff_t size;

	// 计算连续缓存的数目
	size = count_history_pages(mapping, index, max);

	/*
	 * not enough history pages:
	 * it could be a random read
	 */
	// 随机读
	if (size <= req_size)
		return 0;

	/*
	 * starts from beginning of file:
	 * it is a strong indication of long-run stream (or whole-file-read)
	 */
	if (size >= index)
		size *= 2;

	ra->start = index;
	ra->size = min(size + req_size, max);
	ra->async_size = 1;

	return 1;
}

static unsigned long get_init_ra_size(unsigned long size, unsigned long max)
{
	// 向上以2的幂对齐
	unsigned long newsize = roundup_pow_of_two(size);

	if (newsize <= max / 32)
		newsize = newsize * 4;
	else if (newsize <= max / 4)
		newsize = newsize * 2;
	else
		newsize = max;

	return newsize;
}

static unsigned long get_next_ra_size(struct file_ra_state *ra,
				      unsigned long max)
{
	// 当前预读窗口大小
	unsigned long cur = ra->size;

	// 小于要读的1/16，则扩大4倍
	if (cur < max / 16)
		return 4 * cur;
	// 小于要读的1/2，则翻一倍
	if (cur <= max / 2)
		return 2 * cur;
	// 其它情况返回最大值
	return max;
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