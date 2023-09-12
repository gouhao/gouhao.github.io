# bh_cache
源码基于5.10

## alloc_buffer_head
```c
struct buffer_head *alloc_buffer_head(gfp_t gfp_flags)
{
        // 通过slab来分配一个结构
	struct buffer_head *ret = kmem_cache_zalloc(bh_cachep, gfp_flags);
	if (ret) {
                // 一些基本初始化
		INIT_LIST_HEAD(&ret->b_assoc_buffers);
		spin_lock_init(&ret->b_uptodate_lock);
		preempt_disable();
                // 已分配的bh计数？
		__this_cpu_inc(bh_accounting.nr);
                // 好像是重新计算限制的值？todo: 后面再看
		recalc_bh_state();
		preempt_enable();
	}
	return ret;
}

static void recalc_bh_state(void)
{
	int i;
	int tot = 0;

        // bh的限制为4k?
	if (__this_cpu_inc_return(bh_accounting.ratelimit) - 1 < 4096)
		return;
        // 走到这儿，表示已经达到了4k

        // 限制置0
	__this_cpu_write(bh_accounting.ratelimit, 0);

        // 统计每个cpu的bh数量
	for_each_online_cpu(i)
		tot += per_cpu(bh_accounting, i).nr;
        
        // what?
	buffer_heads_over_limit = (tot > max_buffer_heads);
}
```

## free_buffer_head
```c
void free_buffer_head(struct buffer_head *bh)
{
	BUG_ON(!list_empty(&bh->b_assoc_buffers));
        // 释放内存
	kmem_cache_free(bh_cachep, bh);
	preempt_disable();
        // 减少nr
	__this_cpu_dec(bh_accounting.nr);
	recalc_bh_state();
	preempt_enable();
}
```

## create_empty_buffers
```c
void create_empty_buffers(struct page *page,
			unsigned long blocksize, unsigned long b_state)
{
	struct buffer_head *bh, *head, *tail;

        // 根据块大小，分配一页内允许的bh数量，返回值是bh头
	head = alloc_page_buffers(page, blocksize, true);

        // 遍历bh列表，分配设置每个bh的状态
	bh = head;
	do {
		bh->b_state |= b_state;
		tail = bh;
		bh = bh->b_this_page;
	} while (bh);
	tail->b_this_page = head;

	spin_lock(&page->mapping->private_lock);

        // 根据page的状态，分配设置每个bh的状态
	if (PageUptodate(page) || PageDirty(page)) {
		bh = head;
		do {
			if (PageDirty(page))
				set_buffer_dirty(bh);
			if (PageUptodate(page))
				set_buffer_uptodate(bh);
			bh = bh->b_this_page;
		} while (bh != head);
	}

        // 把bh与页相关联，主要设置page->private
	attach_page_private(page, head);
	spin_unlock(&page->mapping->private_lock);
}

struct buffer_head *alloc_page_buffers(struct page *page, unsigned long size,
		bool retry)
{
	struct buffer_head *bh, *head;
	gfp_t gfp = GFP_NOFS | __GFP_ACCOUNT;
	long offset;
	struct mem_cgroup *memcg, *old_memcg;

        // 允许重试的话，就不允许失败
	if (retry)
		gfp |= __GFP_NOFAIL;

        // memcg相关
	memcg = get_mem_cgroup_from_page(page);
	old_memcg = set_active_memcg(memcg);

	head = NULL;
	offset = PAGE_SIZE;

        // 根据页的大小，分配 offset/size个bh
        // 注意：这里是从后往前分配
	while ((offset -= size) >= 0) {
		bh = alloc_buffer_head(gfp);
		if (!bh)
                        // no_grow会把之前分配的释放掉
			goto no_grow;
                
                // 设置bh链关系
                // 第一个分配(也就是最后一个bh)的bh->b_this_page这里是NULL
		bh->b_this_page = head;
		bh->b_blocknr = -1;
		head = bh;

                // 块大小
		bh->b_size = size;

		// 与page关联，并设置数据区指针
		set_bh_page(bh, page, offset);
	}
out:
	set_active_memcg(old_memcg);
	mem_cgroup_put(memcg);
	return head;
        
        // 如果在分配过程中出问题，就释放掉已经分配的
no_grow:
	if (head) {
		do {
			bh = head;
			head = head->b_this_page;
			free_buffer_head(bh);
		} while (head);
	}

	goto out;
}

void set_bh_page(struct buffer_head *bh,
		struct page *page, unsigned long offset)
{
        // 指向page
	bh->b_page = page;
        // 只有bh size为0或者负的时候才会发生这种情况
	BUG_ON(offset >= PAGE_SIZE);

        // 计算b_data数据区的起始地址
	if (PageHighMem(page))
                // 高端内存？在64位上已经不存在了吧
		/*
		 * This catches illegal uses and preserves the offset:
		 */
		bh->b_data = (char *)(0 + offset);
	else
		bh->b_data = page_address(page) + offset;
}

static inline void attach_page_private(struct page *page, void *data)
{
        // 增加page引用
	get_page(page);

        // page->private = private;
	set_page_private(page, (unsigned long)data);

        // 设置PG_private标志，表示页的private字段在用
	SetPagePrivate(page);
}
```

## lookup_bh_lru
```c
static struct buffer_head *
lookup_bh_lru(struct block_device *bdev, sector_t block, unsigned size)
{
	struct buffer_head *ret = NULL;
	unsigned int i;

	// 检查中断已打开
	check_irqs_on();
	// 关中断
	bh_lru_lock();
        
        // 遍历lru列表
	for (i = 0; i < BH_LRU_SIZE; i++) {
		struct buffer_head *bh = __this_cpu_read(bh_lrus.bhs[i]);

		if (bh && bh->b_blocknr == block && bh->b_bdev == bdev &&
		    bh->b_size == size) {
                        // 找到了对应的bh

                        // 如果bh不是第0个
			if (i) {
                                // 把bh前面的都往后挪一个位置
				while (i) {
					__this_cpu_write(bh_lrus.bhs[i],
						__this_cpu_read(bh_lrus.bhs[i - 1]));
					i--;
				}
                                // 把bh写到第0位上
				__this_cpu_write(bh_lrus.bhs[0], bh);
			}
                        
                        // 增加bh引用，然后返回bh
			get_bh(bh);
			ret = bh;
			break;
		}
	}
	bh_lru_unlock();
	return ret;
}
```

## bh_lru_install
```c
static void bh_lru_install(struct buffer_head *bh)
{
	struct buffer_head *evictee = bh;
	struct bh_lru *b;
	int i;

	check_irqs_on();
	bh_lru_lock();

	b = this_cpu_ptr(&bh_lrus);
        // 下面这个循环，，然后，evictee保存的是最后一个元素
	for (i = 0; i < BH_LRU_SIZE; i++) {
                // 把bh放到第0个上, 把后面的元素依次向后移动
		swap(evictee, b->bhs[i]);
                // todo: 这2个值什么时候会相关
		if (evictee == bh) {
			bh_lru_unlock();
			return;
		}
	}

        // 增加bh的引用
	get_bh(bh);
	bh_lru_unlock();
        // 释放最后一个元素
	brelse(evictee);
}

```

## __getblk
```c
static inline struct buffer_head *__getblk(struct block_device *bdev,
					   sector_t block,
					   unsigned size)
{
	return __getblk_gfp(bdev, block, size, __GFP_MOVABLE);
}

struct buffer_head *
__getblk_gfp(struct block_device *bdev, sector_t block,
	     unsigned size, gfp_t gfp)
{
	// 这个函数先在lru里找，然后
	struct buffer_head *bh = __find_get_block(bdev, block, size);

	// 走到这儿说明在cache里没找到

	// 先睡一会
	might_sleep();

	// 为什么要睡一会再判断NULL呢？如果不是NULL,直接返回岂不是更好
	if (bh == NULL)
		bh = __getblk_slow(bdev, block, size, gfp);
	return bh;
}

struct buffer_head *
__find_get_block(struct block_device *bdev, sector_t block, unsigned size)
{
	// 在lru列表里找bh
	struct buffer_head *bh = lookup_bh_lru(bdev, block, size);

	if (bh == NULL) {
		// __find_get_block_slow 会去page_cache里找block对应的页，然后再找到对应的bh
		bh = __find_get_block_slow(bdev, block);
		if (bh)
			// 把bh转移到lru前面
			bh_lru_install(bh);
	} else
		// 找到该bh，这个函数主要对bh对应的page调用mark_page_accessed
		touch_buffer(bh);

	return bh;
}

static struct buffer_head *
__find_get_block_slow(struct block_device *bdev, sector_t block)
{
	struct inode *bd_inode = bdev->bd_inode;
	// 地址空间
	struct address_space *bd_mapping = bd_inode->i_mapping;
	struct buffer_head *ret = NULL;
	pgoff_t index;
	struct buffer_head *bh;
	struct buffer_head *head;
	struct page *page;
	int all_mapped = 1;
	static DEFINE_RATELIMIT_STATE(last_warned, HZ, 1);

	// 算出块在缓存里所在的页序号
	index = block >> (PAGE_SHIFT - bd_inode->i_blkbits);
	// 在cache里找页，找到页后会调用mark_page_accessed，标记页为访问
	page = find_get_page_flags(bd_mapping, index, FGP_ACCESSED);
	if (!page)
		goto out;

	spin_lock(&bd_mapping->private_lock);
	// 判断page有没有buffers，经过上面的find_get_page_flags肯定会有，如果没有则出错
	if (!page_has_buffers(page))
		goto out_unlock;
	// 直接取出private指针，即page里的buffer头指针
	head = page_buffers(page);
	bh = head;
	do {
		// bh没有映射到对应的块
		if (!buffer_mapped(bh))
			all_mapped = 0;
		else if (bh->b_blocknr == block) {
			// 找到了对应的块
			ret = bh;
			// 增加引用
			get_bh(bh);
			goto out_unlock;
		}
		bh = bh->b_this_page;
	} while (bh != head);

	// 设置打印限制
	ratelimit_set_flags(&last_warned, RATELIMIT_MSG_ON_RELEASE);
	// todo: 为啥都映射之后，还要打警告？
	if (all_mapped && __ratelimit(&last_warned)) {
		printk("__find_get_block_slow() failed. block=%llu, "
		       "b_blocknr=%llu, b_state=0x%08lx, b_size=%zu, "
		       "device %pg blocksize: %d\n",
		       (unsigned long long)block,
		       (unsigned long long)bh->b_blocknr,
		       bh->b_state, bh->b_size, bdev,
		       1 << bd_inode->i_blkbits);
	}
out_unlock:
	spin_unlock(&bd_mapping->private_lock);
	put_page(page);
out:
	return ret;
}

static struct buffer_head *
__getblk_slow(struct block_device *bdev, sector_t block,
	     unsigned size, gfp_t gfp)
{
	// 判断size是否正常
	if (unlikely(size & (bdev_logical_block_size(bdev)-1) ||
			(size < 512 || size > PAGE_SIZE))) {
		printk(KERN_ERR "getblk(): invalid block size %d requested\n",
					size);
		printk(KERN_ERR "logical block size: %d\n",
					bdev_logical_block_size(bdev));

		dump_stack();
		return NULL;
	}

	for (;;) {
		struct buffer_head *bh;
		int ret;
		// 去缓存里找一遍
		bh = __find_get_block(bdev, block, size);
		if (bh)
			return bh;

		// 这个函数里会分配页和bh
		ret = grow_buffers(bdev, block, size, gfp);
		if (ret < 0)
			return NULL;
	}
}

static int
grow_buffers(struct block_device *bdev, sector_t block, int size, gfp_t gfp)
{
	pgoff_t index;
	int sizebits;

	sizebits = -1;
	// todo: ？
	do {
		sizebits++;
	} while ((size << sizebits) < PAGE_SIZE);

	// block对应的页的index
	index = block >> sizebits;

	// 检查index是否越界，这里使用sector_t类型比较
	if (unlikely(index != block >> sizebits)) {
		printk(KERN_ERR "%s: requested out-of-range block %llu for "
			"device %pg\n",
			__func__, (unsigned long long)block,
			bdev);
		return -EIO;
	}

	/* Create a page with the proper size buffers.. */
	return grow_dev_page(bdev, block, index, size, sizebits, gfp);
}

static int
grow_dev_page(struct block_device *bdev, sector_t block,
	      pgoff_t index, int size, int sizebits, gfp_t gfp)
{
	struct inode *inode = bdev->bd_inode;
	struct page *page;
	struct buffer_head *bh;
	sector_t end_block;
	int ret = 0;
	gfp_t gfp_mask;

	// 去除GFP_FS标志？
	gfp_mask = mapping_gfp_constraint(inode->i_mapping, ~__GFP_FS) | gfp;

	// 不允许失败
	gfp_mask |= __GFP_NOFAIL;

	// 这个调用pagecache_get_page，第3个参数传的是FGP_LOCK|FGP_ACCESSED|FGP_CREAT，表示如果找不到页，会创建页
	page = find_or_create_page(inode->i_mapping, index, gfp_mask);

	// 走到这里page肯定是上锁的
	BUG_ON(!PageLocked(page));

	// 如果不是新创建的page可以已经有buffer了
	if (page_has_buffers(page)) {
		bh = page_buffers(page);

		// bh的大小和要求的大小一样
		if (bh->b_size == size) {
			// 初始化bhs
			end_block = init_page_buffers(page, bdev,
						(sector_t)index << sizebits,
						size);
			goto done;
		}
		// 释放各个bh
		if (!try_to_free_buffers(page))
			goto failed;
	}

	// 根据页大小和bh的大小，分配合适数据的bh
	bh = alloc_page_buffers(page, size, true);

	/*
	 * Link the page to the buffers and initialise them.  Take the
	 * lock to be atomic wrt __find_get_block(), which does not
	 * run under the page lock.
	 */
	spin_lock(&inode->i_mapping->private_lock);
	// 把所有的bh串成一个环，并把bh头设置给page->private
	link_dev_buffers(page, bh);
	end_block = init_page_buffers(page, bdev, (sector_t)index << sizebits,
			size);
	spin_unlock(&inode->i_mapping->private_lock);
done:
	// 返回1表示成功
	ret = (block < end_block) ? 1 : -ENXIO;
failed:
	unlock_page(page);
	put_page(page);
	return ret;
}

int try_to_free_buffers(struct page *page)
{
	struct address_space * const mapping = page->mapping;
	struct buffer_head *buffers_to_free = NULL;
	int ret = 0;

	BUG_ON(!PageLocked(page));

	// 正在回写的不能释放
	if (PageWriteback(page))
		return 0;

	// todo: can i delete?
	if (mapping == NULL) {		/* can this still happen? */
		ret = drop_buffers(page, &buffers_to_free);
		goto out;
	}

	spin_lock(&mapping->private_lock);
	ret = drop_buffers(page, &buffers_to_free);

	if (ret)
		// 清除页的dirty标志
		cancel_dirty_page(page);
	spin_unlock(&mapping->private_lock);
out:
	// 需要释放bh，释放释放之
	if (buffers_to_free) {
		struct buffer_head *bh = buffers_to_free;

		do {
			struct buffer_head *next = bh->b_this_page;
			free_buffer_head(bh);
			bh = next;
		} while (bh != buffers_to_free);
	}
	return ret;
}

static inline void cancel_dirty_page(struct page *page)
{
	// 有脏标志
	if (PageDirty(page))
		__cancel_dirty_page(page);
}

void __cancel_dirty_page(struct page *page)
{
	struct address_space *mapping = page_mapping(page);

	if (mapping_can_writeback(mapping)) {
		// 设备有回写能力
		struct inode *inode = mapping->host;
		struct bdi_writeback *wb;
		struct wb_lock_cookie cookie = {};

		lock_page_memcg(page);
		// 获取回写对象
		wb = unlocked_inode_to_wb_begin(inode, &cookie);

		// 清除标志，如果之前是dirty，则处理统计相关的
		if (TestClearPageDirty(page))
			account_page_cleaned(page, mapping, wb);

		unlocked_inode_to_wb_end(inode, &cookie);
		unlock_page_memcg(page);
	} else {
		// 没有回写能力的直接清除标志
		ClearPageDirty(page);
	}
}

static int
drop_buffers(struct page *page, struct buffer_head **buffers_to_free)
{
	struct buffer_head *head = page_buffers(page);
	struct buffer_head *bh;

	bh = head;
	// 这个循环检查所有的bh里不能有被用的
	do {
		// b_count不为0或者有BH_Dirty或BH_Lock标志，说明有人在用，
		// 这时就不能释放
		if (buffer_busy(bh))
			goto failed;
		bh = bh->b_this_page;
	} while (bh != head);

	do {
		struct buffer_head *next = bh->b_this_page;

		if (bh->b_assoc_map)
			// 把b_assoc_buffers解链，并设置b_assoc_map为NULL
			__remove_assoc_queue(bh);
		bh = next;
	} while (bh != head);
	// 设置head出参，将在外面释放
	*buffers_to_free = head;
	// 清除private标志和private里的数据
	detach_page_private(page);
	return 1;
failed:
	return 0;
}

static inline void *detach_page_private(struct page *page)
{
	void *data = (void *)page_private(page);

	// 没有private标志
	if (!PagePrivate(page))
		return NULL;

	// 清除标志
	ClearPagePrivate(page);
	// 设置page->private = 0
	set_page_private(page, 0);
	// 减少page的引用
	put_page(page);

	return data;
}

static void __remove_assoc_queue(struct buffer_head *bh)
{
	list_del_init(&bh->b_assoc_buffers);
	WARN_ON(!bh->b_assoc_map);
	bh->b_assoc_map = NULL;
}

static inline void
link_dev_buffers(struct page *page, struct buffer_head *head)
{
	struct buffer_head *bh, *tail;

	// 找到bh的尾部
	bh = head;
	do {
		tail = bh;
		bh = bh->b_this_page;
	} while (bh);

	// 尾部指向头
	tail->b_this_page = head;

	// 头指针设置到page->private
	attach_page_private(page, head);
}

static sector_t
init_page_buffers(struct page *page, struct block_device *bdev,
			sector_t block, int size)
{
	struct buffer_head *head = page_buffers(page);
	struct buffer_head *bh = head;
	// 页是否是最新的
	int uptodate = PageUptodate(page);

	// 设备上最大可读的块
	sector_t end_block = blkdev_max_block(I_BDEV(bdev->bd_inode), size);

	do {
		if (!buffer_mapped(bh)) {
			bh->b_end_io = NULL;
			bh->b_private = NULL;
			bh->b_bdev = bdev;
			bh->b_blocknr = block;
			if (uptodate)
				// 设置BH_Uptodate
				set_buffer_uptodate(bh);
			if (block < end_block)
				// 设置BH_Mapped标志
				set_buffer_mapped(bh);
		}
		block++;
		bh = bh->b_this_page;
	} while (bh != head);

	/*
	 * Caller needs to validate requested block against end of device.
	 */
	return end_block;
}


inline void touch_buffer(struct buffer_head *bh)
{
	trace_block_touch_buffer(bh);
	// 标志reference标记
	mark_page_accessed(bh->b_page);
}

void mark_page_accessed(struct page *page)
{
	// compound_head：如果是组合页的话，找到第一个页
	page = compound_head(page);

	if (!PageReferenced(page)) {
		// 没有引用，则标记
		SetPageReferenced(page);
	} else if (PageUnevictable(page)) {
		/*
		 * Unevictable pages are on the "LRU_UNEVICTABLE" list. But,
		 * this list is never rotated or maintained, so marking an
		 * evictable page accessed has no effect.
		 */
	} else if (!PageActive(page)) {
		// 如果页之前不活跃，需要连续设置2次reference操作才会进这个分支
		/*
		 * If the page is on the LRU, queue it for activation via
		 * lru_pvecs.activate_page. Otherwise, assume the page is on a
		 * pagevec, mark it active and it'll be moved to the active
		 * LRU on the next drain.
		 */
		if (PageLRU(page))
			// 在lru列表上，转移到active列表
			activate_page(page);
		else
			// 设置active标志
			__lru_cache_activate_page(page);
		// 清除reference标志
		ClearPageReferenced(page);
		workingset_activation(page);
	}
	// 清除idle标志，如果有需要
	if (page_is_idle(page))
		clear_page_idle(page);
}

static void activate_page(struct page *page)
{
	page = compound_head(page);

	// 在lru列表上 && 不活跃 && 在不可排出队列
	if (PageLRU(page) && !PageActive(page) && !PageUnevictable(page)) {
		struct pagevec *pvec;

		local_lock(&lru_pvecs.lock);
		// percpu的活跃队列
		pvec = this_cpu_ptr(&lru_pvecs.activate_page);

		// 增加引用
		get_page(page);
		// 加到lru缓存里
		if (!pagevec_add(pvec, page) || PageCompound(page))
			// 如果lru缓存满了（pagevec_add返回0表示percpu-lru满了），或者页是组合页，则移到pgdat的lru里
			pagevec_lru_move_fn(pvec, __activate_page, NULL);
		local_unlock(&lru_pvecs.lock);
	}
}

static void __lru_cache_activate_page(struct page *page)
{
	struct pagevec *pvec;
	int i;

	local_lock(&lru_pvecs.lock);
	// 获取的是add列表
	pvec = this_cpu_ptr(&lru_pvecs.lru_add);

	for (i = pagevec_count(pvec) - 1; i >= 0; i--) {
		struct page *pagevec_page = pvec->pages[i];

		if (pagevec_page == page) {
			// 找到该页后，设置active标志
			SetPageActive(page);
			break;
		}
	}

	local_unlock(&lru_pvecs.lock);
}
```

## __bread
```c
static inline struct buffer_head *
__bread(struct block_device *bdev, sector_t block, unsigned size)
{
	return __bread_gfp(bdev, block, size, __GFP_MOVABLE);
}

struct buffer_head *
__bread_gfp(struct block_device *bdev, sector_t block,
		   unsigned size, gfp_t gfp)
{
	// 先通过getblk读取bh
	struct buffer_head *bh = __getblk_gfp(bdev, block, size, gfp);

	// 一般都能够读取到，如果不是最新的bh，则需要重新读
	if (likely(bh) && !buffer_uptodate(bh))
		bh = __bread_slow(bh);
	return bh;
}

static struct buffer_head *__bread_slow(struct buffer_head *bh)
{
	// 给state设置BH_Lock
	lock_buffer(bh);
	if (buffer_uptodate(bh)) {
		// 因为加锁可能会引起调度，说不定在回来之后，bh已经更新了
		// 当然这种情况不太多
		unlock_buffer(bh);
		return bh;
	} else {
		// 增加引用
		get_bh(bh);
		// 设置更新完的回调
		bh->b_end_io = end_buffer_read_sync;
		// 提交bh请求
		submit_bh(REQ_OP_READ, 0, bh);
		// 等待bh完成，这个是等待BH_Lock解锁，
		// 这个在end_buffer_read_sync里会解锁
		wait_on_buffer(bh);
		
		// 走到这儿，则end_buffer_read_sync已经调用了，在end_buffer_read_sync里会减少bh的引用

		// 如果bh已经更新了，则返回
		if (buffer_uptodate(bh))
			return bh;
	}
	// 减少bh的引用计数
	brelse(bh);
	return NULL;
}

void end_buffer_read_sync(struct buffer_head *bh, int uptodate)
{
	// 设置更新状态并解决bh
	__end_buffer_read_notouch(bh, uptodate);
	// 减少引用
	put_bh(bh);
}

static void __end_buffer_read_notouch(struct buffer_head *bh, int uptodate)
{
	// 根据是否已更新来设置bh的状态
	if (uptodate) {
		set_buffer_uptodate(bh);
	} else {
		/* This happens, due to failed read-ahead attempts. */
		clear_buffer_uptodate(bh);
	}
	
	// 解锁buffer，这个就是清除b_state上的BH_Lock位
	unlock_buffer(bh);
}

```

## brelse
```c
static inline void brelse(struct buffer_head *bh)
{
	if (bh)
		__brelse(bh);
}

void __brelse(struct buffer_head * buf)
{
	if (atomic_read(&buf->b_count)) {
                // 减少bh引用计数
		put_bh(buf);
		return;
	}
	WARN(1, KERN_ERR "VFS: brelse: Trying to free free buffer\n");
}

static inline void put_bh(struct buffer_head *bh)
{
        smp_mb__before_atomic();
        atomic_dec(&bh->b_count);
}
```