# add work
源码基于5.10

## __mark_inode_dirty
添加work的入口好像只有2个，一个在work_fn里，一个就是给inode标脏的时候
```c
void __mark_inode_dirty(struct inode *inode, int flags)
{
	struct super_block *sb = inode->i_sb;
	int dirtytime;

	trace_writeback_mark_inode_dirty(inode, flags);

	// #define I_DIRTY_INODE (I_DIRTY_SYNC | I_DIRTY_DATASYNC)，同步元数据及文件数据
	// I_DIRTY_TIME：只是时间脏了？
	// 有这2个标志之一或全部时，调用文件系统方法进行标脏
	if (flags & (I_DIRTY_INODE | I_DIRTY_TIME)) {
		trace_writeback_dirty_inode_start(inode, flags);

		if (sb->s_op->dirty_inode)
			sb->s_op->dirty_inode(inode, flags);

		trace_writeback_dirty_inode(inode, flags);
	}
	// I_DIRTY_INODE里包括了I_DIRTY_TIME，所以把这个标志去了
	if (flags & I_DIRTY_INODE)
		flags &= ~I_DIRTY_TIME;
	
	// dirtytime如果为true，说明flags里只有I_DIRTY_TIME
	dirtytime = flags & I_DIRTY_TIME;

	/*
	 * Paired with smp_mb() in __writeback_single_inode() for the
	 * following lockless i_state test.  See there for details.
	 */
	smp_mb();

	// 当前inode的标志和要求的相同或者时间变脏但是inode已经被标脏
	if (((inode->i_state & flags) == flags) ||
	    (dirtytime && (inode->i_state & I_DIRTY_INODE)))
		return;

	spin_lock(&inode->i_lock);
	// 加锁之后状态可能改变，所以再判断一次
	if (dirtytime && (inode->i_state & I_DIRTY_INODE))
		goto out_unlock_inode;
	
	// 和当前inode标志不一样
	if ((inode->i_state & flags) != flags) {
		// 已经脏了，#define I_DIRTY (I_DIRTY_INODE | I_DIRTY_PAGES)
		const int was_dirty = inode->i_state & I_DIRTY;

		// 给inode设置wb
		inode_attach_wb(inode, NULL);

		// 脏inode时，去除脏时间
		if (flags & I_DIRTY_INODE)
			inode->i_state &= ~I_DIRTY_TIME;
		// 设置状态
		inode->i_state |= flags;

		// 已经入队的，只需要更新他的标志就行了
		if (inode->i_state & I_SYNC_QUEUED)
			goto out_unlock_inode;

		// 非blk结点，没有哈希，则退出，只添加已哈希的
		// todo: 哈希是在什么时候做的?
		if (!S_ISBLK(inode->i_mode)) {
			if (inode_unhashed(inode))
				goto out_unlock_inode;
		}

		// 正在释放的，则退出
		if (inode->i_state & I_FREEING)
			goto out_unlock_inode;

		// 以前不是脏的，现在变脏了，如果之前就已经脏了，就不要移动它了，
		// 因为在wb的列表里是按时间排好序的，再移动就会打乱它的顺序
		if (!was_dirty) {
			

			struct bdi_writeback *wb;
			struct list_head *dirty_list;
			bool wakeup_bdi = false;

			// 获取inode的wb
			wb = locked_inode_to_wb_and_lock_list(inode);

			WARN((wb->bdi->capabilities & BDI_CAP_WRITEBACK) &&
			     !test_bit(WB_registered, &wb->state),
			     "bdi-%s not registered\n", bdi_dev_name(wb->bdi));

			// 设置脏的时间，是当前
			inode->dirtied_when = jiffies;

			// 如果时间标脏，则记录时间变脏的时间
			if (dirtytime)
				inode->dirtied_time_when = jiffies;

			if (inode->i_state & I_DIRTY)
				// 有数据变脏，加到脏列表
				dirty_list = &wb->b_dirty;
			else
				// 只是时间变脏，则加到时间脏列表
				dirty_list = &wb->b_dirty_time;

			// 移到对应的脏列表里，返回值:wb是否新设置的WB_has_dirty_io标志，如果设置了返回 true，
			// 如果之前已经设置了返回false，这个标志表示wb是否已经放到脏列表上了，也就是这个inode是不是
			// 第一次变脏。如果要移动的列表是b_dirty_time，则这个只返回false
			wakeup_bdi = inode_io_list_move_locked(inode, wb,
							       dirty_list);

			spin_unlock(&wb->list_lock);
			trace_writeback_dirty_inode_enqueue(inode);

			// 如果是第一次变脏，就要把wb加到，回写队列里，后面执行回写
			if (wakeup_bdi &&
			    (wb->bdi->capabilities & BDI_CAP_WRITEBACK))
			    	// inode变脏后，不需要立即回写，所以唤醒会延迟一会
				wb_wakeup_delayed(wb);
			return;
		}
	}
out_unlock_inode:
	spin_unlock(&inode->i_lock);
}

static inline void inode_attach_wb(struct inode *inode, struct page *page)
{
	// 如果inode没设置wb，则设置之
	if (!inode->i_wb)
		__inode_attach_wb(inode, page);
}

void __inode_attach_wb(struct inode *inode, struct page *page)
{
	struct backing_dev_info *bdi = inode_to_bdi(inode);
	struct bdi_writeback *wb = NULL;

	if (inode_cgwb_enabled(inode)) {
		// 这个条件一般都符合
		struct cgroup_subsys_state *memcg_css;

		// 下面是创建或获取一个wb，只是memcg的获取方式不同
		if (page) {
			memcg_css = mem_cgroup_css_from_page(page);
			wb = wb_get_create(bdi, memcg_css, GFP_ATOMIC);
		} else {
			memcg_css = task_get_css(current, memory_cgrp_id);
			wb = wb_get_create(bdi, memcg_css, GFP_ATOMIC);
			css_put(memcg_css);
		}
	}

	// wb没创建成功就用设备的wb
	if (!wb)
		wb = &bdi->wb;

	// 设置wb，但是如果有人设置了其他wb，就释放这个wb
	if (unlikely(cmpxchg(&inode->i_wb, NULL, wb)))
		wb_put(wb);
}


struct bdi_writeback *wb_get_create(struct backing_dev_info *bdi,
				    struct cgroup_subsys_state *memcg_css,
				    gfp_t gfp)
{
	struct bdi_writeback *wb;

	// 标记有可能阻塞
	might_sleep_if(gfpflags_allow_blocking(gfp));

	// 父cg为0, 直接返回设备的wb
	if (!memcg_css->parent)
		return &bdi->wb;

	do {
		// 从树上获取
		wb = wb_get_lookup(bdi, memcg_css);
		// 如果没获取到，则创建之，然后再去获取。todo: 这是无锁并发吗？
	} while (!wb && !cgwb_create(bdi, memcg_css, gfp));

	return wb;
}

struct bdi_writeback *wb_get_lookup(struct backing_dev_info *bdi,
				    struct cgroup_subsys_state *memcg_css)
{
	struct bdi_writeback *wb;

	// 父cg为0, 直接返回
	if (!memcg_css->parent)
		return &bdi->wb;

	rcu_read_lock();
	// 从tree里找wb
	wb = radix_tree_lookup(&bdi->cgwb_tree, memcg_css->id);
	if (wb) {
		struct cgroup_subsys_state *blkcg_css;

		// 检查wb里的blkcg是否改变，如果没变的化增加wb的引用
		blkcg_css = cgroup_get_e_css(memcg_css->cgroup, &io_cgrp_subsys);
		if (unlikely(wb->blkcg_css != blkcg_css || !wb_tryget(wb)))
			wb = NULL;
		css_put(blkcg_css);
	}
	rcu_read_unlock();

	return wb;
}

static int cgwb_create(struct backing_dev_info *bdi,
		       struct cgroup_subsys_state *memcg_css, gfp_t gfp)
{
	struct mem_cgroup *memcg;
	struct cgroup_subsys_state *blkcg_css;
	struct blkcg *blkcg;
	struct list_head *memcg_cgwb_list, *blkcg_cgwb_list;
	struct bdi_writeback *wb;
	unsigned long flags;
	int ret = 0;

	// 获取cg相关的数据
	memcg = mem_cgroup_from_css(memcg_css);
	blkcg_css = cgroup_get_e_css(memcg_css->cgroup, &io_cgrp_subsys);
	blkcg = css_to_blkcg(blkcg_css);
	memcg_cgwb_list = &memcg->cgwb_list;
	blkcg_cgwb_list = &blkcg->cgwb_list;

	/* look up again under lock and discard on blkcg mismatch */
	spin_lock_irqsave(&cgwb_lock, flags);
	wb = radix_tree_lookup(&bdi->cgwb_tree, memcg_css->id);
	// 先从树上找，如果找到的wb的blkcg与当前进程的不同，则kill之
	if (wb && wb->blkcg_css != blkcg_css) {
		cgwb_kill(wb);
		wb = NULL;
	}
	spin_unlock_irqrestore(&cgwb_lock, flags);
	// 如果已经找到则退出
	if (wb)
		goto out_put;

	// 分配一个wb
	wb = kmalloc(sizeof(*wb), gfp);
	if (!wb) {
		ret = -ENOMEM;
		goto out_put;
	}

	// 初始化wb
	ret = wb_init(wb, bdi, gfp);
	if (ret)
		goto err_free;

	// 引用计数置0
	ret = percpu_ref_init(&wb->refcnt, cgwb_release, 0, gfp);
	if (ret)
		goto err_wb_exit;

	// ？？
	ret = fprop_local_init_percpu(&wb->memcg_completions, gfp);
	if (ret)
		goto err_ref_exit;

	// 设置memcg, blkcg
	wb->memcg_css = memcg_css;
	wb->blkcg_css = blkcg_css;
	// 释放时的函数
	INIT_WORK(&wb->release_work, cgwb_release_workfn);
	// 设置已注册状态
	set_bit(WB_registered, &wb->state);

	/*
	 * The root wb determines the registered state of the whole bdi and
	 * memcg_cgwb_list and blkcg_cgwb_list's next pointers indicate
	 * whether they're still online.  Don't link @wb if any is dead.
	 * See wb_memcg_offline() and wb_blkcg_offline().
	 */
	ret = -ENODEV;
	spin_lock_irqsave(&cgwb_lock, flags);
	// 加锁之后还要检查一下bdi的register状态
	if (test_bit(WB_registered, &bdi->wb.state) &&
	    blkcg_cgwb_list->next && memcg_cgwb_list->next) {
		// 把wb加到树里，key是memcg的id
		ret = radix_tree_insert(&bdi->cgwb_tree, memcg_css->id, wb);
		if (!ret) {
			// 添加成功

			// 加到bdi的列表
			list_add_tail_rcu(&wb->bdi_node, &bdi->wb_list);

			// 加到相关cg的列表
			list_add(&wb->memcg_node, memcg_cgwb_list);
			list_add(&wb->blkcg_node, blkcg_cgwb_list);
			// 增加online_pin的引用
			blkcg_pin_online(blkcg);

			// 获取相关的引用
			css_get(memcg_css);
			css_get(blkcg_css);
		}
	}
	spin_unlock_irqrestore(&cgwb_lock, flags);
	if (ret) {
		if (ret == -EEXIST)
			ret = 0;
		goto err_fprop_exit;
	}
	goto out_put;

err_fprop_exit:
	fprop_local_destroy_percpu(&wb->memcg_completions);
err_ref_exit:
	percpu_ref_exit(&wb->refcnt);
err_wb_exit:
	wb_exit(wb);
err_free:
	kfree(wb);
out_put:
	css_put(blkcg_css);
	return ret;
}

void wb_wakeup_delayed(struct bdi_writeback *wb)
{
	unsigned long timeout;

	// 超时时间是回写间隔的时间，间隔时间是厘秒，所以要乘以10
	timeout = msecs_to_jiffies(dirty_writeback_interval * 10);
	spin_lock_bh(&wb->work_lock);
	// 如果wb已经注册，则把wb放到bdi_wq工作队列上
	if (test_bit(WB_registered, &wb->state))
		queue_delayed_work(bdi_wq, &wb->dwork, timeout);
	spin_unlock_bh(&wb->work_lock);
}
```

## wb_queue_work
给wb添加任务
```c
static void wb_queue_work(struct bdi_writeback *wb,
			  struct wb_writeback_work *work)
{
	trace_writeback_queue(wb, work);

	// 任务已完成
	if (work->done)
		atomic_inc(&work->done->cnt);

	spin_lock_bh(&wb->work_lock);

	// wb已注册
	if (test_bit(WB_registered, &wb->state)) {
		// 加到wb列表末尾
		list_add_tail(&work->list, &wb->work_list);
		// 修改超时时间为0，或者把work加到bdi队列
		mod_delayed_work(bdi_wq, &wb->dwork, 0);
	} else
		// 没有注册，直接释放
		finish_writeback_work(wb, work);

	spin_unlock_bh(&wb->work_lock);
}

static void finish_writeback_work(struct bdi_writeback *wb,
				  struct wb_writeback_work *work)
{
	struct wb_completion *done = work->done;

	// 有自动释放标志，直接释放
	if (work->auto_free)
		kfree(work);
	// 已经完成
	if (done) {
		wait_queue_head_t *waitq = done->waitq;

		// 引用减1后，如果为0,则唤醒等待的队列
		if (atomic_dec_and_test(&done->cnt))
			wake_up_all(waitq);
	}
}
```

## bdi_split_work_to_wbs
它的调用者有sync_inodes_sb, __writeback_inodes_sb_nr，通常在同步超级块的时候调用？
```c
static void bdi_split_work_to_wbs(struct backing_dev_info *bdi,
				  struct wb_writeback_work *base_work,
				  bool skip_if_busy)
{
	struct bdi_writeback *last_wb = NULL;
	struct bdi_writeback *wb = list_entry(&bdi->wb_list,
					      struct bdi_writeback, bdi_node);

	might_sleep();
restart:
	rcu_read_lock();

	// 遍历bdi上所有wb
	list_for_each_entry_continue_rcu(wb, &bdi->wb_list, bdi_node) {
		DEFINE_WB_COMPLETION(fallback_work_done, bdi);
		struct wb_writeback_work fallback_work;
		struct wb_writeback_work *work;
		long nr_pages;

		// 释放之前的wb引用
		if (last_wb) {
			wb_put(last_wb);
			last_wb = NULL;
		}

		// wb没有脏inode，dirty_time列表也是空，则不给这个wb里放
		// 因为可能不会进行回写，或者回写会很晚
		if (!wb_has_dirty_io(wb) &&
		    (base_work->sync_mode == WB_SYNC_NONE ||
		     list_empty(&wb->b_dirty_time)))
			continue;
		// 如果这个wb正在回写，并且要跳过忙的，则跳之
		if (skip_if_busy && writeback_in_progress(wb))
			continue;
		// 按当前wb的带宽来决定写多少页。
		nr_pages = wb_split_bdi_pages(wb, base_work->nr_pages);

		work = kmalloc(sizeof(*work), GFP_ATOMIC);
		if (work) {
			// 复制原来work的信息
			*work = *base_work;
			// 这个work要写入的页数
			work->nr_pages = nr_pages;

			// 自动释放
			work->auto_free = 1;
			// 加到wb的work队列里
			wb_queue_work(wb, work);
			continue;
		}

		// 下面是分配work失败，一般情况不会走这里

		// 使用在栈上分配的work
		work = &fallback_work;
		// 复制basework的内容
		*work = *base_work;

		// 栈上的work就写所有的页
		work->nr_pages = nr_pages;

		// 不要释放，因为这是在栈上分配的
		work->auto_free = 0;
		work->done = &fallback_work_done;

		// 把work入队
		wb_queue_work(wb, work);

		// 增加引用，钉住wb
		wb_get(wb);
		last_wb = wb;

		rcu_read_unlock();
		// 等待fallback写结束
		wb_wait_for_completion(&fallback_work_done);

		// todo: 分配work失败，为什么要退出循环重来？
		goto restart;
	}
	rcu_read_unlock();

	if (last_wb)
		wb_put(last_wb);
}
```

## cgroup_writeback_by_id
只有一个调用地方，memcg里按id进行回写
```c
int cgroup_writeback_by_id(u64 bdi_id, int memcg_id, unsigned long nr,
			   enum wb_reason reason, struct wb_completion *done)
{
	struct backing_dev_info *bdi;
	struct cgroup_subsys_state *memcg_css;
	struct bdi_writeback *wb;
	struct wb_writeback_work *work;
	int ret;

	// 找bdi
	bdi = bdi_get_by_id(bdi_id);
	if (!bdi)
		return -ENOENT;

	// 找memcg
	rcu_read_lock();
	memcg_css = css_from_id(memcg_id, &memory_cgrp_subsys);
	if (memcg_css && !css_tryget(memcg_css))
		memcg_css = NULL;
	rcu_read_unlock();
	if (!memcg_css) {
		ret = -ENOENT;
		goto out_bdi_put;
	}

	// 找到memcg相关的wb
	wb = wb_get_lookup(bdi, memcg_css);
	if (!wb) {
		ret = -ENOENT;
		goto out_css_put;
	}

	// nr为0，表示想写尽可能多的页
	if (!nr) {
		unsigned long filepages, headroom, dirty, writeback;

		// 当前cgroup的脏页状态
		mem_cgroup_wb_stats(wb, &filepages, &headroom, &dirty,
				      &writeback);
		// nr为脏页的1.25倍，这应该足够大
		nr = dirty * 10 / 8;
	}

	// 分配一个work
	work = kzalloc(sizeof(*work), GFP_NOWAIT | __GFP_NOWARN);
	if (work) {
		work->nr_pages = nr;
		work->sync_mode = WB_SYNC_NONE;
		// 范围内循环？
		work->range_cyclic = 1;
		work->reason = reason;
		work->done = done;
		work->auto_free = 1;
		// 把work加入wb的队列
		wb_queue_work(wb, work);
		ret = 0;
	} else {
		ret = -ENOMEM;
	}

	wb_put(wb);
out_css_put:
	css_put(memcg_css);
out_bdi_put:
	bdi_put(bdi);
	return ret;
}

void mem_cgroup_wb_stats(struct bdi_writeback *wb, unsigned long *pfilepages,
			 unsigned long *pheadroom, unsigned long *pdirty,
			 unsigned long *pwriteback)
{
	// wb的memcg
	struct mem_cgroup *memcg = mem_cgroup_from_css(wb->memcg_css);
	struct mem_cgroup *parent;

	// 脏文件的数量
	*pdirty = memcg_exact_page_state(memcg, NR_FILE_DIRTY);

	// 正在回写的数量？
	*pwriteback = memcg_exact_page_state(memcg, NR_WRITEBACK);
	// 文件映射的数量：活跃的 + 不活跃的
	*pfilepages = memcg_exact_page_state(memcg, NR_INACTIVE_FILE) +
			memcg_exact_page_state(memcg, NR_ACTIVE_FILE);
	*pheadroom = PAGE_COUNTER_MAX;

	// pheadroom是计费相关？
	while ((parent = parent_mem_cgroup(memcg))) {
		unsigned long ceiling = min(READ_ONCE(memcg->memory.max),
					    READ_ONCE(memcg->memory.high));
		unsigned long used = page_counter_read(&memcg->memory);

		*pheadroom = min(*pheadroom, ceiling - min(ceiling, used));
		memcg = parent;
	}
}

static unsigned long memcg_exact_page_state(struct mem_cgroup *memcg, int idx)
{
	// memcg里的统计
	long x = atomic_long_read(&memcg->vmstats[idx]);
	int cpu;

	// 再加上每个cpu里的统计？
	for_each_online_cpu(cpu)
		x += per_cpu_ptr(memcg->vmstats_percpu, cpu)->stat[idx];
	if (x < 0)
		x = 0;
	return x;
}

```