# work
源码基于5.10

## wb_workfn
```c
void wb_workfn(struct work_struct *work)
{
	struct bdi_writeback *wb = container_of(to_delayed_work(work),
						struct bdi_writeback, dwork);
	long pages_written;

        // 设置当前worker的名称
	set_worker_desc("flush-%s", bdi_dev_name(wb->bdi));
        // 允许给交换分区写
	current->flags |= PF_SWAPWRITE;

        // 当前进程不是紧急线程 或者当前是紧急线程，但是wb没注册？
	if (likely(!current_is_workqueue_rescuer() ||
		   !test_bit(WB_registered, &wb->state))) {
                // 正常路径
		do {
                        // 开始回写
			pages_written = wb_do_writeback(wb);
			trace_writeback_pages_written(pages_written);

			// 一直写，直到工作队列为空
		} while (!list_empty(&wb->work_list));
	} else {
		// 当前进程是紧急线程，并且wb已经注射了。todo: 什么情况下走这个分支。

		/*
                 * bdi_wq没有足够的worker，我们运行在紧急模式下. 别小题大做，
                 * 1024对于有效的IO足够了
		 */
		// writeback_inodes_wb会调到__writeback_inodes_wb里
		pages_written = writeback_inodes_wb(wb, 1024,
						    WB_REASON_FORKER_THREAD);
		trace_writeback_pages_written(pages_written);
	}

	if (!list_empty(&wb->work_list))
                // 工作队列没执行完，则把wb再加回工作队列里，并且超时时间为0
		wb_wakeup(wb);
	else if (wb_has_dirty_io(wb) && dirty_writeback_interval)
		// 如果work_list空了，但是wb里有WB_has_dirty_io的标志，并且周期回写是打开的，
		// 则延迟唤醒，超时时间是周期回写的时间
		wb_wakeup_delayed(wb);

	// 不允许写入交换？
	current->flags &= ~PF_SWAPWRITE;
}

static long wb_do_writeback(struct bdi_writeback *wb)
{
	struct wb_writeback_work *work;
	long wrote = 0;

        // wb正在运行
	set_bit(WB_writeback_running, &wb->state);

        // 回写所有worklist里的work
	while ((work = get_next_work_item(wb)) != NULL) {
		trace_writeback_exec(wb, work);
		wrote += wb_writeback(wb, work);
		finish_writeback_work(wb, work);
	}

	// 下面这3个wb_check***检查如果符合自己的条件就
	// 构造合适的wb，然后调用wb_writeback函数
	/*
	 * 检查全局刷出请求
	 */
	wrote += wb_check_start_all(wb);

	/*
	 * 检查周期回写
	 */
	wrote += wb_check_old_data_flush(wb);

	// 后台刷新
	wrote += wb_check_background_flush(wb);

	// 清除运行标志
	clear_bit(WB_writeback_running, &wb->state);

	return wrote;
}
```

## wb_writeback
```c
static long wb_writeback(struct bdi_writeback *wb,
			 struct wb_writeback_work *work)
{
	unsigned long wb_start = jiffies;
	long nr_pages = work->nr_pages;
	unsigned long dirtied_before = jiffies;
	struct inode *inode;
	long progress;
	struct blk_plug plug;

        // 下面会提交bio，这个函数会延迟bio的入队，
	// 在调用了blk_finish_plug之后，才会正式入队
	blk_start_plug(&plug);
	spin_lock(&wb->list_lock);
	for (;;) {
		// 所有的页已经写完了，就退出
		if (work->nr_pages <= 0)
			break;

		// 后台刷新和kupdate会一直运行下去，如果worklist不为空，就退出，优化执行worklist，
                // 因为在执行work时，这２个也会执行。
		// 这个条件表示在work_list里有其它work时会优先执行其它的，因为后台回写和周期回写总是会触发
		if ((work->for_background || work->for_kupdate) &&
		    !list_empty(&wb->work_list))
			break;

		/*
                 * 对于后台回写来说，如果我们已经低于后台脏域值，退出
		 */
		if (work->for_background && !wb_over_bg_thresh(wb))
			break;
	
		if (work->for_kupdate) {
			// 周期时间
			dirtied_before = jiffies -
				msecs_to_jiffies(dirty_expire_interval * 10);
		} else if (work->for_background)
			// 后台刷新的时间
			dirtied_before = jiffies;

		trace_writeback_start(wb, work);

		// 这个条件表示：优先回写b_io列表的，如果这个列表为空，才把其它队列的放到io队列
		if (list_empty(&wb->b_io))
                        // 回写io是空的，则把more_io和过期的inode放到io队列
			queue_io(wb, work, dirtied_before);
                
		if (work->sb)
                        // 如果sb有值，则只是针对这一个超级块的回写
			progress = writeback_sb_inodes(work->sb, wb, work);
		else
                        // 否则回写所有inodes，
			// 这个函数遍历io列表里的inode，找到一个inode的sb，就调用writeback_sb_inodes，回写
			// 此sb所有的inode
			progress = __writeback_inodes_wb(wb, work);
		trace_writeback_written(wb, work);

		// 更新带宽。todo: 更新带宽没看懂
		wb_update_bandwidth(wb, wb_start);

		// 有回写的就继续循环
		if (progress)
			continue;
		
		// 走到这儿，表示没有提交什么回写任务

		// 如果more_io也空了，则退出
		if (list_empty(&wb->b_more_io))
			break;
		
		// more_io不为空
		/*
		 * Nothing written. Wait for some inode to
		 * become available for writeback. Otherwise
		 * we'll just busyloop.
		 */
		trace_writeback_wait(wb, work);
		// 从more_io取一个元素
		inode = wb_inode(wb->b_more_io.prev);
		spin_lock(&inode->i_lock);
		spin_unlock(&wb->list_lock);
		// 这个函数是等待inode回写完，如果有的话
		inode_sleep_on_writeback(inode);
		spin_lock(&wb->list_lock);
	}
	spin_unlock(&wb->list_lock);
	blk_finish_plug(&plug);

	// 返回值是成功回写的页数
	return nr_pages - work->nr_pages;
}

void wb_update_bandwidth(struct bdi_writeback *wb, unsigned long start_time)
{
	struct dirty_throttle_control gdtc = { GDTC_INIT(wb) };

	__wb_update_bandwidth(&gdtc, NULL, start_time, false);
}

static void __wb_update_bandwidth(struct dirty_throttle_control *gdtc,
				  struct dirty_throttle_control *mdtc,
				  unsigned long start_time,
				  bool update_ratelimit)
{
	struct bdi_writeback *wb = gdtc->wb;
	unsigned long now = jiffies;
	// bw_time_stamp是上次更新wb的时间
	unsigned long elapsed = now - wb->bw_time_stamp;
	unsigned long dirtied;
	unsigned long written;

	lockdep_assert_held(&wb->list_lock);

	// BANDWIDTH_INTERVAL在频率为HZ/5，如果间隔小于它，则不更新
	if (elapsed < BANDWIDTH_INTERVAL)
		return;

	// 脏的数量
	dirtied = percpu_counter_read(&wb->stat[WB_DIRTIED]);
	// 已经写的数量
	written = percpu_counter_read(&wb->stat[WB_WRITTEN]);

	/*
	 * 当磁盘带宽利用率不足时，跳过静默期
	 * 在2个flusher之间最小间隔1秒
	 */
	if (elapsed > HZ && time_before(wb->bw_time_stamp, start_time))
		goto snapshot;

	if (update_ratelimit) {
		domain_update_bandwidth(gdtc, now);
		wb_update_dirty_ratelimit(gdtc, dirtied, elapsed);

		/*
		 * @mdtc is always NULL if !CGROUP_WRITEBACK but the
		 * compiler has no way to figure that out.  Help it.
		 */
		if (IS_ENABLED(CONFIG_CGROUP_WRITEBACK) && mdtc) {
			domain_update_bandwidth(mdtc, now);
			wb_update_dirty_ratelimit(mdtc, dirtied, elapsed);
		}
	}

	// 更新写带宽
	wb_update_write_bandwidth(wb, elapsed, written);

snapshot:
	// 记录脏和已写入的时间
	wb->dirtied_stamp = dirtied;
	wb->written_stamp = written;
	wb->bw_time_stamp = now;
}

static void wb_update_write_bandwidth(struct bdi_writeback *wb,
				      unsigned long elapsed,
				      unsigned long written)
{
	// 周期是3秒？
	const unsigned long period = roundup_pow_of_two(3 * HZ);
	unsigned long avg = wb->avg_write_bandwidth;
	unsigned long old = wb->write_bandwidth;
	u64 bw;

	/*
	 * bw = written * HZ / elapsed
	 *
	 *                   bw * elapsed + write_bandwidth * (period - elapsed)
	 * write_bandwidth = ---------------------------------------------------
	 *                                          period
	 *
	 * @written may have decreased due to account_page_redirty().
	 * Avoid underflowing @bw calculation.
	 */
	// 下面是按上面的公式算出带宽
	bw = written - min(written, wb->written_stamp);
	bw *= HZ;
	if (unlikely(elapsed > period)) {
		bw = div64_ul(bw, elapsed);
		avg = bw;
		goto out;
	}
	bw += (u64)wb->write_bandwidth * (period - elapsed);
	bw >>= ilog2(period);

	// 更新平均带宽
	if (avg > old && old >= (unsigned long)bw)
		avg -= (avg - old) >> 3;

	if (avg < old && old <= (unsigned long)bw)
		avg += (old - avg) >> 3;

out:
	// 不能超过1
	avg = max(avg, 1LU);
	// 如果有脏io，则更新设备的写带宽
	if (wb_has_dirty_io(wb)) {
		long delta = avg - wb->avg_write_bandwidth;
		WARN_ON_ONCE(atomic_long_add_return(delta,
					&wb->bdi->tot_write_bandwidth) <= 0);
	}
	// 记录写带宽
	wb->write_bandwidth = bw;
	// 平均写带宽
	wb->avg_write_bandwidth = avg;
}

static void inode_sleep_on_writeback(struct inode *inode)
	__releases(inode->i_lock)
{
	DEFINE_WAIT(wait);
	// 定义一个位等待队列
	wait_queue_head_t *wqh = bit_waitqueue(&inode->i_state, __I_SYNC);
	int sleep;

	// 等待
	prepare_to_wait(wqh, &wait, TASK_UNINTERRUPTIBLE);

	// 走到这儿，是已经被唤醒了

	// 再次获取状态
	sleep = inode->i_state & I_SYNC;
	spin_unlock(&inode->i_lock);

	// 如果还是有同步标志，则调度？
	if (sleep)
		schedule();
	// 结束等待
	finish_wait(wqh, &wait);
}
```

## queue_io
```c
static void queue_io(struct bdi_writeback *wb, struct wb_writeback_work *work,
		     unsigned long dirtied_before)
{
	int moved;
	unsigned long time_expire_jif = dirtied_before;

	assert_spin_locked(&wb->list_lock);
        // 把more_io转移到io列表
	list_splice_init(&wb->b_more_io, &wb->b_io);
        // 把超期的inode放到io队列里
	moved = move_expired_inodes(&wb->b_dirty, &wb->b_io, dirtied_before);
        // 如果不是同步，则把过期的dirty_time队列的也移到io列表
	if (!work->for_sync)
		time_expire_jif = jiffies - dirtytime_expire_interval * HZ;
	moved += move_expired_inodes(&wb->b_dirty_time, &wb->b_io,
				     time_expire_jif);
        // 设置WB_has_dirty_io，更新统计数据
	if (moved)
		wb_io_lists_populated(wb);
	trace_writeback_queue_io(wb, work, dirtied_before, moved);
}

static int move_expired_inodes(struct list_head *delaying_queue,
			       struct list_head *dispatch_queue,
			       unsigned long dirtied_before)
{
	LIST_HEAD(tmp);
	struct list_head *pos, *node;
	struct super_block *sb = NULL;
	struct inode *inode;
	int do_sb_sort = 0;
	int moved = 0;

	while (!list_empty(delaying_queue)) {
                // 取一个inode
		inode = wb_inode(delaying_queue->prev);
                // 如果在超时时间之后，则直接break，说明delaying_queue里是排好序的
		if (inode_dirtied_after(inode, dirtied_before))
			break;
                // 转移到临时列表
		list_move(&inode->i_io_list, &tmp);
		moved++;
		spin_lock(&inode->i_lock);
                // 更新inode状态
		inode->i_state |= I_SYNC_QUEUED;
		spin_unlock(&inode->i_lock);
                // 是不是bdev文件系统，正常情况都不是
		if (sb_is_blkdev_sb(inode->i_sb))
			continue;
                
                // 如果有多个超级块，则对超级块做排序
		if (sb && sb != inode->i_sb)
			do_sb_sort = 1;
                // 记录超级块
		sb = inode->i_sb;
	}

	// 只有一个sb，则拼接到目标队列
	if (!do_sb_sort) {
		list_splice(&tmp, dispatch_queue);
		goto out;
	}

	// 下面循环是把同一个sb的inode在目标队列里连续排放
	while (!list_empty(&tmp)) {
                // 取最后的sb
		sb = wb_inode(tmp.prev)->i_sb;
                // 把等于sb的放到目标队列
		list_for_each_prev_safe(pos, node, &tmp) {
			inode = wb_inode(pos);
			if (inode->i_sb == sb)
				list_move(&inode->i_io_list, dispatch_queue);
		}
	}
out:
	return moved;
}

static bool wb_io_lists_populated(struct bdi_writeback *wb)
{
	if (wb_has_dirty_io(wb)) {
		return false;
	} else {
                // 写状态
		set_bit(WB_has_dirty_io, &wb->state);
		WARN_ON_ONCE(!wb->avg_write_bandwidth);
                // 更新平均写带宽
		atomic_long_add(wb->avg_write_bandwidth,
				&wb->bdi->tot_write_bandwidth);
		return true;
	}
}
```

## writeback_sb_inodes
```c
static long writeback_sb_inodes(struct super_block *sb,
				struct bdi_writeback *wb,
				struct wb_writeback_work *work)
{
        // 把work里的值复制到wbc里
	struct writeback_control wbc = {
		.sync_mode		= work->sync_mode,
		.tagged_writepages	= work->tagged_writepages,
		.for_kupdate		= work->for_kupdate,
		.for_background		= work->for_background,
		.for_sync		= work->for_sync,
		.range_cyclic		= work->range_cyclic,
		.range_start		= 0,
		.range_end		= LLONG_MAX,
	};
	unsigned long start_time = jiffies;
	long write_chunk;
	long total_wrote = 0;  /* count both pages and inodes */

	while (!list_empty(&wb->b_io)) {
		struct inode *inode = wb_inode(wb->b_io.prev);
		struct bdi_writeback *tmp_wb;
		long wrote;

                // 不属于目标超级块
		if (inode->i_sb != sb) {
			if (work->sb) {
				// 只同步目标超级块，把这个inode从io链表解链，再放回dirty列表
				redirty_tail(inode, wb);
				continue;
			}
                        // 如果没有指定写超级块，则退出。todo:why?
			break;
		}

                // 走到这儿表示inode是目标超级块
		spin_lock(&inode->i_lock);

                /*
                 * 不用担心新inode和正在释放的，前者不需要周期回写，后者的回写会被释放的函数处理，
                 * 所以对于这2种inode，重新放回dirty列表
		 */
		if (inode->i_state & (I_NEW | I_FREEING | I_WILL_FREE)) {
			redirty_tail_locked(inode, wb);
			spin_unlock(&inode->i_lock);
			continue;
		}
                // inode正在回写同步　&& 不是数据完整性回写
		if ((inode->i_state & I_SYNC) && wbc.sync_mode != WB_SYNC_ALL) {
			spin_unlock(&inode->i_lock);
			// 当我们遍历了所有b_io后，再重新回写这个inode，所以把它加到more_io列表
			requeue_io(inode, wb);
			trace_writeback_sb_inodes_requeue(inode);
			continue;
		}
		spin_unlock(&wb->list_lock);

		// 这个inode正在回写，所以这个流程只针对完整性的回写
		if (inode->i_state & I_SYNC) {
			// 等待回写完成
			inode_sleep_on_writeback(inode);
			/* Inode may be gone, start again */
			spin_lock(&wb->list_lock);
			continue;
		}

		// 走到这儿，这个inode还没有回写

		// 先设置回写状态
		inode->i_state |= I_SYNC;
		// 把inode与wbc关联
		wbc_attach_and_unlock_inode(&wbc, inode);

		// 计算page的数量
		write_chunk = writeback_chunk_size(wb, work);
		// 设置需要写的页
		wbc.nr_to_write = write_chunk;
		wbc.pages_skipped = 0;

		// 用I_SYNC把inode钉到内存里，当evict_inode调用时不会释放inode，它会等到inode完成，
		__writeback_single_inode(inode, &wbc);

		//把inode和wbc分离。 todo: 这个函数没看懂
		wbc_detach_inode(&wbc);

		// nr_to_write是还剩余没写的页，下面是算出上面__writeback_single_inode写了多少页
		work->nr_pages -= write_chunk - wbc.nr_to_write;
		// 再减去跳过的，是真正写了的页
		wrote = write_chunk - wbc.nr_to_write - wbc.pages_skipped;
		wrote = wrote < 0 ? 0 : wrote;
		// 总共写入的页
		total_wrote += wrote;

		// 如果需要调度，则让出cpu
		if (need_resched()) {
			// 刷出block层的请求
			blk_flush_plug(current);
			cond_resched();
		}

		// 获取新的wb结构
		tmp_wb = inode_to_wb_and_lock_list(inode);
		spin_lock(&inode->i_lock);

		// todo: 有这个标志为什么要多加一页?
		if (!(inode->i_state & I_DIRTY_ALL))
			total_wrote++;
		// 根据inode的状态，放到不同的列表里
		requeue_inode(inode, tmp_wb, &wbc);
		// 同步完成，修改状态
		inode_sync_complete(inode);
		spin_unlock(&inode->i_lock);

		// 2个wb不相等，说明在回写过程中wb变了，则需要重新加锁
		if (unlikely(tmp_wb != wb)) {
			spin_unlock(&tmp_wb->list_lock);
			spin_lock(&wb->list_lock);
		}

		// 有写入
		if (total_wrote) {
			// 本次写入超过了开始时间的1/10秒，则退出，不能太长会影响其它进程
			if (time_is_before_jiffies(start_time + HZ / 10UL))
				break;
			// 没有要写入的了，也退出
			if (work->nr_pages <= 0)
				break;
		}
	}
	return total_wrote;
}

static void inode_sync_complete(struct inode *inode)
{
	// 清除同步标志
	inode->i_state &= ~I_SYNC;
	// 如果inode没人用，则加到超级块的lru列表
	inode_add_lru(inode);
	// 内存栅栏，前面修改的值，对栅栏后面的人都可见
	smp_mb();
	// 唤醒等待__I_SYNC标志的人
	wake_up_bit(&inode->i_state, __I_SYNC);
}

void inode_add_lru(struct inode *inode)
{
	// 不脏，不释放 && 没有引用 && 活跃
	if (!(inode->i_state & (I_DIRTY_ALL | I_SYNC |
				I_FREEING | I_WILL_FREE)) &&
	    !atomic_read(&inode->i_count) && inode->i_sb->s_flags & SB_ACTIVE)
		inode_lru_list_add(inode);
}

static void inode_lru_list_add(struct inode *inode)
{
	// 把inode加到超级块的lru列表
	if (list_lru_add(&inode->i_sb->s_inode_lru, &inode->i_lru))
		// 添加成功，增加未使用的统计？
		this_cpu_inc(nr_unused);
	else
		// 添加失败，inode正在被用
		inode->i_state |= I_REFERENCED;
}

bool list_lru_add(struct list_lru *lru, struct list_head *item)
{
	// 找到内存所在的node
	int nid = page_to_nid(virt_to_page(item));
	// node对应的lru
	struct list_lru_node *nlru = &lru->node[nid];
	struct mem_cgroup *memcg;
	struct list_lru_one *l;

	spin_lock(&nlru->lock);

	// 只有item是空时才允许添加
	if (list_empty(item)) {
		// 返回对应的lru列表
		l = list_lru_from_kmem(nlru, item, &memcg);
		// 添加到lru列表末尾
		list_add_tail(item, &l->list);
		
		// 如果是列表的第一个元素
		if (!l->nr_items++)
			memcg_set_shrinker_bit(memcg, nid,
					       lru_shrinker_id(lru));
		// node的元素增加
		nlru->nr_items++;
		spin_unlock(&nlru->lock);
		return true;
	}
	spin_unlock(&nlru->lock);
	return false;
}

static void requeue_inode(struct inode *inode, struct bdi_writeback *wb,
			  struct writeback_control *wbc)
{
	// 正在释放
	if (inode->i_state & I_FREEING)
		return;

	// inode是脏的 && (完整性同步 || tagged_writepages)
	if ((inode->i_state & I_DIRTY) &&
	    (wbc->sync_mode == WB_SYNC_ALL || wbc->tagged_writepages))
		inode->dirtied_when = jiffies;

	// 有跳过的页
	if (wbc->pages_skipped) {
		/*
		 * writeback is not making progress due to locked
		 * buffers. Skip this inode for now.
		 */
		redirty_tail_locked(inode, wb);
		return;
	}

	// mapping里有页被标为dirty
	if (mapping_tagged(inode->i_mapping, PAGECACHE_TAG_DIRTY)) {
		if (wbc->nr_to_write <= 0) {
			// 移动到more_io列表
			requeue_io(inode, wb);
		} else {
			// 这个分支表示有拥塞？

			// 移动到脏列表末尾
			redirty_tail_locked(inode, wb);
		}
	} else if (inode->i_state & I_DIRTY) {
		// inode是脏的，则加到脏列表末尾
		redirty_tail_locked(inode, wb);
	} else if (inode->i_state & I_DIRTY_TIME) {
		// 移动到dirty_time列表
		inode->dirtied_when = jiffies;
		inode_io_list_move_locked(inode, wb, &wb->b_dirty_time);
		inode->i_state &= ~I_SYNC_QUEUED;
	} else {
		// inode是干净的，从回写列表里删除
		inode_io_list_del_locked(inode, wb);
	}
}

static void inode_io_list_del_locked(struct inode *inode,
				     struct bdi_writeback *wb)
{
	assert_spin_locked(&wb->list_lock);
	assert_spin_locked(&inode->i_lock);

	// 清除标志
	inode->i_state &= ~I_SYNC_QUEUED;
	// 从列表里解链
	list_del_init(&inode->i_io_list);

	wb_io_lists_depopulated(wb);
}

static void wb_io_lists_depopulated(struct bdi_writeback *wb)
{
	if (wb_has_dirty_io(wb) && list_empty(&wb->b_dirty) &&
	    list_empty(&wb->b_io) && list_empty(&wb->b_more_io)) {
		// 如果所有列表都空了，则清除wb的dirty_io标志
		clear_bit(WB_has_dirty_io, &wb->state);
		// 统计总的写带宽
		WARN_ON_ONCE(atomic_long_sub_return(wb->avg_write_bandwidth,
					&wb->bdi->tot_write_bandwidth) < 0);
	}
}


static void redirty_tail_locked(struct inode *inode, struct bdi_writeback *wb)
{
	assert_spin_locked(&inode->i_lock);

	if (!list_empty(&wb->b_dirty)) {
		struct inode *tail;

		tail = wb_inode(wb->b_dirty.next);
		// 如果inode的脏时间在最后一个元素之前，则把inode设置为当前的脏时间
		if (time_before(inode->dirtied_when, tail->dirtied_when))
			inode->dirtied_when = jiffies;
	}
	// 移动到脏列表
	inode_io_list_move_locked(inode, wb, &wb->b_dirty);
	// 没有到同步队列里
	inode->i_state &= ~I_SYNC_QUEUED;
}

static bool inode_io_list_move_locked(struct inode *inode,
				      struct bdi_writeback *wb,
				      struct list_head *head)
{
	assert_spin_locked(&wb->list_lock);

	list_move(&inode->i_io_list, head);

	/* dirty_time doesn't count as dirty_io until expiration */
	if (head != &wb->b_dirty_time)
		return wb_io_lists_populated(wb);

	wb_io_lists_depopulated(wb);
	return false;
}

static struct bdi_writeback *inode_to_wb_and_lock_list(struct inode *inode)
	__acquires(&wb->list_lock)
{
	spin_lock(&inode->i_lock);
	return locked_inode_to_wb_and_lock_list(inode);
}

static struct bdi_writeback * locked_inode_to_wb_and_lock_list(struct inode *inode)
	__releases(&inode->i_lock)
	__acquires(&wb->list_lock)
{
	while (true) {
		struct bdi_writeback *wb = inode_to_wb(inode);

		/*
		 * inode_to_wb() association is protected by both
		 * @inode->i_lock and @wb->list_lock but list_lock nests
		 * outside i_lock.  Drop i_lock and verify that the
		 * association hasn't changed after acquiring list_lock.
		 */
		wb_get(wb);
		spin_unlock(&inode->i_lock);
		spin_lock(&wb->list_lock);

		// 大部分情况下都是相等的
		if (likely(wb == inode->i_wb)) {
			wb_put(wb);	/* @inode already has ref */
			return wb;
		}

		// 如果不等就重新获取，在加锁期间可能改变？
		spin_unlock(&wb->list_lock);
		wb_put(wb);
		cpu_relax();
		spin_lock(&inode->i_lock);
	}
}

void wbc_detach_inode(struct writeback_control *wbc)
{
	struct bdi_writeback *wb = wbc->wb;
	struct inode *inode = wbc->inode;
	unsigned long avg_time, max_bytes, max_time;
	u16 history;
	int max_id;

	if (!wb)
		return;

	// todo: 下面的计算没看懂
	history = inode->i_wb_frn_history;
	avg_time = inode->i_wb_frn_avg_time;

	/* pick the winner of this round */
	if (wbc->wb_bytes >= wbc->wb_lcand_bytes &&
	    wbc->wb_bytes >= wbc->wb_tcand_bytes) {
		max_id = wbc->wb_id;
		max_bytes = wbc->wb_bytes;
	} else if (wbc->wb_lcand_bytes >= wbc->wb_tcand_bytes) {
		max_id = wbc->wb_lcand_id;
		max_bytes = wbc->wb_lcand_bytes;
	} else {
		max_id = wbc->wb_tcand_id;
		max_bytes = wbc->wb_tcand_bytes;
	}

	/*
	 * Calculate the amount of IO time the winner consumed and fold it
	 * into the running average kept per inode.  If the consumed IO
	 * time is lower than avag / WB_FRN_TIME_CUT_DIV, ignore it for
	 * deciding whether to switch or not.  This is to prevent one-off
	 * small dirtiers from skewing the verdict.
	 */
	max_time = DIV_ROUND_UP((max_bytes >> PAGE_SHIFT) << WB_FRN_TIME_SHIFT,
				wb->avg_write_bandwidth);
	if (avg_time)
		avg_time += (max_time >> WB_FRN_TIME_AVG_SHIFT) -
			    (avg_time >> WB_FRN_TIME_AVG_SHIFT);
	else
		avg_time = max_time;	/* immediate catch up on first run */

	if (max_time >= avg_time / WB_FRN_TIME_CUT_DIV) {
		int slots;

		/*
		 * The switch verdict is reached if foreign wb's consume
		 * more than a certain proportion of IO time in a
		 * WB_FRN_TIME_PERIOD.  This is loosely tracked by 16 slot
		 * history mask where each bit represents one sixteenth of
		 * the period.  Determine the number of slots to shift into
		 * history from @max_time.
		 */
		slots = min(DIV_ROUND_UP(max_time, WB_FRN_HIST_UNIT),
			    (unsigned long)WB_FRN_HIST_MAX_SLOTS);
		history <<= slots;
		if (wbc->wb_id != max_id)
			history |= (1U << slots) - 1;

		if (history)
			trace_inode_foreign_history(inode, wbc, history);

		/*
		 * Switch if the current wb isn't the consistent winner.
		 * If there are multiple closely competing dirtiers, the
		 * inode may switch across them repeatedly over time, which
		 * is okay.  The main goal is avoiding keeping an inode on
		 * the wrong wb for an extended period of time.
		 */
		if (hweight32(history) > WB_FRN_HIST_THR_SLOTS)
			inode_switch_wbs(inode, max_id);
	}

	/*
	 * Multiple instances of this function may race to update the
	 * following fields but we don't mind occassional inaccuracies.
	 */
	inode->i_wb_frn_winner = max_id;
	inode->i_wb_frn_avg_time = min(avg_time, (unsigned long)U16_MAX);
	inode->i_wb_frn_history = history;

	// 解wb引用
	wb_put(wbc->wb);
	wbc->wb = NULL;
}

static int
__writeback_single_inode(struct inode *inode, struct writeback_control *wbc)
{
	struct address_space *mapping = inode->i_mapping;
	long nr_to_write = wbc->nr_to_write;
	unsigned dirty;
	int ret;

	// todo: 什么时候会没有同步标志?
	WARN_ON(!(inode->i_state & I_SYNC));

	trace_writeback_single_inode_start(inode, wbc, nr_to_write);

	// 写inode里的页，这里面主要使用page-cache的方法
	ret = do_writepages(mapping, wbc);

	// 对于数据完整性来说，不需要处理sync系统调用，因为它有自己的方法来保证元数据被正确的写入
	if (wbc->sync_mode == WB_SYNC_ALL && !wbc->for_sync) {
		// 非for_sync需要在这里等待写入完成
		int err = filemap_fdatawait(mapping);
		if (ret == 0)
			ret = err;
	}

	// 如果有脏时间戳 && （完整同步 || sync同步 || 标记时间戳变脏的时间已经过去了dirtytime_expire_interval秒)
	if ((inode->i_state & I_DIRTY_TIME) &&
	    (wbc->sync_mode == WB_SYNC_ALL || wbc->for_sync ||
	     time_after(jiffies, inode->dirtied_time_when +__mark_inode_dirty
			dirtytime_expire_interval * HZ))) {
		trace_writeback_lazytime(inode);
		// 给inode标记I_DIRTY_SYNC
		mark_inode_dirty_sync(inode);
	}

	spin_lock(&inode->i_lock);
	dirty = inode->i_state & I_DIRTY;
	// 先取消脏标记，因为一些文件系统在回写期间会标脏
	inode->i_state &= ~dirty;

	// 内存栅栏，为了让大家都看到修改的状态
	smp_mb();

	// 如果文件映射的页里有PAGECACHE_TAG_DIRTY标记，则把inode标脏页
	if (mapping_tagged(mapping, PAGECACHE_TAG_DIRTY))
		inode->i_state |= I_DIRTY_PAGES;

	spin_unlock(&inode->i_lock);

	// 如果有I_DIRTY_INODE，再回写inode,
	// I_DIRTY是dirtypage和dirtynode的组合，
	if (dirty & ~I_DIRTY_PAGES) {
		// 如果inode不是bad_inode，则调用文件系统的writeinode来同步inode
		int err = write_inode(inode, wbc);
		if (ret == 0)
			ret = err;
	}
	trace_writeback_single_inode(inode, wbc, nr_to_write);
	return ret;
}

int do_writepages(struct address_space *mapping, struct writeback_control *wbc)
{
	int ret;

	// 没有要写的，是怎么进到这个函数的
	if (wbc->nr_to_write <= 0)
		return 0;
	while (1) {
		// 回写页，调用自己的函数或者通用函数
		if (mapping->a_ops->writepages)
			ret = mapping->a_ops->writepages(mapping, wbc);
		else
			ret = generic_writepages(mapping, wbc);
		//　如果是没内存且是完整性回写需要单独处理
		if ((ret != -ENOMEM) || (wbc->sync_mode != WB_SYNC_ALL))
			// 其它情况直接返回
			break;
		
		// 走到这儿表示是完整性同步，且没有内存了

		// 让出cpu，让回收线程有机会执行
		cond_resched();

		// 等待设备不拥塞，超时为1/50秒
		congestion_wait(BLK_RW_ASYNC, HZ/50);
	}
	return ret;
}

int generic_writepages(struct address_space *mapping,
		       struct writeback_control *wbc)
{
	struct blk_plug plug;
	int ret;

	// 必须要有写页的函数
	if (!mapping->a_ops->writepage)
		return 0;

	// 初始化plug，block层会推迟io的提交，直到blk_finish_plug
	blk_start_plug(&plug);
	// 回写目标mapping里的页。todo：写页后面再看
	ret = write_cache_pages(mapping, wbc, __writepage, mapping);
	blk_finish_plug(&plug);
	return ret;
}

static int __writepage(struct page *page, struct writeback_control *wbc,
		       void *data)
{
	struct address_space *mapping = data;
	int ret = mapping->a_ops->writepage(page, wbc);
	mapping_set_error(mapping, ret);
	return ret;
}

int write_cache_pages(struct address_space *mapping,
		      struct writeback_control *wbc, writepage_t writepage,
		      void *data)
{
	int ret = 0;
	int done = 0;
	int error;
	struct pagevec pvec;
	int nr_pages;
	pgoff_t index;
	pgoff_t end;		/* Inclusive */
	pgoff_t done_index;
	int range_whole = 0;
	xa_mark_t tag;

	pagevec_init(&pvec);
	if (wbc->range_cyclic) {
		// 以上次回写的为起点？
		index = mapping->writeback_index; /* prev offset */
		// end没限制
		end = -1;
	} else {
		// 指定了回写范围
		index = wbc->range_start >> PAGE_SHIFT;
		end = wbc->range_end >> PAGE_SHIFT;
		// 如果起点是0，并且
		if (wbc->range_start == 0 && wbc->range_end == LLONG_MAX)
			range_whole = 1;
	}

	if (wbc->sync_mode == WB_SYNC_ALL || wbc->tagged_writepages) {
		// 把每个标了PAGECACHE_TAG_DIRTY的页标记为PAGECACHE_TAG_TOWRITE
		tag_pages_for_writeback(mapping, index, end);
		tag = PAGECACHE_TAG_TOWRITE;
	} else {
		// 如果不是完整性同步，就只回写脏页
		tag = PAGECACHE_TAG_DIRTY;
	}
	done_index = index;
	while (!done && (index <= end)) {
		int i;

		// 在start和end之间找到对应tag的页
		nr_pages = pagevec_lookup_range_tag(&pvec, mapping, &index, end,
				tag);
		// 没有对应tag的页
		if (nr_pages == 0)
			break;

		for (i = 0; i < nr_pages; i++) {
			struct page *page = pvec.pages[i];

			done_index = page->index;

			lock_page(page);

			// page被截断或者无效
			if (unlikely(page->mapping != mapping)) {
continue_unlock:
				unlock_page(page);
				continue;
			}

			// 锁了之后，页不脏了，别人可能写了
			if (!PageDirty(page)) {
				/* someone wrote it for us */
				goto continue_unlock;
			}

			// 页已经有writeback的标志
			if (PageWriteback(page)) {
				// WB_SYNC_NONE是只发出请求就行了，其它模式需要等待回写完成
				if (wbc->sync_mode != WB_SYNC_NONE)
					wait_on_page_writeback(page);
				else
					// WB_SYNC_NONE模式，继续循环
					goto continue_unlock;
			}

			// 什么时候会走到这里？
			BUG_ON(PageWriteback(page));

			// 这个函数清除页映射的pte的标志，并把页标脏，返回之前页的脏状态
			if (!clear_page_dirty_for_io(page))
				goto continue_unlock;

			trace_wbc_writepage(wbc, inode_to_bdi(mapping->host));
			// 真正的回写
			error = (*writepage)(page, wbc, data);
			if (unlikely(error)) {
				// 报错
				if (error == AOP_WRITEPAGE_ACTIVATE) {
					unlock_page(page);
					error = 0;
				} else if (wbc->sync_mode != WB_SYNC_ALL) {
					ret = error;
					done_index = page->index + 1;
					done = 1;
					break;
				}
				if (!ret)
					ret = error;
			}

			// 需要回写的已经写完，并且只是提交请求，则直接退出
			if (--wbc->nr_to_write <= 0 &&
			    wbc->sync_mode == WB_SYNC_NONE) {
				done = 1;
				break;
			}
		}
		pagevec_release(&pvec);
		cond_resched();
	}

	// 如果是循环写，但是没有完成，则从头开始？
	if (wbc->range_cyclic && !done)
		done_index = 0;
	// 记录上次写完的回写坐标
	if (wbc->range_cyclic || (range_whole && wbc->nr_to_write > 0))
		mapping->writeback_index = done_index;

	return ret;
}

static int __writepage(struct page *page, struct writeback_control *wbc,
		       void *data)
{
	struct address_space *mapping = data;
	// 写页
	int ret = mapping->a_ops->writepage(page, wbc);
	// 设置mapping里的一些错误信息
	mapping_set_error(mapping, ret);
	return ret;
}

static inline void mapping_set_error(struct address_space *mapping, int error)
{
	// 没错
	if (likely(!error))
		return;

	// 把error设置到设置mapping->wb_err
	__filemap_set_wb_err(mapping, error);

	// 如果有inode，则把error设置到inode里
	if (mapping->host)
		errseq_set(&mapping->host->i_sb->s_wb_err, error);

	// 设置对应的标志
	if (error == -ENOSPC)
		set_bit(AS_ENOSPC, &mapping->flags);
	else
		set_bit(AS_EIO, &mapping->flags);
}

void __filemap_set_wb_err(struct address_space *mapping, int err)
{
	errseq_t eseq = errseq_set(&mapping->wb_err, err);

	trace_filemap_set_wb_err(mapping, eseq);
}


int clear_page_dirty_for_io(struct page *page)
{
	struct address_space *mapping = page_mapping(page);
	int ret = 0;

	// page没有上锁就是出问题了
	VM_BUG_ON_PAGE(!PageLocked(page), page);

	if (mapping && mapping_can_writeback(mapping)) {
		struct inode *inode = mapping->host;
		struct bdi_writeback *wb;
		struct wb_lock_cookie cookie = {};

		// 刷新page对应的所有映射pte，返回true，表示有被清理的
		if (page_mkclean(page))
			// 对page，以及对应的inode标脏
			set_page_dirty(page);
		/*
		 * We carefully synchronise fault handlers against
		 * installing a dirty pte and marking the page dirty
		 * at this point.  We do this by having them hold the
		 * page lock while dirtying the page, and pages are
		 * always locked coming in here, so we get the desired
		 * exclusion.
		 */
		wb = unlocked_inode_to_wb_begin(inode, &cookie);
		// 清除page脏标志，并递减一些统计量
		if (TestClearPageDirty(page)) {
			dec_lruvec_page_state(page, NR_FILE_DIRTY);
			dec_zone_page_state(page, NR_ZONE_WRITE_PENDING);
			dec_wb_stat(wb, WB_RECLAIMABLE);
			ret = 1;
		}
		unlocked_inode_to_wb_end(inode, &cookie);
		return ret;
	}
	return TestClearPageDirty(page);
}

int page_mkclean(struct page *page)
{
	int cleaned = 0;
	struct address_space *mapping;
	struct rmap_walk_control rwc = {
		.arg = (void *)&cleaned,
		.rmap_one = page_mkclean_one,
		.invalid_vma = invalid_mkclean_vma,
	};

	BUG_ON(!PageLocked(page));

	// page没映射
	if (!page_mapped(page))
		return 0;

	mapping = page_mapping(page);
	if (!mapping)
		return 0;

	// 遍历page对应的vma
	rmap_walk(page, &rwc);

	return cleaned;
}

static bool invalid_mkclean_vma(struct vm_area_struct *vma, void *arg)
{
	// 不修改共享的页
	if (vma->vm_flags & VM_SHARED)
		return false;

	return true;
}

static bool page_mkclean_one(struct page *page, struct vm_area_struct *vma,
			    unsigned long address, void *arg)
{
	struct page_vma_mapped_walk pvmw = {
		.page = page,
		.vma = vma,
		.address = address,
		.flags = PVMW_SYNC,
	};
	struct mmu_notifier_range range;
	int *cleaned = arg;

	/*
	 * We have to assume the worse case ie pmd for invalidation. Note that
	 * the page can not be free from this function.
	 */
	mmu_notifier_range_init(&range, MMU_NOTIFY_PROTECTION_PAGE,
				0, vma, vma->vm_mm, address,
				vma_address_end(page, vma));
	mmu_notifier_invalidate_range_start(&range);

	// 遍历page对应的所有页表项
	// todo: 这个遍历函数有点复杂，没太看懂
	while (page_vma_mapped_walk(&pvmw)) {
		int ret = 0;

		address = pvmw.address;
		if (pvmw.pte) {
			// 有pte

			pte_t entry;
			pte_t *pte = pvmw.pte;
			// 下面pte涉及的函数只看了arch/x86里的

			// pte里没有_PAGE_DIRTY和_PAGE_RW标志
			if (!pte_dirty(*pte) && !pte_write(*pte))
				continue;

			// 这个函数x86没有定义
			flush_cache_page(vma, address, pte_pfn(*pte));

			// 清除pte里的值，并刷新cache，返回值是原来的pte
			entry = ptep_clear_flush(vma, address, pte);
			// 请求_PAGE_RW标志，下次访问时会引发page_fault?
			entry = pte_wrprotect(entry);
			// 清除_PAGE_DIRTY标志
			entry = pte_mkclean(entry);
			// 重新设置pte
			set_pte_at(vma->vm_mm, address, pte, entry);
			ret = 1;
		} else {
			// 没有pte
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
			// 只设置大页的pte ?
			pmd_t *pmd = pvmw.pmd;
			pmd_t entry;

			if (!pmd_dirty(*pmd) && !pmd_write(*pmd))
				continue;

			flush_cache_page(vma, address, page_to_pfn(page));
			entry = pmdp_invalidate(vma, address, pmd);
			entry = pmd_wrprotect(entry);
			entry = pmd_mkclean(entry);
			set_pmd_at(vma->vm_mm, address, pmd, entry);
			ret = 1;
#else
			/* unexpected pmd-mapped page? */
			WARN_ON_ONCE(1);
#endif
		}

		/*
		 * No need to call mmu_notifier_invalidate_range() as we are
		 * downgrading page table protection not changing it to point
		 * to a new page.
		 *
		 * See Documentation/vm/mmu_notifier.rst
		 */
		if (ret)
			(*cleaned)++;
	}

	mmu_notifier_invalidate_range_end(&range);

	return true;
}

int set_page_dirty(struct page *page)
{
	struct address_space *mapping = page_mapping(page);

	// 找到页的头指针
	page = compound_head(page);
	if (likely(mapping)) {
		// 文件系统的set_page_dirty函数
		int (*spd)(struct page *) = mapping->a_ops->set_page_dirty;
		// 清除page的回收标志？
		if (PageReclaim(page))
			ClearPageReclaim(page);
#ifdef CONFIG_BLOCK
		// 文件系统没定义就使用默认的函数
		if (!spd)
			spd = __set_page_dirty_buffers;
#endif
		return (*spd)(page);
	}

	// 没有mapping的路径

	// 对page进行标脏
	if (!PageDirty(page)) {
		if (!TestSetPageDirty(page))
			return 1;
	}
	return 0;
}

int __set_page_dirty_buffers(struct page *page)
{
	int newly_dirty;
	struct address_space *mapping = page_mapping(page);

	// 没有mapping就只设置页有脏状态
	if (unlikely(!mapping))
		return !TestSetPageDirty(page);

	spin_lock(&mapping->private_lock);

	// 标记buffer里的每个bh的脏状态
	if (page_has_buffers(page)) {
		struct buffer_head *head = page_buffers(page);
		struct buffer_head *bh = head;

		do {
			set_buffer_dirty(bh);
			bh = bh->b_this_page;
		} while (bh != head);
	}
	
	lock_page_memcg(page);
	// 设置page的脏状态，返回值为true表示之前不是脏的
	newly_dirty = !TestSetPageDirty(page);
	spin_unlock(&mapping->private_lock);

	// 如果是新脏的，在基数树里标记页的脏状态
	if (newly_dirty)
		__set_page_dirty(page, mapping, 1);

	unlock_page_memcg(page);

	// 标记inode为脏，在这个函数里，可能会把work加到回写队列里
	if (newly_dirty)
		__mark_inode_dirty(mapping->host, I_DIRTY_PAGES);

	return newly_dirty;
}

void __set_page_dirty(struct page *page, struct address_space *mapping,
			     int warn)
{
	unsigned long flags;

	xa_lock_irqsave(&mapping->i_pages, flags);
	if (page->mapping) {
		// page 不是最新的为什么要打警告？
		WARN_ON_ONCE(warn && !PageUptodate(page));

		// 增加各个统计里的脏页数
		account_page_dirtied(page, mapping);
		// 设置页的脏标志
		__xa_set_mark(&mapping->i_pages, page_index(page),
				PAGECACHE_TAG_DIRTY);
	}
	xa_unlock_irqrestore(&mapping->i_pages, flags);
}

void account_page_dirtied(struct page *page, struct address_space *mapping)
{
	struct inode *inode = mapping->host;

	trace_writeback_dirty_page(page, mapping);

	if (mapping_can_writeback(mapping)) {
		struct bdi_writeback *wb;

		// inode和wb关联
		inode_attach_wb(inode, page);
		wb = inode_to_wb(inode);

		// 增加lruvec里的脏计数
		__inc_lruvec_page_state(page, NR_FILE_DIRTY);
		// 增加zone里面待写的计数
		__inc_zone_page_state(page, NR_ZONE_WRITE_PENDING);
		// 增加node里脏的计数
		__inc_node_page_state(page, NR_DIRTIED);
		
		// 增加wb里可回收计数
		inc_wb_stat(wb, WB_RECLAIMABLE);
		// 增加wb里脏计数
		inc_wb_stat(wb, WB_DIRTIED);
		// 增加进程的io字节数
		task_io_account_write(PAGE_SIZE);
		// 当前进程的脏页数？
		current->nr_dirtied++;
		// todo: what?
		this_cpu_inc(bdp_ratelimits);

		mem_cgroup_track_foreign_dirty(page, wb);
	}
}
unsigned pagevec_lookup_range_tag(struct pagevec *pvec,
		struct address_space *mapping, pgoff_t *index, pgoff_t end,
		xa_mark_t tag)
{
	// 从index到end找到tag的页
	pvec->nr = find_get_pages_range_tag(mapping, index, end, tag,
					PAGEVEC_SIZE, pvec->pages);
	return pagevec_count(pvec);
}

void wbc_attach_and_unlock_inode(struct writeback_control *wbc,
				 struct inode *inode)
{
	// 检测在这个inode上是否使能了inode回写，一般情况下都会使能吧
	if (!inode_cgwb_enabled(inode)) {
		spin_unlock(&inode->i_lock);
		return;
	}

	// 把inode与wb相关联
	wbc->wb = inode_to_wb(inode);
	wbc->inode = inode;

	wbc->wb_id = wbc->wb->memcg_css->id;
	wbc->wb_lcand_id = inode->i_wb_frn_winner;
	wbc->wb_tcand_id = 0;
	wbc->wb_bytes = 0;
	wbc->wb_lcand_bytes = 0;
	wbc->wb_tcand_bytes = 0;

	// 增加引用计数
	wb_get(wbc->wb);
	spin_unlock(&inode->i_lock);


	// wb正在销毁。todo: 异常情况后面再看
	/*
	 * A dying wb indicates that either the blkcg associated with the
	 * memcg changed or the associated memcg is dying.  In the first
	 * case, a replacement wb should already be available and we should
	 * refresh the wb immediately.  In the second case, trying to
	 * refresh will keep failing.
	 */
	if (unlikely(wb_dying(wbc->wb) && !css_is_dying(wbc->wb->memcg_css)))
		inode_switch_wbs(inode, wbc->wb_id);
}

static long writeback_chunk_size(struct bdi_writeback *wb,
				 struct wb_writeback_work *work)
{
	long pages;

	/*
	 * WB_SYNC_ALL mode does livelock avoidance by syncing dirty
	 * inodes/pages in one big loop. Setting wbc.nr_to_write=LONG_MAX
	 * here avoids calling into writeback_inodes_wb() more than once.
	 *
	 * The intended call sequence for WB_SYNC_ALL writeback is:
	 *
	 *      wb_writeback()
	 *          writeback_sb_inodes()       <== called only once
	 *              write_cache_pages()     <== called once for each inode
	 *                   (quickly) tag currently dirty pages
	 *                   (maybe slowly) sync all tagged pages
	 */
	// 如果是完整性同步 || tagged？
	if (work->sync_mode == WB_SYNC_ALL || work->tagged_writepages)
		// 设置pages为最大值
		pages = LONG_MAX;
	else {
		// 计算最大page
		pages = min(wb->avg_write_bandwidth / 2,
			    global_wb_domain.dirty_limit / DIRTY_SCOPE);
		// 本次要写的数量
		pages = min(pages, work->nr_pages);
		// 向下对齐到MIN_WRITEBACK_PAGES?
		pages = round_down(pages + MIN_WRITEBACK_PAGES,
				   MIN_WRITEBACK_PAGES);
	}

	return pages;
}
```

## __writeback_inodes_wb
```c
static long __writeback_inodes_wb(struct bdi_writeback *wb,
				  struct wb_writeback_work *work)
{
	unsigned long start_time = jiffies;
	long wrote = 0;

	// 遍历io列表
	while (!list_empty(&wb->b_io)) {
		struct inode *inode = wb_inode(wb->b_io.prev);
		struct super_block *sb = inode->i_sb;

		// 如果不能给sb上锁，则加到dirty列表末尾
		if (!trylock_super(sb)) {
			/*
			 * trylock_super() may fail consistently due to
			 * s_umount being grabbed by someone else. Don't use
			 * requeue_io() to avoid busy retrying the inode/sb.
			 */
			redirty_tail(inode, wb);
			continue;
		}
		// 写超级块的inode
		wrote += writeback_sb_inodes(sb, wb, work);
		up_read(&sb->s_umount);

		/* refer to the same tests at the end of writeback_sb_inodes */
		if (wrote) {
			// 本次写入超过了开始时间的1/10秒，则退出，不能太长会影响其它进程
			if (time_is_before_jiffies(start_time + HZ / 10UL))
				break;
			// 没有要写入的了，也退出
			if (work->nr_pages <= 0)
				break;
		}
	}
	/* Leave any unwritten inodes on b_io */
	return wrote;
}
```