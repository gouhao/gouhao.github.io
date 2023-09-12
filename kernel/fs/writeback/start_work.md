# 发起回写流程
源码基于5.10


## wakeup_flusher_threads
```c
/* 
调用点：
1. 从shrink_inactive_list调用，reason=WB_REASON_VMSCAN
2. 从dirty_writeback_centisecs接口的处理函数dirty_writeback_centisecs_handler调用，reson=WB_REASON_PERIODIC
3. 从ksys_sync调用, 这是sync系统调用
*/
void wakeup_flusher_threads(enum wb_reason reason)
{
	struct backing_dev_info *bdi;

	// 当前进程有正在提交plug，则把已提交的plug刷出
	if (blk_needs_flush_plug(current))
		blk_schedule_flush_plug(current);

	rcu_read_lock();
	// 遍历bdilist回写每个bdi
	// bdi_list是全局变量，保存了系统里所有的bdi
	list_for_each_entry_rcu(bdi, &bdi_list, bdi_list)
		// 唤醒每个bdi的回写线程
		__wakeup_flusher_threads_bdi(bdi, reason);
	rcu_read_unlock();
}

static void __wakeup_flusher_threads_bdi(struct backing_dev_info *bdi,
					 enum wb_reason reason)
{
	struct bdi_writeback *wb;

	// 没有脏的wb，则直接返回，这个函数检查的是tot_write_bandwidth，这个值
	// 不为0表示有脏wb
	if (!bdi_has_dirty_io(bdi))
		return;

	// 遍历每个wb，然后回写之
	list_for_each_entry_rcu(wb, &bdi->wb_list, bdi_node)
		wb_start_writeback(wb, reason);
}

static void wb_start_writeback(struct bdi_writeback *wb, enum wb_reason reason)
{
	// wb如果没有WB_has_dirty_io标志，则直接返回
	if (!wb_has_dirty_io(wb))
		return;

	// 只设置一次这个标志，只有一个进程能设置成功
	if (test_bit(WB_start_all, &wb->state) ||
	    test_and_set_bit(WB_start_all, &wb->state))
		return;

	// 第一个设置成功的人会走到这

	// 设置原因，也就是由谁发起的回写
	wb->start_all_reason = reason;

	// 唤醒wb的工作队列
	wb_wakeup(wb);
}

static void wb_wakeup(struct bdi_writeback *wb)
{
	spin_lock_bh(&wb->work_lock);
	if (test_bit(WB_registered, &wb->state))
		// 把wb加入队列，超时时间加0，说明要求立即开始
		// 这个函数里，如果work已经加入，会把它删除，然后重新按新的超时时间加入
		mod_delayed_work(bdi_wq, &wb->dwork, 0);
	spin_unlock_bh(&wb->work_lock);
}
```

## wb_check_start_all
wb_check_start_all在wb_do_writeback里调用
```c
// wb_check_start_all处理wakeup_flusher_threads发出的请求
static long wb_check_start_all(struct bdi_writeback *wb)
{
	long nr_pages;

	// 没有这个标志，返回。
	// 这个标志是由wb_start_writeback设置的
	if (!test_bit(WB_start_all, &wb->state))
		return 0;

	// 获取脏页的数量，这只是一个近似值，但是不影响
	nr_pages = get_nr_dirty_pages();

	// 有脏页了才执行回写
	if (nr_pages) {
		struct wb_writeback_work work = {
			// 按带宽拆分页的数量
			.nr_pages	= wb_split_bdi_pages(wb, nr_pages),
			// 同步模式为NONE，只提交就返回
			.sync_mode	= WB_SYNC_NONE,
			// 可以循环？
			.range_cyclic	= 1,
			// 原因就是wakeup_flusher_threads里设置的原因
			.reason		= wb->start_all_reason,
		};

		// 开始执行work
		nr_pages = wb_writeback(wb, &work);
	}

	// 执行完了，清除标志
	clear_bit(WB_start_all, &wb->state);
	return nr_pages;
}

static unsigned long get_nr_dirty_pages(void)
{
	// 有脏页的inode和脏的inode
	return global_node_page_state(NR_FILE_DIRTY) +
		get_nr_dirty_inodes();
}

long get_nr_dirty_inodes(void)
{
	// 用已使用的inode - 未使用的inode，
	// 其实这并不是脏inode的数量，只是一个近似值
	long nr_dirty = get_nr_inodes() - get_nr_inodes_unused();
	return nr_dirty > 0 ? nr_dirty : 0;
}

static long wb_split_bdi_pages(struct bdi_writeback *wb, long nr_pages)
{
	// wb平均写带宽
	unsigned long this_bw = wb->avg_write_bandwidth;
	// bdi总的写带宽
	unsigned long tot_bw = atomic_long_read(&wb->bdi->tot_write_bandwidth);

	// 写这么多？
	if (nr_pages == LONG_MAX)
		return LONG_MAX;

	// 总带宽为0 || 平均带宽大于总带宽。
	// 说明没有io过或者io效率较高？
	if (!tot_bw || this_bw >= tot_bw)
		return nr_pages;
	else
		// 平均带宽小于总带宽，说明io效率不太高，按带宽分配页数
		return DIV_ROUND_UP_ULL((u64)nr_pages * this_bw, tot_bw);
}
```

## wb_check_old_data_flush
周期回写。这个函数没有主动发起的位置，只有一个调用地方，就是在每次回写的wb_do_writeback时候调用，完全被动。
```c
static long wb_check_old_data_flush(struct bdi_writeback *wb)
{
	unsigned long expired;
	long nr_pages;

	// 周期回写设为0，表示禁用周期回写,
	// 默认是500厘秒，用户层的接口文件:dirty_writeback_centisecs
	if (!dirty_writeback_interval)
		return 0;

	// 过期时间，last_old_flush是上次刷新的时间
	expired = wb->last_old_flush +
			msecs_to_jiffies(dirty_writeback_interval * 10);

	// 如果没过期，直接返回
	if (time_before(jiffies, expired))
		return 0;

	// 记录回写时间
	wb->last_old_flush = jiffies;
	// 如上，获取脏页数量
	nr_pages = get_nr_dirty_pages();

	// 有脏页才回写
	if (nr_pages) {
		struct wb_writeback_work work = {
			.nr_pages	= nr_pages,
			// 不等待
			.sync_mode	= WB_SYNC_NONE,
			.for_kupdate	= 1,
			.range_cyclic	= 1,
			// 原因是周期回写
			.reason		= WB_REASON_PERIODIC,
		};

		// 开始回写
		return wb_writeback(wb, &work);
	}

	return 0;
}
```

## wb_check_background_flush
这个是后台刷新。这个函数没有主动发起的位置，只有一个调用地方，就是在每次回写的wb_do_writeback时候调用，完全被动。
```c
static long wb_check_background_flush(struct bdi_writeback *wb)
{
	// 如果符合后台脏页达到了要刷新的条件，则执行
	// todo: 这个条件没太看懂
	if (wb_over_bg_thresh(wb)) {

		struct wb_writeback_work work = {
			// 刷新页数没限制，后台回写尽可能的多写页
			.nr_pages	= LONG_MAX,
			// 不等待
			.sync_mode	= WB_SYNC_NONE,
			.for_background	= 1,
			.range_cyclic	= 1,
			// 原因是后台刷新
			.reason		= WB_REASON_BACKGROUND,
		};

		// 开始回写
		return wb_writeback(wb, &work);
	}

	return 0;
}

struct dirty_throttle_control {
#ifdef CONFIG_CGROUP_WRITEBACK
	struct wb_domain	*dom;
	struct dirty_throttle_control *gdtc;	/* only set in memcg dtc's */
#endif
	struct bdi_writeback	*wb;
	struct fprop_local_percpu *wb_completions;

	unsigned long		avail;		/* dirtyable */
	unsigned long		dirty;		/* file_dirty + write + nfs */
	unsigned long		thresh;		/* dirty threshold */
	unsigned long		bg_thresh;	/* dirty background threshold */

	unsigned long		wb_dirty;	/* per-wb counterparts */
	unsigned long		wb_thresh;
	unsigned long		wb_bg_thresh;

	unsigned long		pos_ratio;
};

#define GDTC_INIT(__wb)		.wb = (__wb),				\
				.dom = &global_wb_domain,		\
				.wb_completions = &(__wb)->completions

#define MDTC_INIT(__wb, __gdtc)	.wb = (__wb),				\
				.dom = mem_cgroup_wb_domain(__wb),	\
				.wb_completions = &(__wb)->memcg_completions, \
				.gdtc = __gdtc

bool wb_over_bg_thresh(struct bdi_writeback *wb)
{
	struct dirty_throttle_control gdtc_stor = { GDTC_INIT(wb) };
	struct dirty_throttle_control mdtc_stor = { MDTC_INIT(wb, &gdtc_stor) };
	struct dirty_throttle_control * const gdtc = &gdtc_stor;
	struct dirty_throttle_control * const mdtc = mdtc_valid(&mdtc_stor) ?
						     &mdtc_stor : NULL;

	// 所有可用页面
	gdtc->avail = global_dirtyable_memory();
	// 脏文件页面
	gdtc->dirty = global_node_page_state(NR_FILE_DIRTY);
	// 这个函数主要根据vm_dirty_bytes， dirty_background_bytes来计算这2个限制域值
	domain_dirty_limits(gdtc);

	// 脏页超过了后台刷新的域值，进行后台回收
	if (gdtc->dirty > gdtc->bg_thresh)
		return true;

	// 走到这儿表示脏页未超过限制

	// wb的WB_RECLAIMABLE数量比wb的限制大，也进行后台回收
	// todo: wb_calc_thresh没太看懂
	if (wb_stat(wb, WB_RECLAIMABLE) >
	    wb_calc_thresh(gdtc->wb, gdtc->bg_thresh))
		return true;

	// memcg和上面的计算差不多。
	if (mdtc) {
		unsigned long filepages, headroom, writeback;

		mem_cgroup_wb_stats(wb, &filepages, &headroom, &mdtc->dirty,
				    &writeback);
		mdtc_calc_avail(mdtc, filepages, headroom);
		domain_dirty_limits(mdtc);	/* ditto, ignore writeback */

		if (mdtc->dirty > mdtc->bg_thresh)
			return true;

		if (wb_stat(wb, WB_RECLAIMABLE) >
		    wb_calc_thresh(mdtc->wb, mdtc->bg_thresh))
			return true;
	}

	// 上面条件全不符合，表示没有超过限制值
	return false;
}

unsigned long wb_calc_thresh(struct bdi_writeback *wb, unsigned long thresh)
{
	struct dirty_throttle_control gdtc = { GDTC_INIT(wb),
					       .thresh = thresh };
	return __wb_calc_thresh(&gdtc);
}

static unsigned long __wb_calc_thresh(struct dirty_throttle_control *dtc)
{
	struct wb_domain *dom = dtc_dom(dtc);
	unsigned long thresh = dtc->thresh;
	u64 wb_thresh;
	unsigned long numerator, denominator;
	unsigned long wb_min_ratio, wb_max_ratio;

	/*
	 * 计算wb_completions在completions里面所占的比例，
	 * numerator: 结果的分子；denominator: 结果的分母
	 */
	fprop_fraction_percpu(&dom->completions, dtc->wb_completions,
			      &numerator, &denominator);

	// bdi_min_ratio: 脏页最小比例
	wb_thresh = (thresh * (100 - bdi_min_ratio)) / 100;
	wb_thresh *= numerator;
	wb_thresh = div64_ul(wb_thresh, denominator);

	// todo: 没太看懂
	wb_min_max_ratio(dtc->wb, &wb_min_ratio, &wb_max_ratio);

	// 限制wb的最大最小限制值
	wb_thresh += (thresh * wb_min_ratio) / 100;
	if (wb_thresh > (thresh * wb_max_ratio) / 100)
		wb_thresh = thresh * wb_max_ratio / 100;

	return wb_thresh;
}



static void wb_min_max_ratio(struct bdi_writeback *wb,
			     unsigned long *minp, unsigned long *maxp)
{
	unsigned long this_bw = wb->avg_write_bandwidth;
	unsigned long tot_bw = atomic_long_read(&wb->bdi->tot_write_bandwidth);
	unsigned long long min = wb->bdi->min_ratio;
	unsigned long long max = wb->bdi->max_ratio;

	/*
	 * @wb may already be clean by the time control reaches here and
	 * the total may not include its bw.
	 */
	if (this_bw < tot_bw) {
		if (min) {
			min *= this_bw;
			min = div64_ul(min, tot_bw);
		}
		if (max < 100) {
			max *= this_bw;
			max = div64_ul(max, tot_bw);
		}
	}

	*minp = min;
	*maxp = max;
}
static void domain_dirty_limits(struct dirty_throttle_control *dtc)
{
	const unsigned long available_memory = dtc->avail;
	struct dirty_throttle_control *gdtc = mdtc_gdtc(dtc);
	// 脏数据量限制
	unsigned long bytes = vm_dirty_bytes;
	// 后台刷新脏数据量限制
	unsigned long bg_bytes = dirty_background_bytes;
	// 脏页比例
	unsigned long ratio = (vm_dirty_ratio * PAGE_SIZE) / 100;
	// 后台刷新的脏页比例
	unsigned long bg_ratio = (dirty_background_ratio * PAGE_SIZE) / 100;
	unsigned long thresh;
	unsigned long bg_thresh;
	struct task_struct *tsk;

	/* gdtc is !NULL iff @dtc is for memcg domain */
	if (gdtc) {
		// 关于cgroup的计算
		unsigned long global_avail = gdtc->avail;

		/*
		 * The byte settings can't be applied directly to memcg
		 * domains.  Convert them to ratios by scaling against
		 * globally available memory.  As the ratios are in
		 * per-PAGE_SIZE, they can be obtained by dividing bytes by
		 * number of pages.
		 */
		if (bytes)
			ratio = min(DIV_ROUND_UP(bytes, global_avail),
				    PAGE_SIZE);
		if (bg_bytes)
			bg_ratio = min(DIV_ROUND_UP(bg_bytes, global_avail),
				       PAGE_SIZE);
		bytes = bg_bytes = 0;
	}

	// 下面的bytes和ratio会优先使用bytes，分配计算出限制值
	if (bytes)
		thresh = DIV_ROUND_UP(bytes, PAGE_SIZE);
	else
		thresh = (ratio * available_memory) / PAGE_SIZE;

	if (bg_bytes)
		bg_thresh = DIV_ROUND_UP(bg_bytes, PAGE_SIZE);
	else
		bg_thresh = (bg_ratio * available_memory) / PAGE_SIZE;

	// 后台限制太大，则设置为非后台域值的一半。todo: why?
	if (bg_thresh >= thresh)
		bg_thresh = thresh / 2;
	tsk = current;

	// 对实时进程，相应的增加限制域值，减少io？
	if (rt_task(tsk)) {
		bg_thresh += bg_thresh / 4 + global_wb_domain.dirty_limit / 32;
		thresh += thresh / 4 + global_wb_domain.dirty_limit / 32;
	}

	// 设置域值
	dtc->thresh = thresh;
	dtc->bg_thresh = bg_thresh;

	/* we should eventually report the domain in the TP */
	if (!gdtc)
		trace_global_dirty_state(bg_thresh, thresh);
}

static bool mdtc_valid(struct dirty_throttle_control *dtc)
{
	return dtc->dom;
}

static unsigned long global_dirtyable_memory(void)
{
	unsigned long x;

	// 全局空闲页面
	x = global_zone_page_state(NR_FREE_PAGES);
	// 减去保留页面
	x -= min(x, totalreserve_pages);

	// 加上活跃和不活跃的页面
	x += global_node_page_state(NR_INACTIVE_FILE);
	x += global_node_page_state(NR_ACTIVE_FILE);

	if (!vm_highmem_is_dirtyable)
		x -= highmem_dirtyable_memory(x);
	// 确保永远不返回0
	return x + 1;
}
```