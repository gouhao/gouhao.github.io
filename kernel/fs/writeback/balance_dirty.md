## balance_dirty_pages_ratelimited
这个函数调用的地方比较多，其中在`generic_perform_write`（buffer-write)里，每次写入一页数据，就会调用这个函数。
```c
void balance_dirty_pages_ratelimited(struct address_space *mapping)
{
	struct inode *inode = mapping->host;
	struct backing_dev_info *bdi = inode_to_bdi(inode);
	struct bdi_writeback *wb = NULL;
	int ratelimit;
	int *p;

	//　bdi没有回写能力
	if (!(bdi->capabilities & BDI_CAP_WRITEBACK))
		return;

	// 获取或创建一个wb实例
	if (inode_cgwb_enabled(inode))
		wb = wb_get_create_current(bdi, GFP_KERNEL);
	// 如果inode没有自己的wb，则使用设备的wb
	if (!wb)
		wb = &bdi->wb;

	// 对平衡频率的限制？
	ratelimit = current->nr_dirtied_pause;

	// 如果脏页较多，则减少限制
	if (wb->dirty_exceeded)
		ratelimit = min(ratelimit, 32 >> (PAGE_SHIFT - 10));

	// 禁用抢占
	preempt_disable();
	/*
	 * 原文注释:
	 * 	bdp_ratelimits阻止了一个cpu在没有调用balance_dirty_pages时累积了太多的脏页，这在1000+
	 *	的进程同时标记脏页时可能发生，因此所有人都接受太大的初始task->nr_dirtied_pause
	 */
	p =  this_cpu_ptr(&bdp_ratelimits);

	if (unlikely(current->nr_dirtied >= ratelimit))
		// 当前进程已经脏的页数大于限制
		*p = 0;
	else if (unlikely(*p >= ratelimit_pages)) {
		// todo: what?
		*p = 0;
		ratelimit = 0;
	}
	/*
	 * 原文注释:
	 *	拾取退出进程弄脏的页面，避免了一些短进程避开脏限制，对长期脏任务形成活锁
	 */
	// todo: 这个计算没太看懂，如果进程的脏页较少，则给它加上已退出进程的脏页？
	p = this_cpu_ptr(&dirty_throttle_leaks);
	if (*p > 0 && current->nr_dirtied < ratelimit) {
		unsigned long nr_pages_dirtied;
		// 达到限制的脏页数
		nr_pages_dirtied = min(*p, ratelimit - current->nr_dirtied);
		*p -= nr_pages_dirtied;
		current->nr_dirtied += nr_pages_dirtied;
	}
	preempt_enable();

	// 脏页数大于限制值，则开始平衡
	if (unlikely(current->nr_dirtied >= ratelimit))
		balance_dirty_pages(wb, current->nr_dirtied);

	wb_put(wb);
}

static inline struct bdi_writeback *
wb_get_create_current(struct backing_dev_info *bdi, gfp_t gfp)
{
	struct bdi_writeback *wb;

	rcu_read_lock();
	// 找当前进程的wb
	wb = wb_find_current(bdi);
	if (wb && unlikely(!wb_tryget(wb)))
		wb = NULL;
	rcu_read_unlock();

	// 如果wb为空，则创建之
	if (unlikely(!wb)) {
		struct cgroup_subsys_state *memcg_css;

		memcg_css = task_get_css(current, memory_cgrp_id);
		// 创建wb
		wb = wb_get_create(bdi, memcg_css, gfp);
		css_put(memcg_css);
	}
	return wb;
}

static inline struct bdi_writeback *wb_find_current(struct backing_dev_info *bdi)
{
	struct cgroup_subsys_state *memcg_css;
	struct bdi_writeback *wb;

	// 获取当前进程的memcg
	memcg_css = task_css(current, memory_cgrp_id);
	// 没有父cg，就返回设备的wb
	// 普通进程都会从这里返回吧！！
	if (!memcg_css->parent)
		return &bdi->wb;

	// 在bdi树里找到对应的wb
	wb = radix_tree_lookup(&bdi->cgwb_tree, memcg_css->id);

	// 如果wb的blkcg与进程的相同，则返回wb
	if (likely(wb && wb->blkcg_css == task_css(current, io_cgrp_id)))
		return wb;
	return NULL;
}

static void balance_dirty_pages(struct bdi_writeback *wb,
				unsigned long pages_dirtied)
{
	// 脏页调节域值
	struct dirty_throttle_control gdtc_stor = { GDTC_INIT(wb) };
	struct dirty_throttle_control mdtc_stor = { MDTC_INIT(wb, &gdtc_stor) };
	struct dirty_throttle_control * const gdtc = &gdtc_stor;
	struct dirty_throttle_control * const mdtc = mdtc_valid(&mdtc_stor) ?
						     &mdtc_stor : NULL;
	struct dirty_throttle_control *sdtc;
	unsigned long nr_reclaimable;	/* = file_dirty */
	long period;
	long pause;
	long max_pause;
	long min_pause;
	int nr_dirtied_pause;
	bool dirty_exceeded = false;
	unsigned long task_ratelimit;
	unsigned long dirty_ratelimit;
	struct backing_dev_info *bdi = wb->bdi;
	// 这个标志是保持脏页数量在域值以下
	bool strictlimit = bdi->capabilities & BDI_CAP_STRICTLIMIT;
	unsigned long start_time = jiffies;

	for (;;) {
		unsigned long now = jiffies;
		unsigned long dirty, thresh, bg_thresh;
		unsigned long m_dirty = 0;	/* stop bogus uninit warnings */
		unsigned long m_thresh = 0;
		unsigned long m_bg_thresh = 0;

		// 脏文件数，也就是可回收的页数
		nr_reclaimable = global_node_page_state(NR_FILE_DIRTY);
		// 系统所有可用的页
		gdtc->avail = global_dirtyable_memory();

		// 已经脏的页
		gdtc->dirty = nr_reclaimable + global_node_page_state(NR_WRITEBACK);

		// 计算后台刷新的阈值
		domain_dirty_limits(gdtc);

		// 根据是否严格限制来决定不同的值
		if (unlikely(strictlimit)) {
			// 严格模式下以wb的阈值为准
			wb_dirty_limits(gdtc);

			dirty = gdtc->wb_dirty;
			thresh = gdtc->wb_thresh;
			bg_thresh = gdtc->wb_bg_thresh;
		} else {
			// 非严格模式下以全局阈值为准
			dirty = gdtc->dirty;
			thresh = gdtc->thresh;
			bg_thresh = gdtc->bg_thresh;
		}

		// 同上，如果有memcg的话，计算对应的阈值
		if (mdtc) {
			unsigned long filepages, headroom, writeback;

			/*
			 * If @wb belongs to !root memcg, repeat the same
			 * basic calculations for the memcg domain.
			 */
			mem_cgroup_wb_stats(wb, &filepages, &headroom,
					    &mdtc->dirty, &writeback);
			mdtc->dirty += writeback;
			mdtc_calc_avail(mdtc, filepages, headroom);

			domain_dirty_limits(mdtc);

			if (unlikely(strictlimit)) {
				wb_dirty_limits(mdtc);
				m_dirty = mdtc->wb_dirty;
				m_thresh = mdtc->wb_thresh;
				m_bg_thresh = mdtc->wb_bg_thresh;
			} else {
				m_dirty = mdtc->dirty;
				m_thresh = mdtc->thresh;
				m_bg_thresh = mdtc->bg_thresh;
			}
		}

		/*
		 * Throttle it only when the background writeback cannot
		 * catch-up. This avoids (excessively) small writeouts
		 * when the wb limits are ramping up in case of !strictlimit.
		 *
		 * In strictlimit case make decision based on the wb counters
		 * and limits. Small writeouts when the wb limits are ramping
		 * up are the price we consciously pay for strictlimit-ing.
		 *
		 * If memcg domain is in effect, @dirty should be under
		 * both global and memcg freerun ceilings.
		 */
		// dirty_freerun_ceiling = (thresh + bg_thresh) / 2;
		if (dirty <= dirty_freerun_ceiling(thresh, bg_thresh) &&
		    (!mdtc ||
		     m_dirty <= dirty_freerun_ceiling(m_thresh, m_bg_thresh))) {
			// todo: ?
			unsigned long intv;
			unsigned long m_intv;

free_running:
			intv = dirty_poll_interval(dirty, thresh);
			m_intv = ULONG_MAX;

			current->dirty_paused_when = now;
			current->nr_dirtied = 0;
			if (mdtc)
				m_intv = dirty_poll_interval(m_dirty, m_thresh);
			current->nr_dirtied_pause = min(intv, m_intv);
			break;
		}

		// wb没有工作，则开始回写。todo: 这里为什么是unlikely?
		if (unlikely(!writeback_in_progress(wb)))
			wb_start_background_writeback(wb);

		// 这里面也会发起回写
		mem_cgroup_flush_foreign(wb);


		if (!strictlimit) {
			// 计算wb的限制
			wb_dirty_limits(gdtc);

			// 小于后台刷新的条件
			if ((current->flags & PF_LOCAL_THROTTLE) &&
			    gdtc->wb_dirty <
			    dirty_freerun_ceiling(gdtc->wb_thresh,
						  gdtc->wb_bg_thresh))
				/*
				 * LOCAL_THROTTLE tasks must not be throttled
				 * when below the per-wb freerun ceiling.
				 */
				goto free_running;
		}

		// 有太多脏页
		dirty_exceeded = (gdtc->wb_dirty > gdtc->wb_thresh) &&
			((gdtc->dirty > gdtc->thresh) || strictlimit);

		// todo: 太复杂了，没看
		wb_position_ratio(gdtc);
		sdtc = gdtc;

		if (mdtc) {
			/*
			 * If memcg domain is in effect, calculate its
			 * pos_ratio.  @wb should satisfy constraints from
			 * both global and memcg domains.  Choose the one
			 * w/ lower pos_ratio.
			 */
			if (!strictlimit) {
				wb_dirty_limits(mdtc);

				if ((current->flags & PF_LOCAL_THROTTLE) &&
				    mdtc->wb_dirty <
				    dirty_freerun_ceiling(mdtc->wb_thresh,
							  mdtc->wb_bg_thresh))
					/*
					 * LOCAL_THROTTLE tasks must not be
					 * throttled when below the per-wb
					 * freerun ceiling.
					 */
					goto free_running;
			}
			dirty_exceeded |= (mdtc->wb_dirty > mdtc->wb_thresh) &&
				((mdtc->dirty > mdtc->thresh) || strictlimit);

			wb_position_ratio(mdtc);
			if (mdtc->pos_ratio < gdtc->pos_ratio)
				sdtc = mdtc;
		}

		// 同步wb的脏状态
		if (dirty_exceeded && !wb->dirty_exceeded)
			wb->dirty_exceeded = 1;

		// 如果过了更新带宽的时间，则更新
		if (time_is_before_jiffies(wb->bw_time_stamp +
					   BANDWIDTH_INTERVAL)) {
			spin_lock(&wb->list_lock);
			__wb_update_bandwidth(gdtc, mdtc, start_time, true);
			spin_unlock(&wb->list_lock);
		}

		// 计算wb的脏状态和进程的脏限制
		dirty_ratelimit = wb->dirty_ratelimit;
		task_ratelimit = ((u64)dirty_ratelimit * sdtc->pos_ratio) >>
							RATELIMIT_CALC_SHIFT;
		// 最大最小暂停限制？
		max_pause = wb_max_pause(wb, sdtc->wb_dirty);
		min_pause = wb_min_pause(wb, max_pause,
					 task_ratelimit, dirty_ratelimit,
					 &nr_dirtied_pause);

		// 限制为0, 直接去做平衡
		if (unlikely(task_ratelimit == 0)) {
			period = max_pause;
			pause = max_pause;
			goto pause;
		}
		period = HZ * pages_dirtied / task_ratelimit;
		pause = period;
		if (current->dirty_paused_when)
			pause -= now - current->dirty_paused_when;
		/*
		 * For less than 1s think time (ext3/4 may block the dirtier
		 * for up to 800ms from time to time on 1-HDD; so does xfs,
		 * however at much less frequency), try to compensate it in
		 * future periods by updating the virtual time; otherwise just
		 * do a reset, as it may be a light dirtier.
		 */
		if (pause < min_pause) {
			trace_balance_dirty_pages(wb,
						  sdtc->thresh,
						  sdtc->bg_thresh,
						  sdtc->dirty,
						  sdtc->wb_thresh,
						  sdtc->wb_dirty,
						  dirty_ratelimit,
						  task_ratelimit,
						  pages_dirtied,
						  period,
						  min(pause, 0L),
						  start_time);
			if (pause < -HZ) {
				current->dirty_paused_when = now;
				current->nr_dirtied = 0;
			} else if (period) {
				current->dirty_paused_when += period;
				current->nr_dirtied = 0;
			} else if (current->nr_dirtied_pause <= pages_dirtied)
				current->nr_dirtied_pause += pages_dirtied;
			break;
		}
		if (unlikely(pause > max_pause)) {
			/* for occasional dropped task_ratelimit */
			now += min(pause - max_pause, max_pause);
			pause = max_pause;
		}

pause:
		trace_balance_dirty_pages(wb,
					  sdtc->thresh,
					  sdtc->bg_thresh,
					  sdtc->dirty,
					  sdtc->wb_thresh,
					  sdtc->wb_dirty,
					  dirty_ratelimit,
					  task_ratelimit,
					  pages_dirtied,
					  period,
					  pause,
					  start_time);
		// 设置进程可杀
		__set_current_state(TASK_KILLABLE);
		// 睡眠pause的时间
		wb->dirty_sleep = now;
		io_schedule_timeout(pause);

		// 统计时间
		current->dirty_paused_when = now + pause;
		current->nr_dirtied = 0;
		current->nr_dirtied_pause = nr_dirtied_pause;

		// 进程有限制则退出？
		if (task_ratelimit)
			break;

		/*
		 * In the case of an unresponding NFS server and the NFS dirty
		 * pages exceeds dirty_thresh, give the other good wb's a pipe
		 * to go through, so that tasks on them still remain responsive.
		 *
		 * In theory 1 page is enough to keep the consumer-producer
		 * pipe going: the flusher cleans 1 page => the task dirties 1
		 * more page. However wb_dirty has accounting errors.  So use
		 * the larger and more IO friendly wb_stat_error.
		 */
		if (sdtc->wb_dirty <= wb_stat_error())
			break;

		// 有信号要处理退出
		if (fatal_signal_pending(current))
			break;
	}

	// 同步脏过度状态
	if (!dirty_exceeded && wb->dirty_exceeded)
		wb->dirty_exceeded = 0;

	// 正在回写，则退出
	if (writeback_in_progress(wb))
		return;

	// 笔记本模式下等到更高的阈值再开始回写，这样能省电
	if (laptop_mode)
		return;
	// 正常情况下，可回收的大于后台域值 ，则开始后台回收
	if (nr_reclaimable > gdtc->bg_thresh)
		wb_start_background_writeback(wb);
}

void wb_start_background_writeback(struct bdi_writeback *wb)
{
	trace_writeback_wake_background(wb);
	// 把wb加入工作队列
	wb_wakeup(wb);
}


static inline unsigned long wb_stat_error(void)
{
#ifdef CONFIG_SMP
	return nr_cpu_ids * WB_STAT_BATCH;
#else
	return 1;
#endif
}

static unsigned long dirty_freerun_ceiling(unsigned long thresh,
					   unsigned long bg_thresh)
{
	return (thresh + bg_thresh) / 2;
}

void mem_cgroup_flush_foreign(struct bdi_writeback *wb)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(wb->memcg_css);
	unsigned long intv = msecs_to_jiffies(dirty_expire_interval * 10);
	u64 now = jiffies_64;
	int i;

	for (i = 0; i < MEMCG_CGWB_FRN_CNT; i++) {
		struct memcg_cgwb_frn *frn = &memcg->cgwb_frn[i];

		/*
		 * If the record is older than dirty_expire_interval,
		 * writeback on it has already started.  No need to kick it
		 * off again.  Also, don't start a new one if there's
		 * already one in flight.
		 */
		if (time_after64(frn->at, now - intv) &&
		    atomic_read(&frn->done.cnt) == 1) {
			frn->at = 0;
			trace_flush_foreign(wb, frn->bdi_id, frn->memcg_id);
			cgroup_writeback_by_id(frn->bdi_id, frn->memcg_id, 0,
					       WB_REASON_FOREIGN_FLUSH,
					       &frn->done);
		}
	}
}

static inline void wb_dirty_limits(struct dirty_throttle_control *dtc)
{
	struct bdi_writeback *wb = dtc->wb;
	unsigned long wb_reclaimable;

	/*
	 * wb_thresh is not treated as some limiting factor as
	 * dirty_thresh, due to reasons
	 * - in JBOD setup, wb_thresh can fluctuate a lot
	 * - in a system with HDD and USB key, the USB key may somehow
	 *   go into state (wb_dirty >> wb_thresh) either because
	 *   wb_dirty starts high, or because wb_thresh drops low.
	 *   In this case we don't want to hard throttle the USB key
	 *   dirtiers for 100 seconds until wb_dirty drops under
	 *   wb_thresh. Instead the auxiliary wb control line in
	 *   wb_position_ratio() will let the dirtier task progress
	 *   at some rate <= (write_bw / 2) for bringing down wb_dirty.
	 */
	dtc->wb_thresh = __wb_calc_thresh(dtc);
	dtc->wb_bg_thresh = dtc->thresh ?
		div_u64((u64)dtc->wb_thresh * dtc->bg_thresh, dtc->thresh) : 0;

	/*
	 * In order to avoid the stacked BDI deadlock we need
	 * to ensure we accurately count the 'dirty' pages when
	 * the threshold is low.
	 *
	 * Otherwise it would be possible to get thresh+n pages
	 * reported dirty, even though there are thresh-m pages
	 * actually dirty; with m+n sitting in the percpu
	 * deltas.
	 */
	if (dtc->wb_thresh < 2 * wb_stat_error()) {
		wb_reclaimable = wb_stat_sum(wb, WB_RECLAIMABLE);
		dtc->wb_dirty = wb_reclaimable + wb_stat_sum(wb, WB_WRITEBACK);
	} else {
		wb_reclaimable = wb_stat(wb, WB_RECLAIMABLE);
		dtc->wb_dirty = wb_reclaimable + wb_stat(wb, WB_WRITEBACK);
	}
}

/*
 * Dirty position control.
 *
 * (o) global/bdi setpoints
 *
 * We want the dirty pages be balanced around the global/wb setpoints.
 * When the number of dirty pages is higher/lower than the setpoint, the
 * dirty position control ratio (and hence task dirty ratelimit) will be
 * decreased/increased to bring the dirty pages back to the setpoint.
 *
 *     pos_ratio = 1 << RATELIMIT_CALC_SHIFT
 *
 *     if (dirty < setpoint) scale up   pos_ratio
 *     if (dirty > setpoint) scale down pos_ratio
 *
 *     if (wb_dirty < wb_setpoint) scale up   pos_ratio
 *     if (wb_dirty > wb_setpoint) scale down pos_ratio
 *
 *     task_ratelimit = dirty_ratelimit * pos_ratio >> RATELIMIT_CALC_SHIFT
 *
 * (o) global control line
 *
 *     ^ pos_ratio
 *     |
 *     |            |<===== global dirty control scope ======>|
 * 2.0 .............*
 *     |            .*
 *     |            . *
 *     |            .   *
 *     |            .     *
 *     |            .        *
 *     |            .            *
 * 1.0 ................................*
 *     |            .                  .     *
 *     |            .                  .          *
 *     |            .                  .              *
 *     |            .                  .                 *
 *     |            .                  .                    *
 *   0 +------------.------------------.----------------------*------------->
 *           freerun^          setpoint^                 limit^   dirty pages
 *
 * (o) wb control line
 *
 *     ^ pos_ratio
 *     |
 *     |            *
 *     |              *
 *     |                *
 *     |                  *
 *     |                    * |<=========== span ============>|
 * 1.0 .......................*
 *     |                      . *
 *     |                      .   *
 *     |                      .     *
 *     |                      .       *
 *     |                      .         *
 *     |                      .           *
 *     |                      .             *
 *     |                      .               *
 *     |                      .                 *
 *     |                      .                   *
 *     |                      .                     *
 * 1/4 ...............................................* * * * * * * * * * * *
 *     |                      .                         .
 *     |                      .                           .
 *     |                      .                             .
 *   0 +----------------------.-------------------------------.------------->
 *                wb_setpoint^                    x_intercept^
 *
 * The wb control line won't drop below pos_ratio=1/4, so that wb_dirty can
 * be smoothly throttled down to normal if it starts high in situations like
 * - start writing to a slow SD card and a fast disk at the same time. The SD
 *   card's wb_dirty may rush to many times higher than wb_setpoint.
 * - the wb dirty thresh drops quickly due to change of JBOD workload
 */
static void wb_position_ratio(struct dirty_throttle_control *dtc)
{
	struct bdi_writeback *wb = dtc->wb;
	unsigned long write_bw = wb->avg_write_bandwidth;
	unsigned long freerun = dirty_freerun_ceiling(dtc->thresh, dtc->bg_thresh);
	unsigned long limit = hard_dirty_limit(dtc_dom(dtc), dtc->thresh);
	unsigned long wb_thresh = dtc->wb_thresh;
	unsigned long x_intercept;
	unsigned long setpoint;		/* dirty pages' target balance point */
	unsigned long wb_setpoint;
	unsigned long span;
	long long pos_ratio;		/* for scaling up/down the rate limit */
	long x;

	dtc->pos_ratio = 0;

	if (unlikely(dtc->dirty >= limit))
		return;

	/*
	 * global setpoint
	 *
	 * See comment for pos_ratio_polynom().
	 */
	setpoint = (freerun + limit) / 2;
	pos_ratio = pos_ratio_polynom(setpoint, dtc->dirty, limit);

	/*
	 * The strictlimit feature is a tool preventing mistrusted filesystems
	 * from growing a large number of dirty pages before throttling. For
	 * such filesystems balance_dirty_pages always checks wb counters
	 * against wb limits. Even if global "nr_dirty" is under "freerun".
	 * This is especially important for fuse which sets bdi->max_ratio to
	 * 1% by default. Without strictlimit feature, fuse writeback may
	 * consume arbitrary amount of RAM because it is accounted in
	 * NR_WRITEBACK_TEMP which is not involved in calculating "nr_dirty".
	 *
	 * Here, in wb_position_ratio(), we calculate pos_ratio based on
	 * two values: wb_dirty and wb_thresh. Let's consider an example:
	 * total amount of RAM is 16GB, bdi->max_ratio is equal to 1%, global
	 * limits are set by default to 10% and 20% (background and throttle).
	 * Then wb_thresh is 1% of 20% of 16GB. This amounts to ~8K pages.
	 * wb_calc_thresh(wb, bg_thresh) is about ~4K pages. wb_setpoint is
	 * about ~6K pages (as the average of background and throttle wb
	 * limits). The 3rd order polynomial will provide positive feedback if
	 * wb_dirty is under wb_setpoint and vice versa.
	 *
	 * Note, that we cannot use global counters in these calculations
	 * because we want to throttle process writing to a strictlimit wb
	 * much earlier than global "freerun" is reached (~23MB vs. ~2.3GB
	 * in the example above).
	 */
	if (unlikely(wb->bdi->capabilities & BDI_CAP_STRICTLIMIT)) {
		long long wb_pos_ratio;

		if (dtc->wb_dirty < 8) {
			dtc->pos_ratio = min_t(long long, pos_ratio * 2,
					   2 << RATELIMIT_CALC_SHIFT);
			return;
		}

		if (dtc->wb_dirty >= wb_thresh)
			return;

		wb_setpoint = dirty_freerun_ceiling(wb_thresh,
						    dtc->wb_bg_thresh);

		if (wb_setpoint == 0 || wb_setpoint == wb_thresh)
			return;

		wb_pos_ratio = pos_ratio_polynom(wb_setpoint, dtc->wb_dirty,
						 wb_thresh);

		/*
		 * Typically, for strictlimit case, wb_setpoint << setpoint
		 * and pos_ratio >> wb_pos_ratio. In the other words global
		 * state ("dirty") is not limiting factor and we have to
		 * make decision based on wb counters. But there is an
		 * important case when global pos_ratio should get precedence:
		 * global limits are exceeded (e.g. due to activities on other
		 * wb's) while given strictlimit wb is below limit.
		 *
		 * "pos_ratio * wb_pos_ratio" would work for the case above,
		 * but it would look too non-natural for the case of all
		 * activity in the system coming from a single strictlimit wb
		 * with bdi->max_ratio == 100%.
		 *
		 * Note that min() below somewhat changes the dynamics of the
		 * control system. Normally, pos_ratio value can be well over 3
		 * (when globally we are at freerun and wb is well below wb
		 * setpoint). Now the maximum pos_ratio in the same situation
		 * is 2. We might want to tweak this if we observe the control
		 * system is too slow to adapt.
		 */
		dtc->pos_ratio = min(pos_ratio, wb_pos_ratio);
		return;
	}

	/*
	 * We have computed basic pos_ratio above based on global situation. If
	 * the wb is over/under its share of dirty pages, we want to scale
	 * pos_ratio further down/up. That is done by the following mechanism.
	 */

	/*
	 * wb setpoint
	 *
	 *        f(wb_dirty) := 1.0 + k * (wb_dirty - wb_setpoint)
	 *
	 *                        x_intercept - wb_dirty
	 *                     := --------------------------
	 *                        x_intercept - wb_setpoint
	 *
	 * The main wb control line is a linear function that subjects to
	 *
	 * (1) f(wb_setpoint) = 1.0
	 * (2) k = - 1 / (8 * write_bw)  (in single wb case)
	 *     or equally: x_intercept = wb_setpoint + 8 * write_bw
	 *
	 * For single wb case, the dirty pages are observed to fluctuate
	 * regularly within range
	 *        [wb_setpoint - write_bw/2, wb_setpoint + write_bw/2]
	 * for various filesystems, where (2) can yield in a reasonable 12.5%
	 * fluctuation range for pos_ratio.
	 *
	 * For JBOD case, wb_thresh (not wb_dirty!) could fluctuate up to its
	 * own size, so move the slope over accordingly and choose a slope that
	 * yields 100% pos_ratio fluctuation on suddenly doubled wb_thresh.
	 */
	if (unlikely(wb_thresh > dtc->thresh))
		wb_thresh = dtc->thresh;
	/*
	 * It's very possible that wb_thresh is close to 0 not because the
	 * device is slow, but that it has remained inactive for long time.
	 * Honour such devices a reasonable good (hopefully IO efficient)
	 * threshold, so that the occasional writes won't be blocked and active
	 * writes can rampup the threshold quickly.
	 */
	wb_thresh = max(wb_thresh, (limit - dtc->dirty) / 8);
	/*
	 * scale global setpoint to wb's:
	 *	wb_setpoint = setpoint * wb_thresh / thresh
	 */
	x = div_u64((u64)wb_thresh << 16, dtc->thresh | 1);
	wb_setpoint = setpoint * (u64)x >> 16;
	/*
	 * Use span=(8*write_bw) in single wb case as indicated by
	 * (thresh - wb_thresh ~= 0) and transit to wb_thresh in JBOD case.
	 *
	 *        wb_thresh                    thresh - wb_thresh
	 * span = --------- * (8 * write_bw) + ------------------ * wb_thresh
	 *         thresh                           thresh
	 */
	span = (dtc->thresh - wb_thresh + 8 * write_bw) * (u64)x >> 16;
	x_intercept = wb_setpoint + span;

	if (dtc->wb_dirty < x_intercept - span / 4) {
		pos_ratio = div64_u64(pos_ratio * (x_intercept - dtc->wb_dirty),
				      (x_intercept - wb_setpoint) | 1);
	} else
		pos_ratio /= 4;

	/*
	 * wb reserve area, safeguard against dirty pool underrun and disk idle
	 * It may push the desired control point of global dirty pages higher
	 * than setpoint.
	 */
	x_intercept = wb_thresh / 2;
	if (dtc->wb_dirty < x_intercept) {
		if (dtc->wb_dirty > x_intercept / 8)
			pos_ratio = div_u64(pos_ratio * x_intercept,
					    dtc->wb_dirty);
		else
			pos_ratio *= 8;
	}

	dtc->pos_ratio = pos_ratio;
}
```