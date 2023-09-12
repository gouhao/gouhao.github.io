# 数据结构
源码基于5.10


```c
struct bdi_writeback {
	struct backing_dev_info *bdi;	/* 设备信息 */

	unsigned long state;		/* Always use atomic bitops on this */
	unsigned long last_old_flush;	/* last old data flush */

	struct list_head b_dirty;	// 脏inode列表
	struct list_head b_io;		// 等待回写列表
	/*
	另一个存放等待被 writeback 的 inode 的链表，该链表上的 inode 对象来自 b_io，
	由于某种原因在上一轮处理中未能被及时 wrieback，所以从 b_io 
	中被移出来缓存在这里等待下一次被移回 b_io 继续处理
	*/
	struct list_head b_more_io;	
	struct list_head b_dirty_time;	/* time stamps are dirty */
	spinlock_t list_lock;		/* protects the b_* lists */

	struct percpu_counter stat[NR_WB_STAT_ITEMS];

	unsigned long congested;	/* WB_[a]sync_congested flags */

	unsigned long bw_time_stamp;	/* last time write bw is updated */
	unsigned long dirtied_stamp;
	unsigned long written_stamp;	/* pages written at bw_time_stamp */
	unsigned long write_bandwidth;	/* the estimated write bandwidth */
	unsigned long avg_write_bandwidth; /* further smoothed write bw, > 0 */

	/*
	 * The base dirty throttle rate, re-calculated on every 200ms.
	 * All the bdi tasks' dirty rate will be curbed under it.
	 * @dirty_ratelimit tracks the estimated @balanced_dirty_ratelimit
	 * in small steps and is much more smooth/stable than the latter.
	 */
	unsigned long dirty_ratelimit;
	unsigned long balanced_dirty_ratelimit;

	struct fprop_local_percpu completions;
	int dirty_exceeded;
	enum wb_reason start_all_reason;

	spinlock_t work_lock;		/* protects work_list & dwork scheduling */
	struct list_head work_list;
	struct delayed_work dwork;	/* work item used for writeback */

	unsigned long dirty_sleep;	/* last wait */

	struct list_head bdi_node;	/* anchored at bdi->wb_list */

#ifdef CONFIG_CGROUP_WRITEBACK
	struct percpu_ref refcnt;	/* used only for !root wb's */
	struct fprop_local_percpu memcg_completions;
	struct cgroup_subsys_state *memcg_css; /* the associated memcg */
	struct cgroup_subsys_state *blkcg_css; /* and blkcg */
	struct list_head memcg_node;	/* anchored at memcg->cgwb_list */
	struct list_head blkcg_node;	/* anchored at blkcg->cgwb_list */

	union {
		struct work_struct release_work;
		struct rcu_head rcu;
	};
#endif
};

struct writeback_control {
	long nr_to_write;		// 要写的页数，每写一个页，这个值减1
	long pages_skipped;		// 没有写的页的数目

	/*
	 * For a_ops->writepages(): if start or end are non-zero then this is
	 * a hint that the filesystem need only write out the pages inside that
	 * byterange.  The byte at `end' is included in the writeout request.
	 */
	loff_t range_start;
	loff_t range_end;

	enum writeback_sync_modes sync_mode; // 同步方式

	// 表示回写是由谁调用的
	unsigned for_kupdate:1;		// kupdate回写
	unsigned for_background:1;	// 后台回写
	unsigned tagged_writepages:1;	/* tag-and-write to avoid livelock */
	unsigned for_reclaim:1;		// 页分配器调用 
	unsigned range_cyclic:1;	/* range_start is cyclic */
	unsigned for_sync:1;		// sync调用

	/*
	 * When writeback IOs are bounced through async layers, only the
	 * initial synchronous phase should be accounted towards inode
	 * cgroup ownership arbitration to avoid confusion.  Later stages
	 * can set the following flag to disable the accounting.
	 */
	unsigned no_cgroup_owner:1;

	unsigned punt_to_cgroup:1;	/* cgrp punting, see __REQ_CGROUP_PUNT */

#ifdef CONFIG_CGROUP_WRITEBACK
	struct bdi_writeback *wb;	/* wb this writeback is issued under */
	struct inode *inode;		/* inode being written out */

	/* foreign inode detection, see wbc_detach_inode() */
	int wb_id;			/* current wb id */
	int wb_lcand_id;		/* last foreign candidate wb id */
	int wb_tcand_id;		/* this foreign candidate wb id */
	size_t wb_bytes;		/* bytes written by current wb */
	size_t wb_lcand_bytes;		/* bytes written by last candidate */
	size_t wb_tcand_bytes;		/* bytes written by this candidate */
#endif
};

struct wb_domain {
	spinlock_t lock;

	/*
	 * Scale the writeback cache size proportional to the relative
	 * writeout speed.
	 *
	 * We do this by keeping a floating proportion between BDIs, based
	 * on page writeback completions [end_page_writeback()]. Those
	 * devices that write out pages fastest will get the larger share,
	 * while the slower will get a smaller share.
	 *
	 * We use page writeout completions because we are interested in
	 * getting rid of dirty pages. Having them written out is the
	 * primary goal.
	 *
	 * We introduce a concept of time, a period over which we measure
	 * these events, because demand can/will vary over time. The length
	 * of this period itself is measured in page writeback completions.
	 */
	struct fprop_global completions;
	struct timer_list period_timer;	// 完成的老化计时器？
	unsigned long period_time;	// 周期

	/*
	 * The dirtyable memory and dirty threshold could be suddenly
	 * knocked down by a large amount (eg. on the startup of KVM in a
	 * swapless system). This may throw the system into deep dirty
	 * exceeded state and throttle heavy/light dirtiers alike. To
	 * retain good responsiveness, maintain global_dirty_limit for
	 * tracking slowly down to the knocked down dirty threshold.
	 *
	 * Both fields are protected by ->lock.
	 */
	unsigned long dirty_limit_tstamp;
	unsigned long dirty_limit;
};

// 与wb_control类似
struct wb_writeback_work {
	long nr_pages;
	struct super_block *sb;
	enum writeback_sync_modes sync_mode;
	unsigned int tagged_writepages:1;
	unsigned int for_kupdate:1;
	unsigned int range_cyclic:1;
	unsigned int for_background:1;
	unsigned int for_sync:1;	/* sync(2) WB_SYNC_ALL writeback */
	unsigned int auto_free:1;	/* free on completion */
	enum wb_reason reason;		/* why was writeback initiated? */

	struct list_head list;		/* pending work list */
	struct wb_completion *done;	/* set if the caller waits */
};
```