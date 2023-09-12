# bfq调度器
源码基于5.10

## 0. 数据结构
```c
struct bfq_data {
	struct request_queue *queue; // 设备请求队列
	struct list_head dispatch; // 派发队列

	/* root bfq_group for the device */
	struct bfq_group *root_group;

	struct rb_root_cached queue_weights_tree; // 权重树

	/*
	 * Number of groups with at least one descendant process that
	 * has at least one request waiting for completion. Note that
	 * this accounts for also requests already dispatched, but not
	 * yet completed. Therefore this number of groups may differ
	 * (be larger) than the number of active groups, as a group is
	 * considered active only if its corresponding entity has
	 * descendant queues with at least one request queued. This
	 * number is used to decide whether a scenario is symmetric.
	 * For a detailed explanation see comments on the computation
	 * of the variable asymmetric_scenario in the function
	 * bfq_better_to_idle().
	 *
	 * However, it is hard to compute this number exactly, for
	 * groups with multiple descendant processes. Consider a group
	 * that is inactive, i.e., that has no descendant process with
	 * pending I/O inside BFQ queues. Then suppose that
	 * num_groups_with_pending_reqs is still accounting for this
	 * group, because the group has descendant processes with some
	 * I/O request still in flight. num_groups_with_pending_reqs
	 * should be decremented when the in-flight request of the
	 * last descendant process is finally completed (assuming that
	 * nothing else has changed for the group in the meantime, in
	 * terms of composition of the group and active/inactive state of child
	 * groups and processes). To accomplish this, an additional
	 * pending-request counter must be added to entities, and must
	 * be updated correctly. To avoid this additional field and operations,
	 * we resort to the following tradeoff between simplicity and
	 * accuracy: for an inactive group that is still counted in
	 * num_groups_with_pending_reqs, we decrement
	 * num_groups_with_pending_reqs when the first descendant
	 * process of the group remains with no request waiting for
	 * completion.
	 *
	 * Even this simpler decrement strategy requires a little
	 * carefulness: to avoid multiple decrements, we flag a group,
	 * more precisely an entity representing a group, as still
	 * counted in num_groups_with_pending_reqs when it becomes
	 * inactive. Then, when the first descendant queue of the
	 * entity remains with no request waiting for completion,
	 * num_groups_with_pending_reqs is decremented, and this flag
	 * is reset. After this flag is reset for the entity,
	 * num_groups_with_pending_reqs won't be decremented any
	 * longer in case a new descendant queue of the entity remains
	 * with no request waiting for completion.
	 */
	unsigned int num_groups_with_pending_reqs;

	/*
	 * Per-class (RT, BE, IDLE) number of bfq_queues containing
	 * requests (including the queue in service, even if it is
	 * idling).
	 */
	unsigned int busy_queues[3]; // 3种队列(RT, BE, IDLE)里请求的数量
	/* number of weight-raised busy @bfq_queues */
	int wr_busy_queues;
	int queued; // 已入队的请求数量
	int rq_in_driver; // 已经派发的请求数量,等待完成

	/* true if the device is non rotational and performs queueing */
	bool nonrot_with_queueing; // 不转动的磁盘时为true

	int max_rq_in_driver; // 驱动请求的最大数量
	int hw_tag_samples; // hw_tag的采样数
	/* flag set to one if the driver is showing a queueing behavior */
	int hw_tag;

	int budgets_assigned; // 已分配的budget数量

	// 从正在服务的队列等下一个请求的timer
	struct hrtimer idle_slice_timer;

	// 正在服务的队列
	struct bfq_queue *in_service_queue;

	// 最后一个请求的盘上扇区
	sector_t last_position;

	// 服务队列里上次服务的位置
	sector_t in_serv_last_pos;

	// 上一次请求完成的时间(纳秒)
	u64 last_completion;

	// 上次完成请求的bfqq
	struct bfq_queue *last_completed_rq_bfqq;

	/* time of last transition from empty to non-empty (ns) */
	// 最近一次从空到不空传输的时间
	u64 last_empty_occupied_ns;

	/*
	 * Flag set to activate the sampling of the total service time
	 * of a just-arrived first I/O request (see
	 * bfq_update_inject_limit()). This will cause the setting of
	 * waited_rq when the request is finally dispatched.
	 */
	bool wait_dispatch;

	// 如果设置了,当waited_rq完成时会调用bfq_update_inject_limit
	struct request *waited_rq;
	/*
	 * True if some request has been injected during the last service hole.
	 */
	// 在last_service打洞时有请求被注入
	bool rqs_injected;

	// 第一个派发时间在当前观察间隔(纳秒)
	u64 first_dispatch;
	// 最后派发时间在当前观察间隔
	u64 last_dispatch;

	// 上次budget启动时间
	ktime_t last_budget_start;
	// 上一次idle启动时间
	ktime_t last_idling_start;
	// 上一次idle启动时的jiffies
	unsigned long last_idling_start_jiffies;


	// 采样数量在当前观察间隔
	int peak_rate_samples;
	// 顺序派发的采样数量在当前观察间隔
	u32 sequential_samples;
	// 传输的总扇区数,在当前间隔内
	u64 tot_sectors_dispatched;
	// 最大的rq_size在当前间隔之间
	u32 last_rq_max_size;
	
	// 第1个派发的到当前的时间间隔(微秒)
	u64 delta_from_first;
	// 磁盘比率的预测
	u32 peak_rate;

	// 在重调度前,给一个bfqq分配的最大数量的budget
	int bfq_max_budget;

	// 设备上活跃的bfqq列表
	struct list_head active_list;
	// 设备上空闲的bfqq列表
	struct list_head idle_list;

	// 异步/同步的超时,如果使用它,会按fifo的顺序来处理请求
	u64 bfq_fifo_expire[2];
	// 往后seek时的处罚
	unsigned int bfq_back_penalty;
	// 最大允许的回退seek
	unsigned int bfq_back_max;
	// 最大空闲时间
	u32 bfq_slice_idle;

	// 用户可配置的最大budget数量(0是自动调节)
	int bfq_user_max_budget;

	// bfqq消费budget的超时时间
	unsigned int bfq_timeout;

	// 一个时间片内连续请求的数量
	unsigned int bfq_requests_within_timer;

	// 提供精确的服务,宁愿设备空转?
	bool strict_guarantees;

	/*
	 * Last time at which a queue entered the current burst of
	 * queues being activated shortly after each other; for more
	 * details about this and the following parameters related to
	 * a burst of activations, see the comments on the function
	 * bfq_handle_burst.
	 */
	unsigned long last_ins_in_burst;
	
	// 很短活跃间隔?
	unsigned long bfq_burst_interval;

	// burst队列里最大队列的数量
	int burst_size;

	// burst的父结点
	struct bfq_entity *burst_parent_entity;
	
	// burst最大的限制值
	unsigned long bfq_large_burst_thresh;
	// 标志是否有large_burst
	bool large_burst;
	// burst头指针
	struct hlist_head burst_list;

	// 打开后,会开启低延迟启发式
	bool low_latency;
	
	// 最大权重因子
	unsigned int bfq_wr_coeff;

	// 权重开启期间最大的间隔
	unsigned int bfq_wr_max_time;

	// 最大的权重间隔对于软实时进程
	unsigned int bfq_wr_rt_max_time;
	/*
	 * Minimum idle period after which weight-raising may be
	 * reactivated for a queue (in jiffies).
	 */
	unsigned int bfq_wr_min_idle_time;
	/*
	 * Minimum period between request arrivals after which
	 * weight-raising may be reactivated for an already busy async
	 * queue (in jiffies).
	 */
	unsigned long bfq_wr_min_inter_arr_async;

	/* Max service-rate for a soft real-time queue, in sectors/sec */
	unsigned int bfq_wr_max_softrt_rate;
	/*
	 * Cached value of the product ref_rate*ref_wr_duration, used
	 * for computing the maximum duration of weight raising
	 * automatically.
	 */
	u64 rate_dur_prod;

	/* fallback dummy bfqq for extreme OOM conditions */
	struct bfq_queue oom_bfqq;

	spinlock_t lock;

	/*
	 * bic associated with the task issuing current bio for
	 * merging. This and the next field are used as a support to
	 * be able to perform the bic lookup, needed by bio-merge
	 * functions, before the scheduler lock is taken, and thus
	 * avoid taking the request-queue lock while the scheduler
	 * lock is being held.
	 */
	struct bfq_io_cq *bio_bic;
	/* bfqq associated with the task issuing current bio for merging */
	struct bfq_queue *bio_bfqq;

	/*
	 * Depth limits used in bfq_limit_depth (see comments on the
	 * function)
	 */
	unsigned int word_depths[2][2];
};

struct bfq_queue {
	/* reference counter */
	int ref;
	/* parent bfq_data */
	struct bfq_data *bfqd;

	/* current ioprio and ioprio class */
	unsigned short ioprio, ioprio_class;
	/* next ioprio and ioprio class if a change is in progress */
	unsigned short new_ioprio, new_ioprio_class;

	/* last total-service-time sample, see bfq_update_inject_limit() */
	u64 last_serv_time_ns;
	/* limit for request injection */
	unsigned int inject_limit;
	/* last time the inject limit has been decreased, in jiffies */
	unsigned long decrease_time_jif;

	/*
	 * Shared bfq_queue if queue is cooperating with one or more
	 * other queues.
	 */
	struct bfq_queue *new_bfqq;
	/* request-position tree member (see bfq_group's @rq_pos_tree) */
	struct rb_node pos_node;
	/* request-position tree root (see bfq_group's @rq_pos_tree) */
	struct rb_root *pos_root;

	/* sorted list of pending requests */
	struct rb_root sort_list;
	/* if fifo isn't expired, next request to serve */
	struct request *next_rq;
	/* number of sync and async requests queued */
	int queued[2];
	/* number of requests currently allocated */
	int allocated;
	/* number of pending metadata requests */
	int meta_pending;
	/* fifo list of requests in sort_list */
	struct list_head fifo;

	/* entity representing this queue in the scheduler */
	struct bfq_entity entity;

	/* pointer to the weight counter associated with this entity */
	struct bfq_weight_counter *weight_counter;

	/* maximum budget allowed from the feedback mechanism */
	int max_budget;
	/* budget expiration (in jiffies) */
	unsigned long budget_timeout;

	/* number of requests on the dispatch list or inside driver */
	int dispatched;

	/* status flags */
	unsigned long flags;

	/* node for active/idle bfqq list inside parent bfqd */
	struct list_head bfqq_list;

	/* associated @bfq_ttime struct */
	struct bfq_ttime ttime;

	/* bit vector: a 1 for each seeky requests in history */
	u32 seek_history;

	/* node for the device's burst list */
	struct hlist_node burst_list_node;

	/* position of the last request enqueued */
	sector_t last_request_pos;

	/* Number of consecutive pairs of request completion and
	 * arrival, such that the queue becomes idle after the
	 * completion, but the next request arrives within an idle
	 * time slice; used only if the queue's IO_bound flag has been
	 * cleared.
	 */
	unsigned int requests_within_timer;

	/* pid of the process owning the queue, used for logging purposes */
	pid_t pid;

	/*
	 * Pointer to the bfq_io_cq owning the bfq_queue, set to %NULL
	 * if the queue is shared.
	 */
	struct bfq_io_cq *bic;

	/* current maximum weight-raising time for this queue */
	unsigned long wr_cur_max_time;
	/*
	 * Minimum time instant such that, only if a new request is
	 * enqueued after this time instant in an idle @bfq_queue with
	 * no outstanding requests, then the task associated with the
	 * queue it is deemed as soft real-time (see the comments on
	 * the function bfq_bfqq_softrt_next_start())
	 */
	unsigned long soft_rt_next_start;
	/*
	 * Start time of the current weight-raising period if
	 * the @bfq-queue is being weight-raised, otherwise
	 * finish time of the last weight-raising period.
	 */
	unsigned long last_wr_start_finish;
	/* factor by which the weight of this queue is multiplied */
	unsigned int wr_coeff;
	/*
	 * Time of the last transition of the @bfq_queue from idle to
	 * backlogged.
	 */
	unsigned long last_idle_bklogged;
	/*
	 * Cumulative service received from the @bfq_queue since the
	 * last transition from idle to backlogged.
	 */
	unsigned long service_from_backlogged;
	/*
	 * Cumulative service received from the @bfq_queue since its
	 * last transition to weight-raised state.
	 */
	unsigned long service_from_wr;

	/*
	 * Value of wr start time when switching to soft rt
	 */
	unsigned long wr_start_at_switch_to_srt;

	unsigned long split_time; /* time of last split */

	unsigned long first_IO_time; /* time of first I/O for this queue */

	/* max service rate measured so far */
	u32 max_service_rate;

	/*
	 * Pointer to the waker queue for this queue, i.e., to the
	 * queue Q such that this queue happens to get new I/O right
	 * after some I/O request of Q is completed. For details, see
	 * the comments on the choice of the queue for injection in
	 * bfq_select_queue().
	 */
	struct bfq_queue *waker_bfqq;
	/* node for woken_list, see below */
	struct hlist_node woken_list_node;
	/*
	 * Head of the list of the woken queues for this queue, i.e.,
	 * of the list of the queues for which this queue is a waker
	 * queue. This list is used to reset the waker_bfqq pointer in
	 * the woken queues when this queue exits.
	 */
	struct hlist_head woken_list;
};
```

## 1. 函数表
```c
static struct elevator_type iosched_bfq_mq = {
	.ops = {
		.limit_depth		= bfq_limit_depth,
		.prepare_request	= bfq_prepare_request,
		.requeue_request        = bfq_finish_requeue_request,
		.finish_request		= bfq_finish_requeue_request,
		.exit_icq		= bfq_exit_icq,
		.insert_requests	= bfq_insert_requests,
		.dispatch_request	= bfq_dispatch_request,
		.next_request		= elv_rb_latter_request,
		.former_request		= elv_rb_former_request,
		.allow_merge		= bfq_allow_bio_merge,
		.bio_merge		= bfq_bio_merge,
		.request_merge		= bfq_request_merge,
		.requests_merged	= bfq_requests_merged,
		.request_merged		= bfq_request_merged,
		.has_work		= bfq_has_work,
		.depth_updated		= bfq_depth_updated,
		.init_hctx		= bfq_init_hctx,
		.init_sched		= bfq_init_queue,
		.exit_sched		= bfq_exit_queue,
	},

	.icq_size =		sizeof(struct bfq_io_cq),
	.icq_align =		__alignof__(struct bfq_io_cq),
	.elevator_attrs =	bfq_attrs,
	.elevator_name =	"bfq",
	.elevator_owner =	THIS_MODULE,
};
```
### 1.1. 属性
```c
static struct elv_fs_entry bfq_attrs[] = {
	BFQ_ATTR(fifo_expire_sync),
	BFQ_ATTR(fifo_expire_async),
	BFQ_ATTR(back_seek_max),
	BFQ_ATTR(back_seek_penalty),
	BFQ_ATTR(slice_idle),
	BFQ_ATTR(slice_idle_us),
	BFQ_ATTR(max_budget),
	BFQ_ATTR(timeout_sync),
	BFQ_ATTR(strict_guarantees),
	BFQ_ATTR(low_latency),
	__ATTR_NULL
};

```

## 2. 调度器初始化及退出
### 2.1. 初始化
```c
static int bfq_init_queue(struct request_queue *q, struct elevator_type *e)
{
	struct bfq_data *bfqd;
	struct elevator_queue *eq;

	// 分配eq数据
	eq = elevator_alloc(q, e);
	if (!eq)
		return -ENOMEM;

	// 分配私有数据
	bfqd = kzalloc_node(sizeof(*bfqd), GFP_KERNEL, q->node);
	if (!bfqd) {
		kobject_put(&eq->kobj);
		return -ENOMEM;
	}
	// 设置私有数据
	eq->elevator_data = bfqd;

	// 给队列设置调度器.todo: 这里为什么要加锁
	spin_lock_irq(&q->queue_lock);
	q->elevator = eq;
	spin_unlock_irq(&q->queue_lock);

	// oom_bfqq是在oom时保证正常流程。 todo: bfq_init_bfqq后面看
	bfq_init_bfqq(bfqd, &bfqd->oom_bfqq, NULL, 1, 0);
	// 设置oom_bfqq的一些值
	bfqd->oom_bfqq.ref++;
	bfqd->oom_bfqq.new_ioprio = BFQ_DEFAULT_QUEUE_IOPRIO;
	bfqd->oom_bfqq.new_ioprio_class = IOPRIO_CLASS_BE;
	bfqd->oom_bfqq.entity.new_weight =
		bfq_ioprio_to_weight(bfqd->oom_bfqq.new_ioprio);

	// 清除just_created标志
	bfq_clear_bfqq_just_created(&bfqd->oom_bfqq);

	// ?
	bfqd->oom_bfqq.entity.prio_changed = 1;

	// 队列引用
	bfqd->queue = q;

	// 派发队列
	INIT_LIST_HEAD(&bfqd->dispatch);

	// 时间片timer
	hrtimer_init(&bfqd->idle_slice_timer, CLOCK_MONOTONIC,
		     HRTIMER_MODE_REL);
	// timer的函数
	bfqd->idle_slice_timer.function = bfq_idle_slice_timer;

	bfqd->queue_weights_tree = RB_ROOT_CACHED;
	bfqd->num_groups_with_pending_reqs = 0;

	// 活路,空闲,列表
	INIT_LIST_HEAD(&bfqd->active_list);
	INIT_LIST_HEAD(&bfqd->idle_list);
	INIT_HLIST_HEAD(&bfqd->burst_list);

	bfqd->hw_tag = -1;
	bfqd->nonrot_with_queueing = blk_queue_nonrot(bfqd->queue);

	// bfq_default_max_budget=16*1024
	bfqd->bfq_max_budget = bfq_default_max_budget;

	// 第0个是同步,默认1/4秒
	bfqd->bfq_fifo_expire[0] = bfq_fifo_expire[0];
	// 第1个是异步,默认1/8秒
	bfqd->bfq_fifo_expire[1] = bfq_fifo_expire[1];
	// 默认16 * 1024
	bfqd->bfq_back_max = bfq_back_max;
	// 默认2
	bfqd->bfq_back_penalty = bfq_back_penalty;

	// 默认1/125秒
	bfqd->bfq_slice_idle = bfq_slice_idle;
	// 默认HZ/8
	bfqd->bfq_timeout = bfq_timeout;

	bfqd->bfq_requests_within_timer = 120;

	bfqd->bfq_large_burst_thresh = 8;
	bfqd->bfq_burst_interval = msecs_to_jiffies(180);

	bfqd->low_latency = true;

	// 响应和公平之间的平衡
	bfqd->bfq_wr_coeff = 30;
	bfqd->bfq_wr_rt_max_time = msecs_to_jiffies(300);
	bfqd->bfq_wr_max_time = 0;
	bfqd->bfq_wr_min_idle_time = msecs_to_jiffies(2000);
	bfqd->bfq_wr_min_inter_arr_async = msecs_to_jiffies(500);
	bfqd->bfq_wr_max_softrt_rate = 7000; /*
					      * Approximate rate required
					      * to playback or record a
					      * high-definition compressed
					      * video.
					      */
	bfqd->wr_busy_queues = 0;

	/*
	 * Begin by assuming, optimistically, that the device peak
	 * rate is equal to 2/3 of the highest reference rate.
	 */
	bfqd->rate_dur_prod = ref_rate[blk_queue_nonrot(bfqd->queue)] *
		ref_wr_duration[blk_queue_nonrot(bfqd->queue)];
	bfqd->peak_rate = ref_rate[blk_queue_nonrot(bfqd->queue)] * 2 / 3;

	spin_lock_init(&bfqd->lock);

	/*
	 * The invocation of the next bfq_create_group_hierarchy
	 * function is the head of a chain of function calls
	 * (bfq_create_group_hierarchy->blkcg_activate_policy->
	 * blk_mq_freeze_queue) that may lead to the invocation of the
	 * has_work hook function. For this reason,
	 * bfq_create_group_hierarchy is invoked only after all
	 * scheduler data has been initialized, apart from the fields
	 * that can be initialized only after invoking
	 * bfq_create_group_hierarchy. This, in particular, enables
	 * has_work to correctly return false. Of course, to avoid
	 * other inconsistencies, the blk-mq stack must then refrain
	 * from invoking further scheduler hooks before this init
	 * function is finished.
	 */
	bfqd->root_group = bfq_create_group_hierarchy(bfqd, q->node);
	if (!bfqd->root_group)
		goto out_free;
	bfq_init_root_group(bfqd->root_group, bfqd);
	bfq_init_entity(&bfqd->oom_bfqq.entity, bfqd->root_group);

	wbt_disable_default(q);
	return 0;

out_free:
	kfree(bfqd);
	kobject_put(&eq->kobj);
	return -ENOMEM;
}

static void bfq_init_bfqq(struct bfq_data *bfqd, struct bfq_queue *bfqq,
			  struct bfq_io_cq *bic, pid_t pid, int is_sync)
{
	// 初始化各种表
	RB_CLEAR_NODE(&bfqq->entity.rb_node);
	INIT_LIST_HEAD(&bfqq->fifo);
	INIT_HLIST_NODE(&bfqq->burst_list_node);
	INIT_HLIST_NODE(&bfqq->woken_list_node);
	INIT_HLIST_HEAD(&bfqq->woken_list);

	bfqq->ref = 0;
	// 设置bfqd的引用
	bfqq->bfqd = bfqd;

	// 更新优先级数据？
	if (bic)
		bfq_set_next_ioprio_data(bfqq, bic);

	// 同步？
	if (is_sync) {
		/*
		 * No need to mark as has_short_ttime if in
		 * idle_class, because no device idling is performed
		 * for queues in idle class
		 */
		if (!bfq_class_idle(bfqq))
			/* tentatively mark as has_short_ttime */
			bfq_mark_bfqq_has_short_ttime(bfqq);
		bfq_mark_bfqq_sync(bfqq);
		bfq_mark_bfqq_just_created(bfqq);
	} else
		bfq_clear_bfqq_sync(bfqq);

	/* set end request to minus infinity from now */
	bfqq->ttime.last_end_request = ktime_get_ns() + 1;

	bfq_mark_bfqq_IO_bound(bfqq);

	// 设置pid
	bfqq->pid = pid;

	/* Tentative initial value to trade off between thr and lat */
	bfqq->max_budget = (2 * bfq_max_budget(bfqd)) / 3;
	bfqq->budget_timeout = bfq_smallest_from_now();

	bfqq->wr_coeff = 1;
	bfqq->last_wr_start_finish = jiffies;
	bfqq->wr_start_at_switch_to_srt = bfq_smallest_from_now();
	bfqq->split_time = bfq_smallest_from_now();

	/*
	 * To not forget the possibly high bandwidth consumed by a
	 * process/queue in the recent past,
	 * bfq_bfqq_softrt_next_start() returns a value at least equal
	 * to the current value of bfqq->soft_rt_next_start (see
	 * comments on bfq_bfqq_softrt_next_start).  Set
	 * soft_rt_next_start to now, to mean that bfqq has consumed
	 * no bandwidth so far.
	 */
	bfqq->soft_rt_next_start = jiffies;

	/* first request is almost certainly seeky */
	bfqq->seek_history = 1;
}

static void
bfq_set_next_ioprio_data(struct bfq_queue *bfqq, struct bfq_io_cq *bic)
{
	struct task_struct *tsk = current;
	int ioprio_class;
	struct bfq_data *bfqd = bfqq->bfqd;

	if (!bfqd)
		return;

	ioprio_class = IOPRIO_PRIO_CLASS(bic->ioprio);
	switch (ioprio_class) {
	default:
		pr_err("bdi %s: bfq: bad prio class %d\n",
				bdi_dev_name(bfqq->bfqd->queue->backing_dev_info),
				ioprio_class);
		fallthrough;
	case IOPRIO_CLASS_NONE:
		/*
		 * No prio set, inherit CPU scheduling settings.
		 */
		bfqq->new_ioprio = task_nice_ioprio(tsk);
		bfqq->new_ioprio_class = task_nice_ioclass(tsk);
		break;
	case IOPRIO_CLASS_RT:
		bfqq->new_ioprio = IOPRIO_PRIO_DATA(bic->ioprio);
		bfqq->new_ioprio_class = IOPRIO_CLASS_RT;
		break;
	case IOPRIO_CLASS_BE:
		bfqq->new_ioprio = IOPRIO_PRIO_DATA(bic->ioprio);
		bfqq->new_ioprio_class = IOPRIO_CLASS_BE;
		break;
	case IOPRIO_CLASS_IDLE:
		bfqq->new_ioprio_class = IOPRIO_CLASS_IDLE;
		bfqq->new_ioprio = 7;
		break;
	}

	if (bfqq->new_ioprio >= IOPRIO_BE_NR) {
		pr_crit("bfq_set_next_ioprio_data: new_ioprio %d\n",
			bfqq->new_ioprio);
		bfqq->new_ioprio = IOPRIO_BE_NR - 1;
	}

	bfqq->entity.new_weight = bfq_ioprio_to_weight(bfqq->new_ioprio);
	bfqq->entity.prio_changed = 1;
}
```

### 2.2. 退出
```c
static void bfq_exit_queue(struct elevator_queue *e)
{
	struct bfq_data *bfqd = e->elevator_data;
	struct bfq_queue *bfqq, *n;

	// 取消分片计时
	hrtimer_cancel(&bfqd->idle_slice_timer);

	spin_lock_irq(&bfqd->lock);
	// what?
	list_for_each_entry_safe(bfqq, n, &bfqd->idle_list, bfqq_list)
		bfq_deactivate_bfqq(bfqd, bfqq, false, false);
	spin_unlock_irq(&bfqd->lock);

	// 上面不是已经取消了吗?
	hrtimer_cancel(&bfqd->idle_slice_timer);

	/* release oom-queue reference to root group */
	bfqg_and_blkg_put(bfqd->root_group);

#ifdef CONFIG_BFQ_GROUP_IOSCHED
	blkcg_deactivate_policy(bfqd->queue, &blkcg_policy_bfq);
#else
	spin_lock_irq(&bfqd->lock);
	bfq_put_async_queues(bfqd, bfqd->root_group);
	kfree(bfqd->root_group);
	spin_unlock_irq(&bfqd->lock);
#endif

	wbt_enable_default(bfqd->queue);

	kfree(bfqd);
}

void bfq_deactivate_bfqq(struct bfq_data *bfqd, struct bfq_queue *bfqq,
			 bool ins_into_idle_tree, bool expiration)
{
	struct bfq_entity *entity = &bfqq->entity;

	bfq_deactivate_entity(entity, ins_into_idle_tree, expiration);
}

static void bfq_deactivate_entity(struct bfq_entity *entity,
				  bool ins_into_idle_tree,
				  bool expiration)
{
	struct bfq_sched_data *sd;
	struct bfq_entity *parent = NULL;

	for_each_entity_safe(entity, parent) {
		sd = entity->sched_data;

		if (!__bfq_deactivate_entity(entity, ins_into_idle_tree)) {
			/*
			 * entity is not in any tree any more, so
			 * this deactivation is a no-op, and there is
			 * nothing to change for upper-level entities
			 * (in case of expiration, this can never
			 * happen).
			 */
			return;
		}

		if (sd->next_in_service == entity)
			/*
			 * entity was the next_in_service entity,
			 * then, since entity has just been
			 * deactivated, a new one must be found.
			 */
			bfq_update_next_in_service(sd, NULL, expiration);

		if (sd->next_in_service || sd->in_service_entity) {
			/*
			 * The parent entity is still active, because
			 * either next_in_service or in_service_entity
			 * is not NULL. So, no further upwards
			 * deactivation must be performed.  Yet,
			 * next_in_service has changed.	Then the
			 * schedule does need to be updated upwards.
			 *
			 * NOTE If in_service_entity is not NULL, then
			 * next_in_service may happen to be NULL,
			 * although the parent entity is evidently
			 * active. This happens if 1) the entity
			 * pointed by in_service_entity is the only
			 * active entity in the parent entity, and 2)
			 * according to the definition of
			 * next_in_service, the in_service_entity
			 * cannot be considered as
			 * next_in_service. See the comments on the
			 * definition of next_in_service for details.
			 */
			break;
		}

		/*
		 * If we get here, then the parent is no more
		 * backlogged and we need to propagate the
		 * deactivation upwards. Thus let the loop go on.
		 */

		/*
		 * Also let parent be queued into the idle tree on
		 * deactivation, to preserve service guarantees, and
		 * assuming that who invoked this function does not
		 * need parent entities too to be removed completely.
		 */
		ins_into_idle_tree = true;
	}

	/*
	 * If the deactivation loop is fully executed, then there are
	 * no more entities to touch and next loop is not executed at
	 * all. Otherwise, requeue remaining entities if they are
	 * about to stop receiving service, or reposition them if this
	 * is not the case.
	 */
	entity = parent;
	for_each_entity(entity) {
		/*
		 * Invoke __bfq_requeue_entity on entity, even if
		 * already active, to requeue/reposition it in the
		 * active tree (because sd->next_in_service has
		 * changed)
		 */
		__bfq_requeue_entity(entity);

		sd = entity->sched_data;
		if (!bfq_update_next_in_service(sd, entity, expiration) &&
		    !expiration)
			/*
			 * next_in_service unchanged or not causing
			 * any change in entity->parent->sd, and no
			 * requeueing needed for expiration: stop
			 * here.
			 */
			break;
	}
}
```

## 3. 硬件上下文的初始化
这个是在生成每个hctx的时候调用.

### 3.1. 初始化
```c
static int bfq_init_hctx(struct blk_mq_hw_ctx *hctx, unsigned int index)
{
	bfq_depth_updated(hctx);
	return 0;
}

static void bfq_depth_updated(struct blk_mq_hw_ctx *hctx)
{
	struct bfq_data *bfqd = hctx->queue->elevator->elevator_data;
	struct blk_mq_tags *tags = hctx->sched_tags;
	unsigned int min_shallow;
	// what?
	min_shallow = bfq_update_depths(bfqd, tags->bitmap_tags);
	sbitmap_queue_min_shallow_depth(tags->bitmap_tags, min_shallow);
}

static unsigned int bfq_update_depths(struct bfq_data *bfqd,
				      struct sbitmap_queue *bt)
{
	unsigned int i, j, min_shallow = UINT_MAX;

	/*
	 * In-word depths if no bfq_queue is being weight-raised:
	 * leaving 25% of tags only for sync reads.
	 *
	 * In next formulas, right-shift the value
	 * (1U<<bt->sb.shift), instead of computing directly
	 * (1U<<(bt->sb.shift - something)), to be robust against
	 * any possible value of bt->sb.shift, without having to
	 * limit 'something'.
	 */
	/* no more than 50% of tags for async I/O */
	bfqd->word_depths[0][0] = max((1U << bt->sb.shift) >> 1, 1U);
	/*
	 * no more than 75% of tags for sync writes (25% extra tags
	 * w.r.t. async I/O, to prevent async I/O from starving sync
	 * writes)
	 */
	bfqd->word_depths[0][1] = max(((1U << bt->sb.shift) * 3) >> 2, 1U);

	/*
	 * In-word depths in case some bfq_queue is being weight-
	 * raised: leaving ~63% of tags for sync reads. This is the
	 * highest percentage for which, in our tests, application
	 * start-up times didn't suffer from any regression due to tag
	 * shortage.
	 */
	/* no more than ~18% of tags for async I/O */
	bfqd->word_depths[1][0] = max(((1U << bt->sb.shift) * 3) >> 4, 1U);
	/* no more than ~37% of tags for sync writes (~20% extra tags) */
	bfqd->word_depths[1][1] = max(((1U << bt->sb.shift) * 6) >> 4, 1U);

	for (i = 0; i < 2; i++)
		for (j = 0; j < 2; j++)
			min_shallow = min(min_shallow, bfqd->word_depths[i][j]);

	return min_shallow;
}
```

## 4. bio合并
```c
static bool bfq_allow_bio_merge(struct request_queue *q, struct request *rq,
				struct bio *bio)
{
	struct bfq_data *bfqd = q->elevator->elevator_data;
	bool is_sync = op_is_sync(bio->bi_opf);
	struct bfq_queue *bfqq = bfqd->bio_bfqq, *new_bfqq;

	/*
	 * Disallow merge of a sync bio into an async request.
	 */
	if (is_sync && !rq_is_sync(rq))
		return false;

	/*
	 * Lookup the bfqq that this bio will be queued with. Allow
	 * merge only if rq is queued there.
	 */
	if (!bfqq)
		return false;

	/*
	 * We take advantage of this function to perform an early merge
	 * of the queues of possible cooperating processes.
	 */
	new_bfqq = bfq_setup_cooperator(bfqd, bfqq, bio, false);
	if (new_bfqq) {
		/*
		 * bic still points to bfqq, then it has not yet been
		 * redirected to some other bfq_queue, and a queue
		 * merge between bfqq and new_bfqq can be safely
		 * fulfilled, i.e., bic can be redirected to new_bfqq
		 * and bfqq can be put.
		 */
		bfq_merge_bfqqs(bfqd, bfqd->bio_bic, bfqq,
				new_bfqq);
		/*
		 * If we get here, bio will be queued into new_queue,
		 * so use new_bfqq to decide whether bio and rq can be
		 * merged.
		 */
		bfqq = new_bfqq;

		/*
		 * Change also bqfd->bio_bfqq, as
		 * bfqd->bio_bic now points to new_bfqq, and
		 * this function may be invoked again (and then may
		 * use again bqfd->bio_bfqq).
		 */
		bfqd->bio_bfqq = bfqq;
	}

	return bfqq == RQ_BFQQ(rq);
}

static bool bfq_bio_merge(struct request_queue *q, struct bio *bio,
		unsigned int nr_segs)
{
	struct bfq_data *bfqd = q->elevator->elevator_data;
	struct request *free = NULL;
	/*
	 * bfq_bic_lookup grabs the queue_lock: invoke it now and
	 * store its return value for later use, to avoid nesting
	 * queue_lock inside the bfqd->lock. We assume that the bic
	 * returned by bfq_bic_lookup does not go away before
	 * bfqd->lock is taken.
	 */
	struct bfq_io_cq *bic = bfq_bic_lookup(bfqd, current->io_context, q);
	bool ret;

	spin_lock_irq(&bfqd->lock);

	if (bic)
		bfqd->bio_bfqq = bic_to_bfqq(bic, op_is_sync(bio->bi_opf));
	else
		bfqd->bio_bfqq = NULL;
	bfqd->bio_bic = bic;

	ret = blk_mq_sched_try_merge(q, bio, nr_segs, &free);

	if (free)
		blk_mq_free_request(free);
	spin_unlock_irq(&bfqd->lock);

	return ret;
}

static int bfq_request_merge(struct request_queue *q, struct request **req,
			     struct bio *bio)
{
	struct bfq_data *bfqd = q->elevator->elevator_data;
	struct request *__rq;

	__rq = bfq_find_rq_fmerge(bfqd, bio, q);
	if (__rq && elv_bio_merge_ok(__rq, bio)) {
		*req = __rq;

		if (blk_discard_mergable(__rq))
			return ELEVATOR_DISCARD_MERGE;
		return ELEVATOR_FRONT_MERGE;
	}

	return ELEVATOR_NO_MERGE;
}

static void bfq_requests_merged(struct request_queue *q, struct request *rq,
				struct request *next)
{
	struct bfq_queue *bfqq = bfq_init_rq(rq),
		*next_bfqq = bfq_init_rq(next);

	if (!bfqq)
		return;

	/*
	 * If next and rq belong to the same bfq_queue and next is older
	 * than rq, then reposition rq in the fifo (by substituting next
	 * with rq). Otherwise, if next and rq belong to different
	 * bfq_queues, never reposition rq: in fact, we would have to
	 * reposition it with respect to next's position in its own fifo,
	 * which would most certainly be too expensive with respect to
	 * the benefits.
	 */
	if (bfqq == next_bfqq &&
	    !list_empty(&rq->queuelist) && !list_empty(&next->queuelist) &&
	    next->fifo_time < rq->fifo_time) {
		list_del_init(&rq->queuelist);
		list_replace_init(&next->queuelist, &rq->queuelist);
		rq->fifo_time = next->fifo_time;
	}

	if (bfqq->next_rq == next)
		bfqq->next_rq = rq;

	bfqg_stats_update_io_merged(bfqq_group(bfqq), next->cmd_flags);
}

static void bfq_request_merged(struct request_queue *q, struct request *req,
			       enum elv_merge type)
{
	if (type == ELEVATOR_FRONT_MERGE &&
	    rb_prev(&req->rb_node) &&
	    blk_rq_pos(req) <
	    blk_rq_pos(container_of(rb_prev(&req->rb_node),
				    struct request, rb_node))) {
		struct bfq_queue *bfqq = bfq_init_rq(req);
		struct bfq_data *bfqd;
		struct request *prev, *next_rq;

		if (!bfqq)
			return;

		bfqd = bfqq->bfqd;

		/* Reposition request in its sort_list */
		elv_rb_del(&bfqq->sort_list, req);
		elv_rb_add(&bfqq->sort_list, req);

		/* Choose next request to be served for bfqq */
		prev = bfqq->next_rq;
		next_rq = bfq_choose_req(bfqd, bfqq->next_rq, req,
					 bfqd->last_position);
		bfqq->next_rq = next_rq;
		/*
		 * If next_rq changes, update both the queue's budget to
		 * fit the new request and the queue's position in its
		 * rq_pos_tree.
		 */
		if (prev != bfqq->next_rq) {
			bfq_updated_next_req(bfqd, bfqq);
			/*
			 * See comments on bfq_pos_tree_add_move() for
			 * the unlikely().
			 */
			if (unlikely(!bfqd->nonrot_with_queueing))
				bfq_pos_tree_add_move(bfqd, bfqq);
		}
	}
}
```

## 5. 请求相关

### 5.1. 准备请求
```c
static void bfq_prepare_request(struct request *rq)
{
	/*
	 * Regardless of whether we have an icq attached, we have to
	 * clear the scheduler pointers, as they might point to
	 * previously allocated bic/bfqq structs.
	 */
	rq->elv.priv[0] = rq->elv.priv[1] = NULL;
}
```

### 5.2. 插入请求
```c
static void bfq_insert_requests(struct blk_mq_hw_ctx *hctx,
				struct list_head *list, bool at_head)
{
	while (!list_empty(list)) {
		struct request *rq;

		// 取出请求
		rq = list_first_entry(list, struct request, queuelist);
		list_del_init(&rq->queuelist);

		// 插入bfq里
		bfq_insert_request(hctx, rq, at_head);
		// 递增入队请求数
		atomic_inc(&hctx->elevator_queued);
	}
}

static void bfq_insert_request(struct blk_mq_hw_ctx *hctx, struct request *rq,
			       bool at_head)
{
	struct request_queue *q = hctx->queue;
	struct bfq_data *bfqd = q->elevator->elevator_data;
	struct bfq_queue *bfqq;
	bool idle_timer_disabled = false;
	unsigned int cmd_flags;

#ifdef CONFIG_BFQ_GROUP_IOSCHED
	if (!cgroup_subsys_on_dfl(io_cgrp_subsys) && rq->bio)
		bfqg_stats_update_legacy_io(q, rq);
#endif
	spin_lock_irq(&bfqd->lock);
	// 先尝试合并
	if (blk_mq_sched_try_insert_merge(q, rq)) {
		spin_unlock_irq(&bfqd->lock);
		return;
	}

	spin_unlock_irq(&bfqd->lock);

	// 打印trace
	blk_mq_sched_request_inserted(rq);

	spin_lock_irq(&bfqd->lock);
	bfqq = bfq_init_rq(rq);

	// 没有分配到bfqq || 在前面 || pass请求
	if (!bfqq || at_head || blk_rq_is_passthrough(rq)) {
		// 直接插入派发队列
		if (at_head)
			list_add(&rq->queuelist, &bfqd->dispatch);
		else
			list_add_tail(&rq->queuelist, &bfqd->dispatch);
	} else {
		// 插入请求
		idle_timer_disabled = __bfq_insert_request(bfqd, rq);
		// 重新获取bfqq, 因为在__bfq_insert_request里可能会发生改变
		bfqq = RQ_BFQQ(rq);

		// 请求如果是可合并的
		if (rq_mergeable(rq)) {
			// 加到哈希表里
			elv_rqhash_add(q, rq);

			// 设置queue的最后合并的请求,如果之前没有设置的话
			if (!q->last_merge)
				q->last_merge = rq;
		}
	}

	// 释放锁之后可能会变
	cmd_flags = rq->cmd_flags;

	spin_unlock_irq(&bfqd->lock);

	// 更新插入状态. 调试相关
	bfq_update_insert_stats(q, bfqq, idle_timer_disabled,
				cmd_flags);
}

static struct bfq_queue *bfq_init_rq(struct request *rq)
{
	struct request_queue *q = rq->q;
	struct bio *bio = rq->bio;
	struct bfq_data *bfqd = q->elevator->elevator_data;
	struct bfq_io_cq *bic;
	const int is_sync = rq_is_sync(rq);
	struct bfq_queue *bfqq;
	bool new_queue = false;
	bool bfqq_already_existing = false, split = false;

	// 没有icq?
	if (unlikely(!rq->elv.icq))
		return NULL;

	// 已经分配过值,则直接返回
	if (rq->elv.priv[1])
		return rq->elv.priv[1];

	// 转换成iocq对象
	bic = icq_to_bic(rq->elv.icq);

	// 检查优先级
	bfq_check_ioprio_change(bic, bio);

	// cgroup相关. todo: 后面看
	bfq_bic_update_cgroup(bic, bio);

	// what?
	bfqq = bfq_get_bfqq_handle_split(bfqd, bic, bio, false, is_sync,
					 &new_queue);

	if (likely(!new_queue)) {
		/* If the queue was seeky for too long, break it apart. */
		if (bfq_bfqq_coop(bfqq) && bfq_bfqq_split_coop(bfqq)) {
			bfq_log_bfqq(bfqd, bfqq, "breaking apart bfqq");

			/* Update bic before losing reference to bfqq */
			if (bfq_bfqq_in_large_burst(bfqq))
				bic->saved_in_large_burst = true;

			bfqq = bfq_split_bfqq(bic, bfqq);
			split = true;

			if (!bfqq)
				bfqq = bfq_get_bfqq_handle_split(bfqd, bic, bio,
								 true, is_sync,
								 NULL);
			else
				bfqq_already_existing = true;
		}
	}

	// 分配数增加
	bfqq->allocated++;
	// 引用增加
	bfqq->ref++;
	bfq_log_bfqq(bfqd, bfqq, "get_request %p: bfqq %p, %d",
		     rq, bfqq, bfqq->ref);

	// 设置bic和bfqq
	rq->elv.priv[0] = bic;
	rq->elv.priv[1] = bfqq;

	/*
	 * If a bfq_queue has only one process reference, it is owned
	 * by only this bic: we can then set bfqq->bic = bic. in
	 * addition, if the queue has also just been split, we have to
	 * resume its state.
	 */
	if (likely(bfqq != &bfqd->oom_bfqq) && bfqq_process_refs(bfqq) == 1) {
		bfqq->bic = bic;
		if (split) {
			/*
			 * The queue has just been split from a shared
			 * queue: restore the idle window and the
			 * possible weight raising period.
			 */
			bfq_bfqq_resume_state(bfqq, bfqd, bic,
					      bfqq_already_existing);
		}
	}

	/*
	 * Consider bfqq as possibly belonging to a burst of newly
	 * created queues only if:
	 * 1) A burst is actually happening (bfqd->burst_size > 0)
	 * or
	 * 2) There is no other active queue. In fact, if, in
	 *    contrast, there are active queues not belonging to the
	 *    possible burst bfqq may belong to, then there is no gain
	 *    in considering bfqq as belonging to a burst, and
	 *    therefore in not weight-raising bfqq. See comments on
	 *    bfq_handle_burst().
	 *
	 * This filtering also helps eliminating false positives,
	 * occurring when bfqq does not belong to an actual large
	 * burst, but some background task (e.g., a service) happens
	 * to trigger the creation of new queues very close to when
	 * bfqq and its possible companion queues are created. See
	 * comments on bfq_handle_burst() for further details also on
	 * this issue.
	 */
	if (unlikely(bfq_bfqq_just_created(bfqq) &&
		     (bfqd->burst_size > 0 ||
		      bfq_tot_busy_queues(bfqd) == 0)))
		bfq_handle_burst(bfqd, bfqq);

	return bfqq;
}

static void bfq_check_ioprio_change(struct bfq_io_cq *bic, struct bio *bio)
{
	struct bfq_data *bfqd = bic_to_bfqd(bic);
	struct bfq_queue *bfqq;
	int ioprio = bic->icq.ioc->ioprio;

	/*
	 * This condition may trigger on a newly created bic, be sure to
	 * drop the lock before returning.
	 */
	if (unlikely(!bfqd) || likely(bic->ioprio == ioprio))
		return;

	bic->ioprio = ioprio;

	bfqq = bic_to_bfqq(bic, false);
	if (bfqq) {
		bfq_release_process_ref(bfqd, bfqq);
		bfqq = bfq_get_queue(bfqd, bio, BLK_RW_ASYNC, bic);
		bic_set_bfqq(bic, bfqq, false);
	}

	bfqq = bic_to_bfqq(bic, true);
	if (bfqq)
		bfq_set_next_ioprio_data(bfqq, bic);
}


static struct bfq_queue *bfq_get_bfqq_handle_split(struct bfq_data *bfqd,
						   struct bfq_io_cq *bic,
						   struct bio *bio,
						   bool split, bool is_sync,
						   bool *new_queue)
{
	struct bfq_queue *bfqq = bic_to_bfqq(bic, is_sync);

	if (likely(bfqq && bfqq != &bfqd->oom_bfqq))
		return bfqq;

	if (new_queue)
		*new_queue = true;

	if (bfqq)
		bfq_put_queue(bfqq);
	bfqq = bfq_get_queue(bfqd, bio, is_sync, bic);

	bic_set_bfqq(bic, bfqq, is_sync);
	if (split && is_sync) {
		if ((bic->was_in_burst_list && bfqd->large_burst) ||
		    bic->saved_in_large_burst)
			bfq_mark_bfqq_in_large_burst(bfqq);
		else {
			bfq_clear_bfqq_in_large_burst(bfqq);
			if (bic->was_in_burst_list)
				/*
				 * If bfqq was in the current
				 * burst list before being
				 * merged, then we have to add
				 * it back. And we do not need
				 * to increase burst_size, as
				 * we did not decrement
				 * burst_size when we removed
				 * bfqq from the burst list as
				 * a consequence of a merge
				 * (see comments in
				 * bfq_put_queue). In this
				 * respect, it would be rather
				 * costly to know whether the
				 * current burst list is still
				 * the same burst list from
				 * which bfqq was removed on
				 * the merge. To avoid this
				 * cost, if bfqq was in a
				 * burst list, then we add
				 * bfqq to the current burst
				 * list without any further
				 * check. This can cause
				 * inappropriate insertions,
				 * but rarely enough to not
				 * harm the detection of large
				 * bursts significantly.
				 */
				hlist_add_head(&bfqq->burst_list_node,
					       &bfqd->burst_list);
		}
		bfqq->split_time = jiffies;
	}

	return bfqq;
}

static bool __bfq_insert_request(struct bfq_data *bfqd, struct request *rq)
{
	struct bfq_queue *bfqq = RQ_BFQQ(rq),
		*new_bfqq = bfq_setup_cooperator(bfqd, bfqq, rq, true);
	bool waiting, idle_timer_disabled = false;

	if (new_bfqq) {
		// 释放旧引用,增加新引用
		new_bfqq->allocated++;
		bfqq->allocated--;
		new_bfqq->ref++;
		/*
		 * If the bic associated with the process
		 * issuing this request still points to bfqq
		 * (and thus has not been already redirected
		 * to new_bfqq or even some other bfq_queue),
		 * then complete the merge and redirect it to
		 * new_bfqq.
		 */
		if (bic_to_bfqq(RQ_BIC(rq), 1) == bfqq)
			bfq_merge_bfqqs(bfqd, RQ_BIC(rq),
					bfqq, new_bfqq);

		bfq_clear_bfqq_just_created(bfqq);
		/*
		 * rq is about to be enqueued into new_bfqq,
		 * release rq reference on bfqq
		 */
		bfq_put_queue(bfqq);
		rq->elv.priv[1] = new_bfqq;
		bfqq = new_bfqq;
	}

	bfq_update_io_thinktime(bfqd, bfqq);
	bfq_update_has_short_ttime(bfqd, bfqq, RQ_BIC(rq));
	bfq_update_io_seektime(bfqd, bfqq, rq);

	waiting = bfqq && bfq_bfqq_wait_request(bfqq);
	bfq_add_request(rq);
	idle_timer_disabled = waiting && !bfq_bfqq_wait_request(bfqq);

	// 过期时间
	rq->fifo_time = ktime_get_ns() + bfqd->bfq_fifo_expire[rq_is_sync(rq)];

	// 加到bfqq的队列
	list_add_tail(&rq->queuelist, &bfqq->fifo);

	bfq_rq_enqueued(bfqd, bfqq, rq);

	return idle_timer_disabled;
}

static struct bfq_queue *
bfq_setup_cooperator(struct bfq_data *bfqd, struct bfq_queue *bfqq,
		     void *io_struct, bool request)
{
	struct bfq_queue *in_service_bfqq, *new_bfqq;

	/*
	 * Do not perform queue merging if the device is non
	 * rotational and performs internal queueing. In fact, such a
	 * device reaches a high speed through internal parallelism
	 * and pipelining. This means that, to reach a high
	 * throughput, it must have many requests enqueued at the same
	 * time. But, in this configuration, the internal scheduling
	 * algorithm of the device does exactly the job of queue
	 * merging: it reorders requests so as to obtain as much as
	 * possible a sequential I/O pattern. As a consequence, with
	 * the workload generated by processes doing interleaved I/O,
	 * the throughput reached by the device is likely to be the
	 * same, with and without queue merging.
	 *
	 * Disabling merging also provides a remarkable benefit in
	 * terms of throughput. Merging tends to make many workloads
	 * artificially more uneven, because of shared queues
	 * remaining non empty for incomparably more time than
	 * non-merged queues. This may accentuate workload
	 * asymmetries. For example, if one of the queues in a set of
	 * merged queues has a higher weight than a normal queue, then
	 * the shared queue may inherit such a high weight and, by
	 * staying almost always active, may force BFQ to perform I/O
	 * plugging most of the time. This evidently makes it harder
	 * for BFQ to let the device reach a high throughput.
	 *
	 * Finally, the likely() macro below is not used because one
	 * of the two branches is more likely than the other, but to
	 * have the code path after the following if() executed as
	 * fast as possible for the case of a non rotational device
	 * with queueing. We want it because this is the fastest kind
	 * of device. On the opposite end, the likely() may lengthen
	 * the execution time of BFQ for the case of slower devices
	 * (rotational or at least without queueing). But in this case
	 * the execution time of BFQ matters very little, if not at
	 * all.
	 */
	if (likely(bfqd->nonrot_with_queueing))
		return NULL;

	/*
	 * Prevent bfqq from being merged if it has been created too
	 * long ago. The idea is that true cooperating processes, and
	 * thus their associated bfq_queues, are supposed to be
	 * created shortly after each other. This is the case, e.g.,
	 * for KVM/QEMU and dump I/O threads. Basing on this
	 * assumption, the following filtering greatly reduces the
	 * probability that two non-cooperating processes, which just
	 * happen to do close I/O for some short time interval, have
	 * their queues merged by mistake.
	 */
	if (bfq_too_late_for_merging(bfqq))
		return NULL;

	if (bfqq->new_bfqq)
		return bfqq->new_bfqq;

	if (!io_struct || unlikely(bfqq == &bfqd->oom_bfqq))
		return NULL;

	/* If there is only one backlogged queue, don't search. */
	if (bfq_tot_busy_queues(bfqd) == 1)
		return NULL;

	in_service_bfqq = bfqd->in_service_queue;

	if (in_service_bfqq && in_service_bfqq != bfqq &&
	    likely(in_service_bfqq != &bfqd->oom_bfqq) &&
	    bfq_rq_close_to_sector(io_struct, request,
				   bfqd->in_serv_last_pos) &&
	    bfqq->entity.parent == in_service_bfqq->entity.parent &&
	    bfq_may_be_close_cooperator(bfqq, in_service_bfqq)) {
		new_bfqq = bfq_setup_merge(bfqq, in_service_bfqq);
		if (new_bfqq)
			return new_bfqq;
	}
	/*
	 * Check whether there is a cooperator among currently scheduled
	 * queues. The only thing we need is that the bio/request is not
	 * NULL, as we need it to establish whether a cooperator exists.
	 */
	new_bfqq = bfq_find_close_cooperator(bfqd, bfqq,
			bfq_io_struct_pos(io_struct, request));

	if (new_bfqq && likely(new_bfqq != &bfqd->oom_bfqq) &&
	    bfq_may_be_close_cooperator(bfqq, new_bfqq))
		return bfq_setup_merge(bfqq, new_bfqq);

	return NULL;
}

static void bfq_rq_enqueued(struct bfq_data *bfqd, struct bfq_queue *bfqq,
			    struct request *rq)
{
	if (rq->cmd_flags & REQ_META)
		bfqq->meta_pending++;

	bfqq->last_request_pos = blk_rq_pos(rq) + blk_rq_sectors(rq);

	if (bfqq == bfqd->in_service_queue && bfq_bfqq_wait_request(bfqq)) {
		bool small_req = bfqq->queued[rq_is_sync(rq)] == 1 &&
				 blk_rq_sectors(rq) < 32;
		bool budget_timeout = bfq_bfqq_budget_timeout(bfqq);

		/*
		 * There is just this request queued: if
		 * - the request is small, and
		 * - we are idling to boost throughput, and
		 * - the queue is not to be expired,
		 * then just exit.
		 *
		 * In this way, if the device is being idled to wait
		 * for a new request from the in-service queue, we
		 * avoid unplugging the device and committing the
		 * device to serve just a small request. In contrast
		 * we wait for the block layer to decide when to
		 * unplug the device: hopefully, new requests will be
		 * merged to this one quickly, then the device will be
		 * unplugged and larger requests will be dispatched.
		 */
		if (small_req && idling_boosts_thr_without_issues(bfqd, bfqq) &&
		    !budget_timeout)
			return;

		/*
		 * A large enough request arrived, or idling is being
		 * performed to preserve service guarantees, or
		 * finally the queue is to be expired: in all these
		 * cases disk idling is to be stopped, so clear
		 * wait_request flag and reset timer.
		 */
		bfq_clear_bfqq_wait_request(bfqq);
		hrtimer_try_to_cancel(&bfqd->idle_slice_timer);

		/*
		 * The queue is not empty, because a new request just
		 * arrived. Hence we can safely expire the queue, in
		 * case of budget timeout, without risking that the
		 * timestamps of the queue are not updated correctly.
		 * See [1] for more details.
		 */
		if (budget_timeout)
			bfq_bfqq_expire(bfqd, bfqq, false,
					BFQQE_BUDGET_TIMEOUT);
	}
}
```

### 5.3. 结束请求
```c
static void dd_finish_request(struct request *rq)
{
	struct request_queue *q = rq->q;

	if (blk_queue_is_zoned(q)) {
		struct deadline_data *dd = q->elevator->elevator_data;
		unsigned long flags;

		spin_lock_irqsave(&dd->zone_lock, flags);
		blk_req_zone_write_unlock(rq);
		if (!list_empty(&dd->fifo_list[WRITE]))
			blk_mq_sched_mark_restart_hctx(rq->mq_hctx);
		spin_unlock_irqrestore(&dd->zone_lock, flags);
	}
}
```

### 5.4. 派发请求
```c
static struct request *bfq_dispatch_request(struct blk_mq_hw_ctx *hctx)
{
	struct bfq_data *bfqd = hctx->queue->elevator->elevator_data;
	struct request *rq;
	struct bfq_queue *in_serv_queue;
	bool waiting_rq, idle_timer_disabled;

	spin_lock_irq(&bfqd->lock);

	// 正在服务的队列
	in_serv_queue = bfqd->in_service_queue;
	// 有wait_requests标志
	waiting_rq = in_serv_queue && bfq_bfqq_wait_request(in_serv_queue);

	rq = __bfq_dispatch_request(hctx);

	idle_timer_disabled =
		waiting_rq && !bfq_bfqq_wait_request(in_serv_queue);

	spin_unlock_irq(&bfqd->lock);

	// 更新状态,调试相关
	bfq_update_dispatch_stats(hctx->queue, rq, in_serv_queue,
				  idle_timer_disabled);

	return rq;
}

static struct request *__bfq_dispatch_request(struct blk_mq_hw_ctx *hctx)
{
	struct bfq_data *bfqd = hctx->queue->elevator->elevator_data;
	struct request *rq = NULL;
	struct bfq_queue *bfqq = NULL;

	// 直接派发队列里有请求
	if (!list_empty(&bfqd->dispatch)) {
		// 取出一个请求
		rq = list_first_entry(&bfqd->dispatch, struct request,
				      queuelist);
		list_del_init(&rq->queuelist);

		// 请求对应的bfqq
		bfqq = RQ_BFQQ(rq);

		if (bfqq) {
			// 递增派发数量
			bfqq->dispatched++;

			// 统计之后直接返回
			goto inc_in_driver_start_rq;
		}

		// 直接标记开始,再返回
		goto start_rq;
	}

	bfq_log(bfqd, "dispatch requests: %d busy queues",
		bfq_tot_busy_queues(bfqd));

	// 如果没有忙的队列,直接返回
	if (bfq_tot_busy_queues(bfqd) == 0)
		goto exit;

	/*
	 * Force device to serve one request at a time if
	 * strict_guarantees is true. Forcing this service scheme is
	 * currently the ONLY way to guarantee that the request
	 * service order enforced by the scheduler is respected by a
	 * queueing device. Otherwise the device is free even to make
	 * some unlucky request wait for as long as the device
	 * wishes.
	 *
	 * Of course, serving one request at a time may cause loss of
	 * throughput.
	 */
	if (bfqd->strict_guarantees && bfqd->rq_in_driver > 0)
		goto exit;

	bfqq = bfq_select_queue(bfqd);
	if (!bfqq)
		goto exit;

	rq = bfq_dispatch_rq_from_bfqq(bfqd, bfqq);

	if (rq) {
inc_in_driver_start_rq:
		// 派发给driver的计数
		bfqd->rq_in_driver++;
start_rq:
		// 标记已开始
		rq->rq_flags |= RQF_STARTED;
	}
exit:
	return rq;
}
```