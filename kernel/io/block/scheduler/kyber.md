# kyber

## 0. 私有数据
```c
struct kyber_queue_data {
	struct request_queue *q;

	// 每个调度域的位图？
	struct sbitmap_queue domain_tokens[KYBER_NUM_DOMAINS];

	// 异步深度
	unsigned int async_depth;

	// cpu延迟
	struct kyber_cpu_latency __percpu *cpu_latency;

	// 统计和调度域用的定时器
	struct timer_list timer;

	// ？
	unsigned int latency_buckets[KYBER_OTHER][2][KYBER_LATENCY_BUCKETS];

	// ?
	unsigned long latency_timeout[KYBER_OTHER];

	int domain_p99[KYBER_OTHER];

	// 域延迟
	u64 latency_targets[KYBER_OTHER];
};

// 根据操作类型划分不同调度域
enum {
	KYBER_READ,
	KYBER_WRITE,
	KYBER_DISCARD,
	KYBER_OTHER,
	KYBER_NUM_DOMAINS,
};

enum {
	// 为了避免同步请求被异步淹没，异步请求只允许使用75％
	KYBER_ASYNC_PERCENT = 75,
};

// 各个操作对应的队列深度
static const unsigned int kyber_depth[] = {
	[KYBER_READ] = 256,
	[KYBER_WRITE] = 128,
	[KYBER_DISCARD] = 64,
	[KYBER_OTHER] = 16,
};

// 各种操作批量的大小
static const unsigned int kyber_batch_size[] = {
	[KYBER_READ] = 16,
	[KYBER_WRITE] = 8,
	[KYBER_DISCARD] = 1,
	[KYBER_OTHER] = 1,
};

// 每种操作的延迟时间,对读是友好的
static const u64 kyber_latency_targets[] = {
	[KYBER_READ] = 2ULL * NSEC_PER_MSEC,
	[KYBER_WRITE] = 10ULL * NSEC_PER_MSEC,
	[KYBER_DISCARD] = 5ULL * NSEC_PER_SEC,
};

enum {
	/*
	 * The width of the latency histogram buckets is
	 * 1 / (1 << KYBER_LATENCY_SHIFT) * target latency.
	 */
	KYBER_LATENCY_SHIFT = 2,
	/*
	 * The first (1 << KYBER_LATENCY_SHIFT) buckets are <= target latency,
	 * thus, "good".
	 */
	KYBER_GOOD_BUCKETS = 1 << KYBER_LATENCY_SHIFT,
	/* There are also (1 << KYBER_LATENCY_SHIFT) "bad" buckets. */
	KYBER_LATENCY_BUCKETS = 2 << KYBER_LATENCY_SHIFT,
};

/*
 * We measure both the total latency and the I/O latency (i.e., latency after
 * submitting to the device).
 */
enum {
	KYBER_TOTAL_LATENCY,
	KYBER_IO_LATENCY,
};

struct kyber_cpu_latency {
	atomic_t buckets[KYBER_OTHER][2][KYBER_LATENCY_BUCKETS];
};

// hctx的私有数据
struct kyber_hctx_data {
	spinlock_t lock;
	struct list_head rqs[KYBER_NUM_DOMAINS];// 调度域的队列
	unsigned int cur_domain; // 当前操作域
	unsigned int batching; // 批量派发的数量
	struct kyber_ctx_queue *kcqs; // 软队列
	struct sbitmap kcq_map[KYBER_NUM_DOMAINS];
	struct sbq_wait domain_wait[KYBER_NUM_DOMAINS];
	struct sbq_wait_state *domain_ws[KYBER_NUM_DOMAINS];
	atomic_t wait_index[KYBER_NUM_DOMAINS];
};

struct kyber_ctx_queue {
	/*
	 * Used to ensure operations on rq_list and kcq_map to be an atmoic one.
	 * Also protect the rqs on rq_list when merge.
	 */
	spinlock_t lock;
	struct list_head rq_list[KYBER_NUM_DOMAINS];
} ____cacheline_aligned_in_smp;
```

## 1. 函数表
```c
static struct elevator_type kyber_sched = {
	.ops = {
		.init_sched = kyber_init_sched,
		.exit_sched = kyber_exit_sched,
		.init_hctx = kyber_init_hctx,
		.exit_hctx = kyber_exit_hctx,
		.limit_depth = kyber_limit_depth,
		.bio_merge = kyber_bio_merge,
		.prepare_request = kyber_prepare_request,
		.insert_requests = kyber_insert_requests,
		.finish_request = kyber_finish_request,
		.requeue_request = kyber_finish_request,
		.completed_request = kyber_completed_request,
		.dispatch_request = kyber_dispatch_request,
		.has_work = kyber_has_work,
	},
#ifdef CONFIG_BLK_DEBUG_FS
	.queue_debugfs_attrs = kyber_queue_debugfs_attrs,
	.hctx_debugfs_attrs = kyber_hctx_debugfs_attrs,
#endif
	.elevator_attrs = kyber_sched_attrs,
	.elevator_name = "kyber",
	.elevator_owner = THIS_MODULE,
};
```
### 1.1. 属性
```c
static struct elv_fs_entry kyber_sched_attrs[] = {
	KYBER_LAT_ATTR(read), // 读延迟,纳秒
	KYBER_LAT_ATTR(write), // 写延迟,纳秒
	__ATTR_NULL
};
```

## 2. 调度器初始化及退出
### 2.1. 初始化
```c
static int kyber_init_sched(struct request_queue *q, struct elevator_type *e)
{
	struct kyber_queue_data *kqd;
	struct elevator_queue *eq;

	// 分配调度器对象
	eq = elevator_alloc(q, e);
	if (!eq)
		return -ENOMEM;

	// 分配私有数据
	kqd = kyber_queue_data_alloc(q);
	if (IS_ERR(kqd)) {
		kobject_put(&eq->kobj);
		return PTR_ERR(kqd);
	}

	// 设置队列的统计标志
	blk_stat_enable_accounting(q);

	eq->elevator_data = kqd;
	q->elevator = eq;

	return 0;
}

static struct kyber_queue_data *kyber_queue_data_alloc(struct request_queue *q)
{
	struct kyber_queue_data *kqd;
	unsigned int shift;
	int ret = -ENOMEM;
	int i;

	// 分配一个对象
	kqd = kzalloc_node(sizeof(*kqd), GFP_KERNEL, q->node);
	if (!kqd)
		goto err;

	// 队列引用
	kqd->q = q;

	// cpu延迟
	kqd->cpu_latency = alloc_percpu_gfp(struct kyber_cpu_latency,
					    GFP_KERNEL | __GFP_ZERO);
	if (!kqd->cpu_latency)
		goto err_kqd;

	// 初始化timer
	timer_setup(&kqd->timer, kyber_timer_fn, 0);

	// 遍历所有调度域
	for (i = 0; i < KYBER_NUM_DOMAINS; i++) {
		// depth和batch都不能为0
		WARN_ON(!kyber_depth[i]);
		WARN_ON(!kyber_batch_size[i]);

		// 初始化每个域的token,这些token的深度由kyber_depth定义
		ret = sbitmap_queue_init_node(&kqd->domain_tokens[i],
					      kyber_depth[i], -1, false,
					      GFP_KERNEL, q->node);
		// 如果初始化失败，则释放之前已经分配的
		if (ret) {
			while (--i >= 0)
				sbitmap_queue_free(&kqd->domain_tokens[i]);
			goto err_buckets;
		}
	}

	// 设置默认延迟
	for (i = 0; i < KYBER_OTHER; i++) {
		// todo: what is p99
		kqd->domain_p99[i] = -1;
		// 初始化每个域的延迟
		kqd->latency_targets[i] = kyber_latency_targets[i];
	}

	// 获取硬件队列深度的shift
	shift = kyber_sched_tags_shift(q);
	// 算出异步深度,KYBER_ASYNC_PERCENT是75, 所以异步队列使用限制在75%
	kqd->async_depth = (1U << shift) * KYBER_ASYNC_PERCENT / 100U;

	return kqd;

err_buckets:
	free_percpu(kqd->cpu_latency);
err_kqd:
	kfree(kqd);
err:
	return ERR_PTR(ret);
}

static unsigned int kyber_sched_tags_shift(struct request_queue *q)
{
	/*
	 * 所有硬件队列深度一样，只需获取第1个就可以
	 */
	return q->queue_hw_ctx[0]->sched_tags->bitmap_tags->sb.shift;
}
```

### 2.2. 退出
```c
static void kyber_exit_sched(struct elevator_queue *e)
{
	struct kyber_queue_data *kqd = e->elevator_data;
	int i;

	// 删除timer
	del_timer_sync(&kqd->timer);

	// 释放调度域的位图
	for (i = 0; i < KYBER_NUM_DOMAINS; i++)
		sbitmap_queue_free(&kqd->domain_tokens[i]);
	// 释放cpu延迟
	free_percpu(kqd->cpu_latency);
	// 释放私有数据
	kfree(kqd);
}
```

## 3. 硬件上下文的初始化及释放
这个是在生成每个hctx的时候调用.

### 3.1. 初始化
```c
static int kyber_init_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
	struct kyber_queue_data *kqd = hctx->queue->elevator->elevator_data;
	struct kyber_hctx_data *khd;
	int i;

	// 分配hctx data
	khd = kmalloc_node(sizeof(*khd), GFP_KERNEL, hctx->numa_node);
	if (!khd)
		return -ENOMEM;

	// ctx列表
	khd->kcqs = kmalloc_array_node(hctx->nr_ctx,
				       sizeof(struct kyber_ctx_queue),
				       GFP_KERNEL, hctx->numa_node);
	if (!khd->kcqs)
		goto err_khd;

	// 初始化每个ctx结构
	for (i = 0; i < hctx->nr_ctx; i++)
		kyber_ctx_queue_init(&khd->kcqs[i]);

	// 初始化每个调度域的ctx位图
	for (i = 0; i < KYBER_NUM_DOMAINS; i++) {
		if (sbitmap_init_node(&khd->kcq_map[i], hctx->nr_ctx,
				      ilog2(8), GFP_KERNEL, hctx->numa_node)) {
			// 有分配失败的，释放其它的
			while (--i >= 0)
				sbitmap_free(&khd->kcq_map[i]);
			goto err_kcqs;
		}
	}

	spin_lock_init(&khd->lock);

	// 遍历每个调度域
	for (i = 0; i < KYBER_NUM_DOMAINS; i++) {
		// 请求表
		INIT_LIST_HEAD(&khd->rqs[i]);

		// 下面都是等待相关的

		khd->domain_wait[i].sbq = NULL;
		// 初始化等待队列
		init_waitqueue_func_entry(&khd->domain_wait[i].wait,
					  kyber_domain_wake);
		// 私有数据是hctx
		khd->domain_wait[i].wait.private = hctx;
		INIT_LIST_HEAD(&khd->domain_wait[i].wait.entry);
		atomic_set(&khd->wait_index[i], 0);
	}

	khd->cur_domain = 0;
	khd->batching = 0;

	// 设置调度的私有数据
	hctx->sched_data = khd;
	// 标记最少使用的深度?  使用的是异步深度
	sbitmap_queue_min_shallow_depth(hctx->sched_tags->bitmap_tags,
					kqd->async_depth);

	return 0;

err_kcqs:
	kfree(khd->kcqs);
err_khd:
	kfree(khd);
	return -ENOMEM;
}

static void kyber_ctx_queue_init(struct kyber_ctx_queue *kcq)
{
	unsigned int i;

	// 初始化锁
	spin_lock_init(&kcq->lock);
	// 初始化头指针
	for (i = 0; i < KYBER_NUM_DOMAINS; i++)
		INIT_LIST_HEAD(&kcq->rq_list[i]);
}

```

### 3.2. 释放
```c
static void kyber_exit_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
	struct kyber_hctx_data *khd = hctx->sched_data;
	int i;

	// 释放每个map
	for (i = 0; i < KYBER_NUM_DOMAINS; i++)
		sbitmap_free(&khd->kcq_map[i]);
	// 释放软队列
	kfree(khd->kcqs);
	// 释放私有数据
	kfree(hctx->sched_data);
}
```

## 4. bio合并
```c
static bool kyber_bio_merge(struct request_queue *q, struct bio *bio,
		unsigned int nr_segs)
{
	// 软上下文
	struct blk_mq_ctx *ctx = blk_mq_get_ctx(q);
	// 硬上下文
	struct blk_mq_hw_ctx *hctx = blk_mq_map_queue(q, bio->bi_opf, ctx);
	
	struct kyber_hctx_data *khd = hctx->sched_data;
	// 获取对应的queue
	struct kyber_ctx_queue *kcq = &khd->kcqs[ctx->index_hw[hctx->type]];
	// 操作域
	unsigned int sched_domain = kyber_sched_domain(bio->bi_opf);
	// 获取对应操作的请求列表
	struct list_head *rq_list = &kcq->rq_list[sched_domain];
	bool merged;

	// 使用了通用合并流程
	spin_lock(&kcq->lock);
	merged = blk_bio_list_merge(hctx->queue, rq_list, bio, nr_segs);
	spin_unlock(&kcq->lock);

	return merged;
}
```
## 5. 请求相关

### 5.1. 准备请求
```c
static void kyber_prepare_request(struct request *rq)
{
	// 设置 token为-1
	rq_set_domain_token(rq, -1);
}

static void rq_set_domain_token(struct request *rq, int token)
{
	rq->elv.priv[0] = (void *)(long)token;
}
```

### 5.2. 插入请求
```c
static void kyber_insert_requests(struct blk_mq_hw_ctx *hctx,
				  struct list_head *rq_list, bool at_head)
{
	struct kyber_hctx_data *khd = hctx->sched_data;
	struct request *rq, *next;

	list_for_each_entry_safe(rq, next, rq_list, queuelist) {
		// 根据操作获取对应的域
		unsigned int sched_domain = kyber_sched_domain(rq->cmd_flags);
		// 软队列
		struct kyber_ctx_queue *kcq = &khd->kcqs[rq->mq_ctx->index_hw[hctx->type]];
		// 软队列对应的头结点
		struct list_head *head = &kcq->rq_list[sched_domain];

		spin_lock(&kcq->lock);
		// 根据at_head, 加到软队列的头或尾
		if (at_head)
			list_move(&rq->queuelist, head);
		else
			list_move_tail(&rq->queuelist, head);
		// 设置对应的位
		sbitmap_set_bit(&khd->kcq_map[sched_domain],
				rq->mq_ctx->index_hw[hctx->type]);
		// 这个里面只打印了日志
		blk_mq_sched_request_inserted(rq);
		spin_unlock(&kcq->lock);
	}
}

static unsigned int kyber_sched_domain(unsigned int op)
{
	switch (op & REQ_OP_MASK) {
	case REQ_OP_READ:
		return KYBER_READ;
	case REQ_OP_WRITE:
		return KYBER_WRITE;
	case REQ_OP_DISCARD:
		return KYBER_DISCARD;
	default:
		return KYBER_OTHER;
	}
}

```

### 5.3. 结束请求
```c
static void kyber_finish_request(struct request *rq)
{
	struct kyber_queue_data *kqd = rq->q->elevator->elevator_data;

	// 清除token
	rq_clear_domain_token(kqd, rq);
}

static void rq_clear_domain_token(struct kyber_queue_data *kqd,
				  struct request *rq)
{
	unsigned int sched_domain;
	int nr;

	// 获取token
	nr = rq_get_domain_token(rq);
	if (nr != -1) {
		// 获取操作的调度域
		sched_domain = kyber_sched_domain(rq->cmd_flags);
		// 清除对应token上的位
		sbitmap_queue_clear(&kqd->domain_tokens[sched_domain], nr,
				    rq->mq_ctx->cpu);
	}
}

static int rq_get_domain_token(struct request *rq)
{
	return (long)rq->elv.priv[0];
}
```

### 5.4 完成请求
```c
static void kyber_completed_request(struct request *rq, u64 now)
{
	struct kyber_queue_data *kqd = rq->q->elevator->elevator_data;
	struct kyber_cpu_latency *cpu_latency;
	unsigned int sched_domain;
	u64 target;

	// 获取操作域
	sched_domain = kyber_sched_domain(rq->cmd_flags);
	if (sched_domain == KYBER_OTHER)
		return;

	// 获取当前cpu延迟
	cpu_latency = get_cpu_ptr(kqd->cpu_latency);
	target = kqd->latency_targets[sched_domain];
	// 统计总延迟, start_time_ns是在分配请求时记录的
	add_latency_sample(cpu_latency, sched_domain, KYBER_TOTAL_LATENCY,
			   target, now - rq->start_time_ns);
	// 统计io延迟, io_start_time_ns是底层开始处理请求时记录的
	add_latency_sample(cpu_latency, sched_domain, KYBER_IO_LATENCY, target,
			   now - rq->io_start_time_ns);
	put_cpu_ptr(kqd->cpu_latency);

	// 修改timer
	timer_reduce(&kqd->timer, jiffies + HZ / 10);
}

static void add_latency_sample(struct kyber_cpu_latency *cpu_latency,
			       unsigned int sched_domain, unsigned int type,
			       u64 target, u64 latency)
{
	unsigned int bucket;
	u64 divisor;

	if (latency > 0) {
		// target减少1/4
		divisor = max_t(u64, target >> KYBER_LATENCY_SHIFT, 1);
		// 计算出延迟对应的bucket
		// todo: 这个计算没看懂
		bucket = min_t(unsigned int, div64_u64(latency - 1, divisor),
			       KYBER_LATENCY_BUCKETS - 1);
	} else {
		// 延迟小于0
		bucket = 0;
	}

	// 增加直方图上的计数
	atomic_inc(&cpu_latency->buckets[sched_domain][type][bucket]);
}
```

## 6. 派发

### 6.1. has_work
```c
static bool kyber_has_work(struct blk_mq_hw_ctx *hctx)
{
	struct kyber_hctx_data *khd = hctx->sched_data;
	int i;

	// 遍历各操作域
	for (i = 0; i < KYBER_NUM_DOMAINS; i++) {
		// rqs列表不为空 || map里有设置的位
		if (!list_empty_careful(&khd->rqs[i]) ||
		    sbitmap_any_bit_set(&khd->kcq_map[i]))
			return true;
	}

	return false;
}
```

### 6.2. 派发请求
```c
static struct request *kyber_dispatch_request(struct blk_mq_hw_ctx *hctx)
{
	struct kyber_queue_data *kqd = hctx->queue->elevator->elevator_data;
	struct kyber_hctx_data *khd = hctx->sched_data;
	struct request *rq;
	int i;

	spin_lock(&khd->lock);

	// 批量还没有达到限制
	if (khd->batching < kyber_batch_size[khd->cur_domain]) {
		// 直接派发当前域里的, 返回值表示是否有派发的
		rq = kyber_dispatch_cur_domain(kqd, khd, hctx);
		if (rq)
			goto out;
	}

	/*
	 * 走到这儿有3种情况:
	 * 1. batch达到了限制
	 * 2. batch未达到限制,但是当前域里没请求了
	 * 3. batch未达到限制,但是当前域里没有token了
	 */
	
	// 启动一个新的batch
	khd->batching = 0;

	// 遍历所有调度域
	for (i = 0; i < KYBER_NUM_DOMAINS; i++) {
		if (khd->cur_domain == KYBER_NUM_DOMAINS - 1)
			// 如果域是最后一个那从头开始
			khd->cur_domain = 0;
		else
			// 递增一个域
			khd->cur_domain++;

		rq = kyber_dispatch_cur_domain(kqd, khd, hctx);
		if (rq)
			goto out;
	}

	rq = NULL;
out:
	spin_unlock(&khd->lock);
	return rq;
}

static struct request *
kyber_dispatch_cur_domain(struct kyber_queue_data *kqd,
			  struct kyber_hctx_data *khd,
			  struct blk_mq_hw_ctx *hctx)
{
	struct list_head *rqs;
	struct request *rq;
	int nr;

	// 当前域的请求列表
	rqs = &khd->rqs[khd->cur_domain];

	// 取一个请求
	rq = list_first_entry_or_null(rqs, struct request, queuelist);
	if (rq) {
		// 获取请求成功

		// 获取一个token
		nr = kyber_get_domain_token(kqd, khd, hctx);
		if (nr >= 0) {
			// 获取token成功

			// 递增batch
			khd->batching++;
			// 设置token
			rq_set_domain_token(rq, nr);
			// 从列表里删除请求
			list_del_init(&rq->queuelist);
			return rq;
		} else {
			// 获取token失败,不做操作

			trace_kyber_throttled(kqd->q,
					      kyber_domain_names[khd->cur_domain]);
		}
	

	// rqs获取请求失败

	// 检查位图里有没有设置的位
	} else if (sbitmap_any_bit_set(&khd->kcq_map[khd->cur_domain])) {

		// 获取token
		nr = kyber_get_domain_token(kqd, khd, hctx);
		if (nr >= 0) {
			kyber_flush_busy_kcqs(khd, khd->cur_domain, rqs);

			// 
			rq = list_first_entry(rqs, struct request, queuelist);

			// 下面的处理同上
			khd->batching++;
			rq_set_domain_token(rq, nr);
			list_del_init(&rq->queuelist);
			return rq;
		} else {
			trace_kyber_throttled(kqd->q,
					      kyber_domain_names[khd->cur_domain]);
		}
	}

	/* There were either no pending requests or no tokens. */
	return NULL;
}

static int kyber_get_domain_token(struct kyber_queue_data *kqd,
				  struct kyber_hctx_data *khd,
				  struct blk_mq_hw_ctx *hctx)
{
	unsigned int sched_domain = khd->cur_domain;
	// 操作域的token
	struct sbitmap_queue *domain_tokens = &kqd->domain_tokens[sched_domain];
	struct sbq_wait *wait = &khd->domain_wait[sched_domain];
	struct sbq_wait_state *ws;
	int nr;

	// 获取一个token
	nr = __sbitmap_queue_get(domain_tokens);

	// 获取失败, 等待...
	if (nr < 0 && list_empty_careful(&wait->wait.entry)) {
		// 获取一个等待状态
		ws = sbq_wait_ptr(domain_tokens,
				  &khd->wait_index[sched_domain]);
		khd->domain_ws[sched_domain] = ws;
		// 开始等待
		sbitmap_add_wait_queue(domain_tokens, ws, wait);

		// 等完了再获取一次
		nr = __sbitmap_queue_get(domain_tokens);
	}


	// 如果获取成功,删除wait的等待??
	if (nr >= 0 && !list_empty_careful(&wait->wait.entry)) {
		ws = khd->domain_ws[sched_domain];
		spin_lock_irq(&ws->wait.lock);
		sbitmap_del_wait_queue(wait);
		spin_unlock_irq(&ws->wait.lock);
	}

	return nr;
}



static void kyber_flush_busy_kcqs(struct kyber_hctx_data *khd,
				  unsigned int sched_domain,
				  struct list_head *list)
{
	struct flush_kcq_data data = {
		.khd = khd,
		.sched_domain = sched_domain,
		.list = list,
	};

	// 遍历设置的位
	sbitmap_for_each_set(&khd->kcq_map[sched_domain],
			     flush_busy_kcq, &data);
}

static bool flush_busy_kcq(struct sbitmap *sb, unsigned int bitnr, void *data)
{
	struct flush_kcq_data *flush_data = data;
	// 对应的cqs
	struct kyber_ctx_queue *kcq = &flush_data->khd->kcqs[bitnr];

	spin_lock(&kcq->lock);
	// 把软队列里的加到list里, 这个list引用的是khd->rqs[khd->cur_domain], 所以
	// 这里直接从cqs里移到khd列表里
	list_splice_tail_init(&kcq->rq_list[flush_data->sched_domain],
			      flush_data->list);
	// 清除对应的位
	sbitmap_clear_bit(sb, bitnr);
	spin_unlock(&kcq->lock);

	return true;
}
```

## 7. 限制队列深度
```c
static void kyber_limit_depth(unsigned int op, struct blk_mq_alloc_data *data)
{
	// 限制异步请求
	if (!op_is_sync(op)) {
		// 设置异步深度
		struct kyber_queue_data *kqd = data->q->elevator->elevator_data;

		data->shallow_depth = kqd->async_depth;
	}
}
```

## 8. timer处理
```c
static void kyber_timer_fn(struct timer_list *t)
{
	struct kyber_queue_data *kqd = from_timer(kqd, t, timer);
	unsigned int sched_domain;
	int cpu;
	bool bad = false;

	// 统计所有的percpu延迟
	for_each_online_cpu(cpu) {
		struct kyber_cpu_latency *cpu_latency;

		// cpu延迟
		cpu_latency = per_cpu_ptr(kqd->cpu_latency, cpu);

		// 遍历每个调度域,刷出延迟
		for (sched_domain = 0; sched_domain < KYBER_OTHER; sched_domain++) {
			flush_latency_buckets(kqd, cpu_latency, sched_domain,
					      KYBER_TOTAL_LATENCY);
			flush_latency_buckets(kqd, cpu_latency, sched_domain,
					      KYBER_IO_LATENCY);
		}
	}

	/*
	 * Check if any domains have a high I/O latency, which might indicate
	 * congestion in the device. Note that we use the p90; we don't want to
	 * be too sensitive to outliers here.
	 */
	for (sched_domain = 0; sched_domain < KYBER_OTHER; sched_domain++) {
		int p90;

		// 计算延迟超过90％的？
		p90 = calculate_percentile(kqd, sched_domain, KYBER_IO_LATENCY,
					   90);
		// 超过了好的延迟
		if (p90 >= KYBER_GOOD_BUCKETS)
			bad = true;
	}

	// 调整调度域的深度
	for (sched_domain = 0; sched_domain < KYBER_OTHER; sched_domain++) {
		unsigned int orig_depth, depth;
		int p99;

		// 计算99%的超时？
		p99 = calculate_percentile(kqd, sched_domain,
					   KYBER_TOTAL_LATENCY, 99);
		// 设置？
		if (bad) {
			if (p99 < 0)
				p99 = kqd->domain_p99[sched_domain];
			kqd->domain_p99[sched_domain] = -1;
		} else if (p99 >= 0) {
			kqd->domain_p99[sched_domain] = p99;
		}
		// 没有超过延迟
		if (p99 < 0)
			continue;

		/*
		 * If this domain has bad latency, throttle less. Otherwise,
		 * throttle more iff we determined that there is congestion.
		 *
		 * The new depth is scaled linearly with the p99 latency vs the
		 * latency target. E.g., if the p99 is 3/4 of the target, then
		 * we throttle down to 3/4 of the current depth, and if the p99
		 * is 2x the target, then we double the depth.
		 */
		// 延迟太大，重新计算操作域的深度
		if (bad || p99 >= KYBER_GOOD_BUCKETS) {
			orig_depth = kqd->domain_tokens[sched_domain].sb.depth;
			depth = (orig_depth * (p99 + 1)) >> KYBER_LATENCY_SHIFT;
			kyber_resize_domain(kqd, sched_domain, depth);
		}
	}
}

static void flush_latency_buckets(struct kyber_queue_data *kqd,
				  struct kyber_cpu_latency *cpu_latency,
				  unsigned int sched_domain, unsigned int type)
{
	// 总的buckets
	unsigned int *buckets = kqd->latency_buckets[sched_domain][type];
	// percpu buckets
	atomic_t *cpu_buckets = cpu_latency->buckets[sched_domain][type];
	unsigned int bucket;

	// 把所有percpu的统计放到总的统计里,并把percpu清0
	for (bucket = 0; bucket < KYBER_LATENCY_BUCKETS; bucket++)
		buckets[bucket] += atomic_xchg(&cpu_buckets[bucket], 0);
}

static int calculate_percentile(struct kyber_queue_data *kqd,
				unsigned int sched_domain, unsigned int type,
				unsigned int percentile)
{
	unsigned int *buckets = kqd->latency_buckets[sched_domain][type];
	unsigned int bucket, samples = 0, percentile_samples;

	// 计算bucket里的总延迟
	for (bucket = 0; bucket < KYBER_LATENCY_BUCKETS; bucket++)
		samples += buckets[bucket];

	// 延迟为0
	if (!samples)
		return -1;

	// 重置延迟时间
	if (!kqd->latency_timeout[sched_domain])
		kqd->latency_timeout[sched_domain] = max(jiffies + HZ, 1UL);
	// 还没到达超时时间
	if (samples < 500 &&
	    time_is_after_jiffies(kqd->latency_timeout[sched_domain])) {
		return -1;
	}

	// 走到这儿，表示已经超时？

	// 重置超时时间
	kqd->latency_timeout[sched_domain] = 0;

	// 延迟采样
	percentile_samples = DIV_ROUND_UP(samples * percentile, 100);
	// 遍历bucket
	for (bucket = 0; bucket < KYBER_LATENCY_BUCKETS - 1; bucket++) {
		// ?
		if (buckets[bucket] >= percentile_samples)
			break;
		// 减去采样
		percentile_samples -= buckets[bucket];
	}
	// 设置buckets为0
	memset(buckets, 0, sizeof(kqd->latency_buckets[sched_domain][type]));

	trace_kyber_latency(kqd->q, kyber_domain_names[sched_domain],
			    kyber_latency_type_names[type], percentile,
			    bucket + 1, 1 << KYBER_LATENCY_SHIFT, samples);

	// 返回延迟超时的bucket
	return bucket;
}

static void kyber_resize_domain(struct kyber_queue_data *kqd,
				unsigned int sched_domain, unsigned int depth)
{
	depth = clamp(depth, 1U, kyber_depth[sched_domain]);

	// 不等于当前队列深度
	if (depth != kqd->domain_tokens[sched_domain].sb.depth) {
		// 重新设置域深度
		sbitmap_queue_resize(&kqd->domain_tokens[sched_domain], depth);
		trace_kyber_adjust(kqd->q, kyber_domain_names[sched_domain],
				   depth);
	}
}

```