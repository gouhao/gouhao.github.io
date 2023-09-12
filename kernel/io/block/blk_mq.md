# blk_mq
源码基于5.10

## blk_mq_alloc_tag_set
```c
int blk_mq_alloc_tag_set(struct blk_mq_tag_set *set)
{
	int i, ret;

	// BLK_MQ_MAX_DEPTH = 10240
	// BLK_MQ_UNIQUE_TAG_BITS = 16
	// 最大深度肯定不能比tag的数量多
	BUILD_BUG_ON(BLK_MQ_MAX_DEPTH > 1 << BLK_MQ_UNIQUE_TAG_BITS);

	// 合法性检查
	if (!set->nr_hw_queues)
		return -EINVAL;
	if (!set->queue_depth)
		return -EINVAL;
	// BLK_MQ_TAG_MIN = 1, 队列深度不能小于最小值+保留值，也就是最小深度为1
	if (set->queue_depth < set->reserved_tags + BLK_MQ_TAG_MIN)
		return -EINVAL;

	// 必须要有入队的函数
	if (!set->ops->queue_rq)
		return -EINVAL;

	// 这2个函数要么都有，要么都没有。
	if (!set->ops->get_budget ^ !set->ops->put_budget)
		return -EINVAL;

	// 队列深度太大，BLK_MQ_MAX_DEPTH = 10240
	if (set->queue_depth > BLK_MQ_MAX_DEPTH) {
		pr_info("blk-mq: reduced tag depth to %u\n",
			BLK_MQ_MAX_DEPTH);
		set->queue_depth = BLK_MQ_MAX_DEPTH;
	}

	// map数组的长度
	if (!set->nr_maps)
		set->nr_maps = 1;
	else if (set->nr_maps > HCTX_MAX_TYPES)
		return -EINVAL;

	/*
	 * If a crashdump is active, then we are potentially in a very
	 * memory constrained environment. Limit us to 1 queue and
	 * 64 tags to prevent using too much memory.
	 * 如果crashdump活跃，我们可能在一个内存受限的环境。限制队列深度为1,最多64个tag
	 * 以防止使用太多的内存
	 */
	if (is_kdump_kernel()) {
		set->nr_hw_queues = 1;
		set->nr_maps = 1;
		set->queue_depth = min(64U, set->queue_depth);
	}
	/*
	 * 如果只有一个map，超过cpu数量的hw_queues是没用的
	 */
	if (set->nr_maps == 1 && set->nr_hw_queues > nr_cpu_ids)
		set->nr_hw_queues = nr_cpu_ids;

	// 分配tags
	if (blk_mq_realloc_tag_set_tags(set, 0, set->nr_hw_queues) < 0)
		return -ENOMEM;

	ret = -ENOMEM;
	// 分配mq_map
	for (i = 0; i < set->nr_maps; i++) {
		// 这里给mq_map分配了nr_cpu_ids个元素
		set->map[i].mq_map = kcalloc_node(nr_cpu_ids,
						  sizeof(set->map[i].mq_map[0]),
						  GFP_KERNEL, set->numa_node);
		if (!set->map[i].mq_map)
			goto out_free_mq_map;
		// map映射到hw的数量就是硬件队列的数量
		set->map[i].nr_queues = is_kdump_kernel() ? 1 : set->nr_hw_queues;
	}

	// cpu映射 hw queue 的下标
	ret = blk_mq_update_queue_map(set);
	if (ret)
		goto out_free_mq_map;

	// 分配队列及静态的请求
	ret = blk_mq_alloc_map_and_requests(set);
	if (ret)
		goto out_free_mq_map;

	// 所有队列共享host的bitmap
	if (blk_mq_is_sbitmap_shared(set->flags)) {
		// 设置共享队列数
		atomic_set(&set->active_queues_shared_sbitmap, 0);

		// 初始化共享的位图以及让hwq的queue指向他
		if (blk_mq_init_shared_sbitmap(set, set->flags)) {
			ret = -ENOMEM;
			goto out_free_mq_rq_maps;
		}
	}

	mutex_init(&set->tag_list_lock);
	INIT_LIST_HEAD(&set->tag_list);

	return 0;

out_free_mq_rq_maps:
	for (i = 0; i < set->nr_hw_queues; i++)
		blk_mq_free_map_and_requests(set, i);
out_free_mq_map:
	for (i = 0; i < set->nr_maps; i++) {
		kfree(set->map[i].mq_map);
		set->map[i].mq_map = NULL;
	}
	kfree(set->tags);
	set->tags = NULL;
	return ret;
}

int blk_mq_init_shared_sbitmap(struct blk_mq_tag_set *set, unsigned int flags)
{
	// 请求的数量
	unsigned int depth = set->queue_depth - set->reserved_tags;
	// 分配策略
	int alloc_policy = BLK_MQ_FLAG_TO_ALLOC_POLICY(set->flags);
	bool round_robin = alloc_policy == BLK_TAG_ALLOC_RR;
	int i, node = set->numa_node;

	// 分配普通tag位图
	if (bt_alloc(&set->__bitmap_tags, depth, round_robin, node))
		return -ENOMEM;
	// 分配保留位图
	if (bt_alloc(&set->__breserved_tags, set->reserved_tags,
		     round_robin, node))
		goto free_bitmap_tags;

	// 遍历tag里的每个hwq
	for (i = 0; i < set->nr_hw_queues; i++) {
		struct blk_mq_tags *tags = set->tags[i];

		// 让他的bitmap指向host的bitmap
		tags->bitmap_tags = &set->__bitmap_tags;
		tags->breserved_tags = &set->__breserved_tags;
	}

	return 0;
free_bitmap_tags:
	sbitmap_queue_free(&set->__bitmap_tags);
	return -ENOMEM;
}
```
### blk_mq_realloc_tag_set_tags
```c
// cur_nr_hw_queues: 当前值；new_nr_hw_queues：新值
static int blk_mq_realloc_tag_set_tags(struct blk_mq_tag_set *set,
				  int cur_nr_hw_queues, int new_nr_hw_queues)
{
	struct blk_mq_tags **new_tags;

	// 比新的队列多，当然不用分配了
	if (cur_nr_hw_queues >= new_nr_hw_queues)
		return 0;

	// 分配new_nr_hw_queues个tags
	new_tags = kcalloc_node(new_nr_hw_queues, sizeof(struct blk_mq_tags *),
				GFP_KERNEL, set->numa_node);
	if (!new_tags)
		return -ENOMEM;

	// 如果之前set->tags里有值的话，复制到新的tags里
	if (set->tags)
		memcpy(new_tags, set->tags, cur_nr_hw_queues *
		       sizeof(*set->tags));
	// 释放老的
	kfree(set->tags);
	// 设置新值
	set->tags = new_tags;
	set->nr_hw_queues = new_nr_hw_queues;

	return 0;
}
```
## blk_mq_update_queue_map
```c 
static int blk_mq_update_queue_map(struct blk_mq_tag_set *set)
{
	// 只有1个映射，则设置nr_hw_queues，HCTX_TYPE_DEFAULT是第0个元素
	// 这在前面不是设置过了吗？为啥又要设置一遍？
	if (set->nr_maps == 1)
		set->map[HCTX_TYPE_DEFAULT].nr_queues = set->nr_hw_queues;

	// 有map_queues函数 && 不是kdump
	if (set->ops->map_queues && !is_kdump_kernel()) {
		int i;
		// 映射前先清空
		for (i = 0; i < set->nr_maps; i++)
			blk_mq_clear_mq_map(&set->map[i]);

		return set->ops->map_queues(set);
	} else {
		// 这种情况下只能有一个map
		// 多于一个队列的驱动必须要实现map_queues？
		BUG_ON(set->nr_maps > 1);
		// 只初始化默认的
		return blk_mq_map_queues(&set->map[HCTX_TYPE_DEFAULT]);
	}
}

int blk_mq_map_queues(struct blk_mq_queue_map *qmap)
{
	unsigned int *map = qmap->mq_map;
	// 队列数量
	unsigned int nr_queues = qmap->nr_queues;
	unsigned int cpu, first_sibling, q = 0;

	// 每个cpu先设为-1
	for_each_possible_cpu(cpu)
		map[cpu] = -1;

	// 遍历每个在位的cpu，每个cpu映射一个队列
	for_each_present_cpu(cpu) {
		// 超过了队列的数量就不用映射了
		if (q >= nr_queues)
			break;
		// 计算cpu对应的queue下标, queue_index = qmap->queue_offset + (q % nr_queues);
		map[cpu] = queue_index(qmap, nr_queues, q++);
	}

	// 遍历所有可能的cpu（这些cpu有可能不在线）
	// 一种可能是：如果nr_queues < cpu, 则有的cpu没有映射，所以这个循环处理这些cpu
	for_each_possible_cpu(cpu) {
		// 已经映射过了
		if (map[cpu] != -1)
			continue;

		if (q < nr_queues) {
			// 请求队列比cpu多

			// 还没有达到队列最大值，则继续顺序映射
			map[cpu] = queue_index(qmap, nr_queues, q++);
		} else {
			// cpu比请求队列多

			// 已经超过了队列数量，但是还有cpu未映射，也就是说多个cpu会映射同一队列

			// 获取它的兄弟cpu
			// get_first_sibling如果找到了则返回找到的值，否则返回cpu的值
			first_sibling = get_first_sibling(cpu);
			if (first_sibling == cpu)
				// 如果它没有兄弟结点，则继续向前映射。
				// queue_index是循环的，如果达到了最大值，会从头开始
				map[cpu] = queue_index(qmap, nr_queues, q++);
			else
				// 直接设置兄弟结点的映射
				// todo: 如果first_sibling没有映射呢？岂不是设置的还是-1?
				map[cpu] = map[first_sibling];
		}
	}

	return 0;
}

static int queue_index(struct blk_mq_queue_map *qmap,
		       unsigned int nr_queues, const int q)
{
	// 第一个映射的hw下标
	return qmap->queue_offset + (q % nr_queues);
}
```
### blk_mq_alloc_map_and_requests
```c
static int blk_mq_alloc_map_and_requests(struct blk_mq_tag_set *set)
{
	unsigned int depth;
	int err;

	// 队列深度
	depth = set->queue_depth;
	do {
		// 给每个hctx分配请求队列及静态请求
		err = __blk_mq_alloc_rq_maps(set);

		// 分配成功则退出
		if (!err)
			break;

		// 分配失败，说明内存不够了，队列深度减少一半
		set->queue_depth >>= 1;
		// 减少之后，不能符合最小要求，则直接退出
		if (set->queue_depth < set->reserved_tags + BLK_MQ_TAG_MIN) {
			err = -ENOMEM;
			break;
		}
	} while (set->queue_depth);

	// 深度为0,表示分配失败
	if (!set->queue_depth || err) {
		pr_err("blk-mq: failed to allocate request map\n");
		return -ENOMEM;
	}

	// 深度和刚开始的深度不一样了
	if (depth != set->queue_depth)
		pr_info("blk-mq: reduced tag depth (%u -> %u)\n",
						depth, set->queue_depth);

	return 0;
}

static int __blk_mq_alloc_rq_maps(struct blk_mq_tag_set *set)
{
	int i;

	for (i = 0; i < set->nr_hw_queues; i++) {
		// 给每个hw_queue分配请求队列对应的内存
		if (!__blk_mq_alloc_map_and_request(set, i))
			goto out_unwind;
		// 让出cpu
		cond_resched();
	}

	return 0;

out_unwind:
	while (--i >= 0)
		blk_mq_free_map_and_requests(set, i);

	return -ENOMEM;
}

static bool __blk_mq_alloc_map_and_request(struct blk_mq_tag_set *set,
					int hctx_idx)
{
	unsigned int flags = set->flags;
	int ret = 0;

	// 分配tags和tags的请求队列，并初始化
	set->tags[hctx_idx] = blk_mq_alloc_rq_map(set, hctx_idx,
					set->queue_depth, set->reserved_tags, flags);
	// 分配失败
	if (!set->tags[hctx_idx])
		return false;

	// 分配静态队列请求的内存，并初始化各个请求，分配请求的数量是queue_depth
	ret = blk_mq_alloc_rqs(set, set->tags[hctx_idx], hctx_idx,
				set->queue_depth);
	if (!ret)
		// 分配成功
		return true;

	// 走到这里是分配失败，分配失败之后释放刚才可能分配的，并设置tags为空
	blk_mq_free_rq_map(set->tags[hctx_idx], flags);
	set->tags[hctx_idx] = NULL;
	return false;
}

```

### blk_mq_alloc_rq_map
```c
// nr_tags就是队列深度
struct blk_mq_tags *blk_mq_alloc_rq_map(struct blk_mq_tag_set *set,
					unsigned int hctx_idx,
					unsigned int nr_tags,
					unsigned int reserved_tags,
					unsigned int flags)
{
	struct blk_mq_tags *tags;
	int node;

	// 把hctx_id转换成映射之后的cpu对应的nodeid
	node = blk_mq_hw_queue_to_node(&set->map[HCTX_TYPE_DEFAULT], hctx_idx);

	// 返回NUMA_NO_NODE表示该下标没有映射，没有映射就使用set的node
	if (node == NUMA_NO_NODE)
		node = set->numa_node;

	// 分配并初始化tags
	tags = blk_mq_init_tags(nr_tags, reserved_tags, node, flags);
	if (!tags)
		return NULL;

	// 分配nr_tags个请求指针
	tags->rqs = kcalloc_node(nr_tags, sizeof(struct request *),
				 GFP_NOIO | __GFP_NOWARN | __GFP_NORETRY,
				 node);
	if (!tags->rqs) {
		blk_mq_free_tags(tags, flags);
		return NULL;
	}

	// 分配nr_tags个静态的请求指针
	tags->static_rqs = kcalloc_node(nr_tags, sizeof(struct request *),
					GFP_NOIO | __GFP_NOWARN | __GFP_NORETRY,
					node);
	if (!tags->static_rqs) {
		kfree(tags->rqs);
		blk_mq_free_tags(tags, flags);
		return NULL;
	}

	return tags;
}

int blk_mq_hw_queue_to_node(struct blk_mq_queue_map *qmap, unsigned int index)
{
	int i;

	// 找到映射的cpu后，返回cpu对应的node
	for_each_possible_cpu(i) {
		if (index == qmap->mq_map[i])
			return cpu_to_node(i);
	}

	return NUMA_NO_NODE;
}

struct blk_mq_tags *blk_mq_init_tags(unsigned int total_tags,
				     unsigned int reserved_tags,
				     int node, unsigned int flags)
{
	// 获取flags里的分配策略
	int alloc_policy = BLK_MQ_FLAG_TO_ALLOC_POLICY(flags);
	struct blk_mq_tags *tags;

	// BLK_MQ_TAG_MAX是unsigned的最大值
	if (total_tags > BLK_MQ_TAG_MAX) {
		pr_err("blk-mq: tag depth too large\n");
		return NULL;
	}

	// 分配tags
	tags = kzalloc_node(sizeof(*tags), GFP_KERNEL, node);
	if (!tags)
		return NULL;

	// 初始化字段
	tags->nr_tags = total_tags;
	tags->nr_reserved_tags = reserved_tags;
	spin_lock_init(&tags->lock);

	// 共享host的tag，则直接返回
	if (flags & BLK_MQ_F_TAG_HCTX_SHARED)
		return tags;

	// 初始化自己的tag的bitmap
	if (blk_mq_init_bitmap_tags(tags, node, alloc_policy) < 0) {
		kfree(tags);
		return NULL;
	}
	return tags;
}

static int blk_mq_init_bitmap_tags(struct blk_mq_tags *tags,
				   int node, int alloc_policy)
{
	// 非保留的tag长度
	unsigned int depth = tags->nr_tags - tags->nr_reserved_tags;
	// 从上次分配的开始
	bool round_robin = alloc_policy == BLK_TAG_ALLOC_RR;

	// 初始化__bitmap_tags，这是个sbitmap
	if (bt_alloc(&tags->__bitmap_tags, depth, round_robin, node))
		return -ENOMEM;
	// 初始化保留的bitmap
	if (bt_alloc(&tags->__breserved_tags, tags->nr_reserved_tags,
		     round_robin, node))
		goto free_bitmap_tags;

	// 让另外2个tag指向对应的值
	tags->bitmap_tags = &tags->__bitmap_tags;
	tags->breserved_tags = &tags->__breserved_tags;

	return 0;
free_bitmap_tags:
	sbitmap_queue_free(&tags->__bitmap_tags);
	return -ENOMEM;
}
```

### blk_mq_alloc_rqs
```c
int blk_mq_alloc_rqs(struct blk_mq_tag_set *set, struct blk_mq_tags *tags,
		     unsigned int hctx_idx, unsigned int depth)
{
	unsigned int i, j, entries_per_page, max_order = 4;
	size_t rq_size, left;
	int node;

	// 获取映射的cpu对应的node
	node = blk_mq_hw_queue_to_node(&set->map[HCTX_TYPE_DEFAULT], hctx_idx);
	if (node == NUMA_NO_NODE)
		node = set->numa_node;

	// 初始化页面列表。这个是存放请求对应的内存
	INIT_LIST_HEAD(&tags->page_list);

	// 每个请求的大小以缓冲行对齐，并且末尾要加上cmd的长度？
	rq_size = round_up(sizeof(struct request) + set->cmd_size,
				cache_line_size());
	// 总共需要的长度，depth就是tag数
	left = rq_size * depth;

	// 分配depth个请求
	for (i = 0; i < depth; ) {
		int this_order = max_order;
		struct page *page;
		int to_do;
		void *p;

		// 计算所需的最小order，order_to_size是这个order对应的内存大小
		while (this_order && left < order_to_size(this_order - 1))
			this_order--;

		do {
			// 分配对应的页面
			page = alloc_pages_node(node,
				GFP_NOIO | __GFP_NOWARN | __GFP_NORETRY | __GFP_ZERO,
				this_order);
			// 分配到了page直接退出
			if (page)
				break;
			
			// 走到这儿是分配页面失败

			// 减小order
			if (!this_order--)
				break;

			// 如果order比rq_size还小，则退出。连1个请求都装不下，分配它还有什么用
			if (order_to_size(this_order) < rq_size)
				break;
		} while (1);

		// 分配失败
		if (!page)
			goto fail;

		// private里保存order信息
		page->private = this_order;
		// 添加到page列表里
		list_add_tail(&page->lru, &tags->page_list);

		// 页面地址
		p = page_address(page);
		// todo: kmemleak：后面再看
		kmemleak_alloc(p, order_to_size(this_order), 1, GFP_NOIO);
		// 每个页面多少个请求
		entries_per_page = order_to_size(this_order) / rq_size;
		// 每个页面的请求数，和请求数量的最小值，做为最终请求数量
		to_do = min(entries_per_page, depth - i);
		// 剩余的空间
		left -= to_do * rq_size;

		// 先给静态队列里分配内存
		for (j = 0; j < to_do; j++) {
			struct request *rq = p;

			tags->static_rqs[i] = rq;
			if (blk_mq_init_request(set, rq, hctx_idx, node)) {
				tags->static_rqs[i] = NULL;
				goto fail;
			}

			// 地址增加请求的长度，这里不能使用 p++, 因为　p++ 只是request的长度，
			// 真正的请求后面还有cmd_size
			p += rq_size;
			
			// 注意这里是i++，是外层depth的计数
			i++;
		}
	}
	return 0;

fail:
	blk_mq_free_rqs(set, tags, hctx_idx);
	return -ENOMEM;
}

static int blk_mq_init_request(struct blk_mq_tag_set *set, struct request *rq,
			       unsigned int hctx_idx, int node)
{
	int ret;

	// 调用底层驱动的初始化函数
	if (set->ops->init_request) {
		ret = set->ops->init_request(set, rq, hctx_idx, node);
		if (ret)
			return ret;
	}

	// 设置请求状态为空闲
	WRITE_ONCE(rq->state, MQ_RQ_IDLE);
	return 0;
}
```

## blk_mq_init_queue
```c
struct request_queue *blk_mq_init_queue(struct blk_mq_tag_set *set)
{
	return blk_mq_init_queue_data(set, NULL);
}

struct request_queue *blk_mq_init_queue_data(struct blk_mq_tag_set *set,
		void *queuedata)
{
	struct request_queue *uninit_q, *q;

	// 创建rq，这里面主要是分配一个rq对象，然后对其做一些基本初始化的工作
	uninit_q = blk_alloc_queue(set->numa_node);
	if (!uninit_q)
		return ERR_PTR(-ENOMEM);
	uninit_q->queuedata = queuedata;

	// 初始化的核心，里面会对tag，映射之类的做初始化
	q = blk_mq_init_allocated_queue(set, uninit_q, false);
	if (IS_ERR(q))
		blk_cleanup_queue(uninit_q);

	return q;
}

struct request_queue *blk_alloc_queue(int node_id)
{
	struct request_queue *q;
	int ret;

	// 分配队列，并清0
	q = kmem_cache_alloc_node(blk_requestq_cachep,
				GFP_KERNEL | __GFP_ZERO, node_id);
	if (!q)
		return NULL;

	q->last_merge = NULL;

	// 分配一个id
	q->id = ida_simple_get(&blk_queue_ida, 0, 0, GFP_KERNEL);
	if (q->id < 0)
		goto fail_q;

	// 初始化bio集，BIO_POOL_SIZE=2。主要分配bio_set_slab，mempool，及紧急队列
	ret = bioset_init(&q->bio_split, BIO_POOL_SIZE, 0, BIOSET_NEED_BVECS);
	if (ret)
		goto fail_id;

	// 分配一个bdi,bdi是fs里面用的
	q->backing_dev_info = bdi_alloc(node_id);
	if (!q->backing_dev_info)
		goto fail_split;

	// stats是一个统计状态相关的数据结构
	q->stats = blk_alloc_queue_stats();
	if (!q->stats)
		goto fail_stats;

	q->node = node_id;

	// 活跃共享位图
	atomic_set(&q->nr_active_requests_shared_sbitmap, 0);

	// 笔记本电脑用的timer
	timer_setup(&q->backing_dev_info->laptop_mode_wb_timer,
		    laptop_mode_timer_fn, 0);
	// 超时函数
	timer_setup(&q->timeout, blk_rq_timed_out_timer, 0);
	// 默认的超时工作函数
	INIT_WORK(&q->timeout_work, blk_timeout_work);

	INIT_LIST_HEAD(&q->icq_list);
#ifdef CONFIG_BLK_CGROUP
	INIT_LIST_HEAD(&q->blkg_list);
#endif

	// 初始化为blk_queue类型
	kobject_init(&q->kobj, &blk_queue_ktype);

	// 初始化各种锁
	mutex_init(&q->debugfs_mutex);
	mutex_init(&q->sysfs_lock);
	mutex_init(&q->sysfs_dir_lock);
	spin_lock_init(&q->queue_lock);

	init_waitqueue_head(&q->mq_freeze_wq);
	mutex_init(&q->mq_freeze_lock);

	// 初始化q_usage_counter
	if (percpu_ref_init(&q->q_usage_counter,
				blk_queue_usage_counter_release,
				PERCPU_REF_INIT_ATOMIC, GFP_KERNEL))
		goto fail_bdi;

	// blkcg的队列初始化
	if (blkcg_init_queue(q))
		goto fail_ref;

	// q->dma_alignment = 511;
	blk_queue_dma_alignment(q, 511);
	// 设置默认的限制值
	blk_set_default_limits(&q->limits);
	// 最大请求数，BLKDEV_MAX_RQ = 128
	q->nr_requests = BLKDEV_MAX_RQ;

	return q;

fail_ref:
	percpu_ref_exit(&q->q_usage_counter);
fail_bdi:
	blk_free_queue_stats(q->stats);
fail_stats:
	bdi_put(q->backing_dev_info);
fail_split:
	bioset_exit(&q->bio_split);
fail_id:
	ida_simple_remove(&blk_queue_ida, q->id);
fail_q:
	kmem_cache_free(blk_requestq_cachep, q);
	return NULL;
}

int bioset_init(struct bio_set *bs,
		unsigned int pool_size,
		unsigned int front_pad,
		int flags)
{
	// BIO_INLINE_VECS = 4
	unsigned int back_pad = BIO_INLINE_VECS * sizeof(struct bio_vec);

	bs->front_pad = front_pad;

	spin_lock_init(&bs->rescue_lock);
	bio_list_init(&bs->rescue_list);
	INIT_WORK(&bs->rescue_work, bio_alloc_rescue);

	// 创建bio_slab
	bs->bio_slab = bio_find_or_create_slab(front_pad + back_pad);
	if (!bs->bio_slab)
		return -ENOMEM;

	// 初始化内存池。todo:内存池后面后
	if (mempool_init_slab_pool(&bs->bio_pool, pool_size, bs->bio_slab))
		goto bad;

	// 需要vec，初始化之
	if ((flags & BIOSET_NEED_BVECS) &&
	    biovec_init_pool(&bs->bvec_pool, pool_size))
		goto bad;

	// 不需要紧急队列
	if (!(flags & BIOSET_NEED_RESCUER))
		return 0;

	bs->rescue_workqueue = alloc_workqueue("bioset", WQ_MEM_RECLAIM, 0);
	if (!bs->rescue_workqueue)
		goto bad;

	return 0;
bad:
	bioset_exit(bs);
	return -ENOMEM;
}


static struct kmem_cache *bio_find_or_create_slab(unsigned int extra_size)
{
	unsigned int sz = sizeof(struct bio) + extra_size;
	struct kmem_cache *slab = NULL;
	struct bio_slab *bslab, *new_bio_slabs;
	unsigned int new_bio_slab_max;
	unsigned int i, entry = -1;

	mutex_lock(&bio_slab_lock);

	i = 0;
	while (i < bio_slab_nr) {
		bslab = &bio_slabs[i];

		if (!bslab->slab && entry == -1)
			entry = i;
		else if (bslab->slab_size == sz) {
			slab = bslab->slab;
			bslab->slab_ref++;
			break;
		}
		i++;
	}

	if (slab)
		goto out_unlock;

	if (bio_slab_nr == bio_slab_max && entry == -1) {
		new_bio_slab_max = bio_slab_max << 1;
		new_bio_slabs = krealloc(bio_slabs,
					 new_bio_slab_max * sizeof(struct bio_slab),
					 GFP_KERNEL);
		if (!new_bio_slabs)
			goto out_unlock;
		bio_slab_max = new_bio_slab_max;
		bio_slabs = new_bio_slabs;
	}
	if (entry == -1)
		entry = bio_slab_nr++;

	bslab = &bio_slabs[entry];

	snprintf(bslab->name, sizeof(bslab->name), "bio-%d", entry);
	slab = kmem_cache_create(bslab->name, sz, ARCH_KMALLOC_MINALIGN,
				 SLAB_HWCACHE_ALIGN, NULL);
	if (!slab)
		goto out_unlock;

	bslab->slab = slab;
	bslab->slab_ref = 1;
	bslab->slab_size = sz;
out_unlock:
	mutex_unlock(&bio_slab_lock);
	return slab;
}

{
	struct biovec_slab *bp = bvec_slabs + BVEC_POOL_MAX;

	return mempool_init_slab_pool(pool, pool_entries, bp->slab);
}

struct request_queue *blk_mq_init_allocated_queue(struct blk_mq_tag_set *set,
						  struct request_queue *q,
						  bool elevator_init)
{
	// mq_ops就是set的ops，这个在host初始化时设置
	q->mq_ops = set->ops;

	// poll的回调
	q->poll_cb = blk_stat_alloc_callback(blk_mq_poll_stats_fn,
					     blk_mq_poll_stats_bkt,
					     BLK_MQ_POLL_STATS_BKTS, q);
	if (!q->poll_cb)
		goto err_exit;

	// 分配软件队列
	if (blk_mq_alloc_ctxs(q))
		goto err_poll;

	// sys相关，todo: 后面看
	blk_mq_sysfs_init(q);

	// 未使用hctx列表
	INIT_LIST_HEAD(&q->unused_hctx_list);
	spin_lock_init(&q->unused_hctx_lock);

	// 分配硬件队列，这里面会根据q->nctx和set->nctx的数量来决定是否重新分配或者释放多余的
	blk_mq_realloc_hw_ctxs(set, q);
	// hwq不可能为0，为0就错了
	if (!q->nr_hw_queues)
		goto err_hctxs;

	// mq的超时工作函数
	INIT_WORK(&q->timeout_work, blk_mq_timeout_work);
	// 设置q->rq_timeout
	blk_queue_rq_timeout(q, set->timeout ? set->timeout : 30 * HZ);

	// 队列的tag集合，指向host的set
	q->tag_set = set;

	/*
					// 支持io统计
	#define QUEUE_FLAG_MQ_DEFAULT	((1 << QUEUE_FLAG_IO_STAT) |		\
				// 支持同一cpu group
				 (1 << QUEUE_FLAG_SAME_COMP) |		\
				 // 支持nowait
				 (1 << QUEUE_FLAG_NOWAIT))
	*/
	// 默认标志
	q->queue_flags |= QUEUE_FLAG_MQ_DEFAULT;
	// 如果设备有poll类型的队列映射，则设置QUEUE_FLAG_POLL标志
	if (set->nr_maps > HCTX_TYPE_POLL &&
	    set->map[HCTX_TYPE_POLL].nr_queues)
		blk_queue_flag_set(QUEUE_FLAG_POLL, q);

	// ?
	q->sg_reserved_size = INT_MAX;

	// requeue_work
	INIT_DELAYED_WORK(&q->requeue_work, blk_mq_requeue_work);
	INIT_LIST_HEAD(&q->requeue_list);
	spin_lock_init(&q->requeue_lock);

	// 请求数量就是host的队列深度
	q->nr_requests = set->queue_depth;

	// 经典poll?
	q->poll_nsec = BLK_MQ_POLL_CLASSIC;

	// 初始化queue_ctx
	blk_mq_init_cpu_queues(q, set->nr_hw_queues);
	// 把rq加到tag_set里
	blk_mq_add_queue_tag_set(set, q);
	
	// 映射软硬队列
	blk_mq_map_swqueue(q);

	// 如果有调度器，则调用调度器的初始化
	if (elevator_init)
		elevator_init_mq(q);

	return q;

err_hctxs:
	kfree(q->queue_hw_ctx);
	q->nr_hw_queues = 0;
	blk_mq_sysfs_deinit(q);
err_poll:
	blk_stat_free_callback(q->poll_cb);
	q->poll_cb = NULL;
err_exit:
	q->mq_ops = NULL;
	return ERR_PTR(-ENOMEM);
}

static int blk_mq_alloc_ctxs(struct request_queue *q)
{
	struct blk_mq_ctxs *ctxs;
	int cpu;

	// 分配blk_ma_ctxs对象，注意不是blk_mq_ctx
	ctxs = kzalloc(sizeof(*ctxs), GFP_KERNEL);
	if (!ctxs)
		return -ENOMEM;

	// 分配队列上下文，每个cpu一个
	ctxs->queue_ctx = alloc_percpu(struct blk_mq_ctx);
	if (!ctxs->queue_ctx)
		goto fail;

	// 遍历所有可能存在的cpu，设置每个ctx到ctxs的引用
	for_each_possible_cpu(cpu) {
		struct blk_mq_ctx *ctx = per_cpu_ptr(ctxs->queue_ctx, cpu);
		ctx->ctxs = ctxs;
	}

	q->mq_kobj = &ctxs->kobj;
	// 设置队列的软件上下文
	q->queue_ctx = ctxs->queue_ctx;

	return 0;
 fail:
	kfree(ctxs);
	return -ENOMEM;
}


static void blk_mq_init_cpu_queues(struct request_queue *q,
				   unsigned int nr_hw_queues)
{
	struct blk_mq_tag_set *set = q->tag_set;
	unsigned int i, j;

	// 遍历每个possible cpu
	for_each_possible_cpu(i) {
		// 每个cpu的ctx
		struct blk_mq_ctx *__ctx = per_cpu_ptr(q->queue_ctx, i);
		struct blk_mq_hw_ctx *hctx;
		int k;

		// ctx对应的cpu
		__ctx->cpu = i;
		spin_lock_init(&__ctx->lock);

		// 初始化各种类型对应的list，目前HCTX_MAX_TYPES是3
		for (k = HCTX_TYPE_DEFAULT; k < HCTX_MAX_TYPES; k++)
			INIT_LIST_HEAD(&__ctx->rq_lists[k]);

		// 对应的请求队列
		__ctx->queue = q;

		// 遍历映射的数量，根据需要设置numa
		for (j = 0; j < set->nr_maps; j++) {
			// 找到cpu对应的hctx
			hctx = blk_mq_map_queue_type(q, j, i);
			// 队列数量大于1 && 没有指定的node，则使用cpu对应的node
			if (nr_hw_queues > 1 && hctx->numa_node == NUMA_NO_NODE)
				hctx->numa_node = cpu_to_node(i);
		}
	}
}

static inline struct blk_mq_hw_ctx *blk_mq_map_queue_type(struct request_queue *q,
							  enum hctx_type type,
							  unsigned int cpu)
{
	// 找到cpu映射的hctx
	// q->tag_set->map[type].mq_map[cpu]是cpu映射的hctx的id
	return q->queue_hw_ctx[q->tag_set->map[type].mq_map[cpu]];
}

static void blk_mq_add_queue_tag_set(struct blk_mq_tag_set *set,
				     struct request_queue *q)
{
	mutex_lock(&set->tag_list_lock);

	// tag_list不空 && tag不共享
	if (!list_empty(&set->tag_list) &&
	    !(set->flags & BLK_MQ_F_TAG_QUEUE_SHARED)) {
		// 设置tag共享
		set->flags |= BLK_MQ_F_TAG_QUEUE_SHARED;
		
		// 更新tag里所有队列里的所有hctx的共享标志
		blk_mq_update_tag_set_shared(set, true);
	}
	// 如果set有share标志，则设置q里所有hctx的共享标志
	if (set->flags & BLK_MQ_F_TAG_QUEUE_SHARED)
		queue_set_hctx_shared(q, true);
	
	// 把队列加到set里
	list_add_tail(&q->tag_set_list, &set->tag_list);

	mutex_unlock(&set->tag_list_lock);
}


static void blk_mq_update_tag_set_shared(struct blk_mq_tag_set *set,
					 bool shared)
{
	struct request_queue *q;

	lockdep_assert_held(&set->tag_list_lock);
	// 遍历tag里的每个rq
	list_for_each_entry(q, &set->tag_list, tag_set_list) {
		// 冻住队列，相当于加锁
		blk_mq_freeze_queue(q);
		// 设置共享标志
		queue_set_hctx_shared(q, shared);
		blk_mq_unfreeze_queue(q);
	}
}

static void queue_set_hctx_shared(struct request_queue *q, bool shared)
{
	struct blk_mq_hw_ctx *hctx;
	int i;

	// 遍历每个hctx，然后设置/取消其share_tag
	queue_for_each_hw_ctx(q, hctx, i) {
		if (shared)
			hctx->flags |= BLK_MQ_F_TAG_QUEUE_SHARED;
		else
			hctx->flags &= ~BLK_MQ_F_TAG_QUEUE_SHARED;
	}
}

static void blk_mq_map_swqueue(struct request_queue *q)
{
	unsigned int i, j, hctx_idx;
	struct blk_mq_hw_ctx *hctx;
	struct blk_mq_ctx *ctx;
	
	struct blk_mq_tag_set *set = q->tag_set;

	// 遍历队列里的每个hctx
	queue_for_each_hw_ctx(q, hctx, i) {
		// 清空cpumask
		cpumask_clear(hctx->cpumask);
		// 清空ctx数量
		hctx->nr_ctx = 0;

		hctx->dispatch_from = NULL;
	}

	// 遍历每个possible cpu
	for_each_possible_cpu(i) {
		// cpu对应的软上下文
		ctx = per_cpu_ptr(q->queue_ctx, i);

		// 遍历映射的map
		for (j = 0; j < set->nr_maps; j++) {
			// map里没有队列
			if (!set->map[j].nr_queues) {
				// 把hctx设置为默认的hctx
				ctx->hctxs[j] = blk_mq_map_queue_type(q,
						HCTX_TYPE_DEFAULT, i);
				continue;
			}
			// cpu对应的hctx
			hctx_idx = set->map[j].mq_map[i];
			
			// 如果hctx没有分配tags，则尝试分配
			if (!set->tags[hctx_idx] &&
			    !__blk_mq_alloc_map_and_request(set, hctx_idx)) {
				/*
				 * If tags initialization fail for some hctx,
				 * that hctx won't be brought online.  In this
				 * case, remap the current ctx to hctx[0] which
				 * is guaranteed to always have tags allocated
				 */
				set->map[j].mq_map[i] = 0;
			}

			// 获取cpu映射的hctx
			hctx = blk_mq_map_queue_type(q, j, i);
			// 设置ctx对应的hctx
			ctx->hctxs[j] = hctx;
			// 如果hctx已经被ctx映射了，则继续
			if (cpumask_test_cpu(i, hctx->cpumask))
				continue;

			// 设置hctx已经映射了cpu
			cpumask_set_cpu(i, hctx->cpumask);
			// hctx类型
			hctx->type = j;
			// 软队列的下标？
			ctx->index_hw[hctx->type] = hctx->nr_ctx;
			// hctx到ctx的映射
			hctx->ctxs[hctx->nr_ctx++] = ctx;

			// 超过了当前支持的ctx最大数
			BUG_ON(!hctx->nr_ctx);
		}

		// 遍历每个类型，然后设置到对应的hctx
		for (; j < HCTX_MAX_TYPES; j++)
			ctx->hctxs[j] = blk_mq_map_queue_type(q,
					HCTX_TYPE_DEFAULT, i);
	}

	// 遍历队列里的每个hctx
	queue_for_each_hw_ctx(q, hctx, i) {
		// nr_ctx为0，说明没有ctx映射到它
		if (!hctx->nr_ctx) {
			// 释放分配的tag及请求，除了第一个外
			if (i && set->tags[i])
				blk_mq_free_map_and_requests(set, i);

			hctx->tags = NULL;
			continue;
		}

		// 设置hctx的tags
		hctx->tags = set->tags[i];
		// 怎么会为空？
		WARN_ON(!hctx->tags);

		// 设置真正ctx映射的位图数量
		sbitmap_resize(&hctx->ctx_map, hctx->nr_ctx);

		// 找到第一个cpu
		hctx->next_cpu = blk_mq_first_mapped_cpu(hctx);
		// BLK_MQ_CPU_WORK_BATCH = 8
		hctx->next_cpu_batch = BLK_MQ_CPU_WORK_BATCH;
	}
}

void blk_set_default_limits(struct queue_limits *lim)
{
	// BLK_MAX_SEGMENTS=128
	lim->max_segments = BLK_MAX_SEGMENTS;
	lim->max_discard_segments = 1;
	lim->max_integrity_segments = 0;
	// BLK_SEG_BOUNDARY_MASK=0xFFFFFFFFUL
	lim->seg_boundary_mask = BLK_SEG_BOUNDARY_MASK;
	lim->virt_boundary_mask = 0;
	// BLK_MAX_SEGMENT_SIZE=65536
	lim->max_segment_size = BLK_MAX_SEGMENT_SIZE;
	// BLK_SAFE_MAX_SECTORS=255
	lim->max_sectors = lim->max_hw_sectors = BLK_SAFE_MAX_SECTORS;
	lim->max_dev_sectors = 0;
	lim->chunk_sectors = 0;
	lim->max_write_same_sectors = 0;
	lim->max_write_zeroes_sectors = 0;
	lim->max_zone_append_sectors = 0;
	lim->max_discard_sectors = 0;
	lim->max_hw_discard_sectors = 0;
	lim->discard_granularity = 0;
	lim->discard_alignment = 0;
	lim->discard_misaligned = 0;
	lim->logical_block_size = lim->physical_block_size = lim->io_min = 512;
	lim->bounce_pfn = (unsigned long)(BLK_BOUNCE_ANY >> PAGE_SHIFT);
	lim->alignment_offset = 0;
	lim->io_opt = 0;
	lim->misaligned = 0;
	lim->zoned = BLK_ZONED_NONE;
}
```

## 硬上下文的分配及初始化
```c
static void blk_mq_realloc_hw_ctxs(struct blk_mq_tag_set *set,
						struct request_queue *q)
{
	int i, j, end;
	// 老的hctxs
	struct blk_mq_hw_ctx **hctxs = q->queue_hw_ctx;

	// 如果队列的hwq比set的hwq小
	if (q->nr_hw_queues < set->nr_hw_queues) {
		struct blk_mq_hw_ctx **new_hctxs;

		// 分配set->nr_hw_queues个新的hctx
		new_hctxs = kcalloc_node(set->nr_hw_queues,
				       sizeof(*new_hctxs), GFP_KERNEL,
				       set->numa_node);
		if (!new_hctxs)
			return;

		// 若本来就有值，先把以前的复制过去
		if (hctxs)
			memcpy(new_hctxs, hctxs, q->nr_hw_queues *
			       sizeof(*hctxs));
		// 设置新值
		q->queue_hw_ctx = new_hctxs;
		// 释放老值
		kfree(hctxs);
		hctxs = new_hctxs;
	}

	/* protect against switching io scheduler  */
	mutex_lock(&q->sysfs_lock);
	for (i = 0; i < set->nr_hw_queues; i++) {
		int node;
		struct blk_mq_hw_ctx *hctx;

		// 找出当前hwq映射到的cpu
		node = blk_mq_hw_queue_to_node(&set->map[HCTX_TYPE_DEFAULT], i);
		
		// 如果之前有值，而且映射的numa相同，不继续
		if (hctxs[i] && (hctxs[i]->numa_node == node))
			continue;

		// 走到这儿表示之前hctx[i]没有值，或者有值但numa_node和之前的不一样需要重新设置

		// 分配一个新的hctx
		hctx = blk_mq_alloc_and_init_hctx(set, q, i, node);
		if (hctx) {
			// 分配成功

			if (hctxs[i])
				// 如果以前有值，则先释放之前的
				blk_mq_exit_hctx(q, set, hctxs[i], i);
			// 设置新的
			hctxs[i] = hctx;
		} else {
			// 分配失败

			if (hctxs[i])
				// 如果以前有了，则啥也不干
				pr_warn("Allocate new hctx on node %d fails,\
						fallback to previous one on node %d\n",
						node, hctxs[i]->numa_node);
			else
				// 以前没有，退出循环
				break;
		}
	}
	
	if (i != set->nr_hw_queues) {
		// 从上面的循环可知：i != nr_hw_queues，只有一种情况，
		// 即q->nr_hw_queues < set->nr_hw_queues时，分配新的hctx[i]失败

		// 这里的j记录的是分配失败之后，需要释放的开始位置
		j = q->nr_hw_queues;
		// 需要释放的结束位置
		end = i;
	} else {
		// 全部分配成功，走到这里有2种情况：
		// 1. q->nr_hw_queues < set->nr_hw_queues，这种情况下是不用释放的
		// 2. q->nr_hw_queues > set->nr_hw_queues，这种情况下需要释放掉多余的
		
		// 释放的起点为最后的i，在q->nr_hw_queues > set->nr_hw_queues时，是下一个hctx
		j = i;
		// 结束点为原来队列的数量
		end = q->nr_hw_queues;
		// 设置新的hw数量
		q->nr_hw_queues = set->nr_hw_queues;
	}

	// 释放htcx, 进入这个循环有2种可能：
	// 1. 上面的循环全部分配成功，且q->nr_hw_queues > set->nr_hw_queues，需要释放多余的
	// 2. 上面的循环有分配失败的，且q->nr_hw_queues < set->nr_hw_queues，需要把刚才新分配的释放掉
	for (; j < end; j++) {
		struct blk_mq_hw_ctx *hctx = hctxs[j];

		if (hctx) {
			if (hctx->tags)
				blk_mq_free_map_and_requests(set, j);
			blk_mq_exit_hctx(q, set, hctx, j);
			hctxs[j] = NULL;
		}
	}
	mutex_unlock(&q->sysfs_lock);
}


static struct blk_mq_hw_ctx *blk_mq_alloc_and_init_hctx(
		struct blk_mq_tag_set *set, struct request_queue *q,
		int hctx_idx, int node)
{
	struct blk_mq_hw_ctx *hctx = NULL, *tmp;

	/* reuse dead hctx first */
	spin_lock(&q->unused_hctx_lock);

	// 遍历未使用hctx列表
	list_for_each_entry(tmp, &q->unused_hctx_list, hctx_list) {
		// 如果有和需要node相同的，则使用它
		if (tmp->numa_node == node) {
			hctx = tmp;
			break;
		}
	}

	// 如果在unused里找到，则从未使用列表删除它
	if (hctx)
		list_del_init(&hctx->hctx_list);
	spin_unlock(&q->unused_hctx_lock);

	// 如果没从上面找到，则分配一个
	if (!hctx)
		hctx = blk_mq_alloc_hctx(q, set, node);
	if (!hctx)
		goto fail;

	// 初始化hctx
	if (blk_mq_init_hctx(q, set, hctx, hctx_idx))
		goto free_hctx;

	return hctx;

 free_hctx:
	kobject_put(&hctx->kobj);
 fail:
	return NULL;
}

static struct blk_mq_hw_ctx *
blk_mq_alloc_hctx(struct request_queue *q, struct blk_mq_tag_set *set,
		int node)
{
	struct blk_mq_hw_ctx *hctx;
	gfp_t gfp = GFP_NOIO | __GFP_NOWARN | __GFP_NORETRY;

	// 分配hctx，它的大小与是否有src_struct有关
	hctx = kzalloc_node(blk_mq_hw_ctx_size(set), gfp, node);
	if (!hctx)
		goto fail_alloc_hctx;

	// 清除mask
	if (!zalloc_cpumask_var_node(&hctx->cpumask, gfp, node))
		goto free_hctx;

	// 活跃请求数
	atomic_set(&hctx->nr_active, 0);
	// 调度器入队数量
	atomic_set(&hctx->elevator_queued, 0);

	// 如果没有指定node，然后使用set的node
	if (node == NUMA_NO_NODE)
		node = set->numa_node;
	// 设置hctx的node
	hctx->numa_node = node;

	// 工作函数
	INIT_DELAYED_WORK(&hctx->run_work, blk_mq_run_work_fn);
	spin_lock_init(&hctx->lock);
	INIT_LIST_HEAD(&hctx->dispatch);
	// 对应的队列
	hctx->queue = q;
	// 清除共享标志
	hctx->flags = set->flags & ~BLK_MQ_F_TAG_QUEUE_SHARED;

	INIT_LIST_HEAD(&hctx->hctx_list);

	// 分配各个cpu的ctx
	hctx->ctxs = kmalloc_array_node(nr_cpu_ids, sizeof(void *),
			gfp, node);
	if (!hctx->ctxs)
		goto free_cpumask;

	// 初始化ctx_map
	if (sbitmap_init_node(&hctx->ctx_map, nr_cpu_ids, ilog2(8),
				gfp, node))
		goto free_ctxs;

	// 软队列数量先设置为0
	hctx->nr_ctx = 0;

	spin_lock_init(&hctx->dispatch_wait_lock);
	// 派发函数
	init_waitqueue_func_entry(&hctx->dispatch_wait, blk_mq_dispatch_wake);
	INIT_LIST_HEAD(&hctx->dispatch_wait.entry);

	// 分配冲刷队列对象
	hctx->fq = blk_alloc_flush_queue(hctx->numa_node, set->cmd_size, gfp);
	if (!hctx->fq)
		goto free_bitmap;

	// 如果支持阻塞，则初始化rcu结构
	if (hctx->flags & BLK_MQ_F_BLOCKING)
		init_srcu_struct(hctx->srcu);
	
	// 初始化obj
	blk_mq_hctx_kobj_init(hctx);

	return hctx;

 free_bitmap:
	sbitmap_free(&hctx->ctx_map);
 free_ctxs:
	kfree(hctx->ctxs);
 free_cpumask:
	free_cpumask_var(hctx->cpumask);
 free_hctx:
	kfree(hctx);
 fail_alloc_hctx:
	return NULL;
}


static int blk_mq_hw_ctx_size(struct blk_mq_tag_set *tag_set)
{
	int hw_ctx_size = sizeof(struct blk_mq_hw_ctx);

	// 构建时判断对齐
	BUILD_BUG_ON(ALIGN(offsetof(struct blk_mq_hw_ctx, srcu),
			   __alignof__(struct blk_mq_hw_ctx)) !=
		     sizeof(struct blk_mq_hw_ctx));

	// 如果支持阻塞，加上srcu_struct的大小
	if (tag_set->flags & BLK_MQ_F_BLOCKING)
		hw_ctx_size += sizeof(struct srcu_struct);

	// 否则就是struct blk_mq_hw_ctx结构本身的大小
	return hw_ctx_size;
}

struct blk_flush_queue *blk_alloc_flush_queue(int node, int cmd_size,
					      gfp_t flags)
{
	struct blk_flush_queue *fq;
	int rq_sz = sizeof(struct request);

	// 分配fq
	fq = kzalloc_node(sizeof(*fq), flags, node);
	if (!fq)
		goto fail;

	spin_lock_init(&fq->mq_flush_lock);

	// 请求的大小，请求结构+命令大小再对齐到行大小
	rq_sz = round_up(rq_sz + cmd_size, cache_line_size());
	// 只分配一个请求？
	fq->flush_rq = kzalloc_node(rq_sz, flags, node);
	if (!fq->flush_rq)
		goto fail_rq;

	// 初始化各种列表
	INIT_LIST_HEAD(&fq->flush_queue[0]);
	INIT_LIST_HEAD(&fq->flush_queue[1]);
	INIT_LIST_HEAD(&fq->flush_data_in_flight);

	lockdep_register_key(&fq->key);
	lockdep_set_class(&fq->mq_flush_lock, &fq->key);

	return fq;

 fail_rq:
	kfree(fq);
 fail:
	return NULL;
}

static int blk_mq_init_hctx(struct request_queue *q,
		struct blk_mq_tag_set *set,
		struct blk_mq_hw_ctx *hctx, unsigned hctx_idx)
{
	// 队列id
	hctx->queue_num = hctx_idx;

	// what?
	if (!(hctx->flags & BLK_MQ_F_STACKING))
		cpuhp_state_add_instance_nocalls(CPUHP_AP_BLK_MQ_ONLINE,
				&hctx->cpuhp_online);
	// cpu热插拔相关
	cpuhp_state_add_instance_nocalls(CPUHP_BLK_MQ_DEAD, &hctx->cpuhp_dead);

	// hctx里的tags就是set里hctx_idx对应的tags
	hctx->tags = set->tags[hctx_idx];

	// 若驱动有初始化上下文的函数，则调用之
	if (set->ops->init_hctx &&
	    set->ops->init_hctx(hctx, set->driver_data, hctx_idx))
		goto unregister_cpu_notifier;

	// 初始化flush_rq
	if (blk_mq_init_request(set, hctx->fq->flush_rq, hctx_idx,
				hctx->numa_node))
		goto exit_hctx;
	return 0;

 exit_hctx:
	if (set->ops->exit_hctx)
		set->ops->exit_hctx(hctx, hctx_idx);
 unregister_cpu_notifier:
	blk_mq_remove_cpuhp(hctx);
	return -1;
}
```
## blk_mq_init_sq_queue
初始化单个队列
```c
struct request_queue *blk_mq_init_sq_queue(struct blk_mq_tag_set *set,
					   const struct blk_mq_ops *ops,
					   unsigned int queue_depth,
					   unsigned int set_flags)
{
	struct request_queue *q;
	int ret;

	memset(set, 0, sizeof(*set));
	set->ops = ops;
	// 队列数量1
	set->nr_hw_queues = 1;
	// 映射1
	set->nr_maps = 1;
	// 队列长度
	set->queue_depth = queue_depth;
	// numa无限制
	set->numa_node = NUMA_NO_NODE;
	set->flags = set_flags;

	// 分配tag及队列
	ret = blk_mq_alloc_tag_set(set);
	if (ret)
		return ERR_PTR(ret);

	// 初始化队列
	q = blk_mq_init_queue(set);
	if (IS_ERR(q)) {
		blk_mq_free_tag_set(set);
		return q;
	}

	return q;
}
```