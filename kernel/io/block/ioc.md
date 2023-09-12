# ioc
源码基于5.10

## 0. 结构体
```c
struct io_cq {
	struct request_queue	*q;
	struct io_context	*ioc;

	/*
	 * q_node and ioc_node link io_cq through icq_list of q and ioc
	 * respectively.  Both fields are unused once ioc_exit_icq() is
	 * called and shared with __rcu_icq_cache and __rcu_head which are
	 * used for RCU free of io_cq.
	 */
	union {
		struct list_head	q_node;
		struct kmem_cache	*__rcu_icq_cache;
	};
	union {
		struct hlist_node	ioc_node;
		struct rcu_head		__rcu_head;
	};

	unsigned int		flags;
};
```
## 1. blk_mq_sched_assign_ioc
```c
void blk_mq_sched_assign_ioc(struct request *rq)
{
	struct request_queue *q = rq->q;
	struct io_context *ioc;
	struct io_cq *icq;

	/*
	 * 直通请求可能没有ioc
	 */
	ioc = current->io_context;
	if (!ioc)
		return;

	spin_lock_irq(&q->queue_lock);
	// 找icq
	icq = ioc_lookup_icq(ioc, q);
	spin_unlock_irq(&q->queue_lock);

	// 如果没找到则新建一个
	if (!icq) {
		// 创建icq
		icq = ioc_create_icq(ioc, q, GFP_ATOMIC);
		if (!icq)
			return;
	}
	// 增加上下文引用
	get_io_context(icq->ioc);
	// 设置调度器的icq
	rq->elv.icq = icq;
}
```

## 2. 找icq
```c
struct io_cq *ioc_lookup_icq(struct io_context *ioc, struct request_queue *q)
{
	struct io_cq *icq;

	lockdep_assert_held(&q->queue_lock);

	/*
	 * icq's are indexed from @ioc using radix tree and hint pointer,
	 * both of which are protected with RCU.  All removals are done
	 * holding both q and ioc locks, and we're holding q lock - if we
	 * find a icq which points to us, it's guaranteed to be valid.
	 */
	rcu_read_lock();
	// 取出hint. todo: hint是什么意思? 暗示?
	icq = rcu_dereference(ioc->icq_hint);
	// 如果hint的队列要目标队列相同,直接返回
	if (icq && icq->q == q)
		goto out;

	// 找queue id的icq
	icq = radix_tree_lookup(&ioc->icq_tree, q->id);
	if (icq && icq->q == q)
		// 如果找到了设置hint值
		rcu_assign_pointer(ioc->icq_hint, icq);	/* allowed to race */
	else
		icq = NULL;
out:
	rcu_read_unlock();
	return icq;
}
```

## 3. 创建icq
```c
struct io_cq *ioc_create_icq(struct io_context *ioc, struct request_queue *q,
			     gfp_t gfp_mask)
{
	struct elevator_type *et = q->elevator->type;
	struct io_cq *icq;

	/* allocate stuff */
	icq = kmem_cache_alloc_node(et->icq_cache, gfp_mask | __GFP_ZERO,
				    q->node);
	if (!icq)
		return NULL;

	if (radix_tree_maybe_preload(gfp_mask) < 0) {
		kmem_cache_free(et->icq_cache, icq);
		return NULL;
	}

	icq->ioc = ioc;
	icq->q = q;
	INIT_LIST_HEAD(&icq->q_node);
	INIT_HLIST_NODE(&icq->ioc_node);

	/* lock both q and ioc and try to link @icq */
	spin_lock_irq(&q->queue_lock);
	spin_lock(&ioc->lock);

	if (likely(!radix_tree_insert(&ioc->icq_tree, q->id, icq))) {
		hlist_add_head(&icq->ioc_node, &ioc->icq_list);
		list_add(&icq->q_node, &q->icq_list);
		if (et->ops.init_icq)
			et->ops.init_icq(icq);
	} else {
		kmem_cache_free(et->icq_cache, icq);
		icq = ioc_lookup_icq(ioc, q);
		if (!icq)
			printk(KERN_ERR "cfq: icq link failed!\n");
	}

	spin_unlock(&ioc->lock);
	spin_unlock_irq(&q->queue_lock);
	radix_tree_preload_end();
	return icq;
}
```