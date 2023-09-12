# ctx
源码基于5.10

## blk_mq_get_ctx
```c
static inline struct blk_mq_ctx *blk_mq_get_ctx(struct request_queue *q)
{
	return __blk_mq_get_ctx(q, raw_smp_processor_id());
}

static inline struct blk_mq_ctx *__blk_mq_get_ctx(struct request_queue *q,
					   unsigned int cpu)
{
	// 返回cpu对应的queue_ctx
	return per_cpu_ptr(q->queue_ctx, cpu);
}
```