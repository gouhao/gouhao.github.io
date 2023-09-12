# hctx
源码基于5.10

## blk_mq_map_queue
```c
static inline struct blk_mq_hw_ctx *blk_mq_map_queue(struct request_queue *q,
						     unsigned int flags,
						     struct blk_mq_ctx *ctx)
{
	// 默认取default类型
	enum hctx_type type = HCTX_TYPE_DEFAULT;

	if (flags & REQ_HIPRI)
		// 有高优先级则使用poll
		type = HCTX_TYPE_POLL;
	else if ((flags & REQ_OP_MASK) == REQ_OP_READ)
		// 读请求,使用读类型
		type = HCTX_TYPE_READ;
	
	return ctx->hctxs[type];
}

```