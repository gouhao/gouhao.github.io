# blk层的提交
源码基于5.10

## 1. blk_mq_submit_bio
```c
blk_qc_t blk_mq_submit_bio(struct bio *bio)
{
	// 请求队列
	struct request_queue *q = bio->bi_disk->queue;
	// 是否是同步操作.read是同步的，其它操作就要看有没有REQ_SYNC | REQ_FUA | REQ_PREFLUSH，这三个之一的标志
	const int is_sync = op_is_sync(bio->bi_opf);
	// 有没(REQ_FUA | REQ_PREFLUSH)之一的标志
	const int is_flush_fua = op_is_flush(bio->bi_opf);
	struct blk_mq_alloc_data data = {
		.q		= q,
	};
	struct request *rq;
	struct blk_plug *plug;
	struct request *same_queue_rq = NULL;
	unsigned int nr_segs;
	blk_qc_t cookie;
	blk_status_t ret;

	// bio反弹，如果内存区在高区，则要映射到低区。
	blk_queue_bounce(q, &bio);

	// 如果bio块太大，则对bio进行分割成小的块
	__blk_queue_split(&bio, &nr_segs);

	// 度量初始化
	if (!bio_integrity_prep(bio))
		goto queue_exit;

	// blk_queue_nomerges: 查看q->queue_flags有无QUEUE_FLAG_NOMERGES标志
	// !is_flush_fua && 队列没有禁用合并 && 尝试在current->plug上合并
	if (!is_flush_fua && !blk_queue_nomerges(q) &&
	    blk_attempt_plug_merge(q, bio, nr_segs, &same_queue_rq))
	    	// 如果合并成功直接退出
		goto queue_exit;

	// 尝试io调度器或软队列进行合并，同理，若成功则退出
	if (blk_mq_sched_bio_merge(q, bio, nr_segs))
		goto queue_exit;

	// 走到这儿，表示不能合并，要分配一个新的请求

	// qos节流。todo：后面看
	rq_qos_throttle(q, bio);

	data.cmd_flags = bio->bi_opf;
	// 分配一个请求
	rq = __blk_mq_alloc_request(&data);
	if (unlikely(!rq)) {
		// 分配请求失败
		rq_qos_cleanup(q, bio);
		// 如果不阻塞，则设置错误状态
		if (bio->bi_opf & REQ_NOWAIT)
			bio_wouldblock_error(bio);
		
		goto queue_exit;
	}

	trace_block_getrq(q, bio, bio->bi_opf);

	rq_qos_track(q, rq, bio);

	// 使用tag和队列深度做成的一个cookie值
	cookie = request_to_qc_t(data.hctx, rq);

	// 把bio里的数据写到请求里
	blk_mq_bio_to_request(rq, bio, nr_segs);

	// 有加密的话，才会初始化相关
	ret = blk_crypto_init_request(rq);
	// 加密初始化如果失败，直接失败
	// 一般情况下，没有加密需求的，会直接返回OK
	if (ret != BLK_STS_OK) {
		bio->bi_status = ret;
		bio_endio(bio);
		blk_mq_free_request(rq);
		return BLK_QC_T_NONE;
	}

	// 获取plug，通常都返回current->plug,除非是zone设备的写请求会返回NULL
	plug = blk_mq_plug(q, bio);

	// 是刷新fua请求
	if (unlikely(is_flush_fua)) {
		// 是flush的话，直接绕过调度器直接插入请求
		blk_insert_flush(rq);
		// 运行队列
		blk_mq_run_hw_queue(data.hctx, true);
	
	
	// plug不为空 && (设备是单队列 || 共享hctx位图 || 硬件有commit_rqs函数 || 不是ssd设备)
	} else if (plug && (q->nr_hw_queues == 1 ||
		   blk_mq_is_sbitmap_shared(rq->mq_hctx->flags) ||
		   			    // 检测有无QUEUE_FLAG_NONROT标志，有这个标志表示不旋转的设备
		   q->mq_ops->commit_rqs || !blk_queue_nonrot(q))) {
		// 普通硬盘在大多数情况应该走这里吧
		/*
		 * Use plugging if we have a ->commit_rqs() hook as well, as
		 * we know the driver uses bd->last in a smart fashion.
		 *
		 * Use normal plugging if this disk is slow HDD, as sequential
		 * IO may benefit a lot from plug merging.
		 */
		// 当前plug的请求数量
		unsigned int request_count = plug->rq_count;
		struct request *last = NULL;

		if (!request_count)
			// plug里的第1个请求，先trace一下
			trace_block_plug(q);
		else
			// 请求队列里的最后一个请求
			last = list_entry_rq(plug->mq_list.prev);

		// BLK_PLUG_FLUSH_SIZE＝128k
		// blk_plug_max_rq_count = 64(多队列) or 32(单队列)
		// 请求数量达到了最大值 || (有多个请求 && 最后一个请求的数据长度超过了要刷新的长度)
		// todo: 这里为什么只判断最后一个请求的长度,不应该判断整个plug里所有请求的长度吗?还是这个BLK_PLUG_FLUSH_SIZE只是限制plug里一个request的大小?
		if (request_count >= blk_plug_max_rq_count(plug) || (last &&
		    blk_rq_bytes(last) >= BLK_PLUG_FLUSH_SIZE)) {
			// 刷出当前plug里的所有请求
			blk_flush_plug_list(plug, false);
			// 因为已经刷出了当前的plug，所以再trace一下？
			trace_block_plug(q);
		}

		// 把请求添加到plug->mq_list
		blk_add_rq_to_plug(plug, rq);

	// todo: 什么情况下会走到这儿? ssd?

	// 队列有调度器
	} else if (q->elevator) {
		// io/调度器下发
		blk_mq_sched_insert_request(rq, false, true, true);
	
	// 有plug && 队列没有禁用合并, 走到这个分支的条件:非刷新请求 && 没有调度器 &&
	// 设备是多队列 && 不共享hctx位图 && 设备没有commit_rqs && 不旋转设备
	} else if (plug && !blk_queue_nomerges(q)) {
		// todo: 走到这个分支是什么情况？这个分支没太看明白
		/* 原文注释:
		 * 我们做有限的plugging.如果bio能合并,则合并之.否则,如果合并失败,
		 * 把已经存在于plug列表里的相同的请求直接发布.所以plug列表里最多有
		 * 一个相同的请求.plug列表也许会在这之前被flush,如果这发生了,那plug
		 * 列表就是空的,那same_queue_rq也没用了
		 */
		// plug队列为空, same_queue_rq也就没用了
		if (list_empty(&plug->mq_list))
			same_queue_rq = NULL;
		
		// 如果有same_queue_rq, 还走到这儿,说明上面的合并失败了
		if (same_queue_rq) {
			// 先从列表里删除请求
			list_del_init(&same_queue_rq->queuelist);
			plug->rq_count--;
		}
		// 给plug里添加rq
		blk_add_rq_to_plug(plug, rq);
		trace_block_plug(q);

		// 直接发布same_rq，这个失败的rq会导致后面都不能合并，所以刷出它
		if (same_queue_rq) {
			// 先把same_queue_rq的请求发出
			data.hctx = same_queue_rq->mq_hctx;
			trace_block_unplug(q, 1, true);
			blk_mq_try_issue_directly(data.hctx, same_queue_rq,
					&cookie);
		}

	// (多个队列 && 同步请求) || 队列不忙), 则直接下发
	} else if ((q->nr_hw_queues > 1 && is_sync) ||
			!data.hctx->dispatch_busy) {
		blk_mq_try_issue_directly(data.hctx, rq, &cookie);
	} else {
		// 其它情况使用与调度器相同的方法, 这个会插入软队列或者调用调度器
		blk_mq_sched_insert_request(rq, false, true, true);
	}

	return cookie;
queue_exit:
	// 递减q_usage_counter计数，对应blk_queue_enter()
	blk_queue_exit(q);
	return BLK_QC_T_NONE;
}
```

## 2. bio反弹
```c
void blk_queue_bounce(struct request_queue *q, struct bio **bio_orig)
{
	mempool_t *pool;

	// 没有数据，就直接返回
	if (!bio_has_data(*bio_orig))
		return;

	// 根据是否dma来决定不同的pool
	if (!(q->bounce_gfp & GFP_DMA)) {
		// 不是dma

		// 如果bounce的限制地址大于blk的最大地址，直接返回不用处理
		// blk_max_pfn = max_pfn - 10
		if (q->limits.bounce_pfn >= blk_max_pfn)
			return;
		pool = &page_pool;
	} else {
		// 非dma情况

		// 判断isa_page_pool是否初始化
		BUG_ON(!mempool_initialized(&isa_page_pool));
		pool = &isa_page_pool;
	}

	// 处理反弹
	__blk_queue_bounce(q, bio_orig, pool);
}

static void __blk_queue_bounce(struct request_queue *q, struct bio **bio_orig,
			       mempool_t *pool)
{
	struct bio *bio;
	// write: 1， read：0
	int rw = bio_data_dir(*bio_orig);
	struct bio_vec *to, from;
	struct bvec_iter iter;
	unsigned i = 0;
	bool bounce = false;
	int sectors = 0;
	// scsi或drv操作
	bool passthrough = bio_is_passthrough(*bio_orig);

	bio_for_each_segment(from, *bio_orig, iter) {
		// 统计扇区数, BIO_MAX_PAGES=256
		if (i++ < BIO_MAX_PAGES)
			sectors += from.bv_len >> 9;
		// 大于反弹地址，则需要处理
		if (page_to_pfn(from.bv_page) > q->limits.bounce_pfn)
			bounce = true;
	}
	// 不需要处理反弹,直接返回
	if (!bounce)
		return;

	// 不是直通请求 && 扇区数小于原来的扇区数. todo: 为什么会小于??
	if (!passthrough && sectors < bio_sectors(*bio_orig)) {
		// 分割原来的bio
		bio = bio_split(*bio_orig, sectors, GFP_NOIO, &bounce_bio_split);
		// 把新老bio串起来
		bio_chain(bio, *bio_orig);
		// 提交原来的bio,后面处理新的bio
		submit_bio_noacct(*bio_orig);
		// 设置bio_orig为新的,因为上面的submit已经把旧的提交了
		*bio_orig = bio;
	}


	// 克隆一下bio
	bio = bounce_clone_bio(*bio_orig, GFP_NOIO, passthrough ? NULL :
			&bounce_bio_set);

	// 遍历bio开始的segment, 因为bio里的vecs是不变的,它里面还是原来的数据
	for (i = 0, to = bio->bi_io_vec; i < bio->bi_vcnt; to++, i++) {
		// 记录老的page
		struct page *page = to->bv_page;

		// 小于bounce的地址,则不用处理
		if (page_to_pfn(page) <= q->limits.bounce_pfn)
			continue;

		// 从池里分配新的page
		to->bv_page = mempool_alloc(pool, q->bounce_gfp);
		// 增加zone的反弹计数
		inc_zone_page_state(to->bv_page, NR_BOUNCE);

		// 写操作
		if (rw == WRITE) {
			char *vto, *vfrom;

			// 先刷出原来page的缓存
			flush_dcache_page(page);
			// 算出新地址的起点
			vto = page_address(to->bv_page) + to->bv_offset;
			// 老地址的起点
			vfrom = kmap_atomic(page) + to->bv_offset;
			// 把旧页的地址复制到新页上
			memcpy(vto, vfrom, to->bv_len);
			// 把老的解映射
			kunmap_atomic(vfrom);
		}
	}

	trace_block_bio_bounce(q, *bio_orig);

	// 给bio设置bounced标志
	bio->bi_flags |= (1 << BIO_BOUNCED);

	// 根据池的不同,设置不同的结束回调
	if (pool == &page_pool) {
		bio->bi_end_io = bounce_end_io_write;
		if (rw == READ)
			bio->bi_end_io = bounce_end_io_read;
	} else {
		bio->bi_end_io = bounce_end_io_write_isa;
		if (rw == READ)
			bio->bi_end_io = bounce_end_io_read_isa;
	}

	// 私有数据设置成原来的bio
	bio->bi_private = *bio_orig;
	// orig设置成反弹之后的bio
	*bio_orig = bio;
}

static struct bio *bounce_clone_bio(struct bio *bio_src, gfp_t gfp_mask,
		struct bio_set *bs)
{
	struct bvec_iter iter;
	struct bio_vec bv;
	struct bio *bio;

	// 分配一个bio, bio_segments是算出vec的数量
	bio = bio_alloc_bioset(gfp_mask, bio_segments(bio_src), bs);
	if (!bio)
		return NULL;
	
	// 设置原来的值
	bio->bi_disk		= bio_src->bi_disk;
	bio->bi_opf		= bio_src->bi_opf;
	bio->bi_ioprio		= bio_src->bi_ioprio;
	bio->bi_write_hint	= bio_src->bi_write_hint;
	bio->bi_iter.bi_sector	= bio_src->bi_iter.bi_sector;
	bio->bi_iter.bi_size	= bio_src->bi_iter.bi_size;

	switch (bio_op(bio)) {
	case REQ_OP_DISCARD:
	case REQ_OP_SECURE_ERASE:
	case REQ_OP_WRITE_ZEROES:
		break;
	case REQ_OP_WRITE_SAME:
		// writesame只需复制第一个vec
		bio->bi_io_vec[bio->bi_vcnt++] = bio_src->bi_io_vec[0];
		break;
	default:
		// 其它情况,复制每个vec
		bio_for_each_segment(bv, bio_src, iter)
			bio->bi_io_vec[bio->bi_vcnt++] = bv;
		break;
	}

	// 加密
	if (bio_crypt_clone(bio, bio_src, gfp_mask) < 0)
		goto err_put;

	// 度量
	if (bio_integrity(bio_src) &&
	    bio_integrity_clone(bio, bio_src, gfp_mask) < 0)
		goto err_put;

	// blkcg相关
	bio_clone_blkg_association(bio, bio_src);
	blkcg_bio_issue_init(bio);

	return bio;

err_put:
	bio_put(bio);
	return NULL;
}
```

## 3. bio 分割
```c
void __blk_queue_split(struct bio **bio, unsigned int *nr_segs)
{
	// 磁盘队列
	struct request_queue *q = (*bio)->bi_disk->queue;
	struct bio *split = NULL;

	// 对各类型的操作进行不同的分割
	switch (bio_op(*bio)) {
		// 其它的分割暂时不看，只看默认情况。todo:
	case REQ_OP_DISCARD:
	case REQ_OP_SECURE_ERASE:
		split = blk_bio_discard_split(q, *bio, &q->bio_split, nr_segs);
		break;
	case REQ_OP_WRITE_ZEROES:
		split = blk_bio_write_zeroes_split(q, *bio, &q->bio_split,
				nr_segs);
		break;
	case REQ_OP_WRITE_SAME:
		split = blk_bio_write_same_split(q, *bio, &q->bio_split,
				nr_segs);
		break;
	default:
		// 只看一般情况

		// 没有chunk限制
		if (!q->limits.chunk_sectors &&
		    // 只有1个段
		    (*bio)->bi_vcnt == 1 &&
		    // 所请求的长度在一页以内
		    ((*bio)->bi_io_vec[0].bv_len +
		     (*bio)->bi_io_vec[0].bv_offset) <= PAGE_SIZE) {
			// 这种情况不用分割
			*nr_segs = 1;
			break;
		}
		// 尝试分割，返回值是新分割的bio
		split = blk_bio_segment_split(q, *bio, &q->bio_split, nr_segs);
		break;
	}

	// 如果有分割
	if (split) {
		// 分割后的不需要合并
		split->bi_opf |= REQ_NOMERGE;

		// 把split和bio链起来，split->bi_private会指向bio
		bio_chain(split, *bio);
		
		trace_block_split(q, split, (*bio)->bi_iter.bi_sector);
		// 把第2个bio再次提交，当前提交的就是split对应的bio，
		// 这样会递规，如果分割完的bio还是太多，则会继续分割
		submit_bio_noacct(*bio);
		// 设置当前bio为裁剪之后的
		*bio = split;

		// blkcg限流计费相关
		blk_throtl_charge_bio_split(*bio);
	}
}

static struct bio *blk_bio_segment_split(struct request_queue *q,
					 struct bio *bio,
					 struct bio_set *bs,
					 unsigned *segs)
{
	struct bio_vec bv, bvprv, *bvprvp = NULL;
	struct bvec_iter iter;
	unsigned nsegs = 0, sectors = 0;
	// 从当前bio开始的扇区开始最大的扇区范围
	const unsigned max_sectors = get_max_io_size(q, bio);
	// 队列限制的最大段数
	const unsigned max_segs = queue_max_segments(q);

	// 遍历bio里的每个vec
	bio_for_each_bvec(bv, bio, iter) {
		// 当前的bv与上一个bv之间是否有洞
		// 如果队列不支持SG gaps，添加这个偏移会增加一个gap，所以不允许
		// todo: 没太看懂
		if (bvprvp && bvec_gap_to_prev(q, bvprvp, bv.bv_offset))
			goto split;

		// 大多数情况走这个路径
		// 小于最大段
		if (nsegs < max_segs &&
		    // 请求的扇区数小于最大扇区
		    sectors + (bv.bv_len >> 9) <= max_sectors &&
		    // vec的数据长度小于页大小
		    bv.bv_offset + bv.bv_len <= PAGE_SIZE) {
			// 满足这些条件的段不用分割
			nsegs++;
			sectors += bv.bv_len >> 9;

		// 走到这里表示这个bv超过了限制。

		// 判断一个bio是否要分开，返回true表示需要分割
		} else if (bvec_split_segs(q, &bv, &nsegs, &sectors, max_segs,
					 max_sectors)) {
			goto split;
		}

		bvprv = bv;
		bvprvp = &bvprv;
	}

	// 走到这儿表示没有分割
	*segs = nsegs;
	return NULL;
split:
	// 进行分割
	*segs = nsegs;
	// 裁剪bio，裁剪完之后新的bio在前，原来的bio会前进到新bio的大小后面: newbio---oldbio
	return bio_split(bio, sectors, GFP_NOIO, bs);
}

static bool bvec_split_segs(const struct request_queue *q,
			    const struct bio_vec *bv, unsigned *nsegs,
			    unsigned *sectors, unsigned max_segs,
			    unsigned max_sectors)
{
	// 除了已经有的sector之外，允许的最大长度
	unsigned max_len = (min(max_sectors, UINT_MAX >> 9) - *sectors) << 9;
	// 允许这个bv的最大长度
	unsigned len = min(bv->bv_len, max_len);
	unsigned total_len = 0;
	unsigned seg_size = 0;

	// 没超过限制大小，也没超过段的限制
	while (len && *nsegs < max_segs) {
		// 当前段允许的最大长度。
		seg_size = get_max_segment_size(q, bv->bv_page,
						bv->bv_offset + total_len);
		// 与允许的长度取较小
		seg_size = min(seg_size, len);

		// 允许的段增加
		(*nsegs)++;
		
		total_len += seg_size;
		// 从允许的空间里减段大小
		len -= seg_size;

		// 检查长度有无越界，如果已经越界就退出
		// queue_virt_boundary返回virt_boundary_mask
		if ((bv->bv_offset + total_len) & queue_virt_boundary(q))
			break;
	}

	// 总扇区数加上bv的的扇区数
	*sectors += total_len >> 9;

	// 返回值表示是否应该分割这个bio
	// 当len大于0时，表示这个bv的数据不能被完全处理，所以要分割
	// 如果len不大于0，此时len可能是负的，还要判断bv_len是否超过最大长度，如果超过了最大长度也要分割
	return len > 0 || bv->bv_len > max_len;
}

static inline unsigned get_max_segment_size(const struct request_queue *q,
					    struct page *start_page,
					    unsigned long offset)
{
	// 边界掩码？
	unsigned long mask = queue_segment_boundary(q);

	// 地址在边界内的起点
	offset = mask & (page_to_phys(start_page) + offset);

	// 取较小值，queue_max_segment_size是队列的最大段大小
	return min_not_zero(mask - offset + 1,
			(unsigned long)queue_max_segment_size(q));
}

// sectors是第一部分bio可容纳的扇区数
struct bio *bio_split(struct bio *bio, int sectors,
		      gfp_t gfp, struct bio_set *bs)
{
	struct bio *split;

	// 扇区数为0，还分啥
	BUG_ON(sectors <= 0);
	// 扇区数比bio请求的扇区还多？
	// todo: 什么情况下会走这儿？
	BUG_ON(sectors >= bio_sectors(bio));

	/* Zone 追加命令不能分割 */
	if (WARN_ON_ONCE(bio_op(bio) == REQ_OP_ZONE_APPEND))
		return NULL;

	// 把原来的bio复制一份
	split = bio_clone_fast(bio, gfp, bs);
	if (!split)
		return NULL;
	
	// sectors是第一部分的结束位置，
	// sectors << 9 就是bio请求的长度
	split->bi_iter.bi_size = sectors << 9;

	// todo: 完整性度量初始化
	if (bio_integrity(split))
		bio_integrity_trim(split);

	// 让bio前进bi_size个大小，老的bio就是第2部分
	bio_advance(bio, split->bi_iter.bi_size);

	// 如果bio已经trace过，则设置split也trace了
	if (bio_flagged(bio, BIO_TRACE_COMPLETION))
		bio_set_flag(split, BIO_TRACE_COMPLETION);

	// 返回新分配的bio
	return split;
}

struct bio *bio_clone_fast(struct bio *bio, gfp_t gfp_mask, struct bio_set *bs)
{
	struct bio *b;

	// 分配一个bio
	b = bio_alloc_bioset(gfp_mask, 0, bs);
	if (!b)
		return NULL;

	// 把原来bio里的内容分配到新的bio里
	__bio_clone_fast(b, bio);

	// 复制加密相关
	if (bio_crypt_clone(b, bio, gfp_mask) < 0)
		goto err_put;

	// 复制完整性相关
	if (bio_integrity(bio) &&
	    bio_integrity_clone(b, bio, gfp_mask) < 0)
		goto err_put;

	return b;

err_put:
	bio_put(b);
	return NULL;
}

#define BVEC_POOL_BITS		(3)
#define BVEC_POOL_OFFSET	(16 - BVEC_POOL_BITS)
#define BVEC_POOL_IDX(bio)	((bio)->bi_flags >> BVEC_POOL_OFFSET)

void __bio_clone_fast(struct bio *bio, struct bio *bio_src)
{
	// what?
	BUG_ON(bio->bi_pool && BVEC_POOL_IDX(bio));

	// 磁盘
	bio->bi_disk = bio_src->bi_disk;
	// 分区
	bio->bi_partno = bio_src->bi_partno;
	// 设置克隆标志
	bio_set_flag(bio, BIO_CLONED);
	//　之前bio节流，则新的bio也要设置节流
	if (bio_flagged(bio_src, BIO_THROTTLED))
		bio_set_flag(bio, BIO_THROTTLED);
	// 操作标志
	bio->bi_opf = bio_src->bi_opf;
	// 优先级？
	bio->bi_ioprio = bio_src->bi_ioprio;
	// 写暗示？
	bio->bi_write_hint = bio_src->bi_write_hint;
	// 迭代器
	bio->bi_iter = bio_src->bi_iter;
	// vec
	bio->bi_io_vec = bio_src->bi_io_vec;

	// blkcg相关
	bio_clone_blkg_association(bio, bio_src);
	blkcg_bio_issue_init(bio);
}

static inline unsigned get_max_io_size(struct request_queue *q,
				       struct bio *bio)
{
	// 获取最大允许请求的扇区数
	unsigned sectors = blk_max_size_offset(q, bio->bi_iter.bi_sector, 0);
	unsigned max_sectors = sectors;
	// SECTOR_SHIFT=9
	// 物理块大小限制
	unsigned pbs = queue_physical_block_size(q) >> SECTOR_SHIFT;
	// 逻辑块大小限制
	unsigned lbs = queue_logical_block_size(q) >> SECTOR_SHIFT;
	// 起始的扇区号
	unsigned start_offset = bio->bi_iter.bi_sector & (pbs - 1);

	max_sectors += start_offset;
	max_sectors &= ~(pbs - 1);

	// 起点小于最大扇区，则只允许这么多扇区
	// 一般都走这个分支？
	if (max_sectors > start_offset)
		return max_sectors - start_offset;

	// 否则，就是允许的最大逻辑扇区数？
	return sectors & ~(lbs - 1);
}
```

## 4. blk_attempt_plug_merge
```c
bool blk_attempt_plug_merge(struct request_queue *q, struct bio *bio,
		unsigned int nr_segs, struct request **same_queue_rq)
{
	struct blk_plug *plug;
	struct request *rq;
	struct list_head *plug_list;

	// 获取当前进程plug，如果进程没有调用blk_start_plug的话会返回NULL
	plug = blk_mq_plug(q, bio);
	// 如果没有的话返回NULL,表示没有进行plug机制
	if (!plug)
		return false;

	// 请求列表
	plug_list = &plug->mq_list;

	// 逆序遍历
	list_for_each_entry_reverse(rq, plug_list, queuelist) {
		// 如果plug队列里有相同队列的请求，则记录之，若调用方有需要的话
		if (rq->q == q && same_queue_rq) {
			*same_queue_rq = rq;
		}

		// 队列不同不能合并
		// 为啥不把这个判断放在上面，这样的话代码能简化一点
		if (rq->q != q)
			continue;

		// 合并成功返回BIO_MERGE_OK
		if (blk_attempt_bio_merge(q, rq, bio, nr_segs, false) ==
		    BIO_MERGE_OK)
			return true;
	}

	return false;
}

static enum bio_merge_status blk_attempt_bio_merge(struct request_queue *q,
						   struct request *rq,
						   struct bio *bio,
						   unsigned int nr_segs,
						   bool sched_allow_merge)
{
	// 检查各种合并条件，不符合条件的返回NONE
	if (!blk_rq_merge_ok(rq, bio))
		return BIO_MERGE_NONE;

	// blk_try_merge计算合并的方式
	switch (blk_try_merge(rq, bio)) {
	case ELEVATOR_BACK_MERGE:
		// 把bio追加到rq后面
		// 不需要检测电梯允许合并 || 调用电梯的allow_merge函数(如果有的话)
		if (!sched_allow_merge || blk_mq_sched_allow_merge(q, rq, bio))
			// 如果允许合并，则向后合并
			return bio_attempt_back_merge(rq, bio, nr_segs);
		break;
	case ELEVATOR_FRONT_MERGE:
		// 把bio加到rq前面
		// 同上，若允许，向前合并之
		if (!sched_allow_merge || blk_mq_sched_allow_merge(q, rq, bio))
			return bio_attempt_front_merge(rq, bio, nr_segs);
		break;
	case ELEVATOR_DISCARD_MERGE:
		// 丢弃合并
		return bio_attempt_discard_merge(q, rq, bio);
	default:
		return BIO_MERGE_NONE;
	}

	// 合并失败
	return BIO_MERGE_FAILED;
}

static inline bool
blk_mq_sched_allow_merge(struct request_queue *q, struct request *rq,
			 struct bio *bio)
{
	struct elevator_queue *e = q->elevator;

	// 若有电梯，则判断是否允许合并
	if (e && e->type->ops.allow_merge)
		return e->type->ops.allow_merge(q, rq, bio);

	return true;
}
```

### 4.1 合并的条件检查
```c
bool blk_rq_merge_ok(struct request *rq, struct bio *bio)
{
	// bio_mergeable: 检查bio有无REQ_NOMERGE_FLAGS标志
	// 请求不允许合并 || bio不允许合并，退出
	if (!rq_mergeable(rq) || !bio_mergeable(bio))
		return false;

	// 请求的操作和bio的操作不同，当然不能合并
	if (req_op(rq) != bio_op(bio))
		return false;

	// bio_data_dir，rq_data_dir都是获取操作是读方向还是写方向，
	// 不一定非要是读/写操作，这里只是检查方向。
	// todo: 这里的检查是不是没必要,因为上面已经检查确定了操作是相同的,难道有的操作有多个方向?
	if (bio_data_dir(bio) != rq_data_dir(rq))
		return false;

	// 不是同一个磁盘当然不能合并
	if (rq->rq_disk != bio->bi_disk)
		return false;

	// 完整性要相同 todo: 完整性度量，后面再看
	if (blk_integrity_merge_bio(rq->q, rq, bio) == false)
		return false;

	// 加密上下文要相同。todo: 加密后面再看
	if (!bio_crypt_rq_ctx_compatible(rq, bio))
		return false;

	// write_same操作要biopage和biooffset都相同才能合并
	if (req_op(rq) == REQ_OP_WRITE_SAME &&
	    !blk_write_same_mergeable(rq->bio, bio))
		return false;

	// todo: what is write_hint?
	if (rq->write_hint != bio->bi_write_hint)
		return false;

	// io优先级必须相同？
	if (rq->ioprio != bio_prio(bio))
		return false;

	return true;
}

static inline bool rq_mergeable(struct request *rq)
{
	// passthrough请求是REQ_OP_SCSI_IN | REQ_OP_SCSI_OUT 或者是REQ_OP_DRV_IN | REQ_OP_DRV_OUT
	if (blk_rq_is_passthrough(rq))
		return false;

	// 刷出缓存
	if (req_op(rq) == REQ_OP_FLUSH)
		return false;

	// 对扇区多次写0
	if (req_op(rq) == REQ_OP_WRITE_ZEROES)
		return false;

	// zone设备追加
	if (req_op(rq) == REQ_OP_ZONE_APPEND)
		return false;

	// 标志有不允许合并的标志
	if (rq->cmd_flags & REQ_NOMERGE_FLAGS)
		return false;
	if (rq->rq_flags & RQF_NOMERGE_FLAGS)
		return false;

	// 除了上面的条件，其它的都是可以合并的
	return true;
}
```

### 4.2 判断合并类型
```c
enum elv_merge blk_try_merge(struct request *rq, struct bio *bio)
{
	// 判断丢弃操作合并
	if (blk_discard_mergable(rq))
		return ELEVATOR_DISCARD_MERGE;
	
	// blk_rq_pos是请求扇区的起点
	// blk_rq_sectors是请求扇区的终点
	// bio->bi_iter.bi_sector是bio请求的扇区起点
	// bio_sectors是bio请求扇区的终点
	// 注意：扇区的终点都是不包括的：[start, end)

	// bio请求刚好在rq请求扇区的后面第一个扇区，则执行向后合并
	else if (blk_rq_pos(rq) + blk_rq_sectors(rq) == bio->bi_iter.bi_sector)
		return ELEVATOR_BACK_MERGE;
	
	// bio起点+bio长度刚好等于rq请求扇区的起点，执行前向合并
	else if (blk_rq_pos(rq) - bio_sectors(bio) == bio->bi_iter.bi_sector)
		return ELEVATOR_FRONT_MERGE;
	// 不合并
	return ELEVATOR_NO_MERGE;
}

static inline bool blk_discard_mergable(struct request *req)
{
	// 如果是丢弃操作 && 队列允许丢弃操作，则可合并
	if (req_op(req) == REQ_OP_DISCARD &&
	    queue_max_discard_segments(req->q) > 1)
		return true;
	return false;
}

```

### 4.3 执行真正的合并
一般的合并分为向后和向前合并

#### 4.3.1 向后合并
```c
static enum bio_merge_status bio_attempt_back_merge(struct request *req,
		struct bio *bio, unsigned int nr_segs)
{
	// 请求有快速失败
	const int ff = bio->bi_opf & REQ_FAILFAST_MASK;

	// 后向合并的检查，主要检查了洞、扇区限制，段限制等，如果起过了限制则不能合并
	if (!ll_back_merge_fn(req, bio, nr_segs))
		return BIO_MERGE_FAILED;

	// 走到这儿说明可以合并

	trace_block_bio_backmerge(req->q, req, bio);
	// qos合并。todo: 后面看
	rq_qos_merge(req->q, req, bio);

	// 合并之前，先给请求里的每个bio都设置上快速失败标志，
	// 并给请求标志RQF_MIXED_MERGE标志，并且给里面的每个bio标记REQ_FAILFAST_MASK
	if ((req->cmd_flags & REQ_FAILFAST_MASK) != ff)
		blk_rq_set_mixed_merge(req);

	// 让请求队列的尾部指向新的bio
	req->biotail->bi_next = bio;
	req->biotail = bio;

	// 请求的数据长度加上bio的数据长度
	req->__data_len += bio->bi_iter.bi_size;

	// 释放原来bio的加密上下文，能合并时，他们的加密上下文肯定相同
	bio_crypt_free_ctx(bio);

	// 统计合并？
	blk_account_io_merge_bio(req);

	// 合并成功
	return BIO_MERGE_OK;
}

void blk_rq_set_mixed_merge(struct request *rq)
{
	// 请求是否有快速结束标志
	unsigned int ff = rq->cmd_flags & REQ_FAILFAST_MASK;
	struct bio *bio;

	// 请求已经有了这个标志，直接返回
	if (rq->rq_flags & RQF_MIXED_MERGE)
		return;

	// 设置每个bio的opflag为ff
	for (bio = rq->bio; bio; bio = bio->bi_next) {
		WARN_ON_ONCE((bio->bi_opf & REQ_FAILFAST_MASK) &&
			     (bio->bi_opf & REQ_FAILFAST_MASK) != ff);
		bio->bi_opf |= ff;
	}
	rq->rq_flags |= RQF_MIXED_MERGE;
}
```
##### 4.3.1.1 合并检查
```c
int ll_back_merge_fn(struct request *req, struct bio *bio, unsigned int nr_segs)
{
	// 如果要合并的bio有洞的话不合并
	// 一般都会返回false
	if (req_gap_back_merge(req, bio))
		return 0;
	// 检查完整性
	if (blk_integrity_rq(req) &&
	    integrity_req_gap_back_merge(req, bio))
		return 0;
	// 检查加密
	if (!bio_crypt_ctx_back_mergeable(req, bio))
		return 0;

	// 请求里已有的扇区+要合并的bio的扇区，已经超过了最大的扇区数
	if (blk_rq_sectors(req) + bio_sectors(bio) >
	    blk_rq_get_max_sectors(req, blk_rq_pos(req))) {
		// 设置该请求不再合并
		// todo: 这里为什么要设置不合并，万一下个bio的扇区数比小于这个值呢？
		req_set_nomerge(req->q, req);
		return 0;
	}

	// 检查段是否超过限制
	return ll_new_hw_segment(req, bio, nr_segs);
}

static inline bool req_gap_back_merge(struct request *req, struct bio *bio)
{
	return bio_will_gap(req->q, req, req->biotail, bio);
}

static inline bool bio_will_gap(struct request_queue *q,
		struct request *prev_rq, struct bio *prev, struct bio *next)
{
	struct bio_vec pb, nb;

	// 前一个bio没数据 || !q->virt_boundary_mask(没有边界)
	// virt_boundary_mask默认值是0，大多数情况从这里就直接返回了
	if (!bio_has_data(prev) || !queue_virt_boundary(q))
		return false;

	// 走到这里表示prev有数据且队列有边界

	// 获取bio的第1个vec
	if (prev_rq)
		// 如果有请求，就获取请求的bio
		bio_get_first_bvec(prev_rq->bio, &pb);
	else
		// 如果没有的话就获取最后一个bio的第1个vec
		bio_get_first_bvec(prev, &pb);
	// 如果第一个bio的偏移值超过了队列的边界，则有洞
	if (pb.bv_offset & queue_virt_boundary(q))
		return true;

	/*
	 * We don't need to worry about the situation that the merged segment
	 * ends in unaligned virt boundary:
	 *
	 * - if 'pb' ends aligned, the merged segment ends aligned
	 * - if 'pb' ends unaligned, the next bio must include
	 *   one single bvec of 'nb', otherwise the 'nb' can't
	 *   merge with 'pb'
	 */
	// prev bio的vec
	bio_get_last_bvec(prev, &pb);
	// next bio的vec
	bio_get_first_bvec(next, &nb);

	// 判断物理地址能否合并
	if (biovec_phys_mergeable(q, &pb, &nb))
		return false;
	// 判断gap
	return __bvec_gap_to_prev(q, &pb, nb.bv_offset);
}

static inline bool biovec_phys_mergeable(struct request_queue *q,
		struct bio_vec *vec1, struct bio_vec *vec2)
{
	// 段边界，默认值0xffffffff
	unsigned long mask = queue_segment_boundary(q);
	// 页的起点
	phys_addr_t addr1 = page_to_phys(vec1->bv_page) + vec1->bv_offset;
	phys_addr_t addr2 = page_to_phys(vec2->bv_page) + vec2->bv_offset;

	// 地址不连续，不能合并
	if (addr1 + vec1->bv_len != addr2)
		return false;
	// zen架构？
	if (xen_domain() && !xen_biovec_phys_mergeable(vec1, vec2->bv_page))
		return false;
	// 2个不同时,说明有人越界了，不能合并
	if ((addr1 | mask) != ((addr2 + vec2->bv_len - 1) | mask))
		return false;
	// 可以合并
	return true;
}

static inline bool __bvec_gap_to_prev(struct request_queue *q,
		struct bio_vec *bprv, unsigned int offset)
{
	// 任意越界就表示有洞
	return (offset & queue_virt_boundary(q)) ||
		((bprv->bv_offset + bprv->bv_len) & queue_virt_boundary(q));
}

static inline int ll_new_hw_segment(struct request *req, struct bio *bio,
		unsigned int nr_phys_segs)
{
	// 完整性合并失败，不合并
	if (blk_integrity_merge_bio(req->q, req, bio) == false)
		goto no_merge;

	// 丢弃操作不会添加新段，所以直接返回1
	if (req_op(req) == REQ_OP_DISCARD)
		return 1;

	// 加上新段，超过了请求的最大的段，不合并
	// max_segments默认是128
	if (req->nr_phys_segments + nr_phys_segs > blk_rq_get_max_segments(req))
		// todo: 这里为什么设置不合并，万一下个bio可以合并呢？
		goto no_merge;

	// 可以合并，给请求加上该bio的段的数量
	req->nr_phys_segments += nr_phys_segs;
	return 1;

no_merge:
	// 设置该请求不再合并
	req_set_nomerge(req->q, req);
	return 0;
}

static inline unsigned int blk_rq_get_max_sectors(struct request *rq,
						  sector_t offset)
{
	struct request_queue *q = rq->q;

	// 如果是直通请求，直接返回最大硬件扇区数，默认是255
	if (blk_rq_is_passthrough(rq))
		return q->limits.max_hw_sectors;

	// 特殊操作，获取对应的扇区数
	if (!q->limits.chunk_sectors ||
	    req_op(rq) == REQ_OP_DISCARD ||
	    req_op(rq) == REQ_OP_SECURE_ERASE)
		return blk_queue_get_max_sectors(q, req_op(rq));

	// 获取队列最大扇区数？
	return min(blk_max_size_offset(q, offset, 0),
			blk_queue_get_max_sectors(q, req_op(rq)));
}

static inline void req_set_nomerge(struct request_queue *q, struct request *req)
{
	// 请求设置不合并标志
	req->cmd_flags |= REQ_NOMERGE;

	// 如果是队列上次合并的请求缓存
	if (req == q->last_merge)
		q->last_merge = NULL;
}
```

#### 4.3.2 向后合并
```c
static enum bio_merge_status bio_attempt_front_merge(struct request *req,
		struct bio *bio, unsigned int nr_segs)
{
	const int ff = bio->bi_opf & REQ_FAILFAST_MASK;

	// 前向合并检查。
	if (!ll_front_merge_fn(req, bio, nr_segs))
		return BIO_MERGE_FAILED;

	// 走到这儿表求可以合并

	trace_block_bio_frontmerge(req->q, req, bio);
	// cost.qos相关。todo:后面的看
	rq_qos_merge(req->q, req, bio);

	// 设置混合标志
	if ((req->cmd_flags & REQ_FAILFAST_MASK) != ff)
		blk_rq_set_mixed_merge(req);

	// 把bio插到请求的前面
	bio->bi_next = req->bio;
	// 把请求的起点设置成bio
	req->bio = bio;

	// 设置扇区起点是bio的扇区
	req->__sector = bio->bi_iter.bi_sector;
	// 加上数据长度
	req->__data_len += bio->bi_iter.bi_size;

	// 加密合并
	bio_crypt_do_front_merge(req, bio);

	// 统计bio合并
	blk_account_io_merge_bio(req);
	return BIO_MERGE_OK;
}
```

##### 4.3.2.1 向前合并检查
```c
static int ll_front_merge_fn(struct request *req, struct bio *bio,
		unsigned int nr_segs)
{
	// 检查是否有洞
	if (req_gap_front_merge(req, bio))
		return 0;
	// 完整性
	if (blk_integrity_rq(req) &&
	    integrity_req_gap_front_merge(req, bio))
		return 0;
	// 加密
	if (!bio_crypt_ctx_front_mergeable(req, bio))
		return 0;
	// 如果加上这个bio超过了最大的bio限制,则设置不合并
	if (blk_rq_sectors(req) + bio_sectors(bio) >
	    blk_rq_get_max_sectors(req, bio->bi_iter.bi_sector)) {
		req_set_nomerge(req->q, req);
		return 0;
	}

	// 判断segment是否超标
	return ll_new_hw_segment(req, bio, nr_segs);
}

static inline bool req_gap_front_merge(struct request *req, struct bio *bio)
{
	// 这个和后向合并一样,只不过把bio放到了prev的位置上,req->bio放到next的位置
	return bio_will_gap(req->q, NULL, bio, req->bio);
}
```

## 5. 调度器合并
调度器合并: 如果有调度器则调用调度器的方法, 没有调度器则从软队列里合并请求
```c
static inline bool
blk_mq_sched_bio_merge(struct request_queue *q, struct bio *bio,
		unsigned int nr_segs)
{
	// 如果队列不允许合并 || bio不允许合并，直接返回
	// blk_queue_nomerges: 检测队列有无QUEUE_FLAG_NOMERGES标志
	// bio_mergeable: 检查bio有无REQ_NOMERGE_FLAGS标志
	if (blk_queue_nomerges(q) || !bio_mergeable(bio))
		return false;

	// 调用合并
	return __blk_mq_sched_bio_merge(q, bio, nr_segs);
}

bool __blk_mq_sched_bio_merge(struct request_queue *q, struct bio *bio,
		unsigned int nr_segs)
{
	// 电梯在device_add_disk的时候设置
	struct elevator_queue *e = q->elevator;
	struct blk_mq_ctx *ctx;
	struct blk_mq_hw_ctx *hctx;
	bool ret = false;
	enum hctx_type type;

	// 这个队列有电梯，并且电梯有bio_merge方法，则调之
	if (e && e->type->ops.bio_merge)
		return e->type->ops.bio_merge(q, bio, nr_segs);

	// 没有电梯或者电梯没有bio_merge的合并

	// 获取q->queue_ctx
	ctx = blk_mq_get_ctx(q);
	// 根据flag和ctx，获取对应的硬件上下文
	hctx = blk_mq_map_queue(q, bio->bi_opf, ctx);
	// 硬件队列的类型
	type = hctx->type;
	// 硬件队列不允许合并 || rq_list是空的
	if (!(hctx->flags & BLK_MQ_F_SHOULD_MERGE) ||
	    list_empty_careful(&ctx->rq_lists[type]))
		return false;


	spin_lock(&ctx->lock);

	// 合并软队列里的请求
	if (blk_bio_list_merge(q, &ctx->rq_lists[type], bio, nr_segs)) {
		ctx->rq_merged++;
		ret = true;
	}

	spin_unlock(&ctx->lock);

	return ret;
}

bool blk_bio_list_merge(struct request_queue *q, struct list_head *list,
			struct bio *bio, unsigned int nr_segs)
{
	struct request *rq;
	// 只检查8次？todo: 为什么只检查8次
	int checked = 8;

	list_for_each_entry_reverse(rq, list, queuelist) {
		if (!checked--)
			break;

		// 尝试合并，根据合并结果返回不同的值,与plug的合并流程相同
		switch (blk_attempt_bio_merge(q, rq, bio, nr_segs, true)) {
		case BIO_MERGE_NONE:
			// merge_none是当前rq, 和bio不能合并，尝试下一个。
			continue;
		case BIO_MERGE_OK:
			return true;
		case BIO_MERGE_FAILED:
			return false;
		}

	}

	return false;
}
```