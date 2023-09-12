# bio的一般操作
源码基于5.10

## 1. bio_add_page
```c
int bio_add_page(struct bio *bio, struct page *page,
		 unsigned int len, unsigned int offset)
{
	bool same_page = false;

	// 尝试把page合并到现有的bio里，返回true表示合并成功
	if (!__bio_try_merge_page(bio, page, len, offset, &same_page)) {
		// 这个分支是合并不成功

		// bio是不是已经满了，如果满了则不能添加页
		if (bio_full(bio, len))
			return 0;
		__bio_add_page(bio, page, len, offset);
	}
	return len;
}
```
### 1.1 尝试合并
```c
bool __bio_try_merge_page(struct bio *bio, struct page *page,
		unsigned int len, unsigned int off, bool *same_page)
{
	// 有BIO_CLONED标志不用合并，克隆的bio没有自己的数据
	if (WARN_ON_ONCE(bio_flagged(bio, BIO_CLONED)))
		return false;

	// bi_vcnt是bi_io_vec已有的vec数量，数组里有vec才能合并
	if (bio->bi_vcnt > 0) {
		// 取出最后一个vec
		struct bio_vec *bv = &bio->bi_io_vec[bio->bi_vcnt - 1];

		// 如果page能和当前bv合并，则合并之
		if (page_is_mergeable(bv, page, len, off, same_page)) {
			// 如果bio合并这个page后，大小超过了unsigned的最大值，则不能合并
			if (bio->bi_iter.bi_size > UINT_MAX - len) {
				*same_page = false;
				return false;
			}
			// 增加bv的长度
			bv->bv_len += len;
			// 增加bio的总大小
			bio->bi_iter.bi_size += len;
			return true;
		}
	}
	return false;
}

static inline bool page_is_mergeable(const struct bio_vec *bv,
		struct page *page, unsigned int len, unsigned int off,
		bool *same_page)
{
	// 当前bv终点
	size_t bv_end = bv->bv_offset + bv->bv_len;
	// bv结束的物理地址
	phys_addr_t vec_end_addr = page_to_phys(bv->bv_page) + bv_end - 1;
	// page的物理地址
	phys_addr_t page_addr = page_to_phys(page);

	// vec的终点必紧挨着page的地址，否则不能合并
	if (vec_end_addr + 1 != page_addr + off)
		return false;

	// zen架构相关？
	if (xen_domain() && !xen_biovec_phys_mergeable(bv, page))
		return false;

	// bv最后一页和page是不是同一页
	*same_page = ((vec_end_addr & PAGE_MASK) == page_addr);
	// 是同一页可以合并
	if (*same_page)
		return true;

	// 走到这儿表示不是同一页

	// bv->bv_page + bv_end / PAGE_SIZE 是结束页的page的地址
	// 结束页和当前页的序号相同，也可以合并。 todo: why ?
	return (bv->bv_page + bv_end / PAGE_SIZE) == (page + off / PAGE_SIZE);
}
```
### 1.2 添加页
```c 
static inline bool bio_full(struct bio *bio, unsigned len)
{
	// vec的数量已达到已分配vec的最大值
	if (bio->bi_vcnt >= bio->bi_max_vecs)
		return true;

	// 加上这个长度之后，bio的大小就超了最大值
	if (bio->bi_iter.bi_size > UINT_MAX - len)
		return true;

	return false;
}

void __bio_add_page(struct bio *bio, struct page *page,
		unsigned int len, unsigned int off)
{
	// 取一个bv
	struct bio_vec *bv = &bio->bi_io_vec[bio->bi_vcnt];

	// 这2个warn在前面不是已经判断过了吗？这里为什么还要判断一遍？难道有并发？不可能，因为此时bio还没有发布。
	// 克隆的bio
	WARN_ON_ONCE(bio_flagged(bio, BIO_CLONED));
	// bio已满.
	WARN_ON_ONCE(bio_full(bio, len));

	// 把page的一些信息设置到bi_vcnt对应的vec上
	bv->bv_page = page;
	bv->bv_offset = off;
	bv->bv_len = len;

	// 增加bio总大小
	bio->bi_iter.bi_size += len;
	// 增加bio的vec数量
	bio->bi_vcnt++;

	// 如果包含用户空间工作集的页，则在bio里设置workingset标志
	if (!bio_flagged(bio, BIO_WORKINGSET) && unlikely(PageWorkingset(page)))
		bio_set_flag(bio, BIO_WORKINGSET);
}
```

## 2. 分配bio
```c
static inline struct bio *bio_alloc(gfp_t gfp_mask, unsigned int nr_iovecs)
{
	// fs_bio_set是一个内存池
	return bio_alloc_bioset(gfp_mask, nr_iovecs, &fs_bio_set);
}

struct bio *bio_alloc_bioset(gfp_t gfp_mask, unsigned int nr_iovecs,
			     struct bio_set *bs)
{
	gfp_t saved_gfp = gfp_mask;
	// 前面的填充，想当于真正bio的偏移
	unsigned front_pad;
	// 内联vec的数量
	unsigned inline_vecs;
	struct bio_vec *bvl = NULL;
	struct bio *bio;
	void *p;

	if (!bs) {
		// 内存池为空，则用slab分配

		// UIO_MAXIOV=1024
		if (nr_iovecs > UIO_MAXIOV)
			return NULL;
		// bio末尾是个数组，需要动态计算长度
		p = kmalloc(struct_size(bio, bi_inline_vecs, nr_iovecs), gfp_mask);
		front_pad = 0;
		inline_vecs = nr_iovecs;
	} else {
		// 从内存池分配
		
		// 内存池还没有初始化
		if (WARN_ON_ONCE(!mempool_initialized(&bs->bvec_pool) &&
				 nr_iovecs > 0))
			return NULL;
		/*
		 * submit_bio_noacct() converts recursion to iteration; this
		 * means if we're running beneath it, any bios we allocate and
		 * submit will not be submitted (and thus freed) until after we
		 * return.
		 *
		 * This exposes us to a potential deadlock if we allocate
		 * multiple bios from the same bio_set() while running
		 * underneath submit_bio_noacct(). If we were to allocate
		 * multiple bios (say a stacking block driver that was splitting
		 * bios), we would deadlock if we exhausted the mempool's
		 * reserve.
		 *
		 * We solve this, and guarantee forward progress, with a rescuer
		 * workqueue per bio_set. If we go to allocate and there are
		 * bios on current->bio_list, we first try the allocation
		 * without __GFP_DIRECT_RECLAIM; if that fails, we punt those
		 * bios we would be blocking to the rescuer workqueue before
		 * we retry with the original gfp_flags.
		 */
		// todo: 没看懂，好像是死锁相关，如上注释
		if (current->bio_list &&
		    (!bio_list_empty(&current->bio_list[0]) ||
		     !bio_list_empty(&current->bio_list[1])) &&
		    bs->rescue_workqueue)
			gfp_mask &= ~__GFP_DIRECT_RECLAIM;

		// 从内存池分配
		p = mempool_alloc(&bs->bio_pool, gfp_mask);

		// 分配失败 && 用的分配标志和原始的不一样
		if (!p && gfp_mask != saved_gfp) {
			// 如果分配失败，而且gfp_mask已被修改，则使用原来的再试一次

			// todo: 没太看懂
			punt_bios_to_rescuer(bs);

			// 使用原来的分配标志再试一次
			gfp_mask = saved_gfp;
			p = mempool_alloc(&bs->bio_pool, gfp_mask);
		}

		// 前面的填充
		front_pad = bs->front_pad;
		// BIO_INLINE_VECS：4
		inline_vecs = BIO_INLINE_VECS;
	}

	// 分配失败
	if (unlikely(!p))
		return NULL;

	// 真正bio的起点
	bio = p + front_pad;
	// 把bio清0。后面两个参数是vec指针和vec数量
	bio_init(bio, NULL, 0);

	// 所需要的vec大于inline_vec
	if (nr_iovecs > inline_vecs) {
		unsigned long idx = 0;

		// 分配对应数量的数组
		bvl = bvec_alloc(gfp_mask, nr_iovecs, &idx, &bs->bvec_pool);
		// 分配失败 && 和原始的标志不一样
		if (!bvl && gfp_mask != saved_gfp) {
			punt_bios_to_rescuer(bs);
			// 用原来的分配标志再试一次
			gfp_mask = saved_gfp;
			bvl = bvec_alloc(gfp_mask, nr_iovecs, &idx, &bs->bvec_pool);
		}

		// 还是分配失败，那没办法，只能失败
		if (unlikely(!bvl))
			goto err_free;

		// 走到这里表示分配成功

		// 把idx存在bi_flags里，BVEC_POOL_OFFSET=13
		bio->bi_flags |= idx << BVEC_POOL_OFFSET;
	} else if (nr_iovecs) {
		// 如果内部的vecs已经能满足需求，则使用内部的
		bvl = bio->bi_inline_vecs;
	}

	// 分配的数据池，释放的时候用
	bio->bi_pool = bs;
	// vecs的数量
	bio->bi_max_vecs = nr_iovecs;
	// bi_io_vec真正的指向，要么指向新分配的内存，要么指向inline-vec
	bio->bi_io_vec = bvl;
	return bio;

err_free:
	mempool_free(p, &bs->bio_pool);
	return NULL;
}

static void punt_bios_to_rescuer(struct bio_set *bs)
{
	struct bio_list punt, nopunt;
	struct bio *bio;

	if (WARN_ON_ONCE(!bs->rescue_workqueue))
		return;
	/*
	 * In order to guarantee forward progress we must punt only bios that
	 * were allocated from this bio_set; otherwise, if there was a bio on
	 * there for a stacking driver higher up in the stack, processing it
	 * could require allocating bios from this bio_set, and doing that from
	 * our own rescuer would be bad.
	 *
	 * Since bio lists are singly linked, pop them all instead of trying to
	 * remove from the middle of the list:
	 */

	bio_list_init(&punt);
	bio_list_init(&nopunt);

	while ((bio = bio_list_pop(&current->bio_list[0])))
		bio_list_add(bio->bi_pool == bs ? &punt : &nopunt, bio);
	current->bio_list[0] = nopunt;

	bio_list_init(&nopunt);
	while ((bio = bio_list_pop(&current->bio_list[1])))
		bio_list_add(bio->bi_pool == bs ? &punt : &nopunt, bio);
	current->bio_list[1] = nopunt;

	spin_lock(&bs->rescue_lock);
	bio_list_merge(&bs->rescue_list, &punt);
	spin_unlock(&bs->rescue_lock);

	queue_work(bs->rescue_workqueue, &bs->rescue_work);
}

void bio_init(struct bio *bio, struct bio_vec *table,
	      unsigned short max_vecs)
{
	memset(bio, 0, sizeof(*bio));
	atomic_set(&bio->__bi_remaining, 1);
	// 引用计数为1
	atomic_set(&bio->__bi_cnt, 1);

	// vec数组
	bio->bi_io_vec = table;
	// vec的数量
	bio->bi_max_vecs = max_vecs;
}
```

## bio_advance
```c
void bio_advance(struct bio *bio, unsigned bytes)
{
	// todo: 度量和加密后面再看
	if (bio_integrity(bio))
		bio_integrity_advance(bio, bytes);

	bio_crypt_advance(bio, bytes);
	// 前进对应的Bytes
	bio_advance_iter(bio, &bio->bi_iter, bytes);
}

static inline void bio_advance_iter(const struct bio *bio,
				    struct bvec_iter *iter, unsigned int bytes)
{
	// 起点前进byte个扇区
	iter->bi_sector += bytes >> 9;

	if (bio_no_advance_iter(bio))
		// 没有迭代器，直接从大小里减去byte数量
		iter->bi_size -= bytes;
	else
		bvec_iter_advance(bio->bi_io_vec, iter, bytes);
		/* TODO: It is reasonable to complete bio with error here. */
}

static inline bool bvec_iter_advance(const struct bio_vec *bv,
		struct bvec_iter *iter, unsigned bytes)
{
	// 当前处理的bio索引
	unsigned int idx = iter->bi_idx;

	// 要前进的数量超过了bi的大小，设置bio的大小为0
	if (WARN_ONCE(bytes > iter->bi_size,
		     "Attempted to advance past end of bvec iter\n")) {
		iter->bi_size = 0;
		return false;
	}

	// 从总大小里减去bytes
	iter->bi_size -= bytes;

	// 加上已完成的大小
	bytes += iter->bi_bvec_done;

	// 计算要前进的bytes跨越子几个bv，则前进到对应的idx
	while (bytes && bytes >= bv[idx].bv_len) {
		bytes -= bv[idx].bv_len;
		idx++;
	}

	// 设置当前在处理的idx
	iter->bi_idx = idx;
	// 设置已完成的大小
	iter->bi_bvec_done = bytes;
	return true;
}

static inline bool bio_no_advance_iter(const struct bio *bio)
{
	// 这些操作没有iter
	return bio_op(bio) == REQ_OP_DISCARD ||
	       bio_op(bio) == REQ_OP_SECURE_ERASE ||
	       bio_op(bio) == REQ_OP_WRITE_SAME ||
	       bio_op(bio) == REQ_OP_WRITE_ZEROES;
}
```

## bio_chain
```c
void bio_chain(struct bio *bio, struct bio *parent)
{
	// 这2个如果有值，说明已经提交了？
	BUG_ON(bio->bi_private || bio->bi_end_io);

	// private指向父bio
	bio->bi_private = parent;
	// bio完成时调用的函数
	bio->bi_end_io	= bio_chain_endio;
	// 设置标志及递增计数
	bio_inc_remaining(parent);
}

static inline void bio_inc_remaining(struct bio *bio)
{
	// 给bio设置BIO_CHAIN标志
	bio_set_flag(bio, BIO_CHAIN);
	smp_mb__before_atomic();
	// 增加__bi_remaining
	atomic_inc(&bio->__bi_remaining);
}
```

## bio_get_first_bvec
```c
static inline void bio_get_first_bvec(struct bio *bio, struct bio_vec *bv)
{
	*bv = mp_bvec_iter_bvec(bio->bi_io_vec, bio->bi_iter);
}

#define mp_bvec_iter_bvec(bvec, iter)				\
((struct bio_vec) {						\
	.bv_page	= mp_bvec_iter_page((bvec), (iter)),	\
	.bv_len		= mp_bvec_iter_len((bvec), (iter)),	\
	.bv_offset	= mp_bvec_iter_offset((bvec), (iter)),	\
})



/* multi-page (mp_bvec) helpers */
#define mp_bvec_iter_page(bvec, iter)				\
	(__bvec_iter_bvec((bvec), (iter))->bv_page)

#define __bvec_iter_bvec(bvec, iter)	(&(bvec)[(iter).bi_idx])

#define mp_bvec_iter_len(bvec, iter)				\
	min((iter).bi_size,					\
	    __bvec_iter_bvec((bvec), (iter))->bv_len - (iter).bi_bvec_done)

#define mp_bvec_iter_offset(bvec, iter)				\
	(__bvec_iter_bvec((bvec), (iter))->bv_offset + (iter).bi_bvec_done)
```

## bio_get_last_bvec
```c
static inline void bio_get_last_bvec(struct bio *bio, struct bio_vec *bv)
{
	struct bvec_iter iter = bio->bi_iter;
	int idx;

	bio_get_first_bvec(bio, bv);
	if (bv->bv_len == bio->bi_iter.bi_size)
		return;		/* this bio only has a single bvec */

	bio_advance_iter(bio, &iter, iter.bi_size);

	if (!iter.bi_bvec_done)
		idx = iter.bi_idx - 1;
	else	/* in the middle of bvec */
		idx = iter.bi_idx;

	*bv = bio->bi_io_vec[idx];

	/*
	 * iter.bi_bvec_done records actual length of the last bvec
	 * if this bio ends in the middle of one io vector
	 */
	if (iter.bi_bvec_done)
		bv->bv_len = iter.bi_bvec_done;
}
```



## bio_issue_init
```c
static inline void bio_issue_init(struct bio_issue *issue,
				       sector_t size)
{
	size &= (1ULL << BIO_ISSUE_SIZE_BITS) - 1;
	issue->value = ((issue->value & BIO_ISSUE_RES_MASK) |
			(ktime_get_ns() & BIO_ISSUE_TIME_MASK) |
			((u64)size << BIO_ISSUE_SIZE_SHIFT));
}
```

## bio_put
```c
void bio_put(struct bio *bio)
{
	if (!bio_flagged(bio, BIO_REFFED))
		// 没有被引用直接释放
		bio_free(bio);
	else {
		// 走到这个分支，表示有引用标志

		// 有引用标志但是引用计数为0,有bug
		BIO_BUG_ON(!atomic_read(&bio->__bi_cnt));

		// 递减引用之后，如果计数为0,则释放bio
		if (atomic_dec_and_test(&bio->__bi_cnt))
			bio_free(bio);
	}
}

static void bio_free(struct bio *bio)
{
	struct bio_set *bs = bio->bi_pool;
	void *p;

	bio_uninit(bio);

	if (bs) {
		// 先释放vec
		bvec_free(&bs->bvec_pool, bio->bi_io_vec, BVEC_POOL_IDX(bio));

		p = bio;
		// bio减去前置填充才是当时分配的指针
		p -= bs->front_pad;

		// 从内存池释放
		mempool_free(p, &bs->bio_pool);
	} else {
		// 如果没有bs，则表示从slab里分配的，直接调用kfree
		kfree(bio);
	}
}

void bio_uninit(struct bio *bio)
{
#ifdef CONFIG_BLK_CGROUP
	if (bio->bi_blkg) {
		blkg_put(bio->bi_blkg);
		bio->bi_blkg = NULL;
	}
#endif
	// 度量相关
	if (bio_integrity(bio))
		bio_integrity_free(bio);

	// 如果有加密上下文，则释放之
	bio_crypt_free_ctx(bio);
}
```