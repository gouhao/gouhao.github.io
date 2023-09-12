# 提交bio
源码基于5.10
## 1. submit_bh
文件系统层提交bio的入口，大多是从这里开始。
```c
int submit_bh(int op, int op_flags, struct buffer_head *bh)
{
	return submit_bh_wbc(op, op_flags, bh, 0, NULL);
}

static int submit_bh_wbc(int op, int op_flags, struct buffer_head *bh,
			 enum rw_hint write_hint, struct writeback_control *wbc)
{
	struct bio *bio;

	// bh没有锁
	BUG_ON(!buffer_locked(bh));

	// bh没有映射
	BUG_ON(!buffer_mapped(bh));

	// 要有b_end_io，这个是请求结束时的回调
	BUG_ON(!bh->b_end_io);

	// 有BH_Delay标志，BH_Delay：buffer没有在磁盘上分配空间
	BUG_ON(buffer_delay(bh));
	// 有BH_Unwritten标志，BH_Unwritten：在磁盘上已分配空闲，但是没有写入过
	BUG_ON(buffer_unwritten(bh));

	// 设置BH_Req标志。如果之前req标志已设置 && 而且当前op是写
	if (test_set_buffer_req(bh) && (op == REQ_OP_WRITE))
		// 清除BH_Write_EIO标志
		clear_buffer_write_io_error(bh);

	// 分配一个bio， GFP_NOIO 表示在分配内存的时候不能进行IO
	// 第2个参数表示需要几个vec数量
	bio = bio_alloc(GFP_NOIO, 1);

	// 加密相关。todo：后面看
	fscrypt_set_bio_crypt_ctx_bh(bio, bh, GFP_NOIO);

	// 所请求扇区的起点
	// bh->b_size是块大小,bh->b_size >> 9 = bh->b_size / 512 = 一个块里有多少个扇区
	bio->bi_iter.bi_sector = bh->b_blocknr * (bh->b_size >> 9);
	// 设置磁盘、分区号等内容
	bio_set_dev(bio, bh->b_bdev);
	bio->bi_write_hint = write_hint;

	// 把page添加到bio里
	bio_add_page(bio, bh->b_page, bh->b_size, bh_offset(bh));
	// b_size必须是一样的
	BUG_ON(bio->bi_iter.bi_size != bh->b_size);

	// 设置完成io的回调函数
	bio->bi_end_io = end_bio_bh_io_sync;
	// 私有数据是bh
	bio->bi_private = bh;

	// 有元数据标志BH_Meta
	if (buffer_meta(bh))
		op_flags |= REQ_META;
	// 有优先级标志BH_Prio
	if (buffer_prio(bh))
		op_flags |= REQ_PRIO;
	// 设置bi_opf = op | op_flags
	bio_set_op_attrs(bio, op, op_flags);

	// 根据磁盘扇区的最大值来截断bio。
	guard_bio_eod(bio);

	// 把bio和cgroup关联。todo: cg后面看
	if (wbc) {
		wbc_init_bio(wbc, bio);
		wbc_account_cgroup_owner(wbc, bh->b_page, bh->b_size);
	}

	// 提交bio
	submit_bio(bio);
	return 0;
}

#define bio_set_dev(bio, bdev) 			\
do {						\
	// 与要设置的磁盘不相等，则清除flag
	if ((bio)->bi_disk != (bdev)->bd_disk)	\
		bio_clear_flag(bio, BIO_THROTTLED);\
	// 设置磁盘
	(bio)->bi_disk = (bdev)->bd_disk;	\
	// 设置分区号
	(bio)->bi_partno = (bdev)->bd_partno;	\
	// blkcg相关
	bio_associate_blkg(bio);		\
} while (0)
```

### 1.1 截断bio
```c
void guard_bio_eod(struct bio *bio)
{
	sector_t maxsector;
	struct hd_struct *part;

	rcu_read_lock();
	// 获取分区结构
	part = __disk_get_part(bio->bi_disk, bio->bi_partno);

	// 获取最大扇区数
	if (part)
		maxsector = part_nr_sects_read(part);
	else
		maxsector = get_capacity(bio->bi_disk);
	rcu_read_unlock();

	// 扇区数是0?
	if (!maxsector)
		return;

	/*
	 * io的起点超过了最大扇区,放它过去,在io层会返回EIO
	 */
	if (unlikely(bio->bi_iter.bi_sector >= maxsector))
		return;

	// 减去起点,就是剩余最大的扇区数
	maxsector -= bio->bi_iter.bi_sector;
	// bio->bi_iter.bi_size >> 9 是这次请求的扇区数,如果小于最大扇区数,则不需要截断
	if (likely((bio->bi_iter.bi_size >> 9) <= maxsector))
		return;

	// 截断到最大允许的大小
	bio_truncate(bio, maxsector << 9);
}

void bio_truncate(struct bio *bio, unsigned new_size)
{
	struct bio_vec bv;
	struct bvec_iter iter;
	unsigned int done = 0;
	bool truncated = false;

	// 新大小比bio需要的大,不用截断了
	if (new_size >= bio->bi_iter.bi_size)
		return;

	// 只对读截断
	if (bio_op(bio) != REQ_OP_READ)
		goto exit;

	// 遍历每个vec
	bio_for_each_segment(bv, bio, iter) {

		// 已达到最大的长度
		if (done + bv.bv_len > new_size) {
			unsigned offset;

			if (!truncated)
				// 没有截断过,算出需要截断的起点
				offset = new_size - done;
			else
				// 如果已经截断过,那起点就是0
				offset = 0;
			// 把page里offset开始的地方清0
			zero_user(bv.bv_page, bv.bv_offset + offset,
				  bv.bv_len - offset);
			truncated = true;
		}
		done += bv.bv_len;
	}

 exit:
	// 更新到新size
	/*
	 * 不要修改bvec表,它是不可变的,由于fs的用户会遍历所有的页通过bio_for_each_segment_all在end_bio回调里
	 * 更新bi_size来截断bio足够了,因为我们会使用正确的bvec给驱动
	 */
	bio->bi_iter.bi_size = new_size;
}
```

## 2. submit_bio
```c
blk_qc_t submit_bio(struct bio *bio)
{
	// todo: blkcg相关
	if (blkcg_punt_bio_submit(bio))
		return BLK_QC_T_NONE;

	// 检查bio是否携带了数据，这个if里主要是统计相关
	if (bio_has_data(bio)) {
		unsigned int count;

		// REQ_OP_WRITE_SAME：在同一个扇区写多次
		if (unlikely(bio_op(bio) == REQ_OP_WRITE_SAME))
			// 获取队列限制的逻辑块大小
			count = queue_logical_block_size(bio->bi_disk->queue) >> 9;
		else
			// 所请求的扇区数量
			count = bio_sectors(bio);

		// 统计读/写事件
		if (op_is_write(bio_op(bio))) {
			count_vm_events(PGPGOUT, count);
		} else {
			task_io_account_read(bio->bi_iter.bi_size);
			count_vm_events(PGPGIN, count);
		}

		// block_dump是一个/proc/sys接口,打开它会在日志里输出 log 
		if (unlikely(block_dump)) {
			char b[BDEVNAME_SIZE];
			printk(KERN_DEBUG "%s(%d): %s block %Lu on %s (%u sectors)\n",
			current->comm, task_pid_nr(current),
				op_is_write(bio_op(bio)) ? "WRITE" : "READ",
				(unsigned long long)bio->bi_iter.bi_sector,
				bio_devname(bio, b), count);
		}
	}

	// 读请求里有用户空间所使用的页面
	if (unlikely(bio_op(bio) == REQ_OP_READ &&
	    bio_flagged(bio, BIO_WORKINGSET))) {
		unsigned long pflags;
		blk_qc_t ret;

		// 标记一个进程进入内存停顿的状态?
		psi_memstall_enter(&pflags);
		// 提交bio
		ret = submit_bio_noacct(bio);
		psi_memstall_leave(&pflags);

		return ret;
	}

	// 普通的提交bio, 大多数情况走这个路径
	return submit_bio_noacct(bio);
}

static inline bool bio_has_data(struct bio *bio)
{
	// 主要检查 bi_size 是否有值
	if (bio &&
	    bio->bi_iter.bi_size &&
	    bio_op(bio) != REQ_OP_DISCARD &&
	    bio_op(bio) != REQ_OP_SECURE_ERASE &&
	    bio_op(bio) != REQ_OP_WRITE_ZEROES)
		return true;

	return false;
}
```

## 3. submit_bio_noacct
```c
blk_qc_t submit_bio_noacct(struct bio *bio)
{
	// 先检查请求是否合法
	if (!submit_bio_checks(bio))
		return BLK_QC_T_NONE;

	// bio_list不为0，说明当前进程正在执行submit_io操作，则把这些
	// 请求收集到这个列表里，在之后的submit操作里会自动提交这些bio
	if (current->bio_list) {
		bio_list_add(&current->bio_list[0], bio);
		return BLK_QC_T_NONE;
	}

	// 如果磁盘驱动没有提交函数就调用通用函数
	if (!bio->bi_disk->fops->submit_bio)
		return __submit_bio_noacct_mq(bio);
	
	// 磁盘有submit_bio就调用这个
	return __submit_bio_noacct(bio);
}
```
### 3.1 submit_bio_checks
```c
static noinline_for_stack bool submit_bio_checks(struct bio *bio)
{
	// 磁盘的请求队列
	struct request_queue *q = bio->bi_disk->queue;
	blk_status_t status = BLK_STS_IOERR;
	struct blk_plug *plug;

	// 标识这个函数可能会睡眠
	might_sleep();

	// 获取当前进程的plug。plug是一种机制，在提交过程中把请求先放到plug里缓冲
	// 最后在调用end_plug时，再批量提交请求。
	plug = blk_mq_plug(q, bio);
	// plug有不等待标志，则请求也不等待
	if (plug && plug->nowait)
		bio->bi_opf |= REQ_NOWAIT;

	// 如果bio不阻塞请求的话，要判断设备是否支持不阻塞请求
	if ((bio->bi_opf & REQ_NOWAIT) && !blk_queue_nowait(q))
		goto not_supported;

	// 判断请求是否应该失败，一般都返回false。
	if (should_fail_bio(bio))
		goto end_io;

	if (bio->bi_partno) {
		// 请求的设备是分区，把bio请求的开始扇区映射到分区对应的扇区
		if (unlikely(blk_partition_remap(bio)))
			goto end_io;
	} else {
		// 请求的设备是整个块设备

		// 检查只读请求合法性。这个函数只返回false
		if (unlikely(bio_check_ro(bio, &bio->bi_disk->part0)))
			goto end_io;
		// 检查所请求的扇区是否合法,
		// get_capacity是获取0与分区的最大扇区数，也就是整个磁盘的扇区数
		if (unlikely(bio_check_eod(bio, get_capacity(bio->bi_disk))))
			goto end_io;
	}

	// 操作是flush && 设备不支持回写缓存
	if (op_is_flush(bio->bi_opf) &&
	    !test_bit(QUEUE_FLAG_WC, &q->queue_flags)) {
		// 则取消对应的标志
		bio->bi_opf &= ~(REQ_PREFLUSH | REQ_FUA);

		// 如果没有请求的扇区，则直接标志成功，返回
		// bio_sectors获取本次请求的扇区数量
		if (!bio_sectors(bio)) {
			status = BLK_STS_OK;
			goto end_io;
		}
	}

	// 设备不支持poll，就取消REQ_HIPRI
	if (!test_bit(QUEUE_FLAG_POLL, &q->queue_flags))
		bio->bi_opf &= ~REQ_HIPRI;

	// 对行列的请求类型，进行检查
	switch (bio_op(bio)) {
	case REQ_OP_DISCARD:
		// 丢弃分区
		// 如果队列没有QUEUE_FLAG_DISCARD标志，则不支持
		if (!blk_queue_discard(q))
			goto not_supported;
		break;
	case REQ_OP_SECURE_ERASE:
		// 安全擦除扇区
		// 判断标志QUEUE_FLAG_SECERASE
		if (!blk_queue_secure_erase(q))
			goto not_supported;
		break;
	case REQ_OP_WRITE_SAME:
		// 多次写同一个扇区
		// 最大写同一个扇区数为0，则表示不支持多次写同一个扇区
		if (!q->limits.max_write_same_sectors)
			goto not_supported;
		break;
	case REQ_OP_ZONE_APPEND:
		// zone 设备相关。todo: zone设备后面再看
		status = blk_check_zone_append(q, bio);
		if (status != BLK_STS_OK)
			goto end_io;
		break;
	case REQ_OP_ZONE_RESET:
	case REQ_OP_ZONE_OPEN:
	case REQ_OP_ZONE_CLOSE:
	case REQ_OP_ZONE_FINISH:
		// zone设备的控制指令
		if (!blk_queue_is_zoned(q))
			goto not_supported;
		break;
	case REQ_OP_ZONE_RESET_ALL:
		// zone设备的控制指令
		if (!blk_queue_is_zoned(q) || !blk_queue_zone_resetall(q))
			goto not_supported;
		break;
	case REQ_OP_WRITE_ZEROES:
		// 多次写0填充扇区
		// 最大限制为0则表示不可用
		if (!q->limits.max_write_zeroes_sectors)
			goto not_supported;
		break;
	default:
		break;
	}

	// 创建io_context，如果没有的话
	if (unlikely(!current->io_context))
		create_task_io_context(current, GFP_ATOMIC, q->node);

	// 限流相关
	if (blk_throtl_bio(bio))
		return false;

	// cgroup相关，后面再看
	blk_cgroup_bio_start(bio);
	// 初始化bio->bi_issue->value，
	// 这个value里保存了请求发布的时间和请求的扇区数
	blkcg_bio_issue_init(bio);

	// 当前bio没有过trace，就执行trace，trace完设置这个标志
	if (!bio_flagged(bio, BIO_TRACE_COMPLETION)) {
		trace_block_bio_queue(q, bio);
		// 这个标志表示在完成的时候也要打trace
		bio_set_flag(bio, BIO_TRACE_COMPLETION);
	}
	// 没有错误，返回true
	return true;

not_supported:
	// 不支持
	status = BLK_STS_NOTSUPP;
end_io:
	bio->bi_status = status;
	// 结束io
	bio_endio(bio);
	return false;
}
```

#### 3.1.1 重新映射扇区
```c
static inline int blk_partition_remap(struct bio *bio)
{
	struct hd_struct *p;
	int ret = -EIO;

	rcu_read_lock();
	// 获取分区，这个就是从磁盘的分区表里获取partno的分区
	p = __disk_get_part(bio->bi_disk, bio->bi_partno);
	// 这3个unlikely一般都不会走
	if (unlikely(!p))
		goto out;
	if (unlikely(should_fail_request(p, bio->bi_iter.bi_size)))
		goto out;
	// 检查只读io请求的合法性，这个只检查写请求
	if (unlikely(bio_check_ro(bio, p)))
		goto out;

	// bio所请求的扇区数量
	if (bio_sectors(bio)) {

		// 检查所请求的扇区区间是否合法
		// part_nr_sects_read获取分区的扇区数
		if (bio_check_eod(bio, part_nr_sects_read(p)))
			goto out;

		// 把bio请求的起始扇区号转换成整个磁盘的扇区号，
		// start_sect是分区的起始扇区号，
		bio->bi_iter.bi_sector += p->start_sect;
		trace_block_bio_remap(bio->bi_disk->queue, bio, part_devt(p),
				      bio->bi_iter.bi_sector - p->start_sect);
	}
	// 清空分区号
	bio->bi_partno = 0;
	ret = 0;
out:
	rcu_read_unlock();
	return ret;
}

struct hd_struct *__disk_get_part(struct gendisk *disk, int partno)
{
	// 分区表
	struct disk_part_tbl *ptbl = rcu_dereference(disk->part_tbl);

	// 分区号判断是否非法
	if (unlikely(partno < 0 || partno >= ptbl->len))
		return NULL;
	// 返回对应的分区
	return rcu_dereference(ptbl->part[partno]);
}
```
#### 3.1.2 检查操作是否合法
```c
static inline bool bio_check_ro(struct bio *bio, struct hd_struct *part)
{
	const int op = bio_op(bio);

	// 有policy && 是写操作
	if (part->policy && op_is_write(op)) {
		char b[BDEVNAME_SIZE];

		// 如果是刷出操作，但是不请求扇区
		if (op_is_flush(bio->bi_opf) && !bio_sectors(bio))
			return false;

		WARN_ONCE(1,
		       "Trying to write to read-only block-device %s (partno %d)\n",
			bio_devname(bio, b), part->partno);
		/* Older lvm-tools actually trigger this */
		return false;
	}

	return false;
}

static inline int bio_check_eod(struct bio *bio, sector_t maxsector)
{
	// bio所需要的扇区数
	unsigned int nr_sectors = bio_sectors(bio);

	if (nr_sectors && maxsector &&
	    (nr_sectors > maxsector || // 所需扇区数量比最大的还大
	     bio->bi_iter.bi_sector > maxsector - nr_sectors)) { // 开始的扇区数比剩余的扇区数大
		handle_bad_sector(bio, maxsector);
		return -EIO;
	}
	return 0;
}
```
#### 3.1.3 创建io context
```c
int create_task_io_context(struct task_struct *task, gfp_t gfp_flags, int node)
{
	struct io_context *ioc;
	int ret;

	// 分配上下文并置0
	ioc = kmem_cache_alloc_node(iocontext_cachep, gfp_flags | __GFP_ZERO,
				    node);
	if (unlikely(!ioc))
		return -ENOMEM;

	/* 初始化 */
	atomic_long_set(&ioc->refcount, 1);
	atomic_set(&ioc->nr_tasks, 1);
	atomic_set(&ioc->active_ref, 1);
	spin_lock_init(&ioc->lock);
	INIT_RADIX_TREE(&ioc->icq_tree, GFP_ATOMIC);
	INIT_HLIST_HEAD(&ioc->icq_list);

	// 释放work
	INIT_WORK(&ioc->release_work, ioc_release_fn);

	
	task_lock(task);

	// 进程没有ioc && (没有切换进程 || 进程也没有退出)
	if (!task->io_context &&
	    (task == current || !(task->flags & PF_EXITING)))
		task->io_context = ioc;
	else
		// 不符合上面条件的就释放ioc
		kmem_cache_free(iocontext_cachep, ioc);

	// 成功返回0，失败返回忙
	ret = task->io_context ? 0 : -EBUSY;

	task_unlock(task);

	return ret;
}
```

## 4. __submit_bio_noacct_mq
```c
static blk_qc_t __submit_bio_noacct_mq(struct bio *bio)
{
	// 栈上的bio_list
	struct bio_list bio_list[2] = { };
	blk_qc_t ret = BLK_QC_T_NONE;

	// 设置给进程，对应了submit_bio_noacct里的那个bio_list，
	// 在下面submit期间，如果又发起了提交会加到这个列表里
	current->bio_list = bio_list;

	do {
		// 磁盘
		struct gendisk *disk = bio->bi_disk;

		// 这个主要是增加队列的使用计数，增加成功返回0
		// 如果失败就continue
		if (unlikely(bio_queue_enter(bio) != 0))
			continue;

		// 初始化加密相关。todo: 加密后面再看
		if (!blk_crypto_bio_prep(&bio)) {
			blk_queue_exit(disk->queue);
			ret = BLK_QC_T_NONE;
			continue;
		}

		// 调用block层的提交bio
		ret = blk_mq_submit_bio(bio);

		// 如submit_bio_noacct里的代码，如果在提交过程中又有人进行提交操作，
		// 则会先加到current->bio_list里，这里就是循环处理这种情况
	} while ((bio = bio_list_pop(&bio_list[0])));

	// 重置当前进程的bio_list
	current->bio_list = NULL;
	return ret;
}

static inline int bio_queue_enter(struct bio *bio)
{
	struct request_queue *q = bio->bi_disk->queue;
	// 不阻塞
	bool nowait = bio->bi_opf & REQ_NOWAIT;
	int ret;

	// 这个函数主要是递增q->q_usage_counter，返回0表示递增成功
	// 第2个参数表示不能递增的时候要不要等待
	ret = blk_queue_enter(q, nowait ? BLK_MQ_REQ_NOWAIT : 0);
	if (unlikely(ret)) {
		if (nowait && !blk_queue_dying(q))
			bio_wouldblock_error(bio);
		else
			bio_io_error(bio);
	}

	return ret;
}
```

## 5. __submit_bio_noacct
这是驱动有自己的提交函数时走的路径
```c
static blk_qc_t __submit_bio_noacct(struct bio *bio)
{
	// 在栈上分配的2个bio_list
	struct bio_list bio_list_on_stack[2];
	blk_qc_t ret = BLK_QC_T_NONE;

	// 如果bio->bi_next有值，那就是已经提交过了
	BUG_ON(bio->bi_next);

	// 把第0个bio_list的head, tail设置为0
	bio_list_init(&bio_list_on_stack[0]);

	// 设置current的bio_list，对应submit_bio_noacct()里的相关处理
	current->bio_list = bio_list_on_stack;

	// 这个大循环是为了处理在提交过程中继续提交bio请求
	do {
		// 获取磁盘的请求队列
		struct request_queue *q = bio->bi_disk->queue;
		// 这2个队列是保存在提交过程中，又新增的bio
		// lower保存的是不同队列的，same保存的是与当前bio是同一队列的请求
		struct bio_list lower, same;

		// 这个函数主要是递增q->q_usage_counter
		if (unlikely(bio_queue_enter(bio) != 0))
			continue;

		// 把0号列表的数据移到1号列表
		bio_list_on_stack[1] = bio_list_on_stack[0];
		// 重新初始化0列表
		bio_list_init(&bio_list_on_stack[0]);

		// 提交bio
		ret = __submit_bio(bio);

		// 初始化这2个队列
		bio_list_init(&lower);
		bio_list_init(&same);

		// bio_list_on_stack[0]不为空，说明在submit_bio期间又有人执行了submit操作
		while ((bio = bio_list_pop(&bio_list_on_stack[0])) != NULL)
			// 如果新提交的bio队列和最初的相同则放到same列表，反之，放到lower
			if (q == bio->bi_disk->queue)
				bio_list_add(&same, bio);
			else
				bio_list_add(&lower, bio);

		// 经过上面循环之后bio_list_on_stack[0]已经空了

		// bio_list_merge是把第2个参数链到第1个参数列表后面
		// 经过下面这3个合并，最终链表的顺序是：lower same bio_list_on_stack[1](这个列表里存的也是上一次的lower,same)
		bio_list_merge(&bio_list_on_stack[0], &lower);
		bio_list_merge(&bio_list_on_stack[0], &same);
		bio_list_merge(&bio_list_on_stack[0], &bio_list_on_stack[1]);
	} while ((bio = bio_list_pop(&bio_list_on_stack[0])));

	// 重置当前进程的bio_list
	current->bio_list = NULL;
	return ret;
}

static blk_qc_t __submit_bio(struct bio *bio)
{
	struct gendisk *disk = bio->bi_disk;
	blk_qc_t ret = BLK_QC_T_NONE;

	// 在加密上下文，就初始化它，否则直接返回true
	if (blk_crypto_bio_prep(&bio)) {
		// 设备没有自己的submit_bio就调用通用函数
		if (!disk->fops->submit_bio)
			return blk_mq_submit_bio(bio);
		// 否则调用设备自己的提交函数
		ret = disk->fops->submit_bio(bio);
	}
	// 和bio_queue_enter对应
	blk_queue_exit(disk->queue);
	return ret;
}
```

## bio_attempt_discard_merge
```c
static enum bio_merge_status bio_attempt_discard_merge(struct request_queue *q,
		struct request *req, struct bio *bio)
{
	// 当前请求丢弃的段数
	unsigned short segments = blk_rq_nr_discard_segments(req);

	// 丢弃的超过了最大值
	if (segments >= queue_max_discard_segments(q))
		goto no_merge;
	
	// 请求的扇区数已经大于最大的扇区数
	if (blk_rq_sectors(req) + bio_sectors(bio) >
	    blk_rq_get_max_sectors(req, blk_rq_pos(req)))
		goto no_merge;

	// qos
	rq_qos_merge(q, req, bio);

	// 把bio链表请求的链尾
	req->biotail->bi_next = bio;
	// 设置最后一个指向bio
	req->biotail = bio;
	// 请求的总字节数
	req->__data_len += bio->bi_iter.bi_size;
	// 请求的总段数
	req->nr_phys_segments = segments + 1;

	// 统计
	blk_account_io_merge_bio(req);
	return BIO_MERGE_OK;
no_merge:
	// 设置不合并标志
	req_set_nomerge(q, req);
	return BIO_MERGE_FAILED;
}

static inline unsigned short blk_rq_nr_discard_segments(struct request *rq)
{
	return max_t(unsigned short, rq->nr_phys_segments, 1);
}
```