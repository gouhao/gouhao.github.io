## blkdev_issue_flush
blkdev_issue_flush是调用submit_bio中的一个入口
```c
int blkdev_issue_flush(struct block_device *bdev, gfp_t gfp_mask)
{
	struct bio *bio;
	int ret = 0;

	// 分配一个bio结构
	bio = bio_alloc(gfp_mask, 0);
	// 给bio设置磁盘及分区号
	bio_set_dev(bio, bdev);
	bio->bi_opf = REQ_OP_WRITE | REQ_PREFLUSH;

	// 提交bio，这个函数里会设置完成的回调及超时相关的东西
	ret = submit_bio_wait(bio);
	bio_put(bio);
	return ret;
}

int submit_bio_wait(struct bio *bio)
{
	// 完成量
	DECLARE_COMPLETION_ONSTACK_MAP(done, bio->bi_disk->lockdep_map);
	unsigned long hang_check;

	// 先设置好完成量
	bio->bi_private = &done;
	// 完成io时的回调
	bio->bi_end_io = submit_bio_wait_endio;
	// 请求标志是同步
	bio->bi_opf |= REQ_SYNC;
	submit_bio(bio);

	// 超时时间
	hang_check = sysctl_hung_task_timeout_secs;

	if (hang_check)
		// 如果设置了超时时间，则等待对应的时间
		while (!wait_for_completion_io_timeout(&done,
					hang_check * (HZ/2)))
			;
	else
		// 否则一直等待
		wait_for_completion_io(&done);

	// 把blk的状态码，转换成标准的错误码
	return blk_status_to_errno(bio->bi_status);
}
```

```c

```