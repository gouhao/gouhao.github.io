# scsi 设备
源码基于5.10

## scsi_alloc_sdev
```c
static struct scsi_device *scsi_alloc_sdev(struct scsi_target *starget,
					   u64 lun, void *hostdata)
{
	struct scsi_device *sdev;
	int display_failure_msg = 1, ret;
	struct Scsi_Host *shost = dev_to_shost(starget->dev.parent);

	// 分配sdev
	sdev = kzalloc(sizeof(*sdev) + shost->transportt->device_size,
		       GFP_KERNEL);
	if (!sdev)
		goto out;

	sdev->vendor = scsi_null_device_strs;
	sdev->model = scsi_null_device_strs;
	sdev->rev = scsi_null_device_strs;
	// 设置 host
	sdev->host = shost;
	sdev->queue_ramp_up_period = SCSI_DEFAULT_RAMP_UP_PERIOD;
	sdev->id = starget->id;
	sdev->lun = lun;
	sdev->channel = starget->channel;
	mutex_init(&sdev->state_mutex);
	sdev->sdev_state = SDEV_CREATED;
	INIT_LIST_HEAD(&sdev->siblings);
	INIT_LIST_HEAD(&sdev->same_target_siblings);
	INIT_LIST_HEAD(&sdev->starved_entry);
	INIT_LIST_HEAD(&sdev->event_list);
	spin_lock_init(&sdev->list_lock);
	mutex_init(&sdev->inquiry_mutex);
	// 初始化2个工作线程
	INIT_WORK(&sdev->event_work, scsi_evt_thread);
	INIT_WORK(&sdev->requeue_work, scsi_requeue_run_queue);

	// 父节点是target
	sdev->sdev_gendev.parent = get_device(&starget->dev);
	sdev->sdev_target = starget;

	// host的数据
	sdev->hostdata = hostdata;

	// 最大阻塞为3
	sdev->max_device_blocked = SCSI_DEFAULT_DEVICE_BLOCKED;

	/*
	 * Some low level driver could use device->type
	 */
	sdev->type = -1;

	/*
	 * Assume that the device will have handshaking problems,
	 * and then fix this field later if it turns out it
	 * doesn't
	 */
	sdev->borken = 1;

	// 分配并初始化dev的请求队列
	sdev->request_queue = scsi_mq_alloc_queue(sdev);
	// 分配失败，则释放设备
	if (!sdev->request_queue) {
		/* release fn is set up in scsi_sysfs_device_initialise, so
		 * have to free and put manually here */
		put_device(&starget->dev);
		kfree(sdev);
		goto out;
	}
	// 增加队列引用
	WARN_ON_ONCE(!blk_get_queue(sdev->request_queue));
	// 在queuedata里指向sdev
	sdev->request_queue->queuedata = sdev;

	// 修改队列深度
	scsi_change_queue_depth(sdev, sdev->host->cmd_per_lun ?
					sdev->host->cmd_per_lun : 1);

	// 在sys文件系统上注册
	scsi_sysfs_device_initialize(sdev);

	// todo: what is slave alloc
	if (shost->hostt->slave_alloc) {
		ret = shost->hostt->slave_alloc(sdev);
		if (ret) {
			/*
			 * if LLDD reports slave not present, don't clutter
			 * console with alloc failure messages
			 */
			if (ret == -ENXIO)
				display_failure_msg = 0;
			goto out_device_destroy;
		}
	}

	return sdev;

out_device_destroy:
	__scsi_remove_device(sdev);
out:
	if (display_failure_msg)
		printk(ALLOC_FAILURE_MSG, __func__);
	return NULL;
}

struct request_queue *scsi_mq_alloc_queue(struct scsi_device *sdev)
{
	// 分配并初始化队列
	sdev->request_queue = blk_mq_init_queue(&sdev->host->tag_set);
	if (IS_ERR(sdev->request_queue))
		return NULL;

	// 私有数据
	sdev->request_queue->queuedata = sdev;
	// 初始化队列的一些属性
	__scsi_init_queue(sdev->host, sdev->request_queue);
	// 设置支持scsi_passthrough命令
	blk_queue_flag_set(QUEUE_FLAG_SCSI_PASSTHROUGH, sdev->request_queue);
	return sdev->request_queue;
}

void __scsi_init_queue(struct Scsi_Host *shost, struct request_queue *q)
{
	struct device *dev = shost->dma_dev;

	// 设置最大segment数
	blk_queue_max_segments(q, min_t(unsigned short, shost->sg_tablesize,
					SG_MAX_SEGMENTS));

	if (scsi_host_prot_dma(shost)) {
		shost->sg_prot_tablesize =
			min_not_zero(shost->sg_prot_tablesize,
				     (unsigned short)SCSI_MAX_PROT_SG_SEGMENTS);
		BUG_ON(shost->sg_prot_tablesize < shost->sg_tablesize);
		blk_queue_max_integrity_segments(q, shost->sg_prot_tablesize);
	}

	// 最大扇区数
	if (dev->dma_mask) {
		shost->max_sectors = min_t(unsigned int, shost->max_sectors,
				dma_max_mapping_size(dev) >> SECTOR_SHIFT);
	}
	blk_queue_max_hw_sectors(q, shost->max_sectors);

	// 初始化bounce
	if (shost->unchecked_isa_dma)
		blk_queue_bounce_limit(q, BLK_BOUNCE_ISA);
	blk_queue_segment_boundary(q, shost->dma_boundary);
	// segments边界
	dma_set_seg_boundary(dev, shost->dma_boundary);

	// 最大段长度
	blk_queue_max_segment_size(q, shost->max_segment_size);
	blk_queue_virt_boundary(q, shost->virt_boundary_mask);
	// dma最大段大小
	dma_set_max_seg_size(dev, queue_max_segment_size(q));

	// dma对齐
	blk_queue_dma_alignment(q, max(4, dma_get_cache_alignment()) - 1);
}

int scsi_change_queue_depth(struct scsi_device *sdev, int depth)
{
	// 设置dev的队列深度
	if (depth > 0) {
		sdev->queue_depth = depth;
		wmb();
	}

	// 设置请求队列的深度
	if (sdev->request_queue)
		blk_set_queue_depth(sdev->request_queue, depth);

	// 设置之后返回队列长度
	return sdev->queue_depth;
}
```

