# host
源码基于5.10

## scsi_host_alloc
```c
// sht是host的模板， privsize是hostdata的数据长度
struct Scsi_Host *scsi_host_alloc(struct scsi_host_template *sht, int privsize)
{
	struct Scsi_Host *shost;
	gfp_t gfp_mask = GFP_KERNEL;
	int index;

	// 有这2个则分配标志强制dma
	if (sht->unchecked_isa_dma && privsize)
		gfp_mask |= __GFP_DMA;

	// 分配host和私有数据的长度
	shost = kzalloc(sizeof(struct Scsi_Host) + privsize, gfp_mask);
	if (!shost)
		return NULL;

	// 先设置到默认的锁
	shost->host_lock = &shost->default_lock;
	spin_lock_init(shost->host_lock);

	/*
	一共有这几种状态：
	enum scsi_host_state {
		SHOST_CREATED = 1,
		SHOST_RUNNING,
		SHOST_CANCEL,
		SHOST_DEL,
		SHOST_RECOVERY,
		SHOST_CANCEL_RECOVERY,
		SHOST_DEL_RECOVERY,
	};
	*/
	shost->shost_state = SHOST_CREATED;

	// 各种列表、锁、队列初始化
	INIT_LIST_HEAD(&shost->__devices);
	INIT_LIST_HEAD(&shost->__targets);
	INIT_LIST_HEAD(&shost->eh_cmd_q);
	INIT_LIST_HEAD(&shost->starved_list);
	init_waitqueue_head(&shost->host_wait);
	mutex_init(&shost->scan_mutex);

	// 获取一个id作为host的标识
	index = ida_simple_get(&host_index_ida, 0, 0, GFP_KERNEL);
	if (index < 0) {
		kfree(shost);
		return NULL;
	}
	shost->host_no = index;

	// dma通道？
	shost->dma_channel = 0xff;

	/* 设置默认值，在本函数返回后，低层设备会覆盖这些值 */
	shost->max_channel = 0;
	shost->max_id = 8;
	shost->max_lun = 8;

	// 先设置空白的传输模板
	shost->transportt = &blank_transport_template;

	// 命令默认最大长度
	shost->max_cmd_len = 12;
	// 设置模板
	shost->hostt = sht;
	// 设置模板里的各种数据到host里
	shost->this_id = sht->this_id;
	shost->can_queue = sht->can_queue;
	shost->sg_tablesize = sht->sg_tablesize;
	shost->sg_prot_tablesize = sht->sg_prot_tablesize;
	shost->cmd_per_lun = sht->cmd_per_lun;
	shost->unchecked_isa_dma = sht->unchecked_isa_dma;
	shost->no_write_same = sht->no_write_same;
	shost->host_tagset = sht->host_tagset;

	// shost_eh_deadline是超时时间？-1表示永不超时？
	// 没有eh_host_reset_handler函数，也会永不超时
	if (shost_eh_deadline == -1 || !sht->eh_host_reset_handler)
		shost->eh_deadline = -1;
	else if ((ulong) shost_eh_deadline * HZ > INT_MAX) {
		// 超时时间太大，则限制
		shost_printk(KERN_WARNING, shost,
			     "eh_deadline %u too large, setting to %u\n",
			     shost_eh_deadline, INT_MAX / HZ);
		shost->eh_deadline = INT_MAX;
	} else
		// 设置指定的超时时间（单位是jiffi）
		shost->eh_deadline = shost_eh_deadline * HZ;

	// 如果没设置模式，默认为MODE_INITIATOR
	if (sht->supported_mode == MODE_UNKNOWN)
		shost->active_mode = MODE_INITIATOR;
	else
		shost->active_mode = sht->supported_mode;

	// 设置 最大被阻塞的次数，如果没设置，SCSI_DEFAULT_HOST_BLOCKED是7次
	if (sht->max_host_blocked)
		shost->max_host_blocked = sht->max_host_blocked;
	else
		shost->max_host_blocked = SCSI_DEFAULT_HOST_BLOCKED;

	// IO支持的最大扇区数，SCSI_DEFAULT_MAX_SECTORS是1024
	if (sht->max_sectors)
		shost->max_sectors = sht->max_sectors;
	else
		shost->max_sectors = SCSI_DEFAULT_MAX_SECTORS;

	// 最大segment数，BLK_MAX_SEGMENT_SIZE是65536
	if (sht->max_segment_size)
		shost->max_segment_size = sht->max_segment_size;
	else
		shost->max_segment_size = BLK_MAX_SEGMENT_SIZE;

	// dma边界，如果没设置的话是4G
	if (sht->dma_boundary)
		shost->dma_boundary = sht->dma_boundary;
	else
		shost->dma_boundary = 0xffffffff;

	if (sht->virt_boundary_mask)
		shost->virt_boundary_mask = sht->virt_boundary_mask;

	// 初始化gendev device
	device_initialize(&shost->shost_gendev);
	// 名字是host序号
	dev_set_name(&shost->shost_gendev, "host%d", shost->host_no);
	
	// gen设备连到总线上
	// 总线是scsi_bus
	shost->shost_gendev.bus = &scsi_bus_type;
	// 类型是scsi_host
	shost->shost_gendev.type = &scsi_host_type;

	// 初始化host device
	device_initialize(&shost->shost_dev);
	// 父节点是shost_gendev
	shost->shost_dev.parent = &shost->shost_gendev;
	// dev设备连到scsi_class上
	shost->shost_dev.class = &shost_class;
	// 名字也是host序号
	dev_set_name(&shost->shost_dev, "host%d", shost->host_no);
	// sysfs组
	shost->shost_dev.groups = scsi_sysfs_shost_attr_groups;

	// 启动eh线程, 这是错误报告线程
	shost->ehandler = kthread_run(scsi_error_handler, shost,
			"scsi_eh_%d", shost->host_no);
	// eh线程如果出错了,整个host都不能用
	if (IS_ERR(shost->ehandler)) {
		shost_printk(KERN_WARNING, shost,
			"error handler thread failed to spawn, error = %ld\n",
			PTR_ERR(shost->ehandler));
		shost->ehandler = NULL;
		goto fail;
	}

	// 用于abort SCSI命令的工作队列
	shost->tmf_work_q = alloc_workqueue("scsi_tmf_%d",
					WQ_UNBOUND | WQ_MEM_RECLAIM | WQ_SYSFS,
					   1, shost->host_no);
	// 这个工作队列也是必须的
	if (!shost->tmf_work_q) {
		shost_printk(KERN_WARNING, shost,
			     "failed to create tmf workq\n");
		goto fail;
	}
	// 在proc目录创建目录，名字为 sht->proc_name
	scsi_proc_hostdir_add(shost->hostt);
	return shost;
 fail:
	/*
	 * Host state is still SHOST_CREATED and that is enough to release
	 * ->shost_gendev. scsi_host_dev_release() will free
	 * dev_name(&shost->shost_dev).
	 */
	put_device(&shost->shost_gendev);

	return NULL;
}
```


## scsi_add_host
```c
static inline int __must_check scsi_add_host(struct Scsi_Host *host,
					     struct device *dev)
{
	return scsi_add_host_with_dma(host, dev, dev);
}

int scsi_add_host_with_dma(struct Scsi_Host *shost, struct device *dev,
			   struct device *dma_dev)
{
	struct scsi_host_template *sht = shost->hostt;
	int error = -EINVAL;

	shost_printk(KERN_INFO, shost, "%s\n",
			sht->info ? sht->info(shost) : sht->name);

	// 队列最大深度为0
	if (!shost->can_queue) {
		shost_printk(KERN_ERR, shost,
			     "can_queue = 0 no longer supported\n");
		goto fail;
	}

	// 根据cmd_per_lun修改硬件的队列深度，取最小值
	shost->cmd_per_lun = min_t(int, shost->cmd_per_lun,
				   shost->can_queue);

	// 创建sence slab.
	error = scsi_init_sense_cache(shost);
	if (error)
		goto fail;

	// 初始化shost->tag_set，分配及设置tag
	error = scsi_mq_setup_tags(shost);
	if (error)
		goto fail;

	// 设置gendev的父结点，父结点就是传进来的dev
	if (!shost->shost_gendev.parent)
		shost->shost_gendev.parent = dev ? dev : &platform_bus;
	// dma-dev如果为0, 和通用设备的父设备用成一个
	if (!dma_dev)
		dma_dev = shost->shost_gendev.parent;

	shost->dma_dev = dma_dev;

	// 电源管理相关
	pm_runtime_get_noresume(&shost->shost_gendev);
	pm_runtime_set_active(&shost->shost_gendev);
	pm_runtime_enable(&shost->shost_gendev);
	device_enable_async_suspend(&shost->shost_gendev);

	// 添加gen设备
	error = device_add(&shost->shost_gendev);
	if (error)
		goto out_disable_runtime_pm;

	// 设置host状态为Running
	scsi_host_set_state(shost, SHOST_RUNNING);
	// 增加父结点引用？
	get_device(shost->shost_gendev.parent);

	// 使能dev设备
	device_enable_async_suspend(&shost->shost_dev);

	// 增加gen设备引用
	get_device(&shost->shost_gendev);

	// 添加设备
	error = device_add(&shost->shost_dev);
	if (error)
		goto out_del_gendev;

	// 分配host_data
	if (shost->transportt->host_size) {
		shost->shost_data = kzalloc(shost->transportt->host_size,
					 GFP_KERNEL);
		if (shost->shost_data == NULL) {
			error = -ENOMEM;
			goto out_del_dev;
		}
	}

	// 需要创建工作队列 
	if (shost->transportt->create_work_queue) {
		snprintf(shost->work_q_name, sizeof(shost->work_q_name),
			 "scsi_wq_%d", shost->host_no);
		shost->work_q = alloc_workqueue("%s",
			WQ_SYSFS | __WQ_LEGACY | WQ_MEM_RECLAIM | WQ_UNBOUND,
			1, shost->work_q_name);

		if (!shost->work_q) {
			error = -EINVAL;
			goto out_del_dev;
		}
	}

	// 加到scsisysfs文件系统
	error = scsi_sysfs_add_host(shost);
	if (error)
		goto out_del_dev;

	// 在proc文件系统创建文件
	scsi_proc_host_add(shost);
	// 电源管理相关，主要释放gendev的引用？
	scsi_autopm_put_host(shost);
	return error;

	/*
	 * Any host allocation in this function will be freed in
	 * scsi_host_dev_release().
	 */
 out_del_dev:
	device_del(&shost->shost_dev);
 out_del_gendev:
	/*
	 * Host state is SHOST_RUNNING so we have to explicitly release
	 * ->shost_dev.
	 */
	put_device(&shost->shost_dev);
	device_del(&shost->shost_gendev);
 out_disable_runtime_pm:
	device_disable_async_suspend(&shost->shost_gendev);
	pm_runtime_disable(&shost->shost_gendev);
	pm_runtime_set_suspended(&shost->shost_gendev);
	pm_runtime_put_noidle(&shost->shost_gendev);
 fail:
	return error;
}

static const struct blk_mq_ops scsi_mq_ops_no_commit = {
	.get_budget	= scsi_mq_get_budget,
	.put_budget	= scsi_mq_put_budget,
	.queue_rq	= scsi_queue_rq,
	.complete	= scsi_softirq_done,
	.timeout	= scsi_timeout,
#ifdef CONFIG_BLK_DEBUG_FS
	.show_rq	= scsi_show_rq,
#endif
	.init_request	= scsi_mq_init_request,
	.exit_request	= scsi_mq_exit_request,
	.initialize_rq_fn = scsi_initialize_rq,
	.cleanup_rq	= scsi_cleanup_rq,
	.busy		= scsi_mq_lld_busy,
	.map_queues	= scsi_map_queues,
};

int scsi_mq_setup_tags(struct Scsi_Host *shost)
{
	unsigned int cmd_size, sgl_size;
	struct blk_mq_tag_set *tag_set = &shost->tag_set;

	// sgl大小
	sgl_size = max_t(unsigned int, sizeof(struct scatterlist),
				scsi_mq_inline_sgl_size(shost));
	// 命令大小
	cmd_size = sizeof(struct scsi_cmnd) + shost->hostt->cmd_size + sgl_size;
	// 是否有保护能力，有的话加保护的大小
	if (scsi_host_get_prot(shost))
		cmd_size += sizeof(struct scsi_data_buffer) +
			sizeof(struct scatterlist) * SCSI_INLINE_PROT_SG_CNT;

	memset(tag_set, 0, sizeof(*tag_set));
	// 设置不同的tag的ops
	if (shost->hostt->commit_rqs)
		tag_set->ops = &scsi_mq_ops;
	else
		tag_set->ops = &scsi_mq_ops_no_commit;
	// 队列数量
	tag_set->nr_hw_queues = shost->nr_hw_queues ? : 1;
	// 队列深度
	tag_set->queue_depth = shost->can_queue;
	// 命令大小
	tag_set->cmd_size = cmd_size;
	// 对应的numa
	tag_set->numa_node = NUMA_NO_NODE;
	// 可以合并
	tag_set->flags = BLK_MQ_F_SHOULD_MERGE;
	// 分配策略
	tag_set->flags |=
		BLK_ALLOC_POLICY_TO_MQ_FLAG(shost->hostt->tag_alloc_policy);
	// 设置驱动数据是shost结构
	tag_set->driver_data = shost;
	if (shost->host_tagset)
		tag_set->flags |= BLK_MQ_F_TAG_HCTX_SHARED;

	// 分配tags并做cpu映射，并提前分配request和tag
	return blk_mq_alloc_tag_set(tag_set);
}

int scsi_init_sense_cache(struct Scsi_Host *shost)
{
	struct kmem_cache *cache;
	int ret = 0;

	mutex_lock(&scsi_sense_cache_mutex);
	// 根据是否是dma选择不同的slab
	cache = scsi_select_sense_cache(shost->unchecked_isa_dma);
	// 已经创建了cache，退出
	if (cache)
		goto exit;

	// 根据是否是dma创建不同的slab
	if (shost->unchecked_isa_dma) {
		scsi_sense_isadma_cache =
			kmem_cache_create("scsi_sense_cache(DMA)",
				SCSI_SENSE_BUFFERSIZE, 0,
				SLAB_HWCACHE_ALIGN | SLAB_CACHE_DMA, NULL);
		if (!scsi_sense_isadma_cache)
			ret = -ENOMEM;
	} else {
		scsi_sense_cache =
			kmem_cache_create_usercopy("scsi_sense_cache",
				SCSI_SENSE_BUFFERSIZE, 0, SLAB_HWCACHE_ALIGN,
				0, SCSI_SENSE_BUFFERSIZE, NULL);
		if (!scsi_sense_cache)
			ret = -ENOMEM;
	}
 exit:
	mutex_unlock(&scsi_sense_cache_mutex);
	return ret;
}

```


## scsi_remove_host
```c
void scsi_remove_host(struct Scsi_Host *shost)
{
	unsigned long flags;

	mutex_lock(&shost->scan_mutex);
	spin_lock_irqsave(shost->host_lock, flags);
	// 设置CANCEL状态
	if (scsi_host_set_state(shost, SHOST_CANCEL))
		// 如果设置失败，设置cancel_recovery
		if (scsi_host_set_state(shost, SHOST_CANCEL_RECOVERY)) {
			// 如果再设置失败，直接返回
			spin_unlock_irqrestore(shost->host_lock, flags);
			mutex_unlock(&shost->scan_mutex);
			return;
		}
	spin_unlock_irqrestore(shost->host_lock, flags);

	// 电源管理相关
	scsi_autopm_get_host(shost);
	// 如果tmf工作队列里有东西，则刷出
	flush_workqueue(shost->tmf_work_q);
	scsi_forget_host(shost);
	mutex_unlock(&shost->scan_mutex);
	// 从proc里删除
	scsi_proc_host_rm(shost);

	spin_lock_irqsave(shost->host_lock, flags);
	// 设置删除状态
	if (scsi_host_set_state(shost, SHOST_DEL))
		// 如果出错，设置del_recovery，如果再错了就是bug
		BUG_ON(scsi_host_set_state(shost, SHOST_DEL_RECOVERY));
	spin_unlock_irqrestore(shost->host_lock, flags);

	transport_unregister_device(&shost->shost_gendev);
	// 注销设备
	device_unregister(&shost->shost_dev);
	// 注销gen设备
	device_del(&shost->shost_gendev);
}

void scsi_forget_host(struct Scsi_Host *shost)
{
	struct scsi_device *sdev;
	unsigned long flags;

 restart:
	spin_lock_irqsave(shost->host_lock, flags);
	// 遍历host上的设备
	list_for_each_entry(sdev, &shost->__devices, siblings) {
		if (sdev->sdev_state == SDEV_DEL)
			continue;
		spin_unlock_irqrestore(shost->host_lock, flags);
		__scsi_remove_device(sdev);
		goto restart;
	}
	spin_unlock_irqrestore(shost->host_lock, flags);
}

void __scsi_remove_device(struct scsi_device *sdev)
{
	struct device *dev = &sdev->sdev_gendev;
	int res;

	// 已经设置了删除状态
	if (sdev->sdev_state == SDEV_DEL)
		return;

	if (sdev->is_visible) {
		// 有visible函数
		/*
		 * If scsi_internal_target_block() is running concurrently,
		 * wait until it has finished before changing the device state.
		 */
		mutex_lock(&sdev->state_mutex);
		/*
		 * If blocked, we go straight to DEL and restart the queue so
		 * any commands issued during driver shutdown (like sync
		 * cache) are errored immediately.
		 */

		// 设置取消状态
		res = scsi_device_set_state(sdev, SDEV_CANCEL);
		if (res != 0) {
			// 设置失败后，设置删除状态
			res = scsi_device_set_state(sdev, SDEV_DEL);
			if (res == 0)
				// 设置成功后，停止队列？
				scsi_start_queue(sdev);
		}
		mutex_unlock(&sdev->state_mutex);

		if (res != 0)
			return;

		// 从sysfs里删除
		if (sdev->host->hostt->sdev_groups)
			sysfs_remove_groups(&sdev->sdev_gendev.kobj,
					sdev->host->hostt->sdev_groups);

		// 从bsg里删除
		bsg_unregister_queue(sdev->request_queue);
		// 注销设备
		device_unregister(&sdev->sdev_dev);
		// 主要是从sysfs里删除设备
		transport_remove_device(dev);
		// 真正从系统里删除设备
		device_del(dev);
	} else
		put_device(&sdev->sdev_dev);

	mutex_lock(&sdev->state_mutex);
	// 设置设备状态为删除
	scsi_device_set_state(sdev, SDEV_DEL);
	
	mutex_unlock(&sdev->state_mutex);

	// 清空队列
	blk_cleanup_queue(sdev->request_queue);
	// 停止work
	cancel_work_sync(&sdev->requeue_work);

	if (sdev->host->hostt->slave_destroy)
		sdev->host->hostt->slave_destroy(sdev);
	// 销毁，释放设备
	transport_destroy_device(dev);

	// 释放kref?
	scsi_target_reap(scsi_target(sdev));

	// 减少引用，如果为0会释放
	put_device(dev);
}

void blk_cleanup_queue(struct request_queue *q)
{
	/* cannot be called from atomic context */
	might_sleep();

	WARN_ON_ONCE(blk_queue_registered(q));

	/* mark @q DYING, no new request or merges will be allowed afterwards */
	blk_set_queue_dying(q);

	blk_queue_flag_set(QUEUE_FLAG_NOMERGES, q);
	blk_queue_flag_set(QUEUE_FLAG_NOXMERGES, q);

	/*
	 * Drain all requests queued before DYING marking. Set DEAD flag to
	 * prevent that blk_mq_run_hw_queues() accesses the hardware queues
	 * after draining finished.
	 */
	blk_freeze_queue(q);

	rq_qos_exit(q);

	blk_queue_flag_set(QUEUE_FLAG_DEAD, q);

	/* for synchronous bio-based driver finish in-flight integrity i/o */
	blk_flush_integrity();

	/* @q won't process any more request, flush async actions */
	del_timer_sync(&q->backing_dev_info->laptop_mode_wb_timer);
	blk_sync_queue(q);

	if (queue_is_mq(q))
		blk_mq_exit_queue(q);

	/*
	 * In theory, request pool of sched_tags belongs to request queue.
	 * However, the current implementation requires tag_set for freeing
	 * requests, so free the pool now.
	 *
	 * Queue has become frozen, there can't be any in-queue requests, so
	 * it is safe to free requests now.
	 */
	mutex_lock(&q->sysfs_lock);
	if (q->elevator)
		blk_mq_sched_free_requests(q);
	mutex_unlock(&q->sysfs_lock);

	percpu_ref_exit(&q->q_usage_counter);

	/* @q is and will stay empty, shutdown and put */
	blk_put_queue(q);
}

void device_del(struct device *dev)
{
	struct device *parent = dev->parent;
	struct kobject *glue_dir = NULL;
	struct class_interface *class_intf;
	unsigned int noio_flag;

	device_lock(dev);
	kill_device(dev);
	device_unlock(dev);

	if (dev->fwnode && dev->fwnode->dev == dev)
		dev->fwnode->dev = NULL;

	/* Notify clients of device removal.  This call must come
	 * before dpm_sysfs_remove().
	 */
	noio_flag = memalloc_noio_save();
	if (dev->bus)
		blocking_notifier_call_chain(&dev->bus->p->bus_notifier,
					     BUS_NOTIFY_DEL_DEVICE, dev);

	dpm_sysfs_remove(dev);
	if (parent)
		klist_del(&dev->p->knode_parent);
	if (MAJOR(dev->devt)) {
		devtmpfs_delete_node(dev);
		device_remove_sys_dev_entry(dev);
		device_remove_file(dev, &dev_attr_dev);
	}
	if (dev->class) {
		device_remove_class_symlinks(dev);

		mutex_lock(&dev->class->p->mutex);
		/* notify any interfaces that the device is now gone */
		list_for_each_entry(class_intf,
				    &dev->class->p->interfaces, node)
			if (class_intf->remove_dev)
				class_intf->remove_dev(dev, class_intf);
		/* remove the device from the class list */
		klist_del(&dev->p->knode_class);
		mutex_unlock(&dev->class->p->mutex);
	}
	device_remove_file(dev, &dev_attr_uevent);
	device_remove_attrs(dev);
	bus_remove_device(dev);
	device_pm_remove(dev);
	driver_deferred_probe_del(dev);
	device_platform_notify(dev, KOBJ_REMOVE);
	device_remove_properties(dev);
	device_links_purge(dev);

	if (dev->bus)
		blocking_notifier_call_chain(&dev->bus->p->bus_notifier,
					     BUS_NOTIFY_REMOVED_DEVICE, dev);
	kobject_uevent(&dev->kobj, KOBJ_REMOVE);
	glue_dir = get_glue_dir(dev);
	kobject_del(&dev->kobj);
	cleanup_glue_dir(dev, glue_dir);
	memalloc_noio_restore(noio_flag);
	put_device(parent);
}
```

## scsi_host_lookup
```c
struct Scsi_Host *scsi_host_lookup(unsigned short hostnum)
{
	struct device *cdev;
	struct Scsi_Host *shost = NULL;

	cdev = class_find_device(&shost_class, NULL, &hostnum,
				 __scsi_host_match);
	if (cdev) {
		shost = scsi_host_get(class_to_shost(cdev));
		put_device(cdev);
	}
	return shost;
}
```		