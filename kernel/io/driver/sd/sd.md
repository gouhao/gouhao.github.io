# sd
源码基于5.10

sd是scsi磁盘的驱动

## 1. init
```c

static struct class sd_disk_class = {
	.name		= "scsi_disk",
	.owner		= THIS_MODULE,
	.dev_release	= scsi_disk_release,
	.dev_groups	= sd_disk_groups,
};

static struct scsi_driver sd_template = {
	.gendrv = {
		.name		= "sd",
		.owner		= THIS_MODULE,
		.probe		= sd_probe,
		.probe_type	= PROBE_PREFER_ASYNCHRONOUS,
		.remove		= sd_remove,
		.shutdown	= sd_shutdown,
		.pm		= &sd_pm_ops,
	},
	.rescan			= sd_rescan,
	.init_command		= sd_init_command,
	.uninit_command		= sd_uninit_command,
	.done			= sd_done,
	.eh_action		= sd_eh_action,
	.eh_reset		= sd_eh_reset,
};

static int __init init_sd(void)
{
	int majors = 0, i, err;

	SCSI_LOG_HLQUEUE(3, printk("init_sd: sd driver entry point\n"));

	// todo: 这个是注册什么?
	// SD_MAJORS=16
	for (i = 0; i < SD_MAJORS; i++) {
		if (register_blkdev(sd_major(i), "sd") != 0)
			continue;
		majors++;
		blk_register_region(sd_major(i), SD_MINORS, NULL,
				    sd_default_probe, NULL, NULL);
	}

	// 没有注册成功?
	if (!majors)
		return -ENODEV;

	// 注册磁盘类
	err = class_register(&sd_disk_class);
	if (err)
		goto err_out;

	// 创建cdb缓存
	sd_cdb_cache = kmem_cache_create("sd_ext_cdb", SD_EXT_CDB_SIZE,
					 0, 0, NULL);
	if (!sd_cdb_cache) {
		printk(KERN_ERR "sd: can't init extended cdb cache\n");
		err = -ENOMEM;
		goto err_out_class;
	}

	// 创建cdb内存池
	sd_cdb_pool = mempool_create_slab_pool(SD_MEMPOOL_SIZE, sd_cdb_cache);
	if (!sd_cdb_pool) {
		printk(KERN_ERR "sd: can't init extended cdb pool\n");
		err = -ENOMEM;
		goto err_out_cache;
	}

	// 创建页内存池?
	sd_page_pool = mempool_create_page_pool(SD_MEMPOOL_SIZE, 0);
	if (!sd_page_pool) {
		printk(KERN_ERR "sd: can't init discard page pool\n");
		err = -ENOMEM;
		goto err_out_ppool;
	}

	// 注册 scsi 驱动
	err = scsi_register_driver(&sd_template.gendrv);
	if (err)
		goto err_out_driver;

	return 0;

err_out_driver:
	mempool_destroy(sd_page_pool);

err_out_ppool:
	mempool_destroy(sd_cdb_pool);

err_out_cache:
	kmem_cache_destroy(sd_cdb_cache);

err_out_class:
	class_unregister(&sd_disk_class);
err_out:
	for (i = 0; i < SD_MAJORS; i++)
		unregister_blkdev(sd_major(i), "sd");
	return err;
}

/*
 * Device no to disk mapping:
 * 
 *       major         disc2     disc  p1
 *   |............|.............|....|....| <- dev_t
 *    31        20 19          8 7  4 3  0
 * 
 * Inside a major, we have 16k disks, however mapped non-
 * contiguously. The first 16 disks are for major0, the next
 * ones with major1, ... Disk 256 is for major0 again, disk 272 
 * for major1, ... 
 * As we stay compatible with our numbering scheme, we can reuse 
 * the well-know SCSI majors 8, 65--71, 136--143.
 */

static int sd_major(int major_idx)
{
	switch (major_idx) {
	// SCSI_DISK0_MAJOR=8
	case 0:
		return SCSI_DISK0_MAJOR;
	case 1 ... 7:
		return SCSI_DISK1_MAJOR + major_idx - 1;
	case 8 ... 15:
		return SCSI_DISK8_MAJOR + major_idx - 8;
	default:
		BUG();
		return 0;	/* shut up gcc */
	}
}

```
## 2. sd_probe
```c

static const struct block_device_operations sd_fops = {
	.owner			= THIS_MODULE,
	.open			= sd_open,
	.release		= sd_release,
	.ioctl			= sd_ioctl,
	.getgeo			= sd_getgeo,
#ifdef CONFIG_COMPAT
	.compat_ioctl		= sd_compat_ioctl,
#endif
	.check_events		= sd_check_events,
	.unlock_native_capacity	= sd_unlock_native_capacity,
	.report_zones		= sd_zbc_report_zones,
	.pr_ops			= &sd_pr_ops,
};

static int sd_probe(struct device *dev)
{
	// dev转成scsi设备
	struct scsi_device *sdp = to_scsi_device(dev);
	struct scsi_disk *sdkp;
	struct gendisk *gd;
	int index;
	int error;

	// 获取设备引用
	scsi_autopm_get_device(sdp);
	error = -ENODEV;

	// sd只支持这几种类型
	if (sdp->type != TYPE_DISK &&
	    sdp->type != TYPE_ZBC &&
	    sdp->type != TYPE_MOD &&
	    sdp->type != TYPE_RBC)
		goto out;

#ifndef CONFIG_BLK_DEV_ZONED
	if (sdp->type == TYPE_ZBC)
		goto out;
#endif
	SCSI_LOG_HLQUEUE(3, sdev_printk(KERN_INFO, sdp,
					"sd_probe\n"));

	error = -ENOMEM;

	// 分配一个scsi磁盘对象
	sdkp = kzalloc(sizeof(*sdkp), GFP_KERNEL);
	if (!sdkp)
		goto out;

	// 分配一个gen磁盘
	gd = alloc_disk(SD_MINORS);
	if (!gd)
		goto out_free;

	// 获取一个id
	index = ida_alloc(&sd_index_ida, GFP_KERNEL);
	if (index < 0) {
		sdev_printk(KERN_WARNING, sdp, "sd_probe: memory exhausted.\n");
		goto out_put;
	}

	// 格式化名称，上次分配的id是个整数，这个format会把index转成对应的abc, 所以设备名就是sda/b/c...
	error = sd_format_disk_name("sd", index, gd->disk_name, DISK_NAME_LEN);
	if (error) {
		sdev_printk(KERN_WARNING, sdp, "SCSI disk (sd) name length exceeded.\n");
		goto out_free_index;
	}

	// 设置各个值
	sdkp->device = sdp;
	sdkp->driver = &sd_template;
	sdkp->disk = gd;
	sdkp->index = index;
	// SD_MAX_RETRIES=5
	sdkp->max_retries = SD_MAX_RETRIES;
	// 打开的数量是0
	atomic_set(&sdkp->openers, 0);
	// 错误数量也是0
	atomic_set(&sdkp->device->ioerr_cnt, 0);

	// 设置请求队列超时时间， SD_TIMEOUT=30秒
	if (!sdp->request_queue->rq_timeout) {
		if (sdp->type != TYPE_MOD)
			blk_queue_rq_timeout(sdp->request_queue, SD_TIMEOUT);
		else
			blk_queue_rq_timeout(sdp->request_queue,
					     SD_MOD_TIMEOUT);
	}

	// 初始化内嵌设备
	device_initialize(&sdkp->dev);
	sdkp->dev.parent = get_device(dev);
	sdkp->dev.class = &sd_disk_class;
	dev_set_name(&sdkp->dev, "%s", dev_name(dev));

	// 把设备加到驱动模型里
	error = device_add(&sdkp->dev);
	if (error) {
		put_device(&sdkp->dev);
		goto out;
	}

	// 设置驱动数据
	dev_set_drvdata(dev, sdkp);

	// 主版本，次版本号
	gd->major = sd_major((index & 0xf0) >> 4);
	gd->first_minor = ((index & 0xf) << 4) | (index & 0xfff00);

	// 块设备操作函数表，这个用来和vfs联系
	gd->fops = &sd_fops;
	// 驱动私有数据
	gd->private_data = &sdkp->driver;
	// 设置gendisk的请求队列
	gd->queue = sdkp->device->request_queue;

	// 设置字段默认值 
	sdp->sector_size = 512;
	sdkp->capacity = 0;
	sdkp->media_present = 1;
	sdkp->write_prot = 0;
	sdkp->cache_override = 0;
	sdkp->WCE = 0;
	sdkp->RCD = 0;
	sdkp->ATO = 0;
	sdkp->first_scan = 1;
	sdkp->max_medium_access_timeouts = SD_MAX_MEDIUM_TIMEOUTS;

	// 重置硬盘, 初始化
	sd_revalidate_disk(gd);

	// what?
	gd->flags = GENHD_FL_EXT_DEVT;

	// 可删除属性
	if (sdp->removable) {
		gd->flags |= GENHD_FL_REMOVABLE;
		gd->events |= DISK_EVENT_MEDIA_CHANGE;
		gd->event_flags = DISK_EVENT_FLAG_POLL | DISK_EVENT_FLAG_UEVENT;
	}

	// 初始化电源管理
	blk_pm_runtime_init(sdp->request_queue, dev);
	if (sdp->rpm_autosuspend) {
		pm_runtime_set_autosuspend_delay(dev,
			sdp->host->hostt->rpm_autosuspend_delay);
	}
	// 添加gen设备和disk设备
	device_add_disk(dev, gd, NULL);

	// what?
	if (sdkp->capacity)
		sd_dif_config_host(sdkp);

	// 重置硬盘，两次调用sd_revalidate_disk。这是有意安排的，让在add_disk之前
	// 和之后两次调用sd_revalidate_disk。其原因在于向块I/O子系统确定注册的方式。
	sd_revalidate_disk(gd);

	// 安全相关
	if (sdkp->security) {
		sdkp->opal_dev = init_opal_dev(sdkp, &sd_sec_submit);
		if (sdkp->opal_dev)
			sd_printk(KERN_NOTICE, sdkp, "supports TCG Opal\n");
	}

	sd_printk(KERN_NOTICE, sdkp, "Attached SCSI %sdisk\n",
		  sdp->removable ? "removable " : "");
	// 释放引用
	scsi_autopm_put_device(sdp);

	return 0;

 out_free_index:
	ida_free(&sd_index_ida, index);
 out_put:
	put_disk(gd);
 out_free:
	sd_zbc_release_disk(sdkp);
	kfree(sdkp);
 out:
	scsi_autopm_put_device(sdp);
	return error;
}
```
### 2.1 sd_revalidate_disk
```c
static int sd_revalidate_disk(struct gendisk *disk)
{
	struct scsi_disk *sdkp = scsi_disk(disk);
	struct scsi_device *sdp = sdkp->device;
	struct request_queue *q = sdkp->disk->queue;
	sector_t old_capacity = sdkp->capacity;
	unsigned char *buffer;
	unsigned int dev_max, rw_max;

	SCSI_LOG_HLQUEUE(3, sd_printk(KERN_INFO, sdkp,
				      "sd_revalidate_disk\n"));

	// 不在线, 离线有3种状态: 设备离线, 设备被删除, 传输口离线
	if (!scsi_device_online(sdp))
		goto out;

	// SD_BUF_SIZE=512
	buffer = kmalloc(SD_BUF_SIZE, GFP_KERNEL);
	if (!buffer) {
		sd_printk(KERN_WARNING, sdkp, "sd_revalidate_disk: Memory "
			  "allocation failure.\n");
		goto out;
	}

	// 让磁盘转起来
	sd_spinup_disk(sdkp);

	// 设备在位
	if (sdkp->media_present) {
		// 读容量
		sd_read_capacity(sdkp, buffer);

		// 清除不旋转标志
		blk_queue_flag_clear(QUEUE_FLAG_NONROT, q);
		// 设置随机贡献标志?
		blk_queue_flag_set(QUEUE_FLAG_ADD_RANDOM, q);

		// vdp: 磁盘的备份与恢复.
		// todo: what? 
		if (scsi_device_supports_vpd(sdp)) {
			sd_read_block_provisioning(sdkp);
			sd_read_block_limits(sdkp);
			sd_read_block_characteristics(sdkp);
			sd_zbc_read_zones(sdkp, buffer);
		}

		// 打印磁盘的容量
		sd_print_capacity(sdkp, old_capacity);

		// 读各种标志及数据
		sd_read_write_protect_flag(sdkp, buffer);
		sd_read_cache_type(sdkp, buffer);
		sd_read_app_tag_own(sdkp, buffer);
		sd_read_write_same(sdkp, buffer);
		sd_read_security(sdkp, buffer);
	}

	// 设置 wc 和 fua标志
	sd_set_flush_flag(sdkp);

	// SD_MAX_XFER_BLOCKS=0xffffffff
	// SD_DEF_XFER_BLOCKS=0xffff
	dev_max = sdp->use_16_for_rw ? SD_MAX_XFER_BLOCKS : SD_DEF_XFER_BLOCKS;

	// 有些设备会上报max block count
	dev_max = min_not_zero(dev_max, sdkp->max_xfer_blocks);
	// 最大扇区数
	q->limits.max_dev_sectors = logical_to_sectors(sdp, dev_max);

	if (sd_validate_opt_xfer_size(sdkp, dev_max)) {
		q->limits.io_opt = logical_to_bytes(sdp, sdkp->opt_xfer_blocks);
		rw_max = logical_to_sectors(sdp, sdkp->opt_xfer_blocks);
	} else {
		q->limits.io_opt = 0;
		rw_max = min_not_zero(logical_to_sectors(sdp, dev_max),
				      (sector_t)BLK_DEF_MAX_SECTORS);
	}

	// 不要超过硬件的最大值
	rw_max = min(rw_max, queue_max_hw_sectors(q));

	/*
	 * Only update max_sectors if previously unset or if the current value
	 * exceeds the capabilities of the hardware.
	 */
	if (sdkp->first_scan ||
	    q->limits.max_sectors > q->limits.max_dev_sectors ||
	    q->limits.max_sectors > q->limits.max_hw_sectors)
		q->limits.max_sectors = rw_max;

	sdkp->first_scan = 0;

	// 设置磁盘容量?
	set_capacity_revalidate_and_notify(disk,
		logical_to_sectors(sdp, sdkp->capacity), false);
	// 设置write same相关
	sd_config_write_same(sdkp);
	kfree(buffer);

	// zone设备相关..
	if (sd_zbc_revalidate_zones(sdkp))
		set_capacity_revalidate_and_notify(disk, 0, false);

 out:
	return 0;
}


bool set_capacity_revalidate_and_notify(struct gendisk *disk, sector_t size,
					bool update_bdev)
{
	// 获取原来的容量
	sector_t capacity = get_capacity(disk);

	// 设置新容量,这个是设置 disk->part0.nr_sects
	set_capacity(disk, size);

	// 更新设备
	if (update_bdev)
		revalidate_disk_size(disk, true);

	if (capacity != size && capacity != 0 && size != 0) {
		char *envp[] = { "RESIZE=1", NULL };

		kobject_uevent_env(&disk_to_dev(disk)->kobj, KOBJ_CHANGE, envp);
		return true;
	}

	return false;
}

static void sd_config_write_same(struct scsi_disk *sdkp)
{
	struct request_queue *q = sdkp->disk->queue;
	unsigned int logical_block_size = sdkp->device->sector_size;

	if (sdkp->device->no_write_same) {
		sdkp->max_ws_blocks = 0;
		goto out;
	}

	/* Some devices can not handle block counts above 0xffff despite
	 * supporting WRITE SAME(16). Consequently we default to 64k
	 * blocks per I/O unless the device explicitly advertises a
	 * bigger limit.
	 */
	if (sdkp->max_ws_blocks > SD_MAX_WS10_BLOCKS)
		sdkp->max_ws_blocks = min_not_zero(sdkp->max_ws_blocks,
						   (u32)SD_MAX_WS16_BLOCKS);
	else if (sdkp->ws16 || sdkp->ws10 || sdkp->device->no_report_opcodes)
		sdkp->max_ws_blocks = min_not_zero(sdkp->max_ws_blocks,
						   (u32)SD_MAX_WS10_BLOCKS);
	else {
		sdkp->device->no_write_same = 1;
		sdkp->max_ws_blocks = 0;
	}

	if (sdkp->lbprz && sdkp->lbpws)
		sdkp->zeroing_mode = SD_ZERO_WS16_UNMAP;
	else if (sdkp->lbprz && sdkp->lbpws10)
		sdkp->zeroing_mode = SD_ZERO_WS10_UNMAP;
	else if (sdkp->max_ws_blocks)
		sdkp->zeroing_mode = SD_ZERO_WS;
	else
		sdkp->zeroing_mode = SD_ZERO_WRITE;

	if (sdkp->max_ws_blocks &&
	    sdkp->physical_block_size > logical_block_size) {
		/*
		 * Reporting a maximum number of blocks that is not aligned
		 * on the device physical size would cause a large write same
		 * request to be split into physically unaligned chunks by
		 * __blkdev_issue_write_zeroes() and __blkdev_issue_write_same()
		 * even if the caller of these functions took care to align the
		 * large request. So make sure the maximum reported is aligned
		 * to the device physical block size. This is only an optional
		 * optimization for regular disks, but this is mandatory to
		 * avoid failure of large write same requests directed at
		 * sequential write required zones of host-managed ZBC disks.
		 */
		sdkp->max_ws_blocks =
			round_down(sdkp->max_ws_blocks,
				   bytes_to_logical(sdkp->device,
						    sdkp->physical_block_size));
	}

out:
	blk_queue_max_write_same_sectors(q, sdkp->max_ws_blocks *
					 (logical_block_size >> 9));
	blk_queue_max_write_zeroes_sectors(q, sdkp->max_ws_blocks *
					 (logical_block_size >> 9));
}
```

### 2.2 添加gen磁盘
```c
void device_add_disk(struct device *parent, struct gendisk *disk,
		     const struct attribute_group **groups)

{
	// 最后一个参数是否注册队列
	__device_add_disk(parent, disk, groups, true);
}

static void __device_add_disk(struct device *parent, struct gendisk *disk,
			      const struct attribute_group **groups,
			      bool register_queue)
{
	dev_t devt;
	int retval;

	// 初始化调度器
	if (register_queue)
		elevator_init_mq(disk->queue);

	/* minors == 0 表示使用从part0扩展devt, 同时应该有EXT_DEVT标志
	 * be accompanied with EXT_DEVT flag.  
	 */
	WARN_ON(disk->minors && !(disk->major || disk->first_minor));
	WARN_ON(!disk->minors &&
		!(disk->flags & (GENHD_FL_EXT_DEVT | GENHD_FL_HIDDEN)));

	// 设置disk up状态
	disk->flags |= GENHD_FL_UP;

	// 分配一个dev_t
	retval = blk_alloc_devt(&disk->part0, &devt);
	if (retval) {
		WARN_ON(1);
		return;
	}
	// 取出主设备号, 次设备号
	disk->major = MAJOR(devt);
	disk->first_minor = MINOR(devt);

	// 分配及初始化event
	disk_alloc_events(disk);

	if (disk->flags & GENHD_FL_HIDDEN) {
		// 设备是隐藏的, 不会出现在用户层的视野里
		/*
		 * Don't let hidden disks show up in /proc/partitions,
		 * and don't bother scanning for partitions either.
		 */
		disk->flags |= GENHD_FL_SUPPRESS_PARTITION_INFO;
		disk->flags |= GENHD_FL_NO_PART_SCAN;
	} else {
		// 这里面主要会在用户层里注册一些接口

		struct backing_dev_info *bdi = disk->queue->backing_dev_info;
		struct device *dev = disk_to_dev(disk);
		int ret;

		dev->devt = devt;
		// 注册bdi, fs里会用到
		ret = bdi_register(bdi, "%u:%u", MAJOR(devt), MINOR(devt));
		WARN_ON(ret);
		// 设置owner
		bdi_set_owner(bdi, dev);
		// 注册blk设备子设备号
		blk_register_region(disk_devt(disk), disk->minors, NULL,
				    exact_match, exact_lock, disk);
	}
	// 注册磁盘, 这里面会发uevent事件
	register_disk(parent, disk, groups);
	if (register_queue)
		// 创建blk sys相关
		blk_register_queue(disk);

	// 增加引用
	WARN_ON_ONCE(!blk_get_queue(disk->queue));

	// todo: what is events?
	disk_add_events(disk);
	blk_integrity_add(disk);
}

static void disk_add_events(struct gendisk *disk)
{
	// 创建event
	if (sysfs_create_files(&disk_to_dev(disk)->kobj, disk_events_attrs) < 0)
		pr_warn("%s: failed to create sysfs files for events\n",
			disk->disk_name);

	if (!disk->ev)
		return;

	mutex_lock(&disk_events_mutex);
	list_add_tail(&disk->ev->node, &disk_events);
	mutex_unlock(&disk_events_mutex);

	/*
	 * Block count is initialized to 1 and the following initial
	 * unblock kicks it into action.
	 */
	__disk_unblock_events(disk, true);
}

int blk_register_queue(struct gendisk *disk)
{
	int ret;
	struct device *dev = disk_to_dev(disk);
	struct request_queue *q = disk->queue;

	if (WARN_ON(!q))
		return -ENXIO;

	WARN_ONCE(blk_queue_registered(q),
		  "%s is registering an already registered queue\n",
		  kobject_name(&dev->kobj));

	/*
	 * SCSI probing may synchronously create and destroy a lot of
	 * request_queues for non-existent devices.  Shutting down a fully
	 * functional queue takes measureable wallclock time as RCU grace
	 * periods are involved.  To avoid excessive latency in these
	 * cases, a request_queue starts out in a degraded mode which is
	 * faster to shut down and is made fully functional here as
	 * request_queues for non-existent devices never get registered.
	 */
	if (!blk_queue_init_done(q)) {
		blk_queue_flag_set(QUEUE_FLAG_INIT_DONE, q);
		percpu_ref_switch_to_percpu(&q->q_usage_counter);
	}

	blk_queue_update_readahead(q);

	ret = blk_trace_init_sysfs(dev);
	if (ret)
		return ret;

	mutex_lock(&q->sysfs_dir_lock);

	ret = kobject_add(&q->kobj, kobject_get(&dev->kobj), "%s", "queue");
	if (ret < 0) {
		blk_trace_remove_sysfs(dev);
		goto unlock;
	}

	ret = sysfs_create_group(&q->kobj, &queue_attr_group);
	if (ret) {
		blk_trace_remove_sysfs(dev);
		kobject_del(&q->kobj);
		kobject_put(&dev->kobj);
		goto unlock;
	}

	mutex_lock(&q->debugfs_mutex);
	q->debugfs_dir = debugfs_create_dir(kobject_name(q->kobj.parent),
					    blk_debugfs_root);
	mutex_unlock(&q->debugfs_mutex);

	if (queue_is_mq(q)) {
		__blk_mq_register_dev(dev, q);
		blk_mq_debugfs_register(q);
	}

	mutex_lock(&q->sysfs_lock);
	if (q->elevator) {
		ret = elv_register_queue(q, false);
		if (ret) {
			mutex_unlock(&q->sysfs_lock);
			mutex_unlock(&q->sysfs_dir_lock);
			kobject_del(&q->kobj);
			blk_trace_remove_sysfs(dev);
			kobject_put(&dev->kobj);
			return ret;
		}
	}

	blk_queue_flag_set(QUEUE_FLAG_REGISTERED, q);
	wbt_enable_default(q);
	blk_throtl_register_queue(q);

	/* Now everything is ready and send out KOBJ_ADD uevent */
	kobject_uevent(&q->kobj, KOBJ_ADD);
	if (q->elevator)
		kobject_uevent(&q->elevator->kobj, KOBJ_ADD);
	mutex_unlock(&q->sysfs_lock);

	ret = 0;
unlock:
	mutex_unlock(&q->sysfs_dir_lock);
	return ret;
}

static void disk_alloc_events(struct gendisk *disk)
{
	struct disk_events *ev;

	if (!disk->fops->check_events || !disk->events)
		return;

	ev = kzalloc(sizeof(*ev), GFP_KERNEL);
	if (!ev) {
		pr_warn("%s: failed to initialize events\n", disk->disk_name);
		return;
	}

	INIT_LIST_HEAD(&ev->node);
	ev->disk = disk;
	spin_lock_init(&ev->lock);
	mutex_init(&ev->block_mutex);
	// 事件阻塞深度
	ev->block = 1;
	// poll 间隔
	ev->poll_msecs = -1;
	INIT_DELAYED_WORK(&ev->dwork, disk_events_workfn);

	disk->ev = ev;
}
```

#### 2.2.1 初始化调度器
```c
void elevator_init_mq(struct request_queue *q)
{
	struct elevator_type *e;
	int err;

	// 硬件如果不支持调度则退出
	if (!elv_support_iosched(q))
		return;

	// 判断是否有 QUEUE_FLAG_REGISTERED 标志
	WARN_ON_ONCE(blk_queue_registered(q));

	// 已经有调度器了
	if (unlikely(q->elevator))
		return;

	if (!q->required_elevator_features)
		// 没有设置特征, 则获取默认的调度器
		e = elevator_get_default(q);
	else
		// 有特征, 则获取对应特征的调度器
		e = elevator_get_by_features(q);
	// 没有获取调度器
	if (!e)
		return;

	// 走到这儿表示获取调度器成功

	blk_mq_freeze_queue(q);
	blk_mq_quiesce_queue(q);

	err = blk_mq_init_sched(q, e);

	blk_mq_unquiesce_queue(q);
	blk_mq_unfreeze_queue(q);

	if (err) {
		pr_warn("\"%s\" elevator initialization failed, "
			"falling back to \"none\"\n", e->elevator_name);
		elevator_put(e);
	}
}

static inline bool elv_support_iosched(struct request_queue *q)
{
	// queue_is_mq: 判断有无q->mq_ops
	if (!queue_is_mq(q) ||
		// 有tag_set && tag_set不需要调度器
	    (q->tag_set && (q->tag_set->flags & BLK_MQ_F_NO_SCHED)))
		return false;
	// 其它情况都支持
	return true;
}

static struct elevator_type *elevator_get_default(struct request_queue *q)
{
	// 硬件队列数大于1, 则不用调度器?
	if (q->nr_hw_queues != 1)
		return NULL;

	return elevator_get(q, "mq-deadline", false);
}

static struct elevator_type *elevator_get(struct request_queue *q,
					  const char *name, bool try_loading)
{
	struct elevator_type *e;

	spin_lock(&elv_list_lock);

	// 找已注册的名称与特征匹配的调度器
	e = elevator_find(name, q->required_elevator_features);
	// 如果没找到, 允许加载
	if (!e && try_loading) {
		spin_unlock(&elv_list_lock);
		// 加载外部模块
		request_module("%s-iosched", name);
		spin_lock(&elv_list_lock);
		// 再找一次
		e = elevator_find(name, q->required_elevator_features);
	}

	// 找到了 && 获取引用计数
	if (e && !try_module_get(e->elevator_owner))
		// 获取引用失败
		e = NULL;

	spin_unlock(&elv_list_lock);
	return e;
}

static struct elevator_type *elevator_find(const char *name,
					   unsigned int required_features)
{
	struct elevator_type *e;

	list_for_each_entry(e, &elv_list, list) {
		if (elevator_match(e, name, required_features))
			return e;
	}

	return NULL;
}

static struct elevator_type *elevator_get_by_features(struct request_queue *q)
{
	struct elevator_type *e, *found = NULL;

	spin_lock(&elv_list_lock);

	// 遍历已注册的电梯
	list_for_each_entry(e, &elv_list, list) {
		// 特征是否符合要求的特征
		if (elv_support_features(e->elevator_features,
					 q->required_elevator_features)) {
			found = e;
			break;
		}
	}

	// 如果找到了,获取模块引用计数
	if (found && !try_module_get(found->elevator_owner))
		found = NULL;

	spin_unlock(&elv_list_lock);
	return found;
}


int blk_mq_init_sched(struct request_queue *q, struct elevator_type *e)
{
	struct blk_mq_hw_ctx *hctx;
	struct elevator_queue *eq;
	unsigned int i;
	int ret;

	// 没有调度器
	if (!e) {
		// 设置队列调度器为空
		q->elevator = NULL;
		// 请求数就是队列的深度
		q->nr_requests = q->tag_set->queue_depth;
		return 0;
	}

	
	// 请求数为队列深度2倍，或者128＊2
	q->nr_requests = 2 * min_t(unsigned int, q->tag_set->queue_depth,
				   BLKDEV_MAX_RQ);

	// 遍历每个hw_ctx
	queue_for_each_hw_ctx(q, hctx, i) {
		// 分配sched_tag
		ret = blk_mq_sched_alloc_tags(q, hctx, i);
		if (ret)
			goto err;
	}

	// 调度器的初始化函数
	ret = e->ops.init_sched(q, e);
	if (ret)
		goto err;

	// 打开CONFIG_BLK_DEBUG_FS时, 会创建sched目录
	blk_mq_debugfs_register_sched(q);

	// 遍历每个hw_ctx
	queue_for_each_hw_ctx(q, hctx, i) {
		// 调用调度器的初始化函数
		if (e->ops.init_hctx) {
			ret = e->ops.init_hctx(hctx, i);
			// 初始化错误，释放相关资源
			if (ret) {
				eq = q->elevator;
				blk_mq_sched_free_requests(q);
				blk_mq_exit_sched(q, eq);
				kobject_put(&eq->kobj);
				return ret;
			}
		}
		// 创建hctx的debugfs目录
		blk_mq_debugfs_register_sched_hctx(q, hctx);
	}

	return 0;

err:
	blk_mq_sched_free_requests(q);
	blk_mq_sched_tags_teardown(q);
	q->elevator = NULL;
	return ret;
}

void blk_mq_freeze_queue(struct request_queue *q)
{
	/*
	 * ...just an alias to keep freeze and unfreeze actions balanced
	 * in the blk_mq_* namespace
	 */
	blk_freeze_queue(q);
}

void blk_freeze_queue(struct request_queue *q)
{
	/*
	 * In the !blk_mq case we are only calling this to kill the
	 * q_usage_counter, otherwise this increases the freeze depth
	 * and waits for it to return to zero.  For this reason there is
	 * no blk_unfreeze_queue(), and blk_freeze_queue() is not
	 * exported to drivers as the only user for unfreeze is blk_mq.
	 */
	blk_freeze_queue_start(q);
	blk_mq_freeze_queue_wait(q);
}

void blk_freeze_queue_start(struct request_queue *q)
{
	mutex_lock(&q->mq_freeze_lock);
	if (++q->mq_freeze_depth == 1) {
		percpu_ref_kill(&q->q_usage_counter);
		mutex_unlock(&q->mq_freeze_lock);
		if (queue_is_mq(q))
			blk_mq_run_hw_queues(q, false);
	} else {
		mutex_unlock(&q->mq_freeze_lock);
	}
}

void blk_mq_freeze_queue_wait(struct request_queue *q)
{
	wait_event(q->mq_freeze_wq, percpu_ref_is_zero(&q->q_usage_counter));
}

void blk_mq_quiesce_queue(struct request_queue *q)
{
	struct blk_mq_hw_ctx *hctx;
	unsigned int i;
	bool rcu = false;

	// 设置 QUEUE_FLAG_QUIESCED 标志
	blk_mq_quiesce_queue_nowait(q);

	// 遍历每个hctx, 根据是否有blocking标志, 调用rcu
	queue_for_each_hw_ctx(q, hctx, i) {
		if (hctx->flags & BLK_MQ_F_BLOCKING)
			synchronize_srcu(hctx->srcu);
		else
			rcu = true;
	}
	if (rcu)
		synchronize_rcu();
}


void blk_mq_unquiesce_queue(struct request_queue *q)
{
	blk_queue_flag_clear(QUEUE_FLAG_QUIESCED, q);

	/* dispatch requests which are inserted during quiescing */
	blk_mq_run_hw_queues(q, true);
}

void blk_mq_unfreeze_queue(struct request_queue *q)
{
	mutex_lock(&q->mq_freeze_lock);
	q->mq_freeze_depth--;
	WARN_ON_ONCE(q->mq_freeze_depth < 0);
	if (!q->mq_freeze_depth) {
		percpu_ref_resurrect(&q->q_usage_counter);
		wake_up_all(&q->mq_freeze_wq);
	}
	mutex_unlock(&q->mq_freeze_lock);
}
```