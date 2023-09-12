# target

## scsi_alloc_target
```c
static struct scsi_target *scsi_alloc_target(struct device *parent,
					     int channel, uint id)
{
	struct Scsi_Host *shost = dev_to_shost(parent);
	struct device *dev = NULL;
	unsigned long flags;
	// target的大小
	const int size = sizeof(struct scsi_target)
		+ shost->transportt->target_size;
	struct scsi_target *starget;
	struct scsi_target *found_target;
	int error, ref_got;

	// 分配target
	starget = kzalloc(size, GFP_KERNEL);
	if (!starget) {
		printk(KERN_ERR "%s: allocation failure\n", __func__);
		return NULL;
	}
	dev = &starget->dev;
	// 初始化device
	device_initialize(dev);
	kref_init(&starget->reap_ref);
	// 获取父设备
	dev->parent = get_device(parent);
	// 设备名
	dev_set_name(dev, "target%d:%d:%d", shost->host_no, channel, id);
	// 挂在scsi bus上
	dev->bus = &scsi_bus_type;
	// 类型
	dev->type = &scsi_target_type;
	// id号
	starget->id = id;
	// 通道号
	starget->channel = channel;
	// 队列深度?
	starget->can_queue = 0;
	INIT_LIST_HEAD(&starget->siblings);
	INIT_LIST_HEAD(&starget->devices);
	// 可以创建
	starget->state = STARGET_CREATED;
	// 级别是scsi-2
	starget->scsi_level = SCSI_2;
	// SCSI_DEFAULT_TARGET_BLOCKED=3
	starget->max_target_blocked = SCSI_DEFAULT_TARGET_BLOCKED;
 retry:
	spin_lock_irqsave(shost->host_lock, flags);

	// 根据channel和id去host里找target
	found_target = __scsi_find_target(parent, channel, id);
	// 如果已经找到说明别人已经添加了,则去found处理
	if (found_target)
		goto found;

	// 走到这儿说明没找到

	// 把target挂到host的列表上
	list_add_tail(&starget->siblings, &shost->__targets);
	spin_unlock_irqrestore(shost->host_lock, flags);
	// 添加到transport类里
	transport_setup_device(dev);
	// 如果有target_alloc,则调用之
	if (shost->hostt->target_alloc) {
		error = shost->hostt->target_alloc(starget);

		if(error) {
			if (error != -ENXIO)
				dev_err(dev, "target allocation failed, error %d\n", error);
			/* don't want scsi_target_reap to do the final
			 * put because it will be under the host lock */
			scsi_target_destroy(starget);
			return NULL;
		}
	}
	// 获取设备引用
	get_device(dev);

	return starget;

 found:
	// 获取引用
	ref_got = kref_get_unless_zero(&found_target->reap_ref);

	spin_unlock_irqrestore(shost->host_lock, flags);
	// 如果获取到了,说明真的有人添加了,则直接返回已找到的
	if (ref_got) {
		// 这个会调用到ktype->release的方法,会释放刚才分配的target对象
		put_device(dev);
		return found_target;
	}

	// 走到这儿说明找到的是一个正在销毁的target
	
	// 减少已找到的引用
	put_device(&found_target->dev);
	
	// 睡一会,然后再重试
	msleep(1);
	goto retry;
}

static struct scsi_target *__scsi_find_target(struct device *parent,
					      int channel, uint id)
{
	struct scsi_target *starget, *found_starget = NULL;
	struct Scsi_Host *shost = dev_to_shost(parent);
	// 遍历host的target列表
	list_for_each_entry(starget, &shost->__targets, siblings) {
		// id, channel都相等就是找到
		if (starget->id == id &&
		    starget->channel == channel) {
			found_starget = starget;
			break;
		}
	}
	// 如找到,增引用
	if (found_starget)
		get_device(&found_starget->dev);

	return found_starget;
}
```

## scsi_scan_target
```c
void scsi_scan_target(struct device *parent, unsigned int channel,
		      unsigned int id, u64 lun, enum scsi_scan_mode rescan)
{
	struct Scsi_Host *shost = dev_to_shost(parent);

	if (strncmp(scsi_scan_type, "none", 4) == 0)
		return;

	if (rescan != SCSI_SCAN_MANUAL &&
	    strncmp(scsi_scan_type, "manual", 6) == 0)
		return;

	mutex_lock(&shost->scan_mutex);
	if (!shost->async_scan)
		scsi_complete_async_scans();

	if (scsi_host_scan_allowed(shost) && scsi_autopm_get_host(shost) == 0) {
		__scsi_scan_target(parent, channel, id, lun, rescan);
		scsi_autopm_put_host(shost);
	}
	mutex_unlock(&shost->scan_mutex);
}
```