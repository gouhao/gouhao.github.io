# 扫描
源码基于5.10

## scsi_scan_host
```c
void scsi_scan_host(struct Scsi_Host *shost)
{
	struct async_scan_data *data;

	// 扫描类型如果是none, manual则不进行扫描,默认是async或者sync
	if (strncmp(scsi_scan_type, "none", 4) == 0 ||
	    strncmp(scsi_scan_type, "manual", 6) == 0)
		return;

	// 取引用,获取失败则不扫描
	if (scsi_autopm_get_host(shost) < 0)
		return;

	// 为异步扫描做准备，这里面会给data分配空间。如果返回NULL，说明是同步扫描
	data = scsi_prep_async_scan(shost);
	if (!data) {
		// 执行同步扫描
		do_scsi_scan_host(shost);
		scsi_autopm_put_host(shost);
		return;
	}

	// 执行异步扫描，它会加入到system_unbound_wq队列，最后执行do_scan_async
	async_schedule(do_scan_async, data);

	/* scsi_autopm_put_host(shost) 在scsi_finish_async_scan() 里调用 */
}

static void do_scan_async(void *_data, async_cookie_t c)
{
	struct async_scan_data *data = _data;
	struct Scsi_Host *shost = data->shost;

	// 执行扫描
	do_scsi_scan_host(shost);
	// 完成扫描
	scsi_finish_async_scan(data);
}


static void scsi_finish_async_scan(struct async_scan_data *data)
{
	struct Scsi_Host *shost;
	unsigned long flags;

	// data怎么会为空？
	if (!data)
		return;

	shost = data->shost;

	mutex_lock(&shost->scan_mutex);

	// 没有异步扫描标志，说明调用了2次？
	if (!shost->async_scan) {
		shost_printk(KERN_INFO, shost, "%s called twice\n", __func__);
		dump_stack();
		mutex_unlock(&shost->scan_mutex);
		return;
	}

	// 先等待之前的扫描完成
	wait_for_completion(&data->prev_finished);

	// 在sysfs里添加扫描到的设备
	scsi_sysfs_add_devices(shost);

	spin_lock_irqsave(shost->host_lock, flags);
	// 取消异步扫描状态
	shost->async_scan = 0;
	spin_unlock_irqrestore(shost->host_lock, flags);

	mutex_unlock(&shost->scan_mutex);

	spin_lock(&async_scan_lock);
	// 从列表里删除data
	list_del(&data->list);
	// 扫描列表不为空
	if (!list_empty(&scanning_hosts)) {
		// 获取下个数据
		struct async_scan_data *next = list_entry(scanning_hosts.next,
				struct async_scan_data, list);
		// 设置下个数据，完成
		complete(&next->prev_finished);
	}
	spin_unlock(&async_scan_lock);

	// 释放引用
	scsi_autopm_put_host(shost);
	scsi_host_put(shost);
	// 释放data
	kfree(data);
}

static struct async_scan_data *scsi_prep_async_scan(struct Scsi_Host *shost)
{
	struct async_scan_data *data = NULL;
	unsigned long flags;

	// 如果是同步扫描，直接返回
	if (strncmp(scsi_scan_type, "sync", 4) == 0)
		return NULL;

	mutex_lock(&shost->scan_mutex);
	// 已经在执行异步扫描，则返回错误
	if (shost->async_scan) {
		shost_printk(KERN_DEBUG, shost, "%s called twice\n", __func__);
		goto err;
	}

	// 分配scan_data
	data = kmalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		goto err;
	// 设置host引用
	data->shost = scsi_host_get(shost);
	if (!data->shost)
		goto err;
	// 初始化完成量
	init_completion(&data->prev_finished);

	spin_lock_irqsave(shost->host_lock, flags);
	// 设置host的异步扫描标志
	shost->async_scan = 1;
	spin_unlock_irqrestore(shost->host_lock, flags);
	mutex_unlock(&shost->scan_mutex);

	spin_lock(&async_scan_lock);
	// scanning_hosts已空，则设置完成量
	if (list_empty(&scanning_hosts))
		complete(&data->prev_finished);
	// 把data加到scanning_hosts列表
	list_add_tail(&data->list, &scanning_hosts);
	spin_unlock(&async_scan_lock);

	return data;

 err:
	mutex_unlock(&shost->scan_mutex);
	kfree(data);
	return NULL;
}

```

## do_scsi_scan_host
```c
static void do_scsi_scan_host(struct Scsi_Host *shost)
{
	if (shost->hostt->scan_finished) {
		// 有自定义的扫描函数。todo: 后面再看
		unsigned long start = jiffies;
		if (shost->hostt->scan_start)
			shost->hostt->scan_start(shost);

		while (!shost->hostt->scan_finished(shost, jiffies - start))
			msleep(10);
	} else {
		// 通用扫描函数

		// SCAN_WILD_CARD 表示不限制特定的值
		scsi_scan_host_selected(shost, SCAN_WILD_CARD, SCAN_WILD_CARD,
				SCAN_WILD_CARD, 0);
	}
}

int scsi_scan_host_selected(struct Scsi_Host *shost, unsigned int channel,
			    unsigned int id, u64 lun,
			    enum scsi_scan_mode rescan)
{
	SCSI_LOG_SCAN_BUS(3, shost_printk (KERN_INFO, shost,
		"%s: <%u:%u:%llu>\n",
		__func__, channel, id, lun));

	// 如果指定了值，不能大于最大值
	if (((channel != SCAN_WILD_CARD) && (channel > shost->max_channel)) ||
	    ((id != SCAN_WILD_CARD) && (id >= shost->max_id)) ||
	    ((lun != SCAN_WILD_CARD) && (lun >= shost->max_lun)))
		return -EINVAL;

	mutex_lock(&shost->scan_mutex);

	// 如果是同步扫描，需要等待其他的异步扫描完成
	if (!shost->async_scan)
		scsi_complete_async_scans();

	// host的状态在RUNNING和RECOVERY时，允许扫描
	// scsi_autopm_get_host == 0，表示多次执行时，只扫描一次
	if (scsi_host_scan_allowed(shost) && scsi_autopm_get_host(shost) == 0) {
		if (channel == SCAN_WILD_CARD)
			// 通道没限制，扫描所有通道
			for (channel = 0; channel <= shost->max_channel;
			     channel++)
				scsi_scan_channel(shost, channel, id, lun,
						  rescan);
		else
			// 扫描特定通道
			scsi_scan_channel(shost, channel, id, lun, rescan);
		scsi_autopm_put_host(shost);
	}
	mutex_unlock(&shost->scan_mutex);

	return 0;
}

static void scsi_scan_channel(struct Scsi_Host *shost, unsigned int channel,
			      unsigned int id, u64 lun,
			      enum scsi_scan_mode rescan)
{
	uint order_id;

	if (id == SCAN_WILD_CARD)
		// 没有指定id，则扫描所有id
		for (id = 0; id < shost->max_id; ++id) {
			// 是否要反转id
			if (shost->reverse_ordering)
				/*
				 * Scan from high to low id.
				 */
				order_id = shost->max_id - id - 1;
			else
				order_id = id;
			__scsi_scan_target(&shost->shost_gendev, channel,
					order_id, lun, rescan);
		}
	else
		// 扫描指定id
		__scsi_scan_target(&shost->shost_gendev, channel,
				id, lun, rescan);
}

static void __scsi_scan_target(struct device *parent, unsigned int channel,
		unsigned int id, u64 lun, enum scsi_scan_mode rescan)
{
	struct Scsi_Host *shost = dev_to_shost(parent);
	blist_flags_t bflags = 0;
	int res;
	struct scsi_target *starget;

	// 不要扫描host
	if (shost->this_id == id)
		return;

	// 分配一个target
	starget = scsi_alloc_target(parent, channel, id);
	if (!starget)
		return;
	// 增加target引用
	scsi_autopm_get_target(starget);

	if (lun != SCAN_WILD_CARD) {
		// 扫描特定的lun
		scsi_probe_and_add_lun(starget, lun, NULL, NULL, rescan, NULL);
		goto out_reap;
	}

	// 首先扫描lun0，如果有反应，则更进一步扫描其它lun
	res = scsi_probe_and_add_lun(starget, 0, &bflags, NULL, rescan, NULL);

	// SCSI_SCAN_LUN_PRESENT：目标有响应，在目标结点下有逻辑单元
	// SCSI_SCAN_TARGET_PRESENT：目标有响应，但是在target下没有逻辑
	if (res == SCSI_SCAN_LUN_PRESENT || res == SCSI_SCAN_TARGET_PRESENT) {
		// 先对lun0发送report_lun，这个命令返回目标节点已经实现的lun编号，对于每一个编号，再行探测
		if (scsi_report_lun_scan(starget, bflags, rescan) != 0)
			// 如果上面方法失败，则顺序进行lun探测
			scsi_sequential_lun_scan(starget, bflags,
						 starget->scsi_level, rescan);
	}

 out_reap:
	// 减少target引用
	scsi_autopm_put_target(starget);
	// 如果target没有用，会释放
	scsi_target_reap(starget);

	put_device(&starget->dev);
}

static void scsi_sequential_lun_scan(struct scsi_target *starget,
				     blist_flags_t bflags, int scsi_level,
				     enum scsi_scan_mode rescan)
{
	uint max_dev_lun;
	u64 sparse_lun, lun;
	struct Scsi_Host *shost = dev_to_shost(starget->dev.parent);

	SCSI_LOG_SCAN_BUS(3, starget_printk(KERN_INFO, starget,
		"scsi scan: Sequential scan\n"));

	// max_scsi_luns由各个设备驱动设置
	max_dev_lun = min(max_scsi_luns, shost->max_lun);
	/*
	 * If this device is known to support sparse multiple units,
	 * override the other settings, and scan all of them. Normally,
	 * SCSI-3 devices should be scanned via the REPORT LUNS.
	 */
	if (bflags & BLIST_SPARSELUN) {
		max_dev_lun = shost->max_lun;
		sparse_lun = 1;
	} else
		sparse_lun = 0;

	/*
	 * If less than SCSI_1_CCS, and no special lun scanning, stop
	 * scanning; this matches 2.4 behaviour, but could just be a bug
	 * (to continue scanning a SCSI_1_CCS device).
	 *
	 * This test is broken.  We might not have any device on lun0 for
	 * a sparselun device, and if that's the case then how would we
	 * know the real scsi_level, eh?  It might make sense to just not
	 * scan any SCSI_1 device for non-0 luns, but that check would best
	 * go into scsi_alloc_sdev() and just have it return null when asked
	 * to alloc an sdev for lun > 0 on an already found SCSI_1 device.
	 *
	if ((sdevscan->scsi_level < SCSI_1_CCS) &&
	    ((bflags & (BLIST_FORCELUN | BLIST_SPARSELUN | BLIST_MAX5LUN))
	     == 0))
		return;
	 */
	/*
	 * If this device is known to support multiple units, override
	 * the other settings, and scan all of them.
	 */
	if (bflags & BLIST_FORCELUN)
		max_dev_lun = shost->max_lun;
	/*
	 * REGAL CDC-4X: avoid hang after LUN 4
	 */
	if (bflags & BLIST_MAX5LUN)
		max_dev_lun = min(5U, max_dev_lun);
	/*
	 * Do not scan SCSI-2 or lower device past LUN 7, unless
	 * BLIST_LARGELUN.
	 */
	if (scsi_level < SCSI_3 && !(bflags & BLIST_LARGELUN))
		max_dev_lun = min(8U, max_dev_lun);
	else
		max_dev_lun = min(256U, max_dev_lun);

	/*
	 * We have already scanned LUN 0, so start at LUN 1. Keep scanning
	 * until we reach the max, or no LUN is found and we are not
	 * sparse_lun.
	 */
	for (lun = 1; lun < max_dev_lun; ++lun)
		if ((scsi_probe_and_add_lun(starget, lun, NULL, NULL, rescan,
					    NULL) != SCSI_SCAN_LUN_PRESENT) &&
		    !sparse_lun)
			return;
}


static int scsi_report_lun_scan(struct scsi_target *starget, blist_flags_t bflags,
				enum scsi_scan_mode rescan)
{
	unsigned char scsi_cmd[MAX_COMMAND_SIZE];
	unsigned int length;
	u64 lun;
	unsigned int num_luns;
	unsigned int retries;
	int result;
	struct scsi_lun *lunp, *lun_data;
	struct scsi_sense_hdr sshdr;
	struct scsi_device *sdev;
	struct Scsi_Host *shost = dev_to_shost(&starget->dev);
	int ret = 0;

	/*
	 * Only support SCSI-3 and up devices if BLIST_NOREPORTLUN is not set.
	 * Also allow SCSI-2 if BLIST_REPORTLUN2 is set and host adapter does
	 * support more than 8 LUNs.
	 * Don't attempt if the target doesn't support REPORT LUNS.
	 */
	if (bflags & BLIST_NOREPORTLUN)
		return 1;
	if (starget->scsi_level < SCSI_2 &&
	    starget->scsi_level != SCSI_UNKNOWN)
		return 1;
	if (starget->scsi_level < SCSI_3 &&
	    (!(bflags & BLIST_REPORTLUN2) || shost->max_lun <= 8))
		return 1;
	if (bflags & BLIST_NOLUN)
		return 0;
	if (starget->no_report_luns)
		return 1;

	if (!(sdev = scsi_device_lookup_by_target(starget, 0))) {
		sdev = scsi_alloc_sdev(starget, 0, NULL);
		if (!sdev)
			return 0;
		if (scsi_device_get(sdev)) {
			__scsi_remove_device(sdev);
			return 0;
		}
	}

	/*
	 * Allocate enough to hold the header (the same size as one scsi_lun)
	 * plus the number of luns we are requesting.  511 was the default
	 * value of the now removed max_report_luns parameter.
	 */
	length = (511 + 1) * sizeof(struct scsi_lun);
retry:
	// 分配lun data
	lun_data = kmalloc(length, GFP_KERNEL |
			   (sdev->host->unchecked_isa_dma ? __GFP_DMA : 0));
	if (!lun_data) {
		printk(ALLOC_FAILURE_MSG, __func__);
		goto out;
	}

	scsi_cmd[0] = REPORT_LUNS;

	/*
	 * bytes 1 - 5: reserved, set to zero.
	 */
	memset(&scsi_cmd[1], 0, 5);

	/*
	 * bytes 6 - 9: length of the command.
	 */
	put_unaligned_be32(length, &scsi_cmd[6]);

	scsi_cmd[10] = 0;	/* reserved */
	scsi_cmd[11] = 0;	/* control */

	/*
	 * We can get a UNIT ATTENTION, for example a power on/reset, so
	 * retry a few times (like sd.c does for TEST UNIT READY).
	 * Experience shows some combinations of adapter/devices get at
	 * least two power on/resets.
	 *
	 * Illegal requests (for devices that do not support REPORT LUNS)
	 * should come through as a check condition, and will not generate
	 * a retry.
	 */
	for (retries = 0; retries < 3; retries++) {
		SCSI_LOG_SCAN_BUS(3, sdev_printk (KERN_INFO, sdev,
				"scsi scan: Sending REPORT LUNS to (try %d)\n",
				retries));

		result = scsi_execute_req(sdev, scsi_cmd, DMA_FROM_DEVICE,
					  lun_data, length, &sshdr,
					  SCSI_REPORT_LUNS_TIMEOUT, 3, NULL);

		SCSI_LOG_SCAN_BUS(3, sdev_printk (KERN_INFO, sdev,
				"scsi scan: REPORT LUNS"
				" %s (try %d) result 0x%x\n",
				result ?  "failed" : "successful",
				retries, result));
		if (result == 0)
			break;
		else if (scsi_sense_valid(&sshdr)) {
			if (sshdr.sense_key != UNIT_ATTENTION)
				break;
		}
	}

	if (result) {
		/*
		 * The device probably does not support a REPORT LUN command
		 */
		ret = 1;
		goto out_err;
	}

	/*
	 * Get the length from the first four bytes of lun_data.
	 */
	if (get_unaligned_be32(lun_data->scsi_lun) +
	    sizeof(struct scsi_lun) > length) {
		length = get_unaligned_be32(lun_data->scsi_lun) +
			 sizeof(struct scsi_lun);
		kfree(lun_data);
		goto retry;
	}
	length = get_unaligned_be32(lun_data->scsi_lun);

	num_luns = (length / sizeof(struct scsi_lun));

	SCSI_LOG_SCAN_BUS(3, sdev_printk (KERN_INFO, sdev,
		"scsi scan: REPORT LUN scan\n"));

	/*
	 * Scan the luns in lun_data. The entry at offset 0 is really
	 * the header, so start at 1 and go up to and including num_luns.
	 */
	for (lunp = &lun_data[1]; lunp <= &lun_data[num_luns]; lunp++) {
		lun = scsilun_to_int(lunp);

		if (lun > sdev->host->max_lun) {
			sdev_printk(KERN_WARNING, sdev,
				    "lun%llu has a LUN larger than"
				    " allowed by the host adapter\n", lun);
		} else {
			int res;

			res = scsi_probe_and_add_lun(starget,
				lun, NULL, NULL, rescan, NULL);
			if (res == SCSI_SCAN_NO_RESPONSE) {
				/*
				 * Got some results, but now none, abort.
				 */
				sdev_printk(KERN_ERR, sdev,
					"Unexpected response"
					" from lun %llu while scanning, scan"
					" aborted\n", (unsigned long long)lun);
				break;
			}
		}
	}

 out_err:
	kfree(lun_data);
 out:
	if (scsi_device_created(sdev))
		/*
		 * the sdev we used didn't appear in the report luns scan
		 */
		__scsi_remove_device(sdev);
	scsi_device_put(sdev);
	return ret;
}

static inline int scsi_host_scan_allowed(struct Scsi_Host *shost)
{
	// host的状态在RUNNING和RECOVERY时，允许扫描
	return shost->shost_state == SHOST_RUNNING ||
	       shost->shost_state == SHOST_RECOVERY;
}

int scsi_complete_async_scans(void)
{
	struct async_scan_data *data;

	do {
		if (list_empty(&scanning_hosts))
			return 0;
		/* If we can't get memory immediately, that's OK.  Just
		 * sleep a little.  Even if we never get memory, the async
		 * scans will finish eventually.
		 */
		data = kmalloc(sizeof(*data), GFP_KERNEL);
		if (!data)
			msleep(1);
	} while (!data);

	data->shost = NULL;
	init_completion(&data->prev_finished);

	spin_lock(&async_scan_lock);
	/* Check that there's still somebody else on the list */
	if (list_empty(&scanning_hosts))
		goto done;
	list_add_tail(&data->list, &scanning_hosts);
	spin_unlock(&async_scan_lock);

	printk(KERN_INFO "scsi: waiting for bus probes to complete ...\n");
	wait_for_completion(&data->prev_finished);

	spin_lock(&async_scan_lock);
	list_del(&data->list);
	if (!list_empty(&scanning_hosts)) {
		struct async_scan_data *next = list_entry(scanning_hosts.next,
				struct async_scan_data, list);
		complete(&next->prev_finished);
	}
 done:
	spin_unlock(&async_scan_lock);

	kfree(data);
	return 0;
}
```
## scsi_probe_and_add_lun
```c
static int scsi_probe_and_add_lun(struct scsi_target *starget,
				  u64 lun, blist_flags_t *bflagsp,
				  struct scsi_device **sdevp,
				  enum scsi_scan_mode rescan,
				  void *hostdata)
{
	struct scsi_device *sdev;
	unsigned char *result;
	blist_flags_t bflags;
	int res = SCSI_SCAN_NO_RESPONSE, result_len = 256;
	struct Scsi_Host *shost = dev_to_shost(starget->dev.parent);

	// 找lun对应的设备
	sdev = scsi_device_lookup_by_target(starget, lun);
	if (sdev) {
		// 设备已存在

		// SCSI_SCAN_INITIAL = 0
		// scsi_device_created判断状态是不是scsi_device_created
		// 如果不是第1次扫描或者是第1次扫描且设备不是刚创建出来的
		if (rescan != SCSI_SCAN_INITIAL || !scsi_device_created(sdev)) {
			SCSI_LOG_SCAN_BUS(3, sdev_printk(KERN_INFO, sdev,
				"scsi scan: device exists on %s\n",
				dev_name(&sdev->sdev_gendev)));
			// 需要获取dev指针则设置之，否则减少引用
			if (sdevp)
				*sdevp = sdev;
			else
				scsi_device_put(sdev);

			// 需要获取设备的标志，则获取之
			if (bflagsp)
				*bflagsp = scsi_get_device_flags(sdev,
								 sdev->vendor,
								 sdev->model);
			// 返回lun在线
			return SCSI_SCAN_LUN_PRESENT;
		}
		scsi_device_put(sdev);
	} else
		// 如果没找到则分配一个scsi设备
		sdev = scsi_alloc_sdev(starget, lun, hostdata);
	if (!sdev)
		goto out;

	// 走到这儿开始真正探测设备

	// 分配保存请求结果的内存
	result = kmalloc(result_len, GFP_KERNEL |
			((shost->unchecked_isa_dma) ? __GFP_DMA : 0));
	if (!result)
		goto out_free_sdev;

	// 探测lun，主要是给设备发一个INQUIRY命令.返回0则成功
	if (scsi_probe_lun(sdev, result, result_len, &bflags))
		goto out_free_result;

	// 设置flags
	if (bflagsp)
		*bflagsp = bflags;

	// 如下注释：如果响应的外围设备限定符（PeripheralQualifier）为0x11，那么说明在这个位置上没有逻辑单元
	if ((result[0] >> 5) == 3) {
		/*
		 * For a Peripheral qualifier 3 (011b), the SCSI
		 * spec says: The device server is not capable of
		 * supporting a physical device on this logical
		 * unit.
		 *
		 * For disks, this implies that there is no
		 * logical disk configured at sdev->lun, but there
		 * is a target id responding.
		 */
		SCSI_LOG_SCAN_BUS(2, sdev_printk(KERN_INFO, sdev, "scsi scan:"
				   " peripheral qualifier of 3, device not"
				   " added\n"))
		if (lun == 0) {
			SCSI_LOG_SCAN_BUS(1, {
				unsigned char vend[9];
				unsigned char mod[17];

				sdev_printk(KERN_INFO, sdev,
					"scsi scan: consider passing scsi_mod."
					"dev_flags=%s:%s:0x240 or 0x1000240\n",
					scsi_inq_str(vend, result, 8, 16),
					scsi_inq_str(mod, result, 16, 32));
			});

		}

		res = SCSI_SCAN_TARGET_PRESENT;
		goto out_free_result;
	}

	// 另一种情况是某些具体实现所遵循的，它们用别的值组合来表明某个位置上不存在逻辑单元，
	// 例如NetApp目标节点在响应中使用外围设备限定符为0x01和外围设备类型为0x1F。
	/*
	 * Some targets may set slight variations of PQ and PDT to signal
	 * that no LUN is present, so don't add sdev in these cases.
	 * Two specific examples are:
	 * 1) NetApp targets: return PQ=1, PDT=0x1f
	 * 2) IBM/2145 targets: return PQ=1, PDT=0
	 * 3) USB UFI: returns PDT=0x1f, with the PQ bits being "reserved"
	 *    in the UFI 1.0 spec (we cannot rely on reserved bits).
	 *
	 * References:
	 * 1) SCSI SPC-3, pp. 145-146
	 * PQ=1: "A peripheral device having the specified peripheral
	 * device type is not connected to this logical unit. However, the
	 * device server is capable of supporting the specified peripheral
	 * device type on this logical unit."
	 * PDT=0x1f: "Unknown or no device type"
	 * 2) USB UFI 1.0, p. 20
	 * PDT=00h Direct-access device (floppy)
	 * PDT=1Fh none (no FDD connected to the requested logical unit)
	 */
	if (((result[0] >> 5) == 1 ||
	    (starget->pdt_1f_for_no_lun && (result[0] & 0x1f) == 0x1f)) &&
	    !scsi_is_wlun(lun)) {
		SCSI_LOG_SCAN_BUS(3, sdev_printk(KERN_INFO, sdev,
					"scsi scan: peripheral device type"
					" of 31, no device added\n"));
		res = SCSI_SCAN_TARGET_PRESENT;
		goto out_free_result;
	}

	// 把lun设备添加到scsi里，在添加设备之后就会触发driver的探测
	res = scsi_add_lun(sdev, result, &bflags, shost->async_scan);
	if (res == SCSI_SCAN_LUN_PRESENT) {
		if (bflags & BLIST_KEY) {
			sdev->lockable = 0;
			scsi_unlock_floptical(sdev, result);
		}
	}

 out_free_result:
	kfree(result);
 out_free_sdev:
	if (res == SCSI_SCAN_LUN_PRESENT) {
		if (sdevp) {
			// 获取引用 
			if (scsi_device_get(sdev) == 0) {
				*sdevp = sdev;
			} else {
				// 获取失败，则释放设备
				__scsi_remove_device(sdev);
				res = SCSI_SCAN_NO_RESPONSE;
			}
		}
	} else
		__scsi_remove_device(sdev);
 out:
	return res;
}

static int scsi_probe_lun(struct scsi_device *sdev, unsigned char *inq_result,
			  int result_len, blist_flags_t *bflags)
{
	unsigned char scsi_cmd[MAX_COMMAND_SIZE];
	int first_inquiry_len, try_inquiry_len, next_inquiry_len;
	int response_len = 0;
	int pass, count, result;
	struct scsi_sense_hdr sshdr;

	*bflags = 0;

	// 如果没设置则查询长度为36
	first_inquiry_len = sdev->inquiry_len ? sdev->inquiry_len : 36;
	try_inquiry_len = first_inquiry_len;
	pass = 1;

 next_pass:
	SCSI_LOG_SCAN_BUS(3, sdev_printk(KERN_INFO, sdev,
				"scsi scan: INQUIRY pass %d length %d\n",
				pass, try_inquiry_len));

	// 一共尝试3遍
	for (count = 0; count < 3; ++count) {
		int resid;

		// 设置命令
		memset(scsi_cmd, 0, 6);
		scsi_cmd[0] = INQUIRY;
		scsi_cmd[4] = (unsigned char) try_inquiry_len;

		// 设置结果
		memset(inq_result, 0, try_inquiry_len);

		// 执行请求，这是个同步函数，它执行完，表示命令已经完了
		result = scsi_execute_req(sdev,  scsi_cmd, DMA_FROM_DEVICE,
					  inq_result, try_inquiry_len, &sshdr,
					  HZ / 2 + HZ * scsi_inq_timeout, 3,
					  &resid);

		SCSI_LOG_SCAN_BUS(3, sdev_printk(KERN_INFO, sdev,
				"scsi scan: INQUIRY %s with code 0x%x\n",
				result ? "failed" : "successful", result));

		if (result) {
			// 失败之后,对一些不标准的设备做一些妥协处理
			/*
			 * not-ready to ready transition [asc/ascq=0x28/0x0]
			 * or power-on, reset [asc/ascq=0x29/0x0], continue.
			 * INQUIRY should not yield UNIT_ATTENTION
			 * but many buggy devices do so anyway. 
			 */
			if (driver_byte(result) == DRIVER_SENSE &&
			    scsi_sense_valid(&sshdr)) {
				if ((sshdr.sense_key == UNIT_ATTENTION) &&
				    ((sshdr.asc == 0x28) ||
				     (sshdr.asc == 0x29)) &&
				    (sshdr.ascq == 0))
					continue;
			}
		} else {
			/*
			 * 如果什么都没传输,则再试,这是对USB设备做的妥协
			 */
			if (resid == try_inquiry_len)
				continue;
		}
		break;
	}

	if (result == 0) {
		// 成功

		// 健康检查 
		scsi_sanitize_inquiry_string(&inq_result[8], 8);
		scsi_sanitize_inquiry_string(&inq_result[16], 16);
		scsi_sanitize_inquiry_string(&inq_result[32], 4);

		response_len = inq_result[4] + 5;
		if (response_len > 255)
			response_len = first_inquiry_len;	/* sanity */

		// 获取设备标志
		*bflags = scsi_get_device_flags(sdev, &inq_result[8],
				&inq_result[16]);

		// 如果第一遍就成功了,计算一下多大的传输能工作
		if (pass == 1) {
			// 获取下一次查询的长度
			if (BLIST_INQUIRY_36 & *bflags)
				next_inquiry_len = 36;
			else if (sdev->inquiry_len)
				next_inquiry_len = sdev->inquiry_len;
			else
				next_inquiry_len = response_len;

			// 再试一次,看最大能传输多大长度
			if (next_inquiry_len > try_inquiry_len) {
				try_inquiry_len = next_inquiry_len;
				pass = 2;
				goto next_pass;
			}
		}

	} else if (pass == 2) {
		sdev_printk(KERN_INFO, sdev,
			    "scsi scan: %d byte inquiry failed.  "
			    "Consider BLIST_INQUIRY_36 for this device\n",
			    try_inquiry_len);

		// 如果第2次失败了,则用刚才成功的再试一次
		try_inquiry_len = first_inquiry_len;
		pass = 3;
		goto next_pass;
	}

	// 查询失败
	if (result)
		return -EIO;

	// 不要超过响应长度
	sdev->inquiry_len = min(try_inquiry_len, response_len);

	// inquiry_len最小要等于36?
	if (sdev->inquiry_len < 36) {
		if (!sdev->host->short_inquiry) {
			shost_printk(KERN_INFO, sdev->host,
				    "scsi scan: INQUIRY result too short (%d),"
				    " using 36\n", sdev->inquiry_len);
			sdev->host->short_inquiry = 1;
		}
		sdev->inquiry_len = 36;
	}

	// 设置scsi级别
	sdev->scsi_level = inq_result[2] & 0x07;
	if (sdev->scsi_level >= 2 ||
	    (sdev->scsi_level == 1 && (inq_result[3] & 0x0f) == 1))
		sdev->scsi_level++;
	sdev->sdev_target->scsi_level = sdev->scsi_level;

	/*
	 * 如果scsi2或更低,如果传输需要的话就把lun值保存在cdb1里
	 */
	sdev->lun_in_cdb = 0;
	if (sdev->scsi_level <= SCSI_2 &&
	    sdev->scsi_level != SCSI_UNKNOWN &&
	    !sdev->host->no_scsi2_lun_in_cdb)
		sdev->lun_in_cdb = 1;

	return 0;
}
```