# lun(logic unit number)
源码基于5.10


## scsi_device_lookup_by_target
```c
struct scsi_device *scsi_device_lookup_by_target(struct scsi_target *starget,
						 u64 lun)
{
	struct scsi_device *sdev;
	// host
	struct Scsi_Host *shost = dev_to_shost(starget->dev.parent);
	unsigned long flags;

	spin_lock_irqsave(shost->host_lock, flags);
	// 找
	sdev = __scsi_device_lookup_by_target(starget, lun);

	// 找到后获取引用
	if (sdev && scsi_device_get(sdev))
		sdev = NULL;
	spin_unlock_irqrestore(shost->host_lock, flags);

	return sdev;
}

struct scsi_device *__scsi_device_lookup_by_target(struct scsi_target *starget,
						   u64 lun)
{
	struct scsi_device *sdev;

	// 遍历target上的设备
	list_for_each_entry(sdev, &starget->devices, same_target_siblings) {
		// state是del的跳过
		if (sdev->sdev_state == SDEV_DEL)
			continue;
		// lun号相等的
		if (sdev->lun ==lun)
			return sdev;
	}

	return NULL;
}
```

## scsi_add_lun
```c
static int scsi_add_lun(struct scsi_device *sdev, unsigned char *inq_result,
		blist_flags_t *bflags, int async)
{
	int ret;

	// 分配并复制请求的结果
	sdev->inquiry = kmemdup(inq_result,
				max_t(size_t, sdev->inquiry_len, 36),
				GFP_KERNEL);
	if (sdev->inquiry == NULL)
		return SCSI_SCAN_NO_RESPONSE;

	// 厂商
	sdev->vendor = (char *) (sdev->inquiry + 8);
	// 模型
	sdev->model = (char *) (sdev->inquiry + 16);
	// 版本号
	sdev->rev = (char *) (sdev->inquiry + 32);

	// ata设备, 如注释,做的妥协
	if (strncmp(sdev->vendor, "ATA     ", 8) == 0) {
		/*
		 * sata emulation layer device.  This is a hack to work around
		 * the SATL power management specifications which state that
		 * when the SATL detects the device has gone into standby
		 * mode, it shall respond with NOT READY.
		 */
		sdev->allow_restart = 1;
	}

	if (*bflags & BLIST_ISROM) {
		// CD-ROM
		sdev->type = TYPE_ROM;
		sdev->removable = 1;
	} else {
		// 其它设备

		// 设置类型和可移动属性
		sdev->type = (inq_result[0] & 0x1f);
		sdev->removable = (inq_result[1] & 0x80) >> 7;

		// 有些设备的lun类型和type类型不同
		if (scsi_is_wlun(sdev->lun) && sdev->type != TYPE_WLUN) {
			sdev_printk(KERN_WARNING, sdev,
				"%s: correcting incorrect peripheral device type 0x%x for W-LUN 0x%16xhN\n",
				__func__, sdev->type, (unsigned int)sdev->lun);
			sdev->type = TYPE_WLUN;
		}

	}

	// what?
	if (sdev->type == TYPE_RBC || sdev->type == TYPE_ROM) {
		/* RBC and MMC devices can return SCSI-3 compliance and yet
		 * still not support REPORT LUNS, so make them act as
		 * BLIST_NOREPORTLUN unless BLIST_REPORTLUN2 is
		 * specifically set */
		if ((*bflags & BLIST_REPORTLUN2) == 0)
			*bflags |= BLIST_NOREPORTLUN;
	}

	/*
	 * For a peripheral qualifier (PQ) value of 1 (001b), the SCSI
	 * spec says: The device server is capable of supporting the
	 * specified peripheral device type on this logical unit. However,
	 * the physical device is not currently connected to this logical
	 * unit.
	 *
	 * The above is vague, as it implies that we could treat 001 and
	 * 011 the same. Stay compatible with previous code, and create a
	 * scsi_device for a PQ of 1
	 *
	 * Don't set the device offline here; rather let the upper
	 * level drivers eval the PQ to decide whether they should
	 * attach. So remove ((inq_result[0] >> 5) & 7) == 1 check.
	 */ 

	sdev->inq_periph_qual = (inq_result[0] >> 5) & 7;
	sdev->lockable = sdev->removable;
	sdev->soft_reset = (inq_result[7] & 1) && ((inq_result[3] & 7) == 2);

	if (sdev->scsi_level >= SCSI_3 ||
			(sdev->inquiry_len > 56 && inq_result[56] & 0x04))
		sdev->ppr = 1;
	if (inq_result[7] & 0x60)
		sdev->wdtr = 1;
	if (inq_result[7] & 0x10)
		sdev->sdtr = 1;

	sdev_printk(KERN_NOTICE, sdev, "%s %.8s %.16s %.4s PQ: %d "
			"ANSI: %d%s\n", scsi_device_type(sdev->type),
			sdev->vendor, sdev->model, sdev->rev,
			sdev->inq_periph_qual, inq_result[2] & 0x07,
			(inq_result[3] & 0x0f) == 1 ? " CCS" : "");

	if ((sdev->scsi_level >= SCSI_2) && (inq_result[7] & 2) &&
	    !(*bflags & BLIST_NOTQ)) {
		sdev->tagged_supported = 1;
		sdev->simple_tags = 1;
	}

	/*
	 * Some devices (Texel CD ROM drives) have handshaking problems
	 * when used with the Seagate controllers. borken is initialized
	 * to 1, and then set it to 0 here.
	 */
	if ((*bflags & BLIST_BORKEN) == 0)
		sdev->borken = 0;

	if (*bflags & BLIST_NO_ULD_ATTACH)
		sdev->no_uld_attach = 1;

	/*
	 * Apparently some really broken devices (contrary to the SCSI
	 * standards) need to be selected without asserting ATN
	 */
	if (*bflags & BLIST_SELECT_NO_ATN)
		sdev->select_no_atn = 1;

	/*
	 * Maximum 512 sector transfer length
	 * broken RA4x00 Compaq Disk Array
	 */
	if (*bflags & BLIST_MAX_512)
		blk_queue_max_hw_sectors(sdev->request_queue, 512);
	/*
	 * Max 1024 sector transfer length for targets that report incorrect
	 * max/optimal lengths and relied on the old block layer safe default
	 */
	else if (*bflags & BLIST_MAX_1024)
		blk_queue_max_hw_sectors(sdev->request_queue, 1024);

	/*
	 * Some devices may not want to have a start command automatically
	 * issued when a device is added.
	 */
	if (*bflags & BLIST_NOSTARTONADD)
		sdev->no_start_on_add = 1;

	if (*bflags & BLIST_SINGLELUN)
		scsi_target(sdev)->single_lun = 1;

	sdev->use_10_for_rw = 1;

	/* some devices don't like REPORT SUPPORTED OPERATION CODES
	 * and will simply timeout causing sd_mod init to take a very
	 * very long time */
	if (*bflags & BLIST_NO_RSOC)
		sdev->no_report_opcodes = 1;

	/* set the device running here so that slave configure
	 * may do I/O */
	mutex_lock(&sdev->state_mutex);
	// 设置运行状态
	ret = scsi_device_set_state(sdev, SDEV_RUNNING);
	if (ret)
		// 若失败，设置block状态？
		ret = scsi_device_set_state(sdev, SDEV_BLOCK);
	mutex_unlock(&sdev->state_mutex);

	if (ret) {
		sdev_printk(KERN_ERR, sdev,
			    "in wrong state %s to complete scan\n",
			    scsi_device_state_name(sdev->sdev_state));
		return SCSI_SCAN_NO_RESPONSE;
	}

	if (*bflags & BLIST_NOT_LOCKABLE)
		sdev->lockable = 0;

	if (*bflags & BLIST_RETRY_HWERROR)
		sdev->retry_hwerror = 1;

	if (*bflags & BLIST_NO_DIF)
		sdev->no_dif = 1;

	if (*bflags & BLIST_UNMAP_LIMIT_WS)
		sdev->unmap_limit_for_ws = 1;

	// SCSI_DEFAULT_EH_TIMEOUT＝10秒
	sdev->eh_timeout = SCSI_DEFAULT_EH_TIMEOUT;

	if (*bflags & BLIST_TRY_VPD_PAGES)
		sdev->try_vpd_pages = 1;
	else if (*bflags & BLIST_SKIP_VPD_PAGES)
		sdev->skip_vpd_pages = 1;

	// 配置设备
	transport_configure_device(&sdev->sdev_gendev);

	// 有这个函数则调用之
	if (sdev->host->hostt->slave_configure) {
		ret = sdev->host->hostt->slave_configure(sdev);
		if (ret) {
			/*
			 * if LLDD reports slave not present, don't clutter
			 * console with alloc failure messages
			 */
			if (ret != -ENXIO) {
				sdev_printk(KERN_ERR, sdev,
					"failed to configure device\n");
			}
			return SCSI_SCAN_NO_RESPONSE;
		}
	}

	if (sdev->scsi_level >= SCSI_3)
		scsi_attach_vpd(sdev);

	// 队列深度
	sdev->max_queue_depth = sdev->queue_depth;
	// 设置标志
	sdev->sdev_bflags = *bflags;

	// 不是异步的话，现在就同步加到sysfs里，如果是异步的话，在scsi_finish_async_scan
	// 里会执行这个函数
	if (!async && scsi_sysfs_add_sdev(sdev) != 0)
		return SCSI_SCAN_NO_RESPONSE;

	// 添加成功，返回在位
	return SCSI_SCAN_LUN_PRESENT;
}
```