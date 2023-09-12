# sd设备

## sd_open
```c
static int sd_open(struct block_device *bdev, fmode_t mode)
{
	// 获取scsi磁盘
	struct scsi_disk *sdkp = scsi_disk_get(bdev->bd_disk);
	struct scsi_device *sdev;
	int retval;

	if (!sdkp)
		return -ENXIO;

	SCSI_LOG_HLQUEUE(3, sd_printk(KERN_INFO, sdkp, "sd_open\n"));

	// scsi设备
	sdev = sdkp->device;

	retval = -ENXIO;
	// 设备正常进行设备恢复,则要等待它完成
	if (!scsi_block_when_processing_errors(sdev))
		goto error_out;


	// 需要重新使生效
	if (sd_need_revalidate(bdev, sdkp))
		sd_revalidate_disk(bdev->bd_disk);

	retval = -ENOMEDIUM;
	// 设备不在位?
	if (sdev->removable && !sdkp->media_present && !(mode & FMODE_NDELAY))
		goto error_out;

	retval = -EROFS;
	// 以写方式打开写保护的设备
	if (sdkp->write_prot && (mode & FMODE_WRITE))
		goto error_out;

	retval = -ENXIO;
	// 设备不在线也失败
	if (!scsi_device_online(sdev))
		goto error_out;

	// 递增openers, 打开计数器 && 设备是可移除的
	if ((atomic_inc_return(&sdkp->openers) == 1) && sdev->removable) {
		// 如果设备在线
		if (scsi_block_when_processing_errors(sdev))
			// 设置移除状态?
			scsi_set_medium_removal(sdev, SCSI_REMOVAL_PREVENT);
	}

	return 0;

error_out:
	scsi_disk_put(sdkp);
	return retval;	
}

int scsi_block_when_processing_errors(struct scsi_device *sdev)
{
	int online;

	wait_event(sdev->host->host_wait, !scsi_host_in_recovery(sdev->host));

	online = scsi_device_online(sdev);

	return online;
}

int scsi_set_medium_removal(struct scsi_device *sdev, char state)
{
	char scsi_cmd[MAX_COMMAND_SIZE];
	int ret;

	if (!sdev->removable || !sdev->lockable)
	       return 0;

	scsi_cmd[0] = ALLOW_MEDIUM_REMOVAL;
	scsi_cmd[1] = 0;
	scsi_cmd[2] = 0;
	scsi_cmd[3] = 0;
	scsi_cmd[4] = state;
	scsi_cmd[5] = 0;

	ret = ioctl_internal_command(sdev, scsi_cmd,
			IOCTL_NORMAL_TIMEOUT, NORMAL_RETRIES);
	if (ret == 0)
		sdev->locked = (state == SCSI_REMOVAL_PREVENT);
	return ret;
}

static bool sd_need_revalidate(struct block_device *bdev,
		struct scsi_disk *sdkp)
{
	if (sdkp->device->removable || sdkp->write_prot) {
		if (bdev_check_media_change(bdev))
			return true;
	}

	/*
	 * Force a full rescan after ioctl(BLKRRPART).  While the disk state has
	 * nothing to do with partitions, BLKRRPART is used to force a full
	 * revalidate after things like a format for historical reasons.
	 */
	return test_bit(GD_NEED_PART_SCAN, &bdev->bd_disk->state);
}
```