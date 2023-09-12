# scsi bus
源码基于5.10

## scsi_bus_match
```c
static int scsi_bus_match(struct device *dev, struct device_driver *gendrv)
{
	struct scsi_device *sdp;

	// 设备类型不是scsi类型
	if (dev->type != &scsi_dev_type)
		return 0;

	// 转换成scsi设备
	sdp = to_scsi_device(dev);

	// 禁止连接到上层驱动
	if (sdp->no_uld_attach)
		return 0;
	// pq状态是SCSI_INQ_PQ_CON就可以匹配
	return (sdp->inq_periph_qual == SCSI_INQ_PQ_CON)? 1: 0;
}
```