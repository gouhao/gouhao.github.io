# Scsi子系统初始化
源码基于5.10

## init_scsi
```c
static int __init init_scsi(void)
{
	int error;

	error = scsi_init_procfs();
	if (error)
		goto cleanup_queue;
	error = scsi_init_devinfo();
	if (error)
		goto cleanup_procfs;
	error = scsi_init_hosts();
	if (error)
		goto cleanup_devlist;
	error = scsi_init_sysctl();
	if (error)
		goto cleanup_hosts;
	error = scsi_sysfs_register();
	if (error)
		goto cleanup_sysctl;

	scsi_netlink_init();

	printk(KERN_NOTICE "SCSI subsystem initialized\n");
	return 0;

cleanup_sysctl:
	scsi_exit_sysctl();
cleanup_hosts:
	scsi_exit_hosts();
cleanup_devlist:
	scsi_exit_devinfo();
cleanup_procfs:
	scsi_exit_procfs();
cleanup_queue:
	scsi_exit_queue();
	printk(KERN_ERR "SCSI subsystem failed to initialize, error = %d\n",
	       -error);
	return error;
}
```