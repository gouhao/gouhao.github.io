# eh init

## scsi_error_handler
```c
int scsi_error_handler(void *data)
{
	struct Scsi_Host *shost = data;

	while (true) {
		// 避免错过唤醒。一般是先设置stop标志，然后才唤醒
		set_current_state(TASK_INTERRUPTIBLE);
		if (kthread_should_stop())
			break;

		// (没有失败过 && 没有调用过eh) || 失败次数不等于忙的计数
		if ((shost->host_failed == 0 && shost->host_eh_scheduled == 0) ||
		    shost->host_failed != scsi_host_busy(shost)) {
			// todo: 啥意思？
			SCSI_LOG_ERROR_RECOVERY(1,
				shost_printk(KERN_INFO, shost,
					     "scsi_eh_%d: sleeping\n",
					     shost->host_no));
			// 重新调度
			schedule();
			continue;
		}

		// 设置状态为running
		__set_current_state(TASK_RUNNING);
		SCSI_LOG_ERROR_RECOVERY(1,
			shost_printk(KERN_INFO, shost,
				     "scsi_eh_%d: waking up %d/%d/%d\n",
				     shost->host_no, shost->host_eh_scheduled,
				     shost->host_failed,
				     scsi_host_busy(shost)));

		// 在错误处理的时候不唤醒scsi host
		if (!shost->eh_noresume && scsi_autopm_get_host(shost) != 0) {
			SCSI_LOG_ERROR_RECOVERY(1,
				shost_printk(KERN_ERR, shost,
					     "scsi_eh_%d: unable to autoresume\n",
					     shost->host_no));
			continue;
		}

		if (shost->transportt->eh_strategy_handler)
			shost->transportt->eh_strategy_handler(shost);
		else
			scsi_unjam_host(shost);

		/* All scmds have been handled */
		shost->host_failed = 0;

		/*
		 * Note - if the above fails completely, the action is to take
		 * individual devices offline and flush the queue of any
		 * outstanding requests that may have been pending.  When we
		 * restart, we restart any I/O to any other devices on the bus
		 * which are still online.
		 */
		scsi_restart_operations(shost);
		if (!shost->eh_noresume)
			scsi_autopm_put_host(shost);
	}
	__set_current_state(TASK_RUNNING);

	SCSI_LOG_ERROR_RECOVERY(1,
		shost_printk(KERN_INFO, shost,
			     "Error handler scsi_eh_%d exiting\n",
			     shost->host_no));
	shost->ehandler = NULL;
	return 0;
}
```