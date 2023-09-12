# 执行命令
源码基于5.10

## blk_execute_rq
```c
void blk_execute_rq(struct request_queue *q, struct gendisk *bd_disk,
		   struct request *rq, int at_head)
{
	DECLARE_COMPLETION_ONSTACK(wait);
	unsigned long hang_check;

	// 设置完成量
	rq->end_io_data = &wait;
	// 执行请求，最后一个参数是执行完请求时调用的函数
	blk_execute_rq_nowait(q, bd_disk, rq, at_head, blk_end_sync_rq);

	// 等待请求完成

	hang_check = sysctl_hung_task_timeout_secs;
	if (hang_check)
		// 如果有hang_timeout，则调用timeout函数
		while (!wait_for_completion_io_timeout(&wait, hang_check * (HZ/2)));
	else
		wait_for_completion_io(&wait);
}

static void blk_end_sync_rq(struct request *rq, blk_status_t error)
{
	struct completion *waiting = rq->end_io_data;

	// 清空数据指针
	rq->end_io_data = NULL;

	// 完成等待
	complete(waiting);
}

void blk_execute_rq_nowait(struct request_queue *q, struct gendisk *bd_disk,
			   struct request *rq, int at_head,
			   rq_end_io_fn *done)
{
	WARN_ON(irqs_disabled());
	WARN_ON(!blk_rq_is_passthrough(rq));

	rq->rq_disk = bd_disk;
	// 执行完io时调用的函数
	rq->end_io = done;

	blk_account_io_start(rq);

	/*
	 * don't check dying flag for MQ because the request won't
	 * be reused after dying flag is set
	 */
	blk_mq_sched_insert_request(rq, at_head, true, false);
}
```

## scsi_softirq_done
```c
static void scsi_softirq_done(struct request *rq)
{
	// cmd
	struct scsi_cmnd *cmd = blk_mq_rq_to_pdu(rq);
	int disposition;

	// 初始化eh头
	INIT_LIST_HEAD(&cmd->eh_entry);

	//　统计设备完成的数量
	atomic_inc(&cmd->device->iodone_cnt);
	if (cmd->result)
		atomic_inc(&cmd->device->ioerr_cnt);

	// 决定如果处理请求
	disposition = scsi_decide_disposition(cmd);
	if (disposition != SUCCESS && scsi_cmd_runtime_exceeced(cmd))
		disposition = SUCCESS;

	scsi_log_completion(cmd, disposition);

	switch (disposition) {
	case SUCCESS:
		// 这个只表示请求完成，错误和成功都会走这个分支
		scsi_finish_command(cmd);
		break;
	case NEEDS_RETRY:
		// 重新加入请求队列
		scsi_queue_insert(cmd, SCSI_MLQUEUE_EH_RETRY);
		break;
	case ADD_TO_MLQUEUE:
		// 重新插入请求队列
		scsi_queue_insert(cmd, SCSI_MLQUEUE_DEVICE_BUSY);
		break;
	default:
		// 其他情况进行错误恢复
		scsi_eh_scmd_add(cmd);
		break;
	}
}

int scsi_decide_disposition(struct scsi_cmnd *scmd)
{
	int rtn;

	/*
	 * if the device is offline, then we clearly just pass the result back
	 * up to the top level.
	 */
	if (!scsi_device_online(scmd->device)) {
		SCSI_LOG_ERROR_RECOVERY(5, scmd_printk(KERN_INFO, scmd,
			"%s: device offline - report as SUCCESS\n", __func__));
		return SUCCESS;
	}

	/*
	 * first check the host byte, to see if there is anything in there
	 * that would indicate what we need to do.
	 */
	switch (host_byte(scmd->result)) {
	case DID_PASSTHROUGH:
		/*
		 * no matter what, pass this through to the upper layer.
		 * nuke this special code so that it looks like we are saying
		 * did_ok.
		 */
		scmd->result &= 0xff00ffff;
		return SUCCESS;
	case DID_OK:
		/*
		 * looks good.  drop through, and check the next byte.
		 */
		break;
	case DID_ABORT:
		if (scmd->eh_eflags & SCSI_EH_ABORT_SCHEDULED) {
			set_host_byte(scmd, DID_TIME_OUT);
			return SUCCESS;
		}
		fallthrough;
	case DID_NO_CONNECT:
	case DID_BAD_TARGET:
		/*
		 * note - this means that we just report the status back
		 * to the top level driver, not that we actually think
		 * that it indicates SUCCESS.
		 */
		return SUCCESS;
	case DID_SOFT_ERROR:
		/*
		 * when the low level driver returns did_soft_error,
		 * it is responsible for keeping an internal retry counter
		 * in order to avoid endless loops (db)
		 */
		goto maybe_retry;
	case DID_IMM_RETRY:
		return NEEDS_RETRY;

	case DID_REQUEUE:
		return ADD_TO_MLQUEUE;
	case DID_TRANSPORT_DISRUPTED:
		/*
		 * LLD/transport was disrupted during processing of the IO.
		 * The transport class is now blocked/blocking,
		 * and the transport will decide what to do with the IO
		 * based on its timers and recovery capablilities if
		 * there are enough retries.
		 */
		goto maybe_retry;
	case DID_TRANSPORT_FAILFAST:
		/*
		 * The transport decided to failfast the IO (most likely
		 * the fast io fail tmo fired), so send IO directly upwards.
		 */
		return SUCCESS;
	case DID_ERROR:
		if (msg_byte(scmd->result) == COMMAND_COMPLETE &&
		    status_byte(scmd->result) == RESERVATION_CONFLICT)
			/*
			 * execute reservation conflict processing code
			 * lower down
			 */
			break;
		fallthrough;
	case DID_BUS_BUSY:
	case DID_PARITY:
		goto maybe_retry;
	case DID_TIME_OUT:
		/*
		 * when we scan the bus, we get timeout messages for
		 * these commands if there is no device available.
		 * other hosts report did_no_connect for the same thing.
		 */
		if ((scmd->cmnd[0] == TEST_UNIT_READY ||
		     scmd->cmnd[0] == INQUIRY)) {
			return SUCCESS;
		} else {
			return FAILED;
		}
	case DID_RESET:
		return SUCCESS;
	default:
		return FAILED;
	}

	/*
	 * next, check the message byte.
	 */
	if (msg_byte(scmd->result) != COMMAND_COMPLETE)
		return FAILED;

	/*
	 * check the status byte to see if this indicates anything special.
	 */
	switch (status_byte(scmd->result)) {
	case QUEUE_FULL:
		scsi_handle_queue_full(scmd->device);
		/*
		 * the case of trying to send too many commands to a
		 * tagged queueing device.
		 */
		fallthrough;
	case BUSY:
		/*
		 * device can't talk to us at the moment.  Should only
		 * occur (SAM-3) when the task queue is empty, so will cause
		 * the empty queue handling to trigger a stall in the
		 * device.
		 */
		return ADD_TO_MLQUEUE;
	case GOOD:
		if (scmd->cmnd[0] == REPORT_LUNS)
			scmd->device->sdev_target->expecting_lun_change = 0;
		scsi_handle_queue_ramp_up(scmd->device);
		fallthrough;
	case COMMAND_TERMINATED:
		return SUCCESS;
	case TASK_ABORTED:
		goto maybe_retry;
	case CHECK_CONDITION:
		rtn = scsi_check_sense(scmd);
		if (rtn == NEEDS_RETRY)
			goto maybe_retry;
		/* if rtn == FAILED, we have no sense information;
		 * returning FAILED will wake the error handler thread
		 * to collect the sense and redo the decide
		 * disposition */
		return rtn;
	case CONDITION_GOOD:
	case INTERMEDIATE_GOOD:
	case INTERMEDIATE_C_GOOD:
	case ACA_ACTIVE:
		/*
		 * who knows?  FIXME(eric)
		 */
		return SUCCESS;

	case RESERVATION_CONFLICT:
		sdev_printk(KERN_INFO, scmd->device,
			    "reservation conflict\n");
		set_host_byte(scmd, DID_NEXUS_FAILURE);
		return SUCCESS; /* causes immediate i/o error */
	default:
		return FAILED;
	}
	return FAILED;

maybe_retry:

	/* we requeue for retry because the error was retryable, and
	 * the request was not marked fast fail.  Note that above,
	 * even if the request is marked fast fail, we still requeue
	 * for queue congestion conditions (QUEUE_FULL or BUSY) */
	if (scsi_cmd_retry_allowed(scmd) && !scsi_noretry_cmd(scmd)) {
		return NEEDS_RETRY;
	} else {
		/*
		 * no more retries - report this one back to upper level.
		 */
		return SUCCESS;
	}
}
```

## scsi_times_out
```c
enum blk_eh_timer_return scsi_times_out(struct request *req)
{
	struct scsi_cmnd *scmd = blk_mq_rq_to_pdu(req);
	enum blk_eh_timer_return rtn = BLK_EH_DONE;
	struct Scsi_Host *host = scmd->device->host;

	trace_scsi_dispatch_cmd_timeout(scmd);
	scsi_log_completion(scmd, TIMEOUT_ERROR);

	if (host->eh_deadline != -1 && !host->last_reset)
		host->last_reset = jiffies;

	// 如果有timeout函数，则调用之
	if (host->hostt->eh_timed_out)
		rtn = host->hostt->eh_timed_out(scmd);

	// 如果返回DONE，表示错误已经处理
	if (rtn == BLK_EH_DONE) {
		/*
		 * Set the command to complete first in order to prevent a real
		 * completion from releasing the command while error handling
		 * is using it. If the command was already completed, then the
		 * lower level driver beat the timeout handler, and it is safe
		 * to return without escalating error recovery.
		 *
		 * If timeout handling lost the race to a real completion, the
		 * block layer may ignore that due to a fake timeout injection,
		 * so return RESET_TIMER to allow error handling another shot
		 * at this command.
		 */
		if (test_and_set_bit(SCMD_STATE_COMPLETE, &scmd->state))
			return BLK_EH_RESET_TIMER;
		if (scsi_abort_command(scmd) != SUCCESS) {
			set_host_byte(scmd, DID_TIME_OUT);
			scsi_eh_scmd_add(scmd);
		}
	}

	return rtn;
}
```