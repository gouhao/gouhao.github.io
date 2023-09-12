# 下发请求

## scsi_queue_rq
```c
static blk_status_t scsi_queue_rq(struct blk_mq_hw_ctx *hctx,
			 const struct blk_mq_queue_data *bd)
{
	struct request *req = bd->rq;
	struct request_queue *q = req->q;
	struct scsi_device *sdev = q->queuedata;
	struct Scsi_Host *shost = sdev->host;
	struct scsi_cmnd *cmd = blk_mq_rq_to_pdu(req);
	blk_status_t ret;
	int reason;

	/*
	 * If the device is not in running state we will reject some or all
	 * commands.
	 */
	if (unlikely(sdev->sdev_state != SDEV_RUNNING)) {
		ret = scsi_device_state_check(sdev, req);
		if (ret != BLK_STS_OK)
			goto out_put_budget;
	}

	ret = BLK_STS_RESOURCE;
	if (!scsi_target_queue_ready(shost, sdev))
		goto out_put_budget;
	if (!scsi_host_queue_ready(q, shost, sdev, cmd))
		goto out_dec_target_busy;

	if (!(req->rq_flags & RQF_DONTPREP)) {
		ret = scsi_prepare_cmd(req);
		if (ret != BLK_STS_OK)
			goto out_dec_host_busy;
		req->rq_flags |= RQF_DONTPREP;
	} else {
		clear_bit(SCMD_STATE_COMPLETE, &cmd->state);
	}

	cmd->flags &= SCMD_PRESERVED_FLAGS;
	if (sdev->simple_tags)
		cmd->flags |= SCMD_TAGGED;
	if (bd->last)
		cmd->flags |= SCMD_LAST;

	scsi_set_resid(cmd, 0);
	memset(cmd->sense_buffer, 0, SCSI_SENSE_BUFFERSIZE);
	// 完成时的回调
	cmd->scsi_done = scsi_mq_done;

	blk_mq_start_request(req);
	reason = scsi_dispatch_cmd(cmd);
	if (reason) {
		scsi_set_blocked(cmd, reason);
		ret = BLK_STS_RESOURCE;
		goto out_dec_host_busy;
	}

	return BLK_STS_OK;

out_dec_host_busy:
	scsi_dec_host_busy(shost, cmd);
out_dec_target_busy:
	if (scsi_target(sdev)->can_queue > 0)
		atomic_dec(&scsi_target(sdev)->target_busy);
out_put_budget:
	scsi_mq_put_budget(q);
	switch (ret) {
	case BLK_STS_OK:
		break;
	case BLK_STS_RESOURCE:
	case BLK_STS_ZONE_RESOURCE:
		if (scsi_device_blocked(sdev))
			ret = BLK_STS_DEV_RESOURCE;
		break;
	default:
		if (unlikely(!scsi_device_online(sdev)))
			scsi_req(req)->result = DID_NO_CONNECT << 16;
		else
			scsi_req(req)->result = DID_ERROR << 16;
		/*
		 * Make sure to release all allocated resources when
		 * we hit an error, as we will never see this command
		 * again.
		 */
		if (req->rq_flags & RQF_DONTPREP)
			scsi_mq_uninit_cmd(cmd);
		scsi_run_queue_async(sdev);
		break;
	}
	return ret;
}

static void scsi_mq_done(struct scsi_cmnd *cmd)
{
	if (unlikely(blk_should_fake_timeout(cmd->request->q)))
		return;
	if (unlikely(test_and_set_bit(SCMD_STATE_COMPLETE, &cmd->state)))
		return;
	trace_scsi_dispatch_cmd_done(cmd);
	blk_mq_complete_request(cmd->request);
}

static int scsi_dispatch_cmd(struct scsi_cmnd *cmd)
{
	struct Scsi_Host *host = cmd->device->host;
	int rtn = 0;

	atomic_inc(&cmd->device->iorequest_cnt);

	/* check if the device is still usable */
	if (unlikely(cmd->device->sdev_state == SDEV_DEL)) {
		/* in SDEV_DEL we error all commands. DID_NO_CONNECT
		 * returns an immediate error upwards, and signals
		 * that the device is no longer present */
		cmd->result = DID_NO_CONNECT << 16;
		goto done;
	}

	/* Check to see if the scsi lld made this device blocked. */
	if (unlikely(scsi_device_blocked(cmd->device))) {
		/*
		 * in blocked state, the command is just put back on
		 * the device queue.  The suspend state has already
		 * blocked the queue so future requests should not
		 * occur until the device transitions out of the
		 * suspend state.
		 */
		SCSI_LOG_MLQUEUE(3, scmd_printk(KERN_INFO, cmd,
			"queuecommand : device blocked\n"));
		return SCSI_MLQUEUE_DEVICE_BUSY;
	}

	/* Store the LUN value in cmnd, if needed. */
	if (cmd->device->lun_in_cdb)
		cmd->cmnd[1] = (cmd->cmnd[1] & 0x1f) |
			       (cmd->device->lun << 5 & 0xe0);

	scsi_log_send(cmd);

	/*
	 * Before we queue this command, check if the command
	 * length exceeds what the host adapter can handle.
	 */
	if (cmd->cmd_len > cmd->device->host->max_cmd_len) {
		SCSI_LOG_MLQUEUE(3, scmd_printk(KERN_INFO, cmd,
			       "queuecommand : command too long. "
			       "cdb_size=%d host->max_cmd_len=%d\n",
			       cmd->cmd_len, cmd->device->host->max_cmd_len));
		cmd->result = (DID_ABORT << 16);
		goto done;
	}

	if (unlikely(host->shost_state == SHOST_DEL)) {
		cmd->result = (DID_NO_CONNECT << 16);
		goto done;

	}

	trace_scsi_dispatch_cmd_start(cmd);
	rtn = host->hostt->queuecommand(host, cmd);
	if (rtn) {
		trace_scsi_dispatch_cmd_error(cmd, rtn);
		if (rtn != SCSI_MLQUEUE_DEVICE_BUSY &&
		    rtn != SCSI_MLQUEUE_TARGET_BUSY)
			rtn = SCSI_MLQUEUE_HOST_BUSY;

		SCSI_LOG_MLQUEUE(3, scmd_printk(KERN_INFO, cmd,
			"queuecommand : request rejected\n"));
	}

	return rtn;
 done:
	cmd->scsi_done(cmd);
	return 0;
}
```