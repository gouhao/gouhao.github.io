# 执行请求

## scsi_execute_req
```c
static inline int scsi_execute_req(struct scsi_device *sdev,
	const unsigned char *cmd, int data_direction, void *buffer,
	unsigned bufflen, struct scsi_sense_hdr *sshdr, int timeout,
	int retries, int *resid)
{
	return scsi_execute(sdev, cmd, data_direction, buffer,
		bufflen, NULL, sshdr, timeout, retries,  0, 0, resid);
}

#define scsi_execute(sdev, cmd, data_direction, buffer, bufflen, sense,	\
		     sshdr, timeout, retries, flags, rq_flags, resid)	\
({									\
	BUILD_BUG_ON((sense) != NULL &&					\
		     sizeof(sense) != SCSI_SENSE_BUFFERSIZE);		\
	__scsi_execute(sdev, cmd, data_direction, buffer, bufflen,	\
		       sense, sshdr, timeout, retries, flags, rq_flags,	\
		       resid);						\
})

int __scsi_execute(struct scsi_device *sdev, const unsigned char *cmd,
		 int data_direction, void *buffer, unsigned bufflen,
		 unsigned char *sense, struct scsi_sense_hdr *sshdr,
		 int timeout, int retries, u64 flags, req_flags_t rq_flags,
		 int *resid)
{
	struct request *req;
	struct scsi_request *rq;
	int ret = DRIVER_ERROR << 24;

	// 获取一个请求
	req = blk_get_request(sdev->request_queue,
			data_direction == DMA_TO_DEVICE ?
			REQ_OP_SCSI_OUT : REQ_OP_SCSI_IN,
			rq_flags & RQF_PM ? BLK_MQ_REQ_PM : 0);
	if (IS_ERR(req))
		return ret;
	// 转换成scsi请求
	rq = scsi_req(req);

	// 映射一个内核数据到块层请求
	if (bufflen &&	blk_rq_map_kern(sdev->request_queue, req,
					buffer, bufflen, GFP_NOIO))
		goto out;

	// 设置请求的一些参数
	rq->cmd_len = COMMAND_SIZE(cmd[0]);
	// 命令
	memcpy(rq->cmd, cmd, rq->cmd_len);
	// 重试次数
	rq->retries = retries;
	// 超时时间
	req->timeout = timeout;
	req->cmd_flags |= flags;
	req->rq_flags |= rq_flags | RQF_QUIET;

	// 把请求插入队列里，最后一个参数1表示放在队列头，因为这个请求比较紧急
	// 这个函数是阻塞的，请求执行完才会返回
	blk_execute_rq(req->q, NULL, req, 1);

	/*
	 * Some devices (USB mass-storage in particular) may transfer
	 * garbage data together with a residue indicating that the data
	 * is invalid.  Prevent the garbage from being misinterpreted
	 * and prevent security leaks by zeroing out the excess data.
	 */
	if (unlikely(rq->resid_len > 0 && rq->resid_len <= bufflen))
		memset(buffer + (bufflen - rq->resid_len), 0, rq->resid_len);

	if (resid)
		*resid = rq->resid_len;
	if (sense && rq->sense_len)
		memcpy(sense, rq->sense, SCSI_SENSE_BUFFERSIZE);
	if (sshdr)
		scsi_normalize_sense(rq->sense, rq->sense_len, sshdr);
	ret = rq->result;
 out:
	blk_put_request(req);

	return ret;
}



static inline struct scsi_request *scsi_req(struct request *rq)
{
	return blk_mq_rq_to_pdu(rq);
}

static inline void *blk_mq_rq_to_pdu(struct request *rq)
{
	return rq + 1;
}
```