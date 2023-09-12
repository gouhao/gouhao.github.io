# scsi 相关结构
源码基于5.10
```c
struct Scsi_Host {
	/*
	 * __devices is protected by the host_lock, but you should
	 * usually use scsi_device_lookup / shost_for_each_device
	 * to access it and don't care about locking yourself.
	 * In the rare case of being in irq context you can use
	 * their __ prefixed variants with the lock held. NEVER
	 * access this list directly from a driver.
	 */
	struct list_head	__devices; // 识别到的scsi device
	struct list_head	__targets; // 识别到的scsi target
	
	struct list_head	starved_list; // 可能长时间没有得到执行的scsi device

	spinlock_t		default_lock;
	spinlock_t		*host_lock; // Scsi host锁

	struct mutex		scan_mutex;// 扫描过程使用锁

	struct list_head	eh_cmd_q; // EH时将异常的命令放入此链
	struct task_struct    * ehandler;  // 错误处理/恢复线程
	struct completion     * eh_action; // 等待具体的命令
	wait_queue_head_t       host_wait;
	struct scsi_host_template *hostt;
	struct scsi_transport_template *transportt; // Scsi_transport_template 传输层模板，驱动可以覆盖

	/* Area to keep a shared tag map */
	struct blk_mq_tag_set	tag_set; // Share tag驱动使用的blk_mq_tag_set

	atomic_t host_blocked; // 被阻塞的host数目

	unsigned int host_failed;	   /* commands that failed.
					      protected by host_lock */
	unsigned int host_eh_scheduled;    // 尝试调用EH的次数
    
	unsigned int host_no;  // host-id

	/* next two fields are used to bound the time spent in error handling */
	int eh_deadline;
	unsigned long last_reset; // 上次reset时间


	/*
	 * These three parameters can be used to allow for wide scsi,
	 * and for host adapters that support multiple busses
	 * The last two should be set to 1 more than the actual max id
	 * or lun (e.g. 8 for SCSI parallel systems).
	 */
	unsigned int max_channel; // 支持最大channel
	unsigned int max_id; // 支持最大的id
	u64 max_lun; // 最大的lun

	/*
	 * This is a unique identifier that must be assigned so that we
	 * have some way of identifying each detected host adapter properly
	 * and uniquely.  For hosts that do not support more than one card
	 * in the system at one time, this does not need to be set.  It is
	 * initialized to 0 in scsi_register.
	 */
	unsigned int unique_id; // 唯一id

	/*
	 * The maximum length of SCSI commands that this host can accept.
	 * Probably 12 for most host adapters, but could be 16 for others.
	 * or 260 if the driver supports variable length cdbs.
	 * For drivers that don't set this field, a value of 12 is
	 * assumed.
	 */
	unsigned short max_cmd_len; // 最大命令长度

	int this_id;
	int can_queue; // 表示队列最大深度
	short cmd_per_lun; // 表示每个硬盘深度
	short unsigned int sg_tablesize; // 表示最大segment数目
	short unsigned int sg_prot_tablesize; // 表示最大port segment数目
	unsigned int max_sectors; // 表示IO支持最大sector
	unsigned int max_segment_size; // 表示IO支持最大segment的size
	unsigned long dma_boundary;
	unsigned long virt_boundary_mask;
	/*
	 * In scsi-mq mode, the number of hardware queues supported by the LLD.
	 *
	 * Note: it is assumed that each hardware queue has a queue depth of
	 * can_queue. In other words, the total queue depth per host
	 * is nr_hw_queues * can_queue. However, for when host_tagset is set,
	 * the total queue depth is can_queue.
	 */
	unsigned nr_hw_queues; // 表示支持的硬件队列数目
	unsigned active_mode:2;
	unsigned unchecked_isa_dma:1;

	/*
	 * Host has requested that no further requests come through for the
	 * time being.
	 */
	unsigned host_self_blocked:1;
    
	/*
	 * Host uses correct SCSI ordering not PC ordering. The bit is
	 * set for the minority of drivers whose authors actually read
	 * the spec ;).
	 */
	unsigned reverse_ordering:1;

	/* Task mgmt function in progress */
	unsigned tmf_in_progress:1;

	unsigned async_scan:1; // 异步扫描正在进行中

	// =1 在错误处理之前不去唤醒scsi host, =0 在错误处理前唤醒scsi host
	unsigned eh_noresume:1;

	/* The controller does not support WRITE SAME */
	unsigned no_write_same:1;

	/* True if the host uses host-wide tagspace */
	unsigned host_tagset:1; // 表示使用share-tag

	/* Host responded with short (<36 bytes) INQUIRY result */
	unsigned short_inquiry:1;

	/* The transport requires the LUN bits NOT to be stored in CDB[1] */
	unsigned no_scsi2_lun_in_cdb:1;

	/*
	 * Optional work queue to be utilized by the transport
	 */
	char work_q_name[20];
	struct workqueue_struct *work_q; // workqueue

	/*
	 * Task management function work queue
	 */
	struct workqueue_struct *tmf_work_q;

	/*
	 * Value host_blocked counts down from
	 */
	unsigned int max_host_blocked;

	/* Protection Information */
	unsigned int prot_capabilities; // 保护信息的能力
	unsigned char prot_guard_type; // 保护信息的guard类型

	/* 遗留的，目前驱动很少用 */
	unsigned long base;
	unsigned long io_port;
	unsigned char n_io_port;
	unsigned char dma_channel;
	unsigned int  irq;
	

	enum scsi_host_state shost_state; // scsi host的状态

	// gendev链接到scsi_bus总线, dev 链接到scsi_class
	struct device		shost_gendev, shost_dev; // host的设备

	/*
	 * Points to the transport data (if any) which is allocated
	 * separately
	 */
	void *shost_data; // 一般用于指示到底层驱动对应的hba结构体

	/*
	 * Points to the physical bus device we'd use to do DMA
	 * Needed just in case we have virtual hosts.
	 */
	struct device *dma_dev;

	/*
	 * We should ensure that this is aligned, both for better performance
	 * and also because some compilers (m68k) don't automatically force
	 * alignment to a long boundary.
	 */
	unsigned long hostdata[]  // 可用于存储host相关数据
		__attribute__ ((aligned (sizeof(unsigned long))));
};

struct scsi_host_template {
	struct module *module;
	const char *name;

	/*
	 * The info function will return whatever useful information the
	 * developer sees fit.  If not provided, then the name field will
	 * be used instead.
	 *
	 * Status: OPTIONAL
	 */
	const char *(* info)(struct Scsi_Host *);

	/*
	 * Ioctl interface
	 *
	 * Status: OPTIONAL
	 */
	int (*ioctl)(struct scsi_device *dev, unsigned int cmd,
		     void __user *arg);


#ifdef CONFIG_COMPAT
	/* 
	 * Compat handler. Handle 32bit ABI.
	 * When unknown ioctl is passed return -ENOIOCTLCMD.
	 *
	 * Status: OPTIONAL
	 */
	int (*compat_ioctl)(struct scsi_device *dev, unsigned int cmd,
			    void __user *arg);
#endif

	// 若cmd_size中定义底层驱动私有结构长度，可以通过此接口初始化私有结构，若未定义此接口默认清0
	int (*init_cmd_priv)(struct Scsi_Host *shost, struct scsi_cmnd *cmd);
	int (*exit_cmd_priv)(struct Scsi_Host *shost, struct scsi_cmnd *cmd);

	/*
	 * The queuecommand function is used to queue up a scsi
	 * command block to the LLDD.  When the driver finished
	 * processing the command the done callback is invoked.
	 *
	 * If queuecommand returns 0, then the driver has accepted the
	 * command.  It must also push it to the HBA if the scsi_cmnd
	 * flag SCMD_LAST is set, or if the driver does not implement
	 * commit_rqs.  The done() function must be called on the command
	 * when the driver has finished with it. (you may call done on the
	 * command before queuecommand returns, but in this case you
	 * *must* return 0 from queuecommand).
	 *
	 * Queuecommand may also reject the command, in which case it may
	 * not touch the command and must not call done() for it.
	 *
	 * There are two possible rejection returns:
	 *
	 *   SCSI_MLQUEUE_DEVICE_BUSY: Block this device temporarily, but
	 *   allow commands to other devices serviced by this host.
	 *
	 *   SCSI_MLQUEUE_HOST_BUSY: Block all devices served by this
	 *   host temporarily.
	 *
         * For compatibility, any other non-zero return is treated the
         * same as SCSI_MLQUEUE_HOST_BUSY.
	 *
	 * NOTE: "temporarily" means either until the next command for#
	 * this device/host completes, or a period of time determined by
	 * I/O pressure in the system if there are no other outstanding
	 * commands.
	 *
	 * STATUS: REQUIRED
	 */
	// IO下发函数，各SCSI驱动需要填充
	int (* queuecommand)(struct Scsi_Host *, struct scsi_cmnd *);

	/*
	 * The commit_rqs function is used to trigger a hardware
	 * doorbell after some requests have been queued with
	 * queuecommand, when an error is encountered before sending
	 * the request with SCMD_LAST set.
	 *
	 * STATUS: OPTIONAL
	 */
	void (*commit_rqs)(struct Scsi_Host *, u16);

	/*
	 * This is an error handling strategy routine.  You don't need to
	 * define one of these if you don't want to - there is a default
	 * routine that is present that should work in most cases.  For those
	 * driver authors that have the inclination and ability to write their
	 * own strategy routine, this is where it is specified.  Note - the
	 * strategy routine is *ALWAYS* run in the context of the kernel eh
	 * thread.  Thus you are guaranteed to *NOT* be in an interrupt
	 * handler when you execute this, and you are also guaranteed to
	 * *NOT* have any other commands being queued while you are in the
	 * strategy routine. When you return from this function, operations
	 * return to normal.
	 *
	 * See scsi_error.c scsi_unjam_host for additional comments about
	 * what this function should and should not be attempting to do.
	 *
	 * Status: REQUIRED	(at least one of them)
	 */
	// 错误处理使用，逐步升级处理

	// SCSI错误处理函数，用于abort一个SCSI命令
	int (* eh_abort_handler)(struct scsi_cmnd *);
	// SCSI错误处理函数，用于对device发送device reset
	int (* eh_device_reset_handler)(struct scsi_cmnd *);
	// SCSI错误处理函数，用于对target发送target reset
	int (* eh_target_reset_handler)(struct scsi_cmnd *);
	// SCSI错误处理函数，用于发送bus reset
	int (* eh_bus_reset_handler)(struct scsi_cmnd *);
	// SCSI错误处理函数，用于发送host reset
	int (* eh_host_reset_handler)(struct scsi_cmnd *);

	/*
	 * Before the mid layer attempts to scan for a new device where none
	 * currently exists, it will call this entry in your driver.  Should
	 * your driver need to allocate any structs or perform any other init
	 * items in order to send commands to a currently unused target/lun
	 * combo, then this is where you can perform those allocations.  This
	 * is specifically so that drivers won't have to perform any kind of
	 * "is this a new device" checks in their queuecommand routine,
	 * thereby making the hot path a bit quicker.
	 *
	 * Return values: 0 on success, non-0 on failure
	 *
	 * Deallocation:  If we didn't find any devices at this ID, you will
	 * get an immediate call to slave_destroy().  If we find something
	 * here then you will get a call to slave_configure(), then the
	 * device will be used for however long it is kept around, then when
	 * the device is removed from the system (or * possibly at reboot
	 * time), you will then get a call to slave_destroy().  This is
	 * assuming you implement slave_configure and slave_destroy.
	 * However, if you allocate memory and hang it off the device struct,
	 * then you must implement the slave_destroy() routine at a minimum
	 * in order to avoid leaking memory
	 * each time a device is tore down.
	 *
	 * Status: OPTIONAL
	 */
	// 在SCSI device识别过程中调用
	int (* slave_alloc)(struct scsi_device *);

	/*
	 * Once the device has responded to an INQUIRY and we know the
	 * device is online, we call into the low level driver with the
	 * struct scsi_device *.  If the low level device driver implements
	 * this function, it *must* perform the task of setting the queue
	 * depth on the device.  All other tasks are optional and depend
	 * on what the driver supports and various implementation details.
	 * 
	 * Things currently recommended to be handled at this time include:
	 *
	 * 1.  Setting the device queue depth.  Proper setting of this is
	 *     described in the comments for scsi_change_queue_depth.
	 * 2.  Determining if the device supports the various synchronous
	 *     negotiation protocols.  The device struct will already have
	 *     responded to INQUIRY and the results of the standard items
	 *     will have been shoved into the various device flag bits, eg.
	 *     device->sdtr will be true if the device supports SDTR messages.
	 * 3.  Allocating command structs that the device will need.
	 * 4.  Setting the default timeout on this device (if needed).
	 * 5.  Anything else the low level driver might want to do on a device
	 *     specific setup basis...
	 * 6.  Return 0 on success, non-0 on error.  The device will be marked
	 *     as offline on error so that no access will occur.  If you return
	 *     non-0, your slave_destroy routine will never get called for this
	 *     device, so don't leave any loose memory hanging around, clean
	 *     up after yourself before returning non-0
	 *
	 * Status: OPTIONAL
	 */
	// 在SCSI device识别过程中调用
	int (* slave_configure)(struct scsi_device *);

	/*
	 * Immediately prior to deallocating the device and after all activity
	 * has ceased the mid layer calls this point so that the low level
	 * driver may completely detach itself from the scsi device and vice
	 * versa.  The low level driver is responsible for freeing any memory
	 * it allocated in the slave_alloc or slave_configure calls. 
	 *
	 * Status: OPTIONAL
	 */
	// 在SCSI device释放过程中调用
	void (* slave_destroy)(struct scsi_device *);

	/*
	 * Before the mid layer attempts to scan for a new device attached
	 * to a target where no target currently exists, it will call this
	 * entry in your driver.  Should your driver need to allocate any
	 * structs or perform any other init items in order to send commands
	 * to a currently unused target, then this is where you can perform
	 * those allocations.
	 *
	 * Return values: 0 on success, non-0 on failure
	 *
	 * Status: OPTIONAL
	 */
	// 在SCSI target识别过程中调用
	int (* target_alloc)(struct scsi_target *);

	/*
	 * Immediately prior to deallocating the target structure, and
	 * after all activity to attached scsi devices has ceased, the
	 * midlayer calls this point so that the driver may deallocate
	 * and terminate any references to the target.
	 *
	 * Status: OPTIONAL
	 */
	// 在SCSI target释放过程中调用
	void (* target_destroy)(struct scsi_target *);

	/*
	 * If a host has the ability to discover targets on its own instead
	 * of scanning the entire bus, it can fill in this function and
	 * call scsi_scan_host().  This function will be called periodically
	 * until it returns 1 with the scsi_host and the elapsed time of
	 * the scan in jiffies.
	 *
	 * Status: OPTIONAL
	 */
	// 判断是否扫描scsi device结束
	int (* scan_finished)(struct Scsi_Host *, unsigned long);

	/*
	 * If the host wants to be called before the scan starts, but
	 * after the midlayer has set up ready for the scan, it can fill
	 * in this function.
	 *
	 * Status: OPTIONAL
	 */
	// 开始扫描scsi device
	void (* scan_start)(struct Scsi_Host *);

	/*
	 * Fill in this function to allow the queue depth of this host
	 * to be changeable (on a per device basis).  Returns either
	 * the current queue depth setting (may be different from what
	 * was passed in) or an error.  An error should only be
	 * returned if the requested depth is legal but the driver was
	 * unable to set it.  If the requested depth is illegal, the
	 * driver should set and return the closest legal queue depth.
	 *
	 * Status: OPTIONAL
	 */
	// 用于修改scsi device的队列深度
	int (* change_queue_depth)(struct scsi_device *, int);

	/*
	 * This functions lets the driver expose the queue mapping
	 * to the block layer.
	 *
	 * Status: OPTIONAL
	 */
	// 用于驱动将硬件队列映射到BLOCK层
	int (* map_queues)(struct Scsi_Host *shost);

	/*
	 * Check if scatterlists need to be padded for DMA draining.
	 *
	 * Status: OPTIONAL
	 */
	bool (* dma_need_drain)(struct request *rq);

	/*
	 * This function determines the BIOS parameters for a given
	 * harddisk.  These tend to be numbers that are made up by
	 * the host adapter.  Parameters:
	 * size, device, list (heads, sectors, cylinders)
	 *
	 * Status: OPTIONAL
	 */
	int (* bios_param)(struct scsi_device *, struct block_device *,
			sector_t, int []);

	/*
	 * This function is called when one or more partitions on the
	 * device reach beyond the end of the device.
	 *
	 * Status: OPTIONAL
	 */
	void (*unlock_native_capacity)(struct scsi_device *);

	/*
	 * Can be used to export driver statistics and other infos to the
	 * world outside the kernel ie. userspace and it also provides an
	 * interface to feed the driver with information.
	 *
	 * Status: OBSOLETE
	 */
	// 用于将驱动数据和信息导出到用户态
	int (*show_info)(struct seq_file *, struct Scsi_Host *);
	int (*write_info)(struct Scsi_Host *, char *, int);

	/*
	 * This is an optional routine that allows the transport to become
	 * involved when a scsi io timer fires. The return value tells the
	 * timer routine how to finish the io timeout handling.
	 *
	 * Status: OPTIONAL
	 */
	// EH超时处理
	enum blk_eh_timer_return (*eh_timed_out)(struct scsi_cmnd *);

	/* This is an optional routine that allows transport to initiate
	 * LLD adapter or firmware reset using sysfs attribute.
	 *
	 * Return values: 0 on success, -ve value on failure.
	 *
	 * Status: OPTIONAL
	 */
	// 控制器复位接口
	int (*host_reset)(struct Scsi_Host *shost, int reset_type);
#define SCSI_ADAPTER_RESET	1
#define SCSI_FIRMWARE_RESET	2


	/*
	 * Name of proc directory
	 */
	const char *proc_name;

	/*
	 * Used to store the procfs directory if a driver implements the
	 * show_info method.
	 */
	struct proc_dir_entry *proc_dir;

	/*
	 * This determines if we will use a non-interrupt driven
	 * or an interrupt driven scheme.  It is set to the maximum number
	 * of simultaneous commands a single hw queue in HBA will accept.
	 */
	// 硬件队列深度
	int can_queue;

	/*
	 * In many instances, especially where disconnect / reconnect are
	 * supported, our host also has an ID on the SCSI bus.  If this is
	 * the case, then it must be reserved.  Please set this_id to -1 if
	 * your setup is in single initiator mode, and the host lacks an
	 * ID.
	 */
	int this_id;

	/*
	 * This determines the degree to which the host adapter is capable
	 * of scatter-gather.
	 */
	unsigned short sg_tablesize; // 每个IO最大segment数目
	unsigned short sg_prot_tablesize;

	/*
	 * Set this if the host adapter has limitations beside segment count.
	 */
	unsigned int max_sectors; // 每个IO支持最大sector

	/*
	 * Maximum size in bytes of a single segment.
	 */
	unsigned int max_segment_size; // 每个segment最大的size

	/*
	 * DMA scatter gather segment boundary limit. A segment crossing this
	 * boundary will be split in two.
	 */
	unsigned long dma_boundary; // DMA边界

	unsigned long virt_boundary_mask;

	/*
	 * This specifies "machine infinity" for host templates which don't
	 * limit the transfer size.  Note this limit represents an absolute
	 * maximum, and may be over the transfer limits allowed for
	 * individual devices (e.g. 256 for SCSI-1).
	 */
#define SCSI_DEFAULT_MAX_SECTORS	1024

	/*
	 * True if this host adapter can make good use of linked commands.
	 * This will allow more than one command to be queued to a given
	 * unit on a given host.  Set this to the maximum number of command
	 * blocks to be provided for each device.  Set this to 1 for one
	 * command block per lun, 2 for two, etc.  Do not set this to 0.
	 * You should make sure that the host adapter will do the right thing
	 * before you try setting this above 1.
	 */
	short cmd_per_lun; // 队列深度

	/*
	 * present contains counter indicating how many boards of this
	 * type were found when we did the scan.
	 */
	unsigned char present; // 在增加proc hostdir时增加，表示有多少个hos

	/* If use block layer to manage tags, this is tag allocation policy */
	int tag_alloc_policy; // 默认不设置为BLK_TAG_ALLOC_FIFO，可以设置为BLK_TAG_ALLOC_RR

	/*
	 * Track QUEUE_FULL events and reduce queue depth on demand.
	 */
	unsigned track_queue_depth:1; // 跟踪QUEUE_FULL事件，减少队列深度

	/*
	 * This specifies the mode that a LLD supports.
	 */
	unsigned supported_mode:2; // 默认为MODE_INITIATOR

	/*
	 * True if this host adapter uses unchecked DMA onto an ISA bus.
	 */
	unsigned unchecked_isa_dma:1;

	/*
	 * True for emulated SCSI host adapters (e.g. ATAPI).
	 */
	unsigned emulated:1;

	/*
	 * True if the low-level driver performs its own reset-settle delays.
	 */
	unsigned skip_settle_delay:1; // 是否在eh_host_reset_handler之后需要休眠HOST_RESET_SETTLE_TIME秒

	/* True if the controller does not support WRITE SAME */
	unsigned no_write_same:1; // 是否控制器支持WRITE SAME

	/* True if the host uses host-wide tagspace */
	unsigned host_tagset:1; // 是否为share tag驱动

	/*
	 * Countdown for host blocking with no commands outstanding.
	 */
	unsigned int max_host_blocked; // 最大host被blocked次数

	/*
	 * Default value for the blocking.  If the queue is empty,
	 * host_blocked counts down in the request_fn until it restarts
	 * host operations as zero is reached.  
	 *
	 * FIXME: This should probably be a value in the template
	 */
#define SCSI_DEFAULT_HOST_BLOCKED	7

	/*
	 * Pointer to the sysfs class properties for this host, NULL terminated.
	 */
	struct device_attribute **shost_attrs; // host属性相关，sysfs

	/*
	 * Pointer to the SCSI device properties for this host, NULL terminated.
	 */
	struct device_attribute **sdev_attrs; // dev属性相关，sysfs

	/*
	 * Pointer to the SCSI device attribute groups for this host,
	 * NULL terminated.
	 */
	const struct attribute_group **sdev_groups;

	/*
	 * Vendor Identifier associated with the host
	 *
	 * Note: When specifying vendor_id, be sure to read the
	 *   Vendor Type and ID formatting requirements specified in
	 *   scsi_netlink.h
	 */
	u64 vendor_id; // 厂商ID

	/*
	 * Additional per-command data allocated for the driver.
	 */
	unsigned int cmd_size; // 提前分配request/scsi command时可以为底层驱动分配的per-command数据大小
	struct scsi_host_cmd_pool *cmd_pool;

	/* Delay for runtime autosuspend */
	int rpm_autosuspend_delay; // 是否开启scsi device的autosuspend延时，与scsi/block runtime PM相关
};

struct scsi_target {
	struct scsi_device	*starget_sdev_user; // 指向进行io的设备，如果没有io，则该域为NULL
	struct list_head	siblings; // 兄弟节点
	struct list_head	devices; // target上的设备
	struct device		dev; // 本身的设备，链入scsi_bus_type
	struct kref		reap_ref; /* last put renders target invisible */
	unsigned int		channel; // 通道号
	unsigned int		id; // id号
	unsigned int		create:1; /* signal that it needs to be added */
	unsigned int		single_lun:1;	/* 一次只允许一个节点进行io */
	unsigned int		pdt_1f_for_no_lun:1;	/* PDT = 0x1f
						 * means no lun present. */
	unsigned int		no_report_luns:1;	/* Don't use
						 * REPORT LUNS for scanning. */
	unsigned int		expecting_lun_change:1;	/* A device has reported
						 * a 3F/0E UA, other devices on
						 * the same target will also. */
	/* commands actually active on LLD. */
	atomic_t		target_busy;
	atomic_t		target_blocked;

	/*
	 * LLDs should set this in the slave_alloc host template callout.
	 * If set to zero then there is not limit.
	 */
	unsigned int		can_queue;
	unsigned int		max_target_blocked;
#define SCSI_DEFAULT_TARGET_BLOCKED	3

	char			scsi_level;
	enum scsi_target_state	state;
	void 			*hostdata; /* available to low-level driver */
	unsigned long		starget_data[]; /* for the transport */
	/* starget_data must be the last element!!!! */
} __attribute__((aligned(sizeof(unsigned long))));

struct scsi_disk {
	struct scsi_driver *driver;　// scsi驱动
	struct scsi_device *device; // scsi设备
	struct device	dev;
	struct gendisk	*disk;　// 通用磁盘
	struct opal_dev *opal_dev;
#ifdef CONFIG_BLK_DEV_ZONED
	u32		nr_zones;
	u32		rev_nr_zones;
	u32		zone_blocks;
	u32		rev_zone_blocks;
	u32		zones_optimal_open;
	u32		zones_optimal_nonseq;
	u32		zones_max_open;
	u32		*zones_wp_offset;
	spinlock_t	zones_wp_offset_lock;
	u32		*rev_wp_offset;
	struct mutex	rev_mutex;
	struct work_struct zone_wp_offset_work;
	char		*zone_wp_update_buf;
#endif
	atomic_t	openers;
	sector_t	capacity;	/* size in logical blocks */
	int		max_retries;
	u32		max_xfer_blocks;
	u32		opt_xfer_blocks;
	u32		max_ws_blocks;
	u32		max_unmap_blocks;
	u32		unmap_granularity;
	u32		unmap_alignment;
	u32		index;
	unsigned int	physical_block_size;
	unsigned int	max_medium_access_timeouts;
	unsigned int	medium_access_timed_out;
	u8		media_present;
	u8		write_prot;
	u8		protection_type;/* Data Integrity Field */
	u8		provisioning_mode;
	u8		zeroing_mode;
	unsigned	ATO : 1;	/* state of disk ATO bit */
	unsigned	cache_override : 1; /* temp override of WCE,RCD */
	unsigned	WCE : 1;	/* state of disk WCE bit */
	unsigned	RCD : 1;	/* state of disk RCD bit, unused */
	unsigned	DPOFUA : 1;	/* state of disk DPOFUA bit */
	unsigned	first_scan : 1;
	unsigned	lbpme : 1;
	unsigned	lbprz : 1;
	unsigned	lbpu : 1;
	unsigned	lbpws : 1;
	unsigned	lbpws10 : 1;
	unsigned	lbpvpd : 1;
	unsigned	ws10 : 1;
	unsigned	ws16 : 1;
	unsigned	rc_basis: 2;
	unsigned	zoned: 2;
	unsigned	urswrz : 1;
	unsigned	security : 1;
	unsigned	ignore_medium_access_errors : 1;
};

// 对应一个lun，它可能不是当前操作系统上的设备，可能是另一存储设备上的
struct scsi_device {
	struct Scsi_Host *host; // 所在的host
	struct request_queue *request_queue; // 请求队列

	/* the next two are protected by the host->host_lock */
	struct list_head    siblings;   /* 链接到host的device链表 */
	struct list_head    same_target_siblings; /* 链接到目标target链表 */

	atomic_t device_busy;		/* commands actually active on LLDD */
	atomic_t device_blocked;	/* Device returned QUEUE_FULL. */

	atomic_t restarts;
	spinlock_t list_lock;
	struct list_head starved_entry;
	unsigned short queue_depth;	/* How deep of a queue we want */
	unsigned short max_queue_depth;	/* max queue depth */
	unsigned short last_queue_full_depth; /* These two are used by */
	unsigned short last_queue_full_count; /* scsi_track_queue_full() */
	unsigned long last_queue_full_time;	/* last queue full time */
	unsigned long queue_ramp_up_period;	/* ramp up period in jiffies */
#define SCSI_DEFAULT_RAMP_UP_PERIOD	(120 * HZ)

	unsigned long last_queue_ramp_up;	/* last queue ramp up time */

	unsigned int id, channel; // id号，通道号
	u64 lun; // lun号
	unsigned int manufacturer;	/* Manufacturer of device, for using 
					 * vendor-specific cmd's */
	unsigned sector_size;	/* size in bytes */

	void *hostdata;		/* 底层私有数据 */
	unsigned char type; // INQUIRY响应里的设备类型，高层驱动将根据这一类型来判断是否支持此设备
	char scsi_level;
	char inq_periph_qual;	/* PQ from INQUIRY data */	
	struct mutex inquiry_mutex;
	unsigned char inquiry_len;	/* valid bytes in 'inquiry' */
	unsigned char * inquiry;	/* INQUIRY 响应结果 */
	const char * vendor;		/* INQUIRY的8~15字节*/
	const char * model;		/* INQUIRY的16~31字节 */
	const char * rev;		/* INQUIRY的32~35字节 */

#define SCSI_VPD_PG_LEN                255
	struct scsi_vpd __rcu *vpd_pg0;
	struct scsi_vpd __rcu *vpd_pg83;
	struct scsi_vpd __rcu *vpd_pg80;
	struct scsi_vpd __rcu *vpd_pg89;
	unsigned char current_tag;	/* current tag */
	struct scsi_target      *sdev_target;   /* used only for single_lun */

	blist_flags_t		sdev_bflags; /* black/white flags as also found in
				 * scsi_devinfo.[hc]. For now used only to
				 * pass settings from slave_alloc to scsi
				 * core. */
	unsigned int eh_timeout; /* Error handling timeout */
	unsigned removable:1;
	unsigned changed:1;	/* Data invalid due to media change */
	unsigned busy:1;	/* Used to prevent races */
	unsigned lockable:1;	/* Able to prevent media removal */
	unsigned locked:1;      /* Media removal disabled */
	unsigned borken:1;	/* Tell the Seagate driver to be 
				 * painfully slow on this device */
	unsigned disconnect:1;	/* can disconnect */
	unsigned soft_reset:1;	/* Uses soft reset option */
	unsigned sdtr:1;	/* Device supports SDTR messages */
	unsigned wdtr:1;	/* Device supports WDTR messages */
	unsigned ppr:1;		/* Device supports PPR messages */
	unsigned tagged_supported:1;	/* Supports SCSI-II tagged queuing */
	unsigned simple_tags:1;	/* simple queue tag messages are enabled */
	unsigned was_reset:1;	/* There was a bus reset on the bus for 
				 * this device */
	unsigned expecting_cc_ua:1; /* Expecting a CHECK_CONDITION/UNIT_ATTN
				     * because we did a bus reset. */
	unsigned use_10_for_rw:1; /* first try 10-byte read / write */
	unsigned use_10_for_ms:1; /* first try 10-byte mode sense/select */
	unsigned set_dbd_for_ms:1; /* Set "DBD" field in mode sense */
	unsigned no_report_opcodes:1;	/* no REPORT SUPPORTED OPERATION CODES */
	unsigned no_write_same:1;	/* no WRITE SAME command */
	unsigned use_16_for_rw:1; /* Use read/write(16) over read/write(10) */
	unsigned skip_ms_page_8:1;	/* do not use MODE SENSE page 0x08 */
	unsigned skip_ms_page_3f:1;	/* do not use MODE SENSE page 0x3f */
	unsigned skip_vpd_pages:1;	/* do not read VPD pages */
	unsigned try_vpd_pages:1;	/* attempt to read VPD pages */
	unsigned use_192_bytes_for_3f:1; /* ask for 192 bytes from page 0x3f */
	unsigned no_start_on_add:1;	/* do not issue start on add */
	unsigned allow_restart:1; /* issue START_UNIT in error handler */
	unsigned manage_start_stop:1;	/* Let HLD (sd) manage start/stop */
	unsigned start_stop_pwr_cond:1;	/* Set power cond. in START_STOP_UNIT */
	unsigned no_uld_attach:1; /* disable connecting to upper level drivers */
	unsigned select_no_atn:1;
	unsigned fix_capacity:1;	/* READ_CAPACITY is too high by 1 */
	unsigned guess_capacity:1;	/* READ_CAPACITY might be too high by 1 */
	unsigned retry_hwerror:1;	/* Retry HARDWARE_ERROR */
	unsigned last_sector_bug:1;	/* do not use multisector accesses on
					   SD_LAST_BUGGY_SECTORS */
	unsigned no_read_disc_info:1;	/* Avoid READ_DISC_INFO cmds */
	unsigned no_read_capacity_16:1; /* Avoid READ_CAPACITY_16 cmds */
	unsigned try_rc_10_first:1;	/* Try READ_CAPACACITY_10 first */
	unsigned security_supported:1;	/* Supports Security Protocols */
	unsigned is_visible:1;	/* is the device visible in sysfs */
	unsigned wce_default_on:1;	/* Cache is ON by default */
	unsigned no_dif:1;	/* T10 PI (DIF) should be disabled */
	unsigned broken_fua:1;		/* Don't set FUA bit */
	unsigned lun_in_cdb:1;		/* Store LUN bits in CDB[1] */
	unsigned unmap_limit_for_ws:1;	/* Use the UNMAP limit for WRITE SAME */
	unsigned rpm_autosuspend:1;	/* Enable runtime autosuspend at device
					 * creation time */

	bool offline_already;		/* Device offline message logged */

	atomic_t disk_events_disable_depth; /* disable depth for disk events */

	DECLARE_BITMAP(supported_events, SDEV_EVT_MAXBITS); /* supported events */
	DECLARE_BITMAP(pending_events, SDEV_EVT_MAXBITS); /* pending events */
	struct list_head event_list;	/* asserted events */
	struct work_struct event_work;

	unsigned int max_device_blocked; /* what device_blocked counts down from  */
#define SCSI_DEFAULT_DEVICE_BLOCKED	3

	atomic_t iorequest_cnt;
	atomic_t iodone_cnt;　// io完成数量
	atomic_t ioerr_cnt;　// 有结果的io数量

	struct device		sdev_gendev, // 链接到scsi总线
				sdev_dev; // 链接到scsi_device_class

	struct execute_work	ew; /* used to get process context on put */
	struct work_struct	requeue_work;

	struct scsi_device_handler *handler;
	void			*handler_data;

	size_t			dma_drain_len;
	void			*dma_drain_buf;

	unsigned char		access_state;
	struct mutex		state_mutex;
	enum scsi_device_state sdev_state;
	struct task_struct	*quiesced_by;
	unsigned long		sdev_data[]; // 私有数据
} __attribute__((aligned(sizeof(unsigned long))));

struct scsi_cmnd {
	struct scsi_request req;
	struct scsi_device *device; // 属SCSI设备的描述符的指针
	struct list_head eh_entry; // 当SCSI命令执行出错或超时，故障命令以eh_entry链到host的eh_cmd_q
	struct delayed_work abort_work;

	struct rcu_head rcu; // 链入到所属SCSI设备的命令链表

	int eh_eflags;		/* Used by error handlr */

	/*
	 * This is set to jiffies as it was when the command was first
	 * allocated.  It is used to time how long the command has
	 * been outstanding
	 */
	unsigned long jiffies_at_alloc;

	int retries;
	int allowed;

	unsigned char prot_op;
	unsigned char prot_type;
	unsigned char prot_flags;

	unsigned short cmd_len; // 命令长度
	enum dma_data_direction sc_data_direction; // 命令的方向

	// 命令字符串
	unsigned char *cmnd;


	/* These elements define the operation we ultimately want to perform */
	struct scsi_data_buffer sdb; // SCSI命令的数据缓冲区，对于读操作，由SCSI低层驱动填入，对于写操作，则由SCSI中间层填入。
	struct scsi_data_buffer *prot_sdb;

	unsigned underflow;	/* Return error if less than
				   this amount is transferred */

	unsigned transfersize;	/* How much we are guaranteed to
				   transfer with each SCSI transfer
				   (ie, between disconnect / 
				   reconnects.   Probably == sector
				   size */

	struct request *request;	/* The command we are
				   	   working on */

	unsigned char *sense_buffer;
				/* obtained by REQUEST SENSE when
				 * CHECK CONDITION is received on original
				 * command (auto-sense). Length must be
				 * SCSI_SENSE_BUFFERSIZE bytes. */

	// 低层使用的完成函数
	void (*scsi_done) (struct scsi_cmnd *);

	/*
	 * The following fields can be written to by the host specific code. 
	 * Everything else should be left alone. 
	 */
	struct scsi_pointer SCp;	/* Scratchpad used by some host adapters */

	unsigned char *host_scribble;	/* The host adapter is allowed to
					 * call scsi_malloc and get some memory
					 * and hang it here.  The host adapter
					 * is also expected to call scsi_free
					 * to release this memory.  (The memory
					 * obtained by scsi_malloc is guaranteed
					 * to be at an address < 16Mb). */

	int result;		/* Status code from lower level driver */
	int flags;		/* Command flags */
	unsigned long state;	/* Command completion state */

	unsigned char tag;	/* SCSI-II queued command tag */
	unsigned int extra_len;	/* length of alignment and padding */
};
```