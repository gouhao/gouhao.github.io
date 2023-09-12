# 结构体
源码基于5.10

```c
struct bio {
	struct bio		*bi_next;	//链接到请求队列的下一个bio
	struct gendisk		*bi_disk;	//指向磁盘
	unsigned int		bi_opf;		// 低位请求标志，高位操作标志
	unsigned short		bi_flags;	//状态标志
	unsigned short		bi_ioprio;
	unsigned short		bi_write_hint;
	blk_status_t		bi_status;
	u8			bi_partno;	//分区号
	atomic_t		__bi_remaining;

	struct bvec_iter	bi_iter; // 数据在硬盘中位置以及当前IO数据的完成情况

	bio_end_io_t		*bi_end_io;	//bio的io操作完成时调用的方法

	void			*bi_private;	//通用块层和驱动程序保存自定义数据
#ifdef CONFIG_BLK_CGROUP
	/*
	 * Represents the association of the css and request_queue for the bio.
	 * If a bio goes direct to device, it will not have a blkg as it will
	 * not have a request_queue associated with it.  The reference is put
	 * on release of the bio.
	 */
	struct blkcg_gq		*bi_blkg;
	struct bio_issue	bi_issue;
#ifdef CONFIG_BLK_CGROUP_IOCOST
	u64			bi_iocost_cost;
#endif
#endif

#ifdef CONFIG_BLK_INLINE_ENCRYPTION
	struct bio_crypt_ctx	*bi_crypt_context;
#endif

	union {
#if defined(CONFIG_BLK_DEV_INTEGRITY)
		struct bio_integrity_payload *bi_integrity; /* data integrity */
#endif
	};

	unsigned short		bi_vcnt;	//bi_io_vec里的数目

	/*
	 * Everything starting with bi_max_vecs will be preserved by bio_reset()
	 */

	unsigned short		bi_max_vecs;	/* max bvl_vecs we can hold */

	atomic_t		__bi_cnt;	//引用计数

	struct bio_vec		*bi_io_vec;	// 描述io数据在内存中的组织

	struct bio_set		*bi_pool;

	// 内部申请一些bio_vec，避免多次申请释放bio
	struct bio_vec		bi_inline_vecs[];
};

// nth_page(@bv_page, n) == @bv_page + n， if n * PAGE_SIZE < bv_offset + bv_len
struct bio_vec {
	struct page	*bv_page; // 内存起点
	unsigned int	bv_len; // 内存长度（字节为单位）
	unsigned int	bv_offset; // bv_page里的起点
};

struct bvec_iter {
	sector_t		bi_sector;	// 起始扇区号
	unsigned int		bi_size;	// 剩余未完成的大小

	unsigned int		bi_idx;		// 当前处理的bi_io_vec索引号，前面的都已完成
	unsigned int            bi_bvec_done;	// 当前bi_io_vec已完成的数量（字节为单位）
};

struct bio_set {
	struct kmem_cache *bio_slab; // 分配bio的slab
	unsigned int front_pad;

	// bio和bio_vec会优化从bio_slab里分配，如果slab分配不到了，会从这2个池子里分配
	mempool_t bio_pool; // 分配bio的内存池
	mempool_t bvec_pool; // 分配 bi_io_vec的内存池
#if defined(CONFIG_BLK_DEV_INTEGRITY)
	mempool_t bio_integrity_pool;
	mempool_t bvec_integrity_pool;
#endif

	/*
	 * Deadlock avoidance for stacking block drivers: see comments in
	 * bio_alloc_bioset() for details
	 */
	spinlock_t		rescue_lock;
	struct bio_list		rescue_list;
	struct work_struct	rescue_work;
	struct workqueue_struct	*rescue_workqueue;
};

// 分配 bi_io_vec 的slab
struct biovec_slab {
	int nr_vecs;
	char *name;
	struct kmem_cache *slab;
};

struct gendisk {
	/* 不要直接使用major, first_minor and minors。Use disk_devt() and disk_max_parts(). */
	int major;			//主设备号
	int first_minor;		//次设备号起点
	int minors;                     //最大的次设备号, =1 表示磁盘不能被分区

	char disk_name[DISK_NAME_LEN];	//磁盘名

	unsigned short events;		/* supported events */
	unsigned short event_flags;	/* flags related to event processing */

	struct disk_part_tbl __rcu *part_tbl;	//分区表
	struct hd_struct part0;	//0号分区

	const struct block_device_operations *fops;	//指向块设备操作表的指针
	struct request_queue *queue;	//磁盘请求队列指针
	void *private_data;	//驱动程序的私有数据

	int flags;	//磁盘类型标志
	unsigned long state;	//磁盘状态
#define GD_NEED_PART_SCAN		0
	struct rw_semaphore lookup_sem;
	struct kobject *slave_dir;

	struct timer_rand_state *random;
	atomic_t sync_io;		/* RAID */
	struct disk_events *ev;
#ifdef  CONFIG_BLK_DEV_INTEGRITY
	struct kobject integrity_kobj;
#endif	/* CONFIG_BLK_DEV_INTEGRITY */
#if IS_ENABLED(CONFIG_CDROM)
	struct cdrom_device_info *cdi;
#endif
	int node_id;
	struct badblocks *bb;
	struct lockdep_map lockdep_map;
};

struct request_queue {
	struct request		*last_merge; // 最后合并的请求
	struct elevator_queue	*elevator; // 电梯队列

	struct percpu_ref	q_usage_counter;

	struct blk_queue_stats	*stats;
	struct rq_qos		*rq_qos;

	const struct blk_mq_ops	*mq_ops;

	/* sw queues */
	struct blk_mq_ctx __percpu	*queue_ctx; // 软件队列

	unsigned int		queue_depth;

	/* hw dispatch queues */
	struct blk_mq_hw_ctx	**queue_hw_ctx; // 硬件上下文
	unsigned int		nr_hw_queues; // 硬上下文数量

	struct backing_dev_info	*backing_dev_info;

	/*
	 * The queue owner gets to use this for whatever they like.
	 * ll_rw_blk doesn't touch it.
	 */
	void			*queuedata;

	/*
	 * various queue flags, see QUEUE_* below
	 */
	unsigned long		queue_flags;
	/*
	 * Number of contexts that have called blk_set_pm_only(). If this
	 * counter is above zero then only RQF_PM requests are processed.
	 */
	atomic_t		pm_only;

	/*
	 * ida allocated id for this queue.  Used to index queues from
	 * ioctx.
	 */
	int			id;

	/*
	 * queue needs bounce pages for pages above this limit
	 */
	gfp_t			bounce_gfp;

	spinlock_t		queue_lock;

	/*
	 * queue kobject
	 */
	struct kobject kobj; // rq本身的kobj

	struct kobject *mq_kobj;// 队列的kobj

#ifdef  CONFIG_BLK_DEV_INTEGRITY
	struct blk_integrity integrity;
#endif	/* CONFIG_BLK_DEV_INTEGRITY */

#ifdef CONFIG_PM
	struct device		*dev;
	enum rpm_status		rpm_status;
	unsigned int		nr_pending;
#endif

	/*
	 * queue settings
	 */
	unsigned long		nr_requests;	/* Max # of requests */

	unsigned int		dma_pad_mask;
	unsigned int		dma_alignment;

#ifdef CONFIG_BLK_INLINE_ENCRYPTION
	/* Inline crypto capabilities */
	struct blk_keyslot_manager *ksm;
#endif

	unsigned int		rq_timeout;
	int			poll_nsec;

	struct blk_stat_callback	*poll_cb;
	struct blk_rq_stat	poll_stat[BLK_MQ_POLL_STATS_BKTS];

	struct timer_list	timeout;
	struct work_struct	timeout_work;

	atomic_t		nr_active_requests_shared_sbitmap;

	struct list_head	icq_list;
#ifdef CONFIG_BLK_CGROUP
	DECLARE_BITMAP		(blkcg_pols, BLKCG_MAX_POLS);
	struct blkcg_gq		*root_blkg;
	struct list_head	blkg_list;
#endif

	struct queue_limits	limits;

	unsigned int		required_elevator_features;

#ifdef CONFIG_BLK_DEV_ZONED
	/*
	 * Zoned block device information for request dispatch control.
	 * nr_zones is the total number of zones of the device. This is always
	 * 0 for regular block devices. conv_zones_bitmap is a bitmap of nr_zones
	 * bits which indicates if a zone is conventional (bit set) or
	 * sequential (bit clear). seq_zones_wlock is a bitmap of nr_zones
	 * bits which indicates if a zone is write locked, that is, if a write
	 * request targeting the zone was dispatched. All three fields are
	 * initialized by the low level device driver (e.g. scsi/sd.c).
	 * Stacking drivers (device mappers) may or may not initialize
	 * these fields.
	 *
	 * Reads of this information must be protected with blk_queue_enter() /
	 * blk_queue_exit(). Modifying this information is only allowed while
	 * no requests are being processed. See also blk_mq_freeze_queue() and
	 * blk_mq_unfreeze_queue().
	 */
	unsigned int		nr_zones;
	unsigned long		*conv_zones_bitmap;
	unsigned long		*seq_zones_wlock;
	unsigned int		max_open_zones;
	unsigned int		max_active_zones;
#endif /* CONFIG_BLK_DEV_ZONED */

	/*
	 * sg stuff
	 */
	unsigned int		sg_timeout;
	unsigned int		sg_reserved_size;
	int			node;
	struct mutex		debugfs_mutex;
#ifdef CONFIG_BLK_DEV_IO_TRACE
	struct blk_trace __rcu	*blk_trace;
#endif
	/*
	 * for flush operations
	 */
	struct blk_flush_queue	*fq;

	struct list_head	requeue_list;
	spinlock_t		requeue_lock;
	struct delayed_work	requeue_work;

	struct mutex		sysfs_lock;
	struct mutex		sysfs_dir_lock;

	/*
	 * for reusing dead hctx instance in case of updating
	 * nr_hw_queues
	 */
	struct list_head	unused_hctx_list;
	spinlock_t		unused_hctx_lock;

	int			mq_freeze_depth;

#if defined(CONFIG_BLK_DEV_BSG)
	struct bsg_class_device bsg_dev;
#endif

#ifdef CONFIG_BLK_DEV_THROTTLING
	/* Throttle data */
	struct throtl_data *td;
#endif
	struct rcu_head		rcu_head;
	wait_queue_head_t	mq_freeze_wq;
	/*
	 * Protect concurrent access to q_usage_counter by
	 * percpu_ref_kill() and percpu_ref_reinit().
	 */
	struct mutex		mq_freeze_lock;

	struct blk_mq_tag_set	*tag_set; // tag集合
	struct list_head	tag_set_list; // 挂在tag_set里
	struct bio_set		bio_split;

	struct dentry		*debugfs_dir;

#ifdef CONFIG_BLK_DEBUG_FS
	struct dentry		*sched_debugfs_dir;
	struct dentry		*rqos_debugfs_dir;
#endif

	bool			mq_sysfs_init_done;

	size_t			cmd_size;

#define BLK_MAX_WRITE_HINTS	5
	u64			write_hints[BLK_MAX_WRITE_HINTS];
};

struct queue_limits {
	unsigned long		bounce_pfn;
	unsigned long		seg_boundary_mask;
	unsigned long		virt_boundary_mask;

	unsigned int		max_hw_sectors;
	unsigned int		max_dev_sectors;
	unsigned int		chunk_sectors;
	unsigned int		max_sectors; // request最大扇区数目
	unsigned int		max_segment_size; // 每个segment最大数据量
	unsigned int		physical_block_size;
	unsigned int		logical_block_size;
	unsigned int		alignment_offset;
	unsigned int		io_min;
	unsigned int		io_opt;
	unsigned int		max_discard_sectors;
	unsigned int		max_hw_discard_sectors;
	unsigned int		max_write_same_sectors;
	unsigned int		max_write_zeroes_sectors;
	unsigned int		max_zone_append_sectors;
	unsigned int		discard_granularity;
	unsigned int		discard_alignment;

	unsigned short		max_segments; // 一个request里最大segment数目
	unsigned short		max_integrity_segments;
	unsigned short		max_discard_segments;

	unsigned char		misaligned;
	unsigned char		discard_misaligned;
	unsigned char		raid_partial_stripes_expensive;
	enum blk_zoned_model	zoned;
};

struct disk_part_tbl {
	struct rcu_head rcu_head;
	int len; // part数组长度
	struct hd_struct __rcu *last_lookup; // 上次查找的分区
	struct hd_struct __rcu *part[]; // 分区表
};

// 分区
struct hd_struct {
	sector_t start_sect;	//起始扇区
	sector_t nr_sects;	//扇区数
#if BITS_PER_LONG==32 && defined(CONFIG_SMP)
	seqcount_t nr_sects_seq;	// 保护扇区的序号
#endif
	unsigned long stamp;
	struct disk_stats __percpu *dkstats;
	struct percpu_ref ref;

	struct device __dev;
	struct kobject *holder_dir;
	/*
	policy: 1：分区只读，0：读写
	partno: 磁盘中分区的索引
	*/
	int policy, partno;
	struct partition_meta_info *info;
#ifdef CONFIG_FAIL_MAKE_REQUEST
	int make_it_fail;
#endif
	struct rcu_work rcu_work;
};

struct request {
	struct request_queue *q; // 请求队列
	struct blk_mq_ctx *mq_ctx; //软件ctx
	struct blk_mq_hw_ctx *mq_hctx; //硬ctx

	unsigned int cmd_flags;		/* op and common flags */
	req_flags_t rq_flags;

	int tag;
	int internal_tag;

	/* the following two fields are internal, NEVER access directly */
	unsigned int __data_len;	// 数据长度
	sector_t __sector; // 在磁盘中的起始位置

	struct bio *bio; // bio列表
	struct bio *biotail; // 指向最后一个bio

	struct list_head queuelist; // 链到请求队列

	/*
	 * The hash is used inside the scheduler, and killed once the
	 * request reaches the dispatch list. The ipi_list is only used
	 * to queue the request for softirq completion, which is long
	 * after the request has been unhashed (and even removed from
	 * the dispatch list).
	 */
	union {
		struct hlist_node hash;	/* merge hash */
		struct list_head ipi_list;
	};

	/*
	 * The rb_node is only used inside the io scheduler, requests
	 * are pruned when moved to the dispatch queue. So let the
	 * completion_data share space with the rb_node.
	 */
	union {
		struct rb_node rb_node;	/* sort/lookup */
		struct bio_vec special_vec;
		void *completion_data;
		int error_count; /* for legacy drivers, don't use */
	};

	/*
	 * Three pointers are available for the IO schedulers, if they need
	 * more they have to dynamically allocate it.  Flush requests are
	 * never put on the IO scheduler. So let the flush fields share
	 * space with the elevator data.
	 */
	union {
		struct {
			struct io_cq		*icq;
			void			*priv[2];
		} elv;

		struct {
			unsigned int		seq;
			struct list_head	list;
			rq_end_io_fn		*saved_end_io;
		} flush;
	};

	struct gendisk *rq_disk; // 请求的磁盘
	struct hd_struct *part; // 请求的分区
#ifdef CONFIG_BLK_RQ_ALLOC_TIME
	/* Time that the first bio started allocating this request. */
	u64 alloc_time_ns;
#endif
	/* Time that this request was allocated for this IO. */
	u64 start_time_ns;
	/* Time that I/O was submitted to the device. */
	u64 io_start_time_ns;

#ifdef CONFIG_BLK_WBT
	unsigned short wbt_flags;
#endif
	/*
	 * rq sectors used for blk stats. It has the same value
	 * with blk_rq_sectors(rq), except that it never be zeroed
	 * by completion.
	 */
	unsigned short stats_sectors;

	/*
	 * Number of scatter-gather DMA addr+len pairs after
	 * physical address coalescing is performed.
	 */
	unsigned short nr_phys_segments;

#if defined(CONFIG_BLK_DEV_INTEGRITY)
	unsigned short nr_integrity_segments;
#endif

#ifdef CONFIG_BLK_INLINE_ENCRYPTION
	struct bio_crypt_ctx *crypt_ctx;
	struct blk_ksm_keyslot *crypt_keyslot;
#endif

	unsigned short write_hint;
	unsigned short ioprio;

	enum mq_rq_state state;
	refcount_t ref;

	unsigned int timeout;
	unsigned long deadline;

	union {
		struct __call_single_data csd;
		u64 fifo_time;
	};

	/*
	 * completion callback.
	 */
	rq_end_io_fn *end_io;
	void *end_io_data;
};

struct block_device {
	dev_t			bd_dev;	// 设备号
	int			bd_openers;	// 打开的次数
	struct inode *		bd_inode;	/* 指向bdev伪文件系统里表示该块设备的inode. 将来会删除, 因为可以用bget获取, 所以该项是冗余的*/
	struct super_block *	bd_super;
	struct mutex		bd_mutex;	/* open/close mutex */
	void *			bd_claiming;
	void *			bd_holder;
	int			bd_holders;
	bool			bd_write_holder;
#ifdef CONFIG_SYSFS
	struct list_head	bd_holder_disks;
#endif
	struct block_device *	bd_contains;
	u8			bd_partno;
	struct hd_struct *	bd_part; // 包含在该块设备上的分区
	
	unsigned		bd_part_count; // 引用该设备内分区的数目

	spinlock_t		bd_size_lock; /* for bd_inode->i_size updates */
	struct gendisk *	bd_disk;
	struct backing_dev_info *bd_bdi;

	/* The counter of freeze processes */
	int			bd_fsfreeze_count;
	/* Mutex for freeze */
	struct mutex		bd_fsfreeze_mutex;
} __randomize_layout;

struct bdev_inode {
	struct block_device bdev;
	struct inode vfs_inode;
};

struct device {
	struct kobject kobj;
	struct device		*parent;

	struct device_private	*p;

	const char		*init_name; /* initial name of the device */
	const struct device_type *type;

	struct bus_type	*bus;		/* type of bus device is on */
	struct device_driver *driver;	/* which driver has allocated this
					   device */
	void		*platform_data;	/* Platform specific data, device
					   core doesn't touch it */
	void		*driver_data;	/* Driver data, set and get with
					   dev_set_drvdata/dev_get_drvdata */
#ifdef CONFIG_PROVE_LOCKING
	struct mutex		lockdep_mutex;
#endif
	struct mutex		mutex;	/* mutex to synchronize calls to
					 * its driver.
					 */

	struct dev_links_info	links;
	struct dev_pm_info	power;
	struct dev_pm_domain	*pm_domain;

#ifdef CONFIG_ENERGY_MODEL
	struct em_perf_domain	*em_pd;
#endif

#ifdef CONFIG_GENERIC_MSI_IRQ_DOMAIN
	struct irq_domain	*msi_domain;
#endif
#ifdef CONFIG_PINCTRL
	struct dev_pin_info	*pins;
#endif
#ifdef CONFIG_GENERIC_MSI_IRQ
	raw_spinlock_t		msi_lock;
	struct list_head	msi_list;
#endif
#ifdef CONFIG_DMA_OPS
	const struct dma_map_ops *dma_ops;
#endif
	u64		*dma_mask;	/* dma mask (if dma'able device) */
	u64		coherent_dma_mask;/* Like dma_mask, but for
					     alloc_coherent mappings as
					     not all hardware supports
					     64 bit addresses for consistent
					     allocations such descriptors. */
	u64		bus_dma_limit;	/* upstream dma constraint */
	const struct bus_dma_region *dma_range_map;

	struct device_dma_parameters *dma_parms;

	struct list_head	dma_pools;	/* dma pools (if dma'ble) */

#ifdef CONFIG_DMA_DECLARE_COHERENT
	struct dma_coherent_mem	*dma_mem; /* internal for coherent mem
					     override */
#endif
#ifdef CONFIG_DMA_CMA
	struct cma *cma_area;		/* contiguous memory area for dma
					   allocations */
#endif
	/* arch specific additions */
	struct dev_archdata	archdata;

	struct device_node	*of_node; /* associated device tree node */
	struct fwnode_handle	*fwnode; /* firmware device node */

#ifdef CONFIG_NUMA
	int		numa_node;	/* NUMA node this device is close to */
#endif
	dev_t			devt;	/* dev_t, creates the sysfs "dev" */
	u32			id;	/* device instance */

	spinlock_t		devres_lock;
	struct list_head	devres_head;

	struct class		*class;
	const struct attribute_group **groups;	/* optional groups */

	void	(*release)(struct device *dev);
	struct iommu_group	*iommu_group;
	struct dev_iommu	*iommu;

	bool			offline_disabled:1;
	bool			offline:1;
	bool			of_node_reused:1;
	bool			state_synced:1;
#if defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_DEVICE) || \
    defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_CPU) || \
    defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_CPU_ALL)
	bool			dma_coherent:1;
#endif
#ifdef CONFIG_DMA_OPS_BYPASS
	bool			dma_ops_bypass : 1;
#endif
};

struct dev_links_info {
	struct list_head suppliers;
	struct list_head consumers;
	struct list_head needs_suppliers;
	struct list_head defer_hook;
	bool need_for_probe;
	enum dl_dev_state status; // 连接状态
};

/**
 * struct blk_mq_tag_set - tag set that can be shared between request queues
 * @map:	   One or more ctx -> hctx mappings. One map exists for each
 *		   hardware queue type (enum hctx_type) that the driver wishes
 *		   to support. There are no restrictions on maps being of the
 *		   same size, and it's perfectly legal to share maps between
 *		   types.
 * @nr_maps:	   Number of elements in the @map array. A number in the range
 *		   [1, HCTX_MAX_TYPES].
 * @ops:	   Pointers to functions that implement block driver behavior.
 * @nr_hw_queues:  Number of hardware queues supported by the block driver that
 *		   owns this data structure.
 * @queue_depth:   Number of tags per hardware queue, reserved tags included.
 * @reserved_tags: Number of tags to set aside for BLK_MQ_REQ_RESERVED tag
 *		   allocations.
 * @cmd_size:	   Number of additional bytes to allocate per request. The block
 *		   driver owns these additional bytes.
 * @numa_node:	   NUMA node the storage adapter has been connected to.
 * @timeout:	   Request processing timeout in jiffies.
 * @flags:	   Zero or more BLK_MQ_F_* flags.
 * @driver_data:   Pointer to data owned by the block driver that created this
 *		   tag set.
 * @active_queues_shared_sbitmap:
 * 		   number of active request queues per tag set.
 * @__bitmap_tags: A shared tags sbitmap, used over all hctx's
 * @__breserved_tags:
 *		   A shared reserved tags sbitmap, used over all hctx's
 * @tags:	   Tag sets. One tag set per hardware queue. Has @nr_hw_queues
 *		   elements.
 * @tag_list_lock: Serializes tag_list accesses.
 * @tag_list:	   List of the request queues that use this tag set. See also
 *		   request_queue.tag_set_list.
 */
struct blk_mq_tag_set {
	struct blk_mq_queue_map	map[HCTX_MAX_TYPES]; // ctx->hctx的映射
	unsigned int		nr_maps; // map里面的数量
	const struct blk_mq_ops	*ops; // mq函数表
	unsigned int		nr_hw_queues; // 硬件支持的队列数量
	unsigned int		queue_depth; // 每个硬件队列的tag数量
	unsigned int		reserved_tags; // 保留的tag数量
	unsigned int		cmd_size; // 每个请求分配的附加byte
	int			numa_node; // 存储的numa结点？
	unsigned int		timeout; // 请求超时时间。单位:jiffies
	unsigned int		flags; // MQ
	void			*driver_data; // 创建这个tagset的块层驱动的私有数据
	atomic_t		active_queues_shared_sbitmap; // 每个tagset里活跃请求数量

	struct sbitmap_queue	__bitmap_tags; // tag的bitmap
	struct sbitmap_queue	__breserved_tags; // 保留tag的bitmap
	struct blk_mq_tags	**tags;	// 每个硬件队列一个tagset，共有nr_hw_queues个元素

	struct mutex		tag_list_lock; // 锁
	struct list_head	tag_list; // tag表
};

/**
 * struct blk_mq_queue_map - Map software queues to hardware queues
 * @mq_map:       CPU ID to hardware queue index map. This is an array
 *	with nr_cpu_ids elements. Each element has a value in the range
 *	[@queue_offset, @queue_offset + @nr_queues).
 * @nr_queues:    Number of hardware queues to map CPU IDs onto.
 * @queue_offset: First hardware queue to map onto. Used by the PCIe NVMe
 *	driver to map each hardware queue type (enum hctx_type) onto a distinct
 *	set of hardware queues.
 */
struct blk_mq_queue_map {
	unsigned int *mq_map;
	unsigned int nr_queues;
	unsigned int queue_offset;
};
struct blk_mq_tags {
	unsigned int nr_tags; // 多少个tag
	unsigned int nr_reserved_tags; // 多少个保留tag

	atomic_t active_queues; // 活跃队列

	struct sbitmap_queue *bitmap_tags; // tag位图
	struct sbitmap_queue *breserved_tags; // 保留tag位图

	// 这2个是上面位图的实际指向
	struct sbitmap_queue __bitmap_tags;
	struct sbitmap_queue __breserved_tags;

	struct request **rqs; // 请求表
	struct request **static_rqs; // 静态请求表
	struct list_head page_list; // ??

	/*
	 * used to clear request reference in rqs[] before freeing one
	 * request pool
	 */
	spinlock_t lock;
};

struct blk_plug {
	struct list_head mq_list; // 请求列表
	struct list_head cb_list; // 回调列表
	unsigned short rq_count; // 请求数据
	bool multiple_queues; // 多个队列标志？
	bool nowait; // 此列表不支持等待？
};

// 这个结构主要是wapper
struct blk_mq_ctxs {
	struct kobject kobj; // 用于设备模型
	// 在request_queue里嵌入的是这个对象，而不是struct blk_mq_ctxs
	struct blk_mq_ctx __percpu	*queue_ctx; // 真正的软上下文，percpu对象
};

struct blk_mq_ctx {
	struct {
		spinlock_t		lock;
		struct list_head	rq_lists[HCTX_MAX_TYPES]; // 无调度器时存放待派发的请求
	} ____cacheline_aligned_in_smp;

	unsigned int		cpu;
	unsigned short		index_hw[HCTX_MAX_TYPES]; // 关联硬件队列的软队列编号
	struct blk_mq_hw_ctx 	*hctxs[HCTX_MAX_TYPES]; // 关联的硬件队列

	/* incremented at dispatch time */
	unsigned long		rq_dispatched[2];
	unsigned long		rq_merged;

	/* incremented at completion time */
	unsigned long		____cacheline_aligned_in_smp rq_completed[2];

	struct request_queue	*queue; // 对应的请求队列
	struct blk_mq_ctxs      *ctxs; // 所属软件集合
	struct kobject		kobj;
} ____cacheline_aligned_in_smp;



struct blk_mq_hw_ctx {
	struct {
		/** @lock: Protects the dispatch list. */
		spinlock_t		lock;
		/**
		 * @dispatch: Used for requests that are ready to be
		 * dispatched to the hardware but for some reason (e.g. lack of
		 * resources) could not be sent to the hardware. As soon as the
		 * driver can send new requests, requests at this list will
		 * be sent first for a fairer dispatch.
		 */
		struct list_head	dispatch; // 存放等待派发的rq
		 /**
		  * @state: BLK_MQ_S_* flags. Defines the state of the hw
		  * queue (active, scheduled to restart, stopped).
		  */
		unsigned long		state;
	} ____cacheline_aligned_in_smp;

	/**
	 * @run_work: Used for scheduling a hardware queue run at a later time.
	 */
	struct delayed_work	run_work; // 处理io的工作队列
	/** @cpumask: Map of available CPUs where this hctx can run. */
	cpumask_var_t		cpumask;
	/**
	 * @next_cpu: Used by blk_mq_hctx_next_cpu() for round-robin CPU
	 * selection from @cpumask.
	 */
	int			next_cpu;
	/**
	 * @next_cpu_batch: Counter of how many works left in the batch before
	 * changing to the next CPU.
	 */
	int			next_cpu_batch;

	/** @flags: BLK_MQ_F_* flags. Defines the behaviour of the queue. */
	unsigned long		flags;

	/**
	 * @sched_data: Pointer owned by the IO scheduler attached to a request
	 * queue. It's up to the IO scheduler how to use this pointer.
	 */
	void			*sched_data; // 调度器私有数量
	/**
	 * @queue: Pointer to the request queue that owns this hardware context.
	 */
	struct request_queue	*queue; // 属于的队列
	/** @fq: Queue of requests that need to perform a flush operation. */
	struct blk_flush_queue	*fq;

	/**
	 * @driver_data: Pointer to data owned by the block driver that created
	 * this hctx
	 */
	void			*driver_data;

	/**
	 * @ctx_map: Bitmap for each software queue. If bit is on, there is a
	 * pending request in that software queue.
	 */
	struct sbitmap		ctx_map; // 标识正在处理哪些软队列上的rq

	/**
	 * @dispatch_from: Software queue to be used when no scheduler was
	 * selected.
	 */
	struct blk_mq_ctx	*dispatch_from; // 无调度器时，表示从哪个软队列派发
	/**
	 * @dispatch_busy: Number used by blk_mq_update_dispatch_busy() to
	 * decide if the hw_queue is busy using Exponential Weighted Moving
	 * Average algorithm.
	 */
	unsigned int		dispatch_busy; // 队列忙的状态

	/** @type: HCTX_TYPE_* flags. Type of hardware queue. */
	unsigned short		type; // 队列类型
	/** @nr_ctx: Number of software queues. */
	unsigned short		nr_ctx; // 软队列数量
	/** @ctxs: Array of software queues. */
	struct blk_mq_ctx	**ctxs; // 软队列数组，这里为什么不用percpu变量？

	/** @dispatch_wait_lock: Lock for dispatch_wait queue. */
	spinlock_t		dispatch_wait_lock;
	/**
	 * @dispatch_wait: Waitqueue to put requests when there is no tag
	 * available at the moment, to wait for another try in the future.
	 */
	wait_queue_entry_t	dispatch_wait;

	/**
	 * @wait_index: Index of next available dispatch_wait queue to insert
	 * requests.
	 */
	atomic_t		wait_index;

	/**
	 * @tags: Tags owned by the block driver. A tag at this set is only
	 * assigned when a request is dispatched from a hardware queue.
	 */
	struct blk_mq_tags	*tags; // 继承硬件的tags
	/**
	 * @sched_tags: Tags owned by I/O scheduler. If there is an I/O
	 * scheduler associated with a request queue, a tag is assigned when
	 * that request is allocated. Else, this member is not used.
	 */
	struct blk_mq_tags	*sched_tags; // 调度器的tag

	/** @queued: Number of queued requests. */
	unsigned long		queued;
	/** @run: Number of dispatched requests. */
	unsigned long		run;
#define BLK_MQ_MAX_DISPATCH_ORDER	7
	/** @dispatched: Number of dispatch requests by queue. */
	unsigned long		dispatched[BLK_MQ_MAX_DISPATCH_ORDER];

	/** @numa_node: NUMA node the storage adapter has been connected to. */
	unsigned int		numa_node;
	/** @queue_num: Index of this hardware queue. */
	unsigned int		queue_num;

	/**
	 * @nr_active: Number of active requests. Only used when a tag set is
	 * shared across request queues.
	 */
	atomic_t		nr_active;
	/**
	 * @elevator_queued: Number of queued requests on hctx.
	 */
	atomic_t                elevator_queued;

	/** @cpuhp_online: List to store request if CPU is going to die */
	struct hlist_node	cpuhp_online;
	/** @cpuhp_dead: List to store request if some CPU die. */
	struct hlist_node	cpuhp_dead;
	/** @kobj: Kernel object for sysfs. */
	struct kobject		kobj;

	/** @poll_considered: Count times blk_poll() was called. */
	unsigned long		poll_considered;
	/** @poll_invoked: Count how many requests blk_poll() polled. */
	unsigned long		poll_invoked;
	/** @poll_success: Count how many polled requests were completed. */
	unsigned long		poll_success;

#ifdef CONFIG_BLK_DEBUG_FS
	/**
	 * @debugfs_dir: debugfs directory for this hardware queue. Named
	 * as cpu<cpu_number>.
	 */
	struct dentry		*debugfs_dir;
	/** @sched_debugfs_dir:	debugfs directory for the scheduler. */
	struct dentry		*sched_debugfs_dir;
#endif

	/**
	 * @hctx_list: if this hctx is not in use, this is an entry in
	 * q->unused_hctx_list.
	 */
	struct list_head	hctx_list;

	/**
	 * @srcu: Sleepable RCU. Use as lock when type of the hardware queue is
	 * blocking (BLK_MQ_F_BLOCKING). Must be the last member - see also
	 * blk_mq_hw_ctx_size().
	 */
	struct srcu_struct	srcu[];
};


struct blk_mq_alloc_data {
	/* input parameter */
	struct request_queue *q; // 请求队列
	blk_mq_req_flags_t flags; // 标志
	unsigned int shallow_depth;
	unsigned int cmd_flags; // 命令标志

	/* input & output parameter */
	struct blk_mq_ctx *ctx; // 软件队列
	struct blk_mq_hw_ctx *hctx; // 硬件队列
};

struct blk_mq_queue_data {
	struct request *rq; // 请求
	bool last; // 是否是最后一个请求
};

struct blk_flush_queue {
	unsigned int		flush_pending_idx:1;
	unsigned int		flush_running_idx:1;
	blk_status_t 		rq_status;
	unsigned long		flush_pending_since;
	struct list_head	flush_queue[2];
	struct list_head	flush_data_in_flight;
	struct request		*flush_rq;

	struct lock_class_key	key;
	spinlock_t		mq_flush_lock;
};
```