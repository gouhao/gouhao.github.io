# 挂载
源码基于5.10

## 数据结构
```c
struct ext4_sb_info {
	unsigned long s_desc_size;	/* Size of a group descriptor in bytes */
	unsigned long s_inodes_per_block;/* Number of inodes per block */
	unsigned long s_blocks_per_group;/* Number of blocks in a group */
	unsigned long s_clusters_per_group; /* Number of clusters in a group */
	unsigned long s_inodes_per_group;/* Number of inodes in a group */
	unsigned long s_itb_per_group;	/* Number of inode table blocks per group */
	unsigned long s_gdb_count;	/* Number of group descriptor blocks */
	unsigned long s_desc_per_block;	/* Number of group descriptors per block */
	ext4_group_t s_groups_count;	/* Number of groups in the fs */
	ext4_group_t s_blockfile_groups;/* Groups acceptable for non-extent files */
	unsigned long s_overhead;  /* # of fs overhead clusters */
	unsigned int s_cluster_ratio;	/* Number of blocks per cluster */
	unsigned int s_cluster_bits;	/* log2 of s_cluster_ratio */
	loff_t s_bitmap_maxbytes;	/* max bytes for bitmap files */
	struct buffer_head * s_sbh;	/* Buffer containing the super block */
	struct ext4_super_block *s_es;	/* Pointer to the super block in the buffer */
	struct buffer_head * __rcu *s_group_desc;
	unsigned int s_mount_opt;
	unsigned int s_mount_opt2;
	unsigned long s_mount_flags;
	unsigned int s_def_mount_opt;
	ext4_fsblk_t s_sb_block;
	atomic64_t s_resv_clusters;
	kuid_t s_resuid;
	kgid_t s_resgid;
	unsigned short s_mount_state;
	unsigned short s_pad;
	int s_addr_per_block_bits;
	int s_desc_per_block_bits;
	int s_inode_size;
	int s_first_ino;
	unsigned int s_inode_readahead_blks;
	unsigned int s_inode_goal;
	u32 s_hash_seed[4];
	int s_def_hash_version;
	int s_hash_unsigned;	/* 3 if hash should be signed, 0 if not */
	struct percpu_counter s_freeclusters_counter;
	struct percpu_counter s_freeinodes_counter;
	struct percpu_counter s_dirs_counter;
	struct percpu_counter s_dirtyclusters_counter;
	struct percpu_counter s_sra_exceeded_retry_limit;
	struct blockgroup_lock *s_blockgroup_lock;
	struct proc_dir_entry *s_proc;
	struct kobject s_kobj;
	struct completion s_kobj_unregister;
	struct super_block *s_sb;
	struct buffer_head *s_mmp_bh;

	/* Journaling */
	struct journal_s *s_journal;
	struct list_head s_orphan;
	struct mutex s_orphan_lock;
	unsigned long s_ext4_flags;		/* Ext4 superblock flags */
	unsigned long s_commit_interval;
	u32 s_max_batch_time;
	u32 s_min_batch_time;
	struct block_device *s_journal_bdev;
#ifdef CONFIG_QUOTA
	/* Names of quota files with journalled quota */
	char __rcu *s_qf_names[EXT4_MAXQUOTAS];
	int s_jquota_fmt;			/* Format of quota to use */
#endif
	unsigned int s_want_extra_isize; /* New inodes should reserve # bytes */
	struct ext4_system_blocks __rcu *s_system_blks;

#ifdef EXTENTS_STATS
	/* ext4 extents stats */
	unsigned long s_ext_min;
	unsigned long s_ext_max;
	unsigned long s_depth_max;
	spinlock_t s_ext_stats_lock;
	unsigned long s_ext_blocks;
	unsigned long s_ext_extents;
#endif

	/* for buddy allocator */
	struct ext4_group_info ** __rcu *s_group_info;
	struct inode *s_buddy_cache;
	spinlock_t s_md_lock;
	unsigned short *s_mb_offsets;
	unsigned int *s_mb_maxs;
	unsigned int s_group_info_size;
	unsigned int s_mb_free_pending;
	struct list_head s_freed_data_list;	/* List of blocks to be freed
						   after commit completed */

	/* tunables */
	unsigned long s_stripe;
	unsigned int s_mb_stream_request;
	unsigned int s_mb_max_to_scan;
	unsigned int s_mb_min_to_scan;
	unsigned int s_mb_stats;
	unsigned int s_mb_order2_reqs;
	unsigned int s_mb_group_prealloc;
	unsigned int s_mb_max_inode_prealloc;
	unsigned int s_max_dir_size_kb;
	/* where last allocation was done - for stream allocation */
	unsigned long s_mb_last_group;
	unsigned long s_mb_last_start;
	unsigned int s_mb_prefetch;
	unsigned int s_mb_prefetch_limit;

	/* stats for buddy allocator */
	atomic_t s_bal_reqs;	/* number of reqs with len > 1 */
	atomic_t s_bal_success;	/* we found long enough chunks */
	atomic_t s_bal_allocated;	/* in blocks */
	atomic_t s_bal_ex_scanned;	/* total extents scanned */
	atomic_t s_bal_goals;	/* goal hits */
	atomic_t s_bal_breaks;	/* too long searches */
	atomic_t s_bal_2orders;	/* 2^order hits */
	spinlock_t s_bal_lock;
	unsigned long s_mb_buddies_generated;
	unsigned long long s_mb_generation_time;
	atomic_t s_mb_lost_chunks;
	atomic_t s_mb_preallocated;
	atomic_t s_mb_discarded;
	atomic_t s_lock_busy;

	/* locality groups */
	struct ext4_locality_group __percpu *s_locality_groups;

	/* for write statistics */
	unsigned long s_sectors_written_start;
	u64 s_kbytes_written;

	/* the size of zero-out chunk */
	unsigned int s_extent_max_zeroout_kb;

	unsigned int s_log_groups_per_flex;
	struct flex_groups * __rcu *s_flex_groups;
	ext4_group_t s_flex_groups_allocated;

	/* workqueue for reserved extent conversions (buffered io) */
	struct workqueue_struct *rsv_conversion_wq;

	/* timer for periodic error stats printing */
	struct timer_list s_err_report;

	/* Lazy inode table initialization info */
	struct ext4_li_request *s_li_request;
	/* Wait multiplier for lazy initialization thread */
	unsigned int s_li_wait_mult;

	/* Kernel thread for multiple mount protection */
	struct task_struct *s_mmp_tsk;

	/* record the last minlen when FITRIM is called. */
	atomic_t s_last_trim_minblks;

	/* Reference to checksum algorithm driver via cryptoapi */
	struct crypto_shash *s_chksum_driver;

	/* Precomputed FS UUID checksum for seeding other checksums */
	__u32 s_csum_seed;

	/* Reclaim extents from extent status tree */
	struct shrinker s_es_shrinker;
	struct list_head s_es_list;	/* List of inodes with reclaimable extents */
	long s_es_nr_inode;
	struct ext4_es_stats s_es_stats;
	struct mb_cache *s_ea_block_cache;
	struct mb_cache *s_ea_inode_cache;
	spinlock_t s_es_lock ____cacheline_aligned_in_smp;

	/* Ratelimit ext4 messages. */
	struct ratelimit_state s_err_ratelimit_state;
	struct ratelimit_state s_warning_ratelimit_state;
	struct ratelimit_state s_msg_ratelimit_state;
	atomic_t s_warning_count;
	atomic_t s_msg_count;

	/* Encryption policy for '-o test_dummy_encryption' */
	struct fscrypt_dummy_policy s_dummy_enc_policy;

	/*
	 * Barrier between writepages ops and changing any inode's JOURNAL_DATA
	 * or EXTENTS flag.
	 */
	struct percpu_rw_semaphore s_writepages_rwsem;
	struct dax_device *s_daxdev;
#ifdef CONFIG_EXT4_DEBUG
	unsigned long s_simulate_fail;
#endif
	/* Record the errseq of the backing block device */
	errseq_t s_bdev_wb_err;
	spinlock_t s_bdev_wb_lock;

	/* Ext4 fast commit stuff */
	atomic_t s_fc_subtid;
	atomic_t s_fc_ineligible_updates;
	/*
	 * After commit starts, the main queue gets locked, and the further
	 * updates get added in the staging queue.
	 */
#define FC_Q_MAIN	0
#define FC_Q_STAGING	1
	struct list_head s_fc_q[2];	/* Inodes staged for fast commit
					 * that have data changes in them.
					 */
	struct list_head s_fc_dentry_q[2];	/* directory entry updates */
	unsigned int s_fc_bytes;
	/*
	 * Main fast commit lock. This lock protects accesses to the
	 * following fields:
	 * ei->i_fc_list, s_fc_dentry_q, s_fc_q, s_fc_bytes, s_fc_bh.
	 */
	spinlock_t s_fc_lock;
	struct buffer_head *s_fc_bh;
	struct ext4_fc_stats s_fc_stats;
	u64 s_fc_avg_commit_time;
#ifdef CONFIG_EXT4_DEBUG
	int s_fc_debug_max_replay;
#endif
	struct ext4_fc_replay_state s_fc_replay_state;
};
```
## ext4_mount
```c
static struct dentry *ext4_mount(struct file_system_type *fs_type, int flags,
		       const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, ext4_fill_super);
}

static int ext4_fill_super(struct super_block *sb, void *data, int silent)
{
	// dax设备
	struct dax_device *dax_dev = fs_dax_get_by_bdev(sb->s_bdev);
	char *orig_data = kstrdup(data, GFP_KERNEL);
	struct buffer_head *bh, **group_desc;
	struct ext4_super_block *es = NULL;
	// 超级块信息
	struct ext4_sb_info *sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
	struct flex_groups **flex_groups;
	ext4_fsblk_t block;
	// 获取超级块序号，默认是1，如果用户指定了就使用用户的
	ext4_fsblk_t sb_block = get_sb_block(&data);
	ext4_fsblk_t logical_sb_block;
	unsigned long offset = 0;
	unsigned long journal_devnum = 0;
	unsigned long def_mount_opts;
	struct inode *root;
	const char *descr;
	int ret = -ENOMEM;
	int blocksize, clustersize;
	unsigned int db_count;
	unsigned int i;
	int needs_recovery, has_huge_files;
	__u64 blocks_count;
	int err = 0;
	unsigned int journal_ioprio = DEFAULT_JOURNAL_IOPRIO;
	ext4_group_t first_not_zeroed;

	// 判断orig_data和sbi是否分配成功
	if ((data && !orig_data) || !sbi)
		goto out_free_base;

	sbi->s_daxdev = dax_dev;
	// 这个变量实际上是一个锁数据，数组里每一项对应一个bg
	sbi->s_blockgroup_lock =
		kzalloc(sizeof(struct blockgroup_lock), GFP_KERNEL);
	if (!sbi->s_blockgroup_lock)
		goto out_free_base;

	// 相互引用
	sb->s_fs_info = sbi;
	sbi->s_sb = sb;

	// 预读块数量，EXT4_DEF_INODE_READAHEAD_BLKS=32
	sbi->s_inode_readahead_blks = EXT4_DEF_INODE_READAHEAD_BLKS;
	// 设置超级块序号
	sbi->s_sb_block = sb_block;
	// todo: what?
	if (sb->s_bdev->bd_part)
		sbi->s_sectors_written_start =
			part_stat_read(sb->s_bdev->bd_part, sectors[STAT_WRITE]);

	// 起名字里的 / 替换成 !，todo: 为什么要替换
	strreplace(sb->s_id, '/', '!');

	/* -EINVAL is default */
	ret = -EINVAL;
	// 获取最小块大小，最小不能超过EXT4_DEF_INODE_READAHEAD_BLKS(1024)
	blocksize = sb_min_blocksize(sb, EXT4_MIN_BLOCK_SIZE);

	// 设置失败
	if (!blocksize) {
		ext4_msg(sb, KERN_ERR, "unable to set blocksize");
		goto out_fail;
	}

	// 如果不是最小值，则重新计算超级块序号
	if (blocksize != EXT4_MIN_BLOCK_SIZE) {
		// 基于最小块大小的长度
		logical_sb_block = sb_block * EXT4_MIN_BLOCK_SIZE;
		// 计算块序号和块内的偏移，do_div修改2个值：
		// 1. logical_sb_block /= blocksize。2. offset = logical_sb_block % blocksize
		offset = do_div(logical_sb_block, blocksize);
	} else {
		logical_sb_block = sb_block;
	}

	// 读取超级块
	bh = ext4_sb_bread_unmovable(sb, logical_sb_block);
	if (IS_ERR(bh)) {
		ext4_msg(sb, KERN_ERR, "unable to read superblock");
		ret = PTR_ERR(bh);
		bh = NULL;
		goto out_fail;
	}
	// 取出磁盘上的超级块
	es = (struct ext4_super_block *) (bh->b_data + offset);
	sbi->s_es = es;
	sb->s_magic = le16_to_cpu(es->s_magic);
	// 魔数不相等就错了，EXT2/3/4的魔数都是0xEF53
	if (sb->s_magic != EXT4_SUPER_MAGIC)
		goto cantfind_ext4;
	// todo: 这个变量是什么？
	sbi->s_kbytes_written = le64_to_cpu(es->s_kbytes_written);

	// 元数据校验和gdt校验不能同时设置
	if (ext4_has_feature_metadata_csum(sb) &&
	    ext4_has_feature_gdt_csum(sb))
		ext4_warning(sb, "metadata_csum and uninit_bg are "
			     "redundant flags; please run fsck.");

	// 目前只支持crc32
	if (!ext4_verify_csum_type(sb, es)) {
		ext4_msg(sb, KERN_ERR, "VFS: Found ext4 filesystem with "
			 "unknown checksum algorithm.");
		silent = 1;
		goto cantfind_ext4;
	}

	// 加载crc32驱动
	sbi->s_chksum_driver = crypto_alloc_shash("crc32c", 0, 0);
	if (IS_ERR(sbi->s_chksum_driver)) {
		ext4_msg(sb, KERN_ERR, "Cannot load crc32c driver.");
		ret = PTR_ERR(sbi->s_chksum_driver);
		sbi->s_chksum_driver = NULL;
		goto failed_mount;
	}

	// 校验超级块的校验和
	if (!ext4_superblock_csum_verify(sb, es)) {
		ext4_msg(sb, KERN_ERR, "VFS: Found ext4 filesystem with "
			 "invalid superblock checksum.  Run e2fsck?");
		silent = 1;
		ret = -EFSBADCRC;
		goto cantfind_ext4;
	}

	// 计算校验和种子
	if (ext4_has_feature_csum_seed(sb))
		sbi->s_csum_seed = le32_to_cpu(es->s_checksum_seed);
	else if (ext4_has_metadata_csum(sb) || ext4_has_feature_ea_inode(sb))
		sbi->s_csum_seed = ext4_chksum(sbi, ~0, es->s_uuid,
					       sizeof(es->s_uuid));

	// 默认挂载选项
	def_mount_opts = le32_to_cpu(es->s_default_mount_opts);
	// 初始化inode表
	set_opt(sb, INIT_INODE_TABLE);
	// 是否调试
	if (def_mount_opts & EXT4_DEFM_DEBUG)
		set_opt(sb, DEBUG);
	// what?
	if (def_mount_opts & EXT4_DEFM_BSDGROUPS)
		set_opt(sb, GRPID);
	// 16位uid？
	if (def_mount_opts & EXT4_DEFM_UID16)
		set_opt(sb, NO_UID32);
	// 默认支持扩展属性
	set_opt(sb, XATTR_USER);
	// 默认支持acl
#ifdef CONFIG_EXT4_FS_POSIX_ACL
	set_opt(sb, POSIX_ACL);
#endif
	// 日志快速提交
	if (ext4_has_feature_fast_commit(sb))
		set_opt2(sb, JOURNAL_FAST_COMMIT);
	// 当元数据检验开启的时候，要开启日志校验
	if (ext4_has_metadata_csum(sb))
		set_opt(sb, JOURNAL_CHECKSUM);

	// 设置3种日志模式：data, ordered, writeback
	if ((def_mount_opts & EXT4_DEFM_JMODE) == EXT4_DEFM_JMODE_DATA)
		set_opt(sb, JOURNAL_DATA);
	else if ((def_mount_opts & EXT4_DEFM_JMODE) == EXT4_DEFM_JMODE_ORDERED)
		set_opt(sb, ORDERED_DATA);
	else if ((def_mount_opts & EXT4_DEFM_JMODE) == EXT4_DEFM_JMODE_WBACK)
		set_opt(sb, WRITEBACK_DATA);

	// 设置出错时的行为
	if (le16_to_cpu(sbi->s_es->s_errors) == EXT4_ERRORS_PANIC)
		set_opt(sb, ERRORS_PANIC);
	else if (le16_to_cpu(sbi->s_es->s_errors) == EXT4_ERRORS_CONTINUE)
		set_opt(sb, ERRORS_CONT);
	else
		set_opt(sb, ERRORS_RO);
	// 默认开启块校验
	set_opt(sb, BLOCK_VALIDITY);
	// 支持discard请求
	if (def_mount_opts & EXT4_DEFM_DISCARD)
		set_opt(sb, DISCARD);

	// fs的主人
	sbi->s_resuid = make_kuid(&init_user_ns, le16_to_cpu(es->s_def_resuid));
	sbi->s_resgid = make_kgid(&init_user_ns, le16_to_cpu(es->s_def_resgid));
	// 提交间隔5秒。
	sbi->s_commit_interval = JBD2_DEFAULT_MAX_COMMIT_AGE * HZ;
	// 最小批量时间0
	sbi->s_min_batch_time = EXT4_DEF_MIN_BATCH_TIME;
	// 最大批量时间15毫秒
	sbi->s_max_batch_time = EXT4_DEF_MAX_BATCH_TIME;

	// todo: 没有栅栏
	if ((def_mount_opts & EXT4_DEFM_NOBARRIER) == 0)
		set_opt(sb, BARRIER);

	// ext4默认开启延迟分配
	if (!IS_EXT3_SB(sb) && !IS_EXT2_SB(sb) &&
	    ((def_mount_opts & EXT4_DEFM_NODELALLOC) == 0))
		set_opt(sb, DELALLOC);

	/*
	 * set default s_li_wait_mult for lazyinit, for the case there is
	 * no mount option specified.
	 */
	// todo: EXT4_DEF_LI_WAIT_MULT=10
	sbi->s_li_wait_mult = EXT4_DEF_LI_WAIT_MULT;

	// 逻辑块大小范围验证。
	// s_log_block_size在存的时候以EXT4_MIN_BLOCK_LOG_SIZE为单位再取2的log
	// EXT4_MAX_BLOCK_LOG_SIZE=16, EXT4_MIN_BLOCK_LOG_SIZE=10
	if (le32_to_cpu(es->s_log_block_size) >
	    (EXT4_MAX_BLOCK_LOG_SIZE - EXT4_MIN_BLOCK_LOG_SIZE)) {
		ext4_msg(sb, KERN_ERR,
			 "Invalid log block size: %u",
			 le32_to_cpu(es->s_log_block_size));
		goto failed_mount;
	}
	// cluster块大小验证
	//  EXT4_MAX_CLUSTER_LOG_SIZE=30
	if (le32_to_cpu(es->s_log_cluster_size) >
	    (EXT4_MAX_CLUSTER_LOG_SIZE - EXT4_MIN_BLOCK_LOG_SIZE)) {
		ext4_msg(sb, KERN_ERR,
			 "Invalid log cluster size: %u",
			 le32_to_cpu(es->s_log_cluster_size));
		goto failed_mount;
	}

	// 逻辑块里的块大小
	blocksize = EXT4_MIN_BLOCK_SIZE << le32_to_cpu(es->s_log_block_size);

	// 等于块大小的时候，dio读不用加锁？
	if (blocksize == PAGE_SIZE)
		set_opt(sb, DIOREAD_NOLOCK);

	if (le32_to_cpu(es->s_rev_level) == EXT4_GOOD_OLD_REV) {
		// 老版本

		// EXT4_GOOD_OLD_INODE_SIZE=128
		sbi->s_inode_size = EXT4_GOOD_OLD_INODE_SIZE;
		// EXT4_GOOD_OLD_FIRST_INO=11
		sbi->s_first_ino = EXT4_GOOD_OLD_FIRST_INO;
	} else {
		// 新版本

		// 从超级块里获取inode大小和第一个inode的位置
		sbi->s_inode_size = le16_to_cpu(es->s_inode_size);
		sbi->s_first_ino = le32_to_cpu(es->s_first_ino);

		// 第1个inode不能小于11
		if (sbi->s_first_ino < EXT4_GOOD_OLD_FIRST_INO) {
			ext4_msg(sb, KERN_ERR, "invalid first ino: %u",
				 sbi->s_first_ino);
			goto failed_mount;
		}
		// 判断inodesize是否合法：小于128||不是2的对数||大于块大小，都是不支持的
		if ((sbi->s_inode_size < EXT4_GOOD_OLD_INODE_SIZE) ||
		    (!is_power_of_2(sbi->s_inode_size)) ||
		    (sbi->s_inode_size > blocksize)) {
			ext4_msg(sb, KERN_ERR,
			       "unsupported inode size: %d",
			       sbi->s_inode_size);
			ext4_msg(sb, KERN_ERR, "blocksize: %d", blocksize);
			goto failed_mount;
		}
		// 检查inode的大小能否能存的下最后一个字段。
		// todo: 最后一个字段是i_crtime_extra呀
		if (sbi->s_inode_size >= offsetof(struct ext4_inode, i_atime_extra) +
			sizeof(((struct ext4_inode *)0)->i_atime_extra)) {
			// 每秒的时间间隔？
			sb->s_time_gran = 1;
			// 最大时间戳，EXT4_EXTRA_TIMESTAMP_MAX=(((s64)1 << 34) - 1  + S32_MIN)
			sb->s_time_max = EXT4_EXTRA_TIMESTAMP_MAX;
		} else {
			// 每秒的时间为(1000000000L)纳秒
			sb->s_time_gran = NSEC_PER_SEC;
			// 最大时间戳：S32_MAX(32位有符号最大值)
			sb->s_time_max = EXT4_NON_EXTRA_TIMESTAMP_MAX;
		}
		// 最小时间戳？EXT4_TIMESTAMP_MIN=S32_MIN
		sb->s_time_min = EXT4_TIMESTAMP_MIN;
	}

	// inode_size > 128
	if (sbi->s_inode_size > EXT4_GOOD_OLD_INODE_SIZE) {
		// 额外需要的空间
		sbi->s_want_extra_isize = sizeof(struct ext4_inode) -
			EXT4_GOOD_OLD_INODE_SIZE;
		// 有extra_size特性
		if (ext4_has_feature_extra_isize(sb)) {
			// 额外空间最大不能超过这
			unsigned v, max = (sbi->s_inode_size -
					   EXT4_GOOD_OLD_INODE_SIZE);

			// 需要的额外空间
			v = le16_to_cpu(es->s_want_extra_isize);
			// 比inode_size大就出错了
			if (v > max) {
				ext4_msg(sb, KERN_ERR,
					 "bad s_want_extra_isize: %d", v);
				goto failed_mount;
			}
			// 以盘上的为准，不能小于盘上的
			if (sbi->s_want_extra_isize < v)
				sbi->s_want_extra_isize = v;

			// 最小额外的空间
			v = le16_to_cpu(es->s_min_extra_isize);
			if (v > max) {
				ext4_msg(sb, KERN_ERR,
					 "bad s_min_extra_isize: %d", v);
				goto failed_mount;
			}
			// 不能小于最小值
			if (sbi->s_want_extra_isize < v)
				sbi->s_want_extra_isize = v;
		}
	}

	// 先解析盘上的挂载参数
	if (sbi->s_es->s_mount_opts[0]) {
		char *s_mount_opts = kstrndup(sbi->s_es->s_mount_opts,
					      sizeof(sbi->s_es->s_mount_opts),
					      GFP_KERNEL);
		if (!s_mount_opts)
			goto failed_mount;
		// todo: 解析参数后面再看
		if (!parse_options(s_mount_opts, sb, &journal_devnum,
				   &journal_ioprio, 0)) {
			ext4_msg(sb, KERN_WARNING,
				 "failed to parse options in superblock: %s",
				 s_mount_opts);
		}
		kfree(s_mount_opts);
	}
	// 设置成默认参数
	sbi->s_def_mount_opt = sbi->s_mount_opt;
	// 解析用户传下来的挂载参数
	if (!parse_options((char *) data, sb, &journal_devnum,
			   &journal_ioprio, 0))
		goto failed_mount;

#ifdef CONFIG_UNICODE
	// todo: unicode编码，后面看
	if (ext4_has_feature_casefold(sb) && !sb->s_encoding) {
		const struct ext4_sb_encodings *encoding_info;
		struct unicode_map *encoding;
		__u16 encoding_flags;

		if (ext4_has_feature_encrypt(sb)) {
			ext4_msg(sb, KERN_ERR,
				 "Can't mount with encoding and encryption");
			goto failed_mount;
		}

		if (ext4_sb_read_encoding(es, &encoding_info,
					  &encoding_flags)) {
			ext4_msg(sb, KERN_ERR,
				 "Encoding requested by superblock is unknown");
			goto failed_mount;
		}

		encoding = utf8_load(encoding_info->version);
		if (IS_ERR(encoding)) {
			ext4_msg(sb, KERN_ERR,
				 "can't mount with superblock charset: %s-%s "
				 "not supported by the kernel. flags: 0x%x.",
				 encoding_info->name, encoding_info->version,
				 encoding_flags);
			goto failed_mount;
		}
		ext4_msg(sb, KERN_INFO,"Using encoding defined by superblock: "
			 "%s-%s with flags 0x%hx", encoding_info->name,
			 encoding_info->version?:"\b", encoding_flags);

		sb->s_encoding = encoding;
		sb->s_encoding_flags = encoding_flags;
	}
#endif

	// 使用 data=journal挂载.todo：这个挂载什么意思
	if (test_opt(sb, DATA_FLAGS) == EXT4_MOUNT_JOURNAL_DATA) {
		printk_once(KERN_WARNING "EXT4-fs: Warning: mounting with data=journal disables delayed allocation, dioread_nolock, O_DIRECT and fast_commit support!\n");
		// dioread_noblock与fast_commit与它data=journal共存
		clear_opt(sb, DIOREAD_NOLOCK);
		clear_opt2(sb, JOURNAL_FAST_COMMIT);
		// 不能有直接延迟分配?todo:what?
		if (test_opt2(sb, EXPLICIT_DELALLOC)) {
			ext4_msg(sb, KERN_ERR, "can't mount with "
				 "both data=journal and delalloc");
			goto failed_mount;
		}
		// 不能有dax
		if (test_opt(sb, DAX_ALWAYS)) {
			ext4_msg(sb, KERN_ERR, "can't mount with "
				 "both data=journal and dax");
			goto failed_mount;
		}
		// 不能有加密
		if (ext4_has_feature_encrypt(sb)) {
			ext4_msg(sb, KERN_WARNING,
				 "encrypted files will use data=ordered "
				 "instead of data journaling mode");
		}
		// 若有延迟分配则清除之
		if (test_opt(sb, DELALLOC))
			clear_opt(sb, DELALLOC);
	} else {
		// cg writeback?
		sb->s_iflags |= SB_I_CGROUPWB;
	}

	// 设置是否有acl
	sb->s_flags = (sb->s_flags & ~SB_POSIXACL) |
		(test_opt(sb, POSIX_ACL) ? SB_POSIXACL : 0);

	// 老版本有不兼容的特性
	if (le32_to_cpu(es->s_rev_level) == EXT4_GOOD_OLD_REV &&
	    (ext4_has_compat_features(sb) ||
	     ext4_has_ro_compat_features(sb) ||
	     ext4_has_incompat_features(sb)))
		ext4_msg(sb, KERN_WARNING,
		       "feature flags set on rev 0 fs, "
		       "running e2fsck is recommended");

	// hurd操作系统。todo： 暂时不看
	if (es->s_creator_os == cpu_to_le32(EXT4_OS_HURD)) {
		set_opt2(sb, HURD_COMPAT);
		if (ext4_has_feature_64bit(sb)) {
			ext4_msg(sb, KERN_ERR,
				 "The Hurd can't support 64-bit file systems");
			goto failed_mount;
		}

		/*
		 * ea_inode feature uses l_i_version field which is not
		 * available in HURD_COMPAT mode.
		 */
		if (ext4_has_feature_ea_inode(sb)) {
			ext4_msg(sb, KERN_ERR,
				 "ea_inode feature is not supported for Hurd");
			goto failed_mount;
		}
	}

	// 挂载的是ext2
	if (IS_EXT2_SB(sb)) {
		// 检查是否有不兼容的特性
		if (ext2_feature_set_ok(sb))
			ext4_msg(sb, KERN_INFO, "mounting ext2 file system "
				 "using the ext4 subsystem");
		else {
			// 有不兼容的特性
			if (silent && ext4_feature_set_ok(sb, sb_rdonly(sb)))
				goto failed_mount;
			ext4_msg(sb, KERN_ERR, "couldn't mount as ext2 due "
				 "to feature incompatibilities");
			goto failed_mount;
		}
	}

	// 同上，检查ext3
	if (IS_EXT3_SB(sb)) {
		if (ext3_feature_set_ok(sb))
			ext4_msg(sb, KERN_INFO, "mounting ext3 file system "
				 "using the ext4 subsystem");
		else {
			/*
			 * If we're probing be silent, if this looks like
			 * it's actually an ext4 filesystem.
			 */
			if (silent && ext4_feature_set_ok(sb, sb_rdonly(sb)))
				goto failed_mount;
			ext4_msg(sb, KERN_ERR, "couldn't mount as ext3 due "
				 "to feature incompatibilities");
			goto failed_mount;
		}
	}

	// 走到这儿表示是ext4挂载
	
	// 检查是否有不兼容的特性
	if (!ext4_feature_set_ok(sb, (sb_rdonly(sb))))
		goto failed_mount;

	// 保留的gdt块太多，超过了1/4块数
	if (le16_to_cpu(sbi->s_es->s_reserved_gdt_blocks) > (blocksize / 4)) {
		ext4_msg(sb, KERN_ERR,
			 "Number of reserved GDT blocks insanely large: %d",
			 le16_to_cpu(sbi->s_es->s_reserved_gdt_blocks));
		goto failed_mount;
	}

	// 判断是否支持dax
	if (bdev_dax_supported(sb->s_bdev, blocksize))
		set_bit(EXT4_FLAGS_BDEV_IS_DAX, &sbi->s_ext4_flags);

	// dax_always挂载
	if (sbi->s_mount_opt & EXT4_MOUNT_DAX_ALWAYS) {
		// dax不能使用inline data特性
		if (ext4_has_feature_inline_data(sb)) {
			ext4_msg(sb, KERN_ERR, "Cannot use DAX on a filesystem"
					" that may contain inline data");
			goto failed_mount;
		}
		// 块设置不支持dax
		if (!test_bit(EXT4_FLAGS_BDEV_IS_DAX, &sbi->s_ext4_flags)) {
			ext4_msg(sb, KERN_ERR,
				"DAX unsupported by block device.");
			goto failed_mount;
		}
	}

	// 只支持加密级别为0？
	if (ext4_has_feature_encrypt(sb) && es->s_encryption_level) {
		ext4_msg(sb, KERN_ERR, "Unsupported encryption level %d",
			 es->s_encryption_level);
		goto failed_mount;
	}

	// 上面猜测的块大小与实际的块大小不相同
	if (sb->s_blocksize != blocksize) {
		// 释放之前的bh
		brelse(bh);
		// 设置新的块大小
		if (!sb_set_blocksize(sb, blocksize)) {
			ext4_msg(sb, KERN_ERR, "bad block size %d",
					blocksize);
			bh = NULL;
			goto failed_mount;
		}

		// 按照新的块大小算出块号和偏移
		logical_sb_block = sb_block * EXT4_MIN_BLOCK_SIZE;
		offset = do_div(logical_sb_block, blocksize);
		// 再读一次bg
		bh = ext4_sb_bread_unmovable(sb, logical_sb_block);
		if (IS_ERR(bh)) {
			ext4_msg(sb, KERN_ERR,
			       "Can't read superblock on 2nd try");
			ret = PTR_ERR(bh);
			bh = NULL;
			goto failed_mount;
		}
		// 重新设置磁盘超级块
		es = (struct ext4_super_block *)(bh->b_data + offset);
		sbi->s_es = es;
		// 检查魔数
		if (es->s_magic != cpu_to_le16(EXT4_SUPER_MAGIC)) {
			ext4_msg(sb, KERN_ERR,
			       "Magic mismatch, very weird!");
			goto failed_mount;
		}
	}

	// 有巨文件特性
	has_huge_files = ext4_has_feature_huge_file(sb);
	// 
	sbi->s_bitmap_maxbytes = ext4_max_bitmap_size(sb->s_blocksize_bits,
						      has_huge_files);
	// 算出位置最大长度？
	sb->s_maxbytes = ext4_max_size(sb->s_blocksize_bits, has_huge_files);

	// 组描述符长度
	sbi->s_desc_size = le16_to_cpu(es->s_desc_size);

	if (ext4_has_feature_64bit(sb)) {
		// 64位
		// sbi->s_desc_size < 64 || sbi->s_desc_size > 1024
		// || 描述符大小不是2的幂，则不支持
		if (sbi->s_desc_size < EXT4_MIN_DESC_SIZE_64BIT ||
		    sbi->s_desc_size > EXT4_MAX_DESC_SIZE ||
		    !is_power_of_2(sbi->s_desc_size)) {
			ext4_msg(sb, KERN_ERR,
			       "unsupported descriptor size %lu",
			       sbi->s_desc_size);
			goto failed_mount;
		}
	} else
		// 32位fs，则描述符大小为32
		sbi->s_desc_size = EXT4_MIN_DESC_SIZE;

	// 每个组的块数
	sbi->s_blocks_per_group = le32_to_cpu(es->s_blocks_per_group);
	// 每个组的inode数
	sbi->s_inodes_per_group = le32_to_cpu(es->s_inodes_per_group);

	// 每个块的inode数
	sbi->s_inodes_per_block = blocksize / EXT4_INODE_SIZE(sb);
	// 一个块连一个inode都存不下！！
	if (sbi->s_inodes_per_block == 0)
		goto cantfind_ext4;
	// 组inode数不能小于块inode数 || 组inode数大于8倍的块大小，则无效。why?
	if (sbi->s_inodes_per_group < sbi->s_inodes_per_block ||
	    sbi->s_inodes_per_group > blocksize * 8) {
		ext4_msg(sb, KERN_ERR, "invalid inodes per group: %lu\n",
			 sbi->s_inodes_per_group);
		goto failed_mount;
	}

	// 每个组的inode表占的块数
	sbi->s_itb_per_group = sbi->s_inodes_per_group /
					sbi->s_inodes_per_block;
	// 每个块里组描述符的数量
	sbi->s_desc_per_block = blocksize / EXT4_DESC_SIZE(sb);
	// 记录超级块的bh
	sbi->s_sbh = bh;
	// 挂载状态？
	sbi->s_mount_state = le16_to_cpu(es->s_state);
	// 每个块能存放的地址数（2的幂）
	sbi->s_addr_per_block_bits = ilog2(EXT4_ADDR_PER_BLOCK(sb));
	// 每个块能存放的组描述符数
	sbi->s_desc_per_block_bits = ilog2(EXT4_DESC_PER_BLOCK(sb));

	// 哈希种子
	for (i = 0; i < 4; i++)
		sbi->s_hash_seed[i] = le32_to_cpu(es->s_hash_seed[i]);
	// 哈希版本
	sbi->s_def_hash_version = es->s_def_hash_version;
	// 目录索引？todo: what?
	if (ext4_has_feature_dir_index(sb)) {
		i = le32_to_cpu(es->s_flags);
		if (i & EXT2_FLAGS_UNSIGNED_HASH)
			sbi->s_hash_unsigned = 3;
		else if ((i & EXT2_FLAGS_SIGNED_HASH) == 0) {
#ifdef __CHAR_UNSIGNED__
			if (!sb_rdonly(sb))
				es->s_flags |=
					cpu_to_le32(EXT2_FLAGS_UNSIGNED_HASH);
			sbi->s_hash_unsigned = 3;
#else
			if (!sb_rdonly(sb))
				es->s_flags |=
					cpu_to_le32(EXT2_FLAGS_SIGNED_HASH);
#endif
		}
	}

	// 簇大小
	clustersize = BLOCK_SIZE << le32_to_cpu(es->s_log_cluster_size);

	// 大分配
	if (ext4_has_feature_bigalloc(sb)) {
		// 簇大小比块大小还小，那肯定不行。
		if (clustersize < blocksize) {
			ext4_msg(sb, KERN_ERR,
				 "cluster size (%d) smaller than "
				 "block size (%d)", clustersize, blocksize);
			goto failed_mount;
		}
		// todo: what?
		sbi->s_cluster_bits = le32_to_cpu(es->s_log_cluster_size) -
			le32_to_cpu(es->s_log_block_size);
		// 每个组的簇数
		sbi->s_clusters_per_group =
			le32_to_cpu(es->s_clusters_per_group);
		// 每个组的簇数不能大于8倍的块大小，因为每个簇的使用只用一个块来存储
		if (sbi->s_clusters_per_group > blocksize * 8) {
			ext4_msg(sb, KERN_ERR,
				 "#clusters per group too big: %lu",
				 sbi->s_clusters_per_group);
			goto failed_mount;
		}
		// 每个组的块数与按簇数算出来的每个组的块数不一样
		if (sbi->s_blocks_per_group !=
		    (sbi->s_clusters_per_group * (clustersize / blocksize))) {
			ext4_msg(sb, KERN_ERR, "blocks per group (%lu) and "
				 "clusters per group (%lu) inconsistent",
				 sbi->s_blocks_per_group,
				 sbi->s_clusters_per_group);
			goto failed_mount;
		}
	} else {
		// 没有大分配，则簇大小只能是块大小
		if (clustersize != blocksize) {
			ext4_msg(sb, KERN_ERR,
				 "fragment/cluster size (%d) != "
				 "block size (%d)", clustersize, blocksize);
			goto failed_mount;
		}
		// 一个块位图不能存下一个组的块数，则出错
		if (sbi->s_blocks_per_group > blocksize * 8) {
			ext4_msg(sb, KERN_ERR,
				 "#blocks per group too big: %lu",
				 sbi->s_blocks_per_group);
			goto failed_mount;
		}
		// 簇数与每个组的块数相同
		sbi->s_clusters_per_group = sbi->s_blocks_per_group;
		// 簇数量的2的幂
		sbi->s_cluster_bits = 0;
	}
	// 簇的比例
	sbi->s_cluster_ratio = clustersize / blocksize;

	// 每组块数和簇的数量相等，则是标准的组大小
	if (sbi->s_blocks_per_group == clustersize << 3)
		set_opt2(sb, STD_GROUP_SIZE);

	// 检查文件系统地址？
	err = generic_check_addressable(sb->s_blocksize_bits,
					ext4_blocks_count(es));
	if (err) {
		ext4_msg(sb, KERN_ERR, "filesystem"
			 " too large to mount safely on this system");
		goto failed_mount;
	}

	// 每组块数为0？
	if (EXT4_BLOCKS_PER_GROUP(sb) == 0)
		goto cantfind_ext4;

	// 设备大小除以块大小＝块数
	blocks_count = sb->s_bdev->bd_inode->i_size >> sb->s_blocksize_bits;
	// 设备的块数和超级块里的对不上
	if (blocks_count && ext4_blocks_count(es) > blocks_count) {
		ext4_msg(sb, KERN_WARNING, "bad geometry: block count %llu "
		       "exceeds size of device (%llu blocks)",
		       ext4_blocks_count(es), blocks_count);
		goto failed_mount;
	}

	// 第一个数据块超过了最大的块数
	if (le32_to_cpu(es->s_first_data_block) >= ext4_blocks_count(es)) {
		ext4_msg(sb, KERN_WARNING, "bad geometry: first data "
			 "block %u is beyond end of filesystem (%llu)",
			 le32_to_cpu(es->s_first_data_block),
			 ext4_blocks_count(es));
		goto failed_mount;
	}
	// 第一个数据块是0，块大小是1k，簇比例也是1
	if ((es->s_first_data_block == 0) && (es->s_log_block_size == 0) &&
	    (sbi->s_cluster_ratio == 1)) {
		ext4_msg(sb, KERN_WARNING, "bad geometry: first data "
			 "block is 0 with a 1k block and cluster size");
		goto failed_mount;
	}

	blocks_count = (ext4_blocks_count(es) -
			le32_to_cpu(es->s_first_data_block) +
			EXT4_BLOCKS_PER_GROUP(sb) - 1);
	// 算出组数
	do_div(blocks_count, EXT4_BLOCKS_PER_GROUP(sb));
	// 组数太大？
	if (blocks_count > ((uint64_t)1<<32) - EXT4_DESC_PER_BLOCK(sb)) {
		ext4_msg(sb, KERN_WARNING, "groups count too large: %llu "
		       "(block count %llu, first data block %u, "
		       "blocks per group %lu)", blocks_count,
		       ext4_blocks_count(es),
		       le32_to_cpu(es->s_first_data_block),
		       EXT4_BLOCKS_PER_GROUP(sb));
		goto failed_mount;
	}
	// 组数
	sbi->s_groups_count = blocks_count;
	sbi->s_blockfile_groups = min_t(ext4_group_t, sbi->s_groups_count,
			(EXT4_MAX_BLOCK_FILE_PHYS / EXT4_BLOCKS_PER_GROUP(sb)));

	// 组数*每组inode数 != 总的inode数量，则错误
	if (((u64)sbi->s_groups_count * sbi->s_inodes_per_group) !=
	    le32_to_cpu(es->s_inodes_count)) {
		ext4_msg(sb, KERN_ERR, "inodes count not valid: %u vs %llu",
			 le32_to_cpu(es->s_inodes_count),
			 ((u64)sbi->s_groups_count * sbi->s_inodes_per_group));
		ret = -EINVAL;
		goto failed_mount;
	}

	// 存储组描述符的块数
	db_count = (sbi->s_groups_count + EXT4_DESC_PER_BLOCK(sb) - 1) /
		   EXT4_DESC_PER_BLOCK(sb);
	
	// 有元数据块组
	if (ext4_has_feature_meta_bg(sb)) {
		// 第1个元数据组大于组描述符块数，则出错
		if (le32_to_cpu(es->s_first_meta_bg) > db_count) {
			ext4_msg(sb, KERN_WARNING,
				 "first meta block group too large: %u "
				 "(group descriptor block count %u)",
				 le32_to_cpu(es->s_first_meta_bg), db_count);
			goto failed_mount;
		}
	}
	// 给组描述符分配空间
	rcu_assign_pointer(sbi->s_group_desc,
			   kvmalloc_array(db_count,
					  sizeof(struct buffer_head *),
					  GFP_KERNEL));
	if (sbi->s_group_desc == NULL) {
		ext4_msg(sb, KERN_ERR, "not enough memory");
		ret = -ENOMEM;
		goto failed_mount;
	}

	// 块组锁
	bgl_lock_init(sbi->s_blockgroup_lock);

	// 预读每一个组描述符块的bh
	for (i = 0; i < db_count; i++) {
		block = descriptor_loc(sb, logical_sb_block, i);
		ext4_sb_breadahead_unmovable(sb, block);
	}

	for (i = 0; i < db_count; i++) {
		struct buffer_head *bh;

		block = descriptor_loc(sb, logical_sb_block, i);
		bh = ext4_sb_bread_unmovable(sb, block);
		// 读bh失败
		if (IS_ERR(bh)) {
			ext4_msg(sb, KERN_ERR,
			       "can't read group descriptor %d", i);
			db_count = i;
			ret = PTR_ERR(bh);
			bh = NULL;
			goto failed_mount2;
		}
		// 设置每个bh
		rcu_read_lock();
		rcu_dereference(sbi->s_group_desc)[i] = bh;
		rcu_read_unlock();
	}
	// 组描述符块数
	sbi->s_gdb_count = db_count;
	// 组描述符块数错误
	if (!ext4_check_descriptors(sb, logical_sb_block, &first_not_zeroed)) {
		ext4_msg(sb, KERN_ERR, "group descriptors corrupted!");
		ret = -EFSCORRUPTED;
		goto failed_mount2;
	}

	// 错误报错，如果fs有错误，则每天打印一次信息
	timer_setup(&sbi->s_err_report, print_daily_error_info, 0);

	// 注册内存回收器
	if (ext4_es_register_shrinker(sbi))
		goto failed_mount3;
	
	// 条带大小
	sbi->s_stripe = ext4_get_stripe_size(sbi);
	// what?
	sbi->s_extent_max_zeroout_kb = 32;

	// 超级块函数
	sb->s_op = &ext4_sops;
	// 导出函数
	sb->s_export_op = &ext4_export_ops;
	// 扩展属性
	sb->s_xattr = ext4_xattr_handlers;
#ifdef CONFIG_FS_ENCRYPTION
	// 加密函数
	sb->s_cop = &ext4_cryptops;
#endif
#ifdef CONFIG_FS_VERITY
	// 验证函数？
	sb->s_vop = &ext4_verityops;
#endif
#ifdef CONFIG_QUOTA
	// 配额
	sb->dq_op = &ext4_quota_operations;
	if (ext4_has_feature_quota(sb))
		sb->s_qcop = &dquot_quotactl_sysfile_ops;
	else
		sb->s_qcop = &ext4_qctl_operations;
	sb->s_quota_types = QTYPE_MASK_USR | QTYPE_MASK_GRP | QTYPE_MASK_PRJ;
#endif
	// 复制uuid
	memcpy(&sb->s_uuid, es->s_uuid, sizeof(es->s_uuid));

	// 孤儿列表，已删除但还有打开的列表
	INIT_LIST_HEAD(&sbi->s_orphan); /* unlinked but open files */
	mutex_init(&sbi->s_orphan_lock);

	// fast commit相关初始化
	atomic_set(&sbi->s_fc_subtid, 0);
	atomic_set(&sbi->s_fc_ineligible_updates, 0);
	INIT_LIST_HEAD(&sbi->s_fc_q[FC_Q_MAIN]);
	INIT_LIST_HEAD(&sbi->s_fc_q[FC_Q_STAGING]);
	INIT_LIST_HEAD(&sbi->s_fc_dentry_q[FC_Q_MAIN]);
	INIT_LIST_HEAD(&sbi->s_fc_dentry_q[FC_Q_STAGING]);
	sbi->s_fc_bytes = 0;
	ext4_clear_mount_flag(sb, EXT4_MF_FC_INELIGIBLE);
	ext4_clear_mount_flag(sb, EXT4_MF_FC_COMMITTING);
	spin_lock_init(&sbi->s_fc_lock);
	memset(&sbi->s_fc_stats, 0, sizeof(sbi->s_fc_stats));
	sbi->s_fc_replay_state.fc_regions = NULL;
	sbi->s_fc_replay_state.fc_regions_size = 0;
	sbi->s_fc_replay_state.fc_regions_used = 0;
	sbi->s_fc_replay_state.fc_regions_valid = 0;
	sbi->s_fc_replay_state.fc_modified_inodes = NULL;
	sbi->s_fc_replay_state.fc_modified_inodes_size = 0;
	sbi->s_fc_replay_state.fc_modified_inodes_used = 0;

	sb->s_root = NULL;

	// 是不是需要恢复
	needs_recovery = (es->s_last_orphan != 0 ||
			  ext4_has_feature_journal_needs_recovery(sb));

	// 投影？
	if (ext4_has_feature_mmp(sb) && !sb_rdonly(sb))
		if (ext4_multi_mount_protect(sb, le64_to_cpu(es->s_mmp_block)))
			goto failed_mount3a;

	if (!test_opt(sb, NOLOAD) && ext4_has_feature_journal(sb)) {
		// 加载日志？
		err = ext4_load_journal(sb, es, journal_devnum);
		if (err)
			goto failed_mount3a;
	} else if (test_opt(sb, NOLOAD) && !sb_rdonly(sb) &&
		   ext4_has_feature_journal_needs_recovery(sb)) {
		// 需要恢复journal时需要以只读挂载
		ext4_msg(sb, KERN_ERR, "required journal recovery "
		       "suppressed and not mounted read-only");
		goto failed_mount_wq;
	} else {
		// 非日志模式，所以的日志参数都是非法的

		// 日志校验和
		if (test_opt2(sb, EXPLICIT_JOURNAL_CHECKSUM)) {
			ext4_msg(sb, KERN_ERR, "can't mount with "
				 "journal_checksum, fs mounted w/o journal");
			goto failed_mount_wq;
		}
		// 日志异步提交
		if (test_opt(sb, JOURNAL_ASYNC_COMMIT)) {
			ext4_msg(sb, KERN_ERR, "can't mount with "
				 "journal_async_commit, fs mounted w/o journal");
			goto failed_mount_wq;
		}

		// 日志最大提交间隔
		if (sbi->s_commit_interval != JBD2_DEFAULT_MAX_COMMIT_AGE*HZ) {
			ext4_msg(sb, KERN_ERR, "can't mount with "
				 "commit=%lu, fs mounted w/o journal",
				 sbi->s_commit_interval / HZ);
			goto failed_mount_wq;
		}
		// 以data=挂载，而且不是默认挂载选项
		if (EXT4_MOUNT_DATA_FLAGS &
		    (sbi->s_mount_opt ^ sbi->s_def_mount_opt)) {
			ext4_msg(sb, KERN_ERR, "can't mount with "
				 "data=, fs mounted w/o journal");
			goto failed_mount_wq;
		}
		// 删除日志相关选项标志
		sbi->s_def_mount_opt &= ~EXT4_MOUNT_JOURNAL_CHECKSUM;
		clear_opt(sb, JOURNAL_CHECKSUM);
		clear_opt(sb, DATA_FLAGS);
		clear_opt2(sb, JOURNAL_FAST_COMMIT);
		sbi->s_journal = NULL;
		// 不需要恢复
		needs_recovery = 0;
		// 走无日志模式
		goto no_journal;
	}

	// 日志模式
	
	// 64位时，设置日志64位失败
	if (ext4_has_feature_64bit(sb) &&
	    !jbd2_journal_set_features(EXT4_SB(sb)->s_journal, 0, 0,
				       JBD2_FEATURE_INCOMPAT_64BIT)) {
		ext4_msg(sb, KERN_ERR, "Failed to set 64-bit journal feature");
		goto failed_mount_wq;
	}

	// 设置日志校验和
	if (!set_journal_csum_feature_set(sb)) {
		ext4_msg(sb, KERN_ERR, "Failed to set journal checksum "
			 "feature set");
		goto failed_mount_wq;
	}

	// 设置fast commit
	if (test_opt2(sb, JOURNAL_FAST_COMMIT) &&
		!jbd2_journal_set_features(EXT4_SB(sb)->s_journal, 0, 0,
					  JBD2_FEATURE_INCOMPAT_FAST_COMMIT)) {
		ext4_msg(sb, KERN_ERR,
			"Failed to set fast commit journal feature");
		goto failed_mount_wq;
	}

	/* We have now updated the journal if required, so we can
	 * validate the data journaling mode. */
	switch (test_opt(sb, DATA_FLAGS)) {
	case 0:
		// 设置默认日志模式
		if (jbd2_journal_check_available_features
		    (sbi->s_journal, 0, 0, JBD2_FEATURE_INCOMPAT_REVOKE)) {
			set_opt(sb, ORDERED_DATA);
			sbi->s_def_mount_opt |= EXT4_MOUNT_ORDERED_DATA;
		} else {
			set_opt(sb, JOURNAL_DATA);
			sbi->s_def_mount_opt |= EXT4_MOUNT_JOURNAL_DATA;
		}
		break;

	case EXT4_MOUNT_ORDERED_DATA:
	case EXT4_MOUNT_WRITEBACK_DATA:
		// 设置用户指定的日志模式
		if (!jbd2_journal_check_available_features
		    (sbi->s_journal, 0, 0, JBD2_FEATURE_INCOMPAT_REVOKE)) {
			ext4_msg(sb, KERN_ERR, "Journal does not support "
			       "requested data journaling mode");
			goto failed_mount_wq;
		}
	default:
		break;
	}

	// ordered与异步提交不能共存
	if (test_opt(sb, DATA_FLAGS) == EXT4_MOUNT_ORDERED_DATA &&
	    test_opt(sb, JOURNAL_ASYNC_COMMIT)) {
		ext4_msg(sb, KERN_ERR, "can't mount with "
			"journal_async_commit in data=ordered mode");
		goto failed_mount_wq;
	}

	// 日志优先级
	set_task_ioprio(sbi->s_journal->j_task, journal_ioprio);

	// 日志的提交和完成buffer
	sbi->s_journal->j_submit_inode_data_buffers =
		ext4_journal_submit_inode_data_buffers;
	sbi->s_journal->j_finish_inode_data_buffers =
		ext4_journal_finish_inode_data_buffers;

no_journal:
	// 没有nocache，则创建block缓存
	if (!test_opt(sb, NO_MBCACHE)) {
		// 扩展属性缓存
		sbi->s_ea_block_cache = ext4_xattr_create_cache();
		if (!sbi->s_ea_block_cache) {
			ext4_msg(sb, KERN_ERR,
				 "Failed to create ea_block_cache");
			goto failed_mount_wq;
		}

		// 扩展属性inode?
		if (ext4_has_feature_ea_inode(sb)) {
			sbi->s_ea_inode_cache = ext4_xattr_create_cache();
			if (!sbi->s_ea_inode_cache) {
				ext4_msg(sb, KERN_ERR,
					 "Failed to create ea_inode_cache");
				goto failed_mount_wq;
			}
		}
	}

	// 仅支持块大小等于页大小？
	if (ext4_has_feature_verity(sb) && blocksize != PAGE_SIZE) {
		ext4_msg(sb, KERN_ERR, "Unsupported blocksize for fs-verity");
		goto failed_mount_wq;
	}

	// 假加密？
	if (DUMMY_ENCRYPTION_ENABLED(sbi) && !sb_rdonly(sb) &&
	    !ext4_has_feature_encrypt(sb)) {
		ext4_set_feature_encrypt(sb);
		ext4_commit_super(sb, 1);
	}

	// 计算cluster的开销
	if (es->s_overhead_clusters)
		sbi->s_overhead = le32_to_cpu(es->s_overhead_clusters);
	else {
		err = ext4_calculate_overhead(sb);
		if (err)
			goto failed_mount_wq;
	}

	// 创建并行工作队列
	EXT4_SB(sb)->rsv_conversion_wq =
		alloc_workqueue("ext4-rsv-conversion", WQ_MEM_RECLAIM | WQ_UNBOUND, 1);
	if (!EXT4_SB(sb)->rsv_conversion_wq) {
		printk(KERN_ERR "EXT4-fs: failed to create workqueue\n");
		ret = -ENOMEM;
		goto failed_mount4;
	}

	// 获取根结点，EXT4_ROOT_INO=2
	root = ext4_iget(sb, EXT4_ROOT_INO, EXT4_IGET_SPECIAL);
	if (IS_ERR(root)) {
		ext4_msg(sb, KERN_ERR, "get root inode failed");
		ret = PTR_ERR(root);
		root = NULL;
		goto failed_mount4;
	}
	// 不是目录 || 没有数据块 || 长度为0，则出错
	if (!S_ISDIR(root->i_mode) || !root->i_blocks || !root->i_size) {
		ext4_msg(sb, KERN_ERR, "corrupt root inode, run e2fsck");
		iput(root);
		goto failed_mount4;
	}

#ifdef CONFIG_UNICODE
	if (sb->s_encoding)
		sb->s_d_op = &ext4_dentry_ops;
#endif

	// 创建根结点的dentry
	sb->s_root = d_make_root(root);
	if (!sb->s_root) {
		ext4_msg(sb, KERN_ERR, "get root dentry failed");
		ret = -ENOMEM;
		goto failed_mount4;
	}

	// 设置超级块
	ret = ext4_setup_super(sb, es, sb_rdonly(sb));
	if (ret == -EROFS) {
		sb->s_flags |= SB_RDONLY;
		ret = 0;
	} else if (ret)
		goto failed_mount4a;

	// 预留cluster
	ext4_set_resv_clusters(sb);

	if (test_opt(sb, BLOCK_VALIDITY)) {
		err = ext4_setup_system_zone(sb);
		if (err) {
			ext4_msg(sb, KERN_ERR, "failed to initialize system "
				 "zone (%d)", err);
			goto failed_mount4a;
		}
	}
	// replay之后清除
	ext4_fc_replay_cleanup(sb);
	// 初始化extent
	ext4_ext_init(sb);
	// 初始化mb，todo: what is mb
	err = ext4_mb_init(sb);
	if (err) {
		ext4_msg(sb, KERN_ERR, "failed to initialize mballoc (%d)",
			 err);
		goto failed_mount5;
	}

	// 设置日志提交回调
	if (sbi->s_journal)
		sbi->s_journal->j_commit_callback =
			ext4_journal_commit_callback;

	// 重新计算并设置空闲块大小
	block = ext4_count_free_clusters(sb);
	ext4_free_blocks_count_set(sbi->s_es, 
				   EXT4_C2B(sbi, block));
	
	// 设置校验和
	ext4_superblock_csum_set(sb);
	// 空闲簇的数量
	err = percpu_counter_init(&sbi->s_freeclusters_counter, block,
				  GFP_KERNEL);
	if (!err) {
		// 计算并初始化空闲inode数量
		unsigned long freei = ext4_count_free_inodes(sb);
		sbi->s_es->s_free_inodes_count = cpu_to_le32(freei);
		ext4_superblock_csum_set(sb);
		err = percpu_counter_init(&sbi->s_freeinodes_counter, freei,
					  GFP_KERNEL);
	}

	// 目录数量
	if (!err)
		err = percpu_counter_init(&sbi->s_dirs_counter,
					  ext4_count_dirs(sb), GFP_KERNEL);
	// 脏簇数量
	if (!err)
		err = percpu_counter_init(&sbi->s_dirtyclusters_counter, 0,
					  GFP_KERNEL);
	// 过期重试限制
	if (!err)
		err = percpu_counter_init(&sbi->s_sra_exceeded_retry_limit, 0,
					  GFP_KERNEL);
	if (!err)
		err = percpu_init_rwsem(&sbi->s_writepages_rwsem);

	if (err) {
		ext4_msg(sb, KERN_ERR, "insufficient memory");
		goto failed_mount6;
	}

	// 初始化flex_bg
	if (ext4_has_feature_flex_bg(sb))
		if (!ext4_fill_flex_info(sb)) {
			ext4_msg(sb, KERN_ERR,
			       "unable to initialize "
			       "flex_bg meta info!");
			ret = -ENOMEM;
			goto failed_mount6;
		}
	// todo: what is li？
	err = ext4_register_li_request(sb, first_not_zeroed);
	if (err)
		goto failed_mount6;

	// 在sys, block里创建各自文件
	err = ext4_register_sysfs(sb);
	if (err)
		goto failed_mount7;

#ifdef CONFIG_QUOTA
	// 使能配额
	if (ext4_has_feature_quota(sb) && !sb_rdonly(sb)) {
		err = ext4_enable_quotas(sb);
		if (err)
			goto failed_mount8;
	}
#endif  /* CONFIG_QUOTA */

	/*
	 * Save the original bdev mapping's wb_err value which could be
	 * used to detect the metadata async write error.
	 */
	spin_lock_init(&sbi->s_bdev_wb_lock);
	// 错误检查？
	errseq_check_and_advance(&sb->s_bdev->bd_inode->i_mapping->wb_err,
				 &sbi->s_bdev_wb_err);
	// 超级块引用
	sb->s_bdev->bd_super = sb;

	// 处理孤儿相关
	EXT4_SB(sb)->s_mount_state |= EXT4_ORPHAN_FS;
	ext4_orphan_cleanup(sb, es);
	EXT4_SB(sb)->s_mount_state &= ~EXT4_ORPHAN_FS;
	// 设置恢复完成
	if (needs_recovery) {
		ext4_msg(sb, KERN_INFO, "recovery complete");
		err = ext4_mark_recovery_complete(sb, es);
		if (err)
			goto failed_mount8;
	}
	// 日志模式字符串
	if (EXT4_SB(sb)->s_journal) {
		if (test_opt(sb, DATA_FLAGS) == EXT4_MOUNT_JOURNAL_DATA)
			descr = " journalled data mode";
		else if (test_opt(sb, DATA_FLAGS) == EXT4_MOUNT_ORDERED_DATA)
			descr = " ordered data mode";
		else
			descr = " writeback data mode";
	} else
		descr = "out journal";

	// 如果有discard挂载，则设备要支持
	if (test_opt(sb, DISCARD)) {
		struct request_queue *q = bdev_get_queue(sb->s_bdev);
		if (!blk_queue_discard(q))
			ext4_msg(sb, KERN_WARNING,
				 "mounting with \"discard\" option, but "
				 "the device does not support discard");
	}

	// 打印挂载日志，这里的___ratelimit是对打印的限制
	if (___ratelimit(&ext4_mount_msg_ratelimit, "EXT4-fs mount"))
		ext4_msg(sb, KERN_INFO, "mounted filesystem with%s. "
			 "Opts: %.*s%s%s", descr,
			 (int) sizeof(sbi->s_es->s_mount_opts),
			 sbi->s_es->s_mount_opts,
			 *sbi->s_es->s_mount_opts ? "; " : "", orig_data);

	// 5分钟之后上报错误？
	if (es->s_error_count)
		mod_timer(&sbi->s_err_report, jiffies + 300*HZ); /* 5 minutes */

	// 初始化消息打印频率，默认是每5秒10个消息
	ratelimit_state_init(&sbi->s_err_ratelimit_state, 5 * HZ, 10);
	ratelimit_state_init(&sbi->s_warning_ratelimit_state, 5 * HZ, 10);
	ratelimit_state_init(&sbi->s_msg_ratelimit_state, 5 * HZ, 10);
	atomic_set(&sbi->s_warning_count, 0);
	atomic_set(&sbi->s_msg_count, 0);

	kfree(orig_data);
	return 0;

cantfind_ext4:
	if (!silent)
		ext4_msg(sb, KERN_ERR, "VFS: Can't find ext4 filesystem");
	goto failed_mount;

failed_mount8:
	ext4_unregister_sysfs(sb);
	kobject_put(&sbi->s_kobj);
failed_mount7:
	ext4_unregister_li_request(sb);
failed_mount6:
	ext4_mb_release(sb);
	rcu_read_lock();
	flex_groups = rcu_dereference(sbi->s_flex_groups);
	if (flex_groups) {
		for (i = 0; i < sbi->s_flex_groups_allocated; i++)
			kvfree(flex_groups[i]);
		kvfree(flex_groups);
	}
	rcu_read_unlock();
	percpu_counter_destroy(&sbi->s_freeclusters_counter);
	percpu_counter_destroy(&sbi->s_freeinodes_counter);
	percpu_counter_destroy(&sbi->s_dirs_counter);
	percpu_counter_destroy(&sbi->s_dirtyclusters_counter);
	percpu_counter_destroy(&sbi->s_sra_exceeded_retry_limit);
	percpu_free_rwsem(&sbi->s_writepages_rwsem);
failed_mount5:
	ext4_ext_release(sb);
	ext4_release_system_zone(sb);
failed_mount4a:
	dput(sb->s_root);
	sb->s_root = NULL;
failed_mount4:
	ext4_msg(sb, KERN_ERR, "mount failed");
	if (EXT4_SB(sb)->rsv_conversion_wq)
		destroy_workqueue(EXT4_SB(sb)->rsv_conversion_wq);
failed_mount_wq:
	ext4_xattr_destroy_cache(sbi->s_ea_inode_cache);
	sbi->s_ea_inode_cache = NULL;

	ext4_xattr_destroy_cache(sbi->s_ea_block_cache);
	sbi->s_ea_block_cache = NULL;

	if (sbi->s_journal) {
		jbd2_journal_destroy(sbi->s_journal);
		sbi->s_journal = NULL;
	}
failed_mount3a:
	ext4_es_unregister_shrinker(sbi);
failed_mount3:
	del_timer_sync(&sbi->s_err_report);
	ext4_stop_mmpd(sbi);
failed_mount2:
	rcu_read_lock();
	group_desc = rcu_dereference(sbi->s_group_desc);
	for (i = 0; i < db_count; i++)
		brelse(group_desc[i]);
	kvfree(group_desc);
	rcu_read_unlock();
failed_mount:
	if (sbi->s_chksum_driver)
		crypto_free_shash(sbi->s_chksum_driver);

#ifdef CONFIG_UNICODE
	utf8_unload(sb->s_encoding);
#endif

#ifdef CONFIG_QUOTA
	for (i = 0; i < EXT4_MAXQUOTAS; i++)
		kfree(get_qf_name(sb, sbi, i));
#endif
	fscrypt_free_dummy_policy(&sbi->s_dummy_enc_policy);
	/* ext4_blkdev_remove() calls kill_bdev(), release bh before it. */
	brelse(bh);
	ext4_blkdev_remove(sbi);
out_fail:
	sb->s_fs_info = NULL;
	kfree(sbi->s_blockgroup_lock);
out_free_base:
	kfree(sbi);
	kfree(orig_data);
	fs_put_dax(dax_dev);
	return err ? err : ret;
}
```