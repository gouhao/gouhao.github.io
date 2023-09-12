## 主函数
```c
int main (int argc, char *argv[])
{
	errcode_t	retval = 0;
	ext2_filsys	fs;
	badblocks_list	bb_list = 0;
	unsigned int	journal_blocks = 0;
	unsigned int	i, checkinterval;
	int		max_mnt_count;
	int		val, hash_alg;
	int		flags;
	int		old_bitmaps;
	io_manager	io_ptr;
	char		opt_string[40];
	char		*hash_alg_str;
	int		itable_zeroed = 0;


	// 解析参数
	PRS(argc, argv);

	// what?
#ifdef CONFIG_TESTIO_DEBUG
	if (getenv("TEST_IO_FLAGS") || getenv("TEST_IO_BLOCK")) {
		io_ptr = test_io_manager;
		test_io_backing_manager = unix_io_manager;
	} else
#endif
		io_ptr = unix_io_manager;

	// undo操作
	if (undo_file != NULL || should_do_undo(device_name)) {
		retval = mke2fs_setup_tdb(device_name, &io_ptr);
		if (retval)
			exit(1);
	}

	/*
	 * Initialize the superblock....
	 */
	flags = EXT2_FLAG_EXCLUSIVE;
	// direct_io
	if (direct_io)
		flags |= EXT2_FLAG_DIRECT_IO;
	profile_get_boolean(profile, "options", "old_bitmaps", 0, 0,
			    &old_bitmaps);
	// 64位
	if (!old_bitmaps)
		flags |= EXT2_FLAG_64BITS;
	// 不是静默，打印进程
	if (!quiet)
		flags |= EXT2_FLAG_PRINT_PROGRESS;
	if (android_sparse_file) {
		// android
		char *android_sparse_params = malloc(strlen(device_name) + 48);

		if (!android_sparse_params) {
			com_err(program_name, ENOMEM, "%s",
				_("in malloc for android_sparse_params"));
			exit(1);
		}
		sprintf(android_sparse_params, "(%s):%u:%u",
			 device_name, fs_param.s_blocks_count,
			 1024 << fs_param.s_log_block_size);
		retval = ext2fs_initialize(android_sparse_params, flags,
					   &fs_param, sparse_io_manager, &fs);
		free(android_sparse_params);
	} else
		// 初始化，主要是初始化超级块？
		retval = ext2fs_initialize(device_name, flags, &fs_param,
					   io_ptr, &fs);
	if (retval) {
		com_err(device_name, retval, "%s",
			_("while setting up superblock"));
		exit(1);
	}
	// 进程回调
	fs->progress_ops = &ext2fs_numeric_progress_ops;

	// error类型
	retval = set_error_behavior(fs);
	if (retval)
		usage();

	// 各种特性的检查
	if (!quiet &&
	    !ext2fs_has_feature_journal_dev(fs->super) &&
	    ext2fs_has_feature_metadata_csum(fs->super)) {
		if (!ext2fs_has_feature_extents(fs->super))
			printf("%s",
			       _("Extents are not enabled.  The file extent "
				 "tree can be checksummed, whereas block maps "
				 "cannot.  Not enabling extents reduces the "
				 "coverage of metadata checksumming.  "
				 "Pass -O extents to rectify.\n"));
		if (!ext2fs_has_feature_64bit(fs->super))
			printf("%s",
			       _("64-bit filesystem support is not enabled.  "
				 "The larger fields afforded by this feature "
				 "enable full-strength checksumming.  "
				 "Pass -O 64bit to rectify.\n"));
	}

	if (ext2fs_has_feature_csum_seed(fs->super) &&
	    !ext2fs_has_feature_metadata_csum(fs->super)) {
		printf("%s", _("The metadata_csum_seed feature "
			       "requires the metadata_csum feature.\n"));
		exit(1);
	}

	// 计算日志块大小
	if (!journal_device && ((journal_size) ||
	    ext2fs_has_feature_journal(&fs_param)))
		journal_blocks = figure_journal_size(journal_size, fs);

	// tdb_data_size
	sprintf(opt_string, "tdb_data_size=%d", fs->blocksize <= 4096 ?
		32768 : fs->blocksize * 8);
	
	// io channel
	io_channel_set_options(fs->io, opt_string);
	if (offset) {
		sprintf(opt_string, "offset=%llu", offset);
		io_channel_set_options(fs->io, opt_string);
	}

	// discard
	if (!noaction && discard && dev_size && (io_ptr != undo_io_manager)) {
		retval = mke2fs_discard_device(fs);
		if (!retval && io_channel_discard_zeroes_data(fs->io)) {
			if (verbose)
				printf("%s",
				       _("Discard succeeded and will return "
					 "0s - skipping inode table wipe\n"));
			lazy_itable_init = 1;
			itable_zeroed = 1;
			zero_hugefile = 0;
		}
	}

	// 测试文件系统
	if (fs_param.s_flags & EXT2_FLAGS_TEST_FILESYS)
		fs->super->s_flags |= EXT2_FLAGS_TEST_FILESYS;

	// todo: what?
	if (ext2fs_has_feature_flex_bg(&fs_param) ||
	    ext2fs_has_feature_huge_file(&fs_param) ||
	    ext2fs_has_feature_gdt_csum(&fs_param) ||
	    ext2fs_has_feature_dir_nlink(&fs_param) ||
	    ext2fs_has_feature_metadata_csum(&fs_param) ||
	    ext2fs_has_feature_extra_isize(&fs_param))
		fs->super->s_kbytes_written = 1;

	// 清除老的超级块
	if (!noaction)
		zap_sector(fs, 2, 6);

	// 如果指定了uuid则使用之，否则重新生成
	if (fs_uuid) {
		if ((strcasecmp(fs_uuid, "null") == 0) ||
		    (strcasecmp(fs_uuid, "clear") == 0)) {
			uuid_clear(fs->super->s_uuid);
		} else if (strcasecmp(fs_uuid, "time") == 0) {
			uuid_generate_time(fs->super->s_uuid);
		} else if (strcasecmp(fs_uuid, "random") == 0) {
			uuid_generate(fs->super->s_uuid);
		} else if (uuid_parse(fs_uuid, fs->super->s_uuid) != 0) {
			com_err(device_name, 0, "could not parse UUID: %s\n",
				fs_uuid);
			exit(1);
		}
	} else
		uuid_generate(fs->super->s_uuid);

	if (ext2fs_has_feature_csum_seed(fs->super))
		fs->super->s_checksum_seed = ext2fs_crc32c_le(~0,
				fs->super->s_uuid, sizeof(fs->super->s_uuid));

	// 初始化校验和种子
	ext2fs_init_csum_seed(fs);

	// 获取哈希算法，默认使用md4
	hash_alg_str = get_string_from_profile(fs_types, "hash_alg",
					       "half_md4");
	hash_alg = e2p_string2hash(hash_alg_str);
	free(hash_alg_str);
	fs->super->s_def_hash_version = (hash_alg >= 0) ? hash_alg :
		EXT2_HASH_HALF_MD4;

	if (memcmp(fs_param.s_hash_seed, zero_buf,
		sizeof(fs_param.s_hash_seed)) != 0) {
		memcpy(fs->super->s_hash_seed, fs_param.s_hash_seed,
			sizeof(fs->super->s_hash_seed));
	} else
		uuid_generate((unsigned char *) fs->super->s_hash_seed);

	/*
	 * Periodic checks can be enabled/disabled via config file.
	 * Note we override the kernel include file's idea of what the default
	 * check interval (never) should be.  It's a good idea to check at
	 * least *occasionally*, specially since servers will never rarely get
	 * to reboot, since Linux is so robust these days.  :-)
	 *
	 * 180 days (six months) seems like a good value.
	 */
#ifdef EXT2_DFL_CHECKINTERVAL
#undef EXT2_DFL_CHECKINTERVAL
#endif
#define EXT2_DFL_CHECKINTERVAL (86400L * 180L)

	// 周期fsck
	if (get_bool_from_profile(fs_types, "enable_periodic_fsck", 0)) {
		fs->super->s_checkinterval = EXT2_DFL_CHECKINTERVAL;
		fs->super->s_max_mnt_count = EXT2_DFL_MAX_MNT_COUNT;
		/*
		 * Add "jitter" to the superblock's check interval so that we
		 * don't check all the filesystems at the same time.  We use a
		 * kludgy hack of using the UUID to derive a random jitter value
		 */
		for (i = 0, val = 0 ; i < sizeof(fs->super->s_uuid); i++)
			val += fs->super->s_uuid[i];
		fs->super->s_max_mnt_count += val % EXT2_DFL_MAX_MNT_COUNT;
	} else
		fs->super->s_max_mnt_count = -1;

	// 设置 creator os
	if (creator_os && !set_os(fs->super, creator_os)) {
		com_err (program_name, 0, _("unknown os - %s"), creator_os);
		exit(1);
	}

	/*
	 * For the Hurd, we will turn off filetype since it doesn't
	 * support it.
	 */
	if (fs->super->s_creator_os == EXT2_OS_HURD)
		ext2fs_clear_feature_filetype(fs->super);

	// 设置标签
	if (volume_label) {
		memset(fs->super->s_volume_name, 0,
		       sizeof(fs->super->s_volume_name));
		strncpy((char *) fs->super->s_volume_name, volume_label,
			sizeof(fs->super->s_volume_name));
	}

	// 最后挂载目录
	if (mount_dir) {
		memset(fs->super->s_last_mounted, 0,
		       sizeof(fs->super->s_last_mounted));
		strncpy((char *) fs->super->s_last_mounted, mount_dir,
			sizeof(fs->super->s_last_mounted));
	}

	// 加密
	if (ext2fs_has_feature_encrypt(fs->super)) {
		fs->super->s_encrypt_algos[0] =
			EXT4_ENCRYPTION_MODE_AES_256_XTS;
		fs->super->s_encrypt_algos[1] =
			EXT4_ENCRYPTION_MODE_AES_256_CTS;
	}

	// 元数据校验和
	if (ext2fs_has_feature_metadata_csum(fs->super))
		fs->super->s_checksum_type = EXT2_CRC32C_CHKSUM;

	// 静默和没操作，则打印状态
	if (!quiet || noaction)
		show_stats(fs);

	// 不用操作，直接退出
	if (noaction)
		exit(0);

	// 有日志设备
	if (ext2fs_has_feature_journal_dev(fs->super)) {
		// 创建日志设备
		create_journal_dev(fs);
		printf("\n");
		exit(ext2fs_close_free(&fs) ? 1 : 0);
	}

	// 坏块文件列表
	if (bad_blocks_filename)
		read_bb_file(fs, &bb_list, bad_blocks_filename);

	if (cflag)
		test_disk(fs, &bb_list);
	// 处理坏块
	handle_bad_blocks(fs, bb_list);

	// 条带
	fs->stride = fs_stride = fs->super->s_raid_stride;
	if (!quiet)
		printf("%s", _("Allocating group tables: "));
	
	// 分配group表
	if (ext2fs_has_feature_flex_bg(fs->super) &&
	    packed_meta_blocks)
		retval = packed_allocate_tables(fs);
	else
		retval = ext2fs_allocate_tables(fs);
	if (retval) {
		com_err(program_name, retval, "%s",
			_("while trying to allocate filesystem tables"));
		exit(1);
	}
	if (!quiet)
		printf("%s", _("done                            \n"));

	retval = ext2fs_convert_subcluster_bitmap(fs, &fs->block_map);
	if (retval) {
		com_err(program_name, retval, "%s",
			_("\n\twhile converting subcluster bitmap"));
		exit(1);
	}

	if (super_only) {
		// 只创建超级块
		check_plausibility(device_name, CHECK_FS_EXIST, NULL);
		printf(_("%s may be further corrupted by superblock rewrite\n"),
		       device_name);
		if (!force)
			proceed_question(proceed_delay);
		fs->super->s_state |= EXT2_ERROR_FS;
		fs->flags &= ~(EXT2_FLAG_IB_DIRTY|EXT2_FLAG_BB_DIRTY);
		/*
		 * The command "mke2fs -S" is used to recover
		 * corrupted file systems, so do not mark any of the
		 * inodes as unused; we want e2fsck to consider all
		 * inodes as potentially containing recoverable data.
		 */
		if (ext2fs_has_group_desc_csum(fs)) {
			for (i = 0; i < fs->group_desc_count; i++)
				ext2fs_bg_itable_unused_set(fs, i, 0);
		}
	} else {
		// 保留数量
		blk64_t rsv = 65536 / fs->blocksize;
		// 块数
		blk64_t blocks = ext2fs_blocks_count(fs->super);
		blk64_t start;
		blk64_t ret_blk;

#ifdef ZAP_BOOTBLOCK
		zap_sector(fs, 0, 2);
#endif

		// 起始块
		start = (blocks & ~(rsv - 1));
		if (start > rsv)
			start -= rsv;
		// 把start~block块，清空
		if (start > 0)
			retval = ext2fs_zero_blocks2(fs, start, blocks - start,
						    &ret_blk, NULL);

		if (retval) {
			com_err(program_name, retval,
				_("while zeroing block %llu at end of filesystem"),
				ret_blk);
		}
		// 创建inode表
		write_inode_tables(fs, lazy_itable_init, itable_zeroed);
		// 根目录
		create_root_dir(fs);
		// lost found 目录
		create_lost_and_found(fs);
		// 保留inode
		reserve_inodes(fs);
		// 坏块inode
		create_bad_block_inode(fs, bb_list);
		// todo: resize inode?
		if (ext2fs_has_feature_resize_inode(fs->super)) {
			retval = ext2fs_create_resize_inode(fs);
			if (retval) {
				com_err("ext2fs_create_resize_inode", retval,
					"%s",
				_("while reserving blocks for online resize"));
				exit(1);
			}
		}
	}

	if (journal_device) {
		// 有单独的日志设备
		ext2_filsys	jfs;

		if (!check_plausibility(journal_device, CHECK_BLOCK_DEV,
					NULL) && !force)
			proceed_question(proceed_delay);
		check_mount(journal_device, force, _("journal"));

		retval = ext2fs_open(journal_device, EXT2_FLAG_RW|
				     EXT2_FLAG_JOURNAL_DEV_OK, 0,
				     fs->blocksize, unix_io_manager, &jfs);
		if (retval) {
			com_err(program_name, retval,
				_("while trying to open journal device %s\n"),
				journal_device);
			exit(1);
		}
		if (!quiet) {
			printf(_("Adding journal to device %s: "),
			       journal_device);
			fflush(stdout);
		}
		// 添加日志设备
		retval = ext2fs_add_journal_device(fs, jfs);
		if(retval) {
			com_err (program_name, retval,
				 _("\n\twhile trying to add journal to device %s"),
				 journal_device);
			exit(1);
		}
		if (!quiet)
			printf("%s", _("done\n"));
		ext2fs_close_free(&jfs);
		free(journal_device);
	} else if ((journal_size) ||
		   ext2fs_has_feature_journal(&fs_param)) {
		// 没有单独设备，但有日志属性
		if (super_only) {
			printf("%s", _("Skipping journal creation in super-only mode\n"));
			fs->super->s_journal_inum = EXT2_JOURNAL_INO;
			goto no_journal;
		}

		if (!journal_blocks) {
			ext2fs_clear_feature_journal(fs->super);
			goto no_journal;
		}
		if (!quiet) {
			printf(_("Creating journal (%u blocks): "),
			       journal_blocks);
			fflush(stdout);
		}
		// 添加日志结点
		retval = ext2fs_add_journal_inode2(fs, journal_blocks,
						   journal_location,
						   journal_flags);
		if (retval) {
			com_err(program_name, retval, "%s",
				_("\n\twhile trying to create journal"));
			exit(1);
		}
		if (!quiet)
			printf("%s", _("done\n"));
	}
no_journal:
	// 无日志情况
	if (!super_only &&
	    ext2fs_has_feature_mmp(fs->super)) {
		retval = ext2fs_mmp_init(fs);
		if (retval) {
			fprintf(stderr, "%s",
				_("\nError while enabling multiple "
				  "mount protection feature."));
			exit(1);
		}
		if (!quiet)
			printf(_("Multiple mount protection is enabled "
				 "with update interval %d seconds.\n"),
			       fs->super->s_mmp_update_interval);
	}

	// cluster
	if (ext2fs_has_feature_bigalloc(&fs_param))
		fix_cluster_bg_counts(fs);
	// 配额
	if (ext2fs_has_feature_quota(&fs_param))
		create_quota_inodes(fs);

	// 创建大文件
	retval = mk_hugefiles(fs, device_name);
	if (retval)
		com_err(program_name, retval, "while creating huge files");
	// 从指定的目录复制数据到根目录
	if (src_root_dir) {
		if (!quiet)
			printf("%s", _("Copying files into the device: "));

		retval = populate_fs(fs, EXT2_ROOT_INO, src_root_dir,
				     EXT2_ROOT_INO);
		if (retval) {
			com_err(program_name, retval, "%s",
				_("while populating file system"));
			exit(1);
		} else if (!quiet)
			printf("%s", _("done\n"));
	}

	if (!quiet)
		printf("%s", _("Writing superblocks and "
		       "filesystem accounting information: "));
	// 一些清理工作
	checkinterval = fs->super->s_checkinterval;
	max_mnt_count = fs->super->s_max_mnt_count;
	retval = ext2fs_close_free(&fs);
	if (retval) {
		com_err(program_name, retval, "%s",
			_("while writing out and closing file system"));
		retval = 1;
	} else if (!quiet) {
		printf("%s", _("done\n\n"));
		if (!getenv("MKE2FS_SKIP_CHECK_MSG"))
			print_check_message(max_mnt_count, checkinterval);
	}
	remove_error_table(&et_ext2_error_table);
	remove_error_table(&et_prof_error_table);
	profile_release(profile);
	for (i=0; fs_types[i]; i++)
		free(fs_types[i]);
	free(fs_types);
	return retval;
}

```
## 2. ext2fs_initialize
```c
errcode_t ext2fs_initialize(const char *name, int flags,
			    struct ext2_super_block *param,
			    io_manager manager, ext2_filsys *ret_fs)
{
	ext2_filsys	fs;
	errcode_t	retval;
	struct ext2_super_block *super;
	unsigned int	rem;
	unsigned int	overhead = 0;
	unsigned int	ipg;
	dgrp_t		i;
	blk64_t		free_blocks;
	blk_t		numblocks;
	int		rsv_gdt;
	int		csum_flag;
	int		bigalloc_flag;
	int		io_flags;
	int		has_bg;
	unsigned	reserved_inos;
	char		*buf = 0;
	char		c;
	double		reserved_ratio;
	char		*time_env;

	if (!param || !ext2fs_blocks_count(param))
		return EXT2_ET_INVALID_ARGUMENT;

	retval = ext2fs_get_mem(sizeof(struct struct_ext2_filsys), &fs);
	if (retval)
		return retval;

	memset(fs, 0, sizeof(struct struct_ext2_filsys));
	fs->magic = EXT2_ET_MAGIC_EXT2FS_FILSYS;
	fs->flags = flags | EXT2_FLAG_RW;
	fs->umask = 022;
	fs->default_bitmap_type = EXT2FS_BMAP64_RBTREE;
#ifdef WORDS_BIGENDIAN
	fs->flags |= EXT2_FLAG_SWAP_BYTES;
#endif

	time_env = getenv("E2FSPROGS_FAKE_TIME");
	if (time_env)
		fs->now = strtoul(time_env, NULL, 0);

	io_flags = IO_FLAG_RW;
	if (flags & EXT2_FLAG_EXCLUSIVE)
		io_flags |= IO_FLAG_EXCLUSIVE;
	if (flags & EXT2_FLAG_DIRECT_IO)
		io_flags |= IO_FLAG_DIRECT_IO;
	io_flags |= O_BINARY;
	retval = manager->open(name, io_flags, &fs->io);
	if (retval)
		goto cleanup;
	fs->image_io = fs->io;
	fs->io->app_data = fs;
	retval = ext2fs_get_mem(strlen(name)+1, &fs->device_name);
	if (retval)
		goto cleanup;

	strcpy(fs->device_name, name);
	retval = ext2fs_get_mem(SUPERBLOCK_SIZE, &super);
	if (retval)
		goto cleanup;
	fs->super = super;

	memset(super, 0, SUPERBLOCK_SIZE);

#define set_field(field, default) (super->field = param->field ? \
				   param->field : (default))
#define assign_field(field)	(super->field = param->field)

	super->s_magic = EXT2_SUPER_MAGIC;
	super->s_state = EXT2_VALID_FS;

	bigalloc_flag = ext2fs_has_feature_bigalloc(param);

	assign_field(s_log_block_size);

	if (bigalloc_flag) {
		set_field(s_log_cluster_size, super->s_log_block_size+4);
		if (super->s_log_block_size > super->s_log_cluster_size) {
			retval = EXT2_ET_INVALID_ARGUMENT;
			goto cleanup;
		}
	} else
		super->s_log_cluster_size = super->s_log_block_size;

	set_field(s_first_data_block, super->s_log_cluster_size ? 0 : 1);
	set_field(s_max_mnt_count, 0);
	set_field(s_errors, EXT2_ERRORS_DEFAULT);
	set_field(s_feature_compat, 0);
	set_field(s_feature_incompat, 0);
	set_field(s_feature_ro_compat, 0);
	set_field(s_default_mount_opts, 0);
	set_field(s_first_meta_bg, 0);
	set_field(s_raid_stride, 0);		/* default stride size: 0 */
	set_field(s_raid_stripe_width, 0);	/* default stripe width: 0 */
	set_field(s_log_groups_per_flex, 0);
	set_field(s_flags, 0);
	assign_field(s_backup_bgs[0]);
	assign_field(s_backup_bgs[1]);

	assign_field(s_encoding);
	assign_field(s_encoding_flags);

	if (ext2fs_has_feature_casefold(param))
		fs->encoding = ext2fs_load_nls_table(param->s_encoding);

	if (super->s_feature_incompat & ~EXT2_LIB_FEATURE_INCOMPAT_SUPP) {
		retval = EXT2_ET_UNSUPP_FEATURE;
		goto cleanup;
	}
	if (super->s_feature_ro_compat & ~EXT2_LIB_FEATURE_RO_COMPAT_SUPP) {
		retval = EXT2_ET_RO_UNSUPP_FEATURE;
		goto cleanup;
	}

	set_field(s_rev_level, EXT2_GOOD_OLD_REV);
	if (super->s_rev_level >= EXT2_DYNAMIC_REV) {
		set_field(s_first_ino, EXT2_GOOD_OLD_FIRST_INO);
		set_field(s_inode_size, EXT2_GOOD_OLD_INODE_SIZE);
		if (super->s_inode_size >= sizeof(struct ext2_inode_large)) {
			int extra_isize = sizeof(struct ext2_inode_large) -
				EXT2_GOOD_OLD_INODE_SIZE;
			set_field(s_min_extra_isize, extra_isize);
			set_field(s_want_extra_isize, extra_isize);
		}
	} else {
		super->s_first_ino = EXT2_GOOD_OLD_FIRST_INO;
		super->s_inode_size = EXT2_GOOD_OLD_INODE_SIZE;
	}

	set_field(s_checkinterval, 0);
	super->s_mkfs_time = super->s_lastcheck = fs->now ? fs->now : time(NULL);

	super->s_creator_os = CREATOR_OS;

	fs->fragsize = fs->blocksize = EXT2_BLOCK_SIZE(super);
	fs->cluster_ratio_bits = super->s_log_cluster_size -
		super->s_log_block_size;

	if (bigalloc_flag) {
		unsigned long long bpg;

		if (param->s_blocks_per_group &&
		    param->s_clusters_per_group &&
		    ((param->s_clusters_per_group * EXT2FS_CLUSTER_RATIO(fs)) !=
		     param->s_blocks_per_group)) {
			retval = EXT2_ET_INVALID_ARGUMENT;
			goto cleanup;
		}
		if (param->s_clusters_per_group)
			assign_field(s_clusters_per_group);
		else if (param->s_blocks_per_group)
			super->s_clusters_per_group = 
				param->s_blocks_per_group /
				EXT2FS_CLUSTER_RATIO(fs);
		else if (super->s_log_cluster_size + 15 < 32)
			super->s_clusters_per_group = fs->blocksize * 8;
		else
			super->s_clusters_per_group = (fs->blocksize - 1) * 8;
		if (super->s_clusters_per_group > EXT2_MAX_CLUSTERS_PER_GROUP(super))
			super->s_clusters_per_group = EXT2_MAX_CLUSTERS_PER_GROUP(super);
		bpg = EXT2FS_C2B(fs,
			(unsigned long long) super->s_clusters_per_group);
		if (bpg >= (((unsigned long long) 1) << 32)) {
			retval = EXT2_ET_INVALID_ARGUMENT;
			goto cleanup;
		}
		super->s_blocks_per_group = bpg;
	} else {
		set_field(s_blocks_per_group, fs->blocksize * 8);
		if (super->s_blocks_per_group > EXT2_MAX_BLOCKS_PER_GROUP(super))
			super->s_blocks_per_group = EXT2_MAX_BLOCKS_PER_GROUP(super);
		super->s_clusters_per_group = super->s_blocks_per_group;
	}

	ext2fs_blocks_count_set(super, ext2fs_blocks_count(param) &
				~((blk64_t) EXT2FS_CLUSTER_MASK(fs)));
	ext2fs_r_blocks_count_set(super, ext2fs_r_blocks_count(param));
	if (ext2fs_r_blocks_count(super) >= ext2fs_blocks_count(param)) {
		retval = EXT2_ET_INVALID_ARGUMENT;
		goto cleanup;
	}

	set_field(s_mmp_update_interval, 0);

	/*
	 * If we're creating an external journal device, we don't need
	 * to bother with the rest.
	 */
	if (ext2fs_has_feature_journal_dev(super)) {
		fs->group_desc_count = 0;
		ext2fs_mark_super_dirty(fs);
		*ret_fs = fs;
		return 0;
	}

retry:
	fs->group_desc_count = (dgrp_t) ext2fs_div64_ceil(
		ext2fs_blocks_count(super) - super->s_first_data_block,
		EXT2_BLOCKS_PER_GROUP(super));
	if (fs->group_desc_count == 0) {
		retval = EXT2_ET_TOOSMALL;
		goto cleanup;
	}

	set_field(s_desc_size,
		  ext2fs_has_feature_64bit(super) ?
		  EXT2_MIN_DESC_SIZE_64BIT : 0);

	fs->desc_blocks = ext2fs_div_ceil(fs->group_desc_count,
					  EXT2_DESC_PER_BLOCK(super));

	i = fs->blocksize >= 4096 ? 1 : 4096 / fs->blocksize;

	if (ext2fs_has_feature_64bit(super) &&
	    (ext2fs_blocks_count(super) / i) >= (1ULL << 32))
		set_field(s_inodes_count, ~0U);
	else
		set_field(s_inodes_count, ext2fs_blocks_count(super) / i);

	/*
	 * Make sure we have at least EXT2_FIRST_INO + 1 inodes, so
	 * that we have enough inodes for the filesystem(!)
	 */
	if (super->s_inodes_count < EXT2_FIRST_INODE(super)+1)
		super->s_inodes_count = EXT2_FIRST_INODE(super)+1;

	/*
	 * There should be at least as many inodes as the user
	 * requested.  Figure out how many inodes per group that
	 * should be.  But make sure that we don't allocate more than
	 * one bitmap's worth of inodes each group.
	 */
	ipg = ext2fs_div_ceil(super->s_inodes_count, fs->group_desc_count);
	if (ipg > fs->blocksize * 8) {
		if (!bigalloc_flag && super->s_blocks_per_group >= 256) {
			/* Try again with slightly different parameters */
			super->s_blocks_per_group -= 8;
			ext2fs_blocks_count_set(super,
						ext2fs_blocks_count(param));
			super->s_clusters_per_group = super->s_blocks_per_group;
			goto retry;
		} else {
			retval = EXT2_ET_TOO_MANY_INODES;
			goto cleanup;
		}
	}

	if (ipg > (unsigned) EXT2_MAX_INODES_PER_GROUP(super))
		ipg = EXT2_MAX_INODES_PER_GROUP(super);

ipg_retry:
	super->s_inodes_per_group = ipg;

	/*
	 * Make sure the number of inodes per group completely fills
	 * the inode table blocks in the descriptor.  If not, add some
	 * additional inodes/group.  Waste not, want not...
	 */
	fs->inode_blocks_per_group = (((super->s_inodes_per_group *
					EXT2_INODE_SIZE(super)) +
				       EXT2_BLOCK_SIZE(super) - 1) /
				      EXT2_BLOCK_SIZE(super));
	super->s_inodes_per_group = ((fs->inode_blocks_per_group *
				      EXT2_BLOCK_SIZE(super)) /
				     EXT2_INODE_SIZE(super));
	/*
	 * Finally, make sure the number of inodes per group is a
	 * multiple of 8.  This is needed to simplify the bitmap
	 * splicing code.
	 */
	if (super->s_inodes_per_group < 8)
		super->s_inodes_per_group = 8;
	super->s_inodes_per_group &= ~7;
	fs->inode_blocks_per_group = (((super->s_inodes_per_group *
					EXT2_INODE_SIZE(super)) +
				       EXT2_BLOCK_SIZE(super) - 1) /
				      EXT2_BLOCK_SIZE(super));

	/*
	 * adjust inode count to reflect the adjusted inodes_per_group
	 */
	if ((__u64)super->s_inodes_per_group * fs->group_desc_count > ~0U) {
		ipg--;
		goto ipg_retry;
	}
	super->s_inodes_count = super->s_inodes_per_group *
		fs->group_desc_count;
	super->s_free_inodes_count = super->s_inodes_count;

	/*
	 * check the number of reserved group descriptor table blocks
	 */
	if (ext2fs_has_feature_resize_inode(super))
		rsv_gdt = calc_reserved_gdt_blocks(fs);
	else
		rsv_gdt = 0;
	set_field(s_reserved_gdt_blocks, rsv_gdt);
	if (super->s_reserved_gdt_blocks > EXT2_ADDR_PER_BLOCK(super)) {
		retval = EXT2_ET_RES_GDT_BLOCKS;
		goto cleanup;
	}
	/* Enable meta_bg if we'd lose more than 3/4 of a BG to GDT blocks. */
	if (super->s_reserved_gdt_blocks + fs->desc_blocks >
	    super->s_blocks_per_group * 3 / 4) {
		ext2fs_set_feature_meta_bg(fs->super);
		ext2fs_clear_feature_resize_inode(fs->super);
		set_field(s_reserved_gdt_blocks, 0);
	}

	/*
	 * Calculate the maximum number of bookkeeping blocks per
	 * group.  It includes the superblock, the block group
	 * descriptors, the block bitmap, the inode bitmap, the inode
	 * table, and the reserved gdt blocks.
	 */
	overhead = (int) (3 + fs->inode_blocks_per_group +
			  super->s_reserved_gdt_blocks);

	if (ext2fs_has_feature_meta_bg(fs->super))
		overhead++;
	else
		overhead += fs->desc_blocks;

	/* This can only happen if the user requested too many inodes */
	if (overhead > super->s_blocks_per_group) {
		retval = EXT2_ET_TOO_MANY_INODES;
		goto cleanup;
	}

	/*
	 * See if the last group is big enough to support the
	 * necessary data structures.  If not, we need to get rid of
	 * it.  We need to recalculate the overhead for the last block
	 * group, since it might or might not have a superblock
	 * backup.
	 */
	overhead = (int) (2 + fs->inode_blocks_per_group);
	has_bg = 0;
	if (ext2fs_has_feature_sparse_super2(super)) {
		/*
		 * We have to do this manually since
		 * super->s_backup_bgs hasn't been set up yet.
		 */
		if (fs->group_desc_count == 2)
			has_bg = param->s_backup_bgs[0] != 0;
		else
			has_bg = param->s_backup_bgs[1] != 0;
	} else
		has_bg = ext2fs_bg_has_super(fs, fs->group_desc_count - 1);
	if (has_bg)
		overhead += 1 + fs->desc_blocks + super->s_reserved_gdt_blocks;
	rem = ((ext2fs_blocks_count(super) - super->s_first_data_block) %
	       super->s_blocks_per_group);
	if ((fs->group_desc_count == 1) && rem && (rem < overhead)) {
		retval = EXT2_ET_TOOSMALL;
		goto cleanup;
	}
	if (rem && (rem < overhead+50)) {
		ext2fs_blocks_count_set(super, ext2fs_blocks_count(super) -
					rem);
		/*
		 * If blocks count is changed, we need to recalculate
		 * reserved blocks count not to exceed 50%.
		 */
		reserved_ratio = 100.0 * ext2fs_r_blocks_count(param) /
			ext2fs_blocks_count(param);
		ext2fs_r_blocks_count_set(super, reserved_ratio *
			ext2fs_blocks_count(super) / 100.0);

		goto retry;
	}

	/*
	 * At this point we know how big the filesystem will be.  So
	 * we can do any and all allocations that depend on the block
	 * count.
	 */

	/* Set up the locations of the backup superblocks */
	if (ext2fs_has_feature_sparse_super2(super)) {
		if (super->s_backup_bgs[0] >= fs->group_desc_count)
			super->s_backup_bgs[0] = fs->group_desc_count - 1;
		if (super->s_backup_bgs[1] >= fs->group_desc_count)
			super->s_backup_bgs[1] = fs->group_desc_count - 1;
		if (super->s_backup_bgs[0] == super->s_backup_bgs[1])
			super->s_backup_bgs[1] = 0;
		if (super->s_backup_bgs[0] > super->s_backup_bgs[1]) {
			__u32 t = super->s_backup_bgs[0];
			super->s_backup_bgs[0] = super->s_backup_bgs[1];
			super->s_backup_bgs[1] = t;
		}
	}

	retval = ext2fs_get_mem(strlen(fs->device_name) + 80, &buf);
	if (retval)
		goto cleanup;

	strcpy(buf, "block bitmap for ");
	strcat(buf, fs->device_name);
	retval = ext2fs_allocate_subcluster_bitmap(fs, buf, &fs->block_map);
	if (retval)
		goto cleanup;

	strcpy(buf, "inode bitmap for ");
	strcat(buf, fs->device_name);
	retval = ext2fs_allocate_inode_bitmap(fs, buf, &fs->inode_map);
	if (retval)
		goto cleanup;

	ext2fs_free_mem(&buf);

	retval = ext2fs_get_array(fs->desc_blocks, fs->blocksize,
				&fs->group_desc);
	if (retval)
		goto cleanup;

	memset(fs->group_desc, 0, (size_t) fs->desc_blocks * fs->blocksize);

	/*
	 * Reserve the superblock and group descriptors for each
	 * group, and fill in the correct group statistics for group.
	 * Note that although the block bitmap, inode bitmap, and
	 * inode table have not been allocated (and in fact won't be
	 * by this routine), they are accounted for nevertheless.
	 *
	 * If FLEX_BG meta-data grouping is used, only account for the
	 * superblock and group descriptors (the inode tables and
	 * bitmaps will be accounted for when allocated).
	 */
	free_blocks = 0;
	csum_flag = ext2fs_has_group_desc_csum(fs);
	reserved_inos = super->s_first_ino;
	for (i = 0; i < fs->group_desc_count; i++) {
		/*
		 * Don't set the BLOCK_UNINIT group for the last group
		 * because the block bitmap needs to be padded.
		 */
		if (csum_flag) {
			if (i != fs->group_desc_count - 1)
				ext2fs_bg_flags_set(fs, i,
						    EXT2_BG_BLOCK_UNINIT);
			ext2fs_bg_flags_set(fs, i, EXT2_BG_INODE_UNINIT);
			numblocks = super->s_inodes_per_group;
			if (reserved_inos) {
				if (numblocks > reserved_inos) {
					numblocks -= reserved_inos;
					reserved_inos = 0;
				} else {
					reserved_inos -= numblocks;
					numblocks = 0;
				}
			}
			ext2fs_bg_itable_unused_set(fs, i, numblocks);
		}
		numblocks = ext2fs_reserve_super_and_bgd(fs, i, fs->block_map);
		if (fs->super->s_log_groups_per_flex)
			numblocks += 2 + fs->inode_blocks_per_group;

		free_blocks += numblocks;
		ext2fs_bg_free_blocks_count_set(fs, i, numblocks);
		ext2fs_bg_free_inodes_count_set(fs, i, fs->super->s_inodes_per_group);
		ext2fs_bg_used_dirs_count_set(fs, i, 0);
		ext2fs_group_desc_csum_set(fs, i);
	}
	free_blocks &= ~EXT2FS_CLUSTER_MASK(fs);
	ext2fs_free_blocks_count_set(super, free_blocks);

	c = (char) 255;
	if (((int) c) == -1) {
		super->s_flags |= EXT2_FLAGS_SIGNED_HASH;
	} else {
		super->s_flags |= EXT2_FLAGS_UNSIGNED_HASH;
	}

	ext2fs_mark_super_dirty(fs);
	ext2fs_mark_bb_dirty(fs);
	ext2fs_mark_ib_dirty(fs);

	io_channel_set_blksize(fs->io, fs->blocksize);

	*ret_fs = fs;
	return 0;
cleanup:
	free(buf);
	ext2fs_free(fs);
	return retval;
}
```

## ext2fs_zero_blocks2
```c
#define MAX_STRIDE_LENGTH (4194304 / (int) fs->blocksize)
errcode_t ext2fs_zero_blocks2(ext2_filsys fs, blk64_t blk, int num,
			      blk64_t *ret_blk, int *ret_count)
{
	int		j, count;
	static void	*buf;
	// 每次清0的块数
	static int	stride_length;
	errcode_t	retval;

	// 如果fs是NULL，则只释放 buf
	if (!fs) {
		if (buf) {
			free(buf);
			buf = 0;
			stride_length = 0;
		}
		return 0;
	}

	// 待处理块为0
	if (num <= 0)
		return 0;

	// 如果有zeroout接口，则直接执行
	retval = io_channel_zeroout(fs->io, blk, num);
	if (retval == 0)
		return 0;

	// 大于步进长度 && 步进长度小于最大值
	if (num > stride_length && stride_length < MAX_STRIDE_LENGTH) {
		void *p;
		// 使用最新值
		int new_stride = num;

		// 限制到最大值
		if (new_stride > MAX_STRIDE_LENGTH)
			new_stride = MAX_STRIDE_LENGTH;
		// 分配对应的内存
		p = realloc(buf, fs->blocksize * new_stride);
		if (!p)
			return EXT2_ET_NO_MEMORY;
		buf = p;
		stride_length = new_stride;
		// 清0内存
		memset(buf, 0, fs->blocksize * stride_length);
	}
	/* OK, do the write loop */
	j=0;
	while (j < num) {
		if (blk % stride_length) {
			// 不是步进的起点

			// 最后一个条带的块数量
			count = stride_length - (blk % stride_length);
			// 不能大于最大值
			if (count > (num - j))
				count = num - j;
		} else { // 条带起点
			count = num - j;
			// 限制为步进长度
			if (count > stride_length)
				count = stride_length;
		}
		// 写入buf
		retval = io_channel_write_blk64(fs->io, blk, count, buf);
		if (retval) {
			// 写错误
			if (ret_count)
				*ret_count = count;
			if (ret_blk)
				*ret_blk = blk;
			return retval;
		}
		// 修改计数器
		j += count; blk += count;
	}
	return 0;
}
```

## write_inode_tables
```c
static void write_inode_tables(ext2_filsys fs, int lazy_flag, int itable_zeroed)
{
	errcode_t	retval;
	blk64_t		blk;
	dgrp_t		i;
	int		num;
	struct ext2fs_numeric_progress_struct progress;

	// 打印进度
	ext2fs_numeric_progress_init(fs, &progress,
				     _("Writing inode tables: "),
				     fs->group_desc_count);

	for (i = 0; i < fs->group_desc_count; i++) {
		ext2fs_numeric_progress_update(fs, &progress, i);

		blk = ext2fs_inode_table_loc(fs, i);
		num = fs->inode_blocks_per_group;

		if (lazy_flag)
			num = ext2fs_div_ceil((fs->super->s_inodes_per_group -
					       ext2fs_bg_itable_unused(fs, i)) *
					      EXT2_INODE_SIZE(fs->super),
					      EXT2_BLOCK_SIZE(fs->super));
		if (!lazy_flag || itable_zeroed) {
			/* The kernel doesn't need to zero the itable blocks */
			ext2fs_bg_flags_set(fs, i, EXT2_BG_INODE_ZEROED);
			ext2fs_group_desc_csum_set(fs, i);
		}
		if (!itable_zeroed) {
			retval = ext2fs_zero_blocks2(fs, blk, num, &blk, &num);
			if (retval) {
				fprintf(stderr, _("\nCould not write %d "
					  "blocks in inode table starting at %llu: %s\n"),
					num, blk, error_message(retval));
				exit(1);
			}
		}
		if (sync_kludge) {
			if (sync_kludge == 1)
				io_channel_flush(fs->io);
			else if ((i % sync_kludge) == 0)
				io_channel_flush(fs->io);
		}
	}
	ext2fs_numeric_progress_close(fs, &progress,
				      _("done                            \n"));

	/* Reserved inodes must always have correct checksums */
	if (ext2fs_has_feature_metadata_csum(fs->super))
		write_reserved_inodes(fs);
}

blk64_t ext2fs_inode_table_loc(ext2_filsys fs, dgrp_t group)
{
	struct ext4_group_desc *gdp;

	gdp = ext4fs_group_desc(fs, fs->group_desc, group);
	return gdp->bg_inode_table |
		(ext2fs_has_feature_64bit(fs->super) ?
		 (__u64) gdp->bg_inode_table_hi << 32 : 0);
}


static struct ext4_group_desc *ext4fs_group_desc(ext2_filsys fs,
					  struct opaque_ext2_group_desc *gdp,
					  dgrp_t group)
{
	return (struct ext4_group_desc *)ext2fs_group_desc(fs, gdp, group);
}

struct ext2_group_desc *ext2fs_group_desc(ext2_filsys fs,
					  struct opaque_ext2_group_desc *gdp,
					  dgrp_t group)
{
	// 每个组描述的长度
	int desc_size = EXT2_DESC_SIZE(fs->super) & ~7;

	// 算出group对应的地址
	return (struct ext2_group_desc *)((char *)gdp + group * desc_size);
}

#define EXT2_MIN_DESC_SIZE             32
#define EXT2_MIN_DESC_SIZE_64BIT       64
#define EXT2_MAX_DESC_SIZE             EXT2_MIN_BLOCK_SIZE
#define EXT2_DESC_SIZE(s)                                                \
       ((EXT2_SB(s)->s_feature_incompat & EXT4_FEATURE_INCOMPAT_64BIT) ? \
	(s)->s_desc_size : EXT2_MIN_DESC_SIZE)
```
##  参数解析
```c
static void PRS(int argc, char *argv[])
{
	int		b, c, flags;
	int		cluster_size = 0;
	char 		*tmp, **cpp;
	int		explicit_fssize = 0;
	int		blocksize = 0;
	int		inode_ratio = 0;
	int		inode_size = 0;
	unsigned long	flex_bg_size = 0;
	double		reserved_ratio = -1.0;
	int		lsector_size = 0, psector_size = 0;
	int		show_version_only = 0, is_device = 0;
	unsigned long long num_inodes = 0; /* unsigned long long to catch too-large input */
	errcode_t	retval;
	char *		oldpath = getenv("PATH");
	char *		extended_opts = 0;
	char *		fs_type = 0;
	char *		usage_types = 0;
	/*
	 * NOTE: A few words about fs_blocks_count and blocksize:
	 *
	 * Initially, blocksize is set to zero, which implies 1024.
	 * If -b is specified, blocksize is updated to the user's value.
	 *
	 * Next, the device size or the user's "blocks" command line argument
	 * is used to set fs_blocks_count; the units are blocksize.
	 *
	 * Later, if blocksize hasn't been set and the profile specifies a
	 * blocksize, then blocksize is updated and fs_blocks_count is scaled
	 * appropriately.  Note the change in units!
	 *
	 * Finally, we complain about fs_blocks_count > 2^32 on a non-64bit fs.
	 */
	blk64_t		fs_blocks_count = 0;
	long		sysval;
	int		s_opt = -1, r_opt = -1;
	char		*fs_features = 0;
	int		fs_features_size = 0;
	int		use_bsize;
	char		*newpath;
	int		pathlen = sizeof(PATH_SET) + 1;

	// oldpatch是环境变量
	if (oldpath)
		pathlen += strlen(oldpath);
	newpath = malloc(pathlen);
	if (!newpath) {
		fprintf(stderr, "%s",
			_("Couldn't allocate memory for new PATH.\n"));
		exit(1);
	}
	// #define PATH_SET "PATH=/sbin"
	strcpy(newpath, PATH_SET);

	// 把旧环境变量链到后面
	if (oldpath) {
		strcat (newpath, ":");
		strcat (newpath, oldpath);
	}
	putenv (newpath);

	/* Determine the system page size if possible */
#ifdef HAVE_SYSCONF
#if (!defined(_SC_PAGESIZE) && defined(_SC_PAGE_SIZE))
#define _SC_PAGESIZE _SC_PAGE_SIZE
#endif
#ifdef _SC_PAGESIZE
	sysval = sysconf(_SC_PAGESIZE);
	if (sysval > 0)
		sys_page_size = sysval;
#endif /* _SC_PAGESIZE */
#endif /* HAVE_SYSCONF */

	// MKE2FS_CONFIG 配置
	if ((tmp = getenv("MKE2FS_CONFIG")) != NULL)
		config_fn[0] = tmp;
	profile_set_syntax_err_cb(syntax_err_report);
	retval = profile_init(config_fn, &profile);
	if (retval == ENOENT) {
		retval = profile_init(default_files, &profile);
		if (retval)
			goto profile_error;
		retval = profile_set_default(profile, mke2fs_default_profile);
		if (retval)
			goto profile_error;
	} else if (retval) {
profile_error:
		fprintf(stderr, _("Couldn't init profile successfully"
				  " (error: %ld).\n"), retval);
		exit(1);
	}

	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
	add_error_table(&et_ext2_error_table);
	add_error_table(&et_prof_error_table);
	memset(&fs_param, 0, sizeof(struct ext2_super_block));

	// 版本号
	fs_param.s_rev_level = 1;  /* Create revision 1 filesystems now */

	// 2.2 之前的版本
	if (is_before_linux_ver(2, 2, 0))
		fs_param.s_rev_level = 0;

	if (argc && *argv) {
		program_name = get_progname(*argv);

		// ext3fs
		if (!strcmp(program_name, "mkfs.ext3") ||
		    !strcmp(program_name, "mke3fs"))
			journal_size = -1;
	}

	while ((c = getopt (argc, argv,
		    "b:cd:e:g:i:jl:m:no:qr:s:t:vC:DE:FG:I:J:KL:M:N:O:R:ST:U:Vz:")) != EOF) {
		switch (c) {
		case 'b':
			// 解析出指定的块大小，主要解析后缀
			blocksize = parse_num_blocks2(optarg, -1);
			b = (blocksize > 0) ? blocksize : -blocksize;
			// EXT2_MIN_BLOCK_SIZE = 1024
			// EXT2_MAX_BLOCK_SIZE = 65536
			if (b < EXT2_MIN_BLOCK_SIZE ||
			    b > EXT2_MAX_BLOCK_SIZE) {
				com_err(program_name, 0,
					_("invalid block size - %s"), optarg);
				exit(1);
			}
			// 大于4096在很多系统上用不了
			if (blocksize > 4096)
				fprintf(stderr, _("Warning: blocksize %d not "
						  "usable on most systems.\n"),
					blocksize);
			// 设置逻辑块大小的2次幂
			if (blocksize > 0)
				fs_param.s_log_block_size =
					int_log2(blocksize >>
						 EXT2_MIN_BLOCK_LOG_SIZE);
			break;
		case 'c':	/* Check for bad blocks */
			cflag++;
			break;
		case 'C':
			// cluster大小
			cluster_size = parse_num_blocks2(optarg, -1);
			// 1024～512M之间
			if (cluster_size <= EXT2_MIN_CLUSTER_SIZE ||
			    cluster_size > EXT2_MAX_CLUSTER_SIZE) {
				com_err(program_name, 0,
					_("invalid cluster size - %s"),
					optarg);
				exit(1);
			}
			break;
		case 'd': // 从给定目录复制内核到新fs根目录
			src_root_dir = optarg;
			break;
		case 'D': // 直接io
			direct_io = 1;
			break;
		case 'R': // -R 已废弃
			com_err(program_name, 0, "%s",
				_("'-R' is deprecated, use '-E' instead"));
			/* fallthrough */
		case 'E': // 扩展选项
			extended_opts = optarg;
			break;
		case 'e': // 发生错误时的处理方式
			if (strcmp(optarg, "continue") == 0)
				errors_behavior = EXT2_ERRORS_CONTINUE;
			else if (strcmp(optarg, "remount-ro") == 0)
				errors_behavior = EXT2_ERRORS_RO;
			else if (strcmp(optarg, "panic") == 0)
				errors_behavior = EXT2_ERRORS_PANIC;
			else {
				com_err(program_name, 0,
					_("bad error behavior - %s"),
					optarg);
				usage();
			}
			break;
		case 'F': // 强制创建fs，即使设备正在使用等，这个标志要指定2次才有效
			force++;
			break;
		case 'g': // 每个组块的数量
			fs_param.s_blocks_per_group = strtoul(optarg, &tmp, 0);
			// 转化成数字后不能有其他值
			if (*tmp) {
				com_err(program_name, 0, "%s",
				_("Illegal number for blocks per group"));
				exit(1);
			}
			// block必须是8的倍数
			if ((fs_param.s_blocks_per_group % 8) != 0) {
				com_err(program_name, 0, "%s",
				_("blocks per group must be multiple of 8"));
				exit(1);
			}
			break;
		case 'G': // group的数量
			flex_bg_size = strtoul(optarg, &tmp, 0);
			if (*tmp) {
				com_err(program_name, 0, "%s",
					_("Illegal number for flex_bg size"));
				exit(1);
			}
			// 数量必须是2的倍数
			if (flex_bg_size < 1 ||
			    (flex_bg_size & (flex_bg_size-1)) != 0) {
				com_err(program_name, 0, "%s",
					_("flex_bg size must be a power of 2"));
				exit(1);
			}
			// 不能大于2^31次方
			if (flex_bg_size > MAX_32_NUM) {
				com_err(program_name, 0,
				_("flex_bg size (%lu) must be less than"
				" or equal to 2^31"), flex_bg_size);
				exit(1);
			}
			break;
		case 'i': // inode比例
			inode_ratio = parse_num_blocks(optarg, -1);
			// 介于 1024~65536*1024之间
			if (inode_ratio < EXT2_MIN_BLOCK_SIZE ||
			    inode_ratio > EXT2_MAX_BLOCK_SIZE * 1024) {
				com_err(program_name, 0,
					_("invalid inode ratio %s (min %d/max %d)"),
					optarg, EXT2_MIN_BLOCK_SIZE,
					EXT2_MAX_BLOCK_SIZE * 1024);
				exit(1);
			}
			break;
		case 'I':
			// inode大小
			inode_size = strtoul(optarg, &tmp, 0);
			if (*tmp) {
				com_err(program_name, 0,
					_("invalid inode size - %s"), optarg);
				exit(1);
			}
			break;
		case 'j': // 日志文件系统
			if (!journal_size)
				journal_size = -1;
			break;
		case 'J':
			// 日志选项
			parse_journal_opts(optarg);
			break;
		case 'K': // K已被E代替
			fprintf(stderr, "%s",
				_("Warning: -K option is deprecated and "
				  "should not be used anymore. Use "
				  "\'-E nodiscard\' extended option "
				  "instead!\n"));
			discard = 0;
			break;
		case 'l': // 坏块号文件列表
			bad_blocks_filename = realloc(bad_blocks_filename,
						      strlen(optarg) + 1);
			if (!bad_blocks_filename) {
				com_err(program_name, ENOMEM, "%s",
					_("in malloc for bad_blocks_filename"));
				exit(1);
			}
			strcpy(bad_blocks_filename, optarg);
			break;
		case 'L':
			// label标签
			volume_label = optarg;
			if (strlen(volume_label) > EXT2_LABEL_LEN) {
				volume_label[EXT2_LABEL_LEN] = '\0';
				fprintf(stderr, _("Warning: label too long; will be truncated to '%s'\n\n"),
					volume_label);
			}
			break;
		case 'm':
			// 预留块的比例
			reserved_ratio = strtod(optarg, &tmp);
			// 预留在 0 ~ 50 之间
			if ( *tmp || reserved_ratio > 50 ||
			     reserved_ratio < 0) {
				com_err(program_name, 0,
					_("invalid reserved blocks percent - %s"),
					optarg);
				exit(1);
			}
			break;
		case 'M': // 上次挂载的目录
			mount_dir = optarg;
			break;
		case 'n': // 不真正创建fs，只是显示操作
			noaction++;
			break;
		case 'N': inode数量
			num_inodes = strtoul(optarg, &tmp, 0);
			if (*tmp) {
				com_err(program_name, 0,
					_("bad num inodes - %s"), optarg);
					exit(1);
			}
			break;
		case 'o':
			// 创建fs的os名称
			creator_os = optarg;
			break;
		case 'O': // 指定的特性
			retval = ext2fs_resize_mem(fs_features_size,
				   fs_features_size + 1 + strlen(optarg),
						   &fs_features);
			if (retval) {
				com_err(program_name, retval,
				     _("while allocating fs_feature string"));
				exit(1);
			}
			if (fs_features_size)
				strcat(fs_features, ",");
			else
				fs_features[0] = 0;
			strcat(fs_features, optarg);
			fs_features_size += 1 + strlen(optarg);
			break;
		case 'q': // 静默模式
			quiet = 1;
			break;
		case 'r':
			r_opt = strtoul(optarg, &tmp, 0);
			if (*tmp) {
				com_err(program_name, 0,
					_("bad revision level - %s"), optarg);
				exit(1);
			}
			if (r_opt > EXT2_MAX_SUPP_REV) {
				com_err(program_name, EXT2_ET_REV_TOO_HIGH,
					_("while trying to create revision %d"), r_opt);
				exit(1);
			}
			fs_param.s_rev_level = r_opt;
			break;
		case 's':	/* deprecated */
			s_opt = atoi(optarg);
			break;
		case 'S': // 只写超级块和组描述块，不改变inode表,block表等fs结构，用于恢复fs
			super_only = 1;
			break;
		case 't': // 指定的fs类型
			if (fs_type) {
				com_err(program_name, 0, "%s",
				    _("The -t option may only be used once"));
				exit(1);
			}
			fs_type = strdup(optarg);
			break;
		case 'T': // fs的使用类型
			if (usage_types) {
				com_err(program_name, 0, "%s",
				    _("The -T option may only be used once"));
				exit(1);
			}
			usage_types = strdup(optarg);
			break;
		case 'U': // 指定uuid
			fs_uuid = optarg;
			break;
		case 'v': // 打印描述
			verbose = 1;
			break;
		case 'V':
			// 版本号
			show_version_only++;
			break;
		case 'z': // 把磁盘上老的内容复制到undo_file里，
			undo_file = optarg;
			break;
		default:
			usage();
		}
	}
	// 还有别的选项，则打印使用方式
	if ((optind == argc) && !show_version_only)
		usage();
	// 设备名称
	device_name = argv[optind++];

	// 只打印版本号
	if (!quiet || show_version_only)
		fprintf (stderr, "mke2fs %s (%s)\n", E2FSPROGS_VERSION,
			 E2FSPROGS_DATE);

	// 只打印版本号则退出
	if (show_version_only) {
		fprintf(stderr, _("\tUsing %s\n"),
			error_message(EXT2_ET_BASE));
		exit(0);
	}

	// 没指定块大小，指定了journal设备。todo: 后面看
	if (blocksize <= 0 && journal_device) {
		ext2_filsys	jfs;
		io_manager	io_ptr;

#ifdef CONFIG_TESTIO_DEBUG
		if (getenv("TEST_IO_FLAGS") || getenv("TEST_IO_BLOCK")) {
			io_ptr = test_io_manager;
			test_io_backing_manager = unix_io_manager;
		} else
#endif
			io_ptr = unix_io_manager;
		retval = ext2fs_open(journal_device,
				     EXT2_FLAG_JOURNAL_DEV_OK, 0,
				     0, io_ptr, &jfs);
		if (retval) {
			com_err(program_name, retval,
				_("while trying to open journal device %s\n"),
				journal_device);
			exit(1);
		}
		if ((blocksize < 0) && (jfs->blocksize < (unsigned) (-blocksize))) {
			com_err(program_name, 0,
				_("Journal dev blocksize (%d) smaller than "
				  "minimum blocksize %d\n"), jfs->blocksize,
				-blocksize);
			exit(1);
		}
		blocksize = jfs->blocksize;
		printf(_("Using journal device's blocksize: %d\n"), blocksize);
		fs_param.s_log_block_size =
			int_log2(blocksize >> EXT2_MIN_BLOCK_LOG_SIZE);
		ext2fs_close_free(&jfs);
	}

	// 计算出block的数量
	if (optind < argc) {
		fs_blocks_count = parse_num_blocks2(argv[optind++],
						   fs_param.s_log_block_size);
		if (!fs_blocks_count) {
			com_err(program_name, 0,
				_("invalid blocks '%s' on device '%s'"),
				argv[optind - 1], device_name);
			exit(1);
		}
	}
	if (optind < argc)
		usage();

	profile_get_integer(profile, "options", "sync_kludge", 0, 0,
			    &sync_kludge);
	tmp = getenv("MKE2FS_SYNC");
	if (tmp)
		sync_kludge = atoi(tmp);

	profile_get_integer(profile, "options", "proceed_delay", 0, 0,
			    &proceed_delay);

	/* The isatty() test is so we don't break existing scripts */
	flags = CREATE_FILE;
	if (isatty(0) && isatty(1) && !offset)
		flags |= CHECK_FS_EXIST;
	if (!quiet)
		flags |= VERBOSE_CREATE;
	if (fs_blocks_count == 0)
		flags |= NO_SIZE;
	else
		explicit_fssize = 1;
	if (!check_plausibility(device_name, flags, &is_device) && !force)
		proceed_question(proceed_delay);

	// 检查设备是否已经挂载
	check_mount(device_name, force, _("filesystem"));

	// 获取设备大小
	if (noaction && fs_blocks_count) {
		dev_size = fs_blocks_count;
		retval = 0;
	} else
		// dev_size返回的是块的数量
#ifndef _WIN32
		retval = ext2fs_get_device_size2(device_name,
						 EXT2_BLOCK_SIZE(&fs_param),
						 &dev_size);
#else
		retval = ext2fs_get_device_size(device_name,
						EXT2_BLOCK_SIZE(&fs_param),
						&dev_size);
#endif
	if (retval && (retval != EXT2_ET_UNIMPLEMENTED)) {
		com_err(program_name, retval, "%s",
			_("while trying to determine filesystem size"));
		exit(1);
	}
	if (!fs_blocks_count) {
		// 没有指定块数量，则使用上面计算出来的
		if (retval == EXT2_ET_UNIMPLEMENTED) {
			com_err(program_name, 0, "%s",
				_("Couldn't determine device size; you "
				"must specify\nthe size of the "
				"filesystem\n"));
			exit(1);
		} else {
			if (dev_size == 0) {
				com_err(program_name, 0, "%s",
				_("Device size reported to be zero.  "
				  "Invalid partition specified, or\n\t"
				  "partition table wasn't reread "
				  "after running fdisk, due to\n\t"
				  "a modified partition being busy "
				  "and in use.  You may need to reboot\n\t"
				  "to re-read your partition table.\n"
				  ));
				exit(1);
			}
			fs_blocks_count = dev_size;
			if (sys_page_size > EXT2_BLOCK_SIZE(&fs_param))
				fs_blocks_count &= ~((blk64_t) ((sys_page_size /
					     EXT2_BLOCK_SIZE(&fs_param))-1));
		}
	// 指定的块数量大于计算出的数量
	} else if (!force && is_device && (fs_blocks_count > dev_size)) {
		com_err(program_name, 0, "%s",
			_("Filesystem larger than apparent device size."));
		proceed_question(proceed_delay);
	}

	// 获取默认的fs类型和usage类型
	if (!fs_type)
		profile_get_string(profile, "devices", device_name,
				   "fs_type", 0, &fs_type);
	// 默认使用类型
	if (!usage_types)
		profile_get_string(profile, "devices", device_name,
				   "usage_types", 0, &usage_types);

	// 解析文件系统类型
	fs_types = parse_fs_type(fs_type, usage_types, &fs_param,
				 fs_blocks_count ? fs_blocks_count : dev_size,
				 argv[0]);
	if (!fs_types) {
		fprintf(stderr, "%s", _("Failed to parse fs types list\n"));
		exit(1);
	}

	/* Figure out what features should be enabled */

	tmp = NULL;
	// todo: what?
	if (fs_param.s_rev_level != EXT2_GOOD_OLD_REV) {
		tmp = get_string_from_profile(fs_types, "base_features",
		      "sparse_super,large_file,filetype,resize_inode,dir_index");
		edit_feature(tmp, &fs_param.s_feature_compat);
		free(tmp);

		/* And which mount options as well */
		tmp = get_string_from_profile(fs_types, "default_mntopts",
					      "acl,user_xattr");
		edit_mntopts(tmp, &fs_param.s_default_mount_opts);
		if (tmp)
			free(tmp);

		for (cpp = fs_types; *cpp; cpp++) {
			tmp = NULL;
			profile_get_string(profile, "fs_types", *cpp,
					   "features", "", &tmp);
			if (tmp && *tmp)
				edit_feature(tmp, &fs_param.s_feature_compat);
			if (tmp)
				free(tmp);
		}
		tmp = get_string_from_profile(fs_types, "default_features",
					      "");
	}
	// todo: what?
	if (for_hurd(creator_os)) {
		ext2fs_clear_feature_filetype(&fs_param);
		ext2fs_clear_feature_huge_file(&fs_param);
		ext2fs_clear_feature_metadata_csum(&fs_param);
		ext2fs_clear_feature_ea_inode(&fs_param);
		ext2fs_clear_feature_casefold(&fs_param);
	
	}
	// todo: what?
	edit_feature(fs_features ? fs_features : tmp,
		     &fs_param.s_feature_compat);
	if (tmp)
		free(tmp);
	(void) ext2fs_free_mem(&fs_features);
	
	// hurd不支持一些特性
	if (for_hurd(creator_os)) {
		if (ext2fs_has_feature_filetype(&fs_param)) {
			fprintf(stderr, "%s", _("The HURD does not support the "
						"filetype feature.\n"));
			exit(1);
		}
		if (ext2fs_has_feature_huge_file(&fs_param)) {
			fprintf(stderr, "%s", _("The HURD does not support the "
						"huge_file feature.\n"));
			exit(1);
		}
		if (ext2fs_has_feature_metadata_csum(&fs_param)) {
			fprintf(stderr, "%s", _("The HURD does not support the "
						"metadata_csum feature.\n"));
			exit(1);
		}
		if (ext2fs_has_feature_ea_inode(&fs_param)) {
			fprintf(stderr, "%s", _("The HURD does not support the "
						"ea_inode feature.\n"));
			exit(1);
		}
	}

	// 获取扇区大小
	retval = ext2fs_get_device_sectsize(device_name, &lsector_size);
	if (retval) {
		com_err(program_name, retval, "%s",
			_("while trying to determine hardware sector size"));
		exit(1);
	}

	// 获取物理扇区大小
	retval = ext2fs_get_device_phys_sectsize(device_name, &psector_size);
	if (retval) {
		com_err(program_name, retval, "%s",
			_("while trying to determine physical sector size"));
		exit(1);
	}

	// 环境变量里有这2个值，则用它们代替设备的
	tmp = getenv("MKE2FS_DEVICE_SECTSIZE");
	if (tmp != NULL)
		lsector_size = atoi(tmp);
	tmp = getenv("MKE2FS_DEVICE_PHYS_SECTSIZE");
	if (tmp != NULL)
		psector_size = atoi(tmp);

	// 较老的内核不区分物理与逻辑扇区大小
	if (!psector_size)
		psector_size = lsector_size;

	if (blocksize <= 0) {
		// 没有指定块大小
		use_bsize = get_int_from_profile(fs_types, "blocksize", 4096);

		if (use_bsize == -1) {
			use_bsize = sys_page_size;
			if (is_before_linux_ver(2, 6, 0) && use_bsize > 4096)
				use_bsize = 4096;
		}
		if (lsector_size && use_bsize < lsector_size)
			use_bsize = lsector_size;
		if ((blocksize < 0) && (use_bsize < (-blocksize)))
			use_bsize = -blocksize;
		blocksize = use_bsize;
		// 块数量
		fs_blocks_count /= (blocksize / 1024);
	} else {
		// 块大小小于逻辑大小
		if (blocksize < lsector_size) {			/* Impossible */
			com_err(program_name, EINVAL, "%s",
				_("while setting blocksize; too small "
				  "for device\n"));
			exit(1);
		// 物理块大小小于页大小，警告
		} else if ((blocksize < psector_size) &&
			   (psector_size <= sys_page_size)) {	/* Suboptimal */
			fprintf(stderr, _("Warning: specified blocksize %d is "
				"less than device physical sectorsize %d\n"),
				blocksize, psector_size);
		}
	}

	// 逻辑块大小转换成指数
	fs_param.s_log_block_size =
		int_log2(blocksize >> EXT2_MIN_BLOCK_LOG_SIZE);

	// 块数量大于2^32，则要支持64位
	if ((fs_blocks_count > MAX_32_NUM) &&
	    ext2fs_has_feature_64bit(&fs_param))
		ext2fs_clear_feature_resize_inode(&fs_param);
	if ((fs_blocks_count > MAX_32_NUM) &&
	    !ext2fs_has_feature_64bit(&fs_param) &&
	    get_bool_from_profile(fs_types, "auto_64-bit_support", 0)) {
		ext2fs_set_feature_64bit(&fs_param);
		ext2fs_clear_feature_resize_inode(&fs_param);
	}
	if ((fs_blocks_count > MAX_32_NUM) &&
	    !ext2fs_has_feature_64bit(&fs_param)) {
		fprintf(stderr, _("%s: Size of device (0x%llx blocks) %s "
				  "too big to be expressed\n\t"
				  "in 32 bits using a blocksize of %d.\n"),
			program_name, fs_blocks_count, device_name,
			EXT2_BLOCK_SIZE(&fs_param));
		exit(1);
	}
	// todo: ?
	if (fs_blocks_count >
	    (1ULL << (EXT2_BLOCK_SIZE_BITS(&fs_param) + 3 + 32)) - 1) {
		fprintf(stderr, _("%s: Size of device (0x%llx blocks) %s "
				  "too big to create\n\t"
				  "a filesystem using a blocksize of %d.\n"),
			program_name, fs_blocks_count, device_name,
			EXT2_BLOCK_SIZE(&fs_param));
		exit(1);
	}

	// 设置块数量
	ext2fs_blocks_count_set(&fs_param, fs_blocks_count);

	// 有日志设备
	if (ext2fs_has_feature_journal_dev(&fs_param)) {
		int i;

		for (i=0; fs_types[i]; i++) {
			free(fs_types[i]);
			fs_types[i] = 0;
		}
		fs_types[0] = strdup("journal");
		fs_types[1] = 0;
	}

	// 打印详情
	if (verbose) {
		fputs(_("fs_types for mke2fs.conf resolution: "), stdout);
		print_str_list(fs_types);
	}

	// 旧版本不支持一些特性兼容
	if (r_opt == EXT2_GOOD_OLD_REV &&
	    (fs_param.s_feature_compat || fs_param.s_feature_incompat ||
	     fs_param.s_feature_ro_compat)) {
		fprintf(stderr, "%s", _("Filesystem features not supported "
					"with revision 0 filesystems\n"));
		exit(1);
	}

	// 设置选项
	if (s_opt > 0) {
		if (r_opt == EXT2_GOOD_OLD_REV) {
			fprintf(stderr, "%s",
				_("Sparse superblocks not supported "
				  "with revision 0 filesystems\n"));
			exit(1);
		}
		ext2fs_set_feature_sparse_super(&fs_param);
	} else if (s_opt == 0)
		ext2fs_clear_feature_sparse_super(&fs_param);

	// 设置日志
	if (journal_size != 0) {
		if (r_opt == EXT2_GOOD_OLD_REV) {
			fprintf(stderr, "%s", _("Journals not supported with "
						"revision 0 filesystems\n"));
			exit(1);
		}
		ext2fs_set_feature_journal(&fs_param);
	}

	// 保留比例，如果没指定的话，则获取默认的
	if (reserved_ratio < 0.0) {
		reserved_ratio = get_double_from_profile(
					fs_types, "reserved_ratio", 5.0);
		if (reserved_ratio > 50 || reserved_ratio < 0) {
			com_err(program_name, 0,
				_("invalid reserved blocks percent - %lf"),
				reserved_ratio);
			exit(1);
		}
	}

	// 有日志设备
	if (ext2fs_has_feature_journal_dev(&fs_param)) {
		reserved_ratio = 0;
		fs_param.s_feature_incompat = EXT3_FEATURE_INCOMPAT_JOURNAL_DEV;
		fs_param.s_feature_compat = 0;
		fs_param.s_feature_ro_compat &=
					EXT4_FEATURE_RO_COMPAT_METADATA_CSUM;
 	}

	// 在64位上必须使能extent
	if (ext2fs_has_feature_64bit(&fs_param) &&
	    !ext2fs_has_feature_extents(&fs_param)) {
		printf("%s", _("Extents MUST be enabled for a 64-bit "
			       "filesystem.  Pass -O extents to rectify.\n"));
		exit(1);
	}

	// 设置各种参数
	if (ext2fs_has_feature_meta_bg(&fs_param) &&
	    (tmp = getenv("MKE2FS_FIRST_META_BG")))
		fs_param.s_first_meta_bg = atoi(tmp);
	if (ext2fs_has_feature_bigalloc(&fs_param)) {
		if (!cluster_size)
			cluster_size = get_int_from_profile(fs_types,
							    "cluster_size",
							    blocksize*16);
		fs_param.s_log_cluster_size =
			int_log2(cluster_size >> EXT2_MIN_CLUSTER_LOG_SIZE);
		if (fs_param.s_log_cluster_size &&
		    fs_param.s_log_cluster_size < fs_param.s_log_block_size) {
			com_err(program_name, 0, "%s",
				_("The cluster size may not be "
				  "smaller than the block size.\n"));
			exit(1);
		}
	} else if (cluster_size) {
		com_err(program_name, 0, "%s",
			_("specifying a cluster size requires the "
			  "bigalloc feature"));
		exit(1);
	} else
		fs_param.s_log_cluster_size = fs_param.s_log_block_size;

	// 获取默认inode比例
	if (inode_ratio == 0) {
		inode_ratio = get_int_from_profile(fs_types, "inode_ratio",
						   8192);
		if (inode_ratio < blocksize)
			inode_ratio = blocksize;
		if (inode_ratio < EXT2_CLUSTER_SIZE(&fs_param))
			inode_ratio = EXT2_CLUSTER_SIZE(&fs_param);
	}

#ifdef HAVE_BLKID_PROBE_GET_TOPOLOGY
	retval = get_device_geometry(device_name, &fs_param,
				     (unsigned int) psector_size);
	if (retval < 0) {
		fprintf(stderr,
			_("warning: Unable to get device geometry for %s\n"),
			device_name);
	} else if (retval) {
		printf(_("%s alignment is offset by %lu bytes.\n"),
		       device_name, retval);
		printf(_("This may result in very poor performance, "
			  "(re)-partitioning suggested.\n"));
	}
#endif

	num_backups = get_int_from_profile(fs_types, "num_backup_sb", 2);

	blocksize = EXT2_BLOCK_SIZE(&fs_param);

	/*
	 * Initialize s_desc_size so that the parse_extended_opts()
	 * can correctly handle "-E resize=NNN" if the 64-bit option
	 * is set.
	 */
	if (ext2fs_has_feature_64bit(&fs_param))
		fs_param.s_desc_size = EXT2_MIN_DESC_SIZE_64BIT;

	// 块大小大于页大小
	if (blocksize > sys_page_size) {
		if (!force) {
			com_err(program_name, 0,
				_("%d-byte blocks too big for system (max %d)"),
				blocksize, sys_page_size);
			proceed_question(proceed_delay);
		}
		fprintf(stderr, _("Warning: %d-byte blocks too big for system "
				  "(max %d), forced to continue\n"),
			blocksize, sys_page_size);
	}

	// 3.18之前的内核校验和不完善
	if (is_before_linux_ver(3, 18, 0) &&
	    ext2fs_has_feature_metadata_csum(&fs_param))
		fprintf(stderr, _("Suggestion: Use Linux kernel >= 3.18 for "
			"improved stability of the metadata and journal "
			"checksum features.\n"));

	// 新的内核默认支持lazy_itable
	if (is_before_linux_ver(2, 6, 37))
		lazy_itable_init = 0;
	else
		lazy_itable_init = 1;

	// 有这个文件，延迟加载也是1   
	if (access("/sys/fs/ext4/features/lazy_itable_init", R_OK) == 0)
		lazy_itable_init = 1;

	// 从profile里获取这些配置
	lazy_itable_init = get_bool_from_profile(fs_types,
						 "lazy_itable_init",
						 lazy_itable_init);
	discard = get_bool_from_profile(fs_types, "discard" , discard);
	journal_flags |= get_bool_from_profile(fs_types,
					       "lazy_journal_init", 0) ?
					       EXT2_MKJOURNAL_LAZYINIT : 0;
	journal_flags |= EXT2_MKJOURNAL_NO_MNT_CHECK;

	if (!journal_location_string)
		journal_location_string = get_string_from_profile(fs_types,
						"journal_location", "");
	if ((journal_location == ~0ULL) && journal_location_string &&
	    *journal_location_string)
		journal_location = parse_num_blocks2(journal_location_string,
						fs_param.s_log_block_size);
	free(journal_location_string);

	packed_meta_blocks = get_bool_from_profile(fs_types,
						   "packed_meta_blocks", 0);
	if (packed_meta_blocks)
		journal_location = 0;

	// casefold ?
	if (ext2fs_has_feature_casefold(&fs_param)) {
		char *ef, *en = get_string_from_profile(fs_types,
							"encoding", "utf8");
		int encoding = e2p_str2encoding(en);

		if (encoding < 0) {
			com_err(program_name, 0,
				_("Unknown filename encoding from profile: %s"),
				en);
			exit(1);
		}
		free(en);
		fs_param.s_encoding = encoding;
		ef = get_string_from_profile(fs_types, "encoding_flags", NULL);
		if (ef) {
			if (e2p_str2encoding_flags(encoding, ef,
					&fs_param.s_encoding_flags) < 0) {
				com_err(program_name, 0,
			_("Unknown encoding flags from profile: %s"), ef);
				exit(1);
			}
			free(ef);
		} else
			fs_param.s_encoding_flags =
				e2p_get_encoding_flags(encoding);
	}

	/* Get options from profile */
	for (cpp = fs_types; *cpp; cpp++) {
		tmp = NULL;
		profile_get_string(profile, "fs_types", *cpp, "options", "", &tmp);
			if (tmp && *tmp)
				parse_extended_opts(&fs_param, tmp);
			free(tmp);
	}

	// 解析扩展属性
	if (extended_opts)
		parse_extended_opts(&fs_param, extended_opts);

	// todo: what?
	if (explicit_fssize == 0 && offset > 0) {
		fs_blocks_count -= offset / EXT2_BLOCK_SIZE(&fs_param);
		ext2fs_blocks_count_set(&fs_param, fs_blocks_count);
		fprintf(stderr,
			_("\nWarning: offset specified without an "
			  "explicit file system size.\n"
			  "Creating a file system with %llu blocks "
			  "but this might\n"
			  "not be what you want.\n\n"),
			(unsigned long long) fs_blocks_count);
	}

	// 配额
	if (quotatype_bits & QUOTA_PRJ_BIT)
		ext2fs_set_feature_project(&fs_param);

	// 下面是对各种特性进行判断
	if (ext2fs_has_feature_project(&fs_param)) {
		quotatype_bits |= QUOTA_PRJ_BIT;
		if (inode_size == EXT2_GOOD_OLD_INODE_SIZE) {
			com_err(program_name, 0,
				_("%d byte inodes are too small for "
				  "project quota"),
				inode_size);
			exit(1);
		}
		if (inode_size == 0) {
			inode_size = get_int_from_profile(fs_types,
							  "inode_size", 0);
			if (inode_size <= EXT2_GOOD_OLD_INODE_SIZE*2)
				inode_size = EXT2_GOOD_OLD_INODE_SIZE*2;
		}
	}

	if (ext2fs_has_feature_casefold(&fs_param) &&
	    ext2fs_has_feature_encrypt(&fs_param)) {
		com_err(program_name, 0, "%s",
			_("The encrypt and casefold features are not "
			  "compatible.\nThey can not be both enabled "
			  "simultaneously.\n"));
		      exit (1);
	}

	/* Don't allow user to set both metadata_csum and uninit_bg bits. */
	if (ext2fs_has_feature_metadata_csum(&fs_param) &&
	    ext2fs_has_feature_gdt_csum(&fs_param))
		ext2fs_clear_feature_gdt_csum(&fs_param);

	/* Can't support bigalloc feature without extents feature */
	if (ext2fs_has_feature_bigalloc(&fs_param) &&
	    !ext2fs_has_feature_extents(&fs_param)) {
		com_err(program_name, 0, "%s",
			_("Can't support bigalloc feature without "
			  "extents feature"));
		exit(1);
	}

	if (ext2fs_has_feature_meta_bg(&fs_param) &&
	    ext2fs_has_feature_resize_inode(&fs_param)) {
		fprintf(stderr, "%s", _("The resize_inode and meta_bg "
					"features are not compatible.\n"
					"They can not be both enabled "
					"simultaneously.\n"));
		exit(1);
	}

	if (!quiet && ext2fs_has_feature_bigalloc(&fs_param))
		fprintf(stderr, "%s", _("\nWarning: the bigalloc feature is "
				  "still under development\n"
				  "See https://ext4.wiki.kernel.org/"
				  "index.php/Bigalloc for more information\n\n"));

	/*
	 * Since sparse_super is the default, we would only have a problem
	 * here if it was explicitly disabled.
	 */
	if (ext2fs_has_feature_resize_inode(&fs_param) &&
	    !ext2fs_has_feature_sparse_super(&fs_param)) {
		com_err(program_name, 0, "%s",
			_("reserved online resize blocks not supported "
			  "on non-sparse filesystem"));
		exit(1);
	}

	// 每组的block数 256～8*blocksize
	if (fs_param.s_blocks_per_group) {
		if (fs_param.s_blocks_per_group < 256 ||
		    fs_param.s_blocks_per_group > 8 * (unsigned) blocksize) {
			com_err(program_name, 0, "%s",
				_("blocks per group count out of range"));
			exit(1);
		}
	}

	// 如果是bigalloc，则默认簇大小和blocks_per_group一样
	if (ext2fs_has_feature_bigalloc(&fs_param)) {
		fs_param.s_clusters_per_group = fs_param.s_blocks_per_group;
		fs_param.s_blocks_per_group = 0;
	}

	if (inode_size == 0)
		inode_size = get_int_from_profile(fs_types, "inode_size", 0);
	if (!flex_bg_size && ext2fs_has_feature_flex_bg(&fs_param))
		flex_bg_size = get_uint_from_profile(fs_types,
						     "flex_bg_size", 16);
	if (flex_bg_size) {
		if (!ext2fs_has_feature_flex_bg(&fs_param)) {
			com_err(program_name, 0, "%s",
				_("Flex_bg feature not enabled, so "
				  "flex_bg size may not be specified"));
			exit(1);
		}
		fs_param.s_log_groups_per_flex = int_log2(flex_bg_size);
	}

	if (inode_size && fs_param.s_rev_level >= EXT2_DYNAMIC_REV) {
		if (inode_size < EXT2_GOOD_OLD_INODE_SIZE ||
		    inode_size > EXT2_BLOCK_SIZE(&fs_param) ||
		    inode_size & (inode_size - 1)) {
			com_err(program_name, 0,
				_("invalid inode size %d (min %d/max %d)"),
				inode_size, EXT2_GOOD_OLD_INODE_SIZE,
				blocksize);
			exit(1);
		}
		fs_param.s_inode_size = inode_size;
	}

	/*
	 * If inode size is 128 and inline data is enabled, we need
	 * to notify users that inline data will never be useful.
	 */
	if (ext2fs_has_feature_inline_data(&fs_param) &&
	    fs_param.s_inode_size == EXT2_GOOD_OLD_INODE_SIZE) {
		com_err(program_name, 0,
			_("%d byte inodes are too small for inline data; "
			  "specify larger size"),
			fs_param.s_inode_size);
		exit(1);
	}

	/* Make sure number of inodes specified will fit in 32 bits */
	if (num_inodes == 0) {
		unsigned long long n;
		n = ext2fs_blocks_count(&fs_param) * blocksize / inode_ratio;
		if (n > MAX_32_NUM) {
			if (ext2fs_has_feature_64bit(&fs_param))
				num_inodes = MAX_32_NUM;
			else {
				com_err(program_name, 0,
					_("too many inodes (%llu), raise "
					  "inode ratio?"), n);
				exit(1);
			}
		}
	} else if (num_inodes > MAX_32_NUM) {
		com_err(program_name, 0,
			_("too many inodes (%llu), specify < 2^32 inodes"),
			  num_inodes);
		exit(1);
	}
	/*
	 * Calculate number of inodes based on the inode ratio
	 */
	fs_param.s_inodes_count = num_inodes ? num_inodes :
		(ext2fs_blocks_count(&fs_param) * blocksize) / inode_ratio;

	if ((((unsigned long long)fs_param.s_inodes_count) *
	     (inode_size ? inode_size : EXT2_GOOD_OLD_INODE_SIZE)) >=
	    ((ext2fs_blocks_count(&fs_param)) *
	     EXT2_BLOCK_SIZE(&fs_param))) {
		com_err(program_name, 0, _("inode_size (%u) * inodes_count "
					  "(%u) too big for a\n\t"
					  "filesystem with %llu blocks, "
					  "specify higher inode_ratio (-i)\n\t"
					  "or lower inode count (-N).\n"),
			inode_size ? inode_size : EXT2_GOOD_OLD_INODE_SIZE,
			fs_param.s_inodes_count,
			(unsigned long long) ext2fs_blocks_count(&fs_param));
		exit(1);
	}

	/*
	 * Calculate number of blocks to reserve
	 */
	ext2fs_r_blocks_count_set(&fs_param, reserved_ratio *
				  ext2fs_blocks_count(&fs_param) / 100.0);

	if (ext2fs_has_feature_sparse_super2(&fs_param)) {
		if (num_backups >= 1)
			fs_param.s_backup_bgs[0] = 1;
		if (num_backups >= 2)
			fs_param.s_backup_bgs[1] = ~0;
	}

	free(fs_type);
	free(usage_types);
}
```