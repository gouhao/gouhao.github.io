# ext4初始化
源码基于5.10
## 1. ext4_init_fs
```c
static int __init ext4_init_fs(void)
{
	int i, err;

	// 消息打开限制
	ratelimit_state_init(&ext4_mount_msg_ratelimit, 30 * HZ, 64);
	// todo: what is li?
	ext4_li_info = NULL;
	mutex_init(&ext4_li_mtx);

	// 编译期检查标志有无越界
	ext4_check_flag_values();

	// EXT4_WQ_HASH_SZ = 37
	// 初始化io结束的等待队列
	for (i = 0; i < EXT4_WQ_HASH_SZ; i++)
		init_waitqueue_head(&ext4__ioend_wq[i]);

	// 创建extent_status slab
	err = ext4_init_es();
	if (err)
		return err;

	// 创建 ext4_pending_reservation slab
	err = ext4_init_pending();
	if (err)
		goto out7;

	// 创建 ext4_bio_post_read_ctx 和对应的缓存池
	err = ext4_init_post_read_processing();
	if (err)
		goto out6;

	// 创建page_io用到的io_end_cachep, io_end_vec_cachep slab
	err = ext4_init_pageio();
	if (err)
		goto out5;

	// 创建 ext4_system_zone_cachep slab缓存
	err = ext4_init_system_zone();
	if (err)
		goto out4;

	// 初始化sys里的ext4目录及文件
	err = ext4_init_sysfs();
	if (err)
		goto out3;

	// 创建 ext4_pspace_cachep, ext4_ac_cachep, ext4_free_data_cachep
	err = ext4_init_mballoc();
	if (err)
		goto out2;
	
	// 创建 ext4_inode_cachep slab
	err = init_inodecache();
	if (err)
		goto out1;

	// 创建 ext4_fc_dentry_cachep slab
	err = ext4_fc_init_dentry_cache();
	if (err)
		goto out05;

	// 注册ext3兼容的fs
	register_as_ext3();

	// 注册ext2兼容的fs
	register_as_ext2();

	// 注册ext4 fs
	err = register_filesystem(&ext4_fs_type);
	if (err)
		goto out;

	return 0;
out:
	unregister_as_ext2();
	unregister_as_ext3();
	ext4_fc_destroy_dentry_cache();
out05:
	destroy_inodecache();
out1:
	ext4_exit_mballoc();
out2:
	ext4_exit_sysfs();
out3:
	ext4_exit_system_zone();
out4:
	ext4_exit_pageio();
out5:
	ext4_exit_post_read_processing();
out6:
	ext4_exit_pending();
out7:
	ext4_exit_es();

	return err;
}

int __init ext4_init_sysfs(void)
{
	int ret;

	// 在fs目录创建ext4目录
	ext4_root = kobject_create_and_add("ext4", fs_kobj);
	if (!ext4_root)
		return -ENOMEM;

	ext4_feat = kzalloc(sizeof(*ext4_feat), GFP_KERNEL);
	if (!ext4_feat) {
		ret = -ENOMEM;
		goto root_err;
	}

	// 创建features目录, features里的文件由ext4_feat_ktype控制
	ret = kobject_init_and_add(ext4_feat, &ext4_feat_ktype,
				   ext4_root, "features");
	if (ret)
		goto feat_err;

	// 在proc里创建入口, proc_dirname="fs/ext4"
	ext4_proc_root = proc_mkdir(proc_dirname, NULL);
	return ret;

feat_err:
	kobject_put(ext4_feat);
	ext4_feat = NULL;
root_err:
	kobject_put(ext4_root);
	ext4_root = NULL;
	return ret;
}

static inline void register_as_ext3(void)
{
	// 注册ext3 fs
	int err = register_filesystem(&ext3_fs_type);
	if (err)
		printk(KERN_WARNING
		       "EXT4-fs: Unable to register as ext3 (%d)\n", err);
}

// 使用ext4作为ext2, 需要满足这些配置条件
#if !defined(CONFIG_EXT2_FS) && !defined(CONFIG_EXT2_FS_MODULE) && defined(CONFIG_EXT4_USE_FOR_EXT2)
static inline void register_as_ext2(void)
{
	int err = register_filesystem(&ext2_fs_type);
	if (err)
		printk(KERN_WARNING
		       "EXT4-fs: Unable to register as ext2 (%d)\n", err);
}
#endif
```

## 2. 3种fs的对比
```c
// ext2
static struct file_system_type ext2_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "ext2",
	.mount		= ext4_mount,
	.kill_sb	= kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("ext2");
MODULE_ALIAS("ext2");
#define IS_EXT2_SB(sb) ((sb)->s_bdev->bd_holder == &ext2_fs_type)

// ext3
static struct file_system_type ext3_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "ext3",
	.mount		= ext4_mount,
	.kill_sb	= kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("ext3");
MODULE_ALIAS("ext3");
#define IS_EXT3_SB(sb) ((sb)->s_bdev->bd_holder == &ext3_fs_type)

static struct file_system_type ext4_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "ext4",
	.mount		= ext4_mount,
	.kill_sb	= kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("ext4");
```
ext2/3/4除了注册时的文件系统名不一样之外，其它都是一样的。另外，给这个模块也起了别名，分别为ext2/3/4
