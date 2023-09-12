# fusefs初始化
源码基于stable-5.10.102

## 1. 模块初始化
```c
static int __init fuse_init(void)
{
	int res;

	// 当前版本 7.32
	pr_info("init (API version %i.%i)\n",
		FUSE_KERNEL_VERSION, FUSE_KERNEL_MINOR_VERSION);

	// 链接列表
	INIT_LIST_HEAD(&fuse_conn_list);

	// 初始化文件系统相关，在这个里面会注册文件系统
	res = fuse_fs_init();
	if (res)
		goto err;

	// 注册 fuse 请求杂项设备
	res = fuse_dev_init();
	if (res)
		goto err_fs_cleanup;

	// 初始化fuse的sys文件系统相关文件
	res = fuse_sysfs_init();
	if (res)
		goto err_dev_cleanup;

	// 这个函数就一句话：注册fusectl文件系统
	res = fuse_ctl_init();
	if (res)
		goto err_sysfs_cleanup;

	// 检查限制后台最大请求数的值，如果超过范围，则限制到合理范围
	sanitize_global_limit(&max_user_bgreq);

	// 检查限制最大拥塞阈值，如果超过范围，则限制到合理范围
	sanitize_global_limit(&max_user_congthresh);

	return 0;

 err_sysfs_cleanup:
	fuse_sysfs_cleanup();
 err_dev_cleanup:
	fuse_dev_cleanup();
 err_fs_cleanup:
	fuse_fs_cleanup();
 err:
	return res;
}

static void sanitize_global_limit(unsigned *limit)
{
	// 原文注释：默认请求大小为总内存的1/2^13, 假设每个请求392字节
	if (*limit == 0)
		*limit = ((totalram_pages() << PAGE_SHIFT) >> 13) / 392;

	// 最大不能超过 2^16
	if (*limit >= 1 << 16)
		*limit = (1 << 16) - 1;
}
```
总结fuse模块初始化主要流程：
1. 注册fuse文件系统
2. 创建请求设备
3. 注册fusectl文件系统
4. 创建sys文件系统里的相关目录

## 2. fuse_fs_init
```c
static int __init fuse_fs_init(void)
{
	int err;

	// 创建inode内存缓存
	fuse_inode_cachep = kmem_cache_create("fuse_inode",
			sizeof(struct fuse_inode), 0,
			SLAB_HWCACHE_ALIGN|SLAB_ACCOUNT|SLAB_RECLAIM_ACCOUNT,
			// 初始化方法，每次分配一个对象的时候都调用这个方法
			fuse_inode_init_once);
	err = -ENOMEM;
	if (!fuse_inode_cachep)
		goto out;

	// 注册 fuseblk 文件系统（在CONFIG_BLOCK打开的情况下）
	err = register_fuseblk();
	if (err)
		goto out2;

	// 注册fuse文件系统
	err = register_filesystem(&fuse_fs_type);
	if (err)
		goto out3;

	return 0;

 out3:
	unregister_fuseblk();
 out2:
	kmem_cache_destroy(fuse_inode_cachep);
 out:
	return err;
}

static struct file_system_type fuse_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "fuse",
	.fs_flags	= FS_HAS_SUBTYPE | FS_USERNS_MOUNT,
	.init_fs_context = fuse_init_fs_context,
	.parameters	= fuse_fs_parameters,
	.kill_sb	= fuse_kill_sb_anon,
};
MODULE_ALIAS_FS("fuse");

static struct file_system_type fuseblk_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "fuseblk",
	.init_fs_context = fuse_init_fs_context,
	.parameters	= fuse_fs_parameters,
	.kill_sb	= fuse_kill_sb_blk,
	.fs_flags	= FS_REQUIRES_DEV | FS_HAS_SUBTYPE,
};
MODULE_ALIAS_FS("fuseblk");

static void fuse_inode_init_once(void *foo)
{
	struct inode *inode = foo;
	// 这个调用vfs的方法，初始化inode里的各个成员
	inode_init_once(inode);
}
```

## 3. fuse_dev_init

```c
int __init fuse_dev_init(void)
{
	int err = -ENOMEM;
	// 创建fuse请求内存缓存
	fuse_req_cachep = kmem_cache_create("fuse_request",
					    sizeof(struct fuse_req),
					    0, 0, NULL);
	if (!fuse_req_cachep)
		goto out;

	// 注册一个杂项设备
	err = misc_register(&fuse_miscdevice);
	if (err)
		goto out_cache_clean;

	return 0;

 out_cache_clean:
	kmem_cache_destroy(fuse_req_cachep);
 out:
	return err;
}

static struct miscdevice fuse_miscdevice = {
	.minor = FUSE_MINOR, // 229
	.name  = "fuse",
	.fops = &fuse_dev_operations,
};
```

## fuse_sysfs_init
```c
static int fuse_sysfs_init(void)
{
	int err;

	// 在/sys/fs下面创建fuse目录
	fuse_kobj = kobject_create_and_add("fuse", fs_kobj);
	if (!fuse_kobj) {
		err = -ENOMEM;
		goto out_err;
	}

	// 在/sys/fs/fuse下面创建connections
	err = sysfs_create_mount_point(fuse_kobj, "connections");
	if (err)
		goto out_fuse_unregister;

	return 0;

 out_fuse_unregister:
	kobject_put(fuse_kobj);
 out_err:
	return err;
}
```

## fuse_ctl_init
```c
int __init fuse_ctl_init(void)
{
	return register_filesystem(&fuse_ctl_fs_type);
}

static struct file_system_type fuse_ctl_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "fusectl",
	.init_fs_context = fuse_ctl_init_fs_context,
	.kill_sb	= fuse_ctl_kill_sb,
};
MODULE_ALIAS_FS("fusectl");

```

从上面可知fuse模块有以下别名：fuse, fuseblk, fusectl，当需要这些文件系统时，会自动加载这些模块。