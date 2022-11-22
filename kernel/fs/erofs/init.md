# erofs_module_init

```c
static int __init erofs_module_init(void)
{
	int err;

	// 在编译时期，检查各数据结构大小是否与期望的相等
	erofs_check_ondisk_layout_definitions();

	// 创建inode缓存
	erofs_inode_cachep = kmem_cache_create("erofs_inode",
					       sizeof(struct erofs_inode), 0,
					       SLAB_RECLAIM_ACCOUNT,
					       erofs_inode_init_once);
	if (!erofs_inode_cachep) {
		err = -ENOMEM;
		goto icache_err;
	}

	// 初始化回收机制。todo: 回收后面再看
	err = erofs_init_shrinker();
	if (err)
		goto shrinker_err;

	// 初始化zip压缩子系统
	err = z_erofs_init_zip_subsystem();
	if (err)
		goto zip_err;

	// 注册erofs文件系统
	err = register_filesystem(&erofs_fs_type);
	if (err)
		goto fs_err;

	return 0;

fs_err:
	z_erofs_exit_zip_subsystem();
zip_err:
	erofs_exit_shrinker();
shrinker_err:
	kmem_cache_destroy(erofs_inode_cachep);
icache_err:
	return err;
}

static struct file_system_type erofs_fs_type = {
	.owner          = THIS_MODULE,
	.name           = "erofs",
	.mount          = erofs_mount,
	.kill_sb        = erofs_kill_sb,
	.fs_flags       = FS_REQUIRES_DEV,
};

int __init z_erofs_init_zip_subsystem(void)
{
	pcluster_cachep = kmem_cache_create("erofs_compress",
					    Z_EROFS_WORKGROUP_SIZE, 0,
					    SLAB_RECLAIM_ACCOUNT,
					    z_erofs_pcluster_init_once);
	if (pcluster_cachep) {
		if (!z_erofs_init_workqueue())
			return 0;

		kmem_cache_destroy(pcluster_cachep);
	}
	return -ENOMEM;
}
```

## 回收机制
```c
int __init erofs_init_shrinker(void)
{
	return register_shrinker(&erofs_shrinker_info);
}

static struct shrinker erofs_shrinker_info = {
	.scan_objects = erofs_shrink_scan,
	.count_objects = erofs_shrink_count,
	.seeks = DEFAULT_SEEKS,
};

static unsigned long erofs_shrink_scan(struct shrinker *shrink,
				       struct shrink_control *sc)
{
	struct erofs_sb_info *sbi;
	struct list_head *p;

	unsigned long nr = sc->nr_to_scan;
	unsigned int run_no;
	unsigned long freed = 0;

	spin_lock(&erofs_sb_list_lock);
	do {
		run_no = ++shrinker_run_no;
	} while (run_no == 0);

	/* Iterate over all mounted superblocks and try to shrink them */
	p = erofs_sb_list.next;
	while (p != &erofs_sb_list) {
		sbi = list_entry(p, struct erofs_sb_info, list);

		/*
		 * We move the ones we do to the end of the list, so we stop
		 * when we see one we have already done.
		 */
		if (sbi->shrinker_run_no == run_no)
			break;

		if (!mutex_trylock(&sbi->umount_mutex)) {
			p = p->next;
			continue;
		}

		spin_unlock(&erofs_sb_list_lock);
		sbi->shrinker_run_no = run_no;

		freed += erofs_shrink_workstation(sbi, nr - freed);

		spin_lock(&erofs_sb_list_lock);
		/* Get the next list element before we move this one */
		p = p->next;

		/*
		 * Move this one to the end of the list to provide some
		 * fairness.
		 */
		list_move_tail(&sbi->list, &erofs_sb_list);
		mutex_unlock(&sbi->umount_mutex);

		if (freed >= nr)
			break;
	}
	spin_unlock(&erofs_sb_list_lock);
	return freed;
}
```

## 初始化zip系统
```c
int __init z_erofs_init_zip_subsystem(void)
{
	// 创建压缩缓存
	pcluster_cachep = kmem_cache_create("erofs_compress",
					    Z_EROFS_WORKGROUP_SIZE, 0,
					    SLAB_RECLAIM_ACCOUNT,
					    z_erofs_pcluster_init_once);
	if (pcluster_cachep) {
		// 初始化zip工作队列
		if (!z_erofs_init_workqueue())
			return 0;

		kmem_cache_destroy(pcluster_cachep);
	}
	return -ENOMEM;
}

static inline int z_erofs_init_workqueue(void)
{
	const unsigned int onlinecpus = num_possible_cpus();

	/*
	 * no need to spawn too many threads, limiting threads could minimum
	 * scheduling overhead, perhaps per-CPU threads should be better?
	 */
	// 初始化解压工作队列
	z_erofs_workqueue = alloc_workqueue("erofs_unzipd",
					    WQ_UNBOUND | WQ_HIGHPRI,
					    onlinecpus + onlinecpus / 4);
	return z_erofs_workqueue ? 0 : -ENOMEM;
}
```