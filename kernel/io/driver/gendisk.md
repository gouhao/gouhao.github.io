# gendisk
源码基于5.10

## 1. alloc_disk
```c
#define alloc_disk(minors) alloc_disk_node(minors, NUMA_NO_NODE)

#define alloc_disk_node(minors, node_id)				\
({									\
	static struct lock_class_key __key;				\
	const char *__name;						\
	struct gendisk *__disk;						\
	/* 磁盘名 */								\
	__name = "(gendisk_completion)"#minors"("#node_id")";		\
	/* 分配磁盘 */								\
	__disk = __alloc_disk_node(minors, node_id);			\
	/* 锁位图 */								\
	if (__disk)							\
		lockdep_init_map(&__disk->lockdep_map, __name, &__key, 0); \
									\
	__disk;								\
})

struct gendisk *__alloc_disk_node(int minors, int node_id)
{
	struct gendisk *disk;
	struct disk_part_tbl *ptbl;

	if (minors > DISK_MAX_PARTS) {
		printk(KERN_ERR
			"block: can't allocate more than %d partitions\n",
			DISK_MAX_PARTS);
		minors = DISK_MAX_PARTS;
	}

	// 分配 disk 实例
	disk = kzalloc_node(sizeof(struct gendisk), GFP_KERNEL, node_id);
	if (!disk)
		return NULL;

	// 0分区的磁盘状态
	disk->part0.dkstats = alloc_percpu(struct disk_stats);
	if (!disk->part0.dkstats)
		goto out_free_disk;

	init_rwsem(&disk->lookup_sem);
	disk->node_id = node_id;

	// 分配分区表，这里传的是，所以只分配一个
	if (disk_expand_part_tbl(disk, 0)) {
		free_percpu(disk->part0.dkstats);
		goto out_free_disk;
	}

	ptbl = rcu_dereference_protected(disk->part_tbl, 1);
	// 把0号分区设置到分区表
	rcu_assign_pointer(ptbl->part[0], &disk->part0);

	// 序号、引用初始化
	hd_sects_seq_init(&disk->part0);
	if (hd_ref_init(&disk->part0))
		goto out_free_part0;

	// 次设备号
	disk->minors = minors;

	// 分配disk->random
	rand_initialize_disk(disk);

	// 设置类别和类型
	// #define disk_to_dev(disk)	(&(disk)->part0.__dev)
	disk_to_dev(disk)->class = &block_class;
	disk_to_dev(disk)->type = &disk_type;
	device_initialize(disk_to_dev(disk));
	return disk;

out_free_part0:
	hd_free_part(&disk->part0);
out_free_disk:
	kfree(disk);
	return NULL;
}

void device_initialize(struct device *dev)
{
	dev->kobj.kset = devices_kset;
	kobject_init(&dev->kobj, &device_ktype);
	INIT_LIST_HEAD(&dev->dma_pools);
	mutex_init(&dev->mutex);
#ifdef CONFIG_PROVE_LOCKING
	mutex_init(&dev->lockdep_mutex);
#endif
	lockdep_set_novalidate_class(&dev->mutex);
	spin_lock_init(&dev->devres_lock);
	INIT_LIST_HEAD(&dev->devres_head);
	// 电源管理初始化
	device_pm_init(dev);
	// 设置numa
	set_dev_node(dev, -1);
#ifdef CONFIG_GENERIC_MSI_IRQ
	raw_spin_lock_init(&dev->msi_lock);
	INIT_LIST_HEAD(&dev->msi_list);
#endif
	INIT_LIST_HEAD(&dev->links.consumers);
	INIT_LIST_HEAD(&dev->links.suppliers);
	INIT_LIST_HEAD(&dev->links.needs_suppliers);
	INIT_LIST_HEAD(&dev->links.defer_hook);

	// 设置连接状态，现在是没驱动
	/*
	状态有4个：
	DL_DEV_NO_DRIVER：没有驱动
	DL_DEV_PROBING：驱动正在探测
	DL_DEV_DRIVER_BOUND：驱动已和设备绑定
	DL_DEV_UNBINDING：驱动正在和设备解绑
	*/
	dev->links.status = DL_DEV_NO_DRIVER;
}

int disk_expand_part_tbl(struct gendisk *disk, int partno)
{
	struct disk_part_tbl *old_ptbl =
		rcu_dereference_protected(disk->part_tbl, 1);
	struct disk_part_tbl *new_ptbl;
	int len = old_ptbl ? old_ptbl->len : 0;
	int i, target;

	target = partno + 1;
	/*
	 * 这里面判断错误值是因为，用户可以通过blkpg_ioctl来调到这个方法
	 */
	if (target < 0)
		return -EINVAL;

	/* disk_max_parts() 在初始化期间是0，初始化期间忽略它 */
	if (disk_max_parts(disk) && target > disk_max_parts(disk))
		return -EINVAL;

	// 如果当前长度满足要求，就不用重新分配
	if (target <= len)
		return 0;

	// 分配一个长度为target的分区表
	new_ptbl = kzalloc_node(struct_size(new_ptbl, part, target), GFP_KERNEL,
				disk->node_id);
	if (!new_ptbl)
		return -ENOMEM;

	new_ptbl->len = target;

	// 把旧分区表里的内容复制到新表里
	for (i = 0; i < len; i++)
		rcu_assign_pointer(new_ptbl->part[i], old_ptbl->part[i]);

	// 设置新表，释放旧表
	disk_replace_part_tbl(disk, new_ptbl);
	return 0;
}

static void disk_replace_part_tbl(struct gendisk *disk,
				  struct disk_part_tbl *new_ptbl)
{
	struct disk_part_tbl *old_ptbl =
		rcu_dereference_protected(disk->part_tbl, 1);

	// 给disk分区表重新赋值
	rcu_assign_pointer(disk->part_tbl, new_ptbl);

	// 释放旧表
	if (old_ptbl) {
		rcu_assign_pointer(old_ptbl->last_lookup, NULL);
		kfree_rcu(old_ptbl, rcu_head);
	}
}
```

## 2. disk_map_sector_rcu
```c
struct hd_struct *disk_map_sector_rcu(struct gendisk *disk, sector_t sector)
{
	struct disk_part_tbl *ptbl;
	struct hd_struct *part;
	int i;

	rcu_read_lock();
	ptbl = rcu_dereference(disk->part_tbl);

	part = rcu_dereference(ptbl->last_lookup);
	if (part && sector_in_part(part, sector) && hd_struct_try_get(part))
		goto out_unlock;

	for (i = 1; i < ptbl->len; i++) {
		part = rcu_dereference(ptbl->part[i]);

		if (part && sector_in_part(part, sector)) {
			/*
			 * only live partition can be cached for lookup,
			 * so use-after-free on cached & deleting partition
			 * can be avoided
			 */
			if (!hd_struct_try_get(part))
				break;
			rcu_assign_pointer(ptbl->last_lookup, part);
			goto out_unlock;
		}
	}

	part = &disk->part0;
out_unlock:
	rcu_read_unlock();
	return part;
}
```

## 3. blk_alloc_devt
```c
int blk_alloc_devt(struct hd_struct *part, dev_t *devt)
{
	// 获取gendisk对象
	struct gendisk *disk = part_to_disk(part);
	int idx;

	// 在minors范围内,直接创建devt
	if (part->partno < disk->minors) {
		*devt = MKDEV(disk->major, disk->first_minor + part->partno);
		return 0;
	}

	// 分配idr
	idr_preload(GFP_KERNEL);

	spin_lock_bh(&ext_devt_lock);
	// 分配一个id
	idx = idr_alloc(&ext_devt_idr, part, 0, NR_EXT_DEVT, GFP_NOWAIT);
	spin_unlock_bh(&ext_devt_lock);

	idr_preload_end();
	if (idx < 0)
		return idx == -ENOSPC ? -EBUSY : idx;
	// 创建devt
	// BLOCK_EXT_MAJOR=259, blk_mangle_minor计算一个次设备号,计算较复杂没看懂
	*devt = MKDEV(BLOCK_EXT_MAJOR, blk_mangle_minor(idx));
	return 0;
}

static int blk_mangle_minor(int minor)
{
#ifdef CONFIG_DEBUG_BLOCK_EXT_DEVT
	int i;

	for (i = 0; i < MINORBITS / 2; i++) {
		int low = minor & (1 << i);
		int high = minor & (1 << (MINORBITS - 1 - i));
		int distance = MINORBITS - 1 - 2 * i;

		minor ^= low | high;	/* clear both bits */
		low <<= distance;	/* swap the positions */
		high >>= distance;
		minor |= low | high;	/* and set */
	}
#endif
	return minor;
}

static inline struct gendisk *part_to_disk(struct hd_struct *part)
{
	if (likely(part)) {
		if (part->partno)
			return dev_to_disk(part_to_dev(part)->parent);
		else
			return dev_to_disk(part_to_dev(part));
	}
	return NULL;
}

#define dev_to_disk(device)	container_of((device), struct gendisk, part0.__dev)
#define part_to_dev(part)	(&((part)->__dev))
```

## 4. register_disk
```c
static void register_disk(struct device *parent, struct gendisk *disk,
			  const struct attribute_group **groups)
{
	struct device *ddev = disk_to_dev(disk);
	struct disk_part_iter piter;
	struct hd_struct *part;
	int err;

	// 父结点
	ddev->parent = parent;

	// 设备名
	dev_set_name(ddev, "%s", disk->disk_name);

	// uevent压制
	dev_set_uevent_suppress(ddev, 1);

	// 有group则设之
	if (groups) {
		WARN_ON(ddev->groups);
		ddev->groups = groups;
	}
	// 添加到设备模型
	if (device_add(ddev))
		return;
	
	// sysfs没有屏蔽, 则创建链接
	if (!sysfs_deprecated) {
		err = sysfs_create_link(block_depr, &ddev->kobj,
					kobject_name(&ddev->kobj));
		if (err) {
			device_del(ddev);
			return;
		}
	}

	// 电源管理相关
	pm_runtime_set_memalloc_noio(ddev, true);

	// 创建holders和slave对象
	disk->part0.holder_dir = kobject_create_and_add("holders", &ddev->kobj);
	disk->slave_dir = kobject_create_and_add("slaves", &ddev->kobj);

	// 不在用户层显示
	if (disk->flags & GENHD_FL_HIDDEN)
		return;

	// 扫描分区
	disk_scan_partitions(disk);

	// 取消uevent禁用
	dev_set_uevent_suppress(ddev, 0);
	// 发送add uevent事件
	kobject_uevent(&ddev->kobj, KOBJ_ADD);

	// 遍历分区, 发送分区的uevent事件
	disk_part_iter_init(&piter, disk, 0);
	while ((part = disk_part_iter_next(&piter)))
		kobject_uevent(&part_to_dev(part)->kobj, KOBJ_ADD);
	disk_part_iter_exit(&piter);

	// 创建bdi sys
	if (disk->queue->backing_dev_info->dev) {
		err = sysfs_create_link(&ddev->kobj,
			  &disk->queue->backing_dev_info->dev->kobj,
			  "bdi");
		WARN_ON(err);
	}
}


static void disk_scan_partitions(struct gendisk *disk)
{
	struct block_device *bdev;

	// 容量为0 || 没使能扫描, 则返回
	if (!get_capacity(disk) || !disk_part_scan_enabled(disk))
		return;

	// 设置需要扫描
	set_bit(GD_NEED_PART_SCAN, &disk->state);
	// 打开设备, 在打开的过程中会扫描?
	bdev = blkdev_get_by_dev(disk_devt(disk), FMODE_READ, NULL);
	if (!IS_ERR(bdev))
		blkdev_put(bdev, FMODE_READ);
}

static inline sector_t get_capacity(struct gendisk *disk)
{
	// part0的扇区数
	return disk->part0.nr_sects;
}

static inline bool disk_part_scan_enabled(struct gendisk *disk)
{
	// 支持多个设备 && 没有禁用分区扫描
	return disk_max_parts(disk) > 1 &&
		!(disk->flags & GENHD_FL_NO_PART_SCAN);
}

tatic inline int disk_max_parts(struct gendisk *disk)
{
	// DISK_MAX_PARTS=256, 设备支持动态扩展dev_t
	if (disk->flags & GENHD_FL_EXT_DEVT)
		return DISK_MAX_PARTS;
	// 次设备号数量
	return disk->minors;
}
```

## blkdev_get_by_dev
```c
struct block_device *blkdev_get_by_dev(dev_t dev, fmode_t mode, void *holder)
{
	struct block_device *bdev;
	int err;

	// 分配inode, 获取bdev
	bdev = bdget(dev);
	if (!bdev)
		return ERR_PTR(-ENOMEM);

	// 打开设备
	err = blkdev_get(bdev, mode, holder);
	if (err)
		return ERR_PTR(err);

	return bdev;
}

static struct block_device *bdget(dev_t dev)
{
	struct block_device *bdev;
	struct inode *inode;

	// 获取一个inode
	inode = iget5_locked(blockdev_superblock, hash(dev),
			bdev_test, bdev_set, &dev);

	if (!inode)
		return NULL;

	bdev = &BDEV_I(inode)->bdev;

	// 新创建的inode
	if (inode->i_state & I_NEW) {
		spin_lock_init(&bdev->bd_size_lock);
		bdev->bd_contains = NULL;
		bdev->bd_super = NULL;
		// inode引用
		bdev->bd_inode = inode;
		bdev->bd_part_count = 0;
		// 块文件
		inode->i_mode = S_IFBLK;
		// 设备号
		inode->i_rdev = dev;
		inode->i_bdev = bdev;
		// 块设备操作
		inode->i_data.a_ops = &def_blk_aops;
		// 设置mapping->gfp_mask=GFP_USER
		mapping_set_gfp_mask(&inode->i_data, GFP_USER);
		unlock_new_inode(inode);
	}
	return bdev;
}
```