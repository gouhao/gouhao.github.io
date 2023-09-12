# 块设备与文件系统
源码基于5.10

## 与文件系统交互
```c
void init_special_inode(struct inode *inode, umode_t mode, dev_t rdev)
{
	inode->i_mode = mode;
	if (S_ISCHR(mode)) {
		inode->i_fop = &def_chr_fops;
		inode->i_rdev = rdev;
	} else if (S_ISBLK(mode)) {
		inode->i_fop = &def_blk_fops;
		inode->i_rdev = rdev;
	} else if (S_ISFIFO(mode))
		inode->i_fop = &pipefifo_fops;
	else if (S_ISSOCK(mode))
		;	/* leave it no_open_fops */
	else
		printk(KERN_DEBUG "init_special_inode: bogus i_mode (%o) for"
				  " inode %s:%lu\n", mode, inode->i_sb->s_id,
				  inode->i_ino);
}

const struct file_operations def_blk_fops = {
	.open		= blkdev_open,
	.release	= blkdev_close,
	.llseek		= block_llseek,
	.read_iter	= blkdev_read_iter,
	.write_iter	= blkdev_write_iter,
	.iopoll		= blkdev_iopoll,
	.mmap		= generic_file_mmap,
	.fsync		= blkdev_fsync,
	.unlocked_ioctl	= block_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= compat_blkdev_ioctl,
#endif
	.splice_read	= generic_file_splice_read,
	.splice_write	= iter_file_splice_write,
	.fallocate	= blkdev_fallocate,
};
```

## blkdev_open
```c
static int blkdev_open(struct inode * inode, struct file * filp)
{
	struct block_device *bdev;

	// 为了保持向后兼容，允许大文件访问，后面可能会取消这个
	filp->f_flags |= O_LARGEFILE;

	// 下面是根据标志设备mode
	filp->f_mode |= FMODE_NOWAIT | FMODE_BUF_RASYNC;

	if (filp->f_flags & O_NDELAY)
		filp->f_mode |= FMODE_NDELAY;
	if (filp->f_flags & O_EXCL)
		filp->f_mode |= FMODE_EXCL;
	if ((filp->f_flags & O_ACCMODE) == 3)
		filp->f_mode |= FMODE_WRITE_IOCTL;

	bdev = bd_acquire(inode);
	if (bdev == NULL)
		return -ENOMEM;

	filp->f_mapping = bdev->bd_inode->i_mapping;
	filp->f_wb_err = filemap_sample_wb_err(filp->f_mapping);

	return blkdev_get(bdev, filp->f_mode, filp);
}

static struct block_device *bd_acquire(struct inode *inode)
{
	struct block_device *bdev;

	spin_lock(&bdev_lock);
	bdev = inode->i_bdev;
	if (bdev && !inode_unhashed(bdev->bd_inode)) {
		bdgrab(bdev);
		spin_unlock(&bdev_lock);
		return bdev;
	}
	spin_unlock(&bdev_lock);

	/*
	 * i_bdev references block device inode that was already shut down
	 * (corresponding device got removed).  Remove the reference and look
	 * up block device inode again just in case new device got
	 * reestablished under the same device number.
	 */
	if (bdev)
		bd_forget(inode);

	bdev = bdget(inode->i_rdev);
	if (bdev) {
		spin_lock(&bdev_lock);
		if (!inode->i_bdev) {
			/*
			 * We take an additional reference to bd_inode,
			 * and it's released in clear_inode() of inode.
			 * So, we can access it via ->i_mapping always
			 * without igrab().
			 */
			bdgrab(bdev);
			inode->i_bdev = bdev;
			inode->i_mapping = bdev->bd_inode->i_mapping;
		}
		spin_unlock(&bdev_lock);
	}
	return bdev;
}

static int blkdev_get(struct block_device *bdev, fmode_t mode, void *holder)
{
	int ret, perm = 0;

	// 权限转换
	if (mode & FMODE_READ)
		perm |= MAY_READ;
	if (mode & FMODE_WRITE)
		perm |= MAY_WRITE;
	// cgroup权限检查
	ret = devcgroup_inode_permission(bdev->bd_inode, perm);
	if (ret)
		goto bdput;

	// 打开获取设备
	ret =__blkdev_get(bdev, mode, holder, 0);
	if (ret)
		goto bdput;
	return 0;

bdput:
	bdput(bdev);
	return ret;
}

static int __blkdev_get(struct block_device *bdev, fmode_t mode, void *holder,
		int for_part)
{
	struct block_device *whole = NULL, *claiming = NULL;
	struct gendisk *disk;
	int ret;
	int partno;
	bool first_open = false, unblock_events = true, need_restart;

 restart:
	need_restart = false;
	ret = -ENXIO;
	// 找到设备对应的gendisk
	disk = bdev_get_gendisk(bdev, &partno);
	if (!disk)
		goto out;

	// 如果有分区号先获取0号设备
	if (partno) {
		whole = bdget_disk(disk, 0);
		if (!whole) {
			ret = -ENOMEM;
			goto out_put_disk;
		}
	}

	if (!for_part && (mode & FMODE_EXCL)) {
		WARN_ON_ONCE(!holder);
		if (whole)
			claiming = whole;
		else
			claiming = bdev;
		ret = bd_prepare_to_claim(bdev, claiming, holder);
		if (ret)
			goto out_put_whole;
	}

	disk_block_events(disk);
	mutex_lock_nested(&bdev->bd_mutex, for_part);
	if (!bdev->bd_openers) {
		first_open = true;
		bdev->bd_disk = disk;
		bdev->bd_contains = bdev;
		bdev->bd_partno = partno;

		if (!partno) {
			ret = -ENXIO;
			bdev->bd_part = disk_get_part(disk, partno);
			if (!bdev->bd_part)
				goto out_clear;

			ret = 0;
			if (disk->fops->open) {
				ret = disk->fops->open(bdev, mode);
				/*
				 * If we lost a race with 'disk' being deleted,
				 * try again.  See md.c
				 */
				if (ret == -ERESTARTSYS)
					need_restart = true;
			}

			if (!ret) {
				bd_set_nr_sectors(bdev, get_capacity(disk));
				set_init_blocksize(bdev);
			}

			/*
			 * If the device is invalidated, rescan partition
			 * if open succeeded or failed with -ENOMEDIUM.
			 * The latter is necessary to prevent ghost
			 * partitions on a removed medium.
			 */
			if (test_bit(GD_NEED_PART_SCAN, &disk->state) &&
			    (!ret || ret == -ENOMEDIUM))
				bdev_disk_changed(bdev, ret == -ENOMEDIUM);

			if (ret)
				goto out_clear;
		} else {
			BUG_ON(for_part);
			ret = __blkdev_get(whole, mode, NULL, 1);
			if (ret)
				goto out_clear;
			bdev->bd_contains = bdgrab(whole);
			bdev->bd_part = disk_get_part(disk, partno);
			if (!(disk->flags & GENHD_FL_UP) ||
			    !bdev->bd_part || !bdev->bd_part->nr_sects) {
				ret = -ENXIO;
				goto out_clear;
			}
			bd_set_nr_sectors(bdev, bdev->bd_part->nr_sects);
			set_init_blocksize(bdev);
		}

		if (bdev->bd_bdi == &noop_backing_dev_info)
			bdev->bd_bdi = bdi_get(disk->queue->backing_dev_info);
	} else {
		if (bdev->bd_contains == bdev) {
			ret = 0;
			if (bdev->bd_disk->fops->open)
				ret = bdev->bd_disk->fops->open(bdev, mode);
			/* the same as first opener case, read comment there */
			if (test_bit(GD_NEED_PART_SCAN, &disk->state) &&
			    (!ret || ret == -ENOMEDIUM))
				bdev_disk_changed(bdev, ret == -ENOMEDIUM);
			if (ret)
				goto out_unlock_bdev;
		}
	}
	bdev->bd_openers++;
	if (for_part)
		bdev->bd_part_count++;
	if (claiming)
		bd_finish_claiming(bdev, claiming, holder);

	/*
	 * Block event polling for write claims if requested.  Any write holder
	 * makes the write_holder state stick until all are released.  This is
	 * good enough and tracking individual writeable reference is too
	 * fragile given the way @mode is used in blkdev_get/put().
	 */
	if (claiming && (mode & FMODE_WRITE) && !bdev->bd_write_holder &&
	    (disk->flags & GENHD_FL_BLOCK_EVENTS_ON_EXCL_WRITE)) {
		bdev->bd_write_holder = true;
		unblock_events = false;
	}
	mutex_unlock(&bdev->bd_mutex);

	if (unblock_events)
		disk_unblock_events(disk);

	/* only one opener holds refs to the module and disk */
	if (!first_open)
		put_disk_and_module(disk);
	if (whole)
		bdput(whole);
	return 0;

 out_clear:
	disk_put_part(bdev->bd_part);
	bdev->bd_disk = NULL;
	bdev->bd_part = NULL;
	if (bdev != bdev->bd_contains)
		__blkdev_put(bdev->bd_contains, mode, 1);
	bdev->bd_contains = NULL;
 out_unlock_bdev:
	if (claiming)
		bd_abort_claiming(bdev, claiming, holder);
	mutex_unlock(&bdev->bd_mutex);
	disk_unblock_events(disk);
 out_put_whole:
 	if (whole)
		bdput(whole);
 out_put_disk:
	put_disk_and_module(disk);
	if (need_restart)
		goto restart;
 out:
	return ret;
}
```