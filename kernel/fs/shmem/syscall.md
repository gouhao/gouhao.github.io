## shmget
```c
SYSCALL_DEFINE3(shmget, key_t, key, size_t, size, int, shmflg)
{
	return ksys_shmget(key, size, shmflg);
}

long ksys_shmget(key_t key, size_t size, int shmflg)
{
	struct ipc_namespace *ns;
	static const struct ipc_ops shm_ops = {
		.getnew = newseg,
		.associate = security_shm_associate,
		.more_checks = shm_more_checks,
	};
	struct ipc_params shm_params;

	ns = current->nsproxy->ipc_ns;

	shm_params.key = key;
	shm_params.flg = shmflg;
	shm_params.u.size = size;

	return ipcget(ns, &shm_ids(ns), &shm_ops, &shm_params);
}

int ipcget(struct ipc_namespace *ns, struct ipc_ids *ids,
			const struct ipc_ops *ops, struct ipc_params *params)
{
	if (params->key == IPC_PRIVATE)
		return ipcget_new(ns, ids, ops, params);
	else
		return ipcget_public(ns, ids, ops, params);
}

static int ipcget_public(struct ipc_namespace *ns, struct ipc_ids *ids,
		const struct ipc_ops *ops, struct ipc_params *params)
{
	struct kern_ipc_perm *ipcp;
	int flg = params->flg;
	int err;

	/*
	 * Take the lock as a writer since we are potentially going to add
	 * a new entry + read locks are not "upgradable"
	 */
	down_write(&ids->rwsem);
	// 找key
	ipcp = ipc_findkey(ids, params->key);
	if (ipcp == NULL) {
		// 没找到

		// 如果不需要创建直接返回 NULL
		if (!(flg & IPC_CREAT))
			err = -ENOENT;
		else
			// 否则创建一个
			err = ops->getnew(ns, params);
	} else {
		/* ipc object has been locked by ipc_findkey() */

		if (flg & IPC_CREAT && flg & IPC_EXCL)
			// 已存在
			err = -EEXIST;
		else {
			err = 0;

			// 检查参数
			if (ops->more_checks)
				err = ops->more_checks(ipcp, params);
			if (!err)
				/*
				 * ipc_check_perms returns the IPC id on
				 * success
				 */
				err = ipc_check_perms(ns, ipcp, ops, params);
		}
		ipc_unlock(ipcp);
	}
	up_write(&ids->rwsem);

	return err;
}
```

## newseg
```c
static int newseg(struct ipc_namespace *ns, struct ipc_params *params)
{
	key_t key = params->key;
	int shmflg = params->flg;
	size_t size = params->u.size;
	int error;
	struct shmid_kernel *shp;
	// 把size换算成页数
	size_t numpages = (size + PAGE_SIZE - 1) >> PAGE_SHIFT;
	struct file *file;
	char name[13];
	vm_flags_t acctflag = 0;

	// size边界, SHMMIN是1
	if (size < SHMMIN || size > ns->shm_ctlmax)
		return -EINVAL;

	// 这个检查是不是没用？这里应该恒为false?
	if (numpages << PAGE_SHIFT < size)
		return -ENOSPC;

	// 检查numpages的边界：不能为负数，也不能超过最大值
	if (ns->shm_tot + numpages < ns->shm_tot ||
			ns->shm_tot + numpages > ns->shm_ctlall)
		return -ENOSPC;

	// kvmalloc是先用kmalloc，如果失败则用vmalloc
	shp = kvmalloc(sizeof(*shp), GFP_KERNEL);
	if (unlikely(!shp))
		return -ENOMEM;

	// 设置基本信息
	shp->shm_perm.key = key;
	shp->shm_perm.mode = (shmflg & S_IRWXUGO);
	shp->mlock_user = NULL;

	shp->shm_perm.security = NULL;
	// 安全hook
	error = security_shm_alloc(&shp->shm_perm);
	if (error) {
		kvfree(shp);
		return error;
	}

	// shmem的名字
	sprintf(name, "SYSV%08x", key);
	if (shmflg & SHM_HUGETLB) {
		// 映射到大页？
		struct hstate *hs;
		size_t hugesize;

		hs = hstate_sizelog((shmflg >> SHM_HUGE_SHIFT) & SHM_HUGE_MASK);
		if (!hs) {
			error = -EINVAL;
			goto no_file;
		}
		hugesize = ALIGN(size, huge_page_size(hs));

		/* hugetlb_file_setup applies strict accounting */
		if (shmflg & SHM_NORESERVE)
			acctflag = VM_NORESERVE;
		file = hugetlb_file_setup(name, hugesize, acctflag,
				  &shp->mlock_user, HUGETLB_SHMFS_INODE,
				(shmflg >> SHM_HUGE_SHIFT) & SHM_HUGE_MASK);
	} else {
		// 普通情况
		
		if  ((shmflg & SHM_NORESERVE) &&
				sysctl_overcommit_memory != OVERCOMMIT_NEVER)
			acctflag = VM_NORESERVE;
		file = shmem_kernel_file_setup(name, size, acctflag);
	}
	error = PTR_ERR(file);
	if (IS_ERR(file))
		goto no_file;

	// 设置基本信息
	shp->shm_cprid = get_pid(task_tgid(current));
	shp->shm_lprid = NULL;
	shp->shm_atim = shp->shm_dtim = 0;
	shp->shm_ctim = ktime_get_real_seconds();
	shp->shm_segsz = size;
	shp->shm_nattch = 0;
	shp->shm_file = file;
	shp->shm_creator = current;

	// 把shp加到ids里
	error = ipc_addid(&shm_ids(ns), &shp->shm_perm, ns->shm_ctlmni);
	if (error < 0)
		goto no_id;

	shp->ns = ns;

	task_lock(current);
	// 加到进程的shm_clist里
	list_add(&shp->shm_clist, &current->sysvshm.shm_clist);
	task_unlock(current);

	//文件inode号
	file_inode(file)->i_ino = shp->shm_perm.id;

	// 总共的页
	ns->shm_tot += numpages;

	// 返回的是文件的inode号
	error = shp->shm_perm.id;

	ipc_unlock_object(&shp->shm_perm);
	rcu_read_unlock();
	return error;

no_id:
	ipc_update_pid(&shp->shm_cprid, NULL);
	ipc_update_pid(&shp->shm_lprid, NULL);
	if (is_file_hugepages(file) && shp->mlock_user)
		user_shm_unlock(size, shp->mlock_user);
	fput(file);
	ipc_rcu_putref(&shp->shm_perm, shm_rcu_free);
	return error;
no_file:
	call_rcu(&shp->shm_perm.rcu, shm_rcu_free);
	return error;
}

struct file *shmem_kernel_file_setup(const char *name, loff_t size, unsigned long flags)
{
	return __shmem_file_setup(shm_mnt, name, size, flags, S_PRIVATE);
}

static struct file *__shmem_file_setup(struct vfsmount *mnt, const char *name, loff_t size,
				       unsigned long flags, unsigned int i_flags)
{
	struct inode *inode;
	struct file *res;

	if (IS_ERR(mnt))
		return ERR_CAST(mnt);

	if (size < 0 || size > MAX_LFS_FILESIZE)
		return ERR_PTR(-EINVAL);

	// 检查统计相关
	if (shmem_acct_size(flags, size))
		return ERR_PTR(-ENOMEM);

	// 调用tmpfs文件系统生成一个inode
	inode = shmem_get_inode(mnt->mnt_sb, NULL, S_IFREG | S_IRWXUGO, 0,
				flags);
	if (unlikely(!inode)) {
		shmem_unacct_size(flags, size);
		return ERR_PTR(-ENOSPC);
	}
	// 设置inode的大小
	inode->i_flags |= i_flags;
	inode->i_size = size;
	clear_nlink(inode);	/* It is unlinked */
	// 处理nommu的情况，这个架构比较少，直接返回0
	res = ERR_PTR(ramfs_nommu_expand_for_mapping(inode, size));
	if (!IS_ERR(res))
		// 分配一个文件
		res = alloc_file_pseudo(inode, mnt, name, O_RDWR,
				&shmem_file_operations);
	if (IS_ERR(res))
		iput(inode);
	return res;
}
```

## check
```c
static int shm_more_checks(struct kern_ipc_perm *ipcp, struct ipc_params *params)
{
	struct shmid_kernel *shp;

	shp = container_of(ipcp, struct shmid_kernel, shm_perm);
	// 请求的大小不能超过创建时的大小
	if (shp->shm_segsz < params->u.size)
		return -EINVAL;

	return 0;
}

static int ipc_check_perms(struct ipc_namespace *ns,
			   struct kern_ipc_perm *ipcp,
			   const struct ipc_ops *ops,
			   struct ipc_params *params)
{
	int err;
	// 检查uid, gid, security等权限
	if (ipcperms(ns, ipcp, params->flg))
		err = -EACCES;
	else {
		// 这个是直接调安全接口
		err = ops->associate(ipcp, params->flg);
		if (!err)
			err = ipcp->id;
	}

	return err;
}
```

## shmat
```c
SYSCALL_DEFINE3(shmat, int, shmid, char __user *, shmaddr, int, shmflg)
{
	unsigned long ret;
	long err;

	err = do_shmat(shmid, shmaddr, shmflg, &ret, SHMLBA);
	if (err)
		return err;
	force_successful_syscall_return();
	return (long)ret;
}

long do_shmat(int shmid, char __user *shmaddr, int shmflg,
	      ulong *raddr, unsigned long shmlba)
{
	struct shmid_kernel *shp;
	unsigned long addr = (unsigned long)shmaddr;
	unsigned long size;
	struct file *file, *base;
	int    err;
	unsigned long flags = MAP_SHARED;
	unsigned long prot;
	int acc_mode;
	struct ipc_namespace *ns;
	struct shm_file_data *sfd;
	int f_flags;
	unsigned long populate = 0;

	err = -EINVAL;
	if (shmid < 0)
		goto out;

	// 下面是对各种flag的处理
	if (addr) {
		// 要求固定地址
		if (addr & (shmlba - 1)) {
			if (shmflg & SHM_RND) {
				addr &= ~(shmlba - 1);  /* round down */

				/*
				 * Ensure that the round-down is non-nil
				 * when remapping. This can happen for
				 * cases when addr < shmlba.
				 */
				if (!addr && (shmflg & SHM_REMAP))
					goto out;
			} else
#ifndef __ARCH_FORCE_SHMLBA
				if (addr & ~PAGE_MASK)
#endif
					goto out;
		}

		flags |= MAP_FIXED;
	} else if ((shmflg & SHM_REMAP))
		goto out;

	if (shmflg & SHM_RDONLY) {
		// 只读
		prot = PROT_READ;
		acc_mode = S_IRUGO;
		f_flags = O_RDONLY;
	} else {
		// 读写
		prot = PROT_READ | PROT_WRITE;
		acc_mode = S_IRUGO | S_IWUGO;
		f_flags = O_RDWR;
	}
	if (shmflg & SHM_EXEC) {
		// 可执行
		prot |= PROT_EXEC;
		acc_mode |= S_IXUGO;
	}

	ns = current->nsproxy->ipc_ns;
	rcu_read_lock();

	// 根据id找到对应的实例
	shp = shm_obtain_object_check(ns, shmid);
	if (IS_ERR(shp)) {
		err = PTR_ERR(shp);
		goto out_unlock;
	}

	err = -EACCES;
	// 权限检查
	if (ipcperms(ns, &shp->shm_perm, acc_mode))
		goto out_unlock;

	// 安全回调
	err = security_shm_shmat(&shp->shm_perm, shmaddr, shmflg);
	if (err)
		goto out_unlock;

	ipc_lock_object(&shp->shm_perm);

	/* check if shm_destroy() is tearing down shp */
	if (!ipc_valid_object(&shp->shm_perm)) {
		ipc_unlock_object(&shp->shm_perm);
		err = -EIDRM;
		goto out_unlock;
	}

	// 增加文件引用
	base = get_file(shp->shm_file);
	shp->shm_nattch++;
	// 文件最大值，shm的最大值
	size = i_size_read(file_inode(base));
	ipc_unlock_object(&shp->shm_perm);
	rcu_read_unlock();

	err = -ENOMEM;
	// 分配data对象
	sfd = kzalloc(sizeof(*sfd), GFP_KERNEL);
	if (!sfd) {
		fput(base);
		goto out_nattch;
	}

	// 复制一个文件
	file = alloc_file_clone(base, f_flags,
			  is_file_hugepages(base) ?
				&shm_file_operations_huge :
				&shm_file_operations);
	err = PTR_ERR(file);
	if (IS_ERR(file)) {
		kfree(sfd);
		fput(base);
		goto out_nattch;
	}

	sfd->id = shp->shm_perm.id;
	sfd->ns = get_ipc_ns(ns);
	sfd->file = base;
	sfd->vm_ops = NULL;
	// 设置文件私有数据
	file->private_data = sfd;

	// 映射的安全hook
	err = security_mmap_file(file, prot, flags);
	if (err)
		goto out_fput;

	if (mmap_write_lock_killable(current->mm)) {
		err = -EINTR;
		goto out_fput;
	}

	// 如果是固定映射，要检查是否有重叠
	if (addr && !(shmflg & SHM_REMAP)) {
		err = -EINVAL;
		if (addr + size < addr)
			goto invalid;

		if (find_vma_intersection(current->mm, addr, addr + size))
			goto invalid;
	}

	// 映射，返回的是映射成功的地址
	addr = do_mmap(file, addr, size, prot, flags, 0, &populate, NULL);
	*raddr = addr;
	err = 0;
	if (IS_ERR_VALUE(addr))
		err = (long)addr;
invalid:
	mmap_write_unlock(current->mm);
	if (populate)
		mm_populate(addr, populate);

out_fput:
	fput(file);

out_nattch:
	down_write(&shm_ids(ns).rwsem);
	shp = shm_lock(ns, shmid);
	shp->shm_nattch--;

	if (shm_may_destroy(shp))
		shm_destroy(ns, shp);
	else
		shm_unlock(shp);
	up_write(&shm_ids(ns).rwsem);
	return err;

out_unlock:
	rcu_read_unlock();
out:
	return err;
}

unsigned long shmem_get_unmapped_area(struct file *file,
				      unsigned long uaddr, unsigned long len,
				      unsigned long pgoff, unsigned long flags)
{
	unsigned long (*get_area)(struct file *,
		unsigned long, unsigned long, unsigned long, unsigned long);
	unsigned long addr;
	unsigned long offset;
	unsigned long inflated_len;
	unsigned long inflated_addr;
	unsigned long inflated_offset;

	if (len > TASK_SIZE)
		return -ENOMEM;

	get_area = current->mm->get_unmapped_area;
	// 调用进程的函数
	addr = get_area(file, uaddr, len, pgoff, flags);

	// 没有开启大页，直接返回
	if (!IS_ENABLED(CONFIG_TRANSPARENT_HUGEPAGE))
		return addr;
	
	// 下面都是对大页的处理
	if (IS_ERR_VALUE(addr))
		return addr;
	if (addr & ~PAGE_MASK)
		return addr;
	// 地址到了内核的地址
	if (addr > TASK_SIZE - len)
		return addr;

	// 禁用大页
	if (shmem_huge == SHMEM_HUGE_DENY)
		return addr;
	// 小于大页的长度
	if (len < HPAGE_PMD_SIZE)
		return addr;
	// 固定映射
	if (flags & MAP_FIXED)
		return addr;
	// todo: what?
	if (uaddr == addr)
		return addr;

	if (shmem_huge != SHMEM_HUGE_FORCE) {
		struct super_block *sb;

		if (file) {
			VM_BUG_ON(file->f_op != &shmem_file_operations);
			sb = file_inode(file)->i_sb;
		} else {
			/*
			 * Called directly from mm/mmap.c, or drivers/char/mem.c
			 * for "/dev/zero", to create a shared anonymous object.
			 */
			if (IS_ERR(shm_mnt))
				return addr;
			sb = shm_mnt->mnt_sb;
		}
		if (SHMEM_SB(sb)->huge == SHMEM_HUGE_NEVER)
			return addr;
	}

	offset = (pgoff << PAGE_SHIFT) & (HPAGE_PMD_SIZE-1);
	if (offset && offset + len < 2 * HPAGE_PMD_SIZE)
		return addr;
	if ((addr & (HPAGE_PMD_SIZE-1)) == offset)
		return addr;

	inflated_len = len + HPAGE_PMD_SIZE - PAGE_SIZE;
	if (inflated_len > TASK_SIZE)
		return addr;
	if (inflated_len < len)
		return addr;

	inflated_addr = get_area(NULL, uaddr, inflated_len, 0, flags);
	if (IS_ERR_VALUE(inflated_addr))
		return addr;
	if (inflated_addr & ~PAGE_MASK)
		return addr;

	inflated_offset = inflated_addr & (HPAGE_PMD_SIZE-1);
	inflated_addr += offset - inflated_offset;
	if (inflated_offset > offset)
		inflated_addr += HPAGE_PMD_SIZE;

	if (inflated_addr > TASK_SIZE - len)
		return addr;
	return inflated_addr;
}

static int shmem_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct shmem_inode_info *info = SHMEM_I(file_inode(file));
	int ret;

	// 权限检查
	ret = seal_check_future_write(info->seals, vma);
	if (ret)
		return ret;

	/* arm64 - allow memory tagging on RAM-based files */
	vma->vm_flags |= VM_MTE_ALLOWED;

	// 修改访问时间
	file_accessed(file);
	vma->vm_ops = &shmem_vm_ops;
	if (IS_ENABLED(CONFIG_TRANSPARENT_HUGEPAGE) &&
			((vma->vm_start + ~HPAGE_PMD_MASK) & HPAGE_PMD_MASK) <
			(vma->vm_end & HPAGE_PMD_MASK)) {
		khugepaged_enter(vma, vma->vm_flags);
	}
	return 0;
}

static const struct vm_operations_struct shmem_vm_ops = {
	.fault		= shmem_fault,
	.map_pages	= filemap_map_pages,
#ifdef CONFIG_NUMA
	.set_policy     = shmem_set_policy,
	.get_policy     = shmem_get_policy,
#endif
};

static vm_fault_t shmem_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct inode *inode = file_inode(vma->vm_file);
	gfp_t gfp = mapping_gfp_mask(inode->i_mapping);
	enum sgp_type sgp;
	int err;
	vm_fault_t ret = VM_FAULT_LOCKED;

	/*
	 * Trinity finds that probing a hole which tmpfs is punching can
	 * prevent the hole-punch from ever completing: which in turn
	 * locks writers out with its hold on i_mutex.  So refrain from
	 * faulting pages into the hole while it's being punched.  Although
	 * shmem_undo_range() does remove the additions, it may be unable to
	 * keep up, as each new page needs its own unmap_mapping_range() call,
	 * and the i_mmap tree grows ever slower to scan if new vmas are added.
	 *
	 * It does not matter if we sometimes reach this check just before the
	 * hole-punch begins, so that one fault then races with the punch:
	 * we just need to make racing faults a rare case.
	 *
	 * The implementation below would be much simpler if we just used a
	 * standard mutex or completion: but we cannot take i_mutex in fault,
	 * and bloating every shmem inode for this unlikely case would be sad.
	 */
	if (unlikely(inode->i_private)) {
		struct shmem_falloc *shmem_falloc;

		spin_lock(&inode->i_lock);
		shmem_falloc = inode->i_private;
		if (shmem_falloc &&
		    shmem_falloc->waitq &&
		    vmf->pgoff >= shmem_falloc->start &&
		    vmf->pgoff < shmem_falloc->next) {
			struct file *fpin;
			wait_queue_head_t *shmem_falloc_waitq;
			DEFINE_WAIT_FUNC(shmem_fault_wait, synchronous_wake_function);

			ret = VM_FAULT_NOPAGE;
			fpin = maybe_unlock_mmap_for_io(vmf, NULL);
			if (fpin)
				ret = VM_FAULT_RETRY;

			shmem_falloc_waitq = shmem_falloc->waitq;
			prepare_to_wait(shmem_falloc_waitq, &shmem_fault_wait,
					TASK_UNINTERRUPTIBLE);
			spin_unlock(&inode->i_lock);
			schedule();

			/*
			 * shmem_falloc_waitq points into the shmem_fallocate()
			 * stack of the hole-punching task: shmem_falloc_waitq
			 * is usually invalid by the time we reach here, but
			 * finish_wait() does not dereference it in that case;
			 * though i_lock needed lest racing with wake_up_all().
			 */
			spin_lock(&inode->i_lock);
			finish_wait(shmem_falloc_waitq, &shmem_fault_wait);
			spin_unlock(&inode->i_lock);

			if (fpin)
				fput(fpin);
			return ret;
		}
		spin_unlock(&inode->i_lock);
	}

	sgp = SGP_CACHE;

	// 大页标志判断
	if ((vma->vm_flags & VM_NOHUGEPAGE) ||
	    test_bit(MMF_DISABLE_THP, &vma->vm_mm->flags))
		sgp = SGP_NOHUGE;
	else if (vma->vm_flags & VM_HUGEPAGE)
		sgp = SGP_HUGE;

	err = shmem_getpage_gfp(inode, vmf->pgoff, &vmf->page, sgp,
				  gfp, vma, vmf, &ret);
	if (err)
		return vmf_error(err);
	return ret;
}

static int shmem_getpage_gfp(struct inode *inode, pgoff_t index,
	struct page **pagep, enum sgp_type sgp, gfp_t gfp,
	struct vm_area_struct *vma, struct vm_fault *vmf,
			vm_fault_t *fault_type)
{
	struct address_space *mapping = inode->i_mapping;
	struct shmem_inode_info *info = SHMEM_I(inode);
	struct shmem_sb_info *sbinfo;
	struct mm_struct *charge_mm;
	struct page *page;
	enum sgp_type sgp_huge = sgp;
	pgoff_t hindex = index;
	int error;
	int once = 0;
	int alloced = 0;

	if (index > (MAX_LFS_FILESIZE >> PAGE_SHIFT))
		return -EFBIG;
	if (sgp == SGP_NOHUGE || sgp == SGP_HUGE)
		sgp = SGP_CACHE;
repeat:
	if (sgp <= SGP_CACHE &&
	    ((loff_t)index << PAGE_SHIFT) >= i_size_read(inode)) {
		return -EINVAL;
	}

	sbinfo = SHMEM_SB(inode->i_sb);
	charge_mm = vma ? vma->vm_mm : current->mm;

	// 找页缓存
	page = find_lock_entry(mapping, index);
	if (xa_is_value(page)) {
		// 页被换出到交换设备

		// 换入操作
		error = shmem_swapin_page(inode, index, &page,
					  sgp, gfp, vma, fault_type);
		if (error == -EEXIST)
			goto repeat;

		*pagep = page;
		return error;
	}

	if (page)
		hindex = page->index;

	// 标志页访问
	if (page && sgp == SGP_WRITE)
		mark_page_accessed(page);

	/* fallocated page? */
	if (page && !PageUptodate(page)) {
		if (sgp != SGP_READ)
			goto clear;
		unlock_page(page);
		put_page(page);
		page = NULL;
		hindex = index;
	}

	// page已找到就直接退出
	if (page || sgp == SGP_READ)
		goto out;

	/*
	 * Fast cache lookup did not find it:
	 * bring it back from swap or allocate.
	 */

	if (vma && userfaultfd_missing(vma)) {
		*fault_type = handle_userfault(vmf, VM_UFFD_MISSING);
		return 0;
	}

	/* shmem_symlink() */
	if (mapping->a_ops != &shmem_aops)
		goto alloc_nohuge;
	if (shmem_huge == SHMEM_HUGE_DENY || sgp_huge == SGP_NOHUGE)
		goto alloc_nohuge;
	if (shmem_huge == SHMEM_HUGE_FORCE)
		goto alloc_huge;
	switch (sbinfo->huge) {
	case SHMEM_HUGE_NEVER:
		goto alloc_nohuge;
	case SHMEM_HUGE_WITHIN_SIZE: {
		loff_t i_size;
		pgoff_t off;

		off = round_up(index, HPAGE_PMD_NR);
		i_size = round_up(i_size_read(inode), PAGE_SIZE);
		if (i_size >= HPAGE_PMD_SIZE &&
		    i_size >> PAGE_SHIFT >= off)
			goto alloc_huge;

		fallthrough;
	}
	case SHMEM_HUGE_ADVISE:
		if (sgp_huge == SGP_HUGE)
			goto alloc_huge;
		/* TODO: implement fadvise() hints */
		goto alloc_nohuge;
	}

	// 分配大页/普通页
alloc_huge:
	page = shmem_alloc_and_acct_page(gfp, inode, index, true);
	if (IS_ERR(page)) {
alloc_nohuge:
		page = shmem_alloc_and_acct_page(gfp, inode,
						 index, false);
	}
	if (IS_ERR(page)) {
		int retry = 5;

		error = PTR_ERR(page);
		page = NULL;
		if (error != -ENOSPC)
			goto unlock;
		/*
		 * Try to reclaim some space by splitting a huge page
		 * beyond i_size on the filesystem.
		 */
		while (retry--) {
			int ret;

			ret = shmem_unused_huge_shrink(sbinfo, NULL, 1);
			if (ret == SHRINK_STOP)
				break;
			if (ret)
				goto alloc_nohuge;
		}
		goto unlock;
	}

	if (PageTransHuge(page))
		hindex = round_down(index, HPAGE_PMD_NR);
	else
		hindex = index;

	if (sgp == SGP_WRITE)
		__SetPageReferenced(page);

	// 加入page-cache
	error = shmem_add_to_page_cache(page, mapping, hindex,
					NULL, gfp & GFP_RECLAIM_MASK,
					charge_mm);
	if (error)
		goto unacct;
	// 加入lru
	lru_cache_add(page);

	spin_lock_irq(&info->lock);
	info->alloced += compound_nr(page);
	inode->i_blocks += BLOCKS_PER_PAGE << compound_order(page);
	shmem_recalc_inode(inode);
	spin_unlock_irq(&info->lock);
	alloced = true;

	if (PageTransHuge(page) &&
	    DIV_ROUND_UP(i_size_read(inode), PAGE_SIZE) <
			hindex + HPAGE_PMD_NR - 1) {
		/*
		 * Part of the huge page is beyond i_size: subject
		 * to shrink under memory pressure.
		 */
		spin_lock(&sbinfo->shrinklist_lock);
		/*
		 * _careful to defend against unlocked access to
		 * ->shrink_list in shmem_unused_huge_shrink()
		 */
		if (list_empty_careful(&info->shrinklist)) {
			list_add_tail(&info->shrinklist,
				      &sbinfo->shrinklist);
			sbinfo->shrinklist_len++;
		}
		spin_unlock(&sbinfo->shrinklist_lock);
	}

	/*
	 * Let SGP_FALLOC use the SGP_WRITE optimization on a new page.
	 */
	if (sgp == SGP_FALLOC)
		sgp = SGP_WRITE;
clear:
	/*
	 * Let SGP_WRITE caller clear ends if write does not fill page;
	 * but SGP_FALLOC on a page fallocated earlier must initialize
	 * it now, lest undo on failure cancel our earlier guarantee.
	 */
	if (sgp != SGP_WRITE && !PageUptodate(page)) {
		int i;

		for (i = 0; i < compound_nr(page); i++) {
			clear_highpage(page + i);
			flush_dcache_page(page + i);
		}
		SetPageUptodate(page);
	}

	/* Perhaps the file has been truncated since we checked */
	if (sgp <= SGP_CACHE &&
	    ((loff_t)index << PAGE_SHIFT) >= i_size_read(inode)) {
		if (alloced) {
			ClearPageDirty(page);
			delete_from_page_cache(page);
			spin_lock_irq(&info->lock);
			shmem_recalc_inode(inode);
			spin_unlock_irq(&info->lock);
		}
		error = -EINVAL;
		goto unlock;
	}
out:
	*pagep = page + index - hindex;
	return 0;

	/*
	 * Error recovery.
	 */
unacct:
	shmem_inode_unacct_blocks(inode, compound_nr(page));

	if (PageTransHuge(page)) {
		unlock_page(page);
		put_page(page);
		goto alloc_nohuge;
	}
unlock:
	if (page) {
		unlock_page(page);
		put_page(page);
	}
	if (error == -ENOSPC && !once++) {
		spin_lock_irq(&info->lock);
		shmem_recalc_inode(inode);
		spin_unlock_irq(&info->lock);
		goto repeat;
	}
	if (error == -EEXIST)
		goto repeat;
	return error;
}
```