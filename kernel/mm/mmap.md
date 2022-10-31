# mmap相关

```c
SYSCALL_DEFINE5(mremap, unsigned long, addr, unsigned long, old_len,
		unsigned long, new_len, unsigned long, flags,
		unsigned long, new_addr)
{
    // 当前进程内存空间
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	unsigned long ret = -EINVAL;
	unsigned long charged = 0;
	bool locked = false;
	bool downgraded = false;
	struct vm_userfaultfd_ctx uf = NULL_VM_UFFD_CTX;
	LIST_HEAD(uf_unmap_early);
	LIST_HEAD(uf_unmap);

	
	addr = untagged_addr(addr);

    // 必须要有这三个标志中的一个
	if (flags & ~(MREMAP_FIXED | MREMAP_MAYMOVE | MREMAP_DONTUNMAP))
		return ret;

    // 如果是固定地址，则必须有MREMAP_MAYMOVE标志
	if (flags & MREMAP_FIXED && !(flags & MREMAP_MAYMOVE))
		return ret;

     // MREMAP_DONTUNMAP必须要有MREMAP_MAYMOVE标志，而且新旧长度不能相同
	if (flags & MREMAP_DONTUNMAP &&
			(!(flags & MREMAP_MAYMOVE) || old_len != new_len))
		return ret;

    // 检查地址是不是页对齐的
	if (offset_in_page(addr))
		return ret;

	old_len = PAGE_ALIGN(old_len);
	new_len = PAGE_ALIGN(new_len);

    // 允许老的长度为0,不允许新长度为0
	if (!new_len)
		return ret;

	if (mmap_write_lock_killable(current->mm))
		return -EINTR;

	if (flags & (MREMAP_FIXED | MREMAP_DONTUNMAP)) {
        // 如果是固定地址或者不允许unmap
		ret = mremap_to(addr, old_len, new_addr, new_len,
				&locked, flags, &uf, &uf_unmap_early,
				&uf_unmap);
		goto out;
	}

	/*
	 * Always allow a shrinking remap: that just unmaps
	 * the unnecessary pages..
	 * __do_munmap does all the needed commit accounting, and
	 * downgrades mmap_lock to read if so directed.
	 */
	if (old_len >= new_len) {
		int retval;

		retval = __do_munmap(mm, addr+new_len, old_len - new_len,
				  &uf_unmap, true);
		if (retval < 0 && old_len != new_len) {
			ret = retval;
			goto out;
		/* Returning 1 indicates mmap_lock is downgraded to read. */
		} else if (retval == 1)
			downgraded = true;
		ret = addr;
		goto out;
	}

	/*
	 * Ok, we need to grow..
	 */
	vma = vma_to_resize(addr, old_len, new_len, flags, &charged);
	if (IS_ERR(vma)) {
		ret = PTR_ERR(vma);
		goto out;
	}

	/* old_len exactly to the end of the area..
	 */
	if (old_len == vma->vm_end - addr) {
		/* can we just expand the current mapping? */
		if (vma_expandable(vma, new_len - old_len)) {
			int pages = (new_len - old_len) >> PAGE_SHIFT;

			if (vma_adjust(vma, vma->vm_start, addr + new_len,
				       vma->vm_pgoff, NULL)) {
				ret = -ENOMEM;
				goto out;
			}

			vm_stat_account(mm, vma->vm_flags, pages);
			if (vma->vm_flags & VM_LOCKED) {
				mm->locked_vm += pages;
				locked = true;
				new_addr = addr;
			}
			ret = addr;
			goto out;
		}
	}

	/*
	 * We weren't able to just expand or shrink the area,
	 * we need to create a new one and move it..
	 */
	ret = -ENOMEM;
	if (flags & MREMAP_MAYMOVE) {
		unsigned long map_flags = 0;
		if (vma->vm_flags & VM_MAYSHARE)
			map_flags |= MAP_SHARED;

		new_addr = get_unmapped_area(vma->vm_file, 0, new_len,
					vma->vm_pgoff +
					((addr - vma->vm_start) >> PAGE_SHIFT),
					map_flags);
		if (IS_ERR_VALUE(new_addr)) {
			ret = new_addr;
			goto out;
		}

		ret = move_vma(vma, addr, old_len, new_len, new_addr,
			       &locked, flags, &uf, &uf_unmap);
	}
out:
	if (offset_in_page(ret)) {
		vm_unacct_memory(charged);
		locked = false;
	}
	if (downgraded)
		mmap_read_unlock(current->mm);
	else
		mmap_write_unlock(current->mm);
	if (locked && new_len > old_len)
		mm_populate(new_addr + old_len, new_len - old_len);
	userfaultfd_unmap_complete(mm, &uf_unmap_early);
	mremap_userfaultfd_complete(&uf, addr, ret, old_len);
	userfaultfd_unmap_complete(mm, &uf_unmap);
	return ret;
}


static unsigned long mremap_to(unsigned long addr, unsigned long old_len,
		unsigned long new_addr, unsigned long new_len, bool *locked,
		unsigned long flags, struct vm_userfaultfd_ctx *uf,
		struct list_head *uf_unmap_early,
		struct list_head *uf_unmap)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	unsigned long ret = -EINVAL;
	unsigned long charged = 0;
	unsigned long map_flags = 0;

    // 检查新地址对齐
	if (offset_in_page(new_addr))
		goto out;

    // 新地址不能在内核地址空间
	if (new_len > TASK_SIZE || new_addr > TASK_SIZE - new_len)
		goto out;

	// 新老地址区间不能重合
	if (addr + old_len > new_addr && new_addr + new_len > addr)
		goto out;

    // 至少需要4个map
	if ((mm->map_count + 2) >= sysctl_max_map_count - 3)
		return -ENOMEM;

    // 如果是固定地址，先断开new_addr的映射
	if (flags & MREMAP_FIXED) {
		ret = do_munmap(mm, new_addr, new_len, uf_unmap_early);
		if (ret)
			goto out;
	}

    // 如果是缩小映射，则先把new_len长度的区间断开映射
	if (old_len >= new_len) {
		ret = do_munmap(mm, addr+new_len, old_len - new_len, uf_unmap);
		if (ret && old_len != new_len)
			goto out;
		old_len = new_len;
	}

    // 重新调整老的addr的vma的大小
	vma = vma_to_resize(addr, old_len, new_len, flags, &charged);
	if (IS_ERR(vma)) {
		ret = PTR_ERR(vma);
		goto out;
	}

	/* MREMAP_DONTUNMAP expands by old_len since old_len == new_len */
    // 当新老长度相等时，扩展vma区域
	if (flags & MREMAP_DONTUNMAP &&
		!may_expand_vm(mm, vma->vm_flags, old_len >> PAGE_SHIFT)) {
		ret = -ENOMEM;
		goto out;
	}

	if (flags & MREMAP_FIXED)
		map_flags |= MAP_FIXED;

	if (vma->vm_flags & VM_MAYSHARE)
		map_flags |= MAP_SHARED;

    // 获取一个没有映射的vma
	ret = get_unmapped_area(vma->vm_file, new_addr, new_len, vma->vm_pgoff +
				((addr - vma->vm_start) >> PAGE_SHIFT),
				map_flags);
	if (IS_ERR_VALUE(ret))
		goto out1;

	// 如果不是固定地址映射，则新地址就等于上面获取的vma起始地直
	if (!(flags & MREMAP_FIXED))
		new_addr = ret;

    // 移动vma
	ret = move_vma(vma, addr, old_len, new_len, new_addr, locked, flags, uf,
		       uf_unmap);

	if (!(offset_in_page(ret)))
		goto out;

out1:
	vm_unacct_memory(charged);

out:
	return ret;
}


// do_munmap->__do_munmap，最后一个值传的false

int __do_munmap(struct mm_struct *mm, unsigned long start, size_t len,
		struct list_head *uf, bool downgrade)
{
	unsigned long end;
	struct vm_area_struct *vma, *prev, *last;

    // 判断地址页对齐，且不能在内核地址空间
	if ((offset_in_page(start)) || start > TASK_SIZE || len > TASK_SIZE-start)
		return -EINVAL;

    // 对齐长度
	len = PAGE_ALIGN(len);
	end = start + len;
	if (len == 0)
		return -EINVAL;

	// 架构相关
	arch_unmap(mm, start, end);

	// 找一个结束地址大于start的vma
	vma = find_vma(mm, start);
	if (!vma)
		return 0;
	prev = vma->vm_prev;
	/* we have  start < vma->vm_end  */

    // 从上面选的是vma->vm_end > start, 如果vma->vm_start >= end，
	// 则这个地址是个空洞。直接返回什么也不干。
	if (vma->vm_start >= end)
		return 0;

	if (start > vma->vm_start) {
        // 表示要释放的区间在一个vma内部
		int error;

		// 因为这里要拆分vma，所以这里要判断进程映射的数量是否超过了限制
		if (end < vma->vm_end && mm->map_count >= sysctl_max_map_count)
			return -ENOMEM;

        // 把vma拆分成vma->vm_start---start,  start
		error = __split_vma(mm, vma, start, 0);
		if (error)
			return error;
		prev = vma;
	}

	// 找到一个大于end的vma
	last = find_vma(mm, end);
	if (last && end > last->vm_start) {
        // 把vma拆分成start---end
		int error = __split_vma(mm, last, end, 1);
		if (error)
			return error;
	}
	vma = vma_next(mm, prev);

	if (unlikely(uf)) {
		/*
		 * If userfaultfd_unmap_prep returns an error the vmas
		 * will remain splitted, but userland will get a
		 * highly unexpected error anyway. This is no
		 * different than the case where the first of the two
		 * __split_vma fails, but we don't undo the first
		 * split, despite we could. This is unlikely enough
		 * failure that it's not worth optimizing it for.
		 */
		int error = userfaultfd_unmap_prep(vma, start, end, uf);
		if (error)
			return error;
	}

	// 如果有上锁的页面，并且它处于要释放的map之间，
    // 则把它从上锁的页面移除，并解锁该页面
	if (mm->locked_vm) {
		struct vm_area_struct *tmp = vma;
		while (tmp && tmp->vm_start < end) {
			if (tmp->vm_flags & VM_LOCKED) {
				mm->locked_vm -= vma_pages(tmp);
				munlock_vma_pages_all(tmp);
			}

			tmp = tmp->vm_next;
		}
	}

	// 把这个vma从红黑树中解链
	if (!detach_vmas_to_be_unmapped(mm, vma, prev, end))
		downgrade = false;

	if (downgrade)
		mmap_write_downgrade(mm);

    // 这个会释放vma对应的内存，page_table, pgd, pmd等内存数据
	unmap_region(mm, vma, prev, start, end);

	// 释放vma
	remove_vma_list(mm, vma);

	return downgrade ? 1 : 0;
}

static struct vm_area_struct *vma_to_resize(unsigned long addr,
	unsigned long old_len, unsigned long new_len, unsigned long flags,
	unsigned long *p)
{
	struct mm_struct *mm = current->mm;
    // 找第一个大于addr的vma
	struct vm_area_struct *vma = find_vma(mm, addr);
	unsigned long pgoff;

    // 如果addr是在空洞内，则报错
	if (!vma || vma->vm_start > addr)
		return ERR_PTR(-EFAULT);

	// old_len为0是一种待殊情况，它允许从其它共享map的进程来复制，所以这里要判断vma
    // 是否有共享属性
	if (!old_len && !(vma->vm_flags & (VM_SHARED | VM_MAYSHARE))) {
		pr_warn_once("%s (%d): attempted to duplicate a private mapping with mremap.  This is not supported.\n", current->comm, current->pid);
		return ERR_PTR(-EINVAL);
	}

    // 不卸载的map，只能是非匿名和共享的
	if (flags & MREMAP_DONTUNMAP && (!vma_is_anonymous(vma) ||
			vma->vm_flags & VM_SHARED))
		return ERR_PTR(-EINVAL);

    // 如果是hugetlb页，则报错
	if (is_vm_hugetlb_page(vma))
		return ERR_PTR(-EINVAL);

	// 如果addr跨越了vma，则报错
	if (old_len > vma->vm_end - addr)
		return ERR_PTR(-EFAULT);

    // 如果新老长度相等，则直接返回vma
	if (new_len == old_len)
		return vma;

	/* Need to be careful about a growing mapping */
	pgoff = (addr - vma->vm_start) >> PAGE_SHIFT;
	pgoff += vma->vm_pgoff;
	if (pgoff + (new_len >> PAGE_SHIFT) < pgoff)
		return ERR_PTR(-EINVAL);

	if (vma->vm_flags & (VM_DONTEXPAND | VM_PFNMAP))
		return ERR_PTR(-EFAULT);

	if (vma->vm_flags & VM_LOCKED) {
		unsigned long locked, lock_limit;
		locked = mm->locked_vm << PAGE_SHIFT;
		lock_limit = rlimit(RLIMIT_MEMLOCK);
		locked += new_len - old_len;
		if (locked > lock_limit && !capable(CAP_IPC_LOCK))
			return ERR_PTR(-EAGAIN);
	}

    // 判断
	if (!may_expand_vm(mm, vma->vm_flags,
				(new_len - old_len) >> PAGE_SHIFT))
		return ERR_PTR(-ENOMEM);

    // 统计相关
	if (vma->vm_flags & VM_ACCOUNT) {
		unsigned long charged = (new_len - old_len) >> PAGE_SHIFT;
		if (security_vm_enough_memory_mm(mm, charged))
			return ERR_PTR(-ENOMEM);
		*p = charged;
	}

	return vma;
}

bool may_expand_vm(struct mm_struct *mm, vm_flags_t flags, unsigned long npages)
{
	if (mm->total_vm + npages > rlimit(RLIMIT_AS) >> PAGE_SHIFT)
		return false;

	if (is_data_mapping(flags) &&
	    mm->data_vm + npages > rlimit(RLIMIT_DATA) >> PAGE_SHIFT) {
		/* Workaround for Valgrind */
		if (rlimit(RLIMIT_DATA) == 0 &&
		    mm->data_vm + npages <= rlimit_max(RLIMIT_DATA) >> PAGE_SHIFT)
			return true;

		pr_warn_once("%s (%d): VmData %lu exceed data ulimit %lu. Update limits%s.\n",
			     current->comm, current->pid,
			     (mm->data_vm + npages) << PAGE_SHIFT,
			     rlimit(RLIMIT_DATA),
			     ignore_rlimit_data ? "" : " or use boot option ignore_rlimit_data");

		if (!ignore_rlimit_data)
			return false;
	}

	return true;
}

unsigned long
get_unmapped_area(struct file *file, unsigned long addr, unsigned long len,
		unsigned long pgoff, unsigned long flags)
{
	unsigned long (*get_area)(struct file *, unsigned long,
				  unsigned long, unsigned long, unsigned long);

	unsigned long error = arch_mmap_check(addr, len, flags);
	if (error)
		return error;

	// 判断是否在内核空间
	if (len > TASK_SIZE)
		return -ENOMEM;

	get_area = current->mm->get_unmapped_area;
	if (file) {
		if (file->f_op->get_unmapped_area)
			get_area = file->f_op->get_unmapped_area;
	} else if (flags & MAP_SHARED) {
		/*
		 * mmap_region() will call shmem_zero_setup() to create a file,
		 * so use shmem's get_unmapped_area in case it can be huge.
		 * do_mmap() will clear pgoff, so match alignment.
		 */
		pgoff = 0;
		get_area = shmem_get_unmapped_area;
	}
    // 这个函数会获取一个未映射的vma结构
	addr = get_area(file, addr, len, pgoff, flags);
	if (IS_ERR_VALUE(addr))
		return addr;

	if (addr > TASK_SIZE - len)
		return -ENOMEM;
	if (offset_in_page(addr))
		return -EINVAL;

	error = security_mmap_addr(addr);
	return error ? error : addr;
}

static unsigned long move_vma(struct vm_area_struct *vma,
		unsigned long old_addr, unsigned long old_len,
		unsigned long new_len, unsigned long new_addr,
		bool *locked, unsigned long flags,
		struct vm_userfaultfd_ctx *uf, struct list_head *uf_unmap)
{
	struct mm_struct *mm = vma->vm_mm;
	struct vm_area_struct *new_vma;
	unsigned long vm_flags = vma->vm_flags;
	unsigned long new_pgoff;
	unsigned long moved_len;
	unsigned long excess = 0;
	unsigned long hiwater_vm;
	int split = 0;
	int err;
	bool need_rmap_locks;

     // do_munmap会把一个vma拆分成3个，在后面会调用，所以这里判断
     // 要至少保留3个vma
	if (mm->map_count >= sysctl_max_map_count - 3)
		return -ENOMEM;

    // todo: 没看懂
	err = ksm_madvise(vma, old_addr, old_addr + old_len,
						MADV_UNMERGEABLE, &vm_flags);
	if (err)
		return err;

	new_pgoff = vma->vm_pgoff + ((old_addr - vma->vm_start) >> PAGE_SHIFT);
    // 复制一个vma
	new_vma = copy_vma(&vma, new_addr, new_len, new_pgoff,
			   &need_rmap_locks);
	if (!new_vma)
		return -ENOMEM;

    // 移动页表
	moved_len = move_page_tables(vma, old_addr, new_vma, new_addr, old_len,
				     need_rmap_locks);
    // 如果移动长度小于老的长度，则报错
	if (moved_len < old_len) {
		err = -ENOMEM;
	} else if (vma->vm_ops && vma->vm_ops->mremap) {
		err = vma->vm_ops->mremap(new_vma);
	}

	if (unlikely(err)) {
		/*
		 * On error, move entries back from new area to old,
		 * which will succeed since page tables still there,
		 * and then proceed to unmap new area instead of old.
		 */
		move_page_tables(new_vma, new_addr, vma, old_addr, moved_len,
				 true);
		vma = new_vma;
		old_len = new_len;
		old_addr = new_addr;
		new_addr = err;
	} else {
        // 大多数情况走这儿
		mremap_userfaultfd_prep(new_vma, uf);
		arch_remap(mm, old_addr, old_addr + old_len,
			   new_addr, new_addr + new_len);
	}

    // 统计相关
	if (vm_flags & VM_ACCOUNT) {
		vma->vm_flags &= ~VM_ACCOUNT;
		excess = vma->vm_end - vma->vm_start - old_len;
		if (old_addr > vma->vm_start &&
		    old_addr + old_len < vma->vm_end)
			split = 1;
	}

	hiwater_vm = mm->hiwater_vm;
	vm_stat_account(mm, vma->vm_flags, new_len >> PAGE_SHIFT);

	/* Tell pfnmap has moved from this vma */
	if (unlikely(vma->vm_flags & VM_PFNMAP))
		untrack_pfn_moved(vma);

	if (unlikely(!err && (flags & MREMAP_DONTUNMAP))) {
		if (vm_flags & VM_ACCOUNT) {
			/* Always put back VM_ACCOUNT since we won't unmap */
			vma->vm_flags |= VM_ACCOUNT;

			vm_acct_memory(new_len >> PAGE_SHIFT);
		}

		/*
		 * VMAs can actually be merged back together in copy_vma
		 * calling merge_vma. This can happen with anonymous vmas
		 * which have not yet been faulted, so if we were to consider
		 * this VMA split we'll end up adding VM_ACCOUNT on the
		 * next VMA, which is completely unrelated if this VMA
		 * was re-merged.
		 */
		if (split && new_vma == vma)
			split = 0;

		/* We always clear VM_LOCKED[ONFAULT] on the old vma */
		vma->vm_flags &= VM_LOCKED_CLEAR_MASK;

		/* Because we won't unmap we don't need to touch locked_vm */
		goto out;
	}

    // 卸载老的映射
	if (do_munmap(mm, old_addr, old_len, uf_unmap) < 0) {
		/* OOM: unable to split vma, just get accounts right */
		vm_unacct_memory(excess >> PAGE_SHIFT);
		excess = 0;
	}

	if (vm_flags & VM_LOCKED) {
		mm->locked_vm += new_len >> PAGE_SHIFT;
		*locked = true;
	}
out:
	mm->hiwater_vm = hiwater_vm;

	/* Restore VM_ACCOUNT if one or two pieces of vma left */
	if (excess) {
		vma->vm_flags |= VM_ACCOUNT;
		if (split)
			vma->vm_next->vm_flags |= VM_ACCOUNT;
	}

	return new_addr;
}

unsigned long move_page_tables(struct vm_area_struct *vma,
		unsigned long old_addr, struct vm_area_struct *new_vma,
		unsigned long new_addr, unsigned long len,
		bool need_rmap_locks)
{
	unsigned long extent, old_end;
	struct mmu_notifier_range range;
	pmd_t *old_pmd, *new_pmd;
	pud_t *old_pud, *new_pud;

	old_end = old_addr + len;
    // 刷缓存
	flush_cache_range(vma, old_addr, old_end);

    // 通知回调
	mmu_notifier_range_init(&range, MMU_NOTIFY_UNMAP, 0, vma, vma->vm_mm,
				old_addr, old_end);
	mmu_notifier_invalidate_range_start(&range);

    // 循环处理老地址范围内的页表
	for (; old_addr < old_end; old_addr += extent, new_addr += extent) {
        // 调度
		cond_resched();
		
        // 获取地址的范围，先按照PUD的页大小来判断
		extent = get_extent(NORMAL_PUD, old_addr, old_end, new_addr);

        // 获取老地址的pud
		old_pud = get_old_pud(vma->vm_mm, old_addr);
		if (!old_pud)
			continue;

        // 申请一个新的pud
		new_pud = alloc_new_pud(vma->vm_mm, vma, new_addr);
		if (!new_pud)
			break;
		if (pud_trans_huge(*old_pud) || pud_devmap(*old_pud)) {
            // 处理巨页相关
			if (extent == HPAGE_PUD_SIZE) {
				move_pgt_entry(HPAGE_PUD, vma, old_addr, new_addr,
					       old_pud, new_pud, need_rmap_locks);
				/* We ignore and continue on error? */
				continue;
			}
		} else if (IS_ENABLED(CONFIG_HAVE_MOVE_PUD) && extent == PUD_SIZE) {
            // 如果开启了CONFIG_HAVE_MOVE_PUD，而且页面区间大于PUD_SIZE，则
            // 直接在PUD级别移动页表
			if (move_pgt_entry(NORMAL_PUD, vma, old_addr, new_addr,
					   old_pud, new_pud, true))
				continue;
		}

        // 这里和上面的处理一样，只不过是在pmd级别来移动页表
		extent = get_extent(NORMAL_PMD, old_addr, old_end, new_addr);
		old_pmd = get_old_pmd(vma->vm_mm, old_addr);
		if (!old_pmd)
			continue;
		new_pmd = alloc_new_pmd(vma->vm_mm, vma, new_addr);
		if (!new_pmd)
			break;
		if (is_swap_pmd(*old_pmd) || pmd_trans_huge(*old_pmd) ||
		    pmd_devmap(*old_pmd)) {
			if (extent == HPAGE_PMD_SIZE &&
			    move_pgt_entry(HPAGE_PMD, vma, old_addr, new_addr,
					   old_pmd, new_pmd, need_rmap_locks))
				continue;
			split_huge_pmd(vma, old_pmd, old_addr);
			if (pmd_trans_unstable(old_pmd))
				continue;
		} else if (IS_ENABLED(CONFIG_HAVE_MOVE_PMD) &&
			   extent == PMD_SIZE) {
			/*
			 * If the extent is PMD-sized, try to speed the move by
			 * moving at the PMD level if possible.
			 */
			if (move_pgt_entry(NORMAL_PMD, vma, old_addr, new_addr,
					   old_pmd, new_pmd, true))
				continue;
		}

        // 申请一个pte，移动pte
		if (pte_alloc(new_vma->vm_mm, new_pmd))
			break;
		move_ptes(vma, old_pmd, old_addr, old_addr + extent, new_vma,
			  new_pmd, new_addr, need_rmap_locks);
	}

	mmu_notifier_invalidate_range_end(&range);

    // 返回移动了多少长度的地址范围
	return len + old_addr - old_end;	/* how much done */
}
```