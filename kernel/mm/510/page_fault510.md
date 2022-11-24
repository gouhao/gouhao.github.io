# page fault
代码基于5.10, x86构架

```c

// noinstr变量修饰中断函数，主要是用于防止当前中断正在处理过程中，硬件再次发生同样的中断以覆盖某些状态寄存器：
DEFINE_IDTENTRY_RAW_ERRORCODE(exc_page_fault)
{
	// 缺页地址存在cr2寄存器
	unsigned long address = read_cr2();
	irqentry_state_t state;

	// 对当前进程加锁
	prefetchw(&current->mm->mmap_lock);

	// kvm相关
	if (kvm_handle_async_pf(regs, (u32)address))
		return;

	// rcu相关，与后面的irqentry_exit对应
	state = irqentry_enter(regs);

	// 主要是配合noinstr变量修饰的函数，用于防止在当前中断增在处理过程中，
	// 再次同样的中断发生，以 覆盖当前一些状态寄存器（https://lwn.net/Articles/877229/），begin 为开始锁定区域。
	instrumentation_begin();
	// 处理内存错误
	handle_page_fault(regs, error_code, address);
	instrumentation_end();

	irqentry_exit(regs, state);
}

static __always_inline void
handle_page_fault(struct pt_regs *regs, unsigned long error_code,
			      unsigned long address)
{
	// 调用trace
	trace_page_fault_entries(regs, error_code, address);

	// 判断是不是mmio fault。todo：waht is mmio?
	if (unlikely(kmmio_fault(regs, address)))
		return;

	// fault_in_kernel_space： address >= TASK_SIZE;
	// 一般异常都是user_addr_fault
	if (unlikely(fault_in_kernel_space(address))) {
		do_kern_addr_fault(regs, error_code, address);
	} else {
		do_user_addr_fault(regs, error_code, address);
		/*
		 * User address page fault handling might have reenabled
		 * interrupts. Fixing up all potential exit points of
		 * do_user_addr_fault() and its leaf functions is just not
		 * doable w/o creating an unholy mess or turning the code
		 * upside down.
		 */
		local_irq_disable();
	}
}
```

## do_user_addr_fault
```c
static inline
void do_user_addr_fault(struct pt_regs *regs,
			unsigned long hw_error_code,
			unsigned long address)
{
	struct vm_area_struct *vma;
	struct task_struct *tsk;
	struct mm_struct *mm;
	vm_fault_t fault;
	unsigned int flags = FAULT_FLAG_DEFAULT;

	// 当前进程与进程的mm
	tsk = current;
	mm = tsk->mm;

	// 这个函数不是被NOKPROBE_SYMBOL标记了吗？怎么还会进到kprobe里
	if (unlikely(kprobe_page_fault(regs, X86_TRAP_PF)))
		return;

	// X86_PF_RSVD是保留位，不应该被使用
	if (unlikely(hw_error_code & X86_PF_RSVD))
		pgtable_bad(regs, hw_error_code, address);

	// SMAP: Supervisor Mode Access Prevention
	if (unlikely(cpu_feature_enabled(X86_FEATURE_SMAP) &&
		     !(hw_error_code & X86_PF_USER) &&
		     !(regs->flags & X86_EFLAGS_AC)))
	{
		bad_area_nosemaphore(regs, hw_error_code, address);
		return;
	}

	// 判断是否在中断或者内核线程里
	if (unlikely(faulthandler_disabled() || !mm)) {
		bad_area_nosemaphore(regs, hw_error_code, address);
		return;
	}

	// 用户空间多加了个flag
	if (user_mode(regs)) {
		local_irq_enable();
		flags |= FAULT_FLAG_USER;
	} else {
		if (regs->flags & X86_EFLAGS_IF)
			local_irq_enable();
	}

	// perf 的 page_fault事件
	perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS, 1, regs, address);

	if (hw_error_code & X86_PF_WRITE)
		// 写访问
		flags |= FAULT_FLAG_WRITE;
	if (hw_error_code & X86_PF_INSTR)
		// INSTRUCTION相关
		flags |= FAULT_FLAG_INSTRUCTION;

#ifdef CONFIG_X86_64
	// 虚拟化相关
	if (is_vsyscall_vaddr(address)) {
		if (emulate_vsyscall(hw_error_code, regs, address))
			return;
	}
#endif

	// 加锁
	if (unlikely(!mmap_read_trylock(mm))) {
		if (!user_mode(regs) && !search_exception_tables(regs->ip)) {
			/*
			 * Fault from code in kernel from
			 * which we do not expect faults.
			 */
			bad_area_nosemaphore(regs, hw_error_code, address);
			return;
		}
retry:
		mmap_read_lock(mm);
	} else {
		
		might_sleep();
	}

	// 找到page_fault所在的vma
	vma = find_vma(mm, address);
	if (unlikely(!vma)) {
		bad_area(regs, hw_error_code, address);
		return;
	}

	// 地址在vma区间，说明是正常的
	if (likely(vma->vm_start <= address))
		goto good_area;
	
	// 走到这里 vma->vm_start > address, 因为find_vma找到的是vma->vm_end
	// 第一个大于address的vma，正常情况下只有一种vma那就是栈。

	// 栈是向下增长的有VM_GROWSDOWN标志，其他vma都没有，如果没有这个标志说明是
	// 普通的vma，那肯定出错了。
	if (unlikely(!(vma->vm_flags & VM_GROWSDOWN))) {
		bad_area(regs, hw_error_code, address);
		return;
	}

	// 尝试扩展栈
	if (unlikely(expand_stack(vma, address))) {
		bad_area(regs, hw_error_code, address);
		return;
	}

	// 走到这里说明是正常的vma
	// 如果是栈扩展的话，在expand_stack里修改了栈的vma之后，也会
	// 走到这里，相当于让栈处理一次handle_mm_fault，这里面会做具体的映射

good_area:
	// 根据hw_error_code里的读写标志和vma的标志，来判断是否能正常访问
	if (unlikely(access_error(hw_error_code, vma))) {
		bad_area_access_error(regs, hw_error_code, address, vma);
		return;
	}

	// 处理异常
	fault = handle_mm_fault(vma, address, flags, regs);

	// 判断是否有待处理的信号
	if (fault_signal_pending(fault, regs)) {
		if (!user_mode(regs))
			no_context(regs, hw_error_code, address, SIGBUS,
				   BUS_ADRERR);
		return;
	}

	// 需要重试
	if (unlikely((fault & VM_FAULT_RETRY) &&
		     (flags & FAULT_FLAG_ALLOW_RETRY))) {
		flags |= FAULT_FLAG_TRIED;
		goto retry;
	}

	mmap_read_unlock(mm);


	// 如果错误，则向用户发送fault信号
	if (unlikely(fault & VM_FAULT_ERROR)) {
		mm_fault_error(regs, hw_error_code, address, fault);
		return;
	}

	// vm8086模式
	check_v8086_mode(regs, address, tsk);
}

// 在向下扩展的栈里expand_stack会调到这个函数
int expand_downwards(struct vm_area_struct *vma,
				   unsigned long address)
{
	struct mm_struct *mm = vma->vm_mm;
	struct vm_area_struct *prev;
	int error = 0;

	// 地址页序号
	address &= PAGE_MASK;
	if (address < mmap_min_addr)
		return -EPERM;

	// stack_guard_gap默认是256UL<<PAGE_SHIFT，也就是栈和前一个vma的最小间距

	prev = vma->vm_prev;
	if (prev && !(prev->vm_flags & VM_GROWSDOWN) &&
			vma_is_accessible(prev)) {
		// 如果与前一个vma的间距小于这个值，返回没内存
		if (address - prev->vm_end < stack_guard_gap)
			return -ENOMEM;
	}

	/* We must make sure the anon_vma is allocated. */
	if (unlikely(anon_vma_prepare(vma)))
		return -ENOMEM;

	// 锁定vma
	anon_vma_lock_write(vma->anon_vma);

	// 这里再判断一次是为了必有竞争，因为锁定vma可能会切换进程
	if (address < vma->vm_start) {
		unsigned long size, grow;

		// 新vma的大小 
		size = vma->vm_end - address;

		// 需要增长的页数
		grow = (vma->vm_start - address) >> PAGE_SHIFT;

		error = -ENOMEM;
		if (grow <= vma->vm_pgoff) {
			error = acct_stack_growth(vma, size, grow);
			if (!error) {
				spin_lock(&mm->page_table_lock);
				// 增加locked计数
				if (vma->vm_flags & VM_LOCKED)
					mm->locked_vm += grow;
				vm_stat_account(mm, vma->vm_flags, grow);
				anon_vma_interval_tree_pre_update_vma(vma);
				// 设置新的起始地址
				vma->vm_start = address;

				// 因为栈是向下扩展的，所以这里是减grow
				vma->vm_pgoff -= grow;
				anon_vma_interval_tree_post_update_vma(vma);
				vma_gap_update(vma);
				spin_unlock(&mm->page_table_lock);

				perf_event_mmap(vma);
			}
		}
	}
	anon_vma_unlock_write(vma->anon_vma);
	khugepaged_enter_vma_merge(vma, vma->vm_flags);
	validate_mm(mm);
	return error;
}

static inline int
access_error(unsigned long error_code, struct vm_area_struct *vma)
{
	/* This is only called for the current mm, so: */
	bool foreign = false;

	/*
	 * Read or write was blocked by protection keys.  This is
	 * always an unconditional error and can never result in
	 * a follow-up action to resolve the fault, like a COW.
	 */
	if (error_code & X86_PF_PK)
		return 1;

	/*
	 * Make sure to check the VMA so that we do not perform
	 * faults just to hit a X86_PF_PK as soon as we fill in a
	 * page.
	 */
	if (!arch_vma_access_permitted(vma, (error_code & X86_PF_WRITE),
				       (error_code & X86_PF_INSTR), foreign))
		return 1;

	if (error_code & X86_PF_WRITE) {
		/* write, present and write, not present: */
		if (unlikely(!(vma->vm_flags & VM_WRITE)))
			return 1;
		return 0;
	}

	/* read, present: */
	if (unlikely(error_code & X86_PF_PROT))
		return 1;

	/* read, not present: */
	if (unlikely(!vma_is_accessible(vma)))
		return 1;

	return 0;
}
```

## handle_mm_fault
```c
vm_fault_t handle_mm_fault(struct vm_area_struct *vma, unsigned long address,
			   unsigned int flags, struct pt_regs *regs)
{
	vm_fault_t ret;

	// 设置当前进程为RUNNING状态
	__set_current_state(TASK_RUNNING);

	// 计数统计相关
	count_vm_event(PGFAULT);
	count_memcg_event_mm(vma->vm_mm, PGFAULT);

	/* do counter updates before entering really critical section. */
	check_sync_rss_stat(current);

	if (!arch_vma_access_permitted(vma, flags & FAULT_FLAG_WRITE,
					    flags & FAULT_FLAG_INSTRUCTION,
					    flags & FAULT_FLAG_REMOTE))
		return VM_FAULT_SIGSEGV;

	// 对于用户空间的fault，先调用cgroup的enter函数，与后面的exit对应
	if (flags & FAULT_FLAG_USER)
		mem_cgroup_enter_user_fault();

	if (unlikely(is_vm_hugetlb_page(vma)))
		// 大页
		ret = hugetlb_fault(vma->vm_mm, vma, address, flags);
	else
		// 常规的fault
		ret = __handle_mm_fault(vma, address, flags);

	// 用户空间fault相关的memcg操作
	if (flags & FAULT_FLAG_USER) {
		mem_cgroup_exit_user_fault();
		if (task_in_memcg_oom(current) && !(ret & VM_FAULT_OOM))
			mem_cgroup_oom_synchronize(false);
	}

	mm_account_fault(regs, address, flags, ret);

	return ret;
}

static vm_fault_t __handle_mm_fault(struct vm_area_struct *vma,
		unsigned long address, unsigned int flags)
{
	struct vm_fault vmf = {
		.vma = vma,
		// 地址所在的页地址
		.address = address & PAGE_MASK,
		.flags = flags,
		// 地址所在页的序号
		.pgoff = linear_page_index(vma, address),
		// 分配页时的gfp
		.gfp_mask = __get_fault_gfp_mask(vma),
	};
	// 有写需求就是dirty
	unsigned int dirty = flags & FAULT_FLAG_WRITE;
	// vma所在的mm
	struct mm_struct *mm = vma->vm_mm;
	pgd_t *pgd;
	p4d_t *p4d;
	vm_fault_t ret;

	// 获取pgd表项
	pgd = pgd_offset(mm, address);
	// 获取p4d表项
	p4d = p4d_alloc(mm, pgd, address);
	if (!p4d)
		return VM_FAULT_OOM;

	// pud_alloc与p4d_alloc类似，如果表项为空就分配一个，
	// 否则计算出 pud的偏移
	vmf.pud = pud_alloc(mm, p4d, address);
	if (!vmf.pud)
		return VM_FAULT_OOM;
retry_pud:
	// 如果pud为空，先判断vma是否允许大页，则如果允许则分配一个大页，
	// 大页对于内存型进程能加速，减少映射级数
	if (pud_none(*vmf.pud) && __transparent_hugepage_enabled(vma)) {
		// 创建大页
		ret = create_huge_pud(&vmf);
		if (!(ret & VM_FAULT_FALLBACK))
			return ret;
	} else {
		// 不能创建大页，或者已经分配了pud项
		pud_t orig_pud = *vmf.pud;

		barrier();
		// pud_trans_huge是判断pud里有无_PAGE_BIT_PSE标志，这个标志是4M或2M页的标志
		// pud_devmap是判断有无_PAGE_DEVMAP标志，这是设备映射？
		if (pud_trans_huge(orig_pud) || pud_devmap(orig_pud)) {

			/* NUMA case for anonymous PUDs would go here */

			if (dirty && !pud_write(orig_pud)) {
				ret = wp_huge_pud(&vmf, orig_pud);
				if (!(ret & VM_FAULT_FALLBACK))
					return ret;
			} else {
				huge_pud_set_accessed(&vmf, orig_pud);
				return 0;
			}
		}
	}

	vmf.pmd = pmd_alloc(mm, vmf.pud, address);
	if (!vmf.pmd)
		return VM_FAULT_OOM;

	/* Huge pud page fault raced with pmd_alloc? */
	if (pud_trans_unstable(vmf.pud))
		goto retry_pud;

	if (pmd_none(*vmf.pmd) && __transparent_hugepage_enabled(vma)) {
		ret = create_huge_pmd(&vmf);
		if (!(ret & VM_FAULT_FALLBACK))
			return ret;
	} else {
		pmd_t orig_pmd = *vmf.pmd;

		barrier();
		if (unlikely(is_swap_pmd(orig_pmd))) {
			VM_BUG_ON(thp_migration_supported() &&
					  !is_pmd_migration_entry(orig_pmd));
			if (is_pmd_migration_entry(orig_pmd))
				pmd_migration_entry_wait(mm, vmf.pmd);
			return 0;
		}
		if (pmd_trans_huge(orig_pmd) || pmd_devmap(orig_pmd)) {
			if (pmd_protnone(orig_pmd) && vma_is_accessible(vma))
				return do_huge_pmd_numa_page(&vmf, orig_pmd);

			if (dirty && !pmd_write(orig_pmd)) {
				ret = wp_huge_pmd(&vmf, orig_pmd);
				if (!(ret & VM_FAULT_FALLBACK))
					return ret;
			} else {
				huge_pmd_set_accessed(&vmf, orig_pmd);
				return 0;
			}
		}
	}

	return handle_pte_fault(&vmf);
}


// 取出地址在pgd表里的偏移，在5级映射里PGDIR_SHIFT是48
// PTRS_PER_PGD一般是512，在4K页大小时，一个指针是8位，所以一页只能存512个指针，
// 64K的页理论上可以存8192个指针，但是目前即使是64K页，PTRS_PER_PGD也是512
#define pgd_index(a)  (((a) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))

static inline pgd_t *pgd_offset_pgd(pgd_t *pgd, unsigned long address)
{
	// 这里的pgd是一个进程的pgd基址，这个值在cr3寄存器里保存，
	// 基址+偏移就是address对应的pgd表项
	return (pgd + pgd_index(address));
};

/*
 * a shortcut to get a pgd_t in a given mm
 */
#ifndef pgd_offset
#define pgd_offset(mm, address)		pgd_offset_pgd((mm)->pgd, (address))
#endif


static inline pgdval_t native_pgd_val(pgd_t pgd)
{
	// CONFIG_X86_PAE没打开时，#define PGD_ALLOWED_BITS (~0ULL)，
	// 也就是直接返回原值
	return pgd.pgd & PGD_ALLOWED_BITS;
}

// 这个pgd_none是5级页表的版本
static inline int pgd_none(pgd_t pgd)
{
	// 在x86处理器里，5级页表需要CPU有X86_FEATURE_LA57标志，
	// 否则不支持页表
	if (!pgtable_l5_enabled())
		return 0;
	return !native_pgd_val(pgd);
}

static inline p4d_t *p4d_alloc(struct mm_struct *mm, pgd_t *pgd,
		unsigned long address)
{
	// pgd_none就是判断pgd的值是不是0，如果pgd是,就要通过__p4d_alloc给pgd分配空间，
	// 否则调用p4d_offset算出地址在p4d里的偏移
	return (unlikely(pgd_none(*pgd)) && __p4d_alloc(mm, pgd, address)) ?
		NULL : p4d_offset(pgd, address);
}

int __p4d_alloc(struct mm_struct *mm, pgd_t *pgd, unsigned long address)
{
	// 分配一页内存，并全部清0
	p4d_t *new = p4d_alloc_one(mm, address);
	if (!new)
		return -ENOMEM;

	// 内存屏障，保证可见性，不允许编译器，cpu乱排序
	smp_wmb(); /* See comment in __pte_alloc */

	// 锁定进程的页表锁
	spin_lock(&mm->page_table_lock);

	// 加锁是个耗时操作，可能会等待，如果在等待期间别人已经分配了表项，
	// 就不用再分配了。这里不能在分配p4d页之前判断，因为分配页是一个耗时操作，
	// 有可能会切换进程，所以必须要在分配了页之后判断
	if (pgd_present(*pgd))
		// 和别人冲突了，就释放上面分配的页
		p4d_free(mm, new);
	else
		// 正常情况都走这里，用分配的页内存来填充对应的pgd表项
		pgd_populate(mm, pgd, new);
	spin_unlock(&mm->page_table_lock);
	return 0;
}

// 这是5级页表的版本
static inline void pgd_populate(struct mm_struct *mm, pgd_t *pgd, p4d_t *p4d)
{
	if (!pgtable_l5_enabled())
		return;
	// 这个函数在CONFIG_PARAVIRT_XXL打开时才有效，否则是个空函数
	paravirt_alloc_p4d(mm, __pa(p4d) >> PAGE_SHIFT);

	// __pa是把虚拟地址转成物理地址
	// _PAGE_TABLE是一些保护标志，因为物理地址都是4K对齐的，所以低12位肯定是0，
	// 这样用低位保存一些状态标志
	set_pgd(pgd, __pgd(_PAGE_TABLE | __pa(p4d)));
}

#define __pgd(x)	native_make_pgd(x)
static inline pgd_t native_make_pgd(pgdval_t val)
{
	// 这里只是过滤了一下pgd的合法值
	return (pgd_t) { val & PGD_ALLOWED_BITS };
}

#define set_pgd(pgdp, pgd)		native_set_pgd(pgdp, pgd)
static inline void native_set_pgd(pgd_t *pgdp, pgd_t pgd)
{
	// 把值写到pgd表项里
	WRITE_ONCE(*pgdp, pti_set_user_pgtbl(pgdp, pgd));
}


static inline p4d_t *p4d_offset(pgd_t *pgd, unsigned long address)
{
	// 对于p4d来说，如果5级页表没有使能或者不可用，
	// 那传进来的pgd就是p4d
	if (!pgtable_l5_enabled())
		return (p4d_t *)pgd;
	// 否则，计算p4d的偏移，pgd_page_vaddr是获取pgd的虚拟地址
	return (p4d_t *)pgd_page_vaddr(*pgd) + p4d_index(address);
}

// P4D_SHIFT是39, PTRS_PER_P4D是512
#define p4d_index(address)	(((address) >> P4D_SHIFT) & (PTRS_PER_P4D - 1))


static inline bool __transparent_hugepage_enabled(struct vm_area_struct *vma)
{

	// 这个是硬件/固件禁用了大页
	if (transparent_hugepage_flags & (1 << TRANSPARENT_HUGEPAGE_NEVER_DAX))
		return false;

	// vma是否禁用了大页
	if (!transhuge_vma_enabled(vma, vma->vm_flags))
		return false;

	// 判断此vma是否是栈，如果是栈的话，如果还没有完成设置则不允许大页
	if (vma_is_temporary_stack(vma))
		return false;

	// 有大页标志，直接允许大页
	if (transparent_hugepage_flags & (1 << TRANSPARENT_HUGEPAGE_FLAG))
		return true;

	// vma是文件映射，并且这个inode是dax访问
	if (vma_is_dax(vma))
		return true;

	// 如果大页实现了MADV算法，那就看vma允不允许大页映射
	if (transparent_hugepage_flags &
				(1 << TRANSPARENT_HUGEPAGE_REQ_MADV_FLAG))
		return !!(vma->vm_flags & VM_HUGEPAGE);

	return false;
}
```