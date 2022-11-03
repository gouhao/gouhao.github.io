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