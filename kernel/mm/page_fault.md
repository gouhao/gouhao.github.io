# 缺页
代码基于主线v4.19，构架x86_64

## page_fault总流程

```c
// arch/x86/mm/fault.c

dotraplinkage void notrace
do_page_fault(struct pt_regs *regs, unsigned long error_code)
{
    	// 获取出错的地址，出错的地址在cr2中
	unsigned long address = read_cr2(); 
	enum ctx_state prev_state;

    	// context trace相关
	prev_state = exception_enter();
	if (trace_pagefault_enabled())
        // 调用相关trace的回调接口
		trace_page_fault_entries(address, regs, error_code);

    	// 真正做事的函数
	__do_page_fault(regs, error_code, address);

    	// context trace相关
	exception_exit(prev_state);
}

// 关于error_code各个位的详细说明，看arch/x86/include/asm/traps.h
static noinline void
__do_page_fault(struct pt_regs *regs, unsigned long error_code,
		unsigned long address)
{
	struct vm_area_struct *vma;
	struct task_struct *tsk;
	struct mm_struct *mm;
	vm_fault_t fault, major = 0;
	unsigned int flags = FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_KILLABLE;
	u32 pkey;

    	// 当前进程的task_struct
	tsk = current;

    	// 当前进程的内存结构体
	mm = tsk->mm;

    	// todo: 预取信号量？
	prefetchw(&mm->mmap_sem);

    	// mmio trace 相关，trace可以在这里拦截page_fault
	if (unlikely(kmmio_fault(regs, address)))
		return;

	// 发生在内核空间的缺页，
    	// fault_in_kernel_space只是判断了一下address >= TASK_SIZE_MAX
	if (unlikely(fault_in_kernel_space(address))) {
		if (!(error_code & (X86_PF_RSVD | X86_PF_USER | X86_PF_PROT))) {
			// 如果不是因为页保护缺页，也不是发生在用户空间，也没有使用保留位，
			// 则一定是内核空间的vmalloc缺页
			if (vmalloc_fault(address) >= 0)
				return;
		}

		// 走到这里就是有问题的缺页，或者vmalloc失败

		// 是否是无效的缺页
		if (spurious_fault(error_code, address))
			return;

		// kprobe hook调用
		if (kprobes_fault(regs))
			return;
		// 处理坏区域
		bad_area_nosemaphore(regs, error_code, address, NULL);

		return;
	}

	// kprobe 的回调函数
	if (unlikely(kprobes_fault(regs)))
		return;

	// 如果使用了保留位，则会出现oops
	if (unlikely(error_code & X86_PF_RSVD))
		pgtable_bad(regs, error_code, address);

	// todo: 没看懂
	if (unlikely(smap_violation(error_code, regs))) {
		bad_area_nosemaphore(regs, error_code, address, NULL);
		return;
	}

	// 如果没有缺页被禁用，或者没有mm（意味着是内核线程），
	// 则出错返回
	if (unlikely(faulthandler_disabled() || !mm)) {
		bad_area_nosemaphore(regs, error_code, address, NULL);
		return;
	}

	// 下面是说error_code中各个位表示的意义，写到flag中
	if (user_mode(regs)) {
		local_irq_enable();
		error_code |= X86_PF_USER;
		flags |= FAULT_FLAG_USER;
	} else {
		if (regs->flags & X86_EFLAGS_IF)
			local_irq_enable();
	}

	perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS, 1, regs, address);

	if (error_code & X86_PF_WRITE)
		flags |= FAULT_FLAG_WRITE;
	if (error_code & X86_PF_INSTR)
		flags |= FAULT_FLAG_INSTRUCTION;

	// 下面这一段是处理死锁有关的问题，原代码中有注释
	if (unlikely(!down_read_trylock(&mm->mmap_sem))) {
		if (!(error_code & X86_PF_USER) &&
		    !search_exception_tables(regs->ip)) {
			bad_area_nosemaphore(regs, error_code, address, NULL);
			return;
		}
retry:
		down_read(&mm->mmap_sem);
	} else {
		/*
		 * The above down_read_trylock() might have succeeded in
		 * which case we'll have missed the might_sleep() from
		 * down_read():
		 */
		might_sleep();
	}

	// 找到第一个vm_end大于address的vma
	vma = find_vma(mm, address);
	if (unlikely(!vma)) {
		bad_area(regs, error_code, address);
		return;
	}

	// 如果vm_start小于address，则表示缺页的地址是在一个vma内，
	// 这种情况属于正常的缺页
	if (likely(vma->vm_start <= address))
		goto good_area;
	
	// 走到这里则表示vm_start > address，
	// start和end都大于address，那这个地址当前是落到一个空洞内
	// VM_GROWSDOWN这个标示表示向下增长的栈（也有向上增长的），
	
	// address顶部如果是栈，有可能会导致栈扩充，
	// 否则，就是落到了一个空洞内，进行出错处理

	// bad_area会导致SIGSEGV段错误
	if (unlikely(!(vma->vm_flags & VM_GROWSDOWN))) {
		bad_area(regs, error_code, address);
		return;
	}

	// 走到这里说明上面的vma就是栈，
	// 如果是来自用户空间的，还要检查其合法性
	if (error_code & X86_PF_USER) {
		// 如果来自用户空间，还要对地址
		/*
		 * Accessing the stack below %sp is always a bug.
		 * The large cushion allows instructions like enter
		 * and pusha to work. ("enter $65535, $31" pushes
		 * 32 pointers and then decrements %sp by 65535.)
		 */
		 // 上面的注释说的很清楚，enter指令可以一次放进65536+32个指针的数量，
		 // 所以，如果address加上最大长度，还小于栈顶指针的话，那肯定就是出错了
		if (unlikely(address + 65536 + 32 * sizeof(unsigned long) < regs->sp)) {
			bad_area(regs, error_code, address);
			return;
		}
	}

	// 走到这里的就是正常的访问栈地址而缺页

	// 所以这里先做扩充
	if (unlikely(expand_stack(vma, address))) {
		bad_area(regs, error_code, address);
		return;
	}

good_area:

	// 地址是对的，但是访问权限不允许的话，还是错的
	if (unlikely(access_error(error_code, vma))) {
		bad_area_access_error(regs, error_code, address, vma);
		return;
	}

	// todo： 啥是pkey
	pkey = vma_pkey(vma);

	// 这个是处理缺页的核心
	fault = handle_mm_fault(vma, address, flags);
	major |= fault & VM_FAULT_MAJOR;

	if (unlikely(fault & VM_FAULT_RETRY)) {

		// 缺页处理未成功，还要再尝试
		/* Retry at most once */

		// 这个条件表示，最多尝试一次
		if (flags & FAULT_FLAG_ALLOW_RETRY) {
			flags &= ~FAULT_FLAG_ALLOW_RETRY;
			flags |= FAULT_FLAG_TRIED;

			// 如果当前进程没有信号要处理里，则重试
			if (!fatal_signal_pending(tsk))
				goto retry;
		}

		// 走到这里表示没有进行重试

		// 如果是用户空间的，则直接返回，
		if (flags & FAULT_FLAG_USER)
			return;

		// 如果是内核空间则报错
		no_context(regs, error_code, address, SIGBUS, BUS_ADRERR);
		return;
	}

	up_read(&mm->mmap_sem);

	// 出错处理
	if (unlikely(fault & VM_FAULT_ERROR)) {
		mm_fault_error(regs, error_code, address, &pkey, fault);
		return;
	}

	// 统计相关，主要和次要的缺页？
	if (major) {
		tsk->maj_flt++;
		perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MAJ, 1, regs, address);
	} else {
		tsk->min_flt++;
		perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MIN, 1, regs, address);
	}

	// 检查8086模式相关
	// 模拟windows相关程序，像wine之类的
	check_v8086_mode(regs, address, tsk);
}
```

## 情景一：内核vmalloc

## 情景二：栈扩展
```c
// mm/mmap.c
// 这个是栈向下扩展的版本
// expand_stack直接调用expand_downwards
int expand_downwards(struct vm_area_struct *vma,
				   unsigned long address)
{
	struct mm_struct *mm = vma->vm_mm;
	struct vm_area_struct *prev;
	int error;

	// 把地址按页对齐
	address &= PAGE_MASK;

	// 调用相关安全hook函数，如果hook返回错误，则不再继续
	error = security_mmap_addr(address);
	if (error)
		return error;

	// 栈扩展时，和前一个vma至少要保持stack_guard_gap的距离，
	// 这个距离初始化时是256个页
	prev = vma->vm_prev;
	if (prev && !(prev->vm_flags & VM_GROWSDOWN) &&
			(prev->vm_flags & (VM_WRITE|VM_READ|VM_EXEC))) {
		if (address - prev->vm_end < stack_guard_gap)
			return -ENOMEM;
	}

	// 判断匿名页是否存在，不存在的话则创建之
	if (unlikely(anon_vma_prepare(vma)))
		return -ENOMEM;


	anon_vma_lock_write(vma->anon_vma);

	// 扩展流程
	if (address < vma->vm_start) {
		unsigned long size, grow;

		// size是栈的总大小
		size = vma->vm_end - address;

		// 要增长的页的数量，大多数情况下是页
		grow = (vma->vm_start - address) >> PAGE_SHIFT;

		error = -ENOMEM;
		// todo: vm_pgoff是什么
		if (grow <= vma->vm_pgoff) {
			// 这个函数判断栈大小限制，及vma锁相关的限制
			error = acct_stack_growth(vma, size, grow);
			if (!error) {
				// 走到这里就表示还没有达到限制，一般情况都会走这里
				spin_lock(&mm->page_table_lock);

				// 增加统计计数器相关
				if (vma->vm_flags & VM_LOCKED)
					mm->locked_vm += grow;
				vm_stat_account(mm, vma->vm_flags, grow);

				// 从匿名映射树中移除
				anon_vma_interval_tree_pre_update_vma(vma);

				// 设置vm_start和vm_pgoff的值
				vma->vm_start = address;
				vma->vm_pgoff -= grow;

				// 重新插入到匿名映射树中
				anon_vma_interval_tree_post_update_vma(vma);

				// 自底向上更新vma及与它有关的vma的距离发生变化
				vma_gap_update(vma);
				spin_unlock(&mm->page_table_lock);

				perf_event_mmap(vma);
			}
		}
	}
	anon_vma_unlock_write(vma->anon_vma);

	// todo: 巨页相关
	khugepaged_enter_vma_merge(vma, vma->vm_flags);
	// 调试选项：CONFIG_DEBUG_VM_RB， 验证vm是否正确
	validate_mm(mm);
	return error;
}
```
## 缺页核心流程
```c
// mm/memory.c

vm_fault_t handle_mm_fault(struct vm_area_struct *vma, unsigned long address,
		unsigned int flags)
{
	vm_fault_t ret;

	// 设置当前进程状态
	__set_current_state(TASK_RUNNING);

	// 增加统计相关的数量
	count_vm_event(PGFAULT);
	count_memcg_event_mm(vma->vm_mm, PGFAULT);

	// todo: 没看懂
	check_sync_rss_stat(current);

	// 检查vma是否有请求的读写相关权限，如果没有则返回段错误
	if (!arch_vma_access_permitted(vma, flags & FAULT_FLAG_WRITE,
					    flags & FAULT_FLAG_INSTRUCTION,
					    flags & FAULT_FLAG_REMOTE))
		return VM_FAULT_SIGSEGV;

	// 设置cgroup的fault标志为1,表示此时正在进行缺页处理
	if (flags & FAULT_FLAG_USER)
		mem_cgroup_enter_user_fault();

	// 根据是否是巨页，调用不同的处理过程
	if (unlikely(is_vm_hugetlb_page(vma)))
		ret = hugetlb_fault(vma->vm_mm, vma, address, flags);
	else
		ret = __handle_mm_fault(vma, address, flags);

	// cgroup相关的标志设置
	if (flags & FAULT_FLAG_USER) {
		mem_cgroup_exit_user_fault();
		if (task_in_memcg_oom(current) && !(ret & VM_FAULT_OOM))
			mem_cgroup_oom_synchronize(false);
	}

	return ret;
}

static vm_fault_t __handle_mm_fault(struct vm_area_struct *vma,
		unsigned long address, unsigned int flags)
{
	// 缺页处理参数集
	struct vm_fault vmf = {
		.vma = vma,
		.address = address & PAGE_MASK,
		.flags = flags,
		.pgoff = linear_page_index(vma, address),
		.gfp_mask = __get_fault_gfp_mask(vma),
	};
	unsigned int dirty = flags & FAULT_FLAG_WRITE;
	struct mm_struct *mm = vma->vm_mm;
	pgd_t *pgd;
	p4d_t *p4d;
	vm_fault_t ret;

	// 获取合局页面目录项,指向4级目录的基址
	pgd = pgd_offset(mm, address);

	// 获取/建立4级页面目录项，指向pud的基址
	p4d = p4d_alloc(mm, pgd, address);
	if (!p4d)
		return VM_FAULT_OOM;

	// 获取/建立pud页面目录项
	vmf.pud = pud_alloc(mm, p4d, address);
	if (!vmf.pud)
		return VM_FAULT_OOM;

	// todo: 没太看懂
	// 如果还没建立pud映射，而且这个vma可以创建巨页，则创建
	if (pud_none(*vmf.pud) && transparent_hugepage_enabled(vma)) {	
		ret = create_huge_pud(&vmf);
		if (!(ret & VM_FAULT_FALLBACK))
			return ret;
	} else {
		pud_t orig_pud = *vmf.pud;

		barrier();
		// 如果pud是巨页或者设备直接映射，则进入下面处理
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

	// 获取/建立pmd
	vmf.pmd = pmd_alloc(mm, vmf.pud, address);
	if (!vmf.pmd)
		return VM_FAULT_OOM;
	
	// todo: 没看懂
	// 如果还没建立pmd且vma有巨页标志，则建立巨页pmd
	if (pmd_none(*vmf.pmd) && transparent_hugepage_enabled(vma)) {
		ret = create_huge_pmd(&vmf);
		if (!(ret & VM_FAULT_FALLBACK))
			return ret;
	} else {
		pmd_t orig_pmd = *vmf.pmd;

		barrier();
		// 如果是一个被交换出去的pmd
		if (unlikely(is_swap_pmd(orig_pmd))) {
			VM_BUG_ON(thp_migration_supported() &&
					  !is_pmd_migration_entry(orig_pmd));
			// todo: 没看
			if (is_pmd_migration_entry(orig_pmd))
				pmd_migration_entry_wait(mm, vmf.pmd);
			return 0;
		}

		// 如果pmd是巨页或者设备直接映射，则进入下面处理
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

	// 处理pte缺页
	return handle_pte_fault(&vmf);
}

static vm_fault_t handle_pte_fault(struct vm_fault *vmf)
{
	pte_t entry;

	if (unlikely(pmd_none(*vmf->pmd))) {
		// 一般情况很少进入这个分支
		 /**
		 原文注释：
		 把__pte_alloc放在后面，因为有可能会创建巨页，
		 如果现在申请pte，发生并发问题后，很难撤消
		 */
		vmf->pte = NULL;
	} else {
		// 直接映射相关
		if (pmd_devmap_trans_unstable(vmf->pmd))
			return 0;
		// 获取并设置pte项的地址
		// todo: 这个是虚拟地址？
		vmf->pte = pte_offset_map(vmf->pmd, vmf->address);
		vmf->orig_pte = *vmf->pte;

		barrier();

		// todo: 没太看懂
		// 如果还没建立pte，则解除原来pte，并将其置空
		if (pte_none(vmf->orig_pte)) {
			// 在64位上是空操作
			pte_unmap(vmf->pte);
			vmf->pte = NULL;
		}
	}

	// 如果pte为空，则表示还没有建立过映射
	if (!vmf->pte) {
		// 根据有没有vm_ops来新建相应的pte
		// 栈一般走的是vma_is_anonymous
		if (vma_is_anonymous(vmf->vma))
			return do_anonymous_page(vmf);
		else
			// 文件映射一般走的是这个分支
			return do_fault(vmf);
	}

	// 如果pte不在内存里，则将页面换入内存
	if (!pte_present(vmf->orig_pte))
		return do_swap_page(vmf);

	// 如果pte没有保护权限，且本次是由于读写执行引起的缺页，
	// 则直接分配页面后返回
	if (pte_protnone(vmf->orig_pte) && vma_is_accessible(vmf->vma))
		return do_numa_page(vmf);

	vmf->ptl = pte_lockptr(vmf->vma->vm_mm, vmf->pmd);
	spin_lock(vmf->ptl);
	entry = vmf->orig_pte;
	if (unlikely(!pte_same(*vmf->pte, entry)))
		goto unlock;
	
	if (vmf->flags & FAULT_FLAG_WRITE) {
		// 如果是需求是写，但当前pte又不允许写，则会引起COW
		if (!pte_write(entry))
			return do_wp_page(vmf);
		// 如果没有写保护，则标志当前entry为脏
		entry = pte_mkdirty(entry);
	}

	// 标记pte刚被访问过
	entry = pte_mkyoung(entry);
	if (ptep_set_access_flags(vmf->vma, vmf->address, vmf->pte, entry,
				vmf->flags & FAULT_FLAG_WRITE)) {
		// 更新mmu缓存，这对x86来说是空的
		update_mmu_cache(vmf->vma, vmf->address, vmf->pte);
	} else {
		if (vmf->flags & FAULT_栈一般走的是vma_is_anonymousFLAG_WRITE)
			flush_tlb_fix_spurious_fault(vmf->vma, vmf->address);
	}
unlock:
	pte_unmap_unlock(vmf->pte, vmf->ptl);
	return 0;
}
```

pgd项的计算：
```c
// arch/x86/include/asm/pgtable_64_types.h
// 这是64位的定义
#ifdef CONFIG_X86_5LEVEL
// pgdir_shift默认是39，但如果是这个X86_CR4_LA57，则pgdi_shift为48
#define PGDIR_SHIFT	pgdir_shift
#else
#define PGDIR_SHIFT		39
#endif

// 每个pgd里有512个项，则一个pgd占9位
#define PTRS_PER_PGD	512


// arch/x86/include/asm/pgtable.h
#define pgd_index(address) (((address) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))、
#define pgd_offset_pgd(pgd, address) (pgd + pgd_index((address)))

// mm->pgd是本进程的pgd首地址
#define pgd_offset(mm, address) pgd_offset_pgd((mm)->pgd, (address))

// 最终，计算pgd的展开就是下面：
pgd = mm->pgd + (address >> 39) & (512 - 1)

512 = 0x 200 = b 10 0000 0000
512 - 1 = 0x 1ff = b 1 1111 1111

address右移39位，刚好把右边非pgd的位都移出去

所以， (address >> 39) & (512 - 1) 只留下pgd的下标，
这样再加下mm->pgd就是具体的pgd项，也就是下一级页表的首地址
```

第4级页表的计算：
```c
// include/linux/mm.h
static inline p4d_t *p4d_alloc(struct mm_struct *mm, pgd_t *pgd,
		unsigned long address)
{
	// 如果4级页表的页表项还未建立，则先建立之，
	// 否则直接返回它的地址
	return (unlikely(pgd_none(*pgd)) && __p4d_alloc(mm, pgd, address)) ?
		NULL : p4d_offset(pgd, address);
}

int __p4d_alloc(struct mm_struct *mm, pgd_t *pgd, unsigned long address)
{
	// p4d_alloc_one申请一页的内存
	// p4d_t就是unsigned long
	p4d_t *new = p4d_alloc_one(mm, address);
	if (!new)
		return -ENOMEM;

	// 内存屏障
	smp_wmb(); /* See comment in __pte_alloc */

	spin_lock(&mm->page_table_lock);
	if (pgd_present(*pgd))		/* Another has populated it */
		// 如果pgd已经建立了映射，则释放新申请的p4d
		p4d_free(mm, new);
	else
		// 将p4d的值填充到pgd里
		pgd_populate(mm, pgd, new);
	spin_unlock(&mm->page_table_lock);
	return 0;
}

static inline void pgd_populate(struct mm_struct *mm, pgd_t *pgd, p4d_t *p4d)
{
	if (!pgtable_l5_enabled())
		return;
	// todo: 没看懂
	paravirt_alloc_p4d(mm, __pa(p4d) >> PAGE_SHIFT);

	// __pa是将虚拟地址转换成物理地址
	// __pgd是将值与PGD_ALLOWED_BITS做了与操作，屏蔽掉不允许设置的位
	// set_pgd是将值设置到pgd里
	set_pgd(pgd, __pgd(_PAGE_TABLE | __pa(p4d)));
}

static inline p4d_t *p4d_offset(pgd_t *pgd, unsigned long address)
{
	if (!pgtable_l5_enabled())
		return (p4d_t *)pgd;
	// pgd_page_vaddr是将物理地址转换成虚拟地址
	// p4d_index=(address >> P4D_SHIFT) & (PTRS_PER_P4D - 1)和pgd_offset的计算类似
	// P4D_SHIFT是39,所以如果不支持5级面表，则4级目录相当于没有
	// PTRS_PER_P4D初始化是1，会根据条件调整成512
	return (p4d_t *)pgd_page_vaddr(*pgd) + p4d_index(address);
}
```
pud, pmd的计算与p4d类似。

pte_offset_map的计算：
```c
static inline pmdval_t pmd_pfn_mask(pmd_t pmd)
{
	if (native_pmd_val(pmd) & _PAGE_PSE)
		return PHYSICAL_PMD_PAGE_MASK;
	else
		return PTE_PFN_MASK;
}

static inline unsigned long pmd_page_vaddr(pmd_t pmd)
{
	return (unsigned long)__va(pmd_val(pmd) & pmd_pfn_mask(pmd));
}

static inline unsigned long pte_index(unsigned long address)
{
	return (address >> PAGE_SHIFT) & (PTRS_PER_PTE - 1);
}

static inline pte_t *pte_offset_kernel(pmd_t *pmd, unsigned long address)
{
	// pmd指向的就是一个页面的基址的虚拟地址，再加上pte的值，
	// 就是该pte的虚拟地址值
	return (pte_t *)pmd_page_vaddr(*pmd) + pte_index(address);
}

#define pte_offset_map(dir, address) pte_offset_kernel((dir), (address))
```

## 匿名页（栈页）的缺页
```c
static vm_fault_t do_anonymous_page(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct mem_cgroup *memcg;
	struct page *page;
	vm_fault_t ret = 0;
	pte_t entry;

	// VM_SHARED是文件映射，走到这里都是没有vma->vm_ops的
	// 所以如果是文件映射，走到这肯定是错了
	if (vma->vm_flags & VM_SHARED)
		return VM_FAULT_SIGBUS;

	// 申请一页内存当pte，申请过程和前面p4d的过程差不多
	if (pte_alloc(vma->vm_mm, vmf->pmd, vmf->address))
		return VM_FAULT_OOM;

	// todo: 没看懂。判断透明巨页的稳定性
	if (unlikely(pmd_trans_unstable(vmf->pmd)))
		return 0;

	// 如果只是读权限的话，则申请一个全是0的页面
	if (!(vmf->flags & FAULT_FLAG_WRITE) &&
			!mm_forbids_zeropage(vma->vm_mm)) {
		// 创建一个特殊的pte，这个pte会关联到全0上，
		entry = pte_mkspecial(pfn_pte(my_zero_pfn(vmf->address),
						vma->vm_page_prot));
		// 获取虚拟地址pte
		vmf->pte = pte_offset_map_lock(vma->vm_mm, vmf->pmd,
				vmf->address, &vmf->ptl);
		// 如果pte申请失败，则退出
		if (!pte_none(*vmf->pte))
			goto unlock;
		// todo: 没看
		ret = check_stable_address_space(vma->vm_mm);
		if (ret)
			goto unlock;
		
		// 原文注释：把缺页发送到用户空间
		// todo: 没看懂
		if (userfaultfd_missing(vma)) {
			pte_unmap_unlock(vmf->pte, vmf->ptl);
			return handle_userfault(vmf, VM_UFFD_MISSING);
		}
		goto setpte;
	}

	// 申请写的pte

	// prepare是给vma准备struct anon_vma结构，
	// 如果没有则申请，否则直接返回
	if (unlikely(anon_vma_prepare(vma)))
		goto oom;
	// 申请一页内存。todo: highuser是啥？
	page = alloc_zeroed_user_highpage_movable(vma, vmf->address);
	if (!page)
		goto oom;

	// todo: 没看
	if (mem_cgroup_try_charge_delay(page, vma->vm_mm, GFP_KERNEL, &memcg,
					false))
		goto oom_free_page;

	// 设置页是最新的，就是设置一下页的标志
	__SetPageUptodate(page);

	// 生成pte
	entry = mk_pte(page, vma->vm_page_prot);
	if (vma->vm_flags & VM_WRITE)
		// 如果是写，则标志pte的脏和写标志
		entry = pte_mkwrite(pte_mkdirty(entry));

	// 虚拟pte地址
	vmf->pte = pte_offset_map_lock(vma->vm_mm, vmf->pmd, vmf->address,
			&vmf->ptl);
	// 如果为空，则失败，直接释放
	if (!pte_none(*vmf->pte))
		goto release;

	// todo: 检查地址稳定性？
	ret = check_stable_address_space(vma->vm_mm);
	if (ret)
		goto release;

	// 和读的pte流程一样
	if (userfaultfd_missing(vma)) {
		pte_unmap_unlock(vmf->pte, vmf->ptl);
		mem_cgroup_cancel_charge(page, memcg, false);
		put_page(page);
		return handle_userfault(vmf, VM_UFFD_MISSING);
	}

	// 增加mm的MM_ANONPAGES计数器
	inc_mm_counter_fast(vma->vm_mm, MM_ANONPAGES);

	// 将新申请的页设为匿名页
	page_add_new_anon_rmap(page, vma, vmf->address, false);

	// todo: 控制组没看
	mem_cgroup_commit_charge(page, memcg, false, false);
	lru_cache_add_active_or_unevictable(page, vma);
setpte:

	// 把entry赋值给vmf-pte
	set_pte_at(vma->vm_mm, vmf->address, vmf->pte, entry);

	// 对x86来说这句是空的
	update_mmu_cache(vma, vmf->address, vmf->pte);
unlock:
	pte_unmap_unlock(vmf->pte, vmf->ptl);
	return ret;
release:
	mem_cgroup_cancel_charge(page, memcg, false);
	put_page(page);
	goto unlock;
oom_free_page:
	put_page(page);
oom:
	return VM_FAULT_OOM;
}
```

pte_mkspecial:

```c
entry = pte_mkspecial(pfn_pte(my_zero_pfn(vmf->address),
						vma->vm_page_prot));

extern unsigned long empty_zero_page[PAGE_SIZE / sizeof(unsigned long)]
	__visible;
#define ZERO_PAGE(vaddr) (virt_to_page(empty_zero_page))

static int __init init_zero_pfn(void)
{
	//获取0页地址
	zero_pfn = page_to_pfn(ZERO_PAGE(0));
	return 0;
}
core_initcall(init_zero_pfn);

static inline unsigned long my_zero_pfn(unsigned long addr)
{
	extern unsigned long zero_pfn;
	return zero_pfn;
}


static inline pte_t pfn_pte(unsigned long page_nr, pgprot_t pgprot)
{
	// 获取页的物理地址
	phys_addr_t pfn = (phys_addr_t)page_nr << PAGE_SHIFT;

	// 标志位
	pfn ^= protnone_mask(pgprot_val(pgprot));
	pfn &= PTE_PFN_MASK;

	// 生成一个pte
	return __pte(pfn | check_pgprot(pgprot));
}

static inline pte_t pte_set_flags(pte_t pte, pteval_t set)
{
	pteval_t v = native_pte_val(pte);

	return native_make_pte(v | set);
}

// todo: 没看懂。设置了一个特殊标志？
static inline pte_t pte_mkspecial(pte_t pte)
{
	// todo: _PAGE_SPECIAL是什么意思
	return pte_set_flags(pte, _PAGE_SPECIAL);
}
```

