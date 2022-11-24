# 基本框架

二级页表
```c
// pgtable-2level_types.h
#define PGDIR_SHIFT	22
#define PTRS_PER_PGD	1024


/*
 * the i386 is two-level, so we don't really have any
 * PMD directory physically.
 */

#define PTRS_PER_PTE	1024

/* This covers all VMSPLIT_* and VMSPLIT_*_OPT variants */
#define PGD_KERNEL_START	(CONFIG_PAGE_OFFSET >> PGDIR_SHIFT)
```
在二级页表里并没有定义PMD_SHIFT, PMD_SHIFT通过在pgtable-no{p4d, pud, pmd}.h这些头文件里定义的。

三级页表
```c
// pgtable-3level_types.h

/*
 * PGDIR_SHIFT determines what a top-level page table entry can map
 */
#define PGDIR_SHIFT	30
#define PTRS_PER_PGD	4

/*
 * PMD_SHIFT determines the size of the area a middle-level
 * page table can map
 */
#define PMD_SHIFT	21
#define PTRS_PER_PMD	512

/*
 * entries per page directory level
 */
#define PTRS_PER_PTE	512

#define MAX_POSSIBLE_PHYSMEM_BITS	36
#define PGD_KERNEL_START	(CONFIG_PAGE_OFFSET >> PGDIR_SHIFT)
```
目前 pgtable-2level_types.h， pgtable-3level_types.h，被包含在pgtable_32_types.h里。

32位
```c
// pgtable_32_types.h
/*
 * The Linux x86 paging architecture is 'compile-time dual-mode', it
 * implements both the traditional 2-level x86 page tables and the
 * newer 3-level PAE-mode page tables.
 */
#ifdef CONFIG_X86_PAE
# include <asm/pgtable-3level_types.h>
# define PMD_SIZE	(1UL << PMD_SHIFT)
# define PMD_MASK	(~(PMD_SIZE - 1))
#else
# include <asm/pgtable-2level_types.h>
#endif

#define pgtable_l5_enabled() 0

#define PGDIR_SIZE	(1UL << PGDIR_SHIFT)
#define PGDIR_MASK	(~(PGDIR_SIZE - 1))
```

64位，目前基本上都是64位
```c
// pgtable_64_types.h
#ifdef CONFIG_X86_5LEVEL

// 这里是5级页表的定义

/*
 * PGDIR_SHIFT determines what a top-level page table entry can map

 * pgdir_shift默认初始化为1.
 * pgdir_shift在check_la57_support里设置，根据有无cr4寄存器有无X86_CR4_LA57
 * 标志来设置，如果有这个标志，则把pgdir_shift设置为48
 */
#define PGDIR_SHIFT	pgdir_shift
#define PTRS_PER_PGD	512

/*
 * 4th level page in 5-level paging case
 */
#define P4D_SHIFT		39
#define MAX_PTRS_PER_P4D	512
// ptrs_per_p4d同pgdir_shift，如果有X86_CR4_LA57则设置成512, 否则为1
#define PTRS_PER_P4D		ptrs_per_p4d
#define P4D_SIZE		(_AC(1, UL) << P4D_SHIFT)
#define P4D_MASK		(~(P4D_SIZE - 1))

#define MAX_POSSIBLE_PHYSMEM_BITS	52

#else /* CONFIG_X86_5LEVEL */

// 这里是4级的定义
/*
 * PGDIR_SHIFT determines what a top-level page table entry can map
 */
#define PGDIR_SHIFT		39 // pgd_offset占9位
#define PTRS_PER_PGD		512
#define MAX_PTRS_PER_P4D	1

#endif /* CONFIG_X86_5LEVEL */

/*
 * 3rd level page
 */
#define PUD_SHIFT	30	// pud_offset占9位
#define PTRS_PER_PUD	512

/*
 * PMD_SHIFT determines the size of the area a middle-level
 * page table can map
 */
#define PMD_SHIFT	21	// pmd_offset占9位
#define PTRS_PER_PMD	512

/*
 * entries per page directory level
 */
#define PTRS_PER_PTE	512

#define PMD_SIZE	(_AC(1, UL) << PMD_SHIFT)
#define PMD_MASK	(~(PMD_SIZE - 1))
#define PUD_SIZE	(_AC(1, UL) << PUD_SHIFT)
#define PUD_MASK	(~(PUD_SIZE - 1))
#define PGDIR_SIZE	(_AC(1, UL) << PGDIR_SHIFT)
#define PGDIR_MASK	(~(PGDIR_SIZE - 1))
```

pgtable_32_types.h和pgtable_64_types.h是根据CONFIG_X86_64决定的:
```c
#ifdef CONFIG_X86_64
#include <asm/page_64_types.h>
#define IOREMAP_MAX_ORDER       (PUD_SHIFT)
#else
#include <asm/page_32_types.h>
#define IOREMAP_MAX_ORDER       (PMD_SHIFT)
#endif	/* CONFIG_X86_64 */
```

下面的这些宏都是64位的定义

page_offset
```c
#define __PAGE_OFFSET_BASE_L5	_AC(0xff11000000000000, UL)
#define __PAGE_OFFSET_BASE_L4	_AC(0xffff888000000000, UL)

#ifdef CONFIG_DYNAMIC_MEMORY_LAYOUT // 动态内存布局
#define __PAGE_OFFSET           page_offset_base
#else
#define __PAGE_OFFSET           __PAGE_OFFSET_BASE_L4
#endif /* CONFIG_DYNAMIC_MEMORY_LAYOUT */

#define PAGE_OFFSET		((unsigned long)__PAGE_OFFSET)

#ifndef __pa
#define __pa(x)		__phys_addr((unsigned long)(x))
#endif

#ifndef __va
#define __va(x)			((void *)((unsigned long)(x)+PAGE_OFFSET))
#endif

#define __START_KERNEL_map	_AC(0xffffffff80000000, UL)

/* See Documentation/x86/x86_64/mm.rst for a description of the memory map. */

#define __PHYSICAL_MASK_SHIFT	52

#ifdef CONFIG_X86_5LEVEL
#define __VIRTUAL_MASK_SHIFT	(pgtable_l5_enabled() ? 56 : 47)
#else
#define __VIRTUAL_MASK_SHIFT	47
#endif

/*
 * User space process size.  This is the first address outside the user range.
 * There are a few constraints that determine this:
 *
 * On Intel CPUs, if a SYSCALL instruction is at the highest canonical
 * address, then that syscall will enter the kernel with a
 * non-canonical return address, and SYSRET will explode dangerously.
 * We avoid this particular problem by preventing anything executable
 * from being mapped at the maximum canonical address.
 *
 * On AMD CPUs in the Ryzen family, there's a nasty bug in which the
 * CPUs malfunction if they execute code from the highest canonical page.
 * They'll speculate right off the end of the canonical space, and
 * bad things happen.  This is worked around in the same way as the
 * Intel problem.
 *
 * With page table isolation enabled, we map the LDT in ... [stay tuned]
 */
#define TASK_SIZE_MAX	((_AC(1,UL) << __VIRTUAL_MASK_SHIFT) - PAGE_SIZE)

#define DEFAULT_MAP_WINDOW	((1UL << 47) - PAGE_SIZE)

/* This decides where the kernel will search for a free chunk of vm
 * space during mmap's.
 */
#define IA32_PAGE_OFFSET	((current->personality & ADDR_LIMIT_3GB) ? \
					0xc0000000 : 0xFFFFe000)

#define TASK_SIZE_LOW		(test_thread_flag(TIF_ADDR32) ? \
					IA32_PAGE_OFFSET : DEFAULT_MAP_WINDOW)
#define TASK_SIZE		(test_thread_flag(TIF_ADDR32) ? \
					IA32_PAGE_OFFSET : TASK_SIZE_MAX)
#define TASK_SIZE_OF(child)	((test_tsk_thread_flag(child, TIF_ADDR32)) ? \
					IA32_PAGE_OFFSET : TASK_SIZE_MAX)

#define STACK_TOP		TASK_SIZE_LOW
#define STACK_TOP_MAX		TASK_SIZE_MAX


// ----------
#ifdef CONFIG_DEBUG_VIRTUAL // 这个配置一般是关的
extern unsigned long __phys_addr(unsigned long);
extern unsigned long __phys_addr_symbol(unsigned long);
#else
#define __phys_addr(x)		__phys_addr_nodebug(x)
#define __phys_addr_symbol(x) \
	((unsigned long)(x) - __START_KERNEL_map + phys_base)
#endif

static inline unsigned long __phys_addr_nodebug(unsigned long x)
{
	unsigned long y = x - __START_KERNEL_map;

	/* use the carry flag to determine if x was < __START_KERNEL_map */
	x = y + ((x > y) ? phys_base : (__START_KERNEL_map - PAGE_OFFSET));

	return x;
}
```