## oom主流程
```c
bool out_of_memory(struct oom_control *oc)
{
	unsigned long freed = 0;

	// oom被禁用
	if (oom_killer_disabled)
		return false;

	if (!is_memcg_oom(oc)) {
		// 通知监听oom人
		blocking_notifier_call_chain(&oom_notify_list, 0, &freed);
		// 如果其它人释放了一些内存就不用启动oom-killer了
		if (freed > 0)
			/* Got some memory back in the last second. */
			return true;
	}

	// 当前进程将要释放内存，把它做标记,然后直接退出
	if (task_will_free_mem(current)) {
		// 标志当前进程victim
		mark_oom_victim(current);
		// 这个会唤醒oom raper
		queue_oom_reaper(current);
		return true;
	}

	// oom killer不会补偿非io请求
	if (oc->gfp_mask && !(oc->gfp_mask & __GFP_FS) && !is_memcg_oom(oc))
		return true;

	/*
	 * Check if there were limitations on the allocation (only relevant for
	 * NUMA and memcg) that may require different handling.
	 */
	oc->constraint = constrained_alloc(oc);
	if (oc->constraint != CONSTRAINT_MEMORY_POLICY)
		oc->nodemask = NULL;

	// 根据sysctl_panic_on_oom的设置，决定是否要直接panic
	check_panic_on_oom(oc);

	// sysctl_oom_kill_allocating_task是oom的时候先杀死申请内存的那个进程
	// 当前进程也不能被标记最高优先级OOM_SCORE_ADJ_MIN，
	// 如果符合这些条件就杀死当前进程
	if (!is_memcg_oom(oc) && sysctl_oom_kill_allocating_task &&
	    current->mm && !oom_unkillable_task(current) &&
	    oom_cpuset_eligible(current, oc) &&
	    current->signal->oom_score_adj != OOM_SCORE_ADJ_MIN) {
		get_task_struct(current);
		oc->chosen = current;
		oom_kill_process(oc, "Out of memory (oom_kill_allocating_task)");
		return true;
	}

	// 选一个进程杀死
	select_bad_process(oc);
	/* Found nothing?!?! */
	if (!oc->chosen) {
		// 走到这儿是没选到进程

		dump_header(oc, NULL);
		pr_warn("Out of memory and no killable processes...\n");

		if (!is_sysrq_oom(oc) && !is_memcg_oom(oc))
			// 走到这作表示真的是系统内存不足，也不能杀死进程，那只能panic了
			panic("System is deadlocked on memory\n");
	}
	if (oc->chosen && oc->chosen != (void *)-1UL)
		// 有选到的，就杀死这个进程
		oom_kill_process(oc, !is_memcg_oom(oc) ? "Out of memory" :
				 "Memory cgroup out of memory");
	return !!oc->chosen;
}

static bool task_will_free_mem(struct task_struct *task)
{
	struct mm_struct *mm = task->mm;
	struct task_struct *p;
	bool ret = true;

	/*
	 * Skip tasks without mm because it might have passed its exit_mm and
	 * exit_oom_victim. oom_reaper could have rescued that but do not rely
	 * on that for now. We can consider find_lock_task_mm in future.
	 */
	if (!mm)
		return false;

	if (!__task_will_free_mem(task))
		return false;

	/*
	 * This task has already been drained by the oom reaper so there are
	 * only small chances it will free some more
	 */
	if (test_bit(MMF_OOM_SKIP, &mm->flags))
		return false;

	if (atomic_read(&mm->mm_users) <= 1)
		return true;

	/*
	 * Make sure that all tasks which share the mm with the given tasks
	 * are dying as well to make sure that a) nobody pins its mm and
	 * b) the task is also reapable by the oom reaper.
	 */
	rcu_read_lock();
	for_each_process(p) {
		if (!process_shares_mm(p, mm))
			continue;
		if (same_thread_group(task, p))
			continue;
		ret = __task_will_free_mem(p);
		if (!ret)
			break;
	}
	rcu_read_unlock();

	return ret;
}

 */
static void mark_oom_victim(struct task_struct *tsk)
{
	struct mm_struct *mm = tsk->mm;

	WARN_ON(oom_killer_disabled);
	// 设置memdie标志
	if (test_and_set_tsk_thread_flag(tsk, TIF_MEMDIE))
		return;

	// what?
	if (!cmpxchg(&tsk->signal->oom_mm, NULL, mm)) {
		mmgrab(tsk->signal->oom_mm);
		set_bit(MMF_OOM_VICTIM, &mm->flags);
	}

	// 如果进程被冻结,则解冻
	__thaw_task(tsk);
	// 增加oom_victims计数
	atomic_inc(&oom_victims);
	trace_mark_victim(tsk->pid);
}

#define OOM_REAPER_DELAY (2*HZ)
static void queue_oom_reaper(struct task_struct *tsk)
{
	/* mm is already queued? */
	if (test_and_set_bit(MMF_OOM_REAP_QUEUED, &tsk->signal->oom_mm->flags))
		return;

	get_task_struct(tsk);
	timer_setup(&tsk->oom_reaper_timer, wake_oom_reaper, 0);
	tsk->oom_reaper_timer.expires = jiffies + OOM_REAPER_DELAY;
	add_timer(&tsk->oom_reaper_timer);
}

static void check_panic_on_oom(struct oom_control *oc)
{
	// 没有使能
	if (likely(!sysctl_panic_on_oom))
		return;
	
	// panic_on_oom == 1 只影响 CONSTRAINT_NONE
	if (sysctl_panic_on_oom != 2) {
		if (oc->constraint != CONSTRAINT_NONE)
			return;
	}
	// 不处理sysrq
	if (is_sysrq_oom(oc))
		return;
	// panic
	dump_header(oc, NULL);
	panic("Out of memory: %s panic_on_oom is enabled\n",
		sysctl_panic_on_oom == 2 ? "compulsory" : "system-wide");
}

```
## 选一个进程杀死
```c
static void select_bad_process(struct oom_control *oc)
{
	oc->chosen_points = LONG_MIN;

	if (is_memcg_oom(oc))
		// cgroup相关
		mem_cgroup_scan_tasks(oc->memcg, oom_evaluate_task, oc);
	else {
		// 一般进程都走这个分支
		struct task_struct *p;

		rcu_read_lock();
		for_each_process(p)
			// 返回正数表示出错，返回0，表示选了一个进程
			if (oom_evaluate_task(p, oc))
				break;
		rcu_read_unlock();
	}
}

/*
 * Details of the page allocation that triggered the oom killer that are used to
 * determine what should be killed.
 */
struct oom_control {
	/* Used to determine cpuset */
	struct zonelist *zonelist;

	/* Used to determine mempolicy */
	nodemask_t *nodemask;

	/* Memory cgroup in which oom is invoked, or NULL for global oom */
	struct mem_cgroup *memcg;

	/* Used to determine cpuset and node locality requirement */
	const gfp_t gfp_mask;

	/*
	 * order == -1 means the oom kill is required by sysrq, otherwise only
	 * for display purposes.
	 */
	const int order;

	/* Used by oom implementation, do not set */
	unsigned long totalpages;
	struct task_struct *chosen;
	long chosen_points;

	/* Used to print the constraint info. */
	enum oom_constraint constraint;
};

static int oom_evaluate_task(struct task_struct *task, void *arg)
{
	struct oom_control *oc = arg;
	long points;

	// init进程和内核线程不可杀
	if (oom_unkillable_task(task))
		goto next;

	// oom_cpuset_eligible是判断task的内存是否和current有相交
	if (!is_memcg_oom(oc) && !oom_cpuset_eligible(task, oc))
		goto next;

	// task本身是oom的受害者，则中止或者跳过？
	if (!is_sysrq_oom(oc) && tsk_is_oom_victim(task)) {
		if (test_bit(MMF_OOM_SKIP, &task->signal->oom_mm->flags))
			goto next;
		goto abort;
	}

	// 如果task已经被标记为killed，则把分数设为最大
	if (oom_task_origin(task)) {
		points = LONG_MAX;
		goto select;
	}

	// 计数这个进程的分数
	points = oom_badness(task, oc->totalpages);

	// 如果分数比上一次选的小，则继续下一个
	if (points == LONG_MIN || points < oc->chosen_points)
		goto next;

select:
	// 走到这儿，表示当前task的分数大小上一个已经选择的

	// 递减上一个已经选择的task计数
	if (oc->chosen)
		put_task_struct(oc->chosen);
	
	// 设置新选择的task
	get_task_struct(task);
	oc->chosen = task;
	oc->chosen_points = points;
next:
	return 0;
abort:
	// 中止的话，递减已经选择的task计数
	if (oc->chosen)
		put_task_struct(oc->chosen);
	oc->chosen = (void *)-1UL;
	return 1;
}

static bool oom_unkillable_task(struct task_struct *p)
{
	// init进程
	if (is_global_init(p))
		return true;
	// 内核线程
	if (p->flags & PF_KTHREAD)
		return true;
	return false;
}

static inline int is_global_init(struct task_struct *tsk)
{
	// init进程组id是1
	return task_tgid_nr(tsk) == 1;
}

static bool oom_cpuset_eligible(struct task_struct *start,
				struct oom_control *oc)
{
	struct task_struct *tsk;
	bool ret = false;
	const nodemask_t *mask = oc->nodemask;

	// todo: 后面看
	if (is_memcg_oom(oc))
		return true;

	rcu_read_lock();
	for_each_thread(start, tsk) {
		if (mask) {
			/*
			 * If this is a mempolicy constrained oom, tsk's
			 * cpuset is irrelevant.  Only return true if its
			 * mempolicy intersects current, otherwise it may be
			 * needlessly killed.
			 */
			ret = mempolicy_nodemask_intersects(tsk, mask);
		} else {
			// 当前进程的内存和task的能否相交
			ret = cpuset_mems_allowed_intersects(current, tsk);
		}
		if (ret)
			break;
	}
	rcu_read_unlock();

	return ret;
}

static inline bool is_sysrq_oom(struct oom_control *oc)
{
	return oc->order == -1;
}

static inline bool tsk_is_oom_victim(struct task_struct * tsk)
{
	return tsk->signal->oom_mm;
}

static inline bool oom_task_origin(const struct task_struct *p)
{
	return p->signal->oom_flag_origin;
}

```

## 计算分数
```c
// 返回的分高，则越容易被杀
long oom_badness(struct task_struct *p, unsigned long totalpages)
{
	long points;
	long adj;


	// 不可杀的应用返回最低分
	if (oom_unkillable_task(p))
		return LONG_MIN;

	// 找到本进程组里有mm的那个task
	p = find_lock_task_mm(p);
	// 如果都找不到说明是内核线程
	if (!p)
		return LONG_MIN;

	// OOM_SCORE_ADJ_MIN为不可杀进程
	// MMF_OOM_SKIP表示这个进程正在oom
	// in_vfork表示正在进行vfork调用
	adj = (long)p->signal->oom_score_adj;
	// OOM_SCORE_ADJ_MIN=-1000
	if (adj == OOM_SCORE_ADJ_MIN ||
			test_bit(MMF_OOM_SKIP, &p->mm->flags) ||
			in_vfork(p)) {
		task_unlock(p);
		return LONG_MIN;
	}

	// 已映射的内存 + 交换的内存 + 页表的映射
	points = get_mm_rss(p->mm) + get_mm_counter(p->mm, MM_SWAPENTS) +
		mm_pgtables_bytes(p->mm) / PAGE_SIZE;
	task_unlock(p);

	// 对oom_score_adj进行标准化
	adj *= totalpages / 1000;
	points += adj;

	return points;
}

struct task_struct *find_lock_task_mm(struct task_struct *p)
{
	struct task_struct *t;

	rcu_read_lock();

	for_each_thread(p, t) {
		task_lock(t);
		if (likely(t->mm))
			goto found;
		task_unlock(t);
	}
	t = NULL;
found:
	rcu_read_unlock();

	return t;
}
	
static inline bool in_vfork(struct task_struct *tsk)
{
	bool ret;

	rcu_read_lock();
	// vfork用vfork_done来等待子进程完成，所以有vfork_done肯定是正在进行vfork
	ret = tsk->vfork_done &&
			rcu_dereference(tsk->real_parent)->mm == tsk->mm;
	rcu_read_unlock();

	return ret;
}

static inline unsigned long get_mm_rss(struct mm_struct *mm)
{
	return get_mm_counter(mm, MM_FILEPAGES) +
		get_mm_counter(mm, MM_ANONPAGES) +
		get_mm_counter(mm, MM_SHMEMPAGES);
}
```

## oom_kill_process
```c
static void oom_kill_process(struct oom_control *oc, const char *message)
{
	// 要释放的进程
	struct task_struct *p = oc->chosen;
	unsigned int points = oc->chosen_points;
	struct task_struct *victim = p;
	struct task_struct *child;
	struct task_struct *t;
	struct mem_cgroup *oom_group;
	unsigned int victim_points = 0;
	static DEFINE_RATELIMIT_STATE(oom_global_rs, DEFAULT_RATELIMIT_INTERVAL,
					      DEFAULT_RATELIMIT_BURST);
	bool suppress_print = false;

	/*
	 * If the task is already exiting, don't alarm the sysadmin or kill
	 * its children or threads, just give it access to memory reserves
	 * so it can die quickly
	 */
	task_lock(p);
	
	// 有可能会释放内存
	if (task_will_free_mem(p)) {
		mark_oom_victim(p);
		wake_oom_reaper(p);
		task_unlock(p);
		put_task_struct(p);
		return;
	}
	task_unlock(p);

	if (is_memcg_oom(oc) && __ratelimit(&oom_memcg_rs))
		dump_memcg_header(oc, p);
	else if (!is_memcg_oom(oc) && __ratelimit(&oom_global_rs))
		dump_global_header(oc, p);

	/*
	 * Prevent too much printk to result in softlock in memory cgroup oom.
	 * Meanwhile, Use printk_ratelimit_state rather than oom_memcg_rs to
	 * not suppress important print message overly.
	 */
#ifdef CONFIG_PRINTK
	if (is_memcg_oom(oc) && __ratelimit(&printk_ratelimit_state))
		suppress_print = true;
#endif

	if (!suppress_print)
		pr_err("%s: Kill process %d (%s) score %u or sacrifice child\n",
			message, task_pid_nr(p), p->comm, points);

	/*
	 * If any of p's children has a different mm and is eligible for kill,
	 * the one with the highest oom_badness() score is sacrificed for its
	 * parent.  This attempts to lose the minimal amount of work done while
	 * still freeing memory.
	 */
	read_lock(&tasklist_lock);

	/*
	 * The task 'p' might have already exited before reaching here. The
	 * put_task_struct() will free task_struct 'p' while the loop still try
	 * to access the field of 'p', so, get an extra reference.
	 */
	get_task_struct(p);
	for_each_thread(p, t) {
		list_for_each_entry(child, &t->children, sibling) {
			unsigned int child_points;

			if (process_shares_mm(child, p->mm))
				continue;
			/*
			 * oom_badness() returns 0 if the thread is unkillable
			 */
			child_points = oom_badness(child,
				oc->memcg, oc->nodemask, oc->totalpages);
			if (child_points > victim_points) {
				put_task_struct(victim);
				victim = child;
				victim_points = child_points;
				get_task_struct(victim);
			}
		}
	}
	put_task_struct(p);
	read_unlock(&tasklist_lock);

	/*
	 * Do we need to kill the entire memory cgroup?
	 * Or even one of the ancestor memory cgroups?
	 * Check this out before killing the victim task.
	 */
	oom_group = mem_cgroup_get_oom_group(victim, oc->memcg);

	__oom_kill_process(victim, is_memcg_oom(oc));

	/*
	 * If necessary, kill all tasks in the selected memory cgroup.
	 */
	if (oom_group) {
		mem_cgroup_print_oom_group(oom_group);
		mem_cgroup_scan_tasks(oom_group, oom_kill_memcg_member, NULL);
		mem_cgroup_put(oom_group);
	}
}
```

## oom_reap_task_mm
```c
static bool oom_reap_task_mm(struct task_struct *tsk, struct mm_struct *mm)
{
	bool ret = true;

	// 加锁失败
	if (!down_read_trylock(&mm->mmap_sem)) {
		trace_skip_task_reaping(tsk->pid);
		return false;
	}

	// 要跳过它
	if (test_bit(MMF_OOM_SKIP, &mm->flags)) {
		trace_skip_task_reaping(tsk->pid);
		goto out_unlock;
	}

	trace_start_task_reaping(tsk->pid);

	// 回收内存
	ret = __oom_reap_task_mm(mm);
	if (!ret)
		goto out_finish;

	pr_info("oom_reaper: reaped process %d (%s), now anon-rss:%lukB, file-rss:%lukB, shmem-rss:%lukB\n",
			task_pid_nr(tsk), tsk->comm,
			K(get_mm_counter(mm, MM_ANONPAGES)),
			K(get_mm_counter(mm, MM_FILEPAGES)),
			K(get_mm_counter(mm, MM_SHMEMPAGES)));
out_finish:
	trace_finish_task_reaping(tsk->pid);
out_unlock:
	up_read(&mm->mmap_sem);

	return ret;
}

static inline unsigned long get_mm_counter(struct mm_struct *mm, int member)
{
	long val = atomic_long_read(&mm->rss_stat.count[member]);

#ifdef SPLIT_RSS_COUNTING
	/*
	 * counter is updated in asynchronous manner and may go to minus.
	 * But it's never be expected number for users.
	 */
	if (val < 0)
		val = 0;
#endif
	return (unsigned long)val;
}

bool __oom_reap_task_mm(struct mm_struct *mm)
{
	struct vm_area_struct *vma;
	bool ret = true;

	// 标记内存不再稳定
	set_bit(MMF_UNSTABLE, &mm->flags);

	for (vma = mm->mmap ; vma; vma = vma->vm_next) {
		// 特殊页跳过
		if (!can_madv_lru_vma(vma))
			continue;

		// 匿名页 || 非共享
		if (vma_is_anonymous(vma) || !(vma->vm_flags & VM_SHARED)) {
			const unsigned long start = vma->vm_start;
			const unsigned long end = vma->vm_end;
			struct mmu_gather tlb;

			tlb_gather_mmu(&tlb, mm, start, end);
			// 通知其它人start内存不可用了
			if (mmu_notifier_invalidate_range_start_nonblock(mm, start, end)) {
				tlb_finish_mmu(&tlb, start, end);
				ret = false;
				continue;
			}
			// 解除映射
			unmap_page_range(&tlb, vma, start, end, NULL);
			// 通知其它人end内存不可用了
			mmu_notifier_invalidate_range_end(mm, start, end);
			tlb_finish_mmu(&tlb, start, end);
		}
	}

	return ret;
}

static inline bool can_madv_lru_vma(struct vm_area_struct *vma)
{
	// VM_PFNMAP: 没有物理内存映射
	return !(vma->vm_flags & (VM_LOCKED|VM_HUGETLB|VM_PFNMAP));
}

void unmap_page_range(struct mmu_gather *tlb,
			     struct vm_area_struct *vma,
			     unsigned long addr, unsigned long end,
			     struct zap_details *details)
{
	pgd_t *pgd;
	unsigned long next;

	BUG_ON(addr >= end);
	tlb_start_vma(tlb, vma);
	pgd = pgd_offset(vma->vm_mm, addr);
	do {
		next = pgd_addr_end(addr, end);
		// pgd没映射
		if (pgd_none_or_clear_bad(pgd))
			continue;

		next = zap_p4d_range(tlb, vma, pgd, addr, next, details);
	} while (pgd++, addr = next, addr != end);
	tlb_end_vma(tlb, vma);
}

static inline unsigned long zap_p4d_range(struct mmu_gather *tlb,
				struct vm_area_struct *vma, pgd_t *pgd,
				unsigned long addr, unsigned long end,
				struct zap_details *details)
{
	p4d_t *p4d;
	unsigned long next;

	p4d = p4d_offset(pgd, addr);
	do {
		next = p4d_addr_end(addr, end);
		// p4d未映射
		if (p4d_none_or_clear_bad(p4d))
			continue;
		next = zap_pud_range(tlb, vma, p4d, addr, next, details);
	} while (p4d++, addr = next, addr != end);

	return addr;
}

static inline unsigned long zap_pud_range(struct mmu_gather *tlb,
				struct vm_area_struct *vma, p4d_t *p4d,
				unsigned long addr, unsigned long end,
				struct zap_details *details)
{
	pud_t *pud;
	unsigned long next;

	pud = pud_offset(p4d, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_trans_huge(*pud) || pud_devmap(*pud)) {
			if (next - addr != HPAGE_PUD_SIZE) {
				VM_BUG_ON_VMA(!rwsem_is_locked(&tlb->mm->mmap_sem), vma);
				split_huge_pud(vma, pud, addr);
			} else if (zap_huge_pud(tlb, vma, pud, addr))
				goto next;
			/* fall through */
		}
		// pud未映射
		if (pud_none_or_clear_bad(pud))
			continue;
		next = zap_pmd_range(tlb, vma, pud, addr, next, details);
next:
		cond_resched();
	} while (pud++, addr = next, addr != end);

	return addr;
}

static inline unsigned long zap_pmd_range(struct mmu_gather *tlb,
				struct vm_area_struct *vma, pud_t *pud,
				unsigned long addr, unsigned long end,
				struct zap_details *details)
{
	pmd_t *pmd;
	unsigned long next;

	pmd = pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (is_swap_pmd(*pmd) || pmd_trans_huge(*pmd) || pmd_devmap(*pmd)) {
			if (next - addr != HPAGE_PMD_SIZE)
				__split_huge_pmd(vma, pmd, addr, false, NULL);
			else if (zap_huge_pmd(tlb, vma, pmd, addr))
				goto next;
			/* fall through */
		} else if (details && details->single_page &&
			   PageTransCompound(details->single_page) &&
			   next - addr == HPAGE_PMD_SIZE && pmd_none(*pmd)) {
			spinlock_t *ptl = pmd_lock(tlb->mm, pmd);
			/*
			 * Take and drop THP pmd lock so that we cannot return
			 * prematurely, while zap_huge_pmd() has cleared *pmd,
			 * but not yet decremented compound_mapcount().
			 */
			spin_unlock(ptl);
		}

		// 没有映射
		if (pmd_none_or_trans_huge_or_clear_bad(pmd))
			goto next;
		next = zap_pte_range(tlb, vma, pmd, addr, next, details);
next:
		cond_resched();
	} while (pmd++, addr = next, addr != end);

	return addr;
}

static unsigned long zap_pte_range(struct mmu_gather *tlb,
				struct vm_area_struct *vma, pmd_t *pmd,
				unsigned long addr, unsigned long end,
				struct zap_details *details)
{
	struct mm_struct *mm = tlb->mm;
	int force_flush = 0;
	int rss[NR_MM_COUNTERS];
	spinlock_t *ptl;
	pte_t *start_pte;
	pte_t *pte;
	swp_entry_t entry;

	tlb_remove_check_page_size_change(tlb, PAGE_SIZE);
again:
	init_rss_vec(rss);
	start_pte = pte_offset_map_lock(mm, pmd, addr, &ptl);
	pte = start_pte;
	flush_tlb_batched_pending(mm);
	arch_enter_lazy_mmu_mode();
	do {
		pte_t ptent = *pte;
		// pte没映射
		if (pte_none(ptent))
			continue;

		if (pte_present(ptent)) {
			// pte已映射
			struct page *page;

			// pte转成page
			page = _vm_normal_page(vma, addr, ptent, true);
			if (unlikely(details) && page) {
				/*
				 * unmap_shared_mapping_pages() wants to
				 * invalidate cache without truncating:
				 * unmap shared but keep private pages.
				 */
				if (details->check_mapping &&
				    details->check_mapping != page_rmapping(page))
					continue;

				/*
				 * unmap_mapping_zeropages() only unmaps zero
				 * pages filled in the VMA. Page cache should
				 * not be unmapped.
				 */
				if (unlikely(details->flags & ZAP_ZEROPAGE))
					continue;
			}
			// 清除pte?
			ptent = ptep_get_and_clear_full(mm, addr, pte,
							tlb->fullmm);
			tlb_remove_tlb_entry(tlb, pte, addr);
			if (unlikely(!page)) {
				if (unlikely(details && (details->flags & ZAP_ZEROPAGE)))
					force_flush = 1;
				continue;
			}

			// 非匿名页
			if (!PageAnon(page)) {
				// 若脏标脏
				if (pte_dirty(ptent)) {
					force_flush = 1;
					set_page_dirty(page);
				}
				// 若访问,则标访问
				if (pte_young(ptent) &&
				    likely(!(vma->vm_flags & VM_SEQ_READ)))
					mark_page_accessed(page);
			}
			// 递减页面对应类型的计数器
			// mm_counter返回页面类型
			rss[mm_counter(page)]--;
			// 移除映射
			page_remove_rmap(page, false);
			if (unlikely(page_mapcount(page) < 0))
				print_bad_pte(vma, addr, ptent, page);
			if (unlikely(__tlb_remove_page(tlb, page))) {
				force_flush = 1;
				addr += PAGE_SIZE;
				break;
			}
			continue;
		}

		entry = pte_to_swp_entry(ptent);
		if (non_swap_entry(entry) && is_device_private_entry(entry)) {
			struct page *page = device_private_entry_to_page(entry);

			if (unlikely(details && details->check_mapping)) {
				/*
				 * unmap_shared_mapping_pages() wants to
				 * invalidate cache without truncating:
				 * unmap shared but keep private pages.
				 */
				if (details->check_mapping !=
				    page_rmapping(page))
					continue;
			}

			pte_clear_not_present_full(mm, addr, pte, tlb->fullmm);
			rss[mm_counter(page)]--;
			page_remove_rmap(page, false);
			put_page(page);
			continue;
		}

		entry = pte_to_swp_entry(ptent);
		if (!non_swap_entry(entry)) {
			/* Genuine swap entry, hence a private anon page */
			if (!should_zap_cows(details))
				continue;
			rss[MM_SWAPENTS]--;
		} else if (is_migration_entry(entry)) {
			struct page *page;

			page = migration_entry_to_page(entry);
			if (details && details->check_mapping &&
			    details->check_mapping != page_rmapping(page))
				continue;
			rss[mm_counter(page)]--;
		}
		if (unlikely(!free_swap_and_cache(entry)))
			print_bad_pte(vma, addr, ptent, NULL);
		pte_clear_not_present_full(mm, addr, pte, tlb->fullmm);
	} while (pte++, addr += PAGE_SIZE, addr != end);

	// 从mm里减去计数
	add_mm_rss_vec(mm, rss);
	arch_leave_lazy_mmu_mode();

	/* Do the actual TLB flush before dropping ptl */
	if (force_flush)
		tlb_flush_mmu_tlbonly(tlb);
	pte_unmap_unlock(start_pte, ptl);

	/*
	 * If we forced a TLB flush (either due to running out of
	 * batch buffers or because we needed to flush dirty TLB
	 * entries before releasing the ptl), free the batched
	 * memory too. Restart if we didn't do everything.
	 */
	if (force_flush) {
		force_flush = 0;
		tlb_flush_mmu_free(tlb);
		if (addr != end)
			goto again;
	}

	return addr;
}


void page_remove_rmap(struct page *page, bool compound)
{
	lock_page_memcg(page);

	// 非匿名映射
	if (!PageAnon(page)) {
		page_remove_file_rmap(page, compound);
		goto out;
	}

	// 组合页
	if (compound) {
		page_remove_anon_compound_rmap(page);
		goto out;
	}

	// 减page引用计数
	if (!atomic_add_negative(-1, &page->_mapcount))
		goto out;

	/*
	 * We use the irq-unsafe __{inc|mod}_zone_page_stat because
	 * these counters are not modified in interrupt context, and
	 * pte lock(a spinlock) is held, which implies preemption disabled.
	 */
	__dec_lruvec_page_state(page, NR_ANON_MAPPED);

	if (unlikely(PageMlocked(page)))
		clear_page_mlock(page);

	if (PageTransCompound(page))
		deferred_split_huge_page(compound_head(page));

	/*
	 * It would be tidy to reset the PageAnon mapping here,
	 * but that might overwrite a racing page_add_anon_rmap
	 * which increments mapcount after us but sets mapping
	 * before us: so leave the reset to free_unref_page,
	 * and remember that it's only reliable while mapped.
	 * Leaving it set also helps swapoff to reinstate ptes
	 * faster for those pages still in swapcache.
	 */
out:
	unlock_page_memcg(page);
}

static inline void __dec_lruvec_page_state(struct page *page,
					   enum node_stat_item idx)
{
	__mod_lruvec_page_state(page, idx, -1);
}

static inline void __mod_lruvec_page_state(struct page *page,
					   enum node_stat_item idx, int val)
{
	struct page *head = compound_head(page); /* rmap on tail pages */
	pg_data_t *pgdat = page_pgdat(page);
	struct lruvec *lruvec;

	/* Untracked pages have no memcg, no lruvec. Update only the node */
	if (!head->mem_cgroup) {
		__mod_node_page_state(pgdat, idx, val);
		return;
	}

	lruvec = mem_cgroup_lruvec(head->mem_cgroup, pgdat);
	__mod_lruvec_state(lruvec, idx, val);
}
```