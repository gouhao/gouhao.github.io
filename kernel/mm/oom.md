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
		if (freed > 0)
			/* Got some memory back in the last second. */
			return true;
	}

	// 当前进程可能会释放内存，把它做标记
	if (task_will_free_mem(current)) {
		mark_oom_victim(current);
		queue_oom_reaper(current);
		return true;
	}

	/*
	 * The OOM killer does not compensate for IO-less reclaim.
	 * pagefault_out_of_memory lost its gfp context so we have to
	 * make sure exclude 0 mask - all other users should have at least
	 * ___GFP_DIRECT_RECLAIM to get here. But mem_cgroup_oom() has to
	 * invoke the OOM killer even if it is a GFP_NOFS allocation.
	 */
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
	/* OOM killer might race with memcg OOM */
	if (test_and_set_tsk_thread_flag(tsk, TIF_MEMDIE))
		return;

	/* oom_mm is bound to the signal struct life time. */
	if (!cmpxchg(&tsk->signal->oom_mm, NULL, mm)) {
		mmgrab(tsk->signal->oom_mm);
		set_bit(MMF_OOM_VICTIM, &mm->flags);
	}

	/*
	 * Make sure that the task is woken up from uninterruptible sleep
	 * if it is frozen because OOM killer wouldn't be able to free
	 * any memory and livelock. freezing_slow_path will tell the freezer
	 * that TIF_MEMDIE tasks should be ignored.
	 */
	__thaw_task(tsk);
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
	if (adj == OOM_SCORE_ADJ_MIN ||
			test_bit(MMF_OOM_SKIP, &p->mm->flags) ||
			in_vfork(p)) {
		task_unlock(p);
		return LONG_MIN;
	}

	/*
	 * The baseline for the badness score is the proportion of RAM that each
	 * task's rss, pagetable and swap space use.
	 */
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