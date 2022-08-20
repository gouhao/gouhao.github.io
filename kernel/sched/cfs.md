## 简介
主要介绍CFS（Completely Fair Scheduler）完全公平调度器。

代码基于4.19。


## 两个核心数据结构
```c
// kernel/sched/sched.h: 483
// 可运行队列，每个cpu上都有一个队列
struct cfs_rq {
	struct load_weight	load; //队列中所有进程的权重和
	unsigned long		runnable_weight;
	unsigned int		nr_running; //队列中进程数量
	unsigned int		h_nr_running;

	u64			exec_clock;
	u64			min_vruntime; //进程中最小的vruntime
#ifndef CONFIG_64BIT
	u64			min_vruntime_copy;
#endif

	struct rb_root_cached	tasks_timeline; // 运行队列

	struct sched_entity	*curr; //当前运行的里程

	...
}


// include/linux/sched.h: 447
// 调度实体。调度实体有2种：组调度和进程调度
struct sched_entity {
	/* For load-balancing: */
	struct load_weight		load; //权重 
	unsigned long			runnable_weight; //对于进程来说这个等于权重
	struct rb_node			run_node; //链入cfs_rq的结点
	struct list_head		group_node;
	unsigned int			on_rq; //是否在队列中

	u64				exec_start; //上次开始执行的时间
	u64				sum_exec_runtime; //进程总共执行的时间
	u64				vruntime; //虚拟运行时间
	u64				prev_sum_exec_runtime; //上次运行的时间

	u64				nr_migrations;

	struct sched_statistics		statistics;

#ifdef CONFIG_FAIR_GROUP_SCHED
	// 组调度相关
	int				depth;
	struct sched_entity		*parent;
	struct cfs_rq			*cfs_rq;
	struct cfs_rq			*my_q;
#endif
	...
};

```

## CFS理论简介
下面的公式参考的这篇文章：https://blog.csdn.net/liuxiaowu19911121/article/details/47070111。

在一个调度周期内，分给每个进程的时间（类似于时间片）如下：
* 公式1：分配给进程的运行时间 = 调度周期 * 进程权重 / 所有进程权重之和


如果一个进程得以执行，随着时间的增长（也就是一个个tick的到来），其vruntime将不断增大，没有得到执行的进程vruntime不变。

调度器总是选择vruntime跑得最慢的那个进程来执行。这就是所谓的“完全公平”。为了区别不同优先级的进程，优先级高的进程vruntime增长得慢，以至于它可能得到更多的运行机会。vruntime的计算公式如下：
* 公式2：vruntime = 实际运行时间 * 1024 / 进程权重 (1024就是NICE_0_LOAD的权重)
把公式1代入公式2：
* vruntime = (调度周期 * 进程权重 / 所有进程总权重) * 1024 / 进程权重 = 调度周期 * 1024 / 所有进程总权重 

可以看出虽然进程的权重不同，但是它们的 vruntime增长速度应该是一样的 ，与权重无关。从宏观上来看，进程是同步向前推进的。

首先在创建进程的时候会初始化调度器相关的变量，在fork过程中调用了sched_fork，在sched_fork中有两个过程涉及到了调度器，分别是调用__sched_fork和sched_class->task_fork。

所以CFS的思想就是让每个调度实体（没有组调度的情形下就是进程，以后就说进程了）的vruntime互相追赶，而每个调度实体的vruntime增加速度不同，权重越大的增加的越慢，这样就能获得更多的cpu执行时间。

权重值与进程的nice值相关:
```c
// kernel/sched/core.c
const int sched_prio_to_weight[40] = {
 /* -20 */     88761,     71755,     56483,     46273,     36291,
 /* -15 */     29154,     23254,     18705,     14949,     11916,
 /* -10 */      9548,      7620,      6100,      4904,      3906,
 /*  -5 */      3121,      2501,      1991,      1586,      1277,
 /*   0 */      1024,       820,       655,       526,       423,
 /*   5 */       335,       272,       215,       172,       137,
 /*  10 */       110,        87,        70,        56,        45,
 /*  15 */        36,        29,        23,        18,        15,
};

// include/linux/sched/prio.h

#define MAX_NICE	19
#define MIN_NICE	-20
#define NICE_WIDTH	(MAX_NICE - MIN_NICE + 1)

#define MAX_USER_RT_PRIO	100
#define MAX_RT_PRIO		MAX_USER_RT_PRIO

#define MAX_PRIO		(MAX_RT_PRIO + NICE_WIDTH)
#define DEFAULT_PRIO		(MAX_RT_PRIO + NICE_WIDTH / 2)

#define NICE_TO_PRIO(nice)	((nice) + DEFAULT_PRIO)
#define PRIO_TO_NICE(prio)	((prio) - DEFAULT_PRIO)

#define USER_PRIO(p)		((p)-MAX_RT_PRIO)
#define TASK_USER_PRIO(p)	USER_PRIO((p)->static_prio)
```
将上述宏代入之后，优先级与nice值的计算公式如下：
* prio = nice + 120
* 权重 = sched_prio_to_weight[prio - 100] = sched_prio_to_weight[nice + 20]

## 调度时间的初始化

```c
int sched_fork(unsigned long clone_flags, struct task_struct *p)
{
	unsigned long flags;

	__sched_fork(clone_flags, p);
	
	p->state = TASK_NEW;

	...

	__set_task_cpu(p, smp_processor_id());
	if (p->sched_class->task_fork)
		p->sched_class->task_fork(p);

	...
}


// kernel/sched/core.c: 2164、
static void __sched_fork(unsigned long clone_flags, struct task_struct *p)
{
	p->on_rq			= 0;

	p->se.on_rq			= 0;
	p->se.exec_start		= 0;
	p->se.sum_exec_runtime		= 0;
	p->se.prev_sum_exec_runtime	= 0;
	p->se.nr_migrations		= 0;
	p->se.vruntime			= 0;
	INIT_LIST_HEAD(&p->se.group_node);

#ifdef CONFIG_FAIR_GROUP_SCHED
	p->se.cfs_rq			= NULL;
#endif

	// deadline 调度器初始化

	// rt调度器初始化

	...
}
```
在__sched_fork中将公平调度所用到的部分值进行了重置，权重没有初始化，所以权重就是直接从父进程那里继承来的。

然后调用task_fork对调度相关的进行初始化，这里只看公平调度：
```c
static void task_fork_fair(struct task_struct *p)
{
	struct cfs_rq *cfs_rq;
	struct sched_entity *se = &p->se, *curr;
	struct rq *rq = this_rq();
	struct rq_flags rf;

	rq_lock(rq, &rf);
	update_rq_clock(rq);

	cfs_rq = task_cfs_rq(current);
	curr = cfs_rq->curr;
	if (curr) {
		update_curr(cfs_rq);
		se->vruntime = curr->vruntime;
	}
	place_entity(cfs_rq, se, 1);

	if (sysctl_sched_child_runs_first && curr && entity_before(curr, se)) {
		swap(curr->vruntime, se->vruntime);
		resched_curr(rq);
	}

	se->vruntime -= cfs_rq->min_vruntime;
	rq_unlock(rq, &rf);
}
```
流程如下：
1. 调用update_curr更新当前进程的时间
2. 初始化新进程的vruntime，设置为当前进程的vruntime
3. 调用place_entity调整当前进程的时间
4. 如果设置了子进程先运行，并且当前进程比新进程的时间小，则交换两个进程的vruntime，并设置当前进程的调度标志
5. 将新进程的vruntime的时间减去调度队列的最小虚拟时间

第4步中，sysctl_sched_child_runs_first这个默认是0，在用户空间可以配置为打开。一般情况下在fork阶段都不会抢占父进程。

第5步中，要让vruntime减去当前队列的最小虚拟时间，新进程被调度运行的时候，再加上cpu运行队列的最小运行时间。之所以要这样做，
是因为在fork完之后再调度的时候，新进程不一定在此cpu上运行，如果被迁移到了其他cpu上，还是用本cpu上的最小时间，就会产生错误，
所以在运行的时候再加上新cpu的最小运行时间，这样比较保险。

update_curr用来更新当前进程的时间：
```c
// kernel/sched/fair.c
static void update_curr(struct cfs_rq *cfs_rq)
{
	struct sched_entity *curr = cfs_rq->curr;
	u64 now = rq_clock_task(rq_of(cfs_rq));
	u64 delta_exec;

	delta_exec = now - curr->exec_start;
	if (unlikely((s64)delta_exec <= 0))
		return;

	curr->exec_start = now;

	curr->sum_exec_runtime += delta_exec;

	curr->vruntime += calc_delta_fair(delta_exec, curr);
	update_min_vruntime(cfs_rq);

	//统计相关
	...
}

```
这里的now是当前的时间，单位是纳秒，但是对jiffies做了一些处理，核心的获取时间的方法在sched_clock中：
```c
// include/linux/jiffies.h
/*
 * Have the 32 bit jiffies value wrap 5 minutes after boot
 * so jiffies wrap bugs show up earlier.
 */
#define INITIAL_JIFFIES ((unsigned long)(unsigned int) (-300*HZ))

// kernel/sched/clock.c
unsigned long long __weak sched_clock(void)
{
	return (unsigned long long)(jiffies - INITIAL_JIFFIES)
					* (NSEC_PER_SEC / HZ);
}
```

delta_exec是上次计时时间到现在的差值，然后更新exec_start和sum_exec_runtime的值。

然后调用calc_delta_fair来计算vruntime：
```c
// kernel/sched/fair.c
static inline u64 calc_delta_fair(u64 delta, struct sched_entity *se)
{
	if (unlikely(se->load.weight != NICE_0_LOAD))
		delta = __calc_delta(delta, NICE_0_LOAD, &se->load);

	return delta;
}

static u64 __calc_delta(u64 delta_exec, unsigned long weight, struct load_weight *lw)
{
	u64 fact = scale_load_down(weight);
	int shift = WMULT_SHIFT;

	__update_inv_weight(lw);

	if (unlikely(fact >> 32)) {
		while (fact >> 32) {
			fact >>= 1;
			shift--;
		}
	}

	/* hint to use a 32x32->64 mul */
	fact = (u64)(u32)fact * lw->inv_weight;

	while (fact >> 32) {
		fact >>= 1;
		shift--;
	}

	return mul_u64_u32_shr(delta_exec, fact, shift);
}

```
调用calc_delta_fair的地方很多，这个函数就是计算vruntime的地方。calc_delta_fair和__calc_delta中的计算过程对应的
是上面提到的vruntime的计算公式：vruntime = 实际运行时间 * 1024 / 进程权重

delta就是实际运行时间 ，传过来的se是进程权重，如果进行权重为NICE_0_LOAD（1024），则直接返回运行时间。否则就进入__calc_delta来算vruntime。

__calc_delta里面计算的也是这样那个公式，处理了32位和64位乘法之类的。scale_load_down是将weight右移10位，因为在初始化的时候调用了scale_load左移了10位，
所以这里要将权重还原。

更新完vruntime后，再调用update_min_vruntime更新运行列表里的最小虚拟时间值。
```c
// kernel/sched/fair.c
static void update_min_vruntime(struct cfs_rq *cfs_rq)
{
	struct sched_entity *curr = cfs_rq->curr;
	struct rb_node *leftmost = rb_first_cached(&cfs_rq->tasks_timeline);

	u64 vruntime = cfs_rq->min_vruntime;

	if (curr) {
		if (curr->on_rq)
			vruntime = curr->vruntime;
		else
			curr = NULL;
	}

	if (leftmost) { /* non-empty tree */
		struct sched_entity *se;
		se = rb_entry(leftmost, struct sched_entity, run_node);

		if (!curr)
			vruntime = se->vruntime;
		else
			vruntime = min_vruntime(vruntime, se->vruntime);
	}

	/* ensure we never gain time by being placed backwards. */
	cfs_rq->min_vruntime = max_vruntime(cfs_rq->min_vruntime, vruntime);
#ifndef CONFIG_64BIT
	smp_wmb();
	cfs_rq->min_vruntime_copy = cfs_rq->min_vruntime;
#endif
}
```
rb_first_cached取的是最左叶子节点，最左叶子节点就是最小的虚拟时间对应的节点。


更新完当前进程的时间后，把新进程的vruntime设置为当前进程的vruntime，然后调用place_entity调整新进程时间。

```c
static void place_entity(struct cfs_rq *cfs_rq, struct sched_entity *se, int initial)
{
	u64 vruntime = cfs_rq->min_vruntime;

	/*
	 * The 'current' period is already promised to the current tasks,
	 * however the extra weight of the new task will slow them down a
	 * little, place the new task so that it fits in the slot that
	 * stays open at the end.
	 */
	if (initial && sched_feat(START_DEBIT))
		vruntime += sched_vslice(cfs_rq, se);

	/* sleeps up to a single latency don't count. */
	if (!initial) {
		unsigned long thresh = sysctl_sched_latency;

		/*
		 * Halve their sleep time's effect, to allow
		 * for a gentler effect of sleepers:
		 */
		if (sched_feat(GENTLE_FAIR_SLEEPERS))
			thresh >>= 1;

		vruntime -= thresh;
	}

	/* ensure we never gain time by being placed backwards. */
	se->vruntime = max_vruntime(se->vruntime, vruntime);
}
```
对于新进程initial传的是1，到最后在min_vruntime和se->vruntime之间选了一个较大的，所以新进程的vruntime >= 父进程的vruntime。


## 时间中断调度
时间调度主要来源于时间中断，随着每个tick的到来，更新当前进程的运行时间，并根据条件来判断是否需要调度。

时间调度的入口在core.c中，针对每个调度器都走同样的流程，其中主要一句代码是调用curr->sched_class->task_tick(rq, curr, 0)。
```c
void scheduler_tick(void)
{
	int cpu = smp_processor_id();
	struct rq *rq = cpu_rq(cpu);
	struct task_struct *curr = rq->curr;
	struct rq_flags rf;

	sched_clock_tick();

	rq_lock(rq, &rf);

	update_rq_clock(rq);
	curr->sched_class->task_tick(rq, curr, 0);
	cpu_load_update_active(rq);
	calc_global_load_tick(rq);

	rq_unlock(rq, &rf);

	perf_event_task_tick();

#ifdef CONFIG_SMP
	rq->idle_balance = idle_cpu(cpu);
	trigger_load_balance(rq);
#endif
}
```
在这段代码中除了调用调度器的task_tick，其余代码主要是处理有关cpu负载均衡相关的东西。

```c
// kernel/sched/fair.c
static void task_tick_fair(struct rq *rq, struct task_struct *curr, int queued)
{
	struct cfs_rq *cfs_rq;
	struct sched_entity *se = &curr->se;

	for_each_sched_entity(se) {
		cfs_rq = cfs_rq_of(se);
		entity_tick(cfs_rq, se, queued);
	}

	if (static_branch_unlikely(&sched_numa_balancing))
		task_tick_numa(rq, curr);
}

// 如果没有定义 CONFIG_FAIR_GROUP_SCHED，foreach定义如下
#define for_each_sched_entity(se) \
		for (; se; se = NULL)
```
task_tick_fair的代码很简单，主要是调用for_each_sched_entity遍历调度实体，如果没有打开组调度，则这个
foreach就相当于只有一个entity_tick。

如果打开了sched_numa_balancing，还要进行numa相关的处理，这个标志在打开SCHED_DEBUG时可以在/proc/sys/kernel/中控制。


```c
// kernel/sched/fair.c
static void entity_tick(struct cfs_rq *cfs_rq, struct sched_entity *curr, int queued)
{
	update_curr(cfs_rq);
	
	update_load_avg(cfs_rq, curr, UPDATE_TG);
	update_cfs_group(curr);

#ifdef CONFIG_SCHED_HRTICK
	...
#endif

	if (cfs_rq->nr_running > 1)
		check_preempt_tick(cfs_rq, curr);
}
```
在未开启组调度时,核心代码只有2句，update_curr用来更新当前进程的时间，check_preempt_tick来检查是否需要抢占当前进程。
update_curr的代码已经在前面看过了，下面来看一下check_preempt_tick，这个函数会决定是否要抢占当前进程：

```c
// kernel/sched/fair.c
static void check_preempt_tick(struct cfs_rq *cfs_rq, struct sched_entity *curr)
{
	unsigned long ideal_runtime, delta_exec;
	struct sched_entity *se;
	s64 delta;

	ideal_runtime = sched_slice(cfs_rq, curr);
	delta_exec = curr->sum_exec_runtime - curr->prev_sum_exec_runtime;
	if (delta_exec > ideal_runtime) {
		resched_curr(rq_of(cfs_rq));
		clear_buddies(cfs_rq, curr);
		return;
	}

	if (delta_exec < sysctl_sched_min_granularity)
		return;

	se = __pick_first_entity(cfs_rq);
	delta = curr->vruntime - se->vruntime;

	if (delta < 0)
		return;

	if (delta > ideal_runtime)
		resched_curr(rq_of(cfs_rq));
}
```
check_preempt_tick主要步骤如下：
1. 如果已经运行的时间大于应该运行的时间，则设置当前进程的调度标志位
2. 如果已运行时间小于最小调度时间，则返回
3. 如果当前进程的vruntime比最小vruntime大于自己应该运行的进程，则设置当前进程调度标志位

先来看一下计算应该运行的时候
```c
// kernel/sched/fair.c
static u64 sched_slice(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	u64 slice = __sched_period(cfs_rq->nr_running + !se->on_rq);

	for_each_sched_entity(se) {
		struct load_weight *load;
		struct load_weight lw;

		cfs_rq = cfs_rq_of(se);
		load = &cfs_rq->load;

		if (unlikely(!se->on_rq)) {
			lw = cfs_rq->load;

			update_load_add(&lw, se->load.weight);
			load = &lw;
		}
		slice = __calc_delta(slice, se->load.weight, load);
	}
	return slice;
}

static u64 __sched_period(unsigned long nr_running)
{
	if (unlikely(nr_running > sched_nr_latency))
		return nr_running * sysctl_sched_min_granularity;
	else
		return sysctl_sched_latency;
}

```
这个代码对应的就是上面的公式1：分配给进程的运行时间 = 调度周期 * 进程权重 / 所有进程权重之和。

调度周期是通过__sched_period计算，在__sched_period中根据当前的运行队列中的进程数量来决定应该用多少调度周期，sysctl_sched_latency是默认值。
然后调用__calc_delta来计算进程可运行时间，__calc_delta的代码在上面已经看了，计算的就是公式中的计算步骤。这里传的权重值为load，这个local是&cfs_rq->load，
代表是整个运行队列的整体权重。prev_sum_exec_runtime只在进程被调度时会设置一次，在下面pick_next_task的代码中会看到。

总结，在时钟中断中，触发的调度的条件是：
* 当前进程已经运行了一个时间片
* 当前进程的运行时间比当前进程与最小vruntime，大于一个时间片

## 调度的完整流程
调度的完整流程由kernel/sched/core.c: schedule函数开始:

```c
// kernel/sched/core.c
asmlinkage __visible void __sched schedule(void)
{
	struct task_struct *tsk = current;

	sched_submit_work(tsk);
	do {
		preempt_disable();
		__schedule(false);
		sched_preempt_enable_no_resched();
	} while (need_resched());
}

static void __sched notrace __schedule(bool preempt)
{
	struct task_struct *prev, *next;
	unsigned long *switch_count;
	struct rq_flags rf;
	struct rq *rq;
	int cpu;

	cpu = smp_processor_id();
	rq = cpu_rq(cpu);
	prev = rq->curr;

	...

	switch_count = &prev->nivcsw;
	if (!preempt && prev->state) {
		if (unlikely(signal_pending_state(prev->state, prev))) {
			prev->state = TASK_RUNNING;
		} else {
			deactivate_task(rq, prev, DEQUEUE_SLEEP | DEQUEUE_NOCLOCK);
			prev->on_rq = 0;

			...
		}
		switch_count = &prev->nvcsw;
	}

	next = pick_next_task(rq, prev, &rf);
	clear_tsk_need_resched(prev);
	clear_preempt_need_resched();

	if (likely(prev != next)) {
		rq->nr_switches++;
		rq->curr = next;
		++*switch_count;

		trace_sched_switch(preempt, prev, next);

		/* Also unlocks the rq: */
		rq = context_switch(rq, prev, next, &rf);
	} else {
		rq->clock_update_flags &= ~(RQCF_ACT_SKIP|RQCF_REQ_SKIP);
		rq_unlock_irq(rq, &rf);
	}

	balance_callback(rq);
}
```
在schedule中主要关闭了抢占，调用_schedule，核心流程在_schedule中。程序中cpu是本cpu的编号，rq是这个cpu上的运行队列，prev是当前正在运行的进程的struct task_struct对象，也就是将要被替换的进程。这个函数的主要流程如下：
1. 禁用当前cpu上的中断
2. 调用deactivate_task将当前进程从运行队列上出队
3. 调用pick_next_task选择一个合适的进程
4. 清除prev进程的TIF_NEED_RESCHED
5. 调用context_switch执行切换动作

比较核心的流程就是第3步和第5步，挑选一个合适的进程然后切换进程上下文去执行。

```c
// kernel/sched/core.c:3303
static inline struct task_struct *
pick_next_task(struct rq *rq, struct task_struct *prev, struct rq_flags *rf)
{
	const struct sched_class *class;
	struct task_struct *p;

	if (likely((prev->sched_class == &idle_sched_class ||
		    prev->sched_class == &fair_sched_class) &&
		   rq->nr_running == rq->cfs.h_nr_running)) {

		p = fair_sched_class.pick_next_task(rq, prev, rf);
		if (unlikely(p == RETRY_TASK))
			goto again;

		/* Assumes fair_sched_class->next == idle_sched_class */
		if (unlikely(!p))
			p = idle_sched_class.pick_next_task(rq, prev, rf);

		return p;
	}

again:
	for_each_class(class) {
		p = class->pick_next_task(rq, prev, rf);
		if (p) {
			if (unlikely(p == RETRY_TASK))
				goto again;
			return p;
		}
	}

	/* The idle class should always have a runnable task: */
	BUG();
}
```
选择下一个运行的进程，主要调用sched_class的pick_next_task来挑选。在前面做了个优化，因为大多数进程都是采用公平调度，所以前面的判断在大多数情况下都会成功；如果失败的话就遍历sched_class来选择一个优先级较高的进程。

```c
static struct task_struct *
pick_next_task_fair(struct rq *rq, struct task_struct *prev, struct rq_flags *rf)
{
	struct cfs_rq *cfs_rq = &rq->cfs;
	struct sched_entity *se;
	struct task_struct *p;
	int new_tasks;

again:
	if (!cfs_rq->nr_running)
		goto idle;

#ifdef CONFIG_FAIR_GROUP_SCHED
...
#endif

	put_prev_task(rq, prev);

	do {
		se = pick_next_entity(cfs_rq, NULL);
		set_next_entity(cfs_rq, se);
		cfs_rq = group_cfs_rq(se);
	} while (cfs_rq);

	p = task_of(se);

done: __maybe_unused;
#ifdef CONFIG_SMP
	/*
	 * Move the next running task to the front of
	 * the list, so our cfs_tasks list becomes MRU
	 * one.
	 */
	list_move(&p->se.group_node, &rq->cfs_tasks);
#endif

	if (hrtick_enabled(rq))
		hrtick_start_fair(rq, p);

	return p;

idle:
	new_tasks = idle_balance(rq, rf);

	if (new_tasks < 0)
		return RETRY_TASK;

	if (new_tasks > 0)
		goto again;

	return NULL;
}
```
pick_next_task_fair的主流程如下：
1. 如果当前队列为空，则跳到idle，在idle_balance会进行cpu负载均衡
2. 调用put_prev_entity，更新当前进程时间，将当前进程重新加入运行队列
3. 挑选下一个进程，并设置为当前进程



完全公平调度用红黑树来记录各个进程运行的情况，将最需要运行的进程放在最左子树，在pick_first_entity就是取出最左子树上的sched_entity，当然其中有很多其他场景需要处理。

在set_next_entity中把选出来的进程设置成运行队列上的正在运行进程：

```c
//kernel/sched/fair.c
static void
set_next_entity(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	...

	update_stats_curr_start(cfs_rq, se);
	cfs_rq->curr = se;

	...

	se->prev_sum_exec_runtime = se->sum_exec_runtime;
}

static inline void
update_stats_curr_start(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	se->exec_start = rq_clock_task(rq_of(cfs_rq));
}
```
首先更新当前进程的exec_start，然后设置运行队列的curr为选出来的下一个进程，最后设置se->prev_sum_exec_runtime，这个时间在上面见到过，
它用来统计一个进程的时间片，

调度中最后一个主要流程就是进程虚拟空间的切换：
```c
static __always_inline struct rq *
context_switch(struct rq *rq, struct task_struct *prev,
	       struct task_struct *next, struct rq_flags *rf)
{
	struct mm_struct *mm, *oldmm;

	prepare_task_switch(rq, prev, next);

	mm = next->mm;
	oldmm = prev->active_mm;
	...
	if (!mm) {
		next->active_mm = oldmm;
		mmgrab(oldmm);
		enter_lazy_tlb(oldmm, next);
	} else
		switch_mm_irqs_off(oldmm, mm, next);

	if (!prev->mm) {
		prev->active_mm = NULL;
		rq->prev_mm = oldmm;
	}

	rq->clock_update_flags &= ~(RQCF_ACT_SKIP|RQCF_REQ_SKIP);

	prepare_lock_switch(rq, next, rf);

	/* Here we just switch the register state and the stack. */
	switch_to(prev, next, prev);
	barrier();

	return finish_task_switch(prev);
}
```
context_switch中的next为要换入的进程，prev为要换出的进程。这里的mm为next->mm， oldmm为prev->active_mm。用户空间的进程mm和active_mm是相等的，但是对于内核线程来说它是没有mm结构的为NULL,所以if判断!mm表示要换入的是一个内核线程，内核线程会借用换出进程的active_mm，mmgrab是增加mm的引用计数。

如果是用户空间进程则调用switch_mm_irqs_off切换进程的内存空间，切换内存空间实际上就是将mm里的pgd全局页面目录写入cr3寄存器。mmu是从cr3寄存器，只要把下个进程的pgd写入cr3，虚存空间就切换了。
```c
arch/x86/mm/tlb.c:183
void switch_mm_irqs_off(struct mm_struct *prev, struct mm_struct *next,
			struct task_struct *tsk)
{

	...
		if (need_flush) {
			this_cpu_write(cpu_tlbstate.ctxs[new_asid].ctx_id, next->context.ctx_id);
			this_cpu_write(cpu_tlbstate.ctxs[new_asid].tlb_gen, next_tlb_gen);
			load_new_mm_cr3(next->pgd, new_asid, true);

			trace_tlb_flush_rcuidle(TLB_FLUSH_ON_TASK_SWITCH, TLB_FLUSH_ALL);
		} else {
			/* The new ASID is already up to date. */
			load_new_mm_cr3(next->pgd, new_asid, false);

			/* See above wrt _rcuidle. */
			trace_tlb_flush_rcuidle(TLB_FLUSH_ON_TASK_SWITCH, 0);
		}
	...
	}
	...
}

arch/x86/mm/tlb.c:104
static void load_new_mm_cr3(pgd_t *pgdir, u16 new_asid, bool need_flush)
{
	unsigned long new_mm_cr3;

	if (need_flush) {
		invalidate_user_asid(new_asid);
		new_mm_cr3 = build_cr3(pgdir, new_asid);
	} else {
		new_mm_cr3 = build_cr3_noflush(pgdir, new_asid);
	}
	...
	write_cr3(new_mm_cr3);
}

arch/x86/include/asm/special_insns.h:177
static inline void write_cr3(unsigned long x)
{
	native_write_cr3(x);
}

arch/x86/include/asm/special_insns.h：50
static inline void native_write_cr3(unsigned long val)
{
	asm volatile("mov %0,%%cr3": : "r" (val), "m" (__force_order));
}
```

页面映射过程，以三级映射为例，在32位系统中三级映射pgd为2位，pmd10位，pte10位。
