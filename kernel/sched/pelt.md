# PELT 算法

时间被分成了1024us的序列（也就是1ms，按1024算比较好算），在每一个1024us的周期中，一个entity对系统负载的贡献可以根据该实体处于runnable状态（正在CPU上运行或者等待cpu调度运行）的时间进行计算。任务在1024us的周期窗口内的负载其实就是瞬时负载。如果在该周期内，runnable的时间是t，那么该任务的瞬时负载应该和（t/1024）有正比的关系。类似的概念，任务的瞬时利用率应该通过1024us的周期窗口内的执行时间（不包括runqueue上的等待时间）比率来计算。

瞬时负载：Li = load weight  x （t/1024），瞬时负载中引用的权重。

Ui = Max CPU capacity  x （t/1024）。瞬时利用率中Max CPU capacity最大为1024。

任务的平均负载：
L = L0 + L1*y + L2*y2 + L3*y3 + ...

Li表示在周期pi中的瞬时负载，对于过去的负载我们在计算的时候需要乘一个衰减因子y。在目前的内核代码中，y是确定值：y ^32等于0.5。这样选定的y值，一个调度实体的负荷贡献经过32个窗口（1024us）后，对当前时间的的符合贡献值会衰减一半。

下一层的cfs rq的h_load = 上一层cfs rq的h_load  X  group se 在上一层cfs负载中的占比。

Task se的h_load = task se的load avg  x  cfs rq的h_load / cfs rq的load avg

```c
struct sched_avg {
    // 上次更新的时间
	u64				last_update_time; 

    /**
    *_sum是按几何级数的累加，按照1毫秒一个周期，距离当前点越远，
    衰减越厉害，32个周期后load衰减50%
    */

    // runnable+running的时间
	u64				load_sum;

    // runnable 的时间
	u64				runnable_load_sum;

    // running的时间
	u32				util_sum;

    // 在更新负载时分三段，
    // d1(合入上次更新负载的剩余时间，即不足1ms窗口的时间)
    // d2(满窗时间)
    // d3(不足1ms的时间)
    // period_contrib则记录了d3窗口的时间，方便下次计算d1的时间
	u32				period_contrib;

    // 负载平均值
	unsigned long			load_avg;

    // runnable时的负载平均值
	unsigned long			runnable_load_avg;

    // running时的负载平均值
	unsigned long			util_avg;

    /**
    任务阻塞后，其负载会不断衰减。如果一个重载任务阻塞太长时间，
    那么根据PELT算法计算出来的负载会非常小，当该任务被唤醒重新
    参与调度的时候，由于负载较小会让调度器做出错误的判断。因此
    引入了这个成员，记录阻塞之前的load_avg信息
    */
	struct util_est			util_est;
} ____cacheline_aligned;
```


load_avg的初始化有2个地方：
* init_entity_runnable_average，这个在task fork的时候，或者在cgroup创建的时候。
* post_init_entity_util_avg，在这个阶段里只更新util_avg，这个只有task才会走，因为这个是在wake_up_new_task的时候调用的。

```c
void init_entity_runnable_average(struct sched_entity *se)
{
	struct sched_avg *sa = &se->avg;

	memset(sa, 0, sizeof(*sa));

	/*
     * 原文注释：
	 * 任务被初始化为满负载，被视为繁重的任务，直到它们有机会稳定到其实际负载水平。 
     * 组实体初始化为零负载以反映尚未将任何内容附加到任务组的事实。
	 */
	if (entity_is_task(se))
        // scale_load_down是将权重按比例向下缩小（右移10位）。只在64位平台上有用，在32位平台上，还是
        // 返回原值。
        // 如果在64位平台上，nice0的权重为1024，经过scale_load_down后，权重归为1
        // 所以这里将task的运行平均负载和总平均负载都初始化成1
		sa->runnable_load_avg = sa->load_avg = scale_load_down(se->load.weight);

    // 初始化运行权重
	se->runnable_weight = se->load.weight;

	/* when this task enqueue'ed, it will contribute to its cfs_rq's load_avg */
}

# define SCHED_FIXEDPOINT_SHIFT		10

#ifdef CONFIG_64BIT
# define NICE_0_LOAD_SHIFT	(SCHED_FIXEDPOINT_SHIFT + SCHED_FIXEDPOINT_SHIFT)
# define scale_load(w)		((w) << SCHED_FIXEDPOINT_SHIFT)
# define scale_load_down(w) \
({ \
	unsigned long __w = (w); \
	if (__w) \
		__w = max(2UL, __w >> SCHED_FIXEDPOINT_SHIFT); \
	__w; \
})
#else
# define NICE_0_LOAD_SHIFT	(SCHED_FIXEDPOINT_SHIFT)
# define scale_load(w)		(w)
# define scale_load_down(w)	(w)
#endif

```

```c
void post_init_entity_util_avg(struct sched_entity *se)
{
	struct cfs_rq *cfs_rq = cfs_rq_of(se);
	struct sched_avg *sa = &se->avg;

    // 传NULL进去，最后算出来的值是1024
	long cpu_scale = arch_scale_cpu_capacity(NULL, cpu_of(rq_of(cfs_rq)));

    // avg.util_avg在初始化时为0，所以cap算出来是512
	long cap = (long)(cpu_scale - cfs_rq->avg.util_avg) / 2;

	if (cap > 0) {

		if (cfs_rq->avg.util_avg != 0) {
            // 队列里面还有别的任务

            // todo: 这个计算公式没看懂
			sa->util_avg  = cfs_rq->avg.util_avg * se->load.weight;
			sa->util_avg /= (cfs_rq->avg.load_avg + 1);

			if (sa->util_avg > cap)
				sa->util_avg = cap;
		} else {
            // 队列里还没有任务时，将util_avg初始化为队列的算力
			sa->util_avg = cap;
		}
	}

	if (entity_is_task(se)) {
		struct task_struct *p = task_of(se);
		if (p->sched_class != &fair_sched_class) {
			// 如果不是公平调度，则设置上次更新时间为当前cpu时间
			se->avg.last_update_time = cfs_rq_clock_task(cfs_rq);
			return;
		}
	}

    // 将se添加到当前队列
	attach_entity_cfs_rq(se);
}

static void attach_entity_cfs_rq(struct sched_entity *se)
{
	struct cfs_rq *cfs_rq = cfs_rq_of(se);

#ifdef CONFIG_FAIR_GROUP_SCHED
	// 如果是组公平，则计算层级深度
	se->depth = se->parent ? se->parent->depth + 1 : 0;
#endif

    // 更新task和它所在队列的平均负载
    // sched_feat是有无cpu特征， 在kernel/sched/feature.h中做了初始化
    // ATTACH_AGE_LOAD这个特征默认为true，所以传给update_load_avg的为0
	update_load_avg(cfs_rq, se, sched_feat(ATTACH_AGE_LOAD) ? 0 : SKIP_AGE_LOAD);

	// 将当前这个se加到运行队列里
	attach_entity_load_avg(cfs_rq, se, 0);

	// 下面2个函数和组调度有关
	update_tg_load_avg(cfs_rq, false);
	propagate_entity_cfs_rq(se);
}

/*
 * Optional action to be done while updating the load average
 */
#define UPDATE_TG	0x1
#define SKIP_AGE_LOAD	0x2
#define DO_ATTACH	0x4

/* Update task and its cfs_rq load average */
static inline void update_load_avg(struct cfs_rq *cfs_rq, struct sched_entity *se, int flags)
{
	u64 now = cfs_rq_clock_task(cfs_rq);
	struct rq *rq = rq_of(cfs_rq);
	int cpu = cpu_of(rq);

    // 负载是否衰减
	int decayed;

	// 当last_update_time不为0时，则更新se的负载数据
	if (se->avg.last_update_time && !(flags & SKIP_AGE_LOAD))
		__update_load_avg_se(now, cpu, cfs_rq, se);

    // 更新完se后，更新队列平均负载
	decayed  = update_cfs_rq_load_avg(now, cfs_rq);

    // 向上传播平均负载，主要是组调度里的负载更新
	decayed |= propagate_entity_load_avg(se);

    // flags为0，下面都不走
	if (!se->avg.last_update_time && (flags & DO_ATTACH)) {
		// 第一次入队的时候会走这个分支
		/*
		 * DO_ATTACH means we're here from enqueue_entity().
		 * !last_update_time means we've passed through
		 * migrate_task_rq_fair() indicating we migrated.
		 *
		 * IOW we're enqueueing a task on a new CPU.
		 */
		attach_entity_load_avg(cfs_rq, se, SCHED_CPUFREQ_MIGRATION);
		update_tg_load_avg(cfs_rq, 0);

	} else if (decayed && (flags & UPDATE_TG))
		update_tg_load_avg(cfs_rq, 0);
}

static inline int
update_cfs_rq_load_avg(u64 now, struct cfs_rq *cfs_rq)
{
	unsigned long removed_load = 0, removed_util = 0, removed_runnable_sum = 0;
	struct sched_avg *sa = &cfs_rq->avg;
	int decayed = 0;
    
    // 当有移除的task时走这个分支
	if (cfs_rq->removed.nr) {
		unsigned long r;
		u32 divider = LOAD_AVG_MAX - 1024 + sa->period_contrib;

		raw_spin_lock(&cfs_rq->removed.lock);
		swap(cfs_rq->removed.util_avg, removed_util);
		swap(cfs_rq->removed.load_avg, removed_load);
		swap(cfs_rq->removed.runnable_sum, removed_runnable_sum);
		cfs_rq->removed.nr = 0;
		raw_spin_unlock(&cfs_rq->removed.lock);

		r = removed_load;
		sub_positive(&sa->load_avg, r);
		sub_positive(&sa->load_sum, r * divider);

		r = removed_util;
		sub_positive(&sa->util_avg, r);
		sub_positive(&sa->util_sum, r * divider);

		add_tg_cfs_propagate(cfs_rq, -(long)removed_runnable_sum);

		decayed = 1;
	}

    // 更新队列平均负载
	decayed |= __update_load_avg_cfs_rq(now, cpu_of(rq_of(cfs_rq)), cfs_rq);

#ifndef CONFIG_64BIT
    // smp_wmb好像是插入一个内存屏障
	smp_wmb();

    // 更新负载的时间改变
	cfs_rq->load_last_update_time_copy = sa->last_update_time;
#endif

    // 如果负载有衰减，则更新队列的util值
	if (decayed)
		cfs_rq_util_change(cfs_rq, 0);

	return decayed;
}

int __update_load_avg_cfs_rq(u64 now, int cpu, struct cfs_rq *cfs_rq)
{
    // load.weight和runnable_weight都被缩小2的10次方（右移10位）
	if (___update_load_sum(now, cpu, &cfs_rq->avg,
				scale_load_down(cfs_rq->load.weight),
				scale_load_down(cfs_rq->runnable_weight),
				cfs_rq->curr != NULL)) {

		___update_load_avg(&cfs_rq->avg, 1, 1);
		return 1;
	}

	return 0;
}

/**
now: 当前时间，这个时间是针对cpu调整过的， 单位是ns
cpu: 当前cpu
sa: 队列struct sched_avg结构体
load： 队列的负载权重
runnable: 队列的可运行负载权重
running: 当前队列是否正在运行，这个运行仅判断cfs_rq->curr不为0 

这个函数返回 0 表示没有更新负载和
*/
static __always_inline int
___update_load_sum(u64 now, int cpu, struct sched_avg *sa,
		  unsigned long load, unsigned long runnable, int running)
{
	u64 delta;

	// 计算经上次更新时间后的间隔
	// last_update_time的单位是ns
	delta = now - sa->last_update_time;
	/*
	 原文注释：
	 这应该只在时间倒退时发生，不幸的是，当我们切换到 TSC 时，它会在 sched clock init 期间发生。
	 */
	if ((s64)delta < 0) {
		// 如果确实出现了这种情况，则重置上次更新的时间
		sa->last_update_time = now;
		return 0;
	}

	/*
	 原文注释：
	 使用 1024ns 作为测量单位，因为它是 1us 的合理近似值并且计算速度很快。
	 */
	// 使用1024直接可以用移位进行计算，所以速度快，这里向右移10位，就算出了
	// 有多少个1us，
	delta >>= 10;
	if (!delta)
		return 0;

	// 这里又将delta转化成ns后，加到last_update_time，
	// 这里为什么不直接等于now呢？我猜应该是last_update_time只记录整数us数，
	// 在前面已经将delta归整为纳秒数（虽然是以1024为单位，但是不要在间这些细节）
	sa->last_update_time += delta << 10;

	/*
	 * running is a subset of runnable (weight) so running can't be set if
	 * runnable is clear. But there are some corner cases where the current
	 * se has been already dequeued but cfs_rq->curr still points to it.
	 * This means that weight will be 0 but not running for a sched_entity
	 * but also for a cfs_rq if the latter becomes idle. As an example,
	 * this happens during idle_balance() which calls
	 * update_blocked_averages()
	 */
	 // 当负载为0时，重置runnable和running为0
	 // todo: 这个条件没看懂
	if (!load)
		runnable = running = 0;

	// 计算累积的负载值
	if (!accumulate_sum(delta, cpu, sa, load, runnable, running))
		return 0;

	return 1;
}

/*
 * 原文注释：
 * 累加总和的三个独立部分； d1 上一个（不完整）周期的剩余时间，d2 整个周期的跨度，d3 是（不完整）当前周期的剩余部分。
 *
 *           d1          d2           d3
 *           ^           ^            ^
 *           |           |            |
 *         |<->|<----------------->|<--->|
 * ... |---x---|------| ... |------|-----x (now)
 *
 *                           p-1
 * u' = (u + d1) y^p + 1024 \Sum y^n + d3 y^0
 *                           n=1
 *
 *    = u y^p +					(Step 1)
 *
 *                     p-1
 *      d1 y^p + 1024 \Sum y^n + d3 y^0		(Step 2)
 *                     n=1
 */

static __always_inline u32
accumulate_sum(u64 delta, int cpu, struct sched_avg *sa,
	       unsigned long load, unsigned long runnable, int running)
{
	unsigned long scale_freq, scale_cpu;
	u32 contrib = (u32)delta; /* p == 0 -> delta < 1024 */
	u64 periods;

	// scale_freq在x86平台是1024，这个应该是cpu的频率
	scale_freq = arch_scale_freq_capacity(cpu);

	// 这里的scale_cpu算出来也是1024，因为sd传的是NULL
	scale_cpu = arch_scale_cpu_capacity(NULL, cpu);

	// period_contrib保存的是上一次计算时d3的值，这里将d3的
	// 值再加上，则好和d1组成了一个完整的周期
	delta += sa->period_contrib;

	// 注释说的很清楚，周期是以1毫秒为单位的
	periods = delta / 1024; /* A period is 1024us (~1ms) */

	
	if (periods) {

		// 第一步：先衰减老的统计数据
		sa->load_sum = decay_load(sa->load_sum, periods);
		sa->runnable_load_sum =
			decay_load(sa->runnable_load_sum, periods);
		sa->util_sum = decay_load((u64)(sa->util_sum), periods);

		// delta现在是新的d3的值
		delta %= 1024; 

		// 1024-sa->period_contrib 就是 d1的值
		// __accumulate_pelt_segments是计算本次的d1,d2,d3的值
		contrib = __accumulate_pelt_segments(periods,
				1024 - sa->period_contrib, delta);
	}

	// 保存d3的值
	sa->period_contrib = delta;

	// cap_scale展开：contrib = (contrib * scale_freq) >> 10
	// 在x86平台上，经过计算后的contrib不变
	contrib = cap_scale(contrib, scale_freq);

	// 在进程中load和runnable的权重是一样的，都被变换为1024的倍数
	// 所以在这里累加负载和的时候，将进行的权重也加到里面
	// 权重大的进程负载也重
	if (load)
		sa->load_sum += load * contrib;
	if (runnable)
		sa->runnable_load_sum += runnable * contrib;

	// 计算运行中负载时，将cpu的算力也加了进去
	if (running)
		sa->util_sum += contrib * scale_cpu;

	return periods;
}

/*
 * Approximate:
 *   val * y^n,    where y^32 ~= 0.5 (~1 scheduling period)
 * y^32是0.5，经过32个周期，负载缩减一半
 */
static u64 decay_load(u64 val, u64 n)
{
	unsigned int local_n;

	// LOAD_AVG_PERIOD 是32，经过32*63个周期，负载缩减为0
	if (unlikely(n > LOAD_AVG_PERIOD * 63))
		return 0;

	/* after bounds checking we can collapse to 32-bit */
	local_n = n;

	// 先计算整32数倍周期的，因为32个周期缩减一半，
	// 直接用移位就可以计算，效率高，
	// 估计这也是为什么把负载周期设为1024的原因
	if (unlikely(local_n >= LOAD_AVG_PERIOD)) {
		val >>= local_n / LOAD_AVG_PERIOD;

		// local_n是剩余的小于32的周期
		local_n %= LOAD_AVG_PERIOD;
	}

	// runnable_avg_yN_inv是32个周期的速算数
	// mul_u64_u32_shr实际上就是计算 val * runnable_avg_yN_inv[local_n]
	// mul_u64_u32_shr是做64位与32位的乘法
	val = mul_u64_u32_shr(val, runnable_avg_yN_inv[local_n], 32);
	return val;
}

static u32 __accumulate_pelt_segments(u64 periods, u32 d1, u32 d3)
{
	// c3也就是d3
	u32 c1, c2, c3 = d3; /* y^0 == 1 */

	/*
	 * c1 = d1 y^p
	 */
	 // 先将d1的值衰减periods周期
	c1 = decay_load((u64)d1, periods);

	/*
	 *            p-1
	 * c2 = 1024 \Sum y^n
	 *            n=1
	 *
	 *              inf        inf
	 *    = 1024 ( \Sum y^n - \Sum y^n - y^0 )
	 *              n=0        n=p
	 */
	 // 将c2的计算变换了一下，加快计算效率
	c2 = LOAD_AVG_MAX - decay_load(LOAD_AVG_MAX, periods) - 1024;

	return c1 + c2 + c3;
}
```

```c
static __always_inline void
___update_load_avg(struct sched_avg *sa, unsigned long load, unsigned long runnable)
{
	// todo: divider的计算没看懂
	u32 divider = LOAD_AVG_MAX - 1024 + sa->period_contrib;

	// div_u64是计算除法的：第一个参数 / 第二个参数
	// todo: 这里为什么要乘以load和runnable没看懂
	sa->load_avg = div_u64(load * sa->load_sum, divider);
	sa->runnable_load_avg =	div_u64(runnable * sa->runnable_load_sum, divider);

	// 对于64位及64位以下的类型，WRITE_ONCE展开后就是： 第一个参数 = 第二个参数
	// 大于64位的类型，WRITE_ONCE展开后就是memcpy(第一个参数，第二个参数， sizeof(第一个参数))
	WRITE_ONCE(sa->util_avg, sa->util_sum / divider);
}
```

```c
static void attach_entity_load_avg(struct cfs_rq *cfs_rq, struct sched_entity *se, int flags)
{
	u32 divider = LOAD_AVG_MAX - 1024 + cfs_rq->avg.period_contrib;

	// 同步队列的衰减窗口
	// 原文注释上说，如果不同步这个时间窗口，会出现一些奇怪的事情
	se->avg.last_update_time = cfs_rq->avg.last_update_time;
	se->avg.period_contrib = cfs_rq->avg.period_contrib;

	// 同步了衰减窗口之后，要再重新计算运行总值
	se->avg.util_sum = se->avg.util_avg * divider;

	// 总负载就是divider
	// todo: 没看懂
	se->avg.load_sum = divider;

	// se_weight是将se的权重按比例缩小（向右移10位）
	// 只有优先级比0大时才会进入这个分支，因为nice0的权重是1024，右移10位刚好是1.
	if (se_weight(se)) {
		// 重新计算总负载
		se->avg.load_sum =
			div_u64(se->avg.load_avg * se->avg.load_sum, se_weight(se));
	}

	// 先将可运行负载等于总负载
	se->avg.runnable_load_sum = se->avg.load_sum;

	// 将se的平均负载和总负载加到队列的相应负载上
	enqueue_load_avg(cfs_rq, se);

	// 将se运行时的平均负载和和总负载加到队列相应的变量上
	cfs_rq->avg.util_avg += se->avg.util_avg;
	cfs_rq->avg.util_sum += se->avg.util_sum;

	// 下面两个函数和组调度有关
	add_tg_cfs_propagate(cfs_rq, se->avg.load_sum);

	cfs_rq_util_change(cfs_rq, flags);
}

static inline void
enqueue_load_avg(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	cfs_rq->avg.load_avg += se->avg.load_avg;

	// 加总负载的要扩大se权重的倍数
	cfs_rq->avg.load_sum += se_weight(se) * se->avg.load_sum;
}

```

```c
int __update_load_avg_se(u64 now, int cpu, struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	if (entity_is_task(se))
		// 如果是task，则运行时权重和nice的权重相同
		se->runnable_weight = se->load.weight;

	// ___update_load_sum的后三个参数是load（是否有负载）, runnable（是否可运行）, running（是否正在运行）
	// 对于普通进程来说，load和runnable传的值是相同的，都是!!se->on_rq（!!的意思是将值归为0和1）,
	// se->on_rq表示是否在运行队列上。
	// 第三个参数传的是cfs_rq->curr == se， 表示当前进程是否正在运行
	if (___update_load_sum(now, cpu, &se->avg, !!se->on_rq, !!se->on_rq,
				cfs_rq->curr == se)) {
		// 更新平均负载
		// se_weight和se_runnable会将权重值缩小为nice0权重的倍数
		___update_load_avg(&se->avg, se_weight(se), se_runnable(se));

		// 好像是记录之前的负载
		// todo：没看懂。
		cfs_se_util_change(&se->avg);
		return 1;
	}

	return 0;
}
```