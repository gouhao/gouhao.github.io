# 负载均衡
代码基于4.19。

# 负载均衡的时机
* 在scheduler_tick时进行
* 在schedule时，cpu队列为空时进行
* wake_up_new_task(在fork的时候), sched_exec（执行新程序时）, try_to_wake_up（唤醒一个进程时）

## scheduler_tick
在scheduler_tick中，每次都会调用trigger_load_balance来进行负载均衡。
```c
// kernel/sched/core.c

void scheduler_tick(void)
{
	...
    // 更新当前进程vruntime等统计信息，这个过程中，当前进程可能会被调度
	curr->sched_class->task_tick(rq, curr, 0);

    // 计算负载相关
	cpu_load_update_active(rq);
	calc_global_load_tick(rq);

#ifdef CONFIG_SMP
	rq->idle_balance = idle_cpu(cpu);

    // 负载均衡
	trigger_load_balance(rq);
#endif
}
```

```c
// kernel/sched/fair.c
void trigger_load_balance(struct rq *rq)
{
	// todo:没看懂
	if (unlikely(on_null_domain(rq)))
		return;

    // 如果时间超过了运行队列的next_balance值，则触发软中断进行负载均衡，
	// 软中断在系统调用/中断返回前会进行检测并处理，
	// 所以这里在本次时钟中断执行完后就会执行负载均衡
	if (time_after_eq(jiffies, rq->next_balance))
		raise_softirq(SCHED_SOFTIRQ);

    // todo:没看懂
	nohz_balancer_kick(rq);
}
```
软中断的注册是在fair的初始化函数中，init_sched_fair_class在内核start的时候就会被调用。
```c
// kernel/sched/fair.c
__init void init_sched_fair_class(void)
{
#ifdef CONFIG_SMP
	open_softirq(SCHED_SOFTIRQ, run_rebalance_domains);

#ifdef CONFIG_NO_HZ_COMMON
	nohz.next_balance = jiffies;
	nohz.next_blocked = jiffies;
	zalloc_cpumask_var(&nohz.idle_cpus_mask, GFP_NOWAIT);
#endif
#endif /* SMP */

}
```

```c
// kernel/sched/fair.c
static __latent_entropy void run_rebalance_domains(struct softirq_action *h)
{
	struct rq *this_rq = this_rq();

    // idle_balance的值是在scheduler_tick中设置的，如果
    // 当前cpu空闲，idle_balance为1,否则为0
	enum cpu_idle_type idle = this_rq->idle_balance ?
						CPU_IDLE : CPU_NOT_IDLE;

    // todo:没看懂
	if (nohz_idle_balance(this_rq, idle))
		return;

	// 这个函数里会更新阻塞进程的平均负载
	// todo: 没看懂
	update_blocked_averages(this_rq->cpu);

    // 真正的进行负载均衡
	rebalance_domains(this_rq, idle);
}
```

```c
// kernel/sched/fair.c
static void rebalance_domains(struct rq *rq, enum cpu_idle_type idle)
{
	int continue_balancing = 1; // 继续进行平衡
	int cpu = rq->cpu; // 当前cpu
	unsigned long interval; 
	struct sched_domain *sd;
	/* Earliest time when we have to do rebalance again */
	unsigned long next_balance = jiffies + 60*HZ; // 初始化下一次要平衡的时间，60秒之后
	int update_next_balance = 0;

    //  需要同步          需要衰减
	int need_serialize, need_decay = 0;
	u64 max_cost = 0; // 进行平衡花费的时间

	rcu_read_lock();

    // 开始遍历每个调度域，这个循环自底向上遍历，
    // 因为逻辑cpu处于最下层，所以向上遍历时都会让sd=sd->parent
	for_each_domain(cpu, sd) {

        // 如果当前时间超过了next_decay_max_lb_cost，则衰减max_newidle_lb_cost，
        // max_newidle_lb_cost在idle平衡中会使用
		if (time_after(jiffies, sd->next_decay_max_lb_cost)) {
			// todo:253, 256是什么意思，没看懂
			sd->max_newidle_lb_cost =
				(sd->max_newidle_lb_cost * 253) / 256;
			sd->next_decay_max_lb_cost = jiffies + HZ;
			need_decay = 1;
		}
		max_cost += sd->max_newidle_lb_cost;

        // 如果当前调度域不允许负载均衡，则继续循环
		if (!(sd->flags & SD_LOAD_BALANCE))
			continue;

		// 如果不再需要平衡且不再衰减，则跳出循环
		if (!continue_balancing) {

            // 这里当need_decay为1时，则继续循环，相当于只执行上面对
            // max_newidle_lb_cost做衰减
			if (need_decay)
				continue;
			break;
		}

        // 获取本调度域的平衡间隔时间，其实获取的是sd->balance_interval的值，balance_interval初始化和权重值相同
		// 第二个参数标识当前cpu是否忙，如果是忙的话则是sd->busy_factor * sd->balance_interval的值
		// busy_factor的值为32,在初始化的时候定的
		// 这个间隔值最小为1, 最大为max_load_balance_interval（单位是jiffies）
		// sd->busy_factor, sd->balance_interval这些值都是毫秒为单位，这个函数会把它转化成jiffies为单位
		interval = get_sd_balance_interval(sd, idle != CPU_IDLE);

        // 如果此调度域需要同步，则要获取锁
		need_serialize = sd->flags & SD_SERIALIZE;
		if (need_serialize) {
			if (!spin_trylock(&balancing))
				goto out;
		}

        // 判断当前时间是否达到了此调度域的平衡时间点，平衡时间点为上次平衡时间+平衡间隔
		// 不能太频繁的进行平衡，否则会影响性能
		if (time_after_eq(jiffies, sd->last_balance + interval)) {

            // 真正的进行负载均衡，这个函数的返回值是pull来的进程数
			// continue_balancing这个值会在这个函数里被改
			if (load_balance(cpu, rq, sd, idle, &continue_balancing)) {
                // 如果有拉过来的任务，再判断一下当前cpu的状态
				idle = idle_cpu(cpu) ? CPU_IDLE : CPU_NOT_IDLE;
			}
            
            // 更新上次平衡的时间。last_balance设置的地方只有两个：一个是初始化，一个就是这里
			sd->last_balance = jiffies;

            // 更新平衡时间间隔，因为balance_interval在load_balance中有可能会被修改
			interval = get_sd_balance_interval(sd, idle != CPU_IDLE);
		}
		if (need_serialize)
			spin_unlock(&balancing);
out:
        // 下次均衡的时间最大不能超过调度域最后一次平衡时间+间隔
		// 这个next_balance最后会赋值给rq->next_balance，也就是当前队列下一次要进行平衡的时间
		// 从所有调度域里选择一个最小的时间点，做为此队列下一次要进行负载平衡的时间
		if (time_after(next_balance, sd->last_balance + interval)) {
			next_balance = sd->last_balance + interval;
			update_next_balance = 1;
		}
	}

	// 计算平衡的花费时间
	if (need_decay) {
		rq->max_idle_balance_cost =
			max((u64)sysctl_sched_migration_cost, max_cost);
	}
	rcu_read_unlock();

	// 更新下次平衡时间
	if (likely(update_next_balance)) {
		rq->next_balance = next_balance;

#ifdef CONFIG_NO_HZ_COMMON
		// 更新nohz下次更新时间
		if ((idle == CPU_IDLE) && time_after(nohz.next_balance, rq->next_balance))
			nohz.next_balance = rq->next_balance;
#endif
	}
}
```

// todo:各个平衡时间之间的关系

```c
// kernel/sched/fair.c
/**
* this_cpu, this_rq: 要迁移的cpu号和cpu的队列
* sd: 调度域，表示在要当前调度域里做均衡
* idle: 要迁移的cpu是否空闲
* continue_balancing: 是否要继续做迁移，用做主调函数做判断
*/
static int load_balance(int this_cpu, struct rq *this_rq,
			struct sched_domain *sd, enum cpu_idle_type idle,
			int *continue_balancing)
{
	int ld_moved, cur_ld_moved, active_balance = 0;
	struct sched_domain *sd_parent = sd->parent;
	struct sched_group *group;
	struct rq *busiest;
	struct rq_flags rf;
	struct cpumask *cpus = this_cpu_cpumask_var_ptr(load_balance_mask);

	// 负载均衡时的上下文
	struct lb_env env = {
		.sd		= sd, // 当前cpu所属的调度域
		.dst_cpu	= this_cpu, // 当前cpu序号
		.dst_rq		= this_rq, // 当前cpu队列
		.dst_grpmask    = sched_group_span(sd->groups), // 当前cpu所属组内的cpu集合
		.idle		= idle, // idle状态
		.loop_break	= sched_nr_migrate_break, // 迁移中断的次数（迁移多少次后中断）
		.cpus		= cpus, // 系统可以进行负载均衡的cpu（这个参数在下面会被修改）
		.fbq_type	= all, // 负载均衡的类型（todo: 不是很明白）
		.tasks		= LIST_HEAD_INIT(env.tasks), // 初始化链表头，迁移来的任务会挂在这个链上
	};

	// 这个函数可以看成：cpus = sched_domain_span(sd) & cpu_active_mask;
	// 这里将调度域里的cpu与激活状态的cpu相与，也就是只有激活状态的cpu参与迁移。
	// cpu_active_mask记录着系统里激活状态的cpu。（todo: 还没看这个变量的修改过程）
	cpumask_and(cpus, sched_domain_span(sd), cpu_active_mask);

	// 增加负载均衡计数
	schedstat_inc(sd->lb_count[idle]);

redo:

	// 当前cpu是否应该做负载均衡，如果不合适直接退出
	if (!should_we_balance(&env)) {
		*continue_balancing = 0;
		goto out_balanced;
	}

	// 在本调度域内找一个最繁忙的调度组
	group = find_busiest_group(&env);
	if (!group) {
		// 如果没有最繁忙的组，增加一下相关变量的值，然后返回
		schedstat_inc(sd->lb_nobusyg[idle]);
		goto out_balanced;
	}

	// 在繁忙的组里找一个最忙的运行队列、
	busiest = find_busiest_queue(&env, group);
	if (!busiest) {
		// 如果没有最繁忙的队列，增加一下相关统计变量的值，然后返回
		schedstat_inc(sd->lb_nobusyq[idle]);
		goto out_balanced;
	}

	// 最繁忙的队列怎么会是dst_rq呢？很显然是个bug
	BUG_ON(busiest == env.dst_rq);

	// 把需要移动的负载量加到lb_imbalance[idle]数组里
	// todo: 不知道这个数组里记录这些数据是干什么用的
	schedstat_add(sd->lb_imbalance[idle], env.imbalance);

	// 将最繁忙的cpu和最繁忙的运行队列记录到env环境信息中
	env.src_cpu = busiest->cpu;
	env.src_rq = busiest;

	// 转移到本地cpu的任务数量
	ld_moved = 0;
	if (busiest->nr_running > 1) {
		// todo: 这个标志不啥意思？
		env.flags |= LBF_ALL_PINNED;

		// 循环的最大次数是任务数量和sysctl_sched_nr_migrate的最小值，
		// 这里的迁移次数会在迁移任务的方法里使用，肯定不能超过nr_running次，
		// 否则，只运行了那么多任务，多迁移几次没有意义
		env.loop_max  = min(sysctl_sched_nr_migrate, busiest->nr_running);

more_balance:
		// 要从繁忙队列里转移任务，肯定要先锁住繁忙对列，并且保存中断
		rq_lock_irqsave(busiest, &rf);
		update_rq_clock(busiest);

		// 从繁忙队列里出队几个任务
		cur_ld_moved = detach_tasks(&env);

		// 已经转移完了，就释放繁忙队列锁
		rq_unlock(busiest, &rf);

		// 如果有转移出来的任务，就把任务加到当前队列里
		if (cur_ld_moved) {
			// 移过来的任务加到目标队列中
			attach_tasks(&env);
			ld_moved += cur_ld_moved;
		}

		// 还原中断
		local_irq_restore(rf.flags);

		// 这个标志在detach_tasks中设置，有这个标志需要再次平衡
		// todo: 暂时不知道这个标志是啥意思
		if (env.flags & LBF_NEED_BREAK) {
			env.flags &= ~LBF_NEED_BREAK;
			goto more_balance;
		}

		// 这个标志在detach_tasks中设置，由于迁移的任务不允许在当前cpu中运行，
		// 把重新设置dst_cpu，然后再次转移任务，loop_break设置的是默认值sched_nr_migrate_break
		// 重新选择cpu，重新选择cpu后，就要重新进行选择系统组和繁忙队列
		// todo: 没太看懂
		if ((env.flags & LBF_DST_PINNED) && env.imbalance > 0) {

			/* Prevent to re-select dst_cpu via env's CPUs */
			cpumask_clear_cpu(env.dst_cpu, env.cpus);

			env.dst_rq	 = cpu_rq(env.new_dst_cpu);
			env.dst_cpu	 = env.new_dst_cpu;
			env.flags	&= ~LBF_DST_PINNED;
			env.loop	 = 0;
			env.loop_break	 = sched_nr_migrate_break;

			goto more_balance;
		}

		// 根据条件更新父调度域的不平衡标志
		if (sd_parent) {
			int *group_imbalance = &sd_parent->groups->sgc->imbalance;

			// todo: LBF_SOME_PINNED标志都没有看懂
			// 这里只更新组不平衡，
			// 猜测：经过转移任务之后，如果还没有达到平衡，则设置这个组不平衡
			if ((env.flags & LBF_SOME_PINNED) && env.imbalance > 0)
				*group_imbalance = 1;
		}

		// todo:没看懂
		if (unlikely(env.flags & LBF_ALL_PINNED)) {
			cpumask_clear_cpu(cpu_of(busiest), cpus);
			
			// todo: 没看懂
			if (!cpumask_subset(cpus, env.dst_grpmask)) {
				env.loop = 0;
				env.loop_break = sched_nr_migrate_break;
				goto redo;
			}
			goto out_all_pinned;
		}
	}

	// 下面是处理pull模式下负载均衡失败的情况，
	// 失败时将启用push模式，push模式由最繁忙的cpu主动给本cpu推任务
	if (!ld_moved) {
		// 增加负载均衡失败的计数，没有成功移出任务就被当做是失败
		schedstat_inc(sd->lb_failed[idle]);
		
		// 如果不是将要变成空闲的cpu，则增加调度域的失败次数
		// todo: 为什么只在这种情况下增加失败次数
		if (idle != CPU_NEWLY_IDLE)
			sd->nr_balance_failed++;

		if (need_active_balance(&env)) {
			unsigned long flags;

			raw_spin_lock_irqsave(&busiest->lock, flags);

			// 看目标cpu上正在运行的任务是否允许在当前cpu上运行，如果不允许则直接退出
			if (!cpumask_test_cpu(this_cpu, &busiest->curr->cpus_allowed)) {
				raw_spin_unlock_irqrestore(&busiest->lock, flags);
				// todo：这个标志啥意思？
				env.flags |= LBF_ALL_PINNED;
				goto out_one_pinned;
			}

			// 如果最忙cpu的push模式没有被激活，则激活最忙cpu的push模式，
			// 要push的目标cpu是当前cpu
			if (!busiest->active_balance) {
				busiest->active_balance = 1;
				busiest->push_cpu = this_cpu;
				active_balance = 1;
			}
			raw_spin_unlock_irqrestore(&busiest->lock, flags);

			if (active_balance) {
				// 调用stopper线程来执行push模式的负载均衡，
				// 真正执行的函数是active_load_balance_cpu_stop，
				// stopper是异步执行，但是这个函数会等到push模式的负载均衡
				// 结束之后才会返回
				stop_one_cpu_nowait(cpu_of(busiest),
					active_load_balance_cpu_stop, busiest,
					&busiest->active_balance_work);
			}

			/* We've kicked active balancing, force task migration. */
			sd->nr_balance_failed = sd->cache_nice_tries+1;
		}
	} else
		// 重置均衡失败
		sd->nr_balance_failed = 0;

	if (likely(!active_balance)) {
		// 如果没有激活push模式，则重置均衡间隔为最小间隔
		sd->balance_interval = sd->min_interval;
	} else {
		 // 如果激活了push模式，则把均衡间隔值翻倍
		 // todo: 为啥要翻倍，不明白
		if (sd->balance_interval < sd->max_interval)
			sd->balance_interval *= 2;
	}

	goto out;

// 下面三个out_标签都是处理负载均衡失败的情况
out_balanced:
	// todo: 没看懂
	if (sd_parent && !(env.flags & LBF_ALL_PINNED)) {
		// 这里是清空父调度域调度组的不平衡标志。

		// 下面这三句代码为啥不直接写成： sd_parent->groups->sgc->imbalance = 0，
		// 难道是为了可读性？？
		int *group_imbalance = &sd_parent->groups->sgc->imbalance;

		if (*group_imbalance)
			*group_imbalance = 0;
	}

out_all_pinned:
	/*
	 * We reach balance because all tasks are pinned at this level so
	 * we can't migrate them. Let the imbalance flag set so parent level
	 * can try to migrate them.
	 */
	schedstat_inc(sd->lb_balanced[idle]);

	// 清空失败标志
	// 根据原文注释，这样可以让父调度域继续执行均衡操作
	sd->nr_balance_failed = 0;

out_one_pinned:
	ld_moved = 0;

	if (env.idle == CPU_NEWLY_IDLE)
		goto out;

	/* tune up the balancing interval */
	// todo: 没看懂，为什么在负载固定时要把迁移间隔翻倍
	if (((env.flags & LBF_ALL_PINNED) &&
			sd->balance_interval < MAX_PINNED_INTERVAL) ||
			(sd->balance_interval < sd->max_interval))
		sd->balance_interval *= 2;
out:
	return ld_moved;
}

static int detach_tasks(struct lb_env *env)
{
	struct list_head *tasks = &env->src_rq->cfs_tasks;
	struct task_struct *p;
	unsigned long load;
	int detached = 0;

	lockdep_assert_held(&env->src_rq->lock);

	// 如果需要移动的负载量为0,则不需要移动task，直接返回0
	if (env->imbalance <= 0)
		return 0;

	while (!list_empty(tasks)) {
		// 如果目标队列中只有一个任务或者没有，且当前队列是空闲的，则不移动了，否则会造成新的不平衡，
		// 当cpu繁忙或者可运行数量大于1时则进行迁移
		if (env->idle != CPU_NOT_IDLE && env->src_rq->nr_running <= 1)
			break;

		// 取出最后一个任务
		p = list_last_entry(tasks, struct task_struct, se.group_node);

		// 迁移次数增加1
		env->loop++;
		
		// 如果已经循环到限制值，则停止循环，直接退出
		if (env->loop > env->loop_max)
			break;

		// 如果已经循环到中断值，则退出休息一会，
		// loop_break这个变量应该是控制迁移太快吧，到达这个路径时，则退出迁移，
		// 然后由主控函数来判断是否还需要再次迁移。
		// todo: 这个路径没太看懂
		if (env->loop > env->loop_break) {
			env->loop_break += sched_nr_migrate_break;
			env->flags |= LBF_NEED_BREAK;
			break;
		}

		// 如果不能迁移则继续循环
		if (!can_migrate_task(p, env))
			goto next;

		// 计算进程的负载，如果负载为0，则归为1
		load = max_t(unsigned long, task_h_load(p), 1);

		// 负载小于16并且当前调度域没有失败过时不迁移，可能作者觉得迁移它所带来的花费会抵消优化。
		// sched_feat是调度特性，sched_feat(LB_MIN)应该是限制最小负载的迁移。（猜的）
		// todo: 没太看懂
		if (sched_feat(LB_MIN) && load < 16 && !env->sd->nr_balance_failed)
			goto next;

		// 负载的一半都比本次要迁移的不平衡负载多了，那肯定不能迁移这个进程，
		// 否则会导致新的不平衡。（猜的）
		// todo: 没太看懂，没有证据证明上面说的。
		if ((load / 2) > env->imbalance)
			goto next;

		// 走到这里就表示这进程可以迁移
		// detach_task把这个任务从当前链表脱链，再设置改变目标cpu
		detach_task(p, env->src_rq, env->dst_cpu);

		// 将这个任务加到env的task中
		list_add(&p->se.group_node, &env->tasks);

		// 增加迁移出进程的计数
		detached++;

		// 从拉取的总负载中减掉这个进程的负载
		env->imbalance -= load;

#ifdef CONFIG_PREEMPT
		// 在可抢占的内核中，如果idle类型是NEW_IDLE, 则在转移了一个任务之后，立刻返回，
		// 否则会造成延迟。
		if (env->idle == CPU_NEWLY_IDLE)
			break;
#endif

		// 需要迁移的负载够了，则退出循环
		if (env->imbalance <= 0)
			break;

		continue;
next:
		// 这里把这个任务重新加到任务列表里
		// list_move是先删除再添加
		// todo: 这里为什么要用list_move？
		list_move(&p->se.group_node, tasks);
	}

	// 增加已拉取的进程数，这些都是统计数据，
	// 打开SCHED_DEBUG可以看到这些统计数据
	schedstat_add(env->sd->lb_gained[env->idle], detached);

	// 返回已分离的进程数
	return detached;
}

static int can_migrate_task(struct task_struct *p, struct lb_env *env)
{
	int tsk_cache_hot;

	// 锁住队列
	lockdep_assert_held(&env->src_rq->lock);

	 /**
		下面几种任务不能迁移：
		
		1. cpu_allowed不允许在这个cpu上运行，
		2. 正在运行的进程
		3. 当前cpu上的cache还是热的
	 */

	// 节流进程不许迁移
	if (throttled_lb_pair(task_group(p), env->src_cpu, env->dst_cpu))
		return 0;

	
	if (!cpumask_test_cpu(env->dst_cpu, &p->cpus_allowed)) {
		// 这个分支是当前进程的cpu_allowed，不允许在目标cpu上运行，也不允许转移
		int cpu;

		// 递增因为亲和性迁移失败的次数
		schedstat_inc(p->se.statistics.nr_failed_migrations_affine);

		// todo: 这个标志没看懂
		env->flags |= LBF_SOME_PINNED;

		/*
		 * Remember if this task can be migrated to any other CPU in
		 * our sched_group. We may want to revisit it if we couldn't
		 * meet load balance goals by pulling other tasks on src_cpu.
		 *
		 * Avoid computing new_dst_cpu for NEWLY_IDLE or if we have
		 * already computed one in current iteration.
		 */
		if (env->idle == CPU_NEWLY_IDLE || (env->flags & LBF_DST_PINNED))
			return 0;

		// 重新选择dst_cpu
		for_each_cpu_and(cpu, env->dst_grpmask, env->cpus) {
			if (cpumask_test_cpu(cpu, &p->cpus_allowed)) {
				env->flags |= LBF_DST_PINNED;
				env->new_dst_cpu = cpu;
				break;
			}
		}

		
		return 0;
	}

	// 走到这里表示有任务可以迁移到目标cpu上
	env->flags &= ~LBF_ALL_PINNED;

	// 当前进程正在运行，增加因为运行而迁移失败的次数
	if (task_running(env->src_rq, p)) {
		schedstat_inc(p->se.statistics.nr_failed_migrations_running);
		return 0;
	}

	
	/*
	原文注释：强制转移的条件
	1. 目标numa节点是优选的
	2. 任务的cache是冷的
	3. 平衡失败次数太多
	*/

	// migrate_degrades_locality 只有在CONFIG_NUMA_BALANCING配置打开时才有效，否则返回-1
	/**
	migrate_degrades_locality:
	返回1: 会降低局部性，说明当前进程的缓存是热的
	返回0: 会提高局部性，说明缓存是冷的
	返回-1: 对局部性无影响
	*/
	tsk_cache_hot = migrate_degrades_locality(p, env);

	// 如果迁移此进程对局部性无影响的话，再计算一下缓存是不是热的
	if (tsk_cache_hot == -1)
		tsk_cache_hot = task_hot(p, env);

	// 下面这个if代码写的不太好。。
	// 1.如果缓存不热，则可以迁移
	// 2.如果平衡的失败次数已经超过cache_nice_tries，即使缓存是热的也进行强制迁移
	if (tsk_cache_hot <= 0 ||
	    env->sd->nr_balance_failed > env->sd->cache_nice_tries) {
		if (tsk_cache_hot == 1) {
			// 增加热缓存计数器
			schedstat_inc(env->sd->lb_hot_gained[env->idle]);

			// 增加强制迁移计算器
			schedstat_inc(p->se.statistics.nr_forced_migrations);
		}
		return 1;
	}

	// 增加因为热缓存迁移失败的计数器
	schedstat_inc(p->se.statistics.nr_failed_migrations_hot);
	return 0;
}

static int migrate_degrades_locality(struct task_struct *p, struct lb_env *env)
{
	struct numa_group *numa_group = rcu_dereference(p->numa_group);
	unsigned long src_weight, dst_weight;
	int src_nid, dst_nid, dist;

	// 如果没有使用numa平衡，则对局部性无影响
	if (!static_branch_likely(&sched_numa_balancing))
		return -1;

	// 如果 !p->numa_faults， 或者当前调度域不支持numa，则对局部性无影响
	// todo: 何为numa_faults?
	if (!p->numa_faults || !(env->sd->flags & SD_NUMA))
		return -1;

	// 取出src和dst的numa节点id
	src_nid = cpu_to_node(env->src_cpu);
	dst_nid = cpu_to_node(env->dst_cpu);

	// 如果两个cpu在同一个numa节点里，则对局部性无影响
	if (src_nid == dst_nid)
		return -1;

	// 如果源numa_id是当前进程的优先节点
	if (src_nid == p->numa_preferred_nid) {
		if (env->src_rq->nr_running > env->src_rq->nr_preferred_running)
			// 如果源队列的运行任务比最优运行数量高的话，那么迁移降低局部性
			return 1;
		else
			// 否则，对局部性无影响
			return -1;
	}

	// 如果目标numa节点是当前进程的优先节点，那对局部性有提高
	if (dst_nid == p->numa_preferred_nid)
		return 0;

	// 如果要迁移到的cpu已经空闲，则可以迁移
	// 因为如果目标cpu空闲，即使降低源cpu的局部性，也是有好处的
	if (env->idle == CPU_IDLE)
		return -1;

	// 计算两个节点之间的距离
	// todo: 计算过程没看懂，大意是如果是同一个节点，那距离为10, 否则距离为20
	dist = node_distance(src_nid, dst_nid);
	if (numa_group) {
		src_weight = group_weight(p, src_nid, dist);
		dst_weight = group_weight(p, dst_nid, dist);
	} else {
		src_weight = task_weight(p, src_nid, dist);
		dst_weight = task_weight(p, dst_nid, dist);
	}

	// 如果目标权重小于源权重会减少局部性，否则提高局部性
	return dst_weight < src_weight;
}

static int task_hot(struct task_struct *p, struct lb_env *env)
{
	s64 delta;

	// 给源队列加锁
	lockdep_assert_held(&env->src_rq->lock);

	// 如果调度类不是cfs，则返回0
	// 估计其它调度器不用负载均衡（瞎猜的）
	if (p->sched_class != &fair_sched_class)
		return 0;

	// 如果当前task有idle策略，也表示缓存是冷的
	// todo: 不明白什么意思
	if (unlikely(task_has_idle_policy(p)))
		return 0;
	
	// todo: 没看懂
	if (sched_feat(CACHE_HOT_BUDDY) && env->dst_rq->nr_running &&
			(&p->se == cfs_rq_of(&p->se)->next ||
			 &p->se == cfs_rq_of(&p->se)->last))
		return 1;

	// 迁移花费如果是-1的话，就表示缓存是热的？
	// todo: -1是啥意思？
	if (sysctl_sched_migration_cost == -1)
		return 1;
	
	// 迁移花费如果是0，则表示迁移此任务会提高局部性
	if (sysctl_sched_migration_cost == 0)
		return 0;

	// delta算的是进程开始执行到现在的时间间隔，如果这个间隔小于迁移花费值，
	// 则表示缓存是热的。
	// rq_clock_task取的是当前队列的时间
	delta = rq_clock_task(env->src_rq) - p->se.exec_start;

	return delta < (s64)sysctl_sched_migration_cost;
}

```

```c
// kernel/sched/fair.c
static int should_we_balance(struct lb_env *env)
{
	struct sched_group *sg = env->sd->groups;
	int cpu, balance_cpu = -1;

	// 如果被迁移的cpu不在允许迁移的cpu集中，则不允许迁移
	// 这是肯定的，因为在前一个函数中env->cpus里存的只是激活状态的cpu
	if (!cpumask_test_cpu(env->dst_cpu, env->cpus))
		return 0;

	// 如果被迁移的cpu的idle状态是CPU_NEWLY_IDLE，则允许迁移
	// CPU_NEWLY_IDLE的意思应该是即将进入空闲状态的cpu，这个标志在代码里
	// 只有调度时，如果队列里没有任务时使用这个标志进行均衡
	if (env->idle == CPU_NEWLY_IDLE)
		return 1;

	// 走到这里，就不是从调度的idle进到的负载均衡，而是从时钟中断进入的，
	// 或者第一个cpu，如果找出的cpu不是当前的cpu，
	// 则不需要调度。

	// for_each_cpu_and是遍历第二，三个参数的交集
	// 在这里就是遍历调度组内的cpu，下面会找出组内第一个空闲的cpu
	for_each_cpu_and(cpu, group_balance_mask(sg), env->cpus) {
		if (!idle_cpu(cpu))
			continue;

		balance_cpu = cpu;
		break;
	}

	// 如果没有找到空闲cpu，则找出当前组内第一个cpu
	if (balance_cpu == -1)
		balance_cpu = group_balance_cpu(sg);

	// 只有第一个空闲CPU，或者第一个cpu才能做负载均衡
	return balance_cpu == env->dst_cpu;
}
```

```c
// kernel/sched/fair.c

static struct sched_group *find_busiest_group(struct lb_env *env)
{
	struct sg_lb_stats *local, *busiest;
	struct sd_lb_stats sds;

	// 将sds中的变量都初始化成0
	init_sd_lb_stats(&sds);

	// 计算与负载均衡相关的信息，在这个函数里会更新调度域内
	// 各个组的负载，并选出最繁忙的一个组
	update_sd_lb_stats(env, &sds);
	local = &sds.local_stat;
	busiest = &sds.busiest_stat;

	// 不对称cpu打包。把低优先级cpu上的任务往高cpu上转移（一般cpu序号越低优先级越高）
	if (check_asym_packing(env, &sds))
		return sds.busiest;

	// 如果没有忙的调度组，或者最忙的调度组没有任务，
	// 那说明整个组都是空闲的
	if (!sds.busiest || busiest->sum_nr_running == 0)
		goto out_balanced;

	// 计算调度域的平均负载，SCHED_CAPACITY_SCALE = 1 << 10，
	// SCHED_CAPACITY_SCALE是一个比例因子，看不懂了可以忽略
	sds.avg_load = (SCHED_CAPACITY_SCALE * sds.total_load)
						/ sds.total_capacity;

	// 如果最繁忙的组类型为不平衡，则去强制平衡，不再做下面的检测，
	// 因为下面的检测假设组类型为平衡的或者过载
	if (busiest->group_type == group_imbalanced)
		goto force_balance;

	// 如果当前cpu空闲，且本地组里有容量，最忙组里没容量，则强制平衡
	if (env->idle != CPU_NOT_IDLE && group_has_capacity(env, local) &&
	    busiest->group_no_capacity)
		goto force_balance;

	// 如果当前组的平均负载比最忙的组还忙，则不进行负载均衡
	if (local->avg_load >= busiest->avg_load)
		goto out_balanced;

	// 如果当前组的平均负载比调度域内的平均负载高，则不进行负载均衡
	if (local->avg_load >= sds.avg_load)
		goto out_balanced;

	if (env->idle == CPU_IDLE) {
		// 如果最繁忙的组不是过载，并且本地的空闲cpu数与最繁忙的组空闲cpu差不多，
		// 则不进行负载均衡，这时如果进行均衡，很可能会将不平衡转移到另一个cpu上
		if ((busiest->group_type != group_overloaded) &&
				(local->idle_cpus <= (busiest->idle_cpus + 1)))
			goto out_balanced;
	} else {
		// 最忙组的平均负载小于本地组的平均负载，则不进行负载均衡
		if (100 * busiest->avg_load <=
				env->sd->imbalance_pct * local->avg_load)
			goto out_balanced;
	}

force_balance:
	// 计算需要移动的负载量，这个量就是要从最繁忙队列拉取任务的最大值
	calculate_imbalance(env, &sds);

	// 负载量不为0，则返回最繁忙的组，否则返回NULL
	return env->imbalance ? sds.busiest : NULL;

out_balanced:
	env->imbalance = 0;
	return NULL;
}

static inline void calculate_imbalance(struct lb_env *env, struct sd_lb_stats *sds)
{
	unsigned long max_pull, load_above_capacity = ~0UL;
	struct sg_lb_stats *local, *busiest;

	local = &sds->local_stat;
	busiest = &sds->busiest_stat;

	// 如果当前组类型为不平衡，则选取load_per_task和调用域avg_load
	// 的较小值作为最终的load_per_task
	if (busiest->group_type == group_imbalanced) {
		busiest->load_per_task =
			min(busiest->load_per_task, sds->avg_load);
	}

	// 如果最忙的组平均负载小于调度域的平均负载或者
	// 本地组的平均负载大于调度域的平均负载
	if (busiest->avg_load <= sds->avg_load ||
	    local->avg_load >= sds->avg_load) {
		env->imbalance = 0;
		return fix_small_imbalance(env, sds);
	}

	// 如果最忙的组和本地组的类型都是过载，则计算负载容量的上限
	// todo: 负载容量上限的计算没看懂
	if (busiest->group_type == group_overloaded &&
	    local->group_type   == group_overloaded) {
		load_above_capacity = busiest->sum_nr_running * SCHED_CAPACITY_SCALE;
		if (load_above_capacity > busiest->group_capacity) {
			load_above_capacity -= busiest->group_capacity;
			load_above_capacity *= scale_load_down(NICE_0_LOAD);
			load_above_capacity /= busiest->group_capacity;
		} else
			load_above_capacity = ~0UL;
	}

	/**
	  原文注释：我们尽量让所有cpu达到平均负载。所以在进行了负载均衡后，当前的cpu负载在平均
	  负载之后了，也不希望把最忙cpu的负载降低到平均负载之下。同时，我们也不想把组负载减少到组的容量
	  之下，因此我们寻找最小可能的平衡数量。
	*/
	// 通过原作者做的注释可以看出，负载均衡是想让所以组都达到平均负载，所以尽量减少要平衡的进程数量。	
	// 所以下面max_pull就是要拉取的最大负载，用最忙组的平均负载减去调度域内的平均负载，
	// 所以在理想情况下，可以让所有调度组达到平均负载
	max_pull = min(busiest->avg_load - sds->avg_load, load_above_capacity);

	// 上面算出了最忙组减多少负载可以平衡，这里则算的是本地组加多少负载可以平衡。
	// 最终需要拉取的负载为2者的较小值。
	// 肯定要选较小值，如果是选两者的较大值，有可能导致本地组超过调度域的平均负载，导致新的不平衡
	env->imbalance = min(
		max_pull * busiest->group_capacity,
		(sds->avg_load - local->avg_load) * local->group_capacity
	) / SCHED_CAPACITY_SCALE;

	// 如果要拉取的负载值小于最忙调度组的每个任务的平均负载，
	// 那有可能在后面连1个任务都拉取不到，所以这里就要处理这种情况，
	// 要保证要拉取的负载值，最少能拉到1个任务
	if (env->imbalance < busiest->load_per_task)
		return fix_small_imbalance(env, sds);
}

static inline
void fix_small_imbalance(struct lb_env *env, struct sd_lb_stats *sds)
{
	unsigned long tmp, capa_now = 0, capa_move = 0;
	unsigned int imbn = 2; // 移动任务的数量，默认移动2个
	unsigned long scaled_busy_load_per_task;
	struct sg_lb_stats *local, *busiest;

	local = &sds->local_stat;
	busiest = &sds->busiest_stat;

	if (!local->sum_nr_running)
		// 如果本组没有要运行的任务，则每个任务的平均负载，为目标cpu的平均负载
		local->load_per_task = cpu_avg_load_per_task(env->dst_cpu);
	else if (busiest->load_per_task > local->load_per_task)
		// 如果最忙组的任务负载大于本地组的任务负载，则只需要
		// 移动1个任务就够了
		imbn = 1;

	// 计算任务负载与组容量的比例
	scaled_busy_load_per_task =
		(busiest->load_per_task * SCHED_CAPACITY_SCALE) /
		busiest->group_capacity;

	// 如果给最繁忙的组再加上一个任务的负载大于本地组再加上1或2个任务的负载，
	// 则需要拉取的负载量为一个任务的负载值
	if (busiest->avg_load + scaled_busy_load_per_task >=
	    local->avg_load + (scaled_busy_load_per_task * imbn)) {
		env->imbalance = busiest->load_per_task;
		return;
	}

	// 走到这里就说明，没有足够的负载需要去调整。但是可以通过移动任务来减少总cpu的使用容量。
	// 这也是对cpu负载有好处的。

	// 先计算出来现在的负载
	capa_now += busiest->group_capacity *
			min(busiest->load_per_task, busiest->avg_load);
	capa_now += local->group_capacity *
			min(local->load_per_task, local->avg_load);
	capa_now /= SCHED_CAPACITY_SCALE;

	// 再计算要移动的负载量
	if (busiest->avg_load > scaled_busy_load_per_task) {
		capa_move += busiest->group_capacity *
			    min(busiest->load_per_task,
				busiest->avg_load - scaled_busy_load_per_task);
	}

	// 每个平均负载的值
	if (busiest->avg_load * busiest->group_capacity <
	    busiest->load_per_task * SCHED_CAPACITY_SCALE) {
		tmp = (busiest->avg_load * busiest->group_capacity) /
		      local->group_capacity;
	} else {
		tmp = (busiest->load_per_task * SCHED_CAPACITY_SCALE) /
		      local->group_capacity;
	}
	capa_move += local->group_capacity *
		    min(local->load_per_task, local->avg_load + tmp);
	capa_move /= SCHED_CAPACITY_SCALE;

	// 可以移动的负载大于当前的负载，则设置移动量为一个task的负载
	if (capa_move > capa_now)
		env->imbalance = busiest->load_per_task;
}
```

```c
static inline void update_sd_lb_stats(struct lb_env *env, struct sd_lb_stats *sds)
{
	struct sched_domain *child = env->sd->child; // 子调度域
	struct sched_group *sg = env->sd->groups; // 该调度域内的组
	struct sg_lb_stats *local = &sds->local_stat; // 本地统计信息
	struct sg_lb_stats tmp_sgs;
	int load_idx, prefer_sibling = 0;
	bool overload = false; // 是否过载

	// 根据字面意思，如果子调度域喜欢兄弟调度域，则更倾向在这些调度之间平衡负载
	if (child && child->flags & SD_PREFER_SIBLING)
		prefer_sibling = 1;

#ifdef CONFIG_NO_HZ_COMMON
	if (env->idle == CPU_NEWLY_IDLE && READ_ONCE(nohz.has_blocked))
		env->flags |= LBF_NOHZ_STATS;
#endif

	// 根据idle状态，来获取该调度域内的相应cpu的索引值
	// todo: 没看懂，这个值在初始化的时候是0
	load_idx = get_sd_load_idx(env->sd, env->idle);

	do {
		struct sg_lb_stats *sgs = &tmp_sgs;
		int local_group;

		// 判断目标cpu是不是当前调度组的
		local_group = cpumask_test_cpu(env->dst_cpu, sched_group_span(sg));
		if (local_group) {
			// 如果是当前调度组的，则记录当前调度组为本地组
			sds->local = sg;
			sgs = local;

			// 如果目标cpu不是即将进入空闲的cpu，或者当前时间已经超过了调度组下次更新的时间，
			// 则更新调度组的容量。
			// todo：这里为什么只在目标cpu属于当前调度组的时候更新调度组容量呢？
			if (env->idle != CPU_NEWLY_IDLE ||
			    time_after_eq(jiffies, sg->sgc->next_update))
				update_group_capacity(env->sd, env->dst_cpu);
		}

		// 更新调度组的负载统计数据
		update_sg_lb_stats(env, sg, load_idx, local_group, sgs,
						&overload);

		// 如果是本地组的话，继续遍历下个调度组，
		// 这里就不用将本地组记录为繁忙组了，因为这里找的是最忙组，
		// 如果本组是最忙的，就不用再做负载均衡了
		if (local_group)
			goto next_group;

		// todo: 没看懂
		if (prefer_sibling && sds->local &&
		    group_has_capacity(env, local) &&
		    (sgs->sum_nr_running > local->sum_nr_running + 1)) {
			sgs->group_no_capacity = 1;
			sgs->group_type = group_classify(sg, sgs);
		}

		// 比较当前调度组与老的繁忙组的统计数据，看当前调度组是不是最忙的，
		// 如果是的话，记录之。
		if (update_sd_pick_busiest(env, sds, sg, sgs)) {
			sds->busiest = sg;
			sds->busiest_stat = *sgs;
		}

next_group:
		// 更新调度域里的总运行任务数
		sds->total_running += sgs->sum_nr_running;

		// 更新调度域里的总负载
		sds->total_load += sgs->group_load;

		// 更新调度域里的总容量
		sds->total_capacity += sgs->group_capacity;

		sg = sg->next;
	} while (sg != env->sd->groups);

#ifdef CONFIG_NO_HZ_COMMON
	// NO_HZ相关处理
	// todo: 没看懂
	if ((env->flags & LBF_NOHZ_AGAIN) &&
	    cpumask_subset(nohz.idle_cpus_mask, sched_domain_span(env->sd))) {

		WRITE_ONCE(nohz.next_blocked,
			   jiffies + msecs_to_jiffies(LOAD_AVG_PERIOD));
	}
#endif

	// todo: 没看懂，好像是在判断当前环境中有无远程numa结点
	if (env->sd->flags & SD_NUMA)
		env->fbq_type = fbq_classify_group(&sds->busiest_stat);

	// 如果当前cpu的调度域是根调度域，则更新它的过载标志
	if (!env->sd->parent) {
		if (env->dst_rq->rd->overload != overload)
			env->dst_rq->rd->overload = overload;
	}
}

static bool update_sd_pick_busiest(struct lb_env *env,
				   struct sd_lb_stats *sds,
				   struct sched_group *sg,
				   struct sg_lb_stats *sgs)
{
	/**
	 在init_sd_lb_stats中,busiest_stat被初始化成下面这样，
	 .busiest_stat = {
			.avg_load = 0UL,
			.sum_nr_running = 0,
			.group_type = group_other,
		},
	*/
	struct sg_lb_stats *busiest = &sds->busiest_stat;

	/**
		group_type定义如下，值越大表示越繁忙。
		enum group_type {
			group_other = 0,
			group_imbalanced,
			group_overloaded,
		};
	*/
	if (sgs->group_type > busiest->group_type)
		return true;

	if (sgs->group_type < busiest->group_type)
		return false;

	// 比较平均负载
	if (sgs->avg_load <= busiest->avg_load)
		return false;

	// 走到这里，说明sgs和busiest的group_type相同，
	// 而且平均负载也比busiest的大
	
	// todo: 走到这里已经判断出sg的平均负载比最忙负载大，
	// 为啥不直接返回true


	// SD_ASYM_CPUCAPACITY是cpu算力不对称的标志
	// 也就是说如果这个调度域里的算力都是对称的，直接跳到asym_packing处
	if (!(env->sd->flags & SD_ASYM_CPUCAPACITY))
		goto asym_packing;

	// todo: 没看明白
	if (sgs->sum_nr_running <= sgs->group_weight &&
	    group_smaller_cpu_capacity(sds->local, sg))
		return false;

asym_packing:
	// 如果本调度域都是对称打包，这个sg就是最忙的组
	if (!(env->sd->flags & SD_ASYM_PACKING))
		return true;

	// 如果当前cpu不空闲，说明比busiest忙
	if (env->idle == CPU_NOT_IDLE)
		return true;

	// 走到这里是cpu空闲时，也就是队列里没有任务

	
	// sched_asym_prefer是比较第1个和第2个cpu哪个优化级高
	// 在不对称算力的处理器中一般都是序号小的处理器算力大
	
	// 如果要均衡的cpu算力比sg组内的高优先级的cpu还高
	if (sgs->sum_nr_running &&
	    sched_asym_prefer(env->dst_cpu, sg->asym_prefer_cpu)) {
		if (!sds->busiest)
			return true;

		// 更愿意从低优先级的cpu上转移进程
		if (sched_asym_prefer(sds->busiest->asym_prefer_cpu,
				      sg->asym_prefer_cpu))
			return true;
	}

	return false;
}

```
```c
void update_group_capacity(struct sched_domain *sd, int cpu)
{
	struct sched_domain *child = sd->child; // 子调度域
	struct sched_group *group, *sdg = sd->groups; // 该调度域内的调度组
	unsigned long capacity, min_capacity;
	unsigned long interval;

	// 计算下次进行更新的间隔，
	// 可以看出下次更新的间隔为sd->balance_interval，但是这个值被限制
	// 在 1UL~max_load_balance_interval之间，
	// 

	// 下次更新的间隔为sd->balance_interval
	interval = msecs_to_jiffies(sd->balance_interval);

	// 间隔值被限制在 1UL~max_load_balance_interval之间，
	// max_load_balance_interval = HZ*num_online_cpus()/10;
	// 可以看出max_load_balance_interval与在线cpu有关
	interval = clamp(interval, 1UL, max_load_balance_interval);

	// 更新下次更新的时间点
	sdg->sgc->next_update = jiffies + interval;

	// 如果没有子调度域，说明这是叶子结点，所以直接更新调度域内的cpu容量
	if (!child) {
		update_cpu_capacity(sd, cpu);
		return;
	}

	capacity = 0;
	min_capacity = ULONG_MAX;

	// 子调度域有重叠，todo: 何为重叠呢？
	if (child->flags & SD_OVERLAP) {
		/*
		 * SD_OVERLAP domains cannot assume that child groups
		 * span the current group.
		 */

		for_each_cpu(cpu, sched_group_span(sdg)) {
			struct sched_group_capacity *sgc;
			struct rq *rq = cpu_rq(cpu);

			// 如果cpu的队列没有调度域，则直接加cpu的容量
			if (unlikely(!rq->sd)) {
				capacity += capacity_of(cpu);
			} else {
				sgc = rq->sd->groups->sgc;
				capacity += sgc->capacity;
			}

			min_capacity = min(capacity, min_capacity);
		}
	} else  {
		// 如果没有重叠的话，则统计所有调度组的容量，
		// 以及记录调度组的cpu的最小容量
		group = child->groups;
		do {
			struct sched_group_capacity *sgc = group->sgc;

			capacity += sgc->capacity;
			min_capacity = min(sgc->min_capacity, min_capacity);
			group = group->next;
		} while (group != child->groups);
	}

	// 更新调组的容量值
	sdg->sgc->capacity = capacity;
	sdg->sgc->min_capacity = min_capacity;
}

static void update_cpu_capacity(struct sched_domain *sd, int cpu)
{
	// 计算cpu容量, 
	// 容量 = 当前cpu最大容量值 - 已使用的容量
	unsigned long capacity = scale_rt_capacity(sd, cpu);
	struct sched_group *sdg = sd->groups;

	// arch_scale_cpu_capacity算出来的是当前cpu最大容量值
	cpu_rq(cpu)->cpu_capacity_orig = arch_scale_cpu_capacity(sd, cpu);

	if (!capacity)
		capacity = 1;

	// 更新cpu容量
	cpu_rq(cpu)->cpu_capacity = capacity;

	// 更新调度组容量，因为当前组只有一个cpu，所以
	// 该调度组的容量与cpu的容量相同
	sdg->sgc->capacity = capacity;
	sdg->sgc->min_capacity = capacity;
}
```
```c
static inline void update_sg_lb_stats(struct lb_env *env,
			struct sched_group *group, int load_idx,
			int local_group, struct sg_lb_stats *sgs,
			bool *overload)
{
	unsigned long load;
	int i, nr_running;

	// sgs是组的负载统计数据，在更新的时候先将它清0
	memset(sgs, 0, sizeof(*sgs));

	// 遍历组内cpu
	for_each_cpu_and(i, sched_group_span(group), env->cpus) {
		struct rq *rq = cpu_rq(i);

		// todo: 没看懂
		if ((env->flags & LBF_NOHZ_STATS) && update_nohz_stats(rq, false))
			env->flags |= LBF_NOHZ_AGAIN;

		// 根据是否是组内cpu，来计算当前cpu的负载
		// target_load和source_load的计算过程一模一样，只不过
		// target_load返回的是rq->cpu_load[load_idx-1]，和cpu负载的较大值，
		// source_load返回的是较小值。
		// 这个load返回的是该队列的的平均负载值，这个平均负载值是根据pelt计算
		// 这里的load负载包含了队列中的负载和运行时的负载，pelt算法的作者认为，即使
		// 没有在cpu上运行，该task同样会对系统产生负载
		if (local_group)
			load = target_load(i, load_idx);
		else
			load = source_load(i, load_idx);

		// 统计每个cpu的负载
		sgs->group_load += load;

		// 统计每个cpu正在运行时的负载
		// util负载是只在cpu上运行的负载
		sgs->group_util += cpu_util(i);

		// 统计每个cpu的任务数量
		// h_nr_running好像是控制组内的所有进程数量，如果是普通task,
		// 则这个值和nr_running的值相同
		sgs->sum_nr_running += rq->cfs.h_nr_running;

		// 当前cpu有超过一个任务时就认为是过载的，
		// todo：这里没看懂，只有一个任务就过载，那是不是只有空队列才是不过载的？
		nr_running = rq->nr_running;
		if (nr_running > 1)
			*overload = true;

#ifdef CONFIG_NUMA_BALANCING
		// 如果配置了numa平衡，则统计numa相关的信息
		// 这个配置选项，会自动迁移任务的内存到最近的numa结点
		
		// nr_numa_running：设置了numa节点的进程数量
		// nr_preferred_running：当前numa节点与进程想要运行的numa节点相同的进程数量
		sgs->nr_numa_running += rq->nr_numa_running;
		sgs->nr_preferred_running += rq->nr_preferred_running;
#endif
		// 统计总权重负载，其实上面的load也是用weighted_cpuload算出来的
		sgs->sum_weighted_load += weighted_cpuload(rq);
		
		// 如果当前cpu是空闲，则增加组内的空闲cpu计数器
		if (!nr_running && idle_cpu(i))
			sgs->idle_cpus++;
	}

	// 统计组容量
	sgs->group_capacity = group->sgc->capacity;

	// 统计组平均负载,SCHED_CAPACITY_SCALE=1UL << 10
	// 平均负载=组负载/组容量。todo: 为什么要*SCHED_CAPACITY_SCALE？
	sgs->avg_load = (sgs->group_load*SCHED_CAPACITY_SCALE) / sgs->group_capacity;

	// 计算每个task的负载
	// 每个task的负载 = 总负载 / 运行的进程数。这里的运行包括在队列里和正在cpu上运行的
	if (sgs->sum_nr_running)
		sgs->load_per_task = sgs->sum_weighted_load / sgs->sum_nr_running;

	// 统计组权重
	sgs->group_weight = group->group_weight;

	// 计算调度组是不是没容量了
	sgs->group_no_capacity = group_is_overloaded(env, sgs);

	// 调整组的类型
	// 如果group_no_capacity，则返回group_overloaded，过载
	// 如果sgc->imbalance为真，则返回group_imbalanced，不平衡
	// 否则就是group_other。group_other应该是正常的情况
	// 不平衡说明快要超出负载承受范围了，过载说明已经明显超过负载（todo: 猜的，不是很肯定）
	sgs->group_type = group_classify(group, sgs);
}

static inline bool
group_is_overloaded(struct lb_env *env, struct sg_lb_stats *sgs)
{
	// 如果组内运行任务的数量比组权重小，那肯定是没有过载
	if (sgs->sum_nr_running <= sgs->group_weight)
		return false;

	// todo: 没看懂。
	if ((sgs->group_capacity * 100) <
			(sgs->group_util * env->sd->imbalance_pct))
		return true;

	return false;
}

static unsigned long weighted_cpuload(struct rq *rq)
{
	return cfs_rq_runnable_load_avg(&rq->cfs);
}

static unsigned long source_load(int cpu, int type)
{
	struct rq *rq = cpu_rq(cpu);
	unsigned long total = weighted_cpuload(rq);

	if (type == 0 || !sched_feat(LB_BIAS))
		return total;

	return min(rq->cpu_load[type-1], total);
}

```
```c
// kernel/sched/fair.c

static struct rq *find_busiest_queue(struct lb_env *env,
				     struct sched_group *group)
{
	struct rq *busiest = NULL, *rq;
	unsigned long busiest_load = 0, busiest_capacity = 1;
	int i;

	// 遍历调度组内的cpu，取的是第2,3参数交集的cpu
	for_each_cpu_and(i, sched_group_span(group), env->cpus) {
		unsigned long capacity, wl;

		// enum fbq_type { regular, remote, all };
		// 这三个枚举的定义见下面英文注释
		enum fbq_type rt;

		// 运行队列
		rq = cpu_rq(i);

		// 队列类型，类型见下面注释的定义，有numa和非numa之分
		rt = fbq_classify_rq(rq);

		/*
		 * We classify groups/runqueues into three groups:
		 *  - regular: there are !numa tasks
		 *  - remote:  there are numa tasks that run on the 'wrong' node
		 *  - all:     there is no distinction
		 *
		 * In order to avoid migrating ideally placed numa tasks,
		 * ignore those when there's better options.
		 *
		 * If we ignore the actual busiest queue to migrate another
		 * task, the next balance pass can still reduce the busiest
		 * queue by moving tasks around inside the node.
		 *
		 * If we cannot move enough load due to this classification
		 * the next pass will adjust the group classification and
		 * allow migration of more tasks.
		 *
		 * Both cases only affect the total convergence complexity.
		 */
		 /**
			regular: 表示当前队列里没有numa的任务
			remote: 表示当前队列里有numa的任务。有numa任务意味着有任务要访问远程numa节点
			all: 表示当前队列不区别是否有numa任务

			如果一个队列里有numa任务，那这个task对内存的访问肯定比较慢
		 */
		 // todo:没看懂
		if (rt > env->fbq_type)
			continue;

		// 运行队列容量
		// 容量最大是1024，空闲容量是用最大容量减去使用的容量
		capacity = capacity_of(i);

		// 队列运行时平均负载，这个负载包括了可运行和就绪时
		wl = weighted_cpuload(rq);

		// 如果当前队列只有一个任务，而且队列的负载大于需要pull的负载值时，
		// 如果移动这个队列的任务，则会使这个cpu成为空闲cpu
		// 而且移动过去的负载大于需要移动的负载会造成新的不平衡，所以忽略之
		if (rq->nr_running == 1 && wl > env->imbalance &&
		    !check_cpu_capacity(rq, env->sd))
			continue;

		// 记录最繁忙队列的的信息
		// todo: 为什么比较权重*容量
		if (wl * busiest_capacity > busiest_load * capacity) {
			busiest_load = wl;
			busiest_capacity = capacity;
			busiest = rq;
		}
	}

	return busiest;
}
```

## cpu队列为空

在调度的时候要选择一个新任务，选择新任务是交给每个调度器去选择：
```c
static inline struct task_struct *
pick_next_task(struct rq *rq, struct task_struct *prev, struct rq_flags *rf)
{
	const struct sched_class *class;
	struct task_struct *p;

	// 这里做了一个优化，因为大多数进程的调度器都是fair_sched_class，
	// 所以这里如果是fair或者idle时，就不用遍历每个调度器了
	if (likely((prev->sched_class == &idle_sched_class ||
		    prev->sched_class == &fair_sched_class) &&
		   rq->nr_running == rq->cfs.h_nr_running)) {

		// 调用具体调度器去选择任务
		p = fair_sched_class.pick_next_task(rq, prev, rf);

		// RETRY_TASK是迁移任务失败，所以就跳到again，遍历每个调度器
		// RETRY_TASK的定义是((void*)-1UL)
		if (unlikely(p == RETRY_TASK))
			goto again;

		// 如果返回NULL，则直接调用idle调度器类
		if (unlikely(!p))
			p = idle_sched_class.pick_next_task(rq, prev, rf);

		return p;
	}

again:
	// 这里要遍历每个调度器去选择新task，for_each_class的定义在下面
	for_each_class(class) {
		p = class->pick_next_task(rq, prev, rf);
		if (p) {
			if (unlikely(p == RETRY_TASK))
				goto again;
			return p;
		}
	}

	// 正常情况下是不可能走到这的，即使系统里一个进程也没有，也有idle进程
	// 所以走到这，肯定是bug
	BUG();
}

// kernel/sched/sched.h

// 从for_each_class的定义可以看出，头结点是stop_sched_class，各调度器
// 的链接关系为：stop_sched_class->dl_sched_class->rt_sched_class
// ->fair_sched_class->idle_sched_class->NULL
#ifdef CONFIG_SMP
#define sched_class_highest (&stop_sched_class)
#else
#define sched_class_highest (&dl_sched_class)
#endif
#define for_each_class(class) \
   for (class = sched_class_highest; class; class = class->next)
```

```c
// kernel/sched/fair.c

static struct task_struct *
pick_next_task_fair(struct rq *rq, struct task_struct *prev, struct rq_flags *rf)
{
	struct cfs_rq *cfs_rq = &rq->cfs;
	struct sched_entity *se;
	struct task_struct *p;
	int new_tasks;

again:
	// 如果运行队列为空，则跳到idle进行负载均衡
	if (!cfs_rq->nr_running)
		goto idle;

...

idle:

	// 进行负载均衡，返回的new_tasks是转移到本队列的数量
	new_tasks = idle_balance(rq, rf);

	// 如果有高优先级的任务，则返回上层函数，遍历调度器类
	if (new_tasks < 0)
		return RETRY_TASK;

	// 如果迁移到了任务，则跳到again，选择新任务
	if (new_tasks > 0)
		goto again;

	// 如果没有迁移到任务，则返回上层，会运行idle任务
	return NULL;
}
```

```c
// kernel/sched/fair.c

static int idle_balance(struct rq *this_rq, struct rq_flags *rf)
{
	unsigned long next_balance = jiffies + HZ;
	int this_cpu = this_rq->cpu;
	struct sched_domain *sd;
	int pulled_task = 0;
	u64 curr_cost = 0; // 迁移花费的总时间

	// 记录idle的时间戳
	this_rq->idle_stamp = rq_clock(this_rq);

	// 如果当前cpu不是活跃的，当然不能给它迁移任务
	// todo: 不知道在哪设置的这个状态
	if (!cpu_active(this_cpu))
		return 0;

	/*
	 * This is OK, because current is on_cpu, which avoids it being picked
	 * for load-balance and preemption/IRQs are still disabled avoiding
	 * further scheduler activity on it and we're being very careful to
	 * re-start the picking loop.
	 */
	rq_unpin_lock(this_rq, rf);

	// 如果当前队列的平均空闲时间小于迁移花费的时间，或者当前队列没有过载，则不进行迁移
	// 空闲平均时间是从cpu空间时记下一个时间戳，等到唤醒时再计算空新闲时长
	// 这时如果迁移的话划不来，可能会造成新的不平衡
	if (this_rq->avg_idle < sysctl_sched_migration_cost ||
	    !this_rq->rd->overload) {

		rcu_read_lock();
		sd = rcu_dereference_check_sched_domain(this_rq->sd);

		// 更新sd的下一次平衡的时间
		if (sd)
			update_next_balance(sd, &next_balance);
		rcu_read_unlock();

		nohz_newidle_balance(this_rq);

		goto out;
	}

	raw_spin_unlock(&this_rq->lock);

	// todo: update_blocked_averages没看懂，应该是更新平均负载相关的
	update_blocked_averages(this_cpu);
	rcu_read_lock();

	// 遍历所有调度域
	for_each_domain(this_cpu, sd) {
		int continue_balancing = 1; // 是否要继续平衡
		u64 t0, domain_cost; // 域迁移花费的时间

		// 如果当前调度域不允许进行负载均衡，则跳过
		if (!(sd->flags & SD_LOAD_BALANCE))
			continue;

		// 如果当前队列的空间时间小于迁移花费和空闲迁移花费的和，则不再迁移，结束循环
		if (this_rq->avg_idle < curr_cost + sd->max_newidle_lb_cost) {
			update_next_balance(sd, &next_balance);
			break;
		}

		// 如果当前调度域有SD_BALANCE_NEWIDLE这个标志时，则进行真正的迁移
		// NEWIDLE是当前cpu即将进入空闲时的标志，因为这个方法只有这种情景下才会
		// 调用，所以这里在选择调度域时也要选有空闲平衡标志的调度域
		if (sd->flags & SD_BALANCE_NEWIDLE) {
			// 开始时间
			t0 = sched_clock_cpu(this_cpu);

			// 进行负载平衡，pulled_task为拉的进程数量，负载均衡有2种模式：pull和push，
			// 前者是主动从其他cpu往本队列迁移任务，push是当前cpu往其他cpu推任务
			pulled_task = load_balance(this_cpu, this_rq,
						   sd, CPU_NEWLY_IDLE,
						   &continue_balancing);

			// 计算本次迁移的花费
			domain_cost = sched_clock_cpu(this_cpu) - t0;

			// 更新调度域的max_newidle_lb_cost
			if (domain_cost > sd->max_newidle_lb_cost)
				sd->max_newidle_lb_cost = domain_cost;

			// 更新当前迁移花费的总时间
			curr_cost += domain_cost;
		}

		// 更新下次再进行负载均衡的时间
		update_next_balance(sd, &next_balance);

		// 如果已经拉到了任务，或者当前队列已经有了可运行的任务，
		// 则不再进行负载均衡
		if (pulled_task || this_rq->nr_running > 0)
			break;
	}
	rcu_read_unlock();

	raw_spin_lock(&this_rq->lock);

	// 更新当前cpu本次迁移的花费时间
	if (curr_cost > this_rq->max_idle_balance_cost)
		this_rq->max_idle_balance_cost = curr_cost;

out:
	// 如果当前调度组内有了可以运行的任务，即使没有拉到任务也返回1
	if (this_rq->cfs.h_nr_running && !pulled_task)
		pulled_task = 1;

	// 更新当前队列下次负载平衡的时间
	if (time_after(this_rq->next_balance, next_balance))
		this_rq->next_balance = next_balance;

	// 如果有高优先级的任务，需要遍历调度器链选择高优先级的任务来调度
	if (this_rq->nr_running != this_rq->cfs.h_nr_running)
		pulled_task = -1;

	// 如果拉到了任务，则重置空闲时间戳
	if (pulled_task)
		this_rq->idle_stamp = 0;

	rq_repin_lock(this_rq, rf);

	return pulled_task;
}
```


## select_task_rq
```c
kernel/sched/core.c

/**
这个函数主要是在唤醒一个进程时来进行负载均衡

p: 选择cpu的进程
cpu: 进程当前所在cpu
sd_flags: 调度域标志。需要目标cpu有这个标志
wake_flags: 唤醒的标志。是在什么情况下唤醒的

*/
static inline
int select_task_rq(struct task_struct *p, int cpu, int sd_flags, int wake_flags)
{
	// 判断是否持有pi_lock这个锁
	// todo: 什么意思？
	lockdep_assert_held(&p->pi_lock);

	if (p->nr_cpus_allowed > 1)
		// 当进程允许的cpu大于1个时，调用调度器类的select_task_rq，来挑选一个cpu(运行队列)
		cpu = p->sched_class->select_task_rq(p, cpu, sd_flags, wake_flags);
	else
		// cpumask_any是从cpus_allowed中选择第一个cpu，
		// 如果找不到cpu，则会返回cpu个数的最大值
		cpu = cpumask_any(&p->cpus_allowed);

	// 如果上面选的cpu都用不了，则重新在调度域里选一个cpu
	if (unlikely(!is_cpu_allowed(p, cpu)))
		// 如果上面选择的cpu不是进程所允许的cpu，则重新选择一个合适的cpu
		cpu = select_fallback_rq(task_cpu(p), p);

	return cpu;
}
```

```c
kernel/sched/fair.c

static int
select_task_rq_fair(struct task_struct *p, int prev_cpu, int sd_flag, int wake_flags)
{
	struct sched_domain *tmp, *sd = NULL;
	int cpu = smp_processor_id(); // 当前cpu
	int new_cpu = prev_cpu; // 进程上一次运行的cpu
	int want_affine = 0;

	// WF_SYNC表示：这个进程在唤醒之后很快就会再次调度离开，
	// 所以要避免迁移进程，防止在cpu之间来回跳转。
	int sync = (wake_flags & WF_SYNC) && !(current->flags & PF_EXITING);

	// SD_BALANCE_WAKE只在try_to_wake_up的时候使用过，
	// 表示当前是从唤醒进来的
	if (sd_flag & SD_BALANCE_WAKE) {
		// 记录唤醒的进程次数与被唤醒的进程
		record_wakee(p);

		// wake_wide判断唤醒次数是否太多，wake_cap判断当前cpu是否有能力承载进程p

		// 如果唤醒其它进程次数不太多，当前cpu的可用算力能够承载进程p，且当前cpu
		// 在进程p的允许运行cpu位图中，则置亲和性标志
		want_affine = !wake_wide(p) && !wake_cap(p, cpu, prev_cpu)
			      && cpumask_test_cpu(cpu, &p->cpus_allowed);
	}

	rcu_read_lock();

	// 自底向上遍历调度域
	// 这里的自底是从cpu当前所在的最底调度域向上遍历
	for_each_domain(cpu, tmp) {

		// 如果当前调度域不支持负载均衡则直接退出循环
		// todo: 为什么这里就直接退出循环了，其它的两个负载均衡
		// 在当前调度域不支持均衡的时候，会继续在上层均衡
		if (!(tmp->flags & SD_LOAD_BALANCE))
			break;

		// 如果亲和性标志为1,当前调度域支持SD_WAKE_AFFINE，
		// 并且之前运行的cpu，属于当前调度域
		// 这个条件应该大多数情况下都能成立
		if (want_affine && (tmp->flags & SD_WAKE_AFFINE) &&
		    cpumask_test_cpu(prev_cpu, sched_domain_span(tmp))) {
			if (cpu != prev_cpu)
				// 选择一个亲和性cpu
				// 这里应该是大概率选择当前的cpu
				new_cpu = wake_affine(tmp, p, cpu, prev_cpu, sync);

			sd = NULL; /* Prefer wake_affine over balance flags */
			break;
		}

		if (tmp->flags & sd_flag)
			sd = tmp;
		else if (!want_affine)
			break;
	}

	if (unlikely(sd)) {
		// 慢速路径

		// 这个条件就是没有找到有亲和性的cpu,
		// 如果找到了cpu上面的循环会把sd置NULL

		// find_idlest_cpu是从sd这个调度域里自上而下找一个空闲的cpu，
		// 因为前面的循环是自下而上的循环，最坏的结果就是sd为最项层的调度域
		new_cpu = find_idlest_cpu(sd, p, cpu, prev_cpu, sd_flag);
	} else if (sd_flag & SD_BALANCE_WAKE) {
		// 快速路径
		// SD_BALANCE_WAKE表示在唤醒的时候进行负载均衡

		// 走到这里意味着选择的cpu不是当前cpu就是以前的cpu
		// todo: 这里为啥还要通过select_idle_sibling选一把
		new_cpu = select_idle_sibling(p, prev_cpu, new_cpu);

		// 如果有亲各性标志，则记录最近使用的cpu
		if (want_affine)
			current->recent_used_cpu = cpu;
	}
	rcu_read_unlock();

	return new_cpu;
}

static void record_wakee(struct task_struct *p)
{
	// 如果当前时间与上次衰减的时候经过了1秒，
	// 则把唤醒不同进程的次数除以2, 再记录当前衰减的时间戳
	if (time_after(jiffies, current->wakee_flip_decay_ts + HZ)) {
		current->wakee_flips >>= 1;
		current->wakee_flip_decay_ts = jiffies;
	}

	// 记录当前进程上次唤醒的进程，和唤醒不同进程的次数
	if (current->last_wakee != p) {
		current->last_wakee = p;
		current->wakee_flips++;
	}
}

// 判断cpu的算力能否承载进程p
static int wake_cap(struct task_struct *p, int cpu, int prev_cpu)
{
	long min_cap, max_cap;

	// 两个cpu的实际算力
	min_cap = min(capacity_orig_of(prev_cpu), capacity_orig_of(cpu));

	// cpu的最大算力
	max_cap = cpu_rq(cpu)->rd->max_cpu_capacity;

	// 如果当前cpu的最大算力与最小算力之间相差不超过最大算力的1/3，
	// 则不用禁用wake的亲和性
	if (max_cap - min_cap < max_cap >> 3)
		return 0;

	/* Bring task utilization in sync with prev_cpu */
	sync_entity_load_avg(&p->se);

	// 判断最小算力的cpu是否能承载p进程
	return min_cap * 1024 < task_util(p) * capacity_margin;
}

// 判断p和master之间唤醒不同进程的次数是否太多
static int wake_wide(struct task_struct *p)
{
	unsigned int master = current->wakee_flips;
	unsigned int slave = p->wakee_flips;

	// sd_llc_size是最高级调度域共享缓存的cpu数目
	int factor = this_cpu_read(sd_llc_size);

	if (master < slave)
		swap(master, slave);
	if (slave < factor || master < slave * factor)
		return 0;
	return 1;
}

// 这个函数要么选this_cpu， 要么选prev_cpu，或者没找到
static int wake_affine(struct sched_domain *sd, struct task_struct *p,
		       int this_cpu, int prev_cpu, int sync)
{
	// target被初始化成最大cpu数目
	int target = nr_cpumask_bits;

	// WA_IDLE默认为true
	// 先找亲和性cpu
	if (sched_feat(WA_IDLE))
		target = wake_affine_idle(this_cpu, prev_cpu, sync);

	// WA_WEIGHT默认为true
	// wake_affine_weight根据负载情况，判断是否要返回this_cpu，
	// 如果负载不好，则返回最大cpu号，也就是没找到
	if (sched_feat(WA_WEIGHT) && target == nr_cpumask_bits)
		target = wake_affine_weight(sd, p, this_cpu, prev_cpu, sync);

	// 增加亲和性尝试统计次数
	schedstat_inc(p->se.statistics.nr_wakeups_affine_attempts);

	// 如果在上面还是没找到cpu，则返回之前运行的cpu
	if (target == nr_cpumask_bits)
		return prev_cpu;

	// 增加调度域亲和性迁移次数
	schedstat_inc(sd->ttwu_move_affine);

	// 增加进程亲和性迁移统计次数
	schedstat_inc(p->se.statistics.nr_wakeups_affine);
	return target;
}

// 找到亲和性的空闲cpu
static int wake_affine_idle(int this_cpu, int prev_cpu, int sync)
{
	/**
	原文注释：
		如果 this_cpu 空闲，则意味着唤醒来自中断上下文。 
		仅在共享缓存时才允许移动。 否则，中断密集型工作负
		载可能会根据 IO 拓扑或 IRQ 关联设置将所有任务强
		制到一个节点上。 如果 prev_cpu 空闲并且缓存亲和，
		则避免迁移。 不能保证来自中断的缓存热数据比 
		prev_cpu 上的缓存热数据更重要，从 cpufreq 的角
		度来看，最好在一个 CPU 上具有更高的利用率。
	*/
	// 和之前的cpu可以共享缓存，说明这两个cpu肯定在同一个物理cpu上
	if (available_idle_cpu(this_cpu) && cpus_share_cache(this_cpu, prev_cpu))
		// 调度系统会尽量使用之前运行的cpu来运行进程
		return available_idle_cpu(prev_cpu) ? prev_cpu : this_cpu;

	// 如果进程是同步的，并且当前cpu只有一个进程，则返回当前cpu
	if (sync && cpu_rq(this_cpu)->nr_running == 1)
		return this_cpu;

	// 否则返回cpu数目最大值，也就是没找到
	return nr_cpumask_bits;
}

// 如果当前cpu的负载小于之前cpu的负载，则返回当前cpu，否则返回最大cpu号
// todo: 计算过程没仔细看
static int wake_affine_weight(struct sched_domain *sd, struct task_struct *p,
		   int this_cpu, int prev_cpu, int sync)
{
	s64 this_eff_load, prev_eff_load;
	unsigned long task_load;

	this_eff_load = target_load(this_cpu, sd->wake_idx);

	if (sync) {
		// 如果是同步的，当前进程负载如果大于当前cpu的wake负载，
		// 则直接返回当前cpu
		unsigned long current_load = task_h_load(current);

		if (current_load > this_eff_load)
			return this_cpu;

		this_eff_load -= current_load;
	}

	// 当前进程的负载
	task_load = task_h_load(p);

	this_eff_load += task_load;

	// WA_BIAS标志默认为true
	if (sched_feat(WA_BIAS))
		this_eff_load *= 100;
	this_eff_load *= capacity_of(prev_cpu);

	// 之前cpu的负载
	prev_eff_load = source_load(prev_cpu, sd->wake_idx);
	prev_eff_load -= task_load;
	if (sched_feat(WA_BIAS))
		prev_eff_load *= 100 + (sd->imbalance_pct - 100) / 2;
	prev_eff_load *= capacity_of(this_cpu);

	/*
	 * If sync, adjust the weight of prev_eff_load such that if
	 * prev_eff == this_eff that select_idle_sibling() will consider
	 * stacking the wakee on top of the waker if no other CPU is
	 * idle.
	 */
	if (sync)
		prev_eff_load += 1;

	return this_eff_load < prev_eff_load ? this_cpu : nr_cpumask_bits;
}

static inline int find_idlest_cpu(struct sched_domain *sd, struct task_struct *p,
				  int cpu, int prev_cpu, int sd_flag)
{
	int new_cpu = cpu;

	// 如果进程允许的cpu和调度域里的cpu没有交集，则返回之前运行的cpu
	if (!cpumask_intersects(sched_domain_span(sd), &p->cpus_allowed))
		return prev_cpu;

	// 如果不是从fork进来的，则同步进程的平均负载
	if (!(sd_flag & SD_BALANCE_FORK))
		sync_entity_load_avg(&p->se);

	// 自上而下遍历调度域，直到找到最低层的空闲可运行cpu
	while (sd) {
		struct sched_group *group;
		struct sched_domain *tmp;
		int weight;

		// 如果当前调度域没有需要的标志，则遍历子域
		if (!(sd->flags & sd_flag)) {
			sd = sd->child;
			continue;
		}

		// 找最空闲的调度组
		group = find_idlest_group(sd, p, cpu, sd_flag);
		if (!group) {
			sd = sd->child;
			continue;
		}

		// 在最空闲的调度组里找最空闲的cpu
		new_cpu = find_idlest_group_cpu(group, p, cpu);
		if (new_cpu == cpu) {
			// 如果找到的新cpu和现在cpu相同，则继续在子域里找
			sd = sd->child;
			continue;
		}

		// 然后在低一层的调度域里找权重较小的调度域再次找空闲的cpu
		cpu = new_cpu;
		weight = sd->span_weight;
		sd = NULL;
		for_each_domain(cpu, tmp) {
			if (weight <= tmp->span_weight)
				break;
			if (tmp->flags & sd_flag)
				sd = tmp;
		}
	}

	return new_cpu;
}

/*
返回调度域内最空闲的调度组
 */
static struct sched_group *
find_idlest_group(struct sched_domain *sd, struct task_struct *p,
		  int this_cpu, int sd_flag)
{
	struct sched_group *idlest = NULL, *group = sd->groups;
	struct sched_group *most_spare_sg = NULL;
	unsigned long min_runnable_load = ULONG_MAX;
	unsigned long this_runnable_load = ULONG_MAX;
	unsigned long min_avg_load = ULONG_MAX, this_avg_load = ULONG_MAX;
	unsigned long most_spare = 0, this_spare = 0;
	int load_idx = sd->forkexec_idx;
	int imbalance_scale = 100 + (sd->imbalance_pct-100)/2;

	// 不平衡量定义为nice0的负载，即1024
	unsigned long imbalance = scale_load_down(NICE_0_LOAD) *
				(sd->imbalance_pct-100) / 100;

	if (sd_flag & SD_BALANCE_WAKE)
		load_idx = sd->wake_idx;

	do {
		unsigned long load, avg_load, runnable_load;
		unsigned long spare_cap, max_spare_cap;
		int local_group;
		int i;

		// 如果当前组和进程允许的cpu没有交集，则遍历下个组
		if (!cpumask_intersects(sched_group_span(group),
					&p->cpus_allowed))
			continue;

		// 如果这个cpu属于这个组，则记录本地组
		local_group = cpumask_test_cpu(this_cpu,
					       sched_group_span(group));

		// 统计调度组内的运行时负载和平均负载
		avg_load = 0;
		runnable_load = 0;
		max_spare_cap = 0;

		for_each_cpu(i, sched_group_span(group)) {
			/* Bias balancing toward CPUs of our domain */
			if (local_group)
				load = source_load(i, load_idx);
			else
				load = target_load(i, load_idx);

			runnable_load += load;

			avg_load += cfs_rq_load_avg(&cpu_rq(i)->cfs);

			spare_cap = capacity_spare_wake(i, p);

			if (spare_cap > max_spare_cap)
				max_spare_cap = spare_cap;
		}

		// 根据组算力调整负载
		avg_load = (avg_load * SCHED_CAPACITY_SCALE) /
					group->sgc->capacity;
		runnable_load = (runnable_load * SCHED_CAPACITY_SCALE) /
					group->sgc->capacity;

		if (local_group) {
			// 记录本地组的数据，方便在后面做判断
			this_runnable_load = runnable_load;
			this_avg_load = avg_load;
			this_spare = max_spare_cap;
		} else {
			if (min_runnable_load > (runnable_load + imbalance)) {
				// 如果当前组再加上一个nice0进程的负载量还小于最小的运行负载，
				// 则当前组是最小的运行负载
				min_runnable_load = runnable_load;
				min_avg_load = avg_load;
				idlest = group;
			} else if ((runnable_load < (min_runnable_load + imbalance)) &&
				   (100*min_avg_load > imbalance_scale*avg_load)) {
				// 前后2个组的负载非常接近，只更新一下平均负载
				min_avg_load = avg_load;
				idlest = group;
			}

			if (most_spare < max_spare_cap) {
				most_spare = max_spare_cap;
				most_spare_sg = group;
			}
		}
	} while (group = group->next, group != sd->groups);

	/*
	 * The cross-over point between using spare capacity or least load
	 * is too conservative for high utilization tasks on partially
	 * utilized systems if we require spare_capacity > task_util(p),
	 * so we allow for some task stuffing by using
	 * spare_capacity > task_util(p)/2.
	 *
	 * Spare capacity can't be used for fork because the utilization has
	 * not been set yet, we must first select a rq to compute the initial
	 * utilization.
	 */
	if (sd_flag & SD_BALANCE_FORK)
		goto skip_spare;

	if (this_spare > task_util(p) / 2 &&
	    imbalance_scale*this_spare > 100*most_spare)
		return NULL;

	if (most_spare > task_util(p) / 2)
		return most_spare_sg;

skip_spare:
	if (!idlest)
		return NULL;

	/*
	 * When comparing groups across NUMA domains, it's possible for the
	 * local domain to be very lightly loaded relative to the remote
	 * domains but "imbalance" skews the comparison making remote CPUs
	 * look much more favourable. When considering cross-domain, add
	 * imbalance to the runnable load on the remote node and consider
	 * staying local.
	 */
	if ((sd->flags & SD_NUMA) &&
	    min_runnable_load + imbalance >= this_runnable_load)
		return NULL;

	if (min_runnable_load > (this_runnable_load + imbalance))
		return NULL;

	if ((this_runnable_load < (min_runnable_load + imbalance)) &&
	     (100*this_avg_load < imbalance_scale*min_avg_load))
		return NULL;

	return idlest;
}

/**
选择兄弟空闲cpu
p: 要运行的进程
prev: 之前运行的cpu
target: 目标运行的cpu
*/
static int select_idle_sibling(struct task_struct *p, int prev, int target)
{
	struct sched_domain *sd;
	int i, recent_used_cpu;

	// 如果目标cpu是空闲的，则直接返回
	if (available_idle_cpu(target))
		return target;

	/*
	 * If the previous CPU is cache affine and idle, don't be stupid:
	 */
	// 如果目标cpu不空闲，但是prev空闲，且prev和target之间共享缓存，
	// 则返回prev cpu
	if (prev != target && cpus_share_cache(prev, target) && available_idle_cpu(prev))
		return prev;

	/* Check a recently used CPU as a potential idle candidate: */

	// 如果prev和target都不符合条件，则判断最近使用的cpu是否空闲，
	// 并且符合其它条件，符合的话返回最近使用的cpu
	recent_used_cpu = p->recent_used_cpu;
	if (recent_used_cpu != prev &&
	    recent_used_cpu != target &&
	    cpus_share_cache(recent_used_cpu, target) &&
	    available_idle_cpu(recent_used_cpu) &&
	    cpumask_test_cpu(p->recent_used_cpu, &p->cpus_allowed)) {
		/*
		 * Replace recent_used_cpu with prev as it is a potential
		 * candidate for the next wake:
		 */
		p->recent_used_cpu = prev;
		return recent_used_cpu;
	}

	// 走到这里说明上面三个cpu都不符合条件

	// sd_llc是target cpu所有的调度域的最高级缓存共享调度域
	sd = rcu_dereference(per_cpu(sd_llc, target));
	if (!sd)
		return target;

	// 选择一个空闲的核，如果没有打开SMT配置选项，这个函数直接返回-1
	i = select_idle_core(p, sd, target);
	if ((unsigned)i < nr_cpumask_bits)
		return i;

	// 如果没有空闲的核，选择一个空闲的cpu
	i = select_idle_cpu(p, sd, target);
	if ((unsigned)i < nr_cpumask_bits)
		return i;

	// 如果没有空闲的cpu，则选择一个target上的空闲的超线程cpu（逻辑cpu）
	// select_idle_smt只在CONFIG_SMT打开时才有效，否则返回-1
	i = select_idle_smt(p, sd, target);
	if ((unsigned)i < nr_cpumask_bits)
		return i;

	// 走到这里，意味着全都不符合，那就直接返回target
	return target;
}

/*
原文注释：
	扫描整个 LLC 域以查找空闲内核； 如果系统中没有空闲内核，则动态关闭； 
	通过 sd_llc->shared->has_idle_cores 跟踪并通过上面的 update_idle_core() 启用。
 */
static int select_idle_core(struct task_struct *p, struct sched_domain *sd, int target)
{
	// cpu集合
	struct cpumask *cpus = this_cpu_cpumask_var_ptr(select_idle_mask);
	int core, cpu;

	// 如果sched_smt_present为空，则返回-1
	if (!static_branch_likely(&sched_smt_present))
		return -1;

	// 如果当前cpu所在的共享域没有空闲核，则返回-1
	if (!test_idle_cores(target, false))
		return -1;

	// cpus 等于 调度域范围内的cpu和进程允许cpu的并集
	// todo: 函数的第一行对cpus的赋值有什么意义
	cpumask_and(cpus, sched_domain_span(sd), &p->cpus_allowed);

	// 从target开始遍历cpus里的所有cpu
	for_each_cpu_wrap(core, cpus, target) {
		bool idle = true;

		// 遍历核内的所有超线程cpu
		for_each_cpu(cpu, cpu_smt_mask(core)) {

			// 从cpus集合里移除这个cpu
			cpumask_clear_cpu(cpu, cpus);

			// 如果当前cpu不空闲，则设置不空闲标志
			if (!available_idle_cpu(cpu))
				idle = false;
		}

		// 如果这个核内有空闲cpu，则返回这个核
		if (idle)
			return core;
	}

	// 走到这里表示在target所有的共享调度域内没找到空闲的核,
	// 设置共享调度域的has_idle_cores为0，这个值就是前面test_idle_cores判断的值
	set_idle_cores(target, 0);

	return -1;
}

/*
原文注释：
	扫描LLC域中的空闲CPU；通过比较平均扫描成本（在sd->avg_scan_cost中跟踪）
	与此rq的平均空闲时间（如rq->avg_idle中所示），可以动态调整这一点。
 */
static int select_idle_cpu(struct task_struct *p, struct sched_domain *sd, int target)
{
	struct sched_domain *this_sd;
	u64 avg_cost, avg_idle;
	u64 time, cost;
	s64 delta;
	int cpu, nr = INT_MAX;

	// 获取当前cpu的共享缓存调度域
	this_sd = rcu_dereference(*this_cpu_ptr(&sd_llc));
	if (!this_sd)
		return -1;

	/*
	 原文注释：
	 	由于方差较大，我们需要一个较大的模糊因子；在这里，黑客特别敏感。
	 todo: 不知所云
	 */
	// 将平均空闲时间缩小512倍
	// todo: why?
	avg_idle = this_rq()->avg_idle / 512;

	// 平均扫描花费+1
	avg_cost = this_sd->avg_scan_cost + 1;

	// SIS_AVG_CPU默认为false
	if (sched_feat(SIS_AVG_CPU) && avg_idle < avg_cost)
		return -1;

	// SIS_PROP默认为true
	if (sched_feat(SIS_PROP)) {
		// span_weight好像是域里的总权重
		// todo: span_avg是啥意思
		u64 span_avg = sd->span_weight * avg_idle;

		// 下面计算出来的nr至少为4
		if (span_avg > 4*avg_cost)
			nr = div_u64(span_avg, avg_cost);
		else
			nr = 4;
	}

	time = local_clock();

	// 遍历调度域里的cpu
	for_each_cpu_wrap(cpu, sched_domain_span(sd), target) {
		// nr为遍历的次数，上面计算出来的至少是4
		// todo: 为什么要限制nr次数
		if (!--nr)
			return -1;
		// 进程p不允许在此cpu上运行
		if (!cpumask_test_cpu(cpu, &p->cpus_allowed))
			continue;
		// 如果这个cpu空闲，则返回
		if (available_idle_cpu(cpu))
			break;
	}

	// 计算遍历域里cpu的花费
	time = local_clock() - time;
	cost = this_sd->avg_scan_cost;
	delta = (s64)(time - cost) / 8;
	this_sd->avg_scan_cost += delta;

	return cpu;
}

static int select_idle_smt(struct task_struct *p, struct sched_domain *sd, int target)
{
	int cpu;

	// todo: sched_smt_present不知道是啥意思
	// 既然是likely那这个条件应该不常走
	if (!static_branch_likely(&sched_smt_present))
		return -1;

	// 遍历target里的cpu
	// 如果target是个核，应该会有多个cpu，否则就只有一个cpu
	for_each_cpu(cpu, cpu_smt_mask(target)) {
		// 如果进程不允许在这个cpu上运行，则继续
		if (!cpumask_test_cpu(cpu, &p->cpus_allowed))
			continue;
		// 如果cpu空闲，则返回这个cpu
		if (available_idle_cpu(cpu))
			return cpu;
	}

	return -1;
}

/**
回滚进程的运行队列

因为在负载均衡时没有选择到合适的cpu，所以这里还要回到之前的运行队列
cpu: 进程之前运行的cpu
p: 要唤醒的进程
*/
static int select_fallback_rq(int cpu, struct task_struct *p)
{
	// numa节点id
	int nid = cpu_to_node(cpu);
	const struct cpumask *nodemask = NULL;
	enum { cpuset, possible, fail } state = cpuset;
	int dest_cpu;

	/*
	原文注释：

	 如果 CPU 所在的节点已离线，则 cpu_to_node() 将返回 -1。 
	 节点上没有CPU，我们应该选择另一个节点上的CPU。
	 */

	if (nid != -1) {
		// 这个分支表示cpu所在的numa节点在线

		// numa域内的所有cpu节点
		nodemask = cpumask_of_node(nid);

		// 在numa节点内找一个激活的并且进程p可以在上面运行的cpu，
		// 然后 返回该cpu
		for_each_cpu(dest_cpu, nodemask) {
			if (!cpu_active(dest_cpu))
				continue;
			if (cpumask_test_cpu(dest_cpu, &p->cpus_allowed))
				return dest_cpu;
		}
	}

	// 走到这里就是所在的numa节点已离线。
	// 这个分支应该不经常走吧
	for (;;) {
		/* Any allowed, online CPU? */
		for_each_cpu(dest_cpu, &p->cpus_allowed) {
			// 判断目标cpu能不能运行进程p，可以运行的话就直接返回
			// 目标cpu
			if (!is_cpu_allowed(p, dest_cpu))
				continue;

			goto out;
		}

		/* No more Mr. Nice Guy. */
		/* 没有好人了 */
		// 走到这里就表示一个能用的cpu也没有
		switch (state) {
		case cpuset:
			if (IS_ENABLED(CONFIG_CPUSETS)) {
				// 如果配置了CONFIG_CPUSETS，则强制设置
				// 进程允许运行的cpu，因为进程没有一个能用的cpu
				cpuset_cpus_allowed_fallback(p);
				state = possible;
				break;
			}
			/* Fall-through */
		case possible:
			// 如果没有开启CONFIG_CPUSETS，则将进程的cpumask
			// 设置为cpu_possible_mask
			do_set_cpus_allowed(p, cpu_possible_mask);
			state = fail;
			break;

		case fail:
			BUG();
			break;
		}
	}

out:
	if (state != cpuset) {
		/*
		原文注释：
			不要告诉他们关于移动退出任务或内核线程
			（都是 mm NULL），因为它们永远不会离开内核。

			打印一条日志
		 */
		if (p->mm && printk_ratelimit()) {
			printk_deferred("process %d (%s) no longer affine to cpu%d\n",
					task_pid_nr(p), p->comm, cpu);
		}
	}

	return dest_cpu;
}
```