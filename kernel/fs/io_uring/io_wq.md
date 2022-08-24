# io-wq
io-wq是io_uring用来做异步任务。

## 创建 io-wq
```c
struct io_wq *io_wq_create(unsigned bounded, struct io_wq_data *data)
{
	int ret = -ENOMEM, node;
	struct io_wq *wq;

	if (WARN_ON_ONCE(!data->free_work || !data->do_work))
		return ERR_PTR(-EINVAL);
	if (WARN_ON_ONCE(!bounded))
		return ERR_PTR(-EINVAL);

	wq = kzalloc(sizeof(*wq), GFP_KERNEL);
	if (!wq)
		return ERR_PTR(-ENOMEM);

	// wqe是每个node上申请一个
	wq->wqes = kcalloc(nr_node_ids, sizeof(struct io_wqe *), GFP_KERNEL);
	if (!wq->wqes)
		goto err_wq;

	// todo: 后面看。好像会设置运行任务task的亲和性，应该是附上迁移
	ret = cpuhp_state_add_instance_nocalls(io_wq_online, &wq->cpuhp_node);
	if (ret)
		goto err_wqes;

	// 释放work的函数
	wq->free_work = data->free_work;

	// 提交work的函数
	wq->do_work = data->do_work;

	wq->user = data->user;

	ret = -ENOMEM;
	// 在对应的node上分配wqe
	for_each_node(node) {
		struct io_wqe *wqe;
		int alloc_node = node;

		// node不在线
		if (!node_online(alloc_node))
			// todo: 后面看，这种情况一般很少
			alloc_node = NUMA_NO_NODE;
		// 在对应的node上分配wqe内存
		wqe = kzalloc_node(sizeof(struct io_wqe), GFP_KERNEL, alloc_node);
		if (!wqe)
			goto err;
		// 设置到对应的wqes里
		wq->wqes[node] = wqe;
		wqe->node = alloc_node;

		// 下面是统计相关
		// 最大worker数量
		wqe->acct[IO_WQ_ACCT_BOUND].max_workers = bounded;
		// 当前运行进程数量
		atomic_set(&wqe->acct[IO_WQ_ACCT_BOUND].nr_running, 0);
		if (wq->user) {
			// todo: IO_WQ_ACCT_UNBOUND?
			wqe->acct[IO_WQ_ACCT_UNBOUND].max_workers =
					task_rlimit(current, RLIMIT_NPROC);
		}
		atomic_set(&wqe->acct[IO_WQ_ACCT_UNBOUND].nr_running, 0);
		// wqe对wq的引用
		wqe->wq = wq;
		raw_spin_lock_init(&wqe->lock);

		// 这个是工作列表，异步任务就挂在这个列表上
		INIT_WQ_LIST(&wqe->work_list);
		// todo:
		INIT_HLIST_NULLS_HEAD(&wqe->free_list, 0);
		// todo:
		INIT_LIST_HEAD(&wqe->all_list);
	}

	// 初始化完成量
	init_completion(&wq->done);

	// 创建wq管理器线程
	wq->manager = kthread_create(io_wq_manager, wq, "io_wq_manager");

	if (!IS_ERR(wq->manager)) { // 创建成功

		// 唤醒io_wq_manager线程
		wake_up_process(wq->manager);
		// 等待线程准备完成
		wait_for_completion(&wq->done);

		// 有错误
		if (test_bit(IO_WQ_BIT_ERROR, &wq->state)) {
			ret = -ENOMEM;
			goto err;
		}
		refcount_set(&wq->use_refs, 1);
		// 重新初始化完成量
		reinit_completion(&wq->done);
		return wq;
	}

	// 走到这儿，说明创建io_wq_manager失败
	ret = PTR_ERR(wq->manager);
	// todo: 创建失败后，为啥要调用完成 ？
	complete(&wq->done);
err:
	cpuhp_state_remove_instance_nocalls(io_wq_online, &wq->cpuhp_node);
	for_each_node(node)
		kfree(wq->wqes[node]);
err_wqes:
	kfree(wq->wqes);
err_wq:
	kfree(wq);
	return ERR_PTR(ret);
}
```
io_wq_create的主流程：
1. 创建io_wq实例
2. 创建wq->wqes，这是数组，大小是numa节点的数量
3. 给每个node分配wqe节点
4. 创建 io_wq_manager 线程，这个线程负责创建每个wq_worker线程
5. 唤醒 io_wq_manager 线程，并等待wq->done完成

## io_wq_manager
```c
static int io_wq_manager(void *data)
{
	struct io_wq *wq = data;
	int node;

	refcount_set(&wq->refs, 1);

	// 在每个node上创建worker
	for_each_node(node) {
		// node不在线
		if (!node_online(node))
			continue;
		// 创建worker
		if (create_io_worker(wq, wq->wqes[node], IO_WQ_ACCT_BOUND))
			continue;

		// 走到这儿说明创建失败，直接退出
		set_bit(IO_WQ_BIT_ERROR, &wq->state);
		set_bit(IO_WQ_BIT_EXIT, &wq->state);
		goto out;
	}

	// 走到这儿，说明在每个node上创建成功
	// 完成，这里对应io_wq_create里的完成量
	complete(&wq->done);

	// 下面这个while循环，就是定时遍历wqe的状态，
	// 根据worker上任务的数量，看是否要为其分配 worker
	while (!kthread_should_stop()) {
		// 如果进程有work则先运行进程的work
		if (current->task_works)
			task_work_run();

		for_each_node(node) {
			// 每个node对应的wqe
			struct io_wqe *wqe = wq->wqes[node];
			bool fork_worker[2] = { false, false };

			// node不在线
			if (!node_online(node))
				continue;

			raw_spin_lock_irq(&wqe->lock);
			// 是否需要创建workder
			if (io_wqe_need_worker(wqe, IO_WQ_ACCT_BOUND))
				fork_worker[IO_WQ_ACCT_BOUND] = true;
			if (io_wqe_need_worker(wqe, IO_WQ_ACCT_UNBOUND))
				fork_worker[IO_WQ_ACCT_UNBOUND] = true;
			raw_spin_unlock_irq(&wqe->lock);
			// 如果需要创建，则创建对应的worker
			if (fork_worker[IO_WQ_ACCT_BOUND])
				create_io_worker(wq, wqe, IO_WQ_ACCT_BOUND);
			if (fork_worker[IO_WQ_ACCT_UNBOUND])
				create_io_worker(wq, wqe, IO_WQ_ACCT_UNBOUND);
		}
		// 设置可中断状态，并延迟一秒
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(HZ);
	}

	// 再运行一下进程的work
	if (current->task_works)
		task_work_run();

out:
	if (refcount_dec_and_test(&wq->refs)) {
		// 如果是最后一个走到这儿，还要再调一下完成量，因为有可能是因为出错走到这儿
		complete(&wq->done);
		return 0;
	}

	if (test_bit(IO_WQ_BIT_ERROR, &wq->state)) {
		rcu_read_lock();
		// 如果有错误，就唤醒所有的worker， why?
		for_each_node(node)
			io_wq_for_each_worker(wq->wqes[node], io_wq_worker_wake, NULL);
		rcu_read_unlock();
	}
	return 0;
}

static inline bool io_wqe_need_worker(struct io_wqe *wqe, int index)
	__must_hold(wqe->lock)
{
	struct io_wqe_acct *acct = &wqe->acct[index];

	// free_list里是空闲的worker
	// io_wqe_run_queue是判断wqe里有没有work
	// 如果有空闲的worker，或者没有任务，就不需要再创建worker
	if (!hlist_nulls_empty(&wqe->free_list) || !io_wqe_run_queue(wqe))
		return false;
	// 走到这儿需要创建worker，但是不能超过最大值
	return acct->nr_workers < acct->max_workers;
}
```
io_wq_manager的主要流程:
1. 先在每个node上创建一个io_worker,然后调用wq_done的完成接口,因为io_wq_create还在这个完成量上等待
2. 然后进入一个死循环,每隔一秒,判断一下每个node上的wqe的任务情况,根据是否需要创建io_worker
3. 其它一些出错处理和manager线程退出时的一些操作


## 创建一个worker
```c
static bool create_io_worker(struct io_wq *wq, struct io_wqe *wqe, int index)
{
	// 统计对象
	struct io_wqe_acct *acct = &wqe->acct[index];
	struct io_worker *worker;

	// 在对应的node上创建worker内存
	worker = kzalloc_node(sizeof(*worker), GFP_KERNEL, wqe->node);
	if (!worker)
		return false;

	// 设置引用为1
	refcount_set(&worker->ref, 1);
	worker->nulls_node.pprev = NULL;
	worker->wqe = wqe;
	spin_lock_init(&worker->lock);

	// 创建worker对应的内核线程
	worker->task = kthread_create_on_node(io_wqe_worker, worker, wqe->node,
				"io_wqe_worker-%d/%d", index, wqe->node);
	if (IS_ERR(worker->task)) {
		kfree(worker);
		return false;
	}

	// bind_mask表示只能在这个node对应的cpu上运行
	kthread_bind_mask(worker->task, cpumask_of_node(wqe->node));

	raw_spin_lock_irq(&wqe->lock);
	// 把worker挂在free_list上
	hlist_nulls_add_head_rcu(&worker->nulls_node, &wqe->free_list);
	// 把worker加到all_list表尾
	list_add_tail_rcu(&worker->all_list, &wqe->all_list);

	// 设置 worker现在空闲
	worker->flags |= IO_WORKER_F_FREE;
	if (index == IO_WQ_ACCT_BOUND)
		worker->flags |= IO_WORKER_F_BOUND;
	// 如果是node上的第1个线程,则设置固定标志,因为非固定线程在没有任务时会退出
	if (!acct->nr_workers && (worker->flags & IO_WORKER_F_BOUND))
		worker->flags |= IO_WORKER_F_FIXED;
	// 递增worker数量
	acct->nr_workers++;
	raw_spin_unlock_irq(&wqe->lock);

	// 如果是无界限的则增加用户的进程数量？
	if (index == IO_WQ_ACCT_UNBOUND)
		atomic_inc(&wq->user->processes);

	// 增加wq引用
	refcount_inc(&wq->refs);
	// 唤醒worker线程
	wake_up_process(worker->task);
	return true;
}
```
创建线程比较简单,创建一个内核线程后,把它分别挂在wq的对应列表上,然后再唤醒这个内核线程,就完事了!

## io_wqe_worker
io_wqe_worker是异步任务的主要执行者.
```c
static int io_wqe_worker(void *data)
{
	struct io_worker *worker = data;
	struct io_wqe *wqe = worker->wqe;
	struct io_wq *wq = wqe->wq;

	// 设置woker运行时的一些标志,及上下文
	io_worker_start(wqe, worker);

	while (!test_bit(IO_WQ_BIT_EXIT, &wq->state)) { // 是否要退出
		// 先设置可中断状态,下面可能要睡眠
		set_current_state(TASK_INTERRUPTIBLE);
loop:
		raw_spin_lock_irq(&wqe->lock);

		// 如果有运行的任务
		if (io_wqe_run_queue(wqe)) {
			// 把当前进程设置成running
			__set_current_state(TASK_RUNNING);
			// 处理任务
			io_worker_handle_work(worker);

			// 处理完一个任务后继续循环
			goto loop;
		}

		// 走到这儿表示没有任务要处理

		// 没有任务时就把当前worker加到空闲列表，返回true表示需要释放锁
		if (__io_worker_idle(wqe, worker)) {
			__release(&wqe->lock);
			goto loop;
		}
		raw_spin_unlock_irq(&wqe->lock);

		// 当前进程有信号要处理
		if (signal_pending(current))
			// 处理信号
			flush_signals(current);
		// 睡眠， WORKER_IDLE_TIMEOUT是5秒
		if (schedule_timeout(WORKER_IDLE_TIMEOUT))
			// 走到这儿说明是在睡眠期间被唤醒,
			// 睡眠的时候有被唤醒,说明有任务需要处理,继续循环
			continue;

		// 走到这儿说明是休眠到期唤醒的
		// 如果是退出，或者当前worker不是固定，则退出.
		// 每个node上只有第1个线程是固定,其它都是根据任务的多少动态创建的,
		// 所以走到这儿既然没有任务,那这个非固定线程也就没用了,直接退出
		if (test_bit(IO_WQ_BIT_EXIT, &wq->state) ||
		    !(worker->flags & IO_WORKER_F_FIXED))
			break;
	}

	if (test_bit(IO_WQ_BIT_EXIT, &wq->state)) {
		// 如果是因为设置了退出退出标志,有可能队列中还有工作没做完,
		// 所以把余下的任务做完
		raw_spin_lock_irq(&wqe->lock);
		if (!wq_list_empty(&wqe->work_list))
			io_worker_handle_work(worker);
		else
			raw_spin_unlock_irq(&wqe->lock);
	}

	// woker退出,对应着前面的start
	io_worker_exit(worker);
	return 0;
}

static void io_worker_start(struct io_wqe *wqe, struct io_worker *worker)
{
	// 允许的信号？
	allow_kernel_signal(SIGINT);

	// 设置worker标志
	current->flags |= PF_IO_WORKER;

	// 设置运行标志
	worker->flags |= (IO_WORKER_F_UP | IO_WORKER_F_RUNNING);
	// 设置复原时文件系统相关变量为当前进程的
	worker->restore_files = current->files;
	worker->restore_nsproxy = current->nsproxy;
	worker->restore_fs = current->fs;

	// 增加相应的acct->nr_running数量，这个是运行数量
	io_wqe_inc_running(wqe, worker);
}
```
woker的核心流程是处理队列上的任务.没有任务了就去睡眠.如果是临时woker线程的话,没有任务了这个线程就会退出.

## 处理任务
```c
static void io_worker_handle_work(struct io_worker *worker)
	__releases(wqe->lock)
{
	struct io_wqe *wqe = worker->wqe;
	struct io_wq *wq = wqe->wq;

	do {
		struct io_wq_work *work;
get_next:
		// 取出一个任务
		work = io_get_next_work(wqe);
		if (work)
			// 这个函数去除当前空闲标志,也就是设置忙标志,
			// 主要是从空闲列表里移出
			__io_worker_busy(wqe, worker, work);
		else if (!wq_list_empty(&wqe->work_list))
			// 如果获取work为空,但是work_list不为空,那肯定是在哈希中
			// todo: 这个条件没看懂
			wqe->flags |= IO_WQE_FLAG_STALLED;

		raw_spin_unlock_irq(&wqe->lock);
		if (!work)
			break;
		// 这个主要设置worker->cur_work
		io_assign_current_work(worker, work);

		/* handle a whole dependent link */
		do {
			struct io_wq_work *old_work, *next_hashed, *linked;
			unsigned int hash = io_get_work_hash(work);

			// 下一个任务, work是一个链表
			next_hashed = wq_next_work(work);

			// work的运行上下文与当前worker的不一致的时候，要设置成work的上下文
			io_impersonate_work(worker, work);

			// 当前work已经取消?
			if (test_bit(IO_WQ_BIT_CANCEL, &wq->state))
				work->flags |= IO_WQ_WORK_CANCEL;

			old_work = work;
			// 调用相应work的处理函数
			// todo: 返回的linked是什么？
			linked = wq->do_work(work);

			work = next_hashed;

			// 如果下一个work是空，但是link不为空，且不是哈希表头，设置work为link
			if (!work && linked && !io_wq_is_hashed(linked)) {
				work = linked;
				linked = NULL;
			}
			// 设置下一个work
			io_assign_current_work(worker, work);

			// 释放老的work,也就是处理完的work
			wq->free_work(old_work);

			// 如果link没有处理，说明当前work相关的下一个work不为空，
			// 先把link入队
			if (linked)
				io_wqe_enqueue(wqe, linked);

			// 后面再看
			if (hash != -1U && !next_hashed) {
				raw_spin_lock_irq(&wqe->lock);
				wqe->hash_map &= ~BIT_ULL(hash);
				wqe->flags &= ~IO_WQE_FLAG_STALLED;
				/* skip unnecessary unlock-lock wqe->lock */
				if (!work)
					goto get_next;
				raw_spin_unlock_irq(&wqe->lock);
			}
		} while (work);

		raw_spin_lock_irq(&wqe->lock);
	} while (1);
}

static struct io_wq_work *io_get_next_work(struct io_wqe *wqe)
	__must_hold(wqe->lock)
{
	struct io_wq_work_node *node, *prev;
	struct io_wq_work *work, *tail;
	unsigned int hash;

	// 遍历wqe的work_list
	wq_list_for_each(node, prev, &wqe->work_list) {
		work = container_of(node, struct io_wq_work, list);

		// io_wq_is_hashed判断有没有IO_WQ_WORK_HASHED标志,
		// 这个标志代表是哈希表头
		if (!io_wq_is_hashed(work)) {
			// 不是哈希表头的直接返回
			wq_list_del(&wqe->work_list, node, prev);
			return work;
		}

		// 说明这个work是哈希表头，
		// io_get_work_hash 获取它的哈希值
		hash = io_get_work_hash(work);
		// BIT(nr) = 1 << nr
		// todo: hash_map是什么
		if (!(wqe->hash_map & BIT(hash))) {
			// 把hash对应的那一位设置后,就把hash值对应的
			// 整个哈希表都放到work_list上
			wqe->hash_map |= BIT(hash);
			// 取出这个哈希表
			tail = wqe->hash_tail[hash];
			wqe->hash_tail[hash] = NULL;
			// 把整个哈希表加到work_list上
			wq_list_cut(&wqe->work_list, &tail->list, prev);
			return work;
		}
	}

	return NULL;
}

static void __io_worker_busy(struct io_wqe *wqe, struct io_worker *worker,
			     struct io_wq_work *work)
	__must_hold(wqe->lock)
{
	bool worker_bound, work_bound;

	// 去除空闲标志,并从空闲列表里移出
	if (worker->flags & IO_WORKER_F_FREE) {
		worker->flags &= ~IO_WORKER_F_FREE;
		hlist_nulls_del_init_rcu(&worker->nulls_node);
	}

	// 计算bound/unbound计数器
	worker_bound = (worker->flags & IO_WORKER_F_BOUND) != 0;
	work_bound = (work->flags & IO_WQ_WORK_UNBOUND) == 0;
	if (worker_bound != work_bound) {
		io_wqe_dec_running(wqe, worker);
		if (work_bound) {
			worker->flags |= IO_WORKER_F_BOUND;
			wqe->acct[IO_WQ_ACCT_UNBOUND].nr_workers--;
			wqe->acct[IO_WQ_ACCT_BOUND].nr_workers++;
			atomic_dec(&wqe->wq->user->processes);
		} else {
			worker->flags &= ~IO_WORKER_F_BOUND;
			wqe->acct[IO_WQ_ACCT_UNBOUND].nr_workers++;
			wqe->acct[IO_WQ_ACCT_BOUND].nr_workers--;
			atomic_inc(&wqe->wq->user->processes);
		}
		io_wqe_inc_running(wqe, worker);
	 }
}

static void io_assign_current_work(struct io_worker *worker,
				   struct io_wq_work *work)
{
	if (work) {
		// 如果有信号先处理信号
		if (signal_pending(current))
			flush_signals(current);
		// 让出cpu
		cond_resched();
	}

#ifdef CONFIG_AUDIT
	// 统计相关
	current->loginuid = KUIDT_INIT(AUDIT_UID_UNSET);
	current->sessionid = AUDIT_SID_UNSET;
#endif

	spin_lock_irq(&worker->lock);
	// 设置当前worker的work
	worker->cur_work = work;
	spin_unlock_irq(&worker->lock);
}

static void io_impersonate_work(struct io_worker *worker,
				struct io_wq_work *work)
{
	// 如果work的files与当前worker不同，需要设置？
	if ((work->flags & IO_WQ_WORK_FILES) &&
	    current->files != work->identity->files) {
		task_lock(current);
		current->files = work->identity->files;
		current->nsproxy = work->identity->nsproxy;
		task_unlock(current);
		if (!work->identity->files) {
			/* failed grabbing files, ensure work gets cancelled */
			work->flags |= IO_WQ_WORK_CANCEL;
		}
	}
	// 同上，设置文件系统
	if ((work->flags & IO_WQ_WORK_FS) && current->fs != work->identity->fs)
		current->fs = work->identity->fs;
	// 同上，设置内存
	if ((work->flags & IO_WQ_WORK_MM) && work->identity->mm != worker->mm)
		io_wq_switch_mm(worker, work);
	// cred
	if ((work->flags & IO_WQ_WORK_CREDS) &&
	    worker->cur_creds != work->identity->creds)
		io_wq_switch_creds(worker, work);
	// 信号集
	if (work->flags & IO_WQ_WORK_FSIZE)
		current->signal->rlim[RLIMIT_FSIZE].rlim_cur = work->identity->fsize;
	else if (current->signal->rlim[RLIMIT_FSIZE].rlim_cur != RLIM_INFINITY)
		current->signal->rlim[RLIMIT_FSIZE].rlim_cur = RLIM_INFINITY;
	// blk控制组
	io_wq_switch_blkcg(worker, work);
#ifdef CONFIG_AUDIT
	// 审计的会话相关id
	current->loginuid = work->identity->loginuid;
	current->sessionid = work->identity->sessionid;
#endif
}
static bool __io_worker_idle(struct io_wqe *wqe, struct io_worker *worker)
	__must_hold(wqe->lock)
{
	// 设置空闲标志,加入空闲列表
	if (!(worker->flags & IO_WORKER_F_FREE)) {
		worker->flags |= IO_WORKER_F_FREE;
		hlist_nulls_add_head_rcu(&worker->nulls_node, &wqe->free_list);
	}

	return __io_worker_unuse(wqe, worker);
}

static void io_worker_exit(struct io_worker *worker)
{
	struct io_wqe *wqe = worker->wqe;
	struct io_wqe_acct *acct = io_wqe_get_acct(wqe, worker);

	set_current_state(TASK_INTERRUPTIBLE);

	// 返回0说明还有别人在引用,所以调度出去
	if (!refcount_dec_and_test(&worker->ref))
		schedule();

	// 走到这儿说明没有人引用了

	// 先把状态改回来
	__set_current_state(TASK_RUNNING);

	// 关中断
	preempt_disable();

	// 删除worker标记
	current->flags &= ~PF_IO_WORKER;

	// 减少running计数
	if (worker->flags & IO_WORKER_F_RUNNING)
		atomic_dec(&acct->nr_running);

	// 减少用户的processes计数
	if (!(worker->flags & IO_WORKER_F_BOUND))
		atomic_dec(&wqe->wq->user->processes);
	worker->flags = 0;
	preempt_enable();

	raw_spin_lock_irq(&wqe->lock);
	// 删除worker空闲列表
	hlist_nulls_del_rcu(&worker->nulls_node);
	// 删除all_list
	list_del_rcu(&worker->all_list);

	// 清除所占用的资源
	if (__io_worker_unuse(wqe, worker)) {
		__release(&wqe->lock);
		raw_spin_lock_irq(&wqe->lock);
	}

	acct->nr_workers--;
	raw_spin_unlock_irq(&wqe->lock);

	// 释放worker
	kfree_rcu(worker, rcu);
	// 没有人再使用它了,调用完成量
	if (refcount_dec_and_test(&wqe->wq->refs))
		complete(&wqe->wq->done);
}

static bool __io_worker_unuse(struct io_wqe *wqe, struct io_worker *worker)
{
	bool dropped_lock = false;

	if (worker->saved_creds) {
		revert_creds(worker->saved_creds);
		worker->cur_creds = worker->saved_creds = NULL;
	}

	if (current->files != worker->restore_files) {
		__acquire(&wqe->lock);
		raw_spin_unlock_irq(&wqe->lock);
		dropped_lock = true;

		task_lock(current);
		current->files = worker->restore_files;
		current->nsproxy = worker->restore_nsproxy;
		task_unlock(current);
	}

	if (current->fs != worker->restore_fs)
		current->fs = worker->restore_fs;

	/*
	 * If we have an active mm, we need to drop the wq lock before unusing
	 * it. If we do, return true and let the caller retry the idle loop.
	 */
	if (worker->mm) {
		if (!dropped_lock) {
			__acquire(&wqe->lock);
			raw_spin_unlock_irq(&wqe->lock);
			dropped_lock = true;
		}
		__set_current_state(TASK_RUNNING);
		kthread_unuse_mm(worker->mm);
		mmput(worker->mm);
		worker->mm = NULL;
	}

#ifdef CONFIG_BLK_CGROUP
	if (worker->blkcg_css) {
		kthread_associate_blkcg(NULL);
		worker->blkcg_css = NULL;
	}
#endif
	if (current->signal->rlim[RLIMIT_FSIZE].rlim_cur != RLIM_INFINITY)
		current->signal->rlim[RLIMIT_FSIZE].rlim_cur = RLIM_INFINITY;
	return dropped_lock;
}
```