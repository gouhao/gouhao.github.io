## sqpoll thread
源码基于5.10

```c
static int io_sq_thread(void *data)
{
	struct cgroup_subsys_state *cur_css = NULL;
	const struct cred *old_cred = NULL;
	struct io_sq_data *sqd = data;
	struct io_ring_ctx *ctx;
	unsigned long start_jiffies;

	// 启动时间
	start_jiffies = jiffies;
	while (!kthread_should_stop()) {
		enum sq_ret ret = 0;
		bool cap_entries;

		// 需要暂停
		if (kthread_should_park()) {
			// 暂停自己
			kthread_parkme();
			// 在unpark之后，有可能kthread需要停止
			if (kthread_should_stop())
				break;
		}

		// 新创建的sq-thread会挂到ctx_new_list列表
		if (unlikely(!list_empty(&sqd->ctx_new_list)))
			// 这个函数里会初始化sqo_wait_entry和它的唤醒函数
			io_sqd_init_new(sqd);

		// list_is_singular是判断一个列表是否只有一个元素
		// 这里cap_entries表示，是否有多个ctx
		cap_entries = !list_is_singular(&sqd->ctx_list);

		// 经过上面的io_sqd_init_new，把io_uring_ctx从ctx_new_list列表移到了ctx_list
		list_for_each_entry(ctx, &sqd->ctx_list, sqd_list) {

			// 当前进程的cred与ctx的cred不一样
			if (current->cred != ctx->creds) {
				// todo: cred相关的后面再看
				if (old_cred)
					// 把当前进程的cred还原成旧的cred
					revert_creds(old_cred);
				// 设置当前进程的cred
				old_cred = override_creds(ctx->creds);
			}
			// 关联blkcg
			io_sq_thread_associate_blkcg(ctx, &cur_css);
#ifdef CONFIG_AUDIT
			// 审计相关
			current->loginuid = ctx->loginuid;
			current->sessionid = ctx->sessionid;
#endif

			// 真正处理ctx上的业务
			ret |= __io_sq_thread(ctx, start_jiffies, cap_entries);

			// 释放当前所占用的mm
			io_sq_thread_drop_mm();
		}

		if (ret & SQT_SPIN) {
			// 需要自旋，就先放弃内存引用，然后让出cpu
			io_run_task_work();
			io_sq_thread_drop_mm();
			cond_resched();
		} else if (ret == SQT_IDLE) {
			// 空闲
			if (kthread_should_park())
				continue;
			// 设置每个entry需要唤醒
			list_for_each_entry(ctx, &sqd->ctx_list, sqd_list)
				io_ring_set_wakeup_flag(ctx);
			// 调度出去
			schedule();
			start_jiffies = jiffies;
			// 清除需要唤醒标志
			list_for_each_entry(ctx, &sqd->ctx_list, sqd_list)
				io_ring_clear_wakeup_flag(ctx);
		}
	}

	io_run_task_work();
	io_sq_thread_drop_mm();

	if (cur_css)
		io_sq_thread_unassociate_blkcg();
	if (old_cred)
		revert_creds(old_cred);

	kthread_parkme();

	return 0;
}

static void io_sqd_init_new(struct io_sq_data *sqd)
{
	struct io_ring_ctx *ctx;

	while (!list_empty(&sqd->ctx_new_list)) {
		ctx = list_first_entry(&sqd->ctx_new_list, struct io_ring_ctx, sqd_list);
		init_wait(&ctx->sqo_wait_entry);
		// 设置sqo_wait的唤醒函数
		ctx->sqo_wait_entry.func = io_sq_wake_function;
		// 把ctx移到sqd->ctx列表
		list_move_tail(&ctx->sqd_list, &sqd->ctx_list);
		// 调用完成量
		complete(&ctx->sq_thread_comp);
	}
}
```
sqd主流程如下：
1. 把上下文从new_ctx_list移到ctx_list
2. 处理ctx上的业务
3. 根据处理结果，决定sqd是否要让出cpu.

## 处理业务
```c
static enum sq_ret __io_sq_thread(struct io_ring_ctx *ctx,
				  unsigned long start_jiffies, bool cap_entries)
{
	// 超时时间, sq_thread_idle默认是1秒
	unsigned long timeout = start_jiffies + ctx->sq_thread_idle;
	// 传入的数据
	struct io_sq_data *sqd = ctx->sq_data;
	unsigned int to_submit;
	int ret = 0;

again:
	// poll 列表不为空，则执行poll请求
	if (!list_empty(&ctx->iopoll_list)) {
		unsigned nr_events = 0;

		mutex_lock(&ctx->uring_lock);
		if (!list_empty(&ctx->iopoll_list) && !need_resched())
			// 处理io_poll业务
			io_do_iopoll(ctx, &nr_events, 0);
		mutex_unlock(&ctx->uring_lock);
	}

	// sqe的数量
	to_submit = io_sqring_entries(ctx);

	// 没有提交/忙/需要调度
	if (!to_submit || ret == -EBUSY || need_resched()) {
		// 放弃mm
		io_sq_thread_drop_mm();

		// todo: 这里为啥要自旋
		if (!list_empty(&ctx->iopoll_list) || need_resched() ||
		    (!time_after(jiffies, timeout) && ret != -EBUSY &&
		    !percpu_ref_is_dying(&ctx->refs)))
			return SQT_SPIN;

		// 在sqd->wait上等待
		prepare_to_wait(&sqd->wait, &ctx->sqo_wait_entry,
					TASK_INTERRUPTIBLE);

		// 被唤醒后，如果iopoll_list不为空，则继续处理
		if ((ctx->flags & IORING_SETUP_IOPOLL) &&
		    !list_empty_careful(&ctx->iopoll_list)) {
			finish_wait(&sqd->wait, &ctx->sqo_wait_entry);
			goto again;
		}

		// 睡眠之后要重新获取sqe的数量
		to_submit = io_sqring_entries(ctx);
		// 唤醒后还是没有提交或者当前进程忙，就是空闲状态，返回上层函数后会休眠
		if (!to_submit || ret == -EBUSY)
			return SQT_IDLE;
	}

	// 结束等待
	finish_wait(&sqd->wait, &ctx->sqo_wait_entry);
	// 清除唤醒标志
	io_ring_clear_wakeup_flag(ctx);

	// 如果有多个上下文，且当前ctx的提交数量大于8，则最多只能提交8个
	if (cap_entries && to_submit > 8)
		to_submit = 8;

	mutex_lock(&ctx->uring_lock);

	if (likely(!percpu_ref_is_dying(&ctx->refs) && !ctx->sqo_dead))
		// 真正的提交sqe
		ret = io_submit_sqes(ctx, to_submit);
	mutex_unlock(&ctx->uring_lock);

	// 如果有人在sqo_sq_wait上等待，则唤醒sqo_sq_wait队列
	if (!io_sqring_full(ctx) && wq_has_sleeper(&ctx->sqo_sq_wait))
		wake_up(&ctx->sqo_sq_wait);

	return SQT_DID_WORK;
}
```