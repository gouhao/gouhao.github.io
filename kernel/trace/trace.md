# Ftrace

```c
// kernel/trace/trace.c

// 注册一个tracer
int __init register_tracer(struct tracer *type)
{
	struct tracer *t;
	int ret = 0;

    // tracer名不能为空
	if (!type->name) {
		pr_info("Tracer must have a name\n");
		return -1;
	}

    // 名字长度不能超过MAX_TRACER_SIZE（100）
	if (strlen(type->name) >= MAX_TRACER_SIZE) {
		pr_info("Tracer has a name longer than %d\n", MAX_TRACER_SIZE);
		return -1;
	}

    // 调用locked_down hook
	if (security_locked_down(LOCKDOWN_TRACEFS)) {
		pr_warn("Can not register tracer %s due to lockdown\n",
			   type->name);
		return -EPERM;
	}

	mutex_lock(&trace_types_lock);

    // 这个值为true表示框架自身在运行
    // todo: 这个值，只在写的时候加了锁
	tracing_selftest_running = true;

    // trace_types是所有tracer的链表
    // 遍历链表，避免重复注册
	for (t = trace_types; t; t = t->next) {
		if (strcmp(type->name, t->name) == 0) {
			/* already found */
			pr_info("Tracer %s already registered\n",
				type->name);
			ret = -1;
			goto out;
		}
	}

    // 如果没有set_flag函数，则设置默认的函数
    // dummy_set_flag是个空实现，直接返回0，什么也不做
	if (!type->set_flag)
		type->set_flag = &dummy_set_flag;
	if (!type->flags) {
        // 如果没有设置flags，则申请一个flag
		type->flags = kmalloc(sizeof(*type->flags), GFP_KERNEL);
		if (!type->flags) {
			ret = -ENOMEM;
			goto out;
		}

        // 设置值为0
		type->flags->val = 0;

        // 设置opts为dummy_tracer_opt，
        // dummy_tracer_opt是个空结构体，里面值都是NULL/0
		type->flags->opts = dummy_tracer_opt;
	} else
        // 在有flag没有opts时，设置opts为dummy
		if (!type->flags->opts)
			type->flags->opts = dummy_tracer_opt;

	// 保存自己到flag中
	type->flags->trace = type;

    // todo: 运行自检程序？
	ret = run_tracer_selftest(type);
	if (ret < 0)
		goto out;

    // 把新的tracer加入到trace_types的表头
	type->next = trace_types;
	trace_types = type;

    // todo: 没看
	add_tracer_options(&global_trace, type);

 out:
	tracing_selftest_running = false;
	mutex_unlock(&trace_types_lock);

    // default_bootup_tracer是在命令行参数有值时，才不为空
    // 这里的判断，如果没有在命令行里设置tracer，则直接退出，
    // 否则还要在下面去判断
	if (ret || !default_bootup_tracer)
		goto out_unlock;

    // 如果当前注册的tracer不是在启动命令行里指定的，则退出
	if (strncmp(default_bootup_tracer, type->name, MAX_TRACER_SIZE))
		goto out_unlock;

    // 走到这，注册的就是grub命令行里设置的tracer
	printk(KERN_INFO "Starting tracer '%s'\n", type->name);
	
    // todo: 没看
	tracing_set_tracer(&global_trace, type->name);

    // 把default_bootup_tracer置空
	default_bootup_tracer = NULL;

    // todo: 没看
	apply_trace_boot_options();

	// todo: 没看
	disable_tracing_selftest("running a tracer");

 out_unlock:
	return ret;
}

static int run_tracer_selftest(struct tracer *type)
{
	struct trace_array *tr = &global_trace;
	struct tracer *saved_tracer = tr->current_trace;
	int ret;

	// 如果tracer禁用了自测，则退出
	if (!type->selftest || tracing_selftest_disabled)
		return 0;

	/*
	 * 如果一个tracer在系统启动时注册（此时调度器还没有初始化），这时不能运行他们的自测，
	 * 得稍后再去运行他们。
	 * 这时调用save_selftest，把这个函数的自测函数挂到postponed_selftests这个列表里，
	 * 等到系统完全启动后再运行他们。
	 */
	if (!selftests_can_run)
		return save_selftest(type);

	// 判断trace系统有没有启动。
	// 在tracing_is_on函数里主要判断了global_trace的trace_buffer能不能用
	if (!tracing_is_on()) {
		pr_warn("Selftest for tracer %s skipped due to tracing disabled\n",
			type->name);
		return 0;
	}

	// 重置每个cpu的ring_buffer
	tracing_reset_online_cpus(&tr->array_buffer);

	将当前的trace设置为新trace
	tr->current_trace = type;

#ifdef CONFIG_TRACER_MAX_TRACE
	if (type->use_max_tr) {
		/ 如果设置了最大的ring_buffer, 则将新tracer的max_buffer进行扩展
		/* If we expanded the buffers, make sure the max is expanded too */
		if (ring_buffer_expanded)
			ring_buffer_resize(tr->max_buffer.buffer, trace_buf_size,
					   RING_BUFFER_ALL_CPUS);
		tr->allocated_snapshot = true;
	}
#endif

	/* the test is responsible for initializing and enabling */
	pr_info("Testing tracer %s: ", type->name);

	// 调用自检函数
	ret = type->selftest(type, tr);
	/* the test is responsible for resetting too */
	tr->current_trace = saved_tracer;

	// 如果有错误，就直接返回
	if (ret) {
		printk(KERN_CONT "FAILED!\n");
		/* Add the warning after printing 'FAILED' */
		WARN_ON(1);
		return -1;
	}
	// 然后再重置每个cpu上的ring_buffer
	// todo: why?
	/* Only reset on passing, to avoid touching corrupted buffers */
	tracing_reset_online_cpus(&tr->array_buffer);

#ifdef CONFIG_TRACER_MAX_TRACE
	if (type->use_max_tr) {
		// 释放前面的扩展
		// todo: why?
		tr->allocated_snapshot = false;

		/* Shrink the max buffer again */
		if (ring_buffer_expanded)
			ring_buffer_resize(tr->max_buffer.buffer, 1,
					   RING_BUFFER_ALL_CPUS);
	}
#endif

	printk(KERN_CONT "PASSED\n");
	return 0;
}

void tracing_reset_online_cpus(struct trace_buffer *buf)
{
	struct ring_buffer *buffer = buf->buffer;
	int cpu;

	if (!buffer)
		return;

	// 先把buffer禁用
	ring_buffer_record_disable(buffer);

	/* Make sure all commits have finished */
	synchronize_sched();

	// 记录启动时间
	buf->time_start = buffer_ftrace_now(buf, buf->cpu);

	// 重置每个cpu的ring_buffer
	for_each_online_cpu(cpu)
		ring_buffer_reset_cpu(buffer, cpu);

	// 使能ring_buffer
	ring_buffer_record_enable(buffer);
}
```

## trace用户空间接口文件初始化
```c
tracer_init_tracefs->init_tracer_tracefs
// 这里传过来的tr是global_trace
static void
init_tracer_tracefs(struct trace_array *tr, struct dentry *d_tracer)
{
	struct trace_event_file *file;
	int cpu;

	trace_create_file("available_tracers", 0444, d_tracer,
			tr, &show_traces_fops);

	trace_create_file("current_tracer", 0644, d_tracer,
			tr, &set_tracer_fops);

	trace_create_file("tracing_cpumask", 0644, d_tracer,
			  tr, &tracing_cpumask_fops);

	trace_create_file("trace_options", 0644, d_tracer,
			  tr, &tracing_iter_fops);

	trace_create_file("trace", 0644, d_tracer,
			  tr, &tracing_fops);

	trace_create_file("trace_pipe", 0444, d_tracer,
			  tr, &tracing_pipe_fops);

	trace_create_file("buffer_size_kb", 0644, d_tracer,
			  tr, &tracing_entries_fops);

	trace_create_file("buffer_total_size_kb", 0444, d_tracer,
			  tr, &tracing_total_entries_fops);

	trace_create_file("free_buffer", 0200, d_tracer,
			  tr, &tracing_free_buffer_fops);

	trace_create_file("trace_marker", 0220, d_tracer,
			  tr, &tracing_mark_fops);

	file = __find_event_file(tr, "ftrace", "print");
	if (file && file->dir)
		trace_create_file("trigger", 0644, file->dir, file,
				  &event_trigger_fops);
	tr->trace_marker_file = file;

	trace_create_file("trace_marker_raw", 0220, d_tracer,
			  tr, &tracing_mark_raw_fops);

	trace_create_file("trace_clock", 0644, d_tracer, tr,
			  &trace_clock_fops);

	trace_create_file("tracing_on", 0644, d_tracer,
			  tr, &rb_simple_fops);

	trace_create_file("timestamp_mode", 0444, d_tracer, tr,
			  &trace_time_stamp_mode_fops);

	create_trace_options_dir(tr);

#if defined(CONFIG_TRACER_MAX_TRACE) || defined(CONFIG_HWLAT_TRACER)
	trace_create_file("tracing_max_latency", 0644, d_tracer,
			&tr->max_latency, &tracing_max_lat_fops);
#endif

	if (ftrace_create_function_files(tr, d_tracer))
		WARN(1, "Could not allocate function filter files");

#ifdef CONFIG_TRACER_SNAPSHOT
	trace_create_file("snapshot", 0644, d_tracer,
			  tr, &snapshot_fops);
#endif

	for_each_tracing_cpu(cpu)
		tracing_init_tracefs_percpu(tr, cpu);

	ftrace_init_tracefs(tr, d_tracer);
}
```

## 情景1：echo ftrace > /debug/tracing/current_tracer

```c
static const struct file_operations set_tracer_fops = {
	.open		= tracing_open_generic,
	.read		= tracing_set_trace_read,
	.write		= tracing_set_trace_write,
	.llseek		= generic_file_llseek,
};

用户空间写入这个文件，会调到set_tracer_fops的tracing_set_trace_write函数

static ssize_t
tracing_set_trace_write(struct file *filp, const char __user *ubuf,
			size_t cnt, loff_t *ppos)
{
	// 这里的tr是取的是filp的private_data，
	// 而filp的private_data是inode->i_private，是在tracing_open_generic时设置的，
	// inode->i_private在tracefs_create_file传入的data，在初始时是global_trace
	struct trace_array *tr = filp->private_data;
	char buf[MAX_TRACER_SIZE+1];
	int i;
	size_t ret;
	int err;

	// （省略代码）从用户空间复制字符串

	err = tracing_set_tracer(tr, buf);
	if (err)
		return err;

	*ppos += ret;

	return ret;
}
tracing_set_trace_write通过考贝用户空间传过来的字符串，然后调用tracing_set_tracer。


/**
	tr: 初始的时候是global_trace
	buf: 是用户空间传过来的tracer名称
**/
static int tracing_set_tracer(struct trace_array *tr, const char *buf)
{
	struct tracer *t;
#ifdef CONFIG_TRACER_MAX_TRACE
	bool had_max_tr;
#endif
	int ret = 0;

	mutex_lock(&trace_types_lock);

	// 如果禁用了ring_buffer的扩展，则申请固定问题
	if (!ring_buffer_expanded) {
		ret = __tracing_resize_ring_buffer(tr, trace_buf_size,
						RING_BUFFER_ALL_CPUS);
		if (ret < 0)
			goto out;
		ret = 0;
	}

	// 找到用户要设置的tracer
	for (t = trace_types; t; t = t->next) {
		if (strcmp(t->name, buf) == 0)
			break;
	}

	// 如果没找到就错了
	if (!t) {
		ret = -EINVAL;
		goto out;
	}

	// 如果现在就是这个tracer就退出
	if (t == tr->current_trace)
		goto out;

	// 如果系统正在启动，但是是这个tracer又不能在启动时运行，则退出
	if (system_state < SYSTEM_RUNNING && t->noboot) {
		pr_warn("Tracer '%s' is not allowed on command line, ignored\n",
			t->name);
		goto out;
	}

	// 如果当前tracer不能在这个array运行，则报错退出
	if (!trace_ok_for_array(t, tr)) {
		ret = -EINVAL;
		goto out;
	}

	// 如果当前tracer正在运行，有人读他的pipe，则返回忙，不能设置
	if (tr->current_trace->ref) {
		ret = -EBUSY;
		goto out;
	}

	// 禁用分支预测trace
	trace_branch_disable();

	// 禁用当前trace
	tr->current_trace->enabled--;

	// 调用trace的重置函数
	if (tr->current_trace->reset)
		tr->current_trace->reset(tr);

	// 先把当前trace设置成nop_trace
	tr->current_trace = &nop_trace;

#ifdef CONFIG_TRACER_MAX_TRACE
	had_max_tr = tr->allocated_snapshot;

	if (had_max_tr && !t->use_max_tr) {
		/*
		 * We need to make sure that the update_max_tr sees that
		 * current_trace changed to nop_trace to keep it from
		 * swapping the buffers after we resize it.
		 * The update_max_tr is called from interrupts disabled
		 * so a synchronized_sched() is sufficient.
		 */
		synchronize_sched();
		free_snapshot(tr);
	}
#endif

#ifdef CONFIG_TRACER_MAX_TRACE
	if (t->use_max_tr && !had_max_tr) {
		ret = tracing_alloc_snapshot_instance(tr);
		if (ret < 0)
			goto out;
	}
#endif

	// 如果新trace有init，则调用它的init函数
	if (t->init) {
		ret = tracer_init(t, tr);
		if (ret)
			goto out;
	}

	// 设置当前trace为新trace，使能它，并打开分支预测
	tr->current_trace = t;
	tr->current_trace->enabled++;
	trace_branch_enable(tr);
 out:
	mutex_unlock(&trace_types_lock);

	return ret;
}
```

## Trace function
```c

// kernel/trace/trace_functions.c

static struct tracer function_trace __tracer_data =
{
	.name		= "function",
	.init		= function_trace_init,
	.reset		= function_trace_reset,
	.start		= function_trace_start,
	.flags		= &func_flags,
	.set_flag	= func_set_flag,
	.allow_instances = true,
#ifdef CONFIG_FTRACE_SELFTEST
	.selftest	= trace_selftest_startup_function,
#endif
};

__init int init_function_trace(void)
{
	// init_func_cmd_traceon主要注册了下面5种命令
	init_func_cmd_traceon();
	return register_tracer(&function_trace);
}

// 打开trace
static struct ftrace_func_command ftrace_traceon_cmd = {
	.name			= "traceon",
	.func			= ftrace_trace_onoff_callback,
};

// 关闭trace
static struct ftrace_func_command ftrace_traceoff_cmd = {
	.name			= "traceoff",
	.func			= ftrace_trace_onoff_callback,
};

// 打印栈
static struct ftrace_func_command ftrace_stacktrace_cmd = {
	.name			= "stacktrace",
	.func			= ftrace_stacktrace_callback,
};

// 调用dump
static struct ftrace_func_command ftrace_dump_cmd = {
	.name			= "dump",
	.func			= ftrace_dump_callback,
};

// cpu dump
static struct ftrace_func_command ftrace_cpudump_cmd = {
	.name			= "cpudump",
	.func			= ftrace_cpudump_callback,
};

__init int register_ftrace_command(struct ftrace_func_command *cmd)
{
	struct ftrace_func_command *p;
	int ret = 0;

	mutex_lock(&ftrace_cmd_mutex);

	// ftrace_commands是一个链表
	// 这里遍历ftrace_commands，判断是不是已经注册过同名的cmd，
	// 如果已经注册，则返回BUSY。 
	// todo: 为啥返回BUSY，而不是EXISTS？
	list_for_each_entry(p, &ftrace_commands, list) {
		if (strcmp(cmd->name, p->name) == 0) {
			ret = -EBUSY;
			goto out_unlock;
		}
	}

	// 加到ftrace_commands列表
	list_add(&cmd->list, &ftrace_commands);
 out_unlock:
	mutex_unlock(&ftrace_cmd_mutex);

	return ret;
}

// 注册时第一个调的就是它的自测函数
__init int trace_selftest_startup_function(struct tracer *trace, struct trace_array *tr)
{
	int save_ftrace_enabled = ftrace_enabled;
	unsigned long count;
	int ret;

#ifdef CONFIG_DYNAMIC_FTRACE
	if (ftrace_filter_param) {
		printk(KERN_CONT " ... kernel command line filter set: force PASS ... ");
		return 0;
	}
#endif

	/* make sure msleep has been recorded */
	msleep(1);

	/* start the tracing */
	ftrace_enabled = 1;

	ret = tracer_init(trace, tr);
	if (ret) {
		warn_failed_init_tracer(trace, ret);
		goto out;
	}

	/* Sleep for a 1/10 of a second */
	msleep(100);
	/* stop the tracing. */
	tracing_stop();
	ftrace_enabled = 0;

	/* check the trace buffer */
	ret = trace_test_buffer(&tr->trace_buffer, &count);

	ftrace_enabled = 1;
	trace->reset(tr);
	tracing_start();

	if (!ret && !count) {
		printk(KERN_CONT ".. no entries found ..");
		ret = -1;
		goto out;
	}

	ret = trace_selftest_startup_dynamic_tracing(trace, tr,
						     DYN_FTRACE_TEST_NAME);
	if (ret)
		goto out;

	ret = trace_selftest_function_recursion();
	if (ret)
		goto out;

	ret = trace_selftest_function_regs();
 out:
	ftrace_enabled = save_ftrace_enabled;

	/* kill ftrace totally if we failed */
	if (ret)
		ftrace_kill();

	return ret;
}

// 每次从用户空间设置新的trace时，都会调用这个方法
static int function_trace_init(struct trace_array *tr)
{
	ftrace_func_t func;

	/*
	 * Instance trace_arrays get their ops allocated
	 * at instance creation. Unless it failed
	 * the allocation.
	 */
	if (!tr->ops)
		return -ENOMEM;

	/* Currently only the global instance can do stack tracing */
	if (tr->flags & TRACE_ARRAY_FL_GLOBAL &&
	    func_flags.val & TRACE_FUNC_OPT_STACK)
		func = function_stack_trace_call;
	else
		func = function_trace_call;

	ftrace_init_array_ops(tr, func);

	tr->trace_buffer.cpu = get_cpu();
	put_cpu();

	tracing_start_cmdline_record();
	tracing_start_function_trace(tr);
	return 0;
}
```