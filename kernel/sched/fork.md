## 简介
fork系统调用是用户空间进程的起点，fork的流程中涉及了内核中大多数核心的基础组件，比如：文件系统，内存管理，namespace等等，execve用来执行一个程序，调度是驱动系统运行的核心，所以了解这三个流程，对学习内核是一个很好的引导。

本文基于4.19.190版本的内核。

文中可能有些地方描述不准确，如有请指出，感谢。

## 陷入系统调用
系统调用通过0x80号中断来陷入内核。

在内核启动的主函数start_kernel（init/main.c）中会调用trap_init（arch/x86/kernel/traps.c），来初始化中断向量表，trap_init中又调用idt_setup_traps:
```c
// arch/x86/kernel/idt.c
void __init idt_setup_traps(void)
{
	idt_setup_from_table(idt_table, def_idts, ARRAY_SIZE(def_idts), true);
}

static const __initconst struct idt_data def_idts[] = {
    ...
	SYSG(X86_TRAP_OF,		overflow),
#if defined(CONFIG_IA32_EMULATION)
	SYSG(IA32_SYSCALL_VECTOR,	entry_INT80_compat),
#elif defined(CONFIG_X86_32)
	SYSG(IA32_SYSCALL_VECTOR,	entry_INT80_32),
#endif
};
```
在64位系统中CONFIG_IA32_EMULATION是打开的，所以0x80号中断会进入entry_INT80_compat函数，这个函数在中：
```asm
// arch/x86/entry/entry_64_compat.S

ENTRY(entry_INT80_compat)
    //前面有一大段保存调用栈的语句
	...

	SWITCH_TO_KERNEL_CR3 scratch_reg=%rdi
	...

	movq	%rsp, %rdi
	call	do_int80_syscall_32
.Lsyscall_32_done:

	/* Go back to user mode. */
	TRACE_IRQS_ON
	jmp	swapgs_restore_regs_and_return_to_usermode
END(entry_INT80_compat)
```
系统调用号在eax中，第1～6的参数在ebx,ecx,edx,esi,edi,ebp这几个寄存器中。

do_int80_syscall_32函数，从eax中取出调用号之后，直接通过系统调用函数表调用相应的系统调用。
```c
// arch/x86/entry/common.c

__visible void do_int80_syscall_32(struct pt_regs *regs)
{
	enter_from_user_mode();
	local_irq_enable();
	do_syscall_32_irqs_on(regs);
}

static __always_inline void do_syscall_32_irqs_on(struct pt_regs *regs)
{
	struct thread_info *ti = current_thread_info();
	unsigned int nr = (unsigned int)regs->orig_ax;

	...

	if (likely(nr < IA32_NR_syscalls)) {
		nr = array_index_nospec(nr, IA32_NR_syscalls);
#ifdef CONFIG_IA32_EMULATION
		regs->ax = ia32_sys_call_table[nr](regs);
#else
		...
#endif /* CONFIG_IA32_EMULATION */
	}

	syscall_return_slowpath(regs);
}

```

## Fork流程
在现代glibc里，fork是用clone系统调用实现的，不管是clone还是fork最终调用的函数是一样的_do_fork，只不过传的参数不一样。

```c
// kernel/fork.c

#ifdef __ARCH_WANT_SYS_FORK
SYSCALL_DEFINE0(fork)
{
#ifdef CONFIG_MMU
	return _do_fork(SIGCHLD, 0, 0, NULL, NULL, 0);
#else
	/* can not support in nommu mode */
	return -EINVAL;
#endif
}
#endif

#ifdef __ARCH_WANT_SYS_VFORK
SYSCALL_DEFINE0(vfork)
{
	return _do_fork(CLONE_VFORK | CLONE_VM | SIGCHLD, 0,
			0, NULL, NULL, 0);
}
#endif

SYSCALL_DEFINE5(clone, unsigned long, clone_flags, unsigned long, newsp,
		 int __user *, parent_tidptr,
		 int __user *, child_tidptr,
		 unsigned long, tls)
#endif
{
	return _do_fork(clone_flags, newsp, 0, parent_tidptr, child_tidptr, tls);
}
#endif
```

第一个参数是一个unsigned long类型的标志位，这个标志位由2部分组成，低8位是退出时要发给父进程的信号，比如fork中的SIGCHLD，表示进程退出时要向父进程发送这个信号。

其余部分决定了对父进程的资源如何处理，有2种方式：引用和复制。
* 引用只是简单的增加了父进程相应结构的引用计数，将指针赋值给相关变量；
* 复制则是申请属于进程自己的内存，然后将父进程中的内容复制到新申请的内存，两个进程的修改不会影响各自进程。

当相应的标志位为1时，则表示引用，否则就会复制，比如vfork中的CLONE_VM，就表示引用父进程的mm结构（内存），不申请新内存，因为vfork的设计目标就是想fork之后直接运行新程序。

vfork中的CLONE_VFORK进程，会保证子进程先运行，因为在fork的时候会使父进程会等待，直到子进程启动之后才返回。

_do_frok的主要流程如下：

1. 复制父进程
2. 如果是CLONE_VFORK，初始化vfork完成量
3. 唤醒子进程，实际上是将子进程的状态设为TASK_RUNNING，然后加入运行队列，有可能会抢占
4. 如果是CLONE_VFORK，则等待子进程运行完成再返回

_do_fork的代码在kernel/fork.c：2354中，
```c
long _do_fork(unsigned long clone_flags,
	      unsigned long stack_start,
	      unsigned long stack_size,
	      int __user *parent_tidptr,
	      int __user *child_tidptr,
	      unsigned long tls)
{
	struct completion vfork;
	struct pid *pid;
	struct task_struct *p;
	int trace = 0;
	long nr;

	...

	p = copy_process(clone_flags, stack_start, stack_size,
			 child_tidptr, NULL, trace, tls, NUMA_NO_NODE);
	add_latent_entropy();

	if (IS_ERR(p))
		return PTR_ERR(p);

	...

	pid = get_task_pid(p, PIDTYPE_PID);
	nr = pid_vnr(pid);

	if (clone_flags & CLONE_PARENT_SETTID)
		put_user(nr, parent_tidptr);

	if (clone_flags & CLONE_VFORK) {
		p->vfork_done = &vfork;
		init_completion(&vfork);
		get_task_struct(p);
	}

	wake_up_new_task(p);

	if (clone_flags & CLONE_VFORK) {
		if (!wait_for_vfork_done(p, &vfork))
			ptrace_event_pid(PTRACE_EVENT_VFORK_DONE, pid);
	}

	put_pid(pid);
	return nr;
}
```
如果是vfork的话，父进程要在这里等，子进程调用的exec之后，释放了父进程的空间后，会修改vfork_done这个完成量。

```c
// kernel/fork.c

static void mm_release(struct task_struct *tsk, struct mm_struct *mm)
{
	uprobe_free_utask(tsk);

	/* Get rid of any cached register state */
	deactivate_mm(tsk, mm);

	...

	if (tsk->vfork_done)
		complete_vfork_done(tsk);
}

static void complete_vfork_done(struct task_struct *tsk)
{
	struct completion *vfork;

	task_lock(tsk);
	vfork = tsk->vfork_done;
	if (likely(vfork)) {
		tsk->vfork_done = NULL;
		complete(vfork);
	}
	task_unlock(tsk);
}

```
比较重要的是copy_process和wake_up_new_task。下面分别看一下这两个方法。

copy_process代码也在fork.c:1736中，这个代码比较长有将近500行，是fork的核心。它的主要流程有以下几步：

1. 复制父进程的struct task_struct
2. 复制cred
3. 初始化task的一些重要变量，因为task是直接从父进程复制过来的，需要重置一些成员
4. 设置调度器
5. 复制父进程的资源。比如打开的文件，信号处理器，内存，namespace，io，栈相关信息
6. 申请一个pid
7. 设置父进程，兄弟进程等相关信息
8. 复制其它必要的信息

这其中第1，4，5步比较重要，下面对这几步来分析。

复制task的流程在dup_task_struct中，这个函数会返回一个新建的struct task_struct，代表新进程的task。struct task_struct结构的定义在include/linux/sched.h:599中，在内核里这个结构记录了进程所有的信息。

```c
// kernel/fork.c

//这里的orig传过来的是current
static struct task_struct *dup_task_struct(struct task_struct *orig, int node)
{
	struct task_struct *tsk;
	unsigned long *stack;
	struct vm_struct *stack_vm_area;
	int err;

	if (node == NUMA_NO_NODE)
		node = tsk_fork_get_node(orig);
	tsk = alloc_task_struct_node(node);
	if (!tsk)
		return NULL;

	stack = alloc_thread_stack_node(tsk, node);
	if (!stack)
		goto free_tsk;

	...

	err = arch_dup_task_struct(tsk, orig);

	...
	tsk->stack = stack;
    
    ...

	setup_thread_stack(tsk, orig);
	clear_user_return_notifier(tsk);
	clear_tsk_need_resched(tsk);
	set_task_stack_end_magic(tsk);

    ...

	/*
	 * One for us, one for whoever does the "release_task()" (usually
	 * parent)
	 */
	atomic_set(&tsk->usage, 2);

    ...
	return tsk;

    //出错处理
    ...
}

static inline struct task_struct *alloc_task_struct_node(int node)
{
	return kmem_cache_alloc_node(task_struct_cachep, GFP_KERNEL, node);
}

static unsigned long *alloc_thread_stack_node(struct task_struct *tsk, int node)
{
#ifdef CONFIG_VMAP_STACK
	...
#else
    //THREAD_SIZE_ORDER在x86下是1
	struct page *page = alloc_pages_node(node, THREADINFO_GFP,
					     THREAD_SIZE_ORDER);

	if (likely(page)) {
		tsk->stack = page_address(page);
		return tsk->stack;
	}
	return NULL;
#endif
}

int __weak arch_dup_task_struct(struct task_struct *dst,
					       struct task_struct *src)
{
	*dst = *src;
	return 0;
}

```
task的结构是从专用缓冲区task_struct_cachep进行分配的，接下来是分配系统调用栈，其中 THREAD_SIZE_ORDER在x86架构下是1（在大多数架构下是1,有些是0或2），这里的1表示2的1次方，即分配2个页面，内核里最小的分配单位是页面，假设一个页面为4096的话，一个进程的系统调用栈只有8192，所以在进程的上下文中，不要在函数内分配太大的数组，可能会导致内核崩溃。

> 注意：这里说是2个页面是进程的系统调用栈，不是用户空间的那个调用栈。用户空间的调用栈是可以随着使用去扩展的，但是也有限制，不可能无限扩展。

接下来通过arch_dup_task_struct来复制父进程的结构，这里直接通过结构的指针复制，*dst=*src在gcc的编译后会编译成memcpy，效率是较高的。

下来就是一些task的初始化，注意一下clear_tsk_need_resched，这个函数会清除task->stack->flags中的TIF_NEED_RESCHED这一位。如果这个标志位置位的话，在系统调用返回到用户空间时或者在时间中断处理程序中可能会引起调度，将当前进程切换出去。在这里对于一个刚创建的进程来说，将这一位清空。


第4步设置调度器的代码在kernel/sched/core.c:2318，sched_fork主要用来设置调度策略和调度器，task中sched_reset_on_fork不为0的话，就要在fork的时候重新设置调度策略，可以通过sched_setscheduler系统调用来改变此值。一般都不会设置这个值，直接从父进程复制过来的。

然后根据p->prio优先级来设置调度器，在4.19内核中有这几种高度器：deadline.c, fair.c, idle.c, rt.c, stop_task.c，这些调度器使用了面向对象的设计，扩展性很强。
```c
int sched_fork(unsigned long clone_flags, struct task_struct *p)
{
	unsigned long flags;

	__sched_fork(clone_flags, p);
	
	p->state = TASK_NEW;

	
	p->prio = current->normal_prio;

	
	if (unlikely(p->sched_reset_on_fork)) {
		if (task_has_dl_policy(p) || task_has_rt_policy(p)) {
			p->policy = SCHED_NORMAL;
			p->static_prio = NICE_TO_PRIO(0);
			p->rt_priority = 0;
		} else if (PRIO_TO_NICE(p->static_prio) < 0)
			p->static_prio = NICE_TO_PRIO(0);

		p->prio = p->normal_prio = __normal_prio(p);
		set_load_weight(p, false);

		/*
		 * We don't need the reset flag anymore after the fork. It has
		 * fulfilled its duty:
		 *
		p->sched_reset_on_fork = 0;
	}

	if (dl_prio(p->prio))
		return -EAGAIN;
	else if (rt_prio(p->prio))
		p->sched_class = &rt_sched_class;
	else
		p->sched_class = &fair_sched_clas

	init_entity_runnable_average(&p->se);

	...
	__set_task_cpu(p, smp_processor_id());
	if (p->sched_class->task_fork)
		p->sched_class->task_fork(p);
    
	...
	return 0;
}
```
设置完调度器之后，在init_entity_runnable_average方法中会设置进程的权重，然后调用调度器的task_fork函数，在这个函数里，会初始化当前进程的cfs相关信息，主要更新当前进程的vruntime, 设置新进程的vruntime，这个详细过程在讲调度器的时候再说。


设置完调度器后另一个重要的步骤是复制父进程的资源，主要复制的有以下这些：
```c
	// SystemV信号
	retval = copy_semundo(clone_flags, p);
	if (retval)
		goto bad_fork_cleanup_security;
	
	// 打开的文件
	retval = copy_files(clone_flags, p);
	if (retval)
		goto bad_fork_cleanup_semundo;
	
	// 文件系统
	retval = copy_fs(clone_flags, p);
	if (retval)
		goto bad_fork_cleanup_files;
	
	// 信号处理器
	retval = copy_sighand(clone_flags, p);
	if (retval)
		goto bad_fork_cleanup_fs;
	
	// 信号
	retval = copy_signal(clone_flags, p);
	if (retval)
		goto bad_fork_cleanup_sighand;
	
	// 虚拟内存
	retval = copy_mm(clone_flags, p);
	if (retval)
		goto bad_fork_cleanup_signal;

	// 命名空间
	retval = copy_namespaces(clone_flags, p);
	if (retval)
		goto bad_fork_cleanup_mm;
	
	// 设备io
	retval = copy_io(clone_flags, p);
	if (retval)
		goto bad_fork_cleanup_namespaces;
	
	// 栈
	retval = copy_thread_tls(clone_flags, stack_start, stack_size, p, tls);
	if (retval)
		goto bad_fork_cleanup_io;
```
copy_semundo（ipc/sem.c:2246）复制的是semundo，这是SystemV的一种进程间通信方式，只有CLONE_SYSVSEM这个标志时，才共享父进程相关变量，否则不复制。

vfs有几个比较重要的数据结构：
* struct fs_struct(include/linux/fs_struct.h:9):主要记录了文件系统相关，有本进程所在的根目录和本进程当前的工作目录。
* struct files_struct(include/linux/fdtable.h:49):进程已打开的文件列表。
* struct file(include/linux/fs.h:920)：进程已打开的文件，里面记录了读写位置，file_op指针等信息
* struct dentry(include/linux/dcache.h:91)：逻辑上的文件。里面记录了超级块，文件名，子目录的指针等。一个dentry可以对应多个file。
* struct inode(include/linux/fs.h:611)：物理上的文件。记录了文件的一些基本信息，uid, 各种时间，以及一些基本信息，还有文件在介质上的位置与分布等信息。一个inode可以对应多个dentry，因为一个文件可以有多个链接

```
inode---|				|---file
		|----dentry-----|---file
		|				|---file
		|----dentry
```


copy_files(kernel/fork.c:1433)复制父进程已打开的文件描述符。
```c
static int copy_files(unsigned long clone_flags, struct task_struct *tsk)
{
	struct files_struct *oldf, *newf;
	int error = 0;

	oldf = current->files;
	if (!oldf)
		goto out;

	if (clone_flags & CLONE_FILES) {
		atomic_inc(&oldf->count);
		goto out;
	}

	newf = dup_fd(oldf, &error);
	if (!newf)
		goto out;

	tsk->files = newf;
	error = 0;
out:
	return error;
}
```
oldf是父进程的struct files_struct，如果CLONE_FILES这个标志，则只是增加一下父进程files的引用计数就直接返回。否则的话会通过dup_fd复制父进程中打开的文件。在复制文件的时候会把已打开的文件都复制，把exec_on_close位图也复制。

在struct task_struct中有个files成员用来记录进程打开的全部文件。
```c
struct fdtable {
	unsigned int max_fds; //最大容量
	struct file __rcu **fd;      /* current fd array */
	unsigned long *close_on_exec;
	unsigned long *open_fds;
	unsigned long *full_fds_bits;
	struct rcu_head rcu;
};

/*
 * Open file table structure
 */
struct files_struct {
  /*
   * read mostly part
   */
	atomic_t count; //打开文件的数量
	bool resize_in_progress;
	wait_queue_head_t resize_wait;

	struct fdtable __rcu *fdt;
	struct fdtable fdtab;
  /*
   * written part on a separate cache line in SMP
   */
	spinlock_t file_lock ____cacheline_aligned_in_smp; //锁
	unsigned int next_fd; //下一个fd号
	unsigned long close_on_exec_init[1]; //默认执行时关闭标志
	unsigned long open_fds_init[1]; //默认已打开文件标志
	unsigned long full_fds_bits_init[1];//已经打开了多少个NR_OPEN_DEFAULT的文件
	struct file __rcu * fd_array[NR_OPEN_DEFAULT]; //打开文件的列表,NR_OPEN_DEFAULT为64位
};
```
这两个结构里都有相应的close_on_exec, open_fds, fds_bits这三组字段，这是因为在远古时代files_struct里有上述三个变量，没有fdtab这个字段，也就是说一个进程只能打开NR_OPEN_DEFAULT个文件，在原来32位时，一个进程只能打开32个文件，为了解决打开文件的数量限制，新增了struct fdtable里相应的三个字段，fdtable里的字段在初始化时指向files_struct里对应的字段，如果打开文件数量超过NR_OPEN_DEFAULT，则新申请内存，让fdtable里三个变量指向新申请的内存，这样就解决了打开文件数量的限制。在用户空间使用open打开文件时返回的fd，实际上就是fd_array的下标。

复制文件系统，也是在CLONE_FS置位时增加引用，否则的话进行复制。
```c
struct fs_struct {
	int users;
	spinlock_t lock;
	seqcount_t seq;
	int umask;
	int in_exec;
	struct path root, pwd;
} __randomize_layout;

static int copy_fs(unsigned long clone_flags, struct task_struct *tsk)
{
	struct fs_struct *fs = current->fs;
	if (clone_flags & CLONE_FS) {
		/* tsk->fs is already what we want */
		spin_lock(&fs->lock);
		if (fs->in_exec) {
			spin_unlock(&fs->lock);
			return -EAGAIN;
		}
		fs->users++;
		spin_unlock(&fs->lock);
		return 0;
	}
	tsk->fs = copy_fs_struct(fs);
	if (!tsk->fs)
		return -ENOMEM;
	return 0;
}
```
当CLONE_FS为1的时候，只是增加父进程fs_struct的引用计数，否则会调用copy_fs_struct进行复制，新申请一个fs_struct, 将umask, root, pwd这几个变量复制过来。

```c
struct k_sigaction {
	struct sigaction sa;
#ifdef __ARCH_HAS_KA_RESTORER
	__sigrestore_t ka_restorer;
#endif
};

struct sighand_struct {
	atomic_t		count;
	struct k_sigaction	action[_NSIG];
	spinlock_t		siglock;
	wait_queue_head_t	signalfd_wqh;
};

static int copy_sighand(unsigned long clone_flags, struct task_struct *tsk)
{
	struct sighand_struct *sig;

	if (clone_flags & CLONE_SIGHAND) {
		refcount_inc(&current->sighand->count);
		return 0;
	}
	sig = kmem_cache_alloc(sighand_cachep, GFP_KERNEL);
	RCU_INIT_POINTER(tsk->sighand, sig);
	if (!sig)
		return -ENOMEM;

	refcount_set(&sig->count, 1);
	spin_lock_irq(&current->sighand->siglock);
	memcpy(sig->action, current->sighand->action, sizeof(sig->action));
	spin_unlock_irq(&current->sighand->siglock);

	/* Reset all signal handler not set to SIG_IGN to SIG_DFL. */
	if (clone_flags & CLONE_CLEAR_SIGHAND)
		flush_signal_handlers(tsk, 0);

	return 0;
}
```
copy_sighand是复制信号处理器，sighand_struct中的action数组就是我们在用户空间注册的信号处理器。当CLONE_SIGHAND为1时，只是增加引用计数，否则，新申请内存进行复制，主要使用memcpy将current->sighand->action复制过来。


copy_signal是复制信号相关，如果是线程直接返回，否则新申请一个struct signal_struct，然后对其初始化。
```c
// kernel/fock.c:1470
static int copy_signal(unsigned long clone_flags, struct task_struct *tsk)
{
	struct signal_struct *sig;

	if (clone_flags & CLONE_THREAD)
		return 0;

	sig = kmem_cache_zalloc(signal_cachep, GFP_KERNEL);
	tsk->signal = sig;
	if (!sig)
		return -ENOMEM;

	sig->nr_threads = 1;
	atomic_set(&sig->live, 1);
	atomic_set(&sig->sigcnt, 1);

	/* list_add(thread_node, thread_head) without INIT_LIST_HEAD() */
	sig->thread_head = (struct list_head)LIST_HEAD_INIT(tsk->thread_node);
	tsk->thread_node = (struct list_head)LIST_HEAD_INIT(sig->thread_head);

	init_waitqueue_head(&sig->wait_chldexit);
	sig->curr_target = tsk;
	init_sigpending(&sig->shared_pending);
	INIT_HLIST_HEAD(&sig->multiprocess);
	seqlock_init(&sig->stats_lock);
	prev_cputime_init(&sig->prev_cputime);

#ifdef CONFIG_POSIX_TIMERS
	INIT_LIST_HEAD(&sig->posix_timers);
	hrtimer_init(&sig->real_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	sig->real_timer.function = it_real_fn;
#endif

	task_lock(current->group_leader);
	memcpy(sig->rlim, current->signal->rlim, sizeof sig->rlim);
	task_unlock(current->group_leader);

	posix_cpu_timers_init_group(sig);

	tty_audit_fork(sig);
	sched_autogroup_fork(sig);

	sig->oom_score_adj = current->signal->oom_score_adj;
	sig->oom_score_adj_min = current->signal->oom_score_adj_min;

	mutex_init(&sig->cred_guard_mutex);

	return 0;
}
```

```c
static int copy_mm(unsigned long clone_flags, struct task_struct *tsk)
{
	struct mm_struct *mm, *oldmm;

	...

	oldmm = current->mm;
	if (!oldmm)
		return 0;

	/* initialize the new vmacache entries */
	vmacache_flush(tsk);

	if (clone_flags & CLONE_VM) {
		mmget(oldmm);
		mm = oldmm;
	} else {
		mm = dup_mm(tsk, current->mm);
		if (!mm)
			return -ENOMEM;
	}

	tsk->mm = mm;
	tsk->active_mm = mm;
	return 0;
}

static struct mm_struct *dup_mm(struct task_struct *tsk,
				struct mm_struct *oldmm)
{
	struct mm_struct *mm;
	int err;

	mm = allocate_mm();
	if (!mm)
		goto fail_nomem;

	memcpy(mm, oldmm, sizeof(*mm));

	if (!mm_init(mm, tsk, mm->user_ns))
		goto fail_nomem;

	err = dup_mmap(mm, oldmm);
	if (err)
		goto free_pt;
	...
}
```
当CLONE_VM为1时，只是增加当前进程的虚存引用计数，否则，新申请一个struct mm_struct, 将当前进程的数据结构复制进去，然后调用dup_mmap复制文件映射区，因为进程可能会把文件映射到自己的内存。

clone_namespace，如果没有CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC |CLONE_NEWPID |CLONE_NEWNET | CLONE_NEWCGROUP | CLONE_NEWTIME这些标志，则会共享当前进程的ns, 否则会新建一个ns，新建ns需要CAP_SYS_ADMIN权限（这个权限一般是root）的执行，

clone_io是与磁盘io相关的。

最后一步是copy_thread_tls复制系统栈代码如下：
```
int copy_thread_tls(unsigned long clone_flags, unsigned long sp,
		unsigned long arg, struct task_struct *p, unsigned long tls)
{
	int err;
	struct pt_regs *childregs;
	struct fork_frame *fork_frame;
	struct inactive_task_frame *frame;
	struct task_struct *me = current;

	childregs = task_pt_regs(p);
	fork_frame = container_of(childregs, struct fork_frame, regs);
	frame = &fork_frame->frame;

	frame->flags = X86_EFLAGS_FIXED;
	frame->bp = 0;

	// 新进程执行的地址
	frame->ret_addr = (unsigned long) ret_from_fork;
	p->thread.sp = (unsigned long) fork_frame;
	p->thread.io_bitmap_ptr = NULL;

	...

	if (unlikely(p->flags & PF_KTHREAD)) {
		/* kernel thread */
		memset(childregs, 0, sizeof(struct pt_regs));
		frame->bx = sp;		/* function */
		frame->r12 = arg;
		return 0;
	}
	frame->bx = 0;

	// 复制当前进程的栈
	*childregs = *current_pt_regs();

	// 函数的返回值
	childregs->ax = 0;
	if (sp)
		childregs->sp = sp;

	...
	return err;
}
```
这个函数比较关键，它直接涉及到了新进程的返回地址和返回值。新创建的进程在下次调度的时候会从ret_from_fork中执行，在这个函数里复制了父进程的调用栈，所以子进程在被调度时，也会从相同的路径去返回，返回值在ax中为0, 这也是fork为什么会返回2次的原因。实际不是返回2次，每个函数只返回一次，只是2个不同的进程走了同一条路，从用户空间看即是返回了2次。

复制父进程的流程就完了，再回到_do_fork中，下一个比较关键的函数是wake_up_new_task：
```c
void wake_up_new_task(struct task_struct *p)
{
	struct rq_flags rf;
	struct rq *rq;

	raw_spin_lock_irqsave(&p->pi_lock, rf.flags);
	p->state = TASK_RUNNING;
#ifdef CONFIG_SMP
	p->recent_used_cpu = task_cpu(p);
	rseq_migrate(p);
	__set_task_cpu(p, select_task_rq(p, task_cpu(p), SD_BALANCE_FORK, 0));
#endif
	rq = __task_rq_lock(p, &rf);
	update_rq_clock(rq);
	post_init_entity_util_avg(&p->se);

	activate_task(rq, p, ENQUEUE_NOCLOCK);
	p->on_rq = TASK_ON_RQ_QUEUED;
	trace_sched_wakeup_new(p);
	check_preempt_curr(rq, p, WF_FORK);
#ifdef CONFIG_SMP
	if (p->sched_class->task_woken) {
		rq_unpin_lock(rq, &rf);
		p->sched_class->task_woken(rq, p);
		rq_repin_lock(rq, &rf);
	}
#endif
	task_rq_unlock(rq, p, &rf);
}
```
进程的状态有：
```c
#define TASK_RUNNING			0x0000 //运行
#define TASK_INTERRUPTIBLE		0x0001 //睡眠可中断
#define TASK_UNINTERRUPTIBLE		0x0002 //睡眠不可中断
#define TASK_DEAD			0x0080 //死亡进程
#define TASK_NEW			0x0800 //新进程
```
wake_up_new_task先将当前进程状态修改成TASK_RUNNING，然后选一个cpu分给这个进程，再调用activate_task将当前进程加入运行队列中。

```c
static inline void enqueue_task(struct rq *rq, struct task_struct *p, int flags)
{
	if (!(flags & ENQUEUE_NOCLOCK))
		update_rq_clock(rq);

	if (!(flags & ENQUEUE_RESTORE))
		sched_info_queued(rq, p);

	p->sched_class->enqueue_task(rq, p, flags);
}

void activate_task(struct rq *rq, struct task_struct *p, int flags)
{
	if (task_contributes_to_load(p))
		rq->nr_uninterruptible--;

	enqueue_task(rq, p, flags);
}
```
最终会调用到sched_class->enqueue_task中，按不同的策略加入到运行队列中。现在都是smp结构，所以会加入到某个cpu的的运行队列中。将任务状态修改为TASK_RUNNING，并不代表它立马就可以运行，只是准备就绪，等待调度到它才能获得cpu得以运行。

加入运行队列后，还要通过check_preempt_curr()，检查当前进程是否可以被抢占，如果可以抢占就设置当前进程的TIF_NEED_RESCHED标志。check_preempt_curr内部主要是调用调度器里的check_preempt_curr实现，大概流程就是比较当前task和新task的虚拟运行时间，然后判断当前进程是否被抢占。在这里大概率不会发生抢占，因为当前task的时间片应该还没用完。

fork的最后一步就是处理CLONE_VFORK相关的，如是是vfork调用，父进程必须等到子进程调用了execve系统调用之后才可以运行，父进程在vfork这个完成量上等待子进程调用execve。子进程在调用了execve后，会通知这个完成量来唤醒父进程，父进程得以返回。

在vfork中子进程没有复制父进程的mm，如果子进程不调用execve而修改了mm则可能会破坏父进程的内存空间，因为在vfork到execve之间存在一个窗口期，所以vfork还是有风险的应该尽量少用。vfork主要通过CLONE_VM共享父进程的虚存空间，所以mm没有复制，加快了fork的速度，但是现代内核在fork的mm中采用了COW，vfork所带来的性能提升也不再是亮点。