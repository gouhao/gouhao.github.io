/*
 * NOTE: This example is works on x86 and powerpc.
 * Here's a sample kernel module showing the use of kprobes to dump a
 * stack trace and selected registers when _do_fork() is called.
 *
 * For more information on theory of operation of kprobes, see
 * Documentation/kprobes.txt
 *
 * You will see the trace data in /var/log/messages and on the console
 * whenever _do_fork() is invoked to create a new process.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/smp.h>

#define MAX_SYMBOL_LEN	64
static char symbol[MAX_SYMBOL_LEN] = "_do_fork";
module_param_string(symbol, symbol, sizeof(symbol), 0644);

//----------------- kprobe --------------------

/* kprobe pre_handler: called just before the probed instruction is executed */
/* x86_64中寄存器中参数的顺序: rdi rsi rdx rcx r8 r9*/
/* aarch64: r0-r7 对应参数 */
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	pr_info("handler_pre: clone_flags=%lu, stack_start=%lu, stack_size=%lu," 
		"parent_tidptr=%lu, child_tidptr=%lu, tls=%lu\n", 
		regs->di, regs->si, regs->dx, 
		regs->cx, regs->r8, regs->r9);
	/* A dump_stack() here will give a stack backtrace */
	return 0;
}

/* kprobe post_handler: called after the probed instruction is executed */
static void handler_post(struct kprobe *p, struct pt_regs *regs,
				unsigned long flags)
{
	pr_info("x86_64<%s> post_handler: p->addr = 0x%p, flags = 0x%lx\n",
		p->symbol_name, p->addr, regs->flags);
}

/*
 * fault_handler: this is called if an exception is generated for any
 * instruction within the pre- or post-handler, or when Kprobes
 * single-steps the probed instruction.
 */
static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
	pr_info("fault_handler: p->addr = 0x%p, trap #%dn", p->addr, trapnr);
	/* Return 0 because we don't handle the fault. */
	return 0;
}

/* For each probe you need to allocate a kprobe structure */
static struct kprobe kp = {
	.symbol_name	= symbol,
	.pre_handler	= handler_pre,
	.post_handler 	= handler_post,
	.fault_handler 	= handler_fault
};

//----------------- kprobe --------------------

// -------------- kretprobe ------------------

/* per-instance private data */
struct my_data {
	ktime_t entry_stamp;
};

/* Here we use the entry_hanlder to timestamp function entry */
static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct my_data *data;
	
	if (!current->mm)
		return 1;	/* Skip kernel threads */

	data = (struct my_data *)ri->data;
	data->entry_stamp = ktime_get();
	pr_info("entry_handler\n");
	return 0;
}

/*
 * Return-probe handler: Log the return value and duration. Duration may turn
 * out to be zero consistently, depending upon the granularity of time
 * accounting on the platform.
 */
static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	unsigned long retval = regs_return_value(regs);
	struct my_data *data = (struct my_data *)ri->data;
	s64 delta;
	ktime_t now;

	now = ktime_get();
	delta = ktime_to_ns(ktime_sub(now, data->entry_stamp));
	pr_info("%s returned %lu and took %lld ns to execute\n",
			symbol, retval, (long long)delta);
	return 0;
}

static struct kretprobe my_kretprobe = {
	.handler		= ret_handler,
	.entry_handler		= entry_handler,
	.data_size		= sizeof(struct my_data),
	/* Probe up to 20 instances concurrently. */
	.maxactive		= 20,
	.kp.symbol_name		= symbol
};
// -------------- kretprobe ------------------


static int __init kprobe_init(void)
{
	int ret;

	pr_info("kprobe_init\n");

	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_err("register_kprobe failed, returned %d\n", ret);
		return ret;
	}
	pr_info("register kprobe success\n");

	ret = register_kretprobe(&my_kretprobe);
	if (ret < 0) {
		pr_err("register_kretprobe failed, returned %d\n", ret);
		goto err1;
	}
	pr_info("register kretprobe success\n");

	return 0;

err1:
	unregister_kprobe(&kp);
	return -1;
}

static void __exit kprobe_exit(void)
{
	pr_info("kprobe_exit\n");
	unregister_kprobe(&kp);
	unregister_kretprobe(&my_kretprobe);
}

module_init(kprobe_init)
module_exit(kprobe_exit)
MODULE_LICENSE("GPL");
