#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>

#define TRACE_SYMBOL "do_filp_open"

/* x86_64中寄存器中参数的顺序: rdi rsi rdx rcx r8 r9*/
/* aarch64: r0-r7 对应参数 */
static void do_filp_open_kprobe(struct kprobe *p, struct pt_regs *regs,
				unsigned long flags)
{
    int dfd = -1;
    struct filename *filename = NULL;
#ifdef __x86_64__
    dfd = regs->di;
    filename = (struct filename *) regs->si;
#elif __aarch64__
    dfd = regs->r0;
    filename = (struct filename *) regs->r1;
#endif

    if (filename)
        trace_printk("%s: dfd=%d, name=%s\n", p->symbol_name, dfd, filename->name);
    else
        trace_printk("Unsupport arch!\n");
}

static struct kprobe kprobe = {
	.symbol_name	= TRACE_SYMBOL,
	.post_handler 	= handler_post
};


struct trace_data {
	ktime_t entry_stamp;
};

static int do_filp_open_kretentry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct trace_data *data;

    // 执行之前记录函数开始时间，ri->data最大长度为4096
	data = (struct trace_data *)ri->data;
	data->entry_stamp = ktime_get();
	return 0;
}

static int do_filp_open_kretprobe(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    // 获取返回值
	unsigned long retval = regs_return_value(regs);

    // 获取在do_filp_open_kretentry里保存的数据
	struct trace_data *data = (struct trace_data *)ri->data;
	s64 delta;
	ktime_t now;

	now = ktime_get();

    // 计算执行时间
	delta = ktime_to_ns(ktime_sub(now, data->entry_stamp));
	trace_printk("%s returned %lu and took %lld ns to execute\n", 
                symbol, retval, (long long)delta);
	return 0;
}

static struct kretprobe kretprobe = {
    // 执行函数完成
	.handler		= do_filp_open_kretprobe,
    // 执行函数之前
	.entry_handler		= do_filp_open_kretentry,
	.data_size		= sizeof(struct trace_data),
	.kp.symbol_name		= TRACE_SYMBOL
};

static int __init kprobe_init(void)
{
	int ret;

    // 注册 kprobe
	ret = register_kprobe(&kprobe);
	if (ret < 0) {
		pr_err("register_kprobe failed, returned %d\n", ret);
		return ret;
	}

    // 注册 kretprobe
	ret = register_kretprobe(&kretprobe);
	if (ret < 0) {
		pr_err("register_kretprobe failed, returned %d\n", ret);
		goto err;
	}

	return 0;

err:
	unregister_kprobe(&kprobe);
	return -1;
}

static void __exit kprobe_exit(void)
{
	unregister_kprobe(&kp);
	unregister_kretprobe(&my_kretprobe);
}

module_init(kprobe_init)
module_exit(kprobe_exit)
MODULE_LICENSE("GPL");
