# kprobe
## 简介
本文主要介绍kprobe的3种使用方法：trace, bpftrace, kprobe-module。关于kprobe是什么，网上有很多文章，这里就不细说了。

通过跟踪do_filp_open函数来说明上面的3种跟踪方法，do_filp_open的代码如下：
```c
struct file *do_filp_open(int dfd, struct filename *pathname,
		const struct open_flags *op)
{
	struct nameidata nd;
	int flags = op->lookup_flags;
	struct file *filp;

	set_nameidata(&nd, dfd, pathname);
	filp = path_openat(&nd, op, flags | LOOKUP_RCU);
	if (unlikely(filp == ERR_PTR(-ECHILD)))
		filp = path_openat(&nd, op, flags);
	if (unlikely(filp == ERR_PTR(-ESTALE)))
		filp = path_openat(&nd, op, flags | LOOKUP_REVAL);
	restore_nameidata();
	return filp;
}
```

主要跟踪下面几个场景：
1. 查看入参 dfd, pathname->name。dfd是开始查找的文件描述符，一般不指定的话是AT_FDCWD(FFFFFFFFFFFFFF9C)，pathname是个结构体文件名保存在 struct filename->name里。
2. 查看返回值。返回值是struct file，正常情况下返回file对象，其它情况返回错误代码。
3. 查看do_filp_open某行代码中的返回值。本例中我们查看`filp = path_openat(&nd, op, flags | LOOKUP_RCU);`的返回值。
4. 统计函数执行时间
5. 修改代码返回值（这个只有使用模块方法才能实现）

## trace
### 查看入参以及返回值
我们先找一下name在struct filename里的偏移：
```sh
$ gdb vmlinux # 直接用gdb调试vmlinux

(gdb) p &(((struct filename *)0)->name)
$1 = (const char **) 0x0 <irq_stack_union> # name的偏移值为0
```

参数在寄存器里存储， x86_64参数寄存器 第1~6的参数: %rdi，%rsi，%rdx，%rcx，%r8，%r9, 用下面脚本测试：
```sh
#!/bin/bash
trace_dir=/sys/kernel/debug/tracing/

# 下面echo中的 %si 是存储pathname的寄存器，它是个结构体地址，用 +0(%si) 可以取出它的值， +0是偏移量，也就是name的地址，在外面再用一个+0()，则取出的是name的值
echo 'p:t1 do_filp_open dfd=%di name=+0(+0(%si)):string' >> $trace_dir/kprobe_events

# $retval是返回值
echo 'r:t2 do_filp_open ret=$retval' >> $trace_dir/kprobe_events 

echo 1 > $trace_dir/events/kprobes/t1/enable
echo 1 > $trace_dir/events/kprobes/t2/enable
echo 1 > $trace_dir/tracing_on
cat testfile
echo 0 > $trace_dir/events/kprobes/t1/enable
echo 0 > $trace_dir/events/kprobes/t2/enable
echo 0 > $trace_dir/tracing_on
echo > $trace_dir/kprobe_events
```
打印如下:
```
<...>-7317  [006] .... 88731.883298: t1: (do_filp_open+0x0/0x110) dfd=0xffffff9c name="testfile"
<...>-7317  [006] d... 88731.883304: t2: (do_sys_openat2+0x201/0x290 <- do_filp_open) ret=0xffff9c04e48e0400"
```
可以看到dfd和name的值与我们预期的一样, dfd是0xffffff9c(AT_FDCWD), name是testfile。do_filp_open的返回值是0xffff9c04e48e0400，也就是打开的file对象的指针。

在struct file->f_path.dentry->d_name.name里也保存了文件名，我们来验证一下，返回值里的文件名就是我们打开的文件名，各结构的偏移如下：
```
(gdb) p &((struct file *)0)->f_path.dentry
$1 = (struct dentry **) 0x18 <irq_stack_union+24>
(gdb) p &((struct dentry *)0)->d_name.name
$2 = (const unsigned char **) 0x28 <irq_stack_union+40>
```
因为file里的f_path, dentry里的d_name不是指针，所以用这种方法获取它的地址偏移。  
把上面脚本中观察返回值的语句改成如下：
```sh
echo 'r:t2 do_filp_open ret=$retval ret_name=+0(+40(+24($retval))):string' >> $trace_dir/kprobe_events
```
打印值如下：
```
<...>-7469  [006] .... 90981.880665: t1: (do_filp_open+0x0/0x110) dfd=0xffffff9c name="testfile"
<...>-7469  [006] d... 90981.880673: t2: (do_sys_openat2+0x201/0x290 <- do_filp_open) ret=0xffff9c04e8bcb500 ret_name="testfile"
```
### 查看代码中的返回值
要查看`filp = path_openat(&nd, op, flags | LOOKUP_RCU);`这句代码的返回值.  
首先反汇编vmlinx, 找到path_openat对应的代码,如下:
```asm
ffffffff812e57f0 <do_filp_open>:
... # 省略代码
ffffffff812e5869:       48 89 45 a8             mov    %rax,-0x58(%rbp)
ffffffff812e586d:       83 ca 40                or     $0x40,%edx
ffffffff812e5870:       4c 89 ee                mov    %r13,%rsi
ffffffff812e5873:       4c 89 e7                mov    %r12,%rdi
ffffffff812e5876:       65 48 8b 04 25 80 5c    mov    %gs:0x15c80,%rax
ffffffff812e587d:       01 00
ffffffff812e587f:       4c 89 a0 50 0b 00 00    mov    %r12,0xb50(%rax)
ffffffff812e5886:       e8 d5 d6 ff ff          callq  ffffffff812e2f60 <path_openat>
ffffffff812e588b:       48 83 f8 f6             cmp    $0xfffffffffffffff6,%rax
ffffffff812e588f:       48 89 c3                mov    %rax,%rbx
ffffffff812e5892:       74 33                   je     ffffffff812e58c7 <do_filp_open+0xd7>
```
从汇编代码可以看出调用是在`ffffffff812e5886:       e8 d5 d6 ff ff          callq  ffffffff812e2f60 <path_openat>`这一行, 我们应该在下一行来跟踪它的返回值，也就是`ffffffff812e588b:       48 83 f8 f6             cmp    $0xfffffffffffffff6,%rax`，fffffffffffffff6(-10)就是 -ECHILD。

首先计算一下要跟踪的代码代码到do_filp_open偏移：  
offset = ffffffff812e588b - ffffffff812e57f0 = 9B = 155

我们把脚本改成下成来观察：
```sh
#!/bin/bash
trace_dir=/sys/kernel/debug/tracing/
echo 'p:t1 do_filp_open dfd=%di name=+0(+0(%si)):string' >> $trace_dir/kprobe_events
echo 'r:t2 do_filp_open ret=$retval ret_name=+0(+40(+24($retval))):string' >> $trace_dir/kprobe_events

# 打印 path_openat 的返回值
echo 'p:t3 do_filp_open+155 fp=%ax' >> $trace_dir/kprobe_events

echo 1 > $trace_dir/events/kprobes/t1/enable
echo 1 > $trace_dir/events/kprobes/t2/enable
echo 1 > $trace_dir/events/kprobes/t3/enable
echo 1 > $trace_dir/tracing_on
cat testfile
cat testfile2 #这个文件不存在
echo 0 > $trace_dir/events/kprobes/t1/enable
echo 0 > $trace_dir/events/kprobes/t2/enable
echo 0 > $trace_dir/events/kprobes/t3/enable
echo 0 > $trace_dir/tracing_on
echo > $trace_dir/kprobe_events

```
这个testfile2不存在，trace打印如下：
```
<...>-7492  [006] .... 91462.485985: t1: (do_filp_open+0x0/0x110) dfd=0xffffff9c name="testfile"
<...>-7492  [006] d.Z. 91462.485992: t3: (do_filp_open+0x9b/0x110) fp=0xffff9c04e2ae7900
<...>-7492  [006] d... 91462.485992: t2: (do_sys_openat2+0x201/0x290 <- do_filp_open) ret=0xffff9c04e2ae7900 ret_name="testfile"

......

<...>-7493  [006] .... 91462.486939: t1: (do_filp_open+0x0/0x110) dfd=0xffffff9c name="testfile2"
<...>-7493  [006] d.Z. 91462.486946: t3: (do_filp_open+0x9b/0x110) fp=0xfffffffffffffffe
<...>-7493  [006] d... 91462.486949: t2: (do_sys_openat2+0x201/0x290 <- do_filp_open) ret=0xfffffffffffffffe ret_name=(fault)

```
从上面日志可知，打开testfile时，这个文件存在，返回的是正常的file指针。testfile2不存在，返回了0xfffffffffffffffe，这个值是 -2, 也就是 -ENOENT，返回值的文件名当然显示不出来，显示 fault 。

### 统计函数执行时间
trace统计函数执行时间，可以把/sys/kernel/debug/tracing/current_tracer设置成function_tracer来观察。

### 设置过滤器
trace的打印日志非常多，可以设置过滤器，只打印我们想要的东西。trace的过滤器是filter文件，可以在里面用 && || ! == > < 等这些符号，只有filter里的条件为真时，才会执行打印。  
我们脚本中增加t1的过滤器，t1只显示文件名为testfile和testfile2的，脚本如下：
```
#!/bin/bash
trace_dir=/sys/kernel/debug/tracing/

echo 'p:t1 do_filp_open dfd=%di name=+0(+0(%si)):string' >> $trace_dir/kprobe_events
echo 'r:t2 do_filp_open ret=$retval ret_name=+0(+40(+24($retval))):string' >> $trace_dir/kprobe_events

# 当打开的文件名是testfile或testfile2时才打印
echo 'name=="testfile" || name=="testfile2"' >> $trace_dir/events/kprobes/t1/filter

echo 1 > $trace_dir/events/kprobes/t1/enable
echo 1 > $trace_dir/events/kprobes/t2/enable
echo 1 > $trace_dir/tracing_on
cat testfile
cat testfile2
echo 0 > $trace_dir/events/kprobes/t1/enable
echo 0 > $trace_dir/events/kprobes/t2/enable
echo 0 > $trace_dir/tracing_on
echo > $trace_dir/kprobe_events
```
打印如下：
```
<...>-7628  [006] d... 92891.051256: t2: (do_open_execat+0x83/0x190 <- do_filp_open) ret=0xffff9c04e8bcae00 ret_name="cat"
<...>-7628  [006] d... 92891.051291: t2: (do_open_execat+0x83/0x190 <- do_filp_open) ret=0xffff9c04e8bca300 ret_name="ld-2.28.so"
<...>-7628  [006] d... 92891.051410: t2: (do_sys_openat2+0x201/0x290 <- do_filp_open) ret=0xffff9c04e8bcbf00 ret_name="ld.so.cache"
<...>-7628  [006] d... 92891.051428: t2: (do_sys_openat2+0x201/0x290 <- do_filp_open) ret=0xffff9c04e8bcb800 ret_name="libc-2.28.so"
<...>-7628  [006] d... 92891.051606: t2: (do_sys_openat2+0x201/0x290 <- do_filp_open) ret=0xffff9c04e8bcb100 ret_name="locale-archive"
<...>-7628  [006] .... 92891.051659: t1: (do_filp_open+0x0/0x110) dfd=0xffffff9c name="testfile"
<...>-7628  [006] d... 92891.051666: t2: (do_sys_openat2+0x201/0x290 <- do_filp_open) ret=0xffff9c04e8bca800 ret_name="testfile"
trace_open.sh-7627  [005] d... 92891.051827: t2: (do_sys_openat2+0x201/0x290 <- do_filp_open) ret=0xffff9c04e488b000 ret_name="xterm-256color"
<...>-7629  [006] d... 92891.052110: t2: (do_open_execat+0x83/0x190 <- do_filp_open) ret=0xffff9c04e8bca600 ret_name="cat"
<...>-7629  [006] d... 92891.052133: t2: (do_open_execat+0x83/0x190 <- do_filp_open) ret=0xffff9c04e8bca400 ret_name="ld-2.28.so"
<...>-7629  [006] d... 92891.052242: t2: (do_sys_openat2+0x201/0x290 <- do_filp_open) ret=0xffff9c04e8bcbe00 ret_name="ld.so.cache"
<...>-7629  [006] d... 92891.052258: t2: (do_sys_openat2+0x201/0x290 <- do_filp_open) ret=0xffff9c04e8bcb600 ret_name="libc-2.28.so"
<...>-7629  [006] d... 92891.052425: t2: (do_sys_openat2+0x201/0x290 <- do_filp_open) ret=0xffff9c04e8bcb900 ret_name="locale-archive"
<...>-7629  [006] .... 92891.052467: t1: (do_filp_open+0x0/0x110) dfd=0xffffff9c name="testfile2"
<...>-7629  [006] d... 92891.052475: t2: (do_sys_openat2+0x201/0x290 <- do_filp_open) ret=0xfffffffffffffffe ret_name=(fault)
<...>-7629  [006] d... 92891.052508: t2: (do_sys_openat2+0x201/0x290 <- do_filp_open) ret=0xffff9c04e8bca700 ret_name="locale.alias"
<...>-7629  [006] d... 92891.052544: t2: (do_sys_openat2+0x201/0x290 <- do_filp_open) ret=0xfffffffffffffffe ret_name=(fault)
<...>-7629  [006] d... 92891.052553: t2: (do_sys_openat2+0x201/0x290 <- do_filp_open) ret=0xfffffffffffffffe ret_name=(fault)
<...>-7629  [006] d... 92891.052559: t2: (do_sys_openat2+0x201/0x290 <- do_filp_open) ret=0xffff9c04e8bcb200 ret_name="libc.mo"
<...>-7629  [006] d... 92891.052592: t2: (do_sys_openat2+0x201/0x290 <- do_filp_open) ret=0xffff9c04e8bca000 ret_name="gconv-modules.cache"
trace_open.sh-7627  [005] d... 92891.052716: t2: (do_sys_openat2+0x201/0x290 <- do_filp_open) ret=0xffff9c04e488af00 ret_name="enable"
trace_open.sh-7627  [005] d... 92891.070695: t2: (do_sys_openat2+0x201/0x290 <- do_filp_open) ret=0xffff9c04e488b000 ret_name="enable"
```
可以看出t1只打印了testfile和testfile2，t2全部打印出来了。

## bpftrace
### 查看入参
要查看结构体变量，用下面形式:
```
bpftrace bpftrace.bt
```

bpftrace.bt内容如下：
```
# 需要引入结构体所在的文件件，否则报错
#include <linux/fs.h>
  
k:do_filp_open {printf("dfd=%d, name=%s\n", arg0, str(((struct filename *)arg1)->name));}
```
打印如下：
```
dfd=-100, name=/usr/bin/cat
dfd=-100, name=/lib/ld-linux-aarch64.so.1
dfd=-100, name=/etc/ld.so.cache
dfd=-100, name=/usr/lib64/libc.so.6
dfd=-100, name=/usr/lib/locale/locale-archive
dfd=-100, name=cve_2022_0494.c
dfd=-100, name=/proc/interrupts
dfd=-100, name=/proc/stat

-100就是AT_FDCWD(FFFFFFFFFFFFFF9C)
```

### 查看返回值
```
bpftrace -e 'kr:do_filp_open { printf("ret=0x%x\n", retval);}'
```
打印如下
```
ret=0x907daf00
ret=0x907db540
ret=0x907da640
ret=0x907dadc0
ret=0xfffffffe
ret=0x907dba40
ret=0xfffffffe
ret=0xfffffffe
```
上面的打印里0xfffffffe是文件不存在。

用查看入参里的bt文件形式，也可以看返回值里的文件名称，代码如下：
```
#include <linux/fs.h>
  
k:do_filp_open {printf("dfd=%d, name=%s\n", arg0, str(((struct filename *)arg1)->name));}
kr:do_filp_open { printf("ret=0x%x, name=%s\n", retval, str(((struct file*)retval)->f_path.dentry->d_name.name));}
```

### 查看代码里的返回值
暂时没有找到方法

### 统计函数执行时间
```sh
#!/bin/bpftrace
kprobe:do_filp_open
{
       @start[tid] = nsecs;
}
kretprobe:do_filp_open
/@start[tid]/
{
       $duration_us = (nsecs - @start[tid]) / 1000;
       @us[pid, comm] = hist($duration_us);
       delete(@start[tid]);
}
```
按 ctrl+c 之后会以直方图显示结果，打印如下：
```
@us: 
[1]                  128 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@             |
[2, 4)               170 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[4, 8)                51 |@@@@@@@@@@@@@@@                                     |
[8, 16)               13 |@@@                                                 |
[16, 32)              10 |@@@                                                 |
[32, 64)               4 |@                                                   |
```

## kprobe-module
如果上面两种方法都不能解决我们的问题，还可以用kprobe模块的方法。这个方法不仅能查看入参，返回值，统计执行时间，还能修改代码的执行流程。下面代码在aarch64上全部验证通过，在x86上只没有验证openat_modify_kprobe2，只要偏移填对，应该可以正常执行。

代码如下：
```c
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
#endif
#ifdef __aarch64__
    dfd = regs->regs[0];
    filename = (struct filename *) regs->regs[1];
#endif

    if (filename)
        trace_printk("%s: dfd=%d, name=%s\n", p->symbol_name, dfd, filename->name);
    else
        trace_printk("Unsupport arch!\n");
}

static struct kprobe kprobe = {
	.symbol_name	= TRACE_SYMBOL,
	.post_handler 	= do_filp_open_kprobe
};

static void path_openat_kprobe(struct kprobe *p, struct pt_regs *regs,
				unsigned long flags)
{
    struct file *filp = NULL;

#ifdef __x86_64__
    filp = (struct file *) regs->ax;
#endif
#ifdef __aarch64__
    filp = (struct file *) regs->regs[0];
#endif


    if (!IS_ERR_OR_NULL(filp)) {
        trace_printk("%s: fp=0x%p, name=%s\n", p->symbol_name, filp, filp->f_path.dentry->d_name.name);
		if (!strcmp(filp->f_path.dentry->d_name.name, "testfile3"))
			regs->regs[0] = 0xfffffffffffffffe;
	} else {
        trace_printk("%s: fp=0x%p\n", p->symbol_name, filp);
	}
}

// 跟踪 do_filp_open 里的第一个 path_openat 的返回值
static struct kprobe openat_kprobe = {
	.symbol_name	= TRACE_SYMBOL,
	.post_handler 	= path_openat_kprobe,

	// 下面的偏移量替换成你自己的
#ifdef __x86_64__
	.offset			= 155 
#endif
#ifdef __aarch64__
	.offset 		= 144
#endif
};

static void path_openat_kprobe2(struct kprobe *p, struct pt_regs *regs,
				unsigned long flags)
{
    struct file *filp = NULL;

#ifdef __x86_64__
    filp = (struct file *) regs->ax;
#endif
#ifdef __aarch64__
    filp = (struct file *) regs->regs[0];
#endif

	// 如果文件名是 testfile3, 则强制修改为文件不存在
    if (!IS_ERR_OR_NULL(filp) && !strcmp(filp->f_path.dentry->d_name.name, "testfile3")) {
		trace_printk("change filp value\n");
		regs->regs[0] = regs->regs[20] = 0xfffffffffffffffe;
	}
}

// 修改 do_filp_open 里的第一个 path_openat 的返回值
static struct kprobe openat_modify_kprobe2 = {
	.symbol_name	= TRACE_SYMBOL,
	.post_handler 	= path_openat_kprobe2,

	// 下面的偏移量替换成你自己的
#ifdef __x86_64__
	.offset			= 155 
#endif
#ifdef __aarch64__
	.offset 		= 140
#endif
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
	struct file *filp = (struct file *) regs_return_value(regs);
	const char *filename = "(fault)";
    // 获取在do_filp_open_kretentry里保存的数据
	struct trace_data *data = (struct trace_data *)ri->data;
	s64 delta;
	ktime_t now;

	now = ktime_get();

	if (!IS_ERR(filp))
		filename = filp->f_path.dentry->d_name.name;
    // 计算执行时间
	delta = ktime_to_ns(ktime_sub(now, data->entry_stamp));
	trace_printk("%s: returned 0x%p, took %lld ns, retname=%s\n", 
                ri->rp->kp.symbol_name, filp, (long long)delta, filename);
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
	if (ret < 0) 
		goto err;

	ret = register_kprobe(&openat_kprobe);
	if (ret < 0)
		goto err1;

    // 注册 kretprobe
	ret = register_kretprobe(&kretprobe);
	if (ret < 0)
		goto err2;

	ret = register_kprobe(&openat_modify_kprobe2);
	if (ret < 0)
		goto err3;
	return 0;
err3:
	register_kretprobe(&kretprobe);
err2:
	unregister_kprobe(&openat_kprobe);
err1:
	unregister_kprobe(&kprobe);
err:
	pr_err("register failed, returned %d\n", ret);
	return -1;
}

static void __exit kprobe_exit(void)
{
	unregister_kprobe(&openat_modify_kprobe2);
	unregister_kretprobe(&kretprobe);
	unregister_kprobe(&openat_kprobe);
	unregister_kprobe(&kprobe);
}

module_init(kprobe_init)
module_exit(kprobe_exit)
MODULE_LICENSE("GPL");
```

打印如下：
```
<...>-3273    [006] d...  1056.741428: do_filp_open_kprobe: do_filp_open: dfd=-100, name=testfile
<...>-3273    [006] d...  1056.741438: path_openat_kprobe: do_filp_open: fp=0x000000000f42a712, name=testfile
<...>-3273    [006] d...  1056.741441: do_filp_open_kretprobe: do_filp_open: returned 0x000000000f42a712, took 13390 ns, retname=testfile

<...>-3274    [006] d...  1059.507605: do_filp_open_kprobe: do_filp_open: dfd=-100, name=testfile2
<...>-3274    [006] d...  1059.507614: path_openat_kprobe: do_filp_open: fp=0xfffffffffffffffe
<...>-3274    [006] d...  1059.507615: do_filp_open_kretprobe: do_filp_open: returned 0xfffffffffffffffe, took 10370 ns, retname=(fault)

<...>-3275    [006] d...  1061.017227: do_filp_open_kprobe: do_filp_open: dfd=-100, name=testfile3
<...>-3275    [006] d...  1061.017237: path_openat_kprobe2: change filp value
<...>-3275    [006] d...  1061.017238: path_openat_kprobe: do_filp_open: fp=0xfffffffffffffffe
<...>-3275    [006] d...  1061.017238: do_filp_open_kretprobe: do_filp_open: returned 0xfffffffffffffffe, took 12680 ns, retname=(fault)

```
在我的机子上，testfile和testfile3是存在的，testfile2不存在，在path_openat_kprobe2修改了testfile3的返回值，在命令行也会提示文件不存在。
