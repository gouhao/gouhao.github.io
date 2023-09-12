# 内核调试
本文主要讲解trace, kprobe, debugfs的常用方法。

## 1. Trace
trace接口位于debugfs里，debugfs通常挂载于`/sys/kernel/debug/`. trace路径一般为`/sys/kernel/debug/tracing/`.

### 1.1 常用接口
```sh
1. available_tracers：系统支持的tracer
$ cat available_tracers
hwlat blk function_graph wakeup_dl wakeup_rt wakeup function nop
常用的有function_graph、function、nop

function_graph的输出：
```log
# tracer: function_graph
#
# CPU  DURATION                  FUNCTION CALLS
# |     |   |                     |   |   |   |
 2) + 13.879 us   |  erofs_mount [erofs]();
 4)               |  erofs_mount [erofs]() {
 4)               |    erofs_fill_super [erofs]() {
 4)   0.143 us    |      erofs_parse_options [erofs]();
 4)               |      erofs_read_superblock [erofs]() {
 4)               |        erofs_read_metabuf [erofs]() {
 4)               |          erofs_bread [erofs]() {
 4)   0.130 us    |            erofs_put_metabuf [erofs]();
 4) ! 360.043 us  |          }
 4) ! 360.621 us  |        }
 4)   0.300 us    |        erofs_scan_devices.isra.25 [erofs]();
 4)   0.268 us    |        erofs_put_metabuf [erofs]();
 4) ! 366.668 us  |      }
 4)               |      erofs_iget [erofs]() {
 4)   0.916 us    |        erofs_alloc_inode [erofs]();
 4)   0.220 us    |        erofs_iget_set_actor [erofs]();
 4)               |        erofs_fill_inode [erofs]() {
 4)               |          erofs_read_metabuf [erofs]() {
 4)               |            erofs_bread [erofs]() {
 4)   0.286 us    |              erofs_put_metabuf [erofs]();
 4)   1.367 us    |            }
 4)   1.606 us    |          }
 4)   0.138 us    |          erofs_put_metabuf [erofs]();
 4)   2.651 us    |        }
 4)   6.056 us    |      }
 4) ! 376.105 us  |    }
 4) ! 389.551 us  |  }

```

function的输出：
```log
# tracer: function
#
# entries-in-buffer/entries-written: 27/27   #P:8
#
#                              _-----=> irqs-off
#                             / _----=> need-resched
#                            | / _---=> hardirq/softirq
#                            || / _--=> preempt-depth
#                            ||| /     delay
#           TASK-PID   CPU#  ||||    TIMESTAMP  FUNCTION
#              | |       |   ||||       |         |
           mount-5848  [004] .... 26619.318579: erofs_mount <-mount_fs
           mount-5848  [004] .... 26619.318868: erofs_fill_super <-mount_bdev
           mount-5848  [004] .... 26619.318869: erofs_parse_options <-erofs_fill_super
           mount-5848  [004] .... 26619.318869: erofs_read_superblock <-erofs_fill_super
           mount-5848  [004] .... 26619.318870: erofs_read_metabuf <-erofs_read_superblock
           mount-5848  [004] .... 26619.318870: erofs_bread <-erofs_read_superblock
           mount-5848  [004] .... 26619.318870: erofs_put_metabuf <-erofs_bread
           mount-5848  [004] .... 26619.318898: erofs_scan_devices.isra.25 <-erofs_read_superblock
           mount-5848  [004] .... 26619.318898: erofs_put_metabuf <-erofs_read_superblock
           mount-5848  [004] .... 26619.318898: erofs_iget <-erofs_fill_super
           mount-5848  [004] .... 26619.318899: erofs_alloc_inode <-alloc_inode
           mount-5848  [004] .... 26619.318900: erofs_iget_set_actor <-inode_insert5
```

available_filter_functions：可以过滤的函数
set_ftrace_filter：设置过滤函数，支持全函数名、支持通配符（xxx*、*xxx、*xxx*）
# 比如：只显示erofs的日志
echo erofs* > set_ftrace_filter

trace：查看trace日志
trace_pipe：同上，只不过这是一个管道，读完后trace-buffer里就没数据了

tracing_on：trace的使能开关

events：这个目录里是所有trace_event的接口

kprobe_events: 添加kprobe的接口，在这里添加一个kprobe，会在events里创建相应的目录
```

### 1.2 events
1. event是在内核代码里特定的位置打印日志，在内核里以`trace_`开头的函数都是event。  
2. 每个event目录树里都有个enable文件，这个文件控制当前event及所有子event使能.
```sh

# 打开所有event
echo 1 > /sys/kernel/debug/tracing/events/enable

# 打开所有系统调用的event
echo 1 > /sys/kernel/debug/tracing/events/syscalls/enable
```


3. 叶子节点的event的接口
```sh
# 3.1 enable: 使能开关。0|1

# 3.2 filter：过滤器。过滤器可以过滤日志，只有过滤器里的条件为真时才打印
$ echo 'name=="testfile" || name=="testfile2"' >> filter #注意：一般都使用追加，可以添加多个

# 没有过滤器时
$ cat filter 
### global filter ###
# Use this to set filters for multiple events.
# Only events with the given fields will be affected.
# If no events are modified, an error message will be displayed here


# 3.3 format：event里的成员及打印的格式，这里面的成员可以用在过滤器/触发器里做条件判断
$ cat format 
name: drm_vblank_event
ID: 1236
format:
	# 这个event里的字段

	# common开头的都是所有event共有的
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

	# 空行隔开的下面的字段，是各个event自定义的
        field:int crtc; offset:8;       size:4; signed:1;
        field:unsigned int seq; offset:12;      size:4; signed:0;

# 打印格式，这里的格式就是最终在trace日志里呈现的格式
print fmt: "crtc=%d, seq=%u", REC->crtc, REC->seq


# 3.4 hist：不知

# 3.5 id：不知

# 3.6 trigger：触发器，当条件为真时可以执行一些命令

# 查看支持的命令
$ cat trigger 
# Available triggers:
# traceon traceoff snapshot stacktrace enable_event disable_event enable_hist disable_hist hist

# 设置触发器
$ echo 'traceon if name=="testfile"' >> trigger #注意：一般都使用追加，可以添加多个触发器

```

## 2. Kprobe
kprobe常用方式有2种：1. trace接口；2. 编写模块。

通过跟踪do_filp_open函数来介绍这2种kprobe的使用，do_filp_open的代码如下：
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

找一下name在struct filename里的偏移：
```sh
$ gdb vmlinux # 直接用gdb调试vmlinux

(gdb) p &(((struct filename *)0)->name)
$1 = (const char **) 0x0 <irq_stack_union> # name的偏移值为0
```

参数在寄存器里存储， x86_64参数寄存器 第1~6的参数: %rdi，%rsi，%rdx，%rcx，%r8，%r9,

### 2.1 trace接口
trace接口是：`/sys/kernel/debug/tracing/kprobe_events`，添加一个kprobe_event时会自动在`events`目录创建一个相关目录。

使用方法参考：Documentation/trace/kprobetrace.rst

常用：
```sh
p[:[GRP/]EVENT] [MOD:]SYM[+offs]|MEMADDR [FETCHARGS]	: Set a probe
p:event 函数名+offset|函数地址 获取的参数列表(空格隔开)

r[MAXACTIVE][:[GRP/]EVENT] [MOD:]SYM[+0] [FETCHARGS]	: Set a return probe
p:event 函数名+offset|函数地址 获取的参数列表(空格隔开)
-:[GRP/]EVENT						: Clear a probe
```
#### 2.1.1 查看入参
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
cat /sys/kernel/debug/tracing/trace_pipe

<...>-7317  [006] .... 88731.883298: t1: (do_filp_open+0x0/0x110) dfd=0xffffff9c name="testfile"
<...>-7317  [006] d... 88731.883304: t2: (do_sys_openat2+0x201/0x290 <- do_filp_open) ret=0xffff9c04e48e0400"
```
可以看到dfd和name的值与我们预期的一样, dfd是0xffffff9c(AT_FDCWD), name是testfile。do_filp_open的返回值是0xffff9c04e48e0400，也就是打开的file对象的指针。

在找到了file之后，struct file->f_path.dentry->d_name.name里也保存了文件名，我们来验证一下，返回值里的文件名就是我们打开的文件名，各结构的偏移如下：
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

#### 2.1.2 查看代码中的返回值
要查看`filp = path_openat(&nd, op, flags | LOOKUP_RCU);`这句代码的返回值.  
首先反汇编vmlinx, 找到path_openat对应的代码,如下:
```asm
ffffffff812ed6c0 <do_filp_open>:
... # 省略代码
ffffffff812ed73a:       00
ffffffff812ed73b:       83 ca 40                or     $0x40,%edx
ffffffff812ed73e:       65 48 8b 04 25 80 b4    mov    %gs:0x1b480,%rax
ffffffff812ed745:       01 00
ffffffff812ed747:       48 89 a0 98 0b 00 00    mov    %rsp,0xb98(%rax)
ffffffff812ed74e:       e8 cd d7 ff ff          callq  ffffffff812eaf20 <path_openat>
ffffffff812ed753:       48 89 c3                mov    %rax,%rbx
ffffffff812ed756:       48 83 f8 f6             cmp    $0xfffffffffffffff6,%rax
ffffffff812ed75a:       74 2c                   je     ffffffff812ed788 <do_filp_open+0xc8>
ffffffff812ed75c:       48 83 fb 8c             cmp    $0xffffffffffffff8c,%rbx
```
从汇编代码可以看出调用是在`ffffffff812ed74e:       e8 cd d7 ff ff          callq  ffffffff812eaf20 <path_openat>`这一行, 我们应该在下一行来跟踪它的返回值，也就是`ffffffff812ed753:       48 89 c3                mov    %rax,%rbx`，fffffffffffffff6(-10)就是 -ECHILD。

首先计算一下要跟踪的代码代码到do_filp_open偏移：  
offset = ffffffff812ed753 - ffffffff812ed6c0 = 93 = 147

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

#### 2.1.3 统计函数执行时间
trace统计函数执行时间，可以把/sys/kernel/debug/tracing/current_tracer设置成function_tracer来观察。

#### 2.1.4 设置过滤器
trace的打印日志非常多，可以设置过滤器，只打印我们想要的东西。trace的过滤器是filter文件，可以在里面用 && || ! == > < 等这些符号，只有filter里的条件为真时，才会执行打印。  
我们脚本中增加t1的过滤器，t1只显示文件名为testfile和testfile2的，脚本如下：
```sh
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


### 2.2 kprobe-module
如果上面两种方法都不能解决我们的问题，还可以用kprobe模块的方法。这个方法不仅能查看入参，返回值，统计执行时间，还能修改代码的执行流程。

下面示例演示打开一个存在的文件，修改do_filp_open里寄存器的值，让系统调用出错返回。

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
		if (!strcmp(filp->f_path.dentry->d_name.name, "testfile3")) {
        		trace_printk("change flip value\n");
#ifdef __aarch64__
			regs->regs[0] = 0xfffffffffffffffe;
#endif
#ifdef __x86_64__
			regs->ax = regs->bx = 0xfffffffffffffff6;
#endif
		}
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
	.offset			= 167
#endif
#ifdef __aarch64__
	.offset 		= 144
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
	ret = register_kprobe(&kprobe);
	if (ret < 0) 
		goto err;
	ret = register_kprobe(&openat_kprobe);
	if (ret < 0)
		goto err1;
	ret = register_kretprobe(&kretprobe);
	if (ret < 0)
		goto err2;

	return 0;
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
$ cat testfile3 
cat: testfile3: No child processes

cat-3993  [001] ....   331.459874: do_filp_open_kprobe: do_filp_open: dfd=-100, name=testfile3
cat-3993  [001] d.Z.   331.459885: path_openat_kprobe: do_filp_open: fp=0x00000000b7c6a70e, name=testfile3
cat-3993  [001] d.Z.   331.459888: path_openat_kprobe: change flip value
cat-3993  [001] d...   331.459891: do_filp_open_kretprobe: do_filp_open: returned 0x000000003df10703, took 17271 ns, retname=(fault)


```
在我的机子上，testfile和testfile3是存在的，testfile2不存在，在path_openat_kprobe2修改了testfile3的返回值，在命令行也会提示文件不存在。

## 3. 其他
### 3.1 debugfs
可以使用include/linux/debugfs.h里的`debugfs_create_xxx`接口来在debugfs里创建接口文件，与内核进行通信。比如：可以使用`debugfs_create_bool`创建一些控制开关，然后在代码里使用这些开关，通过控制这些开关的使能来动态控制调试功能。

debugfs_demo

readme
```txt
简介：
    本demo支持6个调试开关。dd_f1~dd_f6

集成到内核:
1.把debugfs_demo.h放到include/linux目录下
2.debusfs_demo.c 随便放到哪，只要编进内核就行
3.在想要用开关的代码中#include <linux/debugfs_demo.h>，就可以用开关
```

debugfs_demo.c
```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/debugfs.h>

#include <linux/debugfs_demo.h>
//#include "debugfs_demo.h"

struct dentry * dd_dir_root;

#define DD_FLAG_COUNT 6

struct dd_value{
    char *name;
    bool *value;
};

#define DEF_FLAG(name) \
    bool dd_##name = false; \
    EXPORT_SYMBOL(dd_##name)

DEF_FLAG(f1);
DEF_FLAG(f2);
DEF_FLAG(f3);
DEF_FLAG(f4);
DEF_FLAG(f5);
DEF_FLAG(f6);

#define DEF_DD_OBJ(name) {"dd_"#name, &dd_##name}

struct dd_value sdv[DD_FLAG_COUNT] = {
    DEF_DD_OBJ(f1), DEF_DD_OBJ(f2),
    DEF_DD_OBJ(f3), DEF_DD_OBJ(f4),
    DEF_DD_OBJ(f5), DEF_DD_OBJ(f6)
};

static int __init dd_init(void)
{
    int i;

    printk("dd_init\n");

    dd_dir_root = debugfs_create_dir("debugfs-demo", NULL);
    if (!dd_dir_root)
        return -ENODEV;

    for (i = 0; i < DD_FLAG_COUNT; i++)     
        if (!debugfs_create_bool(sdv[i].name, 
                0644, dd_dir_root, sdv[i].value)) {
            debugfs_remove(dd_dir_root);
            return -ENODEV;
        }
    
    return 0;
}

static void __exit dd_exit(void)
{
    printk("dd_exit\n");
    if (dd_dir_root)
        debugfs_remove_recursive(dd_dir_root);
}

module_init(dd_init);
module_exit(dd_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("GouHao <gouhao@uniontech.com>");
MODULE_DESCRIPTION("Debug fs demo");
```

debugfs_demo.h
```h
#ifndef DEBUGFS_DEMO_H
#define DEBUGFS_DEMO_H

#define EXT_DEF_FLAG(name) extern bool dd_##name

EXT_DEF_FLAG(f1);
EXT_DEF_FLAG(f2);
EXT_DEF_FLAG(f3);
EXT_DEF_FLAG(f4);
EXT_DEF_FLAG(f5);
EXT_DEF_FLAG(f6);

#endif
```