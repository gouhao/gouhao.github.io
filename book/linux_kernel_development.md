# Linux内核设计与实现

## 第11章 定时器和时间管理
1. 把秒转为jiffies: seconds * HZ
2. 把jiffies转为秒: jiffies / HZ
3. 获取jiffies_64: get_jiffies_64()
4. 比较时间:time_after/before(jiffies, timeout), time_after/before_eq. before判断jiffies是否在timeout之前, after判断jiffies是否超过了timeout
5. 实际时间:struct timespec xtime
```c
// 写xtime
write_seqlock(&xtime_lock);
/* 更新xtime... */
write_sequnlock(&xtime_lock);

//读xtime
do {
    seq = read_seqbegin(&xtime_lock);
    /* 读xtime */
} while (read_seqretry(&xtime_lock, seq));
```
6. 定时器
```c
struct timer_list {
    struct list_head entry;
    unsigned long expires;
    void (*function)(unsigned long);
    unsigned long data;
    struct tvec_t_base_s *base;
};

// 一般使用方法

struct timer_list my_timer;

// 使用前必须要初始化
init_timer(&my_timer);

my_timer.expires = jiffies + delay; // 超时时的节拍数
my_timer.data = 0;  // 给定时器处理函数传的数据
my_timer.function = my_function; // 定时器到期时的处理函数

add_timer(&my_timer); // 激活定时器

// 修改定时器的时间，如果定时器没有激活，这个函数也会激活它。
// 如果定时器未激活，返回0；否则返回1
mod_timer(&my_timer, jiffies+new_delay);

// 删除定时器
// 如果定时器未激活，返回0；否则返回1
del_timer(&my_timer);

// 在删除定时器的时候，有可能在其他cpu上已经执行了定时器处理程序，
// 使用del_timer_sync(&my_timer)，可以等待其他处理器程序都退出
// 这个函数不能在中断上下文中使用
del_timer_sync(&my_timer);
```

7. 延迟执行
```c
// 方法1: 忙等，这种方法会一直占用cpu，不好！
unsigned long timeout = jiffies + 10;
while (time_before(jiffies, timeout))
    ;

// 方法2: 在等待时允许调度其他任务
while (time_before(jiffies, timeout))
    cond_resched(); // 会调度一个新的程序投入运行
```
8. 短延迟，小于1ms的延迟。void u/n/mdelay(unsigned long msecs);
9. 更好的延迟执行:
```c
set_current_state(TASK_INTERRUPTIBLE);
schedule_timeout(s * HZ);
```
## 第12章　内存管理

### 分配以页为单位的内存
```c
#include <linux/gfp.h>

// 分配页
struct page *alloc_pages(gfp_t gfp_mask, unsigned int order);

// 获取物理页的虚拟地址
void *page_address(struct page *page);

// 直接分配页的逻辑地址
unsigned long __get_free_pages(gfp_t gfp_mask, unsigned int order);

// 只申请一页
struct page *alloc_page(gfp_t gfp_mask);
unsigned long __get_free_page(gfp_t gfp_mask);

// 获取填充为0的页
unsigned long get_zeroed_page(unsigned int gfp_mask);

// 释放页
void __free_pages(struct page *page, unsigned int order);
void free_pages(unsigned long addr, unsigned int order);
void free_page(unsigned long addr);
```

### 分配以字节为单位的内存
```c
#include <linux/slab.h>

// 分配物理地址连续的内存
void *kmalloc(size_t size, gfp_t flags);

/*
flags 可用下面内容:

行为修饰符:
__GFP_WAIT      分配器可以睡眠
__GFP_HIGH      分配器可以访问紧急事件缓冲池
__GFP_IO        分配器可以启动磁盘IO
__GFP_FS        分配器可以启动文件系统IO
__GFP_COLD      分配器应该使用高速缓存中快要淘汰出去的页
__GFP_NOWARN    分配器将不打印失败警告
__GFP_REPEAT    分配器在分配失败时重复进行分配，但是这次分配还存在失败的可能
__GFP_NOFAIL    分配器将无限地重复进行分配，分配不能失败
__GFP_NORETRY   分配器在分配失败时绝不会重新分配
__GFP_NO_GROW   由slab层内部使用
__GFP_COMP      添加混合页元数据，在hugetlb的代码内部使用

区修饰符:
__GFP_DMA       在ZONE_DMA分配
__GFP_DMA32     只在ZONE_DMA32分配
__GFP_HIGHMEM   从ZONE_HIGHMEM或ZONE_NORMAL分配

类型标志(一般都使用类型标志):
GFP_ATOMIC      这个标志用在中断处理程序、下半部、持有自旋锁以及其他不能睡眠的地方
GFP_NOWAIT      与GFP_ATOMIC类似，不同之处在于，调用不会退给紧急内存池。这就增加了内存分配失败的可能性
GFP_NOIO        这种分配可以阻塞，但不会启动磁盘IO。这个标志在不能引发更多磁盘IO时能阻塞IO代码，因为这种场景下可能会导致递规
GFP_NOFS        这种分配在必要时可能阻塞，也可能启动磁盘IO，但是不会启动文件系统操作。这个标志在你不能再启动另一个文件系统的操作时，用在文件系统部分的代码中
GFP_KERNEL      这是一种常规的分配方式，可能会阻塞。这个标志在睡眠安全时用在进程上下文代码中。为了获得调用者所需的内存，内核会尽力而为。这个标志应当是首选标志
GFP_USER        这是一种常规分配方式，可能会阻塞。这个标志用于为用户空间进程分配内存时
GFP_HIGHUSER    这是从ZONE_HIGHMEM进行分配，可能会阻塞。这个标志用于为用户空间进程分配内存
GFP_DMA         这是从ZONE_DMA进行分配。需要获取能供DMA使用的内存的设备驱动程序使用这个标志，通常与以上的某个标志组合在一起使用
*/

void kfree(const void *ptr); // 调用kfree(NULL)是安全的


#include <linux/vmalloc.h>

// 分配虚拟地址连续但物理地址不一定连续的内存
void *vmalloc(unsigned long size);

void vfree(const void *addr);


#include <linux/slab.h>

// 创建一个内存缓存
struct kmem_cache *kmem_cache_create(
                    const char *name,
                    size_t size,
                    size_t align,
                    unsigned long flags,
                    void (*ctor)(void*));

/*
 flags可以为0或为以下数值相或:
SLAB_HWCACHE_ALIGN  这个标志命令slab层把一个slab内的所有对象按高速缓存行对齐
SLAB_POISON         用特殊标志的值(a5a5a5a5)填充slab，有利于对未初始化内存的访问
SLAB_RED_ZONE       在已分配的内存周围插入“红色警界区”以探测缓冲越界
SLAB_PANIC          分配失败时，让内存panic。这个标志要求分配只能成功，如果不能成功内核就不能用了
SLAB_CACHE_DMA      这个标志命令slab层使用可以执行DMA的内存给每个slab分配空间。
*/

// 释放内存缓存
int kmem_cache_destroy(struct kmem_cache *cachep);

// 从内存缓存里申请内存。这个flags与alloc_pages里的flags相同，表示如果申请新页面时所用的标志
void *kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags);

// 释放
void *kmem_cache_free(struct kmem_cache *cachep, void *objp);
```
### 高端内存映射
```c
#include <linux/highmem.h>

// 映射一个给定的page结构到内核地址空间，这个函数高端内存和低端内存都能用，
// 如果是低端内存，则相当于page_address只返回页的虚拟地址;
// 如果页是高端内存，则先建立一个映射，再返回虚拟地址
void *kmap(struct page *page);

void kunmap(struct page *page);

// 当必须创建一个映射，而当前上下文又不能睡眠时
void *kmap_atomic(struct page *page, enum km_type type);
void *kunmap_atomic(void *kvaddr, enum km_type type);
```

### percpu
```c
// 传统使用方法:　定义一个数组然后，然后在访问的时候关闭cpu抢占
unsigned long my_percpu[NR_CPUS];

int cpu = get_cpu(); // 获取当前cpu号，并且禁止内核抢占
my_percpu[cpu]++; // 访问
put_cpu();	// 激活内核抢占

// 新接口
#include <linux/percpu.h>

// 定义一个percpu变量
DEFINE_PER_CPU(type, name);
DECLARE_PER_CPU(type, name);

// 访问
get_cpu_var(name);	//访问变量并禁止内核抢占
put_cpu_var(name);	//开抢占

// 运行时分配percpu
void *alloc_percpu(type);
void *__alloc_percpu(size_t size, size_t align);
void free_percpu(const void *);

```
