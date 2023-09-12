#include <linux/init.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <asm-generic/unistd.h>

static int __init demo_init(void)
{
    printk("dd_init\n");
    
    int i;
	printk("__NR_syscalls=%d\n", __NR_syscalls);
	void *sys_table_addr = (void*)kallsyms_lookup_name("sys_call_table");
	printk("addr0=%lx\n", *((unsigned long *)sys_table_addr + 260));
    for (i = 0; i < __NR_syscalls; i++) {
//	printk("addr=%lx\n", *((unsigned long *)sys_table_addr + i));
	    if (*((unsigned long *)sys_table_addr + i) == 0xffff0000080913d0
	    	|| *((unsigned long *)sys_table_addr + i) == 0xffff0000081293b0)
		    printk("unsupport: %d, addr=%lx\n", i, *((unsigned long *)sys_table_addr + i));
    }
#if 0
    for (i = 0; ; i++) {
	    printk("addr=%lx\n", *(sys_table_addr + i)); 
	    
	    /* uos
	    if (*(sys_table_addr + i) == 0xffff0000080900d8)
		    printk("unsupport: %d\n", i);
		   */
	    if (*(sys_table_addr + i) == 0)
		    break;
	    if (*(sys_table_addr + i) == 0xffff0000080913d0)
		    printk("unsupport: %d\n", i);
    }
	printk("__NR_syscalls=%d\n", __NR_syscalls);
#endif
    return 0;
}

static void __exit demo_exit(void)
{
    printk("dd_exit\n");
}

module_init(demo_init);
module_exit(demo_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("GouHao <gouhao@uniontech.com>");
MODULE_DESCRIPTION("Module demo");
