#include <linux/init.h>
#include <linux/module.h>

static int __init demo_init(void)
{
    printk("dd_init\n");
    
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
