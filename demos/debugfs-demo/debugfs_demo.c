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
