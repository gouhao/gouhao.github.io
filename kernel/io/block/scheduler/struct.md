源码基于5.10

```c
struct elevator_queue {
	struct elevator_type *type; // 调度器函数表
	void *elevator_data; // 调度器私有数据
	struct kobject kobj; // 设备模型对象
	struct mutex sysfs_lock;
	unsigned int registered:1; // 是否已注册
	DECLARE_HASHTABLE(hash, ELV_HASH_BITS); // 哈希表, ELV_HASH_BITS=6
};

struct elevator_type {
	/* managed by elevator core */
	struct kmem_cache *icq_cache;

	// 函数表
	struct elevator_mq_ops ops;

	size_t icq_size;	/* see iocontext.h */
	size_t icq_align;	/* ditto */
	struct elv_fs_entry *elevator_attrs; // 调度器的属性
	const char *elevator_name; // 名称
	const char *elevator_alias; // 别名
	const unsigned int elevator_features; // 特征
	struct module *elevator_owner; // 模块
#ifdef CONFIG_BLK_DEBUG_FS
	// 调试相关
	const struct blk_mq_debugfs_attr *queue_debugfs_attrs;
	const struct blk_mq_debugfs_attr *hctx_debugfs_attrs;
#endif

	/* managed by elevator core */
	char icq_cache_name[ELV_NAME_MAX + 6];	/* elvname + "_io_cq" */
	struct list_head list;
};


```