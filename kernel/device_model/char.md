# char device

## struct
```c
struct cdev {
	struct kobject kobj; // 内嵌kobj
	struct module *owner; // 驱动模块
	const struct file_operations *ops; // 指向驱动程序的文件操作指针
	struct list_head list; // 与字符设备文件对应的索引结点链表的头
	dev_t dev; // 主次设备号
	unsigned int count; // 驱动分配的设备号范围的大小
} __randomize_layout;

struct kobj_map {
	struct probe {
		struct probe *next; // 散列冲突的下一个元素
		dev_t dev; // 主次设备号
		unsigned long range; // 设备号范围
		struct module *owner; // 如果是模块，则指向模块指针
		kobj_probe_t *get; // 探测谁拥有这个设备号范围
		int (*lock)(dev_t, void *); // 增加设备号范围内拥有者的引用计数器
		void *data; // 私有数据
	} *probes[255];
	struct mutex *lock;
};

static struct char_device_struct {
	struct char_device_struct *next; // 冲突
	unsigned int major; // 主设备号
	unsigned int baseminor; // 次设备号
	int minorct; // 设备号范围
	char name[64];	// 名称
	struct cdev *cdev; // 指向字符设备驱动
} *chrdevs[255];
```

## cdev_alloc
```c
struct cdev *cdev_alloc(void)
{
	struct cdev *p = kzalloc(sizeof(struct cdev), GFP_KERNEL);
	if (p) {
		INIT_LIST_HEAD(&p->list);
		kobject_init(&p->kobj, &ktype_cdev_dynamic);
	}
	return p;
}
```

## cdev_add
```c
int cdev_add(struct cdev *p, dev_t dev, unsigned count)
{
	int error;

	p->dev = dev;
	p->count = count;

	if (WARN_ON(dev == WHITEOUT_DEV))
		return -EBUSY;

	error = kobj_map(cdev_map, dev, count, NULL,
			 exact_match, exact_lock, p);
	if (error)
		return error;

	kobject_get(p->kobj.parent);

	return 0;
}
```

## register_chrdev_region
```c
int register_chrdev_region(dev_t from, unsigned count, const char *name)
{
	struct char_device_struct *cd;
	dev_t to = from + count;
	dev_t n, next;

	for (n = from; n < to; n = next) {
		next = MKDEV(MAJOR(n)+1, 0);
		if (next > to)
			next = to;
		cd = __register_chrdev_region(MAJOR(n), MINOR(n),
			       next - n, name);
		if (IS_ERR(cd))
			goto fail;
	}
	return 0;
fail:
	to = n;
	for (n = from; n < to; n = next) {
		next = MKDEV(MAJOR(n)+1, 0);
		kfree(__unregister_chrdev_region(MAJOR(n), MINOR(n), next - n));
	}
	return PTR_ERR(cd);
}
```

## alloc_chrdev_region
```c
int alloc_chrdev_region(dev_t *dev, unsigned baseminor, unsigned count,
			const char *name)
{
	struct char_device_struct *cd;
	cd = __register_chrdev_region(0, baseminor, count, name);
	if (IS_ERR(cd))
		return PTR_ERR(cd);
	*dev = MKDEV(cd->major, cd->baseminor);
	return 0;
}
```

## register_chrdev
```c
static inline int register_chrdev(unsigned int major, const char *name,
				  const struct file_operations *fops)
{
	return __register_chrdev(major, 0, 256, name, fops);
}
```