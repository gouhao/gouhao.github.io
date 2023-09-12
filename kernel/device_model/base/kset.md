# kset

## 结构体
```c
struct kset {
	struct list_head list; // 包含在set里的kobject
	spinlock_t list_lock;
	struct kobject kobj; // 自己本身的kobject
	const struct kset_uevent_ops *uevent_ops;
} __randomize_layout;

struct kset_uevent_ops {
	int (* const filter)(struct kset *kset, struct kobject *kobj);
	const char *(* const name)(struct kset *kset, struct kobject *kobj);
	int (* const uevent)(struct kset *kset, struct kobject *kobj,
		      struct kobj_uevent_env *env);
};
```

## kset_init
```c
void kset_init(struct kset *k)
{
	// 初始化kobj
	kobject_init_internal(&k->kobj);
	
	INIT_LIST_HEAD(&k->list);
	spin_lock_init(&k->list_lock);
}
```

## kset_register
```c
int kset_register(struct kset *k)
{
	int err;

	if (!k)
		return -EINVAL;
	// 初始化
	kset_init(k);

	// 这个会在sysfs里创建对应的目录
	err = kobject_add_internal(&k->kobj);
	if (err)
		return err;
	// 用uevent通知，有设备添加
	kobject_uevent(&k->kobj, KOBJ_ADD);
	return 0;
}
```

## kset_unregister
```c
void kset_unregister(struct kset *k)
{
	if (!k)
		return;
	// 从sysfs里删除目录
	kobject_del(&k->kobj);
	// 释放对象
	kobject_put(&k->kobj);
}
```
## kset_find_obj
```c
struct kobject *kset_find_obj(struct kset *kset, const char *name)
{
	struct kobject *k;
	struct kobject *ret = NULL;

	spin_lock(&kset->list_lock);

	// 遍历链表
	list_for_each_entry(k, &kset->list, entry) {
		// k->name && 和目标名称相等
		if (kobject_name(k) && !strcmp(kobject_name(k), name)) {
			// 递增引用
			ret = kobject_get_unless_zero(k);
			break;
		}
	}

	spin_unlock(&kset->list_lock);
	return ret;
}

struct kobject * __must_check kobject_get_unless_zero(struct kobject *kobj)
{
	if (!kobj)
		return NULL;
	// 获取引用, 如果引用是0, 返回 0
	if (!kref_get_unless_zero(&kobj->kref))
		kobj = NULL;
	return kobj;
}
```