# sysfs操作

## sysfs_create_dir_ns
```c
int sysfs_create_dir_ns(struct kobject *kobj, const void *ns)
{
	struct kernfs_node *parent, *kn;
	kuid_t uid;
	kgid_t gid;

	if (WARN_ON(!kobj))
		return -EINVAL;

	// 有parent就用，没有就用sysfs的根目录
	if (kobj->parent)
		parent = kobj->parent->sd;
	else
		parent = sysfs_root_kn;

	// 必须得有父结点
	if (!parent)
		return -ENOENT;

	// 获取uid, gid
	kobject_get_ownership(kobj, &uid, &gid);

	// 创建目录，默认权限为741
	kn = kernfs_create_dir_ns(parent, kobject_name(kobj),
				  S_IRWXU | S_IRUGO | S_IXUGO, uid, gid,
				  kobj, ns);
	// 创建失败
	if (IS_ERR(kn)) {
		// 已存在
		if (PTR_ERR(kn) == -EEXIST)
			sysfs_warn_dup(parent, kobject_name(kobj));
		return PTR_ERR(kn);
	}

	// 设置创建的文件结点
	kobj->sd = kn;
	return 0;
}

void kobject_get_ownership(struct kobject *kobj, kuid_t *uid, kgid_t *gid)
{
	// 先把uid和gid设成根目录的
	*uid = GLOBAL_ROOT_UID;
	*gid = GLOBAL_ROOT_GID;

	// 然后调用类型对象具体的方法
	if (kobj->ktype->get_ownership)
		kobj->ktype->get_ownership(kobj, uid, gid);
}
```

## sysfs_remove_groups
```c
void sysfs_remove_groups(struct kobject *kobj,
			 const struct attribute_group **groups)
{
	int i;

	if (!groups)
		return;
	for (i = 0; groups[i]; i++)
		sysfs_remove_group(kobj, groups[i]);
}

void sysfs_remove_group(struct kobject *kobj,
			const struct attribute_group *grp)
{
	struct kernfs_node *parent = kobj->sd;
	struct kernfs_node *kn;

	if (grp->name) {
		// 有名字就先找到kn
		kn = kernfs_find_and_get(parent, grp->name);
		if (!kn) {
			WARN(!kn, KERN_WARNING
			     "sysfs group '%s' not found for kobject '%s'\n",
			     grp->name, kobject_name(kobj));
			return;
		}
	} else {
		// 没有名字就用父目录
		kn = parent;
		kernfs_get(kn);
	}

	remove_files(kn, grp);

	// 如果有自己的kn，则删除之
	if (grp->name)
		kernfs_remove(kn);

	// 减少kn的引用计数，如果为0，则释放
	kernfs_put(kn);
}

static void remove_files(struct kernfs_node *parent,
			 const struct attribute_group *grp)
{
	struct attribute *const *attr;
	struct bin_attribute *const *bin_attr;

	// 删除各属性
	if (grp->attrs)
		for (attr = grp->attrs; *attr; attr++)
			kernfs_remove_by_name(parent, (*attr)->name);
	// 删除各二进制属性
	if (grp->bin_attrs)
		for (bin_attr = grp->bin_attrs; *bin_attr; bin_attr++)
			kernfs_remove_by_name(parent, (*bin_attr)->attr.name);
}
```