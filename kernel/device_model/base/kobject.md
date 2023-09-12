# kobject 初始化和释放
源码基于5.10

## struct
```c
struct kobject {
	const char		*name; // 名称
	struct list_head	entry; // 用来链入kset
	struct kobject		*parent; // 父对象
	struct kset		*kset; // 指向集合
	struct kobj_type	*ktype; // 类型描述符 
	struct kernfs_node	*sd; // sysfs目录结点
	struct kref		kref; // 引用计数
#ifdef CONFIG_DEBUG_KOBJECT_RELEASE
	struct delayed_work	release;
#endif
	unsigned int state_initialized:1; // 是否已经初始化
	unsigned int state_in_sysfs:1; // 是否已经在sysfs里生成目录
	unsigned int state_add_uevent_sent:1;
	unsigned int state_remove_uevent_sent:1;
	unsigned int uevent_suppress:1;
};

struct kobj_type {
	void (*release)(struct kobject *kobj); // kobject释放时执行
	const struct sysfs_ops *sysfs_ops; // 属性操作函数
	struct attribute **default_attrs; // 属性表
	const struct attribute_group **default_groups; // 属性组

	const struct kobj_ns_type_operations *(*child_ns_type)(struct kobject *kobj);
	const void *(*namespace)(struct kobject *kobj);
	void (*get_ownership)(struct kobject *kobj, kuid_t *uid, kgid_t *gid);
};

```
## kobject_init
```c
void kobject_init(struct kobject *kobj, struct kobj_type *ktype)
{
	char *err_str;

	if (!kobj) {
		err_str = "invalid kobject pointer!";
		goto error;
	}
	if (!ktype) {
		err_str = "must have a ktype to be initialized properly!\n";
		goto error;
	}

	// 已经初始化过了
	if (kobj->state_initialized) {
		/* do not error out as sometimes we can recover */
		pr_err("kobject (%p): tried to init an initialized object, something is seriously wrong.\n",
		       kobj);
		dump_stack();
	}

	kobject_init_internal(kobj);
	// 设置类型
	kobj->ktype = ktype;
	return;

error:
	pr_err("kobject (%p): %s\n", kobj, err_str);
	dump_stack();
}

static void kobject_init_internal(struct kobject *kobj)
{
	if (!kobj)
		return;
	kref_init(&kobj->kref);
	INIT_LIST_HEAD(&kobj->entry);
	// 在sysfs里
	kobj->state_in_sysfs = 0;
	// uevent状态
	kobj->state_add_uevent_sent = 0;
	kobj->state_remove_uevent_sent = 0;
	// 设置已初始化状态
	kobj->state_initialized = 1;
}
```

## kobject_add
```c
int kobject_add(struct kobject *kobj, struct kobject *parent,
		const char *fmt, ...)
{
	va_list args;
	int retval;

	if (!kobj)
		return -EINVAL;

	// 没有初始化
	if (!kobj->state_initialized) {
		pr_err("kobject '%s' (%p): tried to add an uninitialized object, something is seriously wrong.\n",
		       kobject_name(kobj), kobj);
		dump_stack();
		return -EINVAL;
	}
	va_start(args, fmt);
	// 添加
	retval = kobject_add_varg(kobj, parent, fmt, args);
	va_end(args);

	return retval;
}

static __printf(3, 0) int kobject_add_varg(struct kobject *kobj,
					   struct kobject *parent,
					   const char *fmt, va_list vargs)
{
	int retval;

	// 解析名字
	retval = kobject_set_name_vargs(kobj, fmt, vargs);
	if (retval) {
		pr_err("kobject: can not set name properly!\n");
		return retval;
	}
	// 设置父指针
	kobj->parent = parent;

	// 添加
	return kobject_add_internal(kobj);
}

int kobject_set_name_vargs(struct kobject *kobj, const char *fmt,
				  va_list vargs)
{
	const char *s;

	// 名字已经设置并且没有格式化字符串
	if (kobj->name && !fmt)
		return 0;

	// 获取格式化之后的字符串
	s = kvasprintf_const(GFP_KERNEL, fmt, vargs);
	if (!s)
		return -ENOMEM;

	// 如果字符串里有'/'就替换成!
	if (strchr(s, '/')) {
		char *t;
		t = kstrdup(s, GFP_KERNEL);
		kfree_const(s);
		if (!t)
			return -ENOMEM;
		strreplace(t, '/', '!');
		s = t;
	}
	// 释放原来的名字
	kfree_const(kobj->name);
	// 设置新名字
	kobj->name = s;

	return 0;
}

static int kobject_add_internal(struct kobject *kobj)
{
	int error = 0;
	struct kobject *parent;

	if (!kobj)
		return -ENOENT;

	// 必须要有名字
	if (!kobj->name || !kobj->name[0]) {
		WARN(1,
		     "kobject: (%p): attempted to be registered with empty name!\n",
		     kobj);
		return -EINVAL;
	}

	// 增加父对象引用计数
	parent = kobject_get(kobj->parent);

	// 先加到kset里
	if (kobj->kset) {
		// 如果没有父结点，就把kset当作父结点
		if (!parent)
			parent = kobject_get(&kobj->kset->kobj);
		// 把kobj->entry加到kset->list里
		kobj_kset_join(kobj);
		kobj->parent = parent;
	}

	pr_debug("kobject: '%s' (%p): %s: parent: '%s', set: '%s'\n",
		 kobject_name(kobj), kobj, __func__,
		 parent ? kobject_name(parent) : "<NULL>",
		 kobj->kset ? kobject_name(&kobj->kset->kobj) : "<NULL>");

	// 创建目录，每一个kobject都是一个目录
	error = create_dir(kobj);
	if (error) {
		// 处理创建目录失败

		// 先从kset里解链
		kobj_kset_leave(kobj);
		// 释放父引用
		kobject_put(parent);
		kobj->parent = NULL;

		/* be noisy on error issues */
		if (error == -EEXIST)
			pr_err("%s failed for %s with -EEXIST, don't try to register things with the same name in the same directory.\n",
			       __func__, kobject_name(kobj));
		else
			pr_err("%s failed for %s (error: %d parent: %s)\n",
			       __func__, kobject_name(kobj), error,
			       parent ? kobject_name(parent) : "'none'");
	} else
		// 创建成功
		kobj->state_in_sysfs = 1;

	return error;
}

struct kobject *kobject_get(struct kobject *kobj)
{
	if (kobj) {
		// 如果没有初始化，则报警
		if (!kobj->state_initialized)
			WARN(1, KERN_WARNING
				"kobject: '%s' (%p): is not initialized, yet kobject_get() is being called.\n",
			     // 没初始化的时候name不是为空吗？打印这有什么意义
			     kobject_name(kobj), kobj);
		// 递增引用
		kref_get(&kobj->kref);
	}
	// 返回原对象
	return kobj;
}

static void kobj_kset_join(struct kobject *kobj)
{
	if (!kobj->kset)
		return;

	// 先递增kset的引用计数，其实是递增的kset->kobj的
	kset_get(kobj->kset);
	// 给ket加锁
	spin_lock(&kobj->kset->list_lock);
	// 添加到列表
	list_add_tail(&kobj->entry, &kobj->kset->list);
	spin_unlock(&kobj->kset->list_lock);
}

static void kobj_kset_leave(struct kobject *kobj)
{
	if (!kobj->kset)
		return;

	spin_lock(&kobj->kset->list_lock);
	// kobj解链
	list_del_init(&kobj->entry);
	spin_unlock(&kobj->kset->list_lock);
	// 递减kset引用
	kset_put(kobj->kset);
}
```

## create_dir
```c
static int create_dir(struct kobject *kobj)
{
	const struct kobj_type *ktype = get_ktype(kobj);
	const struct kobj_ns_type_operations *ops;
	int error;

	// 在sysfs里创建目录
	error = sysfs_create_dir_ns(kobj, kobject_namespace(kobj));
	if (error)
		return error;

	// 给目录里创建default_attrs属性
	error = populate_dir(kobj);
	if (error) {
		sysfs_remove_dir(kobj);
		return error;
	}

	// 给目录里创建默认default_groups属性
	if (ktype) {
		error = sysfs_create_groups(kobj, ktype->default_groups);
		if (error) {
			sysfs_remove_dir(kobj);
			return error;
		}
	}

	// 增加sd的引用
	sysfs_get(kobj->sd);

	// 如果有子类型，就初始化它
	ops = kobj_child_ns_ops(kobj);
	if (ops) {
		BUG_ON(ops->type <= KOBJ_NS_TYPE_NONE);
		BUG_ON(ops->type >= KOBJ_NS_TYPES);
		BUG_ON(!kobj_ns_type_registered(ops->type));

		sysfs_enable_ns(kobj->sd);
	}

	return 0;
}

int sysfs_create_groups(struct kobject *kobj,
			const struct attribute_group **groups)
{
	return internal_create_groups(kobj, 0, groups);
}

static int internal_create_groups(struct kobject *kobj, int update,
				  const struct attribute_group **groups)
{
	int error = 0;
	int i;

	if (!groups)
		return 0;

	// 遍历属性组，并创建之
	for (i = 0; groups[i]; i++) {
		// 创建一个属性
		error = internal_create_group(kobj, update, groups[i]);
		// 如果创建失败则回退一组属性
		if (error) {
			while (--i >= 0)
				sysfs_remove_group(kobj, groups[i]);
			break;
		}
	}
	return error;
}

static int internal_create_group(struct kobject *kobj, int update,
				 const struct attribute_group *grp)
{
	struct kernfs_node *kn;
	kuid_t uid;
	kgid_t gid;
	int error;

	if (WARN_ON(!kobj || (!update && !kobj->sd)))
		return -EINVAL;

	// 更新时，需要已经初始化
	if (unlikely(update && !kobj->sd))
		return -EINVAL;
	// grp里没有属性也没有二进制属性
	if (!grp->attrs && !grp->bin_attrs) {
		WARN(1, "sysfs: (bin_)attrs not set by subsystem for group: %s/%s\n",
			kobj->name, grp->name ?: "");
		return -EINVAL;
	}
	// 获取uid, gid
	kobject_get_ownership(kobj, &uid, &gid);
	if (grp->name) {
		if (update) {
			// 如果是更新，先找到名称对应的kn
			kn = kernfs_find_and_get(kobj->sd, grp->name);
			if (!kn) {
				pr_warn("Can't update unknown attr grp name: %s/%s\n",
					kobj->name, grp->name);
				return -EINVAL;
			}
		} else {
			// 否则创建一个组目录
			kn = kernfs_create_dir_ns(kobj->sd, grp->name,
						  S_IRWXU | S_IRUGO | S_IXUGO,
						  uid, gid, kobj, NULL);
			if (IS_ERR(kn)) {
				if (PTR_ERR(kn) == -EEXIST)
					sysfs_warn_dup(kobj->sd, grp->name);
				return PTR_ERR(kn);
			}
		}
	} else
		// 如果没有名称，则获取sd
		kn = kobj->sd;
	// 先增加引用，后面再释放
	kernfs_get(kn);
	// 创建组内的文件
	error = create_files(kn, kobj, uid, gid, grp, update);
	if (error) {
		if (grp->name)
			kernfs_remove(kn);
	}
	kernfs_put(kn);

	// 如果是update需要再释放一次，因为上面又get了一次
	if (grp->name && update)
		kernfs_put(kn);

	return error;
}

static int create_files(struct kernfs_node *parent, struct kobject *kobj,
			kuid_t uid, kgid_t gid,
			const struct attribute_group *grp, int update)
{
	struct attribute *const *attr;
	struct bin_attribute *const *bin_attr;
	int error = 0, i;

	// 创建普通属性
	if (grp->attrs) {
		for (i = 0, attr = grp->attrs; *attr && !error; i++, attr++) {
			umode_t mode = (*attr)->mode;

			// 如果是更新，先删除属性
			if (update)
				kernfs_remove_by_name(parent, (*attr)->name);
			
			// 组可见
			if (grp->is_visible) {
				// 如果该属性不可见，则不用创建？
				mode = grp->is_visible(kobj, *attr, i);
				if (!mode)
					continue;
			}

			WARN(mode & ~(SYSFS_PREALLOC | 0664),
			     "Attribute %s: Invalid permissions 0%o\n",
			     (*attr)->name, mode);

			mode &= SYSFS_PREALLOC | 0664;
			// 创建一个属性文件
			error = sysfs_add_file_mode_ns(parent, *attr, false,
						       mode, uid, gid, NULL);
			if (unlikely(error))
				break;
		}
		if (error) {
			remove_files(parent, grp);
			goto exit;
		}
	}

	// 创建二进制文件和上面的普通文件流程大概相同
	if (grp->bin_attrs) {
		for (i = 0, bin_attr = grp->bin_attrs; *bin_attr; i++, bin_attr++) {
			umode_t mode = (*bin_attr)->attr.mode;

			if (update)
				kernfs_remove_by_name(parent,
						(*bin_attr)->attr.name);
			if (grp->is_bin_visible) {
				mode = grp->is_bin_visible(kobj, *bin_attr, i);
				if (!mode)
					continue;
			}

			WARN(mode & ~(SYSFS_PREALLOC | 0664),
			     "Attribute %s: Invalid permissions 0%o\n",
			     (*bin_attr)->attr.name, mode);

			mode &= SYSFS_PREALLOC | 0664;
			error = sysfs_add_file_mode_ns(parent,
					&(*bin_attr)->attr, true,
					mode,
					uid, gid, NULL);
			if (error)
				break;
		}
		if (error)
			remove_files(parent, grp);
	}
exit:
	return error;
}


static int populate_dir(struct kobject *kobj)
{
	struct kobj_type *t = get_ktype(kobj);
	struct attribute *attr;
	int error = 0;
	int i;

	if (t && t->default_attrs) {
		// 遍历属性数组
		for (i = 0; (attr = t->default_attrs[i]) != NULL; i++) {
			// 创建对应的文件
			error = sysfs_create_file(kobj, attr);
			if (error)
				break;
		}
	}
	return error;
}

static inline int __must_check sysfs_create_file(struct kobject *kobj,
						 const struct attribute *attr)
{
	return sysfs_create_file_ns(kobj, attr, NULL);
}

int sysfs_create_file_ns(struct kobject *kobj, const struct attribute *attr,
			 const void *ns)
{
	kuid_t uid;
	kgid_t gid;

	if (WARN_ON(!kobj || !kobj->sd || !attr))
		return -EINVAL;

	// 获取uid, gid
	kobject_get_ownership(kobj, &uid, &gid);
	// 创建文件结点，并添加到父目录
	return sysfs_add_file_mode_ns(kobj->sd, attr, false, attr->mode,
				      uid, gid, ns);
}

int sysfs_add_file_mode_ns(struct kernfs_node *parent,
			   const struct attribute *attr, bool is_bin,
			   umode_t mode, kuid_t uid, kgid_t gid, const void *ns)
{
	struct lock_class_key *key = NULL;
	const struct kernfs_ops *ops;
	struct kernfs_node *kn;
	loff_t size;

	// 区分是否是二进制
	if (!is_bin) {
		struct kobject *kobj = parent->priv;
		const struct sysfs_ops *sysfs_ops = kobj->ktype->sysfs_ops;

		// 每个属性都需要ops,没有则报错
		if (WARN(!sysfs_ops, KERN_ERR
			 "missing sysfs attribute operations for kobject: %s\n",
			 kobject_name(kobj)))
			return -EINVAL;

		// 根据是否有读写函数，决定不同的读函数
		if (sysfs_ops->show && sysfs_ops->store) {
			if (mode & SYSFS_PREALLOC)
				ops = &sysfs_prealloc_kfops_rw;
			else
				ops = &sysfs_file_kfops_rw;
		} else if (sysfs_ops->show) {
			if (mode & SYSFS_PREALLOC)
				ops = &sysfs_prealloc_kfops_ro;
			else
				ops = &sysfs_file_kfops_ro;
		} else if (sysfs_ops->store) {
			if (mode & SYSFS_PREALLOC)
				ops = &sysfs_prealloc_kfops_wo;
			else
				ops = &sysfs_file_kfops_wo;
		} else
			ops = &sysfs_file_kfops_empty;

		// 文件大小？
		size = PAGE_SIZE;
	} else {
		struct bin_attribute *battr = (void *)attr;

		if (battr->mmap)
			ops = &sysfs_bin_kfops_mmap;
		else if (battr->read && battr->write)
			ops = &sysfs_bin_kfops_rw;
		else if (battr->read)
			ops = &sysfs_bin_kfops_ro;
		else if (battr->write)
			ops = &sysfs_bin_kfops_wo;
		else
			ops = &sysfs_file_kfops_empty;

		// 二进制的大小，是自定义的大小
		size = battr->size;
	}

#ifdef CONFIG_DEBUG_LOCK_ALLOC
	if (!attr->ignore_lockdep)
		key = attr->key ?: (struct lock_class_key *)&attr->skey;
#endif

	// 创建文件
	kn = __kernfs_create_file(parent, attr->name, mode & 0777, uid, gid,
				  size, ops, (void *)attr, ns, key);
	if (IS_ERR(kn)) {
		if (PTR_ERR(kn) == -EEXIST)
			sysfs_warn_dup(parent, attr->name);
		return PTR_ERR(kn);
	}
	return 0;
}

```

## kobject_del
```c
void kobject_del(struct kobject *kobj)
{
	struct kobject *parent;

	if (!kobj)
		return;

	parent = kobj->parent;
	__kobject_del(kobj);
	// 减少父目录的引用
	kobject_put(parent);
}

static void __kobject_del(struct kobject *kobj)
{
	struct kernfs_node *sd;
	const struct kobj_type *ktype;

	// sys目录结点
	sd = kobj->sd;
	// 类型节点
	ktype = get_ktype(kobj);

	// 删除默认组属性
	if (ktype)
		sysfs_remove_groups(kobj, ktype->default_groups);

	// 如果有添加事件没有移除事件，还是会发送移除事件？todo:?
	if (kobj->state_add_uevent_sent && !kobj->state_remove_uevent_sent) {
		pr_debug("kobject: '%s' (%p): auto cleanup 'remove' event\n",
			 kobject_name(kobj), kobj);
		kobject_uevent(kobj, KOBJ_REMOVE);
	}

	// 删除目录
	sysfs_remove_dir(kobj);
	// 释放sd
	sysfs_put(sd);

	// 不在sysfs里了
	kobj->state_in_sysfs = 0;

	// 从kset里解链
	kobj_kset_leave(kobj);
	kobj->parent = NULL;
}


```

## kobject_get_path
```c
char *kobject_get_path(struct kobject *kobj, gfp_t gfp_mask)
{
	char *path;
	int len;

	// 路径长度
	len = get_kobj_path_length(kobj);
	if (len == 0)
		return NULL;
	path = kzalloc(len, gfp_mask);
	if (!path)
		return NULL;
	// 填充路径
	fill_kobj_path(kobj, path, len);

	return path;
}

static int get_kobj_path_length(struct kobject *kobj)
{
	int length = 1;
	struct kobject *parent = kobj;

	
	 // 遍历祖先,直接指向根结点
	do {
		// kobject_name=kobj->name

		// 有一个结点为NULL, 就返回 0
		if (kobject_name(parent) == NULL)
			return 0;
		// +1 是因为每个结点都有个 '/' 
		length += strlen(kobject_name(parent)) + 1;
		parent = parent->parent;
	} while (parent);
	return length;
}

static void fill_kobj_path(struct kobject *kobj, char *path, int length)
{
	struct kobject *parent;

	// 先减1, 因为下标从0开始
	--length;
	for (parent = kobj; parent; parent = parent->parent) {
		// 名称长度
		int cur = strlen(kobject_name(parent));
		// 名字的起点
		length -= cur;
		// 复制名字
		memcpy(path + length, kobject_name(parent), cur);
		// 在名字前加分割符
		*(path + --length) = '/';
	}

	pr_debug("kobject: '%s' (%p): %s: path = '%s'\n", kobject_name(kobj),
		 kobj, __func__, path);
}
```

## kobject_init_and_add
```c
int kobject_init_and_add(struct kobject *kobj, struct kobj_type *ktype,
			 struct kobject *parent, const char *fmt, ...)
{
	va_list args;
	int retval;

	// 初始化kobj
	kobject_init(kobj, ktype);

	va_start(args, fmt);
	// 把kobj添加到parent及sysfs里
	retval = kobject_add_varg(kobj, parent, fmt, args);
	va_end(args);

	return retval;
}
```