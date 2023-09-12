# bus

## 结构体
```c
struct bus_type {
	const char		*name; // 总线名称
	const char		*dev_name; // 设备名称？
	struct device		*dev_root; // 根设备 ？
	const struct attribute_group **bus_groups; // 总线组属性
	const struct attribute_group **dev_groups; // 设备组属性
	const struct attribute_group **drv_groups; // 驱动组属性

	int (*match)(struct device *dev, struct device_driver *drv); // 检验给定驱动程序是否支持该设备
	int (*uevent)(struct device *dev, struct kobj_uevent_env *env);
	int (*probe)(struct device *dev); // 探测是否支持设备
	void (*sync_state)(struct device *dev);
	int (*remove)(struct device *dev); // 移除设备时调用
	void (*shutdown)(struct device *dev); // 断电时调用

	// 设备上下线
	int (*online)(struct device *dev);
	int (*offline)(struct device *dev);

	int (*suspend)(struct device *dev, pm_message_t state); // 使设备处于低功率状态
	int (*resume)(struct device *dev); // 使设备处于正常状态

	int (*num_vf)(struct device *dev);

	int (*dma_configure)(struct device *dev);

	const struct dev_pm_ops *pm;

	const struct iommu_ops *iommu_ops;

	struct subsys_private *p;
	struct lock_class_key lock_key;

	bool need_parent_lock;
};

struct subsys_private {
	struct kset subsys; // 集合对象
	struct kset *devices_kset; // 子设备集合
	struct list_head interfaces; // 接口列表
	struct mutex mutex;

	struct kset *drivers_kset; // 总线上的驱动集合
	struct klist klist_devices;
	struct klist klist_drivers;
	struct blocking_notifier_head bus_notifier; // 通知链
	unsigned int drivers_autoprobe:1; // 自动探测
	struct bus_type *bus; // 对bus的引用

	struct kset glue_dirs;
	struct class *class; // 类
};
```

## bus_register
```c
int bus_register(struct bus_type *bus)
{
	int retval;
	struct subsys_private *priv;
	struct lock_class_key *key = &bus->lock_key;

	// 分配子系统结构
	priv = kzalloc(sizeof(struct subsys_private), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	// 和私有数据相互引用
	priv->bus = bus;
	bus->p = priv;

	// 初始化通知链
	BLOCKING_INIT_NOTIFIER_HEAD(&priv->bus_notifier);

	// 设置子系统kobj名称为总线名称
	retval = kobject_set_name(&priv->subsys.kobj, "%s", bus->name);
	if (retval)
		goto out;

	// 给子系统设置总线集合和总线类型，bus_kset就是/sys/bus
	priv->subsys.kobj.kset = bus_kset;
	priv->subsys.kobj.ktype = &bus_ktype;

	// 自动探测默认为1
	priv->drivers_autoprobe = 1;

	// 注册kset
	retval = kset_register(&priv->subsys);
	if (retval)
		goto out;

	// 创建 uevent 接口文件，手动触发uevent事件 
	retval = bus_create_file(bus, &bus_attr_uevent);
	if (retval)
		goto bus_uevent_fail;

	// 创建设备集合kset，并在sysfs里创建对应的目录
	priv->devices_kset = kset_create_and_add("devices", NULL,
						 &priv->subsys.kobj);
	if (!priv->devices_kset) {
		retval = -ENOMEM;
		goto bus_devices_fail;
	}

	// 创建驱动的kset，并在sysfs里创建对应的目录
	priv->drivers_kset = kset_create_and_add("drivers", NULL,
						 &priv->subsys.kobj);
	if (!priv->drivers_kset) {
		retval = -ENOMEM;
		goto bus_drivers_fail;
	}

	// 初始化一些列表，锁
	INIT_LIST_HEAD(&priv->interfaces);
	__mutex_init(&priv->mutex, "subsys mutex", key);
	klist_init(&priv->klist_devices, klist_devices_get, klist_devices_put);
	klist_init(&priv->klist_drivers, NULL, NULL);

	// 添加探测文件
	retval = add_probe_files(bus);
	if (retval)
		goto bus_probe_files_fail;

	// 添加bus自定义的属性
	retval = bus_add_groups(bus, bus->bus_groups);
	if (retval)
		goto bus_groups_fail;

	pr_debug("bus: '%s': registered\n", bus->name);
	return 0;

bus_groups_fail:
	remove_probe_files(bus);
bus_probe_files_fail:
	kset_unregister(bus->p->drivers_kset);
bus_drivers_fail:
	kset_unregister(bus->p->devices_kset);
bus_devices_fail:
	bus_remove_file(bus, &bus_attr_uevent);
bus_uevent_fail:
	kset_unregister(&bus->p->subsys);
out:
	kfree(bus->p);
	bus->p = NULL;
	return retval;
}

static int add_probe_files(struct bus_type *bus)
{
	int retval;

	// 创建drivers_probe接口文件，这个接口可以通过文件名来手动探测设备
	retval = bus_create_file(bus, &bus_attr_drivers_probe);
	if (retval)
		goto out;

	// 创建drivers_autoprobe接口文件
	retval = bus_create_file(bus, &bus_attr_drivers_autoprobe);
	if (retval)
		bus_remove_file(bus, &bus_attr_drivers_probe);
out:
	return retval;
}
```

## bus_unregister
```c
void bus_unregister(struct bus_type *bus)
{
	pr_debug("bus: '%s': unregistering\n", bus->name);
	// 先注销根设备
	if (bus->dev_root)
		device_unregister(bus->dev_root);
	// 移除bus的属性组
	bus_remove_groups(bus, bus->bus_groups);

	// 删除2个探测属性文件
	remove_probe_files(bus);

	// 注销驱动kset
	kset_unregister(bus->p->drivers_kset);

	// 注销设备kset
	kset_unregister(bus->p->devices_kset);

	// 删除uevent文件
	bus_remove_file(bus, &bus_attr_uevent);

	// 删除子系统
	kset_unregister(&bus->p->subsys);
}
```
## bus_probe_device
```c
void bus_probe_device(struct device *dev)
{
	struct bus_type *bus = dev->bus;
	struct subsys_interface *sif;

	if (!bus)
		return;

	// 自动探测，drivers_autoprobe默认是1，可以通过用户接口来修改
	if (bus->p->drivers_autoprobe)
		device_initial_probe(dev);

	// 调用已注册接口的add_dev
	mutex_lock(&bus->p->mutex);
	list_for_each_entry(sif, &bus->p->interfaces, node)
		if (sif->add_dev)
			sif->add_dev(dev, sif);
	mutex_unlock(&bus->p->mutex);
}

void device_initial_probe(struct device *dev)
{
	__device_attach(dev, true);
}

static int __device_attach(struct device *dev, bool allow_async)
{
	int ret = 0;

	device_lock(dev);
	if (dev->p->dead) {
		// 设备已关机
		goto out_unlock;
	} else if (dev->driver) {
		// dev有驱动
		if (device_is_bound(dev)) {
			ret = 1;
			goto out_unlock;
		}
		ret = device_bind_driver(dev);
		if (ret == 0)
			ret = 1;
		else {
			dev->driver = NULL;
			ret = 0;
		}
	} else {
		// 一般走这个分支，设备没有驱动
		struct device_attach_data data = {
			.dev = dev,
			// 在这里是true
			.check_async = allow_async,
			.want_async = false,
		};

		// 获取父设备引用
		if (dev->parent)
			pm_runtime_get_sync(dev->parent);

		// 在总线的所有驱动程序上调用__device_attach_driver函数
		ret = bus_for_each_drv(dev->bus, NULL, &data,
					__device_attach_driver);
		if (!ret && allow_async && data.have_async) {
			// 走到这里表示探测失败，通过异步再试一次
			dev_dbg(dev, "scheduling asynchronous probe\n");
			get_device(dev);
			async_schedule_dev(__device_attach_async_helper, dev);
		} else {
			// 与驱动绑定成功

			// 先设置为空闲状态
			pm_request_idle(dev);
		}

		// 与上面对应，解除与父设备引用
		if (dev->parent)
			pm_runtime_put(dev->parent);
	}
out_unlock:
	device_unlock(dev);
	return ret;
}
```

## bus_add_device
```c
int bus_add_device(struct device *dev)
{
	struct bus_type *bus = bus_get(dev->bus);
	int error = 0;

	if (bus) {
		pr_debug("bus: '%s': add device %s\n", bus->name, dev_name(dev));

		// 在设备目录创建总线共有的属性
		error = device_add_groups(dev, bus->dev_groups);
		if (error)
			goto out_put;
		// 创建在总线目录创建到设备的链接
		error = sysfs_create_link(&bus->p->devices_kset->kobj,
						&dev->kobj, dev_name(dev));
		if (error)
			goto out_groups;
		// 在设备的目录创建到对应总线的链接
		error = sysfs_create_link(&dev->kobj,
				&dev->bus->p->subsys.kobj, "subsystem");
		if (error)
			goto out_subsys;
		// 把设备加到总线的设备列表
		klist_add_tail(&dev->p->knode_bus, &bus->p->klist_devices);
	}
	return 0;

out_subsys:
	sysfs_remove_link(&bus->p->devices_kset->kobj, dev_name(dev));
out_groups:
	device_remove_groups(dev, bus->dev_groups);
out_put:
	bus_put(dev->bus);
	return error;
}
```

## bus_remove_device
```c
void bus_remove_device(struct device *dev)
{
	struct bus_type *bus = dev->bus;
	struct subsys_interface *sif;

	if (!bus)
		return;

	mutex_lock(&bus->p->mutex);
	// 调用接口的remove_dev接口
	list_for_each_entry(sif, &bus->p->interfaces, node)
		if (sif->remove_dev)
			sif->remove_dev(dev, sif);
	mutex_unlock(&bus->p->mutex);

	// 删除设备设备目录删除总线的链接
	sysfs_remove_link(&dev->kobj, "subsystem");
	// 从总线目录删除设备
	sysfs_remove_link(&dev->bus->p->devices_kset->kobj,
			  dev_name(dev));
	// 从device目录里删除总线的属性
	device_remove_groups(dev, dev->bus->dev_groups);

	// 从bus列表把设备删除
	if (klist_node_attached(&dev->p->knode_bus))
		klist_del(&dev->p->knode_bus);

	pr_debug("bus: '%s': remove device %s\n",
		 dev->bus->name, dev_name(dev));
	// 删除设备的驱动引用
	device_release_driver(dev);
	
	// 减少总线的引用 
	bus_put(dev->bus);
}
```

## bus_add_driver
```c
int bus_add_driver(struct device_driver *drv)
{
	struct bus_type *bus;
	struct driver_private *priv;
	int error = 0;

	// 获取bus引用
	bus = bus_get(drv->bus);
	if (!bus)
		return -EINVAL;

	pr_debug("bus: '%s': add driver %s\n", bus->name, drv->name);

	// 分配驱动的私有数据
	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv) {
		error = -ENOMEM;
		goto out_put_bus;
	}
	klist_init(&priv->klist_devices, NULL, NULL);

	// 驱动与驱动私有数据相互引用
	priv->driver = drv;
	drv->p = priv;

	// 指向总线的驱动集合
	priv->kobj.kset = bus->p->drivers_kset;

	// 在总线的drivers里添加驱动目录
	error = kobject_init_and_add(&priv->kobj, &driver_ktype, NULL,
				     "%s", drv->name);
	if (error)
		goto out_unregister;

	// 将驱动添加到总线的驱动列表
	klist_add_tail(&priv->knode_bus, &bus->p->klist_drivers);

	// 如果总线有自动探测，则遍历总线上的设备，然后用驱动进行探测
	if (drv->bus->p->drivers_autoprobe) {
		error = driver_attach(drv);
		if (error)
			goto out_unregister;
	}
	// 如果是模块，则添加模块相关
	module_add_driver(drv->owner, drv);

	// 创建驱动的uevent接口文件
	error = driver_create_file(drv, &driver_attr_uevent);
	if (error) {
		printk(KERN_ERR "%s: uevent attr (%s) failed\n",
			__func__, drv->name);
	}

	// 给驱动里添加总线共有的属性
	error = driver_add_groups(drv, bus->drv_groups);
	if (error) {
		/* How the hell do we get out of this pickle? Give up */
		printk(KERN_ERR "%s: driver_create_groups(%s) failed\n",
			__func__, drv->name);
	}

	// 如果没有禁用bind，则创建bind文件
	if (!drv->suppress_bind_attrs) {
		error = add_bind_files(drv);
		if (error) {
			/* Ditto */
			printk(KERN_ERR "%s: add_bind_files(%s) failed\n",
				__func__, drv->name);
		}
	}

	return 0;

out_unregister:
	kobject_put(&priv->kobj);
	/* drv->p is freed in driver_release()  */
	drv->p = NULL;
out_put_bus:
	bus_put(bus);
	return error;
}
```

## bus_add_driver
```c
int bus_add_driver(struct device_driver *drv)
{
	struct bus_type *bus;
	struct driver_private *priv;
	int error = 0;

	// 获取引用
	bus = bus_get(drv->bus);
	if (!bus)
		return -EINVAL;

	pr_debug("bus: '%s': add driver %s\n", bus->name, drv->name);

	// 分配私有数据
	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv) {
		error = -ENOMEM;
		goto out_put_bus;
	}
	klist_init(&priv->klist_devices, NULL, NULL);
	priv->driver = drv;
	drv->p = priv;
	// 私有数据和bus使用同一个driver_kset
	priv->kobj.kset = bus->p->drivers_kset;
	error = kobject_init_and_add(&priv->kobj, &driver_ktype, NULL,
				     "%s", drv->name);
	if (error)
		goto out_unregister;
	// 添加到总结的驱动列表
	klist_add_tail(&priv->knode_bus, &bus->p->klist_drivers);
	// 自动探测
	if (drv->bus->p->drivers_autoprobe) {
		// 匹配设备
		error = driver_attach(drv);
		if (error)
			goto out_unregister;
	}

	// 如果是模块, 在sysfs里创建 module
	module_add_driver(drv->owner, drv);

	// 创建uevent文件
	error = driver_create_file(drv, &driver_attr_uevent);
	if (error) {
		printk(KERN_ERR "%s: uevent attr (%s) failed\n",
			__func__, drv->name);
	}
	// 创建组属性
	error = driver_add_groups(drv, bus->drv_groups);
	if (error) {
		/* How the hell do we get out of this pickle? Give up */
		printk(KERN_ERR "%s: driver_create_groups(%s) failed\n",
			__func__, drv->name);
	}

	// 如果没有禁止绑定接口,则创建之
	if (!drv->suppress_bind_attrs) {
		error = add_bind_files(drv);
		if (error) {
			/* Ditto */
			printk(KERN_ERR "%s: add_bind_files(%s) failed\n",
				__func__, drv->name);
		}
	}

	return 0;

out_unregister:
	kobject_put(&priv->kobj);
	/* drv->p is freed in driver_release()  */
	drv->p = NULL;
out_put_bus:
	bus_put(bus);
	return error;
}
```

## bus_for_each_dev
```c
int bus_for_each_dev(struct bus_type *bus, struct device *start,
		     void *data, int (*fn)(struct device *, void *))
{
	struct klist_iter i;
	struct device *dev;
	int error = 0;

	if (!bus || !bus->p)
		return -EINVAL;

	// 初始化迭代器
	klist_iter_init_node(&bus->p->klist_devices, &i,
			     (start ? &start->p->knode_bus : NULL));
	// 调用目标函数
	// 有错误或者没有设备了, 就会直接退出
	while (!error && (dev = next_device(&i)))
		error = fn(dev, data);
	klist_iter_exit(&i);
	return error;
}
```