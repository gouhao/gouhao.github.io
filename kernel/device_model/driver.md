# driver

## 结构体
```c
struct device_driver {
	const char		*name; // 驱动名
	struct bus_type		*bus; // 总结

	struct module		*owner; // 模块
	const char		*mod_name; // 名称，用于built-in驱动

	bool suppress_bind_attrs;	// sys属性？
	enum probe_type probe_type;

	const struct of_device_id	*of_match_table; // 设备匹配列表
	const struct acpi_device_id	*acpi_match_table; // acpi设备匹配列表

	int (*probe) (struct device *dev); // 探测，检查驱动是否可以控制该设备
	void (*sync_state)(struct device *dev);
	int (*remove) (struct device *dev); // 移走设备时调用
	void (*shutdown) (struct device *dev); // 设备断电时设备
	int (*suspend) (struct device *dev, pm_message_t state); // 设备运行在低功率状态时调用
	int (*resume) (struct device *dev); // 设备恢复正常状态时调用
	const struct attribute_group **groups; // 属性组
	const struct attribute_group **dev_groups; //设备属性组

	const struct dev_pm_ops *pm;
	void (*coredump) (struct device *dev);

	struct driver_private *p;
};

struct driver_private {
	struct kobject kobj;
	struct klist klist_devices;
	struct klist_node knode_bus;
	struct module_kobject *mkobj;
	struct device_driver *driver;
};
```

## driver_register
```c
int driver_register(struct device_driver *drv)
{
	int ret;
	struct device_driver *other;

	// 总线没有初始化
	if (!drv->bus->p) {
		pr_err("Driver '%s' was unable to register with bus_type '%s' because the bus was not initialized.\n",
			   drv->name, drv->bus->name);
		return -EINVAL;
	}

	// 必须要有这些函数
	if ((drv->bus->probe && drv->probe) ||
	    (drv->bus->remove && drv->remove) ||
	    (drv->bus->shutdown && drv->shutdown))
		pr_warn("Driver '%s' needs updating - please use "
			"bus_type methods\n", drv->name);

	// 在 bus->p->drivers_kset 里找驱动
	other = driver_find(drv->name, drv->bus);

	// 驱动已存在
	if (other) {
		pr_err("Error: Driver '%s' is already registered, "
			"aborting...\n", drv->name);
		return -EBUSY;
	}

	// 走到这儿表示驱动不存在

	// 添加之
	ret = bus_add_driver(drv);
	if (ret)
		return ret;
	ret = driver_add_groups(drv, drv->groups);
	if (ret) {
		bus_remove_driver(drv);
		return ret;
	}
	kobject_uevent(&drv->p->kobj, KOBJ_ADD);

	return ret;
}

struct device_driver *driver_find(const char *name, struct bus_type *bus)
{
	// 从kset里找驱动
	struct kobject *k = kset_find_obj(bus->p->drivers_kset, name);
	struct driver_private *priv;

	if (k) {
		// 释放引用, 因为在kset_find_obj里添加了一次
		kobject_put(k);
		// kobj转成驱动私有数据
		priv = to_driver(k);
		// 返回驱动
		return priv->driver;
	}
	return NULL;
}
```

## driver_unregister
```c
void driver_unregister(struct device_driver *drv)
{
	if (!drv || !drv->p) {
		WARN(1, "Unexpected driver unregister!\n");
		return;
	}
	driver_remove_groups(drv, drv->groups);
	bus_remove_driver(drv);
}
```

## driver_create_file
```c
int driver_create_file(struct device_driver *drv,
		       const struct driver_attribute *attr)
{
	int error;

	if (drv)
		error = sysfs_create_file(&drv->p->kobj, &attr->attr);
	else
		error = -EINVAL;
	return error;
}
```

## driver_add_groups
```c
int driver_add_groups(struct device_driver *drv,
		      const struct attribute_group **groups)
{
	return sysfs_create_groups(&drv->p->kobj, groups);
}
```

## driver_attach
```c
int driver_attach(struct device_driver *drv)
{
	// 遍历设备调用 __driver_attach
	return bus_for_each_dev(drv->bus, NULL, drv, __driver_attach);
}

static int __driver_attach(struct device *dev, void *data)
{
	struct device_driver *drv = data;
	int ret;

	
	// 调用bus的match方法
	ret = driver_match_device(drv, dev);
	if (ret == 0) {
		/* no match */
		return 0;
	} else if (ret == -EPROBE_DEFER) {
		// 延迟探测?
		dev_dbg(dev, "Device match requests probe deferral\n");
		driver_deferred_probe_add(dev);
	} else if (ret < 0) {
		// 错误
		dev_dbg(dev, "Bus failed to match device: %d\n", ret);
		return ret;
	} /* ret > 0 means positive match */

	// 走到这儿返回值 > 0, 表示匹配

	// 允许异步探测
	if (driver_allows_async_probing(drv)) {
		
		/*
		 * Instead of probing the device synchronously we will
		 * probe it asynchronously to allow for more parallelism.
		 *
		 * We only take the device lock here in order to guarantee
		 * that the dev->driver and async_driver fields are protected
		 */
		dev_dbg(dev, "probing driver %s asynchronously\n", drv->name);
		device_lock(dev);
		// 没有驱动了才执行探测
		if (!dev->driver) {
			get_device(dev);
			dev->p->async_driver = drv;
			// 异步执行 __driver_attach_async_helper
			async_schedule_dev(__driver_attach_async_helper, dev);
		}
		device_unlock(dev);
		return 0;
	}

	device_driver_attach(drv, dev);

	return 0;
}

static inline int driver_match_device(struct device_driver *drv,
				      struct device *dev)
{
	// 调用bus的match方法
	return drv->bus->match ? drv->bus->match(dev, drv) : 1;
}

bool driver_allows_async_probing(struct device_driver *drv)
{
	// 根据探测类型
	switch (drv->probe_type) {
	// 如果有明确的异/同步类型, 则直接返回
	case PROBE_PREFER_ASYNCHRONOUS:
		return true;

	case PROBE_FORCE_SYNCHRONOUS:
		return false;

	default:
		// 通过driver_async_probe=命令,指定某个驱动要异步
		if (cmdline_requested_async_probing(drv->name))
			return true;

		// 如果是模块, 模块指定了异步探测
		if (module_requested_async_probing(drv->owner))
			return true;

		return false;
	}
}

static inline bool module_requested_async_probing(struct module *module)
{
	// 异步探测
	return module && module->async_probe_requested;
}

// 异步
static void __driver_attach_async_helper(void *_dev, async_cookie_t cookie)
{
	struct device *dev = _dev;
	struct device_driver *drv;
	int ret = 0;

	__device_driver_lock(dev, dev->parent);

	// 取出驱动
	drv = dev->p->async_driver;

	// 设备没有死 && 没有驱动, 则探测之
	if (!dev->p->dead && !dev->driver)
		ret = driver_probe_device(drv, dev);

	__device_driver_unlock(dev, dev->parent);

	dev_dbg(dev, "driver %s async attach completed: %d\n", drv->name, ret);

	put_device(dev);
}

// 同步
int device_driver_attach(struct device_driver *drv, struct device *dev)
{
	int ret = 0;

	__device_driver_lock(dev, dev->parent);

	// 设备没有死 && 没有驱动, 则探测之
	if (!dev->p->dead && !dev->driver)
		ret = driver_probe_device(drv, dev);

	__device_driver_unlock(dev, dev->parent);

	return ret;
}

int driver_probe_device(struct device_driver *drv, struct device *dev)
{
	int ret = 0;

	// 判断 dev->kobj.state_in_sysfs 是否为 1
	if (!device_is_registered(dev))
		return -ENODEV;

	pr_debug("bus: '%s': %s: matched device %s with driver %s\n",
		 drv->bus->name, __func__, dev_name(dev), drv->name);

	// 获取引用?
	pm_runtime_get_suppliers(dev);
	if (dev->parent)
		pm_runtime_get_sync(dev->parent);

	// 等待待决的请求完成
	pm_runtime_barrier(dev);

	// 真正的探测, really_probe_debug只是比really_probe多了打印探测的时间
	if (initcall_debug)
		ret = really_probe_debug(dev, drv);
	else
		ret = really_probe(dev, drv);

	// 让设备空闲?
	pm_request_idle(dev);

	if (dev->parent)
		pm_runtime_put(dev->parent);

	pm_runtime_put_suppliers(dev);
	return ret;
}

static int really_probe(struct device *dev, struct device_driver *drv)
{
	int ret = -EPROBE_DEFER;
	// 延迟数量?
	int local_trigger_count = atomic_read(&deferred_trigger_count);
	// 测试移除?
	bool test_remove = IS_ENABLED(CONFIG_DEBUG_TEST_DRIVER_REMOVE) &&
			   !drv->suppress_bind_attrs;

	// 推迟探测
	if (defer_all_probes) {
		/* defer_all_probes只被device_block_probing设置,
		 * 之后会调用wait_for_device_probe, 来等待探测完成
		 */
		dev_dbg(dev, "Driver %s force probe deferral\n", drv->name);
		// 加到 deferred_probe_pending_list 列表
		driver_deferred_probe_add(dev);
		return ret;
	}

	// 检查供应商的状态
	ret = device_links_check_suppliers(dev);
	// 如果是延迟,则加到延迟列表
	if (ret == -EPROBE_DEFER)
		driver_deferred_probe_add_trigger(dev, local_trigger_count);

	// 其他错误直接返回错误
	if (ret)
		return ret;

	// 探测数量
	atomic_inc(&probe_count);
	pr_debug("bus: '%s': %s: probing driver %s with device %s\n",
		 drv->bus->name, __func__, drv->name, dev_name(dev));
	// 探测前不能有
	if (!list_empty(&dev->devres_head)) {
		dev_crit(dev, "Resources present before probing\n");
		ret = -EBUSY;
		goto done;
	}

re_probe:
	// 先设置设备的驱动
	dev->driver = drv;

	// 引脚控制
	ret = pinctrl_bind_pins(dev);
	if (ret)
		goto pinctrl_bind_failed;

	// dma配置
	if (dev->bus->dma_configure) {
		ret = dev->bus->dma_configure(dev);
		if (ret)
			goto probe_failed;
	}

	// 在driver和device的sysfs目录里创建相应的链接
	ret = driver_sysfs_add(dev);
	if (ret) {
		pr_err("%s: driver_sysfs_add(%s) failed\n",
		       __func__, dev_name(dev));
		goto probe_failed;
	}

	// 激活设备
	if (dev->pm_domain && dev->pm_domain->activate) {
		ret = dev->pm_domain->activate(dev);
		if (ret)
			goto probe_failed;
	}

	// 总线有探测,则调用总线的
	if (dev->bus->probe) {
		ret = dev->bus->probe(dev);
		if (ret)
			goto probe_failed;
	// 否则调用驱动的探测
	} else if (drv->probe) {
		ret = drv->probe(dev);
		if (ret)
			goto probe_failed;
	}

	// 走到这儿表示探测成功

	ret = device_add_groups(dev, drv->dev_groups);
	if (ret) {
		dev_err(dev, "device_add_groups() failed\n");
		goto dev_groups_failed;
	}

	// driver或bus有同步状态,则创建相应的接口
	if (dev_has_sync_state(dev)) {
		ret = device_create_file(dev, &dev_attr_state_synced);
		if (ret) {
			dev_err(dev, "state_synced sysfs add failed\n");
			goto dev_sysfs_state_synced_failed;
		}
	}

	// 测试删除?
	if (test_remove) {
		test_remove = false;

		device_remove_file(dev, &dev_attr_state_synced);
		device_remove_groups(dev, drv->dev_groups);

		if (dev->bus->remove)
			dev->bus->remove(dev);
		else if (drv->remove)
			drv->remove(dev);

		devres_release_all(dev);
		driver_sysfs_remove(dev);
		dev->driver = NULL;
		dev_set_drvdata(dev, NULL);
		if (dev->pm_domain && dev->pm_domain->dismiss)
			dev->pm_domain->dismiss(dev);
		pm_runtime_reinit(dev);

		goto re_probe;
	}

	// 引脚控制?
	pinctrl_init_done(dev);

	// 电源管理相关
	if (dev->pm_domain && dev->pm_domain->sync)
		dev->pm_domain->sync(dev);

	// 把设备和驱动绑定
	driver_bound(dev);
	ret = 1;
	pr_debug("bus: '%s': %s: bound device %s to driver %s\n",
		 drv->bus->name, __func__, dev_name(dev), drv->name);
	goto done;

dev_sysfs_state_synced_failed:
	device_remove_groups(dev, drv->dev_groups);
dev_groups_failed:
	if (dev->bus->remove)
		dev->bus->remove(dev);
	else if (drv->remove)
		drv->remove(dev);
probe_failed:
	// 探测失败之后,发出通知
	if (dev->bus)
		blocking_notifier_call_chain(&dev->bus->p->bus_notifier,
					     BUS_NOTIFY_DRIVER_NOT_BOUND, dev);
pinctrl_bind_failed:
	// 对各种资源进行释放
	device_links_no_driver(dev);
	devres_release_all(dev);
	arch_teardown_dma_ops(dev);
	kfree(dev->dma_range_map);
	dev->dma_range_map = NULL;
	driver_sysfs_remove(dev);
	dev->driver = NULL;
	dev_set_drvdata(dev, NULL);
	if (dev->pm_domain && dev->pm_domain->dismiss)
		dev->pm_domain->dismiss(dev);
	pm_runtime_reinit(dev);
	dev_pm_set_driver_flags(dev, 0);

	switch (ret) {
	case -EPROBE_DEFER:
		/* Driver requested deferred probing */
		dev_dbg(dev, "Driver %s requests probe deferral\n", drv->name);
		driver_deferred_probe_add_trigger(dev, local_trigger_count);
		break;
	case -ENODEV:
	case -ENXIO:
		pr_debug("%s: probe of %s rejects match %d\n",
			 drv->name, dev_name(dev), ret);
		break;
	default:
		/* driver matched but the probe failed */
		pr_warn("%s: probe of %s failed with error %d\n",
			drv->name, dev_name(dev), ret);
	}
	/*
	 * Ignore errors returned by ->probe so that the next driver can try
	 * its luck.
	 */
	ret = 0;
done:
	// 递增探测数量
	atomic_dec(&probe_count);
	// 唤醒所有探测的等待队列
	wake_up_all(&probe_waitqueue);
	return ret;
}

void driver_deferred_probe_add(struct device *dev)
{
	mutex_lock(&deferred_probe_mutex);
	// 若 deferred_probe 为空, 则加到 deferred_probe_pending_list列表
	if (list_empty(&dev->p->deferred_probe)) {
		dev_dbg(dev, "Added to deferred list\n");
		list_add_tail(&dev->p->deferred_probe, &deferred_probe_pending_list);
	}
	mutex_unlock(&deferred_probe_mutex);
}

int device_links_check_suppliers(struct device *dev)
{
	struct device_link *link;
	int ret = 0;

	/*
	 * Device waiting for supplier to become available is not allowed to
	 * probe.
	 */
	mutex_lock(&wfs_lock);
	if (!list_empty(&dev->links.needs_suppliers) &&
	    dev->links.need_for_probe) {
		mutex_unlock(&wfs_lock);
		return -EPROBE_DEFER;
	}
	mutex_unlock(&wfs_lock);

	device_links_write_lock();

	list_for_each_entry(link, &dev->links.suppliers, c_node) {
		if (!(link->flags & DL_FLAG_MANAGED))
			continue;

		if (link->status != DL_STATE_AVAILABLE &&
		    !(link->flags & DL_FLAG_SYNC_STATE_ONLY)) {
			device_links_missing_supplier(dev);
			ret = -EPROBE_DEFER;
			break;
		}
		WRITE_ONCE(link->status, DL_STATE_CONSUMER_PROBE);
	}
	dev->links.status = DL_DEV_PROBING;

	device_links_write_unlock();
	return ret;
}

static void driver_deferred_probe_add_trigger(struct device *dev,
					      int local_trigger_count)
{
	driver_deferred_probe_add(dev);
	/* Did a trigger occur while probing? Need to re-trigger if yes */
	if (local_trigger_count != atomic_read(&deferred_trigger_count))
		driver_deferred_probe_trigger();
}

static void driver_bound(struct device *dev)
{
	if (device_is_bound(dev)) {
		pr_warn("%s: device %s already bound\n",
			__func__, kobject_name(&dev->kobj));
		return;
	}

	pr_debug("driver: '%s': %s: bound to device '%s'\n", dev->driver->name,
		 __func__, dev_name(dev));

	klist_add_tail(&dev->p->knode_driver, &dev->driver->p->klist_devices);
	device_links_driver_bound(dev);

	device_pm_check_callbacks(dev);

	/*
	 * Make sure the device is no longer in one of the deferred lists and
	 * kick off retrying all pending devices
	 */
	driver_deferred_probe_del(dev);
	driver_deferred_probe_trigger();

	if (dev->bus)
		blocking_notifier_call_chain(&dev->bus->p->bus_notifier,
					     BUS_NOTIFY_BOUND_DRIVER, dev);

	kobject_uevent(&dev->kobj, KOBJ_BIND);
}

static int driver_sysfs_add(struct device *dev)
{
	int ret;

	if (dev->bus)
		blocking_notifier_call_chain(&dev->bus->p->bus_notifier,
					     BUS_NOTIFY_BIND_DRIVER, dev);

	ret = sysfs_create_link(&dev->driver->p->kobj, &dev->kobj,
				kobject_name(&dev->kobj));
	if (ret)
		goto fail;

	ret = sysfs_create_link(&dev->kobj, &dev->driver->p->kobj,
				"driver");
	if (ret)
		goto rm_dev;

	if (!IS_ENABLED(CONFIG_DEV_COREDUMP) || !dev->driver->coredump ||
	    !device_create_file(dev, &dev_attr_coredump))
		return 0;

	sysfs_remove_link(&dev->kobj, "driver");

rm_dev:
	sysfs_remove_link(&dev->driver->p->kobj,
			  kobject_name(&dev->kobj));

fail:
	return ret;
}
```