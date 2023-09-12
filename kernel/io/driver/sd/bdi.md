# bdi
源码基于5.10

## 注册bdi
```c
int bdi_register(struct backing_dev_info *bdi, const char *fmt, ...)
{
	va_list args;
	int ret;

	va_start(args, fmt);
	// 注册
	ret = bdi_register_va(bdi, fmt, args);
	va_end(args);
	return ret;
}

int bdi_register_va(struct backing_dev_info *bdi, const char *fmt, va_list args)
{
	struct device *dev;
	struct rb_node *parent, **p;

	// 已经注册过了
	if (bdi->dev)
		return 0;

	// 设备名
	vsnprintf(bdi->dev_name, sizeof(bdi->dev_name), fmt, args);
	// 创建设备, 用的是bdi_class类
	dev = device_create(bdi_class, NULL, MKDEV(0, 0), bdi, bdi->dev_name);
	if (IS_ERR(dev))
		return PTR_ERR(dev);

	// 添加到bdi的wb_list
	cgwb_bdi_register(bdi);
	// 设备引用
	bdi->dev = dev;

	// 在debugfs/bdi里创建stats文件
	bdi_debug_register(bdi, dev_name(dev));
	// 设置已注册状态
	set_bit(WB_registered, &bdi->wb.state);

	spin_lock_bh(&bdi_lock);

	bdi->id = ++bdi_id_cursor;

	// 根据id找到合适的父结点
	p = bdi_lookup_rb_node(bdi->id, &parent);
	// 链到父结点里,并插入颜色
	rb_link_node(&bdi->rb_node, parent, p);
	rb_insert_color(&bdi->rb_node, &bdi_tree);

	// 添加到bdi列表
	list_add_tail_rcu(&bdi->bdi_list, &bdi_list);

	spin_unlock_bh(&bdi_lock);

	// tracer...
	trace_writeback_bdi_register(bdi);
	return 0;
}

static void cgwb_bdi_register(struct backing_dev_info *bdi)
{
	spin_lock_irq(&cgwb_lock);
	list_add_tail_rcu(&bdi->wb.bdi_node, &bdi->wb_list);
	spin_unlock_irq(&cgwb_lock);
}
```