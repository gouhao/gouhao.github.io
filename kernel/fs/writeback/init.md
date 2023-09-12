# init
源码基于5.10

## default_bdi_init
```c

static int __init default_bdi_init(void)
{
	int err;

	// 分配wq实例
	bdi_wq = alloc_workqueue("writeback", WQ_MEM_RECLAIM | WQ_UNBOUND |
				 WQ_SYSFS, 0);
	if (!bdi_wq)
		return -ENOMEM;

	//　初始化noop_backing_dev_info，这个bdi没什么实际意义，一般在文件系统卸载了用
	err = bdi_init(&noop_backing_dev_info);

	return err;
}
```

## bdi_alloc
```c
struct backing_dev_info *bdi_alloc(int node_id)
{
	struct backing_dev_info *bdi;

	// 分配bdi
	bdi = kzalloc_node(sizeof(*bdi), GFP_KERNEL, node_id);
	if (!bdi)
		return NULL;

	if (bdi_init(bdi)) {
		kfree(bdi);
		return NULL;
	}
	// 有回写能力
	bdi->capabilities = BDI_CAP_WRITEBACK | BDI_CAP_WRITEBACK_ACCT;
	// 最大预读的页数，VM_READAHEAD_PAGES＝128k/page_size=128k/4k=32页
	bdi->ra_pages = VM_READAHEAD_PAGES;
	// 最大的io页数
	bdi->io_pages = VM_READAHEAD_PAGES;
	return bdi;
}
```

## bdi_init
```c
static int bdi_init(struct backing_dev_info *bdi)
{
	int ret;

	bdi->dev = NULL;

        // 各种初始化
	kref_init(&bdi->refcnt);
	bdi->min_ratio = 0;
	bdi->max_ratio = 100;
	// FPROP_FRAC_BASE=1<<10
	bdi->max_prop_frac = FPROP_FRAC_BASE;
	INIT_LIST_HEAD(&bdi->bdi_list);
	INIT_LIST_HEAD(&bdi->wb_list);
	init_waitqueue_head(&bdi->wb_waitq);

        // 初始化cgroup相关
	ret = cgwb_bdi_init(bdi);

	return ret;
}

static int cgwb_bdi_init(struct backing_dev_info *bdi)
{
	int ret;
        
        // 各种初始化
	INIT_RADIX_TREE(&bdi->cgwb_tree, GFP_ATOMIC);
	mutex_init(&bdi->cgwb_release_mutex);
	init_rwsem(&bdi->wb_switch_rwsem);

        // 终于到了初始化回写结构
	ret = wb_init(&bdi->wb, bdi, GFP_KERNEL);
	if (!ret) {
                // 初始化成功。设置mem, blk cg
		bdi->wb.memcg_css = &root_mem_cgroup->css;
		bdi->wb.blkcg_css = blkcg_root_css;
	}
	return ret;
}

static int wb_init(struct bdi_writeback *wb, struct backing_dev_info *bdi,
		   gfp_t gfp)
{
	int i, err;

        // 置0后，再各种初始化
	memset(wb, 0, sizeof(*wb));

	if (wb != &bdi->wb)
		bdi_get(bdi);
	wb->bdi = bdi;
	// 刷新时间戳
	wb->last_old_flush = jiffies;
	INIT_LIST_HEAD(&wb->b_dirty);
	INIT_LIST_HEAD(&wb->b_io);
	INIT_LIST_HEAD(&wb->b_more_io);
	INIT_LIST_HEAD(&wb->b_dirty_time);
	spin_lock_init(&wb->list_lock);

	// 带宽时间戳
	wb->bw_time_stamp = jiffies;
	// INIT_BW = (100 << (20 - PAGE_SHIFT))
	wb->balanced_dirty_ratelimit = INIT_BW;
	wb->dirty_ratelimit = INIT_BW;
	wb->write_bandwidth = INIT_BW;
	wb->avg_write_bandwidth = INIT_BW;

	spin_lock_init(&wb->work_lock);
	INIT_LIST_HEAD(&wb->work_list);
        
        // 回写工作队列，每次有任务的时候都会调用wb_workfn
	INIT_DELAYED_WORK(&wb->dwork, wb_workfn);
	wb->dirty_sleep = jiffies;

        // 完成回写的统计
	err = fprop_local_init_percpu(&wb->completions, gfp);
	if (err)
		goto out_put_bdi;

        // 初始化每个计数器，这是wb里统计的内存使用情况
	for (i = 0; i < NR_WB_STAT_ITEMS; i++) {
		err = percpu_counter_init(&wb->stat[i], 0, gfp);
		if (err)
			goto out_destroy_stat;
	}

	return 0;

out_destroy_stat:
	while (i--)
		percpu_counter_destroy(&wb->stat[i]);
	fprop_local_destroy_percpu(&wb->completions);
out_put_bdi:
	if (wb != &bdi->wb)
		bdi_put(bdi);
	return err;
}

```

## bdi_register_va
```c
int bdi_register_va(struct backing_dev_info *bdi, const char *fmt, va_list args)
{
	struct device *dev;
	struct rb_node *parent, **p;

	// 已经注册过了
	if (bdi->dev)	/* The driver needs to use separate queues per device */
		return 0;

	vsnprintf(bdi->dev_name, sizeof(bdi->dev_name), fmt, args);
	// 创建一个设备对象，并在sysfs里注册
	dev = device_create(bdi_class, NULL, MKDEV(0, 0), bdi, bdi->dev_name);
	if (IS_ERR(dev))
		return PTR_ERR(dev);

	// 把bdi->wb加到bdi->wb_list里
	cgwb_bdi_register(bdi);
	// 设置设备
	bdi->dev = dev;

	// 在debugfs里创建stats目录
	bdi_debug_register(bdi, dev_name(dev));

	// 设置已注册状态
	set_bit(WB_registered, &bdi->wb.state);

	spin_lock_bh(&bdi_lock);

	// id
	bdi->id = ++bdi_id_cursor;

	// 下面这3个是把它加到bdi_tree里
	p = bdi_lookup_rb_node(bdi->id, &parent);
	rb_link_node(&bdi->rb_node, parent, p);
	rb_insert_color(&bdi->rb_node, &bdi_tree);

	// 加到bdi_list里
	list_add_tail_rcu(&bdi->bdi_list, &bdi_list);

	spin_unlock_bh(&bdi_lock);

	trace_writeback_bdi_register(bdi);
	return 0;
}
```