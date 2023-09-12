# 初始化内存管理

源码基于5.10，本文里的代码都是在CONFIG_NUMA打开的情景里，现在内核这个选项都是打开的，即使电脑没有numa结构。

架构是x86的代码。

```c
static void __init mm_init(void)
{
	// 一般都没打开这个配置
	page_ext_init_flatmem();
        // 调试相关
	init_debug_pagealloc();
        // 日志打开
	report_meminit();
        // 内存初始化
	mem_init();
        // slab系统初始化
	kmem_cache_init();
        // 调试相关
	kmemleak_init();
        // 创建一个slab缓存
	pgtable_init();
        // 调试相关
	debug_objects_mem_init();
        // vmalloc初始化
	vmalloc_init();
        // ioremap的大页相关标志的设置
	ioremap_huge_init();
	
        // 下面2个是x86一些特性初始化。暂时不看
	init_espfix_bsp();
	pti_init();
}

void __init mem_init(void)
{
        // todo: iommu相关，暂时不看
	pci_iommu_alloc();

	// 把memblock里的空闲内存释放到buddy系统里
	memblock_free_all();
	after_bootmem = 1;
        // todo: what ?
	x86_init.hyper.init_after_bootmem();

        // todo: 没太看懂
	register_page_bootmem_info();

	// todo: 给/proc/kcore注册内存？
	if (get_gate_vma(&init_mm))
		kclist_add(&kcore_vsyscall, (void *)VSYSCALL_ADDR, PAGE_SIZE, KCORE_USER);

        // 给vmalloc先申请一些内存？
	preallocate_vmalloc_pages();

        // 打印内存信息。
	mem_init_print_info(NULL);
}
```


## vmalloc_init
```c
void __init vmalloc_init(void)
{
	struct vmap_area *va;
	struct vm_struct *tmp;
	int i;

	/*
	 * Create the cache for vmap_area objects.
	 */
	vmap_area_cachep = KMEM_CACHE(vmap_area, SLAB_PANIC);

	for_each_possible_cpu(i) {
		struct vmap_block_queue *vbq;
		struct vfree_deferred *p;

		vbq = &per_cpu(vmap_block_queue, i);
		spin_lock_init(&vbq->lock);
		INIT_LIST_HEAD(&vbq->free);
		p = &per_cpu(vfree_deferred, i);
		init_llist_head(&p->list);
		INIT_WORK(&p->wq, free_work);
	}

	/* Import existing vmlist entries. */
	for (tmp = vmlist; tmp; tmp = tmp->next) {
		va = kmem_cache_zalloc(vmap_area_cachep, GFP_NOWAIT);
		if (WARN_ON_ONCE(!va))
			continue;

		va->va_start = (unsigned long)tmp->addr;
		va->va_end = va->va_start + tmp->size;
		va->vm = tmp;
		insert_vmap_area(va, &vmap_area_root, &vmap_area_list);
	}

	/*
	 * Now we can initialize a free vmap space.
	 */
	vmap_init_free_space();
	vmap_initialized = true;
}
```