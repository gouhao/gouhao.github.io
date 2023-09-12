# 初始化内存管理

源码基于5.10，本文里的代码都是在CONFIG_NUMA打开的情景里，现在内核这个选项都是打开的，即使电脑没有numa结构。

```c
asmlinkage __visible void __init __no_sanitize_address start_kernel(void)
{
	...
	setup_arch(&command_line);
	...
	setup_per_cpu_areas();
	...

	// 建造所有区域
	build_all_zonelists(NULL);
	// 注册了一个热插拔的函数
	page_alloc_init();

	...
	mm_init();

	...
	setup_per_cpu_pageset();
	...
}
```