# setup arch

源码基于5.10，本文里的代码都是在CONFIG_NUMA打开的情景里，现在内核这个选项都是打开的，即使电脑没有numa结构。

架构是x86的代码。
```c
void __init setup_arch(char **cmdline_p)
{
	/*
	 * Reserve the memory occupied by the kernel between _text and
	 * __end_of_kernel_reserve symbols. Any kernel sections after the
	 * __end_of_kernel_reserve symbol must be explicitly reserved with a
	 * separate memblock_reserve() or they will be discarded.
	 */
	memblock_reserve(__pa_symbol(_text),
			 (unsigned long)__end_of_kernel_reserve - (unsigned long)_text);

	/*
	 * Make sure page 0 is always reserved because on systems with
	 * L1TF its contents can be leaked to user processes.
	 */
	memblock_reserve(0, PAGE_SIZE);

	early_reserve_initrd();

	printk(KERN_INFO "Command line: %s\n", boot_command_line);
	boot_cpu_data.x86_phys_bits = MAX_PHYSMEM_BITS;


	iomem_resource.end = (1ULL << boot_cpu_data.x86_phys_bits) - 1;
	e820__memory_setup();
	parse_setup_data();

	copy_edd();

	if (!boot_params.hdr.root_flags)
		root_mountflags &= ~MS_RDONLY;
	init_mm.start_code = (unsigned long) _text;
	init_mm.end_code = (unsigned long) _etext;
	init_mm.end_data = (unsigned long) _edata;
	init_mm.brk = _brk_end;

	code_resource.start = __pa_symbol(_text);
	code_resource.end = __pa_symbol(_etext)-1;
	rodata_resource.start = __pa_symbol(__start_rodata);
	rodata_resource.end = __pa_symbol(__end_rodata)-1;
	data_resource.start = __pa_symbol(_sdata);
	data_resource.end = __pa_symbol(_edata)-1;
	bss_resource.start = __pa_symbol(__bss_start);
	bss_resource.end = __pa_symbol(__bss_stop)-1;

#ifdef CONFIG_CMDLINE_BOOL
#ifdef CONFIG_CMDLINE_OVERRIDE
	strlcpy(boot_command_line, builtin_cmdline, COMMAND_LINE_SIZE);
#else
	if (builtin_cmdline[0]) {
		/* append boot loader cmdline to builtin */
		strlcat(builtin_cmdline, " ", COMMAND_LINE_SIZE);
		strlcat(builtin_cmdline, boot_command_line, COMMAND_LINE_SIZE);
		strlcpy(boot_command_line, builtin_cmdline, COMMAND_LINE_SIZE);
	}
#endif
#endif

	strlcpy(command_line, boot_command_line, COMMAND_LINE_SIZE);
	*cmdline_p = command_line;

	/*
	 * x86_configure_nx() is called before parse_early_param() to detect
	 * whether hardware doesn't support NX (so that the early EHCI debug
	 * console setup can safely call set_fixmap()). It may then be called
	 * again from within noexec_setup() during parsing early parameters
	 * to honor the respective command line option.
	 */
	x86_configure_nx();

	parse_early_param();

	if (efi_enabled(EFI_BOOT))
		efi_memblock_x86_reserve_range();
#ifdef CONFIG_MEMORY_HOTPLUG
	/*
	 * Memory used by the kernel cannot be hot-removed because Linux
	 * cannot migrate the kernel pages. When memory hotplug is
	 * enabled, we should prevent memblock from allocating memory
	 * for the kernel.
	 *
	 * ACPI SRAT records all hotpluggable memory ranges. But before
	 * SRAT is parsed, we don't know about it.
	 *
	 * The kernel image is loaded into memory at very early time. We
	 * cannot prevent this anyway. So on NUMA system, we set any
	 * node the kernel resides in as un-hotpluggable.
	 *
	 * Since on modern servers, one node could have double-digit
	 * gigabytes memory, we can assume the memory around the kernel
	 * image is also un-hotpluggable. So before SRAT is parsed, just
	 * allocate memory near the kernel image to try the best to keep
	 * the kernel away from hotpluggable memory.
	 */
	if (movable_node_is_enabled())
		memblock_set_bottom_up(true);
#endif

	x86_report_nx();

	/* after early param, so could get panic from serial */
	memblock_x86_reserve_range_setup_data();

	if (acpi_mps_check()) {
#ifdef CONFIG_X86_LOCAL_APIC
		disable_apic = 1;
#endif
		setup_clear_cpu_cap(X86_FEATURE_APIC);
	}

	e820__reserve_setup_data();
	e820__finish_early_params();

	if (efi_enabled(EFI_BOOT))
		efi_init();

	dmi_setup();

	/*
	 * VMware detection requires dmi to be available, so this
	 * needs to be done after dmi_setup(), for the boot CPU.
	 */
	init_hypervisor_platform();

	tsc_early_init();
	x86_init.resources.probe_roms();

	/* after parse_early_param, so could debug it */
	insert_resource(&iomem_resource, &code_resource);
	insert_resource(&iomem_resource, &rodata_resource);
	insert_resource(&iomem_resource, &data_resource);
	insert_resource(&iomem_resource, &bss_resource);

	e820_add_kernel_range();
	trim_bios_range();
#ifdef CONFIG_X86_32
	if (ppro_with_ram_bug()) {
		e820__range_update(0x70000000ULL, 0x40000ULL, E820_TYPE_RAM,
				  E820_TYPE_RESERVED);
		e820__update_table(e820_table);
		printk(KERN_INFO "fixed physical RAM map:\n");
		e820__print_table("bad_ppro");
	}
#else
	early_gart_iommu_check();
#endif

	/*
	 * partially used pages are not usable - thus
	 * we are rounding upwards:
	 */
	max_pfn = e820__end_of_ram_pfn();

	/* update e820 for memory not covered by WB MTRRs */
	mtrr_bp_init();
	if (mtrr_trim_uncached_memory(max_pfn))
		max_pfn = e820__end_of_ram_pfn();

	max_possible_pfn = max_pfn;

	/*
	 * This call is required when the CPU does not support PAT. If
	 * mtrr_bp_init() invoked it already via pat_init() the call has no
	 * effect.
	 */
	init_cache_modes();

	/*
	 * Define random base addresses for memory sections after max_pfn is
	 * defined and before each memory section base is used.
	 */
	kernel_randomize_memory();

#ifdef CONFIG_X86_32
	/* max_low_pfn get updated here */
	find_low_pfn_range();
#else
	check_x2apic();

	/* How many end-of-memory variables you have, grandma! */
	/* need this before calling reserve_initrd */
	if (max_pfn > (1UL<<(32 - PAGE_SHIFT)))
		max_low_pfn = e820__end_of_low_ram_pfn();
	else
		max_low_pfn = max_pfn;

	high_memory = (void *)__va(max_pfn * PAGE_SIZE - 1) + 1;
#endif

	/*
	 * Find and reserve possible boot-time SMP configuration:
	 */
	find_smp_config();

	reserve_ibft_region();

	early_alloc_pgt_buf();

	/*
	 * Need to conclude brk, before e820__memblock_setup()
	 *  it could use memblock_find_in_range, could overlap with
	 *  brk area.
	 */
	reserve_brk();

	cleanup_highmap();

	memblock_set_current_limit(ISA_END_ADDRESS);
	e820__memblock_setup();

	reserve_bios_regions();

	efi_fake_memmap();
	efi_find_mirror();
	efi_esrt_init();
	efi_mokvar_table_init();

	/*
	 * The EFI specification says that boot service code won't be
	 * called after ExitBootServices(). This is, in fact, a lie.
	 */
	efi_reserve_boot_services();

	/* preallocate 4k for mptable mpc */
	e820__memblock_alloc_reserved_mpc_new();

#ifdef CONFIG_X86_CHECK_BIOS_CORRUPTION
	setup_bios_corruption_check();
#endif

#ifdef CONFIG_X86_32
	printk(KERN_DEBUG "initial memory mapped: [mem 0x00000000-%#010lx]\n",
			(max_pfn_mapped<<PAGE_SHIFT) - 1);
#endif

	reserve_real_mode();

	trim_platform_memory_ranges();
	trim_low_memory_range();

	init_mem_mapping();

	idt_setup_early_pf();

	/*
	 * Update mmu_cr4_features (and, indirectly, trampoline_cr4_features)
	 * with the current CR4 value.  This may not be necessary, but
	 * auditing all the early-boot CR4 manipulation would be needed to
	 * rule it out.
	 *
	 * Mask off features that don't work outside long mode (just
	 * PCIDE for now).
	 */
	mmu_cr4_features = __read_cr4() & ~X86_CR4_PCIDE;

	memblock_set_current_limit(get_max_mapped());

	/*
	 * NOTE: On x86-32, only from this point on, fixmaps are ready for use.
	 */

#ifdef CONFIG_PROVIDE_OHCI1394_DMA_INIT
	if (init_ohci1394_dma_early)
		init_ohci1394_dma_on_all_controllers();
#endif
	/* Allocate bigger log buffer */
	setup_log_buf(1);

	if (efi_enabled(EFI_BOOT)) {
		switch (boot_params.secure_boot) {
		case efi_secureboot_mode_disabled:
			pr_info("Secure boot disabled\n");
			break;
		case efi_secureboot_mode_enabled:
			pr_info("Secure boot enabled\n");
			break;
		default:
			pr_info("Secure boot could not be determined\n");
			break;
		}
	}

	reserve_initrd();

	acpi_table_upgrade();
	/* Look for ACPI tables and reserve memory occupied by them. */
	acpi_boot_table_init();

	vsmp_init();

	io_delay_init();

	early_platform_quirks();

	early_acpi_boot_init();

	initmem_init();
	dma_contiguous_reserve(max_pfn_mapped << PAGE_SHIFT);

	if (boot_cpu_has(X86_FEATURE_GBPAGES))
		hugetlb_cma_reserve(PUD_SHIFT - PAGE_SHIFT);

	/*
	 * Reserve memory for crash kernel after SRAT is parsed so that it
	 * won't consume hotpluggable memory.
	 */
	reserve_crashkernel();

	memblock_find_dma_reserve();

	if (!early_xdbc_setup_hardware())
		early_xdbc_register_console();

	// 在x86_64下，这个会调到 paging_init
	x86_init.paging.pagetable_init();

	kasan_init();

	/*
	 * Sync back kernel address range.
	 *
	 * FIXME: Can the later sync in setup_cpu_entry_areas() replace
	 * this call?
	 */
	sync_initial_page_table();

	tboot_probe();

	map_vsyscall();

	generic_apic_probe();

	early_quirks();

	/*
	 * Read APIC and some other early information from ACPI tables.
	 */
	acpi_boot_init();
	sfi_init();
	x86_dtb_init();

	/*
	 * get boot-time SMP configuration:
	 */
	get_smp_config();

	/*
	 * Systems w/o ACPI and mptables might not have it mapped the local
	 * APIC yet, but prefill_possible_map() might need to access it.
	 */
	init_apic_mappings();

	prefill_possible_map();

	init_cpu_to_node();
	init_gi_nodes();

	io_apic_init_mappings();

	x86_init.hyper.guest_late_init();

	e820__reserve_resources();
	e820__register_nosave_regions(max_pfn);

	x86_init.resources.reserve_resources();

	e820__setup_pci_gap();

#ifdef CONFIG_VT
#if defined(CONFIG_VGA_CONSOLE)
	if (!efi_enabled(EFI_BOOT) || (efi_mem_type(0xa0000) != EFI_CONVENTIONAL_MEMORY))
		conswitchp = &vga_con;
#endif
#endif
	x86_init.oem.banner();

	x86_init.timers.wallclock_init();

	mcheck_init();

	register_refined_jiffies(CLOCK_TICK_RATE);

#ifdef CONFIG_EFI
	if (efi_enabled(EFI_BOOT))
		efi_apply_memmap_quirks();
#endif

	unwind_init();
}

void __init e820__memory_setup(void)
{
	char *who;

	// 这是固件的二进制接口，不能破坏它
	BUILD_BUG_ON(sizeof(struct boot_e820_entry) != 20);

	// 默认情况下会调用到e820__memory_setup_default
	who = x86_init.resources.memory_setup();

	// todo: what?
	memcpy(e820_table_kexec, e820_table, sizeof(*e820_table_kexec));
	memcpy(e820_table_firmware, e820_table, sizeof(*e820_table_firmware));

	pr_info("BIOS-provided physical RAM map:\n");
	
	
	e820__print_table(who);
}

char *__init e820__memory_setup_default(void)
{
	char *who = "BIOS-e820";

	/*
	 * Try to copy the BIOS-supplied E820-map.
	 *
	 * Otherwise fake a memory map; one section from 0k->640k,
	 * the next section from 1mb->appropriate_mem_k
	 */
	if (append_e820_table(boot_params.e820_table, boot_params.e820_entries) < 0) {
		u64 mem_size;

		/* Compare results from other methods and take the one that gives more RAM: */
		if (boot_params.alt_mem_k < boot_params.screen_info.ext_mem_k) {
			mem_size = boot_params.screen_info.ext_mem_k;
			who = "BIOS-88";
		} else {
			mem_size = boot_params.alt_mem_k;
			who = "BIOS-e801";
		}

		e820_table->nr_entries = 0;
		e820__range_add(0, LOWMEMSIZE(), E820_TYPE_RAM);
		e820__range_add(HIGH_MEMORY, mem_size << 10, E820_TYPE_RAM);
	}

	/* We just appended a lot of ranges, sanitize the table: */
	e820__update_table(e820_table);

	return who;
}

static int __init append_e820_table(struct boot_e820_entry *entries, u32 nr_entries)
{
	/* Only one memory region (or negative)? Ignore it */
	if (nr_entries < 2)
		return -1;

	return __append_e820_table(entries, nr_entries);
}

static int __init __append_e820_table(struct boot_e820_entry *entries, u32 nr_entries)
{
	struct boot_e820_entry *entry = entries;

	while (nr_entries) {
		u64 start = entry->addr;
		u64 size = entry->size;
		u64 end = start + size - 1;
		u32 type = entry->type;

		/* Ignore the entry on 64-bit overflow: */
		if (start > end && likely(size))
			return -1;

		e820__range_add(start, size, type);

		entry++;
		nr_entries--;
	}
	return 0;
}

void __init e820__range_add(u64 start, u64 size, enum e820_type type)
{
	__e820__range_add(e820_table, start, size, type);
}

static void __init __e820__range_add(struct e820_table *table, u64 start, u64 size, enum e820_type type)
{
	int x = table->nr_entries;

	if (x >= ARRAY_SIZE(table->entries)) {
		pr_err("too many entries; ignoring [mem %#010llx-%#010llx]\n",
		       start, start + size - 1);
		return;
	}

	table->entries[x].addr = start;
	table->entries[x].size = size;
	table->entries[x].type = type;
	table->nr_entries++;
}
```

