# 结构体

##
```c
/**
 * struct device - The basic device structure
 * @parent:	The device's "parent" device, the device to which it is attached.
 * 		In most cases, a parent device is some sort of bus or host
 * 		controller. If parent is NULL, the device, is a top-level device,
 * 		which is not usually what you want.
 * @p:		Holds the private data of the driver core portions of the device.
 * 		See the comment of the struct device_private for detail.
 * @kobj:	A top-level, abstract class from which other classes are derived.
 * @init_name:	Initial name of the device.
 * @type:	The type of device.
 * 		This identifies the device type and carries type-specific
 * 		information.
 * @mutex:	Mutex to synchronize calls to its driver.
 * @lockdep_mutex: An optional debug lock that a subsystem can use as a
 * 		peer lock to gain localized lockdep coverage of the device_lock.
 * @bus:	Type of bus device is on.
 * @driver:	Which driver has allocated this
 * @platform_data: Platform data specific to the device.
 * 		Example: For devices on custom boards, as typical of embedded
 * 		and SOC based hardware, Linux often uses platform_data to point
 * 		to board-specific structures describing devices and how they
 * 		are wired.  That can include what ports are available, chip
 * 		variants, which GPIO pins act in what additional roles, and so
 * 		on.  This shrinks the "Board Support Packages" (BSPs) and
 * 		minimizes board-specific #ifdefs in drivers.
 * @driver_data: Private pointer for driver specific info.
 * @links:	Links to suppliers and consumers of this device.
 * @power:	For device power management.
 *		See Documentation/driver-api/pm/devices.rst for details.
 * @pm_domain:	Provide callbacks that are executed during system suspend,
 * 		hibernation, system resume and during runtime PM transitions
 * 		along with subsystem-level and driver-level callbacks.
 * @em_pd:	device's energy model performance domain
 * @pins:	For device pin management.
 *		See Documentation/driver-api/pinctl.rst for details.
 * @msi_list:	Hosts MSI descriptors
 * @msi_domain: The generic MSI domain this device is using.
 * @numa_node:	NUMA node this device is close to.
 * @dma_ops:    DMA mapping operations for this device.
 * @dma_mask:	Dma mask (if dma'ble device).
 * @coherent_dma_mask: Like dma_mask, but for alloc_coherent mapping as not all
 * 		hardware supports 64-bit addresses for consistent allocations
 * 		such descriptors.
 * @bus_dma_limit: Limit of an upstream bridge or bus which imposes a smaller
 *		DMA limit than the device itself supports.
 * @dma_range_map: map for DMA memory ranges relative to that of RAM
 * @dma_parms:	A low level driver may set these to teach IOMMU code about
 * 		segment limitations.
 * @dma_pools:	Dma pools (if dma'ble device).
 * @dma_mem:	Internal for coherent mem override.
 * @cma_area:	Contiguous memory area for dma allocations
 * @archdata:	For arch-specific additions.
 * @of_node:	Associated device tree node.
 * @fwnode:	Associated device node supplied by platform firmware.
 * @devt:	For creating the sysfs "dev".
 * @id:		device instance
 * @devres_lock: Spinlock to protect the resource of the device.
 * @devres_head: The resources list of the device.
 * @knode_class: The node used to add the device to the class list.
 * @class:	The class of the device.
 * @groups:	Optional attribute groups.
 * @release:	Callback to free the device after all references have
 * 		gone away. This should be set by the allocator of the
 * 		device (i.e. the bus driver that discovered the device).
 * @iommu_group: IOMMU group the device belongs to.
 * @iommu:	Per device generic IOMMU runtime data
 *
 * @offline_disabled: If set, the device is permanently online.
 * @offline:	Set after successful invocation of bus type's .offline().
 * @of_node_reused: Set if the device-tree node is shared with an ancestor
 *              device.
 * @state_synced: The hardware state of this device has been synced to match
 *		  the software state of this device by calling the driver/bus
 *		  sync_state() callback.
 * @dma_coherent: this particular device is dma coherent, even if the
 *		architecture supports non-coherent devices.
 * @dma_ops_bypass: If set to %true then the dma_ops are bypassed for the
 *		streaming DMA operations (->map_* / ->unmap_* / ->sync_*),
 *		and optionall (if the coherent mask is large enough) also
 *		for dma allocations.  This flag is managed by the dma ops
 *		instance from ->dma_supported.
 *
 * At the lowest level, every device in a Linux system is represented by an
 * instance of struct device. The device structure contains the information
 * that the device model core needs to model the system. Most subsystems,
 * however, track additional information about the devices they host. As a
 * result, it is rare for devices to be represented by bare device structures;
 * instead, that structure, like kobject structures, is usually embedded within
 * a higher-level representation of the device.
 */
struct device {
	struct kobject kobj; // 内嵌obj
	struct device		*parent; // 父设备

	struct device_private	*p;

	const char		*init_name; /* initial name of the device */
	const struct device_type *type;

	struct bus_type	*bus;		// 总线
	struct device_driver *driver;	// 驱动
	void		*platform_data;	/* Platform specific data, device
					   core doesn't touch it */
	void		*driver_data;	/* Driver data, set and get with
					   dev_set_drvdata/dev_get_drvdata */
#ifdef CONFIG_PROVE_LOCKING
	struct mutex		lockdep_mutex;
#endif
	struct mutex		mutex;	/* mutex to synchronize calls to
					 * its driver.
					 */

	struct dev_links_info	links;
	struct dev_pm_info	power;
	struct dev_pm_domain	*pm_domain;

#ifdef CONFIG_ENERGY_MODEL
	struct em_perf_domain	*em_pd;
#endif

#ifdef CONFIG_GENERIC_MSI_IRQ_DOMAIN
	struct irq_domain	*msi_domain;
#endif
#ifdef CONFIG_PINCTRL
	struct dev_pin_info	*pins;
#endif
#ifdef CONFIG_GENERIC_MSI_IRQ
	raw_spinlock_t		msi_lock;
	struct list_head	msi_list;
#endif
#ifdef CONFIG_DMA_OPS
	const struct dma_map_ops *dma_ops;
#endif
	u64		*dma_mask;	/* dma mask (if dma'able device) */
	u64		coherent_dma_mask;/* Like dma_mask, but for
					     alloc_coherent mappings as
					     not all hardware supports
					     64 bit addresses for consistent
					     allocations such descriptors. */
	u64		bus_dma_limit;	/* upstream dma constraint */
	const struct bus_dma_region *dma_range_map;

	struct device_dma_parameters *dma_parms;

	struct list_head	dma_pools;	/* dma pools (if dma'ble) */

#ifdef CONFIG_DMA_DECLARE_COHERENT
	struct dma_coherent_mem	*dma_mem; /* internal for coherent mem
					     override */
#endif
#ifdef CONFIG_DMA_CMA
	struct cma *cma_area;		/* contiguous memory area for dma
					   allocations */
#endif
	/* arch specific additions */
	struct dev_archdata	archdata;

	struct device_node	*of_node; /* associated device tree node */
	struct fwnode_handle	*fwnode; /* firmware device node */

#ifdef CONFIG_NUMA
	int		numa_node;	/* NUMA node this device is close to */
#endif
	dev_t			devt;	/* dev_t, creates the sysfs "dev" */
	u32			id;	/* device instance */

	spinlock_t		devres_lock;
	struct list_head	devres_head;

	struct class		*class; // 类
	const struct attribute_group **groups;	// 属性

	void	(*release)(struct device *dev);
	struct iommu_group	*iommu_group;
	struct dev_iommu	*iommu;

	bool			offline_disabled:1;
	bool			offline:1;
	bool			of_node_reused:1;
	bool			state_synced:1;
#if defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_DEVICE) || \
    defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_CPU) || \
    defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_CPU_ALL)
	bool			dma_coherent:1;
#endif
#ifdef CONFIG_DMA_OPS_BYPASS
	bool			dma_ops_bypass : 1;
#endif
};
```