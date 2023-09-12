# init

```c
static int __init init_nfsd(void)
{
	int retval;
	printk(KERN_INFO "Installing knfsd (copyright (C) 1996 okir@monad.swb.de).\n");

	// 初始化各种slab缓存
	retval = nfsd4_init_slabs();
	if (retval)
		return retval;
	// 还是初始化缓存
	retval = nfsd4_init_pnfs();
	if (retval)
		goto out_free_slabs;
	// 注册一个rpc程序，这个会在procfs里生成一个接口
	nfsd_stat_init();	/* Statistics */
	// 创建drc缓存
	retval = nfsd_drc_slab_create();
	if (retval)
		goto out_free_stat;
	
	// 初始化lockd
	nfsd_lockd_init();	/* lockd->nfsd callbacks */

	// 在proc里生成fs/nfs接口
	retval = create_proc_exports_entry();
	if (retval)
		goto out_free_lockd;
	
	// 注册nfsd文件系统
	retval = register_filesystem(&nfsd_fs_type);
	if (retval)
		goto out_free_exports;
	// 注册一个网络命名空间子系统
	retval = register_pernet_subsys(&nfsd_net_ops);
	if (retval < 0)
		goto out_free_filesystem;
	// 注册pipefs通知器？
	retval = register_cld_notifier();
	if (retval)
		goto out_free_all;
	return 0;
out_free_all:
	unregister_pernet_subsys(&nfsd_net_ops);
out_free_filesystem:
	unregister_filesystem(&nfsd_fs_type);
out_free_exports:
	remove_proc_entry("fs/nfs/exports", NULL);
	remove_proc_entry("fs/nfs", NULL);
out_free_lockd:
	nfsd_lockd_shutdown();
	nfsd_drc_slab_free();
out_free_stat:
	nfsd_stat_shutdown();
	nfsd4_exit_pnfs();
out_free_slabs:
	nfsd4_free_slabs();
	return retval;
}

```