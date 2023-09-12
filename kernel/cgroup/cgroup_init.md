# cgroup init
源码基于5.10

## cgroup_init
```c
int __init cgroup_init(void)
{
	struct cgroup_subsys *ss;
	int ssid;

	// 目前有15个子系统
	BUILD_BUG_ON(CGROUP_SUBSYS_COUNT > 16);

	// 初始化cgroup, cgroup1的基础文件
	BUG_ON(cgroup_init_cftypes(NULL, cgroup_base_files));
	BUG_ON(cgroup_init_cftypes(NULL, cgroup1_base_files));

	// 初始化rstat
	cgroup_rstat_boot();

	rcu_sync_enter_start(&cgroup_threadgroup_rwsem.rss);

	// 增加userns引用计数
	get_user_ns(init_cgroup_ns.user_ns);

	mutex_lock(&cgroup_mutex);

	// 把init_css_set加到css_set_table里
	hash_add(css_set_table, &init_css_set.hlist,
		 css_set_hash(init_css_set.subsys));

	// 初始化根结点
	BUG_ON(cgroup_setup_root(&cgrp_dfl_root, 0));

	mutex_unlock(&cgroup_mutex);

	// 遍历每个子系统
	for_each_subsys(ss, ssid) {
		if (ss->early_init) {
			struct cgroup_subsys_state *css =
				init_css_set.subsys[ss->id];

			css->id = cgroup_idr_alloc(&ss->css_idr, css, 1, 2,
						   GFP_KERNEL);
			BUG_ON(css->id < 0);
		} else {
			cgroup_init_subsys(ss, false);
		}

		list_add_tail(&init_css_set.e_cset_node[ssid],
			      &cgrp_dfl_root.cgrp.e_csets[ssid]);

		/*
		 * Setting dfl_root subsys_mask needs to consider the
		 * disabled flag and cftype registration needs kmalloc,
		 * both of which aren't available during early_init.
		 */
		if (!cgroup_ssid_enabled(ssid))
			continue;

		if (cgroup1_ssid_disabled(ssid))
			printk(KERN_INFO "Disabling %s control group subsystem in v1 mounts\n",
			       ss->name);

		cgrp_dfl_root.subsys_mask |= 1 << ss->id;

		/* implicit controllers must be threaded too */
		WARN_ON(ss->implicit_on_dfl && !ss->threaded);

		if (ss->implicit_on_dfl)
			cgrp_dfl_implicit_ss_mask |= 1 << ss->id;
		else if (!ss->dfl_cftypes)
			cgrp_dfl_inhibit_ss_mask |= 1 << ss->id;

		if (ss->threaded)
			cgrp_dfl_threaded_ss_mask |= 1 << ss->id;

		if (ss->dfl_cftypes == ss->legacy_cftypes) {
			WARN_ON(cgroup_add_cftypes(ss, ss->dfl_cftypes));
		} else {
			WARN_ON(cgroup_add_dfl_cftypes(ss, ss->dfl_cftypes));
			WARN_ON(cgroup_add_legacy_cftypes(ss, ss->legacy_cftypes));
		}

		if (ss->bind)
			ss->bind(init_css_set.subsys[ssid]);

		mutex_lock(&cgroup_mutex);
		css_populate_dir(init_css_set.subsys[ssid]);
		mutex_unlock(&cgroup_mutex);
	}

	/* init_css_set.subsys[] has been updated, re-hash */
	hash_del(&init_css_set.hlist);
	hash_add(css_set_table, &init_css_set.hlist,
		 css_set_hash(init_css_set.subsys));

	WARN_ON(sysfs_create_mount_point(fs_kobj, "cgroup"));
	WARN_ON(register_filesystem(&cgroup_fs_type));
	WARN_ON(register_filesystem(&cgroup2_fs_type));
	WARN_ON(!proc_create_single("cgroups", 0, NULL, proc_cgroupstats_show));
#ifdef CONFIG_CPUSETS
	WARN_ON(register_filesystem(&cpuset_fs_type));
#endif

	return 0;
}

static int cgroup_init_cftypes(struct cgroup_subsys *ss, struct cftype *cfts)
{
	struct cftype *cft;

	// 名字以\0开始，表示数组的结尾
	for (cft = cfts; cft->name[0] != '\0'; cft++) {
		struct kernfs_ops *kf_ops;

		WARN_ON(cft->ss || cft->kf_ops);

		// 根据是否是顺序读，设置不同函数
		if (cft->seq_start)
			kf_ops = &cgroup_kf_ops;
		else
			kf_ops = &cgroup_kf_single_ops;

		if (cft->max_write_len && cft->max_write_len != PAGE_SIZE) {
			// 用户设置有最大长度时，为什么要复制一个kf_ops
			kf_ops = kmemdup(kf_ops, sizeof(*kf_ops), GFP_KERNEL);
			if (!kf_ops) {
				cgroup_exit_cftypes(cfts);
				return -ENOMEM;
			}
			kf_ops->atomic_write_len = cft->max_write_len;
		}

		// 设置函数表和子系统指针
		cft->kf_ops = kf_ops;
		cft->ss = ss;
	}

	return 0;
}

int cgroup_setup_root(struct cgroup_root *root, u16 ss_mask)
{
	LIST_HEAD(tmp_links);
	struct cgroup *root_cgrp = &root->cgrp;
	struct kernfs_syscall_ops *kf_sops;
	struct css_set *cset;
	int i, ret;

	lockdep_assert_held(&cgroup_mutex);

	// 初始化refcount
	ret = percpu_ref_init(&root_cgrp->self.refcnt, css_release,
			      0, GFP_KERNEL);
	if (ret)
		goto out;

	// 分配 2 * css_set_count 个link, link在tmp_link里返回
	ret = allocate_cgrp_cset_links(2 * css_set_count, &tmp_links);
	if (ret)
		goto cancel_ref;

	// 分配 hierarchy_id 
	ret = cgroup_init_root_id(root);
	if (ret)
		goto cancel_ref;

	kf_sops = root == &cgrp_dfl_root ?
		&cgroup_kf_syscall_ops : &cgroup1_kf_syscall_ops;

	root->kf_root = kernfs_create_root(kf_sops,
					   KERNFS_ROOT_CREATE_DEACTIVATED |
					   KERNFS_ROOT_SUPPORT_EXPORTOP |
					   KERNFS_ROOT_SUPPORT_USER_XATTR,
					   root_cgrp);
	if (IS_ERR(root->kf_root)) {
		ret = PTR_ERR(root->kf_root);
		goto exit_root_id;
	}
	root_cgrp->kn = root->kf_root->kn;
	WARN_ON_ONCE(cgroup_ino(root_cgrp) != 1);
	root_cgrp->ancestor_ids[0] = cgroup_id(root_cgrp);

	ret = css_populate_dir(&root_cgrp->self);
	if (ret)
		goto destroy_root;

	ret = rebind_subsystems(root, ss_mask);
	if (ret)
		goto destroy_root;

	ret = cgroup_bpf_inherit(root_cgrp);
	WARN_ON_ONCE(ret);

	trace_cgroup_setup_root(root);

	/*
	 * There must be no failure case after here, since rebinding takes
	 * care of subsystems' refcounts, which are explicitly dropped in
	 * the failure exit path.
	 */
	list_add(&root->root_list, &cgroup_roots);
	cgroup_root_count++;

	/*
	 * Link the root cgroup in this hierarchy into all the css_set
	 * objects.
	 */
	spin_lock_irq(&css_set_lock);
	hash_for_each(css_set_table, i, cset, hlist) {
		link_css_set(&tmp_links, cset, root_cgrp);
		if (css_set_populated(cset))
			cgroup_update_populated(root_cgrp, true);
	}
	spin_unlock_irq(&css_set_lock);

	BUG_ON(!list_empty(&root_cgrp->self.children));
	BUG_ON(atomic_read(&root->nr_cgrps) != 1);

	ret = 0;
	goto out;

destroy_root:
	kernfs_destroy_root(root->kf_root);
	root->kf_root = NULL;
exit_root_id:
	cgroup_exit_root_id(root);
cancel_ref:
	percpu_ref_exit(&root_cgrp->self.refcnt);
out:
	free_cgrp_cset_links(&tmp_links);
	return ret;
}

static int css_populate_dir(struct cgroup_subsys_state *css)
{
	struct cgroup *cgrp = css->cgroup;
	struct cftype *cfts, *failed_cfts;
	int ret;

	if ((css->flags & CSS_VISIBLE) || !cgrp->kn)
		return 0;

	if (!css->ss) {
		if (cgroup_on_dfl(cgrp))
			cfts = cgroup_base_files;
		else
			cfts = cgroup1_base_files;

		ret = cgroup_addrm_files(&cgrp->self, cgrp, cfts, true);
		if (ret < 0)
			return ret;
	} else {
		list_for_each_entry(cfts, &css->ss->cfts, node) {
			ret = cgroup_addrm_files(css, cgrp, cfts, true);
			if (ret < 0) {
				failed_cfts = cfts;
				goto err;
			}
		}
	}

	css->flags |= CSS_VISIBLE;

	return 0;
err:
	list_for_each_entry(cfts, &css->ss->cfts, node) {
		if (cfts == failed_cfts)
			break;
		cgroup_addrm_files(css, cgrp, cfts, false);
	}
	return ret;
}

int rebind_subsystems(struct cgroup_root *dst_root, u16 ss_mask)
{
	struct cgroup *dcgrp = &dst_root->cgrp;
	struct cgroup_subsys *ss;
	int ssid, i, ret;
	u16 dfl_disable_ss_mask = 0;

	lockdep_assert_held(&cgroup_mutex);

	do_each_subsys_mask(ss, ssid, ss_mask) {
		/*
		 * If @ss has non-root csses attached to it, can't move.
		 * If @ss is an implicit controller, it is exempt from this
		 * rule and can be stolen.
		 */
		if (css_next_child(NULL, cgroup_css(&ss->root->cgrp, ss)) &&
		    !ss->implicit_on_dfl)
			return -EBUSY;

		/* can't move between two non-dummy roots either */
		if (ss->root != &cgrp_dfl_root && dst_root != &cgrp_dfl_root)
			return -EBUSY;

		/*
		 * Collect ssid's that need to be disabled from default
		 * hierarchy.
		 */
		if (ss->root == &cgrp_dfl_root)
			dfl_disable_ss_mask |= 1 << ssid;

	} while_each_subsys_mask();

	if (dfl_disable_ss_mask) {
		struct cgroup *scgrp = &cgrp_dfl_root.cgrp;

		/*
		 * Controllers from default hierarchy that need to be rebound
		 * are all disabled together in one go.
		 */
		cgrp_dfl_root.subsys_mask &= ~dfl_disable_ss_mask;
		WARN_ON(cgroup_apply_control(scgrp));
		cgroup_finalize_control(scgrp, 0);
	}

	do_each_subsys_mask(ss, ssid, ss_mask) {
		struct cgroup_root *src_root = ss->root;
		struct cgroup *scgrp = &src_root->cgrp;
		struct cgroup_subsys_state *css = cgroup_css(scgrp, ss);
		struct css_set *cset;

		WARN_ON(!css || cgroup_css(dcgrp, ss));

		if (src_root != &cgrp_dfl_root) {
			/* disable from the source */
			src_root->subsys_mask &= ~(1 << ssid);
			WARN_ON(cgroup_apply_control(scgrp));
			cgroup_finalize_control(scgrp, 0);
		}

		/* rebind */
		RCU_INIT_POINTER(scgrp->subsys[ssid], NULL);
		rcu_assign_pointer(dcgrp->subsys[ssid], css);
		ss->root = dst_root;
		css->cgroup = dcgrp;

		spin_lock_irq(&css_set_lock);
		hash_for_each(css_set_table, i, cset, hlist)
			list_move_tail(&cset->e_cset_node[ss->id],
				       &dcgrp->e_csets[ss->id]);
		spin_unlock_irq(&css_set_lock);

		/* default hierarchy doesn't enable controllers by default */
		dst_root->subsys_mask |= 1 << ssid;
		if (dst_root == &cgrp_dfl_root) {
			static_branch_enable(cgroup_subsys_on_dfl_key[ssid]);
		} else {
			dcgrp->subtree_control |= 1 << ssid;
			static_branch_disable(cgroup_subsys_on_dfl_key[ssid]);
		}

		ret = cgroup_apply_control(dcgrp);
		if (ret)
			pr_warn("partial failure to rebind %s controller (err=%d)\n",
				ss->name, ret);

		if (ss->bind)
			ss->bind(css);
	} while_each_subsys_mask();

	kernfs_activate(dcgrp->kn);
	return 0;
}
```