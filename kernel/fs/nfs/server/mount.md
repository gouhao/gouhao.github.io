# mount

```c
static struct file_system_type nfsd_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "nfsd",
	.init_fs_context = nfsd_init_fs_context,
	.kill_sb	= nfsd_umount,
};

static const struct fs_context_operations nfsd_fs_context_ops = {
	.free		= nfsd_fs_free_fc,
	.get_tree	= nfsd_fs_get_tree,
};

static int nfsd_init_fs_context(struct fs_context *fc)
{
	put_user_ns(fc->user_ns);
	fc->user_ns = get_user_ns(fc->net_ns->user_ns);
	fc->ops = &nfsd_fs_context_ops;
	return 0;
}

static int nfsd_fs_get_tree(struct fs_context *fc)
{
	return get_tree_keyed(fc, nfsd_fill_super, get_net(fc->net_ns));
}

static int nfsd_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct nfsd_net *nn = net_generic(current->nsproxy->net_ns,
							nfsd_net_id);
	struct dentry *dentry;
	int ret;

	static const struct tree_descr nfsd_files[] = {
		[NFSD_List] = {"exports", &exports_nfsd_operations, S_IRUGO},
		[NFSD_Export_features] = {"export_features",
					&export_features_operations, S_IRUGO},
		[NFSD_FO_UnlockIP] = {"unlock_ip",
					&transaction_ops, S_IWUSR|S_IRUSR},
		[NFSD_FO_UnlockFS] = {"unlock_filesystem",
					&transaction_ops, S_IWUSR|S_IRUSR},
		[NFSD_Fh] = {"filehandle", &transaction_ops, S_IWUSR|S_IRUSR},
		[NFSD_Threads] = {"threads", &transaction_ops, S_IWUSR|S_IRUSR},
		[NFSD_Pool_Threads] = {"pool_threads", &transaction_ops, S_IWUSR|S_IRUSR},
		[NFSD_Pool_Stats] = {"pool_stats", &pool_stats_operations, S_IRUGO},
		[NFSD_Reply_Cache_Stats] = {"reply_cache_stats", &reply_cache_stats_operations, S_IRUGO},
		[NFSD_Versions] = {"versions", &transaction_ops, S_IWUSR|S_IRUSR},
		[NFSD_Ports] = {"portlist", &transaction_ops, S_IWUSR|S_IRUGO},
		[NFSD_MaxBlkSize] = {"max_block_size", &transaction_ops, S_IWUSR|S_IRUGO},
		[NFSD_MaxConnections] = {"max_connections", &transaction_ops, S_IWUSR|S_IRUGO},
#if defined(CONFIG_SUNRPC_GSS) || defined(CONFIG_SUNRPC_GSS_MODULE)
		[NFSD_SupportedEnctypes] = {"supported_krb5_enctypes", &supported_enctypes_ops, S_IRUGO},
#endif /* CONFIG_SUNRPC_GSS or CONFIG_SUNRPC_GSS_MODULE */
#ifdef CONFIG_NFSD_V4
		[NFSD_Leasetime] = {"nfsv4leasetime", &transaction_ops, S_IWUSR|S_IRUSR},
		[NFSD_Gracetime] = {"nfsv4gracetime", &transaction_ops, S_IWUSR|S_IRUSR},
		[NFSD_RecoveryDir] = {"nfsv4recoverydir", &transaction_ops, S_IWUSR|S_IRUSR},
		[NFSD_V4EndGrace] = {"v4_end_grace", &transaction_ops, S_IWUSR|S_IRUGO},
#endif
		/* last one */ {""}
	};

	// 给文件系统填充这些文件
	ret = simple_fill_super(sb, 0x6e667364, nfsd_files);
	if (ret)
		return ret;
	// 创建一个client目录
	dentry = nfsd_mkdir(sb->s_root, NULL, "clients");
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);
	nn->nfsd_client_dir = dentry;
	return 0;
}

int simple_fill_super(struct super_block *s, unsigned long magic,
		      const struct tree_descr *files)
{
	struct inode *inode;
	struct dentry *root;
	struct dentry *dentry;
	int i;

	s->s_blocksize = PAGE_SIZE;
	s->s_blocksize_bits = PAGE_SHIFT;
	s->s_magic = magic;
	s->s_op = &simple_super_operations;
	s->s_time_gran = 1;

	inode = new_inode(s);
	if (!inode)
		return -ENOMEM;
	/*
	 * because the root inode is 1, the files array must not contain an
	 * entry at index 1
	 */
	inode->i_ino = 1;
	inode->i_mode = S_IFDIR | 0755;
	inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);
	inode->i_op = &simple_dir_inode_operations;
	inode->i_fop = &simple_dir_operations;
	set_nlink(inode, 2);
	root = d_make_root(inode);
	if (!root)
		return -ENOMEM;
	for (i = 0; !files->name || files->name[0]; i++, files++) {
		if (!files->name)
			continue;

		/* warn if it tries to conflict with the root inode */
		if (unlikely(i == 1))
			printk(KERN_WARNING "%s: %s passed in a files array"
				"with an index of 1!\n", __func__,
				s->s_type->name);

		dentry = d_alloc_name(root, files->name);
		if (!dentry)
			goto out;
		inode = new_inode(s);
		if (!inode) {
			dput(dentry);
			goto out;
		}
		inode->i_mode = S_IFREG | files->mode;
		inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);
		inode->i_fop = files->ops;
		inode->i_ino = i;
		d_add(dentry, inode);
	}
	s->s_root = root;
	return 0;
out:
	d_genocide(root);
	shrink_dcache_parent(root);
	dput(root);
	return -ENOMEM;
}
```