# fusefs查找文件

```c
static struct dentry *fuse_lookup(struct inode *dir, struct dentry *entry,
				  unsigned int flags)
{
	int err;
	struct fuse_entry_out outarg;
	struct inode *inode;
	struct dentry *newent;
	bool outarg_valid = true;
	bool locked;

	// dir的inode有没有这个标志:FUSE_I_BAD
	if (fuse_is_bad(dir))
		return ERR_PTR(-EIO);

	// 给目录上锁
	locked = fuse_lock_inode(dir);

	// 根据文件名查找inode
	err = fuse_lookup_name(dir->i_sb, get_node_id(dir), &entry->d_name,
			       &outarg, &inode);
	// 解锁目录
	fuse_unlock_inode(dir, locked);
	// 没找到文件
	if (err == -ENOENT) {
		outarg_valid = false;
		err = 0;
	}

	// 其它错误
	if (err)
		goto out_err;

	// 不能找根节点
	err = -EIO;
	if (inode && get_node_id(inode) == FUSE_ROOT_ID)
		goto out_iput;

	// 把inode和dentry关联
	newent = d_splice_alias(inode, entry);
	err = PTR_ERR(newent);
	if (IS_ERR(newent))
		goto out_err;

	entry = newent ? newent : entry;

	if (outarg_valid)
		// 出参是有效的就取消超时
		fuse_change_entry_timeout(entry, &outarg);
	else
		// 返回值无效，就丢掉缓存
		fuse_invalidate_entry_cache(entry);

	if (inode)
		// 这一句只是给父目录设置了一个FUSE_I_ADVISE_RDPLUS标志
		fuse_advise_use_readdirplus(dir);
	return newent;

 out_iput:
	iput(inode);
 out_err:
	return ERR_PTR(err);
}

int fuse_lookup_name(struct super_block *sb, u64 nodeid, const struct qstr *name,
		     struct fuse_entry_out *outarg, struct inode **inode)
{
	struct fuse_mount *fm = get_fuse_mount_super(sb);
	FUSE_ARGS(args);
	struct fuse_forget_link *forget;
	u64 attr_version;
	int err;

	*inode = NULL;
	err = -ENAMETOOLONG;
	// 名称限制为1024
	if (name->len > FUSE_NAME_MAX)
		goto out;


	// 申请一个forget请求
	forget = fuse_alloc_forget();
	err = -ENOMEM;
	if (!forget)
		goto out;

	// 属性的版本号
	attr_version = fuse_get_attr_version(fm->fc);

	// 初始化请求，主要是设置操作码，初始化入参和出参
	fuse_lookup_init(fm->fc, &args, nodeid, name, outarg);
	// 发出请求，这个是同步请求
	err = fuse_simple_request(fm, &args);
	// nodeid为0就当做是没找到文件
	if (err || !outarg->nodeid)
		goto out_put_forget;

	err = -EIO;
	// todo: 这里为什么又要判断一遍
	if (!outarg->nodeid)
		goto out_put_forget;
	// 判断返回的attr是不是无效的
	if (fuse_invalid_attr(&outarg->attr))
		goto out_put_forget;

	// 生成一个inode
	*inode = fuse_iget(sb, outarg->nodeid, outarg->generation,
			   &outarg->attr, entry_attr_timeout(outarg),
			   attr_version);
	err = -ENOMEM;
	// 生成inode为0，那就是没空间了
	if (!*inode) {
		fuse_queue_forget(fm->fc, forget, outarg->nodeid, 1);
		goto out;
	}
	err = 0;

 out_put_forget:
	kfree(forget);
 out:
	return err;
}
```