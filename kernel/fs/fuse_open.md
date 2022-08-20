## fusefs打开文件
```c
static int fuse_open(struct inode *inode, struct file *file)
{
	// 最后一个参数表示，是否是目录
	return fuse_open_common(inode, file, false);
}


int fuse_open_common(struct inode *inode, struct file *file, bool isdir)
{
	struct fuse_mount *fm = get_fuse_mount(inode);
	struct fuse_conn *fc = fm->fc;
	int err;
	// todo: 回写截断？
	bool is_wb_truncate = (file->f_flags & O_TRUNC) &&
			  fc->atomic_o_trunc &&
			  fc->writeback_cache;
	// dax回写截断?
	bool dax_truncate = (file->f_flags & O_TRUNC) &&
			  fc->atomic_o_trunc && FUSE_IS_DAX(inode);

	if (fuse_is_bad(inode))
		return -EIO;

	// 调用通用流程
	err = generic_file_open(inode, file);
	if (err)
		return err;

	// todo: 为什么只在这么情况下加锁
	if (is_wb_truncate || dax_truncate) {
		inode_lock(inode);
		fuse_set_nowrite(inode);
	}

	// todo: dax的流程后面再看
	if (dax_truncate) {
		down_write(&get_fuse_inode(inode)->i_mmap_sem);
		err = fuse_dax_break_layouts(inode, 0, 0);
		if (err)
			goto out;
	}

	// 真正的打开文件
	err = fuse_do_open(fm, get_node_id(inode), file, isdir);
	if (!err)
		fuse_finish_open(inode, file);

out:
	// 下面是各种解锁
	if (dax_truncate)
		up_write(&get_fuse_inode(inode)->i_mmap_sem);

	if (is_wb_truncate | dax_truncate) {
		fuse_release_nowrite(inode);
		inode_unlock(inode);
	}

	return err;
}

int fuse_do_open(struct fuse_mount *fm, u64 nodeid, struct file *file,
		 bool isdir)
{
	struct fuse_conn *fc = fm->fc;
	struct fuse_file *ff;
	// 操作码，打开文件/目录是同一个流程
	int opcode = isdir ? FUSE_OPENDIR : FUSE_OPEN;

	// 创建一个fuse_file对象并初始化
	ff = fuse_file_alloc(fm);
	if (!ff)
		return -ENOMEM;

	// user handle
	ff->fh = 0;
	
	// 默认保持缓存
	ff->open_flags = FOPEN_KEEP_CACHE | (isdir ? FOPEN_CACHE_DIR : 0);

	//  no_opendir/no_open表示当前文件系统是否会响应FUSE_OPENDIR/FUSE_OPEN
	// 这些命令，这两个值默认都是0，由第一次打开文件/目录时改变此值
	if (isdir ? !fc->no_opendir : !fc->no_open) {
		struct fuse_open_out outarg;
		int err;

		// 向用户层发送open命令，同步发送
		err = fuse_send_open(fm, nodeid, file, opcode, &outarg);
		if (!err) {
			// 没有错
			ff->fh = outarg.fh;
			ff->open_flags = outarg.open_flags;

		} else if (err != -ENOSYS) {
			// 其它错误
			fuse_file_free(ff);
			return err;
		} else {
			// 走到这里是ENOSYS，表示当前文件系统不处理相应的命令，设置fc里相应的值
			if (isdir)
				fc->no_opendir = 1;
			else
				fc->no_open = 1;
		}
	}

	// 目录不支持direct_io
	if (isdir)
		ff->open_flags &= ~FOPEN_DIRECT_IO;

	// 设置node号
	ff->nodeid = nodeid;

	// 把文件私有数据设置成ff
	file->private_data = ff;

	return 0;
}

struct fuse_open_in {
	uint32_t	flags;
	uint32_t	unused;
};

struct fuse_open_out {
	uint64_t	fh;
	uint32_t	open_flags;
	uint32_t	padding;
};

static int fuse_send_open(struct fuse_mount *fm, u64 nodeid, struct file *file,
			  int opcode, struct fuse_open_out *outargp)
{
	struct fuse_open_in inarg;
	FUSE_ARGS(args);

	memset(&inarg, 0, sizeof(inarg));
	// 处理标志
	inarg.flags = file->f_flags & ~(O_CREAT | O_EXCL | O_NOCTTY);
	if (!fm->fc->atomic_o_trunc)
		inarg.flags &= ~O_TRUNC;

	args.opcode = opcode;
	args.nodeid = nodeid;

	// 设置入参出差
	args.in_numargs = 1;
	args.in_args[0].size = sizeof(inarg);
	args.in_args[0].value = &inarg;
	args.out_numargs = 1;
	args.out_args[0].size = sizeof(*outargp);
	args.out_args[0].value = outargp;

	// 同步请求
	return fuse_simple_request(fm, &args);
}

void fuse_finish_open(struct inode *inode, struct file *file)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_conn *fc = get_fuse_conn(inode);

	if (ff->open_flags & FOPEN_STREAM)
		// 以 “流“式文件打开。stream_open设置了流的标志及不支持seek等标志
		stream_open(inode, file);
	else if (ff->open_flags & FOPEN_NONSEEKABLE)
		// 不支持seek
		nonseekable_open(inode, file);

	if (fc->atomic_o_trunc && (file->f_flags & O_TRUNC)) {
		// 文件要截断
		struct fuse_inode *fi = get_fuse_inode(inode);

		spin_lock(&fi->lock);
		// 增加版本号
		fi->attr_version = atomic64_inc_return(&fc->attr_version);
		// 设置文件大小为0
		i_size_write(inode, 0);
		spin_unlock(&fi->lock);
		// 截断有关这个inode的所有页缓存
		truncate_pagecache(inode, 0);
		// 让attr无效，下回调用get_attr就会重新从用户空间获取
		fuse_invalidate_attr(inode);
		if (fc->writeback_cache)
			// 更新 m/c_time
			file_update_time(file);
	} else if (!(ff->open_flags & FOPEN_KEEP_CACHE)) {
		// 不用保持页缓存？
		invalidate_inode_pages2(inode->i_mapping);
	}

	if ((file->f_mode & FMODE_WRITE) && fc->writeback_cache)
		// 写到write_entry
		fuse_link_write_file(file);
}
```