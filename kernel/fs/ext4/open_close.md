# 打开关闭
## 1. 打开文件
```c
static int ext4_file_open(struct inode *inode, struct file *filp)
{
	int ret;

	// 已经强关了，直接退出
	if (unlikely(ext4_forced_shutdown(EXT4_SB(inode->i_sb))))
		return -EIO;

	// 记录上次挂载的目录？
	ret = ext4_sample_last_mounted(inode->i_sb, filp->f_path.mnt);
	if (ret)
		return ret;

	// 加密相关
	ret = fscrypt_file_open(inode, filp);
	if (ret)
		return ret;

	// 校验verity文件，verity不能以写打开。
	// todo: what is verity file?
	ret = fsverity_file_open(inode, filp);
	if (ret)
		return ret;

	// 如果是写打开，则先启动日志	
	if (filp->f_mode & FMODE_WRITE) {
		ret = ext4_inode_attach_jinode(inode);
		if (ret < 0)
			return ret;
	}

	// 默认不等待，异步
	filp->f_mode |= FMODE_NOWAIT | FMODE_BUF_RASYNC;
	return dquot_file_open(inode, filp);
}
```

### 1.1 ext4_inode_attach_jinode
```c
int ext4_inode_attach_jinode(struct inode *inode)
{
	struct ext4_inode_info *ei = EXT4_I(inode);
	struct jbd2_inode *jinode;

	// 有了jinode或者此文件系统没有日志，则退出
	if (ei->jinode || !EXT4_SB(inode->i_sb)->s_journal)
		return 0;

	// 分配
	jinode = jbd2_alloc_inode(GFP_KERNEL);
	spin_lock(&inode->i_lock);

	// ei里没有jinode
	if (!ei->jinode) {
		// 分配失败
		if (!jinode) {
			spin_unlock(&inode->i_lock);
			return -ENOMEM;
		}
		// 设置
		ei->jinode = jinode;
		// 初始化。todo: 后面看
		jbd2_journal_init_jbd_inode(ei->jinode, inode);
		jinode = NULL;
	}
	spin_unlock(&inode->i_lock);
	// jinode不空，说明出现了竞争，有人已经设置了jinode，则释放它
	if (unlikely(jinode != NULL))
		jbd2_free_inode(jinode);
	return 0;
}
```

## 1.2 dquot_file_open
```c
int dquot_file_open(struct inode *inode, struct file *file)
{
	int error;

	// 这个只判断了大文件是否合法
	error = generic_file_open(inode, file);
	if (!error && (file->f_mode & FMODE_WRITE))
		// todo: 配额后面看
		error = dquot_initialize(inode);
	return error;
}

int generic_file_open(struct inode * inode, struct file * filp)
{
	// 没有大文件标志，但是文件大小超过了最大值，出错。
	// MAX_NON_LFS	((1UL<<31) - 1)
	if (!(filp->f_flags & O_LARGEFILE) && i_size_read(inode) > MAX_NON_LFS)
		return -EOVERFLOW;
	return 0;
}
```