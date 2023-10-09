# mkdir

## ext4_mkdir
```c
// dir父目录, dentry要创建的目录, mode模式
static int ext4_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	handle_t *handle;
	struct inode *inode;
	int err, err2 = 0, credits, retries = 0;

	// 最大是65000个link
	if (EXT4_DIR_LINK_MAX(dir))
		return -EMLINK;

	// 限额
	err = dquot_initialize(dir);
	if (err)
		return err;

	// what?
	credits = (EXT4_DATA_TRANS_BLOCKS(dir->i_sb) +
		   EXT4_INDEX_EXTRA_TRANS_BLOCKS + 3);
retry:
	// 创建inode
	inode = ext4_new_inode_start_handle(dir, S_IFDIR | mode,
					    &dentry->d_name,
					    0, NULL, EXT4_HT_DIR, credits);
	// handle
	handle = ext4_journal_current_handle();
	err = PTR_ERR(inode);
	if (IS_ERR(inode))
		goto out_stop;

	// 设置各种op
	inode->i_op = &ext4_dir_inode_operations;
	inode->i_fop = &ext4_dir_operations;
	err = ext4_init_new_dir(handle, dir, inode);
	if (err)
		goto out_clear_inode;
	err = ext4_mark_inode_dirty(handle, inode);
	if (!err)
		err = ext4_add_entry(handle, dentry, inode);
	if (err) {
out_clear_inode:
		clear_nlink(inode);
		ext4_orphan_add(handle, inode);
		unlock_new_inode(inode);
		err2 = ext4_mark_inode_dirty(handle, inode);
		if (unlikely(err2))
			err = err2;
		ext4_journal_stop(handle);
		iput(inode);
		goto out_retry;
	}
	ext4_inc_count(dir);

	ext4_update_dx_flag(dir);
	err = ext4_mark_inode_dirty(handle, dir);
	if (err)
		goto out_clear_inode;
	d_instantiate_new(dentry, inode);
	ext4_fc_track_create(handle, dentry);
	if (IS_DIRSYNC(dir))
		ext4_handle_sync(handle);

out_stop:
	if (handle)
		ext4_journal_stop(handle);
out_retry:
	if (err == -ENOSPC && ext4_should_retry_alloc(dir->i_sb, &retries))
		goto retry;
	return err;
}

#define EXT4_LINK_MAX		65000

#define EXT4_DIR_LINK_MAX(dir) unlikely((dir)->i_nlink >= EXT4_LINK_MAX && \
		    !(ext4_has_feature_dir_nlink((dir)->i_sb) && is_dx(dir)))
```

## ext4_init_new_dir
```c
int ext4_init_new_dir(handle_t *handle, struct inode *dir,
			     struct inode *inode)
{
	struct buffer_head *dir_block = NULL;
	struct ext4_dir_entry_2 *de;
	ext4_lblk_t block = 0;
	unsigned int blocksize = dir->i_sb->s_blocksize;
	int csum_size = 0;
	int err;

	// 有校验和特性
	if (ext4_has_metadata_csum(dir->i_sb))
		csum_size = sizeof(struct ext4_dir_entry_tail);

	// 设置状态，
	if (ext4_test_inode_state(inode, EXT4_STATE_MAY_INLINE_DATA)) {
		err = ext4_try_create_inline_dir(handle, dir, inode);
		if (err < 0 && err != -ENOSPC)
			goto out;
		if (!err)
			goto out;
	}

	inode->i_size = 0;
	dir_block = ext4_append(handle, inode, &block);
	if (IS_ERR(dir_block))
		return PTR_ERR(dir_block);
	de = (struct ext4_dir_entry_2 *)dir_block->b_data;
	// 初始化 '.'和'..'的entry
	ext4_init_dot_dotdot(inode, de, blocksize, csum_size, dir->i_ino, 0);
	set_nlink(inode, 2);
	if (csum_size)
		ext4_initialize_dirent_tail(dir_block, blocksize);

	BUFFER_TRACE(dir_block, "call ext4_handle_dirty_metadata");
	err = ext4_handle_dirty_dirblock(handle, inode, dir_block);
	if (err)
		goto out;
	set_buffer_verified(dir_block);
out:
	brelse(dir_block);
	return err;
}

int ext4_try_create_inline_dir(handle_t *handle, struct inode *parent,
			       struct inode *inode)
{
	int ret, inline_size = EXT4_MIN_INLINE_DATA_SIZE;
	struct ext4_iloc iloc;
	struct ext4_dir_entry_2 *de;

	ret = ext4_get_inode_loc(inode, &iloc);
	if (ret)
		return ret;

	ret = ext4_prepare_inline_data(handle, inode, inline_size);
	if (ret)
		goto out;

	/*
	 * For inline dir, we only save the inode information for the ".."
	 * and create a fake dentry to cover the left space.
	 */
	de = (struct ext4_dir_entry_2 *)ext4_raw_inode(&iloc)->i_block;
	de->inode = cpu_to_le32(parent->i_ino);
	de = (struct ext4_dir_entry_2 *)((void *)de + EXT4_INLINE_DOTDOT_SIZE);
	de->inode = 0;
	de->rec_len = ext4_rec_len_to_disk(
				inline_size - EXT4_INLINE_DOTDOT_SIZE,
				inline_size);
	set_nlink(inode, 2);
	inode->i_size = EXT4_I(inode)->i_disksize = inline_size;
out:
	brelse(iloc.bh);
	return ret;
}

static int ext4_prepare_inline_data(handle_t *handle, struct inode *inode,
				    unsigned int len)
{
	int ret, size, no_expand;
	struct ext4_inode_info *ei = EXT4_I(inode);

	// 不支持inline_data
	if (!ext4_test_inode_state(inode, EXT4_STATE_MAY_INLINE_DATA))
		return -ENOSPC;

	size = ext4_get_max_inline_size(inode);
	if (size < len)
		return -ENOSPC;

	ext4_write_lock_xattr(inode, &no_expand);

	if (ei->i_inline_off)
		ret = ext4_update_inline_data(handle, inode, len);
	else
		ret = ext4_create_inline_data(handle, inode, len);

	ext4_write_unlock_xattr(inode, &no_expand);
	return ret;
}

int ext4_get_max_inline_size(struct inode *inode)
{
	int error, max_inline_size;
	struct ext4_iloc iloc;

	// inline数据为0
	if (EXT4_I(inode)->i_extra_isize == 0)
		return 0;

	// 获取inode路径
	error = ext4_get_inode_loc(inode, &iloc);
	if (error) {
		ext4_error_inode_err(inode, __func__, __LINE__, 0, -error,
				     "can't get inode location %lu",
				     inode->i_ino);
		return 0;
	}

	down_read(&EXT4_I(inode)->xattr_sem);
	max_inline_size = get_max_inline_xattr_value_size(inode, &iloc);
	up_read(&EXT4_I(inode)->xattr_sem);

	brelse(iloc.bh);

	// 不支持inline
	if (!max_inline_size)
		return 0;

	// EXT4_MIN_INLINE_DATA_SIZE 就是 i_block 的空间，60字节
	return max_inline_size + EXT4_MIN_INLINE_DATA_SIZE;
}

int ext4_get_inode_loc(struct inode *inode, struct ext4_iloc *iloc)
{
	ext4_fsblk_t err_blk = 0;
	int ret;

	// 计算inode的路径
	ret = __ext4_get_inode_loc(inode->i_sb, inode->i_ino, iloc,
		!ext4_test_inode_state(inode, EXT4_STATE_XATTR), &err_blk);

	if (ret == -EIO)
		ext4_error_inode_block(inode, err_blk, EIO,
					"unable to read itable block");

	return ret;
}

static int __ext4_get_inode_loc(struct super_block *sb, unsigned long ino,
				struct ext4_iloc *iloc, int in_mem,
				ext4_fsblk_t *ret_block)
{
	struct ext4_group_desc	*gdp;
	struct buffer_head	*bh;
	ext4_fsblk_t		block;
	struct blk_plug		plug;
	int			inodes_per_block, inode_offset;

	iloc->bh = NULL;
	// 块号不规范
	if (ino < EXT4_ROOT_INO ||
	    ino > le32_to_cpu(EXT4_SB(sb)->s_es->s_inodes_count))
		return -EFSCORRUPTED;

	// inode所在组号
	iloc->block_group = (ino - 1) / EXT4_INODES_PER_GROUP(sb);
	// 组描述符
	gdp = ext4_get_group_desc(sb, iloc->block_group, NULL);
	if (!gdp)
		return -EIO;

	// 每个块的inode数
	inodes_per_block = EXT4_SB(sb)->s_inodes_per_block;
	// inode组内偏移
	inode_offset = ((ino - 1) %
			EXT4_INODES_PER_GROUP(sb));
	// inode所在块
	block = ext4_inode_table(sb, gdp) + (inode_offset / inodes_per_block);
	// inode在块里的偏移
	iloc->offset = (inode_offset % inodes_per_block) * EXT4_INODE_SIZE(sb);

	// 读块
	bh = sb_getblk(sb, block);
	if (unlikely(!bh))
		return -ENOMEM;
	// 调试
	if (ext4_simulate_fail(sb, EXT4_SIM_INODE_EIO))
		goto simulate_eio;
	// bh不是更新的
	if (!buffer_uptodate(bh)) {
		lock_buffer(bh);

		// 加锁之后可能已经更新
		if (ext4_buffer_uptodate(bh)) {
			/* someone brought it uptodate while we waited */
			unlock_buffer(bh);
			goto has_buffer;
		}

		/*
		 * 如果我们所有的信息都在内存里，而且只对这个块有效，我们不需要读块
		 */
		if (in_mem) {
			struct buffer_head *bitmap_bh;
			int i, start;

			start = inode_offset & ~(inodes_per_block - 1);

			/* Is the inode bitmap in cache? */
			bitmap_bh = sb_getblk(sb, ext4_inode_bitmap(sb, gdp));
			if (unlikely(!bitmap_bh))
				goto make_io;

			/*
			 * If the inode bitmap isn't in cache then the
			 * optimisation may end up performing two reads instead
			 * of one, so skip it.
			 */
			if (!buffer_uptodate(bitmap_bh)) {
				brelse(bitmap_bh);
				goto make_io;
			}
			for (i = start; i < start + inodes_per_block; i++) {
				if (i == inode_offset)
					continue;
				if (ext4_test_bit(i, bitmap_bh->b_data))
					break;
			}
			brelse(bitmap_bh);
			if (i == start + inodes_per_block) {
				/* all other inodes are free, so skip I/O */
				memset(bh->b_data, 0, bh->b_size);
				set_buffer_uptodate(bh);
				unlock_buffer(bh);
				goto has_buffer;
			}
		}

make_io:
		/*
		 * 如果需要做io，就顺便预计一个inode-table.
		 */
		blk_start_plug(&plug);
		// 可以预读
		if (EXT4_SB(sb)->s_inode_readahead_blks) {
			ext4_fsblk_t b, end, table;
			unsigned num;
			// 预读数量
			__u32 ra_blks = EXT4_SB(sb)->s_inode_readahead_blks;

			// ext4对应的inode表
			table = ext4_inode_table(sb, gdp);
			
			// 计算预读起点
			b = block & ~((ext4_fsblk_t) ra_blks - 1);
			if (table > b)
				b = table;
			// 终点
			end = b + ra_blks;
			// 每组inode
			num = EXT4_INODES_PER_GROUP(sb);
			// 有 组校验和时，要预留空间
			if (ext4_has_group_desc_csum(sb))
				num -= ext4_itable_unused_count(sb, gdp);
			// 整个组的block
			table += num / inodes_per_block;
			if (end > table)
				end = table;
			// 读块
			while (b <= end)
				ext4_sb_breadahead_unmovable(sb, b++);
		}

		/*
		 * There are other valid inodes in the buffer, this inode
		 * has in-inode xattrs, or we don't have this inode in memory.
		 * Read the block from disk.
		 */
		trace_ext4_load_inode(sb, ino);
		// 读bh
		ext4_read_bh_nowait(bh, REQ_META | REQ_PRIO, NULL);
		blk_finish_plug(&plug);
		// 等bh读完
		wait_on_buffer(bh);
		if (!buffer_uptodate(bh)) {
		simulate_eio:
			if (ret_block)
				*ret_block = block;
			brelse(bh);
			return -EIO;
		}
	}
has_buffer:
	// 设置bh
	iloc->bh = bh;
	return 0;
}

static int get_max_inline_xattr_value_size(struct inode *inode,
					   struct ext4_iloc *iloc)
{
	struct ext4_xattr_ibody_header *header;
	struct ext4_xattr_entry *entry;
	struct ext4_inode *raw_inode;
	int free, min_offs;

	// xattr起点, EXT4_GOOD_OLD_INODE_SIZE是128
	min_offs = EXT4_SB(inode->i_sb)->s_inode_size -
			EXT4_GOOD_OLD_INODE_SIZE -
			EXT4_I(inode)->i_extra_isize -
			sizeof(struct ext4_xattr_ibody_header);

	/*
	 * We need to subtract another sizeof(__u32) since an in-inode xattr
	 * needs an empty 4 bytes to indicate the gap between the xattr entry
	 * and the name/value pair.
	 */
	// what?
	if (!ext4_test_inode_state(inode, EXT4_STATE_XATTR))
		return EXT4_XATTR_SIZE(min_offs -
			EXT4_XATTR_LEN(strlen(EXT4_XATTR_SYSTEM_DATA)) -
			EXT4_XATTR_ROUND - sizeof(__u32));

	// 获取disk inode
	raw_inode = ext4_raw_inode(iloc);
	// 扩展属性头指针
	header = IHDR(inode, raw_inode);
	// 第一个entry
	entry = IFIRST(header);

	// 遍历所有entry
	for (; !IS_LAST_ENTRY(entry); entry = EXT4_XATTR_NEXT(entry)) {
		if (!entry->e_value_inum && entry->e_value_size) {
			// 值在块内偏移
			size_t offs = le16_to_cpu(entry->e_value_offs);

			// 找出偏移最小值
			if (offs < min_offs)
				min_offs = offs;
		}
	}
	free = min_offs -
		((void *)entry - (void *)IFIRST(header)) - sizeof(__u32);

	if (EXT4_I(inode)->i_inline_off) {
		entry = (struct ext4_xattr_entry *)
			((void *)raw_inode + EXT4_I(inode)->i_inline_off);

		free += EXT4_XATTR_SIZE(le32_to_cpu(entry->e_value_size));
		goto out;
	}

	free -= EXT4_XATTR_LEN(strlen(EXT4_XATTR_SYSTEM_DATA));

	if (free > EXT4_XATTR_ROUND)
		free = EXT4_XATTR_SIZE(free - EXT4_XATTR_ROUND);
	else
		free = 0;

out:
	return free;
}

#define IHDR(inode, raw_inode) \
	((struct ext4_xattr_ibody_header *) \
		((void *)raw_inode + \
		EXT4_GOOD_OLD_INODE_SIZE + \
		EXT4_I(inode)->i_extra_isize))

#define IFIRST(hdr) ((struct ext4_xattr_entry *)((hdr)+1))
```