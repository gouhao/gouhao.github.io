# 目录哈希树

## 0. 
```c

struct fake_dirent
{
	__le32 inode;
	__le16 rec_len;
	u8 name_len;
	u8 file_type;
};

struct dx_root
{
	// 假的 '.', '..' 目录
	struct fake_dirent dot;
	char dot_name[4];
	struct fake_dirent dotdot;
	char dotdot_name[4];

	// 根节点信息
	struct dx_root_info
	{
		__le32 reserved_zero;
		u8 hash_version;
		u8 info_length; /* 8 */
		u8 indirect_levels;
		u8 unused_flags;
	}
	info;

	// entry数量
	struct dx_entry	entries[];
};

struct dx_node
{
	// 为什么需要一个假的dirent来占位
	struct fake_dirent fake;
	// entry数组
	struct dx_entry	entries[];
};

struct dx_countlimit
{
	__le16 limit; // entry最大限制
	__le16 count; // 当前存的数量?
};

struct dx_entry
{
	__le32 hash; // entry 哈希值
	__le32 block; // 块号
};



struct dx_root
{
	// 假的 '.', '..' 目录
	struct fake_dirent dot;
	char dot_name[4];
	struct fake_dirent dotdot;
	char dotdot_name[4];

	// 根节点信息
	struct dx_root_info
	{
		__le32 reserved_zero;
		u8 hash_version;
		u8 info_length; /* 8 */
		u8 indirect_levels;
		u8 unused_flags;
	}
	info;

	// entry数量
	struct dx_entry	entries[];
};



struct dx_frame
{
	struct buffer_head *bh;
	struct dx_entry *entries;
	struct dx_entry *at;
};

struct dx_map_entry
{
	u32 hash;
	u16 offs;
	u16 size;
};

struct dx_hash_info
{
	u32		hash; // 哈希值
	u32		minor_hash; // 最小哈希值
	int		hash_version; // 哈希版本
	u32		*seed; // 种子
};
```
## 1. make_indexed_dir
```c
// 这个bh是第0块的bh
static int make_indexed_dir(handle_t *handle, struct ext4_filename *fname,
			    struct inode *dir,
			    struct inode *inode, struct buffer_head *bh)
{
	struct buffer_head *bh2;
	struct dx_root	*root;
	// EXT4_HTREE_LEVEL 3
	struct dx_frame	frames[EXT4_HTREE_LEVEL], *frame;
	struct dx_entry *entries;
	struct ext4_dir_entry_2	*de, *de2;
	char		*data2, *top;
	unsigned	len;
	int		retval;
	unsigned	blocksize;
	ext4_lblk_t  block;
	struct fake_dirent *fde;
	int csum_size = 0;

	// 如果有校验和特性,需要预留出来大小
	if (ext4_has_metadata_csum(inode->i_sb))
		csum_size = sizeof(struct ext4_dir_entry_tail);

	// 块大小
	blocksize =  dir->i_sb->s_blocksize;
	dxtrace(printk(KERN_DEBUG "Creating index: inode %lu\n", dir->i_ino));
	BUFFER_TRACE(bh, "get_write_access");
	// 日志
	retval = ext4_journal_get_write_access(handle, bh);
	if (retval) {
		ext4_std_error(dir->i_sb, retval);
		brelse(bh);
		return retval;
	}
	// 第0块现在要用来做根节点
	root = (struct dx_root *) bh->b_data;

	// '..'
	fde = &root->dotdot;
	// 普通块里，前两个entry是'.'和'..', 所以'..'之后就是第1个真正的entry
	de = (struct ext4_dir_entry_2 *)((char *)fde +
		ext4_rec_len_from_disk(fde->rec_len, blocksize));
	// 第一个entry杂可能大于块大小?
	if ((char *) de >= (((char *) root) + blocksize)) {
		EXT4_ERROR_INODE(dir, "invalid rec_len for '..'");
		brelse(bh);
		return -EFSCORRUPTED;
	}
	// 剩余空间的长度
	len = ((char *) root) + (blocksize - csum_size) - (char *) de;

	// 分配一个新块来存放第0个块里的数据, 块号从block里返回
	bh2 = ext4_append(handle, dir, &block);
	if (IS_ERR(bh2)) {
		brelse(bh);
		return PTR_ERR(bh2);
	}
	// 给目录设置index标志
	ext4_set_inode_flag(dir, EXT4_INODE_INDEX);
	// data2是新分配的块，即第1块
	data2 = bh2->b_data;
	
	// 把第0块的数据复制到第1块里
	memcpy(data2, de, len);
	// 第1块的头结点
	de = (struct ext4_dir_entry_2 *) data2;
	// 第1块最后一个节点
	top = data2 + len;
	// 找到第1块最后一个节点
	while ((char *)(de2 = ext4_next_entry(de, blocksize)) < top)
		de = de2;
	// 最后一个结点的rec_len设置为其余所剩空间的
	de->rec_len = ext4_rec_len_to_disk(data2 + (blocksize - csum_size) -
					   (char *) de, blocksize);

	// 如果有校验和,则初始化第1块最后的校验和空间
	if (csum_size)
		ext4_initialize_dirent_tail(bh2, blocksize);

	// '..'entry, root是第0块
	de = (struct ext4_dir_entry_2 *) (&root->dotdot);
	// '..'的长度是2，所以剩余空间就是块大小减2
	// todo: root里不是还有info吗？为什么只减2个？
	de->rec_len = ext4_rec_len_to_disk(blocksize - EXT4_DIR_REC_LEN(2),
					   blocksize);
	// 清空info
	memset (&root->info, 0, sizeof(root->info));
	// info长度就是info结构体的长度
	root->info.info_length = sizeof(root->info);
	// 哈希版本
	root->info.hash_version = EXT4_SB(dir->i_sb)->s_def_hash_version;


	// 第0块的第一个元素，第0个entry不存储哈希值(todo: why?),
	// 存储hash的地方用来存count和limit元数据
	entries = root->entries;
	// 第1个索引的块号为1
	dx_set_block(entries, 1);
	// 数量也为1
	dx_set_count(entries, 1);
	// 根节点最大能存放的entry数
	dx_set_limit(entries, dx_root_limit(dir, sizeof(root->info)));

	// 初始化哈希版本
	fname->hinfo.hash_version = root->info.hash_version;
	if (fname->hinfo.hash_version <= DX_HASH_TEA)
		fname->hinfo.hash_version += EXT4_SB(dir->i_sb)->s_hash_unsigned;
	// 哈希种子
	fname->hinfo.seed = EXT4_SB(dir->i_sb)->s_hash_seed;
	// 计算要添加文件的哈希值
	ext4fs_dirhash(dir, fname_name(fname), fname_len(fname), &fname->hinfo);

	memset(frames, 0, sizeof(frames));
	// 因为此时只有一个块, 所以直使用第一个frame
	frame = frames;
	frame->entries = entries;
	// 新文件要插入的地方，经过上面设置entries指向第1个块，第1个块就是要插入的地方
	frame->at = entries;
	// 这里是第0个bh
	frame->bh = bh;

	// 标脏,这个函数里会计算索引的校验和
	retval = ext4_handle_dirty_dx_node(handle, dir, frame->bh);
	if (retval)
		goto out_frames;	
	// 标脏,这个函数里会计算目录块的校验和
	retval = ext4_handle_dirty_dirblock(handle, dir, bh2);
	if (retval)
		goto out_frames;	

	// bh2的数据就是原来第0块里的entry数据，这里面的entry已经满了，所以把bh2里的entry做分割
	de = do_split(handle,dir, &bh2, frame, &fname->hinfo);
	if (IS_ERR(de)) {
		retval = PTR_ERR(de);
		goto out_frames;
	}

	// 把新文件名加到第1块里
	retval = add_dirent_to_buf(handle, fname, dir, inode, de, bh2);
out_frames:
	// 即使失败也需要标脏, 否则文件系统可能会错误
	if (retval)
		ext4_mark_inode_dirty(handle, dir);
	dx_release(frames);
	brelse(bh2);
	return retval;
}


static inline unsigned dx_root_limit(struct inode *dir, unsigned infosize)
{
	// 根节点,先减去存放 '.', '..'的长度, 再减去存放info本身的长度, 就是剩余的空间
	unsigned entry_space = dir->i_sb->s_blocksize - EXT4_DIR_REC_LEN(1) -
		EXT4_DIR_REC_LEN(2) - infosize;

	// 如果还有元数据校验, 则还要减去dx_tail的空间
	if (ext4_has_metadata_csum(dir->i_sb))
		entry_space -= sizeof(struct dx_tail);
	// 返回能够存放dx_entry的数量
	return entry_space / sizeof(struct dx_entry);
}
```

## 2. ext4_dx_add_entry
```c
static int ext4_dx_add_entry(handle_t *handle, struct ext4_filename *fname,
			     struct inode *dir, struct inode *inode)
{
	// // EXT4_HTREE_LEVEL 3
	struct dx_frame frames[EXT4_HTREE_LEVEL], *frame;
	struct dx_entry *entries, *at;
	struct buffer_head *bh;
	struct super_block *sb = dir->i_sb;
	struct ext4_dir_entry_2 *de;
	int restart;
	int err;

again:
	restart = 0;
	// 先找到索引结点及最后一个结点,返回的frame是最后一个节点
	frame = dx_probe(fname, dir, NULL, frames);
	if (IS_ERR(frame))
		return PTR_ERR(frame);

	// 开始的块
	entries = frame->entries;
	// 小于文件名哈希的entry
	at = frame->at;
	// at的块
	bh = ext4_read_dirblock(dir, dx_get_block(frame->at), DIRENT_HTREE);
	if (IS_ERR(bh)) {
		err = PTR_ERR(bh);
		bh = NULL;
		goto cleanup;
	}

	BUFFER_TRACE(bh, "get_write_access");
	err = ext4_journal_get_write_access(handle, bh);
	if (err)
		goto journal_error;

	// 加到at里, 如果添加成功,则直接退出
	err = add_dirent_to_buf(handle, fname, dir, inode, NULL, bh);
	if (err != -ENOSPC)
		goto cleanup;

	// 走到这儿说明at也没空间了
	err = 0;
	/* Block full, should compress but for now just split */
	dxtrace(printk(KERN_DEBUG "using %u of %u node entries\n",
		       dx_get_count(entries), dx_get_limit(entries)));
	// 如果entry的数量已经达到限制值, 则分割entry
	if (dx_get_count(entries) == dx_get_limit(entries)) {
		ext4_lblk_t newblock;
		// 当前frame所在的层级
		int levels = frame - frames + 1;
		unsigned int icount;
		// 是否要添加新的一级
		int add_level = 1;
		struct dx_entry *entries2;
		struct dx_node *node2;
		struct buffer_head *bh2;

		while (frame > frames) {
			// 判断上一层的entry数量是否达到限制
			if (dx_get_count((frame - 1)->entries) <
			    dx_get_limit((frame - 1)->entries)) {
				add_level = 0;
				break;
			}
			// 要分割再上一层的块
			frame--;
			// 上一级的索引节点
			at = frame->at;
			// 上一级的entry头节点
			entries = frame->entries;
			restart = 1;
		}

		// 需要添加一级,但是级数已达到文件系统最大,则报错
		if (add_level && levels == ext4_dir_htree_level(sb)) {
			ext4_warning(sb, "Directory (ino: %lu) index full, "
					 "reach max htree level :%d",
					 dir->i_ino, levels);
			if (ext4_dir_htree_level(sb) < EXT4_HTREE_LEVEL) {
				ext4_warning(sb, "Large directory feature is "
						 "not enabled on this "
						 "filesystem");
			}
			err = -ENOSPC;
			goto cleanup;
		}

		// entry数量
		icount = dx_get_count(entries);
		// 添加一个新块
		bh2 = ext4_append(handle, dir, &newblock);
		if (IS_ERR(bh2)) {
			err = PTR_ERR(bh2);
			goto cleanup;
		}
		node2 = (struct dx_node *)(bh2->b_data);
		// entry数组
		entries2 = node2->entries;

		// 把fake清0
		memset(&node2->fake, 0, sizeof(struct fake_dirent));
		// fake的长度为块大小
		node2->fake.rec_len = ext4_rec_len_to_disk(sb->s_blocksize,
							   sb->s_blocksize);
		BUFFER_TRACE(frame->bh, "get_write_access");
		err = ext4_journal_get_write_access(handle, frame->bh);
		if (err)
			goto journal_error;
		if (!add_level) { // 不用添加层级
			// 两个人一人一半
			unsigned icount1 = icount/2, icount2 = icount - icount1;

			// 获取icount1的哈希
			unsigned hash2 = dx_get_hash(entries + icount1);
			dxtrace(printk(KERN_DEBUG "Split index %i/%i\n",
				       icount1, icount2));

			BUFFER_TRACE(frame->bh, "get_write_access"); /* index root */
			err = ext4_journal_get_write_access(handle,
							     (frame - 1)->bh);
			if (err)
				goto journal_error;

			// 把icount1及之后的icount2个entry移到entries2里
			memcpy((char *) entries2, (char *) (entries + icount1),
			       icount2 * sizeof(struct dx_entry));
			// 原来的为icount1
			dx_set_count(entries, icount1);
			// 新建的为icount2
			dx_set_count(entries2, icount2);
			// 当前块能保存的entry最大数量
			dx_set_limit(entries2, dx_node_limit(dir));

			// 当at的位置大于icount1时,说明count在icount2里, 所以要计算新at的位置,
			if (at - entries >= icount1) {
				frame->at = at = at - entries - icount1 + entries2;
				frame->entries = entries = entries2;
				swap(frame->bh, bh2);
			}
			// 给上一层插入一个新的索引节点
			dx_insert_block((frame - 1), hash2, newblock);
			dxtrace(dx_show_index("node", frame->entries));
			dxtrace(dx_show_index("node",
			       ((struct dx_node *) bh2->b_data)->entries));
			
			// 新分配的块标脏
			err = ext4_handle_dirty_dx_node(handle, dir, bh2);
			if (err)
				goto journal_error;
			brelse (bh2);
			
			// 上一层父节点的bh标脏
			err = ext4_handle_dirty_dx_node(handle, dir,
						   (frame - 1)->bh);
			if (err)
				goto journal_error;
			// 本层的bh标脏
			err = ext4_handle_dirty_dx_node(handle, dir,
							frame->bh);
			if (restart || err)
				goto journal_error;
		} else {
			// 走到这儿说明所有空间都满了,要添加新的一层


			struct dx_root *dxroot;
			// 把entries里所有的entry都挪到entries2里
			memcpy((char *) entries2, (char *) entries,
			       icount * sizeof(struct dx_entry));
			// 设置entry2的限制
			dx_set_limit(entries2, dx_node_limit(dir));

			// 把entries里的entry数量清1
			dx_set_count(entries, 1);
			// 指向新块
			dx_set_block(entries + 0, newblock);

			dxroot = (struct dx_root *)frames[0].bh->b_data;

			// 根节点的层级数加1
			dxroot->info.indirect_levels += 1;
			dxtrace(printk(KERN_DEBUG
				       "Creating %d level index...\n",
				       dxroot->info.indirect_levels));
			// 把frame标脏
			err = ext4_handle_dirty_dx_node(handle, dir, frame->bh);
			if (err)
				goto journal_error;
			// bh2标脏
			err = ext4_handle_dirty_dx_node(handle, dir, bh2);
			brelse(bh2);
			restart = 1;
			goto journal_error;
		}
	}
	// 分割
	de = do_split(handle, dir, &bh, frame, &fname->hinfo);
	if (IS_ERR(de)) {
		err = PTR_ERR(de);
		goto cleanup;
	}

	// 添加到frame里
	err = add_dirent_to_buf(handle, fname, dir, inode, de, bh);
	goto cleanup;

journal_error:
	ext4_std_error(dir->i_sb, err); /* this is a no-op if err == 0 */
cleanup:
	brelse(bh);
	dx_release(frames);
	/* @restart is true means htree-path has been changed, we need to
	 * repeat dx_probe() to find out valid htree-path
	 */
	if (restart && err == 0)
		goto again;
	return err;
}

// 根据文件名的哈希值, 找到中间的索引节点, 返回的是最后一层的索引节点
static struct dx_frame *
dx_probe(struct ext4_filename *fname, struct inode *dir,
	 struct dx_hash_info *hinfo, struct dx_frame *frame_in)
{
	unsigned count, indirect;
	struct dx_entry *at, *entries, *p, *q, *m;
	struct dx_root *root;
	struct dx_frame *frame = frame_in;
	struct dx_frame *ret_err = ERR_PTR(ERR_BAD_DX_DIR);
	u32 hash;

	// frame_in全部清空
	memset(frame_in, 0, EXT4_HTREE_LEVEL * sizeof(frame_in[0]));
	// 读第0块, 0块是根节点
	frame->bh = ext4_read_dirblock(dir, 0, INDEX);
	// 读失败, 直接返回
	if (IS_ERR(frame->bh))
		return (struct dx_frame *) frame->bh;

	// 第0个块是根节点
	root = (struct dx_root *) frame->bh->b_data;
	// 哈希类型目前只支持这4种
	if (root->info.hash_version != DX_HASH_TEA &&
	    root->info.hash_version != DX_HASH_HALF_MD4 &&
	    root->info.hash_version != DX_HASH_LEGACY) {
		ext4_warning_inode(dir, "Unrecognised inode hash code %u",
				   root->info.hash_version);
		goto fail;
	}
	// 取fname里的hinfo
	if (fname)
		hinfo = &fname->hinfo;
	// 设置哈希版本
	hinfo->hash_version = root->info.hash_version;
	// todo: DX_HASH_TEA 的特殊处理?
	if (hinfo->hash_version <= DX_HASH_TEA)
		hinfo->hash_version += EXT4_SB(dir->i_sb)->s_hash_unsigned;
	// 从超级块里取哈希种子
	hinfo->seed = EXT4_SB(dir->i_sb)->s_hash_seed;
	// 有文件名,则对文件名进行哈希, 结果保存在hinfo里
	if (fname && fname_name(fname))
		ext4fs_dirhash(dir, fname_name(fname), fname_len(fname), hinfo);
	// 文件名对应的哈希值
	hash = hinfo->hash;

	// 使用了未使用的字段, 则错误
	if (root->info.unused_flags & 1) {
		ext4_warning_inode(dir, "Unimplemented hash flags: %#06x",
				   root->info.unused_flags);
		goto fail;
	}

	// 间接层数
	indirect = root->info.indirect_levels;
	// 间接层数不能大于最大值, largedir是3层，非则2层
	if (indirect >= ext4_dir_htree_level(dir->i_sb)) {
		ext4_warning(dir->i_sb,
			     "Directory (ino: %lu) htree depth %#06x exceed"
			     "supported value", dir->i_ino,
			     ext4_dir_htree_level(dir->i_sb));
		// 没有开启大目录
		if (ext4_dir_htree_level(dir->i_sb) < EXT4_HTREE_LEVEL) {
			ext4_warning(dir->i_sb, "Enable large directory "
						"feature to access it");
		}
		goto fail;
	}

	// root->info+info_len就是root->entries.
	// 第一个entry保存的是管理信息
	entries = (struct dx_entry *)(((char *)&root->info) +
				      root->info.info_length);

	// entries数量和root的限制不一样, 一般情况下都一样
	if (dx_get_limit(entries) != dx_root_limit(dir,
						   root->info.info_length)) {
		ext4_warning_inode(dir, "dx entry: limit %u != root limit %u",
				   dx_get_limit(entries),
				   dx_root_limit(dir, root->info.info_length));
		goto fail;
	}

	dxtrace(printk("Look up %x", hash));
	while (1) {
		// 获取entry的数量
		count = dx_get_count(entries);
		// 没有entry或者超过发限制, 则失败
		if (!count || count > dx_get_limit(entries)) {
			ext4_warning_inode(dir,
					   "dx entry: count %u beyond limit %u",
					   count, dx_get_limit(entries));
			goto fail;
		}

		// p是下一个entry
		p = entries + 1;
		// q是最后一个entry
		q = entries + count - 1;
		// 使用二分法查找
		while (p <= q) {

			// 取中间值
			m = p + (q - p) / 2;
			dxtrace(printk(KERN_CONT "."));
			// dx_get_hash: entry->hash

			// 小于中间值向左, 反之向右
			if (dx_get_hash(m) > hash)
				q = m - 1;
			else
				p = m + 1;
		}

		if (0) { // linear search cross check
			unsigned n = count - 1;
			at = entries;
			while (n--)
			{
				dxtrace(printk(KERN_CONT ","));
				if (dx_get_hash(++at) > hash)
				{
					at--;
					break;
				}
			}
			assert (at == p - 1);
		}

		// 最左小于目标哈希的entry
		at = p - 1;
		dxtrace(printk(KERN_CONT " %x->%u\n",
			       at == entries ? 0 : dx_get_hash(at),
			       dx_get_block(at)));
		// 设置该层的entry头
		frame->entries = entries;
		// 设置entry所在的链头(小于目标哈希的节点)
		frame->at = at;
		// 如果所有层都已读取,则返回
		if (!indirect--)
			// 这里返回的frame是最后一层的指针
			return frame;最接近目标的
		// 指向下个frame
		frame++;
		// 读取at所在的块
		frame->bh = ext4_read_dirblock(dir, dx_get_block(at), INDEX);
		if (IS_ERR(frame->bh)) {
			ret_err = (struct dx_frame *) frame->bh;
			frame->bh = NULL;
			goto fail;
		}
		// 第二层的第一个节点就是 dx_node了
		entries = ((struct dx_node *) frame->bh->b_data)->entries;

		// 两个限制数量要相同
		if (dx_get_limit(entries) != dx_node_limit(dir)) {
			ext4_warning_inode(dir,
				"dx entry: limit %u != node limit %u",
				dx_get_limit(entries), dx_node_limit(dir));
			goto fail;
		}
	}

	// 走到这儿表示失败了, 都成功就从上面 `return frame了`

fail:
	// 释放frame的资源
	while (frame >= frame_in) {
		brelse(frame->bh);
		frame--;
	}

	// 这种情况是文件系统有问题了
	if (ret_err == ERR_PTR(ERR_BAD_DX_DIR))
		ext4_warning_inode(dir,
			"Corrupt directory, running e2fsck is recommended");
	return ret_err;
}

static void dx_insert_block(struct dx_frame *frame, u32 hash, ext4_lblk_t block)
{
	// entry头结点
	struct dx_entry *entries = frame->entries;
	// 老entry和新entry
	struct dx_entry *old = frame->at, *new = old + 1;
	// entry的数量
	int count = dx_get_count(entries);

	// 已存在entry数量不能超限
	assert(count < dx_get_limit(entries));
	assert(old < entries + count);

	// 把new及之后的entry挪到new+1上
	memmove(new + 1, new, (char *)(entries + count) - (char *)(new));

	// 设置new的哈希值
	dx_set_hash(new, hash);
	// 对应的块
	dx_set_block(new, block);
	// entry数量加1
	dx_set_count(entries, count + 1);
}

// do_split是新分配一个块,然后把一个满块分割成2个块
static struct ext4_dir_entry_2 *do_split(handle_t *handle, struct inode *dir,
			struct buffer_head **bh,struct dx_frame *frame,
			struct dx_hash_info *hinfo)
{
	unsigned blocksize = dir->i_sb->s_blocksize;
	unsigned count, continued;
	struct buffer_head *bh2;
	ext4_lblk_t newblock;
	u32 hash2;
	struct dx_map_entry *map;
	char *data1 = (*bh)->b_data, *data2;
	unsigned split, move, size;
	struct ext4_dir_entry_2 *de = NULL, *de2;
	int	csum_size = 0;
	int	err = 0, i;

	// 校验和
	if (ext4_has_metadata_csum(dir->i_sb))
		csum_size = sizeof(struct ext4_dir_entry_tail);

	// 给目录分配一个新块，newblock返回的是新块号
	bh2 = ext4_append(handle, dir, &newblock);
	if (IS_ERR(bh2)) {
		brelse(*bh);
		*bh = NULL;
		return (struct ext4_dir_entry_2 *) bh2;
	}

	// 日志相关
	BUFFER_TRACE(*bh, "get_write_access");
	err = ext4_journal_get_write_access(handle, *bh);
	if (err)
		goto journal_error;

	BUFFER_TRACE(frame->bh, "get_write_access");
	err = ext4_journal_get_write_access(handle, frame->bh);
	if (err)
		goto journal_error;

	// 新分配块的数据
	data2 = bh2->b_data;

	// 利用尾部的空间数据做映射entry?
	map = (struct dx_map_entry *) (data2 + blocksize);
	// 给原来的数据做映射
	count = dx_make_map(dir, (struct ext4_dir_entry_2 *) data1,
			     blocksize, hinfo, map);
	// map后退count个数量，即映射后map的起点
	map -= count;
	// 按哈希大小值来排序map
	dx_sort_map(map, count);
	
	
	size = 0;
	move = 0;
	
	// 确定要移动的数量
	for (i = count-1; i >= 0; i--) {
		// 检查是否有entry一半超过了blocksize?
		if (size + map[i].size/2 > blocksize/2)
			break;
		size += map[i].size;
		// 要移动的数量
		move++;
	}
	/*
	 * 我们将要分割的map索引
	 * 
	 * 如果entry的大小和没有超过块的一半, 只需要分割一半的数量, 每个块至少有一半的空间
	 */
	if (i > 0)
		// i > 0 表示有entry超过了块大小的一半
		split = count - move;
	else
		split = count/2;

	// 分割点的哈希值
	hash2 = map[split].hash;
	// 为了解决哈希冲突?
	continued = hash2 == map[split - 1].hash;
	dxtrace(printk(KERN_INFO "Split block %lu at %x, %i/%i\n",
			(unsigned long)dx_get_block(frame->at),
					hash2, split, count-split));

	// 从data1里给data2移动map + split之后的数据
	de2 = dx_move_dirents(data1, data2, map + split, count - split,
			      blocksize);
	// 因为上面从data1里给data2移动了一些数据, data1里有些地方已经空了, 
	// 所以把这些空间压缩一下, 弄的更紧凑一些
	de = dx_pack_dirents(data1, blocksize);

	// 重新计算两个entry的末尾空间
	de->rec_len = ext4_rec_len_to_disk(data1 + (blocksize - csum_size) -
					   (char *) de,
					   blocksize);
	de2->rec_len = ext4_rec_len_to_disk(data2 + (blocksize - csum_size) -
					    (char *) de2,
					    blocksize);
	// 重新初始化两个块的末尾
	if (csum_size) {
		ext4_initialize_dirent_tail(*bh, blocksize);
		ext4_initialize_dirent_tail(bh2, blocksize);
	}

	dxtrace(dx_show_leaf(dir, hinfo, (struct ext4_dir_entry_2 *) data1,
			blocksize, 1));
	dxtrace(dx_show_leaf(dir, hinfo, (struct ext4_dir_entry_2 *) data2,
			blocksize, 1));

	// 如果要加入的项大于分割点,则加到新分配的块里
	if (hinfo->hash >= hash2) {
		swap(*bh, bh2);
		de = de2;
	}
	// 把新块插入到 frame->at+1 的地方
	dx_insert_block(frame, hash2 + continued, newblock);

	// block标脏
	err = ext4_handle_dirty_dirblock(handle, dir, bh2);
	if (err)
		goto journal_error;
	// 索引结点标脏
	err = ext4_handle_dirty_dx_node(handle, dir, frame->bh);
	if (err)
		goto journal_error;
	brelse(bh2);
	dxtrace(dx_show_index("frame", frame->entries));
	return de;

journal_error:
	brelse(*bh);
	brelse(bh2);
	*bh = NULL;
	ext4_std_error(dir->i_sb, err);
	return ERR_PTR(err);
}

static struct ext4_dir_entry_2* dx_pack_dirents(char *base, unsigned blocksize)
{
	struct ext4_dir_entry_2 *next, *to, *prev, *de = (struct ext4_dir_entry_2 *) base;
	unsigned rec_len = 0;

	prev = to = de;
	while ((char*)de < base + blocksize) {
		// 保存下一个节点
		next = ext4_next_entry(de, blocksize);

		// de没被删除,且有文件名
		if (de->inode && de->name_len) {
			// de长度
			rec_len = EXT4_DIR_REC_LEN(de->name_len);
			// de如果在to后面,则移到to的位置上
			if (de > to)
				memmove(to, de, rec_len);
			// 设置to的长度
			to->rec_len = ext4_rec_len_to_disk(rec_len, blocksize);
			prev = to;
			// to递增
			to = (struct ext4_dir_entry_2 *) (((char *) to) + rec_len);
		}
		// 下个节点
		de = next;
	}
	return prev;
}

static struct ext4_dir_entry_2 *
dx_move_dirents(char *from, char *to, struct dx_map_entry *map, int count,
		unsigned blocksize)
{
	unsigned rec_len = 0;

	while (count--) {
		// 从from里取一个entry
		struct ext4_dir_entry_2 *de = (struct ext4_dir_entry_2 *)
						(from + (map->offs<<2));
		rec_len = EXT4_DIR_REC_LEN(de->name_len);
		// 把entry从from移动到to里
		memcpy (to, de, rec_len);
		// 设置to的rec_len
		((struct ext4_dir_entry_2 *) to)->rec_len =
				ext4_rec_len_to_disk(rec_len, blocksize);
		// 把from里的inode为0, 这相当于把from里的entry删了
		de->inode = 0;
		// map和to都递增
		map++;
		to += rec_len;
	}
	// 返回to的最后一个节点
	return (struct ext4_dir_entry_2 *) (to - rec_len);
}

static void dx_sort_map (struct dx_map_entry *map, unsigned count)
{
	struct dx_map_entry *p, *q, *top = map + count - 1;
	int more;
	// 对哈希值进行排序
	while (count > 2) {
		// 选一个count, todo: what?
		count = count*10/13;
		if (count - 9 < 2) /* 9, 10 -> 11 */
			count = 11;
		// p是尾, q是头
		for (p = top, q = p - count; q >= map; p--, q--)
			// 如果p小,则交换pq的值
			if (p->hash < q->hash)
				swap(*p, *q);
	}
	// 再从后到前做一次排序
	do {
		more = 0;
		q = top;
		while (q-- > map) {
			if (q[1].hash >= q[0].hash)
				continue;
			swap(*(q+1), *q);
			more = 1;
		}
	} while(more);
}

static int dx_make_map(struct inode *dir, struct ext4_dir_entry_2 *de,
		       unsigned blocksize, struct dx_hash_info *hinfo,
		       struct dx_map_entry *map_tail)
{
	int count = 0;
	char *base = (char *) de;
	struct dx_hash_info h = *hinfo;

	// 遍历所有entry
	while ((char *) de < base + blocksize) {
		// 有文件名且有inode
		if (de->name_len && de->inode) {
			// 计算文件名的哈希
			ext4fs_dirhash(dir, de->name, de->name_len, &h);
			// 设置映射指向的对应哈希值
			map_tail--;
			map_tail->hash = h.hash;
			// todo: 偏移为啥要除以4?
			map_tail->offs = ((char *) de - base)>>2;
			map_tail->size = le16_to_cpu(de->rec_len);
			count++;
			cond_resched();
		}
		// 下个节点
		de = ext4_next_entry(de, blocksize);
	}
	return count;
}

static inline void dx_set_block(struct dx_entry *entry, ext4_lblk_t value)
{
	entry->block = cpu_to_le32(value);
}
```

## ext4_dx_find_entry
```c
static struct buffer_head * ext4_dx_find_entry(struct inode *dir,
			struct ext4_filename *fname,
			struct ext4_dir_entry_2 **res_dir)
{
	struct super_block * sb = dir->i_sb;
	// EXT4_HTREE_LEVEL 3
	struct dx_frame frames[EXT4_HTREE_LEVEL], *frame;
	struct buffer_head *bh;
	ext4_lblk_t block;
	int retval;

#ifdef CONFIG_FS_ENCRYPTION
	*res_dir = NULL;
#endif
	// 根据文件名的哈希值, 找到中间的索引节点, frame返回的是最后一层的索引节点
	frame = dx_probe(fname, dir, NULL, frames);
	if (IS_ERR(frame))
		return (struct buffer_head *) frame;
	do {
		// 所在的块号
		block = dx_get_block(frame->at);
		// 读取块, 类型是目录哈希树
		bh = ext4_read_dirblock(dir, block, DIRENT_HTREE);
		if (IS_ERR(bh))
			goto errout;

		// 根据文件名在块内搜索目标文件名
		retval = search_dirblock(bh, dir, fname,
					 block << EXT4_BLOCK_SIZE_BITS(sb),
					 res_dir);
		// 成功
		if (retval == 1)
			goto success;
			
		// 没有找到
		brelse(bh);

		// 返回-1是出错
		if (retval == -1) {
			bh = ERR_PTR(ERR_BAD_DX_DIR);
			goto errout;
		}

		// 取下一个节点再试一次
		retval = ext4_htree_next_block(dir, fname->hinfo.hash, frame,
					       frames, NULL);
		// 小于0是读取bh出错,
		if (retval < 0) {
			ext4_warning_inode(dir,
				"error %d reading directory index block",
				retval);
			bh = ERR_PTR(retval);
			goto errout;
		}
	} while (retval == 1);

	bh = NULL;
errout:
	dxtrace(printk(KERN_DEBUG "%s not found\n", fname->usr_fname->name));
success:
	dx_release(frames);
	return bh;
}

static inline int search_dirblock(struct buffer_head *bh,
				  struct inode *dir,
				  struct ext4_filename *fname,
				  unsigned int offset,
				  struct ext4_dir_entry_2 **res_dir)
{
	return ext4_search_dir(bh, bh->b_data, dir->i_sb->s_blocksize, dir,
			       fname, offset, res_dir);
}

int ext4_search_dir(struct buffer_head *bh, char *search_buf, int buf_size,
		    struct inode *dir, struct ext4_filename *fname,
		    unsigned int offset, struct ext4_dir_entry_2 **res_dir)
{
	struct ext4_dir_entry_2 * de;
	char * dlimit;
	int de_len;

	// 文件的目录项是按照 ext4_dir_entry_2 在磁盘上来布局的
	de = (struct ext4_dir_entry_2 *)search_buf;
	// 结尾
	dlimit = search_buf + buf_size;
	while ((char *) de < dlimit) {
		/* 这些代码经常被指数级的执行, 做最小的检查 */
		if ((char *) de + de->name_len <= dlimit &&
			// 比较文件名是否相同
		    ext4_match(dir, fname, de)) {
			/* 找到一个匹配的, 为了确定,做一个全面检查 */
			if (ext4_check_dir_entry(dir, NULL, de, bh, search_buf,
						 buf_size, offset))
				return -1;
			*res_dir = de;
			return 1;
		}
		/* 获取当前entry的长度, 这个包装函数是为了阻止坏块的循环 */
		de_len = ext4_rec_len_from_disk(de->rec_len,
						dir->i_sb->s_blocksize);
		if (de_len <= 0)
			return -1;
		// 获取下一个entry
		offset += de_len;
		de = (struct ext4_dir_entry_2 *) ((char *) de + de_len);
	}
	return 0;
}

static inline bool ext4_match(const struct inode *parent,
			      const struct ext4_filename *fname,
			      const struct ext4_dir_entry_2 *de)
{
	struct fscrypt_name f;
#ifdef CONFIG_UNICODE
	const struct qstr entry = {.name = de->name, .len = de->name_len};
#endif

	// 没有inode肯定不匹配
	if (!de->inode)
		return false;

	// 把2个name放到临时变量里
	f.usr_fname = fname->usr_fname;
	f.disk_name = fname->disk_name;
#ifdef CONFIG_FS_ENCRYPTION
	f.crypto_buf = fname->crypto_buf;
#endif

#ifdef CONFIG_UNICODE
	if (parent->i_sb->s_encoding && IS_CASEFOLDED(parent)) {
		if (fname->cf_name.name) {
			struct qstr cf = {.name = fname->cf_name.name,
					  .len = fname->cf_name.len};
			return !ext4_ci_compare(parent, &cf, &entry, true);
		}
		return !ext4_ci_compare(parent, fname->usr_fname, &entry,
					false);
	}
#endif

	return fscrypt_match_name(&f, de->name, de->name_len);
}

static inline bool fscrypt_match_name(const struct fscrypt_name *fname,
				      const u8 *de_name, u32 de_name_len)
{
	// 长度不相等的, 肯定错了
	if (de_name_len != fname->disk_name.len)
		return false;
	// 比较名称是否相同
	return !memcmp(de_name, fname->disk_name.name, fname->disk_name.len);
}

#define ext4_check_dir_entry(dir, filp, de, bh, buf, size, offset)	\
	unlikely(__ext4_check_dir_entry(__func__, __LINE__, (dir), (filp), \
					(de), (bh), (buf), (size), (offset)))

int __ext4_check_dir_entry(const char *function, unsigned int line,
			   struct inode *dir, struct file *filp,
			   struct ext4_dir_entry_2 *de,
			   struct buffer_head *bh, char *buf, int size,
			   unsigned int offset)
{
	const char *error_msg = NULL;
	// 文件名长度
	const int rlen = ext4_rec_len_from_disk(de->rec_len,
						dir->i_sb->s_blocksize);
	// 下一个entry距离buf的距离
	const int next_offset = ((char *) de - buf) + rlen;

	// entry长度小于文件名是1的长度
	if (unlikely(rlen < EXT4_DIR_REC_LEN(1)))
		error_msg = "rec_len is smaller than minimal";
	// entry长度不是4的倍数
	else if (unlikely(rlen % 4 != 0))
		error_msg = "rec_len % 4 != 0";
	// entry长度小于文件名长度
	else if (unlikely(rlen < EXT4_DIR_REC_LEN(de->name_len)))
		error_msg = "rec_len is too small for name_len";
	// 下一个entry如果大于size, 说明当前检查的entry超过界限了
	else if (unlikely(next_offset > size))
		error_msg = "directory entry overrun";
	// 下一个entry大于末尾只能存放一个的目录长度,且next不是size.
	// todo: 这个为什么出错??
	else if (unlikely(next_offset > size - EXT4_DIR_REC_LEN(1) &&
			  next_offset != size))
		error_msg = "directory entry too close to block end";
	// inode号大于文件系统支持的inode总数
	else if (unlikely(le32_to_cpu(de->inode) >
			le32_to_cpu(EXT4_SB(dir->i_sb)->s_es->s_inodes_count)))
		error_msg = "inode out of bounds";
	else
		// 除了上述情况就是正常的
		return 0;

	// 打印错误日志
	if (filp)
		ext4_error_file(filp, function, line, bh->b_blocknr,
				"bad entry in directory: %s - offset=%u, "
				"inode=%u, rec_len=%d, name_len=%d, size=%d",
				error_msg, offset, le32_to_cpu(de->inode),
				rlen, de->name_len, size);
	else
		ext4_error_inode(dir, function, line, bh->b_blocknr,
				"bad entry in directory: %s - offset=%u, "
				"inode=%u, rec_len=%d, name_len=%d, size=%d",
				 error_msg, offset, le32_to_cpu(de->inode),
				 rlen, de->name_len, size);

	return 1;
}


static int ext4_htree_next_block(struct inode *dir, __u32 hash,
				 struct dx_frame *frame,
				 struct dx_frame *frames,
				 __u32 *start_hash)
{
	struct dx_frame *p;
	struct buffer_head *bh;
	int num_frames = 0;
	__u32 bhash;

	p = frame;
	/*
	 * Find the next leaf page by incrementing the frame pointer.
	 * If we run out of entries in the interior node, loop around and
	 * increment pointer in the parent node.  When we break out of
	 * this loop, num_frames indicates the number of interior
	 * nodes need to be read.
	 */
	while (1) {
		// 下一节点没有超界
		if (++(p->at) < p->entries + dx_get_count(p->entries))
			break;
		// 已找到头
		if (p == frames)
			return 0;
		num_frames++;
		// frame退回到上一层
		p--;
	}

	/*
	 * If the hash is 1, then continue only if the next page has a
	 * continuation hash of any value.  This is used for readdir
	 * handling.  Otherwise, check to see if the hash matches the
	 * desired contiuation hash.  If it doesn't, return since
	 * there's no point to read in the successive index pages.
	 */
	// 获取at的哈希
	bhash = dx_get_hash(p->at);
	// 开始哈希
	if (start_hash)
		*start_hash = bhash;
	// todo: what ?
	if ((hash & 1) == 0) {
		if ((bhash & ~1) != hash)
			return 0;
	}
	/*
	 * If the hash is HASH_NB_ALWAYS, we always go to the next
	 * block so no check is necessary
	 */
	// 读出所有中间节点的新的at节点
	while (num_frames--) {
		// 读at
		bh = ext4_read_dirblock(dir, dx_get_block(p->at), INDEX);
		if (IS_ERR(bh))
			return PTR_ERR(bh);
		// p指向下一个
		p++;
		// 先释放之前的bh
		brelse(p->bh);
		// 设置新值
		p->bh = bh;
		// 设置新的at及entries值
		p->at = p->entries = ((struct dx_node *) bh->b_data)->entries;
	}
	return 1;
}



static inline unsigned dx_node_limit(struct inode *dir)
{
	// 和上面dx_root_limit的限制类似, 第0个位置要保存`struct dx_node`,
	// 所以要减去一个rec_len(0)的长度
	unsigned entry_space = dir->i_sb->s_blocksize - EXT4_DIR_REC_LEN(0);

	if (ext4_has_metadata_csum(dir->i_sb))
		entry_space -= sizeof(struct dx_tail);
	return entry_space / sizeof(struct dx_entry);
}

static inline unsigned dx_get_limit(struct dx_entry *entries)
{
	// 能存放entry的最大数量
	return le16_to_cpu(((struct dx_countlimit *) entries)->limit);
}

static inline unsigned dx_get_count(struct dx_entry *entries)
{
	return le16_to_cpu(((struct dx_countlimit *) entries)->count);
}

```