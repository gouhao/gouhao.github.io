# 目录哈希树

## 1. ext4_dx_add_entry
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
	frame = dx_probe(fname, dir, NULL, frames);
	if (IS_ERR(frame))
		return PTR_ERR(frame);
	entries = frame->entries;
	at = frame->at;
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

	err = add_dirent_to_buf(handle, fname, dir, inode, NULL, bh);
	if (err != -ENOSPC)
		goto cleanup;

	err = 0;
	/* Block full, should compress but for now just split */
	dxtrace(printk(KERN_DEBUG "using %u of %u node entries\n",
		       dx_get_count(entries), dx_get_limit(entries)));
	/* Need to split index? */
	if (dx_get_count(entries) == dx_get_limit(entries)) {
		ext4_lblk_t newblock;
		int levels = frame - frames + 1;
		unsigned int icount;
		int add_level = 1;
		struct dx_entry *entries2;
		struct dx_node *node2;
		struct buffer_head *bh2;

		while (frame > frames) {
			if (dx_get_count((frame - 1)->entries) <
			    dx_get_limit((frame - 1)->entries)) {
				add_level = 0;
				break;
			}
			frame--; /* split higher index block */
			at = frame->at;
			entries = frame->entries;
			restart = 1;
		}
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
		icount = dx_get_count(entries);
		bh2 = ext4_append(handle, dir, &newblock);
		if (IS_ERR(bh2)) {
			err = PTR_ERR(bh2);
			goto cleanup;
		}
		node2 = (struct dx_node *)(bh2->b_data);
		entries2 = node2->entries;
		memset(&node2->fake, 0, sizeof(struct fake_dirent));
		node2->fake.rec_len = ext4_rec_len_to_disk(sb->s_blocksize,
							   sb->s_blocksize);
		BUFFER_TRACE(frame->bh, "get_write_access");
		err = ext4_journal_get_write_access(handle, frame->bh);
		if (err)
			goto journal_error;
		if (!add_level) {
			unsigned icount1 = icount/2, icount2 = icount - icount1;
			unsigned hash2 = dx_get_hash(entries + icount1);
			dxtrace(printk(KERN_DEBUG "Split index %i/%i\n",
				       icount1, icount2));

			BUFFER_TRACE(frame->bh, "get_write_access"); /* index root */
			err = ext4_journal_get_write_access(handle,
							     (frame - 1)->bh);
			if (err)
				goto journal_error;

			memcpy((char *) entries2, (char *) (entries + icount1),
			       icount2 * sizeof(struct dx_entry));
			dx_set_count(entries, icount1);
			dx_set_count(entries2, icount2);
			dx_set_limit(entries2, dx_node_limit(dir));

			/* Which index block gets the new entry? */
			if (at - entries >= icount1) {
				frame->at = at = at - entries - icount1 + entries2;
				frame->entries = entries = entries2;
				swap(frame->bh, bh2);
			}
			dx_insert_block((frame - 1), hash2, newblock);
			dxtrace(dx_show_index("node", frame->entries));
			dxtrace(dx_show_index("node",
			       ((struct dx_node *) bh2->b_data)->entries));
			err = ext4_handle_dirty_dx_node(handle, dir, bh2);
			if (err)
				goto journal_error;
			brelse (bh2);
			err = ext4_handle_dirty_dx_node(handle, dir,
						   (frame - 1)->bh);
			if (err)
				goto journal_error;
			err = ext4_handle_dirty_dx_node(handle, dir,
							frame->bh);
			if (restart || err)
				goto journal_error;
		} else {
			struct dx_root *dxroot;
			memcpy((char *) entries2, (char *) entries,
			       icount * sizeof(struct dx_entry));
			dx_set_limit(entries2, dx_node_limit(dir));

			/* Set up root */
			dx_set_count(entries, 1);
			dx_set_block(entries + 0, newblock);
			dxroot = (struct dx_root *)frames[0].bh->b_data;
			dxroot->info.indirect_levels += 1;
			dxtrace(printk(KERN_DEBUG
				       "Creating %d level index...\n",
				       dxroot->info.indirect_levels));
			err = ext4_handle_dirty_dx_node(handle, dir, frame->bh);
			if (err)
				goto journal_error;
			err = ext4_handle_dirty_dx_node(handle, dir, bh2);
			brelse(bh2);
			restart = 1;
			goto journal_error;
		}
	}
	de = do_split(handle, dir, &bh, frame, &fname->hinfo);
	if (IS_ERR(de)) {
		err = PTR_ERR(de);
		goto cleanup;
	}
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
	// 读块, 第0个块, 块类型是索引
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
	// 取fname里的hinfo, 这个是父目录的hinfo
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

	// 未使用的标志被用了, 则错误
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
	// 第一个entry保存的是管理信息？
	entries = (struct dx_entry *)(((char *)&root->info) +
				      root->info.info_length);

	// entries数量和root的限制不一样
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
		// 设置该层的entries起点
		frame->entries = entries;
		// 设置最接近目标的entry
		frame->at = at;
		// 如果所有层都已读取,则返回
		if (!indirect--)
			// 这里返回的frame是最后一层的指针
			return frame;
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
```