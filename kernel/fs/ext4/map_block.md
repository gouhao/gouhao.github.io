# ext4_get_block
源码基于5.10

## ext4_bread
```c
struct buffer_head *ext4_bread(handle_t *handle, struct inode *inode,
			       ext4_lblk_t block, int map_flags)
{
	struct buffer_head *bh;
	int ret;

	bh = ext4_getblk(handle, inode, block, map_flags);
	if (IS_ERR(bh))
		return bh;
	if (!bh || ext4_buffer_uptodate(bh))
		return bh;

	ret = ext4_read_bh_lock(bh, REQ_META | REQ_PRIO, true);
	if (ret) {
		put_bh(bh);
		return ERR_PTR(ret);
	}
	return bh;
}

struct buffer_head *ext4_getblk(handle_t *handle, struct inode *inode,
				ext4_lblk_t block, int map_flags)
{
	struct ext4_map_blocks map;
	struct buffer_head *bh;
	int create = map_flags & EXT4_GET_BLOCKS_CREATE;
	int err;

	J_ASSERT((EXT4_SB(inode->i_sb)->s_mount_state & EXT4_FC_REPLAY)
		 || handle != NULL || create == 0);

	// 逻辑块
	map.m_lblk = block;
	// 块数
	map.m_len = 1;
	// 映射块
	err = ext4_map_blocks(handle, inode, &map, map_flags);

	if (err == 0)
		return create ? ERR_PTR(-ENOSPC) : NULL;
	if (err < 0)
		return ERR_PTR(err);

	bh = sb_getblk(inode->i_sb, map.m_pblk);
	if (unlikely(!bh))
		return ERR_PTR(-ENOMEM);
	if (map.m_flags & EXT4_MAP_NEW) {
		J_ASSERT(create != 0);
		J_ASSERT((EXT4_SB(inode->i_sb)->s_mount_state & EXT4_FC_REPLAY)
			 || (handle != NULL));

		/*
		 * Now that we do not always journal data, we should
		 * keep in mind whether this should always journal the
		 * new buffer as metadata.  For now, regular file
		 * writes use ext4_get_block instead, so it's not a
		 * problem.
		 */
		lock_buffer(bh);
		BUFFER_TRACE(bh, "call get_create_access");
		err = ext4_journal_get_create_access(handle, bh);
		if (unlikely(err)) {
			unlock_buffer(bh);
			goto errout;
		}
		if (!buffer_uptodate(bh)) {
			memset(bh->b_data, 0, inode->i_sb->s_blocksize);
			set_buffer_uptodate(bh);
		}
		unlock_buffer(bh);
		BUFFER_TRACE(bh, "call ext4_handle_dirty_metadata");
		err = ext4_handle_dirty_metadata(handle, inode, bh);
		if (unlikely(err))
			goto errout;
	} else
		BUFFER_TRACE(bh, "not a new buffer");
	return bh;
errout:
	brelse(bh);
	return ERR_PTR(err);
}
```
## 1. ext4_get_block
```c
/*
iblock: 要映射的逻辑块
bh: 把iblock给bh映射
create: 是否创建
*/
int ext4_get_block(struct inode *inode, sector_t iblock,
		   struct buffer_head *bh, int create)
{
	return _ext4_get_block(inode, iblock, bh,
				// 是否要创建块
			       create ? EXT4_GET_BLOCKS_CREATE : 0);
}

static int _ext4_get_block(struct inode *inode, sector_t iblock,
			   struct buffer_head *bh, int flags)
{
	// 结果保存在这个里面
	struct ext4_map_blocks map;
	int ret = 0;

	// 有内部数据就出错? todo: why?
	if (ext4_has_inline_data(inode))
		return -ERANGE;

	// 逻辑块
	map.m_lblk = iblock;
	// 把size转换成对应的块数
	// todo: 创建bh时, b_size=1<<i_blkbits, 这里又右移, m_len岂不是恒为 1 ?
	map.m_len = bh->b_size >> inode->i_blkbits;

	// 在逻辑块和物理块之间建立映射
	ret = ext4_map_blocks(ext4_journal_current_handle(), inode, &map,
			      flags);
	if (ret > 0) {
		// 建立映射成功

		// 设置bh的设备, 块, 块号
		map_bh(bh, inode->i_sb, map.m_pblk);
		// 设置bh的map标志
		ext4_update_bh_state(bh, map.m_flags);
		// 设置bh的大小为请求块数的大小
		bh->b_size = inode->i_sb->s_blocksize * map.m_len;
		ret = 0;
	} else if (ret == 0) {
		// 有洞
		
		// 有洞时只更新bh大小, 不更新其他信息
		bh->b_size = inode->i_sb->s_blocksize * map.m_len;
	}
	return ret;
}

static inline void
map_bh(struct buffer_head *bh, struct super_block *sb, sector_t block)
{
	// 设置MAPPED标志
	set_buffer_mapped(bh);
	// 块设置
	bh->b_bdev = sb->s_bdev;
	// 物理块
	bh->b_blocknr = block;
	// 块大小
	bh->b_size = sb->s_blocksize;
}

static void ext4_update_bh_state(struct buffer_head *bh, unsigned long flags)
{
	unsigned long old_state;
	unsigned long new_state;

	// #define EXT4_MAP_FLAGS (EXT4_MAP_NEW | EXT4_MAP_MAPPED | EXT4_MAP_UNWRITTEN | EXT4_MAP_BOUNDARY)
	// 清除其它标志
	flags &= EXT4_MAP_FLAGS;

	// bh没有对应的页, 则清除 EXT4_MAP_FLAGS 标志
	// todo: 什么情况下bh没有映射的页
	if (!bh->b_page) {
		bh->b_state = (bh->b_state & ~EXT4_MAP_FLAGS) | flags;
		return;
	}
	
	// 在有页时需要以原子的方式修改状态, 因为有可能其他人也在修改bh
	do {
		old_state = READ_ONCE(bh->b_state);
		// 先清除old_state里的EXT4_MAP_FLAGS, 再设置需要的flag
		new_state = (old_state & ~EXT4_MAP_FLAGS) | flags;
	} while (unlikely(
		 cmpxchg(&bh->b_state, old_state, new_state) != old_state));
}
```

## 2. ext4_map_blocks
```c
int ext4_map_blocks(handle_t *handle, struct inode *inode,
		    struct ext4_map_blocks *map, int flags)
{
	struct extent_status es;
	int retval;
	int ret = 0;
#ifdef ES_AGGRESSIVE_TEST
	struct ext4_map_blocks orig_map;

	memcpy(&orig_map, map, sizeof(*map));
#endif

	map->m_flags = 0;
	ext_debug(inode, "flag 0x%x, max_blocks %u, logical block %lu\n",
		  flags, map->m_len, (unsigned long) map->m_lblk);

	// 限制要操作的块数为最大值
	if (unlikely(map->m_len > INT_MAX))
		map->m_len = INT_MAX;

	// 逻辑块号大于EXT_MAX_BLOCKS(0xffffffff), 出错
	if (unlikely(map->m_lblk >= EXT_MAX_BLOCKS))
		return -EFSCORRUPTED;

	// 没有 EXT4_FC_REPLAY 挂载 && 找extent
	if (!(EXT4_SB(inode->i_sb)->s_mount_state & EXT4_FC_REPLAY) &&
		// 在es状态树里找，这里是对查找的加速, 如果找到就可以直接返回
	    ext4_es_lookup_extent(inode, map->m_lblk, NULL, &es)) {
		// es正在写或没有写?  todo: written/unwritten什么意思?
		if (ext4_es_is_written(&es) || ext4_es_is_unwritten(&es)) {
			// ext4_es_pblock是第1个物理块，es_lblk是物理块对应的逻辑块
			// 这里是算出 m_lblk 对应的物理块
			map->m_pblk = ext4_es_pblock(&es) +
					map->m_lblk - es.es_lblk;
			// 如果正在写，则是已映射, 否则未写?
			map->m_flags |= ext4_es_is_written(&es) ?
					EXT4_MAP_MAPPED : EXT4_MAP_UNWRITTEN;
			// es里还剩的空间
			retval = es.es_len - (map->m_lblk - es.es_lblk);
			
			// 如果比要求的块数大，则使用要求的块数
			if (retval > map->m_len)
				retval = map->m_len;
			// 否则, 只能使用剩余的块数, 经过上面可以限制到es的最大长度
			map->m_len = retval;
		
		// ext4是延迟或是个洞状态
		} else if (ext4_es_is_delayed(&es) || ext4_es_is_hole(&es)) {
			// 物理块为0
			map->m_pblk = 0;
			// 同上算出最大允许的块数
			retval = es.es_len - (map->m_lblk - es.es_lblk);
			if (retval > map->m_len)
				retval = map->m_len;
			map->m_len = retval;

			// 这里把retval置0, 表示没有实际的物理块
			// 因为洞或延迟写还没有分配块?
			retval = 0;
		} else {
			// 其它状态就是有bug
			BUG();
		}
#ifdef ES_AGGRESSIVE_TEST
		ext4_map_blocks_es_recheck(handle, inode, map,
					   &orig_map, flags);
#endif
		goto found;
	}

	// 走到这儿, 表示在es状态树里没找到

	down_read(&EXT4_I(inode)->i_data_sem);

	// 根据是否有extent特性来决定使用哪种方式来映射块, 这里flag传的是0, 表示如果找不到,则不创建
	if (ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS)) {
		// extent映射
		retval = ext4_ext_map_blocks(handle, inode, map, 0);
	} else {
		// 间接映射
		retval = ext4_ind_map_blocks(handle, inode, map, 0);
	}
	if (retval > 0) {
		// 大于0表示映射成功, 返回值表示映射的块数

		unsigned int status;

		// 已映射的块数和所要求的不一样
		if (unlikely(retval != map->m_len)) {
			ext4_warning(inode->i_sb,
				     "ES len assertion failed for inode "
				     "%lu: retval %d != map->m_len %d",
				     inode->i_ino, retval, map->m_len);
			WARN_ON(1);
		}

		status = map->m_flags & EXT4_MAP_UNWRITTEN ?
				EXTENT_STATUS_UNWRITTEN : EXTENT_STATUS_WRITTEN;
		// todo: what ?
		if (!(flags & EXT4_GET_BLOCKS_DELALLOC_RESERVE) &&
		    !(status & EXTENT_STATUS_WRITTEN) &&
		    ext4_es_scan_range(inode, &ext4_es_is_delayed, map->m_lblk,
				       map->m_lblk + map->m_len - 1))
			status |= EXTENT_STATUS_DELAYED;
		// 把extent插入es树
		ret = ext4_es_insert_extent(inode, map->m_lblk,
					    map->m_len, map->m_pblk, status);
		if (ret < 0)
			retval = ret;
	}
	up_read((&EXT4_I(inode)->i_data_sem));

found:
	// 如果已映射，则检查block的有效性
	if (retval > 0 && map->m_flags & EXT4_MAP_MAPPED) {
		ret = check_block_validity(inode, map);
		// 返回0表成功，非0即失败
		if (ret != 0)
			return ret;
	}

	// 走到这里说明没找到或未映射, 要创建块

	// 如果不需要创建，则直接返回
	if ((flags & EXT4_GET_BLOCKS_CREATE) == 0)
		return retval;

	// 已经映射
	if (retval > 0 && map->m_flags & EXT4_MAP_MAPPED)
		/*
		 * 如果我们需要转换extent到unwritten, 我们将在
		 * ext4_ext_map_blocks里继续做工作
		 */
		if (!(flags & EXT4_GET_BLOCKS_CONVERT_UNWRITTEN))
			return retval;

	// 走到这儿表求要分配新块

	// 先清除所有块映射的标志
	map->m_flags &= ~EXT4_MAP_FLAGS;

	// 分配新块需要给i_data_sem上锁
	down_write(&EXT4_I(inode)->i_data_sem);

	// 这次映射的时候传了flag, 如果有分配块, 则分配
	if (ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS)) {
		// extent分配
		retval = ext4_ext_map_blocks(handle, inode, map, flags);
	} else {
		// 不使用ext,使用原来的三级间接分配
		retval = ext4_ind_map_blocks(handle, inode, map, flags);

		// 分配成功了为什么要清除这个标志？
		if (retval > 0 && map->m_flags & EXT4_MAP_NEW) {
			/*
			 * We allocated new blocks which will result in
			 * i_data's format changing.  Force the migrate
			 * to fail by clearing migrate flags
			 */
			ext4_clear_inode_state(inode, EXT4_STATE_EXT_MIGRATE);
		}

		/*
		 * 在成功分配之后更新那些延迟的保留的块/元数据.我们对于非extent文件
		 * 不支持fallocate,所以我们要更新保留空间在这里
		 */
		if ((retval > 0) &&
			(flags & EXT4_GET_BLOCKS_DELALLOC_RESERVE))
			ext4_da_update_reserve_space(inode, retval, 1);
	}

	// 有分配的块
	if (retval > 0) {
		unsigned int status;

		// 已分配的与需要的块数不一致
		if (unlikely(retval != map->m_len)) {
			ext4_warning(inode->i_sb,
				     "ES len assertion failed for inode "
				     "%lu: retval %d != map->m_len %d",
				     inode->i_ino, retval, map->m_len);
			WARN_ON(1);
		}

		/*
		 * 获取的块需要清0,则清之
		 * 在把它们插入extent状态树前先要进行zeroout块, 否则其它人可能会看到它们,
		 * 而且在清0之前使用它们. 我们也必须在unmap元数据之前清0, 否则回写
		 * 可能会使用块设备上的数据覆盖0
		 */
		if (flags & EXT4_GET_BLOCKS_ZERO &&
		    map->m_flags & EXT4_MAP_MAPPED &&
		    map->m_flags & EXT4_MAP_NEW) {
			// 这个函数会向block层提交一个写0的请求
			ret = ext4_issue_zeroout(inode, map->m_lblk,
						 map->m_pblk, map->m_len);
			if (ret) {
				retval = ret;
				goto out_sem;
			}
		}

		/*
		 * 如果extent已经清0, 我们不需要更新extent的状态树
		 */
		if ((flags & EXT4_GET_BLOCKS_PRE_IO) &&
		    ext4_es_lookup_extent(inode, map->m_lblk, NULL, &es)) {
			if (ext4_es_is_written(&es))
				goto out_sem;
		}

		// 这里和上面的处理相同
		status = map->m_flags & EXT4_MAP_UNWRITTEN ?
				EXTENT_STATUS_UNWRITTEN : EXTENT_STATUS_WRITTEN;
		
		// todo: ?
		if (!(flags & EXT4_GET_BLOCKS_DELALLOC_RESERVE) &&
		    !(status & EXTENT_STATUS_WRITTEN) &&
		    ext4_es_scan_range(inode, &ext4_es_is_delayed, map->m_lblk,
				       map->m_lblk + map->m_len - 1))
			status |= EXTENT_STATUS_DELAYED;
		// 插入es树
		ret = ext4_es_insert_extent(inode, map->m_lblk, map->m_len,
					    map->m_pblk, status);
		if (ret < 0) {
			retval = ret;
			goto out_sem;
		}
	}

out_sem:
	up_write((&EXT4_I(inode)->i_data_sem));
	// 如果已映射
	if (retval > 0 && map->m_flags & EXT4_MAP_MAPPED) {

		// 检查块的有效性
		ret = check_block_validity(inode, map);
		if (ret != 0)
			return ret;

		/*
		 * 提交日志
		 * inode新分配的块它的内核在日志提交之后才可见
		 */
		if (map->m_flags & EXT4_MAP_NEW &&
		    !(map->m_flags & EXT4_MAP_UNWRITTEN) &&
		    !(flags & EXT4_GET_BLOCKS_ZERO) &&
		    !ext4_is_quota_file(inode) &&
		    ext4_should_order_data(inode)) {
			loff_t start_byte =
				(loff_t)map->m_lblk << inode->i_blkbits;
			loff_t length = (loff_t)map->m_len << inode->i_blkbits;

			if (flags & EXT4_GET_BLOCKS_IO_SUBMIT)
				ret = ext4_jbd2_inode_add_wait(handle, inode,
						start_byte, length);
			else
				ret = ext4_jbd2_inode_add_write(handle, inode,
						start_byte, length);
			if (ret)
				return ret;
		}
	}
	// fc相关
	if (retval > 0 && (map->m_flags & EXT4_MAP_UNWRITTEN ||
				map->m_flags & EXT4_MAP_MAPPED))
		ext4_fc_track_range(handle, inode, map->m_lblk,
					map->m_lblk + map->m_len - 1);
	if (retval < 0)
		ext_debug(inode, "failed with err %d\n", retval);
	return retval;
}
```


## 4. ext4_ext_map_blocks
```c
int ext4_ext_map_blocks(handle_t *handle, struct inode *inode,
			struct ext4_map_blocks *map, int flags)
{
	struct ext4_ext_path *path = NULL;
	struct ext4_extent newex, *ex, ex2;
	struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);
	ext4_fsblk_t newblock = 0, pblk;
	int err = 0, depth, ret;
	unsigned int allocated = 0, offset = 0;
	unsigned int allocated_clusters = 0;
	struct ext4_allocation_request ar;
	ext4_lblk_t cluster_offset;

	ext_debug(inode, "blocks %u/%u requested\n", map->m_lblk, map->m_len);
	trace_ext4_ext_map_blocks_enter(inode, map->m_lblk, map->m_len, flags);

	// 从根节点到目标块的路径
	path = ext4_find_extent(inode, map->m_lblk, NULL, 0);
	if (IS_ERR(path)) {
		err = PTR_ERR(path);
		path = NULL;
		goto out;
	}

	// extent树的深度
	depth = ext_depth(inode);

	// depth不为0时,必然有一个extent小于目标块
	// 深度为0,p_ext为空,说明是个新建的文件,一个extent都没有
	if (unlikely(path[depth].p_ext == NULL && depth != 0)) {
		EXT4_ERROR_INODE(inode, "bad extent address "
				 "lblock: %lu, depth: %d pblock %lld",
				 (unsigned long) map->m_lblk, depth,
				 path[depth].p_block);
		err = -EFSCORRUPTED;
		goto out;
	}

	// 最后一个extent
	ex = path[depth].p_ext;
	// 找到了extent
	if (ex) {
		// ex起始逻辑块
		ext4_lblk_t ee_block = le32_to_cpu(ex->ee_block);
		// ex起始物理块
		ext4_fsblk_t ee_start = ext4_ext_pblock(ex);
		unsigned short ee_len;

		/*
		 * unwritten extents被作为洞对待,除非在写期间剪了一部分已经初始化的
		 */
		// extent真实的长度		
		ee_len = ext4_ext_get_actual_len(ex);

		trace_ext4_ext_show_extent(inode, ee_block, ee_start, ee_len);

		// 如果目标block在extent的范围内, 尽量直接用当前的extent
		if (in_range(map->m_lblk, ee_block, ee_len)) {
			// 目标物理块起点
			newblock = map->m_lblk - ee_block + ee_start;
			// 从目标块开始到extent结尾,可用的块数量
			allocated = ee_len - (map->m_lblk - ee_block);
			ext_debug(inode, "%u fit into %u:%d -> %llu\n",
				  map->m_lblk, ee_block, ee_len, newblock);

			/*
			 * 如果extent已经初始化,则检查用户是否想要把它转换成unwritten
			 */
			if ((!ext4_ext_is_unwritten(ex)) &&
			    (flags & EXT4_GET_BLOCKS_CONVERT_UNWRITTEN)) {
				// 转成unwritten. todo: 后面看
				err = convert_initialized_extent(handle,
					inode, map, &path, &allocated);
				goto out;
			} else if (!ext4_ext_is_unwritten(ex)) {
				// 不是unwritten, 用户也不想转

				// 设置已映射标志
				map->m_flags |= EXT4_MAP_MAPPED;
				// 物理块起点
				map->m_pblk = newblock;
				// extent里剩余的块比要求的多,则已要求的为主
				if (allocated > map->m_len)
					allocated = map->m_len;
				// 设置已映射数量
				map->m_len = allocated;
				// 调试打印
				ext4_ext_show_leaf(inode, path);
				// 退出函数, 最终函数返回值是allocated
				goto out;
			}
			
			// 走到这儿表示unwritten情况

			// 处理unwritten的extent
			ret = ext4_ext_handle_unwritten_extents(
				handle, inode, map, &path, flags,
				allocated, newblock);
			if (ret < 0)
				err = ret;
			else
				allocated = ret;
			goto out;
		}
	}

	// 走到这儿, 表示没有找到extent, 要创建extent

	// 如果没有创建块的标志
	if ((flags & EXT4_GET_BLOCKS_CREATE) == 0) {
		ext4_lblk_t hole_start, hole_len;

		// 起始块
		hole_start = map->m_lblk;
		// 确定块的长度. todo: 后面看
		hole_len = ext4_ext_determine_hole(inode, path, &hole_start);
		
		// 把洞放到cache里, 加速后面的访问. todo: 后面看
		ext4_ext_put_gap_in_cache(inode, hole_start, hole_len);

		/* 在上面determine之后, 更新 hole_len 以反映洞的大小*/
		if (hole_start != map->m_lblk)
			hole_len -= map->m_lblk - hole_start;
		// 物理块为0
		map->m_pblk = 0;
		// 取与洞的较小值作为map的长度
		map->m_len = min_t(unsigned int, map->m_len, hole_len);

		// 退出
		goto out;
	}

	// 走到这儿,说明有create标志, 要分配一个块
	
	// 起始块
	newex.ee_block = cpu_to_le32(map->m_lblk);
	// 起始块在一个cluster里的偏移. todo: cluster是多少个块?
	cluster_offset = EXT4_LBLK_COFF(sbi, map->m_lblk);

	// 如果之前找到ex. todo: what?
	if (cluster_offset && ex &&
	    get_implied_cluster_alloc(inode->i_sb, map, ex, path)) {
		ar.len = allocated = map->m_len;
		newblock = map->m_pblk;
		goto got_allocated_blocks;
	}

	// 分配起点
	ar.lleft = map->m_lblk;
	// 找最靠近左边的块, 经过这个函数后lleft指向左边最近的逻辑块, pleft指向物理块
	err = ext4_ext_search_left(inode, path, &ar.lleft, &ar.pleft);
	if (err)
		goto out;

	// 找右边靠近的块. 同上, lright指向右边最接近的块, pright指向其物理块
	ar.lright = map->m_lblk;
	err = ext4_ext_search_right(inode, path, &ar.lright, &ar.pright, &ex2);
	if (err < 0)
		goto out;

	// cluster相关,后面再看
	if ((sbi->s_cluster_ratio > 1) && err &&
	    get_implied_cluster_alloc(inode->i_sb, map, &ex2, path)) {
		ar.len = allocated = map->m_len;
		newblock = map->m_pblk;
		goto got_allocated_blocks;
	}

	// 对长度做出限制, EXT_INIT_MAX_LEN(1UL<<15)
	if (map->m_len > EXT_INIT_MAX_LEN &&
	    !(flags & EXT4_GET_BLOCKS_UNWRIT_EXT))
		map->m_len = EXT_INIT_MAX_LEN;
	
	// EXT_UNWRITTEN_MAX_LEN(EXT_INIT_MAX_LEN - 1 )
	else if (map->m_len > EXT_UNWRITTEN_MAX_LEN &&
		 (flags & EXT4_GET_BLOCKS_UNWRIT_EXT))
		map->m_len = EXT_UNWRITTEN_MAX_LEN;

	// 最终的长度
	newex.ee_len = cpu_to_le16(map->m_len);
	// 检查是否和当前已有的extent重叠, 检查长度的最大值
	err = ext4_ext_check_overlap(sbi, inode, &newex, path);
	if (err)
		// 返回1表示长度变了或是有重叠, 需要重新获取长度
		allocated = ext4_ext_get_actual_len(&newex);
	else
		// 没有重叠, 长度也合法
		allocated = map->m_len;

	ar.inode = inode;
	// 找一个建议的目标
	ar.goal = ext4_ext_find_goal(inode, path, map->m_lblk);
	// 逻辑块号
	ar.logical = map->m_lblk;
	// 偏移
	offset = EXT4_LBLK_COFF(sbi, map->m_lblk);
	// 最终的长度
	ar.len = EXT4_NUM_B2C(sbi, offset+allocated);
	// 目标
	ar.goal -= offset;
	// 逻辑块偏移
	ar.logical -= offset;
	if (S_ISREG(inode->i_mode))
		// 普通文件
		ar.flags = EXT4_MB_HINT_DATA;
	else
		/* disable in-core preallocation for non-regular files */
		ar.flags = 0;
	// 设置不同标志
	if (flags & EXT4_GET_BLOCKS_NO_NORMALIZE)
		ar.flags |= EXT4_MB_HINT_NOPREALLOC;
	if (flags & EXT4_GET_BLOCKS_DELALLOC_RESERVE)
		ar.flags |= EXT4_MB_DELALLOC_RESERVED;
	if (flags & EXT4_GET_BLOCKS_METADATA_NOFAIL)
		ar.flags |= EXT4_MB_USE_RESERVED;
	
	// 分配块
	newblock = ext4_mb_new_blocks(handle, &ar, &err);
	if (!newblock)
		goto out;
	// 分配成功
	allocated_clusters = ar.len;
	ar.len = EXT4_C2B(sbi, ar.len) - offset;
	ext_debug(inode, "allocate new block: goal %llu, found %llu/%u, requested %u\n",
		  ar.goal, newblock, ar.len, allocated);
	// 设置len为最终分配的
	if (ar.len > allocated)
		ar.len = allocated;

got_allocated_blocks:
	// 物理块
	pblk = newblock + offset;
	// 把物理块号存到newex里
	ext4_ext_store_pblock(&newex, pblk);
	// 把块号保存到pblock里
	newex.ee_len = cpu_to_le16(ar.len);
	// 标志未写入
	if (flags & EXT4_GET_BLOCKS_UNWRIT_EXT) {
		ext4_ext_mark_unwritten(&newex);
		map->m_flags |= EXT4_MAP_UNWRITTEN;
	}

	// 插入extent
	err = ext4_ext_insert_extent(handle, inode, &path, &newex, flags);

	// 插入失败
	if (err) {

		// 如果有已分配的,则丢弃之,并释放已分配的块
		if (allocated_clusters) {
			int fb_flags = 0;


			/*
			 * free data blocks we just allocated.
			 * not a good idea to call discard here directly,
			 * but otherwise we'd need to call it every free().
			 */
			ext4_discard_preallocations(inode, 0);
			if (flags & EXT4_GET_BLOCKS_DELALLOC_RESERVE)
				fb_flags = EXT4_FREE_BLOCKS_NO_QUOT_UPDATE;
			ext4_free_blocks(handle, inode, NULL, newblock,
					 EXT4_C2B(sbi, allocated_clusters),
					 fb_flags);
		}
		goto out;
	}

	// 走到这儿表示插入成功

	// 延迟分配
	if (test_opt(inode->i_sb, DELALLOC) && allocated_clusters) {
		if (flags & EXT4_GET_BLOCKS_DELALLOC_RESERVE) {
			/*
			 * When allocating delayed allocated clusters, simply
			 * reduce the reserved cluster count and claim quota
			 */
			ext4_da_update_reserve_space(inode, allocated_clusters,
							1);
		} else {
			ext4_lblk_t lblk, len;
			unsigned int n;

			/*
			 * When allocating non-delayed allocated clusters
			 * (from fallocate, filemap, DIO, or clusters
			 * allocated when delalloc has been disabled by
			 * ext4_nonda_switch), reduce the reserved cluster
			 * count by the number of allocated clusters that
			 * have previously been delayed allocated.  Quota
			 * has been claimed by ext4_mb_new_blocks() above,
			 * so release the quota reservations made for any
			 * previously delayed allocated clusters.
			 */
			lblk = EXT4_LBLK_CMASK(sbi, map->m_lblk);
			len = allocated_clusters << sbi->s_cluster_bits;
			n = ext4_es_delayed_clu(inode, lblk, len);
			if (n > 0)
				ext4_da_update_reserve_space(inode, (int) n, 0);
		}
	}

	// todo:?
	if ((flags & EXT4_GET_BLOCKS_UNWRIT_EXT) == 0)
		ext4_update_inode_fsync_trans(handle, inode, 1);
	else
		ext4_update_inode_fsync_trans(handle, inode, 0);

	// 新的,已映射
	map->m_flags |= (EXT4_MAP_NEW | EXT4_MAP_MAPPED);
	// 保存相关信息
	map->m_pblk = pblk;
	map->m_len = ar.len;
	allocated = map->m_len;
	// debug 打印
	ext4_ext_show_leaf(inode, path);
out:
	ext4_ext_drop_refs(path);
	kfree(path);

	trace_ext4_ext_map_blocks_exit(inode, flags, map,
				       err ? err : allocated);
	return err ? err : allocated;
}


static unsigned int ext4_ext_check_overlap(struct ext4_sb_info *sbi,
					   struct inode *inode,
					   struct ext4_extent *newext,
					   struct ext4_ext_path *path)
{
	ext4_lblk_t b1, b2;
	unsigned int depth, len1;
	unsigned int ret = 0;

	// 起点
	b1 = le32_to_cpu(newext->ee_block);
	// 长度
	len1 = ext4_ext_get_actual_len(newext);
	// 树深度
	depth = ext_depth(inode);
	// 路径深度对应的地方，没有extent，肯定不会重叠
	if (!path[depth].p_ext)
		goto out;
	// extent逻辑块的起点？
	b2 = EXT4_LBLK_CMASK(sbi, le32_to_cpu(path[depth].p_ext->ee_block));

	/*
	 * 如果path里的extent在所请求的块之前, 获取下一个分配块
	 */
	if (b2 < b1) {
		// 获取下一个已分配的块
		b2 = ext4_ext_next_allocated_block(path);
		// 返回 EXT_MAX_BLOCKS 是错误值
		if (b2 == EXT_MAX_BLOCKS)
			goto out;
		b2 = EXT4_LBLK_CMASK(sbi, b2);
	}

	// 检查环绕情况, 如果环绕则长度被限制到EXT_MAX_BLOCKS
	if (b1 + len1 < b1) {
		len1 = EXT_MAX_BLOCKS - b1;
		newext->ee_len = cpu_to_le16(len1);
		ret = 1;
	}

	// 检查重叠情况, 如果重叠则限制到重叠的最大值
	if (b1 + len1 > b2) {
		newext->ee_len = cpu_to_le16(b2 - b1);
		ret = 1;
	}
out:
	return ret;
}
```


## 7. read_extent_tree_block
```c
#define read_extent_tree_block(inode, pblk, depth, flags)		\
	__read_extent_tree_block(__func__, __LINE__, (inode), (pblk),   \
				 (depth), (flags))

static struct buffer_head *
__read_extent_tree_block(const char *function, unsigned int line,
			 struct inode *inode, ext4_fsblk_t pblk, int depth,
			 int flags)
{
	struct buffer_head		*bh;
	int				err;
	gfp_t				gfp_flags = __GFP_MOVABLE | GFP_NOFS;

	// 不能失败
	if (flags & EXT4_EX_NOFAIL)
		gfp_flags |= __GFP_NOFAIL;
	
	// 获取块的bh
	bh = sb_getblk_gfp(inode->i_sb, pblk, gfp_flags);
	if (unlikely(!bh))
		return ERR_PTR(-ENOMEM);

	// bh 不是最新的，则读bh
	if (!bh_uptodate_or_lock(bh)) {
		trace_ext4_ext_load_extent(inode, pblk, _RET_IP_);
		// 读bh，最后一个值是回调函数，传NULL表示同步
		err = ext4_read_bh(bh, 0, NULL);
		if (err < 0)
			goto errout;
	}
	// 已经验证则退出
	if (buffer_verified(bh) && !(flags & EXT4_EX_FORCE_CACHE))
		return bh;

	// 检查块的状态
	err = __ext4_ext_check(function, line, inode,
			       ext_block_hdr(bh), depth, pblk);
	if (err)
		goto errout;
	// 如果没有错误,则设置它的已检查状态
	set_buffer_verified(bh);
	// 缓存extents
	if (!(flags & EXT4_EX_NOCACHE) && depth == 0) {
		struct ext4_extent_header *eh = ext_block_hdr(bh);
		ext4_cache_extents(inode, eh);
	}
	return bh;
errout:
	put_bh(bh);
	return ERR_PTR(err);

}

int ext4_read_bh(struct buffer_head *bh, int op_flags, bh_end_io_t *end_io)
{
	BUG_ON(!buffer_locked(bh));

	// 已经是最新状态，则退出
	if (ext4_buffer_uptodate(bh)) {
		unlock_buffer(bh);
		return 0;
	}
	// 读bh
	__ext4_read_bh(bh, op_flags, end_io);

	// 等待bh的lock状态被清除
	wait_on_buffer(bh);
	// 已经是最新状态，则退出
	if (buffer_uptodate(bh))
		return 0;
	return -EIO;
}

static inline void __ext4_read_bh(struct buffer_head *bh, int op_flags,
				  bh_end_io_t *end_io)
{
	// 清除认证状态
	clear_buffer_verified(bh);

	// 设置回调
	bh->b_end_io = end_io ? end_io : end_buffer_read_sync;
	get_bh(bh);
	//  取始读bh
	submit_bh(REQ_OP_READ, op_flags, bh);
}

static int __ext4_ext_check(const char *function, unsigned int line,
			    struct inode *inode, struct ext4_extent_header *eh,
			    int depth, ext4_fsblk_t pblk)
{
	const char *error_msg;
	int max = 0, err = -EFSCORRUPTED;

	// 魔数不对
	if (unlikely(eh->eh_magic != EXT4_EXT_MAGIC)) {
		error_msg = "invalid magic";
		goto corrupted;
	}

	// 深度不对
	if (unlikely(le16_to_cpu(eh->eh_depth) != depth)) {
		error_msg = "unexpected eh_depth";
		goto corrupted;
	}

	// max为0
	if (unlikely(eh->eh_max == 0)) {
		error_msg = "invalid eh_max";
		goto corrupted;
	}
	// 最大entry数
	max = ext4_ext_max_entries(inode, depth);
	// max不对
	if (unlikely(le16_to_cpu(eh->eh_max) > max)) {
		error_msg = "too large eh_max";
		goto corrupted;
	}

	// entries数大于max
	if (unlikely(le16_to_cpu(eh->eh_entries) > le16_to_cpu(eh->eh_max))) {
		error_msg = "invalid eh_entries";
		goto corrupted;
	}

	// 验证entry数是否合法
	if (!ext4_valid_extent_entries(inode, eh, &pblk, depth)) {
		error_msg = "invalid extent entries";
		goto corrupted;
	}

	// 最大不能超过32
	if (unlikely(depth > 32)) {
		error_msg = "too large eh_depth";
		goto corrupted;
	}
	
	// 校验非根结点块的校验和
	if (ext_depth(inode) != depth &&
	    !ext4_extent_block_csum_verify(inode, eh)) {
		error_msg = "extent tree corrupted";
		err = -EFSBADCRC;
		goto corrupted;
	}
	return 0;

corrupted:
	ext4_error_inode_err(inode, function, line, 0, -err,
			     "pblk %llu bad header/extent: %s - magic %x, "
			     "entries %u, max %u(%u), depth %u(%u)",
			     (unsigned long long) pblk, error_msg,
			     le16_to_cpu(eh->eh_magic),
			     le16_to_cpu(eh->eh_entries),
			     le16_to_cpu(eh->eh_max),
			     max, le16_to_cpu(eh->eh_depth), depth);
	return err;
}

static int ext4_valid_extent_entries(struct inode *inode,
				     struct ext4_extent_header *eh,
				     ext4_fsblk_t *pblk, int depth)
{
	unsigned short entries;
	if (eh->eh_entries == 0)
		return 1;

	entries = le16_to_cpu(eh->eh_entries);

	if (depth == 0) {
		/* leaf entries */
		struct ext4_extent *ext = EXT_FIRST_EXTENT(eh);
		ext4_lblk_t lblock = 0;
		ext4_lblk_t prev = 0;
		int len = 0;
		while (entries) {
			if (!ext4_valid_extent(inode, ext))
				return 0;

			/* Check for overlapping extents */
			lblock = le32_to_cpu(ext->ee_block);
			len = ext4_ext_get_actual_len(ext);
			if ((lblock <= prev) && prev) {
				*pblk = ext4_ext_pblock(ext);
				return 0;
			}
			ext++;
			entries--;
			prev = lblock + len - 1;
		}
	} else {
		struct ext4_extent_idx *ext_idx = EXT_FIRST_INDEX(eh);
		while (entries) {
			if (!ext4_valid_extent_idx(inode, ext_idx))
				return 0;
			ext_idx++;
			entries--;
		}
	}
	return 1;
}
```

## 8. ext4_ext_handle_unwritten_extents
```c
static int
ext4_ext_handle_unwritten_extents(handle_t *handle, struct inode *inode,
			struct ext4_map_blocks *map,
			struct ext4_ext_path **ppath, int flags,
			unsigned int allocated, ext4_fsblk_t newblock)
{
	struct ext4_ext_path __maybe_unused *path = *ppath;
	int ret = 0;
	int err = 0;

	ext_debug(inode, "logical block %llu, max_blocks %u, flags 0x%x, allocated %u\n",
		  (unsigned long long)map->m_lblk, map->m_len, flags,
		  allocated);
	ext4_ext_show_leaf(inode, path);

	/*
	 * 当向unwritten空间写时,我们如果要给新extent分配元数据块时,不允许失败
	 */
	flags |= EXT4_GET_BLOCKS_METADATA_NOFAIL;

	trace_ext4_ext_handle_unwritten_extents(inode, map, flags,
						    allocated, newblock);

	/* get_block() before submitting IO, split the extent */
	if (flags & EXT4_GET_BLOCKS_PRE_IO) {
		ret = ext4_split_convert_extents(handle, inode, map, ppath,
					 flags | EXT4_GET_BLOCKS_CONVERT);
		if (ret < 0) {
			err = ret;
			goto out2;
		}
		/*
		 * shouldn't get a 0 return when splitting an extent unless
		 * m_len is 0 (bug) or extent has been corrupted
		 */
		if (unlikely(ret == 0)) {
			EXT4_ERROR_INODE(inode,
					 "unexpected ret == 0, m_len = %u",
					 map->m_len);
			err = -EFSCORRUPTED;
			goto out2;
		}
		map->m_flags |= EXT4_MAP_UNWRITTEN;
		goto out;
	}
	/* IO 结束后,把已填充的extent转成writen */
	if (flags & EXT4_GET_BLOCKS_CONVERT) {
		err = ext4_convert_unwritten_extents_endio(handle, inode, map,
							   ppath);
		if (err < 0)
			goto out2;
		ext4_update_inode_fsync_trans(handle, inode, 1);
		goto map_out;
	}
	/* buffered IO cases */
	/*
	 * repeat fallocate creation request
	 * we already have an unwritten extent
	 */
	if (flags & EXT4_GET_BLOCKS_UNWRIT_EXT) {
		map->m_flags |= EXT4_MAP_UNWRITTEN;
		goto map_out;
	}

	/* buffered READ or buffered write_begin() lookup */
	if ((flags & EXT4_GET_BLOCKS_CREATE) == 0) {
		/*
		 * We have blocks reserved already.  We
		 * return allocated blocks so that delalloc
		 * won't do block reservation for us.  But
		 * the buffer head will be unmapped so that
		 * a read from the block returns 0s.
		 */
		map->m_flags |= EXT4_MAP_UNWRITTEN;
		goto out1;
	}

	/*
	 * Default case when (flags & EXT4_GET_BLOCKS_CREATE) == 1.
	 * For buffered writes, at writepage time, etc.  Convert a
	 * discovered unwritten extent to written.
	 */
	ret = ext4_ext_convert_to_initialized(handle, inode, map, ppath, flags);
	if (ret < 0) {
		err = ret;
		goto out2;
	}
	ext4_update_inode_fsync_trans(handle, inode, 1);
	/*
	 * shouldn't get a 0 return when converting an unwritten extent
	 * unless m_len is 0 (bug) or extent has been corrupted
	 */
	if (unlikely(ret == 0)) {
		EXT4_ERROR_INODE(inode, "unexpected ret == 0, m_len = %u",
				 map->m_len);
		err = -EFSCORRUPTED;
		goto out2;
	}

out:
	allocated = ret;
	map->m_flags |= EXT4_MAP_NEW;
map_out:
	map->m_flags |= EXT4_MAP_MAPPED;
out1:
	map->m_pblk = newblock;
	if (allocated > map->m_len)
		allocated = map->m_len;
	map->m_len = allocated;
	ext4_ext_show_leaf(inode, path);
out2:
	return err ? err : allocated;
}
```

## 9. ext4_ext_find_goal
```c
static ext4_fsblk_t ext4_ext_find_goal(struct inode *inode,
			      struct ext4_ext_path *path,
			      ext4_lblk_t block)
{
	if (path) {
		// path所在的深度
		int depth = path->p_depth;
		struct ext4_extent *ex;

		/*
		 * Try to predict block placement assuming that we are
		 * filling in a file which will eventually be
		 * non-sparse --- i.e., in the case of libbfd writing
		 * an ELF object sections out-of-order but in a way
		 * the eventually results in a contiguous object or
		 * executable file, or some database extending a table
		 * space file.  However, this is actually somewhat
		 * non-ideal if we are writing a sparse file such as
		 * qemu or KVM writing a raw image file that is going
		 * to stay fairly sparse, since it will end up
		 * fragmenting the file system's free space.  Maybe we
		 * should have some hueristics or some way to allow
		 * userspace to pass a hint to file system,
		 * especially if the latter case turns out to be
		 * common.
		 */
		// path里最后一个节点所在的ext
		ex = path[depth].p_ext;
		if (ex) {
			// 物理块
			ext4_fsblk_t ext_pblk = ext4_ext_pblock(ex);
			// 逻辑块
			ext4_lblk_t ext_block = le32_to_cpu(ex->ee_block);

			// 以已分配的物理块为目标块
			if (block > ext_block)
				// 目标块大于extent起始块

				// 目标块在物理块右边
				return ext_pblk + (block - ext_block);
			else
				// 目标块在物理块左边
				return ext_pblk - (ext_block - block);
		}

		// 走到这儿表示ex为空

		/* 索引是空的, 从索引开始的地方找一个*/
		// 如果有bh, 则以bh所在的块为起点
		if (path[depth].p_bh)
			return path[depth].p_bh->b_blocknr;
	}

	// 如果上面都找失败了, 则从inode所在块组里找一个块
	return ext4_inode_to_goal_block(inode);
}

ext4_fsblk_t ext4_inode_to_goal_block(struct inode *inode)
{
	struct ext4_inode_info *ei = EXT4_I(inode);
	ext4_group_t block_group;
	ext4_grpblk_t colour;
	// 灵活块组大小
	int flex_size = ext4_flex_bg_size(EXT4_SB(inode->i_sb));
	ext4_fsblk_t bg_start;
	ext4_fsblk_t last_block;

	// inode所在的块组
	block_group = ei->i_block_group;
	// EXT4_FLEX_SIZE_DIR_ALLOC_SCHEME=4

	// todo: 下面这啥意思?
	if (flex_size >= EXT4_FLEX_SIZE_DIR_ALLOC_SCHEME) {
		/*
		 * If there are at least EXT4_FLEX_SIZE_DIR_ALLOC_SCHEME
		 * block groups per flexgroup, reserve the first block
		 * group for directories and special files.  Regular
		 * files will start at the second block group.  This
		 * tends to speed up directory access and improves
		 * fsck times.
		 */
		block_group &= ~(flex_size-1);
		if (S_ISREG(inode->i_mode))
			block_group++;
	}
	// 块组里第一个数据块
	bg_start = ext4_group_first_block_no(inode->i_sb, block_group);
	// 块组里最后一个数据块
	last_block = ext4_blocks_count(EXT4_SB(inode->i_sb)->s_es) - 1;

	/*
	 * 如果我们进行延迟分配, 则不需要考虑着色统计
	 */
	if (test_opt(inode->i_sb, DELALLOC))
		return bg_start;

	// 对起点还要做个偏移. todo: 以16为步进 进行偏移? why?
	if (bg_start + EXT4_BLOCKS_PER_GROUP(inode->i_sb) <= last_block)
		colour = (task_pid_nr(current) % 16) *
			(EXT4_BLOCKS_PER_GROUP(inode->i_sb) / 16);
	else
		colour = (task_pid_nr(current) % 16) *
			((last_block - bg_start) / 16);
	return bg_start + colour;
}
```



## 15. ext4_ext_try_to_merge
```c
static void ext4_ext_try_to_merge(handle_t *handle,
				  struct inode *inode,
				  struct ext4_ext_path *path,
				  struct ext4_extent *ex)
{
	struct ext4_extent_header *eh;
	unsigned int depth;
	int merge_done = 0;

	depth = ext_depth(inode);
	// 头不可能为空
	BUG_ON(path[depth].p_hdr == NULL);
	eh = path[depth].p_hdr;

	// 要插入的extent大于第1个, 尝试先和左边的合并
	if (ex > EXT_FIRST_EXTENT(eh))
		// 最后一个参数是合并的起点, 这里传的是 ex - 1 也左边的合并
		merge_done = ext4_ext_try_to_merge_right(inode, path, ex - 1);

	// 如果左边合并失败, 再和右边合并
	if (!merge_done)
		(void) ext4_ext_try_to_merge_right(inode, path, ex);

	// 左右合并完之后, 尝试向上合并, 收缩树
	// 这个函数只处理一种情况: 树深度为1, 根结点只有一个索引, 第1层的entry小于根节点能存储
	// 的最大extent数量.
	ext4_ext_try_to_merge_up(handle, inode, path);
}
```

### 15.1 ext4_ext_try_to_merge_right
```c
static int ext4_ext_try_to_merge_right(struct inode *inode,
				 struct ext4_ext_path *path,
				 struct ext4_extent *ex)
{
	struct ext4_extent_header *eh;
	unsigned int depth, len;
	int merge_done = 0, unwritten;

	depth = ext_depth(inode);
	BUG_ON(path[depth].p_hdr == NULL);
	eh = path[depth].p_hdr;

	// 遍历直到最后一个extent
	while (ex < EXT_LAST_EXTENT(eh)) {
		// 判断ex和后面的能否合并
		if (!ext4_can_extents_be_merged(inode, ex, ex + 1))
			// 这里直接退出循环, 因为和下一个extent不能合并, 后面的就不用判断了, 因为肯定合并不了
			break;
		// 走到这儿表示可以合并

		// written标志
		unwritten = ext4_ext_is_unwritten(ex);
		// ex的长度为它两的长度和
		ex->ee_len = cpu_to_le16(ext4_ext_get_actual_len(ex)
				+ ext4_ext_get_actual_len(ex + 1));
		// 如果unwritten, 则标记
		if (unwritten)
			ext4_ext_mark_unwritten(ex);

		// ex+1 不是最后一个extent
		if (ex + 1 < EXT_LAST_EXTENT(eh)) {
			// 计算需要移动的字节数
			len = (EXT_LAST_EXTENT(eh) - ex - 1)
				* sizeof(struct ext4_extent);
			// 把ex+2的数据移动到ex+1上, 因为ex+1要与前面的合并了
			memmove(ex + 1, ex + 2, len);
		}
		// entry减1, 因为合并了一个
		le16_add_cpu(&eh->eh_entries, -1);
		// 合并完成
		merge_done = 1;
		// todo: 合并之后的entry怎么会为0 ??
		WARN_ON(eh->eh_entries == 0);
		if (!eh->eh_entries)
			EXT4_ERROR_INODE(inode, "eh->eh_entries = 0!");
	}

	return merge_done;
}
```

### 15.2 ext4_can_extents_be_merged
```c
static int ext4_can_extents_be_merged(struct inode *inode,
				      struct ext4_extent *ex1,
				      struct ext4_extent *ex2)
{
	unsigned short ext1_ee_len, ext2_ee_len;

	// written标志不一样则不能合并
	if (ext4_ext_is_unwritten(ex1) != ext4_ext_is_unwritten(ex2))
		return 0;

	ext1_ee_len = ext4_ext_get_actual_len(ex1);
	ext2_ee_len = ext4_ext_get_actual_len(ex2);

	// ex1与ex2不是首尾相连
	if (le32_to_cpu(ex1->ee_block) + ext1_ee_len !=
			le32_to_cpu(ex2->ee_block))
		return 0;

	// 两个extent合并后, 长度超过了最大值
	if (ext1_ee_len + ext2_ee_len > EXT_INIT_MAX_LEN)
		return 0;

	// todo: what?  
	if (ext4_ext_is_unwritten(ex1) &&
		// EXT_UNWRITTEN_MAX_LEN = EXT_INIT_MAX_LEN - 1
	    ext1_ee_len + ext2_ee_len > EXT_UNWRITTEN_MAX_LEN)
		return 0;
#ifdef AGGRESSIVE_TEST
	if (ext1_ee_len >= 4)
		return 0;
#endif

	// 物理块是连续的才可合并. 所以合并的条件是: 1. written状态相关; 2. 逻辑块
	// 连续; 3. 合并后长度没有超过最大值; 4. 物理块连续
	if (ext4_ext_pblock(ex1) + ext1_ee_len == ext4_ext_pblock(ex2))
		return 1;

	return 0;
}
```

## ext4_ext_try_to_merge_up
```c
static void ext4_ext_try_to_merge_up(handle_t *handle,
				     struct inode *inode,
				     struct ext4_ext_path *path)
{
	size_t s;
	// 根能存extent的数量
	unsigned max_root = ext4_ext_space_root(inode, 0);
	ext4_fsblk_t blk;

	// 这个函数只处理一种情况: 树深度为1, 根结点只有一个索引, 第1层的entry小于根节点能存储
	// 的最大extent数量.


	// path0是根, 只收缩深度为1的情况
	if ((path[0].p_depth != 1) ||
		// 深度为1时, 根的entry必須为1
	    (le16_to_cpu(path[0].p_hdr->eh_entries) != 1) ||
	    	// 深度为1, 根entry为1 时, 第1层的entry数必须小于等于根最大extent数, 才有可能合并
	    (le16_to_cpu(path[1].p_hdr->eh_entries) > max_root))
	    	// 其它情况全部return 
		return;

	/*
	 * 我们需要修改块位图和块组描述符来释放extent块, 如果不能获取日志授权则放弃
	 */
	if (ext4_journal_extend(handle, 2,
			ext4_free_metadata_revoke_credits(inode->i_sb, 1)))
		return;

	// 第1层的块号
	blk = ext4_idx_pblock(path[0].p_idx);
	// 第1层索引节点所有entry的字节数
	s = le16_to_cpu(path[1].p_hdr->eh_entries) *
		sizeof(struct ext4_extent_idx);
	// 再加上头
	s += sizeof(struct ext4_extent_header);

	// 设置最大深度
	path[1].p_maxdepth = path[0].p_maxdepth;
	// 把第1层里的所有数据复制到第0层
	memcpy(path[0].p_hdr, path[1].p_hdr, s);
	// 层数为0
	path[0].p_depth = 0;
	// 重新设置p_ext指针
	path[0].p_ext = EXT_FIRST_EXTENT(path[0].p_hdr) +
		(path[1].p_ext - EXT_FIRST_EXTENT(path[1].p_hdr));
	// 最大extent数量
	path[0].p_hdr->eh_max = cpu_to_le16(max_root);

	// 释放p1的bh
	brelse(path[1].p_bh);
	// 释放第1层的块
	ext4_free_blocks(handle, inode, NULL, blk, 1,
			 EXT4_FREE_BLOCKS_METADATA | EXT4_FREE_BLOCKS_FORGET);
}
```