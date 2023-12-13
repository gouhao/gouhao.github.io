# extent
源码基于5.10

extent 使用b+树来存储, 中间存的都是索引结点, 只有叶子里存的是extent. 根结点存在inode->i_data里.

## 0. struct
```c
struct ext4_extent_header {
	__le16	eh_magic; // 魔数：0xf30a，这是写死的
	__le16	eh_entries; // 块已有的entry数量
	__le16	eh_max;	// 块最大可放entry数量
	__le16	eh_depth; // 树深度。根节点是第0层
	__le32	eh_generation; // 树的年代
};

struct ext4_ext_path {
	ext4_fsblk_t			p_block; // 逻辑块
	__u16				p_depth; // 当前深度
	__u16				p_maxdepth; // 当前层级到最后一层的深度
	struct ext4_extent		*p_ext; // 所在的extent
	struct ext4_extent_idx		*p_idx; // 所在的索引, 这个和p_ext互斥, 有我无它
	struct ext4_extent_header	*p_hdr; // 头部
	struct buffer_head		*p_bh; // bh引用
};

struct ext4_extent {
		__le32	ee_block; // 逻辑块起点
		__le16	ee_len;	// extent长度
		__le16	ee_start_hi; // 物理块号高16位
		__le32	ee_start_lo; // 物理块号的低32位
	};
```
## 1. ext4_find_extent
这个函数找的索引和extent都最接近目标块, 且块号都小于目标. 通过这个函数可以找到从根通往目标的路径.
```c
struct ext4_ext_path *
ext4_find_extent(struct inode *inode, ext4_lblk_t block,
		 struct ext4_ext_path **orig_path, int flags)
{
	struct ext4_extent_header *eh;
	struct buffer_head *bh;
	struct ext4_ext_path *path = orig_path ? *orig_path : NULL;
	short int depth, i, ppos = 0;
	int ret;
	gfp_t gfp_flags = GFP_NOFS;

	// 分配内存时不允许失败
	if (flags & EXT4_EX_NOFAIL)
		gfp_flags |= __GFP_NOFAIL;

	// inode->i_data被解释为extent头, header的大小是96字节,i_data是15*32=480字节
	// ext4_extent和ext4_extent_idx都是96字节,所以i_data剩余空间可以放4个extent/extent_idx
	eh = ext_inode_hdr(inode);
	// 树的深度
	depth = ext_depth(inode);

	// EXT4_MAX_EXTENT_DEPTH是5
	if (depth < 0 || depth > EXT4_MAX_EXTENT_DEPTH) {
		EXT4_ERROR_INODE(inode, "inode has invalid extent depth: %d",
				 depth);
		ret = -EFSCORRUPTED;
		goto err;
	}

	if (path) {
		// 释放引用
		ext4_ext_drop_refs(path);
		// 如果当前的树深度大于之前的, 则把它们都置空,重新分配,
		// 因为之前的path空间装不下现在的depth了
		if (depth > path[0].p_maxdepth) {
			kfree(path);
			*orig_path = path = NULL;
		}
	}
	if (!path) {
		// 分配path. depth从0开始, 所以要 +1.
		// todo: 这里为啥是 +2, 多分配一个块？有可能要增加层级吗？
		path = kcalloc(depth + 2, sizeof(struct ext4_ext_path),
				gfp_flags);
		if (unlikely(!path))
			return ERR_PTR(-ENOMEM);
		// path0里存最大深度
		path[0].p_maxdepth = depth + 1;
	}
	// 第0层是i_data里的header, 也就是根结点，根节点没有bh
	path[0].p_hdr = eh;
	path[0].p_bh = NULL;

	i = depth;
	// 如果没有禁用cache && 深度是0, 则先缓存当前extent
	if (!(flags & EXT4_EX_NOCACHE) && depth == 0)
		ext4_cache_extents(inode, eh);
	// 下面这个循环用来找到目标块的索引结点, 这里i是深度, 如果深度为0, 不会进这个循环, 
	// 能过这个循环至少i为1, 也就是有2层
	while (i) {
		ext_debug(inode, "depth %d: num %d, max %d\n",
			  ppos, le16_to_cpu(eh->eh_entries), le16_to_cpu(eh->eh_max));

		// 找到块对应的索引结点, 找的是小于等于目标块的
		ext4_ext_binsearch_idx(inode, path + ppos, block);
		// 对应的下一层的物理块号, p_idx在上面的binsearch里已经设置
		path[ppos].p_block = ext4_idx_pblock(path[ppos].p_idx);
		// 以当前节点为根的深度, 越靠上的节点深度越大
		path[ppos].p_depth = i;
		// 索引结点没有extent
		path[ppos].p_ext = NULL;

		// 读出下一层的物理块
		bh = read_extent_tree_block(inode, path[ppos].p_block, --i,
					    flags);
		// 有错误,则退出
		if (IS_ERR(bh)) {
			ret = PTR_ERR(bh);
			goto err;
		}

		// eh指向下一层的头, 中间节点不存header, bh里所有的数据都用来存idx/extent
		eh = ext_block_hdr(bh);
                // 增加下标
		ppos++;
		// 设置下一层的bh和header指针
		path[ppos].p_bh = bh;
		path[ppos].p_hdr = eh;
	}

	// 设置深度, 走到这里i肯定是0, 因为上面的循环没有break
	path[ppos].p_depth = i;
	// 先把最后一层的这2值清空
	path[ppos].p_ext = NULL;
	path[ppos].p_idx = NULL;

	// ppos指向最后一层
	
	// 在最后一层找起始块小于目标块的extent, 这个函数和上面找索引的类似
	ext4_ext_binsearch(inode, path + ppos, block);

	// 找到了extent
	if (path[ppos].p_ext)
		// 设置extent物理块
		path[ppos].p_block = ext4_ext_pblock(path[ppos].p_ext);

	// 在调试模式下打印状态
	ext4_ext_show_path(inode, path);

	return path;

err:
	ext4_ext_drop_refs(path);
	kfree(path);
	if (orig_path)
		*orig_path = NULL;
	return ERR_PTR(ret);
}
```

### 1.1 ext4_ext_binsearch_idx
使用二分法来搜索最接近目标块的索引结点
```c
static void
ext4_ext_binsearch_idx(struct inode *inode,
			struct ext4_ext_path *path, ext4_lblk_t block)
{
	struct ext4_extent_header *eh = path->p_hdr;
	struct ext4_extent_idx *r, *l, *m;


	ext_debug(inode, "binsearch for %u(idx):  ", block);

	// 第2个索引节点. todo: 为啥从第二个开始?
        // 如果从第1个开始, 下面的循环需要多循环一次?(猜的)
	l = EXT_FIRST_INDEX(eh) + 1;
	// 最后一个索引节点
	r = EXT_LAST_INDEX(eh);
	// 找到离block最近的索引结点
	while (l <= r) {
		// 中间位置
		m = l + (r - l) / 2;

		if (block < le32_to_cpu(m->ei_block))
			// 如果小于中间值,则从左半边搜索
			r = m - 1;
		else
			// 大于或等于中间值,则从右半边搜索
			l = m + 1;
		ext_debug(inode, "%p(%u):%p(%u):%p(%u) ", l,
			  le32_to_cpu(l->ei_block), m, le32_to_cpu(m->ei_block),
			  r, le32_to_cpu(r->ei_block));
	}

	path->p_idx = l - 1;
	ext_debug(inode, "  -> %u->%lld ", le32_to_cpu(path->p_idx->ei_block),
		  ext4_idx_pblock(path->p_idx));

	// 调试开关
#ifdef CHECK_BINSEARCH
...
#endif
}
```

### 1.2 ext4_ext_binsearch
使用二分法搜索extent
```c
static void
ext4_ext_binsearch(struct inode *inode,
		struct ext4_ext_path *path, ext4_lblk_t block)
{
	struct ext4_extent_header *eh = path->p_hdr;
	struct ext4_extent *r, *l, *m;

	// 叶结点是空的直接返回
	if (eh->eh_entries == 0) {
		return;
	}

	ext_debug(inode, "binsearch for %u:  ", block);

	// 第2个extent.
	l = EXT_FIRST_EXTENT(eh) + 1;
	// 最后一个extent
	r = EXT_LAST_EXTENT(eh);

	// 采用二分法搜索
	while (l <= r) {
		m = l + (r - l) / 2;
		if (block < le32_to_cpu(m->ee_block))
			r = m - 1;
		else
			l = m + 1;
		ext_debug(inode, "%p(%u):%p(%u):%p(%u) ", l,
			  le32_to_cpu(l->ee_block), m, le32_to_cpu(m->ee_block),
			  r, le32_to_cpu(r->ee_block));
	}

	// l是最接近block的extent
	path->p_ext = l - 1;
	ext_debug(inode, "  -> %d:%llu:[%d]%d ",
			le32_to_cpu(path->p_ext->ee_block),
			ext4_ext_pblock(path->p_ext),
			ext4_ext_is_unwritten(path->p_ext),
			ext4_ext_get_actual_len(path->p_ext));

	// 调试相关
#ifdef CHECK_BINSEARCH
	...
#endif

}
```

## 2. ext4_ext_search_left/right
这2个函数用来找到离目标块 左, 右 最近的已分配块, 出参是 logical(逻辑块) 和 phys(物理块), 这2个出参用于分配目标块时做参考.

```c
static int ext4_ext_search_left(struct inode *inode,
				struct ext4_ext_path *path,
				ext4_lblk_t *logical, ext4_fsblk_t *phys)
{
	struct ext4_extent_idx *ix;
	struct ext4_extent *ex;
	int depth, ee_len;

	// path什么时候会等于NULL?
	if (unlikely(path == NULL)) {
		EXT4_ERROR_INODE(inode, "path == NULL *logical %d!", *logical);
		return -EFSCORRUPTED;
	}
	// 路径的深度
	depth = path->p_depth;
	*phys = 0;

	// 如果深度是0, extent为空, 那就不用搜索了
	if (depth == 0 && path->p_ext == NULL)
		return 0;

	// 走到这儿说明深度不为0或者ext不为NULL

	// 这里取的是最后一层的extent
	ex = path[depth].p_ext;

	// 这里ex可能为NULL, 为什么不判断呢?
	ee_len = ext4_ext_get_actual_len(ex);
	/* 通常path里的extent起始块比目标块小, 但是它有可能是文件里的第一个extent*/
	if (*logical < le32_to_cpu(ex->ee_block)) {
		// 小于ex的块的起点

		// ex如果不是第1块, 则找错了..
		if (unlikely(EXT_FIRST_EXTENT(path[depth].p_hdr) != ex)) {
			EXT4_ERROR_INODE(inode,
					 "EXT_FIRST_EXTENT != ex *logical %d ee_block %d!",
					 *logical, le32_to_cpu(ex->ee_block));
			return -EFSCORRUPTED;
		}

		while (--depth >= 0) {
			// 索引块
			ix = path[depth].p_idx;
			// 不是第一个索引块,则出错?
			if (unlikely(ix != EXT_FIRST_INDEX(path[depth].p_hdr))) {
				EXT4_ERROR_INODE(inode,
				  "ix (%d) != EXT_FIRST_INDEX (%d) (depth %d)!",
				  ix != NULL ? le32_to_cpu(ix->ei_block) : 0,
				  EXT_FIRST_INDEX(path[depth].p_hdr) != NULL ?
		le32_to_cpu(EXT_FIRST_INDEX(path[depth].p_hdr)->ei_block) : 0,
				  depth);
				return -EFSCORRUPTED;
			}
		}

		// 这种情况下就以目标块为主, 直接返回
		return 0;
	}

	// 走到这儿说明目标块大于extent的起点, 下面这个判断表示目标块在ex的范围内, 
	// 这种情况是不应该走到ext4_ext_search函数里来的, 所以出错
	if (unlikely(*logical < (le32_to_cpu(ex->ee_block) + ee_len))) {
		EXT4_ERROR_INODE(inode,
				 "logical %d < ee_block %d + ee_len %d!",
				 *logical, le32_to_cpu(ex->ee_block), ee_len);
		return -EFSCORRUPTED;
	}

	// 走到这儿, *logical >= ex->ee_block + ee_len

	// 所以左边最接近的逻辑块是extent的最后一块
	*logical = le32_to_cpu(ex->ee_block) + ee_len - 1;
	// 对应的物理块
	*phys = ext4_ext_pblock(ex) + ee_len - 1;
	return 0;
}

static int ext4_ext_search_right(struct inode *inode,
				 struct ext4_ext_path *path,
				 ext4_lblk_t *logical, ext4_fsblk_t *phys,
				 struct ext4_extent *ret_ex)
{
	struct buffer_head *bh = NULL;
	struct ext4_extent_header *eh;
	struct ext4_extent_idx *ix;
	struct ext4_extent *ex;
	int depth;	/* Note, NOT eh_depth; depth from top of tree */
	int ee_len;

	// path不能等于NULL. todo: why?
	if (unlikely(path == NULL)) {
		EXT4_ERROR_INODE(inode, "path == NULL *logical %d!", *logical);
		return -EFSCORRUPTED;
	}

	// 深度
	depth = path->p_depth;
	// 物理块
	*phys = 0;

	// 路径为空
	if (depth == 0 && path->p_ext == NULL)
		return 0;

	// 走到这儿说明深度不为0或者ext不为NULL

	/* 通常path里的extent起始块比目标块小, 但是它有可能是文件里的第一个extent*/
	ex = path[depth].p_ext;
	// extent长度
	ee_len = ext4_ext_get_actual_len(ex);
	if (*logical < le32_to_cpu(ex->ee_block)) {
		// 走到这个分支只有一种情况, 就是ex是第1个extent
		if (unlikely(EXT_FIRST_EXTENT(path[depth].p_hdr) != ex)) {
			EXT4_ERROR_INODE(inode,
					 "first_extent(path[%d].p_hdr) != ex",
					 depth);
			return -EFSCORRUPTED;
		}

		// 同样, 索引块也必须是第1个块
		while (--depth >= 0) {
			ix = path[depth].p_idx;
			if (unlikely(ix != EXT_FIRST_INDEX(path[depth].p_hdr))) {
				EXT4_ERROR_INODE(inode,
						 "ix != EXT_FIRST_INDEX *logical %d!",
						 *logical);
				return -EFSCORRUPTED;
			}
		}
		// 找到extent
		goto found_extent;
	}

	

	// 走到这儿说明目标块大于extent的起点, 下面这个判断表示目标块在ex的范围内, 
	// 这种情况是不应该走到ext4_ext_search函数里来的, 所以出错
	if (unlikely(*logical < (le32_to_cpu(ex->ee_block) + ee_len))) {
		EXT4_ERROR_INODE(inode,
				 "logical %d < ee_block %d + ee_len %d!",
				 *logical, le32_to_cpu(ex->ee_block), ee_len);
		return -EFSCORRUPTED;
	}

	// 走到这儿, *logical >= ex->ee_block + ee_len

	// 如果ex不是最后一个extent, 则直接使用下个extent
	if (ex != EXT_LAST_EXTENT(path[depth].p_hdr)) {
		ex++;
		goto found_extent;
	}

	// 走到这儿说明ex所在的叶结点也满了, 所以向上找一个有空闲的索引结点
	while (--depth >= 0) {
		ix = path[depth].p_idx;
		// 有空闲的索引结点
		if (ix != EXT_LAST_INDEX(path[depth].p_hdr))
			goto got_index;
	}

	// 没找到extent和索引, 说明整个树都满了, 需要增加树的层级
	return 0;

got_index:
	/* 我们找到了右边的下标，跟着它找到右边最接近的分配块 */
	// 从下个索引开始
	ix++;
	// ix对应的物理块
	block = ext4_idx_pblock(ix);
	// 遍历直到最大层级, 找到最后idx的物理块
	// 注意这里是先++, 所以不会遍历的叶子结点
	while (++depth < path->p_depth) {
		// 读物理块
		bh = read_extent_tree_block(inode, block,
					    path->p_depth - depth, 0);
		if (IS_ERR(bh))
			return PTR_ERR(bh);
		eh = ext_block_hdr(bh);
		ix = EXT_FIRST_INDEX(eh);
		block = ext4_idx_pblock(ix);
		put_bh(bh);
	}

	// 读到extent所在的块
	bh = read_extent_tree_block(inode, block, path->p_depth - depth, 0);
	if (IS_ERR(bh))
		return PTR_ERR(bh);
	// extent所在的bh
	eh = ext_block_hdr(bh);
	// 从第一个extent开始分配. 因为上面大于之前extent的块号, 所以这里从第1个开始
	ex = EXT_FIRST_EXTENT(eh);
found_extent:
	// 逻辑块是extent的起始块
	*logical = le32_to_cpu(ex->ee_block);
	// 物理块
	*phys = ext4_ext_pblock(ex);

	// 如果需要ex, 则返回
	if (ret_ex)
		*ret_ex = *ex;
	if (bh)
		put_bh(bh);
	return 1;
}
```

## 3. ext4_ext_insert_extent
给树里插入一个extent
```c
int ext4_ext_insert_extent(handle_t *handle, struct inode *inode,
				struct ext4_ext_path **ppath,
				struct ext4_extent *newext, int gb_flags)
{
	struct ext4_ext_path *path = *ppath;
	struct ext4_extent_header *eh;
	struct ext4_extent *ex, *fex;
	// 离要插入的最近的extent
	struct ext4_extent *nearex; /* nearest extent */
	struct ext4_ext_path *npath = NULL;
	int depth, len, err;
	ext4_lblk_t next;
	int mb_flags = 0, unwritten;

	if (gb_flags & EXT4_GET_BLOCKS_DELALLOC_RESERVE)
		mb_flags |= EXT4_MB_DELALLOC_RESERVED;
	
	// 新插入的extent是0
	if (unlikely(ext4_ext_get_actual_len(newext) == 0)) {
		EXT4_ERROR_INODE(inode, "ext4_ext_get_actual_len(newext) == 0");
		return -EFSCORRUPTED;
	}
	// 树深度
	depth = ext_depth(inode);
	
	ex = path[depth].p_ext;
	eh = path[depth].p_hdr;

	// 头不能为空
	if (unlikely(path[depth].p_hdr == NULL)) {
		EXT4_ERROR_INODE(inode, "path[%d].p_hdr == NULL", depth);
		return -EFSCORRUPTED;
	}

	// EXT4_GET_BLOCKS_PRE_IO 是 direct io路径
	if (ex && !(gb_flags & EXT4_GET_BLOCKS_PRE_IO)) {

		// ex不是最后一个 && ex的结尾在newext的左边
		if (ex < EXT_LAST_EXTENT(eh) &&
		    (le32_to_cpu(ex->ee_block) +
		    ext4_ext_get_actual_len(ex) <
		    le32_to_cpu(newext->ee_block))) {
			// ex向右移动一个
			ex += 1;
			goto prepend;
		
		// ex不是第1个 && newext在ex的左边
		} else if ((ex > EXT_FIRST_EXTENT(eh)) &&
			   (le32_to_cpu(newext->ee_block) +
			   ext4_ext_get_actual_len(newext) <
			   le32_to_cpu(ex->ee_block)))
			// ex向左移动一位
			ex -= 1;

		// 判断newext是否可以合并到ex后面
		if (ext4_can_extents_be_merged(inode, ex, newext)) {
			ext_debug(inode, "append [%d]%d block to %u:[%d]%d"
				  "(from %llu)\n",
				  ext4_ext_is_unwritten(newext),
				  ext4_ext_get_actual_len(newext),
				  le32_to_cpu(ex->ee_block),
				  ext4_ext_is_unwritten(ex),
				  ext4_ext_get_actual_len(ex),
				  ext4_ext_pblock(ex));
			// 日志:获取path里bh的写权限
			err = ext4_ext_get_access(handle, inode,
						  path + depth);
			if (err)
				return err;
			// 是否还没写入
			unwritten = ext4_ext_is_unwritten(ex);
			// 把newext的长度加到ex上
			ex->ee_len = cpu_to_le16(ext4_ext_get_actual_len(ex)
					+ ext4_ext_get_actual_len(newext));
			
			// 因为unwritten标志是在ee_len里存的, 因为上面的ee_len变了, 所以要重新设置
			if (unwritten)
				ext4_ext_mark_unwritten(ex);
			eh = path[depth].p_hdr;
			// 最近的ex
			nearex = ex;
			goto merge;
		}

prepend:
		// 判断是否能把newext放到ex前面
		if (ext4_can_extents_be_merged(inode, newext, ex)) {
			ext_debug(inode, "prepend %u[%d]%d block to %u:[%d]%d"
				  "(from %llu)\n",
				  le32_to_cpu(newext->ee_block),
				  ext4_ext_is_unwritten(newext),
				  ext4_ext_get_actual_len(newext),
				  le32_to_cpu(ex->ee_block),
				  ext4_ext_is_unwritten(ex),
				  ext4_ext_get_actual_len(ex),
				  ext4_ext_pblock(ex));
			err = ext4_ext_get_access(handle, inode,
						  path + depth);
			if (err)
				return err;

			unwritten = ext4_ext_is_unwritten(ex);
			// 逻辑块从newext的开始
			ex->ee_block = newext->ee_block;
			// 把newext的物理块存储到ex里
			ext4_ext_store_pblock(ex, ext4_ext_pblock(newext));
			// ex长度增加
			ex->ee_len = cpu_to_le16(ext4_ext_get_actual_len(ex)
					+ ext4_ext_get_actual_len(newext));
			// 重新标记标志
			if (unwritten)
				ext4_ext_mark_unwritten(ex);
			eh = path[depth].p_hdr;
			nearex = ex;
			goto merge;
		}
	}

	// 走到这儿说是不能合并, 要新创建一个extent插到path里

	// 这里为什么要再获取一次?? inode的深度并没有变
	depth = ext_depth(inode);
	eh = path[depth].p_hdr;
	// entry数量没有达到最大值,说明还有空间
	if (le16_to_cpu(eh->eh_entries) < le16_to_cpu(eh->eh_max))
		goto has_space;
	
	// 走到这儿,说明这个path里的eh没有空间了

	// eh的最后一个ex
	fex = EXT_LAST_EXTENT(eh);
	next = EXT_MAX_BLOCKS;

	// newext比最后一个extent起点还大, 则获取下一个叶子节点
	if (le32_to_cpu(newext->ee_block) > le32_to_cpu(fex->ee_block))
		next = ext4_ext_next_leaf_block(path);
	if (next != EXT_MAX_BLOCKS) {
		ext_debug(inode, "next leaf block - %u\n", next);
		BUG_ON(npath != NULL);
		npath = ext4_find_extent(inode, next, NULL, gb_flags);
		if (IS_ERR(npath))
			return PTR_ERR(npath);
		BUG_ON(npath->p_depth != path->p_depth);
		eh = npath[depth].p_hdr;
		if (le16_to_cpu(eh->eh_entries) < le16_to_cpu(eh->eh_max)) {
			ext_debug(inode, "next leaf isn't full(%d)\n",
				  le16_to_cpu(eh->eh_entries));
			path = npath;
			goto has_space;
		}
		ext_debug(inode, "next leaf has no free space(%d,%d)\n",
			  le16_to_cpu(eh->eh_entries), le16_to_cpu(eh->eh_max));
	}

	// 走到这儿说明 next == EXT_MAX_BLOCKS, 获取下一个叶子节点失败

	// 如果有nofail标志, 要使用保留的
	if (gb_flags & EXT4_GET_BLOCKS_METADATA_NOFAIL)
		mb_flags |= EXT4_MB_USE_RESERVED;

	// 创建一个新叶子节点
	err = ext4_ext_create_new_leaf(handle, inode, mb_flags, gb_flags,
				       ppath, newext);
	if (err)
		goto cleanup;

	// 再获取一下深度和头
	depth = ext_depth(inode);
	eh = path[depth].p_hdr;

has_space:

	// 最近的点是path里的ext
	nearex = path[depth].p_ext;

	// 获取bh的日志访问
	err = ext4_ext_get_access(handle, inode, path + depth);
	if (err)
		goto cleanup;

	if (!nearex) {
		// 这个叶结点里没有extent
		ext_debug(inode, "first extent in the leaf: %u:%llu:[%d]%d\n",
				le32_to_cpu(newext->ee_block),
				ext4_ext_pblock(newext),
				ext4_ext_is_unwritten(newext),
				ext4_ext_get_actual_len(newext));
		// 使用eh的第1个extent
		nearex = EXT_FIRST_EXTENT(eh);
	} else {
		// newext起始块大于nearex
		if (le32_to_cpu(newext->ee_block)
			   > le32_to_cpu(nearex->ee_block)) {
			/* Insert after */
			ext_debug(inode, "insert %u:%llu:[%d]%d before: "
					"nearest %p\n",
					le32_to_cpu(newext->ee_block),
					ext4_ext_pblock(newext),
					ext4_ext_is_unwritten(newext),
					ext4_ext_get_actual_len(newext),
					nearex);
			// near向右移动一位, 向右加1, newext的逻辑块肯定就小于nearex了
			nearex++;
		} else {
			// newext起始块小于等于nearex

			// 不可能等于, 如果等于的话不应该走到这个分支
			BUG_ON(newext->ee_block == nearex->ee_block);
			ext_debug(inode, "insert %u:%llu:[%d]%d after: "
					"nearest %p\n",
					le32_to_cpu(newext->ee_block),
					ext4_ext_pblock(newext),
					ext4_ext_is_unwritten(newext),
					ext4_ext_get_actual_len(newext),
					nearex);
		}
		// nearex到最后一个extent之间的数量
		len = EXT_LAST_EXTENT(eh) - nearex + 1;
		if (len > 0) {
			ext_debug(inode, "insert %u:%llu:[%d]%d: "
					"move %d extents from 0x%p to 0x%p\n",
					le32_to_cpu(newext->ee_block),
					ext4_ext_pblock(newext),
					ext4_ext_is_unwritten(newext),
					ext4_ext_get_actual_len(newext),
					len, nearex, nearex + 1);
			// 把nearex到最后一个extent都向后移动一位, 留出的位置放新插入的newext
			memmove(nearex + 1, nearex,
				len * sizeof(struct ext4_extent));
		}
	}

	// entry数+1
	le16_add_cpu(&eh->eh_entries, 1);
	// 重新设置path的ext, 
	// 注意: 这里的nearex就是新插入的extent
	path[depth].p_ext = nearex;

	// 下面三行是把newext的数据复制到nearex里
	nearex->ee_block = newext->ee_block;
	ext4_ext_store_pblock(nearex, ext4_ext_pblock(newext));
	nearex->ee_len = newext->ee_len;

merge:
	// 插入extent后, 执行合并

	// todo: EXT4_GET_BLOCKS_PRE_IO这个标志啥意思
	// 没有这个标志则尝试合并
	if (!(gb_flags & EXT4_GET_BLOCKS_PRE_IO))
		// 合并会从3个方向上进行: 向左合并, 向右合并, 向上合并
		ext4_ext_try_to_merge(handle, inode, path, nearex);


	// 更新path里各索引的块号
	err = ext4_ext_correct_indexes(handle, inode, path);
	if (err)
		goto cleanup;

	// 标记extent为脏
	err = ext4_ext_dirty(handle, inode, path + path->p_depth);

cleanup:
	ext4_ext_drop_refs(npath);
	kfree(npath);
	return err;
}
```
insert的主要流程:  
1. 先判断与前后extent能否合并, 如果可以则直接跳到第5步  
2. 如果path[depth]里还有空闲, 则跳到第4步  
3. 如果没空间, 则创建新的叶节点  
4. 插入extent  
5. 进行左右合并, 向上合并  


### 3.1 ext4_ext_correct_indexes
```c
static int ext4_ext_correct_indexes(handle_t *handle, struct inode *inode,
				struct ext4_ext_path *path)
{
	struct ext4_extent_header *eh;
	// extent树深度
	int depth = ext_depth(inode);
	struct ext4_extent *ex;
	__le32 border;
	int k, err = 0;

	eh = path[depth].p_hdr;
	ex = path[depth].p_ext;

	if (unlikely(ex == NULL || eh == NULL)) {
		EXT4_ERROR_INODE(inode,
				 "ex %p == NULL or eh %p == NULL", ex, eh);
		return -EFSCORRUPTED;
	}

	// 深度为0直接退出, 因为没有树
	if (depth == 0) {
		return 0;
	}

	if (ex != EXT_FIRST_EXTENT(eh)) {
		/* we correct tree if first leaf got modified only */
		return 0;
	}

	/*
	 * TODO: we need correction if border is smaller than current one
	 */
	k = depth - 1;
	border = path[depth].p_ext->ee_block;
	err = ext4_ext_get_access(handle, inode, path + k);
	if (err)
		return err;
	path[k].p_idx->ei_block = border;
	err = ext4_ext_dirty(handle, inode, path + k);
	if (err)
		return err;

	while (k--) {
		/* change all left-side indexes */
		if (path[k+1].p_idx != EXT_FIRST_INDEX(path[k+1].p_hdr))
			break;
		err = ext4_ext_get_access(handle, inode, path + k);
		if (err)
			break;
		path[k].p_idx->ei_block = border;
		err = ext4_ext_dirty(handle, inode, path + k);
		if (err)
			break;
	}

	return err;
}
```

## 4. ext4_ext_create_new_leaf
```c
static int ext4_ext_create_new_leaf(handle_t *handle, struct inode *inode,
				    unsigned int mb_flags,
				    unsigned int gb_flags,
				    struct ext4_ext_path **ppath,
				    struct ext4_extent *newext)
{
	struct ext4_ext_path *path = *ppath;
	struct ext4_ext_path *curp;
	int depth, i, err = 0;

repeat:
	// 深度
	i = depth = ext_depth(inode);

	// 遍历树, 查找空闲的索引
	curp = path + depth;

	// 自底向上找, EXT_HAS_FREE_INDEX 检查 eh_entries < eh_max
	while (i > 0 && !EXT_HAS_FREE_INDEX(curp)) {
		i--;
		curp--;
	}

	/* 我们使用已分配的块做索引, 所以后面的数据块应该是连续的 */
	if (EXT_HAS_FREE_INDEX(curp)) {
		/* 如果我们发现索引有空闲的entry, 直接使用这个entry, 创建所有的子树和新叶子 */

		// 要在path[i]这个地方,插入一个子树
		err = ext4_ext_split(handle, inode, mb_flags, path, newext, i);
		if (err)
			goto out;

		// 重新查找extent路径
		path = ext4_find_extent(inode,
				    (ext4_lblk_t)le32_to_cpu(newext->ee_block),
				    ppath, gb_flags);
		if (IS_ERR(path))
			err = PTR_ERR(path);
	} else {
		// 走到这儿, i肯定是0, curp指向树根, 而且curp也满了, 所以要增长树
		
		err = ext4_ext_grow_indepth(handle, inode, mb_flags);
		if (err)
			goto out;

		// 重新查找extent路径
		path = ext4_find_extent(inode,
				   (ext4_lblk_t)le32_to_cpu(newext->ee_block),
				    ppath, gb_flags);
		if (IS_ERR(path)) {
			err = PTR_ERR(path);
			goto out;
		}

		/*
		 * 只有在第一次(depth 0 ->  1)流程中会释放空间, 其他所有情况都需要分割树
		 */
		// 增长之后depth也更新了
		depth = ext_depth(inode);

		// 如果相关的path已经到了最大值, 现在应该有空间了, 再重新查找
		if (path[depth].p_hdr->eh_entries == path[depth].p_hdr->eh_max) {
			goto repeat;
		}
	}

out:
	return err;
}
```
创建新叶节点的流程:  
1. 如果有空闲索引的节点, 则在该节点上创建新的extent子树
2. 如果没有空闲索引了, 则需要增加树的层数    

## 5. ext4_ext_split
```c
static int ext4_ext_split(handle_t *handle, struct inode *inode,
			  unsigned int flags,
			  struct ext4_ext_path *path,
			  struct ext4_extent *newext, int at)
{
	struct buffer_head *bh = NULL;
	int depth = ext_depth(inode);
	struct ext4_extent_header *neh;
	struct ext4_extent_idx *fidx;
	// at是要在path里的哪个位置
	int i = at, k, m, a;
	ext4_fsblk_t newblock, oldblock;
	__le32 border;
	ext4_fsblk_t *ablocks = NULL; /* array of allocated blocks */
	gfp_t gfp_flags = GFP_NOFS;
	int err = 0;
	size_t ext_size = 0;

	// 不允许失败, 分配内存用的
	if (flags & EXT4_EX_NOFAIL)
		gfp_flags |= __GFP_NOFAIL;

	/* 做决定: 从哪儿开始分割? */
	/* FIXME: 现在的决定是最简单的: 当前extent */

	/* 如果当前叶子被分割, 我们应该使用边界从分割点*/

	// p_ext指针错误. ext指针比最大ex还大, 什么时候会有这种情况?
	if (unlikely(path[depth].p_ext > EXT_MAX_EXTENT(path[depth].p_hdr))) {
		EXT4_ERROR_INODE(inode, "p_ext > EXT_MAX_EXTENT!");
		return -EFSCORRUPTED;
	}

	// ext不是最大的extent, 则以path[depth]的逻辑块开始
	if (path[depth].p_ext != EXT_MAX_EXTENT(path[depth].p_hdr)) {
		// p_ext < max_entent
		// border从p_ext后面一个extent开始块
		// p_ext[1]=p_ext+1
		border = path[depth].p_ext[1].ee_block;
		ext_debug(inode, "leaf will be split."
				" next leaf starts at %d\n",
				  le32_to_cpu(border));
	} else {
		// p_ext == max_entent
		// p_ext是最后一个extent, border指向新块
		border = newext->ee_block;
		ext_debug(inode, "leaf will be added."
				" next leaf starts at %d\n",
				le32_to_cpu(border));
	}

	/*
	 * 如果有错误发生, 我们要打断程序标记文件系统为只读
	 * 索引不会被插入, 树会在一致状态.下一次挂载会修改这些buffer
	 */

	/*
	 * 分配一个数组来跟踪所有已分配的块, 我们需要这个来处理错误, 
	 * 然后释放块.
	 */
	
	// 因为要创建新的索引, 所以分配depth个块
	ablocks = kcalloc(depth, sizeof(ext4_fsblk_t), gfp_flags);
	if (!ablocks)
		return -ENOMEM;

	ext_debug(inode, "allocate %d blocks for indexes/leaf\n", depth - at);

	// at: 要插入的层
	// 注意: depth是从0开始的, 且根节点不用分配块, 所以这里分配的包含extent和索引块
	for (a = 0; a < depth - at; a++) {
		newblock = ext4_ext_new_meta_block(handle, inode, path,
						   newext, &err, flags);
		if (newblock == 0)
			goto cleanup;
		ablocks[a] = newblock;
	}

	// 最后一个用来做extent
	newblock = ablocks[--a];
	// 块不能为0, todo: 上面for循环不是已经判断了吗? 这里为啥还要判断?
	if (unlikely(newblock == 0)) {
		EXT4_ERROR_INODE(inode, "newblock == 0!");
		err = -EFSCORRUPTED;
		goto cleanup;
	}
	// 读块的bh
	bh = sb_getblk_gfp(inode->i_sb, newblock, __GFP_MOVABLE | GFP_NOFS);
	if (unlikely(!bh)) {
		err = -ENOMEM;
		goto cleanup;
	}
	lock_buffer(bh);

	// 日志
	err = ext4_journal_get_create_access(handle, bh);
	if (err)
		goto cleanup;

	// 块头
	neh = ext_block_hdr(bh);
	// 现在还没有entry
	neh->eh_entries = 0;
	// 一个块里能存的extent数量
	neh->eh_max = cpu_to_le16(ext4_ext_space_block(inode, 0));
	neh->eh_magic = EXT4_EXT_MAGIC;
	neh->eh_depth = 0;

	/* move remainder of path[depth] to the new leaf */
	// entry还没到最大值, 什么情况才会有
	if (unlikely(path[depth].p_hdr->eh_entries !=
		     path[depth].p_hdr->eh_max)) {
		EXT4_ERROR_INODE(inode, "eh_entries %d != eh_max %d!",
				 path[depth].p_hdr->eh_entries,
				 path[depth].p_hdr->eh_max);
		err = -EFSCORRUPTED;
		goto cleanup;
	}
	// m是从ext开始到最后一个extent还有多少个extent
	// 注意后面的ext++, 移动的是下个节点
	m = EXT_MAX_EXTENT(path[depth].p_hdr) - path[depth].p_ext++;
	ext4_ext_show_move(inode, path, newblock, depth);
	
	if (m) {
		struct ext4_extent *ex;
		// 新块的第一个extent
		ex = EXT_FIRST_EXTENT(neh);
		// 把ext到最后一个extent移到新块里
		memmove(ex, path[depth].p_ext, sizeof(struct ext4_extent) * m);
		// 新块的entry加m
		le16_add_cpu(&neh->eh_entries, m);
	}

	// 新块已用的大小
	ext_size = sizeof(struct ext4_extent_header) +
		sizeof(struct ext4_extent) * le16_to_cpu(neh->eh_entries);
	// 把新块的其它地方清0
	memset(bh->b_data + ext_size, 0, inode->i_sb->s_blocksize - ext_size);
	// 计算新块的校验和
	ext4_extent_block_csum_set(inode, neh);
	// 设置bh最新
	set_buffer_uptodate(bh);
	unlock_buffer(bh);

	// 日志
	err = ext4_handle_dirty_metadata(handle, inode, bh);
	if (err)
		goto cleanup;
	brelse(bh);
	bh = NULL;

	// 修正老的叶结点的entry数
	if (m) {
		// 获取bh访问权
		err = ext4_ext_get_access(handle, inode, path + depth);
		if (err)
			goto cleanup;
		// 老的块entry减少m
		le16_add_cpu(&path[depth].p_hdr->eh_entries, -m);
		// 把bh标脏
		err = ext4_ext_dirty(handle, inode, path + depth);
		if (err)
			goto cleanup;

	}

	// 创建中间索引结点的数量
	k = depth - at - 1;
	// k 怎么会小于0?
	if (unlikely(k < 0)) {
		EXT4_ERROR_INODE(inode, "k %d < 0!", k);
		err = -EFSCORRUPTED;
		goto cleanup;
	}
	if (k)
		ext_debug(inode, "create %d intermediate indices\n", k);

	i = depth - 1;

	// 创建中间索引
	while (k--) {
		oldblock = newblock;

		// 取一个刚分配的块
		newblock = ablocks[--a];
		// 读bh
		bh = sb_getblk(inode->i_sb, newblock);
		if (unlikely(!bh)) {
			err = -ENOMEM;
			goto cleanup;
		}
		lock_buffer(bh);

		// 日志, 创建
		err = ext4_journal_get_create_access(handle, bh);
		if (err)
			goto cleanup;
		
		// bh头
		neh = ext_block_hdr(bh);
		// entry为1, 因为肯定有一个索引结点
		neh->eh_entries = cpu_to_le16(1);
		neh->eh_magic = EXT4_EXT_MAGIC;
		// 能存索引的最大数量
		neh->eh_max = cpu_to_le16(ext4_ext_space_block_idx(inode, 0));
		// 所处的深度
		neh->eh_depth = cpu_to_le16(depth - i);
		// 第一个索引
		fidx = EXT_FIRST_INDEX(neh);
		// 起始逻辑块就是上面的border
		fidx->ei_block = border;
		// 存储下一级的物理块
		ext4_idx_store_pblock(fidx, oldblock);

		ext_debug(inode, "int.index at %d (block %llu): %u -> %llu\n",
				i, newblock, le32_to_cpu(border), oldblock);

		// path[i]没满的话,就应该直接在这一层创建索引, 不用创建新块, 所以肯定出错了
		if (unlikely(EXT_MAX_INDEX(path[i].p_hdr) !=
					EXT_LAST_INDEX(path[i].p_hdr))) {
			EXT4_ERROR_INODE(inode,
					 "EXT_MAX_INDEX != EXT_LAST_INDEX ee_block %d!",
					 le32_to_cpu(path[i].p_ext->ee_block));
			err = -EFSCORRUPTED;
			goto cleanup;
		}
		// 需要移动的索引数量
		m = EXT_MAX_INDEX(path[i].p_hdr) - path[i].p_idx++;
		ext_debug(inode, "cur 0x%p, last 0x%p\n", path[i].p_idx,
				EXT_MAX_INDEX(path[i].p_hdr));
		ext4_ext_show_move(inode, path, newblock, i);
		if (m) {
			// 把path里的m个索引复制到fidx的下一个索引上
			memmove(++fidx, path[i].p_idx,
				sizeof(struct ext4_extent_idx) * m);
			// entry数加m
			le16_add_cpu(&neh->eh_entries, m);
		}
		// 已使用大小
		ext_size = sizeof(struct ext4_extent_header) +
		   (sizeof(struct ext4_extent) * le16_to_cpu(neh->eh_entries));
		// 把未使用的清0
		memset(bh->b_data + ext_size, 0,
			inode->i_sb->s_blocksize - ext_size);
		// 计算block的校验和
		ext4_extent_block_csum_set(inode, neh);
		// 设置bh最新
		set_buffer_uptodate(bh);
		unlock_buffer(bh);

		// 这个好像是标脏
		err = ext4_handle_dirty_metadata(handle, inode, bh);
		if (err)
			goto cleanup;
		brelse(bh);
		bh = NULL;

		// 修正老的索引
		if (m) {
			// 获取访问权
			err = ext4_ext_get_access(handle, inode, path + i);
			if (err)
				goto cleanup;
			// 块的entries减m
			le16_add_cpu(&path[i].p_hdr->eh_entries, -m);
			// 标脏
			err = ext4_ext_dirty(handle, inode, path + i);
			if (err)
				goto cleanup;
		}

		i--;
	}

	// 在path[at]的位置插入新的索引
	err = ext4_ext_insert_index(handle, inode, path + at,
				    le32_to_cpu(border), newblock);

cleanup:
	// 释放bh
	if (bh) {
		if (buffer_locked(bh))
			unlock_buffer(bh);
		brelse(bh);
	}

	// 如果出错, 释放上面分配的块
	if (err) {
		for (i = 0; i < depth; i++) {
			if (!ablocks[i])
				continue;
			ext4_free_blocks(handle, inode, NULL, ablocks[i], 1,
					 EXT4_FREE_BLOCKS_METADATA);
		}
	}
	// 释放临时数组
	kfree(ablocks);

	return err;
}
```
主要流程:  
1. 确立新extent的边界    
2. 分配需要的物理块  
3. 把要分割的extent移动到新块上, 并更新旧extent的相关数据
4. 建立中间索引节点, 把要分割的索引移动到新块上, 并更新旧索引节点的相关数据
5. 在要插入的层级插入新的索引节点

### 5.1 ext4_ext_insert_index
```c
static int ext4_ext_insert_index(handle_t *handle, struct inode *inode,
				 struct ext4_ext_path *curp,
				 int logical, ext4_fsblk_t ptr)
{
	struct ext4_extent_idx *ix;
	int len, err;
	// 日志访问权
	err = ext4_ext_get_access(handle, inode, curp);
	if (err)
		return err;

	// 要插入的等于当前逻辑块, 不应该出现这种情况
	if (unlikely(logical == le32_to_cpu(curp->p_idx->ei_block))) {
		EXT4_ERROR_INODE(inode,
				 "logical %d == ei_block %d!",
				 logical, le32_to_cpu(curp->p_idx->ei_block));
		return -EFSCORRUPTED;
	}

	// 当前块已经满了, 不应该出现这种情况, 因为在插入的时候, 这个节点还有空间
	if (unlikely(le16_to_cpu(curp->p_hdr->eh_entries)
			     >= le16_to_cpu(curp->p_hdr->eh_max))) {
		EXT4_ERROR_INODE(inode,
				 "eh_entries %d >= eh_max %d!",
				 le16_to_cpu(curp->p_hdr->eh_entries),
				 le16_to_cpu(curp->p_hdr->eh_max));
		return -EFSCORRUPTED;
	}

	if (logical > le32_to_cpu(curp->p_idx->ei_block)) {
		// 要插入的块大于当前块, 则插到后面的索引块
		ext_debug(inode, "insert new index %d after: %llu\n",
			  logical, ptr);
		ix = curp->p_idx + 1;
	} else {
		// 要插入的块小于等于当前块, 则插到索引块前面
		ext_debug(inode, "insert new index %d before: %llu\n",
			  logical, ptr);
		ix = curp->p_idx;
	}

	// 最后一个索引到要插入点的索引数量
	len = EXT_LAST_INDEX(curp->p_hdr) - ix + 1;
	// 不可能没有索引
	BUG_ON(len < 0);
	if (len > 0) {
		ext_debug(inode, "insert new index %d: "
				"move %d indices from 0x%p to 0x%p\n",
				logical, len, ix, ix + 1);
		// 把ix及之后的索引都向后移动一位
		memmove(ix + 1, ix, len * sizeof(struct ext4_extent_idx));
	}

	// 不可能大于最大值. todo: 为啥不在移动之前判断?
	if (unlikely(ix > EXT_MAX_INDEX(curp->p_hdr))) {
		EXT4_ERROR_INODE(inode, "ix > EXT_MAX_INDEX!");
		return -EFSCORRUPTED;
	}

	// 把逻辑块存到ix上
	ix->ei_block = cpu_to_le32(logical);
	// 存储物理块
	ext4_idx_store_pblock(ix, ptr);
	// entry加1
	le16_add_cpu(&curp->p_hdr->eh_entries, 1);

	// 什么时候会出现这种情况
	if (unlikely(ix > EXT_LAST_INDEX(curp->p_hdr))) {
		EXT4_ERROR_INODE(inode, "ix > EXT_LAST_INDEX!");
		return -EFSCORRUPTED;
	}

	// inode标脏
	err = ext4_ext_dirty(handle, inode, curp);
	ext4_std_error(inode->i_sb, err);

	return err;
}
```
主流程:  
1. 先找到要插入的位置ix  
2. 把ix原来的数据都往后移动一个位置
3. 把逻辑块, 物理块, entries设置到ix里

## 6. ext4_ext_grow_indepth
```c
/*
 * ext4_ext_grow_indepth:
 * 实现树增长的程序:
 * - 分配新块
 * - 把顶层的数据移动到新块里
 * - 初始化新的顶层块, 创索引指向刚才创建的块
 */
static int ext4_ext_grow_indepth(handle_t *handle, struct inode *inode,
				 unsigned int flags)
{
	struct ext4_extent_header *neh;
	struct buffer_head *bh;
	ext4_fsblk_t newblock, goal = 0;
	struct ext4_super_block *es = EXT4_SB(inode->i_sb)->s_es;
	int err = 0;
	size_t ext_size = 0;

	// 当前深度不为0
	if (ext_depth(inode))
		// 以树根的第1个索引的物理块为目标. todo: why ?
		goal = ext4_idx_pblock(EXT_FIRST_INDEX(ext_inode_hdr(inode)));
	// 如果大于第1个数据块, 则是有意义的
	if (goal > le32_to_cpu(es->s_first_data_block)) {
		flags |= EXT4_MB_HINT_TRY_GOAL;
		// todo: 为啥要减1
		goal--;
	} else
		// 找一个对inode理想的块
		goal = ext4_inode_to_goal_block(inode);

	// 分配元数据块, 返回的是第1个块号
	newblock = ext4_new_meta_blocks(handle, inode, goal, flags,
					// 这里数量传NULL, 表示只分配一个块
					NULL, &err);
	// 返回值为0, 则分配失败, 0号块不用!
	if (newblock == 0)
		return err;

	// 读新分配块的bh
	bh = sb_getblk_gfp(inode->i_sb, newblock, __GFP_MOVABLE | GFP_NOFS);
	if (unlikely(!bh))
		return -ENOMEM;
	lock_buffer(bh);

	// 日志
	err = ext4_journal_get_create_access(handle, bh);
	if (err) {
		unlock_buffer(bh);
		goto out;
	}

	// i_data大小
	ext_size = sizeof(EXT4_I(inode)->i_data);
	// 把原来i_data的数据移到到新分配的bh里
	memmove(bh->b_data, EXT4_I(inode)->i_data, ext_size);
	// 把块里未使用的位置清0
	memset(bh->b_data + ext_size, 0, inode->i_sb->s_blocksize - ext_size);

	// 新块的头, (struct ext4_extent_header *) bh->b_data
	neh = ext_block_hdr(bh);
	
	if (ext_depth(inode))
		// 原来深度不为0, 则原来i_data里存的肯定是索引节点, 所以新分配的用来存放索引节点, 以索引的大小来计算新的max
		neh->eh_max = cpu_to_le16(ext4_ext_space_block_idx(inode, 0));
	else
		// 原来只有根结点, 则原来i_data里存的是extent, 则新分配的只存extent. 以extent的大小来计算新的bh的eh_max
		neh->eh_max = cpu_to_le16(ext4_ext_space_block(inode, 0));
	// 设置魔数
	neh->eh_magic = EXT4_EXT_MAGIC;
	// 计算新分配块的校验和, 校验的数据长度是: sizeof(header) + max * sizeof(extent)
	ext4_extent_block_csum_set(inode, neh);
	// 设置块是最新的
	set_buffer_uptodate(bh);
	unlock_buffer(bh);

	// 日志相关, 元数据脏了?
	err = ext4_handle_dirty_metadata(handle, inode, bh);
	if (err)
		goto out;

	// 修改根节点的header
	neh = ext_inode_hdr(inode);
	// entry为1, 因为把原来的都移动到新分配的块里了
	neh->eh_entries = cpu_to_le16(1);
	// 给索引里存下层的物理块号
	ext4_idx_store_pblock(EXT_FIRST_INDEX(neh), newblock);
	if (neh->eh_depth == 0) {
		// 深度为0时, 根节点存储extent, 现在要存放索引了,
		// 所以要重新计算存放索引的数量
		neh->eh_max = cpu_to_le16(ext4_ext_space_root_idx(inode, 0));
		// 把原来extent的逻辑块号复制到索引节点里来
		EXT_FIRST_INDEX(neh)->ei_block =
			// 因为原来是extent, 所以按extent的布局来解析neh
			EXT_FIRST_EXTENT(neh)->ee_block;
	}
	// todo: 这里为什么不把neh里剩余没用的index清除
	ext_debug(inode, "new root: num %d(%d), lblock %d, ptr %llu\n",
		  le16_to_cpu(neh->eh_entries), le16_to_cpu(neh->eh_max),
		  le32_to_cpu(EXT_FIRST_INDEX(neh)->ei_block),
		  ext4_idx_pblock(EXT_FIRST_INDEX(neh)));

	// 深度加1
	le16_add_cpu(&neh->eh_depth, 1);
	
	//因为这里neh是inode->i_data, 所以这里不用计算校验和
	// 标记inode为脏
	err = ext4_mark_inode_dirty(handle, inode);
out:
	brelse(bh);

	return err;
}
```

### 6.1 ext4_inode_to_goal_block
```c
ext4_fsblk_t ext4_inode_to_goal_block(struct inode *inode)
{
	struct ext4_inode_info *ei = EXT4_I(inode);
	ext4_group_t block_group;
	ext4_grpblk_t colour;
	int flex_size = ext4_flex_bg_size(EXT4_SB(inode->i_sb));
	ext4_fsblk_t bg_start;
	ext4_fsblk_t last_block;

	block_group = ei->i_block_group;
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
	bg_start = ext4_group_first_block_no(inode->i_sb, block_group);
	last_block = ext4_blocks_count(EXT4_SB(inode->i_sb)->s_es) - 1;

	/*
	 * If we are doing delayed allocation, we don't need take
	 * colour into account.
	 */
	if (test_opt(inode->i_sb, DELALLOC))
		return bg_start;

	if (bg_start + EXT4_BLOCKS_PER_GROUP(inode->i_sb) <= last_block)
		colour = (task_pid_nr(current) % 16) *
			(EXT4_BLOCKS_PER_GROUP(inode->i_sb) / 16);
	else
		colour = (task_pid_nr(current) % 16) *
			((last_block - bg_start) / 16);
	return bg_start + colour;
}
```

### 6.2 ext4_new_meta_blocks
```c
ext4_fsblk_t ext4_new_meta_blocks(handle_t *handle, struct inode *inode,
				  ext4_fsblk_t goal, unsigned int flags,
				  unsigned long *count, int *errp)
{
	struct ext4_allocation_request ar;
	ext4_fsblk_t ret;

	memset(&ar, 0, sizeof(ar));
	
	// 填入相关数据
	ar.inode = inode;
	ar.goal = goal;

	// 如果count没指定, 则分配一个块
	ar.len = count ? *count : 1;
	ar.flags = flags;

	// 分配块
	ret = ext4_mb_new_blocks(handle, &ar, errp);
	if (count)
		*count = ar.len;
	/*
	 * 统计已分配的元数据块, 对于元数据块永远不失败, 但是我们要做统计
	 */
	if (!(*errp) && (flags & EXT4_MB_DELALLOC_RESERVED)) {
		dquot_alloc_block_nofail(inode,
				EXT4_C2B(EXT4_SB(inode->i_sb), ar.len));
	}
	return ret;
}
```

### 6.3 ext4_ext_space_block
```c
static inline int ext4_ext_space_block(struct inode *inode, int check)
{
	int size;

	// 一个块里除了头部之外还能存多少个extent
	size = (inode->i_sb->s_blocksize - sizeof(struct ext4_extent_header))
			/ sizeof(struct ext4_extent);
#ifdef AGGRESSIVE_TEST
	if (!check && size > 6)
		size = 6;
#endif
	return size;
}
```

### 6.4 ext4_extent_block_csum_set
```c
static void ext4_extent_block_csum_set(struct inode *inode,
				       struct ext4_extent_header *eh)
{
	struct ext4_extent_tail *et;

	// 如果没有元数据校验和检查, 则退出
	if (!ext4_has_metadata_csum(inode->i_sb))
		return;

	// eh_max开始的地方用来存eh的校验和, 因为extent都是12字节, 在ext4所支持的块大小里,
	// 都有blocksize % 12 >= 4. 校验和是4字节, 所以足够存放了.
	et = find_ext4_extent_tail(eh);
	// 计算校验和
	et->et_checksum = ext4_extent_block_csum(inode, eh);
}
```