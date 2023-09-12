# extent status tree
源码基于5.10
## 3. ext4_es_lookup_extent
```c
int ext4_es_lookup_extent(struct inode *inode, ext4_lblk_t lblk,
			  ext4_lblk_t *next_lblk,
			  struct extent_status *es)
{
	struct ext4_es_tree *tree;
	struct ext4_es_stats *stats;
	struct extent_status *es1 = NULL;
	struct rb_node *node;
	int found = 0;

	// EXT4_FC_REPLAY 状态, 不进行lookup
	if (EXT4_SB(inode->i_sb)->s_mount_state & EXT4_FC_REPLAY)
		return 0;

	trace_ext4_es_lookup_extent_enter(inode, lblk);
	es_debug("lookup extent in block %u\n", lblk);

	// es树
	tree = &EXT4_I(inode)->i_es_tree;
	read_lock(&EXT4_I(inode)->i_es_lock);

	// es清0, es用来给caller返回结果
	es->es_lblk = es->es_len = es->es_pblk = 0;
	// cache_es有值, 这个是用来保存上次搜索用到的es, 如果有
	// 先在上次缓存里找
	if (tree->cache_es) {
		es1 = tree->cache_es;
		// 如果在cache_es的范围里，那直接找到
		// #define in_range(b, first, len)	((b) >= (first) && (b) <= (first) + (len) - 1)
		if (in_range(lblk, es1->es_lblk, es1->es_len)) {
			es_debug("%u cached by [%u/%u)\n",
				 lblk, es1->es_lblk, es1->es_len);
			found = 1;
			goto out;
		}
	}

	// 走到这儿表示在cache_es为空或者目标块不在cache_es的范围里

	// 从es树的根开始遍历
	node = tree->root.rb_node;
	while (node) {
		es1 = rb_entry(node, struct extent_status, rb_node);
		// 树是左小右大
		if (lblk < es1->es_lblk)
			node = node->rb_left;
		else if (lblk > ext4_es_end(es1))
			node = node->rb_right;
		else { // 相等
			found = 1;
			break;
		}
	}

out:
	// 超级块里es的统计信息
	stats = &EXT4_SB(inode->i_sb)->s_es_stats;

	// 找到
	if (found) {
		// es1里包含了找到的信息, 所以如果在es树里找到, 则es1肯定不能为空
		BUG_ON(!es1);
		
		// 把找到的信息设置到es里
		es->es_lblk = es1->es_lblk;
		es->es_len = es1->es_len;
		es->es_pblk = es1->es_pblk;

		// 如果没有设置引用标志，则设之
		if (!ext4_es_is_referenced(es1))
			ext4_es_set_referenced(es1);
		// 增加cache命中的统计
		percpu_counter_inc(&stats->es_stats_cache_hits);
		// 如果caller需要知道下一个结点的信息，则设置之
		if (next_lblk) {
			node = rb_next(&es1->rb_node);
			// 若有node, 则设置下一个逻辑块号, 否则置0
			if (node) {
				es1 = rb_entry(node, struct extent_status,
					       rb_node);
				*next_lblk = es1->es_lblk;
			} else
				*next_lblk = 0;
		}
	} else {
		// 在缓存里没找到, 增加cache-miss统计
		percpu_counter_inc(&stats->es_stats_cache_misses);
	}

	read_unlock(&EXT4_I(inode)->i_es_lock);

	trace_ext4_es_lookup_extent_exit(inode, es, found);
	return found;
}
```
## 6. ext4_cache_extents
```c
static void ext4_cache_extents(struct inode *inode,
			       struct ext4_extent_header *eh)
{
	// header后的第1个extent
	struct ext4_extent *ex = EXT_FIRST_EXTENT(eh);
	ext4_lblk_t prev = 0;
	int i;

	// eh_entries是包含extent的数量, 从最后一个extent找
	for (i = le16_to_cpu(eh->eh_entries); i > 0; i--, ex++) {
		unsigned int status = EXTENT_STATUS_WRITTEN;
		// 第1个逻辑块
		ext4_lblk_t lblk = le32_to_cpu(ex->ee_block);
		// 获取ex的长度
		int len = ext4_ext_get_actual_len(ex);

		// 之前的和现在的不相连, 说明有洞, 把之前的extent先缓存到es里
		if (prev && (prev != lblk))
			ext4_es_cache_extent(inode, prev, lblk - prev, ~0,
					     EXTENT_STATUS_HOLE);

		// 还没写过？ex_len大于(1<<15)时，被认为是已初始化过的
		if (ext4_ext_is_unwritten(ex))
			status = EXTENT_STATUS_UNWRITTEN;
		// 在es里缓存未写入的extent
		ext4_es_cache_extent(inode, lblk, len,
				     ext4_ext_pblock(ex), status);
		prev = lblk + len;
	}
}
```

### 6.1 ext4_es_cache_extent
```c
void ext4_es_cache_extent(struct inode *inode, ext4_lblk_t lblk,
			  ext4_lblk_t len, ext4_fsblk_t pblk,
			  unsigned int status)
{
	struct extent_status *es;
	struct extent_status newes;
	// 结束块
	ext4_lblk_t end = lblk + len - 1;

	// 挂载状态是fc_replay，则返回
	if (EXT4_SB(inode->i_sb)->s_mount_state & EXT4_FC_REPLAY)
		return;

	newes.es_lblk = lblk;
	newes.es_len = len;
	// 储存物理块及状态
	ext4_es_store_pblock_status(&newes, pblk, status);
	trace_ext4_es_cache_extent(inode, &newes);

	if (!len)
		return;

	BUG_ON(end < lblk);

	write_lock(&EXT4_I(inode)->i_es_lock);

	// 先去es树里找一下
	es = __es_tree_search(&EXT4_I(inode)->i_es_tree.root, lblk);

	// 没找到 || 找到的块号大于end
	if (!es || es->es_lblk > end)
		__es_insert_extent(inode, &newes);
	write_unlock(&EXT4_I(inode)->i_es_lock);
}
```

## 14. ext4_es_insert_extent
```c
int ext4_es_insert_extent(struct inode *inode, ext4_lblk_t lblk,
			  ext4_lblk_t len, ext4_fsblk_t pblk,
			  unsigned int status)
{
	struct extent_status newes;
	// 结束的块号
	ext4_lblk_t end = lblk + len - 1;
	int err = 0;
	struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);

	// fc_replay是正在修复吗? 
	if (EXT4_SB(inode->i_sb)->s_mount_state & EXT4_FC_REPLAY)
		return 0;

	es_debug("add [%u/%u) %llu %x to extent status tree of inode %lu\n",
		 lblk, len, pblk, status, inode->i_ino);

	if (!len)
		return 0;

	// 终点小于起点...
	BUG_ON(end < lblk);

	// 延迟和已写??
	if ((status & EXTENT_STATUS_DELAYED) &&
	    (status & EXTENT_STATUS_WRITTEN)) {
		ext4_warning(inode->i_sb, "Inserting extent [%u/%u] as "
				" delayed and written which can potentially "
				" cause data loss.", lblk, len);
		WARN_ON(1);
	}

	// 起始逻辑块和长度
	newes.es_lblk = lblk;
	newes.es_len = len;
	// 存入物理块地址和状态
	ext4_es_store_pblock_status(&newes, pblk, status);
	trace_ext4_es_insert_extent(inode, &newes);

	//调试
	ext4_es_insert_extent_check(inode, &newes);

	write_lock(&EXT4_I(inode)->i_es_lock);
	// 先移除lblk到end这个区间的es
	err = __es_remove_extent(inode, lblk, end, NULL);
	if (err != 0)
		goto error;
retry:
	// 插入es树
	err = __es_insert_extent(inode, &newes);
	if (err == -ENOMEM && __es_shrink(EXT4_SB(inode->i_sb),
					  128, EXT4_I(inode)))
		goto retry;
	if (err == -ENOMEM && !ext4_es_is_delayed(&newes))
		err = 0;

	if (sbi->s_cluster_ratio > 1 && test_opt(inode->i_sb, DELALLOC) &&
	    (status & EXTENT_STATUS_WRITTEN ||
	     status & EXTENT_STATUS_UNWRITTEN))
		__revise_pending(inode, lblk, len);

error:
	write_unlock(&EXT4_I(inode)->i_es_lock);

	ext4_es_print_tree(inode);

	return err;
}
```
