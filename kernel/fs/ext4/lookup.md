# lookup

## 相关结构体
```c
struct ext4_filename {
	const struct qstr *usr_fname; // 文件名qstr指针
	struct fscrypt_str disk_name;
	struct dx_hash_info hinfo;
#ifdef CONFIG_FS_ENCRYPTION
	struct fscrypt_str crypto_buf;
#endif
#ifdef CONFIG_UNICODE
	struct fscrypt_str cf_name;
#endif
};

struct fscrypt_str {
	unsigned char *name; // 名称
	u32 len; // 长度
};

struct ext4_dir_entry_2 {
	__le32	inode;			/* inode号 */
	__le16	rec_len;		/* entry长度 */
	__u8	name_len;		/* 文件长度 */
	__u8	file_type;		/* 文件类型 */
	char	name[EXT4_NAME_LEN];	/* 文件名 */
};
```

## ext4_lookup
```c
// dir: 父目录, dentry: 要查找的文件新建的dentry
static struct dentry *ext4_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
	struct inode *inode;
	struct ext4_dir_entry_2 *de;
	struct buffer_head *bh;

	// EXT4_NAME_LEN 255,文件名不能超过255
	if (dentry->d_name.len > EXT4_NAME_LEN)
		return ERR_PTR(-ENAMETOOLONG);

	bh = ext4_lookup_entry(dir, dentry, &de);
	if (IS_ERR(bh))
		return ERR_CAST(bh);
	inode = NULL;
	if (bh) {
		__u32 ino = le32_to_cpu(de->inode);
		brelse(bh);
		if (!ext4_valid_inum(dir->i_sb, ino)) {
			EXT4_ERROR_INODE(dir, "bad inode number: %u", ino);
			return ERR_PTR(-EFSCORRUPTED);
		}
		if (unlikely(ino == dir->i_ino)) {
			EXT4_ERROR_INODE(dir, "'%pd' linked to parent dir",
					 dentry);
			return ERR_PTR(-EFSCORRUPTED);
		}
		inode = ext4_iget(dir->i_sb, ino, EXT4_IGET_NORMAL);
		if (inode == ERR_PTR(-ESTALE)) {
			EXT4_ERROR_INODE(dir,
					 "deleted inode referenced: %u",
					 ino);
			return ERR_PTR(-EFSCORRUPTED);
		}
		if (!IS_ERR(inode) && IS_ENCRYPTED(dir) &&
		    (S_ISDIR(inode->i_mode) || S_ISLNK(inode->i_mode)) &&
		    !fscrypt_has_permitted_context(dir, inode)) {
			ext4_warning(inode->i_sb,
				     "Inconsistent encryption contexts: %lu/%lu",
				     dir->i_ino, inode->i_ino);
			iput(inode);
			return ERR_PTR(-EPERM);
		}
	}

#ifdef CONFIG_UNICODE
	if (!inode && IS_CASEFOLDED(dir)) {
		/* Eventually we want to call d_add_ci(dentry, NULL)
		 * for negative dentries in the encoding case as
		 * well.  For now, prevent the negative dentry
		 * from being cached.
		 */
		return NULL;
	}
#endif
	return d_splice_alias(inode, dentry);
}

static struct buffer_head *ext4_lookup_entry(struct inode *dir,
					     struct dentry *dentry,
					     struct ext4_dir_entry_2 **res_dir)
{
	int err;
	struct ext4_filename fname;
	struct buffer_head *bh;

	// 给fname设置文件名及长度
	err = ext4_fname_prepare_lookup(dir, dentry, &fname);
	if (err == -ENOENT)
		return NULL;
	if (err)
		return ERR_PTR(err);

	bh = __ext4_find_entry(dir, &fname, res_dir, NULL);

	ext4_fname_free_filename(&fname);
	return bh;
}

// 这个函数根据CONFIG_FS_ENCRYPTION, 有2个不同的函数,这里看的是 !CONFIG_FS_ENCRYPTION 版本
static inline int ext4_fname_prepare_lookup(struct inode *dir,
					    struct dentry *dentry,
					    struct ext4_filename *fname)
{
	return ext4_fname_setup_filename(dir, &dentry->d_name, 1, fname);
}

static inline int ext4_fname_setup_filename(struct inode *dir,
					    const struct qstr *iname,
					    int lookup,
					    struct ext4_filename *fname)
{
	// qstr指针
	fname->usr_fname = iname;
	// 文件名
	fname->disk_name.name = (unsigned char *) iname->name;
	// 文件名长度
	fname->disk_name.len = iname->len;

	// unicode相关
#ifdef CONFIG_UNICODE
	ext4_fname_setup_ci_filename(dir, iname, &fname->cf_name);
#endif

	return 0;
}
```

## __ext4_find_entry
```c
static struct buffer_head *__ext4_find_entry(struct inode *dir,
					     struct ext4_filename *fname,
					     struct ext4_dir_entry_2 **res_dir,
					     int *inlined) // inlined传的是NULL
{
	struct super_block *sb;
	// NAMEI_RA_SIZE是8
	struct buffer_head *bh_use[NAMEI_RA_SIZE];
	struct buffer_head *bh, *ret = NULL;
	ext4_lblk_t start, block;
	// 文件名
	const u8 *name = fname->usr_fname->name;
	size_t ra_max = 0;	/* 预读的bh数量, bh_use[] */
	size_t ra_ptr = 0;	// 预读的下标
	ext4_lblk_t  nblocks;
	int i, namelen, retval;

	*res_dir = NULL;
	// 超级块
	sb = dir->i_sb;
	// 文件名长度
	namelen = fname->usr_fname->len;
	// 文件名不超过255
	if (namelen > EXT4_NAME_LEN)
		return NULL;

	// 判断有无inline数据.todo: 后面看
	if (ext4_has_inline_data(dir)) {
		int has_inline_data = 1;
		ret = ext4_find_inline_entry(dir, fname, res_dir,
					     &has_inline_data);
		if (has_inline_data) {
			if (inlined)
				*inlined = 1;
			goto cleanup_and_exit;
		}
	}

	// '.'和'..'在第0个块里, 所以直接去下面搜索
	if ((namelen <= 2) && (name[0] == '.') &&
	    (name[1] == '.' || name[1] == '\0')) {
		block = start = 0;
		// '.', '..', 只可能有一个块
		nblocks = 1;
		goto restart;
	}

	// dir_dx是使用哈希表存储目录entry项.
	if (is_dx(dir)) {
		ret = ext4_dx_find_entry(dir, fname, res_dir);
		/*
		 * 成功时, 或者错误是文件未找到, 则返回.
		 * 否则, 退回到老的查找方式
		 * 
		 * ERR_BAD_DX_DIR是错误的哈希目录,这种情况也退回到普通查找
		 */
		if (!IS_ERR(ret) || PTR_ERR(ret) != ERR_BAD_DX_DIR)
			goto cleanup_and_exit;
		dxtrace(printk(KERN_DEBUG "ext4_find_entry: dx failed, "
			       "falling back\n"));
		ret = NULL;
	}
	// 目录大小共有多少个块
	nblocks = dir->i_size >> EXT4_BLOCK_SIZE_BITS(sb);
	// 目录为空
	if (!nblocks) {
		ret = NULL;
		goto cleanup_and_exit;
	}
	// 开始查找的块,从上一次查找的地方开始找, 根据局部性原理可以加速查找
	start = EXT4_I(dir)->i_dir_start_lookup;
	// 如果上一次已经找到最后一个// 判断最多预读多少块块,则再从头开始再找
	if (start >= nblocks)
		start = 0;

	// block记录的是当前块?
	block = start;
restart:
	do {
		cond_resched();

		// 如果到达预读点,
		// 第1次进来的时候 ra_ptr, ra_max都是0
		if (ra_ptr >= ra_max) {
			ra_ptr = 0;
			
			if (block < start)
				// 如果小于start说明已经读到末尾,又从头读了, 所以
				// 只需读'start-block'个块就行
				ra_max = start - block;
			else
				// 刚开始进来的时候,block==start, 所以ra_max=nblocks
				ra_max = nblocks - block;
			// 取与8的最小值, 最多预读8个
			ra_max = min(ra_max, ARRAY_SIZE(bh_use));

			// 给bh_use批量读取ra_max个块
			retval = ext4_bread_batch(dir, block, ra_max,
						  false /* 不等待 */, bh_use);
			// 读块出错
			if (retval) {
				ret = ERR_PTR(retval);
				ra_max = 0;
				goto cleanup_and_exit;
			}
		}
		// 经过预读之后应该都有值,如果是NULL,说明是个洞
		if ((bh = bh_use[ra_ptr++]) == NULL)
			goto next;
		// 等待bh完成
		wait_on_buffer(bh);
		// 等待完成之后,bh还不是最新的,说明出错了
		if (!buffer_uptodate(bh)) {
			EXT4_ERROR_INODE_ERR(dir, EIO,
					     "reading directory lblock %lu",
					     (unsigned long) block);
			brelse(bh);
			ret = ERR_PTR(-EIO);
			goto cleanup_and_exit;
		}
		// bh无verified标志 && 不是dx内部? && dirblock校验和不通过,则报错
		if (!buffer_verified(bh) &&
		    !is_dx_internal_node(dir, block,
					 (struct ext4_dir_entry *)bh->b_data) &&
		    !ext4_dirblock_csum_verify(dir, bh)) {
			EXT4_ERROR_INODE_ERR(dir, EFSBADCRC,
					     "checksumming directory "
					     "block %lu", (unsigned long)block);
			brelse(bh);
			ret = ERR_PTR(-EFSBADCRC);
			goto cleanup_and_exit;
		}
		// 设置校验标志
		set_buffer_verified(bh);
		// 在bh里查找文件名, 如果找到了res_dir会带回找到的结果
		i = search_dirblock(bh, dir, fname,
			    block << EXT4_BLOCK_SIZE_BITS(sb), res_dir);
		if (i == 1) {
			// 找到了

			// 设置父目录上次找的块号
			EXT4_I(dir)->i_dir_start_lookup = block;
			// 返回bh
			ret = bh;
			goto cleanup_and_exit;
		} else {
			// 没找到

			// 减少bh引用
			brelse(bh);

			// 如果出错,则退出
			if (i < 0)
				goto cleanup_and_exit;
		}
	next:
		// 这个块没有,找下一个块
		if (++block >= nblocks)
			block = 0;
	} while (block != start);

	// 走到这儿表示没找到

	/*
	 * 在我们搜索期间,如果目录增长了,那再搜索目录的最后一部分在放弃之前
	 */
	block = nblocks;
	// 再读一下目录大小
	nblocks = dir->i_size >> EXT4_BLOCK_SIZE_BITS(sb);

	// 如果目录大小变了,再找一次
	if (block < nblocks) {
		// 这里把start设为0, 说明只需要再查找新增加的块就行
		start = 0;
		goto restart;
	}

cleanup_and_exit:
	// 释放ra_ptr之后的bh引用, 
	for (; ra_ptr < ra_max; ra_ptr++)
		brelse(bh_use[ra_ptr]);
	return ret;
}

static inline int ext4_has_inline_data(struct inode *inode)
{
	return ext4_test_inode_flag(inode, EXT4_INODE_INLINE_DATA) &&
	       EXT4_I(inode)->i_inline_off;
}

#define is_dx(dir) (ext4_has_feature_dir_index((dir)->i_sb) && \
		    ext4_test_inode_flag((dir), EXT4_INODE_INDEX))

int ext4_bread_batch(struct inode *inode, ext4_lblk_t block, int bh_count,
		     bool wait, struct buffer_head **bhs)
{
	int i, err;

	for (i = 0; i < bh_count; i++) {
		// 从内存里读取块或创建一个新块
		bhs[i] = ext4_getblk(NULL, inode, block + i, 0 /* map_flags */);
		if (IS_ERR(bhs[i])) {
			err = PTR_ERR(bhs[i]);
			bh_count = i;
			goto out_brelse;
		}
	}

	for (i = 0; i < bh_count; i++)
		// 如果块不是最新的或者是新建的bh,则从盘上读
		if (bhs[i] && !ext4_buffer_uptodate(bhs[i]))
			ext4_read_bh_lock(bhs[i], REQ_META | REQ_PRIO, false);

	// 不等待的话,直接返回
	if (!wait)
		return 0;

	// 走到这儿表示等待, 等待bh读完
	for (i = 0; i < bh_count; i++)
		if (bhs[i])
			wait_on_buffer(bhs[i]);

	// 经过上面的wait_on_buffer后,如果还不是最新的,说明出错了.
	for (i = 0; i < bh_count; i++) {
		if (bhs[i] && !buffer_uptodate(bhs[i])) {
			err = -EIO;
			goto out_brelse;
		}
	}
	return 0;

out_brelse:
	// 如果出错了就释放所有的bh
	for (i = 0; i < bh_count; i++) {
		brelse(bhs[i]);
		bhs[i] = NULL;
	}
	return err;
}

static int is_dx_internal_node(struct inode *dir, ext4_lblk_t block,
			       struct ext4_dir_entry *de)
{
	struct super_block *sb = dir->i_sb;

	// 无哈希目录特性
	if (!is_dx(dir))
		return 0;
	// 第0块
	if (block == 0)
		return 1;
	// 还没有inode
	if (de->inode == 0 &&
		// 如果页大小不大于65536, 则ext4_rec_len_from_disk返回rec_len
	    ext4_rec_len_from_disk(de->rec_len, sb->s_blocksize) ==
			sb->s_blocksize)
		return 1;
	return 0;
}

int ext4_dirblock_csum_verify(struct inode *inode, struct buffer_head *bh)
{
	struct ext4_dir_entry_tail *t;

	if (!ext4_has_metadata_csum(inode->i_sb))
		return 1;

	t = get_dirent_tail(inode, bh);
	if (!t) {
		warn_no_space_for_csum(inode);
		return 0;
	}

	if (t->det_checksum != ext4_dirblock_csum(inode, bh->b_data,
						  (char *)t - bh->b_data))
		return 0;

	return 1;
}

#define ext4_read_dirblock(inode, block, type) \
	__ext4_read_dirblock((inode), (block), (type), __func__, __LINE__)

static struct buffer_head *__ext4_read_dirblock(struct inode *inode,
						ext4_lblk_t block,
						dirblock_type_t type,
						const char *func,
						unsigned int line)
{
	struct buffer_head *bh;
	struct ext4_dir_entry *dirent;
	int is_dx_block = 0;

	if (ext4_simulate_fail(inode->i_sb, EXT4_SIM_DIRBLOCK_EIO))
		bh = ERR_PTR(-EIO);
	else
		bh = ext4_bread(NULL, inode, block, 0);
	if (IS_ERR(bh)) {
		__ext4_warning(inode->i_sb, func, line,
			       "inode #%lu: lblock %lu: comm %s: "
			       "error %ld reading directory block",
			       inode->i_ino, (unsigned long)block,
			       current->comm, PTR_ERR(bh));

		return bh;
	}
	if (!bh && (type == INDEX || type == DIRENT_HTREE)) {
		ext4_error_inode(inode, func, line, block,
				 "Directory hole found for htree %s block",
				 (type == INDEX) ? "index" : "leaf");
		return ERR_PTR(-EFSCORRUPTED);
	}
	if (!bh)
		return NULL;
	dirent = (struct ext4_dir_entry *) bh->b_data;
	/* Determine whether or not we have an index block */
	if (is_dx(inode)) {
		if (block == 0)
			is_dx_block = 1;
		else if (ext4_rec_len_from_disk(dirent->rec_len,
						inode->i_sb->s_blocksize) ==
			 inode->i_sb->s_blocksize)
			is_dx_block = 1;
	}
	if (!is_dx_block && type == INDEX) {
		ext4_error_inode(inode, func, line, block,
		       "directory leaf block found instead of index block");
		brelse(bh);
		return ERR_PTR(-EFSCORRUPTED);
	}
	if (!ext4_has_metadata_csum(inode->i_sb) ||
	    buffer_verified(bh))
		return bh;

	/*
	 * An empty leaf block can get mistaken for a index block; for
	 * this reason, we can only check the index checksum when the
	 * caller is sure it should be an index block.
	 */
	if (is_dx_block && type == INDEX) {
		if (ext4_dx_csum_verify(inode, dirent) &&
		    !ext4_simulate_fail(inode->i_sb, EXT4_SIM_DIRBLOCK_CRC))
			set_buffer_verified(bh);
		else {
			ext4_error_inode_err(inode, func, line, block,
					     EFSBADCRC,
					     "Directory index failed checksum");
			brelse(bh);
			return ERR_PTR(-EFSBADCRC);
		}
	}
	if (!is_dx_block) {
		if (ext4_dirblock_csum_verify(inode, bh) &&
		    !ext4_simulate_fail(inode->i_sb, EXT4_SIM_DIRBLOCK_CRC))
			set_buffer_verified(bh);
		else {
			ext4_error_inode_err(inode, func, line, block,
					     EFSBADCRC,
					     "Directory block failed checksum");
			brelse(bh);
			return ERR_PTR(-EFSBADCRC);
		}
	}
	return bh;
}
```

