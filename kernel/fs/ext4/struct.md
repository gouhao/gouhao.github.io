# ext4用到的数据结构

```c
// 映射块时使用
struct ext4_map_blocks {
	ext4_fsblk_t m_pblk; // 第1个物理块
	ext4_lblk_t m_lblk; // 第1个逻辑块
	unsigned int m_len; // 所需块数量
	unsigned int m_flags;
};

struct extent_status {
	struct rb_node rb_node;
	ext4_lblk_t es_lblk;	// 第1个逻辑块
	ext4_lblk_t es_len;	// 块数量
	ext4_fsblk_t es_pblk;	// 第1个物理块
};

struct ext4_es_tree {
	struct rb_root root;
	struct extent_status *cache_es;	// 最近访问的extent
};

struct ext4_extent_idx {
	__le32	ei_block;	/* index covers logical blocks from 'block' */
	__le32	ei_leaf_lo;	/* pointer to the physical block of the next *
				 * level. leaf or next index could be there */
	__le16	ei_leaf_hi;	/* high 16 bits of physical block */
	__u16	ei_unused;
};

struct ext4_extent {
	__le32	ee_block;	/* first logical block extent covers */
	__le16	ee_len;		/* number of blocks covered by extent */
	__le16	ee_start_hi;	/* high 16 bits of physical block */
	__le32	ee_start_lo;	/* low 32 bits of physical block */
};

struct ext4_free_extent {
	ext4_lblk_t fe_logical;
	ext4_grpblk_t fe_start;	/* In cluster units */
	ext4_group_t fe_group;
	ext4_grpblk_t fe_len;	/* In cluster units */
};

struct ext4_allocation_context {
	struct inode *ac_inode;
	struct super_block *ac_sb;

	/* 原始请求 */
	struct ext4_free_extent ac_o_ex;

	/* 目标请求 (标准化的 ac_o_ex) */
	struct ext4_free_extent ac_g_ex;

	/* 找到的最好的extent */
	struct ext4_free_extent ac_b_ex;

	/* 在预分配之前复制找到的最好的extent */
	struct ext4_free_extent ac_f_ex;

	__u16 ac_groups_scanned;
	__u16 ac_found;
	__u16 ac_tail;
	__u16 ac_buddy;
	__u16 ac_flags;		/* allocation hints */
	__u8 ac_status;
	__u8 ac_criteria;
	__u8 ac_2order;		/* if request is to allocate 2^N blocks and
				 * N > 0, the field stores N, otherwise 0 */
	__u8 ac_op;		/* operation, for history only */
	struct page *ac_bitmap_page;
	struct page *ac_buddy_page;
	struct ext4_prealloc_space *ac_pa;
	struct ext4_locality_group *ac_lg;
};

struct ext4_allocation_request {
	/* target inode for block we're allocating */
	struct inode *inode;
	/* how many blocks we want to allocate */
	unsigned int len;
	/* logical block in target inode */
	ext4_lblk_t logical;
	/* the closest logical allocated block to the left */
	ext4_lblk_t lleft;
	/* the closest logical allocated block to the right */
	ext4_lblk_t lright;
	/* phys. target (a hint) */
	ext4_fsblk_t goal;
	/* phys. block for the closest logical allocated block to the left */
	ext4_fsblk_t pleft;
	/* phys. block for the closest logical allocated block to the right */
	ext4_fsblk_t pright;
	/* flags. see above EXT4_MB_HINT_* */
	unsigned int flags;
};

struct ext4_iloc
{
	struct buffer_head *bh; // block数据
	unsigned long offset; // 偏移
	ext4_group_t block_group; // 块组描述
};
```