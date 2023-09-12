# buffer head
源码基于5.10

```c
struct buffer_head {
	unsigned long b_state;		// 状态位图
	struct buffer_head *b_this_page; // 链到同一页的bh用这个字段连接，是一个环形表
	struct page *b_page;		// 映射的页面

	sector_t b_blocknr;		// 开始的块号
	size_t b_size;			// 块长度
	char *b_data;			// 数据指针

	struct block_device *b_bdev;
	bh_end_io_t *b_end_io;		// io结束时调的函数
 	void *b_private;		// b_end_io的数据
	struct list_head b_assoc_buffers; /* associated with another mapping */
	struct address_space *b_assoc_map;	/* mapping this buffer is
						   associated with */
	atomic_t b_count;		// 缓冲头的引用计数
	spinlock_t b_uptodate_lock;	/* Used by the first bh in a page, to
					 * serialise IO completion of other
					 * buffers in the page */
};

#define BH_LRU_SIZE	16

struct bh_lru {
	struct buffer_head *bhs[BH_LRU_SIZE];
};

static DEFINE_PER_CPU(struct bh_lru, bh_lrus) = {{ NULL }};
```