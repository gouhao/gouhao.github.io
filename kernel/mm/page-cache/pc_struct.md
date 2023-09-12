# 结构体
源码基于5.10

```c
struct address_space {
	struct inode		*host; // 属主
	struct xarray		i_pages; // 基数树
	gfp_t			gfp_mask; // 分配一页时使所用的类型
	atomic_t		i_mmap_writable; // VM_SHARED类型的映射数量
#ifdef CONFIG_READ_ONLY_THP_FOR_FS
	/* number of thp, only for non-shmem files */
	atomic_t		nr_thps;
#endif
	struct rb_root_cached	i_mmap; // 私有和共享的映射
	struct rw_semaphore	i_mmap_rwsem;
	unsigned long		nrpages; // 有多少缓存的页
	unsigned long		nrexceptional; // 异常页的数量？
	pgoff_t			writeback_index; // 回写的开始位置
	const struct address_space_operations *a_ops; // 操作函数
	unsigned long		flags; // 标志
	errseq_t		wb_err; // 回写错误

	// 属主使用的一些私有锁和私有数据
	spinlock_t		private_lock;
	struct list_head	private_list;
	void			*private_data;
} __attribute__((aligned(sizeof(long)))) __randomize_layout;

struct lru_pvecs {
	local_lock_t lock;
	struct pagevec lru_add;
	struct pagevec lru_deactivate_file;
	struct pagevec lru_deactivate; // 不活跃的页
	struct pagevec lru_lazyfree; // 延迟释放
#ifdef CONFIG_SMP
	struct pagevec activate_page; // 活跃的页
#endif
};

struct pagevec {
	unsigned char nr; // 页的数量
	bool percpu_pvec_drained; // 是否正在排出？
	struct page *pages[PAGEVEC_SIZE]; // page数组，PAGEVEC_SIZE=15
};
```