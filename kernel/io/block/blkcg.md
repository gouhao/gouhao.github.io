# blkcg
源码基于5.10

## blk_cgroup_bio_start
```c
void blk_cgroup_bio_start(struct bio *bio)
{
	int rwd = blk_cgroup_io_type(bio), cpu;
	struct blkg_iostat_set *bis;

	cpu = get_cpu();
	bis = per_cpu_ptr(bio->bi_blkg->iostat_cpu, cpu);
	u64_stats_update_begin(&bis->sync);

	/*
	 * If the bio is flagged with BIO_CGROUP_ACCT it means this is a split
	 * bio and we would have already accounted for the size of the bio.
	 */
	if (!bio_flagged(bio, BIO_CGROUP_ACCT)) {
		bio_set_flag(bio, BIO_CGROUP_ACCT);
		bis->cur.bytes[rwd] += bio->bi_iter.bi_size;
	}
	bis->cur.ios[rwd]++;

	u64_stats_update_end(&bis->sync);
	if (cgroup_subsys_on_dfl(io_cgrp_subsys))
		cgroup_rstat_updated(bio->bi_blkg->blkcg->css.cgroup, cpu);
	put_cpu();
}
```

## blkcg_bio_issue_init
```c
static inline void blkcg_bio_issue_init(struct bio *bio)
{
	bio_issue_init(&bio->bi_issue, bio_sectors(bio));
}
```

## blk_throtl_charge_bio_split
```c
void blk_throtl_charge_bio_split(struct bio *bio)
{
	struct blkcg_gq *blkg = bio->bi_blkg;
	struct throtl_grp *parent = blkg_to_tg(blkg);
	struct throtl_service_queue *parent_sq;
	bool rw = bio_data_dir(bio);

	do {
		if (!parent->has_rules[rw])
			break;

		atomic_inc(&parent->io_split_cnt[rw]);
		atomic_inc(&parent->last_io_split_cnt[rw]);

		parent_sq = parent->service_queue.parent_sq;
		parent = sq_to_tg(parent_sq);
	} while (parent);
}

```

## blkcg_punt_bio_submit
```c
static inline bool blkcg_punt_bio_submit(struct bio *bio)
{
	if (bio->bi_opf & REQ_CGROUP_PUNT)
		return __blkcg_punt_bio_submit(bio);
	else
		return false;
}
```