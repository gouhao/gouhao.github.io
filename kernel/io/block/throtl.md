# 限流
源码基于5.10

## blk_throtl_bio
```c
bool blk_throtl_bio(struct bio *bio)
{
	struct request_queue *q = bio->bi_disk->queue;
	struct blkcg_gq *blkg = bio->bi_blkg;
	struct throtl_qnode *qn = NULL;
	struct throtl_grp *tg = blkg_to_tg(blkg);
	struct throtl_service_queue *sq;
	bool rw = bio_data_dir(bio);
	bool throttled = false;
	struct throtl_data *td = tg->td;

	rcu_read_lock();

	/* see throtl_charge_bio() */
	if (bio_flagged(bio, BIO_THROTTLED))
		goto out;

	if (!cgroup_subsys_on_dfl(io_cgrp_subsys)) {
		blkg_rwstat_add(&tg->stat_bytes, bio->bi_opf,
				bio->bi_iter.bi_size);
		blkg_rwstat_add(&tg->stat_ios, bio->bi_opf, 1);
	}

	if (!tg->has_rules[rw])
		goto out;

	spin_lock_irq(&q->queue_lock);

	throtl_update_latency_buckets(td);

	blk_throtl_update_idletime(tg);

	sq = &tg->service_queue;

again:
	while (true) {
		if (tg->last_low_overflow_time[rw] == 0)
			tg->last_low_overflow_time[rw] = jiffies;
		throtl_downgrade_check(tg);
		throtl_upgrade_check(tg);
		/* throtl is FIFO - if bios are already queued, should queue */
		if (sq->nr_queued[rw])
			break;

		/* if above limits, break to queue */
		if (!tg_may_dispatch(tg, bio, NULL)) {
			tg->last_low_overflow_time[rw] = jiffies;
			if (throtl_can_upgrade(td, tg)) {
				throtl_upgrade_state(td);
				goto again;
			}
			break;
		}

		/* within limits, let's charge and dispatch directly */
		throtl_charge_bio(tg, bio);

		/*
		 * We need to trim slice even when bios are not being queued
		 * otherwise it might happen that a bio is not queued for
		 * a long time and slice keeps on extending and trim is not
		 * called for a long time. Now if limits are reduced suddenly
		 * we take into account all the IO dispatched so far at new
		 * low rate and * newly queued IO gets a really long dispatch
		 * time.
		 *
		 * So keep on trimming slice even if bio is not queued.
		 */
		throtl_trim_slice(tg, rw);

		/*
		 * @bio passed through this layer without being throttled.
		 * Climb up the ladder.  If we're already at the top, it
		 * can be executed directly.
		 */
		qn = &tg->qnode_on_parent[rw];
		sq = sq->parent_sq;
		tg = sq_to_tg(sq);
		if (!tg)
			goto out_unlock;
	}

	/* out-of-limit, queue to @tg */
	throtl_log(sq, "[%c] bio. bdisp=%llu sz=%u bps=%llu iodisp=%u iops=%u queued=%d/%d",
		   rw == READ ? 'R' : 'W',
		   tg->bytes_disp[rw], bio->bi_iter.bi_size,
		   tg_bps_limit(tg, rw),
		   tg->io_disp[rw], tg_iops_limit(tg, rw),
		   sq->nr_queued[READ], sq->nr_queued[WRITE]);

	tg->last_low_overflow_time[rw] = jiffies;

	td->nr_queued[rw]++;
	throtl_add_bio_tg(bio, qn, tg);
	throttled = true;

	/*
	 * Update @tg's dispatch time and force schedule dispatch if @tg
	 * was empty before @bio.  The forced scheduling isn't likely to
	 * cause undue delay as @bio is likely to be dispatched directly if
	 * its @tg's disptime is not in the future.
	 */
	if (tg->flags & THROTL_TG_WAS_EMPTY) {
		tg_update_disptime(tg);
		throtl_schedule_next_dispatch(tg->service_queue.parent_sq, true);
	}

out_unlock:
	spin_unlock_irq(&q->queue_lock);
out:
	bio_set_flag(bio, BIO_THROTTLED);

#ifdef CONFIG_BLK_DEV_THROTTLING_LOW
	if (throttled || !td->track_bio_latency)
		bio->bi_issue.value |= BIO_ISSUE_THROTL_SKIP_LATENCY;
#endif
	rcu_read_unlock();
	return throttled;
}
```