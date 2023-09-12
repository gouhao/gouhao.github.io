# blkcg_writeback
源码基于5.10

## wbc_init_bio
```c
static inline void wbc_init_bio(struct writeback_control *wbc, struct bio *bio)
{
	/*
	 * pageout() path doesn't attach @wbc to the inode being written
	 * out.  This is intentional as we don't want the function to block
	 * behind a slow cgroup.  Ultimately, we want pageout() to kick off
	 * regular writeback instead of writing things out itself.
	 */
	if (wbc->wb)
		bio_associate_blkg_from_css(bio, wbc->wb->blkcg_css);
}
```

## wbc_account_cgroup_owner
```c
void wbc_account_cgroup_owner(struct writeback_control *wbc, struct page *page,
			      size_t bytes)
{
	struct cgroup_subsys_state *css;
	int id;

	/*
	 * pageout() path doesn't attach @wbc to the inode being written
	 * out.  This is intentional as we don't want the function to block
	 * behind a slow cgroup.  Ultimately, we want pageout() to kick off
	 * regular writeback instead of writing things out itself.
	 */
	if (!wbc->wb || wbc->no_cgroup_owner)
		return;

	css = mem_cgroup_css_from_page(page);
	/* dead cgroups shouldn't contribute to inode ownership arbitration */
	if (!(css->flags & CSS_ONLINE))
		return;

	id = css->id;

	if (id == wbc->wb_id) {
		wbc->wb_bytes += bytes;
		return;
	}

	if (id == wbc->wb_lcand_id)
		wbc->wb_lcand_bytes += bytes;

	/* Boyer-Moore majority vote algorithm */
	if (!wbc->wb_tcand_bytes)
		wbc->wb_tcand_id = id;
	if (id == wbc->wb_tcand_id)
		wbc->wb_tcand_bytes += bytes;
	else
		wbc->wb_tcand_bytes -= min(bytes, wbc->wb_tcand_bytes);
}
```