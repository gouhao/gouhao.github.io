# fs crypto
```c
void fscrypt_set_bio_crypt_ctx_bh(struct bio *bio,
				  const struct buffer_head *first_bh,
				  gfp_t gfp_mask)
{
	const struct inode *inode;
	u64 first_lblk;

	if (bh_get_inode_and_lblk_num(first_bh, &inode, &first_lblk))
		fscrypt_set_bio_crypt_ctx(bio, inode, first_lblk, gfp_mask);
}
```

## blk_crypto_init_request
```c
static inline blk_status_t blk_crypto_init_request(struct request *rq)
{
	if (blk_crypto_rq_is_encrypted(rq))
		return __blk_crypto_init_request(rq);
	return BLK_STS_OK;
}

blk_status_t __blk_crypto_init_request(struct request *rq)
{
	return blk_ksm_get_slot_for_key(rq->q->ksm, rq->crypt_ctx->bc_key,
					&rq->crypt_keyslot);
}

blk_status_t blk_ksm_get_slot_for_key(struct blk_keyslot_manager *ksm,
				      const struct blk_crypto_key *key,
				      struct blk_ksm_keyslot **slot_ptr)
{
	struct blk_ksm_keyslot *slot;
	int slot_idx;
	int err;

	*slot_ptr = NULL;
	down_read(&ksm->lock);
	slot = blk_ksm_find_and_grab_keyslot(ksm, key);
	up_read(&ksm->lock);
	if (slot)
		goto success;

	for (;;) {
		blk_ksm_hw_enter(ksm);
		slot = blk_ksm_find_and_grab_keyslot(ksm, key);
		if (slot) {
			blk_ksm_hw_exit(ksm);
			goto success;
		}

		/*
		 * If we're here, that means there wasn't a slot that was
		 * already programmed with the key. So try to program it.
		 */
		if (!list_empty(&ksm->idle_slots))
			break;

		blk_ksm_hw_exit(ksm);
		wait_event(ksm->idle_slots_wait_queue,
			   !list_empty(&ksm->idle_slots));
	}

	slot = list_first_entry(&ksm->idle_slots, struct blk_ksm_keyslot,
				idle_slot_node);
	slot_idx = blk_ksm_get_slot_idx(slot);

	err = ksm->ksm_ll_ops.keyslot_program(ksm, key, slot_idx);
	if (err) {
		wake_up(&ksm->idle_slots_wait_queue);
		blk_ksm_hw_exit(ksm);
		return errno_to_blk_status(err);
	}

	/* Move this slot to the hash list for the new key. */
	if (slot->key)
		hlist_del(&slot->hash_node);
	slot->key = key;
	hlist_add_head(&slot->hash_node, blk_ksm_hash_bucket_for_key(ksm, key));

	atomic_set(&slot->slot_refs, 1);

	blk_ksm_remove_slot_from_lru_list(slot);

	blk_ksm_hw_exit(ksm);
success:
	*slot_ptr = slot;
	return BLK_STS_OK;
}
```

## blk_crypto_rq_bio_prep
```c
static inline int blk_crypto_rq_bio_prep(struct request *rq, struct bio *bio,
					 gfp_t gfp_mask)
{
	if (bio_has_crypt_ctx(bio))
		return __blk_crypto_rq_bio_prep(rq, bio, gfp_mask);
	return 0;
}
```