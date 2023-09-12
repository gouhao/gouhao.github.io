# 度量
源码基于5.10

## bio_integrity
```
static inline struct bio_integrity_payload *bio_integrity(struct bio *bio)
{
	if (bio->bi_opf & REQ_INTEGRITY)
		return bio->bi_integrity;

	return NULL;
}
```