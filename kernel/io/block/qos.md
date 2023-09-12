## qos
源码基于5.10

## rq_qos_throttle
```c
static inline void rq_qos_throttle(struct request_queue *q, struct bio *bio)
{
	/*
	 * BIO_TRACKED lets controllers know that a bio went through the
	 * normal rq_qos path.
	 */
	bio_set_flag(bio, BIO_TRACKED);
	if (q->rq_qos)
		__rq_qos_throttle(q->rq_qos, bio);
}

void __rq_qos_throttle(struct rq_qos *rqos, struct bio *bio)
{
	do {
		if (rqos->ops->throttle)
			rqos->ops->throttle(rqos, bio);
		rqos = rqos->next;
	} while (rqos);
}
```

## rq_qos_cleanup
```c
static inline void rq_qos_cleanup(struct request_queue *q, struct bio *bio)
{
	if (q->rq_qos)
		__rq_qos_cleanup(q->rq_qos, bio);
}

void __rq_qos_cleanup(struct rq_qos *rqos, struct bio *bio)
{
	do {
		if (rqos->ops->cleanup)
			rqos->ops->cleanup(rqos, bio);
		rqos = rqos->next;
	} while (rqos);
}
```

## rq_qos_track
```c
static inline void rq_qos_track(struct request_queue *q, struct request *rq,
				struct bio *bio)
{
	if (q->rq_qos)
		__rq_qos_track(q->rq_qos, rq, bio);
}

void __rq_qos_track(struct rq_qos *rqos, struct request *rq, struct bio *bio)
{
	do {
		if (rqos->ops->track)
			rqos->ops->track(rqos, rq, bio);
		rqos = rqos->next;
	} while (rqos);
}

```

## rq_qos_merge
```c
static inline void rq_qos_merge(struct request_queue *q, struct request *rq,
				struct bio *bio)
{
	if (q->rq_qos)
		__rq_qos_merge(q->rq_qos, rq, bio);
}
```