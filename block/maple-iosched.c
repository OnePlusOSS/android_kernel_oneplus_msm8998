/*
 * Maple I/O Scheduler
 * Heavily based on Zen, with some parts from Tripndroid.
 *
 * Copyright (C) 2012 Brandon Berhent <bbedward@gmail.com>
 *           (C) 2014 LoungeKatt <twistedumbrella@gmail.com>
 *				 2015 Fixes to stop crashing on 3.10 by Matthew Alex <matthewalex@outlook.com>
 *           (C) 2016 Joe Maples <joe@frap129.org>
 */
#include <linux/blkdev.h>
#include <linux/elevator.h>
#include <linux/bio.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>
#ifdef CONFIG_POWERSUSPEND
#include <linux/powersuspend.h>
#endif

enum maple_sync { ASYNC, SYNC };

static const int sync_read_expire  = 150;    /* max time before a read sync is submitted. */
static const int sync_write_expire  = 150;    /* max time before a write sync is submitted. */
static const int async_read_expire = 900;    /* ditto for read async, these limits are SOFT! */
static const int async_write_expire = 900;    /* ditto for write async, these limits are SOFT! */
static const int fifo_batch = 16;
static const int writes_starved = 1;	/* max times reads can starve a write */
static const int sleep_latency_multiple = 3;	/* multple for expire time when device is asleep */

struct maple_data {
	/* Runtime Data */
	/* Requests are only present on fifo_list */
	struct list_head fifo_list[2][2];

        unsigned int batching;          /* number of sequential requests made */
				unsigned int starved;

	/* tunables */
	int fifo_expire[2][2];
	int fifo_batch;
	int writes_starved;
	int sleep_latency_multiple;
};

static inline struct maple_data *
maple_get_data(struct request_queue *q) {
	return q->elevator->elevator_data;
}

static void maple_dispatch(struct maple_data *, struct request *);

static void
maple_merged_requests(struct request_queue *q, struct request *rq,
                    struct request *next)
{
	/*
	 * if next expires before rq, assign its expire time to arq
	 * and move into next position (next will be deleted) in fifo
	 */
	if (!list_empty(&rq->queuelist) && !list_empty(&next->queuelist)) {
		if (time_before(rq_fifo_time(next), rq_fifo_time(rq))) {
			list_move(&rq->queuelist, &next->queuelist);
			rq_set_fifo_time(rq, rq_fifo_time(next));
		}
	}

	/* next request is gone */
	rq_fifo_clear(next);
}

static void maple_add_request(struct request_queue *q, struct request *rq)
{
	struct maple_data *mdata = maple_get_data(q);
	const int sync = rq_is_sync(rq);
	const int dir = rq_data_dir(rq);

#ifdef CONFIG_POWERSUSPEND
	/* inrease expiration when device is asleep */
	unsigned int fifo_expire_suspended = mdata->fifo_expire[sync][dir] * sleep_latency_multiple;
	if (!power_suspended && mdata->fifo_expire[sync][dir]) {
		rq_set_fifo_time(rq, jiffies + mdata->fifo_expire[sync][dir]);
		list_add_tail(&rq->queuelist, &mdata->fifo_list[sync][dir]);
	}	else if (power_suspended && fifo_expire_suspended) {
		rq_set_fifo_time(rq, jiffies + fifo_expire_suspended);
		list_add_tail(&rq->queuelist, &mdata->fifo_list[sync][dir]);
	}
#else
	if (mdata->fifo_expire[sync][dir]) {
		rq_set_fifo_time(rq, jiffies + mdata->fifo_expire[sync][dir]);
		list_add_tail(&rq->queuelist, &mdata->fifo_list[sync][dir]);
	}
#endif
}

static void maple_dispatch(struct maple_data *mdata, struct request *rq)
{
	/* Remove request from list and dispatch it */
	rq_fifo_clear(rq);
	elv_dispatch_add_tail(rq->q, rq);

	/* Increment # of sequential requests */
	mdata->batching++;

	if (rq_data_dir(rq))
		mdata->starved = 0;
	else
		mdata->starved++;
}

/*
 * get the first expired request in direction ddir
 */
static struct request *
maple_expired_request(struct maple_data *mdata, int ddir, int rqtype)
{
        struct request *rq;

        if (list_empty(&mdata->fifo_list[ddir][rqtype]))
                return NULL;

        rq = rq_entry_fifo(mdata->fifo_list[ddir][rqtype].next);
        if (time_after(jiffies, rq_fifo_time(rq)))
                return rq;

        return NULL;
}

/*
 * maple_check_fifo returns 0 if there are no expired requests on the fifo,
 * otherwise it returns the next expired request
 */
static struct request *
maple_check_fifo(struct maple_data *mdata)
{
        struct request *rq_sync_read = maple_expired_request(mdata, SYNC, READ);
				struct request *rq_sync_write = maple_expired_request(mdata, SYNC, WRITE);
        struct request *rq_async_read = maple_expired_request(mdata, ASYNC, READ);
				struct request *rq_async_write = maple_expired_request(mdata, ASYNC, WRITE);

        if (rq_async_read && rq_sync_read) {
        	if (time_after(rq_fifo_time(rq_async_read), rq_fifo_time(rq_async_read)))
                	return rq_sync_read;
        } else if (rq_sync_read) {
                return rq_sync_read;
				} else if (rq_async_read) {
								return rq_async_read;
				}

				if (rq_async_write && rq_sync_write) {
					if (time_after(rq_fifo_time(rq_async_write), rq_fifo_time(rq_sync_write)))
									return rq_sync_write;
				} else if (rq_sync_write) {
								return rq_sync_write;
				} else if (rq_async_write) {
								return rq_async_write;
				}

        return 0;
}

static struct request *
maple_choose_request(struct maple_data *mdata, int rqtype)
{
        /*
         * Retrieve request from available fifo list.
         * Synchronous requests have priority over asynchronous.
				 * Read requests have priority over writes.
         */
			 	if (!list_empty(&mdata->fifo_list[SYNC][rqtype]))
               	return rq_entry_fifo(mdata->fifo_list[SYNC][rqtype].next);
       	if (!list_empty(&mdata->fifo_list[ASYNC][rqtype]))
               	return rq_entry_fifo(mdata->fifo_list[ASYNC][rqtype].next);

        return NULL;
}

static int maple_dispatch_requests(struct request_queue *q, int force)
{
	struct maple_data *mdata = maple_get_data(q);
	struct request *rq = NULL;
	int readwrite = READ;

	/* Check for and issue expired requests */
	if (mdata->batching > mdata->fifo_batch) {
		mdata->batching = 0;
		rq = maple_check_fifo(mdata);
	}

	if (!rq) {
		if (mdata->starved > mdata->writes_starved)
			readwrite = WRITE;

		rq = maple_choose_request(mdata, readwrite);
		if (!rq)
			return 0;
	}

	maple_dispatch(mdata, rq);

	return 1;
}

static int maple_init_queue(struct request_queue *q, struct elevator_type *e)
{
	struct maple_data *mdata;
    struct elevator_queue *eq;

    eq = elevator_alloc(q, e);
    if (!eq)
        return -ENOMEM;

	mdata = kmalloc_node(sizeof(*mdata), GFP_KERNEL, q->node);
    if (!mdata) {
        kobject_put(&eq->kobj);
        return -ENOMEM;
    }
    eq->elevator_data = mdata;

    spin_lock_irq(q->queue_lock);
	q->elevator = eq;
	spin_unlock_irq(q->queue_lock);

	INIT_LIST_HEAD(&mdata->fifo_list[SYNC][READ]);
	INIT_LIST_HEAD(&mdata->fifo_list[SYNC][WRITE]);
	INIT_LIST_HEAD(&mdata->fifo_list[ASYNC][READ]);
	INIT_LIST_HEAD(&mdata->fifo_list[ASYNC][WRITE]);
	mdata->fifo_expire[SYNC][READ] = sync_read_expire;
	mdata->fifo_expire[SYNC][WRITE] = sync_write_expire;
	mdata->fifo_expire[ASYNC][READ] = async_read_expire;
	mdata->fifo_expire[ASYNC][WRITE] = async_write_expire;
	mdata->fifo_batch = fifo_batch;
	mdata->writes_starved = writes_starved;
	mdata->sleep_latency_multiple = sleep_latency_multiple;
	return 0;
}

static void maple_exit_queue(struct elevator_queue *e)
{
	struct maple_data *mdata = e->elevator_data;

	BUG_ON(!list_empty(&mdata->fifo_list[SYNC][READ]));
	BUG_ON(!list_empty(&mdata->fifo_list[SYNC][WRITE]));
	BUG_ON(!list_empty(&mdata->fifo_list[ASYNC][READ]));
	BUG_ON(!list_empty(&mdata->fifo_list[ASYNC][WRITE]));
	kfree(mdata);
}

/* Sysfs */
static ssize_t
maple_var_show(int var, char *page)
{
	return sprintf(page, "%d\n", var);
}

static ssize_t
maple_var_store(int *var, const char *page, size_t count)
{
	*var = simple_strtol(page, NULL, 10);
	return count;
}

#define SHOW_FUNCTION(__FUNC, __VAR, __CONV) \
static ssize_t __FUNC(struct elevator_queue *e, char *page) \
{ \
	struct maple_data *mdata = e->elevator_data; \
	int __data = __VAR; \
	if (__CONV) \
		__data = jiffies_to_msecs(__data); \
		return maple_var_show(__data, (page)); \
}
SHOW_FUNCTION(maple_sync_read_expire_show, mdata->fifo_expire[SYNC][READ], 1);
SHOW_FUNCTION(maple_sync_write_expire_show, mdata->fifo_expire[SYNC][WRITE], 1);
SHOW_FUNCTION(maple_async_read_expire_show, mdata->fifo_expire[ASYNC][READ], 1);
SHOW_FUNCTION(maple_async_write_expire_show, mdata->fifo_expire[ASYNC][WRITE], 1);
SHOW_FUNCTION(maple_fifo_batch_show, mdata->fifo_batch, 0);
SHOW_FUNCTION(maple_writes_starved_show, mdata->writes_starved, 0);
SHOW_FUNCTION(maple_sleep_latency_multiple_show, mdata->sleep_latency_multiple, 0);
#undef SHOW_FUNCTION

#define STORE_FUNCTION(__FUNC, __PTR, MIN, MAX, __CONV) \
static ssize_t __FUNC(struct elevator_queue *e, const char *page, size_t count) \
{ \
	struct maple_data *mdata = e->elevator_data; \
	int __data; \
	int ret = maple_var_store(&__data, (page), count); \
	if (__data < (MIN)) \
		__data = (MIN); \
	else if (__data > (MAX)) \
		__data = (MAX); \
	if (__CONV) \
		*(__PTR) = msecs_to_jiffies(__data); \
	else \
		*(__PTR) = __data; \
	return ret; \
}
STORE_FUNCTION(maple_sync_read_expire_store, &mdata->fifo_expire[SYNC][READ], 0, INT_MAX, 1);
STORE_FUNCTION(maple_sync_write_expire_store, &mdata->fifo_expire[SYNC][WRITE], 0, INT_MAX, 1);
STORE_FUNCTION(maple_async_read_expire_store, &mdata->fifo_expire[ASYNC][READ], 0, INT_MAX, 1);
STORE_FUNCTION(maple_async_write_expire_store, &mdata->fifo_expire[ASYNC][WRITE], 0, INT_MAX, 1);
STORE_FUNCTION(maple_fifo_batch_store, &mdata->fifo_batch, 0, INT_MAX, 0);
STORE_FUNCTION(maple_writes_starved_store, &mdata->writes_starved, 0, INT_MAX, 0);
STORE_FUNCTION(maple_sleep_latency_multiple_store, &mdata->sleep_latency_multiple, 0, INT_MAX, 0);
#undef STORE_FUNCTION

#define DD_ATTR(name) \
        __ATTR(name, S_IRUGO|S_IWUSR, maple_##name##_show, \
                                      maple_##name##_store)

static struct elv_fs_entry maple_attrs[] = {
        DD_ATTR(sync_read_expire),
				DD_ATTR(sync_write_expire),
        DD_ATTR(async_read_expire),
				DD_ATTR(async_write_expire),
        DD_ATTR(fifo_batch),
				DD_ATTR(writes_starved),
        DD_ATTR(sleep_latency_multiple),
        __ATTR_NULL
};

static struct elevator_type iosched_maple = {
	.ops = {
		.elevator_merge_req_fn		= maple_merged_requests,
		.elevator_dispatch_fn		= maple_dispatch_requests,
		.elevator_add_req_fn		= maple_add_request,
		.elevator_former_req_fn         = elv_rb_former_request,
		.elevator_latter_req_fn         = elv_rb_latter_request,
		.elevator_init_fn		= maple_init_queue,
		.elevator_exit_fn		= maple_exit_queue,
	},
	.elevator_attrs = maple_attrs,
	.elevator_name = "maple",
	.elevator_owner = THIS_MODULE,
};

static int __init maple_init(void)
{
	return elv_register(&iosched_maple);
}

static void __exit maple_exit(void)
{
	elv_unregister(&iosched_maple);
}

module_init(maple_init);
module_exit(maple_exit);

MODULE_AUTHOR("Brandon Berhent");
MODULE_AUTHOR("TripNRaVeR");
MODULE_AUTHOR("Joe Maples <joe@frap129.org>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Maple I/O Scheduler");
MODULE_VERSION("1.0");

