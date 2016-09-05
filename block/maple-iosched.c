/*
 * Maple I/O Scheduler
 * Based on Zen and SIO.
 *
 * Copyright (C) 2016 Joe Maples <joe@frap129.org>
 *           (C) 2012 Brandon Berhent <bbedward@gmail.com
 *           (C) 2012 Miguel Boton <mboton@gmail.com>
 *
 * Maple uses a first come first serve style algorithm with seperated read/write
 * handling to allow for read biases. By prioritizing reads, simple tasks should improve
 * in performance. Maple also uses hooks for the powersuspend driver to increase
 * expirations when power is suspended to decrease workload.
 */
#include <linux/blkdev.h>
#include <linux/elevator.h>
#include <linux/bio.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/display_state.h>

#define MAPLE_IOSCHED_PATCHLEVEL	(7)

enum { ASYNC, SYNC };

/* Tunables */
static const int sync_read_expire = 100;	/* max time before a read sync is submitted. */
static const int sync_write_expire = 350;	/* max time before a write sync is submitted. */
static const int async_read_expire = 200;	/* ditto for read async, these limits are SOFT! */
static const int async_write_expire = 500;	/* ditto for write async, these limits are SOFT! */
static const int fifo_batch = 16;		/* # of sequential requests treated as one by the above parameters. */
static const int writes_starved = 3;		/* max times reads can starve a write */
static const int sleep_latency_multiple = 5;	/* multple for expire time when device is asleep */

/* Elevator data */
struct maple_data {
	/* Request queues */
	struct list_head fifo_list[2][2];

	/* Attributes */
	unsigned int batched;
	unsigned int starved;

	/* Settings */
	int fifo_expire[2][2];
	int fifo_batch;
	int writes_starved;
  int sleep_latency_multiple;
};

static inline struct maple_data *
maple_get_data(struct request_queue *q) {
	return q->elevator->elevator_data;
}

static void
maple_merged_requests(struct request_queue *q, struct request *rq,
		    struct request *next)
{
	/*
	 * If next expires before rq, assign its expire time to rq
	 * and move into next position (next will be deleted) in fifo.
	 */
	if (!list_empty(&rq->queuelist) && !list_empty(&next->queuelist)) {
		if (time_before(rq_fifo_time(next), rq_fifo_time(rq))) {
			list_move(&rq->queuelist, &next->queuelist);
			rq_set_fifo_time(rq, rq_fifo_time(next));
		}
	}

	/* Delete next request */
	rq_fifo_clear(next);
}

static void
maple_add_request(struct request_queue *q, struct request *rq)
{
	struct maple_data *mdata = maple_get_data(q);
	const int sync = rq_is_sync(rq);
	const int dir = rq_data_dir(rq);
	const bool display_on = is_display_on();

	/*
	 * Add request to the proper fifo list and set its
	 * expire time.
	 */

   	/* inrease expiration when device is asleep */
   	unsigned int fifo_expire_suspended = mdata->fifo_expire[sync][dir] * sleep_latency_multiple;
   	if (display_on && mdata->fifo_expire[sync][dir]) {
   		rq_set_fifo_time(rq, jiffies + mdata->fifo_expire[sync][dir]);
   		list_add_tail(&rq->queuelist, &mdata->fifo_list[sync][dir]);
   	} else if (!display_on && fifo_expire_suspended) {
   		rq_set_fifo_time(rq, jiffies + fifo_expire_suspended);
   		list_add_tail(&rq->queuelist, &mdata->fifo_list[sync][dir]);
   	}
}

static struct request *
maple_expired_request(struct maple_data *mdata, int sync, int data_dir)
{
	struct list_head *list = &mdata->fifo_list[sync][data_dir];
	struct request *rq;

	if (list_empty(list))
		return NULL;

	/* Retrieve request */
	rq = rq_entry_fifo(list->next);

	/* Request has expired */
	if (time_after_eq(jiffies, rq_fifo_time(rq)))
		return rq;

	return NULL;
}

static struct request *
maple_choose_expired_request(struct maple_data *mdata)
{
	/* Reset (non-expired-)batch-counter */
	mdata->batched = 0;

	struct request *rq_sync_read = maple_expired_request(mdata, SYNC, READ);
	struct request *rq_sync_write = maple_expired_request(mdata, SYNC, WRITE);
	struct request *rq_async_read = maple_expired_request(mdata, ASYNC, READ);
	struct request *rq_async_write = maple_expired_request(mdata, ASYNC, WRITE);

	/*
	 * Check expired requests.
	 * Asynchronous requests have priority over synchronous.
	 * Read requests have priority over write.
	 */

   if (rq_async_read && rq_sync_read) {
     if (time_after(rq_fifo_time(rq_sync_read), rq_fifo_time(rq_async_read)))
             return rq_async_read;
   } else if (rq_async_read) {
           return rq_async_read;
   } else if (rq_sync_read) {
           return rq_sync_read;
   }

   if (rq_async_write && rq_sync_write) {
     if (time_after(rq_fifo_time(rq_sync_write), rq_fifo_time(rq_async_write)))
             return rq_async_write;
   } else if (rq_async_write) {
           return rq_async_write;
   } else if (rq_sync_write) {
           return rq_sync_write;
   }

	return NULL;
}

static struct request *
maple_choose_request(struct maple_data *mdata, int data_dir)
{
	/* Increase (non-expired-)batch-counter */
	mdata->batched++;

	struct list_head *sync = mdata->fifo_list[SYNC];
	struct list_head *async = mdata->fifo_list[ASYNC];

	/*
	 * Retrieve request from available fifo list.
	 * Asynchronous requests have priority over synchronous.
	 * Read requests have priority over write.
	 */
	if (!list_empty(&async[data_dir]))
		return rq_entry_fifo(async[data_dir].next);
	if (!list_empty(&sync[data_dir]))
		return rq_entry_fifo(sync[data_dir].next);

	if (!list_empty(&async[!data_dir]))
			return rq_entry_fifo(async[!data_dir].next);
	if (!list_empty(&sync[!data_dir]))
		return rq_entry_fifo(sync[!data_dir].next);

	return NULL;
}

static inline void
maple_dispatch_request(struct maple_data *mdata, struct request *rq)
{
	/*
	 * Remove the request from the fifo list
	 * and dispatch it.
	 */
	rq_fifo_clear(rq);
	elv_dispatch_add_tail(rq->q, rq);

	if (rq_data_dir(rq)) {
		mdata->starved = 0;
	} else {
		if (!list_empty(&mdata->fifo_list[SYNC][WRITE]) ||
				!list_empty(&mdata->fifo_list[ASYNC][WRITE]))
			mdata->starved++;
	}
}

static int
maple_dispatch_requests(struct request_queue *q, int force)
{
	struct maple_data *mdata = maple_get_data(q);
	struct request *rq = NULL;
	int data_dir = READ;
	const bool display_on = is_display_on();

	/*
	 * Retrieve any expired request after a batch of
	 * sequential requests.
	 */
	if (mdata->batched >= mdata->fifo_batch)
		rq = maple_choose_expired_request(mdata);

	/* Retrieve request */
	if (!rq) {
		/* Treat writes fairly while suspended, otherwise allow them to be starved */
		if (display_on && mdata->starved >= mdata->writes_starved)
			data_dir = WRITE;
		else if (!display_on && mdata->starved >= 1)
			data_dir = WRITE;

		rq = maple_choose_request(mdata, data_dir);
		if (!rq)
			return 0;
	}

	/* Dispatch request */
	maple_dispatch_request(mdata, rq);

	return 1;
}

static struct request *
maple_former_request(struct request_queue *q, struct request *rq)
{
	struct maple_data *mdata = maple_get_data(q);
	const int sync = rq_is_sync(rq);
	const int data_dir = rq_data_dir(rq);

	if (rq->queuelist.prev == &mdata->fifo_list[sync][data_dir])
		return NULL;

	/* Return former request */
	return list_entry(rq->queuelist.prev, struct request, queuelist);
}

static struct request *
maple_latter_request(struct request_queue *q, struct request *rq)
{
	struct maple_data *mdata = maple_get_data(q);
	const int sync = rq_is_sync(rq);
	const int data_dir = rq_data_dir(rq);

	if (rq->queuelist.next == &mdata->fifo_list[sync][data_dir])
		return NULL;

	/* Return latter request */
	return list_entry(rq->queuelist.next, struct request, queuelist);
}

static int maple_init_queue(struct request_queue *q, struct elevator_type *e)
{
	struct maple_data *mdata;
	struct elevator_queue *eq;

	eq = elevator_alloc(q, e);
	if (!eq)
		return -ENOMEM;

	/* Allocate structure */
	mdata = kmalloc_node(sizeof(*mdata), GFP_KERNEL, q->node);
	if (!mdata) {
		kobject_put(&eq->kobj);
		return -ENOMEM;
	}
	eq->elevator_data = mdata;

	/* Initialize fifo lists */
	INIT_LIST_HEAD(&mdata->fifo_list[SYNC][READ]);
	INIT_LIST_HEAD(&mdata->fifo_list[SYNC][WRITE]);
	INIT_LIST_HEAD(&mdata->fifo_list[ASYNC][READ]);
	INIT_LIST_HEAD(&mdata->fifo_list[ASYNC][WRITE]);

	/* Initialize data */
	mdata->batched = 0;
	mdata->fifo_expire[SYNC][READ] = sync_read_expire;
	mdata->fifo_expire[SYNC][WRITE] = sync_write_expire;
	mdata->fifo_expire[ASYNC][READ] = async_read_expire;
	mdata->fifo_expire[ASYNC][WRITE] = async_write_expire;
	mdata->fifo_batch = fifo_batch;
	mdata->writes_starved = writes_starved;
	mdata->sleep_latency_multiple = sleep_latency_multiple;

	spin_lock_irq(q->queue_lock);
	q->elevator = eq;
	spin_unlock_irq(q->queue_lock);
	return 0;
}

static void
maple_exit_queue(struct elevator_queue *e)
{
	struct maple_data *mdata = e->elevator_data;

	/* Free structure */
	kfree(mdata);
}

/*
 * sysfs code
 */

static ssize_t
maple_var_show(int var, char *page)
{
	return sprintf(page, "%d\n", var);
}

static ssize_t
maple_var_store(int *var, const char *page, size_t count)
{
	char *p = (char *) page;

	*var = simple_strtol(p, &p, 10);
	return count;
}

#define SHOW_FUNCTION(__FUNC, __VAR, __CONV)				\
static ssize_t __FUNC(struct elevator_queue *e, char *page)		\
{									\
	struct maple_data *mdata = e->elevator_data;			\
	int __data = __VAR;						\
	if (__CONV)							\
		__data = jiffies_to_msecs(__data);			\
	return maple_var_show(__data, (page));			\
}
SHOW_FUNCTION(maple_sync_read_expire_show, mdata->fifo_expire[SYNC][READ], 1);
SHOW_FUNCTION(maple_sync_write_expire_show, mdata->fifo_expire[SYNC][WRITE], 1);
SHOW_FUNCTION(maple_async_read_expire_show, mdata->fifo_expire[ASYNC][READ], 1);
SHOW_FUNCTION(maple_async_write_expire_show, mdata->fifo_expire[ASYNC][WRITE], 1);
SHOW_FUNCTION(maple_fifo_batch_show, mdata->fifo_batch, 0);
SHOW_FUNCTION(maple_writes_starved_show, mdata->writes_starved, 0);
SHOW_FUNCTION(maple_sleep_latency_multiple_show, mdata->sleep_latency_multiple, 0);
#undef SHOW_FUNCTION

#define STORE_FUNCTION(__FUNC, __PTR, MIN, MAX, __CONV)			\
static ssize_t __FUNC(struct elevator_queue *e, const char *page, size_t count)	\
{									\
	struct maple_data *mdata = e->elevator_data;			\
	int __data;							\
	int ret = maple_var_store(&__data, (page), count);		\
	if (__data < (MIN))						\
		__data = (MIN);						\
	else if (__data > (MAX))					\
		__data = (MAX);						\
	if (__CONV)							\
		*(__PTR) = msecs_to_jiffies(__data);			\
	else								\
		*(__PTR) = __data;					\
	return ret;							\
}
STORE_FUNCTION(maple_sync_read_expire_store, &mdata->fifo_expire[SYNC][READ], 0, INT_MAX, 1);
STORE_FUNCTION(maple_sync_write_expire_store, &mdata->fifo_expire[SYNC][WRITE], 0, INT_MAX, 1);
STORE_FUNCTION(maple_async_read_expire_store, &mdata->fifo_expire[ASYNC][READ], 0, INT_MAX, 1);
STORE_FUNCTION(maple_async_write_expire_store, &mdata->fifo_expire[ASYNC][WRITE], 0, INT_MAX, 1);
STORE_FUNCTION(maple_fifo_batch_store, &mdata->fifo_batch, 1, INT_MAX, 0);
STORE_FUNCTION(maple_writes_starved_store, &mdata->writes_starved, 1, INT_MAX, 0);
STORE_FUNCTION(maple_sleep_latency_multiple_store, &mdata->sleep_latency_multiple, 1, INT_MAX, 0);
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
		.elevator_former_req_fn		= maple_former_request,
		.elevator_latter_req_fn		= maple_latter_request,
		.elevator_init_fn		= maple_init_queue,
		.elevator_exit_fn		= maple_exit_queue,
	},

	.elevator_attrs = maple_attrs,
	.elevator_name = "maple",
	.elevator_owner = THIS_MODULE,
};

static int __init maple_init(void)
{
	/* Register elevator */
	elv_register(&iosched_maple);

	return 0;
}

static void __exit maple_exit(void)
{
	/* Unregister elevator */
	elv_unregister(&iosched_maple);
}

module_init(maple_init);
module_exit(maple_exit);

MODULE_AUTHOR("Joe Maples");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Maple I/O Scheduler");
MODULE_VERSION("1.0");
