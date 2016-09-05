/*
 * FIFO I/O scheduler (_really_ does no-op)
 */
#include <linux/blkdev.h>
#include <linux/elevator.h>
#include <linux/bio.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>

struct fifo_data {
	struct list_head queue;
};

static int fifo_dispatch(struct request_queue *q, int force)
{
	struct fifo_data *fifo_d = q->elevator->elevator_data;

	if (!list_empty(&fifo_d->queue)) {
		struct request *req = list_entry(fifo_d->queue.next, struct request, queuelist);
		list_del_init(&req->queuelist);
		elv_dispatch_add_tail(q, req);
		return 1;
	}
	return 0;
}

static void fifo_add_request(struct request_queue *q, struct request *req)
{
	struct fifo_data *fifo_d = q->elevator->elevator_data;
	list_add_tail(&req->queuelist, &fifo_d->queue);
}

static int fifo_init_queue(struct request_queue *q, struct elevator_type *e)
{
	struct fifo_data *fifo_d;
	struct elevator_queue *eq;

	eq = elevator_alloc(q, e);
	if (!eq)
		return -ENOMEM;

	fifo_d = kmalloc_node(sizeof(*fifo_d), GFP_KERNEL, q->node);
	if (!fifo_d) {
		kobject_put(&eq->kobj);
		return -ENOMEM;
	}
	eq->elevator_data = fifo_d;

	INIT_LIST_HEAD(&fifo_d->queue);

	spin_lock_irq(q->queue_lock);
	q->elevator = eq;
	spin_unlock_irq(q->queue_lock);
	return 0;
}

static void fifo_exit_queue(struct elevator_queue *e)
{
        struct fifo_data *fifo_d = e->elevator_data;

        BUG_ON(!list_empty(&fifo_d->queue));
        kfree(fifo_d);
}

static int fifo_deny_merge(struct request_queue *req_q, struct request *req,
			struct bio *bio)
{
	return ELEVATOR_NO_MERGE;
}

static struct elevator_type elevator_fifo = {
	.ops = {
		.elevator_dispatch_fn		= fifo_dispatch,
		.elevator_add_req_fn		= fifo_add_request,
		.elevator_allow_merge_fn 	= fifo_deny_merge,
		.elevator_init_fn		= fifo_init_queue,
		.elevator_exit_fn		= fifo_exit_queue,
	},
	.elevator_name = "fifo",
	.elevator_owner = THIS_MODULE,
};

static int __init fifo_init(void)
{
	return elv_register(&elevator_fifo);
}

static void __exit fifo_exit(void)
{
	elv_unregister(&elevator_fifo);
}

module_init(fifo_init);
module_exit(fifo_exit);

MODULE_AUTHOR("Aaron Carroll");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("No-op IO scheduler that actually does nothing");
