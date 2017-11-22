#include <linux/init.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/rcupdate.h>
#include <linux/sysrq.h>


static void sysrq_handle_init_state(int key)
{
	struct task_struct *p = NULL;

	rcu_read_lock();
	for_each_process(p) {
		if (p->pid == 1) {
			sched_show_task(p);
			break;
		}
	}
	rcu_read_unlock();
}

static struct sysrq_key_op sysrq_init_state_op = {
	.handler        = sysrq_handle_init_state,
	.help_msg       = "show-init-state(x)",
	.action_msg     = "Show init process state",
	.enable_mask	= SYSRQ_ENABLE_DUMP,
};

static int __init op_sysrq_init(void)
{
	return register_sysrq_key('x', &sysrq_init_state_op);
}

module_init(op_sysrq_init);

