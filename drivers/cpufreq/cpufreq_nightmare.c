/*
 * Nightmare - Load Sensitive CPU Frequency Governor
 *
 * Copyright (c) 2010-2016, Alucard24 <dmbaoh2@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/cpufreq.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/sched/rt.h>
#include <linux/time.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <asm/cputime.h>
#ifdef CONFIG_STATE_NOTIFIER
#include <linux/state_notifier.h>
#endif

struct cpufreq_nightmare_policyinfo {
	struct timer_list policy_timer;
	struct timer_list policy_slack_timer;
	spinlock_t load_lock; /* protects load tracking stat */
	u64 last_evaluated_jiffy;
	struct cpufreq_policy *policy;
	struct cpufreq_frequency_table *freq_table;
	spinlock_t target_freq_lock; /*protects target freq */
	unsigned int target_freq;
	unsigned int min_freq;
	struct rw_semaphore enable_sem;
	bool reject_notification;
	int governor_enabled;
	struct cpufreq_nightmare_tunables *cached_tunables;
	unsigned long *cpu_busy_times;
};

/* Protected by per-policy load_lock */
struct cpufreq_nightmare_cpuinfo {
	u64 time_in_idle;
	u64 time_in_idle_timestamp;
	unsigned int load;
};

static DEFINE_PER_CPU(struct cpufreq_nightmare_policyinfo *, polinfo);
static DEFINE_PER_CPU(struct cpufreq_nightmare_cpuinfo, cpuinfo);

/* realtime thread handles frequency scaling */
static struct task_struct *speedchange_task;
static cpumask_t speedchange_cpumask;
static spinlock_t speedchange_cpumask_lock;
static struct mutex gov_lock;

#define DEFAULT_TIMER_RATE (20 * USEC_PER_MSEC)
#define DEFAULT_TIMER_RATE_SUSP ((unsigned long)(50 * USEC_PER_MSEC))

#define FREQ_RESPONSIVENESS			1113600
#define FREQ_RESPONSIVENESS_MAX		2150400

#define FREQ_STEP_AT_MIN_FREQ		40
#define FREQ_STEP					50
#define FREQ_UP_BRAKE_AT_MIN_FREQ	40
#define FREQ_UP_BRAKE				30
#define FREQ_STEP_DEC				10
#define FREQ_STEP_DEC_AT_MAX_FREQ	10

struct cpufreq_nightmare_tunables {
	int usage_count;
	/*
	 * The sample rate of the timer used to increase frequency
	 */
	unsigned long timer_rate;
#ifdef CONFIG_STATE_NOTIFIER
	unsigned long timer_rate_prev;
#endif
	/*
	 * Max additional time to wait in idle, beyond timer_rate, at speeds
	 * above minimum before wakeup to reduce speed, or -1 if unnecessary.
	 */
#define DEFAULT_TIMER_SLACK (4 * DEFAULT_TIMER_RATE)
	int timer_slack_val;
	bool io_is_busy;
	/*
	 * Whether to align timer windows across all CPUs.
	 */
	bool align_windows;
	/*
	 * CPUs frequency scaling
	 */
	int freq_for_responsiveness;
	int freq_for_responsiveness_max;
	int freq_up_brake_at_min_freq;
	int freq_up_brake;
	int freq_step_at_min_freq;
	int freq_step;
	int freq_step_dec;
	int freq_step_dec_at_max_freq;
};

/* For cases where we have single governor instance for system */
static struct cpufreq_nightmare_tunables *common_tunables;
static struct cpufreq_nightmare_tunables *cached_common_tunables;

static struct attribute_group *get_sysfs_attr(void);

/* Round to starting jiffy of next evaluation window */
static u64 round_to_nw_start(u64 jif,
			     struct cpufreq_nightmare_tunables *tunables)
{
	unsigned long step = usecs_to_jiffies(tunables->timer_rate);
	u64 ret;

	if (tunables->align_windows) {
		do_div(jif, step);
		ret = (jif + 1) * step;
	} else {
		ret = jiffies + usecs_to_jiffies(tunables->timer_rate);
	}

	return ret;
}

static void cpufreq_nightmare_timer_resched(unsigned long cpu,
					      bool slack_only)
{
	struct cpufreq_nightmare_policyinfo *ppol = per_cpu(polinfo, cpu);
	struct cpufreq_nightmare_cpuinfo *pcpu;
	struct cpufreq_nightmare_tunables *tunables =
		ppol->policy->governor_data;
	u64 expires;
	unsigned long flags;
	int i;

	spin_lock_irqsave(&ppol->load_lock, flags);
	expires = round_to_nw_start(ppol->last_evaluated_jiffy, tunables);
	if (!slack_only) {
		for_each_cpu(i, ppol->policy->cpus) {
			pcpu = &per_cpu(cpuinfo, i);
			pcpu->time_in_idle = get_cpu_idle_time(i,
						&pcpu->time_in_idle_timestamp,
						tunables->io_is_busy);
		}
		del_timer(&ppol->policy_timer);
		ppol->policy_timer.expires = expires;
		add_timer(&ppol->policy_timer);
	}

	if (tunables->timer_slack_val >= 0 &&
	    ppol->target_freq > ppol->policy->min) {
		expires += usecs_to_jiffies(tunables->timer_slack_val);
		del_timer(&ppol->policy_slack_timer);
		ppol->policy_slack_timer.expires = expires;
		add_timer(&ppol->policy_slack_timer);
	}

	spin_unlock_irqrestore(&ppol->load_lock, flags);
}

/* The caller shall take enable_sem write semaphore to avoid any timer race.
 * The policy_timer and policy_slack_timer must be deactivated when calling
 * this function.
 */
static void cpufreq_nightmare_timer_start(
	struct cpufreq_nightmare_tunables *tunables, int cpu)
{
	struct cpufreq_nightmare_policyinfo *ppol = per_cpu(polinfo, cpu);
	struct cpufreq_nightmare_cpuinfo *pcpu;
	u64 expires = round_to_nw_start(ppol->last_evaluated_jiffy, tunables);
	unsigned long flags;
	int i;

	spin_lock_irqsave(&ppol->load_lock, flags);
	ppol->policy_timer.expires = expires;
	add_timer(&ppol->policy_timer);
	if (tunables->timer_slack_val >= 0 &&
	    ppol->target_freq > ppol->policy->min) {
		expires += usecs_to_jiffies(tunables->timer_slack_val);
		ppol->policy_slack_timer.expires = expires;
		add_timer(&ppol->policy_slack_timer);
	}

	for_each_cpu(i, ppol->policy->cpus) {
		pcpu = &per_cpu(cpuinfo, i);
		pcpu->time_in_idle =
			get_cpu_idle_time(i, &pcpu->time_in_idle_timestamp,
					  tunables->io_is_busy);
	}
	spin_unlock_irqrestore(&ppol->load_lock, flags);
}

static unsigned int choose_freq(struct cpufreq_nightmare_policyinfo *pcpu,
					unsigned int tmp_freq)
{
	struct cpufreq_policy *policy = pcpu->policy;
	struct cpufreq_frequency_table *table = pcpu->freq_table;
	struct cpufreq_frequency_table *pos;
	unsigned int i = 0, l_freq = 0, h_freq = 0, target_freq = 0, freq;

	if (tmp_freq < policy->min)
		tmp_freq = policy->min;
	if (tmp_freq > policy->max)
		tmp_freq = policy->max;

	cpufreq_for_each_valid_entry(pos, table) {
		freq = pos->frequency;
		i = pos - table;
		if (freq < tmp_freq) {
			h_freq = freq;
		}
		if (freq == tmp_freq) {
			target_freq = freq;
			break;
		}
		if (freq > tmp_freq) {
			l_freq = freq;
			break;
		}
	}
	if (!target_freq) {
		if (policy->cur >= h_freq
			 && policy->cur <= l_freq)
			target_freq = policy->cur;
		else
			target_freq = l_freq;
	}

	return target_freq;
}

static bool update_load(int cpu)
{
	struct cpufreq_nightmare_policyinfo *ppol = per_cpu(polinfo, cpu);
	struct cpufreq_nightmare_cpuinfo *pcpu = &per_cpu(cpuinfo, cpu);
	struct cpufreq_nightmare_tunables *tunables =
		ppol->policy->governor_data;
	u64 now;
	u64 now_idle;
	unsigned int delta_idle;
	unsigned int delta_time;
	bool ignore = false;

	now_idle = get_cpu_idle_time(cpu, &now, tunables->io_is_busy);
	delta_idle = (unsigned int)(now_idle - pcpu->time_in_idle);
	delta_time = (unsigned int)(now - pcpu->time_in_idle_timestamp);

	WARN_ON_ONCE(!delta_time);

	if (delta_time < delta_idle) {
		pcpu->load = 0;
		ignore = true;
	} else {
		pcpu->load = 100 * (delta_time - delta_idle);
		do_div(pcpu->load, delta_time);
	}
	pcpu->time_in_idle = now_idle;
	pcpu->time_in_idle_timestamp = now;

	return ignore;
}

static void cpufreq_nightmare_timer(unsigned long data)
{
	struct cpufreq_nightmare_policyinfo *ppol = per_cpu(polinfo, data);
	struct cpufreq_nightmare_tunables *tunables =
		ppol->policy->governor_data;
	struct cpufreq_nightmare_cpuinfo *pcpu;
	struct cpufreq_govinfo govinfo;
	unsigned int freq_for_responsiveness = tunables->freq_for_responsiveness;
	unsigned int freq_for_responsiveness_max = tunables->freq_for_responsiveness_max;
	int target_cpu_load;
	int freq_step = tunables->freq_step;
	int freq_up_brake = tunables->freq_up_brake;
	int freq_step_dec = tunables->freq_step_dec;
	int tmp_step = 0;
	unsigned int new_freq = 0;
	unsigned int max_load = 0;
	unsigned long flags;
	unsigned long max_cpu;
	int i, fcpu;

	if (!down_read_trylock(&ppol->enable_sem))
		return;
	if (!ppol->governor_enabled)
		goto exit;

	fcpu = cpumask_first(ppol->policy->related_cpus);
	spin_lock_irqsave(&ppol->load_lock, flags);
	ppol->last_evaluated_jiffy = get_jiffies_64();

#ifdef CONFIG_STATE_NOTIFIER
	if (!state_suspended &&
		tunables->timer_rate != tunables->timer_rate_prev)
		tunables->timer_rate = tunables->timer_rate_prev;
	else if (state_suspended &&
		tunables->timer_rate != DEFAULT_TIMER_RATE_SUSP) {
		tunables->timer_rate_prev = tunables->timer_rate;
		tunables->timer_rate
			= max(tunables->timer_rate,
				DEFAULT_TIMER_RATE_SUSP);
	}
#endif
	/* CPUs Online Scale Frequency*/
	target_cpu_load = (ppol->policy->cur * 100) / ppol->policy->max;
	if (ppol->policy->cur < freq_for_responsiveness) {
		freq_step = tunables->freq_step_at_min_freq;
		freq_up_brake = tunables->freq_up_brake_at_min_freq;
	} else if (ppol->policy->cur > freq_for_responsiveness_max) {
		freq_step_dec = tunables->freq_step_dec_at_max_freq;
	}

	max_cpu = cpumask_first(ppol->policy->cpus);
	for_each_cpu(i, ppol->policy->cpus) {
		pcpu = &per_cpu(cpuinfo, i);
		if (update_load(i))
			continue;

		if (pcpu->load > max_load) {
			max_load = pcpu->load;
			max_cpu = i;
		}
	}
	spin_unlock_irqrestore(&ppol->load_lock, flags);

	/*
	 * Send govinfo notification.
	 * Govinfo notification could potentially wake up another thread
	 * managed by its clients. Thread wakeups might trigger a load
	 * change callback that executes this function again. Therefore
	 * no spinlock could be held when sending the notification.
	 */
	for_each_cpu(i, ppol->policy->cpus) {
		pcpu = &per_cpu(cpuinfo, i);
		govinfo.cpu = i;
		govinfo.load = pcpu->load;
		govinfo.sampling_rate_us = tunables->timer_rate;
		atomic_notifier_call_chain(&cpufreq_govinfo_notifier_list,
					   CPUFREQ_LOAD_CHANGE, &govinfo);
	}

	/* Check for frequency increase or for frequency decrease */
	spin_lock_irqsave(&ppol->target_freq_lock, flags);
	if (max_load >= target_cpu_load
		 && ppol->policy->cur < ppol->policy->max) {
		tmp_step = (max_load + freq_step - freq_up_brake) * 1536;
		if (tmp_step < 0)
			tmp_step = 0;

		new_freq = choose_freq(ppol,
			(ppol->policy->cur + tmp_step));
	} else if (max_load < target_cpu_load
				 && ppol->policy->cur > ppol->policy->min) {
		tmp_step = (100 - max_load + freq_step_dec) * 1536;
		if (tmp_step < 0)
			tmp_step = 0;

		new_freq = choose_freq(ppol,
			(ppol->policy->cur < tmp_step ? 0 : ppol->policy->cur - tmp_step));
	}
	if (!new_freq) {
		spin_unlock_irqrestore(&ppol->target_freq_lock, flags);
		goto rearm;
	}

	ppol->target_freq = new_freq;
	spin_unlock_irqrestore(&ppol->target_freq_lock, flags);
	spin_lock_irqsave(&speedchange_cpumask_lock, flags);
	cpumask_set_cpu(max_cpu, &speedchange_cpumask);
	spin_unlock_irqrestore(&speedchange_cpumask_lock, flags);
	wake_up_process_no_notif(speedchange_task);

rearm:
	if (!timer_pending(&ppol->policy_timer))
		cpufreq_nightmare_timer_resched(data, false);

exit:
	up_read(&ppol->enable_sem);
	return;
}

static int cpufreq_nightmare_speedchange_task(void *data)
{
	unsigned int cpu;
	cpumask_t tmp_mask;
	unsigned long flags;
	struct cpufreq_nightmare_policyinfo *ppol;

	while (1) {
		set_current_state(TASK_INTERRUPTIBLE);
		spin_lock_irqsave(&speedchange_cpumask_lock, flags);

		if (cpumask_empty(&speedchange_cpumask)) {
			spin_unlock_irqrestore(&speedchange_cpumask_lock,
					       flags);
			schedule();

			if (kthread_should_stop())
				break;

			spin_lock_irqsave(&speedchange_cpumask_lock, flags);
		}

		set_current_state(TASK_RUNNING);
		tmp_mask = speedchange_cpumask;
		cpumask_clear(&speedchange_cpumask);
		spin_unlock_irqrestore(&speedchange_cpumask_lock, flags);

		for_each_cpu(cpu, &tmp_mask) {
			ppol = per_cpu(polinfo, cpu);
			if (!down_read_trylock(&ppol->enable_sem))
				continue;
			if (!ppol->governor_enabled) {
				up_read(&ppol->enable_sem);
				continue;
			}

 			if (ppol->target_freq != ppol->policy->cur) {
				__cpufreq_driver_target(ppol->policy,
							ppol->target_freq,
							CPUFREQ_RELATION_L);
			}
			up_read(&ppol->enable_sem);
		}
	}

	return 0;
}

static int cpufreq_nightmare_notifier(
	struct notifier_block *nb, unsigned long val, void *data)
{
	struct cpufreq_freqs *freq = data;
	struct cpufreq_nightmare_policyinfo *ppol;
	int cpu;
	unsigned long flags;

	if (val == CPUFREQ_POSTCHANGE) {
		ppol = per_cpu(polinfo, freq->cpu);
		if (!ppol)
			return 0;
		if (!down_read_trylock(&ppol->enable_sem))
			return 0;
		if (!ppol->governor_enabled) {
			up_read(&ppol->enable_sem);
			return 0;
		}

		if (cpumask_first(ppol->policy->cpus) != freq->cpu) {
			up_read(&ppol->enable_sem);
			return 0;
		}
		spin_lock_irqsave(&ppol->load_lock, flags);
		for_each_cpu(cpu, ppol->policy->cpus)
			update_load(cpu);
		spin_unlock_irqrestore(&ppol->load_lock, flags);

		up_read(&ppol->enable_sem);
	}
	return 0;
}

static struct notifier_block cpufreq_notifier_block = {
	.notifier_call = cpufreq_nightmare_notifier,
};

#define show_store_one(file_name)					\
static ssize_t show_##file_name(					\
	struct cpufreq_nightmare_tunables *tunables, char *buf)	\
{									\
	return snprintf(buf, PAGE_SIZE, "%u\n", tunables->file_name);	\
}									\
static ssize_t store_##file_name(					\
		struct cpufreq_nightmare_tunables *tunables,		\
		const char *buf, size_t count)				\
{									\
	int ret;							\
	long unsigned int val;						\
									\
	ret = kstrtoul(buf, 0, &val);				\
	if (ret < 0)							\
		return ret;						\
	tunables->file_name = val;					\
	return count;							\
}
show_store_one(align_windows);

static ssize_t show_timer_rate(struct cpufreq_nightmare_tunables *tunables,
		char *buf)
{
	return sprintf(buf, "%lu\n", tunables->timer_rate);
}

static ssize_t store_timer_rate(struct cpufreq_nightmare_tunables *tunables,
		const char *buf, size_t count)
{
	int ret;
	unsigned long val, val_round;

	ret = kstrtoul(buf, 0, &val);
	if (ret < 0)
		return ret;

	val_round = jiffies_to_usecs(usecs_to_jiffies(val));
	if (val != val_round)
		pr_warn("timer_rate not aligned to jiffy. Rounded up to %lu\n",
			val_round);
	tunables->timer_rate = val_round;
#ifdef CONFIG_STATE_NOTIFIER
	tunables->timer_rate_prev = val_round;
#endif

	return count;
}

static ssize_t show_timer_slack(struct cpufreq_nightmare_tunables *tunables,
		char *buf)
{
	return sprintf(buf, "%d\n", tunables->timer_slack_val);
}

static ssize_t store_timer_slack(struct cpufreq_nightmare_tunables *tunables,
		const char *buf, size_t count)
{
	int ret;
	unsigned long val;

	ret = kstrtol(buf, 10, &val);
	if (ret < 0)
		return ret;

	tunables->timer_slack_val = val;
	return count;
}

static ssize_t show_io_is_busy(struct cpufreq_nightmare_tunables *tunables,
		char *buf)
{
	return sprintf(buf, "%u\n", tunables->io_is_busy);
}

static ssize_t store_io_is_busy(struct cpufreq_nightmare_tunables *tunables,
		const char *buf, size_t count)
{
	int ret;
	unsigned long val;

	ret = kstrtoul(buf, 0, &val);
	if (ret < 0)
		return ret;
	tunables->io_is_busy = val;

	return count;
}

/* freq_for_responsiveness */
static ssize_t show_freq_for_responsiveness(struct cpufreq_nightmare_tunables *tunables,
		char *buf)
{
	return sprintf(buf, "%d\n", tunables->freq_for_responsiveness);
}

static ssize_t store_freq_for_responsiveness(struct cpufreq_nightmare_tunables *tunables,
		const char *buf, size_t count)
{
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	if (input == tunables->freq_for_responsiveness)
		return count;

	tunables->freq_for_responsiveness = input;

	return count;
}

/* freq_for_responsiveness_max */
static ssize_t show_freq_for_responsiveness_max(struct cpufreq_nightmare_tunables *tunables,
		char *buf)
{
	return sprintf(buf, "%d\n", tunables->freq_for_responsiveness_max);
}

static ssize_t store_freq_for_responsiveness_max(struct cpufreq_nightmare_tunables *tunables,
		const char *buf, size_t count)
{
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	if (input == tunables->freq_for_responsiveness_max)
		return count;

	tunables->freq_for_responsiveness_max = input;

	return count;
}

/* freq_step_at_min_freq */
static ssize_t show_freq_step_at_min_freq(struct cpufreq_nightmare_tunables *tunables,
		char *buf)
{
	return sprintf(buf, "%d\n", tunables->freq_step_at_min_freq);
}

static ssize_t store_freq_step_at_min_freq(struct cpufreq_nightmare_tunables *tunables,
		const char *buf, size_t count)
{
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	input = max(min(input,100),0);

	if (input == tunables->freq_step_at_min_freq)
		return count;

	tunables->freq_step_at_min_freq = input;

	return count;
}

/* freq_step */
static ssize_t show_freq_step(struct cpufreq_nightmare_tunables *tunables,
		char *buf)
{
	return sprintf(buf, "%d\n", tunables->freq_step);
}

static ssize_t store_freq_step(struct cpufreq_nightmare_tunables *tunables,
		const char *buf, size_t count)
{
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	input = max(min(input,100),0);

	if (input == tunables->freq_step)
		return count;

	tunables->freq_step = input;

	return count;
}

/* freq_up_brake_at_min_freq */
static ssize_t show_freq_up_brake_at_min_freq(struct cpufreq_nightmare_tunables *tunables,
		char *buf)
{
	return sprintf(buf, "%d\n", tunables->freq_up_brake_at_min_freq);
}

static ssize_t store_freq_up_brake_at_min_freq(struct cpufreq_nightmare_tunables *tunables,
		const char *buf, size_t count)
{
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	input = max(min(input,100),0);

	if (input == tunables->freq_up_brake_at_min_freq)
		return count;

	tunables->freq_up_brake_at_min_freq = input;

	return count;
}

/* freq_up_brake */
static ssize_t show_freq_up_brake(struct cpufreq_nightmare_tunables *tunables,
		char *buf)
{
	return sprintf(buf, "%d\n", tunables->freq_up_brake);
}

static ssize_t store_freq_up_brake(struct cpufreq_nightmare_tunables *tunables,
		const char *buf, size_t count)
{
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	input = max(min(input,100),0);

	if (input == tunables->freq_up_brake)
		return count;

	tunables->freq_up_brake = input;

	return count;
}

/* freq_step_dec */
static ssize_t show_freq_step_dec(struct cpufreq_nightmare_tunables *tunables,
		char *buf)
{
	return sprintf(buf, "%d\n", tunables->freq_step_dec);
}

static ssize_t store_freq_step_dec(struct cpufreq_nightmare_tunables *tunables,
		const char *buf, size_t count)
{
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	input = max(min(input,100),0);

	if (input == tunables->freq_step_dec)
		return count;

	tunables->freq_step_dec = input;

	return count;
}

/* freq_step_dec_at_max_freq */
static ssize_t show_freq_step_dec_at_max_freq(struct cpufreq_nightmare_tunables *tunables,
		char *buf)
{
	return sprintf(buf, "%d\n", tunables->freq_step_dec_at_max_freq);
}

static ssize_t store_freq_step_dec_at_max_freq(struct cpufreq_nightmare_tunables *tunables,
		const char *buf, size_t count)
{
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	input = max(min(input,100),0);

	if (input == tunables->freq_step_dec_at_max_freq)
		return count;

	tunables->freq_step_dec_at_max_freq = input;

	return count;
}

/*
 * Create show/store routines
 * - sys: One governor instance for complete SYSTEM
 * - pol: One governor instance per struct cpufreq_policy
 */
#define show_gov_pol_sys(file_name)					\
static ssize_t show_##file_name##_gov_sys				\
(struct kobject *kobj, struct attribute *attr, char *buf)		\
{									\
	return show_##file_name(common_tunables, buf);			\
}									\
									\
static ssize_t show_##file_name##_gov_pol				\
(struct cpufreq_policy *policy, char *buf)				\
{									\
	return show_##file_name(policy->governor_data, buf);		\
}

#define store_gov_pol_sys(file_name)					\
static ssize_t store_##file_name##_gov_sys				\
(struct kobject *kobj, struct attribute *attr, const char *buf,		\
	size_t count)							\
{									\
	return store_##file_name(common_tunables, buf, count);		\
}									\
									\
static ssize_t store_##file_name##_gov_pol				\
(struct cpufreq_policy *policy, const char *buf, size_t count)		\
{									\
	return store_##file_name(policy->governor_data, buf, count);	\
}

#define show_store_gov_pol_sys(file_name)				\
show_gov_pol_sys(file_name);						\
store_gov_pol_sys(file_name)

show_store_gov_pol_sys(timer_rate);
show_store_gov_pol_sys(timer_slack);
show_store_gov_pol_sys(io_is_busy);
show_store_gov_pol_sys(align_windows);
show_store_gov_pol_sys(freq_for_responsiveness);
show_store_gov_pol_sys(freq_for_responsiveness_max);
show_store_gov_pol_sys(freq_step_at_min_freq);
show_store_gov_pol_sys(freq_step);
show_store_gov_pol_sys(freq_up_brake_at_min_freq);
show_store_gov_pol_sys(freq_up_brake);
show_store_gov_pol_sys(freq_step_dec);
show_store_gov_pol_sys(freq_step_dec_at_max_freq);

#define gov_sys_attr_rw(_name)						\
static struct global_attr _name##_gov_sys =				\
__ATTR(_name, 0644, show_##_name##_gov_sys, store_##_name##_gov_sys)

#define gov_pol_attr_rw(_name)						\
static struct freq_attr _name##_gov_pol =				\
__ATTR(_name, 0644, show_##_name##_gov_pol, store_##_name##_gov_pol)

#define gov_sys_pol_attr_rw(_name)					\
	gov_sys_attr_rw(_name);						\
	gov_pol_attr_rw(_name)

gov_sys_pol_attr_rw(timer_rate);
gov_sys_pol_attr_rw(timer_slack);
gov_sys_pol_attr_rw(io_is_busy);
gov_sys_pol_attr_rw(align_windows);
gov_sys_pol_attr_rw(freq_for_responsiveness);
gov_sys_pol_attr_rw(freq_for_responsiveness_max);
gov_sys_pol_attr_rw(freq_step_at_min_freq);
gov_sys_pol_attr_rw(freq_step);
gov_sys_pol_attr_rw(freq_up_brake_at_min_freq);
gov_sys_pol_attr_rw(freq_up_brake);
gov_sys_pol_attr_rw(freq_step_dec);
gov_sys_pol_attr_rw(freq_step_dec_at_max_freq);

/* One Governor instance for entire system */
static struct attribute *nightmare_attributes_gov_sys[] = {
	&timer_rate_gov_sys.attr,
	&timer_slack_gov_sys.attr,
	&io_is_busy_gov_sys.attr,
	&align_windows_gov_sys.attr,
	&freq_for_responsiveness_gov_sys.attr,
	&freq_for_responsiveness_max_gov_sys.attr,
	&freq_step_at_min_freq_gov_sys.attr,
	&freq_step_gov_sys.attr,
	&freq_up_brake_at_min_freq_gov_sys.attr,
	&freq_up_brake_gov_sys.attr,
	&freq_step_dec_gov_sys.attr,
	&freq_step_dec_at_max_freq_gov_sys.attr,
	NULL,
};

static struct attribute_group nightmare_attr_group_gov_sys = {
	.attrs = nightmare_attributes_gov_sys,
	.name = "nightmare",
};

/* Per policy governor instance */
static struct attribute *nightmare_attributes_gov_pol[] = {
	&timer_rate_gov_pol.attr,
	&timer_slack_gov_pol.attr,
	&io_is_busy_gov_pol.attr,
	&align_windows_gov_pol.attr,
	&freq_for_responsiveness_gov_pol.attr,
	&freq_for_responsiveness_max_gov_pol.attr,
	&freq_step_at_min_freq_gov_pol.attr,
	&freq_step_gov_pol.attr,
	&freq_up_brake_at_min_freq_gov_pol.attr,
	&freq_up_brake_gov_pol.attr,
	&freq_step_dec_gov_pol.attr,
	&freq_step_dec_at_max_freq_gov_pol.attr,
	NULL,
};

static struct attribute_group nightmare_attr_group_gov_pol = {
	.attrs = nightmare_attributes_gov_pol,
	.name = "nightmare",
};

static struct attribute_group *get_sysfs_attr(void)
{
	if (have_governor_per_policy())
		return &nightmare_attr_group_gov_pol;
	else
		return &nightmare_attr_group_gov_sys;
}

static void cpufreq_nightmare_nop_timer(unsigned long data)
{
}

static struct cpufreq_nightmare_tunables *alloc_tunable(
					struct cpufreq_policy *policy)
{
	struct cpufreq_nightmare_tunables *tunables;

	tunables = kzalloc(sizeof(*tunables), GFP_KERNEL);
	if (!tunables)
		return ERR_PTR(-ENOMEM);

	tunables->timer_rate = DEFAULT_TIMER_RATE;
#ifdef CONFIG_STATE_NOTIFIER
	tunables->timer_rate_prev = DEFAULT_TIMER_RATE;
#endif
	tunables->timer_slack_val = DEFAULT_TIMER_SLACK;
	tunables->freq_for_responsiveness = FREQ_RESPONSIVENESS;
	tunables->freq_for_responsiveness_max = FREQ_RESPONSIVENESS_MAX;
	tunables->freq_step_at_min_freq = FREQ_STEP_AT_MIN_FREQ;
	tunables->freq_step = FREQ_STEP;
	tunables->freq_up_brake_at_min_freq = FREQ_UP_BRAKE_AT_MIN_FREQ;
	tunables->freq_up_brake = FREQ_UP_BRAKE;
	tunables->freq_step_dec = FREQ_STEP_DEC;
	tunables->freq_step_dec_at_max_freq = FREQ_STEP_DEC_AT_MAX_FREQ;

	return tunables;
}

static struct cpufreq_nightmare_policyinfo *get_policyinfo(
					struct cpufreq_policy *policy)
{
	struct cpufreq_nightmare_policyinfo *ppol =
				per_cpu(polinfo, policy->cpu);
	int i;
	unsigned long *busy;

	/* polinfo already allocated for policy, return */
	if (ppol)
		return ppol;

	ppol = kzalloc(sizeof(*ppol), GFP_KERNEL);
	if (!ppol)
		return ERR_PTR(-ENOMEM);

	busy = kcalloc(cpumask_weight(policy->related_cpus), sizeof(*busy),
		       GFP_KERNEL);
	if (!busy) {
		kfree(ppol);
		return ERR_PTR(-ENOMEM);
	}
	ppol->cpu_busy_times = busy;

	init_timer_deferrable(&ppol->policy_timer);
	ppol->policy_timer.function = cpufreq_nightmare_timer;
	init_timer(&ppol->policy_slack_timer);
	ppol->policy_slack_timer.function = cpufreq_nightmare_nop_timer;
	spin_lock_init(&ppol->load_lock);
	spin_lock_init(&ppol->target_freq_lock);
	init_rwsem(&ppol->enable_sem);

	for_each_cpu(i, policy->related_cpus)
		per_cpu(polinfo, i) = ppol;
	return ppol;
}

/* This function is not multithread-safe. */
static void free_policyinfo(int cpu)
{
	struct cpufreq_nightmare_policyinfo *ppol = per_cpu(polinfo, cpu);
	int j;

	if (!ppol)
		return;

	for_each_possible_cpu(j)
		if (per_cpu(polinfo, j) == ppol)
			per_cpu(polinfo, cpu) = NULL;
	kfree(ppol->cached_tunables);
	kfree(ppol->cpu_busy_times);
	kfree(ppol);
}

static struct cpufreq_nightmare_tunables *get_tunables(
				struct cpufreq_nightmare_policyinfo *ppol)
{
	if (have_governor_per_policy())
		return ppol->cached_tunables;
	else
		return cached_common_tunables;
}

static int cpufreq_governor_nightmare(struct cpufreq_policy *policy,
		unsigned int event)
{
	int rc;
	struct cpufreq_nightmare_policyinfo *ppol;
	struct cpufreq_frequency_table *freq_table;
	struct cpufreq_nightmare_tunables *tunables;
	unsigned long flags;

	if (have_governor_per_policy())
		tunables = policy->governor_data;
	else
		tunables = common_tunables;

	BUG_ON(!tunables && (event != CPUFREQ_GOV_POLICY_INIT));

	switch (event) {
	case CPUFREQ_GOV_POLICY_INIT:
		ppol = get_policyinfo(policy);
		if (IS_ERR(ppol))
			return PTR_ERR(ppol);

		if (have_governor_per_policy()) {
			WARN_ON(tunables);
		} else if (tunables) {
			tunables->usage_count++;
			policy->governor_data = tunables;
			return 0;
		}

		tunables = get_tunables(ppol);
		if (!tunables) {
			tunables = alloc_tunable(policy);
			if (IS_ERR(tunables))
				return PTR_ERR(tunables);
		}

		tunables->usage_count = 1;
		policy->governor_data = tunables;
		if (!have_governor_per_policy()) {
			common_tunables = tunables;
			WARN_ON(cpufreq_get_global_kobject());
		}

		rc = sysfs_create_group(get_governor_parent_kobj(policy),
				get_sysfs_attr());
		if (rc) {
			kfree(tunables);
			policy->governor_data = NULL;
			if (!have_governor_per_policy()) {
				common_tunables = NULL;
				cpufreq_put_global_kobject();
			}
			return rc;
		}

		if (!policy->governor->initialized)
			cpufreq_register_notifier(&cpufreq_notifier_block,
					CPUFREQ_TRANSITION_NOTIFIER);

		if (have_governor_per_policy())
			ppol->cached_tunables = tunables;
		else
			cached_common_tunables = tunables;

		break;

	case CPUFREQ_GOV_POLICY_EXIT:
		if (!--tunables->usage_count) {
			if (policy->governor->initialized == 1)
				cpufreq_unregister_notifier(&cpufreq_notifier_block,
						CPUFREQ_TRANSITION_NOTIFIER);

			sysfs_remove_group(get_governor_parent_kobj(policy),
					get_sysfs_attr());

			if (!have_governor_per_policy())
				cpufreq_put_global_kobject();
			common_tunables = NULL;
		}

		policy->governor_data = NULL;

		break;

	case CPUFREQ_GOV_START:
		mutex_lock(&gov_lock);

		freq_table = cpufreq_frequency_get_table(policy->cpu);

		ppol = per_cpu(polinfo, policy->cpu);
		ppol->policy = policy;
		ppol->target_freq = policy->cur;
		ppol->freq_table = freq_table;
		ppol->min_freq = policy->min;
		ppol->reject_notification = true;
		down_write(&ppol->enable_sem);
		del_timer_sync(&ppol->policy_timer);
		del_timer_sync(&ppol->policy_slack_timer);
		ppol->policy_timer.data = policy->cpu;
		ppol->last_evaluated_jiffy = get_jiffies_64();
		cpufreq_nightmare_timer_start(tunables, policy->cpu);
		ppol->governor_enabled = 1;
		up_write(&ppol->enable_sem);
		ppol->reject_notification = false;

		mutex_unlock(&gov_lock);
		break;

	case CPUFREQ_GOV_STOP:
		mutex_lock(&gov_lock);

		ppol = per_cpu(polinfo, policy->cpu);
		ppol->reject_notification = true;
		down_write(&ppol->enable_sem);
		ppol->governor_enabled = 0;
		ppol->target_freq = 0;
		del_timer_sync(&ppol->policy_timer);
		del_timer_sync(&ppol->policy_slack_timer);
		up_write(&ppol->enable_sem);
		ppol->reject_notification = false;

		mutex_unlock(&gov_lock);
		break;

	case CPUFREQ_GOV_LIMITS:
		ppol = per_cpu(polinfo, policy->cpu);

		__cpufreq_driver_target(policy,
				policy->cur, CPUFREQ_RELATION_L);

		down_read(&ppol->enable_sem);
		if (ppol->governor_enabled) {
			spin_lock_irqsave(&ppol->target_freq_lock, flags);
			if (policy->max < ppol->target_freq)
				ppol->target_freq = policy->max;
			else if (policy->min >= ppol->target_freq)
				ppol->target_freq = policy->min;
			spin_unlock_irqrestore(&ppol->target_freq_lock, flags);

			if (policy->min < ppol->min_freq)
				cpufreq_nightmare_timer_resched(policy->cpu,
								  true);
			ppol->min_freq = policy->min;
		}

		up_read(&ppol->enable_sem);

		break;
	}
	return 0;
}

#ifndef CONFIG_CPU_FREQ_DEFAULT_GOV_NIGHTMARE
static
#endif
struct cpufreq_governor cpufreq_gov_nightmare = {
	.name = "nightmare",
	.governor = cpufreq_governor_nightmare,
	.max_transition_latency = 10000000,
	.owner = THIS_MODULE,
};

static int __init cpufreq_nightmare_init(void)
{
	struct sched_param param = { .sched_priority = MAX_RT_PRIO-1 };

	spin_lock_init(&speedchange_cpumask_lock);
	mutex_init(&gov_lock);
	speedchange_task =
		kthread_create(cpufreq_nightmare_speedchange_task, NULL,
			       "cfnightmare");
	if (IS_ERR(speedchange_task))
		return PTR_ERR(speedchange_task);

	sched_setscheduler_nocheck(speedchange_task, SCHED_FIFO, &param);
	get_task_struct(speedchange_task);

	/* NB: wake up so the thread does not look hung to the freezer */
	wake_up_process_no_notif(speedchange_task);

	return cpufreq_register_governor(&cpufreq_gov_nightmare);
}

#ifdef CONFIG_CPU_FREQ_DEFAULT_GOV_NIGHTMARE
fs_initcall(cpufreq_nightmare_init);
#else
module_init(cpufreq_nightmare_init);
#endif

static void __exit cpufreq_nightmare_exit(void)
{
	int cpu;

	cpufreq_unregister_governor(&cpufreq_gov_nightmare);
	kthread_stop(speedchange_task);
	put_task_struct(speedchange_task);

	for_each_possible_cpu(cpu)
		free_policyinfo(cpu);
}

module_exit(cpufreq_nightmare_exit);

MODULE_AUTHOR("Alucard24 <dmbaoh2@gmail.com>");
MODULE_DESCRIPTION("'cpufreq_nightmare' - A dynamic cpufreq governor v5.0");
MODULE_LICENSE("GPLv2");
