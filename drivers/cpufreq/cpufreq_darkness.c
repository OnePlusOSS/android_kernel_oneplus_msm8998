/*
 *  drivers/cpufreq/cpufreq_darkness.c
 *
 *  Copyright (C)  2001 Russell King
 *            (C)  2003 Venkatesh Pallipadi <venkatesh.pallipadi@intel.com>.
 *                      Jun Nakajima <jun.nakajima@intel.com>
 *            (C)  2009 Alexander Clouter <alex@digriz.org.uk>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Created by Alucard_24@xda
 */

#include <linux/cpu.h>
#include <linux/percpu-defs.h>
#include <linux/slab.h>
#include <linux/tick.h>
#include "cpufreq_governor.h"

/* darkness governor macros */
#define DEF_SAMPLING_RATE			(20000)
#define MIN_SAMPLING_RATE			(10000)

static DEFINE_PER_CPU(struct dk_cpu_dbs_info_s, dk_cpu_dbs_info);
static DEFINE_PER_CPU(struct dk_dbs_tuners, dk_cached_tuners);

static struct dk_ops dk_ops;

#ifndef CONFIG_CPU_FREQ_DEFAULT_GOV_DARKNESS
static struct cpufreq_governor cpufreq_gov_darkness;
#endif

static void dk_get_cpu_frequency_table(int cpu)
{
	struct dk_cpu_dbs_info_s *dbs_info = &per_cpu(dk_cpu_dbs_info, cpu);

	dbs_info->freq_table = cpufreq_frequency_get_table(cpu);
}

static unsigned int adjust_cpufreq_frequency_target(struct cpufreq_policy *policy,
					struct cpufreq_frequency_table *table,
					unsigned int tmp_freq)
{
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

static void dk_check_cpu(int cpu, unsigned int load)
{
	struct dk_cpu_dbs_info_s *dbs_info = &per_cpu(dk_cpu_dbs_info, cpu);
	struct cpufreq_policy *policy = dbs_info->cdbs.cur_policy;
	unsigned int next_freq = 0;

	next_freq = adjust_cpufreq_frequency_target(policy, dbs_info->freq_table, 
												 load * (policy->max / 100));

	if (next_freq > policy->cur)
		__cpufreq_driver_target(policy, next_freq, CPUFREQ_RELATION_L);
	else if (next_freq < policy->cur && next_freq > 0)
		__cpufreq_driver_target(policy, next_freq, CPUFREQ_RELATION_L);

}

static void dk_dbs_timer(struct work_struct *work)
{
	struct dk_cpu_dbs_info_s *dbs_info = container_of(work,
			struct dk_cpu_dbs_info_s, cdbs.work.work);
	unsigned int cpu = dbs_info->cdbs.cur_policy->cpu;
	struct dk_cpu_dbs_info_s *core_dbs_info = &per_cpu(dk_cpu_dbs_info,
			cpu);
	struct dbs_data *dbs_data = dbs_info->cdbs.cur_policy->governor_data;
	struct dk_dbs_tuners *dk_tuners = dbs_data->tuners;
	int delay = delay_for_sampling_rate(dk_tuners->sampling_rate);
	bool modify_all = true;

	mutex_lock(&core_dbs_info->cdbs.timer_mutex);
	if (!need_load_eval(&core_dbs_info->cdbs, dk_tuners->sampling_rate))
		modify_all = false;
	else
		dbs_check_cpu(dbs_data, cpu);

	gov_queue_work(dbs_data, dbs_info->cdbs.cur_policy, delay, modify_all);
	mutex_unlock(&core_dbs_info->cdbs.timer_mutex);
}

/************************** sysfs interface ************************/
static struct common_dbs_data dk_dbs_cdata;

/**
 * update_sampling_rate - update sampling rate effective immediately if needed.
 * @new_rate: new sampling rate
 *
 * If new rate is smaller than the old, simply updating
 * dbs_tuners_int.sampling_rate might not be appropriate. For example, if the
 * original sampling_rate was 1 second and the requested new sampling rate is 10
 * ms because the user needs immediate reaction from ondemand governor, but not
 * sure if higher frequency will be required or not, then, the governor may
 * change the sampling rate too late; up to 1 second later. Thus, if we are
 * reducing the sampling rate, we need to make the new value effective
 * immediately.
 */
static void update_sampling_rate(struct dbs_data *dbs_data,
		unsigned int new_rate)
{
	struct dk_dbs_tuners *dk_tuners = dbs_data->tuners;
	int cpu;

	dk_tuners->sampling_rate = new_rate = max(new_rate,
			dbs_data->min_sampling_rate);

	get_online_cpus();
	for_each_online_cpu(cpu) {
		struct cpufreq_policy *policy;
		struct dk_cpu_dbs_info_s *dbs_info;
		unsigned long next_sampling, appointed_at;

		policy = cpufreq_cpu_get(cpu);
		if (!policy)
			continue;
		if (policy->governor != &cpufreq_gov_darkness) {
			cpufreq_cpu_put(policy);
			continue;
		}
		dbs_info = &per_cpu(dk_cpu_dbs_info, cpu);
		cpufreq_cpu_put(policy);

		mutex_lock(&dbs_info->cdbs.timer_mutex);

		if (!delayed_work_pending(&dbs_info->cdbs.work)) {
			mutex_unlock(&dbs_info->cdbs.timer_mutex);
			continue;
		}

		next_sampling = jiffies + usecs_to_jiffies(new_rate);
		appointed_at = dbs_info->cdbs.work.timer.expires;

		if (time_before(next_sampling, appointed_at)) {

			mutex_unlock(&dbs_info->cdbs.timer_mutex);
			cancel_delayed_work_sync(&dbs_info->cdbs.work);
			mutex_lock(&dbs_info->cdbs.timer_mutex);

			gov_queue_work(dbs_data, dbs_info->cdbs.cur_policy,
					usecs_to_jiffies(new_rate), true);

		}
		mutex_unlock(&dbs_info->cdbs.timer_mutex);
	}
	put_online_cpus();
}

static ssize_t store_sampling_rate(struct dbs_data *dbs_data, const char *buf,
		size_t count)
{
	unsigned int input;
	int ret = 0;
	int mpd = strcmp(current->comm, "mpdecision");

	if (mpd == 0)
		return ret;

	ret = sscanf(buf, "%u", &input);

	if (ret != 1)
		return -EINVAL;

	update_sampling_rate(dbs_data, input);
	return count;
}

static ssize_t store_ignore_nice_load(struct dbs_data *dbs_data,
		const char *buf, size_t count)
{
	struct dk_dbs_tuners *dk_tuners = dbs_data->tuners;
	unsigned int input, j;
	int ret;

	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	if (input > 1)
		input = 1;

	if (input == dk_tuners->ignore_nice_load) /* nothing to do */
		return count;

	dk_tuners->ignore_nice_load = input;

	/* we need to re-evaluate prev_cpu_idle */
	for_each_online_cpu(j) {
		struct dk_cpu_dbs_info_s *dbs_info;
		dbs_info = &per_cpu(dk_cpu_dbs_info, j);
		dbs_info->cdbs.prev_cpu_idle = get_cpu_idle_time(j,
					&dbs_info->cdbs.prev_cpu_wall, 0);
		if (dk_tuners->ignore_nice_load)
			dbs_info->cdbs.prev_cpu_nice =
				kcpustat_cpu(j).cpustat[CPUTIME_NICE];
	}
	return count;
}

show_store_one(dk, sampling_rate);
show_store_one(dk, ignore_nice_load);
declare_show_sampling_rate_min(dk);

gov_sys_pol_attr_rw(sampling_rate);
gov_sys_pol_attr_rw(ignore_nice_load);
gov_sys_pol_attr_ro(sampling_rate_min);

static struct attribute *dbs_attributes_gov_sys[] = {
	&sampling_rate_min_gov_sys.attr,
	&sampling_rate_gov_sys.attr,
	&ignore_nice_load_gov_sys.attr,
	NULL
};

static struct attribute_group dk_attr_group_gov_sys = {
	.attrs = dbs_attributes_gov_sys,
	.name = "darkness",
};

static struct attribute *dbs_attributes_gov_pol[] = {
	&sampling_rate_min_gov_pol.attr,
	&sampling_rate_gov_pol.attr,
	&ignore_nice_load_gov_pol.attr,
	NULL
};

static struct attribute_group dk_attr_group_gov_pol = {
	.attrs = dbs_attributes_gov_pol,
	.name = "darkness",
};

/************************** sysfs end ************************/

static int dk_init(struct dbs_data *dbs_data)
{
	struct dk_dbs_tuners *cached_tuners = &per_cpu(dk_cached_tuners, dbs_data->cpu);
	struct dk_dbs_tuners *tuners;

	tuners = kzalloc(sizeof(struct dk_dbs_tuners), GFP_KERNEL);
	if (!tuners) {
		pr_err("%s: kzalloc failed\n", __func__);
		return -ENOMEM;
	}

	dbs_data->min_sampling_rate = MIN_SAMPLING_RATE;
	if (cached_tuners->sampling_rate) {
		tuners->sampling_rate = cached_tuners->sampling_rate;
		tuners->ignore_nice_load = cached_tuners->ignore_nice_load;
	} else {
		tuners->sampling_rate = DEF_SAMPLING_RATE;
		tuners->ignore_nice_load = 0;
	}

	dbs_data->tuners = tuners;
	mutex_init(&dbs_data->mutex);
	return 0;
}

static void dk_exit(struct dbs_data *dbs_data)
{
	struct dk_dbs_tuners *cached_tuners = &per_cpu(dk_cached_tuners, dbs_data->cpu);
	struct dk_dbs_tuners *tuners = dbs_data->tuners;

	if (tuners) {
		cached_tuners->sampling_rate = tuners->sampling_rate;
		cached_tuners->ignore_nice_load = tuners->ignore_nice_load;
	}

	kfree(dbs_data->tuners);
	tuners = NULL;
}

define_get_cpu_dbs_routines(dk_cpu_dbs_info);

static struct dk_ops dk_ops = {
	.get_cpu_frequency_table = dk_get_cpu_frequency_table,
};

static struct common_dbs_data dk_dbs_cdata = {
	.governor = GOV_DARKNESS,
	.attr_group_gov_sys = &dk_attr_group_gov_sys,
	.attr_group_gov_pol = &dk_attr_group_gov_pol,
	.get_cpu_cdbs = get_cpu_cdbs,
	.get_cpu_dbs_info_s = get_cpu_dbs_info_s,
	.gov_dbs_timer = dk_dbs_timer,
	.gov_check_cpu = dk_check_cpu,
	.gov_ops = &dk_ops,
	.init = dk_init,
	.exit = dk_exit,
};

static int dk_cpufreq_governor_dbs(struct cpufreq_policy *policy,
				   unsigned int event)
{
	return cpufreq_governor_dbs(policy, &dk_dbs_cdata, event);
}

#ifndef CONFIG_CPU_FREQ_DEFAULT_GOV_DARKNESS
static
#endif
struct cpufreq_governor cpufreq_gov_darkness = {
	.name			= "darkness",
	.governor		= dk_cpufreq_governor_dbs,
	.max_transition_latency	= TRANSITION_LATENCY_LIMIT,
	.owner			= THIS_MODULE,
};

static int __init cpufreq_gov_dbs_init(void)
{
	return cpufreq_register_governor(&cpufreq_gov_darkness);
}

static void __exit cpufreq_gov_dbs_exit(void)
{
	cpufreq_unregister_governor(&cpufreq_gov_darkness);
}

MODULE_AUTHOR("Alucard24@XDA");
MODULE_DESCRIPTION("'cpufreq_darkness' - A dynamic cpufreq governor v6.0");
MODULE_LICENSE("GPL");

#ifdef CONFIG_CPU_FREQ_DEFAULT_GOV_DARKNESS
fs_initcall(cpufreq_gov_dbs_init);
#else
module_init(cpufreq_gov_dbs_init);
#endif
module_exit(cpufreq_gov_dbs_exit);
