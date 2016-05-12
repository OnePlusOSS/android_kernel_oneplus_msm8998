/*
 *  drivers/cpufreq/cpufreq_nightmare.c
 *
 *  Copyright (C)  2011 Samsung Electronics co. ltd
 *    ByungChang Cha <bc.cha@samsung.com>
 *
 *  Based on ondemand governor
 *  Copyright (C)  2001 Russell King
 *            (C)  2003 Venkatesh Pallipadi <venkatesh.pallipadi@intel.com>.
 *                      Jun Nakajima <jun.nakajima@intel.com>
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

/* nightmare governor macros */
#define FREQ_RESPONSIVENESS			1113600
#define FREQ_RESPONSIVENESS_MAX		2150400

#define DEC_CPU_LOAD				60
#define INC_CPU_LOAD				60
#define INC_CPU_LOAD_AT_MIN_FREQ	40
#define FREQ_STEP_AT_MIN_FREQ		40
#define FREQ_STEP					50
#define FREQ_UP_BRAKE_AT_MIN_FREQ	40
#define FREQ_UP_BRAKE				30
#define FREQ_STEP_DEC				10
#define FREQ_STEP_DEC_AT_MAX_FREQ	10

#define DEF_SAMPLING_RATE			(10000)
#define MIN_SAMPLING_RATE			(10000)

static DEFINE_PER_CPU(struct nm_cpu_dbs_info_s, nm_cpu_dbs_info);

static struct nm_ops nm_ops;

#ifndef CONFIG_CPU_FREQ_DEFAULT_GOV_NIGHTMARE
static struct cpufreq_governor cpufreq_gov_nightmare;
#endif

static void nightmare_get_cpu_frequency_table(int cpu)
{
	struct nm_cpu_dbs_info_s *dbs_info = &per_cpu(nm_cpu_dbs_info, cpu);

	dbs_info->freq_table = cpufreq_frequency_get_table(cpu);
}

static unsigned int adjust_cpufreq_frequency_target(struct cpufreq_policy *policy,
					struct cpufreq_frequency_table *table,
					unsigned int tmp_freq)
{
	unsigned int i = 0, l_freq = 0, h_freq = 0, target_freq = 0;

	if (tmp_freq < policy->min)
		tmp_freq = policy->min;
	if (tmp_freq > policy->max)
		tmp_freq = policy->max;

	for (i = 0; (table[i].frequency != CPUFREQ_TABLE_END); i++) {
		unsigned int freq = table[i].frequency;
		if (freq != CPUFREQ_ENTRY_INVALID) {
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

static void nm_check_cpu(int cpu, unsigned int load)
{
	struct nm_cpu_dbs_info_s *dbs_info = &per_cpu(nm_cpu_dbs_info, cpu);
	struct cpufreq_policy *policy = dbs_info->cdbs.cur_policy;
	struct dbs_data *dbs_data = policy->governor_data;
	struct nm_dbs_tuners *nm_tuners = dbs_data->tuners;
	unsigned int freq_for_responsiveness = nm_tuners->freq_for_responsiveness;
	unsigned int freq_for_responsiveness_max = nm_tuners->freq_for_responsiveness_max;
	int dec_cpu_load = nm_tuners->dec_cpu_load;
	int inc_cpu_load = nm_tuners->inc_cpu_load;
	int freq_step = nm_tuners->freq_step;
	int freq_up_brake = nm_tuners->freq_up_brake;
	int freq_step_dec = nm_tuners->freq_step_dec;
	unsigned int tmp_freq = 0;

	/* CPUs Online Scale Frequency*/
	if (policy->cur < freq_for_responsiveness) {
		inc_cpu_load = nm_tuners->inc_cpu_load_at_min_freq;
		freq_step = nm_tuners->freq_step_at_min_freq;
		freq_up_brake = nm_tuners->freq_up_brake_at_min_freq;
	} else if (policy->cur > freq_for_responsiveness_max) {
		freq_step_dec = nm_tuners->freq_step_dec_at_max_freq;
	}

	/* Check for frequency increase or for frequency decrease */
	if (load >= inc_cpu_load
		 && policy->cur < policy->max) {
		tmp_freq = adjust_cpufreq_frequency_target(policy,
												   dbs_info->freq_table,
												   (policy->cur + ((load + freq_step - freq_up_brake == 0 ? 1 : load + freq_step - freq_up_brake) * 3780)));

		__cpufreq_driver_target(policy, tmp_freq, CPUFREQ_RELATION_L);
	} else if (load < dec_cpu_load
				&& policy->cur > policy->min) {
		tmp_freq = adjust_cpufreq_frequency_target(policy,
												   dbs_info->freq_table,
												   (policy->cur - ((100 - load + freq_step_dec == 0 ? 1 : 100 - load + freq_step_dec) * 3780)));

		__cpufreq_driver_target(policy, tmp_freq, CPUFREQ_RELATION_L);
	}
}

static void nm_dbs_timer(struct work_struct *work)
{
	struct nm_cpu_dbs_info_s *dbs_info = container_of(work,
			struct nm_cpu_dbs_info_s, cdbs.work.work);
	unsigned int cpu = dbs_info->cdbs.cur_policy->cpu;
	struct nm_cpu_dbs_info_s *core_dbs_info = &per_cpu(nm_cpu_dbs_info,
			cpu);
	struct dbs_data *dbs_data = dbs_info->cdbs.cur_policy->governor_data;
	struct nm_dbs_tuners *nm_tuners = dbs_data->tuners;
	int delay = delay_for_sampling_rate(nm_tuners->sampling_rate);
	bool modify_all = true;

	mutex_lock(&core_dbs_info->cdbs.timer_mutex);
	if (!need_load_eval(&core_dbs_info->cdbs, nm_tuners->sampling_rate))
		modify_all = false;
	else
		dbs_check_cpu(dbs_data, cpu);

	gov_queue_work(dbs_data, dbs_info->cdbs.cur_policy, delay, modify_all);
	mutex_unlock(&core_dbs_info->cdbs.timer_mutex);
}

/************************** sysfs interface ************************/
static struct common_dbs_data nm_dbs_cdata;

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
	struct nm_dbs_tuners *nm_tuners = dbs_data->tuners;
	int cpu;

	nm_tuners->sampling_rate = new_rate = max(new_rate,
			dbs_data->min_sampling_rate);

	get_online_cpus();
	for_each_online_cpu(cpu) {
		struct cpufreq_policy *policy;
		struct nm_cpu_dbs_info_s *dbs_info;
		unsigned long next_sampling, appointed_at;

		policy = cpufreq_cpu_get(cpu);
		if (!policy)
			continue;
		if (policy->governor != &cpufreq_gov_nightmare) {
			cpufreq_cpu_put(policy);
			continue;
		}
		dbs_info = &per_cpu(nm_cpu_dbs_info, cpu);
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
	struct nm_dbs_tuners *nm_tuners = dbs_data->tuners;
	unsigned int input, j;
	int ret;

	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	if (input > 1)
		input = 1;

	if (input == nm_tuners->ignore_nice_load) /* nothing to do */
		return count;

	nm_tuners->ignore_nice_load = input;

	/* we need to re-evaluate prev_cpu_idle */
	for_each_online_cpu(j) {
		struct nm_cpu_dbs_info_s *dbs_info;
		dbs_info = &per_cpu(nm_cpu_dbs_info, j);
		dbs_info->cdbs.prev_cpu_idle = get_cpu_idle_time(j,
					&dbs_info->cdbs.prev_cpu_wall, 0);
		if (nm_tuners->ignore_nice_load)
			dbs_info->cdbs.prev_cpu_nice =
				kcpustat_cpu(j).cpustat[CPUTIME_NICE];
	}
	return count;
}

/* inc_cpu_load_at_min_freq */
static ssize_t store_inc_cpu_load_at_min_freq(struct dbs_data *dbs_data, const char *buf,
		size_t count)
{
	struct nm_dbs_tuners *nm_tuners = dbs_data->tuners;
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1) {
		return -EINVAL;
	}

	input = min(input,nm_tuners->inc_cpu_load);

	if (input == nm_tuners->inc_cpu_load_at_min_freq)
		return count;

	nm_tuners->inc_cpu_load_at_min_freq = input;

	return count;
}

/* inc_cpu_load */
static ssize_t store_inc_cpu_load(struct dbs_data *dbs_data, const char *buf,
		size_t count)
{
	struct nm_dbs_tuners *nm_tuners = dbs_data->tuners;
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	input = max(min(input,100),0);

	if (input == nm_tuners->inc_cpu_load)
		return count;

	nm_tuners->inc_cpu_load = input;

	return count;
}

/* dec_cpu_load */
static ssize_t store_dec_cpu_load(struct dbs_data *dbs_data, const char *buf,
		size_t count)
{
	struct nm_dbs_tuners *nm_tuners = dbs_data->tuners;
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	input = max(min(input,95),5);

	if (input == nm_tuners->dec_cpu_load)
		return count;

	nm_tuners->dec_cpu_load = input;

	return count;
}

/* freq_for_responsiveness */
static ssize_t store_freq_for_responsiveness(struct dbs_data *dbs_data, const char *buf,
		size_t count)
{
	struct nm_dbs_tuners *nm_tuners = dbs_data->tuners;
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	if (input == nm_tuners->freq_for_responsiveness)
		return count;

	nm_tuners->freq_for_responsiveness = input;

	return count;
}

/* freq_for_responsiveness_max */
static ssize_t store_freq_for_responsiveness_max(struct dbs_data *dbs_data, const char *buf,
		size_t count)
{
	struct nm_dbs_tuners *nm_tuners = dbs_data->tuners;
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	if (input == nm_tuners->freq_for_responsiveness_max)
		return count;

	nm_tuners->freq_for_responsiveness_max = input;

	return count;
}

/* freq_step_at_min_freq */
static ssize_t store_freq_step_at_min_freq(struct dbs_data *dbs_data, const char *buf,
		size_t count)
{
	struct nm_dbs_tuners *nm_tuners = dbs_data->tuners;
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	input = max(min(input,100),0);

	if (input == nm_tuners->freq_step_at_min_freq)
		return count;

	nm_tuners->freq_step_at_min_freq = input;

	return count;
}

/* freq_step */
static ssize_t store_freq_step(struct dbs_data *dbs_data, const char *buf,
		size_t count)
{
	struct nm_dbs_tuners *nm_tuners = dbs_data->tuners;
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	input = max(min(input,100),0);

	if (input == nm_tuners->freq_step)
		return count;

	nm_tuners->freq_step = input;

	return count;
}

/* freq_up_brake_at_min_freq */
static ssize_t store_freq_up_brake_at_min_freq(struct dbs_data *dbs_data, const char *buf,
		size_t count)
{
	struct nm_dbs_tuners *nm_tuners = dbs_data->tuners;
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	input = max(min(input,100),0);

	if (input == nm_tuners->freq_up_brake_at_min_freq)
		return count;

	nm_tuners->freq_up_brake_at_min_freq = input;

	return count;
}

/* freq_up_brake */
static ssize_t store_freq_up_brake(struct dbs_data *dbs_data, const char *buf,
		size_t count)
{
	struct nm_dbs_tuners *nm_tuners = dbs_data->tuners;
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	input = max(min(input,100),0);

	if (input == nm_tuners->freq_up_brake)
		return count;

	nm_tuners->freq_up_brake = input;

	return count;
}

/* freq_step_dec */
static ssize_t store_freq_step_dec(struct dbs_data *dbs_data, const char *buf,
		size_t count)
{
	struct nm_dbs_tuners *nm_tuners = dbs_data->tuners;
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	input = max(min(input,100),0);

	if (input == nm_tuners->freq_step_dec)
		return count;

	nm_tuners->freq_step_dec = input;

	return count;
}

/* freq_step_dec_at_max_freq */
static ssize_t store_freq_step_dec_at_max_freq(struct dbs_data *dbs_data, const char *buf,
		size_t count)
{
	struct nm_dbs_tuners *nm_tuners = dbs_data->tuners;
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	input = max(min(input,100),0);

	if (input == nm_tuners->freq_step_dec_at_max_freq)
		return count;

	nm_tuners->freq_step_dec_at_max_freq = input;

	return count;
}

show_store_one(nm, sampling_rate);
show_store_one(nm, inc_cpu_load_at_min_freq);
show_store_one(nm, inc_cpu_load);
show_store_one(nm, dec_cpu_load);
show_store_one(nm, freq_for_responsiveness);
show_store_one(nm, freq_for_responsiveness_max);
show_store_one(nm, freq_step_at_min_freq);
show_store_one(nm, freq_step);
show_store_one(nm, freq_up_brake_at_min_freq);
show_store_one(nm, freq_up_brake);
show_store_one(nm, freq_step_dec);
show_store_one(nm, freq_step_dec_at_max_freq);
show_store_one(nm, ignore_nice_load);
declare_show_sampling_rate_min(nm);

gov_sys_pol_attr_rw(sampling_rate);
gov_sys_pol_attr_rw(inc_cpu_load_at_min_freq);
gov_sys_pol_attr_rw(inc_cpu_load);
gov_sys_pol_attr_rw(dec_cpu_load);
gov_sys_pol_attr_rw(freq_for_responsiveness);
gov_sys_pol_attr_rw(freq_for_responsiveness_max);
gov_sys_pol_attr_rw(freq_step_at_min_freq);
gov_sys_pol_attr_rw(freq_step);
gov_sys_pol_attr_rw(freq_up_brake_at_min_freq);
gov_sys_pol_attr_rw(freq_up_brake);
gov_sys_pol_attr_rw(freq_step_dec);
gov_sys_pol_attr_rw(freq_step_dec_at_max_freq);
gov_sys_pol_attr_rw(ignore_nice_load);
gov_sys_pol_attr_ro(sampling_rate_min);

static struct attribute *dbs_attributes_gov_sys[] = {
	&sampling_rate_min_gov_sys.attr,
	&sampling_rate_gov_sys.attr,
	&inc_cpu_load_at_min_freq_gov_sys.attr,
	&inc_cpu_load_gov_sys.attr,
	&dec_cpu_load_gov_sys.attr,
	&freq_for_responsiveness_gov_sys.attr,
	&freq_for_responsiveness_max_gov_sys.attr,
	&freq_step_at_min_freq_gov_sys.attr,
	&freq_step_gov_sys.attr,
	&freq_up_brake_at_min_freq_gov_sys.attr,
	&freq_up_brake_gov_sys.attr,
	&freq_step_dec_gov_sys.attr,
	&freq_step_dec_at_max_freq_gov_sys.attr,
	&ignore_nice_load_gov_sys.attr,
	NULL
};

static struct attribute_group nm_attr_group_gov_sys = {
	.attrs = dbs_attributes_gov_sys,
	.name = "nightmare",
};

static struct attribute *dbs_attributes_gov_pol[] = {
	&sampling_rate_min_gov_pol.attr,
	&sampling_rate_gov_pol.attr,
	&inc_cpu_load_at_min_freq_gov_pol.attr,
	&inc_cpu_load_gov_pol.attr,
	&dec_cpu_load_gov_pol.attr,
	&freq_for_responsiveness_gov_pol.attr,
	&freq_for_responsiveness_max_gov_pol.attr,
	&freq_step_at_min_freq_gov_pol.attr,
	&freq_step_gov_pol.attr,
	&freq_up_brake_at_min_freq_gov_pol.attr,
	&freq_up_brake_gov_pol.attr,
	&freq_step_dec_gov_pol.attr,
	&freq_step_dec_at_max_freq_gov_pol.attr,
	&ignore_nice_load_gov_pol.attr,
	NULL
};

static struct attribute_group nm_attr_group_gov_pol = {
	.attrs = dbs_attributes_gov_pol,
	.name = "nightmare",
};

/************************** sysfs end ************************/

static int nm_init(struct dbs_data *dbs_data)
{
	struct nm_dbs_tuners *tuners;

	tuners = kzalloc(sizeof(struct nm_dbs_tuners), GFP_KERNEL);
	if (!tuners) {
		pr_err("%s: kzalloc failed\n", __func__);
		return -ENOMEM;
	}

	dbs_data->min_sampling_rate = MIN_SAMPLING_RATE;
	tuners->sampling_rate = DEF_SAMPLING_RATE;
	tuners->inc_cpu_load_at_min_freq = INC_CPU_LOAD_AT_MIN_FREQ;
	tuners->inc_cpu_load = INC_CPU_LOAD;
	tuners->dec_cpu_load = DEC_CPU_LOAD;
	tuners->freq_for_responsiveness = FREQ_RESPONSIVENESS;
	tuners->freq_for_responsiveness_max = FREQ_RESPONSIVENESS_MAX;
	tuners->freq_step_at_min_freq = FREQ_STEP_AT_MIN_FREQ;
	tuners->freq_step = FREQ_STEP;
	tuners->freq_up_brake_at_min_freq = FREQ_UP_BRAKE_AT_MIN_FREQ;
	tuners->freq_up_brake = FREQ_UP_BRAKE;
	tuners->freq_step_dec = FREQ_STEP_DEC;
	tuners->freq_step_dec_at_max_freq = FREQ_STEP_DEC_AT_MAX_FREQ;
	tuners->ignore_nice_load = 0;

	dbs_data->tuners = tuners;
	mutex_init(&dbs_data->mutex);
	return 0;
}

static void nm_exit(struct dbs_data *dbs_data)
{
	kfree(dbs_data->tuners);
}

define_get_cpu_dbs_routines(nm_cpu_dbs_info);

static struct nm_ops nm_ops = {
	.get_cpu_frequency_table = nightmare_get_cpu_frequency_table,
};

static struct common_dbs_data nm_dbs_cdata = {
	.governor = GOV_NIGHTMARE,
	.attr_group_gov_sys = &nm_attr_group_gov_sys,
	.attr_group_gov_pol = &nm_attr_group_gov_pol,
	.get_cpu_cdbs = get_cpu_cdbs,
	.get_cpu_dbs_info_s = get_cpu_dbs_info_s,
	.gov_dbs_timer = nm_dbs_timer,
	.gov_check_cpu = nm_check_cpu,
	.gov_ops = &nm_ops,
	.init = nm_init,
	.exit = nm_exit,
};

static int nm_cpufreq_governor_dbs(struct cpufreq_policy *policy,
				   unsigned int event)
{
	return cpufreq_governor_dbs(policy, &nm_dbs_cdata, event);
}

#ifndef CONFIG_CPU_FREQ_DEFAULT_GOV_NIGHTMARE
static
#endif
struct cpufreq_governor cpufreq_gov_nightmare = {
	.name			= "nightmare",
	.governor		= nm_cpufreq_governor_dbs,
	.max_transition_latency	= TRANSITION_LATENCY_LIMIT,
	.owner			= THIS_MODULE,
};

static int __init cpufreq_gov_dbs_init(void)
{
	return cpufreq_register_governor(&cpufreq_gov_nightmare);
}

static void __exit cpufreq_gov_dbs_exit(void)
{
	cpufreq_unregister_governor(&cpufreq_gov_nightmare);
}

MODULE_AUTHOR("Alucard24@XDA");
MODULE_DESCRIPTION("'cpufreq_nightmare' - A dynamic cpufreq/cpuhotplug governor v6.0");
MODULE_LICENSE("GPL");

#ifdef CONFIG_CPU_FREQ_DEFAULT_GOV_NIGHTMARE
fs_initcall(cpufreq_gov_dbs_init);
#else
module_init(cpufreq_gov_dbs_init);
#endif
module_exit(cpufreq_gov_dbs_exit);
