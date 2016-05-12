/*
 *  drivers/cpufreq/cpufreq_alucard.c
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

/* alucard governor macros */
#define FREQ_RESPONSIVENESS			1113600

#define CPUS_DOWN_RATE				1
#define CPUS_UP_RATE				1
#define DEC_CPU_LOAD				70
#define DEC_CPU_LOAD_AT_MIN_FREQ	60
#define INC_CPU_LOAD				70
#define INC_CPU_LOAD_AT_MIN_FREQ	60

#define DEF_SAMPLING_RATE			(10000)
#define MIN_SAMPLING_RATE			(10000)

/* Pump Inc/Dec for all cores */
#define PUMP_INC_STEP_AT_MIN_FREQ	2
#define PUMP_INC_STEP				2
#define PUMP_DEC_STEP_AT_MIN_FREQ	2
#define PUMP_DEC_STEP				1

struct ac_pump_cpu_parm {
	int pump_inc_step;
	int pump_inc_step_at_min_freq;
	int pump_dec_step;
	int pump_dec_step_at_min_freq;
};

static DEFINE_PER_CPU(struct ac_cpu_dbs_info_s, ac_cpu_dbs_info);
static DEFINE_PER_CPU_SHARED_ALIGNED(struct ac_pump_cpu_parm, od_ac_pump_cpu_parm);

static struct ac_ops ac_ops;

#ifndef CONFIG_CPU_FREQ_DEFAULT_GOV_ALUCARD
static struct cpufreq_governor cpufreq_gov_alucard;
#endif

static void alucard_get_cpu_frequency_table(int cpu)
{
	struct ac_cpu_dbs_info_s *dbs_info = &per_cpu(ac_cpu_dbs_info, cpu);

	dbs_info->freq_table = cpufreq_frequency_get_table(cpu);
}

static void alucard_get_cpu_frequency_table_minmax(struct cpufreq_policy *policy,
				int cpu)
{
	struct ac_cpu_dbs_info_s *dbs_info = &per_cpu(ac_cpu_dbs_info, cpu);
	struct cpufreq_frequency_table *table = dbs_info->freq_table;
	unsigned int i = 0;

	for (i = 0; (table[i].frequency != CPUFREQ_TABLE_END); i++) {
		unsigned int freq = table[i].frequency;
		if (freq != CPUFREQ_ENTRY_INVALID) {
			if (freq == policy->min)
				dbs_info->min_index = i;
			if (freq == policy->max)
				dbs_info->max_index = i;

			if (freq >= policy->min &&
				freq >= policy->max)
				break;
		}
	}
}

static void alucard_get_cpu_frequency_table_cur(struct cpufreq_policy *policy,
					struct cpufreq_frequency_table *table,
					unsigned int *index)
{
	unsigned int i = 0;

	for (i = 0; (table[i].frequency != CPUFREQ_TABLE_END); i++) {
		unsigned int freq = table[i].frequency;
		if (freq != CPUFREQ_ENTRY_INVALID) {
			if (freq == policy->cur) {
				*index = i;
				break;
			}
		}
	}
}

static void ac_check_cpu(int cpu, unsigned int load)
{
	struct ac_cpu_dbs_info_s *dbs_info = &per_cpu(ac_cpu_dbs_info, cpu);
	struct cpufreq_policy *policy = dbs_info->cdbs.cur_policy;
	struct dbs_data *dbs_data = policy->governor_data;
	struct ac_dbs_tuners *ac_tuners = dbs_data->tuners;
	struct ac_pump_cpu_parm *this_cpu_parm = &per_cpu(od_ac_pump_cpu_parm, cpu);
	unsigned int freq_responsiveness = ac_tuners->freq_responsiveness;
	int dec_cpu_load = ac_tuners->dec_cpu_load;
	int inc_cpu_load = ac_tuners->inc_cpu_load;
	int pump_inc_step = this_cpu_parm->pump_inc_step;
	int pump_dec_step = this_cpu_parm->pump_dec_step;
	unsigned int cpus_up_rate = ac_tuners->cpus_up_rate;
	unsigned int cpus_down_rate = ac_tuners->cpus_down_rate;
	unsigned int index = 0;

	/* Get min, current, max indexes from current cpu policy */
	alucard_get_cpu_frequency_table_cur(policy,
				dbs_info->freq_table,
				&index);

	/* CPUs Online Scale Frequency*/
	if (policy->cur < freq_responsiveness) {
		inc_cpu_load = ac_tuners->inc_cpu_load_at_min_freq;
		dec_cpu_load = ac_tuners->dec_cpu_load_at_min_freq;
		pump_inc_step = this_cpu_parm->pump_inc_step_at_min_freq;
		pump_dec_step = this_cpu_parm->pump_dec_step_at_min_freq;
	}

	/* Check for frequency increase or for frequency decrease */
	if (load >= inc_cpu_load
		 && index < dbs_info->max_index) {
		if (dbs_info->up_rate % cpus_up_rate == 0) {
			if ((index + pump_inc_step) <= dbs_info->max_index)
				index += pump_inc_step;
			else
				index = dbs_info->max_index;

			dbs_info->up_rate = 1;
			dbs_info->down_rate = 1;

			if (dbs_info->freq_table[index].frequency != CPUFREQ_ENTRY_INVALID)
				__cpufreq_driver_target(policy,
										dbs_info->freq_table[index].frequency,
										CPUFREQ_RELATION_L);
		} else {
			if (dbs_info->up_rate < cpus_up_rate)
				++dbs_info->up_rate;
			else
				dbs_info->up_rate = 1;
		}
	} else if (load < dec_cpu_load
				 && index > dbs_info->min_index) {
		if (dbs_info->down_rate % cpus_down_rate == 0) {
			if ((index - dbs_info->min_index) >= pump_dec_step)
				index -= pump_dec_step;
			else
				index = dbs_info->min_index;

			dbs_info->up_rate = 1;
			dbs_info->down_rate = 1;

			if (dbs_info->freq_table[index].frequency != CPUFREQ_ENTRY_INVALID)
				__cpufreq_driver_target(policy,
										dbs_info->freq_table[index].frequency,
										CPUFREQ_RELATION_L);
		} else {
			if (dbs_info->down_rate < cpus_down_rate)
				++dbs_info->down_rate;
			else
				dbs_info->down_rate = 1;
		}
	} else {
		dbs_info->up_rate = 1;
		dbs_info->down_rate = 1;
	}

}

static void ac_dbs_timer(struct work_struct *work)
{
	struct ac_cpu_dbs_info_s *dbs_info = container_of(work,
			struct ac_cpu_dbs_info_s, cdbs.work.work);
	unsigned int cpu = dbs_info->cdbs.cur_policy->cpu;
	struct ac_cpu_dbs_info_s *core_dbs_info = &per_cpu(ac_cpu_dbs_info,
			cpu);
	struct dbs_data *dbs_data = dbs_info->cdbs.cur_policy->governor_data;
	struct ac_dbs_tuners *ac_tuners = dbs_data->tuners;
	int delay = delay_for_sampling_rate(ac_tuners->sampling_rate);
	bool modify_all = true;

	mutex_lock(&core_dbs_info->cdbs.timer_mutex);
	if (!need_load_eval(&core_dbs_info->cdbs, ac_tuners->sampling_rate))
		modify_all = false;
	else
		dbs_check_cpu(dbs_data, cpu);

	gov_queue_work(dbs_data, dbs_info->cdbs.cur_policy, delay, modify_all);
	mutex_unlock(&core_dbs_info->cdbs.timer_mutex);
}

/************************** sysfs interface ************************/
static struct common_dbs_data ac_dbs_cdata;

#define show_pcpu_pump_param(file_name, num_core)		\
static ssize_t show_##file_name##_##num_core		\
(struct kobject *kobj, struct attribute *attr, char *buf)		\
{									\
	struct ac_pump_cpu_parm *this_cpu_parm = &per_cpu(od_ac_pump_cpu_parm, num_core - 1); \
	return sprintf(buf, "%d\n", \
			this_cpu_parm->file_name);		\
}

show_pcpu_pump_param(pump_inc_step_at_min_freq, 1);
show_pcpu_pump_param(pump_inc_step_at_min_freq, 2);
show_pcpu_pump_param(pump_inc_step_at_min_freq, 3);
show_pcpu_pump_param(pump_inc_step_at_min_freq, 4);
show_pcpu_pump_param(pump_inc_step, 1);
show_pcpu_pump_param(pump_inc_step, 2);
show_pcpu_pump_param(pump_inc_step, 3);
show_pcpu_pump_param(pump_inc_step, 4);
show_pcpu_pump_param(pump_dec_step_at_min_freq, 1);
show_pcpu_pump_param(pump_dec_step_at_min_freq, 2);
show_pcpu_pump_param(pump_dec_step_at_min_freq, 3);
show_pcpu_pump_param(pump_dec_step_at_min_freq, 4);
show_pcpu_pump_param(pump_dec_step, 1);
show_pcpu_pump_param(pump_dec_step, 2);
show_pcpu_pump_param(pump_dec_step, 3);
show_pcpu_pump_param(pump_dec_step, 4);

#define store_pcpu_pump_param(file_name, num_core)		\
static ssize_t store_##file_name##_##num_core		\
(struct kobject *kobj, struct attribute *attr,				\
	const char *buf, size_t count)					\
{									\
	int input;						\
	struct ac_pump_cpu_parm *this_cpu_parm; \
	int ret;							\
														\
	ret = sscanf(buf, "%d", &input);					\
	if (ret != 1)											\
		return -EINVAL;										\
														\
	input = min(max(1, input), 6);							\
														\
	this_cpu_parm = &per_cpu(od_ac_pump_cpu_parm, num_core - 1); \
														\
	if (input == this_cpu_parm->file_name) {		\
		return count;						\
	}								\
										\
	this_cpu_parm->file_name = input;			\
	return count;							\
}

store_pcpu_pump_param(pump_inc_step_at_min_freq, 1);
store_pcpu_pump_param(pump_inc_step_at_min_freq, 2);
store_pcpu_pump_param(pump_inc_step_at_min_freq, 3);
store_pcpu_pump_param(pump_inc_step_at_min_freq, 4);
store_pcpu_pump_param(pump_inc_step, 1);
store_pcpu_pump_param(pump_inc_step, 2);
store_pcpu_pump_param(pump_inc_step, 3);
store_pcpu_pump_param(pump_inc_step, 4);
store_pcpu_pump_param(pump_dec_step_at_min_freq, 1);
store_pcpu_pump_param(pump_dec_step_at_min_freq, 2);
store_pcpu_pump_param(pump_dec_step_at_min_freq, 3);
store_pcpu_pump_param(pump_dec_step_at_min_freq, 4);
store_pcpu_pump_param(pump_dec_step, 1);
store_pcpu_pump_param(pump_dec_step, 2);
store_pcpu_pump_param(pump_dec_step, 3);
store_pcpu_pump_param(pump_dec_step, 4);

define_one_global_rw(pump_inc_step_at_min_freq_1);
define_one_global_rw(pump_inc_step_at_min_freq_2);
define_one_global_rw(pump_inc_step_at_min_freq_3);
define_one_global_rw(pump_inc_step_at_min_freq_4);
define_one_global_rw(pump_inc_step_1);
define_one_global_rw(pump_inc_step_2);
define_one_global_rw(pump_inc_step_3);
define_one_global_rw(pump_inc_step_4);
define_one_global_rw(pump_dec_step_at_min_freq_1);
define_one_global_rw(pump_dec_step_at_min_freq_2);
define_one_global_rw(pump_dec_step_at_min_freq_3);
define_one_global_rw(pump_dec_step_at_min_freq_4);
define_one_global_rw(pump_dec_step_1);
define_one_global_rw(pump_dec_step_2);
define_one_global_rw(pump_dec_step_3);
define_one_global_rw(pump_dec_step_4);

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
	struct ac_dbs_tuners *ac_tuners = dbs_data->tuners;
	int cpu;

	ac_tuners->sampling_rate = new_rate = max(new_rate,
			dbs_data->min_sampling_rate);

	get_online_cpus();
	for_each_online_cpu(cpu) {
		struct cpufreq_policy *policy;
		struct ac_cpu_dbs_info_s *dbs_info;
		unsigned long next_sampling, appointed_at;

		policy = cpufreq_cpu_get(cpu);
		if (!policy)
			continue;
		if (policy->governor != &cpufreq_gov_alucard) {
			cpufreq_cpu_put(policy);
			continue;
		}
		dbs_info = &per_cpu(ac_cpu_dbs_info, cpu);
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
	struct ac_dbs_tuners *ac_tuners = dbs_data->tuners;
	unsigned int input, j;
	int ret;

	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	if (input > 1)
		input = 1;

	if (input == ac_tuners->ignore_nice_load) /* nothing to do */
		return count;

	ac_tuners->ignore_nice_load = input;

	/* we need to re-evaluate prev_cpu_idle */
	for_each_online_cpu(j) {
		struct ac_cpu_dbs_info_s *dbs_info;
		dbs_info = &per_cpu(ac_cpu_dbs_info, j);
		dbs_info->cdbs.prev_cpu_idle = get_cpu_idle_time(j,
					&dbs_info->cdbs.prev_cpu_wall, 0);
		if (ac_tuners->ignore_nice_load)
			dbs_info->cdbs.prev_cpu_nice =
				kcpustat_cpu(j).cpustat[CPUTIME_NICE];
	}
	return count;
}

/* inc_cpu_load_at_min_freq */
static ssize_t store_inc_cpu_load_at_min_freq(struct dbs_data *dbs_data, const char *buf,
		size_t count)
{
	struct ac_dbs_tuners *ac_tuners = dbs_data->tuners;
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1) {
		return -EINVAL;
	}

	input = min(input, ac_tuners->inc_cpu_load);

	if (input == ac_tuners->inc_cpu_load_at_min_freq)
		return count;

	ac_tuners->inc_cpu_load_at_min_freq = input;

	return count;
}

/* inc_cpu_load */
static ssize_t store_inc_cpu_load(struct dbs_data *dbs_data, const char *buf,
		size_t count)
{
	struct ac_dbs_tuners *ac_tuners = dbs_data->tuners;
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	input = max(min(input, 100),0);

	if (input == ac_tuners->inc_cpu_load)
		return count;

	ac_tuners->inc_cpu_load = input;

	return count;
}

/* dec_cpu_load_at_min_freq */
static ssize_t store_dec_cpu_load_at_min_freq(struct dbs_data *dbs_data, const char *buf,
		size_t count)
{
	struct ac_dbs_tuners *ac_tuners = dbs_data->tuners;
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1) {
		return -EINVAL;
	}

	input = min(input, ac_tuners->dec_cpu_load);

	if (input == ac_tuners->dec_cpu_load_at_min_freq)
		return count;

	ac_tuners->dec_cpu_load_at_min_freq = input;

	return count;
}

/* dec_cpu_load */
static ssize_t store_dec_cpu_load(struct dbs_data *dbs_data, const char *buf,
		size_t count)
{
	struct ac_dbs_tuners *ac_tuners = dbs_data->tuners;
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	input = max(min(input, 95),5);

	if (input == ac_tuners->dec_cpu_load)
		return count;

	ac_tuners->dec_cpu_load = input;

	return count;
}

/* freq_responsiveness */
static ssize_t store_freq_responsiveness(struct dbs_data *dbs_data, const char *buf,
		size_t count)
{
	struct ac_dbs_tuners *ac_tuners = dbs_data->tuners;
	int input;
	int ret;

	ret = sscanf(buf, "%d", &input);
	if (ret != 1)
		return -EINVAL;

	if (input == ac_tuners->freq_responsiveness)
		return count;

	ac_tuners->freq_responsiveness = input;

	return count;
}

/* cpus_up_rate */
static ssize_t store_cpus_up_rate(struct dbs_data *dbs_data, const char *buf,
		size_t count)
{
	struct ac_dbs_tuners *ac_tuners = dbs_data->tuners;
	unsigned int input;
	int ret;

	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	if (input == ac_tuners->cpus_up_rate)
		return count;

	ac_tuners->cpus_up_rate = input;

	return count;
}

/* cpus_down_rate */
static ssize_t store_cpus_down_rate(struct dbs_data *dbs_data, const char *buf,
		size_t count)
{
	struct ac_dbs_tuners *ac_tuners = dbs_data->tuners;
	unsigned int input;
	int ret;

	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;

	if (input == ac_tuners->cpus_down_rate)
		return count;

	ac_tuners->cpus_down_rate = input;

	return count;
}

show_store_one(ac, sampling_rate);
show_store_one(ac, inc_cpu_load_at_min_freq);
show_store_one(ac, inc_cpu_load);
show_store_one(ac, dec_cpu_load_at_min_freq);
show_store_one(ac, dec_cpu_load);
show_store_one(ac, freq_responsiveness);
show_store_one(ac, cpus_up_rate);
show_store_one(ac, cpus_down_rate);
show_store_one(ac, ignore_nice_load);
declare_show_sampling_rate_min(ac);

gov_sys_pol_attr_rw(sampling_rate);
gov_sys_pol_attr_rw(inc_cpu_load_at_min_freq);
gov_sys_pol_attr_rw(inc_cpu_load);
gov_sys_pol_attr_rw(dec_cpu_load_at_min_freq);
gov_sys_pol_attr_rw(dec_cpu_load);
gov_sys_pol_attr_rw(freq_responsiveness);
gov_sys_pol_attr_rw(cpus_up_rate);
gov_sys_pol_attr_rw(cpus_down_rate);
gov_sys_pol_attr_rw(ignore_nice_load);
gov_sys_pol_attr_ro(sampling_rate_min);

static struct attribute *dbs_attributes_gov_sys[] = {
	&sampling_rate_min_gov_sys.attr,
	&sampling_rate_gov_sys.attr,
	&inc_cpu_load_at_min_freq_gov_sys.attr,
	&inc_cpu_load_gov_sys.attr,
	&dec_cpu_load_at_min_freq_gov_sys.attr,
	&dec_cpu_load_gov_sys.attr,
	&freq_responsiveness_gov_sys.attr,
	&pump_inc_step_at_min_freq_1.attr,
	&pump_inc_step_at_min_freq_2.attr,
	&pump_inc_step_at_min_freq_3.attr,
	&pump_inc_step_at_min_freq_4.attr,
	&pump_inc_step_1.attr,
	&pump_inc_step_2.attr,
	&pump_inc_step_3.attr,
	&pump_inc_step_4.attr,
	&pump_dec_step_at_min_freq_1.attr,
	&pump_dec_step_at_min_freq_2.attr,
	&pump_dec_step_at_min_freq_3.attr,
	&pump_dec_step_at_min_freq_4.attr,
	&pump_dec_step_1.attr,
	&pump_dec_step_2.attr,
	&pump_dec_step_3.attr,
	&pump_dec_step_4.attr,
	&cpus_up_rate_gov_sys.attr,
	&cpus_down_rate_gov_sys.attr,
	&ignore_nice_load_gov_sys.attr,
	NULL
};

static struct attribute_group ac_attr_group_gov_sys = {
	.attrs = dbs_attributes_gov_sys,
	.name = "alucard",
};

static struct attribute *dbs_attributes_gov_pol[] = {
	&sampling_rate_min_gov_pol.attr,
	&sampling_rate_gov_pol.attr,
	&inc_cpu_load_at_min_freq_gov_pol.attr,
	&inc_cpu_load_gov_pol.attr,
	&dec_cpu_load_at_min_freq_gov_pol.attr,
	&dec_cpu_load_gov_pol.attr,
	&freq_responsiveness_gov_pol.attr,
	&pump_inc_step_at_min_freq_1.attr,
	&pump_inc_step_at_min_freq_2.attr,
	&pump_inc_step_at_min_freq_3.attr,
	&pump_inc_step_at_min_freq_4.attr,
	&pump_inc_step_1.attr,
	&pump_inc_step_2.attr,
	&pump_inc_step_3.attr,
	&pump_inc_step_4.attr,
	&pump_dec_step_at_min_freq_1.attr,
	&pump_dec_step_at_min_freq_2.attr,
	&pump_dec_step_at_min_freq_3.attr,
	&pump_dec_step_at_min_freq_4.attr,
	&pump_dec_step_1.attr,
	&pump_dec_step_2.attr,
	&pump_dec_step_3.attr,
	&pump_dec_step_4.attr,
	&cpus_up_rate_gov_pol.attr,
	&cpus_down_rate_gov_pol.attr,
	&ignore_nice_load_gov_pol.attr,
	NULL
};

static struct attribute_group ac_attr_group_gov_pol = {
	.attrs = dbs_attributes_gov_pol,
	.name = "alucard",
};

/************************** sysfs end ************************/

static int ac_init(struct dbs_data *dbs_data)
{
	struct ac_dbs_tuners *tuners;
	unsigned int cpu = 0;

	tuners = kzalloc(sizeof(struct ac_dbs_tuners), GFP_KERNEL);
	if (!tuners) {
		pr_err("%s: kzalloc failed\n", __func__);
		return -ENOMEM;
	}

	for_each_possible_cpu(cpu) {
		struct ac_pump_cpu_parm *this_cpu_parm = &per_cpu(od_ac_pump_cpu_parm, cpu);

		this_cpu_parm->pump_inc_step_at_min_freq = PUMP_INC_STEP_AT_MIN_FREQ;
		this_cpu_parm->pump_inc_step = PUMP_INC_STEP;
		this_cpu_parm->pump_dec_step = PUMP_DEC_STEP;
		this_cpu_parm->pump_dec_step_at_min_freq = PUMP_DEC_STEP_AT_MIN_FREQ;
	}

	dbs_data->min_sampling_rate = MIN_SAMPLING_RATE;
	tuners->sampling_rate = DEF_SAMPLING_RATE;
	tuners->ignore_nice_load = 0;
	tuners->inc_cpu_load_at_min_freq = INC_CPU_LOAD_AT_MIN_FREQ;
	tuners->inc_cpu_load = INC_CPU_LOAD;
	tuners->dec_cpu_load_at_min_freq = DEC_CPU_LOAD_AT_MIN_FREQ;
	tuners->dec_cpu_load = DEC_CPU_LOAD;
	tuners->freq_responsiveness = FREQ_RESPONSIVENESS;
	tuners->cpus_up_rate = CPUS_UP_RATE;
	tuners->cpus_down_rate = CPUS_DOWN_RATE;

	dbs_data->tuners = tuners;
	mutex_init(&dbs_data->mutex);
	return 0;
}

static void ac_exit(struct dbs_data *dbs_data)
{
	kfree(dbs_data->tuners);
}

define_get_cpu_dbs_routines(ac_cpu_dbs_info);

static struct ac_ops ac_ops = {
	.get_cpu_frequency_table = alucard_get_cpu_frequency_table,
	.get_cpu_frequency_table_minmax = alucard_get_cpu_frequency_table_minmax,
};

static struct common_dbs_data ac_dbs_cdata = {
	.governor = GOV_ALUCARD,
	.attr_group_gov_sys = &ac_attr_group_gov_sys,
	.attr_group_gov_pol = &ac_attr_group_gov_pol,
	.get_cpu_cdbs = get_cpu_cdbs,
	.get_cpu_dbs_info_s = get_cpu_dbs_info_s,
	.gov_dbs_timer = ac_dbs_timer,
	.gov_check_cpu = ac_check_cpu,
	.gov_ops = &ac_ops,
	.init = ac_init,
	.exit = ac_exit,
};

static int ac_cpufreq_governor_dbs(struct cpufreq_policy *policy,
				   unsigned int event)
{
	return cpufreq_governor_dbs(policy, &ac_dbs_cdata, event);
}

#ifndef CONFIG_CPU_FREQ_DEFAULT_GOV_ALUCARD
static
#endif
struct cpufreq_governor cpufreq_gov_alucard = {
	.name			= "alucard",
	.governor		= ac_cpufreq_governor_dbs,
	.max_transition_latency	= TRANSITION_LATENCY_LIMIT,
	.owner			= THIS_MODULE,
};

static int __init cpufreq_gov_dbs_init(void)
{
	return cpufreq_register_governor(&cpufreq_gov_alucard);
}

static void __exit cpufreq_gov_dbs_exit(void)
{
	cpufreq_unregister_governor(&cpufreq_gov_alucard);
}

MODULE_AUTHOR("Alucard24@XDA");
MODULE_DESCRIPTION("'cpufreq_alucard' - A dynamic cpufreq governor v4.0");
MODULE_LICENSE("GPL");

#ifdef CONFIG_CPU_FREQ_DEFAULT_GOV_ALUCARD
fs_initcall(cpufreq_gov_dbs_init);
#else
module_init(cpufreq_gov_dbs_init);
#endif
module_exit(cpufreq_gov_dbs_exit);
