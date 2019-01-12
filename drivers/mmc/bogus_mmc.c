// SPDX-License-Identifier: GPL-2.0
/*
 * bogus_mmc.c
 *
 * Copyright (c) 2019 Park Ju Hyung(arter97)
 *
 * This module exposes a bogus sysfs entry /sys/class/mmc_host/mmc0/clk_scaling/enable
 * in order for perfd to operate properly.
 */

#include <linux/device.h>
#include <linux/types.h>
#include <linux/kdev_t.h>
#include <linux/major.h>
#include <linux/module.h>

static struct class *mmc_class;
static struct device *mmc0;

static int enabled = 1;
static ssize_t show_enable(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", enabled);
}

static ssize_t store_enable(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 value;

	if (kstrtou32(buf, 0, &value))
		return -EINVAL;

	enabled = !!value;

	return count;
}

DEVICE_ATTR(enable, S_IRUGO | S_IWUSR, show_enable, store_enable);

static struct attribute *clk_scaling_attrs[] = {
	&dev_attr_enable.attr,
	NULL,
};

static struct attribute_group clk_scaling_attr_grp = {
	.name = "clk_scaling",
	.attrs = clk_scaling_attrs,
};

static int __init bogus_mmc_init(void)
{
	int ret = 0;

	mmc_class = class_create(THIS_MODULE, "mmc_host");
	if (IS_ERR(mmc_class)) {
		ret = PTR_ERR(mmc_class);
		goto out;
	}

	mmc0 = device_create(mmc_class, NULL, MKDEV(BOGUS_MMC_BLOCK_MAJOR, 0),
			NULL, "mmc0");
	ret = sysfs_create_group(&mmc0->kobj, &clk_scaling_attr_grp);

out:
	return ret;
}

module_init(bogus_mmc_init);

MODULE_DESCRIPTION("Bogus MMC sysfs");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Park Ju Hyung");
