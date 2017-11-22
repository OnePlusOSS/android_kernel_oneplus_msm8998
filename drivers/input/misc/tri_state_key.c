/*
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/input.h>
#include <linux/ioport.h>
#include <linux/platform_device.h>
#include <linux/gpio.h>
#include <linux/gpio_keys.h>
#include <linux/of_platform.h>
#include <linux/of_gpio.h>

#include <linux/switch.h>
#include <linux/workqueue.h>
#include <linux/interrupt.h>
#include <asm/uaccess.h>

#include <linux/regulator/consumer.h>

#include <linux/timer.h>
#include <linux/delay.h>

#define DRV_NAME	"tri-state-key"

/*
	        	KEY1(GPIO1)	KEY2(GPIO92)
pin1 connect to pin4	0	            1         | MUTE
pin2 connect to pin5	1	            1         | Do Not Disturb
pin4 connect to pin3	1	            0         | Normal

*/
typedef enum
{
	MODE_UNKNOWN,
	MODE_MUTE,
	MODE_DO_NOT_DISTURB,
	MODE_NORMAL,
	MODE_MAX_NUM
} tri_mode_t;

struct switch_dev_data
{
	int irq_key3;
	int irq_key2;
	int irq_key1;
	int key1_gpio;
	int key2_gpio;
	int key3_gpio;

	struct regulator *vdd_io;

	struct work_struct work;
	struct switch_dev sdev;
	struct device *dev;

	struct timer_list s_timer;
	struct pinctrl * key_pinctrl;
	struct pinctrl_state * set_state;

};

static struct switch_dev_data *switch_data;
static DEFINE_MUTEX(sem);
static int set_gpio_by_pinctrl(void)
{
	return pinctrl_select_state(switch_data->key_pinctrl, switch_data->set_state);
}

/*set  3 gpio default state high */
static int key_pre[3] = {1, 1, 1};
static int delay_time;

static void switch_dev_work(struct work_struct *work)
{
	int key[3];
	int i, j;
	bool have_wrong_key = false;
	int state_same = 0;

	msleep(delay_time);
	key[0] = gpio_get_value(switch_data->key1_gpio);
	key[1] = gpio_get_value(switch_data->key2_gpio);
	key[2] = gpio_get_value(switch_data->key3_gpio);

	pr_err("%s ,key[0]=%d,key[1]=%d,key[2]=%d\n",
	__func__, key[0], key[1], key[2]);

	for (i = 0; i < 3; i++) {
	/*if 3 gpio status  is the same as before ,ignore them*/
		if (key_pre[i] == key[i])
			state_same++;
		if (state_same == 3)
			return;
	}

	for (i = 0; i < 3; i++) {
	/*
	*	1,if the gpio key is low ,and previous status is low ,
	*	we suspect that the gpio is in wrong states
	*/
		if (key[i] + key_pre[i] == 0) {
			pr_err("[sk]key[%d] is in wrong state\n", i);
			have_wrong_key = true;
			delay_time = 300;
			break;
		}
	}

	mutex_lock(&sem);
	if (have_wrong_key == true) {
		if (key[0]+key[1]+key[2] == 2) {
			if (i == 0)
				switch_set_state(
				&switch_data->sdev,
				MODE_MUTE);
			if (i == 1)
				switch_set_state(
				&switch_data->sdev,
				MODE_DO_NOT_DISTURB);
			if (i == 2)
				switch_set_state(
				&switch_data->sdev,
				MODE_NORMAL);
			}
		else {
			for (j = 0; j < 3; j++) {
			/* we got the  gpio is wrong state,
			*  then check which gpio
			*/
				if ((key[j] == 0) && (i != j)) {
					if (j == 0)
						switch_set_state(
						&switch_data->sdev,
						MODE_MUTE);
					if (j == 1)
						switch_set_state(
						&switch_data->sdev,
						MODE_DO_NOT_DISTURB);
					if (j == 2)
						switch_set_state(
						&switch_data->sdev,
						MODE_NORMAL);
				}
			}
		}
	} else {
		if (!key[0])
			switch_set_state(
			&switch_data->sdev,
			MODE_MUTE);
		if (!key[1])
			switch_set_state(
			&switch_data->sdev,
			MODE_DO_NOT_DISTURB);
		if (!key[2])
			switch_set_state(
			&switch_data->sdev,
			MODE_NORMAL);
		}
	for (i = 0; i < 3; i++)
		key_pre[i] = key[i];

	pr_err("%s ,tristatekey set to state(%d)\n",
	__func__, switch_data->sdev.state);
	mutex_unlock(&sem);
}

static irqreturn_t switch_dev_interrupt(int irq, void *_dev)
{
	schedule_work(&switch_data->work);
	return IRQ_HANDLED;
}

static void timer_handle(unsigned long arg)
{
	schedule_work(&switch_data->work);
}

#ifdef CONFIG_OF
static int switch_dev_get_devtree_pdata(struct device *dev)
{
	struct device_node *node;

	node = dev->of_node;
	if (!node)
		return -EINVAL;

	switch_data->key3_gpio= of_get_named_gpio(node, "tristate,gpio_key3", 0);
	if ((!gpio_is_valid(switch_data->key3_gpio)))
		return -EINVAL;
	pr_err("switch_data->key3_gpio=%d \n", switch_data->key3_gpio);

	switch_data->key2_gpio= of_get_named_gpio(node, "tristate,gpio_key2", 0);
	if ((!gpio_is_valid(switch_data->key2_gpio)))
		return -EINVAL;
	pr_err("switch_data->key2_gpio=%d \n", switch_data->key2_gpio);

	switch_data->key1_gpio= of_get_named_gpio(node, "tristate,gpio_key1", 0);
	if ((!gpio_is_valid(switch_data->key1_gpio)))
		return -EINVAL;
	pr_err("switch_data->key1_gpio=%d \n", switch_data->key1_gpio);

	return 0;
}
#else
static inline int
switch_dev_get_devtree_pdata(struct device *dev)
{
	pr_info("%s inline function", __func__);
	return 0;
}
#endif

static int tristate_dev_probe(struct platform_device *pdev)
{
	struct device *dev;
	int ret = 0;

	dev= &pdev->dev;

	switch_data = kzalloc(sizeof(struct switch_dev_data), GFP_KERNEL);
	if (!switch_data)
		return -ENOMEM;

	switch_data->dev = dev;
	switch_data->sdev.name = DRV_NAME;

	switch_data->key_pinctrl = devm_pinctrl_get(switch_data->dev);
	if (IS_ERR_OR_NULL(switch_data->key_pinctrl)) {
		dev_err(switch_data->dev, "Failed to get pinctrl \n");
		goto err_switch_dev_register;
	}
	switch_data->set_state = pinctrl_lookup_state(switch_data->key_pinctrl,
		"pmx_tri_state_key_active");
	if (IS_ERR_OR_NULL(switch_data->set_state)) {
		dev_err(switch_data->dev, "Failed to lookup_state \n");
		goto err_switch_dev_register;
	}

	set_gpio_by_pinctrl();

	ret = switch_dev_get_devtree_pdata(dev);
	if (ret) {
		dev_err(dev, "parse device tree fail!!!\n");
		goto err_switch_dev_register;
	}

	ret = switch_dev_register(&switch_data->sdev);
	if (ret < 0)
		goto err_switch_dev_register;

	//config irq gpio and request irq
	ret = gpio_request(switch_data->key1_gpio, "tristate_key1");
	if (ret < 0)
		goto err_request_gpio;

	ret = gpio_direction_input(switch_data->key1_gpio);
	if (ret < 0)
		goto err_set_gpio_input;

	switch_data->irq_key1 = gpio_to_irq(switch_data->key1_gpio);
	if (switch_data->irq_key1 < 0) {
		ret = switch_data->irq_key1;
		goto err_detect_irq_num_failed;
	}

	ret = request_irq(switch_data->irq_key1, switch_dev_interrupt,
		IRQF_TRIGGER_FALLING|IRQF_TRIGGER_RISING,
		"tristate_key1", switch_data);
	if (ret < 0)
		goto err_request_irq;

	ret = gpio_request(switch_data->key2_gpio,
		"tristate_key2");
	if (ret < 0)
		goto err_request_gpio;

	ret = gpio_direction_input(switch_data->key2_gpio);
	if (ret < 0)
		goto err_set_gpio_input;

	switch_data->irq_key2 = gpio_to_irq(switch_data->key2_gpio);
	if (switch_data->irq_key2 < 0) {
		ret = switch_data->irq_key2;
		goto err_detect_irq_num_failed;
	}

	ret = request_irq(switch_data->irq_key2, switch_dev_interrupt,
		IRQF_TRIGGER_FALLING|IRQF_TRIGGER_RISING,
		"tristate_key2", switch_data);
	if (ret < 0)
		goto err_request_irq;

	ret = gpio_request(switch_data->key3_gpio,
		"tristate_key3");
	if (ret < 0)
		goto err_request_gpio;

	ret = gpio_direction_input(switch_data->key3_gpio);
	if (ret < 0)
		goto err_set_gpio_input;

	switch_data->irq_key3 = gpio_to_irq(switch_data->key3_gpio);
	if (switch_data->irq_key3 < 0) {
		ret = switch_data->irq_key3;
		goto err_detect_irq_num_failed;
	}

	ret = request_irq(switch_data->irq_key3, switch_dev_interrupt,
		IRQF_TRIGGER_FALLING|IRQF_TRIGGER_RISING,
		"tristate_key3", switch_data);
	if (ret < 0)
		goto err_request_irq;

	INIT_WORK(&switch_data->work, switch_dev_work);

	init_timer(&switch_data->s_timer);
	switch_data->s_timer.function = &timer_handle;
	switch_data->s_timer.expires = jiffies + 5*HZ;

	add_timer(&switch_data->s_timer);

	enable_irq_wake(switch_data->irq_key1);
	enable_irq_wake(switch_data->irq_key2);
	enable_irq_wake(switch_data->irq_key3);

	return 0;

err_request_gpio:
	switch_dev_unregister(&switch_data->sdev);
err_request_irq:
err_detect_irq_num_failed:
err_set_gpio_input:
	gpio_free(switch_data->key2_gpio);
	gpio_free(switch_data->key1_gpio);
	gpio_free(switch_data->key3_gpio);
err_switch_dev_register:
	kfree(switch_data);

	return ret;
}

static int tristate_dev_remove(struct platform_device *pdev)
{
	cancel_work_sync(&switch_data->work);
	gpio_free(switch_data->key1_gpio);
	gpio_free(switch_data->key2_gpio);
	gpio_free(switch_data->key3_gpio);
	switch_dev_unregister(&switch_data->sdev);
	kfree(switch_data);

	return 0;
}
#ifdef CONFIG_OF
static struct of_device_id tristate_dev_of_match[] =
{
	{ .compatible = "oneplus,tri-state-key", },
	{ },
};
MODULE_DEVICE_TABLE(of, tristate_dev_of_match);
#endif

static struct platform_driver tristate_dev_driver = {
	.probe		= tristate_dev_probe,
	.remove		= tristate_dev_remove,
	.driver		= {
		.name	= DRV_NAME,
		.owner	= THIS_MODULE,
		.of_match_table = tristate_dev_of_match,
	},
};
static int __init oem_tristate_init(void)
{
	return platform_driver_register(&tristate_dev_driver);
}
module_init(oem_tristate_init);

static void __exit oem_tristate_exit(void)
{
	platform_driver_unregister(&tristate_dev_driver);
}
module_exit(oem_tristate_exit);
MODULE_DESCRIPTION("oem tri_state_key driver");
MODULE_LICENSE("GPL v2");
