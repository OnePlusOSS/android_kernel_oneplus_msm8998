/*
 * tfa98xx.c   tfa98xx codec module
 *
 * Copyright (c) 2015 NXP Semiconductors
 *
 *  Author: Sebastien Jan <sjan@baylibre.com>
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#define pr_fmt(fmt) "%s(): " fmt, __func__

#include <linux/module.h>
#include <linux/i2c.h>
#include <sound/core.h>
#include <sound/pcm.h>
#include <sound/pcm_params.h>
#include <sound/soc.h>
#include <linux/of_gpio.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/firmware.h>
#include <linux/i2c.h>
#include <linux/debugfs.h>
#include <linux/version.h>
#include <linux/input.h>

#include "config.h"
/*zhiguang.su@MultiMedia.AudioDrv, 2014-4-14, add for l21 power*/
#include <linux/regulator/consumer.h>

/*zhiguang.su@MultiMedia.AudioDrv, 2015-11-09, add for debug*/
#include <sound/sounddebug.h>

#define I2C_RETRIES 50
#define I2C_RETRY_DELAY 5 /* ms */
/* TODO: remove genregs usage? */
#ifdef N1A
#include "tfa98xx_genregs_N1A12.h"
#else
#include "tfa98xx_genregs_N1C.h"
#endif
#include "tfa9891_genregs.h"

#include "tfa98xx_tfafieldnames.h"
#include "tfa_internal.h"
#include "tfa.h"
#include "tfa_service.h"
#include "tfa_container.h"
#include "tfa98xx_parameters.h"

#define TFA98XX_VERSION		"2.10.2"

/* Change volume selection behavior:
 * Uncomment following line to generate a profile change when updating
 * a volume control (also changes to the profile of the modified  volume
 * control)
 */
/*#define TFA98XX_ALSA_CTRL_PROF_CHG_ON_VOL	1
*/

/* Supported rates and data formats */
#define TFA98XX_RATES SNDRV_PCM_RATE_8000_48000

//#define TFA98XX_FORMATS	(SNDRV_PCM_FMTBIT_S16_LE | SNDRV_PCM_FMTBIT_S24_LE | SNDRV_PCM_FMTBIT_S32_LE) 
#define TFA98XX_FORMATS	SNDRV_PCM_FMTBIT_S16_LE

#define TF98XX_MAX_DSP_START_TRY_COUNT	10

#define XMEM_TAP_ACK  0x0122
#define XMEM_TAP_READ 0x010f

static LIST_HEAD(profile_list); /* list of user selectable profiles */

#ifdef dev_dbg
#undef dev_dbg
#define dev_dbg dev_err
#endif

#ifdef dev_info
#undef dev_info
#define dev_info dev_err
#endif

static int tfa98xx_kmsg_regs = 0;
static int tfa98xx_ftrace_regs = 0;

static struct tfa98xx *tfa98xx_devices[4] = {NULL, NULL, NULL, NULL};
static int tfa98xx_registered_handles = 0;
static int tfa98xx_vsteps[4]={0,0,0,0};
static int tfa98xx_profile = 0; /* store profile */
static int tfa98xx_prof_vsteps[10] = {0}; /* store vstep per profile (single device) */
static int tfa98xx_mixer_profiles = 0; /* number of user selectable profiles */
static int tfa98xx_mixer_profile = 0; /* current mixer profile */

static char *dflt_prof_name = "";
module_param(dflt_prof_name, charp, S_IRUGO);

static int no_start = 0;
module_param(no_start, int, S_IRUGO);
MODULE_PARM_DESC(no_start, "do not start the work queue; for debugging via user\n");

struct tfa98xx *g_tfa98xx = NULL;
EXPORT_SYMBOL_GPL(g_tfa98xx);

/*zhiguang.su@MultiMedia.AudioDrv, 2014-4-14, add for l21 power*/
struct regulator *bob_power;
EXPORT_SYMBOL_GPL(bob_power);

static void tfa98xx_tapdet_check_update(struct tfa98xx *tfa98xx);
static void tfa98xx_interrupt_restore(struct tfa98xx *tfa98xx);
static int tfa98xx_get_fssel(unsigned int rate);

static int get_profile_from_list(char *buf, int id);
static int get_profile_id_for_sr(int id, unsigned int rate); 
/*zhiguang.su@MultiMediaService,2017-02-09,avoid no sound for ftm*/
static void tfa98xx_dsp_startInit(struct tfa98xx *tfa98xx);
/*zhiguang.su@MultiMediaService,2017-04-26,add ftm spk pa rivision test*/
static int tfa98xx_info_rivision_ctl(struct snd_kcontrol *kcontrol,
				struct snd_ctl_elem_info *uinfo);
static int tfa98xx_get_rivision_ctl(struct snd_kcontrol *kcontrol,
			     struct snd_ctl_elem_value *ucontrol);
static int tfa98xx_set_rivision_ctl(struct snd_kcontrol *kcontrol,
			     struct snd_ctl_elem_value *ucontrol);

/*zhiguang.su@MultiMedia.AudioDrv, 2015-11-09, add for debug*/
int testLogOn = 0;
EXPORT_SYMBOL_GPL(testLogOn);

/*wangdongdong@MultiMediaService,2016/11/30,add for speaker impedence detection*/
static int tfa98xx_speaker_recalibration(Tfa98xx_handle_t handle,unsigned int *speakerImpedance);

struct tfa98xx_rate {
	unsigned int rate;
	unsigned int fssel;
};

static struct tfa98xx_rate rate_to_fssel[] = {
	{ 8000, 0 },
	{ 11025, 1 },
	{ 12000, 2 },
	{ 16000, 3 },
	{ 22050, 4 },
	{ 24000, 5 },
	{ 32000, 6 },
	{ 44100, 7 },
	{ 48000, 8 },
};

/*zhiguang.su@MultiMediaService,2017-04-26,add ftm spk pa rivision test*/
static struct snd_kcontrol_new tfa98xx_at_controls[] = {
	{
		.iface = SNDRV_CTL_ELEM_IFACE_MIXER,
		.name = "SPK_PA rivision",
		.info = tfa98xx_info_rivision_ctl,
		.get = tfa98xx_get_rivision_ctl,
		.put = tfa98xx_set_rivision_ctl,
	},
};
static ssize_t tfa98xx_state_store(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count)
{
    pr_err("%s",__func__);

	return 0;
}
static ssize_t tfa98xx_state_show(struct device *dev, struct device_attribute *attr,
		char *buf)
{
    struct snd_soc_codec *codec;
    struct tfa98xx *tfa98xx;
    char *str;
	uint16_t status;
	int ret, calibrate_done;
/*wangdongdong@MultiMediaService,2016/11/30,add for speaker impedence detection*/
	unsigned int speakerImpedance1 = 0;
    if(g_tfa98xx == NULL)
    {
        pr_err("%s g_tfa98xx = NULL\n",__func__);
        return 0;
    }

    tfa98xx = g_tfa98xx;
    codec = tfa98xx->codec;

	mutex_lock(&tfa98xx->dsp_lock);
	ret = tfa98xx_open(tfa98xx->handle);
	if (ret) {
		mutex_unlock(&tfa98xx->dsp_lock);
		return -EBUSY;
	}

	/* Need to ensure DSP is access-able, use mtp read access for this
	 * purpose
	 */
	ret = tfa98xx_get_mtp(tfa98xx->handle, &status);
	if (ret) {
		ret = -EIO;
		goto r_c_err;
	}

	ret = tfaRunWaitCalibration(tfa98xx->handle, &calibrate_done);
	if (ret) {
		ret = -EIO;
		goto r_c_err;
	}

	str = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!str) {
		ret = -ENOMEM;
		goto r_c_err;
	}

	switch (calibrate_done) {
	case 1:
		/* calibration complete ! */
        tfa98xx_speaker_recalibration(tfa98xx->handle,&speakerImpedance1);
        pr_err("tfa speaker calibration impedance = %d\n",speakerImpedance1);
		ret = print_calibration_modify(tfa98xx->handle, str, PAGE_SIZE);

		break;
	case 0:
	case -1:
		ret = scnprintf(str, PAGE_SIZE, "%d\n", calibrate_done);
		break;
	default:
		pr_err("Unknown calibration status: %d\n", calibrate_done);
		ret = -EINVAL;
	}
	pr_err("calib_done: %d - ret = %d - %s", calibrate_done, ret, str);

	if (ret < 0)
		goto r_err;
    //modify for EngineerMode detection, different from 15801
    if(calibrate_done == 1)
		calibrate_done = 2;
	//ret = simple_read_from_buffer(buf, count, ppos, str, ret);
	ret = sprintf(buf,"%d:%d",calibrate_done,speakerImpedance1);

r_err:
	kfree(str);
r_c_err:
	tfa98xx_close(tfa98xx->handle);
	mutex_unlock(&tfa98xx->dsp_lock);
	return ret;
}

static struct device_attribute tfa98xx_state_attr =
     __ATTR(calibra, 0444, tfa98xx_state_show, tfa98xx_state_store);

/*zhiguang.su@MultiMedia.AudioDrv, 2015-11-05, add for debug*/
static ssize_t tfa98xx_Log_state_store(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count)
{
    pr_err("%s",__func__);

    if (sysfs_streq(buf, "LogOn"))
    {
        testLogOn = 1;
    }
    else if(sysfs_streq(buf, "LogOff"))
    {
        testLogOn = 0;
    }
    else
    {
        testLogOn = 0;
        count = -EINVAL;
    }
    return count;
}

static ssize_t tfa98xx_Log_state_show(struct device *dev, struct device_attribute *attr,
		char *buf)
{
    return 0;
}

static struct device_attribute tfa98xx_Log_state_attr =
     __ATTR(Log, S_IWUSR|S_IRUGO, tfa98xx_Log_state_show, tfa98xx_Log_state_store);


/* Wrapper for tfa start */
static enum tfa_error tfa98xx_tfa_start(struct tfa98xx *tfa98xx, int next_profile, int *vstep)
{
	enum tfa_error err;

	err = tfa_start(next_profile, vstep);

	/* Check and update tap-detection state (in case of profile change) */
	tfa98xx_tapdet_check_update(tfa98xx);

	/* A cold start erases the configuration, including interrupts setting.
	 * Restore it if required
	 */
	tfa98xx_interrupt_restore(tfa98xx);

	return err;
}

static int tfa98xx_input_open(struct input_dev *dev)
{
	struct tfa98xx *tfa98xx = input_get_drvdata(dev);
	dev_dbg(tfa98xx->codec->dev, "opening device file\n");

	/* note: open function is called only once by the framework.
	 * No need to count number of open file instances.
	 */
	if (tfa98xx->dsp_fw_state != TFA98XX_DSP_FW_OK) {
		dev_dbg(&tfa98xx->i2c->dev,
			"DSP not loaded, cannot start tap-detection\n");
		return -EIO;
	}

	/* enable tap-detection service */
	tfa98xx->tapdet_open = true;
	tfa98xx_tapdet_check_update(tfa98xx);

        return 0;
}

static void tfa98xx_input_close(struct input_dev *dev)
{
	struct tfa98xx *tfa98xx = input_get_drvdata(dev);

	dev_dbg(tfa98xx->codec->dev, "closing device file\n");

	/* Note: close function is called if the device is unregistered */

	/* disable tap-detection service */
	tfa98xx->tapdet_open = false;
	tfa98xx_tapdet_check_update(tfa98xx);
}

static int tfa98xx_register_inputdev(struct tfa98xx *tfa98xx)
{
	int err;
	struct input_dev *input;
	input = input_allocate_device();

	if (!input) {
		dev_err(tfa98xx->codec->dev, "Unable to allocate input device\n");
		return -ENOMEM;
	}

	input->evbit[0] = BIT_MASK(EV_KEY);
	input->keybit[BIT_WORD(BTN_0)] |= BIT_MASK(BTN_0);
	input->keybit[BIT_WORD(BTN_1)] |= BIT_MASK(BTN_1);
	input->keybit[BIT_WORD(BTN_2)] |= BIT_MASK(BTN_2);
	input->keybit[BIT_WORD(BTN_3)] |= BIT_MASK(BTN_3);
	input->keybit[BIT_WORD(BTN_4)] |= BIT_MASK(BTN_4);
	input->keybit[BIT_WORD(BTN_5)] |= BIT_MASK(BTN_5);
	input->keybit[BIT_WORD(BTN_6)] |= BIT_MASK(BTN_6);
	input->keybit[BIT_WORD(BTN_7)] |= BIT_MASK(BTN_7);
	input->keybit[BIT_WORD(BTN_8)] |= BIT_MASK(BTN_8);
	input->keybit[BIT_WORD(BTN_9)] |= BIT_MASK(BTN_9);

	input->open = tfa98xx_input_open;
	input->close = tfa98xx_input_close;

	input->name = "tfa98xx-tapdetect";

	input->id.bustype = BUS_I2C;
	input_set_drvdata(input, tfa98xx);

	err = input_register_device(input);
	if (err) {
		dev_err(tfa98xx->codec->dev, "Unable to register input device\n");
		goto err_free_dev;
	}

	dev_dbg(tfa98xx->codec->dev, "Input device for tap-detection registered: %s\n",
		input->name);
	tfa98xx->input = input;
	return 0;

err_free_dev:
	input_free_device(input);
	return err;
}

/*
 * Check if an input device for tap-detection can and shall be registered.
 * Register it if appropriate.
 * If already registered, check if still relevant and remove it if necessary.
 * unregister: true to request inputdev unregistration.
 */
static void __tfa98xx_inputdev_check_register(struct tfa98xx *tfa98xx, bool unregister)
{
	bool tap_profile = false;
	unsigned int i;
	for (i = 0; i < tfaContMaxProfile(tfa98xx->handle); i++) {
		if (strstr(tfaContProfileName(tfa98xx->handle, i), ".tap")) {
			tap_profile = true;
			tfa98xx->tapdet_profiles |= 1 << i;
			dev_info(tfa98xx->codec->dev,
				"found a tap-detection profile (%d - %s)\n",
				i, tfaContProfileName(tfa98xx->handle, i));
		}
	}

	/* Check for device support:
	 *  - at device level
	 *  - at container (profile) level
	 */
	if (!(tfa98xx->flags & TFA98XX_FLAG_TAPDET_AVAILABLE) ||
		!tap_profile ||
		unregister) {
		/* No input device supported or required */
		if (tfa98xx->input) {
			input_unregister_device(tfa98xx->input);
			tfa98xx->input = NULL;
		}
		return;
	}

	/* input device required */
	if (tfa98xx->input)
		dev_info(tfa98xx->codec->dev, "Input device already registered, skipping\n");
	else
		tfa98xx_register_inputdev(tfa98xx);
}

static void tfa98xx_inputdev_check_register(struct tfa98xx *tfa98xx)
{
	__tfa98xx_inputdev_check_register(tfa98xx, false);
}

static void tfa98xx_inputdev_unregister(struct tfa98xx *tfa98xx)
{
	__tfa98xx_inputdev_check_register(tfa98xx, true);
}

#ifdef CONFIG_DEBUG_FS
/* OTC reporting
 * Returns the MTP0 OTC bit value
 */
static int tfa98xx_dbgfs_otc_get(void *data, u64 *val)
{
	struct i2c_client *i2c = (struct i2c_client *)data;
	struct tfa98xx *tfa98xx = i2c_get_clientdata(i2c);
	struct tfa98xx_control *otc = &(handles_local[tfa98xx->handle].dev_ops.controls.otc);
	enum Tfa98xx_Error err, status;
	unsigned short value;

	mutex_lock(&tfa98xx->dsp_lock);
	status = tfa98xx_open(tfa98xx->handle);
	if (status) {
		mutex_unlock(&tfa98xx->dsp_lock);
		return -EBUSY;
	}

	err = tfa98xx_get_mtp(tfa98xx->handle, &value);
	tfa98xx_close(tfa98xx->handle);
	mutex_unlock(&tfa98xx->dsp_lock);

	if (otc->deferrable) {
		if (err != Tfa98xx_Error_Ok && err != Tfa98xx_Error_NoClock) {
			pr_err("Unable to check DSP access: %d\n", err);
			return -EIO;
		} else if (err == Tfa98xx_Error_NoClock) {
			if (otc->rd_valid) {
				/* read cached value */
				*val = otc->rd_value;
				pr_err("Returning cached value of OTC: %llu\n", *val);
			} else {
				pr_info("OTC value never read!\n");
				return -EIO;
			}
			return 0;
		}
	}

	*val = (value & TFA98XX_KEY2_PROTECTED_MTP0_MTPOTC_MSK)
			 >> TFA98XX_KEY2_PROTECTED_MTP0_MTPOTC_POS;
	pr_err("OTC : %d\n", value&1);

	if (otc->deferrable) {
		otc->rd_value = *val;
		otc->rd_valid = true;
	}

	return 0;
}

static int tfa98xx_dbgfs_otc_set(void *data, u64 val)
{
	struct i2c_client *i2c = (struct i2c_client *)data;
	struct tfa98xx *tfa98xx = i2c_get_clientdata(i2c);
	struct tfa98xx_control *otc = &(handles_local[tfa98xx->handle].dev_ops.controls.otc);
	enum Tfa98xx_Error err, status;

	if (val != 0 && val != 1) {
		pr_err("Unexpected value %llu\n\n", val);
		return -EINVAL;
	}
	mutex_lock(&tfa98xx->dsp_lock);
	status = tfa98xx_open(tfa98xx->handle);
	if (status) {
		mutex_unlock(&tfa98xx->dsp_lock);
		return -EBUSY;
	}
	err = tfa98xx_set_mtp(tfa98xx->handle,
			(val << TFA98XX_KEY2_PROTECTED_MTP0_MTPOTC_POS)
			& TFA98XX_KEY2_PROTECTED_MTP0_MTPOTC_MSK,
			TFA98XX_KEY2_PROTECTED_MTP0_MTPOTC_MSK);
	tfa98xx_close(tfa98xx->handle);
	mutex_unlock(&tfa98xx->dsp_lock);

	if (otc->deferrable) {
		if (err != Tfa98xx_Error_Ok && err != Tfa98xx_Error_NoClock) {
			pr_err("Unable to check DSP access: %d\n", err);
			return -EIO;
		} else if (err == Tfa98xx_Error_NoClock) {
			/* defer OTC */
			otc->wr_value = val;
			otc->triggered = true;
			pr_err("Deferring write to OTC (%d)\n", otc->wr_value);
			return 0;
		}
	}

	/* deferrable: cache the value for subsequent offline read */
	if (otc->deferrable) {
		otc->rd_value = val;
		otc->rd_valid = true;
	}

	pr_err("otc < %llu\n", val);

	return 0;
}

static int tfa98xx_dbgfs_mtpex_get(void *data, u64 *val)
{
	struct i2c_client *i2c = (struct i2c_client *)data;
	struct tfa98xx *tfa98xx = i2c_get_clientdata(i2c);
	enum Tfa98xx_Error err, status;
	unsigned short value;

	mutex_lock(&tfa98xx->dsp_lock);
	status = tfa98xx_open(tfa98xx->handle);
	if (status) {
		mutex_unlock(&tfa98xx->dsp_lock);
		return -EBUSY;
	}
	err = tfa98xx_get_mtp(tfa98xx->handle, &value);
	tfa98xx_close(tfa98xx->handle);
	mutex_unlock(&tfa98xx->dsp_lock);

	if (err != Tfa98xx_Error_Ok) {
		pr_err("Unable to check DSP access: %d\n", err);
		return -EIO;
	}

	*val = (value & TFA98XX_KEY2_PROTECTED_MTP0_MTPEX_MSK)
				>> TFA98XX_KEY2_PROTECTED_MTP0_MTPEX_POS;
	pr_err("MTPEX : %d\n", value & 2 >> 1);

	return 0;
}

static int tfa98xx_dbgfs_mtpex_set(void *data, u64 val)
{
	struct i2c_client *i2c = (struct i2c_client *)data;
	struct tfa98xx *tfa98xx = i2c_get_clientdata(i2c);
	struct tfa98xx_control *mtpex = &(handles_local[tfa98xx->handle].dev_ops.controls.mtpex);
	enum Tfa98xx_Error err, status;

	if (val != 0) {
		pr_err("Can only clear MTPEX (0 value expected)\n");
		return -EINVAL;
	}

	mutex_lock(&tfa98xx->dsp_lock);
	status = tfa98xx_open(tfa98xx->handle);
	if (status) {
		mutex_unlock(&tfa98xx->dsp_lock);
		return -EBUSY;
	}
	err = tfa98xx_set_mtp(tfa98xx->handle, 0,
					TFA98XX_KEY2_PROTECTED_MTP0_MTPEX_MSK);
	tfa98xx_close(tfa98xx->handle);
	mutex_unlock(&tfa98xx->dsp_lock);

	if (mtpex->deferrable) {
		if (err != Tfa98xx_Error_Ok && err != Tfa98xx_Error_NoClock) {
			pr_err("Unable to check DSP access: %d\n", err);
			return -EIO;
		} else if (err == Tfa98xx_Error_NoClock) {
			/* defer OTC */
			mtpex->wr_value = 0;
			mtpex->triggered = true;
			pr_err("Deferring write to MTPEX (%d)\n", mtpex->wr_value);
			return 0;
		}
	}

	pr_err("mtpex < 0\n");

	return 0;
}

static int tfa98xx_dbgfs_temp_get(void *data, u64 *val)
{
	struct i2c_client *i2c = (struct i2c_client *)data;
	struct tfa98xx *tfa98xx = i2c_get_clientdata(i2c);
	enum Tfa98xx_Error status;

	mutex_lock(&tfa98xx->dsp_lock);
	status = tfa98xx_open(tfa98xx->handle);
	if (status) {
		mutex_unlock(&tfa98xx->dsp_lock);
		return -EBUSY;
	}
	*val = tfa98xx_get_exttemp(tfa98xx->handle);
	tfa98xx_close(tfa98xx->handle);
	mutex_unlock(&tfa98xx->dsp_lock);

	return 0;
}

static int tfa98xx_dbgfs_temp_set(void *data, u64 val)
{
	struct i2c_client *i2c = (struct i2c_client *)data;
	struct tfa98xx *tfa98xx = i2c_get_clientdata(i2c);
	enum Tfa98xx_Error status;

	mutex_lock(&tfa98xx->dsp_lock);
	status = tfa98xx_open(tfa98xx->handle);
	if (status) {
		mutex_unlock(&tfa98xx->dsp_lock);
		return -EBUSY;
	}
	tfa98xx_set_exttemp(tfa98xx->handle, (short)val);
	tfa98xx_close(tfa98xx->handle);
	mutex_unlock(&tfa98xx->dsp_lock);

	return 0;
}

/*
 * calibration:
 * write key phrase to the 'calibration' file to trigger a new calibration
 * read the calibration file once to get the calibration result
 */
/* tfa98xx_deferred_calibration_status - called from tfaRunWaitCalibration */
void tfa98xx_deferred_calibration_status(Tfa98xx_handle_t handle, int calibrateDone)
{
	struct tfa98xx *tfa98xx = tfa98xx_devices[handle];
	struct tfa98xx_control *calib = &(handles_local[handle].dev_ops.controls.calib);

	if (calib->wr_value) {
		/* a calibration was programmed from the calibration file
		 * interface
		 */
		switch (calibrateDone) {
		case 1:
			/* calibration complete ! */
			calib->wr_value = false; /* calibration over */
			calib->rd_valid = true;  /* result available */
			calib->rd_value = true;  /* result valid */
			tfa_dsp_get_calibration_impedance(tfa98xx->handle);
			wake_up_interruptible(&tfa98xx->wq);
			break;
		case 0:
			pr_info("Calibration not complete, still waiting...\n");
			break;
		case -1:
			pr_info("Calibration failed\n");
			calib->wr_value = false; /* calibration over */
			calib->rd_valid = true;  /* result available */
			calib->rd_value = false; /* result not valid */
			wake_up_interruptible(&tfa98xx->wq);
			break;
		default:
			pr_info("Unknown calibration status: %d\n",
							calibrateDone);
		}
	}
}

static ssize_t tfa98xx_dbgfs_start_get(struct file *file,
				     char __user *user_buf, size_t count,
				     loff_t *ppos)
{
	struct i2c_client *i2c = file->private_data;
	struct tfa98xx *tfa98xx = i2c_get_clientdata(i2c);
	struct tfa98xx_control *calib = &(handles_local[tfa98xx->handle].dev_ops.controls.calib);
	char *str;
	int ret;

	ret = wait_event_interruptible(tfa98xx->wq, calib->wr_value == false);

	if (ret == -ERESTARTSYS) {
		/* interrupted by signal */
		return ret;
	}

	if (!calib->rd_valid)
		/* no calibration result available - skip */
		return 0;

	if (calib->rd_value) {
		/* Calibration already complete, return result */
		str = kmalloc(PAGE_SIZE, GFP_KERNEL);
		if (!str)
			return -ENOMEM;
		ret = print_calibration(tfa98xx->handle, str, PAGE_SIZE);
		if (ret < 0) {
			kfree(str);
			return ret;
		}
		ret = simple_read_from_buffer(user_buf, count, ppos, str, ret);

		pr_err("%s", str);
		kfree(str);
		calib->rd_value = false;
	} else {
		/* Calibration failed, return the error code */
		const char estr[] = "-1\n";
		ret = copy_to_user(user_buf, estr, sizeof(estr));
		if (ret)
			return -EFAULT;
		ret =  sizeof(estr);
	}
	calib->rd_valid = false;
	return ret;
}

static ssize_t tfa98xx_dbgfs_start_set(struct file *file,
				     const char __user *user_buf,
				     size_t count, loff_t *ppos)
{
	struct i2c_client *i2c = file->private_data;
	struct tfa98xx *tfa98xx = i2c_get_clientdata(i2c);
	struct tfa98xx_control *calib = &(handles_local[tfa98xx->handle].dev_ops.controls.calib);
	enum Tfa98xx_Error ret;
	char buf[32];
	const char ref[] = "please calibrate now";
	int buf_size;

	/* check string length, and account for eol */
	if (count > sizeof(ref) + 1 || count < (sizeof(ref) - 1))
		return -EINVAL;

	buf_size = min(count, (size_t)(sizeof(buf)-1));
	if (copy_from_user(buf, user_buf, buf_size))
		return -EFAULT;
	buf[buf_size] = 0;

	/* Compare string, excluding the trailing \0 and the potentials eol */
	if (strncmp(buf, ref, sizeof(ref) - 1))
		return -EINVAL;

	/* Do not open/close tfa98xx: not required by tfa_clibrate */
	mutex_lock(&tfa98xx->dsp_lock);
	ret = tfa_calibrate(tfa98xx->handle);
	mutex_unlock(&tfa98xx->dsp_lock);

	if(ret) {
		pr_info("Calibration start failed (%d), deferring...\n", ret);
		calib->triggered = true;
	} else {
		pr_info("Calibration started\n");
	}
	calib->wr_value = true;  /* request was triggered from here */
	calib->rd_valid = false; /* result not available */
	calib->rd_value = false; /* result not valid (dafault) */

	return count;
}

static ssize_t tfa98xx_dbgfs_r_read(struct file *file,
				     char __user *user_buf, size_t count,
				     loff_t *ppos)
{
	struct i2c_client *i2c = file->private_data;
	struct tfa98xx *tfa98xx = i2c_get_clientdata(i2c);
	char *str;
	uint16_t status;
	int ret, calibrate_done;
/*wangdongdong@MultiMediaService,2016/11/30,add for speaker impedence detection*/
	unsigned int speakerImpedance1 = 0;

	mutex_lock(&tfa98xx->dsp_lock);
	ret = tfa98xx_open(tfa98xx->handle);
	if (ret) {
		mutex_unlock(&tfa98xx->dsp_lock);
		return -EBUSY;
	}

	/* Need to ensure DSP is access-able, use mtp read access for this
	 * purpose
	 */
	ret = tfa98xx_get_mtp(tfa98xx->handle, &status);
	if (ret) {
		ret = -EIO;
		goto r_c_err;
	}

	ret = tfaRunWaitCalibration(tfa98xx->handle, &calibrate_done);
	if (ret) {
		ret = -EIO;
		goto r_c_err;
	}

	str = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!str) {
		ret = -ENOMEM;
		goto r_c_err;
	}

	switch (calibrate_done) {
	case 1:
		/* calibration complete ! */
        tfa98xx_speaker_recalibration(tfa98xx->handle,&speakerImpedance1);
        pr_err("tfa speaker calibration impedance = %d\n",speakerImpedance1);
		ret = print_calibration_modify(tfa98xx->handle, str, PAGE_SIZE);

		break;
	case 0:
	case -1:
		ret = scnprintf(str, PAGE_SIZE, "%d\n", calibrate_done);
		break;
	default:
		pr_err("Unknown calibration status: %d\n", calibrate_done);
		ret = -EINVAL;
	}
	pr_err("calib_done: %d - ret = %d - %s", calibrate_done, ret, str);

	if (ret < 0)
		goto r_err;

	ret = simple_read_from_buffer(user_buf, count, ppos, str, ret);

r_err:
	kfree(str);
r_c_err:
	tfa98xx_close(tfa98xx->handle);
	mutex_unlock(&tfa98xx->dsp_lock);
	return ret;
}

static ssize_t tfa98xx_dbgfs_version_read(struct file *file,
				     char __user *user_buf, size_t count,
				     loff_t *ppos)
{
	char str[] = TFA98XX_VERSION "\n";
	int ret;

	ret = simple_read_from_buffer(user_buf, count, ppos, str, sizeof(str));

	return ret;
}

static ssize_t tfa98xx_dbgfs_dsp_state_get(struct file *file,
				     char __user *user_buf, size_t count,
				     loff_t *ppos)
{
	struct i2c_client *i2c = file->private_data;
	struct tfa98xx *tfa98xx = i2c_get_clientdata(i2c);
	int ret = 0;
	char *str;

	switch (tfa98xx->dsp_init) {
	case TFA98XX_DSP_INIT_STOPPED:
		str = "Stopped\n";
		break;
	case TFA98XX_DSP_INIT_RECOVER:
		str = "Recover requested\n";
		break;
	case TFA98XX_DSP_INIT_FAIL:
		str = "Failed init\n";
		break;
	case TFA98XX_DSP_INIT_PENDING:
		str =  "Pending init\n";
		break;
	case TFA98XX_DSP_INIT_DONE:
		str = "Init complete\n";
		break;
	default:
		str = "Invalid\n";
	}
	ret = simple_read_from_buffer(user_buf, count, ppos, str, strlen(str));
	return ret;
}

static ssize_t tfa98xx_dbgfs_dsp_state_set(struct file *file,
				     const char __user *user_buf,
				     size_t count, loff_t *ppos)
{
	struct i2c_client *i2c = file->private_data;
	struct tfa98xx *tfa98xx = i2c_get_clientdata(i2c);
	enum tfa_error ret;
	char buf[32];
	const char start_cmd[] = "start";
	const char stop_cmd[] = "stop";
	const char mon_start_cmd[] = "monitor start";
	const char mon_stop_cmd[] = "monitor stop";
	int buf_size;

	buf_size = min(count, (size_t)(sizeof(buf)-1));
	if (copy_from_user(buf, user_buf, buf_size))
		return -EFAULT;
	buf[buf_size] = 0;

	/* Compare strings, excluding the trailing \0 */
	if (!strncmp(buf, start_cmd, sizeof(start_cmd) - 1)) {
		pr_info("Manual triggering of dsp start...\n");
		mutex_lock(&tfa98xx->dsp_lock);
		ret = tfa98xx_tfa_start(tfa98xx, tfa98xx_profile, tfa98xx_vsteps);
		mutex_unlock(&tfa98xx->dsp_lock);
		pr_err("tfa_start complete: %d\n", ret);
	} else if (!strncmp(buf, stop_cmd, sizeof(stop_cmd) - 1)) {
		pr_info("Manual triggering of dsp stop...\n");
		mutex_lock(&tfa98xx->dsp_lock);
		ret = tfa_stop();
		mutex_unlock(&tfa98xx->dsp_lock);
		pr_err("tfa_stop complete: %d\n", ret);
	} else if (!strncmp(buf, mon_start_cmd, sizeof(mon_start_cmd) - 1)) {
		pr_info("Manual start of monitor thread...\n");
	} else if (!strncmp(buf, mon_stop_cmd, sizeof(mon_stop_cmd) - 1)) {
		pr_info("Manual stop of monitor thread...\n");
	} else {
		return -EINVAL;
	}

	return count;
}

static ssize_t tfa98xx_dbgfs_accounting_get(struct file *file,
				     char __user *user_buf, size_t count,
				     loff_t *ppos)
{
	struct i2c_client *i2c = file->private_data;
	struct tfa98xx *tfa98xx = i2c_get_clientdata(i2c);
	char str[255];
	int ret;
	int n = 0;

	n += snprintf(&str[n], sizeof(str)-1-n, "Wait4Src\t= %d\n",  tfa98xx->count_wait_for_source_state);
	n += snprintf(&str[n], sizeof(str)-1-n, "NOCLK\t\t= %d\n",  tfa98xx->count_noclk);

	str[n+1] = '\0'; /* in case str is not large enough */

	ret = simple_read_from_buffer(user_buf, count, ppos, str, n+1);

	return ret;
}

static int tfa98xx_dbgfs_pga_gain_get(void *data, u64 *val)
{
	struct i2c_client *i2c = (struct i2c_client *)data;
	struct tfa98xx *tfa98xx = i2c_get_clientdata(i2c);
	int err;
	unsigned int value;

/*	*val = TFA_GET_BF(tfa98xx->handle, SAAMGAIN);*/
	err = regmap_read(tfa98xx->regmap, TFA98XX_CTRL_SAAM_PGA, &value);
	*val = (value & TFA98XX_CTRL_SAAM_PGA_SAAMGAIN_MSK) >>
				TFA98XX_CTRL_SAAM_PGA_SAAMGAIN_POS;
	return 0;
}

static int tfa98xx_dbgfs_pga_gain_set(void *data, u64 val)
{
	struct i2c_client *i2c = (struct i2c_client *)data;
	struct tfa98xx *tfa98xx = i2c_get_clientdata(i2c);
	int err;
	unsigned int value;

	value = val & 0xffff;
	if (value > 7)
		return -EINVAL;
/*	TFA_SET_BF(tfa98xx->handle, SAAMGAIN, value);*/
	err = regmap_update_bits(tfa98xx->regmap, TFA98XX_CTRL_SAAM_PGA,
				TFA98XX_CTRL_SAAM_PGA_SAAMGAIN_MSK,
				value << TFA98XX_CTRL_SAAM_PGA_SAAMGAIN_POS);
	return err;
}

/* Direct registers access - provide register address in hex */
#define TFA98XX_DEBUGFS_REG_SET(__reg)					\
static int tfa98xx_dbgfs_reg_##__reg##_set(void *data, u64 val)		\
{									\
	struct i2c_client *i2c = (struct i2c_client *)data;		\
	struct tfa98xx *tfa98xx = i2c_get_clientdata(i2c);		\
	unsigned int ret, value;					\
									\
	ret = regmap_write(tfa98xx->regmap, 0x##__reg, (val & 0xffff));	\
	value = val & 0xffff;						\
	return 0;							\
}									\
static int tfa98xx_dbgfs_reg_##__reg##_get(void *data, u64 *val)	\
{									\
	struct i2c_client *i2c = (struct i2c_client *)data;		\
	struct tfa98xx *tfa98xx = i2c_get_clientdata(i2c);		\
	unsigned int value;						\
	int ret;							\
	ret = regmap_read(tfa98xx->regmap, 0x##__reg, &value);		\
	*val = value;							\
	return 0;							\
}									\
DEFINE_SIMPLE_ATTRIBUTE(tfa98xx_dbgfs_reg_##__reg##_fops, tfa98xx_dbgfs_reg_##__reg##_get,	\
						tfa98xx_dbgfs_reg_##__reg##_set, "0x%llx\n");

#define VAL(str) #str
#define TOSTRING(str) VAL(str)
#define TFA98XX_DEBUGFS_REG_CREATE_FILE(__reg, __name)				\
	debugfs_create_file(TOSTRING(__reg) "-" TOSTRING(__name), S_IRUGO|S_IWUGO, dbg_reg_dir,\
					i2c, &tfa98xx_dbgfs_reg_##__reg##_fops);


TFA98XX_DEBUGFS_REG_SET(00);
TFA98XX_DEBUGFS_REG_SET(01);
TFA98XX_DEBUGFS_REG_SET(02);
TFA98XX_DEBUGFS_REG_SET(03);
TFA98XX_DEBUGFS_REG_SET(04);
TFA98XX_DEBUGFS_REG_SET(05);
TFA98XX_DEBUGFS_REG_SET(06);
TFA98XX_DEBUGFS_REG_SET(07);
TFA98XX_DEBUGFS_REG_SET(08);
TFA98XX_DEBUGFS_REG_SET(09);
TFA98XX_DEBUGFS_REG_SET(0A);
TFA98XX_DEBUGFS_REG_SET(0B);
TFA98XX_DEBUGFS_REG_SET(0F);
TFA98XX_DEBUGFS_REG_SET(10);
TFA98XX_DEBUGFS_REG_SET(11);
TFA98XX_DEBUGFS_REG_SET(12);
TFA98XX_DEBUGFS_REG_SET(13);
TFA98XX_DEBUGFS_REG_SET(22);
TFA98XX_DEBUGFS_REG_SET(25);

DEFINE_SIMPLE_ATTRIBUTE(tfa98xx_dbgfs_calib_otc_fops, tfa98xx_dbgfs_otc_get,
						tfa98xx_dbgfs_otc_set, "%llu\n");
DEFINE_SIMPLE_ATTRIBUTE(tfa98xx_dbgfs_calib_mtpex_fops, tfa98xx_dbgfs_mtpex_get,
						tfa98xx_dbgfs_mtpex_set, "%llu\n");
DEFINE_SIMPLE_ATTRIBUTE(tfa98xx_dbgfs_calib_temp_fops, tfa98xx_dbgfs_temp_get,
						tfa98xx_dbgfs_temp_set, "%llu\n");

DEFINE_SIMPLE_ATTRIBUTE(tfa98xx_dbgfs_pga_gain_fops, tfa98xx_dbgfs_pga_gain_get,
						tfa98xx_dbgfs_pga_gain_set, "%llu\n");

static const struct file_operations tfa98xx_dbgfs_calib_start_fops = {
	.open = simple_open,
	.read = tfa98xx_dbgfs_start_get,
	.write = tfa98xx_dbgfs_start_set,
	.llseek = default_llseek,
};

static const struct file_operations tfa98xx_dbgfs_r_fops = {
	.open = simple_open,
	.read = tfa98xx_dbgfs_r_read,
	.llseek = default_llseek,
};

static const struct file_operations tfa98xx_dbgfs_version_fops = {
	.open = simple_open,
	.read = tfa98xx_dbgfs_version_read,
	.llseek = default_llseek,
};

static const struct file_operations tfa98xx_dbgfs_dsp_state_fops = {
	.open = simple_open,
	.read = tfa98xx_dbgfs_dsp_state_get,
	.write = tfa98xx_dbgfs_dsp_state_set,
	.llseek = default_llseek,
};

static const struct file_operations tfa98xx_dbgfs_accounting_fops = {
	.open = simple_open,
	.read = tfa98xx_dbgfs_accounting_get,
	.llseek = default_llseek,
};


static void tfa98xx_debug_init(struct tfa98xx *tfa98xx, struct i2c_client *i2c)
{
	char name[50];
	struct dentry *dbg_reg_dir;

	scnprintf(name, MAX_CONTROL_NAME, "%s-%x", i2c->name, i2c->addr);
	tfa98xx->dbg_dir = debugfs_create_dir(name, NULL);
	debugfs_create_file("OTC", S_IRUGO|S_IWUGO, tfa98xx->dbg_dir,
						i2c, &tfa98xx_dbgfs_calib_otc_fops);
	debugfs_create_file("MTPEX", S_IRUGO|S_IWUGO, tfa98xx->dbg_dir,
						i2c, &tfa98xx_dbgfs_calib_mtpex_fops);
	debugfs_create_file("TEMP", S_IRUGO|S_IWUGO, tfa98xx->dbg_dir,
						i2c, &tfa98xx_dbgfs_calib_temp_fops);
	debugfs_create_file("calibrate", S_IRUGO|S_IWUGO, tfa98xx->dbg_dir,
						i2c, &tfa98xx_dbgfs_calib_start_fops);
	debugfs_create_file("R", S_IRUGO, tfa98xx->dbg_dir,
						i2c, &tfa98xx_dbgfs_r_fops);
	debugfs_create_file("version", S_IRUGO, tfa98xx->dbg_dir,
						i2c, &tfa98xx_dbgfs_version_fops);
	debugfs_create_file("dsp-state", S_IRUGO|S_IWUGO, tfa98xx->dbg_dir,
						i2c, &tfa98xx_dbgfs_dsp_state_fops);
	debugfs_create_file("accounting", S_IRUGO, tfa98xx->dbg_dir,
						i2c, &tfa98xx_dbgfs_accounting_fops);

	/* Direct registers access */
	if (tfa98xx->flags & TFA98XX_FLAG_TFA9890_FAM_DEV) {
		dbg_reg_dir = debugfs_create_dir("regs", tfa98xx->dbg_dir);
		TFA98XX_DEBUGFS_REG_CREATE_FILE(00, STATUS);
		TFA98XX_DEBUGFS_REG_CREATE_FILE(01, BATTERYVOLTAGE);
		TFA98XX_DEBUGFS_REG_CREATE_FILE(02, TEMPERATURE);
		TFA98XX_DEBUGFS_REG_CREATE_FILE(03, REVISIONNUMBER);
		TFA98XX_DEBUGFS_REG_CREATE_FILE(04, I2SREG);
		TFA98XX_DEBUGFS_REG_CREATE_FILE(05, BAT_PROT);
		TFA98XX_DEBUGFS_REG_CREATE_FILE(06, AUDIO_CTR);
		TFA98XX_DEBUGFS_REG_CREATE_FILE(07, DCDCBOOST);
		TFA98XX_DEBUGFS_REG_CREATE_FILE(08, SPKR_CALIBRATION);
		TFA98XX_DEBUGFS_REG_CREATE_FILE(09, SYS_CTRL);
		TFA98XX_DEBUGFS_REG_CREATE_FILE(0A, I2S_SEL_REG);
		TFA98XX_DEBUGFS_REG_CREATE_FILE(0B, HIDDEN_MTP_KEY2);
		TFA98XX_DEBUGFS_REG_CREATE_FILE(0F, INTERRUPT_REG);
		TFA98XX_DEBUGFS_REG_CREATE_FILE(10, PDM_CTRL);
		TFA98XX_DEBUGFS_REG_CREATE_FILE(11, PDM_OUT_CTRL);
		TFA98XX_DEBUGFS_REG_CREATE_FILE(12, PDM_DS4_R);
		TFA98XX_DEBUGFS_REG_CREATE_FILE(13, PDM_DS4_L);
		TFA98XX_DEBUGFS_REG_CREATE_FILE(22, CTRL_SAAM_PGA);
		TFA98XX_DEBUGFS_REG_CREATE_FILE(25, MISC_CTRL);
	}

	if (tfa98xx->flags & TFA98XX_FLAG_TFA9897_FAM_DEV) {
		dbg_reg_dir = debugfs_create_dir("regs", tfa98xx->dbg_dir);
		TFA98XX_DEBUGFS_REG_CREATE_FILE(00, STATUS);
		TFA98XX_DEBUGFS_REG_CREATE_FILE(01, BATTERYVOLTAGE);
		TFA98XX_DEBUGFS_REG_CREATE_FILE(02, TEMPERATURE);
		TFA98XX_DEBUGFS_REG_CREATE_FILE(03, REVISIONNUMBER);
		TFA98XX_DEBUGFS_REG_CREATE_FILE(04, I2SREG);
		TFA98XX_DEBUGFS_REG_CREATE_FILE(05, BAT_PROT);
		TFA98XX_DEBUGFS_REG_CREATE_FILE(06, AUDIO_CTR);
		TFA98XX_DEBUGFS_REG_CREATE_FILE(07, DCDCBOOST);
		TFA98XX_DEBUGFS_REG_CREATE_FILE(08, SPKR_CALIBRATION);
		TFA98XX_DEBUGFS_REG_CREATE_FILE(09, SYS_CTRL);
	}

	if (tfa98xx->flags & TFA98XX_FLAG_SAAM_AVAILABLE) {
		dev_dbg(tfa98xx->dev, "Adding pga_gain debug interface\n");
		debugfs_create_file("pga_gain", S_IRUGO, tfa98xx->dbg_dir,
						tfa98xx->i2c,
						&tfa98xx_dbgfs_pga_gain_fops);
	}
}

static void tfa98xx_debug_remove(struct tfa98xx *tfa98xx)
{
	if (tfa98xx->dbg_dir)
		debugfs_remove_recursive(tfa98xx->dbg_dir);
}
#endif
/*wangdongdong@MultiMediaService,2016/11/30,add for speaker impedence detection*/
static int tfa98xx_speaker_recalibration(Tfa98xx_handle_t handle,unsigned int *speakerImpedance)
{
	int err, error = Tfa98xx_Error_Ok;
 //   struct tfa98xx *tfa98xx = container_of(&handle, struct tfa98xx, handle);



	/* Do not open/close tfa98xx: not required by tfa_clibrate */
	error = tfa_calibrate(handle);
	/* powerdown CF */
//	error = tfa98xx_powerdown(handle, 1 );
	msleep_interruptible(25);
	error = tfaRunSpeakerBoost(handle, 1, 0); /* No force coldstart (with profile 0) */
	if(error) {
		pr_err("Calibration failed (error = %d)\n", error);
		*speakerImpedance = 0;
	} else {
		pr_err("Calibration sucessful! \n");
		*speakerImpedance = handles_local[handle].mohm[0];
		pr_err("Calibration  (*speakerImpedance= %d)\n", *speakerImpedance);
		if (TFA_GET_BF(handle, PWDN) != 0) {
			   err = tfa98xx_powerdown(handle, 0);  //leave power off state
		   }
		tfaRunUnmute(handle);	/* unmute */
	}

	return error;
}

static int tfa98xx_get_vstep(struct snd_kcontrol *kcontrol,
			     struct snd_ctl_elem_value *ucontrol)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)
	struct snd_soc_codec *codec = snd_kcontrol_chip(kcontrol);
#else
	struct snd_soc_codec *codec = snd_soc_kcontrol_codec(kcontrol);
#endif
	struct tfa98xx *tfa98xx = snd_soc_codec_get_drvdata(codec);
	int mixer_profile = kcontrol->private_value;
	int profile = get_profile_id_for_sr(mixer_profile, tfa98xx->rate);
	int vstep = tfa98xx_prof_vsteps[profile];
	ucontrol->value.integer.value[0] =
				tfacont_get_max_vstep(tfa98xx->handle, profile)
				- vstep - 1;
	return 0;
}

static int tfa98xx_set_vstep(struct snd_kcontrol *kcontrol,
			     struct snd_ctl_elem_value *ucontrol)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)
	struct snd_soc_codec *codec = snd_kcontrol_chip(kcontrol);
#else
	struct snd_soc_codec *codec = snd_soc_kcontrol_codec(kcontrol);
#endif
	struct tfa98xx *tfa98xx = snd_soc_codec_get_drvdata(codec);
	int mixer_profile = kcontrol->private_value;
	int profile = get_profile_id_for_sr(mixer_profile, tfa98xx->rate);
	int value = ucontrol->value.integer.value[0];
	int vstep = tfa98xx_prof_vsteps[profile];
	int vsteps = tfacont_get_max_vstep(tfa98xx->handle, profile);
	int new_vstep, err = 0;
	int ready = 0;
	unsigned int base_addr_inten = TFA_FAM(tfa98xx->handle,INTENVDDS) >> 8;

	if (no_start != 0)
		return 0;

	if (vstep == vsteps - value - 1)
		return 0;

	new_vstep = vsteps - value - 1;

	if (new_vstep < 0)
		new_vstep = 0;

	tfa98xx_prof_vsteps[profile] = new_vstep;

#ifndef TFA98XX_ALSA_CTRL_PROF_CHG_ON_VOL
	if (profile == tfa98xx_profile) {
#endif
		/* this is the active profile, program the new vstep */
		tfa98xx_vsteps[0] = new_vstep;
		tfa98xx_vsteps[1] = new_vstep;
		mutex_lock(&tfa98xx->dsp_lock);
		tfa98xx_open(tfa98xx->handle);
		tfa98xx_dsp_system_stable(tfa98xx->handle, &ready);
		tfa98xx_close(tfa98xx->handle);

		/* Enable internal clk (osc1m) to switch profile */
		if ((tfa98xx_dev_family(tfa98xx->handle) == 2) && (ready == 0)) {
			/* Disable interrupts (Enabled again in the wrapper function: tfa98xx_tfa_start) */
			regmap_write(tfa98xx->regmap, base_addr_inten + 1, 0);
			/* Set polarity to high */
			TFA_SET_BF(tfa98xx->handle, IPOMWSRC, 1);

			TFA_SET_BF(tfa98xx->handle, RST, 1);
			TFA_SET_BF(tfa98xx->handle, SBSL, 0);
			TFA_SET_BF(tfa98xx->handle, AMPC, 0);
			TFA_SET_BF(tfa98xx->handle, AMPE, 0);
			TFA_SET_BF(tfa98xx->handle, REFCKSEL, 1);
			ready = 1;
		}

		if (ready) {
			err = tfa98xx_tfa_start(tfa98xx, profile, tfa98xx_vsteps);
			if (err) {
				pr_err("Write vstep error: %d\n", err);
			} else {
				pr_err("Succesfully changed vstep index!\n");
			}
		}

		if (tfa98xx_dev_family(tfa98xx->handle) == 2) {
			/* Set back to external clock */
			TFA_SET_BF(tfa98xx->handle, REFCKSEL, 0);
			TFA_SET_BF(tfa98xx->handle, SBSL, 1);
		}

		mutex_unlock(&tfa98xx->dsp_lock);
#ifndef TFA98XX_ALSA_CTRL_PROF_CHG_ON_VOL
	}
#endif

	pr_err("vstep:%d, (control value: %d) - profile %d\n", new_vstep,
								 value, profile);
	return (err == 0);
}

static int tfa98xx_info_vstep(struct snd_kcontrol *kcontrol,
		       struct snd_ctl_elem_info *uinfo)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)
	struct snd_soc_codec *codec = snd_kcontrol_chip(kcontrol);
#else
	struct snd_soc_codec *codec = snd_soc_kcontrol_codec(kcontrol);
#endif
	struct tfa98xx *tfa98xx = snd_soc_codec_get_drvdata(codec);
	int mixer_profile = kcontrol->private_value;
	int profile = get_profile_id_for_sr(mixer_profile, tfa98xx->rate);

	uinfo->type = SNDRV_CTL_ELEM_TYPE_INTEGER;
	uinfo->count = 1;// TODO handles_local[dev_idx].spkr_count
	uinfo->value.integer.min = 0;
	uinfo->value.integer.max = tfacont_get_max_vstep(tfa98xx->handle, profile) - 1;
	pr_err("vsteps count: %d [prof=%d]\n", tfacont_get_max_vstep(tfa98xx->handle, profile),
			profile);
	return 0;
}

static int tfa98xx_get_profile(struct snd_kcontrol *kcontrol,
			       struct snd_ctl_elem_value *ucontrol)
{
    ucontrol->value.integer.value[0] = tfa98xx_mixer_profile;
	return 0;
}

static int tfa98xx_set_profile(struct snd_kcontrol *kcontrol,
			       struct snd_ctl_elem_value *ucontrol)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)
	struct snd_soc_codec *codec = snd_kcontrol_chip(kcontrol);
#else
	struct snd_soc_codec *codec = snd_soc_kcontrol_codec(kcontrol);
#endif
	struct tfa98xx *tfa98xx = snd_soc_codec_get_drvdata(codec);
	
	unsigned int base_addr_inten = TFA_FAM(tfa98xx->handle,INTENVDDS) >> 8;
	int profile_count = tfa98xx_mixer_profiles;
	int profile = tfa98xx_mixer_profile;
	int new_profile = ucontrol->value.integer.value[0];
	int err;
	int ready = 0;
	int prof_idx;


	if (no_start != 0)
		return 0;

	if (new_profile == profile)
		return 0;

	if (new_profile >= profile_count)
		return 0;
    
	/* get the container profile for the requested sample rate */
	prof_idx = get_profile_id_for_sr(new_profile, tfa98xx->rate);
	if (prof_idx < 0) {
		pr_err("tfa98xx: sample rate [%d] not supported for this mixer profile [%d].\n", tfa98xx->rate, new_profile);
		return 0;
	}
	pr_err("selected container profile [%d]\n", prof_idx);
    
	/* update mixer profile */
	tfa98xx_mixer_profile = new_profile;
    
	/* update 'real' profile (container profile) */
	tfa98xx_profile = prof_idx;
	tfa98xx_vsteps[0] = tfa98xx_prof_vsteps[prof_idx];
	tfa98xx_vsteps[1] = tfa98xx_prof_vsteps[prof_idx];

	/*
	 * Don't call tfa_start() on TFA1 if there is no clock.
	 * For TFA2 is able to load the profile without clock.
	 */
	
	mutex_lock(&tfa98xx->dsp_lock);
	tfa98xx_open(tfa98xx->handle);
	tfa98xx_dsp_system_stable(tfa98xx->handle, &ready);
	tfa98xx_close(tfa98xx->handle);
	
	/* Enable internal clk (osc1m) to switch profile */
	if (tfa98xx_dev_family(tfa98xx->handle) == 2 && ready == 0) {
		/* Disable interrupts (Enabled again in the wrapper function: tfa98xx_tfa_start) */
		regmap_write(tfa98xx->regmap, base_addr_inten + 1, 0);
		/* Set polarity to high */
		TFA_SET_BF(tfa98xx->handle, IPOMWSRC, 1);

		TFA_SET_BF(tfa98xx->handle, RST, 1);
		TFA_SET_BF_VOLATILE(tfa98xx->handle, SBSL, 0);
		TFA_SET_BF(tfa98xx->handle, AMPC, 0);
		TFA_SET_BF(tfa98xx->handle, AMPE, 0);
		TFA_SET_BF(tfa98xx->handle, REFCKSEL, 1);
		ready = 1;
	}

	if (ready) {
		/* Also re-enables the interrupts */
		err = tfa98xx_tfa_start(tfa98xx, prof_idx, tfa98xx_vsteps);
		if (err) {
			pr_info("Write profile error: %d\n", err);
		} else {
			pr_err("Changed to profile %d (vstep = %d)\n", prof_idx,
							tfa98xx_vsteps[0]);
		}
	}

	if (tfa98xx_dev_family(tfa98xx->handle) == 2) {
		/* Set back to external clock */
		TFA_SET_BF(tfa98xx->handle, REFCKSEL, 0);
		TFA_SET_BF_VOLATILE(tfa98xx->handle, SBSL, 1);
	}
	
	mutex_unlock(&tfa98xx->dsp_lock);

	/* Flag DSP as invalidated as the profile change may invalidate the
	 * current DSP configuration. That way, further stream start can
	 * trigger a tfa_start.
	 */
	tfa98xx->dsp_init = TFA98XX_DSP_INIT_INVALIDATED;

	return 1;
}

static struct snd_kcontrol_new *tfa98xx_controls;

/* copies the profile basename (i.e. part until .) into buf */
static void get_profile_basename(char* buf, char* profile) 
{
	int cp_len = 0, idx = 0;
	char *pch;
            
	pch = strchr(profile, '.');
	idx = pch - profile;
	cp_len = (pch != NULL) ? idx : (int) strlen(profile);
	memcpy(buf, profile, cp_len);
	buf[cp_len] = 0;
}

/* return the profile name accociated with id from the profile list */
static int get_profile_from_list(char *buf, int id)
{
	struct tfa98xx_baseprofile *bprof;

	list_for_each_entry(bprof, &profile_list, list) {
		if (bprof->item_id == id) {
			strcpy(buf, bprof->basename);
			return 0;
		}
	}

	return -1;
}

/* search for the profile in the profile list */
static int is_profile_in_list(char *profile, int len) 
{
	struct tfa98xx_baseprofile *bprof;

	list_for_each_entry(bprof, &profile_list, list) {
		if (0 == strncmp(bprof->basename, profile, len))
			return 1;
	}

    return 0;
}

/* 
 * for the profile with id, look if the requested samplerate is 
 * supported, if found return the (container)profile for this 
 * samplerate, on error or if not found return -1 
 */
static int get_profile_id_for_sr(int id, unsigned int rate) 
{
	int idx = 0;
	struct tfa98xx_baseprofile *bprof;

	list_for_each_entry(bprof, &profile_list, list) {
		if (id == bprof->item_id) {
			idx = tfa98xx_get_fssel(rate);
			if (idx < 0) {
				/* samplerate not supported */
				return -1;
			}

			return bprof->sr_rate_sup[idx];
		}
	}

	/* profile not found */
	return -1;
}

/* check if this profile is a calibration profile */
static int is_calibration_profile(char *profile)
{
	if (strstr(profile, ".cal") != NULL)
		return 1;
	return 0;
}

/* 
 * adds the (container)profile index of the samplerate found in
 * the (container)profile to a fixed samplerate table in the (mixer)profile
 */
static int add_sr_to_profile(struct tfa98xx *tfa98xx, char *basename, int len, int profile) 
{ 
	struct tfa98xx_baseprofile *bprof;
	int idx = 0;
	unsigned int sr = 0;

	list_for_each_entry(bprof, &profile_list, list) {
		if (0 == strncmp(bprof->basename, basename, len)) {
			/* add supported samplerate for this profile */
			sr = tfa98xx_get_profile_sr(tfa98xx->handle, profile);
			if (!sr) {
				pr_err("unable to identify supported sample rate for %s\n", bprof->basename);
				return -1;
			}

			/* get the index for this samplerate */
			idx = tfa98xx_get_fssel(sr);
			if (idx < 0 || idx >= TFA98XX_NUM_RATES) {
				pr_err("invalid index for samplerate %d\n", idx);
				return -1;
			}

			/* enter the (container)profile for this samplerate at the corresponding index */
			bprof->sr_rate_sup[idx] = profile;
            
			pr_err("added profile:samplerate = [%d:%d] for mixer profile: %s\n", profile, sr, bprof->basename);    
		}
	}

	return 0;
}

static int tfa98xx_info_profile(struct snd_kcontrol *kcontrol,
			 struct snd_ctl_elem_info *uinfo)
{
	char profile_name[MAX_CONTROL_NAME] = {0};
	int count = tfa98xx_mixer_profiles, err = -1;
       
	uinfo->type = SNDRV_CTL_ELEM_TYPE_ENUMERATED;
	uinfo->count = 1;
	uinfo->value.enumerated.items = count;

	if (uinfo->value.enumerated.item >= count)
		uinfo->value.enumerated.item = count - 1;
        
	err = get_profile_from_list(profile_name, uinfo->value.enumerated.item);
	if (err != 0)
		return -EINVAL;
    
	strcpy(uinfo->value.enumerated.name, profile_name);
 
	return 0;
}

static int tfa98xx_get_stop_ctl(struct snd_kcontrol *kcontrol,
			     struct snd_ctl_elem_value *ucontrol)
{
	ucontrol->value.integer.value[0] = 0;
	return 0;
}

static int tfa98xx_set_stop_ctl(struct snd_kcontrol *kcontrol,
			     struct snd_ctl_elem_value *ucontrol)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)
	struct snd_soc_codec *codec = snd_kcontrol_chip(kcontrol);
#else
	struct snd_soc_codec *codec = snd_soc_kcontrol_codec(kcontrol);
#endif
	struct tfa98xx *tfa98xx = snd_soc_codec_get_drvdata(codec);
	int ready = 0;

	pr_err("%ld\n", ucontrol->value.integer.value[0]);

	tfa98xx_open(tfa98xx->handle);
	tfa98xx_dsp_system_stable(tfa98xx->handle, &ready);
	tfa98xx_close(tfa98xx->handle);

	if ((ucontrol->value.integer.value[0] != 0) && ready) {
		cancel_delayed_work_sync(&tfa98xx->init_work);
		if (tfa98xx->dsp_fw_state != TFA98XX_DSP_FW_OK)
			return 0;
		mutex_lock(&tfa98xx->dsp_lock);
		tfa_stop();
		tfa98xx->dsp_init = TFA98XX_DSP_INIT_STOPPED;
		mutex_unlock(&tfa98xx->dsp_lock);
	}

	ucontrol->value.integer.value[0] = 0;
	return 1;
}

/*zhiguang.su@MultiMediaService,2017-04-26,add ftm spk pa rivision test*/
static int tfa98xx_info_rivision_ctl(struct snd_kcontrol *kcontrol,
				struct snd_ctl_elem_info *uinfo)
{
	pr_err("%s\n", __func__);
	uinfo->type = SNDRV_CTL_ELEM_TYPE_INTEGER;
	uinfo->count = 5;
	uinfo->value.integer.min = 0;
	uinfo->value.integer.max = 5;

	return 0;
}

static int tfa98xx_get_rivision_ctl(struct snd_kcontrol *kcontrol,
			     struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_codec *codec = snd_soc_kcontrol_codec(kcontrol);
	struct tfa98xx *tfa98xx = snd_soc_codec_get_drvdata(codec);
	int ret;
	unsigned int reg;

	pr_err("%s\n", __func__);
	ucontrol->value.integer.value[0] = 1;
	ret = regmap_read(tfa98xx->regmap, 0x03, &reg);
	if (ret < 0) {
		pr_err("%s Failed to read Revision register: %d\n",
			__func__, ret);
		ucontrol->value.integer.value[0] = 0;
	}

	return 0;
}

static int tfa98xx_set_rivision_ctl(struct snd_kcontrol *kcontrol,
			     struct snd_ctl_elem_value *ucontrol)
{
	pr_err("%s\n", __func__);
	ucontrol->value.integer.value[0] = 0;
	return 1;
}

static int tfa98xx_create_controls(struct tfa98xx *tfa98xx)
{
	int prof, nprof, mix_index = 0;
	int  nr_controls = 0, id = 0;
	char *name;
	struct tfa98xx_baseprofile *bprofile;

	/* Create the following controls:
	 *  - enum control to select the active profile
	 *  - one volume control for each profile hosting a vstep
	 *  - Stop control on TFA1 devices
	 */

	nr_controls = 1; 	 /* Profile control */
	if (tfa98xx_dev_family(tfa98xx->handle) == 1)
		nr_controls += 1; /* Stop control */

	/* allocate the tfa98xx_controls base on the nr of profiles */
	nprof = tfaContMaxProfile(tfa98xx->handle);

	for (prof = 0; prof < nprof; prof++) {
		if (tfacont_get_max_vstep(tfa98xx->handle, prof))
			nr_controls++; /* Playback Volume control */
	}
	tfa98xx_controls = devm_kzalloc(tfa98xx->codec->dev,
			nr_controls * sizeof(tfa98xx_controls[0]), GFP_KERNEL);
	if(!tfa98xx_controls)
		return -ENOMEM;

	/* Create a mixer item for selecting the active profile */
	name = devm_kzalloc(tfa98xx->codec->dev, MAX_CONTROL_NAME, GFP_KERNEL);
	if (!name)
		return -ENOMEM;
	scnprintf(name, MAX_CONTROL_NAME, "%s Profile", tfa98xx->fw.name);
    printk("tfa98xx_create_controls:name  = %s\n",name);
	tfa98xx_controls[mix_index].name = name;
	tfa98xx_controls[mix_index].iface = SNDRV_CTL_ELEM_IFACE_MIXER;
	tfa98xx_controls[mix_index].info = tfa98xx_info_profile;
	tfa98xx_controls[mix_index].get = tfa98xx_get_profile;
	tfa98xx_controls[mix_index].put = tfa98xx_set_profile;
	// tfa98xx_controls[mix_index].private_value = profs; /* save number of profiles */
	mix_index++;

	/* create mixer items for each profile that has volume */
	for (prof = 0; prof < nprof; prof++) {
		/* create an new empty profile */
		bprofile = devm_kzalloc(tfa98xx->codec->dev, sizeof(*bprofile), GFP_KERNEL);
		if (!bprofile)
			return -ENOMEM;

		bprofile->len = 0;
		bprofile->item_id = -1;
		INIT_LIST_HEAD(&bprofile->list);
        
		/* copy profile name into basename until the . */
		get_profile_basename(bprofile->basename, tfaContProfileName(tfa98xx->handle, prof));
		bprofile->len = strlen(bprofile->basename);
      
		/*
		 * search the profile list for a profile with basename, if it is not found then 
		 * add it to the list and add a new mixer control (if it has vsteps)
		 * also, if it is a calibration profile, do not add it to the list
		 */
		if (is_profile_in_list(bprofile->basename, bprofile->len) == 0 &&
			 is_calibration_profile(tfaContProfileName(tfa98xx->handle, prof)) == 0) {
			/* the profile is not present, add it to the list */
			list_add(&bprofile->list, &profile_list);
			bprofile->item_id = id++;
 
			pr_err("profile added [%d]: %s\n", bprofile->item_id, bprofile->basename);

			if (tfacont_get_max_vstep(tfa98xx->handle, prof)) {
				name = devm_kzalloc(tfa98xx->codec->dev, MAX_CONTROL_NAME, GFP_KERNEL);
				if (!name)
					return -ENOMEM;
			        
				scnprintf(name, MAX_CONTROL_NAME, "%s %s Playback Volume",
				tfa98xx->fw.name, bprofile->basename);

				tfa98xx_controls[mix_index].name = name;
				tfa98xx_controls[mix_index].iface = SNDRV_CTL_ELEM_IFACE_MIXER;
				tfa98xx_controls[mix_index].info = tfa98xx_info_vstep;
				tfa98xx_controls[mix_index].get = tfa98xx_get_vstep;
				tfa98xx_controls[mix_index].put = tfa98xx_set_vstep;
				tfa98xx_controls[mix_index].private_value = prof; /* save profile index */
				mix_index++;
			}
		}
        
		/* look for the basename profile in the list of mixer profiles and add the
		   container profile index to the supported samplerates of this mixer profile */
		add_sr_to_profile(tfa98xx, bprofile->basename, bprofile->len, prof);
	}


	if (tfa98xx_dev_family(tfa98xx->handle) == 1) {
		/* Create a mixer item for stop control on TFA1 */
		name = devm_kzalloc(tfa98xx->codec->dev, MAX_CONTROL_NAME, GFP_KERNEL);
		if (!name)
			return -ENOMEM;

		scnprintf(name, MAX_CONTROL_NAME, "%s Stop", tfa98xx->fw.name);
		tfa98xx_controls[mix_index].name = name;
		tfa98xx_controls[mix_index].iface = SNDRV_CTL_ELEM_IFACE_MIXER;
		tfa98xx_controls[mix_index].info = snd_soc_info_bool_ext;
		tfa98xx_controls[mix_index].get = tfa98xx_get_stop_ctl;
		tfa98xx_controls[mix_index].put = tfa98xx_set_stop_ctl;
		mix_index++;
	}

	/* set the number of user selectable profiles in the mixer */
	tfa98xx_mixer_profiles = id;
/*zhiguang.su@MultiMediaService,2017-04-26,add ftm spk pa rivision test*/
	snd_soc_add_codec_controls(tfa98xx->codec, tfa98xx_at_controls,
				   ARRAY_SIZE(tfa98xx_at_controls));
	return snd_soc_add_codec_controls(tfa98xx->codec,
		tfa98xx_controls, mix_index);
}

static void *tfa98xx_devm_kstrdup(struct device *dev, char *buf)
{
	char *str = devm_kzalloc(dev, strlen(buf) + 1, GFP_KERNEL);
	if (!str)
		return str;
	memcpy(str, buf, strlen(buf));
	return str;
}

static int tfa98xx_append_i2c_address(struct device *dev,
				struct i2c_client *i2c,
				struct snd_soc_dapm_widget *widgets,
				int num_widgets,
				struct snd_soc_dai_driver *dai_drv,
				int num_dai)
{
	char buf[50];
	int i;
	int i2cbus = i2c->adapter->nr;
	int addr = i2c->addr;
	if (dai_drv && num_dai > 0)
		for(i = 0; i < num_dai; i++) {
			snprintf(buf, 50, "%s-%x-%x",dai_drv[i].name, i2cbus,
				addr);
			dai_drv[i].name = tfa98xx_devm_kstrdup(dev, buf);

			snprintf(buf, 50, "%s-%x-%x",
						dai_drv[i].playback.stream_name,
						i2cbus, addr);
			dai_drv[i].playback.stream_name = tfa98xx_devm_kstrdup(dev, buf);

			snprintf(buf, 50, "%s-%x-%x",
						dai_drv[i].capture.stream_name,
						i2cbus, addr);
			dai_drv[i].capture.stream_name = tfa98xx_devm_kstrdup(dev, buf);
		}

	/* the idea behind this is convert:
	 * SND_SOC_DAPM_AIF_IN("AIF IN", "AIF Playback", 0, SND_SOC_NOPM, 0, 0),
	 * into:
	 * SND_SOC_DAPM_AIF_IN("AIF IN", "AIF Playback-2-36", 0, SND_SOC_NOPM, 0, 0),
	 */
	if (widgets && num_widgets > 0)
		for(i = 0; i < num_widgets; i++) {
			if(!widgets[i].sname)
				continue;
			if((widgets[i].id == snd_soc_dapm_aif_in)
				|| (widgets[i].id == snd_soc_dapm_aif_out)) {
				snprintf(buf, 50, "%s-%x-%x", widgets[i].sname,
					i2cbus, addr);
				widgets[i].sname = tfa98xx_devm_kstrdup(dev, buf);
			}
		}

	return 0;
}

static struct snd_soc_dapm_widget tfa98xx_dapm_widgets_common[] = {
	/* Stream widgets */
	SND_SOC_DAPM_AIF_IN("AIF IN", "AIF Playback", 0, SND_SOC_NOPM, 0, 0),
	SND_SOC_DAPM_AIF_OUT("AIF OUT", "AIF Capture", 0, SND_SOC_NOPM, 0, 0),

	SND_SOC_DAPM_OUTPUT("OUTL"),
	SND_SOC_DAPM_INPUT("AEC Loopback"),
};

static struct snd_soc_dapm_widget tfa98xx_dapm_widgets_stereo[] = {
	SND_SOC_DAPM_OUTPUT("OUTR"),
};

static struct snd_soc_dapm_widget tfa98xx_dapm_widgets_saam[] = {
	SND_SOC_DAPM_INPUT("SAAM MIC"),
};

static struct snd_soc_dapm_widget tfa9888_dapm_inputs[] = {
	SND_SOC_DAPM_INPUT("DMIC1"),
	SND_SOC_DAPM_INPUT("DMIC2"),
	SND_SOC_DAPM_INPUT("DMIC3"),
	SND_SOC_DAPM_INPUT("DMIC4"),
};

static const struct snd_soc_dapm_route tfa98xx_dapm_routes_common[] = {
	{ "OUTL", NULL, "AIF IN" },
	{ "AIF OUT", NULL, "AEC Loopback" },
};

static const struct snd_soc_dapm_route tfa98xx_dapm_routes_saam[] = {
	{ "AIF OUT", NULL, "SAAM MIC" },
};

static const struct snd_soc_dapm_route tfa98xx_dapm_routes_stereo[] = {
	{ "OUTR", NULL, "AIF IN" },
};

static const struct snd_soc_dapm_route tfa9888_input_dapm_routes[] = {
	{ "AIF OUT", NULL, "DMIC1" },
	{ "AIF OUT", NULL, "DMIC2" },
	{ "AIF OUT", NULL, "DMIC3" },
	{ "AIF OUT", NULL, "DMIC4" },
};

static void tfa98xx_add_widgets(struct tfa98xx *tfa98xx)
{
	struct snd_soc_dapm_context *dapm =
			snd_soc_codec_get_dapm(tfa98xx->codec);
	struct snd_soc_dapm_widget *widgets;
	unsigned int num_dapm_widgets = ARRAY_SIZE(tfa98xx_dapm_widgets_common);

	widgets = devm_kzalloc(&tfa98xx->i2c->dev,
			sizeof(struct snd_soc_dapm_widget) *
				ARRAY_SIZE(tfa98xx_dapm_widgets_common),
			GFP_KERNEL);
	if (!widgets)
		return;
	memcpy(widgets, tfa98xx_dapm_widgets_common,
			sizeof(struct snd_soc_dapm_widget) *
				ARRAY_SIZE(tfa98xx_dapm_widgets_common));

	tfa98xx_append_i2c_address(&tfa98xx->i2c->dev,
				tfa98xx->i2c,
				widgets,
				num_dapm_widgets,
				NULL,
				0);

	snd_soc_dapm_new_controls(dapm, widgets,
				  ARRAY_SIZE(tfa98xx_dapm_widgets_common));
	snd_soc_dapm_add_routes(dapm, tfa98xx_dapm_routes_common,
				ARRAY_SIZE(tfa98xx_dapm_routes_common));

	if (tfa98xx->flags & TFA98XX_FLAG_STEREO_DEVICE) {
		snd_soc_dapm_new_controls(dapm, tfa98xx_dapm_widgets_stereo,
					  ARRAY_SIZE(tfa98xx_dapm_widgets_stereo));
		snd_soc_dapm_add_routes(dapm, tfa98xx_dapm_routes_stereo,
					ARRAY_SIZE(tfa98xx_dapm_routes_stereo));
	}

	if (tfa98xx->flags & TFA98XX_FLAG_MULTI_MIC_INPUTS) {
		snd_soc_dapm_new_controls(dapm, tfa9888_dapm_inputs,
					  ARRAY_SIZE(tfa9888_dapm_inputs));
		snd_soc_dapm_add_routes(dapm, tfa9888_input_dapm_routes,
					ARRAY_SIZE(tfa9888_input_dapm_routes));
	}

	if (tfa98xx->flags & TFA98XX_FLAG_SAAM_AVAILABLE) {
		snd_soc_dapm_new_controls(dapm, tfa98xx_dapm_widgets_saam,
					  ARRAY_SIZE(tfa98xx_dapm_widgets_saam));
		snd_soc_dapm_add_routes(dapm, tfa98xx_dapm_routes_saam,
					ARRAY_SIZE(tfa98xx_dapm_routes_saam));
	}
}


/* Match tfa98xx device structure with a valid DSP handle */
/* TODO  can be removed once we pass the device struct in stead of handles
	The check in tfa98xx_register_dsp() is implicitly done in tfa_probe() /tfa98xx_cnt_slave2idx(_)
*/
static int tfa98xx_register_dsp(struct tfa98xx *tfa98xx)
{
	int i, handle = -1;
	u8 slave;

	for (i = 0; i < tfa98xx_cnt_max_device(); i++) {
		if (tfaContGetSlave(i, &slave) != Tfa98xx_Error_Ok)
			goto reg_err;
		pr_err("%s: i=%d - dev = 0x%x\n", __func__, i, slave);
		if (slave == tfa98xx->i2c->addr) {
			handle = i;
			break;
		}
	}
	if (handle != -1) {
		tfa98xx_devices[handle] = tfa98xx;
		dev_info(&tfa98xx->i2c->dev,
				"Registered DSP instance with handle %d\n",
								handle);
		tfa98xx_registered_handles++;
		return handle;
	}
reg_err:
	dev_err(&tfa98xx->i2c->dev,
		"Unable to match I2C address 0x%x with a container device\n",
							tfa98xx->i2c->addr);
	return -EINVAL;
}

static void tfa98xx_unregister_dsp(struct tfa98xx *tfa98xx)
{
	tfa98xx_registered_handles--;

	tfa98xx_devices[tfa98xx->handle] = NULL;
	dev_info(&tfa98xx->i2c->dev, "Un-registered DSP instance with handle %d\n",
							tfa98xx->handle);
}


/* I2C wrapper functions */
enum Tfa98xx_Error tfa98xx_write_register16(Tfa98xx_handle_t handle,
					unsigned char subaddress,
					unsigned short value)
{
	enum Tfa98xx_Error error = Tfa98xx_Error_Ok;
	struct tfa98xx *tfa98xx;
	int ret;
	int retries = I2C_RETRIES;

	if (tfa98xx_devices[handle]) {
		tfa98xx = tfa98xx_devices[handle];
		if (!tfa98xx || !tfa98xx->regmap) {
			pr_err("No tfa98xx regmap available\n");
			return Tfa98xx_Error_Bad_Parameter;
		}
retry:
		ret = regmap_write(tfa98xx->regmap, subaddress, value);
		if (ret < 0) {
			pr_warn("i2c error, retries left: %d\n", retries);
			if (retries) {
				retries--;
				msleep(I2C_RETRY_DELAY);
				goto retry;
			}
			return Tfa98xx_Error_Fail;
		}
		if (tfa98xx_kmsg_regs)
			dev_dbg(&tfa98xx->i2c->dev, "  WR reg=0x%02x, val=0x%04x %s\n",
								subaddress, value,
								ret<0? "Error!!" : "");

		if(tfa98xx_ftrace_regs)
			tfa98xx_trace_printk("\tWR     reg=0x%02x, val=0x%04x %s\n",
								subaddress, value,
								ret<0? "Error!!" : "");
	} else {
		pr_err("No device available\n");
		error = Tfa98xx_Error_Fail;
	}
	return error;
}

enum Tfa98xx_Error tfa98xx_read_register16(Tfa98xx_handle_t handle,
					unsigned char subaddress,
					unsigned short *val)
{
	enum Tfa98xx_Error error = Tfa98xx_Error_Ok;
	struct tfa98xx *tfa98xx;
	unsigned int value;
	int retries = I2C_RETRIES;
	int ret;

	if (tfa98xx_devices[handle]) {
		tfa98xx = tfa98xx_devices[handle];
		if (!tfa98xx || !tfa98xx->regmap) {
			pr_err("No tfa98xx regmap available\n");
			return Tfa98xx_Error_Bad_Parameter;
		}
retry:
		ret = regmap_read(tfa98xx->regmap, subaddress, &value);
		if (ret < 0) {
			pr_warn("i2c error at subaddress 0x%x, retries left: %d\n", subaddress, retries);
			if (retries) {
				retries--;
				msleep(I2C_RETRY_DELAY);
				goto retry;
			}
			return Tfa98xx_Error_Fail;
		}
		*val = value & 0xffff;

		if (tfa98xx_kmsg_regs)
			dev_dbg(&tfa98xx->i2c->dev, "RD   reg=0x%02x, val=0x%04x %s\n",
								subaddress, *val,
								ret<0? "Error!!" : "");
		if (tfa98xx_ftrace_regs)
			tfa98xx_trace_printk("\tRD     reg=0x%02x, val=0x%04x %s\n",
								subaddress, *val,
								ret<0? "Error!!" : "");
	} else {
		pr_err("No device available\n");
		error = Tfa98xx_Error_Fail;
	}
	return error;
}

enum Tfa98xx_Error tfa98xx_read_data(Tfa98xx_handle_t handle,
				unsigned char reg,
				int len, unsigned char value[])
{
	enum Tfa98xx_Error error = Tfa98xx_Error_Ok;
	struct tfa98xx *tfa98xx;
	struct i2c_client *tfa98xx_client;
	int err;
	int tries = 0;
	struct i2c_msg msgs[] = {
		{
			.flags = 0,
			.len = 1,
			.buf = &reg,
		}, {
			.flags = I2C_M_RD,
			.len = len,
			.buf = value,
		},
	};

	if (tfa98xx_devices[handle] && tfa98xx_devices[handle]->i2c) {
		tfa98xx = tfa98xx_devices[handle];
		tfa98xx_client = tfa98xx->i2c;
		msgs[0].addr = tfa98xx_client->addr;
		msgs[1].addr = tfa98xx_client->addr;

		do {
			err = i2c_transfer(tfa98xx_client->adapter, msgs,
							ARRAY_SIZE(msgs));
			if (err != ARRAY_SIZE(msgs))
				msleep_interruptible(I2C_RETRY_DELAY);
		} while ((err != ARRAY_SIZE(msgs)) && (++tries < I2C_RETRIES));

		if (err != ARRAY_SIZE(msgs)) {
			dev_err(&tfa98xx_client->dev, "read transfer error %d\n",
									err);
			error = Tfa98xx_Error_Fail;
		}

		if (tfa98xx_kmsg_regs)
			dev_dbg(&tfa98xx_client->dev, "RD-DAT reg=0x%02x, len=%d\n",
								reg, len);
		if (tfa98xx_ftrace_regs)
			tfa98xx_trace_printk("\t\tRD-DAT reg=0x%02x, len=%d\n",
					reg, len);
	} else {
		pr_err("No device available\n");
		error = Tfa98xx_Error_Fail;
	}
	return error;
}

enum Tfa98xx_Error tfa98xx_write_raw(Tfa98xx_handle_t handle,
				int len,
				const unsigned char data[])
{
	enum Tfa98xx_Error error = Tfa98xx_Error_Ok;
	struct tfa98xx *tfa98xx;
	int ret;
	int retries = I2C_RETRIES;

	if (tfa98xx_devices[handle]) {
		tfa98xx = tfa98xx_devices[handle];
retry:
		ret = i2c_master_send(tfa98xx->i2c, data, len);
		if (ret < 0) {
			pr_warn("i2c error, retries left: %d\n", retries);
			if (retries) {
				retries--;
				msleep(I2C_RETRY_DELAY);
				goto retry;
			}
		}

		if (ret == len) {
			if (tfa98xx_kmsg_regs)
				dev_dbg(&tfa98xx->i2c->dev, "  WR-RAW len=%d\n", len);
			if (tfa98xx_ftrace_regs)
				tfa98xx_trace_printk("\t\tWR-RAW len=%d\n", len);
			return Tfa98xx_Error_Ok;
		}
		pr_err("  WR-RAW (len=%d) Error I2C send size mismatch %d\n", len, ret);
		error = Tfa98xx_Error_Fail;
	} else {
		pr_err("No device available\n");
		error = Tfa98xx_Error_Fail;
	}
	return error;
}

/* Read and return status_reg content, and intercept (interrupt related)
 * events if any.
 * mask can be used to ask to ignore some status bits.
 */
static unsigned int tfa98xx_read_status_reg(struct tfa98xx *tfa98xx,
							unsigned int mask)
{
	unsigned int reg;
	/* interrupt bits to check */
	unsigned int errs =	TFA98XX_STATUSREG_WDS |
				TFA98XX_STATUSREG_SPKS;

	regmap_read(tfa98xx->regmap, TFA98XX_STATUSREG, &reg);

	if (reg & errs & ~mask) {
		/* interesting status bits to handle. Just trace for now. */
		dev_info(tfa98xx->codec->dev, "status_reg events: 0x%x\n", reg);
	}

	return reg;
}

/* Interrupts management */

static void tfa98xx_interrupt_restore_tfa2(struct tfa98xx *tfa98xx)
{
	unsigned int base_addr_inten = TFA_FAM(tfa98xx->handle,INTENVDDS) >> 8;

	/* Write interrupt enable registers */
	regmap_write(tfa98xx->regmap, base_addr_inten + 0,
			handles_local[tfa98xx->handle].interrupt_enable[0]);
	regmap_write(tfa98xx->regmap, base_addr_inten + 1,
			handles_local[tfa98xx->handle].interrupt_enable[1]);
	regmap_write(tfa98xx->regmap, base_addr_inten + 2,
			handles_local[tfa98xx->handle].interrupt_enable[2]);
}

static void tfa98xx_interrupt_enable_tfa2(struct tfa98xx *tfa98xx, bool enable)
{
	unsigned int base_addr_inten = TFA_FAM(tfa98xx->handle,INTENVDDS) >> 8;

	if (enable) {
		tfa98xx_interrupt_restore_tfa2(tfa98xx);
	} else {
		regmap_write(tfa98xx->regmap, base_addr_inten + 0, 0);
		regmap_write(tfa98xx->regmap, base_addr_inten + 1, 0);
		regmap_write(tfa98xx->regmap, base_addr_inten + 2, 0);
	}
}

/* Check if tap-detection can and shall be enabled.
 * Configure SPK interrupt accordingly or setup polling mode
 * Tap-detection shall be active if:
 *  - the service is enabled (tapdet_open), AND
 *  - the current profile is a tap-detection profile
 * On TFA1 familiy of devices, activating tap-detection means enabling the SPK
 * interrupt if available.
 * We also update the tapdet_enabled and tapdet_poll variables.
 */
static void tfa98xx_tapdet_check_update(struct tfa98xx *tfa98xx)
{
	unsigned int spkerr, enable = false;
	unsigned int err;
	int val, count = 0;

	/* Support tap-detection on TFA1 family of devices */
	if (!(tfa98xx->flags & TFA98XX_FLAG_TAPDET_AVAILABLE) ||
		(tfa98xx_dev_family(tfa98xx->handle)) != 1)
		return;

	if (tfa98xx->tapdet_open &&
		(tfa98xx->tapdet_profiles & (1 << tfa98xx_profile)))
		enable = true;

	spkerr = enable ? 0 : 1;

	if (!gpio_is_valid(tfa98xx->irq_gpio)) {
		/* interrupt not available, setup polling mode */
		tfa98xx->tapdet_poll = true;
		if (enable)
			queue_delayed_work(tfa98xx->tfa98xx_wq,
						&tfa98xx->tapdet_work, HZ/10);
		else
			cancel_delayed_work_sync(&tfa98xx->tapdet_work);
		dev_dbg(tfa98xx->codec->dev,
			"Polling for tap-detection: %s (%d; 0x%x, %d)\n",
			enable? "enabled":"disabled",
			tfa98xx->tapdet_open, tfa98xx->tapdet_profiles,
			tfa98xx_profile);

	} else {
		dev_dbg(tfa98xx->codec->dev,
			"SPK interrupt for tap-detection: %s (%d; 0x%x, %d)\n",
				enable? "enabled":"disabled",
				tfa98xx->tapdet_open, tfa98xx->tapdet_profiles,
				tfa98xx_profile);

		/* update status_reg mask to match enabled interrupts */
		handles_local[tfa98xx->handle].interrupt_status[0] &=
					~TFA98XX_STATUSREG_SPKS;
		handles_local[tfa98xx->handle].interrupt_status[0] |=
					enable << TFA98XX_STATUSREG_SPKS_POS;

		/* update interrupt_reg to match enabled interrupts */
		handles_local[tfa98xx->handle].interrupt_enable[0] &=
					~TFA98XX_INTERRUPT_REG_SPKD;
		handles_local[tfa98xx->handle].interrupt_enable[0] |=
					spkerr << TFA98XX_INTERRUPT_REG_SPKD_POS;
	}

	/* check disabled => enabled transition to clear pending events */
	if (!tfa98xx->tapdet_enabled && enable) {
		/* clear pending event if any */
		err = tfa98xx_dsp_write_mem_word(tfa98xx->handle, XMEM_TAP_ACK, 0,
							Tfa98xx_DMEM_XMEM);
		if (err)
			pr_info("Unable to write to XMEM\n");

		val = tfa98xx_read_status_reg(tfa98xx, TFA98XX_STATUSREG_SPKS);
		while ((TFA98XX_STATUSREG_SPKS & val) && (count < 50)) {
			val = tfa98xx_read_status_reg(tfa98xx,
							TFA98XX_STATUSREG_SPKS);
			count++;
		}
		if (count > 1)
			pr_info("Had to run %d times to ack SPKS at init\n", count);
	}

	tfa98xx->tapdet_enabled = enable;

	if (!tfa98xx->tapdet_poll)
		tfa98xx_interrupt_restore(tfa98xx);
}

/* Initial configuration of interrupt masks of devices for TFA1 family
 * Disable all interrupts by default.
 */
static void tfa98xx_interrupt_setup_tfa1(struct tfa98xx *tfa98xx)
{
	uint16_t ie_reg = 0;

	/* disable all interrupt sources */
	ie_reg = TFA98XX_INTERRUPT_REG_VDDD |
		TFA98XX_INTERRUPT_REG_OTDD |
		TFA98XX_INTERRUPT_REG_OVDD |
		TFA98XX_INTERRUPT_REG_UVDD |
		TFA98XX_INTERRUPT_REG_OCDD |
		TFA98XX_INTERRUPT_REG_CLKD |
		TFA98XX_INTERRUPT_REG_DCCD |
		TFA98XX_INTERRUPT_REG_SPKD |
		TFA98XX_INTERRUPT_REG_WDD;
	/* preserve reserved value */
	ie_reg |= 1 << 9;

	/* Store requested setup */
	handles_local[tfa98xx->handle].interrupt_enable[0] = ie_reg;
	handles_local[tfa98xx->handle].interrupt_status[0] = 0;

	dev_dbg(&tfa98xx->i2c->dev, "Initial interrupts setup: ICR = 0x%04x\n", ie_reg);
}

/* Restore for 1st generation of devices */
static void tfa98xx_interrupt_restore_tfa1(struct tfa98xx *tfa98xx)
{
	unsigned int ie_reg = 0;

	regmap_read(tfa98xx->regmap, TFA98XX_INTERRUPT_REG, &ie_reg);

	if (ie_reg != handles_local[tfa98xx->handle].interrupt_enable[0]) {
		ie_reg = handles_local[tfa98xx->handle].interrupt_enable[0];

		/* Write interrupt enable registers */
		regmap_write(tfa98xx->regmap, TFA98XX_INTERRUPT_REG, ie_reg);

		dev_dbg(&tfa98xx->i2c->dev, "Restored interrupts: ICR = 0x%04x\n",
									ie_reg);
	} else {
		dev_dbg(&tfa98xx->i2c->dev, "No interrupt restore needed\n");
	}

}

/* Enable for 1st generation of devices */
static void tfa98xx_interrupt_enable_tfa1(struct tfa98xx *tfa98xx, bool enable)
{
	handles_local[tfa98xx->handle].interrupt_enable[0] &= ~TFA98XX_INTERRUPT_REG_INT;
	handles_local[tfa98xx->handle].interrupt_enable[0] |= enable << TFA98XX_INTERRUPT_REG_INT_POS;

	tfa98xx_interrupt_restore_tfa1(tfa98xx);
}

static void tfa98xx_interrupt_setup_tfa2(struct tfa98xx *tfa98xx)
{
	uint16_t ie_reg;

	handles_local[tfa98xx->handle].interrupt_enable[0] = 0;
	ie_reg = 0;
	TFA_SET_BF_VALUE(tfa98xx->handle, IEMWSRC, 1, &ie_reg);
	handles_local[tfa98xx->handle].interrupt_enable[1] = ie_reg;
	handles_local[tfa98xx->handle].interrupt_enable[2] = 0;
}

/* Initial SW configuration for interrupts. Does not enable HW interrupts. */
static void tfa98xx_interrupt_setup(struct tfa98xx *tfa98xx)
{
	if (tfa98xx->flags & TFA98XX_FLAG_SKIP_INTERRUPTS)
		return;

	if (tfa98xx->flags & TFA98XX_FLAG_TFA9890_FAM_DEV)
		tfa98xx_interrupt_setup_tfa1(tfa98xx);
	else
		tfa98xx_interrupt_setup_tfa2(tfa98xx);
}

/* Restore interrupt setup in case it would be lost (at device cold-start) */
static void tfa98xx_interrupt_restore(struct tfa98xx *tfa98xx)
{
	if (tfa98xx->flags & TFA98XX_FLAG_SKIP_INTERRUPTS)
		return;

	if (tfa98xx_dev_family(tfa98xx->handle) == 2)
		tfa98xx_interrupt_restore_tfa2(tfa98xx);
	else
		tfa98xx_interrupt_restore_tfa1(tfa98xx);
}

/* global enable / disable interrupts */
static void tfa98xx_interrupt_enable(struct tfa98xx *tfa98xx, bool enable)
{
	if (tfa98xx->flags & TFA98XX_FLAG_SKIP_INTERRUPTS)
		return;

	if (tfa98xx_dev_family(tfa98xx->handle) == 2)
		tfa98xx_interrupt_enable_tfa2(tfa98xx, enable);
	else
		tfa98xx_interrupt_enable_tfa1(tfa98xx, enable);
}

/* Firmware management
 * Downloaded once only at module init
 * FIXME: may need to review that (one per instance of codec device?)
 */
static char *fw_name = "tfa98xx.cnt";
module_param(fw_name, charp, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(fw_name, "TFA98xx DSP firmware (container file) name.");

static nxpTfaContainer_t *container;
#if 0
static void tfa98xx_container_loaded(const struct firmware *cont, void *context)
{
	struct tfa98xx *tfa98xx = context;
	enum tfa_error tfa_err;
	int container_size;
	int handle;
	int ret;

	tfa98xx->dsp_fw_state = TFA98XX_DSP_FW_FAIL;

	if (!cont) {
		pr_err("Failed to read %s\n", fw_name);
		return;
	}

	pr_err("loaded %s - size: %zu\n", fw_name,
					cont ? cont->size : 0);

	container = kzalloc(cont->size, GFP_KERNEL);
	if (!container) {
		release_firmware(cont);
		pr_err("Error allocating memory\n");
		return;
	}

	container_size = cont->size;
	memcpy(container, cont->data, container_size);
	release_firmware(cont);

	pr_err("%.2s%.2s\n", container->version, container->subversion);
	pr_err("%.8s\n", container->customer);
	pr_err("%.8s\n", container->application);
	pr_err("%.8s\n", container->type);
	pr_err("%d ndev\n", container->ndev);
	pr_err("%d nprof\n", container->nprof);

	tfa_err = tfa_load_cnt(container, container_size);
	if (tfa_err != tfa_error_ok) {
		dev_err(tfa98xx->dev, "Cannot load container file, aborting\n");
		return;
	}

	/* register codec with dsp */
	tfa98xx->handle = tfa98xx_register_dsp(tfa98xx);
	if (tfa98xx->handle < 0) {
		dev_err(tfa98xx->dev, "Cannot register with DSP, aborting\n");
		return;
	}

	if (tfa_probe(tfa98xx->i2c->addr << 1, &handle) != Tfa98xx_Error_Ok) {
		dev_err(tfa98xx->dev, "Failed to probe TFA98xx @ 0x%.2x\n", tfa98xx->i2c->addr);
		return;
	}

	/* prefix is the application name from the cnt */
	tfa_cnt_get_app_name(tfa98xx->fw.name);

	/* Override default profile if requested */
	if (strcmp(dflt_prof_name, "")) {
		unsigned int i;
		for (i = 0; i < tfaContMaxProfile(tfa98xx->handle); i++) {
			if (strcmp(tfaContProfileName(tfa98xx->handle, i),
							dflt_prof_name) == 0) {
				tfa98xx_profile = i;
				dev_info(tfa98xx->dev,
					"changing default profile to %s (%d)\n",
					dflt_prof_name, tfa98xx_profile);
				break;
			}
		}
		if (i >= tfaContMaxProfile(tfa98xx->handle))
			dev_info(tfa98xx->dev,
				"Default profile override failed (%s profile not found)\n",
				dflt_prof_name);
	}


	tfa98xx->dsp_fw_state = TFA98XX_DSP_FW_OK;
	pr_err("Firmware init complete\n");

	if (no_start != 0)
		return;

	/* Only controls for master device */
	if (tfa98xx->handle == 0)
		tfa98xx_create_controls(tfa98xx);


	tfa98xx_inputdev_check_register(tfa98xx);

	if (tfa98xx->flags & TFA98XX_FLAG_DSP_START_ON_MUTE) {
		tfa98xx_interrupt_enable(tfa98xx, true);
		return;
	}

	mutex_lock(&tfa98xx->dsp_lock);

	ret = tfa98xx_tfa_start(tfa98xx, tfa98xx_profile, tfa98xx_vsteps);
	if (ret == Tfa98xx_Error_Ok)
		tfa98xx->dsp_init = TFA98XX_DSP_INIT_DONE;
	mutex_unlock(&tfa98xx->dsp_lock);
	tfa98xx_interrupt_enable(tfa98xx, true);
}
#endif
static int tfa98xx_load_container(struct tfa98xx *tfa98xx)
{
	enum tfa_error tfa_err;
	int handle;
	int container_size;
	const struct firmware *fw;
	int ret;
	tfa98xx->dsp_fw_state = TFA98XX_DSP_FW_FAIL;

	
    ret = request_firmware(&fw,fw_name,tfa98xx->dev);
	if(ret < 0)
	{
		pr_err("Failed to read %s\n", fw_name);
		return ret;
	}
	
	pr_err("loaded %s - size: %zu\n", fw_name,
     fw ? fw->size : 0);
	 
	container = kzalloc(fw->size, GFP_KERNEL);
    if (!container) {
    release_firmware(fw);
    pr_err("Error allocating memory\n");
    return -ENOMEM;
    }
    container_size = fw->size;
	memcpy(container, fw->data, container_size);
    release_firmware(fw);
   
	pr_err("%.2s%.2s\n", container->version, container->subversion);
	pr_err("%.8s\n", container->customer);
	pr_err("%.8s\n", container->application);
	pr_err("%.8s\n", container->type);
	pr_err("%d ndev\n", container->ndev);
	pr_err("%d nprof\n", container->nprof);

	tfa_err = tfa_load_cnt(container, container_size);
	if (tfa_err != tfa_error_ok) {
		dev_err(tfa98xx->dev, "Cannot load container file, aborting\n");
		return tfa_err;
	}

	/* register codec with dsp */
	tfa98xx->handle = tfa98xx_register_dsp(tfa98xx);
	if (tfa98xx->handle < 0) {
		dev_err(tfa98xx->dev, "Cannot register with DSP, aborting\n");
		return tfa98xx->handle;
	}

	if (tfa_probe(tfa98xx->i2c->addr << 1, &handle) != Tfa98xx_Error_Ok) {
		dev_err(tfa98xx->dev, "Failed to probe TFA98xx @ 0x%.2x\n", tfa98xx->i2c->addr);
		return tfa98xx->i2c->addr;
	}

	/* prefix is the application name from the cnt */
	tfa_cnt_get_app_name(tfa98xx->fw.name);

	/* Override default profile if requested */
	if (strcmp(dflt_prof_name, "")) {
		unsigned int i;
		for (i = 0; i < tfaContMaxProfile(tfa98xx->handle); i++) {
			if (strcmp(tfaContProfileName(tfa98xx->handle, i),
							dflt_prof_name) == 0) {
				tfa98xx_profile = i;
				dev_info(tfa98xx->dev,
					"changing default profile to %s (%d)\n",
					dflt_prof_name, tfa98xx_profile);
				break;
			}
		}
		if (i >= tfaContMaxProfile(tfa98xx->handle))
			dev_info(tfa98xx->dev,
				"Default profile override failed (%s profile not found)\n",
				dflt_prof_name);
	}


	tfa98xx->dsp_fw_state = TFA98XX_DSP_FW_OK;
	pr_err("Firmware init complete\n");

	if (no_start != 0)
		return no_start;

	/* Only controls for master device */
	if (tfa98xx->handle == 0)
		tfa98xx_create_controls(tfa98xx);


	tfa98xx_inputdev_check_register(tfa98xx);

	if (tfa98xx->flags & TFA98XX_FLAG_DSP_START_ON_MUTE) {
		tfa98xx_interrupt_enable(tfa98xx, true);
		return 0;
	}

	mutex_lock(&tfa98xx->dsp_lock);

	ret = tfa98xx_tfa_start(tfa98xx, tfa98xx_profile, tfa98xx_vsteps);
	if (ret == Tfa98xx_Error_Ok)
		tfa98xx->dsp_init = TFA98XX_DSP_INIT_DONE;
	mutex_unlock(&tfa98xx->dsp_lock);
	tfa98xx_interrupt_enable(tfa98xx, true);
	//return request_firmware_nowait(THIS_MODULE, FW_ACTION_HOTPLUG,
	//                               fw_name, tfa98xx->dev, GFP_KERNEL,
	//                               tfa98xx, tfa98xx_container_loaded);
	return 0;
}


static void tfa98xx_tapdet(struct tfa98xx *tfa98xx)
{
	unsigned int mem;
	int err, btn, count = 0;
	uint16_t val;

	/* check tap pattern (BTN_0 is "error" wrong tap indication */
	tfa98xx_dsp_read_mem(tfa98xx->handle, XMEM_TAP_READ, 1, &mem);
	switch (mem) {
	case 0xffffffff:
		pr_info("More than 4 taps detected! (flagTapPattern = -1)\n");
		btn = BTN_0;
		break;
	case 0xfffffffe:
		pr_info("Single tap detected! (flagTapPattern = -2)\n");
		btn = BTN_0;
		break;
	case 0:
		pr_info("Unrecognized pattern! (flagTapPattern = 0)\n");
		btn = BTN_0;
		break;
	default:
		pr_info("Detected pattern: %d\n", mem);
		btn = BTN_0 + mem;
		break;
	}

	input_report_key(tfa98xx->input, btn, 1);
	input_report_key(tfa98xx->input, btn, 0);
	input_sync(tfa98xx->input);

	/* acknowledge event */
	err = tfa98xx_dsp_write_mem_word(tfa98xx->handle, XMEM_TAP_ACK, 0, Tfa98xx_DMEM_XMEM);
	if (err)
		pr_info("Unable to write to XMEM\n");

	val = tfa98xx_read_status_reg(tfa98xx, TFA98XX_STATUSREG_SPKS);
	while ((TFA98XX_STATUSREG_SPKS & val) && (count < 50)) {
		val = tfa98xx_read_status_reg(tfa98xx, TFA98XX_STATUSREG_SPKS);
		count++;
	}
	if (count > 1)
		pr_info("Had to run %d times to ack SPKS\n", count);

}

static void tfa98xx_tapdet_work(struct work_struct *work)
{
	struct tfa98xx *tfa98xx;
	u16 val;

	tfa98xx = container_of(work, struct tfa98xx, tapdet_work.work);

	/* Check for SPKS bit*/
	val = snd_soc_read(tfa98xx->codec, TFA98XX_STATUSREG);

	if (val & TFA98XX_STATUSREG_SPKS)
		tfa98xx_tapdet(tfa98xx);

	queue_delayed_work(tfa98xx->tfa98xx_wq, &tfa98xx->tapdet_work, HZ/10);
}



static void tfa98xx_dsp_init(struct tfa98xx *tfa98xx)
{
	int ret;
	bool failed = false;
	bool reschedule = false;

	if (tfa98xx->dsp_fw_state != TFA98XX_DSP_FW_OK) {
		pr_err("Skipping tfa_start (no FW: %d)\n", tfa98xx->dsp_fw_state);
		return;
	}

	if(tfa98xx->dsp_init == TFA98XX_DSP_INIT_DONE) {
		pr_err("Stream already started, skipping DSP power-on\n");
		return;
	}

	mutex_lock(&tfa98xx->dsp_lock);

	tfa98xx->dsp_init = TFA98XX_DSP_INIT_PENDING;

	if (tfa98xx->init_count < TF98XX_MAX_DSP_START_TRY_COUNT) {
		/* directly try to start DSP */
		ret = tfa98xx_tfa_start(tfa98xx, tfa98xx_profile, tfa98xx_vsteps);
		if (ret != Tfa98xx_Error_Ok) {
			/* It may fail as we may not have a valid clock at that
			 * time, so re-schedule and re-try later.
			 */
			dev_err(&tfa98xx->i2c->dev,
					"tfa_start failed! (err %d) - %d\n",
					ret, tfa98xx->init_count);
			reschedule = true;
		} else {
			/* Subsystem ready, tfa init complete */
			dev_dbg(&tfa98xx->i2c->dev,
						"tfa_start success (%d)\n",
						tfa98xx->init_count);
			/* cancel other pending init works */
			cancel_delayed_work(&tfa98xx->init_work);
			tfa98xx->init_count = 0;
			/*
			 * start monitor thread to check IC status bit
			 * periodically, and re-init IC to recover if
			 * needed.
			 */
		}
	} else {
		/* exceeded max number ot start tentatives, cancel start */
		dev_err(&tfa98xx->i2c->dev,
			"Failed starting device (%d)\n",
			tfa98xx->init_count);
			failed = true;
	}
	if (reschedule) {
		/* reschedule this init work for later */
		queue_delayed_work(tfa98xx->tfa98xx_wq,
						&tfa98xx->init_work,
						msecs_to_jiffies(5));
		tfa98xx->init_count++;
	}
	if (failed) {
		tfa98xx->dsp_init = TFA98XX_DSP_INIT_FAIL;
		/* cancel other pending init works */
		cancel_delayed_work(&tfa98xx->init_work);
		tfa98xx->init_count = 0;
	}
	mutex_unlock(&tfa98xx->dsp_lock);
	return;
}

/*zhiguang.su@MultiMediaService,2017-02-09,avoid no sound for ftm*/
static void tfa98xx_dsp_startInit(struct tfa98xx *tfa98xx)
{
	/* Only do dsp init for master device */
	if (tfa98xx->handle != 0)
		return;

	tfa98xx_dsp_init(tfa98xx);
}


static void tfa98xx_dsp_init_work(struct work_struct *work)
{
	struct tfa98xx *tfa98xx = container_of(work, struct tfa98xx, init_work.work);

	/* Only do dsp init for master device */
	if (tfa98xx->handle != 0)
		return;

	tfa98xx_dsp_init(tfa98xx);
}

static void tfa98xx_interrupt(struct work_struct *work)
{
	struct tfa98xx *tfa98xx = container_of(work, struct tfa98xx, interrupt_work.work);
	unsigned int base_addr_inten = TFA_FAM(tfa98xx->handle,INTENVDDS) >> 8;
	unsigned int base_addr_ist   = TFA_FAM(tfa98xx->handle,ISTVDDS) >> 8;
	unsigned int base_addr_icl   = TFA_FAM(tfa98xx->handle,ICLVDDS) >> 8;
	//unsigned int base_addr_ipo   = TFA_FAM(tfa98xx->handle,IPOVDDS) >> 8;

	u32 out1, out2, out3;

	pr_info("\n");

	regmap_read(tfa98xx->regmap, base_addr_ist + 0, &out1);
	regmap_read(tfa98xx->regmap, base_addr_ist + 1, &out2);
	regmap_read(tfa98xx->regmap, base_addr_ist + 2, &out3);

	out1 &= handles_local[tfa98xx->handle].interrupt_enable[0];
	out2 &= handles_local[tfa98xx->handle].interrupt_enable[1];
	out3 &= handles_local[tfa98xx->handle].interrupt_enable[2];

	if (out1) {
		/* clear and enable interrupt(s) again */
		regmap_write(tfa98xx->regmap, base_addr_icl + 0, out1);
		regmap_write(tfa98xx->regmap, base_addr_inten + 0,
			handles_local[tfa98xx->handle].interrupt_enable[0]);
	}

	if (out2) {
		/* manager wait for source state */
		if (TFA_GET_BF_VALUE(tfa98xx->handle, ISTMWSRC, out2) > 0) {
			int manwait1 = TFA_GET_BF(tfa98xx->handle, MANWAIT1);

			if (manwait1 > 0) {
				pr_info("entering wait for source state\n");
				tfa98xx->count_wait_for_source_state++;
				
				/* set AMPC and AMPE to make sure the amp is enabled */
				pr_info("setting AMPC and AMPE to 1 (default) \n");	
				TFA_SET_BF(tfa98xx->handle, AMPC, 1);
				TFA_SET_BF(tfa98xx->handle, AMPE, 1);

				/* set MANSCONF here, the manager will continue if clock is there */
				TFA_SET_BF(tfa98xx->handle, MANSCONF, 1);
			} else {
				/* Now we can switch profile with internal clock it is not required to call tfa_start */
				 
				pr_info("leaving wait for source state\n");

				TFA_SET_BF(tfa98xx->handle, MANSCONF, 0);
			}

			if (manwait1 > 0)
				TFA_SET_BF(tfa98xx->handle, IPOMWSRC, 0);
			else
				TFA_SET_BF(tfa98xx->handle, IPOMWSRC, 1);
		}

		/* clear and enable interrupt(s) again */
		regmap_write(tfa98xx->regmap, base_addr_icl + 1, out2);
		regmap_write(tfa98xx->regmap, base_addr_inten + 1,
			handles_local[tfa98xx->handle].interrupt_enable[1]);
	}

	if (out3) {
		/* clear and enable interrupt(s) again */
		regmap_write(tfa98xx->regmap, base_addr_icl + 2, out3);
		regmap_write(tfa98xx->regmap, base_addr_inten + 2,
			handles_local[tfa98xx->handle].interrupt_enable[2]);
	}

}

static int tfa98xx_startup(struct snd_pcm_substream *substream,
						struct snd_soc_dai *dai)
{
	struct snd_soc_codec *codec = dai->codec;
	struct tfa98xx *tfa98xx = snd_soc_codec_get_drvdata(codec);
	unsigned int sr;
	int len, prof, nprof = tfaContMaxProfile(tfa98xx->handle), idx = 0;
	char *basename;

	/*
	 * Support CODEC to CODEC links,
	 * these are called with a NULL runtime pointer.
	 */
	if (!substream->runtime)
		return 0;

	if (no_start != 0)
		return 0;

	basename = devm_kzalloc(tfa98xx->codec->dev, MAX_CONTROL_NAME, GFP_KERNEL);
	if (!basename)
		return -ENOMEM;
    
	/* copy profile name into basename until the . */
	get_profile_basename(basename, tfaContProfileName(tfa98xx->handle, tfa98xx_profile));  
	len = strlen(basename);
    
	/* loop over all profiles and get the supported samples rate(s) from
	 * the profiles with the same basename
	 */
	for (prof = 0; prof < nprof; prof++) {
		if (0 == strncmp(basename, tfaContProfileName(tfa98xx->handle, prof), len)) {   
			/* Check which sample rate is supported with current profile,
			 * and enforce this.
			 */
			sr = tfa98xx_get_profile_sr(tfa98xx->handle, prof);
			if (!sr)
				dev_info(codec->dev, "Unable to identify supported sample rate\n");
			tfa98xx->rate_constraint_list[idx++] = sr;
			tfa98xx->rate_constraint.count += 1;
		}
	}

/*zhiguang.su@MultiMediaService,2017-02-09,changed for NXP advise,avoid 8k tinyplay problem*/
    return 0;
    #if 0
	return snd_pcm_hw_constraint_list(substream->runtime, 0,
				   SNDRV_PCM_HW_PARAM_RATE,
				   &tfa98xx->rate_constraint);
	#endif

}

static int tfa98xx_set_dai_sysclk(struct snd_soc_dai *codec_dai,
				  int clk_id, unsigned int freq, int dir)
{
	struct tfa98xx *tfa98xx = snd_soc_codec_get_drvdata(codec_dai->codec);

	tfa98xx->sysclk = freq;
	return 0;
}

static int tfa98xx_set_fmt(struct snd_soc_dai *dai, unsigned int fmt)
{
	struct tfa98xx *tfa98xx = snd_soc_codec_get_drvdata(dai->codec);
	struct snd_soc_codec *codec = dai->codec;

	pr_err("fmt=0x%x\n", fmt);

	/* Supported mode: regular I2S, slave, or PDM */
	switch (fmt & SND_SOC_DAIFMT_FORMAT_MASK) {
	case SND_SOC_DAIFMT_I2S:
		if ((fmt & SND_SOC_DAIFMT_MASTER_MASK) != SND_SOC_DAIFMT_CBS_CFS) {
			dev_err(codec->dev, "Invalid Codec master mode\n");
			return -EINVAL;
		}
		break;
	case SND_SOC_DAIFMT_PDM:
		break;
	default:
		dev_err(codec->dev, "Unsupported DAI format %d\n",
					fmt & SND_SOC_DAIFMT_FORMAT_MASK);
		return -EINVAL;
	}

	tfa98xx->audio_mode = fmt & SND_SOC_DAIFMT_FORMAT_MASK;

	return 0;
}

static int tfa98xx_get_fssel(unsigned int rate)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(rate_to_fssel); i++) {
		if (rate_to_fssel[i].rate == rate) {
			return rate_to_fssel[i].fssel;
		}
	}
	return -EINVAL;
}

static int tfa98xx_hw_params(struct snd_pcm_substream *substream,
			     struct snd_pcm_hw_params *params,
			     struct snd_soc_dai *dai)
{
	struct snd_soc_codec *codec = dai->codec;
	struct tfa98xx *tfa98xx = snd_soc_codec_get_drvdata(codec);
	unsigned int rate;
	int prof_idx;

	/* Supported */
	rate = params_rate(params);
	pr_err("Requested rate: %d, sample size: %d, physical size: %d\n",
			rate, snd_pcm_format_width(params_format(params)),
			snd_pcm_format_physical_width(params_format(params)));

	if (params_channels(params) > 2) {
		pr_warn("Unusual number of channels: %d\n", params_channels(params));
	}

	if (no_start != 0)
		return 0;

	/* check if samplerate is supported for this mixer profile */
	prof_idx = get_profile_id_for_sr(tfa98xx_mixer_profile, rate);
	if (prof_idx < 0) {
		pr_err("tfa98xx: invalid sample rate %d.\n", rate);
		return -EINVAL;
	}
	pr_err("mixer profile:container profile = [%d:%d]\n", tfa98xx_mixer_profile, prof_idx);


	/* update 'real' profile (container profile) */
	tfa98xx_profile = prof_idx;
    
	/* update to new rate */
	tfa98xx->rate = rate;

	return 0;
}

static int tfa98xx_mute(struct snd_soc_dai *dai, int mute, int stream)
{
	struct snd_soc_codec *codec = dai->codec;
	struct tfa98xx *tfa98xx = snd_soc_codec_get_drvdata(codec);

	dev_dbg(&tfa98xx->i2c->dev, "state: %d\n", mute);

	if (!(tfa98xx->flags & TFA98XX_FLAG_DSP_START_ON_MUTE))
		return 0;

	if (no_start) {
		pr_err("no_start parameter set no tfa_start or tfa_stop, returning\n");
		return 0;
	}

	if (mute) {
		/* stop DSP only when both playback and capture streams
		 * are deactivated
		 */
		if (stream == SNDRV_PCM_STREAM_PLAYBACK)
			tfa98xx->pstream = 0;
		else
			tfa98xx->cstream = 0;
		if (tfa98xx->pstream != 0 || tfa98xx->cstream != 0)
			return 0;
		cancel_delayed_work_sync(&tfa98xx->init_work);
		if (tfa98xx->dsp_fw_state != TFA98XX_DSP_FW_OK)
			return 0;
		mutex_lock(&tfa98xx->dsp_lock);
		tfa_stop();
		tfa98xx->dsp_init = TFA98XX_DSP_INIT_STOPPED;
		mutex_unlock(&tfa98xx->dsp_lock);
	} else {
		if (stream == SNDRV_PCM_STREAM_PLAYBACK)
			tfa98xx->pstream = 1;
		else
			tfa98xx->cstream = 1;
/*zhiguang.su@MultiMediaService,2017-02-09,avoid no sound for ftm*/
       if(!tfa98xx->startInit)
       {
           tfa98xx->startInit = true;
           tfa98xx_dsp_startInit(tfa98xx);
       }
       else
       {
		/* Start DSP */
		if (tfa98xx->dsp_init != TFA98XX_DSP_INIT_PENDING)
			queue_delayed_work(tfa98xx->tfa98xx_wq,
							&tfa98xx->init_work,
							0);
		}
	}

	return 0;
}

static const struct snd_soc_dai_ops tfa98xx_dai_ops = {
	.startup = tfa98xx_startup,
	.set_fmt = tfa98xx_set_fmt,
	.set_sysclk = tfa98xx_set_dai_sysclk,
	.hw_params = tfa98xx_hw_params,
	.mute_stream = tfa98xx_mute,
};

static struct snd_soc_dai_driver tfa98xx_dai[] = {
	{
		.name = "tfa98xx_codec",
		.base = TFA98XX_TDM_CONFIG0 - 1,
		.id = 1,
		.playback = {
			.stream_name = "Playback",
			.channels_min = 1,
			.channels_max = 2,
			.rates = TFA98XX_RATES,
			.formats = TFA98XX_FORMATS,
		},
		/*.capture = {
			 .stream_name = "Capture",
			 .channels_min = 1,
			 .channels_max = 2,
			 .rates = TFA98XX_RATES,
			 .formats = TFA98XX_FORMATS,
		 },*/
		.ops = &tfa98xx_dai_ops,
		.symmetric_rates = 0,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
		.symmetric_channels = 0,
		.symmetric_samplebits = 0,
#endif
	},
};

static int tfa98xx_probe(struct snd_soc_codec *codec)
{
	struct tfa98xx *tfa98xx = snd_soc_codec_get_drvdata(codec);
	int ret;

	pr_err("\n");

	tfa98xx->rate_constraint.list = &tfa98xx->rate_constraint_list[0];
	tfa98xx->rate_constraint.count =
		ARRAY_SIZE(tfa98xx->rate_constraint_list);

	/* setup work queue, will be used to initial DSP on first boot up */
	tfa98xx->tfa98xx_wq = create_singlethread_workqueue("tfa98xx");
	if (!tfa98xx->tfa98xx_wq)
		return -ENOMEM;

	INIT_DELAYED_WORK(&tfa98xx->init_work, tfa98xx_dsp_init_work);


	INIT_DELAYED_WORK(&tfa98xx->interrupt_work, tfa98xx_interrupt);
	INIT_DELAYED_WORK(&tfa98xx->tapdet_work, tfa98xx_tapdet_work);

	tfa98xx->codec = codec;

	ret = tfa98xx_load_container(tfa98xx);
	pr_err("Container loading requested: %d\n", ret);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)
	codec->control_data = tfa98xx->regmap;
	ret = snd_soc_codec_set_cache_io(codec, 8, 16, SND_SOC_REGMAP);
	if (ret != 0) {
		dev_err(codec->dev, "Failed to set cache I/O: %d\n", ret);
		return ret;
	}
#endif
	tfa98xx_add_widgets(tfa98xx);

	dev_info(codec->dev, "tfa98xx codec registered (%s)",
							tfa98xx->fw.name);
/*zhiguang.su@MultiMediaService,2017-02-09,avoid no sound for ftm*/
tfa98xx->startInit = false;

    g_tfa98xx = tfa98xx;
	return ret;
}

static int tfa98xx_remove(struct snd_soc_codec *codec)
{
	struct tfa98xx *tfa98xx = snd_soc_codec_get_drvdata(codec);
	pr_err("\n");

	tfa98xx_inputdev_unregister(tfa98xx);

	cancel_delayed_work_sync(&tfa98xx->interrupt_work);
	cancel_delayed_work_sync(&tfa98xx->init_work);
	cancel_delayed_work_sync(&tfa98xx->tapdet_work);

	if (tfa98xx->tfa98xx_wq)
		destroy_workqueue(tfa98xx->tfa98xx_wq);

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)
struct regmap *tfa98xx_get_regmap(struct device *dev)
{
	struct tfa98xx *tfa98xx = dev_get_drvdata(dev);

	return tfa98xx->regmap;
}
#endif
static struct snd_soc_codec_driver soc_codec_dev_tfa98xx = {
	.probe =	tfa98xx_probe,
	.remove =	tfa98xx_remove,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)
	.get_regmap = tfa98xx_get_regmap,
#endif
};


static bool tfa98xx_writeable_register(struct device *dev, unsigned int reg)
{
	/* enable read access for all registers */
	return 1;
}

static bool tfa98xx_readable_register(struct device *dev, unsigned int reg)
{
	/* enable read access for all registers */
	return 1;
}

static bool tfa98xx_volatile_register(struct device *dev, unsigned int reg)
{
	/* enable read access for all registers */
	return 1;
}

static const struct regmap_config tfa98xx_regmap = {
	.reg_bits = 8,
	.val_bits = 16,

	.max_register = TFA98XX_MAX_REGISTER,
	.writeable_reg = tfa98xx_writeable_register,
	.readable_reg = tfa98xx_readable_register,
	.volatile_reg = tfa98xx_volatile_register,
	.cache_type = REGCACHE_NONE,
};


static void tfa98xx_irq_tfa2(struct tfa98xx *tfa98xx)
{
	unsigned int base_addr_inten = TFA_FAM(tfa98xx->handle,INTENVDDS) >> 8;
	unsigned int base_addr_ist   = TFA_FAM(tfa98xx->handle,ISTVDDS) >> 8;
	u32 en1, en2, en3;
	u32 out1 = 0, out2 = 0, out3 = 0;

	pr_info("\n");

	regmap_read(tfa98xx->regmap, base_addr_inten + 0, &en1);
	regmap_read(tfa98xx->regmap, base_addr_inten + 1, &en2);
	regmap_read(tfa98xx->regmap, base_addr_inten + 2, &en3);

	regmap_read(tfa98xx->regmap, base_addr_ist + 0, &out1);
	regmap_read(tfa98xx->regmap, base_addr_ist + 1, &out2);
	regmap_read(tfa98xx->regmap, base_addr_ist + 2, &out3);

	pr_info("interrupt1: 0x%.4x (enabled: 0x%.4x)\n", out1, en1);
	pr_info("interrupt2: 0x%.4x (enabled: 0x%.4x)\n", out2, en2);
	pr_info("interrupt3: 0x%.4x (enabled: 0x%.4x)\n", out3, en3);

	out1 &= en1;
	out2 &= en2;
	out3 &= en3;

	en1 = handles_local[tfa98xx->handle].interrupt_enable[0] ^ out1;
	en2 = handles_local[tfa98xx->handle].interrupt_enable[1] ^ out2;
	en3 = handles_local[tfa98xx->handle].interrupt_enable[2] ^ out3;

	regmap_write(tfa98xx->regmap, base_addr_inten + 0, en1);
	regmap_write(tfa98xx->regmap, base_addr_inten + 1, en2);
	regmap_write(tfa98xx->regmap, base_addr_inten + 2, en3);

	if (out1 || out2 || out3)
		queue_delayed_work(tfa98xx->tfa98xx_wq, &tfa98xx->interrupt_work, 0);
}

static void __tfa98xx_irq(struct tfa98xx *tfa98xx)
{
	uint16_t val;
	uint16_t ie = handles_local[tfa98xx->handle].interrupt_status[0];

	val = snd_soc_read(tfa98xx->codec, TFA98XX_STATUSREG);

	dev_info(&tfa98xx->i2c->dev, "interrupt: 0x%04x (enabled: 0x%04x)\n", val, ie);
#ifdef DEBUG
	if (!(val & ie)) {
		unsigned int ireg;
		/* interrupt triggered while all interrupt sources supposedly
		 * disabled
		 */
		ireg = snd_soc_read(tfa98xx->codec, TFA98XX_INTERRUPT_REG);
		dev_dbg(&tfa98xx->i2c->dev, "ICR: 0x%04x\n", ireg);
	}
#endif

	val &= ie;

	/* Check for SPKS bit */
	if (val & TFA98XX_STATUSREG_SPKS)
		tfa98xx_tapdet(tfa98xx);
}

static irqreturn_t tfa98xx_irq(int irq, void *data)
{
	struct tfa98xx *tfa98xx = data;

	if (tfa98xx_dev_family(tfa98xx->handle) == 2)
		tfa98xx_irq_tfa2(tfa98xx);
	else
		__tfa98xx_irq(tfa98xx);

	return IRQ_HANDLED;
}

static int tfa98xx_ext_reset(struct tfa98xx *tfa98xx)
{
	if (tfa98xx && gpio_is_valid(tfa98xx->reset_gpio)) {
		gpio_set_value_cansleep(tfa98xx->reset_gpio, 1);
		gpio_set_value_cansleep(tfa98xx->reset_gpio, 0);
	}
	return 0;
}

static int tfa98xx_parse_dt(struct device *dev, struct tfa98xx *tfa98xx,
		struct device_node *np) {
	tfa98xx->reset_gpio = of_get_named_gpio(np, "reset-gpio", 0);
	if (tfa98xx->reset_gpio < 0)
		dev_dbg(dev, "No reset GPIO provided, will not HW reset device\n");

	tfa98xx->irq_gpio =  of_get_named_gpio(np, "irq-gpio", 0);
	if (tfa98xx->irq_gpio < 0)
		dev_dbg(dev, "No IRQ GPIO provided.\n");

	return 0;
}

static ssize_t tfa98xx_reg_write(struct file *filp, struct kobject *kobj,
				struct bin_attribute *bin_attr,
				char *buf, loff_t off, size_t count)
{
	struct device *dev = container_of(kobj, struct device, kobj);
	struct tfa98xx *tfa98xx = dev_get_drvdata(dev);

	if (count != 1) {
		pr_err("invalid register address");
		return -EINVAL;
	}

	tfa98xx->reg = buf[0];

	return 1;
}

static ssize_t tfa98xx_rw_write(struct file *filp, struct kobject *kobj,
				struct bin_attribute *bin_attr,
				char *buf, loff_t off, size_t count)
{
	struct device *dev = container_of(kobj, struct device, kobj);
	struct tfa98xx *tfa98xx = dev_get_drvdata(dev);
	u8 *data;
	int ret;
	int retries = I2C_RETRIES;

	data = kmalloc(count+1, GFP_KERNEL);
	if (data == NULL) {
		pr_err("can not allocate memory\n");
		return  -ENOMEM;
	}

	data[0] = tfa98xx->reg;
	memcpy(&data[1], buf, count);

retry:
	ret = i2c_master_send(tfa98xx->i2c, data, count+1);
	if (ret < 0) {
		pr_warn("i2c error, retries left: %d\n", retries);
		if (retries) {
			retries--;
			msleep(I2C_RETRY_DELAY);
			goto retry;
		}
	}

	kfree(data);
	return ret;
}

static ssize_t tfa98xx_rw_read(struct file *filp, struct kobject *kobj,
				struct bin_attribute *bin_attr,
				char *buf, loff_t off, size_t count)
{
	struct device *dev = container_of(kobj, struct device, kobj);
	struct tfa98xx *tfa98xx = dev_get_drvdata(dev);
	struct i2c_msg msgs[] = {
		{
			.addr = tfa98xx->i2c->addr,
			.flags = 0,
			.len = 1,
			.buf = &tfa98xx->reg,
		},
		{
			.addr = tfa98xx->i2c->addr,
			.flags = I2C_M_RD,
			.len = count,
			.buf = buf,
		},
	};
	int ret;
	int retries = I2C_RETRIES;
retry:
	ret = i2c_transfer(tfa98xx->i2c->adapter, msgs, ARRAY_SIZE(msgs));
	if (ret < 0) {
		pr_warn("i2c error, retries left: %d\n", retries);
		if (retries) {
			retries--;
			msleep(I2C_RETRY_DELAY);
			goto retry;
		}
		return ret;
	}
	/* ret contains the number of i2c messages send */
	return 1 + ((ret > 1) ? count : 0);
}

static struct bin_attribute dev_attr_rw = {
	.attr = {
		.name = "rw",
		.mode = S_IRUSR | S_IWUSR,
	},
	.size = 0,
	.read = tfa98xx_rw_read,
	.write = tfa98xx_rw_write,
};

static struct bin_attribute dev_attr_reg = {
	.attr = {
		.name = "reg",
		.mode = S_IWUSR,
	},
	.size = 0,
	.read = NULL,
	.write = tfa98xx_reg_write,
};

static int tfa98xx_i2c_probe(struct i2c_client *i2c,
			     const struct i2c_device_id *id)
{
	struct snd_soc_dai_driver *dai;
	struct tfa98xx *tfa98xx;
	struct device_node *np = i2c->dev.of_node;
	int irq_flags;
	unsigned int reg;
	int ret;

	pr_info("%s\n", __func__);

	if (!i2c_check_functionality(i2c->adapter, I2C_FUNC_I2C)) {
		dev_err(&i2c->dev, "check_functionality failed\n");
		return -EIO;
	}

	tfa98xx = devm_kzalloc(&i2c->dev, sizeof(struct tfa98xx),
		      GFP_KERNEL);
	if (tfa98xx == NULL)
		return -ENOMEM;

	tfa98xx->dev = &i2c->dev;
	tfa98xx->i2c = i2c;
	tfa98xx->dsp_init = TFA98XX_DSP_INIT_STOPPED;
	tfa98xx->rate = 48000; /* init to the default sample rate (48kHz) */

	tfa98xx->regmap = devm_regmap_init_i2c(i2c, &tfa98xx_regmap);
	if (IS_ERR(tfa98xx->regmap)) {
		ret = PTR_ERR(tfa98xx->regmap);
		dev_err(&i2c->dev, "Failed to allocate register map: %d\n",
			ret);
		goto err;
	}

	i2c_set_clientdata(i2c, tfa98xx);
	mutex_init(&tfa98xx->dsp_lock);
	init_waitqueue_head(&tfa98xx->wq);

	if (np) {
		ret = tfa98xx_parse_dt(&i2c->dev, tfa98xx, np);
		if (ret) {
			dev_err(&i2c->dev, "Failed to parse DT node\n");
			goto err;
		}
		if (no_start)
			tfa98xx->irq_gpio = -1;
	} else {
		tfa98xx->reset_gpio = -1;
		tfa98xx->irq_gpio = -1;
	}

	if (gpio_is_valid(tfa98xx->reset_gpio)) {
		ret = devm_gpio_request_one(&i2c->dev, tfa98xx->reset_gpio,
			GPIOF_OUT_INIT_LOW, "TFA98XX_RST");
		if (ret)
			goto err;
	}

	if (gpio_is_valid(tfa98xx->irq_gpio)) {
		ret = devm_gpio_request_one(&i2c->dev, tfa98xx->irq_gpio,
			GPIOF_DIR_IN, "TFA98XX_INT");
		if (ret)
			goto err;
	}

	/* Power up! */
	tfa98xx_ext_reset(tfa98xx);

	if (no_start == 0) {
		ret = regmap_read(tfa98xx->regmap, 0x03, &reg);
		if (ret < 0) {
			dev_err(&i2c->dev, "Failed to read Revision register: %d\n",
				ret);
			return -EIO;
		}
		switch (reg & 0xff) {
		case 0x88: /* tfa9888 */
			pr_info("TFA9888 detected\n");
			tfa98xx->flags |= TFA98XX_FLAG_STEREO_DEVICE;
			tfa98xx->flags |= TFA98XX_FLAG_MULTI_MIC_INPUTS;
			break;
		case 0x80: /* tfa9890 */
		case 0x81: /* tfa9890 */
			pr_info("TFA9890 detected\n");
			tfa98xx->flags |= TFA98XX_FLAG_DSP_START_ON_MUTE;
			tfa98xx->flags |= TFA98XX_FLAG_SKIP_INTERRUPTS;
			tfa98xx->flags |= TFA98XX_FLAG_TFA9890_FAM_DEV;
			break;
		case 0x92: /* tfa9891 */
			pr_info("TFA9891 detected\n");
			tfa98xx->flags |= TFA98XX_FLAG_DSP_START_ON_MUTE;
			tfa98xx->flags |= TFA98XX_FLAG_SAAM_AVAILABLE;
			tfa98xx->flags |= TFA98XX_FLAG_TAPDET_AVAILABLE;
			tfa98xx->flags |= TFA98XX_FLAG_TFA9890_FAM_DEV;
			break;
		case 0x97:
			pr_info("TFA9897 detected\n");
			tfa98xx->flags |= TFA98XX_FLAG_DSP_START_ON_MUTE;
            tfa98xx->flags |= TFA98XX_FLAG_SKIP_INTERRUPTS;
			tfa98xx->flags |= TFA98XX_FLAG_TFA9897_FAM_DEV;
			break;
		default:
			pr_info("Unsupported device revision (0x%x)\n", reg & 0xff);
			return -EINVAL;
		}
	}

	/* Modify the stream names, by appending the i2c device address.
	 * This is used with multicodec, in order to discriminate the devices.
	 * Stream names appear in the dai definition and in the stream  	 .
	 * We create copies of original structures because each device will
	 * have its own instance of this structure, with its own address.
	 */
	dai = devm_kzalloc(&i2c->dev, sizeof(tfa98xx_dai), GFP_KERNEL);
	if (!dai)
		return -ENOMEM;
	memcpy(dai, tfa98xx_dai, sizeof(tfa98xx_dai));

	tfa98xx_append_i2c_address(&i2c->dev,
				i2c,
				NULL,
				0,
				dai,
				ARRAY_SIZE(tfa98xx_dai));

	ret = snd_soc_register_codec(&i2c->dev,
				&soc_codec_dev_tfa98xx, dai,
				ARRAY_SIZE(tfa98xx_dai));

	if (ret < 0) {
		dev_err(&i2c->dev, "Failed to register TFA98xx: %d\n", ret);
		goto err_off;
	}

	if (gpio_is_valid(tfa98xx->irq_gpio) &&
		!(tfa98xx->flags & TFA98XX_FLAG_SKIP_INTERRUPTS)) {
		/* register irq handler */
		irq_flags = IRQF_TRIGGER_FALLING | IRQF_ONESHOT;
		ret = devm_request_threaded_irq(&i2c->dev,
					gpio_to_irq(tfa98xx->irq_gpio),
					NULL, tfa98xx_irq, irq_flags,
					"tfa98xx", tfa98xx);
		if (ret != 0) {
			dev_err(&i2c->dev, "Failed to request IRQ %d: %d\n",
					gpio_to_irq(tfa98xx->irq_gpio), ret);
			goto err_off;
		}
		tfa98xx_interrupt_setup(tfa98xx);
	} else {
		dev_info(&i2c->dev, "Skipping IRQ registration\n");
		/* disable feature support if gpio was invalid */
		tfa98xx->flags |= TFA98XX_FLAG_SKIP_INTERRUPTS;
	}

/*zhiguang.su@MultiMedia.AudioDrv, 2014-4-14, add for bob power*/
	pr_err("%s request bob power\n", __func__);
	bob_power = NULL;
	bob_power = regulator_get(&i2c->dev, "bob_power");
	if (IS_ERR(bob_power))
		pr_err("%s request bob power error!\n", __func__);


#ifdef CONFIG_DEBUG_FS
	tfa98xx_debug_init(tfa98xx, i2c);
#endif
	/* Register the sysfs files for climax backdoor access */
	ret = device_create_bin_file(&i2c->dev, &dev_attr_rw);
	if (ret)
		dev_info(&i2c->dev, "error creating sysfs files\n");
	ret = device_create_bin_file(&i2c->dev, &dev_attr_reg);
	if (ret)
		dev_info(&i2c->dev, "error creating sysfs files\n");

	pr_info("%s Probe completed successfully!\n", __func__);

    ret = sysfs_create_file(&i2c->dev.kobj, &tfa98xx_state_attr.attr);
    if(ret < 0)
    {
        pr_err("%s sysfs_create_file tfa98xx_state_attr err.",__func__);
    }
	ret = sysfs_create_file(&i2c->dev.kobj, &tfa98xx_Log_state_attr.attr);
    if(ret < 0)
    {
        pr_err("%s sysfs_create_file tfa98xx_Log_state_attr err.",__func__);
    }

	return 0;

err_off:
	tfa98xx_unregister_dsp(tfa98xx);
err:
	return ret;
}

static int tfa98xx_i2c_remove(struct i2c_client *i2c)
{
	struct tfa98xx *tfa98xx = i2c_get_clientdata(i2c);

	pr_err("\n");

	cancel_delayed_work_sync(&tfa98xx->interrupt_work);
	cancel_delayed_work_sync(&tfa98xx->init_work);
	cancel_delayed_work_sync(&tfa98xx->tapdet_work);

	device_remove_bin_file(&i2c->dev, &dev_attr_reg);
	device_remove_bin_file(&i2c->dev, &dev_attr_rw);
#ifdef CONFIG_DEBUG_FS
	tfa98xx_debug_remove(tfa98xx);
#endif

	tfa98xx_unregister_dsp(tfa98xx);

	snd_soc_unregister_codec(&i2c->dev);

	if (gpio_is_valid(tfa98xx->irq_gpio))
		devm_gpio_free(&i2c->dev, tfa98xx->irq_gpio);
	if (gpio_is_valid(tfa98xx->reset_gpio))
		devm_gpio_free(&i2c->dev, tfa98xx->reset_gpio);

	return 0;
}

static const struct i2c_device_id tfa98xx_i2c_id[] = {
	{ "tfa98xx", 0 },
	{ }
};
MODULE_DEVICE_TABLE(i2c, tfa98xx_i2c_id);

#ifdef CONFIG_OF
static struct of_device_id tfa98xx_dt_match[] = {
	{ .compatible = "nxp,tfa98xx" },
	{ .compatible = "nxp,tfa9890" },
	{ .compatible = "nxp,tfa9891" },
	{ .compatible = "nxp,tfa9888" },
	{ },
};
#endif

static struct i2c_driver tfa98xx_i2c_driver = {
	.driver = {
		.name = "tfa98xx",
		.owner = THIS_MODULE,
		.of_match_table = of_match_ptr(tfa98xx_dt_match),
	},
	.probe =    tfa98xx_i2c_probe,
	.remove =   tfa98xx_i2c_remove,
	.id_table = tfa98xx_i2c_id,
};

static int trace_level = 1;
module_param(trace_level, int, S_IRUGO);
MODULE_PARM_DESC(trace_level, "TFA98xx debug trace level (0=off, bits:1=verbose,2=regdmesg,3=regftrace).");
static int __init tfa98xx_i2c_init(void)
{
	int ret = 0;

	pr_info("TFA98XX driver version %s\n", TFA98XX_VERSION);

	/* Enable debug traces */
	tfa_verbose(trace_level);
	tfa98xx_kmsg_regs = trace_level & 2;
	tfa98xx_ftrace_regs = trace_level & 4;

	ret = i2c_add_driver(&tfa98xx_i2c_driver);

	return ret;
}
module_init(tfa98xx_i2c_init);


static void __exit tfa98xx_i2c_exit(void)
{
	i2c_del_driver(&tfa98xx_i2c_driver);

	kfree(container);
}
module_exit(tfa98xx_i2c_exit);

MODULE_DESCRIPTION("ASoC TFA98XX driver");
MODULE_LICENSE("GPL");



