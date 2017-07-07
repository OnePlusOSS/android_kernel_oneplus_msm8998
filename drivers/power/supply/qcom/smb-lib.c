/* Copyright (c) 2016-2017 The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
/* david.liu@bsp, 20161014 Add charging standard */
#define pr_fmt(fmt) "SMBLIB: %s: " fmt, __func__

#include <linux/device.h>
#include <linux/regmap.h>
#include <linux/delay.h>
#include <linux/iio/consumer.h>
#include <linux/power_supply.h>
#include <linux/regulator/driver.h>
#include <linux/qpnp/qpnp-revid.h>
#include <linux/input/qpnp-power-on.h>
#include <linux/irq.h>
#include "smb-lib.h"
#include "smb-reg.h"
#include "storm-watch.h"
#include <linux/pmic-voter.h>

/* david.liu@bsp, 20160926 Add dash charging */
#include <linux/power/oem_external_fg.h>
#include <linux/gpio.h>
#include <linux/delay.h>
#include <linux/input/qpnp-power-on.h>
#include <linux/spmi.h>
#if defined(CONFIG_FB)
#include <linux/notifier.h>
#include <linux/fb.h>
#endif /*CONFIG_FB*/

#define SOC_INVALID                   0x7E
#define SOC_DATA_REG_0                0x88D
#define HEARTBEAT_INTERVAL_MS         6000
#define CHG_TIMEOUT_COUNT             10 * 10 * 60 /* 10hr */
#define CHG_SOFT_OVP_MV               5800
#define BATT_SOFT_OVP_MV              4500
#define CHG_SOFT_UVP_MV               4300
#define CHG_VOLTAGE_NORMAL            5000
#define BATT_REMOVE_TEMP              -400
#define BATT_TEMP_HYST                20

struct smb_charger *g_chg;
struct qpnp_pon *pm_pon;

static struct external_battery_gauge *fast_charger = NULL;
static int op_charging_en(struct smb_charger *chg, bool en);
bool op_set_fast_chg_allow(struct smb_charger *chg, bool enable);
bool get_prop_fast_chg_started(struct smb_charger *chg);
static bool set_prop_fast_switch_to_normal_false(struct smb_charger *chg);

extern void mcu_en_gpio_set(int value);
extern void usb_sw_gpio_set(int value);
extern void set_mcu_en_gpio_value(int value);
static void op_battery_temp_region_set(struct smb_charger *chg,
		temp_region_type batt_temp_region);
static void set_usb_switch(struct smb_charger *chg, bool enable);
static void op_handle_usb_removal(struct smb_charger *chg);
static bool get_prop_fast_switch_to_normal(struct smb_charger *chg);
static int get_prop_batt_temp(struct smb_charger *chg);
static int get_prop_batt_capacity(struct smb_charger *chg);
static int get_prop_batt_current_now(struct smb_charger *chg);
static int get_prop_batt_voltage_now(struct smb_charger *chg);
static int set_property_on_fg(struct smb_charger *chg,
		enum power_supply_property prop, int val);
static int set_dash_charger_present(int status);
static temp_region_type
		op_battery_temp_region_get(struct smb_charger *chg);
static int get_prop_fg_capacity(struct smb_charger *chg);
static int get_prop_fg_current_now(struct smb_charger *chg);
static int get_prop_fg_voltage_now(struct smb_charger *chg);
static void op_check_charger_collapse(struct smb_charger *chg);
static int op_set_collapse_fet(struct smb_charger *chg, bool on);

#define smblib_err(chg, fmt, ...)		\
	pr_err("%s: %s: " fmt, chg->name,	\
		__func__, ##__VA_ARGS__)	\

#define smblib_dbg(chg, reason, fmt, ...)			\
	do {							\
		if (*chg->debug_mask & (reason))		\
			pr_info("%s: %s: " fmt, chg->name,	\
				__func__, ##__VA_ARGS__);	\
		else						\
			pr_debug("%s: %s: " fmt, chg->name,	\
				__func__, ##__VA_ARGS__);	\
	} while (0)

static bool is_secure(struct smb_charger *chg, int addr)
{
	if (addr == SHIP_MODE_REG || addr == FREQ_CLK_DIV_REG)
		return true;
	/* assume everything above 0xA0 is secure */
	return (bool)((addr & 0xFF) >= 0xA0);
}

int smblib_read(struct smb_charger *chg, u16 addr, u8 *val)
{
	unsigned int temp;
	int rc = 0;

	rc = regmap_read(chg->regmap, addr, &temp);
	if (rc >= 0)
		*val = (u8)temp;

	return rc;
}

int smblib_multibyte_read(struct smb_charger *chg, u16 addr, u8 *val,
				int count)
{
	return regmap_bulk_read(chg->regmap, addr, val, count);
}

int smblib_masked_write(struct smb_charger *chg, u16 addr, u8 mask, u8 val)
{
	int rc = 0;

	mutex_lock(&chg->write_lock);
	if (is_secure(chg, addr)) {
		rc = regmap_write(chg->regmap, (addr & 0xFF00) | 0xD0, 0xA5);
		if (rc < 0)
			goto unlock;
	}

	rc = regmap_update_bits(chg->regmap, addr, mask, val);

unlock:
	mutex_unlock(&chg->write_lock);
	return rc;
}

int smblib_write(struct smb_charger *chg, u16 addr, u8 val)
{
	int rc = 0;

	mutex_lock(&chg->write_lock);

	if (is_secure(chg, addr)) {
		rc = regmap_write(chg->regmap, (addr & ~(0xFF)) | 0xD0, 0xA5);
		if (rc < 0)
			goto unlock;
	}

	rc = regmap_write(chg->regmap, addr, val);

unlock:
	mutex_unlock(&chg->write_lock);
	return rc;
}

static int smblib_get_step_cc_delta(struct smb_charger *chg, int *cc_delta_ua)
{
	int rc, step_state;
	u8 stat;

	if (!chg->step_chg_enabled) {
		*cc_delta_ua = 0;
		return 0;
	}

	rc = smblib_read(chg, BATTERY_CHARGER_STATUS_1_REG, &stat);
	if (rc < 0) {
		smblib_err(chg, "Couldn't read BATTERY_CHARGER_STATUS_1 rc=%d\n",
			rc);
		return rc;
	}

	step_state = (stat & STEP_CHARGING_STATUS_MASK) >>
				STEP_CHARGING_STATUS_SHIFT;
	rc = smblib_get_charge_param(chg, &chg->param.step_cc_delta[step_state],
				     cc_delta_ua);
	if (rc < 0) {
		smblib_err(chg, "Couldn't get step cc delta rc=%d\n", rc);
		return rc;
	}

	return 0;
}

static int smblib_get_jeita_cc_delta(struct smb_charger *chg, int *cc_delta_ua)
{
	int rc, cc_minus_ua;
	u8 stat;

	rc = smblib_read(chg, BATTERY_CHARGER_STATUS_2_REG, &stat);
	if (rc < 0) {
		smblib_err(chg, "Couldn't read BATTERY_CHARGER_STATUS_2 rc=%d\n",
			rc);
		return rc;
	}

	if (!(stat & BAT_TEMP_STATUS_SOFT_LIMIT_MASK)) {
		*cc_delta_ua = 0;
		return 0;
	}

	rc = smblib_get_charge_param(chg, &chg->param.jeita_cc_comp,
				     &cc_minus_ua);
	if (rc < 0) {
		smblib_err(chg, "Couldn't get jeita cc minus rc=%d\n", rc);
		return rc;
	}

	*cc_delta_ua = -cc_minus_ua;
	return 0;
}

int smblib_icl_override(struct smb_charger *chg, bool override)
{
	int rc;

	rc = smblib_masked_write(chg, USBIN_LOAD_CFG_REG,
				ICL_OVERRIDE_AFTER_APSD_BIT,
				override ? ICL_OVERRIDE_AFTER_APSD_BIT : 0);
	if (rc < 0)
		smblib_err(chg, "Couldn't override ICL rc=%d\n", rc);

	return rc;
}

/********************
 * REGISTER GETTERS *
 ********************/

int smblib_get_charge_param(struct smb_charger *chg,
			    struct smb_chg_param *param, int *val_u)
{
	int rc = 0;
	u8 val_raw;

	rc = smblib_read(chg, param->reg, &val_raw);
	if (rc < 0) {
		smblib_err(chg, "%s: Couldn't read from 0x%04x rc=%d\n",
			param->name, param->reg, rc);
		return rc;
	}

	if (param->get_proc)
		*val_u = param->get_proc(param, val_raw);
	else
		*val_u = val_raw * param->step_u + param->min_u;
	smblib_dbg(chg, PR_REGISTER, "%s = %d (0x%02x)\n",
		   param->name, *val_u, val_raw);

	return rc;
}

int smblib_get_usb_suspend(struct smb_charger *chg, int *suspend)
{
	int rc = 0;
	u8 temp;

	rc = smblib_read(chg, USBIN_CMD_IL_REG, &temp);
	if (rc < 0) {
		smblib_err(chg, "Couldn't read USBIN_CMD_IL rc=%d\n", rc);
		return rc;
	}
	*suspend = temp & USBIN_SUSPEND_BIT;

	return rc;
}

struct apsd_result {
	const char * const name;
	const u8 bit;
	const enum power_supply_type pst;
};

enum {
	UNKNOWN,
	SDP,
	CDP,
	DCP,
	OCP,
	FLOAT,
	HVDCP2,
	HVDCP3,
	MAX_TYPES
};

static const struct apsd_result const smblib_apsd_results[] = {
	[UNKNOWN] = {
		.name	= "UNKNOWN",
		.bit	= 0,
		.pst	= POWER_SUPPLY_TYPE_UNKNOWN
	},
	[SDP] = {
		.name	= "SDP",
		.bit	= SDP_CHARGER_BIT,
		.pst	= POWER_SUPPLY_TYPE_USB
	},
	[CDP] = {
		.name	= "CDP",
		.bit	= CDP_CHARGER_BIT,
		.pst	= POWER_SUPPLY_TYPE_USB_CDP
	},
	[DCP] = {
		.name	= "DCP",
		.bit	= DCP_CHARGER_BIT,
		.pst	= POWER_SUPPLY_TYPE_USB_DCP
	},
	[OCP] = {
		.name	= "OCP",
		.bit	= OCP_CHARGER_BIT,
		.pst	= POWER_SUPPLY_TYPE_USB_DCP
	},
	[FLOAT] = {
		.name	= "FLOAT",
		.bit	= FLOAT_CHARGER_BIT,
		.pst	= POWER_SUPPLY_TYPE_USB_DCP
	},
	[HVDCP2] = {
		.name	= "HVDCP2",
		.bit	= DCP_CHARGER_BIT | QC_2P0_BIT,
		.pst	= POWER_SUPPLY_TYPE_USB_HVDCP
	},
	[HVDCP3] = {
		.name	= "HVDCP3",
		.bit	= DCP_CHARGER_BIT | QC_3P0_BIT,
		.pst	= POWER_SUPPLY_TYPE_USB_HVDCP_3,
	},
};

static const struct apsd_result *smblib_get_apsd_result(struct smb_charger *chg)
{
	int rc, i;
	u8 apsd_stat, stat;
	const struct apsd_result *result = &smblib_apsd_results[UNKNOWN];

	rc = smblib_read(chg, APSD_STATUS_REG, &apsd_stat);
	if (rc < 0) {
		smblib_err(chg, "Couldn't read APSD_STATUS rc=%d\n", rc);
		return result;
	}
	smblib_dbg(chg, PR_REGISTER, "APSD_STATUS = 0x%02x\n", apsd_stat);
	if (!(apsd_stat & APSD_DTC_STATUS_DONE_BIT)) {
		pr_info("APSD_DTC_STATUS_DONE_BIT is 0\n");
		return result;
	}
	rc = smblib_read(chg, APSD_RESULT_STATUS_REG, &stat);
	if (rc < 0) {
		smblib_err(chg, "Couldn't read APSD_RESULT_STATUS rc=%d\n",
			rc);
		return result;
	}
	stat &= APSD_RESULT_STATUS_MASK;

	for (i = 0; i < ARRAY_SIZE(smblib_apsd_results); i++) {
		if (smblib_apsd_results[i].bit == stat)
			result = &smblib_apsd_results[i];
	}

	if (apsd_stat & QC_CHARGER_BIT) {
		/* since its a qc_charger, either return HVDCP3 or HVDCP2 */
		if (result != &smblib_apsd_results[HVDCP3])
			result = &smblib_apsd_results[HVDCP2];
	}

	return result;
}

/********************
 * REGISTER SETTERS *
 ********************/

static int chg_freq_list[] = {
	9600, 9600, 6400, 4800, 3800, 3200, 2700, 2400, 2100, 1900, 1700,
	1600, 1500, 1400, 1300, 1200,
};

int smblib_set_chg_freq(struct smb_chg_param *param,
				int val_u, u8 *val_raw)
{
	u8 i;

	if (val_u > param->max_u || val_u < param->min_u)
		return -EINVAL;

	/* Charger FSW is the configured freqency / 2 */
	val_u *= 2;
	for (i = 0; i < ARRAY_SIZE(chg_freq_list); i++) {
		if (chg_freq_list[i] == val_u)
			break;
	}
	if (i == ARRAY_SIZE(chg_freq_list)) {
		pr_err("Invalid frequency %d Hz\n", val_u / 2);
		return -EINVAL;
	}

	*val_raw = i;

	return 0;
}

static int smblib_set_opt_freq_buck(struct smb_charger *chg, int fsw_khz)
{
	union power_supply_propval pval = {0, };
	int rc = 0;

	rc = smblib_set_charge_param(chg, &chg->param.freq_buck, fsw_khz);
	if (rc < 0)
		dev_err(chg->dev, "Error in setting freq_buck rc=%d\n", rc);

	if (chg->mode == PARALLEL_MASTER && chg->pl.psy) {
		pval.intval = fsw_khz;
		/*
		 * Some parallel charging implementations may not have
		 * PROP_BUCK_FREQ property - they could be running
		 * with a fixed frequency
		 */
		power_supply_set_property(chg->pl.psy,
				POWER_SUPPLY_PROP_BUCK_FREQ, &pval);
	}

	return rc;
}

int smblib_set_charge_param(struct smb_charger *chg,
			    struct smb_chg_param *param, int val_u)
{
	int rc = 0;
	u8 val_raw;

	if (param->set_proc) {
		rc = param->set_proc(param, val_u, &val_raw);
		if (rc < 0)
			return -EINVAL;
	} else {
		if (val_u > param->max_u || val_u < param->min_u) {
			smblib_err(chg, "%s: %d is out of range [%d, %d]\n",
				param->name, val_u, param->min_u, param->max_u);
			return -EINVAL;
		}

		val_raw = (val_u - param->min_u) / param->step_u;
	}

	rc = smblib_write(chg, param->reg, val_raw);
	if (rc < 0) {
		smblib_err(chg, "%s: Couldn't write 0x%02x to 0x%04x rc=%d\n",
			param->name, val_raw, param->reg, rc);
		return rc;
	}

	smblib_dbg(chg, PR_REGISTER, "%s = %d (0x%02x)\n",
		   param->name, val_u, val_raw);

	return rc;
}

static int step_charge_soc_update(struct smb_charger *chg, int capacity)
{
	int rc = 0;

	rc = smblib_set_charge_param(chg, &chg->param.step_soc, capacity);
	if (rc < 0) {
		smblib_err(chg, "Error in updating soc, rc=%d\n", rc);
		return rc;
	}

	rc = smblib_write(chg, STEP_CHG_SOC_VBATT_V_UPDATE_REG,
			STEP_CHG_SOC_VBATT_V_UPDATE_BIT);
	if (rc < 0) {
		smblib_err(chg,
			"Couldn't set STEP_CHG_SOC_VBATT_V_UPDATE_REG rc=%d\n",
			rc);
		return rc;
	}

	return rc;
}

int smblib_set_usb_suspend(struct smb_charger *chg, bool suspend)
{
	int rc = 0;

	pr_info("suspend=%d\n", suspend);
	rc = smblib_masked_write(chg, USBIN_CMD_IL_REG, USBIN_SUSPEND_BIT,
				 suspend ? USBIN_SUSPEND_BIT : 0);
	if (rc < 0)
		smblib_err(chg, "Couldn't write %s to USBIN_SUSPEND_BIT rc=%d\n",
			suspend ? "suspend" : "resume", rc);

	return rc;
}

int smblib_set_dc_suspend(struct smb_charger *chg, bool suspend)
{
	int rc = 0;

	rc = smblib_masked_write(chg, DCIN_CMD_IL_REG, DCIN_SUSPEND_BIT,
				 suspend ? DCIN_SUSPEND_BIT : 0);
	if (rc < 0)
		smblib_err(chg, "Couldn't write %s to DCIN_SUSPEND_BIT rc=%d\n",
			suspend ? "suspend" : "resume", rc);

	return rc;
}

static int smblib_set_adapter_allowance(struct smb_charger *chg,
					u8 allowed_voltage)
{
	int rc = 0;

	switch (allowed_voltage) {
	case USBIN_ADAPTER_ALLOW_12V:
	case USBIN_ADAPTER_ALLOW_5V_OR_12V:
	case USBIN_ADAPTER_ALLOW_9V_TO_12V:
	case USBIN_ADAPTER_ALLOW_5V_OR_9V_TO_12V:
	case USBIN_ADAPTER_ALLOW_5V_TO_12V:
		/* PM660 only support max. 9V */
		if (chg->smb_version == PM660_SUBTYPE) {
			smblib_dbg(chg, PR_MISC, "voltage not supported=%d\n",
					allowed_voltage);
			allowed_voltage = USBIN_ADAPTER_ALLOW_5V_OR_9V;
		}
		break;
	}

	rc = smblib_write(chg, USBIN_ADAPTER_ALLOW_CFG_REG, allowed_voltage);
	if (rc < 0) {
		smblib_err(chg, "Couldn't write 0x%02x to USBIN_ADAPTER_ALLOW_CFG rc=%d\n",
			allowed_voltage, rc);
		return rc;
	}

	return rc;
}

#define MICRO_5V	5000000
#define MICRO_9V	9000000
#define MICRO_12V	12000000
static int smblib_set_usb_pd_allowed_voltage(struct smb_charger *chg,
					int min_allowed_uv, int max_allowed_uv)
{
	int rc;
	u8 allowed_voltage;

	if (min_allowed_uv == MICRO_5V && max_allowed_uv == MICRO_5V) {
		allowed_voltage = USBIN_ADAPTER_ALLOW_5V;
		smblib_set_opt_freq_buck(chg, chg->chg_freq.freq_5V);
	} else if (min_allowed_uv == MICRO_9V && max_allowed_uv == MICRO_9V) {
		allowed_voltage = USBIN_ADAPTER_ALLOW_9V;
		smblib_set_opt_freq_buck(chg, chg->chg_freq.freq_9V);
	} else if (min_allowed_uv == MICRO_12V && max_allowed_uv == MICRO_12V) {
		allowed_voltage = USBIN_ADAPTER_ALLOW_12V;
		smblib_set_opt_freq_buck(chg, chg->chg_freq.freq_12V);
	} else if (min_allowed_uv < MICRO_9V && max_allowed_uv <= MICRO_9V) {
		allowed_voltage = USBIN_ADAPTER_ALLOW_5V_TO_9V;
	} else if (min_allowed_uv < MICRO_9V && max_allowed_uv <= MICRO_12V) {
		allowed_voltage = USBIN_ADAPTER_ALLOW_5V_TO_12V;
	} else if (min_allowed_uv < MICRO_12V && max_allowed_uv <= MICRO_12V) {
		allowed_voltage = USBIN_ADAPTER_ALLOW_9V_TO_12V;
	} else {
		smblib_err(chg, "invalid allowed voltage [%d, %d]\n",
			min_allowed_uv, max_allowed_uv);
		return -EINVAL;
	}

	rc = smblib_set_adapter_allowance(chg, allowed_voltage);
	if (rc < 0) {
		smblib_err(chg, "Couldn't configure adapter allowance rc=%d\n",
				rc);
		return rc;
	}

	return rc;
}

/********************
 * HELPER FUNCTIONS *
 ********************/

static void smblib_rerun_apsd(struct smb_charger *chg)
{
	int rc;

	smblib_dbg(chg, PR_MISC, "re-running APSD\n");
	if (chg->wa_flags & QC_AUTH_INTERRUPT_WA_BIT) {
		rc = smblib_masked_write(chg,
				USBIN_SOURCE_CHANGE_INTRPT_ENB_REG,
				AUTH_IRQ_EN_CFG_BIT, AUTH_IRQ_EN_CFG_BIT);
		if (rc < 0)
			smblib_err(chg, "Couldn't enable HVDCP auth IRQ rc=%d\n",
									rc);
	}

	rc = smblib_masked_write(chg, CMD_APSD_REG,
				APSD_RERUN_BIT, APSD_RERUN_BIT);
	if (rc < 0)
		smblib_err(chg, "Couldn't re-run APSD rc=%d\n", rc);
}

static const struct apsd_result *smblib_update_usb_type(struct smb_charger *chg)
{
	const struct apsd_result *apsd_result = smblib_get_apsd_result(chg);

	/* if PD is active, APSD is disabled so won't have a valid result */
	if (chg->pd_active)
		chg->usb_psy_desc.type = POWER_SUPPLY_TYPE_USB_PD;
	if(chg->dash_on)
		chg->usb_psy_desc.type = POWER_SUPPLY_TYPE_DASH;
	else
		chg->usb_psy_desc.type = apsd_result->pst;
	smblib_dbg(chg, PR_MISC, "APSD=%s PD=%d\n",
					apsd_result->name, chg->pd_active);

	return apsd_result;
}

static int smblib_notifier_call(struct notifier_block *nb,
		unsigned long ev, void *v)
{
	struct power_supply *psy = v;
	struct smb_charger *chg = container_of(nb, struct smb_charger, nb);

	if (!strcmp(psy->desc->name, "bms")) {
		if (!chg->bms_psy)
			chg->bms_psy = psy;
		if (ev == PSY_EVENT_PROP_CHANGED)
			schedule_work(&chg->bms_update_work);
	}

	if (!chg->pl.psy && !strcmp(psy->desc->name, "parallel"))
		chg->pl.psy = psy;

	return NOTIFY_OK;
}

static int smblib_register_notifier(struct smb_charger *chg)
{
	int rc;

	chg->nb.notifier_call = smblib_notifier_call;
	rc = power_supply_reg_notifier(&chg->nb);
	if (rc < 0) {
		smblib_err(chg, "Couldn't register psy notifier rc = %d\n", rc);
		return rc;
	}

	return 0;
}

int smblib_mapping_soc_from_field_value(struct smb_chg_param *param,
					     int val_u, u8 *val_raw)
{
	if (val_u > param->max_u || val_u < param->min_u)
		return -EINVAL;

	*val_raw = val_u << 1;

	return 0;
}

int smblib_mapping_cc_delta_to_field_value(struct smb_chg_param *param,
					   u8 val_raw)
{
	int val_u  = val_raw * param->step_u + param->min_u;

	if (val_u > param->max_u)
		val_u -= param->max_u * 2;

	return val_u;
}

int smblib_mapping_cc_delta_from_field_value(struct smb_chg_param *param,
					     int val_u, u8 *val_raw)
{
	if (val_u > param->max_u || val_u < param->min_u - param->max_u)
		return -EINVAL;

	val_u += param->max_u * 2 - param->min_u;
	val_u %= param->max_u * 2;
	*val_raw = val_u / param->step_u;

	return 0;
}

static void smblib_uusb_removal(struct smb_charger *chg)
{
	int rc;

	/* reset both usbin current and voltage votes */
	vote(chg->pl_enable_votable_indirect, USBIN_I_VOTER, false, 0);
	vote(chg->pl_enable_votable_indirect, USBIN_V_VOTER, false, 0);
	vote(chg->pl_disable_votable, PL_DELAY_HVDCP_VOTER, true, 0);

	cancel_delayed_work_sync(&chg->hvdcp_detect_work);

	if (chg->wa_flags & QC_AUTH_INTERRUPT_WA_BIT) {
		/* re-enable AUTH_IRQ_EN_CFG_BIT */
		rc = smblib_masked_write(chg,
				USBIN_SOURCE_CHANGE_INTRPT_ENB_REG,
				AUTH_IRQ_EN_CFG_BIT, AUTH_IRQ_EN_CFG_BIT);
		if (rc < 0)
			smblib_err(chg,
				"Couldn't enable QC auth setting rc=%d\n", rc);
	}

	/* reconfigure allowed voltage for HVDCP */
	rc = smblib_set_adapter_allowance(chg,
			USBIN_ADAPTER_ALLOW_5V_OR_9V_TO_12V);
	if (rc < 0)
		smblib_err(chg, "Couldn't set USBIN_ADAPTER_ALLOW_5V_OR_9V_TO_12V rc=%d\n",
			rc);

	chg->voltage_min_uv = MICRO_5V;
	chg->voltage_max_uv = MICRO_5V;
	chg->usb_icl_delta_ua = 0;
	chg->pulse_cnt = 0;

	/* clear USB ICL vote for USB_PSY_VOTER */
	rc = vote(chg->usb_icl_votable, USB_PSY_VOTER, false, 0);
	if (rc < 0)
		smblib_err(chg, "Couldn't un-vote for USB ICL rc=%d\n", rc);

	/* clear USB ICL vote for DCP_VOTER */
	rc = vote(chg->usb_icl_votable, DCP_VOTER, false, 0);
	if (rc < 0)
		smblib_err(chg,
			"Couldn't un-vote DCP from USB ICL rc=%d\n", rc);

	/* clear USB ICL vote for PL_USBIN_USBIN_VOTER */
	rc = vote(chg->usb_icl_votable, PL_USBIN_USBIN_VOTER, false, 0);
	if (rc < 0)
		smblib_err(chg,
			"Couldn't un-vote PL_USBIN_USBIN from USB ICL rc=%d\n",
			rc);
}

void smblib_suspend_on_debug_battery(struct smb_charger *chg)
{
	int rc;
	union power_supply_propval val;

	if (!chg->suspend_input_on_debug_batt)
		return;

	rc = power_supply_get_property(chg->bms_psy,
			POWER_SUPPLY_PROP_DEBUG_BATTERY, &val);
	if (rc < 0) {
		smblib_err(chg, "Couldn't get debug battery prop rc=%d\n", rc);
		return;
	}

	vote(chg->usb_icl_votable, DEBUG_BOARD_VOTER, val.intval, 0);
	vote(chg->dc_suspend_votable, DEBUG_BOARD_VOTER, val.intval, 0);
	if (val.intval)
		pr_info("Input suspended: Fake battery\n");
}

int smblib_rerun_apsd_if_required(struct smb_charger *chg)
{
	const struct apsd_result *apsd_result;
	union power_supply_propval val;
	int rc;

	rc = smblib_get_prop_usb_present(chg, &val);
	if (rc < 0) {
		smblib_err(chg, "Couldn't get usb present rc = %d\n", rc);
		return rc;
	}

	if (!val.intval)
		return 0;

	apsd_result = smblib_get_apsd_result(chg);
	if ((apsd_result->pst != POWER_SUPPLY_TYPE_UNKNOWN)
		&& (apsd_result->pst != POWER_SUPPLY_TYPE_USB)
		&& (apsd_result->pst != POWER_SUPPLY_TYPE_USB_CDP)
		&& (apsd_result->bit != FLOAT_CHARGER_BIT))
		return 0;

	/* fetch the DPDM regulator */
	if (!chg->dpdm_reg && of_get_property(chg->dev->of_node,
						"dpdm-supply", NULL)) {
		chg->dpdm_reg = devm_regulator_get(chg->dev, "dpdm");
		if (IS_ERR(chg->dpdm_reg)) {
			smblib_err(chg, "Couldn't get dpdm regulator rc=%ld\n",
				PTR_ERR(chg->dpdm_reg));
			chg->dpdm_reg = NULL;
		}
	}

	if (chg->dpdm_reg && !regulator_is_enabled(chg->dpdm_reg)) {
		smblib_dbg(chg, PR_MISC, "enabling DPDM regulator\n");
		rc = regulator_enable(chg->dpdm_reg);
		if (rc < 0)
			smblib_err(chg, "Couldn't enable dpdm regulator rc=%d\n",
				rc);
	}
	smblib_rerun_apsd(chg);
	return 0;
}

static int smblib_get_pulse_cnt(struct smb_charger *chg, int *count)
{
	int rc;
	u8 val[2];

	switch (chg->smb_version) {
	case PMI8998_SUBTYPE:
		rc = smblib_read(chg, QC_PULSE_COUNT_STATUS_REG, val);
		if (rc) {
			pr_err("failed to read QC_PULSE_COUNT_STATUS_REG rc=%d\n",
					rc);
			return rc;
		}
		*count = val[0] & QC_PULSE_COUNT_MASK;
		break;
	case PM660_SUBTYPE:
		rc = smblib_multibyte_read(chg,
				QC_PULSE_COUNT_STATUS_1_REG, val, 2);
		if (rc) {
			pr_err("failed to read QC_PULSE_COUNT_STATUS_1_REG rc=%d\n",
					rc);
			return rc;
		}
		*count = (val[1] << 8) | val[0];
		break;
	default:
		smblib_dbg(chg, PR_PARALLEL, "unknown SMB chip %d\n",
				chg->smb_version);
		return -EINVAL;
	}

	return 0;
}

/*********************
 * VOTABLE CALLBACKS *
 *********************/


static int smblib_dc_suspend_vote_callback(struct votable *votable, void *data,
			int suspend, const char *client)
{
	struct smb_charger *chg = data;

	/* resume input if suspend is invalid */
	if (suspend < 0)
		suspend = 0;

	return smblib_set_dc_suspend(chg, (bool)suspend);
}

#define USBIN_25MA	25000
#define USBIN_100MA	100000
#define USBIN_150MA	150000
#define USBIN_500MA	500000
#define USBIN_900MA	900000

static int set_sdp_current(struct smb_charger *chg, int icl_ua)
{
	int rc;
	u8 icl_options;

	// AP: Fast charge for USB
	if (icl_ua == USBIN_500MA)
	{
		icl_ua = USBIN_900MA;
		pr_info("Boeffla-Kernel: Trigger USB fast charge with 900mA\n");
	}

	/* power source is SDP */
	switch (icl_ua) {
	case USBIN_100MA:
		/* USB 2.0 100mA */
		icl_options = 0;
		break;
	case USBIN_150MA:
		/* USB 3.0 150mA */
		icl_options = CFG_USB3P0_SEL_BIT;
		break;
	case USBIN_500MA:
		/* USB 2.0 500mA */
		icl_options = USB51_MODE_BIT;
		break;
	case USBIN_900MA:
		/* USB 3.0 900mA */
		icl_options = CFG_USB3P0_SEL_BIT | USB51_MODE_BIT;
		break;
	default:
		smblib_err(chg, "ICL %duA isn't supported for SDP\n", icl_ua);
		return -EINVAL;
	}

	rc = smblib_masked_write(chg, USBIN_ICL_OPTIONS_REG,
		CFG_USB3P0_SEL_BIT | USB51_MODE_BIT, icl_options);
	if (rc < 0) {
		smblib_err(chg, "Couldn't set ICL options rc=%d\n", rc);
		return rc;
	}

	return rc;
}
int op_usb_icl_set(struct smb_charger *chg, int icl_ua)
{
	int rc = 0;
	bool override;
	pr_info("%s,icl_ua=%d\n", __func__, icl_ua);
	disable_irq_nosync(chg->irq_info[USBIN_ICL_CHANGE_IRQ].irq);
	rc = smblib_set_charge_param(chg, &chg->param.usb_icl,
			icl_ua - chg->icl_reduction_ua);
	if (rc < 0) {
		smblib_err(chg, "Couldn't set HC ICL rc=%d\n", rc);
		goto enable_icl_changed_interrupt;
	}

	/* determine if override needs to be enforced */
	override = true;
	/* enforce override */
	rc = smblib_masked_write(chg, USBIN_ICL_OPTIONS_REG,
		USBIN_MODE_CHG_BIT, override ? USBIN_MODE_CHG_BIT : 0);

	rc = smblib_icl_override(chg, override);
	if (rc < 0) {
		smblib_err(chg, "Couldn't set ICL override rc=%d\n", rc);
		goto enable_icl_changed_interrupt;
	}

	/* unsuspend after configuring current and override */
	rc = smblib_set_usb_suspend(chg, false);
	if (rc < 0) {
		smblib_err(chg, "Couldn't resume input rc=%d\n", rc);
		goto enable_icl_changed_interrupt;
	}

enable_icl_changed_interrupt:
	enable_irq(chg->irq_info[USBIN_ICL_CHANGE_IRQ].irq);
	return rc;
}

static int smblib_usb_icl_vote_callback(struct votable *votable, void *data,
			int icl_ua, const char *client)
{
	struct smb_charger *chg = data;
	int rc = 0;
	bool override;
	union power_supply_propval pval;
	pr_info("%s,icl_ua=%d\n",__func__,icl_ua);

	/* suspend and return if 25mA or less is requested */
	if (client && (icl_ua < USBIN_25MA))
		return smblib_set_usb_suspend(chg, true);

	disable_irq_nosync(chg->irq_info[USBIN_ICL_CHANGE_IRQ].irq);
	if (!client)
		goto override_suspend_config;

	rc = smblib_get_prop_typec_mode(chg, &pval);
	if (rc < 0) {
		smblib_err(chg, "Couldn't get typeC mode rc = %d\n", rc);
		goto enable_icl_changed_interrupt;
	}

	/* configure current */
	if (pval.intval == POWER_SUPPLY_TYPEC_SOURCE_DEFAULT
		&& (chg->usb_psy_desc.type == POWER_SUPPLY_TYPE_USB)) {
		if (chg->non_std_chg_present) {
		rc = smblib_set_charge_param(chg, &chg->param.usb_icl,
				icl_ua - chg->icl_reduction_ua);
		if (rc < 0) {
			smblib_err(chg, "Couldn't set HC ICL rc=%d\n", rc);
			goto enable_icl_changed_interrupt;
		}
		override = false;
	} else {
		rc = set_sdp_current(chg, icl_ua);
		if (rc < 0) {
			smblib_err(chg, "Couldn't set SDP ICL rc=%d\n", rc);
			goto enable_icl_changed_interrupt;
		}
	}
	} else {
		rc = smblib_set_charge_param(chg, &chg->param.usb_icl,
				icl_ua - chg->icl_reduction_ua);
		if (rc < 0) {
			smblib_err(chg, "Couldn't set HC ICL rc=%d\n", rc);
			goto enable_icl_changed_interrupt;
		}
	}

override_suspend_config:
	/* determine if override needs to be enforced */
	override = true;
	if (client == NULL) {
		/* remove override if no voters - hw defaults is desired */
		override = false;
	} else if (pval.intval == POWER_SUPPLY_TYPEC_SOURCE_DEFAULT) {
		if (chg->usb_psy_desc.type == POWER_SUPPLY_TYPE_USB)
			/* For std cable with type = SDP never override */
			override = false;
		else if (chg->usb_psy_desc.type == POWER_SUPPLY_TYPE_USB_CDP
			&& icl_ua - chg->icl_reduction_ua == 1500000)
			/*
			 * For std cable with type = CDP override only if
			 * current is not 1500mA
			 */
			override = false;
	}

	/* enforce override */
	rc = smblib_masked_write(chg, USBIN_ICL_OPTIONS_REG,
		USBIN_MODE_CHG_BIT, override ? USBIN_MODE_CHG_BIT : 0);

	rc = smblib_icl_override(chg, override);
	if (rc < 0) {
		smblib_err(chg, "Couldn't set ICL override rc=%d\n", rc);
		goto enable_icl_changed_interrupt;
	}

	/* unsuspend after configuring current and override */
	rc = smblib_set_usb_suspend(chg, false);
	if (rc < 0) {
		smblib_err(chg, "Couldn't resume input rc=%d\n", rc);
		goto enable_icl_changed_interrupt;
	}

enable_icl_changed_interrupt:
	enable_irq(chg->irq_info[USBIN_ICL_CHANGE_IRQ].irq);
	return rc;
}

static int smblib_dc_icl_vote_callback(struct votable *votable, void *data,
			int icl_ua, const char *client)
{
	struct smb_charger *chg = data;
	int rc = 0;
	bool suspend;

	if (icl_ua < 0) {
		smblib_dbg(chg, PR_MISC, "No Voter hence suspending\n");
		icl_ua = 0;
	}

	suspend = (icl_ua < USBIN_25MA);
	if (suspend)
		goto suspend;

	rc = smblib_set_charge_param(chg, &chg->param.dc_icl, icl_ua);
	if (rc < 0) {
		smblib_err(chg, "Couldn't set DC input current limit rc=%d\n",
			rc);
		return rc;
	}

suspend:
	rc = vote(chg->dc_suspend_votable, USER_VOTER, suspend, 0);
	if (rc < 0) {
		smblib_err(chg, "Couldn't vote to %s DC rc=%d\n",
			suspend ? "suspend" : "resume", rc);
		return rc;
	}
	return rc;
}

static int smblib_pd_disallowed_votable_indirect_callback(
	struct votable *votable, void *data, int disallowed, const char *client)
{
	struct smb_charger *chg = data;
	int rc;

	rc = vote(chg->pd_allowed_votable, PD_DISALLOWED_INDIRECT_VOTER,
		!disallowed, 0);

	return rc;
}

static int smblib_awake_vote_callback(struct votable *votable, void *data,
			int awake, const char *client)
{
	struct smb_charger *chg = data;

/* david.liu@bsp, 20161014 Add charging standard */
	pr_info("set awake=%d\n", awake);
	if (awake)
		pm_stay_awake(chg->dev);
	else
		pm_relax(chg->dev);

	return 0;
}

static int smblib_chg_disable_vote_callback(struct votable *votable, void *data,
			int chg_disable, const char *client)
{
	struct smb_charger *chg = data;
	int rc;

/* david.liu@bsp, 20161014 Add charging standard */
	pr_err("set chg_disable=%d\n", chg_disable);
	rc = smblib_masked_write(chg, CHARGING_ENABLE_CMD_REG,
				 CHARGING_ENABLE_CMD_BIT,
				 chg_disable ? 0 : CHARGING_ENABLE_CMD_BIT);
	if (rc < 0) {
		smblib_err(chg, "Couldn't %s charging rc=%d\n",
			chg_disable ? "disable" : "enable", rc);
		return rc;
	}

	return 0;
}

static int smblib_pl_enable_indirect_vote_callback(struct votable *votable,
			void *data, int chg_enable, const char *client)
{
	struct smb_charger *chg = data;

	vote(chg->pl_disable_votable, PL_INDIRECT_VOTER, !chg_enable, 0);

	return 0;
}

static int smblib_hvdcp_enable_vote_callback(struct votable *votable,
			void *data,
			int hvdcp_enable, const char *client)
{
	struct smb_charger *chg = data;
	int rc;
	u8 val = HVDCP_AUTH_ALG_EN_CFG_BIT | HVDCP_EN_BIT;
	u8 stat;
	/* vote to enable/disable HW autonomous INOV */
	vote(chg->hvdcp_hw_inov_dis_votable, client, !hvdcp_enable, 0);

	/*
	 * Disable the autonomous bit and auth bit for disabling hvdcp.
	 * This ensures only qc 2.0 detection runs but no vbus
	 * negotiation happens.
	 */
	if (!hvdcp_enable)
		val = HVDCP_EN_BIT;

	rc = smblib_masked_write(chg, USBIN_OPTIONS_1_CFG_REG,
				 HVDCP_EN_BIT | HVDCP_AUTH_ALG_EN_CFG_BIT,
				 val);
	if (rc < 0) {
		smblib_err(chg, "Couldn't %s hvdcp rc=%d\n",
			hvdcp_enable ? "enable" : "disable", rc);
		return rc;
	}
	rc = smblib_read(chg, APSD_STATUS_REG, &stat);
	if (rc < 0) {
		smblib_err(chg, "Couldn't read APSD status rc=%d\n", rc);
		return rc;
	} /* re-run APSD if HVDCP was detected */
	if (stat & QC_CHARGER_BIT) {
		smblib_err(chg, "%s: %d\n", __func__, rc);
		op_rerun_apsd(chg);
	}
	/*May change to the API of QCOM*/

	return 0;
}

static int smblib_hvdcp_disable_indirect_vote_callback(struct votable *votable,
			void *data, int hvdcp_disable, const char *client)
{
	struct smb_charger *chg = data;

	vote(chg->hvdcp_enable_votable, HVDCP_INDIRECT_VOTER,
			!hvdcp_disable, 0);

	return 0;
}

static int smblib_apsd_disable_vote_callback(struct votable *votable,
			void *data,
			int apsd_disable, const char *client)
{
	struct smb_charger *chg = data;
	int rc;

	if (apsd_disable) {
		rc = smblib_masked_write(chg, USBIN_OPTIONS_1_CFG_REG,
							AUTO_SRC_DETECT_BIT,
							0);
		if (rc < 0) {
			smblib_err(chg, "Couldn't disable APSD rc=%d\n", rc);
			return rc;
		}
	} else {
		rc = smblib_masked_write(chg, USBIN_OPTIONS_1_CFG_REG,
							AUTO_SRC_DETECT_BIT,
							AUTO_SRC_DETECT_BIT);
		if (rc < 0) {
			smblib_err(chg, "Couldn't enable APSD rc=%d\n", rc);
			return rc;
		}
	}

	return 0;
}

static int smblib_hvdcp_hw_inov_dis_vote_callback(struct votable *votable,
				void *data, int disable, const char *client)
{
	struct smb_charger *chg = data;
	int rc;

	if (disable) {
		/*
		 * the pulse count register get zeroed when autonomous mode is
		 * disabled. Track that in variables before disabling
		 */
		rc = smblib_get_pulse_cnt(chg, &chg->pulse_cnt);
		if (rc < 0) {
			pr_err("failed to read QC_PULSE_COUNT_STATUS_REG rc=%d\n",
					rc);
			return rc;
		}
	}

	rc = smblib_masked_write(chg, USBIN_OPTIONS_1_CFG_REG,
			HVDCP_AUTONOMOUS_MODE_EN_CFG_BIT,
			disable ? 0 : HVDCP_AUTONOMOUS_MODE_EN_CFG_BIT);
	if (rc < 0) {
		smblib_err(chg, "Couldn't %s hvdcp rc=%d\n",
				disable ? "disable" : "enable", rc);
		return rc;
	}

	return rc;
}

static int smblib_usb_irq_enable_vote_callback(struct votable *votable,
				void *data, int enable, const char *client)
{
	struct smb_charger *chg = data;

	if (!chg->irq_info[INPUT_CURRENT_LIMIT_IRQ].irq ||
				!chg->irq_info[HIGH_DUTY_CYCLE_IRQ].irq)
		return 0;

	if (enable) {
		enable_irq(chg->irq_info[INPUT_CURRENT_LIMIT_IRQ].irq);
		enable_irq(chg->irq_info[HIGH_DUTY_CYCLE_IRQ].irq);
	} else {
		disable_irq(chg->irq_info[INPUT_CURRENT_LIMIT_IRQ].irq);
		disable_irq(chg->irq_info[HIGH_DUTY_CYCLE_IRQ].irq);
	}

	return 0;
}

static int smblib_typec_irq_disable_vote_callback(struct votable *votable,
			void *data, int disable, const char *client)
{
	struct smb_charger *chg = data;

	if (!chg->irq_info[TYPE_C_CHANGE_IRQ].irq)
		return 0;

	if (disable)
		disable_irq_nosync(chg->irq_info[TYPE_C_CHANGE_IRQ].irq);
	else
		enable_irq(chg->irq_info[TYPE_C_CHANGE_IRQ].irq);

	return 0;
}

/*******************
 * VCONN REGULATOR *
 * *****************/

#define MAX_OTG_SS_TRIES 2
static int _smblib_vconn_regulator_enable(struct regulator_dev *rdev)
{
	struct smb_charger *chg = rdev_get_drvdata(rdev);
	u8 otg_stat, val;
	int rc = 0, i;

	if (!chg->external_vconn) {
		/*
		 * Hardware based OTG soft start should complete within 1ms, so
		 * wait for 2ms in the worst case.
		 */
		for (i = 0; i < MAX_OTG_SS_TRIES; ++i) {
			usleep_range(1000, 1100);
			rc = smblib_read(chg, OTG_STATUS_REG, &otg_stat);
			if (rc < 0) {
				smblib_err(chg, "Couldn't read OTG status rc=%d\n",
									rc);
				return rc;
			}

			if (otg_stat & BOOST_SOFTSTART_DONE_BIT)
				break;
		}

		if (!(otg_stat & BOOST_SOFTSTART_DONE_BIT)) {
			smblib_err(chg, "Couldn't enable VCONN; OTG soft start failed\n");
			return -EAGAIN;
		}
	}

	/*
	 * VCONN_EN_ORIENTATION is overloaded with overriding the CC pin used
	 * for Vconn, and it should be set with reverse polarity of CC_OUT.
	 */
	smblib_dbg(chg, PR_OTG, "enabling VCONN\n");
	val = chg->typec_status[3] &
			CC_ORIENTATION_BIT ? 0 : VCONN_EN_ORIENTATION_BIT;
	rc = smblib_masked_write(chg, TYPE_C_INTRPT_ENB_SOFTWARE_CTRL_REG,
				 VCONN_EN_VALUE_BIT | VCONN_EN_ORIENTATION_BIT,
				 VCONN_EN_VALUE_BIT | val);
	if (rc < 0) {
		smblib_err(chg, "Couldn't enable vconn setting rc=%d\n", rc);
		return rc;
	}

	return rc;
}

int smblib_vconn_regulator_enable(struct regulator_dev *rdev)
{
	struct smb_charger *chg = rdev_get_drvdata(rdev);
	int rc = 0;

	mutex_lock(&chg->otg_oc_lock);
	if (chg->vconn_en)
		goto unlock;

	rc = _smblib_vconn_regulator_enable(rdev);
	if (rc >= 0)
		chg->vconn_en = true;

unlock:
	mutex_unlock(&chg->otg_oc_lock);
	return rc;
}

static int _smblib_vconn_regulator_disable(struct regulator_dev *rdev)
{
	struct smb_charger *chg = rdev_get_drvdata(rdev);
	int rc = 0;

	smblib_dbg(chg, PR_OTG, "disabling VCONN\n");
	rc = smblib_masked_write(chg, TYPE_C_INTRPT_ENB_SOFTWARE_CTRL_REG,
				 VCONN_EN_VALUE_BIT, 0);
	if (rc < 0)
		smblib_err(chg, "Couldn't disable vconn regulator rc=%d\n", rc);

	return rc;
}

int smblib_vconn_regulator_disable(struct regulator_dev *rdev)
{
	struct smb_charger *chg = rdev_get_drvdata(rdev);
	int rc = 0;

	mutex_lock(&chg->otg_oc_lock);
	if (!chg->vconn_en)
		goto unlock;

	rc = _smblib_vconn_regulator_disable(rdev);
	if (rc >= 0)
		chg->vconn_en = false;

unlock:
	mutex_unlock(&chg->otg_oc_lock);
	return rc;
}

int smblib_vconn_regulator_is_enabled(struct regulator_dev *rdev)
{
	struct smb_charger *chg = rdev_get_drvdata(rdev);
	int ret;

	mutex_lock(&chg->otg_oc_lock);
	ret = chg->vconn_en;
	mutex_unlock(&chg->otg_oc_lock);
	return ret;
}

/*****************
 * OTG REGULATOR *
 *****************/
#define MAX_RETRY		15
#define MIN_DELAY_US		2000
#define MAX_DELAY_US		9000
static int _smblib_vbus_regulator_enable(struct regulator_dev *rdev)
{
	struct smb_charger *chg = rdev_get_drvdata(rdev);
	int rc, retry_count = 0, min_delay = MIN_DELAY_US;
	u8 stat;

	smblib_dbg(chg, PR_OTG, "halt 1 in 8 mode\n");
	rc = smblib_masked_write(chg, OTG_ENG_OTG_CFG_REG,
				 ENG_BUCKBOOST_HALT1_8_MODE_BIT,
				 ENG_BUCKBOOST_HALT1_8_MODE_BIT);
	if (rc < 0) {
		smblib_err(chg, "Couldn't set OTG_ENG_OTG_CFG_REG rc=%d\n",
			rc);
		return rc;
	}

	smblib_dbg(chg, PR_OTG, "enabling OTG\n");
	rc = smblib_write(chg, CMD_OTG_REG, OTG_EN_BIT);
	if (rc < 0) {
		smblib_err(chg, "Couldn't enable OTG regulator rc=%d\n", rc);
		return rc;
	}

	if (chg->wa_flags & OTG_WA) {
		/* check for softstart */
		do {
			usleep_range(min_delay, min_delay + 100);
			rc = smblib_read(chg, OTG_STATUS_REG, &stat);
			if (rc < 0) {
				smblib_err(chg,
					"Couldn't read OTG status rc=%d\n",
					rc);
				goto out;
			}

			if (stat & BOOST_SOFTSTART_DONE_BIT) {
				rc = smblib_set_charge_param(chg,
					&chg->param.otg_cl, chg->otg_cl_ua);
				if (rc < 0)
					smblib_err(chg,
						"Couldn't set otg limit\n");
				break;
			}

			/* increase the delay for following iterations */
			if (retry_count > 5)
				min_delay = MAX_DELAY_US;
		} while (retry_count++ < MAX_RETRY);

		if (retry_count >= MAX_RETRY) {
			smblib_dbg(chg, PR_OTG, "Boost Softstart not done\n");
			goto out;
		}
	}

	return 0;
out:
	/* disable OTG if softstart failed */
	smblib_write(chg, CMD_OTG_REG, 0);
	return rc;
}

int smblib_vbus_regulator_enable(struct regulator_dev *rdev)
{
	struct smb_charger *chg = rdev_get_drvdata(rdev);
	int rc = 0;

	mutex_lock(&chg->otg_oc_lock);
	if (chg->otg_en)
		goto unlock;

	rc = _smblib_vbus_regulator_enable(rdev);
	if (rc >= 0)
		chg->otg_en = true;

unlock:
	mutex_unlock(&chg->otg_oc_lock);
	return rc;
}

static int _smblib_vbus_regulator_disable(struct regulator_dev *rdev)
{
	struct smb_charger *chg = rdev_get_drvdata(rdev);
	int rc;

	if (!chg->external_vconn && chg->vconn_en) {
		smblib_dbg(chg, PR_OTG, "Killing VCONN before disabling OTG\n");
		rc = _smblib_vconn_regulator_disable(rdev);
		if (rc < 0)
			smblib_err(chg, "Couldn't disable VCONN rc=%d\n", rc);
	}

	if (chg->wa_flags & OTG_WA) {
		/* set OTG current limit to minimum value */
		rc = smblib_set_charge_param(chg, &chg->param.otg_cl,
						chg->param.otg_cl.min_u);
		if (rc < 0) {
			smblib_err(chg,
				"Couldn't set otg current limit rc=%d\n", rc);
			return rc;
		}
	}

	smblib_dbg(chg, PR_OTG, "disabling OTG\n");
	rc = smblib_write(chg, CMD_OTG_REG, 0);
	if (rc < 0) {
		smblib_err(chg, "Couldn't disable OTG regulator rc=%d\n", rc);
		return rc;
	}

	smblib_dbg(chg, PR_OTG, "start 1 in 8 mode\n");
	rc = smblib_masked_write(chg, OTG_ENG_OTG_CFG_REG,
				 ENG_BUCKBOOST_HALT1_8_MODE_BIT, 0);
	if (rc < 0) {
		smblib_err(chg, "Couldn't set OTG_ENG_OTG_CFG_REG rc=%d\n", rc);
		return rc;
	}

	return 0;
}

int smblib_vbus_regulator_disable(struct regulator_dev *rdev)
{
	struct smb_charger *chg = rdev_get_drvdata(rdev);
	int rc = 0;

	mutex_lock(&chg->otg_oc_lock);
	if (!chg->otg_en)
		goto unlock;

	rc = _smblib_vbus_regulator_disable(rdev);
	if (rc >= 0)
		chg->otg_en = false;

unlock:
	mutex_unlock(&chg->otg_oc_lock);
	return rc;
}

int smblib_vbus_regulator_is_enabled(struct regulator_dev *rdev)
{
	struct smb_charger *chg = rdev_get_drvdata(rdev);
	int ret;

	mutex_lock(&chg->otg_oc_lock);
	ret = chg->otg_en;
	mutex_unlock(&chg->otg_oc_lock);
	return ret;
}

/********************
 * BATT PSY GETTERS *
 ********************/

int smblib_get_prop_input_suspend(struct smb_charger *chg,
				  union power_supply_propval *val)
{
	val->intval
		= (get_client_vote(chg->usb_icl_votable, USER_VOTER) == 0)
		 && get_client_vote(chg->dc_suspend_votable, USER_VOTER);
	return 0;
}

int smblib_get_prop_batt_present(struct smb_charger *chg,
				union power_supply_propval *val)
{
	int rc;
	u8 stat;

	rc = smblib_read(chg, BATIF_BASE + INT_RT_STS_OFFSET, &stat);
	if (rc < 0) {
		smblib_err(chg, "Couldn't read BATIF_INT_RT_STS rc=%d\n", rc);
		return rc;
	}

	val->intval = !(stat & (BAT_THERM_OR_ID_MISSING_RT_STS_BIT
					| BAT_TERMINAL_MISSING_RT_STS_BIT));

	return rc;
}

int smblib_get_prop_batt_capacity(struct smb_charger *chg,
				  union power_supply_propval *val)
{
	int rc = -EINVAL;

	if (chg->fake_capacity >= 0) {
		val->intval = chg->fake_capacity;
		return 0;
	}

	if (chg->bms_psy)
		rc = power_supply_get_property(chg->bms_psy,
				POWER_SUPPLY_PROP_CAPACITY, val);
	return rc;
}

int smblib_get_prop_batt_status(struct smb_charger *chg,
				union power_supply_propval *val)
{
	union power_supply_propval pval = {0, };
	bool usb_online, dc_online;
	u8 stat;
	int rc;

	rc = smblib_get_prop_usb_online(chg, &pval);
	if (rc < 0) {
		smblib_err(chg, "Couldn't get usb online property rc=%d\n",
			rc);
		return rc;
	}
	usb_online = (bool)pval.intval;

	rc = smblib_get_prop_dc_online(chg, &pval);
	if (rc < 0) {
		smblib_err(chg, "Couldn't get dc online property rc=%d\n",
			rc);
		return rc;
	}
	dc_online = (bool)pval.intval;

	rc = smblib_read(chg, BATTERY_CHARGER_STATUS_1_REG, &stat);
	if (rc < 0) {
		smblib_err(chg, "Couldn't read BATTERY_CHARGER_STATUS_1 rc=%d\n",
			rc);
		return rc;
	}
	stat = stat & BATTERY_CHARGER_STATUS_MASK;

	if (!usb_online && !dc_online) {
		switch (stat) {
		case TERMINATE_CHARGE:
		case INHIBIT_CHARGE:
			val->intval = POWER_SUPPLY_STATUS_FULL;
			break;
		default:
			val->intval = POWER_SUPPLY_STATUS_DISCHARGING;
			break;
		}
		return rc;
	}

	switch (stat) {
	case TRICKLE_CHARGE:
	case PRE_CHARGE:
	case FAST_CHARGE:
	case FULLON_CHARGE:
	case TAPER_CHARGE:
		val->intval = POWER_SUPPLY_STATUS_CHARGING;
		break;
	case TERMINATE_CHARGE:
	case INHIBIT_CHARGE:
		val->intval = POWER_SUPPLY_STATUS_FULL;
		break;
	case DISABLE_CHARGE:
		val->intval = POWER_SUPPLY_STATUS_NOT_CHARGING;
		break;
	default:
		val->intval = POWER_SUPPLY_STATUS_UNKNOWN;
		break;
	}

	return 0;
}

int smblib_get_prop_batt_charge_type(struct smb_charger *chg,
				union power_supply_propval *val)
{
	int rc;
	u8 stat;

	rc = smblib_read(chg, BATTERY_CHARGER_STATUS_1_REG, &stat);
	if (rc < 0) {
		smblib_err(chg, "Couldn't read BATTERY_CHARGER_STATUS_1 rc=%d\n",
			rc);
		return rc;
	}

	switch (stat & BATTERY_CHARGER_STATUS_MASK) {
	case TRICKLE_CHARGE:
	case PRE_CHARGE:
		val->intval = POWER_SUPPLY_CHARGE_TYPE_TRICKLE;
		break;
	case FAST_CHARGE:
	case FULLON_CHARGE:
		val->intval = POWER_SUPPLY_CHARGE_TYPE_FAST;
		break;
	case TAPER_CHARGE:
		val->intval = POWER_SUPPLY_CHARGE_TYPE_TAPER;
		break;
	default:
		val->intval = POWER_SUPPLY_CHARGE_TYPE_NONE;
	}

	return rc;
}

int smblib_get_prop_batt_health(struct smb_charger *chg,
				union power_supply_propval *val)
{

	int rc;
	u8 stat;

	rc = smblib_read(chg, BATTERY_CHARGER_STATUS_2_REG, &stat);
	if (rc < 0) {
		smblib_err(chg, "Couldn't read BATTERY_CHARGER_STATUS_2 rc=%d\n",
			rc);
		return rc;
	}
	smblib_dbg(chg, PR_REGISTER, "BATTERY_CHARGER_STATUS_2 = 0x%02x\n",
		   stat);

	if (stat & CHARGER_ERROR_STATUS_BAT_OV_BIT) {
	val->intval = POWER_SUPPLY_HEALTH_OVERVOLTAGE;

	}


	if (stat & BAT_TEMP_STATUS_TOO_COLD_BIT)
		val->intval = POWER_SUPPLY_HEALTH_COLD;
	else if (stat & BAT_TEMP_STATUS_TOO_HOT_BIT)
		val->intval = POWER_SUPPLY_HEALTH_OVERHEAT;
	else if (stat & BAT_TEMP_STATUS_COLD_SOFT_LIMIT_BIT)
		val->intval = POWER_SUPPLY_HEALTH_COOL;
	else if (stat & BAT_TEMP_STATUS_HOT_SOFT_LIMIT_BIT)
		val->intval = POWER_SUPPLY_HEALTH_WARM;
	else
		val->intval = POWER_SUPPLY_HEALTH_GOOD;
	return rc;
}

int smblib_get_prop_system_temp_level(struct smb_charger *chg,
				union power_supply_propval *val)
{
	val->intval = chg->system_temp_level;
	return 0;
}

int smblib_get_prop_input_current_limited(struct smb_charger *chg,
				union power_supply_propval *val)
{
	u8 stat;
	int rc;

	rc = smblib_read(chg, AICL_STATUS_REG, &stat);
	if (rc < 0) {
		smblib_err(chg, "Couldn't read AICL_STATUS rc=%d\n", rc);
		return rc;
	}
	val->intval = (stat & SOFT_ILIMIT_BIT) || chg->is_hdc;
	return 0;
}

int smblib_get_prop_batt_voltage_now(struct smb_charger *chg,
				     union power_supply_propval *val)
{
	int rc;

	if (!chg->bms_psy)
		return -EINVAL;

	rc = power_supply_get_property(chg->bms_psy,
				       POWER_SUPPLY_PROP_VOLTAGE_NOW, val);
	return rc;
}

int smblib_get_prop_batt_current_now(struct smb_charger *chg,
				     union power_supply_propval *val)
{
	int rc;

	if (!chg->bms_psy)
		return -EINVAL;

	rc = power_supply_get_property(chg->bms_psy,
				       POWER_SUPPLY_PROP_CURRENT_NOW, val);
	return rc;
}

int smblib_get_prop_batt_temp(struct smb_charger *chg,
			      union power_supply_propval *val)
{
	int rc;

	if (!chg->bms_psy)
		return -EINVAL;

/* david.liu@bsp, 20161014 Add charging standard */
	if (chg->use_fake_temp) {
		val->intval = chg->fake_temp;
		return 0;
	}

	rc = power_supply_get_property(chg->bms_psy,
				       POWER_SUPPLY_PROP_TEMP, val);
	return rc;
}

int smblib_get_prop_step_chg_step(struct smb_charger *chg,
				union power_supply_propval *val)
{
	int rc;
	u8 stat;

	if (!chg->step_chg_enabled) {
		val->intval = -1;
		return 0;
	}

	rc = smblib_read(chg, BATTERY_CHARGER_STATUS_1_REG, &stat);
	if (rc < 0) {
		smblib_err(chg, "Couldn't read BATTERY_CHARGER_STATUS_1 rc=%d\n",
			rc);
		return rc;
	}

	val->intval = (stat & STEP_CHARGING_STATUS_MASK) >>
				STEP_CHARGING_STATUS_SHIFT;

	return rc;
}

int smblib_get_prop_batt_charge_done(struct smb_charger *chg,
					union power_supply_propval *val)
{
	int rc;
	u8 stat;

	rc = smblib_read(chg, BATTERY_CHARGER_STATUS_1_REG, &stat);
	if (rc < 0) {
		smblib_err(chg, "Couldn't read BATTERY_CHARGER_STATUS_1 rc=%d\n",
			rc);
		return rc;
	}

	stat = stat & BATTERY_CHARGER_STATUS_MASK;
	val->intval = (stat == TERMINATE_CHARGE);
	return 0;
}

/***********************
 * BATTERY PSY SETTERS *
 ***********************/

int smblib_set_prop_input_suspend(struct smb_charger *chg,
				  const union power_supply_propval *val)
{
	int rc;

	/* vote 0mA when suspended */
	rc = vote(chg->usb_icl_votable, USER_VOTER, (bool)val->intval, 0);
	if (rc < 0) {
		smblib_err(chg, "Couldn't vote to %s USB rc=%d\n",
			(bool)val->intval ? "suspend" : "resume", rc);
		return rc;
	}

	rc = vote(chg->dc_suspend_votable, USER_VOTER, (bool)val->intval, 0);
	if (rc < 0) {
		smblib_err(chg, "Couldn't vote to %s DC rc=%d\n",
			(bool)val->intval ? "suspend" : "resume", rc);
		return rc;
	}

	power_supply_changed(chg->batt_psy);
	return rc;
}

#define POWER_ROLE_BIT (DFP_EN_CMD_BIT | UFP_EN_CMD_BIT)
/* david.liu@bsp, 20161014 Add charging standard */
static int op_check_battery_temp(struct smb_charger *chg);

int op_set_prop_otg_switch(struct smb_charger *chg,
				  const union power_supply_propval *val)
{
	int rc = 0;
	u8 power_role;
	u8 ctrl = 0;
	bool pre_otg_switch;
	int i = 0;

	pre_otg_switch = chg->otg_switch;
	chg->otg_switch = val->intval;

	if (chg->otg_switch == pre_otg_switch)
		return rc;

	pr_info("set otg_switch=%d\n", chg->otg_switch);
	if (chg->otg_switch)
		power_role = 0;
	else
		power_role = UFP_EN_CMD_BIT;

	for (i = 0; i < 10; i++) {
		rc = smblib_masked_write(chg,
					TYPE_C_INTRPT_ENB_SOFTWARE_CTRL_REG,
					TYPEC_POWER_ROLE_CMD_MASK, power_role);
		if (rc < 0) {
			smblib_err(chg, "Couldn't write 0x%02x to 0x1368 rc=%d\n",
				power_role, rc);
			return rc;
		}
		usleep_range(30000, 31000);
		ctrl = 0;
		rc = smblib_read(chg, TYPE_C_INTRPT_ENB_SOFTWARE_CTRL_REG, &ctrl);
		if (rc < 0) {
			smblib_err(chg, "Couldn't read err=%d\n", rc);
			return rc;
		}
		if ((power_role == 0) && ((ctrl & POWER_ROLE_BIT) == 0))
			break;
		if ((power_role == UFP_EN_CMD_BIT) && (ctrl | UFP_EN_CMD_BIT))
			break;
	}
	pr_info("retry time = %d,ctrl = %d\n", i,ctrl);
	if (i == 10)
		pr_err("retry time over\n");

	return rc;
}

int smblib_set_prop_chg_voltage(struct smb_charger *chg,
				  const union power_supply_propval *val)
{
	chg->fake_chgvol = val->intval;
	chg->use_fake_chgvol = true;
	power_supply_changed(chg->batt_psy);

	return 0;
}

int smblib_set_prop_batt_temp(struct smb_charger *chg,
				  const union power_supply_propval *val)
{
	chg->fake_temp = val->intval;
	chg->use_fake_temp = true;
	power_supply_changed(chg->batt_psy);

	return 0;
}

int smblib_set_prop_chg_protect_status(struct smb_charger *chg,
				  const union power_supply_propval *val)
{
	chg->fake_protect_sts = val->intval;
	chg->use_fake_protect_sts = true;
	power_supply_changed(chg->batt_psy);

	return 0;
}
int smblib_set_prop_charge_parameter_set(struct smb_charger *chg)
{
	chg->is_power_changed = true;
	op_check_battery_temp(chg);
	return 0;
}


int smblib_set_prop_batt_capacity(struct smb_charger *chg,
				  const union power_supply_propval *val)
{
	chg->fake_capacity = val->intval;

	power_supply_changed(chg->batt_psy);

	return 0;
}

int smblib_set_prop_system_temp_level(struct smb_charger *chg,
				const union power_supply_propval *val)
{
	if (val->intval < 0)
		return -EINVAL;

	if (chg->thermal_levels <= 0)
		return -EINVAL;

	if (val->intval > chg->thermal_levels)
		return -EINVAL;

	chg->system_temp_level = val->intval;
	if (chg->system_temp_level == chg->thermal_levels)
		return vote(chg->chg_disable_votable,
			THERMAL_DAEMON_VOTER, true, 0);

	vote(chg->chg_disable_votable, THERMAL_DAEMON_VOTER, false, 0);
	if (chg->system_temp_level == 0)
		return vote(chg->fcc_votable, THERMAL_DAEMON_VOTER, false, 0);

	vote(chg->fcc_votable, THERMAL_DAEMON_VOTER, true,
			chg->thermal_mitigation[chg->system_temp_level]);
	return 0;
}

int smblib_rerun_aicl(struct smb_charger *chg)
{
	int rc, settled_icl_ua;
	u8 stat;

	rc = smblib_read(chg, POWER_PATH_STATUS_REG, &stat);
	if (rc < 0) {
		smblib_err(chg, "Couldn't read POWER_PATH_STATUS rc=%d\n",
								rc);
		return rc;
	}

	/* USB is suspended so skip re-running AICL */
	if (stat & USBIN_SUSPEND_STS_BIT)
		return rc;

	smblib_dbg(chg, PR_MISC, "re-running AICL\n");
	switch (chg->smb_version) {
	case PMI8998_SUBTYPE:
		rc = smblib_get_charge_param(chg, &chg->param.icl_stat,
							&settled_icl_ua);
		if (rc < 0) {
			smblib_err(chg, "Couldn't get settled ICL rc=%d\n", rc);
			return rc;
		}

		vote(chg->usb_icl_votable, AICL_RERUN_VOTER, true,
				max(settled_icl_ua - chg->param.usb_icl.step_u,
				chg->param.usb_icl.step_u));
		vote(chg->usb_icl_votable, AICL_RERUN_VOTER, false, 0);
		break;
	case PM660_SUBTYPE:
		/*
		 * Use restart_AICL instead of trigger_AICL as it runs the
		 * complete AICL instead of starting from the last settled
		 * value.
		 */
		rc = smblib_masked_write(chg, CMD_HVDCP_2_REG,
					RESTART_AICL_BIT, RESTART_AICL_BIT);
		if (rc < 0)
			smblib_err(chg, "Couldn't write to CMD_HVDCP_2_REG rc=%d\n",
									rc);
		break;
	default:
		smblib_dbg(chg, PR_PARALLEL, "unknown SMB chip %d\n",
				chg->smb_version);
		return -EINVAL;
	}

	return 0;
}

static int smblib_dp_pulse(struct smb_charger *chg)
{
	int rc;

	/* QC 3.0 increment */
	rc = smblib_masked_write(chg, CMD_HVDCP_2_REG, SINGLE_INCREMENT_BIT,
			SINGLE_INCREMENT_BIT);
	if (rc < 0)
		smblib_err(chg, "Couldn't write to CMD_HVDCP_2_REG rc=%d\n",
				rc);

	return rc;
}

static int smblib_dm_pulse(struct smb_charger *chg)
{
	int rc;

	/* QC 3.0 decrement */
	rc = smblib_masked_write(chg, CMD_HVDCP_2_REG, SINGLE_DECREMENT_BIT,
			SINGLE_DECREMENT_BIT);
	if (rc < 0)
		smblib_err(chg, "Couldn't write to CMD_HVDCP_2_REG rc=%d\n",
				rc);

	return rc;
}

int smblib_dp_dm(struct smb_charger *chg, int val)
{
	int target_icl_ua, rc = 0;

	switch (val) {
	case POWER_SUPPLY_DP_DM_DP_PULSE:
		rc = smblib_dp_pulse(chg);
		if (!rc)
			chg->pulse_cnt++;
		smblib_dbg(chg, PR_PARALLEL, "DP_DM_DP_PULSE rc=%d cnt=%d\n",
				rc, chg->pulse_cnt);
		break;
	case POWER_SUPPLY_DP_DM_DM_PULSE:
		rc = smblib_dm_pulse(chg);
		if (!rc && chg->pulse_cnt)
			chg->pulse_cnt--;
		smblib_dbg(chg, PR_PARALLEL, "DP_DM_DM_PULSE rc=%d cnt=%d\n",
				rc, chg->pulse_cnt);
		break;
	case POWER_SUPPLY_DP_DM_ICL_DOWN:
		chg->usb_icl_delta_ua -= 100000;
		target_icl_ua = get_effective_result(chg->usb_icl_votable);
		vote(chg->usb_icl_votable, SW_QC3_VOTER, true,
				target_icl_ua + chg->usb_icl_delta_ua);
		break;
	case POWER_SUPPLY_DP_DM_ICL_UP:
	default:
		break;
	}

	return rc;
}

/*******************
 * DC PSY GETTERS *
 *******************/

int smblib_get_prop_dc_present(struct smb_charger *chg,
				union power_supply_propval *val)
{
	int rc;
	u8 stat;

	rc = smblib_read(chg, DCIN_BASE + INT_RT_STS_OFFSET, &stat);
	if (rc < 0) {
		smblib_err(chg, "Couldn't read DCIN_RT_STS rc=%d\n", rc);
		return rc;
	}

	val->intval = (bool)(stat & DCIN_PLUGIN_RT_STS_BIT);
	return 0;
}

int smblib_get_prop_dc_online(struct smb_charger *chg,
			       union power_supply_propval *val)
{
	int rc = 0;
	u8 stat;

	if (get_client_vote(chg->dc_suspend_votable, USER_VOTER)) {
		val->intval = false;
		return rc;
	}

	rc = smblib_read(chg, POWER_PATH_STATUS_REG, &stat);
	if (rc < 0) {
		smblib_err(chg, "Couldn't read POWER_PATH_STATUS rc=%d\n",
			rc);
		return rc;
	}
	smblib_dbg(chg, PR_REGISTER, "POWER_PATH_STATUS = 0x%02x\n",
		   stat);

	val->intval = (stat & USE_DCIN_BIT) &&
		      (stat & VALID_INPUT_POWER_SOURCE_STS_BIT);

	return rc;
}

int smblib_get_prop_dc_current_max(struct smb_charger *chg,
				    union power_supply_propval *val)
{
	val->intval = get_effective_result_locked(chg->dc_icl_votable);
	return 0;
}

/*******************
 * DC PSY SETTERS *
 * *****************/

int smblib_set_prop_dc_current_max(struct smb_charger *chg,
				    const union power_supply_propval *val)
{
	int rc;

	rc = vote(chg->dc_icl_votable, USER_VOTER, true, val->intval);
	return rc;
}

/*******************
 * USB PSY GETTERS *
 *******************/

int smblib_get_prop_usb_present(struct smb_charger *chg,
				union power_supply_propval *val)
{
	int rc;
	u8 stat;

	rc = smblib_read(chg, USBIN_BASE + INT_RT_STS_OFFSET, &stat);
	if (rc < 0) {
		smblib_err(chg, "Couldn't read USBIN_RT_STS rc=%d\n", rc);
		return rc;
	}
	val->intval = (bool)(stat & USBIN_PLUGIN_RT_STS_BIT);
	return 0;
}

int smblib_get_prop_usb_online(struct smb_charger *chg,
			       union power_supply_propval *val)
{
	int rc = 0;
	u8 stat;

	if (get_client_vote(chg->usb_icl_votable, USER_VOTER) == 0) {
		val->intval = false;
		return rc;
	}

/* david.liu@bsp, 20161122 Fix power off charging loop */
	if (chg->vbus_present) {
		val->intval = true;
		return rc;
	}

	rc = smblib_read(chg, POWER_PATH_STATUS_REG, &stat);
	if (rc < 0) {
		smblib_err(chg, "Couldn't read POWER_PATH_STATUS rc=%d\n",
			rc);
		return rc;
	}
	smblib_dbg(chg, PR_REGISTER, "POWER_PATH_STATUS = 0x%02x\n",
		   stat);

	val->intval = (stat & USE_USBIN_BIT) &&
		      (stat & VALID_INPUT_POWER_SOURCE_STS_BIT);
	return rc;
}

int smblib_get_prop_usb_voltage_now(struct smb_charger *chg,
				    union power_supply_propval *val)
{
	int rc = 0;

	rc = smblib_get_prop_usb_present(chg, val);
	if (rc < 0 || !val->intval)
		return rc;

	if (!chg->iio.usbin_v_chan ||
		PTR_ERR(chg->iio.usbin_v_chan) == -EPROBE_DEFER)
		chg->iio.usbin_v_chan = iio_channel_get(chg->dev, "usbin_v");

	if (IS_ERR(chg->iio.usbin_v_chan))
		return PTR_ERR(chg->iio.usbin_v_chan);
		/* yangfb@bsp, 20161229 Vbus switch uV to mV */
	rc = iio_read_channel_processed(chg->iio.usbin_v_chan, &val->intval);
	val->intval = val->intval/1000;
	return rc;
}

int smblib_get_prop_pd_current_max(struct smb_charger *chg,
				    union power_supply_propval *val)
{
	val->intval = get_client_vote_locked(chg->usb_icl_votable, PD_VOTER);
	return 0;
}

int smblib_get_prop_usb_current_max(struct smb_charger *chg,
				    union power_supply_propval *val)
{
	val->intval = get_client_vote_locked(chg->usb_icl_votable,
			USB_PSY_VOTER);
	return 0;
}

int smblib_get_prop_usb_current_now(struct smb_charger *chg,
				    union power_supply_propval *val)
{
	int rc = 0;

	rc = smblib_get_prop_usb_present(chg, val);
	if (rc < 0 || !val->intval)
		return rc;

	if (!chg->iio.usbin_i_chan ||
		PTR_ERR(chg->iio.usbin_i_chan) == -EPROBE_DEFER)
		chg->iio.usbin_i_chan = iio_channel_get(chg->dev, "usbin_i");

	if (IS_ERR(chg->iio.usbin_i_chan))
		return PTR_ERR(chg->iio.usbin_i_chan);

	return iio_read_channel_processed(chg->iio.usbin_i_chan, &val->intval);
}

int smblib_get_prop_charger_temp(struct smb_charger *chg,
				 union power_supply_propval *val)
{
	int rc;

	if (!chg->iio.temp_chan ||
		PTR_ERR(chg->iio.temp_chan) == -EPROBE_DEFER)
		chg->iio.temp_chan = iio_channel_get(chg->dev, "charger_temp");

	if (IS_ERR(chg->iio.temp_chan))
		return PTR_ERR(chg->iio.temp_chan);

	rc = iio_read_channel_processed(chg->iio.temp_chan, &val->intval);
	val->intval /= 100;
	return rc;
}

int smblib_get_prop_charger_temp_max(struct smb_charger *chg,
				    union power_supply_propval *val)
{
	int rc;

	if (!chg->iio.temp_max_chan ||
		PTR_ERR(chg->iio.temp_max_chan) == -EPROBE_DEFER)
		chg->iio.temp_max_chan = iio_channel_get(chg->dev,
							 "charger_temp_max");
	if (IS_ERR(chg->iio.temp_max_chan))
		return PTR_ERR(chg->iio.temp_max_chan);

	rc = iio_read_channel_processed(chg->iio.temp_max_chan, &val->intval);
	val->intval /= 100;
	return rc;
}

int smblib_get_prop_typec_cc_orientation(struct smb_charger *chg,
					 union power_supply_propval *val)
{
	if (chg->typec_status[3] & CC_ATTACHED_BIT)
		val->intval =
			(bool)(chg->typec_status[3] & CC_ORIENTATION_BIT) + 1;
	else
		val->intval = 0;

	return 0;
}

static const char * const smblib_typec_mode_name[] = {
	[POWER_SUPPLY_TYPEC_NONE]		  = "NONE",
	[POWER_SUPPLY_TYPEC_SOURCE_DEFAULT]	  = "SOURCE_DEFAULT",
	[POWER_SUPPLY_TYPEC_SOURCE_MEDIUM]	  = "SOURCE_MEDIUM",
	[POWER_SUPPLY_TYPEC_SOURCE_HIGH]	  = "SOURCE_HIGH",
	[POWER_SUPPLY_TYPEC_NON_COMPLIANT]	  = "NON_COMPLIANT",
	[POWER_SUPPLY_TYPEC_SINK]		  = "SINK",
	[POWER_SUPPLY_TYPEC_SINK_POWERED_CABLE]   = "SINK_POWERED_CABLE",
	[POWER_SUPPLY_TYPEC_SINK_DEBUG_ACCESSORY] = "SINK_DEBUG_ACCESSORY",
	[POWER_SUPPLY_TYPEC_SINK_AUDIO_ADAPTER]   = "SINK_AUDIO_ADAPTER",
	[POWER_SUPPLY_TYPEC_POWERED_CABLE_ONLY]   = "POWERED_CABLE_ONLY",
};

static int smblib_get_prop_ufp_mode(struct smb_charger *chg)
{
	switch (chg->typec_status[0]) {
	case 0:
		return POWER_SUPPLY_TYPEC_NONE;
	case UFP_TYPEC_RDSTD_BIT:
		return POWER_SUPPLY_TYPEC_SOURCE_DEFAULT;
	case UFP_TYPEC_RD1P5_BIT:
		return POWER_SUPPLY_TYPEC_SOURCE_MEDIUM;
	case UFP_TYPEC_RD3P0_BIT:
		return POWER_SUPPLY_TYPEC_SOURCE_HIGH;
	default:
		break;
	}

	return POWER_SUPPLY_TYPEC_NON_COMPLIANT;
}

static int smblib_get_prop_dfp_mode(struct smb_charger *chg)
{
	switch (chg->typec_status[1] & DFP_TYPEC_MASK) {
	case DFP_RA_RA_BIT:
		return POWER_SUPPLY_TYPEC_SINK_AUDIO_ADAPTER;
	case DFP_RD_RD_BIT:
		return POWER_SUPPLY_TYPEC_SINK_DEBUG_ACCESSORY;
	case DFP_RD_RA_VCONN_BIT:
		return POWER_SUPPLY_TYPEC_SINK_POWERED_CABLE;
	case DFP_RD_OPEN_BIT:
		return POWER_SUPPLY_TYPEC_SINK;
	case DFP_RA_OPEN_BIT:
		return POWER_SUPPLY_TYPEC_POWERED_CABLE_ONLY;
	default:
		break;
	}

	return POWER_SUPPLY_TYPEC_NONE;
}

int smblib_get_prop_typec_mode(struct smb_charger *chg,
			       union power_supply_propval *val)
{
	if (!(chg->typec_status[3] & TYPEC_DEBOUNCE_DONE_STATUS_BIT)) {
		val->intval = POWER_SUPPLY_TYPEC_NONE;
		return 0;
	}

	if (chg->typec_status[3] & UFP_DFP_MODE_STATUS_BIT)
		val->intval = smblib_get_prop_dfp_mode(chg);
	else
		val->intval = smblib_get_prop_ufp_mode(chg);

	return 0;
}

int smblib_get_prop_typec_power_role(struct smb_charger *chg,
				     union power_supply_propval *val)
{
	int rc = 0;
	u8 ctrl;

	rc = smblib_read(chg, TYPE_C_INTRPT_ENB_SOFTWARE_CTRL_REG, &ctrl);
	if (rc < 0) {
		smblib_err(chg, "Couldn't read TYPE_C_INTRPT_ENB_SOFTWARE_CTRL rc=%d\n",
			rc);
		return rc;
	}
	smblib_dbg(chg, PR_REGISTER, "TYPE_C_INTRPT_ENB_SOFTWARE_CTRL = 0x%02x\n",
		   ctrl);

	if (ctrl & TYPEC_DISABLE_CMD_BIT) {
		val->intval = POWER_SUPPLY_TYPEC_PR_NONE;
		return rc;
	}

	switch (ctrl & (DFP_EN_CMD_BIT | UFP_EN_CMD_BIT)) {
	case 0:
		val->intval = POWER_SUPPLY_TYPEC_PR_DUAL;
		break;
	case DFP_EN_CMD_BIT:
		val->intval = POWER_SUPPLY_TYPEC_PR_SOURCE;
		break;
	case UFP_EN_CMD_BIT:
		val->intval = POWER_SUPPLY_TYPEC_PR_SINK;
		break;
	default:
		val->intval = POWER_SUPPLY_TYPEC_PR_NONE;
		smblib_err(chg, "unsupported power role 0x%02lx\n",
			ctrl & (DFP_EN_CMD_BIT | UFP_EN_CMD_BIT));
		return -EINVAL;
	}

	return rc;
}

int smblib_get_prop_pd_allowed(struct smb_charger *chg,
			       union power_supply_propval *val)
{
/* david.liu@bsp, 201710503 Fix slow SRC & SNK */
	if (chg->pd_disabled)
		val->intval = 0;
	else
		val->intval = get_effective_result(chg->pd_allowed_votable);
	return 0;
}

int smblib_get_prop_input_current_settled(struct smb_charger *chg,
					  union power_supply_propval *val)
{
	return smblib_get_charge_param(chg, &chg->param.icl_stat, &val->intval);
}

#define HVDCP3_STEP_UV	200000
int smblib_get_prop_input_voltage_settled(struct smb_charger *chg,
						union power_supply_propval *val)
{
	const struct apsd_result *apsd_result = smblib_get_apsd_result(chg);
	int rc, pulses;
	u8 stat;

	val->intval = MICRO_5V;
	if (apsd_result == NULL) {
		smblib_err(chg, "APSD result is NULL\n");
		return 0;
	}

	switch (apsd_result->pst) {
	case POWER_SUPPLY_TYPE_USB_HVDCP_3:
		rc = smblib_read(chg, QC_PULSE_COUNT_STATUS_REG, &stat);
		if (rc < 0) {
			smblib_err(chg,
				"Couldn't read QC_PULSE_COUNT rc=%d\n", rc);
			return 0;
		}
		pulses = (stat & QC_PULSE_COUNT_MASK);
		val->intval = MICRO_5V + HVDCP3_STEP_UV * pulses;
		break;
	default:
		val->intval = MICRO_5V;
		break;
	}

	return 0;
}

int smblib_get_prop_pd_in_hard_reset(struct smb_charger *chg,
			       union power_supply_propval *val)
{
	mutex_lock(&chg->pd_hard_reset_lock);
	val->intval = chg->pd_hard_reset;
	mutex_unlock(&chg->pd_hard_reset_lock);
	return 0;
}

int smblib_get_pe_start(struct smb_charger *chg,
			       union power_supply_propval *val)
{
	/*
	 * hvdcp timeout voter is the last one to allow pd. Use its vote
	 * to indicate start of pe engine
	 */
	val->intval
		= !get_client_vote_locked(chg->pd_disallowed_votable_indirect,
			HVDCP_TIMEOUT_VOTER);
	return 0;
}

int smblib_get_prop_die_health(struct smb_charger *chg,
						union power_supply_propval *val)
{
	int rc;
	u8 stat;

	rc = smblib_read(chg, TEMP_RANGE_STATUS_REG, &stat);
	if (rc < 0) {
		smblib_err(chg, "Couldn't read TEMP_RANGE_STATUS_REG rc=%d\n",
									rc);
		return rc;
	}

	/* TEMP_RANGE bits are mutually exclusive */
	switch (stat & TEMP_RANGE_MASK) {
	case TEMP_BELOW_RANGE_BIT:
		val->intval = POWER_SUPPLY_HEALTH_COOL;
		break;
	case TEMP_WITHIN_RANGE_BIT:
		val->intval = POWER_SUPPLY_HEALTH_WARM;
		break;
	case TEMP_ABOVE_RANGE_BIT:
		val->intval = POWER_SUPPLY_HEALTH_HOT;
		break;
	case ALERT_LEVEL_BIT:
		val->intval = POWER_SUPPLY_HEALTH_OVERHEAT;
		break;
	default:
		val->intval = POWER_SUPPLY_HEALTH_UNKNOWN;
	}

	return 0;
}

/*******************
 * USB PSY SETTERS *
 * *****************/

int smblib_set_prop_pd_current_max(struct smb_charger *chg,
				    const union power_supply_propval *val)
{
	int rc;

	if (chg->pd_active)
		rc = vote(chg->usb_icl_votable, PD_VOTER, true, val->intval);
	else
		rc = -EPERM;

	return rc;
}

int smblib_set_prop_usb_current_max(struct smb_charger *chg,
				    const union power_supply_propval *val)
{
	int rc = 0;

/* david.liu@bsp, 20161014 Add charging standard */
	pr_err("set usb current_max=%d\n", val->intval);
	if (!chg->pd_active) {
		rc = vote(chg->usb_icl_votable, USB_PSY_VOTER,
				true, val->intval);
	} else if (chg->system_suspend_supported) {
		if (val->intval <= USBIN_25MA)
			rc = vote(chg->usb_icl_votable,
				PD_SUSPEND_SUPPORTED_VOTER, true, val->intval);
		else
			rc = vote(chg->usb_icl_votable,
				PD_SUSPEND_SUPPORTED_VOTER, false, 0);
	}
	return rc;
}

int smblib_set_prop_boost_current(struct smb_charger *chg,
				    const union power_supply_propval *val)
{
	int rc = 0;

	rc = smblib_set_charge_param(chg, &chg->param.freq_boost,
				val->intval <= chg->boost_threshold_ua ?
				chg->chg_freq.freq_below_otg_threshold :
				chg->chg_freq.freq_above_otg_threshold);
	if (rc < 0) {
		dev_err(chg->dev, "Error in setting freq_boost rc=%d\n", rc);
		return rc;
	}

	chg->boost_current_ua = val->intval;
	return rc;
}

int smblib_set_prop_typec_power_role(struct smb_charger *chg,
				     const union power_supply_propval *val)
{
	int rc = 0;
	u8 power_role;

	switch (val->intval) {
	case POWER_SUPPLY_TYPEC_PR_NONE:
		power_role = TYPEC_DISABLE_CMD_BIT;
		break;
	case POWER_SUPPLY_TYPEC_PR_DUAL:
		power_role = 0;
		break;
	case POWER_SUPPLY_TYPEC_PR_SINK:
		power_role = UFP_EN_CMD_BIT;
		break;
	case POWER_SUPPLY_TYPEC_PR_SOURCE:
		power_role = DFP_EN_CMD_BIT;
		break;
	default:
		smblib_err(chg, "power role %d not supported\n", val->intval);
		return -EINVAL;
	}

	rc = smblib_masked_write(chg, TYPE_C_INTRPT_ENB_SOFTWARE_CTRL_REG,
				 TYPEC_POWER_ROLE_CMD_MASK, power_role);
	if (rc < 0) {
		smblib_err(chg, "Couldn't write 0x%02x to TYPE_C_INTRPT_ENB_SOFTWARE_CTRL rc=%d\n",
			power_role, rc);
		return rc;
	}

	return rc;
}

int smblib_set_prop_usb_voltage_min(struct smb_charger *chg,
				    const union power_supply_propval *val)
{
	int rc, min_uv;

	min_uv = min(val->intval, chg->voltage_max_uv);
	rc = smblib_set_usb_pd_allowed_voltage(chg, min_uv,
					       chg->voltage_max_uv);
	if (rc < 0) {
		smblib_err(chg, "invalid max voltage %duV rc=%d\n",
			val->intval, rc);
		return rc;
	}

	if (chg->mode == PARALLEL_MASTER)
		vote(chg->pl_enable_votable_indirect, USBIN_V_VOTER,
		     min_uv > MICRO_5V, 0);

	chg->voltage_min_uv = min_uv;
	return rc;
}

int smblib_set_prop_usb_voltage_max(struct smb_charger *chg,
				    const union power_supply_propval *val)
{
	int rc, max_uv;

	max_uv = max(val->intval, chg->voltage_min_uv);
	rc = smblib_set_usb_pd_allowed_voltage(chg, chg->voltage_min_uv,
					       max_uv);
	if (rc < 0) {
		smblib_err(chg, "invalid min voltage %duV rc=%d\n",
			val->intval, rc);
		return rc;
	}

	chg->voltage_max_uv = max_uv;
	return rc;
}

int smblib_set_prop_pd_active(struct smb_charger *chg,
			      const union power_supply_propval *val)
{
	int rc;
	bool orientation, cc_debounced, sink_attached, hvdcp;
	u8 stat;


/* david.liu@bsp, 20160926 Add dash charging */
	if (chg->pd_disabled)
		return rc;

	pr_info("set pd_active=%d\n", val->intval);
	if (!get_effective_result(chg->pd_allowed_votable))
		return -EINVAL;
	rc = smblib_read(chg, APSD_STATUS_REG, &stat);
	if (rc < 0) {
		smblib_err(chg, "Couldn't read APSD status rc=%d\n", rc);
		return rc;
	}
	cc_debounced = (bool)
		(chg->typec_status[3] & TYPEC_DEBOUNCE_DONE_STATUS_BIT);
	sink_attached = (bool)
		(chg->typec_status[3] & UFP_DFP_MODE_STATUS_BIT);
	hvdcp = stat & QC_CHARGER_BIT;
	chg->pd_active = val->intval;
	if (chg->pd_active) {
		vote(chg->apsd_disable_votable, PD_VOTER, true, 0);
		vote(chg->pd_allowed_votable, PD_VOTER, true, 0);
		vote(chg->usb_irq_enable_votable, PD_VOTER, true, 0);

		/*
		 * VCONN_EN_ORIENTATION_BIT controls whether to use CC1 or CC2
		 * line when TYPEC_SPARE_CFG_BIT (CC pin selection s/w override)
		  * is set or when VCONN_EN_VALUE_BIT is set.
		   */
		orientation = chg->typec_status[3] & CC_ORIENTATION_BIT;
		rc = smblib_masked_write(chg,
				TYPE_C_INTRPT_ENB_SOFTWARE_CTRL_REG,
				VCONN_EN_ORIENTATION_BIT,
				orientation ? 0 : VCONN_EN_ORIENTATION_BIT);
		if (rc < 0)
			smblib_err(chg,
				"Couldn't enable vconn on CC line rc=%d\n", rc);
		/* SW controlled CC_OUT */
		rc = smblib_masked_write(chg, TAPER_TIMER_SEL_CFG_REG,
		TYPEC_SPARE_CFG_BIT, TYPEC_SPARE_CFG_BIT);
		if (rc < 0)
			smblib_err(chg, "Couldn't enable SW cc_out rc=%d\n",
					rc);

		/*
		 * Enforce 500mA for PD until the real vote comes in later.
		 * It is guaranteed that pd_active is set prior to
		 * pd_current_max
		 */
		rc = vote(chg->usb_icl_votable, PD_VOTER, true, USBIN_500MA);
		if (rc < 0)
			smblib_err(chg, "Couldn't vote for USB ICL rc=%d\n",
					rc);

		/* since PD was found the cable must be non-legacy */
		vote(chg->usb_icl_votable, LEGACY_UNKNOWN_VOTER, false, 0);

		/* clear USB ICL vote for DCP_VOTER */
		rc = vote(chg->usb_icl_votable, DCP_VOTER, false, 0);
		if (rc < 0)
			smblib_err(chg,
				"Couldn't un-vote DCP from USB ICL rc=%d\n",
				rc);

		/* clear USB ICL vote for PL_USBIN_USBIN_VOTER */
		rc = vote(chg->usb_icl_votable, PL_USBIN_USBIN_VOTER, false, 0);
		if (rc < 0)
			smblib_err(chg,
					"Couldn't un-vote PL_USBIN_USBIN from USB ICL rc=%d\n",
					rc);

		/* remove USB_PSY_VOTER */
		rc = vote(chg->usb_icl_votable, USB_PSY_VOTER, false, 0);
		if (rc < 0)
			smblib_err(chg, "Couldn't unvote USB_PSY rc=%d\n", rc);

		/* pd active set, parallel charger can be enabled now */
		rc = vote(chg->pl_disable_votable, PL_DELAY_HVDCP_VOTER,
				false, 0);
		if (rc < 0)
			smblib_err(chg, "Couldn't unvote PL_DELAY_HVDCP_VOTER rc=%d\n",
					rc);
	} else {
		vote(chg->apsd_disable_votable, PD_VOTER, false, 0);
		vote(chg->hvdcp_disable_votable_indirect, PD_INACTIVE_VOTER,
								false, 0);

		/*
		 * This WA should only run for HVDCP. Non-legacy SDP/CDP could
		 * draw more, but this WA will remove Rd causing VBUS to drop,
		 * and data could be interrupted. Non-legacy DCP could also draw
		 * more, but it may impact compliance.
		 */
		if (!chg->typec_legacy_valid && cc_debounced &&
						!sink_attached && hvdcp) {
			schedule_work(&chg->legacy_detection_work);
		}
	}

	smblib_update_usb_type(chg);
	power_supply_changed(chg->usb_psy);

	return rc;
}
int smblib_set_prop_ship_mode(struct smb_charger *chg,
				const union power_supply_propval *val)
{
	int rc;

	smblib_dbg(chg, PR_MISC, "Set ship mode: %d!!\n", !!val->intval);

	rc = smblib_masked_write(chg, SHIP_MODE_REG, SHIP_MODE_EN_BIT,
			!!val->intval ? SHIP_MODE_EN_BIT : 0);
	if (rc < 0)
		dev_err(chg->dev, "Couldn't %s ship mode, rc=%d\n",
				!!val->intval ? "enable" : "disable", rc);

	return rc;
}

int smblib_reg_block_update(struct smb_charger *chg,
				struct reg_info *entry)
{
	int rc = 0;

	while (entry && entry->reg) {
		rc = smblib_read(chg, entry->reg, &entry->bak);
		if (rc < 0) {
			dev_err(chg->dev, "Error in reading %s rc=%d\n",
				entry->desc, rc);
			break;
		}
		entry->bak &= entry->mask;

		rc = smblib_masked_write(chg, entry->reg,
					 entry->mask, entry->val);
		if (rc < 0) {
			dev_err(chg->dev, "Error in writing %s rc=%d\n",
				entry->desc, rc);
			break;
		}
		entry++;
	}

	return rc;
}

int smblib_reg_block_restore(struct smb_charger *chg,
				struct reg_info *entry)
{
	int rc = 0;

	while (entry && entry->reg) {
		rc = smblib_masked_write(chg, entry->reg,
					 entry->mask, entry->bak);
		if (rc < 0) {
			dev_err(chg->dev, "Error in writing %s rc=%d\n",
				entry->desc, rc);
			break;
		}
		entry++;
	}

	return rc;
}

static struct reg_info cc2_detach_settings[] = {
	{
		.reg	= TYPE_C_CFG_2_REG,
		.mask	= TYPE_C_UFP_MODE_BIT | EN_TRY_SOURCE_MODE_BIT,
		.val	= TYPE_C_UFP_MODE_BIT,
		.desc	= "TYPE_C_CFG_2_REG",
	},
	{
		.reg	= TYPE_C_CFG_3_REG,
		.mask	= EN_TRYSINK_MODE_BIT,
		.val	= 0,
		.desc	= "TYPE_C_CFG_3_REG",
	},
	{
		.reg	= TAPER_TIMER_SEL_CFG_REG,
		.mask	= TYPEC_SPARE_CFG_BIT,
		.val	= TYPEC_SPARE_CFG_BIT,
		.desc	= "TAPER_TIMER_SEL_CFG_REG",
	},
	{
		.reg	= TYPE_C_INTRPT_ENB_SOFTWARE_CTRL_REG,
		.mask	= VCONN_EN_ORIENTATION_BIT,
		.val	= 0,
		.desc	= "TYPE_C_INTRPT_ENB_SOFTWARE_CTRL_REG",
	},
	{
		.reg	= MISC_CFG_REG,
		.mask	= TCC_DEBOUNCE_20MS_BIT,
		.val	= TCC_DEBOUNCE_20MS_BIT,
		.desc	= "Tccdebounce time"
	},
	{
	},
};

static int smblib_cc2_sink_removal_enter(struct smb_charger *chg)
{
	int rc, ccout, ufp_mode;
	u8 stat;

	if ((chg->wa_flags & TYPEC_CC2_REMOVAL_WA_BIT) == 0)
		return 0;

	if (chg->cc2_sink_detach_flag)
		return 0;

	rc = smblib_read(chg, TYPE_C_STATUS_4_REG, &stat);
	if (rc < 0) {
		smblib_err(chg, "Couldn't read TYPE_C_STATUS_4 rc=%d\n", rc);
		return rc;
	}
	ccout = (stat & CC_ATTACHED_BIT) ?
	                                (!!(stat & CC_ORIENTATION_BIT) + 1) : 0;
	ufp_mode = (stat & TYPEC_DEBOUNCE_DONE_STATUS_BIT) ?
	                                !!(stat & UFP_DFP_MODE_BIT) : 0;

	if (ccout != 2)
	        return 0;
	if (!ufp_mode)
	        return 0;
	chg->cc2_sink_detach_flag = true;
	vote(chg->typec_irq_disable_votable, CC2_WA_VOTER, true, 0);
	smblib_reg_block_update(chg, cc2_detach_settings);
	schedule_work(&chg->rdstd_cc2_detach_work);

	return rc;
}

static int smblib_cc2_sink_removal_exit(struct smb_charger *chg)
{
	if ((chg->wa_flags & TYPEC_CC2_REMOVAL_WA_BIT) == 0)
		return 0;

	if (!chg->cc2_sink_detach_flag)
	        return 0;

	chg->cc2_sink_detach_flag = false;
	cancel_work_sync(&chg->rdstd_cc2_detach_work);
	smblib_reg_block_restore(chg, cc2_detach_settings);
	vote(chg->typec_irq_disable_votable, CC2_WA_VOTER, false, 0);
	return 0;
}

int smblib_set_prop_pd_in_hard_reset(struct smb_charger *chg,
				const union power_supply_propval *val)
{
	int rc = 0;

/* david.liu@bsp, 20170202 Add pd_disabled */
	if(chg->pd_disabled)
		return rc;
	mutex_lock(&chg->pd_hard_reset_lock);
	if (chg->pd_hard_reset == val->intval)
		goto unlock;

	chg->pd_hard_reset = val->intval;
	rc = smblib_masked_write(chg, TYPE_C_INTRPT_ENB_SOFTWARE_CTRL_REG,
			EXIT_SNK_BASED_ON_CC_BIT,
			(chg->pd_hard_reset) ? EXIT_SNK_BASED_ON_CC_BIT : 0);
	if (rc < 0)
		smblib_err(chg, "Couldn't set EXIT_SNK_BASED_ON_CC rc=%d\n", rc);

	vote(chg->apsd_disable_votable, PD_HARD_RESET_VOTER,
						chg->pd_hard_reset, 0);	

unlock:
	mutex_unlock(&chg->pd_hard_reset_lock);
	return rc;
}

/***********************
* USB MAIN PSY GETTERS *
*************************/
int smblib_get_prop_fcc_delta(struct smb_charger *chg,
			       union power_supply_propval *val)
{
	int rc, jeita_cc_delta_ua, step_cc_delta_ua, hw_cc_delta_ua = 0;

	rc = smblib_get_step_cc_delta(chg, &step_cc_delta_ua);
	if (rc < 0) {
		smblib_err(chg, "Couldn't get step cc delta rc=%d\n", rc);
		step_cc_delta_ua = 0;
	} else {
		hw_cc_delta_ua = step_cc_delta_ua;
	}

	rc = smblib_get_jeita_cc_delta(chg, &jeita_cc_delta_ua);
	if (rc < 0) {
		smblib_err(chg, "Couldn't get jeita cc delta rc=%d\n", rc);
		jeita_cc_delta_ua = 0;
	} else if (jeita_cc_delta_ua < 0) {
		/* HW will take the min between JEITA and step charge */
		hw_cc_delta_ua = min(hw_cc_delta_ua, jeita_cc_delta_ua);
	}

	val->intval = hw_cc_delta_ua;
	return 0;
}

/***********************
* USB MAIN PSY SETTERS *
*************************/

#define SDP_CURRENT_MA			500000
#define CDP_CURRENT_MA			1500000
#define DCP_CURRENT_MA			1500000
#define HVDCP_CURRENT_MA		3000000
#define TYPEC_DEFAULT_CURRENT_MA	900000
#define TYPEC_MEDIUM_CURRENT_MA		1500000
#define TYPEC_HIGH_CURRENT_MA		3000000
static int smblib_get_charge_current(struct smb_charger *chg,
				int *total_current_ua)
{
	const struct apsd_result *apsd_result = smblib_update_usb_type(chg);
	union power_supply_propval val = {0, };
	int rc, typec_source_rd, current_ua;
	bool non_compliant;
	u8 stat5;

	rc = smblib_read(chg, TYPE_C_STATUS_5_REG, &stat5);
	if (rc < 0) {
		smblib_err(chg, "Couldn't read TYPE_C_STATUS_5 rc=%d\n", rc);
		return rc;
	}
	non_compliant = stat5 & TYPEC_NONCOMP_LEGACY_CABLE_STATUS_BIT;

	/* get settled ICL */
	rc = smblib_get_prop_input_current_settled(chg, &val);
	if (rc < 0) {
		smblib_err(chg, "Couldn't get settled ICL rc=%d\n", rc);
		return rc;
	}

	typec_source_rd = smblib_get_prop_ufp_mode(chg);

	/* QC 2.0/3.0 adapter */
	if (apsd_result->bit & (QC_3P0_BIT | QC_2P0_BIT)) {
		*total_current_ua = HVDCP_CURRENT_MA;
		return 0;
	}

	if (non_compliant) {
		switch (apsd_result->bit) {
		case CDP_CHARGER_BIT:
			current_ua = CDP_CURRENT_MA;
			break;
		case DCP_CHARGER_BIT:
		case OCP_CHARGER_BIT:
		case FLOAT_CHARGER_BIT:
			current_ua = DCP_CURRENT_MA;
			break;
		default:
			current_ua = 0;
			break;
		}

		*total_current_ua = max(current_ua, val.intval);
		return 0;
	}

	switch (typec_source_rd) {
	case POWER_SUPPLY_TYPEC_SOURCE_DEFAULT:
		switch (apsd_result->bit) {
		case CDP_CHARGER_BIT:
			current_ua = CDP_CURRENT_MA;
			break;
		case DCP_CHARGER_BIT:
		case OCP_CHARGER_BIT:
		case FLOAT_CHARGER_BIT:
			current_ua = chg->default_icl_ua;
			break;
		default:
			current_ua = 0;
			break;
		}
		break;
	case POWER_SUPPLY_TYPEC_SOURCE_MEDIUM:
		current_ua = TYPEC_MEDIUM_CURRENT_MA;
		break;
	case POWER_SUPPLY_TYPEC_SOURCE_HIGH:
		current_ua = TYPEC_HIGH_CURRENT_MA;
		break;
	case POWER_SUPPLY_TYPEC_NON_COMPLIANT:
	case POWER_SUPPLY_TYPEC_NONE:
	default:
		current_ua = 0;
		break;
	}

	*total_current_ua = max(current_ua, val.intval);
	return 0;
}

int smblib_set_icl_reduction(struct smb_charger *chg, int reduction_ua)
{
	int current_ua, rc;

	if (reduction_ua == 0) {
		vote(chg->usb_icl_votable, PL_USBIN_USBIN_VOTER, false, 0);
	} else {
		/*
		 * No usb_icl voter means we are defaulting to hw chosen
		 * max limit. We need a vote from s/w to enforce the reduction.
		 */
		if (get_effective_result(chg->usb_icl_votable) == -EINVAL) {
			rc = smblib_get_charge_current(chg, &current_ua);
			if (rc < 0) {
				pr_err("Failed to get ICL rc=%d\n", rc);
				return rc;
			}
			vote(chg->usb_icl_votable, PL_USBIN_USBIN_VOTER, true,
					current_ua);
		}
	}

	chg->icl_reduction_ua = reduction_ua;

	return rerun_election(chg->usb_icl_votable);
}

/************************
 * PARALLEL PSY GETTERS *
 ************************/

int smblib_get_prop_slave_current_now(struct smb_charger *chg,
				      union power_supply_propval *pval)
{
	if (IS_ERR_OR_NULL(chg->iio.batt_i_chan))
		chg->iio.batt_i_chan = iio_channel_get(chg->dev, "batt_i");

	if (IS_ERR(chg->iio.batt_i_chan))
		return PTR_ERR(chg->iio.batt_i_chan);

	return iio_read_channel_processed(chg->iio.batt_i_chan, &pval->intval);
}

/**********************
 * INTERRUPT HANDLERS *
 **********************/

irqreturn_t smblib_handle_debug(int irq, void *data)
{
	struct smb_irq_data *irq_data = data;
	struct smb_charger *chg = irq_data->parent_data;

	smblib_dbg(chg, PR_INTERRUPT, "IRQ: %s\n", irq_data->name);
	return IRQ_HANDLED;
}

irqreturn_t smblib_handle_otg_overcurrent(int irq, void *data)
{
	struct smb_irq_data *irq_data = data;
	struct smb_charger *chg = irq_data->parent_data;
	int rc;
	u8 stat;

	rc = smblib_read(chg, OTG_BASE + INT_RT_STS_OFFSET, &stat);
	if (rc < 0) {
		dev_err(chg->dev, "Couldn't read OTG_INT_RT_STS rc=%d\n", rc);
		return IRQ_HANDLED;
	}

	if (chg->wa_flags & OTG_WA) {
		if (stat & OTG_OC_DIS_SW_STS_RT_STS_BIT)
			smblib_err(chg, "OTG disabled by hw\n");

		/* not handling software based hiccups for PM660 */
		return IRQ_HANDLED;
	}

	if (stat & OTG_OVERCURRENT_RT_STS_BIT)
		schedule_work(&chg->otg_oc_work);

	return IRQ_HANDLED;
}

irqreturn_t smblib_handle_chg_state_change(int irq, void *data)
{
	struct smb_irq_data *irq_data = data;
	struct smb_charger *chg = irq_data->parent_data;
	u8 stat;
	int rc;

	smblib_dbg(chg, PR_INTERRUPT, "IRQ: %s\n", irq_data->name);

	rc = smblib_read(chg, BATTERY_CHARGER_STATUS_1_REG, &stat);
	if (rc < 0) {
		smblib_err(chg, "Couldn't read BATTERY_CHARGER_STATUS_1 rc=%d\n",
			rc);
		return IRQ_HANDLED;
	}

	stat = stat & BATTERY_CHARGER_STATUS_MASK;
/* david.liu@bsp, 20161109 Charging porting */
	if (stat == TERMINATE_CHARGE) {
		/* charge done, disable charge in software also */
		chg->chg_done = true;
		pr_err("TERMINATE_CHARGE: chg_done: CAP=%d (Q:%d), VBAT=%d (Q:%d), IBAT=%d (Q:%d), BAT_TEMP=%d\n",
			get_prop_batt_capacity(chg),
			get_prop_fg_capacity(chg),
			get_prop_batt_voltage_now(chg) / 1000,
			get_prop_fg_voltage_now(chg) / 1000,
			get_prop_batt_current_now(chg) / 1000,
			get_prop_fg_current_now(chg) / 1000,
			get_prop_batt_temp(chg));
		op_charging_en(chg, false);
	}
	power_supply_changed(chg->batt_psy);
	return IRQ_HANDLED;
}

irqreturn_t smblib_handle_step_chg_state_change(int irq, void *data)
{
	struct smb_irq_data *irq_data = data;
	struct smb_charger *chg = irq_data->parent_data;

	smblib_dbg(chg, PR_INTERRUPT, "IRQ: %s\n", irq_data->name);

	if (chg->step_chg_enabled)
		rerun_election(chg->fcc_votable);

	return IRQ_HANDLED;
}

irqreturn_t smblib_handle_step_chg_soc_update_fail(int irq, void *data)
{
	struct smb_irq_data *irq_data = data;
	struct smb_charger *chg = irq_data->parent_data;

	smblib_dbg(chg, PR_INTERRUPT, "IRQ: %s\n", irq_data->name);

	if (chg->step_chg_enabled)
		rerun_election(chg->fcc_votable);

	return IRQ_HANDLED;
}

#define STEP_SOC_REQ_MS	3000
irqreturn_t smblib_handle_step_chg_soc_update_request(int irq, void *data)
{
	struct smb_irq_data *irq_data = data;
	struct smb_charger *chg = irq_data->parent_data;
	int rc;
	union power_supply_propval pval = {0, };

	smblib_dbg(chg, PR_INTERRUPT, "IRQ: %s\n", irq_data->name);

	if (!chg->bms_psy) {
		schedule_delayed_work(&chg->step_soc_req_work,
				      msecs_to_jiffies(STEP_SOC_REQ_MS));
		return IRQ_HANDLED;
	}

	rc = smblib_get_prop_batt_capacity(chg, &pval);
	if (rc < 0)
		smblib_err(chg, "Couldn't get batt capacity rc=%d\n", rc);
	else
		step_charge_soc_update(chg, pval.intval);

	return IRQ_HANDLED;
}

irqreturn_t smblib_handle_batt_temp_changed(int irq, void *data)
{
	struct smb_irq_data *irq_data = data;
	struct smb_charger *chg = irq_data->parent_data;

	rerun_election(chg->fcc_votable);
	power_supply_changed(chg->batt_psy);
	return IRQ_HANDLED;
}

irqreturn_t smblib_handle_batt_psy_changed(int irq, void *data)
{
	struct smb_irq_data *irq_data = data;
	struct smb_charger *chg = irq_data->parent_data;

	smblib_dbg(chg, PR_INTERRUPT, "IRQ: %s\n", irq_data->name);
	power_supply_changed(chg->batt_psy);
	return IRQ_HANDLED;
}

irqreturn_t smblib_handle_usb_psy_changed(int irq, void *data)
{
	struct smb_irq_data *irq_data = data;
	struct smb_charger *chg = irq_data->parent_data;

	smblib_dbg(chg, PR_INTERRUPT, "IRQ: %s\n", irq_data->name);
	power_supply_changed(chg->usb_psy);
	return IRQ_HANDLED;
}
irqreturn_t smblib_handle_usbin_uv(int irq, void *data)
{
	struct smb_irq_data *irq_data = data;
	struct smb_charger *chg = irq_data->parent_data;
	struct storm_watch *wdata;

	smblib_dbg(chg, PR_INTERRUPT, "IRQ: %s\n", irq_data->name);
	if (!chg->irq_info[SWITCH_POWER_OK_IRQ].irq_data)
		return IRQ_HANDLED;

	wdata = &chg->irq_info[SWITCH_POWER_OK_IRQ].irq_data->storm_data;
	reset_storm_count(wdata);
	smblib_err(chg, "DEBUG: RESET STORM COUNT FOR POWER_OK\n");
	return IRQ_HANDLED;
}

static inline void op_dump_reg(struct smb_charger *chip, u16 addr)
{
	u8 reg;

	smblib_read(chip, addr, &reg);
	pr_err("%04X = %02X\n", addr, reg);
}

static void op_dump_regs(struct smb_charger *chip)
{
	u16 addr;

	for (addr = 0x1000; addr <= 0x1700; addr++)
		op_dump_reg(chip, addr);
}

void smblib_micro_usb_plugin(struct smb_charger *chg, bool vbus_rising)
{
	if (!vbus_rising) {
		chg->usb_present = 1;
	} else {
		chg->usb_present = 0;
		smblib_update_usb_type(chg);
		extcon_set_cable_state_(chg->extcon, EXTCON_USB, false);
		smblib_uusb_removal(chg);
	}
}

void smblib_typec_usb_plugin(struct smb_charger *chg, bool vbus_rising)
{
	if (vbus_rising)
		smblib_cc2_sink_removal_exit(chg);
	else
		smblib_cc2_sink_removal_enter(chg);
}

void smblib_usb_plugin(struct smb_charger *chg)
{
	int rc;
	u8 stat;
	bool vbus_rising;
/* david.liu@bsp, 20161014 Add charging standard */
	union power_supply_propval vbus_val;
	bool last_vbus_present;
	int is_usb_supend;
	last_vbus_present = chg->vbus_present;
	chg->dash_on = get_prop_fast_chg_started(chg);
	if (chg->dash_on) {
		pr_err("return directly because dash is online\n");
		return;
	}
	rc = smblib_read(chg, USBIN_BASE + INT_RT_STS_OFFSET, &stat);
	if (rc < 0) {
		smblib_err(chg, "Couldn't read USB_INT_RT_STS rc=%d\n", rc);
		return;
	}

	vbus_rising = (bool)(stat & USBIN_PLUGIN_RT_STS_BIT);
	smblib_set_opt_freq_buck(chg, vbus_rising ? chg->chg_freq.freq_5V :
						chg->chg_freq.freq_removal);

	/* fetch the DPDM regulator */
	if (!chg->dpdm_reg && of_get_property(chg->dev->of_node,
						"dpdm-supply", NULL)) {
		chg->dpdm_reg = devm_regulator_get(chg->dev, "dpdm");
		if (IS_ERR(chg->dpdm_reg)) {
			smblib_err(chg, "Couldn't get dpdm regulator rc=%ld\n",
				PTR_ERR(chg->dpdm_reg));
			chg->dpdm_reg = NULL;
		}
	}

/* david.liu@bsp, 20161014 Add charging standard */
	chg->vbus_present = vbus_rising;
	if (last_vbus_present != chg->vbus_present) {
		if (chg->vbus_present) {
			pr_info("acquire chg_wake_lock\n");
			wake_lock(&chg->chg_wake_lock);
			smblib_get_usb_suspend(chg,&is_usb_supend);
			if(is_usb_supend && chg->deal_vusbin_error_done){
			vote(chg->usb_icl_votable,
                                   BOOST_BACK_VOTER, false, 0);
			chg->deal_vusbin_error_done = false;
                   }
		} else {
			pr_info("release chg_wake_lock\n");
			wake_unlock(&chg->chg_wake_lock);
		}
	}

	if (vbus_rising) {
		if (chg->dpdm_reg && !regulator_is_enabled(chg->dpdm_reg)) {
			smblib_dbg(chg, PR_MISC, "enabling DPDM regulator\n");
			rc = regulator_enable(chg->dpdm_reg);
			if (rc < 0)
				smblib_err(chg, "Couldn't enable dpdm regulator rc=%d\n",
					rc);
		}
		if (chg->micro_usb_mode)
			chg->usb_present = 1;
		if (chg->charger_collpse) {
			op_set_collapse_fet(chg, 0);
			chg->charger_collpse = false;
		}
		schedule_delayed_work(&chg->op_check_apsd_work,
				msecs_to_jiffies(TIME_1000MS));

	} else {
		if (chg->wa_flags & BOOST_BACK_WA)
			vote(chg->usb_icl_votable, BOOST_BACK_VOTER, false, 0);

		if (chg->dpdm_reg && regulator_is_enabled(chg->dpdm_reg)) {
			smblib_dbg(chg, PR_MISC, "disabling DPDM regulator\n");
			rc = regulator_disable(chg->dpdm_reg);
			if (rc < 0)
				smblib_err(chg, "Couldn't disable dpdm regulator rc=%d\n",
					rc);
		}

/* david.liu@bsp, 20160926 Add dash charging */
		if (last_vbus_present != chg->vbus_present)
			op_handle_usb_removal(chg);

		if (chg->micro_usb_mode)
			chg->usb_present = 0;
	}

	if (chg->micro_usb_mode)
		smblib_micro_usb_plugin(chg, vbus_rising);
	else
	        smblib_typec_usb_plugin(chg, vbus_rising);

	power_supply_changed(chg->usb_psy);
	smblib_dbg(chg, PR_INTERRUPT, "IRQ: usbin-plugin %s\n",
		vbus_rising ? "attached" : "detached");
/* david.liu@bsp, 20160926 Add dash charging */
		if (!vbus_rising) {
			rc = smblib_get_prop_usb_voltage_now(chg, &vbus_val);
			if (rc < 0) {
				pr_err("V  fail rc=%d\n", rc);
			} else {
				if (vbus_val.intval > 3000) {
					pr_err("unplg,Vbus=%d",
						vbus_val.intval);
					op_dump_regs(chg);
				}
			}
		}

	pr_err("IRQ: %s %s\n",
		__func__, vbus_rising ? "attached" : "detached");
}

irqreturn_t smblib_handle_usb_plugin(int irq, void *data)
{
	struct smb_irq_data *irq_data = data;
	struct smb_charger *chg = irq_data->parent_data;

	mutex_lock(&chg->lock);
	smblib_usb_plugin(chg);
	mutex_unlock(&chg->lock);
	return IRQ_HANDLED;
}
void op_handle_usb_plugin(struct smb_charger *chg)
{
	mutex_lock(&chg->lock);
	smblib_usb_plugin(chg);
	mutex_unlock(&chg->lock);
}

#define USB_WEAK_INPUT_UA	1400000
#define ICL_CHANGE_DELAY_MS	1000
irqreturn_t smblib_handle_icl_change(int irq, void *data)
{
	u8 stat;
	int rc, settled_ua, delay = ICL_CHANGE_DELAY_MS;
	struct smb_irq_data *irq_data = data;
	struct smb_charger *chg = irq_data->parent_data;

	if (chg->mode == PARALLEL_MASTER) {
		rc = smblib_read(chg, AICL_STATUS_REG, &stat);
		if (rc < 0) {
			smblib_err(chg, "Couldn't read AICL_STATUS rc=%d\n",
					rc);
			return IRQ_HANDLED;
		}

		rc = smblib_get_charge_param(chg, &chg->param.icl_stat,
				&settled_ua);
		if (rc < 0) {
			smblib_err(chg, "Couldn't get ICL status rc=%d\n", rc);
			return IRQ_HANDLED;
		}

		/* If AICL settled then schedule work now */
		if ((settled_ua == get_effective_result(chg->usb_icl_votable))
				|| (stat & AICL_DONE_BIT))
			delay = 0;

		cancel_delayed_work_sync(&chg->icl_change_work);
		schedule_delayed_work(&chg->icl_change_work,
						msecs_to_jiffies(delay));
	}

	return IRQ_HANDLED;
}

static void smblib_handle_slow_plugin_timeout(struct smb_charger *chg,
					      bool rising)
{
	smblib_dbg(chg, PR_INTERRUPT, "IRQ: slow-plugin-timeout %s\n",
		   rising ? "rising" : "falling");
}

static void smblib_handle_sdp_enumeration_done(struct smb_charger *chg,
					       bool rising)
{
	smblib_dbg(chg, PR_INTERRUPT, "IRQ: sdp-enumeration-done %s\n",
		   rising ? "rising" : "falling");
}

#define QC3_PULSES_FOR_6V	5
#define QC3_PULSES_FOR_9V	20
#define QC3_PULSES_FOR_12V	35
static void smblib_hvdcp_adaptive_voltage_change(struct smb_charger *chg)
{
	int rc;
	u8 stat;
	int pulses;

	power_supply_changed(chg->usb_main_psy);
	if (chg->usb_psy_desc.type == POWER_SUPPLY_TYPE_USB_HVDCP) {
		rc = smblib_read(chg, QC_CHANGE_STATUS_REG, &stat);
		if (rc < 0) {
			smblib_err(chg,
				"Couldn't read QC_CHANGE_STATUS rc=%d\n", rc);
			return;
		}

		switch (stat & QC_2P0_STATUS_MASK) {
		case QC_5V_BIT:
			smblib_set_opt_freq_buck(chg,
					chg->chg_freq.freq_5V);
			break;
		case QC_9V_BIT:
			smblib_set_opt_freq_buck(chg,
					chg->chg_freq.freq_9V);
			break;
		case QC_12V_BIT:
			smblib_set_opt_freq_buck(chg,
					chg->chg_freq.freq_12V);
			break;
		default:
			smblib_set_opt_freq_buck(chg,
					chg->chg_freq.freq_removal);
			break;
		}
	}

	if (chg->usb_psy_desc.type == POWER_SUPPLY_TYPE_USB_HVDCP_3) {
		rc = smblib_read(chg, QC_PULSE_COUNT_STATUS_REG, &stat);
		if (rc < 0) {
			smblib_err(chg,
				"Couldn't read QC_PULSE_COUNT rc=%d\n", rc);
			return;
		}
		pulses = (stat & QC_PULSE_COUNT_MASK);

		if (pulses < QC3_PULSES_FOR_6V)
			smblib_set_opt_freq_buck(chg,
				chg->chg_freq.freq_5V);
		else if (pulses < QC3_PULSES_FOR_9V)
			smblib_set_opt_freq_buck(chg,
				chg->chg_freq.freq_6V_8V);
		else if (pulses < QC3_PULSES_FOR_12V)
			smblib_set_opt_freq_buck(chg,
				chg->chg_freq.freq_9V);
		else
			smblib_set_opt_freq_buck(chg,
				chg->chg_freq.freq_12V);
	}
}

/* triggers when HVDCP 3.0 authentication has finished */
static void smblib_handle_hvdcp_3p0_auth_done(struct smb_charger *chg,
					      bool rising)
{
	const struct apsd_result *apsd_result;
	int rc;

	if (!rising)
		return;

	if (chg->wa_flags & QC_AUTH_INTERRUPT_WA_BIT) {
		/*
		 * Disable AUTH_IRQ_EN_CFG_BIT to receive adapter voltage
		 * change interrupt.
		 */
		rc = smblib_masked_write(chg,
				USBIN_SOURCE_CHANGE_INTRPT_ENB_REG,
				AUTH_IRQ_EN_CFG_BIT, 0);
		if (rc < 0)
			smblib_err(chg,
				"Couldn't enable QC auth setting rc=%d\n", rc);
	}

	if (chg->mode == PARALLEL_MASTER)
		vote(chg->pl_enable_votable_indirect, USBIN_V_VOTER, true, 0);

	/* the APSD done handler will set the USB supply type */
	apsd_result = smblib_get_apsd_result(chg);
	if (get_effective_result(chg->hvdcp_hw_inov_dis_votable)) {
		if (apsd_result->pst == POWER_SUPPLY_TYPE_USB_HVDCP) {
			/* force HVDCP2 to 9V if INOV is disabled */
			rc = smblib_masked_write(chg, CMD_HVDCP_2_REG,
					FORCE_9V_BIT, FORCE_9V_BIT);
			if (rc < 0)
				smblib_err(chg,
					"Couldn't force 9V HVDCP rc=%d\n", rc);
		}
	}

	/* QC authentication done, parallel charger can be enabled now */
	vote(chg->pl_disable_votable, PL_DELAY_HVDCP_VOTER, false, 0);

	smblib_dbg(chg, PR_INTERRUPT, "IRQ: hvdcp-3p0-auth-done rising; %s detected\n",
		   apsd_result->name);
}

static void smblib_handle_hvdcp_check_timeout(struct smb_charger *chg,
					      bool rising, bool qc_charger)
{
	const struct apsd_result *apsd_result = smblib_update_usb_type(chg);

	/* Hold off PD only until hvdcp 2.0 detection timeout */
	if (rising) {
		vote(chg->pd_disallowed_votable_indirect, HVDCP_TIMEOUT_VOTER,
								false, 0);

		/* enable HDC and ICL irq for QC2/3 charger */
		if (qc_charger)
			vote(chg->usb_irq_enable_votable, QC_VOTER, true, 0);

		/*
		 * HVDCP detection timeout done
		 * If adapter is not QC2.0/QC3.0 - it is a plain old DCP.
		 */
		if (!qc_charger && (apsd_result->bit & DCP_CHARGER_BIT))
			/* enforce DCP ICL if specified */
			vote(chg->usb_icl_votable, DCP_VOTER,
				chg->dcp_icl_ua != -EINVAL, chg->dcp_icl_ua);
		/*
		 * If adapter is not QC2.0/QC3.0 remove vote for parallel
		 * disable.
		 * Otherwise if adapter is QC2.0/QC3.0 wait for authentication
		 * to complete.
		 */
		if (!qc_charger)
			vote(chg->pl_disable_votable, PL_DELAY_HVDCP_VOTER,
					false, 0);
	}

	smblib_dbg(chg, PR_INTERRUPT, "IRQ: smblib_handle_hvdcp_check_timeout %s\n",
		   rising ? "rising" : "falling");
}

/* triggers when HVDCP is detected */
static void smblib_handle_hvdcp_detect_done(struct smb_charger *chg,
					    bool rising)
{
	if (!rising)
		return;

	/* the APSD done handler will set the USB supply type */
	cancel_delayed_work_sync(&chg->hvdcp_detect_work);
	smblib_dbg(chg, PR_INTERRUPT, "IRQ: hvdcp-detect-done %s\n",
		   rising ? "rising" : "falling");
}

static void smblib_force_legacy_icl(struct smb_charger *chg, int pst)
{
	/* while PD is active it should have complete ICL control */
	if (chg->pd_active)
		return;

	switch (pst) {
	case POWER_SUPPLY_TYPE_USB:
		/*
		 * USB_PSY will vote to increase the current to 500/900mA once
		 * enumeration is done. Ensure that USB_PSY has at least voted
		 * for 100mA before releasing the LEGACY_UNKNOWN vote
		 */
		if (!is_client_vote_enabled(chg->usb_icl_votable,
								USB_PSY_VOTER))
			vote(chg->usb_icl_votable, USB_PSY_VOTER, true, 500000);
		vote(chg->usb_icl_votable, LEGACY_UNKNOWN_VOTER, false, 0);
		break;
	case POWER_SUPPLY_TYPE_USB_CDP:
		vote(chg->usb_icl_votable, LEGACY_UNKNOWN_VOTER, true, 1500000);
		break;
	case POWER_SUPPLY_TYPE_USB_DCP:
		vote(chg->usb_icl_votable, LEGACY_UNKNOWN_VOTER, true, 1500000);
		break;
	case POWER_SUPPLY_TYPE_USB_HVDCP:
	case POWER_SUPPLY_TYPE_USB_HVDCP_3:
		vote(chg->usb_icl_votable, LEGACY_UNKNOWN_VOTER, true, 3000000);
		break;
	default:
		smblib_err(chg, "Unknown APSD %d; forcing 500mA\n", pst);
		vote(chg->usb_icl_votable, LEGACY_UNKNOWN_VOTER, true, 500000);
		break;
	}
}

#define HVDCP_DET_MS 2500
#define DEFAULT_SDP_MA		500
#define DEFAULT_CDP_MA		1500
#define DEFAULT_DCP_MA		1500
#define DEFAULT_AGAING_CHG_MA		1000

int op_rerun_apsd(struct smb_charger *chg)
{
	union power_supply_propval val;
	int rc;

	rc = smblib_get_prop_usb_present(chg, &val);
	if (rc < 0) {
		smblib_err(chg, "Couldn't get usb present rc = %d\n", rc);
		return rc;
	}

	if (!val.intval)
		return 0;
		/* rerun APSD */
		pr_info("OP Reruning APSD type\n");
		rc = smblib_masked_write(chg, CMD_APSD_REG,
					APSD_RERUN_BIT,
					APSD_RERUN_BIT);
		if (rc < 0) {
			smblib_err(chg, "Couldn't rerun APSD rc = %d\n", rc);
			return rc;
		}
	return 0;
}
static void smblib_handle_apsd_done(struct smb_charger *chg, bool rising)
{
/* david.liu@bsp, 20161109 Charging porting */
	int temp_region,current_limit_ua;
	const struct apsd_result *apsd_result;

	if (!rising)
		return;

	apsd_result = smblib_update_usb_type(chg);

	if (!chg->typec_legacy_valid)
		smblib_force_legacy_icl(chg, apsd_result->pst);

	switch (apsd_result->bit) {
	case SDP_CHARGER_BIT:
	case CDP_CHARGER_BIT:
		if (chg->micro_usb_mode)
			extcon_set_cable_state_(chg->extcon, EXTCON_USB,
					true);
	case OCP_CHARGER_BIT:
	case FLOAT_CHARGER_BIT:
		/*
		 * if not DCP then no hvdcp timeout happens. Enable
		 * pd/parallel here.
		 */
		vote(chg->pd_disallowed_votable_indirect, HVDCP_TIMEOUT_VOTER,
				false, 0);
		vote(chg->pl_disable_votable, PL_DELAY_HVDCP_VOTER, false, 0);
		break;
	case DCP_CHARGER_BIT:
		if (chg->wa_flags & QC_CHARGER_DETECTION_WA_BIT)
			schedule_delayed_work(&chg->hvdcp_detect_work,
					      msecs_to_jiffies(HVDCP_DET_MS));
		break;
	default:
		break;
	}

/* david.liu@bsp, 20160926 Add dash charging */
	if((apsd_result->bit)== SDP_CHARGER_BIT)
		current_limit_ua = DEFAULT_SDP_MA*1000;
	else if ((apsd_result->bit) == CDP_CHARGER_BIT)
		current_limit_ua = DEFAULT_CDP_MA*1000;
	else if ((apsd_result->bit) == DCP_CHARGER_BIT)
		current_limit_ua = DEFAULT_DCP_MA*1000;
	else if ((apsd_result->bit) == FLOAT_CHARGER_BIT) {
		if (chg->usb_type_redet_done)
			current_limit_ua = DEFAULT_DCP_MA*1000;
		else
			current_limit_ua = DEFAULT_SDP_MA*1000;
	}
	else if ((apsd_result->bit) == OCP_CHARGER_BIT)
		current_limit_ua = DEFAULT_DCP_MA*1000;

	if (chg->is_aging_test)
		current_limit_ua = DEFAULT_AGAING_CHG_MA*1000;
	vote(chg->usb_icl_votable,
		DCP_VOTER, true, current_limit_ua);

	temp_region = op_battery_temp_region_get(chg);
	if (temp_region != BATT_TEMP_COLD
		&& temp_region != BATT_TEMP_HOT) {
		op_charging_en(chg, true);
	}

	pr_info("apsd result=0x%x, name=%s, psy_type=%d\n",
		apsd_result->bit, apsd_result->name, apsd_result->pst);
	pr_info("apsd done,current_now=%d\n",
		(get_prop_batt_current_now(chg) / 1000));
	if (apsd_result->bit == DCP_CHARGER_BIT
		|| apsd_result->bit == OCP_CHARGER_BIT) {
		schedule_delayed_work(&chg->check_switch_dash_work,
					msecs_to_jiffies(500));
	} else {
		if (!chg->usb_type_redet_done) {
			schedule_delayed_work(&chg->re_det_work,
				msecs_to_jiffies(TIME_1000MS));
		} else {
			schedule_delayed_work(
			&chg->non_standard_charger_check_work,
			msecs_to_jiffies(TIME_1000MS));
		}
	}
	chg->op_apsd_done = true;

	/* set allow read extern fg IIC */
	set_property_on_fg(chg,
		POWER_SUPPLY_PROP_SET_ALLOW_READ_EXTERN_FG_IIC, true);
	smblib_dbg(chg, PR_INTERRUPT, "IRQ: apsd-done rising; %s detected\n",
		   apsd_result->name);
}

irqreturn_t smblib_handle_usb_source_change(int irq, void *data)
{
	struct smb_irq_data *irq_data = data;
	struct smb_charger *chg = irq_data->parent_data;
	int rc = 0;
	u8 stat;

	rc = smblib_read(chg, APSD_STATUS_REG, &stat);
	if (rc < 0) {
		smblib_err(chg, "Couldn't read APSD_STATUS rc=%d\n", rc);
		return IRQ_HANDLED;
	}
	smblib_dbg(chg, PR_REGISTER, "APSD_STATUS = 0x%02x\n", stat);
/* david.liu@bsp, 20160926 Add dash charging */
	pr_info("APSD_STATUS=0x%02x\n", stat);

	smblib_handle_apsd_done(chg,
		(bool)(stat & APSD_DTC_STATUS_DONE_BIT));

	smblib_handle_hvdcp_detect_done(chg,
		(bool)(stat & QC_CHARGER_BIT));

	smblib_handle_hvdcp_check_timeout(chg,
		(bool)(stat & HVDCP_CHECK_TIMEOUT_BIT),
		(bool)(stat & QC_CHARGER_BIT));

	smblib_handle_hvdcp_3p0_auth_done(chg,
		(bool)(stat & QC_AUTH_DONE_STATUS_BIT));

	smblib_handle_sdp_enumeration_done(chg,
		(bool)(stat & ENUMERATION_DONE_BIT));

	smblib_handle_slow_plugin_timeout(chg,
		(bool)(stat & SLOW_PLUGIN_TIMEOUT_BIT));

	smblib_hvdcp_adaptive_voltage_change(chg);

	power_supply_changed(chg->usb_psy);

	rc = smblib_read(chg, APSD_STATUS_REG, &stat);
	if (rc < 0) {
		smblib_err(chg, "Couldn't read APSD_STATUS rc=%d\n", rc);
		return IRQ_HANDLED;
	}
	smblib_dbg(chg, PR_REGISTER, "APSD_STATUS = 0x%02x\n", stat);

	return IRQ_HANDLED;
}

static void typec_source_insertion(struct smb_charger *chg)
{
	bool legacy, rp_high;

	if (chg->typec_legacy_valid) {
		legacy = chg->typec_status[4] & TYPEC_LEGACY_CABLE_STATUS_BIT;
		rp_high = smblib_get_prop_ufp_mode(chg)
			== POWER_SUPPLY_TYPEC_SOURCE_HIGH;
		vote(chg->usb_icl_votable, LEGACY_UNKNOWN_VOTER, false, 0);
		if (legacy && rp_high) {
			/*
			* CC could be shorted to VBUS; keep HVDCP disabled but
			* allow parallel charging
			*/
			vote(chg->pl_disable_votable,
			 PL_DELAY_HVDCP_VOTER, false, 0);
		} else {
			/* safe to HVDCP */
			vote(chg->hvdcp_disable_votable_indirect,
			VBUS_CC_SHORT_VOTER, false, 0);
		}
	}
}

static void typec_sink_insertion(struct smb_charger *chg)
{
	/* when a sink is inserted we should not wait on hvdcp timeout to
	 * enable pd
	 */
	vote(chg->pd_disallowed_votable_indirect, HVDCP_TIMEOUT_VOTER,
			false, 0);
}

static void typec_sink_removal(struct smb_charger *chg)
{
	smblib_set_charge_param(chg, &chg->param.freq_boost,
			chg->chg_freq.freq_above_otg_threshold);
	chg->boost_current_ua = 0;
}

static void smblib_handle_typec_removal(struct smb_charger *chg)
{
	int rc;

	chg->usb_present = 0;
	cancel_delayed_work_sync(&chg->hvdcp_detect_work);

	/* reset input current limit voters */
	vote(chg->usb_icl_votable, LEGACY_UNKNOWN_VOTER, true, 100000);
	vote(chg->usb_icl_votable, PD_VOTER, false, 0);
	vote(chg->usb_icl_votable, USB_PSY_VOTER, false, 0);
	vote(chg->usb_icl_votable, DCP_VOTER, false, 0);
	vote(chg->usb_icl_votable, PL_USBIN_USBIN_VOTER, false, 0);
	/* reset hvdcp voters */
	vote(chg->hvdcp_disable_votable_indirect, VBUS_CC_SHORT_VOTER, true, 0);
	vote(chg->hvdcp_disable_votable_indirect, PD_INACTIVE_VOTER, true, 0);
	/* reset APSD voters */
	vote(chg->apsd_disable_votable, PD_HARD_RESET_VOTER, false, 0);
	vote(chg->apsd_disable_votable, PD_VOTER, false, 0);
	/* reset power delivery voters */
	vote(chg->pd_allowed_votable, PD_VOTER, false, 0);
	vote(chg->pd_disallowed_votable_indirect, CC_DETACHED_VOTER, true, 0);
	vote(chg->pd_disallowed_votable_indirect, HVDCP_TIMEOUT_VOTER, true, 0);
	/* reset usb irq voters */
	vote(chg->usb_irq_enable_votable, PD_VOTER, false, 0);
	vote(chg->usb_irq_enable_votable, QC_VOTER, false, 0);
	/* reset parallel voters */
	vote(chg->pl_disable_votable, PL_DELAY_HVDCP_VOTER, true, 0);
	vote(chg->pl_enable_votable_indirect, USBIN_I_VOTER, false, 0);
	vote(chg->pl_enable_votable_indirect, USBIN_V_VOTER, false, 0);

	chg->vconn_attempts = 0;
	chg->otg_attempts = 0;
	chg->pulse_cnt = 0;
	chg->usb_icl_delta_ua = 0;
	chg->voltage_min_uv = MICRO_5V;
	chg->voltage_max_uv = MICRO_5V;
	chg->pd_active = 0;
	chg->pd_hard_reset = 0;
	chg->typec_legacy_valid = false;

	/* enable APSD CC trigger for next insertion */
	rc = smblib_masked_write(chg, TYPE_C_CFG_REG,
		APSD_START_ON_CC_BIT, APSD_START_ON_CC_BIT);
	if (rc < 0)
		smblib_err(chg, "Couldn't enable APSD_START_ON_CC rc=%d\n", rc);
	if (chg->wa_flags & QC_AUTH_INTERRUPT_WA_BIT) {
		/* re-enable AUTH_IRQ_EN_CFG_BIT */
		rc = smblib_masked_write(chg,
		USBIN_SOURCE_CHANGE_INTRPT_ENB_REG,
		AUTH_IRQ_EN_CFG_BIT, AUTH_IRQ_EN_CFG_BIT);
		if (rc < 0)
			smblib_err(chg,
			"Couldn't enable QC auth setting rc=%d\n", rc);
	}
	 /* reconfigure allowed voltage for HVDCP */
	rc = smblib_set_adapter_allowance(chg,
		USBIN_ADAPTER_ALLOW_5V_OR_9V_TO_12V);
	if (rc < 0)
		smblib_err(chg, "Couldn't set USBIN_ADAPTER_ALLOW_5V_OR_9V_TO_12V rc=%d\n",
				rc);
	/* enable DRP */
	rc = smblib_masked_write(chg,
		TYPE_C_INTRPT_ENB_SOFTWARE_CTRL_REG,
		TYPEC_POWER_ROLE_CMD_MASK, 0);
	if (rc < 0)
		smblib_err(chg, "Couldn't enable DRP rc=%d\n", rc);
	 /* HW controlled CC_OUT */
	rc = smblib_masked_write(chg, TAPER_TIMER_SEL_CFG_REG,
			TYPEC_SPARE_CFG_BIT, 0);
	if (rc < 0)
		smblib_err(chg, "Couldn't enable HW cc_out rc=%d\n", rc);

//	/* reset CC2 removal WA */
//	rc = smblib_cc2_sink_removal_exit(chg);
//	if (rc < 0)
//		smblib_err(chg, "Couldn't reset CC2 removal WA rc=%d\n", rc);

	typec_sink_removal(chg);
	smblib_update_usb_type(chg);
}

static void smblib_handle_typec_insertion(struct smb_charger *chg,
		bool sink_attached)
{
	int rc;

	chg->usb_present = 1;
	vote(chg->pd_disallowed_votable_indirect, CC_DETACHED_VOTER, false, 0);
	/* disable APSD CC trigger since CC is attached */
	rc = smblib_masked_write(chg, TYPE_C_CFG_REG, APSD_START_ON_CC_BIT, 0);
	if (rc < 0)
		smblib_err(chg, "Couldn't disable APSD_START_ON_CC rc=%d\n",
		rc);

	if (sink_attached) {
		typec_sink_insertion(chg);
	} else {
		typec_sink_removal(chg);
		typec_source_insertion(chg);
	}
}

static void smblib_handle_typec_debounce_done(struct smb_charger *chg,
			bool rising, bool sink_attached)
{
	int rc;
	union power_supply_propval pval = {0, };

	rc = smblib_get_prop_typec_mode(chg, &pval);
	if (rc < 0)
		smblib_err(chg, "Couldn't get prop typec mode rc=%d\n", rc);

	if (rising)
		smblib_handle_typec_insertion(chg, sink_attached);
	else
		smblib_handle_typec_removal(chg);

/* david.liu@bsp, 20161014 Add charging standard */
	pr_info("IRQ: debounce-done %s; Type-C %s detected\n",
		   rising ? "rising" : "falling",
		   smblib_typec_mode_name[pval.intval]);
}

irqreturn_t smblib_handle_usb_typec_change_for_uusb(struct smb_charger *chg)
{
	int rc;
	u8 stat;

	rc = smblib_read(chg, TYPE_C_STATUS_3_REG, &stat);
	if (rc < 0) {
		smblib_err(chg, "Couldn't read TYPE_C_STATUS_3 rc=%d\n", rc);
		return IRQ_HANDLED;
	}
	smblib_dbg(chg, PR_REGISTER, "TYPE_C_STATUS_3 = 0x%02x OTG=%d\n",
		stat, !!(stat & (U_USB_GND_NOVBUS_BIT | U_USB_GND_BIT)));

	extcon_set_cable_state_(chg->extcon, EXTCON_USB_HOST,
			!!(stat & (U_USB_GND_NOVBUS_BIT | U_USB_GND_BIT)));
	power_supply_changed(chg->usb_psy);

	return IRQ_HANDLED;
}

static void smblib_usb_typec_change(struct smb_charger *chg)
{
	int rc;
	bool debounce_done, sink_attached;

	rc = smblib_multibyte_read(chg, TYPE_C_STATUS_1_REG,
		chg->typec_status, 5);
	 if (rc) {
		smblib_err(chg, "failed to cache USB Type-C status rc=%d\n",
						rc);
		return;
	}

	debounce_done =
		(bool)(chg->typec_status[3] & TYPEC_DEBOUNCE_DONE_STATUS_BIT);
	sink_attached =
		(bool)(chg->typec_status[3] & UFP_DFP_MODE_STATUS_BIT);
	smblib_handle_typec_debounce_done(chg, debounce_done, sink_attached);
	if (chg->typec_status[3] & TYPEC_VBUS_ERROR_STATUS_BIT)
		smblib_dbg(chg, PR_INTERRUPT, "IRQ: vbus-error\n");

	if (chg->typec_status[3] & TYPEC_VCONN_OVERCURR_STATUS_BIT)
		schedule_work(&chg->vconn_oc_work);

	power_supply_changed(chg->usb_psy);
}

irqreturn_t smblib_handle_usb_typec_change(int irq, void *data)
{
	struct smb_irq_data *irq_data = data;
	struct smb_charger *chg = irq_data->parent_data;

	if (chg->micro_usb_mode)
		return smblib_handle_usb_typec_change_for_uusb(chg);

	mutex_lock(&chg->lock);
	smblib_usb_typec_change(chg);
	mutex_unlock(&chg->lock);
	return IRQ_HANDLED;
}

irqreturn_t smblib_handle_dc_plugin(int irq, void *data)
{
	struct smb_irq_data *irq_data = data;
	struct smb_charger *chg = irq_data->parent_data;

	power_supply_changed(chg->dc_psy);
	return IRQ_HANDLED;
}

irqreturn_t smblib_handle_high_duty_cycle(int irq, void *data)
{
	struct smb_irq_data *irq_data = data;
	struct smb_charger *chg = irq_data->parent_data;

	chg->is_hdc = true;
	schedule_delayed_work(&chg->clear_hdc_work, msecs_to_jiffies(60));

	return IRQ_HANDLED;
}

irqreturn_t smblib_handle_switcher_power_ok(int irq, void *data)
{
	struct smb_irq_data *irq_data = data;
	struct smb_charger *chg = irq_data->parent_data;
	int rc;
	u8 stat;
	int usb_icl, aicl_result;
	union power_supply_propval vbus_val;
	smblib_dbg(chg, PR_INTERRUPT, "IRQ: %s\n", irq_data->name);

	if (!(chg->wa_flags & BOOST_BACK_WA)) {
		smblib_dbg(chg, PR_INTERRUPT, "DEBUG: no BOOST_BACK_WA\n");
		return IRQ_HANDLED;
	}
	rc = smblib_read(chg, POWER_PATH_STATUS_REG, &stat);
	if (rc < 0) {
		smblib_dbg(chg, PR_INTERRUPT,
		"Couldn't read POWER_PATH_STATUS rc=%d\n", rc);

		return IRQ_HANDLED;
	}

	/* skip suspending input if its already suspended by some other voter */
	usb_icl = get_effective_result(chg->usb_icl_votable);
	if ((stat & USE_USBIN_BIT) && usb_icl >= 0 && usb_icl < USBIN_25MA)
		return IRQ_HANDLED;

	if (stat & USE_DCIN_BIT) {
		smblib_dbg(chg, PR_INTERRUPT, "DEBUG: USE_DCIN_BIT\n");
		return IRQ_HANDLED;
	}
	aicl_result = op_get_aicl_result(chg);
	if (aicl_result == 0 || aicl_result > USBIN_100MA)
		return IRQ_HANDLED;
	if (is_storming(&irq_data->storm_data)) {
		/*Use the setting of 0x1380 and 0x1365 is useful*/
		smblib_err(chg, "Reverse boost detected\n");
		rc = smblib_get_prop_usb_voltage_now(chg, &vbus_val);
		if (rc < 0)
			pr_err("fail to read usb_voltage rc=%d\n", rc);
		else if (vbus_val.intval >= 2500)
			pr_err("vbus_val.intval=%d\n", vbus_val.intval);
		vote(chg->usb_icl_votable, BOOST_BACK_VOTER, true, 0);
		schedule_delayed_work(&chg->recovery_suspend_work,
				msecs_to_jiffies(TIME_100MS));
	}
	smblib_dbg(chg, PR_INTERRUPT, "DEBUG: End of Handler\n");

	return IRQ_HANDLED;
}

irqreturn_t smblib_handle_wdog_bark(int irq, void *data)
{
	struct smb_irq_data *irq_data = data;
	struct smb_charger *chg = irq_data->parent_data;
	int rc;

	rc = smblib_write(chg, BARK_BITE_WDOG_PET_REG, BARK_BITE_WDOG_PET_BIT);
	if (rc < 0)
		smblib_err(chg, "Couldn't pet the dog rc=%d\n", rc);

	return IRQ_HANDLED;
}

/* david.liu@bsp, 20161014 Add charging standard */
irqreturn_t smblib_handle_aicl_done(int irq, void *data)
{
	struct smb_irq_data *irq_data = data;
	struct smb_charger *chg = irq_data->parent_data;
	int icl_ma, rc;

	rc = smblib_get_charge_param(chg,
				&chg->param.icl_stat, &icl_ma);
	if (rc < 0) {
		pr_err("Couldn't get ICL status rc=%d\n", rc);
		return IRQ_HANDLED;
	}

	pr_info("IRQ: %s AICL result=%d\n", irq_data->name, icl_ma);
	return IRQ_HANDLED;
}
int op_get_aicl_result(struct smb_charger *chg)
{
	int icl_ma, rc;

	rc = smblib_get_charge_param(chg,
				&chg->param.icl_stat, &icl_ma);
	if (rc < 0) {
		pr_err("Couldn't get ICL status rc=%d\n", rc);
		return  -EINVAL;
	}

	pr_info("AICL result=%d\n", icl_ma);
	return icl_ma;
}

static int get_property_from_fg(struct smb_charger *chg,
		enum power_supply_property prop, int *val)
{
	int rc;
	union power_supply_propval ret = {0, };

	if (!chg->bms_psy)
		chg->bms_psy = power_supply_get_by_name("bms");

	if (chg->bms_psy) {
		rc = power_supply_get_property(chg->bms_psy, prop, &ret);
		if (rc) {
			pr_err("bms psy doesn't support reading prop %d rc = %d\n",
				prop, rc);
			return rc;
		}
		*val = ret.intval;
	} else {
		pr_err("no bms psy found\n");
		return -EINVAL;
	}

	return rc;
}

static int set_property_on_fg(struct smb_charger *chg,
		enum power_supply_property prop, int val)
{
	int rc;
	union power_supply_propval ret = {0, };

	if (!chg->bms_psy)
		chg->bms_psy = power_supply_get_by_name("bms");

	if (chg->bms_psy) {
		ret.intval = val;
		rc = power_supply_set_property(chg->bms_psy, prop, &ret);
		if (rc)
			pr_err("bms psy does not allow updating prop %d rc = %d\n",
				prop, rc);
	} else {
		pr_err("no bms psy found\n");
		return -EINVAL;
	}

	return rc;
}

static int op_charging_en(struct smb_charger *chg, bool en)
{
	int rc;

	pr_err("enable=%d\n", en);
	rc = smblib_masked_write(chg, CHARGING_ENABLE_CMD_REG,
				 CHARGING_ENABLE_CMD_BIT,
				 en ? CHARGING_ENABLE_CMD_BIT : 0);
	if (rc < 0) {
		pr_err("Couldn't %s charging rc=%d\n",
			en ? "enable" : "disable", rc);
		return rc;
	}

	return 0;
}

static bool is_usb_present(struct smb_charger *chg)
{
	int rc = 0;
	u8 stat;

//	rc = smblib_read(chg, TYPE_C_STATUS_4_REG, &stat);
	rc = smblib_read(chg, USBIN_BASE + INT_RT_STS_OFFSET, &stat);
	if (rc < 0) {
		pr_err("Couldn't read TYPE_C_STATUS_4 rc=%d\n", rc);
		return rc;
	}
	pr_debug("TYPE_C_STATUS_4 = 0x%02x\n", stat);

//	return (bool)(stat & CC_ATTACHED_BIT);
	return (bool)(stat & USBIN_PLUGIN_RT_STS_BIT);
}

static bool op_get_fast_low_temp_full(struct smb_charger *chg)
{
	if (fast_charger && fast_charger->get_fast_low_temp_full)
		return fast_charger->get_fast_low_temp_full();
	else {
		pr_err("no fast_charger register found\n");
		return false;
	}
}

static bool get_fastchg_firmware_updated_status(struct smb_charger *chg)
{
	if (fast_charger && fast_charger->get_fastchg_firmware_already_updated)
		return fast_charger->get_fastchg_firmware_already_updated();
	else {
		pr_err("no fast_charger register found\n");
		return false;
	}
}

static bool get_prop_fast_switch_to_normal(struct smb_charger *chg)
{
	if (fast_charger && fast_charger->fast_switch_to_normal)
		return fast_charger->fast_switch_to_normal();
	else {
		pr_err("no fast_charger register found\n");
		return false;
	}
}

bool is_fastchg_allowed(struct smb_charger *chg)
{
	int temp;
	static int pre_temp = 0;
	static bool pre_switch_to_normal;
	bool low_temp_full, switch_to_normal, fw_updated;

	temp = get_prop_batt_temp(chg);
	low_temp_full = op_get_fast_low_temp_full(chg);
	fw_updated = get_fastchg_firmware_updated_status(chg);

	if (!fw_updated)
		return false;
	if (chg->usb_enum_status)
		return false;
	if (temp < 165 || temp > 430) {
		if (temp != pre_temp) {
			pr_err("temp=%d is not allow to swith fastchg\n", temp);
		}
		pre_temp = temp;
		return false;
	}

	switch_to_normal = get_prop_fast_switch_to_normal(chg);
	if (pre_switch_to_normal != switch_to_normal)
		pr_info("switch_to_normal =%d\n", switch_to_normal);
	if (switch_to_normal)
		return false;

	return true;
}

bool get_oem_charge_done_status(void)
{
	if (g_chg)
		return (g_chg->chg_done || g_chg->recharge_status);
	else
		return false;
}

static void op_handle_usb_removal(struct smb_charger *chg)
{
	op_set_fast_chg_allow(chg, false);
	set_prop_fast_switch_to_normal_false(chg);
	set_usb_switch(chg, false);
	set_dash_charger_present(false);

	chg->chg_ovp = false;
	chg->dash_on = false;
	chg->chg_done = false;
	chg->time_out = false;
	chg->recharge_status = false;
	chg->usb_enum_status = false;
	chg->non_std_chg_present = false;
	chg->usb_type_redet_done = false;
	chg->boot_usb_present = false;
	chg->non_stand_chg_current = 0;
	chg->non_stand_chg_count = 0;
	chg->redet_count = 0;
	chg->dump_count = 0;
	chg->op_apsd_done = 0;
	chg->ck_dash_count = 0;
	chg->re_trigr_dash_done = 0;
	chg->recovery_boost_count = 0;
	op_battery_temp_region_set(chg, BATT_TEMP_INVALID);
}

static void smblib_otg_oc_exit(struct smb_charger *chg, bool success)
{
	int rc;

	chg->otg_attempts = 0;
	if (!success) {
		smblib_err(chg, "OTG soft start failed\n");
		chg->otg_en = false;
	}

	smblib_dbg(chg, PR_OTG, "enabling VBUS < 1V check\n");
	rc = smblib_masked_write(chg, OTG_CFG_REG,
					QUICKSTART_OTG_FASTROLESWAP_BIT, 0);
	if (rc < 0)
		smblib_err(chg, "Couldn't enable VBUS < 1V check rc=%d\n", rc);

	if (!chg->external_vconn && chg->vconn_en) {
		chg->vconn_attempts = 0;
		if (success) {
			rc = _smblib_vconn_regulator_enable(
							chg->vconn_vreg->rdev);
			if (rc < 0)
				smblib_err(chg, "Couldn't enable VCONN rc=%d\n",
									rc);
		} else {
			chg->vconn_en = false;
		}
	}
}

#define MAX_OC_FALLING_TRIES 10
static void smblib_otg_oc_work(struct work_struct *work)
{
	struct smb_charger *chg = container_of(work, struct smb_charger,
								otg_oc_work);
	int rc, i;
	u8 stat;

	if (!chg->vbus_vreg || !chg->vbus_vreg->rdev)
		return;

	smblib_err(chg, "over-current detected on VBUS\n");
	mutex_lock(&chg->otg_oc_lock);
	if (!chg->otg_en)
		goto unlock;

	smblib_dbg(chg, PR_OTG, "disabling VBUS < 1V check\n");
	smblib_masked_write(chg, OTG_CFG_REG,
					QUICKSTART_OTG_FASTROLESWAP_BIT,
					QUICKSTART_OTG_FASTROLESWAP_BIT);

	/*
	 * If 500ms has passed and another over-current interrupt has not
	 * triggered then it is likely that the software based soft start was
	 * successful and the VBUS < 1V restriction should be re-enabled.
	 */
	schedule_delayed_work(&chg->otg_ss_done_work, msecs_to_jiffies(500));

	rc = _smblib_vbus_regulator_disable(chg->vbus_vreg->rdev);
	if (rc < 0) {
		smblib_err(chg, "Couldn't disable VBUS rc=%d\n", rc);
		goto unlock;
	}

	if (++chg->otg_attempts > OTG_MAX_ATTEMPTS) {
		cancel_delayed_work_sync(&chg->otg_ss_done_work);
		smblib_err(chg, "OTG failed to enable after %d attempts\n",
			   chg->otg_attempts - 1);
		smblib_otg_oc_exit(chg, false);
		goto unlock;
	}

	/*
	 * The real time status should go low within 10ms. Poll every 1-2ms to
	 * minimize the delay when re-enabling OTG.
	 */
	for (i = 0; i < MAX_OC_FALLING_TRIES; ++i) {
		usleep_range(1000, 2000);
		rc = smblib_read(chg, OTG_BASE + INT_RT_STS_OFFSET, &stat);
		if (rc >= 0 && !(stat & OTG_OVERCURRENT_RT_STS_BIT))
			break;
	}

	if (i >= MAX_OC_FALLING_TRIES) {
		cancel_delayed_work_sync(&chg->otg_ss_done_work);
		smblib_err(chg, "OTG OC did not fall after %dms\n",
						2 * MAX_OC_FALLING_TRIES);
		smblib_otg_oc_exit(chg, false);
		goto unlock;
	}

	smblib_dbg(chg, PR_OTG, "OTG OC fell after %dms\n", 2 * i + 1);
	rc = _smblib_vbus_regulator_enable(chg->vbus_vreg->rdev);
	if (rc < 0) {
		smblib_err(chg, "Couldn't enable VBUS rc=%d\n", rc);
		goto unlock;
	}

unlock:
	mutex_unlock(&chg->otg_oc_lock);
}

static void smblib_vconn_oc_work(struct work_struct *work)
{
	struct smb_charger *chg = container_of(work, struct smb_charger,
								vconn_oc_work);
	int rc, i;
	u8 stat;

	smblib_err(chg, "over-current detected on VCONN\n");
	if (!chg->vconn_vreg || !chg->vconn_vreg->rdev)
		return;

	mutex_lock(&chg->otg_oc_lock);
	rc = _smblib_vconn_regulator_disable(chg->vconn_vreg->rdev);
	if (rc < 0) {
		smblib_err(chg, "Couldn't disable VCONN rc=%d\n", rc);
		goto unlock;
	}

	if (++chg->vconn_attempts > VCONN_MAX_ATTEMPTS) {
		smblib_err(chg, "VCONN failed to enable after %d attempts\n",
			   chg->otg_attempts - 1);
		chg->vconn_en = false;
		chg->vconn_attempts = 0;
		goto unlock;
	}

	/*
	 * The real time status should go low within 10ms. Poll every 1-2ms to
	 * minimize the delay when re-enabling OTG.
	 */
	for (i = 0; i < MAX_OC_FALLING_TRIES; ++i) {
		usleep_range(1000, 2000);
		rc = smblib_read(chg, TYPE_C_STATUS_4_REG, &stat);
		if (rc >= 0 && !(stat & TYPEC_VCONN_OVERCURR_STATUS_BIT))
			break;
	}

	if (i >= MAX_OC_FALLING_TRIES) {
		smblib_err(chg, "VCONN OC did not fall after %dms\n",
						2 * MAX_OC_FALLING_TRIES);
		chg->vconn_en = false;
		chg->vconn_attempts = 0;
		goto unlock;
	}

	smblib_dbg(chg, PR_OTG, "VCONN OC fell after %dms\n", 2 * i + 1);
	if (++chg->vconn_attempts > VCONN_MAX_ATTEMPTS) {
		smblib_err(chg, "VCONN failed to enable after %d attempts\n",
			   chg->vconn_attempts - 1);
		chg->vconn_en = false;
		goto unlock;
	}

	rc = _smblib_vconn_regulator_enable(chg->vconn_vreg->rdev);
	if (rc < 0) {
		smblib_err(chg, "Couldn't enable VCONN rc=%d\n", rc);
		goto unlock;
	}

unlock:
	mutex_unlock(&chg->otg_oc_lock);
}

static void smblib_otg_ss_done_work(struct work_struct *work)
{
	struct smb_charger *chg = container_of(work, struct smb_charger,
							otg_ss_done_work.work);
	int rc;
	bool success = false;
	u8 stat;

	mutex_lock(&chg->otg_oc_lock);
	rc = smblib_read(chg, OTG_STATUS_REG, &stat);
	if (rc < 0)
		smblib_err(chg, "Couldn't read OTG status rc=%d\n", rc);
	else if (stat & BOOST_SOFTSTART_DONE_BIT)
		success = true;

	smblib_otg_oc_exit(chg, success);
	mutex_unlock(&chg->otg_oc_lock);
}

int update_dash_unplug_status(void)
{
	int rc;
	union power_supply_propval vbus_val;

	rc = smblib_get_prop_usb_voltage_now(g_chg, &vbus_val);
	if (rc < 0) {
		pr_err("failed to read usb_voltage rc=%d\n", rc);
	} else if (vbus_val.intval <= 2500) {
		op_handle_usb_plugin(g_chg);
	}

	smblib_update_usb_type(g_chg);
	power_supply_changed(g_chg->usb_psy);

	return 0;
}
void op_write_backup_flag(struct smb_charger *chg,bool bk_flag);
int op_read_backup_flag(struct smb_charger *chg);

static void smblib_icl_change_work(struct work_struct *work)
{
	struct smb_charger *chg = container_of(work, struct smb_charger,
							icl_change_work.work);
	int rc, settled_ua;

	rc = smblib_get_charge_param(chg, &chg->param.icl_stat, &settled_ua);
	if (rc < 0) {
		smblib_err(chg, "Couldn't get ICL status rc=%d\n", rc);
		return;
	}

	power_supply_changed(chg->usb_main_psy);
	vote(chg->pl_enable_votable_indirect, USBIN_I_VOTER,
				settled_ua >= USB_WEAK_INPUT_UA, 0);

	smblib_dbg(chg, PR_INTERRUPT, "icl_settled=%d\n", settled_ua);
}
static int op_set_collapse_fet(struct smb_charger *chg, bool on)
{
	int rc = 0;
	u8 stat;

	rc = smblib_masked_write(chg, USBIN_5V_AICL_THRESHOLD_CFG_REG,
						BIT(0) | BIT(1), on ? 0 : BIT(0) | BIT(1));
	if (rc < 0) {
		smblib_err(chg, "Couldn't write %s to 0x%x rc=%d\n",
			on ? "on" : "off", USBIN_5V_AICL_THRESHOLD_CFG_REG, rc);
		return rc;
	}

	rc = smblib_read(chg, USBIN_5V_AICL_THRESHOLD_CFG_REG, &stat);
	if (rc < 0) {
		smblib_err(chg, "Couldn't read 0x%x rc=%d\n",
			USBIN_5V_AICL_THRESHOLD_CFG_REG, rc);
		return rc;
	}
	pr_info("USBIN_5V_AICL_THRESHOLD_CFG_REG(0x%x)=0x%x\n",
			USBIN_5V_AICL_THRESHOLD_CFG_REG, stat);

	rc = smblib_masked_write(chg, USBIN_CONT_AICL_THRESHOLD_CFG_REG,
						BIT(0) | BIT(1), on ? 0 : BIT(0) | BIT(1));
	if (rc < 0) {
		smblib_err(chg, "Couldn't write %s to 0x%x rc=%d\n",
			on ? "on" : "off", USBIN_CONT_AICL_THRESHOLD_CFG_REG,
			rc);
		return rc;
	}

	rc = smblib_read(chg, USBIN_CONT_AICL_THRESHOLD_CFG_REG, &stat);
	if (rc < 0) {
		smblib_err(chg, "Couldn't read 0x%x rc=%d\n",
			USBIN_CONT_AICL_THRESHOLD_CFG_REG, rc);
		return rc;
	}
	pr_info("USBIN_CONT_AICL_THRESHOLD_CFG_REG(0x%x)=0x%x\n",
			USBIN_CONT_AICL_THRESHOLD_CFG_REG, stat);

	rc = smblib_masked_write(chg, USBIN_AICL_OPTIONS_CFG_REG,
					SUSPEND_ON_COLLAPSE_USBIN_BIT
					| USBIN_HV_COLLAPSE_RESPONSE_BIT
					| USBIN_LV_COLLAPSE_RESPONSE_BIT
					| USBIN_AICL_RERUN_EN_BIT,
					on ? 0 : SUSPEND_ON_COLLAPSE_USBIN_BIT
					| USBIN_HV_COLLAPSE_RESPONSE_BIT
					| USBIN_LV_COLLAPSE_RESPONSE_BIT);
	if (rc < 0) {
		smblib_err(chg,
			"Couldn't write %s to 0x%x rc=%d\n",
			on ? "on" : "off", USBIN_AICL_OPTIONS_CFG_REG, rc);
		return rc;
	}

	rc = smblib_read(chg, USBIN_AICL_OPTIONS_CFG_REG, &stat);
	if (rc < 0) {
		smblib_err(chg, "Couldn't read 0x%x rc=%d\n",
			USBIN_AICL_OPTIONS_CFG_REG, rc);
		return rc;
	}
	pr_info("USBIN_AICL_OPTIONS_CFG_REG(0x%x)=0x%x\n",
		USBIN_AICL_OPTIONS_CFG_REG, stat);

	rc = smblib_masked_write(chg, USBIN_LOAD_CFG_REG, BIT(0)
						| BIT(1), on ? 0 : BIT(0) | BIT(1));
	if (rc < 0) {
		smblib_err(chg, "Couldn't write %s to 0x%x rc=%d\n",
			on ? "on" : "off", USBIN_LOAD_CFG_REG, rc);
		return rc;
	}

	rc = smblib_read(chg, USBIN_LOAD_CFG_REG, &stat);
	if (rc < 0) {
		smblib_err(chg, "Couldn't read 0x%x rc=%d\n",
			USBIN_LOAD_CFG_REG, rc);
		return rc;
	}
	pr_info("USBIN_LOAD_CFG_REG(0x%x)=0x%x\n",
			USBIN_LOAD_CFG_REG, stat);

	return rc;
}


int op_handle_switcher_power_ok(void)
{
	int rc;
	u8 stat;
	union power_supply_propval vbus_val;
	if(!g_chg)
		return 0;
	if (!(g_chg->wa_flags & BOOST_BACK_WA))
		return 0;
	rc = smblib_read(g_chg, POWER_PATH_STATUS_REG, &stat);
	if (rc < 0) {
		smblib_err(g_chg, "Couldn't read POWER_PATH_STATUS rc=%d\n", rc);
		return 0;
	}
	smblib_err(g_chg, "POWER_PATH_STATUS stat=0x%x\n", stat);

	if ((stat & USE_USBIN_BIT) &&
			get_effective_result(g_chg->usb_icl_votable) < USBIN_25MA)
		return 0;

	if (stat & USE_DCIN_BIT)
		return 0;
	usleep_range(50000, 50000);
	rc = smblib_get_prop_usb_voltage_now(g_chg, &vbus_val);
	if (rc < 0) {
		pr_err("fail to read usb_voltage rc=%d\n", rc);
	} else if(vbus_val.intval >= 2500) {
		pr_err("vbus_val.intval=%d\n",vbus_val.intval);
		op_dump_regs(g_chg);
		smblib_err(g_chg, "OP Reverse boost detected\n");
		g_chg->deal_vusbin_error_done = true;
	}

	return 0;
}
void op_irq_control(int enable)
{
	if (g_chg->op_irq_enabled == enable)
		return;
	if (!enable) {
		disable_irq(g_chg->irq_info[SWITCH_POWER_OK_IRQ].irq);
		disable_irq(g_chg->irq_info[USBIN_SRC_CHANGE_IRQ].irq);
		disable_irq(g_chg->irq_info[USBIN_UV_IRQ].irq);
	} else {
		enable_irq(g_chg->irq_info[SWITCH_POWER_OK_IRQ].irq);
		enable_irq(g_chg->irq_info[USBIN_SRC_CHANGE_IRQ].irq);
		enable_irq(g_chg->irq_info[USBIN_UV_IRQ].irq);
	}
	g_chg->op_irq_enabled = enable;
}
int op_contrl(int enable, bool check_power_ok)
{
	pr_info("%s, en=%d\n", __func__, enable);
	if (!g_chg)
		return 0;
	if (enable) {
		if(check_power_ok)
		op_handle_switcher_power_ok();
	}
	else{
		op_set_collapse_fet(g_chg, enable);
	}
	op_irq_control(enable);
	return 0;
}

bool get_prop_fast_chg_started(struct smb_charger *chg)
{
	if (fast_charger && fast_charger->fast_chg_started)
		return fast_charger->fast_chg_started();
	else
		pr_err("no fast_charger register found\n");

	return false;
}

static bool set_prop_fast_switch_to_normal_false(struct smb_charger *chg)
{
	if (fast_charger && fast_charger->set_switch_to_noraml_false)
		return fast_charger->set_switch_to_noraml_false();
	else
		pr_err("no fast_charger register found\n");

	return false;
}

bool op_get_fastchg_ing(struct smb_charger *chg)
{
	if (fast_charger && fast_charger->get_fast_chg_ing)
		return fast_charger->get_fast_chg_ing();
	else
		pr_err("no fast_charger register found\n");

	return false;
}

bool op_set_fast_chg_allow(struct smb_charger *chg, bool enable)
{
	if (fast_charger && fast_charger->set_fast_chg_allow)
		return fast_charger->set_fast_chg_allow(enable);
	else
		pr_err("no fast_charger register found\n");

	return false;
}

static bool op_get_fast_chg_allow(struct smb_charger *chg)
{
	if (fast_charger && fast_charger->get_fast_chg_allow)
		return fast_charger->get_fast_chg_allow();
	else
		pr_err("no fast_charger register found\n");

	return false;
}

static bool op_is_usb_switch_on(struct smb_charger *chg)
{
	if (fast_charger && fast_charger->is_usb_switch_on)
		return fast_charger->is_usb_switch_on();
	else
		pr_err("no fast_charger register found\n");

	return false;
}

static enum batt_status_type op_battery_status_get(struct smb_charger *chg)
{
	return chg->battery_status;
}

static temp_region_type op_battery_temp_region_get(struct smb_charger *chg)
{
	return chg->mBattTempRegion;
}

int fuelgauge_battery_temp_region_get(void)
{
	if (!g_chg)
		return BATT_TEMP_NORMAL;

	return op_battery_temp_region_get(g_chg);
}

static void op_battery_status_set(struct smb_charger *chg,
		enum batt_status_type battery_status)
{
	chg->battery_status = battery_status;
}

static void op_battery_temp_region_set(struct smb_charger *chg,
		temp_region_type batt_temp_region)
{
	chg->mBattTempRegion = batt_temp_region;
	pr_err("set temp_region=%d\n", chg->mBattTempRegion);
}

static void set_prop_batt_health(struct smb_charger *chg, int batt_health)
{
	chg->batt_health = batt_health;
}

static void set_usb_switch(struct smb_charger *chg, bool enable)
{
	int retrger_time;
	if (!fast_charger) {
		pr_err("no fast_charger register found\n");
		return;
	}

	if (enable) {
		pr_err("switch on fastchg\n");
		if (chg->boot_usb_present && chg->re_trigr_dash_done) {
			vote(chg->usb_icl_votable, AICL_RERUN_VOTER,
					true, 0);
			usleep_range(500000, 510000);
			vote(chg->usb_icl_votable, AICL_RERUN_VOTER,
					true, DEFAULT_DCP_MA*1000);
		}
		set_mcu_en_gpio_value(1);
		msleep(10);
		usb_sw_gpio_set(1);
		msleep(10);
		mcu_en_gpio_set(0);
		if (chg->boot_usb_present)
			retrger_time = TIME_3S;
		else
			retrger_time = TIME_200MS;
		if (!chg->re_trigr_dash_done)
			schedule_delayed_work(&chg->rechk_sw_dsh_work,
					msecs_to_jiffies(retrger_time));
	} else {
		pr_err("switch off fastchg\n");
		usb_sw_gpio_set(0);
		mcu_en_gpio_set(1);
	}
}

static void switch_fast_chg(struct smb_charger *chg)
{
	bool fastchg_allowed, is_allowed;
	static bool pre_fastchg_allowed, pre_is_allowed;

	mutex_lock(&chg->sw_dash_lock);
	if (op_is_usb_switch_on(chg)) {
		mutex_unlock(&chg->sw_dash_lock);
		return;
	}
	if (!is_usb_present(chg)) {
		mutex_unlock(&chg->sw_dash_lock);
		return;
	}

	fastchg_allowed = op_get_fast_chg_allow(chg);
	if (pre_fastchg_allowed != fastchg_allowed) {
		pre_fastchg_allowed = fastchg_allowed;
		pr_info("fastchg_allowed = %d\n", fastchg_allowed);
	}
	if (!fastchg_allowed) {
		is_allowed = is_fastchg_allowed(chg);
	if (pre_is_allowed != is_allowed) {
		pre_is_allowed = is_allowed;
		pr_info("is_allowed = %d\n", is_allowed);
	}
		if (is_allowed) {
			set_usb_switch(chg, true);
			op_set_fast_chg_allow(chg, true);
		}
	}
	mutex_unlock(&chg->sw_dash_lock);
}

static void op_re_kick_allowed_voltage(struct smb_charger  *chg)
{
	const struct apsd_result *apsd_result;

	if (!is_usb_present(chg))
		return;

	apsd_result = smblib_get_apsd_result(chg);
	if (apsd_result->bit == SDP_CHARGER_BIT)
		return;

	pr_info("re-kick allowed voltage\n");
	smblib_set_usb_pd_allowed_voltage(chg, MICRO_9V, MICRO_9V);
	msleep(500);
	smblib_set_usb_pd_allowed_voltage(chg, MICRO_5V, MICRO_5V);
}

static void op_re_kick_work(struct work_struct *work)
{
	struct smb_charger *chg = container_of(work,
			struct smb_charger,
			re_kick_work.work);

    if (chg->vbus_present) {
		op_re_kick_allowed_voltage(chg);
		schedule_delayed_work(&chg->check_switch_dash_work,
				msecs_to_jiffies(500));
	}
}
static void retrigger_dash_work(struct work_struct *work)
{
	struct smb_charger *chg = container_of(work,
			struct smb_charger,
			rechk_sw_dsh_work.work);
	pr_debug("chg->ck_dash_count=%d\n", chg->ck_dash_count);
	if (chg->usb_enum_status)
		return;
	if (chg->dash_present) {
		chg->ck_dash_count = 0;
		return;
	}
	if (!chg->vbus_present) {
		chg->ck_dash_count = 0;
		return;
	}
	if (chg->ck_dash_count >= DASH_CHECK_COUNT) {
		pr_info("retrger dash\n");
		chg->re_trigr_dash_done = true;
		set_usb_switch(chg, false);
		set_usb_switch(chg, true);
		chg->ck_dash_count = 0;
	} else {
		chg->ck_dash_count++;
		schedule_delayed_work(&chg->rechk_sw_dsh_work,
				msecs_to_jiffies(TIME_200MS));
	}
}

static void op_chek_apsd_done_work(struct work_struct *work)
{
	struct smb_charger *chg = container_of(work,
			struct smb_charger,
			op_check_apsd_work.work);
	union power_supply_propval vbus_val;
	int rc;
	const struct apsd_result *apsd_result;

	pr_debug("chg->ck_apsd_count=%d\n", chg->ck_apsd_count);
	if (chg->usb_enum_status || chg->op_apsd_done) {
		chg->ck_apsd_count = 0;
		return;
	}
	rc = smblib_get_prop_usb_voltage_now(chg, &vbus_val);
	if (rc < 0) {
		chg->ck_apsd_count = 0;
		pr_info("failed to read usb_voltage rc=%d\n", rc);
		return;
	}
	if (vbus_val.intval < 2500) {
		pr_info("vbus less 2.5v\n");
		chg->ck_apsd_count = 0;
		return;
	}
	apsd_result = smblib_get_apsd_result(chg);
	if (apsd_result->bit) {
		chg->ck_apsd_count = 0;
		return;
	}

	if (chg->ck_apsd_count >= APSD_CHECK_COUTNT) {
		pr_info("apsd done error\n");
		chg->ck_apsd_count = 0;
		op_dump_regs(chg);
		op_rerun_apsd(chg);
	} else {
		chg->ck_apsd_count++;
		schedule_delayed_work(&chg->op_check_apsd_work,
				msecs_to_jiffies(TIME_1000MS));
	}
}



static void op_recovery_usb_suspend_work(struct work_struct *work)
{
	struct smb_charger *chg = container_of(work,
			struct smb_charger,
			recovery_suspend_work.work);
		int effect_result;

		if (!is_usb_present(chg)) {
			chg->recovery_boost_count = 0;
			return;
		}
		if (chg->recovery_boost_count >= BOOST_BACK_COUNT) {
			pr_info("recovery revert boost\n");
			vote(chg->usb_icl_votable, BOOST_BACK_VOTER, false, 0);
			effect_result =
				get_effective_result(chg->usb_icl_votable);
			pr_info("effect_result=%d\n", effect_result);
			if (effect_result > DEFAULT_AGAING_CHG_MA*1000)
				vote(chg->usb_icl_votable, DCP_VOTER,
				true, (effect_result - USBIN_150MA));
		} else {
			chg->recovery_boost_count++;
			schedule_delayed_work(&chg->recovery_suspend_work,
					msecs_to_jiffies(TIME_100MS));
		}
}
static void op_check_allow_switch_dash_work(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct smb_charger *chg = container_of(dwork,
			struct smb_charger, check_switch_dash_work);
	const struct apsd_result *apsd_result;

	if (!is_usb_present(chg))
		return;
	if (chg->usb_enum_status)
		return;

	apsd_result = smblib_get_apsd_result(chg);
	if (((apsd_result->bit != SDP_CHARGER_BIT
		&& apsd_result->bit != CDP_CHARGER_BIT
		&& apsd_result->bit != FLOAT_CHARGER_BIT)
		&& apsd_result->bit)
		|| chg->non_std_chg_present)
		switch_fast_chg(chg);
}

int check_allow_switch_dash(struct smb_charger *chg,
				const union power_supply_propval *val)
{
	if (val->intval < 0)
		return -EINVAL;

	schedule_delayed_work(&chg->check_switch_dash_work,
				msecs_to_jiffies(500));
	return 0;
}

#define DEFAULT_WALL_CHG_MA	1800
static int set_dash_charger_present(int status)
{
	int charger_present;
	bool pre_dash_present;

	if (g_chg) {
		pre_dash_present = g_chg->dash_present;
		charger_present = is_usb_present(g_chg);
		g_chg->dash_present = status && charger_present;
		if (g_chg->dash_present && !pre_dash_present) {
			pr_err("set dash online\n");
			g_chg->usb_psy_desc.type = POWER_SUPPLY_TYPE_DASH;
			vote(g_chg->usb_icl_votable, PD_VOTER, true,
					DEFAULT_WALL_CHG_MA * 1000);
		}
		power_supply_changed(g_chg->batt_psy);
		pr_info("dash_present = %d, charger_present = %d\n",
				g_chg->dash_present, charger_present);
	} else {
		pr_err("set_dash_charger_present error\n");
	}

	return 0;
}
#ifndef CONFIG_OP_DEBUG_CHG
static void op_check_charge_timeout(struct smb_charger *chg)
{
	static int batt_status, count = 0;

	if (chg->chg_done || chg->is_aging_test)
		return;

	batt_status = get_prop_batt_status(chg);
	if (chg->vbus_present
			&& batt_status == POWER_SUPPLY_STATUS_CHARGING)
		count++;
	else
		count = 0;

	if (count > CHG_TIMEOUT_COUNT) {
		pr_err("chg timeout! stop chaging now\n");
		op_charging_en(chg, false);
		chg->time_out = true;
	}
}
#endif
static int get_prop_batt_present(struct smb_charger *chg)
{
	int rc;
	u8 stat;

	rc = smblib_read(chg, BATIF_BASE + INT_RT_STS_OFFSET, &stat);
	if (rc < 0) {
		pr_err("Couldn't read BATIF_INT_RT_STS rc=%d\n", rc);
		return rc;
	}

	return !(stat & (BAT_THERM_OR_ID_MISSING_RT_STS_BIT
					| BAT_TERMINAL_MISSING_RT_STS_BIT));
}

#define DEFAULT_BATT_CAPACITY	50
static int get_prop_batt_capacity(struct smb_charger *chg)
{
	int capacity, rc;

	if (chg->fake_capacity >= 0)
		return chg->fake_capacity;

	rc = get_property_from_fg(chg, POWER_SUPPLY_PROP_CAPACITY, &capacity);
	if (rc) {
		pr_err("Couldn't get capacity rc=%d\n", rc);
		capacity = DEFAULT_BATT_CAPACITY;
	}

	return capacity;
}

#define DEFAULT_BATT_TEMP		200
static int get_prop_batt_temp(struct smb_charger *chg)
{
	int temp, rc;

	if (chg->use_fake_temp)
		return chg->fake_temp;

	rc = get_property_from_fg(chg, POWER_SUPPLY_PROP_TEMP, &temp);
	if (rc) {
		pr_err("Couldn't get temperature rc=%d\n", rc);
		temp = DEFAULT_BATT_TEMP;
	}

	return temp;
}

#define DEFAULT_BATT_CURRENT_NOW	0
static int get_prop_batt_current_now(struct smb_charger *chg)
{
	int ua, rc;

	rc = get_property_from_fg(chg, POWER_SUPPLY_PROP_CURRENT_NOW, &ua);
	if (rc) {
		pr_err("Couldn't get current rc=%d\n", rc);
		ua = DEFAULT_BATT_CURRENT_NOW;
	}

	return ua;
}

#define DEFAULT_BATT_VOLTAGE_NOW	0
static int get_prop_batt_voltage_now(struct smb_charger *chg)
{
	int uv, rc;

	rc = get_property_from_fg(chg, POWER_SUPPLY_PROP_VOLTAGE_NOW, &uv);
	if (rc) {
		pr_err("Couldn't get voltage rc=%d\n", rc);
		uv = DEFAULT_BATT_VOLTAGE_NOW;
	}

	return uv;
}

static int get_prop_fg_capacity(struct smb_charger *chg)
{
	int capacity, rc;

	if (chg->fake_capacity >= 0)
		return chg->fake_capacity;

	rc = get_property_from_fg(chg, POWER_SUPPLY_PROP_FG_CAPACITY, &capacity);
	if (rc) {
		pr_err("Couldn't get capacity rc=%d\n", rc);
		capacity = DEFAULT_BATT_CAPACITY;
	}

	return capacity;
}

static int get_prop_fg_current_now(struct smb_charger *chg)
{
	int ua, rc;

	rc = get_property_from_fg(chg, POWER_SUPPLY_PROP_FG_CURRENT_NOW, &ua);
	if (rc) {
		pr_err("Couldn't get current rc=%d\n", rc);
		ua = DEFAULT_BATT_CURRENT_NOW;
	}

	return ua;
}

static int get_prop_fg_voltage_now(struct smb_charger *chg)
{
	int uv, rc;

	rc = get_property_from_fg(chg, POWER_SUPPLY_PROP_FG_VOLTAGE_NOW, &uv);
	if (rc) {
		pr_err("Couldn't get voltage rc=%d\n", rc);
		uv = DEFAULT_BATT_VOLTAGE_NOW;
	}

	return uv;
}

int get_prop_batt_status(struct smb_charger *chg)
{
	int capacity, batt_status, rc;
	temp_region_type temp_region;
	union power_supply_propval pval = {0, };

	temp_region = op_battery_temp_region_get(chg);
	capacity = get_prop_batt_capacity(chg);
	chg->dash_on = get_prop_fast_chg_started(chg);
	if ((chg->chg_done || chg->recharge_status)
			&& (temp_region == BATT_TEMP_COOL
			|| temp_region == BATT_TEMP_LITTLE_COOL
			|| temp_region == BATT_TEMP_PRE_NORMAL
			|| temp_region == BATT_TEMP_NORMAL)
			&& capacity > 90) {
		return POWER_SUPPLY_STATUS_FULL;
	} else if (chg->dash_on) {
		return POWER_SUPPLY_STATUS_CHARGING;
	}

	rc = smblib_get_prop_batt_status(chg, &pval);
	if (rc)
		batt_status = 0;
	else
		batt_status = pval.intval;

	return batt_status;
}

int get_charging_status(void)
{
	int rc;
	union power_supply_propval pval = {0, };

	if (!g_chg)
		return POWER_SUPPLY_STATUS_DISCHARGING;

	rc = smblib_get_prop_batt_status(g_chg, &pval);
	if (rc)
		return POWER_SUPPLY_STATUS_UNKNOWN;

	return pval.intval;
}

void set_chg_ibat_vbat_max(struct smb_charger *chg, int ibat, int vfloat )
{
	pr_err("set ibatmax=%d and set vbatmax=%d\n",
			ibat, vfloat);

	vote(chg->fcc_votable,
		DEFAULT_VOTER, true, ibat * 1000);
	vote(chg->fv_votable,
		DEFAULT_VOTER, true, vfloat * 1000);

	/* set cc to cv 100mv lower than vfloat */
	set_property_on_fg(chg, POWER_SUPPLY_PROP_CC_TO_CV_POINT, vfloat - 100);
}

/* Tbatt < -3C */
static int handle_batt_temp_cold(struct smb_charger *chg)
{
	temp_region_type temp_region;

	temp_region = op_battery_temp_region_get(chg);
	if (temp_region != BATT_TEMP_COLD || chg->is_power_changed) {
		pr_err("triggered\n");
		chg->is_power_changed = false;

		op_charging_en(chg, false);
		op_battery_temp_region_set(chg, BATT_TEMP_COLD);

		/* Update the temperature boundaries */
		chg->mBattTempBoundT0 = chg->BATT_TEMP_T0 + BATT_TEMP_HYST;
		chg->mBattTempBoundT1 = chg->BATT_TEMP_T1;
		chg->mBattTempBoundT2 = chg->BATT_TEMP_T2;
		chg->mBattTempBoundT3 = chg->BATT_TEMP_T3;
		chg->mBattTempBoundT4 = chg->BATT_TEMP_T4;
		chg->mBattTempBoundT5 = chg->BATT_TEMP_T5;
		chg->mBattTempBoundT6 = chg->BATT_TEMP_T6;
		set_prop_batt_health(chg, POWER_SUPPLY_HEALTH_COLD);
	}

	return 0;
}

/* -3C <= Tbatt <= 0C */
static int handle_batt_temp_little_cold(struct smb_charger *chg)
{
	temp_region_type temp_region;

	if (chg->chg_ovp)
		return 0;

	temp_region = op_battery_temp_region_get(chg);
	if (temp_region != BATT_TEMP_LITTLE_COLD
			|| chg->is_power_changed || chg->recharge_pending) {
		pr_err("triggered\n");
		chg->recharge_pending = false;
		chg->is_power_changed = false;

		if (temp_region == BATT_TEMP_HOT ||
				temp_region == BATT_TEMP_COLD)
			op_charging_en(chg, true);

		set_chg_ibat_vbat_max(chg,
				chg->ibatmax[BATT_TEMP_LITTLE_COLD],
				chg->vbatmax[BATT_TEMP_LITTLE_COLD]);
		op_battery_temp_region_set(chg, BATT_TEMP_LITTLE_COLD);

		/* Update the temperature boundaries */
		chg->mBattTempBoundT0 = chg->BATT_TEMP_T0;
		chg->mBattTempBoundT1 = chg->BATT_TEMP_T1 + BATT_TEMP_HYST;
		chg->mBattTempBoundT2 = chg->BATT_TEMP_T2;
		chg->mBattTempBoundT3 = chg->BATT_TEMP_T3;
		chg->mBattTempBoundT4 = chg->BATT_TEMP_T4;
		chg->mBattTempBoundT5 = chg->BATT_TEMP_T5;
		chg->mBattTempBoundT6 = chg->BATT_TEMP_T6;
		set_prop_batt_health(chg, POWER_SUPPLY_HEALTH_GOOD);
	}

	return 0;
}

/* 0C < Tbatt <= 5C*/
static int handle_batt_temp_cool(struct smb_charger *chg)
{
	temp_region_type temp_region;

	if (chg->chg_ovp)
		return 0;

	temp_region = op_battery_temp_region_get(chg);
	if (temp_region != BATT_TEMP_COOL
			|| chg->is_power_changed || chg->recharge_pending) {
		pr_err("triggered\n");
		chg->recharge_pending = false;
		chg->is_power_changed = false;

		if (temp_region == BATT_TEMP_HOT ||
				temp_region == BATT_TEMP_COLD)
			op_charging_en(chg, true);

		set_chg_ibat_vbat_max(chg,
				chg->ibatmax[BATT_TEMP_COOL],
				chg->vbatmax[BATT_TEMP_COOL]);
		op_battery_temp_region_set(chg, BATT_TEMP_COOL);

		/* Update the temperature boundaries */
		chg->mBattTempBoundT0 = chg->BATT_TEMP_T0;
		chg->mBattTempBoundT1 = chg->BATT_TEMP_T1 ;
		chg->mBattTempBoundT2 = chg->BATT_TEMP_T2 + BATT_TEMP_HYST;
		chg->mBattTempBoundT3 = chg->BATT_TEMP_T3;
		chg->mBattTempBoundT4 = chg->BATT_TEMP_T4;
		chg->mBattTempBoundT5 = chg->BATT_TEMP_T5;
		chg->mBattTempBoundT6 = chg->BATT_TEMP_T6;
		set_prop_batt_health(chg, POWER_SUPPLY_HEALTH_GOOD);
	}

	return 0;
}
/* 5C < Tbatt <= 12C */
static int handle_batt_temp_little_cool(struct smb_charger *chg)
{
	int temp_region, vbat_mv;

	if (chg->chg_ovp)
		return 0;

	temp_region = op_battery_temp_region_get(chg);
	if (temp_region != BATT_TEMP_LITTLE_COOL
			|| chg->is_power_changed || chg->recharge_pending) {
		pr_err("triggered\n");
		chg->recharge_pending = false;
		chg->is_power_changed = false;

		if (temp_region == BATT_TEMP_HOT ||
				temp_region == BATT_TEMP_COLD)
			op_charging_en(chg, true);

		vbat_mv = get_prop_batt_voltage_now(chg) / 1000;
		if (vbat_mv > 4180) {
			set_chg_ibat_vbat_max(chg, 450,
					chg->vbatmax[BATT_TEMP_LITTLE_COOL]);
			chg->temp_littel_cool_set_current_0_point_25c = false;
		} else {
			set_chg_ibat_vbat_max(chg,
					chg->ibatmax[BATT_TEMP_LITTLE_COOL],
					chg->vbatmax[BATT_TEMP_LITTLE_COOL]);
			chg->temp_littel_cool_set_current_0_point_25c = true;
		}
		op_battery_temp_region_set(chg, BATT_TEMP_LITTLE_COOL);

		/* Update the temperature boundaries */
		chg->mBattTempBoundT0 = chg->BATT_TEMP_T0;
		chg->mBattTempBoundT1 = chg->BATT_TEMP_T1;
		chg->mBattTempBoundT2 = chg->BATT_TEMP_T2;
		chg->mBattTempBoundT3 = chg->BATT_TEMP_T3 + BATT_TEMP_HYST;
		chg->mBattTempBoundT4 = chg->BATT_TEMP_T4;
		chg->mBattTempBoundT5 = chg->BATT_TEMP_T5;
		chg->mBattTempBoundT6 = chg->BATT_TEMP_T6;
		set_prop_batt_health(chg, POWER_SUPPLY_HEALTH_GOOD);
	}

	return 0;
}

/* 12C < Tbatt < 22C */
static int handle_batt_temp_prenormal(struct smb_charger *chg)
{
	temp_region_type temp_region;

	if (chg->chg_ovp)
		return 0;

	temp_region = op_battery_temp_region_get(chg);
	if (temp_region != BATT_TEMP_PRE_NORMAL
			|| chg->is_power_changed || chg->recharge_pending) {
		pr_err("triggered\n");
		chg->recharge_pending = false;
		chg->is_power_changed = false;

		if (temp_region == BATT_TEMP_HOT ||
				temp_region == BATT_TEMP_COLD)
			op_charging_en(chg, true);

		set_chg_ibat_vbat_max(chg,
				chg->ibatmax[BATT_TEMP_PRE_NORMAL],
				chg->vbatmax[BATT_TEMP_PRE_NORMAL]);
		op_battery_temp_region_set(chg, BATT_TEMP_PRE_NORMAL);

		/* Update the temperature boundaries */
		chg->mBattTempBoundT0 = chg->BATT_TEMP_T0;
		chg->mBattTempBoundT1 = chg->BATT_TEMP_T1;
		chg->mBattTempBoundT2 = chg->BATT_TEMP_T2;
		chg->mBattTempBoundT3 = chg->BATT_TEMP_T3;
		chg->mBattTempBoundT4 = chg->BATT_TEMP_T4 + BATT_TEMP_HYST;
		chg->mBattTempBoundT5 = chg->BATT_TEMP_T5;
		chg->mBattTempBoundT6 = chg->BATT_TEMP_T6;
		set_prop_batt_health(chg, POWER_SUPPLY_HEALTH_GOOD);
	}

	return 0;
}

/* 15C < Tbatt < 45C */
static int handle_batt_temp_normal(struct smb_charger *chg)
{
	temp_region_type temp_region;

	if (chg->chg_ovp)
		return 0;

	temp_region = op_battery_temp_region_get(chg);
	if ((temp_region != BATT_TEMP_NORMAL)
			|| chg->is_power_changed || chg->recharge_pending) {
		pr_err("triggered\n");
		chg->recharge_pending = false;
		chg->is_power_changed = false;

		if (temp_region == BATT_TEMP_HOT ||
				temp_region == BATT_TEMP_COLD)
			op_charging_en(chg, true);

		set_chg_ibat_vbat_max(chg,
				chg->ibatmax[BATT_TEMP_NORMAL],
				chg->vbatmax[BATT_TEMP_NORMAL]);
		op_battery_temp_region_set(chg, BATT_TEMP_NORMAL);

		/* Update the temperature boundaries */
		chg->mBattTempBoundT0 = chg->BATT_TEMP_T0;
		chg->mBattTempBoundT1 = chg->BATT_TEMP_T1;
		chg->mBattTempBoundT2 = chg->BATT_TEMP_T2;
		chg->mBattTempBoundT3 = chg->BATT_TEMP_T3;
		chg->mBattTempBoundT4 = chg->BATT_TEMP_T4;
		chg->mBattTempBoundT5 = chg->BATT_TEMP_T5;
		chg->mBattTempBoundT6 = chg->BATT_TEMP_T6;
		set_prop_batt_health(chg, POWER_SUPPLY_HEALTH_GOOD);
	}

	return 0;
}

/* 45C <= Tbatt <= 55C */
static int handle_batt_temp_warm(struct smb_charger *chg)
{
	temp_region_type temp_region;

	if (chg->chg_ovp)
		return 0;

	temp_region = op_battery_temp_region_get(chg);
	if ((temp_region != BATT_TEMP_WARM)
			|| chg->is_power_changed || chg->recharge_pending) {
		pr_err("triggered\n");
		chg->is_power_changed = false;
		chg->recharge_pending = false;

		if (temp_region == BATT_TEMP_HOT ||
				temp_region == BATT_TEMP_COLD)
			op_charging_en(chg, true);

		set_chg_ibat_vbat_max(chg,
				chg->ibatmax[BATT_TEMP_WARM],
				chg->vbatmax[BATT_TEMP_WARM]);
		op_battery_temp_region_set(chg, BATT_TEMP_WARM);

		/* Update the temperature boundaries */
		chg->mBattTempBoundT0 = chg->BATT_TEMP_T0;
		chg->mBattTempBoundT1 = chg->BATT_TEMP_T1;
		chg->mBattTempBoundT2 = chg->BATT_TEMP_T2;
		chg->mBattTempBoundT3 = chg->BATT_TEMP_T3;
		chg->mBattTempBoundT4 = chg->BATT_TEMP_T4;
		chg->mBattTempBoundT5 = chg->BATT_TEMP_T5 - BATT_TEMP_HYST;
		chg->mBattTempBoundT6 = chg->BATT_TEMP_T6;
		set_prop_batt_health(chg, POWER_SUPPLY_HEALTH_GOOD);
	}

	return 0;
}

/* 55C < Tbatt */
static int handle_batt_temp_hot(struct smb_charger *chg)
{
	temp_region_type temp_region;

	temp_region = op_battery_temp_region_get(chg);
	if ((temp_region != BATT_TEMP_HOT)
			|| chg->is_power_changed) {
		pr_err("triggered\n");
		chg->is_power_changed = false;

		op_charging_en(chg, false);
		op_battery_temp_region_set(chg, BATT_TEMP_HOT);

		/* Update the temperature boundaries */
		chg->mBattTempBoundT0 = chg->BATT_TEMP_T0;
		chg->mBattTempBoundT1 = chg->BATT_TEMP_T1;
		chg->mBattTempBoundT2 = chg->BATT_TEMP_T2;
		chg->mBattTempBoundT3 = chg->BATT_TEMP_T3;
		chg->mBattTempBoundT4 = chg->BATT_TEMP_T4;
		chg->mBattTempBoundT5 = chg->BATT_TEMP_T5;
		chg->mBattTempBoundT6 = chg->BATT_TEMP_T6 - BATT_TEMP_HYST; /* from hot to warm */
		set_prop_batt_health(chg, POWER_SUPPLY_HEALTH_OVERHEAT);
	}

	return 0;
}

static int op_check_battery_temp(struct smb_charger *chg)
{
	int temp, rc = -1;

	if(!chg->vbus_present)
		return rc;

	temp = get_prop_batt_temp(chg);
	if (temp < chg->mBattTempBoundT0) /* COLD */
		rc = handle_batt_temp_cold(chg);
	else if (temp >=  chg->mBattTempBoundT0 &&
			temp < chg->mBattTempBoundT1) /* LITTLE_COLD */
		rc = handle_batt_temp_little_cold(chg);
	else if (temp >=  chg->mBattTempBoundT1 &&
			temp < chg->mBattTempBoundT2) /* COOL */
		rc = handle_batt_temp_cool(chg);
	else if (temp >= chg->mBattTempBoundT2 &&
			temp < chg->mBattTempBoundT3) /* LITTLE_COOL */
		rc = handle_batt_temp_little_cool(chg);
	else if (temp >= chg->mBattTempBoundT3 &&
			temp < chg->mBattTempBoundT4) /* PRE_NORMAL */
		rc = handle_batt_temp_prenormal(chg);
	else if (temp >= chg->mBattTempBoundT4 &&
			temp < chg->mBattTempBoundT5) /* NORMAL */
		rc = handle_batt_temp_normal(chg);
	else if (temp >= chg->mBattTempBoundT5 &&
			temp <=  chg->mBattTempBoundT6) /* WARM */
		rc = handle_batt_temp_warm(chg);
	else if (temp > chg->mBattTempBoundT6) /* HOT */
		rc = handle_batt_temp_hot(chg);

	return rc;
}

void op_charge_info_init(struct smb_charger *chg)
{
	op_battery_temp_region_set(chg, BATT_TEMP_NORMAL);

	chg->mBattTempBoundT0 = chg->BATT_TEMP_T0;
	chg->mBattTempBoundT1 = chg->BATT_TEMP_T1;
	chg->mBattTempBoundT2 = chg->BATT_TEMP_T2;
	chg->mBattTempBoundT3 = chg->BATT_TEMP_T3;
	chg->mBattTempBoundT4 = chg->BATT_TEMP_T4;
	chg->mBattTempBoundT5 = chg->BATT_TEMP_T5;
	chg->mBattTempBoundT6 = chg->BATT_TEMP_T6;
	chg->chg_ovp = false;
	chg->is_power_changed = false;
	chg->chg_done = false;
	chg->recharge_pending = false;
	chg->recharge_status = false;
	chg->temp_littel_cool_set_current_0_point_25c = false;
	chg->oem_lcd_is_on = false;
	chg->time_out = false;
	chg->battery_status = BATT_STATUS_GOOD;
	chg->disable_normal_chg_for_dash = false;
	chg->usb_enum_status = false;
	chg->non_std_chg_present = false;
	chg->op_irq_enabled = true;
}

static int op_handle_battery_uovp(struct smb_charger *chg)
{
	pr_err("vbat is over voltage, stop charging\n");
	set_prop_batt_health(chg, POWER_SUPPLY_HEALTH_OVERVOLTAGE);
	op_charging_en(chg, false);

	return 0;
}

static int op_handle_battery_restore_from_uovp(struct smb_charger *chg)
{
	pr_err("vbat is back to normal, start charging\n");
	/* restore charging form battery ovp */
	op_charging_en(chg, true);
	set_prop_batt_health(chg, POWER_SUPPLY_HEALTH_GOOD);

	return 0;
}

static void op_check_battery_uovp(struct smb_charger *chg)
{
	int vbat_mv = 0;
	enum batt_status_type battery_status_pre;

	if (!chg->vbus_present)
		return;

	battery_status_pre = op_battery_status_get(chg);
	vbat_mv = get_prop_batt_voltage_now(chg) / 1000;
	pr_debug("bat vol:%d\n", vbat_mv);
	if (vbat_mv > BATT_SOFT_OVP_MV) {
		if (battery_status_pre == BATT_STATUS_GOOD) {
			pr_err("BATTERY_SOFT_OVP_VOLTAGE\n");
			op_battery_status_set(chg, BATT_STATUS_BAD);
			op_handle_battery_uovp(chg);
		}
	}
	else {
		if (battery_status_pre == BATT_STATUS_BAD) {
			pr_err("battery_restore_from_uovp\n");
			op_battery_status_set(chg, BATT_STATUS_GOOD);
			op_handle_battery_restore_from_uovp(chg);
			//smbchg_rerun_aicl(chip);
		}
	}

	return;
}
int op_get_charg_en(struct smb_charger *chg, int *chg_enabled)
{
	int rc = 0;
	u8 temp;

	rc = smblib_read(chg, CHARGING_ENABLE_CMD_REG, &temp);
	if (rc < 0) {
		smblib_err(chg, "Couldn't read chg en rc=%d\n", rc);
		return rc;
	}
	*chg_enabled = temp & CHARGING_ENABLE_CMD_BIT;

	return rc;
}

static void op_check_charger_collapse(struct smb_charger *chg)
{
	int rc, is_usb_supend, curr, chg_en;
	u8 stat, chger_stat, pwer_source_stats;

	if (!chg->vbus_present)
		return;
	if (chg->dash_present)
		return;
	rc = smblib_read(chg, BATTERY_CHARGER_STATUS_1_REG, &chger_stat);
	if (rc < 0) {
		smblib_err(chg, "Couldn't read POWER_PATH_STATUS rc=%d\n",
			rc);
	}
	rc = smblib_read(chg, POWER_PATH_STATUS_REG, &pwer_source_stats);
	if (rc < 0) {
		smblib_err(chg, "Couldn't read AICL_STATUS_REG rc=%d\n",
			rc);
	}
	smblib_get_usb_suspend(chg, &is_usb_supend);
	op_get_charg_en(chg, &chg_en);
	pr_debug("chger_stat=0x%x, aicl_stats =0x%x, chg_en =%d\n",
		chger_stat, pwer_source_stats, chg_en);
	curr = get_prop_batt_current_now(chg) / 1000;
	stat = !chg->chg_done
			&& !is_usb_supend
			&& (curr > 20)
			&& chg_en
			&& ((CC_SOFT_TERMINATE_BIT & chger_stat)
				|| (pwer_source_stats == 0x72));

	if (stat && !chg->charger_collpse) {
		rc = smblib_masked_write(chg, USBIN_AICL_OPTIONS_CFG_REG,
		SUSPEND_ON_COLLAPSE_USBIN_BIT
		|USBIN_AICL_START_AT_MAX_BIT
		| USBIN_AICL_ADC_EN_BIT
		|USBIN_AICL_RERUN_EN_BIT, USBIN_AICL_RERUN_EN_BIT);
		if (rc < 0)
			dev_err(chg->dev,
			"Couldn't configure AICL rc=%d\n", rc);
	smblib_rerun_aicl(chg);
	chg->charger_collpse = true;
	schedule_delayed_work(&chg->op_re_set_work,
				msecs_to_jiffies(TIME_1000MS));
	smblib_err(chg, "op_check_charger_collapse done\n");
	}
}

static void op_check_charger_uovp(struct smb_charger *chg, int vchg_mv)
{
	static int over_volt_count = 0, not_over_volt_count = 0;
	static bool uovp_satus, pre_uovp_satus;
	int detect_time = 3; /* 3 x 6s = 18s */

	if (!chg->vbus_present)
		return;

	pr_debug("charger_voltage=%d charger_ovp=%d\n", vchg_mv, chg->chg_ovp);

	if (!chg->chg_ovp) {
		if (vchg_mv > CHG_SOFT_OVP_MV || vchg_mv <= CHG_SOFT_UVP_MV) {
			pr_err("charger is over voltage, count=%d\n", over_volt_count);
			uovp_satus = true;
			if (pre_uovp_satus)
				over_volt_count++;
			else
				over_volt_count = 0;

			pr_err("uovp_satus=%d, pre_uovp_satus=%d, over_volt_count=%d\n",
					uovp_satus, pre_uovp_satus, over_volt_count);
			if (detect_time <= over_volt_count) {
				/* vchg continuous higher than 5.8v */
				pr_err("charger is over voltage, stop charging\n");
				op_charging_en(chg, false);
				chg->chg_ovp = true;
			}
		}
	} else {
		if (vchg_mv < CHG_SOFT_OVP_MV - 100
				&& vchg_mv > CHG_SOFT_UVP_MV + 100) {
			uovp_satus = false;
			if (!pre_uovp_satus)
				not_over_volt_count++;
			else
				not_over_volt_count = 0;

			pr_err("uovp_satus=%d, pre_uovp_satus=%d,not_over_volt_count=%d\n",
					uovp_satus, pre_uovp_satus, not_over_volt_count);
			if (detect_time <= not_over_volt_count) {
				/* vchg continuous lower than 5.7v */
				pr_err("charger voltage is back to normal\n");
				op_charging_en(chg, true);
				chg->chg_ovp = false;
				op_check_battery_temp(chg);
				smblib_rerun_aicl(chg);
			}
		}
	}
	pre_uovp_satus = uovp_satus;
	return;
}
#if defined(CONFIG_FB)
static int fb_notifier_callback(struct notifier_block *self,
		unsigned long event, void *data)
{
	struct fb_event *evdata = data;
	int *blank;
	struct smb_charger *chip =
		container_of(self, struct smb_charger, fb_notif);

	if (evdata && evdata->data && chip) {
		if (event == FB_EVENT_BLANK) {
			blank = evdata->data;
			if (*blank == FB_BLANK_UNBLANK) {
				if (!chip->oem_lcd_is_on)
					set_property_on_fg(chip,
					POWER_SUPPLY_PROP_UPDATE_LCD_IS_OFF, 0);
				chip->oem_lcd_is_on = true;
			} else if (*blank == FB_BLANK_POWERDOWN) {
				if (chip->oem_lcd_is_on != false)
					set_property_on_fg(chip,
					POWER_SUPPLY_PROP_UPDATE_LCD_IS_OFF, 1);
				chip->oem_lcd_is_on = false;
			}
		}

	}

	return 0;
}
#endif /*CONFIG_FB*/

#define SOFT_CHG_TERM_CURRENT 100 /* 100MA */
void checkout_term_current(struct smb_charger *chg, int batt_temp)
{
	static int term_current_reached = 0;
	int current_ma, voltage_mv, temp_region, batt_status;

	batt_status = get_prop_batt_status(chg);
	if (batt_status != POWER_SUPPLY_STATUS_CHARGING)
		return;

	current_ma = get_prop_batt_current_now(chg) / 1000;
	if (!(current_ma >= -SOFT_CHG_TERM_CURRENT
			&& current_ma <= SOFT_CHG_TERM_CURRENT)) {
		/* soft charge term set to 100mA */
		term_current_reached = 0;
		return;
	}

	voltage_mv = get_prop_batt_voltage_now(chg) / 1000;
	temp_region = op_battery_temp_region_get(chg);
	if (voltage_mv >= chg->vbatmax[temp_region]) {
		term_current_reached++;
	} else {
		term_current_reached = 0;
		return;
	}

	if (term_current_reached >= 5) {
		//smbchg_charging_status_change(chg);
		//set_property_on_fg(chg, POWER_SUPPLY_PROP_CHARGE_DONE, 1);
		chg->chg_done = true;
		term_current_reached = 0;
		pr_err("chg_done: CAP=%d (Q:%d), VBAT=%d (Q:%d), IBAT=%d (Q:%d), BAT_TEMP=%d\n",
				get_prop_batt_capacity(chg),
				get_prop_fg_capacity(chg),
				get_prop_batt_voltage_now(chg) / 1000,
				get_prop_fg_voltage_now(chg) / 1000,
				get_prop_batt_current_now(chg) / 1000,
				get_prop_fg_current_now(chg) / 1000,
				get_prop_batt_temp(chg));
		op_charging_en(chg, false);
	}
}

/* xianglin add for usb enum at first bootup */
static int usb_enum_check(const char *val, struct kernel_param *kp)
{
	const struct apsd_result *apsd_result;
	int usb_sw_reset = 0;
	struct smb_charger *chg = g_chg;

	/*if enum done, return */
	if (chg->usb_enum_status)
		return 0;

	usb_sw_reset = simple_strtoul(val, NULL, 10);
	if (!usb_sw_reset)
		return 0;

	if (!is_usb_present(chg))
		return 0;
	/* if not SDP, return */
	apsd_result = smblib_get_apsd_result(chg);
	if (apsd_result->bit != SDP_CHARGER_BIT)
		return 0;

	pr_info("usb don't enum for longtime in boot\n");
	op_handle_usb_removal(chg);
	chg->non_stand_chg_count = 0;
	schedule_delayed_work(
		&chg->non_standard_charger_check_work,
		msecs_to_jiffies(TIME_1000MS));
	return 0;
}
module_param_call(sys_boot_complete, usb_enum_check, NULL, NULL, 0644);

static void check_non_standard_charger_work(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct smb_charger *chg = container_of(dwork,
	struct smb_charger, non_standard_charger_check_work);
	bool charger_present;
	const struct apsd_result *apsd_result;
	int aicl_result, rc;
	pr_debug("chg->non_stand_chg_count=%d\n", chg->non_stand_chg_count);

	charger_present = is_usb_present(chg);
	if (!charger_present) {
		pr_info("chk_non_std_chger,charger_present\n");
		chg->non_stand_chg_count = 0;
		return;
	}
	if (chg->usb_enum_status) {
		pr_info("chk_non_std_chger,usb_enum_status\n");
		chg->non_stand_chg_count = 0;
		return;
	}
	if (chg->non_stand_chg_count
		>= NON_STANDARD_CHARGER_CHECK_S) {
		apsd_result = smblib_update_usb_type(chg);
		if (apsd_result->bit == DCP_CHARGER_BIT
			|| apsd_result->bit == OCP_CHARGER_BIT)
			return;
		rc = smblib_rerun_aicl(chg);
		if (rc < 0)
			smblib_err(chg, "Couldn't re-run AICL rc=%d\n", rc);
		msleep(500);
		aicl_result = op_get_aicl_result(chg);
		chg->non_stand_chg_current = aicl_result;
		chg->usb_psy_desc.type = POWER_SUPPLY_TYPE_USB_DCP;
		if (chg->is_aging_test)
			op_usb_icl_set(chg, DEFAULT_AGAING_CHG_MA*1000);
		else
			op_usb_icl_set(chg, DEFAULT_DCP_MA*1000);
		power_supply_changed(chg->batt_psy);
		chg->is_power_changed = true;
		chg->non_std_chg_present = true;
		pr_err("non-standard_charger detected,aicl_result=%d\n",
			aicl_result);
	} else {
		chg->non_stand_chg_count++;
		schedule_delayed_work(
			&chg->non_standard_charger_check_work,
			msecs_to_jiffies(TIME_1000MS));
	}
}
static void smbchg_re_det_work(struct work_struct *work)
{
	struct smb_charger *chg = container_of(work,
			struct smb_charger,
			re_det_work.work);

	pr_debug("chg->redet_count=%d\n", chg->redet_count);
	if (chg->usb_enum_status) {
		pr_info("re_det, usb_enum_status\n");
		chg->redet_count = 0;
		return;
	}
	if (!chg->vbus_present) {
		pr_info("re_det, vbus_no_present\n");
		chg->redet_count = 0;
		return;
	}

	if (chg->redet_count >= REDET_COUTNT) {
		op_rerun_apsd(chg);
		chg->usb_type_redet_done = true;
	} else {
		chg->redet_count++;
		schedule_delayed_work(&chg->re_det_work,
				msecs_to_jiffies(TIME_1000MS));
	}
}
static void op_recovery_set_work(struct work_struct *work)
{
	struct smb_charger *chg = container_of(work,
			struct smb_charger,
			op_re_set_work.work);
	int rc;

	pr_debug("chg->reset_count=%d\n", chg->reset_count);
	if (!chg->charger_collpse) {
		chg->reset_count = 0;
		return;
	}
	if (!chg->vbus_present) {
		chg->reset_count = 0;
		return;
	}

	if (chg->reset_count >= 13) {

		pr_err("op_set_collapse_fet\n");
		rc = smblib_write(chg, USBIN_AICL_OPTIONS_CFG_REG, 0xc7);
		if (rc < 0)
			smblib_err(chg,
			"Couldn't enable OTG regulator rc=%d\n", rc);
		chg->charger_collpse = false;
		chg->reset_count = 0;
	} else {
		chg->reset_count++;
		schedule_delayed_work(&chg->op_re_set_work,
				msecs_to_jiffies(TIME_1000MS));
	}
}
#ifdef	CONFIG_OP_DEBUG_CHG
void aging_test_check_aicl(struct smb_charger *chg)
{
	int aicl_result, vbat;

	if (chg->usb_enum_status)
		return;
	vbat = get_prop_fg_voltage_now(chg) / 1000;
	aicl_result = op_get_aicl_result(chg);
	if (aicl_result < 800*1000) {
		if (vbat < 4000) {
			pr_info("set icl 900mA\n");
			vote(chg->usb_icl_votable, AICL_RERUN_VOTER,
				true, 900*1000);
			vote(chg->usb_icl_votable, AICL_RERUN_VOTER, false, 0);
		}
	}
}
#endif
static void op_heartbeat_work(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct smb_charger *chg = container_of(dwork,
			struct smb_charger, heartbeat_work);
	temp_region_type temp_region;
	bool charger_present;
	bool fast_charging;
	static int batt_temp = 0, vbat_mv = 0;
	union power_supply_propval vbus_val;
	int rc;
#ifndef CONFIG_OP_DEBUG_CHG
	op_check_charge_timeout(chg);
#endif
	rc = smblib_get_prop_usb_voltage_now(chg, &vbus_val);
	if (rc < 0) {
		pr_err("failed to read usb_voltage rc=%d\n", rc);
		vbus_val.intval = CHG_VOLTAGE_NORMAL;
	}

	charger_present = is_usb_present(chg);
	if (!charger_present)
		goto out;

	/* charger present */
	power_supply_changed(chg->batt_psy);
	chg->dash_on = get_prop_fast_chg_started(chg);
	if (chg->dash_on) {
		switch_fast_chg(chg);
		pr_info("fast chg started, usb_switch=%d\n",
				op_is_usb_switch_on(chg));
		/* add for disable normal charge */
		fast_charging = op_get_fastchg_ing(chg);
		if (fast_charging) {
			if (!chg->disable_normal_chg_for_dash)
				op_charging_en(chg, false);
			chg->disable_normal_chg_for_dash = true;
		}
		goto out;
	} else {
		if (chg->disable_normal_chg_for_dash) {
			chg->disable_normal_chg_for_dash = false;
			op_charging_en(chg, true);
		}
		schedule_delayed_work(&chg->check_switch_dash_work,
							msecs_to_jiffies(100));
	}

	op_check_charger_uovp(chg, vbus_val.intval);
	op_check_battery_uovp(chg);
	if (vbus_val.intval > 4500)
		op_check_charger_collapse(chg);

	vbat_mv = get_prop_batt_voltage_now(chg) / 1000;
	temp_region = op_battery_temp_region_get(chg);
	if (temp_region == BATT_TEMP_LITTLE_COOL) {
		if (vbat_mv > 4180 + 20
				&& chg->temp_littel_cool_set_current_0_point_25c) {
			chg->is_power_changed = true;
		} else if (vbat_mv < 4180 - 10
				&& !chg->temp_littel_cool_set_current_0_point_25c) {
			chg->is_power_changed = true;
		}
	}

	batt_temp = get_prop_batt_temp(chg);
	checkout_term_current(chg, batt_temp);
	if (!chg->chg_ovp && chg->chg_done
			&& temp_region > BATT_TEMP_COLD
			&& temp_region < BATT_TEMP_HOT
			&& chg->vbatdet[temp_region] >= vbat_mv) {
		chg->chg_done = false;
		chg->recharge_pending = true;
		chg->recharge_status = true;

		op_charging_en(chg, true);
		pr_debug("temp_region=%d, recharge_pending\n", temp_region);
	}

	if (!chg->chg_ovp && chg->battery_status == BATT_STATUS_GOOD
			&& !chg->time_out) {
		op_check_battery_temp(chg);
	}
#ifdef	CONFIG_OP_DEBUG_CHG
	chg->dump_count++;
	if (chg->dump_count == 600) {
		chg->dump_count = 0;
		if ((get_prop_batt_current_now(chg) / 1000) > 0) {
			op_dump_regs(chg);
			aging_test_check_aicl(chg);
		}
	}
#endif
out:
		smblib_dbg(chg, PR_OP_DEBUG, "CAP=%d (Q:%d), VBAT=%d (Q:%d), IBAT=%d (Q:%d), BAT_TEMP=%d, CHG_TYPE=%d, VBUS=%d\n",
				get_prop_batt_capacity(chg),
				get_prop_fg_capacity(chg),
				get_prop_batt_voltage_now(chg) / 1000,
				get_prop_fg_voltage_now(chg) / 1000,
				get_prop_batt_current_now(chg) / 1000,
				get_prop_fg_current_now(chg) / 1000,
				get_prop_batt_temp(chg),
				chg->usb_psy_desc.type,
				vbus_val.intval);

	/*update time 6s*/
	schedule_delayed_work(&chg->heartbeat_work,
			round_jiffies_relative(msecs_to_jiffies
				(HEARTBEAT_INTERVAL_MS)));
}


static int op_read(struct smb_charger *chg, u16 addr, u8 *val)
{
	unsigned int temp;
	int rc = 0;
	if (pm_pon && pm_pon->regmap){
		rc = regmap_read(pm_pon->regmap, addr, &temp);
		if (rc >= 0)
			*val = (u8)temp;
	}
	return rc;
}

int op_read_backup_flag(struct smb_charger *chg)
{
	u8 flag;
	int rc = 0;

	rc = op_read(chg, SOC_DATA_REG_0, &flag);
	if (rc) {
		pr_err("failed to read PM addr[0x%x], rc=%d\n", SOC_DATA_REG_0, rc);
		return 0;
	}
	flag = flag & BIT(7);
	return flag;
}

int op_masked_write(struct smb_charger *chg, u16 addr, u8 mask, u8 val)
{
	int rc = 0;
	if (pm_pon && pm_pon->regmap){
		mutex_lock(&chg->write_lock);
		rc = regmap_update_bits(pm_pon->regmap, addr, mask, val);
		mutex_unlock(&chg->write_lock);
	}else{
		pr_err("pm_pon is NULL\n");
	}
	return rc;
}

void op_write_backup_flag(struct smb_charger *chg,bool bk_flag)
{
	int rc = 0;

	rc = op_masked_write(chg, SOC_DATA_REG_0,
		BIT(7), bk_flag ? BIT(7):0);
	if (rc) {
		pr_err("failed to clean PM addr[0x%x], rc=%d\n", SOC_DATA_REG_0, rc);
	}
}


static int load_data(struct smb_charger *chg)
{
	u8 stored_soc = 0,flag;
	int rc = 0, shutdown_soc = 0;

	if (!chg) {
		pr_err("chg is NULL !\n");
		return SOC_INVALID;
	}
	flag = op_read_backup_flag(chg);
	if(!flag){
		return SOC_INVALID;
	}

	rc = smblib_read(chg, SOC_DATA_REG_0, &stored_soc);
	if (rc) {
		pr_err("failed to read addr[0x%x], rc=%d\n", SOC_DATA_REG_0, rc);
		return SOC_INVALID;
	}

	/* the fist time connect battery, the PM 0x88d bit7 is 0, we do not need load this data.*/
	if (flag)
		shutdown_soc = (stored_soc >> 1 ); /* get data from bit1~bit7 */
	else
		shutdown_soc = SOC_INVALID;

	pr_info("stored_soc[0x%x], shutdown_soc[%d]\n", stored_soc, shutdown_soc);
	return shutdown_soc;
}

int load_soc(void)
{
	int soc = 0;

	soc = load_data(g_chg);
	if (soc == SOC_INVALID || soc < 0 || soc > 100)
		return -1;
	return soc;
}

static void clear_backup_soc(struct smb_charger *chg)
{
	int rc = 0;
	u8 invalid_soc = SOC_INVALID;
	op_write_backup_flag(chg,false);
	rc = smblib_masked_write(chg, SOC_DATA_REG_0,
				BIT(7)| BIT(6)| BIT(5)| BIT(4)| BIT(3)| BIT(2)| BIT(1),
				(BIT(7) & invalid_soc) | (BIT(6) & invalid_soc) | (BIT(5) & invalid_soc) |
				(BIT(4) & invalid_soc) | (BIT(3) & invalid_soc) | (BIT(2) & invalid_soc) |
				(BIT(1) & invalid_soc));
	if (rc)
		pr_err("failed to write addr[0x%x], rc=%d\n",
						SOC_DATA_REG_0, rc);
	if (rc){
		pr_err("failed to clean PM addr[0x%x], rc=%d\n", SOC_DATA_REG_0, rc);
	}
}

void clean_backup_soc_ex(void)
{
	if(g_chg)
		clear_backup_soc(g_chg);
}

static void backup_soc(struct smb_charger *chg, int soc)
{
	int rc = 0;

	if (!chg || soc < 0 || soc > 100) {
		pr_err("chg or soc invalid, store an invalid soc\n");
		if (chg) {
			rc = smblib_masked_write(chg, SOC_DATA_REG_0,
				BIT(7)| BIT(6)| BIT(5)| BIT(4)| BIT(3)| BIT(2)| BIT(1),
				BIT(7)| BIT(6)| BIT(5)| BIT(4)| BIT(3)| BIT(2)| BIT(1));
			if (rc)
				pr_err("failed to write addr[0x%x], rc=%d\n",
						SOC_DATA_REG_0, rc);
			op_write_backup_flag(chg,false);
		}
		return;
	}

	pr_err("backup_soc[%d]\n", soc);
	soc = soc*2;
	rc = smblib_masked_write(chg, SOC_DATA_REG_0,
				BIT(7)| BIT(6)| BIT(5)| BIT(4)| BIT(3)| BIT(2)| BIT(1),
				(BIT(7) & soc) | (BIT(6) & soc) | (BIT(5) & soc) |
				(BIT(4) & soc) | (BIT(3) & soc) | (BIT(2) & soc) |
				(BIT(1) & soc));
	if (rc)
		pr_err("failed to write addr[0x%x], rc=%d\n",
				SOC_DATA_REG_0, rc);
	op_write_backup_flag(chg,true);
}

void backup_soc_ex(int soc)
{
	if (g_chg)
		backup_soc(g_chg, soc);
}

enum chg_protect_status_type {
    PROTECT_CHG_OVP = 1,                  /* 1: VCHG > 5.8V     */
    PROTECT_BATT_MISSING,                 /* 2: battery missing */
    PROTECT_CHG_OVERTIME,                 /* 3: charge overtime */
    PROTECT_BATT_OVP,                     /* 4: vbat >= 4.5     */
    PROTECT_BATT_TEMP_REGION__HOT,        /* 5: 55 < t          */
    PROTECT_BATT_TEMP_REGION_COLD,        /* 6:      t <= -3    */
    PROTECT_BATT_TEMP_REGION_LITTLE_COLD, /* 7: -3 < t <=  0    */
    PROTECT_BATT_TEMP_REGION_COOL,        /* 8:  0 < t <=  5    */
    PROTECT_BATT_TEMP_REGION_WARM         /* 9: 45 < t <= 55    */
};

int get_prop_chg_protect_status(struct smb_charger *chg)
{
	int temp, rc;
	bool batt_present;
	temp_region_type temp_region;
	union power_supply_propval vbus_val;

	if (chg->use_fake_protect_sts)
		return chg->fake_protect_sts;

	if (!is_usb_present(chg))
		return 0;

	rc = smblib_get_prop_usb_voltage_now(chg, &vbus_val);
	if (rc < 0) {
		pr_err("failed to read usb_voltage rc=%d\n", rc);
		vbus_val.intval= CHG_VOLTAGE_NORMAL;
	}

	temp = get_prop_batt_temp(chg);
	batt_present = get_prop_batt_present(chg);
	temp_region = op_battery_temp_region_get(chg);
	if (chg->chg_ovp && vbus_val.intval >= CHG_SOFT_OVP_MV - 100)
		return PROTECT_CHG_OVP;
	else if (BATT_REMOVE_TEMP > temp || !batt_present)
		return  PROTECT_BATT_MISSING;
	else if (BATT_STATUS_BAD == chg->battery_status)
		return PROTECT_BATT_OVP;
	else if (true == chg->time_out)
		return PROTECT_CHG_OVERTIME;
	else if (temp_region == BATT_TEMP_HOT)
		return PROTECT_BATT_TEMP_REGION__HOT;
	else if (temp_region == BATT_TEMP_COLD)
		return PROTECT_BATT_TEMP_REGION_COLD;
	else if (temp_region == BATT_TEMP_LITTLE_COLD
			&& (chg->chg_done || chg->recharge_status))
		return PROTECT_BATT_TEMP_REGION_LITTLE_COLD;
	else if (temp_region == BATT_TEMP_WARM
			&& (chg->chg_done || chg->recharge_status))
		return PROTECT_BATT_TEMP_REGION_WARM;
	else
		return 0;
}

bool get_prop_fastchg_status(struct smb_charger *chg)
{
	int capacity;

	if (chg->dash_present)
		return true;

	if (chg->hvdcp_present) {
		capacity = get_prop_batt_capacity(chg);
		if (capacity >= 1 && capacity <= 85)
			return true;
	}

	return false;
}

static struct notify_dash_event notify_unplug_event  = {
	.notify_event					= update_dash_unplug_status,
	.op_contrl				        = op_contrl,
	.notify_dash_charger_present	= set_dash_charger_present,
};
void op_pm8998_regmap_register(struct qpnp_pon *pon)
{
	if (pm_pon) {
		pm_pon = pon;
		pr_err("multiple battery gauge called\n");
	} else {
		pm_pon = pon;
	}
}

void fastcharge_information_register(struct external_battery_gauge *fast_chg)
{
	if (fast_charger) {
		fast_charger = fast_chg;
		pr_err("multiple battery gauge called\n");
	} else {
		fast_charger = fast_chg;
	}
}
EXPORT_SYMBOL(fastcharge_information_register);

void fastcharge_information_unregister(struct external_battery_gauge *fast_chg)
{
	fast_charger = NULL;
}
EXPORT_SYMBOL(fastcharge_information_unregister);

static int notify_usb_enumeration_function(int status)
{
	pr_info("status=%d\n",status);
	g_chg->usb_enum_status = status;

	return g_chg->usb_enum_status;
}

static struct notify_usb_enumeration_status usb_enumeration  = {
	.notify_usb_enumeration		= notify_usb_enumeration_function,
};

/***************
 * Work Queues *
 ***************/

static void smblib_hvdcp_detect_work(struct work_struct *work)
{
	struct smb_charger *chg = container_of(work, struct smb_charger,
					       hvdcp_detect_work.work);

	vote(chg->pd_disallowed_votable_indirect, HVDCP_TIMEOUT_VOTER,
				false, 0);
	power_supply_changed(chg->usb_psy);
}

static void bms_update_work(struct work_struct *work)
{
	struct smb_charger *chg = container_of(work, struct smb_charger,
						bms_update_work);

	smblib_suspend_on_debug_battery(chg);

	if (chg->batt_psy)
		power_supply_changed(chg->batt_psy);
}

static void step_soc_req_work(struct work_struct *work)
{
	struct smb_charger *chg = container_of(work, struct smb_charger,
						step_soc_req_work.work);
	union power_supply_propval pval = {0, };
	int rc;

	rc = smblib_get_prop_batt_capacity(chg, &pval);
	if (rc < 0) {
		smblib_err(chg, "Couldn't get batt capacity rc=%d\n", rc);
		return;
	}

	step_charge_soc_update(chg, pval.intval);
}

static void clear_hdc_work(struct work_struct *work)
{
	struct smb_charger *chg = container_of(work, struct smb_charger,
						clear_hdc_work.work);

	chg->is_hdc = 0;
}

static void rdstd_cc2_detach_work(struct work_struct *work)
{
	struct smb_charger *chg = container_of(work, struct smb_charger,
						rdstd_cc2_detach_work);
	int rc;
	u8 stat;


	if (!chg->cc2_sink_detach_flag)
		return;
	/*
	 * WA steps -
	 * 1. Enable both UFP and DFP, wait for 10ms.
	 * 2. Disable DFP, wait for 30ms.
	 * 3. Removal detected if both TYPEC_DEBOUNCE_DONE_STATUS
	 *    and TIMER_STAGE bits are gone, otherwise repeat all by
	 *    work rescheduling.
	 * Note, work will be cancelled when USB_PLUGIN rises.
	 */

	rc = smblib_masked_write(chg, TYPE_C_INTRPT_ENB_SOFTWARE_CTRL_REG,
				 UFP_EN_CMD_BIT | DFP_EN_CMD_BIT,
				 UFP_EN_CMD_BIT | DFP_EN_CMD_BIT);
	if (rc < 0) {
		smblib_err(chg, "Couldn't write TYPE_C_CTRL_REG rc=%d\n", rc);
		return;
	}

	usleep_range(10000, 11000);

	rc = smblib_masked_write(chg, TYPE_C_INTRPT_ENB_SOFTWARE_CTRL_REG,
				 UFP_EN_CMD_BIT | DFP_EN_CMD_BIT,
				 UFP_EN_CMD_BIT);
	if (rc < 0) {
		smblib_err(chg, "Couldn't write TYPE_C_CTRL_REG rc=%d\n", rc);
		return;
	}

	usleep_range(30000, 31000);

	rc = smblib_read(chg, TYPE_C_STATUS_4_REG, &stat);
	if (rc < 0) {
		smblib_err(chg, "Couldn't read TYPE_C_STATUS_4 rc=%d\n",
			rc);
		return;
	}
	if (stat & TYPEC_DEBOUNCE_DONE_STATUS_BIT)
		goto rerun;

	rc = smblib_read(chg, TYPE_C_STATUS_5_REG, &stat);
	if (rc < 0) {
		smblib_err(chg,
			"Couldn't read TYPE_C_STATUS_5_REG rc=%d\n", rc);
		return;
	}
	if (stat & TIMER_STAGE_2_BIT)
		goto rerun;

	/* Bingo, cc2 removal detected */
	smblib_reg_block_restore(chg, cc2_detach_settings);
	mutex_lock(&chg->lock);
	smblib_usb_typec_change(chg);
	mutex_unlock(&chg->lock);
	enable_irq(chg->irq_info[TYPE_C_CHANGE_IRQ].irq);
	return;

rerun:
	schedule_work(&chg->rdstd_cc2_detach_work);
}
static void smblib_legacy_detection_work(struct work_struct *work)
{
	struct smb_charger *chg = container_of(work, struct smb_charger,
							legacy_detection_work);
	int rc;

	mutex_lock(&chg->lock);
	smblib_dbg(chg, PR_MISC, "running legacy unknown workaround\n");
	vote(chg->typec_irq_disable_votable, LEGACY_UNKNOWN_VOTER, true, 0);
	rc = smblib_masked_write(chg,
				TYPE_C_INTRPT_ENB_SOFTWARE_CTRL_REG,
				TYPEC_DISABLE_CMD_BIT,
				TYPEC_DISABLE_CMD_BIT);
	if (rc < 0)
		smblib_err(chg, "Couldn't disable type-c rc=%d\n", rc);

	/* wait for the adapter to turn off VBUS */
	msleep(500);

	rc = smblib_masked_write(chg,
				TYPE_C_INTRPT_ENB_SOFTWARE_CTRL_REG,
				TYPEC_DISABLE_CMD_BIT, 0);
	if (rc < 0)
		smblib_err(chg, "Couldn't enable type-c rc=%d\n", rc);

	/* wait for type-c detection to complete */
	msleep(100);

	chg->typec_legacy_valid = true;
	smblib_usb_typec_change(chg);
	vote(chg->typec_irq_disable_votable, LEGACY_UNKNOWN_VOTER, false, 0);
	mutex_unlock(&chg->lock);
}

static int smblib_create_votables(struct smb_charger *chg)
{
	int rc = 0;

	chg->fcc_votable = find_votable("FCC");
	if (!chg->fcc_votable) {
		rc = -EPROBE_DEFER;
		return rc;
	}

	chg->fv_votable = find_votable("FV");
	if (!chg->fv_votable) {
		rc = -EPROBE_DEFER;
		return rc;
	}

	chg->pl_disable_votable = find_votable("PL_DISABLE");
	if (!chg->pl_disable_votable) {
		rc = -EPROBE_DEFER;
		return rc;
	}
	vote(chg->pl_disable_votable, PL_INDIRECT_VOTER, true, 0);
	vote(chg->pl_disable_votable, PL_DELAY_HVDCP_VOTER, true, 0);

	chg->dc_suspend_votable = create_votable("DC_SUSPEND", VOTE_SET_ANY,
					smblib_dc_suspend_vote_callback,
					chg);
	if (IS_ERR(chg->dc_suspend_votable)) {
		rc = PTR_ERR(chg->dc_suspend_votable);
		return rc;
	}

	chg->usb_icl_votable = create_votable("USB_ICL", VOTE_MIN,
					smblib_usb_icl_vote_callback,
					chg);
	if (IS_ERR(chg->usb_icl_votable)) {
		rc = PTR_ERR(chg->usb_icl_votable);
		return rc;
	}

	chg->dc_icl_votable = create_votable("DC_ICL", VOTE_MIN,
					smblib_dc_icl_vote_callback,
					chg);
	if (IS_ERR(chg->dc_icl_votable)) {
		rc = PTR_ERR(chg->dc_icl_votable);
		return rc;
	}

	chg->pd_disallowed_votable_indirect
		= create_votable("PD_DISALLOWED_INDIRECT", VOTE_SET_ANY,
			smblib_pd_disallowed_votable_indirect_callback, chg);
	if (IS_ERR(chg->pd_disallowed_votable_indirect)) {
		rc = PTR_ERR(chg->pd_disallowed_votable_indirect);
		return rc;
	}

	chg->pd_allowed_votable = create_votable("PD_ALLOWED",
					VOTE_SET_ANY, NULL, NULL);
	if (IS_ERR(chg->pd_allowed_votable)) {
		rc = PTR_ERR(chg->pd_allowed_votable);
		return rc;
	}

	chg->awake_votable = create_votable("AWAKE", VOTE_SET_ANY,
					smblib_awake_vote_callback,
					chg);
	if (IS_ERR(chg->awake_votable)) {
		rc = PTR_ERR(chg->awake_votable);
		return rc;
	}

	chg->chg_disable_votable = create_votable("CHG_DISABLE", VOTE_SET_ANY,
					smblib_chg_disable_vote_callback,
					chg);
	if (IS_ERR(chg->chg_disable_votable)) {
		rc = PTR_ERR(chg->chg_disable_votable);
		return rc;
	}

	chg->pl_enable_votable_indirect = create_votable("PL_ENABLE_INDIRECT",
					VOTE_SET_ANY,
					smblib_pl_enable_indirect_vote_callback,
					chg);
	if (IS_ERR(chg->pl_enable_votable_indirect)) {
		rc = PTR_ERR(chg->pl_enable_votable_indirect);
		return rc;
	}

	chg->hvdcp_disable_votable_indirect = create_votable(
				"HVDCP_DISABLE_INDIRECT",
				VOTE_SET_ANY,
				smblib_hvdcp_disable_indirect_vote_callback,
				chg);
	if (IS_ERR(chg->hvdcp_disable_votable_indirect)) {
		rc = PTR_ERR(chg->hvdcp_disable_votable_indirect);
		return rc;
	}

	chg->hvdcp_enable_votable = create_votable("HVDCP_ENABLE",
					VOTE_SET_ANY,
					smblib_hvdcp_enable_vote_callback,
					chg);
	if (IS_ERR(chg->hvdcp_enable_votable)) {
		rc = PTR_ERR(chg->hvdcp_enable_votable);
		return rc;
	}

	chg->apsd_disable_votable = create_votable("APSD_DISABLE",
					VOTE_SET_ANY,
					smblib_apsd_disable_vote_callback,
					chg);
	if (IS_ERR(chg->apsd_disable_votable)) {
		rc = PTR_ERR(chg->apsd_disable_votable);
		return rc;
	}

	chg->hvdcp_hw_inov_dis_votable = create_votable("HVDCP_HW_INOV_DIS",
					VOTE_SET_ANY,
					smblib_hvdcp_hw_inov_dis_vote_callback,
					chg);
	if (IS_ERR(chg->hvdcp_hw_inov_dis_votable)) {
		rc = PTR_ERR(chg->hvdcp_hw_inov_dis_votable);
		return rc;
	}

	chg->usb_irq_enable_votable = create_votable("USB_IRQ_DISABLE",
					VOTE_SET_ANY,
					smblib_usb_irq_enable_vote_callback,
					chg);
	if (IS_ERR(chg->usb_irq_enable_votable)) {
		rc = PTR_ERR(chg->usb_irq_enable_votable);
		return rc;
	}

	chg->typec_irq_disable_votable = create_votable("TYPEC_IRQ_DISABLE",
					VOTE_SET_ANY,
					smblib_typec_irq_disable_vote_callback,
					chg);
	if (IS_ERR(chg->typec_irq_disable_votable)) {
		rc = PTR_ERR(chg->typec_irq_disable_votable);
		return rc;
	}

	return rc;
}

static void smblib_destroy_votables(struct smb_charger *chg)
{
	if (chg->dc_suspend_votable)
		destroy_votable(chg->dc_suspend_votable);
	if (chg->usb_icl_votable)
		destroy_votable(chg->usb_icl_votable);
	if (chg->dc_icl_votable)
		destroy_votable(chg->dc_icl_votable);
	if (chg->pd_disallowed_votable_indirect)
		destroy_votable(chg->pd_disallowed_votable_indirect);
	if (chg->pd_allowed_votable)
		destroy_votable(chg->pd_allowed_votable);
	if (chg->awake_votable)
		destroy_votable(chg->awake_votable);
	if (chg->chg_disable_votable)
		destroy_votable(chg->chg_disable_votable);
	if (chg->pl_enable_votable_indirect)
		destroy_votable(chg->pl_enable_votable_indirect);
	if (chg->apsd_disable_votable)
		destroy_votable(chg->apsd_disable_votable);
	if (chg->hvdcp_hw_inov_dis_votable)
		destroy_votable(chg->hvdcp_hw_inov_dis_votable);
	if (chg->typec_irq_disable_votable)
		destroy_votable(chg->typec_irq_disable_votable);
}

static void smblib_iio_deinit(struct smb_charger *chg)
{
	if (!IS_ERR_OR_NULL(chg->iio.temp_chan))
		iio_channel_release(chg->iio.temp_chan);
	if (!IS_ERR_OR_NULL(chg->iio.temp_max_chan))
		iio_channel_release(chg->iio.temp_max_chan);
	if (!IS_ERR_OR_NULL(chg->iio.usbin_i_chan))
		iio_channel_release(chg->iio.usbin_i_chan);
	if (!IS_ERR_OR_NULL(chg->iio.usbin_v_chan))
		iio_channel_release(chg->iio.usbin_v_chan);
	if (!IS_ERR_OR_NULL(chg->iio.batt_i_chan))
		iio_channel_release(chg->iio.batt_i_chan);
}

int smblib_init(struct smb_charger *chg)
{
	int rc = 0;

	mutex_init(&chg->lock);
	mutex_init(&chg->write_lock);
	mutex_init(&chg->otg_oc_lock);
	mutex_init(&chg->pd_hard_reset_lock);
	mutex_init(&chg->sw_dash_lock);
	INIT_WORK(&chg->bms_update_work, bms_update_work);
	INIT_WORK(&chg->rdstd_cc2_detach_work, rdstd_cc2_detach_work);
	INIT_DELAYED_WORK(&chg->hvdcp_detect_work, smblib_hvdcp_detect_work);
	INIT_DELAYED_WORK(&chg->step_soc_req_work, step_soc_req_work);
/* david.liu@bsp, 20160926 Add dash charging */
	INIT_DELAYED_WORK(&chg->rechk_sw_dsh_work, retrigger_dash_work);
	INIT_DELAYED_WORK(&chg->re_kick_work, op_re_kick_work);
	INIT_DELAYED_WORK(&chg->op_check_apsd_work, op_chek_apsd_done_work);
	INIT_DELAYED_WORK(&chg->recovery_suspend_work,
		op_recovery_usb_suspend_work);
	INIT_DELAYED_WORK(&chg->check_switch_dash_work,
			op_check_allow_switch_dash_work);
	INIT_DELAYED_WORK(&chg->heartbeat_work,
			op_heartbeat_work);
	INIT_DELAYED_WORK(&chg->non_standard_charger_check_work,
		check_non_standard_charger_work);
	INIT_DELAYED_WORK(&chg->re_det_work, smbchg_re_det_work);
	INIT_DELAYED_WORK(&chg->op_re_set_work, op_recovery_set_work);
	schedule_delayed_work(&chg->heartbeat_work,
			msecs_to_jiffies(HEARTBEAT_INTERVAL_MS));
	notify_dash_unplug_register(&notify_unplug_event);
	wake_lock_init(&chg->chg_wake_lock,
			WAKE_LOCK_SUSPEND, "chg_wake_lock");
	g_chg = chg;

	regsister_notify_usb_enumeration_status(&usb_enumeration);
#if defined(CONFIG_FB)
	chg->fb_notif.notifier_call = fb_notifier_callback;

	rc = fb_register_client(&chg->fb_notif);

	if (rc)
		pr_err("Unable to register fb_notifier: %d\n", rc);
#endif /*CONFIG_FB*/
	INIT_DELAYED_WORK(&chg->clear_hdc_work, clear_hdc_work);
	INIT_WORK(&chg->otg_oc_work, smblib_otg_oc_work);
	INIT_WORK(&chg->vconn_oc_work, smblib_vconn_oc_work);
	INIT_DELAYED_WORK(&chg->otg_ss_done_work, smblib_otg_ss_done_work);
	INIT_DELAYED_WORK(&chg->icl_change_work, smblib_icl_change_work);
	INIT_WORK(&chg->legacy_detection_work, smblib_legacy_detection_work);
	chg->fake_capacity = -EINVAL;
	op_set_collapse_fet(chg,false);
	switch (chg->mode) {
	case PARALLEL_MASTER:
		chg->qnovo_fcc_ua = -EINVAL;
		chg->qnovo_fv_uv = -EINVAL;
		rc = smblib_create_votables(chg);
		if (rc < 0) {
			smblib_err(chg, "Couldn't create votables rc=%d\n",
				rc);
			return rc;
		}

		rc = smblib_register_notifier(chg);
		if (rc < 0) {
			smblib_err(chg,
				"Couldn't register notifier rc=%d\n", rc);
			return rc;
		}

		chg->bms_psy = power_supply_get_by_name("bms");
		chg->pl.psy = power_supply_get_by_name("parallel");
		break;
	case PARALLEL_SLAVE:
		break;
	default:
		smblib_err(chg, "Unsupported mode %d\n", chg->mode);
		return -EINVAL;
	}

	return rc;
}

int smblib_deinit(struct smb_charger *chg)
{
	switch (chg->mode) {
	case PARALLEL_MASTER:
/* david.liu@bsp, 20170330 Fix system crash */
		if (chg->nb.notifier_call)
			power_supply_unreg_notifier(&chg->nb);
		smblib_destroy_votables(chg);
		break;
	case PARALLEL_SLAVE:
		break;
	default:
		smblib_err(chg, "Unsupported mode %d\n", chg->mode);
		return -EINVAL;
	}

	smblib_iio_deinit(chg);

/* david.liu@bsp, 20160926 Add dash charging */
	notify_dash_unplug_unregister(&notify_unplug_event);

	return 0;
}
