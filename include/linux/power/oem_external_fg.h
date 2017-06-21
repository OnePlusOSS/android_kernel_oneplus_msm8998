#ifndef	__OEM_EXTERNAL_FG_H__
#define __OEM_EXTERNAL_FG_H__
#include <linux/regmap.h>
#include <linux/input/qpnp-power-on.h>

struct external_battery_gauge {
	int (*get_battery_mvolts) (void);
	int (*get_battery_temperature) (void);
	bool (*is_battery_present) (void);
	bool (*is_battery_temp_within_range) (void);
	bool (*is_battery_id_valid) (void);
	bool (*is_usb_switch_on) (void);
	int (*get_battery_status)(void);
	int (*get_batt_remaining_capacity) (void);
	int (*get_batt_health)(void);
	int (*monitor_for_recharging) (void);
	int (*get_battery_soc) (void);
	int (*get_average_current) (void);
	int (*get_batt_cc) (void);/* yangfangbiao@oneplus.cn, 2015/02/13  Add fcc interface */
	int (*get_batt_fcc) (void);  /* yangfangbiao@oneplus.cn, 2015/01/06  Modify for  sync with KK charge standard  */
	bool (*fast_chg_started) (void);
	bool (*fast_switch_to_normal) (void);
	int (*set_switch_to_noraml_false) (void);
	int (*set_fast_chg_allow) (bool enable);
	bool (*get_fast_chg_allow) (void);
	int (*fast_normal_to_warm)	(void);
	int (*set_normal_to_warm_false)	(void);
	bool (*get_fast_chg_ing)	(void);
	bool (*get_fast_low_temp_full)	(void);
	int (*set_low_temp_full_false)	(void);
	int (*set_allow_reading)(int enable);
	int (*set_lcd_off_status) (int status);
	int (*fast_chg_started_status) (bool status);
	bool (*get_fastchg_firmware_already_updated) (void);
	int (*get_device_type) (void); /* david.liu@bsp, 20161025 Add BQ27411 dash charging */
};

struct notify_dash_event {
	int (*notify_event) (void);
	int (*op_contrl)(int status, bool check_power_ok);
	int (*notify_dash_charger_present) (int true);
};

struct notify_usb_enumeration_status {
	int (*notify_usb_enumeration) (int status);
};

typedef enum {
	BATT_TEMP_COLD = 0,
	BATT_TEMP_LITTLE_COLD,
	BATT_TEMP_COOL,
	BATT_TEMP_LITTLE_COOL,
	BATT_TEMP_PRE_NORMAL,
	BATT_TEMP_NORMAL,
	BATT_TEMP_WARM,
	BATT_TEMP_HOT,
	BATT_TEMP_INVALID,
} temp_region_type;

enum batt_status_type {
	BATT_STATUS_GOOD,
	BATT_STATUS_BAD_TEMP, /* cold or hot */
	BATT_STATUS_BAD,
	BATT_STATUS_REMOVED, /* on v2.2 only */
	BATT_STATUS_INVALID_v1 = BATT_STATUS_REMOVED,
	BATT_STATUS_INVALID
};
void op_pm8998_regmap_register(struct qpnp_pon *pon);

void regsister_notify_usb_enumeration_status(struct notify_usb_enumeration_status *event);
void notify_dash_unplug_register(struct notify_dash_event *event);
void notify_dash_unplug_unregister(struct notify_dash_event *event);
void fastcharge_information_unregister(struct external_battery_gauge *fast_chg);
void fastcharge_information_register(struct external_battery_gauge *fast_chg);
void external_battery_gauge_register(struct external_battery_gauge *batt_gauge);
void external_battery_gauge_unregister(struct external_battery_gauge *batt_gauge);
void bq27541_information_register(struct external_battery_gauge *fast_chg);
void bq27541_information_unregister(struct external_battery_gauge *fast_chg);
bool get_extern_fg_regist_done(void);
bool get_extern_bq_present(void);
int get_prop_pre_shutdown_soc(void);
#endif
