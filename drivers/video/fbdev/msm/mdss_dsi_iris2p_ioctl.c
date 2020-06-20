#include <linux/gcd.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/msm_mdp.h>
#include <linux/mutex.h>
#include <asm/uaccess.h>
#include "mdss_debug.h"
#include "mdss_dsi_iris2p.h"
#include "mdss_panel.h"
#include "mdss_i2c_iris.h"
#include "mdss_dsi_iris2p_def.h"
#include "mdss_dsi_iris2p_extern.h"
#include "mdss_dsi_iris2p_ioctl.h"
#include "mdss_dsi_iris2p_mode_switch.h"

static struct completion iris_vsync_comp;
static struct demo_win_info iris_demo_win_info;
static uint16_t ratio[LEVEL_MAX] = { 8, 6, 5, 4, 4 };
static uint16_t ratio_720[LEVEL_MAX] = { 8, 6, 5, 4, 3};
static uint16_t ratio_16to10_level[LEVEL_MAX][2] = {
	{1212, 758},
	{1152, 720},
	{1024, 640},
	{640, 400},
	{480, 300}
};

static uint16_t ratio_16to9_level[LEVEL_MAX][2] = {
	{1280, 720},
	{1280, 720},
	{1024, 576},
	{640, 360},
	{480, 270}
};

static uint16_t ratio_4to3_level[LEVEL_MAX][2] = {
	{1098, 824},
	{1024, 768},
	{800, 600},
	{640, 480},
	{480, 360}
};

static void mdss_iris_vsync_handler(struct mdss_mdp_ctl *ctl, ktime_t vtime)
{
	printk("#### %s:%d vtime=%lld\n", __func__, __LINE__, vtime.tv64);
	complete(&iris_vsync_comp);
}

static struct mdss_mdp_vsync_handler iris_vsync_handler = {
	.vsync_handler = mdss_iris_vsync_handler,
};

int iris_wait_for_vsync(struct mdss_mdp_ctl *ctl)
{
	int rc;

	printk("#### %s:%d\n", __func__, __LINE__);
	init_completion(&iris_vsync_comp);
	ctl->ops.add_vsync_handler(ctl, &iris_vsync_handler);
	rc = wait_for_completion_interruptible_timeout(
		&iris_vsync_comp, msecs_to_jiffies(100));
	ctl->ops.remove_vsync_handler(ctl, &iris_vsync_handler);
	if (rc < 0)
		printk("#### %s:%d: error %d\n", __func__, __LINE__, rc);
	else if (rc == 0) {
		printk("#### %s:%d: timeout\n", __func__, __LINE__);
		rc = -ETIMEDOUT;
	}
	return rc;
}


int iris_dynamic_fps_set(struct mdss_panel_data *pdata, int curr_fps, int new_fps)
{
	int ret = -1;
	int add_v_lines = 0;
	int vsync_period, hsync_period;
	int diff;
	struct mdss_dsi_ctrl_pdata *ctrl = g_dsi_ctrl;
	struct dsi_panel_cmds panel_cmds;

	static char iris_dtg_dfps_cmds[] = {
		PWIL_TAG('P', 'W', 'I', 'L'),
		PWIL_TAG('G', 'R', 'C', 'P'),
		PWIL_U32(0x00000005),	//valid word number
		0x00,									//burst mode
		0x00,									//reserved
		PWIL_U16(0x0004),				//burst length
		PWIL_U32(IRIS_DTG_ADDR + 0x14),
		PWIL_U32(0x000000),
		PWIL_U32(IRIS_DTG_ADDR + 0x10000),
		PWIL_U32(0x10000),
	};

	static struct dsi_cmd_desc dtg_dfps_config[] = {
		{ { DTYPE_GEN_LWRITE, 1, 0, 0, 0,
			sizeof(iris_dtg_dfps_cmds) }, iris_dtg_dfps_cmds},
	};

	vsync_period = iris_info.output_timing.vbp + iris_info.output_timing.vfp + iris_info.output_timing.vsw + iris_info.output_timing.vres;
	hsync_period = iris_info.output_timing.hbp + iris_info.output_timing.hfp + iris_info.output_timing.hsw + iris_info.output_timing.hres;

	pr_info("#######%s, %d. vbp = %d, vfp = %d, vsw = %d, vsync_period = %d.\n", __func__, __LINE__,
		iris_info.output_timing.vbp, iris_info.output_timing.vfp, iris_info.output_timing.vsw, vsync_period);

	diff = curr_fps - new_fps;

	add_v_lines = mult_frac(vsync_period, diff, new_fps);
	iris_info.output_timing.vfp += add_v_lines;

	pr_info("#######%s, %d. diff = %d, add_v_lines = %d, v_front_porch = %d, vsync_period = %d.\n", __func__, __LINE__,
		diff, add_v_lines, iris_info.output_timing.vfp, vsync_period);

	iris_dtg_dfps_cmds[20] = (__u8)(iris_info.output_timing.vfp & 0xff);
	iris_dtg_dfps_cmds[21] = (__u8)((iris_info.output_timing.vfp >> 8) & 0xff);

	panel_cmds.cmds = dtg_dfps_config;
	panel_cmds.cmd_cnt = ARRAY_SIZE(dtg_dfps_config);
	panel_cmds.link_state = DSI_HS_MODE;
	mdss_dsi_panel_cmds_send_ex(ctrl, &panel_cmds);

	return ret;
}


static int irisDsiStsGet(struct mdss_dsi_ctrl_pdata *ctrl)
{
	//8094_TODO;
	return IRIS_CONFIGURE_GET_VALUE_CORRECT;
}

u32 iris_lp_memc_calc(u32 value)
{
#if defined(CONFIG_IRIS2P_DRC_SUPPORT)
	struct iris_config *iris_cfg = &g_mfd->iris_conf;
#endif
	uint32_t hres, vres;
	uint32_t frc_timing = (uint32_t)lp_memc_timing[1] << 16 | (uint32_t)lp_memc_timing[0];
	static enum res_ratio ratio_type;

	hres = iris_info.work_mode.rx_ch ? (uint32_t)iris_info.input_timing.hres * 2 : (uint32_t)iris_info.input_timing.hres;
	vres = (uint32_t)iris_info.input_timing.vres;

	if (value >= LEVEL_MAX)
	{
		value = LEVEL_MAX - 1;
		pr_err("#### %s:%d, Low Power MEMC level is out of range.\n", __func__, __LINE__);
	}

	pr_debug("#### %s:%d, Low Power MEMC level hres = %d, vres = %d, rx_ch = %d.\n", __func__, __LINE__,
						hres, vres, iris_info.work_mode.rx_ch);

	if(((hres / 4)  == (vres / 3)) || ((hres / 3)  == (vres / 4)))
	{
		ratio_type = ratio_4to3;
	}
	else if(((hres / 16)  == (vres / 10)) || ((hres / 10)  == (vres / 16)))
	{
		ratio_type = ratio_16to10;
	}
	else
	{
		ratio_type = ratio_16to9;
	}

	if ((hres * vres) >= ((uint32_t) IMG1080P_HSIZE * (uint32_t) IMG1080P_VSIZE))
	{
		switch (ratio_type) {
			case ratio_4to3:
				lp_memc_timing[0] = ratio_4to3_level[value][hres > vres ? 0 : 1];
				lp_memc_timing[1] = ratio_4to3_level[value][hres > vres ? 1 : 0];
				if (hres*10 / (uint32_t)lp_memc_timing[0] > 40)
				{
					lp_memc_timing[0] = ratio_4to3_level[value-1][hres > vres ? 0 : 1];
					lp_memc_timing[1] = ratio_4to3_level[value-1][hres > vres ? 1 : 0];
				}
				break;
			case ratio_16to10:
				lp_memc_timing[0] = ratio_16to10_level[value][hres > vres ? 0 : 1];
				lp_memc_timing[1] = ratio_16to10_level[value][hres > vres ? 1 : 0];
				if (hres*10 / (uint32_t)lp_memc_timing[0] > 40) {
					lp_memc_timing[0] = ratio_16to10_level[value-1][hres > vres ? 0 : 1];
					lp_memc_timing[1] = ratio_16to10_level[value-1][hres > vres ? 1 : 0];
				}
				break;
			case ratio_16to9:
				lp_memc_timing[0] = ratio_16to9_level[value][hres > vres ? 0 : 1];
				lp_memc_timing[1] = ratio_16to9_level[value][hres > vres ? 1 : 0];
				if (hres*10 / (uint32_t)lp_memc_timing[0] > 40) {
					lp_memc_timing[0] = ratio_16to9_level[value-1][hres > vres ? 0 : 1];
					lp_memc_timing[1] = ratio_16to9_level[value-1][hres > vres ? 1 : 0];
				}
				break;
			default:
				break;
		};
	} else if ((hres * vres) > ((uint32_t) IMG720P_HSIZE * (uint32_t) IMG720P_VSIZE)) {
		lp_memc_timing[0] = hres * ratio_720[value] / RATIO_NUM;
		lp_memc_timing[1] = vres * ratio_720[value] / RATIO_NUM;
	} else {
		lp_memc_timing[0] = hres * ratio[value] / RATIO_NUM;
		lp_memc_timing[1] = vres * ratio[value] / RATIO_NUM;
	}

	frc_timing = (uint32_t)lp_memc_timing[1] << 16 | (uint32_t)lp_memc_timing[0];

#if defined(CONFIG_IRIS2P_DRC_SUPPORT)
	iris_cfg->lp_frc_timing = frc_timing;
#endif
	pr_debug("#### %s:%d,wHres: %d, wVres: %d, low power memc timing: 0x%x\n", __func__, __LINE__, lp_memc_timing[0], lp_memc_timing[1], frc_timing);

	return frc_timing;
}

static int iris_configure(struct msm_fb_data_type *mfd, u32 type, u32 value)
{
	struct iris_config *iris_cfg = &mfd->iris_conf;
	struct quality_setting * pqlt_cur_setting = & iris_info.setting_info.quality_cur;
	u32 configAddr = 0;
	u32 configValue = 0;

	pr_debug("iris_configure: %d - 0x%x\n", type, value);

	if (type >= IRIS_CONFIG_TYPE_MAX)
		return -EINVAL;

	mutex_lock(&iris_cfg->config_mutex);
	switch (type) {
	case IRIS_PEAKING:
		pqlt_cur_setting->pq_setting.peaking = value & 0xf;
		pqlt_cur_setting->pq_setting.update = 1;
		iris_info.update.pq_setting = true;
		break;
	case IRIS_SHARPNESS:
		pqlt_cur_setting->pq_setting.sharpness = value & 0xf;
		pqlt_cur_setting->pq_setting.update = 1;
		iris_info.update.pq_setting = true;
		break;
	case IRIS_MEMC_DEMO:
		pqlt_cur_setting->pq_setting.memcdemo = value & 0xf;
		pqlt_cur_setting->pq_setting.update = 1;
		iris_info.update.pq_setting = true;
		break;
	case IRIS_PEAKING_DEMO:
		pqlt_cur_setting->pq_setting.peakingdemo = value & 0xf;
		pqlt_cur_setting->pq_setting.update = 1;
		iris_info.update.pq_setting = true;
		break;
	case IRIS_GAMMA:
		pqlt_cur_setting->pq_setting.gamma = value & 0x3;
		pqlt_cur_setting->pq_setting.update = 1;
		iris_info.update.pq_setting = true;
		break;
	case IRIS_MEMC_LEVEL:
		pqlt_cur_setting->pq_setting.memclevel = value & 0x3;
		pqlt_cur_setting->pq_setting.update = 1;
		iris_info.update.pq_setting = true;
		break;
	case IRIS_CONTRAST:
		pqlt_cur_setting->pq_setting.contrast = value & 0xff;
		pqlt_cur_setting->pq_setting.update = 1;
		iris_info.update.pq_setting = true;
		break;
	case IRIS_BRIGHTNESS:
		pqlt_cur_setting->dbc_setting.brightness = value & 0x7f;
		pqlt_cur_setting->dbc_setting.update = 1;
		iris_info.update.dbc_setting = true;
		break;
	case IRIS_EXTERNAL_PWM:
		pqlt_cur_setting->dbc_setting.ext_pwm = value & 0x1;
		pqlt_cur_setting->dbc_setting.update = 1;
		iris_info.update.dbc_setting = true;
		break;
	case IRIS_DBC_QUALITY:
		pqlt_cur_setting->dbc_setting.cabcmode = value & 0xf;
		pqlt_cur_setting->dbc_setting.update = 1;
		iris_info.update.dbc_setting = true;
		break;
	case IRIS_DLV_SENSITIVITY:
		pqlt_cur_setting->dbc_setting.dlv_sensitivity = value & 0xfff;
		pqlt_cur_setting->dbc_setting.update = 1;
		iris_info.update.dbc_setting = true;
		break;
	case IRIS_DBC_CONFIG:
		pqlt_cur_setting->dbc_setting = *((struct iris_dbc_setting *)&value);
		pqlt_cur_setting->dbc_setting.update = 1;
		iris_info.update.dbc_setting = true;
		break;
	case IRIS_PQ_CONFIG:
                value |= pqlt_cur_setting->pq_setting.cinema_en << 24;
		pqlt_cur_setting->pq_setting = *((struct iris_pq_setting *)&value);
		pqlt_cur_setting->pq_setting.update = 1;
		iris_info.update.pq_setting = true;
		break;
	case IRIS_LPMEMC_CONFIG:
		pqlt_cur_setting->lp_memc_setting.level = value;
		pqlt_cur_setting->lp_memc_setting.value = iris_lp_memc_calc(value);
		iris_info.update.lp_memc_setting = true;
		break;
	case IRIS_COLOR_ADJUST:
		pqlt_cur_setting->color_adjust = value & 0xff;
		iris_info.update.color_adjust = true;
		break;
	case IRIS_LCE_SETTING:
		pqlt_cur_setting->lce_setting.mode = value & 0xf;
		pqlt_cur_setting->lce_setting.mode1level = (value & 0xf0) >> 4;
		pqlt_cur_setting->lce_setting.mode2level = (value & 0xf00) >> 8;
		pqlt_cur_setting->lce_setting.demomode = (value & 0xf000) >> 12;
		pqlt_cur_setting->lce_setting.update = 1;
		iris_info.update.lce_setting = true;
		break;
	case IRIS_CM_SETTING:
		pqlt_cur_setting->cm_setting.cm6axes = value & 0x07;
		pqlt_cur_setting->cm_setting.cm3d = (value & 0x1f) >> 3;
		pqlt_cur_setting->cm_setting.demomode = (value & 0x700) >> 8;
		pqlt_cur_setting->cm_setting.ftc_en = (value & 0x800) >> 11;
		pqlt_cur_setting->cm_setting.update = 1;
		iris_info.update.cm_setting = true;
		break;
	case IRIS_CINEMA_MODE:
		pqlt_cur_setting->pq_setting.cinema_en = value & 0x1;
		pqlt_cur_setting->pq_setting.update = 1;
		iris_info.update.pq_setting = true;
		break;
	default:
		mutex_unlock(&iris_cfg->config_mutex);
		return -EINVAL;
	}

	//update dbc mode
     if (iris_info.update.dbc_setting) {
		if (pqlt_cur_setting->dbc_setting.cabcmode == 0)
			iris_info.setting_info.dbc_mode &= ~(1 << 1);
		else
			iris_info.setting_info.dbc_mode |= 1 << 1;
		if (pqlt_cur_setting->dbc_setting.dlv_sensitivity == 0)
			iris_info.setting_info.dbc_mode &= ~1;
		else
			iris_info.setting_info.dbc_mode |= 1;
	}

	//TODO this is work around due to fogbug15362 using iris_reg_add to update
	if (1) {
		mutex_unlock(&iris_cfg->config_mutex);
		return 0;
	}

	// FIXME other mode, use meta method
	if (iris_cfg->sf_notify_mode != IRIS_MODE_RFB) {
		mutex_unlock(&iris_cfg->config_mutex);
		return 0;
	}

	// PQ setting, MB3
	if (iris_info.update.pq_setting) {
		configValue = *((u32 *)&pqlt_cur_setting->pq_setting);
		configAddr = IRIS_PQ_SETTING_ADDR;
		iris_info.update.pq_setting = false;
	} else if (iris_info.update.dbc_setting) {
		configValue = *((u32 *)&pqlt_cur_setting->dbc_setting);
		configAddr = IRIS_DBC_SETTING_ADDR;
		iris_info.update.dbc_setting = false;
	} else if (iris_info.update.lp_memc_setting) {
		configValue = pqlt_cur_setting->lp_memc_setting.value | 0x80000000;
		configAddr = IRIS_LPMEMC_SETTING_ADDR;
		iris_info.update.lp_memc_setting = false;
	} else if (iris_info.update.color_adjust) {
		configValue = ( u32 )pqlt_cur_setting->color_adjust | 0x80000000;
		configAddr = IRIS_COLOR_ADJUST_ADDR;
		iris_info.update.color_adjust = false;
	} else if (iris_info.update.lce_setting) {
		configValue = *((u32 *)&pqlt_cur_setting->lce_setting);
		configAddr = IRIS_LCE_SETTING_ADDR;
		iris_info.update.lce_setting = false;
	} else if (iris_info.update.cm_setting) {
		configValue = *((u32 *)&pqlt_cur_setting->cm_setting);
		configAddr = IRIS_CM_SETTING_ADDR;
		iris_info.update.cm_setting = false;
	}

	if (0 == configValue && 0 == configAddr) {
		mutex_unlock(&iris_cfg->config_mutex);
		pr_warn(" no configValue and configAddr specified, possibly wrong type(%d)!\n", type);
		return -EINVAL;
	}

	pr_debug("%s, %d: configAddr = 0x%x, configValue = 0x%x.\n", __func__, __LINE__, configAddr, configValue);

	iris_register_write(mfd, configAddr, configValue);
	mutex_unlock(&iris_cfg->config_mutex);

	return 0;
}



int iris_configure_ex(struct msm_fb_data_type *mfd, u32 type, u32 count, u32 *values)
{
	struct iris_config *iris_cfg = &g_mfd->iris_conf;
	struct demo_win_info *pdemo_win_info;

	int width, height, frcEndx, frcEndy, frcStartx, frcStarty;
	int color = 0, colsize = 0, rowsize = 0, modectrl = 0x3f00, peakingctrl = 0, winstart = 0, winend = 0;
	int displaywidth = (iris_info.work_mode.tx_ch  ?  iris_info.output_timing.hres * 2 : iris_info.output_timing.hres);
	int ret;

	pdemo_win_info = (struct demo_win_info *)values;

	memcpy(&iris_demo_win_info, values, sizeof(struct demo_win_info));
	pr_debug("%s: startx =%x, starty=%x, endx=%x, endy=%x, color=%x, boardwidth=%x, fi_demo_en = %x, peakingdemoEn = %x\n",
			__func__, iris_demo_win_info.startx, iris_demo_win_info.starty, iris_demo_win_info.endx, iris_demo_win_info.endy,
			iris_demo_win_info.color, iris_demo_win_info.borderwidth,
			iris_demo_win_info.fi_demo_en, iris_demo_win_info.sharpness_en);

	iris_info.fi_demo_win_info.startx = iris_demo_win_info.startx;
	iris_info.fi_demo_win_info.starty = iris_demo_win_info.starty;
	iris_info.fi_demo_win_info.endx = iris_demo_win_info.endx;
	iris_info.fi_demo_win_info.endy = iris_demo_win_info.endy;
	iris_info.fi_demo_win_info.borderwidth = iris_demo_win_info.borderwidth;

	iris_info.peaking_demo_win_info.startx = iris_demo_win_info.startx;
	iris_info.peaking_demo_win_info.starty = iris_demo_win_info.starty;
	iris_info.peaking_demo_win_info.endx = iris_demo_win_info.endx;
	iris_info.peaking_demo_win_info.endy = iris_demo_win_info.endy;
	iris_info.peaking_demo_win_info.sharpness_en = iris_demo_win_info.sharpness_en;

	iris_info.cm_demo_win_info.startx = iris_demo_win_info.startx;
	iris_info.cm_demo_win_info.starty = iris_demo_win_info.starty;
	iris_info.cm_demo_win_info.endx = iris_demo_win_info.endx;
	iris_info.cm_demo_win_info.endy = iris_demo_win_info.endy;
	iris_info.cm_demo_win_info.cm_demo_en = iris_demo_win_info.cm_demo_en;

	if (displaywidth < 100 || iris_info.output_timing.vres < 100) {
		pr_err("panel size too small!\n");
		return -EINVAL;
	}
	if (pdemo_win_info->startx >  displaywidth ||
			pdemo_win_info->starty >  iris_info.output_timing.vres) {
		pr_err("user defined window start point over range!\n");
		return -EINVAL;
	}

	if (pdemo_win_info->endx >  displaywidth ||
		pdemo_win_info->endy >  iris_info.output_timing.vres) {
		pr_err("user defined end point over range!\n");
		return -EINVAL;
	}

	if (pdemo_win_info->startx >  pdemo_win_info->endx ||
		pdemo_win_info->starty >  pdemo_win_info->endy) {
		pr_err("user defined start point > end point!\n");
		return -EINVAL;
	}

	pr_debug("iris_cfg->nrv_enable: %d\n", iris_cfg->nrv_enable);
	if (iris_cfg->nrv_enable) {
		width = iris_cfg->meta.nrv.captureRight - iris_cfg->meta.nrv.captureLeft;
		height = iris_cfg->meta.nrv.captureBottom - iris_cfg->meta.nrv.captureTop;
		frcStartx = pdemo_win_info->startx * width/displaywidth;
		frcStarty = pdemo_win_info->starty * height/iris_info.output_timing.vres;
		frcEndx = pdemo_win_info->endx * width/displaywidth;
		frcEndy = pdemo_win_info->endy * height/iris_info.output_timing.vres;
	} else {
		frcStartx = pdemo_win_info->startx * lp_memc_timing[0] / displaywidth;
		frcStarty = pdemo_win_info->starty * lp_memc_timing[1] / iris_info.output_timing.vres;
		frcEndx = pdemo_win_info->endx *  lp_memc_timing[0] / displaywidth;
		frcEndy = pdemo_win_info->endy *  lp_memc_timing[1] / iris_info.output_timing.vres;
	}

	pr_debug("frc mode resolution: %d - %d - %d - %d - %d - %d\n", frcStartx, frcStarty, frcEndx, frcEndy, lp_memc_timing[0], lp_memc_timing[1]);
	if (frcEndy + pdemo_win_info->borderwidth >= lp_memc_timing[1])
		frcEndy = lp_memc_timing[1] - pdemo_win_info->borderwidth;
	winstart = (pdemo_win_info->startx & 0x3fff) + ((pdemo_win_info->starty & 0x3fff) << 16);
	winend =  (pdemo_win_info->endx & 0x3fff) + ((pdemo_win_info->endy & 0x3fff) << 16);

	peakingctrl = 1 | pdemo_win_info->sharpness_en<<1;

	color = pdemo_win_info->color;

	colsize = (frcStartx & 0xfff) | ((frcEndx & 0xfff)<<16);
	rowsize = (frcStarty & 0xfff) | ((frcEndy & 0xfff)<<16);
	pr_debug("%s:BorderWidth =%x\n", __func__, pdemo_win_info->borderwidth);
	modectrl = modectrl | pdemo_win_info->fi_demo_en;
	modectrl = modectrl | 1<<1;
	modectrl = modectrl | ((pdemo_win_info->borderwidth & 0x7)<<4);

	pr_debug("%s: COL_SIZE =%x, MODE_RING=%x, ROW_SIZE=%x, STARTWIN=%x, ENDWIN=%x, MODE_CTRL=%x, PEAKING_CTRL = %x\n",
		__func__, colsize, color, rowsize, winstart, winend, modectrl, peakingctrl);

	if (pdemo_win_info->fi_demo_en) {
		//backup FI setting for demo window, because when setting demo window, the work mode may can't be MEMC mode, so
		//FI setting can't write.
		iris_info.fi_demo_win_info.colsize = colsize;
		iris_info.fi_demo_win_info.color = color;
		iris_info.fi_demo_win_info.rowsize = rowsize;
		iris_info.fi_demo_win_info.modectrl = modectrl;
		iris_info.update.demo_win_fi = true;

		// FIXME set registers
		if ((iris_cfg->sf_notify_mode == IRIS_MODE_FRC) ||
			(iris_cfg->sf_notify_mode == IRIS_MODE_RFB2FRC) ||
			(iris_cfg->sf_notify_mode == IRIS_MODE_FRC_PREPARE)) {
			iris_info.update.demo_win_fi = false;
			iris_reg_add(FI_DEMO_COL_SIZE, colsize);
			iris_reg_add(FI_DEMO_MODE_RING, color);
			iris_reg_add(FI_DEMO_ROW_SIZE, rowsize);
			iris_reg_add(FI_DEMO_MODE_CTRL, modectrl);
			iris_reg_add(FI_SHADOW_UPDATE, 1);
		}
	}
	if (pdemo_win_info->sharpness_en) {
		// FIXME
		if (iris_cfg->sf_notify_mode != IRIS_MODE_RFB) {
			//mutex_lock(&iris_cfg->cmd_mutex);
			iris_reg_add(PEAKING_STARTWIN, winstart);
			iris_reg_add(PEAKING_ENDWIN, winend);
			iris_reg_add(PEAKING_CTRL, peakingctrl);
			iris_reg_add(PEAKING_SHADOW_UPDATE, 1);
			//mutex_unlock(&iris_cfg->cmd_mutex);
		} else {
			ret = iris_register_write(mfd, PEAKING_STARTWIN, winstart);
			if (ret != 0)
				return ret;
			ret = iris_register_write(mfd, PEAKING_ENDWIN, winend);
			if (ret != 0)
				return ret;
			ret = iris_register_write(mfd, PEAKING_CTRL, peakingctrl);
			if (ret != 0)
				return ret;
			ret = iris_register_write(mfd, PEAKING_SHADOW_UPDATE, 1);
			if (ret != 0)
				return ret;
		}
	}
	if (pdemo_win_info->cm_demo_en) {
		// FIXME
		if (iris_cfg->sf_notify_mode != IRIS_MODE_RFB) {
			//mutex_lock(&iris_cfg->cmd_mutex);
			iris_reg_add(CM_STARTWIN, winstart);
			iris_reg_add(CM_ENDWIN, winend);
			iris_reg_add(CM_SHADOW_UPDATE, 1);
			//mutex_unlock(&iris_cfg->cmd_mutex);
		} else {
			ret = iris_register_write(mfd, CM_STARTWIN, winstart);
			if (ret != 0)
				return ret;
			ret = iris_register_write(mfd, CM_ENDWIN, winend);
			if (ret != 0)
				return ret;
			ret = iris_register_write(mfd, CM_SHADOW_UPDATE, 1);
			if (ret != 0)
				return ret;
		}
	}
	return 0;
}

static int iris_configure_get(struct msm_fb_data_type *mfd, u32 type, u32 count, u32 *values)
{
	int ret = 0;

	struct mdss_overlay_private *mdp5_data;
	struct mdss_panel_data *pdata;
	struct mdss_dsi_ctrl_pdata *ctrl;
	struct quality_setting * pqlt_cur_setting = & iris_info.setting_info.quality_cur;

	mdp5_data = mfd_to_mdp5_data(mfd);
	pdata = mdp5_data->ctl->panel_data;
	ctrl = container_of(pdata, struct mdss_dsi_ctrl_pdata, panel_data);

	if ((type >= IRIS_CONFIG_TYPE_MAX) || (mfd->panel_power_state == MDSS_PANEL_POWER_OFF))
		return -EFAULT;

	ret = irisDsiStsGet(ctrl);
	if (ret != IRIS_CONFIGURE_GET_VALUE_CORRECT)
		return ret;

	switch (type) {
	case IRIS_PEAKING:
		*values = pqlt_cur_setting->pq_setting.peaking;
		break;
	case IRIS_SHARPNESS:
		*values = pqlt_cur_setting->pq_setting.sharpness;
		break;
	case IRIS_MEMC_DEMO:
		*values = pqlt_cur_setting->pq_setting.memcdemo;
		break;
	case IRIS_PEAKING_DEMO:
		*values = pqlt_cur_setting->pq_setting.peakingdemo;
		break;
	case IRIS_GAMMA:
		*values = pqlt_cur_setting->pq_setting.gamma;
		break;
	case IRIS_MEMC_LEVEL:
		*values = pqlt_cur_setting->pq_setting.memclevel;
		break;
	case IRIS_CONTRAST:
		*values = pqlt_cur_setting->pq_setting.contrast;
		break;
	case IRIS_BRIGHTNESS:
		*values = pqlt_cur_setting->pq_setting.sharpness;
		break;
	case IRIS_EXTERNAL_PWM:
		*values = pqlt_cur_setting->dbc_setting.ext_pwm;
		break;
	case IRIS_DBC_QUALITY:
		*values = pqlt_cur_setting->dbc_setting.cabcmode;
		break;
	case IRIS_DLV_SENSITIVITY:
		*values = pqlt_cur_setting->dbc_setting.dlv_sensitivity;
		break;
	case IRIS_DBC_CONFIG:
		*values = *((u32 *)&pqlt_cur_setting->dbc_setting);
		break;
	case IRIS_CINEMA_MODE:
		*values = pqlt_cur_setting->pq_setting.cinema_en;
		break;
	case IRIS_LCE_SETTING:
		*values = *((u32 *)&pqlt_cur_setting->lce_setting);
		break;
	case IRIS_CM_SETTING:
		*values = *((u32 *)&pqlt_cur_setting->cm_setting);
		break;
	case IRIS_COLOR_ADJUST:
		*values = pqlt_cur_setting->color_adjust & 0xff;
		break;
	case IRIS_PQ_CONFIG:
		*values = *((u32 *)&pqlt_cur_setting->pq_setting);
		break;
	case IRIS_LPMEMC_CONFIG:
		*values = pqlt_cur_setting->lp_memc_setting.level;
		break;
	case IRIS_USER_DEMO_WND:
		memcpy(values, &iris_demo_win_info, count * sizeof(u32));
		break;
	case  IRIS_CHIP_VERSION:
		*values = IRIS_CHIP_HW_VER;
		break;
	default:
		return -EFAULT;
	}
	return ret;
}


static int iris_set_rotation(struct msm_fb_data_type *mfd, void __user *argp)
{
	int ret;
	bool rotationen;
	uint32_t top_ctrl0 = 0;
	uint32_t value;

	ret = copy_from_user(&value, argp, sizeof(uint32_t));
	if (ret) {
		pr_err("can not copy form user %s\n", __func__);
		return ret;
	}
	rotationen = !!(value);
	pr_debug("rotationen = %d\n", rotationen);

	top_ctrl0 = (rotationen << ROTATION) | (0 << TRUE_CUT_EXT_EN)
				| (0 << INTERVAL_SHIFT_EN) | (1 << PHASE_SHIFT_EN);
	mutex_lock(&mfd->iris_conf.cmd_mutex);
	iris_reg_add(IRIS_MVC_ADDR + IRIS_MVC_TOP_CTRL0_OFF, top_ctrl0);
	iris_reg_add(IRIS_MVC_ADDR + IRIS_MVC_SW_UPDATE_OFF, 1);
	mutex_unlock(&mfd->iris_conf.cmd_mutex);

	return ret;
}

static int iris_tx_dsi_mode_switch(struct msm_fb_data_type *mfd, void __user *argp)
{
	int ret;
	uint32_t dsi_mode;

	ret = copy_from_user(&dsi_mode, argp, sizeof(uint32_t));
	pr_info("%s, new mode = %d\n", __func__, dsi_mode);

	iris_mipitx_intf_switch_state_reset(mfd, dsi_mode, 1);
	return ret;
}

#if defined(CONFIG_IRIS2P_DRC_SUPPORT)
/*****
* DRC Dynamic resolution change
*
******/
static int iris_set_drc_size(struct msm_fb_data_type *mfd, void __user *argp)
{
	int ret;
	uint32_t utemp;
	ret = copy_from_user(&utemp, argp, sizeof(uint32_t));

	mfd->iris_conf.drc_enable = (utemp > 0) ? true : false;
	mfd->iris_conf.drc_size = utemp;

	return ret;
}
#endif

static int dynamic_fps_set(struct msm_fb_data_type *mfd, void __user *argp)
{
	uint32_t dfps, curr_fps;
	int      ret = 0;
	struct mdss_panel_data *pdata;
	struct mdss_overlay_private *mdp5_data = mfd_to_mdp5_data(mfd);

	ret = copy_from_user(&dfps, argp, sizeof(uint32_t));
	if (ret) {
		pr_err("can not copy form user %s\n", __func__);
		return ret;
	}

	pr_debug("%s: FPS is %d\n", __func__, dfps);

	if (!mdp5_data->ctl || !mdss_mdp_ctl_is_power_on(mdp5_data->ctl))
		return 0;

	pdata = dev_get_platdata(&mfd->pdev->dev);
	if (!pdata) {
		pr_err("no panel connected for fb%d\n", mfd->index);
		return ret;
	}

	curr_fps = pdata->panel_info.mipi.frame_rate;
	if (dfps == pdata->panel_info.mipi.frame_rate) {
		pr_debug("%s: FPS is already %d\n", __func__, dfps);
		return ret;
	}
	mutex_lock(&mdp5_data->dfps_lock);
	if (dfps < pdata->panel_info.min_fps) {
		pr_debug("Unsupported FPS. min_fps = %d\n",
				pdata->panel_info.min_fps);
		mutex_unlock(&mdp5_data->dfps_lock);
		return ret;
	} else if (dfps > pdata->panel_info.max_fps) {
		pr_debug("Unsupported FPS. Configuring to max_fps = %d\n",
				pdata->panel_info.max_fps);
		dfps = pdata->panel_info.max_fps;
		pdata->panel_info.new_fps = dfps;
		ret = mdss_mdp_ctl_update_fps(mdp5_data->ctl);
	} else {
		pdata->panel_info.new_fps = dfps;
		ret = mdss_mdp_ctl_update_fps(mdp5_data->ctl);
	}
	if (!ret) {
		pr_debug("%s: configured to '%d' FPS\n", __func__, dfps);
	} else {
		pr_debug("Failed to configure '%d' FPS. rc = %d\n", dfps, ret);
		mutex_unlock(&mdp5_data->dfps_lock);
		return ret;
	}
	pdata->panel_info.new_fps = dfps;
	mutex_unlock(&mdp5_data->dfps_lock);

	ret = iris_dynamic_fps_set(pdata, curr_fps, dfps);

	return ret;
}

static int iris_notify_video_frame_rate(struct msm_fb_data_type *mfd,
				void __user *argp)
{
	uint32_t r;
	int ret = 0;
	uint32_t frame_rate_ms;

	ret = copy_from_user(&frame_rate_ms, argp, sizeof(uint32_t));
	if (ret) {
		pr_err("copy from user error\n");
		return -EINVAL;
	}
	pr_info("frame_rate_ms = %u\n", frame_rate_ms);

	// round to integer for 23976 and 29976
	mfd->iris_conf.input_frame_rate = (frame_rate_ms + 100) / 1000;
	mfd->iris_conf.output_frame_rate = 60;

	// video mode, no need to set fbo/ratio in/out
	if (mfd->panel_info->type == MIPI_VIDEO_PANEL)
		return ret;

	r = gcd(mfd->iris_conf.input_frame_rate, mfd->iris_conf.output_frame_rate);
	mfd->iris_conf.in_ratio = mfd->iris_conf.input_frame_rate / r;
	mfd->iris_conf.out_ratio = mfd->iris_conf.output_frame_rate / r;
	pr_debug("%s, in_ratio = %d, out_ratio = %d\n", __func__, mfd->iris_conf.in_ratio, mfd->iris_conf.out_ratio);

	return ret;
}


static int msmfb_iris_configure_get(struct msm_fb_data_type *mfd,
				uint32_t type, uint32_t count, void __user *argp)
{
	int ret = -1;
	uint32_t *val = NULL;

	val = kmalloc(count * sizeof(uint32_t),
									GFP_KERNEL);
	if (val == NULL) {
		pr_err("could not kmalloc space for func = %s\n", __func__);
		return -ENOSPC;
	}

	ret = iris_configure_get(mfd, type, count, val);
	if (ret) {
		pr_err("get error\n");
		kfree(val);
		return -EPERM;
	}

	ret = copy_to_user(argp,
					val, sizeof(uint32_t) * count);
	if (ret) {
		pr_err("copy to user error\n");
		kfree(val);
		return -EPERM;
	}

	kfree(val);
	return ret;
}


static int mdss_mipi_dsi_command_t(struct mdss_panel_data *pdata, void __user *argp)
{
	struct mdss_dsi_ctrl_pdata *ctrl;
	struct msmfb_mipi_dsi_cmd cmd;
	struct dsi_cmd_desc desc = {
		.payload = NULL,
	};
	struct dsi_cmd_desc *pdesc_muti, *pdesc;
	char read_response_buf[16] = {0};
	struct dcs_cmd_req req = {
		.cmds = &desc,
		.cmds_cnt = 1,
		.flags = CMD_REQ_COMMIT | CMD_REQ_NO_MAX_PKT_SIZE,
		.rlen = 16,
		.rbuf = (char *)&read_response_buf,
		.cb = NULL
	};
	int ret, indx, cmd_len, cmd_cnt;
	char *pcmd_indx;

	ctrl = container_of(pdata, struct mdss_dsi_ctrl_pdata, panel_data);
	pr_debug("%s:%d: mdss_panel_data: %p mdss_dsi_ctrl_pdata: %p\n", __func__, __LINE__, pdata, ctrl);
	ret = copy_from_user(&cmd, argp, sizeof(cmd));
	if (ret)
		return ret;

	pr_debug("#### %s:%d vc=%u d=%02x f=%u l=%u\n", __func__, __LINE__,
	       cmd.vc, cmd.dtype, cmd.flags, cmd.length);
	if (cmd.length) {
		desc.payload = kmalloc(cmd.length, GFP_KERNEL);
		if (!desc.payload)
			return -ENOMEM;
		ret = copy_from_user(desc.payload, cmd.payload, cmd.length);
		if (ret)
			goto err;
	}

	desc.dchdr.dtype = cmd.dtype;
	desc.dchdr.vc = cmd.vc;
	desc.dchdr.last = !!(cmd.flags & MSMFB_MIPI_DSI_COMMAND_LAST);
	desc.dchdr.ack = !!(cmd.flags & MSMFB_MIPI_DSI_COMMAND_ACK);
	desc.dchdr.dlen = cmd.length;
	desc.dchdr.wait = 0;
	if (cmd.dtype == 0x0f) {
		cmd_cnt = *desc.payload;
		pdesc_muti = kmalloc(sizeof(struct dsi_cmd_desc) * cmd_cnt, GFP_KERNEL);
		pcmd_indx = desc.payload + cmd_cnt + 1;
		for (indx = 0; indx < cmd_cnt; indx++) {
			pdesc = pdesc_muti + indx;
			cmd_len = *(desc.payload + 1 + indx);
			pdesc->dchdr.dtype = *pcmd_indx;
			pdesc->dchdr.vc = 0;
			pdesc->dchdr.last = 0;
			pdesc->dchdr.ack = 0;
			pdesc->dchdr.dlen = cmd_len - 1;
			pdesc->dchdr.wait = 0;
			pdesc->payload = pcmd_indx + 1;

			pcmd_indx += cmd_len;
			if (indx == (cmd_cnt - 1))
				pdesc->dchdr.last = 1;
			printk("dtype:%x, dlen: %d, last: %d\n", pdesc->dchdr.dtype, pdesc->dchdr.dlen, pdesc->dchdr.last);
		}
		req.cmds = pdesc_muti;
		req.cmds_cnt = cmd_cnt;
		req.flags = CMD_REQ_COMMIT;
	}

	if (cmd.flags & MSMFB_MIPI_DSI_COMMAND_ACK) {
		req.flags = req.flags | CMD_REQ_RX;
	}

	// This is debug for switch from BFRC Mode directly to PSR Mode
	if (cmd.flags & MSMFB_MIPI_DSI_COMMAND_DEBUG) {
		struct mdss_data_type *mdata = mdss_mdp_get_mdata();
		static char iris_psr_update_cmd[2] = { 0x1, 0x2 };
		struct dsi_cmd_desc iris_psr_update = {
			{ DTYPE_GEN_WRITE2, 1, 0, 0, 0,
			  sizeof(iris_psr_update_cmd) }, iris_psr_update_cmd
		};

		iris_wait_for_vsync(mdata->ctl_off);
		mdss_dsi_cmd_hs_mode(1, pdata);
		mdss_dsi_cmds_tx(ctrl, &iris_psr_update, 1, (CMD_REQ_DMA_TPG & CMD_REQ_COMMIT));
		mdss_dsi_cmd_hs_mode(0, pdata);
	}

	if (cmd.flags & MSMFB_MIPI_DSI_COMMAND_BLLP) {
		struct mdss_data_type *mdata = mdss_mdp_get_mdata();
		iris_wait_for_vsync(mdata->ctl_off);
	}

	if (cmd.flags & MSMFB_MIPI_DSI_COMMAND_HS)
		mdss_dsi_cmd_hs_mode(1, pdata);

	mdss_dsi_cmdlist_put(ctrl, &req);

	if (cmd.flags & MSMFB_MIPI_DSI_COMMAND_HS)
		mdss_dsi_cmd_hs_mode(0, pdata);

	if (ctrl->rx_buf.data) {
		memcpy(cmd.response, ctrl->rx_buf.data, sizeof(cmd.response));
	}
	ret = copy_to_user(argp, &cmd, sizeof(cmd));
err:
	kfree(desc.payload);
	if (cmd.dtype == 0x0f)
		kfree(pdesc_muti);
	return ret;
}


static int mdss_mipi_dsi_command(struct msm_fb_data_type *mfd, void __user *argp)
{
	struct mdss_overlay_private *mdp5_data = NULL;

	mdp5_data = mfd_to_mdp5_data(mfd);
	if (!mdp5_data) {
		pr_err("mdp5 data is null\n");
		return -EINVAL;
	}

	return mdss_mipi_dsi_command_t(mdp5_data->ctl->panel_data, argp);
}


static void dump_iris_i2c_oprt(struct msmfd_iris_i2c_cmd *i2c_cmd_ptr)
{
	int i = 0;
	for (i = 0; i < i2c_cmd_ptr->addr_comp_len; i++) {
		switch (i2c_cmd_ptr->type) {
		case MSMFB_IRIS_I2C_READ:
			pr_debug("[addr = %08x]\n", i2c_cmd_ptr->addr_comp[i].addr);
			break;
		case MSMFB_IRIS_I2C_WRITE:
			pr_debug("[addr = %08x, val = %08x]\n" ,
					i2c_cmd_ptr->addr_comp[i].addr, i2c_cmd_ptr->addr_comp[i].data);
			break;
		}
	}
}

static int iris_i2c_oprt(struct msm_fb_data_type *mfd, void __user *argp)
{
	int ret = -1;
	int len = 0;
	int ret_val = -1;
	int i = 0;
	struct msmfd_iris_i2c_cmd i2c_cmd;
	struct msmfd_iris_i2c_cmd *i2c_cmd_ptr = (struct msmfd_iris_i2c_cmd *)argp;

	if (mfd && mfd->panel_power_state == MDSS_PANEL_POWER_OFF) {
		pr_err("panel is power off\n");
		return 0;
	}

	memset(&i2c_cmd, 0x00, sizeof(i2c_cmd));
	ret_val = copy_from_user(&i2c_cmd, argp, sizeof(i2c_cmd));
	if (ret_val) {
		pr_err("could not copy from user %d\n", ret_val);
		return ret_val;
	}

	len = i2c_cmd.addr_comp_len;
	if (len == 0) {
		pr_err("no addr is setting\n");
		return -EACCES;
	}

	//dump_iris_i2c_oprt(&i2c_cmd);

	mutex_lock(&mfd->iris_conf.cmd_mutex);
	switch (i2c_cmd.type) {
	case MSMFB_IRIS_I2C_READ:
		ret = iris_i2c_read(i2c_cmd.addr_comp, i2c_cmd.addr_comp_len);
		if (ret) {
			pr_err("the read addr is failed %d\n", ret);
			dump_iris_i2c_oprt(&i2c_cmd);
		}
		break;
	case MSMFB_IRIS_I2C_WRITE:
		ret = iris_i2c_write(i2c_cmd.addr_comp, i2c_cmd.addr_comp_len);
		if (ret) {
			pr_err("the write addr is failed %d\n", ret);
			dump_iris_i2c_oprt(&i2c_cmd);
		}
		break;
	}
	mutex_unlock(&mfd->iris_conf.cmd_mutex);

	if (ret == 0 && i2c_cmd.type == MSMFB_IRIS_I2C_READ) {
		for (i = 0; i < i2c_cmd.addr_comp_len; i++) {
			ret = copy_to_user(&i2c_cmd_ptr->addr_comp[i].data,
					&i2c_cmd.addr_comp[i].data, sizeof(i2c_cmd.addr_comp[i].data));
			if (ret) {
				pr_err("could not copy to user %d\n", ret);
				return ret;
			}
		}
	}
	return ret_val;
}


static int iris_configure_ex_t(struct msm_fb_data_type *mfd, uint32_t type,
								uint32_t count, void __user *values)
{
	int ret = -1;
	uint32_t *val = NULL;

	val = kmalloc(sizeof(uint32_t) * count, GFP_KERNEL);
	if (!val) {
		pr_err("can not kmalloc space\n");
		return -ENOSPC;
	}
	ret = copy_from_user(val, values, sizeof(uint32_t) * count);
	if (ret) {
		kfree(val);
		return ret;
	}

	ret = iris_configure_ex(mfd, type, count, val);

	kfree(val);
	return ret;
}

static int iris_set_dport_writeback_skip(struct msm_fb_data_type *mfd,
																void __user *argp)
{
	int ret;
	int skipCnt;
	ATRACE_BEGIN(__func__);
	ret = copy_from_user(&skipCnt, argp, sizeof(bool));
	mutex_lock(&mfd->iris_conf.cmd_mutex);
	iris_reg_add(IRIS_PWIL_ADDR + 0x134c, 0);
	mutex_unlock(&mfd->iris_conf.cmd_mutex);
	pr_debug("disable iris Dport write back!n");
	ATRACE_END(__func__);

	return ret;
}

static int iris_configure_t(struct msm_fb_data_type *mfd, u32 type, void __user *argp)
{
	int ret = -1;
	uint32_t value = 0;
	ret = copy_from_user(&value, argp, sizeof(uint32_t));
	if (ret)
		return ret;
	ret = iris_configure(mfd, type, value);
	return ret;
}


int msmfb_iris_operate_conf(struct msm_fb_data_type *mfd,
				void __user *argp)
{
	int ret = -1;
	uint32_t parent_type = 0;
	uint32_t child_type = 0;
	struct msmfb_iris_operate_value configure;

	ret = copy_from_user(&configure, argp, sizeof(configure));
	if (ret)
		return ret;

	pr_debug("%s type = %d, value = %d\n",
				__func__, configure.type, configure.count);

	child_type = (configure.type >> 8) & 0xff;
	parent_type = configure.type & 0xff;

	switch (parent_type) {
	case IRIS_OPRT_ROTATION_SET:
		ret = iris_set_rotation(mfd, configure.values);
		break;
	case IRIS_OPRT_VIDEO_FRAME_RATE_SET:
		ret = iris_notify_video_frame_rate(mfd, configure.values);
		break;
	case IRIS_OPRT_CONFIGURE:
		ret = iris_configure_t(mfd, child_type, configure.values);
		break;
	case IRIS_OPRT_CONFIGURE_NEW:
		ret = iris_configure_ex_t(mfd, child_type,
					configure.count, configure.values);
		break;
	case IRIS_OPRT_CONFIGURE_NEW_GET:
		ret = msmfb_iris_configure_get(mfd, child_type,
						configure.count, configure.values);
		break;
	case IRIS_OPRT_DPORT_WRITEBACK_SKIP:
		ret = iris_set_dport_writeback_skip(mfd, configure.values);
		break;
	case IRIS_OPRT_MIPITX_MODESWITCH:
		ret = iris_tx_dsi_mode_switch(mfd, configure.values);
		break;
#if defined(CONFIG_IRIS2P_DRC_SUPPORT)
	case IRIS_OPRT_GET_FRCTIMING:
		ret = iris_get_frc_timing(mfd, configure.values);
		break;
	case IRIS_OPRT_SET_DRC_SIZE:
		ret = iris_set_drc_size(mfd, configure.values);
		break;
#endif
	case IRIS_OPRT_GET_AVAILABLE_MODE:
		ret = iris_get_available_mode(mfd, ((struct msmfb_iris_operate_value*)argp)->values);
		break;
	default:
		pr_err("could not find right opertat type = %d\n", configure.type);
		break;
	}
	return ret;
}

static int iris_set_mode(struct msm_fb_data_type *mfd, void __user *argp)
{
	int ret;
	uint32_t mode;
	struct iris_config *iris_cfg = &(mfd->iris_conf);

	ret = copy_from_user(&mode, argp, sizeof(uint32_t));

	pr_info("iris_set_mode: new mode = %d, old  mode = %d\n",
		mode, iris_cfg->sf_notify_mode);

	if (mode != iris_cfg->sf_notify_mode)
	{
		iris_cfg->sf_mode_change_start = true;
		iris_cfg->sf_notify_mode = mode;
	}
	return ret;
}

static int iris_get_mode(struct msm_fb_data_type *mfd, void __user *argp)
{
	int ret;
	uint32_t mode;
	struct iris_config *iris_cfg = &(mfd->iris_conf);

	mode = iris_cfg->sf_notify_mode;
	pr_debug("mode = %d\n", iris_cfg->sf_notify_mode);
	ret = copy_to_user(argp, &mode, sizeof(uint32_t));

	return ret;
}

int iris_operate_mode(struct msm_fb_data_type *mfd, void __user *argp)
{
	int ret = -1;
	struct msmfb_iris_operate_value val;
	ret = copy_from_user(&val, argp, sizeof(val));
	if (ret != 0) {
		pr_err("can not copy from user\n");
		return -EPERM;
	}

	if (val.type == IRIS_OPRT_MODE_SET) {
		ret = iris_set_mode(mfd, val.values);
	} else {
		ret = iris_get_mode(mfd, val.values);
	}
	return ret;
}

int iris_set_meta(struct msm_fb_data_type *mfd, void __user *argp)
{
	int ret;
	struct iris_config *iris_cfg = &mfd->iris_conf;
	struct iris_meta user_meta;

	ret = copy_from_user((void *)&user_meta, argp, sizeof(struct iris_meta));
	if (ret == 0) {
		mutex_lock(&iris_cfg->meta_mutex);
		iris_cfg->meta_set.op |= user_meta.op;
		if (user_meta.op & MDP_IRIS_OP_NEW_FRAME)
			iris_cfg->meta_set.new_frame = user_meta.new_frame;
		if (user_meta.op & MDP_IRIS_OP_RESTART)
			iris_cfg->meta_set.restart = user_meta.restart;
		if (user_meta.op & MDP_IRIS_OP_VTS)
			iris_cfg->meta_set.video_ts = user_meta.video_ts;
		if (user_meta.op & MDP_IRIS_OP_STS)
			iris_cfg->meta_set.sys_ts = user_meta.sys_ts;
		if (user_meta.op & MDP_IRIS_OP_VID)
			iris_cfg->meta_set.vid = user_meta.vid;
		if (user_meta.op & MDP_IRIS_OP_TE)
			iris_cfg->meta_set.te_period = user_meta.te_period;
		if (user_meta.op & MDP_IRIS_OP_CP) {
			iris_cfg->meta_set.content_period = user_meta.content_period;
			iris_cfg->meta_set.content_period_frac = user_meta.content_period_frac;
		}
		if (user_meta.op & MDP_IRIS_OP_MOTION)
			iris_cfg->meta_set.motion = user_meta.motion;
		if (user_meta.op & MDP_IRIS_OP_JITTER)
			iris_cfg->meta_set.jitter = user_meta.jitter;
		if (user_meta.op & MDP_IRIS_OP_NRV)
			iris_cfg->meta_set.nrv = user_meta.nrv;
		if (user_meta.op & MDP_IRIS_OP_FLG)
			iris_cfg->meta_set.flags = user_meta.flags;
		if (user_meta.op & MDP_IRIS_OP_RPT)
			iris_cfg->meta_set.repeat = user_meta.repeat;
		if (user_meta.op & MDP_IRIS_OP_IF1)
			iris_cfg->meta_set.iris_info1 = user_meta.iris_info1;
		if (user_meta.op & MDP_IRIS_OP_IF2)
			iris_cfg->meta_set.iris_info2 = user_meta.iris_info2;
		mutex_unlock(&iris_cfg->meta_mutex);
	}

	pr_debug("op [%08x] vTimestamp [%u] sTimestamp [%u] flag [%u]\n",
		iris_cfg->meta_set.op, iris_cfg->meta_set.video_ts, iris_cfg->meta_set.sys_ts, iris_cfg->meta_set.flags);

	if (iris_cfg->meta_set.op & MDP_IRIS_OP_RPT)
		pr_debug("repeat: %d\n", iris_cfg->meta_set.repeat);
	if (iris_cfg->meta_set.op & MDP_IRIS_OP_NRV) {
		struct iris_nrv_meta *nrv_meta = &iris_cfg->meta_set.nrv;
		pr_debug("NRV enable [%u]\n", nrv_meta->nrvEnable);
		pr_debug("Capture [%u][%u] [%u][%u]\n", nrv_meta->captureLeft, nrv_meta->captureRight,
											 nrv_meta->captureTop, nrv_meta->captureBottom);
		pr_debug("Display [%u][%u] [%u][%u]\n", nrv_meta->displayLeft, nrv_meta->displayRight,
											 nrv_meta->displayTop, nrv_meta->displayBottom);
	}
	 return ret;
}


int msmfb_iris_operate_tool(struct msm_fb_data_type *mfd,
				void __user *argp)
{
	int ret = -1;
	uint32_t parent_type = 0;
	struct msmfb_iris_operate_value configure;

	ret = copy_from_user(&configure, argp, sizeof(configure));
	if (ret)
		return ret;

	pr_debug("%s type = %d, value = %d\n",
			__func__, configure.type, configure.count);

	parent_type = configure.type & 0xff;
	switch (parent_type) {
	case IRIS_OPRT_TOOL_I2C:
		ret = iris_i2c_oprt(mfd, configure.values);
		break;
	case IRIS_OPRT_TOOL_DSI:
		ret = mdss_mipi_dsi_command(mfd, configure.values);
		break;
	case IRIS_OPRT_DYNAMIC_FPS_SET:
		ret =  dynamic_fps_set(mfd, configure.values);
		break;
	default:
		pr_err("could not find right opertat type = %d\n", configure.type);
		break;
	}
	return ret;
}
