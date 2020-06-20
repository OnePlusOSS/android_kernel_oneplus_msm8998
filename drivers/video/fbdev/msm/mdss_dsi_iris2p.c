/* Copyright (c) 2013, Pixelworks, Inc.
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
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/firmware.h>
#include <linux/debugfs.h>
#include <linux/workqueue.h>
#include <linux/msm_mdp.h>
#include <linux/gpio.h>
#include <linux/circ_buf.h>
#include <linux/gcd.h>
#include <asm/uaccess.h>

#include "mdss_mdp.h"
#include "mdss_fb.h"
#include "mdss_dsi.h"
#include "mdss_dsi_iris2p.h"
#include "mdss_i2c_iris.h"
#include "mdss_debug.h"
#include "mdss_dsi_iris2p_def.h"
#include "mdss_dsi_iris2p_extern.h"
#include "mdss_dsi_iris2p_dbg.h"
//#define DSI_VIDEO_BASE 0xE0000

#define IRIS_REGS 80
#define IRIS_RFB_DATA_PATH_DEFAULT	0x0c840000	// TODO: same as appcode
#define IRIS_PT_DATA_PATH_DEFAULT	0x0c840000	// TODO: same as appcode
#define IRIS_FRC_DATA_PATH_DEFAULT	0x0c840000	// TODO: use_efifo_en = 0

struct iris_reg_t {
	u32 addr;
	u32 val;
};

struct iris_mgmt_t {
	struct work_struct iris_worker;
	struct workqueue_struct *iris_wq;
	void (*iris_handler)(void);
	bool fbo_enable;
	bool sbs_enable;
	struct msm_fb_data_type *mfd;
};



/* Activate Delay 0, FBO Enable: 1, Display Mode: FRC Enable,
* PSR Command: PSR update, Capture Enable: Video
*/
static char fbo_update[2] = {0x15, 0x02};

static char imeta[META_PKT_SIZE] = {
	PWIL_TAG('P', 'W', 'I', 'L'),
	PWIL_TAG('G', 'R', 'C', 'P'),
	PWIL_U32(0x3),
	0x00,
	0x00,
	PWIL_U16(0x2),
};

static struct dsi_cmd_desc iris_meta_pkts[] = {
	{{DTYPE_GEN_LWRITE, 0, 0, 0, 0, sizeof(imeta)}, imeta},
	{{ DTYPE_GEN_WRITE2, 0, 0, 0, 0, sizeof(fbo_update) }, fbo_update },
};

static struct iris_reg_t iris_regs[IRIS_REGS];
static int iris_reg_cnt;

static struct iris_mgmt_t iris_mgmt;


//if it use debug info should open DEBUG, or not DEBUG info
//#define DEBUG


static int iris_set_ratio(struct iris_config *iris_cfg);

static int iris_regs_meta_build(void);

void mdss_dsi_panel_cmds_send_ex(struct mdss_dsi_ctrl_pdata *ctrl,
			struct dsi_panel_cmds *pcmds)
{
	struct dcs_cmd_req cmdreq;
	struct mdss_panel_info *pinfo;

	/*please pay attention to call this funtion, it only used to send write cmd when panel on/off*/
	pinfo = &(ctrl->panel_data.panel_info);
	/* TODO:
		Comment below code for partial update, no impact current system.
		If enable dcs_cmd_by_left, the Iris + panel can't light up.
		Need to debug later.
	*/
	/*
	if (pinfo->dcs_cmd_by_left) {
		if (ctrl->ndx != DSI_CTRL_LEFT)
			return;
	}
	*/

	memset(&cmdreq, 0, sizeof(cmdreq));
	cmdreq.cmds = pcmds->cmds;
	cmdreq.cmds_cnt = pcmds->cmd_cnt;
	cmdreq.flags = CMD_REQ_COMMIT;
	if (pcmds->link_state == DSI_HS_MODE)
		cmdreq.flags |= CMD_REQ_HS_MODE;

	cmdreq.rlen = 0;
	cmdreq.cb = NULL;

	mdss_dsi_cmdlist_put(ctrl, &cmdreq);
}

void iris_update_configure(void)
{
	struct iris_config *iris_cfg = &g_mfd->iris_conf;
	struct quality_setting * pqlt_def_setting = & iris_info.setting_info.quality_def;
	struct quality_setting * pqlt_cur_setting = & iris_info.setting_info.quality_cur;

	pr_debug("iris_update_configure enter\n");

	mutex_lock(&iris_cfg->config_mutex);
	/*pq settings*/
	if (pqlt_def_setting->pq_setting.memcdemo != pqlt_cur_setting->pq_setting.memcdemo) {
		pr_debug("memc demo update\n");
		iris_info.update.pq_setting = true;
	} else if (pqlt_def_setting->pq_setting.peakingdemo != pqlt_cur_setting->pq_setting.peakingdemo) {
		pr_debug("peaking demo update\n");
		iris_info.update.pq_setting = true;
	}else if (pqlt_def_setting->pq_setting.peaking != pqlt_cur_setting->pq_setting.peaking) {
		pr_debug("peaking update cur %i def %i\n", pqlt_cur_setting->pq_setting.peaking, pqlt_def_setting->pq_setting.peaking);
		iris_info.update.pq_setting = true;
	} else if (pqlt_def_setting->pq_setting.sharpness != pqlt_cur_setting->pq_setting.sharpness) {
		pr_debug("sharpness update\n");
		iris_info.update.pq_setting = true;
	} else if (pqlt_def_setting->pq_setting.gamma != pqlt_cur_setting->pq_setting.gamma) {
		pr_debug("gamma level update\n");
		iris_info.update.pq_setting = true;
	} else if (pqlt_def_setting->pq_setting.memclevel != pqlt_cur_setting->pq_setting.memclevel) {
		pr_debug("memc level update\n");
		iris_info.update.pq_setting = true;
	} else if (pqlt_def_setting->pq_setting.contrast != pqlt_cur_setting->pq_setting.contrast) {
		pr_debug("contrast update\n");
		iris_info.update.pq_setting = true;
	} else if (pqlt_def_setting->pq_setting.cinema_en != pqlt_cur_setting->pq_setting.cinema_en) {
		pr_debug("memc cinema update\n");
		iris_info.update.pq_setting = true;
	}

	if (iris_info.update.pq_setting) {
		pqlt_cur_setting->pq_setting.update = 1;

		if (pqlt_cur_setting->pq_setting.memcdemo == 5) {
			//user define level
			iris_info.update.demo_win_fi = true; //first panel on, enter MEMC setting
			pr_debug("iris: first time configure user demo window for MEMC setting ---\n");
		}

		if (pqlt_cur_setting->pq_setting.peakingdemo == 5) {
			//user define level
			iris_reg_add(PEAKING_STARTWIN, (iris_info.peaking_demo_win_info.startx & 0x3fff) + ((iris_info.peaking_demo_win_info.starty & 0x3fff) << 16));
			iris_reg_add(PEAKING_ENDWIN, (iris_info.peaking_demo_win_info.endx & 0x3fff) + ((iris_info.peaking_demo_win_info.endy & 0x3fff) << 16));
			iris_reg_add(PEAKING_CTRL, 1 | iris_info.peaking_demo_win_info.sharpness_en<<1);
			iris_reg_add(PEAKING_SHADOW_UPDATE, 1);
			pr_debug("iris: first time configure user demo window for peaking setting ---\n");
		}
	}

	/*dbc setting*/
	if (pqlt_def_setting->dbc_setting.brightness != pqlt_cur_setting->dbc_setting.brightness) {
		pr_debug("dbc brightness update\n");
		iris_info.update.dbc_setting = true;
	} else if (pqlt_def_setting->dbc_setting.ext_pwm != pqlt_cur_setting->dbc_setting.ext_pwm) {
		pr_debug("external pwm update\n");
		iris_info.update.dbc_setting = true;
	} else if (pqlt_def_setting->dbc_setting.cabcmode != pqlt_cur_setting->dbc_setting.cabcmode) {
		pr_debug("dbc quality update\n");
		iris_info.update.dbc_setting = true;
	} else if (pqlt_def_setting->dbc_setting.dlv_sensitivity != pqlt_cur_setting->dbc_setting.dlv_sensitivity) {
		pr_debug("dlv update\n");
		iris_info.update.dbc_setting = true;
	}

	if (iris_info.update.dbc_setting) {
		pqlt_cur_setting->dbc_setting.update = 1;
	}

	/*lp memc*/
	if (pqlt_def_setting->lp_memc_setting.value != pqlt_cur_setting->lp_memc_setting.value) {
		pr_debug("lp memc update\n");
		iris_info.update.lp_memc_setting = true;
	} else if (pqlt_def_setting->lp_memc_setting.level != pqlt_cur_setting->lp_memc_setting.level) {
		pr_debug("lp level update\n");
		iris_info.update.lp_memc_setting = true;
	}

	if (iris_info.update.lp_memc_setting) {
		pqlt_cur_setting->lp_memc_setting.update = 1;
	}

	/*color adjust*/
	if(pqlt_def_setting->color_adjust != pqlt_cur_setting->color_adjust) {
		pr_debug("color temperature update\n");
		iris_info.update.color_adjust = true;
	}

	/*lce setting*/
	if (pqlt_def_setting->lce_setting.mode != pqlt_cur_setting->lce_setting.mode) {
		pr_debug("lce mode update\n");
		iris_info.update.lce_setting = true;
	} else if (pqlt_def_setting->lce_setting.mode1level != pqlt_cur_setting->lce_setting.mode1level) {
		pr_debug("lce mode1 level update\n");
		iris_info.update.lce_setting = true;
	} else if (pqlt_def_setting->lce_setting.mode2level != pqlt_cur_setting->lce_setting.mode2level) {
		pr_debug("lce mode2 level update\n");
		iris_info.update.lce_setting = true;
	} else if (pqlt_def_setting->lce_setting.demomode != pqlt_cur_setting->lce_setting.demomode) {
		pr_debug("lce demo mode update\n");
		iris_info.update.lce_setting = true;
	}

	if (iris_info.update.lce_setting) {
		pqlt_cur_setting->lce_setting.update = 1;
	}

	/*cm setting*/
	if (pqlt_def_setting->cm_setting.cm6axes != pqlt_cur_setting->cm_setting.cm6axes) {
		pr_debug("6 axes cm update\n");
		iris_info.update.cm_setting = true;
	} else if (pqlt_def_setting->cm_setting.cm3d != pqlt_cur_setting->cm_setting.cm3d) {
		pr_debug("3d cm update\n");
		iris_info.update.cm_setting = true;
	} else if (pqlt_def_setting->cm_setting.ftc_en != pqlt_cur_setting->cm_setting.ftc_en) {
		pr_debug("ftc enable update\n");
		iris_info.update.cm_setting = true;
	} else if (pqlt_def_setting->cm_setting.demomode != pqlt_cur_setting->cm_setting.demomode) {
		pr_debug("cm demo mode update\n");
		iris_info.update.cm_setting = true;
	}

	if (iris_info.update.cm_setting) {
		pqlt_cur_setting->cm_setting.update = 1;

		if (pqlt_cur_setting->cm_setting.demomode == 5) {
			//user define level
			iris_reg_add(CM_STARTWIN, (iris_info.cm_demo_win_info.startx & 0x0fff) + ((iris_info.cm_demo_win_info.starty & 0x0fff) << 16));
			iris_reg_add(CM_ENDWIN, (iris_info.cm_demo_win_info.endx & 0x0fff) + ((iris_info.cm_demo_win_info.endy & 0x0fff) << 16));
			iris_reg_add(CM_SHADOW_UPDATE, 1);
			pr_debug("iris: first time configure user demo window for cm setting ---\n");
		}
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
	mutex_unlock(&iris_cfg->config_mutex);
}

u32 iris_get_vtotal(struct iris_timing_info *info)
{
	u32 vtotal;

	vtotal = info->vfp + info->vsw + info->vbp + info->vres;

	return vtotal;
}

u32 iris_get_htotal(struct iris_timing_info *info)
{
	u32 htotal;

	htotal = info->hfp + info->hsw + info->hbp + info->hres;

	return htotal;
}

void iris_mcuclk_divider_change(struct mdss_dsi_ctrl_pdata *ctrl, char lowMcu)
{
	int switchenable = 0;
	struct iris_config *iris_cfg = &g_mfd->iris_conf;
	struct quality_setting * pqlt_cur_setting = & iris_info.setting_info.quality_cur;

	mutex_lock(&iris_cfg->cmd_mutex);
	if((pqlt_cur_setting->dbc_setting.dlv_sensitivity == 0x0) &&
		(pqlt_cur_setting->dbc_setting.cabcmode == 0x0))
	{
	   switchenable = 1;
	   pr_info("could switch to lower  mcu clock\n");
	}
	pr_info("Sensitive: %x, dvQu: %x\n",pqlt_cur_setting->dbc_setting.dlv_sensitivity,pqlt_cur_setting->dbc_setting.cabcmode );
	// FIXME: iris2-40p needs rework
	/*
	if(lowMcu && switchenable)
	   iris_reg_add(IRIS_SYS_ADDR+0x218, 0x10901);
	else
	   iris_reg_add(IRIS_SYS_ADDR+0x218, 0x1);
	iris_reg_add(IRIS_SYS_ADDR + 0x10, 1);	//reg_update
	iris_reg_add(IRIS_SYS_ADDR + 0x10, 0);	//reg_update
	*/
	mutex_unlock(&iris_cfg->cmd_mutex);
	pr_info("iris: %s, lowMcu: %d\n",  __func__, lowMcu);
}

static void iris_cmds_tx(struct work_struct *data)
{
	struct iris_mgmt_t *mgmt = container_of(data, struct iris_mgmt_t, iris_worker);
	if (mgmt->iris_handler)
		mgmt->iris_handler();
}

#if !defined(FPGA_PLATFORM)
#if 0
static u32  iris_pi_write(struct mdss_dsi_ctrl_pdata *ctrl, u32 addr, u32 value)
{
	struct dcs_cmd_req cmdreq;
	struct iris_config *iris_cfg = &g_mfd->iris_conf;
		static char pwil_write[24] = {
		PWIL_TAG('P', 'W', 'I', 'L'),
		PWIL_TAG('G', 'R', 'C', 'P'),
		PWIL_U32(0x3),
		0x00,
		0x00,
		PWIL_U16(0x2),
		PWIL_U32(IRIS_PROXY_MB0_ADDR), //default set to proxy MB0
		PWIL_U32(0x00000000)
	};
	static struct dsi_cmd_desc iris_pwil_write_cmd = {
		{ DTYPE_GEN_LWRITE,  1, 0, 0, 0, sizeof(pwil_write) }, pwil_write };

	if (!iris_cfg->ready) {
		pr_err("%s:%u: iris not ready!\n", __func__, __LINE__);
		return -EINVAL;
	}

	pr_debug("%s, addr: 0x%x, value: 0x%x\n", __func__, addr, value);

	pwil_write[16] = addr         & 0xff;
	pwil_write[17] = (addr >>  8) & 0xff;
	pwil_write[18] = (addr >> 16) & 0xff;
	pwil_write[19] = (addr >> 24) & 0xff;
	pwil_write[20] = value          & 0xff;
	pwil_write[21] = (value  >>  8) & 0xff;
	pwil_write[22] = (value  >> 16) & 0xff;
	pwil_write[23] = (value  >> 24) & 0xff;

	cmdreq.cmds = &iris_pwil_write_cmd;
	cmdreq.cmds_cnt = 1;
	cmdreq.flags = CMD_REQ_HS_MODE | CMD_REQ_COMMIT | CMD_CLK_CTRL;
	cmdreq.rlen = 0;
	cmdreq.cb = NULL;
	mdss_dsi_cmdlist_put(ctrl, &cmdreq);
	return 0;
}
#endif

u32 iris_pi_read(struct mdss_dsi_ctrl_pdata *ctrl, u32 addr)
{
	u32 value;

	char pi_address[16] = {
		PWIL_TAG('P', 'W', 'I', 'L'),
		PWIL_TAG('S', 'G', 'L', 'W'),
		PWIL_U32(0x01),	//valid body word(4bytes)
		PWIL_U32(IRIS_PROXY_MB0_ADDR),   // proxy MB0
	};

	struct dsi_cmd_desc pi_read_addr_cmd[] = {
		{ { DTYPE_GEN_LWRITE,  1, 0, 0, 0, sizeof(pi_address) }, pi_address },
	};

	char pi_read[1] = { 0x00 };
	struct dsi_cmd_desc pi_read_cmd = {
		{ DTYPE_GEN_READ1,   1, 0, 1, 0, sizeof(pi_read) }, pi_read
	};

	char read_buf[16]; //total 4*32bit register
	struct dcs_cmd_req cmdreq;

	pi_address[12] = addr         & 0xff;
	pi_address[13] = (addr >>  8) & 0xff;
	pi_address[14] = (addr >> 16) & 0xff;
	pi_address[15] = (addr >> 24) & 0xff;

	cmdreq.cmds = pi_read_addr_cmd;
	cmdreq.cmds_cnt = 1;
	cmdreq.flags = CMD_REQ_HS_MODE | CMD_REQ_COMMIT | CMD_CLK_CTRL;
	cmdreq.rlen = 0;
	cmdreq.cb = NULL;
	mdss_dsi_cmdlist_put(ctrl, &cmdreq);

	cmdreq.cmds = &pi_read_cmd;
	cmdreq.cmds_cnt = 1;
	/* 8094 LP mode read is okay, HS mode read failure */
	cmdreq.flags = CMD_REQ_LP_MODE | CMD_REQ_RX | CMD_REQ_COMMIT | CMD_REQ_NO_MAX_PKT_SIZE;
	cmdreq.rlen = 4;
	cmdreq.rbuf = (char *)read_buf;
	cmdreq.cb = NULL;
	mdss_dsi_cmdlist_put(ctrl, &cmdreq);

	value = ctrl->rx_buf.data[0] | (ctrl->rx_buf.data[1] << 8) |
		(ctrl->rx_buf.data[2] << 16) | (ctrl->rx_buf.data[3] << 24);

	return value;
}
#endif

int iris_register_write(struct msm_fb_data_type *mfd,	u32 addr, u32 value)
{
	struct mdss_overlay_private *mdp5_data;
	struct mdss_panel_data *pdata;
	struct mdss_dsi_ctrl_pdata *ctrl;
	struct iris_config *iris_cfg = &g_mfd->iris_conf;
	static char pwil_write[24] = {
		PWIL_TAG('P', 'W', 'I', 'L'),
		PWIL_TAG('G', 'R', 'C', 'P'),
		PWIL_U32(0x3),
		0x00,
		0x00,
		PWIL_U16(0x2),
		PWIL_U32(IRIS_PROXY_MB0_ADDR), //default set to proxy MB0
		PWIL_U32(0x00000000)
	};

	static struct dsi_cmd_desc iris_pwil_write_cmd = {
		{ DTYPE_GEN_LWRITE,  1, 0, 0, 0, sizeof(pwil_write) }, pwil_write };

	struct dcs_cmd_req cmdreq;

	if (!iris_cfg->ready) {
		pr_err("%s:%u: iris not ready!\n", __func__, __LINE__);
		return -EINVAL;
	}

	if (mfd->panel_power_state == MDSS_PANEL_POWER_OFF)
		return 0;

	mdp5_data = mfd_to_mdp5_data(mfd);
	pdata = mdp5_data->ctl->panel_data;
	ctrl = container_of(pdata, struct mdss_dsi_ctrl_pdata, panel_data);

	pr_debug("%s, addr: 0x%x, value: 0x%x\n", __func__, addr, value);

	pwil_write[16] = addr         & 0xff;
	pwil_write[17] = (addr >>  8) & 0xff;
	pwil_write[18] = (addr >> 16) & 0xff;
	pwil_write[19] = (addr >> 24) & 0xff;
	pwil_write[20] = value          & 0xff;
	pwil_write[21] = (value  >>  8) & 0xff;
	pwil_write[22] = (value  >> 16) & 0xff;
	pwil_write[23] = (value  >> 24) & 0xff;

	cmdreq.cmds = &iris_pwil_write_cmd;
	cmdreq.cmds_cnt = 1;
	cmdreq.flags = CMD_REQ_HS_MODE | CMD_REQ_COMMIT | CMD_CLK_CTRL;
	cmdreq.rlen = 0;
	cmdreq.cb = NULL;

	if (MIPI_VIDEO_MODE == iris_info.work_mode.rx_mode) {
		while ((atomic_read(&mfd->iris_conf.mode_switch_cnt)))
			usleep_range(17000, 17000);
	}

	mdss_dsi_cmdlist_put(ctrl, &cmdreq);

	if (MIPI_VIDEO_MODE == iris_info.work_mode.rx_mode) {
		/* wait 1 vsync to sure command issue */
		usleep_range(17000, 17000);
	}
	return 0;
}

void iris_dtg_para_set(int input_mode, int output_mode)
{
	struct iris_setting_info *psetting = &iris_info.setting_info;
	u32 vtotal = iris_get_vtotal(&iris_info.output_timing);
	u32 htotal = iris_get_htotal(&iris_info.output_timing);
	u32 vfp = iris_info.output_timing.vfp;
	u32 ovs_lock_te_en =0, psr_mask = 0, evs_sel = 0;
	u32 te_en = 0, te_interval = 0, te_sel = 0, sw_te_en = 0, sw_fix_te_en = 0, te_auto_adj_en = 0, te_ext_en = 0, te_ext_filter_en = 0, te_ext_filter_thr = 0;
	u32 cmd_mode_en = 0, cm_hw_rfb_mode = 0, cm_hw_frc_mode = 0;
	u32 dtg_en = 1, ivsa_sel = 1, vfp_adj_en = 1, dframe_ratio = 1, vframe_ratio = 1, lock_sel = 1;
	u32 sw_dvs_period = (vtotal << 8);
	u32 sw_te_scanline = 0, sw_te_scanline_frc = 0, te_ext_dly = 0, te_out_sel = 0, te_out_filter_thr = 0, te_out_filter_en = 0, te_ext_dly_frc = 0;
	u32 te2ovs_dly = 0, te2ovs_dly_frc = 0;
	u32 evs_dly = 6, evs_new_dly = 1;
	u32 vfp_max = 0;
	u32 vfp_extra = psetting->delta_period_max;
	u32 lock_mode = 0;
	u32 vres_mem = 0, psr_rd = 2, frc_rd = 4, scale_down = 2, dsc = 2, margin = 2, scale_up = 2;
	u32 peaking = 2;
	u32 i2o_dly = 0;
	struct iris_config *iris_cfg = &g_mfd->iris_conf;

	//dtg 1.1 mode, video in
	if (MIPI_VIDEO_MODE == input_mode)
	{
		evs_sel = 1;
		psr_mask = 1;
		iris_cfg->dtg_setting.dtg_delay = 3;
		vfp_max = vfp + vfp_extra;
	}
	else if (MIPI_VIDEO_MODE == output_mode)
	{
		if (!iris_debug_dtg_v12) {
			//dtg 1.3 mode, command in and video out
			ovs_lock_te_en = 1;
			cmd_mode_en = 1;
			te_en = 1;
			sw_fix_te_en = 1;
			te_auto_adj_en = 1;
			te2ovs_dly = vfp - 1;
			te2ovs_dly_frc = (vtotal*3)/4;
			iris_cfg->dtg_setting.dtg_delay = 2;
			vfp_max = (te2ovs_dly_frc > vfp) ? te2ovs_dly_frc : vfp;
		} else {
			//dtg 1.2 mode, command in and video out
			cmd_mode_en = 1;
			cm_hw_frc_mode = 3;
			cm_hw_rfb_mode = 3;
			te_en = 1;
			te_sel = 1;
			sw_te_en = 1;
			te_auto_adj_en = 1;
			vres_mem = iris_lp_memc_calc(LEVEL_MAX - 1) >> 16;
			i2o_dly = ((psr_rd > frc_rd? psr_rd: frc_rd) + scale_down + dsc + margin) * iris_info.input_timing.vres +
					scale_up * iris_info.output_timing.vres +
					peaking * vres_mem;
			sw_te_scanline = vtotal * vres_mem - (i2o_dly - iris_info.output_timing.vbp * vres_mem - iris_info.output_timing.vsw * vres_mem);
			sw_te_scanline /= vres_mem;
			sw_te_scanline_frc = (vtotal)/4;
			te_out_filter_thr = (vtotal)/2;
			te_out_filter_en = 1;
			iris_cfg->dtg_setting.dtg_delay = 2;
			vfp_max = vfp + vfp_extra;
		}
	}
	//dtg 1.4 mode, command in and command out
	else if (MIPI_CMD_MODE == output_mode)
	{
		vfp_max = vfp + vfp_extra;
		evs_dly = 2;
		evs_sel = 1;
		ovs_lock_te_en = 1;
		cmd_mode_en = 1;
		te_en = 1;
		te_auto_adj_en = 1;
		te_ext_en = 1;

		te_ext_filter_thr = (((u32)iris_info.output_timing.hres * (u32)iris_info.output_timing.vres * 100)/vtotal/htotal)*vtotal/100;
		te2ovs_dly = 2;
		te2ovs_dly_frc = 2;
		te_ext_dly = 1;
		te_out_sel = 1;
		te_out_filter_thr = (vtotal)/2;
		te_out_filter_en = 1;
		te_ext_dly_frc = (vtotal)/4;
		iris_cfg->dtg_setting.dtg_delay = 1;
		te_ext_filter_en = 1;
		lock_mode = 2;

		te_sel = 1;
		sw_te_en = 1;
		vres_mem = iris_lp_memc_calc(LEVEL_MAX - 1) >> 16;
		i2o_dly = ((psr_rd > frc_rd? psr_rd: frc_rd) + scale_down + dsc + margin) * iris_info.input_timing.vres +
				scale_up * iris_info.output_timing.vres +
				peaking * vres_mem;
		sw_te_scanline = vtotal * vres_mem - (i2o_dly - iris_info.output_timing.vbp * vres_mem - iris_info.output_timing.vsw * vres_mem);
		sw_te_scanline /= vres_mem;
		sw_te_scanline_frc = (vtotal)/4;
		evs_new_dly = (scale_down + dsc + margin) * iris_info.input_timing.vres / vres_mem - te2ovs_dly;
	}

	iris_cfg->dtg_setting.dtg_ctrl = dtg_en + (ivsa_sel << 3) + (dframe_ratio << 4) + (vframe_ratio << 9) + (vfp_adj_en << 17) +
								(ovs_lock_te_en << 18) + (lock_sel << 26) + (evs_sel << 28) + (psr_mask << 30);
	iris_cfg->dtg_setting.dtg_ctrl_1 = (cmd_mode_en) + (lock_mode << 5) + (cm_hw_rfb_mode << 10) + (cm_hw_frc_mode << 12);
	iris_cfg->dtg_setting.evs_dly = evs_dly;
	iris_cfg->dtg_setting.evs_new_dly = evs_new_dly;
	iris_cfg->dtg_setting.te_ctrl = (te_en) + (te_interval << 1) + (te_sel << 2) + (sw_te_en << 3) + (sw_fix_te_en << 5) +
						(te_auto_adj_en << 6) + (te_ext_en << 7) + (te_ext_filter_en << 8) + (te_ext_filter_thr << 9);
	iris_cfg->dtg_setting.dvs_ctrl = sw_dvs_period;
	iris_cfg->dtg_setting.te_ctrl_1 = sw_te_scanline;
	iris_cfg->dtg_setting.te_ctrl_2 = sw_te_scanline_frc;
	iris_cfg->dtg_setting.te_ctrl_3 = te_ext_dly + (te_out_sel << 24);
	iris_cfg->dtg_setting.te_ctrl_4 = te_out_filter_thr + (te_out_filter_en << 24);
	iris_cfg->dtg_setting.te_ctrl_5 = te_ext_dly_frc;
	iris_cfg->dtg_setting.te_dly = te2ovs_dly;
	iris_cfg->dtg_setting.te_dly_1 = te2ovs_dly_frc;
	iris_cfg->dtg_setting.vfp_ctrl_0 = vfp + (1<<24);
	iris_cfg->dtg_setting.vfp_ctrl_1 = vfp_max;
}

int iris_set_configure(struct msm_fb_data_type *mfd)
{
	struct iris_config *iris_cfg = &mfd->iris_conf;
	struct quality_setting * pqlt_cur_setting = &iris_info.setting_info.quality_cur;
	// FIXME
	if (iris_cfg->sf_notify_mode == IRIS_MODE_FRC_PREPARE ||
		iris_cfg->sf_notify_mode == IRIS_MODE_FRC_PREPARE_DONE)
		return 0;

	// no update
	if (!iris_info.update.pq_setting && !iris_info.update.dbc_setting
		&& !iris_info.update.lp_memc_setting && !iris_info.update.color_adjust
		&& !iris_info.update.lce_setting &&!iris_info.update.cm_setting)
		return 0;

	mutex_lock(&iris_cfg->config_mutex);
	// PQ setting, MB3
	if (iris_info.update.pq_setting) {
		iris_reg_add(IRIS_PQ_SETTING_ADDR, *((u32 *)&pqlt_cur_setting->pq_setting));
		pr_info("%s, %d: configValue = %d.\n", __func__, __LINE__, *((u32 *)&pqlt_cur_setting->pq_setting));
		iris_info.update.pq_setting = false;
	}

	// DBC setting, MB5
	if (iris_info.update.dbc_setting) {
		iris_reg_add(IRIS_DBC_SETTING_ADDR, *((u32 *)&pqlt_cur_setting->dbc_setting));
		iris_info.update.dbc_setting = false;
	}

	if (iris_info.update.lp_memc_setting) {
		iris_reg_add(IRIS_LPMEMC_SETTING_ADDR, pqlt_cur_setting->lp_memc_setting.value | 0x80000000);
		iris_info.update.lp_memc_setting = false;
	}

	if (iris_info.update.color_adjust) {
		iris_reg_add(IRIS_COLOR_ADJUST_ADDR, (u32)pqlt_cur_setting->color_adjust | 0x80000000);
		iris_info.update.color_adjust = false;
	}
    //LCE Setting,DSC_ENCODER_ALG_PARM2
	if (iris_info.update.lce_setting) {
		iris_reg_add(IRIS_LCE_SETTING_ADDR, *((u32 *)&pqlt_cur_setting->lce_setting));
		iris_info.update.lce_setting = false;
	}

    // CM Setting,DSC_ENCODER_ALG_PARM6
	if (iris_info.update.cm_setting) {
		iris_reg_add(IRIS_CM_SETTING_ADDR, *((u32 *)&pqlt_cur_setting->cm_setting));
		iris_info.update.cm_setting = false;
	}

	mutex_unlock(&iris_cfg->config_mutex);

	return 0;
}


#if defined(CONFIG_IRIS2P_DRC_SUPPORT)
int iris_Drc_LPMemc_update(struct msm_fb_data_type *mfd)
{

	u32 configAddr = 0;
	u32 configValue = 0;

	configValue = g_mfd->iris_conf.drc_size | 0x80000000;
	configAddr = IRIS_DRC_INFO_ADDR;

	if (0 == configValue && 0 == configAddr) {
		pr_warn("iris_Drc_LPMemc_update failed!\n");
		return -EINVAL;
	}

	return iris_register_write(mfd, configAddr, configValue);

}

int iris_get_frc_timing(struct msm_fb_data_type *mfd, void __user *argp)
{
	int ret = -1;
	pr_debug("frc low power timing = %x\n", mfd->iris_conf.lp_frc_timing);
	ret = copy_to_user(argp, &(mfd->iris_conf.lp_frc_timing), sizeof(uint32_t));
	//TODO
	return ret;
}

void iris_calc_drc_exit(struct msm_fb_data_type *mfd)
{
	u32 configAddr = 0;
	u32 configValue = 0;

#if defined(FPGA_PLATFORM)
	configValue = 0x00840200;
#else
	configValue = iris_pi_read(g_dsi_ctrl, IRIS_DATA_PATH_ADDR);
	configValue = configValue & 0xFFFF7FFF;//clear bit 15
#endif
	iris_register_write(mfd, configAddr, configValue);
	return;
}
#endif

static bool iris_is_cmdin_cmdout(void)
{
	struct iris_work_mode *pwork_mode = &(iris_info.work_mode);

	if ((MIPI_CMD_MODE == pwork_mode->rx_mode) &&
		(MIPI_CMD_MODE  == pwork_mode->tx_mode))
		return true;
	else
		return false;
}

bool iris_is_cmdin_videout(void)
{
	struct iris_work_mode *pwork_mode = &(iris_info.work_mode);

	if ((MIPI_CMD_MODE == pwork_mode->rx_mode) &&
		(MIPI_VIDEO_MODE  == pwork_mode->tx_mode))
		return true;
	else
		return false;
}

static bool iris_is_videoin_videout(void)
{
	struct iris_work_mode *pwork_mode = &(iris_info.work_mode);

	if ((MIPI_VIDEO_MODE == pwork_mode->rx_mode) &&
		(MIPI_VIDEO_MODE  == pwork_mode->tx_mode))
		return true;
	else
		return false;
}

static bool iris_is_scale_enable(void)
{
	if (iris_info.input_timing.hres == iris_info.output_timing.hres  &&
		iris_info.output_timing.vres == iris_info.output_timing.vres)
		return false;
	else
		return true;
}

static bool iris_pt_available(struct msm_fb_data_type *mfd)
{
	struct iris_config *iris_cfg = &mfd->iris_conf;

	if (iris_cfg->ready && !iris_is_scale_enable() &&
	    (iris_is_cmdin_cmdout() || iris_is_videoin_videout()))  {
		iris_cfg->avail_mode.kickoff60_request = false;
		iris_cfg->avail_mode.last_frame_repeat_cnt = 0;
		iris_cfg->avail_mode.pt_available = true;
		return true;
	} else {
		iris_cfg->avail_mode.pt_available = false;
		return false;
	}
}

bool iris_is_dbc_setting_disable(void)
{
	struct iris_setting_info * psetting_info = &iris_info.setting_info;
	struct iris_setting_disable_info *pdisable_info = & psetting_info->disable_info;
	struct iris_dbc_setting * dbc_setting = &psetting_info->quality_cur.dbc_setting;
	if (dbc_setting->dlv_sensitivity == pdisable_info->dbc_dlv_sensitivity_disable_val &&
		dbc_setting->cabcmode == pdisable_info->dbc_quality_disable_val) {
		return true;
	}
	return false;
}


static bool iris_is_pq_setting_disable(void)
{
	struct iris_setting_info * psetting_info = &iris_info.setting_info;
	struct iris_setting_disable_info *pdisable_info = & psetting_info->disable_info;
	struct iris_pq_setting  * pq_setting = &psetting_info->quality_cur.pq_setting;

	/*TODO: add following value
	CM 6-Axis Level
	CM 3D LUT Level
	CM Demo Mode
	CM Flesh Tone EN*/
	if (pq_setting->peaking == pdisable_info->pq_peaking_disable_val &&
		pq_setting->peakingdemo == pdisable_info->pq_peaking_demo_disable_val &&
		pq_setting->gamma == pdisable_info->pq_gamma_disable_val &&
		pq_setting->contrast == pdisable_info->pq_contrast_disable_val ) {
		return true;
	}
	return false;
}

bool iris_is_peaking_setting_disable(void)
{
	struct iris_setting_info * psetting_info = &iris_info.setting_info;
	struct iris_setting_disable_info *pdisable_info = & psetting_info->disable_info;
	struct iris_pq_setting  * pq_setting = &psetting_info->quality_cur.pq_setting;

	return pq_setting->peaking == pdisable_info->pq_peaking_disable_val;
}

bool iris_is_lce_setting_disable(void)
{
	//TODO:
	struct iris_setting_info * psetting_info = &iris_info.setting_info;
	struct iris_setting_disable_info *pdisable_info = & psetting_info->disable_info;
	struct iris_lce_setting * lce_setting = &psetting_info->quality_cur.lce_setting;

	if (lce_setting->mode == pdisable_info->lce_mode_disable_val)
		return true;

	return false;
}

bool iris_is_cm_setting_disable(void)
{
	struct iris_setting_info * psetting_info = &iris_info.setting_info;
	struct iris_setting_disable_info *pdisable_info = & psetting_info->disable_info;
	struct iris_cm_setting * cm_setting = &psetting_info->quality_cur.cm_setting;

	if (pdisable_info->cm_c6axes_disable_val ==  cm_setting->cm6axes &&
		pdisable_info->cm_c3d_disable_val == cm_setting->cm3d)
		return true;

	return false;
}

static bool iris_bypass_available(struct msm_fb_data_type *mfd)
{

	struct iris_config *iris_cfg = &mfd->iris_conf;
	struct iris_setting_info * psetting_info = &iris_info.setting_info;
	struct iris_setting_disable_info *pdisable_info = & psetting_info->disable_info;

	/* setting is close
	*  input_timing equal to output_timing
	*  rx mode equal tx mode
	*/
	if (iris_cfg->ready &&
		iris_is_lce_setting_disable() &&
		iris_is_dbc_setting_disable() &&
		iris_is_pq_setting_disable() &&
		iris_is_cm_setting_disable() &&
		(iris_is_cmdin_cmdout() || iris_is_videoin_videout()) &&
		pdisable_info->color_adjust_disable_val == psetting_info->quality_cur.color_adjust) {
		iris_cfg->avail_mode.bypass_available = true;
		return true;
	} else {
		iris_cfg->avail_mode.bypass_available = false;
		return false;
	}
}

int iris_get_available_mode(struct msm_fb_data_type *mfd, void __user *argp)
{
	int ret = -1;
	struct iris_available_mode dbg_iris_avail_mode;
	struct iris_setting_info * psetting_info = &iris_info.setting_info;
	struct iris_setting_disable_info *pdisable_info = & psetting_info->disable_info;
	struct iris_config *iris_cfg = &mfd->iris_conf;
	struct iris_available_mode * piris_avail_mode = &iris_cfg->avail_mode;

	if (MIPI_VIDEO_MODE == iris_info.work_mode.tx_mode) {
		piris_avail_mode->pt_threshold_low = 0;
		piris_avail_mode->rfb_threshold_low = 0;
	}

	if (iris_pt_available(mfd)) {
		if (iris_is_cmdin_cmdout()) {
			//TODO judge LCE and DBC is open then
			if (!iris_is_lce_setting_disable() || !iris_is_dbc_setting_disable()) {
				piris_avail_mode->last_frame_repeat_cnt = pdisable_info->last_frame_repeat_cnt;
				piris_avail_mode->prefer_mode = IRIS_MODE_RFB;
			}
			else
				piris_avail_mode->prefer_mode = IRIS_MODE_PT;

		} else if (iris_is_cmdin_videout()) {
			piris_avail_mode->kickoff60_request = true;
		}
	}

	if (iris_bypass_available(mfd)) {
		pr_debug("%s bypass is available \n", __func__);
	}

	memcpy(&dbg_iris_avail_mode, &iris_cfg->avail_mode, sizeof(struct iris_available_mode));

	if (iris_debug_pt)
		dbg_iris_avail_mode.pt_available = true;
	if (iris_debug_bypass)
		dbg_iris_avail_mode.bypass_available = true;
	if (iris_debug_kickoff60)
		dbg_iris_avail_mode.kickoff60_request = true;
	if (iris_debug_lastframerepeat)
		dbg_iris_avail_mode.last_frame_repeat_cnt = pdisable_info->last_frame_repeat_cnt;
	if (iris_debug_pt_disable)
		dbg_iris_avail_mode.pt_available = false;

	if (iris_debug_pt || iris_debug_bypass || iris_debug_kickoff60 ||
		iris_debug_lastframerepeat || iris_debug_pt_disable) {
		ret = copy_to_user(argp, &dbg_iris_avail_mode, sizeof(struct iris_available_mode));
	} else {
		pr_debug("pt_avail = %d, bypass_avail = %d kickoff60 = %d  last_frame= %d\n",
			piris_avail_mode->pt_available, piris_avail_mode->bypass_available,
			piris_avail_mode->kickoff60_request, piris_avail_mode->last_frame_repeat_cnt);
		ret = copy_to_user(argp, piris_avail_mode, sizeof(struct iris_available_mode));
	}
	return ret;
}


static inline u32 mdss_mdp_cmd_vsync_count(struct mdss_mdp_ctl *ctl)
{
	struct mdss_mdp_mixer *mixer;
	u32 cnt = 0xffff;	/* init to an invalid value */

	mdss_mdp_clk_ctrl(MDP_BLOCK_POWER_ON);

	mixer = mdss_mdp_mixer_get(ctl, MDSS_MDP_MIXER_MUX_LEFT);
	if (!mixer) {
		mixer = mdss_mdp_mixer_get(ctl, MDSS_MDP_MIXER_MUX_RIGHT);
		if (!mixer) {
			mdss_mdp_clk_ctrl(MDP_BLOCK_POWER_OFF);
			goto exit;
		}
	}
	cnt = (mdss_mdp_pingpong_read(mixer->pingpong_base, MDSS_MDP_REG_PP_INT_COUNT_VAL) >> 16) & 0xffff;

	mdss_mdp_clk_ctrl(MDP_BLOCK_POWER_OFF);

exit:
	return cnt;
}

static void iris_proc_te(struct iris_config *iris_cfg, u32 fcnt, u32 lcnt, u32 fps, u32 vper)
{
	static u32 fcnt0, lcnt0;
	static u64 time0;
	static u32 te_period;
	ktime_t ktime = ktime_get();
	u64 time = ktime_to_us(ktime);

	if (fcnt - fcnt0 >= 1200) {
		if (time - time0) {
			u32 detla_t = time - time0;
			te_period = ((fcnt - fcnt0) * vper + lcnt - lcnt0)*1000/fps/(detla_t/1000);
			pr_debug("te_period=%u\n", te_period);
			if (abs(te_period - vper) > (vper >> 5))
				te_period = vper;
		}
		fcnt0 = fcnt;
		lcnt0 = lcnt;
		time0 = time;
	}

	//if (!te_period)
		te_period = vper;

	iris_cfg->meta.te_period = te_period;
	pr_debug("fcnt %u fcnt0 %u lcnt %u lcnt0 %u fps %u\n", fcnt, fcnt0, lcnt, lcnt0, fps);
	pr_debug("time %llu time0 %llu\n", time, time0);
	pr_debug("te %u vper %u\n", te_period, vper);
}

static int iris_vary_te(struct iris_config *iris_cfg, u32 fcnt, int vper)
{
#define THRESHOLD 0
#define FRAME_CNT 120
#define PLAYING 0x01
#define FIRST_FRAME 0x04
	static u32 fcnt0, vts0, time0, sts0;
	static bool player_sts;
	u32 time = iris_cfg->meta.sys_ts;
	u32 vts = iris_cfg->meta.video_ts;
	int delta_time, delta_period;
	int delta_t, delta_v, delta_sts, ret_val = false;
	ktime_t ktime = ktime_get();
	u32 sts = (u32) ktime_to_us(ktime);

	pr_debug("meta.op=0x%x, meta.flags=0x%x, meta.video_ts=%u, delta_period_range(%d, %d) \n",
		iris_cfg->meta.op, iris_cfg->meta.flags, iris_cfg->meta.video_ts,
		iris_info.setting_info.delta_period_max, iris_info.setting_info.delta_period_min);

	if (!(iris_cfg->meta.op & MDP_IRIS_OP_FLG)) {
		pr_debug("flag invalid\n");
		if (iris_cfg->sw_te_period != vper) {
			iris_cfg->sw_te_period = vper;
			ret_val = true;
		}
		return ret_val;
	}
	iris_cfg->meta.op &= ~MDP_IRIS_OP_FLG;

	if (!(iris_cfg->meta.flags & PLAYING)) {
		if (player_sts)
			pr_debug("play stop\n");
		//if video is stopped, retore TE to 60hz
		player_sts = 0;
		if (iris_cfg->sw_te_period != vper) {
			iris_cfg->sw_te_period = vper;
			ret_val = true;
		}
		return ret_val;
	}

	//get reference frame
	if (iris_cfg->meta.flags & FIRST_FRAME) {
		player_sts = 1;
		vts0 = iris_cfg->meta.video_ts;
		time0 = time;
		fcnt0 = fcnt;
		sts0 = sts;
		pr_debug("get reference frame ats0 %u vts0 %u sts0 %u f0 %u\n", time0, vts0, sts0, fcnt0);
	}

	delta_t = time - time0;
	delta_v = vts - vts0;
	delta_sts = sts - sts0;
	delta_time = delta_v - delta_t;

	if ((fcnt - fcnt0 >= FRAME_CNT) && vts && delta_t && delta_v && player_sts) {
		if (iris_cfg->current_mode != IRIS_FRC_MODE) {
			pr_debug("not in FRC mode\n");
			if (iris_cfg->sw_te_period != vper) {
				iris_cfg->sw_te_period = vper;
				ret_val = true;
			}
		} else if (abs(delta_v - delta_t) > THRESHOLD) {
			u32 sw_te_period_prev = iris_cfg->sw_te_period;
			// line_time = 1000000us / (60 * vper);
			// delta_period = delta_time / line_time;
			delta_period = (delta_time * vper) / 16667;
			delta_period = DIV_ROUND_CLOSEST(delta_period, FRAME_CNT);

			if (delta_period < iris_info.setting_info.delta_period_min) {
				pr_debug("delta_period:%d out of min range\n", delta_period);
				delta_period = iris_info.setting_info.delta_period_min;
			} else if (delta_period > iris_info.setting_info.delta_period_max) {
				pr_debug("delta_period:%d out of max range\n", delta_period);
				delta_period = iris_info.setting_info.delta_period_max;
			}
			iris_cfg->sw_te_period = vper + delta_period;
			ret_val = sw_te_period_prev != iris_cfg->sw_te_period;
		}
		pr_debug("fcnt %u fcnt0 %u vts %u vts0 %u delta_v %u\n", fcnt, fcnt0, vts, vts0, delta_v);
		pr_debug("time %u time0 %u delta_t %u\n", time, time0, delta_t);
		pr_debug("sts %u sts0 %u delta_sts %u\n", sts, sts0, delta_sts);
		pr_debug("delta_time %i delta_period %i vper %u ret_val %u\n", delta_time, delta_period, vper, ret_val);

		fcnt0 = fcnt;
	}
	return ret_val;
}

static void iris_proc_ct(struct iris_config *iris_cfg, u32 fps)
{
	u32 prev_vts;
	u32 vts;
	u32 te;

	prev_vts = iris_cfg->prev_vts;
	vts = iris_cfg->meta.video_ts;
	te = iris_cfg->meta.te_period;
	iris_cfg->meta.content_period = (vts - prev_vts) * fps / 1000 * te / 1000;
	iris_cfg->meta.content_period_frac = (((vts - prev_vts) * fps / 1000 * te) & 0xfff) / (1000 >> 8);
	iris_cfg->meta.content_period_frac &= 0xff;
}

static void iris_proc_vp(struct iris_config *iris_cfg)
{
	iris_cfg->meta.vs_period = iris_cfg->meta.te_period;
	iris_cfg->meta.vs_period_frac = 0;
}

static void iris_proc_sts(struct iris_config *iris_cfg, u32 fps, u32 lcnt, u32 vper)
{
	if (iris_cfg->meta.op & MDP_IRIS_OP_STS) {
		pr_debug("sts %u\n", iris_cfg->meta.sys_ts);
		return;
	} else {
		u32 sts;
		ktime_t ktime = ktime_get();
		u64 time = ktime_to_us(ktime);
		sts = (u32) time;
		sts -= 1000000000 / fps / vper * lcnt / 1000;
		iris_cfg->meta.sys_ts = sts;
		return;
	}
}

static void iris_proc_restart(struct iris_config *iris_cfg)
{
	if (!(iris_cfg->meta.op & MDP_IRIS_OP_RESTART))
		iris_cfg->meta.restart = 1;
	else
		iris_cfg->meta.restart = (iris_cfg->prev_vts == iris_cfg->meta.video_ts);
}

static int iris_proc_vts(struct iris_config *iris_cfg)
{
	int ret;
	if (!(iris_cfg->meta.op & MDP_IRIS_OP_VTS))
		return 0;

	ret = (iris_cfg->prev_vts != iris_cfg->meta.video_ts);
	iris_cfg->prev_vts = iris_cfg->meta.video_ts;
	return ret;
}

void iris_set_te(struct iris_config *iris_cfg, int te_flag)
{
	if (!debug_te_enabled || !te_flag)
		return;

	mutex_lock(&iris_cfg->cmd_mutex);
	iris_reg_add(IRIS_DTG_ADDR + 0x00090, (iris_cfg->sw_te_period << 8 | 2 << 30));   //DVS_CTRL
	iris_reg_add(IRIS_DTG_ADDR + 0x10000, 1);	//reg_update
	mutex_unlock(&iris_cfg->cmd_mutex);
	pr_debug("set_te: %d\n", iris_cfg->sw_te_period);
}

static void iris_set_dtg(struct iris_config *iris_cfg)
{
	if (!debug_dtg_enabled)
		return;
	mutex_lock(&iris_cfg->cmd_mutex);
	iris_reg_add(IRIS_DTG_ADDR + 0x10004, iris_cfg->meta.sys_ts);
	iris_reg_add(IRIS_DTG_ADDR + 0x10008, iris_cfg->meta.video_ts);
	iris_reg_add(IRIS_DTG_ADDR + 0x1000c, ((iris_cfg->meta.vs_period & 0xffff) << 8 |
					       (iris_cfg->meta.vs_period_frac & 0xff)));
	iris_reg_add(IRIS_DTG_ADDR + 0x10010, iris_cfg->meta.te_period);
	iris_reg_add(IRIS_DTG_ADDR + 0x10014, ((iris_cfg->meta.content_period & 0xffff) << 8 |
					       (iris_cfg->meta.content_period_frac & 0xff)));
	iris_reg_add(IRIS_DTG_ADDR + 0x10018, ((iris_cfg->meta.restart & 1) << 8 |
					       (iris_cfg->meta.motion & 0xff)));
	iris_reg_add(IRIS_DTG_ADDR + 0x1001c, 1);
	mutex_unlock(&iris_cfg->cmd_mutex);
	pr_debug("dtg set\n");
}

static void iris_proc_scale(struct iris_config *iris_cfg, u32 dvts, u32 prev_dvts)
{
	u32 scale;
	if (abs(dvts-prev_dvts) <= ((dvts + prev_dvts) >> 5))
		scale = 64;
	else {
		scale = (dvts * 64 + prev_dvts / 2) / prev_dvts;
		scale = min((u32)255, scale);
		scale = max((u32)16, scale);
	}
	iris_cfg->scale = scale;
	pr_debug("pdvts %u dvts %u scale %u\n", prev_dvts, dvts, scale);
}

static void iris_set_constant_ratio(struct iris_config *iris_cfg)
{
	unsigned int reg_in, reg_out, reg_scale, reg_cap;

	reg_in = iris_cfg->in_ratio << IRIS_PWIL_IN_FRAME_SHIFT | (1 << 15);
	reg_out = iris_cfg->out_ratio << IRIS_PWIL_OUT_FRAME_SHIFT;
	reg_scale = 4096/iris_cfg->scale << 24 | 64 << 16 | iris_cfg->scale << 8 | iris_cfg->scale;
	/* duplicated video frame */
	reg_cap = (iris_cfg->meta.repeat != IRIS_REPEAT_CAPDIS) << 1;
	reg_cap |= 0xc0000001;
	iris_cfg->iris_ratio_updated = true;

	pr_debug("reg_cap 0x%08x\n", reg_cap);
	mutex_lock(&iris_cfg->cmd_mutex);
	iris_reg_add(IRIS_PWIL_ADDR + 0x12FC, reg_in);
	iris_reg_add(IRIS_PWIL_ADDR + 0x0638, reg_out);
	if (debug_new_repeat == 0)
		iris_reg_add(IRIS_PWIL_ADDR + 0x0218, reg_cap);
	iris_reg_add(IRIS_PWIL_ADDR + 0x10000, (1 << 8) | (1 << 6));
	iris_reg_add(IRIS_MVC_ADDR + 0x1D0, reg_scale);
	iris_reg_add(IRIS_MVC_ADDR + 0x1FF00, 1);
	mutex_unlock(&iris_cfg->cmd_mutex);
}

int iris_proc_constant_ratio(struct iris_config *iris_cfg)
{
	u32 dvts, in_t, out_t;
	uint32_t r;

	dvts = 1000000 / iris_cfg->input_frame_rate;
	in_t = (dvts * iris_cfg->output_frame_rate + 50000) / 100000;
	out_t = 10;

	r = gcd(in_t, out_t);
	pr_debug("in_t %u out_t %u r %u\n", in_t, out_t, r);
	iris_cfg->in_ratio = out_t / r;
	iris_cfg->out_ratio = in_t / r;
	iris_proc_scale(iris_cfg, dvts, dvts);
	// in true-cut case, always keep 1:1
	if (iris_cfg->true_cut_enable) {
		iris_cfg->in_ratio = 1;
		iris_cfg->out_ratio = 1;
		iris_cfg->scale = 64;
	}
	pr_debug("in/out %u:%u\n", iris_cfg->in_ratio, iris_cfg->out_ratio);
	// update register
	iris_set_constant_ratio(iris_cfg);

	return 0;
}

static int iris_proc_ratio(struct iris_config *iris_cfg)
{
	int ret = 0;
	u32 prev_dvts;
	u32 dvts, in_t, out_t;
	uint32_t r;

	if (!(iris_cfg->meta.op & MDP_IRIS_OP_VTS))
		return 0;

	dvts = iris_cfg->meta.video_ts - iris_cfg->prev_vts;
	prev_dvts = iris_cfg->prev_dvts;

	pr_debug("vts %u pvts %u dvts %u\n", iris_cfg->meta.video_ts, iris_cfg->prev_vts, dvts);
	if (dvts > 200000)
		return 0;

	if ((iris_cfg->iris_ratio_updated == true) && (abs(dvts - prev_dvts) < 3000))
		return 0;

	if (iris_cfg->repeat == IRIS_REPEAT_FORCE)
		return 0;

	if (debug_hlmd_enabled && !iris_cfg->true_cut_enable) {
		pr_debug("enable hlmd function.\n");
		// constant ratio
		ret = iris_proc_constant_ratio(iris_cfg);
		iris_cfg->prev_dvts = dvts;
		return ret;
	} else {
		pr_debug("don't enable hlmd function.\n");
		if (!iris_cfg->meta.video_ts || !debug_ratio_enabled)
			return 0;
	}

	if (prev_dvts && dvts) {
		in_t = (dvts * iris_cfg->output_frame_rate + 50000) / 100000;
		out_t = 10;

		r = gcd(in_t, out_t);
		pr_debug("in_t %u out_t %u r %u\n", in_t, out_t, r);
		iris_cfg->in_ratio = out_t / r;
		iris_cfg->out_ratio = in_t / r;
		iris_proc_scale(iris_cfg, dvts, prev_dvts);
		iris_cfg->iris_ratio_updated = (abs(dvts - prev_dvts) < 3000) ? true : false;
		ret = 1;
		pr_debug("in/out %u:%u\n", iris_cfg->in_ratio, iris_cfg->out_ratio);
	}

	if (prev_dvts && !dvts)
		ret = 1;

	if (dvts)
		iris_cfg->prev_dvts = dvts;

	return ret;
}

void iris_calc_nrv(struct mdss_mdp_ctl *ctl)
{
	struct iris_config *iris_cfg = &g_mfd->iris_conf;
	uint16_t width, height;

#define VIDEO_CTRL3	0x104c
#define VIDEO_CTRL4	0x1050
#define VIDEO_CTRL5	0x1054
#define VIDEO_CTRL11	0x106c
#define VIDEO_CTRL12	0x1070
#define DISP_CTRL2		0x120c
#define REG_UPDATE      0x10000

	if (iris_cfg->meta.op & MDP_IRIS_OP_NRV) {
		iris_reg_add(IRIS_PWIL_ADDR + VIDEO_CTRL3, ((uint32_t)iris_cfg->meta.nrv.captureTop << 16) |
													(uint32_t)iris_cfg->meta.nrv.captureLeft);
		width = iris_cfg->meta.nrv.captureRight - iris_cfg->meta.nrv.captureLeft;
		height = iris_cfg->meta.nrv.captureBottom - iris_cfg->meta.nrv.captureTop;
		iris_reg_add(IRIS_PWIL_ADDR + VIDEO_CTRL4, ((uint32_t)height << 16) | (uint32_t)width);
		iris_reg_add(IRIS_PWIL_ADDR + VIDEO_CTRL5, ((uint32_t)height << 16) | (uint32_t)width);
		iris_reg_add(IRIS_PWIL_ADDR + VIDEO_CTRL11, ((uint32_t)height << 16) | (uint32_t)width);
		iris_reg_add(IRIS_PWIL_ADDR + VIDEO_CTRL12, ((uint32_t)height << 16) | (uint32_t)width);
		iris_reg_add(IRIS_PWIL_ADDR + DISP_CTRL2, ((uint32_t)iris_cfg->meta.nrv.displayTop << 16) |
													(uint32_t)iris_cfg->meta.nrv.displayLeft);
		iris_reg_add(IRIS_PWIL_ADDR + REG_UPDATE, 0x100);

		width = iris_cfg->meta.nrv.displayRight - iris_cfg->meta.nrv.displayLeft;
		height = iris_cfg->meta.nrv.displayBottom - iris_cfg->meta.nrv.displayTop;
		iris_reg_add(IRIS_NRV_INFO1_ADDR, ((uint32_t)height << 16) | (uint32_t)width);
		iris_reg_add(IRIS_NRV_INFO2_ADDR, ((uint32_t)iris_cfg->meta.nrv.displayTop << 16) |
											(uint32_t)iris_cfg->meta.nrv.displayLeft);
		iris_cfg->nrv_enable = iris_cfg->meta.nrv.nrvEnable;
	}
}

static void iris_calc_true_cut(struct msm_fb_data_type *mfd) {
	struct iris_config *iris_cfg = &mfd->iris_conf;
	if (iris_cfg->meta.op & MDP_IRIS_OP_IF1) {
		uint32_t info_header = iris_cfg->meta.iris_info1 >> 28;

		pr_debug("true cut: %x\n", iris_cfg->meta.iris_info1);

		if (info_header == 0x8 || info_header == 0x9 ||
				info_header == 0xa || info_header == 0xb) {
			if (debug_true_cut) {
				if (info_header == 0x8)
					iris_cfg->input_vfr = 50;
				else if (info_header == 0x9)
					iris_cfg->input_vfr = 60;
				else if (info_header == 0xa)
					iris_cfg->input_vfr = 15;
				else if (info_header == 0xb)
					iris_cfg->input_vfr = 15;
				iris_cfg->true_cut_enable = true;
				if (iris_cfg->sf_notify_mode == IRIS_MODE_FRC)
					iris_reg_add(IRIS_TRUECUT_INFO_ADDR, iris_cfg->meta.iris_info1);
			}
		} else {
			iris_cfg->input_vfr = 0;
			iris_cfg->true_cut_enable = false;
		}
	}
}
#if 0
int iris_calc_meta(struct msm_fb_data_type *mfd)
{
	struct iris_config *iris_cfg = &mfd->iris_conf;
	struct mdss_overlay_private *mdp5_data = mfd_to_mdp5_data(mfd);
	struct mdss_mdp_ctl *ctl = mdp5_data->ctl;
	struct mdss_panel_data *pdata = mdp5_data->ctl->panel_data;
	u32 fps, fcnt, lcnt;
	u32 vper;
	int ret = 0, te_flag = 0;
	iris_calc_true_cut(ctl->mfd);
	if ((atomic_read(&mfd->iris_conf.mode_switch_cnt))) {
		iris_proc_vts(iris_cfg);
		return ret;
	}

	if (!debug_send_meta_enabled)
		return ret;
	// TODO
	//if (iris_cfg->current_mode != IRIS_MEMC_MODE)
	//	return 0;

	fps = mdss_panel_get_framerate(&pdata->panel_info);
	if (fps == 0)
		return ret;

	vper = iris_get_vtotal(&iris_info.output_timing);

	lcnt = 0;//ctl->read_line_cnt_fnc(ctl);
	if (pdata->panel_info.type == MIPI_CMD_PANEL) {
		fcnt = mdss_mdp_cmd_vsync_count(ctl);
		iris_proc_sts(iris_cfg, fps, lcnt, vper);
		iris_proc_restart(iris_cfg);
		iris_proc_te(iris_cfg, fcnt, lcnt, fps, vper);
		te_flag = iris_vary_te(iris_cfg, fcnt, (int)vper);
		iris_proc_ct(iris_cfg, fps);
		iris_proc_vp(iris_cfg);
		ret = iris_proc_vts(iris_cfg);
	} else if (pdata->panel_info.type == MIPI_VIDEO_PANEL) {
		fcnt = mdss_mdp_video_vsync_count(ctl);
		iris_proc_sts(iris_cfg, fps, lcnt, vper);
		iris_proc_restart(iris_cfg);
		ret = iris_proc_vts(iris_cfg);
	}

	if (iris_is_cmdin_videout())
		iris_set_te(iris_cfg, te_flag);

	iris_set_dtg(iris_cfg);

	pr_debug("sts=%u fps=%u fcnt=%u vts=%u restart=%u in_ratio=%u out_ratio=%u\n", iris_cfg->meta.sys_ts, fps, fcnt,
		iris_cfg->meta.video_ts, iris_cfg->meta.restart, iris_cfg->in_ratio, iris_cfg->out_ratio);

	memset((void *)&iris_cfg->meta, 0, sizeof(struct iris_meta));

	return ret;
}
#endif

static int iris_set_repeat(struct iris_config *iris_cfg)
{
	unsigned int reg_in, reg_out;
	unsigned int val_frcc_cmd_th = iris_cfg->val_frcc_cmd_th;
	unsigned int val_frcc_reg8 = iris_cfg->val_frcc_reg8;
	unsigned int val_frcc_reg16 = iris_cfg->val_frcc_reg16;
	bool cap_enable = true;

	// FIXME
	if (!debug_repeat_enabled || iris_cfg->sf_notify_mode != IRIS_MODE_FRC)
		return true;

	if ((iris_cfg->repeat == IRIS_REPEAT_FORCE) && (!frc_repeat_enter)) {
		reg_in = (1 << IRIS_PWIL_IN_FRAME_SHIFT) | (1 << 15);
		reg_out = 1 << IRIS_PWIL_OUT_FRAME_SHIFT;
		val_frcc_cmd_th &= 0x1fffffff;
		val_frcc_cmd_th |= 0x20000000;
		frc_repeat_enter = true;
		// iris2-40p use [15:8] for REPEATP1_TH iris2 use
		// [13:8] Do replace 0x3f << 8 to 0xff << 8
		// and in design iris2-40p no need to do work around
		val_frcc_reg8 |= 0xff00;
		val_frcc_reg16 &= 0xffff7fff;
		mutex_lock(&iris_cfg->cmd_mutex);
		iris_reg_add(FRCC_CTRL_REG8_ADDR, val_frcc_reg8);
		iris_reg_add(FRCC_CTRL_REG16_ADDR, val_frcc_reg16);
		iris_reg_add(FRCC_CMD_MOD_TH, val_frcc_cmd_th);
		iris_reg_add(FRCC_REG_SHOW, 0x2);
		if (!iris_cfg->true_cut_enable) {	// in true-cut case, always keep 1:1
			iris_reg_add(IRIS_PWIL_ADDR + 0x12FC, reg_in);
			iris_reg_add(IRIS_PWIL_ADDR + 0x0638, reg_out);
			iris_reg_add(IRIS_PWIL_ADDR + 0x10000, (1 << 8) | (1 << 6));
		}
		mutex_unlock(&iris_cfg->cmd_mutex);
	} else if (iris_cfg->repeat != IRIS_REPEAT_FORCE) {
		reg_in = iris_cfg->in_ratio << IRIS_PWIL_IN_FRAME_SHIFT | (1 << 15);
		reg_out = iris_cfg->out_ratio << IRIS_PWIL_OUT_FRAME_SHIFT;
		cap_enable = (iris_cfg->repeat != IRIS_REPEAT_CAPDIS);
		mutex_lock(&iris_cfg->cmd_mutex);
		if (frc_repeat_enter) {
			frc_repeat_enter = false;
			iris_reg_add(FRCC_CTRL_REG8_ADDR, val_frcc_reg8);
			iris_reg_add(FRCC_CTRL_REG16_ADDR, val_frcc_reg16);
			iris_reg_add(FRCC_CMD_MOD_TH, val_frcc_cmd_th);
			iris_reg_add(FRCC_REG_SHOW, 0x2);
			//if (!debug_hlmd_enabled)
			if (!iris_cfg->true_cut_enable)
			{
				iris_reg_add(IRIS_PWIL_ADDR + 0x12FC, reg_in);
				iris_reg_add(IRIS_PWIL_ADDR + 0x0638, reg_out);
				iris_reg_add(IRIS_PWIL_ADDR + 0x10000, (1 << 8) | (1 << 6));
			}
		}
		mutex_unlock(&iris_cfg->cmd_mutex);
	}

	pr_debug("vts %u pvts %u cap_en %d\n", iris_cfg->meta.video_ts, iris_cfg->prev_vts, cap_enable);

	return cap_enable;
}

void iris_cmd_cadence_check(struct mdss_mdp_ctl *ctl)
{
	static u32 prev_frame_addr;
	static u32 prev_frame_count, prev_frames;
	static enum { C11 = 11, C22 = 22, C32 = 32 } cadence = C11;
	static int badedit_cnt;
	bool bad = false;

	struct mdss_overlay_private *mdp5_data = mfd_to_mdp5_data(ctl->mfd);
	struct mdss_mdp_ctl *sctl = mdss_mdp_get_split_ctl(ctl);
	struct mdss_mdp_pipe *pipe;
	struct mdss_mdp_mixer *mixer;
	u32 frame_addr, frame_count, frames;

	if (!mdp5_data && !sctl)
		return;
	list_for_each_entry(pipe, &mdp5_data->pipes_used, list) {
		if (pipe->type == MDSS_MDP_PIPE_TYPE_VIG)
			goto check_cadence;
	}
	return;

check_cadence:
	mixer = mdss_mdp_mixer_get(ctl, MDSS_MDP_MIXER_MUX_LEFT);
	if (!mixer)
		return;

	frame_count = (mdss_mdp_pingpong_read(mixer->pingpong_base, MDSS_MDP_REG_PP_INT_COUNT_VAL) >> 16) & 0xffff;
	frames = frame_count - prev_frame_count;
	frame_addr = readl(pipe->base + MDSS_MDP_REG_SSPP_SRC0_ADDR);
	pr_debug("=== frame %08x count %u diff %u\n",
		 frame_addr, frame_count, frames);
	if (frame_addr == prev_frame_addr)
		return;

	switch (cadence) {
	case C11:
		if (frames == 2 && prev_frames == 2)
			cadence = C22;
		else if (frames == 3 && prev_frames == 2)
			cadence = C32;
		else if (frames == 2 && prev_frames == 3)
			cadence = C32;
		break;
	case C22:
		if (frames != 2)
			bad = true;
		break;
	case C32:
		if (!((frames == 3 && prev_frames == 2) ||
		      (frames == 2 && prev_frames == 3)))
			bad = true;
		break;
	}
	if (bad) {
		badedit_cnt++;
		//trace_exynos_busfreq_target_mif(badedit_cnt);
		pr_debug("=== bad edit %d === (cadence %u, frames %u)\n",
			 badedit_cnt, cadence, frames);
		cadence = C11;
	}

	prev_frame_addr = frame_addr;
	prev_frame_count = frame_count;
	prev_frames = frames;
}

#if 0
static int check_mode_status(struct mdss_dsi_ctrl_pdata *ctrl, int mode)
{
	int i;
	u32 val = 0;
	int try_cnt = 10;
	int ret = 0;

	if (!debug_mode_switch_enabled)
		return ret;

	for (i = 0; i < try_cnt; i++) {
		msleep(16);
#if defined(FPGA_PLATFORM)
		if (i == try_cnt - 1)
			val = IRIS_FRC_MODE;
#else
		val = iris_pi_read(ctrl, IRIS_MODE_ADDR);
#endif
		if (val == mode)
			break;
		else
			pr_err("%s:%d: %08x, cnt = %d\n", __func__, __LINE__, val, i);

	}

	if (i == try_cnt) {
		pr_err("%s: check mode (%d) error\n", __func__, mode);
		ret = -1;
	}
	return ret;
}
#endif

static void iris_pt_entry_wq_handler(struct work_struct *work)
{

	struct mdss_dsi_ctrl_pdata *ctrl = g_dsi_ctrl;
	struct iris_config *iris_cfg = &g_mfd->iris_conf;

	mdss_dsi_cmd_hs_mode(1, &ctrl->panel_data);

	pt_enable[0] = 0x0;
	pt_enable[1] = 0x1;

	mdss_dsi_cmds_tx(ctrl, pt_mode_enter,
			ARRAY_SIZE(pt_mode_enter), (CMD_REQ_DMA_TPG & CMD_REQ_COMMIT));

	atomic_dec(&iris_cfg->mode_switch_cnt);
	pr_debug("%s ------\n", __func__);
}

static void iris_rfb_entry_wq_handler(struct work_struct *work)
{

	struct mdss_dsi_ctrl_pdata *ctrl = g_dsi_ctrl;
	struct iris_config *iris_cfg = &g_mfd->iris_conf;

	mdss_dsi_cmd_hs_mode(1, &ctrl->panel_data);

	pt_enable[0] = 0x3 << 2;
	pt_enable[1] = 0x1;

	mdss_dsi_cmds_tx(ctrl, pt_mode_enter,
			ARRAY_SIZE(pt_mode_enter), (CMD_REQ_DMA_TPG & CMD_REQ_COMMIT));
	mdss_dsi_cmds_tx(ctrl, rfb_data_path_config,
			ARRAY_SIZE(rfb_data_path_config), (CMD_REQ_DMA_TPG & CMD_REQ_COMMIT));
	// TODO: use 200ms to instead the read command
	usleep_range(200000, 200000);

	atomic_dec(&iris_cfg->mode_switch_cnt);
	pr_debug("%s ------\n", __func__);
}

static void iris_pt_prepare_handler(struct work_struct *work)
{
	struct mdss_dsi_ctrl_pdata *ctrl = g_dsi_ctrl;
	struct mdss_panel_info *pinfo = g_mfd->panel_info;
	struct iris_config *iris_cfg = &g_mfd->iris_conf;

	BUG_ON(ctrl == NULL || pinfo == NULL);

	if (g_mfd->panel_info->type == MIPI_VIDEO_PANEL)
	{
		mdss_dsi_cmd_hs_mode(1, &ctrl->panel_data);
		mdss_dsi_cmds_tx(ctrl, pt_data_path_config,
			ARRAY_SIZE(pt_data_path_config), (CMD_REQ_DMA_TPG & CMD_REQ_COMMIT));
		// TODO: use 200ms to instead the read command
		usleep_range(200000, 200000);
	}

	atomic_dec(&iris_cfg->mode_switch_cnt);
	pr_debug("%s ------\n", __func__);
}

static void iris_rfb_prepare_handler(struct work_struct *work)
{
	struct mdss_dsi_ctrl_pdata *ctrl = g_dsi_ctrl;
	struct mdss_panel_info *pinfo = g_mfd->panel_info;
	struct iris_config *iris_cfg = &g_mfd->iris_conf;

	BUG_ON(ctrl == NULL || pinfo == NULL);

	if (g_mfd->panel_info->type == MIPI_VIDEO_PANEL)
	{
		mdss_dsi_cmd_hs_mode(1, &ctrl->panel_data);
		mdss_dsi_cmds_tx(ctrl, rfb_data_path_config,
			ARRAY_SIZE(rfb_data_path_config), (CMD_REQ_DMA_TPG & CMD_REQ_COMMIT));
		// TODO: use 200ms to instead the read command
		usleep_range(200000, 200000);
	}

	atomic_dec(&iris_cfg->mode_switch_cnt);
	pr_debug("%s ------\n", __func__);
}

static void iris_memc_prepare_handler(struct work_struct *work)
{
	struct mdss_dsi_ctrl_pdata *ctrl = g_dsi_ctrl;
	struct mdss_panel_info *pinfo = g_mfd->panel_info;
	struct iris_config *iris_cfg = &g_mfd->iris_conf;

	BUG_ON(ctrl == NULL || pinfo == NULL);

	if (g_mfd->panel_info->type == MIPI_VIDEO_PANEL)
	{
		mdss_dsi_cmd_hs_mode(1, &ctrl->panel_data);
		mdss_dsi_cmds_tx(ctrl, memc_data_path_config,
			ARRAY_SIZE(memc_data_path_config), (CMD_REQ_DMA_TPG & CMD_REQ_COMMIT));
		// TODO: use 200ms to instead the read command
		usleep_range(200000, 200000);
	}

	atomic_dec(&iris_cfg->mode_switch_cnt);
	pr_debug("%s ------\n", __func__);
}

static void iris_memc_cancel_handler(struct work_struct *work)
{
	struct mdss_dsi_ctrl_pdata *ctrl = g_dsi_ctrl;
	struct iris_config *iris_cfg = &g_mfd->iris_conf;

	BUG_ON(ctrl == NULL || iris_cfg == NULL);
//todos, embedded not ready.
#if 0
	mdss_dsi_cmd_hs_mode(1, &ctrl->panel_data);
	mdss_dsi_cmds_tx(ctrl, memc_cancel,
			ARRAY_SIZE(memc_cancel));

	check_mode_status(ctrl, IRIS_PT_MODE);
#endif
	atomic_dec(&iris_cfg->mode_switch_cnt);
	pr_debug("%s ------\n", __func__);
}

static void iris_memc_entry_handler(struct work_struct *work)
{
	struct mdss_dsi_ctrl_pdata *ctrl = g_dsi_ctrl;
	struct mdss_panel_info *pinfo = g_mfd->panel_info;
	struct iris_config *iris_cfg = &g_mfd->iris_conf;

	BUG_ON(ctrl == NULL || pinfo == NULL);
	iris_proc_frcc_setting(g_mfd);
	mdss_dsi_cmd_hs_mode(1, &ctrl->panel_data);
	mdss_dsi_cmds_tx(ctrl, memc_mode_enter,
			ARRAY_SIZE(memc_mode_enter), (CMD_REQ_DMA_TPG & CMD_REQ_COMMIT));
	atomic_dec(&iris_cfg->mode_switch_cnt);
	pr_debug("%s ------\n", __func__);
}

void iris_regs_clear(void)
{
	iris_reg_cnt = 0;
	//memset(iris_regs, 0, sizeof(iris_regs));
}

void iris_reg_add(u32 addr, u32 val)
{
	if (iris_reg_cnt >= IRIS_REGS) {
		pr_warn("iris reg add count is overflow.\n");
		return;
	}
	pr_debug("regs[%i:%08x] = %08x\n", iris_reg_cnt, addr, val);
	iris_regs[iris_reg_cnt].addr = addr;
	iris_regs[iris_reg_cnt].val = val;
	iris_reg_cnt++;
}

static int  iris_regs_meta_build(void)
{
	int i;
	int size;
	char imeta_header[META_HEADER] = {
		PWIL_TAG('P', 'W', 'I', 'L'),
		PWIL_TAG('G', 'R', 'C', 'P'),
		PWIL_U32(0x3),
		0x00,
		0x00,
		PWIL_U16(0x2),
	};

	pr_debug("reg_cnt: %02x", iris_reg_cnt);
	memcpy(imeta, imeta_header, META_HEADER);
	// pair
	for (i = 0; i < iris_reg_cnt; i++) {
		*(u32 *)(imeta + META_HEADER + i*8) = cpu_to_le32(iris_regs[i].addr);
		*(u32 *)(imeta + META_HEADER + i*8 + 4) = cpu_to_le32(iris_regs[i].val);
		/*
		imeta[META_HEADER + i*8    ] = iris_regs[i].addr         & 0xff;
		imeta[META_HEADER + i*8 + 1] = (iris_regs[i].addr >>  8) & 0xff;
		imeta[META_HEADER + i*8 + 2] = (iris_regs[i].addr >> 16) & 0xff;
		imeta[META_HEADER + i*8 + 3] = (iris_regs[i].addr >> 24) & 0xff;

		imeta[META_HEADER + i*8 + 4] = iris_regs[i].addr         & 0xff;
		imeta[META_HEADER + i*8 + 5] = (iris_regs[i].addr >>  8) & 0xff;
		imeta[META_HEADER + i*8 + 6] = (iris_regs[i].addr >> 16) & 0xff;
		imeta[META_HEADER + i*8 + 7] = (iris_regs[i].addr >> 24) & 0xff;
		*/
	}
	// size update
	size = iris_reg_cnt * 2;
	*(u32 *)(imeta + 8) = cpu_to_le32(size + 1);
	*(u16 *)(imeta + 14) = cpu_to_le16(size);
	iris_meta_pkts[0].dchdr.dlen = META_HEADER + iris_reg_cnt * 8;
	return iris_reg_cnt;
}

void iris_copy_meta(struct msm_fb_data_type *mfd)
{
	struct iris_config *iris_cfg = &g_mfd->iris_conf;
	// copy meta
	mutex_lock(&iris_cfg->meta_mutex);
	if (iris_cfg->meta_set.op) {
		memcpy((void *)&iris_cfg->meta, (void *)&iris_cfg->meta_set, sizeof(struct iris_meta));
		memset((void *)&iris_cfg->meta_set, 0, sizeof(struct iris_meta));
		pr_debug("iris_copy_meta\n");
	}
	mutex_unlock(&iris_cfg->meta_mutex);
}


void iris_i2c_send_meta(struct mdss_mdp_ctl *ctl)
{
	int i = 0;
	int len = 0;

	struct iris_config *iris_cfg = &g_mfd->iris_conf;
	struct addr_val addr_list[IRIS_REGS];

	if (!debug_send_meta_enabled)
		return;

	if (ctl && ! mdss_mdp_ctl_is_power_on(ctl)) {
		pr_err("power is off\n");
		return;
	}

	if ((atomic_read(&g_mfd->iris_conf.mode_switch_cnt)))
		return;

	if (iris_cfg->cap_change) {
		//cadence change , capture disable and capture enable
		if ( iris_cfg->cap_enable ) {
			iris_reg_add(IRIS_PWIL_ADDR +0x1204, 0x00020001);
		} else {
			iris_reg_add(IRIS_PWIL_ADDR +0x1204, 0x00100001);
		}
		iris_cfg->cap_change = false;
		pr_debug("cap_change: %d\n", iris_cfg->cap_enable);
	}

	if (iris_reg_cnt <= 0) {
	//mutex_lock(&g_mfd->iris_conf.cmd_mutex);
	//if (!iris_regs_meta_build()) {
		//mutex_unlock(&g_mfd->iris_conf.cmd_mutex);
		return;
	}
	memset(addr_list , 0x00, sizeof(addr_list));

	for (i = 0; i < iris_reg_cnt; i++) {
		addr_list[i].addr = cpu_to_le32(iris_regs[i].addr);
		addr_list[i].data = cpu_to_le32(iris_regs[i].val);
	}
	len = iris_reg_cnt;
	iris_regs_clear();
	//mutex_unlock(&g_mfd->iris_conf.cmd_mutex);
	iris_i2c_write(addr_list, len);
}


void iris_send_meta_cmd(struct mdss_mdp_ctl *ctl)
{
	struct mdss_dsi_ctrl_pdata *ctrl = g_dsi_ctrl;
	struct dcs_cmd_req cmdreq;
	struct iris_config *iris_cfg = &g_mfd->iris_conf;
	int cmd;

	BUG_ON(ctrl == NULL);

	if (!debug_send_meta_enabled)
		return;

	if ((atomic_read(&g_mfd->iris_conf.mode_switch_cnt)))
		return;

	memset(&cmdreq, 0, sizeof(cmdreq));
	cmdreq.cmds_cnt = 1;
	cmdreq.flags = CMD_REQ_HS_MODE | CMD_REQ_COMMIT | CMD_CLK_CTRL;
	cmdreq.rlen = 0;
	cmdreq.cb = NULL;

	if (iris_cfg->cap_change) {
		static char cursor_enable[2] = {0x04, 0x10};
		static struct dsi_cmd_desc cursor_mode_enter[] = {
			{ { DTYPE_GEN_WRITE2, 1, 0, 0, 0, sizeof(cursor_enable) }, cursor_enable},};
		if (iris_cfg->cap_enable)
			cmdreq.cmds = memc_mode_enter;
		else
			cmdreq.cmds = cursor_mode_enter;
		mdss_dsi_cmdlist_put(g_dsi_ctrl, &cmdreq);
		iris_cfg->cap_change = false;
		pr_debug("cap_change: %d\n", iris_cfg->cap_enable);
	}

	pr_debug("%s ++++++\n", __func__);
	mutex_lock(&g_mfd->iris_conf.cmd_mutex);
	if (!iris_regs_meta_build()) {
		mutex_unlock(&g_mfd->iris_conf.cmd_mutex);
		return;
	}
	iris_regs_clear();
	mutex_unlock(&g_mfd->iris_conf.cmd_mutex);
	cmdreq.cmds = iris_meta_pkts;
	iris_meta_pkts[0].dchdr.last = 1;

	for (cmd = 0; cmd < cmdreq.cmds_cnt; cmd++) {
		pr_debug("dchdr: %02x %02x %02x %02x %02x %02x\n",
			iris_meta_pkts[cmd].dchdr.dtype,
			iris_meta_pkts[cmd].dchdr.last,
			iris_meta_pkts[cmd].dchdr.vc,
			iris_meta_pkts[cmd].dchdr.ack,
			iris_meta_pkts[cmd].dchdr.wait,
			iris_meta_pkts[cmd].dchdr.dlen);
		{
		int i;
		for (i = 0; i < iris_meta_pkts[cmd].dchdr.dlen; i += 8)
			pr_debug("%02x %02x %02x %02x %02x %02x %02x %02x\n",
				iris_meta_pkts[cmd].payload[i],   iris_meta_pkts[cmd].payload[i+1],
				iris_meta_pkts[cmd].payload[i+2], iris_meta_pkts[cmd].payload[i+3],
				iris_meta_pkts[cmd].payload[i+4], iris_meta_pkts[cmd].payload[i+5],
				iris_meta_pkts[cmd].payload[i+6], iris_meta_pkts[cmd].payload[i+7]);
		}
	}

	mdss_dsi_cmdlist_put(g_dsi_ctrl, &cmdreq);
	//memset(imeta, 0, sizeof(imeta));
}

static void iris_meta_wq_handler(void)
{
	struct mdss_mdp_ctl *ctl = mfd_to_ctl(g_mfd);
	struct mdss_dsi_ctrl_pdata *ctrl = g_dsi_ctrl;
	struct mdss_panel_data *pdata = ctl->panel_data;
	struct iris_config *iris_cfg = &g_mfd->iris_conf;
	int cmd;
	int cnt;

	if (g_mfd->panel_info->type == MIPI_VIDEO_PANEL)
	{
		cnt = 1;
	}
	else
	{
		cnt = 2;
	}

	//if (ctl->power_state == MDSS_PANEL_POWER_OFF)
	//	return;
	if (pdata->panel_info.panel_power_state == MDSS_PANEL_POWER_OFF)
		return;
	pr_debug("%s ++++++\n", __func__);
	mutex_lock(&iris_cfg->cmd_mutex);
	iris_regs_meta_build();
	iris_regs_clear();
	mutex_unlock(&iris_cfg->cmd_mutex);
	// TODO: when okay use ioctl or other side band to enable new frame
	iris_meta_pkts[0].dchdr.last = debug_new_frame_enabled ? 0 : 1;
	iris_meta_pkts[1].dchdr.last = debug_new_frame_enabled ? 1 : 0;
	if (g_mfd->panel_info->type == MIPI_VIDEO_PANEL)
        {
		iris_meta_pkts[0].dchdr.last = 1;
	}
	for (cmd = 0; cmd < cnt; cmd++) {
		pr_debug("dchdr: %02x %02x %02x %02x %02x %02x\n",
		iris_meta_pkts[cmd].dchdr.dtype,
		iris_meta_pkts[cmd].dchdr.last,
		iris_meta_pkts[cmd].dchdr.vc,
		iris_meta_pkts[cmd].dchdr.ack,
		iris_meta_pkts[cmd].dchdr.wait,
		iris_meta_pkts[cmd].dchdr.dlen);
		{
		int i;
		for (i = 0; i < iris_meta_pkts[cmd].dchdr.dlen; i += 8)
			pr_debug("%02x %02x %02x %02x %02x %02x %02x %02x\n",
			iris_meta_pkts[cmd].payload[i],   iris_meta_pkts[cmd].payload[i+1],
			iris_meta_pkts[cmd].payload[i+2], iris_meta_pkts[cmd].payload[i+3],
			iris_meta_pkts[cmd].payload[i+4], iris_meta_pkts[cmd].payload[i+5],
			iris_meta_pkts[cmd].payload[i+6], iris_meta_pkts[cmd].payload[i+7]);
		}
	}
	mdss_dsi_cmd_hs_mode(1, &ctrl->panel_data);
	// TODO: assume 2 meta packet will both issued at same kickoff
	if (iris_meta_pkts[0].dchdr.dlen > META_HEADER)
		mdss_dsi_cmds_tx(ctrl, iris_meta_pkts, cnt, (CMD_REQ_DMA_TPG & CMD_REQ_COMMIT));
	memset(imeta, 0, sizeof(imeta));
	pr_debug("%s ------\n", __func__);
}


void iris_send_meta_video(struct mdss_mdp_ctl *ctl)
{
	struct msm_fb_data_type *mfd = ctl->mfd;
	struct iris_config *iris_cfg = &mfd->iris_conf;

	BUG_ON(iris_cfg == NULL);

	if (!debug_send_meta_enabled)
		return;

	if ((atomic_read(&g_mfd->iris_conf.mode_switch_cnt)))
		return;

	//schedule_work(&iris_cfg->meta_work);
	iris_mgmt.iris_handler = iris_meta_wq_handler;
	queue_work(iris_mgmt.iris_wq, &iris_mgmt.iris_worker);
}


// shall be called before params_changed clear to 0
static int iris_proc_repeat(struct iris_config *iris_cfg)
{
	u8 prev_repeat;
	int ret;

	prev_repeat = iris_cfg->repeat;

	if (debug_repeat_enabled > 3) {
		iris_cfg->repeat = debug_repeat_enabled - 3;
	} else {
		iris_cfg->repeat = (iris_cfg->meta.op & MDP_IRIS_OP_RPT) ? iris_cfg->meta.repeat : iris_cfg->repeat;
	}

	pr_debug("repeat = %d\n", iris_cfg->repeat);

	ret = ((iris_cfg->repeat != prev_repeat) || (iris_cfg->repeat == IRIS_REPEAT_FORCE));
	return ret;
}

static int iris_set_ratio(struct iris_config *iris_cfg)
{
	unsigned int reg_in, reg_out, reg_scale;
	bool cap_enable;

	reg_in = iris_cfg->in_ratio << IRIS_PWIL_IN_FRAME_SHIFT | (1 << 15);
	reg_out = iris_cfg->out_ratio << IRIS_PWIL_OUT_FRAME_SHIFT;
	reg_scale = 4096/iris_cfg->scale << 24 | 64 << 16 | iris_cfg->scale << 8 | iris_cfg->scale;
	/* duplicated video frame */
	cap_enable = iris_cfg->repeat != IRIS_REPEAT_CAPDIS;
	/*set ratio after mode switch to FRC */
	if (!debug_ratio_enabled ||
		((iris_cfg->sf_notify_mode != IRIS_MODE_FRC) &&
		(iris_cfg->sf_notify_mode != IRIS_MODE_RFB2FRC)))	// FIXME, whether set when FRC_PREPARE
		return true;

	if (iris_cfg->true_cut_enable)
		return cap_enable;

	pr_debug("vts %u pvts %u cap_enable %d\n", iris_cfg->meta.video_ts, iris_cfg->prev_vts, cap_enable);
	mutex_lock(&iris_cfg->cmd_mutex);
	iris_reg_add(IRIS_PWIL_ADDR + 0x12FC, reg_in);
	iris_reg_add(IRIS_PWIL_ADDR + 0x0638, reg_out);
	iris_reg_add(IRIS_PWIL_ADDR + 0x10000, (1 << 8) | (1 << 6));
	iris_reg_add(IRIS_MVC_ADDR + 0x1D0, reg_scale);
	iris_reg_add(IRIS_MVC_ADDR + 0x1FF00, 1);
	mutex_unlock(&iris_cfg->cmd_mutex);
	return cap_enable;
}

bool iris_frc_repeat(struct msm_fb_data_type *mfd)
{
	struct iris_config *iris_cfg = &mfd->iris_conf;
	int ret_r, ret_p;
	int cap_enable = true;
	bool ret;

	if (iris_cfg->sf_notify_mode != IRIS_MODE_FRC)
		return cap_enable;

	ret_r = iris_proc_ratio(iris_cfg);
	ret_p = iris_proc_repeat(iris_cfg);
	if (ret_p)
		cap_enable = iris_set_repeat(iris_cfg);
	else if (ret_r)
		cap_enable = iris_set_ratio(iris_cfg);
	else {
		cap_enable = iris_cfg->cap_enable;
		pr_debug("keep the last value: %d!\n", cap_enable);
	}

	if (iris_cfg->sf_notify_mode == IRIS_MODE_FRC) {
		if (cap_enable != iris_cfg->cap_enable) {
			pr_debug("capture-change: %d!\n", cap_enable);
			if (debug_new_repeat == 1)
				iris_cfg->cap_change = true;
			else if (debug_new_repeat == 0) {
				unsigned int reg_cap;
				if (cap_enable)
					reg_cap = 0xc0000003;
				else
					reg_cap = 0xc0000001;
				mutex_lock(&iris_cfg->cmd_mutex);
				iris_reg_add(IRIS_PWIL_ADDR + 0x0218, reg_cap);
				mutex_unlock(&iris_cfg->cmd_mutex);
			}
			iris_cfg->cap_enable = cap_enable;
		}
	}

	ret = ((debug_new_repeat == 2) ? cap_enable : true);
	return ret;
}


int iris_proc_frcc_setting(struct msm_fb_data_type *mfd)
{
	struct iris_config *iris_cfg = &mfd->iris_conf;
	struct mdss_overlay_private *mdp5_data = mfd_to_mdp5_data(mfd);
	struct mdss_panel_data *pdata = mdp5_data->ctl->panel_data;
	struct quality_setting *pqlt_cur_setting = &iris_info.setting_info.quality_cur;

	// default val of reference register which need host to set.
	u32 val_frcc_reg5 = 0x3c010000;
	u32 val_frcc_reg8 = 0x10000000;
	u32 val_frcc_reg16 = 0x413120c8;
	u32 val_frcc_reg17 = 0x8000;
	u32 val_frcc_reg18 = 0;
	u32 val_frcc_cmd_th = 0x8000;
	u32 val_frcc_dtg_sync = 0;

	//formula variable
	u32 ThreeCoreEn, VD_CAP_DLY1_EN;
	u32 MaxFIFOFI, KeepTH, CarryTH, RepeatP1_TH;
	u32 RepeatCF_TH, TS_FRC_EN, INPUT_RECORD_THR, MERAREC_THR_VALID;
	u32 MetaGen_TH1, MetaGen_TH2, MetaRec_TH1, MetaRec_TH2;
	u32 FIRepeatCF_TH;

	//timing and feature variable
	u32 te_fps, display_vsync, Input_Vres, Scaler_EN = false, Capture_EN, Input_Vtotal;
	u32 DisplayVtotal, HsyncFreqIn, HsyncFreqOut, InVactive, StartLine, Vsize;
	int inputwidth = (iris_info.work_mode.rx_ch  ?  iris_info.input_timing.hres * 2 : iris_info.input_timing.hres);
	u32 Infps = iris_cfg->input_frame_rate;
	int adjustmemclevel = 3;
	int hlmd_func_enable = 0;

	//init variable
	te_fps = mdss_panel_get_framerate(&pdata->panel_info);
	display_vsync = 60;//iris to panel, TODO, or 120
	Input_Vres = pdata->panel_info.yres;
#if defined(CONFIG_IRIS2P_DRC_SUPPORT)
	Capture_EN = iris_cfg->nrv_enable | iris_cfg->drc_enable;
#else
	Capture_EN = iris_cfg->nrv_enable;
#endif
	Input_Vtotal = mdss_panel_get_vtotal(&pdata->panel_info);
	if (lp_memc_timing[0] != inputwidth)
		Scaler_EN = true;
	else
		Scaler_EN = false;
	DisplayVtotal = iris_get_vtotal(&iris_info.output_timing);
	HsyncFreqIn = te_fps * Input_Vtotal;
	HsyncFreqOut = display_vsync * DisplayVtotal;
	InVactive = iris_cfg->meta.nrv.captureBottom - iris_cfg->meta.nrv.captureTop;
#if defined(CONFIG_IRIS2P_DRC_SUPPORT)
	if (iris_cfg->drc_enable)
		InVactive = (iris_cfg->drc_size >> 16);
#endif
	if (Capture_EN)
		StartLine = Input_Vres - InVactive;
	else if (Scaler_EN)
		StartLine = 5;
	else
		StartLine = 0;
	if (Capture_EN)
		Vsize = InVactive;
	else
		Vsize = Input_Vtotal;//DisplayVtotal;

	pr_debug("%s: get timing info, infps=%d, displayVtotal = %d, InVactive = %d, StartLine = %d, Vsize = %d\n",
		__func__, Infps, DisplayVtotal, InVactive, StartLine, Vsize);
	pr_debug("TE_fps = %d, display_vsync = %d, inputVres = %d, Scaler_EN = %d, capture_en = %d, InputVtotal = %d\n",
		te_fps, display_vsync, Input_Vres, Scaler_EN, Capture_EN, Input_Vtotal);

	if (mfd->panel_info->type == MIPI_VIDEO_PANEL) {
		//video mode
		ThreeCoreEn = 1; VD_CAP_DLY1_EN = 0; MaxFIFOFI = 3; KeepTH = 252; CarryTH = 5;
		RepeatP1_TH = 5; RepeatCF_TH = 252; TS_FRC_EN = 0; MERAREC_THR_VALID = 1;
		MetaGen_TH1 = (Vsize / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn - 10;
		MetaGen_TH2 = (Vsize * 6 / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn - 10;
		MetaRec_TH1 = (Vsize * 5 / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn - 10;
		MetaRec_TH2 = (Vsize * 7 / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn - 10;
		INPUT_RECORD_THR = (Vsize  / 2 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		FIRepeatCF_TH = 252;
		goto VAL_CALC;
	}

	if (iris_cfg->fbo_enable) {
		//TODO mbo mode
		ThreeCoreEn = 1; VD_CAP_DLY1_EN = 0; MaxFIFOFI = 4; KeepTH = 252; CarryTH = 5;
		RepeatP1_TH = 5; RepeatCF_TH = 252; TS_FRC_EN = 0; MERAREC_THR_VALID = 1;
		MetaGen_TH1 = (Vsize / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		MetaGen_TH2 = (Vsize * 6 / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		MetaRec_TH1 = (Vsize * 5 / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		MetaRec_TH2 = (Vsize * 7 / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		INPUT_RECORD_THR = (Vsize  / 2 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		FIRepeatCF_TH = 252;
		goto VAL_CALC;
	}

	pr_debug("iris_cfg->input_vfr: %d", iris_cfg->input_vfr);
	//check input is variable frame rate or not.
	switch (iris_cfg->input_vfr) {
	case 15:// 15 fps from 24/25 fps.
		ThreeCoreEn = 0; VD_CAP_DLY1_EN = 0; MaxFIFOFI = 5; KeepTH = 253; CarryTH = 2;
		RepeatP1_TH = 2; RepeatCF_TH = 253; TS_FRC_EN = 1; MERAREC_THR_VALID = 1;
		MetaGen_TH1 = (Vsize / 2 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		MetaGen_TH2 = (Vsize * 6 / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		MetaRec_TH1 = (Vsize * 5 / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		MetaRec_TH2 = (Vsize * 7 / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		INPUT_RECORD_THR = (Vsize  / 2 + StartLine) * HsyncFreqOut / HsyncFreqIn - 10;
		FIRepeatCF_TH = 253;
		if (debug_hlmd_enabled && !iris_cfg->true_cut_enable) {
			hlmd_func_enable = 1;
			RepeatP1_TH = 1;
			CarryTH = 1;
		} else {
			hlmd_func_enable = 0;
		}
		goto VAL_CALC;
	case 50:// vfr from 50 drop
		ThreeCoreEn = 0; VD_CAP_DLY1_EN = 0; MaxFIFOFI = 4; KeepTH = 253; CarryTH = 2;
		RepeatP1_TH = 2; RepeatCF_TH = 253; TS_FRC_EN = 1; MERAREC_THR_VALID = 1;
		MetaGen_TH1 = (Vsize / 2 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		MetaGen_TH2 = (Vsize * 6 / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		MetaRec_TH1 = (Vsize * 5 / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		MetaRec_TH2 = (Vsize * 7 / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		INPUT_RECORD_THR = (Vsize  / 2 + StartLine) * HsyncFreqOut / HsyncFreqIn - 10;
		FIRepeatCF_TH = 253;
		goto VAL_CALC;
	case 60:// vfr from 60 drop
		ThreeCoreEn = 0; VD_CAP_DLY1_EN = 0; MaxFIFOFI = 4; KeepTH = 253; CarryTH = 1;
		RepeatP1_TH = 1; RepeatCF_TH = 253; TS_FRC_EN = 1; MERAREC_THR_VALID = 0;
		MetaGen_TH1 = (Vsize / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		MetaGen_TH2 = (Vsize * 5 / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		MetaRec_TH1 = (Vsize * 5 / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		MetaRec_TH2 = (Vsize * 7 / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		INPUT_RECORD_THR = (Vsize  / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn - 10;
		FIRepeatCF_TH = 253;
		goto VAL_CALC;
	case 0:// vfr is invalid, frame rate is constant
	default :
		break;
	}

	switch (Infps) {
	case 24://24fps
		ThreeCoreEn = 0; VD_CAP_DLY1_EN = 0; MaxFIFOFI = 3; KeepTH = 252; CarryTH = 5;
		RepeatP1_TH = 5; RepeatCF_TH = 252; TS_FRC_EN = 0; MERAREC_THR_VALID = 1;
		MetaGen_TH1 = (Vsize / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		MetaGen_TH2 = (Vsize * 6 / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		MetaRec_TH1 = (Vsize * 5 / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		MetaRec_TH2 = (Vsize * 7 / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		INPUT_RECORD_THR = (Vsize  / 2 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		FIRepeatCF_TH = 252;
		break;
	case 30://30fps
		ThreeCoreEn = 0; VD_CAP_DLY1_EN = 0; MaxFIFOFI = 2; KeepTH = 252; CarryTH = 5;
		RepeatP1_TH = 5; RepeatCF_TH = 252; TS_FRC_EN = 0; MERAREC_THR_VALID = 1;
		MetaGen_TH1 = (Vsize / 2 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		MetaGen_TH2 = (Vsize * 6 / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		MetaRec_TH1 = (Vsize * 5 / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		MetaRec_TH2 = (Vsize * 7 / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		INPUT_RECORD_THR = (Vsize  / 2 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		FIRepeatCF_TH = 252;
		break;
	case 25://25fps
		ThreeCoreEn = 1; VD_CAP_DLY1_EN = 0; MaxFIFOFI = 3; KeepTH = 253; CarryTH = 2;
		RepeatP1_TH = 2; RepeatCF_TH = 253; TS_FRC_EN = 0; MERAREC_THR_VALID = 1;
		MetaGen_TH1 = (Vsize / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		MetaGen_TH2 = (Vsize * 5 / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		MetaRec_TH1 = (Vsize * 3 / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		MetaRec_TH2 = (Vsize * 7 / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		INPUT_RECORD_THR = (Vsize  / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn - 10;
		FIRepeatCF_TH = 253;
		break;
	case 15://15fps
		if (debug_hlmd_enabled && !iris_cfg->true_cut_enable) {
			hlmd_func_enable = 1;
			RepeatP1_TH = 1;
			CarryTH = 1;
		} else {
			hlmd_func_enable = 0;
			RepeatP1_TH = 2;
			CarryTH = 2;
		}
		ThreeCoreEn = 0; VD_CAP_DLY1_EN = 0; MaxFIFOFI = 5; KeepTH = 253;
		RepeatCF_TH = 253; TS_FRC_EN = 1; MERAREC_THR_VALID = 1;
		MetaGen_TH1 = (Vsize / 2 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		MetaGen_TH2 = (Vsize * 6 / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		MetaRec_TH1 = (Vsize * 5 / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		MetaRec_TH2 = (Vsize * 7 / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		INPUT_RECORD_THR = (Vsize  / 2 + StartLine) * HsyncFreqOut / HsyncFreqIn - 10;
		FIRepeatCF_TH = 253;
	case 12://12fps
		ThreeCoreEn = 0; VD_CAP_DLY1_EN = 0; MaxFIFOFI = 5; KeepTH = 253; CarryTH = 2;
		RepeatP1_TH = 2; RepeatCF_TH = 253; TS_FRC_EN = 1; MERAREC_THR_VALID = 1;
		MetaGen_TH1 = (Vsize / 2 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		MetaGen_TH2 = (Vsize * 6 / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		MetaRec_TH1 = (Vsize * 5 / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		MetaRec_TH2 = (Vsize * 7 / 8 + StartLine) * HsyncFreqOut / HsyncFreqIn;
		INPUT_RECORD_THR = (Vsize  / 2 + StartLine) * HsyncFreqOut / HsyncFreqIn - 10;
		FIRepeatCF_TH = 253;
		break;
	default:
		pr_err("%s, using default frcc parameters\n", __func__);
		goto SET_REG;
	}

VAL_CALC:
	if (pqlt_cur_setting->pq_setting.memclevel == 3)
		adjustmemclevel = 3;
	else if (pqlt_cur_setting->pq_setting.memclevel == 2)
		adjustmemclevel = 3;
	else if (pqlt_cur_setting->pq_setting.memclevel == 1)
		adjustmemclevel = 2;
	else if (pqlt_cur_setting->pq_setting.memclevel == 0)
		adjustmemclevel = 0;

	//val_frcc_reg5 = val_frcc_reg5 + ((pqlt_cur_setting->pq_setting.memclevel & 0x3) << 17) + (KeepTH * 2 << 7) + CarryTH;
	val_frcc_reg5 = val_frcc_reg5 + ((adjustmemclevel & 0x3) << 17) + (KeepTH << 8) + CarryTH;
	val_frcc_reg8 = val_frcc_reg8 + (RepeatP1_TH << 8) + RepeatCF_TH;
	val_frcc_reg16 = val_frcc_reg16 + (TS_FRC_EN << 31) + (ThreeCoreEn << 15) + VD_CAP_DLY1_EN;
	val_frcc_reg17 = val_frcc_reg17 + (DisplayVtotal << 16) + INPUT_RECORD_THR;
	val_frcc_reg18 = val_frcc_reg18 + (MERAREC_THR_VALID << 31) + (MetaRec_TH2 << 16) + MetaRec_TH1;
	val_frcc_cmd_th = val_frcc_cmd_th + (MaxFIFOFI << 29) + (MetaGen_TH2 << 16) + MetaGen_TH1;
	val_frcc_dtg_sync |= FIRepeatCF_TH << FI_REPEATCF_TH;

SET_REG:
	pr_debug("%s: reg5=%x, reg8=%x, reg16=%x, reg17=%x, reg18=%x, cmd_th=%x\n", __func__,
		val_frcc_reg5, val_frcc_reg8, val_frcc_reg16, val_frcc_reg17, val_frcc_reg18, val_frcc_cmd_th);
	mutex_lock(&iris_cfg->cmd_mutex);
	iris_reg_add(FRCC_CTRL_REG5_ADDR, val_frcc_reg5);
	iris_reg_add(FRCC_CTRL_REG8_ADDR, val_frcc_reg8);
	iris_reg_add(FRCC_CTRL_REG16_ADDR, val_frcc_reg16);
	iris_reg_add(FRCC_CTRL_REG17_ADDR, val_frcc_reg17);
	iris_reg_add(FRCC_CTRL_REG18_ADDR, val_frcc_reg18);
	iris_reg_add(FRCC_DTG_SYNC, val_frcc_dtg_sync);
	iris_reg_add(FRCC_CMD_MOD_TH, val_frcc_cmd_th);
        iris_reg_add(FRCC_REG_SHOW, 0x2);
	if (debug_hlmd_enabled) {
		if (hlmd_func_enable)
			iris_reg_add(IRIS_MVC_ADDR + 0x1ffe8, 0x00200000);
	}
	if (iris_cfg->true_cut_enable) {
		iris_reg_add(IRIS_MVC_ADDR + 0x1ffe8, 0x00200000);
	} else {
		iris_reg_add(IRIS_MVC_ADDR + 0x1ffe8, 0x00000000);
	}
	mutex_unlock(&iris_cfg->cmd_mutex);
	iris_cfg->val_frcc_cmd_th = val_frcc_cmd_th;
	iris_cfg->val_frcc_reg8 = val_frcc_reg8;
	iris_cfg->val_frcc_reg16 = val_frcc_reg16;
	return 0;
}

void mdss_dsi_iris_init(struct msm_fb_data_type *mfd)
{
	printk("###%s:%d: mfd->panel.type: %i mfd->panel.id: %i\n", __func__, __LINE__, mfd->panel.type, mfd->panel.id);
	if (mfd->index != 0)
		return;
	if (!(mfd->panel.type == MIPI_VIDEO_PANEL || mfd->panel.type == MIPI_CMD_PANEL))
		return;

	g_mfd = mfd;
	printk("###%s:%d: g_mfd: %p\n", __func__, __LINE__, g_mfd);
	iris_mgmt.iris_wq = create_singlethread_workqueue("iris_wq");
	INIT_WORK(&iris_mgmt.iris_worker, iris_cmds_tx);

	mfd->iris_conf.current_mode = IRIS_RFB_MODE;
	mfd->iris_conf.sf_notify_mode  = IRIS_MODE_RFB;
	mfd->iris_conf.fbo_enable = false;
	mfd->iris_conf.memc_enable = false;
	mfd->iris_conf.mode_switch_finish = true;
	mfd->iris_conf.sf_mode_change_start = false;
	mfd->iris_conf.repeat = IRIS_REPEAT_NO;
	mfd->iris_conf.video_on = false;
	mfd->iris_conf.rfb_path = IRIS_RFB_DATA_PATH_DEFAULT;
	mfd->iris_conf.pt_path  = IRIS_PT_DATA_PATH_DEFAULT;
	mfd->iris_conf.frc_path = IRIS_FRC_DATA_PATH_DEFAULT;
	atomic_set(&mfd->iris_conf.mode_switch_cnt, 0);
	mfd->iris_conf.input_frame_rate = 60;
	mfd->iris_conf.output_frame_rate = 60;
	mfd->iris_conf.input_vfr = 0;
	mfd->iris_conf.in_ratio = 1;
	mfd->iris_conf.out_ratio = 1;
	mfd->iris_conf.vp_continous = 0;
	mfd->iris_conf.nrv_enable = false;
	mfd->iris_conf.true_cut_enable = false;
	mfd->iris_conf.ready = false;
	mfd->iris_conf.prev_dvts = 0;
	mfd->iris_conf.iris_ratio_updated = false;
	mfd->iris_conf.cap_change = false;
	mfd->iris_conf.tx_switch_state = IRIS_TX_SWITCH_NONE;
	mfd->iris_conf.tx_switch_debug_flag = 0;
	mfd->iris_conf.lp_frc_timing = 0;
#if defined(CONFIG_IRIS2P_DRC_SUPPORT)
	mfd->iris_conf.drc_enable = false;
	mfd->iris_conf.drc_size = 0;
#endif
	memset((void *)&mfd->iris_conf.meta, 0, sizeof(struct iris_meta));
	memset((void *)&mfd->iris_conf.meta_set, 0, sizeof(struct iris_meta));
	memset((void *)&mfd->iris_conf.avail_mode, 0, sizeof(struct iris_available_mode));
	mfd->iris_conf.avail_mode.prefer_mode = IRIS_MODE_RFB;
	mfd->iris_conf.avail_mode.pt_threshold_low = 0;
	mfd->iris_conf.avail_mode.rfb_threshold_low = 0;
	mfd->iris_conf.avail_mode.rfb_threshold_high = 0;
	mfd->iris_conf.avail_mode.pt_threshold_high = 0;
	if (mfd->panel.type == MIPI_VIDEO_PANEL) {
		mfd->iris_conf.avail_mode.dsi_mode_in_rfb = DSI_VIDEO_MODE;
		mfd->iris_conf.avail_mode.dsi_mode_in_ptl = DSI_VIDEO_MODE;
		mfd->iris_conf.avail_mode.dsi_mode_in_pth = DSI_VIDEO_MODE;
	} else if (mfd->panel.type == MIPI_CMD_PANEL) {
		mfd->iris_conf.avail_mode.dsi_mode_in_rfb = DSI_CMD_MODE;
		mfd->iris_conf.avail_mode.dsi_mode_in_ptl = DSI_CMD_MODE;
		mfd->iris_conf.avail_mode.dsi_mode_in_pth = DSI_CMD_MODE;
	}
	spin_lock_init(&mfd->iris_conf.iris_reset_lock);
	iris_regs_clear();
	INIT_WORK(&mfd->iris_conf.pt_work, iris_pt_entry_wq_handler);
	INIT_WORK(&mfd->iris_conf.rfb_work, iris_rfb_entry_wq_handler);
	INIT_WORK(&mfd->iris_conf.pt_prepare_work, iris_pt_prepare_handler);
	INIT_WORK(&mfd->iris_conf.rfb_prepare_work, iris_rfb_prepare_handler);
	INIT_WORK(&mfd->iris_conf.memc_work, iris_memc_entry_handler);
	INIT_WORK(&mfd->iris_conf.memc_prepare_work, iris_memc_prepare_handler);
	INIT_WORK(&mfd->iris_conf.memc_cancel_work, iris_memc_cancel_handler);
	mutex_init(&mfd->iris_conf.cmd_mutex);
	mutex_init(&mfd->iris_conf.config_mutex);
	mutex_init(&mfd->iris_conf.meta_mutex);

	iris_debugfs_init(mfd);
	iris_i2c_bus_init();
}
