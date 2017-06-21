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
#include <linux/uaccess.h>

#include "mdss_mdp.h"
#include "mdss_fb.h"
#include "mdss_dsi.h"
#include "mdss_dsi_iris2p_lightup_priv.h"
//#include "mdss_dsi_iris2p_extern.h"
//#include "mdss_dsi_iris2p_mode_switch.h"
#include "mdss_dsi_iris2p.h"

struct iris_info_t iris_info;
static u8 iris_power_mode;
static u8 iris_signal_mode;
//static u16 iris_mipirx_status;
static u8 cmd_send_flag = 0;
char iris_read_cmd_buf[16];

static char grcp_header[GRCP_HEADER] = {
	PWIL_TAG('P', 'W', 'I', 'L'),
	PWIL_TAG('G', 'R', 'C', 'P'),
	PWIL_U32(0x3),
	0x00,
	0x00,
	PWIL_U16(0x2),
};
static struct iris_grcp_cmd init_cmd[INIT_CMD_NUM];
static struct iris_grcp_cmd grcp_cmd;
//static struct msm_fb_data_type *gp_mfd;
static struct mdss_dsi_ctrl_pdata *g_ctrl;
//static u8 *fw_buf = NULL;



//#define DUMP_DATA_FOR_BOOTLOADER
#ifdef DUMP_DATA_FOR_BOOTLOADER
void iris_dump_packet(u8 *data, int size)
{
	int i = 0;
	pr_err("size = %d\n", size);
	for (i = 0; i < size; i += 4)
		pr_err("0x%02x, 0x%02x, 0x%02x, 0x%02x,\n",
			*(data+i), *(data+i+1), *(data+i+2), *(data+i+3));
}
#define DUMP_PACKET   iris_dump_packet
#else
#define DUMP_PACKET(...)
#endif

static void iris_mipi_signal_mode_cb(int len)
{
	if (len != 1) {
		pr_err("%s: not short read responese, return len [%02x] != 1\n", __func__, len);
		return;
	}
	iris_signal_mode = (u8)iris_read_cmd_buf[0];
	pr_debug("signal mode [%02x]\n", iris_signal_mode);
}

u8 iris_mipi_signal_mode_read(struct mdss_dsi_ctrl_pdata *ctrl, int state)
{
	struct dcs_cmd_req cmdreq;
	char get_signal_mode[1] = {0x0e};
	struct dsi_cmd_desc iris_signal_mode_cmd = {
		{DTYPE_DCS_READ, 1, 0, 1, 0, sizeof(get_signal_mode)}, get_signal_mode};

	memset(&cmdreq, 0, sizeof(cmdreq));
	iris_signal_mode = 0xff;
	memset(iris_read_cmd_buf, 0, sizeof(iris_read_cmd_buf));

	cmdreq.cmds = &iris_signal_mode_cmd;
	cmdreq.cmds_cnt = 1;
	cmdreq.flags = CMD_REQ_RX | CMD_REQ_COMMIT;
	if (DSI_HS_MODE == state)
		cmdreq.flags |= CMD_REQ_HS_MODE;
	cmdreq.rlen = 1;
	cmdreq.rbuf = iris_read_cmd_buf;
	cmdreq.cb = iris_mipi_signal_mode_cb;
	mdss_dsi_cmdlist_put(ctrl, &cmdreq);

	return iris_signal_mode;
}


static void iris_mipi_power_mode_cb(int len)
{
	if (len != 1) {
		pr_err("%s: not short read responese, return len [%02x] != 1\n", __func__, len);
		return;
	}
	iris_power_mode = (u8)iris_read_cmd_buf[0];
	pr_debug("power mode [%02x]\n", iris_power_mode);
}

u8 iris_mipi_power_mode_read(struct mdss_dsi_ctrl_pdata *ctrl, int state)
{
	struct dcs_cmd_req cmdreq;
	char get_power_mode[1] = {0x0a};
	struct dsi_cmd_desc iris_power_mode_cmd = {
		{DTYPE_DCS_READ, 1, 0, 1, 0, sizeof(get_power_mode)}, get_power_mode};

	memset(&cmdreq, 0, sizeof(cmdreq));
	iris_power_mode = 0;
	memset(iris_read_cmd_buf, 0, sizeof(iris_read_cmd_buf));

	cmdreq.cmds = &iris_power_mode_cmd;
	cmdreq.cmds_cnt = 1;
	cmdreq.flags = CMD_REQ_RX | CMD_REQ_COMMIT;
	if (DSI_HS_MODE == state)
		cmdreq.flags |= CMD_REQ_HS_MODE;
	cmdreq.rlen = 1;
	cmdreq.rbuf = iris_read_cmd_buf;
	cmdreq.cb = iris_mipi_power_mode_cb;
	mdss_dsi_cmdlist_put(ctrl, &cmdreq);

	return iris_power_mode;
}


static void iris_dsi_cmds_send(struct mdss_dsi_ctrl_pdata *ctrl,
			struct dsi_panel_cmds *pcmds)
{
	struct dcs_cmd_req cmdreq;
	struct mdss_panel_info *pinfo;

	pinfo = &(ctrl->panel_data.panel_info);

	memset(&cmdreq, 0, sizeof(cmdreq));
	cmdreq.cmds = pcmds->cmds;
	cmdreq.cmds_cnt = pcmds->cmd_cnt;
	cmdreq.flags = CMD_REQ_COMMIT;

	if (pcmds->link_state == DSI_HS_MODE)
		cmdreq.flags |= CMD_REQ_HS_MODE;

	cmdreq.rlen = 0;
	cmdreq.cb = NULL;

	if (cmd_send_flag) {
		if (cmdreq.flags & CMD_REQ_HS_MODE)
			mdss_dsi_set_tx_power_mode(0, &ctrl->panel_data);
		mdss_dsi_cmdlist_put(ctrl, &cmdreq);
		if (cmdreq.flags & CMD_REQ_HS_MODE)
			mdss_dsi_set_tx_power_mode(1, &ctrl->panel_data);
	} else
		mdss_dsi_cmdlist_put(ctrl, &cmdreq);
}

int iris_power_mode_check(struct mdss_dsi_ctrl_pdata *ctrl, u8 value, int state)
{
#define RETRY_TIMES 5
	u8 cnt = 0, powermode = 0;

	do {
		powermode = iris_mipi_power_mode_read(ctrl, state);
		if (powermode == value)
			break;

		msleep(5);
		cnt++;
	} while ((powermode != value) && cnt < RETRY_TIMES);

	/* read failed */
	if (cnt == RETRY_TIMES) {
		pr_err("power mode check %x failed\n", value);
		return FAILED;
	} else
		pr_debug("power mode check %x success\n", value);

	return SUCCESS;
}


int iris_proxy_check_reset(struct mdss_dsi_ctrl_pdata *ctrl)
{
#define REBOOT_TIMES 5
	u8 cnt = 0, powermode = 0;
	int i;

	struct mdss_panel_info *panel_info = &(ctrl->panel_data.panel_info);

	do {
		powermode = iris_mipi_power_mode_read(ctrl, DSI_LP_MODE);

		pr_debug("read back powermode: %d, cnt: %d\n", powermode, cnt);

		if (powermode == 0x01)
			break;

		for (i = 0; i < panel_info->rst_seq_len; ++i) {
				gpio_set_value((ctrl->rst_gpio),
					panel_info->rst_seq[i]);
				if (panel_info->rst_seq[++i])
					usleep_range(panel_info->rst_seq[i] * 1000, panel_info->rst_seq[i] * 1000);
		}
		cnt++;
	} while ((powermode != 0x01) && cnt < REBOOT_TIMES);

	/* read failed */
	if (cnt == REBOOT_TIMES) {
		pr_err("reboot workaround, power mode check failed\n");
		return FAILED;
	} else
		pr_debug("reboot times, succeed, power mode check success\n");

	return SUCCESS;

}

void iris_workmode_parse(struct device_node *np,
							struct mdss_panel_info *panel_info, struct iris_info_t *piris_info)
{
	int rc;
	u32 iris_rx_ch = 1, iris_tx_ch = 1, iris_rx_dsc = 0, iris_tx_dsc = 0, iris_tx_mode = MIPI_VIDEO_MODE;
	u32 tmp, iris_rx_pxl_mod = 0, iris_tx_pxl_mod = 1;
	struct iris_work_mode *pwork_mode = &(piris_info->work_mode);
	const char *data;

	data = of_get_property(np, "qcom,iris-mipitx-type", NULL);
	if (data && !strncmp(data, "dsi_cmd_mode", 12))
		iris_tx_mode = MIPI_CMD_MODE;
	else
		iris_tx_mode = MIPI_VIDEO_MODE;

	rc = of_property_read_u32(np, "qcom,iris-mipirx-channel", &tmp);
	iris_rx_ch = (!rc ? tmp : 1);
	rc = of_property_read_u32(np, "qcom,iris-mipitx-channel", &tmp);
	iris_tx_ch = (!rc ? tmp : 1);
	rc = of_property_read_u32(np, "qcom,iris-mipirx-dsc", &tmp);
	iris_rx_dsc = (!rc ? tmp : 0);
	rc = of_property_read_u32(np, "qcom,iris-mipitx-dsc", &tmp);
	iris_tx_dsc = (!rc ? tmp : 0);
	rc = of_property_read_u32(np, "qcom,iris-mipirx-pxl-mode", &tmp);
	iris_rx_pxl_mod = (!rc ? tmp : 0);
	rc = of_property_read_u32(np, "qcom,iris-mipitx-pxl-mode", &tmp);
	iris_tx_pxl_mod = (!rc ? tmp : 1);

	/*iris mipirx mode*/
	pwork_mode->rx_mode = (DSI_VIDEO_MODE == panel_info->mipi.mode) ? MIPI_VIDEO_MODE : MIPI_CMD_MODE;
	pwork_mode->rx_ch = (iris_rx_ch == 1) ? 0 : 1;
	pwork_mode->rx_dsc = iris_rx_dsc;
	pwork_mode->rx_pxl_mode = iris_rx_pxl_mod;
	/*iris mipitx mode*/
	pwork_mode->tx_mode = iris_tx_mode;
	pwork_mode->tx_ch = (iris_tx_ch == 1) ? 0 : 1;
	pwork_mode->tx_dsc = iris_tx_dsc;
	pwork_mode->tx_pxl_mode = iris_tx_pxl_mod;

}

void iris_timing_parse(struct device_node *np,
						struct mdss_panel_info *panel_info, struct iris_info_t *piris_info)
{
	int rc = 0;
	u32 tmp;
	struct iris_timing_info *pinput_timing = &(piris_info->input_timing);
	struct iris_timing_info *poutput_timing = &(piris_info->output_timing);

	pinput_timing->hfp = panel_info->lcdc.h_front_porch;
	pinput_timing->hres = panel_info->xres;
	pinput_timing->hbp = panel_info->lcdc.h_back_porch;
	pinput_timing->hsw = panel_info->lcdc.h_pulse_width;

	pinput_timing->vfp = panel_info->lcdc.v_front_porch;
	pinput_timing->vres = panel_info->yres;
	pinput_timing->vbp = panel_info->lcdc.v_back_porch;
	pinput_timing->vsw = panel_info->lcdc.v_pulse_width;
	pinput_timing->fps = panel_info->mipi.frame_rate;

	rc = of_property_read_u32(np, "qcom,iris-out-panel-width", &tmp);
	if (rc) {
		/*copy input timing to output timing*/
		memcpy(poutput_timing, pinput_timing, sizeof(struct iris_timing_info));
	} else {
		/*parse output timing*/
		poutput_timing->hres = (!rc ? tmp : 640);

		rc = of_property_read_u32(np, "qcom,iris-out-panel-height", &tmp);
		poutput_timing->vres = (!rc ? tmp : 480);
		rc = of_property_read_u32(np, "qcom,iris-out-h-front-porch", &tmp);
		poutput_timing->hfp = (!rc ? tmp : 6);
		rc = of_property_read_u32(np, "qcom,iris-out-h-back-porch", &tmp);
		poutput_timing->hbp = (!rc ? tmp : 6);
		rc = of_property_read_u32(np, "qcom,iris-out-h-pulse-width", &tmp);
		poutput_timing->hsw = (!rc ? tmp : 2);
		rc = of_property_read_u32(np, "qcom,iris-out-v-back-porch", &tmp);
		poutput_timing->vbp = (!rc ? tmp : 6);
		rc = of_property_read_u32(np, "qcom,iris-out-v-front-porch", &tmp);
		poutput_timing->vfp = (!rc ? tmp : 6);
		rc = of_property_read_u32(np, "qcom,iris-out-v-pulse-width", &tmp);
		poutput_timing->vsw = (!rc ? tmp : 2);
		rc = of_property_read_u32(np, "qcom,iris-out-framerate", &tmp);
		poutput_timing->fps = (!rc ? tmp : 60);
	}

}

void iris_dsc_info_parse(struct device_node *np,
						struct mdss_panel_info *panel_info, struct iris_info_t *piris_info)
{
	int rc = 0;
	u32 tmp;
	struct iris_dsc_info *pinput_dsc = &(piris_info->input_dsc);
	struct iris_dsc_info *poutput_dsc = &(piris_info->output_dsc);

	/*parse input DSC para*/
	rc = of_property_read_u32(np, "qcom,iris-in-slice-number", &tmp);
	pinput_dsc->slice_number = (!rc ? tmp : 8);
	rc = of_property_read_u32(np, "qcom,iris-in-slice-height", &tmp);
	pinput_dsc->slice_height = (!rc ? tmp : 16);
	rc = of_property_read_u32(np, "qcom,iris-in-bpp", &tmp);
	pinput_dsc->bpp = (!rc ? tmp : 0x80);

	/*parse output DSC para*/
	rc = of_property_read_u32(np, "qcom,iris-in-slice-number", &tmp);
	poutput_dsc->slice_number = (!rc ? tmp : 8);
	rc = of_property_read_u32(np, "qcom,iris-in-slice-height", &tmp);
	poutput_dsc->slice_height = (!rc ? tmp : 16);
	rc = of_property_read_u32(np, "qcom,iris-in-bpp", &tmp);
	poutput_dsc->bpp = (!rc ? tmp : 0x80);
}

void iris_clock_tree_parse(struct device_node *np,
						struct mdss_panel_info *panel_info, struct iris_info_t *piris_info)
{
	int rc = 0, len = 0, cnt, num;
	struct iris_pll_setting *pll = &(piris_info->setting_info.pll_setting);
	struct iris_clock_source *clock = &(piris_info->setting_info.clock_setting.dclk);
	u32 data[12];
	const char *data1;
	struct property *prop;
	char clk_default[6] = {0xb, 0xb, 0x3, 0xb, 0x3, 0x0};

	prop = of_find_property(np, "qcom,iris-pll-setting", &num);
	num /= sizeof(u32);
	if (!prop || !num) {
		pr_info("parse error\n");
	} else {
		rc = of_property_read_u32_array(np, "qcom,iris-pll-setting", data, 12);
		if (rc) {
			pll->ppll_ctrl0 = 0x2;
			pll->ppll_ctrl1 = 0x3e1201;
			pll->ppll_ctrl2 = 0x800000;

			pll->dpll_ctrl0 = 0x2002;
			pll->dpll_ctrl1 = 0x3d1201;
			pll->dpll_ctrl2 = 0xe00000;

			pll->mpll_ctrl0 = 0x2;
			pll->mpll_ctrl1 = 0x3e0901;
			pll->mpll_ctrl2 = 0x800000;

			pll->txpll_div = 0x0;
			pll->txpll_sel = 0x2;
			pll->reserved = 0x0;
		} else {
			*pll = *((struct iris_pll_setting *)data);
		}
	}
	pr_info("%x, %x, %x, %x, %x, %x, %x, %x, %x, %x, %x, %x\n",
		pll->ppll_ctrl0, pll->ppll_ctrl1, pll->ppll_ctrl2,
		pll->dpll_ctrl0, pll->dpll_ctrl1, pll->dpll_ctrl2,
		pll->mpll_ctrl0, pll->mpll_ctrl1, pll->mpll_ctrl2,
		pll->txpll_div, pll->txpll_sel, pll->reserved);

	data1 = of_get_property(np, "qcom,iris-clock-setting", &len);
	if ((!data1) || (len != 6)) {
		data1 = clk_default;
	}
	for (cnt = 0; cnt < 6; cnt++) {
		clock->sel = data1[cnt] & 0xf;
		clock->div = (data1[cnt] >> 4) & 0xf;
		clock->div_en = !!clock->div;
		pr_info("%x %d, %d, %d\n", data1[cnt], clock->sel, clock->div, clock->div_en);
		clock++;
	}

}

void iris_setting_info_parse(struct device_node *np,
						struct mdss_panel_info *panel_info, struct iris_info_t *piris_info)
{
	int rc = 0;
	u32 tmp;
	struct device_node *settings_node = NULL;
	struct iris_setting_info *psetting_info = &(piris_info->setting_info);

	rc = of_property_read_u32(np, "qcom,mipirx-dsi-functional-program", &tmp);
	psetting_info->mipirx_dsi_functional_program = (!rc ? tmp : 0x62);
	rc = of_property_read_u32(np, "qcom,mipirx-eot-ecc-crc-disable", &tmp);
	psetting_info->mipirx_eot_ecc_crc_disable = (!rc ? tmp : 0);
	rc = of_property_read_u32(np, "qcom,mipirx-data-lane-timing-param", &tmp);
	psetting_info->mipirx_data_lane_timing_param = (!rc ? tmp : 0xff04);

	rc = of_property_read_u32(np, "qcom,mipitx-dsi-tx-ctrl", &tmp);
	psetting_info->mipitx_dsi_tx_ctrl = (!rc ? tmp : 0x0a004035);
	rc = of_property_read_u32(np, "qcom,mipitx-hs-tx-timer", &tmp);
	psetting_info->mipitx_hs_tx_timer = (!rc ? tmp : 0x00ffffff);
	rc = of_property_read_u32(np, "qcom,mipitx-bta-lp-timer", &tmp);
	psetting_info->mipitx_bta_lp_timer = (!rc ? tmp : 0x00ffff17);
	rc = of_property_read_u32(np, "qcom,mipitx-initialization-reset-timer", &tmp);
	psetting_info->mipitx_initialization_reset_timer = (!rc ? tmp : 0x0a8c07d0);
	rc = of_property_read_u32(np, "qcom,mipitx-dphy-timing-margin", &tmp);
	psetting_info->mipitx_dphy_timing_margin = (!rc ? tmp : 0x00040401);
	rc = of_property_read_u32(np, "qcom,mipitx-lp-timing-para", &tmp);
	psetting_info->mipitx_lp_timing_para = (!rc ? tmp : 0x1003000a);
	rc = of_property_read_u32(np, "qcom,mipitx-data-lane-timing-param1", &tmp);
	psetting_info->mipitx_data_lane_timing_param = (!rc ? tmp : 0x6030600);
	rc = of_property_read_u32(np, "qcom,mipitx-clock-lane-timing-param", &tmp);
	psetting_info->mipitx_clk_lane_timing_param = (!rc ? tmp : 0x07030d03);
	rc = of_property_read_u32(np, "qcom,mipitx-dphy-pll-para", &tmp);
	psetting_info->mipitx_dphy_pll_para = (!rc ? tmp : 0x000007d0);
	rc = of_property_read_u32(np, "qcom,mipitx-dphy-trim-1", &tmp);
	psetting_info->mipitx_dphy_trim_1 = (!rc ? tmp : 0xedb5384c);

	/*parse delta period for avsync*/
	rc = of_property_read_u32(np, "qcom,iris-delta-period-max", &tmp);
	psetting_info->delta_period_max = (!rc ? tmp : piris_info->output_timing.vfp);
	rc = of_property_read_u32(np, "qcom,iris-delta-period-min", &tmp);
	psetting_info->delta_period_min = (!rc ? (0 - tmp) : (0 - piris_info->output_timing.vfp));

	/*from root to find pxlw,mdss_iris_settings**/
	settings_node = of_find_node_by_name(NULL, "pxlw,mdss_iris_settings");
	if (settings_node) {
		struct iris_setting_disable_info * pdisable_info = &psetting_info->disable_info;

		rc = of_property_read_u32(settings_node, "pxlw,iris-last-frame-repeat-cnt", &tmp);
		pdisable_info->last_frame_repeat_cnt = (!rc ? tmp : 2);

		rc = of_property_read_u32(settings_node, "pxlw,iris-disable-dbc-dlv-sensitivity", &tmp);
		pdisable_info->dbc_dlv_sensitivity_disable_val = (!rc ? tmp : 0);
		rc = of_property_read_u32(settings_node, "pxlw,iris-disable-dbc-quality", &tmp);
		pdisable_info->dbc_quality_disable_val = (!rc ? tmp : 0);

		rc = of_property_read_u32(settings_node, "pxlw,iris-disable-pq-peaking", &tmp);
		pdisable_info->pq_peaking_disable_val = (!rc ? tmp : 0);
		rc = of_property_read_u32(settings_node, "pxlw,iris-disable-pq-peaking-demo", &tmp);
		pdisable_info->pq_peaking_demo_disable_val = (!rc ? tmp : 0);
		rc = of_property_read_u32(settings_node, "pxlw,iris-disable-pq-gamma", &tmp);
		pdisable_info->pq_gamma_disable_val = (!rc ? tmp : 0);
		rc = of_property_read_u32(settings_node, "pxlw,iris-disable-pq-contrast", &tmp);
		pdisable_info->pq_contrast_disable_val = (!rc ? tmp : 50);

		rc = of_property_read_u32(settings_node, "pxlw,iris-disable-color-adjust", &tmp);
		pdisable_info->color_adjust_disable_val = (!rc ? tmp : 0);

		rc = of_property_read_u32(settings_node, "pxlw,iris-disable-lce", &tmp);
		pdisable_info->lce_mode_disable_val = (!rc ? tmp : 0);

		rc = of_property_read_u32(settings_node, "pxlw,iris-disable-cm-c6axes", &tmp);
		pdisable_info->cm_c6axes_disable_val = (!rc ? tmp : 0);
		rc = of_property_read_u32(settings_node, "pxlw,iris-disable-cm-c3d", &tmp);
		pdisable_info->cm_c3d_disable_val = (!rc ? tmp : 0);
		rc = of_property_read_u32(settings_node, "pxlw,iris-disable-cm-fleshtone", &tmp);
		pdisable_info->cm_ftcen_disable_val = (!rc ? tmp : 0);
		rc = of_property_read_u32(settings_node, "pxlw,iris-disable-color-temp-en", &tmp);
		pdisable_info->color_temp_disable_val = (!rc ? tmp : 0);
		rc = of_property_read_u32(settings_node, "pxlw,iris-disable-reading-mode", &tmp);
		pdisable_info->reading_mode_disable_val= (!rc ? tmp : 0);

		/* init APP code default value */
		rc = of_property_read_u32(settings_node, "pxlw,iris-pq-peaking-default", &tmp);
		psetting_info->quality_def.pq_setting.peaking = (!rc ? tmp : 1);
		rc = of_property_read_u32(settings_node, "pxlw,iris-pq-sharpness-default", &tmp);
                psetting_info->quality_def.pq_setting.sharpness = (!rc ? tmp : 0);
		rc = of_property_read_u32(settings_node, "pxlw,iris-pq-peaking-demo-mode-default", &tmp);
		psetting_info->quality_def.pq_setting.peakingdemo = (!rc ? tmp : 0);
		rc = of_property_read_u32(settings_node, "pxlw,iris-pq-memc-demo-mode-default", &tmp);
		psetting_info->quality_def.pq_setting.memcdemo = (!rc ? tmp : 0);
		rc = of_property_read_u32(settings_node, "pxlw,iris-pq-memclevel-default", &tmp);
		psetting_info->quality_def.pq_setting.memclevel = (!rc ? tmp : 3);
		rc = of_property_read_u32(settings_node, "pxlw,iris-pq-gamma-mode-default", &tmp);
		psetting_info->quality_def.pq_setting.gamma = (!rc ? tmp : 0);
		rc = of_property_read_u32(settings_node, "pxlw,iris-pq-contrast-default", &tmp);
		psetting_info->quality_def.pq_setting.contrast = (!rc ? tmp : 0x32);
		rc = of_property_read_u32(settings_node, "pxlw,iris-pq-cinema-default", &tmp);
                psetting_info->quality_def.pq_setting.cinema_en = (!rc ? tmp : 0x00);

		rc = of_property_read_u32(settings_node, "pxlw,iris-cabcmode-default", &tmp);
		psetting_info->quality_def.dbc_setting.cabcmode = (!rc ? tmp : 1);

		rc = of_property_read_u32(settings_node, "pxlw,iris-color-adjust-default", &tmp);
		psetting_info->quality_def.color_adjust = (!rc ? tmp : 0x32);

		rc = of_property_read_u32(settings_node, "pxlw,iris-lce-mode-default", &tmp);
                psetting_info->quality_def.lce_setting.mode = (!rc ? tmp : 0x00);
		rc = of_property_read_u32(settings_node, "pxlw,iris-lce-mode1-level-default", &tmp);
                psetting_info->quality_def.lce_setting.mode1level = (!rc ? tmp : 0x01);
		rc = of_property_read_u32(settings_node, "pxlw,iris-lce-mode2-level-default", &tmp);
                psetting_info->quality_def.lce_setting.mode2level = (!rc ? tmp : 0x01);
		rc = of_property_read_u32(settings_node, "pxlw,iris-lce-demo-mode-default", &tmp);
                psetting_info->quality_def.lce_setting.demomode = (!rc ? tmp : 0x00);

		rc = of_property_read_u32(settings_node, "pxlw,iris-lux-value-default", &tmp);
                psetting_info->quality_def.lux_value.luxvalue= (!rc ? tmp : 0x00);

		rc = of_property_read_u32(settings_node, "pxlw,iris-cct-value-default", &tmp);
                psetting_info->quality_def.cct_value.cctvalue= (!rc ? tmp : 0x00);

		rc = of_property_read_u32(settings_node, "pxlw,iris-reading-mode-default", &tmp);
				psetting_info->quality_def.reading_mode.readingmode= (!rc ? tmp : 0x00);

		rc = of_property_read_u32(settings_node, "pxlw,iris-cm-6axes-default", &tmp);
                psetting_info->quality_def.cm_setting.cm6axes = (!rc ? tmp : 0x00);
		rc = of_property_read_u32(settings_node, "pxlw,iris-cm-3d-default", &tmp);
                psetting_info->quality_def.cm_setting.cm3d = (!rc ? tmp : 0x00);
		rc = of_property_read_u32(settings_node, "pxlw,iris-cm-demo-mode-default", &tmp);
                psetting_info->quality_def.cm_setting.demomode = (!rc ? tmp : 0x00);
		rc = of_property_read_u32(settings_node, "pxlw,iris-cm-fleshtone-default", &tmp);
                psetting_info->quality_def.cm_setting.ftc_en = (!rc ? tmp : 0x00);
		rc = of_property_read_u32(settings_node, "pxlw,iris-color-temp-en-default", &tmp);
		psetting_info->quality_def.cm_setting.color_temp_en= (!rc ? tmp : 0x00);
		rc = of_property_read_u32(settings_node, "pxlw,iris-color-temp-default", &tmp);
		psetting_info->quality_def.cm_setting.color_temp= (!rc ? tmp : 0x00);
		rc = of_property_read_u32(settings_node, "pxlw,iris-sensor-auto-en-default", &tmp);
		psetting_info->quality_def.cm_setting.sensor_auto_en= (!rc ? tmp : 0x00);

		/* init AP default value */
		rc = of_property_read_u32(settings_node, "pxlw,iris-pq-peaking-init", &tmp);
		psetting_info->quality_cur.pq_setting.peaking = (!rc ? tmp : 1);
		rc = of_property_read_u32(settings_node, "pxlw,iris-pq-sharpness-init", &tmp);
                psetting_info->quality_cur.pq_setting.sharpness = (!rc ? tmp : 0);
		rc = of_property_read_u32(settings_node, "pxlw,iris-pq-peaking-demo-mode-init", &tmp);
		psetting_info->quality_cur.pq_setting.peakingdemo = (!rc ? tmp : 0);
		rc = of_property_read_u32(settings_node, "pxlw,iris-pq-memc-demo-mode-init", &tmp);
		psetting_info->quality_cur.pq_setting.memcdemo = (!rc ? tmp : 0);
		rc = of_property_read_u32(settings_node, "pxlw,iris-pq-memclevel-init", &tmp);
		psetting_info->quality_cur.pq_setting.memclevel = (!rc ? tmp : 3);
		rc = of_property_read_u32(settings_node, "pxlw,iris-pq-gamma-mode-init", &tmp);
		psetting_info->quality_cur.pq_setting.gamma = (!rc ? tmp : 0);
		rc = of_property_read_u32(settings_node, "pxlw,iris-pq-contrast-init", &tmp);
		psetting_info->quality_cur.pq_setting.contrast = (!rc ? tmp : 0x32);
		rc = of_property_read_u32(settings_node, "pxlw,iris-pq-cinema-init", &tmp);
                psetting_info->quality_cur.pq_setting.cinema_en = (!rc ? tmp : 0x00);

		rc = of_property_read_u32(settings_node, "pxlw,iris-cabcmode-init", &tmp);
		psetting_info->quality_cur.dbc_setting.cabcmode = (!rc ? tmp : 1);

		rc = of_property_read_u32(settings_node, "pxlw,iris-color-adjust-init", &tmp);
		psetting_info->quality_cur.color_adjust = (!rc ? tmp : 0x32);

		rc = of_property_read_u32(settings_node, "pxlw,iris-lce-mode-init", &tmp);
		psetting_info->quality_cur.lce_setting.mode = (!rc ? tmp : 0x00);
		rc = of_property_read_u32(settings_node, "pxlw,iris-lce-mode1-level-init", &tmp);
		psetting_info->quality_cur.lce_setting.mode1level = (!rc ? tmp : 0x01);
		rc = of_property_read_u32(settings_node, "pxlw,iris-lce-mode2-level-init", &tmp);
		psetting_info->quality_cur.lce_setting.mode2level = (!rc ? tmp : 0x01);
		rc = of_property_read_u32(settings_node, "pxlw,iris-lce-demo-mode-init", &tmp);
		psetting_info->quality_cur.lce_setting.demomode = (!rc ? tmp : 0x00);

		rc = of_property_read_u32(settings_node, "pxlw,iris-lux-value-init", &tmp);
		psetting_info->quality_cur.lux_value.luxvalue= (!rc ? tmp : 0x00);

		rc = of_property_read_u32(settings_node, "pxlw,iris-cct-value-init", &tmp);
		psetting_info->quality_cur.cct_value.cctvalue= (!rc ? tmp : 0x00);

		rc = of_property_read_u32(settings_node, "pxlw,iris-reading-mode-init", &tmp);
		psetting_info->quality_cur.reading_mode.readingmode= (!rc ? tmp : 0x00);

		rc = of_property_read_u32(settings_node, "pxlw,iris-cm-6axes-init", &tmp);
		psetting_info->quality_cur.cm_setting.cm6axes = (!rc ? tmp : 0x00);
		rc = of_property_read_u32(settings_node, "pxlw,iris-cm-3d-init", &tmp);
		psetting_info->quality_cur.cm_setting.cm3d = (!rc ? tmp : 0x00);
		rc = of_property_read_u32(settings_node, "pxlw,iris-cm-demo-mode-init", &tmp);
		psetting_info->quality_cur.cm_setting.demomode = (!rc ? tmp : 0x00);
		rc = of_property_read_u32(settings_node, "pxlw,iris-cm-fleshtone-init", &tmp);
		psetting_info->quality_cur.cm_setting.ftc_en = (!rc ? tmp : 0x00);
		rc = of_property_read_u32(settings_node, "pxlw,iris-color-temp-en-init", &tmp);
		psetting_info->quality_cur.cm_setting.color_temp_en= (!rc ? tmp : 0x00);
		rc = of_property_read_u32(settings_node, "pxlw,iris-color-temp-init", &tmp);
		psetting_info->quality_cur.cm_setting.color_temp= (!rc ? tmp : 0x00);
		rc = of_property_read_u32(settings_node, "pxlw,iris-sensor-auto-en-init", &tmp);
		psetting_info->quality_cur.cm_setting.sensor_auto_en= (!rc ? tmp : 0x00);
	} else {
		pr_err("could not find pxlw,mdss_iris_settings child\n");
	}
}

int iris_dsi_parse_dcs_cmds(struct device_node *np,
		struct dsi_panel_cmds *pcmds, char *cmd_key, char *link_key)
{
	const char *data;
	int blen = 0, len;
	char *buf, *bp;
	struct dsi_ctrl_hdr *dchdr;
	int i, cnt;

	data = of_get_property(np, cmd_key, &blen);
	if (!data) {
		pr_err("%s: failed, key=%s\n", __func__, cmd_key);
		return -ENOMEM;
	}

	buf = kzalloc(sizeof(char) * blen, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	memcpy(buf, data, blen);

	/* scan dcs commands */
	bp = buf;
	len = blen;
	cnt = 0;
	while (len >= sizeof(*dchdr)) {
		dchdr = (struct dsi_ctrl_hdr *)bp;
		dchdr->dlen = ntohs(dchdr->dlen);
		if (dchdr->dlen > len) {
			pr_err("%s: dtsi cmd=%x error, len=%d",
				__func__, dchdr->dtype, dchdr->dlen);
			goto exit_free;
		}
		bp += sizeof(*dchdr);
		len -= sizeof(*dchdr);
		bp += dchdr->dlen;
		len -= dchdr->dlen;
		cnt++;
	}

	if (len != 0) {
		pr_err("%s: dcs_cmd=%x len=%d error!",
				__func__, buf[0], blen);
		goto exit_free;
	}

	pcmds->cmds = kzalloc(cnt * sizeof(struct dsi_cmd_desc),
						GFP_KERNEL);
	if (!pcmds->cmds)
		goto exit_free;

	pcmds->cmd_cnt = cnt;
	pcmds->buf = buf;
	pcmds->blen = blen;

	bp = buf;
	len = blen;
	for (i = 0; i < cnt; i++) {
		dchdr = (struct dsi_ctrl_hdr *)bp;
		len -= sizeof(*dchdr);
		bp += sizeof(*dchdr);
		pcmds->cmds[i].dchdr = *dchdr;
		pcmds->cmds[i].payload = bp;
		bp += dchdr->dlen;
		len -= dchdr->dlen;
	}

	/*Set default link state to LP Mode*/
	pcmds->link_state = DSI_LP_MODE;

	if (link_key) {
		data = of_get_property(np, link_key, NULL);
		if (data && !strcmp(data, "dsi_hs_mode"))
			pcmds->link_state = DSI_HS_MODE;
		else
			pcmds->link_state = DSI_LP_MODE;
	}

	pr_debug("%s: dcs_cmd=%x len=%d, cmd_cnt=%d link_state=%d\n", __func__,
		pcmds->buf[0], pcmds->blen, pcmds->cmd_cnt, pcmds->link_state);

	return 0;

exit_free:
	kfree(buf);
	return -ENOMEM;
}

void iris_on_cmds_parse(struct device_node *np, struct mdss_dsi_ctrl_pdata *ctrl_pdata)
{
	if (MIPI_VIDEO_MODE == iris_info.work_mode.tx_mode)
		iris_dsi_parse_dcs_cmds(np, &ctrl_pdata->on_cmds,
			"qcom,mdss-dsi-on-command-to-video-panel", "qcom,mdss-dsi-on-command-to-video-panel-state");
	else
		iris_dsi_parse_dcs_cmds(np, &ctrl_pdata->on_cmds,
			"qcom,mdss-dsi-on-command-to-cmd-panel", "qcom,mdss-dsi-on-command-to-cmd-panel-state");
}

void iris_off_cmds_parse(struct device_node *np, struct mdss_dsi_ctrl_pdata *ctrl_pdata)
{
	if (MIPI_VIDEO_MODE == iris_info.work_mode.tx_mode)
		iris_dsi_parse_dcs_cmds(np, &ctrl_pdata->off_cmds,
			"qcom,mdss-dsi-off-command-to-video-panel", "qcom,mdss-dsi-off-command-to-video-panel-state");
	else
		iris_dsi_parse_dcs_cmds(np, &ctrl_pdata->off_cmds,
			"qcom,mdss-dsi-off-command-to-cmd-panel", "qcom,mdss-dsi-off-command-to-cmd-panel-state");
}

void iris_tx_switch_cmd_parse(struct device_node *np, struct iris_info_t *piris_info)
{
	//struct iris_tx_switch_cmd *ptx_switch_cmd = &(piris_info->tx_switch_cmd);

	//iris_dsi_parse_dcs_cmds(np, &(ptx_switch_cmd->mipitx_vid2cmd_cmds),
	//		"qcom,video-to-cmd-mode-switch-commands", "qcom,video-to-cmd-mode-switch-commands-state");
	//iris_dsi_parse_dcs_cmds(np, &(ptx_switch_cmd->mipitx_cmd2vid_cmds),
	//		"qcom,cmd-to-video-mode-switch-commands", "qcom,cmd-to-video-mode-switch-commands-state");

}

void iris_intf_switch_info_parse(struct device_node *np, struct iris_info_t *piris_info)
{
	struct iris_intf_switch_info *pswitch_info = &(piris_info->intf_switch_info);

	pswitch_info->rx_switch_enable = of_property_read_bool(np,
			"qcom,dynamic-mode-switch-enabled");
	pswitch_info->rx_current_mode = piris_info->work_mode.rx_mode;

	pswitch_info->tx_switch_enable = of_property_read_bool(np,
			"iris,mipitx-dynamic-mode-switch-enabled");
	pswitch_info->tx_current_mode = piris_info->work_mode.tx_mode;

}

void iris_analog_bypass_info_parse(struct device_node *np, struct iris_info_t *piris_info)
{
	struct iris_abypass_ctrl *pabypss_ctrl = &(piris_info->abypss_ctrl);

	pabypss_ctrl->analog_bypass_enable = of_property_read_bool(np,
			"iris,analog-bypass-mode-enabled");

	pabypss_ctrl->abypass_status = PASS_THROUGH_MODE;
	pabypss_ctrl->abypass_debug = false;
	pabypss_ctrl->abypass_to_pt_enable = 0;
	pabypss_ctrl->pt_to_abypass_enable = 0;
	pabypss_ctrl->abypss_switch_state = MCU_STOP_ENTER_STATE;
	pabypss_ctrl->base_time = 0;
	pabypss_ctrl->frame_delay = 0;

}

void iris_info_structure_init(void)
{
	memset(&iris_info, 0, sizeof(iris_info));

	iris_info.firmware_info.firmware_size = 0x40000;
	iris_info.firmware_info.fw_dw_result = FAILED;
}


void iris_init_params_parse(struct device_node *np, struct mdss_dsi_ctrl_pdata *ctrl_pdata)
{
	struct mdss_panel_info *panel_info = &(ctrl_pdata->panel_data.panel_info);

	if (panel_info->pdest == DISPLAY_1) {
		iris_info_structure_init();
		g_ctrl = ctrl_pdata;

		iris_workmode_parse(np, panel_info, &iris_info);
		iris_timing_parse(np, panel_info, &iris_info);
		iris_dsc_info_parse(np, panel_info, &iris_info);
		iris_clock_tree_parse(np, panel_info, &iris_info);
		iris_setting_info_parse(np, panel_info, &iris_info);
		iris_tx_switch_cmd_parse(np, &iris_info);
		iris_intf_switch_info_parse(np, &iris_info);
		iris_analog_bypass_info_parse(np, &iris_info);

		iris_info.panel_cmd_sync_wait_broadcast = of_property_read_bool(
			np, "qcom,iris-panel-cmd-sync-wait-broadcast");
	}
	if (iris_info.work_mode.rx_mode != iris_info.work_mode.tx_mode) {
		iris_on_cmds_parse(np, ctrl_pdata);
		iris_off_cmds_parse(np, ctrl_pdata);
	}
}

void iris_cmd_reg_add(struct iris_grcp_cmd *pcmd, u32 addr, u32 val)
{
	*(u32 *)(pcmd->cmd + pcmd->cmd_len) = cpu_to_le32(addr);
	*(u32 *)(pcmd->cmd + pcmd->cmd_len + 4) = cpu_to_le32(val);
	pcmd->cmd_len += 8;
}

void iris_sys_reg_config(struct iris_info_t *piris_info, struct iris_grcp_cmd *pcmd)
{
	u32 clkmux_ctrl = 0x42180100, clkdiv_ctrl = 0x08;
	struct iris_pll_setting *pll = &piris_info->setting_info.pll_setting;
	struct iris_clock_setting *clock = &piris_info->setting_info.clock_setting;

	iris_cmd_reg_add(pcmd, IRIS_SYS_ADDR + CLKMUX_CTRL, clkmux_ctrl | (clock->escclk.sel << 11) | pll->txpll_sel);
	iris_cmd_reg_add(pcmd, IRIS_SYS_ADDR + CLKDIV_CTRL, clkdiv_ctrl | (clock->escclk.div << 3) | (clock->escclk.div_en << 7));

	iris_cmd_reg_add(pcmd, IRIS_SYS_ADDR + DCLK_SRC_SEL, clock->dclk.sel | (clock->dclk.div << 8) | (clock->dclk.div_en << 10));
	iris_cmd_reg_add(pcmd, IRIS_SYS_ADDR + INCLK_SRC_SEL, clock->inclk.sel | (clock->inclk.div << 8) | (clock->inclk.div_en << 10));
	iris_cmd_reg_add(pcmd, IRIS_SYS_ADDR + MCUCLK_SRC_SEL, clock->mcuclk.sel | (clock->mcuclk.div << 8) | (clock->mcuclk.div_en << 12));
	iris_cmd_reg_add(pcmd, IRIS_SYS_ADDR + PCLK_SRC_SEL, clock->pclk.sel | (clock->pclk.div << 8) | (clock->pclk.div_en << 10));
	iris_cmd_reg_add(pcmd, IRIS_SYS_ADDR + MCLK_SRC_SEL, clock->mclk.sel | (clock->mclk.div << 8) | (clock->mclk.div_en << 10));

	iris_cmd_reg_add(pcmd, IRIS_SYS_ADDR + PPLL_B_CTRL0, pll->ppll_ctrl0);
	iris_cmd_reg_add(pcmd, IRIS_SYS_ADDR + PPLL_B_CTRL1, pll->ppll_ctrl1);
	iris_cmd_reg_add(pcmd, IRIS_SYS_ADDR + PPLL_B_CTRL2, pll->ppll_ctrl2);

	iris_cmd_reg_add(pcmd, IRIS_SYS_ADDR + DPLL_B_CTRL0, pll->dpll_ctrl0);
	iris_cmd_reg_add(pcmd, IRIS_SYS_ADDR + DPLL_B_CTRL1, pll->dpll_ctrl1);
	iris_cmd_reg_add(pcmd, IRIS_SYS_ADDR + DPLL_B_CTRL2, pll->dpll_ctrl2);

	iris_cmd_reg_add(pcmd, IRIS_SYS_ADDR + MPLL_B_CTRL0, pll->mpll_ctrl0);
	iris_cmd_reg_add(pcmd, IRIS_SYS_ADDR + MPLL_B_CTRL1, pll->mpll_ctrl1);
	iris_cmd_reg_add(pcmd, IRIS_SYS_ADDR + MPLL_B_CTRL2, pll->mpll_ctrl2);

	iris_cmd_reg_add(pcmd, IRIS_SYS_ADDR + PLL_CTRL, 0x1800e);
	iris_cmd_reg_add(pcmd, IRIS_SYS_ADDR + PLL_CTRL, 0x18000);
}

void iris_mipirx_reg_config(struct iris_info_t *piris_info, struct iris_grcp_cmd *pcmd)
{
	struct iris_work_mode *pwork_mode = &(piris_info->work_mode);
	struct iris_timing_info *pinput_timing = &(piris_info->input_timing);
	struct iris_setting_info *psetting_info = &(piris_info->setting_info);
	u32 dbi_handler_ctrl = 0, frame_col_addr = 0;
	u32 rx_ch, mipirx_addr = IRIS_MIPI_RX_ADDR;

	for (rx_ch = 0; rx_ch < (pwork_mode->rx_ch + 1); rx_ch++) {
#ifdef MIPI_SWAP
		mipirx_addr -= rx_ch * IRIS_MIPI_ADDR_OFFSET;
#else
		mipirx_addr += rx_ch * IRIS_MIPI_ADDR_OFFSET;
#endif
		iris_cmd_reg_add(pcmd, mipirx_addr + DEVICE_READY, 0x00000000);
		/*reset for DFE*/
		iris_cmd_reg_add(pcmd, mipirx_addr + RESET_ENABLE_DFE, 0x00000000);
		iris_cmd_reg_add(pcmd, mipirx_addr + RESET_ENABLE_DFE, 0x00000001);

		dbi_handler_ctrl = 0xf0000 + (pwork_mode->rx_ch << 23);
		/* left side enable */
		if (pwork_mode->rx_ch && (0 == rx_ch))
		dbi_handler_ctrl += (1 << 24);
		/*ext_mipi_rx_ctrl*/
		if (1 == rx_ch)
			dbi_handler_ctrl += (1 << 22);
		iris_cmd_reg_add(pcmd, mipirx_addr + DBI_HANDLER_CTRL, dbi_handler_ctrl);

		if (pwork_mode->rx_mode) {
			frame_col_addr = (pwork_mode->rx_ch) ? (pinput_timing->hres * 2 - 1) : (pinput_timing->hres - 1);
			iris_cmd_reg_add(pcmd, mipirx_addr + FRAME_COLUMN_ADDR, frame_col_addr << 16);
			iris_cmd_reg_add(pcmd, mipirx_addr + ABNORMAL_COUNT_THRES, 0xffffffff);
		}
		iris_cmd_reg_add(pcmd, mipirx_addr + INTEN, 0x3);
		iris_cmd_reg_add(pcmd, mipirx_addr + INTERRUPT_ENABLE, 0x0);
		iris_cmd_reg_add(pcmd, mipirx_addr + DSI_FUNCTIONAL_PROGRAMMING, psetting_info->mipirx_dsi_functional_program);
		iris_cmd_reg_add(pcmd, mipirx_addr + EOT_ECC_CRC_DISABLE, psetting_info->mipirx_eot_ecc_crc_disable);
		iris_cmd_reg_add(pcmd, mipirx_addr + DATA_LANE_TIMING_PARAMETER, psetting_info->mipirx_data_lane_timing_param);
		iris_cmd_reg_add(pcmd, mipirx_addr + DPI_SYNC_COUNT, pinput_timing->hsw + (pinput_timing->vsw << 16));
		iris_cmd_reg_add(pcmd, mipirx_addr + DEVICE_READY, 0x00000001);
	}
}

void iris_mipitx_reg_config(struct iris_info_t *piris_info, struct iris_grcp_cmd *pcmd)
{
	struct iris_work_mode *pwork_mode = &(piris_info->work_mode);
	struct iris_setting_info *psetting_info = &(piris_info->setting_info);
	struct iris_timing_info *poutput_timing = &(piris_info->output_timing);
	u32 tx_ch, mipitx_addr = IRIS_MIPI_TX_ADDR, dual_ch_ctrl, dsi_tx_ctrl = 0;
	u32 ddrclk_div, ddrclk_div_en;

	ddrclk_div = piris_info->setting_info.pll_setting.txpll_div;
	ddrclk_div_en = !!ddrclk_div;

	for (tx_ch = 0; tx_ch < (pwork_mode->tx_ch + 1); tx_ch++) {
#ifdef MIPI_SWAP
		mipitx_addr -= tx_ch * IRIS_MIPI_ADDR_OFFSET;
#else
		mipitx_addr += tx_ch * IRIS_MIPI_ADDR_OFFSET;
#endif

		if (pwork_mode->tx_mode)
			dsi_tx_ctrl = psetting_info->mipitx_dsi_tx_ctrl | (0x1 << 8);
		else
			dsi_tx_ctrl = psetting_info->mipitx_dsi_tx_ctrl & (~(0x1 << 8));
		iris_cmd_reg_add(pcmd, mipitx_addr + DSI_TX_CTRL, dsi_tx_ctrl & 0xfffffffe);

		iris_cmd_reg_add(pcmd, mipitx_addr + DPHY_TIMING_MARGIN, psetting_info->mipitx_dphy_timing_margin);
#ifdef FPGA_DEBUG
		iris_cmd_reg_add(pcmd, mipitx_addr + DPHY_LP_TIMING_PARA, psetting_info->mipitx_lp_timing_para + 0x6600);
#else
		iris_cmd_reg_add(pcmd, mipitx_addr + DPHY_LP_TIMING_PARA, psetting_info->mipitx_lp_timing_para);
#endif
		iris_cmd_reg_add(pcmd, mipitx_addr + DPHY_DATA_LANE_TIMING_PARA, psetting_info->mipitx_data_lane_timing_param);
		iris_cmd_reg_add(pcmd, mipitx_addr + DPHY_CLOCK_LANE_TIMING_PARA, psetting_info->mipitx_clk_lane_timing_param);
		//iris_cmd_reg_add(pcmd, mipitx_addr + DPHY_PLL_PARA, psetting_info->mipitx_dphy_pll_para);
		iris_cmd_reg_add(pcmd, mipitx_addr + DPHY_TRIM_1, psetting_info->mipitx_dphy_trim_1);
		iris_cmd_reg_add(pcmd, mipitx_addr + DPHY_CTRL, 1 | (ddrclk_div << 26) | (ddrclk_div_en << 28));

		if (pwork_mode->tx_ch) {
			dual_ch_ctrl = pwork_mode->tx_ch + ((poutput_timing->hres * 2) << 16);
			if (0 == tx_ch)
				dual_ch_ctrl += 1 << 1;
			iris_cmd_reg_add(pcmd, mipitx_addr + DUAL_CH_CTRL, dual_ch_ctrl);
		}
		iris_cmd_reg_add(pcmd, mipitx_addr + HS_TX_TIMER, psetting_info->mipitx_hs_tx_timer);
		iris_cmd_reg_add(pcmd, mipitx_addr + BTA_LP_TIMER, psetting_info->mipitx_bta_lp_timer);
		iris_cmd_reg_add(pcmd, mipitx_addr + INITIALIZATION_RESET_TIMER, psetting_info->mipitx_initialization_reset_timer);

		iris_cmd_reg_add(pcmd, mipitx_addr + TX_RESERVED_0, 4);

		iris_cmd_reg_add(pcmd, mipitx_addr + DSI_TX_CTRL, dsi_tx_ctrl);
	}

}

void iris_init_cmd_setup(struct mdss_dsi_ctrl_pdata *ctrl_pdata)
{
	u32 cnt = 0, grcp_len = 0;
	struct mdss_panel_info *panel_info = &(ctrl_pdata->panel_data.panel_info);
	spin_lock_init(&ctrl_pdata->iris_lock);

	if (DISPLAY_1 == panel_info->pdest) {
		memset(init_cmd, 0, sizeof(init_cmd));
		for (cnt = 0; cnt < INIT_CMD_NUM; cnt++) {
			memcpy(init_cmd[cnt].cmd, grcp_header, GRCP_HEADER);
			init_cmd[cnt].cmd_len = GRCP_HEADER;
		}

		iris_mipitx_reg_config(&iris_info, &init_cmd[0]);
		iris_mipirx_reg_config(&iris_info, &init_cmd[1]);
		iris_sys_reg_config(&iris_info, &init_cmd[1]);

		for (cnt = 0; cnt < INIT_CMD_NUM; cnt++) {
			grcp_len = (init_cmd[cnt].cmd_len - GRCP_HEADER) / 4;
			*(u32 *)(init_cmd[cnt].cmd + 8) = cpu_to_le32(grcp_len + 1);
			*(u16 *)(init_cmd[cnt].cmd + 14) = cpu_to_le16(grcp_len);
		}
	}
}

void iris_mipirx_mode_set(struct mdss_dsi_ctrl_pdata *ctrl, int mode, int state)
{
	char mipirx_mode[1] = {0x3f};
	struct dsi_cmd_desc iris_mipirx_mode_cmds[] = {
		{{ DTYPE_GEN_WRITE1, 1, 0, 0, CMD_PROC, sizeof(mipirx_mode)}, mipirx_mode},
	};
	struct dsi_panel_cmds panel_cmds;

	switch (mode) {
	case MCU_VIDEO:
		mipirx_mode[0] = 0x3f;
		break;
	case MCU_CMD:
		mipirx_mode[0] = 0x1f;
		break;
	case PWIL_VIDEO:
		mipirx_mode[0] = 0xbf;
		break;
	case PWIL_CMD:
		mipirx_mode[0] = 0x7f;
		break;
	case BYPASS_VIDEO:
		mipirx_mode[0] = 0xff;
		break;
	case BYPASS_CMD:
		mipirx_mode[0] = 0xdf;
		break;
	default:
		break;
	}
	pr_debug("iris: set mipirx mode: %d\n", mode);

	panel_cmds.cmds = iris_mipirx_mode_cmds;
	panel_cmds.cmd_cnt = ARRAY_SIZE(iris_mipirx_mode_cmds);
	panel_cmds.link_state = state;
	iris_dsi_cmds_send(ctrl, &panel_cmds);

	DUMP_PACKET(mipirx_mode ,sizeof(mipirx_mode));
}

void iris_init_cmd_send(struct mdss_dsi_ctrl_pdata *ctrl, int state)
{
	struct dsi_cmd_desc iris_init_info_cmds[] = {
		{{DTYPE_GEN_LWRITE, 1, 0, 0, CMD_PROC, CMD_PKT_SIZE}, init_cmd[0].cmd},
		{{DTYPE_GEN_LWRITE, 1, 0, 0, MCU_PROC * 2, CMD_PKT_SIZE}, init_cmd[1].cmd},
	};
	struct dsi_panel_cmds panel_cmds;

	iris_init_info_cmds[0].dchdr.dlen = init_cmd[0].cmd_len;
	iris_init_info_cmds[1].dchdr.dlen = init_cmd[1].cmd_len;

	pr_debug("iris: send init cmd\n");

	panel_cmds.cmds = iris_init_info_cmds;
	panel_cmds.cmd_cnt = ARRAY_SIZE(iris_init_info_cmds);
	panel_cmds.link_state = state;
	iris_dsi_cmds_send(ctrl, &panel_cmds);

	DUMP_PACKET(init_cmd[0].cmd, init_cmd[0].cmd_len);
	DUMP_PACKET(init_cmd[1].cmd, init_cmd[1].cmd_len);
}

#if 0
void iris_timing_info_send(struct mdss_dsi_ctrl_pdata *ctrl, int state)
{
	char iris_workmode[] = {
		0x80, 0x87, 0x0, 0x3,
		PWIL_U32(0x0),
	};
	char iris_timing[] = {
		0x80, 0x87, 0x0, 0x0,
		PWIL_U32(0x01e00010),
		PWIL_U32(0x00160010),
		PWIL_U32(0x0320000a),
		PWIL_U32(0x00080008),
		PWIL_U32(0x3c1f),
		PWIL_U32(0x01e00014),
		PWIL_U32(0x00160010),
		PWIL_U32(0x0320000a),
		PWIL_U32(0x00080008),
		PWIL_U32(0x3c1f),
		PWIL_U32(0x00100008),
		PWIL_U32(0x80),
		PWIL_U32(0x00100008),
		PWIL_U32(0x80)
	};
	struct dsi_cmd_desc iris_timing_info_cmd[] = {
		{{DTYPE_GEN_LWRITE, 1, 0, 0, MCU_PROC, sizeof(iris_workmode)}, iris_workmode},
		{{DTYPE_GEN_LWRITE, 1, 0, 0, MCU_PROC, sizeof(iris_timing)}, iris_timing}
	};
	struct iris_timing_info *pinput_timing = &(iris_info.input_timing);
	struct iris_timing_info *poutput_timing = &(iris_info.output_timing);
	struct iris_dsc_info *pinput_dsc = &(iris_info.input_dsc);
	struct iris_dsc_info *poutput_dsc = &(iris_info.output_dsc);
	struct dsi_panel_cmds panel_cmds;

	memcpy(iris_workmode + 4, &(iris_info.work_mode), 4);

	*(u32 *)(iris_timing + 4) = cpu_to_le32((pinput_timing->hres << 16) + pinput_timing->hfp);
	*(u32 *)(iris_timing + 8) = cpu_to_le32((pinput_timing->hsw << 16) + pinput_timing->hbp);
	*(u32 *)(iris_timing + 12) = cpu_to_le32((pinput_timing->vres << 16) + pinput_timing->vfp);
	*(u32 *)(iris_timing + 16) = cpu_to_le32((pinput_timing->vsw << 16) + pinput_timing->vbp);
	*(u32 *)(iris_timing + 20) = cpu_to_le32((pinput_timing->fps << 8) + 0x1f);

	*(u32 *)(iris_timing + 24) = cpu_to_le32((poutput_timing->hres << 16) + poutput_timing->hfp);
	*(u32 *)(iris_timing + 28) = cpu_to_le32((poutput_timing->hsw << 16) + poutput_timing->hbp);
	*(u32 *)(iris_timing + 32) = cpu_to_le32((poutput_timing->vres << 16) + poutput_timing->vfp);
	*(u32 *)(iris_timing + 36) = cpu_to_le32((poutput_timing->vsw << 16) + poutput_timing->vbp);
	*(u32 *)(iris_timing + 40) = cpu_to_le32((poutput_timing->fps << 8) + 0x1f);

	*(u32 *)(iris_timing + 44) = cpu_to_le32((pinput_dsc->slice_height << 16) + pinput_dsc->slice_number);
	*(u32 *)(iris_timing + 48) = cpu_to_le32(pinput_dsc->bpp);

	*(u32 *)(iris_timing + 52) = cpu_to_le32((poutput_dsc->slice_height << 16) + poutput_dsc->slice_number);
	*(u32 *)(iris_timing + 56) = cpu_to_le32(poutput_dsc->bpp);

	pr_debug("iris: send timing info\n");

	panel_cmds.cmds = iris_timing_info_cmd;
	panel_cmds.cmd_cnt = ARRAY_SIZE(iris_timing_info_cmd);
	panel_cmds.link_state = state;
	iris_dsi_cmds_send(ctrl, &panel_cmds);

	DUMP_PACKET(iris_workmode, sizeof(iris_workmode));
	DUMP_PACKET(iris_timing, sizeof(iris_timing));
}

void iris_timing_info_grcp_send(struct mdss_dsi_ctrl_pdata *ctrl, int state)
{
	static char iris_timing[] = {
		PWIL_TAG('P', 'W', 'I', 'L'),
		PWIL_TAG('G', 'R', 'C', 'P'),
		PWIL_U32(0x00000011),
		0x03,
		0x00,
		PWIL_U16(0x0f),
		PWIL_U32(IRIS_GRCP_BUFFER_ADDR),
		PWIL_U32(0x00800000),				/*work mode*/
		PWIL_U32(0x01e00014),				/*Input's HRES+HFP*/
		PWIL_U32(0x00160010),               /*Input's HSW+HBP*/
		PWIL_U32(0x0320000a),               /*Input's VRES+VFP*/
		PWIL_U32(0x00080008),               /*Input's VSW+VBP*/
		PWIL_U32(0x1f),                     /*Input's DenPol, HsPol, VsPol etc.*/
		PWIL_U32(0x01e00014),               /*Output's HRES+HFP*/
		PWIL_U32(0x00160010),               /*Output's HSW+HBP*/
		PWIL_U32(0x0320000a),               /*OutPut's VRES+VFP*/
		PWIL_U32(0x00080008),               /*Output's VSW+VBP*/
		PWIL_U32(0x1f),                     /*Output's DenPol, HsPol, VsPol etc.*/
		PWIL_U32(0x00100008),               /*Input's SliceHeight+SliceNumber*/
		PWIL_U32(0x80),                     /*wDscBPP*/
		PWIL_U32(0x00100008),               /*Output's SliceHeight+SliceNumber*/
		PWIL_U32(0x80),                     /*wDscBPP*/
	};

	struct dsi_cmd_desc iris_timing_info_cmd[] = {
		{{DTYPE_GEN_LWRITE, 1, 0, 0, CMD_PROC, sizeof(iris_timing)}, iris_timing}
	};
	struct iris_timing_info *pinput_timing = &(iris_info.input_timing);
	struct iris_timing_info *poutput_timing = &(iris_info.output_timing);
	struct iris_dsc_info *pinput_dsc = &(iris_info.input_dsc);
	struct iris_dsc_info *poutput_dsc = &(iris_info.output_dsc);
	struct dsi_panel_cmds panel_cmds;

	memcpy(iris_timing + 20, &(iris_info.work_mode), 4);

	*(u32 *)(iris_timing + 24) = cpu_to_le32((pinput_timing->hres << 16) + pinput_timing->hfp);
	*(u32 *)(iris_timing + 28) = cpu_to_le32((pinput_timing->hsw << 16) + pinput_timing->hbp);
	*(u32 *)(iris_timing + 32) = cpu_to_le32((pinput_timing->vres << 16) + pinput_timing->vfp);
	*(u32 *)(iris_timing + 36) = cpu_to_le32((pinput_timing->vsw << 16) + pinput_timing->vbp);
	*(u32 *)(iris_timing + 40) = cpu_to_le32((pinput_timing->fps << 8) + 0x1f);

	*(u32 *)(iris_timing + 44) = cpu_to_le32((poutput_timing->hres << 16) + poutput_timing->hfp);
	*(u32 *)(iris_timing + 48) = cpu_to_le32((poutput_timing->hsw << 16) + poutput_timing->hbp);
	*(u32 *)(iris_timing + 52) = cpu_to_le32((poutput_timing->vres << 16) + poutput_timing->vfp);
	*(u32 *)(iris_timing + 56) = cpu_to_le32((poutput_timing->vsw << 16) + poutput_timing->vbp);
	*(u32 *)(iris_timing + 60) = cpu_to_le32((poutput_timing->fps << 8) + 0x1f);

	*(u32 *)(iris_timing + 64) = cpu_to_le32((pinput_dsc->slice_height << 16) + pinput_dsc->slice_number);
	*(u32 *)(iris_timing + 68) = cpu_to_le32(pinput_dsc->bpp);

	*(u32 *)(iris_timing + 72) = cpu_to_le32((poutput_dsc->slice_height << 16) + poutput_dsc->slice_number);
	*(u32 *)(iris_timing + 76) = cpu_to_le32(poutput_dsc->bpp);

	pr_debug("iris: send timing info\n");

	panel_cmds.cmds = iris_timing_info_cmd;
	panel_cmds.cmd_cnt = ARRAY_SIZE(iris_timing_info_cmd);
	panel_cmds.link_state = state;
	iris_dsi_cmds_send(ctrl, &panel_cmds);
}

void iris_grcp_buffer_init(struct mdss_dsi_ctrl_pdata *ctrl, int state)
{
	static char grcp_buf_init[] = {
		PWIL_TAG('P', 'W', 'I', 'L'),
		PWIL_TAG('G', 'R', 'C', 'P'),
		PWIL_U32(0x0000000a),
		0x03,
		0x00,
		PWIL_U16(0x08),
		PWIL_U32(IRIS_GRCP_CTRL_ADDR + 0x12fe0),
		PWIL_U32(0x0),
		PWIL_U32(0x0),
		PWIL_U32(0x0),
		PWIL_U32(0x0),
		PWIL_U32(0x0),
		PWIL_U32(0x0),
		PWIL_U32(0x0),
		PWIL_U32(0x0)
	};
	struct dsi_cmd_desc iris_grcp_buf_init_cmd[] = {
		{{DTYPE_GEN_LWRITE, 1, 0, 0, CMD_PROC, sizeof(grcp_buf_init)}, grcp_buf_init}
	};
	struct dsi_panel_cmds panel_cmds;


	pr_debug("iris: init GRCP buffer\n");

	panel_cmds.cmds = iris_grcp_buf_init_cmd;
	panel_cmds.cmd_cnt = ARRAY_SIZE(iris_grcp_buf_init_cmd);
	panel_cmds.link_state = state;
	iris_dsi_cmds_send(ctrl, &panel_cmds);

	DUMP_PACKET(grcp_buf_init, sizeof(grcp_buf_init));
}

void iris_ctrl_cmd_send(struct mdss_dsi_ctrl_pdata *ctrl, u8 cmd, int state)
{
	char romcode_ctrl[] = {
		PWIL_TAG('P', 'W', 'I', 'L'),
		PWIL_TAG('G', 'R', 'C', 'P'),
		PWIL_U32(0x00000005),
		0x00,
		0x00,
		PWIL_U16(0x04),
		PWIL_U32(IRIS_MODE_ADDR),  /*proxy_MB1*/
		PWIL_U32(0x00000000),
		PWIL_U32(IRIS_PROXY_MB7_ADDR),  /*proxy_MB7*/
		PWIL_U32(0x00040000),
	};
	struct dsi_cmd_desc iris_romcode_ctrl_cmd[] = {
		{{ DTYPE_GEN_LWRITE, 1, 0, 0, CMD_PROC, sizeof(romcode_ctrl)}, romcode_ctrl},
	};
	struct dsi_panel_cmds panel_cmds;

	if ((cmd | CONFIG_DATAPATH) || (cmd | ENABLE_DPORT) || (cmd | REMAP))
		iris_romcode_ctrl_cmd[0].dchdr.wait = INIT_WAIT;

	romcode_ctrl[20] = cmd;
	*(u32 *)(romcode_ctrl + 28) = cpu_to_le32(iris_info.firmware_info.firmware_size);

	pr_debug("iris: send romcode ctrl cmd: %x\n", cmd);

	panel_cmds.cmds = iris_romcode_ctrl_cmd;
	panel_cmds.cmd_cnt = ARRAY_SIZE(iris_romcode_ctrl_cmd);
	panel_cmds.link_state = state;
	iris_dsi_cmds_send(ctrl, &panel_cmds);

	DUMP_PACKET(romcode_ctrl, sizeof(romcode_ctrl));
}

void iris_dtg_set(struct mdss_dsi_ctrl_pdata *ctrl, int state)
{
	u32 grcp_len = 0;
	struct mdss_panel_info *panel_info = &(ctrl->panel_data.panel_info);
	struct iris_work_mode *pwork_mode = &(iris_info.work_mode);
	struct dsi_cmd_desc iris_dtg_cmd[] = {
		{{ DTYPE_GEN_LWRITE, 1, 0, 0, CMD_PROC, CMD_PKT_SIZE}, grcp_cmd.cmd},
	};
	struct dsi_panel_cmds panel_cmds;
	struct iris_config *iris_cfg = &g_mfd->iris_conf;

	if (DISPLAY_1 != panel_info->pdest) {
		return;
	}

	memset(&grcp_cmd, 0, sizeof(grcp_cmd));
	memcpy(grcp_cmd.cmd, grcp_header, GRCP_HEADER);
	grcp_cmd.cmd_len = GRCP_HEADER;

	iris_dtg_para_set((int)pwork_mode->rx_mode, (int)pwork_mode->tx_mode);


	iris_cmd_reg_add(&grcp_cmd, IRIS_DTG_ADDR + DTG_DELAY, iris_cfg->dtg_setting.dtg_delay);
	iris_cmd_reg_add(&grcp_cmd, IRIS_DTG_ADDR + TE_CTRL, iris_cfg->dtg_setting.te_ctrl);
	iris_cmd_reg_add(&grcp_cmd, IRIS_DTG_ADDR + TE_CTRL_1, iris_cfg->dtg_setting.te_ctrl_1);
	iris_cmd_reg_add(&grcp_cmd, IRIS_DTG_ADDR + TE_CTRL_2, iris_cfg->dtg_setting.te_ctrl_2);
	iris_cmd_reg_add(&grcp_cmd, IRIS_DTG_ADDR + TE_CTRL_3, iris_cfg->dtg_setting.te_ctrl_3);
	iris_cmd_reg_add(&grcp_cmd, IRIS_DTG_ADDR + TE_CTRL_4, iris_cfg->dtg_setting.te_ctrl_4);
	iris_cmd_reg_add(&grcp_cmd, IRIS_DTG_ADDR + TE_CTRL_5, iris_cfg->dtg_setting.te_ctrl_5);
	iris_cmd_reg_add(&grcp_cmd, IRIS_DTG_ADDR + DTG_CTRL_1,iris_cfg->dtg_setting.dtg_ctrl_1);
	iris_cmd_reg_add(&grcp_cmd, IRIS_DTG_ADDR + DTG_CTRL,iris_cfg->dtg_setting.dtg_ctrl);
	iris_cmd_reg_add(&grcp_cmd, IRIS_DTG_ADDR + EVS_DLY,iris_cfg->dtg_setting.evs_dly);
	iris_cmd_reg_add(&grcp_cmd, IRIS_DTG_ADDR + EVS_NEW_DLY,iris_cfg->dtg_setting.evs_new_dly);
	iris_cmd_reg_add(&grcp_cmd, IRIS_DTG_ADDR + DVS_CTRL, iris_cfg->dtg_setting.dvs_ctrl);
	iris_cmd_reg_add(&grcp_cmd, IRIS_DTG_ADDR + TE_DLY, iris_cfg->dtg_setting.te_dly);
	iris_cmd_reg_add(&grcp_cmd, IRIS_DTG_ADDR + TE_DLY_1, iris_cfg->dtg_setting.te_dly_1);
	iris_cmd_reg_add(&grcp_cmd, IRIS_DTG_ADDR + VFP_CTRL_0, iris_cfg->dtg_setting.vfp_ctrl_0);
	iris_cmd_reg_add(&grcp_cmd, IRIS_DTG_ADDR + VFP_CTRL_1, iris_cfg->dtg_setting.vfp_ctrl_1);
	iris_cmd_reg_add(&grcp_cmd, IRIS_DTG_ADDR + DTG_RESERVE, 0x1000000b);
	iris_cmd_reg_add(&grcp_cmd, IRIS_DTG_ADDR + REGSEL, 1);

#ifdef EFUSE_REWRITE
	iris_cmd_reg_add(&grcp_cmd, IRIS_SYS_ADDR + DFT_EFUSE_CTRL, 0x80000100);
	iris_cmd_reg_add(&grcp_cmd, IRIS_SYS_ADDR + DFT_EFUSE_CTRL_1, 0x0000200d);
#endif
	grcp_len = (grcp_cmd.cmd_len - GRCP_HEADER) / 4;
	*(u32 *)(grcp_cmd.cmd + 8) = cpu_to_le32(grcp_len + 1);
	*(u16 *)(grcp_cmd.cmd + 14) = cpu_to_le16(grcp_len);

	iris_dtg_cmd[0].dchdr.dlen = grcp_cmd.cmd_len;

	pr_debug("iris: set dtg \n");

	panel_cmds.cmds = iris_dtg_cmd;
	panel_cmds.cmd_cnt = ARRAY_SIZE(iris_dtg_cmd);
	panel_cmds.link_state = state;
	iris_dsi_cmds_send(ctrl, &panel_cmds);

	DUMP_PACKET(grcp_cmd.cmd, grcp_cmd.cmd_len);
}
void iris_mipitx_tx_nop(struct mdss_dsi_ctrl_pdata *ctrl, int state)
{
	u32 grcp_len = 0;
	struct dsi_cmd_desc iris_cmd[] = {
		{{ DTYPE_GEN_LWRITE, 1, 0, 0, 5, CMD_PKT_SIZE}, grcp_cmd.cmd},
	};
	struct dsi_panel_cmds panel_cmds;


	memset(&grcp_cmd, 0, sizeof(grcp_cmd));
	memcpy(grcp_cmd.cmd, grcp_header, GRCP_HEADER);
	grcp_cmd.cmd_len = GRCP_HEADER;

	iris_cmd_reg_add(&grcp_cmd, IRIS_MIPI_TX_ADDR + WR_PACKET_HEADER_OFFS, 0x05000409);//nop
	iris_cmd_reg_add(&grcp_cmd, IRIS_MIPI_TX_ADDR + WR_PACKET_PAYLOAD_OFFS, 0x00000000);

#ifdef MIPI_SWAP
	iris_cmd_reg_add(&grcp_cmd, IRIS_MIPI_TX_ADDR - IRIS_MIPI_ADDR_OFFSET + WR_PACKET_HEADER_OFFS, 0x05000409);//nop
	iris_cmd_reg_add(&grcp_cmd, IRIS_MIPI_TX_ADDR - IRIS_MIPI_ADDR_OFFSET + WR_PACKET_PAYLOAD_OFFS, 0x00000000);
#else
	iris_cmd_reg_add(&grcp_cmd, IRIS_MIPI_TX_ADDR + IRIS_MIPI_ADDR_OFFSET + WR_PACKET_HEADER_OFFS, 0x05000409);//nop
	iris_cmd_reg_add(&grcp_cmd, IRIS_MIPI_TX_ADDR + IRIS_MIPI_ADDR_OFFSET + WR_PACKET_PAYLOAD_OFFS, 0x00000000);
#endif

	grcp_len = (grcp_cmd.cmd_len - GRCP_HEADER) / 4;
	*(u32 *)(grcp_cmd.cmd + 8) = cpu_to_le32(grcp_len + 1);
	*(u16 *)(grcp_cmd.cmd + 14) = cpu_to_le16(grcp_len);

	iris_cmd[0].dchdr.dlen = grcp_cmd.cmd_len;

	pr_debug("iris: mipi_tx send null packet\n");
	// iris_dump_packet(grcp_cmd.cmd, grcp_cmd.cmd_len);

	panel_cmds.cmds = iris_cmd;
	panel_cmds.cmd_cnt = ARRAY_SIZE(iris_cmd);
	panel_cmds.link_state = state;
	iris_dsi_cmds_send(ctrl, &panel_cmds);
}

void iris_pwil_mode_set(struct mdss_dsi_ctrl_pdata *ctrl, u8 mode, int state)
{
	char pwil_mode[2] = {0x00, 0x00};
	struct dsi_cmd_desc iris_pwil_mode_cmd[] = {
		{{DTYPE_GEN_WRITE2, 1, 0, 0, CMD_PROC, sizeof(pwil_mode)}, pwil_mode},
	};
	struct dsi_panel_cmds panel_cmds;

	if (PT_MODE == mode) {
		pwil_mode[0] = 0x0;
		pwil_mode[1] = 0x1;
	} else if (RFB_MODE == mode) {
		pwil_mode[0] = 0xc;
		pwil_mode[1] = 0x1;
	} else if (BIN_MODE == mode) {
		pwil_mode[0] = 0xc;
		pwil_mode[1] = 0x20;
	}

	pr_debug("iris: set pwil mode: %x, %x\n", pwil_mode[0], pwil_mode[1]);

	panel_cmds.cmds = iris_pwil_mode_cmd;
	panel_cmds.cmd_cnt = ARRAY_SIZE(iris_pwil_mode_cmd);
	panel_cmds.link_state = state;
	iris_dsi_cmds_send(ctrl, &panel_cmds);

	DUMP_PACKET(pwil_mode, sizeof(pwil_mode));
}

void iris_mipi_mem_addr_set(struct mdss_dsi_ctrl_pdata *ctrl, u16 column, u16 page, int state)
{
	char mem_addr[2] = {0x36, 0x0};
	char pixel_format[2] = {0x3a, 0x77};
	char col_addr[5] = {0x2a, 0x00, 0x00, 0x03, 0xff};
	char page_addr[5] = {0x2b, 0x00, 0x00, 0x03, 0xff};
	struct dsi_cmd_desc iris_mem_addr_cmd[] = {
		{{DTYPE_DCS_WRITE1, 0, 0, 0, 0, sizeof(mem_addr)}, mem_addr},
		{{DTYPE_DCS_WRITE1, 0, 0, 0, 0, sizeof(pixel_format)}, pixel_format},
		{{DTYPE_DCS_LWRITE, 0, 0, 0, 0, sizeof(col_addr)}, col_addr},
		{{DTYPE_DCS_LWRITE, 1, 0, 0, 0, sizeof(page_addr)}, page_addr},
	};
	struct dsi_panel_cmds panel_cmds;

	col_addr[3] = (column >> 8) & 0xff;
	col_addr[4] = column & 0xff;
	page_addr[3] = (page >> 8) & 0xff;
	page_addr[4] = page & 0xff;

	pr_debug("iris: set mipi mem addr: %x, %x\n", column, page);

	panel_cmds.cmds = iris_mem_addr_cmd;
	panel_cmds.cmd_cnt = ARRAY_SIZE(iris_mem_addr_cmd);
	panel_cmds.link_state = state;
	iris_dsi_cmds_send(ctrl, &panel_cmds);

	DUMP_PACKET(mem_addr, sizeof(mem_addr));
	DUMP_PACKET(pixel_format, sizeof(pixel_format));
	DUMP_PACKET(col_addr, sizeof(col_addr));
	DUMP_PACKET(page_addr, sizeof(page_addr));
}

void iris_firmware_download_prepare(struct mdss_dsi_ctrl_pdata *ctrl, size_t size)
{
#define TIME_INTERVAL 20  /*ms*/

	char fw_download_config[] = {
		PWIL_TAG('P', 'W', 'I', 'L'),
		PWIL_TAG('G', 'R', 'C', 'P'),
		PWIL_U32(0x000000013),
		0x00,
		0x00,
		PWIL_U16(0x0012),
		PWIL_U32(IRIS_PWIL_ADDR + 0x0004),  /*PWIL ctrl1 confirm transfer mode and cmd mode, single channel.*/
		PWIL_U32(0x00004144),
		PWIL_U32(IRIS_PWIL_ADDR + 0x0218),  /*CAPEN*/
		PWIL_U32(0xc0000003),
		PWIL_U32(IRIS_PWIL_ADDR + 0x1140),  /*channel order*/
		PWIL_U32(0xc6120010),
		PWIL_U32(IRIS_PWIL_ADDR + 0x1144),  /*pixelformat*/
		PWIL_U32(0x888),
		PWIL_U32(IRIS_PWIL_ADDR + 0x1158),	/*mem addr*/
		PWIL_U32(0x00000000),
		PWIL_U32(IRIS_PWIL_ADDR + 0x10000), /*update setting. using SW update mode*/
		PWIL_U32(0x00000100),
		PWIL_U32(IRIS_PWIL_ADDR + 0x1fff0), /*clear down load int*/
		PWIL_U32(0x00008000),
		PWIL_U32(IRIS_MIPI_RX_ADDR + 0xc),	/*mipi_rx setting DBI_bus*/
		PWIL_U32(0x000f0000),
		PWIL_U32(IRIS_MIPI_RX_ADDR + 0x001c), /*mipi_rx time out threshold*/
		PWIL_U32(0xffffffff)
	};
	u32 threshold = 0, fw_hres, fw_vres;
	struct dsi_panel_cmds panel_cmds;
	struct dsi_cmd_desc fw_download_config_cmd[] = {
		{{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(fw_download_config)}, fw_download_config}
	};

	threshold = ctrl->pclk_rate / 1000;
	threshold *= TIME_INTERVAL;
	*(u32 *)(fw_download_config + 84) = cpu_to_le32(threshold);

	/*firmware download need mipirx work on single cmd mode, pwil work on binarary mode.*/
	panel_cmds.cmds = fw_download_config_cmd;
	panel_cmds.cmd_cnt = ARRAY_SIZE(fw_download_config_cmd);
	panel_cmds.link_state = DSI_HS_MODE;
	iris_dsi_cmds_send(ctrl, &panel_cmds);

	iris_pwil_mode_set(ctrl, BIN_MODE, DSI_HS_MODE);

	fw_hres = FW_COL_CNT - 1;
	fw_vres = (size + FW_COL_CNT * 3 - 1) / (FW_COL_CNT * 3) - 1;
	iris_mipi_mem_addr_set(ctrl, fw_hres, fw_vres, DSI_HS_MODE);

}

void iris_firmware_download_restore(struct mdss_dsi_ctrl_pdata *ctrl, bool cont_splash)
{
	char fw_download_restore[] = {
		PWIL_TAG('P', 'W', 'I', 'L'),
		PWIL_TAG('G', 'R', 'C', 'P'),
		PWIL_U32(0x00000007),
		0x00,
		0x00,
		PWIL_U16(0x06),
		PWIL_U32(IRIS_PWIL_ADDR + 0x0004),
		PWIL_U32(0x00004140),
		PWIL_U32(IRIS_MIPI_RX_ADDR + 0xc),
		PWIL_U32(0x000f0000),
		PWIL_U32(IRIS_MIPI_RX_ADDR + 0x001c),
		PWIL_U32(0xffffffff)
	};
	u32 col_addr = 0, page_addr = 0;
	struct dsi_panel_cmds panel_cmds;
	struct dsi_cmd_desc fw_download_restore_cmd[] = {
		{{DTYPE_GEN_LWRITE, 1, 0, 0, 0, sizeof(fw_download_restore)}, fw_download_restore}
	};

	if (MIPI_CMD_MODE == iris_info.work_mode.rx_mode)
		fw_download_restore[20] += (2 << 1);

	if (1 == iris_info.work_mode.rx_ch) {
		fw_download_restore[20] += 1;
		fw_download_restore[30] = 0x8f;
	}

	if (1 == iris_info.work_mode.rx_ch)
		col_addr = iris_info.input_timing.hres * 2 - 1;
	else
		col_addr = iris_info.input_timing.hres - 1;

	page_addr = iris_info.input_timing.vres - 1;

	panel_cmds.cmds = fw_download_restore_cmd;
	panel_cmds.cmd_cnt = ARRAY_SIZE(fw_download_restore_cmd);
	panel_cmds.link_state = DSI_HS_MODE;
	iris_dsi_cmds_send(ctrl, &panel_cmds);

	if (cont_splash) {
		iris_pwil_mode_set(ctrl, RFB_MODE, DSI_HS_MODE);

		if (MIPI_CMD_MODE == iris_info.work_mode.rx_mode)
			iris_mipi_mem_addr_set(ctrl, col_addr, page_addr, DSI_HS_MODE);
	}
}

int iris_firmware_data_send(struct mdss_dsi_ctrl_pdata *ctrl, u8 *buf, size_t fw_size)
{
	u32 pkt_size = FW_COL_CNT * 3, cmd_len = 0, cmd_cnt = 0, buf_indx = 0, cmd_indx = 0;
	static struct dsi_cmd_desc fw_send_cmd[FW_DW_CMD_CNT];
	struct dsi_panel_cmds panel_cmds;

	memset(fw_send_cmd, 0, sizeof(fw_send_cmd));

	while (fw_size) {
		if (fw_size >= pkt_size)
			cmd_len = pkt_size;
		else
			cmd_len = fw_size;

		cmd_indx = cmd_cnt % FW_DW_CMD_CNT;
		fw_send_cmd[cmd_indx].dchdr.last = 0;
		fw_send_cmd[cmd_indx].dchdr.dtype = 0x39;
		fw_send_cmd[cmd_indx].dchdr.dlen = pkt_size + 1;
		fw_send_cmd[cmd_indx].payload = buf + buf_indx;

		fw_size -= cmd_len;
		cmd_cnt++;
		buf_indx += cmd_len + 1;

		if (((FW_DW_CMD_CNT - 1) == cmd_indx) || (0 == fw_size)) {
			fw_send_cmd[cmd_indx].dchdr.last = 1;
			panel_cmds.cmds = fw_send_cmd;
			panel_cmds.cmd_cnt = cmd_indx + 1;
			panel_cmds.link_state = DSI_HS_MODE;
			iris_dsi_cmds_send(ctrl, &panel_cmds);
		}
	}

	return SUCCESS;
}

static void iris_mipirx_status_cb(int len)
{
	if (len != 2) {
		pr_err("%s: not short read responese, return len [%02x] != 2\n", __func__, len);
		return;
	}

	iris_mipirx_status = (iris_read_cmd_buf[0] & 0xFF) | ((iris_read_cmd_buf[1] & 0x0f) << 8);
	pr_debug("mipi_rx result [%04x]\n", iris_mipirx_status);
}

static u16 iris_fw_download_result_read(struct mdss_dsi_ctrl_pdata *ctrl)
{
	struct dcs_cmd_req cmdreq;
	char mipirx_status[1] = {0xaf};
	struct dsi_cmd_desc mipirx_status_cmd = {
		{DTYPE_DCS_READ, 1, 0, 1, 0, sizeof(mipirx_status)}, mipirx_status};

	memset(iris_read_cmd_buf, 0, sizeof(iris_read_cmd_buf));
	iris_mipirx_status = 0;

	cmdreq.cmds = &mipirx_status_cmd;
	cmdreq.cmds_cnt = 1;
	cmdreq.flags = CMD_REQ_RX | CMD_REQ_COMMIT | CMD_REQ_LP_MODE;
	cmdreq.rlen = 2;
	cmdreq.rbuf = iris_read_cmd_buf;
	cmdreq.cb = iris_mipirx_status_cb;
	mdss_dsi_cmdlist_put(ctrl, &cmdreq);

	return (iris_mipirx_status & 0x0f00);
}

int iris_fw_download_result_check(struct mdss_dsi_ctrl_pdata *ctrl)
{
	u16 cnt = 0, result = 0;

	do {
		result = iris_fw_download_result_read(ctrl);
		if (0x0100 == result)
			break;

		msleep(2);
		cnt++;
	} while ((result != 0x0100) && cnt < 5);

	/*read failed*/
	if (5 == cnt) {
		pr_err("firmware download failed\n");
		return FAILED;
	} else
		pr_debug("firmware download success\n");


	return SUCCESS;
}

int iris_firmware_data_read(const u8 *fw_data, size_t fw_size)
{
    u32 pkt_size = FW_COL_CNT * 3, cmd_len = 0, cmd_cnt = 0, buf_indx = 0;

	fw_buf = kzalloc(DSI_DMA_TX_BUF_SIZE, GFP_KERNEL);
	if (!fw_buf) {
		pr_err("%s: failed to alloc mem, size = %d\n", __func__, DSI_DMA_TX_BUF_SIZE);
		return FAILED;
	}

	memset(fw_buf, 0, DSI_DMA_TX_BUF_SIZE);

	while (fw_size) {
		if (fw_size >= pkt_size)
			cmd_len = pkt_size;
		else
			cmd_len = fw_size;

		if (0 == cmd_cnt)
			fw_buf[0] = DCS_WRITE_MEM_START;
		else
			fw_buf[buf_indx] = DCS_WRITE_MEM_CONTINUE;

		memcpy(fw_buf + buf_indx + 1, fw_data, cmd_len);

		fw_size -= cmd_len;
		fw_data += cmd_len;
		cmd_cnt++;
		buf_indx += cmd_len + 1;
	}
	return SUCCESS;
}

int iris_firmware_download_init(struct msm_fb_data_type *mfd, const char *name)
{
    const struct firmware *fw = NULL;
    int ret = 0, result = SUCCESS;

    iris_info.firmware_info.firmware_size = 0;
    if (name) {
        /* Firmware file must be in /system/etc/firmware/ */
        ret = request_firmware(&fw, name, mfd->fbi->dev);
        if (ret) {
                pr_err("%s: failed to request firmware: %s, ret = %d\n",
                    __func__, name, ret);
			result = FAILED;
        } else {
            pr_info("%s: request firmware: name = %s, size = %zu bytes\n",
                __func__, name, fw->size);
            iris_firmware_data_read(fw->data, fw->size);
            iris_info.firmware_info.firmware_size = fw->size;
            release_firmware(fw);
        }
    } else {
        pr_err("%s: firmware is null\n", __func__);
        result = FAILED;
    }

	return result;
}
int iris2p_firmware_download(struct mdss_dsi_ctrl_pdata *ctrl,
							struct msm_fb_data_type *mfd, const char *name, bool cont_splash)
{
#define DISABLE_FW_DOWNLOAD 1
#define RELOAD_FIRMWARE 2
	int ret = SUCCESS, result = FAILED;
	int fw_size = 0;

	/*firmware debug*/
	if (DISABLE_FW_DOWNLOAD == iris_debug_firmware) {
		return FAILED;
	} else if ((RELOAD_FIRMWARE == iris_debug_firmware) && fw_buf) {
		kfree(fw_buf);
		fw_buf = NULL;
	}

	if (!fw_buf)
		ret = iris_firmware_download_init(mfd, name);

	if (SUCCESS == ret) {
		fw_size = iris_info.firmware_info.firmware_size;

		iris_firmware_download_prepare(ctrl, fw_size);
		iris_firmware_data_send(ctrl, fw_buf, fw_size);
		#ifdef READ_CMD_ENABLE
			result = iris_fw_download_result_check(ctrl);
		#else
			msleep(100);
		#endif
		iris_firmware_download_restore(ctrl, cont_splash);
	}
    return result;
}
#endif
void iris_dport_disable(struct mdss_dsi_ctrl_pdata *ctrl)
{
	char dport_disable[] = {
		PWIL_TAG('P', 'W', 'I', 'L'),
		PWIL_TAG('G', 'R', 'C', 'P'),
		PWIL_U32(0x00000003),
		0x00,
		0x00,
		PWIL_U16(0x02),
		PWIL_U32(IRIS_DPORT_ADDR + 0x04),  /*dport_ctrl1*/
		PWIL_U32(0x21008800),
	};
	struct dsi_cmd_desc iris_dport_disable_cmd[] = {
		{{ DTYPE_GEN_LWRITE, 1, 0, 0, CMD_PROC, sizeof(dport_disable)}, dport_disable},
	};
	struct dsi_panel_cmds panel_cmds;

	pr_debug("iris: send dport disable cmd\n");

	panel_cmds.cmds = iris_dport_disable_cmd;
	panel_cmds.cmd_cnt = ARRAY_SIZE(iris_dport_disable_cmd);
	panel_cmds.link_state = DSI_HS_MODE;
	iris_dsi_cmds_send(ctrl, &panel_cmds);

}

#ifdef EFUSE_REWRITE
static void iris_sys_efuse_rewrite(struct mdss_dsi_ctrl_pdata *ctrl)
{
	u32 grcp_len = 0;
	struct dsi_cmd_desc iris_grcp_cmd[] = {
		{{ DTYPE_GEN_LWRITE, 1, 0, 0, 0, CMD_PKT_SIZE}, grcp_cmd.cmd},
	};
	struct dsi_panel_cmds panel_cmds;

	memset(&grcp_cmd, 0, sizeof(grcp_cmd));
	memcpy(grcp_cmd.cmd, grcp_header, GRCP_HEADER);
	grcp_cmd.cmd_len = GRCP_HEADER;

	iris_cmd_reg_add(&grcp_cmd, IRIS_SYS_ADDR + DFT_EFUSE_CTRL, 0x80000100);
	iris_cmd_reg_add(&grcp_cmd, IRIS_SYS_ADDR + DFT_EFUSE_CTRL_1, 0x0000200d);
	#if 0
		/* software reset */
		iris_cmd_reg_add(&grcp_cmd, IRIS_SYS_ADDR + 0x28, 0x1);
		iris_cmd_reg_add(&grcp_cmd, IRIS_SYS_ADDR + 0x28, 0x3);
		iris_cmd_reg_add(&grcp_cmd, IRIS_SYS_ADDR + 0x28, 0x2);
	#endif
	grcp_len = (grcp_cmd.cmd_len - GRCP_HEADER) / 4;
	*(u32 *)(grcp_cmd.cmd + 8) = cpu_to_le32(grcp_len + 1);
	*(u16 *)(grcp_cmd.cmd + 14) = cpu_to_le16(grcp_len);

	iris_grcp_cmd[0].dchdr.dlen = grcp_cmd.cmd_len;

	pr_debug("iris efuse rewrite\n");

	panel_cmds.cmds = iris_grcp_cmd;
	panel_cmds.cmd_cnt = ARRAY_SIZE(iris_grcp_cmd);
	panel_cmds.link_state = DSI_LP_MODE;
	iris_dsi_cmds_send(ctrl, &panel_cmds);
	DUMP_PACKET(grcp_cmd.cmd, grcp_cmd.cmd_len);

}
#endif
extern int iris_one_wired_cmd_init(struct mdss_dsi_ctrl_pdata *ctrl);
extern void iris_one_wired_cmd_send(struct mdss_dsi_ctrl_pdata *ctrl, int cmd);
void iris_low_power_mode_enter(struct mdss_dsi_ctrl_pdata *ctrl)
{
	u32 grcp_len = 0;
	struct dsi_cmd_desc iris_grcp_cmd[] = {
		{{ DTYPE_GEN_LWRITE, 1, 0, 0, 0, CMD_PKT_SIZE}, grcp_cmd.cmd},
	};
	struct dsi_panel_cmds panel_cmds;

	memset(&grcp_cmd, 0, sizeof(grcp_cmd));
	memcpy(grcp_cmd.cmd, grcp_header, GRCP_HEADER);
	grcp_cmd.cmd_len = GRCP_HEADER;


	/* power down edram1~8 */
	iris_cmd_reg_add(&grcp_cmd, 0xf104000c, 0xfffffffe);

	/*disable DPHY*/
	iris_cmd_reg_add(&grcp_cmd, 0xf0180000, 0x0a00c138);
	iris_cmd_reg_add(&grcp_cmd, 0xf0180004, 0x00000000);

	/* set clock source to XCLK */
	iris_cmd_reg_add(&grcp_cmd, 0xf0000210, 0x0000070b);
	iris_cmd_reg_add(&grcp_cmd, 0xf0000214, 0x0000070b);
	iris_cmd_reg_add(&grcp_cmd, 0xf0000218, 0x00000f0b);
	iris_cmd_reg_add(&grcp_cmd, 0xf000021c, 0x0000070b);
	iris_cmd_reg_add(&grcp_cmd, 0xf0000228, 0x0000070b);
	iris_cmd_reg_add(&grcp_cmd, 0xf0000014, 0x00000001);
	iris_cmd_reg_add(&grcp_cmd, 0xf0000014, 0x00000000);

	/* power down PLL */
	iris_cmd_reg_add(&grcp_cmd, 0xf0000140, 0x00000003);
	iris_cmd_reg_add(&grcp_cmd, 0xf0000150, 0x00002003);
	iris_cmd_reg_add(&grcp_cmd, 0xf0000160, 0x00000003);

	/* gate off clock */
	iris_cmd_reg_add(&grcp_cmd, 0xf0000000, 0x3fc87fff);
	iris_cmd_reg_add(&grcp_cmd, 0xf0000004, 0x00007f8e);


	grcp_len = (grcp_cmd.cmd_len - GRCP_HEADER) / 4;
	*(u32 *)(grcp_cmd.cmd + 8) = cpu_to_le32(grcp_len + 1);
	*(u16 *)(grcp_cmd.cmd + 14) = cpu_to_le16(grcp_len);

	iris_grcp_cmd[0].dchdr.dlen = grcp_cmd.cmd_len;

	pr_debug("iris low power mode\n");

	panel_cmds.cmds = iris_grcp_cmd;
	panel_cmds.cmd_cnt = ARRAY_SIZE(iris_grcp_cmd);
	panel_cmds.link_state = DSI_LP_MODE;
	iris_dsi_cmds_send(ctrl, &panel_cmds);

}

void iris_init(struct mdss_dsi_ctrl_pdata *ctrl)
{
	//u32 column, page;

	if (ctrl->ndx != DSI_CTRL_LEFT)
		return;
#ifdef READ_CMD_ENABLE
	iris_proxy_check_reset(ctrl);
#else
    msleep(10);
#endif
#ifdef EFUSE_REWRITE
	iris_mipirx_mode_set(ctrl, PWIL_CMD, DSI_LP_MODE);
	iris_sys_efuse_rewrite(ctrl);
	iris_power_mode_check(ctrl, 0x01, DSI_LP_MODE);
#endif
    //cmd_send_flag = 1;
	iris_mipirx_mode_set(ctrl, PWIL_CMD, DSI_LP_MODE);
	/* init sys/mipirx/mipitx */
	iris_init_cmd_send(ctrl, DSI_LP_MODE);

	iris_one_wired_cmd_init(ctrl);
	iris_one_wired_cmd_send(ctrl, BYPASS_MODE_CHANGE);
	msleep(100);
	iris_low_power_mode_enter(ctrl);
	return;
#if 0
	/* send work mode and timing info */
#ifdef NEW_WORKFLOW
	iris_timing_info_grcp_send(ctrl, DSI_LP_MODE);
#else
	iris_mipirx_mode_set(ctrl, MCU_CMD, DSI_LP_MODE);
	iris_timing_info_send(ctrl, DSI_LP_MODE);
	iris_mipirx_mode_set(ctrl, PWIL_CMD, DSI_LP_MODE);
#endif
	iris_ctrl_cmd_send(ctrl, CONFIG_DATAPATH, DSI_LP_MODE);

	/*init grcp buffer*/
	iris_grcp_buffer_init(ctrl, DSI_LP_MODE);

	/* bypass panel on command */
	iris_mipirx_mode_set(ctrl, BYPASS_CMD, DSI_HS_MODE);

	/* set mipi_tx's mem addr */
	if (iris_info.work_mode.tx_mode) {
		column = iris_info.work_mode.tx_ch ? (iris_info.output_timing.hres * 2 - 1) : (iris_info.output_timing.hres - 1);
		page = iris_info.output_timing.vres - 1;
		iris_mipi_mem_addr_set(ctrl, column, page, DSI_LP_MODE);
	}
	cmd_send_flag = 0;
#endif
}
#if 0
void iris_lightup(struct mdss_dsi_ctrl_pdata *ctrl)
{
	u32 column, page, cmd = ENABLE_DPORT;

	if (iris_info.work_mode.rx_ch) {
		if (ctrl->ndx == DSI_CTRL_LEFT)
			return;
		else
			ctrl = g_ctrl;
	}
	//return;
	cmd_send_flag = 1;
	iris_mipirx_mode_set(ctrl, PWIL_CMD, DSI_HS_MODE);
	/* firmware download */
	iris_info.firmware_info.fw_dw_result =
			iris2p_firmware_download(ctrl, gp_mfd, IRIS_FIRMWARE_NAME, false);
	if (SUCCESS == iris_info.firmware_info.fw_dw_result)
		cmd += REMAP + ITCM_COPY;

	if (MIPI_VIDEO_MODE == iris_info.work_mode.rx_mode) {
		iris_mipirx_mode_set(ctrl, PWIL_VIDEO, DSI_HS_MODE);
		iris_dtg_set(ctrl, DSI_HS_MODE);
		iris_ctrl_cmd_send(ctrl, cmd, DSI_HS_MODE);
		iris_pwil_mode_set(ctrl, RFB_MODE, DSI_HS_MODE);
	} else {
		iris_dtg_set(ctrl, DSI_HS_MODE);
		if (iris_info.work_mode.tx_ch)
			iris_mipitx_tx_nop(ctrl, DSI_HS_MODE);
		iris_ctrl_cmd_send(ctrl, cmd, DSI_HS_MODE);
		iris_pwil_mode_set(ctrl, RFB_MODE, DSI_HS_MODE);

		column = iris_info.work_mode.rx_ch ? (iris_info.input_timing.hres * 2 - 1) : (iris_info.input_timing.hres - 1);
		page = iris_info.input_timing.vres - 1;
		iris_mipi_mem_addr_set(ctrl, column, page, DSI_HS_MODE);
	}

	if (SUCCESS == iris_info.firmware_info.fw_dw_result)
	{
		iris_update_configure();
		gp_mfd->iris_conf.ready = true;
		iris_info.power_status.low_power = 0;
		iris_info.power_status.low_power_state = 0;
		iris_info.power_status.work_state_wait = 6;
	}
	cmd_send_flag = 0;
}
#endif
void iris_lightoff(struct mdss_dsi_ctrl_pdata *ctrl)
{
	if (ctrl->ndx != DSI_CTRL_LEFT)
		return;

	//gp_mfd->iris_conf.ready = false;

	//iris_mode_switch_reset(ctrl);

	/*disable dport*/
	iris_dport_disable(ctrl);

	/* bypass panel off command */
	iris_mipirx_mode_set(ctrl, BYPASS_CMD, DSI_HS_MODE);

}
#if 0
void iris_panel_cmd_passthrough(struct mdss_dsi_ctrl_pdata *ctrl, struct dcs_cmd_req *cmdreq)
{
	u32 grcp_len = 0, cnt;
	union iris_mipi_tx_cmd_header header;
	union iris_mipi_tx_cmd_payload payload;
	struct dsi_cmd_desc iris_grcp_cmd[] = {
		{{ DTYPE_GEN_LWRITE, 1, 0, 0, 0, CMD_PKT_SIZE}, grcp_cmd.cmd},
	};
	struct dsi_panel_cmds panel_cmds;
	struct dsi_cmd_desc *dsi_cmds = cmdreq->cmds;
	struct iris_config *iris_cfg = &g_mfd->iris_conf;

	if (iris_cfg->current_mode == IRIS_BYPASS_MODE) {
		mdss_dsi_cmdlist_put(ctrl, cmdreq);
		return;
	}
	memset(&grcp_cmd, 0, sizeof(grcp_cmd));
	memcpy(grcp_cmd.cmd, grcp_header, GRCP_HEADER);
	grcp_cmd.cmd_len = GRCP_HEADER;

	memset(&header, 0, sizeof(header));
	memset(&payload, 0, sizeof(payload));
	header.stHdr.dtype = dsi_cmds->dchdr.dtype;

	/* TODO: will re-design it*/
	/*Gate on MIPITX0_DBICLK / MIPITX0_APBCLK */
	//iris_cmd_reg_add(&grcp_cmd, IRIS_SYS_ADDR + 0x0, 0x2cc00044);

	switch (dsi_cmds->dchdr.dtype) {
	case DTYPE_DCS_WRITE:
	case DTYPE_DCS_WRITE1:
	case DTYPE_GEN_WRITE1:
	case DTYPE_GEN_WRITE2:
		//short write
		header.stHdr.ecc = 0x1;
		header.stHdr.len[0] = dsi_cmds->payload[0];
		if (dsi_cmds->dchdr.dlen == 2)
			header.stHdr.len[1] = dsi_cmds->payload[1];
		pr_debug("%s, line%d, header=0x%4x\n", __func__, __LINE__, header.hdr32);
		iris_cmd_reg_add(&grcp_cmd, IRIS_MIPI_TX_ADDR + WR_PACKET_HEADER_OFFS, header.hdr32);
		break;
	case DTYPE_GEN_LWRITE:
		//long write
		header.stHdr.ecc = 0x5;
		header.stHdr.len[0] = dsi_cmds->dchdr.dlen & 0xff;
		header.stHdr.len[1] = (dsi_cmds->dchdr.dlen >> 8) & 0xff;
		pr_debug("%s, line%d, header=0x%x\n", __func__, __LINE__, header.hdr32);

		iris_cmd_reg_add(&grcp_cmd, IRIS_MIPI_TX_ADDR + WR_PACKET_HEADER_OFFS, header.hdr32);
		for (cnt = 0; cnt < dsi_cmds->dchdr.dlen; cnt = cnt+4) {
			memcpy(payload.p, dsi_cmds->payload + cnt, 4);
			pr_debug("payload=0x%x\n", payload.pld32);
			iris_cmd_reg_add(&grcp_cmd, IRIS_MIPI_TX_ADDR + WR_PACKET_PAYLOAD_OFFS, payload.pld32);
		}
		break;
	default:
		break;
	}

	grcp_len = (grcp_cmd.cmd_len - GRCP_HEADER) / 4;
	*(u32 *)(grcp_cmd.cmd + 8) = cpu_to_le32(grcp_len + 1);
	*(u16 *)(grcp_cmd.cmd + 14) = cpu_to_le16(grcp_len);

	iris_grcp_cmd[0].dchdr.dlen = grcp_cmd.cmd_len;

	panel_cmds.cmds = iris_grcp_cmd;
	panel_cmds.cmd_cnt = ARRAY_SIZE(iris_grcp_cmd);
	panel_cmds.link_state = DSI_LP_MODE;
	iris_dsi_cmds_send(ctrl, &panel_cmds);
	iris_info.update.cmd_setting = true;

}
#endif

int iris_one_wired_cmd_init(struct mdss_dsi_ctrl_pdata *ctrl)
{
#if defined(ONE_WIRED_CMD_VIA_RESET_GPIO)
	if (!gpio_is_valid(ctrl->rst_gpio)) {
		pr_err("%s:%d, reset line not configured\n",
			   __func__, __LINE__);
		return FAILED;
	}
#elif defined(ONE_WIRED_CMD_VIA_WAKEUP_GPIO)
	if (!gpio_is_valid(ctrl->px_bp_gpio)) {
		pr_err("%s:%d, reset line not configured\n",
			   __func__, __LINE__);
		return FAILED;
	}
#endif

#if defined(ONE_WIRED_CMD_VIA_RESET_GPIO)
	gpio_direction_output(ctrl->rst_gpio, 1);
#elif defined(ONE_WIRED_CMD_VIA_WAKEUP_GPIO)
	gpio_direction_output(ctrl->px_bp_gpio, 0);
#endif
	msleep(2);

	return SUCCESS;
}

int iris_passthrough_cmd_process(void)
{
  int ret = false;

  iris_info.update.cmd_setting = false;

  return ret;
}

void iris_one_wired_cmd_send(struct mdss_dsi_ctrl_pdata *ctrl, int cmd)
{
#define POR_CLOCK 180	/* 0.1 Mhz*/

	int cnt = 0;
	u32 start_end_delay = 0, pulse_delay = 0;
	unsigned long flags;
#if defined(ONE_WIRED_CMD_VIA_RESET_GPIO)
	if (!gpio_is_valid(ctrl->rst_gpio)) {
		pr_err("%s:%d, reset line not configured\n",
			   __func__, __LINE__);
		return;
	}
#elif defined(ONE_WIRED_CMD_VIA_WAKEUP_GPIO)
	if (!gpio_is_valid(ctrl->px_bp_gpio)) {
		pr_err("%s:%d, reset line not configured\n",
			   __func__, __LINE__);
		return;
	}
#endif
	start_end_delay = 16 * 16 * 16 * 10 / POR_CLOCK;	/*us*/
	pulse_delay = 16 * 16 * 4 * 10 / POR_CLOCK;			/*us*/

	spin_lock_irqsave(&ctrl->iris_lock, flags);
 	for (cnt = 0; cnt < cmd; cnt++) {
#if defined(ONE_WIRED_CMD_VIA_RESET_GPIO)
 		gpio_set_value(ctrl->rst_gpio, 0);
 		udelay(pulse_delay);
 		gpio_set_value(ctrl->rst_gpio, 1);
 		udelay(pulse_delay);
#elif defined(ONE_WIRED_CMD_VIA_WAKEUP_GPIO)
		gpio_set_value(ctrl->px_bp_gpio, 1);
		udelay(30);
		gpio_set_value(ctrl->px_bp_gpio, 0);
		udelay(30);
#endif
 	}
	spin_unlock_irqrestore(&ctrl->iris_lock, flags);
 	/*end*/
	udelay(start_end_delay);
}
#if 0
void iris_all_clock_gate_on(struct msm_fb_data_type *mfd)
{
	struct iris_config *iris_cfg = &mfd->iris_conf;
	struct iris_clock_setting *clock = &iris_info.setting_info.clock_setting;

	if ((IRIS_MODE_BYPASS2PT == iris_cfg->sf_notify_mode) || (IRIS_BYPASS_MODE == iris_cfg->current_mode))
		return;

	iris_reg_add(IRIS_SYS_ADDR + CLKGATE_CTRL0, 0x2cc00044);
	iris_reg_add(IRIS_SYS_ADDR + CLKGATE_CTRL1, 0x00000280);
	iris_reg_add(IRIS_SYS_ADDR + CLKGATE_PWIL_SW, 0xff000000);
	iris_reg_add(IRIS_SYS_ADDR + MCLK_SRC_SEL, clock->mclk.sel | (clock->mclk.div << 8) | (clock->mclk.div_en << 10));
	//iris_reg_add(IRIS_SYS_ADDR + MCUCLK_SRC_SEL, clock->mcuclk.sel | (clock->mcuclk.div << 8) | (clock->mcuclk.div_en << 12) | (1 << 17));
	iris_reg_add(IRIS_SYS_ADDR + MCUCLK_SRC_SEL, clock->mcuclk.sel | (clock->mcuclk.div << 8) | (clock->mcuclk.div_en << 12));
	//iris_reg_add(IRIS_SYS_ADDR + 0x6c, 0x00160000);
	iris_reg_add(IRIS_DPORT_ADDR + 0x0, 0xe2708007);
	iris_reg_add(IRIS_PWIL_ADDR + 0x9c, 0x60000);
	iris_reg_add(0xf104000c, 0x00000000);

	pr_debug("clcok on\n");
}

int iris_power_clock_gate_on(struct msm_fb_data_type *mfd)
{
	struct iris_config *iris_cfg = &mfd->iris_conf;
	u8 signal_mode = 0xff, mode_switch;
	int *pflag = &iris_info.power_status.low_power_state;

	if ((*pflag) || !gp_mfd->iris_conf.ready || iris_debug_power_opt_disable)
		return true;

	mode_switch = iris_cfg->sf_mode_change_start
		&& ((IRIS_MODE_FRC_PREPARE == iris_cfg->sf_notify_mode)
		|| (IRIS_MODE_RFB_PREPARE == iris_cfg->sf_notify_mode)
		|| (IRIS_MODE_PT_PREPARE == iris_cfg->sf_notify_mode)
		|| (IRIS_MODE_PT2BYPASS == iris_cfg->sf_notify_mode)
		|| (IRIS_MODE_BYPASS2PT == iris_cfg->sf_notify_mode));

	if (iris_info.update.pq_setting || iris_info.update.dbc_setting || iris_info.update.color_adjust
		|| iris_info.update.lce_setting || iris_info.update.cm_setting
		|| iris_info.update.cmd_setting || mode_switch || iris_info.update.reading_mode) {
		if (iris_info.power_status.low_power) {

			if ((IRIS_MODE_BYPASS2PT != iris_cfg->sf_notify_mode) && (IRIS_BYPASS_MODE != iris_cfg->current_mode)) {
				signal_mode = iris_mipi_signal_mode_read(g_ctrl, DSI_LP_MODE);
				if (signal_mode != 0)
					return false;
			}
			iris_all_clock_gate_on(mfd);
			iris_info.power_status.low_power = 0;
		}

		if (iris_cfg->sf_mode_change_start)
			*pflag = 2;
		else if (*pflag != 2)
			*pflag = 1;
		pr_debug("flag = %d\n", *pflag);
	}
	return true;
}

void iris_low_power_mode_notify(struct msm_fb_data_type *mfd)
{
	struct iris_config *iris_cfg = &mfd->iris_conf;
	int *pflag = &iris_info.power_status.low_power_state;

	if (0 == *pflag)
		return;

	if (2 == *pflag) {
		pr_debug("mode: %d, %d\n", iris_cfg->current_mode, iris_cfg->sf_notify_mode);
		if (!(((IRIS_RFB_MODE == iris_cfg->current_mode) && (IRIS_MODE_RFB == iris_cfg->sf_notify_mode))
			|| ((IRIS_PT_MODE == iris_cfg->current_mode) && (IRIS_MODE_PT == iris_cfg->sf_notify_mode))
			|| ((IRIS_FRC_MODE == iris_cfg->current_mode) && (IRIS_MODE_FRC == iris_cfg->sf_notify_mode))
			|| ((IRIS_BYPASS_MODE == iris_cfg->current_mode) && (IRIS_MODE_BYPASS == iris_cfg->sf_notify_mode))))
			return;
	}
	*pflag = 0;
	if (!((IRIS_BYPASS_MODE == iris_cfg->current_mode) && (IRIS_MODE_BYPASS == iris_cfg->sf_notify_mode))) {
		iris_reg_add(IRIS_MIPI_RX_ADDR + 0x4, 0x1);
		pr_debug("send flag\n");
	}
	iris_info.power_status.low_power = 1;
	pr_debug("enter low power mode\n");
}

void iris_low_power_stop_mcu(struct mdss_dsi_ctrl_pdata *ctrl, bool stop, int state)
{
	u32 grcp_len = 0;
	struct dsi_cmd_desc iris_grcp_cmd[] = {
		{{ DTYPE_GEN_LWRITE, 1, 0, 0, 0, CMD_PKT_SIZE}, grcp_cmd.cmd},
	};
	struct dsi_panel_cmds panel_cmds;

	memset(&grcp_cmd, 0, sizeof(grcp_cmd));
	memcpy(grcp_cmd.cmd, grcp_header, GRCP_HEADER);
	grcp_cmd.cmd_len = GRCP_HEADER;

	if (stop) {
		iris_cmd_reg_add(&grcp_cmd, IRIS_MIPI_RX_ADDR + 0x4, 2);
	} else {
		/* wake up MCU */
		iris_cmd_reg_add(&grcp_cmd, 0xf0060008, 0x00000001);
		iris_cmd_reg_add(&grcp_cmd, 0xf006000c, 0x00000001);
	}

	grcp_len = (grcp_cmd.cmd_len - GRCP_HEADER) / 4;
	*(u32 *)(grcp_cmd.cmd + 8) = cpu_to_le32(grcp_len + 1);
	*(u16 *)(grcp_cmd.cmd + 14) = cpu_to_le16(grcp_len);

	iris_grcp_cmd[0].dchdr.dlen = grcp_cmd.cmd_len;

	pr_debug("iris low power mcu stop: %d\n", stop);

	panel_cmds.cmds = iris_grcp_cmd;
	panel_cmds.cmd_cnt = ARRAY_SIZE(iris_grcp_cmd);
	panel_cmds.link_state = state;
	iris_dsi_cmds_send(ctrl, &panel_cmds);
}

 void iris_low_power_mode_set(struct mdss_dsi_ctrl_pdata *ctrl, bool enable)
 {
	u32 grcp_len = 0;
	struct dsi_cmd_desc iris_grcp_cmd[] = {
		{{ DTYPE_GEN_LWRITE, 1, 0, 0, 0, CMD_PKT_SIZE}, grcp_cmd.cmd},
	};
	struct dsi_panel_cmds panel_cmds;
	struct iris_work_mode *pwork_mode = &(iris_info.work_mode);
	struct iris_clock_setting *clock = &iris_info.setting_info.clock_setting;
	struct iris_pll_setting *pll = &iris_info.setting_info.pll_setting;
	int i;

	memset(&grcp_cmd, 0, sizeof(grcp_cmd));
	memcpy(grcp_cmd.cmd, grcp_header, GRCP_HEADER);
	grcp_cmd.cmd_len = GRCP_HEADER;

	if (enable) {
		/* power down edram1~8 */
		iris_cmd_reg_add(&grcp_cmd, 0xf1040000, 0x1e7fde51);
		iris_cmd_reg_add(&grcp_cmd, 0xf104000c, 0xfffffffe);

		/*disable DPHY*/
		if(pwork_mode->rx_ch) {
			iris_cmd_reg_add(&grcp_cmd, 0xf0160000, 0x00000000);
			iris_cmd_reg_add(&grcp_cmd, 0xf0160030, 0x00000000);
		}
		iris_cmd_reg_add(&grcp_cmd, 0xf0180000, 0x0a00c138);
		iris_cmd_reg_add(&grcp_cmd, 0xf0180004, 0x00000000);
		iris_cmd_reg_add(&grcp_cmd, 0xf0180018, 0x00000101);
		if(pwork_mode->tx_ch) {
			iris_cmd_reg_add(&grcp_cmd, 0xf01c0000, 0x0a00c138);
			iris_cmd_reg_add(&grcp_cmd, 0xf01c0004, 0x00000000);
			iris_cmd_reg_add(&grcp_cmd, 0xf01c0018, 0x00000101);
		}

		/* set clock source to XCLK */
		iris_cmd_reg_add(&grcp_cmd, 0xf0000210, 0x0000070b);
		iris_cmd_reg_add(&grcp_cmd, 0xf0000214, 0x0000070b);
		iris_cmd_reg_add(&grcp_cmd, 0xf0000218, 0x00000f0b);
		iris_cmd_reg_add(&grcp_cmd, 0xf000021c, 0x0000070b);
		iris_cmd_reg_add(&grcp_cmd, 0xf0000228, 0x0000070b);
		iris_cmd_reg_add(&grcp_cmd, 0xf0000014, 0x00000001);
		iris_cmd_reg_add(&grcp_cmd, 0xf0000014, 0x00000000);

		/* power down PLL */
		iris_cmd_reg_add(&grcp_cmd, 0xf0000140, 0x00000003);
		iris_cmd_reg_add(&grcp_cmd, 0xf0000150, 0x00002003);
		iris_cmd_reg_add(&grcp_cmd, 0xf0000160, 0x00000003);

		/* gate off clock */
		iris_cmd_reg_add(&grcp_cmd, 0xf0000000, 0x3fc87fff);
		iris_cmd_reg_add(&grcp_cmd, 0xf0000004, 0x00007f8e);

		/* power down MIPI_RX1/FRC/CORE domain */
		iris_cmd_reg_add(&grcp_cmd, 0xf0000038, 0x1007001f);
		iris_cmd_reg_add(&grcp_cmd, 0xf0000040, 0x0207000f);
		iris_cmd_reg_add(&grcp_cmd, 0xf000003c, 0x1007000f);
	} else {

		/* power up MIPI_RX1/FRC/CORE domain */
		iris_cmd_reg_add(&grcp_cmd, 0xf0000040, 0x02070000);
		if (pwork_mode->rx_ch)
			iris_cmd_reg_add(&grcp_cmd, 0xf0000038, 0x10070000);
		iris_cmd_reg_add(&grcp_cmd, 0xf000003c, 0x10070000);
		/* gate on clock */
		if (pwork_mode->rx_ch) {
			iris_cmd_reg_add(&grcp_cmd, 0xf0000000, 0x20000000);
			iris_cmd_reg_add(&grcp_cmd, 0xf0000004, 0x00000000);
		} else {
			iris_cmd_reg_add(&grcp_cmd, 0xf0000000, 0x2cc00044);
			iris_cmd_reg_add(&grcp_cmd, 0xf0000004, 0x00000280);
		}
		iris_cmd_reg_add(&grcp_cmd, 0xf0000248, 0x02008000);

		/* power up PLL */
		iris_cmd_reg_add(&grcp_cmd, 0xf0000140, pll->ppll_ctrl0);
		iris_cmd_reg_add(&grcp_cmd, 0xf0000150, pll->dpll_ctrl0);
		iris_cmd_reg_add(&grcp_cmd, 0xf0000160, pll->mpll_ctrl0);

		/* add delay for core domain & PLL power up */
		for (i = 0; i < 30; i++)
			iris_cmd_reg_add(&grcp_cmd, 0xf0000280, 0x10);

		/* restore clock source */
		iris_cmd_reg_add(&grcp_cmd, IRIS_SYS_ADDR + DCLK_SRC_SEL, clock->dclk.sel | (clock->dclk.div << 8) | (clock->dclk.div_en << 10));
		iris_cmd_reg_add(&grcp_cmd, IRIS_SYS_ADDR + INCLK_SRC_SEL, clock->inclk.sel | (clock->inclk.div << 8) | (clock->inclk.div_en << 10));
		iris_cmd_reg_add(&grcp_cmd, IRIS_SYS_ADDR + MCUCLK_SRC_SEL, clock->mcuclk.sel | (clock->mcuclk.div << 8) | (clock->mcuclk.div_en << 12));
		iris_cmd_reg_add(&grcp_cmd, IRIS_SYS_ADDR + PCLK_SRC_SEL, clock->pclk.sel | (clock->pclk.div << 8) | (clock->pclk.div_en << 10));
		iris_cmd_reg_add(&grcp_cmd, IRIS_SYS_ADDR + MCLK_SRC_SEL, clock->mclk.sel | (clock->mclk.div << 8) | (clock->mclk.div_en << 10));
		iris_cmd_reg_add(&grcp_cmd, 0xf0000014, 0x00000001);
		iris_cmd_reg_add(&grcp_cmd, 0xf0000014, 0x00000000);

		/* enable DPHY */
		if(pwork_mode->rx_ch) {
			iris_cmd_reg_add(&grcp_cmd, 0xf0160030, 0x00000001);
			iris_cmd_reg_add(&grcp_cmd, 0xf0160000, 0x00000001);
		}
		iris_cmd_reg_add(&grcp_cmd, 0xf0180004, 0x00000001);
		iris_cmd_reg_add(&grcp_cmd, 0xf0180000, 0x0a00c139);
		if(pwork_mode->tx_ch) {
			iris_cmd_reg_add(&grcp_cmd, 0xf01c0004, 0x00000001);
			iris_cmd_reg_add(&grcp_cmd, 0xf01c0000, 0x0a00c139);
		}

		/* power up edram1~8 */
		iris_cmd_reg_add(&grcp_cmd, 0xf104000c, 0x00000000);
		iris_cmd_reg_add(&grcp_cmd, 0xf1040000, 0x1e7fde52);
	}

	grcp_len = (grcp_cmd.cmd_len - GRCP_HEADER) / 4;
	*(u32 *)(grcp_cmd.cmd + 8) = cpu_to_le32(grcp_len + 1);
	*(u16 *)(grcp_cmd.cmd + 14) = cpu_to_le16(grcp_len);

	iris_grcp_cmd[0].dchdr.dlen = grcp_cmd.cmd_len;

	pr_debug("iris low power mode: %d\n", enable);

	panel_cmds.cmds = iris_grcp_cmd;
	panel_cmds.cmd_cnt = ARRAY_SIZE(iris_grcp_cmd);
	panel_cmds.link_state = DSI_LP_MODE;
	iris_dsi_cmds_send(ctrl, &panel_cmds);

 }
 
void iris_mipitx_te_source_change(struct mdss_dsi_ctrl_pdata *ctrl)
{

	u32 grcp_len = 0;
	struct dsi_cmd_desc iris_grcp_cmd[] = {
		{{ DTYPE_GEN_LWRITE, 1, 0, 0, 0, CMD_PKT_SIZE}, grcp_cmd.cmd},
	};
	struct dsi_panel_cmds panel_cmds;

	struct iris_work_mode *pwork_mode = &(iris_info.work_mode);
	u32 tx_ch, mipitx_addr = IRIS_MIPI_TX_ADDR;

	memset(&grcp_cmd, 0, sizeof(grcp_cmd));
	memcpy(grcp_cmd.cmd, grcp_header, GRCP_HEADER);
	grcp_cmd.cmd_len = GRCP_HEADER;

	for (tx_ch = 0; tx_ch < (pwork_mode->tx_ch + 1); tx_ch++) {
		#ifdef MIPI_SWAP
			mipitx_addr -= tx_ch * IRIS_MIPI_ADDR_OFFSET;
		#else
			mipitx_addr += tx_ch * IRIS_MIPI_ADDR_OFFSET;
		#endif
		iris_cmd_reg_add(&grcp_cmd, mipitx_addr + TE_FLOW_CTRL, 0x00000100);
	}

	iris_cmd_reg_add(&grcp_cmd, IRIS_SYS_ADDR + ALT_CTRL0, 0x00008000);

	grcp_len = (grcp_cmd.cmd_len - GRCP_HEADER) / 4;
	*(u32 *)(grcp_cmd.cmd + 8) = cpu_to_le32(grcp_len + 1);
	*(u16 *)(grcp_cmd.cmd + 14) = cpu_to_le16(grcp_len);

	iris_grcp_cmd[0].dchdr.dlen = grcp_cmd.cmd_len;

	panel_cmds.cmds = iris_grcp_cmd;
	panel_cmds.cmd_cnt = ARRAY_SIZE(iris_grcp_cmd);
	panel_cmds.link_state = DSI_LP_MODE;
	iris_dsi_cmds_send(ctrl, &panel_cmds);
}

void iris_abypass_switch_state_init(int mode)
{
	if (!iris_info.abypss_ctrl.analog_bypass_enable)
		return;

	if (IRIS_MODE_PT2BYPASS == mode) {
		iris_info.abypss_ctrl.pt_to_abypass_enable = 1;
		iris_info.abypss_ctrl.abypass_to_pt_enable = 0;
		iris_info.abypss_ctrl.abypss_switch_state = MCU_STOP_ENTER_STATE;
		iris_info.abypss_ctrl.frame_delay = 0;

		pr_debug("pt->analog bypass\n");
	} else if (IRIS_MODE_BYPASS2PT == mode) {
		iris_info.abypss_ctrl.pt_to_abypass_enable = 0;
		iris_info.abypss_ctrl.abypass_to_pt_enable = 1;
		iris_info.abypss_ctrl.abypss_switch_state = LOW_POWER_EXIT_STATE;
		iris_info.abypss_ctrl.frame_delay = 0;

		pr_debug("analog bypass->pt\n");
	}
}
  int iris_pt_to_abypass_switch(struct mdss_dsi_ctrl_pdata *ctrl)
 {

	int *pswitch_state = &iris_info.abypss_ctrl.abypss_switch_state;
	int *pframe_delay = &iris_info.abypss_ctrl.frame_delay;
	int bypass_mode = BYPASS_CMD, pwil_mode = PWIL_CMD, ret = false;
	u8 signal_mode = 0xff;

	if (!iris_info.abypss_ctrl.pt_to_abypass_enable)
		return ret;

	if (iris_info.work_mode.rx_mode) {
		bypass_mode = BYPASS_CMD;
		pwil_mode = PWIL_CMD;
	} else {
		bypass_mode = BYPASS_VIDEO;
		pwil_mode = PWIL_VIDEO;
	}


	/*if state switch need delay several video frames*/
	if (*pframe_delay > 0)
		*pframe_delay -= 1;
	if (*pframe_delay > 0)
		return ret;


	switch (*pswitch_state) {
	case MCU_STOP_ENTER_STATE:
		/* MCU Stop */
		iris_low_power_stop_mcu(ctrl, true, DSI_HS_MODE);
		*pswitch_state = TTL_CMD_BYPASS_STATE;
		*pframe_delay = 5;
		break;
	case TTL_CMD_BYPASS_STATE:
		/* TTL/CMD bypass */
		signal_mode = iris_mipi_signal_mode_read(g_ctrl, DSI_LP_MODE);
		if (signal_mode == 0) {
			iris_mipirx_mode_set(ctrl, bypass_mode, DSI_HS_MODE);
			*pswitch_state = ANALOG_BYPASS_ENTER_STATE;
			*pframe_delay = 1;
		} else {
			*pframe_delay = 3;
		}
		pr_debug("signal_mode: 0x%x\n", signal_mode);

		break;
	case ANALOG_BYPASS_ENTER_STATE:
		/* analog bypass */
		iris_one_wired_cmd_send(ctrl, BYPASS_MODE_CHANGE);
		*pswitch_state = LOW_POWER_ENTER_STATE;
		*pframe_delay = 1;
		break;
	case LOW_POWER_ENTER_STATE:
		/* enter low power mode */
		iris_mipirx_mode_set(ctrl, pwil_mode, DSI_LP_MODE);


		iris_low_power_mode_set(ctrl, true);
		*pswitch_state = ANALOG_BYPASS_STATE;
		*pframe_delay = 1;
		break;
	case ANALOG_BYPASS_STATE:
		*pframe_delay = 0;
		iris_info.abypss_ctrl.abypass_status = ANALOG_BYPASS_MODE;
		iris_info.abypss_ctrl.pt_to_abypass_enable = 0;
		ret = true;
		break;
	default:
		break;
	}
	pr_debug("state: %d, delay: %d\n", *pswitch_state, *pframe_delay);

	return ret;
}

int iris_abypass_to_pt_switch(struct mdss_dsi_ctrl_pdata *ctrl)
{
	int *pswitch_state = &iris_info.abypss_ctrl.abypss_switch_state;
	int *pframe_delay = &iris_info.abypss_ctrl.frame_delay;

	int bypass_mode = BYPASS_CMD, pwil_mode = PWIL_CMD, ret = false;

	if (!iris_info.abypss_ctrl.abypass_to_pt_enable)
		return ret;

	if (iris_info.work_mode.rx_mode) {
		bypass_mode = BYPASS_CMD;
		pwil_mode = PWIL_CMD;
	} else {

		bypass_mode = BYPASS_VIDEO;
		pwil_mode = PWIL_VIDEO;
	}
	/*if state switch need delay several video frames*/
	if (*pframe_delay > 0)
		*pframe_delay -= 1;
	if (*pframe_delay > 0)
		return ret;

	switch (*pswitch_state) {
	case LOW_POWER_EXIT_STATE:
		/* exit low power mode */
		iris_low_power_mode_set(ctrl, false);
		*pswitch_state = MCU_STOP_EXIT_STATE;
		*pframe_delay = 1;
		break;
	case MCU_STOP_EXIT_STATE:
		/* resume MCU */
		iris_low_power_stop_mcu(ctrl, false, DSI_LP_MODE);
		iris_mipirx_mode_set(ctrl, bypass_mode, DSI_LP_MODE);

		*pswitch_state = ANALOG_BYPASS_EXIT_STATE;
		/* AP should wait Firmware ready */
		*pframe_delay = 15;
		break;
	case ANALOG_BYPASS_EXIT_STATE:
		/* analog bypass */
		iris_one_wired_cmd_send(ctrl, BYPASS_MODE_CHANGE);

		*pswitch_state = PASS_THROUGH_STATE;
		*pframe_delay = 1;
		break;
	case PASS_THROUGH_STATE:
		iris_mipirx_mode_set(ctrl, pwil_mode, DSI_LP_MODE);
		iris_pwil_mode_set(ctrl, PT_MODE, DSI_HS_MODE);
		/* change TX's TE source */
		if (iris_info.work_mode.tx_mode)
			iris_mipitx_te_source_change(ctrl);

		*pframe_delay = 0;
		iris_info.abypss_ctrl.abypass_status = PASS_THROUGH_MODE;
		iris_info.abypss_ctrl.abypass_to_pt_enable = 0;
		ret = true;
		break;
	default:
		break;
	}
	pr_debug("state: %d, delay: %d\n", *pswitch_state, *pframe_delay);

	return ret;
}

void iris_abypass_switch_proc(struct mdss_dsi_ctrl_pdata *ctrl)
{
	if (!iris_info.abypss_ctrl.abypass_debug)
		return;

	if (iris_info.abypss_ctrl.analog_bypass_enable) {
		if (iris_info.abypss_ctrl.abypass_status == PASS_THROUGH_MODE) {
			if (true == iris_pt_to_abypass_switch(ctrl))
				iris_info.abypss_ctrl.abypass_debug = false;
		}
		if (iris_info.abypss_ctrl.abypass_status == ANALOG_BYPASS_MODE) {
			if (true == iris_abypass_to_pt_switch(ctrl))
				iris_info.abypss_ctrl.abypass_debug = false;
		}
 	}
}
void iris_fw_download_cont_splash(struct mdss_dsi_ctrl_pdata *ctrl, bool video_freeze)
{
	//struct mdss_mdp_ctl *ctl = mfd_to_ctl(gp_mfd);


	pr_debug("off video\n");
	if (iris_info.work_mode.rx_mode) {
		if (video_freeze) {
			//mdss_mdp_lock(gp_mfd, 1);
			msleep(100);
		}
	} else {
		//mdss_mdp_time_engine_ctrl(ctl, 0);

		/* reset dsi */
		mdss_dsi_ctrl_setup(ctrl);
		mdss_dsi_sw_reset(ctrl, true);

		/* switch to cmd mode */
		iris_mipirx_mode_set(ctrl, PWIL_CMD, DSI_HS_MODE);
	}

	/* firmware download */
	pr_debug("firmware download\n");
	iris_info.firmware_info.fw_dw_result =
		iris2p_firmware_download(ctrl, gp_mfd, IRIS_FIRMWARE_NAME, true);
	if (SUCCESS == iris_info.firmware_info.fw_dw_result) {
		iris_ctrl_cmd_send(ctrl, ITCM_COPY + REMAP, DSI_HS_MODE);
		gp_mfd->iris_conf.ready = true;
		iris_info.power_status.low_power = 0;
		iris_info.power_status.low_power_state = 0;
		iris_info.power_status.work_state_wait = 6;
	}

	msleep(50);
	if (iris_info.work_mode.rx_mode) {
		if (video_freeze) {
			//mdss_mdp_lock(gp_mfd, 0);
		}
	} else {
		//mdss_mdp_time_engine_ctrl(ctl, 1);

		/* restore to video mode */
		iris_mipirx_mode_set(ctrl, PWIL_VIDEO, DSI_HS_MODE);
	}
	pr_debug("on video\n");

}


static ssize_t iris_one_wired_write(struct file *file, const char __user *buff,
	size_t count, loff_t *ppos)
{
	unsigned long val;

	if (kstrtoul_from_user(buff, count, 0, &val))
		return -EFAULT;

	if (SUCCESS == iris_one_wired_cmd_init(g_ctrl))
		iris_one_wired_cmd_send(g_ctrl, val);

	pr_debug("one wired %u\n", (u32)val);

	return count;
}

static ssize_t iris_fw_dw_write(struct file *file, const char __user *buff,
	size_t count, loff_t *ppos)
{
	unsigned long val;

	if (kstrtoul_from_user(buff, count, 0, &val))
		return -EFAULT;

	iris_fw_download_cont_splash(g_ctrl, 1);

	return count;
}

static ssize_t iris_abypass_switch_write(struct file *file, const char __user *buff,
	size_t count, loff_t *ppos)
{
	unsigned long val;
	static int cnt = 0;

	if (kstrtoul_from_user(buff, count, 0, &val))
		return -EFAULT;

	if (!iris_info.abypss_ctrl.analog_bypass_enable) {
		pr_debug("analog bypass is not enabled\n");
		return count;
	}

	iris_info.abypss_ctrl.abypass_debug = true;
	cnt++;
	if (val) {
		iris_info.abypss_ctrl.pt_to_abypass_enable = 1;
		iris_info.abypss_ctrl.abypass_to_pt_enable = 0;
		iris_info.abypss_ctrl.abypss_switch_state = MCU_STOP_ENTER_STATE;
		iris_info.abypss_ctrl.frame_delay = 0;
		pr_err("pt->analog bypass, %d\n", cnt);

	} else {
		iris_info.abypss_ctrl.pt_to_abypass_enable = 0;
		iris_info.abypss_ctrl.abypass_to_pt_enable = 1;
		iris_info.abypss_ctrl.abypss_switch_state = LOW_POWER_EXIT_STATE;
		iris_info.abypss_ctrl.frame_delay = 0;
		pr_err("analog bypass->pt, %d\n", cnt);
	}

	return count;
}

static const struct file_operations iris_one_wired_fops = {
	.open = simple_open,
	.write = iris_one_wired_write,
};

static const struct file_operations iris_fw_dw_fops = {
	.open = simple_open,
	.write = iris_fw_dw_write,
};

static const struct file_operations iris_abypss_switch_fops = {
	.open = simple_open,
	.write = iris_abypass_switch_write,
};

int iris2p_debugfs_init(struct msm_fb_data_type *mfd)
{
	if (mfd->index != 0)
		return 0;
	if (!(mfd->panel.type == MIPI_VIDEO_PANEL || mfd->panel.type == MIPI_CMD_PANEL))
		return 0;

	gp_mfd = mfd;
	pr_debug("gp_mfd %p\n", gp_mfd);
	pr_debug("%s:%d: mfd->panel.type: %i mfd->panel.id: %i\n", __func__, __LINE__, mfd->panel.type, mfd->panel.id);

	if (debugfs_create_file("iris_one_wired", 0644, NULL, mfd,
				&iris_one_wired_fops) == NULL) {
		pr_err("%s(%d): debugfs_create_file: index fail\n",
			__FILE__, __LINE__);
		return -EFAULT;
	}
	if (debugfs_create_file("iris_fw_dw", 0644, NULL, mfd,
				&iris_fw_dw_fops) == NULL) {
		pr_err("%s(%d): debugfs_create_file: index fail\n",
			__FILE__, __LINE__);
		return -EFAULT;
	}
	if (debugfs_create_file("iris_abypss_switch", 0644, NULL, mfd,
				&iris_abypss_switch_fops) == NULL) {
		pr_err("%s(%d): debugfs_create_file: index fail\n",
			__FILE__, __LINE__);
		return -EFAULT;
	}

	return 0;
}
#endif
static void iris_dsi_panel_cmds_send(struct mdss_dsi_ctrl_pdata *ctrl,
			struct dsi_panel_cmds *pcmds)
{
	struct dcs_cmd_req cmdreq;
	struct mdss_panel_info *pinfo;

	pinfo = &(ctrl->panel_data.panel_info);
	if (pinfo->dcs_cmd_by_left) {
		if (ctrl->ndx != DSI_CTRL_LEFT)
			return;
	}

	memset(&cmdreq, 0, sizeof(cmdreq));
	cmdreq.cmds = pcmds->cmds;
	cmdreq.cmds_cnt = pcmds->cmd_cnt;
	cmdreq.flags = CMD_REQ_COMMIT;

	/*Panel ON/Off commands should be sent in DSI Low Power Mode*/
	if (pcmds->link_state == DSI_LP_MODE)
		cmdreq.flags  |= CMD_REQ_LP_MODE;
	else if (pcmds->link_state == DSI_HS_MODE)
		cmdreq.flags |= CMD_REQ_HS_MODE;

	cmdreq.rlen = 0;
	cmdreq.cb = NULL;
	mdss_dsi_cmdlist_put(ctrl, &cmdreq);
}

void iris_panel_cmds(struct mdss_dsi_ctrl_pdata *ctrl, struct dsi_panel_cmds *pcmds)
{
	bool broadcast;
	bool trigger;

	if (iris_info.panel_cmd_sync_wait_broadcast && ctrl->ndx == DSI_CTRL_LEFT)
		pcmds = NULL;

	if (pcmds && pcmds->cmd_cnt) {
		if (iris_info.panel_cmd_sync_wait_broadcast) {
			broadcast = ctrl->cmd_sync_wait_broadcast;
			trigger = ctrl->cmd_sync_wait_trigger;
			ctrl->cmd_sync_wait_broadcast = true;
			ctrl->cmd_sync_wait_trigger = true;
			iris_dsi_panel_cmds_send(ctrl, pcmds);
			ctrl->cmd_sync_wait_broadcast = broadcast;
			ctrl->cmd_sync_wait_trigger = trigger;
		} else {
			iris_dsi_panel_cmds_send(ctrl, pcmds);
		}
	}
}
