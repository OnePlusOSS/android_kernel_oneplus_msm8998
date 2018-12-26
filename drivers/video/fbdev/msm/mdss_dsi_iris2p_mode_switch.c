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
#include "mdss_dsi_iris2p_def.h"
#include "mdss_dsi_iris2p_extern.h"
#include "mdss_dsi_iris2p_mode_switch.h"
#include "mdss_dsi_iris2p_lightup.h"
#include "mdss_debug.h"

static enum iris_frc_prepare_state eiris_frc_prepare_state;
static enum iris_frc_cancel_state eiris_frc_cancel_state;
static enum iris_mode_rfb2frc_state eiris_mode_rfb2frc_state;
static enum iris_rfb_prepare_state eiris_rfb_prepare_state;
static enum iris_mode_frc2rfb_state eiris_mode_frc2rfb_state;
static enum iris_pt_prepare_state eiris_pt_prepare_state;
static enum iris_mode_pt2rfb_state eiris_mode_pt2rfb_state;
static enum iris_mode_rfb2pt_state eiris_mode_rfb2pt_state;
static int iris_mode_bypass_switch(int val);

static void iris_memc_path_commands_update(void)
{
	struct iris_fun_enable *enable = (struct iris_fun_enable *)&g_mfd->iris_conf.frc_path;

	if (g_mfd->iris_conf.true_cut_enable)
		enable->true_cut_en = 1;
	else
		enable->true_cut_en = 0;

	enable->nrv_drc_en = 0;
	if (g_mfd->iris_conf.nrv_enable)
		enable->nrv_drc_en = 1;
#ifdef CONFIG_IRIS2P_DRC_SUPPORT
	if (g_mfd->iris_conf.drc_enable)
		enable->nrv_drc_en = 1;
#endif
	if (iris_is_peaking_setting_disable() && iris_is_cm_setting_disable())
		enable->pp_en = 0;
	else
		enable->pp_en = 1;
	enable->use_efifo_en = 0;
	enable->psr_post_sel = 0;
	enable->frc_data_format = 1;
	enable->capt_bitwidth = 0;
	enable->psr_bitwidth = 0;
#if defined(FPGA_PLATFORM)
	// TODO: enable all feature to do test
	enable->dbc_lce_en = 1;
	enable->dpp_en = 1;
#else
	if (!iris_is_lce_setting_disable() || !iris_is_dbc_setting_disable())
		enable->dbc_lce_en = 1;
	else
		enable->dbc_lce_en = 0;
#endif
	*(u32 *)(iris_memc_enter_cmds + 20) = cpu_to_le32(g_mfd->iris_conf.frc_path);
}

static void iris_pt_path_commands_update(void)
{
	struct iris_fun_enable *enable = (struct iris_fun_enable *)&g_mfd->iris_conf.pt_path;

	if (iris_is_peaking_setting_disable() && iris_is_cm_setting_disable())
		enable->pp_en = 0;
	else
		enable->pp_en = 1;
	enable->use_efifo_en = 0;
	enable->psr_post_sel = 0;
	enable->frc_data_format = 1;
	enable->capt_bitwidth = 0;
	enable->psr_bitwidth = 0;
#if defined(FPGA_PLATFORM)
	// TODO: enable all feature to do test
	enable->dbc_lce_en = 1;
	enable->dpp_en = 1;
#else
	if (!iris_is_lce_setting_disable() || !iris_is_dbc_setting_disable())
		enable->dbc_lce_en = 1;
	else
		enable->dbc_lce_en = 0;
#endif
	*(u32 *)(iris_pt_enter_cmds + 20) = cpu_to_le32(g_mfd->iris_conf.pt_path);
}

static void iris_rfb_path_commands_update(void)
{
	struct iris_fun_enable *enable = (struct iris_fun_enable *)&g_mfd->iris_conf.rfb_path;

	if (iris_is_peaking_setting_disable() && iris_is_cm_setting_disable())
		enable->pp_en = 0;
	else
		enable->pp_en = 1;
	enable->use_efifo_en = 0;
	enable->psr_post_sel = 1;
	enable->frc_data_format = 1;
	enable->capt_bitwidth = 0;
	enable->psr_bitwidth = 0;
#if defined(FPGA_PLATFORM)
	// TODO: enable all feature to do test
	enable->dbc_lce_en = 1;
	enable->dpp_en = 1;
#else
	if (!iris_is_lce_setting_disable() || !iris_is_dbc_setting_disable())
		enable->dbc_lce_en = 1;
	else
		enable->dbc_lce_en = 0;
#endif
	*(u32 *)(iris_rfb_enter_cmds + 20) = cpu_to_le32(g_mfd->iris_conf.rfb_path);
}

static int iris_memc_reg_write(struct msm_fb_data_type *mfd, struct fi_demo_win fi_demo_win_para)
{
	int endx, endy, startx, starty;
	static int hres, vres;
	struct iris_config *iris_cfg = &mfd->iris_conf;
	int displaywidth = (iris_info.work_mode.tx_ch  ?  iris_info.output_timing.hres * 2 : iris_info.output_timing.hres);

	if ((lp_memc_timing[0] != hres) || (lp_memc_timing[1] != vres)) {
		iris_info.update.demo_win_fi = true;
		hres = lp_memc_timing[0];
		vres = lp_memc_timing[1];
	}

	pr_debug("iris_cfg->nrv_enable: %d\n", iris_cfg->nrv_enable);
	if (iris_info.update.demo_win_fi && (iris_info.setting_info.quality_cur.pq_setting.memcdemo == 5)) {
		iris_info.update.demo_win_fi = false;
		if (!iris_cfg->nrv_enable) {
			startx = iris_info.fi_demo_win_info.startx * lp_memc_timing[0] / displaywidth;
			starty = iris_info.fi_demo_win_info.starty * lp_memc_timing[1] / iris_info.output_timing.vres;
			endx = iris_info.fi_demo_win_info.endx *  lp_memc_timing[0] / displaywidth;
			endy = iris_info.fi_demo_win_info.endy *  lp_memc_timing[1] / iris_info.output_timing.vres;

			if (endy + iris_info.fi_demo_win_info.borderwidth >= lp_memc_timing[1])
				endy = lp_memc_timing[1] - iris_info.fi_demo_win_info.borderwidth;

			pr_debug("iris: %s: startx = %d, starty = %d, endx = %d, endy = %d, lp_memc_timing[0] = %d, lp_memc_timing[1] = %d.\n",
					__func__, startx, starty, endx, endy, lp_memc_timing[0], lp_memc_timing[1]);
			fi_demo_win_para.colsize = (startx & 0xfff) | ((endx & 0xfff) << 16);
			fi_demo_win_para.rowsize = (starty & 0xfff) | ((endy & 0xfff) << 16);
		}

		iris_reg_add(FI_DEMO_COL_SIZE, fi_demo_win_para.colsize);
		iris_reg_add(FI_DEMO_MODE_RING, fi_demo_win_para.color);
		iris_reg_add(FI_DEMO_ROW_SIZE, fi_demo_win_para.rowsize);
		iris_reg_add(FI_DEMO_MODE_CTRL, fi_demo_win_para.modectrl);
		iris_reg_add(FI_SHADOW_UPDATE, 1);
	}
	return 0;
}

static void mdss_dsi_panel_cmds_send(struct mdss_dsi_ctrl_pdata *ctrl,
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
	if (pcmds->link_state == DSI_HS_MODE)
		cmdreq.flags |= CMD_REQ_HS_MODE;

	cmdreq.rlen = 0;
	cmdreq.cb = NULL;

	mdss_dsi_cmdlist_put(ctrl, &cmdreq);
}


void iris_dms_config(struct mdss_dsi_ctrl_pdata *ctrl)
{
	char dms_pwil_conf[] = {
		PWIL_TAG('P', 'W', 'I', 'L'),
		PWIL_TAG('G', 'R', 'C', 'P'),
		PWIL_U32(0x00000007),	// valid word number
		0x00,			// burst mode
		0x00,			// reserved
		PWIL_U16(0x06),		// burst length
		PWIL_U32(IRIS_PWIL_ADDR + 0x0004),  //PWIL ctrl1 confirm transfer mode and cmd mode
		PWIL_U32(0x00082018),
		PWIL_U32(IRIS_DTG_ADDR + 0x0070),  //DTG_CTRL_1/CMD_MODE_EN
		PWIL_U32(0x00000001),
		PWIL_U32(IRIS_DTG_ADDR + 0x10000),  //DTG/REGSEL
		PWIL_U32(0x00000001),
	};

	struct dsi_cmd_desc iris2_dms_restore[] = {
		{ {DTYPE_GEN_LWRITE, 1, 0, 0, 0,  sizeof(dms_pwil_conf)}, dms_pwil_conf}
	};
	struct dsi_panel_cmds panel_cmds;

	pr_info("%s:, rx_mode=%d\n", __func__, iris_info.work_mode.rx_mode);
	//confirm pwil work mode, video or cmd.
	if (MIPI_VIDEO_MODE == iris_info.work_mode.rx_mode)
		dms_pwil_conf[20] = 0x18;
	else
		dms_pwil_conf[20] = 0x1a;

	if (0 != iris_info.work_mode.rx_ch)
		dms_pwil_conf[20] |= 0x01;	//dual channel

	//confirm DTG_CTRL_1/CMD_MODE_EN
	if (MIPI_VIDEO_MODE == iris_info.work_mode.rx_mode)
		dms_pwil_conf[28] = 0x00;
	else
		dms_pwil_conf[28] = 0x01;

	panel_cmds.cmds = iris2_dms_restore;
	panel_cmds.cmd_cnt = ARRAY_SIZE(iris2_dms_restore);
	panel_cmds.link_state = DSI_HS_MODE;
	mdss_dsi_panel_cmds_send(ctrl, &panel_cmds);

	pr_info("%s:-\n", __func__);
}

void iris_mipi_tx_cmds_build(struct msm_fb_data_type *mfd, struct dsi_panel_cmds *pcmds)
{
	union iris_mipi_tx_cmd_header header;
	union iris_mipi_tx_cmd_payload payload;
	u32 i = 0, j = 0;
	u32 cmd_cnt = pcmds->cmd_cnt;

	pr_info("%s, cmd_cnt=%d\n", __func__, cmd_cnt);
	while (i < cmd_cnt) {
		memset(&header, 0, sizeof(header));
		memset(&payload, 0, sizeof(payload));
		header.stHdr.dtype = pcmds->cmds[i].dchdr.dtype;
		pr_debug("dtype=0x%x\n", header.stHdr.dtype);
		if (pcmds->cmds[i].dchdr.dlen <= 2) {
			//short write
			header.stHdr.ecc = 0x1;
			header.stHdr.len[0] = pcmds->cmds[i].payload[0];
			if (pcmds->cmds[i].dchdr.dlen == 2)
				header.stHdr.len[1] = pcmds->cmds[i].payload[1];
			pr_debug("%s, line%d, header=0x%4x\n", __func__, __LINE__, header.hdr32);
			iris_reg_add(IRIS_MIPI_TX_ADDR + WR_PACKET_HEADER_OFFS, header.hdr32);
		} else {
			//long write
			header.stHdr.ecc = 0x5;
			header.stHdr.len[0] = pcmds->cmds[i].dchdr.dlen & 0xff;
			header.stHdr.len[1] = (pcmds->cmds[i].dchdr.dlen >> 8) & 0xff;
			pr_debug("%s, line%d, header=0x%x\n", __func__, __LINE__, header.hdr32);
			iris_reg_add(IRIS_MIPI_TX_ADDR + WR_PACKET_HEADER_OFFS, header.hdr32);
			for (j = 0; j < pcmds->cmds[i].dchdr.dlen; j = j+4) {
				memcpy(payload.p, pcmds->cmds[i].payload + j, 4);
				pr_debug("payload=0x%x\n", payload.pld32);
				iris_reg_add(IRIS_MIPI_TX_ADDR + WR_PACKET_PAYLOAD_OFFS, payload.pld32);
			}
		}
		i++;

		//TODO: if the swich cmds count more than GRCP payload limitation (IRIS_REGS),
		//it will lost some cmds.
	}
}

void iris_dtg_mode_set(struct msm_fb_data_type *mfd, int tx_mode)
{
	struct iris_config *iris_cfg = &g_mfd->iris_conf;

	iris_dtg_para_set(iris_info.intf_switch_info.rx_current_mode, tx_mode);

	iris_reg_add(IRIS_DTG_ADDR + DTG_DELAY, iris_cfg->dtg_setting.dtg_delay);
	iris_reg_add(IRIS_DTG_ADDR + TE_CTRL, iris_cfg->dtg_setting.te_ctrl);
	iris_reg_add(IRIS_DTG_ADDR + TE_CTRL_1, iris_cfg->dtg_setting.te_ctrl_1);
	iris_reg_add(IRIS_DTG_ADDR + TE_CTRL_2, iris_cfg->dtg_setting.te_ctrl_2);
	iris_reg_add(IRIS_DTG_ADDR + TE_CTRL_3, iris_cfg->dtg_setting.te_ctrl_3);
	iris_reg_add(IRIS_DTG_ADDR + TE_CTRL_4, iris_cfg->dtg_setting.te_ctrl_4);
	iris_reg_add(IRIS_DTG_ADDR + TE_CTRL_5, iris_cfg->dtg_setting.te_ctrl_5);
	iris_reg_add(IRIS_DTG_ADDR + DTG_CTRL_1,iris_cfg->dtg_setting.dtg_ctrl_1);
	iris_reg_add(IRIS_DTG_ADDR + DTG_CTRL,iris_cfg->dtg_setting.dtg_ctrl);
	iris_reg_add(IRIS_DTG_ADDR + EVS_DLY,iris_cfg->dtg_setting.evs_dly);
	iris_reg_add(IRIS_DTG_ADDR + DVS_CTRL, iris_cfg->dtg_setting.dvs_ctrl);
	iris_reg_add(IRIS_DTG_ADDR + TE_DLY, iris_cfg->dtg_setting.te_dly);
	iris_reg_add(IRIS_DTG_ADDR + TE_DLY_1, iris_cfg->dtg_setting.te_dly_1);
	iris_reg_add(IRIS_DTG_ADDR + VFP_CTRL_1, iris_cfg->dtg_setting.vfp_ctrl_1);
	iris_reg_add(IRIS_DTG_ADDR + REGSEL, 1);
}

void iris_mipitx_cmd_to_video_proc(struct msm_fb_data_type *mfd)
{
	struct iris_config *iris_cfg = &g_mfd->iris_conf;
	uint32_t dport_ctrl0, dsi_tx_ctrl, pwil_ctrl;

	if (iris_cfg->tx_switch_state != IRIS_TX_SWITCH_NONE)
		pr_info("%s, dsi mode switch state = %d\n",
					__func__, iris_cfg->tx_switch_state);

	switch (iris_cfg->tx_switch_state) {
	case IRIS_TX_SWITCH_STEP1:
		pwil_ctrl = 0xa0c80004;

		mutex_lock(&mfd->iris_conf.cmd_mutex);
		iris_reg_add(IRIS_PWIL_ADDR + PWIL_CTRL_OFFS, pwil_ctrl);
		mutex_unlock(&mfd->iris_conf.cmd_mutex);

		iris_cfg->tx_switch_state = IRIS_TX_SWITCH_STEP2;
		break;
	case IRIS_TX_SWITCH_STEP2:
		dport_ctrl0 = 0xe0e24037;
		dsi_tx_ctrl = 0x0a00c039;

		mutex_lock(&mfd->iris_conf.cmd_mutex);
		/* set Iris2p output to video  */
		iris_reg_add(IRIS_DPORT_ADDR + DPORT_CTRL0_OFFS, dport_ctrl0);
		iris_reg_add(IRIS_DPORT_ADDR + DPORT_REGSEL, 1);
		iris_reg_add(IRIS_MIPI_TX_ADDR + DSI_TX_CTRL, dsi_tx_ctrl);
		iris_reg_add(IRIS_MIPI_TX_ADDR + IRIS_MIPI_ADDR_OFFSET + DSI_TX_CTRL, dsi_tx_ctrl);
		iris_dtg_mode_set(mfd, MIPI_VIDEO_MODE);
		mutex_unlock(&mfd->iris_conf.cmd_mutex);

		iris_cfg->tx_switch_state = IRIS_TX_SWITCH_STEP3;
		break;
	case IRIS_TX_SWITCH_STEP3:
		mutex_lock(&mfd->iris_conf.cmd_mutex);
#ifdef IRIS2_PANEL
		uint32_t count;
		/* set Iris2 input to video  */
		iris_reg_add(IRIS_MIPI_TX_ADDR + WR_PACKET_HEADER_OFFS, 0x0100bf13);

		iris_reg_add(IRIS_MIPI_TX_ADDR + WR_PACKET_HEADER_OFFS, 0x05004009);//nop
		for (count = 0; count < 16; count++)
			iris_reg_add(IRIS_MIPI_TX_ADDR + WR_PACKET_PAYLOAD_OFFS, 0x00000000);

		iris_reg_add(IRIS_MIPI_TX_ADDR + WR_PACKET_HEADER_OFFS, 0x05001829);//header
		iris_reg_add(IRIS_MIPI_TX_ADDR + WR_PACKET_PAYLOAD_OFFS, 0x5057494c);//pwil
		iris_reg_add(IRIS_MIPI_TX_ADDR + WR_PACKET_PAYLOAD_OFFS, 0x47524350);//grcp
		iris_reg_add(IRIS_MIPI_TX_ADDR + WR_PACKET_PAYLOAD_OFFS, 0x00000003);
		iris_reg_add(IRIS_MIPI_TX_ADDR + WR_PACKET_PAYLOAD_OFFS, 0x00020000);
		iris_reg_add(IRIS_MIPI_TX_ADDR + WR_PACKET_PAYLOAD_OFFS, 0xf1240004);//addr
		iris_reg_add(IRIS_MIPI_TX_ADDR + WR_PACKET_PAYLOAD_OFFS, 0x00002098);
#else
		iris_mipi_tx_cmds_build(mfd, &(iris_info.tx_switch_cmd.mipitx_cmd2vid_cmds));
#endif
		mutex_unlock(&mfd->iris_conf.cmd_mutex);
		iris_info.intf_switch_info.tx_current_mode = MIPI_VIDEO_MODE;
		iris_cfg->tx_switch_state = IRIS_TX_SWITCH_NONE;
		break;
	default:
		break;
	}

}

void iris_mipitx_video_to_cmd_proc(struct msm_fb_data_type *mfd)
{
	struct iris_config *iris_cfg = &g_mfd->iris_conf;
	uint32_t dport_ctrl0, dsi_tx_ctrl, pwil_ctrl;

	if (iris_cfg->tx_switch_state != IRIS_TX_SWITCH_NONE)
		pr_info("%s, dsi mode switch state = %d\n",
					__func__, iris_cfg->tx_switch_state);

	switch (iris_cfg->tx_switch_state) {
	case IRIS_TX_SWITCH_STEP1:
		mutex_lock(&mfd->iris_conf.cmd_mutex);
#ifdef IRIS2_PANEL
		uint32_t count;
		/* set Iris2 input to cmd  */
		iris_reg_add(IRIS_MIPI_TX_ADDR + WR_PACKET_HEADER_OFFS, 0x01007f13);

		iris_reg_add(IRIS_MIPI_TX_ADDR + WR_PACKET_HEADER_OFFS, 0x05004009);
		for (count = 0; count < 16; count++)
			iris_reg_add(IRIS_MIPI_TX_ADDR + WR_PACKET_PAYLOAD_OFFS, 0x00000000);

		iris_reg_add(IRIS_MIPI_TX_ADDR + WR_PACKET_HEADER_OFFS, 0x05001829);
		iris_reg_add(IRIS_MIPI_TX_ADDR + WR_PACKET_PAYLOAD_OFFS, 0x5057494c);
		iris_reg_add(IRIS_MIPI_TX_ADDR + WR_PACKET_PAYLOAD_OFFS, 0x47524350);
		iris_reg_add(IRIS_MIPI_TX_ADDR + WR_PACKET_PAYLOAD_OFFS, 0x00000003);
		iris_reg_add(IRIS_MIPI_TX_ADDR + WR_PACKET_PAYLOAD_OFFS, 0x00020000);
		iris_reg_add(IRIS_MIPI_TX_ADDR + WR_PACKET_PAYLOAD_OFFS, 0xf1240004);
		iris_reg_add(IRIS_MIPI_TX_ADDR + WR_PACKET_PAYLOAD_OFFS, 0x0000209a);
#else
		iris_mipi_tx_cmds_build(mfd, &(iris_info.tx_switch_cmd.mipitx_vid2cmd_cmds));
#endif
		mutex_unlock(&mfd->iris_conf.cmd_mutex);
		iris_cfg->tx_switch_state = IRIS_TX_SWITCH_STEP2;
		break;
	case IRIS_TX_SWITCH_STEP2:
		dport_ctrl0 = 0xe0e2c037;
		dsi_tx_ctrl = 0x0a00c139;

		mutex_lock(&mfd->iris_conf.cmd_mutex);
		/* set Iris2p_DPORT to output both TTL&PB */
		iris_reg_add(IRIS_DPORT_ADDR + DPORT_CTRL0_OFFS, dport_ctrl0);
		iris_reg_add(IRIS_DPORT_ADDR + DPORT_REGSEL, 1);
		iris_dtg_mode_set(mfd, MIPI_CMD_MODE);

		/* set Iris2p output to cmd  */
		iris_reg_add(IRIS_MIPI_TX_ADDR + DSI_TX_CTRL, dsi_tx_ctrl);
		iris_reg_add(IRIS_MIPI_TX_ADDR + IRIS_MIPI_ADDR_OFFSET + DSI_TX_CTRL, dsi_tx_ctrl);
		mutex_unlock(&mfd->iris_conf.cmd_mutex);

		iris_cfg->tx_switch_state = IRIS_TX_SWITCH_STEP3;
		break;
	case IRIS_TX_SWITCH_STEP3:
		pwil_ctrl = 0xa0c80014;
		dport_ctrl0 = 0xe0e28037;
		/* set Iris2p_DPORT to output PB */
		mutex_lock(&mfd->iris_conf.cmd_mutex);
		iris_reg_add(IRIS_PWIL_ADDR + PWIL_CTRL_OFFS, pwil_ctrl);
		iris_reg_add(IRIS_DPORT_ADDR + DPORT_CTRL0_OFFS, dport_ctrl0);
		iris_reg_add(IRIS_DPORT_ADDR + DPORT_REGSEL, 1);
		mutex_unlock(&mfd->iris_conf.cmd_mutex);

		iris_info.intf_switch_info.tx_current_mode = MIPI_CMD_MODE;
		iris_cfg->tx_switch_state = IRIS_TX_SWITCH_NONE;
	default:
		break;
	}

}

void iris_mipitx_intf_switch_state_reset(struct msm_fb_data_type *mfd, u32 new_mode, bool debug)
{
	struct iris_config *iris_cfg = &mfd->iris_conf;

	/* reasonability check */
	if (!iris_info.intf_switch_info.tx_switch_enable) {
		pr_err("tx switch is not enabled\n");
		return;
	} else if (iris_info.intf_switch_info.tx_current_mode == new_mode) {
		pr_err("current mode is %d\n", new_mode);
		return;
	} else if ((IRIS_RFB_MODE != iris_cfg->current_mode)
				&& (IRIS_FRC_PRE != iris_cfg->current_mode)
				&& (IRIS_RFB_PRE != iris_cfg->current_mode)) {
		pr_err("iris is not in RFB mode\n");
		return;
	}

	iris_cfg->tx_switch_new_mode = new_mode;
	iris_cfg->tx_switch_state = IRIS_TX_SWITCH_STEP1;
	iris_cfg->tx_switch_debug_flag = debug;
}

u8 iris_mipitx_interface_switch(struct msm_fb_data_type *mfd, bool debug)
{
	struct iris_config *iris_cfg = &mfd->iris_conf;

	if ((IRIS_TX_SWITCH_NONE == iris_cfg->tx_switch_state) || (debug != iris_cfg->tx_switch_debug_flag))
		return 0;

	if (iris_cfg->tx_switch_new_mode == MIPI_CMD_MODE)
		iris_mipitx_video_to_cmd_proc(mfd);
	else
		iris_mipitx_cmd_to_video_proc(mfd);

	return 1;
}

void iris_dsimode_update(char mode)
{
	pr_info("%s, mode=%d\n", __func__, mode);
	iris_info.work_mode.rx_mode = (DSI_VIDEO_MODE == mode) ? MIPI_VIDEO_MODE : MIPI_CMD_MODE;
}

int iris_mode_frc_prepare_video(struct msm_fb_data_type *mfd)
{
	struct iris_config *iris_cfg = &mfd->iris_conf;
	int ret = false;

	switch (eiris_frc_prepare_state)
	{
		case IRIS_FRC_PATH_PROXY:
			if(atomic_read(&g_mfd->iris_conf.mode_switch_cnt) == 0)
			{
				iris_memc_path_commands_update();
				atomic_inc(&iris_cfg->mode_switch_cnt);
				schedule_work(&iris_cfg->memc_prepare_work);
				eiris_frc_prepare_state = IRIS_FRC_WAIT_PREPARE_DONE;
			}
			break;
		case IRIS_FRC_WAIT_PREPARE_DONE:
			if(atomic_read(&g_mfd->iris_conf.mode_switch_cnt) == 0)
				eiris_frc_prepare_state = IRIS_FRC_PRE_DONE;
			break;
		case IRIS_FRC_PRE_DONE:
			iris_proc_constant_ratio(iris_cfg);
			ret = true;
			break;
		default:
			break;
	}

	return ret;

}

int iris_mode_rfb2frc_video(struct msm_fb_data_type *mfd)
{
	struct iris_config *iris_cfg = &mfd->iris_conf;
	int ret = false;
	struct dcs_cmd_req cmdreq;
	struct dsi_cmd_desc cmd_rfb;

	cmdreq.cmds = &cmd_rfb;
	cmdreq.flags = CMD_REQ_COMMIT | CMD_CLK_CTRL | CMD_REQ_HS_MODE;
	cmdreq.rlen = 0;
	cmdreq.cb = NULL;
	cmdreq.cmds_cnt = 1;

	switch (eiris_mode_rfb2frc_state)
	{
		case IRIS_RFB_FRC_SWITCH_COMMAND:
			if(atomic_read(&g_mfd->iris_conf.mode_switch_cnt) == 0)
			{
				iris_proc_frcc_setting(g_mfd);
				iris_memc_reg_write(g_mfd, iris_info.fi_demo_win_info);
				atomic_inc(&iris_cfg->mode_switch_cnt);
				schedule_work(&iris_cfg->memc_work);
				eiris_mode_rfb2frc_state = IRIS_RFB_FRC_SWITCH_DONE;
			}
			break;
		case IRIS_RFB_FRC_SWITCH_DONE:
			if(atomic_read(&g_mfd->iris_conf.mode_switch_cnt) == 0)
			{
				ret = true;
			}
			break;
		default:
			break;
	}

	return ret;

}

int iris_mode_rfb_prepare_video(struct msm_fb_data_type *mfd)
{
	struct iris_config *iris_cfg = &mfd->iris_conf;
	int ret = false;

	switch (eiris_rfb_prepare_state)
	{
		case IRIS_RFB_PATH_PROXY:
			if(atomic_read(&g_mfd->iris_conf.mode_switch_cnt) == 0)
			{
				iris_cfg->iris_ratio_updated = false;
				iris_cfg->prev_dvts = 0;
				iris_cfg->repeat = IRIS_REPEAT_NO;
				eiris_rfb_prepare_state = IRIS_RFB_PRE_DONE;
			}
			break;
		case IRIS_RFB_PRE_DONE:
			if(atomic_read(&g_mfd->iris_conf.mode_switch_cnt) == 0)
			{
				ret = true;
			}
			break;
		default:
			break;
	}

	return ret;

}

int iris_mode_frc2rfb_video(struct msm_fb_data_type *mfd)
{
	struct iris_config *iris_cfg = &mfd->iris_conf;
	int ret = false;

	switch (eiris_mode_frc2rfb_state)
	{
		case IRIS_FRC_RFB_SWITCH_COMMAND:
			if(atomic_read(&g_mfd->iris_conf.mode_switch_cnt) == 0)
			{
				iris_rfb_path_commands_update();
				atomic_inc(&iris_cfg->mode_switch_cnt);
				schedule_work(&iris_cfg->rfb_work);
				eiris_mode_frc2rfb_state = IRIS_FRC_RFB_SWITCH_DONE;
			}
			break;
		case IRIS_FRC_RFB_SWITCH_DONE:
			if(atomic_read(&g_mfd->iris_conf.mode_switch_cnt) == 0)
			{
				if (debug_new_repeat == 0)
				{
					unsigned int reg_cap = 0xc0000003;
					mutex_lock(&iris_cfg->cmd_mutex);
					iris_reg_add(IRIS_PWIL_ADDR + 0x0218, reg_cap);
					mutex_unlock(&iris_cfg->cmd_mutex);
				}
				iris_cfg->pt_switch = false;
				ret = true;
			}
			break;
		default:
			break;
	}

	return ret;

}

int iris_mode_frc_cancel_video(struct msm_fb_data_type *mfd)
{
	int ret = false;

	return ret;
}

int iris_mode_pt_prepare_video(struct msm_fb_data_type *mfd)
{
	struct iris_config *iris_cfg = &mfd->iris_conf;
	int ret = false;

	switch (eiris_pt_prepare_state)
	{
		case IRIS_PT_PATH_PROXY:
			if(atomic_read(&g_mfd->iris_conf.mode_switch_cnt) == 0)
			{
				iris_pt_path_commands_update();
				atomic_inc(&iris_cfg->mode_switch_cnt);
				schedule_work(&iris_cfg->pt_prepare_work);
				eiris_pt_prepare_state = IRIS_PT_WAIT_PREPARE_DONE;
			}
			break;
		case IRIS_PT_WAIT_PREPARE_DONE:
			if(atomic_read(&g_mfd->iris_conf.mode_switch_cnt) == 0) {
				eiris_pt_prepare_state = IRIS_PT_PRE_DONE;
			}
			break;
		case IRIS_PT_PRE_DONE:
			ret = true;
			break;
		default:
			break;
	}
	return ret;
}

int iris_mode_pt2rfb_video(struct msm_fb_data_type *mfd)
{
	struct iris_config *iris_cfg = &mfd->iris_conf;
	int ret = false;

	switch (eiris_mode_pt2rfb_state)
	{
		case IRIS_PT_RFB_SWITCH_COMMAND:
			if(atomic_read(&g_mfd->iris_conf.mode_switch_cnt) == 0)
			{
				iris_rfb_path_commands_update();
				atomic_inc(&iris_cfg->mode_switch_cnt);
				schedule_work(&iris_cfg->rfb_work);
				eiris_mode_pt2rfb_state = IRIS_PT_RFB_SWITCH_DONE;
			}
			break;
		case IRIS_PT_RFB_SWITCH_DONE:
			if(atomic_read(&g_mfd->iris_conf.mode_switch_cnt) == 0)
			{
				iris_cfg->pt_switch = false;
				ret = true;
			}
			break;
		default:
			break;
	}

	return ret;

}

int iris_mode_rfb2pt_video(struct msm_fb_data_type *mfd)
{
	struct iris_config *iris_cfg = &mfd->iris_conf;
	int ret = false;

	switch (eiris_mode_rfb2pt_state)
	{
		case IRIS_RFB_PT_SWITCH_COMMAND:
			if(atomic_read(&g_mfd->iris_conf.mode_switch_cnt) == 0)
			{
				atomic_inc(&iris_cfg->mode_switch_cnt);
				schedule_work(&iris_cfg->pt_work);
				eiris_mode_rfb2pt_state = IRIS_RFB_PT_SWITCH_DONE;
			}
			break;
		case IRIS_RFB_PT_SWITCH_DONE:
			if(atomic_read(&g_mfd->iris_conf.mode_switch_cnt) == 0)
			{
				iris_cfg->pt_switch = false;
				ret = true;
			}
			break;
		default:
			break;
	}

	return ret;

}

int iris_mode_switch_video(struct msm_fb_data_type *mfd)
{
	struct mdss_overlay_private *mdp5_data = mfd_to_mdp5_data(mfd);
	struct mdss_panel_data *pdata;
	struct iris_config *iris_cfg = &mfd->iris_conf;
	int pre_current_mode = iris_cfg->current_mode;

	if (!g_dsi_ctrl) {
		pdata = mdp5_data->ctl->panel_data;
		g_dsi_ctrl = container_of(pdata, struct mdss_dsi_ctrl_pdata, panel_data);
	}

	if (mfd->index != 0)
		return -EFAULT;

	if(iris_cfg->sf_mode_change_start)
	{
		switch(iris_cfg->sf_notify_mode) {
			case IRIS_MODE_FRC_PREPARE:
				eiris_frc_prepare_state = IRIS_FRC_PATH_PROXY;
				break;
			case IRIS_MODE_RFB2FRC:
				eiris_mode_rfb2frc_state = IRIS_RFB_FRC_SWITCH_COMMAND;
				break;
			case IRIS_MODE_RFB_PREPARE:
				eiris_rfb_prepare_state = IRIS_RFB_PATH_PROXY;
				break;
			case IRIS_MODE_FRC2RFB:
				eiris_mode_frc2rfb_state = IRIS_FRC_RFB_SWITCH_COMMAND;
				break;
			case IRIS_MODE_PT_PREPARE:
			case IRIS_MODE_PTLOW_PREPARE:
				eiris_pt_prepare_state = IRIS_PT_PATH_PROXY;
				break;
			case IRIS_MODE_RFB2PT:
				eiris_mode_rfb2pt_state = IRIS_RFB_PT_SWITCH_COMMAND;
				break;
			case IRIS_MODE_PT2RFB:
				eiris_mode_pt2rfb_state = IRIS_PT_RFB_SWITCH_COMMAND;
				break;
			default:
				break;
		}

		iris_cfg->sf_mode_change_start = false;
	}

	switch(iris_cfg->sf_notify_mode) {
		case IRIS_MODE_FRC_PREPARE:
			if(iris_cfg->current_mode != IRIS_RFB_MODE)
				break;
			if(true == iris_mode_frc_prepare_video(mfd))
			{
				iris_cfg->current_mode = IRIS_FRC_PRE;
				iris_cfg->sf_notify_mode = IRIS_MODE_FRC_PREPARE_DONE;
			}
			else
			{
				if(eiris_frc_prepare_state == IRIS_FRC_PRE_TIMEOUT)
				{
					iris_cfg->sf_notify_mode = IRIS_MODE_FRC_PREPARE_TIMEOUT;
				}
			}
			break;
		case IRIS_MODE_RFB2FRC:
			if(iris_cfg->current_mode != IRIS_FRC_PRE)
				break;
			if(true == iris_mode_rfb2frc_video(mfd))
			{
				iris_cfg->current_mode = IRIS_FRC_MODE;
				iris_cfg->sf_notify_mode = IRIS_MODE_FRC;
			}
			break;
		case IRIS_MODE_FRC_CANCEL:
			if((iris_cfg->current_mode == IRIS_FRC_PRE) || (eiris_frc_prepare_state == IRIS_FRC_PRE_TIMEOUT))
			{
				iris_mode_frc_cancel_video(mfd);
				iris_cfg->current_mode = IRIS_RFB_MODE;
				iris_cfg->sf_notify_mode = IRIS_MODE_RFB;
				eiris_frc_prepare_state = IRIS_FRC_PATH_PROXY;
			}
			break;
		case IRIS_MODE_RFB_PREPARE:
			if((iris_cfg->current_mode == IRIS_FRC_MODE) || (iris_cfg->current_mode == IRIS_PT_MODE))
			{
				if(true == iris_mode_rfb_prepare_video(mfd))
				{
					iris_cfg->current_mode = IRIS_RFB_PRE;
					iris_cfg->sf_notify_mode = IRIS_MODE_RFB_PREPARE_DONE;
				}
			}
			break;
		case IRIS_MODE_FRC2RFB:
			if(iris_cfg->current_mode != IRIS_RFB_PRE)
				 break;
			if(true == iris_mode_frc2rfb_video(mfd))
			{
				iris_cfg->current_mode = IRIS_RFB_MODE;
				iris_cfg->sf_notify_mode = IRIS_MODE_RFB;
			}
			break;
		case IRIS_MODE_PT_PREPARE:
		case IRIS_MODE_PTLOW_PREPARE:
			if(iris_cfg->current_mode != IRIS_RFB_MODE)
				break;
			if(true == iris_mode_pt_prepare_video(mfd))
			{
				iris_cfg->pt_switch = true;
				iris_cfg->current_mode = IRIS_PT_PRE;
				iris_cfg->sf_notify_mode = IRIS_MODE_PT_PREPARE_DONE;
			}
			break;
		case IRIS_MODE_RFB2PT:
			if(iris_cfg->current_mode != IRIS_PT_PRE)
				break;
			if(true == iris_mode_rfb2pt_video(mfd))
			{
				iris_cfg->current_mode = IRIS_PT_MODE;
				iris_cfg->sf_notify_mode = IRIS_MODE_PT;
			}
			break;
		case IRIS_MODE_PT2RFB:
			if(iris_cfg->current_mode != IRIS_RFB_PRE)
				break;
			if(true == iris_mode_pt2rfb_video(mfd))
			{
				iris_cfg->current_mode = IRIS_RFB_MODE;
				iris_cfg->sf_notify_mode = IRIS_MODE_RFB;
			}
			break;
		case IRIS_MODE_PT2BYPASS:
			if(iris_cfg->current_mode != IRIS_PT_MODE)
				break;
			if (true == iris_mode_bypass_switch(IRIS_MODE_PT2BYPASS)) {
				iris_cfg->current_mode = IRIS_BYPASS_MODE;
				iris_cfg->sf_notify_mode = IRIS_MODE_BYPASS;
			}
			break;
		case IRIS_MODE_BYPASS2PT:
			if(iris_cfg->current_mode != IRIS_BYPASS_MODE)
				break;
			if (true == iris_mode_bypass_switch(IRIS_MODE_BYPASS2PT)) {
				iris_cfg->current_mode = IRIS_PT_MODE;
				iris_cfg->sf_notify_mode = IRIS_MODE_PT;
			}
			break;

		default:
			break;
	}

	if(pre_current_mode != iris_cfg->current_mode)
		pr_info("%s, %d: mode from %d to %d\n", __func__, __LINE__, pre_current_mode, iris_cfg->current_mode);

	return 0;
}

int iris_mode_frc_prepare(struct msm_fb_data_type *mfd)
{
	struct iris_config *iris_cfg = &mfd->iris_conf;
	u32 val = 0;
	int ret = false;
	struct dcs_cmd_req cmdreq;
	struct dsi_cmd_desc cmd_rfb;

	cmdreq.cmds = &cmd_rfb;
	cmdreq.flags = CMD_REQ_COMMIT | CMD_CLK_CTRL | CMD_REQ_HS_MODE;
	cmdreq.rlen = 0;
	cmdreq.cb = NULL;
	cmdreq.cmds_cnt = 1;

	switch (eiris_frc_prepare_state)
	{
		case IRIS_FRC_PRE_TX_SWITCH:
			if (iris_mipitx_interface_switch(mfd, 0))
				break;
			else
				eiris_frc_prepare_state = IRIS_FRC_PATH_PROXY;
			break;
		case IRIS_FRC_PATH_PROXY:
#if defined(CONFIG_IRIS2P_DRC_SUPPORT)
			// drc LP MEMC update, don't take effect now
			if (g_mfd->iris_conf.drc_enable)
				iris_Drc_LPMemc_update(mfd);
#endif
			iris_memc_path_commands_update();
			if (debug_mode_switch_enabled) {
				memcpy(&cmd_rfb, memc_data_path_config, sizeof(struct dsi_cmd_desc));
				mdss_dsi_cmdlist_put(g_dsi_ctrl, &cmdreq);
			}
			iris_cfg->kickoff_cnt = 1;
			eiris_frc_prepare_state = IRIS_FRC_WAIT_PREPARE_DONE;
			break;
		case IRIS_FRC_WAIT_PREPARE_DONE:
			if (iris_cfg->kickoff_cnt++ < 30)
			{
				if (debug_mode_switch_enabled)
				{
				#if defined(FPGA_PLATFORM)
					if (iris_cfg->kickoff_cnt == 25)
						val = IRIS_FRC_PRE;
					else val = 0;
				#else
					val = iris_pi_read(g_dsi_ctrl, IRIS_MODE_ADDR);
					if(val == 2)
						val = IRIS_FRC_PRE;
				#endif
				}
				else
				{
					val = IRIS_FRC_PRE;
				}

				if (val != IRIS_FRC_PRE) {
					pr_debug("iris: mode = %08x, cnt = %d\n", val, iris_cfg->kickoff_cnt);
				}
				else
				{
					eiris_frc_prepare_state = IRIS_FRC_PRE_DONE;
				}
			}
			else
			{
				pr_debug("iris: memc prep time out\n");
				eiris_frc_prepare_state = IRIS_FRC_PRE_TIMEOUT;
			}
			break;
		case IRIS_FRC_PRE_DONE:
			frc_repeat_enter = false;
			iris_cfg->cap_enable = true;
			iris_cfg->cap_change = false;
			iris_proc_frcc_setting(g_mfd);
			iris_memc_reg_write(g_mfd, iris_info.fi_demo_win_info);
			iris_mcuclk_divider_change(g_dsi_ctrl, 0);
			iris_proc_constant_ratio(iris_cfg);
			ret = true;
			break;
		case IRIS_FRC_PRE_TIMEOUT:
			break;
		default:
			break;
	}

	return ret;

}

static int iris_mode_rfb2frc(struct msm_fb_data_type *mfd)
{
	int ret = false;
	struct dcs_cmd_req cmdreq;
	struct dsi_cmd_desc cmd_rfb;

	cmdreq.cmds = &cmd_rfb;
	cmdreq.flags = CMD_REQ_COMMIT | CMD_CLK_CTRL | CMD_REQ_HS_MODE;
	cmdreq.rlen = 0;
	cmdreq.cb = NULL;
	cmdreq.cmds_cnt = 1;

	switch (eiris_mode_rfb2frc_state)
	{
		case IRIS_RFB_FRC_SWITCH_COMMAND:
			if (debug_mode_switch_enabled) {
				memcpy(&cmd_rfb, memc_mode_enter, sizeof(struct dsi_cmd_desc));
				mdss_dsi_cmdlist_put(g_dsi_ctrl, &cmdreq);
			}
			eiris_mode_rfb2frc_state = IRIS_RFB_FRC_SWITCH_DONE;
			break;
		case IRIS_RFB_FRC_SWITCH_DONE:
			ret = true;
			break;
		default:
			break;
	}

	return ret;
}

static int iris_mode_rfb_prepare(struct msm_fb_data_type *mfd)
{
	struct iris_config *iris_cfg = &mfd->iris_conf;
	int ret = false;
	int vper;

	switch (eiris_rfb_prepare_state)
	{
		case IRIS_RFB_PATH_PROXY:
			if (iris_cfg->pt_switch)
				eiris_rfb_prepare_state = IRIS_RFB_PRE_DONE;
			iris_cfg->iris_ratio_updated = false;
			iris_cfg->prev_dvts = 0;
			iris_cfg->repeat = IRIS_REPEAT_NO;
			iris_cfg->true_cut_enable = false;
			iris_cfg->input_vfr = 0;
#if defined(CONFIG_IRIS2P_DRC_SUPPORT)
			//drc exit
			if (g_mfd->iris_conf.drc_enable)
				iris_calc_drc_exit(mfd);
#endif
			vper = iris_get_vtotal(&iris_info.output_timing);
			if (iris_is_cmdin_videout() && iris_cfg->sw_te_period != vper) {
				iris_cfg->sw_te_period = vper;
				iris_set_te(iris_cfg, true);
			}

			eiris_rfb_prepare_state = IRIS_RFB_WAIT_PREPARE_DONE;
			break;
		case IRIS_RFB_WAIT_PREPARE_DONE:
			eiris_rfb_prepare_state = IRIS_RFB_PRE_DONE;
			break;
		case IRIS_RFB_PRE_DONE:
			ret = true;
			break;
		default:
			break;
	}

	return ret;
}

static int iris_mode_frc2rfb(struct msm_fb_data_type *mfd)
{
	struct iris_config *iris_cfg = &mfd->iris_conf;
	int ret = false;
	struct dcs_cmd_req cmdreq;
	struct dsi_cmd_desc cmd_rfb;

	cmdreq.cmds = &cmd_rfb;
	cmdreq.flags = CMD_REQ_COMMIT | CMD_CLK_CTRL | CMD_REQ_HS_MODE;
	cmdreq.rlen = 0;
	cmdreq.cb = NULL;
	cmdreq.cmds_cnt = 1;

	switch (eiris_mode_frc2rfb_state)
	{
		case IRIS_FRC_RFB_SWITCH_COMMAND:
			pt_enable[0] = 0x3 << 2;
			pt_enable[1] = 0x1;
			memcpy(&cmd_rfb, pt_mode_enter, sizeof(struct dsi_cmd_desc));
			mdss_dsi_cmdlist_put(g_dsi_ctrl, &cmdreq);
			eiris_mode_frc2rfb_state = IRIS_FRC_RFB_DATA_PATH;
			iris_cfg->kickoff_cnt = 0;
			break;
		case IRIS_FRC_RFB_DATA_PATH:
			iris_cfg->kickoff_cnt++;
			if (iris_cfg->kickoff_cnt <=2)
				break;
			iris_rfb_path_commands_update();
			if (debug_mode_switch_enabled) {
				memcpy(&cmd_rfb, rfb_data_path_config, sizeof(struct dsi_cmd_desc));
				mdss_dsi_cmdlist_put(g_dsi_ctrl, &cmdreq);
			}
			eiris_mode_frc2rfb_state = IRIS_FRC_RFB_SWITCH_DONE;
			iris_cfg->kickoff_cnt = 0;
			break;
		case IRIS_FRC_RFB_SWITCH_DONE:
			iris_cfg->kickoff_cnt++;
			if (iris_cfg->kickoff_cnt <=6)
				break;
			if (debug_new_repeat == 0)
			{
				unsigned int reg_cap = 0xc0000003;
				mutex_lock(&iris_cfg->cmd_mutex);
				iris_reg_add(IRIS_PWIL_ADDR + 0x0218, reg_cap);
				mutex_unlock(&iris_cfg->cmd_mutex);
			}
			iris_mcuclk_divider_change(g_dsi_ctrl, 1);
			iris_cfg->pt_switch = false;
			eiris_mode_frc2rfb_state = IRIS_FRC_RFB_TX_SWITCH;
			break;
		case IRIS_FRC_RFB_TX_SWITCH:
			if (iris_mipitx_interface_switch(mfd, 0))
				break;
			else
				ret = true;
			break;
		default:
			break;
	}

	return ret;

}

static int iris_mode_frc_cancel(struct msm_fb_data_type *mfd)
{
	int ret = false;
	struct dcs_cmd_req cmdreq;
	struct dsi_cmd_desc cmd_rfb;

	cmdreq.cmds = &cmd_rfb;
	cmdreq.flags = CMD_REQ_COMMIT | CMD_CLK_CTRL | CMD_REQ_HS_MODE;
	cmdreq.rlen = 0;
	cmdreq.cb = NULL;
	cmdreq.cmds_cnt = 1;


	switch (eiris_frc_cancel_state)
	{
		case IRIS_FRC_CANCEL_PATH_PROXY:
			iris_rfb_enter_cmds[21] = (iris_rfb_enter_cmds[21] & 0xFC) | iris_info.setting_info.dbc_mode;
			if (debug_mode_switch_enabled)
			{
				memcpy(&cmd_rfb, rfb_data_path_config, sizeof(struct dsi_cmd_desc));
				mdss_dsi_cmdlist_put(g_dsi_ctrl, &cmdreq);
			}
			eiris_frc_cancel_state = IRIS_FRC_CANCEL_TX_SWITCH;
			break;
		case IRIS_FRC_CANCEL_TX_SWITCH:
			if (iris_mipitx_interface_switch(mfd, 0))
				break;
			else
				ret = true;
			eiris_frc_cancel_state = IRIS_RFB_PRE_DONE;
			break;
		case IRIS_FRC_CANCEL_DONE:
			ret = true;
			break;
		default:
			break;
	}

	return ret;
}

static int iris_mode_pt2rfb(struct msm_fb_data_type *mfd)
{
	struct iris_config *iris_cfg = &mfd->iris_conf;
	int ret = false;
	struct dcs_cmd_req cmdreq;
	struct dsi_cmd_desc cmd_rfb;

	cmdreq.cmds = &cmd_rfb;
	cmdreq.flags = CMD_REQ_COMMIT | CMD_CLK_CTRL | CMD_REQ_HS_MODE;
	cmdreq.rlen = 0;
	cmdreq.cb = NULL;
	cmdreq.cmds_cnt = 1;

	switch (eiris_mode_pt2rfb_state)
	{
		case IRIS_PT_RFB_SWITCH_COMMAND:
			pt_enable[0] = 0x3 << 2;
			pt_enable[1] = 0x1;
			memcpy(&cmd_rfb, pt_mode_enter, sizeof(struct dsi_cmd_desc));
			mdss_dsi_cmdlist_put(g_dsi_ctrl, &cmdreq);
			eiris_mode_pt2rfb_state = IRIS_PT_RFB_DATA_PATH;
			break;
		case IRIS_PT_RFB_DATA_PATH:
			iris_rfb_path_commands_update();
			if (debug_mode_switch_enabled) {
				memcpy(&cmd_rfb, rfb_data_path_config, sizeof(struct dsi_cmd_desc));
				mdss_dsi_cmdlist_put(g_dsi_ctrl, &cmdreq);
			}

			eiris_mode_pt2rfb_state = IRIS_PT_RFB_SWITCH_DONE;
			break;
		case IRIS_PT_RFB_SWITCH_DONE:
			iris_cfg->pt_switch = false;
			ret = true;
		break;
		default:
			break;
	}

	return ret;

}

static int iris_mode_pt_prepare(struct msm_fb_data_type *mfd)
{
	int ret = false;
	struct dcs_cmd_req cmdreq;
	struct dsi_cmd_desc cmd_rfb;

	cmdreq.cmds = &cmd_rfb;
	cmdreq.flags = CMD_REQ_COMMIT | CMD_CLK_CTRL | CMD_REQ_HS_MODE;
	cmdreq.rlen = 0;
	cmdreq.cb = NULL;
	cmdreq.cmds_cnt = 1;

	switch (eiris_pt_prepare_state)
	{
		case IRIS_PT_PATH_PROXY:
			iris_pt_path_commands_update();
			if (debug_mode_switch_enabled) {
				memcpy(&cmd_rfb, pt_data_path_config, sizeof(struct dsi_cmd_desc));
				mdss_dsi_cmdlist_put(g_dsi_ctrl, &cmdreq);
			}
			eiris_pt_prepare_state = IRIS_PT_WAIT_PREPARE_DONE;
			break;
		case IRIS_PT_WAIT_PREPARE_DONE:
			eiris_pt_prepare_state = IRIS_PT_PRE_DONE;
			break;
		case IRIS_PT_PRE_DONE:
			ret = true;
			break;
		default:
			break;
	}

	return ret;
}


static int iris_mode_rfb2pt(struct msm_fb_data_type *mfd)
{
	struct iris_config *iris_cfg = &mfd->iris_conf;
	int ret = false;
	struct dcs_cmd_req cmdreq;
	struct dsi_cmd_desc cmd_rfb;

	cmdreq.cmds = &cmd_rfb;
	cmdreq.flags = CMD_REQ_COMMIT | CMD_CLK_CTRL | CMD_REQ_HS_MODE;
	cmdreq.rlen = 0;
	cmdreq.cb = NULL;
	cmdreq.cmds_cnt = 1;

	switch (eiris_mode_rfb2pt_state)
	{
		case IRIS_RFB_PT_SWITCH_COMMAND:
			pt_enable[0] = 0x0 << 2;
			pt_enable[1] = 0x1;
			memcpy(&cmd_rfb, pt_mode_enter, sizeof(struct dsi_cmd_desc));
			mdss_dsi_cmdlist_put(g_dsi_ctrl, &cmdreq);
			eiris_mode_rfb2pt_state = IRIS_RFB_PT_DATA_PATH;
			break;
		case IRIS_RFB_PT_DATA_PATH:
			eiris_mode_rfb2pt_state = IRIS_RFB_PT_SWITCH_DONE;
			break;
		case IRIS_RFB_PT_SWITCH_DONE:
			iris_cfg->pt_switch = false;
			ret = true;
			break;
		default:
			break;
	}

	return ret;

}

static int iris_mode_pt_bypass_switch(struct dsi_cmd_desc *desc)
{
	struct dcs_cmd_req req = {
		.cmds = desc,
		.cmds_cnt = 1,
		.flags = CMD_REQ_COMMIT | CMD_REQ_NO_MAX_PKT_SIZE | CMD_CLK_CTRL | CMD_REQ_HS_MODE,
		.rlen = 0,
		.rbuf = NULL,
		.cb = NULL
	};

	mdss_dsi_cmdlist_put(g_dsi_ctrl, &req);

	return 0;
}

static int iris_mode_bypass2pt(void)
{
	struct iris_work_mode *pwork_mode = &(iris_info.work_mode);
	struct dsi_cmd_desc desc_list[] = {
		{ { DTYPE_GEN_WRITE1, 1, 0, 0, 0, sizeof(bypass_enable) }, &bypass_enable},
	};

	if ((MIPI_VIDEO_MODE == pwork_mode->rx_mode) &&
		(pwork_mode->rx_mode == pwork_mode->tx_mode)) {
		bypass_enable = 0xbf;
	} else if ((MIPI_CMD_MODE == pwork_mode->rx_mode) &&
		(pwork_mode->rx_mode == pwork_mode->tx_mode)) {
		bypass_enable = 0x7f;
	}
	pr_info("bypass_enable: %x, rx_mode: %d, tx_mode: %d\n", bypass_enable, pwork_mode->rx_mode, pwork_mode->tx_mode);
	iris_mode_pt_bypass_switch(desc_list);
	return true;
}

static int iris_mode_pt2bypass(void)
{
	struct iris_work_mode *pwork_mode = &(iris_info.work_mode);
	struct dsi_cmd_desc desc_list[] = {
		{ { DTYPE_GEN_WRITE1, 1, 0, 0, 0, sizeof(bypass_enable) }, &bypass_enable},
	};

	if ((MIPI_VIDEO_MODE == pwork_mode->rx_mode) &&
		(pwork_mode->rx_mode == pwork_mode->tx_mode)) {
		bypass_enable = 0xff;
	} else if ((MIPI_CMD_MODE == pwork_mode->rx_mode) &&
		(pwork_mode->rx_mode == pwork_mode->tx_mode)) {
		bypass_enable = 0xdf;
	}
	pr_info("bypass_enable: %x, rx_mode: %d, tx_mode: %d\n", bypass_enable, pwork_mode->rx_mode, pwork_mode->tx_mode);
	iris_mode_pt_bypass_switch(desc_list);
	return true;
}

static int iris_mode_bypass_switch(int val)
{
	int type = iris_info.abypss_ctrl.analog_bypass_enable;
	int ret = false;

	if (type == false) {
		if (IRIS_MODE_PT2BYPASS == val){
			ret = iris_mode_pt2bypass();
		} else if (IRIS_MODE_BYPASS2PT == val) {
			ret = iris_mode_bypass2pt();
		}
	} else {
		if (IRIS_MODE_PT2BYPASS == val) {
			ret = iris_pt_to_abypass_switch(g_dsi_ctrl);
		} else if (IRIS_MODE_BYPASS2PT == val){
			ret = iris_abypass_to_pt_switch(g_dsi_ctrl);
		}
	}
	return ret;
}

int iris_mode_switch_cmd(struct msm_fb_data_type *mfd)
{
	struct mdss_overlay_private *mdp5_data = mfd_to_mdp5_data(mfd);
	struct mdss_panel_data *pdata;
	struct iris_config *iris_cfg = &mfd->iris_conf;
	int pre_current_mode = iris_cfg->current_mode;

	if (mfd->index != 0)
		return -EFAULT;

	if (!g_dsi_ctrl) {
		pdata = mdp5_data->ctl->panel_data;
		g_dsi_ctrl = container_of(pdata, struct mdss_dsi_ctrl_pdata, panel_data);
	}

	if(iris_cfg->sf_mode_change_start)
	{
		switch(iris_cfg->sf_notify_mode) {
			case IRIS_MODE_FRC_PREPARE:
				eiris_frc_prepare_state = IRIS_FRC_PRE_TX_SWITCH;
				iris_mipitx_intf_switch_state_reset(mfd, MIPI_VIDEO_MODE, 0);
				break;
			case IRIS_MODE_RFB2FRC:
				eiris_mode_rfb2frc_state = IRIS_RFB_FRC_SWITCH_COMMAND;
				break;
			case IRIS_MODE_RFB_PREPARE:
				eiris_rfb_prepare_state = IRIS_RFB_PATH_PROXY;
				break;
			case IRIS_MODE_FRC2RFB:
				eiris_mode_frc2rfb_state = IRIS_FRC_RFB_SWITCH_COMMAND;
				iris_mipitx_intf_switch_state_reset(mfd, MIPI_CMD_MODE, 0);
				break;
			case IRIS_MODE_FRC_CANCEL:
				eiris_frc_cancel_state = IRIS_FRC_CANCEL_PATH_PROXY;
				iris_mipitx_intf_switch_state_reset(mfd, MIPI_CMD_MODE, 0);
				break;
			case IRIS_MODE_PT_PREPARE:
			case IRIS_MODE_PTLOW_PREPARE:
				eiris_pt_prepare_state = IRIS_PT_PATH_PROXY;
				break;
			case IRIS_MODE_RFB2PT:
				eiris_mode_rfb2pt_state = IRIS_RFB_PT_SWITCH_COMMAND;
				break;
			case IRIS_MODE_PT2RFB:
				eiris_mode_pt2rfb_state = IRIS_PT_RFB_SWITCH_COMMAND;
				break;
			case IRIS_MODE_PT2BYPASS:
				iris_abypass_switch_state_init(IRIS_MODE_PT2BYPASS);
				break;
			case IRIS_MODE_BYPASS2PT:
				iris_abypass_switch_state_init(IRIS_MODE_BYPASS2PT);
				break;
			default:
				break;
		}

		iris_cfg->sf_mode_change_start = false;
	}

	switch(iris_cfg->sf_notify_mode) {
		case IRIS_MODE_FRC_PREPARE:
			if(iris_cfg->current_mode != IRIS_RFB_MODE)
				break;
			if(true == iris_mode_frc_prepare(mfd))
			{
				iris_cfg->current_mode = IRIS_FRC_PRE;
				iris_cfg->sf_notify_mode = IRIS_MODE_FRC_PREPARE_DONE;
			}
			else
			{
				if(eiris_frc_prepare_state == IRIS_FRC_PRE_TIMEOUT)
				{
					iris_cfg->sf_notify_mode = IRIS_MODE_FRC_PREPARE_TIMEOUT;
				}
			}
			break;
		case IRIS_MODE_RFB2FRC:
			if(iris_cfg->current_mode != IRIS_FRC_PRE)
				break;
			if(true == iris_mode_rfb2frc(mfd))
			{
				iris_cfg->current_mode = IRIS_FRC_MODE;
				iris_cfg->sf_notify_mode = IRIS_MODE_FRC;
			}
			break;
		case IRIS_MODE_FRC_CANCEL:
			if((iris_cfg->current_mode == IRIS_FRC_PRE) || (eiris_frc_prepare_state == IRIS_FRC_PRE_TIMEOUT))
			{
				if (true == iris_mode_frc_cancel(mfd)) {
					iris_cfg->current_mode = IRIS_RFB_MODE;
					eiris_frc_prepare_state = IRIS_FRC_PRE_TX_SWITCH;
					iris_cfg->sf_notify_mode = IRIS_MODE_RFB;
				}
			}
			break;
		case IRIS_MODE_RFB_PREPARE:
			if((iris_cfg->current_mode == IRIS_FRC_MODE) || (iris_cfg->current_mode == IRIS_PT_MODE))
			{
				if(true == iris_mode_rfb_prepare(mfd))
				{
					iris_cfg->current_mode = IRIS_RFB_PRE;
					iris_cfg->sf_notify_mode = IRIS_MODE_RFB_PREPARE_DONE;
				}
			}
			break;
		case IRIS_MODE_FRC2RFB:
			if(iris_cfg->current_mode != IRIS_RFB_PRE)
				 break;
			if(true == iris_mode_frc2rfb(mfd))
			{
				iris_cfg->current_mode = IRIS_RFB_MODE;
				iris_cfg->sf_notify_mode = IRIS_MODE_RFB;
			}
			break;
		case IRIS_MODE_PT_PREPARE:
		case IRIS_MODE_PTLOW_PREPARE:
			if(iris_cfg->current_mode != IRIS_RFB_MODE)
				break;
			if(true == iris_mode_pt_prepare(mfd))
			{
				iris_cfg->pt_switch = true;
				iris_cfg->current_mode = IRIS_PT_PRE;
				iris_cfg->sf_notify_mode = IRIS_MODE_PT_PREPARE_DONE;
			}
			break;
		case IRIS_MODE_RFB2PT:
			if(iris_cfg->current_mode != IRIS_PT_PRE)
				break;
			if(true == iris_mode_rfb2pt(mfd))
			{
				iris_cfg->current_mode = IRIS_PT_MODE;
				iris_cfg->sf_notify_mode = IRIS_MODE_PT;
			}
			break;
		case IRIS_MODE_PT2RFB:
			if(iris_cfg->current_mode != IRIS_RFB_PRE)
				break;
			if(true == iris_mode_pt2rfb(mfd))
			{
				iris_cfg->current_mode = IRIS_RFB_MODE;
				iris_cfg->sf_notify_mode = IRIS_MODE_RFB;
			}
			break;
		case IRIS_MODE_PT2BYPASS:
			if(iris_cfg->current_mode != IRIS_PT_MODE)
				break;
			if (true == iris_mode_bypass_switch(IRIS_MODE_PT2BYPASS)) {
				iris_cfg->current_mode = IRIS_BYPASS_MODE;
				iris_cfg->sf_notify_mode = IRIS_MODE_BYPASS;
			}
			break;
		case IRIS_MODE_BYPASS2PT:
			if(iris_cfg->current_mode != IRIS_BYPASS_MODE)
				break;
			if (true == iris_mode_bypass_switch(IRIS_MODE_BYPASS2PT)) {
				iris_cfg->current_mode = IRIS_PT_MODE;
				iris_cfg->sf_notify_mode = IRIS_MODE_PT;
			}
			break;
		default:
			break;
	}

	if(pre_current_mode != iris_cfg->current_mode)
		pr_info("%s, %d: mode from %d to %d\n", __func__, __LINE__, pre_current_mode, iris_cfg->current_mode);

	return 0;

}

void iris_mode_switch_reset(struct mdss_dsi_ctrl_pdata *ctrl)
{
	struct iris_config *iris_cfg = &g_mfd->iris_conf;
	iris_cfg->sf_notify_mode = IRIS_MODE_RFB;
	iris_cfg->kickoff_cnt = 0;
	iris_cfg->sf_mode_change_start = false;
	iris_cfg->iris_ratio_updated = false;
	iris_cfg->repeat = IRIS_REPEAT_NO;
	iris_cfg->pt_switch = false;
	iris_cfg->true_cut_enable = false;
	iris_cfg->current_mode = IRIS_RFB_MODE;
}

