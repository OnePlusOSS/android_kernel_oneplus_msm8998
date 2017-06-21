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
#ifndef MDSS_DSI_IRIS_H
#define MDSS_DSI_IRIS_H

#include "mdss_mdp.h"
#include "mdss_dsi.h"
#include "linux/fb.h"
#include <linux/types.h>
#include "mdss_dsi_iris2p_lightup_priv.h"

/* WITHOUT_IRIS means that panel is connected to host directly, default is disabled. */
//#define WITHOUT_IRIS
//#define FPGA_PLATFORM


#define IRIS_PSR_MIF_ADDR	0xF1400000
#define IRIS_BLENDING_ADDR	0xF1540000
#define IRIS_GMD_ADDR	0xF20A0000
#define IRIS_FBD_ADDR	0xF20C0000
#define IRIS_CAD_ADDR	0xF20E0000
#define FRCC_CTRL_REG5_ADDR	0xF2010014
#define FRCC_CTRL_REG7_ADDR	0xF201001C
#define FRCC_CTRL_REG8_ADDR	0xF2010020
#define FRCC_CTRL_REG16_ADDR	0xF2010040
#define FRCC_CTRL_REG17_ADDR	0xF2010044
#define FRCC_CTRL_REG18_ADDR	0xF2010048
#define FRCC_CMD_MOD_TH		0xF201004c
#define FRCC_DTG_SYNC		0xF2010060
#define DTG_SYNC_TH		0
#define TH_DTG_EN		15
#define FI_REPEATCF_TH		16
#define VD_P1_CHECK_EN		26
#define MAX_TRSC_DONE		27
#define DELAY_FI_EN		29
#define FRCC_REG_SHOW		0xF2011198
#if !defined(MIPI_SWAP)
#define IRIS_MIPI_RX2_ADDR	0xF0140000
#define IRIS_MIPI_TX2_ADDR	0xF01c0000
#endif
#define PWIL_STATUS_ADDR	0xF1240080
#define IRIS_PWIL_OUT_FRAME_SHIFT 24
#define IRIS_PWIL_IN_FRAME_SHIFT 8
#define IRIS_MVC_ADDR 0xF2100000
#define IRIS_MVC_TOP_CTRL0_OFF	0x0000000c
#define IRIS_MVC_SW_UPDATE_OFF	0x1ff00
#define PHASE_SHIFT_EN		1
#define INTERVAL_SHIFT_EN	2
#define TRUE_CUT_EXT_EN	3
#define ROTATION		4
#define IRIS_BLC_PWM_ADDR 0xF1080000
#define SCALE 0x1D0
#define FI_RANGE_CTRL          0xf2160014
#define FI_DEMO_COL_SIZE       0xf2160018
#define FI_DEMO_MODE_CTRL      0xf216001c
#define FI_DEMO_MODE_RING      0xf2160020
#define FI_DEMO_ROW_SIZE       0xf2160024
#define FI_SHADOW_UPDATE       0xf217ff00
#define PEAKING_CTRL           0xf1a0005c
#define PEAKING_STARTWIN       0xf1a00060
#define PEAKING_ENDWIN         0xf1a00064
#define PEAKING_SHADOW_UPDATE  0xf1a1ff00
#define CM_CTRL                0xf1560000
#define CM_STARTWIN            0xf15600dc
#define CM_ENDWIN              0xf15600e0
#define CM_SHADOW_UPDATE       0xf157ffd0
#define UNIT_CONTRL_ADDR       0xf0060000
#define FRC_DSC_ENCODER0       0xf1620000

#define IRIS_PROXY_MB0_ADDR		(IRIS_PROXY_ADDR+0x00)	// MB0
#define IRIS_MODE_ADDR			(IRIS_PROXY_ADDR+0x08)	// MB1
#define IRIS_DATA_PATH_ADDR		(IRIS_PROXY_ADDR+0x10)	// MB2
#define IRIS_LPMEMC_SETTING_ADDR	(IRIS_PROXY_ADDR+0x20)	// MB4
#define IRIS_DBC_SETTING_ADDR		(IRIS_PROXY_ADDR+0x28)	// MB5
#define IRIS_PQ_SETTING_ADDR		(IRIS_PROXY_ADDR+0x30)	// MB6


#define IRIS_PROXY_MB7_ADDR		(IRIS_PROXY_ADDR+0x38)	// MB7

#define IRIS_COLOR_ADJUST_ADDR	(IRIS_GRCP_CTRL_ADDR+0x12fe0) //ALG_PARM11
#define IRIS_CM_SETTING_ADDR	(IRIS_GRCP_CTRL_ADDR+0x12fe4) //ALG_PARM12
#define IRIS_LCE_SETTING_ADDR	(IRIS_GRCP_CTRL_ADDR+0x12fe8) //ALG_PARM13
#define IRIS_LUX_VALUE_ADDR     (IRIS_GRCP_CTRL_ADDR+0x12ffc)
#define IRIS_CCT_VALUE_ADDR     (IRIS_GRCP_CTRL_ADDR+0x12ff8)
#define IRIS_READING_MODE_ADDR	(IRIS_GRCP_CTRL_ADDR+0x12ff4)


#define IRIS_TRUECUT_INFO_ADDR	(IRIS_GRCP_CTRL_ADDR+0x12fec)
#define IRIS_DRC_INFO_ADDR	(IRIS_GRCP_CTRL_ADDR+0x12ff0)
#define IRIS_NRV_INFO1_ADDR	(FRC_DSC_ENCODER0+0x0c)	// to remove
#define IRIS_NRV_INFO2_ADDR	(FRC_DSC_ENCODER0+0x10)	// to remove


#define PWIL_CTRL_OFFS		0
#define DPORT_CTRL0_OFFS	0
#define DPORT_REGSEL		0x1ffd4

#define ALIGN_UP(x, size)	(((x)+((size)-1))&(~((size)-1)))

//PWIL View Descriptor Valid Word Number
#define PWIL_ViewD_LEN 0x0A
//PWIL Display Descriptor Valid Word Number
#define PWIL_DispD_LEN 0x05

#define IRIS_CONFIGURE_GET_VALUE_CORRECT 0
#define IRIS_CONFIGURE_GET_VALUE_ERROR 1


#define PWIL_CHECK_FORMAT(cmds)	\
	do {	\
		int valid_word_num = (ARRAY_SIZE(cmds) - 12) / 4; \
		int non_burst_len = valid_word_num - 1; \
		if (!strncmp(cmds, "LIWP", 4)) { \
			if (!strncmp(cmds + 4, "PCRG", 4)) { \
				cmds[8] = valid_word_num & 0xFF; \
				cmds[9] = (valid_word_num >> 8) & 0xFF; \
				cmds[10] = (valid_word_num >> 16) & 0xFF; \
				cmds[11] = (valid_word_num >> 24) & 0xFF; \
				cmds[14] = non_burst_len & 0xFF; \
				cmds[15] = (non_burst_len >> 8 ) & 0xFF; \
			} else if (!strncmp(cmds + 4, "WEIV", 4)) { \
				cmds[8] = PWIL_ViewD_LEN & 0xFF; \
				cmds[9] = (PWIL_ViewD_LEN >> 8) & 0xFF; \
				cmds[10] = (PWIL_ViewD_LEN >> 16) & 0xFF; \
				cmds[11] = (PWIL_ViewD_LEN >> 24) & 0xFF; \
			} else if (!strncmp(cmds + 4, "PSID", 4)) { \
				cmds[8] = PWIL_DispD_LEN & 0xFF; \
				cmds[9] = (PWIL_DispD_LEN >> 8) & 0xFF; \
				cmds[10] = (PWIL_DispD_LEN >> 16) & 0xFF; \
				cmds[11] = (PWIL_DispD_LEN >> 24) & 0xFF; \
			} else { \
				\
			} \
		} else { \
			pr_err("PWIL Packet format error!\n"); \
		} \
	} while (0)

enum iris_mode {
	IRIS_PT_MODE = 0,
	IRIS_RFB_MODE,
	IRIS_FRC_MODE,
	IRIS_BYPASS_MODE,
	IRIS_PT_PRE,
	IRIS_RFB_PRE,
	IRIS_FRC_PRE,
	IRIS_FBO_MODE,
};

enum iris_mipi_tx_switch_state {
	IRIS_TX_SWITCH_NONE = 0,
	IRIS_TX_SWITCH_STEP1,
	IRIS_TX_SWITCH_STEP2,
	IRIS_TX_SWITCH_STEP3,
	IRIS_TX_SWITCH_STEP4,
	IRIS_TX_SWITCH_STEP5,
	IRIS_TX_SWITCH_INVALID,
};

struct iris_mipi_tx_cmd_hdr {
	u8 dtype;
	u8 len[2];
	u8 ecc;
};

union iris_mipi_tx_cmd_header {
	struct iris_mipi_tx_cmd_hdr stHdr;
	u32 hdr32;
};

union iris_mipi_tx_cmd_payload {
	u8 p[4];
	u32 pld32;
};


// MB2
struct iris_fun_enable {
	uint32_t reserved0:11;
	uint32_t true_cut_en:1;		//bit11, Only use in FRC mode
	uint32_t reserved1:3;
	uint32_t nrv_drc_en:1;		//bit15, Only use in FRC mode
	uint32_t frc_buf_num:1;		//no used
	uint32_t phase_en:1;		//no used
	uint32_t pp_en:1;		//bit18
	uint32_t reserved2:1;
	uint32_t use_efifo_en:1;	//bit20
	uint32_t psr_post_sel:1;	//bit21
	uint32_t reserved3:1;
	uint32_t frc_data_format:1;	//bit23, 0: YUV444 1: YUV422
	uint32_t capt_bitwidth:1;	//bit24, 0: 8bit; 1: 10bit
	uint32_t psr_bitwidth:1;	//bit25, 0: 8bit; 1: 10bit
	uint32_t dbc_lce_en:1;		//bit26
	uint32_t dpp_en:1;		//bit27
	uint32_t reserved4:4;
};

enum iris_frc_prepare_state {
	IRIS_FRC_PRE_TX_SWITCH = 0x00,
	IRIS_FRC_PATH_PROXY = 0x1,
	IRIS_FRC_WAIT_PREPARE_DONE = 0x02,
	IRIS_FRC_PRE_DONE = 0x03,
	IRIS_FRC_PRE_TIMEOUT = 0x04,
};

enum iris_frc_cancel_state {
	IRIS_FRC_CANCEL_PATH_PROXY = 0x0,
	IRIS_FRC_CANCEL_TX_SWITCH = 0x01,
	IRIS_FRC_CANCEL_DONE = 0x02,
};

enum iris_mode_rfb2frc_state {
	IRIS_RFB_FRC_SWITCH_COMMAND = 0x00,
	IRIS_RFB_FRC_SWITCH_DONE = 0x01,
};

enum iris_rfb_prepare_state {
	IRIS_RFB_PATH_PROXY = 0x0,
	IRIS_RFB_WAIT_PREPARE_DONE = 0x01,
	IRIS_RFB_PRE_DONE = 0x02,
};

enum iris_mode_frc2rfb_state {
	IRIS_FRC_RFB_SWITCH_COMMAND = 0x00,
	IRIS_FRC_RFB_DATA_PATH = 0x01,
	IRIS_FRC_RFB_SWITCH_DONE = 0x02,
	IRIS_FRC_RFB_TX_SWITCH = 0x03,
};

enum iris_pt_prepare_state {
	IRIS_PT_PATH_PROXY = 0x0,
	IRIS_PT_WAIT_PREPARE_DONE = 0x01,
	IRIS_PT_PRE_DONE = 0x02,
};

enum iris_mode_pt2rfb_state {
	IRIS_PT_RFB_SWITCH_COMMAND = 0x00,
	IRIS_PT_RFB_DATA_PATH = 0x01,
	IRIS_PT_RFB_SWITCH_DONE = 0x02,
};

enum iris_mode_rfb2pt_state {
	IRIS_RFB_PT_SWITCH_COMMAND = 0x00,
	IRIS_RFB_PT_DATA_PATH = 0x01,
	IRIS_RFB_PT_SWITCH_DONE = 0x02,
};

int iris_wait_for_vsync(struct mdss_mdp_ctl *ctl);
void mdss_dsi_iris_init(struct msm_fb_data_type *mfd);
int iris_frc_enable(struct mdss_mdp_ctl *ctl, int enable);
void iris_frc_new_frame(struct mdss_mdp_ctl *ctl);
void iris_mcuclk_divider_change(struct mdss_dsi_ctrl_pdata *ctrl, char lowMcu);
void mdss_dsi_panel_cmds_send_ex(struct mdss_dsi_ctrl_pdata *ctrl, struct dsi_panel_cmds *pcmds);
int iris_register_write(struct msm_fb_data_type *mfd,	u32 addr, u32 value);
bool iris_frc_repeat(struct msm_fb_data_type *mfd);
int iris_set_configure(struct msm_fb_data_type *mfd);
int iris_proc_frcc_setting(struct msm_fb_data_type *mfd);
int iris_calc_meta(struct msm_fb_data_type *mfd);
void iris_copy_meta(struct msm_fb_data_type *mfd);
int iris_dynamic_fps_set(struct mdss_panel_data *pdata, int curr_fps, int new_fps);
#if defined(CONFIG_IRIS2P_DRC_SUPPORT)
int iris_Drc_LPMemc_update(struct msm_fb_data_type *mfd);
int iris_get_frc_timing(struct msm_fb_data_type *mfd, void __user *argp);
void iris_calc_drc_exit(struct msm_fb_data_type *mfd);
#endif
void iris_dtg_para_set(int input_mode, int output_mode);
int iris_get_available_mode(struct msm_fb_data_type *mfd, void __user *argp);
int iris_frc_path_update(struct msm_fb_data_type *mfd, void __user *argp);
void iris_send_meta_video(struct mdss_mdp_ctl *ctl);
void iris_send_meta_cmd(struct mdss_mdp_ctl *ctl);
void iris_cmd_cadence_check(struct mdss_mdp_ctl *ctl);
void iris_calc_nrv(struct mdss_mdp_ctl *ctl);
void iris_i2c_send_meta(struct mdss_mdp_ctl *ctl);
void iris_reg_add(u32 addr, u32 val);
void iris_regs_clear(void);
void iris_update_configure(void);
u32 iris_get_vtotal(struct iris_timing_info *info);
//int iris_proc_constant_ratio(struct iris_config *iris_cfg);
#if !defined(FPGA_PLATFORM)
u32 iris_pi_read(struct mdss_dsi_ctrl_pdata *ctrl, u32 addr);
//u32 iris_pi_write(struct mdss_dsi_ctrl_pdata *ctrl, u32 addr, u32 value);
#endif
u32 iris_lp_memc_calc(u32 value);
bool iris_is_dbc_setting_disable(void);
bool iris_is_lce_setting_disable(void);
bool iris_is_cmdin_videout(void);
//void iris_set_te(struct iris_config *iris_cfg, int te_flag);
bool iris_is_peaking_setting_disable(void);
bool iris_is_cm_setting_disable(void);
#endif //MDSS_DSI_IRIS_H
