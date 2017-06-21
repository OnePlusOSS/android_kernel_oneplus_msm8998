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
#ifndef MDSS_DSI_IRISP_H
#define MDSS_DSI_IRISP_H

#include <linux/types.h>
#include "mdss_dsi_iris2p_def.h"


#define CMD_PKT_SIZE 512
#define GRCP_HEADER 16
#define INIT_CMD_NUM 2



//#define FPGA_DEBUG
#ifdef FPGA_DEBUG
#define WAKEUP_TIME 500
#define CMD_PROC 10
#define MCU_PROC 10
#define INIT_WAIT 100
#else
#define WAKEUP_TIME 50
#define CMD_PROC 0
#define MCU_PROC 1
#define INIT_WAIT 0
#endif

//#define MIPI_SWAP
//#define READ_CMD_ENABLE
//#define NEW_WORKFLOW
//#define ONE_WIRED_CMD_VIA_RESET_GPIO
#define ONE_WIRED_CMD_VIA_WAKEUP_GPIO
//#define EFUSE_REWRITE

#define IRIS_SYS_ADDR		0xF0000000
#ifdef MIPI_SWAP
#define IRIS_MIPI_RX_ADDR	0xF0140000
#define IRIS_MIPI_TX_ADDR	0xF01c0000
#else
#define IRIS_MIPI_RX_ADDR	0xF0100000
#define IRIS_MIPI_TX_ADDR	0xF0180000
#endif
#define IRIS_PROXY_ADDR	    0xF0040000
#define IRIS_PWIL_ADDR	    0xF1240000
#define IRIS_DTG_ADDR		0xF1200000
#define IRIS_DPORT_ADDR		0xF1220000

/* SYS register */
#define CLKGATE_CTRL0 0x0
#define CLKGATE_CTRL1 0x4
#define CLKGATE_PWIL_SW 0x8
#define CLKMUX_CTRL	0x0c
#define CLKDIV_CTRL	0x10
#define PPLL_B_CTRL0	0x140
#define PPLL_B_CTRL1	0x144
#define PPLL_B_CTRL2	0x148
#define DPLL_B_CTRL0	0x150
#define DPLL_B_CTRL1	0x154
#define DPLL_B_CTRL2	0x158
#define MPLL_B_CTRL0	0x160
#define MPLL_B_CTRL1	0x164
#define MPLL_B_CTRL2	0x168
#define PLL_CTRL	0x200
#define DCLK_SRC_SEL	0x210
#define INCLK_SRC_SEL	0x214
#define MCUCLK_SRC_SEL	0x218
#define PCLK_SRC_SEL	0x21c
#define MCLK_SRC_SEL	0x228
#define ALT_CTRL0	0x248
#define DFT_EFUSE_CTRL	0x10000
#define DFT_EFUSE_CTRL_1	0x10004


/*DTG register*/
#define HSCTRL1			0x04
#define VSCTRL0			0x10
#define VSCTRL1			0x14
#define DTG_CTRL		0x20
#define EVS_DLY			0x2c
#define EVS_NEW_DLY		0x30
#define DTG_DELAY		0x34
#define TE_CTRL			0x4c
#define TE_CTRL_1		0x50
#define TE_CTRL_2		0x54
#define TE_CTRL_3		0x58
#define TE_CTRL_4		0x5c
#define TE_CTRL_5		0xac
#define DTG_CTRL_1		0x70
#define VFP_CTRL_0		0x7c
#define VFP_CTRL_1		0x80
#define DVS_CTRL		0x90
#define TE_DLY			0x9c
#define TE_DLY_1		0xb0
#define DTG_RESERVE		0xa8
#define REGSEL			0x10000

/*MIPI_RX register*/
#define DBI_HANDLER_CTRL	0x0000c
#define FRAME_COLUMN_ADDR	0x00018
#define ABNORMAL_COUNT_THRES	0x0001c
#define INTEN	0x1ffe8
#define DEVICE_READY		0x20000
#define INTERRUPT_ENABLE	0x20008
#define DSI_FUNCTIONAL_PROGRAMMING	0x2000c
#define EOT_ECC_CRC_DISABLE	0x20024
#define DATA_LANE_TIMING_PARAMETER	0x2002c
#define RESET_ENABLE_DFE	0x20030
#define DPI_SYNC_COUNT		0x20058

/*MIPI_TX register*/
#define DSI_TX_CTRL         0x00000
#define DPHY_CTRL           0x00004
#define MANUAL_BYPASS_CTRL  0x00008
#define TE_FLOW_CTRL        0x00018
#define DUAL_CH_CTRL        0x00020
#define HS_TX_TIMER		0x00024
#define BTA_LP_TIMER		0x00028
#define INITIALIZATION_RESET_TIMER	0x0002c
#define TX_RESERVED_0		0x00030
#define DPHY_TIMING_MARGIN  0x00040
#define DPHY_LP_TIMING_PARA 0x00050
#define DPHY_DATA_LANE_TIMING_PARA  0x00054
#define DPHY_CLOCK_LANE_TIMING_PARA 0x00058
#define DPHY_PLL_PARA		0x0005c
#define DPHY_TRIM_1		0x00064
#define WR_PACKET_HEADER_OFFS       0x1c010
#define WR_PACKET_PAYLOAD_OFFS      0x1c014
#define RD_PACKET_DATA_OFFS         0x1c018


#define IRIS_MIPI_ADDR_OFFSET	0x40000
#define IRIS_GRCP_BUFFER_ADDR  0xf0212C00
#define IRIS_GRCP_CTRL_ADDR    0xf0200000

#define PWIL_TAG(a, b, c, d) d, c, b, a
#define PWIL_U32(x) \
	(__u8)(((x)	) & 0xff), \
	(__u8)(((x) >>  8) & 0xff), \
	(__u8)(((x) >> 16) & 0xff), \
	(__u8)(((x) >> 24) & 0xff)

#define PWIL_U16(x) \
	(__u8)(((x)	) & 0xff), \
	(__u8)(((x) >> 8 ) & 0xff)

#define FW_COL_CNT  85
#define FW_DW_CMD_CNT  1200
#define DSI_DMA_TX_BUF_SIZE	SZ_512K
#define DCS_WRITE_MEM_START 0x2C
#define DCS_WRITE_MEM_CONTINUE 0x3C

#define IRIS_FIRMWARE_NAME	"iris2p.fw"



enum result {
	FAILED = -1,
	SUCCESS = 0,
};


enum mipi_rx_mode {
	MCU_VIDEO = 0,
	MCU_CMD = 1,
	PWIL_VIDEO = 2,
	PWIL_CMD = 3,
	BYPASS_VIDEO = 4,
	BYPASS_CMD = 5,
};

enum romcode_ctrl {
	CONFIG_DATAPATH = 1,
	ENABLE_DPORT = 2,
	ITCM_COPY = 4,
	REMAP = 8,
};

enum pwil_mode {
	PT_MODE,
	RFB_MODE,
	BIN_MODE,
};

enum iris_mipi_mode {
	MIPI_VIDEO_MODE = 0x0,
	MIPI_CMD_MODE = 0x01,
};

enum iris_onewired_cmd {
	RX0_POWER_UP = 1,
	BYPASS_MODE_CHANGE = 2,
	RX0_POWER_DOWN = 3,
	RX0_RESET = 4,
	FORCE_WORK_MODE_SWITCH = 5,
	REVERSED = 6,
};

enum iris_abypass_status {
	ANALOG_BYPASS_MODE = 0,
	PASS_THROUGH_MODE,
};

enum iris_abypss_switch_state {
	PASS_THROUGH_STATE = 0,
	MCU_STOP_ENTER_STATE,
	TTL_CMD_BYPASS_STATE,
	ANALOG_BYPASS_ENTER_STATE,
	RX0_POWER_DOWN_STATE,
	ANALOG_BYPASS_STATE,
	RX0_POWER_UP_STATE ,
	RFB_STATE,
	MCU_STOP_EXIT_STATE,
	ANALOG_BYPASS_EXIT_STATE,
	LOW_POWER_ENTER_STATE,
	LOW_POWER_EXIT_STATE,
};

struct iris_work_mode {
	u32 rx_mode:1;			/* 0-video/1-cmd */
	u32 rx_ch:1;			/* 0-single/1-dual */
	u32 rx_dsc:1;			/* 0-non DSC/1-DSC */
	u32 rx_pxl_mode:1;		/*interleave/left-right */
	u32 reversed0:12;

	u32 tx_mode:1;			/* 0-video/1-cmd */
	u32 tx_ch:1;			/* 0-single/1-dual */
	u32 tx_dsc:1;			/* 0-non DSC/1-DSC */
	u32 tx_pxl_mode:1;		/* interleave/left-right */
	u32 reversed1:12;
};

struct iris_timing_info {
	u16 hfp;
	u16 hres;
	u16 hbp;
	u16 hsw;
	u16 vfp;
	u16 vres;
	u16 vbp;
	u16 vsw;
	u16 fps;
};

struct iris_pll_setting {
	u32 ppll_ctrl0;
	u32 ppll_ctrl1;
	u32 ppll_ctrl2;

	u32 dpll_ctrl0;
	u32 dpll_ctrl1;
	u32 dpll_ctrl2;

	u32 mpll_ctrl0;
	u32 mpll_ctrl1;
	u32 mpll_ctrl2;

	u32 txpll_div;
	u32 txpll_sel;
	u32 reserved;
};

struct iris_clock_source {
	u8 sel;
	u8 div;
	u8 div_en;
};

struct iris_clock_setting {
	struct iris_clock_source dclk;
	struct iris_clock_source inclk;
	struct iris_clock_source mcuclk;
	struct iris_clock_source pclk;
	struct iris_clock_source mclk;
	struct iris_clock_source escclk;
};

struct iris_setting_disable_info {
	u32 last_frame_repeat_cnt;

	u32 dbc_dlv_sensitivity_disable_val;
	u32 dbc_quality_disable_val;

	u32 pq_peaking_disable_val;
	u32 pq_peaking_demo_disable_val;
	int pq_gamma_disable_val;
	u32 pq_contrast_disable_val;

	u32 lce_mode_disable_val;

	u32 color_adjust_disable_val;

	u32 cm_c6axes_disable_val;
	u32 cm_c3d_disable_val;
	u32 color_temp_disable_val;
	u32 reading_mode_disable_val;
	u32 cm_ftcen_disable_val;
};

struct iris_setting_info {
	struct iris_pll_setting pll_setting;
	struct iris_clock_setting clock_setting;

	u32 mipirx_dsi_functional_program;
	u32 mipirx_eot_ecc_crc_disable;
	u32 mipirx_data_lane_timing_param;

	u32 mipitx_dsi_tx_ctrl;
	u32 mipitx_hs_tx_timer;
	u32 mipitx_bta_lp_timer;
	u32 mipitx_initialization_reset_timer;
	u32 mipitx_dphy_timing_margin;
	u32 mipitx_lp_timing_para;
	u32 mipitx_data_lane_timing_param;
	u32 mipitx_clk_lane_timing_param;
	u32 mipitx_dphy_pll_para;
	u32 mipitx_dphy_trim_1;

	int delta_period_max;
	int delta_period_min;

	struct iris_setting_disable_info  disable_info;
	struct quality_setting quality_def;
	struct quality_setting quality_cur;
	//TODO
	u8 dbc_mode;
};

struct iris_dsc_info {
	u16 slice_number;
	u16 slice_height;
	u16 bpp;
};

struct iris_fw_info {
	u32 firmware_size;
	int fw_dw_result;
};

struct iris_tx_switch_cmd {
	struct dsi_panel_cmds mipitx_cmdmode_cmds;
	struct dsi_panel_cmds mipitx_vid2cmd_cmds;
	struct dsi_panel_cmds mipitx_cmd2vid_cmds;
};

struct iris_intf_switch_info {
	u8 rx_switch_enable;
	u8 rx_current_mode;

	u8 tx_switch_enable;
	u8 tx_current_mode;
};


struct iris_abypass_ctrl {
	bool analog_bypass_enable;
	bool abypass_status;
	bool abypass_debug;
	bool abypass_to_pt_enable;
	bool pt_to_abypass_enable;
	int abypss_switch_state;
	u32 base_time;
	int frame_delay;
};

struct iris_power_status {
	int low_power;
	int low_power_state;
	int work_state_wait;
};

struct iris_info_t {
	struct iris_work_mode work_mode;
	struct iris_timing_info input_timing;
	struct iris_timing_info output_timing;
	struct iris_setting_info setting_info;
	struct iris_dsc_info input_dsc;
	struct iris_dsc_info output_dsc;
	struct iris_fw_info firmware_info;
	struct fi_demo_win fi_demo_win_info;
	struct peaking_demo_win peaking_demo_win_info;
	struct cm_demo_win cm_demo_win_info;
	struct iris_conf_update update;
	struct iris_tx_switch_cmd tx_switch_cmd;
	struct iris_intf_switch_info intf_switch_info;
	struct iris_abypass_ctrl abypss_ctrl;
	struct iris_power_status power_status;
	bool panel_cmd_sync_wait_broadcast;
};

struct iris_grcp_cmd {
	char cmd[CMD_PKT_SIZE];
	int cmd_len;
};

struct iris_rom_status {
    u8 init_done : 1;
    u8 config_datapath_done : 1;
    u8 enable_dport_done : 1;
    u8 itcm_copy_done : 1;
    u8 remap_done : 1;
    u8 reserved : 2;
    u8 Romcode : 1;
};

typedef union
{
    struct iris_rom_status Rom_Sts;
    u8 value;
} uPowerMode;


#endif
