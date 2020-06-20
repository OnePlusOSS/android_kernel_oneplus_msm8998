#include "mdss_dsi_iris2p.h"
#include "mdss_dsi_iris2p_def.h"
// iris2, iris workmode

struct iris_info_t iris_info;

struct msm_fb_data_type *g_mfd;
struct mdss_dsi_ctrl_pdata *g_dsi_ctrl;

/* debug send meta */
bool debug_send_meta_enabled = 1;
/* debug new frame flag in video mode */
int debug_new_frame_enabled = 1;
/* debug in/out ratio flag */
int debug_ratio_enabled = 0;
int debug_hlmd_enabled = 0;
/* debug repeat flag */
int debug_repeat_enabled = 1;
/* debug te flag */
int debug_te_enabled = 1;
/* debug dtg */
int debug_dtg_enabled;
bool frc_repeat_enter;
int debug_new_repeat = 1;
/* debug send mode switch */
int debug_mode_switch_enabled = 1;
int debug_true_cut = 1;
int iris_debug_pt = 0;
int iris_debug_bypass = 0;
int iris_debug_kickoff60 = 0;
int iris_debug_lastframerepeat = 0;
int iris_debug_pt_disable = 0;
int iris_debug_dtg_v12 = 1;

// FIXME mdp5 use add vsync handler and no find DMA_P bit
//void mdp4_dsi_video_wait4dmap_done(int cndx);

/* Activate Delay 0, FBO Enable: 0, Display Mode: Normal,
 * PSR Command: PSR Enable, Capture Enable: -
 */
char pt_enable[2] = { 0x00, 0x00 };
char memc_enable[2] = {0x04, 0x2};
char bypass_enable = 0xff;
u16 lp_memc_timing[] = {IRIS_DTG_HRES_SETTING, IRIS_DTG_VRES_SETTING};

char iris_pt_enter_cmds[] = {
	PWIL_TAG('P', 'W', 'I', 'L'),
	PWIL_TAG('G', 'R', 'C', 'P'),
	PWIL_U32(0x00000005),	//valid word number
	0x00,					//burst mode
	0x00,					//reserved
	PWIL_U16(0x0004),		//burst length
	PWIL_U32(IRIS_DATA_PATH_ADDR),	//proxy MB2
	PWIL_U32(0x800000),
	PWIL_U32(IRIS_MODE_ADDR), //proxy MB1
	PWIL_U32(0x800000)
};

char iris_rfb_enter_cmds[] = {
	PWIL_TAG('P', 'W', 'I', 'L'),
	PWIL_TAG('G', 'R', 'C', 'P'),
	PWIL_U32(0x00000005),	//valid word number
	0x00,					//burst mode
	0x00,					//reserved
	PWIL_U16(0x0004),		//burst length
	PWIL_U32(IRIS_DATA_PATH_ADDR),	//proxy MB2
	PWIL_U32(0x800000),
	PWIL_U32(IRIS_MODE_ADDR), //proxy MB1
	PWIL_U32(0x800001)
};

char iris_memc_enter_cmds[] = {
	PWIL_TAG('P', 'W', 'I', 'L'),
	PWIL_TAG('G', 'R', 'C', 'P'),
	PWIL_U32(0x00000005),	//valid word number
	0x00,					//burst mode
	0x00,					//reserved
	PWIL_U16(0x0004),		//burst length
	PWIL_U32(IRIS_DATA_PATH_ADDR),	//proxy MB2
	PWIL_U32(0x800000),
	PWIL_U32(IRIS_MODE_ADDR), //proxy MB1
	PWIL_U32(0x800002)
};

struct dsi_cmd_desc pt_data_path_config[1] = {
	{ { DTYPE_GEN_LWRITE, 1, 0, 0, 0,
		sizeof(iris_pt_enter_cmds) }, iris_pt_enter_cmds},
};

struct dsi_cmd_desc rfb_data_path_config[] = {
	{ { DTYPE_GEN_LWRITE, 1, 0, 0, 0,
		sizeof(iris_rfb_enter_cmds) }, iris_rfb_enter_cmds},
};

struct dsi_cmd_desc pt_mode_enter[1] = {
	{ { DTYPE_GEN_WRITE2, 1, 0, 0, 0,
		sizeof(pt_enable) }, pt_enable},
};

struct dsi_cmd_desc memc_data_path_config[1] = {
	{ { DTYPE_GEN_LWRITE, 1, 0, 0, 0,
		sizeof(iris_memc_enter_cmds) }, iris_memc_enter_cmds},
};

struct dsi_cmd_desc memc_mode_enter[1] = {
	{ { DTYPE_GEN_WRITE2, 1, 0, 0, 0,
		sizeof(memc_enable) }, memc_enable},
};
