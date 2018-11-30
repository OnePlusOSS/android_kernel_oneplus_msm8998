#ifndef MDSS_DSI_IRIS_EXTERN_H
#define MDSS_DSI_IRIS_EXTERN_H
#include "mdss_dsi_iris2p_def.h"
// iris2, iris workmode
extern struct iris_info_t iris_info;
extern struct msm_fb_data_type *g_mfd;
extern struct mdss_dsi_ctrl_pdata *g_dsi_ctrl;

/* debug send meta */
extern bool debug_send_meta_enabled;
/* debug new frame flag in video mode */
extern int debug_new_frame_enabled;
/* debug in/out ratio flag */
extern int debug_ratio_enabled;
extern int debug_hlmd_enabled;
/* debug repeat flag */
extern int debug_repeat_enabled;
/* debug te flag */
extern int debug_te_enabled;
/* debug dtg */
extern int debug_dtg_enabled;
extern bool frc_repeat_enter;
extern int debug_new_repeat;
/* debug send mode switch */
extern int debug_mode_switch_enabled;
extern int debug_true_cut;
extern int iris_debug_pt;
extern int iris_debug_bypass;
extern int iris_debug_kickoff60;
extern int iris_debug_lastframerepeat;
extern int iris_debug_pt_disable;
extern int iris_debug_dtg_v12;

// FIXME mdp5 use add vsync handler and no find DMA_P bit
//void mdp4_dsi_video_wait4dmap_done(int cndx);

/* Activate Delay 0, FBO Enable: 0, Display Mode: Normal,
 * PSR Command: PSR Enable, Capture Enable: -
 */
extern char pt_enable[2];
extern char memc_enable[2];
extern char bypass_enable;
extern u16 lp_memc_timing[];

extern char iris_pt_enter_cmds[];
extern char iris_rfb_enter_cmds[];
extern char iris_memc_enter_cmds[];

extern struct dsi_cmd_desc pt_data_path_config[1];
extern struct dsi_cmd_desc rfb_data_path_config[1];
extern struct dsi_cmd_desc pt_mode_enter[1];

extern struct dsi_cmd_desc memc_data_path_config[1];

extern struct dsi_cmd_desc memc_mode_enter[1];
#endif
