
#ifndef MDSS_DSI_IRISP_API_H
#define MDSS_DSI_IRISP_API_H


extern void iris_init(struct mdss_dsi_ctrl_pdata *ctrl);
extern void iris_lightup(struct mdss_dsi_ctrl_pdata *ctrl);
extern void iris_init_params_parse(struct device_node *np, struct mdss_dsi_ctrl_pdata *ctrl_pdata);
extern void iris_init_cmd_setup(struct mdss_dsi_ctrl_pdata *ctrl_pdata);
extern void iris_lightoff(struct mdss_dsi_ctrl_pdata *ctrl);
extern int iris2p_debugfs_init(struct msm_fb_data_type *mfd);
extern void iris_fw_download_cont_splash(struct mdss_dsi_ctrl_pdata *ctrl, bool video_freeze);
extern void iris_abypass_switch_state_init(int mode);
extern void iris_abypass_switch_proc(struct mdss_dsi_ctrl_pdata *ctrl);
extern int iris_pt_to_abypass_switch(struct mdss_dsi_ctrl_pdata *ctrl);
extern int iris_abypass_to_pt_switch(struct mdss_dsi_ctrl_pdata *ctrl);
extern void iris_panel_cmd_passthrough(struct mdss_dsi_ctrl_pdata *ctrl, struct dcs_cmd_req *cmdreq);
extern int iris_passthrough_cmd_process(void);
extern int iris_power_clock_gate_on(struct msm_fb_data_type *mfd);
extern void iris_low_power_mode_notify(struct msm_fb_data_type *mfd);
extern void iris_panel_cmds(struct mdss_dsi_ctrl_pdata *ctrl, struct dsi_panel_cmds *pcmds);
#endif

