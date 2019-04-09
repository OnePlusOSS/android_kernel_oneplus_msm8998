#ifndef MDSS_DSI_IRIS_MODE_SWITCH
#define MDSS_DSI_IRIS_MODE_SWITCH
void iris_dsimode_update(char mode);
void iris_mipitx_intf_switch_state_reset(struct msm_fb_data_type *mfd, u32 new_mode, bool debug);
u8 iris_mipitx_interface_switch(struct msm_fb_data_type *mfd, bool debug);
void iris_dms_config(struct mdss_dsi_ctrl_pdata *ctrl);
int iris_mode_switch_cmd(struct msm_fb_data_type *mfd);
int iris_mode_switch_video(struct msm_fb_data_type *mfd);
void iris_mode_switch_reset(struct mdss_dsi_ctrl_pdata *ctrl);
#endif
