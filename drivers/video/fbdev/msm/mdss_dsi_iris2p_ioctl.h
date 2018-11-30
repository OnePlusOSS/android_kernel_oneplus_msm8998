#ifndef MDSS_DSI_IRIS_IOCTL
#define MDSS_DSI_IRIS_IOCTL

enum res_ratio{
	ratio_4to3 = 1,
	ratio_16to10,
	ratio_16to9,
};

int msmfb_iris_operate_conf(struct msm_fb_data_type *mfd,
				void __user *argp);

int iris_operate_mode(struct msm_fb_data_type *mfd,
				void __user *argp);

int iris_set_meta(struct msm_fb_data_type *mfd, void __user *argp);


int msmfb_iris_operate_tool(struct msm_fb_data_type *mfd,
				void __user *argp);

#endif
