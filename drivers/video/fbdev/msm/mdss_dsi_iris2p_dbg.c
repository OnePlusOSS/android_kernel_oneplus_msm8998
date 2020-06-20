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
#include "mdss_dsi_iris2p_dbg.h"
#include "mdss_debug.h"

static void iris_nfrv_vsync_handler(struct mdss_mdp_ctl *ctl, ktime_t vtime)
{
	//u32 off, mixercfg;

	printk(KERN_DEBUG "#### %s:%d vtime=%lld\n", __func__, __LINE__, vtime.tv64);
	/*
	mixercfg = MDSS_MDP_LM_BORDER_COLOR;
	off = MDSS_MDP_REG_CTL_LAYER(0);
	mdss_mdp_ctl_write(ctl, off, mixercfg);
	*/
	ctl->force_screen_state = MDSS_SCREEN_FORCE_BLANK;
}

static struct mdss_mdp_vsync_handler nfrv_vsync_handler = {
	.vsync_handler = iris_nfrv_vsync_handler,
};

static int iris_fbo_enable(struct msm_fb_data_type *mfd, int enable)
{
	struct mdss_overlay_private *mdp5_data = mfd_to_mdp5_data(mfd);
	struct mdss_mdp_ctl *ctl = mdp5_data->ctl;

	if (enable && !mfd->iris_fbo_enable) {
		mfd->iris_fbo_enable = true;
		ctl->ops.add_vsync_handler(ctl, &nfrv_vsync_handler);
		pr_err("%s:%d enable\n", __func__, __LINE__);
	} else if (!enable && mfd->iris_fbo_enable) {
		mfd->iris_fbo_enable = false;
		ctl->ops.remove_vsync_handler(ctl, &nfrv_vsync_handler);
		ctl->force_screen_state = MDSS_SCREEN_DEFAULT;
	}

	return 0;
}

static int iris_sbs_enable(struct msm_fb_data_type *mfd, int enable)
{
	if (enable && !mfd->iris_sbs_enable) {
		mfd->iris_sbs_enable = true;
		pr_err("%s:%d enable\n", __func__, __LINE__);
	} else if (!enable && mfd->iris_sbs_enable) {
		mfd->iris_sbs_enable = false;
		pr_err("%s:%d disable\n", __func__, __LINE__);
	}

	return 0;
}

static ssize_t iris_dbg_fbo_write(struct file *file, const char __user *buff,
	size_t count, loff_t *ppos)
{
	struct msm_fb_data_type *mfd = g_mfd;
	unsigned long val;

	if (kstrtoul_from_user(buff, count, 0, &val))
		return -EFAULT;

	switch (val) {
	case 0:
		pr_info("%s:%d native frame rate video disable\n", __func__, __LINE__);
		iris_fbo_enable(mfd, 0);
		break;
	case 1:
		pr_info("%s:%d native frame rate video enable\n", __func__, __LINE__);
		iris_fbo_enable(mfd, 1);
		break;
	default:
		pr_err("%s:%d invalid input\n", __func__, __LINE__);
		break;
	}

	return count;
}

static const struct file_operations iris_dbg_fbo_fops = {
	.open = simple_open,
	.write = iris_dbg_fbo_write,
};

static ssize_t iris_dbg_sbs_write(struct file *file, const char __user *buff,
	size_t count, loff_t *ppos)
{
	struct msm_fb_data_type *mfd = g_mfd;
	unsigned long val;

	if (kstrtoul_from_user(buff, count, 0, &val))
		return -EFAULT;

	pr_info("%s:%d sbs_enable %li\n", __func__, __LINE__, val);
	switch (val) {
	case 0:
		iris_sbs_enable(mfd, 0);
		break;
	case 1:
		iris_sbs_enable(mfd, 1);
		break;
	default:
		pr_err("%s:%d invalid input\n", __func__, __LINE__);
		break;
	}

	return count;
}

static const struct file_operations iris_dbg_sbs_fops = {
	.open = simple_open,
	.write = iris_dbg_sbs_write,
};


static bool debug_vsync_enabled;
static void debug_vsync_handler(struct mdss_mdp_ctl *ctl, ktime_t vtime)
{
	// NOP
}

static struct mdss_mdp_vsync_handler iris_debug_vsync_handler = {
	.vsync_handler = debug_vsync_handler,
};

static ssize_t iris_dbg_vsync_write(struct file *file, const char __user *buff,
	size_t count, loff_t *ppos)
{
	struct msm_fb_data_type *mfd = g_mfd;
	struct mdss_overlay_private *mdp5_data = mfd_to_mdp5_data(mfd);
	struct mdss_mdp_ctl *ctl = mdp5_data->ctl;
	unsigned long val;

	if (kstrtoul_from_user(buff, count, 0, &val))
		return -EFAULT;
	pr_info("%s:%d vsync_enable %li\n", __func__, __LINE__, val);
	if (val && !debug_vsync_enabled) {
		ctl->ops.add_vsync_handler(ctl, &iris_debug_vsync_handler);
		debug_vsync_enabled = true;
	} else if (!val && debug_vsync_enabled) {
		ctl->ops.remove_vsync_handler(ctl, &iris_debug_vsync_handler);
		debug_vsync_enabled = false;
	}
	return count;
}

static const struct file_operations iris_dbg_vsync_fops = {
	.open = simple_open,
	.write = iris_dbg_vsync_write,
};

static ssize_t iris_dbg_meta_enable_write(struct file *file, const char __user *buff,
	size_t count, loff_t *ppos)
{
	struct msm_fb_data_type *mfd = g_mfd;
	struct iris_config *iris_cfg = &g_mfd->iris_conf;
	unsigned long val;
	uint32_t r;

	if (kstrtoul_from_user(buff, count, 0, &val))
		return -EFAULT;
	pr_info("%s:%d meta_enabled %u in/out %u/%u\n", __func__, __LINE__, (u32)val, iris_cfg->input_frame_rate, iris_cfg->output_frame_rate);
	debug_send_meta_enabled = val;

	r = gcd(mfd->iris_conf.input_frame_rate, mfd->iris_conf.output_frame_rate);
	mfd->iris_conf.in_ratio = mfd->iris_conf.input_frame_rate / r;
	mfd->iris_conf.out_ratio = mfd->iris_conf.output_frame_rate / r;

	iris_register_write(mfd, IRIS_PWIL_ADDR + 0x0638,
		(iris_cfg->out_ratio << IRIS_PWIL_OUT_FRAME_SHIFT));
	iris_register_write(mfd, IRIS_PWIL_ADDR + 0x12FC,
		(iris_cfg->in_ratio << IRIS_PWIL_IN_FRAME_SHIFT));
	return count;
}

static ssize_t iris_dbg_meta_enable_read(struct file *file, char __user *buff,
		size_t count, loff_t *ppos)
{
	int len, tot = 0;
	char bp[512];
	if (*ppos)
		return 0;

	len = sizeof(bp);
	tot = scnprintf(bp, len, "%u\n", debug_send_meta_enabled);

	if (copy_to_user(buff, bp, tot))
		return -EFAULT;

	*ppos += tot;

	return tot;
}

static const struct file_operations iris_dbg_meta_fops = {
	.open = simple_open,
	.write = iris_dbg_meta_enable_write,
	.read = iris_dbg_meta_enable_read,
};

int iris_debugfs_init(struct msm_fb_data_type *mfd)
{
	struct iris_config *iris_cfg = &mfd->iris_conf;

	iris_cfg->dbg_root = debugfs_create_dir("iris", NULL);
	if (IS_ERR_OR_NULL(iris_cfg->dbg_root)) {
		pr_err("debugfs_create_dir for iris_debug failed, error %ld\n",
		       PTR_ERR(iris_cfg->dbg_root));
		return -ENODEV;
	}

	debugfs_create_u32("set_ratio", 0644, iris_cfg->dbg_root,
		(u32 *)&debug_ratio_enabled);

	debugfs_create_u32("set_mode_switch", 0644, iris_cfg->dbg_root,
		(u32 *)&debug_mode_switch_enabled);

	debugfs_create_u32("set_repeat", 0644, iris_cfg->dbg_root,
		(u32 *)&debug_repeat_enabled);

	debugfs_create_u32("set_dtg", 0644, iris_cfg->dbg_root,
		(u32 *)&debug_dtg_enabled);

	debugfs_create_u32("set_te", 0644, iris_cfg->dbg_root,
		(u32 *)&debug_te_enabled);

	debugfs_create_u32("set_new_frame", 0644, iris_cfg->dbg_root,
		(u32 *)&debug_new_frame_enabled);

	debugfs_create_u32("new_repeat", 0644, iris_cfg->dbg_root,
		(u32 *)&debug_new_repeat);

	debugfs_create_u32("true_cut", 0644, iris_cfg->dbg_root,
		(u32 *)&debug_true_cut);

	debugfs_create_u32("frc_path", 0644, iris_cfg->dbg_root,
		(u32 *)&g_mfd->iris_conf.frc_path);

	debugfs_create_u32("input_vfr", 0644, iris_cfg->dbg_root,
		(u32 *)&g_mfd->iris_conf.input_vfr);

	debugfs_create_u32("set_hlmd", 0644, iris_cfg->dbg_root,
		(u32 *)&debug_hlmd_enabled);

	debugfs_create_u32("debug_pt", 0644, iris_cfg->dbg_root,
		(u32 *)&iris_debug_pt);

	debugfs_create_u32("debug_bypass", 0644, iris_cfg->dbg_root,
		(u32 *)&iris_debug_bypass);

	debugfs_create_u32("debug_kickoff60", 0644, iris_cfg->dbg_root,
		(u32 *)&iris_debug_kickoff60);

	debugfs_create_u32("debug_lastframerepeat", 0644, iris_cfg->dbg_root,
		(u32 *)&iris_debug_lastframerepeat);

	debugfs_create_u32("debug_pt_disable", 0644, iris_cfg->dbg_root,
		(u32 *)&iris_debug_pt_disable);

	debugfs_create_u32("debug_dtg_v12", 0644, iris_cfg->dbg_root,
		(u32 *)&iris_debug_dtg_v12);

	debugfs_create_u32("dsi_mode_in_rfb", 0644, iris_cfg->dbg_root,
		(u32 *)&iris_cfg->avail_mode.dsi_mode_in_rfb);

	debugfs_create_u32("dsi_mode_in_ptl", 0644, iris_cfg->dbg_root,
		(u32 *)&iris_cfg->avail_mode.dsi_mode_in_ptl);

	debugfs_create_u32("dsi_mode_in_pth", 0644, iris_cfg->dbg_root,
		(u32 *)&iris_cfg->avail_mode.dsi_mode_in_pth);

	if (debugfs_create_file("fbo", 0644, iris_cfg->dbg_root, mfd,
				&iris_dbg_fbo_fops)
			== NULL) {
		printk(KERN_ERR "%s(%d): debugfs_create_file: index fail\n",
			__FILE__, __LINE__);
		return -EFAULT;
	}

	if (debugfs_create_file("sbs", 0644, iris_cfg->dbg_root, mfd,
				&iris_dbg_sbs_fops)
			== NULL) {
		printk(KERN_ERR "%s(%d): debugfs_create_file: index fail\n",
			__FILE__, __LINE__);
		return -EFAULT;
	}

	if (debugfs_create_file("vsync_debug", 0644, iris_cfg->dbg_root, mfd,
				&iris_dbg_vsync_fops)
			== NULL) {
		printk(KERN_ERR "%s(%d): debugfs_create_file: index fail\n",
			__FILE__, __LINE__);
		return -EFAULT;
	}

	if (debugfs_create_file("send_meta", 0644, iris_cfg->dbg_root, mfd,
				&iris_dbg_meta_fops)
			== NULL) {
		printk(KERN_ERR "%s(%d): debugfs_create_file: index fail\n",
			__FILE__, __LINE__);
		return -EFAULT;
	}

	return 0;
}
