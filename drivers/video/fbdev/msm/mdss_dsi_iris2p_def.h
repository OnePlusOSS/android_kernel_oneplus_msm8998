#ifndef MDSS_DSI_IRIS_DEF_H
#define MDSS_DSI_IRIS_DEF_H

#define IRIS_CHIP_HW_VER 1

#define RATIO_NUM  (8)

// assume 1 entry 1 ms
#define IRIS_CMD_FIFO_EMPTY 16
#define IRIS_REPEAT_NO     0
#define IRIS_REPEAT_FORCE  1
#define IRIS_REPEAT_CAPDIS 2

/* Per Panel different */
#define IRIS_DTG_EVS_DLY   224

#define META_PKT_SIZE 512
#define META_HEADER 16

#define IMG720P_VSIZE    (720)
#ifdef ENABLE_IRIS2_480X800_PANEL
#define IRIS_DTG_HRES_SETTING 480
#define IRIS_DTG_VRES_SETTING 800
#else
#define IRIS_DTG_HRES_SETTING 768
#define IRIS_DTG_VRES_SETTING 2048
#endif

#define LEVEL_MAX   (5)
#define IMG1080P_HSIZE   (1920)
#define IMG1080P_VSIZE   (1080)
#define IMG720P_HSIZE    (1280)

#if 0
/* Assume the panel can accept this period increase */
#define IRIS_DELTA_VT_P        (31)
/* VFP needs at least 2 lines VSW needs at least 1 line */
#define IRIS_DELTA_VT_M        (-4)
#endif

// MB3
struct iris_pq_setting {
	uint32_t peaking:4;
	uint32_t sharpness:4;
	uint32_t memcdemo:4;
	uint32_t gamma:2;
	uint32_t memclevel:2;
	uint32_t contrast:8;
	uint32_t cinema_en:1;
	uint32_t peakingdemo:4;
	uint32_t reserved:2;
	uint32_t update:1;
};

// MB5
struct iris_dbc_setting {
	uint32_t update:1;
	uint32_t reserved:7;
	uint32_t brightness:7;
	uint32_t ext_pwm:1;
	uint32_t cabcmode:4;
	uint32_t dlv_sensitivity:12;
};

struct iris_lce_setting {
	uint32_t mode:4;
	uint32_t mode1level:4;
	uint32_t mode2level:4;
	uint32_t demomode:4;
	uint32_t reserved:15;
	uint32_t update:1;
};

struct iris_cm_setting {
	uint32_t cm6axes:3;
	uint32_t cm3d:5;
	uint32_t demomode:3;
	uint32_t ftc_en:1;
	uint32_t color_temp_en:1;
	uint32_t color_temp:15;
	uint32_t sensor_auto_en:1;
	uint32_t reserved:2;
	uint32_t update:1;
};

struct iris_lux_value {
	uint32_t luxvalue:16;
	uint32_t reserved:15;
	uint32_t update:1;
};

struct iris_cct_value {
	uint32_t cctvalue:16;
	uint32_t reserved:15;
	uint32_t update:1;
};

struct iris_reading_mode {
	uint32_t readingmode:1;
	uint32_t reserved:30;
	uint32_t update:1;
};

struct iris_config_setting {
	int    update;
	u8	level;
	uint32_t value;
};

struct iris_conf_update {
	uint32_t demo_win_fi:1;
	uint32_t pq_setting:1;
	uint32_t dbc_setting:1;
	uint32_t lp_memc_setting:1;
	uint32_t color_adjust:1;
	uint32_t lce_setting:1;
	uint32_t cm_setting:1;
	uint32_t cmd_setting:1;
	uint32_t lux_value:1;
	uint32_t cct_value:1;
	uint32_t reading_mode:1;
	uint32_t reserved:21;
};
// ---------------------------------------------------------------------------
//! Structure definition for demo window.
// ---------------------------------------------------------------------------
struct demo_win_info {
	int   startx;    //12bits width
	int   starty;    //12bits width
	int   endx;      //12bits width
	int   endy;     //12bits width
	int   color;      //Y U V 8bits width,      Y[7:0], U[15:8], V[23:16]
	int   borderwidth;    ///3bits width
	int   fi_demo_en;          //bool
	int   sharpness_en;   //bool
	int   cm_demo_en;   //bool
};

// ---------------------------------------------------------------------------
//! Structure  definition for demo window FI setting.
// ---------------------------------------------------------------------------
struct fi_demo_win {
	int   startx;    //12bits width panel position
	int   starty;    //12bits width panel position
	int   endx;      //12bits width panel position
	int   endy;     //12bits width panel position
	int   borderwidth;    ///3bits width
	int   colsize;
	int   color;
	int   rowsize;
	int   modectrl;
};

struct peaking_demo_win {
	int   startx;    //12bits width panel position
	int   starty;    //12bits width panel position
	int   endx;      //12bits width panel position
	int   endy;     //12bits width panel position
	int   sharpness_en;   //bool
};

struct cm_demo_win {
	int   startx;    //12bits width panel position
	int   starty;    //12bits width panel position
	int   endx;      //12bits width panel position
	int   endy;     //12bits width panel position
	int   cm_demo_en;   //bool
};

struct quality_setting {
	struct iris_pq_setting pq_setting;
	struct iris_dbc_setting dbc_setting;
	struct iris_config_setting lp_memc_setting;
	struct iris_lce_setting lce_setting;
	struct iris_cm_setting cm_setting;
	struct iris_lux_value lux_value;
	struct iris_cct_value cct_value;
	struct iris_reading_mode reading_mode;
	u8 color_adjust;
};

#endif
