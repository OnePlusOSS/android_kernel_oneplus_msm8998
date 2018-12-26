#ifndef __DEVICE_INFO_H__
#define __DEVICE_INFO_H__
extern struct pstore_info *psinfo;

extern uint32_t chip_serial_num;
extern char ufs_vendor_and_rev[32];
extern char ddr_manufacture_and_fw_verion[40];


#define MAX_ITEM 4
#define MAX_LENGTH 32

enum {
	serialno = 0,
	hw_version,
	rf_version,
	pcba_number
};

static char oem_serialno[16] = {0};
static char oem_hw_version[3] = {0};
static char oem_rf_version[3] = {0};
static char oem_pcba_number[30] = {0};

const char cmdline_info[MAX_ITEM][MAX_LENGTH] = {
	"androidboot.serialno=",
	"androidboot.hw_version=",
	"androidboot.rf_version=",
	"androidboot.pcba_number=",
};

#endif
