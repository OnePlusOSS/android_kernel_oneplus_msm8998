
#include <linux/kernel.h>

#include <linux/init.h>

#include <linux/types.h>

#include <linux/pstore.h>

#include "device_info.h"

static int __init device_info_init(void)
{
	int i, j, target_len;
	char *substr, *target_str;

	for (i = 0; i < MAX_ITEM; i++) {
		substr = strnstr(boot_command_line,
			cmdline_info[i],
			sizeof(cmdline_info[i]));
		if (substr != NULL)
			substr += strlen(cmdline_info[i]);
		else
			continue;

		if (i == serialno) {
			target_str = oem_serialno;
			target_len = sizeof(oem_serialno);
		} else if (i == hw_version) {
			target_str = oem_hw_version;
			target_len = sizeof(oem_hw_version);
		} else if (i == rf_version) {
			target_str = oem_rf_version;
			target_len = sizeof(oem_rf_version);
		} else if (i == pcba_number) {
			target_str = oem_pcba_number;
			target_len = sizeof(oem_pcba_number);
		} else
			continue;

		for (j = 0; substr[j] != ' ' && j < target_len; j++)
			target_str[j] = substr[j];
		/*target_str[j] = '\0';*/

	}
	return 1;
}




static void __init pstore_write_device_info(const char *s, unsigned c)
{
	const char *e = s + c;

	if (c <= 0)
		return;

	while (s < e) {
		unsigned long flags;
		u64 id;

		if (c > psinfo->bufsize)
			c = psinfo->bufsize;

		if (oops_in_progress) {
			if (!spin_trylock_irqsave(&psinfo->buf_lock, flags))
				break;
		} else {
			spin_lock_irqsave(&psinfo->buf_lock, flags);
		}
		memcpy(psinfo->buf, s, c);
		psinfo->write(PSTORE_TYPE_DEVICE_INFO, 0,
			&id, 0, 0, 0, c, psinfo);
		spin_unlock_irqrestore(&psinfo->buf_lock, flags);
		s += c;
		c = e - s;
	}

	return;

}

static void __init write_device_info(const char *key, const char *value)
{
	pstore_write_device_info(key, strlen(key));
	pstore_write_device_info(": ", 2);
	pstore_write_device_info(value, strlen(value));
	pstore_write_device_info("\r\n", 2);
}

static int __init init_device_info(void)
{

	device_info_init();
	pstore_write_device_info(" * * * begin * * * \r\n",
		strlen(" * * * begin * * * \r\n"));

	write_device_info("hardware version", oem_hw_version);
	write_device_info("rf version", oem_rf_version);
	write_device_info("ddr info", ddr_manufacture_and_fw_verion);
	write_device_info("pcba number", oem_pcba_number);
	write_device_info("serial number", oem_serialno);

	memset(oem_serialno, 0, sizeof(oem_serialno));
	scnprintf(oem_serialno, sizeof(oem_serialno), "%x", chip_serial_num);
	write_device_info("socinfo serial_number", oem_serialno);

	write_device_info("ufs vendor and rev", ufs_vendor_and_rev);

	write_device_info("kernel version", linux_banner);
	write_device_info("boot command", saved_command_line);

	pstore_write_device_info(" * * * end * * * \r\n",
		strlen(" * * * end * * * \r\n"));


	return 0;
}

late_initcall(init_device_info);

