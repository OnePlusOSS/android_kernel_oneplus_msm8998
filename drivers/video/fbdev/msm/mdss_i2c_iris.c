/* Copyright (c) 2015, Pixelworks, Inc.
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

#include <asm-generic/uaccess.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/debugfs.h>
#include <linux/i2c.h>
#include <linux/of.h>
#include <linux/printk.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/workqueue.h>
#include <linux/ktime.h>
#include "mdss_debug.h"
#include "mdss_i2c_iris.h"

#define IRIS_COMPATIBLE_NAME  "pixelworks,iris2"
#define IRIS_I2C_DRIVER_NAME  "iris2"

#define I2C_DBG_TAG      "iris_i2c "

#define IRIS_I2C_DBG
#ifdef IRIS_I2C_DBG
#define iris_i2c_dbg(fmt, args...)		pr_debug(I2C_DBG_TAG "[%s:%d]" fmt, __FUNCTION__, __LINE__, args)
#else
#define iris_i2c_dbg(fmt, args...)        do {}while(0)
#endif

#define MAX_READ_MSG_LEN      (MAX_ADDR_COMP_LEN << 1)
#define MAX_WRITE_MSG_LEN     MAX_ADDR_COMP_LEN
#define MAX_TRANSFER_MSG_LEN    31
//#define IRIS_I2C_USE_WORKQUEUE
/*
* pixelworks extend i2c
*/
enum {
	ONE_BYTE_REG_LEN = 0x04,
	TWO_BYTE_REG_LEN = 0x08,
	FOUR_BYTE_REG_LEN = 0x0c,
	ONE_BYTE_REG_LEN_READ = (MSMFB_IRIS_I2C_READ << 16) |ONE_BYTE_REG_LEN,
	TWO_BYTE_REG_LEN_READ = (MSMFB_IRIS_I2C_READ << 16) |TWO_BYTE_REG_LEN,
	FOUR_BYTE_REG_LEN_READ = (MSMFB_IRIS_I2C_READ << 16) |FOUR_BYTE_REG_LEN,
	ONE_BYTE_REG_LEN_WRITE = (MSMFB_IRIS_I2C_WRITE << 16) |ONE_BYTE_REG_LEN,
	TWO_BYTE_REG_LEN_WRITE = (MSMFB_IRIS_I2C_WRITE << 16) |TWO_BYTE_REG_LEN,
	FOUR_BYTE_REG_LEN_WRITE = (MSMFB_IRIS_I2C_WRITE << 16) |FOUR_BYTE_REG_LEN,
};

enum {
	DBG_I2C_READ = 0x01,
	DBG_I2C_WRITE,
};


/*iris i2c handle*/
static struct i2c_client  *iris_i2c_handle = NULL;
static int  dbg_i2c_flag = 0;

static int iris_i2c_rw_t(uint32_t type, struct addr_val *val, int len);

#ifdef IRIS_I2C_USE_WORKQUEUE
typedef struct iris_i2c_mgmt_t {
	uint32_t type;
	int  len;
	struct addr_val val[MAX_ADDR_COMP_LEN];
	struct work_struct i2c_work;
	struct workqueue_struct *i2c_wq;
} iris_i2c_mgmt;

static iris_i2c_mgmt   i2c_mgmt;
static void iris_i2c_work_func(struct work_struct *work)
{
	int ret = -1;
	ret = iris_i2c_rw_t(i2c_mgmt.type, i2c_mgmt.val, i2c_mgmt.len);
	if (ret != 0) {
		pr_err("read or write is not right \n");
	}
}

static void init_workqueue(void) {
	memset(&i2c_mgmt, 0x00, sizeof(i2c_mgmt));
	i2c_mgmt.i2c_wq = create_singlethread_workqueue("i2c_wq");
	if ( !i2c_mgmt.i2c_wq) {
		pr_err("could not create singlethread workqueue of i2c_wq \n");
		return;
	}

	INIT_WORK(&i2c_mgmt.i2c_work, iris_i2c_work_func);
}
#endif

int get_iris_i2c_flag(void)
{
	return dbg_i2c_flag;
}

static ssize_t iris_dbg_i2c_write(struct file *file, const char __user *buff,
	size_t count, loff_t *ppos)
{
	unsigned long val;

	if (kstrtoul_from_user(buff, count, 0, &val))
		return -EFAULT;

	dbg_i2c_flag = val;
	return count;
}


static ssize_t iris_dbg_i2c_read(struct file *file, char __user *buff,
		size_t count, loff_t *ppos)
{
	int len, tot = 0;
	char bp[512];

	if (*ppos)
		return 0;

	len = sizeof(bp);
	tot = scnprintf(bp, len, "dbg_i2c_flag = %d\n", dbg_i2c_flag);

	if (copy_to_user(buff, bp, tot))
		return -EFAULT;
	*ppos += tot;

	return tot;
}

static const struct file_operations iris_i2c_srw_fops = {
	.open = simple_open,
	.write = iris_dbg_i2c_write,
	.read = iris_dbg_i2c_read,
};

static int iris_i2c_debugfs_init(void)
{
	if (debugfs_create_file("iris_i2c_srw", 0644, NULL, NULL, &iris_i2c_srw_fops)
				== NULL) {
		pr_err("%s:%d""debugfs_create_file: index fail\n",
						__FILE__, __LINE__);
		return -EFAULT;
	}
	return 0;
}

static int iris_i2c_byte_read_t(uint8_t cmd, uint32_t reg_offset, uint32_t *read_buf)
{
	struct i2c_msg msgs[2];
	int ret = -1;
	int reg_len = 0;

	/* write data need cmd so need to add 0 to be comd**/
	uint8_t five_data[5] = {0,};
	uint8_t three_data[3] = {0,};
	uint8_t two_data[2] = {0,};

	uint8_t ret_one_data[1] = {0};
	uint8_t ret_four_data[4] ={0,};
	uint8_t ret_two_data[2] = {0,};

	struct i2c_client * client = iris_i2c_handle;
	uint8_t slave_addr = 0;
	uint8_t *data = NULL;
	uint8_t *ret_data = NULL;

	if (!client) {
		pr_err("iris i2c handle is NULL \n");
		return -EACCES;
	}

	slave_addr = (client->addr &0xff);
	memset(msgs, 0x00, sizeof(msgs)/sizeof(struct i2c_msg));

	iris_i2c_dbg("reading from slave_addr=[%x] and offset=[%x]\n",
		      slave_addr, reg_offset);

	switch (cmd &0x0c) {
		case ONE_BYTE_REG_LEN:
			reg_len = 2;
			two_data[0] = cmd;
			two_data[1] = (reg_offset & 0xff);
			data = two_data;
			ret_data = ret_one_data;
			break;
		case TWO_BYTE_REG_LEN:
			reg_len = 3;
			three_data[0] = cmd;
			three_data[1] = (reg_offset & 0xff);
			three_data[2] = ((reg_offset >> 8) & 0xff);
			data = three_data;
			ret_data = ret_two_data;
			break;
		case FOUR_BYTE_REG_LEN:
			reg_len = 5;
			five_data[0] = cmd;
			five_data[1] = (reg_offset & 0xff);
			five_data[2] = ((reg_offset >> 8) & 0xff);
			five_data[3] = ((reg_offset >> 16) & 0xff);
			five_data[4] = ((reg_offset >> 24) & 0xff);
			data = five_data;
			ret_data = ret_four_data;
			break;
	}

	if (data == NULL) {
		pr_err("the cmd is not right %d \n", cmd);
		return -EACCES;
	}

	msgs[0].addr = slave_addr;
	msgs[0].flags = 0;
	msgs[0].buf = data;
	msgs[0].len = reg_len;

	msgs[1].addr = slave_addr & 0xff;
	msgs[1].flags = I2C_M_RD;
	msgs[1].buf = ret_data;
	msgs[1].len = reg_len -1;

	ret = i2c_transfer(client->adapter, msgs, 2);
	if (ret < 1) {
		pr_err("%s: I2C READ FAILED=[%d]\n", __func__, ret);
		return -EACCES;
	}

	switch (cmd &0x0c) {
		case ONE_BYTE_REG_LEN:
			*read_buf = ret_data[0];
			break;
		case TWO_BYTE_REG_LEN:
			*read_buf = (ret_data[0] << 8) | ret_data[1];
			break;
		case FOUR_BYTE_REG_LEN:
			*read_buf = (ret_data[0] << 24) |(ret_data[1] << 16)
			                | (ret_data[2] << 8) | ret_data[3];
			break;
	}
	iris_i2c_dbg("i2c buf is [%x]\n",*read_buf);
	return 0;
}

int iris_i2c_byte_read(uint32_t reg_offset, uint32_t *read_buf)
{
    return iris_i2c_byte_read_t(0xcc, reg_offset, read_buf);
}

static int iris_i2c_read_transfer(
		struct i2c_adapter *adapter, struct i2c_msg *msgs, int len)
{
	int i = 0;
	int pos = 0;
	int ret = -1;

    for (i = 0; i < len; i++) {
	pos = i << 1;
		ret = i2c_transfer(adapter, &msgs[pos], 2);
		if (ret < 1) {
			pr_err("%s: I2C READ FAILED=[%d]\n", __func__, ret);
			return -EACCES;
		}
    }
    return 0;
}

#if 0
static int iris_i2c_cmd_one_read(struct addr_val * val, int len)
{
	int i = 0;
	int ret = -1;
	const int reg_len = 2;
	const int ret_len = 1;
	uint8_t cmd = 0x44;
	int pos = 0;
	uint8_t slave_addr = 0;
	uint8_t * ret_data = NULL;
	uint8_t * data = NULL;
	uint8_t three_data_list[(3 * MAX_READ_MSG_LEN) >>1] = {0,};

	struct i2c_msg msgs[MAX_READ_MSG_LEN];
	struct i2c_client * client = iris_i2c_handle;

	slave_addr = (client->addr &0xff);
	memset(msgs, 0x00, sizeof(msgs));

	for (i = 0; i < len; i++) {
		pos = 3 *i;
		three_data_list[pos] = cmd;
		three_data_list[pos + 1] = (val[i].addr & 0xff);
		data = &three_data_list[pos];
		ret_data = &data[pos + reg_len];

		pos = i << 1;
		msgs[pos].addr = slave_addr;
		msgs[pos].flags = 0;
		msgs[pos].buf = data;
		msgs[pos].len = reg_len;

		msgs[pos + 1].addr = slave_addr;
		msgs[pos + 1].flags = I2C_M_RD;
		msgs[pos + 1].buf = ret_data;
		msgs[pos + 1].len = ret_len;
	}

	ret = iris_i2c_read_transfer(client->adapter, msgs, len);
	if (ret != 0) {
		return ret;
	}

	for (i = 0; i < len; i++) {
		pos = i * 3 + 2;
		val[i].data = data[pos] ;
	}
	return 0;
}

static int iris_i2c_cmd_two_read(struct addr_val * val, int len)
{
	int i = 0;
	int ret = -1;
	const int reg_len = 3;
	const int ret_len = 2;
	int pos = 0;
	uint8_t cmd = 0x88;
	uint8_t slave_addr = 0;
	uint8_t * ret_data = NULL;
	uint8_t * data = NULL;

	uint8_t five_data_list[(5 * MAX_READ_MSG_LEN) >>1] = {0,};

	struct i2c_msg msgs[MAX_READ_MSG_LEN];
	struct i2c_client * client = iris_i2c_handle;

	slave_addr = (client->addr &0xff);
	memset(msgs, 0x00, sizeof(msgs));

	for (i = 0; i < len; i++) {
		pos = 5 * i;

		five_data_list[pos] = cmd;
		five_data_list[pos + 1] = (val[i].addr & 0xff);
		five_data_list[pos + 2] = ((val[i].addr >> 8) & 0xff);
		data = &five_data_list[pos];
		ret_data = &five_data_list[pos +reg_len];

		pos = i << 1;
		msgs[pos].addr = slave_addr;
		msgs[pos].flags = 0;
		msgs[pos].buf = data;
		msgs[pos].len = reg_len;

		msgs[pos + 1].addr = slave_addr;
		msgs[pos + 1].flags = I2C_M_RD;
		msgs[pos + 1].buf = ret_data;
		msgs[pos + 1].len = ret_len;
	}

	ret = iris_i2c_read_transfer(client->adapter, msgs, len);
	if (ret != 0) {
		return ret;
	}

	for (i = 0; i < len; i++) {
		pos = i * 5 + 3;
		pos = (i << 1);
		val[i].data = (five_data_list[pos] << 8) | five_data_list[1 + pos];
	}
	return 0;
}
#endif

static int iris_i2c_cmd_four_read(struct addr_val * val, int len)
{
	int i = 0;
	int ret = -1;
	int pos = 0;
	const int reg_len = 5;
	const int ret_len = 4;
	uint8_t cmd = 0xcc;
	uint8_t slave_addr = 0;
	uint8_t *data = NULL;
	uint8_t * ret_data = NULL;

	/*for ret value need to be N * len
		 * N is cmd + val+ ret (1+1+1,1+2+2,1+4+4)*/
	uint8_t nine_data_list[(9 * MAX_READ_MSG_LEN) >>1] = {0,};

	struct i2c_msg msgs[MAX_READ_MSG_LEN];
	struct i2c_client * client = iris_i2c_handle;

	slave_addr = (client->addr &0xff);
	memset(msgs, 0x00, sizeof(msgs));

	for (i = 0; i < len; i++) {
		pos = 9 * i;
		nine_data_list[pos] = cmd;
		nine_data_list[pos + 1] = (val[i].addr & 0xff);
		nine_data_list[pos + 2] = ((val[i].addr >> 8) & 0xff);
		nine_data_list[pos + 3] = ((val[i].addr >> 16) & 0xff);
		nine_data_list[pos + 4] = ((val[i].addr >> 24) & 0xff);
		data = &nine_data_list[pos];
		ret_data = &nine_data_list[pos + reg_len];

		pos = i << 1;
		msgs[pos].addr = slave_addr;
		msgs[pos].flags = 0;
		msgs[pos].buf = data;
		msgs[pos].len = reg_len;

		msgs[pos + 1].addr = slave_addr;
		msgs[pos + 1].flags = I2C_M_RD;
		msgs[pos + 1].buf = ret_data;
		msgs[pos + 1].len = ret_len;
	}

	ret = iris_i2c_read_transfer(client->adapter, msgs, len);
	if (ret != 0) {
		return ret;
	}

	for (i = 0; i < len; i++) {
		pos = 9 * i + 5;
		val[i].data = (nine_data_list[pos] << 24) |(nine_data_list[pos + 1] << 16)
						| (nine_data_list[pos + 2] << 8) | nine_data_list[pos + 3];
	}

	return 0;
}

static int iris_i2c_byte_write_t(uint8_t cmd, uint32_t reg_offset,  uint32_t value)
{
	struct i2c_msg msgs[1];

	/* write data need cmd so need to add 0 to be comd**/
	uint8_t nine_data[9] = {0,};
	uint8_t five_data[5] = {0,};
	uint8_t three_data[3] ={0,};

	uint8_t *data = NULL;
	int status = -EACCES;
	int reg_len = 0;
	struct i2c_client * client = iris_i2c_handle;
	uint8_t slave_addr = 0;

	if (!client) {
		pr_err("iris i2c handle is NULL \n");
		return -EACCES;
	}

	slave_addr = (client->addr & 0xff);
	memset(msgs, 0x00, sizeof(msgs)/sizeof(struct i2c_msg));

	iris_i2c_dbg("writing from slave_addr=[%x] and offset=[%x] val = [%x]\n",
		 slave_addr, reg_offset, value);

	switch (cmd &0x0c) {
		case ONE_BYTE_REG_LEN:
			reg_len = 3;
			three_data[0] = cmd;
			three_data[1] = (reg_offset & 0xff);
			three_data[2] = (value & 0xff);
			data = three_data;
			break;
		case TWO_BYTE_REG_LEN:
			reg_len = 5;
			five_data[0] = cmd;
			five_data[1] = (reg_offset &0xff);
			five_data[2] = ((reg_offset >>8) & 0xff);
			/*data and address in reverse direction */
			five_data[3] = (value & 0xff);
			five_data[4] = ((value >> 8) & 0xff);
			data = five_data;
			break;
		case FOUR_BYTE_REG_LEN:
			reg_len = 9;
			nine_data[0] = cmd;
			nine_data[1] = (reg_offset & 0xff);
			nine_data[2] = ((reg_offset >> 8) & 0xff);
			nine_data[3] = ((reg_offset >> 16) & 0xff);
			nine_data[4] = ((reg_offset >> 24) & 0xff);
			nine_data[5] = ((value >> 24) &0xff);
			nine_data[6] = ((value >> 16) &0xff);
			nine_data[7] = ((value >> 8) &0xff);
			nine_data[8] = (value & 0xff);
			data = nine_data;
			break;
	}

	if (data == NULL) {
		pr_err("cmd is not all right %x\n", cmd );
		return -EACCES;
	}

	msgs[0].addr = slave_addr;
	msgs[0].flags = 0;
	msgs[0].len = reg_len;
	msgs[0].buf = data;

	status = i2c_transfer(client->adapter, msgs, 1);
	if (status < 1) {
		pr_err("I2C WRITE FAILED=[%d]\n", status);
		return -EACCES;
	}
	iris_i2c_dbg("I2C write status=%x\n", status);

	return status;
}


int iris_i2c_byte_write(uint32_t reg_offset,  uint32_t value)
{
	uint8_t cmd = 0xcc;
	return iris_i2c_byte_write_t(cmd, reg_offset, value);
}

static int iris_i2c_cmd_four_write(struct addr_val * val, int len)
{
	int i = 0;
	int ret = -1;
	int pos = 0;
	const int reg_len = 9;
	const uint8_t cmd = 0xcc;
	uint8_t slave_addr = 0;
	uint8_t *data = NULL;
	int32_t mult_val = 0;
	int32_t pos_val = 0;
	//uint8_t trace_cmd[128] = {0,};
	//int func_name_len;

	/*for ret value need to be N * len
		 * N is cmd + addr+ val (1+1+1,1+2+2,1+4+4)*/
	uint8_t nine_data_list[9 * MAX_WRITE_MSG_LEN] = {0,};

	struct i2c_msg msgs[MAX_WRITE_MSG_LEN];
	struct i2c_client * client = iris_i2c_handle;

	slave_addr = (client->addr &0xff);
	memset(msgs, 0x00, sizeof(msgs));

	for (i = 0; i < len; i++) {
		pos = reg_len * i;
		nine_data_list[pos] = cmd;
		nine_data_list[pos + 1] = (val[i].addr & 0xff);
		nine_data_list[pos + 2] = ((val[i].addr >> 8) & 0xff);
		nine_data_list[pos + 3] = ((val[i].addr >> 16) & 0xff);
		nine_data_list[pos + 4] = ((val[i].addr >> 24) & 0xff);
		nine_data_list[pos + 5] = ((val[i].data >> 24) &0xff);
		nine_data_list[pos + 6] = ((val[i].data >> 16) &0xff);
		nine_data_list[pos + 7] = ((val[i].data >> 8) &0xff);
		nine_data_list[pos + 8] = (val[i].data & 0xff);

		data = &nine_data_list[pos];

		msgs[i].addr = slave_addr;
		msgs[i].flags = 0;
		msgs[i].buf = data;
		msgs[i].len = reg_len;
	}

	//func_name_len = sprintf(trace_cmd, "%s_", __func__ );
	//sprintf(&trace_cmd[func_name_len], "%d", len );
	//ATRACE_BEGIN(trace_cmd);

	/*according to I2C_MSM_BAM_CONS_SZ in i2c_msm_v2.h
	the write msg should be less than 32 */
	if (len <= MAX_TRANSFER_MSG_LEN) {
		ret = i2c_transfer(client->adapter, msgs, len);
		if (ret < 1) {
			return ret;
		}
	} else {
		mult_val = (len / MAX_TRANSFER_MSG_LEN);
		pos_val = len - (mult_val * MAX_TRANSFER_MSG_LEN);
		for (i = 0; i < mult_val; i++) {
			ret = i2c_transfer(client->adapter,
					&msgs[i * MAX_TRANSFER_MSG_LEN], MAX_TRANSFER_MSG_LEN);
			if (ret < 1) {
				return ret;
			}
		}

		ret = i2c_transfer(client->adapter,
				&msgs[i * MAX_TRANSFER_MSG_LEN], pos_val);
		if (ret < 1) {
			return ret;
		}
	}

	//ATRACE_END(trace_cmd);
	return 0;
}

static int iris_i2c_rw_t(uint32_t type, struct addr_val *val, int len)
{
	int ret = -1;

	switch (type) {
#if 0
		case ONE_BYTE_REG_LEN_READ:
			ret = iris_i2c_cmd_one_read(val, len);
			break;
		case TWO_BYTE_REG_LEN_READ:
			ret = iris_i2c_cmd_two_read(val, len);
			break;
#endif
		case FOUR_BYTE_REG_LEN_READ:
			ret = iris_i2c_cmd_four_read(val, len);
			break;
		case FOUR_BYTE_REG_LEN_WRITE:
			ret = iris_i2c_cmd_four_write(val, len);
			break;
		default:
			pr_err("can not identify the cmd = %x\n", type);
			return -EINVAL;
	}
	return ret;
}

/*currently we use four byte*/
static int iris_i2c_rw(uint32_t type, struct addr_val *val, int len)
{
	struct i2c_client * client = iris_i2c_handle;

	if (!client) {
		pr_err("iris i2c handle is NULL \n");
		return -EACCES;
	}

	if (!val || len == 0) {
		pr_err("the return buf = %p or len = %d \n",
				val, len);
		return -EINVAL;
	}

	if (MSMFB_IRIS_I2C_READ == ((type >> 16)& 0xffff)
			&& len > MAX_READ_MSG_LEN){
		pr_err("the len is two long for read len = %d "
				"MAX_READ_MSG_LEN = %d \n", len, MAX_READ_MSG_LEN);
		return -EINVAL;
	} else if (MSMFB_IRIS_I2C_WRITE == ((type >> 16)& 0xffff)
		&& len > MAX_WRITE_MSG_LEN) {
			pr_err("the len is two long for read len = %d "
					"MAX_READ_MSG_LEN = %d \n", len, MAX_WRITE_MSG_LEN);
		return -EINVAL;
	}
#ifdef IRIS_I2C_USE_WORKQUEUE
	if (MSMFB_IRIS_I2C_READ == ((type >> 16)& 0xffff)) {
		return iris_i2c_rw_t(type, val, len);
	} else {
		//val is local variable should not be call
		memcpy(i2c_mgmt.val, val, len * sizeof(i2c_mgmt.val[0]));
		i2c_mgmt.len = len;
		i2c_mgmt.type = type;
		queue_work(i2c_mgmt.i2c_wq, &i2c_mgmt.i2c_work);
		return 0;
	}
#else
	return iris_i2c_rw_t(type, val, len);
#endif
}

/**now we support four byte read and write*/
int iris_i2c_read(struct addr_val *val, int len) {
	return iris_i2c_rw(FOUR_BYTE_REG_LEN_READ, val, len);
}

int iris_i2c_write(struct addr_val *val, int len) {
	return iris_i2c_rw(FOUR_BYTE_REG_LEN_WRITE, val, len);
}

static int iris_i2c_probe(struct i2c_client *client,
		const struct i2c_device_id *dev_id)
{
	iris_i2c_handle = client;
	return 0;
}

static int iris_i2c_remove(struct i2c_client *client)
{
	iris_i2c_handle = NULL;
	return 0;
}

static const struct i2c_device_id iris_i2c_id_table[] = {
	{IRIS_I2C_DRIVER_NAME, 0},
	{},
};


static struct of_device_id iris_match_table[] = {
	{.compatible = IRIS_COMPATIBLE_NAME,},
	{ },
};

static struct i2c_driver plx_i2c_driver = {
	.driver = {
		.name = IRIS_I2C_DRIVER_NAME,
		.owner = THIS_MODULE,
		.of_match_table = iris_match_table,
	},
	.probe = iris_i2c_probe,
	.remove =  iris_i2c_remove,
	.id_table = iris_i2c_id_table,
};


int iris_i2c_bus_init(void)
{
	i2c_add_driver(&plx_i2c_driver);
	iris_i2c_debugfs_init();
#ifdef IRIS_I2C_USE_WORKQUEUE
	init_workqueue();
#endif
	return 0;
}

void iris_i2c_bus_exit(void)
{
	i2c_del_driver(&plx_i2c_driver);
	iris_i2c_remove(iris_i2c_handle);
#ifdef IRIS_I2C_USE_WORKQUEUE
	destroy_workqueue(i2c_mgmt.i2c_wq);
#endif
	return;
}
