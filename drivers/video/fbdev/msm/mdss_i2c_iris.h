#ifndef MDSS_I2C_IRIS_H
#define MDSS_I2C_IRIS_H

#include <linux/i2c.h>
#include <linux/of.h>
#include <linux/msm_mdp.h>

int iris_i2c_byte_read(uint32_t reg_offset, uint32_t *read_buf);
int iris_i2c_byte_write(uint32_t reg_offset,  uint32_t value);
int iris_i2c_read(struct addr_val *val, int len);
int iris_i2c_write(struct addr_val *val, int len);
int iris_i2c_bus_init(void);
void iris_i2c_bus_exit(void);
int get_iris_i2c_flag(void);

#endif
