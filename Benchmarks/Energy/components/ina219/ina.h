#ifndef INA219_H
#define INA219_H

#include <stdint.h>
#include <stdbool.h>

#include "esp_err.h"
#include "driver/i2c.h"

typedef struct {
    i2c_port_t port;
    gpio_num_t sda_io;
    gpio_num_t scl_io;
    uint32_t clk_hz;

    uint8_t i2c_addr;

    float shunt_ohms;
    float max_current_A;

    bool install_driver;
} ina219_cfg_t;

typedef struct {
    i2c_port_t port;
    uint8_t addr;

    float current_lsb_A;
    float power_lsb_W;

    float shunt_ohms;
} ina219_t;

esp_err_t ina219_init(
    ina219_t *dev,
    const ina219_cfg_t *cfg
);

esp_err_t ina219_set_config(
    ina219_t *dev
);

esp_err_t ina219_read_bus_voltage_mv(
    ina219_t *dev,
    int32_t *mv
);

esp_err_t ina219_read_shunt_voltage_uv(
    ina219_t *dev,
    int32_t *uv
);

esp_err_t ina219_read_current_ma(
    ina219_t *dev,
    int32_t *ma
);

esp_err_t ina219_read_power_mw(
    ina219_t *dev,
    int32_t *mw
);

#endif