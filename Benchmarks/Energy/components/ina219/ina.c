#include "ina.h"

#include <string.h>
#include <math.h>

#include "esp_log.h"

#define TAG "INA219"

#define REG_CONFIG        0x00
#define REG_SHUNT_V       0x01
#define REG_BUS_V         0x02
#define REG_POWER         0x03
#define REG_CURRENT       0x04
#define REG_CALIBRATION   0x05

static esp_err_t i2c_write16(
    ina219_t *dev,
    uint8_t reg,
    uint16_t value)
{
    uint8_t data[3];

    data[0] = reg;
    data[1] = (value >> 8) & 0xFF;
    data[2] = value & 0xFF;

    return i2c_master_write_to_device(
        dev->port,
        dev->addr,
        data,
        sizeof(data),
        pdMS_TO_TICKS(100)
    );
}

static esp_err_t i2c_read16(
    ina219_t *dev,
    uint8_t reg,
    uint16_t *value)
{
    uint8_t data[2];

    esp_err_t ret =
        i2c_master_write_read_device(
            dev->port,
            dev->addr,
            &reg,
            1,
            data,
            2,
            pdMS_TO_TICKS(100)
        );

    if (ret != ESP_OK)
        return ret;

    *value = ((uint16_t)data[0] << 8) | data[1];

    return ESP_OK;
}

esp_err_t ina219_set_config(
    ina219_t *dev)
{
    uint16_t config =
        (0x03 << 13) | // BRNG = 32V
        (0x03 << 11) | // PGA = /8
        (0x09 << 7)  | // BADC
        (0x09 << 3)  | // SADC
        (0x07);         // MODE

    return i2c_write16(dev, REG_CONFIG, config);
}

esp_err_t ina219_init(
    ina219_t *dev,
    const ina219_cfg_t *cfg)
{
    memset(dev, 0, sizeof(*dev));

    dev->port = cfg->port;
    dev->addr = cfg->i2c_addr;

    dev->shunt_ohms = cfg->shunt_ohms;

    if (cfg->install_driver) {

        i2c_config_t i2c_cfg = {
            .mode = I2C_MODE_MASTER,
            .sda_io_num = cfg->sda_io,
            .scl_io_num = cfg->scl_io,
            .sda_pullup_en = GPIO_PULLUP_ENABLE,
            .scl_pullup_en = GPIO_PULLUP_ENABLE,
            .master.clk_speed = cfg->clk_hz
        };

        ESP_ERROR_CHECK(
            i2c_param_config(cfg->port, &i2c_cfg)
        );

        ESP_ERROR_CHECK(
            i2c_driver_install(
                cfg->port,
                i2c_cfg.mode,
                0,
                0,
                0
            )
        );
    }

    dev->current_lsb_A =
        cfg->max_current_A / 32768.0f;

    dev->power_lsb_W =
        dev->current_lsb_A * 20.0f;

    uint16_t calib =
        (uint16_t)(
            0.04096f /
            (dev->current_lsb_A * cfg->shunt_ohms)
        );

    esp_err_t ret;

    ret = i2c_write16(dev, REG_CALIBRATION, calib);

    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "calibration failed");
        return ret;
    }

    ret = ina219_set_config(dev);

    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "config failed");
        return ret;
    }

    return ESP_OK;
}

esp_err_t ina219_read_bus_voltage_mv(
    ina219_t *dev,
    int32_t *mv)
{
    uint16_t r;

    esp_err_t ret;

    ret = i2c_read16(dev, REG_BUS_V, &r);

    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "read failed");
        return ret;
    }

    r >>= 3;

    *mv = (int32_t)r * 4;

    return ESP_OK;
}

esp_err_t ina219_read_shunt_voltage_uv(
    ina219_t *dev,
    int32_t *uv)
{
    uint16_t r;

    esp_err_t ret;

    ret = i2c_read16(dev, REG_BUS_V, &r);

    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "read failed");
        return ret;
    }

    int16_t s = (int16_t)r;

    *uv = (int32_t)s * 10;

    return ESP_OK;
}

esp_err_t ina219_read_current_ma(
    ina219_t *dev,
    int32_t *ma)
{
    uint16_t r;

    esp_err_t ret;

    ret = i2c_read16(dev, REG_BUS_V, &r);

    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "read failed");
        return ret;
    }

    int16_t s = (int16_t)r;

    float current_A =
        s * dev->current_lsb_A;

    *ma = (int32_t)
        lroundf(current_A * 1000.0f);

    return ESP_OK;
}

esp_err_t ina219_read_power_mw(
    ina219_t *dev,
    int32_t *mw)
{
    uint16_t r;

    esp_err_t ret;

    ret = i2c_read16(dev, REG_BUS_V, &r);

    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "read failed");
        return ret;
    }

    float power_W =
        r * dev->power_lsb_W;

    *mw = (int32_t)
        lroundf(power_W * 1000.0f);

    return ESP_OK;
}