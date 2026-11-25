idf_component_register(SRCS "uart.c"
                       INCLUDE_DIRS "includes"
                       REQUIRES esp_driver_uart esp_driver_gpio hal mbedtls
                       PRIV_REQUIRES esp_rom)