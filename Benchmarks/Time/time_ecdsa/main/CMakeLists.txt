idf_component_register(SRCS "time_ecdsa.c"
                    INCLUDE_DIRS "."
                    REQUIRES 
                        idf::mbedtls
                        esp_hw_support
                        esp_rom
                        esp_system
                    PRIV_REQUIRES 
                        nvs_flash 
                        esp_wifi 
                        esp_http_server 
                        esp_netif 
                        esp_event 
                        esp_timer 
                        esp_pm 
                        spiffs 
                        vfs 
                        comm)