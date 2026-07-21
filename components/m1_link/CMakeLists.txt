idf_component_register(SRCS "m1_link.c"
                       INCLUDE_DIRS "include"
                       REQUIRES m1_rpc driver
                       PRIV_REQUIRES esp_common freertos)
