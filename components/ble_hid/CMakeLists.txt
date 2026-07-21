idf_component_register(SRCS "ble_hid.c" "ble_scan.c" "ble_conn.c"
                       INCLUDE_DIRS "include"
                       REQUIRES bt nvs_flash)
