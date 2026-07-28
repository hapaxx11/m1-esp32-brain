idf_component_register(SRCS "ble_hid.c" "ble_scan.c" "ble_conn.c" "ble_spam.c" "ble_nus.c"
                       INCLUDE_DIRS "include"
                       REQUIRES bt nvs_flash esp_hw_support rpc_server wifi_manager)
