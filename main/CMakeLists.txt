idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES m1_link rpc_server wifi_manager wifi_attack m1_rpc ble_hid esp_wifi ieee802154_sniff esp_netif esp_now_link
    PRIV_REQUIRES esp_app_format esp_system
)
