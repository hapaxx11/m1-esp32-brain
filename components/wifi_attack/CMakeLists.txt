idf_component_register(
    SRCS "wifi_attack.c" "wifi_sta_scan.c" "wifi_handshake.c"
    INCLUDE_DIRS "include"
    REQUIRES wifi_manager esp_wifi esp_http_server esp_netif lwip
)
