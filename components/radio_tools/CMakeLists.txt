idf_component_register(
    SRCS "wifi_wps.c" "wifi_channel_monitor.c" "wifi_csi.c"
    INCLUDE_DIRS "include"
    REQUIRES wifi_manager esp_wifi esp_netif lwip esp_timer
)
