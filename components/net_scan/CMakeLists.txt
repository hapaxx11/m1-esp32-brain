idf_component_register(
    SRCS "net_scan.c"
    INCLUDE_DIRS "include"
    REQUIRES wifi_manager esp_netif lwip
)
