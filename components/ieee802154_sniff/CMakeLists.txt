idf_component_register(
    SRCS "ieee802154_sniff.c"
    INCLUDE_DIRS "include"
    REQUIRES ieee802154 m1_rpc esp_phy
)
