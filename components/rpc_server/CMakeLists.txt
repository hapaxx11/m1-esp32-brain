idf_component_register(
    SRCS "rpc_server.c"
    INCLUDE_DIRS "include"
    REQUIRES lwip m1_rpc wifi_manager
)
