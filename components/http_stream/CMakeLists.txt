idf_component_register(
    SRCS "http_stream.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_http_client m1_rpc
)
