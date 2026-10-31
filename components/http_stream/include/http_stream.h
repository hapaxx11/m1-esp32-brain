#ifndef HTTP_STREAM_H
#define HTTP_STREAM_H

#include <stdint.h>
#include "m1_rpc.h"

void http_stream_open(const uint8_t *payload, uint16_t payload_len,
                      m1_rpc_http_open_resp_t *resp);
int http_stream_read(uint8_t *out, uint16_t out_size);
void http_stream_close(void);

#endif
