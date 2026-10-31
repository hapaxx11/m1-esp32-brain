#include "http_stream.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "esp_http_client.h"
#include "lwip/netdb.h"

#define HTTP_STREAM_MAX_REDIRECTS 3
#define HTTP_STREAM_URL_MAX       1024u

static esp_http_client_handle_t s_client;

static void http_stream_set_error(m1_rpc_http_open_resp_t *resp,
                                  m1_rpc_http_result_t result)
{
    resp->result = (uint8_t)result;
    resp->http_status = 0;
    resp->content_length = -1;
}

static m1_rpc_http_result_t http_stream_error_result(esp_http_client_handle_t client,
                                                      esp_err_t err)
{
    if (err == ESP_ERR_HTTP_EAGAIN || err == ESP_ERR_TIMEOUT)
        return M1_RPC_HTTP_RESULT_TIMEOUT;
    if (err == ESP_ERR_NO_MEM)
        return M1_RPC_HTTP_RESULT_NO_MEM;
    if (err == ESP_ERR_HTTP_MAX_REDIRECT)
        return M1_RPC_HTTP_RESULT_REDIRECT;

    int socket_err = client ? esp_http_client_get_errno(client) : 0;
    if (socket_err == EAI_AGAIN || socket_err == EAI_FAIL || socket_err == EAI_NONAME)
        return M1_RPC_HTTP_RESULT_DNS;
    if (socket_err == ETIMEDOUT || socket_err == EAGAIN || socket_err == EWOULDBLOCK)
        return M1_RPC_HTTP_RESULT_TIMEOUT;
    return M1_RPC_HTTP_RESULT_CONNECT;
}

void http_stream_close(void)
{
    if (!s_client)
        return;
    esp_http_client_close(s_client);
    esp_http_client_cleanup(s_client);
    s_client = NULL;
}

void http_stream_open(const uint8_t *payload, uint16_t payload_len,
                      m1_rpc_http_open_resp_t *resp)
{
    char *url = NULL;
    esp_err_t err = ESP_FAIL;

    http_stream_close();
    http_stream_set_error(resp, M1_RPC_HTTP_RESULT_CONNECT);

    if (!payload || payload_len < 7u) {
        http_stream_set_error(resp, M1_RPC_HTTP_RESULT_INVALID);
        return;
    }

    uint32_t timeout_ms = (uint32_t)payload[1] |
                          ((uint32_t)payload[2] << 8u) |
                          ((uint32_t)payload[3] << 16u) |
                          ((uint32_t)payload[4] << 24u);
    uint16_t url_len = (uint16_t)payload[5] | ((uint16_t)payload[6] << 8u);
    if (url_len == 0u || url_len > HTTP_STREAM_URL_MAX ||
        payload_len != (uint16_t)(7u + url_len) ||
        (payload[0] != M1_RPC_HTTP_ACCEPT_JSON && payload[0] != M1_RPC_HTTP_ACCEPT_BINARY) ||
        timeout_ms < 1000u || timeout_ms > 120000u) {
        http_stream_set_error(resp, M1_RPC_HTTP_RESULT_INVALID);
        return;
    }

    url = malloc((size_t)url_len + 1u);
    if (!url) {
        http_stream_set_error(resp, M1_RPC_HTTP_RESULT_NO_MEM);
        return;
    }
    memcpy(url, &payload[7], url_len);
    url[url_len] = '\0';

    esp_http_client_config_t config = {
        .url = url,
        .method = HTTP_METHOD_GET,
        .timeout_ms = (int)timeout_ms,
        .max_redirection_count = HTTP_STREAM_MAX_REDIRECTS,
        .user_agent = "M1-Hapax/1.0",
        .buffer_size = 1024,
        .buffer_size_tx = 512,
    };
    s_client = esp_http_client_init(&config);
    free(url);
    if (!s_client) {
        http_stream_set_error(resp, M1_RPC_HTTP_RESULT_NO_MEM);
        return;
    }

    esp_http_client_set_header(s_client, "Accept",
        payload[0] == M1_RPC_HTTP_ACCEPT_JSON ? "application/json" : "*/*");
    esp_http_client_set_header(s_client, "Connection", "close");

    for (int redirects = 0; redirects <= HTTP_STREAM_MAX_REDIRECTS; redirects++) {
        err = esp_http_client_open(s_client, 0);
        if (err != ESP_OK)
            break;

        int64_t fetched = esp_http_client_fetch_headers(s_client);
        if (fetched < 0) {
            err = fetched == -ESP_ERR_HTTP_EAGAIN ? ESP_ERR_HTTP_EAGAIN : ESP_ERR_HTTP_FETCH_HEADER;
            break;
        }

        int status = esp_http_client_get_status_code(s_client);
        if (status != HttpStatus_MovedPermanently && status != HttpStatus_Found &&
            status != HttpStatus_SeeOther && status != HttpStatus_TemporaryRedirect &&
            status != HttpStatus_PermanentRedirect) {
            resp->result = M1_RPC_HTTP_RESULT_OK;
            resp->http_status = (uint16_t)status;
            int64_t length = esp_http_client_get_content_length(s_client);
            resp->content_length = (length >= 0 && length <= INT32_MAX) ? (int32_t)length : -1;
            return;
        }

        if (redirects == HTTP_STREAM_MAX_REDIRECTS) {
            err = ESP_ERR_HTTP_MAX_REDIRECT;
            break;
        }
        err = esp_http_client_set_redirection(s_client);
        if (err != ESP_OK)
            break;
        esp_http_client_close(s_client);
    }

    http_stream_set_error(resp, http_stream_error_result(s_client, err));
    http_stream_close();
}

int http_stream_read(uint8_t *out, uint16_t out_size)
{
    if (!s_client || !out || out_size == 0u)
        return -ESP_ERR_INVALID_ARG;
    return esp_http_client_read(s_client, (char *)out, out_size);
}
