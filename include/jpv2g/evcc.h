/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "jpv2g/codec.h"
#include "jpv2g/config.h"
#include "jpv2g/discovery.h"
#include "jpv2g/messages.h"
#include "jpv2g/tls.h"
#include "jpv2g/transport.h"
#include "jpv2g/v2gtp.h"

typedef struct {
    jpv2g_evcc_config_t cfg;
    jpv2g_codec_ctx *codec;
    jpv2g_discovery_result_t discovery;
    jpv2g_tcp_client_t tcp;
    jpv2g_tls_socket_t tls;
    bool tls_enabled;
    uint8_t session_id[8];
    /* Optional callbacks to build outgoing messages and process incoming decoded messages. */
    int (*build_message)(jpv2g_message_type_t type, void *user_ctx, uint8_t *out, size_t out_len, size_t *written);
    int (*handle_message)(jpv2g_message_type_t type, const void *decoded, void *user_ctx);
    void *user_ctx;
} jpv2g_evcc_t;

int jpv2g_evcc_init(jpv2g_evcc_t *evcc, const jpv2g_evcc_config_t *cfg, jpv2g_codec_ctx *codec);
int jpv2g_evcc_discover(jpv2g_evcc_t *evcc);
int jpv2g_evcc_connect(jpv2g_evcc_t *evcc);
int jpv2g_evcc_send_v2gtp(jpv2g_evcc_t *evcc, jpv2g_payload_type_t type, const uint8_t *payload, size_t payload_len);
int jpv2g_evcc_recv_v2gtp(jpv2g_evcc_t *evcc, uint8_t *buf, size_t buf_len, jpv2g_v2gtp_t *out, int timeout_ms);
void jpv2g_evcc_close(jpv2g_evcc_t *evcc);

/* Convenience: send a supported app protocol request and wait for response using codec hooks. */
int jpv2g_evcc_handshake_app_protocol(jpv2g_evcc_t *evcc, int timeout_ms);

/* Generic EXI exchange: build, send, receive, decode, and handle. */
int jpv2g_evcc_exchange(jpv2g_evcc_t *evcc,
                          jpv2g_message_type_t req_type,
                          jpv2g_message_type_t res_type,
                          int timeout_ms);
