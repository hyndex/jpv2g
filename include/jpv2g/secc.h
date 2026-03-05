/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "jpv2g/config.h"
#include "jpv2g/codec.h"
#include "jpv2g/messages.h"
#include "jpv2g/backend.h"
#include "jpv2g/evse_controller.h"
#include "jpv2g/transport.h"
#include "jpv2g/tls.h"
#include "jpv2g/types.h"
#include "jpv2g/v2gtp.h"

struct iso2_MessageHeaderType;
struct din_MessageHeaderType;

typedef struct {
    jpv2g_protocol_t protocol;
    const struct iso2_MessageHeaderType *header;     /* ISO 15118 header (if applicable) */
    const struct din_MessageHeaderType *din_header;  /* DIN 70121 header (if applicable) */
    const void *body;                                /* Decoded request body */
} jpv2g_secc_request_t;

typedef struct {
    jpv2g_secc_config_t cfg;
    jpv2g_codec_ctx *codec;
    jpv2g_udp_server_t udp;
    jpv2g_tcp_server_t tcp;
    jpv2g_tcp_server_t tls; /* placeholder for TLS; shares structure */
    jpv2g_backend_t backend;
    jpv2g_evse_controller_t evse_ctl;
    uint8_t session_id[8];
    int64_t meter_Wh;
    char meter_id[16];
    /* Callbacks to build responses based on decoded requests. */
    int (*handle_request)(jpv2g_message_type_t type, const void *decoded, uint8_t *out, size_t out_len, size_t *written, void *user_ctx);
    void *user_ctx;
} jpv2g_secc_t;

int jpv2g_secc_init(jpv2g_secc_t *secc, const jpv2g_secc_config_t *cfg, jpv2g_codec_ctx *codec);
int jpv2g_secc_start_udp(jpv2g_secc_t *secc);
int jpv2g_secc_start_tcp(jpv2g_secc_t *secc);
int jpv2g_secc_start_tls(jpv2g_secc_t *secc);
void jpv2g_secc_stop(jpv2g_secc_t *secc);

/* Handle a single TCP client connection (plaintext). */
int jpv2g_secc_handle_client(jpv2g_secc_t *secc, int client_fd, int timeout_ms);
/* Handle a single TLS client connection (wraps TLS then processes messages). */
int jpv2g_secc_handle_client_tls(jpv2g_secc_t *secc,
                                   int client_fd,
                                   const char *cert_path,
                                   const char *key_path,
                                   const char *ca_path,
                                   int timeout_ms);
/* Peek first bytes and route to TLS/plain automatically; waits for first data up to first_timeout_ms. */
int jpv2g_secc_handle_client_detect(jpv2g_secc_t *secc,
                                      int client_fd,
                                      int first_timeout_ms,
                                      int timeout_ms);

/* Enable/disable verbose decoded request/response logs (enabled by default). */
void jpv2g_secc_set_decoded_logs(bool enable);
bool jpv2g_secc_get_decoded_logs(void);

/* Default response builder (ISO/DIN) usable by custom handlers and tests. */
int jpv2g_secc_default_handle(jpv2g_secc_t *secc,
                                jpv2g_message_type_t type,
                                const jpv2g_secc_request_t *req,
                                uint8_t *out,
                                size_t out_len,
                                size_t *written);
