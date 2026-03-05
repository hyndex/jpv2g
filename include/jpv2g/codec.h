/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct jpv2g_codec_ctx jpv2g_codec_ctx;

typedef int (*jpv2g_codec_encode_fn)(void *user,
                                       const void *msg,
                                       uint8_t *out,
                                       size_t out_len,
                                       size_t *written);

typedef int (*jpv2g_codec_decode_fn)(void *user,
                                       const uint8_t *buf,
                                       size_t len,
                                       void **msg_out);

int jpv2g_codec_init(jpv2g_codec_ctx **ctx);
void jpv2g_codec_free(jpv2g_codec_ctx *ctx);

/* Register external encode/decode hooks (e.g., libcbv2g bindings). */
int jpv2g_codec_set_hooks(jpv2g_codec_ctx *ctx,
                            jpv2g_codec_encode_fn encode_fn,
                            jpv2g_codec_decode_fn decode_fn,
                            void *user);

int jpv2g_encode_exi(jpv2g_codec_ctx *ctx,
                       const void *msg,
                       uint8_t *out,
                       size_t out_len,
                       size_t *written);

int jpv2g_decode_exi(jpv2g_codec_ctx *ctx,
                       const uint8_t *buf,
                       size_t len,
                       void **msg_out);
