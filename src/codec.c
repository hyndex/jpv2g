/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#include "jpv2g/codec.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "jpv2g/log.h"
#include "jpv2g/raw_exi.h"

struct jpv2g_codec_ctx {
    jpv2g_codec_encode_fn encode_fn;
    jpv2g_codec_decode_fn decode_fn;
    void *user;
};

int jpv2g_codec_init(jpv2g_codec_ctx **ctx) {
    if (!ctx) return -EINVAL;
    *ctx = (jpv2g_codec_ctx *)calloc(1, sizeof(jpv2g_codec_ctx));
    if (!*ctx) return -ENOMEM;
    return 0;
}

void jpv2g_codec_free(jpv2g_codec_ctx *ctx) {
    free(ctx);
}

int jpv2g_codec_set_hooks(jpv2g_codec_ctx *ctx,
                            jpv2g_codec_encode_fn encode_fn,
                            jpv2g_codec_decode_fn decode_fn,
                            void *user) {
    if (!ctx || !encode_fn || !decode_fn) return -EINVAL;
    ctx->encode_fn = encode_fn;
    ctx->decode_fn = decode_fn;
    ctx->user = user;
    return 0;
}

int jpv2g_encode_exi(jpv2g_codec_ctx *ctx,
                       const void *msg,
                       uint8_t *out,
                       size_t out_len,
                       size_t *written) {
    if (!ctx || !msg || !out) return -EINVAL;
    if (ctx->encode_fn) {
        return ctx->encode_fn(ctx->user, msg, out, out_len, written);
    }
    /* Fallback: raw EXI passthrough when msg is jpv2g_raw_exi_t */
    const jpv2g_raw_exi_t *raw = (const jpv2g_raw_exi_t *)msg;
    if (raw->len > out_len) return -ENOSPC;
    memcpy(out, raw->data, raw->len);
    if (written) *written = raw->len;
    return 0;
}

int jpv2g_decode_exi(jpv2g_codec_ctx *ctx,
                       const uint8_t *buf,
                       size_t len,
                       void **msg_out) {
    if (!ctx || !buf || !msg_out) return -EINVAL;
    if (ctx->decode_fn) {
        return ctx->decode_fn(ctx->user, buf, len, msg_out);
    }
    /* Fallback: allocate and return raw EXI wrapper */
    jpv2g_raw_exi_t *raw = (jpv2g_raw_exi_t *)calloc(1, sizeof(jpv2g_raw_exi_t));
    if (!raw) return -ENOMEM;
    raw->data = buf;
    raw->len = len;
    *msg_out = raw;
    return 0;
}
