/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#include "jpv2g/cbv2g_adapter.h"

#include <errno.h>

int cbv2g_encode(const void *msg, uint8_t *out, size_t out_len, size_t *written);
int cbv2g_decode(const uint8_t *buf, size_t len, void **out);

/* Provide weak defaults that fail fast if libcbv2g is not linked in. */
__attribute__((weak)) int cbv2g_encode(const void *msg, uint8_t *out, size_t out_len, size_t *written) {
    (void)msg;
    (void)out;
    (void)out_len;
    if (written) *written = 0;
    return -ENOSYS;
}

__attribute__((weak)) int cbv2g_decode(const uint8_t *buf, size_t len, void **out) {
    (void)buf;
    (void)len;
    (void)out;
    return -ENOSYS;
}

static int adapter_encode(void *user, const void *msg, uint8_t *out, size_t out_len, size_t *written) {
    (void)user;
    return cbv2g_encode(msg, out, out_len, written);
}

static int adapter_decode(void *user, const uint8_t *buf, size_t len, void **out) {
    (void)user;
    return cbv2g_decode(buf, len, out);
}

int jpv2g_codec_use_cbv2g(jpv2g_codec_ctx *ctx) {
    if (!ctx) return -EINVAL;
    return jpv2g_codec_set_hooks(ctx, adapter_encode, adapter_decode, NULL);
}
