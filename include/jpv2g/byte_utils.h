/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

/*
 * A V2GTP payload carries exactly one EXI-encoded V2G message, and this stack's
 * encode/decode scratch buffer is JPV2G_MAX_EXI_SIZE (4096 B, jpv2g/constants.h)
 * — nothing larger can ever be legitimately produced or consumed. The previous
 * value (UINT32_MAX) made every `payload_length > JPV2G_MAX_PAYLOAD_LENGTH`
 * guard a dead no-op: because payload_length is a uint32_t, it can never exceed
 * UINT32_MAX. Worse, the un-bounded length then flowed into
 * `JPV2G_V2GTP_HEADER_LEN + payload_length` (secc.c/evcc.c). On the 32-bit
 * ESP32-S3 target that size_t addition wraps for a length field in
 * 0xFFFFFFF8..0xFFFFFFFF, collapsing the total to 0..7 and defeating the
 * downstream `total > buf_len` bound — so a peer on the CCS PLC link could drive
 * a read of ~4 GB into a ~4 KB on-stack receive buffer (remote stack smash).
 * Bounding to the real EXI ceiling makes the guard live at every call site.
 */
#define JPV2G_MAX_PAYLOAD_LENGTH 4096ULL

typedef int (*jpv2g_random_provider_fn)(uint8_t *buf, size_t len);

int jpv2g_hex_to_bytes(const char *hex, uint8_t *out, size_t out_len, size_t *written);
int jpv2g_bytes_to_hex(const uint8_t *in, size_t len, char *out, size_t out_len);
uint16_t jpv2g_read_u16_be(const uint8_t *buf);
uint32_t jpv2g_read_u32_be(const uint8_t *buf);
uint64_t jpv2g_read_u64_be(const uint8_t *buf);
void jpv2g_write_u16_be(uint8_t *buf, uint16_t v);
void jpv2g_write_u32_be(uint8_t *buf, uint32_t v);
void jpv2g_write_u64_be(uint8_t *buf, uint64_t v);
void jpv2g_set_random_provider(jpv2g_random_provider_fn fn);
int jpv2g_random_bytes(uint8_t *buf, size_t len);
