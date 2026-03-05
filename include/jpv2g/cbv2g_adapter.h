/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#pragma once

#include "jpv2g/codec.h"

/* Register libcbv2g encode/decode into the codec context.
 * Requires cbv2g_encode/cbv2g_decode symbols from libcbv2g to be linked in.
 */
int jpv2g_codec_use_cbv2g(jpv2g_codec_ctx *ctx);
