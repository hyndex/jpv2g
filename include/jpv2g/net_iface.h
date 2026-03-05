/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#pragma once

#include "jpv2g/platform_compat.h"
#include "jpv2g/config.h"

/*
 * Resolves an interface name to an index with fallbacks:
 * - Uses the preferred name if provided and valid.
 * - Otherwise uses the JPV2G_IFACE environment variable if set.
 * - Otherwise auto-selects the first UP, non-loopback IPv6 interface (prefers multicast).
 * Always succeeds; if nothing is found, out name stays empty and index is 0 (default scope).
 */
int jpv2g_iface_select(const char *preferred,
                       char out_name[JPV2G_IFACE_NAME_MAX],
                       unsigned int *ifindex_out);
