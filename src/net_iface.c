/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#include "jpv2g/net_iface.h"

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include "jpv2g/log.h"
#include "jpv2g/platform_compat.h"

static bool is_valid_name(const char *name) {
    return name && name[0] != '\0';
}

static void store_name(const char *name, char out[JPV2G_IFACE_NAME_MAX]) {
    if (!out) return;
    if (!name) {
        out[0] = '\0';
        return;
    }
    strncpy(out, name, JPV2G_IFACE_NAME_MAX - 1);
    out[JPV2G_IFACE_NAME_MAX - 1] = '\0';
}

int jpv2g_iface_select(const char *preferred,
                       char out_name[JPV2G_IFACE_NAME_MAX],
                       unsigned int *ifindex_out) {
    if (out_name) out_name[0] = '\0';
    if (ifindex_out) *ifindex_out = 0;

    const char *candidate = preferred;

    if (is_valid_name(candidate)) {
        unsigned int idx = jpv2g_if_nametoindex(candidate);
        if (idx != 0) {
            store_name(candidate, out_name);
            if (ifindex_out) *ifindex_out = idx;
            return 0;
        }
        JPV2G_WARN("if_nametoindex(%s) failed, trying auto interface", candidate);
    }

    const char *fallbacks[] = {"pl0", "eth0", "en0", "st1"};
    for (size_t i = 0; i < (sizeof(fallbacks) / sizeof(fallbacks[0])); ++i) {
        unsigned int idx = jpv2g_if_nametoindex(fallbacks[i]);
        if (idx != 0) {
            store_name(fallbacks[i], out_name);
            if (ifindex_out) *ifindex_out = idx;
            return 0;
        }
    }

    /* Nothing resolved; leave outputs as default (empty/0). */
    if (is_valid_name(candidate)) store_name(candidate, out_name);
    return 0;
}
