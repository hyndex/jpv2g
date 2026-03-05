/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "jpv2g/sdp.h"
#include "jpv2g/transport.h"
#include "jpv2g/v2gtp.h"

typedef struct {
    struct sockaddr_in6 secc_addr;
    uint16_t secc_port;
    uint8_t security;
    uint8_t transport_protocol;
    unsigned int if_index; /* interface index used for scope (link-local IPv6) */
} jpv2g_discovery_result_t;

/**
 * Perform SDP discovery (EVCC side).
 * @param iface network interface name (e.g., "en0")
 * @param security requested security flag (e.g., JPV2G_SECURITY_WITH_TLS)
 * @param transport_protocol requested transport (e.g., JPV2G_TRANSPORT_TCP)
 * @param timeout_ms timeout per request
 * @param max_retries number of attempts (max 50)
 * @param out result container on success
 */
int jpv2g_discover_secc(const char *iface,
                          uint8_t security,
                          uint8_t transport_protocol,
                          int timeout_ms,
                          int max_retries,
                          jpv2g_discovery_result_t *out);
