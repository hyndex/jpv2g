/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#include "jpv2g/discovery.h"

#include <errno.h>
#include <string.h>

#include "jpv2g/log.h"
#include "jpv2g/net_iface.h"

int jpv2g_discover_secc(const char *iface,
                          uint8_t security,
                          uint8_t transport_protocol,
                          int timeout_ms,
                          int max_retries,
                          jpv2g_discovery_result_t *out) {
    if (!out) return -EINVAL;
    if (max_retries <= 0 || max_retries > JPV2G_SDP_REQUEST_MAX_COUNTER) max_retries = JPV2G_SDP_REQUEST_MAX_COUNTER;

    char resolved_ifname[JPV2G_IFACE_NAME_MAX] = {0};
    unsigned int ifidx = 0;
    jpv2g_iface_select(iface, resolved_ifname, &ifidx);
    const char *iface_to_use = resolved_ifname[0] ? resolved_ifname : NULL;
    if (iface && iface[0] && !resolved_ifname[0]) {
        JPV2G_WARN("SDP discovery: requested iface %s not found, using default scope", iface);
    }

    jpv2g_udp_client_t cli;
    int rc = jpv2g_udp_client_start(&cli, iface_to_use);
    if (rc != 0) return rc;

    jpv2g_sdp_req_t req = {.security = security, .transport_protocol = transport_protocol};
    uint8_t sdp_payload[2];
    size_t sdp_len = 0;
    rc = jpv2g_sdp_req_encode(&req, sdp_payload, sizeof(sdp_payload), &sdp_len);
    if (rc != 0) {
        jpv2g_udp_client_stop(&cli);
        return rc;
    }

    uint8_t v2g_msg[JPV2G_V2GTP_HEADER_LEN + sizeof(sdp_payload)];
    size_t v2g_len = 0;
    rc = jpv2g_v2gtp_build(JPV2G_PAYLOAD_SDP_REQ, sdp_payload, sdp_len, v2g_msg, sizeof(v2g_msg), &v2g_len);
    if (rc != 0) {
        jpv2g_udp_client_stop(&cli);
        return rc;
    }

    uint8_t resp_buf[256];
    for (int attempt = 0; attempt < max_retries; ++attempt) {
        int r = jpv2g_udp_client_sendrecv(&cli, v2g_msg, v2g_len, resp_buf, sizeof(resp_buf), timeout_ms);
        if (r < 0) {
            if (r == -EAGAIN || r == -ETIMEDOUT) {
                JPV2G_WARN("SDP attempt %d/%d timed out", attempt + 1, max_retries);
                continue;
            }
            JPV2G_ERROR("SDP attempt %d/%d failed (%d)", attempt + 1, max_retries, r);
            continue;
        }

        jpv2g_v2gtp_t msg;
        rc = jpv2g_v2gtp_parse(resp_buf, (size_t)r, &msg);
        if (rc != 0) {
            JPV2G_WARN("Invalid V2GTP response (%d), retrying", rc);
            continue;
        }
        if (msg.payload_type != JPV2G_PAYLOAD_SDP_RES) {
            JPV2G_WARN("Unexpected payload type 0x%04X", msg.payload_type);
            continue;
        }
        jpv2g_sdp_res_t sdp_res;
        rc = jpv2g_sdp_res_decode(msg.payload, msg.payload_length, &sdp_res);
        if (rc != 0) {
            JPV2G_WARN("Failed to decode SDP response (%d)", rc);
            continue;
        }
        memset(out, 0, sizeof(*out));
        memcpy(&out->secc_addr.sin6_addr, sdp_res.secc_ip, 16);
        out->secc_addr.sin6_family = AF_INET6;
        out->secc_addr.sin6_port = htons(sdp_res.secc_port);
        out->secc_addr.sin6_scope_id = ifidx ? ifidx : cli.ifindex;
        out->secc_port = sdp_res.secc_port;
        out->security = sdp_res.security;
        out->transport_protocol = sdp_res.transport_protocol;
        out->if_index = ifidx ? ifidx : cli.ifindex;
        jpv2g_udp_client_stop(&cli);
        return 0;
    }
    jpv2g_udp_client_stop(&cli);
    return -ETIMEDOUT;
}
