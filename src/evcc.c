/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#include "jpv2g/evcc.h"

#include "jpv2g/cbv2g_codec.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "jpv2g/byte_utils.h"
#include "jpv2g/discovery.h"
#include "jpv2g/log.h"
#include "jpv2g/net_iface.h"
#include "jpv2g/platform_compat.h"
#include "jpv2g/session.h"
#include "jpv2g/time_compat.h"

/* Read exactly len bytes respecting the timeout budget. */
static int evcc_recv_bytes(jpv2g_evcc_t *evcc, uint8_t *buf, size_t len, int timeout_ms) {
    if (!evcc || !buf) return -EINVAL;
    size_t off = 0;
    int64_t deadline = timeout_ms > 0 ? jpv2g_now_monotonic_ms() + timeout_ms : 0;
    while (off < len) {
        int slice = timeout_ms;
        if (timeout_ms > 0) {
            int64_t remaining = deadline - jpv2g_now_monotonic_ms();
            if (remaining <= 0) return -ETIMEDOUT;
            if (remaining > INT32_MAX) remaining = INT32_MAX;
            slice = (int)remaining;
        }
        ssize_t r = evcc->tls_enabled ? jpv2g_tls_recv(&evcc->tls, buf + off, len - off, slice)
                                      : jpv2g_tcp_recv(evcc->tcp.fd, buf + off, len - off, slice);
        if (r == 0) return -ECONNRESET;
        if (r < 0) {
            if (r == -EAGAIN && timeout_ms > 0) return -ETIMEDOUT;
            return (int)r;
        }
        off += (size_t)r;
    }
    return 0;
}

int jpv2g_evcc_init(jpv2g_evcc_t *evcc, const jpv2g_evcc_config_t *cfg, jpv2g_codec_ctx *codec) {
    if (!evcc || !cfg || !codec) return -EINVAL;
    memset(evcc, 0, sizeof(*evcc));
    evcc->cfg = *cfg;
    evcc->codec = codec;
    evcc->tcp.fd = -1;
    evcc->tls.fd = -1;
    evcc->tls_enabled = cfg->use_tls;
    evcc->build_message = NULL;
    evcc->handle_message = NULL;
    evcc->user_ctx = NULL;
    size_t sid_len = 0;
    if (jpv2g_hex_to_bytes(cfg->session_id_hex, evcc->session_id, sizeof(evcc->session_id), &sid_len) != 0 || sid_len != 8) {
        /* generate new session id */
        jpv2g_generate_session_id(NULL, evcc->session_id);
    }
    return 0;
}

int jpv2g_evcc_discover(jpv2g_evcc_t *evcc) {
    if (!evcc) return -EINVAL;
    uint8_t sec = evcc->cfg.use_tls ? JPV2G_SECURITY_WITH_TLS : JPV2G_SECURITY_WITHOUT_TLS;
    int rc = jpv2g_discover_secc(evcc->cfg.network_interface, sec, JPV2G_TRANSPORT_TCP,
                                   JPV2G_TIMEOUT_SDP_RESPONSE, JPV2G_SDP_REQUEST_MAX_COUNTER,
                                   &evcc->discovery);
    if (rc != 0) {
        JPV2G_ERROR("SDP discovery failed (%d)", rc);
        return rc;
    }
    return 0;
}

int jpv2g_evcc_connect(jpv2g_evcc_t *evcc) {
    if (!evcc) return -EINVAL;
    if (evcc->discovery.secc_port == 0) return -EINVAL;
    if (evcc->discovery.secc_addr.sin6_scope_id == 0) {
        unsigned int ifidx = evcc->discovery.if_index;
        char ifname[JPV2G_IFACE_NAME_MAX] = {0};
        if (ifidx == 0) jpv2g_iface_select(evcc->cfg.network_interface, ifname, &ifidx);
        if (ifidx != 0) {
            evcc->discovery.secc_addr.sin6_scope_id = ifidx;
        } else {
            JPV2G_WARN("EVCC connect: no scope id resolved, using default interface");
        }
    }
    int rc = 0;
    if (evcc->cfg.use_tls) {
        rc = jpv2g_tls_client_connect(&evcc->tls,
                                        &evcc->discovery.secc_addr,
                                        sizeof(evcc->discovery.secc_addr),
                                        evcc->cfg.tls_cert_path,
                                        evcc->cfg.tls_key_path,
                                        evcc->cfg.tls_ca_path,
                                        JPV2G_TIMEOUT_COMM_SETUP);
        evcc->tls_enabled = (rc == 0);
    } else {
        rc = jpv2g_tcp_client_connect(&evcc->tcp,
                                        &evcc->discovery.secc_addr,
                                        sizeof(evcc->discovery.secc_addr),
                                        JPV2G_TIMEOUT_COMM_SETUP);
        evcc->tls_enabled = false;
    }
    return rc;
}

int jpv2g_evcc_send_v2gtp(jpv2g_evcc_t *evcc, jpv2g_payload_type_t type, const uint8_t *payload, size_t payload_len) {
    if (!evcc) return -EINVAL;
    if (payload_len > JPV2G_MAX_PAYLOAD_LENGTH) return -E2BIG;
    size_t buf_len = JPV2G_V2GTP_HEADER_LEN + payload_len;
    uint8_t *buf = (uint8_t *)malloc(buf_len);
    if (!buf) return -ENOMEM;
    size_t written = 0;
    int rc = jpv2g_v2gtp_build(type, payload, payload_len, buf, buf_len, &written);
    if (rc != 0) {
        free(buf);
        return rc;
    }
    ssize_t sent;
    if (evcc->tls_enabled) {
        sent = jpv2g_tls_send(&evcc->tls, buf, written);
    } else {
        sent = jpv2g_tcp_send(evcc->tcp.fd, buf, written);
    }
    free(buf);
    if (sent < 0 || (size_t)sent != written) return (int)sent;
    return 0;
}

int jpv2g_evcc_recv_v2gtp(jpv2g_evcc_t *evcc, uint8_t *buf, size_t buf_len, jpv2g_v2gtp_t *out, int timeout_ms) {
    if (!evcc || !buf || !out) return -EINVAL;
    if (buf_len < JPV2G_V2GTP_HEADER_LEN) return -ENOSPC;

    int rc = evcc_recv_bytes(evcc, buf, JPV2G_V2GTP_HEADER_LEN, timeout_ms);
    if (rc != 0) return rc;
    uint32_t payload_len = jpv2g_read_u32_be(&buf[4]);
    if (payload_len > JPV2G_MAX_PAYLOAD_LENGTH) return -E2BIG;

    size_t total = JPV2G_V2GTP_HEADER_LEN + payload_len;
    if (total > buf_len) return -ENOSPC;
    rc = evcc_recv_bytes(evcc, buf + JPV2G_V2GTP_HEADER_LEN, payload_len, timeout_ms);
    if (rc != 0) return rc;

    return jpv2g_v2gtp_parse(buf, total, out);
}

void jpv2g_evcc_close(jpv2g_evcc_t *evcc) {
    if (!evcc) return;
    if (evcc->tls_enabled) {
        jpv2g_tls_close(&evcc->tls);
    } else {
        jpv2g_tcp_client_close(&evcc->tcp);
    }
}

int jpv2g_evcc_handshake_app_protocol(jpv2g_evcc_t *evcc, int timeout_ms) {
    if (!evcc || !evcc->codec) return -EINVAL;
    if (!evcc->build_message || !evcc->handle_message) {
        JPV2G_ERROR("App protocol handshake requires build/handle callbacks");
        return -ENOTSUP;
    }
    uint8_t payload[1024];
    size_t payload_len = 0;
    int rc = evcc->build_message(JPV2G_SUPP_APP_PROTOCOL_REQ, evcc->user_ctx, payload, sizeof(payload), &payload_len);
    if (rc != 0) return rc;
    rc = jpv2g_evcc_send_v2gtp(evcc, JPV2G_PAYLOAD_EXI, payload, payload_len);
    if (rc != 0) return rc;

    uint8_t buf[4096];
    jpv2g_v2gtp_t msg;
    rc = jpv2g_evcc_recv_v2gtp(evcc, buf, sizeof(buf), &msg, timeout_ms);
    if (rc != 0) return rc;
    if (msg.payload_type != JPV2G_PAYLOAD_EXI) return -EBADMSG;

    struct appHand_supportedAppProtocolRes res;
    rc = jpv2g_cbv2g_decode_sapp_res(msg.payload, msg.payload_length, &res);
    if (rc == 0) {
        return evcc->handle_message(JPV2G_SUPP_APP_PROTOCOL_RES, &res, evcc->user_ctx);
    }
    /* Fallback to generic codec if cbv2g is not linked/configured */
    void *decoded = NULL;
    int rc_codec = jpv2g_decode_exi(evcc->codec, msg.payload, msg.payload_length, &decoded);
    if (rc_codec != 0) return rc_codec;
    return evcc->handle_message(JPV2G_SUPP_APP_PROTOCOL_RES, decoded, evcc->user_ctx);
}

int jpv2g_evcc_exchange(jpv2g_evcc_t *evcc,
                          jpv2g_message_type_t req_type,
                          jpv2g_message_type_t res_type,
                          int timeout_ms) {
    if (!evcc || !evcc->build_message || !evcc->handle_message) return -EINVAL;
    uint8_t payload[JPV2G_MAX_EXI_SIZE];
    size_t payload_len = 0;
    int rc = evcc->build_message(req_type, evcc->user_ctx, payload, sizeof(payload), &payload_len);
    if (rc != 0) return rc;
    rc = jpv2g_evcc_send_v2gtp(evcc, JPV2G_PAYLOAD_EXI, payload, payload_len);
    if (rc != 0) return rc;
    uint8_t buf[JPV2G_MAX_V2GTP_SIZE];
    jpv2g_v2gtp_t msg;
    rc = jpv2g_evcc_recv_v2gtp(evcc, buf, sizeof(buf), &msg, timeout_ms);
    if (rc != 0) return rc;
    if (msg.payload_type != JPV2G_PAYLOAD_EXI) return -EBADMSG;
    int handler_rc = -ENOTSUP;
    switch (res_type) {
        case JPV2G_SUPP_APP_PROTOCOL_RES: {
            struct appHand_supportedAppProtocolRes res;
            rc = jpv2g_cbv2g_decode_sapp_res(msg.payload, msg.payload_length, &res);
            if (rc != 0) return rc;
            if (evcc->handle_message) handler_rc = evcc->handle_message(res_type, &res, evcc->user_ctx);
            break;
        }
        case JPV2G_SESSION_SETUP_RES: {
            struct iso2_SessionSetupResType res;
            uint8_t sid[iso2_sessionIDType_BYTES_SIZE];
            rc = jpv2g_cbv2g_decode_session_setup_res(msg.payload, msg.payload_length, &res, sid);
            if (rc != 0) return rc;
            memcpy(evcc->session_id, sid, sizeof(evcc->session_id));
            if (evcc->handle_message) handler_rc = evcc->handle_message(res_type, &res, evcc->user_ctx);
            break;
        }
        case JPV2G_SERVICE_DISCOVERY_RES: {
            struct iso2_ServiceDiscoveryResType res;
            rc = jpv2g_cbv2g_decode_service_discovery_res(msg.payload, msg.payload_length, &res);
            if (rc != 0) return rc;
            if (evcc->handle_message) handler_rc = evcc->handle_message(res_type, &res, evcc->user_ctx);
            break;
        }
        case JPV2G_PAYMENT_SERVICE_SELECTION_RES: {
            struct iso2_PaymentServiceSelectionResType res;
            rc = jpv2g_cbv2g_decode_payment_service_selection_res(msg.payload, msg.payload_length, &res);
            if (rc != 0) return rc;
            if (evcc->handle_message) handler_rc = evcc->handle_message(res_type, &res, evcc->user_ctx);
            break;
        }
        case JPV2G_CHARGE_PARAMETER_DISCOVERY_RES: {
            struct iso2_ChargeParameterDiscoveryResType res;
            rc = jpv2g_cbv2g_decode_charge_parameter_discovery_res(msg.payload, msg.payload_length, &res);
            if (rc != 0) return rc;
            if (evcc->handle_message) handler_rc = evcc->handle_message(res_type, &res, evcc->user_ctx);
            break;
        }
        default: {
            void *decoded = NULL;
            rc = jpv2g_decode_exi(evcc->codec, msg.payload, msg.payload_length, &decoded);
            if (rc != 0) return rc;
            if (evcc->handle_message) handler_rc = evcc->handle_message(res_type, decoded, evcc->user_ctx);
            break;
        }
    }
    return handler_rc;
}
