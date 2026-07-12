/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "jpv2g/config.h"
#include "jpv2g/codec.h"
#include "jpv2g/messages.h"
#include "jpv2g/backend.h"
#include "jpv2g/evse_controller.h"
#include "jpv2g/transport.h"
#include "jpv2g/tls.h"
#include "jpv2g/types.h"
#include "jpv2g/v2gtp.h"

struct iso2_MessageHeaderType;
struct din_MessageHeaderType;

typedef struct {
    jpv2g_protocol_t protocol;
    const struct iso2_MessageHeaderType *header;     /* ISO 15118 header (if applicable) */
    const struct din_MessageHeaderType *din_header;  /* DIN 70121 header (if applicable) */
    const void *body;                                /* Decoded request body */
} jpv2g_secc_request_t;

/* Classification of why a HLC client session ended. The PLC HLC worker
 * branches on this to decide power-path policy: a clean SESSION_STOP can
 * follow a relaxed teardown, an EV TCP reset during active charging
 * must drop current to 0 A immediately, and codec/parse errors imply
 * a stack incompatibility worth surfacing rather than blindly retrying.
 *
 * The numeric values are part of the diagnostic log output; do NOT
 * renumber existing entries.
 */
typedef enum {
    JPV2G_HLC_DROP_UNKNOWN = 0,
    JPV2G_HLC_DROP_FIRST_PACKET_TIMEOUT = 1,  /* peer never spoke within first_timeout_ms */
    JPV2G_HLC_DROP_IDLE_TIMEOUT = 2,          /* idle timeout between messages */
    JPV2G_HLC_DROP_PEER_RESET = 3,            /* TCP RST / orderly close (recv returned 0) */
    JPV2G_HLC_DROP_EV_SESSION_STOP = 4,       /* EV sent SessionStopReq before disconnect */
    JPV2G_HLC_DROP_TCP_RECV_FAIL = 5,         /* socket recv() failed with a non-timeout errno */
    JPV2G_HLC_DROP_TCP_SEND_FAIL = 6,         /* socket send() failed or short-wrote */
    JPV2G_HLC_DROP_CODEC_ERROR = 7,           /* EXI/V2GTP parse rejected */
    JPV2G_HLC_DROP_HANDLER_ERROR = 8,         /* downstream response handler returned non-zero */
    JPV2G_HLC_DROP_LOCAL_STOP = 9,            /* local code closed the socket */
    JPV2G_HLC_DROP_INVALID_ARG = 10,          /* misuse of the API */
    JPV2G_HLC_DROP_SEQUENCE_ERROR = 11,        /* decoded request is invalid in the current protocol phase */
    JPV2G_HLC_DROP_UNKNOWN_SESSION = 12,       /* missing, stale, or mismatched V2G SessionID */
} jpv2g_hlc_drop_reason_t;

/* Map a rc returned from jpv2g_secc_handle_client_detect() (or the
 * underlying handle_stream) to a jpv2g_hlc_drop_reason_t. The mapping
 * uses POSIX errno semantics:
 *   rc == 0               -> JPV2G_HLC_DROP_EV_SESSION_STOP if a stop
 *                            message was observed, otherwise IDLE_TIMEOUT
 *   rc == -ETIMEDOUT      -> IDLE_TIMEOUT (or FIRST_PACKET_TIMEOUT if
 *                            no message was handled before the timeout)
 *   rc == -ECONNRESET     -> PEER_RESET
 *   rc == -EIO            -> TCP_SEND_FAIL
 *   rc == -EBADMSG/-E2BIG -> CODEC_ERROR
 *   rc == -EPROTO         -> SEQUENCE_ERROR
 *   rc == -EACCES         -> UNKNOWN_SESSION
 *   rc == -EINVAL         -> INVALID_ARG
 *   anything else negative-> TCP_RECV_FAIL (catch-all socket-level error)
 *
 * `handled_any` reflects whether at least one HLC request was processed
 * before the disconnect; `saw_session_stop` reflects whether the EV's
 * SessionStopReq passed through the handler. Both are surfaced from the
 * caller because the rc value alone cannot distinguish these cases.
 */
const char *jpv2g_hlc_drop_reason_name(jpv2g_hlc_drop_reason_t reason);
jpv2g_hlc_drop_reason_t jpv2g_secc_classify_disconnect(int rc,
                                                       bool handled_any,
                                                       bool saw_session_stop);

typedef struct {
    jpv2g_secc_config_t cfg;
    jpv2g_codec_ctx *codec;
    jpv2g_udp_server_t udp;
    jpv2g_tcp_server_t tcp;
    jpv2g_tcp_server_t tls; /* placeholder for TLS; shares structure */
    jpv2g_backend_t backend;
    jpv2g_evse_controller_t evse_ctl;
    uint8_t session_id[8];
    /* Pause/resume memory (ISO 15118-2 SessionStop ChargingSession=Pause).
     * last_session_id: SID retained from the most recent Pause (all-zero =
     * none); last_session_end_ms: jpv2g_now_monotonic_ms() stamp of that pause.
     * A SessionSetupReq presenting this SID inside the resume window is answered
     * OK_OldSessionJoined; any other non-zero SID now gets a fresh SECC SID +
     * OK_NewSessionEstablished (see secc_resolve_session). Zero-initialised by
     * the jpv2g_secc_init() memset. */
    uint8_t last_session_id[8];
    int64_t last_session_end_ms;
    int64_t meter_Wh;
    char meter_id[16];
    /* Callbacks to build responses based on decoded requests. */
    int (*handle_request)(jpv2g_message_type_t type, const void *decoded, uint8_t *out, size_t out_len, size_t *written, void *user_ctx);
    void *user_ctx;
} jpv2g_secc_t;

int jpv2g_secc_init(jpv2g_secc_t *secc, const jpv2g_secc_config_t *cfg, jpv2g_codec_ctx *codec);
int jpv2g_secc_start_udp(jpv2g_secc_t *secc);
int jpv2g_secc_start_tcp(jpv2g_secc_t *secc);
int jpv2g_secc_start_tls(jpv2g_secc_t *secc);
void jpv2g_secc_stop(jpv2g_secc_t *secc);

/* Retire the LIVE session id without granting resume rights. Call on every
 * client-connection teardown (TCP drop / idle timeout / codec error / local
 * stop): the default handler only clears session_id on an orderly
 * SessionStopRes, so an unclean drop would otherwise leave the dead SID
 * joinable by the next connection. Preserves the SessionStop(Pause) memory in
 * last_session_id / last_session_end_ms. */
void jpv2g_secc_retire_session(jpv2g_secc_t *secc);

/* Handle a single TCP client connection (plaintext). */
int jpv2g_secc_handle_client(jpv2g_secc_t *secc, int client_fd, int timeout_ms);
/* Handle a single TLS client connection (wraps TLS then processes messages). */
int jpv2g_secc_handle_client_tls(jpv2g_secc_t *secc,
                                   int client_fd,
                                   const char *cert_path,
                                   const char *key_path,
                                   const char *ca_path,
                                   int timeout_ms);
/* Peek first bytes and route to TLS/plain automatically; waits for first data up to first_timeout_ms. */
int jpv2g_secc_handle_client_detect(jpv2g_secc_t *secc,
                                      int client_fd,
                                      int first_timeout_ms,
                                      int timeout_ms);

/* Extended variant that also reports a classified disconnect reason
 * via the out-pointer. The rc return value is unchanged. Both pointers
 * are optional. */
int jpv2g_secc_handle_client_detect_ex(jpv2g_secc_t *secc,
                                        int client_fd,
                                        int first_timeout_ms,
                                        int timeout_ms,
                                        jpv2g_hlc_drop_reason_t *out_reason,
                                        bool *out_saw_session_stop);

/* Enable/disable verbose decoded request/response logs (enabled by default). */
void jpv2g_secc_set_decoded_logs(bool enable);
bool jpv2g_secc_get_decoded_logs(void);
void jpv2g_secc_set_timing_logs(bool enable);
bool jpv2g_secc_get_timing_logs(void);

/* Default response builder (ISO/DIN) usable by custom handlers and tests. */
int jpv2g_secc_default_handle(jpv2g_secc_t *secc,
                                jpv2g_message_type_t type,
                                const jpv2g_secc_request_t *req,
                                uint8_t *out,
                                size_t out_len,
                                size_t *written);

/* Validate the V2G message-header SessionID before invoking a request handler.
 * SupportedAppProtocol has no V2G header, while SessionSetup may carry either
 * an empty/new-session SID or an eight-byte resume candidate. Every later
 * request must present the currently active eight-byte SID. */
int jpv2g_secc_validate_request_session(const jpv2g_secc_t *secc,
                                        jpv2g_message_type_t type,
                                        const jpv2g_secc_request_t *req);
