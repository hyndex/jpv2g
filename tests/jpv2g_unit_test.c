/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "jpv2g/evcc.h"
#include "jpv2g/handler.h"
#include "jpv2g/secc.h"
#include "jpv2g/state_evcc.h"
#include "jpv2g/state_machine.h"
#include "jpv2g/state_secc.h"
#include "jpv2g/v2gtp.h"

typedef struct {
    size_t calls;
    jpv2g_message_type_t last_type;
} test_handler_stats_t;

static int assert_true(int cond, const char *msg) {
    if (cond) return 0;
    fprintf(stderr, "ASSERT FAILED: %s\n", msg);
    return 1;
}

static int counting_handler(jpv2g_message_type_t type, const void *decoded, void *user_ctx) {
    (void)decoded;
    test_handler_stats_t *stats = (test_handler_stats_t *)user_ctx;
    if (!stats) return -EINVAL;
    stats->calls++;
    stats->last_type = type;
    return 0;
}

static int test_v2gtp_round_trip(void) {
    uint8_t payload[6] = {1, 2, 3, 4, 5, 6};
    uint8_t frame[64];
    size_t frame_len = 0;
    int rc = jpv2g_v2gtp_build(JPV2G_PAYLOAD_EXI, payload, sizeof(payload), frame, sizeof(frame), &frame_len);
    if (assert_true(rc == 0, "jpv2g_v2gtp_build should succeed") != 0) return 1;

    jpv2g_v2gtp_t parsed;
    memset(&parsed, 0, sizeof(parsed));
    rc = jpv2g_v2gtp_parse(frame, frame_len, &parsed);
    if (assert_true(rc == 0, "jpv2g_v2gtp_parse should succeed") != 0) return 1;
    if (assert_true(parsed.payload_type == JPV2G_PAYLOAD_EXI, "payload type must match") != 0) return 1;
    if (assert_true(parsed.payload_length == sizeof(payload), "payload length must match") != 0) return 1;
    if (assert_true(memcmp(parsed.payload, payload, sizeof(payload)) == 0, "payload bytes must round trip") != 0) return 1;
    return 0;
}

static int test_evcc_state_sequence(void) {
    jpv2g_state_t states[20];
    jpv2g_evcc_sm_ctx_t ctx;
    jpv2g_evcc_t evcc;
    jpv2g_handler_entry_t handlers[20];
    test_handler_stats_t stats;
    memset(states, 0, sizeof(states));
    memset(&ctx, 0, sizeof(ctx));
    memset(&evcc, 0, sizeof(evcc));
    memset(handlers, 0, sizeof(handlers));
    memset(&stats, 0, sizeof(stats));

    size_t n = jpv2g_evcc_build_sequence(states, 20, &ctx, true);
    if (assert_true(n == 15, "EVCC DC sequence should contain 15 states") != 0) return 1;

    for (size_t i = 0; i < n; ++i) {
        handlers[i].type = states[i].expected;
        handlers[i].handler = counting_handler;
    }
    evcc.user_ctx = &stats;
    ctx.evcc = &evcc;
    ctx.handlers = handlers;
    ctx.handler_count = n;

    jpv2g_state_machine_t sm;
    if (assert_true(jpv2g_sm_init(&sm, &states[0], &ctx) == 0, "EVCC sm init must succeed") != 0) return 1;
    if (assert_true(jpv2g_sm_handle(&sm, JPV2G_SESSION_SETUP_RES, NULL, 0) == -EINVAL,
                    "EVCC sm must reject unexpected message type") != 0) return 1;

    for (size_t i = 0; i < n; ++i) {
        int rc = jpv2g_sm_handle(&sm, states[i].expected, NULL, 0);
        if (assert_true(rc == 0, "EVCC sm should accept expected message type") != 0) return 1;
        if (i + 1 < n) {
            if (assert_true(sm.current == &states[i + 1], "EVCC sm should advance to next state") != 0) return 1;
        } else {
            if (assert_true(sm.current == &states[n - 1], "EVCC sm should stay on final state") != 0) return 1;
        }
    }

    size_t before = stats.calls;
    if (assert_true(jpv2g_sm_handle(&sm, states[n - 1].expected, NULL, 0) == 0,
                    "EVCC final state should remain re-entrant") != 0) return 1;
    if (assert_true(sm.current == &states[n - 1], "EVCC final state pointer should stay unchanged") != 0) return 1;
    if (assert_true(stats.calls == before + 1, "EVCC final state handler should still be called") != 0) return 1;
    return 0;
}

static int test_secc_state_sequence(void) {
    jpv2g_state_t states[20];
    jpv2g_secc_sm_ctx_t ctx;
    jpv2g_secc_t secc;
    jpv2g_handler_entry_t handlers[20];
    test_handler_stats_t stats;
    memset(states, 0, sizeof(states));
    memset(&ctx, 0, sizeof(ctx));
    memset(&secc, 0, sizeof(secc));
    memset(handlers, 0, sizeof(handlers));
    memset(&stats, 0, sizeof(stats));

    size_t n = jpv2g_secc_build_sequence(states, 20, &ctx, false);
    if (assert_true(n == 12, "SECC AC sequence should contain 12 states") != 0) return 1;

    for (size_t i = 0; i < n; ++i) {
        handlers[i].type = states[i].expected;
        handlers[i].handler = counting_handler;
    }
    secc.user_ctx = &stats;
    ctx.secc = &secc;
    ctx.handlers = handlers;
    ctx.handler_count = n;

    jpv2g_state_machine_t sm;
    if (assert_true(jpv2g_sm_init(&sm, &states[0], &ctx) == 0, "SECC sm init must succeed") != 0) return 1;
    if (assert_true(jpv2g_sm_handle(&sm, JPV2G_SESSION_SETUP_REQ, NULL, 0) == -EINVAL,
                    "SECC sm must reject unexpected message type") != 0) return 1;

    for (size_t i = 0; i < n; ++i) {
        int rc = jpv2g_sm_handle(&sm, states[i].expected, NULL, 0);
        if (assert_true(rc == 0, "SECC sm should accept expected message type") != 0) return 1;
        if (i + 1 < n) {
            if (assert_true(sm.current == &states[i + 1], "SECC sm should advance to next state") != 0) return 1;
        } else {
            if (assert_true(sm.current == &states[n - 1], "SECC sm should stay on final state") != 0) return 1;
        }
    }
    if (assert_true(stats.calls == n, "SECC handlers should run once per expected state") != 0) return 1;

    jpv2g_sm_reset(&sm, &states[0]);
    if (assert_true(sm.current == &states[0], "state machine reset should restore first state") != 0) return 1;
    return 0;
}

int main(void) {
    if (test_v2gtp_round_trip() != 0) return 1;
    if (test_evcc_state_sequence() != 0) return 1;
    if (test_secc_state_sequence() != 0) return 1;
    printf("jpv2g_unit_test: PASS\n");
    return 0;
}
