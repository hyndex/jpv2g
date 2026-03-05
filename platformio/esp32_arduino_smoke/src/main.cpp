#include <Arduino.h>

#include <cstring>

extern "C" {
#include "jpv2g/byte_utils.h"
#include "jpv2g/evcc.h"
#include "jpv2g/handler.h"
#include "jpv2g/secc.h"
#include "jpv2g/state_evcc.h"
#include "jpv2g/state_machine.h"
#include "jpv2g/state_secc.h"
#include "jpv2g/v2gtp.h"
}

namespace {

struct HandlerStats {
    size_t calls;
    jpv2g_message_type_t last_type;
};

int counting_handler(jpv2g_message_type_t type, const void* decoded, void* user_ctx) {
    (void)decoded;
    HandlerStats* stats = static_cast<HandlerStats*>(user_ctx);
    if (!stats) return -1;
    stats->calls++;
    stats->last_type = type;
    return 0;
}

bool test_random_bytes() {
    uint8_t rnd[16] = {0};
    return jpv2g_random_bytes(rnd, sizeof(rnd)) == 0;
}

bool test_v2gtp_round_trip() {
    const uint8_t payload[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    uint8_t frame[64] = {0};
    size_t frame_len = 0;
    if (jpv2g_v2gtp_build(JPV2G_PAYLOAD_EXI, payload, sizeof(payload), frame, sizeof(frame), &frame_len) != 0) {
        return false;
    }

    jpv2g_v2gtp_t parsed;
    memset(&parsed, 0, sizeof(parsed));
    if (jpv2g_v2gtp_parse(frame, frame_len, &parsed) != 0) return false;
    if (parsed.payload_type != JPV2G_PAYLOAD_EXI) return false;
    if (parsed.payload_length != sizeof(payload)) return false;
    return memcmp(parsed.payload, payload, sizeof(payload)) == 0;
}

bool test_evcc_state_sequence() {
    jpv2g_state_t states[20];
    jpv2g_evcc_sm_ctx_t ctx;
    jpv2g_evcc_t evcc;
    jpv2g_handler_entry_t handlers[20];
    HandlerStats stats;
    memset(states, 0, sizeof(states));
    memset(&ctx, 0, sizeof(ctx));
    memset(&evcc, 0, sizeof(evcc));
    memset(handlers, 0, sizeof(handlers));
    memset(&stats, 0, sizeof(stats));

    const size_t n = jpv2g_evcc_build_sequence(states, 20, &ctx, true);
    if (n != 15) return false;
    for (size_t i = 0; i < n; ++i) {
        handlers[i].type = states[i].expected;
        handlers[i].handler = counting_handler;
    }

    evcc.user_ctx = &stats;
    ctx.evcc = &evcc;
    ctx.handlers = handlers;
    ctx.handler_count = n;

    jpv2g_state_machine_t sm;
    memset(&sm, 0, sizeof(sm));
    if (jpv2g_sm_init(&sm, &states[0], &ctx) != 0) return false;

    for (size_t i = 0; i < n; ++i) {
        if (jpv2g_sm_handle(&sm, states[i].expected, nullptr, 0) != 0) return false;
    }
    return sm.current == &states[n - 1] && stats.calls == n;
}

bool test_secc_state_sequence() {
    jpv2g_state_t states[20];
    jpv2g_secc_sm_ctx_t ctx;
    jpv2g_secc_t secc;
    jpv2g_handler_entry_t handlers[20];
    HandlerStats stats;
    memset(states, 0, sizeof(states));
    memset(&ctx, 0, sizeof(ctx));
    memset(&secc, 0, sizeof(secc));
    memset(handlers, 0, sizeof(handlers));
    memset(&stats, 0, sizeof(stats));

    const size_t n = jpv2g_secc_build_sequence(states, 20, &ctx, false);
    if (n != 12) return false;
    for (size_t i = 0; i < n; ++i) {
        handlers[i].type = states[i].expected;
        handlers[i].handler = counting_handler;
    }

    secc.user_ctx = &stats;
    ctx.secc = &secc;
    ctx.handlers = handlers;
    ctx.handler_count = n;

    jpv2g_state_machine_t sm;
    memset(&sm, 0, sizeof(sm));
    if (jpv2g_sm_init(&sm, &states[0], &ctx) != 0) return false;

    for (size_t i = 0; i < n; ++i) {
        if (jpv2g_sm_handle(&sm, states[i].expected, nullptr, 0) != 0) return false;
    }
    return sm.current == &states[n - 1] && stats.calls == n;
}

}  // namespace

void setup() {
    Serial.begin(115200);
    delay(500);

    const bool random_ok = test_random_bytes();
    const bool v2gtp_ok = test_v2gtp_round_trip();
    const bool evcc_state_ok = test_evcc_state_sequence();
    const bool secc_state_ok = test_secc_state_sequence();

    Serial.println();
    Serial.println("jpv2g ESP32 Arduino smoke test");
    Serial.printf("test_random_bytes: %s\n", random_ok ? "PASS" : "FAIL");
    Serial.printf("test_v2gtp_round_trip: %s\n", v2gtp_ok ? "PASS" : "FAIL");
    Serial.printf("test_evcc_state_sequence: %s\n", evcc_state_ok ? "PASS" : "FAIL");
    Serial.printf("test_secc_state_sequence: %s\n", secc_state_ok ? "PASS" : "FAIL");
    Serial.printf("overall: %s\n", (random_ok && v2gtp_ok && evcc_state_ok && secc_state_ok) ? "PASS" : "FAIL");
}

void loop() {
    delay(1000);
}
