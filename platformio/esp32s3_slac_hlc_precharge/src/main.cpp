#include <Arduino.h>
#include <SPI.h>
#include <esp_system.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/semphr.h>
#include <WiFi.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include <slac/channel.hpp>
#include <slac/evse_fsm.hpp>
#include <slac/platform.hpp>
#include <slac/slac.hpp>
#include <lwip/etharp.h>
#include <lwip/ethip6.h>
#include <lwip/netif.h>
#include <lwip/pbuf.h>
#include <lwip/tcpip.h>
#include <netif/ethernet.h>

extern "C" {
#include "jpv2g/config.h"
#include "jpv2g/codec.h"
#include "jpv2g/constants.h"
#include "jpv2g/platform_compat.h"
#include "jpv2g/sdp.h"
#include "jpv2g/secc.h"
#include "jpv2g/transport.h"
#include "jpv2g/v2gtp.h"
}

namespace {

// Hardware profile aligned to Basic/src/defs.h
constexpr int PIN_QCA700X_INT = 2;
constexpr int PIN_QCA700X_CS = 10;
constexpr int PIN_QCA700X_RESET = 8;
constexpr int QCA_SPI_SCK = 7;
constexpr int QCA_SPI_MISO = 16;
constexpr int QCA_SPI_MOSI = 15;
constexpr uint32_t QCA_SPI_HZ = 8000000UL;

constexpr int CP_1_PWM_PIN = 38;
constexpr int CP_1_PWM_CHANNEL = 0;
constexpr int CP_1_PWM_FREQUENCY = 1000;
constexpr int CP_1_PWM_RESOLUTION = 12;
constexpr uint32_t CP_1_MAX_DUTY_CYCLE = (1u << CP_1_PWM_RESOLUTION) - 1u;
constexpr int CP_1_READ_PIN = 1;

constexpr int CP_T12_MV = 2300;
constexpr int CP_T9_MV = 2000;
constexpr int CP_T6_MV = 1700;
constexpr int CP_T3_MV = 1450;
constexpr int CP_T0_MV = 1250;
constexpr int CP_NEG_THRESHOLD_MV = 500;
constexpr int CP_HYSTERESIS_MV = 100;
constexpr int CP_SAMPLE_COUNT = 80;
constexpr int CP_SAMPLE_DELAY_US = 6;
constexpr int CP_TOPK = 12;

constexpr uint32_t CP_STABLE_MS = 300;
constexpr uint32_t CP_STATE_DEBOUNCE_MS = 80;
constexpr uint32_t CP_DISCONNECT_DEBOUNCE_MS = 250;
constexpr uint32_t SLAC_HOLD_MS = 3000;
constexpr uint32_t CP_EF_PULSE_MS = 4000;
constexpr uint8_t EF_PULSE_AFTER_FAILURES = 2;
constexpr uint32_t STARTUP_LOG_DELAY_MS = 10000;
constexpr uint32_t QCA_INIT_RETRY_MS = 1000;
constexpr int HLC_FIRST_PACKET_TIMEOUT_MS = 20000;
constexpr int HLC_IDLE_TIMEOUT_MS = 60000;
constexpr uint32_t HLC_TASK_STACK_WORDS = 65536;
constexpr UBaseType_t HLC_CLIENT_QUEUE_DEPTH = 2;
constexpr UBaseType_t LWIP_TX_QUEUE_DEPTH = 12;
constexpr bool ENABLE_DECODED_LOGS = true;

constexpr uint16_t QCA7K_SPI_READ = (1u << 15);
constexpr uint16_t QCA7K_SPI_WRITE = (0u << 15);
constexpr uint16_t QCA7K_SPI_INTERNAL = (1u << 14);
constexpr uint16_t QCA7K_SPI_EXTERNAL = (0u << 14);

constexpr uint16_t SPI_REG_BFR_SIZE = 0x0100;
constexpr uint16_t SPI_REG_WRBUF_SPC_AVA = 0x0200;
constexpr uint16_t SPI_REG_RDBUF_BYTE_AVA = 0x0300;
constexpr uint16_t SPI_REG_SPI_CONFIG = 0x0400;
constexpr uint16_t SPI_REG_SIGNATURE = 0x1A00;

constexpr uint16_t SPI_INT_CPU_ON = (1u << 6);
constexpr uint16_t QCASPI_GOOD_SIGNATURE = 0xAA55;

constexpr uint16_t QCA7K_BUFFER_SIZE = 3163;
constexpr size_t RX_STREAM_CAPACITY = 4096;
constexpr size_t RX_CHUNK_CAPACITY = 4096;
constexpr size_t RX_QUEUE_CAPACITY = 8;

constexpr uint16_t PLC_PEER_MAC_DEFAULT[3] = {0x00B0, 0x5200, 0x0001};

void lwip_ingress_ethernet_frame(const uint8_t* frame, uint16_t len);

class Qca7000Transport final : public slac::ITransport {
public:
    Qca7000Transport() : spi(HSPI) {
        spi_mutex = xSemaphoreCreateMutex();
    }

    ~Qca7000Transport() override {
        if (spi_mutex) {
            vSemaphoreDelete(spi_mutex);
            spi_mutex = nullptr;
        }
    }

    bool begin() {
        if (ready) {
            return true;
        }

        pinMode(PIN_QCA700X_CS, OUTPUT);
        digitalWrite(PIN_QCA700X_CS, HIGH);
        pinMode(PIN_QCA700X_RESET, OUTPUT);
        digitalWrite(PIN_QCA700X_RESET, HIGH);
        pinMode(PIN_QCA700X_INT, INPUT);
        pinMode(QCA_SPI_SCK, OUTPUT);
        pinMode(QCA_SPI_MISO, INPUT);
        pinMode(QCA_SPI_MOSI, OUTPUT);

        // Basic/reference behavior: explicit hardware reset pulse before probing signature.
        digitalWrite(PIN_QCA700X_RESET, LOW);
        delay(10);
        digitalWrite(PIN_QCA700X_RESET, HIGH);
        delay(10);

        spi.begin(QCA_SPI_SCK, QCA_SPI_MISO, QCA_SPI_MOSI, PIN_QCA700X_CS);
        spi.beginTransaction(SPISettings(QCA_SPI_HZ, MSBFIRST, SPI_MODE3));
        spi.endTransaction();

        uint16_t sig = 0;
        if (!probe_signature(sig, 2000, 10)) {
            char buf[80];
            snprintf(buf, sizeof(buf), "QCA7000 signature mismatch (last=0x%04X)", sig);
            last_error = buf;
            return false;
        }

        ready = true;
        last_error.clear();
        return true;
    }

    void modem_reset() {
        uint16_t reg = read_register16(SPI_REG_SPI_CONFIG);
        reg = static_cast<uint16_t>(reg | SPI_INT_CPU_ON);
        write_register16(SPI_REG_SPI_CONFIG, reg);
    }

    bool is_ready() const {
        return ready;
    }

    void service_ingress_once() {
        if (!ready) {
            return;
        }
        poll_ingress();
    }

    IOResult read(uint8_t* buffer, int timeout_ms) override {
        if (!ready) {
            last_error = "transport not ready";
            return IOResult::Failure;
        }

        const uint32_t start_ms = millis();
        while (true) {
            RxFrame frame{};
            if (pop_frame(frame)) {
                memset(buffer, 0, ETH_FRAME_LEN);
                memcpy(buffer, frame.data.data(), frame.len);
                return IOResult::Ok;
            }

            poll_ingress();

            if (timeout_ms >= 0 && (uint32_t)(millis() - start_ms) >= static_cast<uint32_t>(timeout_ms)) {
                return IOResult::Timeout;
            }
            delay(1);
        }
    }

    IOResult write(const void* buffer, size_t size, int timeout_ms) override {
        if (!ready) {
            last_error = "transport not ready";
            return IOResult::Failure;
        }
        if (size == 0 || size > ETH_FRAME_LEN) {
            last_error = "invalid frame size";
            return IOResult::Failure;
        }

        const uint16_t total_len = static_cast<uint16_t>(size + 10u);
        const uint32_t start_ms = millis();
        while (true) {
            uint16_t wrbuf_space = read_register16(SPI_REG_WRBUF_SPC_AVA);
            if (wrbuf_space >= total_len) {
                break;
            }

            if (timeout_ms >= 0 && (uint32_t)(millis() - start_ms) >= static_cast<uint32_t>(timeout_ms)) {
                return IOResult::Timeout;
            }
            delay(1);
        }

        uint8_t hdr[8] = {
            0xAA, 0xAA, 0xAA, 0xAA,
            static_cast<uint8_t>(size & 0xFFu),
            static_cast<uint8_t>((size >> 8u) & 0xFFu),
            0x00, 0x00
        };

        if (!lock_spi(50)) {
            last_error = "spi lock timeout";
            return IOResult::Failure;
        }
        spi.beginTransaction(SPISettings(QCA_SPI_HZ, MSBFIRST, SPI_MODE3));
        digitalWrite(PIN_QCA700X_CS, LOW);
        spi.transfer16(static_cast<uint16_t>(QCA7K_SPI_WRITE | QCA7K_SPI_INTERNAL | SPI_REG_BFR_SIZE));
        spi.transfer16(total_len);
        digitalWrite(PIN_QCA700X_CS, HIGH);

        digitalWrite(PIN_QCA700X_CS, LOW);
        spi.transfer16(static_cast<uint16_t>(QCA7K_SPI_WRITE | QCA7K_SPI_EXTERNAL));
        spi.transfer(hdr, sizeof(hdr));
        spi.transfer(const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(buffer)), size);
        spi.transfer16(0x5555);
        digitalWrite(PIN_QCA700X_CS, HIGH);
        spi.endTransaction();
        unlock_spi();

        return IOResult::Ok;
    }

    const std::string& get_error() const override {
        return last_error;
    }

private:
    struct RxFrame {
        std::array<uint8_t, ETH_FRAME_LEN> data{};
        uint16_t len{0};
    };

    bool probe_signature(uint16_t& last_sig, uint32_t timeout_ms, uint32_t poll_delay_ms) {
        const uint32_t start_ms = millis();
        bool primed = false;
        last_sig = 0;

        while ((millis() - start_ms) < timeout_ms) {
            if (!primed) {
                (void)read_register16(SPI_REG_SIGNATURE);
                primed = true;
                delay(poll_delay_ms);
                continue;
            }

            last_sig = read_register16(SPI_REG_SIGNATURE);
            if (last_sig == QCASPI_GOOD_SIGNATURE) {
                return true;
            }

            primed = false;
            delay(poll_delay_ms);
        }

        return false;
    }

    uint16_t read_register16(uint16_t reg) {
        const uint16_t tx = static_cast<uint16_t>(QCA7K_SPI_READ | QCA7K_SPI_INTERNAL | reg);
        uint16_t rx = 0;
        if (!lock_spi(50)) {
            return 0;
        }
        spi.beginTransaction(SPISettings(QCA_SPI_HZ, MSBFIRST, SPI_MODE3));
        digitalWrite(PIN_QCA700X_CS, LOW);
        spi.transfer16(tx);
        rx = spi.transfer16(0x0000);
        digitalWrite(PIN_QCA700X_CS, HIGH);
        spi.endTransaction();
        unlock_spi();
        return rx;
    }

    void write_register16(uint16_t reg, uint16_t value) {
        const uint16_t tx = static_cast<uint16_t>(QCA7K_SPI_WRITE | QCA7K_SPI_INTERNAL | reg);
        if (!lock_spi(50)) {
            return;
        }
        spi.beginTransaction(SPISettings(QCA_SPI_HZ, MSBFIRST, SPI_MODE3));
        digitalWrite(PIN_QCA700X_CS, LOW);
        spi.transfer16(tx);
        spi.transfer16(value);
        digitalWrite(PIN_QCA700X_CS, HIGH);
        spi.endTransaction();
        unlock_spi();
    }

    uint16_t read_burst(uint8_t* dst) {
        uint16_t available = read_register16(SPI_REG_RDBUF_BYTE_AVA);
        if (available == 0 || available > QCA7K_BUFFER_SIZE || available > RX_CHUNK_CAPACITY) {
            return 0;
        }

        if (!lock_spi(50)) {
            return 0;
        }
        spi.beginTransaction(SPISettings(QCA_SPI_HZ, MSBFIRST, SPI_MODE3));
        digitalWrite(PIN_QCA700X_CS, LOW);
        spi.transfer16(static_cast<uint16_t>(QCA7K_SPI_WRITE | QCA7K_SPI_INTERNAL | SPI_REG_BFR_SIZE));
        spi.transfer16(available);
        digitalWrite(PIN_QCA700X_CS, HIGH);

        digitalWrite(PIN_QCA700X_CS, LOW);
        spi.transfer16(static_cast<uint16_t>(QCA7K_SPI_READ | QCA7K_SPI_EXTERNAL));
        spi.transfer(dst, available);
        digitalWrite(PIN_QCA700X_CS, HIGH);
        spi.endTransaction();
        unlock_spi();

        return available;
    }

    bool push_frame(const uint8_t* frame, uint16_t len) {
        if (q_count >= RX_QUEUE_CAPACITY || len > ETH_FRAME_LEN) {
            return false;
        }
        auto& slot = frame_queue[q_tail];
        memcpy(slot.data.data(), frame, len);
        slot.len = len;
        q_tail = (q_tail + 1u) % RX_QUEUE_CAPACITY;
        q_count++;
        return true;
    }

    bool pop_frame(RxFrame& out) {
        if (q_count == 0) {
            return false;
        }
        out = frame_queue[q_head];
        q_head = (q_head + 1u) % RX_QUEUE_CAPACITY;
        q_count--;
        return true;
    }

    void dispatch_eth_frame(const uint8_t* frame, uint16_t len) {
        if (!frame || len < 14u) {
            return;
        }
        const uint16_t eth_type = static_cast<uint16_t>((frame[12] << 8) | frame[13]);
        if (eth_type == slac::defs::ETH_P_HOMEPLUG_GREENPHY) {
            push_frame(frame, len);
            return;
        }
        lwip_ingress_ethernet_frame(frame, len);
    }

    void process_rx_stream(uint16_t chunk_len) {
        if (chunk_len == 0) {
            return;
        }

        if (rx_stream_len + chunk_len > RX_STREAM_CAPACITY) {
            rx_stream_len = 0;
        }
        if (chunk_len > RX_STREAM_CAPACITY) {
            return;
        }
        memcpy(rx_stream.data() + rx_stream_len, rx_chunk.data(), chunk_len);
        rx_stream_len += chunk_len;

        size_t pos = 0;
        while ((rx_stream_len - pos) >= 14u) {
            uint8_t* frame = rx_stream.data() + pos;
            const bool sof_ok = (frame[4] == 0xAA && frame[5] == 0xAA && frame[6] == 0xAA && frame[7] == 0xAA);
            if (!sof_ok) {
                pos++;
                continue;
            }

            const uint16_t fl = static_cast<uint16_t>(frame[8] | (frame[9] << 8));
            const size_t total = static_cast<size_t>(fl) + 14u;
            if (fl < 60u || fl > ETH_FRAME_LEN || total > RX_STREAM_CAPACITY) {
                pos++;
                continue;
            }

            const size_t avail = rx_stream_len - pos;
            if (avail < total) {
                break;
            }

            if (frame[total - 2u] == 0x55 && frame[total - 1u] == 0x55) {
                dispatch_eth_frame(frame + 12u, fl);
                pos += total;
                continue;
            }

            pos++;
        }

        if (pos > 0) {
            if (pos < rx_stream_len) {
                memmove(rx_stream.data(), rx_stream.data() + pos, rx_stream_len - pos);
            }
            rx_stream_len -= pos;
        }
    }

    void poll_ingress() {
        const uint16_t chunk_len = read_burst(rx_chunk.data());
        if (chunk_len == 0) {
            return;
        }
        process_rx_stream(chunk_len);
    }

    SPIClass spi;
    SemaphoreHandle_t spi_mutex{nullptr};
    bool ready{false};
    std::string last_error;

    std::array<uint8_t, RX_STREAM_CAPACITY> rx_stream{};
    std::array<uint8_t, RX_CHUNK_CAPACITY> rx_chunk{};
    size_t rx_stream_len{0};

    std::array<RxFrame, RX_QUEUE_CAPACITY> frame_queue{};
    size_t q_head{0};
    size_t q_tail{0};
    size_t q_count{0};

    bool lock_spi(uint32_t timeout_ms) {
        if (!spi_mutex) {
            return false;
        }
        return xSemaphoreTake(spi_mutex, pdMS_TO_TICKS(timeout_ms)) == pdTRUE;
    }

    void unlock_spi() {
        if (spi_mutex) {
            xSemaphoreGive(spi_mutex);
        }
    }
};

char cp_state_from_mv(int mv) {
    if (mv <= CP_NEG_THRESHOLD_MV) return 'F';
    if (mv >= (CP_T12_MV + CP_HYSTERESIS_MV)) return 'A';
    if (mv >= (CP_T9_MV + CP_HYSTERESIS_MV)) return 'B';
    if (mv >= (CP_T6_MV + CP_HYSTERESIS_MV)) return 'C';
    if (mv >= (CP_T3_MV + CP_HYSTERESIS_MV)) return 'D';
    if (mv >= (CP_T0_MV + CP_HYSTERESIS_MV)) return 'E';
    return 'F';
}

bool cp_connected(char s) {
    return s == 'B' || s == 'C' || s == 'D';
}

uint32_t cp_pct_to_duty(uint16_t pct) {
    if (pct == 0) return 0;
    if (pct >= 100) return CP_1_MAX_DUTY_CYCLE;
    return (CP_1_MAX_DUTY_CYCLE * static_cast<uint32_t>(pct)) / 100u;
}

const char* evse_state_name(slac::evse::State s) {
    switch (s) {
    case slac::evse::State::Reset:
        return "Reset";
    case slac::evse::State::Idle:
        return "Idle";
    case slac::evse::State::WaitForMatchingStart:
        return "WaitForMatchingStart";
    case slac::evse::State::Matching:
        return "Matching";
    case slac::evse::State::Sounding:
        return "Sounding";
    case slac::evse::State::DoAttenChar:
        return "DoAttenChar";
    case slac::evse::State::WaitForSlacMatch:
        return "WaitForSlacMatch";
    case slac::evse::State::Matched:
        return "Matched";
    case slac::evse::State::SignalError:
        return "SignalError";
    case slac::evse::State::NoSlacPerformed:
        return "NoSlacPerformed";
    case slac::evse::State::MatchingFailed:
        return "MatchingFailed";
    }
    return "Unknown";
}

static uint16_t g_cp_sample_phase_us = 0;

int read_cp_mv_robust() {
    int topk[CP_TOPK];
    int tk = 0;
    int peak = 0;

    auto insert_topk = [&](int v) {
        if (tk < CP_TOPK) {
            int i = tk++;
            while (i > 0 && topk[i - 1] > v) {
                topk[i] = topk[i - 1];
                --i;
            }
            topk[i] = v;
            return;
        }
        if (v <= topk[0]) {
            return;
        }
        topk[0] = v;
        int i = 0;
        while ((i + 1) < tk && topk[i] > topk[i + 1]) {
            const int t = topk[i];
            topk[i] = topk[i + 1];
            topk[i + 1] = t;
            ++i;
        }
    };

    if (g_cp_sample_phase_us) {
        delayMicroseconds(g_cp_sample_phase_us);
    }
    (void)analogRead(CP_1_READ_PIN);
    for (int i = 0; i < CP_SAMPLE_COUNT; ++i) {
        delayMicroseconds(CP_SAMPLE_DELAY_US);
        const int v = analogReadMilliVolts(CP_1_READ_PIN);
        if (v > peak) {
            peak = v;
        }
        insert_topk(v);
        if ((i & 31) == 31) {
            taskYIELD();
        }
    }

    g_cp_sample_phase_us = static_cast<uint16_t>((g_cp_sample_phase_us + 53U) % 1000U);
    if (tk <= 0) {
        return peak;
    }

    int start = tk - ((tk / 6 > 3) ? (tk / 6) : 3);
    int end = tk - (tk >= 6 ? 1 : 0);
    if (start < 0) start = 0;
    if (end <= start) {
        start = (tk > 3) ? (tk - 3) : 0;
        end = tk;
    }

    int64_t sum = 0;
    int n = 0;
    for (int i = start; i < end; ++i) {
        sum += topk[i];
        ++n;
    }
    if (n > 0) {
        return static_cast<int>(sum / n);
    }
    return topk[tk - 1];
}

std::shared_ptr<Qca7000Transport> g_transport;
slac::Channel g_channel;
std::unique_ptr<slac::evse::EvseFsm> g_fsm;
uint8_t g_local_mac[ETH_ALEN]{};

char g_cp_state = 'A';
char g_last_cp_state = 'A';
char g_cp_state_candidate = 'A';
uint32_t g_cp_candidate_since_ms = 0;
uint32_t g_cp_connected_since_ms = 0;

uint16_t g_last_cp_duty_pct = 100;
bool g_ef_pulse_active = false;
uint32_t g_ef_pulse_until_ms = 0;

bool g_session_started = false;
bool g_bcd_entered = false;
bool g_session_matched = false;
uint8_t g_slac_failures_this_cp = 0;
uint32_t g_slac_hold_until_ms = 0;
slac::evse::State g_last_fsm_state = slac::evse::State::Reset;
uint32_t g_next_qca_init_ms = 0;

typedef struct {
    jpv2g_secc_t* secc;
    bool precharge_seen;
    uint32_t precharge_count;
} HlcAppContext;

jpv2g_codec_ctx* g_codec = nullptr;
jpv2g_secc_t g_secc{};
HlcAppContext g_hlc_ctx{};
bool g_hlc_ready = false;
bool g_hlc_active = false;
uint8_t g_secc_ip[16] = {0};
uint32_t g_next_hlc_wait_log_ms = 0;
QueueHandle_t g_hlc_client_queue = nullptr;
TaskHandle_t g_hlc_worker_task = nullptr;
struct netif g_plc_netif{};
bool g_plc_netif_ready = false;
char g_plc_ifname[JPV2G_IFACE_NAME_MAX] = {0};
uint32_t g_next_lwip_drop_log_ms = 0;
struct LwipTxFrame {
    uint16_t len;
    uint8_t data[ETH_FRAME_LEN];
};
QueueHandle_t g_lwip_tx_queue = nullptr;
uint32_t g_next_lwip_tx_drop_log_ms = 0;

void ensure_lwip_socket_stack_ready() {
    static bool initialized = false;
    if (initialized) return;
    WiFi.mode(WIFI_STA);
    WiFi.setSleep(false);
    initialized = true;
    Serial.println("[NET] lwIP socket stack initialized (WiFi STA mode)");
}

void build_link_local_from_mac(const uint8_t mac[6], uint8_t out_ip[16]) {
    memset(out_ip, 0, 16);
    out_ip[0] = 0xFE;
    out_ip[1] = 0x80;
    out_ip[8] = static_cast<uint8_t>(mac[0] ^ 0x02U);
    out_ip[9] = mac[1];
    out_ip[10] = mac[2];
    out_ip[11] = 0xFF;
    out_ip[12] = 0xFE;
    out_ip[13] = mac[3];
    out_ip[14] = mac[4];
    out_ip[15] = mac[5];
}

bool ensure_lwip_tx_queue_ready() {
    if (g_lwip_tx_queue) {
        return true;
    }
    g_lwip_tx_queue = xQueueCreate(LWIP_TX_QUEUE_DEPTH, sizeof(LwipTxFrame));
    if (!g_lwip_tx_queue) {
        Serial.println("[NET] lwIP TX queue create failed");
        return false;
    }
    return true;
}

err_t plc_netif_linkoutput(struct netif* netif, struct pbuf* p) {
    (void)netif;
    if (!p || !g_lwip_tx_queue) {
        return ERR_IF;
    }

    const uint16_t total = static_cast<uint16_t>(p->tot_len);
    if (total == 0 || total > ETH_FRAME_LEN) {
        return ERR_IF;
    }

    LwipTxFrame frame{};
    frame.len = total;
    if (pbuf_copy_partial(p, frame.data, total, 0) != total) {
        return ERR_BUF;
    }
    if (xQueueSend(g_lwip_tx_queue, &frame, 0) != pdTRUE) {
        const uint32_t now = millis();
        if (g_next_lwip_tx_drop_log_ms == 0 || static_cast<int32_t>(now - g_next_lwip_tx_drop_log_ms) >= 0) {
            Serial.println("[NET] lwIP TX queue full, dropping frame");
            g_next_lwip_tx_drop_log_ms = now + 2000;
        }
        return ERR_MEM;
    }
    return ERR_OK;
}

err_t plc_netif_init(struct netif* netif) {
    if (!netif) return ERR_ARG;

    netif->name[0] = 'p';
    netif->name[1] = 'l';
    netif->mtu = 1500;
    netif->hwaddr_len = ETH_ALEN;
    memcpy(netif->hwaddr, g_local_mac, ETH_ALEN);
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET;
#if LWIP_IPV6_MLD
    netif->flags |= NETIF_FLAG_MLD6;
#endif
    netif->output = etharp_output;
    netif->output_ip6 = ethip6_output;
    netif->linkoutput = plc_netif_linkoutput;
    return ERR_OK;
}

bool init_plc_lwip_netif() {
    if (g_plc_netif_ready) {
        return true;
    }
    ensure_lwip_socket_stack_ready();
    if (!ensure_lwip_tx_queue_ready()) {
        return false;
    }

    memset(&g_plc_netif, 0, sizeof(g_plc_netif));
    err_t rc = ERR_OK;
    struct netif* added = nullptr;
    LOCK_TCPIP_CORE();
#if LWIP_IPV4
    ip4_addr_t ipaddr;
    ip4_addr_t netmask;
    ip4_addr_t gw;
    IP4_ADDR(&ipaddr, 0, 0, 0, 0);
    IP4_ADDR(&netmask, 0, 0, 0, 0);
    IP4_ADDR(&gw, 0, 0, 0, 0);
    added = netif_add(&g_plc_netif, &ipaddr, &netmask, &gw, nullptr, plc_netif_init, tcpip_input);
#else
    added = netif_add_noaddr(&g_plc_netif, nullptr, plc_netif_init, tcpip_input);
#endif
    if (!added) {
        rc = ERR_IF;
    } else {
        netif_set_default(&g_plc_netif);
        netif_set_up(&g_plc_netif);
        netif_set_link_up(&g_plc_netif);
#if LWIP_IPV6
        netif_create_ip6_linklocal_address(&g_plc_netif, 1);
#endif
    }
    UNLOCK_TCPIP_CORE();

    if (rc != ERR_OK) {
        Serial.printf("[NET] netif add failed err=%d\n", static_cast<int>(rc));
        return false;
    }

    snprintf(g_plc_ifname, sizeof(g_plc_ifname), "%c%c%u",
             g_plc_netif.name[0], g_plc_netif.name[1], static_cast<unsigned>(g_plc_netif.num));
    g_plc_netif_ready = true;
    Serial.printf("[NET] PLC lwIP netif ready: %s\n", g_plc_ifname);
    return true;
}

void lwip_ingress_ethernet_frame(const uint8_t* frame, uint16_t len) {
    if (!g_plc_netif_ready || !frame || len < 14U || len > ETH_FRAME_LEN) {
        return;
    }

    struct pbuf* p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
    if (!p) {
        const uint32_t now = millis();
        if (g_next_lwip_drop_log_ms == 0 || static_cast<int32_t>(now - g_next_lwip_drop_log_ms) >= 0) {
            Serial.println("[NET] lwIP RX drop: pbuf_alloc failed");
            g_next_lwip_drop_log_ms = now + 2000;
        }
        return;
    }

    if (pbuf_take(p, frame, len) != ERR_OK) {
        pbuf_free(p);
        return;
    }

    const err_t rc = g_plc_netif.input(p, &g_plc_netif);
    if (rc != ERR_OK) {
        pbuf_free(p);
        const uint32_t now = millis();
        if (g_next_lwip_drop_log_ms == 0 || static_cast<int32_t>(now - g_next_lwip_drop_log_ms) >= 0) {
            Serial.printf("[NET] lwIP RX drop: input err=%d\n", rc);
            g_next_lwip_drop_log_ms = now + 2000;
        }
    }
}

void service_lwip_tx_queue_once() {
    if (!g_lwip_tx_queue || !g_transport || !g_transport->is_ready()) {
        return;
    }
    LwipTxFrame frame{};
    while (xQueueReceive(g_lwip_tx_queue, &frame, 0) == pdTRUE) {
        if (frame.len == 0 || frame.len > ETH_FRAME_LEN) {
            continue;
        }
        const auto rc = g_transport->write(frame.data, frame.len, 20);
        if (rc != slac::ITransport::IOResult::Ok) {
            const uint32_t now = millis();
            if (g_next_lwip_tx_drop_log_ms == 0 || static_cast<int32_t>(now - g_next_lwip_tx_drop_log_ms) >= 0) {
                Serial.printf("[NET] lwIP TX write failed rc=%d\n", static_cast<int>(rc));
                g_next_lwip_tx_drop_log_ms = now + 2000;
            }
        }
    }
}

int hlc_handle_request(jpv2g_message_type_t type,
                       const void* decoded,
                       uint8_t* out,
                       size_t out_len,
                       size_t* written,
                       void* user_ctx) {
    HlcAppContext* ctx = static_cast<HlcAppContext*>(user_ctx);
    if (!ctx || !ctx->secc || !decoded) return -EINVAL;
    const jpv2g_secc_request_t* req = static_cast<const jpv2g_secc_request_t*>(decoded);
    if (type == JPV2G_PRE_CHARGE_REQ) {
        if (!ctx->precharge_seen) {
            Serial.println("[HLC] PreChargeReq received");
        }
        ctx->precharge_seen = true;
        ctx->precharge_count++;
    }
    return jpv2g_secc_default_handle(ctx->secc, type, req, out, out_len, written);
}

void hlc_worker_task_main(void* arg) {
    (void)arg;
    for (;;) {
        int client_fd = -1;
        if (!g_hlc_client_queue) {
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }
        if (xQueueReceive(g_hlc_client_queue, &client_fd, pdMS_TO_TICKS(1000)) != pdTRUE) {
            continue;
        }

        if (client_fd < 0) {
            continue;
        }

        if (!g_hlc_ready) {
            jpv2g_socket_close(client_fd);
            continue;
        }

        g_hlc_active = true;
        Serial.println("[HLC] EVCC connected, processing session");
        const int rc = jpv2g_secc_handle_client_detect(&g_secc, client_fd, HLC_FIRST_PACKET_TIMEOUT_MS, HLC_IDLE_TIMEOUT_MS);
        jpv2g_socket_close(client_fd);
        g_hlc_active = false;

        if (g_hlc_ctx.precharge_seen) {
            Serial.printf("[HLC] precharge reached, count=%lu\n", static_cast<unsigned long>(g_hlc_ctx.precharge_count));
        }
        Serial.printf("[HLC] client session done rc=%d\n", rc);
    }
}

bool ensure_hlc_worker_ready() {
    if (!g_hlc_client_queue) {
        g_hlc_client_queue = xQueueCreate(HLC_CLIENT_QUEUE_DEPTH, sizeof(int));
        if (!g_hlc_client_queue) {
            Serial.println("[HLC] queue create failed");
            return false;
        }
    }
    if (!g_hlc_worker_task) {
        const BaseType_t ok = xTaskCreatePinnedToCore(
            hlc_worker_task_main,
            "hlc_worker",
            HLC_TASK_STACK_WORDS,
            nullptr,
            2,
            &g_hlc_worker_task,
            ARDUINO_RUNNING_CORE);
        if (ok != pdPASS || !g_hlc_worker_task) {
            Serial.println("[HLC] worker task create failed");
            return false;
        }
        Serial.printf("[HLC] worker task started stack_bytes=%lu\n", static_cast<unsigned long>(HLC_TASK_STACK_WORDS));
    }
    return true;
}

void stop_hlc_stack() {
    if (!g_hlc_ready) return;
    if (g_hlc_client_queue) {
        int queued_fd = -1;
        while (xQueueReceive(g_hlc_client_queue, &queued_fd, 0) == pdTRUE) {
            if (queued_fd >= 0) {
                jpv2g_socket_close(queued_fd);
            }
        }
    }
    jpv2g_secc_stop(&g_secc);
    if (g_codec) {
        jpv2g_codec_free(g_codec);
        g_codec = nullptr;
    }
    memset(&g_secc, 0, sizeof(g_secc));
    memset(&g_hlc_ctx, 0, sizeof(g_hlc_ctx));
    g_hlc_ready = false;
    g_hlc_active = false;
}

bool init_hlc_stack() {
    if (g_hlc_ready) return true;
    ensure_lwip_socket_stack_ready();
    if (!g_plc_netif_ready && !init_plc_lwip_netif()) {
        Serial.println("[HLC] PLC netif unavailable");
        return false;
    }

    int rc = jpv2g_codec_init(&g_codec);
    if (rc != 0 || !g_codec) {
        Serial.printf("[HLC] codec init failed rc=%d\n", rc);
        return false;
    }

    jpv2g_secc_config_t cfg;
    jpv2g_secc_config_default(&cfg);
    cfg.network_interface[0] = '\0';
    cfg.use_tls = false;
    cfg.tcp_port = 15118;
    cfg.tls_port = 15118;
    Serial.printf("[HLC] bind iface=%s (plc=%s)\n",
                  cfg.network_interface[0] ? cfg.network_interface : "<default>",
                  g_plc_ifname[0] ? g_plc_ifname : "<none>");

    rc = jpv2g_secc_init(&g_secc, &cfg, g_codec);
    if (rc != 0) {
        Serial.printf("[HLC] secc init failed rc=%d\n", rc);
        jpv2g_codec_free(g_codec);
        g_codec = nullptr;
        return false;
    }
    jpv2g_secc_set_decoded_logs(ENABLE_DECODED_LOGS);

    g_hlc_ctx.secc = &g_secc;
    g_hlc_ctx.precharge_seen = false;
    g_hlc_ctx.precharge_count = 0;
    g_secc.handle_request = hlc_handle_request;
    g_secc.user_ctx = &g_hlc_ctx;
    if (!ensure_hlc_worker_ready()) {
        stop_hlc_stack();
        return false;
    }

    rc = jpv2g_secc_start_udp(&g_secc);
    if (rc != 0) {
        Serial.printf("[HLC] SDP UDP start failed rc=%d\n", rc);
        stop_hlc_stack();
        return false;
    }
    rc = jpv2g_secc_start_tcp(&g_secc);
    if (rc != 0) {
        Serial.printf("[HLC] TCP start failed rc=%d\n", rc);
        stop_hlc_stack();
        return false;
    }

    g_hlc_ready = true;
    g_next_hlc_wait_log_ms = millis();
    Serial.println("[HLC] stack ready (SDP+TCP on 15118)");
    return true;
}

void service_sdp_once() {
    if (!g_hlc_ready) return;

    uint8_t in_buf[256];
    struct sockaddr_in6 from;
    socklen_t from_len = sizeof(from);
    int rc = jpv2g_udp_server_recv(&g_secc.udp, in_buf, sizeof(in_buf), &from, &from_len, 0);
    if (rc <= 0) {
        return;
    }

    jpv2g_v2gtp_t msg;
    if (jpv2g_v2gtp_parse(in_buf, static_cast<size_t>(rc), &msg) != 0) return;
    if (msg.payload_type != JPV2G_PAYLOAD_SDP_REQ) return;

    jpv2g_sdp_req_t req;
    if (jpv2g_sdp_req_decode(msg.payload, msg.payload_length, &req) != 0) return;
    if (req.transport_protocol != JPV2G_TRANSPORT_TCP) return;

    jpv2g_sdp_res_t res;
    memset(&res, 0, sizeof(res));
    memcpy(res.secc_ip, g_secc_ip, sizeof(res.secc_ip));
    res.secc_port = static_cast<uint16_t>(g_secc.cfg.tcp_port);
    res.security = g_secc.cfg.use_tls ? JPV2G_SECURITY_WITH_TLS : JPV2G_SECURITY_WITHOUT_TLS;
    res.transport_protocol = JPV2G_TRANSPORT_TCP;

    uint8_t payload[32];
    size_t payload_len = 0;
    if (jpv2g_sdp_res_encode(&res, payload, sizeof(payload), &payload_len) != 0) return;

    uint8_t out[64];
    size_t out_len = 0;
    if (jpv2g_v2gtp_build(JPV2G_PAYLOAD_SDP_RES, payload, payload_len, out, sizeof(out), &out_len) != 0) return;
    (void)jpv2g_udp_server_sendto(&g_secc.udp, out, out_len, &from, from_len);

    Serial.printf("[SDP] req sec=0x%02X tp=0x%02X -> res port=%u sec=0x%02X\n",
                  req.security, req.transport_protocol, res.secc_port, res.security);
}

void service_hlc_tcp_once() {
    if (!g_hlc_ready) return;

    int client_fd = -1;
    struct sockaddr_in6 client_addr;
    socklen_t client_len = sizeof(client_addr);
    int rc = jpv2g_tcp_server_accept(&g_secc.tcp, &client_fd, &client_addr, &client_len, 0);
    if (rc == -EAGAIN || rc == -ETIMEDOUT) {
        const uint32_t now = millis();
        if (static_cast<int32_t>(now - g_next_hlc_wait_log_ms) >= 0) {
            Serial.println("[HLC] waiting for EVCC TCP client...");
            g_next_hlc_wait_log_ms = now + 5000;
        }
        return;
    }
    if (rc != 0) {
        Serial.printf("[HLC] accept failed rc=%d\n", rc);
        return;
    }

    if (!g_hlc_client_queue) {
        Serial.println("[HLC] client queue unavailable");
        jpv2g_socket_close(client_fd);
        return;
    }
    if (xQueueSend(g_hlc_client_queue, &client_fd, 0) != pdTRUE) {
        Serial.println("[HLC] client queue full, dropping session");
        jpv2g_socket_close(client_fd);
        return;
    }
    Serial.println("[HLC] EVCC connected, handed off to worker");
}

void apply_cp_output(char state, uint32_t now_ms) {
    const bool connected = cp_connected(state);
    if (g_ef_pulse_active && static_cast<int32_t>(now_ms - g_ef_pulse_until_ms) >= 0) {
        g_ef_pulse_active = false;
    }

    const bool hold_active = static_cast<int32_t>(now_ms - g_slac_hold_until_ms) < 0;
    const bool pwm_ok = connected && !hold_active && !g_ef_pulse_active;
    uint16_t pct = g_ef_pulse_active ? 0u : (pwm_ok ? 5u : 100u);
    if (pct != g_last_cp_duty_pct) {
        Serial.printf("[CP] duty -> %u%% (state=%c hold=%d ef=%d)\n", pct, state, hold_active ? 1 : 0,
                      g_ef_pulse_active ? 1 : 0);
        g_last_cp_duty_pct = pct;
    }
    ledcWrite(CP_1_PWM_CHANNEL, cp_pct_to_duty(g_last_cp_duty_pct));
}

void start_session(uint32_t now_ms) {
    if (!g_fsm) {
        return;
    }
    g_fsm->start(now_ms);
    g_session_started = true;
    g_bcd_entered = false;
    g_session_matched = false;
    g_last_fsm_state = g_fsm->get_state();
    Serial.println("[SLAC] session start");
}

void stop_session(uint32_t now_ms) {
    if (g_fsm && g_session_started) {
        g_fsm->leave_bcd(now_ms);
    }
    g_session_started = false;
    g_bcd_entered = false;
    g_session_matched = false;
    g_last_fsm_state = slac::evse::State::Reset;
}

void enter_hold_with_optional_ef_pulse(uint32_t now_ms, const char* reason) {
    if (g_slac_failures_this_cp < 0xFF) {
        g_slac_failures_this_cp++;
    }
    if (EF_PULSE_AFTER_FAILURES > 0 && g_slac_failures_this_cp >= EF_PULSE_AFTER_FAILURES) {
        g_ef_pulse_active = true;
        g_ef_pulse_until_ms = now_ms + CP_EF_PULSE_MS;
        Serial.printf("[CP] E/F pulse for %lu ms\n", static_cast<unsigned long>(CP_EF_PULSE_MS));
    }
    g_slac_hold_until_ms = now_ms + SLAC_HOLD_MS;
    stop_session(now_ms);
    Serial.printf("[SLAC] enter hold (%s) %lu ms\n", reason ? reason : "-", static_cast<unsigned long>(SLAC_HOLD_MS));
}

bool try_init_qca_and_fsm(uint32_t now_ms) {
    if (!g_transport) {
        g_transport = std::make_shared<Qca7000Transport>();
    }

    if (!g_transport->begin()) {
        Serial.printf("[QCA] init failed: %s\n", g_transport->get_error().c_str());
        g_next_qca_init_ms = now_ms + QCA_INIT_RETRY_MS;
        return false;
    }
    Serial.println("[QCA] transport ready");

    g_transport->modem_reset();
    delay(150);

    if (!g_channel.open(g_transport, g_local_mac)) {
        Serial.printf("[SLAC] channel open failed: %s\n", g_channel.get_error().c_str());
        g_next_qca_init_ms = now_ms + QCA_INIT_RETRY_MS;
        return false;
    }

    if (!g_plc_netif_ready) {
        (void)init_plc_lwip_netif();
    }

    g_fsm = std::make_unique<slac::evse::EvseFsm>(g_channel, [](const std::string& msg) {
        Serial.printf("[FSM] %s\n", msg.c_str());
    });

    const uint8_t plc_peer_mac[ETH_ALEN] = {
        static_cast<uint8_t>((PLC_PEER_MAC_DEFAULT[0] >> 8) & 0xFF),
        static_cast<uint8_t>((PLC_PEER_MAC_DEFAULT[0] >> 0) & 0xFF),
        static_cast<uint8_t>((PLC_PEER_MAC_DEFAULT[1] >> 8) & 0xFF),
        static_cast<uint8_t>((PLC_PEER_MAC_DEFAULT[1] >> 0) & 0xFF),
        static_cast<uint8_t>((PLC_PEER_MAC_DEFAULT[2] >> 8) & 0xFF),
        static_cast<uint8_t>((PLC_PEER_MAC_DEFAULT[2] >> 0) & 0xFF),
    };
    g_fsm->set_plc_peer_mac(plc_peer_mac);
    g_next_qca_init_ms = 0;
    Serial.println("[APP] ready, waiting for CP B/C/D");
    return true;
}

void process_cp_and_fsm(uint32_t now_ms) {
    const int cp_mv = read_cp_mv_robust();
    const char raw_cp_state = cp_state_from_mv(cp_mv);
    if (raw_cp_state != g_cp_state_candidate) {
        g_cp_state_candidate = raw_cp_state;
        g_cp_candidate_since_ms = now_ms;
    }
    if (g_cp_state_candidate != g_cp_state) {
        const bool was_connected = cp_connected(g_cp_state);
        const bool candidate_connected = cp_connected(g_cp_state_candidate);
        const uint32_t debounce_ms =
            (was_connected && !candidate_connected) ? CP_DISCONNECT_DEBOUNCE_MS : CP_STATE_DEBOUNCE_MS;
        if (static_cast<int32_t>(now_ms - g_cp_candidate_since_ms) >= static_cast<int32_t>(debounce_ms)) {
            g_cp_state = g_cp_state_candidate;
        }
    }
    const bool connected = cp_connected(g_cp_state);

    if (g_cp_state != g_last_cp_state) {
        Serial.printf("[CP] state %c -> %c (%d mV)\n", g_last_cp_state, g_cp_state, cp_mv);
        const bool old_connected = cp_connected(g_last_cp_state);
        if (connected && !old_connected) {
            g_cp_connected_since_ms = now_ms;
            g_slac_failures_this_cp = 0;
            g_slac_hold_until_ms = 0;
        } else if (!connected && old_connected) {
            g_cp_connected_since_ms = 0;
            g_slac_hold_until_ms = 0;
            g_slac_failures_this_cp = 0;
            stop_session(now_ms);
            stop_hlc_stack();
        }
        g_last_cp_state = g_cp_state;
    }

    apply_cp_output(g_cp_state, now_ms);

    if (!connected) {
        return;
    }

    if (!g_session_started && g_cp_connected_since_ms != 0 &&
        (now_ms - g_cp_connected_since_ms) >= CP_STABLE_MS &&
        static_cast<int32_t>(now_ms - g_slac_hold_until_ms) >= 0) {
        start_session(now_ms);
    }

    if (!g_session_started || !g_fsm) {
        return;
    }

    g_fsm->poll_channel_once(2, now_ms);
    g_fsm->poll(now_ms);

    // The EVSE FSM requires an explicit LinkDetected event after CM_SLAC_MATCH.REQ.
    // In this MCU test app, use "match request received" as the trigger source.
    if (g_fsm->get_state() == slac::evse::State::WaitForSlacMatch && g_fsm->received_slac_match()) {
        Serial.println("[SLAC] match request received, signaling link detected");
        g_fsm->notify_link_detected(now_ms);
    }

    const slac::evse::State s = g_fsm->get_state();
    if (s != g_last_fsm_state) {
        Serial.printf("[FSM] %s -> %s\n", evse_state_name(g_last_fsm_state), evse_state_name(s));
        g_last_fsm_state = s;
    }

    if (!g_bcd_entered && s == slac::evse::State::Idle) {
        g_fsm->enter_bcd(now_ms);
        g_bcd_entered = true;
        Serial.println("[FSM] EnterBCD");
    }

    if (s == slac::evse::State::Matched && !g_session_matched) {
        g_session_matched = true;
        Serial.println("[SLAC] MATCHED - starting HLC stack");
    } else if (s == slac::evse::State::MatchingFailed || s == slac::evse::State::NoSlacPerformed) {
        enter_hold_with_optional_ef_pulse(now_ms, "fsm terminal failure");
        stop_hlc_stack();
    }

    if (g_session_matched && !g_hlc_ready) {
        (void)init_hlc_stack();
    }

    if (g_session_matched && g_hlc_ready) {
        service_sdp_once();
        service_hlc_tcp_once();
    }
}

} // namespace

void setup() {
    Serial.begin(115200);
    delay(200);

    Serial.println();
    Serial.println("cbslac + jpv2g ESP32-S3 SLAC/HLC (to PreCharge)");
    Serial.printf("[BOOT] startup log hold %lu ms\n", static_cast<unsigned long>(STARTUP_LOG_DELAY_MS));
    const uint32_t hold_start = millis();
    uint32_t next_tick = hold_start + 1000;
    while ((millis() - hold_start) < STARTUP_LOG_DELAY_MS) {
        const uint32_t now = millis();
        if (static_cast<int32_t>(now - next_tick) >= 0) {
            const uint32_t elapsed = now - hold_start;
            Serial.printf("[BOOT] waiting... %lu/%lu ms\n",
                          static_cast<unsigned long>(elapsed),
                          static_cast<unsigned long>(STARTUP_LOG_DELAY_MS));
            next_tick += 1000;
        }
        delay(10);
    }

    esp_read_mac(g_local_mac, ESP_MAC_WIFI_STA);
    Serial.printf("[NET] local MAC %02X:%02X:%02X:%02X:%02X:%02X\n",
                  g_local_mac[0], g_local_mac[1], g_local_mac[2], g_local_mac[3], g_local_mac[4], g_local_mac[5]);
    build_link_local_from_mac(g_local_mac, g_secc_ip);
    Serial.printf("[NET] SECC IPv6 LL fe80::%02x%02x:%02xff:fe%02x:%02x%02x\n",
                  static_cast<unsigned>(g_secc_ip[8]),
                  static_cast<unsigned>(g_secc_ip[9]),
                  static_cast<unsigned>(g_secc_ip[10]),
                  static_cast<unsigned>(g_secc_ip[13]),
                  static_cast<unsigned>(g_secc_ip[14]),
                  static_cast<unsigned>(g_secc_ip[15]));

    analogReadResolution(12);
    analogSetPinAttenuation(CP_1_READ_PIN, ADC_11db);
    ledcSetup(CP_1_PWM_CHANNEL, CP_1_PWM_FREQUENCY, CP_1_PWM_RESOLUTION);
    ledcAttachPin(CP_1_PWM_PIN, CP_1_PWM_CHANNEL);
    ledcWrite(CP_1_PWM_CHANNEL, cp_pct_to_duty(100));

    (void)try_init_qca_and_fsm(millis());
}

void loop() {
    const uint32_t now_ms = millis();
    if (!g_fsm && static_cast<int32_t>(now_ms - g_next_qca_init_ms) >= 0) {
        (void)try_init_qca_and_fsm(now_ms);
    }
    if (g_transport && g_transport->is_ready()) {
        g_transport->service_ingress_once();
    }
    process_cp_and_fsm(now_ms);
    service_lwip_tx_queue_once();
    delay(5);
}
