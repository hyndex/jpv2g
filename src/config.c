/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#include "jpv2g/config.h"
#include "jpv2g/net_iface.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef JPV2G_PKI_BASE
#define JPV2G_PKI_BASE "certs"
#endif

static void set_pki_path(char *dst, size_t dst_len, const char *leaf) {
    const char *base = JPV2G_PKI_BASE;
    if (!dst || dst_len == 0 || !leaf) return;
    size_t base_len = strlen(base);
    const bool trailing_slash = (base_len > 0 && base[base_len - 1] == '/');
    snprintf(dst, dst_len, trailing_slash ? "%s%s" : "%s/%s", base, leaf);
    dst[dst_len - 1] = '\0';
}

void jpv2g_evcc_config_default(jpv2g_evcc_config_t *cfg) {
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));
    jpv2g_iface_select(NULL, cfg->network_interface, NULL);
#if defined(CONFIG_IDF_TARGET_ESP32) || defined(ARDUINO_ARCH_ESP32)
    /* lwIP on ESP32 often names the PLC interface "pl0"; use it if nothing was auto-resolved. */
    if (!cfg->network_interface[0]) {
        jpv2g_iface_select("pl0", cfg->network_interface, NULL);
    }
#endif
    cfg->use_tls = false;
    strncpy(cfg->session_id_hex, "00", sizeof(cfg->session_id_hex) - 1);
    strncpy(cfg->auth_mode, "Contract", sizeof(cfg->auth_mode) - 1);
    strncpy(cfg->energy_mode, "AC_three_phase_core", sizeof(cfg->energy_mode) - 1);
    cfg->contract_cert_update_days = 14;
    cfg->tls_port = 15118;
    cfg->tcp_port = 15118;
    set_pki_path(cfg->tls_cert_path, sizeof(cfg->tls_cert_path), "evcc_client.fullchain.crt.pem");
    set_pki_path(cfg->tls_key_path, sizeof(cfg->tls_key_path), "evcc_client.key.pem");
    set_pki_path(cfg->tls_ca_path, sizeof(cfg->tls_ca_path), "trust_evcc_ca.pem");
}

void jpv2g_secc_config_default(jpv2g_secc_config_t *cfg) {
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));
    jpv2g_iface_select(NULL, cfg->network_interface, NULL);
#if defined(CONFIG_IDF_TARGET_ESP32) || defined(ARDUINO_ARCH_ESP32)
    if (!cfg->network_interface[0]) {
        jpv2g_iface_select("pl0", cfg->network_interface, NULL);
    }
#endif
    cfg->free_charging = false;
    cfg->private_environment = false;
    cfg->use_tls = true;
    strncpy(cfg->supported_auth_modes, "Contract,ExternalPayment", sizeof(cfg->supported_auth_modes) - 1);
    strncpy(cfg->supported_energy_modes, "AC_three_phase_core,AC_single_phase_core,DC_core,DC_extended,DC_combo_core",
            sizeof(cfg->supported_energy_modes) - 1);
    cfg->tls_port = 15118;
    cfg->tcp_port = 15118;
    set_pki_path(cfg->tls_cert_path, sizeof(cfg->tls_cert_path), "secc_chain.crt.pem");
    set_pki_path(cfg->tls_key_path, sizeof(cfg->tls_key_path), "secc_leaf.key.pem");
    set_pki_path(cfg->tls_ca_path, sizeof(cfg->tls_ca_path), "trust_v2g_roots.pem");
}
