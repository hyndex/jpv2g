/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#define JPV2G_IFACE_NAME_MAX 32
#define JPV2G_AUTH_MODE_MAX 32
#define JPV2G_ENERGY_MODE_MAX 128
#define JPV2G_PATH_MAX 256

typedef struct {
    char network_interface[JPV2G_IFACE_NAME_MAX];
    bool use_tls;
    char session_id_hex[32]; /* up to 8 bytes hex encoded */
    char auth_mode[JPV2G_AUTH_MODE_MAX];
    char energy_mode[JPV2G_ENERGY_MODE_MAX];
    int contract_cert_update_days;
    int tls_port;
    int tcp_port;
    char tls_cert_path[JPV2G_PATH_MAX];
    char tls_key_path[JPV2G_PATH_MAX];
    char tls_ca_path[JPV2G_PATH_MAX];
} jpv2g_evcc_config_t;

typedef struct {
    char network_interface[JPV2G_IFACE_NAME_MAX];
    bool free_charging;
    bool private_environment;
    bool use_tls;
    char supported_auth_modes[JPV2G_AUTH_MODE_MAX];
    char supported_energy_modes[JPV2G_ENERGY_MODE_MAX];
    int tls_port;
    int tcp_port;
    char tls_cert_path[JPV2G_PATH_MAX];
    char tls_key_path[JPV2G_PATH_MAX];
    char tls_ca_path[JPV2G_PATH_MAX];
} jpv2g_secc_config_t;

void jpv2g_evcc_config_default(jpv2g_evcc_config_t *cfg);
void jpv2g_secc_config_default(jpv2g_secc_config_t *cfg);
