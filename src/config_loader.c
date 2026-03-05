/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#include "jpv2g/config_loader.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jpv2g/log.h"

static char *trim(char *s) {
    if (!s) return s;
    while (isspace((unsigned char)*s)) s++;
    if (*s == 0) return s;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return s;
}

static int load_file(const char *path, jpv2g_evcc_config_t *evcc, jpv2g_secc_config_t *secc) {
    FILE *f = fopen(path, "r");
    if (!f) return -errno;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *p = trim(line);
        if (*p == '\0' || *p == '#' || *p == ';') continue;
        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = trim(p);
        char *val = trim(eq + 1);

        if (evcc) {
            if (strcmp(key, "network.interface") == 0) {
                strncpy(evcc->network_interface, val, sizeof(evcc->network_interface) - 1);
            } else if (strcmp(key, "tls") == 0) {
                evcc->use_tls = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
            } else if (strcmp(key, "tls.cert") == 0) {
                strncpy(evcc->tls_cert_path, val, sizeof(evcc->tls_cert_path) - 1);
            } else if (strcmp(key, "tls.key") == 0) {
                strncpy(evcc->tls_key_path, val, sizeof(evcc->tls_key_path) - 1);
            } else if (strcmp(key, "tls.ca") == 0) {
                strncpy(evcc->tls_ca_path, val, sizeof(evcc->tls_ca_path) - 1);
            } else if (strcmp(key, "session.id") == 0) {
                strncpy(evcc->session_id_hex, val, sizeof(evcc->session_id_hex) - 1);
            } else if (strcmp(key, "authentication.mode") == 0) {
                strncpy(evcc->auth_mode, val, sizeof(evcc->auth_mode) - 1);
            } else if (strcmp(key, "energy.transfermode.requested") == 0) {
                strncpy(evcc->energy_mode, val, sizeof(evcc->energy_mode) - 1);
            } else if (strcmp(key, "contract.certificate.update.timespan") == 0) {
                evcc->contract_cert_update_days = atoi(val);
            }
        }

        if (secc) {
            if (strcmp(key, "network.interface") == 0) {
                strncpy(secc->network_interface, val, sizeof(secc->network_interface) - 1);
            } else if (strcmp(key, "charging.free") == 0) {
                secc->free_charging = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
            } else if (strcmp(key, "environment.private") == 0) {
                secc->private_environment = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
            } else if (strcmp(key, "tls") == 0) {
                secc->use_tls = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
            } else if (strcmp(key, "tls.cert") == 0) {
                strncpy(secc->tls_cert_path, val, sizeof(secc->tls_cert_path) - 1);
            } else if (strcmp(key, "tls.key") == 0) {
                strncpy(secc->tls_key_path, val, sizeof(secc->tls_key_path) - 1);
            } else if (strcmp(key, "tls.ca") == 0) {
                strncpy(secc->tls_ca_path, val, sizeof(secc->tls_ca_path) - 1);
            } else if (strcmp(key, "authentication.modes.supported") == 0) {
                strncpy(secc->supported_auth_modes, val, sizeof(secc->supported_auth_modes) - 1);
            } else if (strcmp(key, "energy.transfermodes.supported") == 0) {
                strncpy(secc->supported_energy_modes, val, sizeof(secc->supported_energy_modes) - 1);
            }
        }
    }
    fclose(f);
    return 0;
}

int jpv2g_load_evcc_config(const char *path, jpv2g_evcc_config_t *cfg) {
    if (!cfg) return -EINVAL;
    jpv2g_evcc_config_default(cfg);
    if (!path) return 0;
    int rc = load_file(path, cfg, NULL);
    if (rc != 0) {
        JPV2G_WARN("EVCC config load failed from %s (%d); using defaults", path, rc);
    }
    return rc;
}

int jpv2g_load_secc_config(const char *path, jpv2g_secc_config_t *cfg) {
    if (!cfg) return -EINVAL;
    jpv2g_secc_config_default(cfg);
    if (!path) return 0;
    int rc = load_file(path, NULL, cfg);
    if (rc != 0) {
        JPV2G_WARN("SECC config load failed from %s (%d); using defaults", path, rc);
    }
    return rc;
}
