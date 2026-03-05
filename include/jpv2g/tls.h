/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "jpv2g/platform_compat.h"

typedef struct {
    int fd;
    bool secure;
#ifdef HAVE_MBEDTLS
    struct mbedtls_ssl_context *ssl;
    struct mbedtls_ssl_config *conf;
    struct mbedtls_ctr_drbg_context *ctr_drbg;
    struct mbedtls_entropy_context *entropy;
    struct mbedtls_net_context *net;
#endif
} jpv2g_tls_socket_t;

int jpv2g_tls_client_connect(jpv2g_tls_socket_t *sock,
                               const struct sockaddr_in6 *addr,
                               socklen_t addrlen,
                               const char *cert_path,
                               const char *key_path,
                               const char *ca_path,
                               int timeout_ms);

int jpv2g_tls_server_wrap(jpv2g_tls_socket_t *sock,
                            int client_fd,
                            const char *cert_path,
                            const char *key_path,
                            const char *ca_path);

ssize_t jpv2g_tls_send(jpv2g_tls_socket_t *sock, const uint8_t *buf, size_t len);
ssize_t jpv2g_tls_recv(jpv2g_tls_socket_t *sock, uint8_t *buf, size_t len, int timeout_ms);
void jpv2g_tls_close(jpv2g_tls_socket_t *sock);
