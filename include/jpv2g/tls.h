/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "jpv2g/platform_compat.h"

/*
 * In-memory PEM credentials for the SECC TLS server. This is the primary
 * credential path on the PLC, which has no filesystem PKI: the firmware
 * points these at compiled-in (dev) or NVS-loaded (production) buffers.
 *
 * mbedtls 2.x PEM rule: each buffer must be NUL-terminated and its *_len
 * must COUNT the terminating NUL (sizeof a string literal satisfies both).
 * jpv2g_tls_credentials_validate() enforces this before any parsing.
 *
 * The struct itself is mbedtls-free so it can live in jpv2g_secc_config_t
 * unconditionally; without HAVE_MBEDTLS the buffers are simply never read.
 */
typedef struct {
    const uint8_t *cert_pem;  /* server certificate (chain), PEM incl. NUL */
    size_t cert_pem_len;      /* length INCLUDING the trailing NUL */
    const uint8_t *key_pem;   /* server private key, PEM incl. NUL */
    size_t key_pem_len;       /* length INCLUDING the trailing NUL */
    const uint8_t *ca_pem;    /* optional trust chain; NULL = no client auth */
    size_t ca_pem_len;        /* 0 when ca_pem is NULL */
} jpv2g_tls_credentials_t;

/*
 * Default server-handshake deadline. ISO 15118-2 gives the EV
 * V2G_SECC_Sequence_Timeout-scale patience; a peer that opens TCP, sends
 * a ClientHello prefix and goes silent must not pin the HLC worker
 * forever (the pre-rewrite loop spun on WANT_READ with no bound).
 */
#define JPV2G_TLS_HANDSHAKE_TIMEOUT_MS 15000

typedef struct {
    int fd;
    bool secure;
#ifdef HAVE_MBEDTLS
    struct mbedtls_ssl_context *ssl;
    struct mbedtls_ssl_config *conf;
    struct mbedtls_ctr_drbg_context *ctr_drbg;
    struct mbedtls_entropy_context *entropy;
    /* Owned parse results handed to conf; stored here so jpv2g_tls_close()
     * can free them (they leaked before this rewrite). */
    struct mbedtls_x509_crt *ca_chain;
    struct mbedtls_x509_crt *own_cert;
    struct mbedtls_pk_context *own_key;
#endif
} jpv2g_tls_socket_t;

/* Shape-check credentials (presence + PEM NUL rule). Returns 0 or -EINVAL.
 * Available in every build so hosts without mbedtls can test the contract. */
int jpv2g_tls_credentials_validate(const jpv2g_tls_credentials_t *creds);

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

/* In-memory-credential server wrap. handshake_timeout_ms <= 0 selects
 * JPV2G_TLS_HANDSHAKE_TIMEOUT_MS. On failure the fd stays with the caller
 * (same contract as jpv2g_tls_server_wrap); without HAVE_MBEDTLS this
 * returns -ENOTSUP. */
int jpv2g_tls_server_wrap_mem(jpv2g_tls_socket_t *sock,
                                int client_fd,
                                const jpv2g_tls_credentials_t *creds,
                                int handshake_timeout_ms);

ssize_t jpv2g_tls_send(jpv2g_tls_socket_t *sock, const uint8_t *buf, size_t len);
ssize_t jpv2g_tls_recv(jpv2g_tls_socket_t *sock, uint8_t *buf, size_t len, int timeout_ms);
void jpv2g_tls_close(jpv2g_tls_socket_t *sock);
