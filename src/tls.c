/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#include "jpv2g/tls.h"

#include <errno.h>
#include "jpv2g/poll_compat.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "jpv2g/log.h"
#include "jpv2g/time_compat.h"

#ifdef HAVE_MBEDTLS

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>


static int seed_rng(mbedtls_ctr_drbg_context *ctr_drbg, mbedtls_entropy_context *entropy) {
    mbedtls_entropy_init(entropy);
    mbedtls_ctr_drbg_init(ctr_drbg);
    const char *pers = "jpv2g_tls";
    int rc = mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy, (const unsigned char *)pers, strlen(pers));
    return rc;
}

static int setup_ssl_common(jpv2g_tls_socket_t *sock,
                            bool is_server,
                            const char *cert_path,
                            const char *key_path,
                            const char *ca_path) {
    if (!sock) return -EINVAL;
    sock->ssl = calloc(1, sizeof(mbedtls_ssl_context));
    sock->conf = calloc(1, sizeof(mbedtls_ssl_config));
    sock->ctr_drbg = calloc(1, sizeof(mbedtls_ctr_drbg_context));
    sock->entropy = calloc(1, sizeof(mbedtls_entropy_context));
    if (!sock->ssl || !sock->conf || !sock->ctr_drbg || !sock->entropy) return -ENOMEM;

    mbedtls_ssl_init(sock->ssl);
    mbedtls_ssl_config_init(sock->conf);

    int rc = seed_rng(sock->ctr_drbg, sock->entropy);
    if (rc != 0) return rc;

    rc = mbedtls_ssl_config_defaults(sock->conf,
                                     is_server ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT,
                                     MBEDTLS_SSL_TRANSPORT_STREAM,
                                     MBEDTLS_SSL_PRESET_DEFAULT);
    if (rc != 0) return rc;

    /* Enforce verification when CA is provided on either side. */
    if (ca_path) {
        mbedtls_ssl_conf_authmode(sock->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    } else {
        mbedtls_ssl_conf_authmode(sock->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    }
    mbedtls_ssl_conf_rng(sock->conf, mbedtls_ctr_drbg_random, sock->ctr_drbg);

    mbedtls_x509_crt *cacert = NULL;
    mbedtls_x509_crt *owncert = NULL;
    mbedtls_pk_context *pkey = NULL;

    if (ca_path) {
        cacert = calloc(1, sizeof(mbedtls_x509_crt));
        mbedtls_x509_crt_init(cacert);
        rc = mbedtls_x509_crt_parse_file(cacert, ca_path);
        if (rc != 0) return rc;
        mbedtls_ssl_conf_ca_chain(sock->conf, cacert, NULL);
    }
    if (cert_path && key_path) {
        owncert = calloc(1, sizeof(mbedtls_x509_crt));
        pkey = calloc(1, sizeof(mbedtls_pk_context));
        mbedtls_x509_crt_init(owncert);
        mbedtls_pk_init(pkey);
        rc = mbedtls_x509_crt_parse_file(owncert, cert_path);
        if (rc != 0) return rc;
        rc = mbedtls_pk_parse_keyfile(pkey, key_path, NULL);
        if (rc != 0) return rc;
        rc = mbedtls_ssl_conf_own_cert(sock->conf, owncert, pkey);
        if (rc != 0) return rc;
    }

    rc = mbedtls_ssl_setup(sock->ssl, sock->conf);
    if (rc != 0) return rc;
    mbedtls_ssl_set_bio(sock->ssl, sock->net, mbedtls_net_send, mbedtls_net_recv, NULL);
    return 0;
}

#ifdef HAVE_MBEDTLS

int jpv2g_tls_client_connect(jpv2g_tls_socket_t *sock,
                               const struct sockaddr_in6 *addr,
                               socklen_t addrlen,
                               const char *cert_path,
                               const char *key_path,
                               const char *ca_path,
                               int timeout_ms) {
    if (!sock || !addr) return -EINVAL;
    sock->net = calloc(1, sizeof(mbedtls_net_context));
    if (!sock->net) return -ENOMEM;
    mbedtls_net_init(sock->net);
    int fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0) return -errno;
    int rc = connect(fd, (const struct sockaddr *)addr, addrlen);
    if (rc < 0 && errno != EINPROGRESS) {
        int err = -errno;
        jpv2g_socket_close(fd);
        return err;
    }
    if (rc < 0) {
        struct pollfd pfd = {.fd = fd, .events = POLLOUT};
        int prc = poll(&pfd, 1, timeout_ms);
        if (prc <= 0) {
            int err = prc == 0 ? -ETIMEDOUT : -errno;
            jpv2g_socket_close(fd);
            return err;
        }
        int soerr = 0;
        socklen_t slen = sizeof(soerr);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) < 0 || soerr != 0) {
            int err = soerr ? -soerr : -errno;
            jpv2g_socket_close(fd);
            return err;
        }
    }
    sock->net->fd = fd;
    sock->fd = fd;
    rc = setup_ssl_common(sock, false, cert_path, key_path, ca_path);
    if (rc != 0) {
        JPV2G_ERROR("TLS client setup failed (%d)", rc);
        return rc;
    }
    mbedtls_ssl_set_bio(sock->ssl, sock->net, mbedtls_net_send, mbedtls_net_recv, NULL);
    uint64_t start = 0;
    while ((rc = mbedtls_ssl_handshake(sock->ssl)) != 0) {
        if (rc != MBEDTLS_ERR_SSL_WANT_READ && rc != MBEDTLS_ERR_SSL_WANT_WRITE) {
            JPV2G_ERROR("TLS handshake failed (%d)", rc);
            return -ECONNREFUSED;
        }
        if (timeout_ms > 0 && ++start > (uint64_t)timeout_ms / 10) {
            return -ETIMEDOUT;
        }
        jpv2g_sleep_ms(10);
    }
    sock->secure = true;
    return 0;
}

int jpv2g_tls_server_wrap(jpv2g_tls_socket_t *sock,
                            int client_fd,
                            const char *cert_path,
                            const char *key_path,
                            const char *ca_path) {
    if (!sock) return -EINVAL;
    sock->fd = client_fd;
    if (sock->net) {
        mbedtls_net_free(sock->net);
        free(sock->net);
    }
    sock->net = calloc(1, sizeof(mbedtls_net_context));
    if (!sock->net) return -ENOMEM;
    mbedtls_net_init(sock->net);
    sock->net->fd = client_fd;
    int rc = setup_ssl_common(sock, true, cert_path, key_path, ca_path);
    if (rc != 0) {
        JPV2G_ERROR("TLS server setup failed (%d)", rc);
        return rc;
    }
    mbedtls_ssl_set_bio(sock->ssl, sock->net, mbedtls_net_send, mbedtls_net_recv, NULL);
    while ((rc = mbedtls_ssl_handshake(sock->ssl)) != 0) {
        if (rc != MBEDTLS_ERR_SSL_WANT_READ && rc != MBEDTLS_ERR_SSL_WANT_WRITE) {
            JPV2G_ERROR("TLS server handshake failed (%d)", rc);
            return -ECONNABORTED;
        }
    }
    sock->secure = true;
    return 0;
}

ssize_t jpv2g_tls_send(jpv2g_tls_socket_t *sock, const uint8_t *buf, size_t len) {
    if (!sock || sock->fd < 0 || !buf) return -EINVAL;
    int rc;
    do {
        rc = mbedtls_ssl_write(sock->ssl, buf, len);
    } while (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE);
    if (rc < 0) return rc;
    return 0;
}

ssize_t jpv2g_tls_recv(jpv2g_tls_socket_t *sock, uint8_t *buf, size_t len, int timeout_ms) {
    if (!sock || sock->fd < 0 || !buf) return -EINVAL;
    int rc = mbedtls_ssl_read(sock->ssl, buf, len);
    if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) return -EAGAIN;
    if (rc < 0) return -EIO;
    return rc;
}

void jpv2g_tls_close(jpv2g_tls_socket_t *sock) {
    if (!sock) return;
    if (sock->ssl) {
        mbedtls_ssl_close_notify(sock->ssl);
        mbedtls_ssl_free(sock->ssl);
        free(sock->ssl);
    }
    if (sock->conf) {
        mbedtls_ssl_config_free(sock->conf);
        free(sock->conf);
    }
    if (sock->ctr_drbg) {
        mbedtls_ctr_drbg_free(sock->ctr_drbg);
        free(sock->ctr_drbg);
    }
    if (sock->entropy) {
        mbedtls_entropy_free(sock->entropy);
        free(sock->entropy);
    }
    if (sock->net) {
        mbedtls_net_free(sock->net);
        free(sock->net);
    }
#endif
    if (sock->fd >= 0) jpv2g_socket_close(sock->fd);
    sock->fd = -1;
    sock->secure = false;
}
#else /* !HAVE_MBEDTLS */
int jpv2g_tls_client_connect(jpv2g_tls_socket_t *sock,
                               const struct sockaddr_in6 *addr,
                               socklen_t addrlen,
                               const char *cert_path,
                               const char *key_path,
                               const char *ca_path,
                               int timeout_ms) {
    (void)sock; (void)addr; (void)addrlen; (void)cert_path; (void)key_path; (void)ca_path; (void)timeout_ms;
    return -ENOTSUP;
}

int jpv2g_tls_server_wrap(jpv2g_tls_socket_t *sock,
                            int client_fd,
                            const char *cert_path,
                            const char *key_path,
                            const char *ca_path) {
    (void)sock; (void)client_fd; (void)cert_path; (void)key_path; (void)ca_path;
    return -ENOTSUP;
}

ssize_t jpv2g_tls_send(jpv2g_tls_socket_t *sock, const uint8_t *buf, size_t len) {
    (void)sock; (void)buf; (void)len;
    return -ENOTSUP;
}

ssize_t jpv2g_tls_recv(jpv2g_tls_socket_t *sock, uint8_t *buf, size_t len, int timeout_ms) {
    (void)sock; (void)buf; (void)len; (void)timeout_ms;
    return -ENOTSUP;
}

void jpv2g_tls_close(jpv2g_tls_socket_t *sock) {
    if (!sock) return;
    if (sock->fd >= 0) jpv2g_socket_close(sock->fd);
    sock->fd = -1;
    sock->secure = false;
}
#endif /* HAVE_MBEDTLS */
