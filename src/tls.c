/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

/*
 * TLS transport for the V2G session socket (ISO 15118-2 TLS 1.2 profile).
 *
 * The mbedtls branch below deliberately does NOT use mbedtls_net_* /
 * <mbedtls/net_sockets.h>: the pinned arduino-esp32 framework disables
 * MBEDTLS_NET_C (esp_config.h #undef), so mbedtls_net_send/recv do not
 * exist in the shipped libmbedtls.a. Instead the SSL BIO is wired to raw
 * socket fds via tls_bio_send()/tls_bio_recv(), which work identically on
 * lwIP (ESP32) and POSIX (host builds) through platform_compat.h.
 *
 * Credentials come in two flavours:
 *   - jpv2g_tls_server_wrap()      : PEM files on a filesystem (host/dev).
 *   - jpv2g_tls_server_wrap_mem()  : in-memory PEM buffers
 *     (jpv2g_tls_credentials_t) — the only workable path on the PLC, which
 *     has no PKI files. mbedtls 2.x PEM rule: the buffer must be
 *     NUL-terminated and the length must COUNT the terminating NUL;
 *     jpv2g_tls_credentials_validate() enforces this before any parsing.
 *
 * Ciphersuites are pinned to the ISO 15118-2 [V2G2-602] set
 * (ECDHE/ECDH-ECDSA with AES-128-CBC-SHA256 on secp256r1) and the minimum
 * protocol version is TLS 1.2 — the -2 profile forbids anything older, and
 * the pinned suites are TLS 1.2-only anyway.
 *
 * Every mbedtls object handed to the ssl_config (CA chain, own cert, own
 * key) is also stored on jpv2g_tls_socket_t so jpv2g_tls_close() can free
 * it: the previous implementation leaked all three per session.
 */

#include "jpv2g/tls.h"

#include <errno.h>
#include "jpv2g/poll_compat.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "jpv2g/log.h"
#include "jpv2g/time_compat.h"

/*
 * Credential-shape validation shared by BOTH branches so hosts without
 * mbedtls can still unit-test the contract. Enforces the mbedtls 2.x
 * in-memory PEM rule up front (NUL-terminated, length includes the NUL)
 * instead of letting mbedtls_x509_crt_parse() fail with an opaque
 * ASN.1 error deep inside the handshake path.
 */
int jpv2g_tls_credentials_validate(const jpv2g_tls_credentials_t *creds) {
    if (!creds) return -EINVAL;
    /* Server identity is mandatory: cert + key must both be present. A
     * PEM buffer shorter than 2 bytes cannot hold any content plus the
     * counted NUL terminator. */
    if (!creds->cert_pem || creds->cert_pem_len < 2) return -EINVAL;
    if (creds->cert_pem[creds->cert_pem_len - 1] != '\0') return -EINVAL;
    if (!creds->key_pem || creds->key_pem_len < 2) return -EINVAL;
    if (creds->key_pem[creds->key_pem_len - 1] != '\0') return -EINVAL;
    /* CA chain is optional (NULL = no client-cert verification), but when
     * present it must obey the same PEM rule; a non-NULL pointer with a
     * bogus length, or a length without a pointer, is a caller bug. */
    if (creds->ca_pem) {
        if (creds->ca_pem_len < 2) return -EINVAL;
        if (creds->ca_pem[creds->ca_pem_len - 1] != '\0') return -EINVAL;
    } else if (creds->ca_pem_len != 0) {
        return -EINVAL;
    }
    return 0;
}

#ifdef HAVE_MBEDTLS

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_ciphersuites.h>
#include <mbedtls/x509_crt.h>

/*
 * BIO error codes returned to the mbedtls SSL layer for fatal socket
 * failures. These mirror the MBEDTLS_ERR_NET_* values so mbedtls error
 * logs stay comparable with stock deployments, but are defined locally
 * because <mbedtls/net_sockets.h> is intentionally not included (see the
 * file header: MBEDTLS_NET_C is disabled on the ESP32 framework).
 */
#define JPV2G_TLS_ERR_NET_RECV_FAILED (-0x004C) /* == MBEDTLS_ERR_NET_RECV_FAILED */
#define JPV2G_TLS_ERR_NET_SEND_FAILED (-0x004E) /* == MBEDTLS_ERR_NET_SEND_FAILED */
#define JPV2G_TLS_ERR_NET_CONN_RESET  (-0x0050) /* == MBEDTLS_ERR_NET_CONN_RESET  */

/*
 * How long each BIO attempt waits for socket readiness before reporting
 * WANT_READ/WANT_WRITE. This is what paces the handshake/read retry loops:
 * the fds handed to us are blocking, so without this poll a handshake
 * stuck mid-flight would block inside recv() forever and the deadline in
 * tls_handshake_with_deadline() could never fire.
 */
#define JPV2G_TLS_BIO_POLL_SLICE_MS 100

/* ISO 15118-2 [V2G2-602] TLS 1.2 ciphersuites, terminated by 0. */
static const int k_v2g_ciphersuites[] = {
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
    0
};

/* ISO 15118-2 pins the curve to secp256r1; list terminated by DP_NONE. */
static const mbedtls_ecp_group_id k_v2g_curves[] = {
    MBEDTLS_ECP_DP_SECP256R1,
    MBEDTLS_ECP_DP_NONE
};

/*
 * Raw-fd BIO callbacks. ctx is the jpv2g_tls_socket_t itself; both wait
 * (bounded) for socket readiness, then perform exactly one send()/recv().
 * Returning WANT_READ/WANT_WRITE on the poll timeout keeps control in our
 * retry loops, where the wall-clock deadlines live.
 */
static int tls_bio_recv(void *ctx, unsigned char *buf, size_t len) {
    jpv2g_tls_socket_t *sock = (jpv2g_tls_socket_t *)ctx;
    if (!sock || sock->fd < 0 || !buf) return JPV2G_TLS_ERR_NET_RECV_FAILED;
    struct pollfd pfd;
    pfd.fd = sock->fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    int prc = poll(&pfd, 1, JPV2G_TLS_BIO_POLL_SLICE_MS);
    if (prc == 0) return MBEDTLS_ERR_SSL_WANT_READ;
    if (prc < 0) {
        if (errno == EINTR) return MBEDTLS_ERR_SSL_WANT_READ;
        return JPV2G_TLS_ERR_NET_RECV_FAILED;
    }
    ssize_t n = recv(sock->fd, buf, len, 0);
    if (n >= 0) return (int)n; /* 0 = orderly peer EOF -> SSL_CONN_EOF upstream */
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }
    if (errno == ECONNRESET || errno == EPIPE) return JPV2G_TLS_ERR_NET_CONN_RESET;
    return JPV2G_TLS_ERR_NET_RECV_FAILED;
}

static int tls_bio_send(void *ctx, const unsigned char *buf, size_t len) {
    jpv2g_tls_socket_t *sock = (jpv2g_tls_socket_t *)ctx;
    if (!sock || sock->fd < 0 || !buf) return JPV2G_TLS_ERR_NET_SEND_FAILED;
    ssize_t n = send(sock->fd, buf, len, 0);
    if (n >= 0) return (int)n;
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
        /* Pace the caller's retry loop: wait (bounded) for writability so
         * WANT_WRITE cannot degenerate into a busy spin. */
        struct pollfd pfd;
        pfd.fd = sock->fd;
        pfd.events = POLLOUT;
        pfd.revents = 0;
        (void)poll(&pfd, 1, JPV2G_TLS_BIO_POLL_SLICE_MS);
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    if (errno == ECONNRESET || errno == EPIPE) return JPV2G_TLS_ERR_NET_CONN_RESET;
    return JPV2G_TLS_ERR_NET_SEND_FAILED;
}

/*
 * Free every mbedtls object owned by the socket WITHOUT touching the fd.
 * Used both by jpv2g_tls_close() and by the failure paths of the setup
 * functions — the old code leaked all crypto state when setup failed
 * because only jpv2g_tls_close() (never called on failure) knew how to
 * unwind, and it in turn leaked the cert/key/CA objects it never stored.
 */
static void tls_free_state(jpv2g_tls_socket_t *sock) {
    if (!sock) return;
    if (sock->ssl) {
        mbedtls_ssl_free(sock->ssl);
        free(sock->ssl);
        sock->ssl = NULL;
    }
    if (sock->conf) {
        mbedtls_ssl_config_free(sock->conf);
        free(sock->conf);
        sock->conf = NULL;
    }
    if (sock->ctr_drbg) {
        mbedtls_ctr_drbg_free(sock->ctr_drbg);
        free(sock->ctr_drbg);
        sock->ctr_drbg = NULL;
    }
    if (sock->entropy) {
        mbedtls_entropy_free(sock->entropy);
        free(sock->entropy);
        sock->entropy = NULL;
    }
    if (sock->ca_chain) {
        mbedtls_x509_crt_free(sock->ca_chain);
        free(sock->ca_chain);
        sock->ca_chain = NULL;
    }
    if (sock->own_cert) {
        mbedtls_x509_crt_free(sock->own_cert);
        free(sock->own_cert);
        sock->own_cert = NULL;
    }
    if (sock->own_key) {
        mbedtls_pk_free(sock->own_key);
        free(sock->own_key);
        sock->own_key = NULL;
    }
}

/*
 * Allocate + initialise ssl/conf/rng state and apply the V2G profile
 * (TLS 1.2 minimum, pinned suites/curve, RNG). Credential loading and
 * ssl_setup happen afterwards so the config can take the CA/own-cert
 * pointers first. Errno-style return; on failure the caller must unwind
 * with tls_free_state().
 */
static int tls_setup_conf(jpv2g_tls_socket_t *sock, bool is_server) {
    if (!sock) return -EINVAL;
    sock->ssl = calloc(1, sizeof(mbedtls_ssl_context));
    sock->conf = calloc(1, sizeof(mbedtls_ssl_config));
    sock->ctr_drbg = calloc(1, sizeof(mbedtls_ctr_drbg_context));
    sock->entropy = calloc(1, sizeof(mbedtls_entropy_context));
    if (!sock->ssl || !sock->conf || !sock->ctr_drbg || !sock->entropy) return -ENOMEM;

    mbedtls_ssl_init(sock->ssl);
    mbedtls_ssl_config_init(sock->conf);
    mbedtls_entropy_init(sock->entropy);
    mbedtls_ctr_drbg_init(sock->ctr_drbg);

    const char *pers = "jpv2g_tls";
    int rc = mbedtls_ctr_drbg_seed(sock->ctr_drbg, mbedtls_entropy_func, sock->entropy,
                                   (const unsigned char *)pers, strlen(pers));
    if (rc != 0) {
        JPV2G_ERROR("TLS RNG seed failed (-0x%04X)", (unsigned)-rc);
        return -EIO;
    }

    rc = mbedtls_ssl_config_defaults(sock->conf,
                                     is_server ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT,
                                     MBEDTLS_SSL_TRANSPORT_STREAM,
                                     MBEDTLS_SSL_PRESET_DEFAULT);
    if (rc != 0) {
        JPV2G_ERROR("TLS config defaults failed (-0x%04X)", (unsigned)-rc);
        return -EIO;
    }

    mbedtls_ssl_conf_rng(sock->conf, mbedtls_ctr_drbg_random, sock->ctr_drbg);
    mbedtls_ssl_conf_min_version(sock->conf, MBEDTLS_SSL_MAJOR_VERSION_3,
                                 MBEDTLS_SSL_MINOR_VERSION_3); /* TLS 1.2 */
    mbedtls_ssl_conf_ciphersuites(sock->conf, k_v2g_ciphersuites);
    mbedtls_ssl_conf_curves(sock->conf, k_v2g_curves);
    return 0;
}

/*
 * Hand the parsed CA chain / own cert+key to the ssl_config and finish
 * ssl_setup + BIO wiring. This is the SINGLE mbedtls_ssl_set_bio() call
 * site (the old code called it three times, once against pointers that
 * did not exist yet).
 */
static int tls_finish_setup(jpv2g_tls_socket_t *sock) {
    if (sock->ca_chain) {
        mbedtls_ssl_conf_ca_chain(sock->conf, sock->ca_chain, NULL);
        mbedtls_ssl_conf_authmode(sock->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    } else {
        /* No trust anchors configured: certificate verification cannot
         * succeed, so don't pretend. TLS still provides confidentiality
         * + integrity, which is the dev-TLS (T1) posture. */
        mbedtls_ssl_conf_authmode(sock->conf, MBEDTLS_SSL_VERIFY_NONE);
    }
    if (sock->own_cert && sock->own_key) {
        int rc = mbedtls_ssl_conf_own_cert(sock->conf, sock->own_cert, sock->own_key);
        if (rc != 0) {
            JPV2G_ERROR("TLS own-cert conf failed (-0x%04X)", (unsigned)-rc);
            return -EINVAL;
        }
    }
    int rc = mbedtls_ssl_setup(sock->ssl, sock->conf);
    if (rc != 0) {
        JPV2G_ERROR("TLS ssl_setup failed (-0x%04X)", (unsigned)-rc);
        return rc == MBEDTLS_ERR_SSL_ALLOC_FAILED ? -ENOMEM : -EIO;
    }
    mbedtls_ssl_set_bio(sock->ssl, sock, tls_bio_send, tls_bio_recv, NULL);
    return 0;
}

/*
 * Parse PEM credentials from files (host/dev path; the PLC has no files).
 * The own cert/key pair is optional here — clients may run anonymous with
 * server-only auth — but when one half is given the other is mandatory.
 * Servers enforce cert+key presence at the wrap level instead, so a
 * misconfigured SECC fails fast with -EINVAL rather than mid-handshake.
 */
static int tls_load_credentials_file(jpv2g_tls_socket_t *sock,
                                     const char *cert_path,
                                     const char *key_path,
                                     const char *ca_path) {
    const bool have_cert = (cert_path && cert_path[0]);
    const bool have_key = (key_path && key_path[0]);
    if (have_cert != have_key) return -EINVAL;
    if (ca_path && ca_path[0]) {
        sock->ca_chain = calloc(1, sizeof(mbedtls_x509_crt));
        if (!sock->ca_chain) return -ENOMEM;
        mbedtls_x509_crt_init(sock->ca_chain);
        int rc = mbedtls_x509_crt_parse_file(sock->ca_chain, ca_path);
        if (rc != 0) {
            JPV2G_ERROR("TLS CA parse failed for %s (-0x%04X)", ca_path, (unsigned)-rc);
            return -EINVAL;
        }
    }
    if (have_cert) {
        sock->own_cert = calloc(1, sizeof(mbedtls_x509_crt));
        sock->own_key = calloc(1, sizeof(mbedtls_pk_context));
        if (!sock->own_cert || !sock->own_key) return -ENOMEM;
        mbedtls_x509_crt_init(sock->own_cert);
        mbedtls_pk_init(sock->own_key);
        int rc = mbedtls_x509_crt_parse_file(sock->own_cert, cert_path);
        if (rc != 0) {
            JPV2G_ERROR("TLS cert parse failed for %s (-0x%04X)", cert_path, (unsigned)-rc);
            return -EINVAL;
        }
        rc = mbedtls_pk_parse_keyfile(sock->own_key, key_path, NULL);
        if (rc != 0) {
            JPV2G_ERROR("TLS key parse failed for %s (-0x%04X)", key_path, (unsigned)-rc);
            return -EINVAL;
        }
    }
    return 0;
}

/* Parse PEM credentials from memory (jpv2g_tls_credentials_t contract). */
static int tls_load_credentials_mem(jpv2g_tls_socket_t *sock,
                                    const jpv2g_tls_credentials_t *creds) {
    int rc = jpv2g_tls_credentials_validate(creds);
    if (rc != 0) return rc;
    if (creds->ca_pem) {
        sock->ca_chain = calloc(1, sizeof(mbedtls_x509_crt));
        if (!sock->ca_chain) return -ENOMEM;
        mbedtls_x509_crt_init(sock->ca_chain);
        rc = mbedtls_x509_crt_parse(sock->ca_chain, creds->ca_pem, creds->ca_pem_len);
        if (rc != 0) {
            JPV2G_ERROR("TLS in-memory CA parse failed (-0x%04X)", (unsigned)-rc);
            return -EINVAL;
        }
    }
    sock->own_cert = calloc(1, sizeof(mbedtls_x509_crt));
    sock->own_key = calloc(1, sizeof(mbedtls_pk_context));
    if (!sock->own_cert || !sock->own_key) return -ENOMEM;
    mbedtls_x509_crt_init(sock->own_cert);
    mbedtls_pk_init(sock->own_key);
    rc = mbedtls_x509_crt_parse(sock->own_cert, creds->cert_pem, creds->cert_pem_len);
    if (rc != 0) {
        JPV2G_ERROR("TLS in-memory cert parse failed (-0x%04X)", (unsigned)-rc);
        return -EINVAL;
    }
    rc = mbedtls_pk_parse_key(sock->own_key, creds->key_pem, creds->key_pem_len, NULL, 0);
    if (rc != 0) {
        JPV2G_ERROR("TLS in-memory key parse failed (-0x%04X)", (unsigned)-rc);
        return -EINVAL;
    }
    return 0;
}

/*
 * Drive the handshake to completion with a wall-clock deadline. The old
 * server loop spun on WANT_READ/WANT_WRITE forever, so a peer that opened
 * TCP, sent a ClientHello prefix and then went silent pinned the HLC
 * worker for the life of the connection. The BIO poll slice guarantees
 * each iteration returns within ~JPV2G_TLS_BIO_POLL_SLICE_MS, so this
 * loop re-checks the deadline at that cadence without extra sleeps.
 */
static int tls_handshake_with_deadline(jpv2g_tls_socket_t *sock,
                                       int timeout_ms,
                                       bool is_server) {
    if (timeout_ms <= 0) timeout_ms = JPV2G_TLS_HANDSHAKE_TIMEOUT_MS;
    const int64_t deadline = jpv2g_now_monotonic_ms() + timeout_ms;
    int rc;
    while ((rc = mbedtls_ssl_handshake(sock->ssl)) != 0) {
        if (rc != MBEDTLS_ERR_SSL_WANT_READ && rc != MBEDTLS_ERR_SSL_WANT_WRITE) {
            JPV2G_ERROR("TLS %s handshake failed (-0x%04X)",
                        is_server ? "server" : "client", (unsigned)-rc);
            return is_server ? -ECONNABORTED : -ECONNREFUSED;
        }
        if (jpv2g_now_monotonic_ms() >= deadline) {
            JPV2G_WARN("TLS %s handshake timed out after %d ms",
                       is_server ? "server" : "client", timeout_ms);
            return -ETIMEDOUT;
        }
    }
    sock->secure = true;
    return 0;
}

int jpv2g_tls_client_connect(jpv2g_tls_socket_t *sock,
                               const struct sockaddr_in6 *addr,
                               socklen_t addrlen,
                               const char *cert_path,
                               const char *key_path,
                               const char *ca_path,
                               int timeout_ms) {
    if (!sock || !addr) return -EINVAL;
    int fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0) return -errno;
    int rc = connect(fd, (const struct sockaddr *)addr, addrlen);
    if (rc < 0 && errno != EINPROGRESS) {
        int err = -errno;
        jpv2g_socket_close(fd);
        return err;
    }
    if (rc < 0) {
        struct pollfd pfd = {.fd = fd, .events = POLLOUT, .revents = 0};
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
    sock->fd = fd;
    /* The fd was created here, so every failure below owns its cleanup:
     * free crypto state AND close the fd — the caller never learned it. */
    rc = tls_setup_conf(sock, false);
    /* Client credentials are all optional (server-only auth is the common
     * dev case); the loader parses whichever paths were provided. */
    if (rc == 0) rc = tls_load_credentials_file(sock, cert_path, key_path, ca_path);
    if (rc == 0) rc = tls_finish_setup(sock);
    if (rc == 0) rc = tls_handshake_with_deadline(sock, timeout_ms, false);
    if (rc != 0) {
        JPV2G_ERROR("TLS client connect failed (%d)", rc);
        tls_free_state(sock);
        jpv2g_socket_close(fd);
        sock->fd = -1;
        sock->secure = false;
        return rc;
    }
    return 0;
}

/*
 * Wrap an accepted client fd in a server-side TLS session using PEM files.
 * Contract on failure: crypto state is freed here, but the fd is left
 * open and still belongs to the caller (jpv2g_secc_handle_client_tls
 * closes it) — closing it here too would double-close.
 */
int jpv2g_tls_server_wrap(jpv2g_tls_socket_t *sock,
                            int client_fd,
                            const char *cert_path,
                            const char *key_path,
                            const char *ca_path) {
    if (!sock || client_fd < 0) return -EINVAL;
    /* A server without an identity cannot complete any V2G handshake:
     * fail fast instead of surfacing an mbedtls alert mid-handshake. */
    if (!cert_path || !cert_path[0] || !key_path || !key_path[0]) return -EINVAL;
    sock->fd = client_fd;
    int rc = tls_setup_conf(sock, true);
    if (rc == 0) rc = tls_load_credentials_file(sock, cert_path, key_path, ca_path);
    if (rc == 0) rc = tls_finish_setup(sock);
    if (rc == 0) rc = tls_handshake_with_deadline(sock, JPV2G_TLS_HANDSHAKE_TIMEOUT_MS, true);
    if (rc != 0) {
        JPV2G_ERROR("TLS server wrap failed (%d)", rc);
        tls_free_state(sock);
        sock->secure = false;
        return rc;
    }
    return 0;
}

/* In-memory-credential variant of jpv2g_tls_server_wrap(); same failure
 * contract (fd stays with the caller). */
int jpv2g_tls_server_wrap_mem(jpv2g_tls_socket_t *sock,
                                int client_fd,
                                const jpv2g_tls_credentials_t *creds,
                                int handshake_timeout_ms) {
    if (!sock || client_fd < 0) return -EINVAL;
    int rc = jpv2g_tls_credentials_validate(creds);
    if (rc != 0) return rc;
    sock->fd = client_fd;
    rc = tls_setup_conf(sock, true);
    if (rc == 0) rc = tls_load_credentials_mem(sock, creds);
    if (rc == 0) rc = tls_finish_setup(sock);
    if (rc == 0) rc = tls_handshake_with_deadline(sock, handshake_timeout_ms, true);
    if (rc != 0) {
        JPV2G_ERROR("TLS server wrap (mem) failed (%d)", rc);
        tls_free_state(sock);
        sock->secure = false;
        return rc;
    }
    return 0;
}

ssize_t jpv2g_tls_send(jpv2g_tls_socket_t *sock, const uint8_t *buf, size_t len) {
    if (!sock || sock->fd < 0 || !buf || !sock->ssl) return -EINVAL;
    int rc;
    do {
        rc = mbedtls_ssl_write(sock->ssl, buf, len);
        /* WANT_* retries are paced by the BIO's bounded POLLOUT wait, so
         * this loop cannot busy-spin; the caller (secc_send_bytes) owns
         * the overall send deadline. */
    } while (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE);
    if (rc < 0) {
        if (rc == JPV2G_TLS_ERR_NET_CONN_RESET) return -EPIPE;
        JPV2G_ERROR("TLS send failed (-0x%04X)", (unsigned)-rc);
        return -EIO;
    }
    /* mbedtls_ssl_write follows send(2): success is the number of plaintext
     * bytes consumed and may be shorter than len. */
    return (ssize_t)rc;
}

ssize_t jpv2g_tls_recv(jpv2g_tls_socket_t *sock, uint8_t *buf, size_t len, int timeout_ms) {
    if (!sock || sock->fd < 0 || !buf || !sock->ssl) return -EINVAL;
    const int64_t deadline =
        timeout_ms > 0 ? jpv2g_now_monotonic_ms() + timeout_ms : 0;
    for (;;) {
        int rc = mbedtls_ssl_read(sock->ssl, buf, len);
        if (rc > 0) return (ssize_t)rc;
        if (rc == 0 || rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY ||
            rc == MBEDTLS_ERR_SSL_CONN_EOF) {
            return 0; /* orderly close; caller maps 0 to -ECONNRESET */
        }
        if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
            /* -EAGAIN keeps the secc_recv_bytes retry contract; its own
             * deadline decides when to give up entirely. */
            if (timeout_ms <= 0 || jpv2g_now_monotonic_ms() >= deadline) return -EAGAIN;
            continue; /* BIO poll slice paces this loop */
        }
        if (rc == JPV2G_TLS_ERR_NET_CONN_RESET) return -ECONNRESET;
        JPV2G_ERROR("TLS recv failed (-0x%04X)", (unsigned)-rc);
        return -EIO;
    }
}

void jpv2g_tls_close(jpv2g_tls_socket_t *sock) {
    if (!sock) return;
    if (sock->ssl && sock->secure) {
        mbedtls_ssl_close_notify(sock->ssl);
    }
    tls_free_state(sock);
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

/* Stub mirrors jpv2g_tls_server_wrap: TLS is refused, the caller keeps
 * ownership of client_fd and closes it. Credentials are deliberately NOT
 * validated here — the answer is -ENOTSUP regardless, and callers gate on
 * cert_pem presence before ever reaching this point. */
int jpv2g_tls_server_wrap_mem(jpv2g_tls_socket_t *sock,
                                int client_fd,
                                const jpv2g_tls_credentials_t *creds,
                                int handshake_timeout_ms) {
    (void)sock; (void)client_fd; (void)creds; (void)handshake_timeout_ms;
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
