/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#include "jpv2g/security.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "jpv2g/log.h"

#ifdef HAVE_MBEDTLS
#include <mbedtls/x509_crt.h>
#endif

static int load_file(const char *path, uint8_t **out, size_t *out_len) {
    if (!path || !out || !out_len) return -EINVAL;
    FILE *f = fopen(path, "rb");
    if (!f) return -errno;
    if (fseek(f, 0, SEEK_END) != 0) {
        int err = -errno;
        fclose(f);
        return err;
    }
    long sz = ftell(f);
    if (sz < 0) {
        int err = -errno;
        fclose(f);
        return err;
    }
    rewind(f);
    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) {
        fclose(f);
        return -ENOMEM;
    }
    size_t r = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (r != (size_t)sz) {
        free(buf);
        return -EIO;
    }
    *out = buf;
    *out_len = (size_t)sz;
    return 0;
}

int jpv2g_load_private_key(const char *path, uint8_t **out, size_t *out_len) {
    return load_file(path, out, out_len);
}

int jpv2g_load_certificate(const char *path, uint8_t **out, size_t *out_len) {
    return load_file(path, out, out_len);
}

jpv2g_cert_status_t jpv2g_verify_certificate(const uint8_t *cert, size_t cert_len, const uint8_t *ca_chain, size_t ca_len) {
#ifndef HAVE_MBEDTLS
    (void)cert;
    (void)cert_len;
    (void)ca_chain;
    (void)ca_len;
    return JPV2G_CERT_UNSUPPORTED;
#else
    mbedtls_x509_crt crt;
    mbedtls_x509_crt ca;
    mbedtls_x509_crt_init(&crt);
    mbedtls_x509_crt_init(&ca);

    int rc = mbedtls_x509_crt_parse(&crt, cert, cert_len);
    if (rc != 0) return JPV2G_CERT_INVALID;
    rc = mbedtls_x509_crt_parse(&ca, ca_chain, ca_len);
    if (rc != 0) return JPV2G_CERT_CHAIN_INCOMPLETE;

    uint32_t flags = 0;
    rc = mbedtls_x509_crt_verify(&crt, &ca, NULL, NULL, &flags, NULL, NULL);
    mbedtls_x509_crt_free(&crt);
    mbedtls_x509_crt_free(&ca);
    if (rc != 0) return JPV2G_CERT_INVALID;
    if (flags & MBEDTLS_X509_BADCERT_EXPIRED) return JPV2G_CERT_EXPIRED;
    if (flags & MBEDTLS_X509_BADCERT_FUTURE) return JPV2G_CERT_NOT_YET_VALID;
    return JPV2G_CERT_OK;
#endif
}
