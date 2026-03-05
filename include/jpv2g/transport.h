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

#include "jpv2g/constants.h"
#include "jpv2g/platform_compat.h"

typedef struct {
    int fd;
    struct in6_addr mcast_addr;
    uint16_t port;
} jpv2g_udp_server_t;

typedef struct {
    int fd;
    struct sockaddr_in6 secc_addr;
    socklen_t secc_addrlen;
    unsigned int ifindex;
} jpv2g_udp_client_t;

typedef struct {
    int fd;
    uint16_t port;
} jpv2g_tcp_server_t;

typedef struct {
    int fd;
} jpv2g_tcp_client_t;

int jpv2g_udp_server_start(jpv2g_udp_server_t *srv, const char *iface, uint16_t port);
int jpv2g_udp_server_recv(jpv2g_udp_server_t *srv, uint8_t *buf, size_t buf_len, struct sockaddr_in6 *from, socklen_t *from_len, int timeout_ms);
int jpv2g_udp_server_sendto(jpv2g_udp_server_t *srv, const uint8_t *buf, size_t len, const struct sockaddr_in6 *to, socklen_t to_len);
void jpv2g_udp_server_stop(jpv2g_udp_server_t *srv);

int jpv2g_udp_client_start(jpv2g_udp_client_t *cli, const char *iface);
int jpv2g_udp_client_sendrecv(jpv2g_udp_client_t *cli, const uint8_t *req, size_t req_len, uint8_t *resp, size_t resp_len, int timeout_ms);
void jpv2g_udp_client_stop(jpv2g_udp_client_t *cli);

int jpv2g_tcp_server_start(jpv2g_tcp_server_t *srv, const char *iface, uint16_t port, bool ipv6_only);
int jpv2g_tcp_server_accept(jpv2g_tcp_server_t *srv, int *client_fd, struct sockaddr_in6 *addr, socklen_t *addrlen, int timeout_ms);
void jpv2g_tcp_server_stop(jpv2g_tcp_server_t *srv);

int jpv2g_tcp_client_connect(jpv2g_tcp_client_t *cli, const struct sockaddr_in6 *addr, socklen_t addrlen, int timeout_ms);
ssize_t jpv2g_tcp_send(int fd, const uint8_t *buf, size_t len);
ssize_t jpv2g_tcp_recv(int fd, uint8_t *buf, size_t len, int timeout_ms);
void jpv2g_tcp_client_close(jpv2g_tcp_client_t *cli);
