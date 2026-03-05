/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#include "jpv2g/transport.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include "jpv2g/log.h"
#include "jpv2g/poll_compat.h"
#include "jpv2g/time_compat.h"

static int set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -errno;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return -errno;
    return 0;
}

static int64_t make_deadline_ms(int timeout_ms) {
    if (timeout_ms < 0) return -1;
    return jpv2g_now_monotonic_ms() + (int64_t)timeout_ms;
}

static bool deadline_expired(int64_t deadline_ms) {
    return (deadline_ms >= 0) && (jpv2g_now_monotonic_ms() >= deadline_ms);
}

static void tiny_wait_backoff(void) {
    jpv2g_sleep_ms(1);
}

static ssize_t recv_wait_nonblock(int fd, uint8_t *buf, size_t len, int flags, int timeout_ms) {
    const int64_t deadline = make_deadline_ms(timeout_ms);
    for (;;) {
        ssize_t r = recv(fd, buf, len, flags | MSG_DONTWAIT);
        if (r >= 0) return r;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            if (timeout_ms == 0 || deadline_expired(deadline)) {
                errno = EAGAIN;
                return -1;
            }
            tiny_wait_backoff();
            continue;
        }
        return -1;
    }
}

static ssize_t recvfrom_wait_nonblock(int fd,
                                      uint8_t *buf,
                                      size_t len,
                                      struct sockaddr_in6 *from,
                                      socklen_t *from_len,
                                      int timeout_ms) {
    const int64_t deadline = make_deadline_ms(timeout_ms);
    for (;;) {
        ssize_t r = recvfrom(fd, buf, len, MSG_DONTWAIT, (struct sockaddr *)from, from_len);
        if (r >= 0) return r;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            if (timeout_ms == 0 || deadline_expired(deadline)) {
                errno = EAGAIN;
                return -1;
            }
            tiny_wait_backoff();
            continue;
        }
        return -1;
    }
}

static int accept_wait_nonblock(int fd,
                                struct sockaddr_in6 *addr,
                                socklen_t *addrlen,
                                int timeout_ms) {
    const int64_t deadline = make_deadline_ms(timeout_ms);
    for (;;) {
        int cfd = accept(fd, (struct sockaddr *)addr, addrlen);
        if (cfd >= 0) return cfd;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            if (timeout_ms == 0 || deadline_expired(deadline)) {
                errno = EAGAIN;
                return -1;
            }
            tiny_wait_backoff();
            continue;
        }
        return -1;
    }
}

int jpv2g_udp_server_start(jpv2g_udp_server_t *srv, const char *iface, uint16_t port) {
    if (!srv) return -EINVAL;
    memset(srv, 0, sizeof(*srv));
    srv->fd = -1;
    srv->fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (srv->fd < 0) return -errno;

    int on = 1;
    setsockopt(srv->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);
    addr.sin6_addr = in6addr_any;
    if (bind(srv->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        int err = -errno;
        jpv2g_socket_close(srv->fd);
        return err;
    }

    /* Join multicast group */
    inet_pton(AF_INET6, JPV2G_SDP_MULTICAST_ADDRESS, &srv->mcast_addr);
    struct ipv6_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));
    mreq.ipv6mr_multiaddr = srv->mcast_addr;
    if (iface && iface[0]) {
        mreq.ipv6mr_interface = jpv2g_if_nametoindex(iface);
        if (mreq.ipv6mr_interface == 0) {
            JPV2G_WARN("if_nametoindex(%s) failed, using default interface for multicast join", iface);
            mreq.ipv6mr_interface = 0; /* fallback to default */
        }
    } else {
        mreq.ipv6mr_interface = 0;
    }

    if (setsockopt(srv->fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) < 0) {
        JPV2G_WARN("IPV6_JOIN_GROUP failed on iface %s (errno=%d), continuing without multicast", iface, errno);
    }

    (void)set_nonblock(srv->fd);
    srv->port = port;
    return 0;
}

int jpv2g_udp_server_recv(jpv2g_udp_server_t *srv,
                            uint8_t *buf,
                            size_t buf_len,
                            struct sockaddr_in6 *from,
                            socklen_t *from_len,
                            int timeout_ms) {
    if (!srv || srv->fd < 0 || !buf) return -EINVAL;
    ssize_t r = recvfrom_wait_nonblock(srv->fd, buf, buf_len, from, from_len, timeout_ms);
    if (r < 0) return -errno;
    return (int)r;
}

int jpv2g_udp_server_sendto(jpv2g_udp_server_t *srv,
                              const uint8_t *buf,
                              size_t len,
                              const struct sockaddr_in6 *to,
                              socklen_t to_len) {
    if (!srv || srv->fd < 0 || !buf || !to) return -EINVAL;
    ssize_t s = sendto(srv->fd, buf, len, 0, (const struct sockaddr *)to, to_len);
    if (s < 0 || (size_t)s != len) return -errno;
    return 0;
}

void jpv2g_udp_server_stop(jpv2g_udp_server_t *srv) {
    if (!srv) return;
    if (srv->fd >= 0) jpv2g_socket_close(srv->fd);
    srv->fd = -1;
}

int jpv2g_udp_client_start(jpv2g_udp_client_t *cli, const char *iface) {
    if (!cli) return -EINVAL;
    memset(cli, 0, sizeof(*cli));
    cli->fd = -1;
    cli->fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (cli->fd < 0) return -errno;
    unsigned int ifidx = 0;
    if (iface && iface[0]) {
        ifidx = jpv2g_if_nametoindex(iface);
        if (ifidx == 0) {
            JPV2G_WARN("if_nametoindex(%s) failed, falling back to default iface", iface);
            ifidx = 0;
        }
    }
    cli->ifindex = ifidx;
    if (setsockopt(cli->fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifidx, sizeof(ifidx)) < 0) {
        int err = -errno;
        jpv2g_socket_close(cli->fd);
        return err;
    }
    (void)set_nonblock(cli->fd);
    return 0;
}

int jpv2g_udp_client_sendrecv(jpv2g_udp_client_t *cli,
                                const uint8_t *req,
                                size_t req_len,
                                uint8_t *resp,
                                size_t resp_len,
                                int timeout_ms) {
    if (!cli || cli->fd < 0 || !req || !resp) return -EINVAL;

    struct sockaddr_in6 dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin6_family = AF_INET6;
    dst.sin6_port = htons(JPV2G_UDP_SDP_SERVER_PORT);
    inet_pton(AF_INET6, JPV2G_SDP_MULTICAST_ADDRESS, &dst.sin6_addr);

    ssize_t s = sendto(cli->fd, req, req_len, 0, (struct sockaddr *)&dst, sizeof(dst));
    if (s < 0 || (size_t)s != req_len) return -errno;

    struct sockaddr_in6 from;
    socklen_t fromlen = sizeof(from);
    memset(&from, 0, sizeof(from));
    ssize_t r = recvfrom_wait_nonblock(cli->fd, resp, resp_len, &from, &fromlen, timeout_ms);
    if (r < 0) return -errno;
    cli->secc_addr = from;
    cli->secc_addrlen = fromlen;
    return (int)r;
}

void jpv2g_udp_client_stop(jpv2g_udp_client_t *cli) {
    if (!cli) return;
    if (cli->fd >= 0) jpv2g_socket_close(cli->fd);
    cli->fd = -1;
}

int jpv2g_tcp_server_start(jpv2g_tcp_server_t *srv, const char *iface, uint16_t port, bool ipv6_only) {
    if (!srv) return -EINVAL;
    memset(srv, 0, sizeof(*srv));
    srv->fd = -1;
    srv->fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (srv->fd < 0) return -errno;
    int on = 1;
    setsockopt(srv->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (ipv6_only) {
        setsockopt(srv->fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
    }
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);
    /* bind to interface (best-effort; fall back to default if lookup fails) */
    unsigned int ifidx = 0;
    if (iface && iface[0]) {
        ifidx = jpv2g_if_nametoindex(iface);
        if (ifidx == 0) {
            JPV2G_WARN("if_nametoindex(%s) failed, binding without scope id", iface);
        }
    }
    addr.sin6_scope_id = ifidx;
    addr.sin6_addr = in6addr_any;
    if (bind(srv->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        int err = -errno;
        jpv2g_socket_close(srv->fd);
        return err;
    }
    if (listen(srv->fd, 4) < 0) {
        int err = -errno;
        jpv2g_socket_close(srv->fd);
        return err;
    }
    (void)set_nonblock(srv->fd);
    srv->port = port;
    return 0;
}

int jpv2g_tcp_server_accept(jpv2g_tcp_server_t *srv,
                              int *client_fd,
                              struct sockaddr_in6 *addr,
                              socklen_t *addrlen,
                              int timeout_ms) {
    if (!srv || srv->fd < 0 || !client_fd) return -EINVAL;
    int fd = accept_wait_nonblock(srv->fd, addr, addrlen, timeout_ms);
    if (fd < 0) return -errno;
    *client_fd = fd;
    return 0;
}

void jpv2g_tcp_server_stop(jpv2g_tcp_server_t *srv) {
    if (!srv) return;
    if (srv->fd >= 0) jpv2g_socket_close(srv->fd);
    srv->fd = -1;
}

int jpv2g_tcp_client_connect(jpv2g_tcp_client_t *cli,
                               const struct sockaddr_in6 *addr,
                               socklen_t addrlen,
                               int timeout_ms) {
    if (!cli || !addr) return -EINVAL;
    cli->fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (cli->fd < 0) return -errno;
    int rc = set_nonblock(cli->fd);
    if (rc != 0) {
        jpv2g_socket_close(cli->fd);
        return rc;
    }
    int cres = connect(cli->fd, (const struct sockaddr *)addr, addrlen);
    if (cres < 0 && errno != EINPROGRESS) {
        int err = -errno;
        jpv2g_socket_close(cli->fd);
        return err;
    }
    struct pollfd pfd = {.fd = cli->fd, .events = POLLOUT};
    int prc = poll(&pfd, 1, timeout_ms);
    if (prc <= 0) {
        int err = prc == 0 ? -ETIMEDOUT : -errno;
        jpv2g_socket_close(cli->fd);
        return err;
    }
    int soerr = 0;
    socklen_t slen = sizeof(soerr);
    if (getsockopt(cli->fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) < 0 || soerr != 0) {
        int err = soerr ? -soerr : -errno;
        jpv2g_socket_close(cli->fd);
        return err;
    }
    /* restore blocking */
    int flags = fcntl(cli->fd, F_GETFL, 0);
    fcntl(cli->fd, F_SETFL, flags & ~O_NONBLOCK);
    return 0;
}

ssize_t jpv2g_tcp_send(int fd, const uint8_t *buf, size_t len) {
    if (fd < 0 || !buf) return -EINVAL;
    ssize_t s = send(fd, buf, len, 0);
    return (s < 0) ? -errno : s;
}

ssize_t jpv2g_tcp_recv(int fd, uint8_t *buf, size_t len, int timeout_ms) {
    if (fd < 0 || !buf) return -EINVAL;
    ssize_t r = recv_wait_nonblock(fd, buf, len, 0, timeout_ms);
    if (r < 0) return -errno;
    return r;
}

void jpv2g_tcp_client_close(jpv2g_tcp_client_t *cli) {
    if (!cli) return;
    if (cli->fd >= 0) jpv2g_socket_close(cli->fd);
    cli->fd = -1;
}
