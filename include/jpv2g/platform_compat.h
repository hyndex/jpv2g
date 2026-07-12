/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#pragma once

#include <stdio.h>
#include <string.h>

/*
 * Socket portability boundary.
 *
 * The production ESP32 build uses lwIP, while the library's CMake build and
 * unit/integration tests run against the native POSIX socket API.  Keep the
 * wrapper functions below identical for both environments so networking code
 * does not need platform conditionals of its own.
 */
#if defined(__has_include) && __has_include(<lwip/sockets.h>)
#include <lwip/sockets.h>
#include <lwip/inet.h>
#include <lwip/netdb.h>
#include <lwip/ip6_addr.h>
#if defined(__has_include) && __has_include(<lwip/netif.h>)
#include <lwip/netif.h>
#endif
#if defined(__has_include) && __has_include(<lwip/if_api.h>)
#include <lwip/if_api.h>
#define JPV2G_HAVE_IF_NAMETOINDEX 1
#endif
#if defined(__has_include) && __has_include(<lwip/inet6.h>)
#include <lwip/inet6.h>
#endif
#if defined(__has_include) && __has_include(<lwip/fcntl.h>)
#include <lwip/fcntl.h>
#elif defined(__has_include) && __has_include(<fcntl.h>)
#include <fcntl.h>
#endif
#define JPV2G_HAVE_LWIP 1
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#define JPV2G_HAVE_POSIX_SOCKETS 1
#define JPV2G_HAVE_IF_NAMETOINDEX 1
#endif

#ifndef JPV2G_HAVE_IF_NAMETOINDEX
static inline unsigned int jpv2g_if_nametoindex(const char *ifname) {
    (void)ifname;
    return 0;
}
#else
static inline unsigned int jpv2g_if_nametoindex(const char *ifname) {
    if (!ifname || !ifname[0]) return 0;
    unsigned int idx = if_nametoindex(ifname);
    if (idx != 0) return idx;
#if defined(JPV2G_HAVE_LWIP)
#if defined(__has_include) && __has_include(<lwip/netif.h>)
    /* lwIP if_nametoindex can fail for app-added netifs on some ESP-IDF builds. */
    struct netif *n = netif_list;
    while (n) {
        char nm[8];
        int written = snprintf(nm, sizeof(nm), "%c%c%u", n->name[0], n->name[1], (unsigned)n->num);
        if (written > 0 && strcmp(nm, ifname) == 0) {
#if LWIP_IPV6
            return (unsigned int)netif_get_index(n);
#else
            return (unsigned int)(n->num + 1U);
#endif
        }
        n = n->next;
    }
#endif
#endif
    return 0;
}
#endif

static inline int jpv2g_socket_close(int fd) {
#if defined(lwip_close)
    return lwip_close(fd);
#else
    return close(fd);
#endif
}

// Half-close to wake a blocking recv() on `fd` from another task WITHOUT
// releasing the fd number. Lets a second task signal "stop" to a worker blocked
// in recv() while keeping that worker the sole owner of the eventual close() —
// avoiding a double-close / fd-reuse race (PLC crash audit B3, 2026-06-24).
static inline int jpv2g_socket_shutdown(int fd) {
#if defined(lwip_shutdown)
    return lwip_shutdown(fd, SHUT_RDWR);
#else
    return shutdown(fd, SHUT_RDWR);
#endif
}

// EVX-1 (2026-07-03; matches EVerest EvseV2G 2025.12.0 "Wait for peer FIN before
// closing TCP socket"): graceful, BOUNDED half-close for an orderly session end.
// A bare close() on a socket that still has unread RX data makes lwIP emit a RST
// instead of a FIN, which can discard the final Res the SECC just queued (e.g.
// SessionStopRes / the Pause ACK) before the EV has read it. So: send our FIN
// (SHUT_WR), then drain RX until the peer FINs (recv==0) / errors / the linger
// budget elapses, then close. The per-recv SO_RCVTIMEO (200 ms) times the drain
// and a hard iteration cap bounds total wall time to ~linger_ms so the HLC worker
// never wedges on a chatty or half-dead peer.
static inline int jpv2g_socket_graceful_close(int fd, int linger_ms) {
    if (fd < 0) return -1;
#if defined(lwip_shutdown)
    (void)lwip_shutdown(fd, SHUT_WR);
#else
    (void)shutdown(fd, SHUT_WR);
#endif
    if (linger_ms > 0) {
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 200 * 1000;  // 200 ms per draining recv()
#if defined(lwip_setsockopt)
        (void)lwip_setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#else
        (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
        char sink[64];
        int iters = linger_ms / 200;
        if (iters < 1) iters = 1;
        if (iters > 10) iters = 10;  // hard cap: <= ~2 s total
        for (int i = 0; i < iters; ++i) {
#if defined(lwip_recv)
            int n = lwip_recv(fd, sink, sizeof(sink), 0);
#else
            int n = (int)recv(fd, sink, sizeof(sink), 0);
#endif
            if (n <= 0) break;  // peer FIN (0), or error/timeout (<0)
        }
    }
#if defined(lwip_close)
    return lwip_close(fd);
#else
    return close(fd);
#endif
}
