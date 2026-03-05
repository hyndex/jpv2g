/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#pragma once

#include <stdio.h>
#include <string.h>

/* MCU-only stack: lwIP is required for socket networking. */
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
#error "jpv2g is microcontroller-only and requires lwIP headers."
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
