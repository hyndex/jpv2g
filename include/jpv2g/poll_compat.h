/*
 * Minimal poll() compatibility for platforms without <poll.h>.
 * Falls back to a select()-based shim and supports POLLIN/POLLOUT,
 * which is sufficient for jp-v2g-c usage on ESP-IDF/Arduino.
 */
#pragma once

/* Prefer native poll where available */
#if defined(__has_include)
#  if __has_include(<poll.h>)
#    include <poll.h>
#  elif __has_include(<sys/poll.h>)
#    include <sys/poll.h>
#  endif
#endif

#if !defined(POLLIN)
#include <errno.h>
#include <stddef.h>
#if defined(__has_include) && __has_include(<lwip/select.h>)
#include <lwip/select.h>
#else
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#endif

#define POLLIN 0x0001
#define POLLOUT 0x0004

struct pollfd {
    int fd;
    short events;
    short revents;
};

static inline int poll(struct pollfd *fds, size_t nfds, int timeout_ms) {
    if (!fds || nfds == 0) {
        errno = EINVAL;
        return -1;
    }
    fd_set rfds;
    fd_set wfds;
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    int maxfd = -1;
    for (size_t i = 0; i < nfds; ++i) {
        fds[i].revents = 0;
        if (fds[i].fd < 0) continue;
        if (fds[i].events & POLLIN) FD_SET(fds[i].fd, &rfds);
        if (fds[i].events & POLLOUT) FD_SET(fds[i].fd, &wfds);
        if (fds[i].fd > maxfd) maxfd = fds[i].fd;
    }
    if (maxfd < 0) {
        errno = EINVAL;
        return -1;
    }
    struct timeval tv;
    struct timeval *ptv = NULL;
    if (timeout_ms >= 0) {
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        ptv = &tv;
    }
    int rc = select(maxfd + 1, &rfds, &wfds, NULL, ptv);
    if (rc <= 0) return rc;
    for (size_t i = 0; i < nfds; ++i) {
        if (fds[i].fd < 0) continue;
        if ((fds[i].events & POLLIN) && FD_ISSET(fds[i].fd, &rfds)) fds[i].revents |= POLLIN;
        if ((fds[i].events & POLLOUT) && FD_ISSET(fds[i].fd, &wfds)) fds[i].revents |= POLLOUT;
    }
    return rc;
}
#endif
