/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#pragma once

#include <stdio.h>

typedef enum {
    JPV2G_LOG_TRACE = 0,
    JPV2G_LOG_DEBUG,
    JPV2G_LOG_INFO,
    JPV2G_LOG_WARN,
    JPV2G_LOG_ERROR,
    JPV2G_LOG_FATAL
} jpv2g_log_level_t;

#ifndef JPV2G_LOG_LEVEL
#define JPV2G_LOG_LEVEL JPV2G_LOG_INFO
#endif

#define jpv2g_log(level, ...)                                                                   \
    do {                                                                                          \
        if ((level) >= JPV2G_LOG_LEVEL) {                                                       \
            const char *lvl_str =                                                                 \
                (level) == JPV2G_LOG_TRACE ? "TRACE" :                                          \
                (level) == JPV2G_LOG_DEBUG ? "DEBUG" :                                          \
                (level) == JPV2G_LOG_INFO  ? "INFO " :                                          \
                (level) == JPV2G_LOG_WARN  ? "WARN " :                                          \
                (level) == JPV2G_LOG_ERROR ? "ERROR" : "FATAL";                                 \
            fprintf(stderr, "[%s] %s:%d: ", lvl_str, __FILE__, __LINE__);                      \
            fprintf(stderr, __VA_ARGS__);                                                        \
            fputc('\n', stderr);                                                                 \
        }                                                                                         \
    } while (0)

#define JPV2G_TRACE(...) jpv2g_log(JPV2G_LOG_TRACE, __VA_ARGS__)
#define JPV2G_DEBUG(...) jpv2g_log(JPV2G_LOG_DEBUG, __VA_ARGS__)
#define JPV2G_INFO(...)  jpv2g_log(JPV2G_LOG_INFO,  __VA_ARGS__)
#define JPV2G_WARN(...)  jpv2g_log(JPV2G_LOG_WARN,  __VA_ARGS__)
#define JPV2G_ERROR(...) jpv2g_log(JPV2G_LOG_ERROR, __VA_ARGS__)
#define JPV2G_FATAL(...) jpv2g_log(JPV2G_LOG_FATAL, __VA_ARGS__)
