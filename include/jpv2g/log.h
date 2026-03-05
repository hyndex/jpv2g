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

#define jpv2g_log(level, fmt, ...)                                                              \
    do {                                                                                          \
        if ((level) >= JPV2G_LOG_LEVEL) {                                                       \
            const char *lvl_str =                                                                 \
                (level) == JPV2G_LOG_TRACE ? "TRACE" :                                          \
                (level) == JPV2G_LOG_DEBUG ? "DEBUG" :                                          \
                (level) == JPV2G_LOG_INFO  ? "INFO " :                                          \
                (level) == JPV2G_LOG_WARN  ? "WARN " :                                          \
                (level) == JPV2G_LOG_ERROR ? "ERROR" : "FATAL";                                 \
            fprintf(stderr, "[%s] %s:%d: " fmt "\n", lvl_str, __FILE__, __LINE__, ##__VA_ARGS__); \
        }                                                                                         \
    } while (0)

#define JPV2G_TRACE(fmt, ...) jpv2g_log(JPV2G_LOG_TRACE, fmt, ##__VA_ARGS__)
#define JPV2G_DEBUG(fmt, ...) jpv2g_log(JPV2G_LOG_DEBUG, fmt, ##__VA_ARGS__)
#define JPV2G_INFO(fmt, ...)  jpv2g_log(JPV2G_LOG_INFO,  fmt, ##__VA_ARGS__)
#define JPV2G_WARN(fmt, ...)  jpv2g_log(JPV2G_LOG_WARN,  fmt, ##__VA_ARGS__)
#define JPV2G_ERROR(fmt, ...) jpv2g_log(JPV2G_LOG_ERROR, fmt, ##__VA_ARGS__)
#define JPV2G_FATAL(fmt, ...) jpv2g_log(JPV2G_LOG_FATAL, fmt, ##__VA_ARGS__)
