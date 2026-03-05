/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#include "jpv2g/time_compat.h"

#if defined(ESP_PLATFORM)
#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#else
#include <time.h>
#endif

int64_t jpv2g_now_monotonic_ms(void) {
#if defined(ESP_PLATFORM)
    return (int64_t)(esp_timer_get_time() / 1000LL);
#else
    struct timespec ts;
    if (timespec_get(&ts, TIME_UTC) != TIME_UTC) {
        return 0;
    }
    return (int64_t)ts.tv_sec * 1000 + (int64_t)(ts.tv_nsec / 1000000);
#endif
}

void jpv2g_sleep_ms(unsigned int sleep_ms) {
#if defined(ESP_PLATFORM)
    TickType_t ticks = (TickType_t)((sleep_ms + portTICK_PERIOD_MS - 1U) / portTICK_PERIOD_MS);
    if (ticks == 0) ticks = 1;
    vTaskDelay(ticks);
#else
    const clock_t start = clock();
    const clock_t wait_ticks = (clock_t)(((double)sleep_ms / 1000.0) * (double)CLOCKS_PER_SEC);
    while ((clock() - start) < wait_ticks) {
    }
#endif
}
