/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#include "jpv2g/session.h"

#include <errno.h>
#include <string.h>

#include "jpv2g/byte_utils.h"

int jpv2g_generate_session_id(const uint8_t current[8], uint8_t out[8]) {
    if (!out) return -EINVAL;
    uint8_t candidate[8];
    int attempts = 0;
    do {
        int rc = jpv2g_random_bytes(candidate, sizeof(candidate));
        if (rc != 0) return rc;
        attempts++;
        /* Ensure non-zero and not equal to current (if provided) */
    } while (((candidate[0] | candidate[1] | candidate[2] | candidate[3] |
               candidate[4] | candidate[5] | candidate[6] | candidate[7]) == 0) ||
             (current && memcmp(candidate, current, 8) == 0 && attempts < 8));

    memcpy(out, candidate, 8);
    return 0;
}
