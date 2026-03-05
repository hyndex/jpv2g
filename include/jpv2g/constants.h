/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#pragma once

#include <stdint.h>

#define JPV2G_V2GTP_PAYLOAD_EXI        0x8001
#define JPV2G_V2GTP_PAYLOAD_SDP_REQ    0x9000
#define JPV2G_V2GTP_PAYLOAD_SDP_RES    0x9001

#define JPV2G_SECURITY_WITH_TLS        0x00
#define JPV2G_SECURITY_WITHOUT_TLS     0x10
#define JPV2G_TRANSPORT_TCP            0x00
#define JPV2G_TRANSPORT_UDP            0x10

#define JPV2G_SDP_MULTICAST_ADDRESS    "FF02::1"
#define JPV2G_UDP_SDP_SERVER_PORT      15118

#define JPV2G_TIMEOUT_SEQUENCE_SECC    60000
#define JPV2G_TIMEOUT_SEQUENCE_EVCC    40000
#define JPV2G_TIMEOUT_COMM_SETUP       20000
#define JPV2G_TIMEOUT_ONGOING          60000
#define JPV2G_TIMEOUT_CABLE_CHECK      40000
#define JPV2G_TIMEOUT_PRE_CHARGE       7000
#define JPV2G_TIMEOUT_SDP_RESPONSE     250
#define JPV2G_SDP_REQUEST_MAX_COUNTER  50
/* Wait for the very first HLC packet after link-up (e.g., post-SLAC). */
#define JPV2G_TIMEOUT_FIRST_HLC        20000

#define JPV2G_MAX_EXI_SIZE             4096
#define JPV2G_MAX_V2GTP_SIZE           (JPV2G_V2GTP_HEADER_LEN + JPV2G_MAX_EXI_SIZE)
