/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

#pragma once

#include "jpv2g/messages.h"

static inline int jpv2g_timeout_for_message(jpv2g_message_type_t type) {
    switch (type) {
        case JPV2G_SUPP_APP_PROTOCOL_RES: return 2000;
        case JPV2G_SESSION_SETUP_RES: return 2000;
        case JPV2G_SERVICE_DISCOVERY_RES: return 2000;
        case JPV2G_SERVICE_DETAIL_RES: return 5000;
        case JPV2G_PAYMENT_SERVICE_SELECTION_RES: return 2000;
        case JPV2G_PAYMENT_DETAILS_RES: return 5000;
        case JPV2G_CERTIFICATE_INSTALLATION_RES: return 5000;
        case JPV2G_CERTIFICATE_UPDATE_RES: return 5000;
        case JPV2G_AUTHORIZATION_RES: return 2000;
        case JPV2G_CHARGE_PARAMETER_DISCOVERY_RES: return 2000;
        case JPV2G_CABLE_CHECK_RES: return 7000;
        case JPV2G_POWER_DELIVERY_RES: return 5000;
        case JPV2G_CHARGING_STATUS_RES: return 2000;
        case JPV2G_CURRENT_DEMAND_RES: return 250;
        case JPV2G_METERING_RECEIPT_RES: return 2000;
        case JPV2G_WELDING_DETECTION_RES: return 2000;
        case JPV2G_SESSION_STOP_RES: return 2000;
        case JPV2G_PRE_CHARGE_RES: return 2000;
        default: return 2000;
    }
}
