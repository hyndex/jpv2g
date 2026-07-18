/*
 * Author: Chinmoy Bhuyan
 * Company: Joulepoint Private Limited
 * Copyright (c) 2025 Chinmoy Bhuyan and Joulepoint Private Limited.
 * Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
 */

/*
 * Process-lifetime cbv2g document workspaces.
 *
 * This is an internal jpv2g header.  The generated EXI document structures are
 * tens of kilobytes each and must never be automatic variables on an embedded
 * protocol-worker stack.  The encoder, SECC request decoder, and optional
 * decoded-response logger each need a distinct set because they can be live at
 * the same time during one request/response transaction.
 */

#pragma once

#include <stdbool.h>

#include "cbv2g/app_handshake/appHand_Datatypes.h"
#include "cbv2g/din/din_msgDefDatatypes.h"
#include "cbv2g/iso_2/iso2_msgDefDatatypes.h"

void jpv2g_cbv2g_workspace_init(void);
bool jpv2g_cbv2g_workspace_ready(void);

struct appHand_exiDocument *jpv2g_cbv2g_encode_app_workspace(void);
struct iso2_exiDocument *jpv2g_cbv2g_encode_iso_workspace(void);
struct din_exiDocument *jpv2g_cbv2g_encode_din_workspace(void);

struct appHand_exiDocument *jpv2g_cbv2g_secc_request_app_workspace(void);
struct iso2_exiDocument *jpv2g_cbv2g_secc_request_iso_workspace(void);
struct din_exiDocument *jpv2g_cbv2g_secc_request_din_workspace(void);

struct appHand_exiDocument *jpv2g_cbv2g_secc_log_app_workspace(void);
struct iso2_exiDocument *jpv2g_cbv2g_secc_log_iso_workspace(void);
struct din_exiDocument *jpv2g_cbv2g_secc_log_din_workspace(void);
