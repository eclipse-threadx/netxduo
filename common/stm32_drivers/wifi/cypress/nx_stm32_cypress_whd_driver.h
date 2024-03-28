/***************************************************************************
 * Copyright (c) 2024 Microsoft Corporation
 *
 * This program and the accompanying materials are made available under the
 * terms of the MIT License which is available at
 * https://opensource.org/licenses/MIT.
 *
 * SPDX-License-Identifier: MIT
 **************************************************************************/

/**************************************************************************/
/*                                                                        */
/*                                                                        */
/*  NetX Component                                                        */
/*                                                                        */
/*    Cypress CHIP WiFi driver for the STM32 family of microprocessors    */
/*                                                                        */
/*                                                                        */
/**************************************************************************/

#ifndef NX_STM32_CYPRESS_WHD_DRIVER_H
#define NX_STM32_CYPRESS_WHD_DRIVER_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "whd.h"
#include "nx_api.h"

/* Mode for the WiFi module, i.e. Station or Access Point. */
typedef enum
{
  WIFI_MODE_STA,
  WIFI_MODE_AP
} wifi_mode_t;


/* Public API */
VOID nx_driver_cypress_whd_entry(NX_IP_DRIVER *driver_req_ptr);
void cy_network_process_ethernet_data(whd_interface_t interface, whd_buffer_t buffer);

extern whd_interface_t *Ifp;
extern wifi_mode_t WifiMode;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* NX_STM32_CYPRESS_WHD_DRIVER_H */
