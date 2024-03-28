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
/*    MX CHIP EMW3080 WiFi driver for the STM32 family of microprocessors */
/*                                                                        */
/*                                                                        */
/**************************************************************************/

#ifndef NX_DRIVER_EMW3080_H
#define NX_DRIVER_EMW3080_H


#ifdef __cplusplus
/* Yes, C++ compiler is present. Use standard C. */
extern "C" {
#endif /* __cplusplus */

/* Indicate that driver source is being compiled. */
#define NX_DRIVER_SOURCE

/* Include driver framework include file. */
#include "nx_driver_framework.h"

/* Public API */
/* Define global driver entry function. */
void nx_driver_emw3080_entry(NX_IP_DRIVER *driver_req_ptr);
void nx_driver_emw3080_interrupt(void);

extern uint8_t WifiMode;

#ifdef __cplusplus
/* Yes, C++ compiler is present. Use standard C. */
}
#endif /* __cplusplus */

#endif /* NX_DRIVER_EMW3080_H */
