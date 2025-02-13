/**************************************************************************/
/*                                                                        */
/*       Copyright (c) Microsoft Corporation. All rights reserved.        */
/*                                                                        */
/*       This software is licensed under the Microsoft Software License   */
/*       Terms for Microsoft Azure RTOS. Full text of the license can be  */
/*       found in the LICENSE file at https://aka.ms/AzureRTOS_EULA       */
/*       and in the root directory of this software.                      */
/*                                                                        */
/**************************************************************************/


/**************************************************************************/
/*                                                                        */
/**                                                                       */
/** NetX Component                                                        */
/**                                                                       */
/**   ES-WiFi driver for the STM32 family of microprocessors              */
/**                                                                       */
/*                                                                        */
/**************************************************************************/

#ifndef NX_DRIVER_ISM43362_H
#define NX_DRIVER_ISM43362_H


#ifdef __cplusplus
/* Yes, C++ compiler is present. Use standard C. */
extern "C" {
#endif /* __cplusplus */

/* Include ThreadX header file, if not already. */

#ifndef TX_API_H
#include "tx_api.h"
#endif /* TX_API_H */


/* Include NetX header file, if not already.  */

#ifndef NX_API_H
#include "nx_api.h"
#endif /* NX_API_H */

#define NX_DRIVER_STATE_NOT_INITIALIZED         1
#define NX_DRIVER_STATE_INITIALIZE_FAILED       2
#define NX_DRIVER_STATE_INITIALIZED             3
#define NX_DRIVER_STATE_LINK_ENABLED            4

#define NX_DRIVER_ERROR                         90

/* Define global driver entry function. */
VOID nx_driver_ism43362_entry(NX_IP_DRIVER *driver_req_ptr);

#ifdef __cplusplus
/* Yes, C++ compiler is present. Use standard C. */
}
#endif /* __cplusplus */

#endif /* NX_DRIVER_ISM43362_H */
