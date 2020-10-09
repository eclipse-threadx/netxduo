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

#ifndef TRANSPORT_PROTOCOL_H
#define TRANSPORT_PROTOCOL_H

typedef enum {
    TRANSPORT_PROTOCOL_TCP,
    TRANSPORT_PROTOCOL_UDP,
    TRANSPORT_PROTOCOL_ICMP
} transport_protocol_t;

#endif /* TRANSPORT_PROTOCOL_H */
