/***************************************************************************/
/* Copyright (c) 2024 Microsoft Corporation                                */
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/*                                                                         */
/* This program and the accompanying materials are made available under    */
/* the terms of the MIT License which is available at                      */
/* https://opensource.org/licenses/MIT.                                    */
/*                                                                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

#include "nx_api.h"

/* Declare the function.  */
UINT   dhcp_get_option_value(UCHAR *bootp_message, UINT option, ULONG *value, UINT length); 
UCHAR  *dhcp_search_buffer(UCHAR *bootp_message, UINT option, UINT length);     
ULONG  dhcp_get_data(UCHAR *data, UINT size);                                                           
