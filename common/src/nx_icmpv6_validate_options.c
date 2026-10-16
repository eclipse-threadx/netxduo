/***************************************************************************
 * Copyright (c) 2024 Microsoft Corporation
 * Copyright (c) 2025-present Eclipse ThreadX Contributors
 *
 * This program and the accompanying materials are made available under the
 * terms of the MIT License which is available at
 * https://opensource.org/licenses/MIT.
 *
 * SPDX-License-Identifier: MIT
 **************************************************************************/


/**************************************************************************/
/**************************************************************************/
/**                                                                       */
/** NetX Component                                                        */
/**                                                                       */
/**   Internet Control Message Protocol (ICMP)                            */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SOURCE_CODE


/* Include necessary system files.  */

#include "nx_api.h"
#include "nx_ipv6.h"
#include "nx_icmpv6.h"

#ifdef FEATURE_NX_IPV6

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_icmpv6_validate_options                         PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function validates ICMPv6 additional options.                  */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    option                       Pointer to ICMPv6 option               */
/*    length                       Length of the Option field             */
/*    additional_check             Whether or not caller wishes to        */
/*                                    perform additoinal verification     */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    NX_SUCCESS                   Options are valid                      */
/*    NX_NOT_SUCCESS               Options are invalid                    */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_icmpv6_validate_neighbor_messages                               */
/*    _nx_icmpv6_validate_ra                                              */
/*                                                                        */
/**************************************************************************/
UINT _nx_icmpv6_validate_options(NX_ICMPV6_OPTION *option, INT length, INT additional_check)
{

UINT option_len;

    /* Parse all option headers from the ICMPv6 header. */
    /* GHSA-rf32-h832-hg8r:
       Verify that the length is at least 2 to cover nx_icmpv6_option_length and
       nx_icmpv6_option_type.
       That bound stopped with one or two bytes still unexamined, and the test after
       the loop only rejected a negative remainder, so an option area sized to leave
       such a tail was reported valid. Every consumer then read an option header at
       that tail. Every byte must be accounted for: the loop runs while any length
       remains, a remainder too short to hold an option header is rejected inside it,
       and the area has to divide exactly into whole options. */
    while (length > 0)
    {
        /* A remainder this short cannot hold an option header. */
        if (length < 2)
        {
            return(NX_NOT_SUCCESSFUL);
        }

        /* Verify that the option length is not zero. */
        if (option -> nx_icmpv6_option_length == 0)
        {
            return(NX_NOT_SUCCESSFUL);
        }

        /* Also check for NO SOURCE LINK LAYER ADDRESS.  */
        if ((additional_check == NX_NO_SLLA) &&
            (option -> nx_icmpv6_option_type == 1))
        {

            return(NX_NOT_SUCCESSFUL);
        }

        /* Get the next option. */
        option_len = ((UINT)option -> nx_icmpv6_option_length) << 3;
        length -= (INT)option_len;

        /*lint -e{923} suppress cast between pointer and ULONG, since it is necessary  */
        option = (NX_ICMPV6_OPTION *)NX_UCHAR_POINTER_ADD(option, option_len);
    }

    if (length != 0)
    {

        /* Invalid packet length. */
        return(NX_NOT_SUCCESSFUL);
    }

    return(NX_SUCCESS);
}

#endif /* FEATURE_NX_IPV6 */

