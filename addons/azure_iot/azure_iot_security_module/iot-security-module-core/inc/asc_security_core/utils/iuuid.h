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

#ifndef IUUID_H
#define IUUID_H

#include <stdint.h>


/**
 * @brief Generate a binary uuid
 * @note: not thread-safe.
 *
 * @param buf - The buffer to write the UUID to. Size should be at least 16 bytes.
 *
 * @return 0 on sucess, -1 otherwise
 */
int iuuid_generate(uint8_t *buf);


#endif /* IUUID_H */