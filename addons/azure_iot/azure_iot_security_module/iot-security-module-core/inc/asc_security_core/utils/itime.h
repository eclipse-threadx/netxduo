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

#ifndef ITIME_H
#define ITIME_H

#include <stdint.h>
#include <time.h>

#define SEC_MIN (60)
#define SEC_HOUR (SEC_MIN * 60)
#define SEC_DAY (SEC_HOUR * 24)

typedef uint32_t (*unix_time_callback_t)(uint32_t *unix_time);

void itime_init(unix_time_callback_t time_callback);

/**
 * @brief Get current time and put it in *TIMER if TIMER is not NULL
 *
 * @details This function provides the same functionality as the
 *          standard C @c time() function.
 */
uint32_t itime_time(uint32_t *timer);


#endif /* ITIME_H */
