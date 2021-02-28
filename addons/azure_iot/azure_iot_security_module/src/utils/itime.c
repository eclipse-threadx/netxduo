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

#include <asc_config.h>

#include <time.h>

#include "asc_security_core/utils/itime.h"

static unix_time_callback_t _time_callback = NULL;

void itime_init(unix_time_callback_t time_callback)
{
    _time_callback = time_callback;
}

time_t itime_time(time_t *timer)
{
    if (_time_callback == NULL)
    {
        return -1;
    }

    return _time_callback(timer);
}
