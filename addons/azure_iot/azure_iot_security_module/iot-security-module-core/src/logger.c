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

#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include "asc_security_core/logger.h"

#if LOG_LEVEL != LOG_LEVEL_NOTSET
bool logger_init()
{
    return true;
}

void logger_deinit()
{

}

void logger_log(const char *level, const char *filename, const char *func, int line, const char *fmt, ...)
{
    printf(MDC_FORMAT , level, filename, func, line);

    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);

    printf("\n");
}
#endif
