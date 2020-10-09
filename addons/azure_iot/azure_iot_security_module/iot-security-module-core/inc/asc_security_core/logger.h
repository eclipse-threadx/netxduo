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

#ifndef LOGGER_H
#define LOGGER_H

#include "asc_security_core/utils/macros.h"

#define LOG_LEVEL_NOTSET    0
#define LOG_LEVEL_DEBUG     1
#define LOG_LEVEL_INFO      2
#define LOG_LEVEL_WARN      3
#define LOG_LEVEL_ERROR     4
#define LOG_LEVEL_FATAL     5


#if LOG_LEVEL == LOG_LEVEL_NOTSET
    #define log_debug(...)
    #define log_info(...)
    #define log_warn(...)
    #define log_error(...)
    #define log_fatal(...)
#else
    #include <stdio.h>
    #include <string.h>
    #include <stdbool.h>
    #include <stdint.h>

    #define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
    #define MDC_FORMAT "%s [%s/%s:%d] "

    bool logger_init();
    void logger_deinit();
    void logger_log(const char *level, const char *filename, const char *func, int line, const char *fmt, ...) ATTRIBUTE_FORMAT(5, 6);

    // define log by severity according to LOG_LEVEL
    #if LOG_LEVEL > LOG_LEVEL_DEBUG
        #define log_debug(...)
    #else
        #define log_debug(...)     logger_log("DEBUG", __FILENAME__, __func__, __LINE__, ##__VA_ARGS__)
    #endif
    #if LOG_LEVEL > LOG_LEVEL_INFO
        #define log_info(...)
    #else
        #define log_info(...)      logger_log("INFO", __FILENAME__, __func__, __LINE__, ##__VA_ARGS__)
    #endif
    #if LOG_LEVEL > LOG_LEVEL_WARN
        #define log_warn(...)
    #else
        #define log_warn(...)      logger_log("WARN", __FILENAME__, __func__, __LINE__, ##__VA_ARGS__)
    #endif
    #if LOG_LEVEL > LOG_LEVEL_ERROR
        #define log_error(...)
    #else
        #define log_error(...)     logger_log("ERROR", __FILENAME__, __func__, __LINE__, ##__VA_ARGS__)
    #endif
    #if LOG_LEVEL > LOG_LEVEL_FATAL
        #define log_fatal(...)
    #else
        #define log_fatal(...)     logger_log("FATAL", __FILENAME__, __func__, __LINE__, ##__VA_ARGS__)
    #endif
#endif


#endif //LOGGER_H