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

#ifndef __MACROS_H__
#define __MACROS_H__

#ifdef __clang__
#define ATTRIBUTE_FORMAT(fmt_index, args_index) __attribute__((__format__ (__printf__, fmt_index, args_index)))
#elif __GNUC__
#define ATTRIBUTE_FORMAT(fmt_index, args_index) __attribute__((format(printf, fmt_index, args_index)))
#else
#define ATTRIBUTE_FORMAT(fmt_index, args_index)
#endif

#endif /* __MACROS_H__ */
