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
/**************************************************************************/
/**                                                                       */
/** NetX Component                                                        */
/**                                                                       */
/**   User Specific                                                       */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/


/**************************************************************************/
/*                                                                        */
/*  PORT SPECIFIC C INFORMATION                            RELEASE        */
/*                                                                        */
/*    nx_user.h                                           PORTABLE C      */
/*                                                           6.0          */
/*                                                                        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This file contains user defines for configuring NetX in specific    */
/*    ways. This file will have an effect only if the application and     */
/*    NetX library are built with NX_INCLUDE_USER_DEFINE_FILE defined.    */
/*    Note that all the defines in this file may also be made on the      */
/*    command line when building NetX library and application objects.    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  05-19-2020     Yuxin Zhou               Initial Version 6.0           */
/*                                                                        */
/**************************************************************************/

#ifndef NX_USER_H
#define NX_USER_H

/* Define the extension to hold the control block for 64-bit mode.  */
#define NX_THREAD_EXTENSION_PTR_SET(a, b)                   { \
                                                                TX_THREAD *thread_ptr; \
                                                                thread_ptr = (TX_THREAD *) (a); \
                                                                (thread_ptr -> tx_thread_extension_ptr) = (VOID *)(b); \
                                                            }
#define NX_THREAD_EXTENSION_PTR_GET(a, b, c)                { \
                                                                NX_PARAMETER_NOT_USED(c); \
                                                                TX_THREAD *thread_ptr; \
                                                                thread_ptr = tx_thread_identify(); \
                                                                while(1)\
                                                                { \
                                                                    if (thread_ptr -> tx_thread_extension_ptr) \
                                                                    { \
                                                                        (a) = (b *)(thread_ptr -> tx_thread_extension_ptr); \
                                                                        break; \
                                                                    } \
                                                                    tx_thread_sleep(1); \
                                                                } \
                                                            }
#define NX_TIMER_EXTENSION_PTR_SET(a, b)                    { \
                                                                TX_TIMER *timer_ptr; \
                                                                timer_ptr = (TX_TIMER *) (a);   \
                                                                (timer_ptr -> tx_timer_internal.tx_timer_internal_extension_ptr) = (VOID *)(b); \
                                                            }
#define NX_TIMER_EXTENSION_PTR_GET(a, b, c)                 { \
                                                                NX_PARAMETER_NOT_USED(c); \
                                                                if (!_tx_timer_expired_timer_ptr -> tx_timer_internal_extension_ptr) \
                                                                    return; \
                                                                (a) = (b *)(_tx_timer_expired_timer_ptr -> tx_timer_internal_extension_ptr); \
                                                            }

#endif

