/***************************************************************************
 * Copyright (c) 2024 Microsoft Corporation
 * Copyright (c) 2026 Eclipse ThreadX contributors
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
/**   User Specific - Windows Simulation Port                             */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/


/**************************************************************************/
/*                                                                        */
/*  PORT SPECIFIC C INFORMATION                            RELEASE        */
/*                                                                        */
/*    nx_user_win.h                                      Win32/Win64      */
/*                                                  6.5.2.202603          */
/*                                                                        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Frédéric Desbiens                                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This file overrides selected NetX Duo configuration constants for   */
/*    the Windows simulation port.  Both win32 and win64 flavours of the  */
/*    port run the simulation 10x faster than wall clock (TX_TIMER_PERIOD */
/*    = 1 ms at the default 100 ticks/second).  Protocol-stack constants  */
/*    that are expressed in tick counts and have a large default value    */
/*    may still need to be scaled down to keep CTest within its timeout.  */
/*                                                                        */
/*    This file is intended for test builds only; it is not part of any  */
/*    production configuration.                                            */
/*                                                                        */
/**************************************************************************/

#ifndef NX_USER_WIN_H
#define NX_USER_WIN_H


/* NX_PATH_MTU_INCREASE_WAIT_INTERVAL defaults to 600 (ticks).  At 100
   ticks/second that is 6 real seconds — acceptable in isolation, but the
   win64 test suite runs the related test while other tests are serialised
   on a single core, which can inflate the effective wait.  Reduce to 60
   ticks (0.6 s) so the test exercises the same logic in a fraction of the
   CTest timeout.  */
#ifndef NX_PATH_MTU_INCREASE_WAIT_INTERVAL
#define NX_PATH_MTU_INCREASE_WAIT_INTERVAL   60
#endif


/* NX_IP_TIME_TO_LIVE defaults to 128 (0x80).  NetX Duo initialises the IP
   fragment reassembly timer to MAX(NX_IPV4_MAX_REASSEMBLY_TIME, TTL).  With
   a TTL of 128 the reassembly timeout is 128 IP-periodic intervals = 12 800
   ticks = 12.8 s.  The fragmentation regression tests use NX_IP_TIME_TO_LIVE
   as their delay multiplier so the test duration scales with this value.
   Set it to 20 (> NX_IPV4_MAX_REASSEMBLY_TIME = 15) so the same relative
   timing is preserved while capping the test at ~2.4 s.  Value 20 is still
   large enough for all local simulation routing (TTL is never decremented in
   the RAM driver).  */
#ifndef NX_IP_TIME_TO_LIVE
#define NX_IP_TIME_TO_LIVE                   ((ULONG)20)
#endif


/* NX_ARP_UPDATE_RATE defaults to 10 (IP-periodic intervals between ARP
   retries).  netx_arp_dynamic_entry_fail_test sleeps for
   (NX_ARP_MAXIMUM_RETRIES + 1) * NX_ARP_UPDATE_RATE * NX_IP_PERIODIC_RATE =
   19 * 10 * 100 = 19 000 ticks.  On win32 (x86 under WOW64) the effective
   tick period is higher than on win64 due to context-switch overhead; at
   ~6 ms/tick the sleep takes ~114 s, which barely exceeds the 120 s CTest
   timeout.  Setting NX_ARP_UPDATE_RATE to 1 reduces the sleep to 1 900 ticks
   (~11 s at 6 ms/tick), well within the timeout.  The ARP retry logic is
   unaffected: NX_ARP_MAXIMUM_RETRIES retries still occur, just 10× faster
   in wall-clock time.  */
#ifndef NX_ARP_UPDATE_RATE
#define NX_ARP_UPDATE_RATE                   1
#endif


/* On 64-bit Windows the ABI is LLP64: ULONG is 32 bits while pointers are
   64 bits.  NetX Duo thread/timer entry functions receive the IP/timer
   control-block pointer through a ULONG parameter, which silently truncates
   the upper 32 bits.  The NX_THREAD_EXTENSION_PTR_SET/GET and
   NX_TIMER_EXTENSION_PTR_SET/GET hooks steer around this by storing the
   full 64-bit pointer in the TX_THREAD / TX_TIMER_INTERNAL extension field
   (a VOID *) and recovering it with tx_thread_identify() / the expired-
   timer pointer.  This is identical to what the netxduo64 test build
   already does in its own nx_user.h.  The guard keeps win32 builds
   unaffected: on ILP32/LLP32 ULONG and pointers are both 32 bits so the
   default no-op macros in nx_api.h are correct.  */
#ifdef _WIN64
#define NX_THREAD_EXTENSION_PTR_SET(a, b)                   { \
                                                                TX_THREAD *thread_ptr; \
                                                                thread_ptr = (TX_THREAD *)(a); \
                                                                (thread_ptr -> tx_thread_extension_ptr) = (VOID *)(b); \
                                                            }
#define NX_THREAD_EXTENSION_PTR_GET(a, b, c)                { \
                                                                NX_PARAMETER_NOT_USED(c); \
                                                                TX_THREAD *thread_ptr; \
                                                                thread_ptr = tx_thread_identify(); \
                                                                while (1) \
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
                                                                timer_ptr = (TX_TIMER *)(a); \
                                                                (timer_ptr -> tx_timer_internal.tx_timer_internal_extension_ptr) = (VOID *)(b); \
                                                            }
#define NX_TIMER_EXTENSION_PTR_GET(a, b, c)                 { \
                                                                NX_PARAMETER_NOT_USED(c); \
                                                                if (!_tx_timer_expired_timer_ptr -> tx_timer_internal_extension_ptr) \
                                                                    return; \
                                                                (a) = (b *)(_tx_timer_expired_timer_ptr -> tx_timer_internal_extension_ptr); \
                                                            }
#endif /* _WIN64 */


#endif /* NX_USER_WIN_H */
