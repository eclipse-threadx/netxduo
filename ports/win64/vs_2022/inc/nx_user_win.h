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


#endif /* NX_USER_WIN_H */
