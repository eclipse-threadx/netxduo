/***************************************************************************/
/* Copyright (c) 2024 Microsoft Corporation                                */
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/*                                                                         */
/* This program and the accompanying materials are made available under    */
/* the terms of the MIT License which is available at                      */
/* https://opensource.org/licenses/MIT.                                    */
/*                                                                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

// Portions of this file were generated with AI assistance.

#include <time.h>
#include "nx_api.h"
#include "nxd_sntp_client.h"
                 
extern void      test_control_return(UINT status);

#ifdef __linux__
#define LOOP                1000
#define NTP_UTC_DIFF        2208988800
#define START_YEAR          2015
#define START_UTC           1420075385
#define SECONDS_TEN_YEARS   315360000
#define END_YEAR            2035
#define SECONDS_PER_DAY     86400


extern UINT _nx_sntp_client_utility_convert_seconds_to_date(NX_SNTP_TIME *current_NTP_time_ptr,
                                                            UINT current_year,
                                                            NX_SNTP_DATE_TIME *current_date_time_ptr);
static TX_THREAD sntp_client_thread;

static UINT      error_counter;

/* Set up client thread entry point. */
static void      sntp_client_thread_entry(ULONG info);
static UINT      seconds_to_date_check(time_t utc);

/* Define what the initial system looks like.  */
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_sntp_client_seconds_to_date_test_application_define(void *first_unused_memory)
#endif
{

UINT     status;
UCHAR    *free_memory_pointer;

    error_counter = 0;

    free_memory_pointer = (UCHAR *)first_unused_memory;

    /* Create the client thread */
    status = tx_thread_create(&sntp_client_thread, "SNTP Client Thread", sntp_client_thread_entry, 
                              NX_NULL, free_memory_pointer, 2048, 
                              4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    free_memory_pointer = free_memory_pointer + 2048;

    /* Check for errors */
    if (status != TX_SUCCESS)
        error_counter++;
}


/* Convert a UTC time with the SNTP utility and with gmtime, and report
   whether the two dates differ.  */
static UINT    seconds_to_date_check(time_t utc)
{

NX_SNTP_TIME sntp_time;
NX_SNTP_DATE_TIME date_time;
struct tm *tm_value;

    sntp_time.seconds = (ULONG)(NTP_UTC_DIFF + utc);
    sntp_time.fraction = 0;

    tm_value = gmtime(&utc);
    _nx_sntp_client_utility_convert_seconds_to_date(&sntp_time,
                                                    START_YEAR,
                                                    &date_time);

    return(((tm_value -> tm_year + 1900) != (INT)date_time.year) ||
           ((tm_value -> tm_mon + 1) != (INT)date_time.month) ||
           (tm_value -> tm_mday != (INT)date_time.day) ||
           (tm_value -> tm_hour != (INT)date_time.hour) ||
           (tm_value -> tm_min != (INT)date_time.minute) ||
           (tm_value -> tm_sec != (INT)date_time.second) ||
           (date_time.millisecond != 0));
}


/* Define the client thread.  */
void    sntp_client_thread_entry(ULONG info)
{

UINT i;
UINT year;
time_t utc;

    NX_PARAMETER_NOT_USED(info);

    printf("NetX Test:   NETX SNTP Client Seconds To Date Test.....................");

    /* Bug verification. */
    if (seconds_to_date_check((time_t)(3818415600UL - NTP_UTC_DIFF)))
    {
        error_counter++;
    }

    /* The first second of each year, and the last second of the year before.
       Days are counted from 1970, with every fourth year a leap year, which
       holds for every year this range covers.  */
    for (year = START_YEAR + 1; year <= END_YEAR; year++)
    {
        utc = (time_t)(((365 * (year - 1970)) + ((year - 1969) / 4)) * SECONDS_PER_DAY);
        if (seconds_to_date_check(utc) || seconds_to_date_check(utc - 1))
        {
            error_counter++;
            break;
        }
    }

    srand(time(0));
    for (i = 1; i < LOOP; i++)
    {
        utc = (rand() % SECONDS_TEN_YEARS) + START_UTC;
        if (seconds_to_date_check(utc))
        {
            error_counter++;
            break;
        }
    }

    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    else
    {
        printf("SUCCESS!\n");
        test_control_return(0);
    }
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_sntp_client_seconds_to_date_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   NETX SNTP Client Seconds To Date Test.....................N/A\n");

    test_control_return(3);  
}      
#endif
