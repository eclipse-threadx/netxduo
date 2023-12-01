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


extern UINT _nx_sntp_client_utility_convert_seconds_to_date(NX_SNTP_TIME *current_NTP_time_ptr,
                                                            UINT current_year,
                                                            NX_SNTP_DATE_TIME *current_date_time_ptr);
static TX_THREAD sntp_client_thread;

static UINT      error_counter;

/* Set up client thread entry point. */
static void      sntp_client_thread_entry(ULONG info);

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


/* Define the client thread.  */
void    sntp_client_thread_entry(ULONG info)
{

UINT status;
UINT i;
NX_SNTP_TIME sntp_time;
NX_SNTP_DATE_TIME date_time;
time_t utc;
struct tm *tm_value;

    printf("NetX Test:   NETX SNTP Client Seconds To Date Test.....................");

    srand(time(0));
    sntp_time.fraction = 0;
    for (i = 0; i < LOOP; i++)
    {
        if (i == 0)
        {
            sntp_time.seconds = 3818415600;   /* Bug verification. */
            utc = sntp_time.seconds - NTP_UTC_DIFF;
        }
        else
        {
            utc = (rand() % SECONDS_TEN_YEARS) + START_UTC;
            sntp_time.seconds = NTP_UTC_DIFF + utc;
        }

        /* Convert time by by gmtime and SNTP utility. */
        tm_value = gmtime(&utc);
        _nx_sntp_client_utility_convert_seconds_to_date(&sntp_time,
                                                        START_YEAR,
                                                        &date_time);

        /* Compare result. */
        if (((tm_value -> tm_year + 1900) != date_time.year) ||
            ((tm_value -> tm_mon + 1) != date_time.month) ||
            (tm_value -> tm_mday != date_time.day) ||
            (tm_value -> tm_hour != date_time.hour) ||
            (tm_value -> tm_min != date_time.minute) ||
            (tm_value -> tm_sec != date_time.second) ||
            (date_time.millisecond != 0))
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
