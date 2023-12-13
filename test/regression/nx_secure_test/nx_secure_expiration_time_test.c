#include <stdio.h>
#include <string.h>

typedef unsigned short USHORT;
typedef unsigned int UINT;
typedef unsigned long ULONG;
typedef long LONG;
typedef unsigned char UCHAR;

#define NX_SECURE_ASN_TAG_UTC_TIME 1

#define date_2_chars_to_int(buffer, index)  (LONG)(((buffer[index] - '0') * 10) + (buffer[index + 1] - '0'))

/* Array indexed on month - 1 gives the total number of days in all previous months (through last day of previous
   month). Leap years are handled in the logic below and are not reflected in this array. */
                                         /* J   F   M   A    M    J    J    A    S    O    N    D */
static const UINT days_before_month[12] = { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 }; 

static UINT _nx_secure_x509_asn1_time_to_unix_convert(const UCHAR *asn1_time, USHORT asn1_length, USHORT format, ULONG *unix_time)
{
LONG year, month, day, hour, minute, second;
UINT index;

    index = 0;

    /* See what format we are using. */
    if(format == NX_SECURE_ASN_TAG_UTC_TIME)
    {
        /* UTCTime is either "YYMMDDhhmm[ss]Z" or "YYMMDDhhmm[ss](+|-)hhmm" */
        year = date_2_chars_to_int(asn1_time, 0);
        month = date_2_chars_to_int(asn1_time, 2);
        day = date_2_chars_to_int(asn1_time, 4) - 1; /* For calculations, day is 0-based. */
        hour = date_2_chars_to_int(asn1_time, 6);
        minute = date_2_chars_to_int(asn1_time, 8);
        second = 0;


        /* Check the next field, can be 'Z' for Zulu time (GMT) or [+/-] for local time offset. */
        index = 10;

        /* Check for optional seconds. */
        if(asn1_time[index] != 'Z' && asn1_time[index] != '+' && asn1_time[index] != '-')
        {
            second = date_2_chars_to_int(asn1_time, index);
            index += 2;
        }

        /* Check for GMT time or local time offset. */ 
        if(asn1_time[index] != 'Z')
        {
            /* Check for optional local time offset. NOTE: The additions and subtractions here may
             * result in values > 24 or < 0 but that is OK for the calculations. */
            if(asn1_time[index] == '+')
            {
                index++; /* Skip the '+' */
                hour -= date_2_chars_to_int(asn1_time, index);
                index += 2;
                minute -= date_2_chars_to_int(asn1_time, index);
                index += 2;
            }
            else if(asn1_time[index] == '-')
            {
                index++; /* Skip the '-' */
                hour += date_2_chars_to_int(asn1_time, index);
                index += 2;
                minute += date_2_chars_to_int(asn1_time, index);
                index += 2;
            }
            else
            {
                /* Not a correct UTC time! */
                return(1);
            }
        }
        
        printf("year: %d, month: %d, day: %d, hour: %d, minute: %d, second: %d\n", year, month, day, hour, minute, second);

        /* Now we have our time in integers, calculate leap years. We aren't concerned with years outside the UNIX
           time range of 1970-2038 so we can assume every 4 years starting with 1972 is a leap year (years divisible 
           by 100 are NOT leap years unless also divisible by 400, which the year 2000 is). Using integer division gives
           us the floor of the number of 4 year periods, so add 1. */
        if(year >= 70)
        {
            /* Year is before 2000. Subtract 72 to get duration from first leap year in epoch. */
            year -= 70;
            if(year >= 2)
            {
                day += ((year + 2) / 4) + 1; 
            }
        }
        else
        {
            /* Year is 2000 or greater. Add 28 (2000-1972) to get duration from first leap year in epoch. */
            year += 30;
            day += ((year - 2) / 4) + 1;
        } 
        
        /* Finally, calculate the number of seconds from the extracted values. */
        day += year * 365;
        day += days_before_month[month - 1];
        hour += day * 24;
        minute += hour * 60;
        second += minute * 60;
        
        /* Finally, return the converted time. */
        *unix_time = second;
    }
    return(0);
}


int main()
{
ULONG unix_time;
UINT i;

/*  1500498889 == (ISO 8601: 2017-07-19T21:14:49Z) */

struct {
    UCHAR *asn_time;
    ULONG unix_time;
} test_data[] = 
{
   { "170719211449Z", 1500498889 },
   { "7001010000Z", 0 },
   { "010908184640-0700", 1000000000 },
   { "010909014640Z", 1000000000 },
};

UINT test_data_len = sizeof(test_data) / sizeof(test_data[0]);

    for(i = 0; i < test_data_len; ++i)
    {
        _nx_secure_x509_asn1_time_to_unix_convert(test_data[i].asn_time, strlen(test_data[i].asn_time), 1, &unix_time);
        printf("ASN.1 time %s is %ld in UNIX time, expected UNIX time of: %ld.\n", test_data[i].asn_time, unix_time, test_data[i].unix_time);
    }


    return 0;
}

