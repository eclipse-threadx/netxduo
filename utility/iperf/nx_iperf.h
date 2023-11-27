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
/** NetX Utility                                                          */
/**                                                                       */
/**   NetX Duo IPerf Test Program                                         */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#ifndef NX_IPERF_H
#define NX_IPERF_H

/* Enable authentication.
#define     NX_IPERF_AUTH_ENABLE
*/

#ifndef NX_IPERF_TCP_RX_PORT
#define NX_IPERF_TCP_RX_PORT      5001
#endif

#ifndef NX_IPERF_UDP_RX_PORT
#define NX_IPERF_UDP_RX_PORT      5001
#endif

#ifndef NX_IPERF_DESTINATION_PORT
#define NX_IPERF_DESTINATION_PORT 5001
#endif

#ifndef NX_IPERF_THREAD_PRIORITY
#define NX_IPERF_THREAD_PRIORITY  1
#endif

#ifndef ULONG64_DEFINED
#define ULONG64_DEFINED
#define ULONG64                   unsigned long long
#endif

#define NX_IPERF_CTRL_SIGN_MASK   0x0F
#define NX_IPERF_CLEAN_UP_MASK    0x01

typedef struct
{
    ULONG   CmdID;
    ULONG   version;
    ULONG   ip;
    ULONG   ipv6[4];
    ULONG   port;
    UCHAR   ctrl_sign;
    UINT    ErrorCode;
    ULONG   WperfPort;
    ULONG64 PacketsTxed;
    ULONG64 PacketsRxed;
    ULONG64 BytesTxed;
    ULONG64 BytesRxed;
    ULONG64 StartTime;
    ULONG64 RunTime;
    ULONG64 TestTime;
    ULONG64 ThroughPut;
    ULONG64 PacketSize;
    ULONG64 Rate;
    UINT    TestStatus;     /* 0 means no test is running.
                               1 means Test Thread is created and is running.
                               2 means a test has finished. */
    ULONG64 idleTime;
} ctrl_info;

/*test list for wperf*/
typedef struct
{
    ULONG cmdID;
    ULONG threadID;
} thread_list;

/* test type enum */
enum testTypeList
{
    UNKNOWN_TEST = 0,
    TCP_RX_START = 1,
    UDP_RX_START = 3,
    TCP_TX_START = 5,
    UDP_TX_START = 7,

    UDP_RX_STOP,
    TCP_RX_STOP,
    UDP_TX_STOP,
    TCP_TX_STOP
};

enum errorCodeList
{
    UDP_RX_STOP_ERROR = 5000,
    UDP_RX_CREATE_ERROR,
    UDP_TX_STOP_ERROR,
    UDP_TX_CREATE_ERROR,
    TCP_RX_STOP_ERROR,
    TCP_RX_CREATE_ERROR,
    TCP_TX_STOP_ERROR,
    TCP_TX_CREATE_ERROR
};

typedef struct
{
    int   udp_id;
    ULONG tv_sec;
    ULONG tv_usec;
} udp_payload;

#define htmlwrite(p, s, l) (nx_packet_data_append(p, s, l, server_ptr -> nx_web_http_server_packet_pool_ptr, NX_WAIT_FOREVER))

#define htmlresponse    "HTTP/1.0 200 \r\nContent-Type: text/html\r\n\r\n"
#define htmltag         "<HTML>"
#define htmlendtag      "</HTML>"
#define titleline       "<HEAD><TITLE>NetX IPerf Demonstration</TITLE></HEAD>\r\n"

#define bodytag         "<body bgcolor=\"#000000\">\r\n"
#define bodyendtag      "</body>\r\n"

#define logo_area                                   \
    "<table border=0 align=center width=90%><tr>"   \
    "<td width=30%><img align=left src=mslogo.jpg>" \
    "</td><td width=33%></td><td width=33%><img align=right src=nxlogo.png></td></tr></table>"

#define hrline          "<HR SIZE=6 WIDTH=\"90%\" NOSHADE COLOR=\"#FFFF00\">"
#define h1line1         " <H1><font face=arial color=\"#FFFFFF\">NetX IP Address: "
#define h1line2         "</font></H1><br>\r\n"
#define tabletag        "<table height=50%>"
#define fonttag         "<font face=arial color=\"#FFFFFF\" size=\"5\">"
#define fontcolortag    "<font face=arial color=\"#FFFF00\" size=\"5\">"
#define fontendtag      "</font>"

#define centertag       "<center WIDTH=\"90%\">\r\n"
#define centerendtag    "</center>"
#define outtermosttable "<table width=80% border=0 bordercolor=#ffff00 rules=cols color=#FFFF00 farme=void><tr><td width=55%>\r\n"
#define maintabletag    "<TABLE BORDER=0 ALIGN=left WIDTH=85% ><TR><TD colspan=4>\r\n"
#define tableendtag     "</TABLE>"
#define trtag           "<TR>"
#define trendtag        "</TR>"
#define tdtag           "<TD>"
#define toptdtag        "<TD align=center style=\"vertical-align:top;\">"
#define tdcolspan4tag   "<TD colspan=\"4\">"
#define tdcolspan3tag   "<TD colspan=\"3\">"
#define tdcolspan2tag   "<TD colspan=\"2\">"
#define tdendtag        "</TD>\r\n"
#define doublebr        "<br><br>\r\n"
#define spanline        "<TR><TD colspan=\"4\"><br><br></TD></TR>"
#define rightspanline   "<TR><TD><br><br></TD></TR>"
#define tdcentertag     "<TD align=center>"


#define formtag         "<form action=\"/test.htm\" method=\"get\">"
#define formendtag      "</form>"

#define UDPTXSTRING     "Start UDP Transmit Test"
#define UDP_Tx          "UDP_Tx"
#define udptxsubmittag1                                                                           \
    "<form action=\"/test.htm\" method=\"get\">\r\n"                                              \
    "<TR><TD><input type=\"submit\" Value=\""UDPTXSTRING "\" style= \"background-color:#FFFF00; " \
    "font-size:19px; font-weight: bold\"></TD></TR>\r\n"                                          \
    "<TR><TD><input type=\"hidden\" name=\"TestType\" value=\""UDP_Tx "\"></input></TD></TR>"     \
    "<TR><TD>"fonttag "Destination IP Address:</font></TD>\r\n"                                   \
    "<TD><input name=\"ip\" value=\""

#define udptxsubmittag2                                   \
    "\"></input></TD></TR>\r\n"                           \
    "<TR><TD>"fonttag "Destination Port:</font></TD>\r\n" \
    "<TD><input name=\"port\" value=\""

#define udptxsubmittag3                                     \
    "\"></input></TD></TR>\r\n"                             \
    "<TR><TD>"fonttag "Test Time(Seconds):</font></TD>\r\n" \
    "<TD><input name=\"test_time\" value=\""

#define udptxsubmittag4                              \
    "\"></input></TD></TR>\r\n"                      \
    "<TR><TD>"fonttag "Packet size:</font></TD>\r\n" \
    "<TD><input name=\"size\" value=\""

#define udptxsubmittag5         \
    "\"></input></TD></TR>\r\n" \
    "</form><TR><TD colspan=\"4\"><br><br></TD></TR>\r\n"

#define UDPRXSTRING "Start UDP Receive Test"
#define UDP_Rx      "UDP_Rx"
#define udprxsubmittag1                                                                                                                             \
    "<form action=\"/test.htm\" method=\"get\">\r\n"                                                                                                \
    "<TR><TD><input type=\"submit\" Value=\""UDPRXSTRING "\" style= \"background-color:#FFFF00; font-size:19px; font-weight: bold\"></TD></TR>\r\n" \
    "<TR><TD><input type=\"hidden\" name=\"TestType\" value=\""UDP_Rx "\"></input></TD></TR>"                                                       \
    "<TR><TD>"fonttag "Test Time(Seconds):</font></TD>\r\n"                                                                                         \
    "<TD><input name=\"test_time\" value=\""

#define udprxsubmittag2                \
    "\"></input></TD></TR></form>\r\n" \
    "<TR><TD colspan=\"4\"><br><br></TD></TR>\r\n"

#define TCP_Tx      "TCP_Tx"
#define tcptxsubmittag1                                                                                                                                      \
    "<form action=\"/test.htm\" method=\"get\">\r\n"                                                                                                         \
    "<TR><TD><input type=\"submit\" Value=\"Start TCP Transmit Test\" style= \"background-color:#FFFF00; font-size:19px; font-weight: bold\"></TD></TR>\r\n" \
    "<TR><TD><input type=\"hidden\" name=\"TestType\" value=\""TCP_Tx "\"></input></TD></TR>"                                                                \
    "<TR><TD>"fonttag "Destination IP Address:</font></TD>\r\n"                                                                                              \
    "<TD><input name=\"ip\" value=\""

#define tcptxsubmittag2                                   \
    "\"></input></TD></TR>\r\n"                           \
    "<TR><TD>"fonttag "Destination Port:</font></TD>\r\n" \
    "<TD><input name=\"port\" value=\""

#define tcptxsubmittag3                                     \
    "\"></input></TD></TR>\r\n"                             \
    "<TR><TD>"fonttag "Test Time(Seconds):</font></TD>\r\n" \
    "<TD><input name=\"test_time\" value=\""

#define tcptxsubmittag4         \
    "\"></input></TD></TR>\r\n" \
    "</form><TR><TD colspan=\"4\"><br><br></TD></TR>\r\n"

#define TCP_Rx      "TCP_Rx"
#define tcprxsubmittag1                                                                                                                                     \
    "<form action=\"/test.htm\" method=\"get\">\r\n"                                                                                                        \
    "<TR><TD><input type=\"submit\" Value=\"Start TCP Receive Test\" style= \"background-color:#FFFF00; font-size:19px; font-weight: bold\"></TD></TR>\r\n" \
    "<TR><TD><input type=\"hidden\" name=\"TestType\" value=\""TCP_Rx "\"></input></TD></TR>"                                                               \
    "<TR><TD>"fonttag "Test Time(Seconds):</font></TD>\r\n"                                                                                                 \
    "<TD><input name=\"test_time\" value=\""

#define tcprxsubmittag2         \
    "\"></input></TD></TR>\r\n" \
    "</form>\r\n<TR><TD colspan=\"4\"><br><br></TD></TR>\r\n"

#define choosetesttag \
    "<TD align=center><font align=center face=arial color=\"#FFFFFF\" size=\"5\">Choose a test from the left.</font></TD>\r\n"

#endif /* NX_IPERF_H  */
