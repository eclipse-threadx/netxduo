#include <stdio.h>

#include "nx_secure_tls_api.h"
#include "nx_crypto.h"
#include "tls_test_utility.h"

extern void    test_control_return(UINT status);

static NX_SECURE_TLS_SESSION   tls_session;

static void  NX_Secure_TLS_newest_supported_version_coverage(void);

extern NX_SECURE_VERSIONS_LIST nx_secure_supported_versions_list[];

/* This table is used to determine the legacy TLS versions currently enabled and supported. */
static const NX_SECURE_TLS_VERSIONS nx_secure_tls_invalid_versions_test[] =
{
    {NX_SECURE_TLS_NUM_VERSIONS + 1, 0},   /* Invalid   */
    {NX_SECURE_TLS_NUM_VERSIONS + 2, 0},   /* Invalid   */
    {NX_SECURE_TLS_NUM_VERSIONS + 3, 0},   /* Invalid   */

};

/* This table is used to determine the legacy TLS versions currently enabled and supported. */
static const NX_SECURE_TLS_VERSIONS nx_secure_tls_inverted_versions_test[] =
{
    {3, 1},
    {2, 1},
    {1, 1},
    {0, 1},
};

static const NX_SECURE_TLS_VERSIONS nx_secure_tls_one_entry_versions_test[] =
{
    {0, 1},
};


/* Test cases all taken from RFC 4231. Relevant section numbers included in comments. */

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_tls_newest_supported_version_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Newest Supported Version Test..................");


    NX_Secure_TLS_newest_supported_version_coverage();

    printf("SUCCESS!\n");
    test_control_return(0);

}

extern void _nx_secure_tls_highest_supported_version_negotiate(NX_SECURE_TLS_SESSION* session_ptr, USHORT* protocol_version, UINT id);

extern NX_SECURE_VERSIONS_LIST nx_secure_supported_versions_list0[];


TEST(NX_Secure_TLS, newest_supported_version_coverage)
{

USHORT protocol_version;

   /* Invalid hash size. */

#ifndef NX_SECURE_TLS_SERVER_DISABLED
   /* Test Line 84 */
   tls_session.nx_secure_tls_socket_type = NX_SECURE_TLS_SESSION_TYPE_SERVER;
   tls_session.nx_secure_tls_protocol_version_override = NX_SECURE_TLS_VERSION_TLS_1_2;
   _nx_secure_tls_newest_supported_version(&tls_session, &protocol_version, 0);
   tls_session.nx_secure_tls_negotiated_highest_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;
   _nx_secure_tls_highest_supported_version_negotiate(&tls_session, &protocol_version, 0);

   tls_session.nx_secure_tls_socket_type = NX_SECURE_TLS_SESSION_TYPE_CLIENT;
   tls_session.nx_secure_tls_protocol_version_override = NX_SECURE_TLS_VERSION_TLS_1_2;
   _nx_secure_tls_newest_supported_version(&tls_session, &protocol_version, 0);
   tls_session.nx_secure_tls_negotiated_highest_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;
   _nx_secure_tls_highest_supported_version_negotiate(&tls_session, &protocol_version, 0);

   tls_session.nx_secure_tls_socket_type = NX_SECURE_TLS_SESSION_TYPE_CLIENT;
   tls_session.nx_secure_tls_protocol_version_override = 0;
   _nx_secure_tls_newest_supported_version(&tls_session, &protocol_version, 0);
   tls_session.nx_secure_tls_negotiated_highest_protocol_version = 0;
   _nx_secure_tls_highest_supported_version_negotiate(&tls_session, &protocol_version, 0);


   tls_session.nx_secure_tls_socket_type = NX_SECURE_TLS_SESSION_TYPE_SERVER;
   tls_session.nx_secure_tls_protocol_version_override = 0;
   _nx_secure_tls_newest_supported_version(&tls_session, &protocol_version, 0);
   tls_session.nx_secure_tls_negotiated_highest_protocol_version = 0;
   _nx_secure_tls_highest_supported_version_negotiate(&tls_session, &protocol_version, 0);

   /* Use our special test version configuration. */
   /* Cover line 95, 98, 106, 107 */
   nx_secure_supported_versions_list[0].nx_secure_versions_list = nx_secure_tls_invalid_versions_test;
   nx_secure_supported_versions_list[0].nx_secure_versions_list_count = 3;
   _nx_secure_tls_newest_supported_version(&tls_session, &protocol_version, 0);
   
   /* Cover line 175, 180 ,185, 187, 190 */
   tls_session.nx_secure_tls_negotiated_highest_protocol_version = 0;
   nx_secure_supported_versions_list[0].nx_secure_versions_list = nx_secure_tls_inverted_versions_test;
   nx_secure_supported_versions_list[0].nx_secure_versions_list_count = 4;
   protocol_version = 5;
   _nx_secure_tls_highest_supported_version_negotiate(&tls_session, &protocol_version, 0);   

   nx_secure_supported_versions_list[0].nx_secure_versions_list = nx_secure_tls_inverted_versions_test;
   nx_secure_supported_versions_list[0].nx_secure_versions_list_count = 4;
   protocol_version = 4;
   tls_session.nx_secure_tls_negotiated_highest_protocol_version = 0;
   _nx_secure_tls_highest_supported_version_negotiate(&tls_session, &protocol_version, 0);

   nx_secure_supported_versions_list[0].nx_secure_versions_list = nx_secure_tls_inverted_versions_test;
   nx_secure_supported_versions_list[0].nx_secure_versions_list_count = 4;
   protocol_version = 3;
   tls_session.nx_secure_tls_negotiated_highest_protocol_version = 0;
   _nx_secure_tls_highest_supported_version_negotiate(&tls_session, &protocol_version, 0);

   nx_secure_supported_versions_list[0].nx_secure_versions_list = nx_secure_tls_inverted_versions_test;
   nx_secure_supported_versions_list[0].nx_secure_versions_list_count = 4;
   protocol_version = 2;
   tls_session.nx_secure_tls_negotiated_highest_protocol_version = 0;
   _nx_secure_tls_highest_supported_version_negotiate(&tls_session, &protocol_version, 0);

   nx_secure_supported_versions_list[0].nx_secure_versions_list = nx_secure_tls_inverted_versions_test;
   nx_secure_supported_versions_list[0].nx_secure_versions_list_count = 4;
   protocol_version = 0;
   tls_session.nx_secure_tls_negotiated_highest_protocol_version = 0;
   _nx_secure_tls_highest_supported_version_negotiate(&tls_session, &protocol_version, 0);


   /* Cover 200 */
   nx_secure_supported_versions_list[0].nx_secure_versions_list = nx_secure_tls_one_entry_versions_test;
   nx_secure_supported_versions_list[0].nx_secure_versions_list_count = 1;
   tls_session.nx_secure_tls_negotiated_highest_protocol_version = 0;
   protocol_version = 3;
   _nx_secure_tls_highest_supported_version_negotiate(&tls_session, &protocol_version, 0);   
   

   

#endif



}

