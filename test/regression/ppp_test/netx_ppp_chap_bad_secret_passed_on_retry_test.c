/* This is a test of the NetX Duo PPP CHAP authentication protocol. ppp_1
  has a different secret than ppp_0, therefore ppp_1 who is trying
  to authenticate itself with ppp_0, needs to handle the NAK authentication failure.
  In this test, both PPP instances restart() when notified of NAK/CHAP failure. PPP1
  reloads the responder value with the correct secret and should succeed on the next
  CHAP authentication challenge. 
 */

#include "tx_api.h"
#include "nx_api.h"
#include "nx_ppp.h"

extern void         test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

/* Define demo stack size.   */

#define DEMO_STACK_SIZE     2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
static NX_PACKET_POOL          pool_1;

static NX_IP                   ip_0;
static NX_IP                   ip_1;

static NX_PPP                  ppp_0;
static NX_PPP                  ppp_1;

/* Define the counters used in the demo application...  */

static UINT                    ppp_0_retry_counter = 0;  
static UINT                    ppp_1_retry_counter = 0;  
static ULONG                   ppp_0_link_down_counter;  
static ULONG                   ppp_1_link_down_counter; 
static UINT                    get_values_counter = 0;    
static UINT                    nak_counter = 0;    
static UINT                    nak_authentication_failed = NX_FALSE;
static UINT                    error_counter = 0;
static UINT                    thread_1_alive = NX_TRUE;


static CHAR         name_string[] = "username";
static CHAR         name_string_ppp1[] = "username";  /* testing bad chap value; this makes no difference */
static CHAR         rand_value_string[] = "1234567";
static CHAR         system_string[] = "system";
static CHAR         system_string_ppp1[] = "system";  /* testing bad chap value; this makes no difference */
static CHAR         secret_string[] = "secret";
static CHAR         secret_string_ppp1[] = "secret0";  /* testing bad chap value; this mismatch will cause CHAP failure */


static UINT         get_challenge_values(CHAR *rand_value, CHAR *id, CHAR *name);
static UINT         get_responder_values(CHAR *system, CHAR *name, CHAR *secret);
static UINT         get_responder_values_ppp1(CHAR *system, CHAR *name, CHAR *secret);
static UINT         get_verification_values(CHAR *system, CHAR *name, CHAR *secret);  
static void         ppp_0_serial_byte_output(UCHAR byte);   
static void         ppp_1_serial_byte_output(UCHAR byte);
static void         invalid_packet_handler(NX_PACKET *packet_ptr); 
static void         link_down_callback(NX_PPP *ppp_ptr);    
static void         nak_authentication_notify(void);      

/* Define thread prototypes.  */
static void         thread_0_entry(ULONG thread_input);
static void         thread_1_entry(ULONG thread_input);

/* Define what the initial system looks like.  */      

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ppp_chap_bad_secret_passed_on_retry_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create the thread 0.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            5, 5, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;
               
    /* Create the thread 1.  */
    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            5, 5, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool for ppp_0.  */
    status =  nx_packet_pool_create(&pool_0, "Packet Pool 0", NX_PPP_MIN_PACKET_PAYLOAD, pointer, 2048);
    pointer = pointer + 2048;

    /* Check for pool creation error.  */  
    if (status)
        error_counter++;

    /* Create a packet pool for ppp_1.  */
    status =  nx_packet_pool_create(&pool_1, "Packet Pool 1", NX_PPP_MIN_PACKET_PAYLOAD, pointer, 2048);
    pointer = pointer + 2048;

    /* Check for pool creation error.  */   
    if (status)
        error_counter++;

    /* Create the first PPP instance.  */
    status =  nx_ppp_create(&ppp_0, "PPP0", &ip_0, pointer, 2048, 1, &pool_0, invalid_packet_handler, ppp_0_serial_byte_output);
    pointer =  pointer + 2048;

    /* Check for PPP create error.   */   
    if (status)
        error_counter++;
    
    /* Setup CHAP, this PPP instance is effectively the server since it will verify the name and password.  */
    status = nx_ppp_chap_enable(&ppp_0, get_challenge_values, get_responder_values, get_verification_values);

    status += nx_ppp_link_down_notify(&ppp_0, link_down_callback);

    status += nx_ppp_nak_authentication_notify(&ppp_0, nak_authentication_notify);

    /* Define IP address. This PPP instance is effectively the server since it has both IP addresses. */
    status += nx_ppp_ip_address_assign(&ppp_0, IP_ADDRESS(1, 2, 3, 4), IP_ADDRESS(1, 2, 3, 5));

    /* Check for PPP CHAP enable error.  */
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(0, 0, 0, 0), 0xFFFFF000UL, &pool_0, nx_ppp_driver,
                          pointer, 2048, 1);
    pointer =  pointer + 2048;
                         
    /* Check status.  */    
    if (status)
        error_counter++;

    /* Create the next PPP instance.  */
    status =  nx_ppp_create(&ppp_1, "PPP1", &ip_1, pointer, 2048, 1, &pool_1, invalid_packet_handler, ppp_1_serial_byte_output);
    pointer =  pointer + 2048;

    /* Check for PPP create error.   */   
    if (status)
        error_counter++;


    /* Setup CHAP, this PPP instance will only respond to CHAP challenges.  */
    status = nx_ppp_chap_enable(&ppp_1, NX_NULL, get_responder_values_ppp1, NX_NULL);

    status += nx_ppp_link_down_notify(&ppp_1, link_down_callback);

    status += nx_ppp_nak_authentication_notify(&ppp_1, nak_authentication_notify);

    /* Define IP address. This PPP instance is effectively the client since it doesn't have any IP addresses. */
    status += nx_ppp_ip_address_assign(&ppp_1, IP_ADDRESS(0, 0, 0, 0), IP_ADDRESS(0, 0, 0, 0));

    /* Check for PPP IP address assign error.   */
    if (status)
        error_counter++;

    /* Create another IP instance.  */
    status = nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(0, 0, 0, 0), 0xFFFFF000UL, &pool_0, nx_ppp_driver,
                           pointer, 2048, 1);
    pointer = pointer + 2048;
            
    /* Check status.  */    
    if (status)
        error_counter++;

    /* Enable UDP traffic.  */
    nx_udp_enable(&ip_0);
    nx_udp_enable(&ip_1);

}

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
ULONG       ip_status;

    /* Print out test information banner.  */
    printf("NetX Test:   PPP Chap Bad Secret Passed on Retry Test..................");
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Wait for the link to come up.  */
    do
    {
    
        status =  nx_ip_status_check(&ip_0, NX_IP_LINK_ENABLED, &ip_status, 20 * NX_IP_PERIODIC_RATE);
    }while(status != NX_SUCCESS);   
         
       
    /* Check status.  */
    if ((status) ||  (!ppp_0.nx_ppp_authenticated) || (!ppp_1.nx_ppp_authenticated) ||
        (get_values_counter != 2)  || (nak_authentication_failed) ||
        (nak_counter != 1)||  (ppp_0_link_down_counter != 1) || 
        (ppp_0_retry_counter != 1) || (ppp_1_link_down_counter != 1) || 
        (ppp_1_retry_counter != 1) || nak_authentication_failed || (!ppp_1.nx_ppp_authenticated) ||
        (error_counter))
    {       

        printf("ERROR!\n");
        test_control_return(1);
    }

    while(thread_1_alive)
        tx_thread_sleep(50);

    /* Delete PPP 0, CHAP complete, we don't need to finish IPCP handshake..  */
    nx_ppp_delete(&ppp_0); 

    /* Output successful.  */
    printf("SUCCESS!\n");
    test_control_return(0);
}
    

static void    thread_1_entry(ULONG thread_input)
{

UINT        status;
ULONG       ip_status;
        
    /* Wait for the link to come up.  */
    do
    {
    
        status =  nx_ip_status_check(&ip_1, NX_IP_LINK_ENABLED, &ip_status, 20 * NX_IP_PERIODIC_RATE);
    }while(status != NX_SUCCESS);   
         

    /* Delete PPP 1. CHAP complete, we don't need to finish IPCP handshake..  */
    nx_ppp_delete(&ppp_1);

    thread_1_alive = NX_FALSE;

    return;

}

/* Define the CHAP enable routines.  */
static UINT  get_challenge_values(CHAR *rand_value, CHAR *id, CHAR *name)
{

UINT    i;

    for (i = 0; i< (NX_PPP_NAME_SIZE-1); i++)
    {
        name[i] = name_string[i];
    }
    name[i] =  0;

    *id =  '1';  /* One byte  */
    
    for (i = 0; i< (NX_PPP_VALUE_SIZE-1); i++)
    {
        rand_value[i] =  rand_value_string[i];
    }
    rand_value[i] =  0;

    return(NX_SUCCESS);  
}

static UINT  get_responder_values(CHAR *system, CHAR *name, CHAR *secret)
{

UINT    i;

    for (i = 0; i< (NX_PPP_NAME_SIZE-1); i++)
    {
        name[i] = name_string[i];
    }
    name[i] =  0;

    for (i = 0; i< (NX_PPP_NAME_SIZE-1); i++)
    {
        system[i] =  system_string[i];
    }
    system[i] =  0;

    for (i = 0; i< (NX_PPP_NAME_SIZE-1); i++)
    {
        secret[i] =  secret_string[i];
    }
    secret[i] =  0;

    return(NX_SUCCESS);  
}

/* Get PPP_1's idea of username/secret/system */
static UINT  get_responder_values_ppp1(CHAR *system, CHAR *name, CHAR *secret)
{

UINT    i;

    for (i = 0; i< (NX_PPP_NAME_SIZE-1); i++)
    {
        name[i] = name_string_ppp1[i];   
    }
    name[i] =  0;

    for (i = 0; i< (NX_PPP_NAME_SIZE-1); i++)
    {
        system[i] =  system_string_ppp1[i];
    }
    system[i] =  0;

    for (i = 0; i< (NX_PPP_NAME_SIZE-1); i++)
    {

        /* Check if we are being asked for the secret for the first time. */
        if (get_values_counter == 0)
        {

            /* Yes, start out with the 'bad' secret (CHAP should fail). */
            secret[i] =  secret_string_ppp1[i];
        }
        else
        {
        
            /* We are not. Try the good secret now. */
            secret[i] =  secret_string[i];
        }

    }

    secret[i] =  0;

    get_values_counter++;

    return(NX_SUCCESS);  
}

static UINT  get_verification_values(CHAR *system, CHAR *name, CHAR *secret)
{

UINT    i;

    for (i = 0; i< (NX_PPP_NAME_SIZE-1); i++)
    {
        name[i] = name_string[i];
    }
    name[i] =  0;

    for (i = 0; i< (NX_PPP_NAME_SIZE-1); i++)
    {
        system[i] =  system_string[i];
    }
    system[i] =  0;

    for (i = 0; i< (NX_PPP_NAME_SIZE-1); i++)
    {
        secret[i] =  secret_string[i];
    }
    secret[i] =  0;

    return(NX_SUCCESS);  
}
    
/* Define serial output routines.  Normally these routines would
   map to physical UART routines and the nx_ppp_byte_receive call
   would be made from a UART receive interrupt.  */

static void    ppp_0_serial_byte_output(UCHAR byte)
{

    /* Just feed the PPP 1 input routine.  */
    nx_ppp_byte_receive(&ppp_1, byte);
}

static void    ppp_1_serial_byte_output(UCHAR byte)
{

    /* Just feed the PPP 0 input routine.  */
    nx_ppp_byte_receive(&ppp_0, byte);
}


static void invalid_packet_handler(NX_PACKET *packet_ptr)
{
    /* Print out the non-PPP byte. In Windows, the string "CLIENT" will
       be sent before Windows PPP starts. Once CLIENT is received, we need
       to send "CLIENTSERVER" to establish communication. It's also possible
       to receive modem commands here that might need some response to 
       continue.  */
    nx_packet_release(packet_ptr);
}


static void link_down_callback(NX_PPP *ppp_ptr)
{

    /* Just increment the link down counter.  */
    if (ppp_ptr == &ppp_0)
    {
    
        ppp_0_link_down_counter++;
        ppp_0_retry_counter++;

        /* We'd probably try three times.  */
        if (ppp_0_retry_counter >= 2) 
        {
            /* Error */
            ppp_0_retry_counter = 0;
            nak_authentication_failed = NX_TRUE;
        }
        else
        {
        
            /* Restart the PPP instance.  */    
            nx_ppp_restart(ppp_ptr);
        }
    }
    else
    {

        ppp_1_link_down_counter++;
        ppp_1_retry_counter++;
        if (ppp_1_retry_counter >= 2)
        {
            /* Error. */
            ppp_1_retry_counter = 0;
            nak_authentication_failed = NX_TRUE;
        }
        else
        {
        
            /* Restart the PPP instance.  */    
            nx_ppp_restart(ppp_ptr);
        }
    }   
}   

static void nak_authentication_notify(void)
{

    nak_counter++;       
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ppp_chap_bad_secret_passed_on_retry_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   PPP Chap Bad Secret Passed on Retry Test..................N/A\n"); 

    test_control_return(3);  
}      
#endif

