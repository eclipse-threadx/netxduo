#include    "tx_api.h"
#include    "nx_api.h"

extern void test_control_return(UINT);

#ifdef __PRODUCT_NETXDUO__
#include    "nx_cloud.h"

#define DEMO_STACK_SIZE     4096

static TX_THREAD            test_thread;
static NX_CLOUD             cloud;
static UCHAR                cloud_stack[2048];
static NX_CLOUD_MODULE      cloud_module;
static ULONG                cloud_common_periodic_event = 0;
static ULONG                cloud_module_event_1 = 0;
static ULONG                cloud_module_event_2 = 0;
static ULONG                cloud_module_event_3 = 0;
static ULONG                cloud_module_event_4 = 0;

/* Define module event.  */
#define NX_CLOUD_MODULE_EVENT 0x10000000u

/* Define module own events.  */
#define NX_CLOUD_MODULE_EVENT_1 0x00000001
#define NX_CLOUD_MODULE_EVENT_2 0x00000002
#define NX_CLOUD_MODULE_EVENT_3 0x00000004
#define NX_CLOUD_MODULE_EVENT_4 0x00000008

static void test_entry(ULONG thread_input);
static void cloud_module_event_process(VOID *module_ptr, ULONG common_events, ULONG module_own_events);


#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_cloud_basic_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;


    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create a helper thread for the server. */
    tx_thread_create(&test_thread, "Test thread", test_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();
}

void test_entry(ULONG thread_input)
{

UINT            status;
ULONG           start_time;
ULONG           periodic_count;


    /* Print out test information banner.  */
    printf("NetX Test:   Cloud Basic Test..........................................");

    /* Create cloud.  */
    status = nx_cloud_create(&cloud, "Cloud", cloud_stack, 2048, 3);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Register cloud module.  */
    status = nx_cloud_module_register(&cloud, &cloud_module, "Module 1", (NX_CLOUD_COMMON_PERIODIC_EVENT | NX_CLOUD_MODULE_EVENT), cloud_module_event_process, (void *)(&cloud_module));

    /* Check status.  */
    if ((status) || (cloud.nx_cloud_modules_count != 1))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set the time.  */
    start_time = tx_time_get();

    /* Set module event 1.  */
    status = nx_cloud_module_event_set(&cloud_module, NX_CLOUD_MODULE_EVENT_1);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check events.  */
    if ((cloud_module_event_1 != 1) || (cloud_module_event_2 != 0) || (cloud_module_event_3 != 0) || (cloud_module_event_4 != 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Set module event 1 and 2.  */
    status = nx_cloud_module_event_set(&cloud_module, NX_CLOUD_MODULE_EVENT_1|NX_CLOUD_MODULE_EVENT_2);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check events.  */
    if ((cloud_module_event_1 != 2) || (cloud_module_event_2 != 1) || (cloud_module_event_3 != 0) || (cloud_module_event_4 != 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set module event 1 and 2 and 3.  */
    status = nx_cloud_module_event_set(&cloud_module, NX_CLOUD_MODULE_EVENT_1|NX_CLOUD_MODULE_EVENT_2|NX_CLOUD_MODULE_EVENT_3);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check events.  */
    if ((cloud_module_event_1 != 3) || (cloud_module_event_2 != 2) || (cloud_module_event_3 != 1) || (cloud_module_event_4 != 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set module event 1 and 2 and 3 and 4.  */
    status = nx_cloud_module_event_set(&cloud_module, NX_CLOUD_MODULE_EVENT_1|NX_CLOUD_MODULE_EVENT_2|NX_CLOUD_MODULE_EVENT_3|NX_CLOUD_MODULE_EVENT_4);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check events.  */
    if ((cloud_module_event_1 != 4) || (cloud_module_event_2 != 3) || (cloud_module_event_3 != 2) || (cloud_module_event_4 != 1))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set module 2 and 3 and 4.  */
    status = nx_cloud_module_event_set(&cloud_module, NX_CLOUD_MODULE_EVENT_2|NX_CLOUD_MODULE_EVENT_3|NX_CLOUD_MODULE_EVENT_4);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check events.  */
    if ((cloud_module_event_1 != 4) || (cloud_module_event_2 != 4) || (cloud_module_event_3 != 3) || (cloud_module_event_4 != 2))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Set module 3 and 4.  */
    status = nx_cloud_module_event_set(&cloud_module, NX_CLOUD_MODULE_EVENT_3|NX_CLOUD_MODULE_EVENT_4);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check events.  */
    if ((cloud_module_event_1 != 4) || (cloud_module_event_2 != 4) || (cloud_module_event_3 != 4) || (cloud_module_event_4 != 3))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set 4.  */
    status = nx_cloud_module_event_set(&cloud_module, NX_CLOUD_MODULE_EVENT_4);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check events.  */
    if ((cloud_module_event_1 != 4) || (cloud_module_event_2 != 4) || (cloud_module_event_3 != 4) || (cloud_module_event_4 != 4))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Wait for some periodic events.  */
    tx_thread_sleep(500);

    /* Get periodic count.  */
    periodic_count = (tx_time_get() - start_time) / NX_IP_PERIODIC_RATE;

    /* Check periodic events.  */
    if (cloud_common_periodic_event != periodic_count)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Deregister cloud module.  */
    status = nx_cloud_module_deregister(&cloud, &cloud_module);

    /* Check status.  */
    if ((status) || (cloud.nx_cloud_modules_count != 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete cloud.  */
    status = nx_cloud_delete(&cloud);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}

static void cloud_module_event_process(VOID *module_ptr, ULONG common_events, ULONG module_own_events)
{

    /* Process common_events.  */
    if (common_events & NX_CLOUD_COMMON_PERIODIC_EVENT)
    {
        cloud_common_periodic_event++;
    }

    /* Process module_own_events.  */
    if (module_own_events & NX_CLOUD_MODULE_EVENT_1)
    {
        cloud_module_event_1++;
    }
    if (module_own_events & NX_CLOUD_MODULE_EVENT_2)
    {
        cloud_module_event_2++;
    }
    if (module_own_events & NX_CLOUD_MODULE_EVENT_3)
    {
        cloud_module_event_3++;
    }
    if (module_own_events & NX_CLOUD_MODULE_EVENT_4)
    {
        cloud_module_event_4++;
    }
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_cloud_basic_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Cloud Basic Test..........................................N/A\n"); 

    test_control_return(3);  
}      
#endif

