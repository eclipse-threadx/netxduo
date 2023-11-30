#include    "tx_api.h"
#include    "nx_api.h"

extern void test_control_return(UINT);

#ifdef __PRODUCT_NETXDUO__
#include    "nx_cloud.h"

#define DEMO_STACK_SIZE     4096

static TX_THREAD            test_thread;
static NX_CLOUD             cloud;
static UCHAR                cloud_stack[2048];
static NX_CLOUD_MODULE      cloud_module_1;
static NX_CLOUD_MODULE      cloud_module_2;
static NX_CLOUD_MODULE      cloud_module_3;
static NX_CLOUD_MODULE      cloud_module_4;
static NX_CLOUD_MODULE      cloud_module_5;

/* Define module event.  */
#define NX_CLOUD_MODULE_1_EVENT 0x10000000u
#define NX_CLOUD_MODULE_2_EVENT 0x20000000u
#define NX_CLOUD_MODULE_3_EVENT 0x40000000u
#define NX_CLOUD_MODULE_4_EVENT 0x80000000u
#define NX_CLOUD_MODULE_5_EVENT 0x01000000u

static void test_entry(ULONG thread_input);
static void cloud_module_event_process(VOID *module_ptr, ULONG common_events, ULONG module_own_events);


#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_cloud_module_register_deregister_test_application_define(void *first_unused_memory)
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


    /* Print out test information banner.  */
    printf("NetX Test:   Cloud Module Register And Deregister Test.................");

    /* Create cloud.  */
    status = nx_cloud_create(&cloud, "Cloud", cloud_stack, 2048, 3);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Register cloud module 1.  */
    status = nx_cloud_module_register(&cloud, &cloud_module_1, "Module 1", NX_CLOUD_MODULE_1_EVENT, cloud_module_event_process, (void *)(&cloud_module_1));

    /* Check status.  */
    if ((status) || (cloud.nx_cloud_modules_count != 1))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Register cloud module 1 again.  */
    status = nx_cloud_module_register(&cloud, &cloud_module_1, "Module 1", NX_CLOUD_MODULE_1_EVENT, cloud_module_event_process, (void *)(&cloud_module_1));

    /* Check status.  */
    if ((status != NX_CLOUD_MODULE_ALREADY_REGISTERED) || (cloud.nx_cloud_modules_count != 1))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Register cloud module 2.  */
    status = nx_cloud_module_register(&cloud, &cloud_module_2, "Module 2", NX_CLOUD_MODULE_2_EVENT, cloud_module_event_process, (void *)(&cloud_module_2));

    /* Check status.  */
    if ((status) || (cloud.nx_cloud_modules_count != 2))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Register cloud module 3.  */
    status = nx_cloud_module_register(&cloud, &cloud_module_3, "Module 3", NX_CLOUD_MODULE_3_EVENT, cloud_module_event_process, (void *)(&cloud_module_4));

    /* Check status.  */
    if ((status) || (cloud.nx_cloud_modules_count != 3))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Register cloud module 4.  */
    status = nx_cloud_module_register(&cloud, &cloud_module_4, "Module 4", NX_CLOUD_MODULE_4_EVENT, cloud_module_event_process, (void *)(&cloud_module_4));

    /* Check status.  */
    if ((status) || (cloud.nx_cloud_modules_count != 4))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Deregister cloud module 5.  */
    status = nx_cloud_module_deregister(&cloud, &cloud_module_5);

    /* Check status.  */
    if ((status != NX_CLOUD_MODULE_NOT_REGISTERED) || (cloud.nx_cloud_modules_count != 4))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Deregister cloud module 2.  */
    status = nx_cloud_module_deregister(&cloud, &cloud_module_2);

    /* Check status.  */
    if ((status) || (cloud.nx_cloud_modules_count != 3))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Register cloud module 2 again.  */
    status = nx_cloud_module_register(&cloud, &cloud_module_2, "Module 2", NX_CLOUD_MODULE_1_EVENT, cloud_module_event_process, (void *)(&cloud_module_2));

    /* Check status.  */
    if ((status) || (cloud.nx_cloud_modules_count != 4))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Deregister cloud module 1.  */
    status = nx_cloud_module_deregister(&cloud, &cloud_module_1);

    /* Check status.  */
    if ((status) || (cloud.nx_cloud_modules_count != 3))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Deregister cloud module 4.  */
    status = nx_cloud_module_deregister(&cloud, &cloud_module_4);

    /* Check status.  */
    if ((status) || (cloud.nx_cloud_modules_count != 2))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Deregister cloud module 3.  */
    status = nx_cloud_module_deregister(&cloud, &cloud_module_3);

    /* Check status.  */
    if ((status) || (cloud.nx_cloud_modules_count != 1))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Deregister cloud module 2.  */
    status = nx_cloud_module_deregister(&cloud, &cloud_module_2);

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
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_cloud_module_register_deregister_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Cloud Module Register And Deregister Test.................N/A\n"); 

    test_control_return(3);  
}      
#endif

