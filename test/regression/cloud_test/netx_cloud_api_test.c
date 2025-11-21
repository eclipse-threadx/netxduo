#include    "tx_api.h"
#include    "nx_api.h"

extern void test_control_return(UINT);

#if !defined(NX_DISABLE_ERROR_CHECKING) && defined(__PRODUCT_NETXDUO__)
#include    "nx_cloud.h"

#define DEMO_STACK_SIZE     4096

static TX_THREAD            test_thread;
static NX_CLOUD             cloud;
static UCHAR                cloud_stack[2048];
static NX_CLOUD_MODULE      cloud_module;

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
void    netx_cloud_api_test_application_define(void *first_unused_memory)
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
    printf("NetX Test:   Cloud API Test............................................");

    /* nx_cloud_create.  */
    status = nx_cloud_create(NX_NULL, "Cloud", cloud_stack, 2048, 3);

    /* Check status.  */
    if (status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    status = nx_cloud_create(&cloud, "Cloud", NX_NULL, 2048, 3);

    /* Check status.  */
    if (status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    status = nx_cloud_create(&cloud, "Cloud", cloud_stack, 0, 3);

    /* Check status.  */
    if (status != NX_SIZE_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    status = nx_cloud_create(&cloud, "Cloud", cloud_stack, 2048, TX_MAX_PRIORITIES);

    /* Check status.  */
    if (status != NX_OPTION_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_cloud_create(&cloud, "Cloud", cloud_stack, 2048, 3);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


    /* nx_cloud_module_register.  */
    status = nx_cloud_module_register(NX_NULL, &cloud_module, "Module 1", (NX_CLOUD_COMMON_PERIODIC_EVENT | NX_CLOUD_MODULE_EVENT), cloud_module_event_process, (void *)(&cloud_module));

    /* Check status.  */
    if (status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    status = nx_cloud_module_register(&cloud, NX_NULL, "Module 1", (NX_CLOUD_COMMON_PERIODIC_EVENT | NX_CLOUD_MODULE_EVENT), cloud_module_event_process, (void *)(&cloud_module));

    /* Check status.  */
    if (status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    status = nx_cloud_module_register(&cloud, &cloud_module, "Module 1", 0, cloud_module_event_process, (void *)(&cloud_module));

    /* Check status.  */
    if (status != NX_CLOUD_MODULE_EVENT_INVALID)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    status = nx_cloud_module_register(&cloud, &cloud_module, "Module 1", (NX_CLOUD_COMMON_PERIODIC_EVENT | NX_CLOUD_MODULE_EVENT), NX_NULL, (void *)(&cloud_module));

    /* Check status.  */
    if (status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    status = nx_cloud_module_register(&cloud, &cloud_module, "Module 1", (NX_CLOUD_COMMON_PERIODIC_EVENT | NX_CLOUD_MODULE_EVENT), cloud_module_event_process, (void *)(&cloud_module));

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* nx_cloud_module_event_set.  */
    status = nx_cloud_module_event_set(NX_NULL, NX_CLOUD_MODULE_EVENT_1);

    /* Check status.  */
    if (status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    status = nx_cloud_module_event_set(&cloud_module, 0);

    /* Check status.  */
    if (status != NX_CLOUD_MODULE_EVENT_INVALID)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_cloud_module_event_set(&cloud_module, NX_CLOUD_MODULE_EVENT_1);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

 
    /* nx_cloud_module_event_clear.  */
    status = nx_cloud_module_event_clear(NX_NULL, NX_CLOUD_MODULE_EVENT_1);

    /* Check status.  */
    if (status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    status = nx_cloud_module_event_clear(&cloud_module, 0);

    /* Check status.  */
    if (status != NX_CLOUD_MODULE_EVENT_INVALID)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_cloud_module_event_clear(&cloud_module, NX_CLOUD_MODULE_EVENT_1);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


    /* nx_cloud_module_deregister.  */
    status = nx_cloud_module_deregister(NX_NULL, &cloud_module);

    /* Check status.  */
    if (status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    status = nx_cloud_module_deregister(&cloud, NX_NULL);

    /* Check status.  */
    if (status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_cloud_module_deregister(&cloud, &cloud_module);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


    /* nx_cloud_delete.  */
    status = nx_cloud_delete(NX_NULL);

    /* Check status.  */
    if (status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

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
void    netx_cloud_api_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Cloud API Test............................................N/A\n"); 

    test_control_return(3);  
}      
#endif

