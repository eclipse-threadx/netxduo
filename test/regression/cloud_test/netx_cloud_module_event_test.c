#include    "tx_api.h"
#include    "nx_api.h"

extern void test_control_return(UINT);

#ifdef __PRODUCT_NETXDUO__
#include    "nx_cloud.h"

#define DEMO_STACK_SIZE     4096

static TX_THREAD            test_thread;
static NX_CLOUD             cloud;
static UCHAR                cloud_stack[2048];

typedef struct NX_CLOUD_APP_STRUCT
{

NX_CLOUD_MODULE             nx_cloud_module;
ULONG                       nx_cloud_module_event_periodic;
ULONG                       nx_cloud_module_event_1;
ULONG                       nx_cloud_module_event_2;
ULONG                       nx_cloud_module_event_3;
ULONG                       nx_cloud_module_event_4;
} NX_CLOUD_APP;

static NX_CLOUD_APP         cloud_module[3];

typedef struct MODULE_EVENT_STRUCT
{
ULONG                       nx_cloud_module_event_1;
ULONG                       nx_cloud_module_event_2;
ULONG                       nx_cloud_module_event_3;
ULONG                       nx_cloud_module_event_4;
} MODULE_EVENT;

static MODULE_EVENT         module_event[3];

/* Define module event.  */
#define NX_CLOUD_MODULE_1_EVENT 0x10000000u
#define NX_CLOUD_MODULE_2_EVENT 0x20000000u
#define NX_CLOUD_MODULE_3_EVENT 0x40000000u

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
void    netx_cloud_module_event_test_application_define(void *first_unused_memory)
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
UINT            i;
UINT            j;
UINT            module_id;
ULONG           module_own_events;
ULONG           start_time;
ULONG           periodic_count;


    /* Print out test information banner.  */
    printf("NetX Test:   Cloud Module Event Test...................................");

    /* Create cloud.  */
    status = nx_cloud_create(&cloud, "Cloud", cloud_stack, 2048, 3);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Register cloud module 1.  */
    status = nx_cloud_module_register(&cloud, &cloud_module[0].nx_cloud_module, "Module 1", (NX_CLOUD_COMMON_PERIODIC_EVENT | NX_CLOUD_MODULE_1_EVENT), cloud_module_event_process, (void *)(&cloud_module[0]));

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Register cloud module 2.  */
    status = nx_cloud_module_register(&cloud, &cloud_module[1].nx_cloud_module, "Module 2", NX_CLOUD_MODULE_1_EVENT, cloud_module_event_process, (void *)(&cloud_module[1]));

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Register cloud module 3.  */
    status = nx_cloud_module_register(&cloud, &cloud_module[2].nx_cloud_module, "Module 3", (NX_CLOUD_COMMON_PERIODIC_EVENT|NX_CLOUD_MODULE_1_EVENT), cloud_module_event_process, (void *)(&cloud_module[2]));

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set the time.  */
    start_time = tx_time_get();

    /* Loop to set event.  */
    for (i = 0; i < 100; i ++)
    {
        module_id = rand() % 3;
        module_own_events = 0;
        if(rand() % 2)
        {
            module_own_events |= NX_CLOUD_MODULE_EVENT_1;
            module_event[module_id].nx_cloud_module_event_1 ++;
        }
        if(rand() % 2)
        {
            module_own_events |= NX_CLOUD_MODULE_EVENT_2;
            module_event[module_id].nx_cloud_module_event_2 ++;
        }
        if(rand() % 2)
        {
            module_own_events |= NX_CLOUD_MODULE_EVENT_3;
            module_event[module_id].nx_cloud_module_event_3 ++;
        }
        if(rand() % 2)
        {
            module_own_events |= NX_CLOUD_MODULE_EVENT_4;
            module_event[module_id].nx_cloud_module_event_4 ++;
        }
        nx_cloud_module_event_set(&cloud_module[module_id].nx_cloud_module, module_own_events);

        /* Check modules event.  */
        for (j = 0; j < 3; j++)
        {
            if ((cloud_module[j].nx_cloud_module_event_1 != module_event[j].nx_cloud_module_event_1) ||
                (cloud_module[j].nx_cloud_module_event_2 != module_event[j].nx_cloud_module_event_2) ||
                (cloud_module[j].nx_cloud_module_event_3 != module_event[j].nx_cloud_module_event_3) ||
                (cloud_module[j].nx_cloud_module_event_4 != module_event[j].nx_cloud_module_event_4))
            {
                printf("ERROR!\n");
                test_control_return(1);
            }
        }

        tx_thread_sleep(10);
    }

    /* Get periodic count.  */
    periodic_count = (tx_time_get() - start_time) / NX_IP_PERIODIC_RATE;

    /* Check periodic events.  */
    if ((cloud_module[0].nx_cloud_module_event_periodic != periodic_count) ||
        (cloud_module[1].nx_cloud_module_event_periodic != 0) ||
        (cloud_module[2].nx_cloud_module_event_periodic != periodic_count))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Test module event clear.  */
    nx_cloud_module_event_clear(&cloud_module[0].nx_cloud_module, NX_CLOUD_MODULE_EVENT_1);
    if (cloud_module[0].nx_cloud_module_event_1 != module_event[0].nx_cloud_module_event_1)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Deregister cloud module 3.  */
    status = nx_cloud_module_deregister(&cloud, &cloud_module[2].nx_cloud_module);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Deregister cloud module 2.  */
    status = nx_cloud_module_deregister(&cloud, &cloud_module[1].nx_cloud_module);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Deregister cloud module 1.  */
    status = nx_cloud_module_deregister(&cloud, &cloud_module[0].nx_cloud_module);

    /* Check status.  */
    if (status)
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

NX_CLOUD_APP *cloud_app = (NX_CLOUD_APP*) module_ptr;

    /* Process common_events.  */
    if (common_events & NX_CLOUD_COMMON_PERIODIC_EVENT)
    {
        cloud_app -> nx_cloud_module_event_periodic++;
    }

    /* Process module_own_events.  */
    if (module_own_events & NX_CLOUD_MODULE_EVENT_1)
    {
        cloud_app -> nx_cloud_module_event_1++;
    }
    if (module_own_events & NX_CLOUD_MODULE_EVENT_2)
    {
        cloud_app -> nx_cloud_module_event_2++;
    }
    if (module_own_events & NX_CLOUD_MODULE_EVENT_3)
    {
        cloud_app -> nx_cloud_module_event_3++;
    }
    if (module_own_events & NX_CLOUD_MODULE_EVENT_4)
    {
        cloud_app -> nx_cloud_module_event_4++;
    }
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_cloud_module_event_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Cloud Module Event Test...................................N/A\n"); 

    test_control_return(3);  
}      
#endif

