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
/** NetX Component                                                        */
/**                                                                       */
/**   TSN shaper                                                          */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

/* Include necessary system files.  */
#include "nx_shaper.h"
#include "nx_link.h"

#ifdef NX_ENABLE_VLAN
/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_shaper_create                                    PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function creates shaper in shaper container, and connects the  */
/*    shaper container with interface instance.                           */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    interface_ptr                         Pointer to interface instance */
/*    shaper_container                      Pinter to Shaper container    */
/*    shaper                                Pinter to Shaper              */
/*    shaper_type                           Shaper type                   */
/*    shaper_driver                         Driver entry of shaper        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_shaper_create(NX_INTERFACE *interface_ptr,
                      NX_SHAPER_CONTAINER *shaper_container,
                      NX_SHAPER *shaper,
                      UCHAR shaper_type,
                      NX_SHAPER_DRIVER shaper_driver)
{
UINT                       i;
UINT                       status;
NX_SHAPER_DRIVER_PARAMETER driver_request;

    if ((interface_ptr == NX_NULL) ||
        (shaper_container == NX_NULL) ||
        (shaper == NX_NULL) ||
        (shaper_type >= NX_SHAPER_TYPE_MAX) ||
        (shaper_driver == NX_NULL))
    {
        return(NX_INVALID_PARAMETERS);
    }

    if (shaper_container -> shaper_number >= NX_SHAPER_NUMBERS)
    {
        return(NX_NO_MORE_ENTRIES);
    }

    for (i = 0; i < NX_SHAPER_NUMBERS; i++)
    {
        if (shaper_container -> shaper[i] == NX_NULL)
        {
            shaper_container -> shaper[i] = shaper;
            shaper_container -> shaper[i] -> shaper_type = shaper_type;
            shaper_container -> shaper[i] -> shaper_driver = shaper_driver;

            break;
        }
        shaper_container -> shaper_number++;
    }

    if (i >= NX_SHAPER_NUMBERS)
    {
        return(NX_NO_MORE_ENTRIES);
    }

    /* Bind the shaper_container with interface. */
    if (interface_ptr -> shaper_container == NX_NULL)
    {
        interface_ptr -> shaper_container = shaper_container;
    }

    /* Init process */
    driver_request.nx_shaper_driver_command = NX_SHAPER_COMMAND_INIT;
    driver_request.shaper_type = interface_ptr -> shaper_container -> shaper[i] -> shaper_type;
    driver_request.nx_ip_driver_interface = interface_ptr;
    driver_request.shaper_parameter = NX_NULL;

    status = interface_ptr -> shaper_container -> shaper[i] -> shaper_driver(&driver_request);
    if (status != NX_SUCCESS)
    {
        return(status);
    }

    /* Config process */
    driver_request.nx_shaper_driver_command = NX_SHAPER_COMMAND_CONFIG;
    driver_request.shaper_type = 0; /* not used in driver */
    driver_request.nx_ip_driver_interface = interface_ptr;
    driver_request.shaper_parameter = NX_NULL;

    status = interface_ptr -> shaper_container -> shaper[i] -> shaper_driver(&driver_request);

    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_shaper_delete                                    PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function deletes a shaper from interface instance, unlink the  */
/*    shaper container with IP interface when there is no shaper exists.  */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    interface_ptr                         Pointer to interface instance */
/*    shaper                                Pinter to Shaper              */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_shaper_delete(NX_INTERFACE *interface_ptr, NX_SHAPER *shaper)
{
UINT i;

    if (interface_ptr == NX_NULL)
    {
        return(NX_INVALID_PARAMETERS);
    }

    if (interface_ptr -> shaper_container == NX_NULL)
    {

        /* None shaper existed. */
        return(NX_SUCCESS);
    }

    for (i = 0; i < NX_SHAPER_NUMBERS; i++)
    {
        if (interface_ptr -> shaper_container -> shaper[i] == shaper)
        {
            interface_ptr -> shaper_container -> shaper[i] = NX_NULL;
            interface_ptr -> shaper_container -> shaper_number--;
            break;
        }
    }

    if (i >= NX_SHAPER_NUMBERS)
    {
        return(NX_ENTRY_NOT_FOUND);
    }

    if (interface_ptr -> shaper_container -> shaper_number == 0)
    {

        /* No shaper existed, delete the shaper_container. */
        interface_ptr -> shaper_container = NX_NULL;
    }

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_shaper_config                                    PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function configures the hardware parameters of shaper by       */
/*    network driver.                                                     */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    interface_ptr                         Pointer to interface instance */
/*    port_rate                             Port rate                     */
/*    shaper_capability                     Capability of shaper          */
/*    hw_queue_number                       Number of HW queues           */
/*    hw_queue                              Pointer to HW queue list      */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_shaper_hw_queue_set                Set HW queue info             */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Network driver                                                      */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_shaper_config(NX_INTERFACE *interface_ptr,
                      UINT port_rate,
                      UCHAR shaper_capability,
                      UCHAR hw_queue_number,
                      NX_SHAPER_HW_QUEUE *hw_queue)
{
INT  i;
UINT status;

    interface_ptr -> shaper_container -> port_rate = port_rate;
    interface_ptr -> shaper_container -> shaper_capability |= shaper_capability;
    interface_ptr -> shaper_container -> hw_queue_number = hw_queue_number;
    for (i = 0; i < hw_queue_number; i++)
    {
        status = nx_shaper_hw_queue_set(interface_ptr, hw_queue[i].hw_queue_id, hw_queue[i].priority, hw_queue[i].type);
        if (status != NX_SUCCESS)
        {
            return(status);
        }
    }

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_shaper_hw_queue_set                              PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function configures the hardware queue of shaper.              */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    interface_ptr                         Pointer to interface instance */
/*    hw_queue_id                           HW queue id                   */
/*    priority                              HW queue priority             */
/*    type                                  HW queue type                 */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_shaper_config                      Config the shaper HW params   */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_shaper_hw_queue_set(NX_INTERFACE *interface_ptr, UCHAR hw_queue_id, UCHAR priority, UCHAR type)
{
UCHAR i, insert_id;

    if (interface_ptr -> shaper_container == NX_NULL)
    {
        return(NX_NOT_SUPPORTED);
    }

    for (i = 0; i < interface_ptr -> shaper_container -> hw_queue_number; i++)
    {

        /* If the hw queue is already configured, we should avoid the double config. */
        if ((interface_ptr -> shaper_container -> hw_queue[i].hw_queue_id == hw_queue_id) &&
            (interface_ptr -> shaper_container -> hw_queue[i].type != NX_SHAPER_HW_QUEUE_NONE))
        {
            if (interface_ptr -> shaper_container -> hw_queue[i].priority != priority)
            {
                return(NX_INVALID_PARAMETERS);
            }
            else
            {
                interface_ptr -> shaper_container -> hw_queue[i].type |= type;
                return(NX_SUCCESS);
            }
        }
    }

    /* The queue is not configured, insert the queue to the queue list and sort. */
    for (i = 0; i < interface_ptr -> shaper_container -> hw_queue_number; i++)
    {
        if (interface_ptr -> shaper_container -> hw_queue[i].type == NX_SHAPER_HW_QUEUE_NONE)
        {
            /* find the first unused place to insert */
            break;
        }

        if (interface_ptr -> shaper_container -> hw_queue[i].priority > priority)
        {
            /* find the first place to insert */
            break;
        }
    }

    if (i == interface_ptr -> shaper_container -> hw_queue_number)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    insert_id = i;
    for (i = (UCHAR)(interface_ptr -> shaper_container -> hw_queue_number - 1); i > insert_id; i--)
    {
        memcpy(&interface_ptr -> shaper_container -> hw_queue[i], &interface_ptr -> shaper_container -> hw_queue[i - 1],
               sizeof(struct NX_SHAPER_HW_QUEUE_STRUCT)); /* use case of memcpy is verified. */
    }

    interface_ptr -> shaper_container -> hw_queue[insert_id].hw_queue_id = hw_queue_id;
    interface_ptr -> shaper_container -> hw_queue[insert_id].priority = priority;
    interface_ptr -> shaper_container -> hw_queue[insert_id].type = type;

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_shaper_default_mapping_get                       PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function gets the default pcp to HW queue mapping config.      */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    interface_ptr                         Pointer to interface instance */
/*    pcp_list                              Pointer to PCP list           */
/*    queue_id_list                         Pointer to Queue id list      */
/*    list_size                             Size of PCP list              */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_shaper_hw_cbs_queue_number_get     Get number of CBS HW queue    */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_shaper_default_mapping_get(NX_INTERFACE *interface_ptr, UCHAR *pcp_list, UCHAR *queue_id_list, UCHAR list_size)
{
UCHAR index = (UCHAR)(interface_ptr -> shaper_container -> hw_queue_number - 1);
UCHAR item_number = 0;
UCHAR hw_cbs_queue_number;

    if (interface_ptr -> shaper_container == NX_NULL)
    {
        return(NX_NOT_SUPPORTED);
    }

    if (list_size != NX_SHAPER_MAPPING_LIST_SIZE)
    {
        return(NX_INVALID_PARAMETERS);
    }

    memset(pcp_list, 0, list_size);
    memset(queue_id_list, 0, list_size);

    if (nx_shaper_hw_cbs_queue_number_get(interface_ptr, &hw_cbs_queue_number) != NX_SUCCESS)
    {
        return(NX_NOT_SUPPORTED);
    }

    if (hw_cbs_queue_number == 0)
    {
        /* no default config for this case */
        return(NX_NOT_SUPPORTED);
    }

    if ((hw_cbs_queue_number == 1) ||
        ((hw_cbs_queue_number == 2) &&
         (interface_ptr -> shaper_container -> hw_queue_number == 2)))
    {
        pcp_list[item_number] = NX_SHAPER_CLASS_B_PCP;
        queue_id_list[item_number++] = index--;
        switch (interface_ptr -> shaper_container -> hw_queue_number)
        {
        case 2:
            /* nothing need to do */
            break;

        case 3:
            pcp_list[item_number] = 7;
            queue_id_list[item_number++] = index;
            pcp_list[item_number] = 6;
            queue_id_list[item_number++] = index;
            pcp_list[item_number] = 5;
            queue_id_list[item_number++] = index;
            pcp_list[item_number] = 4;
            queue_id_list[item_number++] = index;
            break;

        case 4:
            pcp_list[item_number] = 7;
            queue_id_list[item_number++] = index;
            pcp_list[item_number] = 6;
            queue_id_list[item_number++] = index--;
            pcp_list[item_number] = 5;
            queue_id_list[item_number++] = index;
            pcp_list[item_number] = 4;
            queue_id_list[item_number++] = index;
            break;

        case 5:
            pcp_list[item_number] = 7;
            queue_id_list[item_number++] = index;
            pcp_list[item_number] = 6;
            queue_id_list[item_number++] = index--;
            pcp_list[item_number] = 5;
            queue_id_list[item_number++] = index;
            pcp_list[item_number] = 4;
            queue_id_list[item_number++] = index--;
            pcp_list[item_number] = 3;
            queue_id_list[item_number++] = index;
            break;

        case 6:
            pcp_list[item_number] = 7;
            queue_id_list[item_number++] = index--;
            pcp_list[item_number] = 6;
            queue_id_list[item_number++] = index--;
            pcp_list[item_number] = 5;
            queue_id_list[item_number++] = index;
            pcp_list[item_number] = 4;
            queue_id_list[item_number++] = index--;
            pcp_list[item_number] = 3;
            queue_id_list[item_number++] = index;
            break;
        case 7:
            pcp_list[item_number] = 7;
            queue_id_list[item_number++] = index--;
            pcp_list[item_number] = 6;
            queue_id_list[item_number++] = index--;
            pcp_list[item_number] = 5;
            queue_id_list[item_number++] = index;
            pcp_list[item_number] = 4;
            queue_id_list[item_number++] = index--;
            pcp_list[item_number] = 3;
            queue_id_list[item_number++] = index--;
            pcp_list[item_number] = 0;
            queue_id_list[item_number++] = index;
            break;
        case 8:
        default:
            pcp_list[item_number] = 7;
            queue_id_list[item_number++] = index--;
            pcp_list[item_number] = 6;
            queue_id_list[item_number++] = index--;
            pcp_list[item_number] = 5;
            queue_id_list[item_number++] = index--;
            pcp_list[item_number] = 4;
            queue_id_list[item_number++] = index--;
            pcp_list[item_number] = 3;
            queue_id_list[item_number++] = index--;
            pcp_list[item_number] = 0;
            queue_id_list[item_number++] = index;
            break;
        }
    }
    else
    {
        pcp_list[item_number] = NX_SHAPER_CLASS_A_PCP;
        queue_id_list[item_number++] = index--;
        pcp_list[item_number] = NX_SHAPER_CLASS_B_PCP;
        queue_id_list[item_number++] = index--;

        switch (interface_ptr -> shaper_container -> hw_queue_number)
        {
        case 3:
            /* nothing need to do */
            break;
        case 4:
            pcp_list[item_number] = 7;
            queue_id_list[item_number++] = index;
            pcp_list[item_number] = 6;
            queue_id_list[item_number++] = index;
            pcp_list[item_number] = 5;
            queue_id_list[item_number++] = index;
            pcp_list[item_number] = 4;
            queue_id_list[item_number++] = index;
            break;
        case 5:
            pcp_list[item_number] = 7;
            queue_id_list[item_number++] = index;
            pcp_list[item_number] = 6;
            queue_id_list[item_number++] = index--;
            pcp_list[item_number] = 5;
            queue_id_list[item_number++] = index;
            pcp_list[item_number] = 4;
            queue_id_list[item_number++] = index;
            break;
        case 6:
            pcp_list[item_number] = 7;
            queue_id_list[item_number++] = index--;
            pcp_list[item_number] = 6;
            queue_id_list[item_number++] = index--;
            pcp_list[item_number] = 5;
            queue_id_list[item_number++] = index;
            pcp_list[item_number] = 4;
            queue_id_list[item_number++] = index;
            break;
        case 7:
            pcp_list[item_number] = 7;
            queue_id_list[item_number++] = index--;
            pcp_list[item_number] = 6;
            queue_id_list[item_number++] = index--;
            pcp_list[item_number] = 5;
            queue_id_list[item_number++] = index--;
            pcp_list[item_number] = 4;
            queue_id_list[item_number++] = index;
            break;
        case 8:
        default:
            pcp_list[item_number] = 7;
            queue_id_list[item_number++] = index--;
            pcp_list[item_number] = 6;
            queue_id_list[item_number++] = index--;
            pcp_list[item_number] = 5;
            queue_id_list[item_number++] = index--;
            pcp_list[item_number] = 4;
            queue_id_list[item_number++] = index--;
            pcp_list[item_number] = 0;
            queue_id_list[item_number++] = index;
            break;
        }
    }

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_shaper_current_mapping_get                       PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function gets the current pcp to HW queue mapping config.      */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    interface_ptr                         Pointer to interface instance */
/*    pcp_list                              Pointer to PCP list           */
/*    queue_id_list                         Pointer to Queue id list      */
/*    list_size                             Size of PCP list              */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_shaper_current_mapping_get(NX_INTERFACE *interface_ptr, UCHAR *pcp_list, UCHAR *queue_id_list, UCHAR list_size)
{
UCHAR i, j;

    if (interface_ptr -> shaper_container == NX_NULL)
    {
        return(NX_NOT_SUPPORTED);
    }

    if (list_size != NX_SHAPER_MAPPING_LIST_SIZE)
    {
        return(NX_INVALID_PARAMETERS);
    }

    for (i = 0; i < list_size; i++)
    {
        pcp_list[i] = i;
        for (j = 0; j < list_size; j++)
        {
            if (interface_ptr -> shaper_container -> hw_queue[j].hw_queue_id ==
                interface_ptr -> shaper_container -> queue_map[pcp_list[i]])
            {
                queue_id_list[i] = j;
                break;
            }
        }
        if (j == list_size)
        {
            return(NX_NOT_SUCCESSFUL);
        }
    }
    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_shaper_hw_queue_number_get                       PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function gets the number of hardware queue.                    */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    interface_ptr                         Pointer to interface instance */
/*    hw_queue_number                       Pointer to HW queue number    */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Internal function                                                   */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_shaper_hw_queue_number_get(NX_INTERFACE *interface_ptr, UCHAR *hw_queue_number)
{
    if (interface_ptr -> shaper_container == NX_NULL)
    {
        return(NX_NOT_SUPPORTED);
    }

    *hw_queue_number = interface_ptr -> shaper_container -> hw_queue_number;
    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_shaper_hw_cbs_queue_number_get                   PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function gets the number of hardware queue that support CBS.   */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    interface_ptr                         Pointer to interface instance */
/*    hw_cbs_queue_number                   Pointer to CBS HW queue       */
/*                                          number                        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_shaper_default_mapping_get                                       */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_shaper_hw_cbs_queue_number_get(NX_INTERFACE *interface_ptr, UCHAR *hw_cbs_queue_number)
{
UCHAR i;

    *hw_cbs_queue_number = 0;
    if (interface_ptr -> shaper_container == NX_NULL)
    {
        return(NX_NOT_SUPPORTED);
    }

    for (i = 0; i < interface_ptr -> shaper_container -> hw_queue_number; i++)
    {
        if (interface_ptr -> shaper_container -> hw_queue[i].type & NX_SHAPER_HW_QUEUE_CBS)
        {
            (*hw_cbs_queue_number)++;
        }
    }

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_shaper_port_rate_get                             PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function gets the port rate of the interface.                  */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    interface_ptr                         Pointer to interface instance */
/*    port_rate                             Pointer to port rate          */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Internal function                                                   */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_shaper_port_rate_get(NX_INTERFACE *interface_ptr, UINT *port_rate)
{
    if (interface_ptr -> shaper_container == NX_NULL)
    {
        return(NX_NOT_SUPPORTED);
    }

    *port_rate = interface_ptr -> shaper_container -> port_rate;
    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_shaper_mapping_set                               PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function configures the pcp to hardware queue mapping.         */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    interface_ptr                         Pointer to interface instance */
/*    pcp_list                              Pointer to PCP list           */
/*    queue_id_list                         Pointer to Queue id list      */
/*    list_size                             Size of PCP list              */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_shaper_mapping_set(NX_INTERFACE *interface_ptr, UCHAR *pcp_list, UCHAR *queue_id_list, UCHAR list_size)
{
UCHAR pcp;
UCHAR queue_id;
UCHAR i;

    if (interface_ptr -> shaper_container == NX_NULL)
    {
        return(NX_NOT_SUPPORTED);
    }

    if (list_size != NX_SHAPER_MAPPING_LIST_SIZE)
    {
        return(NX_INVALID_PARAMETERS);
    }

    for (i = 0; i < list_size; i++)
    {
        pcp = pcp_list[i];
        queue_id = queue_id_list[i];

        if ((pcp > NX_SHAPER_PCP_MAX) ||
            (queue_id >= interface_ptr -> shaper_container -> hw_queue_number))
        {
            return(NX_INVALID_PARAMETERS);
        }

        if ((pcp == 0) && (queue_id == 0))
        {
            /* no need to configure here */
            continue;
        }
        interface_ptr -> shaper_container -> queue_map[pcp] =
            interface_ptr -> shaper_container -> hw_queue[queue_id].hw_queue_id;
    }

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_shaper_cbs_parameter_set                         PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function configures the hardware parameters for CBS shaper.    */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    interface_ptr                         Pointer to interface instance */
/*    cbs_parameter                         Pointer to cbs parameter      */
/*    pcp                                   PCP                           */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_shaper_cbs_parameter_set(NX_INTERFACE *interface_ptr, NX_SHAPER_CBS_PARAMETER *cbs_parameter, UCHAR pcp)
{
UCHAR                      i;
UCHAR                      hw_queue_id;
UCHAR                      cbs_index;
NX_SHAPER_DRIVER_PARAMETER set_parameter;
UINT                       status;

    if (interface_ptr -> shaper_container == NX_NULL)
    {
        return(NX_NOT_SUPPORTED);
    }

    for (i = 0; i < NX_SHAPER_NUMBERS; i++)
    {
        if ((interface_ptr -> shaper_container -> shaper[i] != NX_NULL) &&
            (interface_ptr -> shaper_container -> shaper[i] -> shaper_type == NX_SHAPER_TYPE_CBS))
        {
            cbs_index = i;
            break;
        }
    }

    if (i >= NX_SHAPER_NUMBERS)
    {
        return(NX_NOT_FOUND);
    }

    hw_queue_id = interface_ptr -> shaper_container -> queue_map[pcp];

    for (i = (UCHAR)(interface_ptr -> shaper_container -> hw_queue_number - 1); i > 0; i--)
    {
        if (interface_ptr -> shaper_container -> hw_queue[i].hw_queue_id == hw_queue_id)
        {
            if ((interface_ptr -> shaper_container -> hw_queue[i].type & NX_SHAPER_HW_QUEUE_CBS) == 0)
            {
                return(NX_NOT_SUPPORTED);
            }
            else
            {
                break;
            }
        }
    }

    /* queue id 0 is assumed not support cbs */
    if (i == 0)
    {
        return(NX_NOT_SUPPORTED);
    }

    /* Save the cbs parameter */
    interface_ptr -> shaper_container -> shaper[cbs_index] -> cfg_pointer = (void *)cbs_parameter;

    cbs_parameter -> hw_queue_id = hw_queue_id;

    set_parameter.nx_shaper_driver_command = NX_SHAPER_COMMAND_PARAMETER_SET;
    set_parameter.shaper_type = NX_SHAPER_TYPE_CBS;         /* not used in driver */
    set_parameter.nx_ip_driver_interface = interface_ptr;
    set_parameter.shaper_parameter = (void *)cbs_parameter; /* not used in driver */

    status = interface_ptr -> shaper_container -> shaper[cbs_index] -> shaper_driver(&set_parameter);

    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_shaper_hw_queue_id_get                           PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function gets the hardware queue id by network driver.         */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    interface_ptr                         Pointer to interface instance */
/*    packet_ptr                            Pointer to packet             */
/*    hw_queue_id                           Pointer to HW queue ID        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Network driver                                                      */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_shaper_hw_queue_id_get(NX_INTERFACE *interface_ptr, NX_PACKET *packet_ptr, UCHAR *hw_queue_id)
{
UCHAR *data_ptr = packet_ptr -> nx_packet_prepend_ptr;
UCHAR  pcp = 0;

    if (interface_ptr -> shaper_container == NX_NULL)
    {
        return(NX_NOT_SUPPORTED);
    }

    /* Check VLAN tag.  */
    if (((data_ptr[12] << 8) | data_ptr[13]) == NX_LINK_ETHERNET_TPID)
    {
        /* VLAN tag is present.  */

        /* Get PCP */
        pcp = data_ptr[14] >> 5 & 0x07;

        /* Get hardware queue id for this packet */
        *hw_queue_id = interface_ptr -> shaper_container -> queue_map[pcp];
    }
    else
    {

        /* no VLAN tag in packet, send the packet to besteffort queue */
        *hw_queue_id = interface_ptr -> shaper_container -> queue_map[pcp];
    }

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_shaper_tas_parameter_set                         PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function configures the hardware parameters for TAS shaper.    */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    interface_ptr                         Pointer to interface instance */
/*    tas_config                            Pointer to cbs parameter      */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_shaper_tas_parameter_set(NX_INTERFACE *interface_ptr, NX_SHAPER_TAS_CONFIG *tas_config)
{
NX_SHAPER_TAS_PARAMETER    tas_parameter;
UCHAR                      i, j, tas_index = NX_SHAPER_INVALID_INDEX;
UINT                       front, end, step;
UINT                       left = 0, right;
UCHAR                      gcl_index;
UCHAR                      hw_queue_id;
NX_SHAPER_DRIVER_PARAMETER set_parameter;
UINT                       status;
UINT                       auto_fill_start;
UCHAR                      fp_enable = NX_FALSE;
NX_SHAPER_FP_PARAMETER    *fp_parameter;

    /* Initialize tas_parameter */
    memset(&tas_parameter, 0, sizeof(NX_SHAPER_TAS_PARAMETER));

    /* Initialize set_parameter */
    memset(&set_parameter, 0, sizeof(NX_SHAPER_DRIVER_PARAMETER));

    /* Find the TAS index. */
    for (i = 0; i < NX_SHAPER_NUMBERS; i++)
    {
        if ((interface_ptr -> shaper_container -> shaper[i] != NX_NULL) &&
            (interface_ptr -> shaper_container -> shaper[i] -> shaper_type == NX_SHAPER_TYPE_TAS))
        {
            tas_index = i;
        }
        else if ((interface_ptr -> shaper_container -> shaper[i] != NX_NULL) &&
                 (interface_ptr -> shaper_container -> shaper[i] -> shaper_type == NX_SHAPER_TYPE_FP))
        {
            fp_parameter = (NX_SHAPER_FP_PARAMETER *)interface_ptr -> shaper_container -> shaper[i] -> cfg_pointer;
            fp_enable = NX_TRUE;
            tas_parameter.fp_parameter = (void *)fp_parameter;
        }
    }

    if (tas_index == NX_SHAPER_INVALID_INDEX)
    {
        return(NX_NOT_FOUND);
    }

    auto_fill_start = 0;
    for (i = 0; i < tas_config -> traffic_count; i++)
    {
        if (tas_config -> traffic[i].time_offset + tas_config -> traffic[i].duration > auto_fill_start)
        {
            auto_fill_start = tas_config -> traffic[i].time_offset + tas_config -> traffic[i].duration;
        }
    }

    /* Transform the application input into driver input. */
    front = 0;
    if (tas_config -> auto_fill_status == NX_SHAPER_TAS_IDLE_CYCLE_AUTO_FILL_DISABLED)
    {
        end = auto_fill_start;
    }
    else
    {
        end = tas_config -> cycle_time;
    }
    gcl_index = 0;

    tas_parameter.base_time = tas_config -> base_time;
    tas_parameter.cycle_time = tas_config -> cycle_time;
    tas_parameter.cycle_time_extension = tas_config -> cycle_time / 2;

    /*
        Input:（Cycle time: 1000us, Cycle extension: default (half of cycle time), FP: disabled）
                    slot 0                                  slot 1
        P3(us) |-------200(O)-------|--------------------------800(C)--------------------|
        P2(us) |-------300(O)--------------------|-------------700(C)--------------------|
        Output:
                    slot(GCL)0        slot(GCL)1            slot(GCL)2
        P3(us) |-------200(O)-------|--100(C)----|-------------700(C)--------------------|
        P2(us) |-------200(O)-------|--100(O)----|-------------700(C)--------------------|
        PX(us) |-------200(C)-------|--100(C)----|-------------700(C)--------------------|

        Example:
                tas_config.base_time = 0;
                tas_config.cycle_time = 1000;
                tas_config.auto_fill_status = NX_SHAPER_TAS_IDLE_CYCLE_AUTO_FILL_WITH_CLOSE;
                tas_config.gcl_length = 2;

                tas_config.traffic[0].pcp = 3;
                tas_config.traffic[0].time_offset = 0;
                tas_config.traffic[0].duration = 200;
                tas_config.traffic[0].traffic_control = NX_SHAPER_TRAFFIC_OPEN;

                tas_config.traffic[1].pcp = 2;
                tas_config.traffic[1].time_offset = 0;
                tas_config.traffic[1].duration = 300;
                tas_config.traffic[1].traffic_control = NX_SHAPER_TRAFFIC_OPEN;
     */

    /* Split cycle into slots */
    while (front < end)
    {
        step = end - front;
        for (i = 0; i < tas_config -> traffic_count; i++)
        {
            if ((tas_config -> traffic[i].time_offset > front) && (step > tas_config -> traffic[i].time_offset - front))
            {
                step = tas_config -> traffic[i].time_offset - front;
            }
            else if ((tas_config -> traffic[i].time_offset + tas_config -> traffic[i].duration > front) &&
                     (step > tas_config -> traffic[i].time_offset + tas_config -> traffic[i].duration - front))
            {
                step = tas_config -> traffic[i].time_offset + tas_config -> traffic[i].duration - front;
            }
            else if (step > end - front)
            {
                step = end - front;
            }
        }

        if (front >= auto_fill_start)
        {
            tas_parameter.gcl[gcl_index].gate_control |= NX_SHAPER_GCL_AUTO_FILL_FLAG;
        }
        tas_parameter.gcl_length++;
        tas_parameter.gcl[gcl_index++].duration = step;
        front = front + step;
    }

    /* Config the gate_control on different slot */
    for (i = 0; i < tas_parameter.gcl_length; i++)
    {
        right = left + tas_parameter.gcl[i].duration;
        for (j = 0; j < tas_config -> traffic_count; j++)
        {
            if ((right <= tas_config -> traffic[j].time_offset) || (left >= tas_config -> traffic[j].time_offset + tas_config -> traffic[j].duration))
            {
                continue;
            }

            /* Get the hw queue id from pcp */
            hw_queue_id = interface_ptr -> shaper_container -> queue_map[tas_config -> traffic[j].pcp];
            if (tas_config -> traffic[j].traffic_control == NX_SHAPER_TRAFFIC_OPEN)
            {
                tas_parameter.gcl[i].gate_control |= (UCHAR)(1 << hw_queue_id);
            }
        }

        if (tas_parameter.gcl[i].gate_control & NX_SHAPER_GCL_AUTO_FILL_FLAG)
        {
            if (tas_config -> auto_fill_status == NX_SHAPER_TAS_IDLE_CYCLE_AUTO_FILL_WITH_OPEN)
            {
                tas_parameter.gcl[i].gate_control = 0xFF;
            }
            else
            {
                tas_parameter.gcl[i].gate_control &= ~NX_SHAPER_GCL_AUTO_FILL_FLAG;
            }
        }

        /* If fp is enabled, set the hold/release state based on the express queue status. */
        if (fp_enable)
        {
            /*
               For a GCE with set-hold, all queues opened must be Express queues. For a GCE with
               set-release all queues opened must be Preemptable queues. The same queue cannot
               be open in both a set-hold and a set-release operation.
             */
            if (tas_parameter.gcl[i].gate_control & fp_parameter -> express_queue_bitmap)
            {
                tas_parameter.gcl[i].operation = NX_SHAPER_GATE_OPERATION_HOLD;
            }
            else
            {
                tas_parameter.gcl[i].operation = NX_SHAPER_GATE_OPERATION_RELEASE;
            }
        }
        else
        {
            tas_parameter.gcl[i].operation = NX_SHAPER_GATE_OPERATION_SET;
        }

        left = right;
    }

    /* save the tas parameter */
    interface_ptr -> shaper_container -> shaper[tas_index] -> cfg_pointer = (void *)tas_config;

    /* Set the object(tas_param) of NX_SHAPER_TAS_PARAMETER */
    set_parameter.nx_shaper_driver_command = NX_SHAPER_COMMAND_PARAMETER_SET;
    set_parameter.shaper_type = NX_SHAPER_TYPE_TAS;          /* not used in driver */
    set_parameter.nx_ip_driver_interface = interface_ptr;
    set_parameter.shaper_parameter = (void *)&tas_parameter; /* not used in driver */

    status = interface_ptr -> shaper_container -> shaper[tas_index] -> shaper_driver(&set_parameter);

    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_shaper_express_queue_set                         PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function configures the express queue for frame preemption.    */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    interface_ptr                         Pointer to interface instance */
/*    express_queue_bitmap                  Pointer to express queue      */
/*                                          bitmap                        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_shaper_fp_parameter_set            FP parameter set              */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_shaper_express_queue_set(NX_INTERFACE *interface_ptr, UCHAR *express_queue_bitmap, UCHAR pcp)
{
UCHAR         hw_queue_id;
NX_INTERFACE *parent_interface;

    if (interface_ptr -> nx_interface_parent_ptr != NX_NULL)
    {
        parent_interface = interface_ptr -> nx_interface_parent_ptr;
    }
    else
    {
        parent_interface = interface_ptr;
    }

    if (parent_interface -> shaper_container == NX_NULL)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    hw_queue_id = parent_interface -> shaper_container -> queue_map[pcp];
    *express_queue_bitmap |= (UCHAR)(1 << hw_queue_id);

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_shaper_sdu_tx_time_get                           PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function gets the sdu transmit time.                           */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    interface_ptr                         Pointer to interface instance */
/*    sdu_size                              SDU size                      */
/*    tx_time                               Pointer to transmit time      */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_shaper_fp_parameter_set                                          */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_shaper_sdu_tx_time_get(NX_INTERFACE *interface_ptr, UINT sdu_size, UINT *tx_time)
{
UINT tmp;

    tmp = sdu_size * 8;
    tmp = tmp * 1000;
    if (interface_ptr -> shaper_container -> port_rate != 0)
    {
        tmp = tmp / interface_ptr -> shaper_container -> port_rate;
    }
    else
    {
        return(NX_NOT_SUCCESSFUL);
    }

    *tx_time = tmp;
    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_shaper_fp_parameter_set                          PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sets the frame preemption parameter, when used with   */
/*    other shapers, FP parameter should be set before other shapers.     */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    interface_ptr                         Pointer to interface instance */
/*    fp_parameter                          Pointer to FP parameter       */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_shaper_express_queue_set           Set express queue info        */
/*    nx_shaper_sdu_tx_time_get             Get sdu transmit time         */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_shaper_fp_parameter_set(NX_INTERFACE *interface_ptr, NX_SHAPER_FP_PARAMETER *fp_parameter)
{
UINT                       status;
NX_SHAPER_DRIVER_PARAMETER set_parameter;
UINT                       i;
UINT                       fp_index = NX_SHAPER_INVALID_INDEX;
UINT                       min_ha, max_ra;
UCHAR                      express_queue_bitmap = 0, pcp;


    /* Set the express queue bitmap. */
    for (i = 0; i <= NX_SHAPER_PCP_MAX; i++)
    {
        if (fp_parameter -> express_queue_bitmap & (1 << i))
        {
            pcp = (UCHAR)i;

            status = nx_shaper_express_queue_set(interface_ptr, &express_queue_bitmap, pcp);
            if (status != NX_SUCCESS)
            {
                return(status);
            }
        }
    }
    fp_parameter -> express_queue_bitmap = express_queue_bitmap;

    /* Set the object(fp_param) of NX_SHAPER_FP_PARAMETER */
    set_parameter.nx_shaper_driver_command = NX_SHAPER_COMMAND_PARAMETER_SET;
    set_parameter.shaper_type = NX_SHAPER_TYPE_FP; /* not used in driver */
    set_parameter.nx_ip_driver_interface = interface_ptr;

    nx_shaper_sdu_tx_time_get(interface_ptr, NX_SHAPER_DEFAULT_MIN_FRAGMENTABLE_SDU_SIZE, &min_ha);
    nx_shaper_sdu_tx_time_get(interface_ptr, NX_SHAPER_DEFAULT_MIN_SDU_SIZE, &max_ra);

    if (fp_parameter -> ha < min_ha)
    {
        fp_parameter -> ha = min_ha;
    }
    if (fp_parameter -> ra > max_ra)
    {
        fp_parameter -> ra = max_ra;
    }

    set_parameter.shaper_parameter = (void *)fp_parameter; /* not used in driver */

    for (i = 0; i < NX_SHAPER_NUMBERS; i++)
    {
        if ((interface_ptr -> shaper_container -> shaper[i] != NX_NULL) &&
            (interface_ptr -> shaper_container -> shaper[i] -> shaper_type == NX_SHAPER_TYPE_FP))
        {

            fp_index = i;
            break;
        }
    }

    if (fp_index == NX_SHAPER_INVALID_INDEX)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    /* save the fp parameter */
    interface_ptr -> shaper_container -> shaper[fp_index] -> cfg_pointer = (void *)fp_parameter;

    status = interface_ptr -> shaper_container -> shaper[fp_index] -> shaper_driver(&set_parameter);

    return(status);
}
#endif /* NX_ENABLE_VLAN */
