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
/** NetX MSRP Component                                                   */
/**                                                                       */
/**   Multiple Stream Registration Protocol (MSRP)                        */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#include "nx_msrp.h"

#ifdef NX_ENABLE_VLAN
#ifdef NX_MSRP_DEBUG
#ifndef NX_MSRP_DEBUG_PRINTF
#define NX_MSRP_DEBUG_PRINTF(x) printf x
#endif
#else
#define NX_MSRP_DEBUG_PRINTF(x)
#endif

static NX_MSRP_ATTRIBUTE msrp_attribute_array[NX_MSRP_ATTRIBUTE_ARRAY_MAX_SIZE];

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_msrp_init                                        PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wen Wang,  Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function initialize MSRP paramter.                             */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    msrp_ptr                              MSRP instance pointer         */
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
/*    nx_srp_init                           Initialize SRP                */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023        Wen Wang              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_msrp_init(NX_MSRP *msrp_ptr)
{
    /* Initialize MSRP structure.*/
    msrp_ptr -> nx_msrp_participant.participant_type = NX_MRP_PARTICIPANT_MSRP;
    msrp_ptr -> nx_msrp_participant.protocol_version = NX_MRP_MSRP_PROTOCOL_VERSION;
    msrp_ptr -> nx_msrp_participant.indication_function = nx_msrp_indication_process;
    msrp_ptr -> nx_msrp_participant.unpack_function = nx_msrp_mrpdu_parse;
    msrp_ptr -> nx_msrp_participant.pack_function = nx_msrp_mrpdu_pack;

    msrp_ptr -> nx_msrp_participant.join_timer = NX_MRP_TIMER_JOIN;
    msrp_ptr -> nx_msrp_participant.leaveall_timer = NX_MRP_TIMER_LEAVEALL;

    msrp_ptr -> msrp_callback_data = NX_NULL;

    return(NX_MSRP_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_msrp_attribute_find                              PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wen Wang,  Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function finds an MSRP attribute. Create new one if nothing    */
/*    can be find.                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp                                   MRP instance pointer          */
/*    participant                           MRP participant               */
/*    attribute_ptr                         Attribute pointer             */
/*    attribute_type                        Attribute type                */
/*    attribute_value                       Attribute value               */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_mrp_attribute_new                  Create new mrp attribute      */
/*    NX_MSRP_DEBUG_PRINTF                  Printf for debug              */
/*    memcpy                                Standard library function     */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_msrp_register_stream_request       MSRP register stream requset  */
/*    nx_msrp_register_attach_request       MSRP register stream attach   */
/*    nx_msrp_deregister_stream_request     MSRP deregister stream requset*/
/*    nx_msrp_deregister_attach_request     MSRP deregister stream attach */
/*    nx_msrp_register_domain_request       MSRP register domain requset  */
/*    nx_msrp_deregister_domain_request     MSRP deregister domain requset*/
/*    nx_msrp_mrpdu_parse                   MSRP parse MRP date unit      */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023        Wen Wang              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_msrp_attribute_find(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_MRP_ATTRIBUTE **attribute_ptr, UCHAR attribute_type, UCHAR *attribute_value)
{
NX_MRP_ATTRIBUTE *msrp_attribute;
NX_MRP_ATTRIBUTE *tmp;
INT               difference;

/* Look up attribute_type in attribute array.*/
NX_MRP_ATTRIBUTE *attribute_head = participant -> inused_head;

    while (NX_NULL != attribute_head)
    {
        if (attribute_head -> attribute_type == attribute_type)
        {
            switch (attribute_type)
            {
            case NX_MSRP_TALKER_ADVERTISE_VECTOR:

                if (memcmp(((NX_MSRP_ATTRIBUTE *)attribute_head) -> msrp_attribute_union.talker_advertise.stream_id, (UCHAR *)attribute_value, 8) == 0)
                {
                    *attribute_ptr = attribute_head;

                    return(NX_MSRP_ATTRIBUTE_FOUND);
                }

                break;

            case NX_MSRP_TALKER_LISTENER_VECTOR:

                if (memcmp(((NX_MSRP_ATTRIBUTE *)attribute_head) -> msrp_attribute_union.listener.stream_id, (UCHAR *)attribute_value, 8) == 0)
                {

                    *attribute_ptr = attribute_head;

                    return(NX_MSRP_ATTRIBUTE_FOUND);
                }

                break;

            case NX_MSRP_TALKER_DOMAIN_VECTOR:

                if (((NX_MSRP_ATTRIBUTE *)attribute_head) -> msrp_attribute_union.domain.sr_class_id == *(UCHAR *)attribute_value)
                {
                    *attribute_ptr = attribute_head;

                    return(NX_MSRP_ATTRIBUTE_FOUND);
                }
                NX_MSRP_DEBUG_PRINTF(("sr_class_id = %d \r\n", ((NX_MSRP_ATTRIBUTE *)attribute_head) -> msrp_attribute_union.domain.sr_class_id));

                NX_MSRP_DEBUG_PRINTF(("attribute_value = %d \r\n", *(UCHAR *)attribute_value));

                break;

            case NX_MSRP_TALKER_FAILED_VECTOR:

                if (memcmp(((NX_MSRP_ATTRIBUTE *)attribute_head) -> msrp_attribute_union.talker_advertise.stream_id, (UCHAR *)attribute_value, 8) == 0)
                {
                    *attribute_ptr = attribute_head;

                    return(NX_MSRP_ATTRIBUTE_FOUND);
                }

                break;

            default:

                break;
            }

            attribute_head = attribute_head -> next;
        }
        else
        {
            attribute_head = attribute_head -> next;
        }
    }

    *attribute_ptr = nx_mrp_attribute_new(mrp, participant, (NX_MRP_ATTRIBUTE *)msrp_attribute_array, sizeof(NX_MSRP_ATTRIBUTE), NX_MSRP_ATTRIBUTE_ARRAY_MAX_SIZE);

    /*Initialize attribute_type and part of attribute value.*/
    (*attribute_ptr) -> attribute_type = attribute_type;

    switch ((*attribute_ptr) -> attribute_type)
    {

    case NX_MSRP_TALKER_ADVERTISE_VECTOR:

        memcpy(((NX_MSRP_ATTRIBUTE *)*attribute_ptr) -> msrp_attribute_union.talker_advertise.stream_id,
               (UCHAR *)attribute_value, 8); /* use case of memcpy is verified. */
        break;

    case NX_MSRP_TALKER_LISTENER_VECTOR:

        memcpy(((NX_MSRP_ATTRIBUTE *)*attribute_ptr) -> msrp_attribute_union.listener.stream_id,
               (UCHAR *)attribute_value, 8); /* use case of memcpy is verified. */
        break;

    case NX_MSRP_TALKER_DOMAIN_VECTOR:

        memcpy(&((NX_MSRP_ATTRIBUTE *)*attribute_ptr) -> msrp_attribute_union.domain.sr_class_id,
               (UCHAR *)attribute_value, 1); /* use case of memcpy is verified. */
        break;

    case NX_MSRP_TALKER_FAILED_VECTOR:
    default:

        return(NX_MSRP_ATTRIBUTE_TYPE_ERROR);
    }


    if (*attribute_ptr == NX_NULL)
    {

        return(NX_MSRP_ATTRIBUTE_FIND_ERROR);
    }


    /* Do insert and sort as attribute type value when needs to create a new one.*/
    if (participant -> inused_head == NX_NULL)
    {

        participant -> inused_head = *attribute_ptr;

        return(NX_MSRP_ATTRIBUTE_NEW);
    }

    msrp_attribute = participant -> inused_head;

    while (msrp_attribute)
    {
        if (((*attribute_ptr) -> attribute_type) > (msrp_attribute -> attribute_type))
        {

            tmp = msrp_attribute;

            msrp_attribute =  msrp_attribute -> next;

            if (msrp_attribute == NX_NULL)
            {
                tmp -> next = *attribute_ptr;
                (*attribute_ptr) -> next = NX_NULL;
                return(NX_MSRP_ATTRIBUTE_NEW);
            }

            continue;
        }
        else if ((*attribute_ptr) -> attribute_type == msrp_attribute -> attribute_type)
        {

            while ((*attribute_ptr) -> attribute_type == msrp_attribute -> attribute_type)
            {
                switch ((*attribute_ptr) -> attribute_type)
                {

                case NX_MSRP_TALKER_ADVERTISE_VECTOR:

                    difference =  memcmp(((NX_MSRP_ATTRIBUTE *)*attribute_ptr) -> msrp_attribute_union.talker_advertise.stream_id,
                                         ((NX_MSRP_ATTRIBUTE *)*attribute_ptr) -> msrp_attribute_union.talker_advertise.stream_id, 8);
                    break;

                case NX_MSRP_TALKER_LISTENER_VECTOR:

                    difference =  memcmp(((NX_MSRP_ATTRIBUTE *)*attribute_ptr) -> msrp_attribute_union.listener.stream_id,
                                         ((NX_MSRP_ATTRIBUTE *)*attribute_ptr) -> msrp_attribute_union.listener.stream_id, 8);

                    break;
                case NX_MSRP_TALKER_DOMAIN_VECTOR:

                    difference =  memcmp(&((NX_MSRP_ATTRIBUTE *)*attribute_ptr) -> msrp_attribute_union.domain.sr_class_id,
                                         &((NX_MSRP_ATTRIBUTE *)*attribute_ptr) -> msrp_attribute_union.domain.sr_class_id, 1);

                    break;

                case NX_MSRP_TALKER_FAILED_VECTOR:
                default:

                    return(NX_MSRP_ATTRIBUTE_TYPE_ERROR);
                }

                if (difference < 0)
                {

                    (*attribute_ptr) -> next = msrp_attribute;

                    if (msrp_attribute == participant -> inused_head)
                    {
                        participant -> inused_head = *attribute_ptr;

                        break;
                    }
                    else
                    {
                        tmp -> next = *attribute_ptr;
                    }
                }
                else
                {

                    tmp = msrp_attribute;
                    msrp_attribute = msrp_attribute -> next;
                    if (msrp_attribute == NX_NULL)
                    {
                        tmp -> next = *attribute_ptr;
                        (*attribute_ptr) -> next = NX_NULL;
                        return(NX_MSRP_ATTRIBUTE_NEW);
                    }
                }
            }
        }
        else
        {

            (*attribute_ptr) -> next = msrp_attribute;

            if (msrp_attribute == participant -> inused_head)
            {
                participant -> inused_head = *attribute_ptr;

                break;
            }
            else
            {
                tmp -> next = *attribute_ptr;

                break;
            }
        }
    }

    return(NX_MSRP_ATTRIBUTE_NEW);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_msrp_register_stream_request                     PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wen Wang,  Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function register stream request.                              */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp                                   MRP instance pointer          */
/*    participant                           MRP participant               */
/*    talker_advertise                      Talker advertise properties   */
/*    attribute_type                        Attribute type                */
/*    new_request                           Create new request            */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_msrp_attribute_find                Find MSRP attribute           */
/*    nx_mrp_event_process                  Process mrp_event             */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_srp_talker_start                   Start SRP talker              */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023        Wen Wang              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_msrp_register_stream_request(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_MSRP_TALKER_ADVERTISE *talker_advertise, UINT new_request)
{
NX_MRP_ATTRIBUTE *attribute = NX_NULL;
UINT              status;
UCHAR            *attribute_value;
UCHAR             attribute_type;
UCHAR             mrp_event;

    if (new_request)
    {

        mrp_event = NX_MRP_EVENT_NEW;
    }
    else
    {

        mrp_event = NX_MRP_EVENT_JOIN;
        return(NX_MSRP_EVENT_NOT_SUPPORTED);
    }

    attribute_type = NX_MSRP_TALKER_ADVERTISE_VECTOR;

    attribute_value = talker_advertise -> stream_id;

    /* Get mrp mutex. */
    tx_mutex_get(&mrp -> mrp_mutex, NX_WAIT_FOREVER);

    status = nx_msrp_attribute_find(mrp, participant,  &attribute, attribute_type, attribute_value);

    if (attribute != NX_NULL)
    {

        attribute -> attribute_type = NX_MSRP_TALKER_ADVERTISE_VECTOR;

        memcpy(&(((NX_MSRP_ATTRIBUTE *)attribute) -> msrp_attribute_union.talker_advertise),
                 talker_advertise, sizeof(NX_MSRP_TALKER_ADVERTISE)); /* use case of memcpy is verified. */

        ((NX_MSRP_ATTRIBUTE *)attribute) -> indication_flag = 0;

        status = nx_mrp_event_process(mrp, participant, attribute, mrp_event);
    }
    else
    {
        status = NX_MSRP_ATTRIBUTE_FIND_ERROR;
    }

    /* Release the mutex.  */
    tx_mutex_put(&(mrp -> mrp_mutex));
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_msrp_register_attach_request                     PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wen Wang,  Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function register stream attach request.                       */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp                                   MRP instance pointer          */
/*    participant                           MRP participant               */
/*    stream_id                             Stream ID                     */
/*    fourpacked_value                      fourpacked value              */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_msrp_attribute_find                Find MSRP attribute           */
/*    nx_mrp_event_process                  Process mrp_event             */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_msrp_register_stream_indication    Indication MSRP register      */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023        Wen Wang              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_msrp_register_attach_request(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, UCHAR *stream_id, UINT mrp_event, UCHAR fourpacked_value)
{
NX_MRP_ATTRIBUTE *attribute = NX_NULL;
UINT              status;
UCHAR             attribute_type = NX_MSRP_TALKER_LISTENER_VECTOR;

    /* Get mutex. */
    tx_mutex_get(&mrp -> mrp_mutex, NX_WAIT_FOREVER);

    status = nx_msrp_attribute_find(mrp, participant, &attribute, attribute_type, stream_id);

    if (attribute != NX_NULL)
    {

        attribute -> attribute_type = NX_MSRP_TALKER_LISTENER_VECTOR;

        memcpy(((NX_MSRP_ATTRIBUTE *)attribute) -> msrp_attribute_union.listener.stream_id,
                stream_id, 8); /* use case of memcpy is verified. */

        ((NX_MSRP_ATTRIBUTE *)attribute) -> indication_flag = 0;

        ((NX_MSRP_ATTRIBUTE *)attribute) -> msrp_attribute_union.listener.fourpacked_event = fourpacked_value;

        status = nx_mrp_event_process(mrp, participant, attribute, (UCHAR)mrp_event);
    }
    else
    {
        status = NX_MSRP_ATTRIBUTE_FIND_ERROR;
    }

    /* Release the mutex.  */
    tx_mutex_put(&(mrp -> mrp_mutex));
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_msrp_deregister_stream_request                   PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wen Wang,  Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function deregister stream request.                            */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp                                   MRP instance pointer          */
/*    participant                           MRP participant               */
/*    stream_id                             Stream ID                     */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_msrp_attribute_find                Find MSRP attribute           */
/*    nx_mrp_event_process                  Process mrp_event             */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_srp_talker_stop                    Stop SRP talker               */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023        Wen Wang              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_msrp_deregister_stream_request(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, UCHAR *stream_id)
{
UINT              status;
NX_MRP_ATTRIBUTE *attribute = NX_NULL;
UINT              mrp_event = NX_MRP_EVENT_LV;
UCHAR             attribute_type = NX_MSRP_TALKER_ADVERTISE_VECTOR;

    /* Get mutex. */
    tx_mutex_get(&mrp -> mrp_mutex, NX_WAIT_FOREVER);

    status = nx_msrp_attribute_find(mrp, participant, &attribute, attribute_type, stream_id);

    if (status == NX_MSRP_ATTRIBUTE_FOUND)
    {
        ((NX_MSRP_ATTRIBUTE *)attribute) -> indication_flag = 0;

        status = nx_mrp_event_process(mrp, participant, attribute, (UCHAR)mrp_event);
    }
    else
    {
        status = NX_MSRP_ATTRIBUTE_FIND_ERROR;
    }

    /* Release the mutex.  */
    tx_mutex_put(&(mrp -> mrp_mutex));
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_msrp_deregister_attach_request                   PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wen Wang,  Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function deregister stream attach request.                     */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp                                   MRP instance pointer          */
/*    participant                           MRP participant               */
/*    stream_id                             Stream ID                     */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_msrp_attribute_find                Find MSRP attribute           */
/*    nx_mrp_event_process                  Process MRP mrp_event         */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_msrp_deregister_stream_indication  receive deregister stream     */
/*    nx_srp_listener_stop                  Stop SRP listener             */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023        Wen Wang              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_msrp_deregister_attach_request(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, UCHAR *stream_id)
{
UINT              status;
NX_MRP_ATTRIBUTE *attribute = NX_NULL;
UINT              mrp_event = NX_MRP_EVENT_LV;
UCHAR             attribute_type = NX_MSRP_TALKER_LISTENER_VECTOR;

    /* Get mrp mutex. */
    tx_mutex_get(&mrp -> mrp_mutex, NX_WAIT_FOREVER);

    status = nx_msrp_attribute_find(mrp, participant, &attribute, attribute_type, stream_id);

    if (status == NX_MSRP_ATTRIBUTE_FOUND)
    {

        ((NX_MSRP_ATTRIBUTE *)attribute) -> indication_flag = 0;

        status = nx_mrp_event_process(mrp, participant, attribute, (UCHAR)mrp_event);
    }
    else
    {
        status = NX_MSRP_ATTRIBUTE_FIND_ERROR;
    }

    /* Release the mutex.*/
    tx_mutex_put(&(mrp -> mrp_mutex));
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_msrp_register_domain_request                     PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wen Wang,  Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function register domain request.                              */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp                                   MRP instance pointer          */
/*    participant                           MRP participant               */
/*    domain                                Stream properties             */
/*    new_request                           Create new request            */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_msrp_attribute_find                Find MSRP attribute           */
/*    nx_mrp_event_process                  Process MRP mrp_event             */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_srp_talker_start                   Start SRP talker              */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023        Wen Wang              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_msrp_register_domain_request(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_MSRP_DOMAIN *domain, UINT new_request)
{

NX_MRP_ATTRIBUTE *attribute = NX_NULL;
UINT              mrp_event;
UINT              status;


    if (new_request)
    {
        mrp_event = NX_MRP_EVENT_NEW;
    }
    else
    {
        mrp_event = NX_MRP_EVENT_JOIN;
        return(NX_MSRP_EVENT_NOT_SUPPORTED);
    }

    /* Get mutex. */
    tx_mutex_get(&mrp -> mrp_mutex, NX_WAIT_FOREVER);

    status = nx_msrp_attribute_find(mrp, participant, &attribute, NX_MSRP_TALKER_DOMAIN_VECTOR, &domain -> sr_class_id);

    if (attribute == NX_NULL)
    {
        status = NX_MSRP_ATTRIBUTE_FIND_ERROR;
    }
    else if (status == NX_MSRP_ATTRIBUTE_NEW)
    {

        attribute -> attribute_type = NX_MSRP_TALKER_DOMAIN_VECTOR;

        memcpy(&(((NX_MSRP_ATTRIBUTE *)attribute) -> msrp_attribute_union.domain),
               domain, sizeof(NX_MSRP_DOMAIN)); /* use case of memcpy is verified. */

        ((NX_MSRP_ATTRIBUTE *)attribute) -> indication_flag = 0;

        status = nx_mrp_event_process(mrp, participant, attribute, (UCHAR)mrp_event);
    }
    else
    {
        status = NX_MSRP_SUCCESS;
    }

    /* Release the mutex.  */
    tx_mutex_put(&(mrp -> mrp_mutex));
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_msrp_deregister_domain_request                   PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wen Wang,  Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function deregister domain request.                            */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp                                   MRP instance pointer          */
/*    participant                           MRP participant               */
/*    domain                                Stream properties             */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_msrp_attribute_find                Find MSRP attribute           */
/*    nx_mrp_event_process                  Process MRP mrp_event         */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_srp_talker_stop                    Stop SRP talker               */
/*    nx_srp_listener_stop                  Stop SRP listener             */
/*    nx_msrp_deregister_domain_indication  Deregister MSRP domain        */
/*                                          indication                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023        Wen Wang              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_msrp_deregister_domain_request(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_MSRP_DOMAIN *domain)
{

NX_MRP_ATTRIBUTE *attribute = NX_NULL;
UINT              mrp_event = NX_MRP_EVENT_LV;
UINT              status;

    /* Get mutex. */
    tx_mutex_get(&mrp -> mrp_mutex, NX_WAIT_FOREVER);

    status = nx_msrp_attribute_find(mrp, participant, &attribute, NX_MSRP_TALKER_DOMAIN_VECTOR, &domain -> sr_class_id);

    if (status == NX_MSRP_ATTRIBUTE_FOUND)
    {

        ((NX_MSRP_ATTRIBUTE *)attribute) -> indication_flag = 0;

        status = nx_mrp_event_process(mrp, participant, attribute, (UCHAR)mrp_event);
    }
    else
    {
        status = NX_MSRP_ATTRIBUTE_FIND_ERROR;
    }

    /* Release the mutex.  */
    tx_mutex_put(&(mrp -> mrp_mutex));
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_msrp_register_stream_indication                  PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wen Wang,  Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function register stream indication.                           */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp                                   MRP instance pointer          */
/*    participant                           MRP participant               */
/*    attribute                             Attribute                     */
/*    indication_type                       Indication type               */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_msrp_register_attach_request       MSRP register attach request  */
/*    event_callback                        Application callback          */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_msrp_indication_process            Process MSRP indication       */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023        Wen Wang              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_msrp_register_stream_indication(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_MRP_ATTRIBUTE *attribute, UINT indication_type)
{
UINT                  status;
UCHAR                *stream_id;
NX_MRP_EVENT_CALLBACK event_callback;


    if (((NX_MSRP *)participant) -> listener_enable)
    {

        event_callback = ((NX_MSRP *)participant) -> msrp_event_callback;


        if (event_callback != NX_NULL)
        {

            status = event_callback(participant, attribute, (UCHAR)indication_type, ((NX_MSRP *)participant) -> msrp_callback_data);

            /* Listener receives register stream idication, then starts to register attach request*/
            if (status == NX_MSRP_SUCCESS)
            {

                stream_id = ((NX_MSRP_ATTRIBUTE *)attribute) -> msrp_attribute_union.talker_advertise.stream_id;

                status = nx_msrp_register_attach_request(mrp, participant, stream_id, indication_type, NX_MSRP_FOURPACKED_READY);
            }
        }
        else
        {
            stream_id = ((NX_MSRP_ATTRIBUTE *)attribute) -> msrp_attribute_union.talker_advertise.stream_id;

            ((NX_MSRP_ATTRIBUTE *)attribute) -> msrp_attribute_union.listener.fourpacked_event = NX_MSRP_FOURPACKED_READY;

            status = nx_msrp_register_attach_request(mrp, participant, stream_id, indication_type, NX_MSRP_FOURPACKED_READY);
        }
    }
    else
    {

        return(NX_MSRP_LISTENER_NOT_ENABLED);
    }

    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_msrp_deregister_stream_indication                PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wen Wang,  Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function deregister stream indication.                         */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp                                   MRP instance pointer          */
/*    participant                           MRP participant               */
/*    attribute                             Attribute                     */
/*    indication_type                       Indication type               */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_msrp_deregister_attach_request     MSRP deregister attach request*/
/*    event_callback                        Application callback          */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_msrp_indication_process            Process MSRP indication       */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023        Wen Wang              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_msrp_deregister_stream_indication(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_MRP_ATTRIBUTE *attribute, UCHAR indication_type)
{

UINT                  status;
NX_MRP_EVENT_CALLBACK event_callback;

event_callback             = ((NX_MSRP *)participant) -> msrp_event_callback;
UCHAR *stream_id;

    if (event_callback)
    {

        status = event_callback(participant, attribute, indication_type, ((NX_MSRP *)participant) -> msrp_callback_data);

        if (status)
        {
            return(status);
        }

        stream_id = ((NX_MSRP_ATTRIBUTE *)attribute) -> msrp_attribute_union.talker_advertise.stream_id;

        /*Listener Receive deregister indication, send deregister attach*/
        nx_msrp_deregister_attach_request(mrp, participant, stream_id);
    }

    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_msrp_register_attach_indication                  PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wen Wang,  Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function register attach indication.                           */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    participant                           MRP participant               */
/*    attribute                             Attribute                     */
/*    indication_type                       Indication type               */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    event_callback                        Application callback          */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_msrp_indication_process            Process MSRP indication       */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023        Wen Wang              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_msrp_register_attach_indication(NX_MRP_PARTICIPANT *participant, NX_MRP_ATTRIBUTE *attribute, UCHAR indication_type)
{
UINT                  status = NX_MSRP_SUCCESS;
NX_MRP_EVENT_CALLBACK event_callback;

    event_callback = ((NX_MSRP *)participant) -> msrp_event_callback;

    if (event_callback != NX_NULL)
    {

        status = event_callback(participant, attribute, indication_type, ((NX_MSRP *)participant) -> msrp_callback_data);
    }

    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_msrp_deregister_attach_indication                PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wen Wang,  Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function deregister attach indication.                         */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    participant                           MRP participant               */
/*    attribute                             Attribute                     */
/*    indication_type                       Indication type               */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    event_callback                        Application callback          */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_msrp_indication_process            Process MSRP indication       */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023        Wen Wang              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_msrp_deregister_attach_indication(NX_MRP_PARTICIPANT *participant, NX_MRP_ATTRIBUTE *attribute, UCHAR indication_type)
{
UINT                  status = NX_MSRP_SUCCESS;
NX_MRP_EVENT_CALLBACK event_callback;

    event_callback = ((NX_MSRP *)participant) -> msrp_event_callback;

    if (event_callback != NX_NULL)
    {

        status = event_callback(participant, attribute, indication_type, ((NX_MSRP *)participant) -> msrp_callback_data);
    }

    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_msrp_register_domain_indication                  PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wen Wang,  Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function register domain indication.                           */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp                                   MRP instance pointer          */
/*    participant                           MRP participant               */
/*    attribute                             Attribute                     */
/*    indication_type                       Indication type               */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    event_callback                        Application callback          */
/*    nx_msrp_register_domain_request       MSRP register domain request  */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_msrp_indication_process            Process MSRP indication       */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023        Wen Wang              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_msrp_register_domain_indication(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_MRP_ATTRIBUTE *attribute, UCHAR indication_type)
{
UINT                  status;
NX_MRP_EVENT_CALLBACK event_callback;

event_callback             = ((NX_MSRP *)participant) -> msrp_event_callback;
NX_MSRP_DOMAIN *domain;


    if (event_callback != NX_NULL)
    {
        status = event_callback(participant, attribute, indication_type, ((NX_MSRP *)participant) -> msrp_callback_data);

        if (status != NX_MSRP_SUCCESS)
        {
            return(status);
        }

        domain = &(((NX_MSRP_ATTRIBUTE *)attribute) -> msrp_attribute_union.domain);

        nx_msrp_register_domain_request(mrp, participant, domain, NX_MSRP_ACTION_NEW);
    }

    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_msrp_deregister_domain_indication                PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wen Wang,  Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function deregister domain indication.                         */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp                                   MRP instance pointer          */
/*    participant                           MRP participant               */
/*    attribute                             Attribute                     */
/*    indication_type                       Indication type               */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    event_callback                        Application callback          */
/*    nx_msrp_deregister_domain_request     MSRP deregister domain request*/
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_msrp_indication_process            Process MSRP indication       */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023        Wen Wang              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_msrp_deregister_domain_indication(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_MRP_ATTRIBUTE *attribute, UCHAR indication_type)
{
UINT                  status = NX_MSRP_SUCCESS;
NX_MRP_EVENT_CALLBACK event_callback;

event_callback             = ((NX_MSRP *)participant) -> msrp_event_callback;
NX_MSRP_DOMAIN *domain;

    if (event_callback)
    {
        status = event_callback(participant, attribute, indication_type, ((NX_MSRP *)participant) -> msrp_callback_data);

        if (status != NX_MSRP_SUCCESS)
        {
            return(status);
        }

        domain = &(((NX_MSRP_ATTRIBUTE *)attribute) -> msrp_attribute_union.domain);

        nx_msrp_deregister_domain_request(mrp, participant, domain);
    }

    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_msrp_indication_process                          PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wen Wang,  Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function process MSRP indication.                              */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp                                   MRP instance pointer          */
/*    participant                           MRP participant               */
/*    attribute                             Attribute                     */
/*    indication_type                       Indication type               */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_msrp_register_stream_indication    MSRP register stream indicate */
/*    nx_msrp_deregister_stream_indication  MSRP deregister srteam        */
/*                                          indicate                      */
/*    nx_msrp_register_attach_indication    MSRP register attach indicate */
/*    nx_msrp_deregister_attach_indication  MSRP deregister attach        */
/*                                          indicate                      */
/*    nx_msrp_register_domain_indication    MSRP register domain indicate */
/*    nx_msrp_deregister_domain_indication  MSRP deregister domain        */
/*                                          indicate                      */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_mrp_registrar_event_process        Process registrar mrp_event   */
/*    nx_mrp_attribute_evict                Evict MRP attribute           */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023        Wen Wang              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_msrp_indication_process(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_MRP_ATTRIBUTE *attribute, UCHAR indication_type)
{

UINT status;


    switch (attribute -> attribute_type)
    {
    case NX_MSRP_TALKER_ADVERTISE_VECTOR:

        if (indication_type == NX_MRP_INDICATION_NEW || indication_type == NX_MRP_INDICATION_JOIN)
        {
            {
                ((NX_MSRP_ATTRIBUTE *)attribute) -> indication_flag = 1;

                status = nx_msrp_register_stream_indication(mrp, participant, attribute, indication_type);

                if (status != NX_MSRP_SUCCESS)
                {
                    ((NX_MSRP_ATTRIBUTE *)attribute) -> indication_flag = 0;
                }
            }
        }
        else if (indication_type == NX_MRP_INDICATION_LV)
        {
            {
                ((NX_MSRP_ATTRIBUTE *)attribute) -> indication_flag = 1;

                status = nx_msrp_deregister_stream_indication(mrp, participant, attribute, indication_type);
            }
        }
        else
        {

            status = NX_MSRP_INDICATION_TYPE_ERROR;
        }

        break;

    case NX_MSRP_TALKER_LISTENER_VECTOR:

        if (indication_type == NX_MRP_INDICATION_NEW || indication_type == NX_MRP_INDICATION_JOIN)
        {
            {
                if (((NX_MSRP_ATTRIBUTE *)attribute) -> msrp_attribute_union.listener.fourpacked_event >= NX_MSRP_FOURPACKED_READY)
                {
                    status = nx_msrp_register_attach_indication(participant, attribute, indication_type);

                    ((NX_MSRP_ATTRIBUTE *)attribute) -> indication_flag = 1;
                }
            }
        }
        else if (indication_type == NX_MRP_INDICATION_LV)
        {
            {

                if (((NX_MSRP_ATTRIBUTE *)attribute) -> msrp_attribute_union.listener.fourpacked_event >= NX_MSRP_FOURPACKED_READY)
                {
                    status = nx_msrp_deregister_attach_indication(participant, attribute, indication_type);

                    ((NX_MSRP_ATTRIBUTE *)attribute) -> indication_flag = 1;
                }
            }
        }
        else
        {

            status = NX_MSRP_INDICATION_TYPE_ERROR;
        }

        break;

    case NX_MSRP_TALKER_DOMAIN_VECTOR:

        if (indication_type == NX_MRP_INDICATION_NEW || indication_type == NX_MRP_INDICATION_JOIN)
        {
            {
                ((NX_MSRP_ATTRIBUTE *)attribute) -> indication_flag = 1;

                status = nx_msrp_register_domain_indication(mrp, participant, attribute, indication_type);
            }
        }
        else if (indication_type == NX_MRP_INDICATION_LV)
        {
            {
                ((NX_MSRP_ATTRIBUTE *)attribute) -> indication_flag = 1;

                status = nx_msrp_deregister_domain_indication(mrp, participant, attribute, indication_type);
            }
        }
        else
        {
            status = NX_MSRP_INDICATION_TYPE_ERROR;
        }

        break;

    case NX_MSRP_TALKER_FAILED_VECTOR:

        break;

    default:

        status = NX_MSRP_ATTRIBUTE_TYPE_ERROR;
        break;
    }

    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_msrp_mrpdu_parse                                 PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wen Wang,  Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function parse MRP data unit.                                  */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp                                   MRP instance pointer          */
/*    participant                           MRP participant               */
/*    packet_ptr                            Packet pointer                */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_msrp_attribute_find                MSRP attribute traverse       */
/*    memcpy                                standard library              */
/*                                                                        */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_mrp_registrar_event_process        Process registrar mrp_event   */
/*    nx_mrp_attribute_evict                Evict MRP attribute           */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023        Wen Wang              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_msrp_mrpdu_parse(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_PACKET *packet_ptr)
{
UINT                      status;
NX_MRP_ATTRIBUTE         *attribute = NX_NULL;
NX_MSRP_TALKER_ADVERTISE *talker_advertise_ptr;
NX_MSRP_TALKER_FAILED    *talker_failed_ptr;
UCHAR                     attribute_type;
UINT                      attribute_type_index;
UCHAR                     mrp_event;
UCHAR                     is_end = 0;
UINT                      attribute_list_length_index;
USHORT                    num_of_value;
UINT                      num_of_value_index;
UINT                      first_value_index;
UCHAR                     lva_event;
UCHAR                     four_packed_event;
UCHAR                     three_packed_event;
USHORT                    attribute_list_length;
UCHAR                     SRclass_id;
UCHAR                    *stream_id;
UCHAR                    *data_ptr = packet_ptr -> nx_packet_data_start;



    if (*(data_ptr + NX_MSRP_PROTOCAL_VERSION_INDEX) != 0)
    {
        return(NX_MSRP_VERSION_NOT_SUPPORTED);
    }


    attribute_type_index = NX_MSRP_PROTOCAL_VERSION_INDEX + 1;


    while (is_end == 0)
    {

        num_of_value_index = attribute_type_index + 4;
        attribute_list_length_index = attribute_type_index + 2;

        lva_event = *(data_ptr + num_of_value_index) >> 5;
        num_of_value = (USHORT)((*(data_ptr + num_of_value_index) & 0x1f) | *(data_ptr + num_of_value_index + 1));

        /*attribute header = 5 bytes*/
        first_value_index = attribute_type_index + 6;

        if (num_of_value > 1)
        {

            return(NX_MSRP_NOT_SUPPORTED);
        }

        attribute_type = *(data_ptr + attribute_type_index);

        attribute_list_length = (USHORT)(*(data_ptr + attribute_list_length_index) << 8 | *(data_ptr + attribute_list_length_index + 1));


        if (num_of_value)
        {


            switch (attribute_type)
            {

            case NX_MSRP_TALKER_ADVERTISE_VECTOR:



                talker_advertise_ptr = (NX_MSRP_TALKER_ADVERTISE *)(data_ptr + first_value_index);

                status = nx_msrp_attribute_find(mrp, participant, &attribute, attribute_type, talker_advertise_ptr -> stream_id);

                /* No attribute was found or created.*/
                if (attribute == NX_NULL)
                {

                    return(NX_MSRP_ATTRIBUTE_FIND_ERROR);
                }

                if (status == NX_MSRP_ATTRIBUTE_NEW)
                {

                    memcpy(&((NX_MSRP_ATTRIBUTE *)attribute) -> msrp_attribute_union.talker_advertise, talker_advertise_ptr,
                           sizeof(NX_MSRP_TALKER_ADVERTISE)); /* use case of memcpy is verified. */
                }


                break;

            case NX_MSRP_TALKER_LISTENER_VECTOR:

                stream_id = (data_ptr + first_value_index);

                nx_msrp_attribute_find(mrp, participant, &attribute, attribute_type, stream_id);

                /* No attribute was found or created.*/
                if (attribute == NX_NULL)
                {

                    return(NX_MSRP_ATTRIBUTE_FIND_ERROR);
                }

                if (status == NX_MSRP_ATTRIBUTE_NEW)
                {

                    memcpy(&((NX_MSRP_ATTRIBUTE *)attribute) -> msrp_attribute_union.listener, stream_id,
                           sizeof(NX_MSRP_LISTENER)); /* use case of memcpy is verified. */
                }

                four_packed_event = *(data_ptr + attribute_list_length_index + attribute_list_length - 1);

                /* FourPackedEvents BYTE ::= ((FourPackedType *64) + (FourPackedType *16)+ (FourPackedType *4) + FourPackedType).*/
                four_packed_event = four_packed_event / 64;

                ((NX_MSRP_ATTRIBUTE *)attribute) -> msrp_attribute_union.listener.fourpacked_event = four_packed_event;

                break;

            case NX_MSRP_TALKER_DOMAIN_VECTOR:

                SRclass_id = *(data_ptr + first_value_index);

                status = nx_msrp_attribute_find(mrp, participant, &attribute, attribute_type, &SRclass_id);

                /* No attribute was found or created.*/
                if (attribute == NX_NULL)
                {

                    return(NX_MSRP_ATTRIBUTE_FIND_ERROR);
                }

                if (status == NX_MSRP_ATTRIBUTE_NEW)
                {
                    /* If this is a exsit attribute, we assume that it comes from talker,*/
                    /* and if the applicaion did not start listener, send notify to user callback shouldn't happen.*/
                    if (((NX_MSRP *)participant) -> listener_enable == 0)
                    {

                        ((NX_MSRP_ATTRIBUTE *)attribute) -> indication_flag = 1;
                    }

                    memcpy(&((NX_MSRP_ATTRIBUTE *)attribute) -> msrp_attribute_union.domain, (data_ptr + first_value_index),
                           sizeof(NX_MSRP_DOMAIN)); /* use case of memcpy is verified. */

                    NX_CHANGE_USHORT_ENDIAN(((NX_MSRP_ATTRIBUTE *)attribute) -> msrp_attribute_union.domain.sr_class_vid);
                }

                break;

            case NX_MSRP_TALKER_FAILED_VECTOR:



                talker_failed_ptr = (NX_MSRP_TALKER_FAILED *)(data_ptr + first_value_index);

                nx_msrp_attribute_find(mrp, participant, &attribute, attribute_type, talker_failed_ptr -> stream_id);

                /* No attribute was found or created.*/
                if (attribute == NX_NULL)
                {

                    return(NX_MSRP_ATTRIBUTE_FIND_ERROR);
                }

                break;

            default:

                return(NX_MSRP_ATTRIBUTE_TYPE_ERROR);
                break;
            }


            if (lva_event)
            {

                mrp_event = NX_MRP_EVENT_RLA;

                nx_mrp_event_process(mrp, participant, attribute, mrp_event);
            }

            /* ThreePackedEvents BYTE ::= (((((AttributeEvent) *6) + AttributeEvent) *6) + AttributeEvent).*/
            three_packed_event = *(data_ptr + attribute_list_length_index + attribute_list_length - 2);

            three_packed_event = three_packed_event / 36;

            status = nx_mrp_event_process(mrp, participant, attribute, three_packed_event);

            if (status != NX_MSRP_SUCCESS)
            {
                return(status);
            }
        }

        /* Endmask of each attribute *(data_ptr + attribute_list_length_index + attribute_list_length )*/
        /* Endmask of each attribute *(data_ptr + attribute_list_length_index + attribute_list_length + 1))*/
        if (*(data_ptr + attribute_list_length_index + attribute_list_length + 2) == NX_MSRP_ATTRIBUTE_END_MASK &&
            *(data_ptr + attribute_list_length_index + attribute_list_length + 3) == NX_MSRP_ATTRIBUTE_END_MASK)
        {

            is_end = 1;
        }
        else
        {

            /* 4bytes : attrubute length + attribute_list_length + 1*/
            attribute_type_index = attribute_type_index + attribute_list_length + 4;
        }
    }

    return(NX_MSRP_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_msrp_mrpdu_pack_attribute                        PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wen Wang,  Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function pack attribute into MRP data unit.                    */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    participant                           MRP participant               */
/*    attribute                             Attribute                     */
/*    num_of_value                          Number of value               */
/*    threepacked_event                     Threepacked mrp_event         */
/*    fourpacked_event                      Fourpacked_event              */
/*    data_ptr                              Data pointer                  */
/*    length_ptr                            Length pointer                */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    memcpy                                standard library              */
/*                                                                        */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_msrp_mrpdu_pack                    MSRP pack MRP data unit       */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023        Wen Wang              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_msrp_mrpdu_pack_attribute(NX_MRP_PARTICIPANT *participant, NX_MRP_ATTRIBUTE *attribute, USHORT num_of_value,
                                  UCHAR *threepacked_event, UCHAR *fourpacked_event, UCHAR *data_ptr, UINT *length_ptr)
{

UCHAR  threepacked_value[NX_MSRP_ATTRIBUTE_ARRAY_MAX_SIZE  / 4 / 3 + 1];
UCHAR  fourpacked_value[NX_MSRP_ATTRIBUTE_ARRAY_MAX_SIZE  / 4 / 3 + 1];
UINT   num_of_threepacked;
UINT   num_of_fourpacked;
UINT   i, index = 0;
UINT   lva_event = 0;
USHORT tmp;
USHORT attribute_list_length;

    /* Allowed max value of talker and listener.*/
    if (num_of_value > NX_MSRP_ATTRIBUTE_ARRAY_MAX_SIZE  / 4)
    {

        return(NX_MSRP_PARAMETER_ERROR);
    }

    if (participant -> leaveall.action == NX_MRP_ACTION_SLA)
    {

        lva_event = 1;

        /* Send only lva mrp_event, the attribute content will be null.*/
        if ((attribute -> applicant.action == NX_MRP_ACTION_NULL) || (attribute -> applicant.action > NX_MRP_ACTION_S_OPT))
        {

            num_of_value = 0;

            switch (attribute -> attribute_type)
            {

            case NX_MSRP_TALKER_ADVERTISE_VECTOR:

                *data_ptr++ = NX_MSRP_TALKER_ADVERTISE_VECTOR;
                *data_ptr++ = NX_MSRP_TALKER_ADVERTISE_ATTRIBUTE_LENGTH;
                *data_ptr++ = 0;

                /* 4 = vectorhead + endmark.*/
                attribute_list_length = NX_MSRP_TALKER_ADVERTISE_ATTRIBUTE_LENGTH + 4;
                *data_ptr++ = (UCHAR)attribute_list_length;
                tmp = (USHORT)(lva_event << 13 | num_of_value);
                *data_ptr++ = (UCHAR)(tmp >> 8);
                *data_ptr++ = (UCHAR)tmp;
                memset(data_ptr, 00, attribute_list_length);
                /* 4 = attribute_type + attribute_length_attribute_list_length.*/
                *length_ptr = (UINT)(attribute_list_length + 4);

                break;

            case NX_MSRP_TALKER_LISTENER_VECTOR:

                *data_ptr++ = NX_MSRP_TALKER_LISTENER_VECTOR;
                *data_ptr++ = NX_MSRP_LISTENER_ATTRIBUTE_LENGTH;
                *data_ptr++ = 0;
                attribute_list_length = NX_MSRP_LISTENER_ATTRIBUTE_LENGTH + 4;
                *data_ptr++ = (UCHAR)attribute_list_length;
                tmp = (USHORT)(lva_event << 13 | num_of_value);
                *data_ptr++ = (UCHAR)(tmp >> 8);
                *data_ptr++ = (UCHAR)tmp;
                memset(data_ptr, 00, attribute_list_length);
                *length_ptr = (UINT)(attribute_list_length + 4);     // 4 = attribute_type + attribute_length_attribute_list_length
                break;

            case NX_MSRP_TALKER_DOMAIN_VECTOR:

                *data_ptr++ = NX_MSRP_TALKER_DOMAIN_VECTOR;
                *data_ptr++ = NX_MSRP_DOMAIN_ATTRIBUTE_LENGTH;
                *data_ptr++ = 0;
                attribute_list_length = NX_MSRP_DOMAIN_ATTRIBUTE_LENGTH + 4;
                *data_ptr++ = (UCHAR)attribute_list_length;
                tmp = (USHORT)(lva_event << 13 | num_of_value);
                *data_ptr++ = (UCHAR)(tmp >> 8);
                *data_ptr++ = (UCHAR)tmp;
                memset(data_ptr, 00, attribute_list_length);
                *length_ptr = (UINT)(attribute_list_length + 4);     // 4 = attribute_type + attribute_length_attribute_list_length

                break;
            case NX_MSRP_TALKER_FAILED_VECTOR:
            default:
                break;
            }

            return(NX_MSRP_SUCCESS);
        }
    }

    /* Fill packet content next.*/
    if (num_of_value % 3)
    {
        num_of_threepacked = (UINT)(num_of_value / 3 + 1);

        num_of_fourpacked = (UINT)(num_of_value / 3 + 1);
    }
    else
    {

        num_of_threepacked = (UINT)(num_of_value / 3);

        num_of_fourpacked = (UINT)(num_of_value / 4);
    }

    /*ThreePackedEvents BYTE ::= (((((AttributeEvent) *6) + AttributeEvent) *6) + AttributeEvent)*/
    for (i = 0; i < num_of_threepacked; i++)
    {

        threepacked_value[i++] = (UCHAR)(((((threepacked_event[index]) * 6) + threepacked_event[index + 1]) * 6) + threepacked_event[index + 2]);

        index += 3;
    }

    switch (attribute -> attribute_type)
    {

    case NX_MSRP_TALKER_ADVERTISE_VECTOR:

        *data_ptr++ = NX_MSRP_TALKER_ADVERTISE_VECTOR;
        *data_ptr++ = NX_MSRP_TALKER_ADVERTISE_ATTRIBUTE_LENGTH;
        *data_ptr++ = 0;

        /* 4 = vectorhead + endmark*/
        attribute_list_length = (USHORT)(NX_MSRP_TALKER_ADVERTISE_ATTRIBUTE_LENGTH + 4 + num_of_threepacked);
        *data_ptr++ = (UCHAR)attribute_list_length;
        tmp = (USHORT)(lva_event << 13 | num_of_value);
        *data_ptr++ = (UCHAR)(tmp >> 8);
        *data_ptr++ = (UCHAR)tmp;

        memcpy(data_ptr,  ((NX_MSRP_ATTRIBUTE *)attribute) -> msrp_attribute_union.talker_advertise.stream_id,
               sizeof(NX_MSRP_TALKER_ADVERTISE)); /* use case of memcpy is verified. */

        /* Fix the above copy endian 14 = stream_id + dest_addr*/
        *(data_ptr + 14) = (UCHAR)(((NX_MSRP_ATTRIBUTE *)attribute) -> msrp_attribute_union.talker_advertise.vlan_identifier >> 8);

        *(data_ptr + 15) = (UCHAR)(((NX_MSRP_ATTRIBUTE *)attribute) -> msrp_attribute_union.talker_advertise.vlan_identifier);

        for (i = 0; i < num_of_threepacked; i++)
        {
            *(data_ptr + sizeof(NX_MSRP_TALKER_ADVERTISE) + i) = threepacked_value[i];
        }

        /* Endmark*/
        (*(data_ptr + sizeof(NX_MSRP_TALKER_ADVERTISE) + num_of_threepacked)) = 0;

        (*(data_ptr + sizeof(NX_MSRP_TALKER_ADVERTISE) + num_of_threepacked + 1)) = 0;

        *length_ptr = (UINT)(attribute_list_length + 4);

        break;

    case NX_MSRP_TALKER_LISTENER_VECTOR:

        index = 0;

        /* FourPackedEvents BYTE ::= ((FourPackedType *64) + (FourPackedType *16)+ (FourPackedType *4) + FourPackedType)*/
        for (i = 0; i < num_of_fourpacked; i++)
        {

            fourpacked_value[i++] = (UCHAR)((fourpacked_event[index] * 64) + (fourpacked_event[index + 1] * 16) +
                                            (fourpacked_event[index + 2] * 4) + fourpacked_event[index + 3]);

            index += 4;
        }
        *data_ptr++ = NX_MSRP_TALKER_LISTENER_VECTOR;
        *data_ptr++ = NX_MSRP_LISTENER_ATTRIBUTE_LENGTH;
        *data_ptr++ = 0;
        attribute_list_length = (USHORT)(NX_MSRP_LISTENER_ATTRIBUTE_LENGTH + 4 + num_of_threepacked + num_of_fourpacked);
        *data_ptr++ = (UCHAR)attribute_list_length;
        tmp = (USHORT)(lva_event << 13 | num_of_value);
        *data_ptr++ = (UCHAR)(tmp >> 8);
        *data_ptr++ = (UCHAR)tmp;

        memcpy(data_ptr, ((NX_MSRP_ATTRIBUTE *)attribute) -> msrp_attribute_union.listener.stream_id,
               STREAM_ID_SIZE); /* use case of memcpy is verified. */

        for (i = 0; i < num_of_threepacked; i++)
        {
            *(data_ptr + STREAM_ID_SIZE + i) = threepacked_value[i];
        }

        for (i = 0; i < num_of_fourpacked; i++)
        {
            *(data_ptr + STREAM_ID_SIZE + num_of_threepacked  + i) = fourpacked_value[i];
        }

        /* Endmark*/
        (*(data_ptr + STREAM_ID_SIZE + num_of_threepacked + num_of_fourpacked)) = 0;

        (*(data_ptr + STREAM_ID_SIZE + num_of_threepacked + num_of_fourpacked + 1)) = 0;

        /* 4 = attribute_type + attribute_length_attribute_list_length*/
        *length_ptr = (UINT)(attribute_list_length + 4);

        break;

    case NX_MSRP_TALKER_DOMAIN_VECTOR:

        *data_ptr++ = NX_MSRP_TALKER_DOMAIN_VECTOR;
        *data_ptr++ = NX_MSRP_DOMAIN_ATTRIBUTE_LENGTH;
        *data_ptr++ = 0;
        attribute_list_length = (USHORT)(NX_MSRP_DOMAIN_ATTRIBUTE_LENGTH + 4 + num_of_threepacked);
        *data_ptr++ = (UCHAR)attribute_list_length;
        tmp = (USHORT)((lva_event) << 13 | num_of_value);
        *data_ptr++ = (UCHAR)(tmp >> 8);
        *data_ptr++ = (UCHAR)tmp;

        *data_ptr = ((NX_MSRP_ATTRIBUTE *)attribute) -> msrp_attribute_union.domain.sr_class_id;
        *(data_ptr + 1) = ((NX_MSRP_ATTRIBUTE *)attribute) -> msrp_attribute_union.domain.sr_class_priority;
        *(data_ptr + 2) = (UCHAR)(((NX_MSRP_ATTRIBUTE *)attribute) -> msrp_attribute_union.domain.sr_class_vid >> 8);
        *(data_ptr + 3) = (UCHAR)(((NX_MSRP_ATTRIBUTE *)attribute) -> msrp_attribute_union.domain.sr_class_vid);

        for (i = 0; i < num_of_threepacked; i++)
        {
            *(data_ptr + sizeof(NX_MSRP_DOMAIN) + i) = threepacked_value[i];
        }

        /* Endmark*/
        (*(data_ptr + sizeof(NX_MSRP_DOMAIN) + num_of_threepacked)) = 0;
        (*(data_ptr + sizeof(NX_MSRP_DOMAIN) + num_of_threepacked + 1)) = 0;

        /* 4 = attribute_type + attribute_length_attribute_list_length*/
        *length_ptr = (UINT)(attribute_list_length + 4);

        break;

    case NX_MSRP_TALKER_FAILED_VECTOR:
    default:

        return(NX_MSRP_ATTRIBUTE_TYPE_ERROR);
        break;
    }

    return(NX_MSRP_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_msrp_mrpdu_pack                                  PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wen Wang,  Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function pack MRP data unit.                                   */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp                                   MRP instance pointer          */
/*    participant                           MRP participant               */
/*    packet_ptr                            Packet pointer                */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_packet_data_append                 Append data into packet       */
/*    nx_msrp_mrpdu_pack_attribute          Pack MSRP attribute           */
/*    nx_mrp_attribute_event_get            Get MRP attribute mrp_event   */
/*                                                                        */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_mrp_join_timeout_process           MRP join timer timeout process*/
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023        Wen Wang              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_msrp_mrpdu_pack(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_PACKET *packet_ptr)
{

UCHAR            *data_ptr = packet_ptr -> nx_packet_prepend_ptr;
UINT              data_length = 0;
UINT              status;
NX_MRP_ATTRIBUTE *attribute = participant -> inused_head;
NX_MRP_ATTRIBUTE *attribute_start;
UCHAR            *id[NX_MSRP_ATTRIBUTE_ARRAY_MAX_SIZE];
UCHAR             threepacked_event[NX_MSRP_ATTRIBUTE_ARRAY_MAX_SIZE];
UCHAR             fourpacked_event[NX_MSRP_ATTRIBUTE_ARRAY_MAX_SIZE];
UCHAR             index = 0;
USHORT            num_of_value = 0;

    if (attribute -> attribute_type == 0)
    {
        return(NX_MSRP_ATTRIBUTE_TYPE_ERROR);
    }

    memset(threepacked_event, 0, sizeof(threepacked_event));

    *data_ptr = NX_MRP_MSRP_PROTOCOL_VERSION;

    data_length = 1;

    status = nx_packet_data_append(packet_ptr, data_ptr, data_length, mrp -> pkt_pool, NX_NO_WAIT);

    if (status)
    {
        return(status);
    }

    data_ptr++;

    /*Look up talkeradvertise attribute to pack*/
    while (attribute &&  attribute -> attribute_type == NX_MSRP_TALKER_ADVERTISE_VECTOR)
    {

        if ((attribute -> applicant.action == NX_MRP_ACTION_NULL) || (attribute -> applicant.action > NX_MRP_ACTION_S_OPT))
        {
            /* If lva action is needed, send lva attribute anyway.*/
            if (participant -> leaveall.action == NX_MRP_ACTION_SLA)
            {

                status = nx_msrp_mrpdu_pack_attribute(participant, attribute, num_of_value, threepacked_event, fourpacked_event, data_ptr, &data_length);

                if (status)
                {
                    return(status);
                }

                status = nx_packet_data_append(packet_ptr, data_ptr, data_length, mrp -> pkt_pool, NX_NO_WAIT);

                if (status)
                {
                    return(status);
                }

                data_ptr = data_ptr + data_length;
            }

            attribute = attribute -> next;

            continue;
        }

        attribute_start = attribute;

        nx_mrp_attribute_event_get(attribute, &threepacked_event[0]);

        id[0] = ((NX_MSRP_ATTRIBUTE *)attribute) -> msrp_attribute_union.talker_advertise.stream_id;


        num_of_value = 1;
        index = 1;


        if (attribute -> next == NX_NULL || attribute -> next -> attribute_type != NX_MSRP_TALKER_ADVERTISE_VECTOR)
        {

            status = nx_msrp_mrpdu_pack_attribute(participant, attribute_start, num_of_value, threepacked_event, fourpacked_event, data_ptr, &data_length);

            if (status)
            {
                return(status);
            }

            status = nx_packet_data_append(packet_ptr, data_ptr, data_length, mrp -> pkt_pool, NX_NO_WAIT);

            if (status)
            {
                return(status);
            }

            data_ptr = data_ptr + data_length;

            attribute = attribute -> next;

            break;
        }

        /* Continue looking up talkeradvertise attribute to pack.*/
        while ((attribute = attribute -> next)  && (attribute -> attribute_type == NX_MSRP_TALKER_ADVERTISE_VECTOR))
        {

            if ((attribute -> applicant.action == NX_MRP_ACTION_NULL) || (attribute -> applicant.action > NX_MRP_ACTION_SLA))
            {
                /* If lva action is needed, send lva attribute anyway.*/
                if (participant -> leaveall.action == NX_MRP_ACTION_SLA)
                {
                    /* Need to check the paramter attribute_start or attribute*/
                    status = nx_msrp_mrpdu_pack_attribute(participant, attribute, num_of_value, threepacked_event, fourpacked_event, data_ptr, &data_length);

                    if (status)
                    {
                        return(status);
                    }

                    status = nx_packet_data_append(packet_ptr, data_ptr, data_length, mrp -> pkt_pool, NX_NO_WAIT);

                    if (status)
                    {
                        return(status);
                    }

                    data_ptr = data_ptr + data_length;
                }

                continue;
            }

            id[index] = ((NX_MSRP_ATTRIBUTE *)attribute) -> msrp_attribute_union.talker_advertise.stream_id;

            nx_mrp_attribute_event_get(attribute, &threepacked_event[index]);

            if (memcmp(id[index], id[index - 1], 8) == 1)
            {

                num_of_value++;
                index++;

                continue;
            }
            else
            {

                status = nx_msrp_mrpdu_pack_attribute(participant, attribute_start, num_of_value, threepacked_event, fourpacked_event, data_ptr, &data_length);

                if (status)
                {
                    return(status);
                }

                status = nx_packet_data_append(packet_ptr, data_ptr, data_length, mrp -> pkt_pool, NX_NO_WAIT);

                if (status)
                {
                    return(status);
                }

                data_ptr = data_ptr + data_length;


                break;
            }
        }
    }

    /*Look up listener attribute to pack*/
    while (attribute && attribute -> attribute_type == NX_MSRP_TALKER_LISTENER_VECTOR)
    {

        if ((attribute -> applicant.action == NX_MRP_ACTION_NULL) || (attribute -> applicant.action > NX_MRP_ACTION_SLA))
        {
            /* If lva action is needed, send lva attribute anyway.*/
            if (participant -> leaveall.action == NX_MRP_ACTION_SLA)
            {

                status = nx_msrp_mrpdu_pack_attribute(participant, attribute, num_of_value, threepacked_event, fourpacked_event, data_ptr, &data_length);

                if (status)
                {
                    return(status);
                }

                status = nx_packet_data_append(packet_ptr, data_ptr, data_length, mrp -> pkt_pool, NX_NO_WAIT);

                if (status)
                {
                    return(status);
                }

                data_ptr = data_ptr + data_length;
            }

            attribute = attribute -> next;

            continue;
        }

        attribute_start = attribute;

        nx_mrp_attribute_event_get(attribute, &threepacked_event[0]);

        fourpacked_event[0] = ((NX_MSRP_ATTRIBUTE *)attribute) -> msrp_attribute_union.listener.fourpacked_event;

        id[0] = ((NX_MSRP_ATTRIBUTE *)attribute) -> msrp_attribute_union.listener.stream_id;

        num_of_value = 1;

        index = 1;

        if (attribute -> next == NX_NULL || attribute -> next -> attribute_type != NX_MSRP_TALKER_LISTENER_VECTOR)
        {

            status = nx_msrp_mrpdu_pack_attribute(participant, attribute_start, num_of_value, threepacked_event, fourpacked_event, data_ptr, &data_length);

            if (status)
            {
                return(status);
            }

            status = nx_packet_data_append(packet_ptr, data_ptr, data_length, mrp -> pkt_pool, NX_NO_WAIT);

            if (status)
            {
                return(status);
            }

            data_ptr = data_ptr + data_length;

            attribute = attribute -> next;

            break;
        }
        /* Continue looking up listener attribute to pack.*/
        while ((attribute = attribute -> next)  && (attribute -> attribute_type == NX_MSRP_TALKER_LISTENER_VECTOR))
        {

            if ((attribute -> applicant.action == NX_MRP_ACTION_NULL) || (attribute -> applicant.action > NX_MRP_ACTION_SLA))
            {

                /* If lva action is needed, send lva attribute anyway.*/
                if (participant -> leaveall.action == NX_MRP_ACTION_SLA)
                {

                    status = nx_msrp_mrpdu_pack_attribute(participant, attribute, num_of_value, threepacked_event, fourpacked_event, data_ptr, &data_length);

                    if (status)
                    {
                        return(status);
                    }

                    status = nx_packet_data_append(packet_ptr, data_ptr, data_length, mrp -> pkt_pool, NX_NO_WAIT);

                    if (status)
                    {
                        return(status);
                    }

                    data_ptr = data_ptr + data_length;
                }
                continue;
            }

            id[index] = ((NX_MSRP_ATTRIBUTE *)attribute) -> msrp_attribute_union.listener.stream_id;

            fourpacked_event[index] = ((NX_MSRP_ATTRIBUTE *)attribute) -> msrp_attribute_union.listener.fourpacked_event;

            nx_mrp_attribute_event_get(attribute, &threepacked_event[index]);

            if (memcmp(id[index], id[index - 1], 8) == 1)
            {

                num_of_value++;
                index++;

                continue;
            }
            else
            {

                status = nx_msrp_mrpdu_pack_attribute(participant, attribute_start, num_of_value, threepacked_event, fourpacked_event, data_ptr, &data_length);

                if (status)
                {
                    return(status);
                }

                status = nx_packet_data_append(packet_ptr, data_ptr, data_length, mrp -> pkt_pool, NX_NO_WAIT);

                if (status)
                {
                    return(status);
                }

                data_ptr = data_ptr + data_length;

                break;
            }
        }
    }

    /*Look up domain attribute to pack*/
    while (attribute && attribute -> attribute_type == NX_MSRP_TALKER_DOMAIN_VECTOR)
    {

        if ((attribute -> applicant.action == NX_MRP_ACTION_NULL) || (attribute -> applicant.action > NX_MRP_ACTION_SLA))
        {
            /* If lva action is needed, send lva attribute anyway.*/
            if (participant -> leaveall.action == NX_MRP_ACTION_SLA)
            {

                status = nx_msrp_mrpdu_pack_attribute(participant, attribute, num_of_value, threepacked_event, fourpacked_event, data_ptr, &data_length);

                if (status)
                {
                    return(status);
                }

                status = nx_packet_data_append(packet_ptr, data_ptr, data_length, mrp -> pkt_pool, NX_NO_WAIT);

                if (status)
                {
                    return(status);
                }

                data_ptr = data_ptr + data_length;
            }

            attribute = attribute -> next;

            continue;
        }

        attribute_start = attribute;

        nx_mrp_attribute_event_get(attribute, &threepacked_event[0]);

        id[0] = &((NX_MSRP_ATTRIBUTE *)attribute) -> msrp_attribute_union.domain.sr_class_id;

        num_of_value = 1;
        index = 1;

        if (attribute -> next == NX_NULL)
        {

            status = nx_msrp_mrpdu_pack_attribute(participant, attribute_start, num_of_value, threepacked_event, fourpacked_event, data_ptr, &data_length);

            if (status)
            {
                return(status);
            }

            status = nx_packet_data_append(packet_ptr, data_ptr, data_length, mrp -> pkt_pool, NX_NO_WAIT);

            if (status)
            {
                return(status);
            }

            data_ptr = data_ptr + data_length;

            attribute = attribute -> next;

            break;
        }
        /* Continue looking up domain attribute to pack.*/
        while ((attribute = attribute -> next)  && (attribute -> attribute_type == NX_MSRP_TALKER_DOMAIN_VECTOR))
        {

            if ((attribute -> applicant.action == NX_MRP_ACTION_NULL) || (attribute -> applicant.action > NX_MRP_ACTION_SLA))
            {
                /* If lva action is needed, send lva attribute anyway.*/
                if (participant -> leaveall.action == NX_MRP_ACTION_SLA)
                {

                    status = nx_msrp_mrpdu_pack_attribute(participant, attribute, num_of_value, threepacked_event, fourpacked_event, data_ptr, &data_length);

                    if (status)
                    {
                        return(status);
                    }

                    status = nx_packet_data_append(packet_ptr, data_ptr, data_length, mrp -> pkt_pool, NX_NO_WAIT);

                    if (status)
                    {
                        return(status);
                    }

                    data_ptr = data_ptr + data_length;
                }

                continue;
            }

            id[index] = &((NX_MSRP_ATTRIBUTE *)attribute) -> msrp_attribute_union.domain.sr_class_id;

            nx_mrp_attribute_event_get(attribute, &threepacked_event[index]);

            if (memcmp(id[index], id[index - 1], 1) == 1)
            {

                num_of_value++;
                index++;

                continue;
            }
            else
            {

                status = nx_msrp_mrpdu_pack_attribute(participant, attribute_start, num_of_value, threepacked_event, fourpacked_event, data_ptr, &data_length);

                if (status)
                {
                    return(status);
                }

                status = nx_packet_data_append(packet_ptr, data_ptr, data_length, mrp -> pkt_pool, NX_NO_WAIT);

                if (status)
                {
                    return(status);
                }

                data_ptr = data_ptr + data_length;

                break;
            }
        }
    }

    /* No attribute needs to be send.*/
    if (packet_ptr -> nx_packet_length == 1)
    {
        packet_ptr -> nx_packet_length = 0;

        return NX_MSRP_WAIT;
    }
    else
    {
        /* Add endmark*/
        *data_ptr = 0;
        *(data_ptr + 1) = 0;

        data_length = 2;

        status = nx_packet_data_append(packet_ptr, data_ptr, data_length, mrp -> pkt_pool, NX_NO_WAIT);

        if (status)
        {
            return(status);
        }
    }

    return(status);
}
#endif /* NX_ENABLE_VLAN */

