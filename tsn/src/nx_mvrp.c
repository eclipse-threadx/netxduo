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
/**   Multiple VLAN Registration Protocol (MVRP)                          */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

/* Include necessary system files.  */
#include "nx_mvrp.h"

#ifdef NX_ENABLE_VLAN
NX_MVRP_ATTRIBUTE mvrp_attribute_array[NX_MVRP_ATTRIBUTE_ARRAY_MAX_SIZE];

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_mvrp_indication_process                          PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function process the MVRP indication.                          */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp                                   MRP instance                  */
/*    participant                           MRP participant               */
/*    attribute                             MRP attribute                 */
/*    indication_type                       Indication type               */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_mvrp_action_request                MVRP action request           */
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
UINT nx_mvrp_indication_process(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_MRP_ATTRIBUTE *attribute, UCHAR indication_type)
{
UINT   status;
USHORT vlan_id;
NX_MVRP *mvrp = (NX_MVRP *)participant;

    NX_PARAMETER_NOT_USED(mrp);
    if (mvrp -> mvrp_event_callback)
    {
        status = mvrp -> mvrp_event_callback(participant, attribute, indication_type, NX_NULL);
        if (status != NX_SUCCESS)
        {
            return(status);
        }
    }

    vlan_id = ((NX_MVRP_ATTRIBUTE *)attribute) -> vlan_id;
    status = nx_mvrp_action_request(mrp, participant, vlan_id, indication_type);

    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_mvrp_mrpdu_unpack                                PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function unpack the MVRP message.                              */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp                                   MRP instance                  */
/*    participant                           MRP participant               */
/*    packet_ptr                            MRP packet                    */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_mvrp_attribute_get                 Get MVRP attribute            */
/*    nx_mrp_event_process                  Process MRP event             */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Internal Function                                                   */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_mvrp_mrpdu_unpack(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_PACKET *packet_ptr)
{
UINT              status;
NX_MRP_ATTRIBUTE *attribute = NX_NULL;
UCHAR             attribute_type;
UCHAR             attribute_len;
UCHAR            *data_ptr = packet_ptr -> nx_packet_prepend_ptr;
UCHAR            *end = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;
UCHAR            *attribute_list_end;
USHORT            vector_header;
USHORT            leave_all_event;
USHORT            number_of_values;
USHORT            vlan_id;
USHORT            event_cycle_cnt;
USHORT            i;
UCHAR             three_packed_event, first_event, second_event, third_event;

    if (*data_ptr++ != NX_MRP_MVRP_PROTOCOL_VERSION)
    {
        return(NX_INVALID_PARAMETERS);
    }

    end = end - NX_MVRP_ATTRIBUTE_END_MARK_SIZE;

    /* Message loop */
    while (data_ptr < end)
    {
        /* Attribute start */
        attribute_type = *data_ptr++;
        if (attribute_type != NX_MVRP_ATTRIBUTE_TYPE_VLAN_ID)
        {
            return(NX_INVALID_PACKET);
        }

        attribute_len = *data_ptr++;
        if (attribute_len != NX_MVRP_ATTRIBUTE_LENGTH_VLAN_ID)
        {
            return(NX_INVALID_PACKET);
        }

        attribute_list_end = end - NX_MVRP_ATTRIBUTE_END_MARK_SIZE;

        /* Vector attribute loop */
        while (data_ptr < attribute_list_end)
        {
            vector_header = (USHORT)*data_ptr++;
            vector_header = (USHORT)(vector_header << 8);
            vector_header |= (USHORT)*data_ptr++;

            /* no need to process the case of vector header is 0 */
            if (vector_header == 0)
            {
                return(NX_SUCCESS);
            }

            leave_all_event = vector_header >> 13;
            number_of_values = vector_header & 0x1fff;

            /* First Value */
            vlan_id = (USHORT)*data_ptr++;
            vlan_id = (USHORT)(vlan_id << 8);
            vlan_id |= (USHORT)*data_ptr++;

            event_cycle_cnt = (number_of_values % 3 == 0) ? 0 : 1;
            event_cycle_cnt = (USHORT)(event_cycle_cnt + number_of_values / 3);

            if (data_ptr + event_cycle_cnt >= attribute_list_end)
            {
                return(NX_PACKET_OFFSET_ERROR);
            }

            /* Attribite event loop */
            for (i = 0; i < event_cycle_cnt; i++)
            {
                /* ThreePackedEvents BYTE ::= (((((AttributeEvent_first) *6) + AttributeEvent_second) *6) + AttributeEvent_third) */
                three_packed_event = *data_ptr++;
                third_event = three_packed_event % 6;
                second_event = (UCHAR)((three_packed_event - third_event) / 6) % 6;
                first_event = (UCHAR)((three_packed_event - third_event) / 6 - second_event) / 6;

                /* Get the first vlan id with event */
                if (number_of_values > 0)
                {
                    status = nx_mvrp_attribute_get(mrp, participant, &attribute, vlan_id);
                    if (status != NX_SUCCESS)
                    {
                        return(NX_NOT_SUCCESSFUL);
                    }

                    if (leave_all_event)
                    {
                        nx_mrp_event_process(mrp, participant, attribute, NX_MRP_EVENT_RLA);
                    }
                    else
                    {
                        nx_mrp_event_process(mrp, participant, attribute, first_event);
                    }
                    number_of_values--;
                    vlan_id++;
                }
                else
                {
                    return(NX_INVALID_PACKET);
                }

                /* Get the second vlan id with event */
                if (number_of_values > 0)
                {
                    status = nx_mvrp_attribute_get(mrp, participant, &attribute, vlan_id);
                    if (status != NX_SUCCESS)
                    {
                        return(NX_NOT_SUCCESSFUL);
                    }

                    if (leave_all_event)
                    {
                        nx_mrp_event_process(mrp, participant, attribute, NX_MRP_EVENT_RLA);
                    }
                    else
                    {
                        nx_mrp_event_process(mrp, participant, attribute, second_event);
                    }
                    number_of_values--;
                    vlan_id++;
                }

                /* Get the third vlan id with event */
                if (number_of_values > 0)
                {
                    status = nx_mvrp_attribute_get(mrp, participant, &attribute, vlan_id);
                    if (status != NX_SUCCESS)
                    {
                        return(NX_NOT_SUCCESSFUL);
                    }

                    if (leave_all_event)
                    {
                        nx_mrp_event_process(mrp, participant, attribute, NX_MRP_EVENT_RLA);
                    }
                    else
                    {
                        nx_mrp_event_process(mrp, participant, attribute, third_event);
                    }
                    number_of_values--;
                    vlan_id++;
                }
            }
        }
        data_ptr += NX_MVRP_ATTRIBUTE_END_MARK_SIZE;
    }

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_mvrp_mrpdu_pack                                  PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function pack the MVRP message.                                */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp                                   MRP instance                  */
/*    participant                           MRP participant               */
/*    packet_ptr                            MRP packet                    */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_mrp_attribute_event_get            Get MRP attribute event       */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Internal Function                                                   */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_mvrp_mrpdu_pack(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_PACKET *packet_ptr)
{
NX_MRP_ATTRIBUTE *attribute = participant -> inused_head;
NX_MRP_ATTRIBUTE *vector_attribute;
UCHAR            *data_ptr = packet_ptr -> nx_packet_prepend_ptr;
USHORT            leave_all_event;
USHORT            number_of_values = 0;
UCHAR             attribute_find = NX_FALSE;
USHORT            vector_header;
USHORT            first_value, vlan_id;
USHORT            event_cycle_cnt;
UCHAR             three_packed_event, first_event, second_event, third_event;
USHORT            i;

    NX_PARAMETER_NOT_USED(mrp);
    /* Encaps the protocol version */
    *data_ptr++ = NX_MRP_MVRP_PROTOCOL_VERSION;

    /* Message start */
    /* Attribute type */
    *data_ptr++ = NX_MVRP_ATTRIBUTE_TYPE_VLAN_ID;

    /* Attribute length */
    *data_ptr++ = NX_MVRP_ATTRIBUTE_LENGTH_VLAN_ID;

    /* Attribute list */
    while (attribute)
    {
        if (attribute -> applicant.action == NX_MRP_ACTION_NULL)
        {
            attribute = attribute -> next;
            continue;
        }

        if (participant -> leaveall.action == NX_MRP_ACTION_SLA)
        {
            leave_all_event = NX_TRUE;
        }

        /* Get the first value */
        first_value = ((NX_MVRP_ATTRIBUTE *)attribute) -> vlan_id;
        vlan_id = (USHORT)(first_value + 1);
        vector_attribute = attribute -> next;
        number_of_values = 1;
        attribute_find = NX_TRUE;
        while (vector_attribute)
        {
            if (((NX_MVRP_ATTRIBUTE *)vector_attribute) -> vlan_id == vlan_id)
            {
                if (attribute -> applicant.action == NX_MRP_ACTION_NULL)
                {
                    vector_attribute = vector_attribute -> next;
                    break;
                }
                number_of_values++;
                vlan_id++;
                vector_attribute = vector_attribute -> next;
                continue;
            }
            else
            {
                break;
            }
        }

        vector_header = (USHORT)(leave_all_event << 13);
        vector_header = (USHORT)(vector_header | number_of_values);

        /* Vector header */
        *data_ptr++ = (UCHAR)(vector_header >> 8);
        *data_ptr++ = (UCHAR)(vector_header & 0xff);

        /* First Value */
        *data_ptr++ = (UCHAR)(first_value >> 8);
        *data_ptr++ = (UCHAR)(first_value & 0xff);

        /* Attribute event */
        event_cycle_cnt = (number_of_values % 3 == 0) ? 0 : 1;
        event_cycle_cnt = (USHORT)(event_cycle_cnt + number_of_values / 3);

        for (i = 0; i < event_cycle_cnt; i++)
        {
            nx_mrp_attribute_event_get(attribute, &first_event);
            attribute = attribute -> next;
            number_of_values--;

            if (number_of_values == 0)
            {
                second_event = 0;
                third_event = 0;
            }
            else
            {
                nx_mrp_attribute_event_get(attribute, &second_event);
                attribute = attribute -> next;
                number_of_values--;

                if (number_of_values == 0)
                {
                    third_event = 0;
                }
                else
                {
                    nx_mrp_attribute_event_get(attribute, &third_event);
                    attribute = attribute -> next;
                    number_of_values--;
                }
            }

            /* ThreePackedEvents BYTE ::= (((((AttributeEvent_first) *6) + AttributeEvent_second) *6) + AttributeEvent_third) */
            three_packed_event = (UCHAR)(first_event * 6);
            three_packed_event = (UCHAR)(three_packed_event + second_event);
            three_packed_event = (UCHAR)(three_packed_event * 6);
            three_packed_event = (UCHAR)(three_packed_event + third_event);

            *data_ptr++ = three_packed_event;
        }
    }

    if (attribute_find == NX_FALSE)
    {
        return(NX_NOT_FOUND);
    }

    /* Attribute list end (add the end mark) */
    *data_ptr++ = 0;
    *data_ptr++ = 0;

    /* Message end (add the end mark) */
    *data_ptr++ = 0;
    *data_ptr++ = 0;

    packet_ptr -> nx_packet_append_ptr = data_ptr;
    packet_ptr -> nx_packet_length = (ULONG)(packet_ptr -> nx_packet_append_ptr - packet_ptr -> nx_packet_prepend_ptr);
    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_mvrp_attribute_find                              PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function find the MVRP attribute.                              */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp                                   MRP instance                  */
/*    participant                           MRP participant               */
/*    attribute_ptr                         MRP attribute                 */
/*    vlan_id                               VLAN ID                       */
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
/*    Internal Function                                                   */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_mvrp_attribute_find(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_MRP_ATTRIBUTE **attribute_ptr, USHORT vlan_id)
{
NX_MRP_ATTRIBUTE  *attribute;
NX_MVRP_ATTRIBUTE *mvrp_attribute;

    NX_PARAMETER_NOT_USED(mrp);
    attribute = participant -> inused_head;

    while (attribute != NX_NULL)
    {
        mvrp_attribute = (NX_MVRP_ATTRIBUTE *)attribute;
        if (mvrp_attribute -> vlan_id == vlan_id)
        {
            *attribute_ptr = attribute;
            return(NX_SUCCESS);
        }

        if (mvrp_attribute -> vlan_id > vlan_id)
        {
            /* The vlan id is not found */
            break;
        }
        attribute = attribute -> next;
    }

    return(NX_NOT_SUCCESSFUL);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_mvrp_attribute_insert                            PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function insert the MVRP attribute into attribute list.        */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp                                   MRP instance                  */
/*    participant                           MRP participant               */
/*    attribute                             MRP attribute                 */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_mvrp_attribute_get                 MVRP attribute get            */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
void nx_mvrp_attribute_insert(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_MRP_ATTRIBUTE *attribute)
{
NX_MRP_ATTRIBUTE *tmp_attribute;
USHORT            vlan_id = ((NX_MVRP_ATTRIBUTE *)attribute) -> vlan_id;

    NX_PARAMETER_NOT_USED(mrp);
    tmp_attribute = participant -> inused_head;

    if (tmp_attribute == NX_NULL)
    {
        participant -> inused_head = attribute;
        attribute -> next = NX_NULL;
        attribute -> pre = NX_NULL;
        return;
    }

    while (tmp_attribute != NX_NULL)
    {
        if (((NX_MVRP_ATTRIBUTE *)tmp_attribute) -> vlan_id > vlan_id)
        {
            /* The node should be inserted into the head of the list */
            if (participant -> inused_head == tmp_attribute)
            {

                attribute -> next = tmp_attribute;
                attribute -> pre = NX_NULL;
                tmp_attribute -> pre = attribute;
                participant -> inused_head = attribute;
            }
            else
            {
                attribute -> next = tmp_attribute;
                attribute -> pre = tmp_attribute -> pre;
                tmp_attribute -> pre -> next = attribute;
                tmp_attribute -> pre = attribute;
            }
            return;
        }

        /* The node should be inserted into the tail of the list */
        if (tmp_attribute -> next == NX_NULL)
        {
            attribute -> next = NX_NULL;
            attribute -> pre = tmp_attribute;

            tmp_attribute -> next = attribute;

            return;
        }
        tmp_attribute = tmp_attribute -> next;
    }

    return;
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_mvrp_attribute_get                               PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function gets the MVRP attribute.                              */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp                                   MRP instance                  */
/*    participant                           MRP participant               */
/*    attribute_ptr                         MRP attribute                 */
/*    vlan_id                               VLAN ID                       */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_mvrp_attribute_find                Find MVRP attribute           */
/*    nx_mvrp_attribute_new                 New MVRP attribute            */
/*    nx_mvrp_attribute_insert              Insert MVRP attribute         */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_mvrp_action_request                MVRP action request           */
/*    nx_mvrp_mrpdu_unpack                  MVRP message unpack           */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_mvrp_attribute_get(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_MRP_ATTRIBUTE **attribute_ptr, USHORT vlan_id)
{
NX_MRP_ATTRIBUTE *attribute;
UINT              status;

    if ((mrp == NX_NULL) ||
        (participant == NX_NULL) ||
        (attribute_ptr == NX_NULL))
    {
        return(NX_INVALID_PARAMETERS);
    }

    status = nx_mvrp_attribute_find(mrp, participant, attribute_ptr, vlan_id);
    if (status == NX_SUCCESS)
    {
        return(status);
    }

    /* no attribute find, new an attribute */
    attribute = nx_mrp_attribute_new(mrp, participant, (NX_MRP_ATTRIBUTE *)mvrp_attribute_array,
                                     sizeof(struct NX_MVRP_ATTRIBUTE_STRUCT), NX_MVRP_ATTRIBUTE_ARRAY_MAX_SIZE);

    if (attribute == NX_NULL)
    {
        return(NX_NO_MORE_ENTRIES);
    }

    attribute -> attribute_type = NX_MVRP_ATTRIBUTE_TYPE_VLAN_ID;
    ((NX_MVRP_ATTRIBUTE *)attribute) -> vlan_id = vlan_id;

    nx_mvrp_attribute_insert(mrp, participant, attribute);

    *attribute_ptr = attribute;

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_mvrp_action_request                              PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function is used for requesting MVRP action.                   */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp                                   MRP instance                  */
/*    participant                           MRP participant               */
/*    vlan_id                               VLAN ID                       */
/*    action_type                           Action type                   */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_mvrp_attribute_get                 Get MVRP attribute            */
/*    nx_mrp_event_process                  Process MRP event             */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_mvrp_indication_process            MVRP indication process       */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_mvrp_action_request(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, USHORT vlan_id, UCHAR action_type)
{
NX_MRP_ATTRIBUTE *attribute = NX_NULL;
UINT              status;
UCHAR             mrp_event;

    /* Get mutex. */
    tx_mutex_get(&mrp -> mrp_mutex, NX_WAIT_FOREVER);

    status = nx_mvrp_attribute_get(mrp, participant, &attribute, vlan_id);

    if (status != NX_SUCCESS)
    {
        tx_mutex_put(&(mrp -> mrp_mutex));
        return(status);
    }

    switch (action_type)
    {
    case NX_MVRP_ACTION_NEW:
        mrp_event = NX_MRP_EVENT_NEW;
        break;

    case NX_MVRP_ACTION_TYPE_JOIN:
        mrp_event = NX_MRP_EVENT_JOIN;
        break;

    case NX_MVRP_ACTION_TYPE_LEAVE:
        mrp_event = NX_MRP_EVENT_LV;
        break;

    default:
        tx_mutex_put(&(mrp -> mrp_mutex));
        return(NX_INVALID_PARAMETERS);
    }

    status = nx_mrp_event_process(mrp, participant, attribute, mrp_event);

    /* Release the mutex.  */
    tx_mutex_put(&(mrp -> mrp_mutex));

    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_mvrp_init                                        PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function init the MVRP instance.                               */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mvrp_ptr                              MVRP instance                 */
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
/*    nx_srp_init                           SRP init                      */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_mvrp_init(NX_MVRP *mvrp_ptr)
{

    mvrp_ptr -> participant.participant_type = NX_MRP_PARTICIPANT_MVRP;
    mvrp_ptr -> participant.protocol_version = NX_MRP_MVRP_PROTOCOL_VERSION;
    mvrp_ptr -> participant.indication_function = nx_mvrp_indication_process;
    mvrp_ptr -> participant.unpack_function = nx_mvrp_mrpdu_unpack;
    mvrp_ptr -> participant.pack_function = nx_mvrp_mrpdu_pack;

    mvrp_ptr -> participant.join_timer = NX_MRP_TIMER_JOIN;
    mvrp_ptr -> participant.leaveall_timer = NX_MRP_TIMER_LEAVEALL;

    mvrp_ptr -> participant.inused_head = NX_NULL;
    mvrp_ptr -> participant.next = NX_NULL;

    return(NX_SUCCESS);
}
#endif /* NX_ENABLE_VLAN */
