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
/** NetX SRP Component                                                    */
/**                                                                       */
/**   Stream Reservation Protocol (SRP)                                   */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/
#include "nx_srp.h"
#include "nx_link.h"

#ifdef NX_ENABLE_VLAN

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_srp_init                                         PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wen Wang,  Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function initialize SRP, it initializes MRP, MSRP, MVRP        */
/*    sequencly, and create a thread in MRP initializaton.                */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    srp_ptr                               SRP instance pointer          */
/*    ip_ptr                                IP instance pointer           */
/*    interface_index                       Interface index               */
/*    pkt_pool_ptr                          Packet pool pointer           */
/*    stack_ptr                             Stack pointer                 */
/*    stack_size                            Stack size                    */
/*    priority                              SRP thread priority           */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_mrp_init                           MRP initialization            */
/*    nx_msrp_init                          MSRP initialization           */
/*    nx_mvrp_init                          MVRP initialization           */
/*    nx_mrp_participant_add                ADD mrp participant           */
/*    tx_mutex_put                          Put protection mutex          */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023        Wen Wang              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_srp_init(NX_SRP *srp_ptr, NX_IP *ip_ptr, UINT interface_index, NX_PACKET_POOL *pkt_pool_ptr,
                  VOID *stack_ptr, ULONG stack_size, UINT priority)
{
UINT status;

    status = nx_mrp_init(&srp_ptr -> nx_mrp, ip_ptr, interface_index, pkt_pool_ptr, "MRP thread",
                         stack_ptr, stack_size, priority);


    if (status)
    {
        return(status);
    }

    nx_msrp_init(&srp_ptr -> nx_msrp);

    nx_mrp_participant_add(&srp_ptr -> nx_mrp, &srp_ptr -> nx_msrp.nx_msrp_participant);

    nx_mvrp_init(&srp_ptr -> nx_mvrp);

    nx_mrp_participant_add(&srp_ptr -> nx_mrp, &srp_ptr -> nx_mvrp.participant);

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_srp_talker_start                                 PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wen Wang,  Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function start SRP talker, it sets event callback funtions and */
/*    register domain, Vlan, stream request.                              */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    srp_ptr                               SRP instance pointer          */
/*    domain                                Sream properties              */
/*    stream_id                             Stream ID                     */
/*    dst_addr                              Destination address           */
/*    max_frame_size                        Max frame size                */
/*    max_interval_frames                   Max frame interval            */
/*    event_callback                        Application callback          */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_msrp_register_domain_request       MSRP domain request register  */
/*    nx_mvrp_action_request                MVRP request new              */
/*    nx_msrp_register_stream_request       MSRP stream request register  */
/*    nx_link_multicast_join                Join link multicast           */
/*    nx_srp_talker_cbs_set                 Talker set CBS                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023        Wen Wang              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_srp_talker_start(NX_SRP *srp_ptr, NX_MSRP_DOMAIN *domain, UCHAR *stream_id, UCHAR *dst_addr,
                         UINT max_frame_size, UINT max_interval_frames, NX_MRP_EVENT_CALLBACK event_callback)
{
UINT                     status;
NX_MSRP_TALKER_ADVERTISE talker_advertise;
UINT                     index = NX_SRP_TALKER_NUM;
CHAR                     interface_name[32];
INT                      i;

    srp_ptr -> nx_msrp.msrp_event_callback = event_callback;

    srp_ptr -> nx_mvrp.mvrp_event_callback = event_callback;

    /*send register domain request*/
    status = nx_msrp_register_domain_request(&(srp_ptr -> nx_mrp), &(srp_ptr -> nx_msrp.nx_msrp_participant), domain, NX_MSRP_ACTION_NEW);

    if (status != NX_SUCCESS)
	{

        return(status);
	}

    srp_ptr -> nx_mvrp.mvrp_event_callback = event_callback;

    /*send vlan new request*/
    status = nx_mvrp_action_request(&(srp_ptr -> nx_mrp), &(srp_ptr -> nx_mvrp.participant), domain -> sr_class_vid, NX_MVRP_ACTION_NEW);
    if (status != NX_SUCCESS)
	{

        return(status);
	}

    memcpy(talker_advertise.stream_id, stream_id, 8); /* use case of memcpy is verified. */
    memcpy(talker_advertise.dest_addr, dst_addr, 6); /* use case of memcpy is verified. */
    talker_advertise.vlan_identifier = domain -> sr_class_vid;
    talker_advertise.max_frame_size = (USHORT)max_frame_size;
    talker_advertise.max_interval_frames = (USHORT)max_interval_frames;
    talker_advertise.priority = (UCHAR)(domain -> sr_class_priority & 0x07);
    talker_advertise.accumulated_latency = 0;

    /*send register stream request*/
    status = nx_msrp_register_stream_request(&(srp_ptr -> nx_mrp), &(srp_ptr -> nx_msrp.nx_msrp_participant), &talker_advertise, NX_MSRP_ACTION_NEW);

    if (status != NX_SUCCESS)
	{

        return(status);
	}

    for (i = 0; i < NX_SRP_TALKER_NUM; i++)
    {
        if (srp_ptr -> talker[i].in_used == NX_FALSE)
        {
            index = (UINT)i;
            srp_ptr -> talker[i].in_used = NX_TRUE;
            break;
        }
    }

    if (index == NX_SRP_TALKER_NUM)
    {
        printf("No resource to allocate for talker with stream ID:%s.\r\n", stream_id);
        return(NX_NO_MORE_ENTRIES);
    }

    if (domain -> sr_class_id == NX_SRP_SR_CLASS_A)
    {
        srp_ptr -> talker[index].interval = NX_SRP_CLASS_A_INTERVAL;
    }
    else if (domain -> sr_class_id == NX_SRP_SR_CLASS_B)
    {
        srp_ptr -> talker[index].interval = NX_SRP_CLASS_B_INTERVAL;
    }
    else
    {
        /* Do not support other kind of SR Class Currently. */
        return(NX_INVALID_PARAMETERS);
    }

    memcpy(srp_ptr -> talker[index].stream_id, stream_id, 8); /* use case of memcpy is verified. */
    srp_ptr -> talker[index].class_id = domain -> sr_class_id;
    srp_ptr -> talker[index].class_priority = domain -> sr_class_priority;
    srp_ptr -> talker[index].class_vid = domain -> sr_class_vid;
    srp_ptr -> talker[index].max_interval_frames =  max_interval_frames;
    srp_ptr -> talker[index].max_frame_size = max_frame_size;

    srp_ptr -> talker[index].physical_address_msw = (ULONG)dst_addr[0] << 8 | dst_addr[1];
    srp_ptr -> talker[index].physical_address_lsw = (ULONG)dst_addr[2] << 24 | \
                                                    (ULONG)dst_addr[3] << 16 | \
                                                    (ULONG)dst_addr[4] << 8 | \
                                                    (ULONG)dst_addr[5];

    sprintf(interface_name, "NetX IP Interface 0:%u", srp_ptr -> talker[index].class_vid);

    status = nx_link_multicast_join(srp_ptr -> nx_mrp.ip_ptr, srp_ptr -> nx_mrp.interface_index,
                                    srp_ptr -> talker[index].physical_address_msw,
                                    srp_ptr -> talker[index].physical_address_lsw);

    if (status != NX_SUCCESS)
	{
        return(status);
	}
    else
    {
        printf("[Talker]multicast address join %lx-%lx successful\r\n",
                srp_ptr -> talker[index].physical_address_msw,
                srp_ptr -> talker[index].physical_address_lsw);
    }

    status = nx_srp_talker_cbs_set(srp_ptr, index);
    if (status != NX_SUCCESS)
	{
        return(status);
	}
    else
    {
        printf("[Talker]CBS set successful\r\n");
    }

    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_srp_listener_start                               PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wen Wang,  Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function start SRP listener. It enables listener and set user  */
/*    date and callback function.                                         */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    srp_ptr                               SRP instance pointer          */
/*    event_callback                        Application callback          */
/*    stream_id                             Stream ID                     */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*   None                                                                 */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023        Wen Wang              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_srp_listener_start(NX_SRP *srp_ptr, NX_MRP_EVENT_CALLBACK event_callback, UCHAR *stream_id)
{
    /* Allowed to response to talker.*/
    srp_ptr -> nx_msrp.listener_enable = 1;

    srp_ptr -> nx_msrp.msrp_event_callback = event_callback;

    srp_ptr -> nx_mvrp.mvrp_event_callback = event_callback;

    /* Listener set the stream_id it will accept, it could be NX_NULL.*/
    srp_ptr -> nx_msrp.msrp_callback_data = stream_id;

    return(NX_MSRP_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_srp_talker_stop                                 PORTABLE C       */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wen Wang,  Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function stop SRP talker. It withdraw the domain,Vlan,stream   */
/*    request.                                                            */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    srp_ptr                               SRP instance pointer          */
/*    stream_id                             Stream ID                     */
/*    domain                                Stream properties             */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_msrp_deregister_domain_request     MSRP domain request deregister*/
/*    nx_mvrp_action_request                MVRP request leave            */
/*    nx_msrp_deregister_stream_request     MSRP stream request deregister*/
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023        Wen Wang              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_srp_talker_stop(NX_SRP *srp_ptr, UCHAR *stream_id, NX_MSRP_DOMAIN *domain)
{
UINT status;

    /* Send deregister domain request*/
    status = nx_msrp_deregister_domain_request(&srp_ptr -> nx_mrp, &srp_ptr -> nx_msrp.nx_msrp_participant, domain);

    if (status != NX_SUCCESS)
    {
        return(status);
    }

    /* Send vlan leave request*/
    status = nx_mvrp_action_request(&(srp_ptr -> nx_mrp), &(srp_ptr -> nx_mvrp.participant), domain -> sr_class_vid, NX_MVRP_ACTION_TYPE_LEAVE);

    if (status != NX_SUCCESS)
    {
        return(status);
    }

    /* Send deregister stream request*/
    status = nx_msrp_deregister_stream_request(&srp_ptr -> nx_mrp, &srp_ptr -> nx_msrp.nx_msrp_participant, stream_id);

    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_srp_listener_stop                                PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wen Wang,  Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function stop SRP listener. It unregister the domain,Vlan      */
/*    stream attached to talker.                                          */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    srp_ptr                               SRP instance pointer          */
/*    stream_id                             Stream ID                     */
/*    domain                                Stream properties             */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_msrp_deregister_domain_request     MSRP domain request deregister*/
/*    nx_mvrp_action_request                MVRP request leave            */
/*    nx_msrp_deregister_attach_request     MSRP stream attach deregister */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023        Wen Wang              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_srp_listener_stop(NX_SRP *srp_ptr, UCHAR *stream_id, NX_MSRP_DOMAIN *domain)
{
UINT status;

    if (stream_id == NX_NULL)
    {
        return(NX_SRP_PARAMETER_NULL);
    }

    if (domain == NX_NULL)
    {
        return(NX_SRP_PARAMETER_NULL);
    }

    /* Send deregister domain request.*/
    status = nx_msrp_deregister_domain_request(&srp_ptr -> nx_mrp, &srp_ptr -> nx_msrp.nx_msrp_participant, domain);

    if (status != NX_SUCCESS)
    {
        return(status);
    }

    /* Send vlan leave request.*/
    status = nx_mvrp_action_request(&(srp_ptr -> nx_mrp), &(srp_ptr -> nx_mvrp.participant), domain -> sr_class_vid, NX_MVRP_ACTION_TYPE_LEAVE);


    if (status != NX_SUCCESS)
    {
        return(status);
    }

    /* Send deregister attach request.*/
    status = nx_msrp_deregister_attach_request(&srp_ptr -> nx_mrp, &srp_ptr -> nx_msrp.nx_msrp_participant, stream_id);

    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_srp_cbs_config_get                               PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wen Wang,  Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function get CBS parameters from SRP talker parameter.         */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    sr_class                              Stream class                  */
/*    port_rate                             ethernet port rate            */
/*    frames_per_interval                   Freames per interval          */
/*    max_frame_size                        Max frame size                */
/*    non_sr_frame_size                     Non-stream frame size         */
/*    idle_slope_a                          stream A class Idle slope     */
/*    max_frame_size_a                      stream A class Max frame size */
/*    cbs_param                             CBS parameter                 */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None.                                                               */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_srp_talker_cbs_set                 Set CBS parameter             */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023        Wen Wang              Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_srp_cbs_config_get(UINT sr_class, INT port_rate, UINT interval, UINT frames_per_interval, UINT max_frame_size, UINT non_sr_frame_size, INT idle_slope_a, UINT max_frame_size_a, NX_SHAPER_CBS_PARAMETER *cbs_param)
{
    if (sr_class == NX_SRP_SR_CLASS_A)
    {
        cbs_param -> idle_slope = (INT)((long long)1000000 / interval * frames_per_interval * max_frame_size * 8 / 1000000); /* transfer to Mbps */
        if (cbs_param -> idle_slope >= port_rate)
        {
            printf("The Idleslope : %dMbps must be set less than port rate : %dMbps.\n",  cbs_param -> idle_slope, port_rate);
            return(NX_INVALID_PARAMETERS);
        }
        cbs_param -> send_slope = cbs_param -> idle_slope - port_rate;
        cbs_param -> hi_credit = (INT)((long long)cbs_param -> idle_slope * non_sr_frame_size / port_rate);
        cbs_param -> low_credit = (INT)((long long)cbs_param -> send_slope * max_frame_size / port_rate);

        return(NX_SUCCESS);
    }
    else if (sr_class == NX_SRP_SR_CLASS_B)
    {
        cbs_param -> idle_slope = (INT)((long long)1000000 / interval * frames_per_interval * max_frame_size * 8 / 1000000); /* transfer to Kbps */
        if (cbs_param -> idle_slope >= port_rate)
        {
            printf("The Idleslope : %dMbps must be set less than port rate : %dMbps.\n",  cbs_param -> idle_slope, port_rate);
            return(NX_INVALID_PARAMETERS);
        }
        cbs_param -> send_slope = cbs_param -> idle_slope - port_rate;
        cbs_param -> hi_credit = (INT)((long long)cbs_param -> idle_slope * non_sr_frame_size / (port_rate - idle_slope_a) + (long long)cbs_param -> idle_slope * max_frame_size_a / port_rate);
        cbs_param -> low_credit = (INT)((long long)cbs_param -> send_slope * max_frame_size / port_rate);

        return(NX_SUCCESS);
    }
    else
    {
        return(NX_INVALID_PARAMETERS);
    }
}
/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_srp_talker_cbs_set                               PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Wen Wang,  Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function get CBS parameters.                                   */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    srp_ptr                               SRP instance pointer          */
/*    stream_id                             Stream ID                     */
/*    domain                                Stream properties             */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_srp_cbs_config_get                 Get CBS parameter             */
/*    nx_shaper_cbs_parameter_set           Set CBS parameter to shaper   */
/*                                          layer.                        */
/*    nx_shaper_port_rate_get               Get ethernet port rate from   */
/*                                          shaper layer.                 */
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
UINT nx_srp_talker_cbs_set(NX_SRP *srp_ptr, UINT index)
{
UINT          status;
NX_INTERFACE *interface_ptr;
UINT          port_rate;
INT           i;
INT           idle_slope_a = 0;
UINT          max_frame_size_a = 0;

    interface_ptr = &(srp_ptr -> nx_mrp.ip_ptr -> nx_ip_interface[srp_ptr -> nx_mrp.interface_index]);
    status = nx_shaper_port_rate_get(interface_ptr, &port_rate);
    if (status)
    {
        return(status);
    }

    if (srp_ptr -> talker[index].class_id == NX_SRP_SR_CLASS_B)
    {
        for (i = 0; i < NX_SRP_TALKER_NUM; i++)
      {
            if (srp_ptr -> talker[i].in_used == NX_FALSE)
          {
              continue;
          }

            if (srp_ptr -> talker[i].class_id == NX_SRP_SR_CLASS_A)
          {
              idle_slope_a = srp_ptr -> talker[i].cbs_parameters.idle_slope;
              max_frame_size_a = srp_ptr -> talker[i].max_frame_size;
              break;
          }
      }
    }
    /* Get CBS parameters from SRP paramter. */
    status = nx_srp_cbs_config_get(srp_ptr -> talker[index].class_id,
                                   (INT)port_rate,
                                   srp_ptr -> talker[index].interval,
                                   srp_ptr -> talker[index].max_interval_frames,
                                   srp_ptr -> talker[index].max_frame_size,
                                   interface_ptr -> nx_interface_ip_mtu_size,
                                   idle_slope_a,
                                   max_frame_size_a,
                                   &(srp_ptr -> talker[index].cbs_parameters));
    if (status)
    {
        return(status);
    }

    printf("cbs parameters: idle slope: %d, send slope: %d, hi credit: %d, low credit: %d\r\n",
                srp_ptr -> talker[index].cbs_parameters.idle_slope,
                srp_ptr -> talker[index].cbs_parameters.send_slope,
                srp_ptr -> talker[index].cbs_parameters.hi_credit,
                srp_ptr -> talker[index].cbs_parameters.low_credit);

    /* Set CBS parameters to shaper layer. */
    if (srp_ptr -> talker[index].class_id == NX_SRP_SR_CLASS_A)
    {
        status = nx_shaper_cbs_parameter_set(interface_ptr, &(srp_ptr -> talker[index].cbs_parameters), NX_SHAPER_CLASS_A_PCP);
    }
    else
    {
        status = nx_shaper_cbs_parameter_set(interface_ptr, &(srp_ptr -> talker[index].cbs_parameters), NX_SHAPER_CLASS_B_PCP);
    }

    return(status);
}
#endif /* NX_ENABLE_VLAN */
