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
/**   Multiple Registration Protocol (MRP)                                */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

/* Include necessary system files.  */
#include "nx_mrp.h"

#ifdef NX_ENABLE_VLAN

#ifdef NX_MRP_DEBUG_ENABLE
/* For debug */
UCHAR *event_str[] =
{
    "rNew", "rJoinin", "rIN", "rJoinMT", "rMT", "rLV", "rLA",
    "begin", "new", "join",
    "lv", "tx", "txLA", "txLAF", "Flush", "redec",
    "periodic", "LVTimer", "LATimer", "pTimer",
    "pdEnable", "pdDisable",
};

UCHAR *state_str[] =
{
    "VO", "VP", "VN", "AN", "AA", "QA", "LA", "AO", "QO", "AP", "QP", "LO",
    "IN", "LV", "MT",
    "LA_A", "LA_P",
    "PT_A", "PT_P",
};

UCHAR *action_str[] =
{
    "NX_NULL", "SN", "SJ", "SJOPT", "SL", "S", "SOPT", "SLA",
    "Periodic", "Start_LVT", "Stop_LVT", "Start_LAT", "Stop_LAT",
};
#endif

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_mrp_applicant_event_process                      PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function processes event for attribute of mrp participant.     */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp                                   Pointer to MRP instance       */
/*    participant                           Pointer to MRP participant    */
/*    attribute                             Pointer to MRP attribute      */
/*    event                                 Event to be processed         */
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
/*    nx_mrp_event_process                  MRP event process             */
/*    nx_mrp_attribute_new                  MRP attribute new             */
/*    nx_mrp_periodic_timeout_process       MRP periodic timeout process  */
/*    nx_mrp_join_timeout_process           MRP join timeout process      */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_mrp_applicant_event_process(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_MRP_ATTRIBUTE *attribute, UCHAR mrp_event)
{
#ifdef NX_MRP_DEBUG_ENABLE
UCHAR origin_state = attribute -> applicant.state;
#endif
    NX_PARAMETER_NOT_USED(participant);
    if (attribute == NX_NULL || mrp == NX_NULL)
    {
        return(NX_INVALID_PARAMETERS);
    }

    attribute -> applicant.action = NX_MRP_ACTION_NULL;

    switch (mrp_event)
    {
    case NX_MRP_EVENT_BEGIN:
        attribute -> applicant.state = NX_MRP_APPLICANT_STATE_VO;
        break;

    case NX_MRP_EVENT_NEW:
        if (attribute -> applicant.state != NX_MRP_APPLICANT_STATE_AN)
        {
            attribute -> applicant.state = NX_MRP_APPLICANT_STATE_VN;
        }

        break;

    case NX_MRP_EVENT_JOIN:
        switch (attribute -> applicant.state)
        {
        case NX_MRP_APPLICANT_STATE_VO:
            attribute -> applicant.state = NX_MRP_APPLICANT_STATE_VP;
            break;

        case NX_MRP_APPLICANT_STATE_LA:
            attribute -> applicant.state = NX_MRP_APPLICANT_STATE_AA;
            break;

        case NX_MRP_APPLICANT_STATE_AO:
            attribute -> applicant.state = NX_MRP_APPLICANT_STATE_AP;
            break;

        case NX_MRP_APPLICANT_STATE_QO:
            attribute -> applicant.state = NX_MRP_APPLICANT_STATE_QP;
            break;

        case NX_MRP_APPLICANT_STATE_LO:
            attribute -> applicant.state = NX_MRP_APPLICANT_STATE_VP;
            break;

        default:
            /* do nothing */
            break;
        }
        break;

    case NX_MRP_EVENT_LV:
        switch (attribute -> applicant.state)
        {
        case NX_MRP_APPLICANT_STATE_VP:
            attribute -> applicant.state = NX_MRP_APPLICANT_STATE_VO;
            break;

        case NX_MRP_APPLICANT_STATE_VN:
        case NX_MRP_APPLICANT_STATE_AN:
        case NX_MRP_APPLICANT_STATE_AA:
        case NX_MRP_APPLICANT_STATE_QA:
            attribute -> applicant.state = NX_MRP_APPLICANT_STATE_LA;
            break;

        case NX_MRP_APPLICANT_STATE_AP:
            attribute -> applicant.state = NX_MRP_APPLICANT_STATE_AO;
            break;

        case NX_MRP_APPLICANT_STATE_QP:
            attribute -> applicant.state = NX_MRP_APPLICANT_STATE_QO;
            break;

        default:
            /* do nothing */
            break;
        }
        break;

    case NX_MRP_EVENT_RNEW:
        /* do nothing */
        break;

    case NX_MRP_EVENT_RJOININ:
        switch (attribute -> applicant.state)
        {
        case NX_MRP_APPLICANT_STATE_VO:
            /* Ignored (no transition) if point-to-point subset or if operPointToPointMAC is TRUE */
            if (mrp -> oper_p2p_mac != NX_TRUE)
            {
                attribute -> applicant.state = NX_MRP_APPLICANT_STATE_AO;
            }

            break;

        case NX_MRP_APPLICANT_STATE_VP:
            /* Ignored (no transition) if point-to-point subset or if operPointToPointMAC is TRUE */
            if (mrp -> oper_p2p_mac != NX_TRUE)
            {
                attribute -> applicant.state = NX_MRP_APPLICANT_STATE_AP;
            }
            break;

        case NX_MRP_APPLICANT_STATE_AA:
            attribute -> applicant.state = NX_MRP_APPLICANT_STATE_QA;
            break;

        case NX_MRP_APPLICANT_STATE_AO:
            attribute -> applicant.state = NX_MRP_APPLICANT_STATE_QO;
            break;

        case NX_MRP_APPLICANT_STATE_AP:
            attribute -> applicant.state = NX_MRP_APPLICANT_STATE_QP;
            break;

        default:
            /* do nothing */
            break;
        }
        break;

    case NX_MRP_EVENT_RIN:
        if (attribute -> applicant.state == NX_MRP_APPLICANT_STATE_AA)
        {
            /* Ignored (no transition) if operPointToPointMAC is FALSE */
            if (mrp -> oper_p2p_mac == NX_TRUE)
            {
                attribute -> applicant.state = NX_MRP_APPLICANT_STATE_QA;
            }
        }
        break;

    case NX_MRP_EVENT_RJOINMT:
    case NX_MRP_EVENT_RMT:
        switch (attribute -> applicant.state)
        {
        case NX_MRP_APPLICANT_STATE_QA:
            attribute -> applicant.state = NX_MRP_APPLICANT_STATE_AA;
            break;

        case NX_MRP_APPLICANT_STATE_QO:
            attribute -> applicant.state = NX_MRP_APPLICANT_STATE_AO;
            break;

        case NX_MRP_APPLICANT_STATE_QP:
            attribute -> applicant.state = NX_MRP_APPLICANT_STATE_AP;
            break;

        case NX_MRP_APPLICANT_STATE_LO:
            attribute -> applicant.state = NX_MRP_APPLICANT_STATE_VO;
            break;

        default:
            /* do nothing */
            break;
        }
        break;

    case NX_MRP_EVENT_RLV:
    case NX_MRP_EVENT_RLA:
    case NX_MRP_EVENT_REDECLARE:
        switch (attribute -> applicant.state)
        {
        case NX_MRP_APPLICANT_STATE_VO:
        case NX_MRP_APPLICANT_STATE_AO:
        case NX_MRP_APPLICANT_STATE_QO:
            /* Applicant-Only participants exclude the LO state, and transition to VO */
            attribute -> applicant.state = NX_MRP_APPLICANT_STATE_LO;
            break;

        case NX_MRP_APPLICANT_STATE_AN:
            attribute -> applicant.state = NX_MRP_APPLICANT_STATE_VN;
            break;

        case NX_MRP_APPLICANT_STATE_AA:
        case NX_MRP_APPLICANT_STATE_QA:
        case NX_MRP_APPLICANT_STATE_AP:
        case NX_MRP_APPLICANT_STATE_QP:
            attribute -> applicant.state = NX_MRP_APPLICANT_STATE_VP;
            break;

        default:
            /* do nothing */
            break;
        }
        break;

    case NX_MRP_EVENT_PERIODIC:
        switch (attribute -> applicant.state)
        {
        case NX_MRP_APPLICANT_STATE_QA:
            attribute -> applicant.state = NX_MRP_APPLICANT_STATE_AA;
            break;

        case NX_MRP_APPLICANT_STATE_QP:
            attribute -> applicant.state = NX_MRP_APPLICANT_STATE_AP;
            break;

        default:
            /* do nothing */
            break;
        }
        break;

    case NX_MRP_EVENT_TX:
        switch (attribute -> applicant.state)
        {
        case NX_MRP_APPLICANT_STATE_VO:
        case NX_MRP_APPLICANT_STATE_AO:
        case NX_MRP_APPLICANT_STATE_QO:
        case NX_MRP_APPLICANT_STATE_QP:
            attribute -> applicant.action = NX_MRP_ACTION_S_OPT;
            break;

        case NX_MRP_APPLICANT_STATE_VP:
            attribute -> applicant.action = NX_MRP_ACTION_SJ;
            attribute -> applicant.state = NX_MRP_APPLICANT_STATE_AA;
            break;

        case NX_MRP_APPLICANT_STATE_VN:
            attribute -> applicant.action = NX_MRP_ACTION_SN;
            attribute -> applicant.state = NX_MRP_APPLICANT_STATE_AN;
            break;

        case NX_MRP_APPLICANT_STATE_AN:
            attribute -> applicant.action = NX_MRP_ACTION_SN;
            if (attribute -> registrar.state == NX_MRP_REGISTRAR_STATE_IN)
            {
                attribute -> applicant.state = NX_MRP_APPLICANT_STATE_QA;
            }
            else
            {
                attribute -> applicant.state = NX_MRP_APPLICANT_STATE_AA;
            }
            break;

        case NX_MRP_APPLICANT_STATE_AA:
        case NX_MRP_APPLICANT_STATE_AP:
            attribute -> applicant.action = NX_MRP_ACTION_SJ;
            attribute -> applicant.state = NX_MRP_APPLICANT_STATE_QA;
            break;

        case NX_MRP_APPLICANT_STATE_QA:
            attribute -> applicant.action = NX_MRP_ACTION_SJ_OPT;
            break;

        case NX_MRP_APPLICANT_STATE_LA:
            attribute -> applicant.action = NX_MRP_ACTION_SL;
            attribute -> applicant.state = NX_MRP_APPLICANT_STATE_VO;
            break;

        case NX_MRP_APPLICANT_STATE_LO:
            attribute -> applicant.action = NX_MRP_ACTION_S;
            attribute -> applicant.state = NX_MRP_APPLICANT_STATE_VO;
            break;

        default:
            /* do nothing */
            break;
        }
        break;

    case NX_MRP_EVENT_TXLA:
        switch (attribute -> applicant.state)
        {
        case NX_MRP_APPLICANT_STATE_VO:
        case NX_MRP_APPLICANT_STATE_LA:
        case NX_MRP_APPLICANT_STATE_AO:
        case NX_MRP_APPLICANT_STATE_QO:
        case NX_MRP_APPLICANT_STATE_LO:
            attribute -> applicant.action = NX_MRP_ACTION_S_OPT;
            attribute -> applicant.state = NX_MRP_APPLICANT_STATE_LO;
            break;

        case NX_MRP_APPLICANT_STATE_VP:
            attribute -> applicant.action = NX_MRP_ACTION_S;
            attribute -> applicant.state = NX_MRP_APPLICANT_STATE_AA;
            break;

        case NX_MRP_APPLICANT_STATE_VN:
            attribute -> applicant.action = NX_MRP_ACTION_SN;
            attribute -> applicant.state = NX_MRP_APPLICANT_STATE_AN;
            break;

        case NX_MRP_APPLICANT_STATE_AN:
            attribute -> applicant.action = NX_MRP_ACTION_SN;
            attribute -> applicant.state = NX_MRP_APPLICANT_STATE_QA;
            break;

        case NX_MRP_APPLICANT_STATE_AA:
        case NX_MRP_APPLICANT_STATE_QA:
        case NX_MRP_APPLICANT_STATE_AP:
        case NX_MRP_APPLICANT_STATE_QP:
            attribute -> applicant.action = NX_MRP_ACTION_SJ;
            attribute -> applicant.state = NX_MRP_APPLICANT_STATE_QA;
            break;

        default:
            /* do nothing */
            break;
        }
        break;

    case NX_MRP_EVENT_TXLAF:
        switch (attribute -> applicant.state)
        {
        case NX_MRP_APPLICANT_STATE_VO:
        case NX_MRP_APPLICANT_STATE_LA:
        case NX_MRP_APPLICANT_STATE_AO:
        case NX_MRP_APPLICANT_STATE_QO:
        case NX_MRP_APPLICANT_STATE_LO:
            attribute -> applicant.state = NX_MRP_APPLICANT_STATE_LO;
            break;

        case NX_MRP_APPLICANT_STATE_VP:
        case NX_MRP_APPLICANT_STATE_AA:
        case NX_MRP_APPLICANT_STATE_QA:
        case NX_MRP_APPLICANT_STATE_AP:
        case NX_MRP_APPLICANT_STATE_QP:
            attribute -> applicant.state = NX_MRP_APPLICANT_STATE_VP;
            break;

        case NX_MRP_APPLICANT_STATE_VN:
        case NX_MRP_APPLICANT_STATE_AN:
            attribute -> applicant.state = NX_MRP_APPLICANT_STATE_VN;
            break;

        default:
            /* do nothing */
            break;
        }
        break;

    default:
        /* do nothing */
        break;
    }

    /* Transmitting the value is not necessary for correct protocol operation, transfer it to NX_NULL action */
    if ((attribute -> applicant.action == NX_MRP_ACTION_SJ_OPT) ||
        (attribute -> applicant.action == NX_MRP_ACTION_S_OPT))
    {
        attribute -> applicant.action = NX_MRP_ACTION_NULL;
    }

#ifdef NX_MRP_DEBUG_ENABLE
    printf("APPLICANT: origin state: %4s, mrp_event: %8s, next state: %4s, action: %8s\n",
           state_str[origin_state], event_str[mrp_event], state_str[attribute -> applicant.state], action_str[attribute -> applicant.action]);
#endif

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_mrp_registrar_event_process                      PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function processes event for attribute of mrp registrar.       */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp                                   Pointer to MRP instance       */
/*    participant                           Pointer to MRP participant    */
/*    attribute                             Pointer to MRP attribute      */
/*    event                                 Event to be processed         */
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
/*    nx_mrp_attribute_new                  MRP attribute new             */
/*    nx_mrp_event_process                  MRP event process             */
/*    nx_mrp_join_timeout_process           MRP join timeout process      */
/*    nx_mrp_leave_timeout_process          MRP leave timeout process     */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_mrp_registrar_event_process(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_MRP_ATTRIBUTE *attribute, UCHAR mrp_event)
{
#ifdef NX_MRP_DEBUG_ENABLE
UCHAR origin_state = attribute -> registrar.state;
#endif

    if (participant == NX_NULL || attribute == NX_NULL)
    {
        return(NX_INVALID_PARAMETERS);
    }

    switch (mrp_event)
    {
    case NX_MRP_EVENT_BEGIN:
        attribute -> registrar.state = NX_MRP_REGISTRAR_STATE_MT;
        break;

    case NX_MRP_EVENT_RNEW:
        if (participant -> indication_function != NX_NULL)
        {
            participant -> indication_function(mrp, participant, attribute, NX_MRP_INDICATION_NEW);
        }

        if (attribute -> registrar.state == NX_MRP_REGISTRAR_STATE_LV)
        {
            /* Stop leavetimer */
            attribute -> leave_timer = 0;
        }

        attribute -> registrar.state = NX_MRP_REGISTRAR_STATE_IN;
        break;

    case NX_MRP_EVENT_RJOININ:
    case NX_MRP_EVENT_RJOINMT:
        if (attribute -> registrar.state == NX_MRP_REGISTRAR_STATE_LV)
        {
            /* Stop leavetimer */
            attribute -> leave_timer = 0;
        }
        else if (attribute -> registrar.state == NX_MRP_REGISTRAR_STATE_MT)
        {
            if (participant -> indication_function != NX_NULL)
            {
                participant -> indication_function(mrp, participant, attribute, NX_MRP_INDICATION_JOIN);
            }
        }
        attribute -> registrar.state = NX_MRP_REGISTRAR_STATE_IN;
        break;

    case NX_MRP_EVENT_RLV:
    case NX_MRP_EVENT_RLA:
    case NX_MRP_EVENT_TXLA:
    case NX_MRP_EVENT_REDECLARE:
        if (attribute -> registrar.state == NX_MRP_REGISTRAR_STATE_IN)
        {
            /* Start leavetimer */
            attribute -> leave_timer = NX_MRP_TIMER_LEAVE;
            attribute -> registrar.state = NX_MRP_REGISTRAR_STATE_LV;
        }
        break;

    case NX_MRP_EVENT_FLUSH:
        if (attribute -> registrar.state == NX_MRP_REGISTRAR_STATE_LV)
        {
            if (participant -> indication_function != NX_NULL)
            {
                participant -> indication_function(mrp, participant, attribute, NX_MRP_INDICATION_LV);
            }
        }
        attribute -> registrar.state = NX_MRP_REGISTRAR_STATE_MT;

        break;

    case NX_MRP_EVENT_LEAVETIMER:
        if (attribute -> registrar.state == NX_MRP_REGISTRAR_STATE_LV)
        {
            if (participant -> indication_function != NX_NULL)
            {
                participant -> indication_function(mrp, participant, attribute, NX_MRP_INDICATION_LV);
            }

            attribute -> registrar.state = NX_MRP_REGISTRAR_STATE_MT;
        }
        break;

    default:
        break;
    }

#ifdef NX_MRP_DEBUG_ENABLE
    printf("REGISTRAR: origin state: %4s, mrp_event: %8s, next state: %4s\n",
           state_str[origin_state], event_str[mrp_event], state_str[attribute -> registrar.state]);
#endif

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_mrp_leaveall_event_process                       PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function processes leave all event for participant.            */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    participant                           Pointer to MRP participant    */
/*    mrp_event                             Event to be processed         */
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
/*    nx_mrp_event_process                  MRP event process             */
/*    nx_mrp_join_timeout_process           MRP join timeout process      */
/*    nx_mrp_leaveall_timeout_process       MRP leave all timeout process */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_mrp_leaveall_event_process(NX_MRP_PARTICIPANT *participant, UCHAR mrp_event)
{
#ifdef NX_MRP_DEBUG_ENABLE
UCHAR origin_state = participant -> leaveall.state;
#endif

    if (participant == NX_NULL)
    {
        return(NX_INVALID_PARAMETERS);
    }

    participant -> leaveall.action = NX_MRP_ACTION_NULL;
    switch (mrp_event)
    {
    case NX_MRP_EVENT_BEGIN:
        /* start leave all timer */
        participant -> leaveall_timer = NX_MRP_TIMER_LEAVEALL;
        participant -> leaveall.state = NX_MRP_LA_STATE_PASSIVE;
        break;

    case NX_MRP_EVENT_TX:
        if (participant -> leaveall.state == NX_MRP_LA_STATE_ACTIVE)
        {
            participant -> leaveall.action = NX_MRP_ACTION_SLA; /* The next TX should be changed to TXLA */
            participant -> leaveall.state = NX_MRP_LA_STATE_PASSIVE;
        }
        break;

    case NX_MRP_EVENT_RLA:

        /* start leave all timer */
        participant -> leaveall_timer = NX_MRP_TIMER_LEAVEALL;
        participant -> leaveall.state = NX_MRP_LA_STATE_PASSIVE;
        break;

    case NX_MRP_EVENT_LEAVEALLTIMER:

        /* start leave all timer */
        participant -> leaveall_timer = NX_MRP_TIMER_LEAVEALL;
        participant -> leaveall.state = NX_MRP_LA_STATE_ACTIVE;
        break;

    default:
        break;
    }

#ifdef NX_MRP_DEBUG_ENABLE
    printf("LA       : origin state: %4s, mrp_event: %8s, next state: %4s, action: %8s\n",
           state_str[origin_state], event_str[mrp_event], state_str[participant -> leaveall.state], action_str[participant -> leaveall.action]);
#endif
    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_mrp_participant_add                              PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function adds a participant to the MRP instance.               */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp                                   Pointer to MRP instance       */
/*    participant                           Pointer to MRP participant    */
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
UINT nx_mrp_participant_add(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant)
{
NX_MRP_PARTICIPANT *tmp_participant = mrp -> list_head;

    if ((mrp == NX_NULL) || (participant == NX_NULL))
    {
        return(NX_INVALID_PARAMETERS);
    }

    if (tmp_participant == NX_NULL)
    {
        mrp -> list_head = participant;
    }
    else
    {
        if (tmp_participant == participant)
        {

            /* the participant is already linked, do nothing */
            return(NX_SUCCESS);
        }

        while (tmp_participant -> next != NX_NULL)
        {
            tmp_participant = tmp_participant -> next;
            if (tmp_participant == participant)
            {

                /* the participant is already linked, do nothing */
                return(NX_SUCCESS);
            }
        }
        tmp_participant -> next = participant;
    }
    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_mrp_attribute_new                                PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function news a attribute for the participant.                 */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp                                   Pointer to MRP instance       */
/*    participant                           Pointer to MRP participant    */
/*    attribute_array                       Pointer to attribute array    */
/*    unit_size                             Size of an attribute          */
/*    unit_number                           Number of attribute           */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    pointer to attribute                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_mrp_applicant_event_process        Applicant event process       */
/*    nx_mrp_registrar_event_process        Registrar event process       */
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
NX_MRP_ATTRIBUTE *nx_mrp_attribute_new(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant,
                                       NX_MRP_ATTRIBUTE *attribute_array, UINT unit_size,
                                       UINT unit_number)
{
NX_MRP_ATTRIBUTE *tmp;
UCHAR            *buf;
UINT              i;

    if (mrp == NX_NULL ||
        participant == NX_NULL ||
        attribute_array == NX_NULL)
    {
        return(NX_NULL);
    }

    buf = (UCHAR *)attribute_array;
    for (i = 0; i < unit_number; i++)
    {
        tmp = (NX_MRP_ATTRIBUTE *)buf;
        if (tmp -> in_use == NX_FALSE)
        {
            break;
        }
        buf += unit_size;
    }

    if (i == unit_number)
    {
        return(NX_NULL);
    }

    tmp -> in_use = NX_TRUE;
    tmp -> pre = NX_NULL;
    tmp -> next = NX_NULL;

    nx_mrp_applicant_event_process(mrp, participant, tmp, NX_MRP_EVENT_BEGIN);
    nx_mrp_registrar_event_process(mrp, participant, tmp, NX_MRP_EVENT_BEGIN);

    return(tmp);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_mrp_attribute_evict                              PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function evicts a attribute for the participant.               */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp                                   Pointer to MRP instance       */
/*    participant                           Pointer to MRP participant    */
/*    target                                Pointer to MRP attribute      */
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
UINT nx_mrp_attribute_evict(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_MRP_ATTRIBUTE *target)
{
NX_MRP_ATTRIBUTE *attribute = target;

    if ((attribute -> registrar.state == NX_MRP_REGISTRAR_STATE_MT) &&
        ((attribute -> applicant.state == NX_MRP_APPLICANT_STATE_VO) ||
         (attribute -> applicant.state == NX_MRP_APPLICANT_STATE_AO) ||
         (attribute -> applicant.state == NX_MRP_APPLICANT_STATE_QO)))
    {
        if (attribute -> pre == NX_NULL)
        {
            participant -> inused_head = attribute -> next;
            attribute -> next -> pre = NX_NULL;
        }
        else
        {
            attribute -> pre -> next = attribute -> next;
            attribute -> next -> pre = attribute -> pre;
        }

        if (participant -> indication_function != NX_NULL)
        {
            participant -> indication_function(mrp, participant, attribute, NX_MRP_INDICATION_EVICT);
        }

        /* Delete the attribute from list */
        attribute -> in_use = NX_FALSE;
    }

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_mrp_timer_handle                                 PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function handles the timer interrupt.                          */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp_instance                          Pointer to MRP instance       */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_event_flags_set                    Set event flags               */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_mrp_init                           Initialize MRP Module         */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
void nx_mrp_timer_handle(ULONG mrp_instance)
{
NX_MRP *mrp = (NX_MRP *)mrp_instance;

    tx_event_flags_set(&(mrp -> mrp_events), NX_MRP_TIMER_EVENT, TX_OR);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_mrp_timer_handle                                 PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function is callback function for ethernet receive.            */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                Pointer to IP instance        */
/*    interface_index                       Index to the interface        */
/*    packet_ptr                            Pointer to received packet    */
/*    physical_address_msw                  Physical address MSW          */
/*    physical_address_lsw                  Physical address LSW          */
/*    packet_type                           Packet type                   */
/*    header_size                           Size of the header            */
/*    context                               Pointer to MRP instance       */
/*    time_ptr                              Pointer to time structure     */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_event_flags_set                    Set event flags               */
/*    nx_packet_release                     Release packet                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_mrp_init                           Initialize MRP Module         */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_mrp_ethernet_receive_notify(NX_IP *ip_ptr, UINT interface_index, NX_PACKET *packet_ptr,
                                    ULONG physical_address_msw, ULONG physical_address_lsw,
                                    UINT packet_type, UINT header_size, VOID *context,
                                    struct NX_LINK_TIME_STRUCT *time_ptr)
{
TX_INTERRUPT_SAVE_AREA
NX_MRP *mrp = (NX_MRP *)context;

    NX_PARAMETER_NOT_USED(ip_ptr);
    NX_PARAMETER_NOT_USED(interface_index);
    NX_PARAMETER_NOT_USED(physical_address_msw);
    NX_PARAMETER_NOT_USED(physical_address_lsw);
    NX_PARAMETER_NOT_USED(time_ptr);
    NX_PARAMETER_NOT_USED(header_size);

    if (packet_type == NX_LINK_ETHERNET_MVRP ||
        packet_type == NX_LINK_ETHERNET_MSRP ||
        packet_type == NX_LINK_ETHERNET_MMRP)
    {

        /* Disable interrupts.  */
        TX_DISABLE

        /* Check to see if the receive queue is empty.  */
        if (mrp -> received_packet_head)
        {

            /* Not empty, just place the packet at the end of the queue.  */
            (mrp -> received_packet_tail) -> nx_packet_queue_next = packet_ptr;
            packet_ptr -> nx_packet_queue_next = NX_NULL;
            mrp -> received_packet_tail = packet_ptr;
        }
        else
        {

            /* Empty receive processing queue.  */
            mrp -> received_packet_head = packet_ptr;
            mrp -> received_packet_tail = packet_ptr;
            packet_ptr -> nx_packet_queue_next = NX_NULL;
        }

        /* Restore interrupts.  */
        TX_RESTORE
        /* set packet rcv event */
        tx_event_flags_set(&(mrp -> mrp_events), NX_MRP_RX_EVENT, TX_OR);
    }
    else
    {
        nx_packet_release(packet_ptr);
    }

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_mrp_init                                         PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function initializes the MRP module.                           */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp                                   Pointer to MRP instance       */
/*    ip_ptr                                Pointer to IP instance        */
/*    interface_index                       Index to the interface        */
/*    pkt_pool_ptr                          Pointer to packet pool        */
/*    thread_name                           Name of the thread            */
/*    stack_ptr                             Pointer to stack              */
/*    stack_size                            Size of the stack             */
/*    priority                              Priority of the thread        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_link_packet_receive_callback_add   Add receive callback          */
/*    tx_timer_create                       Create timer                  */
/*    tx_thread_create                      Create thread                 */
/*    tx_event_flags_create                 Create event flag             */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_srp_init                           Initialize SRP Module         */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
UINT nx_mrp_init(NX_MRP *mrp, NX_IP *ip_ptr, UINT interface_index, NX_PACKET_POOL *pkt_pool_ptr,
                 CHAR *thread_name, VOID *stack_ptr, ULONG stack_size, UINT priority)
{
UINT status;

    mrp -> list_head = NX_NULL;
    mrp -> periodic_timer = NX_MRP_TIMER_PERIODIC;
    mrp -> oper_p2p_mac = NX_MRP_DEFAULT_OPER_P2P_MAC;
    mrp -> ip_ptr = ip_ptr;
    mrp -> interface_index = interface_index;
    mrp -> received_packet_head = NX_NULL;
    mrp -> received_packet_tail = NX_NULL;
    mrp -> pkt_pool = pkt_pool_ptr;

    /* Start mrp timer */
    status = tx_timer_create(&(mrp -> mrp_timer), "MRP Timer", nx_mrp_timer_handle,
                             (ULONG)mrp,
                             (TX_TIMER_TICKS_PER_SECOND / NX_MRP_TIMER_TICKS_PER_SECOND),
                             (TX_TIMER_TICKS_PER_SECOND / NX_MRP_TIMER_TICKS_PER_SECOND),
                             TX_AUTO_START);
    if (status != NX_SUCCESS)
    {
        return(status);
    }


    /* Create the mrp main thread.  */
    status = tx_thread_create(&mrp -> mrp_thread, thread_name, nx_mrp_thread_entry, (ULONG)mrp,
                              stack_ptr, stack_size,
                              priority, priority, TX_NO_TIME_SLICE, TX_AUTO_START);
    if (status != NX_SUCCESS)
    {
        return(status);
    }

    /* Add the link callback function */
    status = nx_link_packet_receive_callback_add(mrp -> ip_ptr, mrp -> interface_index, &mrp -> receive_queue,
                                                 NX_LINK_PACKET_TYPE_ALL, nx_mrp_ethernet_receive_notify, (VOID *)mrp);
    if (status != NX_SUCCESS)
    {
        return(status);
    }

    /* Create the mrp event flag instance.  */
    status = tx_event_flags_create(&(mrp -> mrp_events), "MRP Events Queue");
    /* Check for error. */
    if (status != TX_SUCCESS)
    {
        return(status);
    }

    /* Create the mrp mutex */
    status = tx_mutex_create(&(mrp -> mrp_mutex), "MRP Mutex", TX_NO_INHERIT);
    if (status != TX_SUCCESS)
    {
        return(status);
    }

    /* Join MSRP multicase group */
    status = nx_link_multicast_join(mrp -> ip_ptr, mrp -> interface_index,
                                    NX_MRP_MRP_ETH_MULTICAST_ADDR_MSB, NX_MRP_MSRP_ETH_MULTICAST_ADDR_LSB);
    if (status != TX_SUCCESS)
    {
        return(status);
    }

    /* Join MVRP multicase group */
    status = nx_link_multicast_join(mrp -> ip_ptr, mrp -> interface_index,
                                    NX_MRP_MRP_ETH_MULTICAST_ADDR_MSB, NX_MRP_MVRP_ETH_MULTICAST_ADDR_LSB);
    if (status != TX_SUCCESS)
    {
        return(status);
    }

    /* Join MMRP multicase group */
    status = nx_link_multicast_join(mrp -> ip_ptr, mrp -> interface_index,
                                    NX_MRP_MRP_ETH_MULTICAST_ADDR_MSB, NX_MRP_MVRP_ETH_MULTICAST_ADDR_LSB);
    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_mrp_participant_search                           PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function searches a participant in the MRP instance.           */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp                                   Pointer to MRP instance       */
/*    participant_type                      Type of the participant       */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    pointer to participant                                              */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    Pointer to participant                                              */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_mrp_rcv_pkt_process                Process received packet       */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
NX_MRP_PARTICIPANT *nx_mrp_participant_search(NX_MRP *mrp, UINT participant_type)
{
NX_MRP_PARTICIPANT *participant = NX_NULL;

    participant = mrp -> list_head;

    while (participant)
    {
        if (participant -> participant_type == participant_type)
        {
            return(participant);
        }

        participant = participant -> next;
    }

    return(NX_NULL);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_mrp_rcv_pkt_process                              PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function handles the received packet.                          */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp                                   Pointer to MRP instance       */
/*    participant_type                      Type of the participant       */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_link_ethernet_header_parse         Parse ethernet header         */
/*    nx_mrp_participant_search             Search participant            */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_mrp_thread_entry                   MRP thread entry              */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
void nx_mrp_rcv_pkt_process(NX_MRP *mrp)
{
TX_INTERRUPT_SAVE_AREA
USHORT              packet_type;
UINT                header_size;
USHORT              vlan_tag;
UCHAR               vlan_tag_valid;
ULONG               physical_address_msw;
ULONG               physical_address_lsw;
NX_PACKET          *packet_ptr = NX_NULL;
NX_MRP_PARTICIPANT *participant;

    /* Loop to receive all packets. */
    while (mrp -> received_packet_head)
    {

        /* Remove the first packet and process it!  */

        /* Disable interrupts.  */
        TX_DISABLE

        /* Pickup the first packet.  */
        packet_ptr =  mrp -> received_packet_head;

        /* Move the head pointer to the next packet.  */
        mrp -> received_packet_head =  packet_ptr -> nx_packet_queue_next;

        if (mrp -> received_packet_head == NX_NULL)
        {

            /* Yes, the queue is empty.  Set the tail pointer to NX_NULL.  */
            mrp -> received_packet_tail =  NX_NULL;
        }

        /* Restore interrupts.  */
        TX_RESTORE

        /*The packet parsed twice(need to optimize) */
        nx_link_ethernet_header_parse(packet_ptr, &physical_address_msw, &physical_address_lsw,
                                      NX_NULL, NX_NULL, &packet_type, &vlan_tag, &vlan_tag_valid, &header_size);

        /* Clean off the Ethernet header.  */
        packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr + header_size;

        /* Adjust the packet length.  */
        packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length - header_size;

        if ((packet_type == NX_LINK_ETHERNET_MVRP) ||
            (packet_type == NX_LINK_ETHERNET_MSRP) ||
            (packet_type == NX_LINK_ETHERNET_MMRP))
        {
            participant = nx_mrp_participant_search(mrp, packet_type);
            if (participant && (participant -> unpack_function != NX_NULL))
            {
                participant -> unpack_function(mrp, participant, packet_ptr);
            }
            nx_packet_release(packet_ptr);
        }
    }
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_mrp_event_process                                PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function processes event for attribute of mrp participant.     */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp                                   Pointer to MRP instance       */
/*    participant                           Pointer to MRP participant    */
/*    attribute                             Pointer to MRP attribute      */
/*    mrp_event                             Event to be processed         */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_mrp_applicant_event_process        Applicant event process       */
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
UINT nx_mrp_event_process(NX_MRP *mrp, NX_MRP_PARTICIPANT *participant, NX_MRP_ATTRIBUTE *attribute, UCHAR mrp_event)
{
UINT status;

    switch (mrp_event)
    {
    case NX_MRP_EVENT_NEW:
    case NX_MRP_EVENT_JOIN:
    case NX_MRP_EVENT_LV:

    /* Receive msg types just need to process for applicant */
    case NX_MRP_EVENT_RIN:
    case NX_MRP_EVENT_RMT:
        status = nx_mrp_applicant_event_process(mrp, participant, attribute, mrp_event);
        break;

    case NX_MRP_EVENT_RNEW:
    case NX_MRP_EVENT_RJOININ:
    case NX_MRP_EVENT_RJOINMT:
    case NX_MRP_EVENT_RLV:
    case NX_MRP_EVENT_REDECLARE:
        status = nx_mrp_applicant_event_process(mrp, participant, attribute, mrp_event);
        status = nx_mrp_registrar_event_process(mrp, participant, attribute, mrp_event);
        break;

    case NX_MRP_EVENT_RLA:
        status = nx_mrp_applicant_event_process(mrp, participant, attribute, mrp_event);
        status = nx_mrp_registrar_event_process(mrp, participant, attribute, mrp_event);
        status = nx_mrp_leaveall_event_process(participant, mrp_event);
        break;

    default:
        status = NX_INVALID_PARAMETERS;
        break;
    }

    return(status);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_mrp_attribute_event_get                          PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function gets event for attribute.                             */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    attribute                             Pointer to MRP attribute      */
/*    event_ptr                             Pointer to event              */
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
UINT nx_mrp_attribute_event_get(NX_MRP_ATTRIBUTE *attribute, UCHAR *event_ptr)
{

    switch (attribute -> applicant.action)
    {
    case NX_MRP_ACTION_SN:
        *event_ptr = NX_MRP_ATTRIBUTE_EVENT_NEW;
        break;

    case NX_MRP_ACTION_SJ:
        if (attribute -> registrar.state == NX_MRP_REGISTRAR_STATE_IN)
        {
            *event_ptr = NX_MRP_ATTRIBUTE_EVENT_JOININ;
        }
        else if (attribute -> registrar.state == NX_MRP_REGISTRAR_STATE_MT  ||
                 attribute -> registrar.state == NX_MRP_REGISTRAR_STATE_LV)
        {
            *event_ptr = NX_MRP_ATTRIBUTE_EVENT_JOINMT;
        }
        else
        {
            return(NX_INVALID_PARAMETERS);
        }

        break;

    case NX_MRP_ACTION_SL:
        *event_ptr = NX_MRP_ATTRIBUTE_EVENT_LV;
        break;

    case NX_MRP_ACTION_S:
        if (attribute -> registrar.state == NX_MRP_REGISTRAR_STATE_IN)
        {
            *event_ptr = NX_MRP_ATTRIBUTE_EVENT_IN;
        }
        else if (attribute -> registrar.state == NX_MRP_REGISTRAR_STATE_MT  ||
                 attribute -> registrar.state == NX_MRP_REGISTRAR_STATE_LV)
        {
            *event_ptr = NX_MRP_ATTRIBUTE_EVENT_MT;
        }
        else
        {
            return(NX_INVALID_PARAMETERS);
        }

        break;

    default:
        return(NX_INVALID_PARAMETERS);
    }

    return(NX_SUCCESS);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_mrp_periodic_timeout_process                     PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function handles the periodic timeout.                         */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp                                   Pointer to MRP instance       */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_mrp_applicant_event_process        Applicant event process       */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_mrp_timeout_process                MRP timeout process           */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
void nx_mrp_periodic_timeout_process(NX_MRP *mrp)
{
NX_MRP_PARTICIPANT *participant;
NX_MRP_ATTRIBUTE   *attribute;

    if (mrp -> periodic_timer > NX_MRP_TIMEOUT_INTERVAL)
    {
        mrp -> periodic_timer -= NX_MRP_TIMEOUT_INTERVAL;
    }
    else if (mrp -> periodic_timer == NX_MRP_TIMEOUT_INTERVAL)
    {
        /* Periodic timeout, restart */
        mrp -> periodic_timer = NX_MRP_TIMER_PERIODIC;

        participant = mrp -> list_head;
        while (participant != NX_NULL)
        {
            attribute = participant -> inused_head;
            while (attribute != NX_NULL)
            {
                nx_mrp_applicant_event_process(mrp, participant, attribute, NX_MRP_EVENT_PERIODIC);
                attribute = attribute -> next;
            }

            participant = participant -> next;
        }
    }
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_mrp_join_timeout_process                         PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function handles the join timeout.                             */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp                                   Pointer to MRP instance       */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_mrp_leaveall_event_process         Leaveall event process        */
/*    nx_mrp_applicant_event_process        Applicant event process       */
/*    nx_mrp_registrar_event_process        Registrar event process       */
/*    nx_packet_allocate                    Allocate a packet             */
/*    nx_packet_release                     Release a packet              */
/*    nx_link_ethernet_packet_send          Send a packet                 */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_mrp_timeout_process                MRP timeout process           */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
void nx_mrp_join_timeout_process(NX_MRP *mrp)
{
NX_MRP_PARTICIPANT *participant;
NX_MRP_ATTRIBUTE   *attribute;
UCHAR               mrp_event;
NX_PACKET          *packet_ptr;
UINT                status;
ULONG               mul_msb;
ULONG               mul_lsb;
UINT                eth_type;

    participant = mrp -> list_head;
    while (participant != NX_NULL)
    {
        if (participant -> join_timer > NX_MRP_TIMEOUT_INTERVAL)
        {
            participant -> join_timer -= NX_MRP_TIMEOUT_INTERVAL;
        }
        else if (participant -> join_timer == NX_MRP_TIMEOUT_INTERVAL)
        {
            /* Join timeout, restart */
            participant -> join_timer = NX_MRP_TIMER_JOIN;

            /* Tx! process for participant */
            mrp_event = NX_MRP_EVENT_TX;
            nx_mrp_leaveall_event_process(participant, mrp_event);

            /* If the LeaveAll state machine has signaled LeaveAll, then tx! is modified to txLA! */
            if (participant -> leaveall.action == NX_MRP_ACTION_SLA)
            {
                mrp_event = NX_MRP_EVENT_TXLA;
            }

            attribute = participant -> inused_head;

            if (attribute == NX_NULL)
            {
                participant = participant -> next;
                continue;
            }

            while (attribute != NX_NULL)
            {
                nx_mrp_applicant_event_process(mrp, participant, attribute, mrp_event);

                if (mrp_event == NX_MRP_EVENT_TXLA)
                {
                    nx_mrp_registrar_event_process(mrp, participant, attribute, mrp_event);
                }

                attribute = attribute -> next;
            }

            if (participant -> pack_function)
            {
                /* Allocate a packet.  */
                status =  nx_packet_allocate(mrp -> pkt_pool, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);
                if (status != NX_SUCCESS)
                {
                    return;
                }

                status = participant -> pack_function(mrp, participant, packet_ptr);

                if (status != NX_SUCCESS)
                {
                    nx_packet_release(packet_ptr);
                }
                else
                {
                    switch (participant -> participant_type)
                    {
                    case NX_MRP_PARTICIPANT_MSRP:
                        mul_lsb = NX_MRP_MSRP_ETH_MULTICAST_ADDR_LSB;
                        eth_type = NX_LINK_ETHERNET_MSRP;
                        break;
                    case NX_MRP_PARTICIPANT_MMRP:
                        mul_lsb = NX_MRP_MMRP_ETH_MULTICAST_ADDR_LSB;
                        eth_type = NX_LINK_ETHERNET_MMRP;
                        break;
                    case NX_MRP_PARTICIPANT_MVRP:
                        mul_lsb = NX_MRP_MVRP_ETH_MULTICAST_ADDR_LSB;
                        eth_type = NX_LINK_ETHERNET_MVRP;
                        break;
                    default:
                        /* do nothing */
                        break;
                    }
                    mul_msb = NX_MRP_MRP_ETH_MULTICAST_ADDR_MSB;
                    if (packet_ptr -> nx_packet_length == 0)
                    {
                        nx_packet_release(packet_ptr);
                        return;
                    }

                    /* Send out one packet */
                    status = nx_link_ethernet_packet_send(mrp -> ip_ptr,
                                                          mrp -> interface_index, packet_ptr,
                                                          mul_msb,
                                                          mul_lsb,
                                                          eth_type);

                    if (status)
                    {

                        /* release packet in case of error */
                        nx_packet_release(packet_ptr);
                    }
                }
            }
        }
        participant = participant -> next;
    }
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_mrp_join_timeout_process                         PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function handles the leaveall timeout.                         */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp                                   Pointer to MRP instance       */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_mrp_leaveall_event_process         Leaveall event process        */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_mrp_timeout_process                MRP timeout process           */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
void nx_mrp_leaveall_timeout_process(NX_MRP *mrp)
{
NX_MRP_PARTICIPANT *participant;

    participant = mrp -> list_head;
    while (participant != NX_NULL)
    {
        if (participant -> leaveall_timer > NX_MRP_TIMEOUT_INTERVAL)
        {
            participant -> leaveall_timer -= NX_MRP_TIMEOUT_INTERVAL;
        }
        else if (participant -> leaveall_timer == NX_MRP_TIMEOUT_INTERVAL)
        {

            /* Generate leave all timeout event */
            nx_mrp_leaveall_event_process(participant, NX_MRP_EVENT_LEAVEALLTIMER);
        }

        participant = participant -> next;
    }
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_mrp_join_timeout_process                         PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function handles the leave timeout.                            */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp                                   Pointer to MRP instance       */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_mrp_registrar_event_process        Registrar event process       */
/*    nx_mrp_attribute_evict                Evict attribute               */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_mrp_timeout_process                MRP timeout process           */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
void nx_mrp_leave_timeout_process(NX_MRP *mrp)
{
NX_MRP_PARTICIPANT *participant;
NX_MRP_ATTRIBUTE   *attribute;

    participant = mrp -> list_head;
    while (participant != NX_NULL)
    {
        attribute = participant -> inused_head;
        while (attribute != NX_NULL)
        {
            if (attribute -> leave_timer > NX_MRP_TIMEOUT_INTERVAL)
            {
                attribute -> leave_timer -= NX_MRP_TIMEOUT_INTERVAL;
            }
            else if (attribute -> leave_timer == NX_MRP_TIMEOUT_INTERVAL)
            {
                nx_mrp_registrar_event_process(mrp, participant, attribute, NX_MRP_EVENT_LEAVETIMER);

                nx_mrp_attribute_evict(mrp, participant, attribute);
            }
            attribute = attribute -> next;
        }
        participant = participant -> next;
    }
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_mrp_join_timeout_process                         PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function handles the timeout of MRP.                           */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp                                   Pointer to MRP instance       */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_mrp_periodic_timeout_process      Process periodic timeout       */
/*    nx_mrp_leaveall_timeout_process      Process leaveall timeout       */
/*    nx_mrp_join_timeout_process          Process join timeout           */
/*    nx_mrp_leave_timeout_process         Process leave timeout          */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_mrp_thread_entry                   MRP thread entry              */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  12-31-2023     Yajun Xia                Initial Version 6.4.0         */
/*                                                                        */
/**************************************************************************/
void nx_mrp_timeout_process(NX_MRP *mrp)
{
    /* Periodic timer process (based on each port) */
    nx_mrp_periodic_timeout_process(mrp);

    /* Leave all timer process (based on participant) */
    nx_mrp_leaveall_timeout_process(mrp);

    /* Join timer process (based on participant) */
    nx_mrp_join_timeout_process(mrp);

    /* Leave timer process (based on each participant) */
    nx_mrp_leave_timeout_process(mrp);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    nx_mrp_thread_entry                                 PORTABLE C      */
/*                                                           6.4.0        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yajun Xia, Microsoft Corporation                                    */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function is the entry of MRP thread.                           */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    mrp_instance                          Pointer to MRP instance       */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_mrp_timeout_process               Process timeout                */
/*    nx_mrp_rcv_pkt_process               Process received packet        */
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
void nx_mrp_thread_entry(ULONG mrp_instance)
{
NX_MRP *mrp = (NX_MRP *)mrp_instance;
ULONG   actual_flags;

    while (1)
    {
        /* Wait for event.  */
        tx_event_flags_get(&mrp -> mrp_events, NX_MRP_ALL_EVENTS, TX_OR_CLEAR,
                           &actual_flags, TX_WAIT_FOREVER);
        /* Get mutex. */
        tx_mutex_get(&mrp -> mrp_mutex, NX_WAIT_FOREVER);

        if (actual_flags & NX_MRP_TIMER_EVENT)
        {
            nx_mrp_timeout_process(mrp);
        }

        if (actual_flags & NX_MRP_RX_EVENT)
        {
            nx_mrp_rcv_pkt_process(mrp);
        }

        /* Release the mutex.  */
        tx_mutex_put(&(mrp -> mrp_mutex));
    }
}
#endif /* NX_ENABLE_VLAN */

