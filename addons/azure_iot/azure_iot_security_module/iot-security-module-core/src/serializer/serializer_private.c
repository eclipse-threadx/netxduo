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

#include <stdint.h>

#include "asc_security_core/logger.h"
#include "asc_security_core/model/schema/message_builder.h"
#include "asc_security_core/utils/iuuid.h"

#include "serializer_private.h"

asc_result_t serializer_event_start(serializer_t *serializer, uint32_t timestamp, uint32_t collection_interval)
{
    if (serializer->state == SERIALIZER_STATE_MESSAGE_EMPTY && flatbuffers_failed(AzureIoTSecurity_Message_events_start(&serializer->builder))) {
        log_error("failed in AzureIoTSecurity_Message_events_start");
        serializer->state = SERIALIZER_STATE_EXCEPTION;
        return ASC_RESULT_EXCEPTION;
    }

    if (flatbuffers_failed(AzureIoTSecurity_Message_events_push_start(&serializer->builder))) {
        log_error("failed in AzureIoTSecurity_Event_vec_push_start");
        serializer->state = SERIALIZER_STATE_EXCEPTION;
        return ASC_RESULT_EXCEPTION;
    }

    uint8_t uuid[16] = { 0 };
    if (iuuid_generate(uuid) < 0) {
        log_error("failed in iuuid_generate");
        serializer->state = SERIALIZER_STATE_EXCEPTION;
        return ASC_RESULT_EXCEPTION;
    }

    if (flatbuffers_failed(AzureIoTSecurity_Event_id_create(&serializer->builder, uuid))) {
        log_error("failed in AzureIoTSecurity_Event_id_create");
        serializer->state = SERIALIZER_STATE_EXCEPTION;
        return ASC_RESULT_EXCEPTION;

    }

    if (flatbuffers_failed(AzureIoTSecurity_Event_time_add(&serializer->builder, timestamp))) {
        log_error("failed in AzureIoTSecurity_Event_time_add");
        serializer->state = SERIALIZER_STATE_EXCEPTION;
        return ASC_RESULT_EXCEPTION;
    }

    if (flatbuffers_failed(AzureIoTSecurity_Event_collection_interval_add(&serializer->builder, collection_interval))) {
        log_error("failed in AzureIoTSecurity_Event_collection_interval_add");
        serializer->state = SERIALIZER_STATE_EXCEPTION;
        return ASC_RESULT_EXCEPTION;
    }

    return ASC_RESULT_OK;
}
