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

#include "nx_azure_iot_hub_client.h"
#include "nx_azure_iot_security_module.h"

#include "asc_security_core/logger.h"
#include "asc_security_core/utils/irand.h"
#include "asc_security_core/utils/itime.h"

#include "iot_security_module/mti.h"


#define AZURE_IOT_SECURITY_MODULE_NAME      "Azure IoT Security Module"
#define AZURE_IOT_SECURITY_MODULE_EVENTS    (NX_CLOUD_MODULE_AZURE_ISM_EVENT | NX_CLOUD_COMMON_PERIODIC_EVENT)

#define MAX_PROPERTY_COUNT  2
static const CHAR *telemetry_headers[MAX_PROPERTY_COUNT][2] = {{MTI_KEY, MTI_VALUE},
                                                               {"%24.ifid", "urn%3Aazureiot%3ASecurity%3ASecurityAgent%3A1"}};

static NX_AZURE_IOT_SECURITY_MODULE _security_module;
static NX_AZURE_IOT_SECURITY_MODULE *_security_module_ptr = NULL;


static uint32_t _security_module_unix_time_get(uint32_t *unix_time);
static VOID _security_module_event_process(VOID *security_module_ptr, ULONG common_events, ULONG module_own_events);
static UINT _security_module_event_process_state_pending(NX_AZURE_IOT_SECURITY_MODULE *security_module_ptr);
static UINT _security_module_event_process_state_active(NX_AZURE_IOT_SECURITY_MODULE *security_module_ptr);
static UINT _security_module_event_process_state_suspended(NX_AZURE_IOT_SECURITY_MODULE *security_module_ptr);
static UINT _security_module_message_send(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr, security_message_t *security_message_ptr);
static VOID _security_module_clear_message(NX_AZURE_IOT_SECURITY_MODULE *security_module_ptr);
static asc_result_t _security_module_collect(NX_AZURE_IOT_SECURITY_MODULE *security_module_ptr);
static UINT _security_module_update_state(NX_AZURE_IOT_SECURITY_MODULE *security_module_ptr, security_module_state_t state);
static bool _security_module_exists_connected_iot_hub(NX_AZURE_IOT *nx_azure_iot_ptr);


UINT nx_azure_iot_security_module_enable(NX_AZURE_IOT *nx_azure_iot_ptr)
{
UINT status = NX_AZURE_IOT_SUCCESS;

    /* Check if Security Module instance is already been initialized. */
    if (_security_module_ptr == NULL)
    {

        if (nx_azure_iot_ptr == NULL)
        {
            status = NX_AZURE_IOT_INVALID_PARAMETER;
            goto cleanup;
        }

        /* Update singleton pointer. */
        _security_module_ptr = &_security_module;

        memset(_security_module_ptr, 0, sizeof(NX_AZURE_IOT_SECURITY_MODULE));

        /* Persist the nx_azure_iot_ptr. */
        _security_module_ptr->nx_azure_iot_ptr = nx_azure_iot_ptr;

        /* Initialize Security Module time interface.  */
        itime_init((unix_time_callback_t)_security_module_unix_time_get);

        /* Initialize Security Module core. */
        _security_module_ptr->core_ptr = core_init();
        if (_security_module_ptr->core_ptr == NULL)
        {
            status = NX_AZURE_IOT_FAILURE;
            LogError(LogLiteralArgs("Failed to enable IoT Security Module, CORE INIT FAIL"));
            goto cleanup;
        }

        /* Register Azure IoT Security Module on cloud helper.  */
        if ((status = nx_cloud_module_register(
            &(nx_azure_iot_ptr->nx_azure_iot_cloud),
            &(_security_module_ptr->nx_azure_iot_security_module_cloud),
            AZURE_IOT_SECURITY_MODULE_NAME,
            AZURE_IOT_SECURITY_MODULE_EVENTS,
            _security_module_event_process,
            _security_module_ptr
        )))
        {
            LogError(LogLiteralArgs("Security module register fail, error=%d"), status);
            goto cleanup;
        }

        /* Set security module state as active. */
        if ((status = _security_module_update_state(_security_module_ptr, SECURITY_MODULE_STATE_PENDING)))
        {
            LogError(LogLiteralArgs("Failed to update Security Module state, error=%d"), status);
            goto cleanup;
        }
    }

cleanup:
    if (status != NX_AZURE_IOT_SUCCESS)
    {
        LogError(LogLiteralArgs("Failed to enable Azure IoT Security Module, error=%d"), status);

        /* Destroy Security Module instance */
        nx_azure_iot_security_module_disable(nx_azure_iot_ptr);
    }
    else
    {
        LogInfo(LogLiteralArgs("Azure IoT Security Module has been enabled, status=%d"), status);
    }

    return status;
}


UINT nx_azure_iot_security_module_disable(NX_AZURE_IOT *nx_azure_iot_ptr)
{
UINT status = NX_AZURE_IOT_SUCCESS;

    if (_security_module_ptr != NULL)
    {
        if (_security_module_ptr->nx_azure_iot_ptr != nx_azure_iot_ptr && nx_azure_iot_ptr != NULL)
        {
            status = NX_AZURE_IOT_INVALID_PARAMETER;
        }
        else
        {

            /* Set security module state as not initialized. */
            if ((status = _security_module_update_state(_security_module_ptr, SECURITY_MODULE_STATE_NOT_INITIALIZED)))
            {
                LogError(LogLiteralArgs("Failed to update IoT Security state, error=%d"), status);
            }

            /* Deregister Azure IoT Security Module from cloud helper.  */
            if (_security_module_ptr->nx_azure_iot_ptr != NULL)
            {
                if ((status = nx_cloud_module_deregister(
                            &(_security_module_ptr->nx_azure_iot_ptr->nx_azure_iot_cloud),
                            &(_security_module_ptr->nx_azure_iot_security_module_cloud)
                )))
                {
                    LogError(LogLiteralArgs("Failed to deregister Azure IoT Security Module, error=%d"), status);
                    status = NX_AZURE_IOT_FAILURE;
                }
            }

            core_deinit(_security_module_ptr->core_ptr);
            _security_module_ptr->core_ptr = NULL;

            _security_module_ptr = NULL;
        }
    }

    if (status != NX_AZURE_IOT_SUCCESS)
    {
        LogError(LogLiteralArgs("Failed to disable IoT Security Module, error=%d"), status);
    }
    else
    {
        LogInfo(LogLiteralArgs("Azure IoT Security Module has been disabled, status=%d"), status);
    }

    return status;
}


static uint32_t _security_module_unix_time_get(uint32_t *unix_time)
{
ULONG t;

    if (_security_module_ptr == NULL || _security_module_ptr->nx_azure_iot_ptr == NULL)
    {
        return (uint32_t)-1;
    }

    if (_security_module_ptr->nx_azure_iot_ptr->nx_azure_iot_unix_time_get(&t) == NX_SUCCESS)
    {
        if (unix_time != NULL)
        {
            *unix_time = (uint32_t)t;
        }

        return (uint32_t)t;
    }

    return (uint32_t)-1;
}


static VOID _security_module_event_process(VOID *security_module_ptr, ULONG common_events, ULONG module_own_events)
{
UINT status = NX_AZURE_IOT_SUCCESS;
NX_AZURE_IOT_SECURITY_MODULE *security_module = (NX_AZURE_IOT_SECURITY_MODULE*)security_module_ptr;

    NX_PARAMETER_NOT_USED(module_own_events);

    /* Process common events.  */
    if (common_events & NX_CLOUD_COMMON_PERIODIC_EVENT)
    {
        if (security_module == NULL)
        {
            /* Periodic events must use instance of security module. */
            status = NX_AZURE_IOT_INVALID_PARAMETER;
            LogError(LogLiteralArgs("Security Module process periodic events must receive an instance, status=%d"), status);
            goto error;
        }

        switch(security_module->state)
        {
            case SECURITY_MODULE_STATE_NOT_INITIALIZED:
                /* Cannot occurred. */
                break;
            case SECURITY_MODULE_STATE_PENDING:
                status = _security_module_event_process_state_pending(security_module);
                break;
            case SECURITY_MODULE_STATE_ACTIVE:
                status = _security_module_event_process_state_active(security_module);
                break;
            case SECURITY_MODULE_STATE_SUSPENDED:
                status = _security_module_event_process_state_suspended(security_module);
                break;
            default:
                LogError(LogLiteralArgs("Unsupported Security Module state=%d"), security_module->state);
        }

        if (status != NX_AZURE_IOT_SUCCESS)
        {
            LogError(LogLiteralArgs("Failed to process state=%d"), security_module->state);
            goto error;
        }
    }

error:
    if (status != NX_AZURE_IOT_SUCCESS)
    {
        LogError(LogLiteralArgs("Security Module process periodic events finished with an error, status=%d"), status);
    }
}


static UINT _security_module_event_process_state_pending(NX_AZURE_IOT_SECURITY_MODULE *security_module_ptr)
{
UINT status = NX_AZURE_IOT_SUCCESS;
asc_result_t asc_result = ASC_RESULT_OK;
uint32_t now_timestamp;
security_message_t *security_message_ptr = &security_module_ptr->security_message;

    /* Check if Security Message is already cached */
    if (!security_message_is_empty(security_message_ptr))
    {
        /* Security Message is cached clear Security Message. */
        _security_module_clear_message(security_module_ptr);
    }

    /* Collect security events. */
    asc_result = _security_module_collect(security_module_ptr);
    if (asc_result == ASC_RESULT_EMPTY)
    {
        /* No security message */
        status = NX_AZURE_IOT_SUCCESS;
    }
    else if (asc_result != ASC_RESULT_OK)
    {
        status = NX_AZURE_IOT_FAILURE;
        LogError(LogLiteralArgs("Core failed to collect security message, error=%d"), status);
        goto error;
    }

    /* Reevaluate Security Module State */
    if (_security_module_exists_connected_iot_hub(security_module_ptr->nx_azure_iot_ptr))
    {
        /* Security Module is able to send security messages. */

        /* Update security Module state to active. */
        if ((status = _security_module_update_state(security_module_ptr, SECURITY_MODULE_STATE_ACTIVE)))
        {
            LogError(LogLiteralArgs("Failed to update IoT Security state, error=%d"), status);
            goto error;
        }
    }

     /* Get current timestamp. */
    if (_security_module_unix_time_get(&now_timestamp) == (uint32_t)-1)
    {
        status = NX_AZURE_IOT_FAILURE;
        LogError(LogLiteralArgs("Failed to retrieve timestamp, error=%d"), status);
        goto error;
    }

    if (now_timestamp - security_module_ptr->state_timestamp > ASC_SECURITY_MODULE_PENDING_TIME)
    {
        /* Security Module pending state time expired. */

        /* Update security Module state to suspend. */
        if ((status = _security_module_update_state(security_module_ptr, SECURITY_MODULE_STATE_SUSPENDED)))
        {
            LogError(LogLiteralArgs("Failed to update Security Module state, error=%d"), status);
            goto error;
        }
    }

error:
    if (status != NX_AZURE_IOT_SUCCESS)
    {
        LogError(LogLiteralArgs("Failed to process security module pending state, error=%d"), status);
    }

    return status;
}


static UINT _security_module_event_process_state_active(NX_AZURE_IOT_SECURITY_MODULE *security_module_ptr)
{
UINT status = NX_AZURE_IOT_SUCCESS;
asc_result_t asc_result = ASC_RESULT_OK;
security_message_t *security_message_ptr = &security_module_ptr->security_message;
NX_AZURE_IOT_RESOURCE *resource_ptr;

    if (security_message_is_empty(security_message_ptr))
    {
        asc_result = _security_module_collect(security_module_ptr);
    }

    if (asc_result == ASC_RESULT_EMPTY)
    {
        /* Security message has no events, skip. */
    }
    else if (asc_result == ASC_RESULT_OK)
    {
        /* Send security message to IoT Hubs.  */

        /* If exists at least one connected IoT Hub, Security Module will remain in active state. */
        bool exists_connected_iot_hub = false;

        /* Iterate over all NX_AZURE_IOT_HUB_CLIENT instances. */
        for (resource_ptr = security_module_ptr->nx_azure_iot_ptr->nx_azure_iot_resource_list_header;
            resource_ptr != NX_NULL;
            resource_ptr = resource_ptr->resource_next)
        {
            /* Filter only IoT Hub resources */
            if (resource_ptr->resource_type == NX_AZURE_IOT_RESOURCE_IOT_HUB)
            {
                NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr = (NX_AZURE_IOT_HUB_CLIENT *)resource_ptr->resource_data_ptr;

                /* Filter only connected IoT Hubs. */
                if (hub_client_ptr->nx_azure_iot_hub_client_state == NX_AZURE_IOT_HUB_CLIENT_STATUS_CONNECTED)
                {
                    exists_connected_iot_hub = true;

                    /*
                        Skip resource iff a security message is already been sent to this specific device. Avoid
                        sending security message to a Device Identity and to his Module Identities if both connected.
                    */
                    bool skip_resource = false;

                    if (resource_ptr != security_module_ptr->nx_azure_iot_ptr->nx_azure_iot_resource_list_header)
                    {
                         /* Iterate over previous seen IoT Hub resources and send Security Message only for unique devices. */
                        for (NX_AZURE_IOT_RESOURCE *prev_resource_ptr = security_module_ptr->nx_azure_iot_ptr->nx_azure_iot_resource_list_header;
                            prev_resource_ptr != resource_ptr;
                            prev_resource_ptr = prev_resource_ptr->resource_next)
                        {
                            NX_AZURE_IOT_HUB_CLIENT *prev_hub_client_ptr = (NX_AZURE_IOT_HUB_CLIENT *)prev_resource_ptr->resource_data_ptr;

                            if (az_span_is_content_equal(
                                    hub_client_ptr->iot_hub_client_core._internal.iot_hub_hostname,
                                    prev_hub_client_ptr->iot_hub_client_core._internal.iot_hub_hostname
                                ) && az_span_is_content_equal(
                                    hub_client_ptr->iot_hub_client_core._internal.device_id,
                                    prev_hub_client_ptr->iot_hub_client_core._internal.device_id
                                ))
                            {
                                skip_resource = true;
                                break;
                            }
                        }
                    }

                    if (!skip_resource)
                    {
                        if ((status = _security_module_message_send(hub_client_ptr, security_message_ptr)))
                        {
                            LogError(LogLiteralArgs("Failed to send security message, error=%d"), status);
                        }
                    }
                }
            }
        }

        if (!exists_connected_iot_hub)
        {
            /* Update security Module state to pending. */
            if ((status = _security_module_update_state(security_module_ptr, SECURITY_MODULE_STATE_PENDING)))
            {
                LogError(LogLiteralArgs("Failed to update IoT Security state, error=%d"), status);
            }
        }

        if (status == NX_AZURE_IOT_SUCCESS)
        {
            _security_module_clear_message(security_module_ptr);
        }
    }
    else
    {
        status = NX_AZURE_IOT_FAILURE;
        LogError(LogLiteralArgs("Security Module event process failed, error=%d"), status);
    }

    return status;
}


static UINT _security_module_event_process_state_suspended(NX_AZURE_IOT_SECURITY_MODULE *security_module_ptr)
{
UINT status = NX_AZURE_IOT_SUCCESS;

    /* Reevaluate Security Module State */
    if (_security_module_exists_connected_iot_hub(security_module_ptr->nx_azure_iot_ptr))
    {
        /* Security Module is able to send security messages. */

        /* Update security Module state to active. */
        if ((status = _security_module_update_state(security_module_ptr, SECURITY_MODULE_STATE_ACTIVE)))
        {
            LogError(LogLiteralArgs("Failed to update IoT Security state, error=%d"), status);
        }
    }

    return status;
}


static UINT _security_module_message_send(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr, security_message_t *security_message_ptr)
{
UINT status = NX_AZURE_IOT_SUCCESS;
NX_PACKET *packet_ptr = NULL;

    /* Create a telemetry message packet. */
    if ((status = nx_azure_iot_hub_client_telemetry_message_create(hub_client_ptr,
                                                                &packet_ptr,
                                                                NX_NO_WAIT)))
    {
        LogError(LogLiteralArgs("Security Message telemetry message create failed, error=%d"), status);
        return status;
    }

    /* Add properties to telemetry message. */
    for (int index = 0; index < MAX_PROPERTY_COUNT; index++)
    {
        if ((status =
                nx_azure_iot_hub_client_telemetry_property_add(packet_ptr,
                                                            (UCHAR*)telemetry_headers[index][0],
                                                            (USHORT)strlen(telemetry_headers[index][0]),
                                                            (UCHAR *)telemetry_headers[index][1],
                                                            (USHORT)strlen(telemetry_headers[index][1]),
                                                            NX_NO_WAIT)))
        {
            LogError(LogLiteralArgs("Failed to add telemetry property, error=%d"), status);

            /* Remove resources. */
            nx_azure_iot_hub_client_telemetry_message_delete(packet_ptr);

            return status;
        }
    }

    UCHAR *data = security_message_ptr->data;
    size_t data_length = security_message_ptr->size;

    if ((status = nx_azure_iot_hub_client_telemetry_send(hub_client_ptr,
                                                         packet_ptr,
                                                         data,
                                                         data_length,
                                                         NX_NO_WAIT)))
    {
        LogError(LogLiteralArgs("Failed to send Security Message, error=%d"), status);

        /* Delete telemetry message */
        nx_azure_iot_hub_client_telemetry_message_delete(packet_ptr);
    }
    else
    {
        /* packet_ptr will be released `nx_azure_iot_hub_client_telemetry_send`. */
        LogDebug(LogLiteralArgs("Security Message has been sent successfully"));
    }

    return status;
}


static VOID _security_module_clear_message(NX_AZURE_IOT_SECURITY_MODULE *security_module_ptr)
{
security_message_t *security_message_ptr = &security_module_ptr->security_message;

    /* Clear security message */
    core_message_deinit(security_module_ptr->core_ptr);

    security_message_clear(security_message_ptr);
    security_message_ptr = NULL;
}


static asc_result_t _security_module_collect(NX_AZURE_IOT_SECURITY_MODULE *security_module_ptr)
{
asc_result_t asc_result = ASC_RESULT_OK;
security_message_t *security_message_ptr = &security_module_ptr->security_message;

    /* Collect security events. */
    asc_result = core_collect(security_module_ptr->core_ptr);
    if (asc_result == ASC_RESULT_EMPTY)
    {
        /* No events found */
        return ASC_RESULT_OK;
    }
    else if (asc_result != ASC_RESULT_OK)
    {
        LogError(LogLiteralArgs("Core failed to collect events, error=%d"), asc_result);
        return asc_result;
    }

    /* Sign and retrieve Security Message. */
    asc_result = core_message_get(security_module_ptr->core_ptr,  security_message_ptr);
    if (asc_result == ASC_RESULT_EMPTY)
    {
        /* No events found */
    }
    else if (asc_result != ASC_RESULT_OK)
    {
        LogError(LogLiteralArgs("Core failed to set security message, error=%d"), asc_result);
        return asc_result;
    }

    return asc_result;
}


static UINT _security_module_update_state(NX_AZURE_IOT_SECURITY_MODULE *security_module_ptr, security_module_state_t state)
{
UINT status = NX_AZURE_IOT_SUCCESS;

    if (security_module_ptr->state == state)
    {
        /* Security Module is already set to given state. */
        goto cleanup;
    }

    /* Set security module state timestamp. */
    if (itime_time(&(security_module_ptr->state_timestamp)) == (uint32_t)-1)
    {
        status = NX_AZURE_IOT_FAILURE;
        LogError(LogLiteralArgs("Failed to retrive time"));
        goto cleanup;
    }

    /* Set security module state. */
    security_module_ptr->state = state;

cleanup:
    if (status != NX_AZURE_IOT_SUCCESS)
    {
        LogError(LogLiteralArgs("Failed to update Security Message state, error=%d"), status);
    }

    return status;
}


static bool _security_module_exists_connected_iot_hub(NX_AZURE_IOT *nx_azure_iot_ptr)
{
NX_AZURE_IOT_RESOURCE *resource_ptr;

    /* Iterate over all NX_AZURE_IOT_HUB_CLIENT instances. */
    for (resource_ptr = nx_azure_iot_ptr->nx_azure_iot_resource_list_header;
        resource_ptr != NX_NULL;
        resource_ptr = resource_ptr->resource_next)
    {
        if (resource_ptr->resource_type == NX_AZURE_IOT_RESOURCE_IOT_HUB)
        {
            NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr = (NX_AZURE_IOT_HUB_CLIENT *)resource_ptr->resource_data_ptr;

            /* Check IoT Hub client connectivity. */
            if (hub_client_ptr->nx_azure_iot_hub_client_state == NX_AZURE_IOT_HUB_CLIENT_STATUS_CONNECTED)
            {
                return true;
            }
        }
    }

    return false;
}