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

#include <stdio.h>
#include <setjmp.h>
#include <cmocka.h>  /* macros: https://api.cmocka.org/group__cmocka__asserts.html */

#include "nx_api.h"
#include "nx_azure_iot_hub_client.h"
#include "nx_azure_iot_cert.h"
#include "nx_azure_iot_ciphersuites.h"


#define DEMO_DHCP_DISABLE
#define DEMO_IPV4_ADDRESS         IP_ADDRESS(192, 168, 100, 33)
#define DEMO_IPV4_MASK            0xFFFFFF00UL
#define DEMO_GATEWAY_ADDRESS      IP_ADDRESS(192, 168, 100, 1)
#define DEMO_DNS_SERVER_ADDRESS   IP_ADDRESS(192, 168, 100, 1)
#define NETWORK_DRIVER            _nx_ram_network_driver

/* Include main.c in the test case since we need to disable DHCP in this test. */
#include "main.c"

#define C2D_TOPIC                 "devices/device_id/messages/devicebound/"

#define STRING_UNSIGNED_ARGS(s) (UCHAR *)s, strlen(s)

#ifndef DEMO_CLOUD_STACK_SIZE
#define DEMO_CLOUD_STACK_SIZE   2048
#endif /* DEMO_CLOUD_STACK_SIZE */

#ifndef DEMO_CLOUD_THREAD_PRIORITY
#define DEMO_CLOUD_THREAD_PRIORITY  (4)
#endif /* DEMO_CLOUD_THREAD_PRIORITY */

#ifndef MAXIMUM_PROPERTY_LENGTH
#define MAXIMUM_PROPERTY_LENGTH 1400 /* packet size */
#endif /* MAXIMUM_PROPERTY_LENGTH */

typedef struct
{
    UCHAR *name;
    USHORT name_length;
    UCHAR *value;
    USHORT value_length;
} PROPERTY;

#define PROPERTY_INIT(name, value) {(name), sizeof(name) - 1, (value), sizeof(value) - 1}

static VOID initialize_data();
static VOID empty_property_test();
static VOID multiple_properties_test();
static VOID construct_c2d_packet(NX_PACKET **packet_pptr, PROPERTY *properties, UINT property_count,
                                 UCHAR *message_payload_ptr, ULONG message_payload_length);
extern UINT _nxd_mqtt_client_append_message(NXD_MQTT_CLIENT *client_ptr, NX_PACKET *packet_ptr, CHAR *message,
                                            UINT length, ULONG wait_option);
extern UINT _nxd_mqtt_client_set_fixed_header(NXD_MQTT_CLIENT *client_ptr, NX_PACKET *packet_ptr,
                                              UCHAR control_header, UINT length, UINT wait_option);

static NX_AZURE_IOT iot;
static NX_AZURE_IOT_HUB_CLIENT iot_client;
static NX_SECURE_X509_CERT root_ca_cert;
static UCHAR metadata_buffer[NX_AZURE_IOT_TLS_METADATA_BUFFER_SIZE];
static ULONG demo_cloud_thread_stack[DEMO_CLOUD_STACK_SIZE / sizeof(ULONG)];
static UCHAR property_name[MAXIMUM_PROPERTY_LENGTH];
static UCHAR property_value[MAXIMUM_PROPERTY_LENGTH];
static UCHAR message_payload[32];

VOID demo_entry(NX_IP* ip_ptr, NX_PACKET_POOL* pool_ptr, NX_DNS* dns_ptr, UINT (*unix_time_callback)(ULONG *unix_time))
{
CHAR *host_name = "host_name";
CHAR *device_id = "device_id";
CHAR *module_id = "module_id";
CHAR *symmetric_key = "symmetric_key";
ULONG pool_ptr_available_packet;

    /* Initialize root certificate.  */
    assert_int_equal(nx_secure_x509_certificate_initialize(&root_ca_cert, (UCHAR *)_nx_azure_iot_root_cert, (USHORT)_nx_azure_iot_root_cert_size,
                                                           NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE),
                     NX_AZURE_IOT_SUCCESS);
                     
    assert_int_equal(nx_azure_iot_create(&iot, (UCHAR *)"Azure IoT", ip_ptr, pool_ptr, dns_ptr, (UCHAR *)demo_cloud_thread_stack,
                                         sizeof(demo_cloud_thread_stack), DEMO_CLOUD_THREAD_PRIORITY, unix_time_callback),
                     NX_AZURE_IOT_SUCCESS);

    /* Record number of available packet before test */
    pool_ptr_available_packet = pool_ptr -> nx_packet_pool_available;

    assert_int_equal(nx_azure_iot_hub_client_initialize(&iot_client, &iot,
                                                        STRING_UNSIGNED_ARGS(host_name),
                                                        STRING_UNSIGNED_ARGS(device_id),
                                                        STRING_UNSIGNED_ARGS(""),
                                                        _nx_azure_iot_tls_supported_crypto,
                                                        _nx_azure_iot_tls_supported_crypto_size,
                                                        _nx_azure_iot_tls_ciphersuite_map,
                                                        _nx_azure_iot_tls_ciphersuite_map_size,
                                                        metadata_buffer, sizeof(metadata_buffer),
                                                        &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);


    /* Perform actual tests. */
    initialize_data();
    empty_property_test();
    multiple_properties_test();


    assert_int_equal(nx_azure_iot_hub_client_deinitialize(&iot_client),
                     NX_AZURE_IOT_SUCCESS);

    /* Check if all the packet are released */
    assert_int_equal(pool_ptr -> nx_packet_pool_available, pool_ptr_available_packet);

    assert_int_equal(nx_azure_iot_delete(&iot), NX_AZURE_IOT_SUCCESS);
}

static VOID initialize_data()
{
UINT i;

    for (i = 0; i < MAXIMUM_PROPERTY_LENGTH; i++)
    {
        property_name[i] = (NX_RAND() % 26) + 'a';
        property_value[i] = (NX_RAND() % 26) + 'a';
    }

    for (i = 0; i < sizeof(message_payload); i++)
    {
        message_payload[i] = (NX_RAND() % 26) + 'a';
    }
}

static VOID construct_c2d_packet(NX_PACKET **packet_pptr, PROPERTY *properties, UINT property_count,
                                 UCHAR *message_payload_ptr, ULONG message_payload_length)
{
NX_PACKET *packet_ptr;
ULONG topic_length = sizeof(C2D_TOPIC) - 1;
ULONG total_length;
UCHAR bytes[2];
UINT i;

    assert_int_equal(nx_packet_allocate(iot.nx_azure_iot_pool_ptr, &packet_ptr, 0, NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);

    for (i = 0; i < property_count; i++)
    {
        topic_length += properties[i].name_length + properties[i].value_length + 2; /* '=' and '&' */
    }

    if (property_count)
    {
        topic_length--; /* Reduce by one since last '&' is not needed. */
    }
    total_length = topic_length + 2 + 2 + message_payload_length; /* Two bytes for fixed topic_length field
                                                                     and two bytes for packet id. */

    /* Set fixed header. */
    assert_int_equal(_nxd_mqtt_client_set_fixed_header(&(iot_client.nx_azure_iot_hub_client_resource.resource_mqtt), packet_ptr,
                                                       (UCHAR)((MQTT_CONTROL_PACKET_TYPE_PUBLISH << 4) | MQTT_PUBLISH_QOS_LEVEL_1),
                                                       total_length, NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);

    /* Set topic length. */
    bytes[0] = (topic_length >> 8) & 0xFF;
    bytes[1] = topic_length & 0xFF;
    assert_int_equal(nx_packet_data_append(packet_ptr, bytes, sizeof(bytes),
                                           iot.nx_azure_iot_pool_ptr, NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);

    /* Set topic. */
    assert_int_equal(nx_packet_data_append(packet_ptr, C2D_TOPIC, sizeof(C2D_TOPIC) - 1,
                                           iot.nx_azure_iot_pool_ptr, NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);
    for (i = 0; i < property_count; i++)
    {
        if (i != 0)
        {
            assert_int_equal(nx_packet_data_append(packet_ptr, "&", 1,
                                                   iot.nx_azure_iot_pool_ptr, NX_NO_WAIT),
                             NX_AZURE_IOT_SUCCESS);
        }
        assert_int_equal(nx_packet_data_append(packet_ptr, properties[i].name, properties[i].name_length,
                                               iot.nx_azure_iot_pool_ptr, NX_NO_WAIT),
                         NX_AZURE_IOT_SUCCESS);
        assert_int_equal(nx_packet_data_append(packet_ptr, "=", 1,
                                               iot.nx_azure_iot_pool_ptr, NX_NO_WAIT),
                         NX_AZURE_IOT_SUCCESS);
        assert_int_equal(nx_packet_data_append(packet_ptr, properties[i].value, properties[i].value_length,
                                               iot.nx_azure_iot_pool_ptr, NX_NO_WAIT),
                         NX_AZURE_IOT_SUCCESS);
    }

    /* Set packet ID. The value does not matter. */
    assert_int_equal(nx_packet_data_append(packet_ptr, bytes, sizeof(bytes),
                                           iot.nx_azure_iot_pool_ptr, NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);

    /* Set message payload. */
    if (message_payload_length > 0)
    {
        assert_int_equal(nx_packet_data_append(packet_ptr, message_payload_ptr, message_payload_length,
                                               iot.nx_azure_iot_pool_ptr, NX_NO_WAIT),
                         NX_AZURE_IOT_SUCCESS);
    }

    *packet_pptr = packet_ptr;
}

static VOID empty_property_test()
{
NX_PACKET *packet_ptr;
CHAR *fake_property_name = "fake_property_name";
USHORT result_size;
const UCHAR *result;

    /* No properties are added. */
    construct_c2d_packet(&packet_ptr, NX_NULL, 0, NX_NULL, 0);

    /* Search for NX_NULL. */
    assert_int_not_equal(nx_azure_iot_hub_client_cloud_message_property_get(&iot_client, packet_ptr, NX_NULL,
                                                                            0, &result, &result_size),
                         NX_AZURE_IOT_SUCCESS);
                         
    /* Search for a property does not existed. */
    assert_int_not_equal(nx_azure_iot_hub_client_cloud_message_property_get(&iot_client, packet_ptr, fake_property_name,
                                                                            (USHORT)strlen(fake_property_name),
                                                                            &result, &result_size),
                         NX_AZURE_IOT_SUCCESS);

    nx_packet_release(packet_ptr);
}

static VOID multiple_properties_test()
{
NX_PACKET *packet_ptr;
CHAR *fake_property_name = "fake_property_name";
USHORT result_size;
const UCHAR *result;
ULONG fixed_property_length = 10;
PROPERTY property_0 = PROPERTY_INIT("property_name_0", "property_value_0");
PROPERTY property_1 = PROPERTY_INIT("property_name_1", "property_value_1");
PROPERTY property_random = {property_name, 0, property_value, 0};
PROPERTY properties[3];
ULONG message_payload_length;
UINT property_count;
UINT i, j, k, l;

    for (i = 0; i < 2; i++)
    {

        if (i == 0)
        {

            /* First round, length of property name is variable.
             * Length of property value is fixed. */
            property_random.value_length = fixed_property_length;
        }
        else
        {

            /* Second round, length of property name is fixed.
             * Length of property value is variable. */
            property_random.name_length = fixed_property_length;
        }

        for (j = 1; j < MAXIMUM_PROPERTY_LENGTH; j++)
        {
            if (i == 0)
            {

                /* First round, length of property name is variable.
                 * Length of property value is fixed. */
                property_random.name_length = j;
            }
            else
            {

                /* Second round, length of property name is fixed.
                 * Length of property value is variable. */
                property_random.value_length = j;
            }

            for (k = 0; k < 4; k++)
            {

                /* For each random property, test the following situations.
                 * 1. One property with random length.
                 * 2. Three properties. The first one with random length and last two with fixed lengths.
                 * 3. Three properties. The first and last with fixed lengths, the middle one with random length.
                 * 4. Three properties. The first two with fixed lengths, the last one with random length. */
                if (k == 0)
                {

                    /* Test only one random length property. */
                    property_count = 1;
                    properties[0] = property_random;
                }
                else
                {

                    /* Test three properties with different sequence. */
                    property_count = 3;
                    if (k == 1)
                    {
                        properties[0] = property_random;
                        properties[1] = property_0;
                        properties[2] = property_1;
                    }
                    else if (k == 2)
                    {
                        properties[0] = property_0;
                        properties[1] = property_random;
                        properties[2] = property_1;
                    }
                    else
                    {
                        properties[0] = property_0;
                        properties[1] = property_1;
                        properties[2] = property_random;
                    }
                }

                message_payload_length = (NX_RAND() & 31);
                construct_c2d_packet(&packet_ptr, properties, property_count, message_payload, message_payload_length);

                /* Search for a property does not existed. */
                assert_int_not_equal(nx_azure_iot_hub_client_cloud_message_property_get(&iot_client, packet_ptr, fake_property_name,
                                                                                        (USHORT)strlen(fake_property_name),
                                                                                        &result, &result_size),
                                     NX_AZURE_IOT_SUCCESS);

                /* Verify all properties. */
                for (l = 0; l < property_count; l++)
                {

                    /* Search for an existing property. */
                    assert_int_equal(nx_azure_iot_hub_client_cloud_message_property_get(&iot_client, packet_ptr, properties[l].name,
                                                                                        properties[l].name_length,
                                                                                        &result, &result_size),
                                     NX_AZURE_IOT_SUCCESS);
                    assert_int_equal(properties[l].value_length, result_size);
                    assert_memory_equal(properties[l].value, result, result_size);
                }

                nx_packet_release(packet_ptr);
            }
        }
    }
}
