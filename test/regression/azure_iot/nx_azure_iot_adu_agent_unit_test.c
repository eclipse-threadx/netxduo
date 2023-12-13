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

#include "azure/core/az_span.h"
#include "nx_api.h"
#include "nx_packet.h"
#include "nx_azure_iot_adu_agent.h"
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

#ifndef DEMO_CLOUD_STACK_SIZE
#define DEMO_CLOUD_STACK_SIZE           2048
#endif /* DEMO_CLOUD_STACK_SIZE */

#ifndef DEMO_CLOUD_THREAD_PRIORITY
#define DEMO_CLOUD_THREAD_PRIORITY      (4)
#endif /* DEMO_CLOUD_THREAD_PRIORITY */

#ifndef MAXIMUM_PAYLOAD_LENGTH
#define MAXIMUM_PAYLOAD_LENGTH          10240
#endif /* MAXIMUM_PAYLOAD_LENGTH */

#define STRING_UNSIGNED_ARGS(s) (UCHAR *)s, sizeof(s) - 1

#define MQTT_CLIENT_GET(c)              ((c) -> nx_azure_iot_hub_client_resource.resource_mqtt)
#define TX_MUTEX_GET(c)                 ((c) -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr)

/* Device properties.  */
#define SAMPLE_DEVICE_MANUFACTURER              "Contoso"
#define SAMPLE_DEVICE_MODEL                     "IoTDevice"
#define SAMPLE_DEVICE_INSTALLED_CRITERIA        "6.1.0"
#define SAMPLE_DEVICE_INSTALLED_CRITERIA_NEW    "7.0.0"

#define SAMPLE_LEAF_DEVICE_MANUFACTURER         "Contoso"
#define SAMPLE_LEAF_DEVICE_MODEL                "IoTDevice-Leaf"
#define SAMPLE_LEAF_DEVICE_INSTALLED_CRITERIA   "1.0.0"

#define SAMPLE_LEAF2_DEVICE_MANUFACTURER        "Contoso"
#define SAMPLE_LEAF2_DEVICE_MODEL               "IoTDevice-Leaf2"
#define SAMPLE_LEAF2_DEVICE_INSTALLED_CRITERIA  "1.0.0"

typedef VOID (*NX_AZURE_TEST_FN)();

static ULONG network_bytes_generate_stack[DEMO_HELPER_STACK_SIZE / sizeof(ULONG)];
static TX_THREAD network_bytes_generate_thread;

static const CHAR *g_expected_message = NX_NULL;
static UINT g_expected_message_index = 0;
static const UCHAR g_hostname[] = "unit-test.iot-azure.com";
static const UCHAR g_device_id[] = "unit_test_device";
static const UCHAR g_pnp_model_id[] = "pnp_model_id_unit_test";
static const UCHAR g_symmetric_key[] = "6CLK6It9jOiABpFVu11CQDv9O49ebAneK3KbsvaoU1o=";
static const CHAR reported_property_success_topic[] = "$iothub/twin/res/204/?$rid=%d&$version=6";
static UINT reported_property_success_topic_count;

/* Startup message, such as: "{\"deviceUpdate\":{\"__t\":\"c\",\"agent\":{\"deviceProperties\":{\"manufacturer\":\"Contoso\",\"model\":\"IoTDevice\",\"contractModelId\":\"dtmi:azure:iot:deviceUpdateContractModel;2\",\"aduVer\":\"AzureRTOS;agent/6.2.0\"},\"compatPropertyNames\":\"manufacturer,model\"}}}" */
static const UCHAR g_adu_agent_reported_property_startup1[] = "{\"deviceUpdate\":{\"__t\":\"c\",\"agent\":{\"deviceProperties\":{\"manufacturer\":\"Contoso\",\"model\":\"IoTDevice\",\"contractModelId\":\"dtmi:azure:iot:deviceUpdateContractModel;2\",\"aduVer\":\"AzureRTOS;agent/";
static const UCHAR g_adu_agent_reported_property_startup2[] = "\"},\"compatPropertyNames\":\"manufacturer,model\"}}}";
static UCHAR g_adu_agent_reported_property_startup[300];

static const CHAR g_adu_agent_new_udpate_topic[] = "$iothub/twin/PATCH/properties/desired/?$version=6";
static const UCHAR g_adu_agent_new_udpate_1[] = "{\"deviceUpdate\":{\"service\":{\"workflow\":{\"action\":3,\"id\":\"25ed0df8-4e9a-42d8-bde6-cf78c1c1555c\"},\"updateManifest\":\"{\\\"manifestVersion\\\":\\\"4\\\",\\\"updateId\\\":{\\\"provider\\\":\\\"Contoso\\\",\\\"name\\\":\\\"IoTDevice\\\",\\\"version\\\":\\\"8.0.0\\\"},\\\"compatibility\\\":[{\\\"manufacturer\\\":\\\"Contoso\\\",\\\"model\\\":\\\"IoTDevice\\\"}],\\\"instructions\\\":{\\\"steps\\\":[{\\\"handler\\\":\\\"microsoft/swupdate:1\\\",\\\"files\\\":[\\\"f54c62cc342281d4c\\\"],\\\"handlerProperties\\\":{\\\"installedCriteria\\\":\\\"7.0.0\\\"}}]},\\\"files\\\":{\\\"f54c62cc342281d4c\\\":{\\\"fileName\\\":\\\"firmware_7.0.0.bin\\\",\\\"sizeInBytes\\\":1978,\\\"hashes\\\":{\\\"sha256\\\":\\\"qr+xRWnfo/POaFNv+KVddBsJngGxCiSQ25WEW8t4dLc=\\\"}}},\\\"createdDateTime\\\":\\\"2022-11-09T10:42:02.5542967Z\\\"}\",\"updateManifestSignature\":\"eyJhbGciOiJSUzI1NiIsInNqd2siOiJleUpoYkdjaU9pSlNVekkxTmlJc0ltdHBaQ0k2SWtGRVZTNHlNREEzTURJdVVpSjkuZXlKcmRIa2lPaUpTVTBFaUxDSnVJam9pYkV4bWMwdHZPRmwwWW1Oak1sRXpUalV3VlhSTVNXWlhVVXhXVTBGRlltTm9LMFl2WTJVM1V6Rlpja3BvV0U5VGNucFRaa051VEhCVmFYRlFWSGMwZWxndmRHbEJja0ZGZFhrM1JFRmxWVzVGU0VWamVEZE9hM2QzZVRVdk9IcExaV3AyWTBWWWNFRktMMlV6UWt0SE5FVTBiMjVtU0ZGRmNFOXplSGRQUzBWbFJ6QkhkamwzVjB3emVsUmpUblprUzFoUFJGaEdNMVZRWlVveGIwZGlVRkZ0Y3pKNmJVTktlRUppZEZOSldVbDBiWFpwWTNneVpXdGtWbnBYUm5jdmRrdFVUblZMYXpob2NVczNTRkptYWs5VlMzVkxXSGxqSzNsSVVVa3dZVVpDY2pKNmEyc3plR2d4ZEVWUFN6azRWMHBtZUdKamFsQnpSRTgyWjNwWmVtdFlla05OZW1Fd1R6QkhhV0pDWjB4QlZGUTVUV1k0V1ZCd1dVY3lhblpQWVVSVmIwTlJiakpWWTFWU1RtUnNPR2hLWW5scWJscHZNa3B5SzFVNE5IbDFjVTlyTjBZMFdubFRiMEoyTkdKWVNrZ3lXbEpTV2tab0wzVlRiSE5XT1hkU2JWbG9XWEoyT1RGRVdtbHhhemhJVWpaRVUyeHVabTVsZFRJNFJsUm9SVzF0YjNOVlRUTnJNbGxNYzBKak5FSnZkWEIwTTNsaFNEaFpia3BVTnpSMU16TjFlakU1TDAxNlZIVnFTMmMzVkdGcE1USXJXR0owYmxwRU9XcFVSMkY1U25Sc2FFWmxWeXRJUXpVM1FYUkJSbHBvY1ZsM2VVZHJXQ3M0TTBGaFVGaGFOR0V4VHpoMU1qTk9WVWQxTWtGd04yOU5NVTR3ZVVKS0swbHNUM29pTENKbElqb2lRVkZCUWlJc0ltRnNaeUk2SWxKVE1qVTJJaXdpYTJsa0lqb2lRVVJWTGpJeE1EWXdPUzVTTGxNaWZRLlJLS2VBZE02dGFjdWZpSVU3eTV2S3dsNFpQLURMNnEteHlrTndEdkljZFpIaTBIa2RIZ1V2WnoyZzZCTmpLS21WTU92dXp6TjhEczhybXo1dnMwT1RJN2tYUG1YeDZFLUYyUXVoUXNxT3J5LS1aN2J3TW5LYTNkZk1sbkthWU9PdURtV252RWMyR0hWdVVTSzREbmw0TE9vTTQxOVlMNThWTDAtSEthU18xYmNOUDhXYjVZR08xZXh1RmpiVGtIZkNIU0duVThJeUFjczlGTjhUT3JETHZpVEtwcWtvM3RiSUwxZE1TN3NhLWJkZExUVWp6TnVLTmFpNnpIWTdSanZGbjhjUDN6R2xjQnN1aVQ0XzVVaDZ0M05rZW1UdV9tZjdtZUFLLTBTMTAzMFpSNnNTR281azgtTE1sX0ZaUmh4djNFZFNtR2RBUTNlMDVMRzNnVVAyNzhTQWVzWHhNQUlHWmcxUFE3aEpoZGZHdmVGanJNdkdTSVFEM09wRnEtZHREcEFXbUo2Zm5sZFA1UWxYek5tQkJTMlZRQUtXZU9BYjh0Yjl5aVhsemhtT1dLRjF4SzlseHpYUG9GNmllOFRUWlJ4T0hxTjNiSkVISkVoQmVLclh6YkViV2tFNm4zTEoxbkd5M1htUlVFcER0Umdpa0tBUzZybFhFT0VneXNjIn0.eyJzaGEyNTYiOiJ1MTVFa25xNDBvcUV4Z25yZVRyaVFVZ25COW5qcGFnU3JsNlVQNDJ1YWw4PSJ9.TOtLVW-wgMFUzonOn5Os5_bY6hjpeW3MW1votMDuc1jTlrAS9xpLLEFbJJhlaFQdKWjpoWNPS9HnwjgWVQhGh_-PrvVB5CUegKkJZfCY_xlJGPrs2ydYeVqHKbY4bX37Uw3uCaHYI6021unkLjywV_eXVIJ0tT4DKXrMcmPED_isI63rTIUDe0tBUwGtyNu_PobMOE-6MZRZ3tDXYe7xKSvKJVg-nhKsG6-mdE9r44nvTA3I-SIpwp1PJMjzNWmXBXZNaJISs-K7O0LK1X0i4muO1F42qMYqP41xbYGtaof92LksfZTk7KhSgfXbj4-K6VslrGvTYf2oRNCrZXoDyGa9aQuI8gOdSDVSyV1nOafSgBseV9QqxxYXZoDq2SAx87c8mOKAYFjUevZ1FRqEeNQA5eiv-EysbCrknGVG7ueGUVj8bGeFB1-90OOY2AlJQoSvwR_Fc2MNBpPbr6ZIhy9Tg_UXPn1xSs8skG8Oq-R1wm0ghXDR7-yDNtTAZ2f6\",\"fileUrls\":{\"f54c62cc342281d4c\":\"http://jackyztest--jackyztest.b.nlu.dl.adu.microsoft.com/southeastasia/jackyztest--jackyztest/6c1f3eadc320465694af478f67b41dd1/firmware_7.0.0.bin\"}},\"__t\":\"c\"},\"$version\":6}";
static const UCHAR g_adu_agent_new_udpate_2[] = "{\"deviceUpdate\":{\"__t\":\"c\",\"service\":{\"workflow\":{\"action\":3,\"id\":\"3c192285-1bce-4d57-9486-07991fc74fb0\"},\"updateManifest\":\"{\\\"manifestVersion\\\":\\\"5\\\",\\\"updateId\\\":{\\\"provider\\\":\\\"Contoso\\\",\\\"name\\\":\\\"IoTDevice\\\",\\\"version\\\":\\\"12.1.1\\\"},\\\"compatibility\\\":[{\\\"manufacturer\\\":\\\"Contoso\\\",\\\"model\\\":\\\"IoTDevice\\\"}],\\\"instructions\\\":{\\\"steps\\\":[{\\\"handler\\\":\\\"microsoft/swupdate:1\\\",\\\"files\\\":[\\\"f1d70776744216017\\\"],\\\"handlerProperties\\\":{\\\"installedCriteria\\\":\\\"12.1.1\\\"}}]},\\\"files\\\":{\\\"f1d70776744216017\\\":{\\\"fileName\\\":\\\"firmware_12.1.1.bin\\\",\\\"sizeInBytes\\\":16,\\\"hashes\\\":{\\\"sha256\\\":\\\"Fqv5r0ZD/x6ok0aRqJERX2JuW36O+GOxn0/r7aBJkOs=\\\"}}},\\\"createdDateTime\\\":\\\"2023-03-27T08:01:26.6316Z\\\"}\",\"updateManifestSignature\":\"eyJhbGciOiJSUzI1NiIsInNqd2siOiJleUpoYkdjaU9pSlNVekkxTmlJc0ltdHBaQ0k2SWtGRVZTNHlNREEzTURJdVVpSjkuZXlKcmRIa2lPaUpTVTBFaUxDSnVJam9pYmt0bVdVdEVSREF4VERoSldVaExTekV2WVhGTEwwMXBOWEpaUVdKd1RHcEVUM2g2VEZBelpHTmFLM0ZwWVZGRk5WZFhjazlZWTFndlZUaGFPR1l6ZDNseFJXRkVOVFpWYkRsYVowWnZNamN4TUhkd1lpOVlPRWRHTW5oQmQzbHhkMWR2YlV4SVltWnNNazlxYVU1R1ZtNW5ObXRIT1RZdlRVOXZjR2xQWXpsS1IwVkpiMjVXUkRoQ2NHeFJWRTV2TUM5UGVFcFNZVXBzWjNwMVdtbE9ZVFpLY2paT2NraDNaMmRDYVU1V05GcFlWa3hWT1ZCbGN6ZHhOVTFwTDI5ak1FZHFTbFF5V0dSd2RGVnZOVnBHUjNSV1REZENjREF5VEZseFZuVnFVblZsYkRsUlJHMVdjMUoxSzBoeWVEUmlibFpvY1dWWFNrc3pVazVDYWtsVmIxTmxVWFJaWkNzdlVUTXpaREkxVkVobmVGaHFhbkpLSzI5c01DOHJXREp6Vmk5QlZFUnlVaXRUTlRSaGJHRklhMXBuWldWcWRrOVBXVE13Ym1KNFJHZHpSVVpuTldnelVXTkhOR2gxVEU5elRXbzJWemg1Y1c5UU1VTmxPV1V3YzFVdlUzYzFXWHBCUW5SYWNWaFROVFE0YWtaelVHSmplbTF1UXpaVWFrTlFaVkprZFZsWlFXVk1ZekZDVm1OamIyTkVWRzVaWnpaMmNYcElNbUp5WWk5bE5GSm1SRzQ0WVN0aFQxRkdSWFZ6TTNCVmVqRmFNR1JJYUV4aVpHMUpkMkZMTjFCTksxRm5aVTlCWWt4dVVuTjJUamh4ZEVKM2IwWnZhbXBNVm10VWFHbENVQzl6T0ZOV2JXWkdOekpGTVRWeU9GSTVXRVZvV2xkMVpWZ3pVbllpTENKbElqb2lRVkZCUWlJc0ltRnNaeUk2SWxKVE1qVTJJaXdpYTJsa0lqb2lRVVJWTGpJeU1EVXdNeTVTTGxNaWZRLnlCblhub1FiTHZudHV4N3djaFh6a3lwX2ZLbGF2ZzhCMnJlQV9vNzFwWnlnd0x6RV9NM2xDM2tna1NQUHRvMEZkclFuWDZqS1lkdG1MUXVJVDVPdkdmR0d5MmIyTDJOa1VVZDZnSGs4SF9zTlFfS0ZEYkdFUWREczZGeHFGYkxrRHp6cktreXczSmxLWWRKUXJaLTFDTlZWc0FmSVVfb013YjYzQ2E5VEdrNWFqNlNMVWE1V1BWLW5Td2VQRHAzQ2YyV0ZCa09jdC1IMGtLTDlJeTI0Q01uT1IwVmVwYUlGZmk4anFDRVlwX1lrcUw3Z1VNRTFWT1ZGczFRTnFRZ0pLVDZDRnRjU3lGcFVVOXRITlgxWnhYdE1jcTNMR3M2Yk9NUjlvTXV5bDVfUE5OLXlWNTVJSFFNb3hXZkl3V1QwZTdXcGFsdzJJSW5LLUptWkVjYURPYkQyaWI1ZDZUTlduVnJXQ2JHaHRjejducG1fbTVMSlJkc1JUcC1DYWlSRkEtV3daQzRfSW9nTDZZMXFzb3lRb1kwTU04OFNhdl91b1p6VGYtenZZR0hJcGdhb1pnN1pzTGU0SGNSYzFSZGhNcUREWEw3UE9iX2ktbmVoNUEzV1pRczVkNGNmak5iRHI1c2I3QWdEMnZENGZFRXg0TmxpcE9nWWVESGNvRTRxIn0.eyJzaGEyNTYiOiJ3RkFVS0xXVmNxanMrZWNoRmJEWnVDQ2QyK2dRWkd4RmVad2FGNHlCR3pRPSJ9.FGPzrtKewHlWi-AQBgMKpeg4piX1PP3OZ-kHkviUi6MlKfwBSiLGVH1CszROLfvaJQAfsePAK_uCnGsQMXAsksi2Ci4jXeHZVnwtRwZk2bR8l-k-VG1v-fNDB43G2mThBQFabNwfzctqxTfpsD-7LEN4tAqKRf03DeMPMEfYukhwmehPRA5Nx0qwEzHaIdRic405bYN4yq-ZSMnfY-_x0ZzT52txlUt261pr-rWUeNRBnU67TXs3MKugXxK6kbL5b4W1JHVIxldGfXcCWB6UpXzEqugJbpGWluL4ILUIrGfzGhQxo_1k2umNhlDss8HnOe4UQByv7AoUiYUmx4TvuyZT3umvWHHtExsl1TO4EvhQ__iPpdUOTdoBQ1MK_NeOXzUtSDBvJEMRjybcUrB7FbpWnP49IGNLL1wpk2pwOa7N_Ez8sF8-EUjRjIH9dEmrJp3M4xwMkHl7h1zC7GKJ2ckZxqzuNLF7I1udfMY8ajhHVIVLzUcyNFIVUCg8ZSx1\",\"fileUrls\":{\"f1d70776744216017\":\"http://azurertos-adu--azurertos-adu.b.nlu.dl.adu.microsoft.com/eastus/azurertos-adu--azurertos-adu/3e80714356924d1e9f1975bafb7a6cd4/firmware_12.1.1.bin\"}}},\"$version\":6}";

/* Two steps/firmware.  */
static const UCHAR g_adu_agent_new_update_3[] = "{\"deviceUpdate\":{\"service\":{\"workflow\":{\"action\":3,\"id\":\"6b831565-bd1c-4b84-995a-f2ab4e6a4bb1\"},\"updateManifest\":\"{\\\"manifestVersion\\\":\\\"5\\\",\\\"updateId\\\":{\\\"provider\\\":\\\"Contoso\\\",\\\"name\\\":\\\"IoTDevice\\\",\\\"version\\\":\\\"7.0.1\\\"},\\\"compatibility\\\":[{\\\"manufacturer\\\":\\\"Contoso\\\",\\\"model\\\":\\\"IoTDevice\\\"}],\\\"instructions\\\":{\\\"steps\\\":[{\\\"type\\\":\\\"reference\\\",\\\"detachedManifestFileId\\\":\\\"f0df8c0e22a1b60c1\\\"},{\\\"handler\\\":\\\"microsoft/swupdate:1\\\",\\\"files\\\":[\\\"fba3f0b3def43a3a4\\\"],\\\"handlerProperties\\\":{\\\"installedCriteria\\\":\\\"7.0.1\\\"}}]},\\\"files\\\":{\\\"fba3f0b3def43a3a4\\\":{\\\"fileName\\\":\\\"firmware_7.0.1.bin\\\",\\\"sizeInBytes\\\":1978,\\\"hashes\\\":{\\\"sha256\\\":\\\"qr+xRWnfo/POaFNv+KVddBsJngGxCiSQ25WEW8t4dLc=\\\"}},\\\"f0df8c0e22a1b60c1\\\":{\\\"fileName\\\":\\\"contoso.iotdevice-leaf.7.0.1.updatemanifest5.json\\\",\\\"sizeInBytes\\\":601,\\\"hashes\\\":{\\\"sha256\\\":\\\"fP+yIYtGfsxMkL1iRS+olh+iXBebXYEapROyG6+nBjE=\\\"}}},\\\"createdDateTime\\\":\\\"2022-12-19T05:25:47.9977098Z\\\"}\",\"updateManifestSignature\":\"eyJhbGciOiJSUzI1NiIsInNqd2siOiJleUpoYkdjaU9pSlNVekkxTmlJc0ltdHBaQ0k2SWtGRVZTNHlNREEzTURJdVVpSjkuZXlKcmRIa2lPaUpTVTBFaUxDSnVJam9pYkV4bWMwdHZPRmwwWW1Oak1sRXpUalV3VlhSTVNXWlhVVXhXVTBGRlltTm9LMFl2WTJVM1V6Rlpja3BvV0U5VGNucFRaa051VEhCVmFYRlFWSGMwZWxndmRHbEJja0ZGZFhrM1JFRmxWVzVGU0VWamVEZE9hM2QzZVRVdk9IcExaV3AyWTBWWWNFRktMMlV6UWt0SE5FVTBiMjVtU0ZGRmNFOXplSGRQUzBWbFJ6QkhkamwzVjB3emVsUmpUblprUzFoUFJGaEdNMVZRWlVveGIwZGlVRkZ0Y3pKNmJVTktlRUppZEZOSldVbDBiWFpwWTNneVpXdGtWbnBYUm5jdmRrdFVUblZMYXpob2NVczNTRkptYWs5VlMzVkxXSGxqSzNsSVVVa3dZVVpDY2pKNmEyc3plR2d4ZEVWUFN6azRWMHBtZUdKamFsQnpSRTgyWjNwWmVtdFlla05OZW1Fd1R6QkhhV0pDWjB4QlZGUTVUV1k0V1ZCd1dVY3lhblpQWVVSVmIwTlJiakpWWTFWU1RtUnNPR2hLWW5scWJscHZNa3B5SzFVNE5IbDFjVTlyTjBZMFdubFRiMEoyTkdKWVNrZ3lXbEpTV2tab0wzVlRiSE5XT1hkU2JWbG9XWEoyT1RGRVdtbHhhemhJVWpaRVUyeHVabTVsZFRJNFJsUm9SVzF0YjNOVlRUTnJNbGxNYzBKak5FSnZkWEIwTTNsaFNEaFpia3BVTnpSMU16TjFlakU1TDAxNlZIVnFTMmMzVkdGcE1USXJXR0owYmxwRU9XcFVSMkY1U25Sc2FFWmxWeXRJUXpVM1FYUkJSbHBvY1ZsM2VVZHJXQ3M0TTBGaFVGaGFOR0V4VHpoMU1qTk9WVWQxTWtGd04yOU5NVTR3ZVVKS0swbHNUM29pTENKbElqb2lRVkZCUWlJc0ltRnNaeUk2SWxKVE1qVTJJaXdpYTJsa0lqb2lRVVJWTGpJeE1EWXdPUzVTTGxNaWZRLlJLS2VBZE02dGFjdWZpSVU3eTV2S3dsNFpQLURMNnEteHlrTndEdkljZFpIaTBIa2RIZ1V2WnoyZzZCTmpLS21WTU92dXp6TjhEczhybXo1dnMwT1RJN2tYUG1YeDZFLUYyUXVoUXNxT3J5LS1aN2J3TW5LYTNkZk1sbkthWU9PdURtV252RWMyR0hWdVVTSzREbmw0TE9vTTQxOVlMNThWTDAtSEthU18xYmNOUDhXYjVZR08xZXh1RmpiVGtIZkNIU0duVThJeUFjczlGTjhUT3JETHZpVEtwcWtvM3RiSUwxZE1TN3NhLWJkZExUVWp6TnVLTmFpNnpIWTdSanZGbjhjUDN6R2xjQnN1aVQ0XzVVaDZ0M05rZW1UdV9tZjdtZUFLLTBTMTAzMFpSNnNTR281azgtTE1sX0ZaUmh4djNFZFNtR2RBUTNlMDVMRzNnVVAyNzhTQWVzWHhNQUlHWmcxUFE3aEpoZGZHdmVGanJNdkdTSVFEM09wRnEtZHREcEFXbUo2Zm5sZFA1UWxYek5tQkJTMlZRQUtXZU9BYjh0Yjl5aVhsemhtT1dLRjF4SzlseHpYUG9GNmllOFRUWlJ4T0hxTjNiSkVISkVoQmVLclh6YkViV2tFNm4zTEoxbkd5M1htUlVFcER0Umdpa0tBUzZybFhFT0VneXNjIn0.eyJzaGEyNTYiOiIwcHRkQXFDV1B4NXdqWk5wOXg4ZnJGWTNlR0RjdEhCQjZWZTV4eHExZlI0PSJ9.VAKBz0jsx_PGXCL174k1xoHQsFqavxlvX_B1CUFUYjDgU7fLR_fah5JOHIGLYYvCmycX4zdCOayG8e5Hbqy1lFTGDMCPuyvEcKgFm5eBs4H8jMC3-LBg1pvsIgIPnw46RxrRQCOLBUFItu-hrbcGcXN0_blVsDfFEVZdkP64Pt1No-Az-hvRUv2UUeiq1OwFuVIMfm-fK2177DG8Mfw_ZTk3CMNn0aeo3eFVVLy4xfHiXqD3-7jah_HcLLuiaKLBM-XfIrm5Q5fuZ4pHnKlJNFKgW2ykIh274kcdVw_D0bfgxeOaCj0SftmsoCxnLUzLAfxDlqdY-yw6O-gTski81TrCMH5X-Ykd9TkZDyMZN08jp_V3jSX29us-MNHf_5fqKM07H4pCk7sGwQTaq7WmIfwyOC7M7Ea7N65IErBS_ejNsyu9-R9XOFROWyN_hqHxj1zvbubgOU-UBEaYwSgWb4gqFFzhlxVfAAElQDRTa1T_4FFs1-edKdifURz9hGKc\",\"fileUrls\":{\"fba3f0b3def43a3a4\":\"http://azurertos-adu--azurertos-adu.b.nlu.dl.adu.microsoft.com/eastus/azurertos-adu--azurertos-adu/a58ae7c5286e499486bd841373abd884/firmware_7.0.1.bin\",\"f0df8c0e22a1b60c1\":\"http://azurertos-adu--azurertos-adu.b.nlu.dl.adu.microsoft.com/eastus/azurertos-adu--azurertos-adu/72e4076e2dea427b9c24c76765f35371/contoso.iotdevice-leaf.7.0.1.updatemanifest5.json\",\"fa0feb4ccadb5c2fe\":\"http://azurertos-adu--azurertos-adu.b.nlu.dl.adu.microsoft.com/eastus/azurertos-adu--azurertos-adu/ba2e3429b1814c03bb4cfd72587dac54/leaf_firmware_7.0.2.bin\"}},\"__t\":\"c\"},\"$version\":6}";

/* Null file url.  */
static const UCHAR g_adu_agent_new_update_4[] = "{\"deviceUpdate\":{\"service\":{\"workflow\":{\"action\":3,\"id\":\"6b831565-bd1c-4b84-995a-f2ab4e6a4bb1\"},\"updateManifest\":\"{\\\"manifestVersion\\\":\\\"5\\\",\\\"updateId\\\":{\\\"provider\\\":\\\"Contoso\\\",\\\"name\\\":\\\"IoTDevice\\\",\\\"version\\\":\\\"7.0.1\\\"},\\\"compatibility\\\":[{\\\"manufacturer\\\":\\\"Contoso\\\",\\\"model\\\":\\\"IoTDevice\\\"}],\\\"instructions\\\":{\\\"steps\\\":[{\\\"type\\\":\\\"reference\\\",\\\"detachedManifestFileId\\\":\\\"f0df8c0e22a1b60c1\\\"},{\\\"handler\\\":\\\"microsoft/swupdate:1\\\",\\\"files\\\":[\\\"fba3f0b3def43a3a4\\\"],\\\"handlerProperties\\\":{\\\"installedCriteria\\\":\\\"7.0.1\\\"}}]},\\\"files\\\":{\\\"fba3f0b3def43a3a4\\\":{\\\"fileName\\\":\\\"firmware_7.0.1.bin\\\",\\\"sizeInBytes\\\":1978,\\\"hashes\\\":{\\\"sha256\\\":\\\"qr+xRWnfo/POaFNv+KVddBsJngGxCiSQ25WEW8t4dLc=\\\"}},\\\"f0df8c0e22a1b60c1\\\":{\\\"fileName\\\":\\\"contoso.iotdevice-leaf.7.0.1.updatemanifest5.json\\\",\\\"sizeInBytes\\\":601,\\\"hashes\\\":{\\\"sha256\\\":\\\"fP+yIYtGfsxMkL1iRS+olh+iXBebXYEapROyG6+nBjE=\\\"}}},\\\"createdDateTime\\\":\\\"2022-12-19T05:25:47.9977098Z\\\"}\",\"updateManifestSignature\":\"eyJhbGciOiJSUzI1NiIsInNqd2siOiJleUpoYkdjaU9pSlNVekkxTmlJc0ltdHBaQ0k2SWtGRVZTNHlNREEzTURJdVVpSjkuZXlKcmRIa2lPaUpTVTBFaUxDSnVJam9pYkV4bWMwdHZPRmwwWW1Oak1sRXpUalV3VlhSTVNXWlhVVXhXVTBGRlltTm9LMFl2WTJVM1V6Rlpja3BvV0U5VGNucFRaa051VEhCVmFYRlFWSGMwZWxndmRHbEJja0ZGZFhrM1JFRmxWVzVGU0VWamVEZE9hM2QzZVRVdk9IcExaV3AyWTBWWWNFRktMMlV6UWt0SE5FVTBiMjVtU0ZGRmNFOXplSGRQUzBWbFJ6QkhkamwzVjB3emVsUmpUblprUzFoUFJGaEdNMVZRWlVveGIwZGlVRkZ0Y3pKNmJVTktlRUppZEZOSldVbDBiWFpwWTNneVpXdGtWbnBYUm5jdmRrdFVUblZMYXpob2NVczNTRkptYWs5VlMzVkxXSGxqSzNsSVVVa3dZVVpDY2pKNmEyc3plR2d4ZEVWUFN6azRWMHBtZUdKamFsQnpSRTgyWjNwWmVtdFlla05OZW1Fd1R6QkhhV0pDWjB4QlZGUTVUV1k0V1ZCd1dVY3lhblpQWVVSVmIwTlJiakpWWTFWU1RtUnNPR2hLWW5scWJscHZNa3B5SzFVNE5IbDFjVTlyTjBZMFdubFRiMEoyTkdKWVNrZ3lXbEpTV2tab0wzVlRiSE5XT1hkU2JWbG9XWEoyT1RGRVdtbHhhemhJVWpaRVUyeHVabTVsZFRJNFJsUm9SVzF0YjNOVlRUTnJNbGxNYzBKak5FSnZkWEIwTTNsaFNEaFpia3BVTnpSMU16TjFlakU1TDAxNlZIVnFTMmMzVkdGcE1USXJXR0owYmxwRU9XcFVSMkY1U25Sc2FFWmxWeXRJUXpVM1FYUkJSbHBvY1ZsM2VVZHJXQ3M0TTBGaFVGaGFOR0V4VHpoMU1qTk9WVWQxTWtGd04yOU5NVTR3ZVVKS0swbHNUM29pTENKbElqb2lRVkZCUWlJc0ltRnNaeUk2SWxKVE1qVTJJaXdpYTJsa0lqb2lRVVJWTGpJeE1EWXdPUzVTTGxNaWZRLlJLS2VBZE02dGFjdWZpSVU3eTV2S3dsNFpQLURMNnEteHlrTndEdkljZFpIaTBIa2RIZ1V2WnoyZzZCTmpLS21WTU92dXp6TjhEczhybXo1dnMwT1RJN2tYUG1YeDZFLUYyUXVoUXNxT3J5LS1aN2J3TW5LYTNkZk1sbkthWU9PdURtV252RWMyR0hWdVVTSzREbmw0TE9vTTQxOVlMNThWTDAtSEthU18xYmNOUDhXYjVZR08xZXh1RmpiVGtIZkNIU0duVThJeUFjczlGTjhUT3JETHZpVEtwcWtvM3RiSUwxZE1TN3NhLWJkZExUVWp6TnVLTmFpNnpIWTdSanZGbjhjUDN6R2xjQnN1aVQ0XzVVaDZ0M05rZW1UdV9tZjdtZUFLLTBTMTAzMFpSNnNTR281azgtTE1sX0ZaUmh4djNFZFNtR2RBUTNlMDVMRzNnVVAyNzhTQWVzWHhNQUlHWmcxUFE3aEpoZGZHdmVGanJNdkdTSVFEM09wRnEtZHREcEFXbUo2Zm5sZFA1UWxYek5tQkJTMlZRQUtXZU9BYjh0Yjl5aVhsemhtT1dLRjF4SzlseHpYUG9GNmllOFRUWlJ4T0hxTjNiSkVISkVoQmVLclh6YkViV2tFNm4zTEoxbkd5M1htUlVFcER0Umdpa0tBUzZybFhFT0VneXNjIn0.eyJzaGEyNTYiOiIwcHRkQXFDV1B4NXdqWk5wOXg4ZnJGWTNlR0RjdEhCQjZWZTV4eHExZlI0PSJ9.VAKBz0jsx_PGXCL174k1xoHQsFqavxlvX_B1CUFUYjDgU7fLR_fah5JOHIGLYYvCmycX4zdCOayG8e5Hbqy1lFTGDMCPuyvEcKgFm5eBs4H8jMC3-LBg1pvsIgIPnw46RxrRQCOLBUFItu-hrbcGcXN0_blVsDfFEVZdkP64Pt1No-Az-hvRUv2UUeiq1OwFuVIMfm-fK2177DG8Mfw_ZTk3CMNn0aeo3eFVVLy4xfHiXqD3-7jah_HcLLuiaKLBM-XfIrm5Q5fuZ4pHnKlJNFKgW2ykIh274kcdVw_D0bfgxeOaCj0SftmsoCxnLUzLAfxDlqdY-yw6O-gTski81TrCMH5X-Ykd9TkZDyMZN08jp_V3jSX29us-MNHf_5fqKM07H4pCk7sGwQTaq7WmIfwyOC7M7Ea7N65IErBS_ejNsyu9-R9XOFROWyN_hqHxj1zvbubgOU-UBEaYwSgWb4gqFFzhlxVfAAElQDRTa1T_4FFs1-edKdifURz9hGKc\",\"fileUrls\":{\"f352dcaace6710428\":null,\"fba3f0b3def43a3a4\":\"http://azurertos-adu--azurertos-adu.b.nlu.dl.adu.microsoft.com/eastus/azurertos-adu--azurertos-adu/a58ae7c5286e499486bd841373abd884/firmware_7.0.1.bin\",\"f0df8c0e22a1b60c1\":\"http://azurertos-adu--azurertos-adu.b.nlu.dl.adu.microsoft.com/eastus/azurertos-adu--azurertos-adu/72e4076e2dea427b9c24c76765f35371/contoso.iotdevice-leaf.7.0.1.updatemanifest5.json\",\"fa0feb4ccadb5c2fe\":\"http://azurertos-adu--azurertos-adu.b.nlu.dl.adu.microsoft.com/eastus/azurertos-adu--azurertos-adu/ba2e3429b1814c03bb4cfd72587dac54/leaf_firmware_7.0.2.bin\",\"fd253bec341ca4d00\":null}},\"__t\":\"c\"},\"$version\":6}";

static const UCHAR *g_adu_agent_new_udpate = g_adu_agent_new_udpate_1;
static UINT   g_adu_agent_new_udpate_size = sizeof(g_adu_agent_new_udpate_1);
static const CHAR g_adu_agent_cancel_udpate_topic[] = "$iothub/twin/PATCH/properties/desired/?$version=7";
static const UCHAR g_adu_agent_cancel_update[] = "{\"deviceUpdate\":{\"service\":{\"workflow\":{\"action\":255,\t\"id\":\"nodeployment\"}},\"__t\":\"c\"},\"$version\":6}";
static const UCHAR g_adu_agent_cancel_response[] = "{\"deviceUpdate\":{\"__t\":\"c\",\"agent\":{\"state\":0,\"workflow\":{\"action\":255,\"id\":\"nodeployment\"}}}}";

static const UCHAR g_adu_agent_proxy_manifest[] = "{\"updateManifest\":\"{\\\"manifestVersion\\\":\\\"5\\\",\\\"updateId\\\":{\\\"provider\\\":\\\"Contoso\\\",\\\"name\\\":\\\"IoTDevice-Leaf\\\",\\\"version\\\":\\\"7.0.1\\\"},\\\"compatibility\\\":[{\\\"manufacturer\\\":\\\"Contoso\\\",\\\"model\\\":\\\"IoTDevice-Leaf\\\"}],\\\"instructions\\\":{\\\"steps\\\":[{\\\"handler\\\":\\\"microsoft/swupdate:1\\\",\\\"files\\\":[\\\"fa0feb4ccadb5c2fe\\\"],\\\"handlerProperties\\\":{\\\"installedCriteria\\\":\\\"7.0.2\\\"}}]},\\\"files\\\":{\\\"fa0feb4ccadb5c2fe\\\":{\\\"fileName\\\":\\\"leaf_firmware_7.0.2.bin\\\",\\\"sizeInBytes\\\":1978,\\\"hashes\\\":{\\\"sha256\\\":\\\"qr+xRWnfo/POaFNv+KVddBsJngGxCiSQ25WEW8t4dLc=\\\"}}},\\\"createdDateTime\\\":\\\"2022-12-19T05:25:47.922477Z\\\"}\"}";

unsigned char g_adu_agent_firmware[] = {
  0x23, 0x20, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x20, 0x55, 0x70, 0x64,
  0x61, 0x74, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x49, 0x6f, 0x54, 0x20,
  0x48, 0x75, 0x62, 0x20, 0x53, 0x63, 0x72, 0x69, 0x70, 0x74, 0x73, 0x20,
  0x28, 0x50, 0x6f, 0x77, 0x65, 0x72, 0x53, 0x68, 0x65, 0x6c, 0x6c, 0x29,
  0x0a, 0x0a, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x53, 0x54, 0x4d, 0x33,
  0x32, 0x4c, 0x34, 0x53, 0x35, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x2e,
  0x70, 0x73, 0x31, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x63, 0x72, 0x65, 0x61,
  0x74, 0x69, 0x6e, 0x67, 0x20, 0x69, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x20,
  0x6d, 0x61, 0x6e, 0x69, 0x66, 0x65, 0x73, 0x74, 0x20, 0x66, 0x6f, 0x72,
  0x20, 0x53, 0x54, 0x4d, 0x34, 0x32, 0x4c, 0x34, 0x53, 0x35, 0x20, 0x70,
  0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x2e, 0x20, 0x55, 0x73, 0x65, 0x72,
  0x20, 0x63, 0x61, 0x6e, 0x20, 0x75, 0x73, 0x65, 0x20, 0x74, 0x68, 0x69,
  0x73, 0x20, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x20, 0x74, 0x6f, 0x20,
  0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x20, 0x74, 0x68, 0x72, 0x65, 0x65,
  0x20, 0x74, 0x79, 0x70, 0x65, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x69, 0x6d,
  0x70, 0x6f, 0x72, 0x74, 0x20, 0x6d, 0x61, 0x6e, 0x69, 0x66, 0x65, 0x73,
  0x74, 0x2e, 0x20, 0x4e, 0x6f, 0x74, 0x65, 0x3a, 0x20, 0x74, 0x68, 0x65,
  0x20, 0x70, 0x61, 0x74, 0x68, 0x20, 0x6f, 0x66, 0x20, 0x66, 0x69, 0x72,
  0x6d, 0x77, 0x61, 0x72, 0x65, 0x20, 0x6d, 0x75, 0x73, 0x74, 0x20, 0x69,
  0x6e, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x20, 0x74, 0x68, 0x65, 0x20, 0x76,
  0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x73, 0x74, 0x72, 0x69, 0x6e,
  0x67, 0x2e, 0x20, 0x59, 0x6f, 0x75, 0x20, 0x63, 0x61, 0x6e, 0x20, 0x61,
  0x6c, 0x73, 0x6f, 0x20, 0x74, 0x79, 0x70, 0x65, 0x20, 0x2a, 0x2a, 0x21,
  0x3f, 0x2a, 0x2a, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x68, 0x65, 0x6c, 0x70,
  0x2e, 0x20, 0x0a, 0x0a, 0x23, 0x23, 0x20, 0x31, 0x2e, 0x20, 0x43, 0x72,
  0x65, 0x61, 0x74, 0x65, 0x20, 0x69, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x20,
  0x6d, 0x61, 0x6e, 0x69, 0x66, 0x65, 0x73, 0x74, 0x20, 0x66, 0x6f, 0x72,
  0x20, 0x68, 0x6f, 0x73, 0x74, 0x20, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65,
  0x2e, 0x0a, 0x49, 0x6e, 0x70, 0x75, 0x74, 0x20, 0x76, 0x65, 0x72, 0x73,
  0x69, 0x6f, 0x6e, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x70, 0x61, 0x74, 0x68,
  0x20, 0x6f, 0x66, 0x20, 0x68, 0x6f, 0x73, 0x74, 0x20, 0x66, 0x69, 0x72,
  0x6d, 0x77, 0x61, 0x72, 0x65, 0x2c, 0x20, 0x74, 0x68, 0x65, 0x6e, 0x20,
  0x66, 0x69, 0x72, 0x6d, 0x77, 0x61, 0x72, 0x65, 0x20, 0x2a, 0x2a, 0x66,
  0x69, 0x72, 0x6d, 0x77, 0x61, 0x72, 0x65, 0x5f, 0x32, 0x2e, 0x30, 0x2e,
  0x30, 0x2e, 0x62, 0x69, 0x6e, 0x2a, 0x2a, 0x20, 0x61, 0x6e, 0x64, 0x20,
  0x6d, 0x61, 0x6e, 0x69, 0x66, 0x65, 0x73, 0x74, 0x20, 0x2a, 0x2a, 0x53,
  0x54, 0x4d, 0x69, 0x63, 0x72, 0x6f, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x72,
  0x6f, 0x6e, 0x69, 0x63, 0x73, 0x2e, 0x53, 0x54, 0x4d, 0x33, 0x32, 0x4c,
  0x34, 0x53, 0x35, 0x2e, 0x32, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x69, 0x6d,
  0x70, 0x6f, 0x72, 0x74, 0x6d, 0x61, 0x6e, 0x69, 0x66, 0x65, 0x73, 0x74,
  0x2e, 0x6a, 0x73, 0x6f, 0x6e, 0x2a, 0x2a, 0x20, 0x77, 0x69, 0x6c, 0x6c,
  0x20, 0x62, 0x65, 0x20, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65,
  0x64, 0x20, 0x69, 0x6e, 0x20, 0x2a, 0x2a, 0x53, 0x54, 0x4d, 0x69, 0x63,
  0x72, 0x6f, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x72, 0x6f, 0x6e, 0x69, 0x63,
  0x73, 0x2e, 0x53, 0x54, 0x4d, 0x33, 0x32, 0x4c, 0x34, 0x53, 0x35, 0x2e,
  0x32, 0x2e, 0x30, 0x2e, 0x30, 0x2a, 0x2a, 0x20, 0x66, 0x6f, 0x6c, 0x64,
  0x65, 0x72, 0x2e, 0x0a, 0x60, 0x60, 0x60, 0x0a, 0x50, 0x53, 0x20, 0x3e,
  0x20, 0x2e, 0x5c, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x53, 0x54, 0x4d,
  0x33, 0x32, 0x4c, 0x34, 0x53, 0x35, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65,
  0x2e, 0x70, 0x73, 0x31, 0x0a, 0x0a, 0x63, 0x6d, 0x64, 0x6c, 0x65, 0x74,
  0x20, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x53, 0x54, 0x4d, 0x33, 0x32,
  0x4c, 0x34, 0x53, 0x35, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x2e, 0x70,
  0x73, 0x31, 0x20, 0x61, 0x74, 0x20, 0x63, 0x6f, 0x6d, 0x6d, 0x61, 0x6e,
  0x64, 0x20, 0x70, 0x69, 0x70, 0x65, 0x6c, 0x69, 0x6e, 0x65, 0x20, 0x70,
  0x6f, 0x73, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x31, 0x0a, 0x53, 0x75,
  0x70, 0x70, 0x6c, 0x79, 0x20, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x20,
  0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x66, 0x6f, 0x6c, 0x6c,
  0x6f, 0x77, 0x69, 0x6e, 0x67, 0x20, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x65,
  0x74, 0x65, 0x72, 0x73, 0x3a, 0x0a, 0x28, 0x54, 0x79, 0x70, 0x65, 0x20,
  0x21, 0x3f, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x48, 0x65, 0x6c, 0x70, 0x2e,
  0x29, 0x0a, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x32,
  0x2e, 0x30, 0x2e, 0x30, 0x0a, 0x48, 0x6f, 0x73, 0x74, 0x50, 0x61, 0x74,
  0x68, 0x3a, 0x20, 0x66, 0x69, 0x72, 0x6d, 0x77, 0x61, 0x72, 0x65, 0x5f,
  0x32, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x62, 0x69, 0x6e, 0x0a, 0x60, 0x60,
  0x60, 0x0a, 0x0a, 0x23, 0x23, 0x20, 0x32, 0x2e, 0x20, 0x43, 0x72, 0x65,
  0x61, 0x74, 0x65, 0x20, 0x69, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x20, 0x6d,
  0x61, 0x6e, 0x69, 0x66, 0x65, 0x73, 0x74, 0x20, 0x66, 0x6f, 0x72, 0x20,
  0x68, 0x6f, 0x73, 0x74, 0x20, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x20,
  0x61, 0x6e, 0x64, 0x20, 0x6c, 0x65, 0x61, 0x66, 0x20, 0x75, 0x70, 0x64,
  0x61, 0x74, 0x65, 0x0a, 0x49, 0x6e, 0x70, 0x75, 0x74, 0x20, 0x76, 0x65,
  0x72, 0x73, 0x69, 0x6f, 0x6e, 0x2c, 0x20, 0x70, 0x61, 0x74, 0x68, 0x20,
  0x6f, 0x66, 0x20, 0x68, 0x6f, 0x73, 0x74, 0x20, 0x66, 0x69, 0x72, 0x6d,
  0x77, 0x61, 0x72, 0x65, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x70, 0x61, 0x74,
  0x68, 0x20, 0x6f, 0x66, 0x20, 0x6c, 0x65, 0x61, 0x66, 0x20, 0x66, 0x69,
  0x72, 0x6d, 0x77, 0x61, 0x72, 0x65, 0x2c, 0x20, 0x74, 0x68, 0x65, 0x6e,
  0x20, 0x66, 0x69, 0x72, 0x6d, 0x77, 0x61, 0x72, 0x65, 0x20, 0x2a, 0x2a,
  0x66, 0x69, 0x72, 0x6d, 0x77, 0x61, 0x72, 0x65, 0x5f, 0x32, 0x2e, 0x30,
  0x2e, 0x30, 0x2e, 0x62, 0x69, 0x6e, 0x2a, 0x2a, 0x2c, 0x20, 0x2a, 0x2a,
  0x6c, 0x65, 0x61, 0x66, 0x5f, 0x66, 0x69, 0x72, 0x6d, 0x77, 0x61, 0x72,
  0x65, 0x5f, 0x32, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x62, 0x69, 0x6e, 0x2a,
  0x2a, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x6d, 0x61, 0x6e, 0x69, 0x66, 0x65,
  0x73, 0x74, 0x20, 0x2a, 0x2a, 0x53, 0x54, 0x4d, 0x69, 0x63, 0x72, 0x6f,
  0x65, 0x6c, 0x65, 0x63, 0x74, 0x72, 0x6f, 0x6e, 0x69, 0x63, 0x73, 0x2e,
  0x53, 0x54, 0x4d, 0x33, 0x32, 0x4c, 0x34, 0x53, 0x35, 0x2e, 0x32, 0x2e,
  0x30, 0x2e, 0x30, 0x2e, 0x69, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x6d, 0x61,
  0x6e, 0x69, 0x66, 0x65, 0x73, 0x74, 0x2e, 0x6a, 0x73, 0x6f, 0x6e, 0x2a,
  0x2a, 0x2c, 0x20, 0x2a, 0x2a, 0x53, 0x54, 0x4d, 0x69, 0x63, 0x72, 0x6f,
  0x65, 0x6c, 0x65, 0x63, 0x74, 0x72, 0x6f, 0x6e, 0x69, 0x63, 0x73, 0x2e,
  0x53, 0x54, 0x4d, 0x33, 0x32, 0x4c, 0x34, 0x53, 0x35, 0x2d, 0x4c, 0x65,
  0x61, 0x66, 0x2e, 0x32, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x69, 0x6d, 0x70,
  0x6f, 0x72, 0x74, 0x6d, 0x61, 0x6e, 0x69, 0x66, 0x65, 0x73, 0x74, 0x2e,
  0x6a, 0x73, 0x6f, 0x6e, 0x2a, 0x2a, 0x20, 0x77, 0x69, 0x6c, 0x6c, 0x20,
  0x62, 0x65, 0x20, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x64,
  0x20, 0x69, 0x6e, 0x20, 0x2a, 0x2a, 0x53, 0x54, 0x4d, 0x69, 0x63, 0x72,
  0x6f, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x72, 0x6f, 0x6e, 0x69, 0x63, 0x73,
  0x2e, 0x53, 0x54, 0x4d, 0x33, 0x32, 0x4c, 0x34, 0x53, 0x35, 0x2e, 0x32,
  0x2e, 0x30, 0x2e, 0x30, 0x2a, 0x2a, 0x20, 0x66, 0x6f, 0x6c, 0x64, 0x65,
  0x72, 0x2e, 0x0a, 0x60, 0x60, 0x60, 0x0a, 0x50, 0x53, 0x20, 0x3e, 0x20,
  0x2e, 0x5c, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x53, 0x54, 0x4d, 0x33,
  0x32, 0x4c, 0x34, 0x53, 0x35, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x2e,
  0x70, 0x73, 0x31, 0x0a, 0x0a, 0x63, 0x6d, 0x64, 0x6c, 0x65, 0x74, 0x20,
  0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x53, 0x54, 0x4d, 0x33, 0x32, 0x4c,
  0x34, 0x53, 0x35, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x73,
  0x31, 0x20, 0x61, 0x74, 0x20, 0x63, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64,
  0x20, 0x70, 0x69, 0x70, 0x65, 0x6c, 0x69, 0x6e, 0x65, 0x20, 0x70, 0x6f,
  0x73, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x31, 0x0a, 0x53, 0x75, 0x70,
  0x70, 0x6c, 0x79, 0x20, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x20, 0x66,
  0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x66, 0x6f, 0x6c, 0x6c, 0x6f,
  0x77, 0x69, 0x6e, 0x67, 0x20, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x65, 0x74,
  0x65, 0x72, 0x73, 0x3a, 0x0a, 0x28, 0x54, 0x79, 0x70, 0x65, 0x20, 0x21,
  0x3f, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x48, 0x65, 0x6c, 0x70, 0x2e, 0x29,
  0x0a, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x32, 0x2e,
  0x30, 0x2e, 0x30, 0x0a, 0x48, 0x6f, 0x73, 0x74, 0x50, 0x61, 0x74, 0x68,
  0x3a, 0x20, 0x66, 0x69, 0x72, 0x6d, 0x77, 0x61, 0x72, 0x65, 0x5f, 0x32,
  0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x62, 0x69, 0x6e, 0x0a, 0x4c, 0x65, 0x61,
  0x66, 0x50, 0x61, 0x74, 0x68, 0x3a, 0x20, 0x2e, 0x2f, 0x6c, 0x65, 0x61,
  0x66, 0x5f, 0x66, 0x69, 0x72, 0x6d, 0x77, 0x61, 0x72, 0x65, 0x5f, 0x32,
  0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x62, 0x69, 0x6e, 0x0a, 0x60, 0x60, 0x60,
  0x0a, 0x0a, 0x23, 0x23, 0x20, 0x33, 0x2e, 0x20, 0x43, 0x72, 0x65, 0x61,
  0x74, 0x65, 0x20, 0x69, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x20, 0x6d, 0x61,
  0x6e, 0x69, 0x66, 0x65, 0x73, 0x74, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x6c,
  0x65, 0x61, 0x66, 0x20, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x0a, 0x49,
  0x6e, 0x70, 0x75, 0x74, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
  0x2c, 0x20, 0x70, 0x61, 0x74, 0x68, 0x20, 0x6f, 0x66, 0x20, 0x6c, 0x65,
  0x61, 0x66, 0x20, 0x66, 0x69, 0x72, 0x6d, 0x77, 0x61, 0x72, 0x65, 0x2c,
  0x20, 0x74, 0x68, 0x65, 0x6e, 0x20, 0x66, 0x69, 0x72, 0x6d, 0x77, 0x61,
  0x72, 0x65, 0x20, 0x2a, 0x2a, 0x6c, 0x65, 0x61, 0x66, 0x5f, 0x66, 0x69,
  0x72, 0x6d, 0x77, 0x61, 0x72, 0x65, 0x5f, 0x32, 0x2e, 0x30, 0x2e, 0x30,
  0x2e, 0x62, 0x69, 0x6e, 0x2a, 0x2a, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x6d,
  0x61, 0x6e, 0x69, 0x66, 0x65, 0x73, 0x74, 0x20, 0x2a, 0x2a, 0x53, 0x54,
  0x4d, 0x69, 0x63, 0x72, 0x6f, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x72, 0x6f,
  0x6e, 0x69, 0x63, 0x73, 0x2e, 0x53, 0x54, 0x4d, 0x33, 0x32, 0x4c, 0x34,
  0x53, 0x35, 0x2e, 0x32, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x69, 0x6d, 0x70,
  0x6f, 0x72, 0x74, 0x6d, 0x61, 0x6e, 0x69, 0x66, 0x65, 0x73, 0x74, 0x2e,
  0x6a, 0x73, 0x6f, 0x6e, 0x2a, 0x2a, 0x2c, 0x20, 0x2a, 0x2a, 0x53, 0x54,
  0x4d, 0x69, 0x63, 0x72, 0x6f, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x72, 0x6f,
  0x6e, 0x69, 0x63, 0x73, 0x2e, 0x53, 0x54, 0x4d, 0x33, 0x32, 0x4c, 0x34,
  0x53, 0x35, 0x2d, 0x4c, 0x65, 0x61, 0x66, 0x2e, 0x32, 0x2e, 0x30, 0x2e,
  0x30, 0x2e, 0x69, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x6d, 0x61, 0x6e, 0x69,
  0x66, 0x65, 0x73, 0x74, 0x2e, 0x6a, 0x73, 0x6f, 0x6e, 0x2a, 0x2a, 0x20,
  0x77, 0x69, 0x6c, 0x6c, 0x20, 0x62, 0x65, 0x20, 0x67, 0x65, 0x6e, 0x65,
  0x72, 0x61, 0x74, 0x65, 0x64, 0x20, 0x69, 0x6e, 0x20, 0x2a, 0x2a, 0x53,
  0x54, 0x4d, 0x69, 0x63, 0x72, 0x6f, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x72,
  0x6f, 0x6e, 0x69, 0x63, 0x73, 0x2e, 0x53, 0x54, 0x4d, 0x33, 0x32, 0x4c,
  0x34, 0x53, 0x35, 0x2e, 0x32, 0x2e, 0x30, 0x2e, 0x30, 0x2a, 0x2a, 0x20,
  0x66, 0x6f, 0x6c, 0x64, 0x65, 0x72, 0x2e, 0x0a, 0x60, 0x60, 0x60, 0x0a,
  0x50, 0x53, 0x20, 0x3e, 0x20, 0x2e, 0x5c, 0x43, 0x72, 0x65, 0x61, 0x74,
  0x65, 0x53, 0x54, 0x4d, 0x33, 0x32, 0x4c, 0x34, 0x53, 0x35, 0x55, 0x70,
  0x64, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x73, 0x31, 0x0a, 0x0a, 0x63, 0x6d,
  0x64, 0x6c, 0x65, 0x74, 0x20, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x53,
  0x54, 0x4d, 0x33, 0x32, 0x4c, 0x34, 0x53, 0x35, 0x55, 0x70, 0x64, 0x61,
  0x74, 0x65, 0x2e, 0x70, 0x73, 0x31, 0x20, 0x61, 0x74, 0x20, 0x63, 0x6f,
  0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x20, 0x70, 0x69, 0x70, 0x65, 0x6c, 0x69,
  0x6e, 0x65, 0x20, 0x70, 0x6f, 0x73, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x20,
  0x31, 0x0a, 0x53, 0x75, 0x70, 0x70, 0x6c, 0x79, 0x20, 0x76, 0x61, 0x6c,
  0x75, 0x65, 0x73, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20,
  0x66, 0x6f, 0x6c, 0x6c, 0x6f, 0x77, 0x69, 0x6e, 0x67, 0x20, 0x70, 0x61,
  0x72, 0x61, 0x6d, 0x65, 0x74, 0x65, 0x72, 0x73, 0x3a, 0x0a, 0x28, 0x54,
  0x79, 0x70, 0x65, 0x20, 0x21, 0x3f, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x48,
  0x65, 0x6c, 0x70, 0x2e, 0x29, 0x0a, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f,
  0x6e, 0x3a, 0x20, 0x32, 0x2e, 0x30, 0x2e, 0x30, 0x0a, 0x48, 0x6f, 0x73,
  0x74, 0x50, 0x61, 0x74, 0x68, 0x3a, 0x0a, 0x4c, 0x65, 0x61, 0x66, 0x50,
  0x61, 0x74, 0x68, 0x3a, 0x20, 0x2e, 0x2f, 0x6c, 0x65, 0x61, 0x66, 0x5f,
  0x66, 0x69, 0x72, 0x6d, 0x77, 0x61, 0x72, 0x65, 0x5f, 0x32, 0x2e, 0x30,
  0x2e, 0x30, 0x2e, 0x62, 0x69, 0x6e, 0x0a, 0x60, 0x60, 0x60
};
unsigned int g_adu_agent_firmware_size = 1978;

static const UCHAR g_adu_agent_response_proxy_preprocess_error[] = "{\"deviceUpdate\":{\"__t\":\"c\",\"agent\":{\"state\":255,\"workflow\":{\"action\":3,\"id\":\"6b831565-bd1c-4b84-995a-f2ab4e6a4bb1\"},\"lastInstallResult\":{\"resultCode\":0,\"extendedResultCode\":0,\"resultDetails\":\"\",\"stepResults\":{\"step_0\":{\"resultCode\":0,\"extendedResultCode\":0,\"resultDetails\":\"\"},\"step_1\":{\"resultCode\":200,\"extendedResultCode\":0,\"resultDetails\":\"\"}}}}}}";
static const UCHAR g_adu_agent_response_proxy_write_error[] = "{\"deviceUpdate\":{\"__t\":\"c\",\"agent\":{\"state\":255,\"workflow\":{\"action\":3,\"id\":\"6b831565-bd1c-4b84-995a-f2ab4e6a4bb1\"},\"lastInstallResult\":{\"resultCode\":0,\"extendedResultCode\":0,\"resultDetails\":\"\",\"stepResults\":{\"step_0\":{\"resultCode\":0,\"extendedResultCode\":0,\"resultDetails\":\"\"},\"step_1\":{\"resultCode\":200,\"extendedResultCode\":0,\"resultDetails\":\"\"}}}}}}";
static const UCHAR g_adu_agent_response_proxy_install_error[] = "{\"deviceUpdate\":{\"__t\":\"c\",\"agent\":{\"state\":255,\"workflow\":{\"action\":3,\"id\":\"6b831565-bd1c-4b84-995a-f2ab4e6a4bb1\"},\"lastInstallResult\":{\"resultCode\":0,\"extendedResultCode\":0,\"resultDetails\":\"\",\"stepResults\":{\"step_0\":{\"resultCode\":0,\"extendedResultCode\":0,\"resultDetails\":\"\"},\"step_1\":{\"resultCode\":200,\"extendedResultCode\":0,\"resultDetails\":\"\"}}}}}}";
static const UCHAR g_adu_agent_response_proxy_apply_error[] = "{\"deviceUpdate\":{\"__t\":\"c\",\"agent\":{\"state\":255,\"workflow\":{\"action\":3,\"id\":\"6b831565-bd1c-4b84-995a-f2ab4e6a4bb1\"},\"lastInstallResult\":{\"resultCode\":0,\"extendedResultCode\":0,\"resultDetails\":\"\",\"stepResults\":{\"step_0\":{\"resultCode\":0,\"extendedResultCode\":0,\"resultDetails\":\"\"},\"step_1\":{\"resultCode\":600,\"extendedResultCode\":0,\"resultDetails\":\"\"}}}}}}";

static const UCHAR g_adu_agent_response_preprocess_error[] = "{\"deviceUpdate\":{\"__t\":\"c\",\"agent\":{\"state\":255,\"workflow\":{\"action\":3,\"id\":\"6b831565-bd1c-4b84-995a-f2ab4e6a4bb1\"},\"lastInstallResult\":{\"resultCode\":0,\"extendedResultCode\":0,\"resultDetails\":\"\",\"stepResults\":{\"step_0\":{\"resultCode\":600,\"extendedResultCode\":0,\"resultDetails\":\"\"},\"step_1\":{\"resultCode\":0,\"extendedResultCode\":0,\"resultDetails\":\"\"}}}}}}";
static const UCHAR g_adu_agent_response_write_error[] = "{\"deviceUpdate\":{\"__t\":\"c\",\"agent\":{\"state\":255,\"workflow\":{\"action\":3,\"id\":\"6b831565-bd1c-4b84-995a-f2ab4e6a4bb1\"},\"lastInstallResult\":{\"resultCode\":0,\"extendedResultCode\":0,\"resultDetails\":\"\",\"stepResults\":{\"step_0\":{\"resultCode\":600,\"extendedResultCode\":0,\"resultDetails\":\"\"},\"step_1\":{\"resultCode\":0,\"extendedResultCode\":0,\"resultDetails\":\"\"}}}}}}";
static const UCHAR g_adu_agent_response_install_error[] = "{\"deviceUpdate\":{\"__t\":\"c\",\"agent\":{\"state\":255,\"workflow\":{\"action\":3,\"id\":\"6b831565-bd1c-4b84-995a-f2ab4e6a4bb1\"},\"lastInstallResult\":{\"resultCode\":0,\"extendedResultCode\":0,\"resultDetails\":\"\",\"stepResults\":{\"step_0\":{\"resultCode\":600,\"extendedResultCode\":0,\"resultDetails\":\"\"},\"step_1\":{\"resultCode\":0,\"extendedResultCode\":0,\"resultDetails\":\"\"}}}}}}";
static const UCHAR g_adu_agent_response_apply_error[] = "{\"deviceUpdate\":{\"__t\":\"c\",\"agent\":{\"state\":255,\"workflow\":{\"action\":3,\"id\":\"6b831565-bd1c-4b84-995a-f2ab4e6a4bb1\"},\"lastInstallResult\":{\"resultCode\":0,\"extendedResultCode\":0,\"resultDetails\":\"\",\"stepResults\":{\"step_0\":{\"resultCode\":700,\"extendedResultCode\":0,\"resultDetails\":\"\"},\"step_1\":{\"resultCode\":0,\"extendedResultCode\":0,\"resultDetails\":\"\"}}}}}}";

static const UCHAR g_adu_agent_response_success[] = "{\"deviceUpdate\":{\"__t\":\"c\",\"agent\":{\"state\":0,\"workflow\":{\"action\":3,\"id\":\"6b831565-bd1c-4b84-995a-f2ab4e6a4bb1\"},\"installedUpdateId\":\"{\\\"provider\\\":\\\"Contoso\\\",\\\"name\\\":\\\"IoTDevice\\\",\\\"version\\\":\\\"7.0.1\\\"}\",\"lastInstallResult\":{\"resultCode\":700,\"extendedResultCode\":0,\"resultDetails\":\"\",\"stepResults\":{\"step_0\":{\"resultCode\":700,\"extendedResultCode\":0,\"resultDetails\":\"\"},\"step_1\":{\"resultCode\":700,\"extendedResultCode\":0,\"resultDetails\":\"\"}}}}}}";


static UINT g_version = 10;

static UINT g_total_append = 0;
static UINT g_failed_append_index = 0;
static UINT g_total_allocation = 0;
static UINT g_failed_allocation_index = -1;
static NX_IP* g_ip_ptr;
static NX_PACKET_POOL* g_pool_ptr;
static NX_DNS* g_dns_ptr;
static ULONG g_available_packet;
static UINT generate_test_property_send_response_bytes = NX_FALSE;
static UINT generate_test_properties_new_update = NX_FALSE;
static UINT handle_agent_update_received_notify = NX_FALSE;

static UINT g_update_received_count = 0;
static UINT g_update_applied_count = 0;

static UINT g_adu_agent_driver_preprocess_fail = NX_FALSE;
static UINT g_adu_agent_driver_write_fail = NX_FALSE;
static UINT g_adu_agent_driver_install_fail = NX_FALSE;
static UINT g_adu_agent_driver_apply_fail = NX_FALSE;

static UINT g_adu_agent_proxy_driver_preprocess_fail = NX_FALSE;
static UINT g_adu_agent_proxy_driver_write_fail = NX_FALSE;
static UINT g_adu_agent_proxy_driver_install_fail = NX_FALSE;
static UINT g_adu_agent_proxy_driver_apply_fail = NX_FALSE;

static UINT g_ingore_manifest_verification = NX_FALSE;

/* HTTP data type. */
#define HTTP_DATA_TYPE_PROXY_MANIFEST 1
#define HTTP_DATA_TYPE_FIRMWARE       2

static UINT g_adu_agent_http_data_type = 0;

static UCHAR g_adu_metadata[6*1024];

extern UINT _nxd_mqtt_client_append_message(NXD_MQTT_CLIENT *client_ptr, NX_PACKET *packet_ptr, CHAR *message,
                                            UINT length, ULONG wait_option);
extern UINT _nxd_mqtt_client_set_fixed_header(NXD_MQTT_CLIENT *client_ptr, NX_PACKET *packet_ptr,
                                              UCHAR control_header, UINT length, UINT wait_option);

static NX_AZURE_IOT iot;
static NX_AZURE_IOT_HUB_CLIENT iothub_client;
static NX_AZURE_IOT_ADU_AGENT adu_agent;
static NX_SECURE_X509_CERT root_ca_cert;
static UCHAR metadata_buffer[NX_AZURE_IOT_TLS_METADATA_BUFFER_SIZE];
static ULONG demo_cloud_thread_stack[DEMO_CLOUD_STACK_SIZE / sizeof(ULONG)];
static UCHAR message_payload[MAXIMUM_PAYLOAD_LENGTH];
static UCHAR result_buffer[MAXIMUM_PAYLOAD_LENGTH];
static UCHAR packet_buffer[MAXIMUM_PAYLOAD_LENGTH];
static VOID (*test_receive_notify)(NXD_MQTT_CLIENT *client_ptr, UINT message_count) = NX_NULL;

UINT __wrap_nx_azure_iot_security_module_enable(NX_AZURE_IOT *nx_azure_iot_ptr)
{
    printf("HIJACKED: %s\n", __func__);
    return(NX_AZURE_IOT_SUCCESS);
}

UINT __wrap_nx_azure_iot_security_module_disable(NX_AZURE_IOT *nx_azure_iot_ptr)
{
    printf("HIJACKED: %s\n", __func__);
    return(NX_AZURE_IOT_SUCCESS);
}

UINT __wrap__nxde_mqtt_client_receive_notify_set(NXD_MQTT_CLIENT *client_ptr,
                                                 VOID (*receive_notify)(NXD_MQTT_CLIENT *client_ptr, UINT message_count))
{
    printf("HIJACKED: %s\n", __func__);
    test_receive_notify = receive_notify;
    return(NX_AZURE_IOT_SUCCESS);
}

UINT __wrap__nxde_mqtt_client_subscribe(NXD_MQTT_CLIENT *client_ptr, UINT op,
                                        CHAR *topic_name, UINT topic_name_length,
                                        USHORT *packet_id_ptr, UINT QoS)
{
    printf("HIJACKED: %s\n", __func__);

    iothub_client.nx_azure_iot_hub_client_properties_subscribe_ack = NX_TRUE;

    return((UINT)mock());
}

UINT __real__nx_packet_data_append(NX_PACKET *packet_ptr, VOID *data_start, ULONG data_size,
                                     NX_PACKET_POOL *pool_ptr, ULONG wait_option);
UINT __wrap__nx_packet_data_append(NX_PACKET *packet_ptr, VOID *data_start, ULONG data_size,
                                     NX_PACKET_POOL *pool_ptr, ULONG wait_option)
{
    printf("HIJACKED: %s\n", __func__);

    if (g_failed_append_index == g_total_append)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    g_total_append++;
    return __real__nx_packet_data_append(packet_ptr, data_start, data_size, pool_ptr, wait_option);
}

UINT __real_nx_azure_iot_buffer_allocate(NX_AZURE_IOT *nx_azure_iot_ptr, UCHAR **buffer_pptr,
                                         UINT *buffer_size, VOID **buffer_context);
UINT __wrap_nx_azure_iot_buffer_allocate(NX_AZURE_IOT *nx_azure_iot_ptr, UCHAR **buffer_pptr,
                                         UINT *buffer_size, VOID **buffer_context)
{
    printf("HIJACKED: %s\n", __func__);

    if (g_failed_allocation_index == g_total_allocation)
    {
        return(NX_NOT_SUCCESSFUL);
    }

    g_total_allocation++;
    return __real_nx_azure_iot_buffer_allocate(nx_azure_iot_ptr, buffer_pptr, buffer_size, buffer_context);
}

UINT __wrap__nxd_mqtt_client_publish_packet_send(NXD_MQTT_CLIENT *client_ptr, NX_PACKET *packet_ptr,
                                                 USHORT packet_id, UINT QoS, ULONG wait_option)
{
UINT topic_name_length;
UINT message_length;
UCHAR *buffer_ptr;

    printf("HIJACKED: %s\n", __func__);
    tx_mutex_put(client_ptr -> nxd_mqtt_client_mutex_ptr);

    if ((g_expected_message) && (g_expected_message_index == 0))
    {
        buffer_ptr = packet_ptr -> nx_packet_prepend_ptr;
        topic_name_length = (buffer_ptr[5] << 8) | (buffer_ptr[6]);
        message_length = packet_ptr -> nx_packet_length - (7 + topic_name_length);
        assert_memory_equal(&buffer_ptr[7 + topic_name_length], g_expected_message, message_length);
    }

    if (g_expected_message_index)
    {
        g_expected_message_index--;
    }

    /* packet ownership taken and released */
    nx_packet_release(packet_ptr);

    return(NX_AZURE_IOT_SUCCESS);
}

UINT __wrap__nxde_mqtt_client_secure_connect(NXD_MQTT_CLIENT *client_ptr, NXD_ADDRESS *server_ip, UINT server_port,
                                             UINT (*tls_setup)(NXD_MQTT_CLIENT *client_ptr, NX_SECURE_TLS_SESSION *,
                                                               NX_SECURE_X509_CERT *, NX_SECURE_X509_CERT *),
                                             UINT keepalive, UINT clean_session, ULONG wait_option)
{
az_span source = az_span_create(client_ptr -> nxd_mqtt_client_username,
                                (INT)client_ptr -> nxd_mqtt_client_username_length);
az_span target = az_span_create((UCHAR *)g_pnp_model_id, sizeof(g_pnp_model_id) - 1);

    printf("HIJACKED: %s\n", __func__);

    /* Check username and client Id to contain modelId and device */
    assert_memory_equal(client_ptr -> nxd_mqtt_client_id, g_device_id, sizeof(g_device_id) - 1);
    assert_int_not_equal(az_span_find(source, target), -1);

    tx_thread_suspend(&(iot.nx_azure_iot_ip_ptr -> nx_ip_thread));
    client_ptr -> nxd_mqtt_client_state = NXD_MQTT_CLIENT_STATE_CONNECTED;
    client_ptr -> nxd_mqtt_client_packet_identifier = 1;
    client_ptr -> nxd_mqtt_tls_session.nx_secure_tls_id = NX_SECURE_TLS_ID;
    client_ptr -> nxd_mqtt_tls_session.nx_secure_tls_local_session_active = NX_FALSE;
    client_ptr -> nxd_mqtt_tls_session.nx_secure_tls_tcp_socket = &client_ptr -> nxd_mqtt_client_socket;
    client_ptr -> nxd_mqtt_client_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V4;
    client_ptr -> nxd_mqtt_client_socket.nx_tcp_socket_state = NX_TCP_ESTABLISHED;

    return(NXD_MQTT_SUCCESS);
}

UINT __wrap__nxde_mqtt_client_disconnect(NXD_MQTT_CLIENT *client_ptr)
{
    printf("HIJACKED: %s\n", __func__);
    client_ptr -> nxd_mqtt_client_state = NXD_MQTT_CLIENT_STATE_IDLE;
    client_ptr -> nxd_mqtt_client_socket.nx_tcp_socket_state = NX_TCP_CLOSED;
    return(NXD_MQTT_SUCCESS);
}

UINT __wrap__nxde_dns_host_by_name_get(NX_DNS *dns_ptr, UCHAR *host_name, NXD_ADDRESS *host_address_ptr,
                                       ULONG wait_option, UINT lookup_type)
{
    printf("HIJACKED: %s\n", __func__);
    host_address_ptr -> nxd_ip_address.v4 = IP_ADDRESS(127, 0, 0, 1);
    return(NX_DNS_SUCCESS);
}

UINT __wrap__nxe_web_http_client_connect(NX_WEB_HTTP_CLIENT *client_ptr, NXD_ADDRESS *server_ip, UINT server_port, ULONG wait_option)
{
    printf("HIJACKED: %s\n", __func__);
    return(NX_SUCCESS);
}

UINT __wrap__nxe_web_http_client_request_send(NX_WEB_HTTP_CLIENT *client_ptr, ULONG wait_option)
{
    printf("HIJACKED: %s\n", __func__);
    return(NX_SUCCESS);
}

UINT __wrap__nxe_web_http_client_response_body_get(NX_WEB_HTTP_CLIENT *client_ptr, NX_PACKET **packet_ptr, ULONG wait_option)
{
NX_PACKET *data_packet;
UCHAR fake_binary[] = "test binary data";

    printf("HIJACKED: %s\n", __func__);

    assert_int_equal(nx_packet_allocate(iot.nx_azure_iot_pool_ptr, &data_packet, 0, NX_NO_WAIT), NX_AZURE_IOT_SUCCESS);
    if (g_adu_agent_http_data_type == HTTP_DATA_TYPE_PROXY_MANIFEST)
    {        
        assert_int_equal(__real__nx_packet_data_append(data_packet, (VOID *)g_adu_agent_proxy_manifest, sizeof(g_adu_agent_proxy_manifest) - 1,
                                                       iot.nx_azure_iot_pool_ptr, NX_NO_WAIT),
                        NX_AZURE_IOT_SUCCESS);
    }
    else if (g_adu_agent_http_data_type == HTTP_DATA_TYPE_FIRMWARE)
    {        
        assert_int_equal(__real__nx_packet_data_append(data_packet, (VOID *)g_adu_agent_firmware, g_adu_agent_firmware_size,
                                                       iot.nx_azure_iot_pool_ptr, NX_NO_WAIT),
                        NX_AZURE_IOT_SUCCESS);
    }
    else
    {
        assert_int_equal(__real__nx_packet_data_append(data_packet, fake_binary, sizeof(fake_binary) - 1,
                                                    iot.nx_azure_iot_pool_ptr, NX_NO_WAIT),
                        NX_AZURE_IOT_SUCCESS);
    }

    *packet_ptr = data_packet;

    return(NX_WEB_HTTP_GET_DONE);
}

static UINT mqtt_client_set_fixed_header(NXD_MQTT_CLIENT *client_ptr, NX_PACKET *packet_ptr, UCHAR control_header, UINT length, UINT wait_option)
{
UCHAR  fixed_header[5];
UCHAR *byte = fixed_header;
UINT   count = 0;
UINT   ret;

    *byte = control_header;
    byte++;

    do
    {
        if (length & 0xFFFFFF80)
        {
            *(byte + count) = (UCHAR)((length & 0x7F) | 0x80);
        }
        else
        {
            *(byte + count) = length & 0x7F;
        }
        length = length >> 7;

        count++;
    } while (length != 0);

    ret = __real__nx_packet_data_append(packet_ptr, fixed_header, count + 1,
                                        client_ptr -> nxd_mqtt_client_packet_pool_ptr, wait_option);

    return(ret);
}

static VOID construct_command_message(NX_AZURE_IOT_HUB_CLIENT *iothub_client_ptr,
                                      const UCHAR *topic, ULONG topic_len,
                                      const UCHAR *message_payload_ptr, ULONG message_payload_length,
                                      NX_PACKET **packet_pptr)
{
NX_PACKET *packet_ptr;
ULONG total_length;
ULONG topic_length = topic_len;
UCHAR bytes[2];
UINT i;

    assert_int_equal(nx_packet_allocate(iot.nx_azure_iot_pool_ptr, &packet_ptr, 0, NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);
    total_length = topic_length + 2 + 2 + message_payload_length; /* Two bytes for fixed topic_length field
                                                                     and two bytes for packet id. */

    /* Set fixed header. */
    assert_int_equal(mqtt_client_set_fixed_header(&(MQTT_CLIENT_GET(iothub_client_ptr)), packet_ptr,
                                                  (UCHAR)((MQTT_CONTROL_PACKET_TYPE_PUBLISH << 4) | MQTT_PUBLISH_QOS_LEVEL_1),
                                                  total_length, NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);

    /* Set topic length. */
    bytes[0] = (topic_length >> 8) & 0xFF;
    bytes[1] = topic_length & 0xFF;
    assert_int_equal(__real__nx_packet_data_append(packet_ptr, bytes, sizeof(bytes),
                                                   iot.nx_azure_iot_pool_ptr, NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);

    /* Set topic. */
    assert_int_equal(__real__nx_packet_data_append(packet_ptr, (VOID *)topic, topic_len,
                                                   iot.nx_azure_iot_pool_ptr, NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);
    /* Set packet ID. The value does not matter. */
    assert_int_equal(__real__nx_packet_data_append(packet_ptr, bytes, sizeof(bytes),
                                                   iot.nx_azure_iot_pool_ptr, NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);

    /* Set message payload. */
    if (message_payload_length > 0)
    {
        assert_int_equal(__real__nx_packet_data_append(packet_ptr, (VOID *)message_payload_ptr, message_payload_length,
                                                       iot.nx_azure_iot_pool_ptr, NX_NO_WAIT),
                         NX_AZURE_IOT_SUCCESS);
    }

    *packet_pptr = packet_ptr;
}

#if 0
extern UINT nx_azure_iot_adu_agent_component_properties_process(VOID *reader_ptr,
                                                                ULONG version,
                                                                VOID *args);
                                                         
static VOID inject_new_update(NX_AZURE_IOT_HUB_CLIENT *iothub_client_ptr)
{
NX_AZURE_IOT_JSON_READER reader_ptr;

    nx_azure_iot_json_reader_with_buffer_init(&reader_ptr, g_adu_agent_service_metedata, sizeof(g_adu_agent_service_metedata) - 1);

    nx_azure_iot_json_reader_next_token(&reader_ptr);

    nx_azure_iot_json_reader_next_token(&reader_ptr);

    nx_azure_iot_adu_agent_component_properties_process(&reader_ptr, g_version, &adu_agent);
}
#endif

static UCHAR topic_buffer[100];
static VOID generate_test_property_send_response(NX_AZURE_IOT_HUB_CLIENT *iothub_client_ptr)
{
NX_PACKET *packet_ptr;
UINT topic_size;

    printf("Bytes : %s\n", __func__);

    topic_size = snprintf(topic_buffer, sizeof(topic_buffer), reported_property_success_topic, reported_property_success_topic_count);
    construct_command_message(iothub_client_ptr, topic_buffer,
                              topic_size, "", 0, &packet_ptr);

    /* Simulate callback from MQTT layer.  */
    MQTT_CLIENT_GET(iothub_client_ptr).message_receive_queue_head = packet_ptr;
    MQTT_CLIENT_GET(iothub_client_ptr).message_receive_queue_depth = 1;
    tx_mutex_get(TX_MUTEX_GET(iothub_client_ptr), NX_WAIT_FOREVER);
    test_receive_notify(&(MQTT_CLIENT_GET(iothub_client_ptr)), 1);
    tx_mutex_put(TX_MUTEX_GET(iothub_client_ptr));
}

static VOID generate_test_property_new_update_send(NX_AZURE_IOT_HUB_CLIENT *iothub_client_ptr)
{
NX_PACKET *packet_ptr;
UINT topic_size;

    printf("Bytes : %s\n", __func__);

    topic_size = snprintf(topic_buffer, sizeof(topic_buffer), reported_property_success_topic, reported_property_success_topic_count);
    construct_command_message(iothub_client_ptr, 
                              g_adu_agent_new_udpate_topic,
                              sizeof(g_adu_agent_new_udpate_topic) - 1,
                              g_adu_agent_new_udpate,
                              g_adu_agent_new_udpate_size - 1,
                              &packet_ptr);

    /* Simulate callback from MQTT layer.  */
    MQTT_CLIENT_GET(iothub_client_ptr).message_receive_queue_head = packet_ptr;
    MQTT_CLIENT_GET(iothub_client_ptr).message_receive_queue_depth = 1;
    tx_mutex_get(TX_MUTEX_GET(iothub_client_ptr), NX_WAIT_FOREVER);
    test_receive_notify(&(MQTT_CLIENT_GET(iothub_client_ptr)), 1);
    tx_mutex_put(TX_MUTEX_GET(iothub_client_ptr));
}

static VOID generate_test_property_cancel_update_send(NX_AZURE_IOT_HUB_CLIENT *iothub_client_ptr)
{
NX_PACKET *packet_ptr;
UINT topic_size;

    printf("Bytes : %s\n", __func__);

    topic_size = snprintf(topic_buffer, sizeof(topic_buffer), reported_property_success_topic, reported_property_success_topic_count);
    construct_command_message(iothub_client_ptr, 
                              g_adu_agent_cancel_udpate_topic,
                              sizeof(g_adu_agent_cancel_udpate_topic) - 1,
                              g_adu_agent_cancel_update,
                              sizeof(g_adu_agent_cancel_update) - 1,
                              &packet_ptr);

    /* Simulate callback from MQTT layer.  */
    MQTT_CLIENT_GET(iothub_client_ptr).message_receive_queue_head = packet_ptr;
    MQTT_CLIENT_GET(iothub_client_ptr).message_receive_queue_depth = 1;
    tx_mutex_get(TX_MUTEX_GET(iothub_client_ptr), NX_WAIT_FOREVER);
    test_receive_notify(&(MQTT_CLIENT_GET(iothub_client_ptr)), 1);
    tx_mutex_put(TX_MUTEX_GET(iothub_client_ptr));
}

/* Generate network received bytes */
static VOID network_bytes_generate_entry(ULONG args)
{
    while (NX_TRUE)
    {
        if (generate_test_property_send_response_bytes)
        {
            generate_test_property_send_response_bytes = NX_FALSE;
            generate_test_property_send_response(&iothub_client);
        }

        if (generate_test_properties_new_update)
        {
            generate_test_properties_new_update = NX_FALSE;
            generate_test_property_new_update_send(&iothub_client);
        }

        tx_thread_sleep(NX_IP_PERIODIC_RATE);
    }
}

static VOID on_receive_callback(NX_AZURE_IOT_HUB_CLIENT *iothub_client_ptr, VOID *arg)
{
    *((UINT *)arg) = 1;
}

static VOID reported_property_cb(NX_AZURE_IOT_HUB_CLIENT *iothub_client_ptr,
                                 UINT request_id, UINT response_status,
                                 ULONG version, VOID *args)
{
    *((UINT *)args) = response_status;
}

static VOID reset_global_state()
{
    /* reset global state */
    g_failed_append_index = (UINT)-1;
    g_total_append = 0;
    g_failed_allocation_index = (UINT)-1;
    g_total_allocation = 0;
    generate_test_property_send_response_bytes = NX_FALSE;
    generate_test_properties_new_update = NX_FALSE;
}

/* Hook execute before all tests. */
static VOID test_suit_begin()
{
    assert_int_equal(tx_thread_create(&network_bytes_generate_thread,
                                      "UintTestNetworkBytesGenerator",
                                      network_bytes_generate_entry, 0,
                                      network_bytes_generate_stack,
                                      DEMO_HELPER_STACK_SIZE,
                                      DEMO_HELPER_THREAD_PRIORITY + 1,
                                      DEMO_HELPER_THREAD_PRIORITY + 1,
                                      TX_NO_TIME_SLICE, TX_AUTO_START),
                     NX_AZURE_IOT_SUCCESS);

    /* Initialize root certificate.  */
    assert_int_equal(nx_secure_x509_certificate_initialize(&root_ca_cert,
                                                           (UCHAR *)_nx_azure_iot_root_cert,
                                                           (USHORT)_nx_azure_iot_root_cert_size,
                                                           NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE),
                     NX_AZURE_IOT_SUCCESS);

    /* Initialize azure iot handle.  */
    assert_int_equal(nx_azure_iot_create(&iot, (UCHAR *)"Azure IoT",
                                         g_ip_ptr, g_pool_ptr, g_dns_ptr,
                                         (UCHAR *)demo_cloud_thread_stack,
                                         sizeof(demo_cloud_thread_stack),
                                         DEMO_CLOUD_THREAD_PRIORITY, unix_time_get),
                     NX_AZURE_IOT_SUCCESS);


    /* Initialize azure iot handle.  */
    assert_int_equal(nx_azure_iot_hub_client_initialize(&iothub_client, &iot,
                                                        STRING_UNSIGNED_ARGS(g_hostname),
                                                        STRING_UNSIGNED_ARGS(g_device_id),
                                                        STRING_UNSIGNED_ARGS(""),
                                                        _nx_azure_iot_tls_supported_crypto,
                                                        _nx_azure_iot_tls_supported_crypto_size,
                                                        _nx_azure_iot_tls_ciphersuite_map,
                                                        _nx_azure_iot_tls_ciphersuite_map_size,
                                                        metadata_buffer, sizeof(metadata_buffer),
                                                        &root_ca_cert),
                     NX_AZURE_IOT_SUCCESS);

    /* Set model id.  */
    assert_int_equal(nx_azure_iot_hub_client_model_id_set(&iothub_client,
                                                          STRING_UNSIGNED_ARGS(g_pnp_model_id)),
                     NX_AZURE_IOT_SUCCESS);

    /* Set symmetric key credentials  */
    assert_int_equal(nx_azure_iot_hub_client_symmetric_key_set(&iothub_client,
                                                               g_symmetric_key,
                                                               sizeof(g_symmetric_key) - 1),
                     NX_AZURE_IOT_SUCCESS);

    will_return_always(__wrap__nxde_mqtt_client_subscribe, NX_AZURE_IOT_SUCCESS);

    /* Connect IoTHub client */
    assert_int_equal(nx_azure_iot_hub_client_connect(&iothub_client, NX_FALSE, NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);
                     
    /* Enable properties.  */     
    assert_int_equal(nx_azure_iot_hub_client_properties_enable(&iothub_client),
                     NX_AZURE_IOT_SUCCESS);  
}

/* Hook execute after all tests are executed successfully */
static VOID test_suit_end()
{
    assert_int_equal(nx_azure_iot_hub_client_disconnect(&iothub_client),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_hub_client_deinitialize(&iothub_client),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_delete(&iot),
                     NX_AZURE_IOT_SUCCESS);
}

/* Hook executed before every test */
static VOID test_begin()
{
    reset_global_state();

    /* Record number of available packet before test */
    g_available_packet = g_pool_ptr -> nx_packet_pool_available;
}

/* Hook execute after all tests are executed successfully */
static VOID test_end()
{
    /* Check if all the packet are released */
    assert_int_equal(g_pool_ptr -> nx_packet_pool_available, g_available_packet);
}

static void nx_azure_iot_adu_agent_driver(NX_AZURE_IOT_ADU_AGENT_DRIVER *driver_req_ptr)
{

    /* Default to successful return.  */
    driver_req_ptr -> nx_azure_iot_adu_agent_driver_status = NX_AZURE_IOT_SUCCESS;
        
    /* Process according to the driver request type.  */
    switch (driver_req_ptr -> nx_azure_iot_adu_agent_driver_command)
    {
        
        case NX_AZURE_IOT_ADU_AGENT_DRIVER_INITIALIZE:
        {
           
            /* Process initialize requests.  */
            break;
        }
            
        case NX_AZURE_IOT_ADU_AGENT_DRIVER_PREPROCESS:
        {
        
            /* Process firmware preprocess requests before writing firmware.
               Such as: erase the flash at once to improve the speed.  */
            if (g_adu_agent_driver_preprocess_fail)
            {
                driver_req_ptr -> nx_azure_iot_adu_agent_driver_status = NX_AZURE_IOT_FAILURE;
            }

            else if ((memcmp(driver_req_ptr -> nx_azure_iot_adu_agent_driver_firmware_sha256, "qr+xRWnfo/POaFNv+KVddBsJngGxCiSQ25WEW8t4dLc=", driver_req_ptr -> nx_azure_iot_adu_agent_driver_firmware_sha256_length) != 0) &&
                     (memcmp(driver_req_ptr -> nx_azure_iot_adu_agent_driver_firmware_sha256, "Fqv5r0ZD/x6ok0aRqJERX2JuW36O+GOxn0/r7aBJkOs=", driver_req_ptr -> nx_azure_iot_adu_agent_driver_firmware_sha256_length) != 0)) /* For update 2. */
            {
                driver_req_ptr -> nx_azure_iot_adu_agent_driver_status = NX_AZURE_IOT_FAILURE;
            }
    
            break;
        }
            
        case NX_AZURE_IOT_ADU_AGENT_DRIVER_WRITE:
        {
        
            /* Process firmware write requests.  */
            
            /* Write firmware contents.
               1. This function must support figure out which bank it should write to.
               2. Write firmware contents into new bank.
               3. Decrypt and authenticate the firmware itself if needed.
            */
            if (g_adu_agent_driver_write_fail)
            {
                driver_req_ptr -> nx_azure_iot_adu_agent_driver_status = NX_AZURE_IOT_FAILURE;
            }
            
            break;
        } 
            
        case NX_AZURE_IOT_ADU_AGENT_DRIVER_INSTALL:
        {

            /* Set the new firmware for next boot.  */
            if (g_adu_agent_driver_install_fail)
            {
                driver_req_ptr -> nx_azure_iot_adu_agent_driver_status = NX_AZURE_IOT_FAILURE;
            }

            break;
        } 
            
        case NX_AZURE_IOT_ADU_AGENT_DRIVER_APPLY:
        {

            /* Apply the new firmware, and reboot device from that.*/
            if (g_adu_agent_driver_apply_fail)
            {
                driver_req_ptr -> nx_azure_iot_adu_agent_driver_status = NX_AZURE_IOT_FAILURE;
            }
        
            break;
        } 
        default:
        {
                
            /* Invalid driver request.  */

            /* Default to successful return.  */
            driver_req_ptr -> nx_azure_iot_adu_agent_driver_status =  NX_AZURE_IOT_FAILURE;
        }
    }
}

#if (NX_AZURE_IOT_ADU_AGENT_PROXY_UPDATE_COUNT >= 1)
static void nx_azure_iot_adu_agent_proxy_driver(NX_AZURE_IOT_ADU_AGENT_DRIVER *driver_req_ptr)
{

    /* Default to successful return.  */
    driver_req_ptr -> nx_azure_iot_adu_agent_driver_status = NX_AZURE_IOT_SUCCESS;
        
    /* Process according to the driver request type.  */
    switch (driver_req_ptr -> nx_azure_iot_adu_agent_driver_command)
    {
        
        case NX_AZURE_IOT_ADU_AGENT_DRIVER_INITIALIZE:
        {
           
            /* Process initialize requests.  */
            break;
        }
            
        case NX_AZURE_IOT_ADU_AGENT_DRIVER_PREPROCESS:
        {
        
            /* Process firmware preprocess requests before writing firmware.
               Such as: erase the flash at once to improve the speed.  */
            if (g_adu_agent_proxy_driver_preprocess_fail)
            {
                driver_req_ptr -> nx_azure_iot_adu_agent_driver_status = NX_AZURE_IOT_FAILURE;
            }

            else if (memcmp(driver_req_ptr -> nx_azure_iot_adu_agent_driver_firmware_sha256, "qr+xRWnfo/POaFNv+KVddBsJngGxCiSQ25WEW8t4dLc=", driver_req_ptr -> nx_azure_iot_adu_agent_driver_firmware_sha256_length) != 0)
            {
                driver_req_ptr -> nx_azure_iot_adu_agent_driver_status = NX_AZURE_IOT_FAILURE;
            }

            break;
        }
            
        case NX_AZURE_IOT_ADU_AGENT_DRIVER_WRITE:
        {
        
            /* Process firmware write requests.  */
            
            /* Write firmware contents.
               1. This function must support figure out which bank it should write to.
               2. Write firmware contents into new bank.
               3. Decrypt and authenticate the firmware itself if needed.
            */
            if (g_adu_agent_proxy_driver_write_fail)
            {
                driver_req_ptr -> nx_azure_iot_adu_agent_driver_status = NX_AZURE_IOT_FAILURE;
            }
            
            break;
        } 
            
        case NX_AZURE_IOT_ADU_AGENT_DRIVER_INSTALL:
        {

            /* Set the new firmware for next boot.  */
            if (g_adu_agent_proxy_driver_install_fail)
            {
                driver_req_ptr -> nx_azure_iot_adu_agent_driver_status = NX_AZURE_IOT_FAILURE;
            }

            break;
        } 
            
        case NX_AZURE_IOT_ADU_AGENT_DRIVER_APPLY:
        {

            /* Apply the new firmware, and reboot device from that.*/
            if (g_adu_agent_proxy_driver_apply_fail)
            {
                driver_req_ptr -> nx_azure_iot_adu_agent_driver_status = NX_AZURE_IOT_FAILURE;
            }
        
            break;
        } 
        default:
        {
                
            /* Invalid driver request.  */

            /* Default to successful return.  */
            driver_req_ptr -> nx_azure_iot_adu_agent_driver_status =  NX_AZURE_IOT_FAILURE;
        }
    }
}
#endif /* (NX_AZURE_IOT_ADU_AGENT_PROXY_UPDATE_COUNT >= 1) */

static void adu_agent_update_notify(NX_AZURE_IOT_ADU_AGENT *adu_agent_ptr,
                                    UINT update_state,
                                    UCHAR *provider, UINT provider_length,
                                    UCHAR *name, UINT name_length,
                                    UCHAR *version, UINT version_length)
{

    if (update_state == NX_AZURE_IOT_ADU_AGENT_UPDATE_RECEIVED)
    {

        g_update_received_count++;

        if(handle_agent_update_received_notify)
        {
            /* Received new update.  */
            printf("Received new update: Provider: %.*s; Name: %.*s, Version: %.*s\r\n",
                provider_length, provider, name_length, name, version_length, version);

            /* Start to download and install update immediately for testing.  */
            nx_azure_iot_adu_agent_update_download_and_install(adu_agent_ptr);
        }
    }
    else if(update_state == NX_AZURE_IOT_ADU_AGENT_UPDATE_INSTALLED)
    {
        g_update_applied_count++;

        /* Start to apply update immediately for testing.  */
        nx_azure_iot_adu_agent_update_apply(adu_agent_ptr);
    }
}

/**
 * Test invalid argument failure.
 *
 **/
static VOID test_nx_azure_iot_adu_agent_invalid_argument_fail()
{
NX_AZURE_IOT_JSON_WRITER writer;
NX_AZURE_IOT_JSON_READER reader;
const UCHAR *component_name;
UINT length;

    printf("test starts =>: %s\n", __func__);

    assert_int_not_equal(nx_azure_iot_adu_agent_start(NX_NULL,
                                                      &iothub_client,
                                                      (const UCHAR *)SAMPLE_DEVICE_MANUFACTURER, sizeof(SAMPLE_DEVICE_MANUFACTURER) - 1,
                                                      (const UCHAR *)SAMPLE_DEVICE_MODEL, sizeof(SAMPLE_DEVICE_MODEL) - 1,
                                                      (const UCHAR *)SAMPLE_DEVICE_INSTALLED_CRITERIA, sizeof(SAMPLE_DEVICE_INSTALLED_CRITERIA) - 1,
                                                      adu_agent_update_notify,
                                                      nx_azure_iot_adu_agent_driver),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_adu_agent_start(&adu_agent,
                                                      NX_NULL,
                                                      (const UCHAR *)SAMPLE_DEVICE_MANUFACTURER, sizeof(SAMPLE_DEVICE_MANUFACTURER) - 1,
                                                      (const UCHAR *)SAMPLE_DEVICE_MODEL, sizeof(SAMPLE_DEVICE_MODEL) - 1,
                                                      (const UCHAR *)SAMPLE_DEVICE_INSTALLED_CRITERIA, sizeof(SAMPLE_DEVICE_INSTALLED_CRITERIA) - 1,
                                                      adu_agent_update_notify,
                                                      nx_azure_iot_adu_agent_driver),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_adu_agent_start(&adu_agent,
                                                      &iothub_client,
                                                      NX_NULL, sizeof(SAMPLE_DEVICE_MANUFACTURER) - 1,
                                                      (const UCHAR *)SAMPLE_DEVICE_MODEL, sizeof(SAMPLE_DEVICE_MODEL) - 1,
                                                      (const UCHAR *)SAMPLE_DEVICE_INSTALLED_CRITERIA, sizeof(SAMPLE_DEVICE_INSTALLED_CRITERIA) - 1,
                                                      adu_agent_update_notify,
                                                     nx_azure_iot_adu_agent_driver),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_adu_agent_start(&adu_agent,
                                                      &iothub_client,
                                                      (const UCHAR *)SAMPLE_DEVICE_MANUFACTURER, 0,
                                                      (const UCHAR *)SAMPLE_DEVICE_MODEL, sizeof(SAMPLE_DEVICE_MODEL) - 1,
                                                      (const UCHAR *)SAMPLE_DEVICE_INSTALLED_CRITERIA, sizeof(SAMPLE_DEVICE_INSTALLED_CRITERIA) - 1,
                                                      adu_agent_update_notify,
                                                      nx_azure_iot_adu_agent_driver),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_adu_agent_start(&adu_agent,
                                                      &iothub_client,
                                                      (const UCHAR *)SAMPLE_DEVICE_MANUFACTURER, sizeof(SAMPLE_DEVICE_MANUFACTURER) - 1,
                                                      NX_NULL, sizeof(SAMPLE_DEVICE_MODEL) - 1,
                                                      (const UCHAR *)SAMPLE_DEVICE_INSTALLED_CRITERIA, sizeof(SAMPLE_DEVICE_INSTALLED_CRITERIA) - 1,
                                                      adu_agent_update_notify,
                                                      nx_azure_iot_adu_agent_driver),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_adu_agent_start(&adu_agent,
                                                      &iothub_client,
                                                      (const UCHAR *)SAMPLE_DEVICE_MANUFACTURER, sizeof(SAMPLE_DEVICE_MANUFACTURER) - 1,
                                                      (const UCHAR *)SAMPLE_DEVICE_MODEL, 0,
                                                      (const UCHAR *)SAMPLE_DEVICE_INSTALLED_CRITERIA, sizeof(SAMPLE_DEVICE_INSTALLED_CRITERIA) - 1,
                                                      adu_agent_update_notify,
                                                      nx_azure_iot_adu_agent_driver),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_adu_agent_start(&adu_agent,
                                                      &iothub_client,
                                                      (const UCHAR *)SAMPLE_DEVICE_MANUFACTURER, sizeof(SAMPLE_DEVICE_MANUFACTURER) - 1,
                                                      (const UCHAR *)SAMPLE_DEVICE_MODEL, sizeof(SAMPLE_DEVICE_MODEL) - 1,
                                                      NX_NULL, sizeof(SAMPLE_DEVICE_INSTALLED_CRITERIA) - 1,
                                                      adu_agent_update_notify,
                                                      nx_azure_iot_adu_agent_driver),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_adu_agent_start(&adu_agent,
                                                      &iothub_client,
                                                      (const UCHAR *)SAMPLE_DEVICE_MANUFACTURER, sizeof(SAMPLE_DEVICE_MANUFACTURER) - 1,
                                                      (const UCHAR *)SAMPLE_DEVICE_MODEL, sizeof(SAMPLE_DEVICE_MODEL) - 1,
                                                      (const UCHAR *)SAMPLE_DEVICE_INSTALLED_CRITERIA, sizeof(SAMPLE_DEVICE_INSTALLED_CRITERIA) - 1,
                                                      adu_agent_update_notify,
                                                      NX_NULL),
                         NX_AZURE_IOT_SUCCESS);

#if (NX_AZURE_IOT_ADU_AGENT_PROXY_UPDATE_COUNT >= 1)

    assert_int_not_equal(nx_azure_iot_adu_agent_proxy_update_add(NX_NULL,
                                                                 (const UCHAR *)SAMPLE_LEAF_DEVICE_MANUFACTURER, sizeof(SAMPLE_LEAF_DEVICE_MANUFACTURER) - 1,
                                                                 (const UCHAR *)SAMPLE_LEAF_DEVICE_MODEL, sizeof(SAMPLE_LEAF_DEVICE_MODEL) - 1,
                                                                 (const UCHAR *)SAMPLE_LEAF_DEVICE_INSTALLED_CRITERIA, sizeof(SAMPLE_LEAF_DEVICE_INSTALLED_CRITERIA) - 1,
                                                                 nx_azure_iot_adu_agent_driver),
                         NX_AZURE_IOT_SUCCESS);
                        
    assert_int_not_equal(nx_azure_iot_adu_agent_proxy_update_add(&adu_agent,
                                                                 NX_NULL, sizeof(SAMPLE_LEAF_DEVICE_MANUFACTURER) - 1,
                                                                 (const UCHAR *)SAMPLE_LEAF_DEVICE_MODEL, sizeof(SAMPLE_LEAF_DEVICE_MODEL) - 1,
                                                                 (const UCHAR *)SAMPLE_LEAF_DEVICE_INSTALLED_CRITERIA, sizeof(SAMPLE_LEAF_DEVICE_INSTALLED_CRITERIA) - 1,
                                                                 nx_azure_iot_adu_agent_driver),
                         NX_AZURE_IOT_SUCCESS);
                         
    assert_int_not_equal(nx_azure_iot_adu_agent_proxy_update_add(&adu_agent,
                                                                 (const UCHAR *)SAMPLE_LEAF_DEVICE_MANUFACTURER, 0,
                                                                 (const UCHAR *)SAMPLE_LEAF_DEVICE_MODEL, sizeof(SAMPLE_LEAF_DEVICE_MODEL) - 1,
                                                                 (const UCHAR *)SAMPLE_LEAF_DEVICE_INSTALLED_CRITERIA, sizeof(SAMPLE_LEAF_DEVICE_INSTALLED_CRITERIA) - 1,
                                                                 nx_azure_iot_adu_agent_driver),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_adu_agent_proxy_update_add(&adu_agent,
                                                                 (const UCHAR *)SAMPLE_LEAF_DEVICE_MANUFACTURER, sizeof(SAMPLE_LEAF_DEVICE_MANUFACTURER) - 1,
                                                                 NX_NULL, sizeof(SAMPLE_LEAF_DEVICE_MODEL) - 1,
                                                                 (const UCHAR *)SAMPLE_LEAF_DEVICE_INSTALLED_CRITERIA, sizeof(SAMPLE_LEAF_DEVICE_INSTALLED_CRITERIA) - 1,
                                                                 nx_azure_iot_adu_agent_driver),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_adu_agent_proxy_update_add(&adu_agent,
                                                                 (const UCHAR *)SAMPLE_LEAF_DEVICE_MANUFACTURER, sizeof(SAMPLE_LEAF_DEVICE_MANUFACTURER) - 1,
                                                                 (const UCHAR *)SAMPLE_LEAF_DEVICE_MODEL, 0,
                                                                 (const UCHAR *)SAMPLE_LEAF_DEVICE_INSTALLED_CRITERIA, sizeof(SAMPLE_LEAF_DEVICE_INSTALLED_CRITERIA) - 1,
                                                                 nx_azure_iot_adu_agent_driver),
                         NX_AZURE_IOT_SUCCESS);


    assert_int_not_equal(nx_azure_iot_adu_agent_proxy_update_add(&adu_agent,
                                                                 (const UCHAR *)SAMPLE_LEAF_DEVICE_MANUFACTURER, sizeof(SAMPLE_LEAF_DEVICE_MANUFACTURER) - 1,
                                                                 (const UCHAR *)SAMPLE_LEAF_DEVICE_MODEL, sizeof(SAMPLE_LEAF_DEVICE_MODEL) - 1,
                                                                 NX_NULL, sizeof(SAMPLE_LEAF_DEVICE_INSTALLED_CRITERIA) - 1,
                                                                 nx_azure_iot_adu_agent_driver),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_adu_agent_proxy_update_add(&adu_agent,
                                                                 (const UCHAR *)SAMPLE_LEAF_DEVICE_MANUFACTURER, sizeof(SAMPLE_LEAF_DEVICE_MANUFACTURER) - 1,
                                                                 (const UCHAR *)SAMPLE_LEAF_DEVICE_MODEL, sizeof(SAMPLE_LEAF_DEVICE_MODEL) - 1,
                                                                 (const UCHAR *)SAMPLE_LEAF_DEVICE_INSTALLED_CRITERIA, sizeof(SAMPLE_LEAF_DEVICE_INSTALLED_CRITERIA) - 1,
                                                                 NX_NULL),
                         NX_AZURE_IOT_SUCCESS);

#endif /* (NX_AZURE_IOT_ADU_AGENT_PROXY_UPDATE_COUNT >= 1) */

    assert_int_not_equal(nx_azure_iot_adu_agent_stop(NX_NULL),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_adu_agent_update_download_and_install(NX_NULL),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_adu_agent_update_apply(NX_NULL),
                         NX_AZURE_IOT_SUCCESS);
}

/**
 * Test successful adu agent start.
 *
 **/
static VOID test_nx_azure_iot_adu_agent_start_success()
{
NX_AZURE_IOT_JSON_WRITER writer;
UINT request_id;
UINT response_status;
ULONG version;

    printf("test starts =>: %s\n", __func__);

    reported_property_success_topic_count = 1;
    generate_test_property_send_response_bytes = NX_TRUE;

    /* Build startup message.  */
    snprintf(g_adu_agent_reported_property_startup,
             sizeof(g_adu_agent_reported_property_startup),
             "%s%d.%d.%d%s",
             (const char *)g_adu_agent_reported_property_startup1,
             NETXDUO_MAJOR_VERSION,
             NETXDUO_MINOR_VERSION,
             NETXDUO_PATCH_VERSION,
             (const char *)g_adu_agent_reported_property_startup2);
    g_expected_message = g_adu_agent_reported_property_startup;

    assert_int_equal(nx_azure_iot_adu_agent_start(&adu_agent,
                                                  &iothub_client,
                                                  (const UCHAR *)SAMPLE_DEVICE_MANUFACTURER, sizeof(SAMPLE_DEVICE_MANUFACTURER) - 1,
                                                  (const UCHAR *)SAMPLE_DEVICE_MODEL, sizeof(SAMPLE_DEVICE_MODEL) - 1,
                                                  (const UCHAR *)SAMPLE_DEVICE_INSTALLED_CRITERIA, sizeof(SAMPLE_DEVICE_INSTALLED_CRITERIA) - 1,
                                                  adu_agent_update_notify,
                                                  nx_azure_iot_adu_agent_driver),
                    NX_AZURE_IOT_SUCCESS);


    /* Reset.  */
    g_expected_message = NX_NULL;
}

/**
 * Test adu agent update apply fail.
 *
 **/
static VOID test_nx_azure_iot_adu_agent_update_start_fail()
{
NX_AZURE_IOT_JSON_WRITER writer;
UINT request_id;
UINT response_status;
ULONG version;

    printf("test starts =>: %s\n", __func__);

    assert_int_not_equal(nx_azure_iot_adu_agent_update_download_and_install(NX_NULL),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_adu_agent_update_apply(NX_NULL),
                         NX_AZURE_IOT_SUCCESS);
}

/**
 * Test successful adu agent stop.
 *
 **/
static VOID test_nx_azure_iot_adu_agent_stop_success()
{
NX_AZURE_IOT_JSON_WRITER writer;
UINT request_id;
UINT response_status;
ULONG version;

    printf("test starts =>: %s\n", __func__);

    /* Stop ADU agent.  */
    assert_int_equal(nx_azure_iot_adu_agent_stop(&adu_agent),
                     NX_AZURE_IOT_SUCCESS);

    /* Restart ADU agent.  */
    reported_property_success_topic_count += 2;
    generate_test_property_send_response_bytes = NX_TRUE;

    assert_int_equal(nx_azure_iot_adu_agent_start(&adu_agent,
                                                  &iothub_client,
                                                  (const UCHAR *)SAMPLE_DEVICE_MANUFACTURER, sizeof(SAMPLE_DEVICE_MANUFACTURER) - 1,
                                                  (const UCHAR *)SAMPLE_DEVICE_MODEL, sizeof(SAMPLE_DEVICE_MODEL) - 1,
                                                  (const UCHAR *)SAMPLE_DEVICE_INSTALLED_CRITERIA, sizeof(SAMPLE_DEVICE_INSTALLED_CRITERIA) - 1,
                                                  adu_agent_update_notify,
                                                  nx_azure_iot_adu_agent_driver),
                     NX_AZURE_IOT_SUCCESS);
                         
    /* Stop ADU agent again.  */
    assert_int_equal(nx_azure_iot_adu_agent_stop(&adu_agent),
                     NX_AZURE_IOT_SUCCESS);
}

#if (NX_AZURE_IOT_ADU_AGENT_PROXY_UPDATE_COUNT >= 1)
/**
 * Test proxy add.
 *
 **/
static VOID test_nx_azure_iot_adu_agent_proxy_add()
{
NX_AZURE_IOT_JSON_WRITER writer;
UINT request_id;
UINT response_status;
ULONG version;

    printf("test starts =>: %s\n", __func__);

    /* Restart ADU agent.  */
    reported_property_success_topic_count += 2;
    generate_test_property_send_response_bytes = NX_TRUE;

    assert_int_equal(nx_azure_iot_adu_agent_start(&adu_agent,
                                                  &iothub_client,
                                                  (const UCHAR *)SAMPLE_DEVICE_MANUFACTURER, sizeof(SAMPLE_DEVICE_MANUFACTURER) - 1,
                                                  (const UCHAR *)SAMPLE_DEVICE_MODEL, sizeof(SAMPLE_DEVICE_MODEL) - 1,
                                                  (const UCHAR *)SAMPLE_DEVICE_INSTALLED_CRITERIA, sizeof(SAMPLE_DEVICE_INSTALLED_CRITERIA) - 1,
                                                  adu_agent_update_notify,
                                                  nx_azure_iot_adu_agent_driver),
                     NX_AZURE_IOT_SUCCESS);
                     
    assert_int_equal(nx_azure_iot_adu_agent_proxy_update_add(&adu_agent,
                                                             (const UCHAR *)SAMPLE_LEAF_DEVICE_MANUFACTURER, sizeof(SAMPLE_LEAF_DEVICE_MANUFACTURER) - 1,
                                                             (const UCHAR *)SAMPLE_LEAF_DEVICE_MODEL, sizeof(SAMPLE_LEAF_DEVICE_MODEL) - 1,
                                                             (const UCHAR *)SAMPLE_LEAF_DEVICE_INSTALLED_CRITERIA, sizeof(SAMPLE_LEAF_DEVICE_INSTALLED_CRITERIA) - 1,
                                                             nx_azure_iot_adu_agent_driver),
                     NX_AZURE_IOT_SUCCESS);
                     
    assert_int_equal(nx_azure_iot_adu_agent_proxy_update_add(&adu_agent,
                                                             (const UCHAR *)SAMPLE_LEAF2_DEVICE_MANUFACTURER, sizeof(SAMPLE_LEAF2_DEVICE_MANUFACTURER) - 1,
                                                             (const UCHAR *)SAMPLE_LEAF2_DEVICE_MODEL, sizeof(SAMPLE_LEAF2_DEVICE_MODEL) - 1,
                                                             (const UCHAR *)SAMPLE_LEAF2_DEVICE_INSTALLED_CRITERIA, sizeof(SAMPLE_LEAF2_DEVICE_INSTALLED_CRITERIA) - 1,
                                                             nx_azure_iot_adu_agent_driver),
                     NX_AZURE_IOT_NO_MORE_ENTRIES);
                         
    /* Stop ADU agent again.  */
    assert_int_equal(nx_azure_iot_adu_agent_stop(&adu_agent),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test step result.
 *
 **/
static VOID test_nx_azure_iot_adu_agent_step_result()
{
NX_AZURE_IOT_JSON_WRITER writer;
UINT request_id;
UINT response_status;
ULONG version;
NX_PACKET *packet_ptr;
UINT i;

    printf("test starts =>: %s\n", __func__);

    for (i = 0; i < 9; i++)
    {

        /* Restart ADU agent.  */
        reported_property_success_topic_count += 2;
        generate_test_property_send_response_bytes = NX_TRUE;
        handle_agent_update_received_notify = NX_TRUE;

        assert_int_equal(nx_azure_iot_adu_agent_start(&adu_agent,
                                                    &iothub_client,
                                                    (const UCHAR *)SAMPLE_DEVICE_MANUFACTURER, sizeof(SAMPLE_DEVICE_MANUFACTURER) - 1,
                                                    (const UCHAR *)SAMPLE_DEVICE_MODEL, sizeof(SAMPLE_DEVICE_MODEL) - 1,
                                                    (const UCHAR *)SAMPLE_DEVICE_INSTALLED_CRITERIA, sizeof(SAMPLE_DEVICE_INSTALLED_CRITERIA) - 1,
                                                    adu_agent_update_notify,
                                                    nx_azure_iot_adu_agent_driver),
                        NX_AZURE_IOT_SUCCESS);
                        
        assert_int_equal(nx_azure_iot_adu_agent_proxy_update_add(&adu_agent,
                                                                (const UCHAR *)SAMPLE_LEAF_DEVICE_MANUFACTURER, sizeof(SAMPLE_LEAF_DEVICE_MANUFACTURER) - 1,
                                                                (const UCHAR *)SAMPLE_LEAF_DEVICE_MODEL, sizeof(SAMPLE_LEAF_DEVICE_MODEL) - 1,
                                                                (const UCHAR *)SAMPLE_LEAF_DEVICE_INSTALLED_CRITERIA, sizeof(SAMPLE_LEAF_DEVICE_INSTALLED_CRITERIA) - 1,
                                                                nx_azure_iot_adu_agent_proxy_driver),
                        NX_AZURE_IOT_SUCCESS);
                        
        adu_agent.nx_azure_iot_adu_agent_crypto.method_rsa_metadata = g_adu_metadata;
        adu_agent.nx_azure_iot_adu_agent_crypto.method_rsa_metadata_size = sizeof(g_adu_metadata);
        
        /* Set the expected message and check the third mesage (reported state message).  */
        if (i == 0)
        {
            g_adu_agent_proxy_driver_preprocess_fail = NX_TRUE;
            g_expected_message = g_adu_agent_response_proxy_preprocess_error;
        }
        else if (i == 1)
        {
            g_adu_agent_proxy_driver_write_fail = NX_TRUE;
            g_expected_message = g_adu_agent_response_proxy_write_error;
        }
        else if (i == 2)
        {
            g_adu_agent_proxy_driver_install_fail = NX_TRUE;
            g_expected_message = g_adu_agent_response_proxy_write_error;
        }
        else if (i == 3)
        {
            g_adu_agent_driver_preprocess_fail = NX_TRUE;
            g_expected_message = g_adu_agent_response_preprocess_error;
        }
        else if (i == 4)
        {
            g_adu_agent_driver_write_fail = NX_TRUE;
            g_expected_message = g_adu_agent_response_write_error;
        }
        else if (i == 5)
        {
            g_adu_agent_driver_install_fail = NX_TRUE;
            g_expected_message = g_adu_agent_response_write_error;
        }
        else if (i == 6)
        {
            g_adu_agent_proxy_driver_apply_fail = NX_TRUE;
            g_expected_message = g_adu_agent_response_proxy_apply_error;
        }
        else if (i == 7)
        {
            g_adu_agent_driver_apply_fail = NX_TRUE;
            g_expected_message = g_adu_agent_response_apply_error;
        }
        else
        {
            g_expected_message = g_adu_agent_response_success;
        }

        g_expected_message_index = 2;
        reported_property_success_topic_count += 6;

        /* Inject the new update message.  */
        g_adu_agent_new_udpate = g_adu_agent_new_update_3;
        g_adu_agent_new_udpate_size = sizeof(g_adu_agent_new_update_3);
        generate_test_property_new_update_send(&iothub_client);

        tx_thread_sleep(100);

        assert_int_equal(nx_azure_iot_hub_client_writable_properties_receive(&iothub_client,
                                                                            &packet_ptr,
                                                                            NX_WAIT_FOREVER),
                        NX_AZURE_IOT_SUCCESS);

        assert_int_equal(nx_packet_release(packet_ptr),
                        NX_AZURE_IOT_SUCCESS);                     

        /* Receive proxy manifest.  */
        g_adu_agent_http_data_type = HTTP_DATA_TYPE_PROXY_MANIFEST;
        nx_cloud_module_event_set(&(adu_agent.nx_azure_iot_adu_agent_cloud_module), NX_AZURE_IOT_ADU_AGENT_HTTP_RECEIVE_EVENT);
        tx_thread_sleep(100);

        if (i != 0)
        {

            /* Receive proxy firmware.  */
            g_adu_agent_http_data_type = HTTP_DATA_TYPE_FIRMWARE;
            nx_cloud_module_event_set(&(adu_agent.nx_azure_iot_adu_agent_cloud_module), NX_AZURE_IOT_ADU_AGENT_HTTP_RECEIVE_EVENT);
            tx_thread_sleep(100);
        }

        if (i >= 4)
        {

            /* Receive firmware.  */
            g_adu_agent_http_data_type = HTTP_DATA_TYPE_FIRMWARE;
            nx_cloud_module_event_set(&(adu_agent.nx_azure_iot_adu_agent_cloud_module), NX_AZURE_IOT_ADU_AGENT_HTTP_RECEIVE_EVENT);
            tx_thread_sleep(100);
        }

        /* Stop ADU agent.  */
        assert_int_equal(nx_azure_iot_adu_agent_stop(&adu_agent),
                        NX_AZURE_IOT_SUCCESS);

        /* Reset */
        g_adu_agent_proxy_driver_preprocess_fail = NX_FALSE;
        g_adu_agent_proxy_driver_write_fail = NX_FALSE;
        g_adu_agent_proxy_driver_install_fail = NX_FALSE;
        g_adu_agent_proxy_driver_apply_fail = NX_FALSE;
        g_adu_agent_driver_preprocess_fail = NX_FALSE;
        g_adu_agent_driver_write_fail = NX_FALSE;
        g_adu_agent_driver_install_fail = NX_FALSE;
        g_adu_agent_driver_apply_fail = NX_FALSE;
        g_expected_message = NX_NULL;
    }
}


/**
 * Test null file url.
 *
 **/
static VOID test_nx_azure_iot_adu_agent_null_file_url()
{
NX_AZURE_IOT_JSON_WRITER writer;
UINT request_id;
UINT response_status;
ULONG version;
NX_PACKET *packet_ptr;

    printf("test starts =>: %s\n", __func__);

    /* Restart ADU agent.  */
    reported_property_success_topic_count += 2;
    generate_test_property_send_response_bytes = NX_TRUE;
    handle_agent_update_received_notify = NX_TRUE;

    assert_int_equal(nx_azure_iot_adu_agent_start(&adu_agent,
                                                &iothub_client,
                                                (const UCHAR *)SAMPLE_DEVICE_MANUFACTURER, sizeof(SAMPLE_DEVICE_MANUFACTURER) - 1,
                                                (const UCHAR *)SAMPLE_DEVICE_MODEL, sizeof(SAMPLE_DEVICE_MODEL) - 1,
                                                (const UCHAR *)SAMPLE_DEVICE_INSTALLED_CRITERIA, sizeof(SAMPLE_DEVICE_INSTALLED_CRITERIA) - 1,
                                                adu_agent_update_notify,
                                                nx_azure_iot_adu_agent_driver),
                    NX_AZURE_IOT_SUCCESS);
                    
    assert_int_equal(nx_azure_iot_adu_agent_proxy_update_add(&adu_agent,
                                                            (const UCHAR *)SAMPLE_LEAF_DEVICE_MANUFACTURER, sizeof(SAMPLE_LEAF_DEVICE_MANUFACTURER) - 1,
                                                            (const UCHAR *)SAMPLE_LEAF_DEVICE_MODEL, sizeof(SAMPLE_LEAF_DEVICE_MODEL) - 1,
                                                            (const UCHAR *)SAMPLE_LEAF_DEVICE_INSTALLED_CRITERIA, sizeof(SAMPLE_LEAF_DEVICE_INSTALLED_CRITERIA) - 1,
                                                            nx_azure_iot_adu_agent_proxy_driver),
                    NX_AZURE_IOT_SUCCESS);
                    
    adu_agent.nx_azure_iot_adu_agent_crypto.method_rsa_metadata = g_adu_metadata;
    adu_agent.nx_azure_iot_adu_agent_crypto.method_rsa_metadata_size = sizeof(g_adu_metadata);
    
    g_expected_message = g_adu_agent_response_success;
    g_expected_message_index = 2;
    reported_property_success_topic_count += 6;

    /* Inject the new update message.  */
    g_adu_agent_new_udpate = g_adu_agent_new_update_4;
    g_adu_agent_new_udpate_size = sizeof(g_adu_agent_new_update_4);
    generate_test_property_new_update_send(&iothub_client);

    tx_thread_sleep(100);

    assert_int_equal(nx_azure_iot_hub_client_writable_properties_receive(&iothub_client,
                                                                        &packet_ptr,
                                                                        NX_WAIT_FOREVER),
                    NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_packet_release(packet_ptr),
                    NX_AZURE_IOT_SUCCESS);                     

    /* Receive proxy manifest.  */
    g_adu_agent_http_data_type = HTTP_DATA_TYPE_PROXY_MANIFEST;
    nx_cloud_module_event_set(&(adu_agent.nx_azure_iot_adu_agent_cloud_module), NX_AZURE_IOT_ADU_AGENT_HTTP_RECEIVE_EVENT);
    tx_thread_sleep(100);

    /* Receive proxy firmware.  */
    g_adu_agent_http_data_type = HTTP_DATA_TYPE_FIRMWARE;
    nx_cloud_module_event_set(&(adu_agent.nx_azure_iot_adu_agent_cloud_module), NX_AZURE_IOT_ADU_AGENT_HTTP_RECEIVE_EVENT);
    tx_thread_sleep(100);

    /* Receive firmware.  */
    g_adu_agent_http_data_type = HTTP_DATA_TYPE_FIRMWARE;
    nx_cloud_module_event_set(&(adu_agent.nx_azure_iot_adu_agent_cloud_module), NX_AZURE_IOT_ADU_AGENT_HTTP_RECEIVE_EVENT);
    tx_thread_sleep(100);

    /* Stop ADU agent.  */
    assert_int_equal(nx_azure_iot_adu_agent_stop(&adu_agent),
                    NX_AZURE_IOT_SUCCESS);
                    
    g_expected_message = NX_NULL;
}
#endif /* (NX_AZURE_IOT_ADU_AGENT_PROXY_UPDATE_COUNT >= 1) */

/**
 * Test notify.
 *
 **/
static VOID test_nx_azure_iot_adu_agent_notify()
{
NX_AZURE_IOT_JSON_WRITER writer;
UINT request_id;
UINT response_status;
ULONG version;
NX_PACKET *packet_ptr;

    printf("test starts =>: %s\n", __func__);

    /* Restart ADU agent.  */
    reported_property_success_topic_count += 2;
    generate_test_property_send_response_bytes = NX_TRUE;
    g_update_received_count = 0;

    assert_int_equal(nx_azure_iot_adu_agent_start(&adu_agent,
                                                  &iothub_client,
                                                  (const UCHAR *)SAMPLE_DEVICE_MANUFACTURER, sizeof(SAMPLE_DEVICE_MANUFACTURER) - 1,
                                                  (const UCHAR *)SAMPLE_DEVICE_MODEL, sizeof(SAMPLE_DEVICE_MODEL) - 1,
                                                  (const UCHAR *)SAMPLE_DEVICE_INSTALLED_CRITERIA, sizeof(SAMPLE_DEVICE_INSTALLED_CRITERIA) - 1,
                                                  adu_agent_update_notify,
                                                  nx_azure_iot_adu_agent_driver),
                     NX_AZURE_IOT_SUCCESS);
                     
    adu_agent.nx_azure_iot_adu_agent_crypto.method_rsa_metadata = g_adu_metadata;
    adu_agent.nx_azure_iot_adu_agent_crypto.method_rsa_metadata_size = sizeof(g_adu_metadata);
    
    g_adu_agent_new_udpate = g_adu_agent_new_udpate_1;
    g_adu_agent_new_udpate_size = sizeof(g_adu_agent_new_udpate_1);
    generate_test_property_new_update_send(&iothub_client);

    tx_thread_sleep(100);

    /* New update check.  */
    assert_int_equal(g_update_received_count, 1);

    assert_int_equal(nx_azure_iot_hub_client_writable_properties_receive(&iothub_client,
                                                                         &packet_ptr,
                                                                         NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);
                     
    assert_int_equal(nx_packet_release(packet_ptr),
                     NX_AZURE_IOT_SUCCESS);

    /* Stop ADU agent.  */
    assert_int_equal(nx_azure_iot_adu_agent_stop(&adu_agent),
                     NX_AZURE_IOT_SUCCESS);
                     
    /* Restart ADU agent with same installed criteria.  */
    reported_property_success_topic_count += 6;
    generate_test_property_send_response_bytes = NX_TRUE;

    assert_int_equal(nx_azure_iot_adu_agent_start(&adu_agent,
                                                  &iothub_client,
                                                  (const UCHAR *)SAMPLE_DEVICE_MANUFACTURER, sizeof(SAMPLE_DEVICE_MANUFACTURER) - 1,
                                                  (const UCHAR *)SAMPLE_DEVICE_MODEL, sizeof(SAMPLE_DEVICE_MODEL) - 1,
                                                  (const UCHAR *)SAMPLE_DEVICE_INSTALLED_CRITERIA_NEW, sizeof(SAMPLE_DEVICE_INSTALLED_CRITERIA_NEW) - 1,
                                                  adu_agent_update_notify,
                                                  nx_azure_iot_adu_agent_driver),
                     NX_AZURE_IOT_SUCCESS);
                     
    adu_agent.nx_azure_iot_adu_agent_crypto.method_rsa_metadata = g_adu_metadata;
    adu_agent.nx_azure_iot_adu_agent_crypto.method_rsa_metadata_size = sizeof(g_adu_metadata);
    
    reported_property_success_topic_count += 4;

    generate_test_property_new_update_send(&iothub_client);

    tx_thread_sleep(100);

    /* Same update check.  */
    assert_int_equal(g_update_received_count, 1);
    
    assert_int_equal(nx_azure_iot_hub_client_writable_properties_receive(&iothub_client,
                                                                         &packet_ptr,
                                                                         NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);
                     
    assert_int_equal(nx_packet_release(packet_ptr),
                     NX_AZURE_IOT_SUCCESS);

    /* Stop ADU agent.  */
    assert_int_equal(nx_azure_iot_adu_agent_stop(&adu_agent),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test update cancel.
 *
 **/
static VOID test_nx_azure_iot_adu_agent_update_cancel()
{
NX_AZURE_IOT_JSON_WRITER writer;
UINT request_id;
UINT response_status;
ULONG version;
NX_PACKET *packet_ptr;

    printf("test starts =>: %s\n", __func__);

    reported_property_success_topic_count += 2;
    generate_test_property_send_response_bytes = NX_TRUE;

    assert_int_equal(nx_azure_iot_adu_agent_start(&adu_agent,
                                                  &iothub_client,
                                                  (const UCHAR *)SAMPLE_DEVICE_MANUFACTURER, sizeof(SAMPLE_DEVICE_MANUFACTURER) - 1,
                                                  (const UCHAR *)SAMPLE_DEVICE_MODEL, sizeof(SAMPLE_DEVICE_MODEL) - 1,
                                                  (const UCHAR *)SAMPLE_DEVICE_INSTALLED_CRITERIA, sizeof(SAMPLE_DEVICE_INSTALLED_CRITERIA) - 1,
                                                  adu_agent_update_notify,
                                                  nx_azure_iot_adu_agent_driver),
                    NX_AZURE_IOT_SUCCESS);

    /* Set the expected message and check the second mesage.  */
    g_expected_message = g_adu_agent_cancel_response;
    g_expected_message_index++;

    reported_property_success_topic_count += 4;

    generate_test_property_cancel_update_send(&iothub_client);

    tx_thread_sleep(100);
                     
    /* Reset.  */
    g_expected_message = NX_NULL;
    
    assert_int_equal(nx_azure_iot_hub_client_writable_properties_receive(&iothub_client,
                                                                         &packet_ptr,
                                                                         NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);
                     
    assert_int_equal(nx_packet_release(packet_ptr),
                     NX_AZURE_IOT_SUCCESS);

    /* Stop ADU agent.  */
    assert_int_equal(nx_azure_iot_adu_agent_stop(&adu_agent),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test install success.
 *
 **/
static VOID test_nx_azure_iot_adu_agent_install()
{
NX_AZURE_IOT_JSON_WRITER writer;
UINT request_id;
UINT response_status;
ULONG version;
NX_PACKET *packet_ptr;

    printf("test starts =>: %s\n", __func__);

    /* Restart ADU agent.  */
    g_update_received_count = 0;
    g_update_applied_count = 0;
    reported_property_success_topic_count += 2;
    generate_test_property_send_response_bytes = NX_TRUE;
    handle_agent_update_received_notify = NX_TRUE;

    assert_int_equal(nx_azure_iot_adu_agent_start(&adu_agent,
                                                  &iothub_client,
                                                  (const UCHAR *)SAMPLE_DEVICE_MANUFACTURER, sizeof(SAMPLE_DEVICE_MANUFACTURER) - 1,
                                                  (const UCHAR *)SAMPLE_DEVICE_MODEL, sizeof(SAMPLE_DEVICE_MODEL) - 1,
                                                  (const UCHAR *)SAMPLE_DEVICE_INSTALLED_CRITERIA, sizeof(SAMPLE_DEVICE_INSTALLED_CRITERIA) - 1,
                                                  adu_agent_update_notify,
                                                  nx_azure_iot_adu_agent_driver),
                     NX_AZURE_IOT_SUCCESS);
                     
    adu_agent.nx_azure_iot_adu_agent_crypto.method_rsa_metadata = g_adu_metadata;
    adu_agent.nx_azure_iot_adu_agent_crypto.method_rsa_metadata_size = sizeof(g_adu_metadata);
    
    g_adu_agent_new_udpate = g_adu_agent_new_udpate_2;
    g_adu_agent_new_udpate_size = sizeof(g_adu_agent_new_udpate_2);
    generate_test_property_new_update_send(&iothub_client);

    tx_thread_sleep(100);

    /* New update check.  */
    assert_int_equal(g_update_received_count, 1);

    assert_int_equal(nx_azure_iot_hub_client_writable_properties_receive(&iothub_client,
                                                                         &packet_ptr,
                                                                         NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_packet_release(packet_ptr),
                     NX_AZURE_IOT_SUCCESS);
    
    g_adu_agent_http_data_type = 0;

    nx_cloud_module_event_set(&(adu_agent.nx_azure_iot_adu_agent_cloud_module), NX_AZURE_IOT_ADU_AGENT_HTTP_RECEIVE_EVENT);
    tx_thread_sleep(100);

    assert_int_equal(g_update_applied_count, 1);

    /* Stop ADU agent.  */
    assert_int_equal(nx_azure_iot_adu_agent_stop(&adu_agent),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test adu agent start failure as pnp is not enabled.
 *
 **/
static VOID test_nx_azure_iot_adu_agent_start_fail_with_no_pnp()
{

    printf("test starts =>: %s\n", __func__);

    /* Clear model id.  */
    iothub_client.iot_hub_client_core._internal.options.model_id = AZ_SPAN_EMPTY;

    assert_int_equal(nx_azure_iot_adu_agent_start(&adu_agent,
                                                  &iothub_client,
                                                  (const UCHAR *)SAMPLE_DEVICE_MANUFACTURER, sizeof(SAMPLE_DEVICE_MANUFACTURER) - 1,
                                                  (const UCHAR *)SAMPLE_DEVICE_MODEL, sizeof(SAMPLE_DEVICE_MODEL) - 1,
                                                  (const UCHAR *)SAMPLE_DEVICE_INSTALLED_CRITERIA, sizeof(SAMPLE_DEVICE_INSTALLED_CRITERIA) - 1,
                                                  adu_agent_update_notify,
                                                  nx_azure_iot_adu_agent_driver),
                    NX_AZURE_IOT_NOT_ENABLED);
   
    /* Set model id.  */
    assert_int_equal(nx_azure_iot_hub_client_model_id_set(&iothub_client,
                                                          STRING_UNSIGNED_ARGS(g_pnp_model_id)),
                     NX_AZURE_IOT_SUCCESS);
}

VOID demo_entry(NX_IP* ip_ptr, NX_PACKET_POOL* pool_ptr, NX_DNS* dns_ptr, UINT (*unix_time_callback)(ULONG *unix_time))
{
    NX_AZURE_TEST_FN tests[] = {test_nx_azure_iot_adu_agent_invalid_argument_fail,
                                test_nx_azure_iot_adu_agent_start_success,
                                test_nx_azure_iot_adu_agent_update_start_fail,
                                test_nx_azure_iot_adu_agent_stop_success,
#if (NX_AZURE_IOT_ADU_AGENT_PROXY_UPDATE_COUNT >= 1)
                                test_nx_azure_iot_adu_agent_proxy_add,
                                test_nx_azure_iot_adu_agent_step_result,
                                test_nx_azure_iot_adu_agent_null_file_url,
#endif /* (NX_AZURE_IOT_ADU_AGENT_PROXY_UPDATE_COUNT >= 1) */
                                test_nx_azure_iot_adu_agent_notify,
                                test_nx_azure_iot_adu_agent_update_cancel,
                                test_nx_azure_iot_adu_agent_install,
                                test_nx_azure_iot_adu_agent_start_fail_with_no_pnp
                               };
    INT number_of_tests =  sizeof(tests)/sizeof(tests[0]);
    g_ip_ptr = ip_ptr;
    g_pool_ptr = pool_ptr;
    g_dns_ptr = dns_ptr;

    test_suit_begin();

    printf("Number of tests %d\r\n", number_of_tests);
    for (INT index = 0; index < number_of_tests; index++)
    {
        test_begin();
        tests[index]();
        test_end();
    }

    test_suit_end();
}
