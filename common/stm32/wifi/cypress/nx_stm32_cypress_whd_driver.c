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
/*                                                                        */
/*                                                                        */
/*  NetX Component                                                        */
/*                                                                        */
/*    Cypress CHIP WiFi driver for the STM32 family of microprocessors    */
/*                                                                        */
/*                                                                        */
/**************************************************************************/

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>

#include "nx_api.h"
#include "whd.h"
#include "whd_debug.h"
#include "whd_types.h"
#include "whd_int.h"
#include "cy_wifi_conf.h"

#include "whd_config.h"

#ifndef NX_DRIVER_DEFERRED_PROCESSING
/* #error The symbol NX_DRIVER_DEFERRED_PROCESSING should be defined */
#endif /* NX_DRIVER_DEFERRED_PROCESSING */


#define NX_DRIVER_ENABLE_DEFERRED

/* Indicate that driver source is being compiled. */
#define NX_DRIVER_SOURCE

#if !defined(NX_DEBUG_DRIVER_SOURCE_LOG)
#define NX_DEBUG_DRIVER_SOURCE_LOG(...)   /* ; */
#define REMOVE_DEBUG_FUNC
#endif /*NX_DEBUG_DRIVER_SOURCE_LOG*/

#include "nx_stm32_cypress_whd_driver.h"
#include "nx_driver_framework.c"

whd_interface_t *Ifp;

/* Private variables ---------------------------------------------------------*/
static uint32_t CypressAliveInterfaceCount = 0;
static whd_driver_t WhdDriver;
static uint16_t EventIndex = 0xFF;

/* The station mode is the default. */
wifi_mode_t WifiMode = WIFI_MODE_STA;

static const whd_event_num_t sta_link_change_events[] =
{
  WLC_E_SET_SSID,
  WLC_E_LINK,
  WLC_E_AUTH,
  WLC_E_ASSOC,
  WLC_E_DEAUTH_IND,
  WLC_E_DISASSOC_IND,
  WLC_E_DISASSOC,
  WLC_E_REASSOC,
  WLC_E_PSK_SUP,
  WLC_E_ACTION_FRAME_COMPLETE,
  WLC_E_NONE
};


/* Declare the boot function implemented in whd_config.c */
cy_rslt_t whd_boot(whd_driver_t *pwhd_driver);

static UINT _nx_driver_cypress_whd_initialize(NX_IP_DRIVER *driver_req_ptr);
static UINT _nx_driver_cypress_whd_enable(NX_IP_DRIVER *driver_req_ptr);
static UINT _nx_driver_cypress_whd_disable(NX_IP_DRIVER *driver_req_ptr);
static UINT _nx_driver_cypress_whd_packet_send(NX_PACKET *packet_ptr);
static UINT _nx_driver_cypress_whd_interface_status(NX_IP_DRIVER *driver_req_ptr);
static VOID _nx_driver_cypress_whd_packet_received(VOID);

static VOID *_nx_driver_cypress_whd_event_handler(whd_interface_t ifp,
                                                  const whd_event_header_t *event_header,
                                                  const uint8_t *event_data, void *handler_user_data);


#if !defined(REMOVE_DEBUG_FUNC)
static void HexDump(const void *pData, size_t Size);
#endif /* REMOVE_DEBUG_FUNC */

extern UINT cypress_whd_alloc_init(VOID);

VOID nx_driver_cypress_whd_entry(NX_IP_DRIVER *driver_req_ptr)
{
  static bool started = false;
  if (!started)
  {
    nx_driver_hardware_initialize      = _nx_driver_cypress_whd_initialize;
    nx_driver_hardware_enable          = _nx_driver_cypress_whd_enable;
    nx_driver_hardware_disable         = _nx_driver_cypress_whd_disable;
    nx_driver_hardware_packet_send     = _nx_driver_cypress_whd_packet_send;
    nx_driver_hardware_get_status      = _nx_driver_cypress_whd_interface_status;
    nx_driver_hardware_packet_received = _nx_driver_cypress_whd_packet_received;

    started = true;
  }

  nx_driver_framework_entry_default(driver_req_ptr);
}


void cy_network_process_ethernet_data(whd_interface_t interface, whd_buffer_t buffer)
{
  NX_PACKET *packet_ptr = buffer;

  (void)interface;

  /* Avoid starving.  */
  if (packet_ptr -> nx_packet_pool_owner -> nx_packet_pool_available == 0)
  {
    nx_packet_release(packet_ptr);
    return;
  }

  /* Everything is OK, transfer the packet to NetX. */
  nx_driver_transfer_to_netx(nx_driver_information.nx_driver_information_ip_ptr, packet_ptr);
}


UINT _nx_driver_cypress_whd_initialize(NX_IP_DRIVER *driver_req_ptr)
{
  UINT ret = NX_SUCCESS;
  whd_mac_t mac;

  (void)(driver_req_ptr);

  if (cypress_whd_alloc_init())
  {
    return NX_DRIVER_ERROR;
  }

  if (CypressAliveInterfaceCount == 0)
  {
    /* Boot cypress module and start whd driver for very first interface. */
    if (WHD_SUCCESS != whd_boot(&WhdDriver))
    {
      WPRINT_WHD_ERROR(("Can't perform initialization of the WHD driver and module\n"));
      ret = NX_DRIVER_ERROR;
    }

    if (NX_SUCCESS == ret)
    {
      Ifp = WHD_MALLOC(sizeof(whd_interface_t));
      if (Ifp == NULL)
      {
        WPRINT_WHD_ERROR(("WHD_MALLOC() Failed in %s() at line %d \n",
                          __func__, __LINE__));
      }

      if (WHD_SUCCESS != whd_wifi_on(WhdDriver, Ifp))
      {
        WPRINT_WHD_ERROR(("Failed when creating WIFI default interface\n"));
        ret = NX_DRIVER_ERROR;
      }
      else
      {
        NX_DEBUG_DRIVER_SOURCE_LOG("WHD initialization interface done\n");
        CypressAliveInterfaceCount++;
        ret = NX_SUCCESS;
      }
    }
  }
  else
  {
    whd_mac_t mac_addr = {{0xA0, 0xC9, 0xA0, 0X3D, 0x43, 0x41}};
    if (WHD_SUCCESS != whd_add_secondary_interface(WhdDriver, &mac_addr, Ifp))
    {
      WPRINT_WHD_ERROR(("Failed when creating WIFI default interface\n"));
      ret = NX_DRIVER_ERROR;
    }
    else
    {
      NX_DEBUG_DRIVER_SOURCE_LOG("WHD initialization interface done\n");
      CypressAliveInterfaceCount++;
      ret = NX_SUCCESS;
    }
  }

  if (whd_wifi_get_mac_address(*Ifp, &mac) == WHD_SUCCESS)
  {
    nx_driver_update_hardware_address(mac.octet);
  }

  return NX_SUCCESS;
}


static VOID *_nx_driver_cypress_whd_event_handler(whd_interface_t ifp,
                                                  const whd_event_header_t *event_header,
                                                  const uint8_t *event_data, void *handler_user_data)
{
  UNUSED_PARAMETER(event_data);

  if (event_header->bsscfgidx >= WHD_INTERFACE_MAX)
  {
    WPRINT_WHD_ERROR(("event_header: Bad interface\n"));
    return NULL;
  }

  if ((event_header->event_type == WLC_E_DEAUTH_IND) ||
      (event_header->event_type == WLC_E_DISASSOC_IND) ||
      ((event_header->event_type == WLC_E_PSK_SUP) &&
       (event_header->status == WLC_SUP_KEYED) &&
       (event_header->reason == WLC_E_SUP_DEAUTH)) ||
      ((event_header->event_type == WLC_E_LINK) &&
       (event_header->reason == WLC_E_REASON_LOW_RSSI)))
  {
    return handler_user_data;
  }

  if (((event_header->event_type == WLC_E_PSK_SUP) &&
       (event_header->status == WLC_SUP_KEYED) &&
       (event_header->reason == WLC_E_SUP_OTHER)) ||
      (whd_wifi_is_ready_to_transceive(ifp) == WHD_SUCCESS))
  {
    return handler_user_data;
  }

  return handler_user_data;
}


UINT _nx_driver_cypress_whd_enable(NX_IP_DRIVER *driver_req_ptr)
{
  int32_t ret = 0;
  whd_security_t privacy = WHD_SECURITY_WPA2_AES_PSK;
  whd_ssid_t myssid = {0};
  const char security_key[] = WIFI_PASSWORD;

  (void)driver_req_ptr;

  strncpy((char *) myssid.value, WIFI_SSID, sizeof(myssid.value));
  myssid.length = (uint8_t)strlen((const char *)myssid.value);

  if (WifiMode == WIFI_MODE_STA)
  {
    whd_wifi_set_event_handler(*Ifp, (uint32_t const *) sta_link_change_events,
                               _nx_driver_cypress_whd_event_handler, NULL, &EventIndex);

    NX_DEBUG_DRIVER_SOURCE_LOG("Joining ... \"%s\"\n", myssid.value);

    ret = whd_wifi_join(*Ifp, (whd_ssid_t const *) &myssid, privacy,
                        (uint8_t const *) security_key, strlen(security_key));
    if (ret != 0)
    {
      WPRINT_WHD_ERROR(("Can't join \"%s\"\n", myssid.value));
      ret = NX_DRIVER_ERROR;
    }
  }
  else
  {
    NX_DEBUG_DRIVER_SOURCE_LOG("Initialize the Access Point ... \"%s\"\n", myssid.value);

    ret = whd_wifi_init_ap(*Ifp, &myssid, WHD_SECURITY_OPEN,
                           (uint8_t const *) security_key, strlen(security_key),
                           (uint8_t)8u);
    if (ret != 0)
    {
      WPRINT_WHD_ERROR(("Can't initialize as Access Point \"%s\"\n", myssid.value));
      ret = NX_DRIVER_ERROR;
    }
    else
    {
      ret = whd_wifi_start_ap((*Ifp));
      if (ret != 0)
      {
        WPRINT_WHD_ERROR(("Can't start the Access Point \"%s\"\n", myssid.value));
        ret = NX_DRIVER_ERROR;
      }
    }
  }
  return NX_SUCCESS;
}


UINT _nx_driver_cypress_whd_disable(NX_IP_DRIVER *driver_req_ptr)
{
  int32_t ret = 0;

  (void)driver_req_ptr;

  ret = whd_wifi_leave(*Ifp);
  if (ret != 0)
  {
    WPRINT_WHD_ERROR(("Can't leave \"%s\"\n", WIFI_SSID));
    ret = NX_DRIVER_ERROR;
  }

  if (WHD_SUCCESS != whd_wifi_off(*Ifp))
  {
    WPRINT_WHD_ERROR(("Failed when deleting WIFI default interface\n"));
    ret = NX_DRIVER_ERROR;
  }

  return ret;
}

UINT _nx_driver_cypress_whd_packet_send(NX_PACKET *packet_ptr)
{
  NX_DEBUG_DRIVER_SOURCE_LOG("\n\n>***\n");

#if !defined(REMOVE_DEBUG_FUNC)
  HexDump(packet_ptr->nx_packet_prepend_ptr, packet_ptr->nx_packet_length);
#endif /* REMOVE_DEBUG_FUNC */

  whd_network_send_ethernet_data(*Ifp, packet_ptr);

  NX_DEBUG_DRIVER_SOURCE_LOG("\n<***\n\n");

  return NX_SUCCESS;
}

static VOID _nx_driver_cypress_whd_packet_received(VOID)
{

}

static UINT _nx_driver_cypress_whd_interface_status(NX_IP_DRIVER *driver_req_ptr)
{
  UINT status = NX_PTR_ERROR;

  if (NULL != driver_req_ptr -> nx_ip_driver_return_ptr)
  {
    *driver_req_ptr -> nx_ip_driver_return_ptr = (CypressAliveInterfaceCount > 0) ? NX_TRUE : NX_FALSE;
    status = NX_SUCCESS;
  }

  return status;
}


#if !defined(REMOVE_DEBUG_FUNC)
static void HexDump(const void *pData, size_t Size)
{
  char ascii[17] = {0};

  for (size_t i = 0; i < Size; ++i)
  {
    const uint8_t data_byte = ((uint8_t *)pData)[i];
    NX_DEBUG_DRIVER_SOURCE_LOG("%02" PRIx32 " ", (uint32_t)data_byte);

    if ((data_byte >= ' ') && (data_byte <= '~'))
    {
      ascii[i % 16] = (char)data_byte;
    }
    else
    {
      ascii[i % 16] = '.';
    }

    if (((i + 1) % 8 == 0) || ((i + 1) == Size))
    {
      NX_DEBUG_DRIVER_SOURCE_LOG(" ");
      if ((i + 1) % 16 == 0)
      {
        NX_DEBUG_DRIVER_SOURCE_LOG("|  %s \n", ascii);
      }
      else if (i + 1 == Size)
      {
        ascii[(i + 1) % 16] = '\0';
        if ((i + 1) % 16 <= 8)
        {
          NX_DEBUG_DRIVER_SOURCE_LOG(" ");
        }
        for (size_t j = (i + 1) % 16; j < 16; ++j)
        {
          NX_DEBUG_DRIVER_SOURCE_LOG("   ");
        }
        NX_DEBUG_DRIVER_SOURCE_LOG("|  %s \n", ascii);
      }
    }
  }
}
#endif /* REMOVE_DEBUG_FUNC */
