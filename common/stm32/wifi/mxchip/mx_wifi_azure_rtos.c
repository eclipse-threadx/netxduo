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
/*    MX CHIP EMW3080 WiFi driver implementation                          */
/*                                                                        */
/*                                                                        */
/**************************************************************************/

#include "mx_wifi.h"
#define NX_DRIVER_SOURCE
#include "nx_driver_emw3080.h"
#include "nx_user.h"
#include <inttypes.h>

#if !defined(NX_DEBUG_DRIVER_SOURCE_LOG)
#define NX_DEBUG_DRIVER_SOURCE_LOG(...)   /* ; */
#endif /*NX_DEBUG_DRIVER_SOURCE_LOG*/

extern TX_THREAD *_tx_thread_current_ptr;

extern NX_DRIVER_INFORMATION nx_driver_information;


#define MX_WIFI_BYTE_POOL_SIZE (1024 * 4) /* less than 3k is actually used */

static ULONG mx_wifi_byte_pool_buffer[MX_WIFI_BYTE_POOL_SIZE / sizeof(ULONG)];

static TX_BYTE_POOL mx_wifi_byte_pool;
static CHAR mx_wifi_byte_pool_name[] = "MX WiFi byte pool";

UINT mx_wifi_alloc_init(void)
{
  if (tx_byte_pool_create(&mx_wifi_byte_pool,
                          mx_wifi_byte_pool_name,
                          mx_wifi_byte_pool_buffer,
                          MX_WIFI_BYTE_POOL_SIZE))
  {
    return NX_DRIVER_ERROR;
  }

  return NX_SUCCESS;
}


void *mx_wifi_malloc(size_t size)
{
  UINT status;
  void *p = NULL;

  status = tx_byte_allocate(&mx_wifi_byte_pool,
                            &p,
                            size,
                            TX_NO_WAIT);
  if (status != TX_SUCCESS)
  {
    return NULL;
  }

  MX_ASSERT(p);

  NX_DEBUG_DRIVER_SOURCE_LOG("\n mx_wifi_malloc(): %p (%" PRIu32 ")\n", p, (uint32_t)size);

  return p;
}


void mx_wifi_free(void *p)
{
  UINT status;

  MX_ASSERT(p);

  status = tx_byte_release(p);
  MX_ASSERT(status == NX_SUCCESS);

  NX_DEBUG_DRIVER_SOURCE_LOG("\n mx_wifi_free()  : %p\n", p);
}


NX_PACKET *mx_net_buffer_alloc(uint32_t n)
{
  UINT status;
  NX_PACKET *packet_ptr;

  if (!nx_driver_information.nx_driver_information_packet_pool_ptr)
  {
    return NULL;
  }

  if (n > nx_driver_information.nx_driver_information_packet_pool_ptr->nx_packet_pool_payload_size)
  {
    return NULL;
  }

  status = nx_packet_allocate(nx_driver_information.nx_driver_information_packet_pool_ptr,
                              &packet_ptr,
                              NX_RECEIVE_PACKET,
                              NX_NO_WAIT);
  if (status != NX_SUCCESS)
  {
    MX_STAT_LOG();
    return NULL;
  }

  MX_ASSERT(packet_ptr);

  MX_STAT(alloc);

#if defined(NX_DEBUG) && defined(NX_ENABLE_PACKET_DEBUG_INFO)
  {
    const struct NX_PACKET_POOL_STRUCT *const pool_owner = packet_ptr->nx_packet_pool_owner;

    NX_DEBUG_DRIVER_SOURCE_LOG("\n mx_net_buffer_alloc(): allocated %p -> %" PRIu32 ", allocated by \"%s\"\n",
                               (void *)packet_ptr, (uint32_t)pool_owner->nx_packet_pool_available, packet_ptr->nx_packet_debug_thread);
  }
#endif /* NX_DEBUG && NX_ENABLE_PACKET_DEBUG_INFO*/

  packet_ptr->nx_packet_next = NULL;
  packet_ptr->nx_packet_prepend_ptr += 2;
  packet_ptr->nx_packet_append_ptr = packet_ptr->nx_packet_prepend_ptr + n;
  packet_ptr->nx_packet_length = n;
  MX_ASSERT(packet_ptr->nx_packet_append_ptr <= packet_ptr->nx_packet_data_end);

  return packet_ptr;
}


void mx_net_buffer_free(NX_PACKET *packet_ptr)
{
  UINT status;

  MX_ASSERT(packet_ptr);
  MX_STAT(free);

#if defined(NX_DEBUG) && defined(NX_ENABLE_PACKET_DEBUG_INFO)
  {
    const struct NX_PACKET_POOL_STRUCT *const pool_owner = packet_ptr->nx_packet_pool_owner;

    NX_DEBUG_DRIVER_SOURCE_LOG("\n mx_net_buffer_free() : releasing %p, allocated by \"%s\"\n", (void *)packet_ptr, packet_ptr->nx_packet_debug_thread);

    for (UCHAR *p = packet_ptr->nx_packet_data_start; p < packet_ptr->nx_packet_data_end; p++)
    {
      *p = (UCHAR)'D';
    }
#endif /* NX_DEBUG && NX_ENABLE_PACKET_DEBUG_INFO*/

    status = nx_packet_release(packet_ptr);

#if defined(NX_DEBUG) && defined(NX_ENABLE_PACKET_DEBUG_INFO)
    NX_DEBUG_DRIVER_SOURCE_LOG("\n mx_net_buffer_free() : -> %" PRIu32 "\n",
                               (uint32_t)pool_owner->nx_packet_pool_available);
  }
#endif /* NX_DEBUG && NX_ENABLE_PACKET_DEBUG_INFO*/

  MX_ASSERT(status == NX_SUCCESS);
}


UINT mx_wifi_thread_init(TX_THREAD *thread_ptr, CHAR *name_ptr,
                         VOID (*entry_function)(ULONG), ULONG entry_input,
                         ULONG stack_size, UINT priority)
{
  /* Do not worry about alignment, it is handled by tx_thread_create */
  void *stack = mx_wifi_malloc(stack_size);
  MX_ASSERT(stack);
  if (!stack)
  {
    return TX_NO_MEMORY;
  }

  return tx_thread_create(
           thread_ptr,
           name_ptr,
           entry_function, entry_input,
           stack, stack_size,
           priority, priority,
           TX_NO_TIME_SLICE,
           TX_AUTO_START);
}


UINT mx_wifi_thread_deinit(TX_THREAD *thread_ptr)
{
  MX_ASSERT(thread_ptr);
  MX_ASSERT(thread_ptr->tx_thread_stack_start);

  mx_wifi_free(thread_ptr->tx_thread_stack_start);

  return tx_thread_delete(thread_ptr);
}


void mx_wifi_thread_terminate(void)
{
  tx_thread_terminate(_tx_thread_current_ptr);
}


UINT mx_wifi_fifo_init(TX_QUEUE *queue_ptr, CHAR *name_ptr, ULONG size)
{
  void *queue_start = mx_wifi_malloc(size * TX_1_ULONG * sizeof(ULONG));
  MX_ASSERT(queue_start);
  if (!queue_start)
  {
    return TX_NO_MEMORY;
  }

  return tx_queue_create(
           queue_ptr,
           name_ptr,
           TX_1_ULONG,
           queue_start,
           size * sizeof(ULONG));
}


UINT mx_wifi_fifo_deinit(TX_QUEUE *queue_ptr)
{
  MX_ASSERT(queue_ptr);
  MX_ASSERT(queue_ptr->tx_queue_start);

  mx_wifi_free(queue_ptr->tx_queue_start);

  return tx_queue_delete(queue_ptr);
}


UINT mx_wifi_fifo_push(TX_QUEUE *queue_ptr, void *source_ptr, ULONG wait_option)
{
  MX_ASSERT(queue_ptr);

  NX_DEBUG_DRIVER_SOURCE_LOG("\n mx_wifi_fifo_push(): pushing %p\n", source_ptr);

  return tx_queue_send(queue_ptr, source_ptr, wait_option);
}


void *mx_wifi_fifo_pop(TX_QUEUE *queue_ptr, ULONG wait_option)
{
  void *destination_ptr;

  MX_ASSERT(queue_ptr);

  UINT status = tx_queue_receive(queue_ptr, &destination_ptr, wait_option);
  if (status != TX_SUCCESS)
  {
    return NULL;
  }

  NX_DEBUG_DRIVER_SOURCE_LOG("\n mx_wifi_fifo_pop() : popping %p\n", destination_ptr);

  return destination_ptr;
}
