#include   "tx_api.h"
#include   "nx_api.h"
#include   "nxd_mqtt_client.h"

extern UINT _nxd_mqtt_read_remaining_length(NX_PACKET *packet_ptr, UINT *remaining_length, ULONG *offset);
extern UINT _nxd_mqtt_client_set_fixed_header(NXD_MQTT_CLIENT *client_ptr, NX_PACKET *packet_ptr, UCHAR control_header, UINT length, UINT wait_option);

static ULONG                   error_counter;
extern void  test_control_return(UINT status);
extern void SET_ERROR_COUNTER(ULONG *error_counter, CHAR *filename, int line_number);

#define NUM_PACKETS                 24
#define PACKET_SIZE                 1536
#define PACKET_POOL_SIZE            (NUM_PACKETS * (PACKET_SIZE + sizeof(NX_PACKET)))

#ifdef CTEST
void test_application_define(void * first_unused_memory)
#else /* CTEST */
void netx_mqtt_remaining_length_test(void * first_unused_memory)
#endif /* CTEST */
{
CHAR *pointer;
NX_PACKET_POOL pool_0;
NXD_MQTT_CLIENT *client_ptr;
NX_PACKET *packet_ptr;
UINT status;
UINT remaining_length;
ULONG offset;
int i;
UCHAR *byte;

    /* Print out test information banner.  */
    printf("NetX Test:   MQTT Remaining Length Test ...............................");

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", PACKET_SIZE, pointer, PACKET_POOL_SIZE);

    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    } 

    pointer = pointer + PACKET_POOL_SIZE;

    client_ptr = (NXD_MQTT_CLIENT *)pointer;
    client_ptr -> nxd_mqtt_client_packet_pool_ptr = &pool_0;

    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_WAIT_FOREVER);
    
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    } 
    

    /* Test set function, remaining length <= 127 */
    for(i = 1; i < 128; i++)
    {
        packet_ptr->nx_packet_length = 0;
        packet_ptr->nx_packet_append_ptr = packet_ptr->nx_packet_prepend_ptr;
        packet_ptr->nx_packet_next = 0;
        memset(packet_ptr->nx_packet_prepend_ptr, 0, 10);
        status = _nxd_mqtt_client_set_fixed_header(client_ptr, packet_ptr, 0, i, NX_WAIT_FOREVER);
        /* Verify the value. */
        if((status != 0) || (packet_ptr -> nx_packet_length != 2) || ((*(packet_ptr -> nx_packet_prepend_ptr + 1)) != i))
            SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

        packet_ptr->nx_packet_length += i;
        packet_ptr->nx_packet_append_ptr += i;
        status = _nxd_mqtt_read_remaining_length(packet_ptr, &remaining_length, &offset);
        if((status != 0) || (remaining_length != i) || (offset != 2))
            SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    }

    /* test 128 */
    packet_ptr->nx_packet_length = 0;
    packet_ptr->nx_packet_append_ptr = packet_ptr->nx_packet_prepend_ptr;
    memset(packet_ptr->nx_packet_prepend_ptr, 0, 10);
    status = _nxd_mqtt_client_set_fixed_header(client_ptr, packet_ptr, 0, 128, NX_WAIT_FOREVER);
    /* Verify the value. */
    if((status != 0) || (packet_ptr -> nx_packet_length != 3) || 
       ((*(packet_ptr -> nx_packet_prepend_ptr + 1) != 0x80) && (*(packet_ptr -> nx_packet_prepend_ptr + 2) != 0x01)))
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    packet_ptr->nx_packet_length += 128;
    packet_ptr->nx_packet_append_ptr += 128;
    status = _nxd_mqtt_read_remaining_length(packet_ptr, &remaining_length, &offset);
    if((status != 0) || (remaining_length != 128) || (offset != 3))
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);    


    /* test 16383 */
    packet_ptr->nx_packet_length = 0;
    packet_ptr->nx_packet_append_ptr = packet_ptr->nx_packet_prepend_ptr;
    memset(packet_ptr->nx_packet_prepend_ptr, 0, 10);
    status = _nxd_mqtt_client_set_fixed_header(client_ptr, packet_ptr, 0, 16383, NX_WAIT_FOREVER);
    /* Verify the value. */
    if((status != 0) || (packet_ptr -> nx_packet_length != 3) || 
       ((*(packet_ptr -> nx_packet_prepend_ptr + 1) != 0xFF) && (*(packet_ptr -> nx_packet_prepend_ptr + 2) != 0x7F)))
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    packet_ptr->nx_packet_length += 16383;
    packet_ptr->nx_packet_append_ptr += 16383;
    status = _nxd_mqtt_read_remaining_length(packet_ptr, &remaining_length, &offset);
    if((status != 0) || (remaining_length != 16383) || (offset != 3))
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);    

    /* test 16384 */
    packet_ptr->nx_packet_length = 0;
    packet_ptr->nx_packet_append_ptr = packet_ptr->nx_packet_prepend_ptr;
    memset(packet_ptr->nx_packet_prepend_ptr, 0, 10);
    status = _nxd_mqtt_client_set_fixed_header(client_ptr, packet_ptr, 0, 16384, NX_WAIT_FOREVER);
    /* Verify the value. */
    if((status != 0) || (packet_ptr -> nx_packet_length != 4) || 
       ((*(packet_ptr -> nx_packet_prepend_ptr + 1) != 0x80) && (*(packet_ptr -> nx_packet_prepend_ptr + 2) != 0x80)) && 
       ((*(packet_ptr -> nx_packet_prepend_ptr + 3) != 0x01)))
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    packet_ptr->nx_packet_length += 16384;
    packet_ptr->nx_packet_append_ptr += 16384;
    status = _nxd_mqtt_read_remaining_length(packet_ptr, &remaining_length, &offset);
    if((status != 0) || (remaining_length != 16384) || (offset != 4))
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);    

    /* test 2 097 151 */
    packet_ptr->nx_packet_length = 0;
    packet_ptr->nx_packet_append_ptr = packet_ptr->nx_packet_prepend_ptr;
    memset(packet_ptr->nx_packet_prepend_ptr, 0, 10);
    status = _nxd_mqtt_client_set_fixed_header(client_ptr, packet_ptr, 0, 2097151, NX_WAIT_FOREVER);
    /* Verify the value. */
    if((status != 0) || (packet_ptr -> nx_packet_length != 4) || 
       ((*(packet_ptr -> nx_packet_prepend_ptr + 1) != 0xFF) && (*(packet_ptr -> nx_packet_prepend_ptr + 2) != 0xFF)) && 
       ((*(packet_ptr -> nx_packet_prepend_ptr + 3) != 0x7f)))
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    packet_ptr->nx_packet_length += 2097151;
    packet_ptr->nx_packet_append_ptr += 2097151;
    status = _nxd_mqtt_read_remaining_length(packet_ptr, &remaining_length, &offset);
    if((status != 0) || (remaining_length != 2097151) || (offset != 4))
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);    

    /* test 2 097 152 */
    packet_ptr->nx_packet_length = 0;
    packet_ptr->nx_packet_append_ptr = packet_ptr->nx_packet_prepend_ptr;
    memset(packet_ptr->nx_packet_prepend_ptr, 0, 10);
    status = _nxd_mqtt_client_set_fixed_header(client_ptr, packet_ptr, 0, 2097152, NX_WAIT_FOREVER);
    /* Verify the value. */
    if((status != 0) || (packet_ptr -> nx_packet_length != 5) || 
       ((*(packet_ptr -> nx_packet_prepend_ptr + 1) != 0x80) && (*(packet_ptr -> nx_packet_prepend_ptr + 2) != 0x80)) && 
       ((*(packet_ptr -> nx_packet_prepend_ptr + 3) != 0x80)) && ((*(packet_ptr -> nx_packet_prepend_ptr + 4) != 0x1)))
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    packet_ptr->nx_packet_length += 2097152;
    packet_ptr->nx_packet_append_ptr += 2097152;
    status = _nxd_mqtt_read_remaining_length(packet_ptr, &remaining_length, &offset);
    if((status != 0) || (remaining_length != 2097152) || (offset != 5))
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);    

    /* test 268 435 455 */
    packet_ptr->nx_packet_length = 0;
    packet_ptr->nx_packet_append_ptr = packet_ptr->nx_packet_prepend_ptr;
    memset(packet_ptr->nx_packet_prepend_ptr, 0, 10);
    status = _nxd_mqtt_client_set_fixed_header(client_ptr, packet_ptr, 0, 268435455, NX_WAIT_FOREVER);
    /* Verify the value. */
    if((status != 0) || (packet_ptr -> nx_packet_length != 5) || 
       ((*(packet_ptr -> nx_packet_prepend_ptr + 1) != 0xff) && (*(packet_ptr -> nx_packet_prepend_ptr + 2) != 0xff)) && 
       ((*(packet_ptr -> nx_packet_prepend_ptr + 3) != 0xff)) && ((*(packet_ptr -> nx_packet_prepend_ptr + 4) != 0x7f)))
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    packet_ptr->nx_packet_length += 268435455;
    packet_ptr->nx_packet_append_ptr += 268435455;
    status = _nxd_mqtt_read_remaining_length(packet_ptr, &remaining_length, &offset);
    if((status != 0) || (remaining_length != 268435455) || (offset != 5))
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);    

    /* Test for invalid length */
    packet_ptr->nx_packet_length = 6;
    packet_ptr->nx_packet_append_ptr = packet_ptr->nx_packet_prepend_ptr + 6;
    
    byte = packet_ptr -> nx_packet_prepend_ptr + 1;
    *byte = 0x80; byte++;
    *byte = 0x80; byte++;
    *byte = 0x80; byte++;
    *byte = 0x80; byte++;
    *byte = 0x7f; byte++;
    status = _nxd_mqtt_read_remaining_length(packet_ptr, &remaining_length, &offset);
    if(status == 0)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);        

    nx_packet_release(packet_ptr);

    nx_packet_pool_delete(&pool_0);

    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }   
    else
    {   
        printf("SUCCESS!\n");
        test_control_return(0);
    }

}
