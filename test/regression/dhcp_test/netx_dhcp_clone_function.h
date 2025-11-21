#include "nx_api.h"

/* Declare the function.  */
UINT   dhcp_get_option_value(UCHAR *bootp_message, UINT option, ULONG *value, UINT length); 
UCHAR  *dhcp_search_buffer(UCHAR *bootp_message, UINT option, UINT length);     
ULONG  dhcp_get_data(UCHAR *data, UINT size);                                                           
