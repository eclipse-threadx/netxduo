                                 
#include   "netx_dhcp_clone_function.h"           
#include   "nxd_dhcp_client.h"
#include   "nxd_dhcp_server.h"
                                                        

UINT  dhcp_get_option_value(UCHAR *bootp_message, UINT option, ULONG *value, UINT length)
{

UCHAR *data;


    /* Find the option.  */
    if ((option != NX_DHCP_OPTION_PAD) && (option != NX_DHCP_OPTION_END))
    {

        /* Search the buffer for the option.  */
        data =  dhcp_search_buffer(bootp_message, option, length);

        /* Check to see if the option was found.  */
        if (data != NX_NULL)
        {

            /* Check for the proper size.  */
            if (*data > 4)
            {

                /* Check for the gateway option.  */
                if (option == NX_DHCP_OPTION_GATEWAYS)
                {

                    /* Pickup the first gateway address.  */
                    *value =  dhcp_get_data(data + 1, 4);

                    /* For now, just disregard any additional gateway addresses.  */
                    return(NX_SUCCESS);
                }
                else
                {

                    /* Invalid size, return error.  */
                    return(NX_SIZE_ERROR);
                }
            }
            else
            {

                /* Get the actual value.  */
                *value = dhcp_get_data(data + 1, *data);
                return(NX_SUCCESS);  
            }
        }
    }

    /* Return an error if not found.  */
    return(NX_OPTION_ERROR);
}
UCHAR  *dhcp_search_buffer(UCHAR *bootp_message, UINT option, UINT length)
{

UCHAR   *data;
UINT    i;


    /* Setup buffer pointer.  */
    data = &bootp_message[NX_BOOTP_OFFSET_OPTIONS];
    i = NX_BOOTP_OFFSET_OPTIONS;

    /* Search as long as there are valid options.   */
    while (i < length)
    {

        /* Simply skip any padding */
        if (*data == NX_DHCP_OPTION_PAD)
        {

            data++;
            i++;
        }

        /* On a match, return a pointer to the size.  */
        else if (*data == option)
        {

            /* Return a pointer to the option size byte.  */
            return(data + 1);
        }

        /* Otherwise skip the option by adding the size to the pointer.  */
        else
        {

        UINT size = *(++data);

            /* skip the data plus the size byte */
            data += size + 1;
            i += size + 1;
        }
    }

    /* Return NULL to indicate the option was not found.  */
    return(NX_NULL);
}
ULONG  dhcp_get_data(UCHAR *data, UINT size)
{

ULONG   value = 0;

   
    /* Process the data retrieval request.  */
    while (size-- > 0)
    {

        /* Build return value.  */
        value = (value << 8) | *data++;
    }

    /* Return value.  */
    return(value);
}
