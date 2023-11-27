/* This is an include file for the NetX SNMP demo programs for setting up the MIB for 
   user callback functions. It is not part of the official release of NetX SNMP Agent. */

#ifndef SMALL_MIB_HELPER_H
#define SMALL_MIB_HELPER_H

/* Determine if a C++ compiler is being used.  If so, ensure that standard
   C is used to process the API information.  */

#ifdef   __cplusplus

/* Yes, C++ compiler is present.  Use standard C.  */
extern   "C" {

#endif

/* Include necessary digest and encryption files.  */

#include "tx_api.h"
#include "nx_api.h"
#ifdef __PRODUCT_NETXDUO__
#include "nxd_snmp.h"
#else
#include "nx_snmp.h"
#endif  

/* Define application MIB data structure. Actual application structures would certainly vary.  */

typedef struct MIB_ENTRY_STRUCT
{

    UCHAR       *object_name;
    void        *object_value_ptr;
    UINT        (*object_get_callback)(VOID *source_ptr, NX_SNMP_OBJECT_DATA *object_data);
    UINT        (*object_get_octet_callback)(VOID *source_ptr, NX_SNMP_OBJECT_DATA *object_data, UINT length);
    UINT        (*object_set_callback)(VOID *destination_ptr, NX_SNMP_OBJECT_DATA *object_data);
    UINT        length;
} MIB_ENTRY;

#endif /* SMALL_MIB_HELPER_H */
