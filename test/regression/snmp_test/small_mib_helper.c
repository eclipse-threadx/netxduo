
/* Determine if a C++ compiler is being used.  If so, ensure that standard
   C is used to process the API information.  */

#ifdef   __cplusplus

/* Yes, C++ compiler is present.  Use standard C.  */
extern   "C" {
#endif

#include "small_mib_helper.h"

/* Define function prototypes. */

UINT    mib2_get_processing(NX_SNMP_AGENT *agent_ptr, UCHAR *object_requested, NX_SNMP_OBJECT_DATA *object_data);
UINT    mib2_getnext_processing(NX_SNMP_AGENT *agent_ptr, UCHAR *object_requested, NX_SNMP_OBJECT_DATA *object_data);
UINT    mib2_set_processing(NX_SNMP_AGENT *agent_ptr, UCHAR *object_requested, NX_SNMP_OBJECT_DATA *object_data);
UINT    mib2_username_processing(NX_SNMP_AGENT *agent_ptr, UCHAR *username);
//UINT    mib2_username_processing_public(NX_SNMP_AGENT *agent_ptr, UCHAR *username);
//UINT    mib2_username_processing_admin(NX_SNMP_AGENT *agent_ptr, UCHAR *username);
//UINT    mib2_username_processing_view(NX_SNMP_AGENT *agent_ptr, UCHAR *username);
//VOID    mib2_variable_update(NX_IP *ip_ptr, NX_SNMP_AGENT *agent_ptr);
//VOID    mib2_variable_update_public(NX_IP *ip_ptr, NX_SNMP_AGENT *agent_ptr);
//VOID    mib2_variable_update_view(NX_IP *ip_ptr, NX_SNMP_AGENT *agent_ptr) ;
//VOID    mib2_variable_update_admin(NX_IP *ip_ptr, NX_SNMP_AGENT *agent_ptr) ;


/* Define the MIB-2 "system" group.  */

UCHAR   sysDescr[] =                "NetX SNMP Agent";              /* sysDescr:OctetString                 RO */
UCHAR   sysObjectID[] =             "1.3.6.1.2.1.1";                /* sysObjectID:ObjectID                 RO */
ULONG   sysUpTime =                  0;                             /* sysUpTime:TimeTicks                  RO */
UCHAR   sysContact[128] =           "NetX sysContact Name";         /* sysContact:OctetString               RW */
UCHAR   sysName[128] =              "NetX sysName";                 /* sysName:OctetString                  RW */
UCHAR   sysLocation[128] =          "NetX sysLocation";             /* sysLocation:OctetString              RW */
ULONG   sysServices =               1;                              /* sysServices:Integer                  RW */

ULONG   ipForwarding =              0;                              /* ipForwarding:Integer                 RW */ 
ULONG   ipDefaultTTL =              NX_IP_TIME_TO_LIVE;             /* ipDefaultTTL:Integer                 RW */ 

/* Define the MIB-2 "interfaces" group, assuming one interface. Update of these variables could be added to the
   underlying application driver, but for now simple defaults are used.  */     
ULONG   ifLastChange =              2048;                           /* ifLastChange:TimeTicks               RO */ 
ULONG   ifInOctets =                155;                            /* ifInOctets:Counter                   RO */ 
ULONG64 ifInUcastPkts =             0;                              /* ifInUcastPkts:Counter                RO */ 

UCHAR   ifDescr[] =                 "NetX Physical Interface";      /* ifDescr:OctetString                  RO */ 
#if 0
ULONG   ifNumber =                  1;                              /* ifNumber:Integer                     RO */
ULONG   ifIndex =                   1;                              /* ifIndex:Integer                      RO */ 
ULONG   ifType =                    1;                              /* ifType:Integer                       RO */ 
ULONG   ifMtu =                     2048;                           /* ifMTU:Integer                        RO */ 
ULONG   ifSpeed =                   1000000;                        /* ifSpeed:Guage                        RO */ 
UCHAR   ifPhysAddress[] =           {0x00,0x04,0xac,0xe3,0x1d,0xc5};/* ifPhysAddress:OctetString            RO */ 
ULONG   ifAdminStatus =             IFADMINSTATUS_UP;               /* ifAdminStatus:Integer                RW */ 
ULONG   ifOperStatus =              1;                              /* ifOperStatus:Integer                 RO */ 
ULONG   ifInNUcastPkts =            0;                              /* ifInNUcastPkts:Counter               RO */ 
ULONG   ifInDiscards =              0;                              /* ifInDiscards:Counter                 RO */ 
ULONG   ifInErrors =                0;                              /* ifInErrors:Counter                   RO */ 
ULONG   ifInUnknownProtos =         0;                              /* ifInUnknownProtos:Counter            RO */ 
ULONG   ifOutOctets =               0;                              /* ifOutOctets:Counter                  RO */ 
ULONG   ifOutUcastPkts =            0;                              /* ifOutUcastPkts:Counter               RO */ 
ULONG   ifOutNUcastPkts =           0;                              /* ifOutNUcastPkts:Counter              RO */ 
ULONG   ifOutDiscards =             0;                              /* ifOutDiscards:Counter                RO */ 
ULONG   ifOutErrors =               0;                              /* ifOutErrors:Counter                  RO */ 
ULONG   ifOutQLen =                 0;                              /* ifOutQLen:Guage                      RO */ 
UCHAR   ifSpecific[] =              "1.3.6.1.2.1.1";                /* ifSpecific:ObjectID                  RO */ 
#endif
/* Define the MIB-2 "address translation" group, assuming one address translation.  */

//ULONG   atIfIndex =                 1;                              /* atIfIndex:Integer                    RW */ 
UCHAR   atPhysAddress[] =           {0x00,0x04,0xac,0xe3,0x1d,0xc5};/* atPhysAddress:OctetString            RW */ 
ULONG   atNetworkAddress =          0;                              /* atNetworkAddress:NetworkAddr         RW */ 
UCHAR   atIPv6NetworkAddress[16];                                   /* atNetworkAddress:NetworkAddr IPv6    RW */ 


/* Define the MIB-2 "ip" group.  */
//ULONG   ipForwarding =              0;                              /* ipForwarding:Integer                 RW */ 
ULONG   oid_var = 1234U;


/* Define the actual MIB-2.  */

MIB_ENTRY   mib2_mib[] = {

    /*    OBJECT ID                OBJECT VARIABLE                  LENGTH OF OBJECT VARIABLE        GET ROUTINE/ GET_OCTET_ROUTINE            SET ROUTINE      LENGTH */
#if 1
    {(UCHAR *) "1.3.6.1.2.1.1.1.0",       sysDescr,                   nx_snmp_object_string_get, NX_NULL,      nx_snmp_object_string_set, sizeof(sysDescr)},
    {(UCHAR *) "1.3.6.1.2.1.1.2.0",       sysObjectID,                nx_snmp_object_id_get, NX_NULL,          NX_NULL, sizeof(sysObjectID)},
    {(UCHAR *) "1.3.6.1.2.1.1.3.0",       &sysUpTime,                 nx_snmp_object_timetics_get, NX_NULL,    NX_NULL, sizeof(sysUpTime)},
    {(UCHAR *) "1.3.6.1.2.1.1.4.0",       sysContact,                 nx_snmp_object_string_get, NX_NULL,      nx_snmp_object_string_set, sizeof(sysContact)},
    {(UCHAR *) "1.3.6.1.2.1.1.5.0",       sysName,                    nx_snmp_object_string_get, NX_NULL,      nx_snmp_object_string_set, sizeof(sysName)},
    {(UCHAR *) "1.3.6.1.2.1.1.6.0",       sysLocation,                nx_snmp_object_string_get, NX_NULL,      nx_snmp_object_string_set, sizeof(sysLocation)},
    {(UCHAR *) "1.3.6.1.2.1.1.7.0",       &sysServices,               nx_snmp_object_integer_get, NX_NULL,     NX_NULL,  sizeof(sysServices)},
#endif
    {(UCHAR *) "1.3.6.1.2.1.3.1.1.3.0",   &atNetworkAddress,          nx_snmp_object_ip_address_get, NX_NULL,  nx_snmp_object_ip_address_set, sizeof(atNetworkAddress)},
#ifdef FEATURE_NX_IPV6
     /* Either GET method should work. IPv6 addresses are handled as octet strings and accept any IPv6 address format e.g. addresses with '::'s are accepted as is. */
    {(UCHAR *) "1.3.6.1.2.1.3.1.1.3.1",   &atIPv6NetworkAddress,      nx_snmp_object_ipv6_address_get, NX_NULL, nx_snmp_object_ipv6_address_set, sizeof(atIPv6NetworkAddress)},
    {(UCHAR *) "1.3.6.1.2.1.3.1.1.3.2",   &atIPv6NetworkAddress,      NX_NULL, nx_snmp_object_octet_string_get, nx_snmp_object_octet_string_set, sizeof(atIPv6NetworkAddress)},
#endif

    {(UCHAR *) "1.3.6.1.2.1.2.2.1.2.0",   ifDescr,                    nx_snmp_object_string_get, NX_NULL,      NX_NULL,  sizeof(ifDescr)},
    {(UCHAR *) "1.3.6.1.2.1.3.1.1.2.0",   &atPhysAddress,             NX_NULL, nx_snmp_object_octet_string_get, nx_snmp_object_octet_string_set, sizeof(atPhysAddress)},
    {(UCHAR *) "1.3.6.1.2.1.2.2.1.9.0",   &ifLastChange,              nx_snmp_object_timetics_get, NX_NULL,    nx_snmp_object_timetics_set,  sizeof(ifLastChange)},
    {(UCHAR *) "1.3.6.1.2.1.2.2.1.10.0",  &ifInOctets,                nx_snmp_object_counter_get, NX_NULL,     nx_snmp_object_counter_set,  sizeof(ifInOctets)},
    {(UCHAR *) "1.3.6.1.2.1.2.2.1.11.0",  &ifInUcastPkts,             nx_snmp_object_counter64_get, NX_NULL,   nx_snmp_object_counter64_set,  sizeof(ifInUcastPkts)},
    
    {(UCHAR *) "1.3.6.1.2.1.4.1.0",       &ipForwarding,              nx_snmp_object_integer_get, NX_NULL,     nx_snmp_object_integer_set,  sizeof(ipForwarding)},
    {(UCHAR *) "1.3.6.1.2.1.4.2.0",       &ipDefaultTTL,              nx_snmp_object_integer_get, NX_NULL,     NX_NULL,  sizeof(ipDefaultTTL)},
    {(UCHAR *) "1.3.6.1.4.1.51000.1.4.0", &oid_var,                   nx_snmp_object_integer_get, NX_NULL,     NX_NULL,  sizeof(oid_var)},

    {(UCHAR *) "1.3.6.1.7",               (UCHAR *) "1.3.6.1.7",      nx_snmp_object_end_of_mib,  NX_NULL,     NX_NULL, sizeof("1.3.6.1.7") - 1},
    {NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, 0}

};
