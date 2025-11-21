#ifndef __MQTT_INTEROPERABILITY_TEST__
#define __MQTT_INTEROPERABILITY_TEST__

#include "tls_test_frame.h"

#define MQTT_PORT 8884

#ifndef MQTT_PORT
#define MQTT_PORT 8883
#endif /* MQTT_PORT */

#define STRING(s) str(s)
#define str(s) #s

#endif /* __MQTT_INEROPERABILITY_TEST__ */
