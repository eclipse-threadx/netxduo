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

#ifndef VERSION_H
#define VERSION_H

#ifndef DISABLE_ASC_PORT
#include "asc_version.h"
#else
#ifndef SECURITY_MODULE_VERSION_MAJOR
#define SECURITY_MODULE_VERSION_MAJOR 0
#endif
#ifndef SECURITY_MODULE_VERSION_MINOR
#define SECURITY_MODULE_VERSION_MINOR 0
#endif
#ifndef SECURITY_MODULE_VERSION_PATCH
#define SECURITY_MODULE_VERSION_PATCH 0
#endif
#endif /* DISABLE_ASC_PORT */


#define SECURITY_MODULE_VERSION ((SECURITY_MODULE_VERSION_MAJOR << 24) |\
                                      (SECURITY_MODULE_VERSION_MINOR << 16) |\
                                       SECURITY_MODULE_VERSION_PATCH)

#endif /* VERSION_H */
