/***************************************************************************
 * Copyright (c) 2024 Microsoft Corporation
 *
 * This program and the accompanying materials are made available under the
 * terms of the MIT License which is available at
 * https://opensource.org/licenses/MIT.
 *
 * SPDX-License-Identifier: MIT
 **************************************************************************/

#ifndef NX_STM32_CUSTOM_DRIVER_H
#define NX_STM32_CUSTOM_DRIVER_H


#ifdef   __cplusplus

extern   "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#include "nx_api.h"

/* USER CODE BEGIN Includes */

/* USER CODE END Includes */

/* Exported types ------------------------------------------------------------*/
/* USER CODE BEGIN ET */

/* USER CODE END ET */

/* Exported constants --------------------------------------------------------*/
/* USER CODE BEGIN EC */

/* USER CODE END EC */

/* Exported macro ------------------------------------------------------------*/
/* USER CODE BEGIN EM */

/* USER CODE END EM */

/* Exported functions prototypes ---------------------------------------------*/
/* Define global driver entry function. */

VOID  nx_stm32_custom_driver(NX_IP_DRIVER *driver_req_ptr);


/* USER CODE BEGIN EFP */

/* USER CODE END EFP */

/* Private defines -----------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* USER CODE BEGIN 1 */

/* USER CODE END 1 */

#ifdef   __cplusplus
    }
#endif
#endif /* NX_STM32_CUSTOM_DRIVER_H */
