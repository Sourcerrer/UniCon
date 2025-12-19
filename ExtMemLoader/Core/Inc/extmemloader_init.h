/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file    extmemloader_init.h
  * @author  MCD Application Team
  * @brief   Header file of Loader_Src.c
  *
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2025 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef EXTMEMLOADER_INIT_H
#define EXTMEMLOADER_INIT_H

/* Includes ------------------------------------------------------------------*/
#include "stm32h7rsxx_hal.h"

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

/* USER CODE BEGIN EFP */

/* USER CODE END EFP */

uint32_t extmemloader_Init(void);
void Error_Handler(void);

/* Private defines -----------------------------------------------------------*/

/* USER CODE BEGIN Private defines */

/* USER CODE END Private defines */

#define DIN1_Pin GPIO_PIN_0
#define DIN1_GPIO_Port GPIOF
#define LED_POWER_ON_Pin GPIO_PIN_0
#define LED_POWER_ON_GPIO_Port GPIOG
#define DOUT2_Pin GPIO_PIN_1
#define DOUT2_GPIO_Port GPIOD
#define LED_DIN1_Pin GPIO_PIN_1
#define LED_DIN1_GPIO_Port GPIOE
#define DIN2_Pin GPIO_PIN_1
#define DIN2_GPIO_Port GPIOF
#define DOUT1_Pin GPIO_PIN_0
#define DOUT1_GPIO_Port GPIOD
#define LED_RED_Pin GPIO_PIN_7
#define LED_RED_GPIO_Port GPIOB
#define LED_CONNECTIVITY_Pin GPIO_PIN_3
#define LED_CONNECTIVITY_GPIO_Port GPIOE
#define LED_DIN2_Pin GPIO_PIN_9
#define LED_DIN2_GPIO_Port GPIOG
#define LED_GREEN_Pin GPIO_PIN_10
#define LED_GREEN_GPIO_Port GPIOD
#endif /* EXTMEMLOADER_INIT_H */
