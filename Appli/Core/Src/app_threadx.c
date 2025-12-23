/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file    app_threadx.c
  * @author  MCD Application Team
  * @brief   ThreadX applicative file
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2020-2021 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */

/* Includes ------------------------------------------------------------------*/
#include "app_threadx.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include "main.h"
#include <stdbool.h>
#include <stdio.h>
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
/* USER CODE BEGIN PV */
TX_THREAD	myThread_Startup;

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
/* USER CODE BEGIN PFP */
void myThread_Startup_entry(ULONG thread_input);
/* USER CODE END PFP */

/**
  * @brief  Application ThreadX Initialization.
  * @param memory_ptr: memory pointer
  * @retval int
  */
UINT App_ThreadX_Init(VOID *memory_ptr)
{
  UINT ret = TX_SUCCESS;
  /* USER CODE BEGIN App_ThreadX_MEM_POOL */
  TX_BYTE_POOL *ptr_byte_pool = (TX_BYTE_POOL*)memory_ptr;
  UCHAR *puc_StackPtr = NULL;

  /* USER CODE END App_ThreadX_MEM_POOL */

  /* USER CODE BEGIN App_ThreadX_Init */
  if( tx_byte_allocate( ptr_byte_pool,
			  	  	  	(VOID**) &puc_StackPtr,
						TX__STARTUP__THREAD_STACK_SIZE,
						TX_NO_WAIT ) != TX_SUCCESS  )
  {
	  return TX_POOL_ERROR;
  }

  /* Create "startup" Thread.  */
  if (tx_thread_create(&myThread_Startup, "Startup Thread",
		  myThread_Startup_entry, 0x1234, puc_StackPtr,
		  TX__STARTUP__THREAD_STACK_SIZE, TX__STARTUP__THREAD_PRIO,
		  TX__STARTUP__THREAD_PREEMPTION_THRESHOLD,
		  TX__STARTUP__THREAD_TIME_SLICE, TX__STARTUP__THREAD_AUTO_START) != TX_SUCCESS)
  {
    return TX_THREAD_ERROR;
  }
  /* USER CODE END App_ThreadX_Init */

  return ret;
}

  /**
  * @brief  Function that implements the kernel's initialization.
  * @param  None
  * @retval None
  */
void MX_ThreadX_Init(void)
{
  /* USER CODE BEGIN  Before_Kernel_Start */

  /* USER CODE END  Before_Kernel_Start */

  tx_kernel_enter();

  /* USER CODE BEGIN  Kernel_Start_Error */

  /* USER CODE END  Kernel_Start_Error */
}

/* USER CODE BEGIN 1 */
#define DIN_ON  GPIO_PIN_RESET
#define DIN_OFF GPIO_PIN_SET
void  myThread_Startup_entry(ULONG thread_input)
{
	extern volatile bool is_mqtt_client_connected;
    const static ULONG sleep_time = 250;
    bool ArmState = false;
    bool mqtt_Din = false;
    /* switch on power on led */
    HAL_GPIO_WritePin( LED_POWER_ON_GPIO_Port, LED_POWER_ON_Pin, GPIO_PIN_SET);

	while (1)
    {
//		/* Get the ARM Disarm input from mqtt topic */
////		ArmState = true; // Just for testing purpose

		if(HAL_GPIO_ReadPin(DIN1_GPIO_Port, DIN1_Pin) == DIN_ON){
			HAL_GPIO_WritePin(LED_DIN2_GPIO_Port, LED_DIN2_Pin, GPIO_PIN_SET);
//			printf("Input1 ON\r\n");
		}
		else{
			HAL_GPIO_WritePin(LED_DIN2_GPIO_Port, LED_DIN2_Pin, GPIO_PIN_RESET);
		}

		if(HAL_GPIO_ReadPin(DIN2_GPIO_Port, DIN2_Pin) == DIN_ON){
			HAL_GPIO_WritePin(LED_DIN1_GPIO_Port, LED_DIN1_Pin, GPIO_PIN_SET);
//			printf("Input 2 ON\r\n");
		}
		else{
			HAL_GPIO_WritePin(LED_DIN1_GPIO_Port, LED_DIN1_Pin, GPIO_PIN_RESET);
		}


		/* Check for the inputs and switch on the LEDs & outputs */
		if(HAL_GPIO_ReadPin(DIN1_GPIO_Port, DIN1_Pin) == DIN_ON ||
		   HAL_GPIO_ReadPin(DIN2_GPIO_Port, DIN2_Pin) == DIN_ON){
			HAL_GPIO_WritePin(DOUT1_GPIO_Port, DOUT1_Pin, GPIO_PIN_SET);
//			printf("Output ON\r\n");
		}
		else{
			HAL_GPIO_WritePin(DOUT1_GPIO_Port, DOUT1_Pin, GPIO_PIN_RESET);
//			printf("Both Input OFF\r\n");
		}

		/* Check for ARM Disarm Input */

		/* If input from mqtt is switched on then DOUt 2 will be ON */

		/* Output 1 will switched on if input 1 or input 2 is ON */
		if(is_mqtt_client_connected){
			/* toggle the conectivity led*/
			HAL_GPIO_TogglePin(LED_CONNECTIVITY_GPIO_Port, LED_CONNECTIVITY_Pin);
		}
		else{
			/* switch off the conectivity led*/
			HAL_GPIO_WritePin( LED_CONNECTIVITY_GPIO_Port,
					           LED_CONNECTIVITY_Pin, GPIO_PIN_RESET);
		}

		/* Check Arm disarm input */
		HAL_GPIO_TogglePin(GPIOD, GPIO_PIN_13);
    	tx_thread_sleep(sleep_time); // Sleep for 100 ticks

    }
}
/* USER CODE END 1 */
