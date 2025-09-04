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
void  myThread_Startup_entry(ULONG thread_input)
{

	while (1)
    {
		HAL_GPIO_TogglePin(GPIOD, GPIO_PIN_13);
    	tx_thread_sleep(100); // Sleep for 100 ticks

    }
}
/* USER CODE END 1 */
