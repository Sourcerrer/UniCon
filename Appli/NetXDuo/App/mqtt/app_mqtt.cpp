/*
 * mqtt_util.c
 *
 *  Created on: Sep 10, 2025
 *      Author: alpl_
 */

#include "app_netxduo.h"
#include "tx_api.h"
#include "nxd_mqtt_client.h"
#include <stdbool.h>
#include <stdio.h>


/* private function prototypes */
static UCHAR *get_MqttApp_byte_pool_buffer(void);
static TX_BYTE_POOL * get_MqttApp_byte_pool(void);
static UINT Is_Memory_available_in_MqttApp_BytePool(TX_BYTE_POOL *ptr_byte_pool, ULONG size);

#define  MY_MQTT_APP_MEM_POOL_SIZE (1024 * 4) // Size of the memory pool for MQTT app
/**************************************************
 * @brief Initialize the mqtt app
 * @return true if successful, false otherwise
 */
bool mqtt_app_init(void){

	UINT ret;
	  /* Create a byte pool for the messages used to */
    /* Create a byte pool for application memory allocation.
     * THis pool is used by the application as runtime pool by tasks such as
     * "Tracex Thread"
     * "Web Server" etc */
    ret =  tx_byte_pool_create(get_MqttApp_byte_pool(), const_cast<CHAR *>("User memory pool"),
    		get_MqttApp_byte_pool_buffer(), MY_MQTT_APP_MEM_POOL_SIZE);
	if (ret != TX_SUCCESS)
	{
	  return TX_POOL_ERROR;
	}
	  /* Create a queue to receive messages from topic */

	  /* Create a queue to send messages to a topic
	   * The message structure in queue is
	   * 1. pointer to the topic name
	   * 2. pointer to the message to be sent
	   * 3. Type of message being sent
	   * 4.  */
	  return true;

}

/*************************************************
 * Byte pool management functions
 */
/**
 * @brief Get the User byte pool buffer.
 *
 * This function returns a pointer to the static buffer used for the User byte pool.
 * The buffer is aligned to 32 bytes as required by TraceX.
 *
 * @return Pointer to the User byte pool buffer.
 */
static UCHAR *get_MqttApp_byte_pool_buffer(void)
{
	__ALIGN_BEGIN static UCHAR tx_byte_pool_buffer[MY_MQTT_APP_MEM_POOL_SIZE] __ALIGN_END;
	return (UCHAR *)tx_byte_pool_buffer;
}

/**
 * @brief Get the MQTT app byte pool buffer.
 *
 * This function returns a pointer to the static buffer used for the MQTT app byte pool.
 * The buffer is aligned to 32 bytes as required by TraceX.
 *
 * @return Pointer to the MQTT app byte pool buffer.
 */
static TX_BYTE_POOL * get_MqttApp_byte_pool(void)
{
	static TX_BYTE_POOL tx_app_byte_pool;
	return (TX_BYTE_POOL * const)&tx_app_byte_pool;
}

/**
 * @brief Check and alllocate memory from the byte pool.
 *
 * @note Allowed From Threads
 * 		 Preemption Possible Yes
 *
 *  */
static UINT Is_Memory_available_in_MqttApp_BytePool(TX_BYTE_POOL *ptr_byte_pool, ULONG size){
	/* USER CODE BEGIN Check_Byte_Pool_Available */
//	TX_BYTE_POOL *ptr_byte_pool = (TX_BYTE_POOL*)get_App_byte_pool();

	if(ptr_byte_pool == NULL){
		return TX_POOL_ERROR;
	}
	if(size == 0){
		return TX_SUCCESS;
	}

	UINT status = TX_SUCCESS;
	CHAR *name;
	ULONG available;
	ULONG fragments;
	TX_THREAD *first_suspended;
	ULONG suspended_count;
	TX_BYTE_POOL *next_pool;

	status = tx_byte_pool_info_get( ptr_byte_pool, &name,
									&available, &fragments,
									&first_suspended, &suspended_count,
									&next_pool);
	if(status == TX_SUCCESS){
		printf("User Byte Pool Info: Name: %s, Available: %lu, Fragments: %lu, Suspended Count: %lu\n",
				name, available, fragments, suspended_count);
		if(available < size ){
			printf("User Byte Pool: Not enough memory available. Requested: %lu, Available: %lu\n", size, available);
			status = TX_POOL_ERROR;
		}
	}

	return status;
}

/**
 * @brief Allocate memory from the USER byte pool.
 *
 * @params Size of memory to be allocated
 * @param Pointer to the allocated memory if sucessful
 * @param Timeout in milliseconds to wait for memory allocation
 * @return TX_SUCCESS if memory is allocated successfully, else TX_POOL_ERROR
 * @note Allowed From Threads
 *
 * @return  TX_SUCCESS (0x00) 		Successful memory allocation.
 * 			TX_DELETED (0x01) 		Memory pool was deleted while thread
 * 							  		was suspended.
 * 			TX_NO_MEMORY (0x10) 	Service was unable to allocate the
 * 									memory within the specified time to
 * 									wait.
 * 			TX_WAIT_ABORTED (0x1A)  Suspension was aborted by another
 * 									thread, timer, or ISR.
 * 			TX_POOL_ERROR (0x02) 	Invalid memory pool pointer.
 * 			TX_PTR_ERROR (0x03) 	Invalid pointer to destination pointer.
 * 			TX_SIZE_ERROR (0X05) 	Requested size is zero or larger than
 * 									the pool.
 * 			TX_WAIT_ERROR (0x04) 	A wait option other than TX_NO_WAIT
 * 									was specified on a call from a nonthread.
 * 			TX_CALLER_ERROR (0x13)  Invalid caller of this service.
 *
 */
UINT Allocate_Memory_From_MqttApp_Byte_Pool(ULONG size, VOID **memory_ptr, ULONG timeout_ms){

	/* USER CODE BEGIN Allocate_Memory_From_User_Byte_Pool */
	TX_BYTE_POOL *ptr_byte_pool = (TX_BYTE_POOL*)get_MqttApp_byte_pool();
//	static const ULONG timeout_ms = 100; // Timeout to get the bytes from the pool
	if(ptr_byte_pool == NULL){
		return TX_POOL_ERROR;
	}

	if(size == 0){
		return TX_SUCCESS;
	}

	UINT status = Is_Memory_available_in_MqttApp_BytePool(ptr_byte_pool, size);
	if(status != TX_SUCCESS){
		return status;
	}

	status = tx_byte_allocate(ptr_byte_pool, memory_ptr, size, timeout_ms);
	if(status != TX_SUCCESS){
		printf("Error Allocating %ld TraceX bytes from App Pool\n", size);
		return status;
	}

	return TX_SUCCESS;
}

/**
 * @brief Release memory back to the USER byte pool.
 * @param memory_ptr Pointer to the memory to be released
 */
UINT Release_Memory_To_MqttApp_Byte_Pool(VOID *memory_ptr){
	/* USER CODE BEGIN Release_Memory_To_User_Byte_Pool */
	TX_BYTE_POOL *ptr_byte_pool = (TX_BYTE_POOL*)get_MqttApp_byte_pool();
	if(ptr_byte_pool == NULL){
		return TX_POOL_ERROR;
	}

	if(memory_ptr == NULL){
		return TX_SUCCESS;
	}

	UINT status = tx_byte_release(memory_ptr);
	if(status != TX_SUCCESS){
		printf("Error Releasing TraceX bytes to App Pool\n");
		return status;
	}

	return TX_SUCCESS;
}

/***********************************************
 *  @brief Get DNS address of the MQTT broker
 *  @todo Implement retry mechanism and error handling
 *        Create a list of valid DNS servers to use
 *        Check if broker is on local network or remote
 *        If local, use mDNS to resolve address
 *        If remote, use public DNS server
 *  @param dns_client_ptr Pointer to the DNS client
 *  @return NX_SUCCESS if successful, error code otherwise
 */
bool get_mqtt_broker_ip_address(NX_DNS *ptrDnsClient ,ULONG *ip_address){
//	/* Get the mqtt addresses from the table */
//
//	/* Look up MQTT Server address. */
//	UINT ret;
//	do{
//		ret = nx_dns_host_by_name_get(ptrDnsClient, (UCHAR *)MQTT_BROKER_NAME,
//				&ip_address, DEFAULT_TIMEOUT);
//		if (ret != NX_SUCCESS)
//		{
//			printf("DNS look up failed, error: 0x%x. Retrying...\n", ret);
//			tx_thread_sleep(DEFAULT_TIMEOUT);
//		}
//	}while(ret != NX_SUCCESS);
//
//	printf("MQTT broker address: %lu.%lu.%lu.%lu\n",
//			(*ip_address >> 24) & 0xff,
//			(*ip_address >> 16) & 0xff,
//			(*ip_address >> 8) & 0xff,
//			(*ip_address) & 0xff);
//
//	return true;

}
/**************************************************
 * @brief Check connection with the MQTT broker
 * @description ping to the broker
 */


/**************************************************
 * @brief Connect to the MQTT broker
 * @note Call get dns address first
 */



/**************************************************
 * @brief Publish a message to the MQTT broker
 */

/***************************************************
 * @brief Subscribe to a topic
 */

/***************************************************
 * @brief Unsubscribe from a topic
 */

/***************************************************
 * @brief Create a CSV string to publish
 */
bool create_csv_string(char *data, size_t max_len, const char *format, ...)
{
//	va_list args;
//	int len;
//
//	/* Get the time */
//	va_start(args, format);
//	len = vsnprintf(data, max_len, format, args);
//	va_end(args);
//
//	if (len < 0 || (size_t)len >= max_len) {
//		// Encoding error or output was truncated
//		return false;
//	}
//	return true;
}

/***************************************************
 * @brief Generate a random number to stuff in the message
 */

/****************************************************
 * @brief Callback to setup TLS parameters for secure MQTT connection.
 */

/******************************************************
 * @brief  Create a JSON string to publish
 * @param  data: pointer to the data to be included in the JSON
 * @retval status
 */
