/*
 * mqtt_util.c
 *
 *  Created on: Sep 10, 2025
 *      Author: alpl_
 */

#include <old_mqtt/app_mqtt.h>
#include <old_mqtt/mosquitto.cert.h>
#include "app_netxduo.h"
#include "tx_api.h"
#include "nxd_mqtt_client.h"
#include <stdbool.h>
#include <stdio.h>
#include  MOSQUITTO_CERT_FILE

/* private function prototypes */
static UCHAR *get_MqttApp_byte_pool_buffer(void);
static TX_BYTE_POOL * get_MqttApp_byte_pool(void);
static UINT Is_Memory_available_in_MqttApp_BytePool(TX_BYTE_POOL *ptr_byte_pool, ULONG size);

ULONG mqtt_client_stack[MQTT_CLIENT_STACK_SIZE];
TX_EVENT_FLAGS_GROUP mqtt_app_flag;
/* Declare buffers to hold message and topic. */
static char message[NXD_MQTT_MAX_MESSAGE_LENGTH];
static UCHAR message_buffer[NXD_MQTT_MAX_MESSAGE_LENGTH * 2];
static UCHAR topic_buffer[NXD_MQTT_MAX_TOPIC_NAME_LENGTH * 2];
/* TLS buffers and certificate containers. */
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;
/* calculated with nx_secure_tls_metadata_size_calculate */
static CHAR crypto_metadata_client[11600];
/* Define the TLS packet reassembly buffer. */
UCHAR tls_packet_buffer[4000];
ULONG current_time;
volatile bool is_mqtt_client_connected = false; /* this variable is set & reset in
													the notify & disconnect callbacks */

/**************************************************
 * @brief Initialize the mqtt app
 * @return true if successful, false otherwise
 */
bool mqtt_app_init(void *byte_pool){

	UINT ret;
	  /* Create a byte pool for the messages used to */
    /* Create a byte pool for application memory allocation.
     * THis pool is used by the application as runtime pool by tasks such as
     * "Tracex Thread"
     * "Web Server" etc */
    ret =  tx_byte_pool_create( get_MqttApp_byte_pool(),
    							const_cast<CHAR *>("User memory pool"),
								get_MqttApp_byte_pool_buffer(),
								MY_MQTT_APP_MEM_POOL_SIZE);
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

/*==============================================================================
  MQTT functions
  ==============================================================================*/
/* Declare the disconnect notify function. */
static VOID my_disconnect_func(NXD_MQTT_CLIENT *client_ptr)
{
  NX_PARAMETER_NOT_USED(client_ptr);
  printf("client disconnected from broker < %s >.\n", MQTT_BROKER_NAME);
  tx_event_flags_set(&mqtt_app_flag, emqtt_connected, TX_AND);  // clear the connected event flag
  is_mqtt_client_connected = false;
}

/* Declare the notify function. */
static VOID my_notify_func(NXD_MQTT_CLIENT* client_ptr, UINT number_of_messages)
{
  NX_PARAMETER_NOT_USED(client_ptr);
  NX_PARAMETER_NOT_USED(number_of_messages);
  tx_event_flags_set(&mqtt_app_flag, emqtt_message_received, TX_OR);  // set the message received event flag
  return;
}

static VOID mqtt_connect_notify(NXD_MQTT_CLIENT *client_ptr, UINT status, VOID *context){
  NX_PARAMETER_NOT_USED(client_ptr);
  NX_PARAMETER_NOT_USED(context);

  if(status == NX_SUCCESS){
	printf("MQTT client connected to broker < %s > successfully.\n",MQTT_BROKER_NAME);
	tx_event_flags_set(&mqtt_app_flag, emqtt_connected, TX_OR);  // set the connected event flag
	is_mqtt_client_connected = true;
  }
  else{
	printf("MQTT client failed to connect to broker < %s > with error code: 0x%x.\n",MQTT_BROKER_NAME, status);
	tx_event_flags_set(&mqtt_app_flag, emqtt_connected, TX_AND);  // clear the connected event flag
	is_mqtt_client_connected = false;
  }
  return;
}

/**************************************************
 *  @brief Get DNS address of the MQTT broker
 *  @todo Implement retry mechanism and error handling
 *        Create a list of valid DNS servers to use
 *        Check if broker is on local network or remote
 *        If local, use mDNS to resolve address
 *        If remote, use public DNS server
 *  @param dns_client_ptr Pointer to the DNS client
 *  @return NX_SUCCESS if successful, error code otherwise
 */
static inline bool get_mqtt_broker_ip_address(NX_DNS *ptrDnsClient ,ULONG *ip_address){
	/* Get the mqtt addresses from the table */

	/* Look up MQTT Server address. */
	UINT ret;
	do{
		ret = nx_dns_host_by_name_get(ptrDnsClient, (UCHAR *)MQTT_BROKER_NAME,
				ip_address, DEFAULT_TIMEOUT);
		if (ret != NX_SUCCESS)
		{
			printf("DNS look up failed, error: 0x%x. Retrying...\n", ret);
			tx_thread_sleep(DEFAULT_TIMEOUT * 2);
		}
	}while(ret != NX_SUCCESS);

	printf("MQTT broker address: %lu.%lu.%lu.%lu\n",
			( (*ip_address) >> 24) & 0xff,
			( (*ip_address) >> 16) & 0xff,
			( (*ip_address) >> 8) & 0xff,
			( (*ip_address) ) & 0xff );

	return true;
}

static inline bool is_mqtt_broker_reachable(ULONG ip_address){
	/* Ping the mqtt broker to check if it is reachable */
	UINT ret;
	uint16_t ping_retry = 0;
	NX_PACKET *ping_response;
	static const ULONG PING_TIMEOUT = (20 * NX_IP_PERIODIC_RATE);// 1s
	static const uint16_t PING_RETRIES = 3;


	/* Ping broker with retries */
	for (ping_retry = 0; ping_retry < PING_RETRIES; ping_retry++) {
		ret = nx_icmp_ping(&NetXDuoEthIpInstance,ip_address,
				NULL, 0, &ping_response, PING_TIMEOUT);
		if (ret == NX_SUCCESS) {
//			printf("Ping to %s: Success\n", MQTT_BROKER_NAME);
			nx_packet_release(ping_response);
			break;
		}
		printf("Ping attempt %d to %s: Failed, error: 0x%x\n", ping_retry + 1, MQTT_BROKER_NAME, ret);
		if (ping_retry < PING_RETRIES - 1) {
			tx_thread_sleep(PING_TIMEOUT / 2);
		}
	}
	if (ret != NX_SUCCESS) {
		printf("Ping to %s failed after %d attempts, error: 0x%x\n", MQTT_BROKER_NAME, PING_RETRIES, ret);
		//		  tx_thread_suspend(&AppMQTTClientThread); // Wait before retrying the whole process
		return false;
	}

	return true;
}

static inline bool connect_to_mqtt_broker(NXD_ADDRESS *mqtt_server_ip){
	UINT ret;
	  ret = nxd_mqtt_client_secure_connect( &MqttClient, mqtt_server_ip,
			  	  	  	  	  	  	  	  	MQTT_PORT, tls_setup_callback,
	                                        MQTT_KEEP_ALIVE_TIMER,
											CLEAN_SESSION, NX_WAIT_FOREVER);

	  if (ret != NX_SUCCESS){
	    printf("\nMQTT client failed to connect to broker < %s >.\n",MQTT_BROKER_NAME);
	    return false;
//	    tx_thread_suspend(tx_thread_identify());
	  }
	  else{
	    printf("\nMQTT client connected to broker < %s > at PORT %d :\n",MQTT_BROKER_NAME, MQTT_PORT);
	  }

	  return true;
}

static const char *Device_Id = "IUC/001"; //example device id
static bool Power_Status = true; //example power status
static bool Device_Online_when_DataCaptured = true; //example device online status
static uint32_t Input_Status = 0x5A5A; //example input status
static inline bool publish_time_to_topic(void){
    /* Publish a message with QoS Level 1. */
	UINT ret;
	UINT message_count = 0;
    ULONG retries = 0;
    static const ULONG max_retries = 5;
    const static ULONG WaitTime = 100;
    static ULONG toggle_count = 0;
    static const ULONG toggle_count_limit = 60;
    /* TODO Get the buffer from User byte pool */
    CHAR message[64];
    char time_string[32];
    rtc_time_to_buffer(&RtcHandle, time_string, sizeof(time_string));
    /* Toggle power status for demonstration */
    Power_Status ^=1;
    /* Toggle device online status for demonstration */
    Device_Online_when_DataCaptured ^=1;

    if(++toggle_count >= toggle_count_limit){
		toggle_count = 0;
		/* Toggle input status for demonstration */
		Input_Status ^= 0xFFFF;
	}
//    Input_Status ^= 0xFFFF;
    /* Prepare the string */
    snprintf(message, sizeof(message), "%s, %s, "
    		"%d, %d, 0x%lx\r\n",
    		time_string, Device_Id,
			Power_Status, Device_Online_when_DataCaptured, Input_Status);
    /* TODO Add sensor data to the message */
	/* Publish the message to the broker */
    do{
    	ret = nxd_mqtt_client_publish(&MqttClient, TOPIC_NAME, STRLEN(TOPIC_NAME),
    	                                  (CHAR*)message, strlen(message), NX_TRUE, QOS1, NX_WAIT_FOREVER);
    	if (ret != NX_SUCCESS)
    	{
    		printf("MQTT publish failed, 0x%x\r\n", ret);
    		tx_thread_sleep(100);
    		//    	      Error_Handler();
    	}
    }while(ret != NX_SUCCESS && retries++ < max_retries);

    if(retries < max_retries){
		printf("Message %d published: TOPIC = %s, MESSAGE = %s\n", message_count + 1, TOPIC_NAME, message);
		return true;
	}

    printf("MQTT publish failed after %ld retries,\r\n", retries);
    return false;

}


static inline bool mqtt_client_disconnect(void){
	UINT ret;
	/* send an empty message at the end of the session to avoid the "Retain" message behavior */
	ret = nxd_mqtt_client_publish(&MqttClient, TOPIC_NAME, STRLEN(TOPIC_NAME), NULL, 0, NX_TRUE, QOS1, NX_WAIT_FOREVER);

	if (ret != NX_SUCCESS){
		printf("MQTT publish failed\r\n");
		return false;
	}

	/* Now unsubscribe the topic. */
	ret = nxd_mqtt_client_unsubscribe(&MqttClient, TOPIC_NAME, STRLEN(TOPIC_NAME));

	if (ret != NX_SUCCESS){
		printf("MQTT unsubscribe failed\r\n");
		return false;
	}

	/* Disconnect from the broker. */
	ret = nxd_mqtt_client_disconnect(&MqttClient);

	if (ret != NX_SUCCESS){
		printf("MQTT disconnect failed\r\n");
		return false;
	}
	printf("MQTT client disconnected\r\n");
	return true;
}

/**
  * @brief  MQTT Client thread entry.
  * @param thread_input: ULONG user argument used by the thread entry
  * @retval none
  */
static VOID App_MQTT_Client_Thread_Entry(ULONG thread_input)
{
  UINT ret = NX_SUCCESS;
  NXD_ADDRESS mqtt_server_ip;
  static const ULONG SLEEP_AFTER_DISCONNECT = (100 * NX_IP_PERIODIC_RATE); // 10 secs
//  ULONG events;
//  UINT aRandom32bit;
//  UINT topic_length, message_length;
//  UINT remaining_msg = NB_MESSAGE;
//  UINT message_count = 0;
//  UINT unlimited_publish = NX_FALSE;

  mqtt_server_ip.nxd_ip_version = 4;
  ULONG actual_event_flags = 0;
//  UINT retry_count = 0;
//  NX_PACKET *ping_response;
//  UINT ping_retry;
  TX_BYTE_POOL *byte_pool = (size_t)thread_input;

  /******************************************************/
  printf("Starting MQTT client..\n");
  /* Create MQTT client instance. */
  ret = nxd_mqtt_client_create( &MqttClient, "my_client", CLIENT_ID_STRING,
		  	  	  	  	  	  	STRLEN(CLIENT_ID_STRING), &NetXDuoEthIpInstance,
								&NxAppPool, (VOID*)mqtt_client_stack,
								MQTT_CLIENT_STACK_SIZE,
                                MQTT_THREAD_PRIORTY, NX_NULL, 0);

  if (ret != NX_SUCCESS)
  {
	  printf("MQTT client creation failed\r\n");
	  tx_thread_suspend(tx_thread_identify());
  }

  printf("MQTT client created.\n");

  /* Register the disconnect notification function. */
  nxd_mqtt_client_disconnect_notify_set(&MqttClient, my_disconnect_func);

  /* Set the receive notify function. */
  nxd_mqtt_client_receive_notify_set(&MqttClient, my_notify_func);

  /* Set connect notification */
  MqttClient.nxd_mqtt_connect_notify  = mqtt_connect_notify;
  MqttClient.nxd_mqtt_connect_context = NX_NULL; // optional user context

  /* Create an MQTT flag */
  ret = tx_event_flags_create(&mqtt_app_flag, "my app event");
  if (ret != TX_SUCCESS)
  {
	  printf("MQTT event flag creation failed\r\n");
	  tx_thread_suspend(tx_thread_identify());
  }
  /****************************************************************/
  /* Get the broker server address */
  get_mqtt_broker_ip_address(&DnsClient, &mqtt_server_ip.nxd_ip_address.v4);
  /* Check if the broker is reachable */
  is_mqtt_broker_reachable(mqtt_server_ip.nxd_ip_address.v4);
  /* Start a secure connection to the server. */
  connect_to_mqtt_broker(&mqtt_server_ip);
  //wait for connection event flag
  tx_event_flags_get(&mqtt_app_flag, emqtt_connected, TX_AND, &actual_event_flags, NX_WAIT_FOREVER);
  while(1){
	  /* Wait for incoming message for 2000 millisecs */

	  /* Check the connection to the broker */
	  ret = tx_event_flags_get(&mqtt_app_flag, emqtt_connected, TX_AND, &actual_event_flags, 100);
//	  if( !is_mqtt_broker_reachable(mqtt_server_ip.nxd_ip_address.v4) ){
//	  if( (ret != TX_SUCCESS) || ( (actual_event_flags & emqtt_connected) == 0 ) ){
	  if(!is_mqtt_client_connected){
		  /* Disconnect from the broker */
		  mqtt_client_disconnect();
		  tx_thread_sleep(SLEEP_AFTER_DISCONNECT);
		  /* Get the broker server address */
		  get_mqtt_broker_ip_address(&DnsClient, &mqtt_server_ip.nxd_ip_address.v4);
		  /* Start a secure connection to the server. */
		  connect_to_mqtt_broker(&mqtt_server_ip);
		  //wait for connection event flag
		  tx_event_flags_get(&mqtt_app_flag, emqtt_connected, TX_AND, &actual_event_flags, NX_WAIT_FOREVER);
		  /* Subscribe to topic on the broker */
		  ret = nxd_mqtt_client_subscribe(&MqttClient, TOPIC_NAME, STRLEN(TOPIC_NAME), QOS1);
	  }

	  /* Check the queue for message to be published */

	  /* Publish the message to the broker */
	 	  publish_time_to_topic();

	  /* Check the queue whether message is received */

	  /* Get the message from the broker if queue is not empty */



	  /* Process the configuration */


	  /* sleep for 2 seconds */
	  /* Delay 1s between each pub */
	  tx_thread_sleep(2000);

  }
  /* Disconnect from the broker */
  mqtt_client_disconnect();
  /* Delete the client instance, release all the resources. */
  ret = nxd_mqtt_client_delete(&MqttClient);

  if (ret != NX_SUCCESS)
  {
	  printf("MQTT client delete failed\r\n");
//    Error_Handler();
  }
  /************************************************************/

//  /* Subscribe to the topic with QoS level 1. */
//  ret = nxd_mqtt_client_subscribe(&MqttClient, TOPIC_NAME, STRLEN(TOPIC_NAME), QOS1);
//
//  if (ret != NX_SUCCESS)
//  {
//	  printf("MQTT subscribe failed. Suspending thread\r\n");
//	  tx_thread_suspend(tx_thread_identify());
//  }
//
//  if (NB_MESSAGE ==0)
//    unlimited_publish = NX_TRUE;
//
//  while(unlimited_publish || remaining_msg)
//  {
//    aRandom32bit = message_generate();
//
//    snprintf(message, STRLEN(message), "%u", aRandom32bit);
//
//    /* Publish a message with QoS Level 1. */
//
//    ULONG retries = 0;
//    const ULONG max_retries = 5;
//    do{
//    	ret = nxd_mqtt_client_publish(&MqttClient, TOPIC_NAME, STRLEN(TOPIC_NAME),
//    	                                  (CHAR*)message, STRLEN(message), NX_TRUE, QOS1, NX_WAIT_FOREVER);
//    	if (ret != NX_SUCCESS)
//    	{
//    		printf("MQTT publish failed, 0x%x\r\n", ret);
//    		tx_thread_sleep(100);
//    		//    	      Error_Handler();
//    	}
//    }while(ret != NX_SUCCESS && retries++ < max_retries);
//
//    if(retries < max_retries)
//	{
//		printf("Message %d published: TOPIC = %s, MESSAGE = %s\n", message_count + 1, TOPIC_NAME, message);
//	}
//	else
//	{
//		printf("MQTT publish failed after %ld retries, SUpending thread....\r\n", retries);
//		tx_thread_suspend(tx_thread_identify());
//	}
//
//    /* Wait for the broker to publish the message. */
//    tx_event_flags_get(&mqtt_app_flag, DEMO_ALL_EVENTS, TX_OR_CLEAR, &events, TX_WAIT_FOREVER);
//
//    /* Check event received */
//    if(events & DEMO_MESSAGE_EVENT)
//    {
//      /* Get message from the broker */
////    	do{
////    		ret = nxd_mqtt_client_message_get(&MqttClient, topic_buffer, sizeof(topic_buffer), &topic_length,
////    		                                        message_buffer, sizeof(message_buffer), &message_length);
////    	}while(ret == NXD_MQTT_NO_MESSAGE);
//      ret = nxd_mqtt_client_message_get(&MqttClient, topic_buffer, sizeof(topic_buffer), &topic_length,
//                                        message_buffer, sizeof(message_buffer), &message_length);
//      if(ret == NXD_MQTT_SUCCESS)
//      {
//        printf("Message %d received: TOPIC = %s, MESSAGE = %s\n", message_count + 1, topic_buffer, message_buffer);
//      }
//      else
//      {
//    	  printf("MQTT get message failed, 0x%x\r\n", ret);
////        Error_Handler();
//      }
//    }
//
//    /* Decrement message numbre */
//    remaining_msg -- ;
//    message_count ++ ;
//
//    /* Delay 1s between each pub */
//    tx_thread_sleep(100);
//
//  }
//
//  /* send an empty message at the end of the session to avoid the "Retain" message behavior */
//  ret = nxd_mqtt_client_publish(&MqttClient, TOPIC_NAME, STRLEN(TOPIC_NAME), NULL, 0, NX_TRUE, QOS1, NX_WAIT_FOREVER);
//
//  if (ret != NX_SUCCESS)
//  {
//	  printf("MQTT publish failed\r\n");
//    Error_Handler();
//  }
//
//  /* Now unsubscribe the topic. */
//  ret = nxd_mqtt_client_unsubscribe(&MqttClient, TOPIC_NAME, STRLEN(TOPIC_NAME));
//
//  if (ret != NX_SUCCESS)
//  {
//	  printf("MQTT unsubscribe failed\r\n");
//    Error_Handler();
//  }
//
//  /* Disconnect from the broker. */
//  ret = nxd_mqtt_client_disconnect(&MqttClient);
//
//  if (ret != NX_SUCCESS)
//  {
//	  printf("MQTT disconnect failed\r\n");
//    Error_Handler();
//  }
//
//
//
//  /* Test OK -> success Handler */
////  Success_Handler();
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
