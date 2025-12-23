/*
 * app_mqtt.cpp
 *
 *  Created on: Oct 15, 2025
 *      Author: alpl_
 */

#include <iostream>
#include <cstdint>
#include <sstream>
#include <string_view>
#include <cstring>

/* Appication includes */
#include "app_mqtt.h"
#include "app_threadx.h"
#include "log_util.h"


TX_THREAD AppMQTTClientThread;
NXD_MQTT_CLIENT MqttClient;
//ULONG mqtt_client_stack[MQTT_CLIENT_STACK_SIZE];
TX_EVENT_FLAGS_GROUP mqtt_app_flag;
//static char message[NXD_MQTT_MAX_MESSAGE_LENGTH];
//static UCHAR message_buffer[NXD_MQTT_MAX_MESSAGE_LENGTH];
//static UCHAR topic_buffer[NXD_MQTT_MAX_TOPIC_NAME_LENGTH];
static VOID App_MQTT_Client_Thread_Entry(ULONG thread_input);
/*==============================================================================
  MQTT functions
  ==============================================================================*/

/* MQTT configurations */
#define IS_BROKER_REMOTE  1 //1 if broker is remote, 0 if broker is on local network
/* END MQTT configurations */
volatile bool is_mqtt_client_connected = false; /* this variable is set & reset in */

struct mqtt_client_info_t{
	ULONG       broker_ip_address;
	NX_PACKET_POOL *packet_pool;
	NX_IP *ip_instance;
	NX_DNS *dns_client_ptr;
	TX_BYTE_POOL *byte_pool;
};

TX_THREAD* get_mqtt_thread_instance(void){
	return &AppMQTTClientThread;
}
/**
 * @brief  Initialize the MQTT client application
 * @param  byte_pool: pointer to a previously created byte pool
 * @note   Get the pointer form the application
 * @
 */
uint16_t app_mqtt_init( void *byte_pool, NX_PACKET_POOL *packet_pool,
						NX_IP *ip_instance, NX_DNS *dns_client_ptr ) {
	const ULONG stack_size = MQTT_STACK_SIZE;
	CHAR *stack_ptr;
	static mqtt_client_info_t mqtt_client_info;

	if (byte_pool == TX_NULL || packet_pool == TX_NULL || ip_instance == TX_NULL || dns_client_ptr == TX_NULL) {
		std::cerr << "Error: Null pointer passed to app_mqtt_init" << std::endl;
		return TX_POOL_ERROR;
	}

	mqtt_client_info.dns_client_ptr = dns_client_ptr;
	mqtt_client_info.ip_instance = ip_instance;
	mqtt_client_info.packet_pool = packet_pool;
	mqtt_client_info.byte_pool = static_cast<TX_BYTE_POOL *>(byte_pool);
	/* Allocate the memory for MQTT client thread */
	if (tx_byte_allocate( mqtt_client_info.byte_pool,
//						  (VOID **) &stack_ptr,
						  static_cast<void**>(static_cast<void*>(&stack_ptr)),
						  stack_size, TX_NO_WAIT) != TX_SUCCESS){
		return TX_POOL_ERROR;
	}
	/* create the MQTT client thread */
	uint16_t ret = tx_thread_create(&AppMQTTClientThread, const_cast<CHAR *>("App MQTT Thread"),
			App_MQTT_Client_Thread_Entry, reinterpret_cast<ULONG>(&mqtt_client_info),
			stack_ptr, stack_size,
			MQTT_PRIORITY, MQTT_PRIORITY,
			TX_NO_TIME_SLICE, TX_DONT_START);
	MSG_DEBUG("Nx_MQTT_Client application started..\n");


	return ret;

}

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

static inline bool is_mqtt_broker_reachable(ULONG ip_address, NX_IP *NetXDuoEthIpInstance){
	/* Ping the mqtt broker to check if it is reachable */
	UINT ret;
	uint16_t ping_retry = 0;
	NX_PACKET *ping_response;
	static const ULONG PING_TIMEOUT = (20 * NX_IP_PERIODIC_RATE);// 1s
	static const uint16_t PING_RETRIES = 3;


	/* Ping broker with retries */
	for (ping_retry = 0; ping_retry < PING_RETRIES; ping_retry++) {
		ret = nx_icmp_ping(NetXDuoEthIpInstance,ip_address,
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

static inline bool secure_connect_to_mqtt_broker(NXD_ADDRESS *mqtt_server_ip){
//	UINT ret;
//	  ret = nxd_mqtt_client_secure_connect(&MqttClient, mqtt_server_ip, MQTT_PORT, tls_setup_callback,
//	                                       MQTT_KEEP_ALIVE_TIMER, CLEAN_SESSION, NX_WAIT_FOREVER);
//
//	  if (ret != NX_SUCCESS){
//	    printf("\nMQTT client failed to connect to broker < %s >.\n",MQTT_BROKER_NAME);
//	    return false;
////	    tx_thread_suspend(tx_thread_identify());
//	  }
//	  else{
//	    printf("\nMQTT client connected to broker < %s > at PORT %d :\n",MQTT_BROKER_NAME, MQTT_PORT);
//	  }

	  return true;
}

static inline bool connect_to_mqtt_broker(NXD_ADDRESS *mqtt_server_ip){
	UINT ret;
	const static uint16_t MAX_RETRIES = 3;
	uint16_t retry = 0;

	do{
		/* Try to connect to the MQTT broker */
		ret = nxd_mqtt_client_connect(  &MqttClient, mqtt_server_ip, MQTT_PORT,
										MQTT_KEEP_ALIVE_TIMER, CLEAN_SESSION, DEFAULT_TIMEOUT);
		if (ret != NX_SUCCESS){
			tx_thread_sleep(DEFAULT_TIMEOUT * 2);;
		}
	}while(ret != NX_SUCCESS && retry++ < MAX_RETRIES);

	if (ret != NX_SUCCESS){
		std::cerr << "\nMQTT client failed to connect to broker < "
				  << MQTT_BROKER_NAME << " >, error: 0x"
				  << std::hex << ret << std::dec << std::endl;
		return false;
	}
	else{
		std::cout << "\nMQTT client connected to broker < "
				  << MQTT_BROKER_NAME << " > at PORT "
				  << MQTT_PORT << std::endl;
	}

	return true;
}

static const char *Device_Id = "v6/001"; //example device id
static bool Power_Status = true; //example power status
static bool Device_Online_when_DataCaptured = true; //example device online status
static uint32_t Input_Status = 0x5A5A; //example input status
static inline bool publish_time_to_topic(std::string_view topic){
    /* Publish a message with QoS Level 1. */
	UINT ret;
	static UINT message_count = 0;
    ULONG retries = 0;
    static const ULONG max_retries = 5;
    extern RTC_HandleTypeDef RtcHandle;
//    const static ULONG WaitTime = 100;

    /* TODO Get the buffer from User byte pool */
//    CHAR message[100];
    char time_string[32];
    rtc_time_to_buffer(&RtcHandle, time_string, sizeof(time_string));
    /* Toggle power status for demonstration */
    Power_Status ^=1;
    /* Toggle device online status for demonstration */
    Device_Online_when_DataCaptured ^=1;

    Input_Status ^= 0xFFFF;
    /* Prepare the string */
    std::stringstream ss;
    ss << "Time: " << time_string
	   << ", Device ID: " << Device_Id
	   << ", Power Status: " << (Power_Status ? "ON" : "OFF")
	   << ", Device Online when Data Captured: " << (Device_Online_when_DataCaptured ? "YES" : "NO")
	   << ", Input Status: 0x" << std::hex << Input_Status;
    std::string message = ss.str();
    /* TODO Add sensor data to the message */
	/* Publish the message to the broker */
    do{
    	ret = nxd_mqtt_client_publish(&MqttClient, const_cast<CHAR *>( topic.data() ), topic.length(),
    	                                  static_cast<CHAR *>( message.data() ), message.length(),
										  NX_TRUE, QOS1, NX_WAIT_FOREVER);
    	if (ret != NX_SUCCESS)
    	{
    		std::cerr << "MQTT publish failed, 0x" << std::hex << ret << std::dec << std::endl;
    		tx_thread_sleep(100);
    	}
    }while(ret != NX_SUCCESS && retries++ < max_retries);

    if(ret == NX_SUCCESS){
//    	std::cout << "Message " << ++message_count << " published: TOPIC = " << topic
//				  << ", MESSAGE = " << message << std::endl;
		return true;
	}

    printf("MQTT publish failed after %ld retries,\r\n", retries);
    return false;

}

static bool mqtt_client_publish_empty_message(std::string_view topic){
	/* Publish messages infinitely if NB_MESSAGE is 0 */
	UINT ret;
	uint16_t retries = 0;
	constexpr const static ULONG max_retries = 5;
    do{
    	/* send an empty message at the end of the session to avoid the "Retain" message behavior */
    	ret = nxd_mqtt_client_publish(  &MqttClient, const_cast<CHAR *>( topic.data() ),
    									topic.length(), NULL, 0, NX_TRUE, QOS1, NX_WAIT_FOREVER  );
    	if (ret != NX_SUCCESS){
    		std::cerr << "MQTT publish failed when sending empty message, 0x"
    				  << std::hex << ret << std::dec << std::endl;
    		return false;
    	}
    }while(ret != NX_SUCCESS && retries++ < max_retries);

	return true;
}

static inline bool mqtt_client_disconnect(void){
	UINT ret;

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
	mqtt_server_ip.nxd_ip_version = 4;
	ULONG actual_event_flags = 0;
    static const constexpr std::string_view topic = "ppmt/v6/data1";
    static const constexpr std::string_view client_id_string = "v6_001";

	/******************************************************/
    //get the mqtt client info from the thread input
	mqtt_client_info_t *mqtt_client_info = reinterpret_cast<mqtt_client_info_t *>(thread_input);
	CHAR *pointer;
	/************************************/
	std::cout << "Starting MQTT client.." << std::endl;
	/* Allocate the memory for packet_pool.  */
	if (tx_byte_allocate( mqtt_client_info->byte_pool,
						  (VOID **) &pointer, MQTT_CLIENT_STACK_SIZE, TX_NO_WAIT) != TX_SUCCESS)
	{
//		log_e("Failed to allocate memory for MQTT client stack");
		std::cerr << LOG_LOC << "Failed to allocate memory for MQTT client stack" << std::endl;
		Error_Handler();
	}
	/*TODO Create the mqtt_client_stack from NX_Pool */
	/* Create MQTT client instance. */
	ret = nxd_mqtt_client_create(	  &MqttClient,
			const_cast<CHAR *>("my_client"),
			const_cast<CHAR *>(client_id_string.data()),
			client_id_string.length(),
			mqtt_client_info->ip_instance,
			mqtt_client_info->packet_pool,
			(void*)pointer,
			MQTT_CLIENT_STACK_SIZE,
			MQTT_THREAD_PRIORTY,
			NX_NULL,
			0);


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
	ret = tx_event_flags_create( &mqtt_app_flag, const_cast<CHAR *>("my app event") );
	if (ret != TX_SUCCESS)
	{
		printf("MQTT event flag creation failed\r\n");
		tx_thread_suspend(tx_thread_identify());
	}
	/****************************************************************/

#if(IS_BROKER_REMOTE == 1)
	{
		/* Get the broker server address */
		get_mqtt_broker_ip_address(mqtt_client_info->dns_client_ptr, &mqtt_server_ip.nxd_ip_address.v4);
		/* Check if the broker is reachable */
	}
#else
	/* Set MQTT server IP directly */
	mqtt_server_ip.nxd_ip_version = NX_IP_VERSION_V4;
	mqtt_server_ip.nxd_ip_address.v4 = IP_ADDRESS(192, 168, 0, 213); // 192.168.0.239
#endif
	is_mqtt_broker_reachable(mqtt_server_ip.nxd_ip_address.v4, mqtt_client_info->ip_instance);
	/* Start a secure connection to the server. */

	if( connect_to_mqtt_broker(&mqtt_server_ip) == false ){
		/* TODO handle connection to a different broker */
		tx_thread_suspend(tx_thread_identify());
	}

	//wait for connection event flag
	tx_event_flags_get(&mqtt_app_flag, emqtt_connected, TX_AND, &actual_event_flags, NX_WAIT_FOREVER);
	/* Subscribe to topic on the broker */
//	ret = nxd_mqtt_client_subscribe(&MqttClient, TOPIC_NAME, STRLEN(TOPIC_NAME), QOS1);
	while(1){
		/* Wait for incoming message for 2000 millisecs */

		/* Check the connection to the broker */
		ret = tx_event_flags_get(&mqtt_app_flag, emqtt_connected, TX_AND, &actual_event_flags, 100);
//		if( !is_mqtt_broker_reachable(mqtt_server_ip.nxd_ip_address.v4) ){
		//	  if( (ret != TX_SUCCESS) || ( (actual_event_flags & emqtt_connected) == 0 ) ){
		if(!is_mqtt_client_connected){
			/* Disconnect from the broker */
			mqtt_client_disconnect();
			tx_thread_sleep(SLEEP_AFTER_DISCONNECT);
			/* Get the broker server address */
			get_mqtt_broker_ip_address(mqtt_client_info->dns_client_ptr, &mqtt_server_ip.nxd_ip_address.v4);
			/* Start a secure connection to the server. */
			connect_to_mqtt_broker(&mqtt_server_ip);
			//wait for connection event flag
			tx_event_flags_get(&mqtt_app_flag, emqtt_connected, TX_AND, &actual_event_flags, NX_WAIT_FOREVER);
			/* Subscribe to topic on the broker */
//			ret = nxd_mqtt_client_subscribe(&MqttClient, TOPIC_NAME, STRLEN(TOPIC_NAME), QOS1);
		}

		/* Check the queue for message to be published */

		/* Publish the message to the broker */
		publish_time_to_topic(topic);
		mqtt_client_publish_empty_message(topic);
		/* Check the queue whether message is received */

		/* Get the message from the broker if queue is not empty */



		/* Process the configuration */


		/* sleep for 2 seconds */
		/* Delay 1s between each pub */
		tx_thread_sleep(1000);
	}
	/* Disconnect from the broker */
	mqtt_client_disconnect();
	/* Delete the client instance, release all the resources. */
	ret = nxd_mqtt_client_delete(&MqttClient);
	if (ret != NX_SUCCESS)
	{
		printf("MQTT client delete failed\r\n");
	}
}


