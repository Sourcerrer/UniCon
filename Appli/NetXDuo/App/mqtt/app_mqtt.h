/*
 * app_mqtt.h
 *
 *  Created on: Oct 15, 2025
 *      Author: alpl_
 */

#ifndef APP_MQTT_APP_MQTT_H_
#define APP_MQTT_APP_MQTT_H_

#include "nx_api.h"
#include "app_netxduo.h"


/* MQTT Client USER configuration */
#define ENBALE_MQTT_PUBLISH_LOGS	0  /* Set to 1 to enable MQTT publish logs, 0 to disable */


/* MQTT Client configuration */
#define MQTT_CLIENT_STACK_SIZE      1024 * 10
#define MQTT_PRIORITY               10
#define MQTT_STACK_SIZE             1024 * 6
#define CLIENT_ID_STRING            "MQTT_client_ID"
#define MQTT_THREAD_PRIORTY         12
#define MQTT_KEEP_ALIVE_TIMER       60                    /* Define the MQTT keep alive timer for 60 seconds */
#define CLEAN_SESSION               NX_TRUE
#define STRLEN(p)                   (sizeof(p) - 1)
#define TOPIC_NAME                  "v6/data"  /* Topic to subscribe */
#define NB_MESSAGE                  10                    /*  if NB_MESSAGE = 0, client will publish messages infinitely */
#define MQTT_BROKER_NAME            "test.mosquitto.org" /* MQTT Server */
//#define MQTT_BROKER_NAME 			"broker.emqx.io"
// Ensure port is 1883
//#define MQTT_BROKER_NAME            "192.168.0.60" /* MQTT Server */
//#define MQTT_PORT                   NXD_MQTT_TLS_PORT
#define MQTT_PORT                   1883 /* MQTT Server port */
#define QOS0                        0
#define QOS1                        1
#define DEMO_MESSAGE_EVENT          1
#define DEMO_ALL_EVENTS             3


typedef enum {
	emqtt_connected 			= ( (ULONG)(1UL << 0UL) ),
	emqtt_subscribed	 		= ( (ULONG)(1UL << 1UL) ),
	emqtt_unsubscribed 			= ( (ULONG)(1UL << 2UL) ),
	emqtt_message_received  	= ( (ULONG)(1UL << 3UL) ),
	emqtt_message_published 	= ( (ULONG)(1UL << 4UL) ),

	emqtt_all_events 		= ( emqtt_connected |
								emqtt_subscribed |
								emqtt_unsubscribed |
								emqtt_message_received |
								emqtt_message_published ),
} e_mqtt_event_type;

#ifdef __cplusplus
extern "C" {
#endif
uint16_t app_mqtt_init( void *byte_pool, NX_PACKET_POOL *packet_pool,
						NX_IP *ip_instance, NX_DNS *dns_client_ptr );
TX_THREAD* get_mqtt_thread_instance(void);

#ifdef __cplusplus
}
#endif



#endif /* APP_MQTT_APP_MQTT_H_ */
