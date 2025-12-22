/*
 * app_mqtt.h
 *
 *  Created on: 19-Dec-2025
 *      Author: alpl_
 */

#ifndef APP_MQTT_APP_MQTT_H_
#define APP_MQTT_APP_MQTT_H_
#include <tx_api.h>

#define MOSQUITTO_CERT_FILE         "mosquitto.cert.h"
#define  MY_MQTT_APP_MEM_POOL_SIZE (1024 * 4) // Size of the memory pool for MQTT app
#define MQTT_THREAD_PRIORTY         9
#define MQTT_PRIORITY               10

/* MQTT Client configuration */
#define MQTT_THREAD_STACK_SIZE               1024 * 3
#define MQTT_CLIENT_STACK_SIZE      1024 * 10
#define CLIENT_ID_STRING            "IUC_MQTT_client_ID"
#define MQTT_KEEP_ALIVE_TIMER       60                    /* Define the MQTT keep alive timer for 60 seconds */
#define CLEAN_SESSION               NX_TRUE
#define STRLEN(p)                   (sizeof(p) - 1)
//#define TOPIC_NAME                  "Temperature"
#define TOPIC_NAME                  "IUC/data"

#define NB_MESSAGE                  10                    /*  if NB_MESSAGE = 0, client will publish messages infinitely */
#define MQTT_BROKER_NAME            "test.mosquitto.org" /* MQTT Server */
#define MQTT_PORT                   NXD_MQTT_TLS_PORT
#define QOS0                        0
#define QOS1                        1

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

/**
 * @Exported functions prototypes
 */

#endif /* APP_MQTT_APP_MQTT_H_ */
