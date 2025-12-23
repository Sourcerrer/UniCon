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
#ifdef __cplusplus
extern "C" {
uint16_t app_mqtt_init( void *byte_pool, NX_PACKET_POOL *packet_pool,
						NX_IP *ip_instance, NX_DNS *dns_client_ptr );
TX_THREAD* get_mqtt_thread_instance(void);
}

#endif



#endif /* APP_MQTT_APP_MQTT_H_ */
