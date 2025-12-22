/*
 * app_usp_server.h
 *
 *  Created on: Oct 24, 2025
 *      Author: alpl_
 */

#ifndef APP_UDP_APP_UDP_SERVER_H_
#define APP_UDP_APP_UDP_SERVER_H_

#include "app_udp.h"
#include "nx_api.h"

#define LOGGING_PORT 6000
#define CANOPEN_PORT 6001
#define QUEUE_MAX_SIZE 512
#define DATA_BUFFER_SIZE 512
#define UDP_RECEIVE_TIMEOUT (NX_IP_PERIODIC_RATE)
#define CLIENT_TIMEOUT_MS 5000  // 5 seconds without packets = client disconnected

#ifdef __cplusplus

extern "C" {

uint16_t app_udp_server_init( void *byte_pool, NX_IP *ip_instance, NX_PACKET_POOL *packet_pool);
TX_THREAD* get_udp_server_thread_instance(void);
}
#endif

/*************************************************************************
 * Webpages namespace
 * This namespace contains functions related to serving web pages and handling error packets.
 */
//namespace programs {
//	// Function to serve the index page
//	UINT serve_index_page(NX_WEB_HTTP_SERVER* server_ptr, NX_PACKET* packet_ptr);
//	UINT serve_404_page(NX_WEB_HTTP_SERVER* server_ptr, NX_PACKET* packet_ptr);
//	UINT serve_login_page(NX_WEB_HTTP_SERVER* server_ptr, NX_PACKET* packet_ptr);
//	UINT led_on(NX_WEB_HTTP_SERVER* server_ptr, NX_PACKET* packet_ptr);
//	UINT led_off(NX_WEB_HTTP_SERVER* server_ptr, NX_PACKET* packet_ptr);
//	UINT get_led_state(NX_WEB_HTTP_SERVER* server_ptr, NX_PACKET* packet_ptr);
//
//	// Function to send an error packet
//	UINT error_packet_send(NX_WEB_HTTP_SERVER *server_ptr, NX_PACKET *packet_ptr, CHAR *status_code,
//			const CHAR *AdditionErrorMessage);
//
//} // namespace Webpages

#endif /* APP_UDP_APP_UDP_SERVER_H_ */
