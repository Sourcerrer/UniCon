/*
 * app_sntp.h
 *
 *  Created on: 09-Jan-2026
 *      Author: alpl_
 */

#ifndef APP_SNTP_INC_APP_SNTP_H_
#define APP_SNTP_INC_APP_SNTP_H_

#include "nx_api.h"
#include "nxd_dns.h"

#define SNTP_PRIORITY               14
/* SNTP Client configuration */
#define SNTP_CLIENT_THREAD_MEMORY    6 * 1024
//#define SNTP_SERVER_NAME             "time1.google.com"
//#define SNTP_SERVER_NAME_1			 "0.in.pool.ntp.org"

#define SNTP_UPDATE_EVENT           (uint32_t)( 1UL << 0UL )
#define SNTP_RTC_UPDATE_EVENT		(uint32_t)( 1UL << 1UL )
#define SNTP_NETWORK_CABLE_CONNECTED_EVENT		(uint32_t)( 1UL << 2UL )
/* Define how often the demo checks for SNTP updates. */
#define PERIODIC_CHECK_INTERVAL      (60 * NX_IP_PERIODIC_RATE)
/* Define how often we check on SNTP server status. */
#define CHECK_SNTP_UPDATES_TIMEOUT   (180 * NX_IP_PERIODIC_RATE)
#define EPOCH_TIME_DIFF              2208988800     /* is equivalent to 70 years in sec
                                                     calculated with www.epochconverter.com/date-difference */
#ifdef __cplusplus
extern "C" {
#endif

/**  * @brief  Initialize the SNTP client application
  * @param  byte_pool: pointer to a previously created byte pool
  * @note   Get the pointer form the application.
  * 		Call this function after the DNS client is created.
  * 		Call tx_thread_resume on the SNTP thread in the app_netxduo.c app_netx_thread_entry
  * @retval UINT status
  */
UINT app_sntp_init( void *byte_pool, NX_PACKET_POOL *packet_pool,
					NX_IP *ip_instance, NX_DNS *dns_client_ptr);
/**
 * @brief  Get the SNTP client thread instance.
 * @return TX_THREAD* Pointer to the SNTP client thread instance.
 * @note This is externed function to get the SNTP client thread instance.
 *       get the Thread this in the app_netx_thread after the dns is created.
 *       This is required to start the SNTP client thread after
 *       the network is initialized.
 */
TX_THREAD* get_sntp_client_thread_instance(void);

#ifdef __cplusplus
}
#endif



#endif /* APP_SNTP_INC_APP_SNTP_H_ */
