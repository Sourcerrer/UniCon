/*
 * mqtt_util.c
 *
 *  Created on: Sep 10, 2025
 *      Author: alpl_
 */


#include "app_netxduo.h"
#include "nxd_mqtt_client.h"
#include <stdbool.h>
#include <stdio.h>

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
bool get_mqtt_broker_ip_address(NX_DNS *ptrDnsClient ,ULONG *ip_address){
	/* Get the mqtt addresses from the table */

	/* Look up MQTT Server address. */
	UINT ret;
	do{
		ret = nx_dns_host_by_name_get(ptrDnsClient, (UCHAR *)MQTT_BROKER_NAME,
				&ip_address, DEFAULT_TIMEOUT);
		if (ret != NX_SUCCESS)
		{
			printf("DNS look up failed, error: 0x%x. Retrying...\n", ret);
			tx_thread_sleep(DEFAULT_TIMEOUT);
		}
	}while(ret != NX_SUCCESS);

	printf("MQTT broker address: %lu.%lu.%lu.%lu\n",
			(*ip_address >> 24) & 0xff,
			(*ip_address >> 16) & 0xff,
			(*ip_address >> 8) & 0xff,
			(*ip_address) & 0xff);

	return true;

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
	va_list args;
	int len;

	/* Get the time */
	va_start(args, format);
	len = vsnprintf(data, max_len, format, args);
	va_end(args);

	if (len < 0 || (size_t)len >= max_len) {
		// Encoding error or output was truncated
		return false;
	}
	return true;
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
