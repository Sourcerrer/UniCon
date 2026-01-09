/*
 * public_ip.cpp
 *
 *  Created on: 07-Jan-2026
 *      Author: alpl_
 */

#include <stdio.h>
#include <string.h>
#include <string_view>
#include <cstring>
#include <cstdint>
#include <log_util.h>
#include "netx_util.h"

/* Buffer for the HTTP response */
#define HTTP_BUFFER_SIZE 512
UCHAR http_buffer[HTTP_BUFFER_SIZE];


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
static inline bool get_domain_name_ip(NX_DNS *ptrDnsClient ,ULONG *ip_address, std::string_view domain_name){
	/* Get the mqtt addresses from the table */
	std::uint16_t retries = 0;
	static const ULONG timeout = 10 * NX_IP_PERIODIC_RATE;
	/* Look up MQTT Server address. */
	if(ip_address == nullptr || ptrDnsClient == nullptr){
		return false;
	}
	UINT ret;
	do{
		ret = nx_dns_host_by_name_get(  ptrDnsClient, const_cast<UCHAR*>((UCHAR *)domain_name.data()),
										ip_address, timeout);
		if (ret != NX_SUCCESS)
		{
			printf("DNS look up failed, error: 0x%x. Retrying...\n", ret);
			tx_thread_sleep(timeout * 2);

		}
	}while(ret != NX_SUCCESS && retries++ < 5);
	if (ret != NX_SUCCESS){
		std::cerr << LOG_LOC << "DNS look up for "
				  << domain_name
				  << " failed, error: 0x"
				  << std::hex << ret << std::dec
				  << std::endl;
		return false;
	}
	std::cout << LOG_LOC << domain_name
			  << " IP address resolved successfully." << std::endl;
	return true;

}

static inline bool is_domain_reachable( NX_IP *NetXDuoEthIpInstance,
										ULONG ip_address, std::string_view domain_name){
	/* Ping the mqtt broker to check if it is reachable */
	UINT ret;
	std::uint16_t ping_retry = 0;
	NX_PACKET *ping_response;
	static const ULONG PING_TIMEOUT = (20 * NX_IP_PERIODIC_RATE);// 1s
	static const uint16_t PING_RETRIES = 3;


	/* Ping broker with retries */
	for (ping_retry = 0; ping_retry < PING_RETRIES; ping_retry++) {
		ret = nx_icmp_ping(NetXDuoEthIpInstance,ip_address,
				NULL, 0, &ping_response, PING_TIMEOUT);
		if (ret == NX_SUCCESS) {
			std::cout << LOG_LOC << "Ping to "
					  << domain_name
					  << " successful." << std::endl;
			nx_packet_release(ping_response);
			break;
		}
		std::cout << LOG_LOC
				  << "Ping attempt " << ping_retry + 1
				  << " to " << domain_name
				  << " failed, error: 0x"
				  << std::hex << ret << std::dec
				  << std::endl;
		if (ping_retry < PING_RETRIES - 1) {
			tx_thread_sleep(PING_TIMEOUT / 2);
		}
	}
	if (ret != NX_SUCCESS) {
		std::cout << LOG_LOC
				  << "Ping to " << domain_name
				  << " failed after " << PING_RETRIES
				  << " attempts, error: 0x"
				  << std::hex << ret << std::dec
				  << std::endl;
		return false;
	}

	return true;
}

bool Get_Public_IP(NX_IP *ip_ptr, NX_PACKET_POOL *pool_ptr, NX_DNS *dns_ptr)
{
    UINT status;
    NX_TCP_SOCKET socket;
    NXD_ADDRESS server_ip;
    NX_PACKET *request_packet;
    NX_PACKET *response_packet;
//    ULONG bytes_received;
    static const std::string_view domain_name {"api.ipify.org"};

    printf("Resolving api.ipify.org...\n");


    if(dns_ptr == NULL || ip_ptr == NULL || pool_ptr == NULL){
		return false;
	}
    /* 1. Resolve the Server IP */
    /* We use 'api.ipify.org' because it returns JUST the IP text */
    server_ip.nxd_ip_version = NX_IP_VERSION_V4;

    if( !get_domain_name_ip( dns_ptr,
    				    	&server_ip.nxd_ip_address.v4,
							domain_name ) ){
    	return false;
    }

    /* 3. Check if the domain is reachable */
	if( !is_domain_reachable( ip_ptr,
							  server_ip.nxd_ip_address.v4,
							  domain_name ) ){
		return false;
	}

    /* 2. Create a TCP Socket */
    status = nx_tcp_socket_create(ip_ptr, &socket, const_cast<CHAR *>("PublicIP_Socket"),
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY,
                                  NX_IP_TIME_TO_LIVE, 512,
                                  NX_NULL, NX_NULL);

    if (status != NX_SUCCESS) return false;

    /* 3. Bind to any local port */
    status = nx_tcp_client_socket_bind(&socket, NX_ANY_PORT, NX_WAIT_FOREVER);
    if (status != NX_SUCCESS)
    {
        nx_tcp_socket_delete(&socket);
        return false;
    }

    /* 4. Connect to the Server (Port 80) */
    printf("Connecting to Server...\n");
    status = nxd_tcp_client_socket_connect(&socket, &server_ip, 80, 2000); // 2 sec timeout

    if (status == NX_SUCCESS)
    {
        /* 5. Prepare the HTTP GET Request */
        /* Raw HTTP 1.1 Request */
        const char *http_request = "GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n";

        status = nx_packet_allocate(pool_ptr, &request_packet, NX_TCP_PACKET, NX_WAIT_FOREVER);
        if (status == NX_SUCCESS)
        {
            /* Append data to packet */
            nx_packet_data_append(request_packet, (VOID *)http_request, strlen(http_request), pool_ptr, NX_WAIT_FOREVER);

            /* Send it */
            printf("Sending Request...\n");
            nx_tcp_socket_send(&socket, request_packet, 200);
            // Note: Packet is released automatically by NetX after send
        }

        /* 6. Receive the Response */
        /* The server will send headers + body. The IP is in the body. */
        printf("Waiting for Response...\n");
        status = nx_tcp_socket_receive(&socket, &response_packet, 5000); // 5 sec wait

        if (status == NX_SUCCESS)
        {
            /* Extract data */
            ULONG length;
            UCHAR *buffer_ptr;

            /* Get pointer to the actual data in the packet */
            buffer_ptr = response_packet -> nx_packet_prepend_ptr;
            length = response_packet -> nx_packet_length;

            /* Ensure null termination for printing */
            if (length > HTTP_BUFFER_SIZE - 1) length = HTTP_BUFFER_SIZE - 1;
            memcpy(http_buffer, buffer_ptr, length);
            http_buffer[length] = '\0';

            printf("\n--- SERVER RESPONSE ---\n%s\n-----------------------\n", http_buffer);

            /* Parse simple check: The IP is at the end of the headers (after \r\n\r\n) */
            char *body_start = strstr((char *)http_buffer, "\r\n\r\n");
            if (body_start)
            {
                printf("MY PUBLIC IP: %s\n", body_start + 4);
            }

            nx_packet_release(response_packet);
        }
        else
        {
            printf("No Response Received.\n");
        }

        /* 7. Disconnect */
        nx_tcp_socket_disconnect(&socket, 200);
    }
    else
    {
        printf("Connection Failed: 0x%02X\n", status);
    }

    /* 8. Cleanup */
    nx_tcp_client_socket_unbind(&socket);
    nx_tcp_socket_delete(&socket);

    return (status == NX_SUCCESS);
}
