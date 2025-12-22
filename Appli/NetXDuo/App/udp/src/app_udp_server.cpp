/*
 * app_usp_server.cpp
 *
 *  Created on: Oct 24, 2025
 *      Author: alpl_
 */


#include <iostream>
#include <cstdint>
#include <cstring>
#include <array>
#include <functional>
#include <string>
/* Appication includes */
#include "app_udp_server.h"
#include "log_util.h"

/* UDP app */
TX_THREAD AppUDPThread;
//NX_UDP_SOCKET UDPSocket;
NX_UDP_SOCKET logging_socket;
NX_UDP_SOCKET canopen_socket;
static VOID App_UDP_Thread_Entry(ULONG thread_input);


/*****************************************************/

struct udp_server_info_t{
	NX_PACKET_POOL *packet_pool;
	NX_IP *ip_instance;
	TX_BYTE_POOL *byte_pool;
};
/*********Exported functions *************************/
/**
 * Exported function to get UDP server thread instance
 */
TX_THREAD* get_udp_server_thread_instance(void){
	return &AppUDPThread;
}

/**
 * @brief  Initialize the MQTT client application
 * @param  byte_pool: pointer to a previously created byte pool
 * @note   Get the pointer form the application
 * @
 */

uint16_t app_udp_server_init( void *byte_pool, NX_IP *ip_instance, NX_PACKET_POOL *packet_pool) {
	constexpr static const ULONG NX_UDP_APP_STACK_SIZE = 1024 * 2;
	constexpr static const UINT NX_UDP_APP_THREAD_PRIORITY = 22;
	static udp_server_info_t udp_server_info;
	CHAR *stack_ptr;
	if (byte_pool == TX_NULL || ip_instance == TX_NULL || packet_pool == TX_NULL) {
		std::cerr << LOG_LOC << "Error: Null pointer passed to app_udp_server_init" << std::endl;
		return NX_PTR_ERROR;
	}
	udp_server_info.ip_instance = ip_instance;
	udp_server_info.packet_pool = packet_pool;
	udp_server_info.byte_pool = static_cast<TX_BYTE_POOL *>(byte_pool);
	/* Allocate the memory for UDP client thread */
	if (tx_byte_allocate( static_cast<TX_BYTE_POOL *>(byte_pool),
						  static_cast<void **>(static_cast<void*>(&stack_ptr)),
						  NX_UDP_APP_STACK_SIZE, TX_NO_WAIT) != TX_SUCCESS){
		return TX_POOL_ERROR;
	}
	/* create the UDP client thread */
	uint16_t ret = tx_thread_create( &AppUDPThread,
							const_cast<CHAR *>("App UDP Thread"),
							App_UDP_Thread_Entry,
							reinterpret_cast<ULONG>(&udp_server_info),
							stack_ptr,
							NX_UDP_APP_STACK_SIZE,
							NX_UDP_APP_THREAD_PRIORITY,
							NX_UDP_APP_THREAD_PRIORITY,
							TX_NO_TIME_SLICE,
							TX_DONT_START);

	if (ret != TX_SUCCESS) {return NX_NOT_ENABLED;}

	std::cout << LOG_LOC << "Udp server application Initialized.." << std::endl;
	return ret;

}

/***************************************************************************
 * @ref UDP functions and threads
 */

static void send_udp_packets(
    NX_PACKET_POOL *packet_pool,
    NX_IP *ip_instance,
    NX_UDP_SOCKET *socket,
    ULONG client_ip,
    UINT client_port)
{
    UINT status;
    NX_PACKET *packet = nullptr;
    static const char *payload = "Periodic CANopen update";
    UINT payload_length = strlen(payload);

    if (client_ip == 0) {
        std::cerr << LOG_LOC << "Error: Invalid client IP (0.0.0.0)" << std::endl;
        return;
    }

    // Allocate packet from pool
    status = nx_packet_allocate(packet_pool, &packet, NX_UDP_PACKET, TX_NO_WAIT);
    if (status != NX_SUCCESS) {
        std::cerr << LOG_LOC << "Error: Failed to allocate packet, code: "
                  << status << std::endl;
        return;
    }

    // Append data to packet
    status = nx_packet_data_append(packet, (VOID*)payload, payload_length,
                                   packet_pool, TX_NO_WAIT);
    if (status != NX_SUCCESS) {
        std::cerr << LOG_LOC << "Error: Failed to append data to packet, code: "
                  << status << std::endl;
        nx_packet_release(packet);
        return;
    }

    // Create address structure for IPv4
    NXD_ADDRESS client_address;
    client_address.nxd_ip_version = NX_IP_VERSION_V4;
    client_address.nxd_ip_address.v4 = client_ip;

    // Send packet using NetX Duo API (supports both IPv4 and IPv6)
    status = nxd_udp_socket_send(socket, packet, &client_address, client_port);

    if (status != NX_SUCCESS) {
        std::cerr << LOG_LOC << "Error: Failed to send UDP packet, code: "
                  << status << std::endl;
        // Release packet only on failure; on success, NetX releases it
        nx_packet_release(packet);
    } else {
        std::cout << "Sent " << payload_length << " bytes to "
                  << ((client_ip >> 24) & 0xFF) << "."
                  << ((client_ip >> 16) & 0xFF) << "."
                  << ((client_ip >> 8) & 0xFF) << "."
                  << (client_ip & 0xFF) << ":" << client_port << std::endl;
    }
}



static VOID App_UDP_Thread_Entry(ULONG thread_input)
{
    UINT ret;
    NX_PACKET *data_packet;
    ULONG bytes_read;
    UCHAR data_buffer[DATA_BUFFER_SIZE];

    // Client tracking
    ULONG remote_ip = 0;
    UINT remote_port = 0;
    UINT protocol;
    UINT interface_index;
    ULONG last_packet_time = 0;

    // Extract server info from thread input
    udp_server_info_t *udp_server_info = reinterpret_cast<udp_server_info_t *>(thread_input);

    if (!udp_server_info) {
        std::cerr << LOG_LOC << "Error: Invalid UDP server info" << std::endl;
        return;
    }

    // ===== Create and bind logging socket =====
    ret = nx_udp_socket_create(
        udp_server_info->ip_instance,
        &logging_socket,
        const_cast<char *>("LoggingSocket"),
        NX_IP_NORMAL,
        NX_FRAGMENT_OKAY,
        NX_IP_TIME_TO_LIVE,
        QUEUE_MAX_SIZE
    );

    if (ret != NX_SUCCESS) {
        std::cerr << LOG_LOC << "Error: Failed to create logging socket, code: "
                  << ret << std::endl;
        tx_thread_suspend(tx_thread_identify());
        return;
    }

    ret = nx_udp_socket_bind(&logging_socket, LOGGING_PORT, TX_WAIT_FOREVER);
    if (ret != NX_SUCCESS) {
        std::cerr << LOG_LOC << "Error: Failed to bind logging socket to port "
                  << LOGGING_PORT << ", code: " << ret << std::endl;
        nx_udp_socket_delete(&logging_socket);
        tx_thread_suspend(tx_thread_identify());
        return;
    }

    // ===== Create and bind CANopen socket =====
    ret = nx_udp_socket_create(
        udp_server_info->ip_instance,
        &canopen_socket,
        const_cast<char *>("CANopenSocket"),
        NX_IP_NORMAL,
        NX_FRAGMENT_OKAY,
        NX_IP_TIME_TO_LIVE,
        QUEUE_MAX_SIZE
    );

    if (ret != NX_SUCCESS) {
        std::cerr << LOG_LOC << "Error: Failed to create CANopen socket, code: "
                  << ret << std::endl;
        nx_udp_socket_unbind(&logging_socket);
        nx_udp_socket_delete(&logging_socket);
        tx_thread_suspend(tx_thread_identify());
        return;
    }

    ret = nx_udp_socket_bind(&canopen_socket, CANOPEN_PORT, TX_WAIT_FOREVER);
    if (ret != NX_SUCCESS) {
        std::cerr << LOG_LOC << "Error: Failed to bind CANopen socket to port "
                  << CANOPEN_PORT << ", code: " << ret << std::endl;
        nx_udp_socket_delete(&canopen_socket);
        nx_udp_socket_unbind(&logging_socket);
        nx_udp_socket_delete(&logging_socket);
        tx_thread_suspend(tx_thread_identify());
        return;
    }

    std::cout << LOG_LOC << "UDP server initialized successfully" << std::endl;
    std::cout << LOG_LOC << "Listening on ports: "
              << LOGGING_PORT << " (logging), "
              << CANOPEN_PORT << " (CANopen)" << std::endl;

    // ===== Main server loop ===========================================
    while (true) {
        // ----- Handle logging port -----
        ret = nx_udp_socket_receive(&logging_socket, &data_packet, UDP_RECEIVE_TIMEOUT);
        if (ret == NX_SUCCESS) {
            // Retrieve packet data
            ret = nx_packet_data_retrieve(data_packet, data_buffer, &bytes_read);
            if (ret == NX_SUCCESS) {
                std::cout << LOG_LOC << "Received " << bytes_read
                          << " bytes on logging port" << std::endl;

                // Extract client address information
                ret = nx_udp_packet_info_extract(
                    data_packet,
                    &remote_ip,
                    &protocol,
                    &remote_port,
                    &interface_index
                );

                if (ret == NX_SUCCESS && remote_ip != 0) {
                    std::cout << LOG_LOC << "Client: "
                              << ((remote_ip >> 24) & 0xFF) << "."
                              << ((remote_ip >> 16) & 0xFF) << "."
                              << ((remote_ip >> 8) & 0xFF) << "."
                              << (remote_ip & 0xFF) << ":" << remote_port << std::endl;

                    // Update last packet timestamp
                    last_packet_time = tx_time_get();

                    // Process/log the received data here
                    // Example: parse commands, log data, etc.
                }
            }

            nx_packet_release(data_packet);
        }

        // ----- Handle CANopen port -----
        ret = nx_udp_socket_receive(&canopen_socket, &data_packet, UDP_RECEIVE_TIMEOUT);
        if (ret == NX_SUCCESS) {
            ret = nx_packet_data_retrieve(data_packet, data_buffer, &bytes_read);
            if (ret == NX_SUCCESS) {
                std::cout << LOG_LOC << "Received " << bytes_read
                          << " bytes on CANopen port" << std::endl;

                // Process CANopen data here
                // Example: parse CANopen protocol, handle requests, etc.
            }

            nx_packet_release(data_packet);
        }

        // ----- Send periodic data to connected client -----
        if (remote_ip != 0) {
            // Check for client timeout
            ULONG current_time = tx_time_get();
            if ((current_time - last_packet_time) > TX_TIMER_TICKS_PER_SECOND * (CLIENT_TIMEOUT_MS / 1000)) {
                std::cout << LOG_LOC << "Client timeout, stopping periodic sends" << std::endl;
                remote_ip = 0;
                remote_port = 0;
            } else {
                // Send periodic updates to client
                send_udp_packets(
                    udp_server_info->packet_pool,
                    udp_server_info->ip_instance,
                    &logging_socket,
                    remote_ip,
                    remote_port
                );
            }
        }

        // Sleep to control loop rate and allow other threads to run
        tx_thread_sleep(20);  // ~20ms at typical tick rate
    }

    // Cleanup (unreachable in current design, but good practice)
    nx_udp_socket_unbind(&logging_socket);
    nx_udp_socket_delete(&logging_socket);
    nx_udp_socket_unbind(&canopen_socket);
    nx_udp_socket_delete(&canopen_socket);
}

