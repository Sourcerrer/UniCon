/*
 * tcp_server.cpp
 *
 *  Created on: Oct 2, 2025
 *      Author: Neha-Anup
 */


/* * Include necessary header files */
#include "app_netxduo.h"
#include "nx_api.h"
#include "nx_tcp.h"

extern "C"
{
TX_THREAD 		AppTCPThread;

}
/* private variables for TCP server */
static TX_SEMAPHORE   	TCPSemaphore;
static NX_TCP_SOCKET 	TCPSocket;

/* TCP server thread function prototype */
static VOID App_TCP_Thread_Entry(ULONG thread_input);
/* TCP listen callback function prototype */
static VOID tcp_listen_callback(NX_TCP_SOCKET *socket_ptr, UINT port);

/*==========================================================*/

/**
 * @brief Init the TCP server
 */
UINT tcp_server_init(void *byte_pool)
{
  if (byte_pool == NULL){ return TX_PTR_ERROR; }


  UINT ret = NX_SUCCESS;
  /* Allocate the memory for TCP thread   */
  UCHAR *pointer = NULL;
  /***********************************/
  ret = tx_byte_allocate( static_cast<TX_BYTE_POOL *>(byte_pool), (VOID **) &pointer,
		  	  	  	  	  NX_APP_THREAD_STACK_SIZE, TX_NO_WAIT);
  if (ret != TX_SUCCESS)
  {
	return TX_POOL_ERROR;
  }

  /* Create the TCP server thread */
  /* Create the TCP thread */
  ret = tx_thread_create(&AppTCPThread, const_cast<CHAR *>("TCP Thread"),
		  	  	  	  	  App_TCP_Thread_Entry, reinterpret_cast<ULONG>(byte_pool),
						  pointer, TCP_THREAD_STACK_SIZE,
						 TCP_THREAD_PRIORITY, TCP_THREAD_PRIORITY,
						 TX_NO_TIME_SLICE, TX_DONT_START);

  if (ret != TX_SUCCESS)
  {
	return TX_THREAD_ERROR;
  }

  /* Create the semaphore used to notify a new client connection */
  ret = tx_semaphore_create(&TCPSemaphore, const_cast<CHAR *>("TCP Semaphore"), 0);
  if (ret != TX_SUCCESS)
  {
	  return TX_SEMAPHORE_ERROR;
  };
  return ret;
}

/**
* @brief  TCP listen call back
* @param socket_ptr: NX_TCP_SOCKET socket registered for the callback
* @param port: UINT  the port on which the socket is listening
* @retval none
*/
static VOID tcp_listen_callback(NX_TCP_SOCKET *socket_ptr, UINT port)
{
  tx_semaphore_put(&TCPSemaphore);
}

/**
* @brief  TCP server thread entry-
* @param thread_input: ULONG thread parameter
* @retval none
*/
static VOID App_TCP_Thread_Entry(ULONG thread_input)
{
	extern NX_IP NetXDuoEthIpInstance;

	/* get the NX byte pool to allocate the necessary memory for the
	 * */
	TX_BYTE_POOL *byte_pool = reinterpret_cast<TX_BYTE_POOL *>(thread_input);
	/* Allocate 4 kB memory from the byte pool when socket is connected */


  UINT ret;
  UCHAR data_buffer[512];

  ULONG source_ip_address;
  NX_PACKET *data_packet;

  UINT source_port;
  ULONG bytes_read;

  /* Create the TCP socket */
  ret = nx_tcp_socket_create( &NetXDuoEthIpInstance, &TCPSocket,
		  	  	  	  	  	  const_cast<CHAR *>("TCP Server Socket"), NX_IP_NORMAL,
							  NX_FRAGMENT_OKAY,
                              NX_IP_TIME_TO_LIVE, WINDOW_SIZE, NX_NULL, NX_NULL);
  if (ret != NX_SUCCESS)
  {
	  printf("nx_tcp_socket_create() failed: error 0x%08x", ret);
    Error_Handler();
  }

  /*
  * Listen to new client connections.
  * The TCP_listen_callback will release the 'Semaphore' when a new connection is available
  */
  ret = nx_tcp_server_socket_listen(&NetXDuoEthIpInstance, DEFAULT_PORT, &TCPSocket, MAX_TCP_CLIENTS, tcp_listen_callback);

  if (ret != NX_SUCCESS)
  {
	  printf("nx_tcp_server_socket_listen() failed: error 0x%08x", ret);
    Error_Handler();
  }
  else
  {
    printf("TCP Server listening on PORT %d ..\n", DEFAULT_PORT);
  }

  if(tx_semaphore_get(&TCPSemaphore, TX_WAIT_FOREVER) != TX_SUCCESS)
  {
	  printf("tx_semaphore_get() failed: error 0x%08x", ret);
    Error_Handler();
  }
  else
  {
    /* Accept the new client connection before starting data exchange */
    ret = nx_tcp_server_socket_accept(&TCPSocket, TX_WAIT_FOREVER);

    if (ret != NX_SUCCESS)
    {
    	printf("nx_tcp_server_socket_accept() failed: error 0x%08x", ret);
      Error_Handler();
    }
  }

  printf("TCP server connected to a client. Start receiving data..\n");
  while(1)
  {
    ULONG socket_state;

    TX_MEMSET(data_buffer, '\0', sizeof(data_buffer));

    /* Get the socket state */
    nx_tcp_socket_info_get(&TCPSocket, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &socket_state, NULL, NULL, NULL);

    /* If the connections is not established then accept new ones, otherwise start receiving data */
    if(socket_state != NX_TCP_ESTABLISHED)
    {
      ret = nx_tcp_server_socket_accept(&TCPSocket, NX_IP_PERIODIC_RATE);
    }

    if(ret == NX_SUCCESS)
    {
      /* Receive the TCP packet send by the client */
      ret = nx_tcp_socket_receive(&TCPSocket, &data_packet, NX_WAIT_FOREVER);

      if (ret == NX_SUCCESS)
      {
        HAL_GPIO_TogglePin(LED_GREEN_GPIO_Port, LED_GREEN_Pin);

        /* Get the client IP address and  port */
        nx_udp_source_extract(data_packet, &source_ip_address, &source_port);

        /* Retrieve the data sent by the client */
        nx_packet_data_retrieve(data_packet, data_buffer, &bytes_read);

        /* Print the received data */
        PRINT_DATA(source_ip_address, source_port, data_buffer);

        /* Immediately resend the same packet */
        ret =  nx_tcp_socket_send(&TCPSocket, data_packet, NX_IP_PERIODIC_RATE);

        if (ret == NX_SUCCESS)
        {
          HAL_GPIO_TogglePin(LED_GREEN_GPIO_Port, LED_GREEN_Pin);
        }
      }
      else
      {
        nx_tcp_socket_disconnect(&TCPSocket, NX_WAIT_FOREVER);
        nx_tcp_server_socket_unaccept(&TCPSocket);
        nx_tcp_server_socket_relisten(&NetXDuoEthIpInstance, DEFAULT_PORT, &TCPSocket);
      }
    }
    else
    {
      /*Toggle the green led to indicate the idle state */
      HAL_GPIO_TogglePin(LED_GREEN_GPIO_Port, LED_GREEN_Pin);
    }
  }
}
