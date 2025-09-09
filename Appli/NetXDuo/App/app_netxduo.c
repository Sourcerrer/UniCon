/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file    app_netxduo.c
  * @author  MCD Application Team
  * @brief   NetXDuo applicative file
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2020-2021 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */

/* Includes ------------------------------------------------------------------*/
#include "app_netxduo.h"

/* Private includes ----------------------------------------------------------*/
#include "nxd_dhcp_client.h"
/* USER CODE BEGIN Includes */
#include   <stdbool.h>
#include   <inttypes.h>
#include   <time.h>

#include "nx_ip.h"
#include "nx_stm32_eth_config.h"
#include "msg.h"
#include  MOSQUITTO_CERT_FILE
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */
extern RNG_HandleTypeDef hrng;
TX_THREAD AppMQTTClientThread;
TX_THREAD AppSNTPThread;
TX_THREAD AppLinkThread;
NXD_MQTT_CLIENT MqttClient;
NX_SNTP_CLIENT  SntpClient;
static NX_DNS   DnsClient;
TX_EVENT_FLAGS_GROUP     SntpFlags;
ULONG   IpAddress;
ULONG   NetMask;
ULONG mqtt_client_stack[MQTT_CLIENT_STACK_SIZE];
TX_EVENT_FLAGS_GROUP mqtt_app_flag;
/* Declare buffers to hold message and topic. */
static char message[NXD_MQTT_MAX_MESSAGE_LENGTH];
static UCHAR message_buffer[NXD_MQTT_MAX_MESSAGE_LENGTH];
static UCHAR topic_buffer[NXD_MQTT_MAX_TOPIC_NAME_LENGTH];
/* TLS buffers and certificate containers. */
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;
/* calculated with nx_secure_tls_metadata_size_calculate */
static CHAR crypto_metadata_client[11600];
/* Define the TLS packet reassembly buffer. */
UCHAR tls_packet_buffer[4000];
ULONG current_time;

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
TX_THREAD      NxAppThread;
NX_PACKET_POOL NxAppPool;
NX_IP          NetXDuoEthIpInstance;
TX_SEMAPHORE   DHCPSemaphore;
NX_DHCP        DHCPClient;
/* USER CODE BEGIN PV */

TX_SEMAPHORE   TCPSemaphore;
TX_THREAD AppTCPThread;
TX_THREAD AppLinkThread;

ULONG IpAddress;
ULONG NetMask;

NX_DHCP DHCPClient;
NX_TCP_SOCKET TCPSocket;

/* SNTP client variables */
CHAR                     buffer[64];  // buffer to store the date and time string
struct tm timeInfos;
/* RTC handler declaration */
RTC_HandleTypeDef RtcHandle;

/* Set the SNTP network interface to the primary interface. */
UINT  iface_index =0;
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
static VOID nx_app_thread_entry (ULONG thread_input);
static VOID ip_address_change_notify_callback(NX_IP *ip_instance, VOID *ptr);
/* USER CODE BEGIN PFP */
/* TCP server */
static VOID App_TCP_Thread_Entry(ULONG thread_input);
static VOID tcp_listen_callback(NX_TCP_SOCKET *socket_ptr, UINT port);
/* SNTP client */
static UINT kiss_of_death_handler(NX_SNTP_CLIENT *client_ptr, UINT KOD_code);
static void display_rtc_time(RTC_HandleTypeDef *hrtc);
static void rtc_time_update(NX_SNTP_CLIENT *client_ptr);
/* MQTT client */
static VOID App_MQTT_Client_Thread_Entry(ULONG thread_input);
static VOID App_SNTP_Thread_Entry(ULONG thread_input);
static VOID App_Link_Thread_Entry(ULONG thread_input);
static VOID time_update_callback(NX_SNTP_TIME_MESSAGE *time_update_ptr, NX_SNTP_TIME *local_time);
static ULONG nx_secure_tls_session_time_function(void);
static UINT dns_create(NX_DNS *dns_ptr);
static UINT message_generate(void);
static UINT tls_setup_callback(NXD_MQTT_CLIENT *client_pt,
                        NX_SECURE_TLS_SESSION *TLS_session_ptr,
                        NX_SECURE_X509_CERT *certificate_ptr,
                        NX_SECURE_X509_CERT *trusted_certificate_ptr);
#if defined(__ICCARM__)
size_t __write(int file, unsigned char const *ptr, size_t len);
#endif /* __ICCARM__ */
/* USER CODE END PFP */

/**
  * @brief  Application NetXDuo Initialization.
  * @param memory_ptr: memory pointer
  * @retval int
  */
UINT MX_NetXDuo_Init(VOID *memory_ptr)
{
  UINT ret = NX_SUCCESS;
  TX_BYTE_POOL *byte_pool = (TX_BYTE_POOL*)memory_ptr;
  CHAR *pointer;

  /* USER CODE BEGIN MX_NetXDuo_MEM_POOL */
  /* USER CODE END MX_NetXDuo_MEM_POOL */

  /* USER CODE BEGIN 0 */
  printf( "*************************************************\r\n"
		     "Unicon Network Initialization..\n");
  /* USER CODE END 0 */

  /* Initialize the NetXDuo system. */
  nx_system_initialize();

    /* Allocate the memory for packet_pool.  */
  if (tx_byte_allocate(byte_pool, (VOID **) &pointer, NX_APP_PACKET_POOL_SIZE, TX_NO_WAIT) != TX_SUCCESS)
  {
    return TX_POOL_ERROR;
  }

  /* Create the Packet pool to be used for packet allocation,
   * If extra NX_PACKET are to be used the NX_APP_PACKET_POOL_SIZE should be increased
   */
  ret = nx_packet_pool_create(&NxAppPool, "NetXDuo App Pool", DEFAULT_PAYLOAD_SIZE, pointer, NX_APP_PACKET_POOL_SIZE);

  if (ret != NX_SUCCESS)
  {
    return NX_POOL_ERROR;
  }

    /* Allocate the memory for Ip_Instance */
  if (tx_byte_allocate(byte_pool, (VOID **) &pointer, Nx_IP_INSTANCE_THREAD_SIZE, TX_NO_WAIT) != TX_SUCCESS)
  {
    return TX_POOL_ERROR;
  }

   /* Create the main NX_IP instance */
  ret = nx_ip_create(&NetXDuoEthIpInstance, "NetX Ip instance", NX_APP_DEFAULT_IP_ADDRESS, NX_APP_DEFAULT_NET_MASK, &NxAppPool, nx_stm32_eth_driver,
                     pointer, Nx_IP_INSTANCE_THREAD_SIZE, NX_APP_INSTANCE_PRIORITY);

  if (ret != NX_SUCCESS)
  {
    return NX_NOT_SUCCESSFUL;
  }

    /* Allocate the memory for ARP */
  if (tx_byte_allocate(byte_pool, (VOID **) &pointer, DEFAULT_ARP_CACHE_SIZE, TX_NO_WAIT) != TX_SUCCESS)
  {
    return TX_POOL_ERROR;
  }

  /* Enable the ARP protocol and provide the ARP cache size for the IP instance */

  /* USER CODE BEGIN ARP_Protocol_Initialization */

  /* USER CODE END ARP_Protocol_Initialization */

  ret = nx_arp_enable(&NetXDuoEthIpInstance, (VOID *)pointer, DEFAULT_ARP_CACHE_SIZE);

  if (ret != NX_SUCCESS)
  {
    return NX_NOT_SUCCESSFUL;
  }

  /* Enable the ICMP */

  /* USER CODE BEGIN ICMP_Protocol_Initialization */

  /* USER CODE END ICMP_Protocol_Initialization */

  ret = nx_icmp_enable(&NetXDuoEthIpInstance);

  if (ret != NX_SUCCESS)
  {
    return NX_NOT_SUCCESSFUL;
  }

  /* Enable TCP Protocol */

  /* USER CODE BEGIN TCP_Protocol_Initialization */
  /* Allocate the memory for TCP server thread   */
  if (tx_byte_allocate(byte_pool, (VOID **) &pointer, TCP_THREAD_STACK_SIZE, TX_NO_WAIT) != TX_SUCCESS)
  {
    return TX_POOL_ERROR;
  }

  /* Create the TCP server thread */
  ret = tx_thread_create( &AppTCPThread, "App TCP Thread", App_TCP_Thread_Entry,
		  	  	  	  	  0, pointer, TCP_THREAD_STACK_SIZE,
						  TCP_THREAD_PRIORITY, TCP_THREAD_PRIORITY,
						  TX_NO_TIME_SLICE, TX_DONT_START);

  if (ret != TX_SUCCESS)
  {
    return NX_NOT_SUCCESSFUL;
  }
  /* USER CODE END TCP_Protocol_Initialization */

  ret = nx_tcp_enable(&NetXDuoEthIpInstance);

  if (ret != NX_SUCCESS)
  {
    return NX_NOT_SUCCESSFUL;
  }

  /* Enable the UDP protocol required for  DHCP communication */

  /* USER CODE BEGIN UDP_Protocol_Initialization */

  /* USER CODE END UDP_Protocol_Initialization */

  ret = nx_udp_enable(&NetXDuoEthIpInstance);

  if (ret != NX_SUCCESS)
  {
    return NX_NOT_SUCCESSFUL;
  }

   /* Allocate the memory for main thread   */
  if (tx_byte_allocate(byte_pool, (VOID **) &pointer, NX_APP_THREAD_STACK_SIZE, TX_NO_WAIT) != TX_SUCCESS)
  {
    return TX_POOL_ERROR;
  }

  /* Create the main thread */
  ret = tx_thread_create(&NxAppThread, "NetXDuo App thread", nx_app_thread_entry , 0, pointer, NX_APP_THREAD_STACK_SIZE,
                         NX_APP_THREAD_PRIORITY, NX_APP_THREAD_PRIORITY, TX_NO_TIME_SLICE, TX_AUTO_START);

  if (ret != TX_SUCCESS)
  {
    return TX_THREAD_ERROR;
  }

  /* Create the DHCP client */

  /* USER CODE BEGIN DHCP_Protocol_Initialization */

  /* USER CODE END DHCP_Protocol_Initialization */

  ret = nx_dhcp_create(&DHCPClient, &NetXDuoEthIpInstance, "DHCP Client");

  if (ret != NX_SUCCESS)
  {
    return NX_DHCP_ERROR;
  }

  /* set DHCP notification callback  */
  tx_semaphore_create(&DHCPSemaphore, "DHCP Semaphore", 0);

  /* USER CODE BEGIN MX_NetXDuo_Init */
  /* Set DHCP notification callback  */
  tx_semaphore_create(&TCPSemaphore, "TCP Semaphore", 0);

  printf("Nx_MQTT_Client application started..\n");

  /* Allocate the memory for SNTP client thread */
  if (tx_byte_allocate(byte_pool, (VOID **) &pointer, SNTP_CLIENT_THREAD_MEMORY, TX_NO_WAIT) != TX_SUCCESS)
  {
    return TX_POOL_ERROR;
  }

  /* create the SNTP client thread */
  ret = tx_thread_create(&AppSNTPThread, "App SNTP Thread", App_SNTP_Thread_Entry, 0, pointer, SNTP_CLIENT_THREAD_MEMORY,
                         SNTP_PRIORITY, SNTP_PRIORITY, TX_NO_TIME_SLICE, TX_DONT_START);

  if (ret != TX_SUCCESS)
  {
    return TX_THREAD_ERROR;
  }

  /* Create the event flags. */
  ret = tx_event_flags_create(&SntpFlags, "SNTP event flags");

  /* Check for errors */
  if (ret != NX_SUCCESS)
  {
    return NX_NOT_ENABLED;
  }

  /* Allocate the memory for MQTT client thread */
  if (tx_byte_allocate(byte_pool, (VOID **) &pointer, MQTT_THREAD_STACK_SIZE, TX_NO_WAIT) != TX_SUCCESS)
  {
    return TX_POOL_ERROR;
  }

  /* create the MQTT client thread */
  ret = tx_thread_create( &AppMQTTClientThread, "App MQTT Thread",
		  	  	  	  	  App_MQTT_Client_Thread_Entry, 0, pointer,
						  MQTT_THREAD_STACK_SIZE, MQTT_PRIORITY,
						  MQTT_PRIORITY, TX_NO_TIME_SLICE, TX_DONT_START);

  if (ret != TX_SUCCESS)
  {
    return TX_THREAD_ERROR;
  }

  /* Allocate the memory for Link thread   */
  if (tx_byte_allocate(byte_pool, (VOID **) &pointer,LINK_STACK, TX_NO_WAIT) != TX_SUCCESS)
  {
    return TX_POOL_ERROR;
  }

  /* Create the Link thread */
  ret = tx_thread_create( &AppLinkThread, "App Link Thread", App_Link_Thread_Entry,
		  	  	  	  	  0, pointer, LINK_STACK,
                          LINK_PRIORITY, LINK_PRIORITY,
						  TX_NO_TIME_SLICE, TX_AUTO_START);

  if (ret != TX_SUCCESS)
  {
    return NX_NOT_ENABLED;
  }

  /* USER CODE END MX_NetXDuo_Init */

  return ret;
}

/**
* @brief  ip address change callback.
* @param ip_instance: NX_IP instance
* @param ptr: user data
* @retval none
*/
static VOID ip_address_change_notify_callback(NX_IP *ip_instance, VOID *ptr)
{
  /* USER CODE BEGIN ip_address_change_notify_callback */
  /* Release the semaphore as soon as an IP address is available */
  if (nx_ip_address_get(&NetXDuoEthIpInstance, &IpAddress, &NetMask) != NX_SUCCESS)
  {
    /* USER CODE BEGIN IP address change callback error */
	  printf("nx_ip_address_get() failed: error 0x%08x", NX_NOT_SUCCESSFUL);
    Error_Handler();
    /* USER CODE END IP address change callback error */
  }
  if(IpAddress != NULL_ADDRESS)
  {
    tx_semaphore_put(&DHCPSemaphore);
  }
  /* USER CODE END ip_address_change_notify_callback */
}

/**
* @brief  Main thread entry.
* @param thread_input: ULONG user argument used by the thread entry
* @retval none
*/
static VOID nx_app_thread_entry (ULONG thread_input)
{
  /* USER CODE BEGIN Nx_App_Thread_Entry 0 */

  /* USER CODE END Nx_App_Thread_Entry 0 */

  UINT ret = NX_SUCCESS;

  /* USER CODE BEGIN Nx_App_Thread_Entry 1 */

  /* USER CODE END Nx_App_Thread_Entry 1 */

  /* register the IP address change callback */
  ret = nx_ip_address_change_notify(&NetXDuoEthIpInstance, ip_address_change_notify_callback, NULL);
  if (ret != NX_SUCCESS)
  {
    /* USER CODE BEGIN IP address change callback error */
	  printf("nx_ip_address_change_notify() failed: error 0x%08x", ret);
    Error_Handler();
    /* USER CODE END IP address change callback error */
  }

  /* start the DHCP client */
  ret = nx_dhcp_start(&DHCPClient);
  if (ret != NX_SUCCESS)
  {
    /* USER CODE BEGIN DHCP client start error */
	  printf("nx_dhcp_start() failed: error 0x%08x", ret);
    Error_Handler();
    /* USER CODE END DHCP client start error */
  }
  printf("Looking for DHCP server ..\n");
  /* wait until an IP address is ready */
  if(tx_semaphore_get(&DHCPSemaphore, TX_WAIT_FOREVER) != TX_SUCCESS)
  {
    /* USER CODE BEGIN DHCPSemaphore get error */
	  printf("tx_semaphore_get() failed: error 0x%08x", NX_NOT_SUCCESSFUL);
    Error_Handler();
    /* USER CODE END DHCPSemaphore get error */
  }

  /* USER CODE BEGIN Nx_App_Thread_Entry 2 */
  PRINT_IP_ADDRESS(IpAddress);

  /* The network is correctly initialized, start the TCP server thread */
  tx_thread_resume(&AppTCPThread);
  
    /* Start the SNTP client thread */
  tx_thread_resume(&AppSNTPThread);

  /* If this thread is not needed any more, we relinquish it */
  tx_thread_relinquish();

  return;
  /* USER CODE END Nx_App_Thread_Entry 2 */

}
/* USER CODE BEGIN 1 */
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
  * @brief  DNS Create Function.
  * @param dns_ptr
  * @retval ret
  */

UINT dns_create(NX_DNS *dns_ptr)
{
  UINT ret = NX_SUCCESS;

  /* Create a DNS instance for the Client */
  ret = nx_dns_create(dns_ptr, &NetXDuoEthIpInstance, (UCHAR *)"DNS Client");
  if (ret != NX_SUCCESS)
  {
	printf("nx_dns_create() failed: error 0x%08x\r\n", ret);
    Error_Handler();
  }
  /* Initialize DNS instance with a dummy server */
  ret = nx_dns_server_add(dns_ptr, USER_DNS_ADDRESS);
  if (ret != NX_SUCCESS)
  {
	  printf("nx_dns_server_add() failed: error 0x%08x\r\n", ret);
    Error_Handler();
  }

  return ret;
}

/* Declare the disconnect notify function. */
static VOID my_disconnect_func(NXD_MQTT_CLIENT *client_ptr)
{
  NX_PARAMETER_NOT_USED(client_ptr);
  printf("client disconnected from broker < %s >.\n", MQTT_BROKER_NAME);
}

/* Declare the notify function. */
static VOID my_notify_func(NXD_MQTT_CLIENT* client_ptr, UINT number_of_messages)
{
  NX_PARAMETER_NOT_USED(client_ptr);
  NX_PARAMETER_NOT_USED(number_of_messages);
  tx_event_flags_set(&mqtt_app_flag, DEMO_MESSAGE_EVENT, TX_OR);
  return;
}

/**
* @brief  TCP server thread entry
* @param thread_input: ULONG thread parameter
* @retval none
*/
static VOID App_TCP_Thread_Entry(ULONG thread_input)
{
  UINT ret;
  UCHAR data_buffer[512];

  ULONG source_ip_address;
  NX_PACKET *data_packet;

  UINT source_port;
  ULONG bytes_read;

  /* Create the TCP socket */
  ret = nx_tcp_socket_create(&NetXDuoEthIpInstance, &TCPSocket, "TCP Server Socket", NX_IP_NORMAL, NX_FRAGMENT_OKAY,
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

/**
* @brief  Link thread entry
* @param thread_input: ULONG thread parameter
* @retval none
*/
static VOID App_Link_Thread_Entry(ULONG thread_input)
{
  ULONG actual_status;
  UINT linkdown = 0, status;

  while(1)
  {
    /* Send request to check if the Ethernet cable is connected. */
    status = nx_ip_interface_status_check(&NetXDuoEthIpInstance, 0, NX_IP_LINK_ENABLED,
                                      &actual_status, 10);

    if(status == NX_SUCCESS)
    {
      if(linkdown == 1)
      {
        linkdown = 0;

        /* The network cable is connected. */
        printf("The network cable is connected.\n");

        /* Send request to enable PHY Link. */
        nx_ip_driver_direct_command(&NetXDuoEthIpInstance, NX_LINK_ENABLE,
                                      &actual_status);

        /* Send request to check if an address is resolved. */
        status = nx_ip_interface_status_check(&NetXDuoEthIpInstance, 0, NX_IP_ADDRESS_RESOLVED,
                                      &actual_status, 10);
        if(status == NX_SUCCESS)
        {
          /* Stop DHCP */
          nx_dhcp_stop(&DHCPClient);

          /* Reinitialize DHCP */
          nx_dhcp_reinitialize(&DHCPClient);

          /* Start DHCP */
          nx_dhcp_start(&DHCPClient);

          /* Wait until an IP address is ready */
          if(tx_semaphore_get(&DHCPSemaphore, TX_WAIT_FOREVER) != TX_SUCCESS)
          {
            /* USER CODE BEGIN DHCPSemaphore get error */
        	  printf("tx_semaphore_get() failed: error 0x%08x", NX_NOT_SUCCESSFUL);
            Error_Handler();
            /* USER CODE END DHCPSemaphore get error */
          }

          PRINT_IP_ADDRESS(IpAddress);
        }
        else
        {
          /* Set the DHCP Client's remaining lease time to 0 seconds to trigger an immediate renewal request for a DHCP address. */
          nx_dhcp_client_update_time_remaining(&DHCPClient, 0);
        }
      }
    }
    else
    {
      if(0 == linkdown)
      {
        linkdown = 1;
        /* The network cable is not connected. */
        printf("The network cable is not connected.\n");
        nx_ip_driver_direct_command(&NetXDuoEthIpInstance, NX_LINK_DISABLE,
                                      &actual_status);
      }
    }

    tx_thread_sleep(NX_APP_CABLE_CONNECTION_CHECK_PERIOD);
  }
}

/**
  * @brief  message generation Function.
  * @param  RandomNbr
  * @retval none
  */
static UINT message_generate(void)
{
  uint32_t RandomNbr = 0;

  HAL_RNG_Init(&hrng);

  /* Generate a random number */
  if(HAL_RNG_GenerateRandomNumber(&hrng, &RandomNbr) != HAL_OK)
  {
	  printf("HAL_RNG_GenerateRandomNumber() failed");
    Error_Handler();
  }

  return RandomNbr %= 50;
}

/* Function (set by user) to call when TLS needs the current time. */
ULONG nx_secure_tls_session_time_function(void)
{
  return (current_time);
}

/* Callback to setup TLS parameters for secure MQTT connection. */
UINT tls_setup_callback(NXD_MQTT_CLIENT *client_pt,
                        NX_SECURE_TLS_SESSION *TLS_session_ptr,
                        NX_SECURE_X509_CERT *certificate_ptr,
                        NX_SECURE_X509_CERT *trusted_certificate_ptr)
{
  UINT ret = NX_SUCCESS;
  NX_PARAMETER_NOT_USED(client_pt);

  /* Initialize TLS module */
  nx_secure_tls_initialize();

  /* Create a TLS session */
  ret = nx_secure_tls_session_create(TLS_session_ptr, &nx_crypto_tls_ciphers,
                                     crypto_metadata_client, sizeof(crypto_metadata_client));
  if (ret != NX_SUCCESS)
  {
	  printf("nx_secure_tls_session_create() failed: error 0x%08x", ret);
    Error_Handler();
  }

  /* Need to allocate space for the certificate coming in from the broker. */
  memset((certificate_ptr), 0, sizeof(NX_SECURE_X509_CERT));

    ret = nx_secure_tls_session_time_function_set(TLS_session_ptr, nx_secure_tls_session_time_function);

  if (ret != NX_SUCCESS)
  {
	  printf("nx_secure_tls_session_time_function_set() failed: error 0x%08x", ret);
    Error_Handler();
  }

  /* Allocate space for packet reassembly. */
  ret = nx_secure_tls_session_packet_buffer_set(TLS_session_ptr, tls_packet_buffer,
                                                sizeof(tls_packet_buffer));
  if (ret != NX_SUCCESS)
  {
	  printf("nx_secure_tls_session_packet_buffer_set() failed: error 0x%08x", ret);
    Error_Handler();
  }

  /* Allocate space for the certificate coming in from the remote host */
  ret = nx_secure_tls_remote_certificate_allocate(TLS_session_ptr, certificate_ptr,
                                                  tls_packet_buffer, sizeof(tls_packet_buffer));
  if (ret != NX_SUCCESS)
  {
	  printf("nx_secure_tls_remote_certificate_allocate() failed: error 0x%08x", ret);
    Error_Handler();
  }

  /* Initialize Certificate to verify incoming server certificates. */
  ret = nx_secure_x509_certificate_initialize(trusted_certificate_ptr, (UCHAR*)mosquitto_org_der,
                                              mosquitto_org_der_len, NX_NULL, 0, NULL, 0,
                                              NX_SECURE_X509_KEY_TYPE_NONE);
  if (ret != NX_SUCCESS)
  {
    printf("Certificate issue..\nPlease make sure that your X509_certificate is valid. \n");
    Error_Handler();
  }

  /* Add a CA Certificate to our trusted store */
  ret = nx_secure_tls_trusted_certificate_add(TLS_session_ptr, trusted_certificate_ptr);
  if (ret != TX_SUCCESS)
  {
	  printf("nx_secure_tls_trusted_certificate_add() failed: error 0x%08x", ret);
    Error_Handler();
  }

  return ret;
}

///* This callback defined handler for notifying SNTP time update event. */
//static VOID time_update_callback(NX_SNTP_TIME_MESSAGE *time_update_ptr, NX_SNTP_TIME *local_time)
//{
//  NX_PARAMETER_NOT_USED(time_update_ptr);
//  NX_PARAMETER_NOT_USED(local_time);
//
//  tx_event_flags_set(&SntpFlags, SNTP_UPDATE_EVENT, TX_OR);
//}

/*==============================================================================
  SNTP Client thread entry
  ==============================================================================*/
/**
  * @brief  SNTP thread entry.
  * @param thread_input: ULONG user argument used by the thread entry
  * @retval none
  */
/* Define the client thread. */
static void App_SNTP_Thread_Entry(ULONG info)
{
  UINT ret;
  RtcHandle.Instance = RTC;
  ULONG  seconds, fraction;
  ULONG  events = 0;
  UINT   server_status;
  NXD_ADDRESS sntp_server_ip;
  NX_PARAMETER_NOT_USED(info);
  const static ULONG WaitTime = 100;
  const static ULONG WaitTime_long = 2000;
  sntp_server_ip.nxd_ip_version = 4;
  UINT old_threshold;
//  tx_thread_sleep ( WaitTime_long);
//  tx_thread_preemption_change(&AppSNTPThread, 0, &old_threshold );

  /* Create a DNS client */
  do{
	  ret = dns_create(&DnsClient);
	  tx_thread_sleep(WaitTime);
  }while(ret != NX_SUCCESS);
  printf("dns created\r\n");


  /* Look up SNTP Server address.
   * TODO add a lookup table to get the servers address */
  do{
	  ret = nx_dns_host_by_name_get(&DnsClient, (UCHAR *)SNTP_SERVER_NAME_1,
	                                  &sntp_server_ip.nxd_ip_address.v4, NX_APP_DEFAULT_TIMEOUT);
	  tx_thread_sleep(WaitTime);
  }while(ret != NX_SUCCESS);
  printf("dns host got\r\n");

  /* Create the SNTP Client */
  do{
	  ret =  nx_sntp_client_create(	&SntpClient,
			  	  	  	  	  	  	  &NetXDuoEthIpInstance,
									  iface_index, &NxAppPool, NULL, kiss_of_death_handler, NULL);
	  tx_thread_sleep(WaitTime);
  }while(ret != NX_SUCCESS);
  printf("SNTP client created\r\n");

  /* Setup time update callback function. */
   nx_sntp_client_set_time_update_notify(&SntpClient, time_update_callback);

  /* Use the IPv4 service to set up the Client and set the IPv4 SNTP server. */
   do{
	   ret = nx_sntp_client_initialize_unicast(&SntpClient, sntp_server_ip.nxd_ip_address.v4);
	   tx_thread_sleep(WaitTime);
   }while(ret != NX_SUCCESS);
   printf("SNTP client intialized unicast\r\n");

  /* Run whichever service the client is configured for. */
   do{
	   ret = nx_sntp_client_run_unicast(&SntpClient);
	   tx_thread_sleep(WaitTime);
   }while(ret != NX_SUCCESS);
   printf("SNTP client run unicast\r\n");

   PRINT_CNX_SUCC();
//   tx_thread_preemption_change(&AppSNTPThread, old_threshold, &old_threshold );
  /* Wait for a server update event. */
   do{
	   tx_event_flags_get(&SntpFlags, SNTP_UPDATE_EVENT, TX_OR_CLEAR, &events, PERIODIC_CHECK_INTERVAL);
	   if( (  (events & SNTP_UPDATE_EVENT) != SNTP_UPDATE_EVENT  )  ){
		   /* We can stop the SNTP service if for example we think the SNTP server has stopped sending updates */
		   do{
		 	  ret = nx_sntp_client_stop(&SntpClient);
		 	  tx_thread_sleep(WaitTime);
		   }while(ret != NX_SUCCESS);
		   printf("SNTP client stopped\r\n");
		   do{
		 	  ret = nx_dns_host_by_name_get(&DnsClient, (UCHAR *)SNTP_SERVER_NAME,
		 	                                  &sntp_server_ip.nxd_ip_address.v4, NX_APP_DEFAULT_TIMEOUT);
		 	  tx_thread_sleep(WaitTime);
		   }while(ret != NX_SUCCESS);

		   nx_sntp_client_set_time_update_notify(&SntpClient, time_update_callback);
		   ret = nx_sntp_client_initialize_unicast(&SntpClient, sntp_server_ip.nxd_ip_address.v4);
		   tx_thread_sleep(WaitTime);
		   ret = nx_sntp_client_run_unicast(&SntpClient);
		   tx_thread_sleep(WaitTime);
		   PRINT_CNX_SUCC_1();
	   }

//	   tx_thread_sleep(WaitTime * 2);
   }while( (  (events & SNTP_UPDATE_EVENT) != SNTP_UPDATE_EVENT  ) );
   printf("SNTP Event Update\r\n");
    /* Check for valid SNTP server status. */
	  do{
		  ret = nx_sntp_client_receiving_updates(&SntpClient, &server_status);
		  tx_thread_sleep(WaitTime);
	  }while((ret != NX_SUCCESS) || (server_status == NX_FALSE));
	  printf("SNTP client receiving updates\r\n");
    /* We have a valid update.  Get the SNTP Client time. */
    ret = nx_sntp_client_get_local_time_extended(&SntpClient, &seconds, &fraction, NX_NULL, 0);
    printf("SNTP Secconds = %lu \r\n", seconds + 19800 );
    do{
        ret = nx_sntp_client_utility_display_date_time(&SntpClient,buffer,64);
        tx_thread_sleep(WaitTime);

    }while(ret != NX_SUCCESS);

    printf("\nSNTP update :\n");
    printf("%s\n\n",buffer);

  /* Set Current time from SNTP TO RTC */
  rtc_time_update(&SntpClient);
  /* We can stop the SNTP service if for example we think the SNTP server has stopped sending updates */
  do{
	  ret = nx_sntp_client_stop(&SntpClient);
	  tx_thread_sleep(WaitTime);
  }while(ret != NX_SUCCESS);
  printf("SNTP client stopped\r\n");


  /* When done with the SNTP Client, we delete it */
  do{
	  ret = nx_sntp_client_delete(&SntpClient);
	  tx_thread_sleep(WaitTime);
  }while( (ret != NX_SUCCESS) );
  printf("SNTP client deleted\r\n");
  /* Display RTC time each second */
  display_rtc_time(&RtcHandle);

  /* start the MQTT client thread */
  tx_thread_resume(&AppMQTTClientThread);
  /* Toggling LED after a success Time update */
  while(1)
  {
    tx_event_flags_set(&SntpFlags, SNTP_RTC_UPDATE_EVENT, TX_OR);

//    HAL_GPIO_TogglePin(LED1_GPIO_Port, LED1_Pin);
    /* Delay for 1s */
    tx_thread_sleep(5000);
  }
}
/* This application defined handler for handling a Kiss of Death packet is not
required by the SNTP Client. A KOD handler should determine
if the Client task should continue vs. abort sending/receiving time data
from its current time server, and if aborting if it should remove
the server from its active server list.

Note that the KOD list of codes is subject to change. The list
below is current at the time of this software release. */

static UINT kiss_of_death_handler(NX_SNTP_CLIENT *client_ptr, UINT KOD_code)
{
  UINT    remove_server_from_list = NX_FALSE;
  UINT    status = NX_SUCCESS;

  NX_PARAMETER_NOT_USED(client_ptr);

  /* Handle kiss of death by code group. */
  switch (KOD_code)
  {

  case NX_SNTP_KOD_RATE:
  case NX_SNTP_KOD_NOT_INIT:
  case NX_SNTP_KOD_STEP:

    /* Find another server while this one is temporarily out of service. */
    status =  NX_SNTP_KOD_SERVER_NOT_AVAILABLE;

    break;

  case NX_SNTP_KOD_AUTH_FAIL:
  case NX_SNTP_KOD_NO_KEY:
  case NX_SNTP_KOD_CRYP_FAIL:

    /* These indicate the server will not service client with time updates
    without successful authentication. */

    remove_server_from_list =  NX_TRUE;

    break;


  default:

    /* All other codes. Remove server before resuming time updates. */

    remove_server_from_list =  NX_TRUE;
    break;
  }

  /* Removing the server from the active server list? */
  if (remove_server_from_list)
  {

    /* Let the caller know it has to bail on this server before resuming service. */
    status = NX_SNTP_KOD_REMOVE_SERVER;
  }

  return status;
}
/* This application defined handler for notifying SNTP time update event. */
static VOID time_update_callback(NX_SNTP_TIME_MESSAGE *time_update_ptr, NX_SNTP_TIME *local_time)
{
  NX_PARAMETER_NOT_USED(time_update_ptr);
  NX_PARAMETER_NOT_USED(local_time);

  tx_event_flags_set(&SntpFlags, SNTP_UPDATE_EVENT, TX_OR);
}
/* This application updates Time from SNTP to STM32 RTC */
static void rtc_time_update(NX_SNTP_CLIENT *client_ptr)
{
  RTC_DateTypeDef sdatestructure ={0};
  RTC_TimeTypeDef stimestructure ={0};
  struct tm ts;
  CHAR  temp[32] = {0};
  const static ULONG UTC_to_IST = 19800; /* UTC to IST offset in seconds */

  /* Convert SNTP time (seconds since 01-01-1900 to 01-01-1970)

  EPOCH_TIME_DIFF is equivalent to 70 years in sec
  calculated with www.epochconverter.com/date-difference
  This constant is used to delete difference between :
  Epoch converter (referenced to 1970) and SNTP (referenced to 1900) */
  time_t timestamp = client_ptr->nx_sntp_current_server_time_message.receive_time.seconds
		             - EPOCH_TIME_DIFF + UTC_to_IST;

  /* Convert time in yy/mm/dd hh:mm:sec */
  ts = *localtime(&timestamp);

  /* Convert date composants to hex format */
  sprintf(temp, "%d", (ts.tm_year - 100));
  sdatestructure.Year = strtol(temp, NULL, 16);
  sprintf(temp, "%d", ts.tm_mon + 1);
  sdatestructure.Month = strtol(temp, NULL, 16);
  sprintf(temp, "%d", ts.tm_mday);
  sdatestructure.Date = strtol(temp, NULL, 16);
  /* Dummy weekday */
  sdatestructure.WeekDay =0x00;

  if (HAL_RTC_SetDate(&RtcHandle, &sdatestructure, RTC_FORMAT_BCD) != HAL_OK)
  {
	printf("RTC Set Date Error\r\n");
    Error_Handler();
  }
  /* Convert time composants to hex format */
  sprintf(temp,"%d", ts.tm_hour);
  stimestructure.Hours = strtol(temp, NULL, 16);
  sprintf(temp,"%d", ts.tm_min);
  stimestructure.Minutes = strtol(temp, NULL, 16);
  sprintf(temp, "%d", ts.tm_sec);
  stimestructure.Seconds = strtol(temp, NULL, 16);

  if (HAL_RTC_SetTime(&RtcHandle, &stimestructure, RTC_FORMAT_BCD) != HAL_OK)
  {
	  printf("RTC Set Time Error\r\n");
    Error_Handler();
  }

}

/* This application displays time from RTC */
static void display_rtc_time(RTC_HandleTypeDef *hrtc)
{
  RTC_TimeTypeDef RTC_Time = {0};
  RTC_DateTypeDef RTC_Date = {0};

  HAL_RTC_GetTime(&RtcHandle,&RTC_Time,RTC_FORMAT_BCD);
  HAL_RTC_GetDate(&RtcHandle,&RTC_Date,RTC_FORMAT_BCD);

  printf("%02x-%02x-20%02x / %02x:%02x:%02x\n",\
        RTC_Date.Date, RTC_Date.Month, RTC_Date.Year,RTC_Time.Hours,RTC_Time.Minutes,RTC_Time.Seconds);
}

static inline uint8_t BCD_To_Decimal(uint8_t bcd) {
    return ((bcd >> 4) * 10) + (bcd & 0x0F);
}
bool update_date_from_rtc(uint16_t *Day, uint16_t *Month, uint16_t *Year){
	  RTC_TimeTypeDef RTC_Time = {0};
	  RTC_DateTypeDef RTC_Date = {0};
	  ULONG  events = 0;
	  UINT status = tx_event_flags_get(&SntpFlags, SNTP_RTC_UPDATE_EVENT, TX_OR, &events, PERIODIC_CHECK_INTERVAL);
	  if(status != TX_SUCCESS){ return false; }
	  /* TODO Check if the RTC value has been updated and RTC is correct else  return false */
	  HAL_RTC_GetTime(&RtcHandle,&RTC_Time,RTC_FORMAT_BCD);
	  HAL_RTC_GetDate(&RtcHandle,&RTC_Date,RTC_FORMAT_BCD);

	  *Day = RTC_Date.Date;
	  *Month = RTC_Date.Month;
	  *Year =  (uint16_t)( BCD_To_Decimal( RTC_Date.Year ) )  + 2000;


	  return true;

}

bool update_date_time_from_rtc( uint16_t *Day, uint16_t *Month, uint16_t *Year,
								uint16_t *hour, uint16_t *minute, uint16_t *second,
								uint8_t *TimeFormat ){
	  RTC_TimeTypeDef RTC_Time = {0};
	  RTC_DateTypeDef RTC_Date = {0};
	  ULONG  events = 0;

	  /* TODO Check if the RTC value has been updated and RTC is correct else  return false */
	  HAL_RTC_GetTime(&RtcHandle,&RTC_Time,RTC_FORMAT_BCD);
	  HAL_RTC_GetDate(&RtcHandle,&RTC_Date,RTC_FORMAT_BCD);

	  *Day =  (uint16_t)( BCD_To_Decimal( RTC_Date.Date ) );
	  *Month = (uint16_t)( BCD_To_Decimal( RTC_Date.Month ) );
	  *Year =  (uint16_t)( BCD_To_Decimal( RTC_Date.Year ) )  + 2000;
	  *hour = (uint16_t)( BCD_To_Decimal( RTC_Time.Hours ) );
	  *minute = (uint16_t)( BCD_To_Decimal( RTC_Time.Minutes ) );
	  *second = (uint16_t)( BCD_To_Decimal( RTC_Time.Seconds ) );
	  *TimeFormat = RTC_Time.TimeFormat;
	  return true;

}

bool update_date_time_from_sntp( uint16_t *Day, uint16_t *Month, uint16_t *Year,
								uint16_t *hour, uint16_t *minute, uint16_t *second, uint8_t *TimeFormat ){
	  RTC_TimeTypeDef RTC_Time = {0};
	  RTC_DateTypeDef RTC_Date = {0};
	  ULONG  events = 0;


	  /**
	   * @note : Use 'TX_NO_WAIT' if not calling from a task
	   */
	  UINT status = tx_event_flags_get(&SntpFlags, SNTP_RTC_UPDATE_EVENT, TX_OR, &events, TX_NO_WAIT);

	  if(status != TX_SUCCESS){ return false; }

	  /* TODO Check if the RTC value has been updated and RTC is correct else  return false */
	  HAL_RTC_GetTime(&RtcHandle,&RTC_Time,RTC_FORMAT_BCD);
	  HAL_RTC_GetDate(&RtcHandle,&RTC_Date,RTC_FORMAT_BCD);

	  *Day =  (uint16_t)( BCD_To_Decimal( RTC_Date.Date ) );
	  *Month = (uint16_t)( BCD_To_Decimal( RTC_Date.Month ) );
	  *Year =  (uint16_t)( BCD_To_Decimal( RTC_Date.Year ) )  + 2000;
	  *hour = (uint16_t)( BCD_To_Decimal( RTC_Time.Hours ) );
	  *minute = (uint16_t)( BCD_To_Decimal( RTC_Time.Minutes ) );
	  *second = (uint16_t)( BCD_To_Decimal( RTC_Time.Seconds ) );
	  *TimeFormat = RTC_Time.TimeFormat;

	  return true;

}


/*******************************************************************************/


/*==============================================================================
  MQTT Client thread entry
  ==============================================================================*/

/** @brief  SNTP Client thread entry.
  * @param thread_input: ULONG user argument used by the thread entry
  * @retval none
  */
//static VOID App_SNTP_Thread_Entry(ULONG thread_input)
//{
//  UINT ret;
//  ULONG  fraction;
//  ULONG  events = 0;
//  UINT   server_status;
//  NXD_ADDRESS sntp_server_ip;
//
//  sntp_server_ip.nxd_ip_version = 4;
//
//  /* Look up SNTP Server address. */
//  ret = nx_dns_host_by_name_get(&DnsClient, (UCHAR *)SNTP_SERVER_NAME, &sntp_server_ip.nxd_ip_address.v4, DEFAULT_TIMEOUT);
//
//  /* Check for error. */
//  if (ret != NX_SUCCESS)
//  {
//    Error_Handler();
//  }
//
//  /* Create the SNTP Client */
//  ret =  nx_sntp_client_create(&SntpClient, &NetXDuoEthIpInstance, 0, &NxAppPool, NULL, NULL, NULL);
//
//  /* Check for error. */
//  if (ret != NX_SUCCESS)
//  {
//    Error_Handler();
//  }
//
//  /* Setup time update callback function. */
//  nx_sntp_client_set_time_update_notify(&SntpClient, time_update_callback);
//
//  /* Use the IPv4 service to set up the Client and set the IPv4 SNTP server. */
//  ret = nx_sntp_client_initialize_unicast(&SntpClient, sntp_server_ip.nxd_ip_address.v4);
//
//  if (ret != NX_SUCCESS)
//  {
//    Error_Handler();
//  }
//
//  /* Run whichever service the client is configured for. */
//  ret = nx_sntp_client_run_unicast(&SntpClient);
//
//  if (ret != NX_SUCCESS)
//  {
//    Error_Handler();
//  }
//
//  /* Wait for a server update event. */
//  tx_event_flags_get(&SntpFlags, SNTP_UPDATE_EVENT, TX_OR_CLEAR, &events, PERIODIC_CHECK_INTERVAL);
//
//  if (events == SNTP_UPDATE_EVENT)
//  {
//    /* Check for valid SNTP server status. */
//    ret = nx_sntp_client_receiving_updates(&SntpClient, &server_status);
//
//    if ((ret != NX_SUCCESS) || (server_status == NX_FALSE))
//    {
//      /* We do not have a valid update. */
//      Error_Handler();
//    }
//    /* We have a valid update.  Get the SNTP Client time. */
//    ret = nx_sntp_client_get_local_time_extended(&SntpClient, &current_time, &fraction, NX_NULL, 0);
//
//    if (ret != NX_SUCCESS)
//    {
//      Error_Handler();
//    }
//    /* Take off 70 years difference */
//    current_time -= EPOCH_TIME_DIFF;
//
//  }
//  else
//  {
//    Error_Handler();
//  }
//
//  /* start the MQTT client thread */
//  tx_thread_resume(&AppMQTTClientThread);
//
//}
/**
  * @brief  MQTT Client thread entry.
  * @param thread_input: ULONG user argument used by the thread entry
  * @retval none
  */
static VOID App_MQTT_Client_Thread_Entry(ULONG thread_input)
{
  UINT ret = NX_SUCCESS;
  NXD_ADDRESS mqtt_server_ip;
  ULONG events;
  UINT aRandom32bit;
  UINT topic_length, message_length;
  UINT remaining_msg = NB_MESSAGE;
  UINT message_count = 0;
  UINT unlimited_publish = NX_FALSE;

  mqtt_server_ip.nxd_ip_version = 4;

  printf("Starting MQTT client..\n");
  /* Look up MQTT Server address. */
  ret = nx_dns_host_by_name_get(&DnsClient, (UCHAR *)MQTT_BROKER_NAME,
                                &mqtt_server_ip.nxd_ip_address.v4, DEFAULT_TIMEOUT);

  /* Check status. */
  if (ret != NX_SUCCESS)
  {
	printf("DNS get host by name failed\r\n");
    Error_Handler();
  }

  printf("MQTT broker address: %lu.%lu.%lu.%lu\n",
		 (mqtt_server_ip.nxd_ip_address.v4 >> 24) & 0xff,
		 (mqtt_server_ip.nxd_ip_address.v4 >> 16) & 0xff,
		 (mqtt_server_ip.nxd_ip_address.v4 >> 8) & 0xff,
		 (mqtt_server_ip.nxd_ip_address.v4) & 0xff);
  /* Create MQTT client instance. */
  ret = nxd_mqtt_client_create(&MqttClient, "my_client", CLIENT_ID_STRING, STRLEN(CLIENT_ID_STRING),
                               &NetXDuoEthIpInstance, &NxAppPool, (VOID*)mqtt_client_stack, MQTT_CLIENT_STACK_SIZE,
                               MQTT_THREAD_PRIORTY, NX_NULL, 0);

  if (ret != NX_SUCCESS)
  {
		printf("MQTT client creation failed\r\n");
    Error_Handler();
  }

  printf("MQTT client created.\n");

  /* Register the disconnect notification function. */
  nxd_mqtt_client_disconnect_notify_set(&MqttClient, my_disconnect_func);

  /* Set the receive notify function. */
  nxd_mqtt_client_receive_notify_set(&MqttClient, my_notify_func);

  /* Create an MQTT flag */
  ret = tx_event_flags_create(&mqtt_app_flag, "my app event");
  if (ret != TX_SUCCESS)
  {
	  printf("MQTT event flag creation failed\r\n");
    Error_Handler();
  }

  /* Start a secure connection to the server. */
  ret = nxd_mqtt_client_secure_connect(&MqttClient, &mqtt_server_ip, MQTT_PORT, tls_setup_callback,
                                       MQTT_KEEP_ALIVE_TIMER, CLEAN_SESSION, NX_WAIT_FOREVER);

  if (ret != NX_SUCCESS)
  {
    printf("\nMQTT client failed to connect to broker < %s >.\n",MQTT_BROKER_NAME);
    Error_Handler();
  }
  else
  {
    printf("\nMQTT client connected to broker < %s > at PORT %d :\n",MQTT_BROKER_NAME, MQTT_PORT);
  }

  /* Subscribe to the topic with QoS level 1. */
  ret = nxd_mqtt_client_subscribe(&MqttClient, TOPIC_NAME, STRLEN(TOPIC_NAME), QOS1);

  if (ret != NX_SUCCESS)
  {
	  printf("MQTT subscribe failed\r\n");
    Error_Handler();
  }

  if (NB_MESSAGE ==0)
    unlimited_publish = NX_TRUE;

  while(unlimited_publish || remaining_msg)
  {
    aRandom32bit = message_generate();

    snprintf(message, STRLEN(message), "%u", aRandom32bit);

    /* Publish a message with QoS Level 1. */
    ret = nxd_mqtt_client_publish(&MqttClient, TOPIC_NAME, STRLEN(TOPIC_NAME),
                                  (CHAR*)message, STRLEN(message), NX_TRUE, QOS1, NX_WAIT_FOREVER);
    if (ret != NX_SUCCESS)
    {
    	printf("MQTT publish failed\r\n");
      Error_Handler();
    }

    /* Wait for the broker to publish the message. */
    tx_event_flags_get(&mqtt_app_flag, DEMO_ALL_EVENTS, TX_OR_CLEAR, &events, TX_WAIT_FOREVER);

    /* Check event received */
    if(events & DEMO_MESSAGE_EVENT)
    {
      /* Get message from the broker */
      ret = nxd_mqtt_client_message_get(&MqttClient, topic_buffer, sizeof(topic_buffer), &topic_length,
                                        message_buffer, sizeof(message_buffer), &message_length);
      if(ret == NXD_MQTT_SUCCESS)
      {
        printf("Message %d received: TOPIC = %s, MESSAGE = %s\n", message_count + 1, topic_buffer, message_buffer);
      }
      else
      {
    	  printf("MQTT get message failed\r\n");
        Error_Handler();
      }
    }

    /* Decrement message numbre */
    remaining_msg -- ;
    message_count ++ ;

    /* Delay 1s between each pub */
    tx_thread_sleep(100);

  }

  /* send an empty message at the end of the session to avoid the "Retain" message behavior */
  ret = nxd_mqtt_client_publish(&MqttClient, TOPIC_NAME, STRLEN(TOPIC_NAME), NULL, 0, NX_TRUE, QOS1, NX_WAIT_FOREVER);

  if (ret != NX_SUCCESS)
  {
	  printf("MQTT publish failed\r\n");
    Error_Handler();
  }

  /* Now unsubscribe the topic. */
  ret = nxd_mqtt_client_unsubscribe(&MqttClient, TOPIC_NAME, STRLEN(TOPIC_NAME));

  if (ret != NX_SUCCESS)
  {
	  printf("MQTT unsubscribe failed\r\n");
    Error_Handler();
  }

  /* Disconnect from the broker. */
  ret = nxd_mqtt_client_disconnect(&MqttClient);

  if (ret != NX_SUCCESS)
  {
	  printf("MQTT disconnect failed\r\n");
    Error_Handler();
  }

  /* Delete the client instance, release all the resources. */
  ret = nxd_mqtt_client_delete(&MqttClient);

  if (ret != NX_SUCCESS)
  {
	  printf("MQTT client delete failed\r\n");
    Error_Handler();
  }

  /* Test OK -> success Handler */
//  Success_Handler();
}

/* USER CODE END 1 */
