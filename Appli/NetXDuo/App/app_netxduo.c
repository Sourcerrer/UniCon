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
#include "app_udp_server.h"
#include "app_mqtt.h"
#include "app_mdns.h"
#include "tcp_server.h"

/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */
extern RNG_HandleTypeDef hrng;
//TX_THREAD AppMQTTClientThread;
TX_THREAD AppSNTPThread;
TX_THREAD AppLinkThread;
//NXD_MQTT_CLIENT MqttClient;
NX_SNTP_CLIENT  SntpClient;
static NX_DNS   DnsClient;
TX_EVENT_FLAGS_GROUP     SntpFlags;
ULONG   IpAddress;
ULONG   NetMask;

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
/* Global Event Flag for the Link Thread */
/* Global Variable Declaration */
TX_EVENT_FLAGS_GROUP link_event_group;
#define EVENT_LINK_UP   0x01
#define EVENT_LINK_DOWN 0x02
VOID my_link_callback(NX_IP *ip_ptr, UINT interface_index, UINT link_up);

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


TX_THREAD AppLinkThread;

ULONG IpAddress;
ULONG NetMask;

NX_DHCP DHCPClient;


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
//static VOID App_TCP_Thread_Entry(ULONG thread_input);
/* SNTP client */
static UINT kiss_of_death_handler(NX_SNTP_CLIENT *client_ptr, UINT KOD_code);
static void display_rtc_time(RTC_HandleTypeDef *hrtc);
static void rtc_time_update(NX_SNTP_CLIENT *client_ptr);
/* MQTT client */
//static VOID App_MQTT_Client_Thread_Entry(ULONG thread_input);
static VOID App_SNTP_Thread_Entry(ULONG thread_input);
static VOID App_Link_Thread_Entry(ULONG thread_input);
static VOID time_update_callback(NX_SNTP_TIME_MESSAGE *time_update_ptr, NX_SNTP_TIME *local_time);
//static ULONG nx_secure_tls_session_time_function(void);
static UINT dns_create(NX_DNS *dns_ptr);
//static UINT message_generate(void);
//static UINT tls_setup_callback(NXD_MQTT_CLIENT *client_pt,
//                        NX_SECURE_TLS_SESSION *TLS_session_ptr,
//                        NX_SECURE_X509_CERT *certificate_ptr,
//                        NX_SECURE_X509_CERT *trusted_certificate_ptr);
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

//  {
//	  /* Initialize the TCP server over local network */
//	  UINT tcp_server_init(void *byte_pool);
//	  tcp_server_init(byte_pool);
//  }
  /* Set DHCP notification callback  */
//  tx_semaphore_create(&TCPSemaphore, "TCP Semaphore", 0);

  /* Allocate the memory for SNTP client thread */
  if (tx_byte_allocate(byte_pool, (VOID **) &pointer, SNTP_CLIENT_THREAD_MEMORY, TX_NO_WAIT) != TX_SUCCESS)
  {
    return TX_POOL_ERROR;
  }

  /* create the SNTP client thread */
  ret = tx_thread_create( &AppSNTPThread, "App SNTP Thread", App_SNTP_Thread_Entry, 0,
		  	  	  	  	  pointer, SNTP_CLIENT_THREAD_MEMORY,
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

  /* Create the Event Flags Group for Link Status */
    ret = tx_event_flags_create(&link_event_group, "Link Event Group");
    if (ret != TX_SUCCESS)
    {
        printf("Failed to create link event group: 0x%02X\n", ret);
        return ret;
    }

  {
	  /* Initialize the MDNS service */
	  UINT mdns_init( void *byte_pool, NX_IP *ip_instance, NX_PACKET_POOL *packet_pool);
	  ret = mdns_init( (void *)byte_pool, &NetXDuoEthIpInstance, &NxAppPool);
	  if (ret != TX_SUCCESS){
		  printf("MDNS Init failed\r\n");
		  return NX_NOT_ENABLED;
	  }
  }

  {
	  /* Initialize UDP Server */
	  printf("UDP Server Init..\n");
	  uint16_t app_udp_server_init( void *byte_pool, NX_IP *ip_instance, NX_PACKET_POOL *packet_pool);
	  ret = app_udp_server_init((void *)byte_pool, &NetXDuoEthIpInstance, &NxAppPool);
	  if (ret != TX_SUCCESS){
		  printf("udp server Init failed\r\n");
		  return NX_NOT_ENABLED;
	  }
  }

  {
	  /* Initialize mqtt client */
	  uint16_t app_mqtt_init( void *byte_pool, NX_PACKET_POOL *packet_pool,
	  						NX_IP *ip_instance, NX_DNS *dns_client_ptr );
	  uint16_t ret = app_mqtt_init( (void *)byte_pool, &NxAppPool,
			  	  	  	  	  	  &NetXDuoEthIpInstance,
								  &DnsClient );
	  if(ret != TX_SUCCESS){
		  printf("MQTT Init failed\r\n");
		  return NX_NOT_ENABLED;
	  }
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
	printf("DHCP Client assigned IP Address : %lu.%lu.%lu.%lu\n",
		   (IpAddress >> 24) & 0xFF,
		   (IpAddress >> 16) & 0xFF,
		   (IpAddress >> 8) & 0xFF,
		   (IpAddress) & 0xFF);
    tx_semaphore_put(&DHCPSemaphore);
    printf("DHCP Client IP Address available signal sent.................\n");
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
	extern TX_THREAD 		AppTCPThread;
  /* USER CODE END Nx_App_Thread_Entry 0 */

  UINT ret = NX_SUCCESS;

  /* USER CODE BEGIN Nx_App_Thread_Entry 1 */
  /* After nx_ip_create... */
//  nx_ip_link_status_change_notify_set(&NetXDuoEthIpInstance, my_link_callback);
//  if (ret != NX_SUCCESS)
//  {
//	/* USER CODE BEGIN link status change callback error */
//	  printf("nx_ip_link_status_change_notify_set() failed: error 0x%08x", NX_NOT_SUCCESSFUL);
//	Error_Handler();
//	/* USER CODE END link status change callback error */
//  }
  /* USER CODE END Nx_App_Thread_Entry 1 */

  /* register the IP address change callback */
  ret = nx_ip_address_change_notify(&NetXDuoEthIpInstance, ip_address_change_notify_callback, NULL);
  if (ret != NX_SUCCESS)
  {
    /* USER CODE BEGIN IP address change callback error */
	  printf("nx_ip_address_get() failed: error 0x%08x", NX_NOT_SUCCESSFUL);
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

  /* the network is correctly initialized, start the UDP thread */
  TX_THREAD* get_udp_server_thread_instance(void);
  tx_thread_resume( get_udp_server_thread_instance() );
  /* The network is correctly initialized, start the App MDNS thread. */
  TX_THREAD* get_mdns_thread_instance(void);
  tx_thread_resume(get_mdns_thread_instance());

  /* If this thread is not needed any more, we relinquish it */
  tx_thread_relinquish();

  return;
  /* USER CODE END Nx_App_Thread_Entry 2 */

}
/* USER CODE BEGIN 1 */


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

/* Private variables ---------------------------------------------------------*/
/* Track previous state: 0 = Down, 1 = Up */
static UINT is_link_up_prev = 0;

/* Private functions ---------------------------------------------------------*/

/**
  * @brief  Handles the sequence when the link goes DOWN.
  */
static void Handle_Link_Down(void)
{
    ULONG actual_status;

    printf("The network cable is not connected.\n");

    /* Disable the PHY to save power or reset state */
    nx_ip_driver_direct_command(&NetXDuoEthIpInstance, NX_LINK_DISABLE, &actual_status);

    /* Optional: Clear the IP address so the stack knows we are offline */
    nx_ip_address_set(&NetXDuoEthIpInstance, 0, 0);
}

/**
  * @brief  Handles the sequence when the link comes UP.
  */
static void Handle_Link_Up(void)
{
    ULONG actual_status;
    UINT status;

    printf("The network cable is connected.\n");

    /* 1. Enable PHY Link */
    nx_ip_driver_direct_command(&NetXDuoEthIpInstance, NX_LINK_ENABLE, &actual_status);

    /* 2. Restart DHCP Sequence
       Always restart DHCP on a fresh link connection to ensure a valid lease. */
    nx_dhcp_stop(&DHCPClient);
    nx_dhcp_reinitialize(&DHCPClient);
    nx_dhcp_start(&DHCPClient);

    printf("DHCP Request sent. Waiting for IP...\n");

    /* 3. Wait for IP Address (With Timeout!)
       We use a timeout (e.g., 5 seconds) instead of TX_WAIT_FOREVER.
       If DHCP fails, we exit this function so the thread can keep monitoring the link. */
    if(tx_semaphore_get(&DHCPSemaphore, 500) == TX_SUCCESS) /* 500 ticks ~ 5 seconds */
    {
        /* IP Acquired Successfully */
        ULONG ip_address, network_mask;
        nx_ip_address_get(&NetXDuoEthIpInstance, &ip_address, &network_mask);

        printf("IP Address Resolved: %lu.%lu.%lu.%lu\n",
               (ip_address >> 24) & 0xFF,
               (ip_address >> 16) & 0xFF,
               (ip_address >> 8) & 0xFF,
               (ip_address) & 0xFF);
    }
    else
    {
        /* Timeout occurred - Link is up, but no DHCP Server found yet. */
        printf("DHCP Timeout: No IP received yet. Retrying in background...\n");
    }
}

/* The Callback Function */
VOID my_link_callback(NX_IP *ip_ptr, UINT interface_index, UINT link_up)
{
    if (link_up)
    {
        /* Cable Plugged In */
    	printf("The network cable is connected (link Callback).\n");
        tx_event_flags_set(&link_event_group, EVENT_LINK_UP, TX_OR);
    }
    else
    {
        /* Cable Unplugged */
    	printf("The network cable is NOT connected (link Callback).\n");
        tx_event_flags_set(&link_event_group, EVENT_LINK_DOWN, TX_OR);
    }
}

/* Global handles */
extern NX_IP          NetXDuoEthIpInstance;
extern NX_DHCP        DHCPClient;
extern TX_SEMAPHORE   DHCPSemaphore;

/**
  * @brief  Robust Link Monitor & DHCP Manager
  * Replaces reliance on broken callbacks.
  */
static VOID App_Link_Thread_Entry(ULONG thread_input)
{
    ULONG actual_status;
    ULONG ip_address, network_mask;
    UINT  link_status;
    UINT  last_link_status = NX_FALSE; /* Assume started disconnected */

    printf("Link Monitor Thread Started...\n");

    /* Infinite Loop: The Heartbeat of your Network */
    for (;;)
    {
        /* 1. Poll the Physical Link Status directly */
        /* This queries the PHY registers. It works on ALL hardware. */
        UINT status = nx_ip_interface_status_check(&NetXDuoEthIpInstance, 0,
                                                   NX_IP_LINK_ENABLED,
                                                   &actual_status,
                                                   10);

        link_status = (status == NX_SUCCESS) ? NX_TRUE : NX_FALSE;

        /* 2. Check for State Change */
        if (link_status != last_link_status)
        {
            if (link_status == NX_TRUE)
            {
                /* ====================================================
                   CASE: Cable Just Plugged In (Link UP)
                   ==================================================== */
                printf("\n>>> Cable CONNECTED. Starting Network...\n");

                /* A. Enable the Interface */
                nx_ip_driver_direct_command(&NetXDuoEthIpInstance, NX_LINK_ENABLE, &actual_status);

                /* B. Restart DHCP (Stop first to be safe) */
                nx_dhcp_stop(&DHCPClient);
                nx_dhcp_reinitialize(&DHCPClient);
                nx_dhcp_start(&DHCPClient);

                printf("DHCP Request Sent. Waiting for Address...\n");

                /* C. Wait for IP (Polling instead of Semaphore for simplicity)
                      We check every 500ms for up to 5 seconds */
                for(int i = 0; i < 10; i++)
                {
                    tx_thread_sleep(50); // Wait 500ms (assuming 10ms tick)

                    if (nx_ip_address_get(&NetXDuoEthIpInstance, &ip_address, &network_mask) == NX_SUCCESS)
                    {
                        if (ip_address != 0)
                        {
                            printf(">>> IP ACQUIRED: %lu.%lu.%lu.%lu\n",
                                   (ip_address >> 24) & 0xFF,
                                   (ip_address >> 16) & 0xFF,
                                   (ip_address >> 8) & 0xFF,
                                   (ip_address) & 0xFF);

                            /* SIGNAL MAIN APP HERE (e.g. set a flag or semaphore) */
                            tx_semaphore_put(&DHCPSemaphore);
                            break;
                        }
                    }
                }
            }
            else
            {
                /* ====================================================
                   CASE: Cable Unplugged (Link DOWN)
                   ==================================================== */
                printf("\n>>> Cable DISCONNECTED. Stopping Network...\n");

                /* A. Stop DHCP to prevent timeouts */
                nx_dhcp_stop(&DHCPClient);

                /* B. Reset IP to 0.0.0.0 so App knows we are offline */
                nx_ip_address_set(&NetXDuoEthIpInstance, 0, 0);

                /* C. Disable Interface */
                nx_ip_driver_direct_command(&NetXDuoEthIpInstance, NX_LINK_DISABLE, &actual_status);
            }

            /* Update tracking variable */
            last_link_status = link_status;
        }

        /* 3. Sleep to save CPU (Check cable every 500ms) */
        tx_thread_sleep(NX_APP_CABLE_CONNECTION_CHECK_PERIOD);
    }
}

/**
* @brief  Link thread entry
* @param thread_input: ULONG thread parameter
* @retval none
*/
//static VOID App_Link_Thread_Entry(ULONG thread_input)
//{
//  ULONG actual_status;
//  UINT current_link_status;
//  UINT status;
//
//  /* Initialize previous state based on actual startup state */
//  status = nx_ip_interface_status_check(&NetXDuoEthIpInstance, 0, NX_IP_LINK_ENABLED, &actual_status, 10);
//  is_link_up_prev = (status == NX_SUCCESS) ? 1 : 0;
//
//  for(;;)
//  {
//    /* 1. Check current physical link status */
//    status = nx_ip_interface_status_check(&NetXDuoEthIpInstance, 0, NX_IP_LINK_ENABLED, &actual_status, 10);
//
//    /* Normalize status to 0 or 1 */
//    current_link_status = (status == NX_SUCCESS) ? 1 : 0;
//
//    /* 2. Detect State Change */
//    if (current_link_status != is_link_up_prev)
//    {
//        if (current_link_status == 1)
//        {
//            /* Transition: Down -> Up */
//            Handle_Link_Up();
//        }
//        else
//        {
//            /* Transition: Up -> Down */
//            Handle_Link_Down();
//        }
//
//        /* Update history */
//        is_link_up_prev = current_link_status;
//    }
//
//    /* 3. Reduce polling frequency to save CPU */
//    tx_thread_sleep(NX_APP_CABLE_CONNECTION_CHECK_PERIOD);
//  }
//}

//static VOID App_Link_Thread_Entry(ULONG thread_input)
//{
//  ULONG events;
//
//  /* Initial Check (in case we booted with cable already in) */
//  /* ... (same initial check logic as before) ... */
//
//  while(1)
//  {
//      /* Wait for EITHER Link Up OR Link Down event */
//      tx_event_flags_get(&link_event_group,
//                         EVENT_LINK_UP | EVENT_LINK_DOWN,
//                         TX_OR_CLEAR,
//                         &events,
//                         TX_WAIT_FOREVER);
//
//      if (events & EVENT_LINK_UP)
//      {
//          printf("Callback said: Link is UP!\n");
//          Handle_Link_Up(); // The helper function we wrote earlier
//      }
//
//      if (events & EVENT_LINK_DOWN)
//      {
//          printf("Callback said: Link is DOWN!\n");
//          Handle_Link_Down(); // The helper function we wrote earlier
//      }
//  }
//}

///**
//* @brief  Link thread entry
//* @param thread_input: ULONG thread parameter
//* @retval none
//*/
//static VOID App_Link_Thread_Entry(ULONG thread_input)
//{
//  ULONG actual_status;
//  UINT linkdown = 0, status;
//
//  while(1)
//  {
//    /* Send request to check if the Ethernet cable is connected. */
//    status = nx_ip_interface_status_check(&NetXDuoEthIpInstance, 0, NX_IP_LINK_ENABLED,
//                                      &actual_status, 10);
//    printf("Checking network cable connection..\n");
//    if(status == NX_SUCCESS)
//    {
//
//      if(linkdown == 1)
//      {
//        linkdown = 0;
//
//        /* The network cable is connected. */
//        printf("The network cable is connected.\n");
//
//        /* Send request to enable PHY Link. */
//        nx_ip_driver_direct_command(&NetXDuoEthIpInstance, NX_LINK_ENABLE,
//                                      &actual_status);
//
//        /* Send request to check if an address is resolved. */
//        status = nx_ip_interface_status_check(&NetXDuoEthIpInstance, 0, NX_IP_ADDRESS_RESOLVED,
//                                      &actual_status, 10);
//        if(status == NX_SUCCESS)
//        {
//          /* Stop DHCP */
//          nx_dhcp_stop(&DHCPClient);
//
//          /* Reinitialize DHCP */
//          nx_dhcp_reinitialize(&DHCPClient);
//
//          /* Start DHCP */
//          nx_dhcp_start(&DHCPClient);
//
//          /* Wait until an IP address is ready */
//          if(tx_semaphore_get(&DHCPSemaphore, TX_WAIT_FOREVER) != TX_SUCCESS)
//          {
//            /* USER CODE BEGIN DHCPSemaphore get error */
//        	  printf("tx_semaphore_get() failed: error 0x%08x", NX_NOT_SUCCESSFUL);
//            Error_Handler();
//            /* USER CODE END DHCPSemaphore get error */
//          }
//
//          PRINT_IP_ADDRESS(IpAddress);
//        }
//        else
//        {
//          /* Set the DHCP Client's remaining lease time to 0 seconds to trigger an immediate renewal request for a DHCP address. */
//          nx_dhcp_client_update_time_remaining(&DHCPClient, 0);
//          printf("DHCP lease renewal triggered.\n");
//        }
//      }
//    }
//    else
//    {
//      if(0 == linkdown)
//      {
//        linkdown = 1;
//        /* The network cable is not connected. */
//        printf("The network cable is not connected.\n");
//        nx_ip_driver_direct_command(&NetXDuoEthIpInstance, NX_LINK_DISABLE,
//                                      &actual_status);
//      }
//    }
//
//    tx_thread_sleep(NX_APP_CABLE_CONNECTION_CHECK_PERIOD);
//  }
//}

///**
//  * @brief  message generation Function.
//  * @param  RandomNbr
//  * @retval none
//  */
//static UINT message_generate(void)
//{
//  uint32_t RandomNbr = 0;
//
//  HAL_RNG_Init(&hrng);
//
//  /* Generate a random number */
//  if(HAL_RNG_GenerateRandomNumber(&hrng, &RandomNbr) != HAL_OK)
//  {
//	  printf("HAL_RNG_GenerateRandomNumber() failed");
//    Error_Handler();
//  }
//
//  return RandomNbr %= 50;
//}
//
///* Function (set by user) to call when TLS needs the current time. */
//ULONG nx_secure_tls_session_time_function(void)
//{
//  return (current_time);
//}
//
///* Callback to setup TLS parameters for secure MQTT connection. */
//UINT tls_setup_callback(NXD_MQTT_CLIENT *client_pt,
//                        NX_SECURE_TLS_SESSION *TLS_session_ptr,
//                        NX_SECURE_X509_CERT *certificate_ptr,
//                        NX_SECURE_X509_CERT *trusted_certificate_ptr)
//{
//  UINT ret = NX_SUCCESS;
//  NX_PARAMETER_NOT_USED(client_pt);
//
//  /* Initialize TLS module */
//  nx_secure_tls_initialize();
//
//  /* Create a TLS session */
//  ret = nx_secure_tls_session_create(TLS_session_ptr, &nx_crypto_tls_ciphers,
//                                     crypto_metadata_client, sizeof(crypto_metadata_client));
//  if (ret != NX_SUCCESS)
//  {
//	  printf("nx_secure_tls_session_create() failed: error 0x%08x", ret);
//    Error_Handler();
//  }
//
//  /* Need to allocate space for the certificate coming in from the broker. */
//  memset((certificate_ptr), 0, sizeof(NX_SECURE_X509_CERT));
//
//    ret = nx_secure_tls_session_time_function_set(TLS_session_ptr, nx_secure_tls_session_time_function);
//
//  if (ret != NX_SUCCESS)
//  {
//	  printf("nx_secure_tls_session_time_function_set() failed: error 0x%08x", ret);
//    Error_Handler();
//  }
//
//  /* Allocate space for packet reassembly. */
//  ret = nx_secure_tls_session_packet_buffer_set(TLS_session_ptr, tls_packet_buffer,
//                                                sizeof(tls_packet_buffer));
//  if (ret != NX_SUCCESS)
//  {
//	  printf("nx_secure_tls_session_packet_buffer_set() failed: error 0x%08x", ret);
//    Error_Handler();
//  }
//
//  /* Allocate space for the certificate coming in from the remote host */
//  ret = nx_secure_tls_remote_certificate_allocate(TLS_session_ptr, certificate_ptr,
//                                                  tls_packet_buffer, sizeof(tls_packet_buffer));
//  if (ret != NX_SUCCESS)
//  {
//	  printf("nx_secure_tls_remote_certificate_allocate() failed: error 0x%08x", ret);
//    Error_Handler();
//  }
//
//  /* Initialize Certificate to verify incoming server certificates. */
//  ret = nx_secure_x509_certificate_initialize(trusted_certificate_ptr, (UCHAR*)mosquitto_org_der,
//                                              mosquitto_org_der_len, NX_NULL, 0, NULL, 0,
//                                              NX_SECURE_X509_KEY_TYPE_NONE);
//  if (ret != NX_SUCCESS)
//  {
//    printf("Certificate issue..\nPlease make sure that your X509_certificate is valid. \n");
//    Error_Handler();
//  }
//
//  /* Add a CA Certificate to our trusted store */
//  ret = nx_secure_tls_trusted_certificate_add(TLS_session_ptr, trusted_certificate_ptr);
//  if (ret != TX_SUCCESS)
//  {
//	  printf("nx_secure_tls_trusted_certificate_add() failed: error 0x%08x", ret);
//    Error_Handler();
//  }
//
//  return ret;
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
  static const ULONG RESYNC_INTERVAL = 30 * 60 * TX_TIMER_TICKS_PER_SECOND;

  /* Create a DNS client */
  do{
	  ret = dns_create(&DnsClient);
	  tx_thread_sleep(WaitTime);
  }while(ret != NX_SUCCESS);
  printf("dns created\r\n");

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

  /* Look up SNTP Server address.
   * TODO add a lookup table to get the servers address */
  do{
	  ret = nx_dns_host_by_name_get(&DnsClient, (UCHAR *)SNTP_SERVER_NAME_1,
	                                  &sntp_server_ip.nxd_ip_address.v4, NX_APP_DEFAULT_TIMEOUT);
	  tx_thread_sleep(WaitTime);
  }while(ret != NX_SUCCESS);
  printf("dns host got\r\n");

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
   /* Display RTC time each second */
   display_rtc_time(&RtcHandle);

//  /* start the MQTT client thread */
//  tx_thread_resume(&AppMQTTClientThread);
  /* start the MQTT client thread */
  TX_THREAD* get_mqtt_thread_instance(void);  // forward declaration in app_mqtt.h
  tx_thread_resume( get_mqtt_thread_instance() );
  /* Toggling LED after a success Time update */
  while(1)
  {

	  /* Delay for 30 minutes */
	  tx_thread_sleep(RESYNC_INTERVAL);

	  printf("\nRe-syncing time...\n");
	  do{
		  ret = nx_dns_host_by_name_get(&DnsClient, (UCHAR *)SNTP_SERVER_NAME_1,
		                                  &sntp_server_ip.nxd_ip_address.v4, NX_APP_DEFAULT_TIMEOUT);
		  tx_thread_sleep(WaitTime);
	  }while(ret != NX_SUCCESS);

	  printf("dns host got\r\n");
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
	    /* Display RTC time each second */
	    display_rtc_time(&RtcHandle);
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
//    Error_Handler();
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
//    Error_Handler();
  }

}

/* This application displays time from RTC */
static void display_rtc_time(RTC_HandleTypeDef *hrtc)
{
  RTC_TimeTypeDef RTC_Time = {0};
  RTC_DateTypeDef RTC_Date = {0};

  HAL_RTC_GetTime(&RtcHandle,&RTC_Time,RTC_FORMAT_BCD);
  HAL_RTC_GetDate(&RtcHandle,&RTC_Date,RTC_FORMAT_BCD);

  printf("%02x-%02x-20%02x / %02x:%02x:%02x IST\n",\
        RTC_Date.Date, RTC_Date.Month, RTC_Date.Year,RTC_Time.Hours,RTC_Time.Minutes,RTC_Time.Seconds);
}

static void rtc_time_to_buffer(RTC_HandleTypeDef *hrtc, char *buffer, size_t len)
{
  RTC_TimeTypeDef RTC_Time = {0};
  RTC_DateTypeDef RTC_Date = {0};

  HAL_RTC_GetTime(&RtcHandle,&RTC_Time,RTC_FORMAT_BCD);
  HAL_RTC_GetDate(&RtcHandle,&RTC_Date,RTC_FORMAT_BCD);

  snprintf(buffer, len, "%02x-%02x-20%02x / %02x:%02x:%02x IST",\
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



/* USER CODE END 1 */
