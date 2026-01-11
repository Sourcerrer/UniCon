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


#include "nx_ip.h"
#include "nx_stm32_eth_config.h"
#include "msg.h"
#include "app_udp_server.h"
#include "app_mqtt.h"
#include "app_mdns.h"
#include "app_sntp.h"
#include "tcp_server.h"

/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */
extern RNG_HandleTypeDef hrng;
//TX_THREAD AppMQTTClientThread;

TX_THREAD AppLinkThread;
//NXD_MQTT_CLIENT MqttClient;

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

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
static VOID nx_app_thread_entry (ULONG thread_input);
static VOID ip_address_change_notify_callback(NX_IP *ip_instance, VOID *ptr);
static VOID App_Link_Thread_Entry(ULONG thread_input);
static UINT dns_create(NX_DNS *dns_ptr);
/* USER CODE BEGIN PFP */
/* TCP server */
//static VOID App_TCP_Thread_Entry(ULONG thread_input);

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
  /* Ensure IGMP is enabled on the IP instance */
  ret = nx_igmp_enable(&NetXDuoEthIpInstance);
  if (ret != NX_SUCCESS) {
    printf("Error: nx_igmp_enable failed: 0x%02x\r\n", ret);
    return NX_NOT_SUCCESSFUL;
  }
  /* USER CODE END DHCP_Protocol_Initialization */

  ret = nx_dhcp_create(&DHCPClient, &NetXDuoEthIpInstance, "DHCP Client");

  if (ret != NX_SUCCESS)
  {
    return NX_DHCP_ERROR;
  }

  /* set DHCP notification callback  */
  tx_semaphore_create(&DHCPSemaphore, "DHCP Semaphore", 0);

  /* USER CODE BEGIN MX_NetXDuo_Init */

  /* Create the event flags. */
  ret = tx_event_flags_create(&SntpFlags, "SNTP event flags");

  /* Check for errors */
  if (ret != NX_SUCCESS)
  {
    return NX_NOT_ENABLED;
  }

  /* Create a link thread to monitor the network */
  /* Create the Event Flags Group for Link Status */
    ret = tx_event_flags_create(&link_event_group, "Link Event Group");
    if (ret != TX_SUCCESS)
    {
        printf("Failed to create link event group: 0x%02X\n", ret);
        return ret;
    }
    /* Allocate the memory for Link thread   */
    if (tx_byte_allocate(byte_pool, (VOID **) &pointer,LINK_STACK, TX_NO_WAIT) != TX_SUCCESS){
      return TX_POOL_ERROR;
    }

    /* Create the Link thread */
    ret = tx_thread_create( &AppLinkThread, "App Link Thread", App_Link_Thread_Entry,
  		  	  	  	  	  0, pointer, LINK_STACK,
                            LINK_PRIORITY, LINK_PRIORITY,
  						  TX_NO_TIME_SLICE, TX_AUTO_START);

    if (ret != TX_SUCCESS){ return NX_NOT_ENABLED; }
    /* END of Link thread initialization */

    /* START of Applications Initialisation ******************************/
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

    {
    	/* Initiaize sntp client */
    	UINT app_sntp_init( void *byte_pool, NX_PACKET_POOL *packet_pool,
    						NX_IP *ip_instance, NX_DNS *dns_client_ptr);
    	uint16_t ret = app_sntp_init( (void *)byte_pool, &NxAppPool,
							&NetXDuoEthIpInstance,
							&DnsClient);
    	if(ret != TX_SUCCESS){
    		printf("SNTP Init failed\r\n");
			return NX_NOT_ENABLED;
    	}
    }

    /* END of Applications Initialization ******************************/

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

  /* the network is correctly initialized, start the UDP thread */
  TX_THREAD* get_udp_server_thread_instance(void);
  tx_thread_resume( get_udp_server_thread_instance() );

  /* The network is correctly initialized, start the App MDNS thread. */
  TX_THREAD* get_mdns_thread_instance(void);
  tx_thread_resume(get_mdns_thread_instance());

  /* Create a DNS client */
  do{
	  ret = dns_create(&DnsClient);
	  tx_thread_sleep(DEFAULT_TIMEOUT);
  }while(ret != NX_SUCCESS);
  printf("dns created\r\n");

    /* Start the SNTP client thread */

  /* start sntp thread */
  TX_THREAD* get_sntp_client_thread_instance(void);  // forward declaration in app_sntp.h
  tx_thread_resume( get_sntp_client_thread_instance() );
  /* start the MQTT client thread */
  TX_THREAD* get_mqtt_thread_instance(void);  // forward declaration in app_mqtt.h
  tx_thread_resume( get_mqtt_thread_instance() );


  printf("Network initialization completed.\n");
  /* If this thread is not needed any more, we relinquish it */
  tx_thread_relinquish();

  return;
  /* USER CODE END Nx_App_Thread_Entry 2 */

}
/* USER CODE BEGIN 1 */




/* Private variables ---------------------------------------------------------*/
/* Track previous state: 0 = Down, 1 = Up */
//static UINT is_link_up_prev = 0;



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




/* USER CODE END 1 */
