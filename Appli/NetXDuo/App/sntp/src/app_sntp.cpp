/*
 * app_sntp.cpp
 *
 *  Created on: 09-Jan-2026
 *      Author: alpl_
 */


#include <iostream>
#include <array>
#include <string_view>
#include <time.h>

#include "app_sntp.h"
#include "nxd_sntp_client.h"
#include "stm32h7rsxx_hal.h"
#include "log_util.h"
#include "netx_util.h"

TX_THREAD AppSNTPThread;
NX_SNTP_CLIENT  SntpClient;
/* SNTP client variables */
CHAR                     buffer[64];  // buffer to store the date and time string
struct tm timeInfos;
/* RTC handler declaration */
RTC_HandleTypeDef RtcHandle;
/* Set the SNTP network interface to the primary interface. */
UINT  iface_index =0;
/* SNTP client */
static UINT kiss_of_death_handler(NX_SNTP_CLIENT *client_ptr, UINT KOD_code);
static void display_rtc_time(RTC_HandleTypeDef *hrtc);
static void rtc_time_update(NX_SNTP_CLIENT *client_ptr);
static VOID sntp_random_number_generator(NX_SNTP_CLIENT *client_ptr, ULONG *rand_value);
static UINT sntp_leap_second_handler(NX_SNTP_CLIENT *client_ptr, UINT indicator);
/* MQTT client */
//static VOID App_MQTT_Client_Thread_Entry(ULONG thread_input);
static VOID App_SNTP_Thread_Entry(ULONG thread_input);
static VOID time_update_callback(NX_SNTP_TIME_MESSAGE *time_update_ptr, NX_SNTP_TIME *local_time);
static UINT Sntp_Resolve_And_Start(NX_SNTP_CLIENT *sntp_ptr, NX_DNS *dns_ptr, ULONG wait_option);
//static ULONG nx_secure_tls_session_time_function(void);
/***********************************************************************/
struct sntp_client_info_t{
	ULONG       	broker_ip_address;
	NX_PACKET_POOL *packet_pool;
	NX_IP 			*ip_instance;
	NX_DNS 			*dns_client_ptr;
	TX_BYTE_POOL 	*byte_pool;
};


/**********************************************************************/


/**  * @brief  Initialize the SNTP client application
  * @param  byte_pool: pointer to a previously created byte pool
  * @note   Get the pointer form the application.
  * 		Call this function after the DNS client is created.
  * 		Call tx_thread_resume on the SNTP thread in the app_netxduo.c app_netx_thread_entry
  * @retval UINT status
  */
UINT app_sntp_init( void *byte_pool, NX_PACKET_POOL *packet_pool,
					NX_IP *ip_instance, NX_DNS *dns_client_ptr){
	UINT ret;
	const ULONG stack_size = SNTP_CLIENT_THREAD_MEMORY;
	const CHAR *sntp_thread_name = "App SNTP Thread";
	CHAR *stack_ptr;

	// Define the SNTP client info structure.
	//THIS HAS TO BE STATIC TO AVOID STACK CORRUPTION
	static sntp_client_info_t sntp_client_info{};

	if (byte_pool == TX_NULL || packet_pool == TX_NULL || ip_instance == TX_NULL || dns_client_ptr == TX_NULL) {
		std::cerr << "Error: Null pointer passed to app_sntp_init" << std::endl;
		return TX_POOL_ERROR;
	}

	sntp_client_info.dns_client_ptr = dns_client_ptr;
	sntp_client_info.ip_instance 	= ip_instance;
	sntp_client_info.packet_pool 	= packet_pool;
	sntp_client_info.byte_pool 		= static_cast<TX_BYTE_POOL *>(byte_pool);
	/* Allocate the memory for SNTP client thread */
	if (tx_byte_allocate(   sntp_client_info.byte_pool,
							static_cast<void**>(static_cast<void*>(&stack_ptr)),
							stack_size, TX_NO_WAIT) != TX_SUCCESS){
		return TX_POOL_ERROR;
	}

	/* create the SNTP client thread */
	ret = tx_thread_create( &AppSNTPThread, const_cast<CHAR *>(sntp_thread_name),
							App_SNTP_Thread_Entry, reinterpret_cast<ULONG>(&sntp_client_info),
							stack_ptr, stack_size,
							SNTP_PRIORITY, SNTP_PRIORITY,
							TX_NO_TIME_SLICE, TX_DONT_START);

	std::cout << LOG_LOC << "MQTT client thread created with status: " << ret << std::endl;
	if (ret != TX_SUCCESS) { return TX_THREAD_ERROR; }
	return NX_SUCCESS;
}

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
  ULONG wait_for_dns{ 5 * NX_IP_PERIODIC_RATE };  // wait for 5 seconds
//  const static ULONG WaitTime_long = 2000;
  sntp_server_ip.nxd_ip_version = 4;
//  UINT old_threshold;
  static const ULONG RESYNC_INTERVAL = 30 * 60 * TX_TIMER_TICKS_PER_SECOND;

  /******************************************************/
  //get the sntp client info from the thread input
  sntp_client_info_t *sntp_client_info = reinterpret_cast<sntp_client_info_t *>(info);
  /************************************/

	std::cout << "Starting sntp client.." << std::endl;

  /* Create the SNTP Client */
  do{
	  ret =  nx_sntp_client_create( &SntpClient,
			  	  	  	  	  	  	sntp_client_info->ip_instance,
									iface_index,
									sntp_client_info->packet_pool,
									sntp_leap_second_handler,   /* leap_second_handler() (Optional) A
																 * function pointer called if the NTP
																 * server warns of an upcoming leap second.
															     * Pass NX_NULL if you don't care. */
									kiss_of_death_handler,      /* (Optional) A function pointer called if the
															     * Server rejects you (sends a "Kiss of Death" packet).
															     * Pass NX_NULL if you don't care. */
									sntp_random_number_generator /* (Mandatory) A function pointer that returns a random ULONG.
									   	   	   	   	   	   	      * NetX uses this to generate "Jitter" so all devices don't hit
									   	   	   	   	   	    	  * the server at the exact same millisecond. */
									 );
	  tx_thread_sleep(WaitTime);
  }while(ret != NX_SUCCESS);
  std::cout << LOG_LOC << "SNTP client created with status: " << ret << std::endl;

  /* 1. Get Current Server Name from your Object */
  std::string_view current_host = sntp_servers.get_current();

  /* Setup time update callback function. */
  nx_sntp_client_set_time_update_notify(&SntpClient, time_update_callback);

   std::cout << LOG_LOC << "Resolving: " << current_host << "..." << std::endl;
   Sntp_Resolve_And_Start(&SntpClient,
		   sntp_client_info->dns_client_ptr,
		   wait_for_dns);

  /* Run whichever service the client is configured for. */
   do{
	   ret = nx_sntp_client_run_unicast(&SntpClient);
	   tx_thread_sleep(WaitTime);
   }while(ret != NX_SUCCESS);

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

/*==============================================================================
  SNTP Client Helper Functions
  ==============================================================================*/
struct SntpConfig {
    /* 1. The Fixed Data (The List) */
    static constexpr std::array<std::string_view, 2> list = {
		/* Primary: Google (Low latency, Anycast) */
		"time.google.com",

		/* Secondary: Cloudflare (Very fast, Anycast) */
		"time.cloudflare.com",

		/* Tertiary: India Specific Pools (Good for local routing) */
		"0.in.pool.ntp.org",
		"1.in.pool.ntp.org",

		/* Fallback: NIST (US Government, very reliable but higher latency from Asia) */
		"time.nist.gov",

		/* Fallback: Windows Time */
		"time.windows.com"
    };

    /* 2. The State (Which one is active?) */
    size_t current_index = 0;

    /* 3. Helper: Get the current server string safely */
    std::string_view get_current() const {
        if (current_index < list.size()) {
            return list[current_index];
        }
        return "Unknown";
    }

    /* 4. Helper: Switch to the next server (Round Robin) */
    void next() {
        current_index++;
        if (current_index >= list.size()) {
            current_index = 0; // Loop back to start
        }
    }

    /* 5. Lambda-ready Printer */
    void print_status() const {
        std::cout << "SNTP Selected Server [" << current_index << "]: < "
                  << get_current() << " >" << std::endl;
    }
};

/* Create the global instance */
SntpConfig sntp_servers;
/* Function: Sntp_Resolve_And_Start
 * Description: Blocking call that loops indefinitely until a DNS IP is found.
 */
static UINT Sntp_Resolve_And_Start(NX_SNTP_CLIENT *sntp_ptr, NX_DNS *dns_ptr, ULONG wait_option)
{
    const int MAX_DNS_RETRIES = 3;
    const int RETRY_DELAY_TICKS = 100;

    UINT status = NX_DNS_TIMEOUT;
    ULONG server_ip = 0;
    int retry_count = 0;

    std::cout << LOG_LOC << "Starting SNTP Server Resolution..." << std::endl;

    /* --- 1. DNS Resolution Loop (Do...While) --- */
    do
    {
        /* Get current target from your config object */
        std::string_view host = sntp_servers.get_current();

        std::cout << LOG_LOC << "Resolving: " << host << "..." << std::endl;

        /* Try DNS */
        status = nx_dns_host_by_name_get(dns_ptr,
                                         (UCHAR *)host.data(),
                                         &server_ip,
                                         wait_option);

        /* Logic for FAILURE (Continue Looping) */
        if (status != NX_SUCCESS)
        {
            std::cout << LOG_LOC << "DNS Failed (0x" << std::hex << status
                      << "). Retrying..." << std::dec << std::endl;

            retry_count++;
            tx_thread_sleep(RETRY_DELAY_TICKS);

            /* Switch Server if Retries Exceeded */
            if (retry_count >= MAX_DNS_RETRIES)
            {
                std::cout << LOG_LOC << "Server " << host
                          << " unreachable. Switching to backup..." << std::endl;

                sntp_servers.next(); // Move to next server in list
                retry_count = 0;     // Reset counter
            }
        }

    } while (status != NX_SUCCESS);

    /* --- 2. Success Logic --- */
    /* Using format_ip() instead of ip_to_str() */
    std::cout << LOG_LOC << "DNS Success! Resolved to " << format_ip(server_ip) << std::endl;

    /* --- 3. Initialize SNTP Unicast --- */
    status = nx_sntp_client_initialize_unicast(sntp_ptr, server_ip);

    if (status == NX_SUCCESS)
    {
        std::cout << LOG_LOC << "SNTP Client Initialized (Unicast) with IP: "
                  << format_ip(server_ip) << std::endl;
    }
    else
    {
        std::cout << LOG_LOC << "SNTP Init Failed: 0x"
                  << std::hex << status << std::dec << std::endl;
    }

    return status;
}

/**
 * @brief  Get the SNTP client thread instance.
 * @return TX_THREAD* Pointer to the SNTP client thread instance.
 * @note This is externed function to get the SNTP client thread instance.
 *       get the Thread this in the app_netx_thread after the dns is created.
 *       This is required to start the SNTP client thread after
 *       the network is initialized.
 */
TX_THREAD* get_sntp_client_thread_instance(void){
	return &AppSNTPThread;
}

/* 1. Random Number Generator (REQUIRED) */
/* NetX calls this to get a random seed for timing calculations */
static VOID sntp_random_number_generator(NX_SNTP_CLIENT *client_ptr, ULONG *rand_value)
{
    /* Use the STM32 Hardware RNG if available, or a simple C rand() */
    /* Assuming you have HAL_RNG initialized, or just use standard rand() */
    *rand_value = (ULONG)rand();
}

/* 2. Leap Second Handler (Optional) */
static UINT sntp_leap_second_handler(NX_SNTP_CLIENT *client_ptr, UINT indicator)
{
    /* Indicator: 1=Add second, 2=Subtract second */
    printf("SNTP Warning: Leap Second pending! Indicator: %d\n", indicator);
    return NX_SUCCESS;
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

