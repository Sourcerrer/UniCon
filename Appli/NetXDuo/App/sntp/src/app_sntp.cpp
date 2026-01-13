/*
 * app_sntp.cpp
 *
 *  Created on: 09-Jan-2026
 *      Author: alpl_
 */


#include <iostream>
#include <array>
#include <vector>
#include <string_view>
#include <time.h>
#include <string>
#include <cstring>
#include <cstdio>
#include <cstdlib> // For atol
#include <cstdlib>
//#include <cstring>
#include "nx_api.h"
#include "app_sntp.h"
#include "nxd_sntp_client.h"
#include "stm32h7rsxx_hal.h"
#include "log_util.h"
#include "netx_util.h"

TX_THREAD AppSNTPThread;
NX_SNTP_CLIENT  SntpClient;
TX_EVENT_FLAGS_GROUP     SntpFlags;
/* SNTP client variables */
CHAR                     buffer[64];  // buffer to store the date and time string
struct tm timeInfos;
/* RTC handler declaration */
RTC_HandleTypeDef RtcHandle;
/* Set the SNTP network interface to the primary interface. */
UINT  iface_index =0;
/* Private SNTP client function prototypes */
static UINT kiss_of_death_handler(NX_SNTP_CLIENT *client_ptr, UINT KOD_code);
static void display_rtc_time(RTC_HandleTypeDef *hrtc);
static void rtc_time_update(NX_SNTP_CLIENT *client_ptr);
static VOID sntp_random_number_generator(NX_SNTP_CLIENT *client_ptr, ULONG *rand_value);
static UINT sntp_leap_second_handler(NX_SNTP_CLIENT *client_ptr, UINT indicator);
/* MQTT client */
//static VOID App_MQTT_Client_Thread_Entry(ULONG thread_input);
static VOID App_SNTP_Thread_Entry(ULONG thread_input);
static VOID time_update_callback(NX_SNTP_TIME_MESSAGE *time_update_ptr, NX_SNTP_TIME *local_time);
//static UINT Sntp_Resolve_And_Start(NX_SNTP_CLIENT *sntp_ptr, NX_DNS *dns_ptr, ULONG wait_option);
static void Sntp_Start_And_Sync(NX_SNTP_CLIENT *sntp_ptr, NX_DNS *dns_ptr, ULONG wait_option);
static void Sntp_Process_Time(NX_SNTP_CLIENT *sntp_ptr, ULONG timezone_offset_sec);
/* END private SNTP client function prototypes  */
UINT Get_Timezone_Offset(NX_IP *ip_ptr, NX_PACKET_POOL *pool_ptr, NX_DNS *dns_ptr, LONG *result_offset);
void Sntp_Auto_Zone_And_Process(NX_SNTP_CLIENT *sntp_ptr,
                                NX_IP *ip_ptr,
                                NX_PACKET_POOL *pool_ptr,
                                NX_DNS *dns_ptr);

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

	/* Create the event flags. */
	ret = tx_event_flags_create(&SntpFlags, const_cast<CHAR *>("SNTP event flags") );

	/* Check for errors */
	if (ret != NX_SUCCESS) { return NX_NOT_ENABLED; }

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
  NX_PARAMETER_NOT_USED(info);
  ULONG wait_for_dns{ 5 * NX_IP_PERIODIC_RATE };  // wait for 5 seconds
//  sntp_server_ip.nxd_ip_version = 4;
  static const ULONG RESYNC_INTERVAL = 30 * 60 * TX_TIMER_TICKS_PER_SECOND;

  /******************************************************/
  //get the sntp client info from the thread input
  sntp_client_info_t *sntp_client_info = reinterpret_cast<sntp_client_info_t *>(info);
  /************************************/

	/* ----------------------------------------------------------------
	 * 1. Create SNTP Client (DO NOT LOOP THIS)
	 * ----------------------------------------------------------------
	 * If creation fails (e.g., No Memory), retrying usually won't help.
	 * We check once and handle the fatal error.
	 */
	ret = nx_sntp_client_create(&SntpClient,
			sntp_client_info->ip_instance,
			iface_index,
			sntp_client_info->packet_pool,
			sntp_leap_second_handler,			/* leap_second_handler() (Optional) A
			 * function pointer called if the NTP
			 * server warns of an upcoming leap second.
			 * Pass NX_NULL if you don't care. */
			kiss_of_death_handler,			/* (Optional) A function pointer called if the
			 * Server rejects you (sends a "Kiss of Death" packet).
			 * Pass NX_NULL if you don't care. */
			sntp_random_number_generator);	/* (Mandatory) A function pointer that returns a random ULONG.
			 * NetX uses this to generate "Jitter" so all devices don't hit
			 * the server at the exact same millisecond. */

	if (ret != NX_SUCCESS){
		std::cout << LOG_LOC << "FATAL: SNTP Create Failed (0x" << std::hex << ret << ")" << std::endl;
		tx_thread_suspend(tx_thread_identify());
	}
  std::cout << LOG_LOC << "SNTP client created with status: " << ret << std::endl;

  /* Setup time update callback function. */
  nx_sntp_client_set_time_update_notify(&SntpClient, time_update_callback);
  while(1)
  {
	  /* 1. Start SNTP and Sync Time */
	  Sntp_Start_And_Sync( &SntpClient,
						   sntp_client_info->dns_client_ptr,
						   wait_for_dns);

	  /* 2. Determine Timezone & Display Time */
	  Sntp_Auto_Zone_And_Process( &SntpClient,
								  sntp_client_info->ip_instance,
								  sntp_client_info->packet_pool,
								  sntp_client_info->dns_client_ptr);

	  /* 3. Set Current time from SNTP TO RTC */
	  rtc_time_update(&SntpClient);
	  /* We can stop the SNTP service if for example we think the SNTP server has stopped sending updates */
	  do{
		  ret = nx_sntp_client_stop(&SntpClient);
		  tx_thread_sleep(wait_for_dns);
	  }while(ret != NX_SUCCESS);
	  printf("SNTP client stopped\r\n");
	  display_rtc_time(&RtcHandle);
	  /* Delay for 30 minutes */
	  tx_thread_sleep(RESYNC_INTERVAL);
	  std::cout << LOG_LOC << "Starting SNTP re-sync.." << std::endl;
  }
}

/*==============================================================================
  SNTP Client Helper Functions
  ==============================================================================*/
struct SntpConfig {
    /* 1. The Fixed Data (The List) */
    static constexpr std::array<std::string_view, 6> list = {
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

/* Function: Sntp_Start_And_Sync
 * Description: Robustly connects to SNTP.
 * - Retry Level 1: DNS (3x per server)
 * - Retry Level 2: SNTP Handshake (3x per server)
 * - Retry Level 3: Server List (Switch to next server)
 */
static void Sntp_Start_And_Sync(NX_SNTP_CLIENT *sntp_ptr, NX_DNS *dns_ptr, ULONG wait_option)
{
	/* Configuration */
	const int RETRY_DELAY_TICKS     = 100;  // 1 sec between retries
	const int SNTP_SYNC_TIMEOUT     = 500;  // 5 sec wait for Time Sync
	const int MAX_DNS_RETRIES       = 3;
	const int MAX_PROTOCOL_RETRIES  = 3;    // <--- NEW: Retry SNTP 3 times

	UINT status;
	ULONG server_ip = 0;
	ULONG events = 0;
	sntp_servers.current_index = 0; // Reset to first server
	std::cout << LOG_LOC << "--- Starting SNTP Sync Process ---" << std::endl;

	/* --- LEVEL 3: SERVER LIST LOOP --- */
	while (true)
	{
		std::string_view host = sntp_servers.get_current();
		std::cout << LOG_LOC << "Targeting Server: " << host << "..." << std::endl;

		/* ==================================================================
		 * LEVEL 1: DNS RESOLUTION
		 * ================================================================== */
		int dns_attempts = 0;
		bool dns_success = false;

		do {
			status = nx_dns_host_by_name_get(dns_ptr, (UCHAR *)host.data(), &server_ip, wait_option);
			if (status == NX_SUCCESS) {
				dns_success = true;
				break;
			}
			dns_attempts++;
			std::cout << LOG_LOC << "DNS Attempt " << dns_attempts << " Failed. Retrying..." << std::endl;
			if (dns_attempts < MAX_DNS_RETRIES) tx_thread_sleep(RETRY_DELAY_TICKS);

		} while (dns_attempts < MAX_DNS_RETRIES);

		if (!dns_success) {
			std::cout << LOG_LOC << "Server " << host << " DNS Failed. Switching..." << std::endl;
			sntp_servers.next();
			tx_thread_sleep(RETRY_DELAY_TICKS);
			continue; // Restart Outer Loop
		}
		else{
			std::cout << LOG_LOC << "DNS Success! Resolved " << host
					<< " to " << format_ip(server_ip) << std::endl;
		}

		/* ==================================================================
		 * LEVEL 2: SNTP PROTOCOL HANDSHAKE (The New Retry Logic)
		 * ================================================================== */
		int proto_attempts = 0;
		bool time_synced = false;

		/* Retry Protocol on the SAME IP address before giving up */
		do {
			proto_attempts++;

			/* A. Cleanup and Restart to force a new packet */
			nx_sntp_client_stop(sntp_ptr);
			nx_sntp_client_initialize_unicast(sntp_ptr, server_ip);

			status = nx_sntp_client_run_unicast(sntp_ptr);

			if (status == NX_SUCCESS || status == NX_SNTP_CLIENT_ALREADY_STARTED)
			{
				std::cout << LOG_LOC << "SNTP Request Sent (Attempt " << proto_attempts
						<< "). Waiting for Reply..." << std::endl;

				/* B. Wait for Response */
				tx_event_flags_set(&SntpFlags, ~SNTP_UPDATE_EVENT, TX_AND);

				status = tx_event_flags_get(&SntpFlags, SNTP_UPDATE_EVENT, TX_OR_CLEAR, &events, SNTP_SYNC_TIMEOUT);

				if (status == TX_SUCCESS) {
					time_synced = true;
					break; // VICTORY! Break Protocol Loop
				} else {
					std::cout << LOG_LOC << "Time Sync Timeout." << std::endl;
				}
			}
			else {
				std::cout << LOG_LOC << "SNTP Run Error: 0x" << std::hex << status << std::dec << std::endl;
			}

			/* Small delay before next protocol attempt */
			if (proto_attempts < MAX_PROTOCOL_RETRIES) tx_thread_sleep(RETRY_DELAY_TICKS);

		} while (proto_attempts < MAX_PROTOCOL_RETRIES);


		/* ==================================================================
		 * FINAL DECISION
		 * ================================================================== */
		if (time_synced)
		{
			std::cout << LOG_LOC << "SUCCESS: Time Synchronized with " << host << "!" << std::endl;
			ULONG s, f;
			nx_sntp_client_get_local_time(sntp_ptr, &s, &f, NX_NULL);
			std::cout << LOG_LOC << "Unix Time: " << s << std::endl;
			break; // Exit Level 3 (Main Loop) - We are done.
		}
		else
		{
			std::cout << LOG_LOC << "Server " << host << " Unresponsive (UDP). Switching..." << std::endl;
			sntp_servers.next(); // Switch Server
		}
	}
}

/* Defines for Backup Registers */
#define BKP_REG_MAGIC       RTC_BKP_DR1
#define BKP_REG_OFFSET      RTC_BKP_DR2
#define BKP_MAGIC_VALUE     0xA5A5A5A5  // Signature to verify data validity

/* External RTC Handle from main.c */
extern RTC_HandleTypeDef hrtc;

/* Function: Save_Offset_To_Backup
 * Description: Writes the offset to RTC Backup registers.
 */
void Save_Offset_To_Backup(LONG offset)
{
    /* 1. Unlock Backup Domain (Usually handled by HAL_RTC_Init, but good practice) */
    HAL_PWR_EnableBkUpAccess();

    /* 2. Write the Offset */
    /* Note: Backup registers are 32-bit, so they fit a LONG perfectly */
    HAL_RTCEx_BKUPWrite(&hrtc, BKP_REG_OFFSET, (uint32_t)offset);

    /* 3. Write the Magic Number (Signature) */
    HAL_RTCEx_BKUPWrite(&hrtc, BKP_REG_MAGIC, BKP_MAGIC_VALUE);

    std::cout << LOG_LOC << "[Persist] Offset " << offset << " saved to Backup Regs." << std::endl;
}

/* Function: Load_Offset_From_Backup
 * Description: Tries to read offset. Returns TRUE if valid data found.
 */
bool Load_Offset_From_Backup(LONG *offset)
{
    /* 1. Check Magic Number */
    uint32_t magic = HAL_RTCEx_BKUPRead(&hrtc, BKP_REG_MAGIC);

    if (magic == BKP_MAGIC_VALUE)
    {
        /* 2. Valid! Read the Offset */
        /* Cast back to signed LONG (important for negative zones like NY) */
        *offset = (LONG)HAL_RTCEx_BKUPRead(&hrtc, BKP_REG_OFFSET);

        std::cout << LOG_LOC << "[Persist] Found saved offset: " << *offset << std::endl;
        return true;
    }

    std::cout << LOG_LOC << "[Persist] No saved offset found (First run?)" << std::endl;
    return false;
}

/* Function: Sntp_Auto_Zone_And_Process
 * Description:
 * 1. Attempts to get the current Timezone Offset via IP Geolocation (Internet).
 * 2. Falls back to a hardcoded default (Pune, India) if Internet fails.
 * 3. Applies the offset and displays the final local time.
 */
void Sntp_Auto_Zone_And_Process(NX_SNTP_CLIENT *sntp_ptr,
                                NX_IP *ip_ptr,
                                NX_PACKET_POOL *pool_ptr,
                                NX_DNS *dns_ptr)
{
    /* Hardcoded Fallback (Factory Default) */
    const LONG FACTORY_DEFAULT_OFFSET = 19800; // Pune/India

    LONG final_offset = 0;
    UINT geo_status;

    std::cout << LOG_LOC << "--- Determining Timezone ---" << std::endl;

    /* 1. Try Internet Lookup */
    geo_status = Get_Timezone_Offset(ip_ptr, pool_ptr, dns_ptr, &final_offset);

    if (geo_status == NX_SUCCESS)
    {
        /* CASE A: Internet Success */
        std::cout << LOG_LOC << "[Geo] Internet Lookup Success. Offset: " << final_offset << std::endl;

        /* Save to Backup for next time */
        Save_Offset_To_Backup(final_offset);
    }
    else
    {
        /* CASE B: Internet Failed */
        std::cout << LOG_LOC << "[Geo] Internet Failed. Checking Backup Memory..." << std::endl;

        /* 2. Try Loading from Backup Registers */
        if (Load_Offset_From_Backup(&final_offset))
        {
             std::cout << LOG_LOC << "[Geo] Using Saved Offset from Backup." << std::endl;
        }
        else
        {
             /* 3. Total Failure -> Use Factory Default */
             std::cout << LOG_LOC << "[Geo] No Backup found. Using Factory Default (IST)." << std::endl;
             final_offset = FACTORY_DEFAULT_OFFSET;
        }
    }

    /* 4. Apply Time */
    Sntp_Process_Time(sntp_ptr, final_offset);
}

/* Function: Sntp_Process_Time
 * Description: Verifies update status, retrieves time, applies timezone, and prints.
 * Parameters:
 * - sntp_ptr: Pointer to client
 * - timezone_offset_sec: Seconds to add (e.g., 19800 for India IST +5:30)
 */
static void Sntp_Process_Time(NX_SNTP_CLIENT *sntp_ptr, ULONG timezone_offset_sec)
{
    UINT ret;
    UINT server_status = NX_FALSE;
    ULONG seconds, fraction;
    CHAR time_buffer[64];

    /* 1. Verify we are actually receiving updates */
    /* We don't need a loop here; the Event Flag in the previous step guarantees this is ready.
       But we check once for sanity. */
    ret = nx_sntp_client_receiving_updates(sntp_ptr, &server_status);

    if ((ret != NX_SUCCESS) || (server_status == NX_FALSE))
    {
        std::cout << LOG_LOC << "Error: SNTP Event Triggered, but 'Receiving Updates' is FALSE." << std::endl;
        return; // specific error handling or return logic could go here
    }

    std::cout << LOG_LOC << "Status: Valid SNTP Updates Active." << std::endl;

    /* 2. Get the Time (Raw UTC) */
    ret = nx_sntp_client_get_local_time_extended(sntp_ptr, &seconds, &fraction, NX_NULL, 0);

    if (ret == NX_SUCCESS)
    {
        /* 3. Apply Timezone Offset (Manual Calculation) */
        ULONG local_seconds = seconds + timezone_offset_sec;

        std::cout << LOG_LOC << "UTC Seconds: " << seconds
                  << " | Local Seconds (+5:30): " << local_seconds << std::endl;

        /* 4. Format and Display */
        /* Note: This utility uses the raw UTC seconds from the client internal structure usually,
           so it might print UTC. If you want to print Local Time string, you might need
           standard C library tools like ctime() on 'local_seconds'.

           However, using the NetX utility as requested: */
        ret = nx_sntp_client_utility_display_date_time(sntp_ptr, time_buffer, sizeof(time_buffer));

        if (ret == NX_SUCCESS)
        {
            std::cout << LOG_LOC << "NetX Formatted Time: " << time_buffer << std::endl;
        }
        else
        {
            std::cout << LOG_LOC << "Time Format Failed (Buffer too small?)" << std::endl;
        }
    }
    else
    {
        std::cout << LOG_LOC << "Failed to retrieve local time extended (0x" << std::hex << ret << ")" << std::dec << std::endl;
    }
}
/*==============================================================================
  GeoIP Timezone Offset Fetcher
  ==============================================================================*/

/* Structure to define an API Provider */
struct GeoProvider {
    const char* host;       // e.g., "ip-api.com"
    const char* path;       // e.g., "/json/?fields=offset"
    const char* search_key; // JSON key to find, e.g., "offset"
};

/* List of Free Geolocation APIs (Ordered by priority) */
static const std::array<GeoProvider, 3> GEO_SERVERS = {{
    /* 1. ip-api.com: Best free tier, returns seconds */
    { "ip-api.com",       "/json/?fields=offset", "offset" },

    /* 2. ipwho.is: Very reliable, similar output */
    { "ipwho.is",         "/",                    "offset" },

    /* 3. WorldTimeAPI: Solid backup (Note: Check if 'raw_offset' meets your needs) */
    { "worldtimeapi.org", "/api/ip",              "raw_offset" }
}};


/* * Helper: Parse_Json_Int
 * Generic helper to find a specific key ("offset", "raw_offset") and parse the value.
 */
static LONG Parse_Json_Int(std::string_view json, const char* target_key)
{
    /* 1. Construct search string with quotes, e.g., "offset" */
    char key_pattern[32];
    snprintf(key_pattern, sizeof(key_pattern), "\"%s\"", target_key);

    /* 2. Find Key */
    auto key_pos = json.find(key_pattern);
    if (key_pos == std::string_view::npos) return 0;

    /* 3. Find Separator ':' */
    auto val_pos = json.find(':', key_pos);
    if (val_pos == std::string_view::npos) return 0;

    /* 4. Parse Number */
    /* data() + val_pos + 1 points to value start. strtol handles signs/spaces. */
    return std::strtol(json.data() + val_pos + 1, nullptr, 10);
}


/* * Function: Get_Timezone_Offset_Robust
 * Description: Cycles through multiple API providers to find the timezone offset.
 */
UINT Get_Timezone_Offset(NX_IP *ip_ptr, NX_PACKET_POOL *pool_ptr, NX_DNS *dns_ptr, LONG *result_offset)
{
    /* --- Configuration --- */

    constexpr static const ULONG HTTP_WINDOW_SIZE {2048},
						  	  	 HTTP_BUFFER_SIZE {2048};
    /* ----END configuration -------------- */
    UINT status;
    NX_TCP_SOCKET socket;
    NXD_ADDRESS server_ip;
    NX_PACKET *request_packet;
    NX_PACKET *response_packet;

    UCHAR buffer[HTTP_BUFFER_SIZE];
    bool global_success = false;
    *result_offset = 0;

    std::cout << LOG_LOC << "--- Starting Geolocation Lookup (Multi-API) ---" << std::endl;

    /* --- OUTER LOOP: Iterate through Providers --- */
    for (const auto& provider : GEO_SERVERS)
    {
        std::cout << LOG_LOC << "[Geo] Trying Provider: " << provider.host << "..." << std::endl;

        /* 1. Resolve DNS for current provider */
        status = nx_dns_host_by_name_get(dns_ptr, (UCHAR*)provider.host, &server_ip.nxd_ip_address.v4, 2000);
        server_ip.nxd_ip_version = NX_IP_VERSION_V4;

        if (status != NX_SUCCESS) {
            std::cout << LOG_LOC << "[Geo] DNS Failed for " << provider.host << ". Trying next..." << std::endl;
            continue; // Try next provider
        }

        /* 2. Create Socket */
        status = nx_tcp_socket_create(ip_ptr, &socket, (CHAR*)"GeoSocket",
                                      NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80,
                                      HTTP_WINDOW_SIZE, NX_NULL, NX_NULL);
        if (status != NX_SUCCESS) return status; // Fatal resource error

        status = nx_tcp_client_socket_bind(&socket, NX_ANY_PORT, NX_WAIT_FOREVER);
        if (status != NX_SUCCESS) { nx_tcp_socket_delete(&socket); return status; }

        /* 3. Retry Loop for Current Provider */
        for (int attempt = 1; attempt <= 2; attempt++) // Try each provider twice
        {
            /* CONNECT */
            status = nxd_tcp_client_socket_connect(&socket, &server_ip, 80, 3000);
            if (status != NX_SUCCESS) {
                nx_tcp_socket_disconnect(&socket, NX_NO_WAIT);
                tx_thread_sleep(50); continue;
            }

            /* ALLOCATE */
            status = nx_packet_allocate(pool_ptr, &request_packet, NX_TCP_PACKET, NX_WAIT_FOREVER);
            if (status != NX_SUCCESS) {
                nx_tcp_socket_disconnect(&socket, NX_NO_WAIT); break;
            }

            /* BUILD REQUEST (Using provider-specific path) */
            char request_header[256];
            snprintf(request_header, sizeof(request_header),
                    "GET %s HTTP/1.0\r\n"
                    "Host: %s\r\n"
                    "User-Agent: STM32_Client/1.0\r\n"
                    "Accept: */*\r\n"
                    "Connection: close\r\n\r\n",
                    provider.path, provider.host);

            nx_packet_data_append(request_packet, (VOID*)request_header, strlen(request_header), pool_ptr, NX_WAIT_FOREVER);

            /* SEND */
            status = nx_tcp_socket_send(&socket, request_packet, 200);
            if (status != NX_SUCCESS) {
                nx_tcp_socket_disconnect(&socket, NX_NO_WAIT); tx_thread_sleep(50); continue;
            }

            /* RECEIVE */
            status = nx_tcp_socket_receive(&socket, &response_packet, 5000);
            if (status == NX_SUCCESS)
            {
                /* DATA ASSEMBLY */
                ULONG total_copied = 0;
                NX_PACKET *curr = response_packet;
                while (curr && total_copied < (HTTP_BUFFER_SIZE - 1)) {
                    ULONG bytes = curr->nx_packet_length;
                    if (total_copied + bytes > HTTP_BUFFER_SIZE - 1) bytes = (HTTP_BUFFER_SIZE - 1) - total_copied;
                    memcpy(&buffer[total_copied], curr->nx_packet_prepend_ptr, bytes);
                    total_copied += bytes;
                    curr = curr->nx_packet_next;
                }
                buffer[total_copied] = '\0';
                nx_packet_release(response_packet);

                /* PARSE (Using provider-specific key) */
                char *body = strstr((char*)buffer, "\r\n\r\n");
                if (body) {
                    LONG temp = Parse_Json_Int(body, provider.search_key);

                    /* Validation: Non-zero or explicit 0 found */
                    char zero_pattern[32];
                    snprintf(zero_pattern, sizeof(zero_pattern), "\"%s\":0", provider.search_key);

                    if (temp != 0 || strstr(body, zero_pattern)) {
                        *result_offset = temp;
                        global_success = true;
                        std::cout << LOG_LOC << "[Geo] Success via " << provider.host << "! Offset: " << temp << std::endl;
                    }
                }

                nx_tcp_socket_disconnect(&socket, 200);
                break; // Break Retry Loop (Success)
            }
            else {
                nx_tcp_socket_disconnect(&socket, NX_NO_WAIT);
                tx_thread_sleep(50);
            }
        }

        /* Cleanup Socket before next provider */
        nx_tcp_client_socket_unbind(&socket);
        nx_tcp_socket_delete(&socket);

        if (global_success) break; // Break Provider Loop (Done!)
    }

    return (global_success ? NX_SUCCESS : NX_NOT_CONNECTED);
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

/* * Function: sntp_random_number_generator
 * Description:
 * - Uses STM32 Hardware RNG if 'RNG' or 'HAL_RNG_MODULE_ENABLED' is defined.
 * - Falls back to standard C rand() if hardware is missing or fails.
 * - Conforms to NetX Duo callback signature (VOID return, write to pointer).
 */
static VOID sntp_random_number_generator(NX_SNTP_CLIENT *client_ptr, ULONG *rand_value)
{
    /* Avoid compiler warning for unused parameter */
    NX_PARAMETER_NOT_USED(client_ptr);

/* Check if Hardware RNG is enabled in your project */
#if defined(RNG) || defined(HAL_RNG_MODULE_ENABLED)

    extern RNG_HandleTypeDef hrng; // Ensure this is accessible (defined in main.c)
    uint32_t hw_random_val = 0;

    /* Attempt to get Hardware Random Number */
    if (HAL_RNG_GenerateRandomNumber(&hrng, &hw_random_val) == HAL_OK)
    {
        *rand_value = (ULONG)hw_random_val;
        return; /* Success - exit function */
    }

    /* If we reach here, Hardware RNG failed. Fall through to software backup. */

#endif

    /* Software Fallback (Weak Randomness) */
    /* Note: Ideally, seed this with srand(tick_count) somewhere in main() */
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


/*==============================================================================
  RTC Helper Functions
  ==============================================================================*/
/* This application updates Time from SNTP to STM32 RTC */

/**
 * @ref Exported funtion
 *  */
void RTC_Format_DateTime(char *buffer, size_t len)
{
  RTC_TimeTypeDef RTC_Time = {0};
  RTC_DateTypeDef RTC_Date = {0};

  HAL_RTC_GetTime(&RtcHandle,&RTC_Time,RTC_FORMAT_BCD);
  HAL_RTC_GetDate(&RtcHandle,&RTC_Date,RTC_FORMAT_BCD);

  snprintf(buffer, len, "%02x-%02x-20%02x / %02x:%02x:%02x IST",\
		RTC_Date.Date, RTC_Date.Month, RTC_Date.Year,RTC_Time.Hours,RTC_Time.Minutes,RTC_Time.Seconds);
}
/*******************************************************/


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

