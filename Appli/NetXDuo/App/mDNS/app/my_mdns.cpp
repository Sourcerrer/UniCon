/*
 * my_mdns.cpp
 *
 * Created on: Nov 12, 2025
 * Author: alpl_
 */
#include <iostream>
#include <cstdint>
#include "tx_api.h"
#include "nx_api.h"
#include "my_mdns.h"
#include "app_mdns.h"
#include "log_util.h"

/* --- DEFINITIONS FOR UDP SERVICES --- */
#define SERVICE_UDP_TYPE        (UCHAR *)"_custom_server._udp"
#define SERVICE_UDP_INST_6000   (UCHAR *)"MyServer-6000"
#define SERVICE_UDP_INST_6001   (UCHAR *)"MyServer-6001"
#define SERVICE_PORT_6000       6000
#define SERVICE_PORT_6001       6001

/* START mDNS variables */
static TX_THREAD AppMdnsThread;
static CHAR AppMdnsThreadName[] = "App Mdns thread";
NX_MDNS MdnsInstance;
static UCHAR LocalServiceCache[MDNS_LOCAL_CACHE_SIZE];
static UCHAR PeerServiceCache[MDNS_PEER_CACHE_SIZE];
static VOID App_Mdns_Thread_Entry(ULONG thread_input);
constexpr static char mdns_host_name[] = "unicon";

/* Global Event Group */
TX_EVENT_FLAGS_GROUP mdns_event_group;

/* END mDNS variables */

/***********************************************************
 * @Exported Functions
 */
TX_THREAD *get_mdns_thread_instance(void){
    return &AppMdnsThread;
}

uint16_t Set_mdns_Notifications(void){
#ifndef NX_MDNS_DISABLE_CLIENT
  ULONG service_mask = 0x00000002;
#endif /* NX_MDNS_DISABLE_CLIENT  */

    uint16_t ret = nx_mdns_cache_notify_set(&MdnsInstance, cache_full_notify);

    if (ret != NX_SUCCESS)
    {
        std::cout << LOG_LOC << "Error setting cache full notification"<< std::endl;
    }

#ifndef NX_MDNS_DISABLE_CLIENT
    ret = nx_mdns_service_notify_set(&MdnsInstance, service_mask, service_change_notify);

    if (ret != NX_SUCCESS)
    {
        std::cout << LOG_LOC << "Error setting service change notification"<< std::endl;
    }
#endif /* NX_MDNS_DISABLE_CLIENT  */
    return ret;
}


/* @brief mdns init */
UINT mdns_init( void *byte_pool, NX_IP *ip_instance, NX_PACKET_POOL *packet_pool)
{
  const ULONG stack_size = NETX_MDNS_THREAD_STACK_SIZE;
  VOID *stack_ptr;

  if (tx_byte_allocate(static_cast<TX_BYTE_POOL *>(byte_pool),
                          (VOID **) &stack_ptr, stack_size, TX_NO_WAIT) != TX_SUCCESS)
  {
    return TX_POOL_ERROR;
  }

  UINT ret = nx_mdns_create(&MdnsInstance, ip_instance, packet_pool,
                       NETX_MDNS_THREAD_PRIORITY, stack_ptr, stack_size,
                       (UCHAR *)mdns_host_name,
                       (VOID *)LocalServiceCache, sizeof(LocalServiceCache),
                       (VOID *)PeerServiceCache, sizeof(PeerServiceCache), probing_notify);

  if (ret != NX_SUCCESS)
  {
    return NX_NOT_ENABLED;
  }
  std::cout << LOG_LOC << "nx_mdns_create() done" << std::endl;

  {
    const ULONG app_stack_size = APP_MDNS_THREAD_STACK_SIZE;
    VOID *app_stack_ptr;

    if (tx_byte_allocate(static_cast<TX_BYTE_POOL *>(byte_pool), &app_stack_ptr, app_stack_size, TX_NO_WAIT) != TX_SUCCESS)
    {
      return TX_POOL_ERROR;
    }

    Set_mdns_Notifications();

    ret = tx_thread_create(&AppMdnsThread, AppMdnsThreadName,
                            App_Mdns_Thread_Entry, reinterpret_cast<ULONG>(byte_pool),
                            app_stack_ptr, app_stack_size,
                            APP_MDNS_THREAD_PRIORITY, APP_MDNS_THREAD_PRIORITY, TX_NO_TIME_SLICE, TX_DONT_START);

    if (ret != TX_SUCCESS)
    {
      return NX_NOT_ENABLED;
    }
    std::cout << LOG_LOC << "mdns_thread() done" << std::endl;
  }
  return NX_SUCCESS;
}

/**
  * @brief App MDNS thread entry with Link Monitor.
  * This monitors the Ethernet link status and restarts mDNS services
  * when the link comes back up (e.g., cable replug).
  */
static VOID App_Mdns_Thread_Entry(ULONG thread_input)
{
    NX_PARAMETER_NOT_USED(thread_input);

    UINT ret = NX_SUCCESS;
    ULONG actual_status;
    bool is_connected = false;
    ULONG ip_address = 0x00000000;
    ULONG NetMask = 0x00000000;

    const ULONG polling_interval = (2 * TX_TIMER_TICKS_PER_SECOND); // Check every 2 seconds

    std::cout << LOG_LOC << "mDNS Thread Started (Link Monitor Mode)>\n";

    /* Create the event flag */
    tx_event_flags_create(&mdns_event_group, (CHAR *)"mdns_event_flags");
    /* Sleep before checking link status again */
	tx_thread_sleep(polling_interval);
    /* Main State Machine Loop */
    for (;;)
    {
        /* 1. Check if Ethernet Link is UP */
        ret = nx_ip_status_check(MdnsInstance.nx_mdns_ip_ptr, NX_IP_LINK_ENABLED, &actual_status, 10);
        if (ret == NX_SUCCESS)
        {
        	do{
            	ret = nx_ip_address_get(MdnsInstance.nx_mdns_ip_ptr, &ip_address, &NetMask);
				if (ret != NX_SUCCESS){
					std::cout << LOG_LOC << "nx_ip_address_get() failed: error 0x" << std::hex << ret << std::dec << std::endl;
					tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND);
				}
        	}while(ret != NX_SUCCESS);

            /* --- CASE: LINK IS UP --- */
            if (!is_connected && (actual_status & NX_IP_LINK_ENABLED) == NX_IP_LINK_ENABLED)
            {
                /* Transition: Down -> Up */
                std::cout << LOG_LOC << "Link UP detected! (Re)Starting mDNS..." << std::endl;

                /* A. Disable first to reset state (in case it was half-stuck) */
                nx_mdns_disable(&MdnsInstance, 0);

                /* B. Clear any old services to prevent duplicates.
                 * Note: nx_mdns_service_delete_all is a NetX Duo API call. */
                delete_local_service( (UCHAR *)SERVICE_UDP_INST_6000, (UCHAR *)SERVICE_UDP_TYPE, SERVICE_SUBTYPE_NULL );
                delete_local_service( (UCHAR *)SERVICE_UDP_INST_6001, (UCHAR *)SERVICE_UDP_TYPE, SERVICE_SUBTYPE_NULL );
                std::cout << LOG_LOC << "Old mDNS services cleared." << std::endl;

                /* C. Enable mDNS */
                ret = nx_mdns_enable(&MdnsInstance, 0);
                if (ret != NX_SUCCESS) {
                     std::cout << LOG_LOC << "mDNS Enable Failed: 0x" << std::hex << ret << std::dec << std::endl;
                }

                /* D. Wait a moment for IGMP Join to propagate */
                tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND / 2);

                /* E. Re-Register Services */
                std::cout << LOG_LOC << "Registering Services..." << std::endl;

                // Service 1
                register_local_service(SERVICE_UDP_INST_6000, SERVICE_UDP_TYPE, SERVICE_SUBTYPE_NULL,
                                     (UCHAR *)"ver=1.0", SERVICE_TTL, SERVICE_PRIORITY, SERVICE_WEIGHT,
                                     SERVICE_PORT_6000, NX_TRUE);

                // Service 2
                register_local_service(SERVICE_UDP_INST_6001, SERVICE_UDP_TYPE, SERVICE_SUBTYPE_NULL,
                                     (UCHAR *)"ver=1.0", SERVICE_TTL, SERVICE_PRIORITY, SERVICE_WEIGHT,
                                     SERVICE_PORT_6001, NX_TRUE);

                std::cout << LOG_LOC << "mDNS Services Announced." << std::endl;

                is_connected = true;
            }
        }
        else
        {
            /* --- CASE: LINK IS DOWN --- */
            if (is_connected)
            {
                /* Transition: Up -> Down */
                std::cout << LOG_LOC << "Link DOWN detected! Stopping mDNS..." << std::endl;

                /* Disable mDNS to stop it from trying to send packets to a dead link */
                nx_mdns_disable(&MdnsInstance, 0);

                is_connected = false;
            }
        }

        /* Sleep before checking link status again */
        tx_thread_sleep(polling_interval);
    }
}
