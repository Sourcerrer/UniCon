/*
 * my_mdns.cpp
 *
 *  Created on: Nov 12, 2025
 *      Author: alpl_
 */
#include <iostream>
#include <cstdint>
#include "tx_api.h"

#include "my_mdns.h"
#include "app_mdns.h"

/* START mDNS variables */
static TX_THREAD AppMdnsThread;
static CHAR AppMdnsThreadName[] = "App Mdns thread";
//static TX_THREAD AppMain2Thread;
//static CHAR AppMain2ThreadName[] = "App Main2 thread";
//static __IO bool AppMain2ThreadRunning = true;
NX_MDNS MdnsInstance;
static UCHAR LocalServiceCache[MDNS_LOCAL_CACHE_SIZE];
static UCHAR PeerServiceCache[MDNS_PEER_CACHE_SIZE];
static VOID App_Mdns_Thread_Entry(ULONG thread_input);
constexpr static char mdns_host_name[] = "ppmt-v6";

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
	/* Set the cache notify callback function.  */
	uint16_t ret = nx_mdns_cache_notify_set(&MdnsInstance, cache_full_notify);

	if (ret != NX_SUCCESS)
	{
//		Error_Handler();/
		std::cout << "Error setting cache full notification"<< std::endl;
	}

#ifndef NX_MDNS_DISABLE_CLIENT
	/* Set the service change callback function to listen the service.  */
	ret = nx_mdns_service_notify_set(&MdnsInstance, service_mask, service_change_notify);

	if (ret != NX_SUCCESS)
	{
//		Error_Handler();
		std::cout << "Error setting service change notification"<< std::endl;
	}
#endif /* NX_MDNS_DISABLE_CLIENT  */
	return ret;  // Return success
}


/* @brief mdns init */

UINT mdns_init( void *byte_pool, NX_IP *ip_instance, NX_PACKET_POOL *packet_pool)
{
//  UINT status;

//  /* Initialize the mDNS instance. */
//  status = nx_mdns_create(&MdnsInstance, ip_instance, "stm32h5_mdns",
//		  NX_MDNS_DEFAULT_TTL, MDNS_PACKET_POOL_SIZE, MDNS_STACK_SIZE, MDNS_PRIORITY);
//  if (status != NX_MDNS_SUCCESS)
//  {
//	MSG_ERROR("mDNS creation failed: %u\n", status);
//	return status;
//  }
//
//  /* Start the mDNS instance. */
//  status = nx_mdns_start(&MdnsInstance);
//  if (status != NX_MDNS_SUCCESS)
//  {
//	MSG_ERROR("mDNS start failed: %u\n", status);
//	return status;
//  }
//
//  return NX_MDNS_SUCCESS;

  /***********************************************************/
  const ULONG stack_size = NETX_MDNS_THREAD_STACK_SIZE;
  VOID *stack_ptr;

  if (tx_byte_allocate(static_cast<TX_BYTE_POOL *>(byte_pool),
		  	  	  	  	  (VOID **) &stack_ptr, stack_size, TX_NO_WAIT) != TX_SUCCESS)
  {
    return TX_POOL_ERROR;
  }

  /* Create the MDNS instance. */
  UINT ret = nx_mdns_create(&MdnsInstance, ip_instance, packet_pool,
                       NETX_MDNS_THREAD_PRIORITY, stack_ptr, stack_size,
                       (UCHAR *)mdns_host_name,
                       (VOID *)LocalServiceCache, sizeof(LocalServiceCache),
                       (VOID *)PeerServiceCache, sizeof(PeerServiceCache), probing_notify);

  if (ret != NX_SUCCESS)
  {
    return NX_NOT_ENABLED;
  }
//  MSG_DEBUG("nx_mdns_create() done\n");
  std::cout << "nx_mdns_create() done" << std::endl;

  /* Allocate the memory for MDNS thread. */
  {
    const ULONG stack_size = APP_MDNS_THREAD_STACK_SIZE;
    VOID *stack_ptr;

    if (tx_byte_allocate(static_cast<TX_BYTE_POOL *>(byte_pool), &stack_ptr, stack_size, TX_NO_WAIT) != TX_SUCCESS)
    {
      return TX_POOL_ERROR;
    }

    /* Create the App MDNS thread. */
    ret = tx_thread_create(&AppMdnsThread, AppMdnsThreadName,
    						App_Mdns_Thread_Entry,reinterpret_cast<ULONG>(byte_pool),
							stack_ptr, stack_size,
                           APP_MDNS_THREAD_PRIORITY, APP_MDNS_THREAD_PRIORITY, TX_NO_TIME_SLICE, TX_DONT_START);

    if (ret != TX_SUCCESS)
    {
      return NX_NOT_ENABLED;
    }
    std::cout << "mdns_thread() done" << std::endl;
//    MSG_DEBUG("mdns_thread() done\n");
  }
  return NX_SUCCESS;
}


TX_EVENT_FLAGS_GROUP mdns_event_group;
/**
  * @brief App MDNS thread entry.
  * @param thread_input: ULONG user argument used by the thread entry
  * @retval none
  */
static VOID App_Mdns_Thread_Entry(ULONG thread_input)
{
//  TX_BYTE_POOL *const byte_pool = (TX_BYTE_POOL *) thread_input;
	const TX_BYTE_POOL *const byte_pool = reinterpret_cast<TX_BYTE_POOL *>(thread_input);
  UINT ret = NX_SUCCESS;
  MDNS_TESTCASES testcase;
  const ULONG ticksFor2s = (2 * TX_TIMER_TICKS_PER_SECOND);
  const ULONG ticksFor5s = (5 * TX_TIMER_TICKS_PER_SECOND);
  const ULONG ticksFor8s = (8 * TX_TIMER_TICKS_PER_SECOND);
  ULONG actual_events;
//  MSG_DEBUG(">\n");
  std::cout << ">\n";

  /* Share the byte pool with the future needs. */
//  AppBytePool = byte_pool;
  UINT status = TX_SUCCESS;
  status =  tx_event_flags_create(&mdns_event_group, "mdns_event_flags");

  testcase = MDNS_START;
  tx_thread_sleep(ticksFor8s);
  /* start mDNS */
  ret = nx_mdns_enable(&MdnsInstance, 0);

  /* Check for mdns to be enables*/
  /* Wait for host name register. */
  tx_thread_sleep(ticksFor5s);

  /* Register / announce HTTP service */
//  log_i("\n\nStarting http_Announce_Service_ ...\r\n");
//  log_i("Registering HTTP service...\r\n");
  std::cout << "\n\nStarting http_Announce_Service_ ...\r\n"
		    << "Registering HTTP service..." << std::endl;

  /* Register HTTP service */
  register_local_service((UCHAR *)SERVICE_INSTANCE_NAME_HTTP, (UCHAR *)SERVICE_NAME,
                         SERVICE_SUBTYPE_NULL, (UCHAR *)SERVICE_TXT_INFO, SERVICE_TTL,
                         SERVICE_PRIORITY, SERVICE_WEIGHT, SERVICE_PORT, NX_TRUE);

  if (ret != NX_SUCCESS) {
	  std::cout << "mDNS service add failed: 0x"<< std::hex << ret << std::dec << std::endl;
//      MSG_INFO("mDNS service add failed: 0x%x\r\n", ret);
//      Error_Handler();
  }

//  log_i("mDNS started: %s.local, service %s.%s.local:%u\r\n",
//		  mdns_host_name, SERVICE_INSTANCE_NAME_HTTP, SERVICE_NAME, SERVICE_PORT);
  std::cout << "mDNS started: " << mdns_host_name << ".local, service "
		    << SERVICE_INSTANCE_NAME_HTTP << "." << SERVICE_NAME << ".local:" << SERVICE_PORT << std::endl;

//  tx_thread_sleep(ticksFor5s);
//  delete_local_service( (UCHAR *)SERVICE_INSTANCE_NAME_HTTP, (UCHAR *)SERVICE_NAME,
//          			  SERVICE_SUBTYPE_NULL);
//  tx_thread_sleep(ticksFor5s);
//  delete_all_services( (UCHAR *)SERVICE_INSTANCE_NAME_HTTP, (UCHAR *)SERVICE_NAME,
//  		  SERVICE_SUBTYPE_NULL );
  /* Infinite loop */
  for (;;)
  {
	  tx_thread_sleep(ticksFor8s);
//	  status = tx_event_flags_get(&mdns_event_group, 0x11, TX_OR_CLEAR, &actual_events, 2 * ticksFor8s);
//
//	  if(status == TX_SUCCESS && false)
//	  {
//		  delete_local_service((UCHAR *)SERVICE_INSTANCE_NAME_HTTP, (UCHAR *)SERVICE_NAME, SERVICE_SUBTYPE_NULL);
//		  /* delete all services */
//		  delete_all_services((UCHAR *)SERVICE_INSTANCE_NAME_HTTP, (UCHAR *)SERVICE_NAME, SERVICE_SUBTYPE_NULL);
//		  tx_thread_sleep(ticksFor2s);
//
//		  nx_mdns_disable(&MdnsInstance, 0); // Disable mDNS service
//
//		  tx_thread_sleep(ticksFor5s);
//		  /* start mDNS */
//		  ret = nx_mdns_enable(&MdnsInstance, 0);
//
//		  /* Check for mdns to be enables*/
//		  /* Wait for host name register. */
//		  tx_thread_sleep(ticksFor5s);
//
//		  /* Register / announce HTTP service */
////		  log_i("\n\nStarting http_Announce_Service_ ...\r\n");
//		  std::cout << "\n\nStarting http_Announce_Service_ ...\r\n"
//				    << "Registering HTTP service..." << std::endl;
////		  log_i("Registering HTTP service...\r\n");
//
//		  /* Register HTTP service */
//		  register_local_service((UCHAR *)SERVICE_INSTANCE_NAME_HTTP, (UCHAR *)SERVICE_NAME,
//				  SERVICE_SUBTYPE_NULL, (UCHAR *)SERVICE_TXT_INFO, SERVICE_TTL,
//				  SERVICE_PRIORITY, SERVICE_WEIGHT, SERVICE_PORT, NX_TRUE);
//
//		  if (ret != NX_SUCCESS) {
////			  log_i("mDNS service add failed: 0x%x\r\n", ret);
//			  std::cout << "mDNS service add failed: 0x"<< std::hex << ret << std::dec << std::endl;
////			  Error_Handler();
//		  }
//
////		  log_i("mDNS started: %s.local, service %s.%s.local:%u\r\n",
////				  mdns_host_name, SERVICE_INSTANCE_NAME_HTTP, SERVICE_NAME, SERVICE_PORT);
//		  std::cout << "mDNS started: " << mdns_host_name << ".local, service "
//				    << SERVICE_INSTANCE_NAME_HTTP << "." << SERVICE_NAME << ".local:" << SERVICE_PORT << std::endl;
//		  tx_thread_sleep(ticksFor5s);
//	  }
//	  perform_oneshot_query( (UCHAR *)SERVICE_INSTANCE_NAME_HTTP, (UCHAR *)SERVICE_NAME,
//							  SERVICE_SUBTYPE_NULL, 1000);
  }
}



