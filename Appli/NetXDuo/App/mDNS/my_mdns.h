/*
 * my_mdns.h
 *
 *  Created on: Nov 12, 2025
 *      Author: alpl_
 */

#ifndef APP_MDNS_MY_MDNS_H_
#define APP_MDNS_MY_MDNS_H_

#include "nx_api.h"


#define APP_MDNS_THREAD_STACK_SIZE           (4096)
#define APP_MDNS_THREAD_PRIORITY             (13)

#define NETX_MDNS_THREAD_STACK_SIZE          (4096)
#define NETX_MDNS_THREAD_PRIORITY            (12)

#ifdef __cplusplus

extern "C" {
UINT mdns_init( void *byte_pool, NX_IP *ip_instance, NX_PACKET_POOL *packet_pool);
uint16_t Set_mdns_Notifications(void);
TX_THREAD *get_mdns_thread_instance(void);
//uint16_t app_udp_server_init( void *byte_pool, NX_IP *ip_instance, NX_PACKET_POOL *packet_pool);
//TX_THREAD* get_udp_server_thread_instance(void);
}
#endif

//extern NX_MDNS MdnsInstance;

//VOID probing_notify(struct NX_MDNS_STRUCT *mdns_ptr, UCHAR *name, UINT state);
//VOID cache_full_notify(NX_MDNS *mdns_ptr, UINT state, UINT cache_type);
//VOID service_change_notify(NX_MDNS *mdns_ptr, NX_MDNS_SERVICE *service_ptr, UINT state);


//VOID registerlocal_service(UCHAR *instance, UCHAR *type, UCHAR *subtype, UCHAR *txt, UINT ttl,
//                            USHORT priority, USHORT weight, USHORT port, UCHAR is_unique);
//VOID delete_local_service(UCHAR *instance, UCHAR *type, UCHAR *subtype);
//VOID delete_all_services(UCHAR *instance, UCHAR *type, UCHAR *subtype);
//VOID perform_oneshot_query(UCHAR *instance, UCHAR *type, UCHAR *subtype, UINT timeout);
//VOID start_continous_query(UCHAR *instance, UCHAR *type, UCHAR *subtype);
#endif /* APP_MDNS_MY_MDNS_H_ */
