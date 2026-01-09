/*
 * netx_util.h
 *
 *  Created on: 07-Jan-2026
 *      Author: alpl_
 */

#ifndef APP_NETX_UTILS_INC_NETX_UTIL_H_
#define APP_NETX_UTILS_INC_NETX_UTIL_H_

#include "nx_api.h"
#include "nxd_dns.h"

/* Exported functions */
bool Get_Public_IP(NX_IP *ip_ptr, NX_PACKET_POOL *pool_ptr, NX_DNS *dns_ptr);


#endif /* APP_NETX_UTILS_INC_NETX_UTIL_H_ */
