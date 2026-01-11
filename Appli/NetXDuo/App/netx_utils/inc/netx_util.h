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
#include <iostream>


/* Printing IP address helper ********************/
/* 1. Helper Struct (Safe in header)
 * no need for typedef like in c language since
 * In C++, struct names are automatically types.*/
struct IpFmt { ULONG ip; };

/* 2. Operator: Use 'inline' so it can be included multiple times safely */
inline std::ostream& operator<<(std::ostream& os, const IpFmt& p) {
    return os << " IP [ " << ((p.ip >> 24) & 0xFF) << "."
              << ((p.ip >> 16) & 0xFF) << "."
              << ((p.ip >> 8)  & 0xFF) << "."
              << (p.ip & 0xFF)
			  << " ] ";
}

/* 3. Converter: Use an inline function instead of a global lambda variable.
      This does the exact same thing but is safe for headers.

      @usage note call from std::cout
      @example std::cout << format_ip()  */
inline IpFmt format_ip(ULONG ip) {
    return IpFmt{ip};
}

/************************************************/
/* Exported functions */
#ifdef __cplusplus
extern "C" {
bool Get_Public_IP(NX_IP *ip_ptr, NX_PACKET_POOL *pool_ptr, NX_DNS *dns_ptr);
}
#endif


#endif /* APP_NETX_UTILS_INC_NETX_UTIL_H_ */
