#ifndef _NET_ETHERNET_H
#define _NET_ETHERNET_H

#include <stdint.h>
#include <mlibc-config.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __MLIBC_LINUX_OPTION
#	include <linux/if_ether.h>
#endif

struct ether_addr {
	uint8_t ether_addr_octet[6];
} __attribute__ ((__packed__));

#ifdef __cplusplus
}
#endif

#endif
