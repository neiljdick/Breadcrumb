#ifndef NETWORKING_HEADER
#define NETWORKING_HEADER

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#ifdef _WIN32
	#include <winsock2.h>
	#define snprintf _snprintf
#else
	#include <netinet/in.h>
#endif
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <linux/if_link.h>

#include <miniupnpc/miniwget.h>
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>
#include <miniupnpc/declspec.h>
#include <miniupnpc/igd_desc_parse.h>
#include <miniupnpc/miniupnpctypes.h>
#include <miniupnpc/portlistingparse.h>
#include <miniupnpc/upnpreplyparse.h>

#define UPNP_LOCAL_PORT_ANY		(0)

#ifndef PORT_MAX
	#define PORT_MAX 							(65533)
#endif
#ifndef PORT_MIN
	#define PORT_MIN 							(16384)
#endif

#define IP_BUF_MAX_LEN 			(64)

#define TCP_BYTE_OVERHEAD 		(66)

int get_public_ip_address(char *thread_id, char *public_ip_addr, int public_ip_buf_len);
int get_lan_ip_address(char *thread_id, char *public_ip_addr, int public_ip_buf_len);
int get_eth_ip_address(char *thread_id, char *eth_ip_addr, int eth_ip_buf_len);
int add_port_mapping(char *thread_id, unsigned int port, char *protocol);
int get_is_port_mapped(char *thread_id, unsigned int port, char *protocol, unsigned int *is_mapped);

#endif