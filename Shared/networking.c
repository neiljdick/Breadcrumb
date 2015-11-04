#include "networking.h"

#define ENABLE_LOGGING
//#define DEBUG_MODE

static int is_upnp_init=0;

struct UPNPDev *devlist;
struct UPNPUrls urls;
struct IGDdatas data;
char lanaddr[64];

static int init_globals(void)
{
	devlist = NULL;
	memset(lanaddr, 0, sizeof(lanaddr));

	return 0;
}

static int init_upnp(char *thread_id)
{
  	int ret;
  	const char * multicastif = 0;
	const char * minissdpdpath = 0;
	int error;
	struct UPNPDev *device;

	if(is_upnp_init != 0) {
		return 0;
	}
	init_globals();

	#ifdef ENABLE_LOGGING
		fprintf(stdout, "%s Initializing UPNP\n", thread_id);
	#endif

	devlist = upnpDiscover(2000, multicastif, minissdpdpath, UPNP_LOCAL_PORT_ANY, 0, &error);
 	if(devlist == NULL) {
 		#ifdef ENABLE_LOGGING
 			fprintf(stdout, "%s Failed to initialize upnp\n", thread_id);
 		#endif

 		return -1;
 	}

	#ifdef ENABLE_LOGGING
		fprintf(stdout, "%s List of UPNP devices found on the network:\n", thread_id);
	#endif
	for(device = devlist; device; device = device->pNext) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Desc: %s, st: %s\n", thread_id, device->descURL, device->st);
		#endif

		ret = UPNP_GetValidIGD(device, &urls, &data, lanaddr, sizeof(lanaddr));
		if(ret == 1) {
	 		break;
	 	}
	}
	if(device == NULL) {
		#ifdef ENABLE_LOGGING
 			fprintf(stdout, "%s Failed to initialize upnp\n", thread_id);
 		#endif

		return -1;
	}

 	is_upnp_init = 1;

 	return 0;
}

int get_public_ip_address(char *thread_id, char *public_ip_addr, int public_ip_buf_len)
{
	int ret;

	if(public_ip_addr == NULL) {
		return -1;
	}
	if(public_ip_buf_len < 64) {
		return -1;
	}

	ret = init_upnp(thread_id);
	if(ret < 0) {
		return -1;
	}

	ret = UPNP_GetExternalIPAddress(urls.controlURL, data.first.servicetype, public_ip_addr);
	if(ret != UPNPCOMMAND_SUCCESS) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Failed to get public ip address\n", thread_id);
		#endif

		return -1;
	}
	#ifdef ENABLE_LOGGING
		fprintf(stdout, "%s Got public ip address: %s\n", thread_id, public_ip_addr);
	#endif

	return 0;
}

int get_lan_ip_address(char *thread_id, char *lan_ip_addr, int lan_ip_buf_len)
{
	int ret;

	if(lan_ip_addr == NULL) {
		return -1;
	}
	if(lan_ip_buf_len < sizeof(lanaddr)) {
		return -1;
	}

	ret = init_upnp(thread_id);
	if(ret < 0) {
		return -1;
	}

	memcpy(lan_ip_addr, lanaddr, sizeof(lanaddr));
	#ifdef ENABLE_LOGGING
		fprintf(stdout, "%s Got lan ip address: %s\n", thread_id, lan_ip_addr);
	#endif

	return 0;
}

int get_eth_ip_address(char *thread_id, char *eth_ip_addr, int eth_ip_buf_len)
{
	const char *eth_str = "eth";
	int ret, family, found_eth_ip;
	unsigned int size;
	struct ifaddrs *ifaddr, *ifa;
	char host[NI_MAXHOST];
	struct in_addr in_addr_tmp;

	if(eth_ip_addr == NULL) {
		return -1;
	}
	if(eth_ip_buf_len < 64) {
		return -1;
	}

	ret = getifaddrs(&ifaddr);
	if(ret < 0) {
		return -1;
	}

	found_eth_ip = 0;
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;

		family = ifa->ifa_addr->sa_family;
		if (family == AF_INET || family == AF_INET6) {
			size = (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
			ret = getnameinfo(ifa->ifa_addr, size, host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
			if (ret == 0) {
				ret = strncasecmp(ifa->ifa_name, eth_str, strlen(eth_str));
				if(ret == 0) {
					ret = inet_aton(host, &in_addr_tmp);
					if(ret != 0) {
						memcpy(eth_ip_addr, host, 64);
						found_eth_ip = 1;
						break;
					}
				}
			}
		}
	}
	freeifaddrs(ifaddr);

	if(found_eth_ip == 0) {
		return -1;
	}
	#ifdef ENABLE_LOGGING
		fprintf(stdout, "%s Got eth ip address: %s\n", thread_id, eth_ip_addr);
	#endif

	return 0;
}

int add_port_mapping(char *thread_id, unsigned int port, char *protocol)
{
	int ret;
	char port_buf[64], intClient[40], intPort[6], duration[16];

	if(thread_id == NULL) {
		return -1;
	}
	if(port > PORT_MAX) {
		return -1;
	}
	if(protocol == NULL) {
		return -1;
	}
	sprintf(port_buf, "%u", port);

	ret = init_upnp(thread_id);
	if(ret < 0) {
		return -1;
	}

	ret = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype, port_buf, port_buf, lanaddr, NULL, protocol, 0, "0");
	if(ret != UPNPCOMMAND_SUCCESS) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Failed to add port mapping, error = %s\n", thread_id, strupnperror(ret));
		#endif

		return -1;
	}

	ret = UPNP_GetSpecificPortMappingEntry(urls.controlURL, data.first.servicetype, port_buf, protocol, intClient, intPort, NULL, NULL, duration);
	if(ret != UPNPCOMMAND_SUCCESS) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Failed to get specific port mapping entry, error = %s\n", thread_id, strupnperror(ret));
		#endif

		return -1;
	}
	#ifdef ENABLE_LOGGING
		fprintf(stdout, "%s Successfully mapped external port %s (%s) to internal %s:%s (duration=%s)\n", thread_id, port_buf, protocol, intClient, intPort, duration);
	#endif

	return 0;
}

int get_is_port_mapped(char *thread_id, unsigned int port, char *protocol, unsigned int *is_mapped)
{
	int ret;
	char port_buf[64], intClient[40], intPort[6], duration[16];

	if(thread_id == NULL) {
		return -1;
	}
	if(port > PORT_MAX) {
		return -1;
	}
	if(protocol == NULL) {
		return -1;
	}
	if(is_mapped == NULL) {
		return -1;
	}
	sprintf(port_buf, "%u", port);

	ret = UPNP_GetSpecificPortMappingEntry(urls.controlURL, data.first.servicetype, port_buf, protocol, intClient, intPort, NULL, NULL, duration);
	if(ret != UPNPCOMMAND_SUCCESS) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Found port %u unmapped\n", thread_id, port);
		#endif

		*is_mapped = 0;
	} else {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Found port %u is mapped\n", thread_id, port);
		#endif

		*is_mapped = 1;
	}

	return 0;
}

#ifdef DEBUG_MODE
	
int main(int argc, char const *argv[])
{
	unsigned int is_mapped;
	char external_ip_addr[64], lan_ip_addr[64];
	char eth_ip_addr[64];

	get_lan_ip_address("[MAIN THREAD]", lan_ip_addr, sizeof(lan_ip_addr));
	get_public_ip_address("[MAIN THREAD]", external_ip_addr, sizeof(external_ip_addr));
	get_eth_ip_address("[MAIN THREAD]", eth_ip_addr, sizeof(eth_ip_addr));
	add_port_mapping("[MAIN THREAD]", 54545, "TCP");

	get_is_port_mapped("[MAIN THREAD]", 54545, "TCP", &is_mapped);
	get_is_port_mapped("[MAIN THREAD]", 54546, "TCP", &is_mapped);
	
	return 0;
}

#endif