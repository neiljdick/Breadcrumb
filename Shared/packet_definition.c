#include "packet_definition.h"

#define ENABLE_LOGGING

const unsigned int payload_start_byte = (MAX_ROUTE_LENGTH * sizeof(onion_route_data));

int initialize_packet_definitions(char *thread_id)
{
	if(ONION_ROUTE_DATA_SIZE != sizeof(onion_route_data)) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Onion route struct has been padded incorrectly, size = %lu, correct size = %u\n", thread_id, sizeof(onion_route_data), ONION_ROUTE_DATA_SIZE);
		#endif

		return -1;
	}

	return 0;
}

void print_packet_definitions(void)
{
	fprintf(stdout, "Packet size bytes = %u\n", PACKET_SIZE_BYTES);
	fprintf(stdout, "Size of struct 'onion_route_data_encrypted' = %lu\n", sizeof(onion_route_data_encrypted));
	fprintf(stdout, "Size of struct 'onion_route_data' = %lu\n", sizeof(onion_route_data));
	fprintf(stdout, "Size of struct 'id_cache_data' = %lu\n", sizeof(id_cache_data));
	fprintf(stdout, "Size of struct 'payload_start_byte' = %u\n", payload_start_byte);
	fprintf(stdout, "Onion route data size = %u\n", ONION_ROUTE_DATA_SIZE);
}