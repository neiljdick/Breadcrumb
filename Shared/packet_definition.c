#include "packet_definition.h"

#define ENABLE_LOGGING

const unsigned int packet_size_bytes = (((ONION_ROUTE_DATA_SIZE * MAX_ROUTE_LENGTH) * 2) + (sizeof(payload_data)));
const unsigned int payload_start_byte = (MAX_ROUTE_LENGTH * sizeof(onion_route_data));
const unsigned int cipher_text_byte_offset = offsetof(onion_route_data, ord_enc);
const unsigned int max_payload_len = (PACKET_SIZE_BYTES - (2 * (MAX_ROUTE_LENGTH * sizeof(onion_route_data))));

int initialize_packet_definitions(char *thread_id)
{
	if(ONION_ROUTE_DATA_SIZE != sizeof(onion_route_data)) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Onion route struct has been padded incorrectly, size = %lu, correct size = %u\n", thread_id, 
				(long unsigned int)sizeof(onion_route_data), ONION_ROUTE_DATA_SIZE);
		#endif

		return -1;
	}

	return 0;
}

void print_packet_definitions(void)
{
	fprintf(stdout, "Packet size bytes = %u\n", packet_size_bytes);
	fprintf(stdout, "Size of struct 'onion_route_data_encrypted' = %lu\n", (long unsigned int)sizeof(onion_route_data_encrypted));
	fprintf(stdout, "Size of struct 'onion_route_data' = %lu\n", (long unsigned int)sizeof(onion_route_data));
	fprintf(stdout, "Size of struct 'id_cache_data' = %lu\n", (long unsigned int)sizeof(id_cache_data));
	fprintf(stdout, "Size of struct 'payload_start_byte' = %u\n", payload_start_byte);
	fprintf(stdout, "Onion route data size = %u\n", ONION_ROUTE_DATA_SIZE);
}

int print_or_data(char *thread_id, onion_route_data *or_data)
{
	int i;

	if(or_data == NULL) {
		return -1;
	}

	fprintf(stdout, "%s Onion Route IV = ", thread_id);
	for(i = 0; i < AES_KEY_SIZE_BYTES; i++) {
		fprintf(stdout, "%02x", (0xff & or_data->iv[i]));
	}
	fprintf(stdout, "\n%s Onion Route UID = %u\n", thread_id, or_data->uid);
	fprintf(stdout, "%s Onion Route ENC = ", thread_id);
	for(i = 0; i < sizeof(onion_route_data_encrypted); i++) {
		fprintf(stdout, "%02x", (0xff & ((char *)&(or_data->ord_enc))[i]));
	}
	fprintf(stdout, "\n");

	return 0;
}

char* get_string_for_payload_type(payload_type type)
{
	switch(type) {
		case DUMMY_PACKET_NO_RETURN_ROUTE:	return "DUMMY_PACKET_NO_RETURN_ROUTE";
		case DUMMY_PACKET_W_RETURN_ROUTE:	return "DUMMY_PACKET_W_RETURN_ROUTE";
		case SINGLE_RETURN_ROUTE:			return "SINGLE_RETURN_ROUTE";
		case DUAL_RETURN_ROUTE:				return "DUAL_RETURN_ROUTE";
		case MESSAGE_PACKET:				return "MESSAGE_PACKET";
	}

	#ifdef ENABLE_LOGGING
		fprintf(stdout, "Found unknown packet type = 0x%x\n", 0xffff & type);
	#endif

	return "UNKNOWN";
}