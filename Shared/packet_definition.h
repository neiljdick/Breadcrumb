#ifndef PACKET_DEFINITION_HEADER
#define PACKET_DEFINITION_HEADER

#include <stdint.h>
#include <stddef.h>

#include "key_storage.h"

#define MAX_ROUTE_LENGTH 						(3)
#define PACKET_SIZE_BYTES						(512)

#define ONION_ROUTE_DATA_SIZE 					((AES_KEY_SIZE_BYTES * 2) + 32)

extern const unsigned int payload_start_byte;
extern const unsigned int cipher_text_byte_offset;

typedef struct onion_route_data_encrypted
{
	uint64_t next_pkg_ip;
	uint16_t next_pkg_port;
	uint16_t align_filler1;
	uint32_t new_uid;
	uint8_t new_key[AES_KEY_SIZE_BYTES];
} onion_route_data_encrypted;

typedef struct onion_route_data
{
	uint8_t iv[AES_KEY_SIZE_BYTES];
	uint32_t uid;
	uint32_t align_filler1;
	uint64_t align_filler2;
	onion_route_data_encrypted ord_enc;
} onion_route_data;

typedef struct id_cache_data
{
	uint8_t aes_key[AES_KEY_SIZE_BYTES];
	uint32_t relay_user_id;
} id_cache_data;

int initialize_packet_definitions(char *thread_id);
void print_packet_definitions(void);
int print_or_data(char *thread_id, onion_route_data *or_data);

#endif