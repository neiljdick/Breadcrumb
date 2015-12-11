#ifndef PACKET_DEFINITION_HEADER
#define PACKET_DEFINITION_HEADER

#include <stdint.h>
#include <stddef.h>

#include "key_storage.h"

#define MIN_ROUTE_LENGTH 						(2)
#define MIN_RETURN_ROUTE_LENGTH					(1)
#define MAX_ROUTE_LENGTH 						(3)
#define ONION_ROUTE_DATA_SIZE 					((AES_KEY_SIZE_BYTES * 2) + 32)
#define PAYLOAD_SIZE_BYTES 						((ONION_ROUTE_DATA_SIZE * MAX_ROUTE_LENGTH) * 2)
#define PACKET_SIZE_BYTES 						(((ONION_ROUTE_DATA_SIZE * MAX_ROUTE_LENGTH) * 2) + (sizeof(payload_data)))
#define MESSAGE_OFFSET	 						(ONION_ROUTE_DATA_SIZE * 2)

extern const unsigned int payload_start_byte;
extern const unsigned int cipher_text_byte_offset;
extern const unsigned int max_payload_len;
extern const unsigned int packet_size_bytes;

typedef enum payload_type {
	DUMMY_PACKET_NO_RETURN_ROUTE = 0,
	DUMMY_PACKET_W_RETURN_ROUTE,
	SINGLE_RETURN_ROUTE,
	DUAL_RETURN_ROUTE,
	MESSAGE_PACKET
} payload_type;

typedef struct onion_route_data_encrypted
{
	uint64_t next_pkg_ip;
	uint16_t next_pkg_port;
	uint16_t ord_checksum;
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
	uint8_t payload_aes_key[AES_KEY_SIZE_BYTES];
	uint32_t payload_relay_user_id;
	uint8_t return_route_aes_key[AES_KEY_SIZE_BYTES];
	uint32_t return_route_user_id;
	uint8_t return_route_payload_aes_key[AES_KEY_SIZE_BYTES];
	uint32_t return_route_payload_user_id;
	uint8_t incoming_msg_aes_key[AES_KEY_SIZE_BYTES];
	uint32_t incoming_msg_relay_user_id;
	uint8_t outgoing_msg_aes_key[AES_KEY_SIZE_BYTES];
	uint32_t outgoing_msg_relay_user_id;
	uint64_t padding_rsa_1024;
} id_cache_data;

typedef struct payload_data
{
	uint16_t type;
	uint16_t onion_r1;
	uint16_t onion_r2;
	uint16_t order;
	uint32_t client_id;
	uint32_t conversation_id;
	uint8_t payload[PAYLOAD_SIZE_BYTES];
} payload_data;

int initialize_packet_definitions(char *thread_id);
int get_ord_packet_checksum(onion_route_data_encrypted *ord_enc, uint16_t *ord_checksum);
void print_packet_definitions(void);
int print_or_data(char *thread_id, onion_route_data *or_data);
char* get_string_for_payload_type(payload_type type);

#endif