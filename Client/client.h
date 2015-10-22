#ifndef CLIENT_HEADER
#define CLIENT_HEADER

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <errno.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <semaphore.h>
#include <termios.h>
#include <ctype.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "../Shared/key_storage.h"
#include "../Shared/cryptography.h"
#include "../Shared/packet_definition.h"

char *program_name = "Client";

#define PORT_MAX 								(65533)
#define NUM_CERT_READ_ATTEMPTS 					(10)
#define NUM_BIND_ATTEMPTS 						(5)
#define MAX_SEND_ATTEMPTS 						(5)

#define PUBLIC_KEY_CERT_SIZE					(426)
#define CONVERSATION_NAME_MAX_LENGTH 			(128)
#define USER_NAME_MIN_LENGTH 					(4)
#define USER_NAME_MAX_LENGTH 					(128)
#define RELAY_POOL_MAX_SIZE						(20)
#define MAX_CONVERSATIONS						(32)
#define RELAY_IP_MAX_LENGTH						(16)
#define RELAY_ID_LEN 							((SHA256_DIGEST_LENGTH * 2) + 1)

#define MINIMUM_NUM_RELAYS_REQ_FOR_REGISTER 	(2)

const char *public_cert_dir = ".relay_certs";

typedef enum {
	REGISTER_USER_ID_WITH_ENTRY_RELAY = 0,
	REGISTER_USER_ID_WITH_RELAY,
	DUMMY_PACKET
} packet_type;

typedef struct relay_indexer_info
{
	char *ip_address;
	RSA *public_cert;
} relay_indexer_info;

typedef struct relay_info
{
	int is_active;
	char relay_id[RELAY_ID_LEN];
	char relay_ip[RELAY_IP_MAX_LENGTH];
	unsigned char aes_key[AES_KEY_SIZE_BYTES];
	unsigned int relay_user_id;
	RSA *public_cert;
} relay_info;

typedef struct conversation_info
{
	int conversation_valid;
	char conversation_name[CONVERSATION_NAME_MAX_LENGTH];
	char friend_name[USER_NAME_MAX_LENGTH];
	int index_of_server_relay;
	int index_of_entry_relay;
	relay_info ri_pool[RELAY_POOL_MAX_SIZE];
} conversation_info;

typedef struct route_info
{
	int relay_route[MAX_ROUTE_LENGTH];
	int route_length;
} route_info;

int get_friend_id(char *friend_id /* out */);
int init_chat(char *friend_name, conversation_info *ci_out /* out */);
int get_relay_public_certificates_debug(conversation_info *ci_info);
int set_entry_relay_for_conversation(conversation_info *ci_info);
int set_relay_keys_for_conversation(conversation_info *ci_info);
int set_user_ids_for_conversation(conversation_info *ci_info);
int perform_user_id_registration(conversation_info *ci_info);
int get_index_of_next_free_conversation(conversation_info *conversations);
int send_packet(packet_type type, conversation_info *ci_info, route_info *r_info, char *msg, void *other);
int create_packet(packet_type type, conversation_info *ci_info, route_info *r_info, char *msg, void *other, unsigned char *packet, char *destination_ip, int *destination_port);
int send_packet_to_relay(unsigned char *packet, char *destination_ip, int destination_port);
int generate_new_user_id(unsigned int *uid /* out */);
int is_valid_ip(char *ip, int *valid /* out */);
int print_conversation(char *thread_id, conversation_info *ci_info);
char* get_packet_type_str(packet_type type);

#endif