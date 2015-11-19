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
#include <signal.h>

#include "../Shared/key_storage.h"
#include "../Shared/cryptography.h"
#include "../Shared/packet_definition.h"
#include "../Shared/networking.h"

char *program_name = "Client";

#ifndef PORT_MAX
	#define PORT_MAX 							(65533)
#endif
#define NUM_CERT_READ_ATTEMPTS 					(10)
#define NUM_BIND_ATTEMPTS 						(5)
#define MAX_SEND_ATTEMPTS 						(5)
#define MAIN_THREAD_SLEEP_TIME					(5)
#define MAX_READ_ATTEMPTS 						(5)
#define LISTEN_BACKLOG_MAX 						(5)

#define PACKET_TRANSMISSION_DELAY				(3)
#define MINIMUM_NUM_RELAYS_REQ_FOR_REGISTER 	(3)

#define PUBLIC_KEY_CERT_SIZE					(426)
#define CONVERSATION_NAME_MAX_LENGTH 			(128)
#define USER_NAME_MIN_LENGTH 					(4)
#define USER_NAME_MAX_LENGTH 					(128)
#define RELAY_POOL_MAX_SIZE						(20)
#define MAX_CONVERSATIONS						(32)
#define RELAY_IP_MAX_LENGTH						(16)
#define RELAY_ID_LEN 							((SHA256_DIGEST_LENGTH * 2) + 1)
#define PATH_HISTORY_LENGTH						(20)
#define MAX_UID_HISTORY_RECONNECT_ATTEMPTS 		(3)

#define MSG_PORT_PROTOCOL						("TCP")

#define THREAD_COMMAND_DATA_SIZE 				(512)
#define THREAD_RETURN_PACKET_CONFIRM_SIZE		(64)
#define MAX_CHECK_NODE_TIME_SEC					(6)
#define MAX_VERIFY_ROUTE_TIME_SEC				(6)

const char *public_cert_dir = ".relay_certs";

typedef enum {
	REGISTER_UIDS_WITH_ENTRY_RELAY = 0,
	REGISTER_UIDS_WITH_RELAY,
	DUMMY_PACKET,
	DUMMY_PACKET_USING_RETURN_ROUTE_KEY_UID_PAIRS,
	DUMMY_PACKET_USING_RETURN_ROUTE_KEY_UID_PAIRS_FOR_VERIFICATION
} packet_type;

typedef enum {
	DISABLE_HISTORY = 0,
	ENABLE_HISTORY
} history_type;

typedef enum {
	VERIFY_USING_FORWARD_KEY_UID_PAIR = 0,
	VERIFY_USING_RETURN_KEY_UID_PAIR
} verification_type;

typedef struct relay_indexer_info
{
	char *ip_address;
	RSA *public_cert;
} relay_indexer_info;

typedef struct id_key_info
{
	unsigned char aes_key[AES_KEY_SIZE_BYTES];
	unsigned int relay_user_id;
	unsigned char payload_aes_key[AES_KEY_SIZE_BYTES];
	unsigned int payload_relay_user_id;
	unsigned char return_route_aes_key[AES_KEY_SIZE_BYTES];
	unsigned int return_route_user_id;
	unsigned char return_route_payload_aes_key[AES_KEY_SIZE_BYTES];
	unsigned int return_route_payload_user_id;
} id_key_info;

typedef struct relay_info
{
	int is_active;
	int is_responsive;
	unsigned int max_uid;
	char relay_id[RELAY_ID_LEN];
	char relay_ip[RELAY_IP_MAX_LENGTH];
	id_key_info current_key_info;
	id_key_info key_info_history[PATH_HISTORY_LENGTH];
	int kih_index;
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

typedef struct route_pair
{
	route_info forward_route;
	route_info return_route;
} route_pair;

typedef struct route_history_info
{
	int relay_route[MAX_ROUTE_LENGTH*2];
	int route_length;
} route_history_info;

typedef struct route_history
{
	route_history_info history[PATH_HISTORY_LENGTH];
	int rh_index;
} route_history;

typedef struct send_packet_node
{
	unsigned char packet_buf[PACKET_SIZE_BYTES];
	char destination_ip[RELAY_IP_MAX_LENGTH];
	int destination_port;
	struct send_packet_node *next;
} send_packet_node;

typedef enum {
	NO_COMMAND						= 0,
	VERIFY_RETURN_DATA,				
	PLACE_LATEST_IN_QUEUE,
	VERIFY_DUMMY_PACKET_RECEIVED
} command;

typedef enum {
	IDLE_STATUS 			= 0,
	IN_PROGRESS,
	COMPLETE
} command_status;

typedef enum {
	FAILURE 				= 0,
	SUCCESS
} command_return_code;

typedef struct command_attempts
{
	uint16_t num_attempts;
	uint16_t num_succeeded;
	uint16_t num_failed;
} command_attempts;

typedef struct thread_comm
{
	command curr_command;
	command_status curr_status;
	command_return_code curr_return_code;
	command_attempts curr_attempts;
	uint8_t command_data[THREAD_COMMAND_DATA_SIZE];
} thread_comm;

#endif