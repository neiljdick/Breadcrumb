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
#include <openssl/err.h>
#include <signal.h>

#include "../Shared/key_storage.h"
#include "../Shared/cryptography.h"
#include "../Shared/packet_definition.h"
#include "../Shared/networking.h"
#include "../Shared/utils.h"

char *program_name = "Client";

#ifndef PORT_MAX
	#define PORT_MAX 							(65533)
#endif
#ifndef PORT_MIN
	#define PORT_MIN 							(16384)
#endif
#define NUM_CERT_READ_ATTEMPTS 					(10)
#define NUM_BIND_ATTEMPTS 						(5)
#define MAX_SEND_ATTEMPTS 						(5)
#define MAX_READ_ATTEMPTS 						(5)
#define LISTEN_BACKLOG_MAX 						(5)

#define MINIMUM_NUM_NODES_REQ_FOR_REGISTER 		(3)

#define PUBLIC_KEY_CERT_SIZE					(251)
#define USER_NAME_MIN_LENGTH 					(4)
#define USER_NAME_MAX_LENGTH 					(32)
#define NODE_POOL_MAX_SIZE						(20)
#define MAX_CONVERSATIONS						(32)
#define NODE_IP_MAX_LENGTH						(16)
#define NODE_ID_LEN 							((SHA256_DIGEST_LENGTH * 2) + 1)
#define PATH_HISTORY_LENGTH						(20)
#define MAX_UID_HISTORY_RECONNECT_ATTEMPTS 		(3)

#define MSG_PORT_PROTOCOL						("TCP")

#define THREAD_COMMAND_DATA_SIZE 				(512)
#define THREAD_RETURN_PACKET_CONFIRM_SIZE		(64)
#define MAX_CHECK_NODE_TIME_SEC					(5)
#define MAX_VERIFY_ROUTE_TIME_SEC				(10)

#define BANDWIDTH_ST_LENGTH						(64)
#define CONSTANT_BANDWIDTH_BYTES_PER_SEC		(256.0)
#define MIN_PACKET_TRANSMISSION_DELAY_US		(500000)

#define MAX_MESSAGE_SIZE 						(PAYLOAD_SIZE_BYTES - MESSAGE_OFFSET)
#define OM_MESSAGE_BUFFER_SIZE 					(MAX_MESSAGE_SIZE * 2) // TODO

#define PROVIDE_MESSAGE_RETURN_ROUTE_PERCENT 	(60)

#define ID_HASH_COUNT 							(3000000)

const char prompt_char 		= '>';
const char *my_chat_tag	 	= "me/>";
const char *feedback_tag	= "-!-";

const char *connect_to_chat_cmnd 			= "/connect ";
const char *network_connectivity_test_cmnd 	= "/network";
const char *exit_cmnd 						= "/exit";
const char *leave_convo_cmnd				= "/leave";
const char *help_cmnd 						= "/help";
const char *test_rr_cmnd					= "/testrr";

const char *public_cert_dir = ".node_certs";

typedef enum {
	REGISTER_UIDS_WITH_ENTRY_NODE = 0,
	REGISTER_UIDS_WITH_NODE,
	DUMMY_PACKET,
	DUMMY_PACKET_USING_RETURN_ROUTE_KEY_UID_PAIRS,
	DUMMY_PACKET_USING_RETURN_ROUTE_KEY_UID_PAIRS_FOR_VERIFICATION,
	OUTGOING_MESSAGE_PACKET,
	INCOMING_MESSAGE_PACKET
} packet_type;

typedef enum {
	DISABLE_HISTORY = 0,
	ENABLE_HISTORY
} history_type;

typedef enum {
	SOFT_RECONNECT = 0,
	HARD_RECONNECT
} reconnect_type;

typedef enum {
	VERIFY_USING_FORWARD_KEY_UID_PAIR = 0,
	VERIFY_USING_RETURN_KEY_UID_PAIR
} verification_type;

typedef enum {
	USE_PREVIOUS_RETURN_KEY = 0,
	APPLY_RETURN_KEY_HISTORY,
} return_key_history_type;

typedef struct node_indexer_info
{
	char *ip_address;
	RSA *public_cert;
} node_indexer_info;

typedef struct id_key_info
{
	unsigned char aes_key[AES_KEY_SIZE_BYTES];
	unsigned int node_user_id;
	unsigned char payload_aes_key[AES_KEY_SIZE_BYTES];
	unsigned int payload_node_user_id;
	unsigned char return_route_aes_key[AES_KEY_SIZE_BYTES];
	unsigned int return_route_user_id;
	unsigned char return_route_payload_aes_key[AES_KEY_SIZE_BYTES];
	unsigned int return_route_payload_user_id;
} id_key_info;

typedef struct msg_key_info
{
	unsigned char incoming_msg_aes_key[AES_KEY_SIZE_BYTES];
	unsigned int incoming_msg_node_user_id;
	unsigned char outgoing_msg_aes_key[AES_KEY_SIZE_BYTES];
	unsigned int outgoing_msg_node_user_id;
} msg_key_info;

typedef struct msg_key_info_cached
{
	unsigned char new_incoming_msg_aes_key[AES_KEY_SIZE_BYTES];
	unsigned int new_incoming_msg_node_user_id;
	unsigned char new_entry_node_incoming_msg_aes_key[AES_KEY_SIZE_BYTES];
	unsigned int new_entry_node_incoming_msg_node_user_id;
} msg_key_info_cached;

typedef struct node_info
{
	int is_active;
	int is_responsive;
	unsigned int max_uid;
	char node_id[NODE_ID_LEN];
	char node_ip[NODE_IP_MAX_LENGTH];
	unsigned int node_port;
	id_key_info current_key_info;
	id_key_info key_info_history[PATH_HISTORY_LENGTH];
	msg_key_info current_msg_key_info;
	msg_key_info_cached current_msg_key_info_cached;
	unsigned char im_fingerprint[IM_FINGERPRINT_LENGTH];
	int kih_index;
	RSA *public_cert;
} node_info;

typedef struct route_info
{
	int node_route[MAX_ROUTE_LENGTH];
	int route_length;
} route_info;

typedef struct conversation_info
{
	int conversation_valid;
	unsigned char conversation_name[USER_NAME_MAX_LENGTH];
	unsigned char friend_name[USER_NAME_MAX_LENGTH];
	int index_of_server_node;
	int index_of_entry_node;
	int index_of_friend_entry_node;
	short outgoing_msg_counter;
	route_info incoming_message_routes_to_supply[NODE_POOL_MAX_SIZE];
	node_info ri_pool[NODE_POOL_MAX_SIZE];
} conversation_info;

typedef struct route_pair
{
	route_info forward_route;
	route_info return_route;
} route_pair;

typedef struct route_history_info
{
	int node_route[MAX_ROUTE_LENGTH * 2];
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
	char destination_ip[NODE_IP_MAX_LENGTH];
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

typedef enum {
	IM_NO_COMMAND						= 0,
	HANDLE_NEW_INCOMING_CHAT_MESSAGE
} im_message_command;

typedef struct incoming_message_comm
{
	im_message_command curr_command; 
	int im_node_index;
	uint16_t message_displayed;
	unsigned char curr_message[MAX_MESSAGE_SIZE];
} incoming_message_comm;

typedef enum {
	OM_NO_COMMAND						= 0,
	HANDLE_NEW_OUTGOING_CHAT_MSG
} om_message_command;

typedef struct outgoing_message_comm
{
	om_message_command curr_command;
	uint32_t om_buf_rd_index;
	uint32_t om_buf_wr_index;
	unsigned char om_message_buffer[OM_MESSAGE_BUFFER_SIZE];
} outgoing_message_comm;

const char *bandwidth_log_name = "bandwidth.csv";

typedef struct bandwidth_st
{
	float timediff_sec;
	char sent_packet;
} bandwidth_st;

typedef struct bandwidth_data
{
	bandwidth_st b_st[BANDWIDTH_ST_LENGTH];
	int index;
} bandwidth_data;

typedef enum {
	DONT_SEND_PACKET 					= 0,
	DONT_SEND_PACKET_R,
	DONT_SEND_PACKET_RR,
	DONT_SEND_PACKET_T2,
	DONT_SEND_PACKET_T3,
	SEND_DUMMY_PACKET_NO_RR,
	SEND_DUMMY_PACKET_NO_RR_T2,
	SEND_DUMMY_PACKET_NO_RR_AND_W_RR,
	SEND_DUMMY_PACKET_W_RR,
	SEND_DUMMY_PACKET_W_RR_T2,
	SEND_DUMMY_PACKET_W_RR_AND_NO_RR,
	DO_NODE_CONNECTION_CHECK
} constant_bandwidth_packet_send;

typedef enum {
	NO_ERROR 							= 0,
	ENTRY_NODE_OFFLINE					= 1,
	SERVER_NODE_OFFLINE 				= 2,
	TOO_FEW_NODES_ONLINE 				= 4
} error_codes;

#endif