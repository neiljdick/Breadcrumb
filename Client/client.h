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
#define PATH_HISTORY_LENGTH						(10)
#define MAX_UID_HISTORY_RECONNECT_ATTEMPTS 		(2)

#define MSG_PORT_PROTOCOL						("TCP")

#define THREAD_COMMAND_DATA_SIZE 				(512)
#define THREAD_RETURN_PACKET_CONFIRM_SIZE		(64)
#define MAX_CHECK_NODE_TIME_SEC					(3)

const char *public_cert_dir = ".relay_certs";

typedef enum {
	REGISTER_UIDS_WITH_ENTRY_RELAY = 0,
	REGISTER_UIDS_WITH_RELAY,
	DUMMY_PACKET
} packet_type;

typedef enum {
	DISABLE_HISTORY = 0,
	ENABLE_HISTORY
} history_type;

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
	NO_COMMAND				= 0,
	VERIFY_RETURN_DATA,
	PLACE_LATEST_IN_QUEUE
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

static int init_globals(int argc, char const *argv[]);
static int handle_received_packet(char *packet);
static void print_ret_code(char *thread_id, int ret);
static void handle_pthread_ret(char *thread_id, int ret, int clientfd);
static int init_send_packet_thread(pthread_t *send_packet_thread);
static int init_receive_packet_thread(pthread_t *receive_packet_thread);
static int init_listening_socket(char *thread_id, unsigned int port, int *listening_socket /* out */);
static int init_self_ip(char *thread_id);
static int initialize_relay_verification_command(payload_data *verification_payload);
static int wait_for_command_completion(int max_command_time, int *command_ret_status);
static int verify_entry_relay_online(char *thread_id, conversation_info *ci_info, int *entry_relay_online);
static int verify_relay_online(char *thread_id, conversation_info *ci_info, int relay_index, history_type h_type, int *relay_is_online);
static int verify_all_relays_online(char *thread_id, conversation_info *ci_info, int *all_relays_online);
static int update_relay_connectivity_status(char *thread_id, conversation_info *ci_info);
static int attempt_to_reconnect_unresponsive_relays_via_key_history(char *thread_id, conversation_info *ci_info);
static int attempt_to_reconnect_unresponsive_relays_via_reregister_id(char *thread_id, conversation_info *ci_info);
static char get_send_packet_char(void);
static int commit_current_key_info_to_history(relay_info *r_info);
static int commit_key_info_to_history(conversation_info *ci_info);
static int commit_route_info_to_history(packet_type type, conversation_info *info, route_info *r_info, route_info *return_r_info, void *arg);
static int print_key_history(relay_info *r_info);
static int print_route_info_history(void);

int place_packet_on_send_queue(unsigned char *packet, char *destination_ip, int destination_port);
int get_number_of_packets_in_send_queue(int *num_packets);
int get_friend_id(char *friend_id /* out */);
int init_chat(char *friend_name, conversation_info *ci_out /* out */);
int get_relay_public_certificates_debug(conversation_info *ci_info);
int set_entry_relay_for_conversation(conversation_info *ci_info);
int set_relay_keys_for_conversation(conversation_info *ci_info);
int set_user_ids_for_conversation(conversation_info *ci_info);
int perform_user_id_registration(conversation_info *ci_info);
int get_index_of_next_free_conversation(conversation_info *conversations);
int create_packet(packet_type type, conversation_info *ci_info, route_info *r_info, payload_data *payload, void *other, unsigned char *packet, char *destination_ip, int *destination_port);
int send_packet_to_relay(unsigned char *packet, char *destination_ip, int destination_port);
int generate_new_user_id(conversation_info *ci_info, int relay_index, unsigned int *uid /* out */);
int is_valid_ip(char *ip, int *valid /* out */);
int print_conversation(char *thread_id, conversation_info *ci_info);
char* get_packet_type_str(packet_type type);
int send_dummy_packet_no_return_route(conversation_info *ci_info);
int send_dummy_packet_with_return_route(conversation_info *ci_info);
int verify_entry_relay_online(char *thread_id, conversation_info *ci_info, int *entry_relay_online);
int generate_onion_route_data_from_route_info(conversation_info *ci_info, route_info *r_info, unsigned char *packet);
int generate_onion_route_payload_from_route_info(conversation_info *ci_info, route_info *r_info, payload_data *payload, unsigned char *packet /* out */);
int generate_return_onion_route_data_from_route_info(conversation_info *ci_info, route_info *return_r_info, unsigned char *packet);
int generate_return_onion_route_payload_from_route_info(conversation_info *ci_info, route_info *return_r_info, unsigned char *packet);
int generate_packet_metadata(conversation_info *ci_info, payload_type p_type, route_info *return_r_info, payload_data *payload);
int send_packet(packet_type type, conversation_info *ci_info, route_info *r_info, payload_data *payload, void *other);

#endif