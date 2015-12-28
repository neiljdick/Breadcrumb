#ifndef NODE_HEADER
#define NODE_HEADER

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
#include <signal.h>
#include <limits.h>

#include "../Shared/key_storage.h"
#include "../Shared/cryptography.h"
#include "../Shared/packet_definition.h"

const char *program_name = "Node";

const char *log_file = "node_log.csv";

const char *msg_handler_str 		= "MSG HANDLER";
const char *id_cache_handler_str 	= "ID CACHE HANDLER";
const char *unknown_str 			= "UNKNOWN";

#define POOL_ID_LEN 					(64)

#ifndef PORT_MAX
	#define PORT_MAX 					(65533)
#endif
#ifndef PORT_MIN
	#define PORT_MIN 					(16384)
#endif
#define LISTEN_BACKLOG_MAX 				(50)
#define MAX_PACKET_TRANSMIT_DELAY_USEC	(200000) // TODO determine experimentally?

#define NUM_MSG_HANDLER_THREADS 		(500)
#define MSG_HANDLER_THREAD_MAX_AGE 		(5)

#define NUM_USER_ID_CACHE_THREADS 		(50)
#define USER_ID_CACHE_THREAD_MAX_AGE 	(5)

#define NODE_ID_HASH_COUNT 				(3000)

#define NUM_THREAD_POOLS				(2)
#define MSG_THREAD_POOL_INDEX			(0)
#define USER_ID_CACHE_POOL_INDEX		(1)

#define USEC_PER_SEC 					(1000000)
#define MAIN_THREAD_SLEEP_USEC 			(200000)
#define CERT_REQUEST_SLEEP_US 			(50000)
#define ID_CACHE_SLEEP_US 				(50000)

#define NUM_READ_ATTEMPTS 				(5)
#define NUM_BIND_ATTEMPTS 				(5)
#define MAX_SEND_ATTEMPTS 				(5)

#define DEFAULT_LOGGING_INTERVAL 		(PER_HOUR)
#define LOGGING_DATA_LEN 				(360)

#define TCP_BYTES_OVERHEAD 				(502)

#define NODE_IP_MAX_LENGTH				(16)

typedef struct client_thread_description
{
	pthread_t thread_id;
	int thread_age;
	int thread_fd;
	struct client_thread_description *next;
} client_thread_description;

typedef struct thread_pool
{
	sem_t ct_pool_sem;
	void *(*start_routine) (void *);
	unsigned int thread_pool_length;
	unsigned int thread_pool_max_age;
	client_thread_description *cthread_pool;
	client_thread_description *first_ct, *last_ct;
	unsigned int num_active_client_threads;
} thread_pool;

typedef enum 
{
	PER_SECOND				= 0,
	PER_FIFTEEN_SECONDS,
	PER_MINUTE,
	PER_FIVE_MINUTES,
	PER_TEN_MINUTES,
	PER_FIFTEEN_MINUTES,
	PER_THIRTY_MINUTES,
	PER_HOUR,
	PER_DAY,
	PER_WEEK
} logging_interval;

typedef struct
{
	unsigned int logging_index;
	unsigned int new_logging_data_available;
	unsigned long logging_index_valid[LOGGING_DATA_LEN];
	unsigned long num_cert_requests[LOGGING_DATA_LEN];
	unsigned long num_id_cache_packets[LOGGING_DATA_LEN];
	unsigned long num_node_packets[LOGGING_DATA_LEN];
	unsigned long num_non_node_packets[LOGGING_DATA_LEN];
	float percentage_of_keystore_used[LOGGING_DATA_LEN];
	unsigned long num_key_get_failures[LOGGING_DATA_LEN];
	unsigned long total_num_of_id_cache_threads_created[LOGGING_DATA_LEN];
	unsigned long total_num_of_node_threads_created[LOGGING_DATA_LEN];
	unsigned long total_num_of_id_cache_threads_destroyed[LOGGING_DATA_LEN];
	unsigned long total_num_of_node_threads_destroyed[LOGGING_DATA_LEN];
} logging_data;

int initialize_key_store(char *thread_id);
int init_listening_socket(char *thread_id, unsigned int port, int *listening_socket /* out */);
int add_new_thread_to_pool(char *thread_id, int thread_pool_index, int client_socket);
void *certificate_request_handler_thread(void *ptr);
void *handle_msg_client_thread(void *ptr);
void *handle_id_cache_thread(void *ptr);
void *thread_pool_manager_thread_thread(void *ptr);
void *client_msg_new_connection_handler(void *ptr);
void *client_id_cache_handler(void *ptr);
int initialize_thread_pools();
int get_index_of_unused_thread_descriptor(client_thread_description *cthread_pool, unsigned int thread_pool_length, int *index /* out */);
int get_thread_pool_id_from_index(int index, char *pool_id /* out */);
int handle_non_route_packet(char *thread_id, payload_data *pd_ptr);
int send_packet_to_node(unsigned char *packet, char *destination_ip, int destination_port);
int apply_packet_mixing_delay(void);

#endif