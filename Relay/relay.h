#ifndef RELAY_HEADER
#define RELAY_HEADER

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

char *program_name = "Relay";

#define PORT_MAX 						(65533)
#define LISTEN_BACKLOG_MAX 				(50)

#define NUM_MSG_HANDLER_THREADS 		(500)
#define MSG_HANDLER_THREAD_MAX_AGE 		(5)

#define NUM_USER_ID_CACHE_THREADS 		(50)
#define USER_ID_CACHE_THREAD_MAX_AGE 	(5)

#define RELAY_ID_HASH_COUNT 			(3000)

#define NUM_THREAD_POOLS				(2)
#define MSG_THREAD_POOL_INDEX			(0)
#define USER_ID_CACHE_POOL_INDEX		(1)

typedef struct client_thread_description
{
	pthread_t thread_id;
	int thread_age;
	struct client_thread_description *next;
} client_thread_description;

typedef struct thread_pool
{
	sem_t ct_pool_sem;
	unsigned int thread_pool_length;
	unsigned int thread_pool_max_age;
	client_thread_description *cthread_pool;
	client_thread_description *first_ct, *last_ct;
	unsigned int num_active_client_threads;
} thread_pool;

int init_listening_socket(char *thread_id, unsigned int port, int *listening_socket /* out */);
int handle_new_msg_client_connection(int client_socket);
void *certificate_request_handler_thread(void *ptr);
void *handle_client_thread(void *ptr);
void *thread_pool_manager_thread_thread(void *ptr);
int initialize_thread_pools();
int get_index_of_unused_thread_descriptor(client_thread_description *cthread_pool, unsigned int thread_pool_length, int *index /* out */);

#endif