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

#define PORT_MAX 						(65534)
#define LISTEN_BACKLOG_MAX 				(50)

#define NUM_CLIENT_HANDLER_THREADS 		(500)
#define CLIENT_HANDLER_THREAD_MAX_AGE 	(10)

#define RELAY_ID_HASH_COUNT 			(3000)

typedef struct client_thread_description
{
	pthread_t thread_id;
	int thread_age;
	struct client_thread_description *next;
} client_thread_description;

int init_listening_socket(char *thread_id, unsigned int port, int *listening_socket /* out */);
int handle_new_client_connection(int client_socket);
void *certificate_request_handler_thread(void *ptr);
void *handle_client_thread(void *ptr);
void *manage_clients_threads_thread(void *ptr);
int initialize_ct_thread_pool(client_thread_description *cthread_pool, unsigned int thread_pool_length);
int get_index_of_unused_thread_descriptor(client_thread_description *cthread_pool, unsigned int thread_pool_length, int *index /* out */);

#endif