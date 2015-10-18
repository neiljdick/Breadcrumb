#ifndef RELAY_HEADER
#define RELAY_HEADER

char *program_name = "Relay";

#define PORT_MAX 						(65534)
#define LISTEN_BACKLOG_MAX 				(50)

#define NUM_CLIENT_HANDLER_THREADS 		(500)
#define CLIENT_HANDLER_THREAD_MAX_AGE 	(10)

typedef struct client_thread_description
{
	pthread_t thread_id;
	int thread_age;
	struct client_thread_description *next;
} client_thread_description;

int init_listening_socket(unsigned int port, int *listening_socket /* out */);
int handle_new_client_connection(int client_socket);
void *handle_client_thread(void *ptr);
void *manage_clients_threads_thread(void *ptr);
int initialize_ct_thread_pool(client_thread_description *cthread_pool, unsigned int thread_pool_length);
int get_index_of_unused_thread_descriptor(client_thread_description *cthread_pool, unsigned int thread_pool_length, int *index /* out */);

#endif