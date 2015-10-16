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

#include "relay.h"

#define ENABLE_LOGGING

client_thread_description cthread_pool[NUM_CLIENT_HANDLER_THREADS];
client_thread_description *first_ct = NULL, *last_ct = NULL;
unsigned int num_active_client_threads = 0;

int main(int argc, char const *argv[])
{
	unsigned int port;
	int ret, listening_socket, client_socket;
	int errno_cached;
	socklen_t sockaddr_len;
	struct sockaddr_in client_addr;

	if(argc != 2) {
		fprintf(stdout, "Usage: ./%s [PORT]\n", program_name);
		exit(-1);
	}

	#ifdef ENABLE_LOGGING
		fprintf(stdout, "%s program begin\n", program_name);
	#endif

	ret = initialize_ct_thread_pool(cthread_pool, (sizeof(cthread_pool)/sizeof(client_thread_description)));
	if(ret < 0) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "Failed to initialize program memory");
		#endif

		exit(-1);
	}

	port = (unsigned int)atoi(argv[1]);
	if(port > PORT_MAX) {
		fprintf(stdout, "Port number (%u) must be less than %u\n", port, PORT_MAX);
		exit(-2);
	}

	ret = init_listening_socket(port, &listening_socket);
	if(ret < 0) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "Failed to initialize listening socket on port %u\n", port);
		#endif

		exit(-3);
	}

	#ifdef ENABLE_LOGGING
		fprintf(stdout, "%s listening on port=%u\n", program_name, port);
	#endif	

	while(1) {
		sockaddr_len = sizeof(client_addr);
		bzero((char *) &client_addr, sizeof(client_addr));
		client_socket = accept(listening_socket, (struct sockaddr *)&client_addr, &sockaddr_len);
		if(client_socket < 0) {
			errno_cached = errno;
			#ifdef ENABLE_LOGGING
				fprintf(stdout, "Failed to accept client connection, %s\n", strerror(errno_cached));
			#endif

			continue;
		}
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s:%d connected\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
		#endif

		handle_new_client_connection(client_socket);		
	}

	return 0;
}

int handle_new_client_connection(int client_socket)
{
	int ret, errno_cached;
	int unused_thread_index;

	if(client_socket < 0) {
		return -1;
	}

	if(num_active_client_threads >= NUM_CLIENT_HANDLER_THREADS) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "Unable to accept new client socket connections as number of connections (%u) has reached maximum allowed\n", num_active_client_threads);
		#endif

		close(client_socket);
		return -1;
	}

	get_index_of_unused_thread_descriptor(cthread_pool, (sizeof(cthread_pool)/sizeof(client_thread_description)), &unused_thread_index);
	if(unused_thread_index == -1) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "Client thread pool reached maximum, rejecting client connection attempt");
		#endif

		close(client_socket);
		return -1;
	}

	ret = pthread_create(&cthread_pool[unused_thread_index].thread_id, NULL, handle_client_thread, &client_socket);
	if(ret != 0) {
		errno_cached = errno;
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "Failed to create client handler thread, %s\n", strerror(errno_cached));
		#endif

		close(client_socket);
		return -1;
	}
	cthread_pool[unused_thread_index].thread_age = 0;
	cthread_pool[unused_thread_index].next = NULL;
	if(first_ct == NULL) {
		first_ct = &cthread_pool[unused_thread_index];
		last_ct = first_ct;
	} else {
		first_ct->next = &cthread_pool[unused_thread_index];
		first_ct = first_ct->next;
	}
	num_active_client_threads++;

	return 0;
}

int get_index_of_unused_thread_descriptor(client_thread_description *cthread_pool, unsigned int thread_pool_length, int *index /* out */)
{
	unsigned int i;

	if(cthread_pool == NULL) {
		return -1;
	}
	if(index == NULL) {
		return -1;
	}

	*index = -1;
	for (i = 0; i < thread_pool_length; ++i) {
		if(cthread_pool[i].thread_age == -1) {
			*index = i;
		}
	}

	return 0;
}

int initialize_ct_thread_pool(client_thread_description *cthread_pool, unsigned int thread_pool_length)
{
	unsigned int i;

	if(cthread_pool == NULL) {
		return -1;
	}

	for (i = 0; i < thread_pool_length; ++i) {
		cthread_pool[i].thread_age = -1;
		cthread_pool[i].next = NULL;
	}

	return 0;
}

void *handle_client_thread(void *ptr)
{
	int client_socket;
	char *pthread_ret;

	if(ptr == NULL) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "Handle client thread created with null arguments\n");
		#endif

		pthread_ret = (char *)-1;
		pthread_exit(pthread_ret);
	}
	#ifdef ENABLE_LOGGING
		fprintf(stdout, "Created new client thread\n");
	#endif
	client_socket = *((int *)ptr);

	sleep(3);

	#ifdef ENABLE_LOGGING
		fprintf(stdout, "Client thread exit\n");
	#endif
	close(client_socket);

	pthread_ret = (char *)0;
	pthread_exit(pthread_ret);
}

void *manage_clients_threads_thread(void *ptr)
{
	char *pthread_ret;

	#ifdef ENABLE_LOGGING
		fprintf(stdout, "Created manage client thread\n");
	#endif

	while(1) {
		sleep(10);
	}

	pthread_ret = (char *)0;
	pthread_exit(pthread_ret);
}

int init_listening_socket(unsigned int port, int *listening_socket /* out */)
{
	struct sockaddr_in serv_addr;

	if(port > PORT_MAX) {
		return -1;	
	}
	if(listening_socket == NULL) {
		return -1;
	}

	*listening_socket = socket(AF_INET, SOCK_STREAM, 0);
	if(*listening_socket < 0){
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "Failed to create stream socket");
		#endif

		return -1;
	}

	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(port);
	if (bind(*listening_socket, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "Error on binding");
		#endif

		return -1;
	}
	listen(*listening_socket, LISTEN_BACKLOG_MAX);	

	return 0;
}