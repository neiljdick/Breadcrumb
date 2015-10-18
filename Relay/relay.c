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

#include "relay.h"
#include "cryptography.h"

#define ENABLE_LOGGING

sem_t ct_pool_sem;
client_thread_description cthread_pool[NUM_CLIENT_HANDLER_THREADS];
client_thread_description *first_ct = NULL, *last_ct = NULL;
unsigned int num_active_client_threads = 0;

int main(int argc, char const *argv[])
{
	unsigned int client_msg_port, cert_request_port;
	int ret, listening_socket, client_socket;
	int errno_cached;
	socklen_t sockaddr_len;
	struct sockaddr_in client_addr;
	pthread_t client_thread_manager_thread;
	RSA *rsa;

	if(argc != 3) {
		fprintf(stdout, "[MAIN THREAD] Usage: ./%s [RELAY ID] [PORT]\n", program_name);
		exit(-1);
	}
	#ifdef ENABLE_LOGGING
		fprintf(stdout, "[MAIN THREAD] %s program begin\n", program_name);
	#endif

	ret = load_rsa_key_pair(argv[1], &rsa);
	if(ret < 0) {
		exit(-2);	
	}

	sem_init(&ct_pool_sem, 0, 1);
	sem_wait(&ct_pool_sem);
	ret = initialize_ct_thread_pool(cthread_pool, (sizeof(cthread_pool)/sizeof(client_thread_description)));
	if(ret < 0) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Failed to initialize program memory");
		#endif

		exit(-3);
	}
	sem_post(&ct_pool_sem);

	ret = pthread_create(&client_thread_manager_thread, NULL, manage_clients_threads_thread, NULL);
	if(ret != 0) {
		errno_cached = errno;
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Failed to create client thread manager thread\n");
		#endif

		exit(-4);
	}

	client_msg_port = (unsigned int)atoi(argv[2]);
	if(client_msg_port > PORT_MAX) {
		fprintf(stdout, "[MAIN THREAD] Port number (%u) must be less than %u\n", client_msg_port, PORT_MAX);
		exit(-5);
	}
	cert_request_port = client_msg_port + 1;

	ret = init_listening_socket(client_msg_port, &listening_socket);
	if(ret < 0) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Failed to initialize listening socket on port %u\n", client_msg_port);
		#endif

		exit(-5);
	}

	#ifdef ENABLE_LOGGING
		fprintf(stdout, "[MAIN THREAD] %s listening on port=%u\n", program_name, client_msg_port);
	#endif	

	while(1) {
		sockaddr_len = sizeof(client_addr);
		bzero((char *) &client_addr, sizeof(client_addr));
		client_socket = accept(listening_socket, (struct sockaddr *)&client_addr, &sockaddr_len);
		if(client_socket < 0) {
			errno_cached = errno;
			#ifdef ENABLE_LOGGING
				fprintf(stdout, "[MAIN THREAD] Failed to accept client connection, %s\n", strerror(errno_cached));
			#endif

			continue;
		}
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] %s:%d connected\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
		#endif

		handle_new_client_connection(client_socket);		
	}

	return 0;
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
			fprintf(stdout, "[MAIN THREAD] Failed to create stream socket");
		#endif

		return -1;
	}

	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(port);
	if (bind(*listening_socket, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Error on binding");
		#endif

		return -1;
	}
	listen(*listening_socket, LISTEN_BACKLOG_MAX);	

	return 0;
}

int handle_new_client_connection(int client_socket)
{
	int ret, errno_cached;
	int unused_thread_index;

	if(client_socket < 0) {
		return -1;
	}

	sem_wait(&ct_pool_sem);
	if(num_active_client_threads >= NUM_CLIENT_HANDLER_THREADS) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Unable to accept new client socket connections as number of connections (%u) has reached maximum allowed\n", num_active_client_threads);
		#endif

		close(client_socket);
		sem_post(&ct_pool_sem);
		return -1;
	}

	get_index_of_unused_thread_descriptor(cthread_pool, (sizeof(cthread_pool)/sizeof(client_thread_description)), &unused_thread_index);
	if(unused_thread_index == -1) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Client thread pool reached maximum, rejecting client connection attempt");
		#endif

		close(client_socket);
		sem_post(&ct_pool_sem);
		return -1;
	}

	ret = pthread_create(&cthread_pool[unused_thread_index].thread_id, NULL, handle_client_thread, &client_socket);
	if(ret != 0) {
		errno_cached = errno;
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Failed to create client handler thread, %s\n", strerror(errno_cached));
		#endif

		close(client_socket);
		sem_post(&ct_pool_sem);
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
	sem_post(&ct_pool_sem);

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

void *manage_clients_threads_thread(void *ptr)
{
	char *pthread_ret;
	pthread_t self_thread_id;
	int ret;
	void *res;
	struct client_thread_description *ct_descript_node, *ct_descript_node_prev;

	self_thread_id = pthread_self();
	#ifdef ENABLE_LOGGING
		fprintf(stdout, "[MANAGE CLIENT THREAD 0x%x] Created manage client thread\n", (unsigned int)self_thread_id);
	#endif

	while(1) {
		sleep(5);

		sem_wait(&ct_pool_sem);
		ct_descript_node = last_ct;
		ct_descript_node_prev = NULL;
		if(ct_descript_node == NULL) {
			#ifdef ENABLE_LOGGING
				fprintf(stdout, "[MANAGE CLIENT THREAD 0x%x] Found no client threads to manage\n", (unsigned int)self_thread_id);
			#endif
		} else {
			while(ct_descript_node != NULL) {
				ret = pthread_tryjoin_np(ct_descript_node->thread_id, &res);
				if(ret != 0) {
					#ifdef ENABLE_LOGGING
						fprintf(stdout, "[MANAGE CLIENT THREAD 0x%x] Found client thread with id=0x%x still active\n", (unsigned int)self_thread_id, (unsigned int)ct_descript_node->thread_id);
					#endif

					ct_descript_node->thread_age++;
					ct_descript_node_prev = ct_descript_node;
					ct_descript_node = ct_descript_node->next;
				} else {
					#ifdef ENABLE_LOGGING
						fprintf(stdout, "[MANAGE CLIENT THREAD 0x%x] Joined with client thread with id=0x%x\n", (unsigned int)self_thread_id, (unsigned int)ct_descript_node->thread_id);
					#endif

					if(ct_descript_node == first_ct) {
						first_ct = NULL;
					}
					if (ct_descript_node == last_ct) {
						last_ct = ct_descript_node->next;
						ct_descript_node->thread_id = 0;
						ct_descript_node->thread_age = -1;
						ct_descript_node->next = NULL;
						ct_descript_node = last_ct;
					} else {
						ct_descript_node_prev->next = ct_descript_node->next;
						ct_descript_node->thread_id = 0;
						ct_descript_node->thread_age = -1;
						ct_descript_node->next = NULL;
						ct_descript_node = ct_descript_node_prev;
					}
					if(num_active_client_threads != 0) {
						num_active_client_threads--;
					}
					free(res);
				}
			}
		}
		sem_post(&ct_pool_sem);
	}

	pthread_ret = (char *)0;
	pthread_exit(pthread_ret);
}

void *handle_client_thread(void *ptr)
{
	int client_socket;
	char *pthread_ret;
	pthread_t self_thread_id;

	self_thread_id = pthread_self();
	#ifdef ENABLE_LOGGING
		fprintf(stdout, "[CLIENT THREAD 0x%x] Created new client thread\n", (unsigned int)self_thread_id);
	#endif

	if(ptr == NULL) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[CLIENT THREAD 0x%x] Handle client thread created with null arguments\n", (unsigned int)self_thread_id);
		#endif

		pthread_ret = (char *)-1;
		pthread_exit(pthread_ret);
	}
	client_socket = *((int *)ptr);	

	#ifdef ENABLE_LOGGING
		fprintf(stdout, "[CLIENT THREAD 0x%x] Client thread exit\n", (unsigned int)self_thread_id);
	#endif
	close(client_socket);

	pthread_ret = (char *)0;
	pthread_exit(pthread_ret);
}