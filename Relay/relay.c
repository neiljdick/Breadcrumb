#include "relay.h"
#include "key_storage.h"
#include "../Shared/cryptography.h"

#define ENABLE_LOGGING

thread_pool thread_pools[NUM_THREAD_POOLS];
client_thread_description msg_client_pool[NUM_MSG_HANDLER_THREADS];
client_thread_description user_id_cache_pool[NUM_USER_ID_CACHE_THREADS];

unsigned int client_msg_port, id_cache_port, cert_request_port;
char *relay_id;
int relay_id_len;

int main(int argc, char const *argv[])
{
	int ret, listening_socket, client_socket;
	int errno_cached;
	socklen_t sockaddr_len;
	struct sockaddr_in client_addr;
	pthread_t certificate_request_thread, thread_pool_manager_thread;
	RSA *rsa;

	if(argc != 3) {
		fprintf(stdout, "[MAIN THREAD] Usage: ./%s [RELAY ID] [PORT]\n", program_name);
		exit(-1);
	}
	#ifdef ENABLE_LOGGING
		fprintf(stdout, "[MAIN THREAD] %s program begin\n", program_name);
	#endif

	ret = get_hash_of_string("[MAIN THREAD]", RELAY_ID_HASH_COUNT, argv[1], &relay_id, &relay_id_len);
	if(ret < 0) {
		exit(-2);	
	}
	#ifdef ENABLE_LOGGING
		fprintf(stdout, "[MAIN THREAD] Relay id=%s\n", relay_id);
	#endif

	ret = load_rsa_key_pair(relay_id, &rsa);
	if(ret < 0) {
		exit(-2);	
	}

	ret = init_key_store("[MAIN THREAD]");
	if(ret < 0) {
		exit(-2);	
	}

	client_msg_port = (unsigned int)atoi(argv[2]);
	if(client_msg_port > PORT_MAX) {
		fprintf(stdout, "[MAIN THREAD] Port number (%u) must be less than %u\n", client_msg_port, PORT_MAX);
		exit(-5);
	}
	id_cache_port = client_msg_port + 1;
	cert_request_port = client_msg_port + 2;

	ret = pthread_create(&certificate_request_thread, NULL, certificate_request_handler_thread , NULL);
	if(ret != 0) {
		errno_cached = errno;
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Failed to create certificate request thread\n");
		#endif

		exit(-4);
	}

	ret = initialize_thread_pools();
	if(ret < 0) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Failed to initialize thread pools");
		#endif

		exit(-3);
	}

	ret = pthread_create(&thread_pool_manager_thread, NULL, thread_pool_manager_thread_thread, NULL);
	if(ret != 0) {
		errno_cached = errno;
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Failed to create thread pool manager thread\n");
		#endif

		exit(-4);
	}

	ret = init_listening_socket("[MAIN THREAD]", client_msg_port, &listening_socket);
	if(ret < 0) {
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

		handle_new_msg_client_connection(client_socket);
	}

	return 0;
}

void *certificate_request_handler_thread(void *ptr)
{
	int ret, certificate_request_listening_socket, client_socket;
	int errno_cached;
	socklen_t sockaddr_len;
	struct sockaddr_in client_addr;
	char *public_key_buffer;
	int public_key_buffer_len;

	#ifdef ENABLE_LOGGING
		fprintf(stdout, "[CERTIFICATE REQUEST THREAD] Created certificate request handler thread\n");
	#endif

	ret = load_public_key_into_buffer("[CERTIFICATE REQUEST THREAD]", &public_key_buffer, &public_key_buffer_len);
	if(ret < 0) {
		exit(-2);
	}

	ret = init_listening_socket("[CERTIFICATE REQUEST THREAD]", cert_request_port, &certificate_request_listening_socket);
	if(ret < 0) {
		exit(-5);
	}

	while(1) {
		sockaddr_len = sizeof(client_addr);
		bzero((char *) &client_addr, sizeof(client_addr));
		client_socket = accept(certificate_request_listening_socket, (struct sockaddr *)&client_addr, &sockaddr_len);
		if(client_socket < 0) {
			errno_cached = errno;
			#ifdef ENABLE_LOGGING
				fprintf(stdout, "[CERTIFICATE REQUEST THREAD] Failed to accept client connection, %s\n", strerror(errno_cached));
			#endif

			continue;
		}
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[CERTIFICATE REQUEST THREAD] %s:%d requested certificate\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
		#endif

		write(client_socket, (void *)relay_id, relay_id_len);
		write(client_socket, (void *)public_key_buffer, public_key_buffer_len);
		fsync(client_socket);
		close(client_socket);
	}
}

int init_listening_socket(char *thread_id, unsigned int port, int *listening_socket /* out */)
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
			fprintf(stdout, "%s Failed to create stream socket\n", thread_id);
		#endif

		return -1;
	}

	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(port);
	if (bind(*listening_socket, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Error on binding\n", thread_id);
		#endif

		return -1;
	}
	listen(*listening_socket, LISTEN_BACKLOG_MAX);	

	return 0;
}

int handle_new_msg_client_connection(int client_socket)
{
	int ret, errno_cached;
	int unused_thread_index;

	if(client_socket < 0) {
		return -1;
	}

	sem_wait(&(thread_pools[MSG_THREAD_POOL_INDEX].ct_pool_sem));
	if(thread_pools[MSG_THREAD_POOL_INDEX].num_active_client_threads >= NUM_MSG_HANDLER_THREADS) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Unable to accept new client socket connections as number of connections (%u) \
				has reached maximum allowed\n", thread_pools[MSG_THREAD_POOL_INDEX].num_active_client_threads);
		#endif

		close(client_socket);
		sem_post(&(thread_pools[MSG_THREAD_POOL_INDEX].ct_pool_sem));
		return -1;
	}

	get_index_of_unused_thread_descriptor(thread_pools[MSG_THREAD_POOL_INDEX].cthread_pool, (sizeof(msg_client_pool)/sizeof(client_thread_description)), &unused_thread_index);
	if(unused_thread_index == -1) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Client thread pool reached maximum, rejecting client connection attempt");
		#endif

		close(client_socket);
		sem_post(&(thread_pools[MSG_THREAD_POOL_INDEX].ct_pool_sem));
		return -1;
	}

	ret = pthread_create(&(thread_pools[MSG_THREAD_POOL_INDEX].cthread_pool[unused_thread_index].thread_id), NULL, handle_client_thread, &client_socket);
	if(ret != 0) {
		errno_cached = errno;
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Failed to create client handler thread, %s\n", strerror(errno_cached));
		#endif

		close(client_socket);
		sem_post(&(thread_pools[MSG_THREAD_POOL_INDEX].ct_pool_sem));
		return -1;
	}
	thread_pools[MSG_THREAD_POOL_INDEX].cthread_pool[unused_thread_index].thread_age = 0;
	thread_pools[MSG_THREAD_POOL_INDEX].cthread_pool[unused_thread_index].next = NULL;
	if(thread_pools[MSG_THREAD_POOL_INDEX].first_ct == NULL) {
		thread_pools[MSG_THREAD_POOL_INDEX].first_ct = &(thread_pools[MSG_THREAD_POOL_INDEX].cthread_pool[unused_thread_index]);
		thread_pools[MSG_THREAD_POOL_INDEX].last_ct = thread_pools[MSG_THREAD_POOL_INDEX].first_ct;
	} else {
		thread_pools[MSG_THREAD_POOL_INDEX].first_ct->next = &(thread_pools[MSG_THREAD_POOL_INDEX].cthread_pool[unused_thread_index]);
		thread_pools[MSG_THREAD_POOL_INDEX].first_ct = thread_pools[MSG_THREAD_POOL_INDEX].first_ct->next;
	}
	thread_pools[MSG_THREAD_POOL_INDEX].num_active_client_threads++;
	sem_post(&(thread_pools[MSG_THREAD_POOL_INDEX].ct_pool_sem));

	return 0;
}

int initialize_thread_pools()
{
	unsigned int i, j;

	sem_init(&thread_pools[MSG_THREAD_POOL_INDEX].ct_pool_sem, 0, 1);
	sem_init(&thread_pools[USER_ID_CACHE_POOL_INDEX].ct_pool_sem, 0, 1);

	thread_pools[MSG_THREAD_POOL_INDEX].thread_pool_length = NUM_MSG_HANDLER_THREADS;
	thread_pools[USER_ID_CACHE_POOL_INDEX].thread_pool_length = NUM_USER_ID_CACHE_THREADS;

	thread_pools[MSG_THREAD_POOL_INDEX].thread_pool_max_age = MSG_HANDLER_THREAD_MAX_AGE;
	thread_pools[USER_ID_CACHE_POOL_INDEX].thread_pool_max_age = USER_ID_CACHE_THREAD_MAX_AGE;

	thread_pools[MSG_THREAD_POOL_INDEX].cthread_pool = msg_client_pool; 
	thread_pools[USER_ID_CACHE_POOL_INDEX].cthread_pool = user_id_cache_pool;

	thread_pools[MSG_THREAD_POOL_INDEX].first_ct = NULL;
	thread_pools[USER_ID_CACHE_POOL_INDEX].first_ct = NULL;

	thread_pools[MSG_THREAD_POOL_INDEX].last_ct = NULL;
	thread_pools[USER_ID_CACHE_POOL_INDEX].last_ct = NULL;

	thread_pools[MSG_THREAD_POOL_INDEX].num_active_client_threads = 0;
	thread_pools[USER_ID_CACHE_POOL_INDEX].num_active_client_threads = 0;

	for (i = 0; i < NUM_THREAD_POOLS; ++i) {
		for (j = 0; j < thread_pools[i].thread_pool_length; ++j) {
			thread_pools[i].cthread_pool[j].thread_age = -1;
			thread_pools[i].cthread_pool[j].next = NULL;
		}
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

void *thread_pool_manager_thread_thread(void *ptr)
{
	char *pthread_ret;
	pthread_t self_thread_id;
	int ret, i;
	void *res;
	struct client_thread_description *ct_descript_node, *ct_descript_node_prev;

	self_thread_id = pthread_self();
	#ifdef ENABLE_LOGGING
		fprintf(stdout, "[MANAGE CLIENT THREAD 0x%x] Created manage client thread\n", (unsigned int)self_thread_id);
	#endif

	while(1) {
		sleep(5);

		for(i = 0; i < NUM_THREAD_POOLS; i++) {
			sem_wait(&(thread_pools[i].ct_pool_sem));
			ct_descript_node = thread_pools[i].last_ct;
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

						ct_descript_node->thread_age++; // TODO Cancel thread based upon CLIENT_HANDLER_THREAD_MAX_AGE
						ct_descript_node_prev = ct_descript_node;
						ct_descript_node = ct_descript_node->next;
					} else {
						#ifdef ENABLE_LOGGING
							fprintf(stdout, "[MANAGE CLIENT THREAD 0x%x] Joined with client thread with id=0x%x\n", (unsigned int)self_thread_id, (unsigned int)ct_descript_node->thread_id);
						#endif

						if(ct_descript_node == thread_pools[i].first_ct) {
							thread_pools[i].first_ct = NULL;
						}
						if (ct_descript_node == thread_pools[i].last_ct) {
							thread_pools[i].last_ct = ct_descript_node->next;
							ct_descript_node->thread_id = 0;
							ct_descript_node->thread_age = -1;
							ct_descript_node->next = NULL;
							ct_descript_node = thread_pools[i].last_ct;
						} else {
							ct_descript_node_prev->next = ct_descript_node->next;
							ct_descript_node->thread_id = 0;
							ct_descript_node->thread_age = -1;
							ct_descript_node->next = NULL;
							ct_descript_node = ct_descript_node_prev;
						}
						if(thread_pools[i].num_active_client_threads != 0) {
							thread_pools[i].num_active_client_threads--;
						}
						free(res);
					}
				}
			}
			sem_post(&(thread_pools[i].ct_pool_sem));
		}
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

	sleep(5);

	#ifdef ENABLE_LOGGING
		fprintf(stdout, "[CLIENT THREAD 0x%x] Client thread exit\n", (unsigned int)self_thread_id);
	#endif
	close(client_socket);

	pthread_ret = (char *)0;
	pthread_exit(pthread_ret);
}