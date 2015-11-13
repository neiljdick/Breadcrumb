#include "relay.h"

#define ENABLE_LOGGING
#define DEBUG_MODE
//#define ENABLE_THREAD_LOGGING
//#define PRINT_PACKETS

sem_t keystore_sem;

thread_pool thread_pools[NUM_THREAD_POOLS];
client_thread_description msg_client_pool[NUM_MSG_HANDLER_THREADS];
client_thread_description user_id_cache_pool[NUM_USER_ID_CACHE_THREADS];

unsigned int client_msg_port, id_cache_port, cert_request_port;
char *relay_id;
int relay_id_len;
RSA *rsa;
unsigned int max_uid, total_key_clash_backups;

void handle_pthread_ret(char *thread_id, int ret, int clientfd);
void handle_pthread_bytesread(int bytes_read, int clientfd);
void init_globals();

int main(int argc, char const *argv[])
{
	int ret;
	pthread_t certificate_request_thread, thread_pool_manager_thread;
	pthread_t client_msg_new_connection_handler_thread, client_id_cache_handler_thread;

	if(argc != 3) {
		fprintf(stdout, "[MAIN THREAD] Usage: ./%s [RELAY ID] [PORT]\n", program_name);
		exit(-1);
	}
	init_globals();

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

	ret = initialize_key_store("[MAIN THREAD]");
	if(ret < 0) {
		exit(-2);	
	}

	ret = initialize_packet_definitions("[MAIN THREAD]");
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

	ret = initialize_thread_pools();
	if(ret < 0) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Failed to initialize thread pools");
		#endif

		exit(-3);
	}

	ret = pthread_create(&thread_pool_manager_thread, NULL, thread_pool_manager_thread_thread, NULL);
	if(ret != 0) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Failed to create thread pool manager thread, %s\n", strerror(errno));
		#endif

		exit(-4);
	}

	ret = pthread_create(&certificate_request_thread, NULL, certificate_request_handler_thread , NULL);
	if(ret != 0) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Failed to create certificate request thread, %s\n", strerror(errno));
		#endif

		exit(-4);
	}

	ret = pthread_create(&client_msg_new_connection_handler_thread, NULL, client_msg_new_connection_handler, NULL);
	if(ret != 0) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Failed to create new msg connection handler thread, %s\n", strerror(errno));
		#endif

		exit(-4);
	}

	ret = pthread_create(&client_id_cache_handler_thread, NULL, client_id_cache_handler, NULL);
	if(ret != 0) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Failed to create new msg connection handler thread, %s\n", strerror(errno));
		#endif

		exit(-4);
	}

	while(1) sleep(MAIN_THREAD_SLEEP_SEC);

	return 0;
}

void init_globals(void)
{
	client_msg_port = 0;
	id_cache_port = 0; 
	cert_request_port = 0;
	max_uid = 0;
	total_key_clash_backups = 0;
	relay_id = NULL;
	relay_id_len = -1;
	rsa = NULL;
}

int initialize_key_store(char *thread_id)
{
	int ret;

	sem_init(&keystore_sem, 0 , 1);

	#ifdef DEBUG_MODE
		ret = init_key_store(thread_id, SOFT);
	#else
		ret = init_key_store(thread_id, HARD);
	#endif
	if(ret < 0) {
		return -1;
	}

	get_max_user_id(thread_id, &max_uid);
	get_number_of_key_clash_backups(thread_id, &total_key_clash_backups);

	return 0;
}

void *certificate_request_handler_thread(void *ptr)
{
	int ret, certificate_request_listening_socket, client_socket;
	int public_key_buffer_len;
	socklen_t sockaddr_len;
	struct sockaddr_in client_addr;
	char *public_key_buffer;

	#ifdef ENABLE_THREAD_LOGGING
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
			#ifdef ENABLE_THREAD_LOGGING
				fprintf(stdout, "[CERTIFICATE REQUEST THREAD] Failed to accept client connection, %s\n", strerror(errno));
			#endif

			continue;
		}
		#ifdef ENABLE_THREAD_LOGGING
			fprintf(stdout, "[CERTIFICATE REQUEST THREAD] %s:%d requested certificate\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
		#endif

		write(client_socket, &max_uid, sizeof(max_uid));
		write(client_socket, relay_id, relay_id_len); // TODO check all bytes are sent
		write(client_socket, public_key_buffer, public_key_buffer_len);
		fsync(client_socket);
		close(client_socket);

		usleep(CERT_REQUEST_SLEEP_US);
	}
}

void *client_msg_new_connection_handler(void *ptr)
{
	int ret, listening_socket, client_socket;
	socklen_t sockaddr_len;
	struct sockaddr_in client_addr;

	ret = init_listening_socket("[MSG CONNECTION HANDLER THREAD]", client_msg_port, &listening_socket);
	if(ret < 0) {
		exit(-5);
	}
	#ifdef ENABLE_THREAD_LOGGING
		fprintf(stdout, "[MSG CONNECTION HANDLER THREAD] listening on port=%u\n", client_msg_port);
	#endif	

	while(1) {
		sockaddr_len = sizeof(client_addr);
		bzero((char *) &client_addr, sizeof(client_addr));
		client_socket = accept(listening_socket, (struct sockaddr *)&client_addr, &sockaddr_len);
		if(client_socket < 0) {
			#ifdef ENABLE_THREAD_LOGGING
				fprintf(stdout, "[MSG CONNECTION HANDLER THREAD] Failed to accept client connection, %s\n", strerror(errno));
			#endif

			continue;
		}
		#ifdef ENABLE_THREAD_LOGGING
			fprintf(stdout, "[MSG CONNECTION HANDLER THREAD] %s:%d connected\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
		#endif

		add_new_thread_to_pool("[MSG CONNECTION HANDLER THREAD]", MSG_THREAD_POOL_INDEX, client_socket);
	}
}

void *client_id_cache_handler(void *ptr)
{
	int ret, listening_socket, client_socket;
	socklen_t sockaddr_len;
	struct sockaddr_in client_addr;

	ret = init_listening_socket("[ID CACHE HANDLER THREAD]", id_cache_port, &listening_socket);
	if(ret < 0) {
		exit(-5);
	}
	#ifdef ENABLE_THREAD_LOGGING
		fprintf(stdout, "[ID CACHE HANDLER THREAD] Listening on port=%u\n", id_cache_port);
	#endif	

	while(1) {
		sockaddr_len = sizeof(client_addr);
		bzero((char *) &client_addr, sizeof(client_addr));
		client_socket = accept(listening_socket, (struct sockaddr *)&client_addr, &sockaddr_len);
		if(client_socket < 0) {
			#ifdef ENABLE_THREAD_LOGGING
				fprintf(stdout, "[ID CACHE HANDLER THREAD] Failed to accept client connection, %s\n", strerror(errno));
			#endif

			continue;
		}
		#ifdef ENABLE_THREAD_LOGGING
			fprintf(stdout, "[ID CACHE HANDLER THREAD] %s:%d connected\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
		#endif

		add_new_thread_to_pool("[ID CACHE HANDLER THREAD]", USER_ID_CACHE_POOL_INDEX, client_socket);

		usleep(ID_CACHE_SLEEP_US);
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

int add_new_thread_to_pool(char *thread_id, int thread_pool_index, int client_socket)
{
	int ret;
	int unused_thread_index;
	void *thread_arg;

	if(client_socket < 0) {
		return -1;
	}

	sem_wait(&(thread_pools[thread_pool_index].ct_pool_sem));
	if(thread_pools[thread_pool_index].num_active_client_threads >= thread_pools[thread_pool_index].thread_pool_length) {
		#ifdef ENABLE_THREAD_LOGGING
			fprintf(stdout, "%s Unable to accept new client socket connections as number of connections (%u) \
				has reached maximum allowed\n", thread_id, thread_pools[thread_pool_index].num_active_client_threads);
		#endif

		close(client_socket);
		sem_post(&(thread_pools[thread_pool_index].ct_pool_sem));
		return -1;
	}

	get_index_of_unused_thread_descriptor(thread_pools[thread_pool_index].cthread_pool, thread_pools[thread_pool_index].thread_pool_length, &unused_thread_index);
	if(unused_thread_index == -1) {
		#ifdef ENABLE_THREAD_LOGGING
			fprintf(stdout, "%s Client thread pool reached maximum, rejecting client connection attempt\n", thread_id);
		#endif

		close(client_socket);
		sem_post(&(thread_pools[thread_pool_index].ct_pool_sem));
		return -1;
	}
	thread_pools[thread_pool_index].cthread_pool[unused_thread_index].thread_fd = client_socket;
	thread_arg = (void *)&(thread_pools[thread_pool_index].cthread_pool[unused_thread_index].thread_fd);

	ret = pthread_create(&(thread_pools[thread_pool_index].cthread_pool[unused_thread_index].thread_id), NULL, thread_pools[thread_pool_index].start_routine, thread_arg);
	if(ret != 0) {
		#ifdef ENABLE_THREAD_LOGGING
			fprintf(stdout, "%s Failed to create client handler thread, %s\n", thread_id, strerror(errno));
		#endif

		close(client_socket);
		sem_post(&(thread_pools[thread_pool_index].ct_pool_sem));
		return -1;
	}
	thread_pools[thread_pool_index].cthread_pool[unused_thread_index].thread_age = 0;
	thread_pools[thread_pool_index].cthread_pool[unused_thread_index].next = NULL;
	if(thread_pools[thread_pool_index].first_ct == NULL) {
		thread_pools[thread_pool_index].first_ct = &(thread_pools[thread_pool_index].cthread_pool[unused_thread_index]);
		thread_pools[thread_pool_index].last_ct = thread_pools[thread_pool_index].first_ct;
	} else {
		thread_pools[thread_pool_index].first_ct->next = &(thread_pools[thread_pool_index].cthread_pool[unused_thread_index]);
		thread_pools[thread_pool_index].first_ct = thread_pools[thread_pool_index].first_ct->next;
	}
	thread_pools[thread_pool_index].num_active_client_threads++;
	#ifdef ENABLE_THREAD_LOGGING
		fprintf(stdout, "%s New number of active client threads: %u\n", thread_id, thread_pools[thread_pool_index].num_active_client_threads);
	#endif
	sem_post(&(thread_pools[thread_pool_index].ct_pool_sem));

	return 0;
}

int initialize_thread_pools()
{
	unsigned int i, j;

	sem_init(&thread_pools[MSG_THREAD_POOL_INDEX].ct_pool_sem, 0, 1);
	sem_init(&thread_pools[USER_ID_CACHE_POOL_INDEX].ct_pool_sem, 0, 1);

	thread_pools[MSG_THREAD_POOL_INDEX].start_routine = handle_msg_client_thread;
	thread_pools[USER_ID_CACHE_POOL_INDEX].start_routine = handle_id_cache_thread;

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
	int ret, i;
	void *res;
	struct client_thread_description *ct_descript_node, *ct_descript_node_prev;
	
	#ifdef ENABLE_THREAD_LOGGING
		pthread_t self_thread_id;
		self_thread_id = pthread_self();
		fprintf(stdout, "[MANAGE CLIENT THREAD 0x%x] Created manage client thread\n", (unsigned int)self_thread_id);
	#endif

	while(1) {
		sleep(5);

		for(i = 0; i < NUM_THREAD_POOLS; i++) {
			sem_wait(&(thread_pools[i].ct_pool_sem));
			ct_descript_node = thread_pools[i].last_ct;
			ct_descript_node_prev = NULL;
			if(ct_descript_node == NULL) {
				#ifdef ENABLE_THREAD_LOGGING
					char pool_id_buf[POOL_ID_LEN];
					get_thread_pool_id_from_index(i, pool_id_buf);
					fprintf(stdout, "[MANAGE CLIENT THREAD 0x%x] Found no client threads to manage for thread pool = %s\n", (unsigned int)self_thread_id, pool_id_buf);
				#endif
			} else {
				while(ct_descript_node != NULL) {
					ret = pthread_tryjoin_np(ct_descript_node->thread_id, &res);
					if(ret != 0) {
						#ifdef ENABLE_THREAD_LOGGING
							fprintf(stdout, "[MANAGE CLIENT THREAD 0x%x] Found client thread with id=0x%x still active\n", (unsigned int)self_thread_id, (unsigned int)ct_descript_node->thread_id);
						#endif

						ct_descript_node->thread_age++; // TODO Cancel thread based upon CLIENT_HANDLER_THREAD_MAX_AGE
						ct_descript_node_prev = ct_descript_node;
						ct_descript_node = ct_descript_node->next;
					} else {
						#ifdef ENABLE_THREAD_LOGGING
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
							#ifdef ENABLE_THREAD_LOGGING
								fprintf(stdout, "[MSG CONNECTION HANDLER THREAD] New number of active client threads: %u\n", thread_pools[i].num_active_client_threads);
							#endif
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

void *handle_msg_client_thread(void *ptr)
{
	int i, ret, bytes_read, client_socket;
	char *pthread_ret;
	pthread_t self_thread_id;
	unsigned char packet_data_encrypted[packet_size_bytes], packet_data_decrypted[packet_size_bytes];
	unsigned char payload_data_decrypted[packet_size_bytes], packet_data[packet_size_bytes];
	onion_route_data *or_data_ptr, *or_payload_data_ptr;
	onion_route_data *or_data_decrypted_ptr, *or_payload_data_decrypted_ptr;
	char thread_id_buf[64];
	key_entry ke_entry;
	struct in_addr next_addr;
	payload_data *pd_ptr;
	uint16_t ord_checksum;

	self_thread_id = pthread_self();
	sprintf(thread_id_buf, "[MSG CLIENT THREAD 0x%x]", (unsigned int)self_thread_id);
	#ifdef ENABLE_THREAD_LOGGING
		fprintf(stdout, "%s Created new client thread\n", thread_id_buf);
	#endif

	if(ptr == NULL) {
		pthread_ret = (char *)-1;
		pthread_exit(pthread_ret);
	}
	client_socket = *((int *)ptr);	

	bytes_read = 0;
	for(i = 0; i < NUM_READ_ATTEMPTS; i++) {
		bytes_read += read(client_socket, (packet_data_encrypted + bytes_read), (packet_size_bytes - bytes_read));
		if(bytes_read < 0)
			break;
	}
	handle_pthread_bytesread(bytes_read, client_socket);
	#ifdef PRINT_PACKETS
		fprintf(stdout, "\n ------------------------------------------------------------ \n\n");
		for (i = 0; i < packet_size_bytes; ++i) {
			fprintf(stdout, "%02x", packet_data_encrypted[i]);
		}
		fprintf(stdout, "\n\n ------------------------------------------------------------ \n");
	#endif
	
	or_data_ptr = (onion_route_data *)packet_data_encrypted;
	or_data_decrypted_ptr = (onion_route_data *)packet_data_decrypted;

	for (i = -1; i < (int)total_key_clash_backups; ++i) {
		ret = get_key_for_user_id(thread_id_buf, or_data_ptr->uid, i, &ke_entry);
		handle_pthread_ret(thread_id_buf, ret, client_socket);
		if(ke_entry.age < 0) {
			continue;
		}
		// TODO - If succeeded and i != -1 need to swap current mapping to RAM

		ret = aes_decrypt_block(thread_id_buf, (unsigned char *)&(or_data_ptr->ord_enc), (payload_start_byte - cipher_text_byte_offset), 
									(unsigned char *)ke_entry.p_key.value, AES_KEY_SIZE_BYTES, or_data_ptr->iv, (packet_data_decrypted + cipher_text_byte_offset));
		handle_pthread_ret(thread_id_buf, ret, client_socket);

		get_ord_packet_checksum(&(or_data_decrypted_ptr->ord_enc), &ord_checksum);
		if(ord_checksum == 0) {
			break;
		}
	}
	if(i >= (int)total_key_clash_backups) {
		handle_pthread_ret(thread_id_buf, -5, client_socket);
	}

	remove_currently_mapped_key_from_key_store(thread_id_buf);
	ret = set_key_for_user_id(thread_id_buf, or_data_decrypted_ptr->ord_enc.new_uid, (key *)&(or_data_decrypted_ptr->ord_enc.new_key));
	handle_pthread_ret(thread_id_buf, ret, client_socket);

	or_payload_data_ptr = (onion_route_data *)(packet_data_encrypted + payload_start_byte);
	or_payload_data_decrypted_ptr = (onion_route_data *)payload_data_decrypted;

	for (i = -1; i < (int)total_key_clash_backups; ++i) {
		ret = get_key_for_user_id(thread_id_buf, or_payload_data_ptr->uid, i, &ke_entry);
		handle_pthread_ret(thread_id_buf, ret, client_socket);
		if(ke_entry.age < 0) {
			continue;
		}

		ret = aes_decrypt_block(thread_id_buf, (unsigned char *)&(or_payload_data_ptr->ord_enc), (packet_size_bytes - payload_start_byte - cipher_text_byte_offset), 
									(unsigned char *)ke_entry.p_key.value, AES_KEY_SIZE_BYTES, or_payload_data_ptr->iv, (payload_data_decrypted + cipher_text_byte_offset));
		handle_pthread_ret(thread_id_buf, ret, client_socket);

		get_ord_packet_checksum(&(or_payload_data_decrypted_ptr->ord_enc), &ord_checksum);
		if(ord_checksum == 0) {
			break;
		}
	}
	if(i >= (int)total_key_clash_backups) {
		handle_pthread_ret(thread_id_buf, -5, client_socket);
	}

	remove_currently_mapped_key_from_key_store(thread_id_buf);
	ret = set_key_for_user_id(thread_id_buf, or_payload_data_decrypted_ptr->ord_enc.new_uid, (key *)&(or_payload_data_decrypted_ptr->ord_enc.new_key));
	handle_pthread_ret(thread_id_buf, ret, client_socket);
	
	ret = fill_buf_with_random_data(packet_data, packet_size_bytes);
	handle_pthread_ret(thread_id_buf, ret, client_socket);
	memcpy(packet_data, (packet_data_decrypted + sizeof(onion_route_data)), (sizeof(onion_route_data) * 2));
	memcpy((packet_data + payload_start_byte), (payload_data_decrypted + sizeof(onion_route_data)), (packet_size_bytes - payload_start_byte - sizeof(onion_route_data)));

	if(or_data_decrypted_ptr->ord_enc.next_pkg_ip == 0) {
		pd_ptr = (payload_data *)(packet_data + payload_start_byte);

		handle_non_route_packet(thread_id_buf, pd_ptr);
	} else {
		next_addr.s_addr = or_data_decrypted_ptr->ord_enc.next_pkg_ip;
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Found next ip = %s, port = %u\n", thread_id_buf, inet_ntoa(next_addr), or_data_decrypted_ptr->ord_enc.next_pkg_port);
		#endif

		send_packet_to_relay(packet_data, inet_ntoa(next_addr), or_data_decrypted_ptr->ord_enc.next_pkg_port);
	}

	#ifdef ENABLE_THREAD_LOGGING
		fprintf(stdout, "%s Client thread exit\n", thread_id_buf);
	#endif

	close(client_socket);
	pthread_ret = (char *)0;
	pthread_exit(pthread_ret);
}

int handle_non_route_packet(char *thread_id, payload_data *pd_ptr)
{
	int ret;
	struct in_addr next_addr;
	uint16_t next_port;
	unsigned char packet_data[packet_size_bytes];

	switch(pd_ptr->type) {
		case DUMMY_PACKET_W_RETURN_ROUTE:
			next_addr.s_addr = (((uint64_t)pd_ptr->client_id) << 32) | ((uint64_t)pd_ptr->conversation_id);
			next_port = pd_ptr->onion_r1;
			#ifdef ENABLE_LOGGING
				fprintf(stdout, "%s Received non-route packet, type = %s. Next ip = %s, port = %u\n", thread_id, get_string_for_payload_type(pd_ptr->type), inet_ntoa(next_addr), next_port);
			#endif

			ret = fill_buf_with_random_data(packet_data, packet_size_bytes);
			if(ret < 0) {
				return -1;
			}
			memcpy(packet_data, pd_ptr->payload, sizeof(pd_ptr->payload));

			send_packet_to_relay(packet_data, inet_ntoa(next_addr), next_port);
		break;
	}

	return 0;
}

void *handle_id_cache_thread(void *ptr)
{
	int i, bytes_read;
	int client_socket;
	char *pthread_ret;
	pthread_t self_thread_id;
	unsigned char packet_data_encrypted[packet_size_bytes], packet_data[packet_size_bytes];
	id_cache_data *id_data;
	char buf[64];

	self_thread_id = pthread_self();
	sprintf(buf, "[ID CACHE CLIENT THREAD 0x%x]", (unsigned int)self_thread_id);
	#ifdef ENABLE_THREAD_LOGGING
		fprintf(stdout, "%s Created new client thread\n", buf);
	#endif

	if(ptr == NULL) {
		#ifdef ENABLE_THREAD_LOGGING
			fprintf(stdout, "%s Handle client thread created with null arguments\n", buf);
		#endif

		pthread_ret = (char *)-1;
		pthread_exit(pthread_ret);
	}
	client_socket = *((int *)ptr);

	bytes_read = 0;
	for(i = 0; i < NUM_READ_ATTEMPTS; i++) {
		bytes_read += read(client_socket, (packet_data_encrypted + bytes_read), (packet_size_bytes - bytes_read));
		if(bytes_read < 0)
			break;
	}
	handle_pthread_bytesread(bytes_read, client_socket);
	#ifdef PRINT_PACKETS
		fprintf(stdout, "\n ------------------------------------------------------------ \n\n");
		for (i = 0; i < packet_size_bytes; ++i) {
			fprintf(stdout, "%02x", packet_data_encrypted[i]);
		}
		fprintf(stdout, "\n\n ------------------------------------------------------------ \n");
	#endif
	
	RSA_private_decrypt(RSA_KEY_LENGTH_BYTES, (packet_data_encrypted + payload_start_byte), packet_data, rsa, RSA_PKCS1_OAEP_PADDING);
	id_data = ((id_cache_data *)packet_data);
	#ifdef ENABLE_LOGGING
		fprintf(stdout, "%s Received id cache data\n", buf);
	#endif

	sem_wait(&keystore_sem);
	set_key_for_user_id(buf, id_data->relay_user_id, (key *)id_data->aes_key);
	set_key_for_user_id(buf, id_data->payload_relay_user_id, (key *)id_data->payload_aes_key);
	set_key_for_user_id(buf, id_data->return_route_user_id, (key *)id_data->return_route_aes_key);
	set_key_for_user_id(buf, id_data->return_route_payload_user_id, (key *)id_data->return_route_payload_aes_key);
	sem_post(&keystore_sem);

	#ifdef ENABLE_THREAD_LOGGING
		fprintf(stdout, "%s Client thread exit\n", buf);
	#endif

	// TODO need to prevent flood of new keys from non relay client! Make sure only 1 packet / 3 sec from same IP

	close(client_socket);
	pthread_ret = (char *)0;
	pthread_exit(pthread_ret);
}

int send_packet_to_relay(unsigned char *packet, char *destination_ip, int destination_port)
{
	int i, ret, bytes_sent;
	int source_port, cr_socket;
	struct sockaddr_in serv_addr, client_addr;
	unsigned int initial_seed_value;

	cr_socket = socket(AF_INET, SOCK_STREAM, 0);
	if(cr_socket < 0){
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Failed to create stream socket\n");
		#endif

		return -1;
	}

	apply_packet_mixing_delay();

	// Lets randomize the source port (otherwise linux just increments by 3 each time)
	bzero((char *) &client_addr, sizeof(client_addr));
	client_addr.sin_family = AF_INET;
	for(i = 0; i < NUM_BIND_ATTEMPTS; i++) {
		initial_seed_value = (((unsigned int)relay_id[1])<<24) | (((unsigned int)relay_id[3])<<16) | (((unsigned int)relay_id[0])<<8) | ((unsigned int)relay_id[2]);
		source_port = get_pseudo_random_number(initial_seed_value);
		source_port %= 65535;
		if(source_port < 16384)
			source_port += 16384;
		client_addr.sin_port = htons(source_port);

		ret = bind(cr_socket, (struct sockaddr *) &client_addr, sizeof(client_addr));
		if(ret == 0)
			break;

		usleep(100000);
	}

	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(destination_port);
	serv_addr.sin_addr.s_addr = inet_addr(destination_ip);
	ret = connect(cr_socket, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
	if(ret != 0){
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Failed to connect to relay with ip = %s\n", destination_ip);
		#endif

		return -1;
	}

	bytes_sent = 0;
	for (i = 0; i < MAX_SEND_ATTEMPTS; i++) {
		bytes_sent += write(cr_socket, (packet + bytes_sent), (packet_size_bytes - bytes_sent));
		if(bytes_sent == packet_size_bytes) {
			break;
		}
	}
	close(cr_socket);

	if(bytes_sent != packet_size_bytes) {
		return -1;
	}
	return 0;
}

int get_thread_pool_id_from_index(int index, char *pool_id /* out */)
{
	if(pool_id == NULL) {
		return -1;
	}

	memset(pool_id, 0, POOL_ID_LEN);
	if(index == MSG_THREAD_POOL_INDEX) {
		memcpy(pool_id, msg_handler_str, strlen(msg_handler_str));
	} else if (index == USER_ID_CACHE_POOL_INDEX) {
		memcpy(pool_id, id_cache_handler_str, strlen(id_cache_handler_str));
	} else {
		memcpy(pool_id, unknown_str, strlen(unknown_str));
	}

	return 0;
}

int apply_packet_mixing_delay(void)
{
	unsigned int sleep_time_usec;

	sleep_time_usec = get_pseudo_random_number(0);
	sleep_time_usec %= MAX_PACKET_TRANSMIT_DELAY_USEC;
	usleep(sleep_time_usec);

	return 0;
}

void print_ret_code(char *thread_id, int ret)
{
	#ifdef ENABLE_LOGGING
		if(ret == -5) {
			fprintf(stdout, "%s Failed to retrieve key\n", thread_id);
		} else if (ret < 0) {
			fprintf(stdout, "%s Generic thread error\n", thread_id);
		}
	#endif
}

void handle_pthread_ret(char *thread_id, int ret, int clientfd)
{
	char *pthread_ret;

	if(ret < 0) {
		print_ret_code(thread_id, ret);
		if(clientfd >= 0) {
			close(clientfd);
		}
		pthread_ret = (char *)0;
		pthread_exit(pthread_ret);
	}
}

void handle_pthread_bytesread(int bytes_read, int clientfd)
{
	char *pthread_ret;

	if(bytes_read != packet_size_bytes) {
		close(clientfd);
		pthread_ret = (char *)0;
		pthread_exit(pthread_ret);
	}
}