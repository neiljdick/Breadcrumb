#include "node.h"

#define ENABLE_LOGGING
#define ENABLE_LOG_ON_EXIT
//#define ENABLE_THREAD_LOGGING
//#define ENABLE_PACKET_LOGGING
//#define ENABLE_UID_LOGGING
//#define LOG_TO_FILE_INSTEAD_OF_STDOUT
//#define SOFT_RESET_KEY_STORE
//#define ENABLE_BANDWIDTH_REPORTING_UI

sem_t keystore_sem, logging_sem;

thread_pool thread_pools[NUM_THREAD_POOLS];
client_thread_description msg_client_pool[NUM_MSG_HANDLER_THREADS];
client_thread_description user_id_cache_pool[NUM_USER_ID_CACHE_THREADS];

unsigned int g_client_msg_port, g_id_cache_port, g_cert_request_port;
unsigned int g_max_uid, g_total_key_clash_backups;
char *g_node_id;
int g_node_id_len;
RSA *rsa;
logging_interval g_logging_interval;
logging_data g_logging_data;
unsigned int num_node_packets_bandwidth_report;

payload_data g_message_cache[32];
int g_message_index = 0;

void init_globals(int argc, char *argv[]);
void handle_pthread_ret(char *thread_id, int ret);
void handle_pthread_bytesread(int bytes_read, int clientfd);
void update_amount_of_keys_used_for_logging(void);
void handle_logging(void);
void log_data_to_file(int dummy);
void log_data_to_file_and_exit(int dummy);
void handle_bandwidth_reporting(void);

#ifdef ENABLE_UID_LOGGING
FILE *fp_set_uids=NULL;
#endif

int main(int argc, char *argv[])
{
	int ret, n, one_sec_count;
	pthread_t certificate_request_thread, thread_pool_manager_thread;
	pthread_t client_msg_new_connection_handler_thread, client_id_cache_handler_thread;

	#ifdef ENABLE_UID_LOGGING
		fp_set_uids = fopen("set_uids.csv", "w");
		if(fp_set_uids == NULL)
			exit(1);
	#endif

	init_globals(argc, argv);

	signal(SIGUSR1, log_data_to_file);
	#ifdef ENABLE_LOG_ON_EXIT
		signal(SIGINT, log_data_to_file_and_exit);
	#endif

	#ifdef ENABLE_LOGGING
		fprintf(stdout, "[MAIN THREAD] %s program begin\n", program_name);
	#endif

	ret = load_rsa_key_pair(g_node_id, &rsa);
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

	n = 0;
	one_sec_count = (USEC_PER_SEC/MAIN_THREAD_SLEEP_USEC);
	while(1) {
		usleep(MAIN_THREAD_SLEEP_USEC);

		#ifdef ENABLE_BANDWIDTH_REPORTING_UI
			handle_bandwidth_reporting();
		#endif
			
		n++;
		if(n >= one_sec_count)  {
			handle_logging();
			sem_wait(&keystore_sem);
			handle_key_entry_age_increment("[MAIN THREAD]");
			sem_post(&keystore_sem);
		}		
		if(n >= one_sec_count) {
			n = 0;
		}
	}

	return 0;
}

void init_globals(int argc, char *argv[])
{
	int ret;

	if(argv == NULL) {
		exit(-1);
	}

	if(argc < 3) {
		fprintf(stdout, "[MAIN THREAD] Usage: ./%s NODE_ID PORT [LOGGING INTERVAL]\n", program_name);
		exit(-1);
	}

	#ifdef LOG_TO_FILE_INSTEAD_OF_STDOUT
		char buf[256];
		sprintf(buf, "%s.log", argv[1]);
		freopen(buf, "w", stdout);
	#endif

	ret = get_sha256_hash_of_string("[MAIN THREAD]", NODE_ID_HASH_COUNT, argv[1], &g_node_id, &g_node_id_len);
	if(ret < 0) {
		exit(-2);	
	}
	#ifdef ENABLE_LOGGING
		fprintf(stdout, "[MAIN THREAD] Node id=%s\n", g_node_id);
	#endif

	g_client_msg_port = (unsigned int)atoi(argv[2]);
	if(g_client_msg_port > PORT_MAX) {
		fprintf(stdout, "[MAIN THREAD] Port number (%u) must be less than %u\n", g_client_msg_port, PORT_MAX);
		exit(-5);
	}
	if(g_client_msg_port < PORT_MIN) {
		fprintf(stdout, "[MAIN THREAD] Port number (%u) must be greater than %u\n", g_client_msg_port, PORT_MIN);
		exit(-5);
	}
	g_id_cache_port = g_client_msg_port + 1;
	g_cert_request_port = g_client_msg_port + 2;

	g_max_uid = 0;
	g_total_key_clash_backups = 0;
	rsa = NULL;

	sem_init(&logging_sem, 0, 1);
	memset(&g_logging_data, 0, sizeof(g_logging_data));

	memset(g_message_cache, 0, sizeof(g_message_cache)); // TODO - remove

	if(argc > 3) {
		g_logging_interval = (unsigned int)atoi(argv[3]);
		if(g_logging_interval > PER_WEEK) {
			g_logging_interval = DEFAULT_LOGGING_INTERVAL;
		}
	} else {
		g_logging_interval = DEFAULT_LOGGING_INTERVAL;
	}
	
}

int initialize_key_store(char *thread_id)
{
	int ret;

	sem_init(&keystore_sem, 0, 1);

	#ifdef SOFT_RESET_KEY_STORE
		ret = init_key_store(thread_id, SOFT);
	#else
		ret = init_key_store(thread_id, HARD);
	#endif
	if(ret < 0) {
		return -1;
	}

	get_max_user_id(thread_id, &g_max_uid);
	get_number_of_key_clash_backups(thread_id, &g_total_key_clash_backups);

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

	ret = init_listening_socket("[CERTIFICATE REQUEST THREAD]", g_cert_request_port, &certificate_request_listening_socket);
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

		write(client_socket, &g_max_uid, sizeof(g_max_uid));
		write(client_socket, g_node_id, g_node_id_len); // TODO check all bytes are sent
		write(client_socket, public_key_buffer, public_key_buffer_len);
		fsync(client_socket);
		close(client_socket);

		sem_wait(&logging_sem);
		g_logging_data.num_cert_requests[g_logging_data.logging_index]++;
		sem_post(&logging_sem);

		usleep(CERT_REQUEST_SLEEP_US);
	}
}

void *client_msg_new_connection_handler(void *ptr)
{
	int ret, listening_socket, client_socket;
	socklen_t sockaddr_len;
	struct sockaddr_in client_addr;

	ret = init_listening_socket("[MSG CONNECTION HANDLER THREAD]", g_client_msg_port, &listening_socket);
	if(ret < 0) {
		exit(-5);
	}
	#ifdef ENABLE_THREAD_LOGGING
		fprintf(stdout, "[MSG CONNECTION HANDLER THREAD] listening on port=%u\n", g_client_msg_port);
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

		sem_wait(&logging_sem);
		g_logging_data.total_num_of_node_threads_created[g_logging_data.logging_index]++;
		sem_post(&logging_sem);
	}
}

void *client_id_cache_handler(void *ptr)
{
	int ret, listening_socket, client_socket;
	socklen_t sockaddr_len;
	struct sockaddr_in client_addr;

	ret = init_listening_socket("[ID CACHE HANDLER THREAD]", g_id_cache_port, &listening_socket);
	if(ret < 0) {
		exit(-5);
	}
	#ifdef ENABLE_THREAD_LOGGING
		fprintf(stdout, "[ID CACHE HANDLER THREAD] Listening on port=%u\n", g_id_cache_port);
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

		sem_wait(&logging_sem);
		g_logging_data.total_num_of_id_cache_threads_created[g_logging_data.logging_index]++;
		sem_post(&logging_sem);

		usleep(ID_CACHE_SLEEP_US);
	}
}

int init_listening_socket(char *thread_id, unsigned int port, int *listening_socket /* out */)
{
	struct sockaddr_in serv_addr;

	if(port > PORT_MAX) {
		exit(1);
	}
	if(listening_socket == NULL) {
		exit(1);
	}

	*listening_socket = socket(AF_INET, SOCK_STREAM, 0);
	if(*listening_socket < 0){
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Failed to create stream socket\n", thread_id);
		#endif

		exit(1);
	}

	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(port);
	if (bind(*listening_socket, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Error on binding\n", thread_id);
		#endif

		exit(1);
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
		sleep(1);
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
					if(ct_descript_node->thread_id == 0) { // TODO - something went wrong here
						;
					}
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
							if(ct_descript_node == thread_pools[i].last_ct) {
								thread_pools[i].first_ct = NULL;
								thread_pools[i].last_ct = NULL;
							} else {
								thread_pools[i].first_ct = ct_descript_node_prev;
								thread_pools[i].first_ct->next = NULL;
							}
							ct_descript_node->thread_id = 0;
							ct_descript_node->thread_age = -1;
							ct_descript_node = NULL;
						} else if (ct_descript_node == thread_pools[i].last_ct) {
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
							ct_descript_node = ct_descript_node_prev->next;
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
	#ifdef ENABLE_PACKET_LOGGING
		fprintf(stdout, "\n ------------------------------------------------------------ \n\n");
		for (i = 0; i < packet_size_bytes; ++i) {
			fprintf(stdout, "%02x", packet_data_encrypted[i]);
		}
		fprintf(stdout, "\n\n ------------------------------------------------------------ \n");
	#endif

	sem_wait(&keystore_sem);
	
	or_data_ptr = (onion_route_data *)packet_data_encrypted;
	or_data_decrypted_ptr = (onion_route_data *)packet_data_decrypted;

	for (i = -1; i < (int)g_total_key_clash_backups; ++i) {
		ret = get_key_for_user_id(thread_id_buf, or_data_ptr->uid, i, &ke_entry);
		if((ret < 0) || ((i == -1) && (ke_entry.age == 0))) {
			sem_post(&keystore_sem);
			close(client_socket);
			sem_wait(&logging_sem);
			g_logging_data.num_key_get_failures[g_logging_data.logging_index]++;
			fprintf(stderr, "KF_OD_I: %u\n", or_data_ptr->uid);
			sem_post(&logging_sem);
			handle_pthread_ret(thread_id_buf, -5);
		} 
		if(((~key_clash_tag) & ke_entry.age) == 0) {
			continue;
		}

		ret = aes_decrypt_block(thread_id_buf, (unsigned char *)&(or_data_ptr->ord_enc), (payload_start_byte - cipher_text_byte_offset), 
									(unsigned char *)ke_entry.p_key.value, AES_KEY_SIZE_BYTES, or_data_ptr->iv, (packet_data_decrypted + cipher_text_byte_offset));
		if(ret < 0) {
			sem_post(&keystore_sem);
			close(client_socket);
			handle_pthread_ret(thread_id_buf, ret);
		}

		get_ord_packet_checksum(&(or_data_decrypted_ptr->ord_enc), &ord_checksum);
		if(ord_checksum == 0) {
			// TODO - If succeeded and i != -1 need to swap current mapping to RAM
			break;
		}
	}
	if(i >= (int)g_total_key_clash_backups) {
		sem_post(&keystore_sem);
		close(client_socket);
		sem_wait(&logging_sem);
		g_logging_data.num_key_get_failures[g_logging_data.logging_index]++;
		fprintf(stderr, "KF_OD: %u\n", or_data_ptr->uid);
		sem_post(&logging_sem);
		handle_pthread_ret(thread_id_buf, -5);
	}

	remove_key_from_key_store(thread_id_buf, or_data_ptr->uid, i);
	ret = set_key_for_user_id(thread_id_buf, or_data_decrypted_ptr->ord_enc.new_uid, (key *)&(or_data_decrypted_ptr->ord_enc.new_key));
	if(ret < 0) {
		sem_post(&keystore_sem);
		close(client_socket);
		handle_pthread_ret(thread_id_buf, ret);
	}
	#ifdef ENABLE_UID_LOGGING
		fprintf(fp_set_uids, "%u,\n", or_data_decrypted_ptr->ord_enc.new_uid);
	#endif

	or_payload_data_ptr = (onion_route_data *)(packet_data_encrypted + payload_start_byte);
	or_payload_data_decrypted_ptr = (onion_route_data *)payload_data_decrypted;

	for (i = -1; i < (int)g_total_key_clash_backups; ++i) {
		ret = get_key_for_user_id(thread_id_buf, or_payload_data_ptr->uid, i, &ke_entry);
		if((ret < 0) || ((i == -1) && (ke_entry.age == 0))) {
			sem_post(&keystore_sem);
			close(client_socket);
			sem_wait(&logging_sem);
			g_logging_data.num_key_get_failures[g_logging_data.logging_index]++;
			fprintf(stderr, "KF_PD_I: %u\n", or_payload_data_ptr->uid);
			sem_post(&logging_sem);
			handle_pthread_ret(thread_id_buf, -5);
		} 
		if(((~key_clash_tag) & ke_entry.age) == 0) {
			continue;
		}

		ret = aes_decrypt_block(thread_id_buf, (unsigned char *)&(or_payload_data_ptr->ord_enc), (packet_size_bytes - payload_start_byte - cipher_text_byte_offset), 
									(unsigned char *)ke_entry.p_key.value, AES_KEY_SIZE_BYTES, or_payload_data_ptr->iv, (payload_data_decrypted + cipher_text_byte_offset));
		if(ret < 0) {
			sem_post(&keystore_sem);
			close(client_socket);
			handle_pthread_ret(thread_id_buf, ret);
		}

		get_ord_packet_checksum(&(or_payload_data_decrypted_ptr->ord_enc), &ord_checksum);
		if(ord_checksum == 0) {
			break;
		}
	}
	if(i >= (int)g_total_key_clash_backups) {
		sem_post(&keystore_sem);
		close(client_socket);
		sem_wait(&logging_sem);
		g_logging_data.num_key_get_failures[g_logging_data.logging_index]++;
		fprintf(stderr, "KF_PD: %u\n", or_payload_data_ptr->uid);
		sem_post(&logging_sem);
		handle_pthread_ret(thread_id_buf, -5);
	}

	remove_key_from_key_store(thread_id_buf, or_payload_data_ptr->uid, i);
	ret = set_key_for_user_id(thread_id_buf, or_payload_data_decrypted_ptr->ord_enc.new_uid, (key *)&(or_payload_data_decrypted_ptr->ord_enc.new_key));
	if(ret < 0) {
		sem_post(&keystore_sem);
		close(client_socket);
		handle_pthread_ret(thread_id_buf, ret);
	}
	#ifdef ENABLE_UID_LOGGING
		fprintf(fp_set_uids, "%u,\n", or_payload_data_decrypted_ptr->ord_enc.new_uid);
	#endif

	sem_post(&keystore_sem);
	
	ret = fill_buf_with_random_data(packet_data, packet_size_bytes);
	if(ret < 0) {
		close(client_socket);
		handle_pthread_ret(thread_id_buf, ret);
	}
	memcpy(packet_data, (packet_data_decrypted + sizeof(onion_route_data)), (sizeof(onion_route_data) * 2));
	memcpy((packet_data + payload_start_byte), (payload_data_decrypted + sizeof(onion_route_data)), (packet_size_bytes - payload_start_byte - sizeof(onion_route_data)));

	if(or_data_decrypted_ptr->ord_enc.next_pkg_ip == 0) {
		pd_ptr = (payload_data *)(packet_data + payload_start_byte);

		handle_non_route_packet(thread_id_buf, pd_ptr);

		sem_wait(&logging_sem);
		g_logging_data.num_non_node_packets[g_logging_data.logging_index]++;
		g_logging_data.total_num_of_node_threads_destroyed[g_logging_data.logging_index]++;
		num_node_packets_bandwidth_report += 1;
		sem_post(&logging_sem);
	} else {
		next_addr.s_addr = or_data_decrypted_ptr->ord_enc.next_pkg_ip;
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Received routing packet, next ip = %s, port = %u\n", thread_id_buf, inet_ntoa(next_addr), or_data_decrypted_ptr->ord_enc.next_pkg_port);
		#endif

		send_packet_to_node(packet_data, inet_ntoa(next_addr), or_data_decrypted_ptr->ord_enc.next_pkg_port);

		sem_wait(&logging_sem);
		g_logging_data.num_node_packets[g_logging_data.logging_index]++;
		g_logging_data.total_num_of_node_threads_destroyed[g_logging_data.logging_index]++;
		num_node_packets_bandwidth_report += 2;
		sem_post(&logging_sem);
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
	int i, ret;
	struct in_addr next_addr;
	unsigned int next_port;
	unsigned char packet_data[packet_size_bytes];
	return_route_ip_data *rr1_ip_data, *rr2_ip_data;
	struct in_addr rr1_ip_addr, rr2_ip_addr;

	switch(pd_ptr->type) {
		case DUMMY_PACKET_NO_RETURN_ROUTE:
			#ifdef ENABLE_LOGGING
				fprintf(stdout, "%s Received non-route packet, type = %s. Dropping packet\n", thread_id, get_string_for_payload_type(pd_ptr->type));
			#endif	
		break;
		case DUMMY_PACKET_W_RETURN_ROUTE:
			next_addr.s_addr = (((uint64_t)pd_ptr->client_id) << 32) | ((uint64_t)pd_ptr->conversation_id);
			next_port = (unsigned int)pd_ptr->onion_r1;
			#ifdef ENABLE_LOGGING
				fprintf(stdout, "%s Received non-route packet, type = %s. Next ip = %s, port = %u\n", thread_id, get_string_for_payload_type(pd_ptr->type), inet_ntoa(next_addr), next_port);
			#endif

			ret = fill_buf_with_random_data(packet_data, packet_size_bytes);
			if(ret < 0) {
				return -1;
			}
			memcpy(packet_data, pd_ptr->payload, sizeof(pd_ptr->payload));

			send_packet_to_node(packet_data, inet_ntoa(next_addr), next_port);
		break;
		case MESSAGE_PACKET:
			#ifdef ENABLE_LOGGING
				fprintf(stdout, "%s Received message packet, onion_r1 = 0x%x, order = 0x%x, client_id = 0x%x, conversation_id = 0x%x. Storing packet\n", 
									thread_id, pd_ptr->onion_r1, pd_ptr->order, pd_ptr->client_id, pd_ptr->conversation_id);
			#endif
			memcpy(&(g_message_cache[g_message_index]), pd_ptr, sizeof(payload_data)); // TODO
			if((++g_message_index) >= 32) {
				g_message_index = 0;
			}
		break;
		case DUAL_RETURN_ROUTE:
			#ifdef ENABLE_LOGGING
				rr1_ip_data = (return_route_ip_data *)pd_ptr->payload;
				rr2_ip_data = (return_route_ip_data *)(pd_ptr->payload + payload_start_byte);
				rr1_ip_addr.s_addr = rr1_ip_data->onion_return_ip;
				rr2_ip_addr.s_addr = rr2_ip_data->onion_return_ip;

				fprintf(stdout, "%s Received return route packet, onion_r1 = 0x%x, onion_r2 = 0x%x, client_id = 0x%x, conversation_id = 0x%x ", 
									thread_id, pd_ptr->onion_r1, pd_ptr->onion_r2, pd_ptr->client_id, pd_ptr->conversation_id);
				fprintf(stdout, "onion_r1_ip = %s, onion_r1_port = %u, onion_r1_ip = %s, onion_r2_port = %u. Searching for matching message packet\n", 
										inet_ntoa(rr1_ip_addr), rr1_ip_data->onion_return_port, inet_ntoa(rr2_ip_addr), rr2_ip_data->onion_return_port);
			#endif
			for (i = 0; i < 32; ++i) {
				if((pd_ptr->client_id != g_message_cache[i].client_id) && 
						(pd_ptr->onion_r1 == g_message_cache[i].onion_r1) &&
							(pd_ptr->conversation_id == g_message_cache[i].conversation_id)) {
					fprintf(stdout, "Found matching onion, %x\n", pd_ptr->onion_r1);

					ret = fill_buf_with_random_data(packet_data, packet_size_bytes);
					if(ret < 0) {
						return -1;
					}
					memcpy(packet_data, pd_ptr->payload + sizeof(return_route_ip_data), ((sizeof(onion_route_data) * 3) - sizeof(return_route_ip_data)));
					memcpy(packet_data + payload_start_byte, g_message_cache[i].payload, PAYLOAD_SIZE_BYTES);

					send_packet_to_node(packet_data, inet_ntoa(rr1_ip_addr), rr1_ip_data->onion_return_port);

					memset(&(g_message_cache[i]), 0, sizeof(payload_data));
					break;
				} else if((pd_ptr->client_id != g_message_cache[i].client_id) && 
							(pd_ptr->onion_r2 == g_message_cache[i].onion_r1) &&
								(pd_ptr->conversation_id == g_message_cache[i].conversation_id)) {
					fprintf(stdout, "Found matching onion, %x\n", pd_ptr->onion_r2);

					ret = fill_buf_with_random_data(packet_data, packet_size_bytes);
					if(ret < 0) {
						return -1;
					}
					memcpy(packet_data, pd_ptr->payload + (sizeof(onion_route_data) * 3) + sizeof(return_route_ip_data), ((sizeof(onion_route_data) * 3) - sizeof(return_route_ip_data)));
					memcpy(packet_data + payload_start_byte, g_message_cache[i].payload, PAYLOAD_SIZE_BYTES);

					send_packet_to_node(packet_data, inet_ntoa(rr2_ip_addr), rr2_ip_data->onion_return_port);

					memset(&(g_message_cache[i]), 0, sizeof(payload_data));
					break;
				}
			}
			if(i == 32) {
				fprintf(stdout, "Failed to find matching message packet\n");
			}
		break;
		default:
			#ifdef ENABLE_LOGGING
				fprintf(stdout, "%s Received unknown non-route packet, (type = %u). Dropping packet\n", thread_id, pd_ptr->type);
			#endif
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
	#ifdef ENABLE_PACKET_LOGGING
		fprintf(stdout, "\n ------------------------------------------------------------ \n\n");
		for (i = 0; i < packet_size_bytes; ++i) {
			fprintf(stdout, "%02x", packet_data_encrypted[i]);
		}
		fprintf(stdout, "\n\n ------------------------------------------------------------ \n");
	#endif
	
	RSA_private_decrypt(RSA_KEY_LENGTH_BYTES, (packet_data_encrypted + payload_start_byte), packet_data, rsa, RSA_NO_PADDING);
	id_data = ((id_cache_data *)packet_data);
	#ifdef ENABLE_LOGGING
		fprintf(stdout, "%s Received id cache data\n", buf);
	#endif

	sem_wait(&keystore_sem);
	set_key_for_user_id(buf, id_data->node_user_id, (key *)id_data->aes_key);
	set_key_for_user_id(buf, id_data->payload_node_user_id, (key *)id_data->payload_aes_key);
	set_key_for_user_id(buf, id_data->return_route_user_id, (key *)id_data->return_route_aes_key);
	set_key_for_user_id(buf, id_data->return_route_payload_user_id, (key *)id_data->return_route_payload_aes_key);
	set_key_for_user_id(buf, id_data->incoming_msg_node_user_id, (key *)id_data->incoming_msg_aes_key);
	set_key_for_user_id(buf, id_data->outgoing_msg_node_user_id, (key *)id_data->outgoing_msg_aes_key);
	sem_post(&keystore_sem);

	sem_wait(&logging_sem);
	g_logging_data.num_id_cache_packets[g_logging_data.logging_index]++;
	g_logging_data.total_num_of_id_cache_threads_destroyed[g_logging_data.logging_index]++;
	sem_post(&logging_sem);

	#ifdef ENABLE_THREAD_LOGGING
		fprintf(stdout, "%s Client thread exit\n", buf);
	#endif

	// TODO need to prevent flood of new keys from non node client! Make sure only 1 packet / 3 sec from same IP

	close(client_socket);
	pthread_ret = (char *)0;
	pthread_exit(pthread_ret);
}

int send_packet_to_node(unsigned char *packet, char *destination_ip, int destination_port)
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
		initial_seed_value = (((unsigned int)g_node_id[1])<<24) | (((unsigned int)g_node_id[3])<<16) | (((unsigned int)g_node_id[0])<<8) | ((unsigned int)g_node_id[2]);
		source_port = get_random_number(initial_seed_value);
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
			fprintf(stdout, "[MAIN THREAD] Failed to connect to node with ip = %s\n", destination_ip);
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

	sleep_time_usec = get_random_number(0);
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

void handle_pthread_ret(char *thread_id, int ret)
{
	char *pthread_ret;

	sem_wait(&logging_sem);
	g_logging_data.total_num_of_node_threads_destroyed[g_logging_data.logging_index]++;
	sem_post(&logging_sem);

	print_ret_code(thread_id, ret);
	pthread_ret = (char *)0;
	pthread_exit(pthread_ret);
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

void update_amount_of_keys_used_for_logging(void)
{
	unsigned long tmp;

	get_current_amount_of_keys_used(&tmp);

	g_logging_data.percentage_of_keystore_used[g_logging_data.logging_index] = ((float)tmp/(float)g_max_uid) * 100.0;
}

__attribute__((unused)) void handle_bandwidth_reporting(void)
{
	static float average_bandwidth[((USEC_PER_SEC/MAIN_THREAD_SLEEP_USEC) * 3)];
	static unsigned int average_bandwidth_index = 0;
	static unsigned int prev_num_node_packets_bandwidth_report = 0;
	unsigned int num_packets_nodeed, i;
	float bandwidth, average_bandwidth_reporting;

	if(prev_num_node_packets_bandwidth_report > num_node_packets_bandwidth_report) {
		num_packets_nodeed = num_node_packets_bandwidth_report + (UINT_MAX - prev_num_node_packets_bandwidth_report);
	} else {
		num_packets_nodeed = num_node_packets_bandwidth_report - prev_num_node_packets_bandwidth_report;
	}
	prev_num_node_packets_bandwidth_report = num_node_packets_bandwidth_report;

	bandwidth = (((float)packet_size_bytes + (float)TCP_BYTES_OVERHEAD) * (float)num_packets_nodeed) * (float)(USEC_PER_SEC/MAIN_THREAD_SLEEP_USEC);
	bandwidth /= 1000.0;

	average_bandwidth[average_bandwidth_index] = bandwidth;
	average_bandwidth_index++;
	if(average_bandwidth_index >= sizeof(average_bandwidth)/sizeof(average_bandwidth[0])) {
		average_bandwidth_index = 0;
	}

	average_bandwidth_reporting = 0;
	for (i = 0; i < sizeof(average_bandwidth)/sizeof(average_bandwidth[0]); ++i) {
		average_bandwidth_reporting += average_bandwidth[i];
	}
	average_bandwidth_reporting /= (float)(sizeof(average_bandwidth)/sizeof(average_bandwidth[0]));

	fprintf(stdout, "%c[2K", 27);
	fprintf(stdout, "\r%.2f kB/s ", average_bandwidth_reporting);
	for (i = 0; i < (unsigned int)bandwidth; i+=10) {
		fprintf(stdout, "-");
	}
	fflush(stdout);
}

void handle_logging(void)
{
	static unsigned int interval_count = 0;
	int perform_logging_shift;

	perform_logging_shift = 0;
	interval_count++;
	switch(g_logging_interval) {
		case PER_SECOND:
			interval_count = 0;
			perform_logging_shift = 1;
		break;
		case PER_FIFTEEN_SECONDS:
			if((interval_count % 15) == 0) {
				interval_count = 0;
				perform_logging_shift = 1;
			}
		break;
		case PER_MINUTE:
			if((interval_count % 60) == 0) {
				interval_count = 0;
				perform_logging_shift = 1;
			}
		break;
		case PER_FIVE_MINUTES:
			if((interval_count % 300) == 0) {
				interval_count = 0;
				perform_logging_shift = 1;
			}
		break;
		case PER_TEN_MINUTES:
			if((interval_count % 600) == 0) {
				interval_count = 0;
				perform_logging_shift = 1;
			}
		break;
		case PER_FIFTEEN_MINUTES:
			if((interval_count % 900) == 0) {
				interval_count = 0;
				perform_logging_shift = 1;
			}
		break;
		case PER_THIRTY_MINUTES:
			if((interval_count % 1800) == 0) {
				interval_count = 0;
				perform_logging_shift = 1;
			}
		break;
		case PER_HOUR:
			if((interval_count % 3600) == 0) {
				interval_count = 0;
				perform_logging_shift = 1;
			}
		break;
		case PER_DAY:
			if((interval_count % 86400) == 0) {
				interval_count = 0;
				perform_logging_shift = 1;
			}
		break;
		case PER_WEEK:
			if((interval_count % 604800) == 0) {
				interval_count = 0;
				perform_logging_shift = 1;
			}
		break;
	}

	if(perform_logging_shift) {
		sem_wait(&logging_sem);
		update_amount_of_keys_used_for_logging();
		g_logging_data.new_logging_data_available = 1;
		g_logging_data.logging_index_valid[g_logging_data.logging_index] = 1;
		g_logging_data.logging_index++;
		if(g_logging_data.logging_index >= LOGGING_DATA_LEN) {
			g_logging_data.logging_index = 0;
		}
		g_logging_data.logging_index_valid[g_logging_data.logging_index] = 0;
		g_logging_data.num_cert_requests[g_logging_data.logging_index] = 0;
		g_logging_data.num_id_cache_packets[g_logging_data.logging_index] = 0;
		g_logging_data.num_node_packets[g_logging_data.logging_index] = 0;
		g_logging_data.num_non_node_packets[g_logging_data.logging_index] = 0;
		g_logging_data.percentage_of_keystore_used[g_logging_data.logging_index] = 0;
		g_logging_data.num_key_get_failures[g_logging_data.logging_index] = 0;
		g_logging_data.total_num_of_id_cache_threads_created[g_logging_data.logging_index] = 0;
		g_logging_data.total_num_of_node_threads_created[g_logging_data.logging_index] = 0;
		g_logging_data.total_num_of_id_cache_threads_destroyed[g_logging_data.logging_index] = 0;
		g_logging_data.total_num_of_node_threads_destroyed[g_logging_data.logging_index] = 0;
		sem_post(&logging_sem);
	}
}

void log_data_to_file(int dummy)
{
	FILE *fp;
	int curr_log_index;

	if(g_logging_data.new_logging_data_available == 0) {
		return;
	}

	fp = fopen(log_file, "w");
	if(fp == NULL) {
		return;
	}

	sem_wait(&logging_sem);
	g_logging_data.new_logging_data_available = 0;
	curr_log_index = g_logging_data.logging_index + 1;
	if(g_logging_data.logging_index >= LOGGING_DATA_LEN) {
		curr_log_index = 0;
	}
	while(curr_log_index != g_logging_data.logging_index) {
		if(g_logging_data.logging_index_valid[curr_log_index]) {
			fprintf(fp, "%lu, %lu, %lu, %lu, %f, %lu, %lu, %lu, %lu, %lu\n", g_logging_data.num_cert_requests[curr_log_index], g_logging_data.num_id_cache_packets[curr_log_index], 
						g_logging_data.num_node_packets[curr_log_index], g_logging_data.num_non_node_packets[curr_log_index], g_logging_data.percentage_of_keystore_used[curr_log_index], 
						g_logging_data.num_key_get_failures[curr_log_index], g_logging_data.total_num_of_id_cache_threads_created[curr_log_index], g_logging_data.total_num_of_id_cache_threads_destroyed[curr_log_index],
								g_logging_data.total_num_of_node_threads_created[curr_log_index], g_logging_data.total_num_of_node_threads_destroyed[curr_log_index]);
		}
		curr_log_index++;
		if(curr_log_index >= LOGGING_DATA_LEN) {
			curr_log_index = 0;
		}
	}
	sem_post(&logging_sem);

	fclose(fp);
}

void log_data_to_file_and_exit(int dummy)
{
	log_data_to_file(0);
	exit(0);
}