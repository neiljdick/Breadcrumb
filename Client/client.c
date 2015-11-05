#include "client.h"

#define ENABLE_LOGGING
#define DEBUG_MODE
//#define LAN_NETWORKING_MODE
//#define PRINT_PACKETS
//#define UID_CLASH_ENABLE

#ifdef DEBUG_MODE
	static int debug_convo_count = 0;
#endif

#ifdef UID_CLASH_ENABLE
	int uid_clash_offset;
#endif

sem_t sp_node_sem;
send_packet_node *sp_node;

unsigned char user_id[USER_NAME_MAX_LENGTH];
int index_of_active_conversation;
conversation_info conversations[MAX_CONVERSATIONS];
char friend_id[USER_NAME_MAX_LENGTH];
char client_ip_addr[IP_BUF_MAX_LEN];

int message_port, id_cache_port, cert_request_port;

void *send_packet_handler(void *);
void *receive_packet_handler(void *);

int main(int argc, char const *argv[])
{
	int ret;
	int free_convo_index;
	pthread_t send_packet_thread, receive_packet_thread;

	ret = init_globals(argc, argv);
	if(ret < 0) {
		return -2; // TODO error #defines
	}
	ret = initialize_packet_definitions("[MAIN THREAD]");
	if(ret < 0) {
		return -3;
	}

	ret = init_networking("[MAIN THREAD]");
	if(ret < 0) {
		return -4;
	}
	ret = init_send_packet_thread(&send_packet_thread);
	if(ret < 0) {
		return -5;	
	}
	ret = init_receive_packet_thread(&receive_packet_thread);
	if(ret < 0) {
		return -6;	
	}

	free_convo_index = get_index_of_next_free_conversation(conversations);
	if(free_convo_index < 0) {
		return -7;
	}
	init_chat(friend_id, &(conversations[free_convo_index]));

	while(1) {
		sleep(MAIN_THREAD_SLEEP_TIME);
	}

	return 0;
}

static int init_globals(int argc, char const *argv[])
{
	if(argc != 3) {
		fprintf(stdout, "Usage: ./%s [USER ID] [PORT]\n", program_name);
		exit(-1);
	}

	sem_init(&sp_node_sem, 0, 1);
	sp_node = NULL;
	index_of_active_conversation = 0;

	if(strlen(argv[2]) > USER_NAME_MAX_LENGTH) {
		fprintf(stdout, "Username must be less than %u characters\n", USER_NAME_MAX_LENGTH);
		return -1;
	}
	if(strlen(argv[2]) < USER_NAME_MIN_LENGTH) {
		fprintf(stdout, "Username must be more than %u characters\n", USER_NAME_MIN_LENGTH);
		return -1;
	}
	message_port = (unsigned int)atoi(argv[2]);
	if(message_port > PORT_MAX) {
		fprintf(stdout, "[MAIN THREAD] Port number (%u) must be less than %u\n", message_port, PORT_MAX);
		return -1;
	}
	id_cache_port = message_port + 1;
	cert_request_port = message_port + 2;
	memset(user_id, 0, sizeof(user_id));
	strncpy((char *)user_id, argv[1], (USER_NAME_MAX_LENGTH-1));
	memset(conversations, 0, sizeof(conversations));
	memset(friend_id, 0, sizeof(friend_id));
	memset(client_ip_addr, 0, sizeof(client_ip_addr));
	
	get_friend_id(friend_id);

	#ifdef UID_CLASH_ENABLE
		uid_clash_offset = get_pseudo_random_number(0) % 10000;
	#endif

	return 0;
}

static int init_networking(char *thread_id)
{
	int ret;

	#ifdef DEBUG_MODE
		ret = get_eth_ip_address(thread_id, client_ip_addr, sizeof(client_ip_addr));
		if(ret < 0) {
			#ifdef ENABLE_LOGGING
				fprintf(stdout, "%s Failed to get eth ip address\n", thread_id);
			#endif

			return -1;
		}
	#else
		#ifdef LAN_NETWORKING_MODE
			ret = get_lan_ip_address(thread_id, client_ip_addr, sizeof(client_ip_addr));
			if(ret < 0) {
				#ifdef ENABLE_LOGGING
					fprintf(stdout, "%s Failed to get lan ip address\n", thread_id);
				#endif

				return -1;
			}
		#else
			ret = get_public_ip_address(thread_id, client_ip_addr, sizeof(client_ip_addr));
			if(ret < 0) {
				#ifdef ENABLE_LOGGING
					fprintf(stdout, "%s Failed to get public ip address\n", thread_id);
				#endif

				return -1;
			}

			ret = add_port_mapping(thread_id, message_port, MSG_PORT_PROTOCOL);
			if(ret < 0) {
				#ifdef ENABLE_LOGGING
					fprintf(stdout, "%s Failed to add port mapping to upnp router\n", thread_id);
				#endif

				return -1;
			}
		#endif
	#endif	

	#ifdef ENABLE_LOGGING
		fprintf(stdout, "%s Found my ip address: %s\n", thread_id, client_ip_addr);
	#endif

	return 0;
}

static int init_receive_packet_thread(pthread_t *receive_packet_thread)
{
	int ret; 

	if(receive_packet_thread == NULL) {
		return -1;
	}

	ret = pthread_create(receive_packet_thread, NULL, receive_packet_handler, NULL);
	if(ret != 0) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Failed to create receive packet thread, %s\n", strerror(errno));
		#endif

		return -1;
	}

	return 0;
}

void *receive_packet_handler(void *ptr)
{
	int ret, i;
	int relay_socket, rp_listening_socket, bytes_read;
	struct sockaddr_in relay_addr;
	socklen_t sockaddr_len;
	char packet[packet_size_bytes];

	#ifdef ENABLE_LOGGING
		fprintf(stdout, "[RECEIVE PACKET THREAD] Receive packet thread begin\n");
	#endif

	ret = init_listening_socket("[RECEIVE PACKET THREAD]", message_port, &rp_listening_socket);
	handle_pthread_ret("[RECEIVE PACKET THREAD]", ret, -1);

	while(1) {
		sleep(PACKET_TRANSMISSION_DELAY);

		sockaddr_len = sizeof(relay_addr);
		bzero((char *) &relay_addr, sizeof(relay_addr));
		relay_socket = accept(rp_listening_socket, (struct sockaddr *)&relay_addr, &sockaddr_len);
		if(relay_socket < 0) {
			#ifdef ENABLE_LOGGING
				fprintf(stdout, "[RECEIVE PACKET THREAD] Failed to accept relay connection, %s\n", strerror(errno));
			#endif

			continue;
		}
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[RECEIVE PACKET THREAD] %s:%d received packet\n", inet_ntoa(relay_addr.sin_addr), ntohs(relay_addr.sin_port));
		#endif

		bytes_read = 0;
		for (i = 0; i < MAX_READ_ATTEMPTS; i++) {
			bytes_read += read(relay_socket, (packet + bytes_read), (packet_size_bytes - bytes_read));
			if(bytes_read == packet_size_bytes) {
				handle_received_packet(packet);
				break;
			}
		}
		close(relay_socket);
	}
}

static int handle_received_packet(char *packet)
{
	if(packet == NULL) {
		return -1;
	}


	return 0;
}

static int init_listening_socket(char *thread_id, unsigned int port, int *listening_socket /* out */)
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

static int init_send_packet_thread(pthread_t *send_packet_thread)
{
	int ret; 

	if(send_packet_thread == NULL) {
		return -1;
	}

	ret = pthread_create(send_packet_thread, NULL, send_packet_handler, NULL);
	if(ret != 0) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Failed to create send packet thread, %s\n", strerror(errno));
		#endif

		return -1;
	}

	return 0;
}

void *send_packet_handler(void *ptr)
{
	int ret;
	send_packet_node *sp_node_to_free;

	while(1) {
		sleep(PACKET_TRANSMISSION_DELAY);

		if(sp_node == NULL) {
			#ifdef ENABLE_LOGGING
				fprintf(stdout, "-");
				fflush(stdout);
			#endif
		} else {
			sem_wait(&sp_node_sem);

			ret = send_packet_to_relay(sp_node->packet_buf, sp_node->destination_ip, sp_node->destination_port);
			if(ret < 0) {
				#ifdef ENABLE_LOGGING
					fprintf(stdout, "[SEND PACKET THREAD] Failed to send packet to relay, ip = %s\n", sp_node->destination_ip);
				#endif
			}
			#ifdef ENABLE_LOGGING
				fprintf(stdout, ".");
				fflush(stdout);
			#endif

			sp_node_to_free = sp_node;
			sp_node = sp_node->next;
			free(sp_node_to_free);
			sem_post(&sp_node_sem);
		}
	}
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

	// Lets randomize the source port (otherwise linux just increments by 3 each time)
	bzero((char *) &client_addr, sizeof(client_addr));
	client_addr.sin_family = AF_INET;
	for(i = 0; i < NUM_BIND_ATTEMPTS; i++) {
		initial_seed_value = (((unsigned int)user_id[1])<<24) | (((unsigned int)user_id[3])<<16) | (((unsigned int)user_id[0])<<8) | ((unsigned int)user_id[2]);
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

int init_chat(char *friend_name, conversation_info *ci_out /* out */)
{
	int ret;
	//int convo_valid;

	if((friend_name == NULL) || (ci_out == NULL)) {
		return -1;
	}
	if(strlen(friend_name) > USER_NAME_MAX_LENGTH) {
		return -1;
	}

	#ifndef DEBUG_MODE

		// Talk to conversation index server to initiate conversation
		// TODO - node filtering (only use nodes with substantially different IP addresses (not with same /16 subnet))

	#else
		
		sprintf(ci_out->conversation_name, "debug_mode_convo_%u", debug_convo_count++);
		memcpy(ci_out->friend_name, friend_name, strlen(friend_name));
		ci_out->index_of_server_relay = 3;
		strcpy(ci_out->ri_pool[0].relay_ip, "10.10.6.200");
		strcpy(ci_out->ri_pool[1].relay_ip, "10.10.6.201");
		strcpy(ci_out->ri_pool[2].relay_ip, "10.10.6.202");
		strcpy(ci_out->ri_pool[3].relay_ip, "10.10.6.220");
		ci_out->ri_pool[0].is_active = 1;
		ci_out->ri_pool[1].is_active = 1;
		ci_out->ri_pool[2].is_active = 1;
		ci_out->ri_pool[3].is_active = 1;

		ret = get_relay_public_certificates_debug(ci_out);
		if(ret < 0) {
			return -1;
		}

	#endif

	/*  TODO - Check enough nodes (minimum 3 including server node)
	 *  Check no two nodes have IP address within same subnet (lower 10 bits or something)
	 *  Check no two nodes have same public cert
	 *  Check no two nodes have same id
	 */ 
	//check_validity_of_conversation(&convo_valid);

	ret = set_entry_relay_for_conversation(ci_out);
	if(ret < 0) {
		return -1;
	}
	ret = set_relay_keys_for_conversation(ci_out);
	if(ret < 0) {
		return -1;
	}
	ret = set_user_ids_for_conversation(ci_out);
	if(ret < 0) {
		return -1;
	}

	#ifdef ENABLE_LOGGING
		print_conversation("[MAIN THREAD]", ci_out);
	#endif

	ret = perform_user_id_registration(ci_out);
	if(ret < 0) {
		return -1;
	}

	//send_dummy_packet_no_return_route(ci_out);
	send_dummy_packet_with_return_route(ci_out);

	return ret;
}

int get_index_of_next_free_conversation(conversation_info *conversations)
{
	int i;

	for(i = 0; i < MAX_CONVERSATIONS; i++) {
		if(conversations[i].conversation_valid == 0) {
			return i;
		}
	}

	return -1;
}

int get_relay_public_certificates_debug(conversation_info *ci_info)
{
	int i, j, ret;
	unsigned int source_port, initial_seed_value;
	int cr_socket, bytes_read, tmp;
	int id_read_success, key_read_success;
	struct sockaddr_in serv_addr, client_addr;
	FILE *fp_public_key;
	char cert_buf[PUBLIC_KEY_CERT_SIZE], relay_cert_file_name[RELAY_ID_LEN + 64];

	if(ci_info == NULL) {
		return -1;
	}
	if(ci_info->ri_pool == NULL) {
		return -1;
	}

	// TODO in non debug version grab certificates not from relays but from indexing server
	// TODO check if already have certificate cached on disk (based on relay ID)

	for(i = 0; i < RELAY_POOL_MAX_SIZE; i++) {
		if(ci_info->ri_pool[i].is_active == 0) {
			continue;
		}

		cr_socket = socket(AF_INET, SOCK_STREAM, 0);
		if(cr_socket < 0){
			#ifdef ENABLE_LOGGING
				fprintf(stdout, "[MAIN THREAD] Failed to create stream socket\n");
			#endif

			return -1;
		}

		// Lets randomize the source port (otherwise linux just increments by 3 each time)
		bzero((char *) &client_addr, sizeof(client_addr));
		client_addr.sin_family = AF_INET;
		for(j = 0; j < NUM_BIND_ATTEMPTS; j++) {
			initial_seed_value = (((unsigned int)user_id[0])<<24) | (((unsigned int)user_id[1])<<16) | (((unsigned int)user_id[2])<<8) | ((unsigned int)user_id[3]);
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
		serv_addr.sin_port = htons(cert_request_port);
		serv_addr.sin_addr.s_addr = inet_addr(ci_info->ri_pool[i].relay_ip);
		ret = connect(cr_socket, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
		if(ret != 0) {
			ci_info->ri_pool[i].is_active = 0;
			continue;
		}

		read(cr_socket, &(ci_info->ri_pool[i].max_uid), sizeof(ci_info->ri_pool[i].max_uid));

		id_read_success = key_read_success = 0;
		bytes_read = 0;
		for(j = 0; j < NUM_CERT_READ_ATTEMPTS; j++) {
			tmp = read(cr_socket, (ci_info->ri_pool[i].relay_id + bytes_read), ((SHA256_DIGEST_LENGTH * 2) - bytes_read));
			if(tmp < 0) {
				break;
			}
			bytes_read += tmp;
			if(bytes_read >= (SHA256_DIGEST_LENGTH * 2)) {
				id_read_success = 1;
				break;
			}

			usleep(10000);
		}

		bytes_read = 0;
		for(j = 0; j < NUM_CERT_READ_ATTEMPTS; j++) {
			tmp = read(cr_socket, (cert_buf + bytes_read), (sizeof(cert_buf) - bytes_read));
			if(tmp < 0) {
				break;
			}
			bytes_read += tmp;
			if(bytes_read >= sizeof(cert_buf)) {
				key_read_success = 1;
				break;
			}

			usleep(10000);
		}
		close(cr_socket);
		if((id_read_success == 0) || (key_read_success == 0)) {
			#ifdef ENABLE_LOGGING
				fprintf(stdout, "[MAIN THREAD] Failed to read id and key from ip = %s, id read success = %u, key read success = %u\n", ci_info->ri_pool[i].relay_ip, id_read_success, key_read_success);
			#endif

			ci_info->ri_pool[i].is_active = 0;
			continue;
		}
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Successfully read public certificate from relay, id = '%s', ip = '%s', max uid = %u\n", 
				ci_info->ri_pool[i].relay_id, ci_info->ri_pool[i].relay_ip, ci_info->ri_pool[i].max_uid);
		#endif

		sprintf(relay_cert_file_name, "./%s", public_cert_dir);
		mkdir(relay_cert_file_name, S_IRWXU | S_IRWXG);
		sprintf(relay_cert_file_name, "%s/.pubkey_%s", public_cert_dir, ci_info->ri_pool[i].relay_id);
		fp_public_key = fopen(relay_cert_file_name, "w");
		if(fp_public_key == NULL) {
			ci_info->ri_pool[i].public_cert = NULL;
			ci_info->ri_pool[i].is_active = 0;
			continue;
		}
		fwrite(cert_buf, sizeof(char), bytes_read, fp_public_key);
		fclose(fp_public_key);

		fp_public_key = fopen(relay_cert_file_name, "r");
		if(fp_public_key == NULL) {
			ci_info->ri_pool[i].public_cert = NULL;
			ci_info->ri_pool[i].is_active = 0;
			continue;
		}
		ci_info->ri_pool[i].public_cert = PEM_read_RSAPublicKey(fp_public_key, NULL, NULL, NULL);
		fclose(fp_public_key);		
	}
	
	return 0;
}

int set_entry_relay_for_conversation(conversation_info *ci_info)
{
	int i;
	unsigned int initial_seed_value, num_relays;
	unsigned int first_relay_index;

	if(ci_info == NULL) {
		return -1;
	}
	if(ci_info->ri_pool == NULL) {
		return -1;
	}

	num_relays = 0;
	for (i = 0; i < RELAY_POOL_MAX_SIZE; i++) {
		if(ci_info->ri_pool[i].is_active) {
			num_relays++;
		}
	}
	if(num_relays < MINIMUM_NUM_RELAYS_REQ_FOR_REGISTER) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Unable to register user ID with relays as number of relays (%u) is less than minimum (%u)\n", num_relays, MINIMUM_NUM_RELAYS_REQ_FOR_REGISTER);
		#endif

		return -1;
	}

	for (i = 0; (i+4) < strlen((char *)user_id); i+=4) {
		initial_seed_value ^= (((unsigned int)user_id[0])<<24) | (((unsigned int)user_id[1])<<16) | (((unsigned int)user_id[2])<<8) | ((unsigned int)user_id[3]);
	}
	while(1) {
		first_relay_index = get_pseudo_random_number(initial_seed_value);
		initial_seed_value ^= first_relay_index;

		first_relay_index %= RELAY_POOL_MAX_SIZE;
		if(first_relay_index == ci_info->index_of_server_relay)
			continue;
		if(ci_info->ri_pool[first_relay_index].is_active)
			break;
	}
	ci_info->index_of_entry_relay = first_relay_index;
	#ifdef ENABLE_LOGGING
		fprintf(stdout, "[MAIN THREAD] Set first relay = %s\n", ci_info->ri_pool[ci_info->index_of_entry_relay].relay_ip);
	#endif

	return 0;
}

int set_relay_keys_for_conversation(conversation_info *ci_info)
{
	int ret, i;

	if(ci_info == NULL) {
		return -1;
	}

	for (i = 0; i < RELAY_POOL_MAX_SIZE; ++i) {
		if(ci_info->ri_pool[i].is_active) {
			ret = generate_AES_key(ci_info->ri_pool[i].aes_key, AES_KEY_SIZE_BYTES);
			if(ret < 0) {
				return -1;
			}
			ret = generate_AES_key(ci_info->ri_pool[i].payload_aes_key, AES_KEY_SIZE_BYTES);
			if(ret < 0) {
				return -1;
			}
			ret = generate_AES_key(ci_info->ri_pool[i].return_route_aes_key, AES_KEY_SIZE_BYTES);
			if(ret < 0) {
				return -1;
			}
			ret = generate_AES_key(ci_info->ri_pool[i].return_route_payload_aes_key, AES_KEY_SIZE_BYTES);
			if(ret < 0) {
				return -1;
			}
		}
	}

	return 0;
}

int set_user_ids_for_conversation(conversation_info *ci_info)
{
	int i;

	if(ci_info == NULL) {
		return -1;
	}

	for (i = 0; i < RELAY_POOL_MAX_SIZE; ++i) {
		if(ci_info->ri_pool[i].is_active) {
			generate_new_user_id(ci_info, i, &(ci_info->ri_pool[i].relay_user_id));
			generate_new_user_id(ci_info, i, &(ci_info->ri_pool[i].payload_relay_user_id));
			generate_new_user_id(ci_info, i, &(ci_info->ri_pool[i].return_route_user_id));
			generate_new_user_id(ci_info, i, &(ci_info->ri_pool[i].return_route_payload_user_id));
		}
	}

	return 0;
}

int generate_new_user_id(conversation_info *ci_info, int relay_index, unsigned int *uid /* out */)
{
	int i;
	unsigned int initial_seed_value;
	unsigned int relay_user_id;

	if((ci_info == NULL) || (uid == NULL)) {
		return -1;
	}
	if((relay_index < 0) || (relay_index > RELAY_POOL_MAX_SIZE)) {
		return -1;
	}
	if(ci_info->ri_pool[relay_index].max_uid == 0) {
		return -1;
	}

	for (i = 0; (i+4) < strlen((char *)user_id); i+=4) {
		initial_seed_value ^= (((unsigned int)user_id[3])<<24) | (((unsigned int)user_id[2])<<16) | (((unsigned int)user_id[1])<<8) | ((unsigned int)user_id[0]);
	}
	relay_user_id = get_pseudo_random_number(initial_seed_value);
	relay_user_id %= ci_info->ri_pool[relay_index].max_uid;

	#ifdef UID_CLASH_ENABLE
		relay_user_id %= 5;
		relay_user_id += uid_clash_offset;
	#endif
	*uid = relay_user_id;
	
	#ifdef ENABLE_LOGGING
		fprintf(stdout, "[MAIN THREAD] Generated new user ID = %u, relay_index = %u, max = %u\n", *uid, relay_index, ci_info->ri_pool[relay_index].max_uid);
	#endif

	return 0;
}

int perform_user_id_registration(conversation_info *ci_info)
{
	int ret, i;
	unsigned int seed_val, relay_register_index;
	unsigned int total_active_relays, total_registered_relays;
	char index_of_relays_registered[RELAY_POOL_MAX_SIZE];

	if(ci_info == NULL) {
		return -1;
	}

	ret = send_packet(REGISTER_UIDS_WITH_ENTRY_RELAY, ci_info, NULL, NULL, NULL);
	if(ret < 0) {
		return -1;				
	}

	total_active_relays = total_registered_relays = 0;
	for (i = 0; i < RELAY_POOL_MAX_SIZE; i++) {
		if((ci_info->ri_pool[i].is_active == 1) && (i != ci_info->index_of_entry_relay)) {
			total_active_relays++;
		}
	}
	memset(index_of_relays_registered, 0, RELAY_POOL_MAX_SIZE);
	seed_val = (((unsigned int)user_id[2])<<24) | (((unsigned int)user_id[1])<<16) | (((unsigned int)user_id[3])<<8) | ((unsigned int)user_id[0]);
	while(1) {
		relay_register_index = get_pseudo_random_number(seed_val);
		seed_val ^= relay_register_index;

		relay_register_index %= RELAY_POOL_MAX_SIZE;
		if((ci_info->ri_pool[relay_register_index].is_active == 1) && (relay_register_index != ci_info->index_of_entry_relay)) {
			if(index_of_relays_registered[relay_register_index] == 0) {
				ret = send_packet(REGISTER_UIDS_WITH_RELAY, ci_info, NULL,  NULL, &relay_register_index);
				if(ret < 0) {
					return -1;
				}

				index_of_relays_registered[relay_register_index]++;
				total_registered_relays++;
			}	
		}
		if(total_registered_relays == total_active_relays) {
			break;
		}
	}

	return 0;
}

int generate_random_route(conversation_info *ci_info, route_info *r_info)
{
	int num_routed;
	unsigned int seed_val, index;
	char index_of_relays_used[RELAY_POOL_MAX_SIZE];

	if((ci_info == NULL) || (r_info == NULL)) {
		return -1;
	}

	memset(index_of_relays_used, 0, RELAY_POOL_MAX_SIZE);
	seed_val = (((unsigned int)user_id[1])<<24) | (((unsigned int)user_id[0])<<16) | (((unsigned int)user_id[3])<<8) | ((unsigned int)user_id[2]);

	r_info->relay_route[0] = ci_info->index_of_entry_relay;
	r_info->route_length = MIN_ROUTE_LENGTH + (get_pseudo_random_number(seed_val) % (MAX_ROUTE_LENGTH - (MIN_ROUTE_LENGTH - 1)));

	num_routed = 1;
	while(num_routed < r_info->route_length) {
		index = get_pseudo_random_number(seed_val);
		seed_val ^= index;

		index %= RELAY_POOL_MAX_SIZE;
		if((ci_info->ri_pool[index].is_active == 1) && (index != ci_info->index_of_entry_relay)) {
			if(index_of_relays_used[index] == 0) {
				r_info->relay_route[num_routed] = index;

				index_of_relays_used[index] = 1;
				num_routed++;
			}
		}
	}

	return 0;
}

int generate_random_return_route(conversation_info *ci_info, route_info *r_info, route_info *return_r_info)
{
	int i;
	unsigned int seed_val, index;

	if((ci_info == NULL) || (r_info == NULL) || (return_r_info == NULL)) {
		return -1;
	}

	seed_val = (((unsigned int)user_id[1])<<24) | (((unsigned int)user_id[0])<<16) | (((unsigned int)user_id[3])<<8) | ((unsigned int)user_id[2]);
	return_r_info->route_length = MIN_ROUTE_LENGTH + (get_pseudo_random_number(seed_val) % (MAX_ROUTE_LENGTH - (MIN_ROUTE_LENGTH - 1)));
	return_r_info->relay_route[(return_r_info->route_length - 1)] = ci_info->index_of_entry_relay;

	i = 0;
	while(i < (return_r_info->route_length - 1)) {
		index = get_pseudo_random_number(seed_val);
		seed_val ^= index;

		index %= RELAY_POOL_MAX_SIZE;
		if((ci_info->ri_pool[index].is_active == 1) && (index != ci_info->index_of_entry_relay)) {
			if(i > 0) {
				if(index != return_r_info->relay_route[(i - 1)]) {
					return_r_info->relay_route[i++] = index;
				}
			} else {
				if(index != r_info->relay_route[(r_info->route_length - 1)]) {
					return_r_info->relay_route[i++] = index;
				}
			}
		}
	}

	return 0;
}

int send_dummy_packet_no_return_route(conversation_info *ci_info)
{
	int ret;
	route_info r_info;
	payload_data dummy_packet_payload;

	if(ci_info == NULL) {
		return -1;
	}

	ret = generate_random_route(ci_info, &r_info);
	if(ret < 0) {
		return -1;
	}
	#ifdef ENABLE_LOGGING
		int i;
		fprintf(stdout, "[MAIN THREAD] Sending dummy packet with route length = %u\n", r_info.route_length);
		for (i = 0; i < r_info.route_length; i++) {
			fprintf(stdout, "[MAIN THREAD] Route %u, index = %u, ip = %s\n", (i + 1), r_info.relay_route[i], ci_info->ri_pool[r_info.relay_route[i]].relay_ip);	
		}
	#endif

	ret = fill_buf_with_random_data((unsigned char *)&dummy_packet_payload, sizeof(dummy_packet_payload));
	if(ret < 0) {
		return -1;
	}
	dummy_packet_payload.type = DUMMY_PACKET_NO_RETURN_ROUTE;
	
	ret = send_packet(DUMMY_PACKET, ci_info, &r_info, &dummy_packet_payload, NULL);
	if(ret < 0) {
		return -1;
	}

	return 0;
}

int send_dummy_packet_with_return_route(conversation_info *ci_info)
{
	int ret;
	route_info r_info, return_r_info;
	payload_data dummy_packet_payload;
	uint64_t ip_first_return_relay;

	if(ci_info == NULL) {
		return -1;
	}

	ret = generate_random_route(ci_info, &r_info);
	if(ret < 0) {
		return -1;
	}
	#ifdef ENABLE_LOGGING
		int i;
		fprintf(stdout, "[MAIN THREAD] Sending dummy packet with route length = %u\n", r_info.route_length);
		for (i = 0; i < r_info.route_length; i++) {
			fprintf(stdout, "[MAIN THREAD] Route %u, index = %u, ip = %s\n", (i + 1), r_info.relay_route[i], ci_info->ri_pool[r_info.relay_route[i]].relay_ip);	
		}
	#endif

	ret = generate_random_return_route(ci_info, &r_info, &return_r_info);
	if(ret < 0) {
		return -1;
	}
	#ifdef ENABLE_LOGGING
		fprintf(stdout, "[MAIN THREAD] Return route length = %u\n", return_r_info.route_length);
		for (i = 0; i < return_r_info.route_length - 1; i++) {
			fprintf(stdout, "[MAIN THREAD] Return route %u, index = %u, ip = %s\n", (i + 1), return_r_info.relay_route[i], ci_info->ri_pool[return_r_info.relay_route[i]].relay_ip);
		}
	#endif
	
	ret = fill_buf_with_random_data((unsigned char *)&dummy_packet_payload, sizeof(dummy_packet_payload));
	if(ret < 0) {
		return -1;
	}
	ret = generate_return_onion_route_data_from_route_info(ci_info, &return_r_info, dummy_packet_payload.payload);
	if(ret < 0) {
		return -1;
	}
	ret = generate_return_onion_route_payload_from_route_info(ci_info, &return_r_info, dummy_packet_payload.payload);
	if(ret < 0) {
		return -1;
	}
	dummy_packet_payload.type = DUMMY_PACKET_W_RETURN_ROUTE;
	dummy_packet_payload.onion_r1 = message_port;
	inet_aton(ci_info->ri_pool[return_r_info.relay_route[0]].relay_ip, (struct in_addr *)&ip_first_return_relay);
	dummy_packet_payload.client_id = (uint32_t)((ip_first_return_relay >> 32) & 0xFFFFFFFF);
	dummy_packet_payload.conversation_id = (uint32_t)(ip_first_return_relay & 0xFFFFFFFF);

	ret = send_packet(DUMMY_PACKET, ci_info, &r_info, &dummy_packet_payload, NULL);
	if(ret < 0) {
		return -1;
	}

	return 0;
}

int send_packet(packet_type type, conversation_info *ci_info, route_info *r_info, payload_data *payload, void *other)
{
	int ret;
	unsigned char packet_buf[packet_size_bytes];
	char destination_ip[RELAY_IP_MAX_LENGTH];
	int destination_port;

	ret = create_packet(type, ci_info, r_info, payload, other, packet_buf, destination_ip, &destination_port);
	if(ret < 0) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Failed to create packet, type = %s\n", get_packet_type_str(type));
		#endif

		return -1;
	}
	#ifdef PRINT_PACKETS
		int i;
		fprintf(stdout, "\n ------------------------------------------------------------ \n\n");
		for (i = 0; i < packet_size_bytes; i++) {
			fprintf(stdout, "%02x", packet_buf[i]);
		}
		fprintf(stdout, "\n\n ------------------------------------------------------------ \n");
	#endif

	ret = place_packet_on_send_queue(packet_buf, destination_ip, destination_port);
	if(ret < 0) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Failed to place packet on send queue\n");
		#endif

		return -1;
	}

	return 0;
}

int create_packet(packet_type type, conversation_info *ci_info, route_info *r_info, payload_data *payload, void *other, unsigned char *packet, char *destination_ip, int *destination_port)
{
	int ret, first_relay_index;
	id_cache_data ic_data;
	unsigned int relay_register_index;
	onion_route_data or_data[MAX_ROUTE_LENGTH];
	onion_route_data or_payload_data[MAX_ROUTE_LENGTH];
	unsigned char encrypt_buffer[packet_size_bytes];

	memset(destination_ip, 0, RELAY_IP_MAX_LENGTH);
	
	ret = fill_buf_with_random_data(packet, packet_size_bytes);
	if(ret < 0) {
		return -1;
	}

	switch(type) {
		case REGISTER_UIDS_WITH_ENTRY_RELAY:
			if(ci_info == NULL) {
				return -1;
			}
			memcpy(destination_ip, ci_info->ri_pool[ci_info->index_of_entry_relay].relay_ip, RELAY_IP_MAX_LENGTH);
			*destination_port = id_cache_port;

			memcpy(ic_data.aes_key, ci_info->ri_pool[ci_info->index_of_entry_relay].aes_key, AES_KEY_SIZE_BYTES);
			ic_data.relay_user_id = ci_info->ri_pool[ci_info->index_of_entry_relay].relay_user_id;	
			memcpy(ic_data.payload_aes_key, ci_info->ri_pool[ci_info->index_of_entry_relay].payload_aes_key, AES_KEY_SIZE_BYTES);
			ic_data.payload_relay_user_id = ci_info->ri_pool[ci_info->index_of_entry_relay].payload_relay_user_id;
			memcpy(ic_data.return_route_aes_key, ci_info->ri_pool[ci_info->index_of_entry_relay].return_route_aes_key, AES_KEY_SIZE_BYTES);
			ic_data.return_route_user_id = ci_info->ri_pool[ci_info->index_of_entry_relay].return_route_user_id;
			memcpy(ic_data.return_route_payload_aes_key, ci_info->ri_pool[ci_info->index_of_entry_relay].return_route_payload_aes_key, AES_KEY_SIZE_BYTES);
			ic_data.return_route_payload_user_id = ci_info->ri_pool[ci_info->index_of_entry_relay].return_route_payload_user_id;
			
			ret = RSA_public_encrypt(sizeof(id_cache_data), (unsigned char *)&ic_data, (packet + payload_start_byte), ci_info->ri_pool[ci_info->index_of_entry_relay].public_cert, RSA_PKCS1_OAEP_PADDING);
			if(ret != RSA_KEY_LENGTH_BYTES) {
				#ifdef ENABLE_LOGGING
					fprintf(stdout, "[MAIN THREAD] Failed to encrypt id cache data\n");
				#endif

				return -1;
			}
			#ifdef ENABLE_LOGGING
				fprintf(stdout, "[MAIN THREAD] %s with relay = %s\n", get_packet_type_str(type), destination_ip);
			#endif
		break;
		case REGISTER_UIDS_WITH_RELAY:
			if((ci_info == NULL) || (other == NULL)){
				return -1;
			}
			relay_register_index = *((unsigned int *)other);
			if(relay_register_index > RELAY_POOL_MAX_SIZE) {
				return -1;
			}
			ret = fill_buf_with_random_data((unsigned char *)or_data, sizeof(or_data));
			if(ret < 0) {
				return -1;
			}
			ret = fill_buf_with_random_data((unsigned char *)or_payload_data, sizeof(or_payload_data));
			if(ret < 0) {
				return -1;
			}
			memcpy(destination_ip, ci_info->ri_pool[ci_info->index_of_entry_relay].relay_ip, RELAY_IP_MAX_LENGTH);
			*destination_port = message_port;

			generate_AES_key((unsigned char *)or_data[0].iv, AES_KEY_SIZE_BYTES);
			or_data[0].uid = ci_info->ri_pool[ci_info->index_of_entry_relay].relay_user_id;
			generate_new_user_id(ci_info, ci_info->index_of_entry_relay, &(or_data[0].ord_enc.new_uid));
			generate_AES_key((unsigned char *)or_data[0].ord_enc.new_key, AES_KEY_SIZE_BYTES);
			inet_aton(ci_info->ri_pool[relay_register_index].relay_ip, (struct in_addr *)&(or_data[0].ord_enc.next_pkg_ip));
			or_data[0].ord_enc.next_pkg_port = id_cache_port;

			or_data[0].ord_enc.ord_checksum = 0;
			get_ord_packet_checksum(&(or_data[0].ord_enc), &(or_data[0].ord_enc.ord_checksum));

			ret = aes_encrypt_block("[MAIN THREAD]", (unsigned char *)&(or_data[0].ord_enc), sizeof(onion_route_data_encrypted), 
										ci_info->ri_pool[ci_info->index_of_entry_relay].aes_key, AES_KEY_SIZE_BYTES, (unsigned char *)&(or_data[0].iv), (packet + cipher_text_byte_offset));
			if(ret < 0) {
				return -1;
			}
			memcpy(packet, &(or_data[0]), cipher_text_byte_offset);

			generate_AES_key((unsigned char *)or_payload_data[0].iv, AES_KEY_SIZE_BYTES);
			or_payload_data[0].uid = ci_info->ri_pool[ci_info->index_of_entry_relay].payload_relay_user_id;
			generate_new_user_id(ci_info, ci_info->index_of_entry_relay, &(or_payload_data[0].ord_enc.new_uid));
			generate_AES_key((unsigned char *)or_payload_data[0].ord_enc.new_key, AES_KEY_SIZE_BYTES);

			or_payload_data[0].ord_enc.ord_checksum = 0;
			get_ord_packet_checksum(&(or_payload_data[0].ord_enc), &(or_payload_data[0].ord_enc.ord_checksum));

			memcpy(encrypt_buffer, &(or_payload_data[0]), sizeof(onion_route_data));
			memcpy(ic_data.aes_key, ci_info->ri_pool[relay_register_index].aes_key, AES_KEY_SIZE_BYTES);
			ic_data.relay_user_id = ci_info->ri_pool[relay_register_index].relay_user_id;	
			memcpy(ic_data.payload_aes_key, ci_info->ri_pool[relay_register_index].payload_aes_key, AES_KEY_SIZE_BYTES);
			ic_data.payload_relay_user_id = ci_info->ri_pool[relay_register_index].payload_relay_user_id;
			memcpy(ic_data.return_route_aes_key, ci_info->ri_pool[relay_register_index].return_route_aes_key, AES_KEY_SIZE_BYTES);
			ic_data.return_route_user_id = ci_info->ri_pool[relay_register_index].return_route_user_id;
			memcpy(ic_data.return_route_payload_aes_key, ci_info->ri_pool[relay_register_index].return_route_payload_aes_key, AES_KEY_SIZE_BYTES);
			ic_data.return_route_payload_user_id = ci_info->ri_pool[relay_register_index].return_route_payload_user_id;
			
			ret = RSA_public_encrypt(sizeof(id_cache_data), (unsigned char *)&ic_data, (encrypt_buffer + (sizeof(onion_route_data))), 
										ci_info->ri_pool[relay_register_index].public_cert, RSA_PKCS1_OAEP_PADDING);
			if(ret != RSA_KEY_LENGTH_BYTES) {
				#ifdef ENABLE_LOGGING
					fprintf(stdout, "[MAIN THREAD] Failed to encrypt id cache data\n");
				#endif

				return -1;
			}

			memcpy((packet + payload_start_byte), &or_payload_data[0], cipher_text_byte_offset);
			ret = aes_encrypt_block("[MAIN THREAD]", encrypt_buffer + cipher_text_byte_offset, (sizeof(onion_route_data_encrypted) + RSA_KEY_LENGTH_BYTES), 
										ci_info->ri_pool[ci_info->index_of_entry_relay].payload_aes_key, AES_KEY_SIZE_BYTES, (unsigned char *)&(or_payload_data[0].iv), 
											(packet + payload_start_byte + cipher_text_byte_offset));
			if(ret < 0) {
				return -1;
			}

			ci_info->ri_pool[ci_info->index_of_entry_relay].relay_user_id = or_data[0].ord_enc.new_uid;
			memcpy(ci_info->ri_pool[ci_info->index_of_entry_relay].aes_key, or_data[0].ord_enc.new_key, AES_KEY_SIZE_BYTES);
			ci_info->ri_pool[ci_info->index_of_entry_relay].payload_relay_user_id = or_payload_data[0].ord_enc.new_uid;
			memcpy(ci_info->ri_pool[ci_info->index_of_entry_relay].payload_aes_key, or_payload_data[0].ord_enc.new_key, AES_KEY_SIZE_BYTES);

			#ifdef ENABLE_LOGGING
				fprintf(stdout, "[MAIN THREAD] %s with relay = %s, via relay = %s, Relay UID = %u, Payload UID = %u\n", 
						get_packet_type_str(type), ci_info->ri_pool[relay_register_index].relay_ip, destination_ip, or_data[0].uid, or_payload_data[0].uid);
			#endif

		break;
		case DUMMY_PACKET:
			if(r_info == NULL) {
				return -1;
			}

			first_relay_index = r_info->relay_route[0];
			if((first_relay_index < 0) || (first_relay_index >= RELAY_POOL_MAX_SIZE)) {
				return -1;
			}
			if(ci_info->ri_pool[first_relay_index].is_active == 0) {
				return -1;
			}
			memcpy(destination_ip, ci_info->ri_pool[first_relay_index].relay_ip, RELAY_IP_MAX_LENGTH);
			*destination_port = message_port;

			ret = generate_onion_route_data_from_route_info(ci_info, r_info, packet);
			if(ret < 0) {
				return -1;
			}

			ret = generate_onion_route_payload_from_route_info(ci_info, r_info, payload, packet);
			if(ret < 0) {
				return -1;
			}

		break;
	}

	return 0;
}

int generate_onion_route_data_from_route_info(conversation_info *ci_info, route_info *r_info, unsigned char *packet)
{
	int i, ret;
	int route_index, previous_route_index;
	unsigned int or_offset;
	onion_route_data or_data[MAX_ROUTE_LENGTH];
	unsigned char encrypt_buffer[packet_size_bytes];

	if((ci_info == NULL) || (r_info == NULL) || (packet == NULL)) {
		return -1;
	}
	if(r_info->route_length > MAX_ROUTE_LENGTH) {
		return -1;
	}

	ret = fill_buf_with_random_data((unsigned char *)or_data, sizeof(or_data));
	if(ret < 0) {
		return -1;
	}

	previous_route_index = -1;
	or_offset = (r_info->route_length - 1) * sizeof(onion_route_data);
	for (i = (r_info->route_length - 1); i >= 0; i--) {
		route_index = r_info->relay_route[i];
		if((route_index < 0) || (route_index >= RELAY_POOL_MAX_SIZE)) {
			return -1;
		}
		if(ci_info->ri_pool[route_index].is_active != 1) {
			return -1;
		}

		generate_AES_key((unsigned char *)or_data[i].iv, AES_KEY_SIZE_BYTES);
		or_data[i].uid = ci_info->ri_pool[route_index].relay_user_id;
		generate_new_user_id(ci_info, route_index, &(or_data[i].ord_enc.new_uid));
		generate_AES_key((unsigned char *)or_data[i].ord_enc.new_key, AES_KEY_SIZE_BYTES);
		or_data[i].ord_enc.next_pkg_port = message_port;
		if(previous_route_index < 0) {
			or_data[i].ord_enc.next_pkg_ip = 0;
		} else {
			inet_aton(ci_info->ri_pool[previous_route_index].relay_ip, (struct in_addr *)&(or_data[i].ord_enc.next_pkg_ip));
		}

		or_data[i].ord_enc.ord_checksum = 0;
		get_ord_packet_checksum(&(or_data[i].ord_enc), &(or_data[i].ord_enc.ord_checksum));

		memcpy((packet + or_offset), &(or_data[i]), cipher_text_byte_offset);
		memcpy((encrypt_buffer + or_offset), &(or_data[i]), sizeof(onion_route_data));
		ret = aes_encrypt_block("[MAIN THREAD]", (encrypt_buffer + or_offset + cipher_text_byte_offset), (payload_start_byte - or_offset - cipher_text_byte_offset), 
									ci_info->ri_pool[route_index].aes_key, AES_KEY_SIZE_BYTES, (unsigned char *)&(or_data[i].iv), (packet + or_offset + cipher_text_byte_offset));
		if(ret < 0) {
			return -1;
		}
		ci_info->ri_pool[route_index].relay_user_id = or_data[i].ord_enc.new_uid;
		memcpy(ci_info->ri_pool[route_index].aes_key, or_data[i].ord_enc.new_key, AES_KEY_SIZE_BYTES);
		memcpy((encrypt_buffer + or_offset + cipher_text_byte_offset), (packet + or_offset + cipher_text_byte_offset), (payload_start_byte - or_offset - cipher_text_byte_offset));

		previous_route_index = route_index;
		or_offset -= sizeof(onion_route_data);
	}

	return 0;
}

int generate_onion_route_payload_from_route_info(conversation_info *ci_info, route_info *r_info, payload_data *payload, unsigned char *packet /* out */)
{
	int i, ret;
	int route_index;
	unsigned int or_offset;
	onion_route_data or_data[MAX_ROUTE_LENGTH];
	unsigned char encrypt_buffer[packet_size_bytes];

	if((ci_info == NULL) || (r_info == NULL) || (packet == NULL) || (payload == NULL)) {
		return -1;
	}
	if(r_info->route_length > MAX_ROUTE_LENGTH) {
		return -1;
	}

	ret = fill_buf_with_random_data((unsigned char *)or_data, sizeof(or_data));
	if(ret < 0) {
		return -1;
	}
	ret = fill_buf_with_random_data((unsigned char *)encrypt_buffer, packet_size_bytes);
	if(ret < 0) {
		return -1;
	}
	memcpy((encrypt_buffer + payload_start_byte + (r_info->route_length * sizeof(onion_route_data))), payload, sizeof(payload_data));

	or_offset = payload_start_byte + ((r_info->route_length - 1) * sizeof(onion_route_data));
	for (i = (r_info->route_length - 1); i >= 0; i--) {
		route_index = r_info->relay_route[i];
		if((route_index < 0) || (route_index >= RELAY_POOL_MAX_SIZE)) {
			return -1;
		}
		if(ci_info->ri_pool[route_index].is_active != 1) {
			return -1;
		}

		generate_AES_key((unsigned char *)or_data[i].iv, AES_KEY_SIZE_BYTES);
		or_data[i].uid = ci_info->ri_pool[route_index].payload_relay_user_id;
		generate_new_user_id(ci_info, route_index, &(or_data[i].ord_enc.new_uid));
		generate_AES_key((unsigned char *)or_data[i].ord_enc.new_key, AES_KEY_SIZE_BYTES);

		or_data[i].ord_enc.ord_checksum = 0;
		get_ord_packet_checksum(&(or_data[i].ord_enc), &(or_data[i].ord_enc.ord_checksum));

		memcpy((packet + or_offset), &(or_data[i]), cipher_text_byte_offset);
		memcpy((encrypt_buffer + or_offset), &(or_data[i]), sizeof(onion_route_data));
		ret = aes_encrypt_block("[MAIN THREAD]", (encrypt_buffer + or_offset + cipher_text_byte_offset), (packet_size_bytes - or_offset - cipher_text_byte_offset), 
									ci_info->ri_pool[route_index].payload_aes_key, AES_KEY_SIZE_BYTES, (unsigned char *)&(or_data[i].iv), (packet + or_offset + cipher_text_byte_offset));
		if(ret < 0) {
			return -1;
		}
		ci_info->ri_pool[route_index].payload_relay_user_id = or_data[i].ord_enc.new_uid;
		memcpy(ci_info->ri_pool[route_index].payload_aes_key, or_data[i].ord_enc.new_key, AES_KEY_SIZE_BYTES);
		memcpy((encrypt_buffer + or_offset + cipher_text_byte_offset), (packet + or_offset + cipher_text_byte_offset), (packet_size_bytes - or_offset - cipher_text_byte_offset));

		or_offset -= sizeof(onion_route_data);
	}

	return 0;
}

int generate_return_onion_route_data_from_route_info(conversation_info *ci_info, route_info *return_r_info, unsigned char *packet)
{
	int i, ret;
	int route_index, previous_route_index;
	unsigned int or_offset;
	onion_route_data or_data[MAX_ROUTE_LENGTH];
	unsigned char encrypt_buffer[packet_size_bytes];

	if((ci_info == NULL) || (return_r_info == NULL) || (packet == NULL)) {
		return -1;
	}
	if(return_r_info->route_length > MAX_ROUTE_LENGTH) {
		return -1;
	}

	ret = fill_buf_with_random_data((unsigned char *)or_data, sizeof(or_data));
	if(ret < 0) {
		return -1;
	}

	previous_route_index = -1;
	or_offset = (return_r_info->route_length - 1) * sizeof(onion_route_data);
	for (i = (return_r_info->route_length - 1); i >= 0; i--) {
		route_index = return_r_info->relay_route[i];
		if((route_index < 0) || (route_index >= RELAY_POOL_MAX_SIZE)) {
			return -1;
		}
		if(ci_info->ri_pool[route_index].is_active != 1) {
			return -1;
		}

		generate_AES_key((unsigned char *)or_data[i].iv, AES_KEY_SIZE_BYTES);
		or_data[i].uid = ci_info->ri_pool[route_index].return_route_user_id;
		generate_new_user_id(ci_info, route_index, &(or_data[i].ord_enc.new_uid));
		generate_AES_key((unsigned char *)or_data[i].ord_enc.new_key, AES_KEY_SIZE_BYTES);
		or_data[i].ord_enc.next_pkg_port = message_port;
		if(previous_route_index < 0) {
			inet_aton(client_ip_addr, (struct in_addr *)&(or_data[i].ord_enc.next_pkg_ip));
		} else {
			inet_aton(ci_info->ri_pool[previous_route_index].relay_ip, (struct in_addr *)&(or_data[i].ord_enc.next_pkg_ip));
		}

		or_data[i].ord_enc.ord_checksum = 0;
		get_ord_packet_checksum(&(or_data[i].ord_enc), &(or_data[i].ord_enc.ord_checksum));

		memcpy((packet + or_offset), &(or_data[i]), cipher_text_byte_offset);
		memcpy((encrypt_buffer + or_offset), &(or_data[i]), sizeof(onion_route_data));
		ret = aes_encrypt_block("[MAIN THREAD]", (encrypt_buffer + or_offset + cipher_text_byte_offset), (payload_start_byte - or_offset - cipher_text_byte_offset), 
									ci_info->ri_pool[route_index].return_route_aes_key, AES_KEY_SIZE_BYTES, (unsigned char *)&(or_data[i].iv), (packet + or_offset + cipher_text_byte_offset));
		if(ret < 0) {
			return -1;
		}
		ci_info->ri_pool[route_index].return_route_user_id = or_data[i].ord_enc.new_uid;
		memcpy(ci_info->ri_pool[route_index].return_route_aes_key, or_data[i].ord_enc.new_key, AES_KEY_SIZE_BYTES);
		memcpy((encrypt_buffer + or_offset + cipher_text_byte_offset), (packet + or_offset + cipher_text_byte_offset), (payload_start_byte - or_offset - cipher_text_byte_offset));

		previous_route_index = route_index;
		or_offset -= sizeof(onion_route_data);
	}

	return 0;
}

int generate_return_onion_route_payload_from_route_info(conversation_info *ci_info, route_info *return_r_info, unsigned char *packet)
{
	int i, ret;
	int route_index;
	unsigned int or_offset;
	onion_route_data or_data[MAX_ROUTE_LENGTH];
	unsigned char encrypt_buffer[packet_size_bytes];

	if((ci_info == NULL) || (return_r_info == NULL) || (packet == NULL)) {
		return -1;
	}
	if(return_r_info->route_length > MAX_ROUTE_LENGTH) {
		return -1;
	}

	ret = fill_buf_with_random_data((unsigned char *)or_data, sizeof(or_data));
	if(ret < 0) {
		return -1;
	}

	or_offset = (return_r_info->route_length - 1) * sizeof(onion_route_data);
	for (i = (return_r_info->route_length - 1); i >= 0; i--) {
		route_index = return_r_info->relay_route[i];
		if((route_index < 0) || (route_index >= RELAY_POOL_MAX_SIZE)) {
			return -1;
		}
		if(ci_info->ri_pool[route_index].is_active != 1) {
			return -1;
		}

		generate_AES_key((unsigned char *)or_data[i].iv, AES_KEY_SIZE_BYTES);
		or_data[i].uid = ci_info->ri_pool[route_index].return_route_payload_user_id;
		generate_new_user_id(ci_info, route_index, &(or_data[i].ord_enc.new_uid));
		generate_AES_key((unsigned char *)or_data[i].ord_enc.new_key, AES_KEY_SIZE_BYTES);
		or_data[i].ord_enc.next_pkg_port = message_port;

		or_data[i].ord_enc.ord_checksum = 0;
		get_ord_packet_checksum(&(or_data[i].ord_enc), &(or_data[i].ord_enc.ord_checksum));

		memcpy((packet + payload_start_byte + or_offset), &(or_data[i]), cipher_text_byte_offset);
		memcpy((encrypt_buffer + or_offset), &(or_data[i]), sizeof(onion_route_data));
		ret = aes_encrypt_block("[MAIN THREAD]", (encrypt_buffer + or_offset + cipher_text_byte_offset), (payload_start_byte - or_offset - cipher_text_byte_offset), 
									ci_info->ri_pool[route_index].return_route_payload_aes_key, AES_KEY_SIZE_BYTES, (unsigned char *)&(or_data[i].iv), 
										(packet + payload_start_byte + or_offset + cipher_text_byte_offset));
		if(ret < 0) {
			return -1;
		}
		ci_info->ri_pool[route_index].return_route_payload_user_id = or_data[i].ord_enc.new_uid;
		memcpy(ci_info->ri_pool[route_index].return_route_payload_aes_key, or_data[i].ord_enc.new_key, AES_KEY_SIZE_BYTES);
		memcpy((encrypt_buffer + or_offset + cipher_text_byte_offset), (packet + payload_start_byte + or_offset + cipher_text_byte_offset), (payload_start_byte - or_offset - cipher_text_byte_offset));

		or_offset -= sizeof(onion_route_data);
	}

	return 0;
}


int place_packet_on_send_queue(unsigned char *packet, char *destination_ip, int destination_port)
{
	send_packet_node *sp, *sp_tmp;

	if((packet == NULL) || (destination_ip == NULL)) {
		return -1;
	}

	sem_wait(&sp_node_sem);
	
	sp_tmp = calloc(1, sizeof(send_packet_node));
	if(sp_tmp == NULL) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Failed to allocate memory on packet send queue\n");
		#endif

		return -1;
	}
	memcpy(sp_tmp->packet_buf, packet, packet_size_bytes);
	memcpy(sp_tmp->destination_ip, destination_ip, RELAY_IP_MAX_LENGTH);
	sp_tmp->destination_port = destination_port;

	if(sp_node == NULL) {
		sp_node = sp_tmp;
	} else {
		sp = sp_node;
		while(sp->next != NULL) {
			sp = sp->next;
		}
		sp->next = sp_tmp;
	}

	sem_post(&sp_node_sem);

	return 0;
}

int get_friend_id(char *friend_id)
{
	int i;
	char c;

	if(friend_id == NULL) {
		return -1;
	}

	fprintf(stdout, "Please enter friends user id: ");
	fflush(stdout);

	i = 0;
	while(1) {
		c = (char)fgetc(stdin);
		if(isalnum(c) || ispunct(c)) {
			if(i < USER_NAME_MAX_LENGTH) {
				friend_id[i] = c;
				i++;
			}
		} else {
			break;
		}
	}
	
	return 0;
}

int is_valid_ip(char *ip, int *valid /* out */)
{
	int result;
	struct sockaddr_in sa;

	if ((ip == NULL) || (valid == NULL)) {
		return -1;
	}

    result = inet_pton(AF_INET, ip, &(sa.sin_addr));
    if(result == 1) {
    	*valid = 1;
    } else {
    	*valid = 0;
    }

    return -1;
}

int print_conversation(char *thread_id, conversation_info *ci_info)
{
	int i, j;
	char buf[(AES_KEY_SIZE_BYTES*2)];

	if((thread_id == NULL) || (ci_info == NULL)) {
		return -1;
	}

	fprintf(stdout, "%s Conversation valid = %d\n", thread_id, ci_info->conversation_valid);
	fprintf(stdout, "%s Conversation name = %s\n", thread_id, ci_info->conversation_name);
	fprintf(stdout, "%s Friends name = %s\n", thread_id, ci_info->friend_name);
	fprintf(stdout, "%s Index of server relay = %u\n", thread_id, ci_info->index_of_server_relay);
	fprintf(stdout, "%s Index of entry relay = %u\n", thread_id, ci_info->index_of_entry_relay);

	for (i = 0; i < RELAY_POOL_MAX_SIZE; ++i) {
		if(ci_info->ri_pool[i].is_active) {
			fprintf(stdout, "%s ------------ Relay %d -------------\n", thread_id, i);
			fprintf(stdout, "%s Relay ID = %s\n", thread_id, ci_info->ri_pool[i].relay_id);
			fprintf(stdout, "%s Relay IP = %s\n", thread_id, ci_info->ri_pool[i].relay_ip);
			
			for (j = 0; j < AES_KEY_SIZE_BYTES; j++) {
				sprintf((buf + (j*2)), "%02x", 0xff & ci_info->ri_pool[i].aes_key[j]);
			}
			fprintf(stdout, "%s Relay Key = %s\n", thread_id, buf);
			fprintf(stdout, "%s Relay User ID = %u\n", thread_id, ci_info->ri_pool[i].relay_user_id);

			for (j = 0; j < AES_KEY_SIZE_BYTES; j++) {
				sprintf((buf + (j*2)), "%02x", 0xff & ci_info->ri_pool[i].payload_aes_key[j]);
			}
			fprintf(stdout, "%s Payload Relay Key = %s\n", thread_id, buf);
			fprintf(stdout, "%s Payload Relay User ID = %u\n", thread_id, ci_info->ri_pool[i].payload_relay_user_id);

			for (j = 0; j < AES_KEY_SIZE_BYTES; j++) {
				sprintf((buf + (j*2)), "%02x", 0xff & ci_info->ri_pool[i].return_route_aes_key[j]);
			}
			fprintf(stdout, "%s Return Route Relay Key = %s\n", thread_id, buf);
			fprintf(stdout, "%s Return Route Relay User ID = %u\n", thread_id, ci_info->ri_pool[i].return_route_user_id);

			for (j = 0; j < AES_KEY_SIZE_BYTES; j++) {
				sprintf((buf + (j*2)), "%02x", 0xff & ci_info->ri_pool[i].return_route_payload_aes_key[j]);
			}
			fprintf(stdout, "%s Return Route Relay Key = %s\n", thread_id, buf);
			fprintf(stdout, "%s Return Route Relay User ID = %u\n", thread_id, ci_info->ri_pool[i].return_route_payload_user_id);
		}
	}
	fprintf(stdout, "%s ------------------------------------\n", thread_id);

	return 0;
}

char* get_packet_type_str(packet_type type)
{
	switch(type) {
		case REGISTER_UIDS_WITH_ENTRY_RELAY:
			return "REGISTER_UIDS_WITH_ENTRY_RELAY";
		case REGISTER_UIDS_WITH_RELAY:
			return "REGISTER_UIDS_WITH_RELAY";
		case DUMMY_PACKET:
			return "DUMMY_PACKET";
	}

	return "UNKNOWN";
}

void print_ret_code(char *thread_id, int ret)
{
	#ifdef ENABLE_LOGGING
		{
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
