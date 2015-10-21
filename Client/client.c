#include "client.h"

#define ENABLE_LOGGING
#define DEBUG_MODE

#ifdef DEBUG_MODE
	static int debug_convo_count = 0;
#endif

unsigned char user_id[USER_NAME_MAX_LENGTH];
int index_of_active_conversation;
conversation_info conversations[MAX_CONVERSATIONS];

int message_port, id_cache_port, cert_request_port;

int main(int argc, char const *argv[])
{
	int free_convo_index;
	char friend_id[USER_NAME_MAX_LENGTH];

	if(argc != 3) {
		fprintf(stdout, "Usage: ./%s [USER ID] [PORT]\n", program_name);
		exit(-1);
	}
	// TODO refactor into function which performs command line argument veracity check
	if(strlen(argv[2]) > USER_NAME_MAX_LENGTH) {
		fprintf(stdout, "Username must be less than %u characters\n", USER_NAME_MAX_LENGTH);
		exit(-1);
	}
	if(strlen(argv[2]) < USER_NAME_MIN_LENGTH) {
		fprintf(stdout, "Username must be more than %u characters\n", USER_NAME_MIN_LENGTH);
		exit(-1);	
	}
	message_port = (unsigned int)atoi(argv[2]);
	if(message_port > PORT_MAX) {
		fprintf(stdout, "[MAIN THREAD] Port number (%u) must be less than %u\n", message_port, PORT_MAX);
		exit(-5);
	}

	// TODO refactor into function which performs global variable initialization
	id_cache_port = message_port + 1;
	cert_request_port = message_port + 2;
	memset(user_id, 0, sizeof(user_id));
	strncpy((char *)user_id, argv[1], (USER_NAME_MAX_LENGTH-1));
	memset(friend_id, 0, sizeof(friend_id));
	memset(conversations, 0, sizeof(conversations));

	get_friend_id(friend_id);
	free_convo_index = get_index_of_next_free_conversation(conversations);
	if(free_convo_index < 0) {
		return -1;
	}
	init_chat(friend_id, &(conversations[free_convo_index]));

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

	//check_validity_of_conversation(&convo_valid); // TODO

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
	ret = perform_user_id_registration(ci_out);
	if(ret < 0) {
		return -1;
	}

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
			fprintf(stdout, "[MAIN THREAD] Successfully read public certificate from relay, id = '%s', ip = '%s'\n", ci_info->ri_pool[i].relay_id, ci_info->ri_pool[i].relay_ip);
		#endif

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
	unsigned int initial_seed_value;
	unsigned int first_relay_index, max_valid_relay_index;

	if(ci_info == NULL) {
		return -1;
	}
	if(ci_info->ri_pool == NULL) {
		return -1;
	}

	for (i = (RELAY_POOL_MAX_SIZE-1); i >= 0; i--) {
		if(ci_info->ri_pool[i].public_cert != NULL) {
			max_valid_relay_index = i;
			break;
		}
	}
	if(i < MINIMUM_NUM_RELAYS_REQ_FOR_REGISTER) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Unable to register user ID with relays as number of relays (%u) is less than minimum (%u)\n", (i+1), MINIMUM_NUM_RELAYS_REQ_FOR_REGISTER);
		#endif

		return -1;
	}

	for (i = 0; (i+4) < strlen((char *)user_id); i+=4) {
		initial_seed_value ^= (((unsigned int)user_id[0])<<24) | (((unsigned int)user_id[1])<<16) | (((unsigned int)user_id[2])<<8) | ((unsigned int)user_id[3]);
	}
	while(1) {
		first_relay_index = get_pseudo_random_number(initial_seed_value);
		initial_seed_value ^= first_relay_index;

		first_relay_index %= (max_valid_relay_index + 1);
		if(first_relay_index == ci_info->index_of_server_relay)
			continue;
		if(ci_info->ri_pool[first_relay_index].public_cert != NULL)
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
			generate_new_user_id(&(ci_info->ri_pool[i].relay_user_id));
		}
	}

	return 0;
}

int generate_new_user_id(unsigned int *uid /* out */)
{
	int i;
	unsigned int initial_seed_value;
	unsigned int relay_user_id;

	if(uid == NULL) {
		return -1;
	}

	for (i = 0; (i+4) < strlen((char *)user_id); i+=4) {
		initial_seed_value ^= (((unsigned int)user_id[3])<<24) | (((unsigned int)user_id[2])<<16) | (((unsigned int)user_id[1])<<8) | ((unsigned int)user_id[0]);
	}
	relay_user_id = get_pseudo_random_number(initial_seed_value);
	relay_user_id %= get_max_user_id();

	*uid = relay_user_id;

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

	ret = send_packet(REGISTER_USER_ID_WITH_ENTRY_RELAY, ci_info, NULL, NULL, NULL);
	if(ret < 0) {
		return -1;				
	}

	total_active_relays = total_registered_relays = 0;
	for (i = 0; i < RELAY_POOL_MAX_SIZE; i++) {
		if(ci_info->ri_pool[i].is_active == 1) {
			total_active_relays++;
		}
	}
	memset(index_of_relays_registered, 0, RELAY_POOL_MAX_SIZE);
	seed_val = (((unsigned int)user_id[2])<<24) | (((unsigned int)user_id[1])<<16) | (((unsigned int)user_id[3])<<8) | ((unsigned int)user_id[0]);
	while(1) {
		relay_register_index = get_pseudo_random_number(seed_val);
		seed_val ^= relay_register_index;

		relay_register_index %= RELAY_POOL_MAX_SIZE;
		if(ci_info->ri_pool[relay_register_index].is_active == 1) {
			if(index_of_relays_registered[relay_register_index] == 0) {
				ret = send_packet(REGISTER_USER_ID_WITH_RELAY, ci_info, NULL,  NULL, &relay_register_index);
				if(ret < 0) {
					return -1;
				}

				index_of_relays_registered[relay_register_index] = 1;
				total_registered_relays++;
			}		
		}
		if(total_registered_relays == total_active_relays) {
			break;
		}
	}

	return 0;
}

int send_packet(packet_type type, conversation_info *ci_info, route_info *r_info, char *msg, void *other)
{
	int i, ret, bytes_sent;
	unsigned char packet_buf[PACKET_SIZE_BYTES];
	id_cache_data ic_data;
	unsigned int relay_register_index, initial_seed_value;
	int cr_socket;
	struct sockaddr_in serv_addr, client_addr;
	char destination_ip[RELAY_IP_MAX_LENGTH];
	int source_port, destination_port;

	memset(destination_ip, 0, RELAY_IP_MAX_LENGTH);

	ret = fill_buf_with_random_data(packet_buf, PACKET_SIZE_BYTES);
	if(ret < 0) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Failed to fill packet buffer with random data\n");
		#endif

		return -1;
	}

	switch(type) {
		case REGISTER_USER_ID_WITH_ENTRY_RELAY:
			if(ci_info == NULL) {
				return -1;
			}
			memcpy(destination_ip, ci_info->ri_pool[ci_info->index_of_entry_relay].relay_ip, RELAY_IP_MAX_LENGTH);
			destination_port = id_cache_port;

			memcpy(ic_data.aes_key, ci_info->ri_pool[ci_info->index_of_entry_relay].aes_key, AES_KEY_SIZE_BYTES);
			ic_data.relay_user_id = ci_info->ri_pool[ci_info->index_of_entry_relay].relay_user_id;

			ret = RSA_public_encrypt(sizeof(id_cache_data), (unsigned char *)&ic_data, packet_buf, ci_info->ri_pool[ci_info->index_of_entry_relay].public_cert, RSA_PKCS1_OAEP_PADDING);
			if(ret != RSA_KEY_LENGTH_BYTES) {
				#ifdef ENABLE_LOGGING
					fprintf(stdout, "[MAIN THREAD] Failed to encrypt id cache data\n");
				#endif

				return -1;
			}
		break;
		case REGISTER_USER_ID_WITH_RELAY:
			if((ci_info == NULL) || (other == NULL)){
				return -1;
			}
			relay_register_index = *((unsigned int *)other);
			if(relay_register_index > RELAY_POOL_MAX_SIZE) {
				return -1;
			}
			memcpy(destination_ip, ci_info->ri_pool[relay_register_index].relay_ip, RELAY_IP_MAX_LENGTH);
			destination_port = message_port;

			return -1; // TODO - Remove

		break;
		case DUMMY_PACKET:

		break;
	}

	#ifdef ENABLE_LOGGING
		fprintf(stdout, "[MAIN THREAD] Sending packet of type: %s to Relay = %s\n", get_packet_type_str(type), destination_ip);
	#endif

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
		bytes_sent += write(cr_socket, packet_buf, PACKET_SIZE_BYTES);
		if(bytes_sent == PACKET_SIZE_BYTES) {
			break;
		}
	}
	close(cr_socket);

	if(bytes_sent != PACKET_SIZE_BYTES) {
		return -1;
	}
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
		}
	}
	fprintf(stdout, "%s ------------------------------------\n", thread_id);

	return 0;
}

char* get_packet_type_str(packet_type type)
{
	switch(type) {
		case REGISTER_USER_ID_WITH_ENTRY_RELAY:
			return "REGISTER_USER_ID_WITH_ENTRY_RELAY";
		case REGISTER_USER_ID_WITH_RELAY:
			return "REGISTER_USER_ID_WITH_RELAY";
		case DUMMY_PACKET:
			return "DUMMY_PACKET";
	}

	return "UNKNOWN";
}