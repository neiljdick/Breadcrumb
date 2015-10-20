#include "client.h"
#include "../Shared/key_storage.h"
#include "../Shared/cryptography.h"

#define ENABLE_LOGGING
#define DEBUG_MODE

#ifdef DEBUG_MODE
	static int debug_convo_count = 0;
#endif

char user_id[USER_NAME_MAX_LENGTH];
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
	if(strlen(argv[2]) > USER_NAME_MAX_LENGTH) {
		fprintf(stdout, "Username must be less than %u characters\n", USER_NAME_MAX_LENGTH);
		exit(-1);
	}
	message_port = (unsigned int)atoi(argv[2]);
	if(message_port > PORT_MAX) {
		fprintf(stdout, "[MAIN THREAD] Port number (%u) must be less than %u\n", message_port, PORT_MAX);
		exit(-5);
	}
	id_cache_port = message_port + 1;
	cert_request_port = message_port + 2;
	memset(user_id, 0, sizeof(user_id));
	strncpy(user_id, argv[1], (USER_NAME_MAX_LENGTH-1));
	memset(friend_id, 0, sizeof(friend_id));
	memset(conversations, 0, sizeof(conversations));

	free_convo_index = get_index_of_next_free_conversation(conversations);
	if(free_convo_index < 0) {
		return -1;
	}
	get_friend_id(friend_id);
	init_chat(friend_id, &(conversations[free_convo_index]));

	return 0;
}

int init_chat(char *friend_name, conversation_info *ci_out /* out */)
{
	int ret;

	if((friend_name == NULL) || (ci_out == NULL)) {
		return -1;
	}
	if(strlen(friend_name) > USER_NAME_MAX_LENGTH) {
		return -1;
	}

	ci_out->conversation_valid = 1;
	memcpy(ci_out->friend_name, friend_name, strlen(friend_name));
	#ifndef DEBUG_MODE
		// Talk to conversation index server to initiate conversation
	#else
		
		sprintf(ci_out->conversation_name, "debug_mode_convo_%u", debug_convo_count++);
		strcpy(ci_out->ri_pool[0].relay_ip, "10.10.6.200");
		strcpy(ci_out->ri_pool[1].relay_ip, "10.10.6.201");
		strcpy(ci_out->ri_pool[2].relay_ip, "10.10.6.202");
		
		ret = get_relay_public_certificates_debug(ci_out->ri_pool);
		if(ret < 0) {
			return -1;
		}

		ret = register_user_id_with_active_relays(ci_out->ri_pool);
		if(ret < 0) {
			return -1;
		}

	#endif

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

int get_relay_public_certificates_debug(relay_info *ri_pool)
{
	int i, j, ret, valid_ip;
	unsigned int source_port, initial_seed_value;
	int cr_socket, bytes_read, tmp;
	int id_read_success, key_read_success;
	struct sockaddr_in serv_addr, client_addr;
	FILE *fp_public_key;
	char cert_buf[PUBLIC_KEY_CERT_SIZE], relay_cert_file_name[sizeof(ri_pool[i].relay_id) + 64];

	if(ri_pool == NULL) {
		return -1;
	}

	for(i = 0; i < RELAY_POOL_MAX_SIZE; i++) {
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
		id_read_success = key_read_success = 0;

		is_valid_ip(ri_pool[i].relay_ip, &valid_ip);
		if(valid_ip == 0) {
			continue;
		}

		serv_addr.sin_addr.s_addr = inet_addr(ri_pool[i].relay_ip);
		ret = connect(cr_socket, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
		if(ret != 0) {
			continue;
		}

		bytes_read = 0;
		for(j = 0; j < NUM_CERT_READ_ATTEMPTS; j++) {
			tmp = read(cr_socket, (ri_pool[i].relay_id + bytes_read), ((SHA256_DIGEST_LENGTH * 2) - bytes_read));
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
				fprintf(stdout, "[MAIN THREAD] Failed to read id and key from ip = %s, id read success = %u, key read success = %u\n", ri_pool[i].relay_ip, id_read_success, key_read_success);
			#endif

			continue;
		}
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Successfully read public certificate from relay, id = '%s', ip = '%s'\n", ri_pool[i].relay_id, ri_pool[i].relay_ip);
		#endif

		sprintf(relay_cert_file_name, "%s/.pubkey_%s", public_cert_dir, ri_pool[i].relay_id);
		fp_public_key = fopen(relay_cert_file_name, "w");
		if(fp_public_key == NULL) {
			ri_pool[i].public_cert = NULL;
			continue;
		}
		fwrite(cert_buf, sizeof(char), bytes_read, fp_public_key);
		fclose(fp_public_key);

		fp_public_key = fopen(relay_cert_file_name, "r");
		if(fp_public_key == NULL) {
			ri_pool[i].public_cert = NULL;
			continue;
		}
		ri_pool[i].public_cert = PEM_read_RSAPublicKey(fp_public_key, NULL, NULL, NULL);
		fclose(fp_public_key);		
	}
	
	return 0;
}

int register_user_id_with_active_relays(relay_info *ri_pool)
{
	int i;
	unsigned int initial_seed_value;
	unsigned int first_relay_index, max_valid_relay_index;

	for (i = (RELAY_POOL_MAX_SIZE-1); i >= 0; i--) {
		if(ri_pool[i].public_cert != NULL) {
			max_valid_relay_index = i;
			break;
		}
	}
	if(i < MINIMUM_NUM_RELAYS) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Unable to register user ID with relays as number of relays (%u) is less than minimum (%u)\n", (i+1), MINIMUM_NUM_RELAYS);
		#endif

		return -1;
	}

	while(1) {
		for (i = 0; (i+4) < strlen(user_id); i+=4) {
			initial_seed_value ^= (((unsigned int)user_id[0])<<24) | (((unsigned int)user_id[1])<<16) | (((unsigned int)user_id[2])<<8) | ((unsigned int)user_id[3]);
		}
		first_relay_index = get_pseudo_random_number(initial_seed_value);
		first_relay_index %= (max_valid_relay_index + 1);

		if(ri_pool[first_relay_index].public_cert != NULL)
			break;
	}
	#ifdef ENABLE_LOGGING
		fprintf(stdout, "[MAIN THREAD] First relay = %s\n", ri_pool[first_relay_index].relay_ip);
	#endif

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