#include "client.h"
#include "../Shared/cryptography.h"

#define ENABLE_LOGGING
#define DEBUG_MODE

#ifdef DEBUG_MODE
	static int debug_convo_count = 0;
#endif

int message_port;
int certificate_request_port;

int main(int argc, char const *argv[])
{
	char user_id[USER_NAME_MAX_LENGTH];
	char friend_id[USER_NAME_MAX_LENGTH];
	conversation_info conversations[MAX_CONVERSATIONS];
	int free_convo_index;

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
	certificate_request_port = message_port + 1;
	memcpy(user_id, argv[2], strlen(argv[2]));
	memset(user_id, 0, sizeof(user_id));
	memset(friend_id, 0, sizeof(friend_id));
	memset(conversations, 0, sizeof(conversations));

	free_convo_index = get_index_of_next_free_conversation(conversations);
	if(free_convo_index < 0) {
		return -1;
	}
	get_friend_id(friend_id);
	init_chat_metadata(friend_id, &(conversations[free_convo_index]));

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

int init_chat_metadata(char *friend_name, conversation_info *ci_out /* out */)
{
	int ret, i;

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
		ci_out->num_relays_active = 1;
		for (i = 0; i < ci_out->num_relays_active; ++i) {
			ci_out->ri_pool[i].in_use = 1;
		}
		strcpy(ci_out->ri_pool[0].relay_ip, "10.10.6.201");
		//strcpy(ci_out->ri_pool[1].relay_ip, "10.10.6.200");
		//strcpy(ci_out->ri_pool[2].relay_ip, "10.10.6.202");
		ret = get_relay_public_certificates_debug(ci_out->ri_pool);
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
	int i, j, ret;
	int cr_socket, bytes_read, tmp;
	struct sockaddr_in serv_addr;
	FILE *fp_public_cert;
	char cert_buf[1024], relay_cert_file_name[sizeof(ri_pool[i].relay_id) + 64];

	if(ri_pool == NULL) {
		return -1;
	}

	cr_socket = socket(AF_INET, SOCK_STREAM, 0);
	if(cr_socket < 0){
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Failed to create stream socket\n");
		#endif

		return -1;
	}

	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(certificate_request_port);
	for(i = 0; i < RELAY_POOL_MAX_SIZE; i++) {
		if(ri_pool[i].in_use == 0) {
			break;
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
				ri_pool[i].in_use = 0;
				break;
			}
			if(tmp == 0) {
				break;
			}
			bytes_read += tmp;
			if(bytes_read >= (SHA256_DIGEST_LENGTH * 2)) {
				break;
			}

			usleep(10000);
		}
		bytes_read = 0;
		for(j = 0; j < NUM_CERT_READ_ATTEMPTS; j++) {
			tmp = read(cr_socket, (cert_buf + bytes_read), (sizeof(cert_buf) - bytes_read));
			if(tmp < 0) {
				ri_pool[i].in_use = 0;
				break;
			}
			if(tmp == 0) {
				break;
			}
			bytes_read += tmp;
			if(bytes_read >= sizeof(cert_buf)) {
				break;
			}

			usleep(10000);
		}
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Successfully read public certificate from relay, id = '%s', ip = '%s'\n", ri_pool[i].relay_id, ri_pool[i].relay_ip);
		#endif

		sprintf(relay_cert_file_name, "%s/.pubkey_%s", public_cert_dir, ri_pool[i].relay_id);
		fp_public_cert = fopen(relay_cert_file_name, "w");
		if(fp_public_cert == NULL) {
			continue;
		}
		fwrite(cert_buf, sizeof(char), bytes_read, fp_public_cert);
		fclose(fp_public_cert);
	}
	
	return 0;
}