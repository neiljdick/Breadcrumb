#include "client.h"

#define ENABLE_STANDARD_LOGGING
//#define ENABLE_LOGGING
//#define ENABLE_TRANSMIT_RECEIVE_LOGGING
//#define ENABLE_KEY_HISTORY_LOGGING
//#define ENABLE_BANDWIDTH_LOGGING
//#define ENABLE_UID_LOGGING
#define DEBUG_MODE
//#define LAN_NETWORKING_MODE
//#define PRINT_PACKETS
//#define UID_CLASH_ENABLE
//#define PRINT_UID_GENERATION

#ifdef DEBUG_MODE
	static int debug_convo_count = 0;
#endif

#ifdef UID_CLASH_ENABLE
	int g_uid_clash_offset;
#endif

sem_t g_sp_node_sem;
send_packet_node *g_sp_node;
bandwidth_data g_bandwidth_data;
int g_queue_dummy_packet_transmission = 0;
int g_performing_relay_verification_and_reconnection = 0;

sem_t th_comm_sem;
thread_comm g_th_comm;

unsigned char g_user_id[USER_NAME_MAX_LENGTH];
int g_current_conversation_index;
conversation_info g_conversations[MAX_CONVERSATIONS];
char g_friend_id[USER_NAME_MAX_LENGTH];
char g_client_ip_addr[IP_BUF_MAX_LEN];
int g_message_port;

route_history g_rhistory;

char g_curr_send_packet_char = '-';

void *send_packet_handler(void *);
void *receive_packet_handler(void *);

static int init_globals(int argc, char const *argv[]);
static int handle_received_packet(char *packet);
static int is_message_packet(char *packet, int *is_message);
static int handle_message_packet(char *packet);
static int handle_command_packet(char *packet);
static void print_ret_code(char *thread_id, int ret);
static void handle_pthread_ret(char *thread_id, int ret, int clientfd);
static int init_send_packet_thread(pthread_t *send_packet_thread);
static int init_receive_packet_thread(pthread_t *receive_packet_thread);
static int init_listening_socket(char *thread_id, unsigned int port, int *listening_socket /* out */);
static int init_self_ip(char *thread_id);
static int initialize_relay_verification_command(payload_data *verification_payload);
static int wait_for_command_completion(int max_command_time, int *command_ret_status);
static int verify_entry_relay_online(char *thread_id, conversation_info *ci_info, history_type h_type, verification_type v_type, int *entry_relay_online);
static int verify_relay_online(char *thread_id, conversation_info *ci_info, int relay_index, history_type h_type, verification_type v_type, int *relay_is_online);
static int verify_all_relays_online_rapid(char *thread_id, conversation_info *ci_info, int *all_relays_online);
static int verify_all_relays_online_basic(char *thread_id, conversation_info *ci_info, int *all_relays_online);
static int generate_rapid_verification_routes(char *thread_id, conversation_info *ci_info, route_pair *r_pair, int route_pair_length);
static int update_non_entry_relay_connectivity_status(char *thread_id, conversation_info *ci_info);
static int update_unresponsive_non_entry_relay_connectivity_status(char *thread_id, conversation_info *ci_info);
static int update_is_active_flag_based_on_is_responsive_flag(char *thread_id, conversation_info *ci_info);
static int handle_potential_loss_of_nodes(conversation_info *ci_info);
static int reconnect_to_entry_relay_via_key_history(char *thread_id, conversation_info *ci_info, return_key_history_type rkh_type, int *reconnect_success);
static int attempt_to_reconnect_unresponsive_relays_via_key_history(char *thread_id, conversation_info *ci_info, int *reconnected_to_all_relays);
static int attempt_to_reconnect_unresponsive_relays_via_reregister_id(char *thread_id, conversation_info *ci_info, int *reconnected_to_all_relays);
static int perform_relay_verification_and_reconnection(char *thread_id, conversation_info *ci_info, reconnect_type rc_type, int *success);
static int check_if_loss_of_relay_is_fatal(char *thread_id, conversation_info *ci_info, int *fatal_connection_err);
static int initialize_should_receive_dummy_packet_command(void);
static char get_send_packet_char(void);
static int commit_current_key_info_to_history(relay_info *r_info);
static int commit_key_info_to_history(conversation_info *ci_info);
static int commit_route_info_to_history(packet_type type, conversation_info *info, route_info *r_info, route_info *return_r_info, void *arg);
static int print_key_history(relay_info *r_info);
static int print_return_key_history(relay_info *r_info);
static int print_route_info_history(void);
static char* get_packet_type_str(packet_type type);
static char* get_history_type_str(history_type h_type);
static char* get_verification_type_str(verification_type v_type);
static int place_packet_on_send_queue(unsigned char *packet, char *destination_ip, int destination_port);
static int get_number_of_packets_in_send_queue(int *num_packets);
static int get_friend_id(char *friend_id /* out */);
static int init_chat(char *friend_name, conversation_info *ci_out /* out */);
static int get_relay_public_certificates_debug(conversation_info *ci_info);
static int set_entry_relay_for_conversation(conversation_info *ci_info);
static int set_relay_keys_for_conversation(conversation_info *ci_info);
static int set_user_ids_for_conversation(conversation_info *ci_info);
static int perform_user_id_registration(char *thread_id, conversation_info *ci_info);
static int get_index_of_next_free_conversation(conversation_info *conversations);
static int create_packet(packet_type type, conversation_info *ci_info, route_info *r_info, payload_data *payload, void *other, unsigned char *packet, char *destination_ip, int *destination_port);
static int send_packet_to_relay(unsigned char *packet, char *destination_ip, int destination_port);
static int generate_new_user_id(int max_uid, unsigned int *uid /* out */);
static int is_valid_ip(char *ip, int *valid /* out */);
static int print_conversation(char *thread_id, conversation_info *ci_info);
static int wait_for_send_queue_empty(char *thread_id);
static int send_dummy_packet_no_return_route(conversation_info *ci_info);
static int send_dummy_packet_with_return_route(conversation_info *ci_info);
static int send_dummy_packet_with_routes_defined(conversation_info *ci_info, route_info *r_info, route_info *return_r_info);
static int generate_onion_route_data_from_route_info(conversation_info *ci_info, route_info *r_info, unsigned char *packet);
static int generate_onion_route_payload_from_route_info(conversation_info *ci_info, route_info *r_info, payload_data *payload, unsigned char *packet /* out */);
static int generate_return_onion_route_data_from_route_info(conversation_info *ci_info, route_info *return_r_info, unsigned char *packet);
static int generate_return_onion_route_payload_from_route_info(conversation_info *ci_info, route_info *return_r_info, unsigned char *packet);
static int generate_onion_route_data_from_route_info_using_rr_pairs(conversation_info *ci_info, route_info *r_info, unsigned char *packet);
static int generate_onion_route_payload_from_route_info_using_rr_pairs(conversation_info *ci_info, route_info *r_info, payload_data *payload, unsigned char *packet /* out */);
static int generate_onion_route_data_from_route_info_verify_using_rr_pairs(conversation_info *ci_info, route_info *r_info, unsigned char *packet);
static int generate_onion_route_payload_from_route_info_verify_using_rr_pairs(conversation_info *ci_info, route_info *r_info, payload_data *payload, unsigned char *packet /* out */);
static int generate_packet_metadata(conversation_info *ci_info, payload_type p_type, route_info *return_r_info, payload_data *payload);
static int send_packet(packet_type type, conversation_info *ci_info, route_info *r_info, payload_data *payload, void *other);
static int handle_constant_bandwidth(int did_send_packet, int *should_send_packet);
static int get_current_average_bandwidth(float *current_bandwidth);
static int handle_packet_transmission(int should_send_packet, int *did_send_packet);
static int handle_dummy_packet_transmission(void);
static int print_key_uid_pair(id_key_info *id_key_info_val);
static int print_rr_key_uid_pair(id_key_info *id_key_info_val);
static int print_route_pairs(char *thread_id, route_pair *r_pair, int route_pair_length);
static int reset_relay(char *thread_id, relay_info* r_info);
void logging_interrupt_handler(int dummy);
int save_uid_history_to_file(void);

int main(int argc, char const *argv[])
{
	int ret;
	pthread_t send_packet_thread, receive_packet_thread;

	ret = init_globals(argc, argv);
	if(ret < 0) {
		return -2; // TODO error #defines
	}
	ret = initialize_packet_definitions("[MAIN THREAD]");
	if(ret < 0) {
		return -3;
	}

	#ifdef ENABLE_UID_LOGGING
		signal(SIGINT, logging_interrupt_handler);
	#endif

	ret = init_self_ip("[MAIN THREAD]");
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

	g_current_conversation_index = get_index_of_next_free_conversation(g_conversations);
	if(g_current_conversation_index < 0) {
		return -7;
	}
	init_chat(g_friend_id, &(g_conversations[g_current_conversation_index]));

	while(1) {
		usleep(MIN_PACKET_TRANSMISSION_DELAY_US);
		usleep(get_random_number(0) % MIN_PACKET_TRANSMISSION_DELAY_US);
		if(g_queue_dummy_packet_transmission) {
			handle_dummy_packet_transmission();
			g_queue_dummy_packet_transmission = 0;
		}
	}

	return 0;
}

static int init_globals(int argc, char const *argv[])
{
	if(argc != 3) {
		#ifdef ENABLE_STANDARD_LOGGING
			fprintf(stdout, "Usage: ./%s USER_ID PORT\n", program_name);
		#endif
		exit(-1);
	}

	sem_init(&th_comm_sem, 0, 1);
	sem_init(&g_sp_node_sem, 0, 1);
	g_sp_node = NULL;
	g_current_conversation_index = 0;

	if(strlen(argv[2]) > USER_NAME_MAX_LENGTH) {
		#ifdef ENABLE_STANDARD_LOGGING
			fprintf(stdout, "Username must be less than %u characters\n", USER_NAME_MAX_LENGTH);
		#endif
		exit(-1);
	}
	if(strlen(argv[2]) < USER_NAME_MIN_LENGTH) {
		#ifdef ENABLE_STANDARD_LOGGING
			fprintf(stdout, "Username must be more than %u characters\n", USER_NAME_MIN_LENGTH);
		#endif
		exit(-1);
	}
	g_message_port = (unsigned int)atoi(argv[2]);
	if(g_message_port > PORT_MAX) {
		#ifdef ENABLE_STANDARD_LOGGING
			fprintf(stdout, "[MAIN THREAD] Port number (%u) must be less than %u\n", g_message_port, PORT_MAX);
		#endif
		exit(-1);
	}
	if(g_message_port < PORT_MIN) {
		#ifdef ENABLE_STANDARD_LOGGING
			fprintf(stdout, "[MAIN THREAD] Port number (%u) must be greater than %u\n", g_message_port, PORT_MIN);
		#endif
		exit(-1);
	}
	memset(g_user_id, 0, sizeof(g_user_id));
	strncpy((char *)g_user_id, argv[1], (USER_NAME_MAX_LENGTH-1));
	memset(g_conversations, 0, sizeof(g_conversations));
	memset(g_friend_id, 0, sizeof(g_friend_id));
	memset(g_client_ip_addr, 0, sizeof(g_client_ip_addr));
	memset(&g_rhistory, 0, sizeof(g_rhistory));
	g_current_conversation_index = 0;
	g_queue_dummy_packet_transmission = 0;

	memset(&g_bandwidth_data, 0, sizeof(bandwidth_data));
	#ifdef ENABLE_BANDWIDTH_LOGGING
		FILE *fp = fopen(bandwidth_log_name, "w");
		if(fp != NULL)
			fclose(fp);
	#endif
	
	get_friend_id(g_friend_id);

	#ifdef UID_CLASH_ENABLE
		g_uid_clash_offset = get_random_number(0) % 10000;
	#endif

	return 0;
}

static int init_self_ip(char *thread_id)
{
	int ret;

	#ifdef DEBUG_MODE
		ret = get_eth_ip_address(thread_id, g_client_ip_addr, sizeof(g_client_ip_addr));
		if(ret < 0) {
			#ifdef ENABLE_LOGGING
				fprintf(stdout, "%s Failed to get eth ip address\n", thread_id);
			#endif

			return -1;
		}
	#else
		#ifdef LAN_NETWORKING_MODE
			ret = get_lan_ip_address(thread_id, g_client_ip_addr, sizeof(g_client_ip_addr));
			if(ret < 0) {
				#ifdef ENABLE_LOGGING
					fprintf(stdout, "%s Failed to get lan ip address\n", thread_id);
				#endif

				return -1;
			}
		#else
			ret = get_public_ip_address(thread_id, g_client_ip_addr, sizeof(g_client_ip_addr));
			if(ret < 0) {
				#ifdef ENABLE_LOGGING
					fprintf(stdout, "%s Failed to get public ip address\n", thread_id);
				#endif

				return -1;
			}

			ret = add_port_mapping(thread_id, g_message_port, MSG_PORT_PROTOCOL);
			if(ret < 0) {
				#ifdef ENABLE_LOGGING
					fprintf(stdout, "%s Failed to add port mapping to upnp router\n", thread_id);
				#endif

				return -1;
			}
		#endif
	#endif	

	#ifdef ENABLE_LOGGING
		fprintf(stdout, "%s Found my ip address: %s\n", thread_id, g_client_ip_addr);
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

	#ifdef ENABLE_TRANSMIT_RECEIVE_LOGGING
		fprintf(stdout, "[RECEIVE PACKET THREAD] Receive packet thread begin\n");
	#endif

	ret = init_listening_socket("[RECEIVE PACKET THREAD]", g_message_port, &rp_listening_socket);
	handle_pthread_ret("[RECEIVE PACKET THREAD]", ret, -1);

	while(1) {
		usleep(MIN_PACKET_TRANSMISSION_DELAY_US);

		sockaddr_len = sizeof(relay_addr);
		bzero((char *) &relay_addr, sizeof(relay_addr));
		relay_socket = accept(rp_listening_socket, (struct sockaddr *)&relay_addr, &sockaddr_len);
		if(relay_socket < 0) {
			#ifdef ENABLE_LOGGING
				fprintf(stdout, "[RECEIVE PACKET THREAD] Failed to accept relay connection, %s\n", strerror(errno));
			#endif

			continue;
		}
		#ifdef ENABLE_TRANSMIT_RECEIVE_LOGGING
			fprintf(stdout, "\r[RECEIVE PACKET THREAD] %s:%d received packet\n", inet_ntoa(relay_addr.sin_addr), ntohs(relay_addr.sin_port));
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
	int ret, is_message;

	if(packet == NULL) {
		return -1;
	}

	#ifdef PRINT_PACKETS 
		fprintf(stdout, "Received payload: ");
		for(i = 0; i < packet_size_bytes; i++) {
			fprintf(stdout, "%02x", (unsigned char)packet[i]);
		}
		fprintf(stdout, "\n");
	#endif

	ret = is_message_packet(packet, &is_message);
	if(ret < 0) {
		return -1;
	}
	if(is_message) {
		handle_message_packet(packet);
	} else {
		handle_command_packet(packet);
	}

	return 0;
}

static int is_message_packet(char *packet, int *is_message)
{
	if((packet == NULL) || (is_message == NULL)) {
		return -1;
	}

	*is_message = 0; // TODO

	return 0;
}

static int handle_message_packet(char *packet)
{
	if(packet == NULL) {
		return -1;
	}

	// TODO

	return 0;
}

static int handle_command_packet(char *packet)
{
	int ret;

	if(packet == NULL) {
		return -1;
	}

	sem_wait(&th_comm_sem);
	if(g_th_comm.curr_status == IN_PROGRESS) {
		g_th_comm.curr_attempts.num_attempts++;
		switch(g_th_comm.curr_command) {
			case NO_COMMAND:
				g_th_comm.curr_status = COMPLETE;
			break;
			case VERIFY_RETURN_DATA:
				ret = memcmp(packet, g_th_comm.command_data, THREAD_RETURN_PACKET_CONFIRM_SIZE);
				if(ret == 0) {
					g_th_comm.curr_status = COMPLETE;
					g_th_comm.curr_return_code = SUCCESS;
				}
			break;
			case PLACE_LATEST_IN_QUEUE:
			break;
			case VERIFY_DUMMY_PACKET_RECEIVED:
				g_th_comm.curr_status = COMPLETE;
				g_th_comm.curr_return_code = SUCCESS;
			break;
		}
	}
	sem_post(&th_comm_sem);

	return 0;
}

static int init_listening_socket(char *thread_id, unsigned int port, int *listening_socket /* out */)
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
	int should_send_packet, did_send_packet;

	should_send_packet = 0;
	did_send_packet = 0;
	while(1) {
		handle_constant_bandwidth(did_send_packet, &should_send_packet);
		handle_packet_transmission(should_send_packet, &did_send_packet);	
	}
}

static int handle_constant_bandwidth(int did_send_packet, int *should_send_packet)
{
	int ret;
	struct timeval time_diff;
	float current_average_bandwidth;
	static struct timeval prev_time, curr_time;
	static int time_initialized = 0;

	if(should_send_packet == NULL) {
		return -1;
	}

	if(time_initialized) {
		timeval_subtract(&time_diff, &curr_time, &prev_time);

		g_bandwidth_data.b_st[g_bandwidth_data.index].timediff_sec = (float)time_diff.tv_sec + ((float)time_diff.tv_usec / (float)1000000);
		g_bandwidth_data.b_st[g_bandwidth_data.index].sent_packet = did_send_packet;
		g_bandwidth_data.index++;
		if(g_bandwidth_data.index >= BANDWIDTH_ST_LENGTH) {
			g_bandwidth_data.index = 0;
		}

		if(g_performing_relay_verification_and_reconnection) {
			*should_send_packet = 1;
		} else {
			get_current_average_bandwidth(&current_average_bandwidth);
			if(current_average_bandwidth < CONSTANT_BANDWIDTH_BYTES_PER_SEC) {
				*should_send_packet = 1;
			} else {
				*should_send_packet = 0;
			}
		}
	}
	ret = gettimeofday(&prev_time, NULL);
	if(ret < 0) {
		return -1;
	}

	usleep(MIN_PACKET_TRANSMISSION_DELAY_US);
	usleep(get_random_number(0) % MIN_PACKET_TRANSMISSION_DELAY_US);

	ret = gettimeofday(&curr_time, NULL);
	if(ret < 0) {
		return -1;
	}
	time_initialized = 1;

	return 0;
}

static int get_current_average_bandwidth(float *current_average_bandwidth)
{
	int i, total_packets;
	float total_time_sec;

	if(current_average_bandwidth == NULL) {
		return -1;
	}

	total_packets = 0;
	total_time_sec = 0;
	for(i = 0; i < BANDWIDTH_ST_LENGTH; ++i) {
		total_time_sec += g_bandwidth_data.b_st[i].timediff_sec;
		if(g_bandwidth_data.b_st[i].sent_packet) {
			total_packets++;
		}
	}

	*current_average_bandwidth = ((float)total_packets * ((float)PACKET_SIZE_BYTES + (float)TCP_BYTE_OVERHEAD)) / total_time_sec;

	return 0;
}

static int handle_packet_transmission(int should_send_packet, int *did_send_packet)
{
	int ret;
	send_packet_node *sp_node_to_free;

	if(did_send_packet == NULL) {
		return -1;
	}

	if(should_send_packet == 0) {
		*did_send_packet = 0;
		return 0;
	}

	if(g_sp_node == NULL) {
		g_queue_dummy_packet_transmission = 1;
		*did_send_packet = 0;

		#ifdef ENABLE_BANDWIDTH_LOGGING
			FILE *fp;
			fp = fopen(bandwidth_log_name, "a+");
			if(fp != NULL) {
				fprintf(fp, "0,\n");
				fclose(fp);
			}
		#endif
	} else {		
		sem_wait(&g_sp_node_sem);

		#ifdef ENABLE_TRANSMIT_RECEIVE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Transmitting packet\n");
			fflush(stdout);
		#endif

		ret = send_packet_to_relay(g_sp_node->packet_buf, g_sp_node->destination_ip, g_sp_node->destination_port);
		if(ret < 0) {
			#ifdef ENABLE_LOGGING
				fprintf(stdout, "[SEND PACKET THREAD] Failed to send packet to relay, ip = %s\n", g_sp_node->destination_ip);
			#endif

			#ifdef ENABLE_STANDARD_LOGGING
				fprintf(stdout, "Fatal connection error occurred, err_code=%x\n", (unsigned int)ENTRY_RELAY_OFFLINE);
			#endif
			exit(0);
		}

		sp_node_to_free = g_sp_node;
		g_sp_node = g_sp_node->next;
		free(sp_node_to_free);
		sem_post(&g_sp_node_sem);

		*did_send_packet = 1;

		#ifdef ENABLE_BANDWIDTH_LOGGING
			FILE *fp;
			fp = fopen(bandwidth_log_name, "a+");
			if(fp != NULL) {
				fprintf(fp, "%lu,\n", PACKET_SIZE_BYTES);
				fclose(fp);
			}
		#endif
	}

	return 0;
}

static int handle_dummy_packet_transmission(void)
{
	int ret, rand_val, perform_relay_verification, dummy_packet_received;
	static int dont_send_packet_counter = 0;

	if(dont_send_packet_counter > 0) {
		dont_send_packet_counter--;
		return 0;
	}

	perform_relay_verification = 0;
	rand_val = get_random_number(0) % (DO_NODE_CONNECTION_CHECK + 1);
	switch(rand_val) {
		case DONT_SEND_PACKET:
			dont_send_packet_counter = 0;
			break;
		case DONT_SEND_PACKET_R:
			dont_send_packet_counter = 0;
			break;
		case DONT_SEND_PACKET_RR:
			dont_send_packet_counter = 0;
			break;
		case DONT_SEND_PACKET_T2:
			dont_send_packet_counter = 1;
			break;
		case DONT_SEND_PACKET_T3:
			dont_send_packet_counter = 2;
			break;
		case SEND_DUMMY_PACKET_NO_RR:
			send_dummy_packet_no_return_route(&(g_conversations[g_current_conversation_index]));
			break;
		case SEND_DUMMY_PACKET_NO_RR_T2:
			send_dummy_packet_no_return_route(&(g_conversations[g_current_conversation_index]));
			send_dummy_packet_no_return_route(&(g_conversations[g_current_conversation_index]));
			break;
		case SEND_DUMMY_PACKET_NO_RR_AND_W_RR:
			send_dummy_packet_no_return_route(&(g_conversations[g_current_conversation_index]));
			wait_for_send_queue_empty("[MAIN THREAD]");
			initialize_should_receive_dummy_packet_command();
			send_dummy_packet_with_return_route(&(g_conversations[g_current_conversation_index]));
			ret = wait_for_command_completion(MAX_VERIFY_ROUTE_TIME_SEC, &dummy_packet_received);
			if(ret < 0) {
				return -1;
			}
			if(dummy_packet_received == 0) {
				perform_relay_verification = 1;
			}
			break;
		case SEND_DUMMY_PACKET_W_RR:
			wait_for_send_queue_empty("[MAIN THREAD]");
			initialize_should_receive_dummy_packet_command();
			send_dummy_packet_with_return_route(&(g_conversations[g_current_conversation_index]));
			ret = wait_for_command_completion(MAX_VERIFY_ROUTE_TIME_SEC, &dummy_packet_received);
			if(ret < 0) {
				return -1;
			}
			if(dummy_packet_received == 0) {
				perform_relay_verification = 1;
			}
			break;
		case SEND_DUMMY_PACKET_W_RR_T2:
			wait_for_send_queue_empty("[MAIN THREAD]");
			initialize_should_receive_dummy_packet_command();
			send_dummy_packet_with_return_route(&(g_conversations[g_current_conversation_index]));
			ret = wait_for_command_completion(MAX_VERIFY_ROUTE_TIME_SEC, &dummy_packet_received);
			if(ret < 0) {
				return -1;
			}
			if(dummy_packet_received == 0) {
				perform_relay_verification = 1;
				break;
			}
			wait_for_send_queue_empty("[MAIN THREAD]");
			initialize_should_receive_dummy_packet_command();
			send_dummy_packet_with_return_route(&(g_conversations[g_current_conversation_index]));
			ret = wait_for_command_completion(MAX_VERIFY_ROUTE_TIME_SEC, &dummy_packet_received);
			if(ret < 0) {
				return -1;
			}
			if(dummy_packet_received == 0) {
				perform_relay_verification = 1;
			}
			break;
		case SEND_DUMMY_PACKET_W_RR_AND_NO_RR:
			wait_for_send_queue_empty("[MAIN THREAD]");
			initialize_should_receive_dummy_packet_command();
			send_dummy_packet_with_return_route(&(g_conversations[g_current_conversation_index]));
			ret = wait_for_command_completion(MAX_VERIFY_ROUTE_TIME_SEC, &dummy_packet_received);
			if(ret < 0) {
				return -1;
			}
			if(dummy_packet_received == 0) {
				perform_relay_verification = 1;
			}
			send_dummy_packet_no_return_route(&(g_conversations[g_current_conversation_index]));
			break;
		case DO_NODE_CONNECTION_CHECK:
			handle_potential_loss_of_nodes(&(g_conversations[g_current_conversation_index]));
			break;
		default:
			return 0;
	}

	if(perform_relay_verification == 1) {
		handle_potential_loss_of_nodes(&(g_conversations[g_current_conversation_index]));
	}

	return 0;
}

static int get_number_of_packets_in_send_queue(int *num_packets)
{
	send_packet_node *sp_node_tmp;

	if(num_packets == NULL) {
		return -1;
	}

	sp_node_tmp = g_sp_node;
	*num_packets = 0;
	while(sp_node_tmp) {
		sp_node_tmp = sp_node_tmp->next;
		(*num_packets)++;
	}

	return 0;
}

static int send_packet_to_relay(unsigned char *packet, char *destination_ip, int destination_port)
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
		initial_seed_value = (((unsigned int)g_user_id[1])<<24) | (((unsigned int)g_user_id[3])<<16) | (((unsigned int)g_user_id[0])<<8) | ((unsigned int)g_user_id[2]);
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

static int init_chat(char *friend_name, conversation_info *ci_out /* out */)
{
	int ret;
	//int convo_valid;

	if((friend_name == NULL) || (ci_out == NULL)) {
		return -1;
	}
	if(strlen(friend_name) > USER_NAME_MAX_LENGTH) {
		return -1;
	}

	#ifdef ENABLE_STANDARD_LOGGING
		fprintf(stdout, "Initializing conversation.");
		fflush(stdout);
	#endif

	memset(ci_out, 0, sizeof(conversation_info));

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
		ci_out->ri_pool[0].relay_port = 22222;
		ci_out->ri_pool[1].relay_port = 22222;
		ci_out->ri_pool[2].relay_port = 22222;
		ci_out->ri_pool[3].relay_port = 22222;
		ci_out->ri_pool[0].is_active = 1;
		ci_out->ri_pool[1].is_active = 1;
		ci_out->ri_pool[2].is_active = 1;
		ci_out->ri_pool[3].is_active = 1;
		ci_out->conversation_valid = 1;

		ret = get_relay_public_certificates_debug(ci_out);
		if(ret < 0) {
			return -1;
		}

	#endif

	/*  TODO - Check enough relays (minimum 3 including server node)
	 *  Check no two relays have IP address within same subnet (lower 10 bits or something)
	 *  Check validity of relay port (compare against PORT_MAX and PORT_MIN)
	 *  Check no two relays have same public cert
	 *  Check no two relays have same id
	 *  Server relay is online
	 *  Entry relay is online
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
	#ifdef ENABLE_STANDARD_LOGGING 
		fprintf(stdout, "done\nInitializing networking.");
		fflush(stdout);
	#endif

	ret = perform_user_id_registration("[MAIN THREAD]", ci_out);
	if(ret < 0) {
		return -1;
	}

	ret = handle_potential_loss_of_nodes(ci_out);
	if(ret < 0) {
		return -1;
	}

	#ifdef ENABLE_STANDARD_LOGGING
		fprintf(stdout, "done\n");
	#endif

	return ret;
}

static int get_index_of_next_free_conversation(conversation_info *conversations)
{
	int i;

	for(i = 0; i < MAX_CONVERSATIONS; i++) {
		if(conversations[i].conversation_valid == 0) {
			return i;
		}
	}

	return -1;
}

static int get_relay_public_certificates_debug(conversation_info *ci_info)
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
			initial_seed_value = (((unsigned int)g_user_id[0])<<24) | (((unsigned int)g_user_id[1])<<16) | (((unsigned int)g_user_id[2])<<8) | ((unsigned int)g_user_id[3]);
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
		serv_addr.sin_port = htons(ci_info->ri_pool[i].relay_port + 2);
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
	#ifdef ENABLE_STANDARD_LOGGING
		fprintf(stdout, ".");
		fflush(stdout);
	#endif
	
	return 0;
}

static int set_entry_relay_for_conversation(conversation_info *ci_info)
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

	for (i = 0; (i+4) < strlen((char *)g_user_id); i+=4) {
		initial_seed_value ^= (((unsigned int)g_user_id[0])<<24) | (((unsigned int)g_user_id[1])<<16) | (((unsigned int)g_user_id[2])<<8) | ((unsigned int)g_user_id[3]);
	}
	while(1) {
		first_relay_index = get_random_number(initial_seed_value);
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
	#ifdef ENABLE_STANDARD_LOGGING
		fprintf(stdout, ".");
		fflush(stdout);
	#endif

	return 0;
}

static int reset_relay(char *thread_id, relay_info* r_info)
{
	int ret;

	if(r_info == NULL) {
		return -1;
	}

	memset(&(r_info->current_key_info), 0, sizeof(r_info->current_key_info));
	memset(&(r_info->key_info_history), 0, sizeof(r_info->key_info_history));
	r_info->kih_index = 0;

	ret = generate_AES_key(r_info->current_key_info.aes_key, AES_KEY_SIZE_BYTES);
	if(ret < 0) {
		return -1;
	}
	ret = generate_AES_key(r_info->current_key_info.payload_aes_key, AES_KEY_SIZE_BYTES);
	if(ret < 0) {
		return -1;
	}
	ret = generate_AES_key(r_info->current_key_info.return_route_aes_key, AES_KEY_SIZE_BYTES);
	if(ret < 0) {
		return -1;
	}
	ret = generate_AES_key(r_info->current_key_info.return_route_payload_aes_key, AES_KEY_SIZE_BYTES);
	if(ret < 0) {
		return -1;
	}
	generate_new_user_id(r_info->max_uid, &(r_info->current_key_info.relay_user_id));
	generate_new_user_id(r_info->max_uid, &(r_info->current_key_info.payload_relay_user_id));
	generate_new_user_id(r_info->max_uid, &(r_info->current_key_info.return_route_user_id));
	generate_new_user_id(r_info->max_uid, &(r_info->current_key_info.return_route_payload_user_id));

	return 0;
}

static int set_relay_keys_for_conversation(conversation_info *ci_info)
{
	int ret, i;

	if(ci_info == NULL) {
		return -1;
	}

	for (i = 0; i < RELAY_POOL_MAX_SIZE; ++i) {
		if(ci_info->ri_pool[i].is_active) {
			ret = generate_AES_key(ci_info->ri_pool[i].current_key_info.aes_key, AES_KEY_SIZE_BYTES);
			if(ret < 0) {
				return -1;
			}
			ret = generate_AES_key(ci_info->ri_pool[i].current_key_info.payload_aes_key, AES_KEY_SIZE_BYTES);
			if(ret < 0) {
				return -1;
			}
			ret = generate_AES_key(ci_info->ri_pool[i].current_key_info.return_route_aes_key, AES_KEY_SIZE_BYTES);
			if(ret < 0) {
				return -1;
			}
			ret = generate_AES_key(ci_info->ri_pool[i].current_key_info.return_route_payload_aes_key, AES_KEY_SIZE_BYTES);
			if(ret < 0) {
				return -1;
			}
		}
	}
	#ifdef ENABLE_STANDARD_LOGGING
		fprintf(stdout, ".");
		fflush(stdout);
	#endif

	return 0;
}

static int set_user_ids_for_conversation(conversation_info *ci_info)
{
	int i;

	if(ci_info == NULL) {
		return -1;
	}

	for (i = 0; i < RELAY_POOL_MAX_SIZE; ++i) {
		if(ci_info->ri_pool[i].is_active) {
			generate_new_user_id(ci_info->ri_pool[i].max_uid, &(ci_info->ri_pool[i].current_key_info.relay_user_id));
			generate_new_user_id(ci_info->ri_pool[i].max_uid, &(ci_info->ri_pool[i].current_key_info.payload_relay_user_id));
			generate_new_user_id(ci_info->ri_pool[i].max_uid, &(ci_info->ri_pool[i].current_key_info.return_route_user_id));
			generate_new_user_id(ci_info->ri_pool[i].max_uid, &(ci_info->ri_pool[i].current_key_info.return_route_payload_user_id));
		}
	}
	#ifdef ENABLE_STANDARD_LOGGING
		fprintf(stdout, ".");
		fflush(stdout);
	#endif

	return 0;
}

static int generate_new_user_id(int max_uid, unsigned int *uid /* out */)
{
	int i;
	unsigned int initial_seed_value;
	unsigned int relay_user_id;

	if(uid == NULL) {
		return -1;
	}

	for (i = 0; (i+4) < strlen((char *)g_user_id); i+=4) {
		initial_seed_value ^= (((unsigned int)g_user_id[3])<<24) | (((unsigned int)g_user_id[2])<<16) | (((unsigned int)g_user_id[1])<<8) | ((unsigned int)g_user_id[0]);
	}
	relay_user_id = get_random_number(initial_seed_value);
	relay_user_id %= max_uid;

	#ifdef UID_CLASH_ENABLE
		relay_user_id %= 5;
		relay_user_id += g_uid_clash_offset;
	#endif
	*uid = relay_user_id;
	
	#ifdef PRINT_UID_GENERATION 
		fprintf(stdout, "[MAIN THREAD] Generated new user ID = %u, max = %u\n", *uid, max_uid);
	#endif

	return 0;
}

static int perform_user_id_registration(char *thread_id, conversation_info *ci_info)
{
	int ret, i;
	unsigned int seed_val, relay_register_index;
	unsigned int total_active_relays, total_registered_relays;
	char index_of_relays_registered[RELAY_POOL_MAX_SIZE];

	if(ci_info == NULL) {
		return -1;
	}

	commit_key_info_to_history(ci_info);
	commit_route_info_to_history(REGISTER_UIDS_WITH_ENTRY_RELAY, ci_info, NULL, NULL, NULL);	
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
	seed_val = (((unsigned int)g_user_id[2])<<24) | (((unsigned int)g_user_id[1])<<16) | (((unsigned int)g_user_id[3])<<8) | ((unsigned int)g_user_id[0]);
	while(1) {
		relay_register_index = get_random_number(seed_val);
		seed_val ^= relay_register_index;

		relay_register_index %= RELAY_POOL_MAX_SIZE;
		if((ci_info->ri_pool[relay_register_index].is_active == 1) && (relay_register_index != ci_info->index_of_entry_relay)) {
			if(index_of_relays_registered[relay_register_index] == 0) {
				wait_for_send_queue_empty(thread_id);
				#ifdef ENABLE_STANDARD_LOGGING 
					fprintf(stdout, ".");
					fflush(stdout);
				#endif

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
	commit_key_info_to_history(ci_info);
	commit_route_info_to_history(REGISTER_UIDS_WITH_RELAY, ci_info, NULL, NULL, &relay_register_index);

	return 0;
}

static int generate_random_route(conversation_info *ci_info, route_info *r_info)
{
	int num_routed;
	unsigned int seed_val, index;
	char index_of_relays_used[RELAY_POOL_MAX_SIZE];

	if((ci_info == NULL) || (r_info == NULL)) {
		return -1;
	}

	memset(index_of_relays_used, 0, RELAY_POOL_MAX_SIZE);
	seed_val = (((unsigned int)g_user_id[1])<<24) | (((unsigned int)g_user_id[0])<<16) | (((unsigned int)g_user_id[3])<<8) | ((unsigned int)g_user_id[2]);
	r_info->relay_route[0] = ci_info->index_of_entry_relay;
	r_info->route_length = MIN_ROUTE_LENGTH + (get_random_number(seed_val) % (MAX_ROUTE_LENGTH - (MIN_ROUTE_LENGTH - 1)));

	num_routed = 1;
	while(num_routed < r_info->route_length) {
		index = get_random_number(seed_val);
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

static int generate_random_return_route(conversation_info *ci_info, route_info *r_info, route_info *return_r_info)
{
	int i;
	unsigned int seed_val, index;

	if((ci_info == NULL) || (r_info == NULL) || (return_r_info == NULL)) {
		return -1;
	}

	seed_val = (((unsigned int)g_user_id[1])<<24) | (((unsigned int)g_user_id[0])<<16) | (((unsigned int)g_user_id[3])<<8) | ((unsigned int)g_user_id[2]);
	return_r_info->route_length = MIN_RETURN_ROUTE_LENGTH + (get_random_number(seed_val) % (MAX_ROUTE_LENGTH - (MIN_RETURN_ROUTE_LENGTH - 1)));
	return_r_info->relay_route[(return_r_info->route_length - 1)] = ci_info->index_of_entry_relay;

	i = 0;
	while(i < (return_r_info->route_length - 1)) {
		index = get_random_number(seed_val);
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

static int generate_payload_metadata_for_entry_relay(char *thread_id, char* ip_addr, payload_data *payload)
{
	uint64_t ip_first_return_relay;

	if((ip_addr == NULL) || (payload == NULL)) {
		return -1;
	}

	payload->type = DUMMY_PACKET_W_RETURN_ROUTE;
	payload->onion_r1 = g_message_port;
	inet_aton(ip_addr, (struct in_addr *)&ip_first_return_relay);
	payload->client_id = (uint32_t)((ip_first_return_relay >> 32) & 0xFFFFFFFF);
	payload->conversation_id = (uint32_t)(ip_first_return_relay & 0xFFFFFFFF);

	return 0;
}

static int initialize_relay_verification_command(payload_data *verification_payload)
{
	if(verification_payload == NULL) {
		return -1;
	}

	sem_wait(&th_comm_sem);
	g_th_comm.curr_command = VERIFY_RETURN_DATA; 
	g_th_comm.curr_status = IN_PROGRESS;
	g_th_comm.curr_attempts.num_attempts = 0;
	memcpy(g_th_comm.command_data, (verification_payload->payload + sizeof(onion_route_data)), THREAD_RETURN_PACKET_CONFIRM_SIZE);

	#ifdef PRINT_PACKETS
		int i;
		fprintf(stdout, "Init payload: ");
		for(i = 0; i < THREAD_RETURN_PACKET_CONFIRM_SIZE; i++) {
			fprintf(stdout, "%02x", g_th_comm.command_data[i]);
		}
		fprintf(stdout, "\n");
	#endif

	sem_post(&th_comm_sem);

	return 0;
}

static int initialize_entry_relay_verification_command(payload_data *verification_payload)
{
	if(verification_payload == NULL) {
		return -1;
	}

	sem_wait(&th_comm_sem);
	g_th_comm.curr_command = VERIFY_RETURN_DATA; 
	g_th_comm.curr_status = IN_PROGRESS;
	g_th_comm.curr_attempts.num_attempts = 0;
	memcpy(g_th_comm.command_data, verification_payload->payload, THREAD_RETURN_PACKET_CONFIRM_SIZE);

	#ifdef PRINT_PACKETS
		int i;
		fprintf(stdout, "Init payload: ");
		for(i = 0; i < THREAD_RETURN_PACKET_CONFIRM_SIZE; i++) {
			fprintf(stdout, "%02x", g_th_comm.command_data[i]);
		}
		fprintf(stdout, "\n");
	#endif

	sem_post(&th_comm_sem);

	return 0;
}

static int initialize_should_receive_dummy_packet_command(void)
{
	sem_wait(&th_comm_sem);
	g_th_comm.curr_command = VERIFY_DUMMY_PACKET_RECEIVED; 
	g_th_comm.curr_status = IN_PROGRESS;
	g_th_comm.curr_attempts.num_attempts = 0;
	sem_post(&th_comm_sem);

	return 0;
}

static int wait_for_command_completion(int max_command_time, int *command_ret_status)
{
	int i;

	if(command_ret_status == NULL) {
		return -1;
	}

	*command_ret_status = 0;
	for (i = 0; i < max_command_time; ++i) {
		if((g_th_comm.curr_status == COMPLETE) && (g_th_comm.curr_return_code == SUCCESS)) {
			*command_ret_status = 1;
			break;
		}
		sleep(1);
	}
	sem_wait(&th_comm_sem);
	g_th_comm.curr_status = IDLE_STATUS;
	sem_post(&th_comm_sem);

	return 0;
}

static int check_if_loss_of_relay_is_fatal(char *thread_id, conversation_info *ci_info, int *fatal_connection_err)
{
	int i, total_active_and_responsive;

	if((ci_info == NULL) || (fatal_connection_err == NULL)) {
		return -1;
	}

	*fatal_connection_err = 0;

	total_active_and_responsive = 0;
	for (i = 0; i < RELAY_POOL_MAX_SIZE; ++i) {
		if((ci_info->ri_pool[i].is_active == 1) && (ci_info->ri_pool[i].is_responsive == 1)) {
			total_active_and_responsive++;
		} else if((ci_info->ri_pool[i].is_active == 1) && (ci_info->ri_pool[i].is_responsive == 0)) {
			if(i == ci_info->index_of_entry_relay) {
				*fatal_connection_err |= ENTRY_RELAY_OFFLINE;
			}
			if(i == ci_info->index_of_server_relay) {
				*fatal_connection_err |= SERVER_RELAY_OFFLINE;
			}
		}
	}
	if(total_active_and_responsive < MINIMUM_NUM_RELAYS_REQ_FOR_REGISTER) {
		*fatal_connection_err |= TOO_FEW_RELAYS_ONLINE;
	}

	return 0;
}

static int update_is_active_flag_based_on_is_responsive_flag(char *thread_id, conversation_info *ci_info)
{
	int i;

	if(ci_info == NULL) {
		return -1;
	}

	for (i = 0; i < RELAY_POOL_MAX_SIZE; ++i) {
		if((ci_info->ri_pool[i].is_active == 1) && (ci_info->ri_pool[i].is_responsive == 0)) {
			#ifdef ENABLE_STANDARD_LOGGING
				fprintf(stdout, "Unabled to reconnect to relay %d, removing it from relay pool\n", i);
			#endif
			ci_info->ri_pool[i].is_active = 0;
		}
	}

	return 0;
}

static int handle_potential_loss_of_nodes(conversation_info *ci_info)
{
	int verification_successful, fatal_connection_err;

	if(ci_info == NULL) {
		return -1;
	}

	perform_relay_verification_and_reconnection("[MAIN THREAD]", ci_info, HARD_RECONNECT, &verification_successful);
	if(verification_successful == 0) {
		check_if_loss_of_relay_is_fatal("[MAIN THREAD]", ci_info, &fatal_connection_err);
		if(fatal_connection_err) {
			#ifdef ENABLE_STANDARD_LOGGING
				fprintf(stdout, "Fatal connection error occurred, err_code=%x\n", (unsigned int)fatal_connection_err);
			#endif

			exit(0);
		}
		update_is_active_flag_based_on_is_responsive_flag("[MAIN THREAD]", ci_info);
	}

	return 0;
}

static int perform_relay_verification_and_reconnection(char *thread_id, conversation_info *ci_info, reconnect_type rc_type, int *success)
{
	int all_relays_online, all_relays_reconnected;
	int ret;

	if((ci_info == NULL) || (success == NULL)) {
		return -1;
	}

	wait_for_send_queue_empty(thread_id);

	g_performing_relay_verification_and_reconnection = 1;
	*success = 0;

	ret = verify_all_relays_online_rapid(thread_id, ci_info, &all_relays_online);
	if(ret < 0) {
		return -1;
	}
	if(all_relays_online) {
		g_performing_relay_verification_and_reconnection = 0;
		*success = 1;
		return 0;
	}

	ret = attempt_to_reconnect_unresponsive_relays_via_key_history(thread_id, ci_info, &all_relays_reconnected);
	if(ret < 0) {
		return -1;
	}
	if(all_relays_reconnected) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Successfully reconnected all relays\n", thread_id);
		#endif

		g_performing_relay_verification_and_reconnection = 0;
		*success = 1;
		return 0;
	}
	if(rc_type == SOFT_RECONNECT) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Failed reconnected all relays - not attempting to reregister as in 'SOFT_RECONNECT' mode\n", thread_id);
		#endif

		g_performing_relay_verification_and_reconnection = 0;
		*success = 0;
		return 0;
	}

	ret = attempt_to_reconnect_unresponsive_relays_via_reregister_id(thread_id, ci_info, &all_relays_reconnected);
	if(ret < 0) {
		return -1;
	}
	if(all_relays_reconnected) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Successfully reconnected all relays ('HARD_RECONNECT' mode)\n", thread_id);
		#endif

		*success = 1;
	} else {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Failed to reconnect all relays ('HARD_RECONNECT' mode)\n", thread_id);
		#endif
	}
	g_performing_relay_verification_and_reconnection = 0;

	return 0;
}

static int reconnect_to_entry_relay_via_key_history(char *thread_id, conversation_info *ci_info, return_key_history_type rkh_type, int *reconnect_success)
{
	int ret, reconnect_attempts, hist_index_forward_key_pair, hist_index_reverse_key_pair;
	id_key_info id_key_info_tmp;

	if((ci_info == NULL) || (reconnect_success == NULL)) {
		return -1;
	}
	*reconnect_success = 0;

	#ifdef ENABLE_KEY_HISTORY_LOGGING
		int j;
		fprintf(stdout, "First Attempt to connect to entry relay (forward key) (%s) with UID: %d and KEY: ", ci_info->ri_pool[ci_info->index_of_entry_relay].relay_ip, ci_info->ri_pool[ci_info->index_of_entry_relay].current_key_info.relay_user_id);
		for (j = 0; j < AES_KEY_SIZE_BYTES; ++j) {
			fprintf(stdout, "%02x", 0xff & ci_info->ri_pool[ci_info->index_of_entry_relay].current_key_info.aes_key[j]);
		}
		fprintf(stdout, "\n");
	#endif

	ret = verify_entry_relay_online("[MAIN THREAD]", ci_info, DISABLE_HISTORY, VERIFY_USING_FORWARD_KEY_UID_PAIR, reconnect_success);
	if(ret < 0) {
		return -1;
	}
	if(*reconnect_success == 0) {
		// Attempt reconnect with current key
		reconnect_attempts = 0;
		if(ci_info->ri_pool[ci_info->index_of_entry_relay].kih_index >= PATH_HISTORY_LENGTH) {
			ci_info->ri_pool[ci_info->index_of_entry_relay].kih_index = 0;
		}
		hist_index_forward_key_pair = ci_info->ri_pool[ci_info->index_of_entry_relay].kih_index - 1;
		memcpy(&id_key_info_tmp, &(ci_info->ri_pool[ci_info->index_of_entry_relay].current_key_info), (sizeof(id_key_info) / 2));
		while(1) {
			while(1) {
				ret = memcmp(&id_key_info_tmp, &(ci_info->ri_pool[ci_info->index_of_entry_relay].key_info_history[hist_index_forward_key_pair]), (sizeof(id_key_info) / 2));
				if(ret != 0) {
					break;
				}
				hist_index_forward_key_pair--;
				if(hist_index_forward_key_pair < 0) {
					hist_index_forward_key_pair = PATH_HISTORY_LENGTH - 1;
				}
				if(hist_index_forward_key_pair == ci_info->ri_pool[ci_info->index_of_entry_relay].kih_index) {
					break;
				}
				if(ci_info->ri_pool[ci_info->index_of_entry_relay].key_info_history[hist_index_forward_key_pair].relay_user_id == 0) {
					break;
				}
			}
			if(hist_index_forward_key_pair == ci_info->ri_pool[ci_info->index_of_entry_relay].kih_index) {
				break;
			}
			if(ci_info->ri_pool[ci_info->index_of_entry_relay].key_info_history[hist_index_forward_key_pair].relay_user_id == 0) {
				break;
			}

			memcpy(&id_key_info_tmp, &(ci_info->ri_pool[ci_info->index_of_entry_relay].key_info_history[hist_index_forward_key_pair]), (sizeof(id_key_info)/2));			
			memcpy(&(ci_info->ri_pool[ci_info->index_of_entry_relay].current_key_info), 
						&(ci_info->ri_pool[ci_info->index_of_entry_relay].key_info_history[hist_index_forward_key_pair]), (sizeof(id_key_info)/2));

			#ifdef ENABLE_KEY_HISTORY_LOGGING
				fprintf(stdout, "Attempting to connect to entry relay (%s) with UID: %d and KEY: ", ci_info->ri_pool[ci_info->index_of_entry_relay].relay_ip, ci_info->ri_pool[ci_info->index_of_entry_relay].current_key_info.relay_user_id);
				for (j = 0; j < AES_KEY_SIZE_BYTES; ++j) {
					fprintf(stdout, "%02x", 0xff & ci_info->ri_pool[ci_info->index_of_entry_relay].current_key_info.aes_key[j]);
				}
				fprintf(stdout, "\n");
			#endif

			ret = verify_entry_relay_online("[MAIN THREAD]", ci_info, DISABLE_HISTORY, VERIFY_USING_FORWARD_KEY_UID_PAIR, reconnect_success);
			if(ret < 0) {
				return -1;
			}
			if(*reconnect_success) {
				break;
			}
			if(++reconnect_attempts > MAX_UID_HISTORY_RECONNECT_ATTEMPTS) {
				break;
			}
		}
	}

	#ifdef ENABLE_KEY_HISTORY_LOGGING
		fprintf(stdout, "First Attempt to connect to entry relay (return key) (%s) with UID: %d and KEY: ", ci_info->ri_pool[ci_info->index_of_entry_relay].relay_ip, ci_info->ri_pool[ci_info->index_of_entry_relay].current_key_info.return_route_user_id);
		for (j = 0; j < AES_KEY_SIZE_BYTES; ++j) {
			fprintf(stdout, "%02x", 0xff & ci_info->ri_pool[ci_info->index_of_entry_relay].current_key_info.return_route_aes_key[j]);
		}
		fprintf(stdout, "\n");
	#endif

	if(rkh_type == USE_PREVIOUS_RETURN_KEY) {
		memcpy(((char *)&(ci_info->ri_pool[ci_info->index_of_entry_relay].current_key_info)) + (sizeof(id_key_info) / 2),  
					((char *)&(ci_info->ri_pool[ci_info->index_of_entry_relay].key_info_history[ci_info->ri_pool[ci_info->index_of_entry_relay].kih_index - 1])) + (sizeof(id_key_info) / 2), (sizeof(id_key_info) / 2));
	}

	ret = verify_entry_relay_online("[MAIN THREAD]", ci_info, DISABLE_HISTORY, VERIFY_USING_RETURN_KEY_UID_PAIR, reconnect_success);
	if(ret < 0) {
		return -1;
	}
	if(*reconnect_success == 0) {
		// Attempt reconnect with current key
		reconnect_attempts = 0;
		if(ci_info->ri_pool[ci_info->index_of_entry_relay].kih_index >= PATH_HISTORY_LENGTH) {
			ci_info->ri_pool[ci_info->index_of_entry_relay].kih_index = 0;
		}
		hist_index_reverse_key_pair = ci_info->ri_pool[ci_info->index_of_entry_relay].kih_index - 1;
		memcpy(&id_key_info_tmp, ((char *)&(ci_info->ri_pool[ci_info->index_of_entry_relay].current_key_info)) + (sizeof(id_key_info) / 2), (sizeof(id_key_info) / 2));
		while(1) {
			while(1) {
				ret = memcmp(&id_key_info_tmp, ((char *)&(ci_info->ri_pool[ci_info->index_of_entry_relay].key_info_history[hist_index_reverse_key_pair])) + (sizeof(id_key_info) / 2), (sizeof(id_key_info) / 2));
				if(ret != 0) {
					break;
				}
				hist_index_reverse_key_pair--;
				if(hist_index_reverse_key_pair < 0) {
					hist_index_reverse_key_pair = PATH_HISTORY_LENGTH - 1;
				}
				if(hist_index_reverse_key_pair == ci_info->ri_pool[ci_info->index_of_entry_relay].kih_index) {
					break;
				}
				if(ci_info->ri_pool[ci_info->index_of_entry_relay].key_info_history[hist_index_reverse_key_pair].relay_user_id == 0) {
					break;
				}
			}
			if(hist_index_reverse_key_pair == ci_info->ri_pool[ci_info->index_of_entry_relay].kih_index) {
				break;
			}
			if(ci_info->ri_pool[ci_info->index_of_entry_relay].key_info_history[hist_index_reverse_key_pair].relay_user_id == 0) {
				break;
			}

			memcpy(&id_key_info_tmp, ((char *)&(ci_info->ri_pool[ci_info->index_of_entry_relay].key_info_history[hist_index_reverse_key_pair])) + (sizeof(id_key_info) / 2), (sizeof(id_key_info)/2));
			memcpy(((char *)&(ci_info->ri_pool[ci_info->index_of_entry_relay].current_key_info) + (sizeof(id_key_info) / 2)), 
						((char *)&(ci_info->ri_pool[ci_info->index_of_entry_relay].key_info_history[hist_index_reverse_key_pair]) + (sizeof(id_key_info) / 2)), (sizeof(id_key_info)/2));

			#ifdef ENABLE_KEY_HISTORY_LOGGING
				fprintf(stdout, "Attempting to connect to entry relay (%s) with UID: %d and KEY: ", ci_info->ri_pool[ci_info->index_of_entry_relay].relay_ip, ci_info->ri_pool[ci_info->index_of_entry_relay].current_key_info.return_route_user_id);
				for (j = 0; j < AES_KEY_SIZE_BYTES; ++j) {
					fprintf(stdout, "%02x", 0xff & ci_info->ri_pool[ci_info->index_of_entry_relay].current_key_info.return_route_aes_key[j]);
				}
				fprintf(stdout, "\n");
			#endif

			ret = verify_entry_relay_online("[MAIN THREAD]", ci_info, DISABLE_HISTORY, VERIFY_USING_RETURN_KEY_UID_PAIR, reconnect_success);
			if(ret < 0) {
				return -1;
			}
			if(*reconnect_success) {
				break;
			}
			if(++reconnect_attempts > MAX_UID_HISTORY_RECONNECT_ATTEMPTS) {
				break;
			}
		}
	}

	if(*reconnect_success) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Reconnected to entry relay (ip = %s)\n", thread_id, ci_info->ri_pool[ci_info->index_of_entry_relay].relay_ip);
		#endif

		ci_info->ri_pool[ci_info->index_of_entry_relay].is_responsive = 1;
		commit_key_info_to_history(ci_info);
	} else {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Failed to reconnect to entry relay (ip = %s)\n", thread_id, ci_info->ri_pool[ci_info->index_of_entry_relay].relay_ip);
		#endif

		ci_info->ri_pool[ci_info->index_of_entry_relay].is_responsive = 0;
	}

	return 0;
}

static int attempt_to_reconnect_unresponsive_relays_via_key_history(char *thread_id, conversation_info *ci_info, int *reconnected_to_all_relays)
{
	int i, ret, relay_is_online, forward_hist_index, reverse_hist_index;
	int reconnect_attempts, entry_relay_online;
	id_key_info id_key_info_tmp;

	if((ci_info == NULL) || (reconnected_to_all_relays == NULL)) {
		return -1;
	}

	#ifdef ENABLE_STANDARD_LOGGING
		fprintf(stdout, "Detected network error, attempting to reconnect to relays\n");
	#endif

	*reconnected_to_all_relays = 0;
	for (i = 0; i < RELAY_POOL_MAX_SIZE; ++i) {
		if(i == ci_info->index_of_entry_relay) {
			continue;
		}
		if((ci_info->ri_pool[i].is_active == 1) && (ci_info->ri_pool[i].is_responsive == 0)) {
			#ifdef ENABLE_STANDARD_LOGGING
				fprintf(stdout, "Relay %d.", i);
			#endif
			if((i == 0) || (ci_info->ri_pool[i-1].is_responsive == 0)) {
				ret = reconnect_to_entry_relay_via_key_history(thread_id, ci_info, APPLY_RETURN_KEY_HISTORY, &entry_relay_online);
				if(ret < 0) {
					return -1;
				}
				if(entry_relay_online == 0) {
					*reconnected_to_all_relays = 0;
					return 0;
				}
			}

			#ifdef ENABLE_KEY_HISTORY_LOGGING
				int j;
				fprintf(stdout, "First Attempt to connect to relay (%d, %s) with UID: %d and KEY: ", i, ci_info->ri_pool[i].relay_ip, ci_info->ri_pool[i].current_key_info.relay_user_id);
				for (j = 0; j < AES_KEY_SIZE_BYTES; ++j) {
					fprintf(stdout, "%02x", 0xff & ci_info->ri_pool[i].current_key_info.aes_key[j]);
				}
				fprintf(stdout, "\n");
			#endif
			#ifdef ENABLE_STANDARD_LOGGING
				fprintf(stdout, ".");
				fflush(stdout);
			#endif
			ret = verify_relay_online("[MAIN THREAD]", ci_info, i, DISABLE_HISTORY, VERIFY_USING_FORWARD_KEY_UID_PAIR, &relay_is_online);
			if(ret < 0) {
				return -1;
			}
			if(relay_is_online == 0) {
				reconnect_attempts = 0;
				if(ci_info->ri_pool[i].kih_index >= PATH_HISTORY_LENGTH) {
					ci_info->ri_pool[i].kih_index = 0;
				}
				forward_hist_index = ci_info->ri_pool[i].kih_index - 1;
				memcpy(&id_key_info_tmp, &(ci_info->ri_pool[i].current_key_info), (sizeof(id_key_info_tmp) / 2));
				while(1) {
					ret = reconnect_to_entry_relay_via_key_history(thread_id, ci_info, APPLY_RETURN_KEY_HISTORY, &entry_relay_online);
					if(ret < 0) {
						return -1;
					}
					if(entry_relay_online == 0) {
						*reconnected_to_all_relays = 0;
						return 0;
					}
					while(1) {
						ret = memcmp(&id_key_info_tmp, &(ci_info->ri_pool[i].key_info_history[forward_hist_index]), (sizeof(id_key_info)/2));
						if(ret != 0) {
							break;
						}
						forward_hist_index--;
						if(forward_hist_index < 0) {
							forward_hist_index = PATH_HISTORY_LENGTH - 1;
						}
						if(forward_hist_index == ci_info->ri_pool[i].kih_index) {
							break;
						}
					}
					if(forward_hist_index == ci_info->ri_pool[i].kih_index) {
						break;
					}
					if(ci_info->ri_pool[i].key_info_history[forward_hist_index].relay_user_id == 0) {
						break;
					}

					memcpy(&id_key_info_tmp, &(ci_info->ri_pool[i].key_info_history[forward_hist_index]), (sizeof(id_key_info)/2));
					memcpy(&(ci_info->ri_pool[i].current_key_info), &(ci_info->ri_pool[i].key_info_history[forward_hist_index]), (sizeof(id_key_info)/2));

					#ifdef ENABLE_KEY_HISTORY_LOGGING
						fprintf(stdout, "Attempting to connect to relay (%d, %s) with UID: %d and KEY: ", i, ci_info->ri_pool[i].relay_ip, ci_info->ri_pool[i].current_key_info.relay_user_id);
						for (j = 0; j < AES_KEY_SIZE_BYTES; ++j) {
							fprintf(stdout, "%02x", 0xff & ci_info->ri_pool[i].current_key_info.aes_key[j]);
						}
						fprintf(stdout, "\n");
					#endif
					#ifdef ENABLE_STANDARD_LOGGING
						fprintf(stdout, ".");
						fflush(stdout);
					#endif
					ret = verify_relay_online("[MAIN THREAD]", ci_info, i, DISABLE_HISTORY, VERIFY_USING_FORWARD_KEY_UID_PAIR, &relay_is_online);
					if(ret < 0) {
						return -1;
					}
					if(relay_is_online) {
						break;
					}
					if(reconnect_attempts++ > MAX_UID_HISTORY_RECONNECT_ATTEMPTS) {
						break;
					}
				}
			}
			if(relay_is_online) {
				commit_key_info_to_history(ci_info);
			}

			#ifdef ENABLE_STANDARD_LOGGING
				fprintf(stdout, ".");
				fflush(stdout);
			#endif
			ret = verify_relay_online("[MAIN THREAD]", ci_info, i, DISABLE_HISTORY, VERIFY_USING_RETURN_KEY_UID_PAIR, &relay_is_online);
			if(ret < 0) {
				return -1;
			}
			if(relay_is_online == 0) {
				reconnect_attempts = 0;
				if(ci_info->ri_pool[i].kih_index >= PATH_HISTORY_LENGTH) {
					ci_info->ri_pool[i].kih_index = 0;
				}
				reverse_hist_index = ci_info->ri_pool[i].kih_index - 1;
				memcpy(&id_key_info_tmp, ((char *)&(ci_info->ri_pool[i].current_key_info)) + (sizeof(id_key_info_tmp) / 2), (sizeof(id_key_info_tmp) / 2));
				while(1) {
					ret = reconnect_to_entry_relay_via_key_history(thread_id, ci_info, USE_PREVIOUS_RETURN_KEY, &entry_relay_online);
					if(ret < 0) {
						return -1;
					}
					if(entry_relay_online == 0) {
						*reconnected_to_all_relays = 0;
						return 0;
					}
					while(1) {
						ret = memcmp(&id_key_info_tmp, ((char *)&(ci_info->ri_pool[i].key_info_history[reverse_hist_index])) + (sizeof(id_key_info)/2), (sizeof(id_key_info)/2));
						if(ret != 0) {
							break;
						}
						reverse_hist_index--;
						if(reverse_hist_index < 0) {
							reverse_hist_index = PATH_HISTORY_LENGTH - 1;
						}
						if(reverse_hist_index == ci_info->ri_pool[i].kih_index) {
							break;
						}
					}
					if(reverse_hist_index == ci_info->ri_pool[i].kih_index) {
						break;
					}
					if(ci_info->ri_pool[i].key_info_history[reverse_hist_index].relay_user_id == 0) {
						break;
					}
					
					memcpy(&id_key_info_tmp, ((char *)&(ci_info->ri_pool[i].key_info_history[reverse_hist_index])) + (sizeof(id_key_info)/2), (sizeof(id_key_info)/2));
					memcpy(((char *)&(ci_info->ri_pool[i].current_key_info)) + (sizeof(id_key_info)/2), 
							((char *)&(ci_info->ri_pool[i].key_info_history[reverse_hist_index])) + (sizeof(id_key_info)/2), (sizeof(id_key_info)/2));

					#ifdef ENABLE_KEY_HISTORY_LOGGING
						fprintf(stdout, "Attempting to connect to relay (%d, %s) with UID: %d and KEY: ", i, ci_info->ri_pool[i].relay_ip, ci_info->ri_pool[i].current_key_info.return_route_user_id);
						for (j = 0; j < AES_KEY_SIZE_BYTES; ++j) {
							fprintf(stdout, "%02x", 0xff & ci_info->ri_pool[i].current_key_info.return_route_aes_key[j]);
						}
						fprintf(stdout, "\n");
					#endif
					#ifdef ENABLE_STANDARD_LOGGING
						fprintf(stdout, ".");
						fflush(stdout);
					#endif
					ret = verify_relay_online("[MAIN THREAD]", ci_info, i, DISABLE_HISTORY, VERIFY_USING_RETURN_KEY_UID_PAIR, &relay_is_online);
					if(ret < 0) {
						return -1;
					}
					if(relay_is_online) {
						break;
					}
					if(reconnect_attempts++ > MAX_UID_HISTORY_RECONNECT_ATTEMPTS) {
						break;
					}
				}
			}

			if(relay_is_online) {
				#ifdef ENABLE_LOGGING
					fprintf(stdout, "%s Reconnect relay with index: %d and ip = %s\n", thread_id, i, ci_info->ri_pool[i].relay_ip);
				#endif
				#ifdef ENABLE_STANDARD_LOGGING
					fprintf(stdout, "success\n");
				#endif

				ci_info->ri_pool[i].is_responsive = 1;
				commit_key_info_to_history(ci_info);
			} else {
				#ifdef ENABLE_LOGGING
					fprintf(stdout, "%s Failed to reconnect relay with index: %d and ip = %s\n", thread_id, i, ci_info->ri_pool[i].relay_ip);
				#endif
				#ifdef ENABLE_STANDARD_LOGGING
					fprintf(stdout, "failed\n");
				#endif

				ci_info->ri_pool[i].is_responsive = 0;
			}
		}
	}

	*reconnected_to_all_relays = 1;
	for (i = 0; i < RELAY_POOL_MAX_SIZE; ++i) {
		if((ci_info->ri_pool[i].is_active == 1) && (ci_info->ri_pool[i].is_responsive == 0)) {
			*reconnected_to_all_relays = 0;
		}
	}

	return 0;
}

static int attempt_to_reconnect_unresponsive_relays_via_reregister_id(char *thread_id, conversation_info *ci_info, int *reconnected_to_all_relays)
{
	int i, ret;

	if((ci_info == NULL) || (reconnected_to_all_relays == NULL)) {
		return -1;
	}

	if(ci_info->ri_pool[ci_info->index_of_entry_relay].is_responsive == 0) {
		ret = reset_relay(thread_id, &(ci_info->ri_pool[ci_info->index_of_entry_relay]));
		if(ret < 0) {
			return -1;
		}	
		commit_key_info_to_history(ci_info);
		commit_route_info_to_history(REGISTER_UIDS_WITH_ENTRY_RELAY, ci_info, NULL, NULL, NULL);
		ret = send_packet(REGISTER_UIDS_WITH_ENTRY_RELAY, ci_info, NULL,  NULL, NULL);
		if(ret < 0) {
			return -1;
		}
		ci_info->ri_pool[ci_info->index_of_entry_relay].is_responsive = 1;
	}

	for (i = 0; i < RELAY_POOL_MAX_SIZE; ++i) {
		if(i == ci_info->index_of_entry_relay) {
			continue;
		}
		if((ci_info->ri_pool[i].is_active == 1) && (ci_info->ri_pool[i].is_responsive == 0)) {
			ret = reset_relay(thread_id, &(ci_info->ri_pool[i]));
			if(ret < 0) {
				return -1;
			}
			commit_key_info_to_history(ci_info);
			commit_route_info_to_history(REGISTER_UIDS_WITH_RELAY, ci_info, NULL, NULL, NULL);
			ret = send_packet(REGISTER_UIDS_WITH_RELAY, ci_info, NULL,  NULL, &i);
			if(ret < 0) {
				return -1;
			}
		}
	}

	ret = update_unresponsive_non_entry_relay_connectivity_status(thread_id, ci_info);
	if(ret < 0) {
		return -1;
	}

	return 0;
}

static int generate_rapid_verification_routes(char *thread_id, conversation_info *ci_info, route_pair *r_pair, int route_pair_length)
{
	int ret, i, num_active_relays, current_route_index;
	int forward_routes_covered, reverse_routes_covered;
	int forward_routes_to_cover, reverse_routes_to_cover;
	char index_of_relays_used[RELAY_POOL_MAX_SIZE]; // Bit flags -> | X | X | X | X | X | X | REVERSE COVERED | FORWARD COVERED |
	route_info r_info, rr_info;
	int loop_iterations;

	if((ci_info == NULL) || (r_pair == NULL)) {
		return -1;
	}
	if(route_pair_length < RELAY_POOL_MAX_SIZE) {
		return -1;
	}
	
	memset(index_of_relays_used, 0, RELAY_POOL_MAX_SIZE);
	memset(r_pair, 0, (route_pair_length * sizeof(r_pair)));

	num_active_relays = 0;
	for (i = 0; i < RELAY_POOL_MAX_SIZE; ++i) {
		if(ci_info->ri_pool[i].is_active) {
			num_active_relays++;
		}
	}

	current_route_index = 0;
	forward_routes_covered = reverse_routes_covered = 0;
	while(1) {
		loop_iterations = 0;
		while(1) {
			forward_routes_to_cover = 0;
			ret = generate_random_route(ci_info, &r_info);
			if(ret < 0) {
				return -1;
			}
			for (i = 0; i < r_info.route_length; ++i) {
				if((index_of_relays_used[r_info.relay_route[i]] & 0x01) == 0) {
					forward_routes_to_cover++;
				}
			}
			if(forward_routes_to_cover == MAX_ROUTE_LENGTH) {
				break;
			} else if((forward_routes_to_cover + forward_routes_covered) >= num_active_relays) {
				break;
			} else if(++loop_iterations > 20) {
				break;
			}
		}
		forward_routes_covered += forward_routes_to_cover;

		loop_iterations = 0;
		while(1) {
			reverse_routes_to_cover = 0;
			ret = generate_random_return_route(ci_info, &r_info, &rr_info);
			if(ret < 0) {
				return -1;
			}
			for (i = 0; i < rr_info.route_length; ++i) {
				if((index_of_relays_used[rr_info.relay_route[i]] & 0x02) == 0) {
					reverse_routes_to_cover++;
				}
			}
			if(reverse_routes_to_cover == MAX_ROUTE_LENGTH) {
				break;
			} else if((reverse_routes_to_cover + reverse_routes_covered) >= num_active_relays) {
				break;
			} else if(++loop_iterations > 20) {
				break;
			}
		}
		reverse_routes_covered += reverse_routes_to_cover;

		for (i = 0; i < r_info.route_length; ++i) {
			index_of_relays_used[r_info.relay_route[i]] |= 0x01;
		}
		for (i = 0; i < rr_info.route_length; ++i) {
			index_of_relays_used[rr_info.relay_route[i]] |= 0x02;
		}

		memcpy(&(r_pair[current_route_index].forward_route), &r_info, sizeof(r_info));
		memcpy(&(r_pair[current_route_index].return_route), &rr_info, sizeof(rr_info));
		current_route_index++;
		if(current_route_index >= route_pair_length) {
			return -1;
		}
		if(forward_routes_covered >= num_active_relays) {
			if(reverse_routes_covered >= num_active_relays) {
				break;
			}
		}
	}
	
	return 0;
}

static int wait_for_send_queue_empty(char *thread_id)
{
	int num_packets_in_send_queue;

	num_packets_in_send_queue = -1;
	while(num_packets_in_send_queue != 0) {
		get_number_of_packets_in_send_queue(&num_packets_in_send_queue);
		usleep(100000);
	}

	return 0;
}

static int verify_all_relays_online_rapid(char *thread_id, conversation_info *ci_info, int *all_relays_online)
{
	int ret, curr_route_index;
	int dummy_packet_received;
	route_pair r_pair[RELAY_POOL_MAX_SIZE];

	if((ci_info == NULL) || (all_relays_online == NULL)) {
		return -1;
	}

	ret = generate_rapid_verification_routes(thread_id, ci_info, r_pair, sizeof(r_pair)/sizeof(route_pair));
	if(ret < 0) {
		return -1;
	}
	#ifdef ENABLE_LOGGING
		fprintf(stderr, "%s Attempting to verify all relays are online rapidly\n", thread_id);
		print_route_pairs(thread_id, r_pair, sizeof(r_pair)/sizeof(route_pair));
	#endif

	*all_relays_online = 1;
	curr_route_index = 0;
	while(1) {
		if(r_pair[curr_route_index].forward_route.route_length == 0) {
			break;
		}
		if(r_pair[curr_route_index].return_route.route_length == 0) {
			break;
		}

		wait_for_send_queue_empty(thread_id);

		initialize_should_receive_dummy_packet_command();

		ret = send_dummy_packet_with_routes_defined(ci_info, &(r_pair[curr_route_index].forward_route), &(r_pair[curr_route_index].return_route));
		if(ret < 0) {
			return -1;
		}
		ret = wait_for_command_completion(MAX_VERIFY_ROUTE_TIME_SEC, &dummy_packet_received);
		if(ret < 0) {
			return -1;
		}
		if(dummy_packet_received == 0) {
			*all_relays_online = 0;
			break;
		}

		curr_route_index++;
		if(curr_route_index >= (sizeof(r_pair)/sizeof(route_pair))) {
			break;
		}
	}

	#ifdef ENABLE_LOGGING
		if(*all_relays_online) {
			fprintf(stdout, "%s Rapidly verification of all relays successful\n", thread_id);
		} else {
			fprintf(stdout, "%s Rapidly verification of all relays failed\n", thread_id);
		}
	#endif

	return 0;
}

__attribute__((unused)) static int verify_all_relays_online_basic(char *thread_id, conversation_info *ci_info, int *all_relays_online)
{
	int i, ret;

	if((ci_info == NULL) || (all_relays_online == NULL)) {
		return -1;
	}

	ret = verify_entry_relay_online(thread_id, ci_info, ENABLE_HISTORY, VERIFY_USING_FORWARD_KEY_UID_PAIR, &(ci_info->ri_pool[ci_info->index_of_entry_relay].is_responsive));
	if(ret < 0) {
		return -1;
	}
	if(ci_info->ri_pool[ci_info->index_of_entry_relay].is_responsive == 0) {
		*all_relays_online = 0;
		return 0;
	}
	ret = verify_entry_relay_online(thread_id, ci_info, ENABLE_HISTORY, VERIFY_USING_RETURN_KEY_UID_PAIR, &(ci_info->ri_pool[ci_info->index_of_entry_relay].is_responsive));
	if(ret < 0) {
		return -1;
	}
	if(ci_info->ri_pool[ci_info->index_of_entry_relay].is_responsive == 0) {
		*all_relays_online = 0;
		return 0;
	}

	ret = update_non_entry_relay_connectivity_status(thread_id, ci_info);
	if(ret < 0) {
		return -1;
	}

	*all_relays_online = 1;
	for (i = 0; i < RELAY_POOL_MAX_SIZE; ++i) {
		if((ci_info->ri_pool[i].is_active == 1) && (ci_info->ri_pool[i].is_responsive == 0)) {
			*all_relays_online = 0;
		}
	}

	#ifdef ENABLE_LOGGING
		if(*all_relays_online) {
			fprintf(stdout, "%s Found all relays are online\n", thread_id);
		} else {
			fprintf(stdout, "%s Found offline relays\n", thread_id);
		}
	#endif

	return 0;
}

static int update_non_entry_relay_connectivity_status(char *thread_id, conversation_info *ci_info)
{
	int i, ret, relay_is_online, entry_relay_online;
	unsigned int seed_val, index;
	int num_checked, num_to_check;
	char index_of_relays_used[RELAY_POOL_MAX_SIZE];

	if(ci_info == NULL) {
		return -1;
	}

	memset(index_of_relays_used, 0, RELAY_POOL_MAX_SIZE);

	num_to_check = num_checked = 0;
	for (i = 0; i < RELAY_POOL_MAX_SIZE; ++i) {
		if((ci_info->ri_pool[i].is_active == 1) && (i != ci_info->index_of_entry_relay)) {
			num_to_check++;
		}
	}
	seed_val = (((unsigned int)g_user_id[0]) ^ ((unsigned int)g_user_id[1]) ^ ((unsigned int)g_user_id[2]) ^ ((unsigned int)g_user_id[3]));
	while(num_checked < num_to_check) {
		index = get_random_number(seed_val);
		seed_val ^= index;

		index %= RELAY_POOL_MAX_SIZE;
		if((ci_info->ri_pool[index].is_active == 1) && (index != ci_info->index_of_entry_relay)) {
			if(index_of_relays_used[index] == 0) {
				ret = verify_relay_online("[MAIN THREAD]", ci_info, index, ENABLE_HISTORY, VERIFY_USING_FORWARD_KEY_UID_PAIR, &relay_is_online);
				if(ret < 0) {
					return -1;
				}
				if(relay_is_online) {
					ret = verify_relay_online("[MAIN THREAD]", ci_info, index, ENABLE_HISTORY, VERIFY_USING_RETURN_KEY_UID_PAIR, &relay_is_online);
					if(ret < 0) {
						return -1;
					}
					if(relay_is_online) {
						ci_info->ri_pool[index].is_responsive = 1;
					} else {
						ci_info->ri_pool[index].is_responsive = 0;
					}
				} else {
					ci_info->ri_pool[index].is_responsive = 0;
				}
				if(ci_info->ri_pool[index].is_responsive == 0) {
					ci_info->ri_pool[index].is_responsive = 0;
					ret = reconnect_to_entry_relay_via_key_history(thread_id, ci_info, APPLY_RETURN_KEY_HISTORY, &entry_relay_online);
					if(ret < 0) {
						return -1;
					}
					if(entry_relay_online == 0) {
						return 0;
					}
				}
				index_of_relays_used[index] = 1;
				num_checked++;
			}
		}
	}

	return 0;
}

static int update_unresponsive_non_entry_relay_connectivity_status(char *thread_id, conversation_info *ci_info)
{
	int i, ret, relay_is_online, entry_relay_online;
	unsigned int seed_val, index;
	int num_checked, num_to_check;
	char index_of_relays_used[RELAY_POOL_MAX_SIZE];

	if(ci_info == NULL) {
		return -1;
	}

	memset(index_of_relays_used, 0, RELAY_POOL_MAX_SIZE);

	num_to_check = num_checked = 0;
	for (i = 0; i < RELAY_POOL_MAX_SIZE; ++i) {
		if(((ci_info->ri_pool[i].is_active == 1) && (i != ci_info->index_of_entry_relay)) && (ci_info->ri_pool[i].is_responsive == 0)) {
			num_to_check++;
		}
	}
	seed_val = (((unsigned int)g_user_id[0]) ^ ((unsigned int)g_user_id[1]) ^ ((unsigned int)g_user_id[2]) ^ ((unsigned int)g_user_id[3]));
	while(num_checked < num_to_check) {
		index = get_random_number(seed_val);
		seed_val ^= index;

		index %= RELAY_POOL_MAX_SIZE;
		if(((ci_info->ri_pool[index].is_active == 1) && (index != ci_info->index_of_entry_relay)) && (ci_info->ri_pool[index].is_responsive == 0)) {
			if(index_of_relays_used[index] == 0) {
				ret = verify_relay_online("[MAIN THREAD]", ci_info, index, ENABLE_HISTORY, VERIFY_USING_FORWARD_KEY_UID_PAIR, &relay_is_online);
				if(ret < 0) {
					return -1;
				}
				if(relay_is_online) {
					ret = verify_relay_online("[MAIN THREAD]", ci_info, index, ENABLE_HISTORY, VERIFY_USING_RETURN_KEY_UID_PAIR, &relay_is_online);
					if(ret < 0) {
						return -1;
					}
					if(relay_is_online) {
						ci_info->ri_pool[index].is_responsive = 1;
					} else {
						ci_info->ri_pool[index].is_responsive = 0;
					}
				} else {
					ci_info->ri_pool[index].is_responsive = 0;
				}
				if(ci_info->ri_pool[index].is_responsive == 0) {
					ci_info->ri_pool[index].is_responsive = 0;
					ret = reconnect_to_entry_relay_via_key_history(thread_id, ci_info, APPLY_RETURN_KEY_HISTORY, &entry_relay_online);
					if(ret < 0) {
						return -1;
					}
					if(entry_relay_online == 0) {
						return 0;
					}
				}
				index_of_relays_used[index] = 1;
				num_checked++;
			}
		}
	}

	return 0;
}

static int verify_entry_relay_online(char *thread_id, conversation_info *ci_info, history_type h_type, verification_type v_type, int *entry_relay_online)
{
	int ret;
	route_info r_info;
	payload_data check_relay_payload;

	if((ci_info == NULL) || (entry_relay_online == NULL)) {
		return -1;
	}

	wait_for_send_queue_empty(thread_id);

	r_info.route_length = 1;
	r_info.relay_route[0] = ci_info->index_of_entry_relay;

	if(h_type == ENABLE_HISTORY) {
		commit_key_info_to_history(ci_info);
		commit_route_info_to_history(DUMMY_PACKET, ci_info, &r_info, NULL, NULL);
	}

	ret = fill_buf_with_random_data((unsigned char *)&check_relay_payload, sizeof(check_relay_payload));
	if(ret < 0) {
		return -1;
	}
	generate_payload_metadata_for_entry_relay(thread_id, g_client_ip_addr, &check_relay_payload);

	initialize_entry_relay_verification_command(&check_relay_payload);	

	if(v_type == VERIFY_USING_FORWARD_KEY_UID_PAIR) {
		ret = send_packet(DUMMY_PACKET, ci_info, &r_info, &check_relay_payload, NULL);
		if(ret < 0) {
			return -1;
		}
	} else {
		ret = send_packet(DUMMY_PACKET_USING_RETURN_ROUTE_KEY_UID_PAIRS, ci_info, &r_info, &check_relay_payload, NULL);
		if(ret < 0) {
			return -1;
		}
	}

	ret = wait_for_command_completion(MAX_CHECK_NODE_TIME_SEC, entry_relay_online);
	if(ret < 0) {
		return -1;
	}

	#ifdef ENABLE_LOGGING
		if(*entry_relay_online) {
			fprintf(stdout, "%s Found entry relay (index = %d, ip = %s) is online, using verification type = %s\n", 
				thread_id, ci_info->index_of_entry_relay, ci_info->ri_pool[ci_info->index_of_entry_relay].relay_ip, get_verification_type_str(v_type));
		} else {
			fprintf(stdout, "%s Found entry relay (index = %d, ip = %s) is offline, using verification type = %s\n", 
				thread_id, ci_info->index_of_entry_relay, ci_info->ri_pool[ci_info->index_of_entry_relay].relay_ip, get_verification_type_str(v_type));
		}
	#endif

	return 0;
}

static int verify_relay_online(char *thread_id, conversation_info *ci_info, int relay_index, history_type h_type, verification_type v_type, int *relay_is_online)
{
	int ret, is_active;
	route_info r_info, return_r_info;
	payload_data check_relay_payload;

	if((ci_info == NULL) || (relay_is_online == NULL)) {
		return -1;
	}
	if((relay_index < 0) || (relay_index > MAX_ROUTE_LENGTH)) {
		return -1;	
	}
	*relay_is_online = 0;

	is_active = ci_info->ri_pool[relay_index].is_active;
	if(is_active == 0) {
		return -1;
	}
	if(ci_info->index_of_entry_relay == relay_index) {
		ret = verify_entry_relay_online(thread_id, ci_info, h_type, VERIFY_USING_FORWARD_KEY_UID_PAIR, relay_is_online);
		if(*relay_is_online == 0) {
			return ret;
		} else {
			ret = verify_entry_relay_online(thread_id, ci_info, h_type, VERIFY_USING_RETURN_KEY_UID_PAIR, relay_is_online);
		}
		return ret;
	}

	wait_for_send_queue_empty(thread_id);

	r_info.route_length = 2;
	r_info.relay_route[0] = ci_info->index_of_entry_relay;
	r_info.relay_route[1] = relay_index;

	return_r_info.route_length = 1;
	return_r_info.relay_route[0] = ci_info->index_of_entry_relay;

	if(h_type == ENABLE_HISTORY) {
		commit_key_info_to_history(ci_info);
		commit_route_info_to_history(DUMMY_PACKET, ci_info, &r_info, &return_r_info, NULL);
	}
	
	ret = fill_buf_with_random_data((unsigned char *)&check_relay_payload, sizeof(check_relay_payload));
	if(ret < 0) {
		return -1;
	}
	ret = initialize_relay_verification_command(&check_relay_payload);
	if(ret < 0) {
		return -1;
	}
	ret = generate_return_onion_route_data_from_route_info(ci_info, &return_r_info, check_relay_payload.payload);
	if(ret < 0) {
		return -1;
	}
	ret = generate_return_onion_route_payload_from_route_info(ci_info, &return_r_info, check_relay_payload.payload);
	if(ret < 0) {
		return -1;
	}
	ret = generate_packet_metadata(ci_info, DUMMY_PACKET_W_RETURN_ROUTE, &return_r_info, &check_relay_payload);
	if(ret < 0) {
		return -1;
	}

	if(v_type == VERIFY_USING_FORWARD_KEY_UID_PAIR) {
		ret = send_packet(DUMMY_PACKET, ci_info, &r_info, &check_relay_payload, NULL);
		if(ret < 0) {
			return -1;
		}
	} else {
		ret = send_packet(DUMMY_PACKET_USING_RETURN_ROUTE_KEY_UID_PAIRS_FOR_VERIFICATION, ci_info, &r_info, &check_relay_payload, NULL);
		if(ret < 0) {
			return -1;
		}
	}

	ret = wait_for_command_completion(MAX_CHECK_NODE_TIME_SEC, relay_is_online);
	if(ret < 0) {
		return -1;
	}

	#ifdef ENABLE_LOGGING
		if(*relay_is_online) {
			fprintf(stdout, "%s Found relay (index = %d, ip = %s) is online, using verification type = %s\n", thread_id, relay_index, ci_info->ri_pool[relay_index].relay_ip, get_verification_type_str(v_type));
		} else {
			fprintf(stdout, "%s Found relay (index = %d, ip = %s) is offline, using verification type = %s\n", thread_id, relay_index, ci_info->ri_pool[relay_index].relay_ip, get_verification_type_str(v_type));
		}
	#endif

	return 0;
}

static int send_dummy_packet_no_return_route(conversation_info *ci_info)
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

	commit_key_info_to_history(ci_info);
	commit_route_info_to_history(DUMMY_PACKET, ci_info, &r_info, NULL, NULL);

	ret = fill_buf_with_random_data((unsigned char *)&dummy_packet_payload, sizeof(dummy_packet_payload));
	if(ret < 0) {
		return -1;
	}
	ret = generate_packet_metadata(ci_info, DUMMY_PACKET_NO_RETURN_ROUTE, NULL, &dummy_packet_payload);
	if(ret < 0) {
		return -1;
	}
	
	ret = send_packet(DUMMY_PACKET, ci_info, &r_info, &dummy_packet_payload, NULL);
	if(ret < 0) {
		return -1;
	}

	return 0;
}

static int send_dummy_packet_with_return_route(conversation_info *ci_info)
{
	int ret;
	route_info r_info, return_r_info;
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

	ret = generate_random_return_route(ci_info, &r_info, &return_r_info);
	if(ret < 0) {
		return -1;
	}
	#ifdef ENABLE_LOGGING
		fprintf(stdout, "[MAIN THREAD] Return route length = %u\n", return_r_info.route_length);
		for (i = 0; i < return_r_info.route_length; i++) {
			fprintf(stdout, "[MAIN THREAD] Return route %u, index = %u, ip = %s\n", (i + 1), return_r_info.relay_route[i], ci_info->ri_pool[return_r_info.relay_route[i]].relay_ip);
		}
		fprintf(stdout, "[MAIN THREAD] Return route %u, index = none, ip = %s\n", (i + 1), g_client_ip_addr);
	#endif

	commit_key_info_to_history(ci_info);
	commit_route_info_to_history(DUMMY_PACKET, ci_info, &r_info, &return_r_info, NULL);
	
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
	ret = generate_packet_metadata(ci_info, DUMMY_PACKET_W_RETURN_ROUTE, &return_r_info, &dummy_packet_payload);
	if(ret < 0) {
		return -1;
	}

	ret = send_packet(DUMMY_PACKET, ci_info, &r_info, &dummy_packet_payload, NULL);
	if(ret < 0) {
		return -1;
	}

	return 0;
}

static int send_dummy_packet_with_routes_defined(conversation_info *ci_info, route_info *r_info, route_info *return_r_info)
{
	int ret;
	payload_data dummy_packet_payload;

	if((ci_info == NULL) || (r_info == NULL) || (return_r_info == NULL)) {
		return -1;
	}

	commit_key_info_to_history(ci_info);
	commit_route_info_to_history(DUMMY_PACKET, ci_info, r_info, return_r_info, NULL);
	
	ret = fill_buf_with_random_data((unsigned char *)&dummy_packet_payload, sizeof(dummy_packet_payload));
	if(ret < 0) {
		return -1;
	}
	ret = generate_return_onion_route_data_from_route_info(ci_info, return_r_info, dummy_packet_payload.payload);
	if(ret < 0) {
		return -1;
	}
	ret = generate_return_onion_route_payload_from_route_info(ci_info, return_r_info, dummy_packet_payload.payload);
	if(ret < 0) {
		return -1;
	}
	ret = generate_packet_metadata(ci_info, DUMMY_PACKET_W_RETURN_ROUTE, return_r_info, &dummy_packet_payload);
	if(ret < 0) {
		return -1;
	}

	ret = send_packet(DUMMY_PACKET, ci_info, r_info, &dummy_packet_payload, NULL);
	if(ret < 0) {
		return -1;
	}

	return 0;
}

static int generate_packet_metadata(conversation_info *ci_info, payload_type p_type, route_info *return_r_info, payload_data *payload)
{
	uint64_t ip_first_return_relay;

	if((ci_info == NULL) || (payload == NULL)) {
		return -1;
	}

	switch(p_type) {
		case DUMMY_PACKET_NO_RETURN_ROUTE:
			payload->type = DUMMY_PACKET_NO_RETURN_ROUTE;
		break;
		case DUMMY_PACKET_W_RETURN_ROUTE:
			if(return_r_info == NULL) {
				return -1;
			}
			payload->type = DUMMY_PACKET_W_RETURN_ROUTE;
			payload->onion_r1 = ci_info->ri_pool[return_r_info->relay_route[0]].relay_port;
			inet_aton(ci_info->ri_pool[return_r_info->relay_route[0]].relay_ip, (struct in_addr *)&ip_first_return_relay);
			payload->client_id = (uint32_t)((ip_first_return_relay >> 32) & 0xFFFFFFFF);
			payload->conversation_id = (uint32_t)(ip_first_return_relay & 0xFFFFFFFF);
		break;
		case SINGLE_RETURN_ROUTE:
			payload->type = SINGLE_RETURN_ROUTE;
			// TODO
		break;
		case DUAL_RETURN_ROUTE:
			payload->type = DUAL_RETURN_ROUTE;
			// TODO
		break;
		case MESSAGE_PACKET:
			payload->type = MESSAGE_PACKET;
			// TODO
		break;
	}

	return 0;
}

static int send_packet(packet_type type, conversation_info *ci_info, route_info *r_info, payload_data *payload, void *other)
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

	ret = place_packet_on_send_queue(packet_buf, destination_ip, destination_port);
	if(ret < 0) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Failed to place packet on send queue\n");
		#endif

		return -1;
	}

	return 0;
}

static int create_packet(packet_type type, conversation_info *ci_info, route_info *r_info, payload_data *payload, void *other, unsigned char *packet, char *destination_ip, int *destination_port)
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
			*destination_port = (ci_info->ri_pool[ci_info->index_of_entry_relay].relay_port + 1);

			memcpy(ic_data.aes_key, ci_info->ri_pool[ci_info->index_of_entry_relay].current_key_info.aes_key, AES_KEY_SIZE_BYTES);
			ic_data.relay_user_id = ci_info->ri_pool[ci_info->index_of_entry_relay].current_key_info.relay_user_id;	
			memcpy(ic_data.payload_aes_key, ci_info->ri_pool[ci_info->index_of_entry_relay].current_key_info.payload_aes_key, AES_KEY_SIZE_BYTES);
			ic_data.payload_relay_user_id = ci_info->ri_pool[ci_info->index_of_entry_relay].current_key_info.payload_relay_user_id;
			memcpy(ic_data.return_route_aes_key, ci_info->ri_pool[ci_info->index_of_entry_relay].current_key_info.return_route_aes_key, AES_KEY_SIZE_BYTES);
			ic_data.return_route_user_id = ci_info->ri_pool[ci_info->index_of_entry_relay].current_key_info.return_route_user_id;
			memcpy(ic_data.return_route_payload_aes_key, ci_info->ri_pool[ci_info->index_of_entry_relay].current_key_info.return_route_payload_aes_key, AES_KEY_SIZE_BYTES);
			ic_data.return_route_payload_user_id = ci_info->ri_pool[ci_info->index_of_entry_relay].current_key_info.return_route_payload_user_id;
			
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
			*destination_port = ci_info->ri_pool[ci_info->index_of_entry_relay].relay_port;

			generate_AES_key((unsigned char *)or_data[0].iv, AES_KEY_SIZE_BYTES);
			or_data[0].uid = ci_info->ri_pool[ci_info->index_of_entry_relay].current_key_info.relay_user_id;
			generate_new_user_id(ci_info->ri_pool[ci_info->index_of_entry_relay].max_uid, &(or_data[0].ord_enc.new_uid));
			generate_AES_key((unsigned char *)or_data[0].ord_enc.new_key, AES_KEY_SIZE_BYTES);
			inet_aton(ci_info->ri_pool[relay_register_index].relay_ip, (struct in_addr *)&(or_data[0].ord_enc.next_pkg_ip));
			or_data[0].ord_enc.next_pkg_port = (ci_info->ri_pool[relay_register_index].relay_port + 1);

			or_data[0].ord_enc.ord_checksum = 0;
			get_ord_packet_checksum(&(or_data[0].ord_enc), &(or_data[0].ord_enc.ord_checksum));

			ret = aes_encrypt_block("[MAIN THREAD]", (unsigned char *)&(or_data[0].ord_enc), sizeof(onion_route_data_encrypted), 
										ci_info->ri_pool[ci_info->index_of_entry_relay].current_key_info.aes_key, AES_KEY_SIZE_BYTES, (unsigned char *)&(or_data[0].iv), (packet + cipher_text_byte_offset));
			if(ret < 0) {
				return -1;
			}
			memcpy(packet, &(or_data[0]), cipher_text_byte_offset);

			generate_AES_key((unsigned char *)or_payload_data[0].iv, AES_KEY_SIZE_BYTES);
			or_payload_data[0].uid = ci_info->ri_pool[ci_info->index_of_entry_relay].current_key_info.payload_relay_user_id;
			generate_new_user_id(ci_info->ri_pool[ci_info->index_of_entry_relay].max_uid, &(or_payload_data[0].ord_enc.new_uid));
			generate_AES_key((unsigned char *)or_payload_data[0].ord_enc.new_key, AES_KEY_SIZE_BYTES);

			or_payload_data[0].ord_enc.ord_checksum = 0;
			get_ord_packet_checksum(&(or_payload_data[0].ord_enc), &(or_payload_data[0].ord_enc.ord_checksum));

			memcpy(encrypt_buffer, &(or_payload_data[0]), sizeof(onion_route_data));
			memcpy(ic_data.aes_key, ci_info->ri_pool[relay_register_index].current_key_info.aes_key, AES_KEY_SIZE_BYTES);
			ic_data.relay_user_id = ci_info->ri_pool[relay_register_index].current_key_info.relay_user_id;	
			memcpy(ic_data.payload_aes_key, ci_info->ri_pool[relay_register_index].current_key_info.payload_aes_key, AES_KEY_SIZE_BYTES);
			ic_data.payload_relay_user_id = ci_info->ri_pool[relay_register_index].current_key_info.payload_relay_user_id;
			memcpy(ic_data.return_route_aes_key, ci_info->ri_pool[relay_register_index].current_key_info.return_route_aes_key, AES_KEY_SIZE_BYTES);
			ic_data.return_route_user_id = ci_info->ri_pool[relay_register_index].current_key_info.return_route_user_id;
			memcpy(ic_data.return_route_payload_aes_key, ci_info->ri_pool[relay_register_index].current_key_info.return_route_payload_aes_key, AES_KEY_SIZE_BYTES);
			ic_data.return_route_payload_user_id = ci_info->ri_pool[relay_register_index].current_key_info.return_route_payload_user_id;
			
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
										ci_info->ri_pool[ci_info->index_of_entry_relay].current_key_info.payload_aes_key, AES_KEY_SIZE_BYTES, (unsigned char *)&(or_payload_data[0].iv), 
											(packet + payload_start_byte + cipher_text_byte_offset));
			if(ret < 0) {
				return -1;
			}

			ci_info->ri_pool[ci_info->index_of_entry_relay].current_key_info.relay_user_id = or_data[0].ord_enc.new_uid;
			memcpy(ci_info->ri_pool[ci_info->index_of_entry_relay].current_key_info.aes_key, or_data[0].ord_enc.new_key, AES_KEY_SIZE_BYTES);
			ci_info->ri_pool[ci_info->index_of_entry_relay].current_key_info.payload_relay_user_id = or_payload_data[0].ord_enc.new_uid;
			memcpy(ci_info->ri_pool[ci_info->index_of_entry_relay].current_key_info.payload_aes_key, or_payload_data[0].ord_enc.new_key, AES_KEY_SIZE_BYTES);

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
			*destination_port = ci_info->ri_pool[first_relay_index].relay_port;

			ret = generate_onion_route_data_from_route_info(ci_info, r_info, packet);
			if(ret < 0) {
				return -1;
			}
			ret = generate_onion_route_payload_from_route_info(ci_info, r_info, payload, packet);
			if(ret < 0) {
				return -1;
			}
		break;
		case DUMMY_PACKET_USING_RETURN_ROUTE_KEY_UID_PAIRS:
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
			*destination_port = ci_info->ri_pool[first_relay_index].relay_port;

			ret = generate_onion_route_data_from_route_info_using_rr_pairs(ci_info, r_info, packet);
			if(ret < 0) {
				return -1;
			}
			ret = generate_onion_route_payload_from_route_info_using_rr_pairs(ci_info, r_info, payload, packet);
			if(ret < 0) {
				return -1;
			}
		break;
		case DUMMY_PACKET_USING_RETURN_ROUTE_KEY_UID_PAIRS_FOR_VERIFICATION:
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
			*destination_port = ci_info->ri_pool[first_relay_index].relay_port;

			ret = generate_onion_route_data_from_route_info_verify_using_rr_pairs(ci_info, r_info, packet);
			if(ret < 0) {
				return -1;
			}
			ret = generate_onion_route_payload_from_route_info_verify_using_rr_pairs(ci_info, r_info, payload, packet);
			if(ret < 0) {
				return -1;
			}
		break;
	}

	return 0;
}

static int generate_onion_route_data_from_route_info(conversation_info *ci_info, route_info *r_info, unsigned char *packet)
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
		or_data[i].uid = ci_info->ri_pool[route_index].current_key_info.relay_user_id;
		generate_new_user_id(ci_info->ri_pool[route_index].max_uid, &(or_data[i].ord_enc.new_uid));
		generate_AES_key((unsigned char *)or_data[i].ord_enc.new_key, AES_KEY_SIZE_BYTES);
		if(previous_route_index < 0) {
			or_data[i].ord_enc.next_pkg_ip = 0;
			or_data[i].ord_enc.next_pkg_port = 0;
		} else {
			inet_aton(ci_info->ri_pool[previous_route_index].relay_ip, (struct in_addr *)&(or_data[i].ord_enc.next_pkg_ip));
			or_data[i].ord_enc.next_pkg_port = ci_info->ri_pool[previous_route_index].relay_port;
		}

		or_data[i].ord_enc.ord_checksum = 0;
		get_ord_packet_checksum(&(or_data[i].ord_enc), &(or_data[i].ord_enc.ord_checksum));

		memcpy((packet + or_offset), &(or_data[i]), cipher_text_byte_offset);
		memcpy((encrypt_buffer + or_offset), &(or_data[i]), sizeof(onion_route_data));
		ret = aes_encrypt_block("[MAIN THREAD]", (encrypt_buffer + or_offset + cipher_text_byte_offset), (payload_start_byte - or_offset - cipher_text_byte_offset), 
									ci_info->ri_pool[route_index].current_key_info.aes_key, AES_KEY_SIZE_BYTES, (unsigned char *)&(or_data[i].iv), (packet + or_offset + cipher_text_byte_offset));
		if(ret < 0) {
			return -1;
		}
		ci_info->ri_pool[route_index].current_key_info.relay_user_id = or_data[i].ord_enc.new_uid;
		memcpy(ci_info->ri_pool[route_index].current_key_info.aes_key, or_data[i].ord_enc.new_key, AES_KEY_SIZE_BYTES);
		memcpy((encrypt_buffer + or_offset + cipher_text_byte_offset), (packet + or_offset + cipher_text_byte_offset), (payload_start_byte - or_offset - cipher_text_byte_offset));

		previous_route_index = route_index;
		or_offset -= sizeof(onion_route_data);
	}

	return 0;
}

static int generate_onion_route_payload_from_route_info(conversation_info *ci_info, route_info *r_info, payload_data *payload, unsigned char *packet /* out */)
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
		or_data[i].uid = ci_info->ri_pool[route_index].current_key_info.payload_relay_user_id;
		generate_new_user_id(ci_info->ri_pool[route_index].max_uid, &(or_data[i].ord_enc.new_uid));
		generate_AES_key((unsigned char *)or_data[i].ord_enc.new_key, AES_KEY_SIZE_BYTES);

		or_data[i].ord_enc.ord_checksum = 0;
		get_ord_packet_checksum(&(or_data[i].ord_enc), &(or_data[i].ord_enc.ord_checksum));

		memcpy((packet + or_offset), &(or_data[i]), cipher_text_byte_offset);
		memcpy((encrypt_buffer + or_offset), &(or_data[i]), sizeof(onion_route_data));
		ret = aes_encrypt_block("[MAIN THREAD]", (encrypt_buffer + or_offset + cipher_text_byte_offset), (packet_size_bytes - or_offset - cipher_text_byte_offset), 
									ci_info->ri_pool[route_index].current_key_info.payload_aes_key, AES_KEY_SIZE_BYTES, (unsigned char *)&(or_data[i].iv), (packet + or_offset + cipher_text_byte_offset));
		if(ret < 0) {
			return -1;
		}
		ci_info->ri_pool[route_index].current_key_info.payload_relay_user_id = or_data[i].ord_enc.new_uid;
		memcpy(ci_info->ri_pool[route_index].current_key_info.payload_aes_key, or_data[i].ord_enc.new_key, AES_KEY_SIZE_BYTES);
		memcpy((encrypt_buffer + or_offset + cipher_text_byte_offset), (packet + or_offset + cipher_text_byte_offset), (packet_size_bytes - or_offset - cipher_text_byte_offset));

		or_offset -= sizeof(onion_route_data);
	}

	return 0;
}

static int generate_onion_route_data_from_route_info_using_rr_pairs(conversation_info *ci_info, route_info *r_info, unsigned char *packet)
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
		or_data[i].uid = ci_info->ri_pool[route_index].current_key_info.return_route_user_id;
		generate_new_user_id(ci_info->ri_pool[route_index].max_uid, &(or_data[i].ord_enc.new_uid));
		generate_AES_key((unsigned char *)or_data[i].ord_enc.new_key, AES_KEY_SIZE_BYTES);
		
		if(previous_route_index < 0) {
			or_data[i].ord_enc.next_pkg_ip = 0;
			or_data[i].ord_enc.next_pkg_port = 0;
		} else {
			inet_aton(ci_info->ri_pool[previous_route_index].relay_ip, (struct in_addr *)&(or_data[i].ord_enc.next_pkg_ip));
			or_data[i].ord_enc.next_pkg_port = ci_info->ri_pool[previous_route_index].relay_port;
		}

		or_data[i].ord_enc.ord_checksum = 0;
		get_ord_packet_checksum(&(or_data[i].ord_enc), &(or_data[i].ord_enc.ord_checksum));

		memcpy((packet + or_offset), &(or_data[i]), cipher_text_byte_offset);
		memcpy((encrypt_buffer + or_offset), &(or_data[i]), sizeof(onion_route_data));
		ret = aes_encrypt_block("[MAIN THREAD]", (encrypt_buffer + or_offset + cipher_text_byte_offset), (payload_start_byte - or_offset - cipher_text_byte_offset), 
									ci_info->ri_pool[route_index].current_key_info.return_route_aes_key, AES_KEY_SIZE_BYTES, (unsigned char *)&(or_data[i].iv), 
										(packet + or_offset + cipher_text_byte_offset));
		if(ret < 0) {
			return -1;
		}
		ci_info->ri_pool[route_index].current_key_info.return_route_user_id = or_data[i].ord_enc.new_uid;
		memcpy(ci_info->ri_pool[route_index].current_key_info.return_route_aes_key, or_data[i].ord_enc.new_key, AES_KEY_SIZE_BYTES);
		memcpy((encrypt_buffer + or_offset + cipher_text_byte_offset), (packet + or_offset + cipher_text_byte_offset), (payload_start_byte - or_offset - cipher_text_byte_offset));

		previous_route_index = route_index;
		or_offset -= sizeof(onion_route_data);
	}

	return 0;
}

static int generate_onion_route_payload_from_route_info_using_rr_pairs(conversation_info *ci_info, route_info *r_info, payload_data *payload, unsigned char *packet /* out */)
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
		or_data[i].uid = ci_info->ri_pool[route_index].current_key_info.return_route_payload_user_id;
		generate_new_user_id(ci_info->ri_pool[route_index].max_uid, &(or_data[i].ord_enc.new_uid));
		generate_AES_key((unsigned char *)or_data[i].ord_enc.new_key, AES_KEY_SIZE_BYTES);

		or_data[i].ord_enc.ord_checksum = 0;
		get_ord_packet_checksum(&(or_data[i].ord_enc), &(or_data[i].ord_enc.ord_checksum));

		memcpy((packet + or_offset), &(or_data[i]), cipher_text_byte_offset);
		memcpy((encrypt_buffer + or_offset), &(or_data[i]), sizeof(onion_route_data));
		ret = aes_encrypt_block("[MAIN THREAD]", (encrypt_buffer + or_offset + cipher_text_byte_offset), (packet_size_bytes - or_offset - cipher_text_byte_offset), 
									ci_info->ri_pool[route_index].current_key_info.return_route_payload_aes_key, AES_KEY_SIZE_BYTES, (unsigned char *)&(or_data[i].iv), 
										(packet + or_offset + cipher_text_byte_offset));
		if(ret < 0) {
			return -1;
		}
		ci_info->ri_pool[route_index].current_key_info.return_route_payload_user_id = or_data[i].ord_enc.new_uid;
		memcpy(ci_info->ri_pool[route_index].current_key_info.return_route_payload_aes_key, or_data[i].ord_enc.new_key, AES_KEY_SIZE_BYTES);
		memcpy((encrypt_buffer + or_offset + cipher_text_byte_offset), (packet + or_offset + cipher_text_byte_offset), (packet_size_bytes - or_offset - cipher_text_byte_offset));

		or_offset -= sizeof(onion_route_data);
	}

	return 0;
}

static int generate_onion_route_data_from_route_info_verify_using_rr_pairs(conversation_info *ci_info, route_info *r_info, unsigned char *packet)
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
		if(i != 0) {
			or_data[i].uid = ci_info->ri_pool[route_index].current_key_info.return_route_user_id;
		} else {
			or_data[i].uid = ci_info->ri_pool[route_index].current_key_info.relay_user_id;
		}
		generate_new_user_id(ci_info->ri_pool[route_index].max_uid, &(or_data[i].ord_enc.new_uid));
		generate_AES_key((unsigned char *)or_data[i].ord_enc.new_key, AES_KEY_SIZE_BYTES);
		if(previous_route_index < 0) {
			or_data[i].ord_enc.next_pkg_ip = 0;
			or_data[i].ord_enc.next_pkg_port = 0;
		} else {
			inet_aton(ci_info->ri_pool[previous_route_index].relay_ip, (struct in_addr *)&(or_data[i].ord_enc.next_pkg_ip));
			or_data[i].ord_enc.next_pkg_port = ci_info->ri_pool[previous_route_index].relay_port;
		}

		or_data[i].ord_enc.ord_checksum = 0;
		get_ord_packet_checksum(&(or_data[i].ord_enc), &(or_data[i].ord_enc.ord_checksum));

		memcpy((packet + or_offset), &(or_data[i]), cipher_text_byte_offset);
		memcpy((encrypt_buffer + or_offset), &(or_data[i]), sizeof(onion_route_data));
		if(i != 0) {
			ret = aes_encrypt_block("[MAIN THREAD]", (encrypt_buffer + or_offset + cipher_text_byte_offset), (payload_start_byte - or_offset - cipher_text_byte_offset), 
										ci_info->ri_pool[route_index].current_key_info.return_route_aes_key, AES_KEY_SIZE_BYTES, (unsigned char *)&(or_data[i].iv), 
											(packet + or_offset + cipher_text_byte_offset));
		} else {
			ret = aes_encrypt_block("[MAIN THREAD]", (encrypt_buffer + or_offset + cipher_text_byte_offset), (payload_start_byte - or_offset - cipher_text_byte_offset), 
										ci_info->ri_pool[route_index].current_key_info.aes_key, AES_KEY_SIZE_BYTES, (unsigned char *)&(or_data[i].iv), 
											(packet + or_offset + cipher_text_byte_offset));
		}
		
		if(ret < 0) {
			return -1;
		}
		if(i != 0) {
			ci_info->ri_pool[route_index].current_key_info.return_route_user_id = or_data[i].ord_enc.new_uid;
			memcpy(ci_info->ri_pool[route_index].current_key_info.return_route_aes_key, or_data[i].ord_enc.new_key, AES_KEY_SIZE_BYTES);
		} else {
			ci_info->ri_pool[route_index].current_key_info.relay_user_id = or_data[i].ord_enc.new_uid;
			memcpy(ci_info->ri_pool[route_index].current_key_info.aes_key, or_data[i].ord_enc.new_key, AES_KEY_SIZE_BYTES);
		}		

		memcpy((encrypt_buffer + or_offset + cipher_text_byte_offset), (packet + or_offset + cipher_text_byte_offset), (payload_start_byte - or_offset - cipher_text_byte_offset));

		previous_route_index = route_index;
		or_offset -= sizeof(onion_route_data);
	}

	return 0;
}

static int generate_onion_route_payload_from_route_info_verify_using_rr_pairs(conversation_info *ci_info, route_info *r_info, payload_data *payload, unsigned char *packet /* out */)
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
		if(i != 0) {
			or_data[i].uid = ci_info->ri_pool[route_index].current_key_info.return_route_payload_user_id;
		} else {
			or_data[i].uid = ci_info->ri_pool[route_index].current_key_info.payload_relay_user_id;
		}
		
		generate_new_user_id(ci_info->ri_pool[route_index].max_uid, &(or_data[i].ord_enc.new_uid));
		generate_AES_key((unsigned char *)or_data[i].ord_enc.new_key, AES_KEY_SIZE_BYTES);

		or_data[i].ord_enc.ord_checksum = 0;
		get_ord_packet_checksum(&(or_data[i].ord_enc), &(or_data[i].ord_enc.ord_checksum));

		memcpy((packet + or_offset), &(or_data[i]), cipher_text_byte_offset);
		memcpy((encrypt_buffer + or_offset), &(or_data[i]), sizeof(onion_route_data));
		if(i != 0) {
			ret = aes_encrypt_block("[MAIN THREAD]", (encrypt_buffer + or_offset + cipher_text_byte_offset), (packet_size_bytes - or_offset - cipher_text_byte_offset), 
									ci_info->ri_pool[route_index].current_key_info.return_route_payload_aes_key, AES_KEY_SIZE_BYTES, (unsigned char *)&(or_data[i].iv), 
										(packet + or_offset + cipher_text_byte_offset));
		} else {
			ret = aes_encrypt_block("[MAIN THREAD]", (encrypt_buffer + or_offset + cipher_text_byte_offset), (packet_size_bytes - or_offset - cipher_text_byte_offset), 
									ci_info->ri_pool[route_index].current_key_info.payload_aes_key, AES_KEY_SIZE_BYTES, (unsigned char *)&(or_data[i].iv), 
										(packet + or_offset + cipher_text_byte_offset));
		}
		
		if(ret < 0) {
			return -1;
		}
		if(i != 0) {
			ci_info->ri_pool[route_index].current_key_info.return_route_payload_user_id = or_data[i].ord_enc.new_uid;
			memcpy(ci_info->ri_pool[route_index].current_key_info.return_route_payload_aes_key, or_data[i].ord_enc.new_key, AES_KEY_SIZE_BYTES);	
		} else {
			ci_info->ri_pool[route_index].current_key_info.payload_relay_user_id = or_data[i].ord_enc.new_uid;
			memcpy(ci_info->ri_pool[route_index].current_key_info.payload_aes_key, or_data[i].ord_enc.new_key, AES_KEY_SIZE_BYTES);
		}
		
		memcpy((encrypt_buffer + or_offset + cipher_text_byte_offset), (packet + or_offset + cipher_text_byte_offset), (packet_size_bytes - or_offset - cipher_text_byte_offset));

		or_offset -= sizeof(onion_route_data);
	}

	return 0;
}

static int generate_return_onion_route_data_from_route_info(conversation_info *ci_info, route_info *return_r_info, unsigned char *packet)
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

	memcpy(encrypt_buffer, packet, PAYLOAD_SIZE_BYTES);
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
		or_data[i].uid = ci_info->ri_pool[route_index].current_key_info.return_route_user_id;
		generate_new_user_id(ci_info->ri_pool[route_index].max_uid, &(or_data[i].ord_enc.new_uid));
		generate_AES_key((unsigned char *)or_data[i].ord_enc.new_key, AES_KEY_SIZE_BYTES);
		if(previous_route_index < 0) {
			inet_aton(g_client_ip_addr, (struct in_addr *)&(or_data[i].ord_enc.next_pkg_ip));
			or_data[i].ord_enc.next_pkg_port = g_message_port;
		} else {
			inet_aton(ci_info->ri_pool[previous_route_index].relay_ip, (struct in_addr *)&(or_data[i].ord_enc.next_pkg_ip));
			or_data[i].ord_enc.next_pkg_port = ci_info->ri_pool[previous_route_index].relay_port;
		}

		or_data[i].ord_enc.ord_checksum = 0;
		get_ord_packet_checksum(&(or_data[i].ord_enc), &(or_data[i].ord_enc.ord_checksum));

		memcpy((packet + or_offset), &(or_data[i]), cipher_text_byte_offset);
		memcpy((encrypt_buffer + or_offset), &(or_data[i]), sizeof(onion_route_data));
		ret = aes_encrypt_block("[MAIN THREAD]", (encrypt_buffer + or_offset + cipher_text_byte_offset), (payload_start_byte - or_offset - cipher_text_byte_offset), 
									ci_info->ri_pool[route_index].current_key_info.return_route_aes_key, AES_KEY_SIZE_BYTES, (unsigned char *)&(or_data[i].iv), (packet + or_offset + cipher_text_byte_offset));
		if(ret < 0) {
			return -1;
		}
		ci_info->ri_pool[route_index].current_key_info.return_route_user_id = or_data[i].ord_enc.new_uid;
		memcpy(ci_info->ri_pool[route_index].current_key_info.return_route_aes_key, or_data[i].ord_enc.new_key, AES_KEY_SIZE_BYTES);
		memcpy((encrypt_buffer + or_offset + cipher_text_byte_offset), (packet + or_offset + cipher_text_byte_offset), (payload_start_byte - or_offset - cipher_text_byte_offset));

		previous_route_index = route_index;
		or_offset -= sizeof(onion_route_data);
	}

	return 0;
}

static int generate_return_onion_route_payload_from_route_info(conversation_info *ci_info, route_info *return_r_info, unsigned char *packet)
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

	memcpy(encrypt_buffer, packet, PAYLOAD_SIZE_BYTES);
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
		or_data[i].uid = ci_info->ri_pool[route_index].current_key_info.return_route_payload_user_id;
		generate_new_user_id(ci_info->ri_pool[route_index].max_uid, &(or_data[i].ord_enc.new_uid));
		generate_AES_key((unsigned char *)or_data[i].ord_enc.new_key, AES_KEY_SIZE_BYTES);
		or_data[i].ord_enc.next_pkg_port = ci_info->ri_pool[route_index].relay_port;

		or_data[i].ord_enc.ord_checksum = 0;
		get_ord_packet_checksum(&(or_data[i].ord_enc), &(or_data[i].ord_enc.ord_checksum));

		memcpy((packet + payload_start_byte + or_offset), &(or_data[i]), cipher_text_byte_offset);
		memcpy((encrypt_buffer + or_offset), &(or_data[i]), sizeof(onion_route_data));
		ret = aes_encrypt_block("[MAIN THREAD]", (encrypt_buffer + or_offset + cipher_text_byte_offset), (payload_start_byte - or_offset - cipher_text_byte_offset), 
									ci_info->ri_pool[route_index].current_key_info.return_route_payload_aes_key, AES_KEY_SIZE_BYTES, (unsigned char *)&(or_data[i].iv), 
										(packet + payload_start_byte + or_offset + cipher_text_byte_offset));
		if(ret < 0) {
			return -1;
		}
		ci_info->ri_pool[route_index].current_key_info.return_route_payload_user_id = or_data[i].ord_enc.new_uid;
		memcpy(ci_info->ri_pool[route_index].current_key_info.return_route_payload_aes_key, or_data[i].ord_enc.new_key, AES_KEY_SIZE_BYTES);
		memcpy((encrypt_buffer + or_offset + cipher_text_byte_offset), (packet + payload_start_byte + or_offset + cipher_text_byte_offset), (payload_start_byte - or_offset - cipher_text_byte_offset));

		or_offset -= sizeof(onion_route_data);
	}

	return 0;
}

static int place_packet_on_send_queue(unsigned char *packet, char *destination_ip, int destination_port)
{
	send_packet_node *sp, *sp_tmp;

	if((packet == NULL) || (destination_ip == NULL)) {
		return -1;
	}

	sem_wait(&g_sp_node_sem);
	
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

	if(g_sp_node == NULL) {
		g_sp_node = sp_tmp;
	} else {
		sp = g_sp_node;
		while(sp->next != NULL) {
			sp = sp->next;
		}
		sp->next = sp_tmp;
	}

	sem_post(&g_sp_node_sem);

	return 0;
}

static int commit_current_key_info_to_history(relay_info *r_info)
{
	if(r_info == NULL) {
		return -1;
	}

	if(r_info->kih_index >= PATH_HISTORY_LENGTH) {
		r_info->kih_index = 0;
	}
	memcpy((r_info->key_info_history + r_info->kih_index), &(r_info->current_key_info), sizeof(id_key_info));

	++(r_info->kih_index);
	if(r_info->kih_index >= PATH_HISTORY_LENGTH) {
		r_info->kih_index = 0;
	}

	return 0;
}

static int commit_key_info_to_history(conversation_info *ci_info)
{
	int i;

	if(ci_info == NULL) {
		return -1;
	}

	for (i = 0; i < RELAY_POOL_MAX_SIZE; ++i) {
		if(ci_info->ri_pool[i].is_active == 1) {
			commit_current_key_info_to_history(&(ci_info->ri_pool[i]));
		}
	}
	
	return 0;
}

__attribute__((unused)) static int print_key_history(relay_info *r_info)
{
	int curr_hist_index, hist_index, i;
	char buf[(AES_KEY_SIZE_BYTES*2)];

	if(r_info == NULL) {
		return -1;
	}

	curr_hist_index = (r_info->kih_index + 1);
	if (curr_hist_index >= PATH_HISTORY_LENGTH) {
		curr_hist_index = 0;
	}

	hist_index = 0;
	while(curr_hist_index != r_info->kih_index) {
		if(r_info->key_info_history[curr_hist_index].relay_user_id != 0) {
			fprintf(stdout, "Key History %d:\n", hist_index);
			for (i = 0; i < AES_KEY_SIZE_BYTES; i++) {
				sprintf((buf + (i*2)), "%02x", 0xff & r_info->key_info_history[curr_hist_index].aes_key[i]);
			}
			fprintf(stdout, "\tRelay Key = %s\n", buf);
			fprintf(stdout, "\tRelay User ID = %d\n", r_info->key_info_history[curr_hist_index].relay_user_id);

			hist_index++;
		}

		curr_hist_index++;
		if (curr_hist_index >= PATH_HISTORY_LENGTH) {
			curr_hist_index = 0;
		}
	}

	fprintf(stdout, "-----------------------------------------\n");

	return 0;
}

__attribute__((unused)) static int print_return_key_history(relay_info *r_info)
{
	int curr_hist_index, hist_index, i;
	char buf[(AES_KEY_SIZE_BYTES*2)];

	if(r_info == NULL) {
		return -1;
	}

	curr_hist_index = (r_info->kih_index + 1);
	if (curr_hist_index >= PATH_HISTORY_LENGTH) {
		curr_hist_index = 0;
	}

	hist_index = 0;
	while(curr_hist_index != r_info->kih_index) {
		if(r_info->key_info_history[curr_hist_index].relay_user_id != 0) {
			fprintf(stdout, "Return Route Key History %d:\n", hist_index);
			for (i = 0; i < AES_KEY_SIZE_BYTES; i++) {
				sprintf((buf + (i*2)), "%02x", 0xff & r_info->key_info_history[curr_hist_index].return_route_aes_key[i]);
			}
			fprintf(stdout, "\tReturn Route Relay Key = %s\n", buf);
			fprintf(stdout, "\tReturn Route Relay User ID = %d\n", r_info->key_info_history[curr_hist_index].return_route_user_id);

			hist_index++;
		}

		curr_hist_index++;
		if (curr_hist_index >= PATH_HISTORY_LENGTH) {
			curr_hist_index = 0;
		}
	}

	fprintf(stdout, "-----------------------------------------\n");

	return 0;
}

__attribute__((unused)) static int print_key_uid_pair(id_key_info *id_key_info_val)
{
	int i;

	if(id_key_info_val == NULL) {
		return -1;
	}

	fprintf(stdout, "UID: %d ", id_key_info_val->relay_user_id);
	fprintf(stdout, "Key: ");
	for (i = 0; i < AES_KEY_SIZE_BYTES; i++) {
		fprintf(stdout, "%02x", 0xff & id_key_info_val->aes_key[i]);
	}
	fprintf(stdout, "\n");

	return 0;
}

__attribute__((unused)) static int print_rr_key_uid_pair(id_key_info *id_key_info_val)
{
	int i;

	if(id_key_info_val == NULL) {
		return -1;
	}

	fprintf(stdout, "UID: %d ", id_key_info_val->return_route_user_id);
	fprintf(stdout, "Key: ");
	for (i = 0; i < AES_KEY_SIZE_BYTES; i++) {
		fprintf(stdout, "%02x", 0xff & id_key_info_val->return_route_aes_key[i]);
	}
	fprintf(stdout, "\n");

	return 0;
}

static int commit_route_info_to_history(packet_type type, conversation_info *c_info, route_info *r_info, route_info *return_r_info, void *arg)
{
	int i, j;

	if(c_info == NULL) {
		return -1;
	}

	switch(type) {
		case REGISTER_UIDS_WITH_ENTRY_RELAY:
			if(g_rhistory.rh_index >= PATH_HISTORY_LENGTH) {
				g_rhistory.rh_index = 0;
			}
			g_rhistory.history[g_rhistory.rh_index].relay_route[0] = c_info->index_of_entry_relay;
			g_rhistory.history[g_rhistory.rh_index].route_length = 1;
			g_rhistory.rh_index++;			
		break;
		case REGISTER_UIDS_WITH_RELAY:
			if (arg == NULL) {
				return -1;
			}
			if(g_rhistory.rh_index >= PATH_HISTORY_LENGTH) {
				g_rhistory.rh_index = 0;
			}
			g_rhistory.history[g_rhistory.rh_index].relay_route[0] = c_info->index_of_entry_relay;
			g_rhistory.history[g_rhistory.rh_index].relay_route[1] = *((int *)arg);
			g_rhistory.history[g_rhistory.rh_index].route_length = 2;
			g_rhistory.rh_index++;
		break;
		case DUMMY_PACKET:
		case DUMMY_PACKET_USING_RETURN_ROUTE_KEY_UID_PAIRS:
		case DUMMY_PACKET_USING_RETURN_ROUTE_KEY_UID_PAIRS_FOR_VERIFICATION:
			if(r_info == NULL) {
				return -1;
			}
			if(g_rhistory.rh_index >= PATH_HISTORY_LENGTH) {
				g_rhistory.rh_index = 0;
			}
			j = 0;
			for(i = 0; i < r_info->route_length; ++i) {
				if(i >= MAX_ROUTE_LENGTH) {
					return -1;
				}
				g_rhistory.history[g_rhistory.rh_index].relay_route[j++] = r_info->relay_route[i];
			}
			if(return_r_info != NULL) {
				for(i = 0; i < return_r_info->route_length; ++i) {
					if(i >= MAX_ROUTE_LENGTH) {
						return -1;
					}
					g_rhistory.history[g_rhistory.rh_index].relay_route[j++] = return_r_info->relay_route[i];
				}	
			}
			g_rhistory.history[g_rhistory.rh_index].route_length = j;
			g_rhistory.rh_index++;
		break;
	}

	return 0;
}

__attribute__((unused)) static int print_route_info_history(void)
{
	int i;
	int hist_index, print_index;

	hist_index = g_rhistory.rh_index + 1;
	if(hist_index >= PATH_HISTORY_LENGTH) {
		hist_index = 0;
	}

	print_index = 0;
	while(hist_index != g_rhistory.rh_index) {
		if(g_rhistory.history[hist_index].route_length != 0) {
			fprintf(stdout, "Path history %d:", print_index++);
			for(i = 0; i < g_rhistory.history[hist_index].route_length; ++i) {
				if(i >= (MAX_ROUTE_LENGTH*2)) {
					return -1;
				}
				fprintf(stdout, " %d ", g_rhistory.history[hist_index].relay_route[i]);
			}
			fprintf(stdout, "\n");
		}

		hist_index++;
		if(hist_index >= PATH_HISTORY_LENGTH) {
			hist_index = 0;
		}		
	}

	return 0;
}

static int get_friend_id(char *friend_id)
{
	int i;
	char c;

	if(friend_id == NULL) {
		return -1;
	}

	#ifdef ENABLE_STANDARD_LOGGING
		fprintf(stdout, "Please enter friends user id: ");
		fflush(stdout);
	#endif

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

__attribute__((unused)) static int is_valid_ip(char *ip, int *valid /* out */)
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

__attribute__((unused)) static int print_conversation(char *thread_id, conversation_info *ci_info)
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
				sprintf((buf + (j*2)), "%02x", 0xff & ci_info->ri_pool[i].current_key_info.aes_key[j]);
			}
			fprintf(stdout, "%s Relay Key = %s\n", thread_id, buf);
			fprintf(stdout, "%s Relay User ID = %u\n", thread_id, ci_info->ri_pool[i].current_key_info.relay_user_id);

			for (j = 0; j < AES_KEY_SIZE_BYTES; j++) {
				sprintf((buf + (j*2)), "%02x", 0xff & ci_info->ri_pool[i].current_key_info.payload_aes_key[j]);
			}
			fprintf(stdout, "%s Payload Relay Key = %s\n", thread_id, buf);
			fprintf(stdout, "%s Payload Relay User ID = %u\n", thread_id, ci_info->ri_pool[i].current_key_info.payload_relay_user_id);

			for (j = 0; j < AES_KEY_SIZE_BYTES; j++) {
				sprintf((buf + (j*2)), "%02x", 0xff & ci_info->ri_pool[i].current_key_info.return_route_aes_key[j]);
			}
			fprintf(stdout, "%s Return Route Relay Key = %s\n", thread_id, buf);
			fprintf(stdout, "%s Return Route Relay User ID = %u\n", thread_id, ci_info->ri_pool[i].current_key_info.return_route_user_id);

			for (j = 0; j < AES_KEY_SIZE_BYTES; j++) {
				sprintf((buf + (j*2)), "%02x", 0xff & ci_info->ri_pool[i].current_key_info.return_route_payload_aes_key[j]);
			}
			fprintf(stdout, "%s Return Route Relay Key = %s\n", thread_id, buf);
			fprintf(stdout, "%s Return Route Relay User ID = %u\n", thread_id, ci_info->ri_pool[i].current_key_info.return_route_payload_user_id);
		}
	}
	fprintf(stdout, "%s ------------------------------------\n", thread_id);

	return 0;
}

__attribute__((unused)) static int print_route_pairs(char *thread_id, route_pair *r_pair, int route_pair_length)
{
	int i, j;

	if(r_pair == NULL) {
		return -1;
	}

	for (i = 0; i < route_pair_length; ++i) {
		if(r_pair[i].forward_route.route_length == 0) {
			break;
		}
		fprintf(stdout, "%s Forward route (%d): ", thread_id, i);
		for(j = 0; j < r_pair[i].forward_route.route_length; j++) {
			fprintf(stdout, "%d ", r_pair[i].forward_route.relay_route[j]);
			if(j >= MAX_ROUTE_LENGTH) {
				break;
			}
		}
		fprintf(stdout, "\n");
		if(r_pair[i].return_route.route_length == 0) {
			break;
		}
		fprintf(stdout, "%s Return route (%d): ", thread_id, i);
		for(j = 0; j < r_pair[i].return_route.route_length; j++) {
			fprintf(stdout, "%d ", r_pair[i].return_route.relay_route[j]);
			if(j >= MAX_ROUTE_LENGTH) {
				break;
			}
		}
		fprintf(stdout, "\n");
	}

	return 0;
}

__attribute__((unused)) static char* get_packet_type_str(packet_type type)
{
	switch(type) {
		case REGISTER_UIDS_WITH_ENTRY_RELAY:
			return "REGISTER_UIDS_WITH_ENTRY_RELAY";
		case REGISTER_UIDS_WITH_RELAY:
			return "REGISTER_UIDS_WITH_RELAY";
		case DUMMY_PACKET:
			return "DUMMY_PACKET";
		case DUMMY_PACKET_USING_RETURN_ROUTE_KEY_UID_PAIRS:
			return "DUMMY_PACKET_USING_RETURN_ROUTE_KEY_UID_PAIRS";
		case DUMMY_PACKET_USING_RETURN_ROUTE_KEY_UID_PAIRS_FOR_VERIFICATION:
			return "DUMMY_PACKET_USING_RETURN_ROUTE_KEY_UID_PAIRS_FOR_VERIFICATION";
	}

	return "UNKNOWN";
}

__attribute__((unused)) static char* get_history_type_str(history_type h_type)
{
	switch(h_type) {
		case DISABLE_HISTORY:
			return "DISABLE_HISTORY";
		case ENABLE_HISTORY:
			return "ENABLE_HISTORY";
	}

	return "UNKNOWN";	
}

__attribute__((unused)) static char* get_verification_type_str(verification_type v_type)
{
	switch(v_type) {
		case VERIFY_USING_FORWARD_KEY_UID_PAIR:
			return "VERIFY_USING_FORWARD_KEY_UID_PAIR";
		case VERIFY_USING_RETURN_KEY_UID_PAIR:
			return "VERIFY_USING_RETURN_KEY_UID_PAIR";
	}

	return "UNKNOWN";	
}

__attribute__((unused)) static char get_send_packet_char(void)
{
	switch(g_curr_send_packet_char) {
		case '-':
			g_curr_send_packet_char = '\\';
		break;
		case '\\':
			g_curr_send_packet_char = '|';
		break;
		case '|':
			g_curr_send_packet_char = '/';
		break;
		case '/':
			g_curr_send_packet_char = '-';
		break;
		default:
			g_curr_send_packet_char = '-';
		break;
	}

	return g_curr_send_packet_char;
}

static void print_ret_code(char *thread_id, int ret)
{
	#ifdef ENABLE_LOGGING
		{
			fprintf(stdout, "%s Generic thread error\n", thread_id);
		}
	#endif
}

static void handle_pthread_ret(char *thread_id, int ret, int clientfd)
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

void logging_interrupt_handler(int dummy) 
{
	#ifdef ENABLE_UID_LOGGING
		save_uid_history_to_file();
	#endif

	exit(0); 
}

int save_uid_history_to_file(void) 
{
	int i, j, k;
	FILE *fp;

	fp = fopen("uid_history.log", "w");
	if(fp == NULL) {
		return -1;
	}

	for(i = 0; i < MAX_CONVERSATIONS; i++) {
		if(g_conversations[i].conversation_valid == 1) {
			fprintf(fp, "-------------- CONVERSATION %d --------------\n", i);
			for(j = 0; j < RELAY_POOL_MAX_SIZE; ++j) {
				if(g_conversations[i].ri_pool[j].is_active == 0) {
					continue;
				}
				if(j == g_conversations[i].index_of_entry_relay) {
					fprintf(fp, "-----> Entry relay: %d, ip: %s\n", j, g_conversations[i].ri_pool[j].relay_ip);
				} else {
					fprintf(fp, "-----> Relay %d, ip: %s\n", j, g_conversations[i].ri_pool[j].relay_ip);
				}
				fprintf(fp, "\t\tCurrent Forward UID: %d, Reverse UID: %d\n", g_conversations[i].ri_pool[j].current_key_info.relay_user_id, g_conversations[i].ri_pool[j].current_key_info.return_route_user_id);
				for (k = 0; k < PATH_HISTORY_LENGTH; ++k) {
					fprintf(fp, "\t\tForward UID: %d, Reverse UID: %d\n", g_conversations[i].ri_pool[j].key_info_history[k].relay_user_id, g_conversations[i].ri_pool[j].key_info_history[k].return_route_user_id);
				}
			}	
		}
	}
	fclose(fp);

	return 0;
}