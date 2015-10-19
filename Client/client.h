#ifndef CLIENT_HEADER
#define CLIENT_HEADER

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
#include <termios.h>
#include <ctype.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

char *program_name = "Client";

#define PORT_MAX 						(65534)
#define NUM_CERT_READ_ATTEMPTS 			(10)

#define CONVERSATION_NAME_MAX_LENGTH 	(128)
#define USER_NAME_MAX_LENGTH 			(128)
#define RELAY_POOL_MAX_SIZE				(20)
#define MAX_CONVERSATIONS				(32)
#define RELAY_IP_MAX_LENGTH				(16)

const char *public_cert_dir = ".relay_certs";

typedef struct relay_indexer_info
{
	char *ip_address;
	RSA public_cert;
} relay_indexer_info;

typedef struct relay_info
{
	int in_use;
	char relay_id[(SHA256_DIGEST_LENGTH * 2) + 1];
	char relay_ip[RELAY_IP_MAX_LENGTH];
	RSA *public_cert;
} relay_info;

typedef struct conversation_info
{
	int conversation_valid;
	char conversation_name[CONVERSATION_NAME_MAX_LENGTH];
	char friend_name[USER_NAME_MAX_LENGTH];
	int num_relays_active;
	relay_info ri_pool[RELAY_POOL_MAX_SIZE];	
} conversation_info;

int get_friend_id(char *friend_id /* out */);
int init_chat_metadata(char *friend_name, conversation_info *ci_out /* out */);
int get_relay_public_certificates_debug(relay_info *ri_pool);
int get_index_of_next_free_conversation(conversation_info *conversations);

#endif