#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <errno.h>

#include "relay.h"

#define ENABLE_LOGGING

int main(int argc, char const *argv[])
{
	unsigned int port;
	int ret, listening_socket, client_socket;
	int errno_cached;
	socklen_t sockaddr_len;
	struct sockaddr client_addr;

	if(argc != 2) {
		fprintf(stdout, "Usage: ./%s [PORT]\n", program_name);
		exit(-1);
	}

	#ifdef ENABLE_LOGGING
		fprintf(stdout, "%s program begin\n", program_name);
	#endif

	port = (unsigned int)atoi(argv[1]);
	if(port > PORT_MAX) {
		fprintf(stdout, "Port number (%u) must be less than %u\n", port, PORT_MAX);
		exit(-1);
	}

	ret = init_listening_socket(port, &listening_socket);
	if(ret < 0) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "Failed to initialize listening socket on port %u\n", port);
		#endif

		exit(-2);
	}

	#ifdef ENABLE_LOGGING
		fprintf(stdout, "%s listening on port=%u\n", program_name, port);
	#endif	

	while(1) {
		sockaddr_len = sizeof(client_addr);
		bzero((char *) &client_addr, sizeof(client_addr));
		client_socket = accept(listening_socket, &client_addr, &sockaddr_len);
		if(client_socket < 0) {
			errno_cached = errno;
			#ifdef ENABLE_LOGGING
				fprintf(stdout, "Failed to accept client connection, %s\n", strerror(errno_cached));
			#endif

			continue;
		}


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
			fprintf(stdout, "Failed to create stream socket");
		#endif

		return -1;
	}

	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(port);
	if (bind(*listening_socket, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "Error on binding");
		#endif

		return -1;
	}
	listen(*listening_socket, LISTEN_BACKLOG_MAX);	

	return 0;
}