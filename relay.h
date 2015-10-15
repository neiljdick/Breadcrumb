#ifndef RELAY_HEADER
#define RELAY_HEADER

char *program_name = "Relay";

#define PORT_MAX 			(65535)

#define LISTEN_BACKLOG_MAX 	(50)

int init_listening_socket(unsigned int port, int *listening_socket /* out */);

#endif