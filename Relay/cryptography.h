#ifndef CRYPTOGRAPHY_HEADER
#define CRYPTOGRAPHY_HEADER

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <termios.h>
#include <ctype.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define RSA_PRIVATE_KEY_HASH_COUNT 	(3000000)

#define RELAY_RSA_PUBLIC_KEY_FILE 	("relay_public_rsa_key.pem")
#define RELAY_RSA_PRIVATE_KEY_FILE 	("relay_private_rsa_key.pem")

#define RSA_KEY_LENGTH 				(2048)
#define RSA_EXPONENT 				(65537)

int load_public_key(const char *thread_id, RSA **rsa_public_out /* out */);
int load_rsa_key_pair(const char *relay_id, RSA **rsa_out /* out */);
int save_key_pair_to_file(RSA *rsa_key_pair);
unsigned char* get_private_key_password_hash();
int generate_rsa_key_pair(const char *relay_id, RSA **rsa_out /* out */);
int cb(char *buf, int size, int rwflag, void *u);

#endif 