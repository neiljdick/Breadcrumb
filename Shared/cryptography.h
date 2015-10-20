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
#include <time.h>

#define RSA_PRIVATE_KEY_HASH_COUNT 	(3000000)

#define RELAY_RSA_PUBLIC_KEY_FILE 	("relay_public_rsa_key.pem")
#define RELAY_RSA_PRIVATE_KEY_FILE 	("relay_private_rsa_key.pem")

#define RSA_KEY_LENGTH 				(2048)
#define RSA_KEY_LENGTH_BYTES		(RSA_KEY_LENGTH/8)
#define RSA_EXPONENT 				(65537)

int load_public_key_into_buffer(const char *thread_id, char **rsa_public_out /* out */, int *public_key_buffer_len /* out */);
int load_rsa_key_pair(const char *relay_id, RSA **rsa_out /* out */);
int save_key_pair_to_file(RSA *rsa_key_pair);
unsigned char* get_private_key_password_hash();
int generate_rsa_key_pair(const char *relay_id, RSA **rsa_out /* out */);
int cb(char *buf, int size, int rwflag, void *u);
int get_hash_of_string(char *thread_id, int hash_count, const char *in_str, char **out_str /* out */, int *relay_id_len /* out */);
int get_pseudo_random_number(unsigned int initial_seed);
int generate_AES_key(unsigned char *seed, unsigned char *buf, int buf_len);

#endif 