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
#include <openssl/err.h>
#include <time.h>
#include <sys/time.h>

#include "key_storage.h"

#define RSA_PRIVATE_KEY_HASH_COUNT 	(3000000)

#define RELAY_RSA_PUBLIC_KEY_FILE 	("relay_public_rsa_key.pem")
#define RELAY_RSA_PRIVATE_KEY_FILE 	("relay_private_rsa_key.pem")

#define RSA_KEY_LENGTH 				(1024)
#define RSA_KEY_LENGTH_BYTES		(RSA_KEY_LENGTH/8)
#define RSA_EXPONENT 				(65537)

#define AES_128_KEY_BYTE_LEN 		(16)
#define AES_192_KEY_BYTE_LEN 		(24)
#define AES_256_KEY_BYTE_LEN 		(32)

int load_public_key_into_buffer(const char *thread_id, char **rsa_public_out /* out */, int *public_key_buffer_len /* out */);
int load_rsa_key_pair(const char *relay_id, RSA **rsa_out /* out */);
int save_key_pair_to_file(RSA *rsa_key_pair);
unsigned char* get_private_key_password_hash();
int generate_rsa_key_pair(const char *relay_id, RSA **rsa_out /* out */);
int cb(char *buf, int size, int rwflag, void *u);
int get_sha256_hash_of_string(char *thread_id, int hash_count, const char *in_str, char **out_str /* out */, int *out_str_len /* out */);
int get_random_number(unsigned int initial_seed);
int generate_AES_key(unsigned char *buf, int buf_len);
int aes_encrypt_block(char *thread_id, unsigned char *plaintext, int plaintext_len, unsigned char *key, int key_len, unsigned char *iv, unsigned char *cipher_text);
int aes_decrypt_block(char *thread_id, unsigned char *cipher_text, int cipher_text_len, unsigned char *key, int key_len, unsigned char *iv, unsigned char *plaintext /* out */);
int fill_buf_with_random_data(unsigned char *buf, int buf_len);

#endif 