#ifndef KEY_STORAGE_HEADER
#define KEY_STORAGE_HEADER

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

#define USER_ID_BITS 			(24)

#define AES_KEY_SIZE_BITS 		(128)
#define AES_KEY_SIZE_BYTES 		(AES_KEY_SIZE_BITS/8)

typedef struct key
{
	char value[AES_KEY_SIZE_BYTES];
} key;

int init_key_store(char *thread_id);
int free_key_store(char *thread_id);

int remove_key_from_key_store(char *thread_id, unsigned int user_id);
int set_key_for_user_id(char *thread_id, unsigned int user_id, key *key_in);
int get_key_for_user_id(char *thread_id, unsigned int user_id, key *key_out /* out */);

#endif