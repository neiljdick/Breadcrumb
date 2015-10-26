#include "key_storage.h"

#define ENABLE_LOGGING

key *key_store = NULL;

unsigned int max_user_id, key_storage_size;

int init_key_store(char *thread_id)
{
	if(key_store != NULL) {
		return -1;
	}

	max_user_id = (((int)powf((float)2, (float)USER_ID_BITS)) - 1);
	key_storage_size = max_user_id + 1;

	key_store = calloc(key_storage_size, sizeof(key));
	if(key_store == NULL) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Failed to allocate memory for key storage\n", thread_id);
		#endif

		return -1;
	}

	#ifdef ENABLE_LOGGING
		fprintf(stdout, "%s Successfully initialized key storage\n", thread_id);
	#endif

	return 0;
}

int free_key_store(char *thread_id)
{
	if(key_store == NULL) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Key storage is already freed\n", thread_id);
		#endif

		return -1;
	}

	free(key_store);

	return 0;
}

int remove_key_from_key_store(char *thread_id, unsigned int user_id)
{
	if(key_store == NULL) {
		return -1;
	}

	if(user_id > max_user_id) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Failed to set key, user ID (%u) must be less than key storage size (%u)\n", thread_id, user_id, max_user_id);
		#endif

		return -1;
	}
	memset(&key_store[user_id], 0, AES_KEY_SIZE_BYTES);

	return 0;
}

int set_key_for_user_id(char *thread_id, unsigned int user_id, key *key_in)
{
	int i;

	if((key_in == NULL) || (key_store == NULL)) {
		return -1;
	}

	if(user_id > max_user_id) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Failed to set key, user ID (%u) must be less than key storage size (%u)\n", thread_id, user_id, max_user_id);
		#endif

		return -1;
	}

	for (i = 0; i < sizeof(key); i++) {
		if(key_store[user_id].value[i] != 0) {
			#ifdef ENABLE_LOGGING
				fprintf(stdout, "%s Failed to set key, key slot %u is not empty, key = ", thread_id, user_id);
				for(i = 0; i < AES_KEY_SIZE_BYTES; i++) {
					fprintf(stdout, "%02x", (0xff & key_in->value[i]));
				}
				fprintf(stdout, "\n");
			#endif

			return -1;
		}
	}
	memcpy(&key_store[user_id], key_in->value, AES_KEY_SIZE_BYTES);

	#ifdef ENABLE_LOGGING
		fprintf(stdout, "%s Successfully set key = ", thread_id);
		for(i = 0; i < AES_KEY_SIZE_BYTES; i++) {
			fprintf(stdout, "%02x", (0xff & key_in->value[i]));
		}
		fprintf(stdout, " for user = %u\n", user_id);
	#endif

	return 0;
}

int get_key_for_user_id(char *thread_id, unsigned int user_id, key *key_out /* out */)
{
	int i;

	if((key_out == NULL) || (key_store == NULL)) {
		return -1;
	}

	if(user_id > max_user_id) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Failed to get key, user ID (%u) must be less than key storage size (%u)\n", thread_id, user_id, max_user_id);
		#endif

		return -1;
	}
	memcpy(key_out, &key_store[user_id], AES_KEY_SIZE_BYTES);

	for (i = 0; i < AES_KEY_SIZE_BYTES; i++) {
		if(key_store[user_id].value[i] != 0)
			break;
	}
	if(i == AES_KEY_SIZE_BYTES) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Failed to get key, key for user ID (%u) is empty\n", thread_id, user_id);
		#endif

		return -1;
	}

	#ifdef ENABLE_LOGGING
		fprintf(stdout, "%s Successfully got key = ", thread_id);
		for(i = 0; i < AES_KEY_SIZE_BYTES; i++) {
			fprintf(stdout, "%02x", (0xff & key_out->value[i]));
		}
		fprintf(stdout, " for user = %u\n", user_id);
	#endif

	return 0;
}

int get_max_user_id(void)
{
	init_key_store("[MAIN THREAD]");

	return max_user_id;
}