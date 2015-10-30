#include "key_storage.h"

#define ENABLE_LOGGING
#define DEBUG_MODE

key *key_store = NULL;

unsigned int max_user_id, key_storage_size;

#ifdef DEBUG_MODE

int main(int argc, char const *argv[])
{
	unsigned long mem_free_bytes;
	int ret;

	fprintf(stdout, "DEBUG_MODE Begin\n");

	ret = get_free_mem_byte(&mem_free_bytes);
	if(ret < 0) {
		fprintf(stdout, "Failed to get free memory\n");

		return -1;
	}
	
	return 0;
}

#endif

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

int get_free_mem_byte(unsigned long *mem_free_bytes)
{
	int ret, i, j, k;
	FILE *fp;
	char line[256], *c_ptr;
	const char *memfree_str = "memfree";
	char free_bytes_buf[32], qualifier_buf[3];
	int found_free_bytes, prev_char_was_digit, found_qualifier;
	float multiplier;

	if(mem_free_bytes == NULL) {
		return -1;
	}

	fp = fopen(MEM_STAT_FILE, "r");
	if(fp == NULL) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "Failed to open memory statistics file, %s\n", MEM_STAT_FILE);
		#endif

		return -1;
	}

	while(1) {
		c_ptr = fgets(line, sizeof(line), fp);
		if(c_ptr == NULL) {
			fclose(fp);
			return -1;
		}
		ret = strncasecmp(memfree_str, (const char *)line, (sizeof(memfree_str) - 1));
		if(ret == 0) {
			break;
		}
	}

	memset(free_bytes_buf, 0, sizeof(free_bytes_buf));
	memset(qualifier_buf, 0, sizeof(qualifier_buf));
	found_free_bytes = prev_char_was_digit = 0;
	found_qualifier = 0;
	j = k = 0;
	for(i = 0; i < 256; i++) {
		if(line[i] == '\0')
			break;
		if(line[i] == '\n')
			break;

		if((found_free_bytes == 0) || (prev_char_was_digit == 1)) {
			if(isdigit(line[i]) != 0) {
				if(j >= (sizeof(free_bytes_buf) - 1)) {
					fclose(fp);
					return -1;
				}
				free_bytes_buf[j++] = line[i];
				found_free_bytes = 1;
				prev_char_was_digit = 1;
			} else {
				prev_char_was_digit = 0;
			}
		} else {
			if(found_free_bytes == 1) {
				if(isalpha(line[i]) != 0) {
					if(k >= (sizeof(qualifier_buf) - 1)) {
						fclose(fp);
						return -1;
					}
					qualifier_buf[k++] = line[i];
					found_qualifier = 1;
				}
			}
		}
	}

	if(found_free_bytes == 1) {
		switch(qualifier_buf[0]) {
			case 'k':
			case 'K':
				multiplier = (1.0/1024.0);
			break;
			case 'm':
			case 'M':
				multiplier = 1.0;
			break;
			case 'g':
			case 'G':
				multiplier = (1024.0);
			break;
			default:
				multiplier = (1.0/1024.0);
			break;
		}
		*mem_free_bytes = (unsigned long)(multiplier * (float)atol(free_bytes_buf));

		#ifdef ENABLE_LOGGING
			fprintf(stdout, "Found memory statistics: %lu MB\n", *mem_free_bytes);
		#endif

		fclose(fp);
		return 0;
	} else {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "Failed to parse memory statistics, found_free_bytes: %d, found_qualifier: %d\n", found_free_bytes, found_qualifier);
		#endif

		fclose(fp);
		return -1;
	}
}