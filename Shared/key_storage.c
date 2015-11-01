#include "key_storage.h"

#define ENABLE_LOGGING
#define DEBUG_MODE

key_entry *key_store = NULL;

unsigned int max_user_id, key_storage_size, num_keystore_clash_heaps;
unsigned long ram_available_for_keystore_mb;
int ks_fd[MAX_KEY_CLASH_PERMITTED];
char *curr_ks_clash_addr;
off_t pa_offset;

#ifdef DEBUG_MODE

int main(int argc, char const *argv[])
{
	unsigned long ram_free_mb;
	int ret;
	key debug_key;

	fprintf(stdout, "[DEBUG MODE] Begin\n");
	fprintf(stdout, "[DEBUG MODE] Size of key entry: %lu\n", sizeof(key_entry));

	init_key_store("[DEBUG MODE]");

	memset(debug_key.value, 0x30, AES_KEY_SIZE_BYTES);
	set_key_for_user_id("[DEBUG MODE]", 22045, &debug_key);
	memset(debug_key.value, 0x31, AES_KEY_SIZE_BYTES);
	set_key_for_user_id("[DEBUG MODE]", 22045, &debug_key);
	
	memset(debug_key.value, 0x32, AES_KEY_SIZE_BYTES);
	set_key_for_user_id("[DEBUG MODE]", 22046, &debug_key);
	memset(debug_key.value, 0x33, AES_KEY_SIZE_BYTES);
	set_key_for_user_id("[DEBUG MODE]", 22046, &debug_key);
	
	memset(debug_key.value, 0x34, AES_KEY_SIZE_BYTES);
	set_key_for_user_id("[DEBUG MODE]", 22047, &debug_key);
	memset(debug_key.value, 0x35, AES_KEY_SIZE_BYTES);
	set_key_for_user_id("[DEBUG MODE]", 22047, &debug_key);

	memset(debug_key.value, 0x36, AES_KEY_SIZE_BYTES);
	set_key_for_user_id("[DEBUG MODE]", 22048, &debug_key);
	memset(debug_key.value, 0x37, AES_KEY_SIZE_BYTES);
	set_key_for_user_id("[DEBUG MODE]", 22048, &debug_key);

	memset(debug_key.value, 0x38, AES_KEY_SIZE_BYTES);
	set_key_for_user_id("[DEBUG MODE]", 22049, &debug_key);
	memset(debug_key.value, 0x39, AES_KEY_SIZE_BYTES);
	set_key_for_user_id("[DEBUG MODE]", 22049, &debug_key);

	get_key_for_user_id("[DEBUG MODE]", 22045, -1, &debug_key);
	get_key_for_user_id("[DEBUG MODE]", 22045, 0, &debug_key);
	get_key_for_user_id("[DEBUG MODE]", 22046, -1, &debug_key);
	get_key_for_user_id("[DEBUG MODE]", 22046, 0, &debug_key);

	while(1) sleep(10);
	
	return 0;
}

#endif

int init_key_store(char *thread_id)
{
	int ret;

	if(key_store != NULL) {
		return -1;
	}

	ret = init_globals(thread_id);
	if(ret < 0) {
		return -1;
	}

	ret = init_key_storage_memory(thread_id);
	if(ret < 0) {
		return -1;
	}

	ret = reset_key_entry_ages(thread_id);
	if(ret < 0) {
		return -1;
	}

	#ifdef ENABLE_LOGGING
		fprintf(stdout, "%s Successfully initialized key storage\n", thread_id);
	#endif

	return 0;
}

int shutdown_key_store(char *thread_id)
{
	// TODO

	return 0;
} 

int init_globals(char *thread_id)
{
	int i;

	max_user_id = 0;
	key_storage_size = 0;
	ram_available_for_keystore_mb = 0;
	num_keystore_clash_heaps = 0;
	curr_ks_clash_addr = NULL;

	for (i = 0; i < MAX_KEY_CLASH_PERMITTED; ++i) {
		ks_fd[i] = -1;
	}

	return 0;
}

static int init_key_storage_memory(char *thread_id)
{
	const int empty_key_buf_size = 100;
	int ret, i, j;
	unsigned long ram_free_mb, max_num_keys_can_store;
	unsigned long disk_free_mb, disk_space_required_mb;
	unsigned int key_entry_size;
	float attempting_usage_ratio;
	char buf[64], empty_key_buf[sizeof(key_entry) * empty_key_buf_size];
	int num_empty_key_to_write;
	key_entry empty_key_entry;

	if(key_store != NULL) {
		return -1;
	}

	ret = get_free_ram_in_mb(thread_id, &ram_free_mb);
	if(ret < 0) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Unable to determine free RAM for initialization of key storage memory\n", thread_id);
		#endif

		ram_free_mb = DEFAULT_RAM_FREE_MB;
	}

	attempting_usage_ratio = 1.0;
	while(1) {
		ram_available_for_keystore_mb = (unsigned long)((float)ram_free_mb * (float)RAM_FOR_KEYSTORE_RATIO * (float)attempting_usage_ratio);
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Attempting to use %lu MB for key storage\n", thread_id, ram_available_for_keystore_mb);
		#endif

		max_user_id = (ram_available_for_keystore_mb * (1024*1024)) / ((unsigned long)sizeof(key_entry));
		max_user_id += 0x80;
		max_user_id &= (~((unsigned int)0xFF));

		key_store = calloc(max_user_id, sizeof(key_entry));
		if(key_store != NULL) {
			break;	
		}

		attempting_usage_ratio *= 0.9;
		if(attempting_usage_ratio < MIN_MEMORY_ATTEMPTING_USAGE_RATIO) {
			return -1;
		}
	}
	#ifdef ENABLE_LOGGING
		fprintf(stdout, "%s Successfully allocated key storage memory with a maximum user id = %u\n", thread_id, max_user_id);
	#endif

	ret = get_free_disk_space_in_mb(thread_id, &disk_free_mb);
	if(ret < 0) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Unable to determine free disk space for key storage clash memory\n", thread_id);
		#endif

		disk_free_mb = DEFAULT_DISK_FREE_MB;
	}
	disk_free_mb *= MAX_DISK_UTILIZATION_RATIO;

	num_keystore_clash_heaps = MAX_KEY_CLASH_PERMITTED;
	while((ram_available_for_keystore_mb * num_keystore_clash_heaps) > disk_free_mb) {
		num_keystore_clash_heaps--;
		if(num_keystore_clash_heaps == 0) {
			break;
		}
	}

	fprintf(stdout, "%s Initializing key store heaps", thread_id);
	fflush(stdout);
	sprintf(buf, "./%s", key_storage_dir);
	mkdir(buf, S_IRWXU | S_IRWXG);
	num_empty_key_to_write = (ram_available_for_keystore_mb * (1024*1024)) / sizeof(empty_key_buf);
	memset(&(empty_key_entry.p_key), 0, sizeof(key));
	empty_key_entry.age = -1;
	for (i = 0; i < empty_key_buf_size; ++i) {
		memcpy(empty_key_buf + (sizeof(key_entry) * i), &empty_key_entry, sizeof(key_entry));
	}
	for (i = 0; i < num_keystore_clash_heaps; ++i) {
		if(i >= MAX_KEY_CLASH_PERMITTED) {
			return -1;
		}

		sprintf(buf, "./%s/_chp.%u", key_storage_dir, i);
		ks_fd[i] = open(buf, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
		if(ks_fd[i] < 0) {
			free_key_store(thread_id);
			return -1;
		}

		for (j = 0; j < num_empty_key_to_write; ++j) {
			write(ks_fd[i], empty_key_buf, sizeof(empty_key_buf));
			if((j % 20000) == 0) {
				fsync(ks_fd[i]);
				fprintf(stdout, ".");
				fflush(stdout);
			}
		}
		fsync(ks_fd[i]);
	}
	fprintf(stdout, "done\n");
	
	return 0;
}

static int reset_key_entry_ages(char *thread_id)
{
	key_entry *ke_ptr;
	int i;
	#ifdef ENABLE_LOGGING
		struct timeval res, t1, t2;
		gettimeofday(&t1, NULL);
	#endif

	ke_ptr = (key_store);
	for (i = 0; i < max_user_id; i++) {
		ke_ptr->age = -1;
		ke_ptr++;
	}

	#ifdef ENABLE_LOGGING
		gettimeofday(&t2, NULL);
		timeval_subtract(&res, &t2, &t1);
		fprintf(stdout, "%s Time to complete key age reset task: %lu us\n", thread_id, res.tv_usec);
	#endif

	return 0;
}

static int handle_key_entry_age_increment(char *thread_id)
{
	key_entry *ke_ptr;
	int i;
	#ifdef ENABLE_LOGGING
		struct timeval res, t1, t2;
		gettimeofday(&t1, NULL);
	#endif

	ke_ptr = (key_store);
	for (i = 0; i < max_user_id; i++) {
		ke_ptr->age++;
		ke_ptr++;
	}

	#ifdef ENABLE_LOGGING
		gettimeofday(&t2, NULL);
		timeval_subtract(&res, &t2, &t1);
		fprintf(stdout, "%s Time to complete key age increment task: %lu us\n", thread_id, res.tv_usec);
	#endif

	return 0;
}

static int free_key_store(char *thread_id)
{
	if(key_store == NULL) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Key storage is already freed\n", thread_id);
		#endif

		return -1;
	}

	// TODO

	return 0;
}

int set_key_for_user_id(char *thread_id, unsigned int user_id, key *key_in)
{
	int i, j;
	key_entry *ke_ptr;
	#ifdef ENABLE_LOGGING
		struct timeval res, t1, t2;
		gettimeofday(&t1, NULL);
	#endif

	if((key_in == NULL) || (key_store == NULL)) {
		return -1;
	}

	if(user_id > max_user_id) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Failed to set key, user ID (%u) must be less than key storage size (%u)\n", thread_id, user_id, max_user_id);
		#endif

		return -1;
	}
	if(curr_ks_clash_addr != NULL) {
		munmap(curr_ks_clash_addr, sizeof(key_entry) + ((off_t)user_id * sizeof(key_entry)) - pa_offset);
	}

	ke_ptr = (key_store + user_id);
	if(ke_ptr->age < 0) {
		memcpy(&(ke_ptr->p_key), key_in, sizeof(key));
		ke_ptr->age = 0;
	} else {
		for(i = 0; i < num_keystore_clash_heaps; i++) {
			if(i > MAX_KEY_CLASH_PERMITTED) {
				return -1;
			}
			if(ks_fd[i] < 0) {
				continue;
			}

			pa_offset = ((off_t)user_id * sizeof(key_entry)) & ~(sysconf(_SC_PAGE_SIZE) - 1);
			curr_ks_clash_addr = mmap(NULL, sizeof(key_entry) + ((off_t)user_id * sizeof(key_entry)) - pa_offset, PROT_WRITE, MAP_SHARED, ks_fd[i], pa_offset);
    		if(curr_ks_clash_addr == MAP_FAILED) {
    			#ifdef ENABLE_LOGGING
					fprintf(stdout, "%s Failed to mmap key storage clash file (%u)\n", thread_id, i);
				#endif

				return -1;
    		}

    		ke_ptr = (key_entry *)(curr_ks_clash_addr + ((off_t)user_id * sizeof(key_entry)) - pa_offset);
    		if(ke_ptr->age < 0) {
    			memcpy(&(ke_ptr->p_key), key_in, sizeof(key));
				ke_ptr->age = 0;
    			munmap(curr_ks_clash_addr, sizeof(key_entry) + ((off_t)user_id * sizeof(key_entry)) - pa_offset);
    			curr_ks_clash_addr = NULL;

    			break;
    		} else {
    			#ifdef ENABLE_LOGGING
					for(j = 0; j < AES_KEY_SIZE_BYTES; j++) {
						fprintf(stdout, "%02x", (0xff & ke_ptr->p_key.value[j]));
					}
					fprintf(stdout, "\n");
				#endif
			}
    		munmap(curr_ks_clash_addr, sizeof(key_entry) + ((off_t)user_id * sizeof(key_entry)) - pa_offset);
    		curr_ks_clash_addr = NULL;
		}
		if(i >= num_keystore_clash_heaps) {
			return -1;
		}
	}

	#ifdef ENABLE_LOGGING
		gettimeofday(&t2, NULL);
		timeval_subtract(&res, &t2, &t1);
		fprintf(stdout, "%s Successfully set key = ", thread_id);
		for(i = 0; i < AES_KEY_SIZE_BYTES; i++) {
			fprintf(stdout, "%02x", (0xff & key_in->value[i]));
		}
		fprintf(stdout, " for user = %u. Time taken: %lu us\n", user_id, res.tv_usec);
	#endif

	return 0;
}

int get_key_for_user_id(char *thread_id, unsigned int user_id, int backup_index, key *key_out /* out */)
{
	int i;
	key_entry *ke_ptr;
	#ifdef ENABLE_LOGGING
		struct timeval res, t1, t2;
		gettimeofday(&t1, NULL);
	#endif

	if((key_out == NULL) || (key_store == NULL)) {
		return -1;
	}

	if(user_id > max_user_id) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Failed to set key, user ID (%u) must be less than key storage size (%u)\n", thread_id, user_id, max_user_id);
		#endif

		return -1;
	}
	if(backup_index >= (int)num_keystore_clash_heaps) {
		return -1;
	}
	if(curr_ks_clash_addr != NULL) {
		munmap(curr_ks_clash_addr, sizeof(key_entry) + ((off_t)user_id * sizeof(key_entry)) - pa_offset);
	}

	if(backup_index < 0) {
		ke_ptr = (key_store + user_id);
		if(ke_ptr->age < 0) {
			key_out = NULL;
		} else {
			memcpy(key_out, &(ke_ptr->p_key), sizeof(key));
		}
	} else {
		if(ks_fd[backup_index] < 0) {
			return -1;
		}

		pa_offset = ((off_t)user_id * sizeof(key_entry)) & ~(sysconf(_SC_PAGE_SIZE) - 1);
		curr_ks_clash_addr = mmap(NULL, sizeof(key_entry) + ((off_t)user_id * sizeof(key_entry)) - pa_offset, PROT_READ, MAP_SHARED, ks_fd[backup_index], pa_offset);
		if(curr_ks_clash_addr == MAP_FAILED) {
			#ifdef ENABLE_LOGGING
				fprintf(stdout, "%s Failed to mmap key storage clash file (%u)\n", thread_id, backup_index);
			#endif

			return -1;
		}

		ke_ptr = (key_entry *)(curr_ks_clash_addr + ((off_t)user_id * sizeof(key_entry)) - pa_offset);
		if(ke_ptr->age < 0) {
			key_out = NULL;
		} else {
			memcpy(key_out, &(ke_ptr->p_key), sizeof(key));
		}
	}

	#ifdef ENABLE_LOGGING
		gettimeofday(&t2, NULL);
		timeval_subtract(&res, &t2, &t1);
		fprintf(stdout, "%s Successfully got key = ", thread_id);
		if(key_out != NULL) {
			for(i = 0; i < AES_KEY_SIZE_BYTES; i++) {
				fprintf(stdout, "%02x", (0xff & key_out->value[i]));
			}
		} else {
			fprintf(stdout, "NULL");
		}
		fprintf(stdout, " for user = %u. Time taken: %lu us\n", user_id, res.tv_usec);
	#endif

	return 0;
}

int get_max_user_id(void)
{
	init_key_store("[MAIN THREAD]");

	return max_user_id;
}

int get_free_ram_in_mb(char *thread_id, unsigned long *ram_free_mb)
{
	int ret, i, j, k;
	FILE *fp;
	char line[256], *c_ptr;
	const char *memfree_str = "memfree";
	char free_bytes_buf[32], qualifier_buf[3];
	int found_free_bytes, prev_char_was_digit, found_qualifier;
	float multiplier;

	if(ram_free_mb == NULL) {
		return -1;
	}

	fp = fopen(MEM_STAT_FILE, "r");
	if(fp == NULL) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Failed to open memory statistics file, %s\n", thread_id, MEM_STAT_FILE);
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
		*ram_free_mb = (unsigned long)(multiplier * (float)atol(free_bytes_buf));

		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Found free RAM: %lu MB\n", thread_id, *ram_free_mb);
		#endif

		fclose(fp);
		return 0;
	} else {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Failed to parse memory statistics, found_free_bytes: %d, found_qualifier: %d\n", thread_id, 
						found_free_bytes, found_qualifier);
		#endif

		fclose(fp);
		return -1;
	}
}

int get_free_disk_space_in_mb(char *thread_id, unsigned long *disk_free_mb)
{
	int ret;
	struct statvfs fs_stat;

	if(disk_free_mb == NULL) {
		return -1;
	}

	ret = statvfs(".", &fs_stat);
	if(ret < 0) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Failed to get file system statistics\n", thread_id);
		#endif

		return -1;
	}

	*disk_free_mb = ((fs_stat.f_bsize * fs_stat.f_bfree) / 1000000);

	#ifdef ENABLE_LOGGING
		fprintf(stdout, "%s Found free DISK: %lu MB\n", thread_id, *disk_free_mb);
	#endif

	return 0;
}

int timeval_subtract (struct timeval *result, struct timeval *x, struct timeval *y)
{
	/* Perform the carry for the later subtraction by updating y. */
	if (x->tv_usec < y->tv_usec) {
		int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
		y->tv_usec -= 1000000 * nsec;
		y->tv_sec += nsec;
	}
	if (x->tv_usec - y->tv_usec > 1000000) {
		int nsec = (x->tv_usec - y->tv_usec) / 1000000;
		y->tv_usec += 1000000 * nsec;
		y->tv_sec -= nsec;
	}

	/* Compute the time remaining to wait.
	tv_usec is certainly positive. */
	result->tv_sec = x->tv_sec - y->tv_sec;
	result->tv_usec = x->tv_usec - y->tv_usec;

	/* Return 1 if result is negative. */
	return x->tv_sec < y->tv_sec;
}