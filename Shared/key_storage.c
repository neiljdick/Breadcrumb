#include "key_storage.h"

//#define ENABLE_LOGGING
//#define DEBUG_MODE

const uint8_t key_clash_tag = 0x80;
const unsigned char *key_storage_dir = (unsigned char *)".key_storage";

key_entry *g_key_store=NULL;

unsigned int g_max_user_id, g_num_keystore_clash_heaps;
unsigned long g_ram_available_for_keystore_mb;
unsigned int g_cached_user_id;
unsigned int g_clash_backup_index;
unsigned int g_clash_offset;
int g_ks_fd[MAX_KEY_CLASH_PERMITTED];
char *g_curr_ks_clash_addr;
off_t g_pa_offset;
unsigned long g_total_keys_used;
int g_backup_index;
FILE *gk_log_file=NULL;

static int init_key_storage_memory(char *thread_id, init_type i_type);
static int reset_key_entry_ages(char *thread_id);
static int free_key_store(char *thread_id);
static int init_globals(char *thread_id);
static int get_clash_backup_index_from_uid(unsigned int user_id, unsigned int *clash_backup_index, unsigned int *clash_offset);

int init_key_store(char *thread_id, FILE *log_file, init_type i_type)
{
	int ret;

	if(g_key_store != NULL) {
		return -1;
	}
	if(log_file == NULL) {
		return -1;
	}
	gk_log_file = log_file;

	ret = init_globals(thread_id);
	if(ret < 0) {
		return -1;
	}

	ret = init_key_storage_memory(thread_id, i_type);
	if(ret < 0) {
		return -1;
	}

	ret = reset_key_entry_ages(thread_id);
	if(ret < 0) {
		return -1;
	}

	#ifdef ENABLE_LOGGING
		fprintf(gk_log_file, "%s Successfully initialized key storage\n", thread_id);
	#endif

	return 0;
}

int get_number_of_key_clash_backups(char *thread_id, unsigned int *total_key_clash_backups)
{
	if(total_key_clash_backups == NULL) {
		return -1;
	}

	#ifdef ENABLE_LOGGING
		fprintf(gk_log_file, "%s Total number of keystore clash heaps: %u\n", thread_id, g_num_keystore_clash_heaps);
	#endif

	*total_key_clash_backups = g_num_keystore_clash_heaps;

	return 0;
}

int shutdown_key_store(char *thread_id)
{
	// TODO

	return 0;
} 

static int init_globals(char *thread_id)
{
	int i;

	g_max_user_id = 0;
	g_ram_available_for_keystore_mb = 0;
	g_num_keystore_clash_heaps = 0;
	g_curr_ks_clash_addr = NULL;
	g_cached_user_id = 0;
	g_total_keys_used = 0;
	g_clash_backup_index = 0;
	g_clash_offset = 0;

	for (i = 0; i < MAX_KEY_CLASH_PERMITTED; ++i) {
		g_ks_fd[i] = -1;
	}

	return 0;
}

static int init_key_storage_memory(char *thread_id, init_type i_type)
{
	int ret, i;
	unsigned int j;
	unsigned long ram_free_mb;
	unsigned long disk_free_mb;
	float attempting_usage_ratio;
	const unsigned int empty_ke_buf_len = 1000;
	char buf[64], empty_key_entry_buf[sizeof(key_entry) * empty_ke_buf_len];
	unsigned int empty_key_entry_count, empty_key_entry_count_overflow;
	key_entry empty_key_entry;

	if(g_key_store != NULL) {
		return -1;
	}

	ret = get_free_ram_in_mb(thread_id, &ram_free_mb);
	if(ret < 0) {
		#ifdef ENABLE_LOGGING
			fprintf(gk_log_file, "%s Unable to determine free RAM for initialization of key storage memory\n", thread_id);
		#endif

		ram_free_mb = DEFAULT_RAM_FREE_MB;
	}

	attempting_usage_ratio = 1.0;
	while(1) {
		g_ram_available_for_keystore_mb = (unsigned long)((float)ram_free_mb * (float)RAM_FOR_KEYSTORE_RATIO * (float)attempting_usage_ratio);
		#ifdef ENABLE_LOGGING
			fprintf(gk_log_file, "%s Attempting to use %lu MB for key storage\n", thread_id, g_ram_available_for_keystore_mb);
		#endif

		g_max_user_id = (g_ram_available_for_keystore_mb * (1024*1024)) / ((unsigned long)sizeof(key_entry));
		g_key_store = calloc(g_max_user_id, sizeof(key_entry));
		if(g_key_store != NULL) {
			break;	
		}

		attempting_usage_ratio *= 0.9;
		if(attempting_usage_ratio < MIN_MEMORY_ATTEMPTING_USAGE_RATIO) {
			return -1;
		}
	}
	#ifdef ENABLE_LOGGING
		fprintf(gk_log_file, "%s Successfully allocated key storage memory with a maximum user id = %u\n", thread_id, g_max_user_id);
	#endif

	ret = get_free_disk_space_in_mb(thread_id, &disk_free_mb);
	if(ret < 0) {
		#ifdef ENABLE_LOGGING
			fprintf(gk_log_file, "%s Unable to determine free disk space for key storage clash memory\n", thread_id);
		#endif

		disk_free_mb = DEFAULT_DISK_FREE_MB;
	}
	disk_free_mb *= MAX_DISK_UTILIZATION_RATIO;

	g_num_keystore_clash_heaps = MAX_KEY_CLASH_PERMITTED;
	while((g_ram_available_for_keystore_mb * g_num_keystore_clash_heaps) > disk_free_mb) {
		g_num_keystore_clash_heaps--;
		if(g_num_keystore_clash_heaps == 0) {
			break;
		}
	}

	fprintf(gk_log_file, "%s Initializing key store heaps..", thread_id);
	fflush(gk_log_file);
	sprintf(buf, "./%s", key_storage_dir);
	mkdir(buf, S_IRWXU | S_IRWXG);
	memset(&(empty_key_entry.p_key), 0, sizeof(key));
	empty_key_entry.age = 0;
	empty_key_entry_count = (g_max_user_id * sizeof(key_entry)) / sizeof(empty_key_entry_buf);
	empty_key_entry_count_overflow = g_max_user_id % sizeof(empty_key_entry_buf);
	for (i = 0; i < empty_ke_buf_len; ++i) {
		memcpy(empty_key_entry_buf + (sizeof(key_entry) * i), &empty_key_entry, sizeof(key_entry));
	}
	for (i = 0; i < g_num_keystore_clash_heaps; ++i) {
		if(i >= MAX_KEY_CLASH_PERMITTED) {
			return -1;
		}

		sprintf(buf, "./%s/_chp.%u", key_storage_dir, i);
		if(i_type == SOFT) {
			g_ks_fd[i] = open(buf, O_RDWR | S_IRUSR | S_IWUSR);
			if(g_ks_fd[i] >= 0) {
				continue;
			}
		}
		g_ks_fd[i] = open(buf, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);	
		if(g_ks_fd[i] < 0) {
			free_key_store(thread_id);
			return -1;
		}

		for (j = 0; j < empty_key_entry_count; ++j) {
			write(g_ks_fd[i], &empty_key_entry_buf, sizeof(empty_key_entry_buf));
			if((j % 1000) == 0) {
				fsync(g_ks_fd[i]);
				fprintf(gk_log_file, ".");
				fflush(gk_log_file);
			}
		}
		for (j = 0; j < empty_key_entry_count_overflow; ++j) {
			write(g_ks_fd[i], &empty_key_entry, sizeof(empty_key_entry));
		}
		fsync(g_ks_fd[i]);
	}
	fprintf(gk_log_file, "done\n");
	
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

	ke_ptr = (g_key_store);
	for (i = 0; i < g_max_user_id; i++) {
		ke_ptr->age = 0;
		ke_ptr++;
	}
	g_total_keys_used = 0;

	#ifdef ENABLE_LOGGING
		gettimeofday(&t2, NULL);
		timeval_subtract(&res, &t2, &t1);
		fprintf(gk_log_file, "%s Time to complete key age reset task: %lu us\n", thread_id, res.tv_usec);
	#endif

	return 0;
}

int handle_key_entry_age_increment(char *thread_id)
{
	key_entry *ke_ptr;
	int i;
	#ifdef ENABLE_LOGGING
		struct timeval res, t1, t2;
		gettimeofday(&t1, NULL);
	#endif

	ke_ptr = (g_key_store);
	for (i = 0; i < g_max_user_id; i++) {
		if(((~key_clash_tag) & ke_ptr->age) > 0) {
			if(((~key_clash_tag) & ke_ptr->age) > MAX_KEY_ENTRY_AGE) {
				remove_key_from_key_store(thread_id, i, -1);
			} else {
				ke_ptr->age = ((key_clash_tag & ke_ptr->age) | (((~key_clash_tag) & ke_ptr->age) + 1));
			}
		}
		ke_ptr++;
	}

	#ifdef ENABLE_LOGGING
		gettimeofday(&t2, NULL);
		timeval_subtract(&res, &t2, &t1);
		fprintf(gk_log_file, "%s Time to complete key age increment task: %lu us\n", thread_id, res.tv_usec);
	#endif

	return 0;
}

static int free_key_store(char *thread_id)
{
	if(g_key_store == NULL) {
		#ifdef ENABLE_LOGGING
			fprintf(gk_log_file, "%s Key storage is already freed\n", thread_id);
		#endif

		return -1;
	}

	// TODO

	return 0;
}

static int get_clash_backup_index_from_uid(unsigned int user_id, unsigned int *clash_backup_index, unsigned int *clash_offset)
{
	if((clash_backup_index == NULL) || (clash_offset == NULL)) {
		return -1;
	}
	if(user_id >= g_max_user_id) {
		return -1;
	}

	*clash_backup_index = 0;
	*clash_offset = (user_id * g_num_keystore_clash_heaps);
	while((*clash_offset) >= g_max_user_id) {
		(*clash_offset) -= g_max_user_id;
		(*clash_backup_index)++;
		if(*clash_backup_index >= g_num_keystore_clash_heaps) {
			return -1;
		}
	}

	return 0;
}

int set_key_for_user_id(char *thread_id, unsigned int user_id, key *key_in)
{
	int i, ret;
	key_entry *ke_ptr;
	#ifdef ENABLE_LOGGING
		struct timeval res, t1, t2;
		gettimeofday(&t1, NULL);
	#endif

	if((key_in == NULL) || (g_key_store == NULL)) {
		return -1;
	}

	if(user_id >= g_max_user_id) {
		#ifdef ENABLE_LOGGING
			fprintf(gk_log_file, "%s Failed to set key, user ID (%u) must be less than key storage size (%u)\n", thread_id, user_id, g_max_user_id);
		#endif

		return -1;
	}
	if(g_curr_ks_clash_addr != NULL) {
		munmap(g_curr_ks_clash_addr, (sizeof(key_entry) * g_num_keystore_clash_heaps) + ((off_t)g_clash_offset * sizeof(key_entry)) - g_pa_offset);
		g_curr_ks_clash_addr = NULL;
	}

	ke_ptr = (g_key_store + user_id);
	if((((~key_clash_tag) & ke_ptr->age) == 0) || (((~key_clash_tag) & ke_ptr->age) >= MAX_KEY_ENTRY_AGE)) {
		memcpy(&(ke_ptr->p_key), key_in, sizeof(key));
		ke_ptr->age = 1;
	} else {
		ret = get_clash_backup_index_from_uid(user_id, &g_clash_backup_index, &g_clash_offset);
		if(ret < 0) {
			return -1;
		}
		if((g_clash_backup_index > g_num_keystore_clash_heaps) || (g_clash_backup_index < 0)) {
			return -1;
		}
		if(g_clash_offset >= g_max_user_id) {
			return -1;
		}

		g_pa_offset = ((off_t)g_clash_offset * sizeof(key_entry)) & ~(sysconf(_SC_PAGE_SIZE) - 1);
		g_curr_ks_clash_addr = mmap(NULL, (sizeof(key_entry) * g_num_keystore_clash_heaps) + ((off_t)g_clash_offset * sizeof(key_entry)) - g_pa_offset, PROT_READ | PROT_WRITE, MAP_SHARED, g_ks_fd[g_clash_backup_index], g_pa_offset);
		if(g_curr_ks_clash_addr == MAP_FAILED) {
			#ifdef ENABLE_LOGGING
				fprintf(gk_log_file, "%s Failed to mmap key storage clash file (%u)\n", thread_id, g_clash_backup_index);
			#endif

			return -1;
		}

		for(i = 0; i < g_num_keystore_clash_heaps; i++) {
			if(i > MAX_KEY_CLASH_PERMITTED) {
				munmap(g_curr_ks_clash_addr, (sizeof(key_entry) * g_num_keystore_clash_heaps) + ((off_t)g_clash_offset * sizeof(key_entry)) - g_pa_offset);
				g_curr_ks_clash_addr = NULL;
				return -1;
			}

    		ke_ptr = (key_entry *)(g_curr_ks_clash_addr + ((off_t)(g_clash_offset + i) * sizeof(key_entry)) - g_pa_offset);
    		if((((~key_clash_tag) & ke_ptr->age) == 0) || (((~key_clash_tag) & ke_ptr->age) >= MAX_KEY_ENTRY_AGE)) {
    			memcpy(&(ke_ptr->p_key), key_in, sizeof(key));
				ke_ptr->age = 1;
    			munmap(g_curr_ks_clash_addr, (sizeof(key_entry) * g_num_keystore_clash_heaps) + ((off_t)g_clash_offset * sizeof(key_entry)) - g_pa_offset);
    			g_curr_ks_clash_addr = NULL;
    			ke_ptr = (g_key_store + user_id);
    			ke_ptr->age |= key_clash_tag;
    			//fprintf(gk_log_file, "s%d %d\n", i, user_id);
    			break;
    		}
		}
		if(i >= g_num_keystore_clash_heaps) {
			munmap(g_curr_ks_clash_addr, (sizeof(key_entry) * g_num_keystore_clash_heaps) + ((off_t)g_clash_offset * sizeof(key_entry)) - g_pa_offset);
			g_curr_ks_clash_addr = NULL;
			return -1;
		}
	}
	g_total_keys_used++;

	#ifdef ENABLE_LOGGING
		gettimeofday(&t2, NULL);
		timeval_subtract(&res, &t2, &t1);
		fprintf(gk_log_file, "%s Successfully set key = ", thread_id);
		for(i = 0; i < AES_KEY_SIZE_BYTES; i++) {
			fprintf(gk_log_file, "%02x", (0xff & key_in->value[i]));
		}
		fprintf(gk_log_file, " for user = %u. Time taken: %lu us\n", user_id, res.tv_usec);
	#endif

	return 0;
}

int get_key_for_user_id(char *thread_id, unsigned int user_id, int backup_index, key_entry *ke_out /* out */)
{
	int i, ret;
	key_entry *ke_ptr;
	#ifdef ENABLE_LOGGING
		struct timeval res, t1, t2;
		gettimeofday(&t1, NULL);
	#endif

	if((ke_out == NULL) || (g_key_store == NULL)) {
		return -1;
	}
	if(user_id >= g_max_user_id) {
		#ifdef ENABLE_LOGGING
			fprintf(gk_log_file, "%s Failed to get key, user ID (%u) must be less than key storage size (%u)\n", thread_id, user_id, g_max_user_id);
		#endif

		return -1;
	}
	if(backup_index >= (int)g_num_keystore_clash_heaps) {
		return -1;
	}
	#ifdef ENABLE_LOGGING
		fprintf(gk_log_file, "%s Attempting to get key for UID (%u)..", thread_id, user_id);
	#endif

	if(backup_index < 0) {
		ke_ptr = (g_key_store + user_id);
		memcpy(ke_out, ke_ptr, sizeof(key_entry));
	} else {
		if(user_id != g_cached_user_id) {
			if(g_curr_ks_clash_addr != NULL) {
				munmap(g_curr_ks_clash_addr, (sizeof(key_entry) * g_num_keystore_clash_heaps) + ((off_t)g_clash_offset * sizeof(key_entry)) - g_pa_offset);
				g_curr_ks_clash_addr = NULL;
			}
		}
		ret = get_clash_backup_index_from_uid(user_id, &g_clash_backup_index, &g_clash_offset);
		if(ret < 0) {
			return -1;
		}
		if((g_clash_backup_index > g_num_keystore_clash_heaps) || (g_clash_backup_index < 0)) {
			return -1;
		}
		if(g_clash_offset >= g_max_user_id) {
			return -1;
		}
		if((user_id != g_cached_user_id) || (g_curr_ks_clash_addr == NULL)) {
			g_pa_offset = ((off_t)(g_clash_offset + backup_index) * sizeof(key_entry)) & ~(sysconf(_SC_PAGE_SIZE) - 1);
			g_curr_ks_clash_addr = mmap(NULL, (sizeof(key_entry) * g_num_keystore_clash_heaps) + ((off_t)(g_clash_offset + backup_index) * sizeof(key_entry)) - g_pa_offset, PROT_WRITE, MAP_SHARED, g_ks_fd[g_clash_backup_index], g_pa_offset);
			if(g_curr_ks_clash_addr == MAP_FAILED) {
				#ifdef ENABLE_LOGGING
					fprintf(gk_log_file, "Failed to mmap key storage clash file (%u)\n", g_clash_backup_index);
				#endif

				return -1;
			}
			g_cached_user_id = user_id;
		}

		ke_ptr = (key_entry *)(g_curr_ks_clash_addr + ((off_t)(g_clash_offset + backup_index) * sizeof(key_entry)) - g_pa_offset);
		memcpy(ke_out, ke_ptr, sizeof(key_entry));
		//fprintf(gk_log_file, "g%d %d\n", backup_index, user_id);
	}

	#ifdef ENABLE_LOGGING
		if((ke_ptr->age & (~key_clash_tag)) > 0) {
			gettimeofday(&t2, NULL);
			timeval_subtract(&res, &t2, &t1);
			fprintf(gk_log_file, "Successfully got key = ");
			for(i = 0; i < AES_KEY_SIZE_BYTES; i++) {
				fprintf(gk_log_file, "%02x", (0xff & ke_out->p_key.value[i]));
			}
			fprintf(gk_log_file, " for user = %u, at index: %u. Clash/Age: 0x%x, Time taken: %lu us\n", user_id, (backup_index + 1), (0xFF & ke_ptr->age), res.tv_usec);
		} else {
			gettimeofday(&t2, NULL);
			timeval_subtract(&res, &t2, &t1);
			fprintf(gk_log_file, "Found key expired. Time taken: %lu us\n", res.tv_usec);
		}
	#endif

	return 0;
}

int remove_key_from_key_store(char *thread_id, unsigned int user_id, int backup_index)
{
	int i, ret, all_clashes_removed;
	key_entry *ke_ptr;

	if(g_key_store == NULL) {
		return -1;
	}
	if(user_id >= g_max_user_id) {
		#ifdef ENABLE_LOGGING
			fprintf(gk_log_file, "%s Failed to remove key, user ID (%u) must be less than key storage size (%u)\n", thread_id, user_id, g_max_user_id);
		#endif

		return -1;
	}
	if(backup_index >= (int)g_num_keystore_clash_heaps) {
		return -1;
	}
	#ifdef ENABLE_LOGGING
		fprintf(gk_log_file, "%s Attempting to remove key for UID (%u)..", thread_id, user_id);
	#endif

	if(backup_index < 0) {
		ke_ptr = (g_key_store + user_id);
		ke_ptr->age = (key_clash_tag & ke_ptr->age);
	} else {
		if(user_id != g_cached_user_id) {
			if(g_curr_ks_clash_addr != NULL) {
				munmap(g_curr_ks_clash_addr, (sizeof(key_entry) * g_num_keystore_clash_heaps) + ((off_t)g_clash_offset * sizeof(key_entry)) - g_pa_offset);
				g_curr_ks_clash_addr = NULL;
			}
		}
		ret = get_clash_backup_index_from_uid(user_id, &g_clash_backup_index, &g_clash_offset);
		if(ret < 0) {
			return -1;
		}
		if((g_clash_backup_index > g_num_keystore_clash_heaps) || (g_clash_backup_index < 0)) {
			return -1;
		}
		if(g_clash_offset >= g_max_user_id) {
			return -1;
		}
		if((user_id != g_cached_user_id) || (g_curr_ks_clash_addr == NULL)) {
			g_pa_offset = ((off_t)(g_clash_offset + backup_index) * sizeof(key_entry)) & ~(sysconf(_SC_PAGE_SIZE) - 1);
			g_curr_ks_clash_addr = mmap(NULL, (sizeof(key_entry) * g_num_keystore_clash_heaps) + ((off_t)(g_clash_offset + backup_index) * sizeof(key_entry)) - g_pa_offset, PROT_WRITE, MAP_SHARED, g_ks_fd[g_clash_backup_index], g_pa_offset);
			if(g_curr_ks_clash_addr == MAP_FAILED) {
				#ifdef ENABLE_LOGGING
					fprintf(gk_log_file, "Failed to mmap key storage clash file (%u)\n", g_clash_backup_index);
				#endif

				return -1;
			}
			g_cached_user_id = user_id;
		}

		ke_ptr = (key_entry *)(g_curr_ks_clash_addr + ((off_t)(g_clash_offset + backup_index) * sizeof(key_entry)) - g_pa_offset);
		ke_ptr->age = 0;
		g_backup_index = backup_index;

		all_clashes_removed = 1;
		for (i = 0; i < g_num_keystore_clash_heaps; ++i) {
			ke_ptr = (key_entry *)(g_curr_ks_clash_addr + ((off_t)(g_clash_offset + i) * sizeof(key_entry)) - g_pa_offset);
			if(ke_ptr->age != 0) {
				all_clashes_removed = 0;
			}
		}
		if(all_clashes_removed) {
			ke_ptr = (g_key_store + user_id);
			ke_ptr->age = (~key_clash_tag) & ke_ptr->age;
			#ifdef ENABLE_LOGGING
				fprintf(gk_log_file, "%s Found all key clashes for UID = %u removed\n", thread_id, user_id);
			#endif
		}
		//fprintf(gk_log_file, "r%d %d\n", backup_index, user_id);
	}
	
	if(g_total_keys_used > 0)
		g_total_keys_used--;
	#ifdef ENABLE_LOGGING
		fprintf(gk_log_file, "%s Successfully removed key with UID = %u and backup index = %d\n", thread_id, user_id, backup_index);
	#endif

	return 0;
}

int get_max_user_id(char *thread_id, unsigned int *max_uid)
{
	if(max_uid == NULL) {
		return -1;
	}

	*max_uid = g_max_user_id;

	return 0;
}

int get_current_amount_of_keys_used(unsigned long *num_keys_used)
{
	if(num_keys_used == NULL) {
		return -1;
	}

	*num_keys_used = g_total_keys_used;

	return 0;
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
			fprintf(gk_log_file, "%s Failed to open memory statistics file, %s\n", thread_id, MEM_STAT_FILE);
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
			fprintf(gk_log_file, "%s Found free RAM: %lu MB\n", thread_id, *ram_free_mb);
		#endif

		fclose(fp);
		return 0;
	} else {
		#ifdef ENABLE_LOGGING
			fprintf(gk_log_file, "%s Failed to parse memory statistics, found_free_bytes: %d, found_qualifier: %d\n", thread_id, 
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
			fprintf(gk_log_file, "%s Failed to get file system statistics\n", thread_id);
		#endif

		return -1;
	}

	*disk_free_mb = ((fs_stat.f_bsize * fs_stat.f_bfree) / 1000000);

	#ifdef ENABLE_LOGGING
		fprintf(gk_log_file, "%s Found free DISK: %lu MB\n", thread_id, *disk_free_mb);
	#endif

	return 0;
}

#ifdef DEBUG_MODE

int main(int argc, char const *argv[])
{
	int ret;
	key debug_key;
	key_entry debug_ke_entry;

	fprintf(gk_log_file, "[DEBUG MODE] Begin\n");
	fprintf(gk_log_file, "[DEBUG MODE] Size of key entry: %lu\n", sizeof(key_entry));

	ret = init_key_store("[DEBUG MODE]", SOFT);
	if(ret < 0) {
		return -1;
	}

	memset(debug_key.value, 0x30, AES_KEY_SIZE_BYTES);
	set_key_for_user_id("[DEBUG MODE]", 0, &debug_key);
	memset(debug_key.value, 0x31, AES_KEY_SIZE_BYTES);
	set_key_for_user_id("[DEBUG MODE]", 0, &debug_key);
	memset(debug_key.value, 0x32, AES_KEY_SIZE_BYTES);
	set_key_for_user_id("[DEBUG MODE]", 0, &debug_key);
	memset(debug_key.value, 0x33, AES_KEY_SIZE_BYTES);
	set_key_for_user_id("[DEBUG MODE]", 0, &debug_key);
	memset(debug_key.value, 0x34, AES_KEY_SIZE_BYTES);
	set_key_for_user_id("[DEBUG MODE]", 0, &debug_key);
	
	/*memset(debug_key.value, 0x35, AES_KEY_SIZE_BYTES);
	set_key_for_user_id("[DEBUG MODE]", (g_max_user_id>>2) + 1, &debug_key);
	memset(debug_key.value, 0x36, AES_KEY_SIZE_BYTES);
	set_key_for_user_id("[DEBUG MODE]", (g_max_user_id>>2) + 1, &debug_key);
	memset(debug_key.value, 0x37, AES_KEY_SIZE_BYTES);
	set_key_for_user_id("[DEBUG MODE]", (g_max_user_id>>2) + 1, &debug_key);
	memset(debug_key.value, 0x38, AES_KEY_SIZE_BYTES);
	set_key_for_user_id("[DEBUG MODE]", (g_max_user_id>>2) + 1, &debug_key);
	memset(debug_key.value, 0x39, AES_KEY_SIZE_BYTES);
	set_key_for_user_id("[DEBUG MODE]", (g_max_user_id>>2) + 1, &debug_key);
	
	memset(debug_key.value, 0x3A, AES_KEY_SIZE_BYTES);
	set_key_for_user_id("[DEBUG MODE]", (g_max_user_id-1), &debug_key);
	memset(debug_key.value, 0x3B, AES_KEY_SIZE_BYTES);
	set_key_for_user_id("[DEBUG MODE]", (g_max_user_id-1), &debug_key);
	memset(debug_key.value, 0x3C, AES_KEY_SIZE_BYTES);
	set_key_for_user_id("[DEBUG MODE]", (g_max_user_id-1), &debug_key);
	memset(debug_key.value, 0x3D, AES_KEY_SIZE_BYTES);
	set_key_for_user_id("[DEBUG MODE]", (g_max_user_id-1), &debug_key);
	memset(debug_key.value, 0x3E, AES_KEY_SIZE_BYTES);
	set_key_for_user_id("[DEBUG MODE]", (g_max_user_id-1), &debug_key);*/

	get_key_for_user_id("[DEBUG MODE]", 0, -1, &debug_ke_entry);
	get_key_for_user_id("[DEBUG MODE]", 0, 0, &debug_ke_entry);
	get_key_for_user_id("[DEBUG MODE]", 0, 1, &debug_ke_entry);
	get_key_for_user_id("[DEBUG MODE]", 0, 2, &debug_ke_entry);
	get_key_for_user_id("[DEBUG MODE]", 0, 3, &debug_ke_entry);

	remove_key_from_key_store("[DEBUG MODE]", 0, -1);
	remove_key_from_key_store("[DEBUG MODE]", 0, 0);
	remove_key_from_key_store("[DEBUG MODE]", 0, 3);

	get_key_for_user_id("[DEBUG MODE]", 0, -1, &debug_ke_entry);
	get_key_for_user_id("[DEBUG MODE]", 0, 0, &debug_ke_entry);
	get_key_for_user_id("[DEBUG MODE]", 0, 1, &debug_ke_entry);
	get_key_for_user_id("[DEBUG MODE]", 0, 2, &debug_ke_entry);
	get_key_for_user_id("[DEBUG MODE]", 0, 3, &debug_ke_entry);

	remove_key_from_key_store("[DEBUG MODE]", 0, 1);
	remove_key_from_key_store("[DEBUG MODE]", 0, 2);

	get_key_for_user_id("[DEBUG MODE]", 0, -1, &debug_ke_entry);
	get_key_for_user_id("[DEBUG MODE]", 0, 0, &debug_ke_entry);
	get_key_for_user_id("[DEBUG MODE]", 0, 1, &debug_ke_entry);
	get_key_for_user_id("[DEBUG MODE]", 0, 2, &debug_ke_entry);
	get_key_for_user_id("[DEBUG MODE]", 0, 3, &debug_ke_entry);

	memset(debug_key.value, 0x50, AES_KEY_SIZE_BYTES);
	set_key_for_user_id("[DEBUG MODE]", 0, &debug_key);

	get_key_for_user_id("[DEBUG MODE]", 0, -1, &debug_ke_entry);

	memset(debug_key.value, 0x51, AES_KEY_SIZE_BYTES);
	set_key_for_user_id("[DEBUG MODE]", 0, &debug_key);

	get_key_for_user_id("[DEBUG MODE]", 0, -1, &debug_ke_entry);
	get_key_for_user_id("[DEBUG MODE]", 0, 0, &debug_ke_entry);

	/*get_key_for_user_id("[DEBUG MODE]", (g_max_user_id>>2) + 1, -1, &debug_ke_entry);
	get_key_for_user_id("[DEBUG MODE]", (g_max_user_id>>2) + 1, 0, &debug_ke_entry);
	get_key_for_user_id("[DEBUG MODE]", (g_max_user_id>>2) + 1, 1, &debug_ke_entry);
	get_key_for_user_id("[DEBUG MODE]", (g_max_user_id>>2) + 1, 2, &debug_ke_entry);
	get_key_for_user_id("[DEBUG MODE]", (g_max_user_id>>2) + 1, 3, &debug_ke_entry);
	
	get_key_for_user_id("[DEBUG MODE]", (g_max_user_id-1), -1, &debug_ke_entry);
	get_key_for_user_id("[DEBUG MODE]", (g_max_user_id-1), 0, &debug_ke_entry);
	get_key_for_user_id("[DEBUG MODE]", (g_max_user_id-1), 1, &debug_ke_entry);
	get_key_for_user_id("[DEBUG MODE]", (g_max_user_id-1), 2, &debug_ke_entry);
	get_key_for_user_id("[DEBUG MODE]", (g_max_user_id-1), 3, &debug_ke_entry);*/

	//swap_current_mapping_to_ram("[DEBUG MODE]");

	/*memset(debug_key.value, 0x41, AES_KEY_SIZE_BYTES);
	set_key_for_user_id("[DEBUG MODE]", (g_max_user_id>>2) + 4, &debug_key);
	get_key_for_user_id("[DEBUG MODE]", (g_max_user_id>>2) + 3, -1, &debug_ke_entry);
	memset(debug_key.value, 0x3D, AES_KEY_SIZE_BYTES);
	set_key_for_user_id("[DEBUG MODE]", (g_max_user_id>>2) + 3, &debug_key);
	memset(debug_key.value, 0x3E, AES_KEY_SIZE_BYTES);
	get_key_for_user_id("[DEBUG MODE]", (g_max_user_id>>2) + 0, 1, &debug_ke_entry);
	get_key_for_user_id("[DEBUG MODE]", (g_max_user_id>>2) + 0, 2, &debug_ke_entry);
	get_key_for_user_id("[DEBUG MODE]", (g_max_user_id>>2) + 0, 3, &debug_ke_entry);
	set_key_for_user_id("[DEBUG MODE]", (g_max_user_id>>2) + 3, &debug_key);
	memset(debug_key.value, 0x3F, AES_KEY_SIZE_BYTES);
	set_key_for_user_id("[DEBUG MODE]", (g_max_user_id>>2) + 3, &debug_key);
	memset(debug_key.value, 0x40, AES_KEY_SIZE_BYTES);
	set_key_for_user_id("[DEBUG MODE]", (g_max_user_id>>2) + 3, &debug_key);
	get_key_for_user_id("[DEBUG MODE]", (g_max_user_id>>2) + 3, 1, &debug_ke_entry);
	get_key_for_user_id("[DEBUG MODE]", (g_max_user_id>>2) + 4, 0, &debug_ke_entry);
	get_key_for_user_id("[DEBUG MODE]", (g_max_user_id>>2) + 4, -1, &debug_ke_entry);

	get_key_for_user_id("[DEBUG MODE]", (g_max_user_id>>2) + 3, 0, &debug_ke_entry);
	memset(debug_key.value, 0x42, AES_KEY_SIZE_BYTES);
	set_key_for_user_id("[DEBUG MODE]", (g_max_user_id>>2) + 4, &debug_key);
	get_key_for_user_id("[DEBUG MODE]", (g_max_user_id>>2) + 3, 2, &debug_ke_entry);
	memset(debug_key.value, 0x43, AES_KEY_SIZE_BYTES);
	set_key_for_user_id("[DEBUG MODE]", (g_max_user_id>>2) + 4, &debug_key);
	get_key_for_user_id("[DEBUG MODE]", (g_max_user_id>>2) + 4, 0, &debug_ke_entry);
	get_key_for_user_id("[DEBUG MODE]", (g_max_user_id>>2) + 4, -1, &debug_ke_entry);*/
	
	while(1) sleep(10);
	
	return 0;
}

#endif