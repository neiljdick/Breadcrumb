#ifndef KEY_STORAGE_HEADER
#define KEY_STORAGE_HEADER

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define MAX_KEY_CLASH_PERMITTED 			(4)

#define AES_KEY_SIZE_BITS 					(128)
#define AES_KEY_SIZE_BYTES 					(AES_KEY_SIZE_BITS/8)

#define MEM_STAT_FILE 						("/proc/meminfo")

#define DEFAULT_RAM_FREE_MB 				(1000)
#define RAM_FOR_KEYSTORE_RATIO 				(0.1)
#define MIN_MEMORY_ATTEMPTING_USAGE_RATIO 	(0.2)
#define DEFAULT_DISK_FREE_MB 				(1000)
#define MAX_DISK_UTILIZATION_RATIO			(0.2)

#define MAX_KEY_ENTRY_AGE 					(100) // 8-bit

const unsigned char *key_storage_dir = ".key_storage";

typedef enum 
{
	SOFT = 0,
	HARD  
} init_type;

typedef struct key
{
	char value[AES_KEY_SIZE_BYTES];
} key;

typedef struct key_entry
{
	key p_key;
	int8_t age;
} key_entry;

int init_key_store(char *thread_id, init_type i_type);
int shutdown_key_store(char *thread_id);

int remove_key_from_key_store(char *thread_id, unsigned int user_id);
int set_key_for_user_id(char *thread_id, unsigned int user_id, key *key_in);
int get_key_for_user_id(char *thread_id, unsigned int user_id, int backup_index, key *key_out /* out */);
int get_max_user_id(void);
int get_free_ram_in_mb(char *thread_id, unsigned long *ram_free_mb);
int get_free_disk_space_in_mb(char *thread_id, unsigned long *disk_free_mb);
int swap_current_mapping_to_ram(char *thread_id);

static int init_key_storage_memory(char *thread_id, init_type i_type);
static int reset_key_entry_ages(char *thread_id);
static int free_key_store(char *thread_id);

int timeval_subtract(struct timeval *result, struct timeval *x, struct timeval *y);

#endif