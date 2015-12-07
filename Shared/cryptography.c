#include "cryptography.h"

//#define ENABLE_LOGGING

static int added_all_algorithms = 0;

int init_cryptography_env()
{
	if(added_all_algorithms == 0) {
		OpenSSL_add_all_algorithms();
		added_all_algorithms = 1;
	}

	return 0;
}

int load_public_key_into_buffer(const char *thread_id, char **rsa_public_out /* out */, int *public_key_buffer_len /* out */)
{
	int num_bytes, num_bytes_read;
	FILE *fp_pub_key;

	if((thread_id == NULL) || (rsa_public_out == NULL)) {
		return -1;
	}

	fp_pub_key = fopen(RELAY_RSA_PUBLIC_KEY_FILE, "r");
	if(fp_pub_key == NULL) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Failed to open public RSA key file\n", thread_id);
		#endif

		return -1;
	}
	
	fseek(fp_pub_key, 0L, SEEK_END);
	num_bytes = ftell(fp_pub_key);
	fseek(fp_pub_key, 0L, SEEK_SET);

	*rsa_public_out = calloc(num_bytes, sizeof(char));
	if(*rsa_public_out == NULL) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Failed to allocate memory for public key as bytes buffer\n", thread_id);
		#endif

		return -1;	
	}

	num_bytes_read = fread((*rsa_public_out), sizeof(char), num_bytes, fp_pub_key);
	if(num_bytes_read != num_bytes) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Failed to read %u bytes from public key file into buffer\n", thread_id, num_bytes);
		#endif

		return -1;
	}
	*public_key_buffer_len = num_bytes;

	return 0;
}

int load_rsa_key_pair(const char *relay_id, RSA **rsa_out /* out */)
{
	FILE *fp_pub_key, *fp_priv_key;
	int ret;

	if((rsa_out == NULL) || (relay_id == NULL)) {
		return -1;
	}

	init_cryptography_env();

	fp_pub_key = fopen(RELAY_RSA_PUBLIC_KEY_FILE, "r");
	fp_priv_key = fopen(RELAY_RSA_PRIVATE_KEY_FILE, "r");
	if((fp_pub_key == NULL) || (fp_priv_key == NULL)) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Failed to read RSA key file, generating key pair instead\n");
		#endif

		ret = generate_rsa_key_pair(relay_id, rsa_out);
		if(ret < 0) {
			return -1;
		}
		save_key_pair_to_file(*rsa_out);

		return 0;
	}

	*rsa_out = PEM_read_RSAPrivateKey(fp_priv_key, NULL, &cb, NULL);
	if(*rsa_out == NULL) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Private RSA key file exists but failed to read private key\n");
		#endif

		return -1;
	}

	return 0;
}

int save_key_pair_to_file(RSA *rsa_key_pair)
{
	FILE *fp_pub_key, *fp_priv_key;
	const EVP_CIPHER *cipher;

	if(rsa_key_pair == NULL) {
		return -1;
	}

	init_cryptography_env();

	fp_pub_key = fopen(RELAY_RSA_PUBLIC_KEY_FILE, "w");
	if(fp_pub_key == NULL) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Failed to open public key file %s\n", RELAY_RSA_PUBLIC_KEY_FILE);
		#endif

		return -1;
	}
	PEM_write_RSAPublicKey(fp_pub_key, rsa_key_pair);
	fclose(fp_pub_key);

	fp_priv_key = fopen(RELAY_RSA_PRIVATE_KEY_FILE, "w");
	if(fp_priv_key == NULL) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Failed to open private key file %s\n", RELAY_RSA_PRIVATE_KEY_FILE);
		#endif

		return -1;
	}
	cipher = EVP_get_cipherbyname("aes-256-cbc");
	PEM_write_RSAPrivateKey(fp_priv_key, rsa_key_pair, cipher, NULL, 0, &cb, NULL);
	fclose(fp_priv_key);

	return 0;
}

unsigned char* get_private_key_password_hash(int double_check)
{
	int i, j, ret;
	char c, asterisk = '*';
	SHA256_CTX sha256;
	unsigned char *hash, *hash_double_check;
	struct termios termios_attr, termios_attr_cached;

	init_cryptography_env();
	
	if(double_check > 1)
		double_check = 1;

	hash = calloc(SHA256_DIGEST_LENGTH, sizeof(char));
	if(hash == NULL) {
		#ifdef ENABLE_LOGGING
	  		fprintf(stdout, "[MAIN THREAD] Failed to allocate memory for password storage\n");
	  	#endif

	  	return NULL;
	}
	if(double_check) {
		hash_double_check = calloc(SHA256_DIGEST_LENGTH, sizeof(char));
		if(hash_double_check == NULL) {
			#ifdef ENABLE_LOGGING
		  		fprintf(stdout, "[MAIN THREAD] Failed to allocate memory for password storage\n");
		  	#endif

		  	return NULL;
		}
	}

	tcgetattr(STDIN_FILENO, &termios_attr);
	memcpy(&termios_attr_cached, &termios_attr, sizeof(termios_attr));

	termios_attr.c_lflag &= ~(ICANON | ECHO);
  	termios_attr.c_cc[VMIN] = 1;
  	termios_attr.c_cc[VTIME] = 0;
  	tcsetattr(STDIN_FILENO, TCSAFLUSH, &termios_attr);

  	for (j = 0; j <= double_check; ++j) {
  		if(j == 0)
  			fprintf(stdout, "Enter private key password: ");
  		else if(j == 1)
  			fprintf(stdout, "Re-enter private key password: ");
	  	fflush(stdout);
	  	i = 0;
	  	while(1) {
	  		read(STDIN_FILENO, &c, 1);
	  		if(isalnum(c) || ispunct(c)) {
	  			if(i < (SHA256_DIGEST_LENGTH - 1)) {
	  				if(j == 0)
			  			hash[i] = c;
			  		else if(j == 1)
		  				hash_double_check[i] = c;
		  			write(STDOUT_FILENO, &asterisk, 1);
		  			i++;
		  		}
	  		} else {
	  			if(j == 0)
		  			hash[i] = '\0';
		  		else if(j == 1)
	  				hash_double_check[i] = '\0';
	  			break;
	  		}
	  	}
	  	fprintf(stdout, "\n");
  	}
  	tcsetattr(STDIN_FILENO, TCSAFLUSH, &termios_attr_cached);
  	
  	if(double_check) {
  		ret = memcmp(hash, hash_double_check, SHA256_DIGEST_LENGTH);
  		if(ret != 0) {
  			fprintf(stdout, "Passwords don't match.\n");
  			exit(-1);
  		}
  		free(hash_double_check);
  	}

    SHA256_Init(&sha256);
    for (i = 0; i < RSA_PRIVATE_KEY_HASH_COUNT; ++i) {
	    SHA256_Update(&sha256, hash, SHA256_DIGEST_LENGTH);    	
    }
    SHA256_Final(hash, &sha256);

	return hash;
}

int cb(char *buf, int size, int rwflag, void *u)
{
	unsigned char *hash;
	int password_size;

	if(buf == NULL) {
		return 0; // 0 denotes callback failure
	}

	hash = get_private_key_password_hash(rwflag);
	if(hash == NULL) {
		return 0; // 0 denotes callback failure
	}

	if(SHA256_DIGEST_LENGTH <= size) {
		password_size = SHA256_DIGEST_LENGTH;
	} else {
		password_size = size;
	}
	memcpy(buf, hash, password_size);
	free(hash);

	return password_size;
}

int generate_rsa_key_pair(const char *relay_id, RSA **rsa_out /* out */)
{
	BIGNUM *e;
	int ret;

	if((relay_id == NULL) || (rsa_out == NULL)) {
		return -1;
	}

	init_cryptography_env();

	*rsa_out = RSA_new();
	RAND_seed((const void *)relay_id, strlen(relay_id));
	ret = RAND_status();
	if(ret != 1) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] The PRNG has not been seeded with enough random data\n");
		#endif

		// TODO ?
	}
	e = BN_new();
	ret = BN_set_word(e, (unsigned long)RSA_EXPONENT);
	if(ret != 1) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Failed to generate BIGNUM exponent\n");
		#endif

		return -1;
	}
	ret = RSA_generate_key_ex(*rsa_out, RSA_KEY_LENGTH, e, NULL);
	BN_free(e);

	if (ret != 1) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "[MAIN THREAD] Failed to generate RSA key file\n");
		#endif

		return -1;
	}

	return 0;
}

int aes_encrypt_block(char *thread_id, unsigned char *plaintext, int plaintext_len, unsigned char *key, int key_len, unsigned char *iv, unsigned char *cipher_text /* out */)
{
	int ret;
	EVP_CIPHER_CTX ctx;
	int cipher_text_len;

	if((plaintext == NULL) || (key == NULL) || (iv == NULL) || (cipher_text == NULL)) {
		return -1;
	}

	init_cryptography_env();

	if((plaintext_len % key_len) != 0) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s AES encryption function passed plaintext size (%u) not aligned to block boundary (%u)\n", thread_id, plaintext_len, key_len);
		#endif

		return -1;
	}

	EVP_CIPHER_CTX_init(&ctx);
	if(key_len == AES_128_KEY_BYTE_LEN) {
		ret = EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv);
	}
	else if(key_len == AES_192_KEY_BYTE_LEN) {
		ret = EVP_EncryptInit_ex(&ctx, EVP_aes_192_cbc(), NULL, key, iv);
	}
	else if(key_len == AES_256_KEY_BYTE_LEN) {
		ret = EVP_EncryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, key, iv);
	}
	else {
		return -1;
	}
	if(ret != 1) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Failed to initialize AES encryption\n", thread_id);
		#endif

		return -1;
	}

	ret = EVP_EncryptUpdate(&ctx, cipher_text, &cipher_text_len, plaintext, plaintext_len);
	if(ret != 1) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Failed to perform %u bit AES encryption\n", thread_id, (key_len*8));
		#endif

		return -1;
	}

	EVP_CIPHER_CTX_cleanup(&ctx);

	return 0;	
}

int aes_decrypt_block(char *thread_id, unsigned char *cipher_text, int cipher_text_len, unsigned char *key, int key_len, unsigned char *iv, unsigned char *plaintext /* out */)
{
	int ret;
	EVP_CIPHER_CTX ctx;
	int plain_text_len;

	if((cipher_text == NULL) || (key == NULL) || (iv == NULL) || (plaintext == NULL)) {
		return -1;
	}
	
	init_cryptography_env();

	if((cipher_text_len % key_len) != 0) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s AES decryption function passed ciphertext size (%u) not aligned to block boundary (%u)\n", thread_id, cipher_text_len, key_len);
		#endif

		return -1;
	}

	EVP_CIPHER_CTX_init(&ctx);
	if(key_len == AES_128_KEY_BYTE_LEN) {
		ret = EVP_DecryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv);
	}
	else if(key_len == AES_192_KEY_BYTE_LEN) {
		ret = EVP_DecryptInit_ex(&ctx, EVP_aes_192_cbc(), NULL, key, iv);
	}
	else if(key_len == AES_256_KEY_BYTE_LEN) {
		ret = EVP_DecryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, key, iv);
	}
	else {
		return -1;
	}
	if(ret != 1) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Failed to initialize AES encryption\n", thread_id);
		#endif

		return -1;
	}

	ret = EVP_DecryptUpdate(&ctx, plaintext, &plain_text_len, cipher_text, cipher_text_len);
	if(ret != 1) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Failed to perform %u bit AES decryption\n", thread_id, (key_len*8));
		#endif

		return -1;
	}

	EVP_CIPHER_CTX_cleanup(&ctx);

	return 0;	
}

int generate_AES_key(unsigned char *buf, int buf_len)
{
	int ret;

	if(buf == NULL) {
		return -1;
	}

	init_cryptography_env();
	ret = RAND_status();
	if(ret != 1) {
		return -1;
	}

	ret = RAND_bytes(buf, buf_len);
	if(ret != 1) {
		return -1;
	}
	return 0;
}

int fill_buf_with_random_data(unsigned char *buf, int buf_len)
{
	int ret;

	if(buf == NULL) {
		return -1;
	}

	init_cryptography_env();
	ret = RAND_status();
	if(ret != 1) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "Failed to fill packet buffer with random data \n");
		#endif

		return -1;
	}

	ret = RAND_bytes(buf, buf_len);
	if(ret != 1) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "Failed to fill packet buffer with random data \n");
		#endif

		return -1;
	}
	return 0;
}

int get_hash_of_string(char *thread_id, int hash_count, const char *in_str, char **out_str /* out */, int *relay_id_len /* out */)
{
	char tmp_hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	int i;

	if((in_str == NULL) || (out_str == NULL)) {
		return -1;
	}

	*relay_id_len = (SHA256_DIGEST_LENGTH*2);
	*out_str = calloc((SHA256_DIGEST_LENGTH*2), sizeof(char));
	if(*out_str == NULL) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Failed to allocate memory for string hash\n", thread_id);
		#endif

		return -1;
	}

	init_cryptography_env();

	strncpy(tmp_hash, in_str, SHA256_DIGEST_LENGTH);
	SHA256_Init(&sha256);
    for (i = 0; i < hash_count; i++) {
	    SHA256_Update(&sha256, tmp_hash, SHA256_DIGEST_LENGTH);    	
    }
    SHA256_Final((unsigned char *)tmp_hash, &sha256);

    for (i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
    	sprintf(((*out_str) + (i*2)), "%02x", 0xff & tmp_hash[i]);
    }

    return 0;
}

int get_random_number(unsigned int initial_seed)
{
	unsigned int seed, rand_val;
	FILE* dev_urandom;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	dev_urandom = fopen("/dev/urandom", "r"); // TODO try multiple times!
	if(dev_urandom == NULL) {
		seed = initial_seed ^ (unsigned int)time(NULL);
		seed ^= (unsigned int)tv.tv_usec;
	} else {
		fread(&seed, sizeof(unsigned int), 1, dev_urandom);
		seed ^= initial_seed;
		seed ^= (unsigned int)time(NULL);
		seed ^= (unsigned int)tv.tv_usec;
		fclose(dev_urandom);
	}

	srand(seed);
	rand_val = rand();

	return rand_val;
}