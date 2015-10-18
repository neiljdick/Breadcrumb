#include "cryptography.h"

#define ENABLE_LOGGING

static int added_all_algorithms = 0;

int init_cryptography_env()
{
	if(added_all_algorithms == 0) {
		OpenSSL_add_all_algorithms();
		added_all_algorithms = 1;
	}

	return 0;
}

int load_public_key(const char *thread_id, RSA **rsa_public_out /* out */)
{
	FILE *fp_pub_key;

	init_cryptography_env();

	if(rsa_public_out == NULL) {
		return -1;
	}

	fp_pub_key = fopen(RELAY_RSA_PUBLIC_KEY_FILE, "r");
	if(fp_pub_key == NULL) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Failed to open public RSA key file\n", thread_id);
		#endif

		return -1;
	}

	*rsa_public_out = PEM_read_RSAPublicKey(fp_pub_key, NULL, NULL, NULL);
	if(*rsa_public_out == NULL) {
		#ifdef ENABLE_LOGGING
			fprintf(stdout, "%s Failed to read public RSA key from keyfile=%s\n", thread_id, RELAY_RSA_PUBLIC_KEY_FILE);
		#endif

		return -1;
	}

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