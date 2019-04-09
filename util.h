#ifndef UTIL_H
#define UTIL_H

#include "wiiudisc.h"
#include "multi_file.h"

#include <stdio.h>

#define PRINT_128(PTR) \
	{ \
		const unsigned char *x = PTR; \
		fprintf(stderr, "%02x %02x %02x %02x %02x %02x %02x %02x-%02x %02x %02x %02x %02x %02x %02x %02x\n", \
		        x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8], x[9], x[10], x[11], x[12], x[13], x[14], x[15]); \
	}

#define FIT_TO_BLOCKS(X, BS) (((X) / (BS) + ((X) % (BS) == 0 ? 0 : 1)) * (BS))
#define BLOCK_START(X, BS) ((X) / (BS) * (BS))

#define OPENSSL_ENCRYPT (1)
#define OPENSSL_DECRYPT (0)

typedef struct {
	multi_FILE *f;
	off_t start;
	int offset;
	int size;
	int readSize;
	char key[16];
	char IV[16];
	char *buffer;
	int special;
	int cluster;
	long long int clusterOffset;
	int outOffset;
} WiiUEncryptedFile;

int read_unterminated_string(multi_FILE *f, const size_t bytes, char *buffer);
int read_unterminated_string_from(multi_FILE *f, const off_t offset, const size_t bytes, char *buffer);
WiiUEncryptedFile *open_encrypted_file(WiiUDisc *w, int partition, int index);
int read_encrypted_block(WiiUEncryptedFile *f, char *buffer);
void free_encrypted_file(WiiUEncryptedFile *f);
int crypt_aes_128_cbc(const unsigned char const *in, unsigned char *out, 
          const unsigned int datalen, const unsigned char const *key,
          const unsigned char const *iv, const int enc);
int find_index_of_file_by_name(const WiiUPartition *p, int start, const char *name);
int get_index_of_directory_from_file_index(const WiiUPartition *p, int index);

#endif
