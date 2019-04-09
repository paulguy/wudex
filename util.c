#include "util.h"
#include "wiiudisc.h"
#include "multi_file.h"

#include <string.h>

#define NEWER_OPENSSL_VERSION 0x10100000

#define FILE_READ_SIZE (1024 * 1024)

#define SPECIAL_BLOCK_SIZE (0x10000)
#define SPECIAL_BLOCK_HEADER (0x400)
#define SPECIAL_BLOCK_DATA (SPECIAL_BLOCK_SIZE - SPECIAL_BLOCK_HEADER)

int read_unterminated_string(multi_FILE *f, const size_t bytes, char *buffer) {
	if(multi_fread(buffer, bytes, f) < bytes) {
		fprintf(stderr, "Failed to read!\n");
		return(-1);
	}

	buffer[bytes] = '\0';

	return(0);
}

int read_unterminated_string_from(multi_FILE *f, const off_t offset, const size_t bytes, char *buffer) {
	if(multi_fseeko(f, offset) != 0) {
		fprintf(stderr, "Failed to seek!\n");
		return(-1);
	}

	return(read_unterminated_string(f, bytes, buffer));
}

int read_file_block(multi_FILE *f, char *buffer, off_t offset, size_t size) {
	if(multi_fseeko(f, offset) != 0) {
		fprintf(stderr, "Failed to seek!\n");
		return(-1);
	}

	return(multi_fread(buffer, size, f));
}

WiiUEncryptedFile *open_encrypted_file(WiiUDisc *w, int partition, int index) {
	WiiUEncryptedFile *f;

	if(partition >= 0 && partition >= w->partitionsCount) {
		fprintf(stderr, "Partition is out of range!\n");
		return(NULL);
	}

	if(index >= 0 && index >= w->partitions[partition]->dirEntsCount) {
		fprintf(stderr, "Directory entry is out of range!\n");
		return(NULL);
	}

	f = malloc(sizeof(WiiUEncryptedFile));
	if(f == NULL) {
		fprintf(stderr, "Failed to allocate memory!\n");
		return(NULL);
	}

	bzero(f->IV, 16);

	f->f = w->f;
	f->offset = 0;
	f->readSize = BLOCKSIZE;
	f->special = 0;
	f->size = -1;
	if(partition < 0) {
		memcpy(f->key, w->discKey, KEYSIZE);
		f->start = DECRYPTED_AREA_POS;
		/* IV == 0 */
	} else {
		memcpy(f->key, w->partitions[partition]->key, KEYSIZE);
		if(index < 0) {
			f->start = w->partitions[partition]->offset;
			/* IV == 0 */
		} else {
			f->size = w->partitions[partition]->dirEnts[index]->size;
			*(short *)(&f->IV[0]) = htobe16(w->partitions[partition]->dirEnts[index]->cluster);
			f->readSize = FILE_READ_SIZE; /* make it bigger for when extracting files */

			if((w->partitions[partition]->dirEnts[index]->flags == 0x0400) ||
			   (w->partitions[partition]->dirEnts[index]->flags == 0x0040) ||
			   ((w->partitions[partition]->clusters[w->partitions[partition]->dirEnts[index]->cluster]->flags0 & 0x00000400) &&
			    (w->partitions[partition]->clusters[w->partitions[partition]->dirEnts[index]->cluster]->flags1 & 0x02000000))) {
				f->special = 1;
				f->cluster = w->partitions[partition]->dirEnts[index]->cluster;
				f->clusterOffset = w->partitions[partition]->dirEnts[index]->clusterOffset;
				/* for special files, we need to be aware of the alignment of the file within the cluster, so only store the start of
                   the cluster in start, then use clusterOffset and offset */
				f->start = w->partitions[partition]->offset +
				           w->partitions[partition]->clusters[w->partitions[partition]->dirEnts[index]->cluster]->offset;
			} else {
				f->start = w->partitions[partition]->offset +
				           w->partitions[partition]->clusters[w->partitions[partition]->dirEnts[index]->cluster]->offset + 
				           w->partitions[partition]->dirEnts[index]->clusterOffset;
			}
		}
	}

	f->buffer = malloc(f->readSize);
	if(f->buffer == NULL) {
		fprintf(stderr, "Failed to allocate memory!\n");
		free(f);
		return(NULL);
	}

	return(f);
}

int decrypt_block(WiiUEncryptedFile *f, char *buffer, int dataRead) {
	int totalout, outl;

	if(crypt_aes_128_cbc(f->buffer, buffer, dataRead, f->key, f->IV, OPENSSL_DECRYPT) < 0) {
		fprintf(stderr, "Failed to decrypt block!\n");
		return(-1);
	}

	/* save the IV */
	memcpy(f->IV, &f->buffer[dataRead - 16], 16);
	
	return(0);
}

int sha1_digest(char *buffer, int size, char *digest) {
#if OPENSSL_VERSION_NUMBER < NEWER_OPENSSL_VERSION
	EVP_MD_CTX c;
#define MDCTX (&c)
#else
	EVP_MD_CTX *c;
#define MDCTX (c)
#endif
	int len;
	
#if OPENSSL_VERSION_NUMBER < NEWER_OPENSSL_VERSION
	EVP_MD_CTX_init(&c);
#else
    c = EVP_MD_CTX_new();
#endif
	
	if(EVP_DigestInit_ex(MDCTX, EVP_sha1(), NULL) == 0) {
		fprintf(stderr, "Failed to initialize SHA1 digest!\n");
        goto error;
	}

	if(EVP_DigestUpdate(MDCTX, buffer, size) == 0) {
		fprintf(stderr, "Failed to digest data!\n");
        goto error;
	}

	if(EVP_DigestFinal_ex(MDCTX, digest, &len) == 0) {
		fprintf(stderr, "Failed to get digest!\n");
        goto error;
	}

#if OPENSSL_VERSION_NUMBER < NEWER_OPENSSL_VERSION
	EVP_MD_CTX_cleanup(&c);
#else
    EVP_MD_CTX_free(c);
#endif

	return(0);

error:
#if OPENSSL_VERSION_NUMBER < NEWER_OPENSSL_VERSION
	EVP_MD_CTX_cleanup(&c);
#else
    EVP_MD_CTX_free(c);
#endif
    return(-1);
#undef MDCTX
}

int decrypt_block_special(WiiUEncryptedFile *f, char *buffer, int dataRead, int preFileData) {
	int i;
	int totalout, outl;
	int ivnum;
	char IV[16];
	char origSHA1[0x14];
	char thisSHA1[0x14];
	int outBuffOffset;
	int clusterOffset;
	int actuallyRead;
	
	clusterOffset = f->clusterOffset + f->offset;

	if(preFileData > 0 && f->size - f->offset > dataRead) {
		/* skip last partial block so next read is aligned, unless this is our only read */
		dataRead -= SPECIAL_BLOCK_SIZE;
	}

	for(i = 0; i < dataRead; i += SPECIAL_BLOCK_SIZE) {
		int dest = i / SPECIAL_BLOCK_SIZE * SPECIAL_BLOCK_DATA;
		//fprintf(stderr, "%d %d\n", i, dest);

		if(preFileData > 0) { /* unaligned */
			if(i == 0) { /* first */
				/* decrypt to the start of the buffer to be hashed then moved later */
				outBuffOffset = dest;
			} else { /* middle */
				/* decrypt whole blocks with offset */
				outBuffOffset = dest - preFileData;
			}
		} else { /* aligned */
			outBuffOffset = dest;
		}
		//fprintf(stderr, "%lld %d %d %d\n", clusterOffset, outOffset, outSize, outBuffOffset);

		/* decrypt header */
		if(crypt_aes_128_cbc(&f->buffer[i], &buffer[outBuffOffset], SPECIAL_BLOCK_HEADER, f->key, f->IV, OPENSSL_DECRYPT) < 0) {
			fprintf(stderr, "Failed to decrypt block!\n");
			return(-1);
		}

		/* weird Nintendo magic */
		ivnum = ((clusterOffset + dest) / SPECIAL_BLOCK_DATA) & 0xF;
		//fprintf(stderr, "%d\n", ivnum);
		memcpy(IV, &buffer[outBuffOffset + (ivnum * 0x14)], sizeof(IV));
		if(ivnum == 0) {
			IV[1] ^= (char)(f->cluster & 0xFF);
		}
		memcpy(origSHA1, &buffer[outBuffOffset + (ivnum * 0x14)], sizeof(origSHA1));

		/* decrypt the rest */
		if(crypt_aes_128_cbc(&f->buffer[i + SPECIAL_BLOCK_HEADER], &buffer[outBuffOffset], SPECIAL_BLOCK_DATA,
				 f->key, IV, OPENSSL_DECRYPT) < 0) {
			fprintf(stderr, "Failed to decrypt block!\n");
			return(-1);
		}

		if(sha1_digest(&buffer[outBuffOffset], SPECIAL_BLOCK_DATA, thisSHA1) != 0) {
			fprintf(stderr, "Failed to get SHA1 digest!\n");
			return(-1);
		}
		if(ivnum == 0) {
			thisSHA1[1] ^= (char)(f->cluster & 0xFF);
		}

		if(memcmp(origSHA1, thisSHA1, sizeof(thisSHA1)) != 0) {
			fprintf(stderr, "SHA1 check failed!\n");
/*			FILE *test = fopen("test.bin", "wb");
			fwrite(&f->buffer[i], 1, SPECIAL_BLOCK_HEADER, test);
			fwrite(&buffer[outBuffOffset], 1, SPECIAL_BLOCK_DATA, test);
			fclose(test);*/
			return(-1);
		}

		/* move first unaligned read so additional whole reads can be directly decrypted to out buffer */
		if(preFileData > 0 && i == 0) {
			memmove(buffer, &buffer[preFileData], SPECIAL_BLOCK_DATA - preFileData);
		}
	}

	//fprintf(stderr, "%d %d %d\n", dataRead, preFileData, i);
	if(preFileData > 0) {
		actuallyRead = ((i / SPECIAL_BLOCK_SIZE - 1) * SPECIAL_BLOCK_DATA) + (SPECIAL_BLOCK_DATA - preFileData);
	} else {
		actuallyRead = i / SPECIAL_BLOCK_SIZE * SPECIAL_BLOCK_DATA;
	}

	if(actuallyRead > f->size - f->offset) {
		return(f->size - f->offset);
	}
	
	return(actuallyRead);
}

int read_encrypted_block(WiiUEncryptedFile *f, char *buffer) {
	int dataRead, readSize, preFileData;

	if(f->size >= 0 && f->offset >= f->size) {
		fprintf(stderr, "End of file reached!\n");
		return(-1);
	}

	if(f->special == 0) {
		if(f->size > 0 && f->readSize > f->size - f->offset) {
			readSize = f->size - f->offset;
		} else {
			readSize = f->readSize;
		}

		dataRead = read_file_block(f->f, f->buffer, f->start + f->offset, FIT_TO_BLOCKS(readSize, 16));
		if(dataRead < readSize) {
			fprintf(stderr, "Failed to read!\n");
			return(-1);
		}

		if(decrypt_block(f, buffer, dataRead) < 0) {
			fprintf(stderr, "Failed to decrypt block!\n");
			return(-1);
		}
		dataRead = readSize;
	} else {
		preFileData = (f->clusterOffset + f->offset) % SPECIAL_BLOCK_DATA;
		/* if the read size in data blocks is greater than the data we have remaining to read, find the number of blocks
		   we really do need to read */
		if(f->readSize / SPECIAL_BLOCK_SIZE * SPECIAL_BLOCK_DATA > f->size - f->offset) {
			/* whole blocks */
			readSize = (f->size - f->offset) / SPECIAL_BLOCK_DATA;
			if(preFileData > 0) {
				/* block containing partial data head */
				readSize++;
				/* determine if there's a partial tail */
				if((readSize * SPECIAL_BLOCK_DATA) + (SPECIAL_BLOCK_DATA - preFileData) < f->size - f->offset) {
					readSize++;
				}
			} else {
				/* determine if there's a partial tail */
				if(readSize * SPECIAL_BLOCK_DATA < f->size - f->offset) {
					readSize++;
				}
			}
			readSize *= SPECIAL_BLOCK_SIZE;
		} else {
			/* however many blocks fit in to the buffer */
			readSize = BLOCK_START(f->readSize, SPECIAL_BLOCK_SIZE);
		}
		//fprintf(stderr, "%d %d\n", f->size, readSize);
		/* in this case, start is just the start of the cluster.  f->clusterOffset + f->offset is the current read position
		   within the cluster data, excluding headers */
		/* read whole, aligned blocks */
		dataRead = read_file_block(f->f, f->buffer, 
		                           f->start + ((f->clusterOffset + f->offset) / SPECIAL_BLOCK_DATA * SPECIAL_BLOCK_SIZE),
		                           readSize);
		//fprintf(stderr, "%d\n", dataRead);
		if(dataRead < readSize) {
			fprintf(stderr, "Failed to read!\n");
			return(-1);
		}

		dataRead = decrypt_block_special(f, buffer, dataRead, preFileData);
		//fprintf(stderr, "%d\n", dataRead);
		if(dataRead < 1) {
			fprintf(stderr, "Failed to decrypt special block!\n");
			return(-1);
		}
	}

	f->offset += dataRead;
	return(dataRead);
}

void free_encrypted_file(WiiUEncryptedFile *r) {
	free(r->buffer);
	free(r);
}

int crypt_aes_128_cbc(const unsigned char const *in, unsigned char *out, 
          const unsigned int datalen, const unsigned char const *key,
          const unsigned char const *iv, const int enc) {
#if OPENSSL_VERSION_NUMBER < NEWER_OPENSSL_VERSION
	EVP_CIPHER_CTX c;
#define CIPHERCTX (&c)
#else
	EVP_CIPHER_CTX *c;
#define CIPHERCTX (c)
#endif
	unsigned int outl;
	unsigned int totalout;

	if(enc != 0 && enc != 1) {
		fprintf(stderr, "enc must be 0 (decrypt) or 1 (encrypt)!\n");

	}

#if OPENSSL_VERSION_NUMBER < NEWER_OPENSSL_VERSION
	EVP_CIPHER_CTX_init(&c);
#else
    c = EVP_CIPHER_CTX_new();
#endif

	if(EVP_CipherInit_ex(CIPHERCTX, EVP_aes_128_cbc(), NULL, key, iv, enc) == 0) {
		fprintf(stderr, "Failed to initialize AES cipher!\n");
        goto error1;
	}
	EVP_CIPHER_CTX_set_padding(CIPHERCTX, 0);

	if(EVP_CipherUpdate(CIPHERCTX, out, &outl, in, datalen) == 0) {
		fprintf(stderr, "Failed to en/decrypt data!\n");
        goto error1;
	}
	totalout = outl;

	if(EVP_CipherFinal_ex(CIPHERCTX, out, &outl) == 0) {
		fprintf(stderr, "Failed to en/decrypt final data!\n");
        goto error1;
	}
	totalout += outl;

	if(totalout != datalen) {
		fprintf(stderr, "Different data length returned! %d %d\n", datalen, totalout);
        goto error1;
	}

#if OPENSSL_VERSION_NUMBER < NEWER_OPENSSL_VERSION
	EVP_CIPHER_CTX_cleanup(&c);
#else
    EVP_CIPHER_CTX_free(c);
#endif

	return(0);

error1:
#if OPENSSL_VERSION_NUMBER < NEWER_OPENSSL_VERSION
	EVP_CIPHER_CTX_cleanup(&c);
#else
    EVP_CIPHER_CTX_free(c);
#endif
error0:
    return(-1);
#undef CIPHERCTX
}

int find_index_of_file_by_name(const WiiUPartition *p, int start, const char *name) {
	int i;
	
	for(i = start + 1; i < p->dirEntsCount; i++) {
		if(strcmp(p->dirEnts[i]->name, name) == 0) {
			return(i);
		}
	}
	
	return(-1);
}

int get_index_of_directory_from_file_index(const WiiUPartition *p, int index) {
	int i;
	
	for(i = index - 1; i > 0; i--) {
		if(p->dirEnts[i]->type == WIIU_DIRECTORY) {
			return(i);
		}
	}

	return(0);
}
