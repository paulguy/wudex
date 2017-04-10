#include "wiiudisc.h"
#include "util.h"
#include "multi_file.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <endian.h>
#include <strings.h>

const char DISC_SIGNATURE[] = { 0x57, 0x55, 0x50, 0x2D }; // "WUP-"
const char TOC_SIGNATURE[] = { 0xCC, 0xA6, 0xE6, 0x7B }; 
const char FILE_TABLE_SIGNATURE[] = { 0x46, 0x53, 0x54, 0x00 };

const char UNENCRYPTED_PREFIXES[][2] = {{'S', 'I'}, {'G', 'I'}, {'U', 'P'}};

const char TICKET_FILENAME[] = "title.tik";
#define UNENCRYPTED_PREFIX_SIZE (sizeof(UNENCRYPTED_PREFIXES[0]))
#define UNENCRYPTED_PREFIXES_COUNT (sizeof(UNENCRYPTED_PREFIXES) / UNENCRYPTED_PREFIX_SIZE)

#define READ_BE32_FROM_BUFFER(BUFF, LOC) (be32toh(*(int *)&(BUFF[LOC])))
#define READ_BE16_FROM_BUFFER(BUFF, LOC) (be16toh(*(short int *)&(BUFF[LOC])))

WiiUDisc *init_wiiu_disc() {
	WiiUDisc *w;

	w = malloc(sizeof(WiiUDisc));
	if(w == NULL) {
		fprintf(stderr, "Failed to allocate memory!\n");
		return(NULL);
	}

	w->fileTableBuffer = NULL;
	w->partitionsCount = 0;
	w->partitionsMemory = NULL;
	w->partitions = NULL;

	return(w);
}

void free_wiiu_disc(WiiUDisc *w) {
	int i;
	for(i = 0; i < w->partitionsCount; i++) {
		if(w->partitions[i]->dirEntsMemory != NULL)
			free(w->partitions[i]->dirEntsMemory);
		if(w->partitions[i]->dirEnts != NULL)
			free(w->partitions[i]->dirEnts);
	}
	for(i = 0; i < w->partitionsCount; i++) {
		if(w->partitions[i]->clustersMemory != NULL)
			free(w->partitions[i]->clustersMemory);
		if(w->partitions[i]->clusters != NULL)
			free(w->partitions[i]->clusters);
	}

	if(w->partitionsMemory != NULL)
		free(w->partitionsMemory);
	if(w->partitions != NULL)
		free(w->partitions);
	if(w->fileTableBuffer != NULL)
		free(w->fileTableBuffer);
	free(w);
}

void buffer_to_dirEnt(char *buffer, WiiUDirEnt *d) {
	if(buffer[0] == 1) {
		d->type = WIIU_DIRECTORY;
		d->nextEntry = READ_BE32_FROM_BUFFER(buffer, 8);
		d->size = 0;
	} else {
		d->type = WIIU_FILE;
		d->size = READ_BE32_FROM_BUFFER(buffer, 8);
		d->nextEntry = 0;
	}

	d->nameOffset = READ_BE32_FROM_BUFFER(buffer, 0) & 0x00FFFFFF;
	d->clusterOffset = (long long int)READ_BE32_FROM_BUFFER(buffer, 4) << 5LL;
	d->flags = READ_BE16_FROM_BUFFER(buffer, 0xC);
	d->cluster = READ_BE16_FROM_BUFFER(buffer, 0xE);
}

int populate_partition_table(WiiUDisc *w) {
	WiiUEncryptedFile *f;
	unsigned int i, j;
	char *toc;

	f = open_encrypted_file(w, -1, -1);
	if(f == NULL) {
		fprintf(stderr, "Failed to open encrypted disc region!\n");
		goto error0;
	}

	toc = malloc(f->readSize);
	if(toc == NULL) {
		fprintf(stderr, "Failed to allocate memory!\n");
		goto error1;
	}

	if(read_encrypted_block(f, toc) < f->readSize) {
		fprintf(stderr, "Failed to read TOC!\n");
		goto error2;
	}

	if(memcmp(toc, TOC_SIGNATURE, sizeof(TOC_SIGNATURE)) != 0) {
		fprintf(stderr, "Invalid TOC signature!\n");
		goto error2;
	}

	w->partitionsCount = READ_BE32_FROM_BUFFER(toc, 0x1C);

	w->partitionsMemory = malloc(sizeof(WiiUPartition) * w->partitionsCount);
	if(w->partitionsMemory == NULL) {
		fprintf(stderr, "Failed to allocate memory!\n");
		goto error2;
	}
	w->partitions = malloc(sizeof(WiiUPartition *) * w->partitionsCount);
	if(w->partitions == NULL) {
		fprintf(stderr, "Failed to allocate memory!\n");
		goto error3;
	}

	for(i = 0; i < w->partitionsCount; i++) {
		w->partitions[i] = (WiiUPartition *)&(w->partitionsMemory[i * sizeof(WiiUPartition)]);

		memcpy(w->partitions[i]->id, &(toc[PARTITION_TOC_OFFSET + (i * PARTITION_TOC_ENTRY_SIZE)]), 0x19);
		w->partitions[i]->id[PARTITIONIDSIZE] = '\0';

		w->partitions[i]->offset =
			(long long int)READ_BE32_FROM_BUFFER(toc, PARTITION_TOC_OFFSET + (i * PARTITION_TOC_ENTRY_SIZE) + 0x20) 
			* BLOCKSIZE - 0x10000LL + DECRYPTED_AREA_POS;

		/* Insert disc key for partitions not title key encrypted. */
		for(j = 0; j < UNENCRYPTED_PREFIXES_COUNT; j++) {
			if(memcmp(UNENCRYPTED_PREFIXES[j], w->partitions[i]->id, UNENCRYPTED_PREFIX_SIZE) == 0) {
				memcpy(w->partitions[i]->key, w->discKey, KEYSIZE);
			}
		}

		w->partitions[i]->clustersCount = 0;
		w->partitions[i]->clustersMemory = NULL;
		w->partitions[i]->clusters = NULL;
		w->partitions[i]->dirEntsCount = 0;
		w->partitions[i]->dirEntsMemory = NULL;
		w->partitions[i]->dirEnts = NULL;

		/* Keys and IVs for encrypted partitions will come later. */
	}

	free(toc);
	free_encrypted_file(f);
	return(0);

error3:
	free(w->partitionsMemory);
	w->partitionsMemory = NULL;
	w->partitionsCount = 0;
error2:
	free(toc);
error1:
	free_encrypted_file(f);
error0:
	return(-1);
}

int populate_file_tree(WiiUDisc *w, int part) {
	int i;
	size_t fileTableBufferSize, clusterTableSize, dirEntsSize, entryNamesSize;
	char *temp;
	WiiUDirEnt rootDir;
	WiiUEncryptedFile *f;

	WiiUPartition *p = w->partitions[part];

	f = open_encrypted_file(w, part, -1);
	if(f == NULL) {
		fprintf(stderr, "Failed to open partition!\n");
		goto error0;
	}

	fileTableBufferSize = f->readSize;
	w->fileTableBuffer = malloc(fileTableBufferSize);
	if(w->fileTableBuffer == NULL) {
		fprintf(stderr, "Failed to allocate memory!\n");
		goto error1;
	}

	if(read_encrypted_block(f, w->fileTableBuffer) < f->readSize) {
		fprintf(stderr, "Failed to read first file table block!\n");
		goto error2;
	}

	if(memcmp(w->fileTableBuffer, FILE_TABLE_SIGNATURE, sizeof(FILE_TABLE_SIGNATURE)) != 0) {
		fprintf(stderr, "Invalid file table signature!\n");
		goto error2;
	}

	p->clustersCount = READ_BE32_FROM_BUFFER(w->fileTableBuffer, 8);
	p->clustersMemory = malloc(sizeof(WiiUCluster) * p->clustersCount);
	if(p->clustersMemory == NULL) {
		fprintf(stderr, "Failed to allocate memory!\n");
		goto error2;
	}
	p->clusters = malloc(sizeof(WiiUCluster *) * p->clustersCount);
	if(p->clusters == NULL) {
		fprintf(stderr, "Failed to allocate memory!\n");
		goto error3;
	}

	/* if the cluster table is larger than the block we've read, read the rest in */
	clusterTableSize = CLUSTER_DESCRIPTOR_SIZE * p->clustersCount + FILE_BLOCK_HEADER_SIZE;
	if(fileTableBufferSize < clusterTableSize) {
		temp = realloc(w->fileTableBuffer, FIT_TO_BLOCKS(clusterTableSize, f->readSize));
		if(temp == NULL) {
			fprintf(stderr, "Failed to allocate memory!\n");
			goto error4;
		}
		w->fileTableBuffer = temp;

		for(i = fileTableBufferSize; i < clusterTableSize; i += f->readSize) {
			if(read_encrypted_block(f, &w->fileTableBuffer[i]) < f->readSize) {
				fprintf(stderr, "Couldn't read more cluster table!\n");
				goto error4;
			}
		}
		fileTableBufferSize = FIT_TO_BLOCKS(clusterTableSize, f->readSize);
	}

	for(i = 0; i < p->clustersCount; i++) {
		p->clusters[i] = (WiiUCluster *)&(p->clustersMemory[i * sizeof(WiiUCluster)]);

		p->clusters[i]->offset =
			(long long int)READ_BE32_FROM_BUFFER(w->fileTableBuffer, FILE_BLOCK_HEADER_SIZE + (CLUSTER_DESCRIPTOR_SIZE * i)) * BLOCKSIZE;

		/* original code had this */
		if(p->clusters[i]->offset > 0) {
			p->clusters[i]->offset -= BLOCKSIZE;
		}
		
		p->clusters[i]->size =
			(long long int)READ_BE32_FROM_BUFFER(w->fileTableBuffer, FILE_BLOCK_HEADER_SIZE + (CLUSTER_DESCRIPTOR_SIZE * i) + 4)
			* BLOCKSIZE;

		p->clusters[i]->flags0 =
			READ_BE32_FROM_BUFFER(w->fileTableBuffer, FILE_BLOCK_HEADER_SIZE + (CLUSTER_DESCRIPTOR_SIZE * i) + 0x10);
		p->clusters[i]->flags1 =
			READ_BE32_FROM_BUFFER(w->fileTableBuffer, FILE_BLOCK_HEADER_SIZE + (CLUSTER_DESCRIPTOR_SIZE * i) + 0x14);

		//fprintf(stderr, "%d %lld %lld %08X %08X\n", i, p->clusters[i]->offset, p->clusters[i]->size, p->clusters[i]->flags0, p->clusters[i]->flags1);
		
	}

	/* Start reading in directories */

	/* if our buffer doesn't contain the root directory entry, read it in */
	if(fileTableBufferSize < clusterTableSize + DIRENT_SIZE) {
		temp = realloc(w->fileTableBuffer, FIT_TO_BLOCKS(clusterTableSize + DIRENT_SIZE, f->readSize));
		if(temp == NULL) {
			fprintf(stderr, "Failed to allocate memory!\n");
			goto error4;
		}
		w->fileTableBuffer = temp;

		if(read_encrypted_block(f, &w->fileTableBuffer[clusterTableSize]) < f->readSize) {
			fprintf(stderr, "Couldn't read root directory!\n");
			goto error4;
		}
		fileTableBufferSize = FIT_TO_BLOCKS(clusterTableSize + DIRENT_SIZE, f->readSize);
	}

	buffer_to_dirEnt(&w->fileTableBuffer[clusterTableSize], &rootDir);

	if(rootDir.type != WIIU_DIRECTORY) {
		fprintf(stderr, "Root is not a directory!\n");
		goto error4;
	}
	p->dirEntsCount = rootDir.nextEntry;

	/* if the directory entry table is larger than the block we've read, read the rest in */
	dirEntsSize = DIRENT_SIZE * p->dirEntsCount;
	if(fileTableBufferSize < clusterTableSize + dirEntsSize) {
		temp = realloc(w->fileTableBuffer, FIT_TO_BLOCKS(clusterTableSize + dirEntsSize, f->readSize));
		if(temp == NULL) {
			fprintf(stderr, "Failed to allocate memory!\n");
			goto error4;
		}
		w->fileTableBuffer = temp;

		for(i = fileTableBufferSize; i < clusterTableSize + dirEntsSize; i += f->readSize) {
			if(read_encrypted_block(f, &w->fileTableBuffer[i]) < f->readSize) {
				fprintf(stderr, "Couldn't read more directories!\n");
				goto error4;
			}
		}
		fileTableBufferSize = FIT_TO_BLOCKS(clusterTableSize + dirEntsSize, f->readSize);
	}

	p->dirEntsMemory = malloc(sizeof(WiiUDirEnt) * p->dirEntsCount);
	if(p->dirEntsMemory == NULL) {
		fprintf(stderr, "Failed to allocate memory!\n");
		goto error4;
	}
	p->dirEnts = malloc(sizeof(WiiUDirEnt *) * p->dirEntsCount);
	if(p->dirEnts == NULL) {
		fprintf(stderr, "Failed to allocate memory!\n");
		goto error5;
	}

	for(i = 0; i < p->dirEntsCount; i++) {
		p->dirEnts[i] = (WiiUDirEnt *)&(p->dirEntsMemory[i * sizeof(WiiUDirEnt)]);

		buffer_to_dirEnt(&w->fileTableBuffer[clusterTableSize + DIRENT_SIZE * i], p->dirEnts[i]);
		if(p->dirEnts[i]->cluster > p->clustersCount) {
			fprintf(stderr, "Directory entry references cluster out of range!\n");
			goto error6;
		}
	}

	/* heuristic, try to find where the directory entries table ends by finding the physically first cluster */
	off_t lowestCluster = 0;
	for(i = 0; i < p->clustersCount; i++) {
		if(p->clusters[i]->size == 0) {
			continue;
		}

		if(lowestCluster == 0) {
			lowestCluster = p->clusters[i]->offset;
			continue;
		}

		if(p->clusters[i]->offset < lowestCluster) {
			lowestCluster = p->clusters[i]->offset;
		}
	}
	if(lowestCluster == 0) {
		fprintf(stderr, "No non-zero size clusters!\n");
		goto error6;
	}

	/* if the entry names block is larger than the block we've read, read the rest in */
	entryNamesSize = lowestCluster - (clusterTableSize + dirEntsSize);
	if(fileTableBufferSize < clusterTableSize + dirEntsSize + entryNamesSize) {
		temp = realloc(w->fileTableBuffer, FIT_TO_BLOCKS(clusterTableSize + dirEntsSize + entryNamesSize, f->readSize));
		if(temp == NULL) {
			fprintf(stderr, "Failed to allocate memory!\n");
			goto error6;
		}
		w->fileTableBuffer = temp;

		for(i = fileTableBufferSize; i < clusterTableSize + dirEntsSize + entryNamesSize; i += f->readSize) {
			if(read_encrypted_block(f, &w->fileTableBuffer[i]) < f->readSize) {
				fprintf(stderr, "Couldn't read more directory entry names!\n");
				goto error6;
			}
		}
		fileTableBufferSize = FIT_TO_BLOCKS(clusterTableSize + dirEntsSize + entryNamesSize, f->readSize);
	}

	/* and now we're done with all the previous data, so move the memory back */
	memmove(w->fileTableBuffer, &w->fileTableBuffer[clusterTableSize + dirEntsSize], entryNamesSize);
	/* and free what's left */
	temp = realloc(w->fileTableBuffer, entryNamesSize);
	if(temp == NULL) {
		fprintf(stderr, "Failed to allocate memory!\n");
		goto error6;
	}
	w->fileTableBuffer = temp;

	for(i = 0; i < p->dirEntsCount; i++) {
		if(p->dirEnts[i]->nameOffset > entryNamesSize) {
			fprintf(stderr, "Entry name offset out of range!\n");
			goto error6;
		}
		p->dirEnts[i]->name = &w->fileTableBuffer[p->dirEnts[i]->nameOffset];
		/*fprintf(stderr, "%d: %s %d %d %d %d %hd %lld %04hX\n", i, p->dirEnts[i]->name, p->dirEnts[i]->type, p->dirEnts[i]->size,
				p->dirEnts[i]->nextEntry, p->dirEnts[i]->nameOffset, p->dirEnts[i]->cluster, p->dirEnts[i]->clusterOffset,
				p->dirEnts[i]->flags);*/
	}

	/* don't free fileTableBuffer, because filenames are referenced from it */
	free_encrypted_file(f);
	return(0);

error6:
	free(p->dirEnts);
	p->dirEnts = NULL;
error5:
	free(p->dirEntsMemory);
	p->dirEntsMemory = NULL;
error4:
	p->dirEntsCount = 0;
	free(p->clusters);
	p->clusters = NULL;
error3:
	free(p->clustersMemory);
	p->clustersMemory = NULL;
error2:
	p->clustersCount = 0;
	free(w->fileTableBuffer);
	w->fileTableBuffer = NULL;
error1:
	free_encrypted_file(f);
error0:
	return(-1);
}

int populate_file_trees(WiiUDisc *w) {
	int i, j;
	char *encKey;
	char *titleID;
	int partitionKey;
	char IV[16];

	/* Read (and scan for tickets in) unencrypted partitions first */
	for(i = 0; i < w->partitionsCount; i++) {
		for(j = 0; j < UNENCRYPTED_PREFIXES_COUNT; j++) {
			if(memcmp(UNENCRYPTED_PREFIXES[j], w->partitions[i]->id, UNENCRYPTED_PREFIX_SIZE) == 0) {
				if(populate_file_tree(w, i) != 0) {
					fprintf(stderr, "Failed to populate file tree for %s!\n", w->partitions[i]->id);
					return(-1);
				}

				/* scan for tickets */
				if(w->partitions[i]->id[0] == 'S' && w->partitions[i]->id[1] == 'I') {
					int tikindex = 0;
					for(;;) {
						tikindex = find_index_of_file_by_name(w->partitions[i], tikindex, TICKET_FILENAME);

						if(tikindex == -1) {
							break;
						}

						if(w->partitions[i]->dirEnts[tikindex]->type == WIIU_DIRECTORY) {
							fprintf(stderr, "%s found as directory?\n", TICKET_FILENAME);
							continue;
						}
						
						if(w->partitions[i]->dirEnts[tikindex]->size > 65536) {
							fprintf(stderr, "Very large ticket?  Not going to try.\n");
							return(-1);
						}
						char ticket[w->partitions[i]->dirEnts[tikindex]->size];

						WiiUEncryptedFile *f = open_encrypted_file(w, i, tikindex);
						if(f == NULL) {
							fprintf(stderr, "Failed to open disc file!\n");
							return(-1);
						}

						//fprintf(stderr, "%d\n", f->special);

						if(read_encrypted_block(f, ticket) < w->partitions[i]->dirEnts[tikindex]->size) {
							fprintf(stderr, "Couldn't read ticket!\n");
							free_encrypted_file(f);
							return(-1);
						}
/*
						FILE *test = fopen("test.bin", "wb");
						fwrite(ticket, 1, w->partitions[i]->dirEnts[tikindex]->size, test);
						fclose(test);
*/
						free_encrypted_file(f);

						partitionKey = 
							atoi(w->partitions[i]->dirEnts[get_index_of_directory_from_file_index(w->partitions[i], tikindex)]->name);
						if(partitionKey == 0) {
							fprintf(stderr, "Key for partition 0!\n");
							return(-1);
						}
						/* get the encrypted key, decrypt it using the common key and title ID as IV */
						encKey = &ticket[0x1BF];
						titleID = &ticket[0x1DC];
						bzero(IV, KEYSIZE);
						memcpy(IV, titleID, 8);
						if(crypt(encKey, w->partitions[partitionKey]->key, KEYSIZE, w->commonKey, IV, OPENSSL_DECRYPT) != 0) {
							fprintf(stderr, "Failed to decrypt partition key for %d!\n", partitionKey);
							return(-1);
						}

						fprintf(stderr, "Key found for %d!\n", partitionKey);
					}
				}
				break;
			}
		}
	}

	/* Read encrypted partitions */
	for(i = 0; i < w->partitionsCount; i++) {
		for(j = 0; j < UNENCRYPTED_PREFIXES_COUNT; j++) {
			if(memcmp(UNENCRYPTED_PREFIXES[j], w->partitions[i]->id, UNENCRYPTED_PREFIX_SIZE) == 0) {
				break;
			}
		}
		if(j == UNENCRYPTED_PREFIXES_COUNT) {
			if(populate_file_tree(w, i) != 0) {
				fprintf(stderr, "Failed to populate file tree for %s!\n", w->partitions[i]->id);
				return(-1);
			}
		}
		if(i == 3) break;
	}

	return(0);
}

WiiUDisc *wiiu_read_disc_structure(multi_FILE *in, const char *commonKey, const char *discKey) {
	WiiUDisc *w;
	int i;

	w = init_wiiu_disc();
	if(w == NULL) {
		fprintf(stderr, "Failed to initialize WiiU disc context!\n");
		goto error0;
	}

	w->f = in;

	memcpy(w->commonKey, commonKey, KEYSIZE);
	memcpy(w->discKey, discKey, KEYSIZE);

	if(read_unterminated_string(in, SERIALSIZE, w->serial) != 0) {
		fprintf(stderr, "Failed to read serial!\n");
		goto error1;
	}
	if(read_unterminated_string_from(in, REVISIONPOS, REVISIONSIZE, w->revision) != 0) {
		fprintf(stderr, "Failed to read revision!\n");
		goto error1;
	}
	if(read_unterminated_string_from(in, SYSTEMMENUVERSIONPOS, SYSTEMMENUVERSIONSIZE, w->systemMenuVersion) != 0) {
		fprintf(stderr, "Failed to read system menu version!\n");
		goto error1;
	}
	if(read_unterminated_string_from(in, REGIONPOS, REGIONSIZE, w->region) != 0) {
		fprintf(stderr, "Failed to read region!\n");
		goto error1;
	}

	if(memcmp(w->serial, DISC_SIGNATURE, sizeof(DISC_SIGNATURE)) != 0) {
		fprintf(stderr, "Invalid disc signature!  Trying to continue anyway...\n");
	}

	if(populate_partition_table(w) != 0) {
		fprintf(stderr, "Failed to populate partition table!\n");
		goto error1;
	}

	if(populate_file_trees(w) != 0) {
		fprintf(stderr, "Failed to populate file trees!\n");
		goto error1;
	}

	return(w);

error1:
	free_wiiu_disc(w);
error0:
	return(NULL);
}
