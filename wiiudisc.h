#ifndef WIIUDISC_H
#define WIIUDISC_H

#include "multi_file.h"
#include <openssl/evp.h>

#define BLOCKSIZE (0x8000)

#define DECRYPTED_AREA_POS (BLOCKSIZE * 3)
#define TOCSIZE BLOCKSIZE

#define PARTITION_TOC_OFFSET (0x800)
#define PARTITION_TOC_ENTRY_SIZE (0x80)

#define KEYSIZE (16)

#define SERIALSIZE (10)

#define REVISIONPOS (0xB)
#define REVISIONSIZE (2)

#define SYSTEMMENUVERSIONPOS (0xE)
#define SYSTEMMENUVERSIONSIZE (3)

#define REGIONPOS (0x11)
#define REGIONSIZE (3)

#define PARTITIONIDSIZE (0x19)

#define FILE_BLOCK_HEADER_SIZE (0x20)
#define CLUSTER_DESCRIPTOR_SIZE (0x20)

#define DIRENT_SIZE (0x10)

typedef enum {
	WIIU_DIRECTORY,
	WIIU_FILE
} WiiUFileType;

typedef struct {
	WiiUFileType type;
	int size;
	int nextEntry;
	int nameOffset;
	short int cluster;
	long long int clusterOffset;
	short int flags;

	/* derived values */
	char *name;
} WiiUDirEnt;

typedef struct {
	off_t offset;
	size_t size;
	int flags0;
	int flags1;
} WiiUCluster;

typedef struct {
	off_t offset;
	char id[PARTITIONIDSIZE + 1];
	char key[KEYSIZE];
//	char IV[KEYSIZE];

	int clustersCount;
	char *clustersMemory;
	WiiUCluster **clusters;

	int dirEntsCount;
	char *dirEntsMemory;
	WiiUDirEnt **dirEnts;
} WiiUPartition;

typedef struct {
	multi_FILE *f;
	char commonKey[KEYSIZE];
	char discKey[KEYSIZE];
	char serial[SERIALSIZE + 1];
	char revision[REVISIONSIZE + 1];
	char systemMenuVersion[SYSTEMMENUVERSIONSIZE + 1];
	char region[REGIONSIZE + 1];

	char *fileTableBuffer;

	unsigned int partitionsCount;
	char *partitionsMemory;
	WiiUPartition **partitions;
} WiiUDisc;

WiiUDisc *wiiu_read_disc_structure(multi_FILE *in, const char *commonKey, const char *discKey);
void free_wiiu_disc(WiiUDisc *w);

#endif
