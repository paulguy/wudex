#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include "wiiudisc.h"
#include "util.h"

#define MAX_PATH_DEPTH (16)

int read_key_file(char *keyBuff, char *fileName);
int make_dir_and_go(const char *name);
int go_up_dir();

int main(int argc, char **argv) {
	FILE *wudFile;
	FILE *out;
	char *outDir = NULL;
	int partitionNum = -1;
	char commonKey[KEYSIZE];
	char discKey[KEYSIZE];
	WiiUDisc *w;
	int i, j, k;
	WiiUEncryptedFile *f;
	char *readBuffer = NULL;

	if(argc < 4) {
		fprintf(stderr, "USAGE: wudex <WUD filename> <common key> <disc key> [output dir]\n");
		goto error0;
	}

	wudFile = fopen(argv[1], "rb");
	if(wudFile == NULL) {
		fprintf(stderr, "Failed to open %s for read!\n", argv[1]);
		goto error0;
	}

	if(read_key_file(commonKey, argv[2]) < 0) {
		fprintf(stderr, "Failed to read common key from file %s!\n", argv[3]);
		goto error1;
	}

	if(read_key_file(discKey, argv[3]) < 0) {
		fprintf(stderr, "Failed to read disc key from file %s!\n", argv[4]);
		goto error1;
	}

	if(argc > 4) {
		outDir = argv[4];
	}

	w = wiiu_read_disc_structure(wudFile, commonKey, discKey);
	if(w == NULL) {
		fprintf(stderr, "Failed to read disc structure!\n");
		goto error1;
	}

	fprintf(stderr, "----- Disc Info -----\n"
	                "Serial             : %s\n"
	                "Revision           : %s\n"
	                "System Menu Version: %s\n"
	                "Region             : %s\n",
	        w->serial, w->revision, w->systemMenuVersion, w->region);

	fprintf(stderr, "\n----- Partition Table -----\n"
	                "##: Name                      Offset\n");
	for(i = 0; i < w->partitionsCount; i++) {
		fprintf(stderr, "%02d: %-25s %llu\n", i, w->partitions[i]->id, (long long int)w->partitions[i]->offset);
	}

	fprintf(stderr, "\n----- File Table -----\n");
	if(outDir != NULL) {
		if(make_dir_and_go(outDir) < 0) {
			fprintf(stderr, "Failed to create directory %s!\n", outDir);
			goto error2;
		}
	}
	for(j = 0; j < w->partitionsCount; j++) {
		WiiUPartition *p = w->partitions[j];
		fprintf(stderr, "Partition %d: %s\n", j, p->id);

		if(outDir != NULL) {
			if(make_dir_and_go(p->id) < 0) {
				fprintf(stderr, "Failed to create directory %s!\n", p->id);
				goto error3;
			}
		}

		int path[MAX_PATH_DEPTH];
		int pathdepth = 1;
		path[0] = 0;
		for(i = 1; i < p->dirEntsCount; i++) {
			if(i == p->dirEnts[path[pathdepth - 1]]->nextEntry) {
				pathdepth--;
				if(pathdepth == 0) {
					fprintf(stderr, "Path traversal went up too far!\n");
				}

				if(outDir != NULL) {
					if(go_up_dir() < 0) {
						fprintf(stderr, "Failed to go up a directory!\n");
						goto error3;
					}
				}

				i--;
				continue;
			}

			//fwrite(space, 1, pathdepth, stderr);
			for(k = 1; k < pathdepth; k++) {
				fprintf(stderr, "/%s", p->dirEnts[path[k]]->name);
			}
			fprintf(stderr, "/%s\n", p->dirEnts[i]->name);

			if(outDir != NULL) {
				if(p->dirEnts[i]->type == WIIU_DIRECTORY) {
					if(pathdepth == 16) {
						fprintf(stderr, "Path went too deep!\n");
						goto error3;
					}

					if(make_dir_and_go(p->dirEnts[i]->name) < 0) {
						fprintf(stderr, "Failed to create directory %s!\n", p->dirEnts[i]->name);
						goto error3;
					}

					path[pathdepth] = i;
					pathdepth++;
				} else {
					out = fopen(p->dirEnts[i]->name, "rb");
					if(out == NULL) {
						out = fopen(p->dirEnts[i]->name, "wb");
						if(out == NULL) {
							fprintf(stderr, "Failed to open file!\n");
							goto error3;
						}

						f = open_encrypted_file(w, j, i);
						if(f == NULL) {
							fprintf(stderr, "Failed to open disc file!\n");
							fclose(out);
							goto error3;
						}

						if(f->size > 0) {
							if(readBuffer == NULL) {
								readBuffer = malloc(f->readSize);
								if(readBuffer == NULL) {
									fprintf(stderr, "Failed to allocate memory!\n");
									fclose(out);
									goto error2;
								}
							}

							int bytesRead;
							while(f->offset < f->size) {
								bytesRead = read_encrypted_block(f, readBuffer);
								if(bytesRead < 1) {
									fprintf(stderr, "Couldn't read file!\n");
									free_encrypted_file(f);
									fclose(out);
									goto error3;
								}

								if(fwrite(readBuffer, 1, bytesRead, out) < bytesRead) {
									fprintf(stderr, "Failed to write to file!\n");
									free_encrypted_file(f);
									fclose(out);
									goto error3;
								}
							}
						}

						free_encrypted_file(f);
					}
					fclose(out);
				}
			}
		}

		/* return to extraction root */
		for(i = 1; i <= pathdepth; i++) {
			if(go_up_dir() < 0) {
				fprintf(stderr, "Failed to go up a directory!\n");
				goto error3;
			}
		}

		fprintf(stderr, "\n");
	}

	if(readBuffer != NULL)
		free(readBuffer);
	free_wiiu_disc(w);
	fclose(wudFile);
	exit(EXIT_SUCCESS);

error3:
	if(readBuffer != NULL)
		free(readBuffer);
error2:
	free_wiiu_disc(w);
error1:
	fclose(wudFile);
error0:
	exit(EXIT_FAILURE);
}

int read_key_file(char *keyBuff, char *fileName) {
	FILE *keyFile;

	keyFile = fopen(fileName, "rb");
	if(keyFile == NULL) {
		fprintf(stderr, "Failed to open %s for read!\n", fileName);
		return(-1);
	}

	if(fread(keyBuff, 1, KEYSIZE, keyFile) < KEYSIZE) {
		fprintf(stderr, "Short read from %s!\n", fileName);
		return(-1);
	}

	fclose(keyFile);

	return(0);
}

int make_dir_and_go(const char *name) {
	if(mkdir(name, 0755) < 0 && errno != EEXIST) {
		fprintf(stderr, "Failed to create directory %s: %s!\n", name, strerror(errno));
		return(-1);
	}

	if(chdir(name) < 0) {
		fprintf(stderr, "Failed to change directory %s: %s!\n", name, strerror(errno));
		return(-1);
	}

	return(0);
}

int go_up_dir() {
	if(chdir("..") < 0) {
		fprintf(stderr, "Failed to go up a dir: %s!\n", strerror(errno));
		return(-1);
	}

	return(0);
}
