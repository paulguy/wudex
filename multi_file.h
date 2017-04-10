#ifndef MULTI_FILE_H
#define MULTI_FILE_H

#include <stdio.h>

#define MULTI_FILE_START_COUNT (12)

typedef struct {
	int files;
	FILE **f;
	off_t *sizes;
	int tableSize;
	int current;
} multi_FILE;

multi_FILE *multi_fopen(multi_FILE *f, const char *name);
int multi_fclose(multi_FILE *f);
int multi_fseeko(multi_FILE *f, off_t offset);
size_t multi_fread(void *ptr, size_t size, multi_FILE *f);

#endif
