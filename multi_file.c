#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "multi_file.h"

multi_FILE *multi_fopen(multi_FILE *f, const char *name) {
	int modeLen;

	/* create it if it doesn't exist */
	if(f == NULL) {
		f = malloc(sizeof(multi_FILE));
		if(f == NULL) {
			goto error0;
		}

		f->current = 0;
		f->files = 0;
		f->tableSize = MULTI_FILE_START_COUNT;
		f->f = malloc(sizeof(FILE *) * f->tableSize);
		if(f->f == NULL) {
			goto error1;
		}
		f->sizes = malloc(sizeof(off_t) * f->tableSize);
		if(f->sizes == NULL) {
			goto error2;
		}
	}

	/* expand buffers if needed */
	if(f->files == f->tableSize) {
		f->tableSize *= 2;
		FILE **ftemp = realloc(f->f, sizeof(FILE *) * f->tableSize);
		if(ftemp == NULL) {
			goto error3;
		}

		int *sizestemp = realloc(f->sizes, sizeof(off_t) * f->tableSize);
		if(sizestemp == NULL) {
			goto error3;
		}
	}

	f->f[f->files] = fopen(name, "rb");
	if(f->f[f->files] == NULL) {
		goto error3;
	}

	if(fseeko(f->f[f->files], 0, SEEK_END) < 0) {
		goto error3;
	}

	f->sizes[f->files] = ftello(f->f[f->files]);
	if(f->sizes[f->files] < 0) {
		goto error3;
	}
	if(f->sizes[f->files] == 0) { /* zero length files have no effect, so don't open them */
		fclose(f->f[f->files]);
	} else {
		if(fseeko(f->f[f->files], 0, SEEK_SET) < 0) {
			goto error3;
		}

		f->files++;
	}

	return(f);

error3:
	free(f->sizes);
error2:
	free(f->f);
error1:
	free(f);
error0:
	return(NULL);	
}

int multi_fclose(multi_FILE *f) {
	int ret, r;
	int i;

	ret = 0;
	for(i = 0; i < f->files; i++) {
		r = fclose(f->f[i]);
		if(r != 0) {
			ret = r;
		}
	}

	free(f->sizes);
	free(f->f);
	free(f);

	return(ret);
}
	
int multi_fseeko(multi_FILE *f, off_t offset) {
	int i;
	
	for(i = 0; i < f->files; i++) {
		if(offset < f->sizes[i]) {
			f->current = i;
			return(fseeko(f->f[f->current], offset, SEEK_SET));
		}
		offset -= f->sizes[i];
	}

	return(-1);
}

size_t multi_fread(void *ptr, size_t size, multi_FILE *f) {
	size_t totalRead = 0;

	for(;;) {
		totalRead += fread(&((char *)ptr)[totalRead], 1, size <= f->sizes[f->current] ? size : f->sizes[f->current], f->f[f->current]);
		if(totalRead < size) {
			if(f->current == f->files) {
				break;
			}
			f->current++;
			if(fseeko(f->f[f->current], 0, SEEK_SET) < 0) {
				break;
			}
		} else {
			break;
		}
	}

	return(totalRead);
}
