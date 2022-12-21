#ifndef BASTOOLS_MMAP_H
#define BASTOOLS_MMAP_H

#include <stddef.h>

void *mmap_file_read(const char *name, size_t *len);
void *mmap_file_write(const char *name, size_t len);

#endif
