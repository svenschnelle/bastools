#define _GNU_SOURCE 1
#include <stdio.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <stdint.h>

void *mmap_file_read(const char *name, size_t *len)
{
	void *ret = MAP_FAILED;
	struct stat stbuf;
	int fd;

	fd = open(name, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "%s: open: %m\n", __func__);
		return MAP_FAILED;
	}

	if (fstat(fd, &stbuf) == -1) {
		fprintf(stderr, "%s: stat: %m\n", __func__);
		goto out;
	}

	ret = mmap(NULL, stbuf.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (ret == MAP_FAILED)
		fprintf(stderr, "%s: mmap: %m\n", __func__);
	*len = stbuf.st_size;
out:
	close(fd);
	return ret;
}

void *mmap_file_write(const char *name, size_t len)
{
	void *ret = MAP_FAILED;
	int fd;

	fd = open(name, O_RDWR|O_TRUNC|O_CREAT, 0644);
	if (fd == -1) {
		fprintf(stderr, "%s: open: %m\n", __func__);
		return MAP_FAILED;
	}

	if (lseek(fd, len - 1, SEEK_SET) == -1) {
		fprintf(stderr, "%s: lseek: %m\n", __func__);
		goto out;
	}
	if (write(fd, "", 1) == -1) {
		fprintf(stderr, "%s: write: %m\n", __func__);
		goto out;
	}

	ret = mmap(NULL, len, PROT_WRITE, MAP_SHARED, fd, 0);
	if (ret == MAP_FAILED)
		fprintf(stderr, "%s: mmap: %m\n", __func__);
out:
	close(fd);
	return ret;
}
