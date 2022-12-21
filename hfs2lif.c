#define _GNU_SOURCE 1
#include <stdio.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <stdint.h>
#include "mmap.h"

static const char hfshdr[] = {
	0x80, 0x00, 'H', 'F', 'S', 'L', 'I', 'F'
};

int main(int argc, char **argv)
{
	uint8_t *in, *out;
	size_t inlen;

	if (argc < 3) {
		fprintf(stderr, "%s: usage: %s <infile> <outfile>\n", argv[0], argv[0]);
		return 1;
	}

	in = mmap_file_read(argv[1], &inlen);
	if (in == MAP_FAILED)
		return 1;

	if (memcmp(in, hfshdr, sizeof(hfshdr))) {
		fprintf(stderr, "invalid lif header\n");
		return 1;
	}
	if (inlen < 480) {
		fprintf(stderr, "file to small\n");
		munmap(in, inlen);
		return 1;
	}
	out = mmap_file_write(argv[2], inlen - 480);
	if (out == MAP_FAILED)
		return 1;
	memcpy(out, in + 256, 32);
	memcpy(out + 32, in + 512, inlen - 512);
	msync(out, inlen - 480, MS_SYNC);
	munmap(out, inlen - 480);
	munmap(in, inlen);
	return 0;
}
