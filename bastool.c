#define _GNU_SOURCE 1
#include <stdio.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include "mmap.h"

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))
#define OPTION_COUNT 80 /* What is the maximum option number? */

#define __packed __attribute__((packed));

struct lifhdr {
	char name[10];
	uint16_t type;
	uint32_t loc;
	uint32_t size;
	uint16_t tim0;
	uint16_t tim1;
	uint16_t tim2;
	uint16_t volnr;
	uint32_t entry;
} __packed;

struct module {
	uint32_t length;
	uint32_t _unknown[6];
	uint32_t offset_desc;
} __packed;

struct basichdr {
	struct lifhdr lif;
	uint32_t loadaddr;
	uint32_t modules_length;
	struct module modules[0];
} __packed;


struct option_entry {
	char *name;
	void *buf;
	size_t maplen;
	size_t writelen;
	size_t pos;
	int fd;
};

struct option_entry options[256] = { 0 };

#define LIF_ALIGN(x, align) ((x + align) & ~(align-1))

static void write_file(char *name, char *lif, void *buf, size_t len, size_t align)
{
	size_t maplen = LIF_ALIGN(len, align);
	char *map;

	map = mmap_file_write(name, sizeof(struct lifhdr) + maplen);
	if (map == MAP_FAILED)
		return;

	memcpy(map, lif, sizeof(struct lifhdr));
	memcpy(map + sizeof(struct lifhdr) + 4, buf, len);
	msync(map, maplen, MS_SYNC);
	munmap(map, maplen);
}

static int dump_module(char *p, char *end, uint32_t pos, bool extract)
{
	struct module *module = (struct module *)p;
	unsigned int len, namelen, nameoffset;
	char outfile[64], *name, lifname[16], *p1;
	(void)extract;

	if (p + sizeof(*module) > end)
		return 0;
	len = ntohl(module->length);
	nameoffset = ntohl(module->offset_desc);

	if (p + nameoffset > end)
		return 0;

	namelen = p[nameoffset + 28];
	name = p + nameoffset + 29;

	if (name + namelen > end)
		return 0;

	memset(lifname, ' ', 10);
	printf("%08x: len %5d, [%.*s]\n", pos, len, namelen, name);

	if (!extract)
		return len;
	p1 = memchr(name, ' ', namelen);
	if (!p1 || p1 - name > 10) {
		sprintf(outfile, "file_%08x", pos);
		memcpy(lifname, "UNKNOWN", sizeof("UNKNOWN")-1);
	} else {
		sprintf(outfile, "%.*s", (int)(p1 - name), name);
		memcpy(lifname, name, p1 - name);
	}
	write_file(outfile, lifname, p, len + 4, 256);
	return len;
}

static void dump_module_list(struct basichdr *basic, char *buf, size_t basic_start, char *end, size_t length)
{
	uint32_t addr, offset;
	unsigned int i;

	printf("Entries in Option Table:\n");
	buf += basic_start + 0x166;
	offset = ntohl(basic->loadaddr);

	for (i = 1; i < ARRAY_SIZE(options); i++) {
		addr = ntohl(((uint32_t *)buf)[i]);
		if (addr < offset || addr - offset > length)
			continue;
		if (i == 5 || i == 13)
			continue;
		dump_module((char *)&basic->modules + addr - offset, end, addr - offset, false);
	}
}

static void dump_files(void *buf, size_t length, bool extract)
{
	struct basichdr *basic = (struct basichdr *)buf;
	char *p, *end = (char *)buf + length;
	unsigned int len;

	printf("load addr %x, entry %x (%x), modules length %x\n",
	       ntohl(basic->loadaddr), ntohl(basic->lif.entry),
	       ntohl(basic->lif.entry) - ntohl(basic->loadaddr),
	       ntohl(basic->modules_length));

	p = (char *)basic->modules;

	uint32_t pos = ntohl(basic->loadaddr);

	while (pos < ntohl(basic->lif.entry)) {
		len = dump_module(p, end, pos, extract);
		if (!len)
			break;
		pos += len;
		p += len;
	}
	if (extract)
		write_file("BASIC", buf, p, (char *)buf + length - p + 4, 256);
	dump_module_list(basic, buf, ntohl(basic->lif.entry) - ntohl(basic->loadaddr), end, length);
}

static int dumpfile(const char *name, bool extract)
{
	size_t length;
	void *buf;

	buf = mmap_file_read(name, &length);
	if (buf == MAP_FAILED)
		return -1;
	dump_files(buf, length, extract);
	return munmap(buf, length);
}

static int read_file(const char *filename)
{
	struct option_entry *option;
	uint8_t optnr;
	size_t maplen;
	void *buf;

	buf = mmap_file_read(filename, &maplen);
	if (buf == MAP_FAILED) {
		fprintf(stderr, "%s: mmap %s: %m\n", __func__, filename);
		return -1;
	}

	optnr = ((char *)buf)[0x28];

	option = &options[optnr];
	option->buf = buf;
	option->name = strndup(buf, 10);
	option->maplen= maplen;

	if (optnr == 0xff) {
		/* basic interpreter */
		option->writelen = maplen - sizeof(struct lifhdr);
	} else {
		/* driver file */
		option->writelen = ntohl(*(uint32_t *)(option->buf + 0x24));
	}
	return 0;
}

static void free_option_list(void)
{
	struct option_entry *option;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(options); i++) {
		option = &options[i];
		munmap(option->buf, option->maplen);
		close(option->fd);
		free(option->name);
	}
}

static void write_options(uint8_t *buf, uint32_t entry)
{
	uint32_t *optlist = (uint32_t *)(buf + entry + 0x150);
	struct basichdr *hdr = (struct basichdr *)buf;
	struct option_entry *option;

	int i;

	for (i = 2; i < OPTION_COUNT; i++) {
		if (i == 5 || i == 13)
			continue;
		optlist[i] = 0;
	}

	for (i = 2; i < OPTION_COUNT; i++) {
		option = &options[i];
		if (option->buf)
			optlist[i] = ntohl(option->pos + ntohl(hdr->loadaddr) - sizeof(struct basichdr));
	}
}

static int write_lif_header(uint8_t *buf, size_t length, uint32_t entry)
{
	struct basichdr *hdr = (struct basichdr *)buf;
	hdr->modules_length = htonl(length - 64);
	hdr->loadaddr = htonl(ntohl(hdr->lif.entry) - entry + 0x16);
	return 0;
}

static size_t output_size(void)
{
	size_t ret = sizeof(struct basichdr);
	unsigned int i;
	for (i = 0; i < ARRAY_SIZE(options); i++) {
		ret += options[i].writelen;
	}
	return ret;
}

static int write_output(const char *filename)
{
	struct option_entry *option;
	uint32_t entry, pos;
	unsigned int i;
	uint8_t *buf;
	size_t len;

	len = output_size();
	buf = mmap_file_write(filename, len);
	if (buf == MAP_FAILED)
		return -1;
	pos = sizeof(struct basichdr);
	for (i = 2; i < ARRAY_SIZE(options); i++) {
		option = &options[i];
		if (!option->name)
			continue;
		printf("writing %s opt %3d, file offset %7d, size %6ld\n",
		       option->name, i, pos, option->writelen);
			memcpy(buf, option->buf, sizeof(struct lifhdr));
			memcpy(buf + pos, option->buf + 0x24, option->writelen);
			option->pos = pos;
			pos += option->writelen;
	}

	entry = options[255].pos;
	write_lif_header(buf, pos, entry);
	write_options(buf, entry);
	printf("output file size %ld\n", len);
	if (msync(buf, len, MS_SYNC) == -1)
		fprintf(stderr, "msync output file: %m\n");
	return munmap(buf, len);
}


static void createfile(const char *filename, int optind, int argc, char **argv)
{
	int i;

	for (i = optind; i < argc; i++) {
		if (read_file(argv[i]) == -1)
			break;
	}

	if (!options[255].name) {
		fprintf(stderr, "missing basic core image\n");
		free_option_list();
		return;
	}
	if (i == argc)
		write_output(filename);
	free_option_list();
}

int main(int argc, char **argv)
{
	char c, *filename = NULL, *basicfile = NULL;
	bool list = false, create = false, extract = false;

	while ((c = getopt(argc, argv, "l:hc:b:x:")) != -1) {
		switch (c) {
		case 'h':
			printf("%s: usage: %s\n"
			       "-l	list modules\n"
			       "-c	create basic file\n"
			       "-b	basic interpreter to use when creating file\n"
			       "-h	help\n", argv[0], argv[0]);
			break;
		case 'l':
			basicfile = optarg;
			list = true;
			break;
		case 'c':
			filename = optarg;
			create = true;
			break;
		case 'x':
			basicfile = optarg;
			extract = true;
			break;
		default:
			fprintf(stderr, "unknown option -%c", c);
			break;
		}
	}

	if (create)
		createfile(filename, optind, argc, argv);
	if (list || extract)
		dumpfile(basicfile, extract);
}
