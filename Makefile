CFLAGS=-O2 -Wall -Wextra -g -std=c11

all:	bastool lif2hfs hfs2lif

bastool: bastool.o mmap.o
	$(CC) $(LDFLAGS) -o "$@" $^

lif2hfs: lif2hfs.o mmap.o
	$(CC) $(LDFLAGS) -o "$@" $^

hfs2lif: hfs2lif.o mmap.o
	$(CC) $(LDFLAGS) -o "$@" $^

%.o:	%.c Makefile
	$(CC) $(CFLAGS) -c -o "$@" $<

clean:
	rm -f bastool lif2hfs
