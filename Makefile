all: hpfs

hpfs: hpfs.c
	rm -f $@
	gcc -Wall `pkg-config fuse --cflags --libs` -lulockmgr $^ -o $@

.PHONY: clean

clean:
	rm hpfs