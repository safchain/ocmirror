CC=gcc

all: ocmirror

ocmirror.o: ocmirror.c Makefile
	$(CC) -O3 -c ocmirror.c

ocmirror: ocmirror.o
	$(CC) -o ocmirror ocmirror.o

clean:
	rm -f ocmirror.o

mrproper:
	rm -f ocmirror.o ocmirror
