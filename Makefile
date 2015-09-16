CC=gcc

ocmirror: ocmirror.o
	     $(CC) -o ocmirror ocmirror.o

clean:
	rm -f ocmirror.o

mrproper:
	rm -f ocmirror.o ocmirror
