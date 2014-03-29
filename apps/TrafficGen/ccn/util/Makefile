CFLAGS=-Wall -g -pg -I. -fpic -c
INCLUDE=-I. -I../../
OBJS=util.o

all: lib

lib: $(OBJS)
	$(AR) -rcs libccn_util.a $(OBJS)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDE) $<

clean:
	rm -f *.o *.dylib *.a
