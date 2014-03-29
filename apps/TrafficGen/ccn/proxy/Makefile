CFLAGS=-Wall -g -pg -I. -fpic -c -Wno-deprecated-declarations
INCLUDE=-I. -I../../
OBJS=proxy.o

all: lib

lib: $(OBJS)
	$(AR) -rcs libccn_proxy.a $(OBJS)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDE) $< 

clean:
	rm -f *.o *.dylib *.a
