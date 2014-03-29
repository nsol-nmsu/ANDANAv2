CFLAGS=-Wall -g -Wno-deprecated-declarations
INCLUDE=-I. -I../
CLIBS=-lccn -lcrypto

all: tgen

tgen: server.c $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDE) -o tgen server.c proxy.c util.c $(OBJS) $(CLIBS)

clean:
	rm -rf *.o tgen

