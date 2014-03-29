CFLAGS=-Wall -g -pg -fpic -c -Wno-deprecated-declarations
INCLUDE=-I../../ -I.
OBJS=encryption.o toolkit.o authentication.o key.o keyserver.o
CLIBS=-L. -lcrypto -lccn -lccn_crypto
all: lib

lib: $(OBJS)
	$(AR) -rcs libccn_crypto.a $(OBJS)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDE) $<

keyserver_test_server: keyserver_test_server.c $(OBJS)
	$(CC) -Wall -g -pg -I. -Wno-deprecated-declarations $(INCLUDE) -o keyserver_test_server keyserver_test_server.c $(CLIBS)

keyserver_test_client: keyserver_test_client.c $(OBJS)
	$(CC)  -Wall -g -pg -I. -Wno-deprecated-declarations $(INCLUDE) -o keyserver_test_client keyserver_test_client.c $(CLIBS)

clean:
	rm -f *.o keyserver_test_server keyserver_test_client *.dylib *.a
