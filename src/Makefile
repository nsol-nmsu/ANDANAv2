FLAGS=-g -w
INCLUDE=-I. 
LIBS=-lccn -lcrypto 

all: consumer server

consumer: 
	gcc $(FLAGS) $(INCLUDE) -o AnonConsumer AnonConsumer.c Proxy.c DownstreamProxy.c UpstreamProxy.c ProxyState.c Crypto.c CryptoWrapper.c ini.c Util.c sha256.c $(LIBS)

server:
	gcc $(FLAGS) $(INCLUDE) -o AnonServer AnonServer.c Proxy.c DownstreamProxy.c UpstreamProxy.c ProxyState.c Crypto.c CryptoWrapper.c ini.c Util.c sha256.c $(LIBS)

clean: 
	rm -f *.o
	rm -f AnonConsumer
	rm -f AnonServer
