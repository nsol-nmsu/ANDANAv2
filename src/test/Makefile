FLAGS=-g -w
INCLUDE=-I. 
LIBS=-lccn -lcrypto 

crypto:
	gcc $(FLAGS) -o TestCrypto TestCrypto.c ../Crypto.c ../Util.c -lcrypto -lccn
	gcc $(FLAGS) -o ConsumerTest ConsumerTest.c ../Crypto.c ../Proxy.c ../UpstreamProxy.c ../CryptoWrapper.c ../Util.c ../ProxyState.c -lcrypto -lccn
	gcc $(FLAGS) -o ProxyStateTest ProxyStateTest.c ../Crypto.c ../Proxy.c ../UpstreamProxy.c ../CryptoWrapper.c ../Util.c ../ProxyState.c -lcrypto -lccn
