/**
 * File: TestCrypto.cpp
 * Description: Simple unit test for the crypto functions.
 * Author: Christopher A. Wood, woodc1@uci.edu
 */

#include <stdio.h>
#include "../Util.h"
#include "../Crypto.h"

#define HASH_INPUT_LENGTH 1024
#define SK_INPUT_LENGTH 12
#define PK_INPUT_LENGTH 128
#define MAC_INPUT_LENGTH 2048

#define PKFILE "pub"
#define SKFILE "pri"

int testInc()
{
	unsigned char* buffer = (unsigned char*)malloc(sizeof(unsigned char) * HASH_INPUT_LENGTH);
	for (int i = 0; i < HASH_INPUT_LENGTH; i++)
	{
		buffer[i] = 0;
	} 
	buffer[HASH_INPUT_LENGTH - 1] = 0xFF;
	INC(buffer, HASH_INPUT_LENGTH);
	assert(buffer[HASH_INPUT_LENGTH - 1] == 0x00);
	assert(buffer[HASH_INPUT_LENGTH - 2] == 0x01);

	buffer[HASH_INPUT_LENGTH - 1] = 0xFE;
	buffer[HASH_INPUT_LENGTH - 2] = 0x00;
	INC(buffer, HASH_INPUT_LENGTH);
	assert(buffer[HASH_INPUT_LENGTH - 1] == 0xFF);
	assert(buffer[HASH_INPUT_LENGTH - 2] == 0x00);

	for (int i = 0; i < HASH_INPUT_LENGTH; i++)
	{
		buffer[i] = 0xFF;
	}
	INC(buffer, HASH_INPUT_LENGTH);
	for (int i = 0; i < HASH_INPUT_LENGTH; i++)
	{
		assert(buffer[i] == 0x00);
	}

	INC(buffer, HASH_INPUT_LENGTH);
	assert(buffer[HASH_INPUT_LENGTH - 1] == 0x01);

	return 1;
}

int testHash()
{
	int i;
	BOB* out;
	unsigned char* buffer = (unsigned char*)malloc(sizeof(unsigned char) * HASH_INPUT_LENGTH);
	for (i = 0; i < HASH_INPUT_LENGTH; i++)
	{
		buffer[i] = i % 256;
	}
	return Hash(&out, buffer, HASH_INPUT_LENGTH) == 0;
}

int testSKEncrypt()
{
	int i;
	BOB* out;
	unsigned char* buffer = (unsigned char*)malloc(sizeof(unsigned char) * SK_INPUT_LENGTH);
	for (i = 0; i < SK_INPUT_LENGTH; i++)
	{
		buffer[i] = i % 256;
	}
	unsigned char* key = (unsigned char*)malloc(sizeof(unsigned char) * SESSION_KEYLEN);
	if(!RAND_bytes(key, SESSION_KEYLEN)) return -1;
	return SKEncrypt(&out, key, buffer, SK_INPUT_LENGTH) == 0;
}

int testSKDecrypt()
{
	int i;
	BOB* out;
	unsigned char* buffer = (unsigned char*)malloc(sizeof(unsigned char) * SK_INPUT_LENGTH);
	unsigned char* original = (unsigned char*)malloc(sizeof(unsigned char) * SK_INPUT_LENGTH);
	for (i = 0; i < SK_INPUT_LENGTH; i++)
	{
		buffer[i] = i % 256;
	}
	unsigned char* key = (unsigned char*)malloc(sizeof(unsigned char) * SESSION_KEYLEN);
	if(!RAND_bytes(key, SESSION_KEYLEN)) return -1;
	SKEncrypt(&out, key, buffer, SK_INPUT_LENGTH);
	int ctlen = 0;
	BOB* dec;
	if (SKDecrypt(&dec, key, out->blob, SK_INPUT_LENGTH) == 0)
	{
		if (dec->len != SK_INPUT_LENGTH) return -1;
		return 0;
	}
	return -1;
}

int testSK()
{
	int i;
	BOB* out;
	unsigned char* buffer = (unsigned char*)malloc(sizeof(unsigned char) * SK_INPUT_LENGTH);
	unsigned char* original = (unsigned char*)malloc(sizeof(unsigned char) * SK_INPUT_LENGTH);
	memset(buffer, 0, SK_INPUT_LENGTH);
	memset(original, 0, SK_INPUT_LENGTH);
	for (i = 0; i < SK_INPUT_LENGTH; i++)
	{
		buffer[i] = i % 256;
	}
	unsigned char* key = (unsigned char*)malloc(sizeof(unsigned char) * SESSION_KEYLEN);
	if(!RAND_bytes(key, SESSION_KEYLEN)) return -1;
	SKEncrypt(&out, key, buffer, SK_INPUT_LENGTH);
	int ctlen = 0;
	BOB* dec;
	SKDecrypt(&original, key, out->blob, SK_INPUT_LENGTH);	
	if (dec->len != SK_INPUT_LENGTH) return -1;

	// Compare the two...
	for (i = 0; i < SK_INPUT_LENGTH; i++)
	{
		if (buffer[i] != original[i]) return -1;
	}
	return 1;
}

int testMACTag()
{
	int i;
	BOB* out;
	unsigned char* buffer = (unsigned char*)malloc(sizeof(unsigned char) * MAC_INPUT_LENGTH);
	for (i = 0; i < MAC_INPUT_LENGTH; i++)
	{
		buffer[i] = i % 256;
	}
	unsigned char* key = (unsigned char*)malloc(sizeof(unsigned char) * SESSION_KEYLEN);
	if(!RAND_bytes(key, SESSION_KEYLEN)) return -1;
	return MACTag(&out, key, buffer, MAC_INPUT_LENGTH) == 0;
}

int testMACVerify()
{
	int i;
	BOB* out;
	unsigned char* buffer = (unsigned char*)malloc(sizeof(unsigned char) * MAC_INPUT_LENGTH);
	for (i = 0; i < MAC_INPUT_LENGTH; i++)
	{
		buffer[i] = i % 256;
	}
	unsigned char* key = (unsigned char*)malloc(sizeof(unsigned char) * SESSION_KEYLEN);
	if(!RAND_bytes(key, SESSION_KEYLEN)) return -1;
	MACTag(&out, key, buffer, MAC_INPUT_LENGTH);

	// int MACVerify(unsigned char* key, BOB* tag, int tag_len, unsigned char* msg, int len)

	assert(MACVerify(key, out, out->len, buffer, MAC_INPUT_LENGTH) == 1);
	buffer[0] = (buffer[0] + 1) % 256;
	assert(MACVerify(key, out, out->len, buffer, MAC_INPUT_LENGTH) == 0);
	return 1;
}


//////////

int testLoadKeyStore()
{
	RSAKeyPair* keys;
	return LoadKeyStore(PKFILE, SKFILE, &keys) == 0;
}

// int testPKEncrypt()
// {
// 	int i;
// 	BOB* out;
// 	unsigned char* buffer = (unsigned char*)malloc(sizeof(unsigned char) * PK_INPUT_LENGTH);
// 	for (i = 0; i < PK_INPUT_LENGTH; i++)
// 	{
// 		buffer[i] = i % 256;
// 	}
// 	// unsigned char* key = (unsigned char*)malloc(sizeof(unsigned char) * SESSION_KEYLEN);
// 	// if(!RAND_bytes(key, SESSION_KEYLEN)) return -1;

// 	// LoadKeyStore(char* pkFile, char* skFile, RSAKeyPair** keys)
// 	RSAKeyPair* keys;
// 	i = LoadKeyStore(PKFILE, SKFILE, &keys);
// 	if (i != 0)
// 	{
// 		cerr << "Failed to load keys\n");
// 		return 0;	
// 	}
// 	else
// 	{
// 		return PKEncrypt(&out, keys->pk, buffer, PK_INPUT_LENGTH) == 0;
// 	}

// 	// return 0;
// }

// int testPKDecrypt()
// {
// 	int i;
// 	BOB* out;
// 	unsigned char* buffer = (unsigned char*)malloc(sizeof(unsigned char) * PK_INPUT_LENGTH);
// 	unsigned char* original = (unsigned char*)malloc(sizeof(unsigned char) * PK_INPUT_LENGTH);
// 	for (i = 0; i < PK_INPUT_LENGTH; i++)
// 	{
// 		buffer[i] = i % 256;
// 	}
// 	unsigned char* key = (unsigned char*)malloc(sizeof(unsigned char) * SESSION_KEYLEN);
// 	if(!RAND_bytes(key, SESSION_KEYLEN)) return -1;
// 	// PKEncrypt(&out, key, buffer, PK_INPUT_LENGTH);
// 	// return PKDecrypt(&original, key, out) == 0;
// 	return 0;
// }

int testPK()
{
	int i;
	BOB* out;
	unsigned char* buffer = (unsigned char*)malloc(sizeof(unsigned char) * PK_INPUT_LENGTH);
	memset(buffer, 0, PK_INPUT_LENGTH);
	for (i = 0; i < PK_INPUT_LENGTH; i++)
	{
		buffer[i] = i % 256;
	}
	// unsigned char* key = (unsigned char*)malloc(sizeof(unsigned char) * SESSION_KEYLEN);
	// if(!RAND_bytes(key, SESSION_KEYLEN)) return -1;
	// PKEncrypt(&out, key, buffer, PK_INPUT_LENGTH);
	// PKDecrypt(&original, key, out);

	RSAKeyPair* keys;
	i = LoadKeyStore(PKFILE, SKFILE, &keys);
	if (i != 0)
	{
		printf("Failed to load keys\n");
		return 0;	
	}
	else
	{
		PKEncrypt(&out, keys->pk, buffer, PK_INPUT_LENGTH);

		unsigned char* original = (unsigned char*)malloc(sizeof(unsigned char) * out->len);
		memset(original, 0, out->len);
		PKDecrypt(original, keys->sk, out);

		// Compare the two...
		for (i = 0; i < PK_INPUT_LENGTH; i++)
		{
			if (buffer[i] != original[i]) return 0;
		}
		return 1;
	}

	return 0;
}

//////////

int main(int argc, char** argv)
{
	// Test the hash routine
	printf("Running Hash() test... ");
	if (!testHash())
	{
		printf("failed.\n");
		return -1;
	}
	printf("passed.\n");

	// Test the secret key encryption routines
	printf("Running SKEncrypt() test... ");
	if (!testSKEncrypt())
	{
		printf("failed.\n");
		return -1;
	}
	printf("passed.\n");
	printf("Running SKDecrypt() test... ");
	if (!testSKDecrypt())
	{
		printf("failed.\n");
		return -1;
	}
	printf("passed.\n");
	printf("Running SK() test... ");
	if (!testSK())
	{
		printf("failed. \n");
		return -1;
	}
	printf("passed.\n");

	// Test the MAC routines
	printf("Running MACTag() test... ");
	if (!testMACTag())
	{
		printf("failed.\n");
		return -1;
	}
	printf("passed.\n");
	printf("Running MACVerify() test... ");
	if (!testMACVerify())
	{
		printf("failed.\n");
		return -1;
	}
	printf("passed.\n");

	// Test LoadKeyStore routine
	printf("Running LoadKeyStore() test... ");
	if (!testLoadKeyStore())
	{
		printf("failed.\n");
		return -1;
	}
	printf("passed.\n");

	// Test the PK (non-hybrid) routines
	// printf("Running PKEncrypt() test... ");
	// if (!testPKEncrypt())
	// {
	// 	printf("failed.\n");
	// 	return -1;
	// }
	// printf("passed.\n");
	// printf("Running PKDecrypt() test... ");
	// if (!testPKDecrypt())
	// {
	// 	printf("failed.\n");
	// 	return -1;
	// }
	// printf("passed.\n");
	printf("Running PK() test... ");
	if (!testPK())
	{
		printf("failed.\n");
		return -1;
	}
	printf("passed.\n");

	printf("Running INC() test... ");
	if (!testInc())
	{
		printf("failed.\n");
		return -1;
	}
	printf("passed.\n");	

	printf("All tests passed.\n");
	return 0;
}
