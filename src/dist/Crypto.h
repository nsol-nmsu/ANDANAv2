/**
 * File: Crypto.h
 * Description: Class that encapsulates a generic application-layer proxy over NDN.
 */

#ifndef CRYPTO_H_
#define CRYPTO_H_ 

#include <inttypes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>

#define KEYLEN 128/8                                     // symmetric cipher key length in bytes
#define IVLEN 128/8                                      // IV length in bits
#define MACKLEN 128/8                                    // MAC key length in bits
#define NODE_KEYLEN 128/8                                // Long term node key length
#define SESSION_KEYLEN 128/8                             // length of a session key
#define SESSIONRAND_LENGTH 128/8                         // length of the randomness provided by the node
#define SESSIONID_LENGTH IVLEN + SESSION_KEYLEN + MACLEN // length of a session identifier
#define MACLEN SHA256_DIGEST_LENGTH
#define PERLINKTAGSIZE 1

/////////////////////////////////////////////
// Return structs for crypto operations
/////////////////////////////////////////////

// Struct to wrap a "blob of bytes" and its length for easy handoffs
typedef struct 
{
    uint32_t len;
    uint8_t* blob;
} BOB;

// Struct to store RSA public/private key pair
typedef struct
{
	RSA* pk;
	RSA* sk;
} RSAKeyPair;

// Struct to store a symmetric key
typedef struct 
{
    uint8_t *key;
    uint32_t nbits;
    uint32_t nbytes;
} SymmetricKey;

/**
 * XOR 
 */
void XOR(uint8_t* x, uint8_t* y, uint8_t* z, int len);

/**
 * Byte array increment (treat as unsigned int and +1).
 */
void INC(uint8_t* x, int len);

/**
 * Compute the SHA256 hash of the contents in the buffer.
 *
 * @param out - output blob to store the hash digest.
 * @param buffer - input message.
 * @param len - length of the input message.
 *
 * @return 0 if success, non-zero on error.
 */
int Hash(BOB** out, uint8_t* buffer, int len);

/**
 * Encrypt the input plaintext using hyrbid RSA-OAEP + AES-CTR with the specified session and public key. 
 *
 * @param out - output blob to store the ciphertext.
 * @param session_key - symmetric key used to encrypt the data
 * @param pk - public key of the receiver
 * @param pt - input plaintext.
 * @param len - length of the plaintext.
 *
 * @return 0 if success, non-zero on error.
 */
int PKHybridEncrypt(BOB** out, uint8_t* session_key, RSA* pk, uint8_t* pt, int len);

/**
 * Decrypt the input ciphertext using hyrbid RSA-OAEP + AES-CTR with the specified session and public key. 
 *
 * @param out - output blob to store the plaintext.
 * @param sk - private key of the receiver
 * @param in - blob of ciphertext data (tuple of encrypted symmetric key and the encrypted ciphertext)
 *
 * @return 0 if success, non-zero on error.
 */
int PKHybridDecrypt(uint8_t** out, RSA* sk, BOB* in);

/**
 * Encrypt the input plaintext using RSA-OAEPwith the specified public key. 
 *
 * @param out - output blob to store the ciphertext.
 * @param pk - public key of the receiver
 * @param pt - input plaintext.
 * @param len - length of the plaintext.
 *
 * @return 0 if success, non-zero on error.
 */
int PKEncrypt(BOB** out, RSA* pk, uint8_t* pt, int len);

/**
 * Decrypt the input ciphertext using RSA-OAEP with the specified public key. 
 *
 * @param out - output to store the decrypted ciphertext
 * @param sk - RSA secret key
 * @param in - input ciphertext BOB
 *
 * @return 0 if success, non-zero on error.
 */
int PKDecrypt(uint8_t* out, RSA* sk, BOB* in);

/**
 * Encrypt the input plaintext using AES-CTR+HMAC.
 * 
 * @param out - output blob to store the ciphertext.
 * @param key - symmetric key used for encryption.
 * @param pt - input plaintext.
 * @param len - length of the plaintext.
 */
int SKEncrypt(BOB** out, uint8_t* key, uint8_t* pt, int len);

/**
 * Decrypt the input ciphertext using AES-CTR+HMAC.
 * 
 * @param out - output buffer to store the plaintext.
 * @param key - symmetric key used for decryption.
 * @param ct - input ciphertext.
 * @param len - length of the ciphertext.
 */
int SKDecrypt(BOB** out, uint8_t* key, uint8_t* ct, int len);

/**
 * Compute the MAC tag of the input message.
 * 
 * @param out - output blob to store the MAC tag.
 * @param key - key for the MAC.
 * @param msg - input message to be MAC'd.
 * @param len - length of the input message.
 */
int MACTag(BOB** out, uint8_t* key, uint8_t* msg, int len);

/**
 * Verify the MAC tag of an input message.
 * 
 * @param key - key for the MAC.
 * @param tag - tag for the message
 * @param tag_len - length of the message tag
 * @param msg - input message to be MAC'd.
 * @param len - length of the input message.
 */
int MACVerify(uint8_t* key, BOB* tag, int tag_len, uint8_t* msg, int len);

/*
 * Load the RSA public/private key pairs from the default CCNx directory.
 * 
 * @param pkFile - name of file containing the public key.
 * @param skFile - name of file containing the private key.
 * @param keys - pointer to the struct where the key data will be stored.
 */
int LoadKeyStore(char* pkFile, char* skFile, RSAKeyPair** keys);

/**
 * Generate (pseudo)random bytes and store them in the buffer.
 *
 * @param buffer - user buffer to store the bytes.
 * @param len - number of bytes to generate.
 */
int RandomBytes(uint8_t* buffer, uint32_t len);

/**
 * Seed the PRG.
 *
 * @param seed - buffer seed.
 * @param len - length of the seed.
 */
void RandomSeed(uint8_t* seed, uint32_t len);

/**
 * XOR-based encryption/decryption.
 *
 * @param key
 * @param keylen
 * @param pt
 * @param ct
 * @param len
 */
int PRGBasedXorPad(uint8_t* key, uint32_t keylen, uint8_t* pt, uint8_t* ct, uint32_t len);

#endif /* CRYPTO_H_ */
