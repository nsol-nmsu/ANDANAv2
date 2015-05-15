/**
 * File: Crypto.c
 * Description: Implementation of the cryptographic function wrappers used by the system.
 */

#include <stdio.h>
#include <assert.h>
#include <stdio.h>
#include <ccn/ccn.h>
#include <ccn/charbuf.h>

#include "Util.h"
#include "Crypto.h"

//////////////////////
// BEGIN PRIVATE FUNCTIONS
//////////////////////

/**
 * Key derivation function to generate a new key from some random bits.
 * 
 * @param key - input session key
 * @param keylen - length of the input key
 * @param s - differentiating string (fresh randomness)
 * @param slen - length of the random string
 */
unsigned char* KDF(unsigned char * key, unsigned int keylen, char * s, unsigned int slen) 
{
    unsigned int r;
    unsigned char * ret = (unsigned char *) malloc(MACLEN);
    HMAC(EVP_sha256(), key, keylen, (unsigned char *)s, slen, ret, &r);
    return ret;
}

//////////////////////
// END PRIVATE FUNCTIONS
//////////////////////

/**
 * XOR 
 */
void XOR(uint8_t* x, uint8_t* y, uint8_t* z, int len)
{
    int i;
    for (i = 0; i < len; i++)
    {
        z[i] = x[i] ^ y[i];
    }
}

/**
 * Byte array increment (treat as unsigned int and +1).
 */
void INC(uint8_t* x, int len)
{
    int i;
    int carry = 0;
    for (i = len - 1; i >= 0; i--) 
    {
        if (x[i] == 0xFF)
        {
            x[i] = 0;
            carry = 1;
        }
        else if (carry == 1 && x[i] != 0xFF)
        {
            x[i]++;
            break;
        }
        else
        {
            x[i]++;
            break;
        }
    }
}

/**
 * Compute the SHA256 hash of the contents in the buffer.
 *
 * @param out - output blob to store the hash digest.
 * @param buffer - input message.
 * @param len - length of the input message.
 *
 * @return 0 if success, non-zero on error.
 */
int Hash(BOB** out, unsigned char* buffer, int len)
{
    int result = 0;
    unsigned char* digest = (unsigned char*)malloc(sizeof(unsigned char) * SHA256_DIGEST_LENGTH);
    (*out) = (BOB*)malloc(sizeof(BOB));
    (*out)->len = SHA256_DIGEST_LENGTH;
    (*out)->blob = (unsigned char*)malloc(sizeof(unsigned char) * SHA256_DIGEST_LENGTH);

    // Perform the hash and store the output digest
    // SHA256_CTX sha256;
    // SHA256_Init(&sha256);
    // SHA256_Update(&sha256, buffer, len);
    // SHA256_Final((*out)->blob, &sha256);

    printf("Hash input: ");
    print_hex(buffer, len);
    SHA256(buffer, len, (*out)->blob);
    printf("Hash output: ");
    print_hex((*out)->blob, len);

    // SHA256_CTX_CUSTOM ctx;
    // sha256_init(&ctx);
    // sha256_update(&ctx, buffer, len);
    // sha256_final(&ctx, (*out)->blob);

    return result;
}

/**
 * Create an 256 bit key and IV using the supplied key_data. salt can be added for taste.
 * Fills in the encryption and decryption ctx objects and returns 0 on success
 **/
int AESInit(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx)
{
  int i, nrounds = 5;
  unsigned char key[32], iv[32];
  
  /*
   * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
   * nrounds is the number of times the we hash the material. More rounds are more secure but
   * slower.
   */
  i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
  if (i != 32) {
    printf("Key size is %d bits - should be 256 bits\n", i);
    return -1;
  }

  if (e_ctx != 0)
  {
    EVP_CIPHER_CTX_init(e_ctx);
    EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);    
  }
  if (d_ctx != 0)
  {
    EVP_CIPHER_CTX_init(d_ctx);
    EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);
  }

  return 0;
}

/*
 * Encrypt *len bytes of data
 * All data going in & out is considered binary (unsigned char[])
 */
unsigned char* AESEncrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len)
{
  /* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
  int c_len = *len + 128, f_len = 0;
  unsigned char* ciphertext = (unsigned char*)malloc(c_len);

  /* allows reusing of 'e' for multiple encryption cycles */
  EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);

  /* update ciphertext, c_len is filled with the length of ciphertext generated,
    *len is the size of plaintext in bytes */
  EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);

  /* update ciphertext with the final remaining bytes */
  EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len);

  *len = c_len + f_len;
  return ciphertext;
}

/*
 * Decrypt *len bytes of ciphertext
 */
unsigned char *AESDecrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len)
{
  /* because we have padding ON, we must allocate an extra cipher block size of memory */
  int p_len = *len, f_len = 0;
  unsigned char *plaintext = (unsigned char*)malloc(p_len + 128);
  
  EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
  EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
  EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);

  *len = p_len + f_len;
  return plaintext;
}

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
int PKHybridEncrypt(BOB** out, unsigned char* session_key, RSA* pk, unsigned char* pt, int len)
{
    int i;
    int result = 0;
    int rsasize = RSA_size(pk); 
    int ctsize = (2 * rsasize) + IVLEN + MACLEN + len; // len is the length of the pt (and ct) in bytes

    // Allocate the BOB for the encrypted session key, IV, and ciphertext
    (*out) = (BOB*)malloc(sizeof(BOB));
    (*out)->len = ctsize;
    (*out)->blob = (unsigned char*)malloc(sizeof(unsigned char) * ctsize);
    memset((*out)->blob, 0, ctsize);

    // Encrypt the key, and then encrypt the plaintext using AES-CTR
    result = RSA_public_encrypt(SESSION_KEYLEN, session_key, (*out)->blob, pk, RSA_PKCS1_OAEP_PADDING);
    if (result < 0)
    {
        DEBUG_PRINT("Error: RSA_public_encrypt\n");
        return result;
    }

    // Encrypt the length of the plaintext
    DEBUG_PRINT("Encoding the length: %d\n", len);
    unsigned char elen[4];
    for (i = 0; i < 4; i++) // the length is encoded in an integer - 4 bytes - suitable for 32-bit architectures
    {
        elen[3 - i] = (len >> (i * 8));
    }
    result = RSA_public_encrypt(4, elen, (*out)->blob + rsasize, pk, RSA_PKCS1_OAEP_PADDING);
    if (result < 0)
    {
        DEBUG_PRINT("Error: RSA_public_encrypt\n");
        return result;
    }    

    // Setup the encryption and whatnot (CBC mode)
    EVP_CIPHER_CTX en;
    if (AESInit(session_key, SESSION_KEYLEN, 0, &en, 0)) 
    {
        DEBUG_PRINT("Error: couldn't initialize AES cipher for encryption\n");
        return -1;
    }
    unsigned char* ciphertext = AESEncrypt(&en, pt, &len);
    memcpy((*out)->blob + (2 * rsasize), ciphertext, len);
    EVP_CIPHER_CTX_cleanup(&en);

    // TODO: MAC the ciphertext here?

    return result;
}

/**
 * Decrypt the input ciphertext using hyrbid RSA-OAEP + AES-CTR with the specified session and public key. 
 *
 * @param out - output blob to store the plaintext.
 * @param sk - private key of the receiver
 * @param in - blob of ciphertext data (tuple of encrypted symmetric key and the encrypted ciphertext)
 *
 * @return 0 if success, non-zero on error.
 */
int PKHybridDecrypt(unsigned char** out, RSA* sk, BOB* in)
{
    int result = 0;
    int rsasize = RSA_size(sk);

    // Decrypt the key
    unsigned char symmetric_key[SESSION_KEYLEN];
    result = RSA_private_decrypt(rsasize, in->blob, symmetric_key, sk, RSA_PKCS1_OAEP_PADDING);
    if (result < 0)
    {
        DEBUG_PRINT("Error: RSA_private_decrypt for symmetric key - %d\n");
        return result;
    }

    // Decrypt the length of the plaintext and recover the length
    unsigned char elen[4];
    result = RSA_private_decrypt(rsasize, in->blob + rsasize, elen, sk, RSA_PKCS1_OAEP_PADDING);
    if (result < 0)
    {
        DEBUG_PRINT("Error: RSA_private_decrypt for encoded length - %d\n");
        return result;
    }
    int len = (elen[3] << 24) | (elen[2] << 16) | (elen[1] << 8) | elen[0];
    DEBUG_PRINT("Computed length: %d\n");

    // Allocate the BOB for the encrypted session key, IV, and ciphertext
    (*out) = (unsigned char*)malloc(sizeof(unsigned char) * len);

    // Setup the encryption and whatnot (CBC mode)
    EVP_CIPHER_CTX dec;
    if (AESInit(symmetric_key, SESSION_KEYLEN, 0, 0, &dec)) 
    {
        DEBUG_PRINT("Error: couldn't initialize AES cipher for decryption\n");
        return -1;
    }
    unsigned char* plaintext = AESDecrypt(&dec, in->blob + (2 * rsasize), &len);
    memcpy((*out), plaintext, len);
    EVP_CIPHER_CTX_cleanup(&dec);

    return result;
}

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
int PKEncrypt(BOB** out, RSA* pk, unsigned char* pt, int len)
{
    int result = 0;
    int ctsize = RSA_size(pk);

    // Make sure the size of the plaintext is smaller than the ciphertext so it can fit
    assert(len <= ctsize);

    // Allocate the BOB for the encrypted session key, IV, and ciphertext
    (*out) = (BOB*)malloc(sizeof(BOB));
    (*out)->len = ctsize;
    (*out)->blob = (unsigned char*)malloc(sizeof(unsigned char) * ctsize);
    memset((*out)->blob, 0, ctsize);

    // Perform the encryption
    result = RSA_public_encrypt(len, pt, (*out)->blob, pk, RSA_PKCS1_OAEP_PADDING);
    if (result < 0)
    {
        DEBUG_PRINT("Error: RSA_public_encrypt - %d\n");
        return result;
    }

    return result;
}

/**
 * Decrypt the input ciphertext using RSA-OAEP with the specified public key. 
 *
 * @param out - output to store the decrypted ciphertext
 * @param sk - RSA secret key
 * @param in - input ciphertext BOB
 *
 * @return 0 if success, non-zero on error.
 */
int PKDecrypt(unsigned char* out, RSA* sk, BOB* in)
{
    int result = 0;

    // Sanity check
    assert(RSA_size(sk) == in->len);

    result = RSA_private_decrypt(in->len, in->blob, out, sk, RSA_PKCS1_OAEP_PADDING);
    if (result < 0)
    {
        DEBUG_PRINT("Error: RSA_private_decrypt - %d\n");
        return result;
    }

    return result;
}

/**
 * Encrypt the input plaintext using AES-CTR+HMAC.
 * 
 * @param out - output blob to store the ciphertext.
 * @param key - symmetric key used for encryption.
 * @param pt - input plaintext.
 * @param len - length of the plaintext.
 */
int SKEncrypt(BOB** out, unsigned char* key, unsigned char* pt, int len)
{
    // Allocate the BOB for the encrypted session key, IV, and ciphertext
    (*out) = (BOB*)malloc(sizeof(BOB));
    // (*out)->len = len;

    int i, nrounds = 5;
    unsigned char raw_key[32], iv[32];
    memset(raw_key, 0, 32);
    memset(iv, 0, 32);

    /*
    * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
    * nrounds is the number of times the we hash the material. More rounds are more secure but
    * slower.
    */
    // i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), NULL, key, KEYLEN, nrounds, raw_key, iv);
    // if (i != 32) 
    // {
    //     printf("Key size is %d bits - should be 256 bits\n", i);
    //     return -1;
    // }

    EVP_CIPHER_CTX e_ctx;
    EVP_CIPHER_CTX_init(&e_ctx);
    EVP_EncryptInit_ex(&e_ctx, EVP_aes_256_cbc(), NULL, key, iv);

    /* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
    int c_len = len + AES_BLOCK_SIZE, f_len = 0;
    unsigned char *ciphertext = malloc(c_len);

    /* allows reusing of 'e' for multiple encryption cycles */
    EVP_EncryptInit_ex(&e_ctx, NULL, NULL, NULL, NULL);

    /* update ciphertext, c_len is filled with the length of ciphertext generated,
    *len is the size of plaintext in bytes */
    EVP_EncryptUpdate(&e_ctx, ciphertext, &c_len, pt, len);

    /* update ciphertext with the final remaining bytes */
    EVP_EncryptFinal_ex(&e_ctx, ciphertext+c_len, &f_len);

    // Save the resulting encryption information
    (*out)->blob = (unsigned char*)malloc(sizeof(unsigned char) * c_len);
    memcpy((*out)->blob, ciphertext, c_len);
    (*out)->len = c_len;

    // // Setup the encryption and whatnot (CBC mode)
    // EVP_CIPHER_CTX en;
    // if (AESInit(key, SESSION_KEYLEN, 0, &en, 0)) 
    // {
    //     DEBUG_PRINT("Error: couldn't initialize AES cipher for encryption\n");
    //     return -1;
    // }
    // int outlen = 0;
    // unsigned char* ciphertext = AESEncrypt(&en, pt, &outlen);
    // memcpy((*out)->blob, ciphertext, outlen);
    // EVP_CIPHER_CTX_cleanup(&en);
    return 0;
}

/**
 * Decrypt the input ciphertext using AES-CTR+HMAC.
 * 
 * @param out - output buffer to store the plaintext.
 * @param key - symmetric key used for decryption.
 * @param ct - input ciphertext.
 * @param len - length of the ciphertext.
 */
int SKDecrypt(BOB** out, uint8_t* key, uint8_t* ct, int len)
{
    // Allocate the BOB for the encrypted session key, IV, and ciphertext
    (*out) = (BOB*)malloc(sizeof(BOB));
    // (*out)->len = len;
    // (*out) = (unsigned char*)malloc(sizeof(unsigned char) * len);

    int i, nrounds = 5;
    unsigned char raw_key[32], iv[32];
    memset(raw_key, 0, 32);
    memset(iv, 0, 32);

    /*
    * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
    * nrounds is the number of times the we hash the material. More rounds are more secure but
    * slower.
    */
    // i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), NULL, key, KEYLEN, nrounds, raw_key, iv);
    // if (i != 32) 
    // {
    //     printf("Key size is %d bits - should be 256 bits\n", i);
    //     return -1;
    // }

    EVP_CIPHER_CTX e_ctx;
    EVP_CIPHER_CTX_init(&e_ctx);
    EVP_DecryptInit_ex(&e_ctx, EVP_aes_256_cbc(), NULL, key, iv);

    int p_len = len, f_len = 0;
    unsigned char *plaintext = malloc(p_len + AES_BLOCK_SIZE);

    EVP_DecryptInit_ex(&e_ctx, NULL, NULL, NULL, NULL);
    EVP_DecryptUpdate(&e_ctx, plaintext, &p_len, ct, len);
    EVP_DecryptFinal_ex(&e_ctx, plaintext + p_len, &f_len);

    (*out)->blob = (unsigned char*)malloc(sizeof(unsigned char) * (p_len + 1));
    memcpy((*out)->blob, plaintext, p_len);
    (*out)->len = p_len;

    // // Setup the encryption and whatnot (CBC mode)
    // EVP_CIPHER_CTX dec;
    // if (AESInit(key, SESSION_KEYLEN, 0, 0, &dec)) 
    // {
    //     DEBUG_PRINT("Error: couldn't initialize AES cipher for decryption\n");
    //     return -1;
    // }
    // unsigned char* plaintext = AESDecrypt(&dec, ct, &len);
    // memcpy((*out), plaintext, len);
    // EVP_CIPHER_CTX_cleanup(&dec);
    return 0;
}

/**
 * Compute the MAC tag of the input message.
 * 
 * @param out - output blob to store the MAC tag.
 * @param key - key for the MAC.
 * @param msg - input message to be MAC'd.
 * @param len - length of the input message.
 */
int MACTag(BOB** out, unsigned char* key, unsigned char* msg, int len)
{
    // Allocate the BOB for the encrypted session key, IV, and ciphertext
    (*out) = (BOB*)malloc(sizeof(BOB));
    (*out)->len = len;
    (*out)->blob = (unsigned char*)malloc(sizeof(unsigned char) * len);
    memset((*out)->blob, 0, len);

    // unsigned char * mac_key;
    // mac_key = KDF(key, KEYLEN, "\1", 1);
    HMAC(EVP_sha256(), key, MACKLEN, msg, len, (*out)->blob, NULL);
    return 0;
}

/**
 * Verify the MAC tag of an input message.
 * 
 * @param key - key for the MAC.
 * @param tag - tag for the message
 * @param tag_len - length of the message tag
 * @param msg - input message to be MAC'd.
 * @param len - length of the input message.
 */
int MACVerify(unsigned char* key, BOB* tag, int tag_len, unsigned char* msg, int len)
{
    // Allocate the BOB for the encrypted session key, IV, and ciphertext
    BOB* to;
    int i;
    if (MACTag(&to, key, msg, len) == 0 && to->len == tag_len)
    {
        for (i = 0; i < tag_len; i++)
        {
            if ((tag->blob)[i] != (to->blob)[i])
            {
                return 0;
            }
        }
        return 1;
    }
    return 0;
}

/*
 * Load the RSA public/private key pairs from the default CCNx directory.
 * 
 * @param pkFile - name of file containing the public key.
 * @param skFile - name of file containing the private key.
 * @param keys - pointer to the struct where the key data will be stored.
 */
int LoadKeyStore(char* pkFile, char* skFile, RSAKeyPair** keys)
{
    int result = 0;
    FILE* pkfp;
    FILE* skfp;

    // Allocate space for the keys and then read them from the file
    (*keys) = (RSAKeyPair*)malloc(sizeof(RSAKeyPair));
    pkfp = fopen(pkFile, "r");
    if (pkfp == NULL)
    {
        DEBUG_PRINT("Public key file cannot be opened\n");
        return -2;
    }
    skfp = fopen(skFile, "r");
    if (skfp == NULL)
    {
        DEBUG_PRINT("Private key file cannot be opened\n");
        return -2;
    }

    // NOTE: third param is the password callback
    // RSA *PEM_read_RSAPublicKey(FILE *fp, RSA **x, pem_password_cb *cb, void *u);
    (*keys)->pk = PEM_read_RSA_PUBKEY(pkfp, NULL, NULL, NULL);
    if ((*keys)->pk == NULL) 
    {
        DEBUG_PRINT("Public key load failed\n");
        return -1;
    }
    // RSA *PEM_read_RSAPrivateKey(FILE *fp, RSA **x, pem_password_cb *cb, void *u);
    (*keys)->sk = PEM_read_RSAPrivateKey(skfp, NULL, NULL, NULL);
    if ((*keys)->sk == NULL)
    {
        DEBUG_PRINT("Private key load failed\n");
        return -1;
    }

    return result;
}

/**
 * Generate (pseudo)random bytes and store them in the buffer.
 *
 * @param buffer - user buffer to store the bytes.
 * @param len - number of bytes to generate.
 */
int RandomBytes(uint8_t* buffer, uint32_t len)
{
    return RAND_bytes(buffer, len);
}

/**
 * Seed the PRG.
 *
 * @param seed - buffer seed.
 * @param len - length of the seed.
 */
void RandomSeed(uint8_t* seed, uint32_t len)
{
    RAND_seed(seed, len);
}

/**
 * XOR-based encryption/decryption.
 *
 * @param key
 * @param keylen
 * @param pt
 * @param ct
 * @param len
 */
int PRGBasedXorPad(uint8_t* key, uint32_t keylen, uint8_t* pt, uint8_t* ct, uint32_t len)
{
    // Force a re-seed
    RAND_seed(key, keylen);

    // Generate the random pad using a DPRG
    uint8_t* pad = (uint8_t*)malloc(len * sizeof(uint8_t));
    int res = RandomBytes(pad, len);
    if (res < 0)
    {
        return -1;
    }

    // Padding for encryption/decryption
    XOR(pt, pad, ct, len);

    return 0;
}
