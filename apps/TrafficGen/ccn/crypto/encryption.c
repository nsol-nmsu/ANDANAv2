//
//  encryption.c
//  namecrypto
//
//  Created by Paolo Gasti <pgasti@uci.edu> on 6/3/11.
//  Copyright 2011 Paolo Gasti. All rights reserved.
//

// Limitations: name components (and names) must be shorter than 64KB

#include <string.h>

#include <assert.h>

#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

#include <ccn/ccn.h>
#include <ccn/charbuf.h>

#include <ccn/crypto/encryption.h>
#include <ccn/crypto/toolkit.h>

#include <ccn/crypto/key.h>

#ifdef DEBUG
#define DEBUG_PRINT(...) do{ fprintf( stderr, __VA_ARGS__ ); } while( 0 )
#else
#define DEBUG_PRINT(...) do{ } while ( 0 )
#endif

int symmetric_encrypt_binary(unsigned char * name, unsigned int name_length, unsigned char * symmkey, unsigned int symmkey_length, unsigned char * key, unsigned char * session_id, unsigned char ** encrypted_name);

int symmetric_decrypt_binary(unsigned char * encrypted_name, unsigned char ** symmkey, unsigned int * symmkey_length, unsigned char * key, unsigned char ** plaintext);

unsigned char * KDF(unsigned char * key, unsigned int keylen, char * s, unsigned int slen) // change this with something like HKDF
{
    unsigned int r;
    unsigned char * ret = (unsigned char *) malloc(MACLEN);
    HMAC(EVP_sha256(), key, keylen, (unsigned char *)s, slen, ret, &r);
    return ret;
}

int symm_enc_no_mac(unsigned char * plaintext, unsigned int plaintext_length, unsigned char * ciphertext, unsigned char * key)
{
    unsigned char ecount_buf[AES_BLOCK_SIZE];
    unsigned int num = 0;
    unsigned char IV[IVLEN];
    AES_KEY aeskey;

    if(!RAND_bytes(IV, IVLEN))
        return -1;

    memset(ecount_buf, 0, AES_BLOCK_SIZE);
    memcpy(ciphertext, IV, IVLEN);

    if(AES_set_encrypt_key(key, KEYLEN * 8, &aeskey))
        return -2;

    AES_ctr128_encrypt(plaintext, ciphertext + IVLEN, plaintext_length, &aeskey, IV, ecount_buf, &num);

    return plaintext_length + IVLEN;
}

// len is the length of ciphertext + IV
int symm_dec_no_mac(unsigned char * ciphertext, unsigned int ciphertext_length, unsigned char * plaintext, unsigned char * key)
{
    unsigned char ecount_buf[AES_BLOCK_SIZE];
    unsigned char IV[IVLEN];
    unsigned int num = 0;

    AES_KEY aeskey;

    if(AES_set_encrypt_key(key, KEYLEN * 8, &aeskey))
        return -2;

    memset(ecount_buf, 0, AES_BLOCK_SIZE);
    memcpy(IV, ciphertext, IVLEN);

    AES_ctr128_encrypt(ciphertext + IVLEN, plaintext, ciphertext_length - IVLEN, &aeskey, IV, ecount_buf, &num);

    return 0;
}


int symm_enc(unsigned char * plaintext, unsigned int plaintext_length, unsigned char * ciphertext, unsigned char * key)
{
    unsigned char ecount_buf[AES_BLOCK_SIZE];
    unsigned char * aes_key;
    unsigned char * mac_key;
    unsigned int num = 0;
    unsigned char IV[IVLEN];
    AES_KEY aeskey;

    aes_key = KDF(key, KEYLEN, "\0", 1);
    mac_key = KDF(key, KEYLEN, "\1", 1);

    if(!RAND_bytes(IV, IVLEN))
        return -1;

    memset(ecount_buf, 0, AES_BLOCK_SIZE);
    memcpy(ciphertext, IV, IVLEN);

    if(AES_set_encrypt_key(aes_key, KEYLEN * 8, &aeskey))
        return -2;

    AES_ctr128_encrypt(plaintext, ciphertext + IVLEN, plaintext_length, &aeskey, IV, ecount_buf, &num);
    HMAC(EVP_sha256(), mac_key, MACKLEN, ciphertext, IVLEN + plaintext_length, ciphertext+plaintext_length + IVLEN, NULL);

    //    printf("\naes_key0   = ");
    //    print_hex(aes_key, 16);
    //    printf("\nmac_key0   = ");
    //    print_hex(mac_key, 16);
    //    printf("\nIV0        = ");
    //    print_hex(IV, 16);
    //    printf("\n");
    //
    //
    //    printf("\nMACmsg0  %d= ", IVLEN + plaintext_length);
    //    print_hex(ciphertext, plaintext_length+IVLEN);
    //    printf("\nMAC0       = ");
    //    print_hex(ciphertext+plaintext_length + IVLEN, MACLEN);


    free(aes_key);
    free(mac_key);
    return 0;
}

unsigned char * encrypt_data(unsigned char * plaintext, unsigned int len, unsigned char * ciphertext, unsigned int * ciphertextlen, unsigned char * key, unsigned int keylen)
{
    int ret;
    *ciphertextlen = len + IVLEN + MACLEN;

    assert(keylen = 16);
    if(!ciphertext)
        ciphertext = (unsigned char *)malloc(*ciphertextlen);

    if((ret = symm_enc(plaintext, len, ciphertext, key)))
        *ciphertextlen =  ret;
    return ciphertext;
}


int dem_encrypt(unsigned char * plaintext, unsigned int len, unsigned char * dem, unsigned char * sesskey)
{
    if(!RAND_bytes(sesskey, KEYLEN))
        return -1;

    return symm_enc(plaintext, len, dem, sesskey);
}

// len does not consider the mac, but only the message
int dem_decrypt(unsigned char * dem, unsigned int len, unsigned char * plaintext, unsigned char * sesskey)
{
    unsigned char ecount_buf[AES_BLOCK_SIZE];
    unsigned char IV[IVLEN];
    unsigned char mac[MACLEN];
    unsigned char * aes_key;
    unsigned char * mac_key;
    unsigned int num;

    AES_KEY aeskey;

    //    printf("\nciphertext = ");
    //    print_hex(dem, len + IVLEN + MACLEN);


    aes_key = KDF(sesskey, KEYLEN, "\0", 1);
    mac_key = KDF(sesskey, KEYLEN, "\1", 1);

    if(AES_set_encrypt_key(aes_key, KEYLEN * 8, &aeskey))
        return -2;

    memset(ecount_buf, 0, AES_BLOCK_SIZE);
    num = 0;
    memcpy(IV, dem, IVLEN);

    HMAC(EVP_sha256(), mac_key, MACKLEN, dem, len + IVLEN, mac, NULL);


    //        printf("\naes_key1   = ");
    //        print_hex(aes_key, 16);
    //        printf("\nmac_key1   = ");
    //        print_hex(mac_key, 16);
    //        printf("\nIV1        = ");
    //        print_hex(IV, 16);
    //        printf("\n");
    //
    //
    //        printf("\nMACmsg1  %d= ", len+IVLEN);
    //        print_hex(dem, len+IVLEN);
    //        printf("\nMAC_KEY1   = ");
    //        print_hex(mac_key, 16);
    //        printf("\nMAC1       = ");
    //        print_hex(mac, MACLEN);
    //        printf("\nMAC2       = ");
    //        print_hex(dem+len+IVLEN, MACLEN);
    //        printf("\nmsg1       = ");
    //        print_hex(dem+IVLEN, 16);

    if(memcmp(mac, dem + len + IVLEN, MACLEN))
    {

        return -3;
    }

    AES_ctr128_encrypt(dem + IVLEN, plaintext, len, &aeskey, IV, ecount_buf, &num);

    free(aes_key);
    free(mac_key);
    return 0;

}

//alias for dem_decrypt
int symm_dec(unsigned char * ciphertext, unsigned int len, unsigned char * plaintext, unsigned char * key)
{
    return dem_decrypt(ciphertext, len, plaintext, key);
}

// if ciphertext
unsigned char * decrypt_data(unsigned char * ciphertext, unsigned int ciphertext_length, unsigned char * plaintext, unsigned int * len, unsigned char * key, unsigned int keylen)
{
    int ret;
    int plainlen = ciphertext_length - IVLEN - MACLEN;

    assert(keylen = 16);

    if(!plaintext)
        plaintext = (unsigned char *)malloc(plainlen);

    if((ret = dem_decrypt(ciphertext, plainlen, plaintext, key)))
        *len = ret;
    else
        *len = plainlen;

    return plaintext;
}


int kem_encrypt(int len, unsigned char * session_key, unsigned char * ciphertext, RSA * key)
{
    return RSA_public_encrypt(len, session_key, ciphertext, key, RSA_PKCS1_OAEP_PADDING);
}

int kem_decrypt(int len, unsigned char * kem, unsigned char * session_key, RSA * key)
{
    char* buff[120];
    int lib, func, reason;
    unsigned long error;
    printf("%d\n", len);
    int result = RSA_private_decrypt(len, kem, session_key, key, RSA_PKCS1_OAEP_PADDING);
    error = ERR_get_error();
    printf("%lu\n", error);
    printf("%d %d %d\n", ERR_GET_LIB(error), ERR_GET_FUNC(error), ERR_GET_REASON(error));
    ERR_load_crypto_strings();
    ERR_error_string(error, buff);
    printf("Error: %s\n", buff);
    return result;
}

/*
 * Encrypts a name or a subset of a name using RSA-OAEP.
 */

int encrypt_name(unsigned char * name, unsigned int name_length, RSA * key, unsigned char ** encrypted_name)
{
    int kemlen;
    int modsize;
    unsigned char * kem;
    unsigned char * dem;
    unsigned char sesskey[KEYLEN];

    modsize = BN_num_bytes(key->n);

    *encrypted_name = (unsigned char *) malloc(2 + modsize + 2 + IVLEN + name_length  + MACLEN); // len KEM + KEM + len DEM + DEM (AES-CTR w/ IV + MAC)

    kem = *encrypted_name;
    dem = *encrypted_name + 2 + modsize;

    dem_encrypt(name, name_length, dem + 2, sesskey);

    kemlen = kem_encrypt(KEYLEN, sesskey, kem + 2, key);

    assert(kemlen == modsize);// modsize == kemlen

    kem[0] = (modsize >> 8) & 0xFF;
    kem[1] = modsize & 0xFF;

    dem[0] = (name_length >> 8) & 0xFF;
    dem[1] = name_length & 0xFF;


    return 2 + modsize + 2 + IVLEN + name_length  + MACLEN;
}

/*
 * Decrypts a name encrypted using "encrypt" above
 * Returns the length of the encrypted payload, or a negative
 * value in case of error.
 * The length of encrypted_name is implicit in the format
 */
int decrypt_name(unsigned char * encrypted_name, RSA * key, unsigned char ** plaintext)
{
    int demlen;
    int kemlen;
    unsigned char * kem;
    unsigned char * dem;
    unsigned char sesskey[KEYLEN];

    kemlen = (encrypted_name[0] & 0xFF) * 256 + (encrypted_name[1] & 0xFF);
    printf("kemlen = %d\n", kemlen);
    printf("keylength macro = %d\n", KEYLEN);
    kem = encrypted_name;
    dem = encrypted_name + kemlen + 2;
    demlen = (dem[0] & 0xFF) * 256 + (dem[1] & 0xFF);

    *plaintext = (unsigned char *) malloc(demlen);

    printf("in decrypt_name\n");

    if (kem_decrypt(kemlen, kem+2, sesskey, key)==-1)
    {
        printf("ERR DECRYPTING KEM\n");
        return ERR_DECRYPTING_KEM;
    }

    printf("after kem_Decrypt\n");

    if(dem_decrypt(dem+2 , demlen, *plaintext, sesskey))
        return ERR_DECRYPTING_DEM;

    printf("after dem_decrypt\n");

    return demlen;
}

int ciphsize(unsigned char * ciphertext)
{
    int kemlen;
    int demlen;

    kemlen = ciphertext[0] * 256 + ciphertext[1];
    demlen = ciphertext[2 + kemlen] * 256 + ciphertext[2 + kemlen + 1] + IVLEN + MACLEN;
    return 2 + kemlen + 2 + demlen;
}

/*
 * Attaches a symmetric key (if present) and encrypts name
 */

int encrypt_binary(unsigned char * name, unsigned int name_length, unsigned char * symmkey, unsigned int symmkey_length, RSA * key, unsigned char ** encrypted_name)
{
    unsigned char * toEncrypt; // toEncrypt = name_length || name || symmk_length || symmkey
    int toEncryptLen;
    int name_offset;
    int symmkey_offset;
    int ciphlen;

    if(!symmkey)
        symmkey_length = 0;

    name_offset = 2;
    symmkey_offset = name_offset + name_length + 2;

    // Build the string toEncrypt as name_length || name || symmk_length || symmkey
    toEncryptLen = 2 + name_length + 2 + symmkey_length;
    if(!(toEncrypt = (unsigned char *) malloc(toEncryptLen)))
        return ERR_ALLOCATION_ERROR;
    memcpy(toEncrypt + name_offset, name, name_length);
    if(symmkey)
        memcpy(toEncrypt + symmkey_offset, symmkey, symmkey_length);

    toEncrypt[0] = (name_length >> 8) & 0xFF;
    toEncrypt[1] = name_length & 0xFF;

    toEncrypt[2 + name_length + 0] = (symmkey_length >> 8) & 0xFF;
    toEncrypt[2 + name_length + 1] = symmkey_length & 0xFF;


    // Encrypt toEncrypt
    ciphlen = encrypt_name(toEncrypt, toEncryptLen, key, encrypted_name);

    free(toEncrypt);

    return ciphlen;
}

/*
 * Same as above, but it also
 * encodes the ciphertext in "pseudo-base64" (where '/' is replaced with
 * '-') a name.
 */

int encrypt_encode(unsigned char * name, unsigned int name_length, unsigned char * symmkey, unsigned int symmkey_length, RSA * key, unsigned char ** encrypted_name)
{

    int ciphlen;
    unsigned char * ciph;

    ciphlen = encrypt_binary(name, name_length, symmkey, symmkey_length, key, &ciph);

    // Encode in Base64 the ciphertext
    *encrypted_name = (unsigned char *)base64_encode(ciph, ciphlen);

    free(ciph);
    return (int)strlen((char* )*encrypted_name);
}


int decrypt_binary(unsigned char * encrypted_name, unsigned char ** symmkey, unsigned int * symmkey_length, RSA * key, unsigned char ** plaintext)
{
    unsigned char * plain; //  name_length || name || symmk_length || symmkey
    int msglen;
    int name_offset;
    int symmkey_offset;

    printf("here\n");

    // Decrypt decoded ciphertext
    msglen = decrypt_name(encrypted_name, key, &plain);
    if(msglen < 0)
    {
        printf("decrypt_name failed (returned -1 size\n");
        return msglen;
    }

    printf("Decrypt decoded ciphertext\n");

    // Extract name and symmetric key
    msglen = plain[0] * 256 + plain[1];
    *symmkey_length = plain[2 + msglen + 0] * 256 + plain[2 + msglen + 1];

    printf("Extract name and symmetric key\n");

    name_offset = 2;
    symmkey_offset = name_offset + msglen + 2;

    *plaintext = (unsigned char *) malloc(msglen);
    *symmkey = (unsigned char *) malloc(*symmkey_length);

    printf("before memcpy\n");

    memcpy(*plaintext, plain + name_offset, msglen);
    memcpy(*symmkey, plain + symmkey_offset, *symmkey_length);

    printf("before free/after memcpy\n");

    free(plain);

    return msglen;
}

/*
 * Decodes and decrypt the output of the previous function.
 * Encrypted_name is a NULL-terminated C string.
 */

int decrypt_decode(char * encrypted_name, unsigned char ** symmkey, unsigned int * symmkey_length, RSA * key, unsigned char ** plaintext)
{
    unsigned char * ciph; // E(name_length || name || symmk_length || symmkey)
    int msglen;

    // Decode base64 ciphertext
    if(!(ciph = base64_decode(encrypted_name)))
        return ERR_DECODING_CIPHERTEXT;

    msglen = decrypt_binary(ciph, symmkey, symmkey_length, key, plaintext);
    free(ciph);

    return msglen;
}

/*
 * Same as above but with sessions
 * Output: encrypted name = Base64(session_id || len of tEl ||  E(name_length || name || symmk_length || symmkey))
 * where tEl = name_length || name || symmk_length || symmkey
 */
int symmetric_encrypt_encode(unsigned char * name, unsigned int name_length, unsigned char * symmkey, unsigned int symmkey_length, unsigned char * key, unsigned char * session_id, unsigned char ** encrypted_name)
{
    unsigned char * ciph;
    int ciphlen;
    ciphlen = symmetric_encrypt_binary(name, name_length, symmkey, symmkey_length, key, session_id, &ciph);

    // Encode in Base64 the ciphertext
    *encrypted_name = (unsigned char *)base64_encode(ciph, ciphlen);

    free(ciph);
    return (int)strlen((char* )*encrypted_name);
}


/* Same as above without base64 */
int symmetric_encrypt_binary(unsigned char * name, unsigned int name_length, unsigned char * symmkey, unsigned int symmkey_length, unsigned char * key, unsigned char * session_id, unsigned char ** encrypted_name)
{
    unsigned char * toEncrypt; // toEncrypt = name_length || name || symmk_length || symmkey
    int toEncryptLen;
    int name_offset;
    int symmkey_offset;
    int ciphlen;

    if(!symmkey)
        symmkey_length = 0;

    name_offset = 2;
    symmkey_offset = name_offset + name_length + 2;
    toEncryptLen = 2 + name_length + 2 + symmkey_length;

    // Build the string toEncrypt as name_length || name || symmk_length || symmkey
    if(!(toEncrypt = (unsigned char *) malloc(toEncryptLen)))
        return ERR_ALLOCATION_ERROR;
    memcpy(toEncrypt + name_offset, name, name_length);
    if(symmkey)
        memcpy(toEncrypt + symmkey_offset, symmkey, symmkey_length);

    toEncrypt[0] = (name_length >> 8) & 0xFF;
    toEncrypt[1] = name_length & 0xFF;

    toEncrypt[2 + name_length + 0] = (symmkey_length >> 8) & 0xFF;
    toEncrypt[2 + name_length + 1] = symmkey_length & 0xFF;


    /*
     * Now we have the message to encrypt in toEncrypt. It's time to prepare the
     * buffer for the ciphertext
     */
    ciphlen = SESSIONID_LENGTH + 2 + toEncryptLen + IVLEN + MACLEN;
    *encrypted_name = (unsigned char *) malloc(ciphlen);

    //put the sessionid at the beginning of ciph
    memcpy(*encrypted_name, session_id, SESSIONID_LENGTH);

    // Encrypt toEncrypt and put the ciphertext after the sessionid
    if(symm_enc(toEncrypt, toEncryptLen, (*encrypted_name) + 2 + SESSIONID_LENGTH, key))
        return -1;

    (*encrypted_name)[SESSIONID_LENGTH] = (toEncryptLen >> 8) & 0xFF;
    (*encrypted_name)[SESSIONID_LENGTH + 1] = toEncryptLen & 0xFF;


    //ciphlen = encrypt_name(toEncrypt, toEncryptLen, key, &ciph);


    //    printf("\nEncrypt %d %d: ciph = ", ciphlen, ciphsize(ciph));
    //    print_hex(ciph, ciphsize(ciph)); //ciphlen);
    //    printf("\n");

    free(toEncrypt);
    return ciphlen;
}

/*
 * Decodes and decrypt the output of the previous function.
 * Encrypted_name is a NULL-terminated C string.
 */

int symmetric_decrypt_decode(unsigned char * encrypted_name, unsigned char ** symmkey, unsigned int * symmkey_length, unsigned char * key, unsigned char ** plaintext)
{
    unsigned char * ciph;
    int len;
    // Decode base64 ciphertext
    if(!(ciph = base64_decode((char *)encrypted_name)))
        return ERR_DECODING_CIPHERTEXT;
    len = symmetric_decrypt_binary(ciph, symmkey, symmkey_length, key, plaintext);

    free(ciph);
    return len;
}

/* Same as above without base64 */
int symmetric_decrypt_binary(unsigned char * encrypted_name, unsigned char ** symmkey, unsigned int * symmkey_length, unsigned char * key, unsigned char ** plaintext)
{
    unsigned char * plain; //  name_length || name || symmk_length || symmkey
    unsigned char * sessionkey;
    int r;
    int msglen;
    int ciphlen;
    int name_offset;
    int symmkey_offset;

    // Extract the session key from the session_id
    if(0 != getSessionKey(encrypted_name, &sessionkey, key))
        return -1;


    // Decrypt decoded ciphertext
    ciphlen = encrypted_name[SESSIONID_LENGTH] * 256 + encrypted_name[SESSIONID_LENGTH +1];
    plain = (unsigned char *) malloc(ciphlen);
    r = dem_decrypt(encrypted_name + SESSIONID_LENGTH + 2, ciphlen, plain, sessionkey);

    if(r < 0)
        return r;

    // Extract name and symmetric key
    msglen = plain[0] * 256 + plain[1];
    *symmkey_length = plain[2 + msglen + 0] * 256 + plain[2 + msglen + 1];

    name_offset = 2;
    symmkey_offset = name_offset + msglen + 2;

    *plaintext = (unsigned char *) malloc(msglen);
    *symmkey = (unsigned char *) malloc(*symmkey_length);

    memcpy(*plaintext, plain + name_offset, msglen);
    memcpy(*symmkey, plain + symmkey_offset, *symmkey_length);

    return msglen;
}


/*
 * Encrypts a name for an anonymizing node.
 * symmkey can be NULL, in which case
 * symmkey_length is ignored.
 * encryptedName is a Base64-encoded string
 * symmkey is the key chosen by the client
 * under which the signature and the original
 * name of the content is encrypted.
 * Public key encryption is used. For symmetric
 * encryption-only, use session_encrypt_for_node
 */
//int encrypt_name_for_node_B64(RSA * node_pubkey, unsigned char * privateName, int privateName_length, unsigned char * symmkey, unsigned int symmkey_length, unsigned char ** encryptedName)
//{
//    return  encrypt_encode((unsigned char *)privateName, privateName_length, symmkey, symmkey_length, node_pubkey, encryptedName);
//}


#ifdef LINKENCRYPTION
/* Same as above without base64 */
int encrypt_name_for_node(RSA * node_pubkey, unsigned char * privateName, int privateName_length, unsigned char * symmkey, unsigned int symmkey_length, unsigned char ** encryptedName)
{
    unsigned char * shortEncryptedName;
    int r;

    r = encrypt_binary(privateName, privateName_length, symmkey, symmkey_length, node_pubkey, &shortEncryptedName);

    *encryptedName = (unsigned char *)malloc(r+1);
    *encryptedName[0] = NO_PER_LINK_ENCRYPTION;
    memcpy((*encryptedName)+1, shortEncryptedName, r);

    free(shortEncryptedName);
    return r+1;
}

int per_link_encrypt(RSA * node_pubkey, unsigned char * plaintext, int plaintext_length, unsigned char * symmkey, unsigned int symmkey_length, unsigned char ** encryptedName)
{
    unsigned char * shortEncryptedName;
    int r;

    r = encrypt_binary(plaintext, plaintext_length, symmkey, symmkey_length, node_pubkey, &shortEncryptedName);

    *encryptedName = (unsigned char *)malloc(r+1);
    *encryptedName[0] = ASYMMETRIC_PER_LINK_ENCRYPTION;
    memcpy((*encryptedName)+1, shortEncryptedName, r);

    free(shortEncryptedName);
    return r+1;
}

int per_link_decrypt(unsigned char * ciphertext, RSA * node_pubkey, unsigned char ** symmkey, unsigned int * symmkey_length, unsigned char ** decryptedName)
{
    return decrypt_binary(ciphertext+1, symmkey, symmkey_length, node_pubkey, decryptedName);
}

int is_per_link_encrypted(unsigned char * ciphertext)
{
    return ciphertext[0] & 0xFF;
}
#else
int encrypt_name_for_node(RSA * node_pubkey, unsigned char * privateName, int privateName_length, unsigned char * symmkey, unsigned int symmkey_length, unsigned char ** encryptedName)
{
    return encrypt_binary(privateName, privateName_length, symmkey, symmkey_length, node_pubkey, encryptedName);
}

#endif

/*
 * Run on an anonymizing node. Decrypts a name
 * and possibly symmetric key in input
 * Input is E(name||k) (e.g. E([interest]||k))
 */

//int decrypt_name_on_node_B64(char * ciphertext, RSA * node_pubkey, unsigned char ** symmkey, unsigned int * symmkey_length, unsigned char ** decryptedName)
//{
//    return decrypt_decode(ciphertext, symmkey, symmkey_length, node_pubkey, decryptedName);
//}

/* Same as above without base64 */
int decrypt_name_on_node(unsigned char * ciphertext, RSA * node_pubkey, unsigned char ** symmkey, unsigned int * symmkey_length, unsigned char ** decryptedName)
{
    return decrypt_binary(ciphertext, symmkey, symmkey_length, node_pubkey, decryptedName);
}

/*
 * Run on an encrypting node. The client requests
 * a new session and receives session_id and key.
 * node_key is provided by the node environment
 * The encryption of the key into the session id
 * is probabilistic. It could be deterministic,
 * but because of the birthday paradox the long
 * term key would be useful for less than O(sqrt(k))
 * sessions. (is it true here as well? think...)
 */

int createSession(unsigned char ** session_id, unsigned char ** key,unsigned char ** rand, unsigned char * user_provided_key, unsigned int userkey_len, unsigned char * node_key)
{
    int ret;

    unsigned char buf1[SESSIONRAND_LENGTH + userkey_len];
    unsigned char buf2[SHA256_DIGEST_LENGTH];

    *rand  = (unsigned char *) malloc(SESSIONRAND_LENGTH);;
    *key = (unsigned char *) malloc(SESSION_KEYLEN);
    *session_id = (unsigned char *) malloc(SESSIONID_LENGTH);

    if(!RAND_bytes(*rand, SESSIONRAND_LENGTH))
        return -1;

    memcpy(buf1, *rand, SESSIONRAND_LENGTH);
    memcpy(buf1+SESSIONRAND_LENGTH, user_provided_key, userkey_len);

    SHA256(buf1, SESSIONRAND_LENGTH + userkey_len, buf2);

    memcpy(*key, buf2, SESSION_KEYLEN);

    if((ret = symm_enc(*key, SESSION_KEYLEN, *session_id, node_key)))
        return ret;

    return SESSIONID_LENGTH;
}

/* Verifies that the node generated the key properly; returns 1 if correct, 0 otherwise */
int verifyKeyFromNode(unsigned char * user_provided_key, unsigned int userkey_len, unsigned char * node_randomness, unsigned char * session_key)
{
    unsigned char buf1[SESSIONRAND_LENGTH + userkey_len];
    unsigned char buf2[SHA256_DIGEST_LENGTH];

    memcpy(buf1, node_randomness, SESSIONRAND_LENGTH);
    memcpy(buf1 + SESSIONRAND_LENGTH, user_provided_key, userkey_len);

    SHA256(buf1, SESSIONRAND_LENGTH + userkey_len, buf2);

    return !memcmp(buf2, session_key, SESSION_KEYLEN);
}

/*
 * Run on an ecnrypting node. The client sends
 * the session ID and the node retrieves the
 * corresponding session key
 */
int getSessionKey(unsigned char * session_id, unsigned char ** key, unsigned char * node_key)
{
    *key = (unsigned char *) malloc(SESSION_KEYLEN);
    return dem_decrypt(session_id, SESSION_KEYLEN, *key, node_key);
}


/*
 * Encrypts a name for an anonymizing node. nodeName is a NULL-terminated string.
 * symmkey can be NULL, in which case symmkey_length is ignored.
 * encryptedName is a NULL-terminated string that contains nodeName||/||E(privateName)
 * symmkey is the key chosen by the client under which the signature and the original name
 * of the content is encrypted.
 */
int session_encrypt_name_for_node_B64(unsigned char * sessionkey, unsigned char * session_id, unsigned char * privateName, int privateName_length, unsigned char * symmkey, unsigned int symmkey_length, unsigned char ** encryptedName)
{
    return symmetric_encrypt_encode(privateName, privateName_length, symmkey, symmkey_length, sessionkey, session_id, encryptedName);
}

/* Same as above without base64 */
int session_encrypt_name_for_node(unsigned char * sessionkey, unsigned char * session_id, unsigned char * privateName, int privateName_length, unsigned char * symmkey, unsigned int symmkey_length, unsigned char ** encryptedName)
{
    return symmetric_encrypt_binary(privateName, privateName_length, symmkey, symmkey_length, sessionkey, session_id, encryptedName);
}

/*
 * Run on an anonymizing node. Decrypts a name and possibly symmetric key in input
 * Input is /nodename/E(name||k) (e.g. /ndn/uci/anonymizer/E(/ndn/ucla/secret||k))
 * encrypted by session_encrypt_for_node.
 */

int session_decrypt_name_on_node_B64(unsigned char * ciphertext, int ciphertext_length, unsigned char * node_key, unsigned char ** symmkey, unsigned int * symmkey_length, unsigned char ** decryptedName)
{
    return symmetric_decrypt_decode(ciphertext, symmkey, symmkey_length, node_key, decryptedName);
}


/* Same as above without base64 */
int session_decrypt_name_on_node(unsigned char * ciphertext, int ciphertext_length, unsigned char * node_key, unsigned char ** symmkey, unsigned int * symmkey_length, unsigned char ** decryptedName)
{
    return symmetric_decrypt_binary(ciphertext, symmkey, symmkey_length, node_key, decryptedName);
}


/*
  void
  ccn_crypto_name_asym_link_decrypt(struct ccn_pkey *privkey,
  unsigned char *encrypted,
  struct ccn_pkey **out_symkey,
  struct ccn_charbuf **out_decrypted,
  struct ccn_indexbuf **out_decrypted_comps)
  {
  RSA *rsa_privkey = EVP_PKEY_get1_RSA((EVP_PKEY *)privkey);

  if (rsa_privkey == NULL) {
  DEBUG_PRINT(
  "ABORT %d %s Unable to extract RSA public key\n",
  __LINE__, __func__);
  abort();
  }

  unsigned char *symkey_data = NULL;
  unsigned int symkey_bytes;
  unsigned char *decrypted = NULL;
  int decrypted_length =	per_link_decrypt(encrypted,
  rsa_privkey,
  &symkey_data,
  &symkey_bytes,
  &decrypted);

  *out_decrypted = ccn_charbuf_create();
  ccn_charbuf_append(*out_decrypted, decrypted, decrypted_length);

  if (*out_decrypted_comps != NULL) {
  struct ccn_buf_decoder decoder;
  struct ccn_buf_decoder *d = &decoder;

  ccn_buf_decoder_start(d,
  (*out_decrypted)->buf,
  (*out_decrypted)->length);

  if (ccn_parse_Name(d, *out_decrypted_comps) < 0) {
  DEBUG_PRINT(
  "ABORT %d %s Failed to parse decrypted name\n",
  __LINE__, __func__);
  abort();
  }
  }

  *out_symkey = ccn_proxy_symkey_init_all(symkey_data, symkey_bytes);
  free(symkey_data);
  free(decrypted);
  }
*/

/*
 * This a temporary bridge between proxy stuff and the name encryption library.
 * Ideally, there should be a single, unified crypto interface based on
 * ccn_pkeys.
 *
 * Paths and Nodes do not care what type of key is actually be used for
 * encryption/decryption. As such, any reference to the current used
 * crypto library (OpenSSL libcrypto at the moment), should be abstracted
 * by the name encryption interface.
 */

void
ccn_crypto_name_asym_encrypt(struct ccn_pkey *pubkey,
                             unsigned char *name,
                             const size_t length,
                             struct ccn_pkey *symkey,
                             unsigned char **out_name,
                             size_t *out_name_length)
{
    if (pubkey == NULL) {
        DEBUG_PRINT("ABORT %s %d received bad pubkey\n", __FILE__, __LINE__);
        abort();
    }
    RSA *rsa_pubkey = EVP_PKEY_get1_RSA((EVP_PKEY *)pubkey);

    *out_name_length = encrypt_name_for_node(rsa_pubkey,
                                             name,
                                             (unsigned int)length,
                                             ccn_crypto_symkey_key(symkey),
                                             (unsigned int)ccn_crypto_symkey_bytes(symkey),
                                             out_name);

    //FIXME BEGIN DECRYPT TEST
//	struct ccn_pkey *test_privkey = ccn_proxy_privkey_cheat();
//	RSA *test_rsa_privkey = EVP_PKEY_get1_RSA((EVP_PKEY *)test_privkey);
//	unsigned char *test_symkey = NULL;
//	unsigned int test_length;
//	unsigned char *test_name = NULL;
//	decrypt_name_on_node(*out_name, test_rsa_privkey, &test_symkey, &test_length, &test_name);
//	if(memcmp(name, test_name, length) == 0) {
//		DEBUG_PRINT("SAME\n");
//	} else {
//		DEBUG_PRINT("DIFFERENT\n");
//	}
    //FIXME END DECRYPT TEST
}

/*
 * Bridge function
 */




void
ccn_crypto_name_asym_decrypt(struct ccn_pkey *privkey,
                             unsigned char *encrypted,
                             struct ccn_pkey **out_symkey,
                             struct ccn_charbuf **out_decrypted,
                             struct ccn_indexbuf **out_decrypted_comps)
{
    RSA *rsa_privkey = EVP_PKEY_get1_RSA((EVP_PKEY *)privkey);

    if (rsa_privkey == NULL) {
        DEBUG_PRINT(
            "ABORT %d %s Unable to extract RSA public key\n",
            __LINE__, __func__);
        abort();
    }

    unsigned char *symkey_data = NULL;
    unsigned int symkey_bytes;
    unsigned char *decrypted = NULL;

    printf("okay... so far so good. trying decrypt_name_on_node\n");

    int decrypted_length =	decrypt_name_on_node(encrypted,
                                                     rsa_privkey,
                                                     &symkey_data,
                                                     &symkey_bytes,
                                                     &decrypted);

    *out_decrypted = ccn_charbuf_create();

    // these should match!
    printf("%d %d\n", decrypted_length, symkey_bytes);

    ccn_charbuf_append(*out_decrypted, decrypted, decrypted_length);

    DEBUG_PRINT("%d %s Decrypted %s\n", __LINE__, __func__, decrypted);

    if (*out_decrypted_comps != NULL) {
        struct ccn_buf_decoder decoder;
        struct ccn_buf_decoder *d = &decoder;

        ccn_buf_decoder_start(d,
                              (*out_decrypted)->buf,
                              (*out_decrypted)->length);

        if (ccn_parse_Name(d, *out_decrypted_comps) < 0) {
            printf("FAILED TO PARSE DECRYPTED NAME\n");
            DEBUG_PRINT(
                "ABORT %d %s Failed to parse decrypted name\n",
                __LINE__, __func__);
            abort();
        }
    }

    *out_symkey = ccn_crypto_symkey_init_all(symkey_data, symkey_bytes);
    free(symkey_data);
    free(decrypted);
}

void
ccn_crypto_name_sym_encrypt(struct ccn_pkey *sessionkey,
                            unsigned char *session_id,
                            unsigned char *name,
                            const size_t length,
                            struct ccn_pkey *symkey,
                            unsigned char **out_name,
                            size_t *out_name_length)
{
    *out_name_length = session_encrypt_name_for_node(ccn_crypto_symkey_key(sessionkey),
                                                     session_id,
                                                     name,
                                                     (int)length,
                                                     ccn_crypto_symkey_key(symkey),
                                                     (unsigned int)ccn_crypto_symkey_bytes(symkey),
                                                     out_name);
}

void
ccn_crypto_name_sym_decrypt(struct ccn_pkey *sessionkey,
                            unsigned char *encrypted,
                            size_t encrypted_length,
                            struct ccn_pkey **out_symkey,
                            struct ccn_charbuf **out_decrypted,
                            struct ccn_indexbuf **out_decrypted_comps)
{
    unsigned char *symkey_data = NULL;
    unsigned int symkey_bytes;
    unsigned char *decrypted = NULL;

    int decrypted_length = session_decrypt_name_on_node(encrypted,
                                                        (int)encrypted_length,
                                                        ccn_crypto_symkey_key(sessionkey),
                                                        &symkey_data,
                                                        &symkey_bytes,
                                                        &decrypted);

    *out_decrypted = ccn_charbuf_create();
    ccn_charbuf_append(*out_decrypted, decrypted, decrypted_length);

    DEBUG_PRINT("%d %s Decrypted %s\n", __LINE__, __func__, decrypted);

    if (*out_decrypted_comps != NULL) {
        struct ccn_buf_decoder decoder;
        struct ccn_buf_decoder *d = &decoder;

        ccn_buf_decoder_start(d,
                              (*out_decrypted)->buf,
                              (*out_decrypted)->length);

        if (ccn_parse_Name(d, *out_decrypted_comps) < 0) {
            DEBUG_PRINT(
                "ABORT %d %s Failed to parse decrypted name\n",
                __LINE__, __func__);
            abort();
        }
    }

    *out_symkey = ccn_crypto_symkey_init_all(symkey_data, symkey_bytes);
    free(symkey_data);
    free(decrypted);
}


void
ccn_crypto_content_encrypt(struct ccn_pkey *symkey,
                           unsigned char *content,
                           size_t length,
                           unsigned char **encrypted_content,
                           size_t *encrypted_length)
{
    unsigned int enc_length;

    *encrypted_content = encrypt_data(content,
                                      (unsigned int)length,
                                      NULL,
                                      &enc_length,
                                      ccn_crypto_symkey_key(symkey),
                                      (unsigned int)ccn_crypto_symkey_bytes(symkey));

    *encrypted_length = enc_length;
}

void
ccn_crypto_content_decrypt(struct ccn_pkey *symkey,
                           unsigned char *encrypted_content,
                           size_t length,
                           unsigned char **content,
                           size_t *content_length)
{
    unsigned int out_length;
    *content = decrypt_data(
        (unsigned char *)encrypted_content,
        (unsigned int)length,
        NULL,
        &out_length,
        ccn_crypto_symkey_key(symkey),
        (unsigned int)ccn_crypto_symkey_bytes(symkey));
    *content_length = (size_t)out_length;

}
