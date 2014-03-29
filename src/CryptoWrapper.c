#include <stdio.h>
#include <assert.h>
#include <stdio.h>
#include <ccn/charbuf.h>

#include "Util.h"
#include "CryptoWrapper.h"

// Private region
static int _addedAlgs;

/*
 * Initialize a symmetric key with the specified number of bits.
 * 
 * @param key_bits - bits in the key
 *
 * @return a CCN key
 */
struct ccn_pkey* InitSymmetricKey(const uint32_t key_bits)
{
    SymmetricKey *symkey = (SymmetricKey*)malloc(sizeof(SymmetricKey));

    symkey->nbits = key_bits;
    symkey->nbytes = key_bits / 8;
    symkey->key = (uint8_t*)malloc(symkey->nbytes * sizeof(uint8_t));

    RandomBytes(symkey->key, (int)symkey->nbytes);

    return (struct ccn_pkey*)symkey;
}

/*
 * Create a copy of the specified public key.
 * 
 * @param key - key to copy.
 *
 * @return copy of the passed in key.
 */
struct ccn_pkey* CopyPublicKey(struct ccn_pkey *key)
{
    struct ccn_pkey *key_copy = NULL;
    SetPublicKey(&key_copy, key);
    return(key_copy);
}

/*
 * Set the public key in the destination buffer using the key pointed to by the source.
 * 
 * @param dst - destination where the new key will be stored.
 * @param src - pointer to origin key
 *
 * @return 0 if successful, nonzero otherwise
 */
int SetPublicKey(struct ccn_pkey **dst, struct ccn_pkey *src)
{
    int res;

    if (*dst) 
    {
        ccn_crypto_pubkey_destroy(dst);
    }

    uint8_t *buf = NULL;
    printf("here1\n");
    res = ccn_crypto_pubkey_serialize(src, &buf);
    printf("here2\n");
    *dst = ccn_crypto_pubkey_deserialize(buf, res);

    free(buf);

    return (*dst != NULL);
}

///// Migration needed

int ccn_crypto_pubkey_destroy(struct ccn_pkey **key)
{
    EVP_PKEY *p = *((EVP_PKEY **)key);
    EVP_PKEY_free(p);
    *key = NULL;
    return(0);
}

int ccn_crypto_pubkey_serialize(struct ccn_pkey *pubkey, uint8_t **out_buf)
{
    EVP_PKEY *key = (EVP_PKEY *)pubkey;
    uint8_t *p = NULL;
    printf("id2key\n");
    int len = i2d_PUBKEY(key, NULL);

    printf("so far so good\n");
    *out_buf = (uint8_t*)OPENSSL_malloc(len);
    p = *out_buf;

    return (i2d_PUBKEY(key, &p));
}

struct ccn_pkey* ccn_crypto_pubkey_deserialize(uint8_t const *buf, unsigned int len)
{
    uint8_t const *p;
    p = buf;
    return ((struct ccn_pkey *)d2i_PUBKEY(NULL, &p, len));
}

struct ccn_pkey* ccn_crypto_pubkey_from_pkcs12(char *filename, char *password)
{
    EVP_PKEY *privkey = NULL;
    X509 *cert = NULL;

    FILE *fp;
    PKCS12 *keystore;
    struct ccn_pkey *pubkey = NULL;
    int res;

    if(_addedAlgs == 0) {
        OpenSSL_add_all_algorithms();
        _addedAlgs = 1;
    }

    fp = fopen(filename, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Unable to open %s", filename);
        return(NULL);
    }

    keystore = d2i_PKCS12_fp(fp, NULL);
    fclose(fp);
    if (keystore == NULL) {
        fprintf(stderr, "Unable to create keystore instance\n");
        return(NULL);
    }

    res = PKCS12_parse(keystore, password, &privkey, &cert, NULL);
    PKCS12_free(keystore);

    if (res == 0) {
        fprintf(stderr, "Bad parse of keystore file\n");
        return(NULL);
    }

    pubkey = (struct ccn_pkey *) X509_get_pubkey(cert);

    EVP_PKEY_free(privkey);
    X509_free(cert);

    return(pubkey);
}

struct ccn_pkey* ccn_crypto_privkey_from_pkcs12(char *filename, char *password)
{
    EVP_PKEY *privkey = NULL;
    X509 *cert = NULL;

    FILE *fp;
    PKCS12 *keystore;
    int res;

    if(_addedAlgs == 0) {
        OpenSSL_add_all_algorithms();
        _addedAlgs = 1;
    }

    fp = fopen(filename, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Unable to open %s", filename);
        return(NULL);
    }

    keystore = d2i_PKCS12_fp(fp, NULL);
    fclose(fp);
    if (keystore == NULL) {
        fprintf(stderr, "Unable to create keystore instance\n");
        return(NULL);
    }

    res = PKCS12_parse(keystore, password, &privkey, &cert, NULL);
    PKCS12_free(keystore);

    if (res == 0) {
        fprintf(stderr, "Bad parse of keystore file\n");
        return(NULL);
    }

    X509_free(cert);

    return((struct ccn_pkey *)privkey);
}

struct ccn_pkey* ccn_crypto_pubkey_load_default(void)
{
    struct ccn_charbuf *loc = ccn_charbuf_create();
    ccn_charbuf_putf(loc, "%s/.ccnx/.ccnx_keystore", getenv("HOME"));
    struct ccn_pkey *pubkey = ccn_crypto_pubkey_from_pkcs12(
        ccn_charbuf_as_string(loc),
        "Th1s1sn0t8g00dp8ssw0rd.");

    if (pubkey == NULL) {
        fprintf(stderr, "%d %s unable to retrieve default public key\n",
                __LINE__, __func__);
    }
    ccn_charbuf_destroy(&loc);
    return(pubkey);
}

struct ccn_pkey* ccn_crypto_privkey_load_default(void)
{
    struct ccn_charbuf *loc = ccn_charbuf_create();
    ccn_charbuf_putf(loc, "%s/.ccnx/.ccnx_keystore", getenv("HOME"));

    fprintf(stderr, "%d %s reading default privkey from %s\n", __LINE__, __func__, ccn_charbuf_as_string(loc));

    struct ccn_pkey *privkey = ccn_crypto_privkey_from_pkcs12(
        ccn_charbuf_as_string(loc),
        "Th1s1sn0t8g00dp8ssw0rd.");

    if (privkey == NULL) {
        fprintf(stderr, "%d %s unable to retrieve default private key\n",
                __LINE__, __func__);
    }
    ccn_charbuf_destroy(&loc);
    return(privkey);
}

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
void ccn_crypto_name_asym_encrypt(struct ccn_pkey *pubkey, uint8_t *name, const size_t length, struct ccn_pkey *symkey, uint8_t **out_name, size_t *out_name_length)
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
}

/*
 * Bridge function
 */
void ccn_crypto_name_asym_decrypt(struct ccn_pkey *privkey, uint8_t *encrypted, struct ccn_pkey **out_symkey, struct ccn_charbuf **out_decrypted, struct ccn_indexbuf **out_decrypted_comps)
{
    RSA *rsa_privkey = EVP_PKEY_get1_RSA((EVP_PKEY *)privkey);

    if (rsa_privkey == NULL) {
        DEBUG_PRINT(
            "ABORT %d %s Unable to extract RSA public key\n",
            __LINE__, __func__);
        abort();
    }

    uint8_t *symkey_data = NULL;
    unsigned int symkey_bytes;
    uint8_t *decrypted = NULL;

    printf("okay... so far so good. trying decrypt_name_on_node\n");

    int decrypted_length =  decrypt_name_on_node(encrypted,
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

void ccn_crypto_content_decrypt(struct ccn_pkey *symkey, uint8_t *encrypted_content, size_t length, uint8_t **content, size_t *content_length)
{
    unsigned int out_length;
    *content = decrypt_data(
        (uint8_t *)encrypted_content,
        (unsigned int)length,
        NULL,
        &out_length,
        ccn_crypto_symkey_key(symkey),
        (unsigned int)ccn_crypto_symkey_bytes(symkey));
    *content_length = (size_t)out_length;

}

struct ccn_pkey* ccn_crypto_symkey_init_all(const uint8_t *key, const size_t num_bytes)
{
    struct ccn_crypto_symkey *symkey = calloc(1, sizeof(struct ccn_crypto_symkey));

    symkey->nbits = num_bytes * 8;
    symkey->nbytes = num_bytes;

    symkey->key = calloc(num_bytes, sizeof(uint8_t));
    memcpy(symkey->key, key, symkey->nbytes);

    return((struct ccn_pkey *)symkey);
}

size_t ccn_crypto_symkey_bits(struct ccn_pkey *key)
{
    struct ccn_crypto_symkey *symkey = (struct ccn_crypto_symkey *)key;
    return(symkey->nbits);
}

size_t ccn_crypto_symkey_bytes(struct ccn_pkey *key)
{
    struct ccn_crypto_symkey *symkey = (struct ccn_crypto_symkey *)key;
    return(symkey->nbytes);
}

uint8_t* ccn_crypto_symkey_key(struct ccn_pkey *key)
{
    struct ccn_crypto_symkey *symkey = (struct ccn_crypto_symkey *)key;
    return(symkey->key);
}

int encrypt_name_for_node(RSA * node_pubkey, uint8_t * privateName, int privateName_length, uint8_t * symmkey, unsigned int symmkey_length, uint8_t ** encryptedName)
{
    uint8_t * shortEncryptedName;
    int r;

    r = encrypt_binary(privateName, privateName_length, symmkey, symmkey_length, node_pubkey, &shortEncryptedName);

    *encryptedName = (uint8_t *)malloc(r+1);
    *encryptedName[0] = NO_PER_LINK_ENCRYPTION;
    memcpy((*encryptedName)+1, shortEncryptedName, r);

    free(shortEncryptedName);
    return r+1;
}

int decrypt_name_on_node(uint8_t * ciphertext, RSA * node_pubkey, uint8_t ** symmkey, unsigned int * symmkey_length, uint8_t ** decryptedName)
{
    return decrypt_binary(ciphertext, symmkey, symmkey_length, node_pubkey, decryptedName);
}

/*
 * Attaches a symmetric key (if present) and encrypts name
 */
int encrypt_binary(uint8_t * name, unsigned int name_length, uint8_t * symmkey, unsigned int symmkey_length, RSA * key, uint8_t ** encrypted_name)
{
    uint8_t * toEncrypt; // toEncrypt = name_length || name || symmk_length || symmkey
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
    if(!(toEncrypt = (uint8_t *) malloc(toEncryptLen)))
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
 * Same as above, but it also encodes the ciphertext in "pseudo-base64" (where '/' is replaced with
 * '-') a name.
 */
int encrypt_encode(uint8_t * name, unsigned int name_length, uint8_t * symmkey, unsigned int symmkey_length, RSA * key, uint8_t ** encrypted_name)
{

    int ciphlen;
    uint8_t * ciph;

    ciphlen = encrypt_binary(name, name_length, symmkey, symmkey_length, key, &ciph);

    // Encode in Base64 the ciphertext
    *encrypted_name = (uint8_t *)base64_encode(ciph, ciphlen);

    free(ciph);
    return (int)strlen((char* )*encrypted_name);
}


int decrypt_binary(uint8_t * encrypted_name, uint8_t ** symmkey, unsigned int * symmkey_length, RSA * key, uint8_t ** plaintext)
{
    uint8_t * plain; //  name_length || name || symmk_length || symmkey
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

    *plaintext = (uint8_t *) malloc(msglen);
    *symmkey = (uint8_t *) malloc(*symmkey_length);

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
int decrypt_decode(char * encrypted_name, uint8_t ** symmkey, unsigned int * symmkey_length, RSA * key, uint8_t ** plaintext)
{
    uint8_t * ciph; // E(name_length || name || symmk_length || symmkey)
    int msglen;

    // Decode base64 ciphertext
    if(!(ciph = base64_decode(encrypted_name)))
        return ERR_DECODING_CIPHERTEXT;

    msglen = decrypt_binary(ciph, symmkey, symmkey_length, key, plaintext);
    free(ciph);

    return msglen;
}

// if ciphertext
uint8_t * decrypt_data(uint8_t * ciphertext, unsigned int ciphertext_length, uint8_t * plaintext, unsigned int * len, uint8_t * key, unsigned int keylen)
{
    int ret;
    int plainlen = ciphertext_length - IVLEN - MACLEN;

    assert(keylen = 16);

    if(!plaintext)
        plaintext = (uint8_t *)malloc(plainlen);

    if((ret = dem_decrypt(ciphertext, plainlen, plaintext, key)))
        *len = ret;
    else
        *len = plainlen;

    return plaintext;
}

/*
 * Encrypts a name or a subset of a name using RSA-OAEP.
 */
int encrypt_name(uint8_t * name, unsigned int name_length, RSA * key, uint8_t ** encrypted_name)
{
    int kemlen;
    int modsize;
    uint8_t * kem;
    uint8_t * dem;
    uint8_t sesskey[KEYLEN];

    modsize = BN_num_bytes(key->n);

    *encrypted_name = (uint8_t *) malloc(2 + modsize + 2 + IVLEN + name_length  + MACLEN); // len KEM + KEM + len DEM + DEM (AES-CTR w/ IV + MAC)

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

int dem_encrypt(uint8_t * plaintext, unsigned int len, uint8_t * dem, uint8_t * sesskey)
{
    if(!RAND_bytes(sesskey, KEYLEN))
        return -1;

    return symm_enc(plaintext, len, dem, sesskey);
}

// len does not consider the mac, but only the message
int dem_decrypt(uint8_t * dem, unsigned int len, uint8_t * plaintext, uint8_t * sesskey)
{
    uint8_t ecount_buf[AES_BLOCK_SIZE];
    uint8_t IV[IVLEN];
    uint8_t mac[MACLEN];
    uint8_t * aes_key;
    uint8_t * mac_key;
    unsigned int num;

    AES_KEY aeskey;
    aes_key = KDF(sesskey, KEYLEN, "\0", 1);
    mac_key = KDF(sesskey, KEYLEN, "\1", 1);

    if(AES_set_encrypt_key(aes_key, KEYLEN * 8, &aeskey))
        return -2;

    memset(ecount_buf, 0, AES_BLOCK_SIZE);
    num = 0;
    memcpy(IV, dem, IVLEN);

    HMAC(EVP_sha256(), mac_key, MACKLEN, dem, len + IVLEN, mac, NULL);

    if(memcmp(mac, dem + len + IVLEN, MACLEN))
    {
        return -3;
    }

    AES_ctr128_encrypt(dem + IVLEN, plaintext, len, &aeskey, IV, ecount_buf, &num);

    free(aes_key);
    free(mac_key);
    return 0;

}

int kem_encrypt(int len, uint8_t * session_key, uint8_t * ciphertext, RSA * key)
{
    return RSA_public_encrypt(len, session_key, ciphertext, key, RSA_PKCS1_OAEP_PADDING);
}

int kem_decrypt(int len, uint8_t * kem, uint8_t * session_key, RSA * key)
{
    char* buff[120];
    int lib, func, reason;
    unsigned long error;
    DEBUG_PRINT("%d\n", len);
    int result = RSA_private_decrypt(len, kem, session_key, key, RSA_PKCS1_OAEP_PADDING);
    error = ERR_get_error();
    DEBUG_PRINT("%lu\n", error);
    DEBUG_PRINT("%d %d %d\n", ERR_GET_LIB(error), ERR_GET_FUNC(error), ERR_GET_REASON(error));
    ERR_load_crypto_strings();
    ERR_error_string(error, buff);
    DEBUG_PRINT("Error: %s\n", buff);
    return result;
}

int symm_enc_no_mac(uint8_t * plaintext, unsigned int plaintext_length, uint8_t * ciphertext, uint8_t * key)
{
    uint8_t ecount_buf[AES_BLOCK_SIZE];
    unsigned int num = 0;
    uint8_t IV[IVLEN];
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
int symm_dec_no_mac(uint8_t * ciphertext, unsigned int ciphertext_length, uint8_t * plaintext, uint8_t * key)
{
    uint8_t ecount_buf[AES_BLOCK_SIZE];
    uint8_t IV[IVLEN];
    unsigned int num = 0;

    AES_KEY aeskey;

    if(AES_set_encrypt_key(key, KEYLEN * 8, &aeskey))
        return -2;

    memset(ecount_buf, 0, AES_BLOCK_SIZE);
    memcpy(IV, ciphertext, IVLEN);

    AES_ctr128_encrypt(ciphertext + IVLEN, plaintext, ciphertext_length - IVLEN, &aeskey, IV, ecount_buf, &num);

    return 0;
}


int symm_enc(uint8_t * plaintext, unsigned int plaintext_length, uint8_t * ciphertext, uint8_t * key)
{
    uint8_t ecount_buf[AES_BLOCK_SIZE];
    uint8_t * aes_key;
    uint8_t * mac_key;
    unsigned int num = 0;
    uint8_t IV[IVLEN];
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

    free(aes_key);
    free(mac_key);
    return 0;
}

/*
 * Decrypts a name encrypted using "encrypt" above
 * Returns the length of the encrypted payload, or a negative
 * value in case of error.
 * The length of encrypted_name is implicit in the format
 */
int decrypt_name(uint8_t * encrypted_name, RSA * key, uint8_t ** plaintext)
{
    int demlen;
    int kemlen;
    uint8_t * kem;
    uint8_t * dem;
    uint8_t sesskey[KEYLEN];

    kemlen = (encrypted_name[0] & 0xFF) * 256 + (encrypted_name[1] & 0xFF);
    kem = encrypted_name;
    dem = encrypted_name + kemlen + 2;
    demlen = (dem[0] & 0xFF) * 256 + (dem[1] & 0xFF);

    *plaintext = (uint8_t *) malloc(demlen);

    if (kem_decrypt(kemlen, kem+2, sesskey, key)==-1)
    {
        DEBUG_PRINT("ERR DECRYPTING KEM\n");
        return ERR_DECRYPTING_KEM;
    }

    if(dem_decrypt(dem+2 , demlen, *plaintext, sesskey))
        return ERR_DECRYPTING_DEM;

    return demlen;
}

