
#include <key.h>

#include <ccn/charbuf.h>

#include <string.h>

#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>


static int ccn_crypto_pubkey_added_algos = 0;

/* Opaque representation of a symmetric key.
 * Plan to replace this with EVP_PKEY (if possible).
 */

struct ccn_crypto_symkey {
    unsigned char *key;
    size_t nbits;
    size_t nbytes;
};


struct ccn_pkey *
ccn_crypto_symkey_init(const size_t key_bits)
{
    struct ccn_crypto_symkey *symkey = calloc(1, sizeof(struct ccn_crypto_symkey));

    symkey->nbits = key_bits;
    symkey->nbytes = key_bits / 8;

    symkey->key = calloc(1, symkey->nbytes * sizeof(unsigned char));
    RAND_bytes(symkey->key, (int)symkey->nbytes);

    return((struct ccn_pkey *)symkey);
}

struct ccn_pkey *
ccn_crypto_symkey_init_all(const unsigned char *key, const size_t num_bytes)
{
    struct ccn_crypto_symkey *symkey = calloc(1, sizeof(struct ccn_crypto_symkey));

    symkey->nbits = num_bytes * 8;
    symkey->nbytes = num_bytes;

    symkey->key = calloc(num_bytes, sizeof(unsigned char));
    memcpy(symkey->key, key, symkey->nbytes);

    return((struct ccn_pkey *)symkey);
}

struct ccn_pkey *
ccn_crypto_symkey_copy(struct ccn_pkey *key)
{
    struct ccn_crypto_symkey *k = (struct ccn_crypto_symkey *)key;
    return(ccn_crypto_symkey_init_all(k->key, k->nbytes));
}


struct ccn_pkey *
ccn_crypto_symkey_from_pkcs12(char *filename, char *password)
{
    EVP_PKEY *privkey = NULL;
    X509 *cert = NULL;

    FILE *fp;
    PKCS12 *keystore;
    int res;

    if(ccn_crypto_pubkey_added_algos == 0) {
    	OpenSSL_add_all_algorithms();
    	ccn_crypto_pubkey_added_algos = 1;
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

//    /* cache the public key digest to avoid work later */
//    if (1 != ASN1_item_digest(ASN1_ITEM_rptr(X509_PUBKEY), EVP_sha256(),
//                              X509_get_X509_PUBKEY(p->certificate),
//                              p->pubkey_digest, NULL)) return (-1);
//    p->pubkey_digest_length = SHA256_DIGEST_LENGTH;
//    p->initialized = 1;

    X509_free(cert);

    return((struct ccn_pkey *)privkey);
}


size_t
ccn_crypto_symkey_bits(struct ccn_pkey *key)
{
    struct ccn_crypto_symkey *symkey = (struct ccn_crypto_symkey *)key;
    return(symkey->nbits);
}

size_t
ccn_crypto_symkey_bytes(struct ccn_pkey *key)
{
    struct ccn_crypto_symkey *symkey = (struct ccn_crypto_symkey *)key;
    return(symkey->nbytes);
}

unsigned char *
ccn_crypto_symkey_key(struct ccn_pkey *key)
{
    struct ccn_crypto_symkey *symkey = (struct ccn_crypto_symkey *)key;
    return(symkey->key);
}

int
ccn_crypto_symkey_destroy(struct ccn_pkey **key)
{
    struct ccn_crypto_symkey *s = *((struct ccn_crypto_symkey **)key);

    free(s->key);
    free(s);
    return(0);
}







struct ccn_pkey *
ccn_crypto_pubkey_create(void)
{
    EVP_PKEY *pubkey = EVP_PKEY_new();
    return((struct ccn_pkey *)pubkey);
}


int
ccn_crypto_pubkey_init(struct ccn_pkey *key, const size_t key_bits)
{
    int res;
    EVP_PKEY *pkey = (EVP_PKEY *)key;
    RSA *rsa = RSA_new();
    BIGNUM *pub_exp = BN_new();

    BN_set_word(pub_exp, RSA_F4); /* Uses exponent of 65537 */
    res = 1;

    res &= RSA_generate_key_ex(rsa, (int)key_bits, pub_exp, NULL);
    res &= EVP_PKEY_set1_RSA(pkey, rsa);

    if (res == 0) {
        fprintf(stderr, "ABORT %s %d Error generating public key pair\n", __FILE__, __LINE__);
        abort();
    }

    RSA_free(rsa);
    BN_free(pub_exp);

    /* Convert OpenSSL successful return to 0 (and vice versa) to match ccnx*/
    return(!(res == 1));
}

struct ccn_pkey *
ccn_crypto_pubkey_copy(struct ccn_pkey *key)
{
    struct ccn_pkey *key_copy = NULL;
    ccn_crypto_pubkey_set(&key_copy, key);
    return(key_copy);
}

int
ccn_crypto_pubkey_set(struct ccn_pkey **dst, struct ccn_pkey *src)
{
    int res;

    if (*dst) {
        ccn_crypto_pubkey_destroy(dst);
    }

    unsigned char *buf = NULL;
    res = ccn_crypto_pubkey_serialize(src, &buf);
    *dst = ccn_crypto_pubkey_deserialize(buf, res);

    free(buf);

    return (*dst != NULL);
}

struct ccn_pkey *
ccn_crypto_pubkey_from_pkcs12(char *filename, char *password)
{
    EVP_PKEY *privkey = NULL;
    X509 *cert = NULL;

    FILE *fp;
    PKCS12 *keystore;
    struct ccn_pkey *pubkey = NULL;
    int res;

    if(ccn_crypto_pubkey_added_algos == 0) {
    	OpenSSL_add_all_algorithms();
    	ccn_crypto_pubkey_added_algos = 1;
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

struct ccn_pkey *
ccn_crypto_privkey_from_pkcs12(char *filename, char *password)
{
    EVP_PKEY *privkey = NULL;
    X509 *cert = NULL;

    FILE *fp;
    PKCS12 *keystore;
    int res;

    if(ccn_crypto_pubkey_added_algos == 0) {
    	OpenSSL_add_all_algorithms();
    	ccn_crypto_pubkey_added_algos = 1;
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


struct ccn_pkey *
ccn_crypto_pubkey_load_default(void)
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

struct ccn_pkey *
ccn_crypto_privkey_load_default(void)
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


size_t
ccn_crypto_pubkey_size(struct ccn_pkey *key)
{
    return(EVP_PKEY_size((EVP_PKEY *)key));
}


int
ccn_crypto_pubkey_serialize(struct ccn_pkey *pubkey, unsigned char **out_buf)
{
    EVP_PKEY *key = (EVP_PKEY *)pubkey;
    unsigned char *p = NULL;
    int len = i2d_PUBKEY(key, NULL);

    *out_buf = OPENSSL_malloc(len);
    p = *out_buf;

    return (i2d_PUBKEY(key, &p));
}

struct ccn_pkey *
ccn_crypto_pubkey_deserialize(unsigned char const *buf, unsigned int len)
{
    unsigned char const *p;
    p = buf;
    return ((struct ccn_pkey *)d2i_PUBKEY(NULL, &p, len));
}


int
ccn_crypto_pubkey_destroy(struct ccn_pkey **key)
{
    EVP_PKEY *p = *((EVP_PKEY **)key);
    EVP_PKEY_free(p);
    *key = NULL;
    return(0);
}
