

#ifndef CCN_CRYPTO_KEY_H_
#define CCN_CRYPTO_KEY_H_

#include <stdlib.h>

//#include <openssl/rsa.h>


struct ccn_pkey *
ccn_crypto_symkey_init(const size_t key_bits);

struct ccn_pkey *
ccn_crypto_symkey_init_all(const unsigned char *key, const size_t num_bytes);

struct ccn_pkey *
ccn_crypto_symkey_from_pkcs12(char *filename, char *password);

struct ccn_pkey *
ccn_crypto_symkey_copy(struct ccn_pkey *key);

size_t
ccn_crypto_symkey_bits(struct ccn_pkey *key);

size_t
ccn_crypto_symkey_bytes(struct ccn_pkey *key);

unsigned char *
ccn_crypto_symkey_key(struct ccn_pkey *key);

int
ccn_crypto_symkey_destroy(struct ccn_pkey **key);






struct ccn_pkey *
ccn_crypto_pubkey_create(void);

int
ccn_crypto_pubkey_init(struct ccn_pkey *key, const size_t key_bits);

struct ccn_pkey *
ccn_crypto_pubkey_copy(struct ccn_pkey *key);

int
ccn_crypto_pubkey_set(struct ccn_pkey **dst, struct ccn_pkey *src);

struct ccn_pkey *
ccn_crypto_pubkey_from_pkcs12(char *filename, char *password);

struct ccn_pkey *
ccn_crypto_privkey_from_pkcs12(char *filename, char *password);

struct ccn_pkey *
ccn_crypto_pubkey_load_default(void);

struct ccn_pkey *
ccn_crypto_privkey_load_default(void);

size_t
ccn_crypto_pubkey_size(struct ccn_pkey *key);

int
ccn_crypto_pubkey_serialize(struct ccn_pkey *pubkey, unsigned char **out_buf);

struct ccn_pkey *
ccn_crypto_pubkey_deserialize(unsigned char const *buf, unsigned int len);

int
ccn_crypto_pubkey_destroy(struct ccn_pkey **pkey);

#endif /* CCN_CRYPTO_KEY_H_ */
