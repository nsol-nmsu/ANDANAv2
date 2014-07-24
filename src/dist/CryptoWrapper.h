#ifndef CRYPTO_WRAPPER_H_
#define CRYPTO_WRAPPER_H_

#include "Util.h"
#include "Crypto.h"

#include <inttypes.h>

#include <ccn/charbuf.h>
#include <ccn/ccn.h>
#include <ccn/uri.h>

// Crypto error codes
#define ERR_DECRYPTING_KEM              -1
#define ERR_DECRYPTING_DEM              -2
#define ERR_ALLOCATION_ERROR            -3
#define ERR_DECODING_CIPHERTEXT         -4

// Configuration flags
#define NO_PER_LINK_ENCRYPTION          0
#define SYMMETRIC_PER_LINK_ENCRYPTION   1
#define ASYMMETRIC_PER_LINK_ENCRYPTION  2

/*
 * Initialize a symmetric key with the specified number of bits.
 * 
 * @param key_bits - bits in the key
 *
 * @return a CCN key
 */
struct ccn_pkey* InitSymmetricKey(const uint32_t key_bits);

/*
 * Create a copy of the specified public key.
 * 
 * @param key - key to copy.
 *
 * @return copy of the passed in key.
 */
struct ccn_pkey* CopyPublicKey(struct ccn_pkey *key);

/*
 * Set the public key in the destination buffer using the key pointed to by the source.
 * 
 * @param dst - destination where the new key will be stored.
 * @param src - pointer to origin key
 *
 * @return 0 if successful, nonzero otherwise
 */
int SetPublicKey(struct ccn_pkey **dst, struct ccn_pkey *src);

//////// Migration needed

struct ccn_crypto_symkey 
{
    unsigned char *key;
    size_t nbits;
    size_t nbytes;
};

struct ccn_pkey* ccn_crypto_pubkey_deserialize(uint8_t const *buf, unsigned int len);
struct ccn_pkey* ccn_crypto_pubkey_from_pkcs12(char *filename, char *password);
struct ccn_pkey* ccn_crypto_privkey_from_pkcs12(char *filename, char *password);
struct ccn_pkey* ccn_crypto_pubkey_load_default(void);
struct ccn_pkey* ccn_crypto_privkey_load_default(void);
void ccn_crypto_name_asym_encrypt(struct ccn_pkey *pubkey, unsigned char *name, const size_t length, struct ccn_pkey *symkey, unsigned char **out_name, size_t *out_name_length);
void ccn_crypto_name_asym_decrypt(struct ccn_pkey *privkey, unsigned char *encrypted, struct ccn_pkey **out_symkey, struct ccn_charbuf **out_decrypted, struct ccn_indexbuf **out_decrypted_comps);
void ccn_crypto_content_decrypt(struct ccn_pkey *symkey, unsigned char *encrypted_content, size_t length, unsigned char **content, size_t *content_length);
struct ccn_pkey* ccn_crypto_symkey_init_all(const unsigned char *key, const size_t num_bytes);
size_t ccn_crypto_symkey_bits(struct ccn_pkey *key);
size_t ccn_crypto_symkey_bytes(struct ccn_pkey *key);
unsigned char* ccn_crypto_symkey_key(struct ccn_pkey *key);
int encrypt_name_for_node(RSA * node_pubkey, unsigned char * privateName, int privateName_length, unsigned char * symmkey, unsigned int symmkey_length, unsigned char ** encryptedName);
int decrypt_name_on_node(unsigned char * ciphertext, RSA * node_pubkey, unsigned char ** symmkey, unsigned int * symmkey_length, unsigned char ** decryptedName);
int encrypt_binary(unsigned char * name, unsigned int name_length, unsigned char * symmkey, unsigned int symmkey_length, RSA * key, unsigned char ** encrypted_name);
int encrypt_encode(unsigned char * name, unsigned int name_length, unsigned char * symmkey, unsigned int symmkey_length, RSA * key, unsigned char ** encrypted_name);
int decrypt_binary(unsigned char * encrypted_name, unsigned char ** symmkey, unsigned int * symmkey_length, RSA * key, unsigned char ** plaintext);
int decrypt_decode(char * encrypted_name, unsigned char ** symmkey, unsigned int * symmkey_length, RSA * key, unsigned char ** plaintext);
unsigned char * decrypt_data(unsigned char * ciphertext, unsigned int ciphertext_length, unsigned char * plaintext, unsigned int * len, unsigned char * key, unsigned int keylen);
int encrypt_name(unsigned char * name, unsigned int name_length, RSA * key, unsigned char ** encrypted_name);
int dem_decrypt(unsigned char * dem, unsigned int len, unsigned char * plaintext, unsigned char * sesskey);
int dem_encrypt(unsigned char * plaintext, unsigned int len, unsigned char * dem, unsigned char * sesskey);
int kem_decrypt(int len, unsigned char * kem, unsigned char * session_key, RSA * key);
int kem_encrypt(int len, unsigned char * session_key, unsigned char * ciphertext, RSA * key);
int symm_enc_no_mac(unsigned char * plaintext, unsigned int plaintext_length, unsigned char * ciphertext, unsigned char * key);
int symm_dec_no_mac(unsigned char * ciphertext, unsigned int ciphertext_length, unsigned char * plaintext, unsigned char * key);
int symm_enc(unsigned char * plaintext, unsigned int plaintext_length, unsigned char * ciphertext, unsigned char * key);
int decrypt_name(unsigned char * encrypted_name, RSA * key, unsigned char ** plaintext);

#endif /* CRYPTO_WRAPPER_H_ */
