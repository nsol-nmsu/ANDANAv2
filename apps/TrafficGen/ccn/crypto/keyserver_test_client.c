#include <stdlib.h>
#include <stdio.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include <ccn/ccn.h>
#include <ccn/charbuf.h>
#include <ccn/uri.h>
#include <ccn/signing.h>

#include <key.h>
#include <util.h>


struct ccn_pkey *
deserialize_pubkey(unsigned char const *buf, unsigned int len)
{
    unsigned char const *p;
    p = buf;
    return ((struct ccn_pkey *)d2i_PUBKEY(NULL, &p, len));
}

void
test_serialization(struct ccn_pkey *a, struct ccn_pkey *b)
{
    int res = EVP_PKEY_cmp((EVP_PKEY *) a, (EVP_PKEY *) b);

    switch (res) {
    case 1:
        fprintf(stderr, "match\n");
        break;
    case 0:
        fprintf(stderr, "different\n");
        break;
    case -1:
        fprintf(stderr, "different types\n");
        break;
    case -2:
        fprintf(stderr, "unsupported\n");
        break;
    }
}

int main()
{
    struct ccn *h = ccn_create();
    ccn_connect(h, NULL);

    struct ccn_charbuf *key_name = ccn_charbuf_create();
    ccn_name_from_uri(key_name, "ccnx:/hello/key");

    struct ccn_charbuf *templ = ccn_charbuf_create();
    ccn_charbuf_append_tt(templ, CCN_DTAG_Interest, CCN_DTAG);
    ccn_charbuf_append(templ, key_name->buf, key_name->length); /* Name */
    ccn_charbuf_append_closer(templ); /* </Interest> */

    struct ccn_charbuf *key_obj = ccn_charbuf_create();
    struct ccn_parsed_ContentObject pco = {0};

    struct ccn_indexbuf *comps = ccn_indexbuf_create();

    int res = ccn_get(h,
                      key_name,
                      templ,
                      10000,
                      key_obj,
                      &pco,
                      comps,
                      0);



    unsigned char const *DER_pubkey = NULL;
    size_t DER_length;
    res = ccn_content_get_value(key_obj->buf, key_obj->length, &pco, &DER_pubkey, &DER_length);

    struct ccn_pkey *recvd_pubkey = deserialize_pubkey(DER_pubkey, DER_length);

    struct ccn_pkey *default_pubkey = ccn_crypto_pubkey_load_default();


    test_serialization(recvd_pubkey, default_pubkey);

}
