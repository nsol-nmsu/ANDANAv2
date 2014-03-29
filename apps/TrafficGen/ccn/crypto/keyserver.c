
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

#include <ccn/crypto/key.h>
//#include <ccn/util/util.h>


#include <ccn/crypto/keyserver.h>
#include <ccn/util/util.h>



struct ccn_keyserver {
    struct ccn_charbuf *namespace;
    struct ccn_charbuf *key_name;
    struct ccn_pkey *pubkey;
    unsigned char *DER_pubkey;
    int DER_length;
    struct ccn_charbuf *content;
    struct ccn *handle;
    struct ccn_closure callback;
};

struct ccn_charbuf *
ccn_keyserver_namespace(struct ccn_keyserver *server)
{
    return (server->namespace);
}

static int
ccn_keyserver_update_content(struct ccn_keyserver *server);







struct ccn_keyserver *
ccn_keyserver_init(struct ccn *handle, const char *namespace, struct ccn_pkey *pubkey)
{
    int res;
    struct ccn_keyserver *server = calloc(1, sizeof(*server));
    server->namespace = ccn_charbuf_create();

    res = ccn_name_from_uri(server->namespace, namespace);

    if (res < 0) {
        fprintf(stderr, "Bad namespace URI\n");
        goto BAIL_NAMESPACE;
    }

    server->key_name = ccn_charbuf_create();
    ccn_charbuf_append_charbuf(server->key_name, server->namespace);
    ccn_name_append_str(server->key_name, "key");


    if (handle == NULL) {
        fprintf(stderr, "Bad handle\n");
        goto BAIL_CONNECT;
    }

    server->handle = handle;

    server->callback.p = &ccn_keyserver_serve;
    server->callback.data = server;


    if (pubkey == NULL) {
        if ((pubkey = ccn_crypto_pubkey_load_default()) == NULL) {
            fprintf(stderr, "Unable to load default public key and no public key provided\n");
            goto BAIL_KEY_INIT;
        }

    }

    ccn_keyserver_update_pubkey(server, pubkey);


    res = ccn_set_interest_filter(server->handle, server->namespace, &server->callback);

    if (res < 0) {
        fprintf(stderr, "Failed to set interest filter\n");
        goto BAIL_FILTER;
    }

    return (server);

BAIL_FILTER:
BAIL_CONNECT:
    ccn_charbuf_destroy(&server->namespace);
BAIL_KEY_INIT:
BAIL_NAMESPACE:
    free(server);
    return (NULL);
}


int
ccn_keyserver_update_pubkey(struct ccn_keyserver *server, struct ccn_pkey *pubkey)
{
    int res;
    server->pubkey = pubkey;

    if (server->DER_pubkey) {
        OPENSSL_free(server->DER_pubkey);
    }

    server->DER_length = ccn_crypto_pubkey_serialize(server->pubkey, &server->DER_pubkey);
    res = ccn_keyserver_update_content(server);

    return (res);
}

static int
ccn_keyserver_update_content(struct ccn_keyserver *server)
{
    struct ccn_signing_params sp = CCN_SIGNING_PARAMS_INIT;
    sp.type = CCN_CONTENT_KEY;

    if (server->content) {
        ccn_charbuf_destroy(&server->content);
    }
    server->content = ccn_charbuf_create();

    struct ccn_charbuf *new_content = ccn_charbuf_create();
    ccn_charbuf_append(new_content, server->DER_pubkey, server->DER_length);

    int res = ccn_sign_content(server->handle,
                           server->content,
                           server->key_name,
                           &sp,
                           new_content->buf,
                           new_content->length);

    if (res < 0) {
        DEBUG_PRINT("%d %s Failed to construct content object\n", __LINE__, __func__);
    }

    return (res);
}



enum ccn_upcall_res
ccn_keyserver_serve(struct ccn_closure *selfp,
                enum ccn_upcall_kind kind,
                struct ccn_upcall_info *info)
{
    int res;
    struct ccn_keyserver *server = selfp->data;

    switch (kind) {
    case CCN_UPCALL_INTEREST:
        DEBUG_PRINT("%d %s received session request\n", __LINE__, __func__);
        break;
    case CCN_UPCALL_INTEREST_TIMED_OUT:
        DEBUG_PRINT("%d %s received session request time out\n", __LINE__, __func__);
        /* Fall through */
    default:
        DEBUG_PRINT("OUT %d %s\n", __LINE__, __func__);
        return(CCN_UPCALL_RESULT_OK);
    }


    res = ccn_put(server->handle, server->content->buf, server->content->length);

    if (res < 0) {
        return (CCN_UPCALL_RESULT_ERR);
    }
    return (CCN_UPCALL_RESULT_INTEREST_CONSUMED);
}

int
ccn_keyserver_destroy(struct ccn_keyserver **server)
{
    struct ccn_keyserver *kserver = *server;

    ccn_charbuf_destroy(&kserver->namespace);
    ccn_charbuf_destroy(&kserver->key_name);
    free(kserver->DER_pubkey);
    ccn_charbuf_destroy(&kserver->content);
    free(kserver);

    *server = NULL;

    return (0);
}


