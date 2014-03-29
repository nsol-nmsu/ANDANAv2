/*
 * proxy.c
 *
 *  Created on: Jun 29, 2011
 *      Author: sdibened
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <limits.h>


#include "tgen.h"
#include "util.h"



/**
 * Initialize a new CCN proxy with specified namespaces.
 *
 * @param Interest filter URI (specifies Interests that should be accepted)
 * @param Namespace this proxy is responsible for
 * (outbound Interest name on client-side, input Interest name on server-side)
 *
 * @returns Initialized ccn proxy
 */

struct ccn_proxy *
ccn_proxy_init(const char *filter_uri,
               const char *prefix_uri)
{
    struct ccn_proxy *proxy = calloc(1, sizeof(struct ccn_proxy));
    struct ccn_buf_decoder decoder;
    struct ccn_buf_decoder *d = &decoder;
    int res;

    DEBUG_PRINT("IN %d %s\n", __LINE__, __func__);



    /* Convert URI to name this proxy is responsible for */

    proxy->prefix = ccn_charbuf_create();
    res = ccn_name_from_uri(proxy->prefix, prefix_uri);

    if (res < 0) {
        DEBUG_PRINT("ABORT %d %s bad ccn URI: %s\n", __LINE__, __func__, prefix_uri);
        abort();
    }

    d = ccn_buf_decoder_start(d, proxy->prefix->buf, proxy->prefix->length);
    proxy->prefix_comps = ccn_indexbuf_create();
    proxy->prefix_ncomps = ccn_parse_Name(d, proxy->prefix_comps);


    proxy->filter = ccn_charbuf_create();
    res = ccn_name_from_uri(proxy->filter, filter_uri);

    if (res < 0) {
        DEBUG_PRINT("ABORT %d %s bad ccn URI: %s\n", __LINE__, __func__, filter_uri);
        abort();
    }


    /* Initialization should be done by ccn_proxy_connect() */

    proxy->handle_name = ccn_charbuf_create();
    ccn_charbuf_append_string(proxy->handle_name, "in/outb");



    DEBUG_PRINT("OUT %d %s\n", __LINE__, __func__);

    return(proxy);
}

/**
 * Change the ccn_closure called when an Interest arrives (inbound face only)
 *
 * @param proxy to have its Interest handler changed
 * @param callback to be used on receipt of Interest
 */

void
ccn_proxy_set_interest_handler(struct ccn_proxy *proxy,
                               struct ccn_closure *callback)
{
    proxy->int_handler = callback;
}

/**
 * Change the ccn_closure called when a Content Object arrives (outbound face only)
 *
 * @param proxy to have its Content Object handler changed
 * @param callback to be used on receipt of Content Object
 */

void
ccn_proxy_set_content_handler(struct ccn_proxy *proxy,
                              struct ccn_closure *callback)
{
    proxy->content_handler = callback;
}

/**
 * Convenience function to simultaneously update Interest and Content Object
 * handlers.
 *
 * @see ccn_proxy_set_interest_handler
 * @see ccn_proxy_set_content_handler
 *
 * @param proxy to update
 * @param int_callback to be used on receipt of Interest
 * @param content_callback to be used on receipt of Content Object
 */

void ccn_proxy_set_handlers(struct ccn_proxy *proxy,
                            struct ccn_closure *int_callback,
                            struct ccn_closure *content_callback)
{
    ccn_proxy_set_interest_handler(proxy, int_callback);
    ccn_proxy_set_content_handler(proxy, content_callback);
}


/**
 * Connect proxy to ccnd and announce namespace
 * @param proxy initialized ccn proxy
 * @returns 0 on success, -1 if fails to connect to ccnd
 */

int
ccn_proxy_connect(struct ccn_proxy *proxy)
{
    DEBUG_PRINT("IN %d %s\n", __LINE__, __func__);

    if ((proxy->handle = ccn_create()) == NULL) {
        DEBUG_PRINT("OUT %d %s failed to create %s ccn handle\n", __LINE__, __func__, proxy->handle_name->buf);
        return(-1);
    }

    if (ccn_connect(proxy->handle, NULL) == -1) {
        DEBUG_PRINT("OUT %d %s failed to connect %s ccn handle\n", __LINE__, __func__, proxy->handle_name->buf);
        return(-2);
    }


    DEBUG_PRINT("%d %s setting up interest handler\n", __LINE__, __func__);

    ccn_set_interest_filter(proxy->handle, proxy->filter, proxy->int_handler);

    DEBUG_PRINT("%d %s interest printer setup\n", __LINE__, __func__);
    DEBUG_PRINT("OUT %d %s\n", __LINE__, __func__);
    return(0);
}

/**
 * Run the proxy.
 *
 * Currently has return value (always 0), but implemented with forever loop.
 * This may change in the future to make ccn_proxy_run behave more like ccn_run.
 *
 * @param proxy to run (start proxy-ing traffic)
 * @returns 0 (always, expect negative value in future to indicate error)
 */

int
ccn_proxy_run(struct ccn_proxy *proxy)
{
    DEBUG_PRINT("IN %d %s\n", __LINE__, __func__);

    if (ccn_run(proxy->handle, -1) < 0) {
        DEBUG_PRINT("%d %s error running %s handle\n", __LINE__, __func__, proxy->handle_name->buf);
        return(-1);
    }

    DEBUG_PRINT("OUT %d %s\n", __LINE__, __func__);
    return(0);
}

/**
 * Destroy/free a ccn proxy.
 *
 * @param pointer to the proxy to be destroyed
 *
 * @returns 0 (always)
 */

int
ccn_proxy_destroy(struct ccn_proxy **proxy)
{
    struct ccn_proxy *p = *proxy;
    DEBUG_PRINT("IN %d %s\n", __LINE__, __func__);

    ccn_destroy(&(p->handle));

    ccn_charbuf_destroy(&(p->handle_name));

    ccn_indexbuf_destroy(&(p->prefix_comps));
    ccn_charbuf_destroy(&(p->prefix));

    ccn_charbuf_destroy(&(p->filter));

    free(p);

    DEBUG_PRINT("OUT %d %s\n", __LINE__, __func__);
    return(0);
}








/**
 * Finalize function used by hash table to clean up entries.
 *
 * @params e hash table enumerator to be cleaned up
 */

static void
ccn_proxy_server_finalize_entry(struct hashtb_enumerator *e)
{
}


/**
 * Allocate and initialize a new ccn proxy server. This is essentially a
 * ccn proxy, except it also has a hash table to remember the original and produced
 * names of Interests it processes.
 *
 * @param key_uri ccnx URI of key used for signing Content Objects
 * @param filter_uri ccnx URI to be used for Interest filtering (i.e. select what it SHOULD process)
 * @param prefix_uri ccnx URI of name prefix that should be removed from incoming Interests.
 *
 * Note that prefix_uri and filter_uri may be the same.
 *
 * @returns initialized ccn proxy server
 */

struct ccn_proxy_server *
ccn_proxy_server_init(const char *filter_uri, const char *prefix_uri)
{
    struct ccn_proxy_server *server = calloc(1, sizeof(struct ccn_proxy_server));
    server->proxy = ccn_proxy_init(filter_uri, prefix_uri);

    server->hash_param.finalize = &ccn_proxy_server_finalize_entry;
    server->cname_to_iname = hashtb_create(sizeof(struct ccn_charbuf *), &(server->hash_param));

    return(server);
}

/**
 * Up call handler used by server for handling Interests. Extracts an Interest
 * that has been stored in a single name component that immediately follows the
 * prefix used to initialize the server. This is the counterpart to the Interest
 * encapsulation function that may be used by proxy clients.
 *
 * @see ccn_proxy_server_init
 * @see ccn_proxy_client_encap_interest
 *
 * @params selfp's data is expected to point to a ccn proxy server
 * @param kind is the type of up call
 * @param info is normal ccn Interest information
 *
 * @returns result of upcall (OK or ERR)
 */

enum ccn_upcall_res
ccn_proxy_server_decap_interest(
    struct ccn_closure *selfp,
    enum ccn_upcall_kind kind,
    struct ccn_upcall_info *info)
{
    struct ccn_proxy_server *server = selfp->data;
    struct ccn_proxy *proxy = server->proxy;

    struct ccn_charbuf *new_interest = NULL;
    struct ccn_charbuf *new_name = NULL;

    struct ccn_charbuf *orig_name = NULL;
    struct ccn_indexbuf *orig_name_indexbuf = NULL;
    int orig_name_ncomps;

    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;

    int res;


    DEBUG_PRINT("IN %d %s\n", __LINE__, __func__);

    switch (kind) {
    case CCN_UPCALL_INTEREST:
        DEBUG_PRINT("%d %s received interest\n", __LINE__, __func__);
        break;
    default:
        DEBUG_PRINT("OUT %d %s\n", __LINE__, __func__);
        return(CCN_UPCALL_RESULT_OK);
    }


    /* Extract Name from Interest */

    orig_name_ncomps = ccn_util_extract_name(info->interest_ccnb,
                                             info->interest_comps,
                                             &orig_name,
                                             &orig_name_indexbuf);

    /* Decapsulate Interest. */

    const unsigned char *interest_ccnb = NULL;
    size_t interest_size;
    ccn_name_comp_get(orig_name->buf, orig_name_indexbuf, (unsigned int)proxy->prefix_ncomps, &interest_ccnb, &interest_size);



    /* Parse out the encap'd Interest */
    struct ccn_parsed_interest new_pi = {0};
    struct ccn_indexbuf *new_comps = ccn_indexbuf_create();
    res = ccn_parse_interest(interest_ccnb, interest_size, &new_pi, new_comps);

    if (res < 0) {
        DEBUG_PRINT("ABORT %d %s failed to parse encapsulated Interest res = %d\n", __LINE__, __func__, res);
        abort();
    }

    new_interest = ccn_charbuf_create();
    ccn_charbuf_append(new_interest, interest_ccnb, interest_size);

    struct ccn_indexbuf *new_name_comps = NULL;
    res = ccn_util_extract_name(interest_ccnb, new_comps, &new_name, &new_name_comps);


    /*Map new name to that of the original Interest*/


    hashtb_start(server->cname_to_iname, e);

    res = hashtb_seek(e, new_name->buf, new_name->length, 0);

    if (res == HT_NEW_ENTRY) {
        struct ccn_charbuf **p = e->data;
        *p = orig_name;
        res = 0;
    } else if (res == HT_OLD_ENTRY) {
        res = 0;
        DEBUG_PRINT("Interest recording found old entry\n");
    } else {
        DEBUG_PRINT("Error in Interest insertion\n");
    }
    hashtb_end(e);




    DEBUG_PRINT("%d %s starting to write new interest\n", __LINE__, __func__);

    res = ccn_express_interest(proxy->handle, new_name, proxy->content_handler, new_interest);

    DEBUG_PRINT("%d %s done to writing new interest\n", __LINE__, __func__);

    if(res != 0) {
        DEBUG_PRINT("ABORT %d %s express interest res = %d\n", __LINE__, __func__, res);
        abort();
    }

    ccn_indexbuf_destroy(&new_comps);

    ccn_charbuf_destroy(&new_name);
    ccn_charbuf_destroy(&new_interest);
    ccn_indexbuf_destroy(&orig_name_indexbuf);

    DEBUG_PRINT("OUT %d %s\n", __LINE__, __func__);

    return(CCN_UPCALL_RESULT_OK);
}

/**
 * Proxy server's up call handler for Content Objects. Encapsulates Content
 * Objects (sent in response to decapsulated Interests) within a new Content
 * Object. This entire package is can then be signed by the proxy server's key.
 * Client proxy is expected to decapsulate the Content Object.
 *
 * @see ccn_proxy_server_decap_interest
 * @see ccn_proxy_client_decap_content
 *
 * @params selfp's data is expected to point to a ccn proxy server
 * @params kind is the type of up call event
 * @params info is the normal ccn Content Object information
 *
 * @returns result of up call (OK or ERR)
 */

enum ccn_upcall_res
ccn_proxy_server_encap_content(
    struct ccn_closure *selfp,
    enum ccn_upcall_kind kind,
    struct ccn_upcall_info *info)
{
    struct ccn_proxy_server *server = selfp->data;
    struct ccn_proxy *proxy = server->proxy;

    struct ccn_charbuf *new_name = NULL;
    struct ccn_charbuf **orig_ptr = NULL;
    struct ccn_charbuf *orig_name = NULL;
    struct ccn_charbuf *new_content = NULL;
    struct ccn_signing_params sp = CCN_SIGNING_PARAMS_INIT;

    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;

    int res;

    DEBUG_PRINT("IN %d %s\n",__LINE__, __func__);

    switch (kind) {
    case CCN_UPCALL_CONTENT:           /**< incoming verified content */
        DEBUG_PRINT("%d %s Incoming verified content\n",__LINE__, __func__);
        break;
    case CCN_UPCALL_CONTENT_UNVERIFIED:/**< content that has not been verified */
        DEBUG_PRINT("%d %s Incoming unverified content\n", __LINE__, __func__);
        break;
    case CCN_UPCALL_CONTENT_BAD:        /**< verification failed */
        DEBUG_PRINT("%d %s Incoming bad content (verification failure)\n", __LINE__, __func__);
        break;

    case CCN_UPCALL_INTEREST_TIMED_OUT:/**< interest timed out */
        DEBUG_PRINT("OUT %d %s Interest timed out\n", __LINE__, __func__);
        return(CCN_UPCALL_RESULT_OK);

    case CCN_UPCALL_FINAL:/**< handler is about to be deregistered */
        DEBUG_PRINT("OUT %d %s final upcall\n", __LINE__, __func__);
        return(CCN_UPCALL_RESULT_OK);

    case CCN_UPCALL_INTEREST:          /**< incoming interest */
    case CCN_UPCALL_CONSUMED_INTEREST: /**< incoming interest, someone has answered */
    default:
        DEBUG_PRINT("OUT %d %s upcall other kind = %d\n", __LINE__, __func__, kind);
        return(CCN_UPCALL_RESULT_ERR);
    }



    DEBUG_PRINT("%d %s Received content object\n", __LINE__, __func__);

    if (info->content_ccnb == NULL) {
        DEBUG_PRINT("OUT %d %s in content upcall, but no content, check kind: %d\n", __LINE__, __func__, kind);
        return(CCN_UPCALL_RESULT_OK);
    }

    /*Find name in Content Object*/

    new_name = ccn_charbuf_create();
    ccn_name_init(new_name);
    ccn_name_append_components(new_name, info->content_ccnb,
                               info->content_comps->buf[0], info->content_comps->buf[info->matched_comps]);

    orig_ptr = hashtb_lookup(server->cname_to_iname, new_name->buf, new_name->length);


    if(orig_ptr == NULL) {
        /* No match for name*/
        DEBUG_PRINT("Unsolicited content object with name: ");
#ifdef PROXYDEBUG
        ccn_util_print_pc_fmt(new_name->buf, new_name->length);
        DEBUG_PRINT("\n");
#endif
        return(CCN_UPCALL_RESULT_ERR);
        //      abort();
    }

    orig_name = *orig_ptr;

    if (orig_name->buf == NULL) {
        DEBUG_PRINT("Empty charbuf?\n");
        abort();
    }

    hashtb_start(server->cname_to_iname, e);
    hashtb_seek(e, new_name->buf, new_name->length, 0);
    hashtb_delete(e);
    hashtb_end(e);

    //  ccn_name_append_components(orig_name, proxy->prefix->buf,
    //          proxy->prefix_comps->buf[0],
    //          proxy->prefix_comps->buf[proxy->prefix_ncomps]);
    //
    //  ccn_name_append_components(orig_name, info->content_ccnb,
    //          info->content_comps->buf[0],
    //          info->content_comps->buf[info->pco->name_ncomps]);

    /*Created signed info for new content object*/

    new_content = ccn_charbuf_create();

    sp.type = CCN_CONTENT_DATA;

    //TODO double check what ccn_sign_content is using the handle for
    res = ccn_sign_content(proxy->handle,
                           new_content,
                           orig_name,
                           &sp,
                           info->content_ccnb,
                           info->pco->offset[CCN_PCO_E]);


    //    if (ccn_util_validate_content_object(new_content->buf, new_content->length) != 0) {
    //       DEBUG_PRINT("ABORT %d %s Failed to validated signed content\n", __LINE__, __func__);
    //      abort();
    //    } else {
    //       DEBUG_PRINT("OK %d %s signed content is valid\n", __LINE__, __func__);
    //    }


    if (res != 0) {
        DEBUG_PRINT("ABORT %d %s Failed to encode ContentObject (res == %d)\n", __LINE__, __func__, res);
        abort();
    }

    DEBUG_PRINT("%d %s starting content write\n", __LINE__, __func__);

    res = ccn_put(proxy->handle, new_content->buf, new_content->length);

    DEBUG_PRINT("%d %s done content write line\n", __LINE__, __func__);

    if (res < 0) {
        DEBUG_PRINT("ABORT %d %s ccn_put failed (res == %d)\n", __LINE__, __func__, res);
        abort();
    }

    DEBUG_PRINT("%d %s Reply sent\n", __LINE__, __func__);

    ccn_charbuf_destroy(&new_name);
    ccn_charbuf_destroy(&orig_name);
    ccn_charbuf_destroy(&new_content);


    DEBUG_PRINT("OUT %d %s\n", __LINE__, __func__);

    return(CCN_UPCALL_RESULT_OK);
}

/**
 * Destroy/free the ccn proxy server.
 *
 * @params server to be free'd
 *
 * @returns 0 (always)
 */

int
ccn_proxy_server_destroy(struct ccn_proxy_server **server)
{
    struct ccn_proxy_server *s = *server;

    ccn_proxy_destroy(&(s->proxy));
    hashtb_destroy(&(s->cname_to_iname));

    free(s);

    return(0);
}




/**
 * Convenience function for initializing a ccn proxy client.
 * Proxy clients create new Interests with the name specified
 * by the provided prefix URI. A new name component is used to
 * carry the entire Interest message the client application sent
 * to the proxy client.
 *
 * A constructed filtering URI is currently in use for debugging
 * convenience. Ideally, ccnx:/ should be the filter.
 *
 * @param prefix_uri Namespace client should use the send Interests.
 *
 * @returns a new ccn proxy
 */

struct ccn_proxy *
ccn_proxy_client_init(const char *prefix_uri)
{
    const char filter_uri[] = "ccnx:/";
    struct ccn_proxy *client = ccn_proxy_init(filter_uri, prefix_uri);

    return(client);
}











// #include <string.h>

// // #include <openssl/rsa.h>
// // #include <openssl/evp.h>
// // #include <path.h>
// // #include <ccn/crypto/encryption.h>
// // #include <ccn/crypto/key.h>
// // #include <ccn/util/util.h>
// #include "util.h"
// #include "tgen.h"

// /**
//  * Structure used to remember the agreed upon ephemeral
//  * symmetric key for content encryption.
//  */

// struct tgen_server_pair {
//     struct ccn_pkey *symkey;
//     struct ccn_charbuf *name;
// };




// struct tgen_server {
//     // struct ccn_proxy *proxy;

//     // struct ccn_closure session_handler;

//     struct hashtb_param session_hash_params;

//     struct hashtb *cname_to_pair;
//     struct hashtb_param cname_hash_params;
// };



// /**
//  * Convenience function to create an initialize a pair structure.
//  * Used to store name mapping and ephemeral key information for
//  * content object encryption.
//  *
//  * @param original Interest name
//  * @param ephemeral symmetric key for encryption
//  *
//  * @returns new name/key pair
//  */

// static struct tgen_server_pair *
// tgen_server_pair_init(struct ccn_charbuf *name, struct ccn_pkey *symkey)
// {
//     struct tgen_server_pair *p =
//         calloc(1, sizeof(struct tgen_server_pair));

//     p->name = ccn_charbuf_create();
//     ccn_charbuf_append_charbuf(p->name, name);

//     return(p);
// }

// /**
//  * Cleanup and destroy pair structure. Called when
//  * a content object arrives (no longer need entry), interest times out,
//  * or as part of anonymous server cleanup.
//  */

// static int
// tgen_server_pair_destroy(struct tgen_server_pair **p)
// {
//     struct tgen_server_pair *ap = *p;

//     ccn_charbuf_destroy(&(ap->name));
//     free(ap);

//     return(0);
// }


// static void
// tgen_server_finalize(struct hashtb_enumerator *e)
// {
//     struct tgen_server_pair **p = e->data;
//     if (p != NULL && *p != NULL) {
//         tgen_server_pair_destroy(p);
//     }
// }


// /**
//  * Create and initialize a new anonymous server proxy.
//  * Decrypts and decapsulates incoming Interests and encrypts
//  * and encapsulates the returning content objects with an
//  * agreed upon ephemeral symmetric key (carried in the Interest).
//  *
//  * @param key_uri ccnx URI of key used for signing Content Objects
//  * @param filter_uri ccnx URI to be used for Interest filtering (i.e. select what it SHOULD process)
//  * @param prefix_uri ccnx URI of name prefix that should be removed from incoming Interests.
//  *
//  * Note that prefix_uri and filter_uri may be the same.
//  *
//  * @returns initialized anonymous server
//  */

// struct tgen_server *
// tgen_server_init(const char *filter_uri, const char *prefix_uri)
// {
//     struct tgen_server *server =
//         calloc(1, sizeof(struct tgen_server));

//     DEBUG_PRINT("%d %s tgen_server_init invoked\n", __LINE__, __func__);

//     // server->proxy = ccn_proxy_init(key_uri, filter_uri, prefix_uri);

//     struct ccn_closure *int_handler = calloc(1, sizeof(*int_handler));
//     int_handler->p = &tgen_server_decap_interest;
//     int_handler->data = server;

//     struct ccn_closure *content_handler = calloc(1, sizeof(*content_handler));
//     content_handler->p = &tgen_server_encap_content;
//     content_handler->data = server;

//     ccn_proxy_set_handlers(server->proxy, int_handler, content_handler);


//     server->ENC = server->proxy->prefix_ncomps;
//     server->SESSION_FLAG = server->proxy->prefix_ncomps;
//     server->SESSION_ENC = server->SESSION_FLAG + 1;


//     // server->privkey = ccn_crypto_privkey_load_default();
//     // server->node_key = ccn_crypto_symkey_init(128);

//     server->session_hash_params.finalize = &tgen_server_finalize;
//     // server->session_to_key = hashtb_create(sizeof(struct ccn_pkey *), &(server->session_hash_params));

//     server->cname_hash_params.finalize = &tgen_server_finalize;
//     server->cname_to_pair = hashtb_create(sizeof(struct tgen_server_pair *), &(server->cname_hash_params));

//     return(server);
// }

// void
// tgen_server_set_handlers(struct tgen_server *server,
//                            struct ccn_closure *int_handler,
//                            struct ccn_closure *content_handler)
// {
//     ccn_proxy_set_handlers(server->proxy, int_handler, content_handler);
// }



// int
// tgen_server_run(struct tgen_server *server)
// {
//     return ccn_proxy_run(server->proxy);
// }

// /**
//  * Initialize interest/content handlers and connect to underlying
//  * ccnd instance.
//  *
//  * @param anonymous server to configure
//  * @returns result of setting interest filter
//  */

// int
// tgen_server_connect(struct tgen_server *server)
// {
//     int res;
//     res = ccn_proxy_connect(server->proxy);

//     if (res != 0) {
//         return(res);
//     }

//     struct ccn_charbuf *session_namespace = ccn_charbuf_create();
//     ccn_charbuf_append_charbuf(session_namespace, server->proxy->filter);
//     ccn_name_append_str(session_namespace, "CREATESESSION");

//     server->session_handler.p = &tgen_server_session_listener;
//     server->session_handler.data = server;

//     res = ccn_set_interest_filter(server->proxy->handle,
//                                   session_namespace,
//                                   &(server->session_handler));

//     ccn_charbuf_destroy(&session_namespace);

//     return(res);
// }

// /**
//  * Listener to handle requests to set up new
//  * sessions (symmetric encryption only).
//  */

// enum ccn_upcall_res
// tgen_server_session_listener(
//     struct ccn_closure *selfp,
//     enum ccn_upcall_kind kind,
//     struct ccn_upcall_info *info)
// {
//     int res;
//     struct tgen_server *server = selfp->data;

//     const unsigned char * const_encrypted = NULL;
//     unsigned char *encrypted = NULL;
//     size_t enc_size;

//     /*
//      * Extract the client's randomness (aka the symmetric key it sent us.
//      * Should be the last component of the incoming Interest.
//      */

//     struct ccn_charbuf *request_name = NULL;
//     struct ccn_indexbuf *request_comps = NULL;


//     DEBUG_PRINT("IN %d %s\n", __LINE__, __func__);

// //     switch (kind) {
// //     case CCN_UPCALL_INTEREST:
// //         DEBUG_PRINT("%d %s received session request\n", __LINE__, __func__);
// //         break;
// //     case CCN_UPCALL_INTEREST_TIMED_OUT:
// //         DEBUG_PRINT("%d %s received session request time out\n", __LINE__, __func__);
// //         /* Fall through */
// //     default:
// //         DEBUG_PRINT("OUT %d %s\n", __LINE__, __func__);
// //         return(CCN_UPCALL_RESULT_OK);
// //     }

// //     printf("here now mk?\n");

// //     res = ccn_util_extract_name(info->interest_ccnb, info->interest_comps, &request_name, &request_comps);

// //     if (res < 0) {
// //         DEBUG_PRINT("%d %s Failed to extract session request name\n", __LINE__, __func__);
// //         ccn_charbuf_destroy(&request_name);
// //         ccn_indexbuf_destroy(&request_comps);
// //         return(CCN_UPCALL_RESULT_ERR);
// //     }

// //     printf("passed util extract name\n");

// //     res = ccn_name_comp_get(request_name->buf,
// //                             request_comps,
// //                             (unsigned int)request_comps->n - 2,
// //                             &const_encrypted,
// //                             &enc_size);

// //     if (res < 0) {
// //         DEBUG_PRINT("%d %s Failed to extract session creation data\n", __LINE__, __func__);
// //         ccn_charbuf_destroy(&request_name);
// //         ccn_indexbuf_destroy(&request_comps);
// //         return(CCN_UPCALL_RESULT_ERR);
// //     }


// //     encrypted = calloc(enc_size, sizeof(unsigned char));

// //     printf("encryption size = %d\n", enc_size);
// //     if (encrypted == NULL) printf("invalid pointer return from calloc\n");

// //     memcpy(encrypted, const_encrypted, enc_size);

// //     struct ccn_pkey *symkey = NULL;
// //     struct ccn_charbuf *decrypted = NULL;
// //     struct ccn_indexbuf *decrypted_comps = ccn_indexbuf_create();

// //     printf("trying asymmetric decryption\n");

// //     ccn_crypto_name_asym_decrypt(server->privkey, encrypted, &symkey, &decrypted, &decrypted_comps);
// //     // ccn_crypto_name_sym_decrypt(server->node_key, encrypted, encrypted_size, &decrypted, &decrypted_comps);

// //     /*
// // cn_crypto_name_sym_decrypt(server->node_key,
// //                                     encrypted,
// //                                     encrypted_size,
// //                                     &symkey,
// //                                     &decrypted,
// //                                     &decrypted_comps);
// //     */

// //     printf("good - now creating a session\n");


// //     unsigned char *session_id = NULL;
// //     unsigned char *session_key = NULL;
// //     unsigned char *server_rand = NULL;

// //     /*
// //      * Create a new session id and session key using the client's randomness.
// //      * The server is also responsible for contributing randomness of its own for security.
// //      */

// //     createSession(&session_id,
// //                   &session_key,
// //                   &server_rand,
// //                   ccn_crypto_symkey_key(symkey),
// //                   (unsigned int)ccn_crypto_symkey_bytes(symkey),
// //                   ccn_crypto_symkey_key(server->node_key));

// //     printf("Session made!\n");

//     /* Construct the response message using a ccn name (for convenience). */

//     struct ccn_charbuf *resp = ccn_charbuf_create();
//     ccn_name_init(session_info);

//     unsigned char* random = (unsigned char*)malloc(1024 * sizeof(unsigned char));
//     for (int i = 0; i < 1024; i++)
//     {
//         random[i] = 0xFF;
//     }
//     ccn_name_append(resp, random, 1024);

//     // ccn_name_append(session_info, session_id, SESSIONID_LENGTH);
//     // ccn_name_append(session_info, session_key, SESSION_KEYLEN);
//     // ccn_name_append(session_info, server_rand, SESSIONRAND_LENGTH);


//     res = ccn_put(server->proxy->handle, resp, 1024); // is this correct?

//     // /**
//     //  * Encrypt the response message using the symmetric key
//     //  * provided by the client and send it out.
//     //  */

//     // unsigned char *enc_info = NULL;
//     // ccn_crypto_content_encrypt(symkey, session_info->buf, session_info->length, &enc_info, &enc_size);

//     // struct ccn_charbuf *signed_enc_info = ccn_charbuf_create();
//     // struct ccn_signing_params sp = CCN_SIGNING_PARAMS_INIT;
//     // sp.type = CCN_CONTENT_DATA;


//     // res = ccn_sign_content(server->proxy->handle,
//     //                        signed_enc_info,
//     //                        request_name,
//     //                        &sp,
//     //                        enc_info,
//     //                        enc_size);

    



//     // ccn_charbuf_destroy(&decrypted);
//     // ccn_indexbuf_destroy(&decrypted_comps);
//     // ccn_crypto_symkey_destroy(&symkey);
//     // free(session_id);
//     // free(session_key);
//     // free(server_rand);
//     // free(enc_info);
//     // ccn_charbuf_destroy(&signed_enc_info);

//     // if (res < 0) {
//     //     DEBUG_PRINT("%d %s Error writing session creation response\n", __LINE__, __func__);
//     //     return(CCN_UPCALL_RESULT_ERR);
//     // }

//     // DEBUG_PRINT("OUT %d %s Created new session. Response sent\n", __LINE__, __func__);

//     return(CCN_UPCALL_RESULT_INTEREST_CONSUMED);
// }

// /**
//  * Clean up and destroy anonymous server object. Expect
//  * to be called once at program close.
//  *
//  * @param pointer to anonymous server to be destroyed
//  * @returns 0 (always)
//  */

// int
// tgen_server_destroy(struct tgen_server **server)
// {
//     struct tgen_server *s = *server;

//     free(s->proxy->int_handler);
//     free(s->proxy->content_handler);
//     ccn_proxy_destroy(&(s->proxy));
//     ccn_crypto_pubkey_destroy(&(s->privkey));
//     hashtb_destroy(&(s->cname_to_pair));
//     free(s);

//     return(0);
// }
