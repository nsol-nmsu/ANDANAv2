/*
 * proxy.h
 *
 *  Created on: Jun 13, 2011
 *      Author: sdibened
 */

#ifndef PROXY_H_
#define PROXY_H_

#include <ccn/ccn.h>
#include <ccn/charbuf.h>
#include <ccn/uri.h>
#include <ccn/keystore.h>
#include <ccn/signing.h>
#include <ccn/hashtb.h>

#include <sys/time.h>

struct ccn_proxy {

    struct ccn *handle;
    struct ccn_charbuf *handle_name;
    size_t nhandles;

    struct ccn_charbuf *filter; /* Name used for filtering Interests */
//	struct ccn_indexbuf *filter_comps;
//	size_t filter_ncomps;

    struct ccn_charbuf *prefix; /* Name used for processing Interests */
    struct ccn_indexbuf *prefix_comps;
    size_t prefix_ncomps;

    struct ccn_closure *int_handler;
    struct ccn_closure *content_handler;
};





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
ccn_proxy_init(const char *filter_uri, const char *prefix_uri);


/**
 * Change the ccn_closure called when an Interest arrives (inbound face only)
 *
 * @param proxy to have its Interest handler changed
 * @param callback to be used on receipt of Interest
 */

void
ccn_proxy_set_interest_handler(struct ccn_proxy *proxy,
                               struct ccn_closure *callback);

/**
 * Change the ccn_closure called when a Content Object arrives (outbound face only)
 *
 * @param proxy to have its Content Object handler changed
 * @param callback to be used on receipt of Content Object
 */

void
ccn_proxy_set_content_handler(struct ccn_proxy *proxy,
                              struct ccn_closure *callback);

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
                            struct ccn_closure *content_callback);


/**
 * Connect proxy to ccnd and announce namespace
 * @param proxy initialized ccn proxy
 * @returns 0 on success, -1 if fails to connect to ccnd
 */

int ccn_proxy_connect(struct ccn_proxy *proxy);


/**
 * Run the proxy. Polls inbound and outbound faces for new Interests and
 * Content Objects, respectively. Terms "inbound" and "outbound" are relative
 * to the direction Interests travel. Interests arrive on inbound face, a
 * user specified operation is performed, and a (potentially/usually) new Interest
 * is sent through the outbound face.
 *
 * Currently has return value (always 0), but implemented with forever loop.
 * This may change in the future to make ccn_proxy_run behave more like ccn_run.
 *
 * @param proxy to run (start proxy-ing traffic)
 * @returns 0 (always, expect negative value in future to indicate error)
 */

int ccn_proxy_run(struct ccn_proxy *proxy);

/**
 * Destroy/free a ccn proxy.
 *
 * @param pointer to the proxy to be destroyed
 *
 * @returns 0 (always)
 */

int ccn_proxy_destroy(struct ccn_proxy **proxy);







struct ccn_proxy_server {
    struct ccn_proxy *proxy;

    struct hashtb *cname_to_iname;
    struct hashtb_param hash_param;
};



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
ccn_proxy_server_init(const char *filter_uri, const char *prefix_uri);

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
ccn_proxy_server_decap_interest(struct ccn_closure *selfp,
                                enum ccn_upcall_kind kind,
                                struct ccn_upcall_info *info);

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
ccn_proxy_server_encap_content(struct ccn_closure *selfp,
                               enum ccn_upcall_kind kind,
                               struct ccn_upcall_info *info);


/**
 * Destroy/free the ccn proxy server.
 *
 * @params server to be free'd
 *
 * @returns 0 (always)
 */

int ccn_proxy_server_destroy(struct ccn_proxy_server **server);








struct ccn_proxy_client {
    struct ccn_proxy *proxy;
};

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
ccn_proxy_client_init(const char *prefix_uri);


#endif /* PROXY_H_ */


// #ifndef TGEN_H_
// #define TGEN_H_

// struct tgen_server;


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
// tgen_server_init(const char *filter_uri, const char *prefix_uri);


// void
// tgen_server_set_handlers(struct tgen_server *server, struct ccn_closure *int_handler, struct ccn_closure *content_handler);

// /**
//  * Initialize interest/content handlers and connect to underlying
//  * ccnd instance.
//  *
//  * @param anonymous server to configure
//  * @returns result of setting interest filter
//  */

// int
// tgen_server_connect(struct tgen_server *server);



// int
// tgen_server_run(struct tgen_server *server);


// /**
//  * Listener to handle requests to set up new
//  * sessions (symmetric encryption only).
//  */
// enum ccn_upcall_res
// tgen_server_session_listener(struct ccn_closure *selfp, enum ccn_upcall_kind kind, struct ccn_upcall_info *info);
// /**
//  * Clean up and destroy anonymous server object. Expect
//  * to be called once at program close.
//  *
//  * @param pointer to anonymous server to be destroyed
//  * @returns 0 (always)
//  */

// int
// tgen_server_destroy(struct tgen_server **server);


// #endif /* TGEN_H_ */
