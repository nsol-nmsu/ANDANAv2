/**
 * File: Proxy.h
 * Description: Definitions for generic application-layer proxy over NDN.
 * Author: Christopher A. Wood, woodc1@uci.edu
 */

#ifndef PROXY_H_
#define PROXY_H_

#include "Util.h"
#include "CryptoWrapper.h"
#include "Crypto.h"
#include "ProxyState.h"
#include "Config.h"
 
#include <ccn/ccn.h>
#include <ccn/charbuf.h>
#include <ccn/uri.h>
#include <ccn/keystore.h>
#include <ccn/signing.h>
#include <ccn/hashtb.h>
#include <sys/time.h>

typedef struct
{
    struct ccn_pkey *privkey;

    struct ccn *handle; /* Handle to the underlying ccnd */
    struct ccn_charbuf* handle_name; /* Name of the handle */
    size_t nhandles;
    const char* key_uri; /* Location of the proxy's keystore */
    struct ccn_charbuf* filter; /* Name used for filtering Interests */

    // Name used for processing Interests
    struct ccn_charbuf* prefix;
    struct ccn_indexbuf* prefix_comps;
    size_t prefix_ncomps;

    // Callback functions for handling upstream interests and downstream content
    struct ccn_closure* int_handler;
    struct ccn_closure* content_handler;

    struct ccn_charbuf* uri;               /* ccnx uri for this proxy */
    struct ccn_indexbuf* uri_comps;
    // struct ccn_charbuf* interest_template; /* Template to use for this proxy */
    struct ccn_pkey* pubkey;               /* Public key identifying this proxy. */
    // struct ccn_pkey* symkey;

    // Timeliness
    suseconds_t usec_offset;

    // Circuit details
    int is_exit;
} Proxy;

/**
 * Initialize a new CCN proxy with specified namespaces.
 *
 * @param Interest filter URI (specifies Interests that should be accepted)
 * @param Namespace this proxy is responsible for
 * (outbound Interest name on client-side, input Interest name on server-side)
 *
 * @returns Initialized ccn proxy
 */
Proxy* InitProxy(const char *key_uri, const char *filter_uri, const char *prefix_uri);

// TODO
int DestroyProxy(Proxy* proxy);

/**
 * Change the ccn_closure called when an Interest arrives (inbound face only)
 *
 * @param callback to be used on receipt of Interest
 */
void ccn_proxy_set_interest_handler(Proxy* proxy, struct ccn_closure *callback);

/**
 * Change the ccn_closure called when a Content Object arrives (outbound face only)
 *
 * @param callback to be used on receipt of Content Object
 */
void ccn_proxy_set_content_handler(Proxy* proxy, struct ccn_closure *callback);
/**
 * Convenience function to simultaneously update Interest and Content Object
 * handlers.
 *
 * @see ccn_proxy_set_interest_handler
 * @see ccn_proxy_set_content_handler
 *
 * @param int_callback to be used on receipt of Interest
 * @param content_callback to be used on receipt of Content Object
 */
void ccn_proxy_set_handlers(Proxy* proxy, struct ccn_closure *int_callback, struct ccn_closure *content_callback);

/**
 * Connect proxy to ccnd and announce namespace
 *
 * @returns 0 on success, -1 if fails to connect to ccnd
 */
int ProxyConnect(Proxy* proxy);

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
 * @returns 0 (always, expect negative value in future to indicate error)
 */
int ProxyRun(Proxy* proxy);

#endif /* PROXY_H_ */
