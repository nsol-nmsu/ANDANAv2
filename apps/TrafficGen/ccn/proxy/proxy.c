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

#include <ccn/proxy/proxy.h>

#include <ccn/util/util.h>



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
                            struct ccn_closure *int_callback)
{
    ccn_proxy_set_interest_handler(proxy, int_callback);
    // ccn_proxy_set_content_handler(proxy, content_callback);
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

enum ccn_upcall_res
ccn_proxy_server_decap_interest(
    struct ccn_closure *selfp,
    enum ccn_upcall_kind kind,
    struct ccn_upcall_info *info)
{

    // TODO: need to fill up random buffer and then inject it using ccn_put

    return(CCN_UPCALL_RESULT_OK);
}


