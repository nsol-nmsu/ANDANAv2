/**
 * File: Proxy.cpp
 * Description: Proxy class implementation.
 * Author: Christopher A. Wood, woodc1@uci.edu
 */

#include "Proxy.h"
#include "Util.h"

/**
 * Initialize a new CCN proxy with specified namespaces.
 *
 * @param Interest filter URI (specifies Interests that should be accepted)
 * @param Namespace this proxy is responsible for
 * (outbound Interest name on client-side, input Interest name on server-side)
 *
 * @returns Initialized ccn proxy
 */
Proxy* InitProxy(const char *key_uri, const char *filter_uri, const char *prefix_uri)
{
    struct ccn_buf_decoder decoder;
    struct ccn_buf_decoder *d = &decoder;
    int res;
    Proxy* proxy = (Proxy*)malloc(sizeof(Proxy));

    DEBUG_PRINT("IN %d %s\n", __LINE__, __func__);

    // Convert URI to name this proxy is responsible for
    DEBUG_PRINT("Creating prefix URI\n");
    proxy->prefix = ccn_charbuf_create();
    res = ccn_name_from_uri(proxy->prefix, prefix_uri);
    if (res < 0) 
    {
        DEBUG_PRINT("ABORT %d %s bad ccn URI: %s\n", __LINE__, __func__, prefix_uri);
        return NULL;
    }

    // Initialize the prefix decoder
    DEBUG_PRINT("Initializing prefix decoder\n");
    d = ccn_buf_decoder_start(d, proxy->prefix->buf, proxy->prefix->length);
    proxy->prefix_comps = ccn_indexbuf_create();
    proxy->prefix_ncomps = ccn_parse_Name(d, proxy->prefix_comps);

    // Set the filter
    if (filter_uri != NULL)
    {
        DEBUG_PRINT("Setting the filter: %s\n", filter_uri);
        proxy->filter = ccn_charbuf_create();
        res = ccn_name_from_uri(proxy->filter, filter_uri);
        if (res < 0) 
        {
            DEBUG_PRINT("ABORT %d %s bad ccn URI: %s\n", __LINE__, __func__, filter_uri);
            return NULL;
        }
    }

    // Initialization should be done by ccn_proxy_connect() 
    proxy->handle_name = ccn_charbuf_create();
    ccn_charbuf_append_string(proxy->handle_name, "in/outb");

    DEBUG_PRINT("OUT %d %s\n", __LINE__, __func__);

    return proxy;
}

Proxy* InitProxyBase(struct ccn_charbuf *uri, struct ccn_pkey *pubkey, struct ccn_charbuf *interest_template, int is_exit)
{
    Proxy *node = NULL;

    if (uri == NULL)
    {
        DEBUG_PRINT("url null\n");
        return NULL;
    }
    if (pubkey == NULL)
    {
        DEBUG_PRINT("pubkey null\n");
        return NULL;
    }

    // Allocate space for the node
    node = malloc(sizeof(Proxy));

    // Parse the URI namespace for the node
    node->uri = ccn_charbuf_create();
    ccn_charbuf_append_charbuf(node->uri, uri);

    // Create a decoder for interests corresponding to this namespace
    node->uri_comps = ccn_indexbuf_create();
    struct ccn_buf_decoder decoder;
    ccn_buf_decoder_start(&decoder, uri->buf, uri->length);
    if (ccn_parse_Name(&decoder, node->uri_comps) < 0 ) 
    {
        DEBUG_PRINT("ABORT %d %s cannot create node with invalid name\n", __LINE__, __func__);
        goto Bail;
    }

    // if (interest_template == NULL) 
    // {
    //     node->interest_template = NULL;
    // } 
    // else 
    // {
    //     node->interest_template = ccn_charbuf_create();
    //     ccn_charbuf_append_charbuf(node->interest_template, interest_template);
    // }

    DEBUG_PRINT("Populating the public key and initializing a random symmetric key\n");
    //  node->usec_offset = .5 * 1000000; /*Half of a second */
    node->usec_offset = 0;
    node->pubkey = CopyPublicKey(pubkey);
    // node->symkey = (struct ccn_pkey*)InitSymmetricKey(128);
    node->is_exit = is_exit;

    return(node);

Bail:
    DEBUG_PRINT("bailing out\n");
    // andana_path_node_destroy(&node);

    return(NULL);
}

/**
 * Destroy/free a ccn proxy.
 *
 * @returns 0 (always)
 */
int DestroyProxy(Proxy* proxy)
{
    DEBUG_PRINT("IN %d %s\n", __LINE__, __func__);

    // // Free up CCNx resources
    // ccn_destroy(&handle);
    // ccn_charbuf_destroy(&handle_name);
    // ccn_indexbuf_destroy(&prefix_comps);
    // ccn_charbuf_destroy(&prefix);
    // ccn_charbuf_destroy(&filter);

    DEBUG_PRINT("OUT %d %s\n", __LINE__, __func__);

    return 0; // success
}

/**
 * Change the ccn_closure called when an Interest arrives (inbound face only)
 *
 * @param proxy to have its Interest handler changed
 * @param callback to be used on receipt of Interest
 */
void ccn_proxy_set_interest_handler(Proxy* proxy, struct ccn_closure *callback)
{
    proxy->int_handler = callback;
}

/**
 * Change the ccn_closure called when a Content Object arrives (outbound face only)
 *
 * @param proxy to have its Content Object handler changed
 * @param callback to be used on receipt of Content Object
 */
void ccn_proxy_set_content_handler(Proxy* proxy, struct ccn_closure *callback)
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
 * @param int_callback to be used on receipt of Interest
 * @param content_callback to be used on receipt of Content Object
 */
void ccn_proxy_set_handlers(Proxy* proxy, struct ccn_closure *int_callback,  struct ccn_closure *content_callback)
{
    ccn_proxy_set_interest_handler(proxy, int_callback);
    ccn_proxy_set_content_handler(proxy, content_callback);
}

/**
 * Connect proxy to ccnd and announce namespace
 *
 * @returns 0 on success, -1 if fails to connect to ccnd
 */
int ProxyConnect(Proxy* proxy)
{
    DEBUG_PRINT("IN %d %s\n", __LINE__, __func__);

    if ((proxy->handle = ccn_create()) == NULL) 
    {
        DEBUG_PRINT("OUT %d %s failed to create %s ccn handle\n", __LINE__, __func__, proxy->handle_name->buf);
        return -1;
    }

    if (ccn_connect(proxy->handle, NULL) == -1) 
    {
        DEBUG_PRINT("OUT %d %s failed to connect %s ccn handle\n", __LINE__, __func__, proxy->handle_name->buf);
        return -2;
    }

    DEBUG_PRINT("%d %s setting up interest handler \n", __LINE__, __func__);
    ccn_set_interest_filter(proxy->handle, proxy->filter, proxy->int_handler);

    DEBUG_PRINT("%d %s interest printer setup\n", __LINE__, __func__);
    DEBUG_PRINT("OUT %d %s\n", __LINE__, __func__);
    
    return 0;
}

/**
 * Run the proxy.
 *
 * Currently has return value (always 0), but implemented with forever loop.
 * This may change in the future to make ccn_proxy_run behave more like ccn_run.
 *
 * @returns 0 (always, expect negative value in future to indicate error)
 */
int ProxyRun(Proxy* proxy)
{
    DEBUG_PRINT("IN %d %s\n", __LINE__, __func__);

    if (ccn_run(proxy->handle, -1) < 0) 
    {
        DEBUG_PRINT("ccn_run error: %d\n", ccn_geterror(proxy->handle));
        DEBUG_PRINT("%d %s error running %s handle\n", __LINE__, __func__, proxy->handle_name->buf);
        return -1;
    }

    DEBUG_PRINT("OUT %d %s\n", __LINE__, __func__);
    return 0;
}
