#ifndef ANON_SERVER_PROXY_H_
#define ANON_SERVER_PROXY_H_

#include "Config.h"
#include "Crypto.h"
#include "CryptoWrapper.h"
#include "Proxy.h"
#include "ProxyState.h"

#include <ccn/charbuf.h>
#include <ccn/ccn.h>
#include <ccn/uri.h>

typedef struct
{
    ProxySessionTable* sessionTable;
    ProxyStateTable* stateTable;
    UpstreamProxyStateTable* upstreamStateTable;
    Config* config;
    Proxy* baseProxy;
    struct ccn_closure session_handler;
} DownstreamProxy;

/**
 * TODO
 */
DownstreamProxy* ProxySessionInit(Config* config, struct ccn_charbuf *uri, struct ccn_pkey *pubkey, struct ccn_charbuf *interest_template, int is_exit);

/**
 * TODO
 */
DownstreamProxy* DownstreamProxyInit(const char *key_uri, const char *filter_uri, const char *prefix_uri);

/** 
 * Set the interest and content handlers.
 *
 * @param server - the producer server to configure.
 * @param int_handler - pointer to the interest handler.
 * @param content_handler - pointer to the content handler.
 */
void DownstreamProxySetHandlers(DownstreamProxy* server, struct ccn_closure *int_handler, struct ccn_closure *content_handler);

/**
 * Initialize interest/content handlers and connect to underlying
 * ccnd instance.
 *
 * @param anonymous server to configure.
 * @returns result of setting interest filter
 */
int DownstreamConnect(DownstreamProxy* server);

/** 
 * Run the producer server proxy.
 *
 * @param server - the producer server to run.
 */
int DownstreamRun(DownstreamProxy* server);

/**
 * TODO
 */
enum ccn_upcall_res DownstreamSessionListener(struct ccn_closure *selfp, enum ccn_upcall_kind kind, struct ccn_upcall_info *info);

/**
 * TODO
 */
enum ccn_upcall_res UnwrapInterest(struct ccn_closure *selfp, enum ccn_upcall_kind kind, struct ccn_upcall_info *info);

/**
 * TODO
 */
enum ccn_upcall_res WrapContent(struct ccn_closure *selfp, enum ccn_upcall_kind kind, struct ccn_upcall_info *info);

/**
 * Clean up and destroy anonymous server object.
 *
 * @param pointer to anonymous server to be destroyed
 * @returns 0 (always)
 */
int AnonServerDestroy(DownstreamProxy** server);

#endif /* ANON_SERVER_PROXY_H_ */

