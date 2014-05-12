#ifndef ANON_CONSUMER_PROXY_H_
#define ANON_CONSUMER_PROXY_H_

#include "Util.h"
#include "Config.h"
#include "Crypto.h"
#include "CryptoWrapper.h"
#include "Proxy.h"
#include "ProxyState.h"

#include <ccn/charbuf.h>
#include <ccn/ccn.h>
#include <ccn/uri.h>

// Toggle for useful printouts
#define UPSTREAM_PROXY_DEBUG 1

typedef struct UpstreamProxy UpstreamProxy;

struct UpstreamProxy
{
    ProxySessionTable* sessionTable;
    ProxyStateTable* stateTable;
    UpstreamProxyStateTable* upstreamStateTable;
    Config* config;
    Proxy* baseProxy;

    // Only used by the start of the chain for encapsulating interests
    UpstreamProxy** pathProxies;
    int numProxies;

    // Flag to determine if a session has been established or not
    // (for piggybacking creation only)
    char sessionEstablished;
};

/**
 * TODO
 */
enum ccn_upcall_res WrapInterest(struct ccn_closure *selfp, enum ccn_upcall_kind kind, struct ccn_upcall_info *info);

/**
 * TODO
 */
struct ccn_charbuf* EncryptInterest(UpstreamProxy* client, UpstreamProxyStateTableEntry* newStateEntry, struct ccn_charbuf* origInterest, struct ccn_indexbuf *origComponents);

/**
 * TODO
 */
enum ccn_upcall_res UnwrapContent(struct ccn_closure *selfp, enum ccn_upcall_kind kind, struct ccn_upcall_info *info);

#endif /* ANON_CONSUMER_PROXY_H_ */
