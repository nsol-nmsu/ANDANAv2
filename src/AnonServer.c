/**
 * File: AnonConsumer.c
 * Description: Entry point for an anonymous server proxy.
 * Author: Christopher A. Wood, woodc1@uci.edu
 */

#include <stdio.h>

#include "Config.h"
#include "CryptoWrapper.h"
#include "Proxy.h"
#include "DownstreamProxy.h"
#include "Util.h"

/**
 * Entry point.
 */
int main(int argc, char** argv)
{
	if (argc != 2)
	{
		DEBUG_PRINT("usage: producer uri\n");
		return -1;
	}

    DEBUG_PRINT("Starting server on URI: %s\n", argv[1]);

    // Initialize the server handler
    struct ccn_pkey *pubkey = ccn_crypto_pubkey_load_default();
    struct ccn_charbuf *anon_uri = ccn_charbuf_create();
    DownstreamProxy* server = DownstreamProxyInit(anon_uri, argv[1], argv[1]);

    // Connect to the ccnd instance and then run
    DownstreamConnect(server);
    DownstreamRun(server);

    // Success...
	return 0;
}
