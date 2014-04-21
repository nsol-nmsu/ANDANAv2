/**
 * File: AnonConsumer.c
 * Description: Entry point for an anonymous consumer proxy.
 * Author: Christopher A. Wood, woodc1@uci.edu
 */

#include <stdio.h>

#include "Config.h"
#include "CryptoWrapper.h"
#include "Proxy.h"
#include "UpstreamProxy.h"
#include "Util.h"
#include "ini.h"

static int ConfigParseHandler(void* user, const char* section, const char* name, const char* value)
{
    Config* pconfig = (Config*)user;

    #define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0
    if (MATCH("global", "circuit_creation")) 
    {
        pconfig->circuit_creation = atoi(value);
    } 
    else if (MATCH("global", "circuit_independent")) 
    {
        pconfig->circuit_independent = atoi(value);
    } 
    else if (MATCH("global", "circuit_signature_scheme")) 
    {
        pconfig->circuit_signature_scheme = atoi(value);
    } 
    else 
    {
        return 0;  /* unknown section/name, error */
    }

    return 1;
}

/**
 * Entry point.
 */
int main(int argc, char** argv)
{
    int i;

	if (argc < 3)
	{
		DEBUG_PRINT("usage: consumer config->ini hop1 {hops}\n");
		return -1;
	}

	// Parse the configuration file
	DEBUG_PRINT("[L%d - %s] Parsing: %s...\n", __LINE__, __func__, argv[1]);

    // Populate the config struct from the ini file.
	Config* config = (Config*)malloc(sizeof(Config));
	if (ini_parse(argv[1], ConfigParseHandler, config) < 0) 
	{
        printf("Can't load 'test.ini'\n");
        return 1;
    }
    DEBUG_PRINT("[L%d - %s] Config loaded from 'test.ini': circuit_creation=%d, circuit_independent=%d, circuit_signature_scheme=%d\n",
        __LINE__, __func__, config->circuit_creation, config->circuit_independent, config->circuit_signature_scheme);

    // Perform preliminary verification of configuration data
    switch (config->circuit_creation)
    {
        case CIRCUIT_CREATION_HANDSHAKE:
            DEBUG_PRINT(">> Handshake-based circuit formation.\n");
            break;
        case CIRCUIT_CREATION_PIGGYBACK:
            DEBUG_PRINT(">> Content piggyback circuit formation.\n");
            break;
        default:
            DEBUG_PRINT(">> Error: invalid circuit creation flag: %d\n", config->circuit_creation);
            return -1;
    }
    switch (config->circuit_independent)
    {
        case 0:
            DEBUG_PRINT(">> Dependent circuit creation.\n");
            break;
        case 1:
            DEBUG_PRINT(">> Independent circuit creation.\n");
            break;
        default:
            DEBUG_PRINT(">> Error: invalid flag for Independent circuit creation: %d\n", config->circuit_independent);
            return -1;
    }
    switch (config->circuit_signature_scheme)
    {
        case CIRCUIT_SIG_SCHEME_ALL_DIGITAL_SIGS:
            DEBUG_PRINT(">> CIRCUIT_SIG_SCHEME_ALL_DIGITAL_SIGS not implemented.\n");
            return -1;
        case CIRCUIT_SIG_SCHEME_MIXED:
            DEBUG_PRINT(">> Mixed MAC and digital signature scheme.\n");
            break;
        case CIRCUIT_SIG_SCHEME_ALL_MACS:
            DEBUG_PRINT(">> CIRCUIT_SIG_SCHEME_ALL_MACS not implemented.\n");
            return -1;
        default: 
            DEBUG_PRINT(">> Error: invalid signature scheme specification: %d\n", config->circuit_signature_scheme);
            return -1;
    }

    // Load our default public key
    struct ccn_pkey *pubkey = ccn_crypto_pubkey_load_default();

    DEBUG_PRINT("Starting path creation\n");

    // Initialize each proxy hop specified by the user
    int numProxies = argc - 2;
    int pIndex = 0;
    UpstreamProxy** proxies = (UpstreamProxy**)malloc(numProxies * sizeof(UpstreamProxy*));
    DEBUG_PRINT("Creating %d proxies\n", numProxies);
	for (pIndex = 0, i = 2; pIndex < numProxies; pIndex++, i++) 
	{
        DEBUG_PRINT("Initializing session state for node %s\n", argv[i]);
		struct ccn_charbuf *uri = ccn_charbuf_create();
		ccn_name_from_uri(uri, argv[i]);
		proxies[pIndex] = UpstreamProxySessionInit(config, uri, pubkey, NULL, pIndex == numProxies - 1);
	}

    DEBUG_PRINT("Sessions established - setting up the interest/content handlers now\n");

    // Hookup the wrapping/unwrapping handlers and then start the client
    UpstreamProxy* client = proxies[0];
    struct ccn_closure int_handler;
    struct ccn_closure content_handler;
    int_handler.p = &WrapInterest;
    int_handler.data = client;
    content_handler.p = &UnwrapContent;
    content_handler.data = client;
    ccn_proxy_set_handlers(client->baseProxy, &int_handler, &content_handler);

    // Store the path for recovery later in the upstream handler
    client->pathProxies = (UpstreamProxy**)malloc(numProxies * sizeof(UpstreamProxy*));
    client->numProxies = numProxies;
    memcpy(client->pathProxies, proxies, numProxies * sizeof(UpstreamProxy*));

    // Connect and run
    if (ProxyConnect(client->baseProxy) < 0) 
    {
        fprintf(stderr, "Error: Failed to connect to ccnd\n");
        return -1;
    } 
    else 
    {
        // Kick it...
        ProxyRun(client->baseProxy);
    }

	return 0;
}
