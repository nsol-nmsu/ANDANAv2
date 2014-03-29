/*
 * anonymous_client.c
 *
 *  Created on: Jul 8, 2011
 *      Author: sdibened
 *
 *  Configures and runs a client-side anonymizer. All users
 *  on the same node will use the same client-side anonymizer.
 *
 *  Main contains example of how to specify a path (used for encryption/encapsulation).
 *
 *  Arguments: ccnx uris of the anonymizing servers to use. URIs must begin with ccnx:/
 */

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

#include <andana.h>

#include <path.h>
#include <ccn/crypto/key.h>


int main(int argc, char **argv)
{
    int res;
    struct ccn_closure int_handler;
    struct ccn_closure content_handler;

    struct andana_path *path = andana_path_init(argc-1);
    fprintf(stderr, "Constructing path of length: %d\n", argc-1);

    /* FIXME Cheating on getting a pubkey */
    struct ccn_pkey *pubkey = ccn_crypto_pubkey_load_default();

    int i;
    for (i = 1; i < argc; i++) {
        struct ccn_charbuf *anon_uri = ccn_charbuf_create();
        ccn_name_from_uri(anon_uri, argv[i]);

        res = andana_path_set_node_session(path,
                                        i-1,
                                        anon_uri,
                                        pubkey,
                                        NULL);

        if (res < 0) {
            fprintf(stderr, "Unable add node to path\n");
            return(1);
        }
        ccn_charbuf_destroy(&anon_uri);
    }


    struct andana_client *client =
        andana_client_init(argv[1], path);

    int_handler.p = &andana_client_encap_interest;
    int_handler.data = client;

    content_handler.p = &andana_client_decap_content;
    content_handler.data = client;

    andana_client_set_handlers(client, &int_handler, &content_handler);

    if (andana_client_connect(client) < 0) {
    	fprintf(stderr, "Error: Failed to connect to ccnd\n");
    	exit(1);
    } else {
    	andana_client_run(client);
    }

    fprintf(stderr, "Done running proxy\n");


    andana_client_destroy(&client);
    andana_path_destroy(&path);
    ccn_crypto_pubkey_destroy(&pubkey);
    return(0);
}
