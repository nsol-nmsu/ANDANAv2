/*
 * client.c
 *
 *  Created on: Jun 27, 2011
 *      Author: sdibened
 */

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

#include <ccn/proxy/proxy.h>


int main(int argc, char **argv)
{
    struct ccn_closure int_handler;
    struct ccn_closure content_handler;

    fprintf(stderr, "Running with namespace %s\n", argv[1]);
    struct ccn_proxy *client = ccn_proxy_client_init(argv[1]);

    int_handler.p = &ccn_proxy_client_encap_interest;
    int_handler.data = client;

    content_handler.p = &ccn_proxy_client_decap_content;
    content_handler.data = client;

    ccn_proxy_set_handlers(client, &int_handler, &content_handler);

    if (ccn_proxy_connect(client) < 0) {
    	fprintf(stderr, "Error: Failed to connect to ccnd\n");
    	exit(1);
    }

    ccn_proxy_run(client);

    fprintf(stderr, "Done running proxy\n");

    ccn_proxy_destroy(&client);

    return(0);
}

