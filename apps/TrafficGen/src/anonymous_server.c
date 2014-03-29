/*
 * anonymous_server.c
 *
 *  Created on: Jul 8, 2011
 *      Author: sdibened
 *
 *  Runs a anonymizing proxy server.
 */



#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <andana.h>

static void
usage(const char* progname)
{
	fprintf(stderr, "usage: %s [-h] PREFIX ...\n", progname);
	exit(1);
}

int
main(int argc, char **argv)
{
	const char *progname = argv[0];
	int res;

    struct andana_server *server = NULL;
    const char *key_uri = NULL;
    struct ccn_closure int_handler;
    struct ccn_closure content_handler;



	while ((res = getopt(argc, argv, "hk:")) != -1) {
		switch (res) {

		default:
		case 'h':
			usage(progname);
			break;
		}
	}

    argc -= optind;
    argv += optind;

    if (argv[0] == NULL)
        usage(progname);

    server = andana_server_init(key_uri, argv[0], argv[0]);

	/*Initialize Interest and Content handlers*/

	int_handler.p = &andana_server_decap_interest;
	int_handler.data = server;

	content_handler.p = &andana_server_encap_content;
	content_handler.data = server;

	andana_server_set_handlers(server, &int_handler, &content_handler);

    if (andana_server_connect(server) < 0) {
        fprintf(stderr, "Error: Server Failed to connect to ccnd %d\n", __LINE__);
        exit(1);
    }

    //ccn_run(proxy->h, -1);//3600 * 1000);
    andana_server_run(server);

    fprintf(stderr, "Done running proxy\n");

    //ccn_disconnect(proxy->h);
    andana_server_destroy(&server);

	return(0);
}
