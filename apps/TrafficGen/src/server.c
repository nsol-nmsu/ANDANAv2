

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "proxy.h"

int
main(int argc, char **argv)
{
	const char *progname = argv[0];
	int res;

    struct ccn_proxy_server *server = NULL;
    struct ccn_closure int_handler;
    struct ccn_closure content_handler;

    server = ccn_proxy_server_init(argv[1], argv[1]);

	/*Initialize Interest and Content handlers*/

	int_handler.p = &ccn_proxy_server_decap_interest;
	int_handler.data = server;

	ccn_proxy_set_handlers(server->proxy, &int_handler);

    if (ccn_proxy_connect(server->proxy) < 0) {
        fprintf(stderr, "Error: Server Failed to connect to ccnd %d\n", __LINE__);
        exit(1);
    }

    //ccn_run(proxy->h, -1);//3600 * 1000);
    ccn_proxy_run(server->proxy);

    fprintf(stderr, "Done running proxy\n");

    //ccn_disconnect(proxy->h);
    ccn_proxy_server_destroy(&server);

	return(0);
}
