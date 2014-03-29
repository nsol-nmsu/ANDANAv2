#include <stdlib.h>
#include <stdio.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include <ccn/ccn.h>
#include <ccn/charbuf.h>
#include <ccn/uri.h>
#include <ccn/signing.h>

#include <key.h>
#include <util.h>

#include <keyserver.h>

int main()
{
    struct ccn *h = ccn_create();
    ccn_connect(h, NULL);


    struct ccn_keyserver *server = ccn_keyserver_init(h, "ccnx:/hello", NULL);

    ccn_run(h, -1);

    ccn_keyserver_destroy(&server);

    return 0;
}
