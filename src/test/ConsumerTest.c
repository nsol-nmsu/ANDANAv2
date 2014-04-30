#include "../UpstreamProxy.h"
#include "../Proxy.h"
#include "../Crypto.h"
#include "../CryptoWrapper.h"
#include "../Util.h"

int main(int argc, char** argv)
{
	struct ccn_charbuf* orig = ccn_charbuf_create();
	struct ccn_charbuf* newName = ccn_charbuf_create();
	ccn_name_init(orig);
	ccn_name_init(newName);
	ccn_name_append_str(orig, "rawr");
	printf("origName = %s\n", ccn_charbuf_as_string(orig));

	BOB *encryptedPayload = NULL;
	unsigned char encryption_key[KEYLEN];
	int res = SKEncrypt(&encryptedPayload, encryption_key, orig->buf, orig->length);

	printf("same? %d\n", memcmp(orig->buf, encryptedPayload->blob, orig->length) == 0);

    if (res < 0)
    {
        DEBUG_PRINT("Failed encrypting interest payload\n");
        return CCN_UPCALL_RESULT_ERR;
    }
    ccn_name_append_str(newName, "ccnx:/proxy/");
    printf("newName = %s\n", ccn_charbuf_as_string(newName));
    printf("len = %d\n", newName->length);
    res = ccn_name_append(newName, (void*)encryptedPayload->blob, encryptedPayload->len);
    if (res < 0)
    {
    	DEBUG_PRINT("Failed appending string\n");
    }
    printf("newName after append = %s\n", ccn_charbuf_as_string(newName));
    printf("len = %d\n", newName->length);

    printf("same names? %d\n", memcmp(orig->buf, newName->buf, orig->length) == 0);

    ///// send over the wire....
    // now decrypt

    struct ccn_charbuf *name = NULL;
    struct ccn_indexbuf *nameComponents = NULL;
    // printf("%d\n", ccn_name_chop(newName->buf, nameComponents, 3));

	struct ccn_parsed_interest *interest;
    printf("%d\n", ccn_parse_interest(newName->buf, newName->length, interest, nameComponents));

    // numComponents = ccn_util_extract_name(info->interest_ccnb, info->interest_comps, &name, &nameComponents);
    // ccn_util_extract_name(const unsigned char *ccnb, const struct ccn_indexbuf *offsets, struct ccn_charbuf **name, struct ccn_indexbuf **indexbuf)
    // DEBUG_PRINT("Interest = %s\n", ccn_charbuf_as_string(name));

	return 0;
}