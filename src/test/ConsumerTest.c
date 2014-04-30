#include "../UpstreamProxy.h"
#include "../Proxy.h"
#include "../Crypto.h"
#include "../CryptoWrapper.h"
#include "../Util.h"

int main(int argc, char** argv)
{
	struct ccn_charbuf* orig = ccn_charbuf_create();
	ccn_name_init(orig);
	ccn_name_append_str(orig, "rawr");
	printf("name = %s\n", ccn_charbuf_as_string(orig));

	// TODO	

	return 0;
}