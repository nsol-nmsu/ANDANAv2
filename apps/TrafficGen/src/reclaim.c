#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>


#include <ccn/ccn.h>
#include <ccn/charbuf.h>


void
hprint(const void *s, const size_t size)
{
	const unsigned char *p = s;
    int i;
    for (i = 0; i < size - 1; i++) {
    	printf("%.2x ",p[i]);
    }
    printf("%.2x",p[size-1]);
}

void
hprintln(const void *s, const size_t size)
{
	hprint(s, size);
	printf("\n");
}


//size_t
//host_nbytes(const void *s, const size_t size)
//{
//	const unsigned char *p = s;
//	size_t n = 1;
//	size_t i;
//	for (i = 1; i < size; i++) {
//		if (p[i] > 0) {
//			n = i;
//		}
//	}
//	return(n);
//}
//
//size_t
//net_nbytes(const void *s, const size_t size)
//{
//	const unsigned char *p = s;
//
//	size_t i;
//	for (i = size - 1; i > 0; i--) {
//		if (p[i] > 0) {
//			return(size - i + 1);
//		}
//	}
//	return(1);
//}

//void *
//hton(const void *s, const size_t size)
//{
//	const unsigned char *h = s;
//	unsigned char *n = calloc(size, sizeof(unsigned char));
//
//	size_t i;
//	for (i = 0; i < size; i++) {
//		n[size - 1 - i] = h[i];
//	}
//	return(n);
//}

//void *
//ntoh(const void *s, const size_t size)
//{
//	const unsigned char *n = s;
//	unsigned char *h = calloc(size, sizeof(unsigned char));
//
//	size_t i;
//	for (i = 0; i < size; i++) {
//		h[size - 1 - i] = n[i];
//	}
//	return(h);
//}

void
ntoh(const void *s, const size_t size, void *out)
{
	const unsigned char *n = s;
	unsigned char *h = out;

	size_t i;
	for (i = 0; i < size; i++) {
		h[size - 1 - i] = n[i];
	}
}


int
reclaim_ts(const unsigned char *p, size_t psize, intmax_t *secs, int *nsecs)
{
	const unsigned char *t = p;
	size_t tsize = psize;
	const double frac = 0.000244140625; /*2^-12*/
	const size_t billion = 1000000000;

    unsigned char marker = 0;
    memcpy(&marker, t, sizeof(unsigned char));
    t += sizeof(unsigned char);
    tsize--;


    switch (marker) {
    case CCN_MARKER_VERSION:
    	break;
    default:
    	return(-__LINE__);
    }

    if (tsize > 48) {
    	/*Timestamp is too big*/
    	return(-__LINE__);
    }

    intmax_t ts = 0;
    ntoh(t, tsize, &ts);

    *secs = ts * frac;
    *nsecs = (ts * frac - *secs) * billion;

    return(0);
}

int
gen_test(struct ccn_charbuf **name, struct ccn_indexbuf **comps)
{
	int res;

    intmax_t secs = 1234567890;
    int nsecs = 6000000;

    *name = ccn_charbuf_create();
    ccn_name_init(*name);

    res = ccn_create_version(NULL, *name, 0, secs, nsecs);

    if (res < 0) {
    	printf("Unable to create version\n");
    	return(-__LINE__);
    }

    *comps = ccn_indexbuf_create();
    struct ccn_buf_decoder decoder;
    struct ccn_buf_decoder *d = &decoder;
    ccn_buf_decoder_start(d, (*name)->buf, (*name)->length);

    res = ccn_parse_Name(d, *comps);

    if (res < 0) {
     	printf("Unable to parse name\n");
     	return(-__LINE__);
     }

    return(0);
}

int main(void)
{
	int res;
	struct ccn_charbuf *name = NULL;
	struct ccn_indexbuf *comps = NULL;

    const unsigned char *comp0 = NULL;
    size_t comp0size;

	gen_test(&name, &comps);

    res = ccn_name_comp_get(name->buf, comps, 0, &comp0, &comp0size);

    if (res < 0) {
     	printf("Unable to get comp\n");
     	return(-__LINE__);
     }

    intmax_t rec_secs = 0;
    int rec_nsecs = 0;
    reclaim_ts(comp0, comp0size, &rec_secs, &rec_nsecs);

//    printf("seconds = %lu %s\n", rec_secs, (secs == rec_secs)?("YES"):("NO"));
//    printf("nano seconds = %d %s\n", rec_nsecs, (nsecs == rec_nsecs)?("YES"):("NO"));

    ccn_charbuf_destroy(&name);
    ccn_indexbuf_destroy(&comps);

    return(0);
}
