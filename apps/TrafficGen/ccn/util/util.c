/*
 * util.c
 *
 *  Created on: Jun 27, 2011
 *      Author: sdibened
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <ccn/ccn.h>
#include <ccn/uri.h>
#include <ccn/util/util.h>



/**
 * Network to host byte order conversion for arbitrary sized
 * pieces of data. (FIXME) This isn't a good function and is assuming
 * host byte order is little endian.
 *
 * @param data in network byte order
 * @param size of data
 * @param data in host byte order (out)
 */

static void
ntoh(const void *s, const size_t size, void *out)
{
    const unsigned char *n = s;
    unsigned char *h = out;

    size_t i;
    for (i = 0; i < size; i++) {
        h[size - 1 - i] = n[i];
    }
}

/**
 * Convert a ccn version/timestamp into a timeval struct.
 * Used for anonymizer replay window checking.
 *
 * @param timestamp
 * @param size of timestamp
 * @param output timeval structure of timestamp
 *
 * @returns 0 on success, negative if timestamp is too large (more than 48 bytes)
 */

int
ccn_util_extract_timestamp(const unsigned char *p,
                                 size_t psize,
                                 struct timeval *out_ts)
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

//    *secs = ts * frac;
//    *nsecs = (ts * frac - *secs) * billion;

    intmax_t sec = ts * frac;
    out_ts->tv_sec = sec;
    out_ts->tv_usec = (ts * frac - sec) * billion / 1000000; /* FIXME Pretty sure I'm not extracting the correct precision */

    return(0);
}

/**
 * Check if the provided timestamp falls within the specified window.
 *
 * @param timestamp to check
 * @param +/- window from current time
 *
 * @returns true if in window, otherwise false
 */

int
ccn_util_timestamp_window(const struct timeval *ts,
                                const struct timeval *window)
{
    struct timeval now;
    struct timeval upper = {.tv_sec=(ts->tv_sec + window->tv_sec), .tv_usec=(ts->tv_usec + window->tv_usec)};
    struct timeval lower = {.tv_sec=(ts->tv_sec - window->tv_sec), .tv_usec=(ts->tv_usec - window->tv_usec)};

    if (lower.tv_usec < 0) {
        lower.tv_sec--;
        lower.tv_usec = 1000000 - lower.tv_usec;
    }

    if (upper.tv_usec > 1000000) {
        upper.tv_sec++;
        upper.tv_usec = 1000000 - upper.tv_usec;
    }

    gettimeofday(&now, NULL);

    DEBUG_PRINT( "%d %s Now    = %ld.%d\n", __LINE__, __func__, now.tv_sec, now.tv_usec);
    DEBUG_PRINT( "%d %s ts     = %ld.%d\n", __LINE__, __func__, ts->tv_sec, ts->tv_usec);
    DEBUG_PRINT( "%d %s window = %ld.%d\n", __LINE__, __func__, window->tv_sec, window->tv_usec);
    DEBUG_PRINT( "%d %s (%ld.%d\t%ld.%d)", __LINE__, __func__, lower.tv_sec, lower.tv_usec, upper.tv_sec, upper.tv_usec);

/*

caw: debug removal for now, it's causing things to be dropped and it's pissing me off.

    if (now.tv_sec < lower.tv_sec || now.tv_sec > upper.tv_sec) {
        return(0);
    }

    if (now.tv_sec == lower.tv_sec) {
        return(now.tv_usec >= lower.tv_usec);
    } else if (now.tv_sec == upper.tv_sec) {
        return(now.tv_usec <= lower.tv_usec);
    }
*/
    return(1);
}

/**
 * Convenience function for validating a Content Object. Sets up
 * and calls ccn_parse_ContentObject for actual validation.
 *
 * @param buf Content Object to be validated. Expects everything from <Content> through </Content> to be inside.
 * @param length length of the Content Object
 * @returns 0 on success, otherwise negative number (pass thru result from ccn_parse_ContentObject)
 */

int
ccn_util_validate_content_object(const unsigned char *buf, size_t length)
{
    int res;
    struct ccn_parsed_ContentObject obj = {0};
    struct ccn_indexbuf *ibuf = ccn_indexbuf_create();

    res = ccn_parse_ContentObject(buf, length, &obj, ibuf);

    if (res < 0) {
        DEBUG_PRINT( "Failed to parse Content Object (res = %d)\n", res);
    } else {
        DEBUG_PRINT( "Content Object parsed (res = %d)\n", res);
    }

    ccn_indexbuf_destroy(&ibuf);

    return(res);
}

/**
 * Convenience function for validating a ccn name. Sets up
 * and calls ccn_parse_Name for actual validation.
 *
 * @param buf ccn name to be validated. Expects everything from <Name> through </Name> to be inside.
 * @param length length of the ccn name
 * @returns -1 on error, otherwise the number of parse components (pass thru result from ccn_parse_Name)
 */

int
ccn_util_validate_name(const unsigned char *buf, size_t length)
{
    int res;
    struct ccn_indexbuf *ibuf = ccn_indexbuf_create();
    struct ccn_buf_decoder decoder;
    struct ccn_buf_decoder *d = &decoder;

    d = ccn_buf_decoder_start(d, buf, length);
    res = ccn_parse_Name(d, ibuf);

    if (res < 0) {
        DEBUG_PRINT( "Invalid name (res = %d)\n", res);
    } else {
        DEBUG_PRINT( "Name OK (res = %d)\n", res);
    }

    ccn_indexbuf_destroy(&ibuf);

    return(res);
}

/**
 * Extract a ccn name from ccnb. Also provides the indexbuf for the
 * extracted name.
 *
 * @param ccnb that contains a name
 * @param indexbuf for input ccnb
 * @param pointer to extracted name (output)
 * @param pointer to indexbuf for extracted name (output)
 *
 * returns negative on failure, otherwise number of components in extracted name
 */

int
ccn_util_extract_name(const unsigned char *ccnb,
                            const struct ccn_indexbuf *offsets,
                            struct ccn_charbuf **name,
                            struct ccn_indexbuf **indexbuf)
{
    int res;
    int name_num_comps;

    *name = ccn_charbuf_create();
    *indexbuf = ccn_indexbuf_create();

    struct ccn_buf_decoder decoder;
    struct ccn_buf_decoder *d = &decoder;
    size_t ncomps = offsets->n - 1;

    ccn_name_init(*name);
    res = ccn_name_append_components(*name, ccnb,
                                     offsets->buf[0], offsets->buf[ncomps]);


//    if(ncomps != offsets->n) {
//    	DEBUG_PRINT( "TESTING _extract_name: ncomps (%d) != offsets->n (%d)\n", ncomps, offsets->n);
//    }


    d = ccn_buf_decoder_start(d, (*name)->buf, (*name)->length);
    name_num_comps = ccn_parse_Name(d, *indexbuf);

    if(name_num_comps < 0) {
        DEBUG_PRINT( "Parsed Interest name is broken\n");
        ccn_charbuf_destroy(name);
        ccn_indexbuf_destroy(indexbuf);
        return(-1);
    }

    return name_num_comps;
}

/**
 * Convenience function for printing a ccnx name in the % format
 * @param ccnb containing ccn name
 * @param size of ccnb
 */

void
ccn_util_print_pc_fmt(const unsigned char *ccnb, const size_t size)
{
    struct ccn_charbuf *c = ccn_charbuf_create();
    ccn_uri_append(c, ccnb, size, 1);
    DEBUG_PRINT( "%s", ccn_charbuf_as_string(c));
    ccn_charbuf_destroy(&c);
}

/**
 * Convenience function for printing a ccnx name in the % format with a newline
 * @param ccnb containing ccn name
 * @param size of ccnb
 */

void
ccn_util_println_pc_fmt(const unsigned char *ccnb, const size_t size)
{
    struct ccn_charbuf *c = ccn_charbuf_create();
    ccn_uri_append(c, ccnb, size, 1);
    DEBUG_PRINT( "%s\n", ccn_charbuf_as_string(c));
    ccn_charbuf_destroy(&c);
}

/**
 * Convenience function creating and initializing a ccnx uri from ccnb
 * @param ccnb containing ccn name
 * @param size of ccnb
 *
 * @returns uri of name
 */

struct ccn_charbuf *
ccn_util_create_uri_charbuf(const unsigned char *ccnb, const size_t size)
{
    struct ccn_charbuf *uri = ccn_charbuf_create();
    ccn_uri_append(uri, ccnb, size, 1);
    return uri;
}

/**
 * Convenience function for printing hex of byte array
 * @param data to be printed
 * @param size of data
 */

void
ccn_util_print_buf(const unsigned char *buf, size_t length)
{
    int x;
    for (x=0; x<length; x++) {
        DEBUG_PRINT( "%x ", buf[x]);
    }
    DEBUG_PRINT( "\n");
}

/**
 * Convenience function for printing hex of charbuf
 * @param data to be printed
 * @param size of data
 */

void
ccn_util_print_charbuf(struct ccn_charbuf *buf)
{
    int x;
    for (x=0; x< buf->length; x++) {
        DEBUG_PRINT( "%x ", buf->buf[x]);
    }
    DEBUG_PRINT( "\n");
}

/**
 * Convenience function for printing the current time. Only
 * works if debugging is enabled.
 */

void
ccn_util_print_time(void)
{
    struct timeval t;
    gettimeofday(&t, NULL);

    DEBUG_PRINT( "%ld.000000 ", (long)t.tv_sec);// ctime(&t.tv_sec));
}


/* Compare 2 names (a and b) and determine the number of common
 * prefix components. Only identifies matches beginning with the
 * first component.
 *
 * @param a first name
 * @param a_comps indexbuf of a's components
 * @param b second name
 * @param b_comps indexbuf of b's components

 * @returns -1 on error, otherwise number of matching components (0+).
 * 0 is equivalent to no match.
 */

int
ccn_util_name_match(struct ccn_charbuf *a,
                          struct ccn_indexbuf *a_comps,
                          struct ccn_charbuf *b,
                          struct ccn_indexbuf *b_comps)
{
    size_t min_comps;

    if (a_comps->n <= b_comps->n) {
        min_comps = a_comps->n - 1;
    } else {
        min_comps = b_comps->n - 1;
    }


    int matches = 0;
    int i;
    for (i = 0; i < min_comps; i++) {
        int res;
        const unsigned char *a_data = NULL;
        size_t a_data_size;
        const unsigned char *b_data = NULL;
        size_t b_data_size;

        /* Retrieve data in ith name component (and its length). */

        res = ccn_name_comp_get(a->buf, a_comps, i,
                                &a_data, &a_data_size);
        if (res < 0) {
            DEBUG_PRINT( "Error retrieving component %d from a's name\n", i);
            return(-1);
        }

        res = ccn_name_comp_get(b->buf, b_comps, i,
                                &b_data, &b_data_size);

        if (res < 0) {
            DEBUG_PRINT( "Error retrieving component %d from b's name\n", i);
            return(-1);
        }

        /* Now check the data for equivalence */

        if (a_data_size != b_data_size ||
            memcmp(a_data, b_data, a_data_size) != 0) {
            break;
        }
        matches++;
    }

    /* Interest name matches the proxy's mask. i == # of matching components */

    return(matches);
}
