#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

#include <ccn/ccn.h>
#include <ccn/uri.h>

#include "Util.h"

void print_hex(unsigned char * s, int len)
{
	int i;
	for (i=0 ; i<len ; i++)
	{
		printf("%02X", 0xff & s[i]);
	}
}

char * base64_encode(const unsigned char *input, int length, int* outlen)
{
    BIO *bmem, *b64;
    BUF_MEM *bptr;
    char *buff;
    int i;
    
    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // All in one line
    
    b64 = BIO_push(b64, bmem);
    if(BIO_write(b64, input, length)<=0)
    {
        BIO_free_all(b64);
        return NULL;   
    }
    
    (void)BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    
    buff = (char *)malloc(bptr->length+1);
    
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = 0;
    
    BIO_free_all(b64);
    
    //replace '/' with '-'    
    for(i=0; buff[i]; i++)
        if(buff[i] == '/')
            buff[i] = '-';
    memcpy(outlen, i, sizeof(int));
    
    return buff;
}

unsigned char * base64_decode(char *in)
{
    BIO *b64, *bmem;
    int length = (int)strlen(in);
    int i;
    char * input = (char *)malloc(length+1);
    memcpy(input, in, length + 1);
    
    //replace '-' with '/'  
    for(i=0; input[i]; i++)
        if(input[i] == '-')
            input[i] = '/';
    
    length++;
    
    unsigned char *buffer = (unsigned char *)calloc(1,length);
    
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // All in one line
    
    bmem = BIO_new_mem_buf(input, length);
    bmem = BIO_push(b64, bmem);
    
    if(BIO_read(bmem, buffer, length)<=0)
    {
        free(buffer);
        free(input);
        buffer = NULL;
    }
    
    BIO_free_all(bmem);
    free(input);
    return buffer;
}

unsigned char * base64_decode_len(char *in, int * len)
{
    BIO *b64, *bmem;
    int length = (int)strlen(in);
    int i;
    char * input = (char *)malloc(length+1);
    memcpy(input, in, length + 1);
    
    //replace '-' with '/'  
    for(i=0; input[i]; i++)
        if(input[i] == '-')
            input[i] = '/';
    
    length++;
    
    unsigned char *buffer = (unsigned char *)calloc(1,length);
    
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // All in one line
    
    bmem = BIO_new_mem_buf(input, length);
    bmem = BIO_push(b64, bmem);
    
    if((*len = BIO_read(bmem, buffer, length))<=0)
    {
        free(buffer);
        free(input);
        buffer = NULL;
    }
    
    BIO_free_all(bmem);
    free(input);
    return buffer;
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
ccn_util_extract_name(const unsigned char *ccnb, const struct ccn_indexbuf *offsets, struct ccn_charbuf **name, struct ccn_indexbuf **indexbuf)
{
    int res;
    int name_num_comps;

    *name = ccn_charbuf_create();
    *indexbuf = ccn_indexbuf_create();

    struct ccn_buf_decoder decoder;
    struct ccn_buf_decoder *d = &decoder;
    size_t ncomps = offsets->n - 1;

    ccn_name_init(*name);
    res = ccn_name_append_components(*name, ccnb, offsets->buf[0], offsets->buf[ncomps]);

//    if(ncomps != offsets->n) {
//      DEBUG_PRINT( "TESTING _extract_name: ncomps (%d) != offsets->n (%d)\n", ncomps, offsets->n);
//    }

    d = ccn_buf_decoder_start(d, (*name)->buf, (*name)->length);
    name_num_comps = ccn_parse_Name(d, *indexbuf);

    if(name_num_comps < 0) 
    {
        DEBUG_PRINT("Parsed Interest name is broken\n");
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
void ccn_util_print_pc_fmt(const unsigned char *ccnb, const size_t size)
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
void ccn_util_println_pc_fmt(const unsigned char *ccnb, const size_t size)
{
    struct ccn_charbuf *c = ccn_charbuf_create();
    ccn_uri_append(c, ccnb, size, 1);
    DEBUG_PRINT( "%s\n", ccn_charbuf_as_string(c));
    ccn_charbuf_destroy(&c);
}

/* Compare two names (a and b) and determine the number of common prefix components. Only 
 * identifies matches beginning with the first component.
 *
 * @param a first name
 * @param a_comps indexbuf of a's components
 * @param b second name
 * @param b_comps indexbuf of b's components
 * @returns -1 on error, otherwise number of matching components (0+).
 * 0 is equivalent to no match.
 */
int ccn_util_name_match(struct ccn_charbuf *a, struct ccn_indexbuf *a_comps, struct ccn_charbuf *b, struct ccn_indexbuf *b_comps)
{
    size_t min_comps;

    if (a_comps->n <= b_comps->n) {
        min_comps = a_comps->n - 1;
    } else {
        min_comps = b_comps->n - 1;
    }


    int matches = 0;
    int i;
    for (i = 0; i < min_comps; i++) 
    {
        int res;
        const unsigned char *a_data = NULL;
        size_t a_data_size;
        const unsigned char *b_data = NULL;
        size_t b_data_size;

        // Retrieve data in ith name component (and its length).
        res = ccn_name_comp_get(a->buf, a_comps, i, &a_data, &a_data_size);
        if (res < 0) 
        {
            DEBUG_PRINT( "Error retrieving component %d from a's name\n", i);
            return -1;
        }

        res = ccn_name_comp_get(b->buf, b_comps, i,
                                &b_data, &b_data_size);

        if (res < 0) 
        {
            DEBUG_PRINT( "Error retrieving component %d from b's name\n", i);
            return -1;
        }

        // Now check the data for equivalence
        if (a_data_size != b_data_size || memcmp(a_data, b_data, a_data_size) != 0) 
        {
            break;
        }
        matches++;
    }

    // Interest name matches the proxy's mask. i == # of matching components
    return(matches);
}
