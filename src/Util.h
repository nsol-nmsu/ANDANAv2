/**
 * File: Util.h
 * Description: Helpful collection of utility functions and macros 
 * Author: Christopher A. Wood, woodc1@uci.edu
 */

#ifndef UTIL_H_
#define UTIL_H_

#include <math.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Toggle debug output
#define DEBUG_ENABLED 1

// Debug print
#if DEBUG_ENABLED
#define DEBUG_PRINT(...) do{ fprintf( stderr, __VA_ARGS__ ); } while( 0 )
#else
#define DEBUG_PRINT(...) 
#endif

///// TODO
void print_hex(unsigned char * s, int len);
char * base64_encode(const unsigned char *input, int length);
unsigned char *base64_decode(char *input);
unsigned char * base64_decode_len(char *in, int * len);

/**
 * Extract a ccn name from ccnb. Also provides the indexbuf for the extracted name.
 *
 * @param ccnb that contains a name
 * @param indexbuf for input ccnb
 * @param pointer to extracted name (output)
 * @param pointer to indexbuf for extracted name (output)
 *
 * returns negative on failure, otherwise number of components in extracted name
 */
int ccn_util_extract_name(const unsigned char *ccnb, const struct ccn_indexbuf *offsets, struct ccn_charbuf **name, struct ccn_indexbuf **indexbuf);

/* Compare two names (a and b) and determine the number of common prefix components. Only identifies 
 * matches beginning with the first component.
 *
 * @param a first name
 * @param a_comps indexbuf of a's components
 * @param b second name
 * @param b_comps indexbuf of b's components

 * @returns -1 on error, otherwise number of matching components (0+).
 * 0 is equivalent to no match.
 */
int ccn_util_name_match(struct ccn_charbuf *a, struct ccn_indexbuf *a_comps, struct ccn_charbuf *b, struct ccn_indexbuf *b_comps);

#endif /* UTIL_H_ */
