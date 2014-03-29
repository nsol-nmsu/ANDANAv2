#ifndef UTIL_H_
#define UTIL_H_

#include <ccn/charbuf.h>
#include <ccn/indexbuf.h>
#include <sys/time.h>

// #ifdef DEBUG
#define DEBUG_PRINT(...) do{ fprintf( stderr, __VA_ARGS__ ); } while( 0 )
// #else
//#define DEBUG_PRINT(...) do{ } while ( 0 )
// #endif

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
                           struct timeval *out_ts);

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
                          const struct timeval *window);
/**
 * Convenience function for validating a Content Object. Sets up
 * and calls ccn_parse_ContentObject for actual validation.
 *
 * @param buf Content Object to be validated. Expects everything from <Content> through </Content> to be inside.
 * @param length length of the Content Object
 * @returns 0 on success, otherwise negative number (pass thru result from ccn_parse_ContentObject)
 */

int
ccn_util_validate_content_object(const unsigned char *buf, size_t length);

/**
 * Convenience function for validating a ccn name. Sets up
 * and calls ccn_parse_Name for actual validation.
 *
 * @param buf ccn name to be validated. Expects everything from <Name> through </Name> to be inside.
 * @param length length of the ccn name
 * @returns -1 on error, otherwise the number of parse components (pass thru result from ccn_parse_Name)
 */

int
ccn_util_validate_name(const unsigned char *buf, size_t length);

/**
 * Convenience function for printing a ccnx name in the % format
 * @param ccnb containing ccn name
 * @param size of ccnb
 */

void
ccn_util_print_pc_fmt(const unsigned char *ccnb, const size_t size);

/**
 * Convenience function for printing a ccnx name in the % format with a newline
 * @param ccnb containing ccn name
 * @param size of ccnb
 */


void
ccn_util_println_pc_fmt(const unsigned char *ccnb, const size_t size);

/**
 * Convenience function creating and initializing a ccnx uri from ccnb
 * @param ccnb containing ccn name
 * @param size of ccnb
 *
 * @returns uri of name
 */

struct ccn_charbuf *
ccn_util_create_uri_charbuf(const unsigned char *ccnb, const size_t size);

/**
 * Convenience function for printing hex of byte array
 * @param data to be printed
 * @param size of data
 */

void
ccn_util_print_buf(const unsigned char *buf, size_t length);

/**
 * Convenience function for printing hex of charbuf
 * @param data to be printed
 * @param size of data
 */


void
ccn_util_print_charbuf(struct ccn_charbuf *buf);

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
                    struct ccn_indexbuf *b_comps);


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

/**
 * Convenience function for printing the current time. Only
 * works if debugging is enabled.
 */

int
ccn_util_extract_name(const unsigned char *ccnb,
                      const struct ccn_indexbuf *offsets,
                      struct ccn_charbuf **name,
                      struct ccn_indexbuf **indexbuf);

void
ccn_util_print_time(void);

#endif /* UTIL_H_ */