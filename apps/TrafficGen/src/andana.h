#ifndef ANDANA_H_
#define ANDANA_H_

#include <ccn/proxy/proxy.h>

struct andana_path;

struct andana_client;


/**
 * Create and initialize a new anonymous client proxy. Encrypts
 * an encapsulates all interests except those that match a given
 * prefix (to prevent an endless loop of proxy'd interests).
 *
 * @param prefix to ignore (aka the prefix outbound Interests will have)
 * @param initial path to use for encryption and encapsulation
 * @returns initialized anonymous client proxy
 */

struct andana_client *
andana_client_init(const char *prefix_uri,
                   struct andana_path *path);


void
andana_client_set_handlers(struct andana_client *client,
                           struct ccn_closure *int_handler,
                           struct ccn_closure *content_handler);


int
andana_client_connect(struct andana_client *client);

int
andana_client_run(struct andana_client *client);

/**
 * Change the "path" encryption & encapsulation structure
 * used by the client. Path changes may be made at any time
 * as the mapping process remembers the path it used.
 *
 * @param anonymous client whose path should be changed
 * @param new encryption & encapsulation path
 */


void
andana_client_set_path(struct andana_client *client,
                       struct andana_path *path);

/**
 * Encapsulate and encrypt incoming Interest. Supports session-based (symmetric)
 * and asymmetric cryptography. The path structure used for encryption and encapsulation
 * is stored so that paths may be changed at any time.
 *
 */

enum ccn_upcall_res
andana_client_encap_interest(struct ccn_closure *selfp,
                             enum ccn_upcall_kind kind,
                             struct ccn_upcall_info *info);

/**
 * Decrypt and decapsulate an incoming content object using
 * pre-arranged symmetric key.
 */

enum ccn_upcall_res
andana_client_decap_content(struct ccn_closure *selfp,
                            enum ccn_upcall_kind kind,
                            struct ccn_upcall_info *info);

/**
 * Destroy/clean up anonymous client. Only expect this to be called
 * when the program is done.
 *
 * @param pointer to the anonymous client to be destroyed
 * @returns 0
 */


int
andana_client_destroy(struct andana_client **aclient);






struct andana_server;




/**
 * Create and initialize a new anonymous server proxy.
 * Decrypts and decapsulates incoming Interests and encrypts
 * and encapsulates the returning content objects with an
 * agreed upon ephemeral symmetric key (carried in the Interest).
 *
 * @param key_uri ccnx URI of key used for signing Content Objects
 * @param filter_uri ccnx URI to be used for Interest filtering (i.e. select what it SHOULD process)
 * @param prefix_uri ccnx URI of name prefix that should be removed from incoming Interests.
 *
 * Note that prefix_uri and filter_uri may be the same.
 *
 * @returns initialized anonymous server
 */

struct andana_server *
andana_server_init(const char *key_uri,
                   const char *filter_uri,
                   const char *prefix_uri);


void
andana_server_set_handlers(struct andana_server *server,
                           struct ccn_closure *int_handler,
                           struct ccn_closure *content_handler);

/**
 * Initialize interest/content handlers and connect to underlying
 * ccnd instance.
 *
 * @param anonymous server to configure
 * @returns result of setting interest filter
 */

int
andana_server_connect(struct andana_server *server);



int
andana_server_run(struct andana_server *server);


/**
 * Listener to handle requests to set up new
 * sessions (symmetric encryption only).
 */


enum ccn_upcall_res
andana_server_session_listener(struct ccn_closure *selfp,
                               enum ccn_upcall_kind kind,
                               struct ccn_upcall_info *info);


/**
 * Decapsulate and encrypt incoming interest. Stores
 * reverse mapping of outgoing interest name to original
 * to simplify content object processing (similar to normal proxy server).
 *
 * Supports asymmetric and session-based Interest encryption. Outgoing interests
 * use the template specified in the decrypted payload.
 *
 * Also supports timestamp checking to avoid an adversary using this node
 * as a decryption oracle. Default window (in code, not theory) is 1.6 seconds.
 * This is completely arbitrary and was for my testing convenience.
 */

enum ccn_upcall_res
andana_server_decap_interest(struct ccn_closure *selfp,
                             enum ccn_upcall_kind kind,
                             struct ccn_upcall_info *info);

/**
 * Encapsulate and encrypt returning content objects. Encryption
 * uses the ephemeral symmetric key provided by the user in the original
 * interest (stored in a pair).
 *
 * This node will naturally sign the outgoing content object, thus providing
 * verifiability.
 */


enum ccn_upcall_res
andana_server_encap_content(struct ccn_closure *selfp,
                            enum ccn_upcall_kind kind,
                            struct ccn_upcall_info *info);

/**
 * Clean up and destroy anonymous server object. Expect
 * to be called once at program close.
 *
 * @param pointer to anonymous server to be destroyed
 * @returns 0 (always)
 */

int
andana_server_destroy(struct andana_server **server);


#endif
