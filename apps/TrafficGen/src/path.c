

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include <openssl/rsa.h>
#include <openssl/evp.h>

#include <ccn/crypto/encryption.h>

#include <ccn/crypto/key.h>
#include <path.h>



/* Private representation of a single path element */

struct andana_path_node {
    struct ccn_charbuf *uri; /* ccnx uri for this proxy */
    struct ccn_indexbuf *uri_comps;
    struct ccn_charbuf *interest_template; /* Template to use for this proxy */

    struct ccn_pkey *pubkey; /* Public key identifying this proxy. */
    struct ccn_pkey *symkey; /* Symmetric key node should use to encrypt Content Objects */

    enum {ASYMMETRIC, SESSION} key_type;

    struct ccn_pkey *session_key; /* Symmetric/session key identify this proxy */
    struct ccn_charbuf *session_id;

    char is_exit;

    suseconds_t usec_offset;
};

static int
andana_path_node_destroy(struct andana_path_node **node);

static int
andana_path_node_decrypt_decap(struct andana_path_node *node,
                               void *content_object,
                               size_t length,
                               struct ccn_parsed_ContentObject *pco,
                               unsigned char **content,
                               size_t *content_length);

/**
 * Creates an initializes a base path node. Each node is
 * specified by a ccnx namespace and its public key. An interest
 * template may also be specified for how this node should reach
 * the next hop (another anonymizer).
 *
 * If this is the last node in the path, is_exit is set to 1
 * to signal that the node's template should be ignored (correct
 * template was previously specified by the client-side anonymizer).
 *
 * Specialist initializers for asymmetric and session-based cryptography
 * call this function for common setup requirements.
 *
 * @param ccnx namespace uri specifying this node
 * @param public key of this node (also used for encryption if asymmetric in use)
 * @param interest template for reaching the next hop anonymizer (ignored if is_exit is true)
 * @param true if this node is the last anonymizer in the path
 *
 * @returns initialized path node, further setup needed for cryptography options
 */

static struct andana_path_node *
andana_path_node_init_common(struct ccn_charbuf *uri,
                             struct ccn_pkey *pubkey,
                             struct ccn_charbuf *interest_template,
                             char is_exit)
{
    struct andana_path_node *node = NULL;

    if (uri == NULL || pubkey == NULL) {
        return(NULL);
    }

    node = calloc(1, sizeof(struct andana_path_node));

    node->uri = ccn_charbuf_create();
    ccn_charbuf_append_charbuf(node->uri, uri);

    node->uri_comps = ccn_indexbuf_create();
    struct ccn_buf_decoder decoder;
    struct ccn_buf_decoder *d = &decoder;

    ccn_buf_decoder_start(d, uri->buf, uri->length);
    if (ccn_parse_Name(d, node->uri_comps) < 0 ) {
        fprintf(stderr,
                "ABORT %d %s cannot create node with invalid name\n",
                __LINE__, __func__);
        goto Bail;
    }


    if (interest_template == NULL) {
        node->interest_template = NULL;
    } else {
        node->interest_template = ccn_charbuf_create();
        ccn_charbuf_append_charbuf(node->interest_template, interest_template);
    }

//	node->usec_offset = .5 * 1000000; /*Half of a second */
    node->usec_offset = 0;
    node->pubkey = ccn_crypto_pubkey_copy(pubkey);
    node->symkey = ccn_crypto_symkey_init(128);

    node->is_exit = is_exit;

    return(node);

Bail:
    andana_path_node_destroy(&node);

    return(NULL);
}

/**
 * Specialist initializer for a path node that should be reached through
 * asymmetric cryptography. In this case, the public key that specifies the node
 * will also be used for encrypted communication.
 *
 * @param ccnx namespace uri specifying this node
 * @param public key of this node (used for encryption)
 * @param interest template for reaching the next hop anonymizer (ignored if is_exit is true)
 * @param true if this node is the last anonymizer in the path
 *
 * @returns fully initialized path node
 */

static struct andana_path_node *
andana_path_node_init_asym(struct ccn_charbuf *uri,
                           struct ccn_pkey *pubkey,
                           struct ccn_charbuf *interest_template,
                           char is_exit)
{
    struct andana_path_node *node =
        andana_path_node_init_common(uri, pubkey, interest_template, is_exit);

    if (node == NULL) {
        return(NULL);
    }

    node->key_type = ASYMMETRIC;
    node->session_key = NULL;

    return(node);
}


/**
 * Specialist initializer for a path node that should be reached through
 * session/symmetric key cryptography. This function triggers a direct communication
 * with the anonymizing server when called to establish an ephemeral session key.
 *
 * The anonymizer's public key is used to encrypt this initialize exchange.
 *
 * @param ccnx namespace uri specifying this node
 * @param public key of this node (used for session setup encryption)
 * @param interest template for reaching the next hop anonymizer (ignored if is_exit is true)
 * @param true if this node is the last anonymizer in the path
 *
 * @returns fully initialized path node or NULL if the session setup fails.
 */

static struct andana_path_node *
andana_path_node_init_session(struct ccn_charbuf *uri,
                              struct ccn_pkey *pubkey,
                              struct ccn_charbuf *interest_template,
                              char is_exit)
{
    char bail = 0;
    struct andana_path_node *node =
        andana_path_node_init_common(uri, pubkey, interest_template, is_exit);

    if (node == NULL) {
        fprintf(stderr, "%d %s Basic node setup failure\n", __LINE__, __func__);
        return(NULL);
    }

    node->key_type = SESSION;

    int res;
    struct ccn *sessionh = ccn_create();
    res = ccn_connect(sessionh, NULL);

    if (res == -1) {
        fprintf(stderr, "%d %s Unable to create session. Failed to connect to ccnd\n", __LINE__, __func__);
        bail = 1;
        goto BailConnect;
    }

    /* Craft a special name to request a session from the specified proxy. */

    struct ccn_charbuf *int_name = ccn_charbuf_create();
    ccn_charbuf_append_charbuf(int_name, uri);
    ccn_name_append_str(int_name, "CREATESESSION");

    struct ccn_charbuf *session_token = ccn_charbuf_create();
    ccn_name_init(session_token);
    ccn_name_append_str(session_token, "CREATE");

    unsigned char *enc_session_token = NULL;
    size_t enc_size;

    ccn_crypto_name_asym_encrypt(node->pubkey,
                                 session_token->buf,
                                 session_token->length,
                                 node->symkey,
                                 &enc_session_token,
                                 &enc_size);

    ccn_name_append(int_name, enc_session_token, enc_size);

    struct ccn_parsed_ContentObject response_pco = { 0 };
    struct ccn_charbuf *response = ccn_charbuf_create();
    struct ccn_indexbuf *response_comps = ccn_indexbuf_create();

    res = ccn_get(sessionh, int_name, NULL, 3000, response, &response_pco, response_comps, 0);

    if (res  == -1) {
    	fprintf(stderr, "%d %s Unable to create new session\n", __LINE__,__func__);
    	bail = 1;
    	goto BailGetSession;
    }

    /* Decrypt response and extract new session key */

    const unsigned char *const_payload = NULL;
    unsigned char *payload = NULL;
    size_t payload_length;

    res = ccn_content_get_value(response->buf,
                                response->length,
                                &response_pco,
                                &const_payload,
                                &payload_length);

    payload = calloc(payload_length, sizeof(unsigned char));
    memcpy(payload, const_payload, payload_length);

    unsigned char *dec_payload = NULL;
    size_t dec_size;
    ccn_crypto_content_decrypt(node->symkey, payload, payload_length, &dec_payload, &dec_size);

    struct ccn_buf_decoder decoder;
    struct ccn_buf_decoder *d = &decoder;

    struct ccn_indexbuf *payload_comps = ccn_indexbuf_create();
    ccn_buf_decoder_start(d, dec_payload, dec_size);
    res = ccn_parse_Name(d, payload_comps);

    if (res == -1) {
        fprintf(stderr, "%d %s Error parsing session response payload\n", __LINE__, __func__);
        bail = 1;
        goto BailPayloadParse;
    } else if (res != 3) {
        fprintf(stderr, "%d %s Malformed session response payload\n", __LINE__, __func__);
        bail = 1;
        goto BailPayloadParse;
    }

    const unsigned char *session_id = NULL;
    size_t session_id_size;
    ccn_name_comp_get(dec_payload, payload_comps, 0, &session_id, &session_id_size);

    if (session_id_size != SESSIONID_LENGTH) {
        fprintf(stderr,
                "%d %s differing session id sizes: got %lu expected %d",
                __LINE__, __func__, session_id_size, SESSIONID_LENGTH);
        bail = 1;
        goto BailPayloadParse;
    }

    const unsigned char *session_key = NULL;
    size_t session_key_size;
    ccn_name_comp_get(dec_payload, payload_comps, 1, &session_key, &session_key_size);

    if (session_key_size != SESSION_KEYLEN) {
        fprintf(stderr,
                "%d %s differing session key sizes: got %lu expected %d",
                __LINE__, __func__, session_key_size, SESSION_KEYLEN);
        bail = 1;
        goto BailPayloadParse;
    }

    const unsigned char *const_session_rand = NULL;
    unsigned char *session_rand = NULL;
    size_t session_rand_size;
    ccn_name_comp_get(dec_payload, payload_comps, 2, &const_session_rand, &session_rand_size);

    session_rand = calloc(session_rand_size, sizeof(unsigned char));
    memcpy(session_rand, const_session_rand, session_rand_size);

    if (session_rand_size != SESSIONRAND_LENGTH) {
        fprintf(stderr,
                "%d %s differing session randomness sizes: got %lu expected %d",
                __LINE__, __func__, session_rand_size, SESSIONRAND_LENGTH);
        bail = 1;
        goto BailSessionFail;
    }

    node->session_id = ccn_charbuf_create();
    ccn_charbuf_append(node->session_id, session_id, session_id_size);
    node->session_key = ccn_crypto_symkey_init_all(session_key, session_key_size);

    res = verifyKeyFromNode(ccn_crypto_symkey_key(node->symkey),
                            (unsigned int)ccn_crypto_symkey_bytes(node->symkey),
                            session_rand,
                            ccn_crypto_symkey_key(node->session_key));

    if (res == 0) {
        fprintf(stderr, "%d %s Failed to verify server's randomness.\n", __LINE__, __func__);
        bail = 1;
        goto BailVerifyFail;
    }

BailVerifyFail:

BailSessionFail:
    free(session_rand);

BailPayloadParse:
    free(payload);
    free(dec_payload);
    ccn_indexbuf_destroy(&payload_comps);

BailGetSession:
    free(enc_session_token);
    ccn_charbuf_destroy(&int_name);
    ccn_charbuf_destroy(&session_token);
    ccn_charbuf_destroy(&response);
    ccn_indexbuf_destroy(&response_comps);

BailConnect:
    ccn_destroy(&sessionh);

    if (bail == 1) {
        andana_path_node_destroy(&node);
        return(NULL);
    }

    return(node);
}

/**
 * Allocate and initialize a deep copy of the provided path node.
 *
 * @param node to be copied
 *
 * @returns deep copy of provided node
 */

static struct andana_path_node *
andana_path_node_copy(struct andana_path_node *node)
{
    struct andana_path_node *node_copy = NULL;

    if (node == NULL) {
        return(NULL);
    }

    node_copy = calloc(1, sizeof(struct andana_path_node));

    node_copy->uri = ccn_charbuf_create();
    ccn_charbuf_append_charbuf(node_copy->uri, node->uri);

    node_copy->uri_comps = ccn_indexbuf_create();
    struct ccn_buf_decoder decoder;
    struct ccn_buf_decoder *d = &decoder;

    ccn_buf_decoder_start(d, node->uri->buf, node->uri->length);
    if (ccn_parse_Name(d, node_copy->uri_comps) < 0 ) {
        fprintf(stderr,
                "ABORT %d %s cannot create node with invalid name\n",
                __LINE__, __func__);
        abort();
    }

    if (node->interest_template == NULL) {
        node_copy->interest_template = NULL;
    } else {
        ccn_charbuf_append_charbuf(node_copy->interest_template,
                                   node->interest_template);
    }

    node_copy->key_type = node->key_type;

    if (node->key_type == ASYMMETRIC) {
        node_copy->pubkey = ccn_crypto_pubkey_copy(node->pubkey);
    } else {
        node_copy->session_key = ccn_crypto_symkey_copy(node->session_key);
        node_copy->session_id = ccn_charbuf_create();
        ccn_charbuf_append_charbuf(node_copy->session_id, node->session_id);
    }
    node_copy->symkey = ccn_crypto_symkey_copy(node->symkey);

    node_copy->is_exit = node->is_exit;
    node_copy->usec_offset = node->usec_offset;

    return(node_copy);
}

/**
 * Generate a new ephemeral symmetric key for this node to use
 * when encrypting content objects.
 *
 * @param node to generate key for
 *
 * @returns 0
 */

static int
andana_path_node_regen_symkey(struct andana_path_node *node)
{
    const size_t key_bits = ccn_crypto_symkey_bits(node->symkey);

    if (node->symkey != NULL) {
        ccn_crypto_symkey_destroy(&(node->symkey));
    }
    node->symkey = ccn_crypto_symkey_init(key_bits);
    return(0);
}

/**
 * This function is used by clients for the initial encryption/encapsulation.
 *
 * Perform interest encryption and encapsulation within
 * a ccn name. The initial interest should be pre-appended
 * to the input name (i.e. ccnx:/foo/<Interest>...</Interest>
 * where foo is the desired final content name/destination).
 *
 * Subsequent interests are specified by the node's template
 * (used for reaching next hop). This template is ignored if
 * node's is_exit is set.
 *
 *
 * @param node with settings for encryption and encapsulation
 * @param name to be encrypted and encapsulated
 * @param indexbuf for input name
 * @param pointer to encrypted & encapsulated name (output)
 * @param pointer to indexbuf for encrypted & encapsulated name (output)
 *
 * @returns number of compontents in encrypted & encapsulated name (or -1 if parse_Name fails)
 */

static int
andana_path_node_encrypt_encap(struct andana_path_node *node,
                               struct ccn_charbuf *name,
                               struct ccn_indexbuf *name_comps,
                               struct ccn_charbuf **result_name,
                               struct ccn_indexbuf **result_name_comps)
{
    int res;

    struct ccn_charbuf *name_to_enc = ccn_charbuf_create();

    struct ccn_charbuf *encapd_name = ccn_charbuf_create();
    struct ccn_indexbuf *encapd_name_comps = *result_name_comps;

    struct ccn_buf_decoder decoder;
    struct ccn_buf_decoder *d = &decoder;

    unsigned char *enc_name = NULL;
    size_t enc_name_length;

    /*
     * Craft a special, valid, name for encryption. Crafted name
     * should begin with the user's provided name
     * followed by the Interest template to be used.
     *
     * <Name> <Comp> CCN Timestamp </Comp> ...Comps from name... <Comp> template </Comp> </Name>
     *
     * In IP, we would just nest entire packets. However, the
     * current CCNx API is not really intended for
     * sending a fully constructed Interest that the user provides.
     *
     * Name encryption library works off a copy, so we only craft
     * this new name if a non-default Interest template is used.
     */


    ccn_name_init(name_to_enc);

    /* Append CCN timestamp (version information) to name */

    struct timeval now;
    gettimeofday(&now, NULL);

    if (now.tv_usec + node->usec_offset >= 1000000) {
    	if (node->usec_offset >= now.tv_usec) {
            now.tv_usec = node->usec_offset - now.tv_usec;
    	} else {
            now.tv_usec = now.tv_usec - node->usec_offset;
    	}
    	now.tv_sec += 1;
    } else {
    	now.tv_usec += node->usec_offset;
    }
    res = ccn_create_version(NULL, name_to_enc, 0, now.tv_sec, now.tv_usec / 1000);

    if (res < 0) {
        fprintf(stderr, "%d %s Error creating version tag\n", __LINE__, __func__);
    }

    ccn_name_append_components(name_to_enc, name->buf,
                               name_comps->buf[0],
                               name_comps->buf[name_comps->n - 1]);

    if (node->is_exit == 0) {
        if (node->interest_template == NULL) {
            /* Append empty component to signal default template should be used */
            unsigned char empty = 0;
            if (ccn_name_append(name_to_enc, &empty, 0) < 0 ) {
                fprintf(stderr, "ABORT %d %s name doesn't like empty append\n", __LINE__, __func__);
                abort();
            }
        } else {
            ccn_name_append(name_to_enc,
                            node->interest_template->buf,
                            node->interest_template->length);
        }
    }

    if (node->key_type == ASYMMETRIC) {
        ccn_crypto_name_asym_encrypt(node->pubkey,
                                     name_to_enc->buf,
                                     name_to_enc->length,
                                     node->symkey,
                                     &enc_name,
                                     &enc_name_length);
    } else {

        if (node->session_id->length != SESSIONID_LENGTH) {
            fprintf(stderr, "%d %s Stored session id has wrong length\n", __LINE__, __func__);
            abort();
        }

        ccn_crypto_name_sym_encrypt(node->session_key,
                                    node->session_id->buf,
                                    name_to_enc->buf,
                                    name_to_enc->length,
                                    node->symkey,
                                    &enc_name,
                                    &enc_name_length);
    }

    /*
     * enc_name is now an encrypted blob.
     *
     * Create a new name with this proxy's uri as the prefix.
     * Remainder of the name will be the encrypted blob.
     *
     * Result will look like:
     * <Name> ...URI Comps... <Comp> encrypted </Comp> </Name>
     *
     * Note the distinction. URI is a valid name so we're just
     * extracting its <Comp>...</Comps>. The encrypted blob is just
     * bits so we need to throw <Comp></Comp> around it.
     */

    ccn_name_init(encapd_name);

    /* Append name prefix for next hop */

    ccn_name_append_components(encapd_name,
                               node->uri->buf,
                               node->uri_comps->buf[0],
                               node->uri_comps->buf[node->uri_comps->n - 1]);


    if (node->key_type == SESSION) {
        /* Need to append session ID to signal anonymizer */
        ccn_name_append_str(encapd_name, "SESSION");
    }

    ccn_name_append(encapd_name, enc_name, enc_name_length);

    *result_name = encapd_name;

    /*
     * This function behaves similarly to parse_Name. If user
     * asked us for an updated indexbuf, we provide one.
     */

    ccn_buf_decoder_start(d, encapd_name->buf, encapd_name->length);
    res = ccn_parse_Name(d, encapd_name_comps);

    if (res <= 0) {
        fprintf(stderr,
                "ABORT %s %d error parsing encapsulated + encrypted name\n",
                __FILE__, __LINE__);
        abort();
    }


    free(enc_name);
    ccn_charbuf_destroy(&name_to_enc);

    /* Number of comps in encapsulated name: (# comps in node URI) + 1 */
    return(res);
}


/**
 * This function is called by clients for the
 * final decryption and decapsulation of returning content objects.
 *
 * Decrypt and decapsulate a provided content object with the specified
 * ephemeral symmetric key.
 *
 * @param node specifying ephemeral symmetric key to use for decrypting this layer
 * @param content object to be decapsulated and decrypted
 * @param length of content object
 * @param parsed content object pointer for manipulating content object (output)
 * @param pointer to decapsulated and decrypted content object (output)
 * @param size of output content object (see previous)
 *
 * @returns result of extracting internal content object (0 on success)
 */

static int
andana_path_node_decrypt_decap(struct andana_path_node *node,
                               void *content_object,
                               size_t length,
                               struct ccn_parsed_ContentObject *pco,
                               unsigned char **content,
                               size_t *content_length)
{
    int res;

    /* Extract payload (Content field) from Content Object */

    const unsigned char *const_payload = NULL;
    unsigned char *payload = NULL;
    size_t payload_length;

    res = ccn_content_get_value(content_object,
                                length,
                                pco,
                                &const_payload,
                                &payload_length);

    if (res < 0) {
        fprintf(stderr, "Error parsing encaspulated content object\n");
        abort();
    }

    /* payload = calloc(payload_length, sizeof(unsigned char)); */
    payload = calloc(1, payload_length);
    memcpy(payload, const_payload, payload_length);

    /* Decrypt payload */
    ccn_crypto_content_decrypt(node->symkey,
                               payload,
                               payload_length,
                               content,
                               content_length);

    /* { */

    /* 	struct ccn_parsed_ContentObject new_pco = {0}; */
    /*         int parse_res = 0; */
    /* 	parse_res = ccn_parse_ContentObject(content, content_length, &new_pco, NULL); */

    /*         if (parse_res < 0) { */
    /*             fprintf(stderr, "ABORT %d %s received bad content object\n", __LINE__, __func__); */
    /*             abort(); */
    /*         } */

    /* } */

    free(payload);

    return(res);
}

/**
 * Cleanup and destroy a path node. Expected to be called
 * when user wishes to change anonymizers.
 *
 * @param pointer to node to be destroyed
 *
 * @returns 0
 */

static int
andana_path_node_destroy(struct andana_path_node **node)
{
    struct andana_path_node *n = *node;

    if (n->uri != NULL) {
        ccn_charbuf_destroy(&(n->uri));
    }

    if (n->uri_comps != NULL) {
        ccn_indexbuf_destroy(&(n->uri_comps));
    }

    if (n->interest_template != NULL) {
        ccn_charbuf_destroy(&(n->interest_template));
    }

    ccn_crypto_pubkey_destroy(&(n->pubkey));
    ccn_crypto_symkey_destroy(&(n->symkey));

    if (n->key_type == SESSION) {
        if (n->session_key != NULL) {
            ccn_crypto_symkey_destroy(&n->session_key);
        }

        if (n->session_id != NULL) {
            ccn_charbuf_destroy(&(n->session_id));
        }
    }


    free(n);

    return(0);
}

/**
 * Path identifying anomyizer nodes (proxies). Names & public keys
 * identify nodes (or an entire service).
 *
 * Path is "walked" during processing to perform encryption & encapsulation
 * or decapsulation & decryption. Path nodes do all of the actual work.
 */

struct andana_path {

    struct andana_path_node **nodes;
    size_t length;
};

/**
 * Allocate and initialize a fixed size path structure. Nodes
 * must still be created before usage. Paths may simultaneously
 * contain asymmetric and session-based cryptography nodes.
 *
 * @param length of path (# anonymizers) to be used
 *
 * @returns new path
 */

struct andana_path *
andana_path_init(const size_t length)
{
    struct andana_path *path = calloc(1, sizeof(struct andana_path));
    size_t i;

    path->nodes = calloc(length, sizeof(struct andana_path_node *));
    path->length = length;

    for (i = 0; i < length; i++) {
        path->nodes[i] = NULL;
    }

    return(path);
}

/**
 * Perform a deep copy of the path. This is used frequently by
 * the client-side anonymizer so that paths may be changed at anytime
 * while still retaining the ability to process traffic that is currently
 * in flight.
 *
 * @param path to be duplicated
 *
 * @returns deep copy of input path
 */

struct andana_path *
andana_path_copy(struct andana_path *path)
{
    struct andana_path *path_copy = andana_path_init(path->length);
    int i;

    for (i = 0; i < path->length; i++) {
        path_copy->nodes[i] = andana_path_node_copy(path->nodes[i]);
    }

    return(path_copy);
}

/**
 * Initialize the index'th node to be an anonymizer to be reached
 * through asymmetric cryptography. Public key provided for node is
 * always used for asymmetric encryption.
 *
 * @param path to be configured with new node
 * @param path index of node to be created/updated
 * @param namespace for reaching this node
 * @param public key for this node (used for encryption)
 * @param interest template this node should use for reaching the next hop
 *
 * @returns 0 on success, negative if invalid index
 */

int
andana_path_set_node_asym(struct andana_path *path,
                          const size_t index,
                          struct ccn_charbuf *node_uri,
                          struct ccn_pkey *pubkey,
                          struct ccn_charbuf *interest)
{
    if (index >= path->length) {
        return(-__LINE__);
    }

    if (path->nodes[index] != NULL) {
        andana_path_node_destroy(&(path->nodes[index]));
    }

    path->nodes[index] =
        andana_path_node_init_asym(node_uri,
                                   pubkey,
                                   interest,
                                   index == path->length - 1);

    return(0);
}

/**
 * Initialize the index'th node to be an anonymizer to be reached
 * through session-based cryptography. Public key provided for node is
 * only used for initial session negotiation.
 *
 * @param path to be configured with new node
 * @param path index of node to be created/updated
 * @param namespace for reaching this node
 * @param public key for this node (used for session negotiation)
 * @param interest template this node should use for reaching the next hop
 *
 * @returns 0 on success, -1 on session failure (node is still node),
 *  other negative if invalid index.
 */

int
andana_path_set_node_session(struct andana_path *path,
                             const size_t index,
                             struct ccn_charbuf *node_uri,
                             struct ccn_pkey *pubkey,
                             struct ccn_charbuf *interest)
{
    if (index >= path->length) {
        return(-__LINE__);
    }

    if (path->nodes[index] != NULL) {
        andana_path_node_destroy(&(path->nodes[index]));
    }

    path->nodes[index] =
        andana_path_node_init_session(node_uri,
                                      pubkey,
                                      interest,
                                      index == path->length - 1);

    if (path->nodes[index] == NULL) {
        return(-1);
    }

    return(0);
}

/**
 * Generate a new ephemeral symmetric key (content encryption)
 * for use by the index'th node
 *
 * @param path with node to be updated
 * @param path index to be updated
 *
 * @returns result of key regen (0)
 */

int
andana_path_replace_symkey(struct andana_path *path, size_t index)
{
    int res;
    if (index >= path->length) {
        return(-__LINE__);
    }

    res = andana_path_node_regen_symkey(path->nodes[index]);

    return(res);
}

/**
 * Convenience function for updating the content encryption
 * keys of all nodes in path
 *
 * @param path to be updated
 * @returns result of key generation (0)
 */

int
andana_path_replace_all_symkeys(struct andana_path *path)
{
    int res = 0;
    size_t i;

    for (i = 0; i < path->length; i++) {
        res |= andana_path_node_regen_symkey(path->nodes[i]);
    }

    return(res);
}

/**
 * This function is used by clients for the initial encryption/encapsulation.
 *
 * Perform interest encryption and encapsulation within
 * a ccn name. The initial interest should be pre-appended
 * to the input name (i.e. ccnx:/foo/<Interest>...</Interest>
 * where foo is the desired final content name/destination).
 *
 * Subsequent interests are specified by the node's template
 * (used for reaching next hop). This template is ignored if
 * node's is_exit is set.
 *
 *
 * @param node with settings for encryption and encapsulation
 * @param name to be encrypted and encapsulated
 * @param indexbuf for input name
 * @param pointer to encrypted & encapsulated name (output)
 * @param pointer to indexbuf for encrypted & encapsulated name (output)
 *
 * @returns negative on failure
 */

int
andana_path_encrypt_encap(struct andana_path *path,
                          struct ccn_charbuf *name,
                          struct ccn_indexbuf *name_comps,
                          struct ccn_charbuf **result_name,
                          struct ccn_indexbuf **result_name_comps)
{
    int res;
    struct ccn_charbuf *tmp_name = NULL;
    struct ccn_indexbuf *tmp_name_comps = NULL;

    int i;
    const size_t path_length = path->length;

    /*
     * Iteratively encrypt and encapsulate the provided data.
     *
     * Path is in ordered from src to dst so it must be walked
     * in reverse for encryption (decryption is forward).
     *
     * Each step produces a valid CCN name that can be fed
     * back in for further processing.
     */

    if (path_length >= 1) {

        if (*result_name_comps == NULL) {
            *result_name_comps = ccn_indexbuf_create();
        }

        res = andana_path_node_encrypt_encap(
            path->nodes[path_length - 1],
            name,
            name_comps,
            result_name,
            result_name_comps);

        tmp_name = *result_name;
        tmp_name_comps = *result_name_comps;
    } else {
        /*
         * TODO Behavior for empty path undefined.
         * May be useful to give user back their name and comps,
         * but would want it to be a deep copy.
         */
        fprintf(stderr,
                "ABORT %d %s undefined behavior: path length is 0\n",
                __LINE__,__func__);
        abort();
    }


    for (i = (int)path_length - 2; i >= 0; i--) {
        *result_name = NULL;
        *result_name_comps = ccn_indexbuf_create();

        res = andana_path_node_encrypt_encap(path->nodes[i],
                                             tmp_name,
                                             tmp_name_comps,
                                             result_name,
                                             result_name_comps);

        ccn_charbuf_destroy(&tmp_name);
        ccn_indexbuf_destroy(&tmp_name_comps);

        tmp_name = *result_name;
        tmp_name_comps = *result_name_comps;
    }

//	if (tmp_name_comps != NULL) {
//		ccn_indexbuf_destroy(&tmp_name_comps);
//	}

    return(res);
}


/**
 * This function is called by clients for the
 * final decryption and decapsulation of returning content objects.
 *
 * Decrypt and decapsulate a provided content object with the specified
 * ephemeral symmetric key.
 *
 * @param node specifying ephemeral symmetric key to use for decrypting this layer
 * @param content object to be decapsulated and decrypted
 * @param length of content object
 * @param parsed content object pointer for manipulating content object (output)
 * @param pointer to decapsulated and decrypted content object (output)
 * @param size of output content object (see previous)
 *
 * @returns 0 on success
 */

int
andana_path_decrypt_decap(struct andana_path *path,
                          void *content_object,
                          size_t length,
                          struct ccn_parsed_ContentObject *pco,
                          unsigned char **content,
                          size_t *content_length)
{
    int res;

    void *tmp_content = NULL;
    size_t tmp_length;

    int i;
    const size_t path_length = path->length;

    /*
     * Iteratively decrypt and decapsulate the provided data.
     *
     * Path is in ordered from src to dst so it must be walked
     * in forward for decrypted (encryption is reverse).
     *
     * Each step produces a valid Content Object that can be fed
     * back in for further processing.
     */

    if (path_length >= 1) {

        res = andana_path_node_decrypt_decap(
            path->nodes[0],
            content_object,
            length,
            pco,
            content,
            content_length);

        tmp_content = *content;
        tmp_length = *content_length;

    } else {
        /*
         * TODO Behavior for empty path undefined.
         * May be useful to give user back their name and comps,
         * but would want it to be a deep copy.
         */
        fprintf(stderr,
                "ABORT %d %s undefined behavior: path length is 0\n",
                __LINE__,__func__);
        abort();
    }


    for (i = 1; i < path_length; i++) {
        struct ccn_parsed_ContentObject new_pco = {0};
        int parse_res = 0;
        parse_res = ccn_parse_ContentObject(tmp_content, tmp_length, &new_pco, NULL);

        if (parse_res < 0) {
            fprintf(stderr, "%d %s Bad content object layer %d\n", __LINE__, __func__, i);
            return(-1);
        }

        res = andana_path_node_decrypt_decap(path->nodes[i],
                                             tmp_content,
                                             tmp_length,
                                             &new_pco,
                                             content,
                                             content_length);

        free(tmp_content);

        tmp_content = *content;
        tmp_length = *content_length;
    }


    return(res);
}

/**
 * Cleanup and destroy the path structure. Triggers
 * destruction of contained nodes.
 *
 * @param pointer to path to be destroyed
 *
 * @returns 0
 */

int
andana_path_destroy(struct andana_path **path)
{
    struct andana_path *p = *path;
    size_t i;

    for (i = 0; i < p->length; i++) {
        andana_path_node_destroy(&(p->nodes[i]));
    }

    free(p->nodes);
    free(p);

    return(0);
}
