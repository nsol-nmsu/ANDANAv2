#include <string.h>

#include <openssl/rsa.h>
#include <openssl/evp.h>

#include <path.h>
#include <ccn/crypto/encryption.h>
#include <ccn/crypto/key.h>

#include <ccn/util/util.h>
#include <andana.h>

struct andana_client {
    struct ccn_proxy *proxy;

    struct andana_path *path;

    struct hashtb *name_to_path;
    struct hashtb_param path_hash_params;

};

/**
 * Finalize function used by hash table to clean up entries.
 *
 * @params e hash table enumerator to be cleaned up
 */

static void
andana_client_finalize(struct hashtb_enumerator *e)
{
    struct andana_path **p = e->data;
    if (p != NULL && *p != NULL) {
        andana_path_destroy(p);
    }
}

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
                       struct andana_path *path)
{
    client->path = andana_path_copy(path);
}

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
                   struct andana_path *path)
{
    struct andana_client *aclient = calloc(1, sizeof(*aclient));
    aclient->proxy = ccn_proxy_client_init(prefix_uri);

    struct ccn_closure *int_handler = calloc(1, sizeof(*int_handler));
    int_handler->p = &andana_client_encap_interest;
    int_handler->data = aclient;

    struct ccn_closure *content_handler = calloc(1, sizeof(*content_handler));
    content_handler->p = &andana_client_decap_content;
    content_handler->data = aclient;

    ccn_proxy_set_handlers(aclient->proxy, int_handler, content_handler);

    aclient->path = andana_path_copy(path);

    aclient->path_hash_params.finalize = &andana_client_finalize;
    aclient->name_to_path = hashtb_create(sizeof(struct ccn_charbuf *), &(aclient->path_hash_params));

    return(aclient);
}

void
andana_client_set_handlers(struct andana_client *client,
                           struct ccn_closure *int_handler,
                           struct ccn_closure *content_handler)
{
    ccn_proxy_set_handlers(client->proxy, int_handler, content_handler);
}

int
andana_client_connect(struct andana_client *client)
{
    return ccn_proxy_connect(client->proxy);
}

int
andana_client_run(struct andana_client *client)
{
    return ccn_proxy_run(client->proxy);
}

/**
 * Encapsulate and encrypt incoming Interest. Supports session-based (symmetric)
 * and asymmetric cryptography. The path structure used for encryption and encapsulation
 * is stored so that paths may be changed at any time.
 *
 */

enum ccn_upcall_res
andana_client_encap_interest(
    struct ccn_closure *selfp,
    enum ccn_upcall_kind kind,
    struct ccn_upcall_info *info)
{
    int res;
    enum ccn_upcall_res upcall_res = CCN_UPCALL_RESULT_ERR;

    struct andana_client *client = selfp->data;
    struct ccn_proxy *proxy = client->proxy;

    size_t orig_name_ncomps;
    struct ccn_charbuf *orig_name = NULL;
    struct ccn_indexbuf *orig_name_comps = NULL;
    struct ccn_charbuf *new_name = NULL;
    struct ccn_indexbuf *new_name_comps = NULL;


    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;

    switch (kind) {
    case CCN_UPCALL_INTEREST:
        DEBUG_PRINT("Received Interest\n");
        break;
    case CCN_UPCALL_FINAL:
        DEBUG_PRINT("Encap: callback final\n");
        return(CCN_UPCALL_RESULT_OK);
    default:
        return(CCN_UPCALL_RESULT_ERR);
    }

    /* Extract Name from Interest */

    orig_name_ncomps = ccn_util_extract_name(info->interest_ccnb,
                                             info->interest_comps,
                                             &orig_name,
                                             &orig_name_comps);


    /*
     * Need to check this Interest doesn't match what we send out.
     * Otherwise, we'll just keep encapsulating the same thing over and over.
     */

    int num_matching_comps =
        ccn_util_name_match(client->proxy->prefix,
                            client->proxy->prefix_comps,
                            orig_name,
                            orig_name_comps);

    if (num_matching_comps == client->proxy->prefix_ncomps) {
        DEBUG_PRINT("Interest matches %d of %d components, ignoring interest\n", num_matching_comps, (int)client->proxy->prefix_ncomps);
#ifdef PROXYDEBUG
	ccn_util_println_pc_fmt(orig_name->buf, orig_name->length);
	DEBUG_PRINT("Name has %lu comps\n", orig_name_comps->n-1);
	ccn_util_println_pc_fmt(client->proxy->prefix->buf, client->proxy->prefix->length);
	DEBUG_PRINT("Name has %lu comps\n", client->proxy->prefix_comps->n-1);
#endif
        goto MatchBail;
    } else {
        DEBUG_PRINT("Interest matches %d of %d components\n", num_matching_comps, (int)client->proxy->prefix_ncomps);
    }


    /* Create a new name encapsulated & encrypted name */

    //	new_name_comps = ccn_indexbuf_create();
    ccn_name_append(orig_name, info->interest_ccnb, info->pi->offset[CCN_PI_E]);
    ccn_indexbuf_destroy(&orig_name_comps);

    struct ccn_buf_decoder decoder;
    struct ccn_buf_decoder *d = &decoder;
    ccn_buf_decoder_start(d, orig_name->buf, orig_name->length);

    orig_name_comps = ccn_indexbuf_create();
    res = ccn_parse_Name(d, orig_name_comps);

    if (res <= 0) {
        DEBUG_PRINT("%d %s error parsing encapsulated name\n",
                    __LINE__, __func__);
        goto MatchBail;
    }

    res = andana_path_encrypt_encap(client->path,
                                    orig_name,
                                    orig_name_comps,
                                    &new_name,
                                    &new_name_comps);

    if (res <= 0) {
        DEBUG_PRINT("%d %s error encapsulating and encrypting name\n",
                    __LINE__, __func__);
        goto EncryptBail;
    }

    /* Remember the new name so we know how to decrypt & decapsulate it later */

    hashtb_start(client->name_to_path, e);
    res = hashtb_seek(e, new_name->buf, new_name->length, 0);

    if (res == HT_NEW_ENTRY) {

    } else if (res == HT_OLD_ENTRY) {
        DEBUG_PRINT("Interest recording found old entry\n");
        upcall_res = CCN_UPCALL_RESULT_OK;
        goto LookupBail;
    } else {
        DEBUG_PRINT("Error in Interest insertion\n");
        goto LookupBail;
    }

    /* Send out new Interest */

#ifdef PROXYDEBUG
    struct ccn_charbuf *c = ccn_charbuf_create();
    ccn_uri_append(c, new_name->buf, new_name->length, 1);
    DEBUG_PRINT("name = %s\n", ccn_charbuf_as_string(c));
    ccn_charbuf_destroy(&c);
#endif
    res = ccn_express_interest(proxy->handle, new_name, proxy->content_handler, NULL);

    if(res != 0) {
        DEBUG_PRINT("express interest res = %d\n",res);
    } else {
        struct andana_path **path_ptr = e->data;
        *path_ptr = andana_path_copy(client->path);

        upcall_res = CCN_UPCALL_RESULT_INTEREST_CONSUMED;
    }



LookupBail:
    hashtb_end(e);

EncryptBail:

    ccn_charbuf_destroy(&new_name);
    ccn_indexbuf_destroy(&new_name_comps);

MatchBail:
    ccn_charbuf_destroy(&orig_name);
    ccn_indexbuf_destroy(&orig_name_comps);

    return(upcall_res);
}

/**
 * Decrypt and decapsulate an incoming content object using
 * pre-arranged symmetric key.
 */

int
andana_client_decap_content(struct ccn_closure *selfp,
                            enum ccn_upcall_kind kind,
                            struct ccn_upcall_info *info)
{
    int res;
    struct andana_client *client = selfp->data;

    struct andana_path **path_ptr;

    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;


    DEBUG_PRINT("Client Content handle called\n");


    switch (kind) {
    case CCN_UPCALL_CONTENT:           /**< incoming verified content */
        DEBUG_PRINT("Incoming verified content\n");
        break;
    case CCN_UPCALL_CONTENT_UNVERIFIED:/**< content that has not been verified */
        DEBUG_PRINT("Incoming unverified content\n");
        break;
    case CCN_UPCALL_CONTENT_BAD:        /**< verification failed */
        DEBUG_PRINT("Incoming bad content (verification failure)\n");
        break;

    case CCN_UPCALL_INTEREST_TIMED_OUT:/**< interest timed out */
    {
        const unsigned char *name = info->interest_ccnb + info->pi->offset[CCN_PI_B_Name];
        const size_t length =  info->pi->offset[CCN_PI_E_Name] - info->pi->offset[CCN_PI_B_Name];
        DEBUG_PRINT("Interest timed out\n");
        hashtb_start(client->name_to_path, e);
        hashtb_seek(e, name, length, 0);
        hashtb_delete(e);
        hashtb_end(e);

        return(CCN_UPCALL_RESULT_ERR);
    }
    case CCN_UPCALL_INTEREST:          /**< incoming interest */
    case CCN_UPCALL_CONSUMED_INTEREST: /**< incoming interest, someone has answered */
    case CCN_UPCALL_FINAL:             /**< handler is about to be deregistered */
    default:
        DEBUG_PRINT("upcall other kind = %d\n", kind);
        return(CCN_UPCALL_RESULT_ERR);
    }


    const unsigned char *content_name = info->content_ccnb + info->pco->offset[CCN_PCO_B_Name];
    const size_t name_length = info->pco->offset[CCN_PCO_E_Name] - info->pco->offset[CCN_PCO_B_Name];
    hashtb_start(client->name_to_path, e);
    res = hashtb_seek(e, content_name, name_length, 0);

    if (res == HT_NEW_ENTRY) {
        DEBUG_PRINT("ABORT %d %s Received unsolicited content?\n", __LINE__, __func__);
        abort();
    } else if (res == HT_OLD_ENTRY) {
        path_ptr = e->data;
        DEBUG_PRINT("Interest recording found old entry\n");
    } else {
        DEBUG_PRINT("Error in Interest insertion\n");
    }
    //	hashtb_end(e);

    /* Inner content object (that we just extracted) should exactly
     * match the original requesting Interest. Decrypted and send it out
     */

    unsigned char *decrypted_content = NULL;
    size_t decrypted_length;

    unsigned char *content_ccnb = calloc(info->pco->offset[CCN_PCO_E], sizeof(unsigned char));
    memcpy(content_ccnb, info->content_ccnb, info->pco->offset[CCN_PCO_E]);

    res = andana_path_decrypt_decap(*path_ptr,
                                    content_ccnb,
                                    info->pco->offset[CCN_PCO_E],
                                    info->pco,
                                    &decrypted_content,
                                    &decrypted_length);

    if (res < 0) {
        hashtb_delete(e);
        hashtb_end(e);
        free(content_ccnb);
        free(decrypted_content);
        return(CCN_UPCALL_RESULT_ERR);
    }


    //	ccn_util_validate_content_object(decrypted_content, decrypted_length);

    res = ccn_put(client->proxy->handle, decrypted_content, decrypted_length);

    if (res < 0) {
        DEBUG_PRINT("Error sending parsed content object\n");
        abort();
    }

    //    andana_path_destroy(path_ptr);
    hashtb_delete(e);
    hashtb_end(e);
    free(content_ccnb);
    free(decrypted_content);
    //	andana_path_destroy(path_ptr);
    return(CCN_UPCALL_RESULT_OK);
}


/**
 * Destroy/clean up anonymous client. Only expect this to be called
 * when the program is done.
 *
 * @param pointer to the anonymous client to be destroyed
 * @returns 0
 */

int
andana_client_destroy(struct andana_client **aclient)
{
    struct andana_client *ac = *aclient;

    ccn_proxy_destroy(&(ac->proxy));
    andana_path_destroy(&(ac->path));
    hashtb_destroy(&(ac->name_to_path));

    free(ac);

    return(0);
}







/**
 * Structure used to remember the agreed upon ephemeral
 * symmetric key for content encryption.
 */

struct andana_server_pair {
    struct ccn_pkey *symkey;
    struct ccn_charbuf *name;
};




struct andana_server {
    struct ccn_proxy *proxy;
    struct ccn_pkey *privkey;

    struct ccn_pkey *node_key;
    struct ccn_closure session_handler;

    size_t SESSION_FLAG;
    size_t SESSION_ENC;
    size_t ENC;

    struct hashtb *session_to_key;
    struct hashtb_param session_hash_params;

    struct hashtb *cname_to_pair;
    struct hashtb_param cname_hash_params;
};



/**
 * Convenience function to create an initialize a pair structure.
 * Used to store name mapping and ephemeral key information for
 * content object encryption.
 *
 * @param original Interest name
 * @param ephemeral symmetric key for encryption
 *
 * @returns new name/key pair
 */

static struct andana_server_pair *
andana_server_pair_init(struct ccn_charbuf *name, struct ccn_pkey *symkey)
{
    struct andana_server_pair *p =
        calloc(1, sizeof(struct andana_server_pair));

    p->name = ccn_charbuf_create();
    ccn_charbuf_append_charbuf(p->name, name);

    p->symkey = ccn_crypto_symkey_copy(symkey);

    return(p);
}

/**
 * Cleanup and destroy pair structure. Called when
 * a content object arrives (no longer need entry), interest times out,
 * or as part of anonymous server cleanup.
 */

static int
andana_server_pair_destroy(struct andana_server_pair **p)
{
    struct andana_server_pair *ap = *p;

    ccn_crypto_symkey_destroy(&(ap->symkey));
    ccn_charbuf_destroy(&(ap->name));
    free(ap);

    return(0);
}


static void
andana_server_finalize(struct hashtb_enumerator *e)
{
    struct andana_server_pair **p = e->data;
    if (p != NULL && *p != NULL) {
        andana_server_pair_destroy(p);
    }
}


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
                   const char *prefix_uri)
{
    struct andana_server *server =
        calloc(1, sizeof(struct andana_server));

    DEBUG_PRINT("%d %s andana_server_init invoked\n", __LINE__, __func__);

    server->proxy = ccn_proxy_init(key_uri, filter_uri, prefix_uri);

    struct ccn_closure *int_handler = calloc(1, sizeof(*int_handler));
    int_handler->p = &andana_server_decap_interest;
    int_handler->data = server;

    struct ccn_closure *content_handler = calloc(1, sizeof(*content_handler));
    content_handler->p = &andana_server_encap_content;
    content_handler->data = server;

    ccn_proxy_set_handlers(server->proxy, int_handler, content_handler);


    server->ENC = server->proxy->prefix_ncomps;
    server->SESSION_FLAG = server->proxy->prefix_ncomps;
    server->SESSION_ENC = server->SESSION_FLAG + 1;


    server->privkey = ccn_crypto_privkey_load_default();
    server->node_key = ccn_crypto_symkey_init(128);

    server->session_hash_params.finalize = &andana_server_finalize;
    server->session_to_key = hashtb_create(sizeof(struct ccn_pkey *), &(server->session_hash_params));

    server->cname_hash_params.finalize = &andana_server_finalize;
    server->cname_to_pair = hashtb_create(sizeof(struct andana_server_pair *), &(server->cname_hash_params));

    return(server);
}

void
andana_server_set_handlers(struct andana_server *server,
                           struct ccn_closure *int_handler,
                           struct ccn_closure *content_handler)
{
    ccn_proxy_set_handlers(server->proxy, int_handler, content_handler);
}



int
andana_server_run(struct andana_server *server)
{
    return ccn_proxy_run(server->proxy);
}

/**
 * Initialize interest/content handlers and connect to underlying
 * ccnd instance.
 *
 * @param anonymous server to configure
 * @returns result of setting interest filter
 */

int
andana_server_connect(struct andana_server *server)
{
    int res;
    res = ccn_proxy_connect(server->proxy);

    if (res != 0) {
        return(res);
    }

    struct ccn_charbuf *session_namespace = ccn_charbuf_create();
    ccn_charbuf_append_charbuf(session_namespace, server->proxy->filter);
    ccn_name_append_str(session_namespace, "CREATESESSION");

    server->session_handler.p = &andana_server_session_listener;
    server->session_handler.data = server;

    res = ccn_set_interest_filter(server->proxy->handle,
                                  session_namespace,
                                  &(server->session_handler));

    ccn_charbuf_destroy(&session_namespace);

    return(res);
}

/**
 * Listener to handle requests to set up new
 * sessions (symmetric encryption only).
 */

enum ccn_upcall_res
andana_server_session_listener(
    struct ccn_closure *selfp,
    enum ccn_upcall_kind kind,
    struct ccn_upcall_info *info)
{
    int res;
    struct andana_server *server = selfp->data;

    const unsigned char * const_encrypted = NULL;
    unsigned char *encrypted = NULL;
    size_t enc_size;

    /*
     * Extract the client's randomness (aka the symmetric key it sent us.
     * Should be the last component of the incoming Interest.
     */

    struct ccn_charbuf *request_name = NULL;
    struct ccn_indexbuf *request_comps = NULL;


    DEBUG_PRINT("IN %d %s\n", __LINE__, __func__);

    switch (kind) {
    case CCN_UPCALL_INTEREST:
        DEBUG_PRINT("%d %s received session request\n", __LINE__, __func__);
        break;
    case CCN_UPCALL_INTEREST_TIMED_OUT:
        DEBUG_PRINT("%d %s received session request time out\n", __LINE__, __func__);
        /* Fall through */
    default:
        DEBUG_PRINT("OUT %d %s\n", __LINE__, __func__);
        return(CCN_UPCALL_RESULT_OK);
    }

    printf("here now mk?\n");

    res = ccn_util_extract_name(info->interest_ccnb, info->interest_comps, &request_name, &request_comps);

    if (res < 0) {
        DEBUG_PRINT("%d %s Failed to extract session request name\n", __LINE__, __func__);
        ccn_charbuf_destroy(&request_name);
        ccn_indexbuf_destroy(&request_comps);
        return(CCN_UPCALL_RESULT_ERR);
    }

    printf("passed util extract name\n");

    res = ccn_name_comp_get(request_name->buf,
                            request_comps,
                            (unsigned int)request_comps->n - 2,
                            &const_encrypted,
                            &enc_size);

    if (res < 0) {
        DEBUG_PRINT("%d %s Failed to extract session creation data\n", __LINE__, __func__);
        ccn_charbuf_destroy(&request_name);
        ccn_indexbuf_destroy(&request_comps);
        return(CCN_UPCALL_RESULT_ERR);
    }


    encrypted = calloc(enc_size, sizeof(unsigned char));

    printf("encryption size = %d\n", enc_size);
    if (encrypted == NULL) printf("invalid pointer return from calloc\n");

    memcpy(encrypted, const_encrypted, enc_size);

    struct ccn_pkey *symkey = NULL;
    struct ccn_charbuf *decrypted = NULL;
    struct ccn_indexbuf *decrypted_comps = ccn_indexbuf_create();

    printf("trying asymmetric decryption\n");

    ccn_crypto_name_asym_decrypt(server->privkey, encrypted, &symkey, &decrypted, &decrypted_comps);
    // ccn_crypto_name_sym_decrypt(server->node_key, encrypted, encrypted_size, &decrypted, &decrypted_comps);

    /*
cn_crypto_name_sym_decrypt(server->node_key,
                                    encrypted,
                                    encrypted_size,
                                    &symkey,
                                    &decrypted,
                                    &decrypted_comps);
    */

    printf("good - now creating a session\n");


    unsigned char *session_id = NULL;
    unsigned char *session_key = NULL;
    unsigned char *server_rand = NULL;

    /*
     * Create a new session id and session key using the client's randomness.
     * The server is also responsible for contributing randomness of its own for security.
     */

    createSession(&session_id,
                  &session_key,
                  &server_rand,
                  ccn_crypto_symkey_key(symkey),
                  (unsigned int)ccn_crypto_symkey_bytes(symkey),
                  ccn_crypto_symkey_key(server->node_key));

    printf("Session made!\n");

    /* Construct the response message using a ccn name (for convenience). */

    struct ccn_charbuf *session_info = ccn_charbuf_create();
    ccn_name_init(session_info);
    ccn_name_append(session_info, session_id, SESSIONID_LENGTH);
    ccn_name_append(session_info, session_key, SESSION_KEYLEN);
    ccn_name_append(session_info, server_rand, SESSIONRAND_LENGTH);

    /**
     * Encrypt the response message using the symmetric key
     * provided by the client and send it out.
     */

    unsigned char *enc_info = NULL;
    ccn_crypto_content_encrypt(symkey, session_info->buf, session_info->length, &enc_info, &enc_size);

    struct ccn_charbuf *signed_enc_info = ccn_charbuf_create();
    struct ccn_signing_params sp = CCN_SIGNING_PARAMS_INIT;
    sp.type = CCN_CONTENT_DATA;


    res = ccn_sign_content(server->proxy->handle,
                           signed_enc_info,
                           request_name,
                           &sp,
                           enc_info,
                           enc_size);

    if (res < 0) {
        DEBUG_PRINT("%d %s Failed to signed session creation response\n", __LINE__, __func__);
    } else {
        res = ccn_put(server->proxy->handle, signed_enc_info->buf, signed_enc_info->length);
    }



    ccn_charbuf_destroy(&decrypted);
    ccn_indexbuf_destroy(&decrypted_comps);
    ccn_crypto_symkey_destroy(&symkey);
    free(session_id);
    free(session_key);
    free(server_rand);
    free(enc_info);
    ccn_charbuf_destroy(&signed_enc_info);

    if (res < 0) {
        DEBUG_PRINT("%d %s Error writing session creation response\n", __LINE__, __func__);
        return(CCN_UPCALL_RESULT_ERR);
    }

    DEBUG_PRINT("OUT %d %s Created new session. Response sent\n", __LINE__, __func__);

    return(CCN_UPCALL_RESULT_INTEREST_CONSUMED);
}

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
andana_server_decap_interest(
    struct ccn_closure *selfp,
    enum ccn_upcall_kind kind,
    struct ccn_upcall_info *info)
{
    enum ccn_upcall_res upcall_res = CCN_UPCALL_RESULT_ERR;
    struct andana_server *server = selfp->data;

    struct ccn_proxy *proxy = server->proxy;

    struct ccn_charbuf *new_interest = NULL;
    struct ccn_charbuf *new_name = NULL;

    struct ccn_charbuf *orig_name = NULL;
    struct ccn_indexbuf *orig_name_indexbuf = NULL;
    int orig_name_ncomps;

    char is_session = 0;

    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;

    int res;


    DEBUG_PRINT("IN %d %s\n", __LINE__, __func__);

    switch (kind) {
    case CCN_UPCALL_INTEREST:
        DEBUG_PRINT("%d %s received interest\n", __LINE__, __func__);
        break;
    case CCN_UPCALL_INTEREST_TIMED_OUT:
        DEBUG_PRINT("%d %s received interest time out\n", __LINE__, __func__);
        /* Fall through */
    default:
        DEBUG_PRINT("OUT %d %s\n", __LINE__, __func__);
        return(CCN_UPCALL_RESULT_OK);
    }


    /* Extract Name from Interest */

    orig_name_ncomps = ccn_util_extract_name(info->interest_ccnb,
                                             info->interest_comps,
                                             &orig_name,
                                             &orig_name_indexbuf);

#ifdef PROXYDEBUG
    ccn_util_print_pc_fmt(orig_name->buf, orig_name->length);
    DEBUG_PRINT("\n");

    DEBUG_PRINT("Name has %lu comps\n", orig_name_indexbuf->n-1);
#endif

    /*Decapsulate & decrypt Interest. */


    const unsigned char *const_encrypted = NULL;
    unsigned char *encrypted = NULL;
    size_t encrypted_size;

    if (orig_name_ncomps >= 2) {
        const unsigned char *session_check = NULL;
        size_t session_check_size;

        res = ccn_name_comp_get(orig_name->buf,
				orig_name_indexbuf,
				(unsigned int)server->SESSION_FLAG,
				&session_check,
				&session_check_size);

        if (res < 0) {
            DEBUG_PRINT("%d %s Error extracting session check component %lu\n", __LINE__, __func__, server->SESSION_FLAG);
            goto SessionFail;
        } else {
            DEBUG_PRINT("%d %s Extracted component %lu\n", __LINE__, __func__,server->SESSION_FLAG);
        }

        if (session_check_size == strlen("SESSION") &&
            memcmp(session_check, "SESSION", session_check_size) == 0) {

            DEBUG_PRINT("%d %s Session identified\n", __LINE__, __func__);
            is_session = 1;

        } else {
            DEBUG_PRINT("%d %s Not a session\n", __LINE__, __func__);
        }
    }



    /* Decrypt the name (contains a new name and an Interest template) */

    struct ccn_pkey *symkey = NULL;
    struct ccn_charbuf *decrypted = NULL;
    struct ccn_indexbuf *decrypted_comps = ccn_indexbuf_create();

    if (is_session) {

        res = ccn_name_comp_get(orig_name->buf,
				orig_name_indexbuf,
				(unsigned int)server->SESSION_ENC,
				&const_encrypted,
				&encrypted_size);

        if (res < 0) {
            DEBUG_PRINT("%d %s Error extracting encrypted session component %lu\n", __LINE__, __func__, server->SESSION_ENC);
            goto SessionParseFail;
        } else {
            DEBUG_PRINT("%d %s Extracted encrypted session component  %lu\n", __LINE__, __func__, server->SESSION_ENC);
        }

        encrypted = calloc(encrypted_size, sizeof(unsigned char));
        memcpy(encrypted, const_encrypted, encrypted_size);

        ccn_crypto_name_sym_decrypt(server->node_key,
                                    encrypted,
                                    encrypted_size,
                                    &symkey,
                                    &decrypted,
                                    &decrypted_comps);
    } else {

        ccn_name_comp_get(orig_name->buf, orig_name_indexbuf, (unsigned int)server->ENC, &const_encrypted, &encrypted_size);
        encrypted = calloc(encrypted_size, sizeof(unsigned char));
        memcpy(encrypted, const_encrypted, encrypted_size);

        ccn_crypto_name_asym_decrypt(server->privkey,
                                     encrypted,
                                     &symkey,
                                     &decrypted,
                                     &decrypted_comps);
    }

    size_t ncomps = decrypted_comps->n-1;
    const unsigned char *tmpl = NULL;
    size_t tmpl_size;

    res = ccn_name_comp_get(decrypted->buf, decrypted_comps, (unsigned int)ncomps - 1, &tmpl, &tmpl_size);

    if (res < 0) {
        DEBUG_PRINT("ABORT %d %s unable to retrieve component %d\n",
                    __LINE__, __func__, (int)ncomps);
        goto CompExtractFail;
    }

    /* Pull timestamp component (comp 0) */
    const unsigned char *ts_data = NULL;
    size_t ts_size;
    res = ccn_name_comp_get(decrypted->buf, decrypted_comps, 0, &ts_data, &ts_size);

    if (res < 0) {
        goto CompExtractFail;
    }

    struct timeval timestamp;
    ccn_util_extract_timestamp(ts_data, ts_size, &timestamp);

    struct timeval window = {.tv_sec = 1, .tv_usec = 600000};

    if (ccn_util_timestamp_window(&timestamp, &window) == 0) {
        /* Timestamp too far away, this may be a replay attack */
        DEBUG_PRINT("%d %s Timestamp too distant\n", __LINE__, __func__);
        goto TimestampFail;
    }

    new_name = ccn_charbuf_create();
    ccn_name_init(new_name);


    res = ccn_name_append_components(new_name,
                                     decrypted->buf,
                                     decrypted_comps->buf[1],
                                     decrypted_comps->buf[ncomps-1]);

    if (res < 0) {
        DEBUG_PRINT("ABORT %d %s unable to append components\n",
                    __LINE__, __func__);
        goto AppendCompFail;
    }


    /*Construct new Interest*/

    if (tmpl_size == 0) {
        /* Detected default template */
        DEBUG_PRINT("%d %s Using default Interest template\n", __LINE__, __func__);
        new_interest = NULL;
    } else {
        DEBUG_PRINT("%d %s Copying Interest template\n", __LINE__, __func__);
        new_interest = ccn_charbuf_create();
        ccn_charbuf_append(new_interest, tmpl, tmpl_size);
    }

    /*Map new name to that of the original Interest and the requested symkey */

    hashtb_start(server->cname_to_pair, e);
    res = hashtb_seek(e, new_name->buf, new_name->length, 0);

    if (res == HT_NEW_ENTRY) {
        struct andana_server_pair *p = andana_server_pair_init(orig_name, symkey);
        struct andana_server_pair **loc = e->data;
        *loc = p;
    } else if (res == HT_OLD_ENTRY) {
        DEBUG_PRINT("Interest recording found old entry\n");
        goto LookupFail;
    } else {
        DEBUG_PRINT("Error in Interest insertion\n");
        goto LookupFail;
    }





    DEBUG_PRINT("%d %s starting to write new interest\n", __LINE__, __func__);

    res = ccn_express_interest(proxy->handle, new_name, proxy->content_handler, new_interest);

    DEBUG_PRINT("%d %s done to writing new interest\n", __LINE__, __func__);

    if(res != 0) {
        DEBUG_PRINT("ABORT %d %s express interest res = %d\n", __LINE__, __func__, res);
        goto SendFail;
    }

    upcall_res = CCN_UPCALL_RESULT_OK;


SendFail:
LookupFail:

    if (upcall_res == CCN_UPCALL_RESULT_ERR) {
        hashtb_delete(e);
    }

    hashtb_end(e);

    if (new_interest != NULL) {
        ccn_charbuf_destroy(&new_interest);
    }

TimestampFail:
AppendCompFail:
    ccn_charbuf_destroy(&new_name);

CompExtractFail:
    ccn_charbuf_destroy(&decrypted);
    free(encrypted);
    ccn_crypto_symkey_destroy(&symkey);

SessionParseFail:
    ccn_indexbuf_destroy(&decrypted_comps);

SessionFail:
    ccn_charbuf_destroy(&orig_name);
    ccn_indexbuf_destroy(&orig_name_indexbuf);

    DEBUG_PRINT("OUT %d %s\n", __LINE__, __func__);

    return(upcall_res);
}

/**
 * Encapsulate and encrypt returning content objects. Encryption
 * uses the ephemeral symmetric key provided by the user in the original
 * interest (stored in a pair).
 *
 * This node will naturally sign the outgoing content object, thus providing
 * verifiability.
 */

enum ccn_upcall_res
andana_server_encap_content(
    struct ccn_closure *selfp,
    enum ccn_upcall_kind kind,
    struct ccn_upcall_info *info)
{
    enum ccn_upcall_res upcall_res = CCN_UPCALL_RESULT_ERR;
    struct andana_server *server = selfp->data;
    struct ccn_proxy *proxy = server->proxy;

    struct ccn_charbuf *new_name = NULL;
    struct andana_server_pair **pair_ptr = NULL;
    struct ccn_charbuf *new_content = NULL;
    struct ccn_signing_params sp = CCN_SIGNING_PARAMS_INIT;

    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;

    int res;

    DEBUG_PRINT("IN %d %s\n",__LINE__, __func__);

    switch (kind) {
    case CCN_UPCALL_CONTENT:           /**< incoming verified content */
        DEBUG_PRINT("%d %s Incoming verified content\n",__LINE__, __func__);
        break;
    case CCN_UPCALL_CONTENT_UNVERIFIED:/**< content that has not been verified */
        DEBUG_PRINT("%d %s Incoming unverified content\n", __LINE__, __func__);
        break;
    case CCN_UPCALL_CONTENT_BAD:        /**< verification failed */
        DEBUG_PRINT("%d %s Incoming bad content (verification failure)\n", __LINE__, __func__);
        break;

    case CCN_UPCALL_INTEREST_TIMED_OUT:/**< interest timed out */
    {
        DEBUG_PRINT("OUT %d %s Interest timed out\n", __LINE__, __func__);

        const unsigned char *name = info->interest_ccnb + info->pi->offset[CCN_PI_B_Name];
        const size_t length =  info->pi->offset[CCN_PI_E_Name] - info->pi->offset[CCN_PI_B_Name];

        hashtb_start(server->cname_to_pair, e);
        hashtb_seek(e, name, length, 0);
        hashtb_delete(e);
        hashtb_end(e);

        return(CCN_UPCALL_RESULT_OK);
    }
    case CCN_UPCALL_FINAL:/**< handler is about to be deregistered */
        DEBUG_PRINT("OUT %d %s final upcall\n", __LINE__, __func__);
        return(CCN_UPCALL_RESULT_OK);

    case CCN_UPCALL_INTEREST:          /**< incoming interest */
    case CCN_UPCALL_CONSUMED_INTEREST: /**< incoming interest, someone has answered */
    default:
        DEBUG_PRINT("OUT %d %s upcall other kind = %d\n", __LINE__, __func__, kind);
        return(CCN_UPCALL_RESULT_ERR);
    }



    DEBUG_PRINT("%d %s Received content object\n", __LINE__, __func__);

    if (info->content_ccnb == NULL) {
        DEBUG_PRINT("OUT %d %s in content upcall, but no content, check kind: %d\n", __LINE__, __func__, kind);
        return(CCN_UPCALL_RESULT_OK);
    }

    /*Find name in Content Object*/

    new_name = ccn_charbuf_create();
    ccn_name_init(new_name);
    ccn_name_append_components(new_name, info->content_ccnb,
                               info->content_comps->buf[0], info->content_comps->buf[info->matched_comps]);

#ifdef PROXYDEBUG
    DEBUG_PRINT("name matches %d comps\n", info->matched_comps);
    ccn_util_print_pc_fmt(info->content_ccnb + info->pco->offset[CCN_PCO_B_Name],
                          info->pco->offset[CCN_PCO_E_Name] - info->pco->offset[CCN_PCO_B_Name]);
    DEBUG_PRINT("\n");
#endif

    pair_ptr = hashtb_lookup(server->cname_to_pair, new_name->buf, new_name->length);

    if(pair_ptr == NULL) {
        /* No match for name*/
#ifdef PROXYDEBUG
        DEBUG_PRINT("Unsolicited content object with name: ");
        ccn_util_print_pc_fmt(new_name->buf, new_name->length);
        DEBUG_PRINT("\n");
#endif
        goto LookupFail;
    }

    struct ccn_charbuf *orig_name = (*pair_ptr)->name;
    struct ccn_pkey *symkey = (*pair_ptr)->symkey;






    /*Created signed info for new content object*/
    unsigned char *encrypted_content = NULL;
    size_t encrypted_length;

    struct ccn_charbuf *content = ccn_charbuf_create();
    ccn_charbuf_append(content, info->content_ccnb, info->pco->offset[CCN_PCO_E]);

    ccn_crypto_content_encrypt(symkey, content->buf, content->length, &encrypted_content, &encrypted_length);

    new_content = ccn_charbuf_create();
    sp.type = CCN_CONTENT_DATA;

    res = ccn_sign_content(proxy->handle,
                           new_content,
                           orig_name,
                           &sp,
                           encrypted_content,
                           encrypted_length);


    if (ccn_util_validate_content_object(new_content->buf, new_content->length) != 0) {
        DEBUG_PRINT("ABORT %d %s Failed to validated signed content\n", __LINE__, __func__);
        abort();
        goto SignFail;
    } else {
        DEBUG_PRINT("OK %d %s signed content is valid\n", __LINE__, __func__);
    }


    if (res != 0) {
        DEBUG_PRINT("ABORT %d %s Failed to encode ContentObject (res == %d)\n", __LINE__, __func__, res);
        goto SignFail;
    }

    DEBUG_PRINT("%d %s starting content write\n", __LINE__, __func__);

    res = ccn_put(proxy->handle, new_content->buf, new_content->length);

    DEBUG_PRINT("%d %s done content write line\n", __LINE__, __func__);

    if (res < 0) {
        DEBUG_PRINT("ABORT %d %s ccn_put failed (res == %d)\n", __LINE__, __func__, res);
        goto SendFail;
    }

    DEBUG_PRINT("%d %s Reply sent\n", __LINE__, __func__);
    upcall_res = CCN_UPCALL_RESULT_OK;


SendFail:
    hashtb_start(server->cname_to_pair, e);
    hashtb_seek(e, new_name->buf, new_name->length, 0);
    hashtb_delete(e);
    hashtb_end(e);



SignFail:
    ccn_charbuf_destroy(&new_content);
    free(encrypted_content);
    ccn_charbuf_destroy(&content);

LookupFail:
    ccn_charbuf_destroy(&new_name);

    DEBUG_PRINT("OUT %d %s\n", __LINE__, __func__);

    return(upcall_res);
}


/**
 * Clean up and destroy anonymous server object. Expect
 * to be called once at program close.
 *
 * @param pointer to anonymous server to be destroyed
 * @returns 0 (always)
 */

int
andana_server_destroy(struct andana_server **server)
{
    struct andana_server *s = *server;

    free(s->proxy->int_handler);
    free(s->proxy->content_handler);
    ccn_proxy_destroy(&(s->proxy));
    ccn_crypto_pubkey_destroy(&(s->privkey));
    hashtb_destroy(&(s->cname_to_pair));
    free(s);

    return(0);
}
