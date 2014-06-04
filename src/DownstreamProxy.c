#include "DownstreamProxy.h"
#include "CryptoWrapper.h"
#include "Util.h"
#include "Config.h"

DownstreamProxy* ProxySessionInit(Config* config, struct ccn_charbuf *uri, struct ccn_pkey *pubkey, struct ccn_charbuf *interest_template, int is_exit)
{   
    char bail = 0;
    int res = 0;

    Proxy* baseNode = InitProxyBase(uri, pubkey, interest_template, is_exit);
    DownstreamProxy* node = (DownstreamProxy*)malloc(sizeof(DownstreamProxy));
    node->sessionTable = (ProxySessionTable*)malloc(sizeof(ProxySessionTable));
    node->config = (Config*)malloc(sizeof(Config));
    node->baseProxy = (Proxy*)malloc(sizeof(Proxy));
    memcpy((void*)node->baseProxy, (void*)baseNode, sizeof(Proxy));

    if (node == NULL) 
    {
        DEBUG_PRINT("%d %s Basic node setup failure\n", __LINE__, __func__);
        return NULL;
    }

    // Save the configuration struct
    DEBUG_PRINT("Continuing with node setup\n");
    memcpy(node->config, config, sizeof(Config));

    // Perform circuit establishment handshake, if specified in the config struct
    if (config->circuit_creation == CIRCUIT_CREATION_HANDSHAKE)
    {
        DEBUG_PRINT("Connecting a session\n");

        struct ccn *sessionh = ccn_create();
        if (sessionh == NULL)
        {
            fprintf(stderr, "%d %s Failed to create new session.\n", __LINE__, __func__);
            return NULL;
        }
        res = ccn_connect(sessionh, NULL);
        if (res == -1) 
        {
            fprintf(stderr, "%d %s Unable to create session. Failed to connect to ccnd\n", __LINE__, __func__);
            return NULL;
        }

        DEBUG_PRINT("Starting session establishment\n");

        // Craft a special name to request a session from the specified proxy. 
        struct ccn_charbuf *int_name = ccn_charbuf_create();
        ccn_charbuf_append_charbuf(int_name, uri);
        ccn_name_append_str(int_name, "CREATESESSION");

        DEBUG_PRINT("Creating state information: %s\n", uri);

        // Create the session state information (on the client side, obviously)
        unsigned char encryption_key[KEYLEN];
        memset(encryption_key, 0, KEYLEN);
        unsigned char mac_key[MACKLEN];
        memset(mac_key, 0, MACKLEN);
        unsigned char counter_iv[SHA256_DIGEST_LENGTH];
        memset(counter_iv, 0, SHA256_DIGEST_LENGTH);
        unsigned char session_iv[SHA256_DIGEST_LENGTH];
        memset(session_iv, 0, SHA256_DIGEST_LENGTH);
        unsigned char session_id[SHA256_DIGEST_LENGTH];
        memset(session_id, 0, SHA256_DIGEST_LENGTH);
        unsigned char session_index[SHA256_DIGEST_LENGTH];
        memset(session_index, 0, SHA256_DIGEST_LENGTH);

        // Populate everything with some random bytes
        if(!RandomBytes(encryption_key, KEYLEN)) return NULL;
        if(!RandomBytes(mac_key, MACKLEN)) return NULL;
        if(!RandomBytes(counter_iv, SHA256_DIGEST_LENGTH)) return NULL;
        if(!RandomBytes(session_iv, SHA256_DIGEST_LENGTH)) return NULL;

        // The session ID is the hash of some fresh randomness
        unsigned char randomness[SHA256_DIGEST_LENGTH];
        if(!RandomBytes(randomness, SHA256_DIGEST_LENGTH))
        {
            return NULL;
        }

        // Generate the session - hash of the randomness
        SHA256(session_id, SHA256_DIGEST_LENGTH, randomness);

        // Lastly, generate the session index
        unsigned char tempBuffer[SHA256_DIGEST_LENGTH + SHA256_DIGEST_LENGTH];
        memcpy(tempBuffer, session_id, SHA256_DIGEST_LENGTH);
        memcpy(tempBuffer + SHA256_DIGEST_LENGTH, session_iv, SHA256_DIGEST_LENGTH);
        SHA256(session_index, SHA256_DIGEST_LENGTH + SHA256_DIGEST_LENGTH, tempBuffer);

        DEBUG_PRINT("Storing state in local state table\n");

        // Persist the state information in the node
        ProxySessionTableEntry* stateEntry = (ProxySessionTableEntry*)malloc(sizeof(ProxySessionTableEntry));
        memcpy(stateEntry->encryption_key, encryption_key, KEYLEN);
        memcpy(stateEntry->mac_key, mac_key, MACKLEN);
        memcpy(stateEntry->counter_iv, counter_iv, SHA256_DIGEST_LENGTH);
        memcpy(stateEntry->session_iv, session_iv, SHA256_DIGEST_LENGTH);
        memcpy(stateEntry->session_id, session_id, SHA256_DIGEST_LENGTH);
        // memcpy(stateEntry->session_index, session_index, SHA256_DIGEST_LENGTH);
        stateEntry->nonce = 0xDEADBEEF; // for debugging purposes
        node->stateTable = (ProxyStateTable*)malloc(sizeof(ProxyStateTable));
        node->stateTable->head = NULL;
        node->upstreamStateTable = (UpstreamProxyStateTable*)malloc(sizeof(UpstreamProxyStateTable));
        node->upstreamStateTable->head = NULL;
        node->sessionTable = (ProxySessionTable*)malloc(sizeof(ProxySessionTable));
        node->sessionTable->head = NULL;

        // Use the session ID to recreate the initial rand_seed for encryption/decryption
        RandomSeed(session_id, SHA256_DIGEST_LENGTH);
        RandomBytes(stateEntry->rand_seed, SHA256_DIGEST_LENGTH);

        DEBUG_PRINT("Appending new state table entry\n");
        AddStateEntry(node->sessionTable, stateEntry);

        // Total length of the payload
        unsigned payloadSize = KEYLEN + MACKLEN + SHA256_DIGEST_LENGTH + SHA256_DIGEST_LENGTH + SHA256_DIGEST_LENGTH + SHA256_DIGEST_LENGTH;

        DEBUG_PRINT("Packing the interest\n");

        // Pack in the state information
        // struct ccn_charbuf *encryption_key_payload = ccn_charbuf_create();
        // ccn_name_init(encryption_key_payload);
        ccn_name_append(int_name, encryption_key, KEYLEN);

        // struct ccn_charbuf *mac_key_payload = ccn_charbuf_create();
        // ccn_name_init(mac_key_payload);
        ccn_name_append(int_name, mac_key, MACKLEN);

        // struct ccn_charbuf *counter_iv_payload = ccn_charbuf_create();
        // ccn_name_init(counter_iv_payload);
        ccn_name_append(int_name, counter_iv, SHA256_DIGEST_LENGTH);

        // struct ccn_charbuf *session_iv_payload = ccn_charbuf_create();
        // ccn_name_init(session_iv_payload);
        ccn_name_append(int_name, session_iv, SHA256_DIGEST_LENGTH);

        // struct ccn_charbuf *session_id_payload = ccn_charbuf_create();
        // ccn_name_init(session_id_payload);
        ccn_name_append(int_name, session_id, SHA256_DIGEST_LENGTH);

        // struct ccn_charbuf *session_index_payload = ccn_charbuf_create();
        // ccn_name_init(session_index_payload);
        // ccn_name_append(int_name, session_index, SHA256_DIGEST_LENGTH);

        // struct ccn_charbuf *nonce_payload = ccn_charbuf_create();
        // ccn_name_init(nonce_payload);
        ccn_name_append(int_name, &(stateEntry->nonce), sizeof(unsigned int));

        // Send the interest out and wait for the response
        DEBUG_PRINT("Sending nonce: %x\n", stateEntry->nonce);
        struct ccn_parsed_ContentObject response_pco = { 0, 0, 0, 0, 0, 0, 0, 0 };
        struct ccn_charbuf *response = ccn_charbuf_create();
        struct ccn_indexbuf *response_comps = ccn_indexbuf_create();
        res = ccn_get(sessionh, int_name, NULL, 3000, response, &response_pco, response_comps, 0);
        if (res < 0) 
        {
            fprintf(stderr, "%d %s Unable to create new session\n", __LINE__,__func__);
            return NULL;
        }

        const unsigned char *const_payload = NULL;
        unsigned char *payload = NULL;
        size_t payload_length;

        DEBUG_PRINT("Trying to recover the content object\n");
        res = ccn_content_get_value(response->buf, response->length, &response_pco, &const_payload, &payload_length);

        // Verify the the ack'd message was correct
        if (payload_length != sizeof(unsigned int)) 
        {
            fprintf(stderr, "%d %s differing session id sizes: got %lu expected %d\n", __LINE__, __func__, payload_length, SHA256_DIGEST_LENGTH);
            return NULL;
        }

        // Store a local copy of the response payload
        payload = calloc(payload_length, sizeof(unsigned char));
        memcpy(payload, const_payload, payload_length);

        DEBUG_PRINT("Trying to parse the returned response of length: %lu\n", payload_length);

        unsigned int nonce_ack = 0;
        memcpy(&nonce_ack, payload, sizeof(unsigned int));
        DEBUG_PRINT("Retrieved nonce: %x\n", nonce_ack);

        // if (memcmp(payload, session_index, sizeof(unsigned int)) != 0)
        // {
        //     fprintf(stderr, "%d %s invalid session index ACK'd back\n", __LINE__, __func__);
        //     bail = 1;
        //     return NULL;
        // }

        DEBUG_PRINT("Session created successfully.\n");
    }
    else if (config->circuit_creation == CIRCUIT_CREATION_PIGGYBACK)
    {
        DEBUG_PRINT("CIRCUIT_CREATION_PIGGYBACK - no interests to be sent in this case.\n");
    }

    return node;
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
DownstreamProxy* DownstreamProxyInit(const char *key_uri, const char *filter_uri, const char *prefix_uri)
{
    DownstreamProxy *server = (DownstreamProxy*)malloc(sizeof(DownstreamProxy));
    server->stateTable = (ProxyStateTable*)malloc(sizeof(ProxyStateTable));
    server->sessionTable = (ProxySessionTable*)malloc(sizeof(ProxySessionTable));
    server->sessionTable->head = NULL;

    DEBUG_PRINT("%d %s DownstreamProxyInit invoked\n", __LINE__, __func__);

    // Initialize the proxy
    server->baseProxy = InitProxy(key_uri, filter_uri, prefix_uri);

    // Create the interest handler
    struct ccn_closure *int_handler = calloc(1, sizeof(*int_handler));
    int_handler->p = &UnwrapInterest;
    int_handler->data = server;

    // Create the content handler
    struct ccn_closure *content_handler = calloc(1, sizeof(*content_handler));
    content_handler->p = &WrapContent;
    content_handler->data = server;

    DEBUG_PRINT("Setting server handlers\n");

    // Fix the handlers
    ccn_proxy_set_handlers(server->baseProxy, int_handler, content_handler);

    DEBUG_PRINT("%d %s DownstreamProxyInit complete\n", __LINE__, __func__);

    return server;
}

/** 
 * Set the interest and content handlers.
 *
 * @param server - the producer server to configure.
 * @param int_handler - pointer to the interest handler.
 * @param content_handler - pointer to the content handler.
 */
void DownstreamProxySetHandlers(DownstreamProxy* server, struct ccn_closure *int_handler, struct ccn_closure *content_handler)
{
    server->baseProxy->int_handler = int_handler;
    server->baseProxy->content_handler = content_handler;
}

/** 
 * Run the producer server proxy.
 *
 * @param server - the producer server to run.
 */
int DownstreamRun(DownstreamProxy* server)
{
    Proxy* proxy = server->baseProxy;
    DEBUG_PRINT("IN %d %s\n", __LINE__, __func__);

    if (ccn_run(proxy->handle, -1) < 0) 
    {
        DEBUG_PRINT("ccn_run error: %d\n", ccn_geterror(proxy->handle));
        DEBUG_PRINT("%d %s error running %s handle\n", __LINE__, __func__, proxy->handle_name->buf);
        return -1;
    }

    DEBUG_PRINT("OUT %d %s\n", __LINE__, __func__);
    return 0;
}

/**
 * Initialize interest/content handlers and connect to underlying
 * ccnd instance.
 *
 * @param anonymous server to configure.
 * @returns result of setting interest filter
 */
int DownstreamConnect(DownstreamProxy* server)
{
    int res;
    res = ProxyConnect(server->baseProxy);

    if (res != 0) 
    {
        return res;
    }

    // Create a listener for sessions
    struct ccn_charbuf *session_namespace = ccn_charbuf_create();
    ccn_charbuf_append_charbuf(session_namespace, server->baseProxy->filter);
    ccn_name_append_str(session_namespace, "CREATESESSION");

    // Hook up the session listener
    DEBUG_PRINT("Hooking up session listener: %s\n", server->baseProxy->filter);
    server->session_handler.p = &DownstreamSessionListener;
    server->session_handler.data = server;
    res = ccn_set_interest_filter(server->baseProxy->handle, session_namespace, &(server->session_handler));

    // Free up the memory
    ccn_charbuf_destroy(&session_namespace);

    return res;
}

/**
 * Listener to handle requests to set up new sessions (symmetric encryption only).
 */
enum ccn_upcall_res DownstreamSessionListener(struct ccn_closure *selfp, enum ccn_upcall_kind kind, struct ccn_upcall_info *info)
{
    int res;
    unsigned char* compBuffer = NULL;
    struct ccn_charbuf* request_name = NULL;
    struct ccn_indexbuf* request_comps = NULL;
    size_t compSize;

    // Extract the server ref
    DownstreamProxy *server = selfp->data;

    DEBUG_PRINT("IN DownstreamSessionListener %d %s\n", __LINE__, __func__);

    switch (kind) 
    {
        case CCN_UPCALL_INTEREST:
            DEBUG_PRINT("%d %s received session request\n", __LINE__, __func__);
            break;
        case CCN_UPCALL_INTEREST_TIMED_OUT:
            DEBUG_PRINT("%d %s received session request time out\n", __LINE__, __func__);
            /* Fall through */
        default:
            DEBUG_PRINT("OUT %d %s\n", __LINE__, __func__);
            return CCN_UPCALL_RESULT_OK;
    }

    DEBUG_PRINT("Server received an interest - extracting the session information.\n");

    // Allocate space for the state/session tables
    // sessionEntry = (ProxySessionTableEntry*)malloc(sizeof(ProxySessionTableEntry));
    ProxySessionTableEntry* sessionEntry = AllocateNewSessionEntry(server->sessionTable);
    DEBUG_PRINT("Done.\n");

    // Extract the name and components
    res = ccn_util_extract_name(info->interest_ccnb, info->interest_comps, &request_name, &request_comps);
    if (res < 0)
    {
        DEBUG_PRINT("%d %s Failed to extract interest name\n", __LINE__, __func__);   
        return CCN_UPCALL_RESULT_ERR;
    }

    DEBUG_PRINT("Successfully extracted the name.\n");
    DEBUG_PRINT("Number of components = %d\n", request_comps->n);
    res = ccn_name_comp_get(request_name->buf, request_comps, (unsigned int)request_comps->n - 2, &compBuffer, &compSize);
    if (res < 0)
    {
        DEBUG_PRINT("%d %s Failed to extract session creation data\n", __LINE__, __func__);
        ccn_charbuf_destroy(&request_name);
        ccn_indexbuf_destroy(&request_comps);
        return CCN_UPCALL_RESULT_ERR;
    }

    // Create the session state information (on the client side, obviously)
    unsigned char encryption_key[KEYLEN];
    memset(encryption_key, 0, KEYLEN);
    unsigned char mac_key[MACKLEN];
    memset(mac_key, 0, MACKLEN);
    unsigned char counter_iv[SHA256_DIGEST_LENGTH];
    memset(counter_iv, 0, SHA256_DIGEST_LENGTH);
    unsigned char session_iv[SHA256_DIGEST_LENGTH];
    memset(session_iv, 0, SHA256_DIGEST_LENGTH);
    unsigned char session_id[SHA256_DIGEST_LENGTH];
    memset(session_id, 0, SHA256_DIGEST_LENGTH);
    unsigned char session_index[SHA256_DIGEST_LENGTH];
    memset(session_index, 0, SHA256_DIGEST_LENGTH);

    // Recover the session information...
    res = ccn_name_comp_get(request_name->buf, request_comps, (unsigned int)request_comps->n - 7, &compBuffer, &compSize);
    if (res < 0) 
    {
        DEBUG_PRINT("%d %s Failed to extract session creation data\n", __LINE__, __func__);
        ccn_charbuf_destroy(&request_name);
        ccn_indexbuf_destroy(&request_comps);
        return CCN_UPCALL_RESULT_ERR;
    }
    // memcpy(encryption_key, compBuffer, KEYLEN);
    memcpy(sessionEntry->encryption_key, compBuffer, KEYLEN);

    res = ccn_name_comp_get(request_name->buf, request_comps, (unsigned int)request_comps->n - 6, &compBuffer, &compSize);
    if (res < 0) 
    {
        DEBUG_PRINT("%d %s Failed to extract session creation data\n", __LINE__, __func__);
        ccn_charbuf_destroy(&request_name);
        ccn_indexbuf_destroy(&request_comps);
        return CCN_UPCALL_RESULT_ERR;
    }
    // memcpy(mac_key, compBuffer, KEYLEN);
    memcpy(sessionEntry->mac_key, compBuffer, KEYLEN);

    res = ccn_name_comp_get(request_name->buf, request_comps, (unsigned int)request_comps->n - 5, &compBuffer, &compSize);
    if (res < 0) 
    {
        DEBUG_PRINT("%d %s Failed to extract session creation data\n", __LINE__, __func__);
        ccn_charbuf_destroy(&request_name);
        ccn_indexbuf_destroy(&request_comps);
        return CCN_UPCALL_RESULT_ERR;
    }
    // memcpy(counter_iv, compBuffer, SHA256_DIGEST_LENGTH);
    memcpy(sessionEntry->counter_iv, compBuffer, SHA256_DIGEST_LENGTH);

    res = ccn_name_comp_get(request_name->buf, request_comps, (unsigned int)request_comps->n - 4, &compBuffer, &compSize);
    if (res < 0) 
    {
        DEBUG_PRINT("%d %s Failed to extract session creation data\n", __LINE__, __func__);
        ccn_charbuf_destroy(&request_name);
        ccn_indexbuf_destroy(&request_comps);
        return CCN_UPCALL_RESULT_ERR;
    }
    // memcpy(session_iv, compBuffer, SHA256_DIGEST_LENGTH);
    memcpy(sessionEntry->session_iv, compBuffer, SHA256_DIGEST_LENGTH);

    res = ccn_name_comp_get(request_name->buf, request_comps, (unsigned int)request_comps->n - 3, &compBuffer, &compSize);
    if (res < 0) 
    {
        DEBUG_PRINT("%d %s Failed to extract session creation data\n", __LINE__, __func__);
        ccn_charbuf_destroy(&request_name);
        ccn_indexbuf_destroy(&request_comps);
        return CCN_UPCALL_RESULT_ERR;
    }
    // memcpy(session_id, compBuffer, SHA256_DIGEST_LENGTH);
    memcpy(sessionEntry->session_id, compBuffer, SHA256_DIGEST_LENGTH);

    // res = ccn_name_comp_get(request_name->buf, request_comps, (unsigned int)request_comps->n - 3, &compBuffer, &compSize);
    // if (res < 0) 
    // {
    //     DEBUG_PRINT("%d %s Failed to extract session creation data\n", __LINE__, __func__);
    //     ccn_charbuf_destroy(&request_name);
    //     ccn_indexbuf_destroy(&request_comps);
    //     return CCN_UPCALL_RESULT_ERR;
    // }
    // memcpy(session_index, compBuffer, SHA256_DIGEST_LENGTH);

    // Compute the initial session index
    BOB bob;
    bob.blob = (uint8_t*)malloc(SHA256_DIGEST_LENGTH * sizeof(uint8_t));
    bob.len = SHA256_DIGEST_LENGTH;
    XOR(session_id, session_iv, bob.blob, bob.len);
    BOB* out;
    res = Hash(&out, bob.blob, bob.len);
    if (res < 0)
    {
        DEBUG_PRINT("Failed to create the session index\n");
        return CCN_UPCALL_RESULT_ERR;
    }
    // memcpy(session_index, out->blob, bob.len);
    assert(bob.len == SHA256_DIGEST_LENGTH);
    memcpy(sessionEntry->session_index, out->blob, SHA256_DIGEST_LENGTH);

    // Use the encryption key to populate the seed (from the session ID)
    RandomSeed(sessionEntry->session_id, SHA256_DIGEST_LENGTH);
    RandomBytes(sessionEntry->rand_seed, SHA256_DIGEST_LENGTH);

    res = ccn_name_comp_get(request_name->buf, request_comps, (unsigned int)request_comps->n - 2, &compBuffer, &compSize);
    if (res < 0) 
    {
        DEBUG_PRINT("%d %s Failed to extract session creation data\n", __LINE__, __func__);
        ccn_charbuf_destroy(&request_name);
        ccn_indexbuf_destroy(&request_comps);
        return CCN_UPCALL_RESULT_ERR;
    }
    memcpy(&(sessionEntry->nonce), compBuffer, sizeof(unsigned int));

    // Copy the contents of the encrypted payload to the entry
    assert(sessionEntry->nonce == 0xDEADBEEF);
    DEBUG_PRINT("Nonce = %x\n", sessionEntry->nonce);

    // Construct the response message using a ccn name (for convenience).
    // The response just consists of the nonce (signed)
    struct ccn_charbuf *session_response = ccn_charbuf_create();
    ccn_name_init(session_response);
    ccn_name_append(session_response, &(sessionEntry->nonce), sizeof(unsigned int));
    struct ccn_charbuf *signedResp = ccn_charbuf_create();
    struct ccn_signing_params sp = CCN_SIGNING_PARAMS_INIT;
    sp.type = CCN_CONTENT_DATA;
    unsigned int nonce = sessionEntry->nonce;

    // Sign the response
    res = ccn_sign_content(server->baseProxy->handle, signedResp, request_name, &sp, &nonce, sizeof(nonce));
    if (res < 0) 
    {
        DEBUG_PRINT("%d %s Failed to signed session creation response\n", __LINE__, __func__);
    } 
    else 
    {
        DEBUG_PRINT("Sending %d bytes\n", signedResp->length);
        res = ccn_put(server->baseProxy->handle, signedResp->buf, signedResp->length);
    }

    // ccn_charbuf_destroy(&decrypted);
    // ccn_indexbuf_destroy(&decrypted_comps);
    // ccn_crypto_symkey_destroy(&symkey);
    // free(session_id);
    // free(session_key);
    // free(server_rand);
    // free(enc_info);
    // ccn_charbuf_destroy(&signedResp);

    if (res < 0) 
    {
        DEBUG_PRINT("%d %s Error writing session creation response\n", __LINE__, __func__);
        return CCN_UPCALL_RESULT_ERR;
    }

    DEBUG_PRINT("OUT %d %s Created new session. Response sent\n", __LINE__, __func__);

    return CCN_UPCALL_RESULT_INTEREST_CONSUMED;
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
enum ccn_upcall_res UnwrapInterest(struct ccn_closure *selfp, enum ccn_upcall_kind kind, struct ccn_upcall_info *info)
{
    enum ccn_upcall_res upcall_res = CCN_UPCALL_RESULT_ERR;
    int res = 0;

    DownstreamProxy* proxy = selfp->data;
    ProxyStateTable* stateTable = proxy->stateTable;
    struct ccn_charbuf *new_interest = NULL;
    struct ccn_charbuf *origName = NULL;
    struct ccn_indexbuf *origNameIndexbuf = NULL;
    int origName_ncomps;

    DEBUG_PRINT("IN %d %s\n", __LINE__, __func__);

    switch (kind) 
    {
    case CCN_UPCALL_INTEREST:
        DEBUG_PRINT("%d %s received interest\n", __LINE__, __func__);
        break;
    case CCN_UPCALL_INTEREST_TIMED_OUT:
        DEBUG_PRINT("%d %s received interest time out\n", __LINE__, __func__);
    default:
        DEBUG_PRINT("OUT %d %s\n", __LINE__, __func__);
        return CCN_UPCALL_RESULT_OK;
    }

    // Extract Name from Interest
    origName_ncomps = ccn_util_extract_name(info->interest_ccnb, info->interest_comps, &origName, &origNameIndexbuf);
    ccn_util_print_pc_fmt(origName->buf, origName->length);
    DEBUG_PRINT("\n");

    // Buffers to store interest components
    const unsigned char *sessionIndexCompBuffer = NULL;
    const unsigned char *payloadCompBuffer = NULL;
    unsigned char *sessionIndexBuffer = NULL;
    unsigned char *payloadBuffer = NULL;
    size_t sessionIndexCompBufferSize;
    size_t payloadCompBufferSize;

    // Extract the session identifier (contains a new name and an Interest template)
    // Index 1 will always be the session index
    res = ccn_name_comp_get(origName->buf, origNameIndexbuf, 1, &sessionIndexCompBuffer, &sessionIndexCompBufferSize);
    if (res < 0)
    {
        DEBUG_PRINT("Failed to extract session index.\n");
        return CCN_UPCALL_RESULT_ERR;
    }
    if (sessionIndexCompBufferSize != SHA256_DIGEST_LENGTH)
    {
        DEBUG_PRINT("Invalid session index length retreived.\n");
        return CCN_UPCALL_RESULT_ERR; 
    }

    // Lookup the session identifier and use the associated key to decrypt the interest
    ProxySessionTableEntry* sessionEntry = FindEntryByIndex(proxy->sessionTable, sessionIndexCompBuffer, sessionIndexCompBufferSize);
    if (sessionEntry == NULL)
    {
        DEBUG_PRINT("Session index could not be found.\n");
        return CCN_UPCALL_RESULT_ERR;
    }

    // Extract the encrypted interest
    // Index 2 will always be the encrypted payload
    res = ccn_name_comp_get(origName->buf, origNameIndexbuf, 2, &payloadCompBuffer, &payloadCompBufferSize);
    if (res < 0)
    {
        DEBUG_PRINT("Failed to extract encrypted interest payload.\n");
        return CCN_UPCALL_RESULT_ERR;
    }

    // Decrypt the interest
    BOB* decryptedPayload;
    res = SKDecrypt(&decryptedPayload, sessionEntry->encryption_key, payloadCompBuffer, payloadCompBufferSize);
    if (res < 0)
    {
        DEBUG_PRINT("Failed decrypting interest payload.\n");
        return CCN_UPCALL_RESULT_ERR;
    }

    int j;
    for (j = 0; j < 32; j++)
    {
        if (decryptedPayload->blob[j] != 0xFF) DEBUG_PRINT("RAWR: %d %x\n", j, decryptedPayload->blob[j]);
    }

    // Copy the plaintext to a charbuf buffer and then extract the components
    struct ccn_charbuf* decryptedName = ccn_charbuf_create();
    ccn_name_init(decryptedName);
    res = ccn_charbuf_append(decryptedName, decryptedPayload->blob, decryptedPayload->len);

    // // Manual extraction...
    // struct ccn_buf_decoder decoder;
    // struct ccn_buf_decoder *d = &decoder;
    // d = ccn_buf_decoder_start(d, decryptedName->buf, decryptedName->length);
    // struct ccn_indexbuf* finalNameIndexBuffer = NULL;
    // int numComponents = ccn_parse_Name(d, finalNameIndexBuffer);
    // if (numComponents != 3)
    // {
    //     DEBUG_PRINT("Failed to extract new name.\n");
    //     return CCN_UPCALL_RESULT_ERR;
    // }

    // Save the interest name in the state table so it (and the session entry) can be recovered later
    ProxyStateTableEntry* stateEntry = AllocateNewStateEntry(stateTable);
    stateEntry->ink = (uint8_t*)malloc(decryptedName->length * sizeof(uint8_t));
    stateEntry->inklen = decryptedName->length;
    memcpy(stateEntry->ink, decryptedName->buf, decryptedName->length);
    stateEntry->inv = (uint8_t*)malloc(payloadCompBufferSize * sizeof(uint8_t));
    stateEntry->invlen = payloadCompBufferSize;
    memcpy(stateEntry->inv, payloadCompBuffer, payloadCompBufferSize);

    // Shoot out the decrypted/unwrapped interest
    DEBUG_PRINT("%d %s starting to write new interest\n", __LINE__, __func__);
    res = ccn_express_interest(proxy->baseProxy->handle, decryptedName, proxy->baseProxy->content_handler, NULL);
    if (res != 0) 
    {
        DEBUG_PRINT("ABORT %d %s express interest res = %d\n", __LINE__, __func__, res);
        return CCN_UPCALL_RESULT_ERR;
    }
    DEBUG_PRINT("%d %s done to writing new interest\n", __LINE__, __func__);

    upcall_res = CCN_UPCALL_RESULT_OK;
    DEBUG_PRINT("OUT %d %s\n", __LINE__, __func__);

    return upcall_res;
}

/**
 * Encapsulate and encrypt returning content objects. Encryption
 * uses the ephemeral symmetric key provided by the user in the original
 * interest (stored in a pair).
 *
 * This node will naturally sign the outgoing content object, thus providing
 * verifiability.
 */
enum ccn_upcall_res WrapContent(struct ccn_closure *selfp, enum ccn_upcall_kind kind, struct ccn_upcall_info *info)
{
    enum ccn_upcall_res upcall_res = CCN_UPCALL_RESULT_ERR;
    int res;
    
    DownstreamProxy* proxy = selfp->data;
    ProxyStateTable* stateTable = proxy->stateTable;
    Proxy* baseProxy = proxy->baseProxy;

    struct ccn_charbuf *new_name = NULL;
    struct ccn_charbuf *new_content = NULL;
    struct ccn_signing_params sp = CCN_SIGNING_PARAMS_INIT;

    DEBUG_PRINT("IN %d %s\n",__LINE__, __func__);

    switch (kind) 
    {
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
        // TODO
        return CCN_UPCALL_RESULT_OK;
    }
    case CCN_UPCALL_FINAL:/**< handler is about to be deregistered */
        DEBUG_PRINT("OUT %d %s final upcall\n", __LINE__, __func__);
        return CCN_UPCALL_RESULT_OK;

    case CCN_UPCALL_INTEREST:          /**< incoming interest */
    case CCN_UPCALL_CONSUMED_INTEREST: /**< incoming interest, someone has answered */
    default:
        DEBUG_PRINT("OUT %d %s upcall other kind = %d\n", __LINE__, __func__, kind);
        return CCN_UPCALL_RESULT_ERR;
    }

    DEBUG_PRINT("%d %s Received content object\n", __LINE__, __func__);

    if (info->content_ccnb == NULL) 
    {
        DEBUG_PRINT("OUT %d %s in content upcall, but no content, check kind: %d\n", __LINE__, __func__, kind);
        return CCN_UPCALL_RESULT_OK;
    }

    // Find name in Content Object
    new_name = ccn_charbuf_create();
    ccn_name_init(new_name);
    ccn_name_append_components(new_name, info->content_ccnb, info->content_comps->buf[0], info->content_comps->buf[info->matched_comps]);

#ifdef PROXYDEBUG
    DEBUG_PRINT("name matches %d comps\n", info->matched_comps);
    ccn_util_print_pc_fmt(info->content_ccnb + info->pco->offset[CCN_PCO_B_Name], info->pco->offset[CCN_PCO_E_Name] - info->pco->offset[CCN_PCO_B_Name]);
    DEBUG_PRINT("\n");
#endif

    // Retrieve the original name from the state table
    ProxyStateTableEntry* stateEntry = FindStateEntry(stateTable, new_name->buf, new_name->length);
    if (stateEntry == NULL)
    {
        DEBUG_PRINT("Could not find matching interest name in the state table.\n");
        return CCN_UPCALL_RESULT_ERR;
    }
    struct ccn_charbuf *origName = ccn_charbuf_create();
    res = ccn_charbuf_append(origName, stateEntry->inv, stateEntry->invlen);

    // Created signed info for new content object
    unsigned char *encrypted_content = NULL;
    size_t encrypted_length;
    struct ccn_charbuf *content = ccn_charbuf_create();
    ccn_charbuf_append(content, info->content_ccnb, info->pco->offset[CCN_PCO_E]);

    // caw: refactor
    // ccn_crypto_content_encrypt(symkey, content->buf, content->length, &encrypted_content, &encrypted_length);

    // Sign the new encrypted content
    new_content = ccn_charbuf_create();
    sp.type = CCN_CONTENT_DATA;
    res = ccn_sign_content(baseProxy->handle, new_content, origName, &sp, encrypted_content, encrypted_length);
    if (res != 0) 
    {
        DEBUG_PRINT("ABORT %d %s Failed to encode ContentObject (res == %d)\n", __LINE__, __func__, res);
        return CCN_UPCALL_RESULT_ERR;
    }

    DEBUG_PRINT("%d %s starting content write\n", __LINE__, __func__);
    res = ccn_put(baseProxy->handle, new_content->buf, new_content->length);
    if (res < 0) 
    {
        DEBUG_PRINT("ABORT %d %s ccn_put failed (res == %d)\n", __LINE__, __func__, res);
        return CCN_UPCALL_RESULT_ERR;
    }
    DEBUG_PRINT("%d %s done content write line\n", __LINE__, __func__);

    // Friendly friend or foely foe
    DEBUG_PRINT("%d %s Reply sent\n", __LINE__, __func__);
    upcall_res = CCN_UPCALL_RESULT_OK;
    DEBUG_PRINT("OUT %d %s\n", __LINE__, __func__);

    return upcall_res;
}

/**
 * Clean up and destroy anonymous server object. Expect
 * to be called once at program close.
 *
 * @param pointer to anonymous server to be destroyed
 * @returns 0 (always)
 */
int AnonServerDestroy(DownstreamProxy** server)
{
    DownstreamProxy* s = *server;

    free(s->baseProxy->int_handler);
    free(s->baseProxy->content_handler);
    // ccn_proxy_destroy(&(s->proxy));
    // ccn_crypto_pubkey_destroy(&(s->privkey));

    // TODO: free up other malloc'd resources

    // Lastly, free up the server
    free(s);

    return 0;
}
