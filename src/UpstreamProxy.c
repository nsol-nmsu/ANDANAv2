#include <stdio.h>

#include "UpstreamProxy.h"

UpstreamProxy* UpstreamProxySessionInit(Config* config, struct ccn_charbuf *uri, struct ccn_pkey *pubkey, struct ccn_charbuf *interest_template, int is_exit)
{   
    char bail = 0;
    int res = 0;

    Proxy* baseNode = InitProxyBase(uri, pubkey, interest_template, is_exit);
    UpstreamProxy* node = (UpstreamProxy*)malloc(sizeof(UpstreamProxy));
    // node->sessionTable = (ProxySessionTable*)malloc(sizeof(ProxySessionTable));
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
        unsigned char randomness[SESSIONRAND_LENGTH];
        if(!RandomBytes(randomness, SESSIONRAND_LENGTH))
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
        node->upstreamStateTable = (UpstreamProxyStateTable*)malloc(sizeof(UpstreamProxyStateTable));
        node->sessionTable = (ProxySessionTable*)malloc(sizeof(ProxySessionTable));

        // Use the session ID to recreate the initial rand_seed for encryption/decryption
        RandomSeed(session_id, SHA256_DIGEST_LENGTH);
        RandomBytes(stateEntry->rand_seed, SHA256_DIGEST_LENGTH);

        DEBUG_PRINT("Appending new state table entry\n");
        AddStateEntry(node->sessionTable, stateEntry);

        // Total length of the payload
        unsigned payloadSize = KEYLEN + MACKLEN + SHA256_DIGEST_LENGTH + SHA256_DIGEST_LENGTH + SHA256_DIGEST_LENGTH + SHA256_DIGEST_LENGTH;

        DEBUG_PRINT("Packing the interest\n");

        // Pack in the state information
        struct ccn_charbuf *encryption_key_payload = ccn_charbuf_create();
        ccn_name_init(encryption_key_payload);
        ccn_name_append(int_name, encryption_key, KEYLEN);

        struct ccn_charbuf *mac_key_payload = ccn_charbuf_create();
        ccn_name_init(mac_key_payload);
        ccn_name_append(int_name, mac_key, MACKLEN);

        struct ccn_charbuf *counter_iv_payload = ccn_charbuf_create();
        ccn_name_init(counter_iv_payload);
        ccn_name_append(int_name, counter_iv, SHA256_DIGEST_LENGTH);

        struct ccn_charbuf *session_iv_payload = ccn_charbuf_create();
        ccn_name_init(session_iv_payload);
        ccn_name_append(int_name, session_iv, SHA256_DIGEST_LENGTH);

        struct ccn_charbuf *session_id_payload = ccn_charbuf_create();
        ccn_name_init(session_id_payload);
        ccn_name_append(int_name, session_id, SHA256_DIGEST_LENGTH);

        // struct ccn_charbuf *session_index_payload = ccn_charbuf_create();
        // ccn_name_init(session_index_payload);
        // ccn_name_append(int_name, session_index, SHA256_DIGEST_LENGTH);

        struct ccn_charbuf *nonce_payload = ccn_charbuf_create();
        ccn_name_init(nonce_payload);
        ccn_name_append(int_name, &(stateEntry->nonce), sizeof(unsigned int));

        // Send the interest out and wait for the response
        DEBUG_PRINT("Sending nonce: %x\n", stateEntry->nonce);
        struct ccn_parsed_ContentObject response_pco = { 0 };
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
        res = ccn_content_get_value(response->buf, response->length, &response_pco, &const_payload,&payload_length);

        // Store a local copy of the response payload
        payload = calloc(payload_length, sizeof(unsigned char));
        memcpy(payload, const_payload, payload_length);

        DEBUG_PRINT("Trying to parse the returned response of length: %lu\n", payload_length);

        const unsigned char *session_index_ack = NULL;
        size_t session_index_ack_size;
        // ccn_name_comp_get(const_payload, payload_comps, 0, &session_index_ack, &session_index_ack_size);

        unsigned int nonce_ack = 0;
        memcpy(&nonce_ack, payload, sizeof(unsigned int));
        DEBUG_PRINT("Retrieved nonce: %x\n", nonce_ack);

        // Verify the the ack'd message was correct
        if (payload_length != sizeof(unsigned int)) 
        {
            fprintf(stderr, "%d %s differing session id sizes: got %lu expected %d\n", __LINE__, __func__, payload_length, SHA256_DIGEST_LENGTH);
            return NULL;
        }
        // if (memcmp(payload, session_index, sizeof(unsigned int)) != 0)
        // {
        //     fprintf(stderr, "%d %s invalid session index ACK'd back\n", __LINE__, __func__);
        //     bail = 1;
        //     return NULL;
        // }

        DEBUG_PRINT("Session created successfully\n");
    }
    else if (config->circuit_creation == CIRCUIT_CREATION_PIGGYBACK)
    {
        DEBUG_PRINT("CIRCUIT_CREATION_PIGGYBACK - no interests to be sent here.\n");
    }

    return node;
}

/**
 * TODO
 */
enum ccn_upcall_res WrapInterest(struct ccn_closure *selfp, enum ccn_upcall_kind kind, struct ccn_upcall_info *info)
{
	enum ccn_upcall_res ret = CCN_UPCALL_RESULT_ERR;
	int res;

    UpstreamProxy* client = selfp->data;
    Proxy* proxy = client->baseProxy;

    int i;
    size_t numComponents;
    struct ccn_charbuf *name = NULL;
    struct ccn_indexbuf *nameComponents = NULL;
    struct ccn_charbuf *newName = NULL;
    struct ccn_indexbuf *newNameComponents = NULL;

    switch (kind) 
    {
    case CCN_UPCALL_INTEREST:
        DEBUG_PRINT("Received Interest\n");
        break;
    case CCN_UPCALL_FINAL:
        DEBUG_PRINT("Encap: callback final\n");
        return CCN_UPCALL_RESULT_OK;
    default:
        return CCN_UPCALL_RESULT_ERR;
    }

    // Extract the interest name
    numComponents = ccn_util_extract_name(info->interest_ccnb, info->interest_comps, &name, &nameComponents);

    // Need to check to make sure this interest doesn't match what we sent out. Otherwise, 
    // we'll just keep encapsulating the same thing over and over.
    int num_matching_comps = ccn_util_name_match(client->baseProxy->prefix, client->baseProxy->prefix_comps, name, nameComponents);

    if (num_matching_comps == client->baseProxy->prefix_ncomps) 
    {
        DEBUG_PRINT("Interest matches %d of %d components, ignoring interest\n", num_matching_comps, (int)client->baseProxy->prefix_ncomps);

#ifdef PROXYDEBUG
    ccn_util_println_pc_fmt(name->buf, name->length);
    DEBUG_PRINT("Name has %lu comps\n", nameComponents->n-1);
    ccn_util_println_pc_fmt(client->baseProxy->prefix->buf, client->baseProxy->prefix->length);
    DEBUG_PRINT("Name has %lu comps\n", client->baseProxy->prefix_comps->n-1);
#endif
        ccn_charbuf_destroy(&name);
        ccn_indexbuf_destroy(&nameComponents);
        return ret;
    } 
    else 
    {
        DEBUG_PRINT("Interest matches %d of %d components\n", num_matching_comps, (int)client->baseProxy->prefix_ncomps);
    }

    // Create a new name encapsulated & encrypted name 
    //  newNameComponents = ccn_indexbuf_create();
    ccn_name_append(name, info->interest_ccnb, info->pi->offset[CCN_PI_E]);
    ccn_indexbuf_destroy(&nameComponents);

    // Parse the name components in their encrypted form
    struct ccn_buf_decoder decoder;
    struct ccn_buf_decoder *d = &decoder;
    ccn_buf_decoder_start(d, name->buf, name->length);
    nameComponents = ccn_indexbuf_create();
    res = ccn_parse_Name(d, nameComponents);
    if (res <= 0) 
    {
        DEBUG_PRINT("%d %s error parsing encapsulated name\n", __LINE__, __func__);
        ccn_charbuf_destroy(&name);
        ccn_indexbuf_destroy(&nameComponents);
        return ret;
    }

    // Allocate a new state entry
    UpstreamProxyStateTableEntry* newStateEntry = AllocateNewUpstreamStateEntry(client->upstreamStateTable);
    newStateEntry->invalues = (uint8_t**)malloc(sizeof(uint8_t*) * client->numProxies);
    for (i = 0; i < client->numProxies; i++)
    {
        newStateEntry->invalues[i] = (uint8_t*)malloc(SHA256_DIGEST_LENGTH);
    }

    // Set the original interest name in the upstream state entry
    newStateEntry->origName = ccn_charbuf_create();
    ccn_charbuf_append_charbuf(newStateEntry->origName, name);

    // Initialize the base name for the wrapped interest
    ccn_name_init(newName);

    // Iteratively wrapped interest
    struct ccn_charbuf *wrappedInterest = NULL;

    if (client->config->circuit_creation == CIRCUIT_CREATION_PIGGYBACK)
    {
        // TODO: re-write to make it non-sloppy
    }
    else // CIRCUIT_CREATION_HANDSHAKE
    {
        // Encrypt the new name
        // get session/state table entries for each router
        // compute H(session + siv)
        // increment SIV
        for (i = client->numProxies - 1; i >= 0; i--)
        {
            // session_index = H(sid XOR siv)
            uint8_t session_index[SHA256_DIGEST_LENGTH];
            XOR(client->pathProxies[i]->sessionTable->head->session_id, client->pathProxies[i]->sessionTable->head->session_iv, session_index, SHA256_DIGEST_LENGTH);
            BOB* out;
            res = Hash(&out, session_index, SHA256_DIGEST_LENGTH);
            if (res < 0)
            {
                DEBUG_PRINT("Failed to compute the session index\n");
                return CCN_UPCALL_RESULT_ERR;
            }

            // siv++
            INC(client->pathProxies[i]->sessionTable->head->session_iv, SHA256_DIGEST_LENGTH);

            // The inner interest
            struct ccn_charbuf *innerName = NULL;
            ccn_name_init(innerName);

            // append prefix URI
            UpstreamProxy* hop = client->pathProxies[i];
            Proxy* hopBase = hop->baseProxy;
            ccn_name_append_components(innerName, hopBase->uri->buf, hopBase->uri_comps->buf[0], hopBase->uri_comps->buf[hopBase->uri_comps->n - 1]);

            // append session ID
            ccn_name_append(innerName, (void*)session_index, SHA256_DIGEST_LENGTH);

            // Append the index to the upstream state table
            memcpy(newStateEntry->invalues[i], session_index, SHA256_DIGEST_LENGTH);

            // Encrypt the name using the encryption key
            BOB *encryptedPayload = NULL;

            // Perform wrapping, depending on where we are in the circuit
            if (i == client->numProxies - 1)
            {
                // Encrypt the original interest
                res = SKEncrypt(&encryptedPayload, hop->sessionTable->head->encryption_key, name->buf, name->length);
                if (res < 0)
                {
                    DEBUG_PRINT("Failed encrypting interest payload: %d.\n", i);
                    return CCN_UPCALL_RESULT_ERR;
                }
                res = ccn_name_append(innerName, (void*)encryptedPayload->blob, encryptedPayload->len);
                if (res < 0)
                {
                    DEBUG_PRINT("Failed appending encrypted name to wrapped interest.\n");
                    return CCN_UPCALL_RESULT_ERR;
                }
            }
            else
            {
                // Encrypt the previous interest
                res = SKEncrypt(&encryptedPayload, hop->sessionTable->head->encryption_key, wrappedInterest, wrappedInterest->length);
                if (res < 0)
                {
                    DEBUG_PRINT("Failed encrypting interest payload: %d.\n", i);
                    return CCN_UPCALL_RESULT_ERR;
                }
                res = ccn_name_append(innerName, (void*)encryptedPayload->blob, encryptedPayload->len);
                if (res < 0)
                {
                    DEBUG_PRINT("Failed appending encrypted name to wrapped interest.\n");
                    return CCN_UPCALL_RESULT_ERR;
                }

                // Wipe out the wrapped interest so it can be rebuild below
                ccn_charbuf_destroy(wrappedInterest);
            }

            // Copy this interest so that it can be encrypted the next go round
            ccn_charbuf_append_charbuf(wrappedInterest, innerName);

    #ifdef UPSTREAM_PROXY_DEBUG
        struct ccn_charbuf *c = ccn_charbuf_create();
        ccn_uri_append(c, wrappedInterest->buf, wrappedInterest->length, 1);
        DEBUG_PRINT("name = %s\n", ccn_charbuf_as_string(c));
        ccn_charbuf_destroy(&c);
    #endif

        }

        // Copy the mangled/wrapped interest into newName - the new interest to be sent out
        ccn_charbuf_append_charbuf(newName, wrappedInterest);

    #ifdef UPSTREAM_PROXY_DEBUG
        struct ccn_charbuf *c = ccn_charbuf_create();
        ccn_uri_append(c, newName->buf, newName->length, 1);
        DEBUG_PRINT("name = %s\n", ccn_charbuf_as_string(c));
        ccn_charbuf_destroy(&c);
    #endif
    }

    // Now set the key to the encrypted interest name 
    newStateEntry->ink = (uint8_t*)malloc(sizeof(uint8_t) * newName->length);
    memcpy(newStateEntry->ink, newName->buf, newName->length);
    newStateEntry->inklen = newName->length;

    // Shoot out the new interest
    res = ccn_express_interest(proxy->handle, newName, proxy->content_handler, NULL);
    if(res != 0) 
    {
        DEBUG_PRINT("Express interest result = %d\n",res);
        return CCN_UPCALL_RESULT_ERR;
    } 
    else 
    {
        ret = CCN_UPCALL_RESULT_INTEREST_CONSUMED;
    }

	return ret;
}

/**
 * TODO
 */
enum ccn_upcall_res UnwrapContent(struct ccn_closure *selfp, enum ccn_upcall_kind kind, struct ccn_upcall_info *info)
{
	enum ccn_upcall_res ret = CCN_UPCALL_RESULT_ERR;
	int res;
    int i;

    // Recover the proxy     
    UpstreamProxy *proxy = selfp->data;
    struct ccn_charbuf *new_name = NULL;
    struct ccn_charbuf *new_content = NULL;
    struct ccn_charbuf *name = NULL;
    struct ccn_indexbuf *nameComponents = NULL;
    int numComponents = 0;

    DEBUG_PRINT("Client Content handle called\n");

    switch (kind) 
    {
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
        DEBUG_PRINT("Interest timed out\n");
        return CCN_UPCALL_RESULT_ERR;
    }
    case CCN_UPCALL_INTEREST:          /**< incoming interest */
    case CCN_UPCALL_CONSUMED_INTEREST: /**< incoming interest, someone has answered */
    case CCN_UPCALL_FINAL:             /**< handler is about to be deregistered */
    default:
        DEBUG_PRINT("Upcall other kind = %d\n", kind);
        return CCN_UPCALL_RESULT_ERR;
    }

    // Find name in Content Object
    new_name = ccn_charbuf_create();
    ccn_name_init(new_name);
    ccn_name_append_components(new_name, info->content_ccnb, info->content_comps->buf[0], info->content_comps->buf[info->matched_comps]);
    numComponents = ccn_util_extract_name(info->interest_ccnb, info->interest_comps, &name, &nameComponents);

#ifdef PROXYDEBUG
    DEBUG_PRINT("Name matches %d comps\n", info->matched_comps);
    ccn_util_print_pc_fmt(info->content_ccnb + info->pco->offset[CCN_PCO_B_Name], info->pco->offset[CCN_PCO_E_Name] - info->pco->offset[CCN_PCO_B_Name]);
    DEBUG_PRINT("\n");
#endif

    // Retrieve the original name from the state table and re-build a ccn-compliant name to send downstream
    UpstreamProxyStateTableEntry* stateEntry = FindUpstreamStateEntry(proxy->stateTable, name->buf, name->length);
    struct ccn_charbuf *origName = ccn_charbuf_create();
    ccn_name_init(origName);
    ccn_charbuf_append_charbuf(origName, stateEntry->origName);

    // Extract the encrypted piece of content
    unsigned char *decrypted_content = NULL;
    size_t decrypted_length;
    struct ccn_charbuf *content = ccn_charbuf_create();
    ccn_charbuf_append(content, info->content_ccnb, info->pco->offset[CCN_PCO_E]);

    // Unwrap each layer of XOR padding, (content->buf and content->length)
    uint8_t* ptContent = (uint8_t*)malloc(content->length * sizeof(uint8_t));
    uint32_t ptLength = content->length;
    memcpy(ptContent, content->buf, ptLength);
    for (i = proxy->numProxies - 1; i >= 0; i--) // order of unwrapping does't matter - XOR is commutative
    {
        // Identify the correct session table entry
        ProxySessionTableEntry *entry = FindEntryByIndex(proxy->pathProxies[i]->sessionTable, stateEntry->invalues[i], SHA256_DIGEST_LENGTH);

        // Perform the XOR padding on the same plaintext buffer (XOR is commutative) to remove a layer of encryption
        PRGBasedXorPad(entry->encryption_key, KEYLEN, ptContent, ptContent, ptLength);
    }

    // // Sign the new encrypted content
    // new_content = ccn_charbuf_create();
    // sp.type = CCN_CONTENT_DATA;
    // res = ccn_sign_content(baseProxy->handle, new_content, origName, &sp, encrypted_content, encrypted_length);
    // if (res != 0) 
    // {
    //     DEBUG_PRINT("ABORT %d %s Failed to encode ContentObject (res == %d)\n", __LINE__, __func__, res);
    //     return CCN_UPCALL_RESULT_ERR;
    // }

    // caw: refactor
    // res = ccn_put(proxy->baseProxy->handle, decrypted_content, decrypted_length);
    if (res < 0) 
    {
        DEBUG_PRINT("Error sending parsed content object\n");
        return CCN_UPCALL_RESULT_ERR;
    }

	return CCN_UPCALL_RESULT_OK;
}

