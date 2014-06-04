#include <stdio.h>

#include "UpstreamProxy.h"

/**
 * TODO
 */
enum ccn_upcall_res WrapInterest(struct ccn_closure *selfp, enum ccn_upcall_kind kind, struct ccn_upcall_info *info)
{
	enum ccn_upcall_res ret = CCN_UPCALL_RESULT_ERR;
	int res;
    int i;
    size_t numComponents;
    struct ccn_charbuf *name = NULL;
    struct ccn_indexbuf *nameComponents = NULL;
    struct ccn_charbuf *newName = NULL;
    UpstreamProxyStateTableEntry* newStateEntry;

    // Extract the client/proxy
    UpstreamProxy* client = selfp->data;
    Proxy* proxy = client->baseProxy;

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

    // Allocate a new state entry
    newStateEntry = AllocateNewUpstreamStateEntry(client->upstreamStateTable);
    newStateEntry->invalues = (uint8_t**)malloc(sizeof(uint8_t*) * client->numProxies);
    for (i = 0; i < client->numProxies; i++)
    {
        newStateEntry->invalues[i] = (uint8_t*)malloc(SHA256_DIGEST_LENGTH);
    }
    DEBUG_PRINT("upstream PIT entry setup\n");

    // Extract the interest name and then generate the encrypted interest
    numComponents = ccn_util_extract_name(info->interest_ccnb, info->interest_comps, &name, &nameComponents);
    DEBUG_PRINT("Interest = %s\n", ccn_charbuf_as_string(name));
    newName = EncryptInterest(client, newStateEntry, name, nameComponents);

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

struct ccn_charbuf* EncryptInterest(UpstreamProxy* client, UpstreamProxyStateTableEntry* newStateEntry, struct ccn_charbuf* origInterest, struct ccn_indexbuf *origComponents)
{
    int i, j;
    int res;
    struct ccn_charbuf* newName;
    struct ccn_charbuf* wrappedInterestName;

    // Set the original interest name in the upstream state entry
    newStateEntry->origName = ccn_charbuf_create();
    ccn_charbuf_append_charbuf(newStateEntry->origName, origInterest);

    // Initialize the base name for the wrapped interest
    wrappedInterestName = ccn_charbuf_create();
    ccn_name_init(wrappedInterestName);

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

            // append prefix URI
            UpstreamProxy* hop = client->pathProxies[i];
            Proxy* hopBase = hop->baseProxy;

            // The inner interest - create it with the URI of the designated hop
            // struct ccn_charbuf *innerName = ccn_charbuf_create();
            // ccn_name_from_uri(innerName, hopBase->uri->buf);
            struct ccn_charbuf *innerName = ccn_charbuf_create();
            ccn_charbuf_append_charbuf(innerName, hopBase->uri);
            ccn_name_append_str(innerName, "TEMP");

            // append session ID
            ccn_name_append(innerName, (void*)session_index, SHA256_DIGEST_LENGTH);
            DEBUG_PRINT("innerName = %s\n", ccn_charbuf_as_string(innerName));
            DEBUG_PRINT("name = %s\n", ccn_charbuf_as_string(origInterest));

            // Append the index to the upstream state table
            memcpy(newStateEntry->invalues[i], session_index, SHA256_DIGEST_LENGTH);

            // Encrypt the name using the encryption key
            BOB *encryptedPayload = NULL;

            // Perform wrapping, depending on where we are in the circuit
            if (i == client->numProxies - 1)
            {
                DEBUG_PRINT("Encrypting first interest...\n");
                DEBUG_PRINT("Interest = %s\n", ccn_charbuf_as_string(origInterest));
                DEBUG_PRINT("Length = %d\n", origInterest->length);

                unsigned char tmp[32];
                for (j = 0; j < 32; j++) tmp[j] = 0xFF;

                // Encrypt the original interest
                // res = SKEncrypt(&encryptedPayload, hop->sessionTable->head->encryption_key, origInterest->buf, origInterest->length);
                res = SKEncrypt(&encryptedPayload, hop->sessionTable->head->encryption_key, tmp, 32);
                if (res < 0)
                {
                    DEBUG_PRINT("Failed encrypting interest payload: %d.\n", i);
                    return CCN_UPCALL_RESULT_ERR;
                }

                // Format the raw string of bytes for the interest by appendig a CCN_CLOSE terminator
                uint8_t* formattedPayload = (uint8_t*)malloc((encryptedPayload->len + 1) * sizeof(uint8_t));
                memcpy(formattedPayload, encryptedPayload->blob, encryptedPayload->len);
                uint8_t closer = CCN_CLOSE;
                memcpy(formattedPayload + encryptedPayload->len, &closer, sizeof(uint8_t));
                int finalLen;
                uint8_t* finalNamePayload = base64_encode(formattedPayload, encryptedPayload->len + 1, &finalLen);

                // Append the formatted interest (with the interest terminator) to the end
                res = ccn_name_append(innerName, (void*)finalNamePayload, finalLen);
                // ccn_name_append(int_name, &(stateEntry->nonce), sizeof(unsigned int));
                DEBUG_PRINT("innerName = %s\n", ccn_charbuf_as_string(innerName));
                if (res < 0)
                {
                    DEBUG_PRINT("Failed appending encrypted name to wrapped interest.: %d\n", res);
                    return CCN_UPCALL_RESULT_ERR;
                }
            }
            else
            {
                DEBUG_PRINT("Encrypting previous interest\n");

                // Encrypt the previous interest
                res = SKEncrypt(&encryptedPayload, hop->sessionTable->head->encryption_key, wrappedInterestName, wrappedInterestName->length);
                if (res < 0)
                {
                    DEBUG_PRINT("Failed encrypting interest payload: %d.\n", i);
                    return CCN_UPCALL_RESULT_ERR;
                }

                // caw: adopt formatting above if it works

                res = ccn_name_append(innerName, (void*)encryptedPayload->blob, encryptedPayload->len);
                if (res < 0)
                {
                    DEBUG_PRINT("Failed appending encrypted name to wrapped interest.: %d\n", res);
                    return CCN_UPCALL_RESULT_ERR;
                }

                // Wipe out the wrapped interest so it can be rebuild below
                // ccn_charbuf_destroy(wrappedInterest);
            }

            // Copy this interest so that it can be encrypted the next go round
            ccn_name_append(wrappedInterestName, innerName->buf, innerName->length);
            DEBUG_PRINT("wrappedInterestName = %s\n", ccn_charbuf_as_string(wrappedInterestName));

        // #ifdef UPSTREAM_PROXY_DEBUG
        //     struct ccn_charbuf *c = ccn_charbuf_create();
        //     ccn_charbuf_append_charbuf(c, wrappedInterest);
        //     DEBUG_PRINT("name = %s\n", ccn_charbuf_as_string(c));
        //     ccn_charbuf_destroy(&c);
        // #endif

        }

        // Copy the mangled/wrapped interest into newName - the new interest to be sent out
        // UpstreamProxy* hop = client->pathProxies[i];
        // Proxy* hopBase = hop->baseProxy;
        // newName = ccn_charbuf_create();
        // ccn_name_from_uri(newName, hopBase->uri->buf);
        // ccn_name_append(newName, wrappedInterestName->buf, wrappedInterestName->length);

    // #ifdef UPSTREAM_PROXY_DEBUG
    //     struct ccn_charbuf *c = ccn_charbuf_create();
    //     ccn_uri_append(c, newName->buf, newName->length, 1);
    //     DEBUG_PRINT("newName to be sent = %s\n", ccn_charbuf_as_string(c));
    //     ccn_charbuf_destroy(&c);
    // #endif
    }

    // Now set the key to the encrypted interest name 
    newName = wrappedInterestName;
    newStateEntry->ink = (uint8_t*)malloc(sizeof(uint8_t) * newName->length);
    memcpy(newStateEntry->ink, newName->buf, newName->length);
    newStateEntry->inklen = newName->length;

    return newName;
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

