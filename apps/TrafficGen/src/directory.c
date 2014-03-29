#include <ccn/crypto/keyserver.h>
#include <ccn/util/util.h>

#include <database.h>
#include <directory.h>

struct andana_dir {
    struct ccn *handle;
    struct ccn_keyserver *kserver;

    struct andana_dir_db *db;

    struct ccn_charbuf *serve_namespace;
    struct ccn_charbuf *write_namespace;

    struct ccn_closure serve_callback;
    struct ccn_closure write_callback;

    struct ccn_charbuf *ack_obj;
};

struct andana_dir_write_data {
    struct andana_dir *dir;
    struct ccn_charbuf *relay_namespace;
};

struct andana_dir *
andana_dir_init(struct ccn *handle, const char *namespace, struct ccn_pkey *pubkey)
{
    int res;
    struct andana_dir *dir = calloc(1, sizeof(*dir));

    dir->handle = handle;
    dir->kserver = ccn_keyserver_init(handle, namespace, pubkey);
    dir->db = andana_dir_db_init();

    dir->serve_namespace = ccn_charbuf_create();
    ccn_charbuf_append_charbuf(dir->serve_namespace, ccn_keyserver(dir->kserver));
    ccn_name_append_str(dir->serve_namespace, "serve");

    dir->serve_callback.p = &andana_dir_serve;
    dir->serve_callback.data = dir;

    res = ccn_set_interest_filter(dir->handle,
                                  dir->serve_namespace,
                                  &dir->serve_callback);

    if (res < 0) {
        fprintf(stderr, "Failed to setup serve namespace\n");
        abort();
    }


    dir->write_namespace = ccn_charbuf_create();
    ccn_charbuf_append_charbuf(dir->write_namespace, ccn_keywriter(dir->kserver));
    ccn_name_append_str(dir->write_namespace, "write");

    dir->write_callback.p = &andana_dir_write;
    dir->write_callback.data = dir;

    res = ccn_set_interest_filter(dir->handle,
                                  dir->write_namespace,
                                  &dir->write_callback);

    if (res < 0) {
        fprintf(stderr, "Failed to setup write namespace\n");
        abort();
    }

    const unsigned char ACK[] = "ACK";

    struct ccn_signing_params sp = CCN_SIGNING_PARAMS_INIT;
    sp.type = CCN_CONTENT_DATA;

    dir->ack_obj = ccn_charbuf_create();

    res = ccn_sign_content(dir->handle,
                           dir->ack_obj,
                           request_name,
                           &sp,
                           ACK,
                           strlen(ACK)+1);

    if (res < 0) {
        DEBUG_PRINT("%d %s Failed to sign ACK\n", __LINE__, __func__);
        abort();
    }

    return (dir);
}



enum ccn_upcall_res
andana_dir_write(struct ccn_closure *selfp,
                 enum ccn_upcall_kind kind,
                 struct ccn_upcall_info *info)
{
    int res;
    struct andana_dir *dir = selfp->data;

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

    res = ccn_util_extract_name(info->interest_ccnb, info->interest_comps, &request_name, &request_comps);

    if (res < 0) {
        DEBUG_PRINT("%d %s Failed to extract namespace from Interest\n", __LINE__, __func__);
        goto NameBail;
    }

    unsigned char const *const_name_buf = NULL;
    size_t name_buf_size;

    res = ccn_name_comp_get(request_name->buf,
                            request_comps,
                            (unsigned int)request_comps->n - 2,
                            &const_name_buf,
                            &name_buf_size);

    if (res < 0) {
        DEBUG_PRINT("%d %s Failed to extract relay namespace\n", __LINE__, __func__);
        goto NameBail;
    }

    struct ccn_charbuf *relay_namespace = ccn_charbuf_create();
    struct ccn_charbuf *relay_comps = ccn_indexbuf_create();
    ccn_charbuf_append(relay_namespace, const_name_buf, name_buf_size);

    struct ccn_buf_decoder decoder = {0};
    struct ccn_buf_decoder *d = &decoder;

    res = ccn_parse_name(d, relay_comps);

    if (res < 0) {
        DEBUG_PRINT("%d %s Received malformed relay namespace\n", __LINE__, __func__);
        goto MalformedNameBail;
    }


    res = ccn_put(server->handle, ack_obj->buf, ack_obj->length);

    if (res < 0) {
        DEBUG_PRINT("%d %s Failed to send ACK\n", __LINE__, __func__);
        abort();
    }

    struct ccn_charbuf *relay_key_name = ccn_charbuf_create();
    ccn_charbuf_append_charbuf(relay_key_name, relay_namespace);
    ccn_name_append_str(relay_key_name, "key");

    struct ccn_charbuf *pull_request = ccn_charbuf_create();
    ccn_charbuf_append_tt(pull_request, CCN_DTAG_Interest, CCN_DTAG);
    ccn_charbuf_append(pull_request, relay_key_name->buf, relay_key_name->length); /* Name */
    ccn_charbuf_append_closer(pull_request); /* </Interest> */


    struct andana_dir_write_data *write_data = calloc(1, sizeof(*write_data));
    write_data->dir = dir;
    write_data->relay_namespace = relay_namespace;

    struct ccn_closure *confirmed_callback = calloc(1, sizeof(*confirmed_callback));
    confirmed_callback->p = &andana_dir_write_confirmed;
    confirmed_callback->data = write_data;

    res = ccn_express_interest(dir->handle,
                               relay_key_name,
                               confirmed_callback,
                               pull_request);

    if (res < 0) {
        DEBUG_PRINT("%d %s Failed to send pull request\n", __LINE__, __func__);
        abort();
    }

    ccn_charbuf_destroy(&relay_key_name);
    ccn_charbuf_destroy(&pull_request);

    return(CCN_UPCALL_RESULT_INTEREST_CONSUMED);

MalformedNameBail:
    ccn_charbuf_destroy(&relay_namespace);
    ccn_indexbuf_destroy(&relay_comps);
NameBail:
    ccn_charbuf_destroy(&request_name);
    ccn_indexbuf_destroy(&request_comps);

    return (CCN_UPCALL_RESULT_ERR);
}


enum ccn_upcall_res
andana_dir_write_confirmed(struct ccn_closure *selfp,
                           enum ccn_upcall_kind kind,
                           struct ccn_upcall_info *info)
{
    int res;
    struct andana_dir_write_data *write_data = selfp->data;
    struct andana_dir *dir = write_data->dir;
    struct ccn_charbuf *relay_namespace = write_data->relay_namespace;

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

    unsigned char const *const_payload = NULL;
    size_t payload_length;

    res = ccn_content_get_value(info->ccnb,
                                info->pco->offset[CCN_PCO_E],
                                info->pco,
                                &const_payload,
                                &payload_length);

    if (res < 0) {
        DEBUG_PRINT("%d %s Unable to extract payload\n", __LINE__, __func__);
        goto ExtractBail;
    }

    /** Expected format:
        [2 byte fingerprint length]
        [FINGERPRINT]
        [2 byte key length]
        [DER public key]
    */

    size_t cur_size = 0;
    unsigned char const *p = const_payload;
    uint16_t fp_length;

    if (payload_length <= sizeof(fp_length)) {
        DEBUG_PRINT("%d %s Malformed packet: too small for fingerprint length\n", __LINE__, __func__);
        goto MalformedFpLength;
    }

    cur_size += sizeof(fp_length);


    memcpy(&fp_length, p, sizeof(fp_length));
    fp_length = ntohs(fp_length);
    p += sizeof(fp_length);
    cur_size += fp_length;

    if (payload_length <= cur_size) {
        DEBUG_PRINT("%d %s Malformed packet: too small for fingerprint\n", __LINE__, __func__);
        goto MalformedFpLength;
    }

    unsigned char *relay_fingerprint = malloc(fp_length);
    memcpy(relay_fingerprint, p, fp_length);
    p += fp_length;

    uint16_t DER_pubkey_length;
    cur_size += sizeof(DER_pubkey_length);

    if (payload_length <= cur_size) {
        DEBUG_PRINT("%d %s Malformed packet: too small for public key length\n", __LINE__, __func__);
        goto MalformedPubKeyLength;
    }

    memcpy(DER_pubkey_length, p, sizeof(DER_pubkey_length));
    DER_pubkey_length = ntohs(DER_pubkey_length);
    p += DER_pubkey_length;
    cur_size += DER_pubkey_length;

    if (DER_pubkey_length != payload_length - cur_size) {
        DEBUG_PRINT("%d %s Malformed packet: key size mismatch\n", __LINE__, __func__);
        goto MalformedPubKey;
    }


    struct ccn_pkey *relay_pubkey = ccn_crypto_deserialize_pubkey(p, DER_pubkey_length);

    if (relay_pubkey == NULL) {
        DEBUG_PRINT("%d %s Malformed packet: bad public key\n", __LINE__, __func__);
        goto MalformedPubKey;
    }

    res = andana_dir_db_update_entry(dir->db, relay_namespace, relay_fingerprint, fp_length, relay_pubkey);

    if (res < 0) {
        DEBUG_PRINT("%d %s Bad registration attempt\n", __LINE__, __func__);
        goto BadReg;
    }

    return (CCN_UPCALL_RESULT_OK);

BadReg:
MalformedPubKey:
MalformedPubKeyLength:
    free(relay_fingerprint);

MalformedFpLength:
ExtractBail:
    ccn_charbuf_destroy(&relay_namespace);
    free(write_data);

    return (CCN_UPCALL_RESULT_ERR);
}


enum ccn_upcall_res
andana_dir_serve(struct ccn_closure *selfp,
                 enum ccn_upcall_kind kind,
                 struct ccn_upcall_info *info)
{
    struct andana_dir *dir = selfp->data;
    int res;

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




    return (CCN_UPCALL_RESULT_INTEREST_CONSUMED);
}

