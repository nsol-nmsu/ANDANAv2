#include <database.h>

#include <ccn/uri.h>
#include <ccn/hashtb.h>
#include <ccn/util/util.h>

#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

struct andana_dir_db_entry {
    struct ccn_charbuf *namespace;
    unsigned char *fingerprint;
    uint16_t fp_length;
    struct ccn_pkey *pubkey;
};

static struct andana_dir_db_entry *
andana_dir_db_entry_init(struct ccn_charbuf *namespace,
                         unsigned char *fingerprint,
                         uint16_t fp_length,
                         struct ccn_pkey *pubkey)
{
    struct andana_dir_db_entry *entry = calloc(1, sizeof(*entry));

    entry->namespace = ccn_charbuf_create();
    ccn_charbuf_append_charbuf(entry->namespace, namespace);

    entry->fingerprint = malloc(fp_length);
    memcpy(entry->fingerprint, fingerprint, fp_length);

    entry->fp_length = fp_length;
    entry->pubkey = ccn_crypto_pubkey_copy(pubkey);

    return (entry);
}

static int
andana_dir_db_entry_serialize(struct andana_dir_db_entry *entry,
                              unsigned char **out_encoded,
                              uint16_t *length)
{
    unsigned char *DER_pubkey = NULL;
    uint16_t DER_length = ccn_crypto_pubkey_serialize(entry->pubkey, &DER_pubkey);

    *length = sizeof(uint16_t) +
        entry->namespace->length +
        sizeof(entry->fp_length) +
        entry->fp_length +
        sizeof(DER_length) +
        DER_length;


    *out_encoded = malloc(*length);
    unsigned char *p = *out_encoded;

    uint16_t net_length = htons(*length);

    memcpy(p, &net_length, sizeof(net_length));
    p += sizeof(net_length);

    memcpy(p, entry->namespace->buf, entry->namespace->length);
    p += entry->namespace->length;

    uint16_t net_fp_length = htons(entry->fp_length);
    memcpy(p, &net_fp_length, sizeof(net_fp_length));
    p += sizeof(net_fp_length);

    memcpy(p, entry->fingerprint, entry->fp_length);
    p += entry->fp_length;

    uint16_t net_DER_length = htons(DER_length);
    memcpy(p, &net_DER_length, sizeof(net_DER_length));
    p += sizeof(net_DER_length);

    memcpy(p, DER_pubkey, DER_length);

    return (0);
}


static int
andana_dir_db_entry_destroy(struct andana_dir_db_entry **entry)
{
    struct andana_dir_db_entry *e = *entry;

    ccn_charbuf_destroy(&e->namespace);
    free(e->fingerprint);
    ccn_crypto_pubkey_destroy(&e->pubkey);
    free(*entry);
    *entry = NULL;

    return (0);
}

struct andana_dir_db {

    struct hashtb *entries;
    struct hashtb_param params;
};




static void
andana_dir_db_finalize(struct hashtb_enumerator *e)
{
    struct andana_dir_db_entry **entry = e->data;
    andana_dir_db_entry_destroy(entry);
}


struct andana_dir_db *
andana_dir_db_create()
{
    struct andana_dir_db *db = calloc(1, sizeof(*db));
    db->params.finalize = &andana_dir_db_finalize;
    db->entries = hashtb_create(sizeof(struct andana_dir_db_entry *), &db->params);

    return (db);
}

int
andana_dir_db_update_entry(struct andana_dir_db *db,
                           struct ccn_charbuf *namespace,
                           unsigned char *fingerprint,
                           uint16_t fp_length,
                           struct ccn_pkey *pubkey)
{
    int res;
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;

    hashtb_start(db->entries, e);
    res = hashtb_seek(e, fingerprint, fp_length, 0);

    struct andana_dir_db_entry *entry = andana_dir_db_entry_init(namespace,
                                                                 fingerprint,
                                                                 fp_length,
                                                                 pubkey);

    if (res == HT_NEW_ENTRY) {
        struct andana_dir_db_entry **p = e->data;
        *p = entry;
    } else if (res == HT_OLD_ENTRY) {
        struct andana_dir_db_entry **p = e->data;
        andana_dir_db_entry_destroy(p);
        *p = entry;
    } else {
        DEBUG_PRINT("Error updating entry\n");
        andana_dir_db_entry_destroy(&entry);
        hashtb_end(e);
        return (-__LINE__);
    }
    hashtb_end(e);

    return (0);
}

int
andana_dir_db_destroy(struct andana_dir_db **db)
{
    struct andana_dir_db *d = *db;

    hashtb_destroy(&d->entries);

    free(d);
    *db = NULL;
    return (0);
}

int main()
{
    struct andana_dir_db *db = andana_dir_db_create();

    struct ccn_charbuf *name = ccn_charbuf_create();
    ccn_name_from_uri(name, "ccnx:/hello");
    unsigned char fp [] = "World";
    uint16_t fp_length = sizeof(fp);

    struct ccn_pkey *pub = ccn_crypto_pubkey_load_default();

    andana_dir_db_update_entry(db, name, fp, fp_length, pub);
    ccn_crypto_pubkey_destroy(&pub);


    unsigned char fp2 [] = "World";
    uint16_t fp_length2 = sizeof(fp2);


    andana_dir_db_update_entry(db, name, fp2, fp_length2, pub);

    andana_dir_db_destroy(&db);

    ccn_charbuf_destroy(&name);

    return 0;
}
