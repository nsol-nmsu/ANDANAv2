#ifndef ANDANA_DIRECTORY_DATABASE_H
#define ANDANA_DIRECTORY_DATABASE_H

#include <stdlib.h>
#include <stdint.h>

#include <ccn/crypto/key.h>
#include <ccn/charbuf.h>



struct andana_dir_db;



struct andana_dir_db *
andana_dir_db_create();

int
andana_dir_db_update_entry(struct andana_dir_db *db,
                           struct ccn_charbuf *namespace,
                           unsigned char *fingerprint,
                           uint16_t fp_length,
                           struct ccn_pkey *pubkey);


#endif
