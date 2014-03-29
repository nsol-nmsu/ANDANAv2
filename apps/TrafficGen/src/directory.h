#ifndef ANDANA_DIRECTORY_H
#define ANDANA_DIRECTORY_H

struct andana_dir;

struct andana_dir *
andana_dir_init(struct ccn *handle, const char *namespace, struct ccn_pkey *pubkey);

#endif
