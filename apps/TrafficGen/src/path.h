#ifndef ANDANA_PATH_H_
#define ANDANA_PATH_H_

#include <ccn/charbuf.h>
#include <ccn/ccn.h>
#include <ccn/uri.h>


/* Opaque proxy path */
struct andana_path;


struct andana_path *
andana_path_init(const size_t length);

struct andana_path *
andana_path_copy(struct andana_path *path);

int
andana_path_set_node_asym(struct andana_path *path,
                          const size_t index,
                          struct ccn_charbuf *node_uri,
                          struct ccn_pkey *pubkey,
                          struct ccn_charbuf *interest);

int
andana_path_set_node_session(struct andana_path *path,
                             const size_t index,
                             struct ccn_charbuf *node_uri,
                             struct ccn_pkey *pubkey,
                             struct ccn_charbuf *interest);

int
andana_path_replace_symkey(struct andana_path *path, size_t index);

int
andana_path_replace_all_symkeys(struct andana_path *path);

int
andana_path_encrypt_encap(struct andana_path *path,
                          struct ccn_charbuf *name,
                          struct ccn_indexbuf *name_comps,
                          struct ccn_charbuf **result_name,
                          struct ccn_indexbuf **result_name_comps);

int
andana_path_decrypt_decap(struct andana_path *path,
                          void *content_object,
                          size_t length,
                          struct ccn_parsed_ContentObject *pco,
                          unsigned char **content,
                          size_t *content_length);

int
andana_path_destroy(struct andana_path **path);




#endif /* ANDANA_PATH_H_ */
