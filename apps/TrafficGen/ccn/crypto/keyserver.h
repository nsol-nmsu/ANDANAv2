#ifndef CCN_KEYSERVER_H
#define CCN_KEYSERVER_H

struct ccn_keyserver;


struct ccn_keyserver *
ccn_keyserver_init(struct ccn *handle, const char *namespace, struct ccn_pkey *pubkey);

int
ccn_keyserver_update_pubkey(struct ccn_keyserver *server, struct ccn_pkey *pubkey);


struct ccn_charbuf *
ccn_keyserver_namespace(struct ccn_keyserver *server);

enum ccn_upcall_res
ccn_keyserver_serve(struct ccn_closure *selfp,
                 enum ccn_upcall_kind kind,
                 struct ccn_upcall_info *info);


int
ccn_keyserver_destroy(struct ccn_keyserver **server);





#endif
