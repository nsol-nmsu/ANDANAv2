#ifndef PROXY_STATE_H_
#define PROXY_STATE_H_

#include "Util.h"
#include "CryptoWrapper.h"
#include "Crypto.h"

// State table to hold interest name pairs
struct ProxyStateTableEntry;
typedef struct ProxyStateTableEntry
{
  uint8_t ink; // interest name key
  uint8_t inv; // interest name value
  struct ProxyStateTableEntry* next;
} ProxyStateTableEntry;

typedef struct 
{
  ProxyStateTableEntry* head;  
} ProxyStateTable;

// Session table to hold information about each session
struct ProxySessionTableEntry;
typedef struct ProxySessionTableEntry
{
  unsigned char encryption_key[KEYLEN];
  unsigned char mac_key[MACKLEN];
  unsigned char counter_iv[IVLEN];
  unsigned char session_iv[IVLEN];
  unsigned char session_id[SHA256_DIGEST_LENGTH];
  unsigned char session_index[SHA256_DIGEST_LENGTH];
  unsigned int nonce;
  struct ProxySessionTableEntry* next;
} ProxySessionTableEntry;

typedef struct 
{
  ProxySessionTableEntry* head;
} ProxySessionTable;

/**
 * TODO
 */
void AppendSessionEntry(ProxySessionTable* table, ProxySessionTableEntry* entry);

/**
 * TODO
 */ 
void AddStateEntry(ProxyStateTable* table, ProxyStateTableEntry* entry);

#endif /* PROXY_STATE_H_ */
