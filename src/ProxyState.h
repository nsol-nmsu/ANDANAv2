#ifndef PROXY_STATE_H_
#define PROXY_STATE_H_

#include "Util.h"
#include "CryptoWrapper.h"
#include "Crypto.h"

// State table to hold interest name pairs
struct ProxyStateTableEntry;
typedef struct ProxyStateTableEntry
{
  uint8_t* ink; // interest name key - this is the decrypted interest name
  uint32_t inklen;
  uint8_t* inv; // interest name value - this is the encrypted interest name
  uint32_t invlen;
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
  uint8_t encryption_key[KEYLEN];
  uint8_t mac_key[MACKLEN];
  uint8_t counter_iv[IVLEN];
  uint8_t session_iv[IVLEN];
  uint8_t session_id[SHA256_DIGEST_LENGTH];
  uint8_t session_index[SHA256_DIGEST_LENGTH];
  uint8_t rand_seed[SHA256_DIGEST_LENGTH];
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
ProxySessionTableEntry* AllocateNewSessionEntry(ProxySessionTable* table);

/**
 * TODO
 */
ProxySessionTableEntry* FindEntryByIndex(ProxySessionTable* table, uint8_t* index, uint32_t len);

/**
 * TODO
 */ 
void AddStateEntry(ProxyStateTable* table, ProxyStateTableEntry* entry);

/**
 * TODO
 */
ProxyStateTableEntry* AllocateNewStateEntry(ProxyStateTable* table);

/**
 * TODO
 */
ProxyStateTableEntry* FindStateEntry(ProxyStateTable* table, uint8_t* key, uint32_t len);

#endif /* PROXY_STATE_H_ */
