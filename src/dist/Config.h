#ifndef CONFIG_H_
#define CONFIG_H_

// Circuit creation flags
#define CIRCUIT_CREATION_HANDSHAKE 1
#define CIRCUIT_CREATION_PIGGYBACK 2

// Circuit signature scheme 
#define CIRCUIT_SIG_SCHEME_ALL_DIGITAL_SIGS 1 // NOT IMPLEMENTED
#define CIRCUIT_SIG_SCHEME_MIXED 2
#define CIRCUIT_SIG_SCHEME_ALL_MACS 3         // NOT IMPLEMENTED

typedef struct
{
    int circuit_creation;
    int circuit_independent;
    int circuit_signature_scheme;
} Config;

#endif /* CONFIG_H_ */
