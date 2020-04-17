#include "config.h"
#include "scale.h"

#ifndef SUBSTRATE_H
#define SUBSTRATE_H

#define ADDRESS_LEN 32      // length of a substrate account ID in bytes
#define SIZE_HASH_256 32    // length of a hash value
#define SIGNATURE_LEN 64    // length of an ed25519 signature in bytes
#define SIZE_SPEC 4         // length of the specVersion field in bytes

enum Chain {
    polkadot=0, 
    kusama=2, 
    generic=42
};

// -------------------
// Runtime

// Substrate runtimes offer a set of "modules". We support those in `RuntimeModules`
typedef enum {
    System,
    Balances,
    Timestamp,
    NONE = 100
} RuntimeModules;

// Generic `Call` used to interact with a module
typedef struct {
    uint8_t args;
    uint8_t index;
} SubstrateCall;

// Module `Balances`
typedef struct {
    uint8_t index;
    RuntimeModules name;
    SubstrateCall transfer;

} SubstrateBalances;

// Module `System`
typedef struct {
    uint8_t index;
    RuntimeModules name;

} SubstrateSystem;

// Module Timestamp
typedef struct {
    uint8_t index;
    RuntimeModules name;
    SubstrateCall set;

} SubstrateTimestamp;

// Generic Substrate Module
typedef struct {
    RuntimeModules name;
    union
    {
        SubstrateBalances balances;
        SubstrateSystem system;
        SubstrateTimestamp timestamp;
    } module;
    
} SubstrateModule;

// Metadata of the Runtime
typedef struct {
    SubstrateModule modules[32]; // contains a list of modules
    uint8_t count; // number of modules

} SubstrateMetadata;

// Substrate Runtime
typedef struct {
    int version;
    enum Chain chain;
    uint8_t genesis_hash[SIZE_HASH_256];

    SubstrateMetadata metadata;

} SubstrateRuntime;

// -------------------
// Types

// minimal information about a block
typedef struct {
    uint8_t hash[SIZE_HASH_256];
    uint32_t number;
} SubstrateBlock;

enum Transaction_Versions {
    v4_signed,
    v4_unsigned
};

typedef struct {
    enum Transaction_Versions version; // version of the transaction
    ScaleElem amount; // amount of the transaction
    ScaleElem tip;
    ScaleElem nonce;
    ScaleElem era; // for how long the transaction will be valid
    uint8_t recipient[ADDRESS_LEN];
    uint8_t from[ADDRESS_LEN];
    uint8_t hash[SIZE_HASH_256];

} SubstrateTransaction;

// ExtrinsicObject is an extrinsic contained in a valid block
// could be either signed or unsigned
typedef struct {
    RuntimeModules module;
    SubstrateTransaction transaction; // filled if extrinsic is signed
    // filled if unsigned
    uint8_t timestamp[SCALE_COMPACT_MAX];
    uint8_t timestamp_len;
} SubstrateExtrinsicObject;

uint8_t set_metadata(SubstrateMetadata *metadata, SubstrateBalances *balances);
uint8_t get_transaction_version(enum Transaction_Versions version);
uint8_t get_next_byte(const uint8_t *raw_extrinsic, size_t raw_extrinsic_len, size_t *consumed, uint8_t *next_byte);
uint8_t decode_raw_extrinsic(const uint8_t *rawExtrinsic, const size_t raw_extrinsic_len, SubstrateRuntime *Runtime, const unsigned long blockNumber, SubstrateExtrinsicObject *decodedExtrinsic);
uint8_t get_module_index(RuntimeModules module, const SubstrateMetadata *metadata);
uint8_t get_module_position(RuntimeModules module, const SubstrateMetadata *metadata);

#endif
