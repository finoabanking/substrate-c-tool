
#include "substrate.h"

#ifndef SUBSTRATE_ADDRESS_H
#define SUBSTRATE_ADDRESS_H

// address
// implements the spec: https://github.com/paritytech/substrate/wiki/External-Address-Format-(SS58)

uint8_t generate_keypair(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
uint8_t ss58_encode(uint8_t **address, size_t* addrlen, const uint8_t *pubkey, enum Chain chain_id);
uint8_t ss58_encode_from_seed(uint8_t **address, size_t* addrlen, uint8_t **privkey, size_t* privkeylen, const uint8_t *seed, enum Chain chain_id);
uint8_t ss58_decode(uint8_t *out, const uint8_t *address, size_t *out_len, enum Chain chain_id);

#endif
