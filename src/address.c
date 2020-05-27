#include "substrate-address.h"

// generates a new keypair from a seed
uint8_t generate_keypair(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    return SUBSTRATE_GENERATE_KEYPAIR(pk, sk, seed);
}

uint8_t ss58_encode_from_seed(uint8_t **address, size_t* addrlen, uint8_t **privkey, size_t *privkeylen, const uint8_t *seed, enum Chain addr_type) {

    uint8_t pk[ADDRESS_LEN];
    uint8_t sk[ADDRESS_LEN];
    if ( generate_keypair(pk, sk, seed) == 0) {
        if ( ss58_encode(address, addrlen, pk, addr_type) == 0 ) {
            // success. also make available the private key
            *privkeylen = ADDRESS_LEN;
            *privkey = SUBSTRATE_MALLOC(*privkeylen);
            SUBSTRATE_MEMCPY(*privkey, sk, *privkeylen);
            return 0;
        }
    }
    return 1;
}

// computes the `checksum` of a substrate address
// @return 0 when success
// @param `checksum` is a pre-allocated byte array with size 2
// @param `pubkey` is the account ID
// @param `addr_type` is the code associated with the Chain
// @param `prefix` is the prefix string
uint8_t compute_address_checksum(uint8_t* checksum, const uint8_t *pubkey, const uint8_t addr_type, const uint8_t* prefix) {

    const size_t digest_size = 64; // using blake2-512
    const uint32_t msglen = 40; // from substrate spec

    uint8_t out[digest_size];
    uint8_t msg[msglen];

    // construct the message (prefix+addr_type+pubkey)
    SUBSTRATE_MEMCPY((void*) msg, prefix, 7);
    SUBSTRATE_MEMCPY((void*) &msg[7], &addr_type, 1);
    SUBSTRATE_MEMCPY((void*) &msg[8], pubkey, ADDRESS_LEN);

    // hash the message 
    if ( SUBSTRATE_BLAKE2B(out, digest_size, msg, msglen, NULL, 0) == 0 ) { // keylen=0 because optional
        SUBSTRATE_MEMCPY(checksum, out, 2); // take the first 2 bytes
        return 0;
    } else return 1;
}


// `ss58_encode` encodes an account ID into a Substrate address
// @return 0 if success or 1 in case of error
// @param `address` 
// @param `addrlen` is the length of the returned address
// @param `pubkey` is the account ID to encode. It is assumed of length ADDRESS_LEN as per specification
// @param `addr_type` is the ID of the target chain
uint8_t ss58_encode(uint8_t **address, size_t* addrlen, const uint8_t *pubkey, enum Chain addr_type) {
    
    *addrlen = 0;
    if (*address)
        return 1;

    if (! ( (addr_type == GENERIC) || (addr_type == POLKADOT) || (addr_type == KUSAMA) ) )
        return 1;
    
    const uint8_t prefix[7] = {0x53, 0x53, 0x35, 0x38, 0x50, 0x52, 0x45}; //  (the string SS58PRE)
    uint8_t checksum[2];

    // compute checksum
    if (compute_address_checksum(checksum, pubkey, addr_type, prefix) == 0) {
        // concatenate conc = addr_type + pubkey + checksum
        const size_t binsz = 35; // 1 + 32 + 2
        uint8_t conc[binsz];
        SUBSTRATE_MEMCPY((void*) &conc[0], &addr_type, 1);
        SUBSTRATE_MEMCPY((void*) &conc[1], pubkey, ADDRESS_LEN);
        SUBSTRATE_MEMCPY((void*) &conc[33], checksum, 2);

        size_t buf_size = 64;
        uint8_t buf[buf_size];
        SUBSTRATE_MEMSET(buf, 0, buf_size);

        // encode base 58
        if (SUBSTRATE_BASE58ENC(buf, &buf_size, &conc, binsz) == 0) {
            SUBSTRATE_PRINTF("Substrate: error in b58 encoding\n");
            return 1;
        }

        if (buf_size < 512) { // just for safety against external lib b58enc
            *addrlen = buf_size-1;
            *address = SUBSTRATE_MALLOC(*addrlen);
            if (*address != NULL) {
                SUBSTRATE_MEMCPY(*address, buf, *addrlen);
                return 0;
            }
        }
    }
    return 1;
}

// `ss58_decode` decodes a valid SS58-encoded address
// @return 0/1 if success/failure
// @param `address` is the SS-58-encoded address
// @param `out` contains the decoded value
// @param `out_len` is the number of bytes written in `out`
// @param `addr_type` is the ID of the target chain
uint8_t ss58_decode(uint8_t* out, const uint8_t *address, size_t *out_len, enum Chain addr_type) {

    const size_t buf_size = 64; // total size of the buffer
    size_t buf_used = buf_size; // part of the buffer that is used
    uint8_t checksum_len;
    uint8_t *decoded;

    // validate input
    if (!out) {
        SUBSTRATE_PRINTF("Allocate a buffer\n");
        return 1;
    }
    if (!address) {
        return 1;
    }

    // init empty buffer
    uint8_t buf[buf_size];
    SUBSTRATE_MEMSET(buf, 0, buf_size);
    if ( SUBSTRATE_BASE58TOBIN(buf, &buf_used, address, 0) == 1 ) {
        decoded = &buf[buf_size-buf_used];
        // determine checksum length
        switch (buf_used)
        {
        case 3:
        case 4:
        case 6:
        case 10:
            checksum_len = 1;
            break;
        
        case 5:
        case 7:
        case 11:
        case 35:
            checksum_len = 2;
            break;

        case 8:
        case 12:
            checksum_len = 3;
            break;

        case 9:
        case 13:
            checksum_len = 4;
            break;

        case 14:
            checksum_len = 5;
            break;

        case 15:
            checksum_len = 6;
            break;

        case 16:
            checksum_len = 7;
            break;

        case 17:
            checksum_len = 8;
            break;
        
        default:
            checksum_len = 0;
            break;
        }

        // verify address-type (it's the first byte)
        if (decoded[0] != addr_type)
            return 1;

        // verify that public key is a valid ed25519 point
        if (buf_used == 35 && checksum_len == 2) { // (only if address is using account ID)
            if (SUBSTRATE_ISVALIDPOINT(&decoded[1]) != 1) { // account ID starts at position 1
                SUBSTRATE_PRINTF("Invalid point\n");
                return 1;
            }
        }

        // verify checksum
        if (checksum_len > 0) {
            // compute checksum
            size_t digest_size = 64; // using blake2-512
            const uint8_t prefix[7] = {0x53, 0x53, 0x35, 0x38, 0x50, 0x52, 0x45}; //  (the string SS58PRE)
            const uint32_t msglen = 7+buf_used-checksum_len;
            // msg = prefix + addr_type + "account_id"
            uint8_t msg[msglen];
            SUBSTRATE_MEMCPY(msg, prefix, 7);
            SUBSTRATE_MEMCPY(&msg[7], decoded, buf_used-checksum_len);

            uint8_t checksum[digest_size];

            if ( SUBSTRATE_BLAKE2B((void*) checksum, digest_size, msg, msglen, NULL, 0) == 0 ) {
                // checksum must be equal to computed checksum
                if ( SUBSTRATE_MEMCMP(checksum, &decoded[buf_used-checksum_len], checksum_len) == 0) {
                    if (*out_len >= buf_used - 1 - checksum_len) {
                        // success: prepare output
                        *out_len = buf_used - 1 - checksum_len;
                        SUBSTRATE_MEMCPY(out, &decoded[1], buf_size-checksum_len);
                        return 0;
                    }
                }
            }
        }
    }
    // error if here
    return 1;
}
