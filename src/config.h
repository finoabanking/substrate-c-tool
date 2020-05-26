// Substrate configuration of Dependencies
// See the examples of DEFAULT_CONFIG as reference
#ifndef SUBSTRATE_CONFIG_H
#define SUBSTRATE_CONFIG_H

#ifndef DEFAULT_CONFIG

// provide an implementation of blake2b function
// the signature of the function is the reference implementation (https://blake2.net)
#define SUBSTRATE_BLAKE2B(a, b, c, d, e, f)
// provide a function that compares memory pointers
#define SUBSTRATE_MEMCMP(a, b, c)
// provide a function that copies memory
#define SUBSTRATE_MEMCPY(a, b, c)
// provide a function that allocates memory
#define SUBSTRATE_MALLOC(x)
// provide a function that frees allocated memory
#define SUBSTRATE_FREE(x)
// provide a function that allocates memory
#define SUBSTRATE_MEMSET(a, b, c)
// provide a function that encodes Base 58
// the signature is the Bitcoin b58tobin function
#define SUBSTRATE_BASE58TOBIN(a, b, c, d)
// provide a function that decodes Base 58
// the signature is the Bitcoin b58tobin function
#define SUBSTRATE_BASE58ENC(a, b, c, d)
// provide a function that does printf
#define SUBSTRATE_PRINTF(...)
// provide a function that generates a keypair (secret and public key)
#define SUBSTRATE_GENERATE_KEYPAIR(a, b, c)
// provide a function that verifies that pointer `a` is on ed25519
// returns 1 if is on the curve, 0 otherwise
#define SUBSTRATE_ISVALIDPOINT(a) 

#else // an example of configuration
    #include <string.h>
    #include <stdint.h>
    #include <stddef.h>
    #include <stdio.h>
    #include <sodium.h>

    #include "../lib/libbase58/libbase58.h"
    #include "../lib/BLAKE2/sse/blake2.h"

    #define SUBSTRATE_BLAKE2B(a, b, c, d, e, f) blake2b(a, b, c, d, e, f)
    #define SUBSTRATE_MEMCMP(a, b, c)           memcmp(a, b, c)
    #define SUBSTRATE_MEMCPY(a, b, c)           memcpy((void*) a, (void*) b, c)
    #define SUBSTRATE_MALLOC(x)                 malloc(x)
    #define SUBSTRATE_FREE(x)                   free((void*) x)
    #define SUBSTRATE_MEMSET(a, b, c)           memset(a, b, c)
    #define SUBSTRATE_BASE58TOBIN(a, b, c, d)   b58tobin((void*) a, b, (const char*) c, d)
    #define SUBSTRATE_BASE58ENC(a, b, c, d)     b58enc((char*)a, b, (void*) c, d)
    #define SUBSTRATE_PRINTF(...)               printf(__VA_ARGS__)
    #define SUBSTRATE_GENERATE_KEYPAIR(a, b, c) crypto_sign_seed_keypair(a, b, c)
    #define SUBSTRATE_ISVALIDPOINT(a)           crypto_core_ed25519_is_valid_point(a)
#endif // DEFAULT_CONFIG

#endif // SUBSTRATE_CONFIG_H
