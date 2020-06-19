#include <stdio.h>

#include "../src/substrate-methods.h"
#include "../src/substrate-address.h"

// this example shows how to generate a Substrate address
// it also shows how to decode the address to the corresponding public key
int main() {
    
    // generate random seed
    uint8_t seed[32];
    SUBSTRATE_RANDOMBYTES_BUFFER(seed, 32);

    size_t address_len;
    uint8_t *address = NULL;
    uint8_t *privkey = NULL;
    size_t privkey_len;
    if (ss58_encode_from_seed(&address, &address_len, &privkey, &privkey_len, seed, GENERIC) != 0)
        exit(1);

    uint8_t address_s[address_len+1];
    SUBSTRATE_MEMSET(address_s, 0, address_len+1);
    SUBSTRATE_MEMCPY(address_s, address, address_len);
    printf("Substrate address: %s\n", address_s);

    size_t decoded_address_buf = 64;
    uint8_t decoded_address[decoded_address_buf];
    ss58_decode(decoded_address, address, &decoded_address_buf, GENERIC);
    printf("Public key:\n");
    for (int i=0; i < decoded_address_buf; i++) {
        printf("%02x", decoded_address[i]);
    }
    printf("\n");
    SUBSTRATE_FREE(address);

    return 0;
}
