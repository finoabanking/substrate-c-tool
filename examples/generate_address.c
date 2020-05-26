#include <stdio.h>

#include "../src/substrate-methods.h"
#include "../tests/utils.h"
#include "../src/substrate-address.h"

// this example shows how to generate a Substrate address
// it also shows how to decode the address to the corresponding public key
int main() {
    
    generate_Alices_test_keypair();

    size_t address_len;
    uint8_t *address = NULL;
    if (ss58_encode(&address, &address_len, Alice.public_key, GENERIC) != 0)
        exit(1);

    printf("Substrate address: %s\n", address);

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
