#include <stdio.h>

#include "../src/substrate-methods.h"
#include "../tests/utils.h"
#include "../src/kusama.h"

// this example shows how to generate a signed extrinsic containing a balance transfer
// the resulting hex array is ready to be submitted to the JSON RPC author_submitExtrinsic
int main() {
    SubstrateKeypair keypair;
    generate_Alices_test_keypair(&keypair);

    // init a runtime
    SubstrateRuntime kusamaRuntime;
    init_kusama_runtime(&kusamaRuntime);

    // prepare the struct SubstrateTransaction
    SubstrateTransaction transaction_data;
    uint8_t amount[1] = {0x00};
    uint8_t nonce[1] = {0x04};
    uint8_t tip[1] = {0x00};
    encode_scale(&(transaction_data.amount), amount, 1, type_compact);
    encode_scale(&(transaction_data.nonce), nonce, 1, type_compact);
    encode_scale(&(transaction_data.tip), tip, 1, type_compact);

    // immortal transaction
    transaction_data.era.type = type_era;
    transaction_data.era.elem.era.length = 1;
    transaction_data.era.elem.era.type = type_era;
    transaction_data.era.elem.era.value[0] = 0x00;
    
    transaction_data.version = v4_signed;

    SUBSTRATE_MEMCPY(transaction_data.recipient, Alice.public_key, ADDRESS_LEN);

    uint8_t* transaction;
    size_t transaction_len;
    SubstrateBlock current_block;
    uint8_t block_hash[SIZE_HASH_256] = {0xb0, 0xa8, 0xd4, 0x93, 0x28, 0x5c, 0x2d, 0xf7, 0x32, 0x90, 0xdf, 0xb7, 0xe6, 0x1f, 0x87, 0x0f, 0x17, 0xb4, 0x18, 0x01, 0x19, 0x7a, 0x14, 0x9c, 0xa9, 0x36, 0x54, 0x49, 0x9e, 0xa3, 0xda, 0xfe};
    SUBSTRATE_MEMCPY(current_block.hash, block_hash, SIZE_HASH_256);
    current_block.number = 0;

    if ( sign_transfer_with_secret(&transaction, &transaction_len, &keypair, &transaction_data, &kusamaRuntime, &current_block) > 0 ) {
        printf("Error signing the extrinsic!!\n");
        return 1;
    } else {
        printf("Transaction extrinsic: 0x");
        for (int i=0; i < transaction_len; i++) {
            printf("%02x", transaction[i]);
        }
        printf("\n");        
    }
    SUBSTRATE_FREE(transaction);
    return 0;
}
