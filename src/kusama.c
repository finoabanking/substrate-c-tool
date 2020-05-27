#include "kusama.h"

// Initialize the `runtime` to the Kusama runtime
uint8_t init_kusama_runtime(SubstrateRuntime *runtime) {

    if (!runtime)
        return 1;

    uint8_t kusama_genesis[SIZE_HASH_256] = {0xb0, 0xa8, 0xd4, 0x93, 0x28, 0x5c, 0x2d, 0xf7, 0x32, 0x90, 0xdf, 0xb7, 0xe6, 0x1f, 0x87, 0x0f, 0x17, 0xb4, 0x18, 0x01, 0x19, 0x7a, 0x14, 0x9c, 0xa9, 0x36, 0x54, 0x49, 0x9e, 0xa3, 0xda, 0xfe};
    runtime->chain = KUSAMA;
    runtime->version = 1055;
    SUBSTRATE_MEMCPY(runtime->genesis_hash, kusama_genesis, SIZE_HASH_256);
    // init metadata
    runtime->metadata.count = 3;

    runtime->metadata.modules[0].name = Balances;
    SubstrateBalances b;
    b.index = 0x04;
    b.transfer.args = 1;
    b.transfer.index = 0x00;
    runtime->metadata.modules[0].module.balances = b;

    runtime->metadata.modules[1].name = Timestamp;
    SubstrateTimestamp t;
    t.index = 0x02;
    runtime->metadata.modules[1].module.timestamp = t;
    runtime->metadata.modules[1].module.timestamp.set.index = 0x00;

    runtime->metadata.modules[2].name = System;
    SubstrateSystem s;
    s.index = 0x00;
    runtime->metadata.modules[2].module.system = s;

    return 0;
}
