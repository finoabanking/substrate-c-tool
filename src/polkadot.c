#include "polkadot.h"

// Initialize the `runtime` to the Polkadot runtime
uint8_t init_polkadot_runtime(SubstrateRuntime *runtime) {

    if (!runtime)
        return 1;

    uint8_t polkadot_genesis[SIZE_HASH_256] = {0x91, 0xb1, 0x71, 0xbb, 0x15, 0x8e, 0x2d, 0x38, 0x48, 0xfa, 0x23, 0xa9, 0xf1, 0xc2, 0x51, 0x82, 0xfb, 0x8e, 0x20, 0x31, 0x3b, 0x2c, 0x1e, 0xb4, 0x92, 0x19, 0xda, 0x7a, 0x70, 0xce, 0x90, 0xc3};
    runtime->chain = POLKADOT;
    runtime->version = 8;
    SUBSTRATE_MEMCPY(runtime->genesis_hash, polkadot_genesis, SIZE_HASH_256);
    // init metadata
    runtime->metadata.count = 3;

    runtime->metadata.modules[0].name = Balances;
    SubstrateBalances b;
    b.index = 0x05;
    b.transfer.args = 2;
    b.transfer.index = 0x00;
    runtime->metadata.modules[0].module.balances = b;

    runtime->metadata.modules[1].name = Timestamp;
    SubstrateTimestamp t;
    t.index = 0x03;
    runtime->metadata.modules[1].module.timestamp = t;
    runtime->metadata.modules[1].module.timestamp.set.index = 0x00;

    runtime->metadata.modules[2].name = System;
    SubstrateSystem s;
    s.index = 0x00;
    runtime->metadata.modules[2].module.system = s;

    return 0;
}
