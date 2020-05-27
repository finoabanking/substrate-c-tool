#include "substrate.h"

#ifndef SUBSTRATE_METHODS_H
#define SUBSTRATE_METHODS_H

// keypair used for signing
typedef struct {
    // first 32 bytes are the private key, last 32 bytes are the corresponding public key
    uint8_t sk[2*ADDRESS_LEN];
} SubstrateKeypair;
uint8_t get_keypair(const uint8_t *priv_key, SubstrateKeypair *keypair);

uint8_t sign_transfer_with_secret(uint8_t **transaction, size_t *transaction_len, const SubstrateKeypair *keypair, const SubstrateTransaction *transaction_data, const SubstrateRuntime *runtime, const SubstrateBlock *current_block);

// helpers

uint8_t* construct_BalanceTransferFunction(const SubstrateTransaction *tx_data, const SubstrateRuntime *runtime, size_t* call_len);
uint8_t* construct_TransactionPayload(const SubstrateTransaction *tx_data, const SubstrateRuntime *runtime, const SubstrateBlock *block, uint8_t* call, size_t call_len, size_t* payload_len);
uint8_t* construct_TransactionInfo(const SubstrateTransaction *tx_data, const uint8_t *sender, const uint8_t *signature, size_t* transaction_info_len);
size_t get_extrinsic_length(size_t transaction_info_len, size_t call_len);
uint8_t costruct_Extrinsic(uint8_t* extrinsic, uint8_t* transaction_info, size_t transaction_info_len, uint8_t* call, size_t call_len);

#endif
