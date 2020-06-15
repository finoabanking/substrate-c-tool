#include "substrate-methods.h"

// convert the Runtime Version to its byte representation
// @return 0/1 in case of success/failure
// `raw_runtime_version` the pre-allocated buffer (of size SIZE_SPEC) to fill
// `spec_version` the number to convert
uint8_t set_runtime_version(uint8_t *raw_runtime_version, uint32_t spec_version) {
    if ((raw_runtime_version)&&(spec_version)) {

        if (is_bigendian) {
            raw_runtime_version[0] = spec_version >> 24;
            raw_runtime_version[1] = spec_version >> 16;
            raw_runtime_version[2] = spec_version >> 8;
            raw_runtime_version[3] = spec_version;
        } else {
            raw_runtime_version[3] = spec_version >> 24;
            raw_runtime_version[2] = spec_version >> 16;
            raw_runtime_version[1] = spec_version >> 8;
            raw_runtime_version[0] = spec_version;
        }
        return 0;
    }
    return 1;
}

// construct BalanceTransferFunction based on `tx_data` and `context` (which are already validated)
// @return the pointer to BalanceTransferFunction or NULL if something goes wrong
// @param `tx_data` contains the TransactionData. assumes that the structure has been already validated
// @param `runtime` contains the Substrate Runtime. assumes that the structure has been already validated
// @param `call_len`: will contain the length of the BalanceTransferFunction
uint8_t* construct_BalanceTransferFunction(const SubstrateTransaction *tx_data, const SubstrateRuntime *runtime, size_t* call_len) {

    uint8_t* call = NULL;
    uint8_t res;
    uint8_t module_index, call_index;
    size_t pos, module_len, call_index_len, amount_len;
    uint8_t balances_pos = get_module_position(Balances, &(runtime->metadata));
    if (balances_pos == UINT8_MAX)
        return NULL; // Balances module not found

    module_index = runtime->metadata.modules[balances_pos].module.balances.index;
    call_index = runtime->metadata.modules[balances_pos].module.balances.transfer.index;
    module_len = 1;
    call_index_len = 1;
    amount_len = get_scale_length(&(tx_data->amount));
    uint8_t amount_value[amount_len];
    res = get_scale_value(&(tx_data->amount), amount_value, amount_len);
    if ((res == 0) && (amount_len > 0)) {
        *call_len = module_len + call_index_len + ADDRESS_LEN + amount_len;
        call = SUBSTRATE_MALLOC(*call_len);
        if (call) {
            pos = 0;
            SUBSTRATE_MEMCPY(call, &module_index, module_len);
            pos += module_len;
            SUBSTRATE_MEMCPY(&call[pos], &call_index, call_index_len);
            pos += call_index_len;
            SUBSTRATE_MEMCPY(&call[pos], tx_data->recipient, ADDRESS_LEN);
            pos += ADDRESS_LEN;
            SUBSTRATE_MEMCPY(&call[pos], amount_value, amount_len);
        }
    }
    return call;
}

// constructs TransactionPayload based on `tx_data` and `context` (which are already validated)
// @return the byte array TransactionPayload or NULL if something goes wrong
// @param `tx_data` points to the transaction
// @param `runtime` points to the runtime
// @param `block` points to the block
// @param `call` points to the pre-computed Call byte array
// @param `call_len` is the length of `call`
// @param `payload_len` will contain the length of the TransactionPayload
uint8_t* construct_TransactionPayload(const SubstrateTransaction *tx_data, const SubstrateRuntime *runtime, const SubstrateBlock *block, uint8_t* call, size_t call_len, size_t* payload_len) {

    uint8_t res_nonce, res_tip, res_era;
    uint8_t* transaction_payload = NULL;
    uint8_t genesis_hash[SIZE_HASH_256];
    uint8_t block_hash[SIZE_HASH_256];
    size_t pos, nonce_length, tip_length, era_length;

    era_length = get_scale_length(&(tx_data->era));
    uint8_t era_value[era_length];
    res_era = get_scale_value(&(tx_data->era), era_value, era_length);
    nonce_length = get_scale_length(&(tx_data->nonce));
    uint8_t nonce_value[nonce_length];
    res_nonce = get_scale_value(&(tx_data->nonce), nonce_value, nonce_length);
    tip_length = get_scale_length(&(tx_data->tip));
    uint8_t tip_value[tip_length];
    res_tip = get_scale_value(&(tx_data->tip), tip_value, tip_length);

    uint8_t runtime_version[SIZE_SPEC];
    set_runtime_version(runtime_version, runtime->version);

    if ( (res_nonce == 0) && (res_tip == 0) && (res_era == 0) &&
        (nonce_length > 0) && (tip_length > 0) && (era_length > 0)) { // encoded value is retrieved
        *payload_len = call_len + era_length + nonce_length + tip_length + SIZE_SPEC + SIZE_HASH_256 + SIZE_HASH_256;
        transaction_payload = SUBSTRATE_MALLOC(*payload_len);

        if (transaction_payload != NULL) {
            SUBSTRATE_MEMCPY(genesis_hash, runtime->genesis_hash, SIZE_HASH_256);
            if (era_length > 1)
                SUBSTRATE_MEMCPY(block_hash, block->hash, SIZE_HASH_256);
            else
                SUBSTRATE_MEMCPY(block_hash, runtime->genesis_hash, SIZE_HASH_256);

            pos = 0;
            SUBSTRATE_MEMCPY(transaction_payload, call, call_len);
            pos = call_len;
            SUBSTRATE_MEMCPY(&transaction_payload[pos], era_value, era_length);
            pos += era_length;
            SUBSTRATE_MEMCPY(&transaction_payload[pos], nonce_value, nonce_length);
            pos += nonce_length;
            SUBSTRATE_MEMCPY(&transaction_payload[pos], tip_value, tip_length);
            pos += tip_length;
            SUBSTRATE_MEMCPY(&transaction_payload[pos], runtime_version, SIZE_SPEC);
            pos += SIZE_SPEC;
            SUBSTRATE_MEMCPY(&transaction_payload[pos], genesis_hash, SIZE_HASH_256);
            pos += ADDRESS_LEN;
            SUBSTRATE_MEMCPY(&transaction_payload[pos], block_hash, SIZE_HASH_256);
        }
    } else SUBSTRATE_PRINTF("payload: failed\n");
    return transaction_payload;
}

// construct TransactionInfo based on `tx_data` and `context` (which are already sanitized)
// @return the byte array TransactionInfo or NULL if something goes wrong
// @param `tx_data` the transaction
// @param `sender` the public key of the sender
// @param `signature` the byte array containing the signature (of length 64 bytes)
// @param `transaction_info_len` will contain the length of TransactionInfo
uint8_t* construct_TransactionInfo(const SubstrateTransaction *tx_data, const uint8_t *sender, const uint8_t *signature, size_t* transaction_info_len) {

    uint8_t res_nonce, res_tip, res_era;
    size_t pos, nonce_length, tip_length, era_length, signature_type_len;
    uint8_t* transaction_info = NULL;
    uint8_t signature_type;
    signature_type = 0x00;
    signature_type_len = 1;

    if ( (sender) && (signature) ) { // basic check

        era_length = get_scale_length(&(tx_data->era));
        uint8_t era_value[era_length];
        res_era = get_scale_value(&(tx_data->era), era_value, era_length);
        nonce_length = get_scale_length(&(tx_data->nonce));
        uint8_t nonce_value[nonce_length];
        res_nonce = get_scale_value(&(tx_data->nonce), nonce_value, nonce_length);
        tip_length = get_scale_length(&(tx_data->tip));
        uint8_t tip_value[tip_length];
        res_tip = get_scale_value(&(tx_data->tip), tip_value, tip_length);
        if ( (res_nonce == 0) && (res_tip==0) && (res_era==0) &&
            (nonce_length > 0) && (tip_length > 0) && (era_length > 0)) {

            *transaction_info_len =  ADDRESS_LEN + signature_type_len + SIGNATURE_LEN + era_length + nonce_length + tip_length;
            transaction_info = SUBSTRATE_MALLOC(*transaction_info_len);
            if (transaction_info != NULL) {
                pos = 0;
                SUBSTRATE_MEMCPY(&transaction_info[pos], sender, ADDRESS_LEN);
                pos += ADDRESS_LEN;
                SUBSTRATE_MEMCPY(&transaction_info[pos], &signature_type, signature_type_len);
                pos += signature_type_len;
                SUBSTRATE_MEMCPY(&transaction_info[pos], signature, SIGNATURE_LEN);
                pos += SIGNATURE_LEN;
                SUBSTRATE_MEMCPY(&transaction_info[pos], era_value, era_length);
                pos += era_length;
                SUBSTRATE_MEMCPY(&transaction_info[pos], nonce_value, nonce_length);
                pos += nonce_length;
                SUBSTRATE_MEMCPY(&transaction_info[pos], tip_value, tip_length);
            }
        }
    }
    return transaction_info;
}

// gets the size of Extrinsic
// @return the size of the Extrinsic
// @param `transaction_info_len` the size of TransactionInfo
// @param `call_len` the size of the Call
size_t get_extrinsic_length(size_t transaction_info_len, size_t call_len) {
    if ((transaction_info_len) && (call_len))
        return 1 + transaction_info_len + call_len;
    else
        return 0;
}

// constructs Extrinsic: it is only used in the final stage, hence all the input parameters are trusted
// @return 0/1 in case of success/failure
// @param `extrinsic` points to the pre-allocated extrinsic (of length given by get_extrinsic_length)
// @param `transaction_info` raw bytes of the TransactionInfo
// @param `transaction_info_len` length of `transaction_info`
// @param `call` raw bytes of the Call
// @param `call_len` length of `call`
uint8_t costruct_Extrinsic(uint8_t* extrinsic, uint8_t* transaction_info, size_t transaction_info_len, uint8_t* call, size_t call_len) {
    
    uint8_t pos;
    uint8_t scale_option = get_transaction_version(v4_signed);

    pos = 0;
    SUBSTRATE_MEMCPY(&extrinsic[pos], &scale_option, 1);
    pos += 1;
    SUBSTRATE_MEMCPY(&extrinsic[pos], transaction_info, transaction_info_len);
    pos += transaction_info_len;
    SUBSTRATE_MEMCPY(&extrinsic[pos], call, call_len);
    return 0;
}


// validates the SubstrateTransaction fields
// @return 0/1 in case of success/failure
// @param `transaction_data` the transaction to be validated
uint8_t validate_transaction_data(const SubstrateTransaction *transaction_data) {

    if (transaction_data) {
        if ((transaction_data->from) && (transaction_data->recipient)) {
            // has sender and receiver
            if (transaction_data->version == v4_signed) {
                // the version is supported
                if ( ( contains_scale(&transaction_data->amount) && 
                contains_scale(&transaction_data->era) &&
                contains_scale(&transaction_data->tip) &&
                contains_scale(&transaction_data->nonce) )) {
                    // amount, era, nonce and tip are valid
                    return 0;
                }
            }
        }

    }
    return 1;
}

// validates a Substrate Runtime
// @return 0/1 in case of success/failure
// @param `runtime` points to the runtime
uint8_t validate_runtime(const SubstrateRuntime *runtime) {
    if (runtime) {
        if ( runtime->chain == KUSAMA )
            return 0;
    }
    SUBSTRATE_PRINTF("Invalid chain\n");
    return 1;
}

uint8_t get_keypair(const uint8_t *priv_key, SubstrateKeypair *keypair) {
#ifdef DEFAULT_CONFIG
    if (sodium_init() < 0) {
        /* panic! the library couldn't be initialized, it is not safe to use */
        return 1;
    }
    // establish keypair
    unsigned char sender[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    unsigned char * seed = SUBSTRATE_MALLOC(crypto_sign_SEEDBYTES);
    SUBSTRATE_MEMCPY(seed, priv_key, ADDRESS_LEN);
    crypto_sign_seed_keypair(sender, sk, seed);
    SUBSTRATE_MEMCPY(keypair->sk, sk, crypto_sign_SECRETKEYBYTES);
    SUBSTRATE_MEMSET(seed, 0, ADDRESS_LEN);
    free(seed);
#else
    // provide a crypto library with digital signature
    exit(1);
#endif
    return 0;
}

// Signs a transaction with a private key, outputs the raw bytes
// @return 0/1 in case of success/failure
// @param `transaction` the byte array that will contain the signed transaction. must be initialized to NULL
// @param `transaction_len` the amount of bytes allocated for `transaction`
// @param `from_addr` the private key of length 32 bytes
// @param `transaction_data` the transaction to be signed. is validated internally
// @param `runtime` the Substrate Runtime in use. is validated internally
// @param `current_block` is the block to be used as a checkpoint for the transaction validity
uint8_t sign_transfer_with_secret(uint8_t **transaction, size_t *transaction_len, const SubstrateKeypair *keypair, const SubstrateTransaction *transaction_data, const SubstrateRuntime *runtime, const SubstrateBlock *current_block) {

    size_t call_len, payload_len, transaction_info_len, extrinsic_len;
    const uint8_t* transaction_payload = NULL;
    uint8_t* call = NULL;
    uint8_t* transaction_info = NULL;
    uint8_t* extrinsic = NULL;
    uint8_t res = 1;
    *transaction = NULL;
    uint8_t signature[SIGNATURE_LEN];

    if ((validate_transaction_data(transaction_data) == 0) && (validate_runtime(runtime) == 0) ) {
        // from this point `transaction_data` and `runtime` are trusted
        call = construct_BalanceTransferFunction(transaction_data, runtime, &call_len);
        if ((call) && (call_len>0))
            transaction_payload = construct_TransactionPayload(transaction_data, runtime, current_block, call, call_len, &payload_len);

        if ((transaction_payload) && (payload_len > 0)) {
            // sign transaction_payload
            SUBSTRATE_CRYPTO_SIGN(signature, NULL, transaction_payload, payload_len, keypair->sk);

            // `call` and `signature` are valid. construct the final Extrinsic
            transaction_info = construct_TransactionInfo(transaction_data, &keypair->sk[ADDRESS_LEN], signature, &transaction_info_len);
            if ((transaction_info) && (transaction_info_len > 0)) {
                extrinsic_len = get_extrinsic_length(transaction_info_len, call_len);
                
                if (extrinsic_len>0)
                    extrinsic = SUBSTRATE_MALLOC(extrinsic_len);

                if (extrinsic) {
                    costruct_Extrinsic(extrinsic, transaction_info, transaction_info_len, call, call_len);
                    // build final transaction
                    *transaction_len = get_vector_u8_size(extrinsic_len);
                    if (*transaction_len > 0)
                        *transaction = SUBSTRATE_MALLOC(*transaction_len);

                    if (*transaction)
                        res = as_scale_vector_u8(*transaction, *transaction_len, extrinsic, extrinsic_len);

                    if (res > 0) // something went wrong in SCALE encoder
                        SUBSTRATE_FREE(*transaction);
                }
            }
        }

        // release everything (except for *transaction of course)
        // we can do this here because all pointers were initialized to NULL
        if (extrinsic)
            SUBSTRATE_FREE(extrinsic);
        if (transaction_info)
            SUBSTRATE_FREE(transaction_info);
        if (transaction_payload)
            SUBSTRATE_FREE(transaction_payload);
        if (call)
            SUBSTRATE_FREE(call);

    }

    return res;
}
