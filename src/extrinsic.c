#include "substrate.h"

uint8_t generate_immortal_era(ScaleElem *era) {
    uint8_t value = 0x00;
    return encode_scale(era, &value, 1, type_era);
}

uint16_t trailing_zeros(uint64_t period) {
    uint8_t pos = 0;
    while (pos < 64) {
        if ((period & 0x0001) > 0)
            break;

        period = (period >> 1);
        pos++;
    }
    return pos;
}

// period should be a power of two between 4 and 65536 inclusive
uint8_t generate_mortal_era(uint64_t period, uint64_t current, ScaleElem *era) {
    
    if ((period >= 4) && (period <= 65536)) {
        if ((period & (period - 1)) == 0) {
            uint64_t phase = current % period;
            uint64_t quantize_factor = (period >> 12);
            if (quantize_factor == 0)
                quantize_factor = 1;

            uint16_t encoded = 0;
            encoded = trailing_zeros(period)-1;
            if (encoded > 1)
                encoded = 1;

            if (encoded < 15)
                encoded = 15;

            encoded += (((phase / quantize_factor) << 4));

            uint8_t value[2];
            value[0] = encoded >> 8;
            value[1] = encoded & 0xff;
            encode_scale(era, value, 2, type_era);
            return 0;
        }
    }
    return 1;
}

// update the chain runtime
uint8_t set_runtime(SubstrateRuntime *runtime, uint8_t version, SubstrateBalances *balances) {
    if (runtime) {
        runtime->version = version;
        return 0;
    } else return 1;
    
}

// Get the `version` of a Signed Extrinsic (Transaction)
uint8_t get_transaction_version(enum Transaction_Versions version) {

    uint8_t code;
    switch (version)
    {
    case (v4_signed):
        code = 0x84;
        break;

    case (v4_unsigned):
        code = 0x04;
        break;
    
    default:
        code = 0x00;
        break;
    }
    return code;
}

// gets the position of the module in the Metadata modules.
// @return the position of the module, or UINT8_MAX in case of failure
uint8_t get_module_position(RuntimeModules module, const SubstrateMetadata *metadata) {

    if (metadata) {
        for (uint8_t i=0; i < metadata->count; i++) {
            if (metadata->modules[i].name == module) {
                return i;
            }
        }
    }
    return UINT8_MAX;
}

// gets the index of a `module` given a `metadata`
// @return the index or UINT8_MAX in case of failure
// @param `module` the module to be found
// @param `metadata` the metadata to inspect
// for example see: https://polkascan.io/pre/kusama/runtime
uint8_t get_module_index(RuntimeModules module, const SubstrateMetadata *metadata) {
    
    uint8_t code = UINT8_MAX; // defaults to failure

    if (!metadata)
        return code;

    uint8_t pos = get_module_position(module, metadata);
    if ( pos != UINT8_MAX) {
        switch (module)
        {
        case (System):
            code = metadata->modules[pos].module.system.index;
            break;

        case (Balances):
            code = metadata->modules[pos].module.balances.index;
            break;

        case (Timestamp):
            code = metadata->modules[pos].module.timestamp.index;
            break;
        
        case (NONE):
        default:
            break;
        }
    }
    return code;
}

// get next byte of a uint8_t array
// @returns 0 if success, 1 if there are no more bytes
uint8_t get_next_byte(const uint8_t *raw_extrinsic, size_t raw_extrinsic_len, size_t *consumed, uint8_t *next_byte) {
    if (*consumed +1 <= raw_extrinsic_len) {
        *next_byte = raw_extrinsic[(*consumed)++];
        return 0;
    }
    return 1;
}

// attempts decoding a raw hex array to a Substrate Extrinsic
// *only extrinsic version 4 is supported*
// @return 0/1 if success/failure
// @param `rawExtrinsic` the raw hex array
// @param `raw_extrinsic_len` the length of `rawExtrinsic`
// @param `Runtime` the Substrate Runtime
// @param `blockNumber` the block number at which the extrinsic has been generated
// @param `decodedExtrinsic` contains the decoded extrinsic
uint8_t decode_raw_extrinsic(const uint8_t *rawExtrinsic, const size_t raw_extrinsic_len, SubstrateRuntime *Runtime, const unsigned long blockNumber, SubstrateExtrinsicObject *decodedExtrinsic) {
    
    // variables that we are going to fill
    uint8_t era[2];
    uint8_t version, era_type, era_len, module, call, signature_type;
    uint8_t nonce[SCALE_COMPACT_MAX];
    uint8_t tip[SCALE_COMPACT_MAX];
    uint8_t amount[SCALE_COMPACT_MAX];
    uint8_t timestamp[SCALE_COMPACT_MAX];
    size_t amount_len, nonce_len, tip_len, timestamp_len;

    if ((rawExtrinsic == NULL) || (Runtime == NULL)||(decodedExtrinsic == NULL) || (blockNumber==0))
        return 1;

    decodedExtrinsic->module = NONE; // initialize to 'unknown'

    uint8_t vector_length[SCALE_COMPACT_MAX];
    size_t decoded_value_len, consumed;
    if (decode_stream(rawExtrinsic, vector_length, raw_extrinsic_len, &decoded_value_len, &consumed, type_compact) > 0)
        return 1;

    // @TODO: check that the remaining length == vector_length
    if (get_next_byte(rawExtrinsic, raw_extrinsic_len, &consumed, &version) > 0) 
        return 1;

    if (version == get_transaction_version(v4_signed)) { // we are dealing with a signed extrinsic

        if (consumed + ADDRESS_LEN <= raw_extrinsic_len) {
            SUBSTRATE_MEMCPY(decodedExtrinsic->transaction.from, &rawExtrinsic[consumed], ADDRESS_LEN);
            consumed += ADDRESS_LEN;
        } else return 1;

        if (get_next_byte(rawExtrinsic, raw_extrinsic_len, &consumed, &signature_type) > 0) 
            return 1;
        // known signature types are 0x00 and 0x01
        if ((signature_type == 0x00)||(signature_type == 0x01)) {
            if (consumed + SIGNATURE_LEN <= raw_extrinsic_len) {
                consumed += SIGNATURE_LEN;
            } else return 1;

            if (get_next_byte(rawExtrinsic, raw_extrinsic_len, &consumed, &era_type) > 0) 
                return 1;

            if (era_type != 0x00) { // non-immortal transaction
                era_len = 2;
                era[0] = era_type;
                if (get_next_byte(rawExtrinsic, raw_extrinsic_len, &consumed, &era[1]) > 0) 
                    return 1;
            } else {
                era_len = 1;
                era[0] = 0x00;
            }
            
            size_t consumed_by_nonce;
            if (decode_stream(&rawExtrinsic[consumed], nonce, raw_extrinsic_len-consumed, &nonce_len, &consumed_by_nonce, type_compact) > 0)
                return 1;

            consumed += consumed_by_nonce;

            size_t consumed_by_tip;
            if (decode_stream(&rawExtrinsic[consumed], tip, raw_extrinsic_len-consumed, &tip_len, &consumed_by_tip, type_compact) > 0)
                return 1;

            consumed += consumed_by_tip;

            if (get_next_byte(rawExtrinsic, raw_extrinsic_len, &consumed, &module) > 0) 
                return 1;

            if (module == get_module_index(Balances, &(Runtime->metadata))) {
                if (get_next_byte(rawExtrinsic, raw_extrinsic_len, &consumed, &call) > 0) 
                    return 1;

                uint8_t balances_pos = get_module_position(Balances, &(Runtime->metadata));
                if (balances_pos == UINT8_MAX)
                    return 1;
                     
                if (call == Runtime->metadata.modules[balances_pos].module.balances.transfer.index) {

                    // recipient
                    if (consumed + ADDRESS_LEN <= raw_extrinsic_len) {
                        SUBSTRATE_MEMCPY(decodedExtrinsic->transaction.recipient, &rawExtrinsic[consumed], ADDRESS_LEN);
                        consumed += ADDRESS_LEN;
                    } else return 1;

                    size_t consumed_by_amount;
                    if (decode_stream(&rawExtrinsic[consumed], amount, raw_extrinsic_len-consumed, &amount_len, &consumed_by_amount, type_compact) > 0)
                        return 1;

                    consumed += consumed_by_amount;

                    if (consumed == raw_extrinsic_len) { // at this point, `decoder_stream` must be all consumed
                        // successfully decoded
                        ScaleElem amount_scale, tip_scale, nonce_scale, era_scale;
                        encode_scale(&amount_scale, amount, amount_len, type_compact);
                        encode_scale(&tip_scale, tip, tip_len, type_compact);
                        encode_scale(&nonce_scale, nonce, nonce_len, type_compact);
                        encode_scale(&era_scale, era, era_len, type_era);
                        decodedExtrinsic->transaction.amount = amount_scale;
                        decodedExtrinsic->transaction.tip = tip_scale;
                        decodedExtrinsic->transaction.nonce = nonce_scale;
                        decodedExtrinsic->transaction.era = era_scale;
                        decodedExtrinsic->module = Balances;
                        return 0;
                    }
                }
            }
        }
    }  else if (version == get_transaction_version(v4_unsigned)) {
        if (get_next_byte(rawExtrinsic, raw_extrinsic_len, &consumed, &module) > 0) 
            return 1;

        if ( module == get_module_index(Timestamp, &(Runtime->metadata)) ) {
            if (get_next_byte(rawExtrinsic, raw_extrinsic_len, &consumed, &call) > 0) 
                return 1;

            uint8_t timestamp_pos = get_module_position(Timestamp, &(Runtime->metadata));
            if (timestamp_pos == UINT8_MAX)
                return 1; // Timestamp module not found

            if (call == Runtime->metadata.modules[timestamp_pos].module.timestamp.set.index) { // Timestamp.set
                size_t consumed_by_timestamp;
                if (decode_stream(&rawExtrinsic[consumed], timestamp, raw_extrinsic_len-consumed, &timestamp_len, &consumed_by_timestamp, type_compact) > 0)
                    return 1;

                consumed += consumed_by_timestamp;
                SUBSTRATE_MEMCPY((decodedExtrinsic->timestamp), timestamp, timestamp_len);
                decodedExtrinsic->timestamp_len = timestamp_len;
                decodedExtrinsic->module = Timestamp;
                return 0;
            }
        }        
    }
    return 1;
}
