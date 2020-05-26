#include <string>
#include <iostream>
#include <exception>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstring>

extern "C"
{
#include "../../src/substrate-methods.h"
#include "../utils.h"
#include "../../src/kusama.h"
}

int print_input(uint8_t *value, size_t value_len)
{
    std::stringstream s;
    for (unsigned int i = 0; i < value_len; i++)
    {
        s << std::setfill('0') << std::setw(2) << std::right << std::hex << +value[i];
    }
    std::cerr << s.str() << std::endl;
    std::cerr << "Length: " << value_len << std::endl;
    return 0;
}

// returns 1 if fails
int string_to_ScaleElem(std::string s, ScaleElem *sElem, enum ScaleTypes type) {

    if ((s.length() > SCALE_COMPACT_MAX) || (s.length() == 0))
        return 1;

    size_t len = s.size();
    uint8_t val[len];
    std::copy(s.begin(), s.end(), val);
    std::cerr << s.size() << std::endl;
    if (type == type_era) {
        if ( (val[0]== 0x00) && (s.size() > 1)) {
            std::cerr << "Meaningless Era" << std::endl;
            return 1;
        }
    }
    return encode_scale(sElem, val, len, type);
}

int decoded_is_correct(ScaleElem *scale, std::string input) {
    size_t len;
    uint8_t decoded[SCALE_COMPACT_MAX];
    decode_scale(scale, decoded, &len);
    uint8_t input_n[input.size()];
    std::copy(input.begin(), input.end(), input_n);

    if ( std::memcmp(decoded, input_n, input.size()) != 0)
        throw std::runtime_error(std::string("Failed SCALE encoded != decoded\n"));

    return 0;
}

// input is: amount nonce tip era blockNumber
int main(int argc, char **argv)
{
    // private key and block_hash are always the same, their value is meaningless
    generate_Alices_test_keypair();
    uint8_t block_hash[SIZE_HASH_256] = {0xb0, 0xa8, 0xd4, 0x93, 0x28, 0x5c, 0x2d, 0xf7, 0x32, 0x90, 0xdf, 0xb7, 0xe6, 0x1f, 0x87, 0x0f, 0x17, 0xb4, 0x18, 0x01, 0x19, 0x7a, 0x14, 0x9c, 0xa9, 0x36, 0x54, 0x49, 0x9e, 0xa3, 0xda, 0xfe};

    std::string samount, snonce, stip, sera, sblockNumber;
    std::ifstream f;
    if (argc >= 2)
    {
        f.open(argv[1]);
    }
    std::istream &in = (argc >= 2) ? f : std::cin;

    std::getline(in, samount);
    std::getline(in, snonce);
    std::getline(in, stip);
    std::getline(in, sera);
    std::getline(in, sblockNumber);

    std::cerr << "init" << std::endl;

    // parse input and don't waste time with impossible inputs
    // prepare the struct SubstrateTransaction
    SubstrateTransaction transaction_data;
    uint32_t blockNumber;
    if (string_to_ScaleElem(samount, &transaction_data.amount, type_compact) > 0)
        return 0;

    if (string_to_ScaleElem(snonce, &transaction_data.nonce, type_compact) > 0)
        return 0;
    
    if (string_to_ScaleElem(stip, &transaction_data.tip, type_compact) > 0)
        return 0;

    if (string_to_ScaleElem(sera, &transaction_data.era, type_era) > 0)
        return 0;

    transaction_data.version = v4_signed;
     // ok we use priv key as the pub key of the receiver... it doesn't matter
    SUBSTRATE_MEMCPY(transaction_data.recipient, Alice.private_key, ADDRESS_LEN);

    try{
        blockNumber = std::stoul(sblockNumber, nullptr, 0);
    } catch (...){
        return 0;
    }
    if (blockNumber == 0)
        return 0;

    // now we start the real testing

    // input is:
    std::cerr << "Tx: amount, nonce, tip, era:" << std::endl;
    print_scale(&transaction_data.amount);
    print_scale(&transaction_data.nonce);
    print_scale(&transaction_data.tip);
    print_scale(&transaction_data.era);
    std::cerr << "BlockNumber: " << blockNumber <<std::endl;

    uint8_t* transaction;
    size_t transaction_len;

    // 1) current block is not interesting to test
    SubstrateBlock current_block;
    SUBSTRATE_MEMCPY(current_block.hash, block_hash, SIZE_HASH_256);
    current_block.number = blockNumber;

    SubstrateRuntime kusamaRuntime;
    init_kusama_runtime(&kusamaRuntime);
    std::cerr << "Runtime initialized!" << std::endl;
    if (sign_transfer_with_secret(&transaction, &transaction_len, Alice.private_key, &transaction_data, &kusamaRuntime, &current_block) > 0) {
        throw std::runtime_error(std::string("Error signing the extrinsic"));
    }

    std::cerr << "Raw transaction" << std::endl;
    print_input(transaction, transaction_len);

    // 2) decode Extrinsic
    SubstrateExtrinsicObject decodedExtrinsic;
    if ( decode_raw_extrinsic(transaction, transaction_len, &kusamaRuntime, blockNumber, &decodedExtrinsic) > 0) {
        throw std::runtime_error(std::string("Error decoding the extrinsic"));
    }

    // 3) decoded == encoded
    if (decodedExtrinsic.module != Balances)
        throw std::runtime_error(std::string("Wrong module"));

    if ( std::memcmp(Alice.public_key, decodedExtrinsic.transaction.from, ADDRESS_LEN) != 0 )
        throw std::runtime_error(std::string("Failed SCALE encoded != decoded (from)\n"));
    
    if ( std::memcmp(transaction_data.recipient, decodedExtrinsic.transaction.recipient, ADDRESS_LEN) != 0 )
        throw std::runtime_error(std::string("Failed SCALE encoded != decoded (to)\n"));

    std::cerr << "Verifying amount..." << std::endl;
    decoded_is_correct(&transaction_data.amount,samount);

    std::cerr << "Verifying nonce..." << std::endl;
    decoded_is_correct(&decodedExtrinsic.transaction.nonce,snonce);

    std::cerr << "Verifying tip..." << std::endl;
    decoded_is_correct(&decodedExtrinsic.transaction.tip,stip);

    std::cerr << "Verifying era..." << sera <<  std::endl;
    decoded_is_correct(&decodedExtrinsic.transaction.era,sera);

    SUBSTRATE_FREE(transaction);
    return 0;
}
