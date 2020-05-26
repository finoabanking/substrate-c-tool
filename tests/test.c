#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sodium.h>

#include "../src/substrate.h"
#include "../src/substrate-methods.h"
#include "../lib/munit/munit.h"
#include "../src/substrate-address.h"
#include "../src/kusama.h"
#include "utils.h"

// creates a `SubstrateTransaction` without checking if values are acceptable
// returns 1 if the creation fails
int mock_transaction(SubstrateTransaction* transaction, uint8_t* amount, size_t amount_len,
    uint8_t* nonce, size_t nonce_len, uint8_t* tip, size_t tip_len, enum Chain chain, uint8_t version, uint8_t* recipient) {
    
    int res_amount, res_nonce, res_tip;

    res_amount = encode_scale(&(transaction->amount), amount, amount_len, type_compact);
    res_nonce = encode_scale(&(transaction->nonce), nonce, nonce_len, type_compact);
    res_tip = encode_scale(&(transaction->tip), tip, tip_len, type_compact);

    if ( (res_amount != 0) || (res_nonce != 0) || (res_tip != 0))
        return 1;

    transaction->era.type = type_era;
    transaction->era.elem.era.length =1;
    transaction->era.elem.era.type = type_era;
    transaction->era.elem.era.value[0] = 0x00;
    
    transaction-> version = v4_signed;

    SUBSTRATE_MEMCPY(transaction->recipient, recipient, ADDRESS_LEN);

    return 0;
}

void print_bytes(uint8_t* in, size_t len) {
    for (int i=0; i < len; i++) {
        printf("%02x", in[i]);
    }
    printf("\n");
}

void mock_current_block(SubstrateBlock *current_block) {

  uint8_t block_hash[SIZE_HASH_256] = {0xb0, 0xa8, 0xd4, 0x93, 0x28, 0x5c, 0x2d, 0xf7, 0x32, 0x90, 0xdf, 0xb7, 0xe6, 0x1f, 0x87, 0x0f, 0x17, 0xb4, 0x18, 0x01, 0x19, 0x7a, 0x14, 0x9c, 0xa9, 0x36, 0x54, 0x49, 0x9e, 0xa3, 0xda, 0xfe};
  SUBSTRATE_MEMCPY(current_block->hash, block_hash, SIZE_HASH_256);
  current_block->number = 0;
}

uint8_t * hexstring_to_array(const char *string, size_t *output_len) {

  int s;
  uint8_t *output = NULL;
  if (string == NULL)
    return NULL;

  size_t len = strlen(string);
  if((len % 2) != 0)
      return NULL;

  *output_len = len/2;

  output = malloc(*output_len);
  memset(output, 0, *output_len);

  for (int i=0; i<len; i++) {
      char c = string[i];
      s = 0;
      if(c >= '0' && c <= '9')
        s = (c - '0');
      else if (c >= 'A' && c <= 'F') 
        s = (10 + (c - 'A'));
      else if (c >= 'a' && c <= 'f')
        s = (10 + (c - 'a'));
      else {
        free(output);
        return NULL;
      }
      output[(i/2)] += s << (((i + 1) % 2) * 4);
  }
  // success
  return output;

}

static MunitResult encodes_era(const MunitParameter params[], void* data) {

  uint8_t *expected_result;
  uint8_t scale_len;
  uint8_t *encoded_value;
  ScaleElem era;
  size_t len;

  // immortal transaction
  expected_result = hexstring_to_array("00", &len);
  uint8_t v[1] = {0x00};
  encode_scale(&era, v, 1, type_era);
  scale_len = get_scale_length(&era);
  encoded_value = malloc(scale_len*sizeof(uint8_t));
  get_scale_value(&era, encoded_value, scale_len);
  munit_assert_true(scale_len == 1);
  munit_assert_memory_equal(scale_len, encoded_value, expected_result);
  free((void*) expected_result);
  free((void*) encoded_value);

  // transaction of limited time
  expected_result = hexstring_to_array("3c01", &len);
  uint8_t v2[2] = {0x3c, 0x01};
  encode_scale(&era, v2, 2, type_era);
  scale_len = get_scale_length(&era);
  encoded_value = malloc(scale_len*sizeof(uint8_t));
  get_scale_value(&era, encoded_value, scale_len);
  munit_assert_true(scale_len == 2);
  munit_assert_memory_equal(scale_len, encoded_value, expected_result);
  free((void*) expected_result);
  free((void*) encoded_value);  

  return MUNIT_OK;

}

static MunitResult decodes_scale(const MunitParameter params[], void* data) {

  uint8_t* raw_scale;
  size_t raw_scale_len, decoded_value_len, consumed;
  uint8_t decoded_value[SCALE_COMPACT_MAX];
  int res;
  size_t len;

  // case 0b00u
  raw_scale = hexstring_to_array("00", &len);
  raw_scale_len = 1;
  res = decode_stream(raw_scale, decoded_value, raw_scale_len, &decoded_value_len, &consumed, type_compact);
  munit_assert_false(res);
  free((void*) raw_scale);
  memset(&decoded_value, 0, SCALE_COMPACT_MAX);

  // case 0b01u, number 64
  raw_scale = hexstring_to_array("0101", &len);
  raw_scale_len = 2;
  res = decode_stream(raw_scale, decoded_value, raw_scale_len, &decoded_value_len, &consumed, type_compact);
  munit_assert_false(res);
  free((void*) raw_scale);
  memset(&decoded_value, 0, SCALE_COMPACT_MAX);

  // case 0b01u, number (base 16) = 8000;
  raw_scale = hexstring_to_array("02000200", &len);
  raw_scale_len = 4;
  res = decode_stream(raw_scale, decoded_value, raw_scale_len, &decoded_value_len, &consumed, type_compact);
  munit_assert_false(res);
  munit_assert_true(decoded_value_len == 4);
  free((void*) raw_scale);
  memset(&decoded_value, 0, SCALE_COMPACT_MAX);

  // case 0b10u
  // number 123456789, hex(number) = 0x75bcd15
  char v3[4] = { 0x56, 0x34, 0x6f, 0x1d}; 
  raw_scale = (uint8_t*) v3;
  raw_scale_len = 4;
  res = decode_stream(raw_scale, decoded_value, raw_scale_len, &decoded_value_len, &consumed, type_compact);
  munit_assert_true(decoded_value_len == 4);
  munit_assert_false(res);
  memset(&decoded_value, 0, SCALE_COMPACT_MAX);

  // case 0b11u
  // number 1234567899, hex(number) = 0x499602db
  char v[5] = { 0x03, 0xdb, 0x02, 0x96, 0x49};
  raw_scale = (uint8_t*) v;
  raw_scale_len = 5;
  res = decode_stream(raw_scale, decoded_value, raw_scale_len, &decoded_value_len, &consumed, type_compact);
  munit_assert_true(decoded_value_len == 4);
  munit_assert_false(res);
  memset(&decoded_value, 0, SCALE_COMPACT_MAX);

  // case 0b11u; 
  // number: 123456789123456789123456789123456789, hex(number): 0x17c6e3c032f89045ad746684045f15
  char v2[16] = { 0x2f, 0x15, 0x5f, 0x04, 0x84, 0x66, 0x74, 0xad, 0x45, 0x90, 0xf8, 0x32, 0xc0, 0xe3, 0xc6, 0x17};
  raw_scale = (uint8_t*) v2;
  raw_scale_len = 16;
  res = decode_stream(raw_scale, decoded_value, raw_scale_len, &decoded_value_len, &consumed, type_compact);
  munit_assert_true(decoded_value_len == 15);
  munit_assert_false(res);

  return MUNIT_OK;
}

// decode a transaction
// 290284fe6549bbf4dde68661a07690ffb908e9a586e3867a6a0c4066d451d3387d168300c168ac0902387ec587c054657bcfb6bcc1727e5380087bbe0f8b3f38e3dc80eea98366f8bd64abbfa25338f148fed4250645e11ad45ff38331e4958a0a2e5f060000000400fe6549bbf4dde68661a07690ffb908e9a586e3867a6a0c4066d451d3387d168300
static MunitResult decodes_raw_extrinsic(const MunitParameter params[], void* data) {

  int res;
  uint8_t* raw_extrinsic = NULL;
  size_t raw_extrinsic_len;
  SubstrateExtrinsicObject decodedExtrinsic;

  // init a runtime
  SubstrateRuntime kusamaRuntime;
  init_kusama_runtime(&kusamaRuntime);

  // must fail because blockNumber == 0
  raw_extrinsic = hexstring_to_array("290284fe6549bbf4dde68661a07690ffb908e9a586e3867a6a0c4066d451d3387d1683", &raw_extrinsic_len);
  res = decode_raw_extrinsic(raw_extrinsic, 1234, &kusamaRuntime, 0, &decodedExtrinsic);
  munit_assert_true(res);
  
  const unsigned long blockNumber = 1375087; // runtime 1050
  // must fail getting `version`
  raw_extrinsic = hexstring_to_array("2902", &raw_extrinsic_len);
  res = decode_raw_extrinsic(raw_extrinsic, raw_extrinsic_len, &kusamaRuntime, blockNumber, &decodedExtrinsic);
  munit_assert_true(res);

  // must fail getting `version`
  raw_extrinsic = hexstring_to_array("290284", &raw_extrinsic_len);
  res = decode_raw_extrinsic(raw_extrinsic, raw_extrinsic_len, &kusamaRuntime, blockNumber, &decodedExtrinsic);
  munit_assert_true(res);

  // must fail getting `signature_type`
  raw_extrinsic = hexstring_to_array("290284fe6549bbf4dde68661a07690ffb908e9a586e3867a6a0c4066d451d3387d1683", &raw_extrinsic_len);
  res = decode_raw_extrinsic(raw_extrinsic, raw_extrinsic_len, &kusamaRuntime, blockNumber, &decodedExtrinsic);
  munit_assert_true(res);

  // must fail getting `era`
  raw_extrinsic = hexstring_to_array("290284fe6549bbf4dde68661a07690ffb908e9a586e3867a6a0c4066d451d3387d168300c168ac0902387ec587c054657bcfb6bcc1727e5380087bbe0f8b3f38e3dc80eea98366f8bd64abbfa25338f148fed4250645e11ad45ff38331e4958a0a2e5f06", &raw_extrinsic_len);
  res = decode_raw_extrinsic(raw_extrinsic, raw_extrinsic_len, &kusamaRuntime, blockNumber, &decodedExtrinsic);
  munit_assert_true(res);

  // must fail getting `era`
  raw_extrinsic = hexstring_to_array("290284fe6549bbf4dde68661a07690ffb908e9a586e3867a6a0c4066d451d3387d168300c168ac0902387ec587c054657bcfb6bcc1727e5380087bbe0f8b3f38e3dc80eea98366f8bd64abbfa25338f148fed4250645e11ad45ff38331e4958a0a2e5f06", &raw_extrinsic_len);
  res = decode_raw_extrinsic(raw_extrinsic, raw_extrinsic_len, &kusamaRuntime, blockNumber, &decodedExtrinsic);
  munit_assert_true(res);

  // must fail getting `tip`
  raw_extrinsic = hexstring_to_array("290284fe6549bbf4dde68661a07690ffb908e9a586e3867a6a0c4066d451d3387d168300c168ac0902387ec587c054657bcfb6bcc1727e5380087bbe0f8b3f38e3dc80eea98366f8bd64abbfa25338f148fed4250645e11ad45ff38331e4958a0a2e5f060000", &raw_extrinsic_len);
  res = decode_raw_extrinsic(raw_extrinsic, raw_extrinsic_len, &kusamaRuntime, blockNumber, &decodedExtrinsic);
  munit_assert_true(res);

  // must fail getting `module`
  raw_extrinsic = hexstring_to_array("290284fe6549bbf4dde68661a07690ffb908e9a586e3867a6a0c4066d451d3387d168300c168ac0902387ec587c054657bcfb6bcc1727e5380087bbe0f8b3f38e3dc80eea98366f8bd64abbfa25338f148fed4250645e11ad45ff38331e4958a0a2e5f06000000", &raw_extrinsic_len);
  res = decode_raw_extrinsic(raw_extrinsic, raw_extrinsic_len, &kusamaRuntime, blockNumber, &decodedExtrinsic);
  munit_assert_true(res);

  // must fail getting `call`
  raw_extrinsic = hexstring_to_array("290284fe6549bbf4dde68661a07690ffb908e9a586e3867a6a0c4066d451d3387d168300c168ac0902387ec587c054657bcfb6bcc1727e5380087bbe0f8b3f38e3dc80eea98366f8bd64abbfa25338f148fed4250645e11ad45ff38331e4958a0a2e5f060000000400fe6549bbf4dde68661a07690ffb908e9a586e3867a6a0c4066d451d3387d1683", &raw_extrinsic_len);
  res = decode_raw_extrinsic(raw_extrinsic, raw_extrinsic_len, &kusamaRuntime, blockNumber, &decodedExtrinsic);
  munit_assert_true(res);

  // must succeed
  raw_extrinsic = hexstring_to_array("290284fe6549bbf4dde68661a07690ffb908e9a586e3867a6a0c4066d451d3387d168300c168ac0902387ec587c054657bcfb6bcc1727e5380087bbe0f8b3f38e3dc80eea98366f8bd64abbfa25338f148fed4250645e11ad45ff38331e4958a0a2e5f060000000400fe6549bbf4dde68661a07690ffb908e9a586e3867a6a0c4066d451d3387d168300", &raw_extrinsic_len);
  res = decode_raw_extrinsic(raw_extrinsic, raw_extrinsic_len, &kusamaRuntime, blockNumber, &decodedExtrinsic);
  munit_assert_false(res);

  return MUNIT_OK;
}

static MunitResult generates_address_from_seed(const MunitParameter params[], void* data) {

  size_t address_len, pklen;
  uint8_t* address = NULL;
  uint8_t* pk = NULL;
  uint8_t seed[32] = {0xab, 0xf8, 0xe5, 0xbd, 0xbe, 0x30, 0xc6, 0x56, 0x56, 0xc0, 0xa3, 0xcb, 0xd1, 0x81, 0xff, 0x8a, 0x56, 0x29, 0x4a, 0x69, 0xdf, 0xed, 0xd2, 0x79, 0x82, 0xaa, 0xce, 0x4a, 0x76, 0x90, 0x91, 0x15};
  ss58_encode_from_seed(&address, &address_len, &pk, &pklen, seed, GENERIC);
  munit_assert_memory_equal(address_len, address, "5FA9nQDVg267DEd8m1ZypXLBnvN7SFxYwV7ndqSYGiN9TTpu");
  munit_assert(pklen == ADDRESS_LEN);
  uint8_t expected_key[ADDRESS_LEN] = {0xab, 0xf8, 0xe5, 0xbd, 0xbe, 0x30, 0xc6, 0x56, 0x56, 0xc0, 0xa3, 0xcb, 0xd1, 0x81, 0xff, 0x8a, 0x56, 0x29, 0x4a, 0x69, 0xdf, 0xed, 0xd2, 0x79, 0x82, 0xaa, 0xce, 0x4a, 0x76, 0x90, 0x91, 0x15};
  munit_assert_memory_equal(pklen, pk, expected_key);
  free((void*) address);
  free((void*) pk);
  return MUNIT_OK;
}

static MunitResult address_is_correct(const MunitParameter params[], void* data) {

  size_t address_len;
  generate_Alices_test_keypair();
  uint8_t* address = NULL;
  ss58_encode(&address, &address_len, Alice.public_key, GENERIC);
  munit_assert_memory_equal(address_len, address, "5FA9nQDVg267DEd8m1ZypXLBnvN7SFxYwV7ndqSYGiN9TTpu");
  free((void*) address);
  return MUNIT_OK;
}

static MunitResult generates_polkadot_address(const MunitParameter params[], void* data) {

  uint8_t* address = NULL;
  size_t address_len;
  generate_Alices_test_keypair();
  uint8_t expected[] = "146SvjUZXoMaemdeiecyxgALeYMm8ZWh1yrGo8RtpoPfe7WL";
  ss58_encode(&address, &address_len, Alice.public_key, POLKADOT);

  munit_assert_memory_equal(address_len, address, expected);
  free((void*) address);  
  return MUNIT_OK;
}

static MunitResult fails_for_unknown_chain(const MunitParameter params[], void* data) {

  size_t address_len;
  uint8_t *address = NULL;
  generate_Alices_test_keypair();
  ss58_encode(&address, &address_len, Alice.public_key, -1);
  munit_assert_null((char*) address);
  return MUNIT_OK;
}

static MunitResult constructs_balance_transfer_function(const MunitParameter params[], void* data) { 

  size_t len;
  generate_Alices_test_keypair();
  const uint8_t* expected_result = hexstring_to_array("040088dc3417d5058ec4b4503e0c12ea1a0a89be200fe98922423d4334014fa6b0ee00", &len);
  SubstrateTransaction transaction_data;
  size_t call_len;
  uint8_t* result;

  // init a runtime
  SubstrateRuntime kusamaRuntime;
  init_kusama_runtime(&kusamaRuntime);  

  // construct transaction
  uint8_t amount[1] = {0x00};
  uint8_t nonce[1] = {0x01};
  uint8_t tip[1] = {0x00};
  if (mock_transaction(&transaction_data, amount, 1, nonce, 1, tip, 1, KUSAMA, 4, Alice.public_key) != 0)
    return MUNIT_ERROR;

  // construct context
  SubstrateBlock current_block;
  mock_current_block(&current_block);
  
  result = construct_BalanceTransferFunction(&transaction_data, &kusamaRuntime, &call_len);
  munit_assert_memory_equal(call_len, result, expected_result);
  free((void*) expected_result);
  
  return MUNIT_OK;
}

static MunitResult constructs_transaction_payload(const MunitParameter params[], void* data) { 

  size_t len;
  generate_Alices_test_keypair();
  const uint8_t* expected_result = hexstring_to_array("040088dc3417d5058ec4b4503e0c12ea1a0a89be200fe98922423d4334014fa6b0ee000004001f040000b0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafeb0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe", &len);
  SubstrateTransaction transaction_data;
  size_t payload_len;
  // init a runtime
  SubstrateRuntime kusamaRuntime;
  init_kusama_runtime(&kusamaRuntime);  
  uint8_t* result;

  // assume call is computed
  uint8_t* call = hexstring_to_array("040088dc3417d5058ec4b4503e0c12ea1a0a89be200fe98922423d4334014fa6b0ee00", &len);

  // construct transaction
  uint8_t amount[1] = {0x00};
  uint8_t nonce[1] = {0x01};
  uint8_t tip[1] = {0x00};
  mock_transaction(&transaction_data, amount, 1, nonce, 1, tip, 1, KUSAMA, 4, Alice.public_key);
  // construct context
  SubstrateBlock current_block;
  mock_current_block(&current_block);

  result = construct_TransactionPayload(&transaction_data, &kusamaRuntime, &current_block, call, len, &payload_len);
  munit_assert_memory_equal(payload_len, result, expected_result);
  free((void*) expected_result);

  return MUNIT_OK;
}


static MunitResult constructs_transaction_info(const MunitParameter params[], void* data) { 

  size_t len;
  generate_Alices_test_keypair();
  const uint8_t* expected_result = hexstring_to_array("88dc3417d5058ec4b4503e0c12ea1a0a89be200fe98922423d4334014fa6b0ee0015999702d5a1580bf8e7961385e3e487cbc462d2e553d5df100bbc48b1b1f1d18f9c2cc66a220c68f8e6bdec7357aa4da917e6d70c8f799ac1329a85a7100509000400", &len);
  size_t transaction_info_len;
  uint8_t* result;

  // construct transaction
  uint8_t amount[1] = {0x00};
  uint8_t nonce[1] = {0x01};
  uint8_t tip[1] = {0x00};
  SubstrateTransaction transaction_data;
  mock_transaction(&transaction_data, amount, 1, nonce, 1, tip, 1, KUSAMA, 4, Alice.public_key);

  // construct context
  SubstrateBlock current_block;
  mock_current_block(&current_block);

  // assume signature is computed
  uint8_t * signature = hexstring_to_array("15999702d5a1580bf8e7961385e3e487cbc462d2e553d5df100bbc48b1b1f1d18f9c2cc66a220c68f8e6bdec7357aa4da917e6d70c8f799ac1329a85a7100509", &len);
  
  result = construct_TransactionInfo(&transaction_data, Alice.public_key, signature, &transaction_info_len);
  munit_assert_memory_equal(transaction_info_len, result, expected_result);

  free((void*) signature);
  free((void*) expected_result);

  return MUNIT_OK;
}

static MunitResult constructs_extrinsic(const MunitParameter params[], void* data) { 

  size_t len, transaction_info_len, call_len, extrinsic_len;
  uint8_t* transaction_info = hexstring_to_array("88dc3417d5058ec4b4503e0c12ea1a0a89be200fe98922423d4334014fa6b0ee0015999702d5a1580bf8e7961385e3e487cbc462d2e553d5df100bbc48b1b1f1d18f9c2cc66a220c68f8e6bdec7357aa4da917e6d70c8f799ac1329a85a7100509000400", &transaction_info_len);
  const uint8_t* expected_result = hexstring_to_array("8488dc3417d5058ec4b4503e0c12ea1a0a89be200fe98922423d4334014fa6b0ee0015999702d5a1580bf8e7961385e3e487cbc462d2e553d5df100bbc48b1b1f1d18f9c2cc66a220c68f8e6bdec7357aa4da917e6d70c8f799ac1329a85a71005090004000400e5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a00", &len);
  uint8_t* result;

  // assume call is computed
  uint8_t* call = hexstring_to_array("0400e5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a00", &call_len);

  extrinsic_len = get_extrinsic_length(transaction_info_len, call_len);
  result = malloc(extrinsic_len);
  if (result)
    costruct_Extrinsic(result, transaction_info, transaction_info_len, call, call_len);

  munit_assert_true( extrinsic_len == (1 +transaction_info_len + call_len) );
  munit_assert_memory_equal(transaction_info_len, result, expected_result);
  free((void*) transaction_info);
  free((void*) call);
  free((void*) expected_result);

  return MUNIT_OK;
}

static MunitResult signs_transaction_v4(const MunitParameter params[], void* data) {

  generate_Alices_test_keypair();
  const uint8_t* expected_result;
  SubstrateTransaction* transaction_data;
  uint8_t* transaction;
  size_t transaction_len, len;
  SubstrateBlock current_block;
  mock_current_block(&current_block);
  // init a runtime
  SubstrateRuntime kusamaRuntime;
  init_kusama_runtime(&kusamaRuntime);

  // test amount = 0
  expected_result = hexstring_to_array("21028488dc3417d5058ec4b4503e0c12ea1a0a89be200fe98922423d4334014fa6b0ee00959ecca272c11cd3ea67cca328d558a322671a47d620080ab4f3329464d5d72081b58cae2f94b3b7b5dec9b69e8f012603fad3ffae952471964e8c8569044003000400040088dc3417d5058ec4b4503e0c12ea1a0a89be200fe98922423d4334014fa6b0ee00", &len);

  transaction_data = malloc(sizeof(SubstrateTransaction));
  uint8_t amount[1] = {0x00};
  uint8_t nonce[1] = {0x01};
  uint8_t tip[1] = {0x00};
  mock_transaction(transaction_data, amount, 1, nonce, 1, tip, 1, KUSAMA, 4, Alice.public_key);

  sign_transfer_with_secret(&transaction, &transaction_len, Alice.private_key, transaction_data, &kusamaRuntime, &current_block);
  munit_assert_memory_equal(transaction_len, transaction, expected_result);
  SUBSTRATE_FREE(expected_result);
  SUBSTRATE_FREE(transaction);
  SUBSTRATE_FREE(transaction_data);

  // test amount = 69 (0x45) (Compact will have size 2)
  expected_result = hexstring_to_array("25028488dc3417d5058ec4b4503e0c12ea1a0a89be200fe98922423d4334014fa6b0ee003e2e6e9b865739cea7e07410abb2b71e8cc0b2d0641d33d954cad9cfc4cf1470ae2b6811a26684e50292fa8bbe03aa3eb41240e7011fc44e92e0fb52577f2104001000040088dc3417d5058ec4b4503e0c12ea1a0a89be200fe98922423d4334014fa6b0ee1501", &len);

  transaction_data = malloc(sizeof(SubstrateTransaction));
  uint8_t amount2[2] = {0x45};
  uint8_t nonce2[1] = {0x04};
  mock_transaction(transaction_data, amount2, 2, nonce2, 1, tip, 1, KUSAMA, 4, Alice.public_key);
  sign_transfer_with_secret(&transaction, &transaction_len, Alice.private_key, transaction_data, &kusamaRuntime, &current_block);

  munit_assert_memory_equal(transaction_len, transaction, expected_result);
  SUBSTRATE_FREE(expected_result);
  SUBSTRATE_FREE(transaction);
  SUBSTRATE_FREE(transaction_data);

  // test amount = 36893488147419103232
  expected_result = hexstring_to_array("45028488dc3417d5058ec4b4503e0c12ea1a0a89be200fe98922423d4334014fa6b0ee004cbef33b14ea981ae497476dda53ea0edb05761eda4ee76b571d86df2b28ff98ff2554126d5fcbccc7806afb06b914ad7d2baccc40ed0d62bd03842fdf062906000000040088dc3417d5058ec4b4503e0c12ea1a0a89be200fe98922423d4334014fa6b0ee17000000000000000002", &len);

  transaction_data = malloc(sizeof(SubstrateTransaction));
  uint8_t amount3[9] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
  uint8_t nonce3[1] = {0x00};
  mock_transaction(transaction_data, amount3, 9, nonce3, 1, tip, 1, KUSAMA, 4, Alice.public_key);
  sign_transfer_with_secret(&transaction, &transaction_len, Alice.private_key, transaction_data, &kusamaRuntime, &current_block);

  munit_assert_memory_equal(transaction_len, transaction, expected_result);

  SUBSTRATE_FREE(expected_result);
  SUBSTRATE_FREE(transaction);
  SUBSTRATE_FREE(transaction_data);

  return MUNIT_OK;
}

static MunitResult encode_compacts(const MunitParameter params[], void* data) { 

  uint8_t* expected_result;
  uint8_t number;
  size_t len;
  ScaleElem* scale_elem;
  uint8_t* result = NULL;
  uint8_t scale_len;

  // easy one - just 1 byte
  expected_result = hexstring_to_array("04", &len);
  number = 0x01;
  scale_elem = malloc(sizeof(ScaleElem));
  encode_scale(scale_elem, &number, sizeof(uint8_t), type_compact);
  scale_len = get_scale_length(scale_elem);
  result = malloc(scale_len*sizeof(uint8_t));
  get_scale_value(scale_elem, result, scale_len);
  munit_assert_memory_equal(1, result, expected_result);
  free((void*) expected_result);
  free((void*) scale_elem);
  free((void*) result);
  
  // also easy
  expected_result = hexstring_to_array("a8", &len);
  number = 42;
  scale_elem = malloc(sizeof(ScaleElem));
  encode_scale(scale_elem, &number, sizeof(uint8_t), type_compact);
  result = malloc(scale_len*sizeof(uint8_t));  
  get_scale_value(scale_elem, result, scale_len);
  munit_assert_memory_equal(1, result, expected_result);
  free((void*) expected_result);
  free((void*) scale_elem);
  free((void*) result);


  // compact type 2
  expected_result = hexstring_to_array("0101", &len);
  number = 64;
  scale_elem = malloc(sizeof(ScaleElem));
  encode_scale(scale_elem, &number, sizeof(uint8_t), type_compact);
  scale_len = get_scale_length(scale_elem);
  result = malloc(scale_len*sizeof(uint8_t));
  get_scale_value(scale_elem, result, scale_len);
  munit_assert_memory_equal(2, result, expected_result);
  free((void*) expected_result);
  free((void*) scale_elem);
  free((void*) result);


  // compact type 3
  expected_result = hexstring_to_array("02000200", &len);
  uint8_t number_32768[4] = {0x00, 0x80, 0x00, 0x00};
  scale_elem = malloc(sizeof(ScaleElem));
  encode_scale(scale_elem, (uint8_t*) number_32768, 4, type_compact);
  scale_len = get_scale_length(scale_elem);
  result = malloc(scale_len*sizeof(uint8_t));
  get_scale_value(scale_elem, result, scale_len);
  munit_assert_memory_equal(len, result, expected_result);
  free((void*) expected_result);
  free((void*) scale_elem);
  free((void*) result);  

  // now the hard part: BigInteger compact
  expected_result = hexstring_to_array("071234567899", &len);
  uint8_t input[5] = {0x12, 0x34, 0x56, 0x78, 0x99};
  scale_elem = malloc(sizeof(ScaleElem));
  encode_scale(scale_elem, input, 5, type_compact);
  scale_len = get_scale_length(scale_elem);
  result = malloc(scale_len*sizeof(uint8_t));
  get_scale_value(scale_elem, result, scale_len);
  munit_assert_memory_equal(6, result, expected_result);
  free((void*) expected_result);
  free((void*) scale_elem);
  free((void*) result);

  // test a corner case (just in case)
  len = 1000;
  scale_elem = malloc(sizeof(ScaleElem));
  int res = encode_scale(scale_elem, input, len, type_compact);
  munit_assert_true(res);
  free((void*) scale_elem);

  return MUNIT_OK;
}

static MunitResult encodes_vector_u8(const MunitParameter params[], void* data) {

  uint8_t* expected_result;
  uint8_t* input;
  uint8_t* result;
  size_t len;

  expected_result = hexstring_to_array("290284ff34602b88f60513f1c805d87ef52896934baf6a662bc37414dbdbf69356b1a69100236f9b56555b860ffa1c5271e42abca515d1a6c6b6174c368a3d114cf12e086963d4136373a5f0db211c9634a8d7e851f0b09d5b547eb5c3f87c153838e448030000000600ff34602b88f60513f1c805d87ef52896934baf6a662bc37414dbdbf69356b1a69100", &len);
  input = hexstring_to_array("84ff34602b88f60513f1c805d87ef52896934baf6a662bc37414dbdbf69356b1a69100236f9b56555b860ffa1c5271e42abca515d1a6c6b6174c368a3d114cf12e086963d4136373a5f0db211c9634a8d7e851f0b09d5b547eb5c3f87c153838e448030000000600ff34602b88f60513f1c805d87ef52896934baf6a662bc37414dbdbf69356b1a69100", &len);
  len = 138;
  uint8_t s = get_vector_u8_size(len);
  result = malloc(s);
  as_scale_vector_u8(result, s, input, len);
  munit_assert_memory_equal(s, result, expected_result);
  free(result);

  return MUNIT_OK;

}



static MunitTest test_suite_tests[] = {
  {
    "[scale] encodes Era",
    encodes_era
  },
  {
    "[scale] decodes Compact",
    decodes_scale
  },
  {
    "[scale] encodes Compact",
    encode_compacts
  },
  {
    "[scale] encodes Vector u8",
    encodes_vector_u8
  },
  {
    "[address] generates generic",
    address_is_correct,
  },
  {
    "[address] generates pair from seed",
    generates_address_from_seed
  },
  {
    "[address] generates polkadot",
    generates_polkadot_address
  },
  {
    "[address] handles unknown chain",
    fails_for_unknown_chain
  },
  {
    "[transaction] constructs BalanceTransferFunction correctly",
    constructs_balance_transfer_function
  },
  {
    "[transaction] constructs TransactionPayload correctly",
    constructs_transaction_payload
  },
  {
    "[transaction] constructs TransactionInfo correctly",
    constructs_transaction_info
  },
  {
    "[transaction] constructs Extrinsic correctly",
    constructs_extrinsic
  },
  {
    "[transaction] transaction (v4) is correct",
    signs_transaction_v4
  },
  {
    "[extrinsic] decodes from raw",
    decodes_raw_extrinsic
  }
};

static const MunitSuite test_suite = {
  (char*) "",
  test_suite_tests,
  NULL,
  1,
  MUNIT_SUITE_OPTION_NONE
};

int main(int argc, char* argv[MUNIT_ARRAY_PARAM(argc + 1)]) {

    return munit_suite_main(&test_suite, (void*) "µnit", argc, argv);
}
