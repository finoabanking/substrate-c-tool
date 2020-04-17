#include <string>
#include <iostream>
#include <exception>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstring>

extern "C" {
#include "../../src/scale.h"
}

int print_input(uint8_t *value, size_t value_len) {
  std::stringstream s;
  for (unsigned int i=0; i<value_len; i++) {
      s << std::setfill('0') << std::setw(2) << std::right << std::hex << +value[i];
  }
  std::cerr << s.str() << std::endl;
  std::cerr << "Length: " << value_len << std::endl;
  return 0;
}

int main(int argc, char **argv){
  
  std::string input;  
  ScaleElem encoded_value;
  uint8_t decoded_value[SCALE_COMPACT_MAX] = {0};
  size_t decoded_value_len, consumed, encoded_value_len;

  std::ifstream f;
  if (argc >= 2) {
    f.open(argv[1]);
  }
  std::istream &in = (argc >= 2) ? f : std::cin;

  std::getline(in, input);

  // vector to char array
  size_t value_len = input.size();
  uint8_t value[value_len];
  copy(input.begin(), input.end(), value);

  std::cerr << "Input" << std::endl;
  print_input(value, value_len);

  // let's start the testing
  if (value_len >= SCALE_COMPACT_MAX) // this case is not interesting
    return 0;

  if (value_len == 0) // also not interesting
    return 0;

  // 1) can encode
  if ( encode_scale(&encoded_value, value, value_len, type_compact) > 0)
    throw std::runtime_error(std::string("Failed SCALE encoding\n"));

  // 2) decodes expected value
  if ( decode_scale(&encoded_value, decoded_value, &decoded_value_len) > 0)
    throw std::runtime_error(std::string("Failed SCALE decoding\n"));

  // 3) encoded == decoded ?
  print_scale(&encoded_value);
  std::cerr << "Decoded" << std::endl;
  print_input(decoded_value, decoded_value_len);
  if (value_len >= decoded_value_len) {
    if ( std::memcmp(value, decoded_value, value_len) != 0 )
      throw std::runtime_error(std::string("Failed SCALE encoded != decoded (value_len >= decoded_value_len)\n"));
  } else {
    if ( std::memcmp(value, decoded_value, value_len) != 0 )
      throw std::runtime_error(std::string("Failed SCALE encoded != decoded (value_len < decoded_value_len)\n"));
  }



  return 0;
}
