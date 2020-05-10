#include "config.h"
#include <stddef.h>
#include <stdint.h>

#ifndef SCALE_H
#define SCALE_H

// SCALE codec
// - The supported types are enumerated in `ScaleTypes`
// - Each type is encapsulated in a `ScaleElem`
// - The codec does not allocate/deallocate memory by design

#define SCALE_COMPACT_MAX 68

enum ScaleTypes {
    type_compact,
    type_era,
    type_bool,
    type_invalid // this should always be the last element
};

// SCALE Compact
typedef struct {
    uint8_t length;
    uint8_t type;
    uint8_t value[SCALE_COMPACT_MAX];
} Compact;

// SCALE Boolean
typedef struct {
    uint8_t length;
    uint8_t type;
    uint8_t value;
} ScaleBoolean;

// SCALE Era
typedef struct {
    uint8_t length;
    uint8_t type;
    uint8_t value[2];
} Era;

// SCALE element
typedef struct {
    enum ScaleTypes type;
    union {
        Compact compact;
        ScaleBoolean boolean;
        Era era;     
    } elem;
} ScaleElem;

// Functions
uint8_t encode_scale(ScaleElem* encoded_value, uint8_t* value, size_t value_len, enum ScaleTypes type);
uint8_t decode_stream(const uint8_t* encoded_value, uint8_t* decoded_value, size_t encoded_value_len, size_t *decoded_value_len, size_t *consumed, enum ScaleTypes type);
uint8_t decode_scale(const ScaleElem *scale_elem, uint8_t *value, size_t *value_len);
void print_scale(ScaleElem* scale_elem);
uint8_t get_scale_value(const ScaleElem *scale_elem, uint8_t* value, uint8_t value_len);
enum ScaleTypes get_scale_type(const ScaleElem *scale_elem);
uint8_t get_scale_length(const ScaleElem *scale_elem);
size_t get_vector_u8_size(size_t value_len);
uint8_t as_scale_vector_u8(uint8_t* encoded_value, size_t encoded_value_len, uint8_t* value, size_t value_len);
uint8_t contains_scale(const ScaleElem *el);

// Internals
void uint_as_compact(Compact *compact, uint32_t value);

#define is_bigendian (!*(uint8_t *)&(uint16_t){1})

#endif
