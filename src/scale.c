// implementation of SCALE codec

#include "scale.h"

// prints the value of a ScaleElem on stdout
// @param `scale_elem` is the SCALE struct to print
void print_scale(ScaleElem* scale_elem) {
    
    if (scale_elem) {
        uint8_t length = get_scale_length(scale_elem);
        if (length > 0) {
            SUBSTRATE_PRINTF("0x");
            uint8_t scale_value[length];
            get_scale_value(scale_elem, scale_value, length);
            for (int i=0; i< length; i++)
                SUBSTRATE_PRINTF("%02x", scale_value[i]);

            SUBSTRATE_PRINTF("\n");
        }
    } else SUBSTRATE_PRINTF("No SCALE\n");

}

// basic check useful when dealing with untrusted ScaleElem
// @return 0/1 in case of success/failure
// @param `el` the SCALE struct to check
uint8_t contains_scale(const ScaleElem *el) {
    if (el) {
        if (el->type == type_compact) {
            if (el->elem.compact.type == type_compact)
                if (el->elem.compact.length >0)
                    return 1;
        } else if (el->type == type_era) {
            if (el->elem.era.type == type_era)
                if (el->elem.era.length > 0)
                    return 1;
        }
    }
    return 0;
}

// converts the `value` to a Compact
// @param `compact` is the pre-allocated compact to fill
// @param `value` is the uint32_t to be encoded
void uint_as_compact(Compact *compact, uint32_t value) {

    uint32_t c;

    if (compact) {

        compact->type = type_compact;

        if (value <= 0x3F) {
            c = (value << 2);
            compact->length = 1;
            compact->value[0] = c;

        } else if (value <= 0x3FFF) {
            c = (( value << 2) | 0x01 );
            compact->length = 2;
            compact->value[0] = c;
            compact->value[1] = (c >> 8);

        } else if (value <= 0x3FFFFFFF) {
            compact->length = 4;
            c = (( value << 2) | 0x02 );
            compact->value[0] = c;
            compact->value[1] = (c >> 8);
            compact->value[2] = (c >> 16);
            compact->value[3] = (c >> 24);
        } else {
            compact->length = 5;
            compact->value[0] = 0x03;
            compact->value[1] = value;
            compact->value[2] = (value >> 8);
            compact->value[3] = (value >> 16);
            compact->value[4] = (value >> 24);
        }
    }
    return;
}

// encodes a value to its Compact representation
// @return 0/1 in case of success/failure
// @param `compact` is the pre-allocated compact to fill
// @param `value` is the bytearray (with length `value_len`) to be encoded
// @param `value_len` is the length of `value`
uint8_t as_compact(Compact *compact, uint8_t* value, uint8_t value_len) {

    if ( (compact) && (value) && (value_len > 0) ) {
        if (value_len <= 4) { // fast implementation
            uint32_t val = 0;
            if ( is_bigendian ) {
                SUBSTRATE_PRINTF("Bigendian detected\n");
                uint8_t value_revert[value_len];
                for (int j=0; j<value_len; j++) {
                    value_revert[j] = value[value_len-j-1];
                }
                SUBSTRATE_MEMCPY(&val, value_revert, value_len);
            } else {
                SUBSTRATE_MEMCPY(&val, value, value_len);
            }
            uint_as_compact(compact, val);
            return 0;
        } else if (value_len < SCALE_COMPACT_MAX) {
            // Big Integer
            compact->length = value_len+1;
            compact->type = type_compact;
            compact->value[0] = (((value_len - 4) << 2 ) | 0x03);
            SUBSTRATE_MEMCPY(&(compact->value[1]), value, value_len);
            return 0;
        }
    }
    return 1;
}

// gets the length of a vector
// @return the SCALE-encoded size or 0 in case of failure
// @param `value_len` is the size of the vector
size_t get_vector_u8_size(size_t value_len) {
    size_t size = 0;
    Compact prefix;
    if (value_len > 0) {
        uint_as_compact(&prefix, value_len);
        size = prefix.length + value_len;
    }
    return size;
}

// encodes the byte array `value` (of size `value_len`) to SCALE Vector.
// @param `encoded_value` is a pre-allocated buffer of size `encoded_value_len` that will contain the result.
// @param `encoded_value_len` is pre-computed by function `get_vector_u8_size`.
// @param `value` is the u8 vector to be SCALE-encoded
// @param `value_len` is the length of `value`
uint8_t as_scale_vector_u8(uint8_t* encoded_value, size_t encoded_value_len, uint8_t* value, size_t value_len) {

    Compact prefix;
    size_t local_length;
    if (encoded_value && value && encoded_value_len) {
        uint_as_compact(&prefix, value_len);
        local_length = prefix.length + value_len;
        if (local_length == encoded_value_len) {
            SUBSTRATE_MEMCPY(&encoded_value[0], prefix.value, prefix.length);
            SUBSTRATE_MEMCPY(&encoded_value[prefix.length], value, value_len);
            return 0;
        }
    }
    return 1;
}

// gets the length of the value of ScaleElem
// @return the length or 0 in case of failure
// @param `scale_elem` points to a SCALE struct
uint8_t get_scale_length(const ScaleElem *scale_elem) {
    uint8_t length = 0;
    if (scale_elem) {
        if (scale_elem->type == type_compact) {
            length = scale_elem->elem.compact.length;
        } else if (scale_elem->type == type_bool) {
            length = scale_elem->elem.boolean.length;
        } else if (scale_elem->type == type_era) {
            length = scale_elem->elem.era.length;
        }
    }
    return length;
}

// returns the type of ScaleElem
// @param `scale_elem` points to a SCALE struct
enum ScaleTypes get_scale_type(const ScaleElem *scale_elem) {
    if (scale_elem) {
        return scale_elem->type;
    } else {
        return type_invalid;
    }
}

// Receives a pointer to a ScaleElem and a pointer to a buffer of size `get_scale_length(ScaleElem* scale_elem)`.
// Fills the buffer with the raw bytes of a SCALE-encoded struct
// @return 0/1 if success/failure
// @param `scale_elem` the SCALE struct
// @param `value` should be a pre-allocated buffer with size SCALE_COMPACT_MAX
// @param `value_len` the amount of bytes written to `value`
uint8_t get_scale_value(const ScaleElem* scale_elem, uint8_t* value, uint8_t value_len) {

    if ( (scale_elem != NULL) && (value != NULL) ) {
        uint8_t scale_len = get_scale_length(scale_elem);
        if (value_len == scale_len) {
            if (scale_elem->type == type_compact) {
                SUBSTRATE_MEMCPY(value, scale_elem->elem.compact.value, value_len);
            } else if (scale_elem->type == type_bool) {
                ScaleBoolean b = scale_elem->elem.boolean;
                SUBSTRATE_MEMCPY(value, &b.value, value_len);
            } else if (scale_elem-> type == type_era) {
                SUBSTRATE_MEMCPY(value, scale_elem->elem.era.value, value_len);
            }
            return 0;
        } else SUBSTRATE_PRINTF("get_scale_value: value_len != scale_len\n");
    } else SUBSTRATE_PRINTF("get_scale_value: failed\n");
    return 1;
}

// SCALE encoder of a boolean `value`
// @param `result` points to the resulting SCALE-encoded bool
// @param `value` the value to encode
void as_boolean(ScaleBoolean* result, uint8_t value) {
    if (result) {
        result->value = value & 0x01;
        result->length = 1;
        result->type = type_bool;
    }
}

// encodes `value` to its SCALE format
// @return 0/1 if success/failure
// @param `encoded_value` will contain the SCALE encoded. Must be pre-allocated.
// @param `value` is the *little endian* representation of the value to encode. 
// @param `value_len` the length of `value`. Should be lower than SCALE_COMPACT_MAX.
// @param `type` ScaleTypes to encode to.
uint8_t encode_scale(ScaleElem* encoded_value, uint8_t* value, size_t value_len, enum ScaleTypes type) {

    size_t squeezed_len;
    uint8_t failed = 1;

    if ((encoded_value) && (value) && (value_len > 0)) {
        if (type == type_compact) {

            if (value_len < SCALE_COMPACT_MAX) {
                Compact c;
                // we squeeze `value` in `squeezed_value` by removing trailing zeros
                // for instance 0x01123400 is squeezed to 0x011234
                // iterate for squeezed_len>1 to include the case `value == 0x00`
                for (squeezed_len=value_len; squeezed_len>1; squeezed_len--) {
                    if (value[squeezed_len-1] > 0x00) // first non-zero found
                        break;
                }
                if ( as_compact(&c, value, squeezed_len) == 0) {
                    // embed the Compact in a ScaleElem
                    SUBSTRATE_MEMSET(encoded_value->elem.compact.value, 0, SCALE_COMPACT_MAX);
                    encoded_value->type = type_compact;
                    (encoded_value->elem).compact.type = type_compact;
                    (encoded_value->elem).compact.length = c.length;
                    SUBSTRATE_MEMCPY((encoded_value->elem).compact.value, c.value, c.length);
                    failed = 0;
                }
            }

        } else if (type == type_bool) {
            if (value_len == 1) {
                ScaleBoolean b;
                as_boolean(&b, *value);
                // embed the Boolean in a ScaleElem
                encoded_value->type = type_bool;
                (encoded_value->elem).compact.type = type_bool;
                (encoded_value->elem).compact.length = b.length;
                SUBSTRATE_MEMCPY(&(encoded_value->elem).boolean.value, &b.value, b.length);
                failed = 0;
            }

        } else if (type == type_era) {

            if ((value_len == 1) && (value[0] == 0x00)) {
                // immortal transaction
                (encoded_value->elem).era.length = 1;
                (encoded_value->elem).era.value[0] = 0x00;
            } else if (value_len == 2) {
                (encoded_value->elem).era.length = 2;
                (encoded_value->elem).era.value[0] = value[0];
                (encoded_value->elem).era.value[1] = value[1];
            } else {
                return 1;
                SUBSTRATE_PRINTF("Era is wrong\n");
            }

            encoded_value->type = type_era;
            (encoded_value->elem).era.type = type_era;
            failed = 0;
        }
    }
    return failed;
}

// decodes a ScaleElem to the raw value
// returns 0 if success
// @param `scale_elem` the ScaleElem to be decoded
// @param `value` pointer to a buffer of size SCALE_COMPACT_MAX pre-allocated by the user
// @param `value_len` the number of bytes of `value` filled by this function
uint8_t decode_scale(const ScaleElem *scale_elem, uint8_t *value, size_t *value_len) {

    size_t consumed;
    uint8_t len;
    enum ScaleTypes t;

    if ((scale_elem != NULL) && (value != NULL)) {
        len = get_scale_length(scale_elem);
        if (len > 0) { // must contain a SCALE
            uint8_t encoded_value[len];
            if (get_scale_value(scale_elem, encoded_value, len) == 0) {
                t = get_scale_type(scale_elem);
                if (t!= type_invalid) { // must be valid SCALE type
                    SUBSTRATE_MEMSET(value, 0, SCALE_COMPACT_MAX);
                    if (decode_stream(encoded_value, value, len, value_len, &consumed, t) == 0)
                        if (consumed == len) // must consume all buffer 
                            return 0;
                }
            }
        }
    }
    return 1;
}

// decodes the stream of bytes `encoded_value`
// returns 0 if success
// @param `encoded_value` byte array to be decoded
// @param `encoded_value_len` length of `encoded_value`
// @param `type` SCALE type of `encoded_value`
// @param `decoded_value` byte array containing the decoded value. must be already allocated with size at least SCALE_COMPACT_MAX
// @param `decoded_value_len` number of bytes written to `decoded_value`
// @param `consumed` number of bytes of `encoded_value` used by this function. useful for sequential decoding of `encoded_value` stream
uint8_t decode_stream(const uint8_t* encoded_value, uint8_t* decoded_value, size_t encoded_value_len, size_t *decoded_value_len, size_t *consumed, enum ScaleTypes type) {

    if ((encoded_value == NULL) || (decoded_value == NULL) || (encoded_value_len == 0))
        return 1;

    if (type == type_compact) {
        const uint8_t mode = encoded_value[0] & 0x03;

        if (mode == 0b11u) {
            uint8_t bytes_enc = (encoded_value[0] >> 2) + 4;
            *decoded_value_len = bytes_enc;
            *consumed = bytes_enc + 1;
            if (*decoded_value_len <= SCALE_COMPACT_MAX) {
                if (encoded_value_len >= bytes_enc) {
                    SUBSTRATE_MEMCPY(decoded_value, &encoded_value[1], bytes_enc);
                    return 0;
                }
            }
            return 1;

        } else { // first three modes

            if (mode == 0b00u) {
                *decoded_value_len = 1;
                *consumed = 1;

            } else if (mode == 0b01u) {
                if (encoded_value_len > 1) {    
                    *decoded_value_len = 2;
                    *consumed = 2;
                } else return 1;

            } else if (mode == 0b10u) {
                if (encoded_value_len > 3) {
                    *decoded_value_len = 4;
                    *consumed = 4;
                } else return 1;

            } else {
                SUBSTRATE_PRINTF("Unresolved mode\n");
                return 1;
            }
            size_t pos = 0;
            size_t decoded_short = encoded_value[pos++];
            size_t shift = 256u;
            while (pos < *decoded_value_len) {
                decoded_short += (encoded_value[pos++]) * shift;
                shift = shift << 8;
            }
            decoded_short = decoded_short >> 2;
            SUBSTRATE_MEMCPY(decoded_value, &decoded_short, sizeof(size_t));            
            return 0;
        } // end first three modes

    } else if (type == type_era) {
        if (encoded_value[0] == 0x00) {
            decoded_value[0] = encoded_value[0];
            *decoded_value_len = 1;
            *consumed = 1;
        } else {
            if (encoded_value_len > 1) {
                decoded_value[0] = encoded_value[0];
                decoded_value[1] = encoded_value[1];
                *decoded_value_len = 2;
                *consumed = 2;
            } else return 1;
        }
        return 0;
    } else if (type == type_bool) {
        *decoded_value_len = 1;
        *consumed = 1;
        decoded_value[0] = encoded_value[0];
        return 0;
    }
    SUBSTRATE_PRINTF("Invalid SCALE type\n");
    return 1;
}
