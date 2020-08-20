#ifndef LIBMPECDSA_INCLUDE_H_
#define LIBMPECDSA_INCLUDE_H_

#include <stdint.h>

extern "C" {
#ifdef WIN32
typedef uint16_t codeunit;
#else
typedef uint8_t codeunit;
#endif

char *libmpecdsa_keygen_round1(int64_t input, int64_t *bc_lengt, int64_t *decom_length);

}

#endif
