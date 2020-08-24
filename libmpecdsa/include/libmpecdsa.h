#ifndef LIBMPECDSA_INCLUDE_H_
#define LIBMPECDSA_INCLUDE_H_

#include <stdint.h>

extern "C" {
#ifdef WIN32
typedef uint16_t codeunit;
#else
typedef uint8_t codeunit;
#endif

void *libmpecdsa_kengen_ctx_init(
        int32_t party_index,
        int32_t party_total,
        int32_t threshold
);

void *libmpecdsa_kengen_ctx_free(void *);

char *libmpecdsa_keygen_round1(
        void *ctx,
        int32_t *bc_length,
        int32_t *decom_length
);

char *libmpecdsa_keygen_round2(
        void *ctx,
        char *bcs,
        int32_t *bc_i_length,
        char *decoms,
        int32_t *decom_i_length,
        int32_t *ciphertexts_length
);

char *libmpecdsa_keygen_round3(
        void *ctx,
        char *ciphertexts,//exclude self
        int32_t *ciphertext_i_length, //size = party_total - 1
        int32_t *result_length //size = 1
);

char *libmpecdsa_keygen_round4(
        void *ctx,
        char *vss_schemes, //exclude self
        int32_t *vss_scheme_length, //size = party_total - 1
        int32_t result_length //size = 1
)


#endif
