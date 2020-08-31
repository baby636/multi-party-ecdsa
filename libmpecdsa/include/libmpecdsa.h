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
        int32_t party_index, // >= 1
        int32_t party_total, // n
        int32_t threshold // t
);

void *libmpecdsa_kengen_ctx_free(void *);

// return bc || decom,
// their length stored in bc_length and decom_length respectively.
char *libmpecdsa_keygen_round1(
        void *ctx,
        int32_t *bc_length, // size = 1
        int32_t *decom_length // size = 1
);

//input bcs, length of each party stored in bc_i_length array.
//so do decoms.
//return ciphertexts, length of each party stored in ciphertexts_length array.
char *libmpecdsa_keygen_round2(
        void *ctx,
        char *bcs, // self included
        int32_t *bc_i_length, // size = part_total
        char *decoms, // self included
        int32_t *decom_i_length, // size = party_total
        int32_t *ciphertexts_length // size = party_total - 1
);

// input ciphertexts, length of each party (exclude self) stored in ciphertext_i_length array.
//return vss_scheme, its length stored in result_length.
char *libmpecdsa_keygen_round3(
        void *ctx,
        char *ciphertexts,//exclude self
        int32_t *ciphertext_i_length, //size = party_total - 1
        int32_t *result_length //size = 1
);

//input vss_schemes, length of each party (exclude self) stored in vss_scheme_length array.
//return dlog_proof, its length stored in result_length.
// if error happens, return "", and length = 0
char *libmpecdsa_keygen_round4(
        void *ctx,
        char *vss_schemes, //exclude self
        int32_t *vss_scheme_length, //size = party_total - 1
        int32_t *result_length //size = 1
);

// input dlog_proofs, length of each party stored in dlof_proof_length.
// output keystore, its length stored in result_length
// if error happens, return "", and length = 0
char *libmpecdsa_keygen_round5(
        void *ctx,
        char *dlog_proofs, // self included
        int32_t *dlof_proof_length, // size = party_total
        int32_t *result_length //size = 1
);

}
#endif
