#ifndef LIBMPECDSA_INCLUDE_H_
#define LIBMPECDSA_INCLUDE_H_

#include <stdint.h>

extern "C" {

    void *libmpecdsa_keygen_ctx_init(
            int32_t party_index, // >= 1
            int32_t party_total, // n
            int32_t threshold // t
    );

    void *libmpecdsa_keygen_ctx_free(void *);

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
            const char *bcs, // self included
            const int32_t *bc_i_length, // size = part_total
            const char *decoms, // self included
            const int32_t *decom_i_length, // size = party_total
            int32_t *ciphertexts_length // size = party_total - 1
    );

    // input ciphertexts, length of each party (exclude self) stored in ciphertext_i_length array.
    //return vss_scheme, its length stored in result_length.
    char *libmpecdsa_keygen_round3(
            void *ctx,
            const char *ciphertexts,//exclude self
            const int32_t *ciphertext_i_length //size = party_total - 1
    );

    //input vss_schemes, length of each party (exclude self) stored in vss_scheme_length array.
    //return dlog_proof, its length stored in result_length.
    // if error happens, return "", and length = 0
    char *libmpecdsa_keygen_round4(
            void *ctx,
            const char *vss_schemes, //exclude self
            const int32_t *vss_scheme_length //size = party_total - 1
    );

    // input dlog_proofs, length of each party stored in dlof_proof_length.
    // output keystore, its length stored in result_length
    // if error happens, return "", and length = 0
    char *libmpecdsa_keygen_round5(
            void *ctx,
            const char *dlog_proofs, // self included
            const int32_t *dlof_proof_length // size = party_total
    );


    // sign begin here
    void *libmpecdsa_sign_ctx_init(
            int32_t party_total,  // n
            int32_t threshold    //  t
    );

    void *libmpecdsa_sign_ctx_free(void *);

    //the output includes: commit || m_a
    char *libmpecdsa_sign_round1(
            void *ctx,
            const char *keygen_result,      //the keygen result
            const int32_t *signers,         //the parties involving in generating the signature
            int32_t signers_num,      //the number of signers, must be larger that threshold (t)
            int32_t *commit_length,   // the length of commit in the returned value, size = 1
            int32_t *m_a_k_length       // the length of m_a_k in the returned value, size = 1
    );

    //the output includes: m_b_gamma || m_b_wi, both have the size: signers_num - 1
    char *libmpecdsa_sign_round2(
            void *ctx,
            const char *commits,                //size = signers_num
            const int32_t *commits_length,      // size = signers_num
            const char *m_a_ks,                 // size = signers_num
            const int32_t *m_a_ks_length,       // size = signers_num
            int32_t *m_b_gamma_length,    // size = signers_num - 1
            int32_t *m_b_wi_length        // size = signers_num - 1
    );

    // the output includes: delta_i
    char *libmpecdsa_sign_round3(
            void *ctx,
            const char *m_b_gamma_rec,         // size = signers_num - 1
            const int32_t *m_b_gamma_length,   // size = signers_num - 1
            const char *m_b_wi_rec,            // size = signers_num - 1
            const int32_t *m_b_wi_rec_length   // size = signers_num - 1
    );

    // the output includes: decommit
    char *libmpecdsa_sign_round4(
            void *ctx,
            const char *delta_i_rec,    // size = signers_num
            const int32_t *delta_i_length   // size = signers_nun
    );

    // the output includes: R || R_dash || phase5_proof
    char *libmpecdsa_sign_round5(
            void *ctx,
            const char *decommit_rec,         // size = signers_num
            const int32_t *decommit_length,     // size = signers_num
            int32_t *r_dash_proof_length   // size = 3
    );

    //the output includes: S || homo_elgamal_proof || T_i
    char *libmpecdsa_sign_round6(
            void *ctx,
            const char *R_rec,           // size = signers_num
            const int32_t *R_length,     // size = signers_num
            const char *R_dash_rec,        // size = signers_num
            const int32_t *R_dash_length,       // size = signers_num
            const char *phase5_proof_rec,       // size = signers_num
            const int32_t *phase5_proof_length,  // size = signers_num
            int32_t *S_proof_T_length     // size =  3
    );


    //the output includes: local_sig || s_i
    char *libmpecdsa_sign_round7(
            void *ctx,
            const char *S_rec,           // size = signers_num
            const int32_t *S_length,          // size = singers_num
            const char *homo_proof_rec,          //size = signers_num
            const int32_t *homo_proof_length,    //size = signers_num
            const char *T_i_rec,                 // size = signers_num
            const int32_t *T_i_length,          // size = signers_num
            const char *message_hash               // the 32 hex byte of message hash
    );

    // the output includes: signature
    char *libmpecdsa_sign_round8(
            void *ctx,
            const char *local_sig_rec,           // size = signers_num
            const int32_t *local_sig_length     // size = signers_num
    );

}
#endif
