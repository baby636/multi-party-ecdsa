extern crate curv;
extern crate libc;
extern crate multi_party_ecdsa;

use std::borrow::Borrow;
use std::ffi::{CStr, CString};
use std::ptr::slice_from_raw_parts;
use std::slice::from_raw_parts_mut;

use curv::{
    arithmetic::traits::Converter,
    BigInt,
    cryptographic_primitives::{
        proofs::sigma_dlog::DLogProof, secret_sharing::feldman_vss::VerifiableSS,
    },
    elliptic::curves::traits::{ECPoint, ECScalar}, FE, GE,
};
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof;
use curv::elliptic::curves::secp256_k1::Secp256k1Point;
use libc::c_char;
use paillier::EncryptionKey;
use zk_paillier::zkproofs::DLogStatement;

use lib::{AEAD, aes_decrypt, aes_encrypt};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::{
    KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys, LocalSignature, Parameters, PartyPrivate,
    SharedKeys, SignatureRecid, SignBroadcastPhase1, SignDecommitPhase1, SignKeys,
};
use multi_party_ecdsa::utilities::mta::{MessageA, MessageB};
use multi_party_ecdsa::utilities::zk_pdl_with_slack::PDLwSlackProof;

mod lib;

pub struct KeygenContext {
    party_index: u16,
    party_keys: Keys,
    params: Parameters,
    shared_keys: SharedKeys,
    vss_scheme_vec: Vec<VerifiableSS>,
    dlog_statements: Vec<DLogStatement>,
    //Paillier encryption keys
    paillier_ek_vec: Vec<EncryptionKey>,
    y_sum: GE,
    enc_keys: Vec<BigInt>,
    party_shares: Vec<FE>,
    decoms_y_i: Vec<GE>,
}

pub fn read_char(input: *const c_char) -> Option<String> {
    let output = unsafe { CStr::from_ptr(input) }.to_str();
    match output {
        Ok(s) => {
            Some(s.to_string())
        }
        Err(e) => {
            None
        }
    }
}

#[no_mangle]
pub extern "system" fn libmpecdsa_keygen_ctx_init(
    party_index: i32,
    party_total: i32,
    threshold: i32,
) -> *mut KeygenContext {
    assert!(party_index > 0, "party index must be positive.");
    assert!(party_index <= party_total, "party index must be less than party_total.");
    assert!(threshold > 0, "threshold must be positive.");
    assert!(threshold < party_total, "threshold must be less than party_total.");

    let ctx = Box::new(KeygenContext {
        party_index: party_index as u16,
        party_keys: Keys::create(0),
        params: Parameters {
            threshold: threshold as u16,
            share_count: party_total as u16,
        },
        shared_keys: SharedKeys {
            y: GE::base_point2(),
            x_i: FE::zero(),
        },
        vss_scheme_vec: Vec::with_capacity(party_total as usize),
        dlog_statements: Vec::with_capacity(party_total as usize),
        paillier_ek_vec: Vec::with_capacity(party_total as usize),
        y_sum: GE::base_point2(),
        enc_keys: Vec::with_capacity((party_total - 1) as usize),
        party_shares: Vec::with_capacity(party_total as usize),
        decoms_y_i: Vec::with_capacity(party_total as usize),
    });

    Box::into_raw(ctx)
}

#[no_mangle]
pub extern "system" fn libmpecdsa_keygen_ctx_free(ctx: *mut KeygenContext) {
    drop(unsafe { Box::from_raw(ctx) });
}

//return { bc || decom }
#[no_mangle]
pub extern "system" fn libmpecdsa_keygen_round1(
    ctx: *mut KeygenContext,
    bc_length: *mut i32, //size = 1
    decom_length: *mut i32, // size = 1
) -> *mut c_char {
    let party_index = unsafe { &*ctx }.party_index;
    //It's better to use create_safe_prime, however it's extraordinarily inefficient.
    // let party_keys = Keys::create_safe_prime(party_index as usize);
    unsafe { &mut *ctx }.party_keys = Keys::create(party_index as usize);
    let (bc_i, decom_i) = unsafe { &*ctx }.party_keys
        .phase1_broadcast_phase3_proof_of_correct_key_proof_of_correct_h1h2();

    let bc = serde_json::to_string(&bc_i).unwrap();
    unsafe {
        *bc_length = bc.len() as i32;
    }
    let decom = serde_json::to_string(&decom_i).unwrap();
    unsafe {
        *decom_length = decom.len() as i32;
    }

    let mut result = String::new();
    result.push_str(&bc);
    result.push_str(&decom);

    CString::new(result).unwrap().into_raw()
}

// return ciphertexts,  and each length listed in  ciphertexts_length
#[no_mangle]
pub extern "system" fn libmpecdsa_keygen_round2(
    ctx: *mut KeygenContext,
    bcs: *const c_char, //self included
    bc_i_length: *const i32, //size = party_total
    decoms: *const c_char, //self included
    decom_i_length: *const i32, //size = party_total
    ciphertexts_length: *mut i32, //size = party_total - 1
) -> *mut c_char {
    let party_total = unsafe { &*ctx }.params.share_count;
    let threshold = unsafe { &*ctx }.params.threshold;
    let party_index = unsafe { &*ctx }.party_index;
    let party_keys = unsafe { &*ctx }.party_keys.clone();

    let mut j = 0;
    let mut decom_vec: Vec<KeyGenDecommitMessage1> = Vec::new();

    let decom_i_lenth_array = slice_from_raw_parts(decom_i_length, party_total as usize);
    let decoms_str = match read_char(decoms) {
        Some(s) => s,
        None => return std::ptr::null_mut() as *mut c_char
    };

    for i in 1..=party_total {
        let current_party_length = unsafe { &*decom_i_lenth_array }[(i - 1) as usize] as usize;
        let decom_j: KeyGenDecommitMessage1 = match serde_json::from_str(&decoms_str[j..j + current_party_length]) {
            Ok(r) => r,
            Err(_) => return std::ptr::null_mut() as *mut c_char
        };
        unsafe { &mut *ctx }.decoms_y_i.push(decom_j.y_i);
        decom_vec.push(decom_j.clone());
        if i != party_index {
            unsafe { &mut *ctx }.enc_keys.push(
                match (decom_j.y_i.clone() * party_keys.u_i).x_coor() {
                    Some(r) => r,
                    None => return std::ptr::null_mut() as *mut c_char
                }
            );
        }
        j = j + current_party_length;
    }

    let (head, tail) = unsafe { &mut *ctx }.decoms_y_i.split_at(1);
    unsafe { &mut *ctx }.y_sum = tail.iter().fold(head[0], |acc, x| acc + x);

    let bc_i_length_array = slice_from_raw_parts(bc_i_length, party_total as usize);

    let bcs_str = match read_char(bcs) {
        Some(s) => s,
        None => return std::ptr::null_mut() as *mut c_char
    };

    let mut bc_vec: Vec<KeyGenBroadcastMessage1> = Vec::new();
    j = 0;
    for i in 0..party_total as usize {
        let current_party_length = unsafe { &*bc_i_length_array }[i] as usize;
        let bc_i: KeyGenBroadcastMessage1 = match serde_json::from_str(&bcs_str[j..j + current_party_length]) {
            Ok(r) => r,
            Err(_) => return std::ptr::null_mut() as *mut c_char
        };

        unsafe { &mut *ctx }.paillier_ek_vec.push(bc_i.e.clone());
        unsafe { &mut *ctx }.dlog_statements.push(bc_i.dlog_statement.clone());
        bc_vec.insert(i, bc_i);
        j = j + current_party_length;
    }

    let params = Parameters {
        threshold: threshold,
        share_count: party_total,
    };
    // let (vss_scheme, secret_shares, _index) =
    match party_keys.phase1_verify_com_phase3_verify_correct_key_verify_dlog_phase2_distribute(
        &params,
        &decom_vec,
        &bc_vec,
    ) {
        Ok((vss_scheme, secret_shares, _)) => {
            // push self
            unsafe { &mut *ctx }.vss_scheme_vec.push(vss_scheme);
            unsafe { &mut *ctx }.party_shares.push(secret_shares[(party_index - 1) as usize]);

            let mut result = String::new();
            let ciphertext_i_length: &mut [i32] = unsafe { from_raw_parts_mut(ciphertexts_length, (party_total - 1) as usize) };
            j = 0;
            for (k, i) in (1..=party_total).enumerate() {
                if i != party_index {
                    // prepare encrypted ss for party i:
                    let mut key_i = BigInt::to_vec(unsafe { &*ctx }.enc_keys[j].borrow());
                    while key_i.len() < 32 {
                        key_i.insert(0, 0);
                    }
                    let plaintext = BigInt::to_vec(&secret_shares[k].to_big_int());
                    let aead_pack_i = aes_encrypt(&key_i, &plaintext);

                    let aead_pack_i_serialized = serde_json::to_string(&aead_pack_i).unwrap();
                    ciphertext_i_length[j] = aead_pack_i_serialized.len() as i32;

                    result.push_str(&aead_pack_i_serialized);
                    j += 1;
                }
            }

            CString::new(result).unwrap().into_raw()
        }
        Err(_) => {
            std::ptr::null_mut() as *mut c_char
        }
    }
}

#[no_mangle]
pub extern "system" fn libmpecdsa_keygen_round3(
    ctx: *mut KeygenContext,
    ciphertexts: *const c_char,// exclude self
    ciphertext_i_length: *const i32,//size = party_total - 1
) -> *mut c_char {
    let party_total = unsafe { &*ctx }.params.share_count as usize;
    let party_index = unsafe { &*ctx }.party_index as usize;
    let ciphertext_i_length_array = slice_from_raw_parts(ciphertext_i_length, party_total);
    let ciphertexts_str = match read_char(ciphertexts) {
        Some(s) => s,
        None => return std::ptr::null_mut() as *mut c_char
    };

    let mut j = 0;
    let mut index: usize = 0;
    let secret_share = unsafe { &*ctx }.party_shares[0].clone();
    unsafe { &mut *ctx }.party_shares.clear();

    for i in 1..=party_total {
        if i == party_index {
            unsafe { &mut *ctx }.party_shares.push(secret_share);
        } else {
            let current_party_length = unsafe { &*ciphertext_i_length_array }[j] as usize;
            let aead_pack: AEAD = match serde_json::from_str(&ciphertexts_str[index..index + current_party_length]) {
                Ok(r) => r,
                Err(_) => return std::ptr::null_mut() as *mut c_char
            };
            let enc_key_i = unsafe { &*ctx }.enc_keys[j].clone();
            let mut key_i = BigInt::to_vec(&enc_key_i);
            while key_i.len() < 32 {
                key_i.insert(0, 0);
            }
            let out = aes_decrypt(&key_i, aead_pack);
            let out_bn = BigInt::from(&out[..]);
            let out_fe = ECScalar::from(&out_bn);
            unsafe { &mut *ctx }.party_shares.push(out_fe);

            j += 1;
            index += current_party_length;
        }
    }

    //return vss commitments
    assert!(unsafe { &*ctx }.vss_scheme_vec.len() == 1);
    let vss_scheme = unsafe { &*ctx }.vss_scheme_vec[0].clone();
    let result = serde_json::to_string(&vss_scheme).unwrap();

    CString::new(result).unwrap().into_raw()
}

#[no_mangle]
pub extern "system" fn libmpecdsa_keygen_round4(
    ctx: *mut KeygenContext,
    vss_schemes: *const c_char, //exclude self
    vss_scheme_length: *const i32, //size = party_total - 1
) -> *mut c_char {
    let party_index = unsafe { &*ctx }.party_index as usize;
    let party_total = unsafe { &*ctx }.params.share_count as usize;
    let vss_i_length_array = slice_from_raw_parts(vss_scheme_length, party_total);

    let vss_schemes_str = match read_char(vss_schemes) {
        Some(s) => s,
        None => return std::ptr::null_mut() as *mut c_char
    };

    let mut j = 0;
    let mut index = 0;
    for i in 1..=party_total {
        if i != party_index {
            let length = unsafe { &*vss_i_length_array }[j] as usize;
            let vss_scheme_j: VerifiableSS = match serde_json::from_str(&vss_schemes_str[index..index + length]) {
                Ok(r) => r,
                Err(_) => return std::ptr::null_mut() as *mut c_char
            };
            if i < party_total {
                unsafe { &mut *ctx }.vss_scheme_vec.insert(i - 1, vss_scheme_j);
            } else {
                unsafe { &mut *ctx }.vss_scheme_vec.push(vss_scheme_j);
            }
            j += 1;
            index += length;
        }
    }
    let mut tmp_ctx = unsafe { &mut *ctx };
    match tmp_ctx.party_keys
        .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
            &tmp_ctx.params,
            &tmp_ctx.decoms_y_i,
            &tmp_ctx.party_shares,
            &tmp_ctx.vss_scheme_vec,
            party_index,
        ) {
        Ok((shared_keys, dlog_proof)) => {
            let dlog_proof_str = serde_json::to_string(&dlog_proof).unwrap();
            tmp_ctx.shared_keys = shared_keys;

            CString::new(dlog_proof_str).unwrap().into_raw()
        }
        Err(_) => {
            std::ptr::null_mut() as *mut c_char
        }
    }
}

#[no_mangle]
pub extern "system" fn libmpecdsa_keygen_round5(
    ctx: *mut KeygenContext,
    dlog_proofs: *const c_char, //self included
    dlog_proof_length: *const i32, //size = party_total
) -> *mut c_char {
    let party_total = unsafe { &*ctx }.params.share_count as usize;

    let dlog_proof_length_array = slice_from_raw_parts(dlog_proof_length, party_total);
    let dlog_proofs_str = match read_char(dlog_proofs) {
        Some(s) => s,
        None => return std::ptr::null_mut() as *mut c_char
    };

    // TODO: check length of dlog_proofs_str satisfies.
    let mut index = 0;
    let mut dlog_proof_vec: Vec<DLogProof> = Vec::new();
    for i in 0..party_total {
        let length = unsafe { &*dlog_proof_length_array }[i] as usize;
        let dlog_proof_i: DLogProof = match serde_json::from_str(&dlog_proofs_str[index..index + length]) {
            Ok(r) => r,
            Err(_) => return std::ptr::null_mut() as *mut c_char
        };
        dlog_proof_vec.push(dlog_proof_i);
        index += length;
    }

    let tmp_ctx = unsafe { &mut *ctx };
    match Keys::verify_dlog_proofs(&tmp_ctx.params, &dlog_proof_vec, &tmp_ctx.decoms_y_i) {
        Ok(()) => {
            let result = serde_json::to_string(&(
                &tmp_ctx.party_keys,
                &tmp_ctx.shared_keys,
                &tmp_ctx.y_sum,
                &tmp_ctx.vss_scheme_vec,
                &tmp_ctx.paillier_ek_vec,
                &tmp_ctx.dlog_statements,
                tmp_ctx.party_index,
            )).unwrap();

            CString::new(result).unwrap().into_raw()
        }
        Err(_) => {
            std::ptr::null_mut() as *mut c_char
        }
    }
}

#[test]
fn libmpecdsa_keygen_test() {
    use std::fs;

    let ctx1 = libmpecdsa_keygen_ctx_init(1, 2, 1);
    let ctx2 = libmpecdsa_keygen_ctx_init(2, 2, 1);
    let mut bc1_length: i32 = 0;
    let mut decom1_length: i32 = 0;
    let mut bc2_length: i32 = 0;
    let mut decom2_length: i32 = 0;
    let str1_ptr = libmpecdsa_keygen_round1(ctx1, &mut bc1_length, &mut decom1_length);
    let str2_ptr = libmpecdsa_keygen_round1(ctx2, &mut bc2_length, &mut decom2_length);

    let mut bcs_string = String::new();
    let mut decoms_string = String::new();

    let str1_str = unsafe { CStr::from_ptr(str1_ptr) }
        .to_str()
        .expect("invalid str1_ptr")
        .to_string();

    bcs_string.push_str(&str1_str[..bc1_length as usize]);
    decoms_string.push_str(&str1_str[bc1_length as usize..]);

    assert_eq!(bc1_length + decom1_length, str1_str.len() as i32);
    let str2_str = unsafe { CStr::from_ptr(str2_ptr) }
        .to_str()
        .expect("invalid str2_ptr")
        .to_string();

    bcs_string.push_str(&str2_str[..bc2_length as usize]);
    decoms_string.push_str(&str2_str[bc2_length as usize..]);

    assert_eq!(bc2_length + decom2_length, str2_str.len() as i32);

    let mut ciphertext1_length = [0];
    let round2_str1_ptr = libmpecdsa_keygen_round2(
        ctx1,
        CString::new(bcs_string.clone()).unwrap().into_raw(),
        &[bc1_length, bc2_length][0],
        CString::new(decoms_string.clone()).unwrap().into_raw(),
        &[decom1_length, decom2_length][0],
        &mut ciphertext1_length[0],
    );

    let round2_ans1_str = unsafe { CStr::from_ptr(round2_str1_ptr) }
        .to_str()
        .expect("invalid round2_str1_ptr")
        .to_string();

    assert_eq!(ciphertext1_length[0], round2_ans1_str.len() as i32);
    // println!("round2 ans: length {:?}, {:?}", ciphertext_length[0], round2_ans_str);

    let mut ciphertext2_length = [0];
    let round2_str2_ptr = libmpecdsa_keygen_round2(
        ctx2,
        CString::new(bcs_string).unwrap().into_raw(),
        &[bc1_length, bc2_length][0],
        CString::new(decoms_string).unwrap().into_raw(),
        &[decom1_length, decom2_length][0],
        &mut ciphertext2_length[0],
    );

    let round2_ans2_str = unsafe { CStr::from_ptr(round2_str2_ptr) }
        .to_str()
        .expect("invalid round2_str2_ptr")
        .to_string();

    assert_eq!(ciphertext2_length[0], round2_ans2_str.len() as i32);
    // println!("round2 ans: length {:?}, {:?}", ciphertext_length[0], round2_ans_str);

    //round3 party1
    let round3_ans1_ptr = libmpecdsa_keygen_round3(
        ctx1,
        CString::new(round2_ans2_str).unwrap().into_raw(),
        &ciphertext2_length[0],
    );

    let round3_ans1_str = unsafe { CStr::from_ptr(round3_ans1_ptr) }
        .to_str()
        .expect("invalid round3_ans1_ptr")
        .to_string();

    // println!("round3_ans1_str {:?}", round3_ans1_str);
    let round3_ans1_len = [round3_ans1_str.len() as i32];

    //round3 party2
    let round3_ans2_ptr = libmpecdsa_keygen_round3(
        ctx2,
        CString::new(round2_ans1_str).unwrap().into_raw(),
        &ciphertext1_length[0],
    );

    let round3_ans2_str = unsafe { CStr::from_ptr(round3_ans2_ptr) }
        .to_str()
        .expect("invalid round3_ans2_ptr");

    // println!("round3_ans2_str {:?}", round3_ans2_str);
    let round3_ans2_len = [round3_ans2_str.len() as i32];

    let round4_ans1_ptr = libmpecdsa_keygen_round4(
        ctx1,
        CString::new(round3_ans2_str).unwrap().into_raw(),
        &round3_ans2_len[0],
    );

    let round4_ans1_str = unsafe { CString::from_raw(round4_ans1_ptr).into_string().unwrap() };
    // println!("round4_ans1_str {:?}", round4_ans1_str);

    let round4_ans2_ptr = libmpecdsa_keygen_round4(
        ctx2,
        CString::new(round3_ans1_str).unwrap().into_raw(),
        &round3_ans1_len[0],
    );

    let round4_ans2_str = unsafe { CString::from_raw(round4_ans2_ptr).into_string().unwrap() };
    // println!("round4_ans2_str {:?}", round4_ans2_str);

    //round 5
    let mut dlog_proofs = String::new();
    dlog_proofs.push_str(&round4_ans1_str);
    dlog_proofs.push_str(&round4_ans2_str);
    let dlog_proof_length = [round4_ans1_str.len() as i32, round4_ans2_str.len() as i32];

    let round5_ans1_ptr = libmpecdsa_keygen_round5(
        ctx1,
        CString::new(dlog_proofs.clone()).unwrap().into_raw(),
        &dlog_proof_length[0],
    );

    let round5_ans1_str = unsafe { CString::from_raw(round5_ans1_ptr).into_string().unwrap() };
    // println!("round5_ans1_str {:?}", round5_ans1_str);
    assert!(round5_ans1_str.len() > 0);
    fs::write("keys1.store", round5_ans1_str).expect("Unable to save.");

    let round5_ans2_ptr = libmpecdsa_keygen_round5(
        ctx2,
        CString::new(dlog_proofs).unwrap().into_raw(),
        &dlog_proof_length[0],
    );

    let round5_ans2_str = unsafe { CString::from_raw(round5_ans2_ptr).into_string().unwrap() };
    // println!("round5_ans2_str {:?}", round5_ans2_str);
    assert!(round5_ans2_str.len() > 0);
    fs::write("keys2.store", round5_ans2_str).expect("Unable to save.");

    libmpecdsa_keygen_ctx_free(ctx1);
    libmpecdsa_keygen_ctx_free(ctx2);
}

// Sign
pub struct SignContext {
    party_total: u16,
    threshold: u16,
    party_index: u16, //start from 1 to n
    party_keys: Keys,
    y_sum: GE,         // public key of x
    vss_scheme_vec: Vec<VerifiableSS>,
    paillier_ek_vec: Vec<EncryptionKey>,
    dlog_statements: Vec<DLogStatement>,
    signers_vec: Vec<usize>,
    signer_num: usize,
    signer_index: usize, // start from 0 to signers_vec.len() - 1
    sign_keys: SignKeys,
    commit_phase1_vec: Vec<SignBroadcastPhase1>,
    m_a_k_vec: Vec<MessageA>,
    decommit_phase1: SignDecommitPhase1,
    m_a_randomness: BigInt,
    gamma_beta_vec: Vec<FE>,
    wi_beta_vec: Vec<FE>,
    m_b_gamma_rec_vec: Vec<MessageB>,
    sigma_i: FE,
    delta_inv: FE,
    T_i: GE,
    l_i: FE,
    R_vec: Vec<GE>,
    R_dash_vec: Vec<Secp256k1Point>,
    S_vec: Vec<GE>,
}

#[no_mangle]
pub extern "system" fn libmpecdsa_sign_ctx_init(
    party_total: i32,
    threshold: i32,
) -> *mut SignContext {
    assert!(threshold > 0, "threshold must be positive.");
    assert!(threshold < party_total, "threshold must be less than party_total.");

    let ctx = Box::new(SignContext {
        party_total: party_total as u16,
        threshold: threshold as u16,
        party_index: 0,
        party_keys: Keys::create(0),
        y_sum: GE::base_point2(),
        vss_scheme_vec: Vec::with_capacity(party_total as usize),
        paillier_ek_vec: Vec::<EncryptionKey>::with_capacity(party_total as usize),
        dlog_statements: Vec::with_capacity(party_total as usize),
        signers_vec: Vec::with_capacity(party_total as usize),
        signer_num: 0,
        signer_index: 0,
        sign_keys: SignKeys {
            w_i: FE::zero(),
            g_w_i: GE::base_point2(),
            k_i: FE::zero(),
            gamma_i: FE::zero(),
            g_gamma_i: GE::base_point2(),
        },
        commit_phase1_vec: Vec::with_capacity(party_total as usize),
        m_a_k_vec: Vec::with_capacity(party_total as usize),
        decommit_phase1: SignDecommitPhase1 {
            blind_factor: BigInt::zero(),
            g_gamma_i: GE::base_point2(),
        },
        m_a_randomness: BigInt::zero(),
        gamma_beta_vec: Vec::with_capacity(party_total as usize),
        wi_beta_vec: Vec::with_capacity(party_total as usize),
        m_b_gamma_rec_vec: Vec::with_capacity(party_total as usize),  //size = signer_num - 1
        sigma_i: FE::zero(),
        delta_inv: FE::zero(),
        T_i: GE::base_point2(),
        l_i: FE::zero(),
        R_vec: Vec::with_capacity(party_total as usize), //size  = signer_num
        R_dash_vec: Vec::with_capacity(party_total as usize), //size = signer_num
        S_vec: Vec::with_capacity(party_total as usize), //size = signer_num
    });

    Box::into_raw(ctx)
}

#[no_mangle]
pub extern "system" fn libmpecdsa_sign_ctx_free(ctx: *mut SignContext) {
    drop(unsafe { Box::from_raw(ctx) });
}

#[no_mangle]
pub extern "system" fn libmpecdsa_sign_round1(
    ctx: *mut SignContext,
    keygen_result: *const c_char,
    signers: *const i32,
    signers_num: i32,
    commit_length: *mut i32,
    m_a_length: *mut i32,
) -> *mut c_char {
    let keygen_result_str = match read_char(keygen_result) {
        Some(s) => s,
        None => return std::ptr::null_mut() as *mut c_char
    };
    let (
        party_keys,
        shared_keys,
        y_sum,
        vss_scheme_vec,
        paillier_ek_vec,
        dlog_statements,
        party_index,
    ): (
        Keys,
        SharedKeys,
        GE,
        Vec<VerifiableSS>,
        Vec<EncryptionKey>,
        Vec<DLogStatement>,
        u16,
    ) = match serde_json::from_str(&keygen_result_str) {
        Ok(r) => r,
        Err(_) => return std::ptr::null_mut() as *mut c_char
    };

    let mut tmp_ctx = unsafe { &mut *ctx };
    assert!(party_index > 0, "party index must be positive.");
    assert!(party_index <= tmp_ctx.party_total, "party index must be less than party_total.");
    assert!(signers_num as u16 > tmp_ctx.threshold, "the number of signers must be larger than threshold");
    assert!(signers_num as u16 <= tmp_ctx.party_total, "the number of signers must be less than party_total");

    tmp_ctx.party_index = party_index;
    tmp_ctx.party_keys = party_keys.clone();
    tmp_ctx.y_sum = y_sum;
    tmp_ctx.vss_scheme_vec = vss_scheme_vec.clone();
    tmp_ctx.paillier_ek_vec = paillier_ek_vec;
    tmp_ctx.dlog_statements = dlog_statements;


    let signers_num = signers_num as usize;

    let signers_array = slice_from_raw_parts(signers, signers_num);
    let mut signers_vec: Vec<usize> = Vec::with_capacity(signers_num);
    unsafe {
        signers_vec.set_len(signers_num)
    };
    let mut is_self_included = false;
    for i in 0..signers_num {
        signers_vec[i] = unsafe { &*signers_array }[i] as usize;
        if signers_vec[i] == (tmp_ctx.party_index - 1) as usize {
            tmp_ctx.signer_index = i;
            is_self_included = true;
        }
    }
    if !is_self_included {
        return std::ptr::null_mut() as *mut c_char;
    }
    tmp_ctx.signers_vec = signers_vec.clone();
    tmp_ctx.signer_num = signers_num;

    let private = PartyPrivate::set_private(party_keys.clone(), shared_keys);
    let sign_keys = SignKeys::create(
        &private,
        &vss_scheme_vec[signers_vec[tmp_ctx.signer_index]],
        signers_vec[tmp_ctx.signer_index],
        &signers_vec,
    );
    tmp_ctx.sign_keys = sign_keys.clone();
    let (commit_phase1, decommit_phase1) = sign_keys.phase1_broadcast();
    let (m_a_k, m_a_randomness) = MessageA::a(
        &sign_keys.k_i,
        &party_keys.ek,
    );
    tmp_ctx.decommit_phase1 = decommit_phase1;
    tmp_ctx.m_a_randomness = m_a_randomness;
    let commit_str = serde_json::to_string(&commit_phase1).unwrap();
    let m_a_k_str = serde_json::to_string(&m_a_k).unwrap();

    unsafe {
        *commit_length = commit_str.len() as i32;
        *m_a_length = m_a_k_str.len() as i32;
    }

    let mut result = String::new();
    result.push_str(&commit_str);
    result.push_str(&m_a_k_str);
    CString::new(result).unwrap().into_raw()
}

#[no_mangle]
pub extern "system" fn libmpecdsa_sign_round2(
    ctx: *mut SignContext,
    commits: *const c_char,
    commits_length: *const i32,  // size = signers_num
    m_a_ks: *const c_char,
    m_a_ks_length: *const i32,   // size = signers_num
    m_b_gamma_length: *mut i32,  // size = signers_num - 1
    m_b_wi_length: *mut i32,     // size  = signers-num - 1
) -> *mut c_char {
    let mut tmp_ctx = unsafe { &mut *ctx };
    let mut commit_vec: Vec<SignBroadcastPhase1> = Vec::new();
    let commits_length_array = slice_from_raw_parts(commits_length, tmp_ctx.signer_num);
    let commits_str = match read_char(commits) {
        Some(s) => s,
        None => return std::ptr::null_mut() as *mut c_char
    };
    let mut j = 0;
    for i in 0..tmp_ctx.signer_num {
        let current_length = unsafe { &*commits_length_array }[i] as usize;
        let commit: SignBroadcastPhase1 = match serde_json::from_str(&commits_str[j..j + current_length]) {
            Ok(r) => r,
            Err(_) => return std::ptr::null_mut() as *mut c_char
        };
        commit_vec.push(commit);
        j = j + current_length;
    }
    tmp_ctx.commit_phase1_vec = commit_vec;


    let mut m_a_k_vec: Vec<MessageA> = Vec::new();
    let m_a_k_lenth_array = slice_from_raw_parts(m_a_ks_length, tmp_ctx.signer_num);
    let m_a_ks_str = match read_char(m_a_ks) {
        Some(s) => s,
        None => return std::ptr::null_mut() as *mut c_char
    };

    j = 0;
    for i in 0..tmp_ctx.signer_num {
        let current_length = unsafe { &*m_a_k_lenth_array }[i] as usize;
        let m_a_k: MessageA = match serde_json::from_str(&m_a_ks_str[j..j + current_length]) {
            Ok(r) => r,
            Err(_) => return std::ptr::null_mut() as *mut c_char
        };
        m_a_k_vec.push(m_a_k);
        j = j + current_length;
    }
    tmp_ctx.m_a_k_vec = m_a_k_vec.clone();

    let mut m_b_gamma_send_vec: Vec<MessageB> = Vec::new();
    let mut gamma_beta_vec: Vec<FE> = Vec::new();
    let mut m_b_w_send_vec: Vec<MessageB> = Vec::new();
    let mut wi_beta_vec: Vec<FE> = Vec::new();

    for i in 0..tmp_ctx.signer_num {
        if i != tmp_ctx.signer_index {
            let (m_b_gamma, beta_gamma, _, _) = MessageB::b(
                &tmp_ctx.sign_keys.gamma_i,
                &tmp_ctx.paillier_ek_vec[tmp_ctx.signers_vec[i]],
                m_a_k_vec[i].clone(),
            );
            let (m_b_w, beta_wi, _, _) = MessageB::b(
                &tmp_ctx.sign_keys.w_i,
                &tmp_ctx.paillier_ek_vec[tmp_ctx.signers_vec[i]],
                m_a_k_vec[i].clone(),
            );
            m_b_gamma_send_vec.push(m_b_gamma);
            m_b_w_send_vec.push(m_b_w);
            gamma_beta_vec.push(beta_gamma);
            wi_beta_vec.push(beta_wi);
        }
    }
    tmp_ctx.gamma_beta_vec = gamma_beta_vec;
    tmp_ctx.wi_beta_vec = wi_beta_vec;

    let mut result = String::new();
    let m_b_gamma_length: &mut [i32] = unsafe { from_raw_parts_mut(m_b_gamma_length, tmp_ctx.signer_num - 1) };
    for i in 0..tmp_ctx.signer_num - 1 {
        let m_b_gamma_str = serde_json::to_string(&m_b_gamma_send_vec[i]).unwrap();
        m_b_gamma_length[i] = m_b_gamma_str.len() as i32;
        result.push_str(&m_b_gamma_str);
    }

    let m_b_w_length: &mut [i32] = unsafe { from_raw_parts_mut(m_b_wi_length, tmp_ctx.signer_num - 1) };
    for i in 0..tmp_ctx.signer_num - 1 {
        let m_b_w_str = serde_json::to_string(&m_b_w_send_vec[i]).unwrap();
        m_b_w_length[i] = m_b_w_str.len() as i32;
        result.push_str(&m_b_w_str);
    }

    CString::new(result).unwrap().into_raw()
}

#[no_mangle]
pub extern "system" fn libmpecdsa_sign_round3(
    ctx: *mut SignContext,
    m_b_gamma_rec: *const c_char,
    m_b_gamma_length: *const i32, // size = signers_num - 1
    m_b_wi_rec: *const c_char,
    m_b_wi_rec_length: *const i32, // size = signers_num - 1
) -> *mut c_char {
    let mut tmp_ctx = unsafe { &mut *ctx };
    let mut m_b_gamma_rev_vec: Vec<MessageB> = Vec::new();
    let m_b_gamma_length_array = slice_from_raw_parts(m_b_gamma_length, tmp_ctx.signer_num - 1);
    let m_b_gamma_rec_str = match read_char(m_b_gamma_rec) {
        Some(s) => s,
        None => return std::ptr::null_mut() as *mut c_char
    };

    let mut j = 0;
    for i in 0..tmp_ctx.signer_num - 1 {
        let current_length = unsafe { &*m_b_gamma_length_array }[i] as usize;
        let m_b_gamma: MessageB = match serde_json::from_str(&m_b_gamma_rec_str[j..j + current_length]) {
            Ok(r) => r,
            Err(_) => return std::ptr::null_mut() as *mut c_char
        };
        m_b_gamma_rev_vec.push(m_b_gamma);
        j = j + current_length;
    }

    let mut m_b_wi_rec_vec: Vec<MessageB> = Vec::new();
    let m_b_wi_length_array = slice_from_raw_parts(m_b_wi_rec_length, tmp_ctx.signer_num - 1);
    let m_b_wi_rec_str = match read_char(m_b_wi_rec) {
        Some(s) => s,
        None => return std::ptr::null_mut() as *mut c_char
    };

    j = 0;
    for i in 0..tmp_ctx.signer_num - 1 {
        let current_length = unsafe { &*m_b_wi_length_array }[i] as usize;
        let m_b_wi: MessageB = match serde_json::from_str(&m_b_wi_rec_str[j..j + current_length]) {
            Ok(r) => r,
            Err(_) => return std::ptr::null_mut() as *mut c_char
        };
        m_b_wi_rec_vec.push(m_b_wi);
        j = j + current_length;
    }
    tmp_ctx.m_b_gamma_rec_vec = m_b_gamma_rev_vec.clone();

    let mut alpha_vec: Vec<FE> = Vec::new();
    let mut miu_vec: Vec<FE> = Vec::new();

    //TODO: identify these errors
    j = 0;
    let xi_com_vec = Keys::get_commitments_to_xi(&tmp_ctx.vss_scheme_vec);
    for i in 0..tmp_ctx.signer_num {
        if i != tmp_ctx.signer_index {
            let m_b = m_b_gamma_rev_vec[j].clone();
            let alpha_ij_gamma = match m_b.verify_proofs_get_alpha(&tmp_ctx.party_keys.dk, &tmp_ctx.sign_keys.k_i) {
                Ok(r) => r,
                Err(_) => return std::ptr::null_mut() as *mut c_char
            };
            let m_b = m_b_wi_rec_vec[j].clone();
            let alpha_ij_wi = match m_b.verify_proofs_get_alpha(&tmp_ctx.party_keys.dk, &tmp_ctx.sign_keys.k_i) {
                Ok(r) => r,
                Err(_) => return std::ptr::null_mut() as *mut c_char
            };
            alpha_vec.push(alpha_ij_gamma.0);
            miu_vec.push(alpha_ij_wi.0);
            let g_w_i = Keys::update_commitments_to_xi(
                &xi_com_vec[tmp_ctx.signers_vec[i]],
                &tmp_ctx.vss_scheme_vec[tmp_ctx.signers_vec[i]],
                tmp_ctx.signers_vec[i],
                &tmp_ctx.signers_vec,
            );
            if !(m_b.b_proof.pk == g_w_i) {
                return std::ptr::null_mut() as *mut c_char;
            }
            j = j + 1;
        }
    }

    let delta_i = tmp_ctx.sign_keys.phase2_delta_i(&alpha_vec, &tmp_ctx.gamma_beta_vec);
    let sigma_i = tmp_ctx.sign_keys.phase2_sigma_i(&miu_vec, &tmp_ctx.wi_beta_vec);
    tmp_ctx.sigma_i = sigma_i;
    let mut result = String::new();
    result.push_str(&serde_json::to_string(&delta_i).unwrap());
    CString::new(result).unwrap().into_raw()
}

#[no_mangle]
pub extern "system" fn libmpecdsa_sign_round4(
    ctx: *mut SignContext,
    delta_i_rec: *const c_char,
    delta_i_length: *const i32,
) -> *mut c_char {
    let mut tmp_ctx = unsafe { &mut *ctx };
    let mut delta_i_rec_vec: Vec<FE> = Vec::new();
    let delta_i_length_array = slice_from_raw_parts(delta_i_length, tmp_ctx.signer_num);
    let delta_i_rec_str = match read_char(delta_i_rec) {
        Some(s) => s,
        None => return std::ptr::null_mut() as *mut c_char
    };

    let mut j = 0;
    for i in 0..tmp_ctx.signer_num {
        let current_length = unsafe { &*delta_i_length_array }[i] as usize;
        let delta_i: FE = match serde_json::from_str(&delta_i_rec_str[j..j + current_length]) {
            Ok(r) => r,
            Err(_) => return std::ptr::null_mut() as *mut c_char
        };
        delta_i_rec_vec.push(delta_i);
        j = j + current_length;
    }
    let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_i_rec_vec);
    tmp_ctx.delta_inv = delta_inv;
    // all parties compute the T_i
    let (T_i, l_i) = SignKeys::phase3_compute_t_i(&tmp_ctx.sigma_i);
    tmp_ctx.T_i = T_i;
    tmp_ctx.l_i = l_i;

    let decommit_str = serde_json::to_string(&tmp_ctx.decommit_phase1).unwrap();
    CString::new(decommit_str).unwrap().into_raw()
}

#[no_mangle]
pub extern "system" fn libmpecdsa_sign_round5(
    ctx: *mut SignContext,
    decommit_rec: *const c_char,
    decommit_length: *const i32,
    r_dash_proof_length: *mut i32,
) -> *mut c_char {
    let tmp_ctx = unsafe { &mut *ctx };
    let mut decommit_rec_vec: Vec<SignDecommitPhase1> = Vec::new();
    let decommit_length_array = slice_from_raw_parts(decommit_length, tmp_ctx.signer_num);
    let decommit_rec_str = match read_char(decommit_rec) {
        Some(s) => s,
        None => return std::ptr::null_mut() as *mut c_char
    };

    let mut j = 0;
    for i in 0..tmp_ctx.signer_num {
        let current_length = unsafe { &*decommit_length_array }[i] as usize;
        let decommit: SignDecommitPhase1 = match serde_json::from_str(&decommit_rec_str[j..j + current_length]) {
            Ok(r) => r,
            Err(_) => return std::ptr::null_mut() as *mut c_char
        };
        decommit_rec_vec.push(decommit);
        j = j + current_length;
    }

    let b_proof_vec = (0..tmp_ctx.m_b_gamma_rec_vec.len())
        .map(|i| &tmp_ctx.m_b_gamma_rec_vec[i].b_proof)
        .collect::<Vec<&DLogProof>>();
    let R = match SignKeys::phase4(&tmp_ctx.delta_inv, &b_proof_vec, decommit_rec_vec, &tmp_ctx.commit_phase1_vec, tmp_ctx.signer_index) {
        Ok(r) => r,
        Err(_) => {
            return std::ptr::null_mut() as *mut c_char;
        }
    };

    let R_dash = R * tmp_ctx.sign_keys.k_i;
    let mut phase5_proof: Vec<PDLwSlackProof> = Vec::new();
    for j in 0..tmp_ctx.signer_num - 1 {
        let ind = if j < tmp_ctx.signer_index { j } else { j + 1 };
        let proof = LocalSignature::phase5_proof_pdl(
            &R_dash,
            &R,
            &tmp_ctx.m_a_k_vec[tmp_ctx.signer_index].c,
            &tmp_ctx.paillier_ek_vec[tmp_ctx.signers_vec[tmp_ctx.signer_index]],
            &tmp_ctx.sign_keys.k_i,
            &tmp_ctx.m_a_randomness,
            &tmp_ctx.party_keys,
            &tmp_ctx.dlog_statements[tmp_ctx.signers_vec[ind]],
        );
        phase5_proof.push(proof);
    }
    let mut result = String::new();
    let r_dash_proof_size: &mut [i32] = unsafe { from_raw_parts_mut(r_dash_proof_length, 3) };
    let R_str = serde_json::to_string(&R).unwrap();
    r_dash_proof_size[0] = R_str.len() as i32;
    result.push_str(&R_str);
    let R_dash_str = serde_json::to_string(&R_dash).unwrap();
    r_dash_proof_size[1] = R_dash_str.len() as i32;
    result.push_str(&R_dash_str);
    let proof_str = serde_json::to_string(&phase5_proof).unwrap();
    r_dash_proof_size[2] = proof_str.len() as i32;
    result.push_str(&proof_str);

    CString::new(result).unwrap().into_raw()
}

#[no_mangle]
pub extern "system" fn libmpecdsa_sign_round6(
    ctx: *mut SignContext,
    R_rec: *const c_char,
    R_length: *const i32,
    R_dash_rec: *const c_char,
    R_dash_length: *const i32,
    phase5_proof_rec: *const c_char,
    phase5_proof_length: *const i32,
    S_proof_T_length: *mut i32,
) -> *mut c_char {
    let mut tmp_ctx = unsafe { &mut *ctx };
    let mut R_rec_vec: Vec<GE> = Vec::new();
    let R_length_array = slice_from_raw_parts(R_length, tmp_ctx.signer_num);
    let R_rec_str = match read_char(R_rec) {
        Some(s) => s,
        None => return std::ptr::null_mut() as *mut c_char
    };

    let mut j = 0;
    for i in 0..tmp_ctx.signer_num {
        let current_length = unsafe { &*R_length_array }[i] as usize;
        let R: GE = match serde_json::from_str(&R_rec_str[j..j + current_length]) {
            Ok(r) => r,
            Err(_) => return std::ptr::null_mut() as *mut c_char
        };
        R_rec_vec.push(R);
        j = j + current_length;
    }
    tmp_ctx.R_vec = R_rec_vec;

    let mut R_dash_rec_vec: Vec<Secp256k1Point> = Vec::new();
    let R_dash_length_array = slice_from_raw_parts(R_dash_length, tmp_ctx.signer_num);
    let R_dash_rec_str = match read_char(R_dash_rec) {
        Some(s) => s,
        None => return std::ptr::null_mut() as *mut c_char
    };

    j = 0;
    for i in 0..tmp_ctx.signer_num {
        let current_length = unsafe { &*R_dash_length_array }[i] as usize;
        let R_dash: Secp256k1Point = match serde_json::from_str(&R_dash_rec_str[j..j + current_length]) {
            Ok(r) => r,
            Err(_) => return std::ptr::null_mut() as *mut c_char
        };
        R_dash_rec_vec.push(R_dash);
        j = j + current_length;
    }
    tmp_ctx.R_dash_vec = R_dash_rec_vec;

    let mut phase5_proof_rec_vec: Vec<Vec<PDLwSlackProof>> = Vec::new();
    let phase5_proof_length_array = slice_from_raw_parts(phase5_proof_length, tmp_ctx.signer_num);
    let phase5_proof_rec_str = match read_char(phase5_proof_rec) {
        Some(s) => s,
        None => return std::ptr::null_mut() as *mut c_char
    };

    j = 0;
    for i in 0..tmp_ctx.signer_num {
        let current_length = unsafe { &*phase5_proof_length_array }[i] as usize;
        let phase5_proof: Vec<PDLwSlackProof> = match serde_json::from_str(&phase5_proof_rec_str[j..j + current_length]) {
            Ok(r) => r,
            Err(_) => return std::ptr::null_mut() as *mut c_char
        };
        phase5_proof_rec_vec.push(phase5_proof);
        j = j + current_length;
    }

    for i in 0..tmp_ctx.signer_num {
        if i != tmp_ctx.signer_index {
            let phase5_verify_zk = LocalSignature::phase5_verify_pdl(
                &phase5_proof_rec_vec[i],
                &tmp_ctx.R_dash_vec[i],
                &tmp_ctx.R_vec[tmp_ctx.signer_index],
                &tmp_ctx.m_a_k_vec[i].c,
                &tmp_ctx.paillier_ek_vec[tmp_ctx.signers_vec[i]],
                &tmp_ctx.dlog_statements[..],
                &tmp_ctx.signers_vec,
                i,
            );
            if phase5_verify_zk.is_err() {
                return std::ptr::null_mut() as *mut c_char;
            }
        }
    }

    //each party must run the test
    let phase5_check = LocalSignature::phase5_check_R_dash_sum(&tmp_ctx.R_dash_vec);
    if phase5_check.is_err() {
        // initiate phase 5 blame protocol to learn which parties acted maliously.
        return std::ptr::null_mut() as *mut c_char;
    }

    //phase 6
    let (S, homo_elgamal_proof) = LocalSignature::phase6_compute_S_i_and_proof_of_consistency(
        &tmp_ctx.R_vec[tmp_ctx.signer_index],
        &tmp_ctx.T_i,
        &tmp_ctx.sigma_i,
        &tmp_ctx.l_i,
    );
    let mut result = String::new();
    let S_proof_T_size: &mut [i32] = unsafe { from_raw_parts_mut(S_proof_T_length, 3) };
    let S_str = serde_json::to_string(&S).unwrap();
    S_proof_T_size[0] = S_str.len() as i32;
    result.push_str(&S_str);
    let proof_str = serde_json::to_string(&homo_elgamal_proof).unwrap();
    S_proof_T_size[1] = proof_str.len() as i32;
    result.push_str(&proof_str);
    let T_i_str = serde_json::to_string(&tmp_ctx.T_i).unwrap();
    S_proof_T_size[2] = T_i_str.len() as i32;
    result.push_str(&T_i_str);

    CString::new(result).unwrap().into_raw()
}

#[no_mangle]
pub extern "system" fn libmpecdsa_sign_round7(
    ctx: *mut SignContext,
    S_rec: *const c_char,
    S_length: *const i32,
    homo_proof_rec: *const c_char,
    homo_proof_length: *const i32,
    T_i_rec: *const c_char,
    T_i_length: *const i32,
    message: *const c_char,
    sig_s_i_length: *mut i32,
) -> *mut c_char {
    let tmp_ctx = unsafe { &mut *ctx };
    let mut S_rec_vec: Vec<GE> = Vec::new();
    let S_length_array = slice_from_raw_parts(S_length, tmp_ctx.signer_num);
    let S_rec_str = match read_char(S_rec) {
        Some(s) => s,
        None => return std::ptr::null_mut() as *mut c_char
    };

    let mut j = 0;
    for i in 0..tmp_ctx.signer_num {
        let current_length = unsafe { &*S_length_array }[i] as usize;
        let S: GE = match serde_json::from_str(&S_rec_str[j..j + current_length]) {
            Ok(r) => r,
            Err(_) => return std::ptr::null_mut() as *mut c_char
        };
        S_rec_vec.push(S);
        j = j + current_length;
    }

    let mut homo_proof_rec_vec: Vec<HomoELGamalProof> = Vec::new();
    let homo_proof_length_array = slice_from_raw_parts(homo_proof_length, tmp_ctx.signer_num);
    let homo_proof_str = match read_char(homo_proof_rec) {
        Some(s) => s,
        None => return std::ptr::null_mut() as *mut c_char
    };

    j = 0;
    for i in 0..tmp_ctx.signer_num {
        let current_length = unsafe { &*homo_proof_length_array }[i] as usize;
        let homo_proof: HomoELGamalProof = match serde_json::from_str(&homo_proof_str[j..j + current_length]) {
            Ok(r) => r,
            Err(_) => return std::ptr::null_mut() as *mut c_char
        };
        homo_proof_rec_vec.push(homo_proof);
        j = j + current_length;
    }

    let mut T_i_rec_vec: Vec<GE> = Vec::new();
    let T_i_length_array = slice_from_raw_parts(T_i_length, tmp_ctx.signer_num);
    let T_i_rec_str = match read_char(T_i_rec) {
        Some(s) => s,
        None => return std::ptr::null_mut() as *mut c_char
    };

    j = 0;
    for i in 0..tmp_ctx.signer_num {
        let current_length = unsafe { &*T_i_length_array }[i] as usize;
        let T_i: GE = match serde_json::from_str(&T_i_rec_str[j..j + current_length]) {
            Ok(r) => r,
            Err(_) => return std::ptr::null_mut() as *mut c_char
        };
        T_i_rec_vec.push(T_i);
        j = j + current_length;
    }

    match LocalSignature::phase6_verify_proof(&S_rec_vec, &homo_proof_rec_vec, &tmp_ctx.R_vec, &T_i_rec_vec) {
        Ok(()) => (),
        Err(_) => {
            return std::ptr::null_mut() as *mut c_char;
        }
    };

    let phase6_check = LocalSignature::phase6_check_S_i_sum(&tmp_ctx.y_sum, &S_rec_vec);
    if phase6_check.is_err() {
        return std::ptr::null_mut() as *mut c_char;
    }

    let message_str = match read_char(message) {
        Some(s) => s,
        None => return std::ptr::null_mut() as *mut c_char
    };

    let message = match hex::decode(message_str.clone()) {
        Ok(x) => x,
        Err(_e) => message_str.as_bytes().to_vec(),
    };
    let message = &message[..];

    let message_bn = HSha256::create_hash(&[&BigInt::from(&message[..])]);
    let local_sig = LocalSignature::phase7_local_sig(
        &tmp_ctx.sign_keys.k_i,
        &message_bn,
        &tmp_ctx.R_vec[tmp_ctx.signer_index],
        &tmp_ctx.sigma_i,
        &tmp_ctx.y_sum,
    );
    let s_i = local_sig.s_i.clone();

    let mut result = String::new();
    let sig_s_i_size: &mut [i32] = unsafe { from_raw_parts_mut(sig_s_i_length, 2) };
    let local_sig_str = serde_json::to_string(&local_sig).unwrap();
    sig_s_i_size[0] = local_sig_str.len() as i32;
    result.push_str(&local_sig_str);
    let s_i_str = serde_json::to_string(&s_i).unwrap();
    sig_s_i_size[1] = s_i_str.len() as i32;
    result.push_str(&s_i_str);

    CString::new(result).unwrap().into_raw()
}

#[no_mangle]
pub extern "system" fn libmpecdsa_sign_round8(
    ctx: *mut SignContext,
    local_sig_rec: *const c_char,
    local_sig_length: *const i32,
    s_i_rec: *const c_char,
    s_i_length: *const i32,
) -> *mut c_char {
    let tmp_ctx = unsafe { &mut *ctx };
    let mut local_sig_vec: Vec<LocalSignature> = Vec::new();
    let local_sig_length_array = slice_from_raw_parts(local_sig_length, tmp_ctx.signer_num);
    let local_sig_str = match read_char(local_sig_rec) {
        Some(s) => s,
        None => return std::ptr::null_mut() as *mut c_char
    };

    let mut j = 0;
    for i in 0..tmp_ctx.signer_num {
        let current_length = unsafe { &*local_sig_length_array }[i] as usize;
        let local_sig: LocalSignature = match serde_json::from_str(&local_sig_str[j..j + current_length]) {
            Ok(r) => r,
            Err(_) => return std::ptr::null_mut() as *mut c_char
        };
        local_sig_vec.push(local_sig);
        j = j + current_length;
    }

    let mut s_i_vec: Vec<FE> = Vec::new();
    let s_i_length_array = slice_from_raw_parts(s_i_length, tmp_ctx.signer_num);
    let s_i_str = match read_char(s_i_rec) {
        Some(s) => s,
        None => return std::ptr::null_mut() as *mut c_char
    };

    let mut j = 0;
    for i in 0..tmp_ctx.signer_num {
        let current_length = unsafe { &*s_i_length_array }[i] as usize;
        let s_i: FE = match serde_json::from_str(&s_i_str[j..j + current_length]) {
            Ok(r) => r,
            Err(_) => return std::ptr::null_mut() as *mut c_char
        };
        s_i_vec.push(s_i);
        j = j + current_length;
    }

    assert_eq!(local_sig_vec[0].y, tmp_ctx.y_sum);
    let sig = local_sig_vec[0].output_signature(&s_i_vec[1..]);
    // test
    //error in phase 7:
    if sig.is_err() {
        return std::ptr::null_mut() as *mut c_char;
    }
    //for testing purposes: checking with a second verifier:

    let sig = sig.unwrap();

    CString::new(serde_json::to_string(&sig).unwrap()).unwrap().into_raw()
}


#[test]
fn libmpecdsa_sign_test() {
    use std::fs;
    use crate::lib::check_sig;

    let ctx1 = libmpecdsa_sign_ctx_init(2, 1);
    let ctx2 = libmpecdsa_sign_ctx_init(2, 1);


    // round 1
    let keygen_result1 = fs::read_to_string("keys1.store").unwrap();
    let keygen_result2 = fs::read_to_string("keys2.store").unwrap();

    let signers = [1, 0];
    let mut commit1_length: i32 = 0;
    let mut m_a_k1_length: i32 = 0;

    let mut commit2_length: i32 = 0;
    let mut m_a_k2_length: i32 = 0;
    let round1_ptr1 = libmpecdsa_sign_round1(
        ctx1,
        CString::new(keygen_result1).unwrap().into_raw(),
        &signers[0],
        2,
        &mut commit1_length,
        &mut m_a_k1_length,
    );

    let round1_ptr2 = libmpecdsa_sign_round1(
        ctx2,
        CString::new(keygen_result2).unwrap().into_raw(),
        &signers[0],
        2,
        &mut commit2_length,
        &mut m_a_k2_length,
    );

    let tmp_ctx1 = unsafe { &*ctx1 };
    let tmp_ctx2 = unsafe { &*ctx2 };
    assert_eq!(tmp_ctx1.party_index, 1);
    assert_eq!(tmp_ctx2.party_index, 2);
    assert_eq!(tmp_ctx1.signer_index, 1);
    assert_eq!(tmp_ctx2.signer_index, 0);

    let round1_str1 = unsafe { CString::from_raw(round1_ptr1).into_string().unwrap() };
    let round1_str2 = unsafe { CString::from_raw(round1_ptr2).into_string().unwrap() };

    let mut commits_string = String::new();
    let mut m_a_ks_string = String::new();
    //place the string according the signer index order
    commits_string.push_str(&round1_str2[..commit2_length as usize]);
    commits_string.push_str(&round1_str1[..commit1_length as usize]);
    m_a_ks_string.push_str(&round1_str2[commit2_length as usize..]);
    m_a_ks_string.push_str(&round1_str1[commit1_length as usize..]);
    assert_eq!((commit1_length + m_a_k1_length) as usize, round1_str1.len());

    assert_eq!((commit2_length + m_a_k2_length) as usize, round1_str2.len());

    //round 2
    let mut m_b_gamma1_length = [0];
    let mut m_b_wi1_length = [0];
    let round2_ptr1 = libmpecdsa_sign_round2(
        ctx1,
        CString::new(commits_string.clone()).unwrap().into_raw(),
        &[commit2_length, commit1_length][0],
        CString::new(m_a_ks_string.clone()).unwrap().into_raw(),
        &[m_a_k2_length, m_a_k1_length][0],
        &mut m_b_gamma1_length[0],
        &mut m_b_wi1_length[0],
    );
    let round2_str1 = unsafe { CString::from_raw(round2_ptr1).into_string().unwrap() };
    assert_eq!(m_b_gamma1_length[0] + m_b_wi1_length[0], round2_str1.len() as i32);

    let mut m_b_gamma2_length = [0];
    let mut m_b_wi2_length = [0];
    let round2_ptr2 = libmpecdsa_sign_round2(
        ctx2,
        CString::new(commits_string).unwrap().into_raw(),
        &[commit2_length, commit1_length][0],
        CString::new(m_a_ks_string).unwrap().into_raw(),
        &[m_a_k2_length, m_a_k1_length][0],
        &mut m_b_gamma2_length[0],
        &mut m_b_wi2_length[0],
    );
    let round2_str2 = unsafe { CString::from_raw(round2_ptr2).into_string().unwrap() };
    assert_eq!(m_b_gamma2_length[0] + m_b_wi2_length[0], round2_str2.len() as i32);

    //round 3
    let mut m_b_gamma1_string = String::new();
    let mut m_b_wi1_string = String::new();
    m_b_gamma1_string.push_str(&round2_str2[..m_b_gamma2_length[0] as usize]);
    m_b_wi1_string.push_str(&round2_str2[m_b_gamma2_length[0] as usize..]);
    let round3_ptr1 = libmpecdsa_sign_round3(
        ctx1,
        CString::new(m_b_gamma1_string).unwrap().into_raw(),
        &[m_b_gamma2_length[0]][0],
        CString::new(m_b_wi1_string).unwrap().into_raw(),
        &[m_b_wi2_length[0]][0],
    );
    let round3_str1 = unsafe { CString::from_raw(round3_ptr1).into_string().unwrap() };

    let mut m_b_gamma2_string = String::new();
    let mut m_b_wi2_string = String::new();
    m_b_gamma2_string.push_str(&round2_str1[..m_b_gamma1_length[0] as usize]);
    m_b_wi2_string.push_str(&round2_str1[m_b_gamma1_length[0] as usize..]);
    let round3_ptr2 = libmpecdsa_sign_round3(
        ctx2,
        CString::new(m_b_gamma2_string).unwrap().into_raw(),
        &[m_b_gamma1_length[0]][0],
        CString::new(m_b_wi2_string).unwrap().into_raw(),
        &[m_b_wi1_length[0]][0],
    );
    let round3_str2 = unsafe { CString::from_raw(round3_ptr2).into_string().unwrap() };
//    assert_eq!(round3_str1.len(), round3_str2.len());

    //round4
    let mut delta_i_rec = String::new();
    delta_i_rec.push_str(&round3_str2);
    delta_i_rec.push_str(&round3_str1);

    let round4_ptr1 = libmpecdsa_sign_round4(
        ctx1,
        CString::new(delta_i_rec.clone()).unwrap().into_raw(),
        &[round3_str2.len() as i32, round3_str1.len() as i32][0],
    );
    let round4_str1 = unsafe { CString::from_raw(round4_ptr1).into_string().unwrap() };

    let round4_ptr2 = libmpecdsa_sign_round4(
        ctx2,
        CString::new(delta_i_rec).unwrap().into_raw(),
        &[round3_str2.len() as i32, round3_str1.len() as i32][0],
    );
    let round4_str2 = unsafe { CString::from_raw(round4_ptr2).into_string().unwrap() };
//    assert_eq!(round4_str1.len(), round4_str2.len());

    //round 5
    let mut R_string = String::new();
    let mut R_dash_string = String::new();
    let mut proof_string = String::new();
    let mut r_dash_proof_length = [0, 0, 0];  // the size is fixed as 3
    let mut decommit_rec = String::new();
    decommit_rec.push_str(&round4_str2);
    decommit_rec.push_str(&round4_str1);
    let round5_ptr1 = libmpecdsa_sign_round5(
        ctx1,
        CString::new(decommit_rec.clone()).unwrap().into_raw(),
        &[round4_str2.len() as i32, round4_str1.len() as i32][0],
        &mut r_dash_proof_length[0],
    );
    let round5_str1 = unsafe { CString::from_raw(round5_ptr1).into_string().unwrap() };

    let mut r_dash_proof2_length = [0, 0, 0];  // the size is fixed as 3
    let round5_ptr2 = libmpecdsa_sign_round5(
        ctx2,
        CString::new(decommit_rec).unwrap().into_raw(),
        &[round4_str2.len() as i32, round4_str1.len() as i32][0],
        &mut r_dash_proof2_length[0],
    );
    let round5_str2 = unsafe { CString::from_raw(round5_ptr2).into_string().unwrap() };

    let mut i = r_dash_proof2_length[0] as usize;
    R_string.push_str(&round5_str2[..i]);
    let mut j = i + r_dash_proof2_length[1] as usize;
    R_dash_string.push_str(&round5_str2[i..j]);
    proof_string.push_str(&round5_str2[j..]);
    assert_eq!(j + r_dash_proof2_length[2] as usize, round5_str2.len());

    i = r_dash_proof_length[0] as usize;
    R_string.push_str(&round5_str1[..i]);
    j = i + r_dash_proof_length[1] as usize;
    R_dash_string.push_str(&round5_str1[i..j]);
    proof_string.push_str(&round5_str1[j..]);
    assert_eq!(j + r_dash_proof_length[2] as usize, round5_str1.len());

    //the R in each party is equal
    assert_eq!(&round5_str1[..r_dash_proof_length[0] as usize], &round5_str2[..r_dash_proof2_length[0] as usize]);

    //round 6
    let mut S_proof_T1_length = [0, 0, 0];
    let mut S_string = String::new();
    let mut homo_proof_string = String::new();
    let mut T_i_string = String::new();

    let round6_ptr1 = libmpecdsa_sign_round6(
        ctx1,
        CString::new(R_string.clone()).unwrap().into_raw(),
        &[r_dash_proof2_length[0], r_dash_proof_length[0]][0],
        CString::new(R_dash_string.clone()).unwrap().into_raw(),
        &[r_dash_proof2_length[1], r_dash_proof_length[1]][0],
        CString::new(proof_string.clone()).unwrap().into_raw(),
        &[r_dash_proof2_length[2], r_dash_proof_length[2]][0],
        &mut S_proof_T1_length[0],
    );
    let round6_str1 = unsafe { CString::from_raw(round6_ptr1).into_string().unwrap() };

    let mut S_proof_T2_length = [0, 0, 0];
    let round6_ptr2 = libmpecdsa_sign_round6(
        ctx2,
        CString::new(R_string).unwrap().into_raw(),
        &[r_dash_proof2_length[0], r_dash_proof_length[0]][0],
        CString::new(R_dash_string).unwrap().into_raw(),
        &[r_dash_proof2_length[1], r_dash_proof_length[1]][0],
        CString::new(proof_string).unwrap().into_raw(),
        &[r_dash_proof2_length[2], r_dash_proof_length[2]][0],
        &mut S_proof_T2_length[0],
    );
    let round6_str2 = unsafe { CString::from_raw(round6_ptr2).into_string().unwrap() };

    i = S_proof_T2_length[0] as usize;
    S_string.push_str(&round6_str2[..i]);
    j = i + S_proof_T2_length[1] as usize;
    homo_proof_string.push_str(&round6_str2[i..j]);
    T_i_string.push_str(&round6_str2[j..]);
    assert_eq!(j + S_proof_T2_length[2] as usize, round6_str2.len());

    i = S_proof_T1_length[0] as usize;
    S_string.push_str(&round6_str1[..i]);
    j = i + S_proof_T1_length[1] as usize;
    homo_proof_string.push_str(&round6_str1[i..j]);
    T_i_string.push_str(&round6_str1[j..]);
    assert_eq!(j + S_proof_T1_length[2] as usize, round6_str1.len());


    //round 7
    let mut local_sig_string = String::new();
    let mut s_i_string = String::new();
    let mut message: String = String::new();
    message.push_str("multi-party ecdsa signature");

    let mut sig_s_i1_length = [0, 0];
    let round7_ptr1 = libmpecdsa_sign_round7(
        ctx1,
        CString::new(S_string.clone()).unwrap().into_raw(),
        &[S_proof_T2_length[0], S_proof_T1_length[0]][0],
        CString::new(homo_proof_string.clone()).unwrap().into_raw(),
        &[S_proof_T2_length[1], S_proof_T1_length[1]][0],
        CString::new(T_i_string.clone()).unwrap().into_raw(),
        &[S_proof_T2_length[2], S_proof_T1_length[2]][0],
        CString::new(message.clone()).unwrap().into_raw(),
        &mut sig_s_i1_length[0],
    );
    let round7_str1 = unsafe { CString::from_raw(round7_ptr1).into_string().unwrap() };
    assert_eq!((sig_s_i1_length[0] + sig_s_i1_length[1]) as usize, round7_str1.len());

    let mut sig_s_i2_length = [0, 0];
    let round7_ptr2 = libmpecdsa_sign_round7(
        ctx2,
        CString::new(S_string).unwrap().into_raw(),
        &[S_proof_T2_length[0], S_proof_T1_length[0]][0],
        CString::new(homo_proof_string).unwrap().into_raw(),
        &[S_proof_T2_length[1], S_proof_T1_length[1]][0],
        CString::new(T_i_string).unwrap().into_raw(),
        &[S_proof_T2_length[2], S_proof_T1_length[2]][0],
        CString::new(message.clone()).unwrap().into_raw(),
        &mut sig_s_i2_length[0],
    );
    let round7_str2 = unsafe { CString::from_raw(round7_ptr2).into_string().unwrap() };
    assert_eq!((sig_s_i2_length[0] + sig_s_i2_length[1]) as usize, round7_str2.len());

    local_sig_string.push_str(&round7_str2[..sig_s_i2_length[0] as usize]);
    local_sig_string.push_str(&round7_str1[..sig_s_i1_length[0] as usize]);

    s_i_string.push_str(&round7_str2[sig_s_i2_length[0] as usize..]);
    s_i_string.push_str(&round7_str1[sig_s_i1_length[0] as usize..]);

    //round 8
    let round8_ptr1 = libmpecdsa_sign_round8(
        ctx1,
        CString::new(local_sig_string.clone()).unwrap().into_raw(),
        &[sig_s_i2_length[0], sig_s_i1_length[0]][0],
        CString::new(s_i_string.clone()).unwrap().into_raw(),
        &[sig_s_i2_length[1], sig_s_i1_length[1]][0],
    );
    let round8_str1 = unsafe { CString::from_raw(round8_ptr1).into_string().unwrap() };
    let sig1: SignatureRecid = serde_json::from_str(&round8_str1).unwrap();

    println!("R: {:?}", sig1.r.get_element());
    println!("s: {:?} \n", sig1.s.get_element());
    println!("recid: {:?} \n", sig1.recid.clone());

    let message = match hex::decode(message.clone()) {
        Ok(x) => x,
        Err(_e) => message.as_bytes().to_vec(),
    };
    let message = &message[..];

    let message_bn = HSha256::create_hash(&[&BigInt::from(&message[..])]);

    check_sig(&sig1.r, &sig1.s, &message_bn, &tmp_ctx1.y_sum);

    let round8_ptr2 = libmpecdsa_sign_round8(
        ctx2,
        CString::new(local_sig_string).unwrap().into_raw(),
        &[sig_s_i2_length[0], sig_s_i1_length[0]][0],
        CString::new(s_i_string).unwrap().into_raw(),
        &[sig_s_i2_length[1], sig_s_i1_length[1]][0],
    );
    let round8_str2 = unsafe { CString::from_raw(round8_ptr2).into_string().unwrap() };
    let sig2: SignatureRecid = serde_json::from_str(&round8_str2).unwrap();
    println!("R: {:?}", sig2.r.get_element());
    println!("s: {:?} \n", sig2.s.get_element());
    println!("recid: {:?} \n", sig2.recid.clone());
    check_sig(&sig2.r, &sig2.s, &message_bn, &tmp_ctx2.y_sum);
    let sig1_str = format!("{:?}", sig1);
    let sig2_str = format!("{:?}", sig2);
    assert_eq!(&sig1_str, &sig2_str);

    libmpecdsa_sign_ctx_free(ctx1);
    libmpecdsa_sign_ctx_free(ctx2);
}


