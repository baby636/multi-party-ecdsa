extern crate curv;
extern crate libc;
extern crate multi_party_ecdsa;

use std::borrow::Borrow;
use std::ffi::CString;
use std::ptr::slice_from_raw_parts;
use std::slice;

use curv::{
    arithmetic::traits::Converter,
    BigInt,
    cryptographic_primitives::{
        proofs::sigma_dlog::DLogProof, secret_sharing::feldman_vss::VerifiableSS,
    },
    elliptic::curves::traits::{ECPoint, ECScalar}, FE, GE,
};
use libc::c_char;
use paillier::EncryptionKey;
use zk_paillier::zkproofs::DLogStatement;

use lib::{AEAD, aes_decrypt, aes_encrypt};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::{
    KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys, Parameters, SharedKeys,
};

mod lib;

pub struct KeygenContext {
    party_index: u16,
    party_keys: Keys,
    params: Parameters,
    shared_keys: SharedKeys,
    vss_scheme_vec: Vec<VerifiableSS>,
    dlog_statements: Vec<DLogStatement>,
    paillier_ek_vec: Vec<EncryptionKey>, //Paillier encryption keys
    y_sum: GE,
    enc_keys: Vec<BigInt>,
    party_shares: Vec<FE>,
    decoms_y_i: Vec<GE>,
}

#[no_mangle]
pub extern "system" fn libmpecdsa_kengen_ctx_init(
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
pub extern "system" fn libmpecdsa_kengen_ctx_free(ctx: *mut KeygenContext) {
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
    let (bc_i, decom_i) = unsafe { &*ctx }.party_keys.phase1_broadcast_phase3_proof_of_correct_key_proof_of_correct_h1h2();

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
    bcs: *mut c_char, //self included
    bc_i_length: *const i32, //size = party_total
    decoms: *mut c_char, //self included
    decom_i_length: *const i32, //size = party_total
    ciphertexts_length: *mut i32, //size = party_total - 1
) -> *mut c_char {
    let party_total = unsafe { &*ctx }.params.share_count;
    let threshold = unsafe { &*ctx }.params.threshold;
    let party_index = unsafe { &*ctx }.party_index;
    let party_keys = unsafe { &*ctx }.party_keys.clone();

    let mut j = 0;
    // let mut point_vec: Vec<GE> = Vec::new();
    let mut decom_vec: Vec<KeyGenDecommitMessage1> = Vec::new();

    let decom_i_lenth_array = {
        assert!(!decom_i_length.is_null());
        slice_from_raw_parts(decom_i_length, party_total as usize)
    };
    let decoms_str = unsafe {
        CString::from_raw(decoms).into_string().unwrap()
    };

    for i in 1..=party_total {
        let current_party_length = unsafe { &*decom_i_lenth_array }[(i - 1) as usize] as usize;
        let decom_j: KeyGenDecommitMessage1 = serde_json::from_str(&decoms_str[j..j + current_party_length]).unwrap();
        unsafe { &mut *ctx }.decoms_y_i.push(decom_j.y_i);
        decom_vec.push(decom_j.clone());
        if i != party_index {
            unsafe { &mut *ctx }.enc_keys.push((decom_j.y_i.clone() * party_keys.u_i).x_coor().unwrap());
        }
        j = j + current_party_length;
    }

    let (head, tail) = unsafe { &mut *ctx }.decoms_y_i.split_at(1);
    unsafe { &mut *ctx }.y_sum = tail.iter().fold(head[0], |acc, x| acc + x);

    let bc_i_length_array = {
        assert!(!bc_i_length.is_null());
        slice_from_raw_parts(bc_i_length, party_total as usize)
    };
    let bcs_str = unsafe {
        CString::from_raw(bcs).into_string().unwrap()
    };

    let mut bc_vec: Vec<KeyGenBroadcastMessage1> = Vec::new();
    j = 0;
    for i in 0..party_total as usize {
        let current_party_length = unsafe { &*bc_i_length_array }[i] as usize;
        let bc_i: KeyGenBroadcastMessage1 = serde_json::from_str(&bcs_str[j..j + current_party_length]).unwrap();

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
            let ciphertext_i_length: &mut [i32] = unsafe { slice::from_raw_parts_mut(ciphertexts_length, (party_total - 1) as usize) };
            j = 0;
            for (k, i) in (1..=party_total).enumerate() {
                if i != party_index {
                    // prepare encrypted ss for party i:
                    let key_i = BigInt::to_vec(unsafe { &*ctx }.enc_keys[j].borrow());
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
            unsafe {
                *ciphertexts_length = 0
            };
            CString::new("").unwrap().into_raw()
        }
    }
}

#[no_mangle]
pub extern "system" fn libmpecdsa_keygen_round3(
    ctx: *mut KeygenContext,
    ciphertexts: *mut c_char,// exclude self
    ciphertext_i_length: *const i32,//party_total - 1
    result_length: *mut i32, // size = 1
) -> *mut c_char {
    let party_total = unsafe { &*ctx }.params.share_count as usize;
    let party_index = unsafe { &*ctx }.party_index as usize;
    let ciphertext_i_length_array = {
        assert!(!ciphertext_i_length.is_null());
        slice_from_raw_parts(ciphertext_i_length, party_total)
    };
    let ciphertexts_str = unsafe {
        CString::from_raw(ciphertexts).into_string().unwrap()
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
            let aead_pack: AEAD = serde_json::from_str(&ciphertexts_str[index..index + current_party_length]).unwrap();
            let enc_key_i = unsafe { &*ctx }.enc_keys[j].clone();
            let key_i = BigInt::to_vec(&enc_key_i);
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
    unsafe {
        *result_length = result.len() as i32;
    }

    CString::new(result).unwrap().into_raw()
}

#[no_mangle]
pub extern "system" fn libmpecdsa_keygen_round4(
    ctx: *mut KeygenContext,
    vss_schemes: *mut c_char, //exclude self
    vss_scheme_length: *const i32, //party_total - 1
    result_length: *mut i32, //size = 1
) -> *mut c_char {
    let party_index = unsafe { &*ctx }.party_index as usize;
    let party_total = unsafe { &*ctx }.params.share_count as usize;
    let vss_i_length_array = {
        assert!(!vss_scheme_length.is_null());
        slice_from_raw_parts(vss_scheme_length, party_total)
    };
    let vss_schemes_str = unsafe {
        CString::from_raw(vss_schemes).into_string().unwrap()
    };

    let mut j = 0;
    let mut index = 0;
    for i in 1..=party_total {
        if i != party_index {
            let length = unsafe { &*vss_i_length_array }[j] as usize;
            let vss_scheme_j: VerifiableSS = serde_json::from_str(&vss_schemes_str[index..index + length]).unwrap();
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
            unsafe {
                *result_length = dlog_proof_str.len() as i32
            };
            tmp_ctx.shared_keys = shared_keys;

            CString::new(dlog_proof_str).unwrap().into_raw()
        }
        Err(_) => {
            unsafe {
                *result_length = 0
            };
            CString::new("").unwrap().into_raw()
        }
    }
}

#[no_mangle]
pub extern "system" fn libmpecdsa_keygen_round5(
    ctx: *mut KeygenContext,
    dlog_proofs: *mut c_char, //self included
    dlog_proof_length: *const i32, //size = party_total
    result_length: *mut i32,//size = 1
) -> *mut c_char {
    let party_total = unsafe { &*ctx }.params.share_count as usize;

    let dlog_proof_length_array = {
        assert!(!dlog_proof_length.is_null());
        slice_from_raw_parts(dlog_proof_length, party_total)
    };
    let dlog_proofs_str = unsafe {
        CString::from_raw(dlog_proofs).into_string().unwrap()
    };
    // TODO: check length of dlog_proofs_str satisfies.
    let mut index = 0;
    let mut dlog_proof_vec: Vec<DLogProof> = Vec::new();
    for i in 0..party_total {
        let length = unsafe { &*dlog_proof_length_array }[i] as usize;
        let dlog_proof_i: DLogProof = serde_json::from_str(&dlog_proofs_str[index..index + length]).unwrap();
        dlog_proof_vec.push(dlog_proof_i);
        index += length;
    }

    let tmp_ctx = unsafe { &mut *ctx };
    match Keys::verify_dlog_proofs(&tmp_ctx.params, &dlog_proof_vec, &tmp_ctx.decoms_y_i) {
        Ok(()) => {
            let pk_vec = (0..party_total).map(|i| dlog_proof_vec[i].pk).collect::<Vec<GE>>();
            let result = serde_json::to_string(&(
                &tmp_ctx.party_keys,
                &tmp_ctx.shared_keys,
                pk_vec,
                &tmp_ctx.y_sum,
                &tmp_ctx.vss_scheme_vec,
                &tmp_ctx.paillier_ek_vec,
                &tmp_ctx.dlog_statements,
                tmp_ctx.party_index,
            )).unwrap();
            unsafe {
                *result_length = result.len() as i32;
            }
            CString::new(result).unwrap().into_raw()
        }
        Err(_) => {
            unsafe {
                *result_length = 0
            };
            CString::new("").unwrap().into_raw()
        }
    }
}

#[test]
fn libmpecdsa_keygen_rounds_test() {
    use std::fs;

    let ctx1 = libmpecdsa_kengen_ctx_init(1, 2, 1);
    let ctx2 = libmpecdsa_kengen_ctx_init(2, 2, 1);
    let mut bc1_length: i32 = 0;
    let mut decom1_length: i32 = 0;
    let mut bc2_length: i32 = 0;
    let mut decom2_length: i32 = 0;
    let str1_ptr = libmpecdsa_keygen_round1(ctx1, &mut bc1_length, &mut decom1_length);
    let str2_ptr = libmpecdsa_keygen_round1(ctx2, &mut bc2_length, &mut decom2_length);

    let mut bcs_string = String::new();
    let mut decoms_string = String::new();

    let str1_str = unsafe { CString::from_raw(str1_ptr).into_string().unwrap() };
    bcs_string.push_str(&str1_str[..bc1_length as usize]);
    decoms_string.push_str(&str1_str[bc1_length as usize..]);

    assert_eq!(bc1_length + decom1_length, str1_str.len() as i32);

    let str2_str = unsafe { CString::from_raw(str2_ptr).into_string().unwrap() };
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

    let round2_ans1_str = unsafe { CString::from_raw(round2_str1_ptr).into_string().unwrap() };
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

    let round2_ans2_str = unsafe { CString::from_raw(round2_str2_ptr).into_string().unwrap() };
    assert_eq!(ciphertext2_length[0], round2_ans2_str.len() as i32);
    // println!("round2 ans: length {:?}, {:?}", ciphertext_length[0], round2_ans_str);

    //round3 party1
    let mut round3_ans1_len = [0];
    let round3_ans1_ptr = libmpecdsa_keygen_round3(
        ctx1,
        CString::new(round2_ans2_str).unwrap().into_raw(),
        &ciphertext2_length[0],
        &mut round3_ans1_len[0],
    );

    let round3_ans1_str = unsafe { CString::from_raw(round3_ans1_ptr).into_string().unwrap() };
    // println!("round3_ans1_str {:?}", round3_ans1_str);
    assert_eq!(round3_ans1_len[0], round3_ans1_str.len() as i32);

    //round3 party2
    let mut round3_ans2_len = [0];
    let round3_ans2_ptr = libmpecdsa_keygen_round3(
        ctx2,
        CString::new(round2_ans1_str).unwrap().into_raw(),
        &ciphertext1_length[0],
        &mut round3_ans2_len[0],
    );

    let round3_ans2_str = unsafe { CString::from_raw(round3_ans2_ptr).into_string().unwrap() };
    // println!("round3_ans2_str {:?}", round3_ans2_str);
    assert_eq!(round3_ans2_len[0], round3_ans2_str.len() as i32);

    let mut round4_ans1_len = 0;
    let round4_ans1_ptr = libmpecdsa_keygen_round4(
        ctx1,
        CString::new(round3_ans2_str).unwrap().into_raw(),
        &round3_ans2_len[0],
        &mut round4_ans1_len,
    );

    let round4_ans1_str = unsafe { CString::from_raw(round4_ans1_ptr).into_string().unwrap() };
    // println!("round4_ans1_str {:?}", round4_ans1_str);
    assert_eq!(round4_ans1_str.len(), round4_ans1_len as usize);

    let mut round4_ans2_len = 0;
    let round4_ans2_ptr = libmpecdsa_keygen_round4(
        ctx2,
        CString::new(round3_ans1_str).unwrap().into_raw(),
        &round3_ans1_len[0],
        &mut round4_ans2_len,
    );

    let round4_ans2_str = unsafe { CString::from_raw(round4_ans2_ptr).into_string().unwrap() };
    // println!("round4_ans2_str {:?}", round4_ans2_str);
    assert_eq!(round4_ans2_str.len(), round4_ans2_len as usize);

    //round 5
    let mut dlog_proofs = String::new();
    dlog_proofs.push_str(&round4_ans1_str);
    dlog_proofs.push_str(&round4_ans2_str);
    let dlog_proof_length = [round4_ans1_len, round4_ans2_len];

    let mut round5_ans1_length = 0;
    let round5_ans1_ptr = libmpecdsa_keygen_round5(
        ctx1,
        CString::new(dlog_proofs.clone()).unwrap().into_raw(),
        &dlog_proof_length[0],
        &mut round5_ans1_length,
    );

    let round5_ans1_str = unsafe { CString::from_raw(round5_ans1_ptr).into_string().unwrap() };
    // println!("round5_ans1_str {:?}", round5_ans1_str);
    assert_eq!(round5_ans1_length as usize, round5_ans1_str.len());
    fs::write("keys1.store", round5_ans1_str).expect("Unable to save.");

    let mut round5_ans2_length = 0;
    let round5_ans2_ptr = libmpecdsa_keygen_round5(
        ctx2,
        CString::new(dlog_proofs).unwrap().into_raw(),
        &dlog_proof_length[0],
        &mut round5_ans2_length,
    );

    let round5_ans2_str = unsafe { CString::from_raw(round5_ans2_ptr).into_string().unwrap() };
    // println!("round5_ans2_str {:?}", round5_ans2_str);
    assert_eq!(round5_ans2_length as usize, round5_ans2_str.len());
    fs::write("keys2.store", round5_ans2_str).expect("Unable to save.");

    libmpecdsa_kengen_ctx_free(ctx1);
    libmpecdsa_kengen_ctx_free(ctx2);
}

// Sign
pub struct SignContext {}

#[no_mangle]
pub extern "system" fn libmpecdsa_sign_ctx_init(
    party_index: i32,
    party_total: i32,
    threshold: i32,
) -> *mut SignContext {
    assert!(party_index > 0, "party index must be positive.");
    assert!(party_index <= party_total, "party index must be less than party_total.");
    assert!(threshold > 0, "threshold must be positive.");
    assert!(threshold < party_total, "threshold must be less than party_total.");

    let ctx = Box::new(SignContext {});

    Box::into_raw(ctx)
}

#[no_mangle]
pub extern "system" fn libmpecdsa_sign_ctx_free(ctx: *mut SignContext) {
    drop(unsafe { Box::from_raw(ctx) });
}

