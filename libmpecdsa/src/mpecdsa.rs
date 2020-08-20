extern crate libc;
extern crate curv;
extern crate multi_party_ecdsa;

use curv::{
    BigInt, GE
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::{
    KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys, Parameters,
};

use std::ffi::CString;

use libc::{c_char, c_uchar, int64_t};

//return { bc || decom }
#[no_mangle]
pub extern "system" fn libmpecdsa_keygen_round1(
    party_index: int64_t,
    bc_length: *mut int64_t,
    decom_length: *mut int64_t,
) -> *mut c_char {
    assert!(party_index >= 0, "party index must be non negative.");

    //It's better to use create_safe_prime, however it's extraordinarily inefficient.
    // let party_keys = Keys::create_safe_prime(party_index as usize);
    let party_keys = Keys::create(party_index as usize);
    let (bc_i, decom_i) = party_keys.phase1_broadcast_phase3_proof_of_correct_key_proof_of_correct_h1h2();

    let bc = serde_json::to_string(&bc_i).unwrap();
    unsafe {
        *bc_length = bc.len() as int64_t;
    }
    let decom = serde_json::to_string(&decom_i).unwrap();
    unsafe {
        *decom_length = decom.len() as int64_t;
    }

    let mut result = String::new();
    result.push_str(&bc);
    result.push_str(&decom);

    CString::new(result).unwrap().into_raw()
}

#[test]
fn libmpecdsa_keygen_round1_test() {
    let mut bc_length: i64 = 0;
    let mut decom_length: i64 = 0;
    let mut str_ptr= libmpecdsa_keygen_round1(0, &mut bc_length, &mut decom_length);

    let str = unsafe {CString::from_raw(str_ptr).into_string().unwrap()};

    assert_eq!(bc_length + decom_length, str.len() as i64);
}

