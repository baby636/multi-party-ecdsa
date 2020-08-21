#![allow(non_snake_case)]

use std::{env, fs, time};

pub mod common;
use common::{
    postb, Params, PartySignup, broadcast, poll_for_broadcasts, aes_encrypt, aes_decrypt,
    sendp2p, poll_for_p2p, AEAD
};
use reqwest::Client;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::{Parameters, Keys, KeyGenBroadcastMessage1, KeyGenDecommitMessage1};
use paillier::EncryptionKey;
use zk_paillier::zkproofs::DLogStatement;
use curv::{GE, BigInt, FE};
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::arithmetic::traits::Converter;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;

fn main() {
    if env::args().nth(3).is_some() {
        panic!("too many arguments")
    }
    if env::args().nth(2).is_none() {
        panic!("too few arguments")
    }
    let data = fs::read_to_string("params.json")
        .expect("unable to read params, make sure param file is present in the same folder");
    let params: Params = serde_json::from_str(&data).unwrap();
    let PARTIES: u16 = params.parties.parse::<u16>().unwrap();
    let THRESHOLD: u16 = params.threshold.parse::<u16>().unwrap();

    let client = Client::new();

    let delay = time::Duration::from_millis(25);
    let params = Parameters {
        threshold: THRESHOLD,
        share_count: PARTIES,
    };

    //signup:
    let (party_num_int, uuid) = match signup(&client).unwrap() {
        PartySignup { number, uuid} => (number, uuid),
    };
    let party_keys = Keys::create(party_num_int as usize);
    let (bc_i, decom_i) = party_keys.phase1_broadcast_phase3_proof_of_correct_key_proof_of_correct_h1h2();
    assert!(broadcast(
        &client,
        party_num_int,
        "round1",
        serde_json::to_string(&bc_i).unwrap(),
        uuid.clone()
    ).is_ok());
    let round1_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        PARTIES,
        delay,
        "round1",
        uuid.clone(),
    );
    let mut bc1_vec = round1_ans_vec
        .iter()
        .map(|m| serde_json::from_str::<KeyGenBroadcastMessage1>(m).unwrap())
        .collect::<Vec<_>>();
    bc1_vec.insert(party_num_int as usize - 1, bc_i);

    let e_vec = bc1_vec
        .iter()
        .map(|bc1| bc1.e.clone())
        .collect::<Vec<EncryptionKey>>();

    let h1_h2_N_tilde_vec = bc1_vec
        .iter()
        .map(|bc1| bc1.dlog_statement.clone())
        .collect::<Vec<DLogStatement>>();
    assert!(broadcast(
        &client,
        party_num_int,
        "round2",
        serde_json::to_string(&decom_i).unwrap(),
        uuid.clone()
    ).is_ok());
    let round2_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        PARTIES,
        delay,
        "round2",
        uuid.clone(),
    );
    let mut decom_vec: Vec<KeyGenDecommitMessage1> = Vec::new();
    let mut y_vec: Vec<GE> = Vec::new();
    let mut enc_keys: Vec<BigInt> = Vec::new();
    let mut j = 0;
    for i in 1..=PARTIES {
        if i == party_num_int {
            y_vec.push(decom_i.y_i);
            decom_vec.push(decom_i.clone());
        } else {
            let decom_j: KeyGenDecommitMessage1 = serde_json::from_str(&round2_ans_vec[j]).unwrap();
            y_vec.push(decom_j.y_i);
            decom_vec.push(decom_j.clone());
            enc_keys.push((decom_j.y_i.clone() * party_keys.u_i).x_coor().unwrap());
            j = j + 1;
        }
    }
    let mut y_vec_iter = y_vec.iter();
    let head =  y_vec_iter.next().unwrap();
    let tail = y_vec_iter;
    let y_sum = tail.fold(head.clone(), |acc, x| acc + x);

    let res = party_keys
        .phase1_verify_com_phase3_verify_correct_key_verify_dlog_phase2_distribute(
            &params, &decom_vec, &bc1_vec
        );
    let (vss_scheme, secret_shares, _index) = match res {
        Ok((v, s, i)) => (v, s, i),
        Err(e) => {
            eprintln!("catch bad actors: {:?}", e);
            panic!("phase1_verify_com_phase3_verify_correct_key_verify_dlog_phase2_distribute failed");
        }
    };

    let mut j = 0;
    for (k, i) in (1..=PARTIES).enumerate() {
        if i != party_num_int {
            let key_i = BigInt::to_vec(&enc_keys[j]);
            let plaintext = BigInt::to_vec(&secret_shares[k].to_big_int());
            let aead_pack_i = aes_encrypt(&key_i, &plaintext);
            assert!(sendp2p(
                &client,
                party_num_int,
                i,
                "round3",
                serde_json::to_string(&aead_pack_i).unwrap(),
                uuid.clone()
            ).is_ok());
            j += 1;
        }
    }

    let round3_ans_vec = poll_for_p2p(
        &client,
        party_num_int,
        PARTIES,
        delay,
        "round3",
        uuid.clone(),
    );

    let mut j = 0;
    let mut party_shares: Vec<FE> = Vec::new();
    for i in 1..=PARTIES {
        if i == party_num_int {
            party_shares.push(secret_shares[(i - 1) as usize]);
        } else {
            let aead_pack: AEAD = serde_json::from_str(&round3_ans_vec[j]).unwrap();
            let key_i = BigInt::to_vec(&enc_keys[j]);
            let out = aes_decrypt(&key_i, aead_pack);
            let out_bn = BigInt::from(&out[..]);
            let out_fe = ECScalar::from(&out_bn);
            party_shares.push(out_fe);

            j += 1;
        }
    }

    //round 4: send vss commitments
    assert!(broadcast(
       &client,
        party_num_int,
        "round4",
        serde_json::to_string(&vss_scheme).unwrap(),
        uuid.clone()
    ).is_ok());
    let roun4_ans_vec = poll_for_broadcasts(
      &client,
        party_num_int,
        PARTIES,
        delay,
        "round4",
        uuid.clone(),
    );

    let mut j = 0;
    let mut vss_schme_vec: Vec<VerifiableSS> = Vec::new();
    for i in 1..=PARTIES {
        if i == party_num_int {
            vss_schme_vec.push(vss_scheme.clone());
        } else {
            let vss_schme_j: VerifiableSS = serde_json::from_str(&roun4_ans_vec[j]).unwrap();
            vss_schme_vec.push(vss_schme_j);
            j += 1;
        }
    }
    let (shared_keys, dlog_proof) = match party_keys
        .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
        &params,
        &y_vec,
        &party_shares,
        &vss_schme_vec,
        party_num_int as usize,
    ) {
        Ok((s, d)) => (s, d),
        Err(e) => {
            eprintln!("catch bad actors: {:?}", e);
            panic!("phase2_verify_vss_construct_keypair_phase3_pok_dlog failed");
        }
    };


    // round 5: send dlog proof
    assert!(broadcast(
        &client,
        party_num_int,
        "round5",
        serde_json::to_string(&dlog_proof).unwrap(),
        uuid.clone()
    ).is_ok());
    let round5_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        PARTIES,
        delay,
        "round5",
        uuid.clone(),
    );

    let mut j = 0;
    let mut dlog_proof_vec: Vec<DLogProof> = Vec::new();
    for i in 1..=PARTIES {
        if i == party_num_int {
            dlog_proof_vec.push(dlog_proof.clone());
        } else {
            let dlog_proof_j: DLogProof = serde_json::from_str(&round5_ans_vec[j]).unwrap();
            dlog_proof_vec.push(dlog_proof_j);
            j += 1;
        }
    }
    match Keys::verify_dlog_proofs(&params, &dlog_proof_vec, &y_vec) {
        Ok(()) => (),
        Err(e) => {
            eprintln!("cat bad actor: {:?}", e);
            panic!("verify dlog proofs failed.");
        }
    };

    //save key to file
    let paillier_key_vec = (0..PARTIES)
        .map(|i| bc1_vec[i as usize].e.clone())
        .collect::<Vec<EncryptionKey>>();
    let keygen_json = serde_json::to_string(&(
        party_keys,
        shared_keys,
        party_num_int,
        vss_schme_vec,
        paillier_key_vec,
        y_sum
    )).unwrap();
    fs::write(env::args().nth(2).unwrap(), keygen_json).expect("Unable to save");

}

pub fn signup(client: &Client) -> Result<PartySignup, ()> {
    let key = "signup-keygen".to_string();

    let res_body = postb(&client, "signupkeygen", key).unwrap();
    serde_json::from_str(&res_body).unwrap()
}