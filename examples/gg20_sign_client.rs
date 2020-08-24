#![allow(non_snake_case)]

use std::{env, time, fs};
use reqwest::Client;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::{Keys, SharedKeys, PartyPrivate, SignKeys, SignBroadcastPhase1, SignDecommitPhase1, LocalSignature};
use curv::{GE, FE, BigInt};
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use paillier::EncryptionKey;
use zk_paillier::zkproofs::DLogStatement;

mod common;
use common:: {
  Params, PartySignup, postb, broadcast, poll_for_broadcasts, sendp2p, poll_for_p2p, check_sig
};
use multi_party_ecdsa::utilities::mta::{MessageA, MessageB};
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::elliptic::curves::secp256_k1::Secp256k1Point;
use multi_party_ecdsa::utilities::zk_pdl_with_slack::PDLwSlackProof;
use criterion::AxisScale::Logarithmic;
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_encryption_of_dlog::HomoELGamalDlogProof;
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::blame::GlobalStatePhase7;
use curv::elliptic::curves::traits::ECScalar;

#[allow(clippy::cognitive_complexity)]
fn main() {
   if env::args().nth(4).is_some() {
       panic!("too many arguments")
   }
   if env::args().nth(3).is_none() {
       panic!("too few arguments")
   }
   let message_str = env::args().nth(3).unwrap_or_else(|| "".to_string());
   let message = match hex::decode(message_str.clone()) {
       Ok(x) => x,
       Err(_e) => message_str.as_bytes().to_vec(),
   };
   let message = &message[..];
   let client = Client::new();
    // delay:
   let delay = time::Duration::from_millis(25);
   let data = fs::read_to_string(env::args().nth(2).unwrap())
       .expect("Unable to load keys, did you run keygen first? ");
    let (
        party_keys,
        shared_keys,
        pk_vec,
        y_sum,
        vss_scheme_vec,
        e_vec,
        h1_h2_N_tilde_vec,
        party_id,
    ): (
        Keys,
        SharedKeys,
        Vec<GE>,
        GE,
        Vec<VerifiableSS>,
        Vec<EncryptionKey>,
        Vec<DLogStatement>,
        u16,
    ) = serde_json::from_str(&data).unwrap();

    //read parameters:
    let data = fs::read_to_string("params.json")
        .expect("unable to read the params, make sure config file is present in the same folder");
    let params: Params = serde_json::from_str(&data).unwrap();
    let THRESHOLD = params.threshold.parse::<u16>().unwrap();

    //signup:
    let (party_num_int, uuid) = match signup(&client).unwrap() {
        PartySignup {number, uuid} => (number, uuid),
    };
    println!("number: {:?}, uuid: {:?}", party_num_int, uuid);

    //round 0: collect signers IDs
    assert!(broadcast(
        &client,
        party_num_int,
        "round0",
        serde_json::to_string(&party_id).unwrap(),
        uuid.clone()
    ).is_ok());
    let round0_ans_vec = poll_for_broadcasts(
      &client,
        party_num_int,
        THRESHOLD + 1,
        delay,
        "round0",
        uuid.clone(),
    );
   let mut j = 0;
   let mut signers_vec: Vec<usize> = Vec::new();
   for i in 1..=THRESHOLD + 1 {
       if i == party_num_int {
           signers_vec.push((party_id - 1) as usize);
       } else {
           let signer_j: u16 = serde_json::from_str(&round0_ans_vec[j]).unwrap();
           signers_vec.push((signer_j - 1) as usize);
           j += 1;
       }
   }
   let private = PartyPrivate::set_private(party_keys.clone(), shared_keys);
   let sign_keys = SignKeys::create(
       &private,
       &vss_scheme_vec[signers_vec[(party_num_int - 1) as usize]],
       signers_vec[(party_num_int - 1) as usize],
       &signers_vec
   );

   let xi_com_vec = Keys::get_commitments_to_xi(&vss_scheme_vec);

   let (com, decommit) = sign_keys.phase1_broadcast();
   let (m_a_k, m_a_randomness) = MessageA::a(
       &sign_keys.k_i,
       &party_keys.ek,
   );

   assert!(broadcast(
       &client,
       party_num_int,
       "round1",
       serde_json::to_string(&(com.clone(), m_a_k.clone())).unwrap(),
       uuid.clone()
   ).is_ok());
   let round1_ans_vec = poll_for_broadcasts(
       &client,
       party_num_int,
       THRESHOLD + 1,
       delay,
       "round1",
       uuid.clone()
   );

   let mut j = 0;
   let mut bc1_vec: Vec<SignBroadcastPhase1> = Vec::new();
   let mut m_a_vec: Vec<MessageA> = Vec::new();

   for i in 1..THRESHOLD + 2 {
       if i == party_num_int {
           bc1_vec.push(com.clone());
       } else {
           let (bc_j, m_a_party_j): (SignBroadcastPhase1, MessageA) =
             serde_json::from_str(&round1_ans_vec[j]).unwrap();
           bc1_vec.push(bc_j);
           m_a_vec.push(m_a_party_j);

           j += 1;
       }
   }

   assert_eq!(signers_vec.len(), bc1_vec.len());

    ////////////////////////////////////////////////////
    let mut m_b_gamma_send_vec: Vec<MessageB> = Vec::new();
    let mut beta_vec: Vec<FE> = Vec::new();
    let mut m_b_w_send_vec: Vec<MessageB> = Vec::new();
    let mut ni_vec: Vec<FE> = Vec::new();
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i != party_num_int {
            let (m_b_gamma, beta_gamma, _, _) = MessageB::b(
              &sign_keys.gamma_i,
                &e_vec[signers_vec[(i - 1 ) as usize]],
                m_a_vec[j].clone(),
            );
            let (m_b_w, beta_wi, _, _) = MessageB::b(
                &sign_keys.w_i,
                &e_vec[signers_vec[(i - 1) as usize]],
                m_a_vec[j].clone(),
            );
            m_b_gamma_send_vec.push(m_b_gamma);
            m_b_w_send_vec.push(m_b_w);
            beta_vec.push(beta_gamma);
            ni_vec.push(beta_wi);
            j += 1;
        }
    }

    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i != party_num_int {
            assert!(sendp2p(
                &client,
                party_num_int,
                i,
                "round2",
                serde_json::to_string(&(m_b_gamma_send_vec[j].clone(), m_b_w_send_vec[j].clone()))
                    .unwrap(),
                uuid.clone()
            ).is_ok());
            j += 1;
        }
    }

    let round2_ans_vec = poll_for_p2p(
        &client,
        party_num_int,
        THRESHOLD + 1,
        delay,
        "round2",
        uuid.clone(),
    );

    let mut m_b_gamma_rec_vec: Vec<MessageB> = Vec::new();
    let mut m_b_w_rec_vec: Vec<MessageB> = Vec::new();

    for i in 0..THRESHOLD {
        let (m_b_gamma_i, m_b_w_i): (MessageB, MessageB) =
           serde_json::from_str(&round2_ans_vec[i as usize]).unwrap();
        m_b_gamma_rec_vec.push(m_b_gamma_i);
        m_b_w_rec_vec.push(m_b_w_i);
    }

    let mut alpha_vec: Vec<FE> = Vec::new();
    let mut miu_vec: Vec<FE> = Vec::new();

    //TODO: identify these errors
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i != party_num_int {
            let m_b = m_b_gamma_rec_vec[j].clone();
            let alpha_ij_gamma = m_b.verify_proofs_get_alpha(&party_keys.dk, & sign_keys.k_i)
                .expect("wrong dlog or m_b");
            let m_b = m_b_w_rec_vec[j].clone();
            let alpha_ij_wi = m_b.verify_proofs_get_alpha(&party_keys.dk, &sign_keys.k_i)
                .expect("wrong dlog or m_b");
            alpha_vec.push(alpha_ij_gamma.0);
            miu_vec.push(alpha_ij_wi.0);
            let g_w_i = Keys::update_commitments_to_xi(
                &xi_com_vec[signers_vec[(i - 1) as usize]],
                &vss_scheme_vec[signers_vec[(i - 1) as usize]],
                signers_vec[(i - 1) as usize],
                &signers_vec,
            );
            assert_eq!(m_b.b_proof.pk, g_w_i);
            j += 1;
        }
    }

    //////////////////////////////////////////
    let delta_i = sign_keys.phase2_delta_i(&alpha_vec, &beta_vec);
    let sigma = sign_keys.phase2_sigma_i(&miu_vec, &ni_vec);

    // all parties broadcast delta_i and compute delta_i^(-1)
    assert!(broadcast(
        &client,
        party_num_int,
        "round3",
        serde_json::to_string(&delta_i).unwrap(),
        uuid.clone()
    ).is_ok());
    let round3_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        THRESHOLD + 1,
        delay,
        "round3",
        uuid.clone(),
    );
    let mut delta_vec: Vec<FE> = Vec::new();
    format_vec_from_reads(
        &round3_ans_vec,
        party_num_int as usize,
        delta_i,
        &mut delta_vec,
    );

    let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_vec);
    // all parties compute the T_i
    let (T_i, l_i) = SignKeys::phase3_compute_t_i(&sigma);

    ///////////////////////////////////////
    //decommit to gamma_i
    assert!(broadcast(
        &client,
        party_num_int,
        "round4",
        serde_json::to_string(&decommit).unwrap(),
        uuid.clone()
    ).is_ok());
    let round4_ans_vec = poll_for_broadcasts(
      &client,
        party_num_int,
        THRESHOLD + 1,
        delay,
        "round4",
        uuid.clone(),
    );
    let mut decommit_vec: Vec<SignDecommitPhase1> = Vec::new();
    format_vec_from_reads(
        &round4_ans_vec,
        party_num_int as usize,
        decommit,
        &mut decommit_vec,
    );

    let b_proof_vec = (0..m_b_gamma_rec_vec.len())
        .map(|i| &m_b_gamma_rec_vec[i].b_proof)
        .collect::<Vec<&DLogProof>>();
    let index = (party_num_int - 1) as usize;
    let R = match SignKeys::phase4(&delta_inv, &b_proof_vec, decommit_vec, &bc1_vec, index) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("catch bad actors:{:?}", e);
            panic!("phase 4 error");
        }
    };

    let R_dash = R * sign_keys.k_i;
//    let phase5_proof = LocalSignature::phase5_proof_pdl(
//        &R_dash,
//        &R,
//        &m_a_k.c,
//        &e_vec[signers_vec[(party_num_int - 1) as usize]],
//        &sign_keys.k_i,
//        &m_a_randomness,
//        &party_keys,
//        &h1_h2_N_tilde_vec[signers_vec[(party_num_int - 1) as usize]]
//    );
    let mut phase5_proof: Vec<PDLwSlackProof> = Vec::new();
    for j in 0..THRESHOLD {
        let ind = if j < (party_num_int - 1) { j } else { j + 1 };
        let proof = LocalSignature::phase5_proof_pdl(
            &R_dash,
            &R,
            &m_a_k.c,
            &e_vec[signers_vec[(party_num_int - 1) as usize]],
            &sign_keys.k_i,
            &m_a_randomness,
            &party_keys,
            &h1_h2_N_tilde_vec[signers_vec[ind as usize]]
        );
        phase5_proof.push(proof);
    }

    assert!(broadcast(
        &client,
        party_num_int,
        "round5",
        serde_json::to_string(&(R_dash.clone(), phase5_proof.clone())).unwrap(),
        uuid.clone()
    ).is_ok());
    let round5_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        THRESHOLD + 1,
        delay,
        "round5",
        uuid.clone(),
    );

    let mut R_dash_vec: Vec<Secp256k1Point> = Vec::new();
    let mut phase5_proof_vec: Vec<Vec<PDLwSlackProof>> = vec![Vec::new(); (THRESHOLD + 1) as usize];
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i == party_num_int {
            R_dash_vec.push(R_dash.clone());
            phase5_proof_vec.push(phase5_proof.clone());
        } else {
            let (R_dash_j, phase5_proof_j): (Secp256k1Point, Vec<PDLwSlackProof>) =
                serde_json::from_str(&round5_ans_vec[j]).unwrap();
            R_dash_vec.push(R_dash_j);
            phase5_proof_vec.push(phase5_proof_j);

            j += 1;
        }
    }
    for i in 0..THRESHOLD + 1 {
      if i != (party_num_int - 1) {
          let ind  = if i < (party_num_int - 1) { i } else { i - 1 };
          let phase5_verify_zk = LocalSignature::phase5_verify_pdl(
              &phase5_proof_vec[i as usize],
              &R_dash_vec[i as usize],
              &R,
              &m_a_vec[ind as usize].c,
              &e_vec[signers_vec[i as usize]],
              &h1_h2_N_tilde_vec[..],
              &signers_vec,
              i as usize,
          );
          if phase5_verify_zk.is_err() {
              eprintln!("catch bad actors: {:?}", phase5_verify_zk.err().unwrap());
              panic!("phase5_verify_pdl failded.");
          }
      }
    }

    //each party must run the test
    let phase5_check = LocalSignature::phase5_check_R_dash_sum(&R_dash_vec);
    if phase5_check.is_err() {
        // initiate phase 5 blame protocol to learn which parties acted maliously.
//        let mut local_state_vec = Vec::new();
        panic!("phase5 check failed!");
    }

    //phase 6
    let (S, homo_elgamal_proof) = LocalSignature::phase6_compute_S_i_and_proof_of_consistency(
        &R,
        &T_i,
        &sigma,
        &l_i,
    );

    assert!(broadcast(
        &client,
        party_num_int,
        "round6",
        serde_json::to_string(&(S.clone(), homo_elgamal_proof.clone(), T_i.clone(), R.clone())).unwrap(),
        uuid.clone()
    ).is_ok());
    let round6_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        THRESHOLD + 1,
        delay,
        "round6",
        uuid.clone(),
    );

    let mut S_vec = Vec::new();
    let mut homo_elgamal_proof_vec = Vec::new();
    let mut T_vec = Vec::new();
    let mut R_vec = Vec::new();
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i == party_num_int {
            S_vec.push(S.clone());
            homo_elgamal_proof_vec.push(homo_elgamal_proof.clone());
            T_vec.push(T_i.clone());
            R_vec.push(R.clone());
        } else {
            let (S_j, home_elgamal_proof_j, T_j, R_j): (GE, HomoELGamalProof, Secp256k1Point, Secp256k1Point) =
                serde_json::from_str(&round6_ans_vec[j]).unwrap();
            S_vec.push(S_j);
            homo_elgamal_proof_vec.push(home_elgamal_proof_j);
            T_vec.push(T_j);
            R_vec.push(R);

            j += 1;
        }
    }

   match LocalSignature::phase6_verify_proof(&S_vec, &homo_elgamal_proof_vec, &R_vec, &T_vec) {
        Ok(()) => (),
        Err(e) => {
            eprintln!("catch bad actors: {:?}", e);
            panic!("phase6_verify_proof failed");
        }
    };

    let phase6_check = LocalSignature::phase6_check_S_i_sum(&y_sum, &S_vec);
    if phase6_check.is_err() {
        panic!("phase6 check failed");
    }

    let message_bn = HSha256::create_hash(&[&BigInt::from(&message[..])]);
    let local_sig = LocalSignature::phase7_local_sig(
        &sign_keys.k_i,
        &message_bn,
        &R,
        &sigma,
        &y_sum,
    );
    let s_i  = local_sig.s_i.clone();

    //////////////////////////////////////////////////////////////////////////////
    assert!(broadcast(
        &client,
        party_num_int,
        "round7",
        serde_json::to_string(&(local_sig.clone(), s_i.clone())).unwrap(),
        uuid.clone()
    )
        .is_ok());
    let round7_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        THRESHOLD + 1,
        delay,
        "round7",
        uuid.clone(),
    );

    let mut local_sig_vec: Vec<LocalSignature> = Vec::new();
    let mut s_i_vec: Vec<FE> = Vec::new();
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i == party_num_int {
            local_sig_vec.push(local_sig.clone());
            s_i_vec.push(s_i.clone());
            T_vec.push(T_i);
            R_vec.push(R);
        } else {
            let (local_sig_j, s_j): (LocalSignature, FE) =
                serde_json::from_str(&round7_ans_vec[j]).unwrap();
            local_sig_vec.push(local_sig_j);
            s_i_vec.push(s_j);

            j += 1;
        }
    }

    let sig = local_sig_vec[0].output_signature(&s_i_vec[1..]);
    // test
    assert_eq!(local_sig_vec[0].y, y_sum);
    //error in phase 7:
    if sig.is_err() {
        let global_state = GlobalStatePhase7 {
            s_vec: s_i_vec,
            r: local_sig_vec[0].r,
            R_dash_vec,
            m: local_sig_vec[0].m.clone(),
            R: local_sig_vec[0].R,
            S_vec,
        };
        global_state.phase7_blame();
    }
    //for testing purposes: checking with a second verifier:

    let sig = sig.unwrap();
    println!("party {:?} Output Signature: \n", party_num_int);
    println!("R: {:?}", sig.r.get_element());
    println!("s: {:?} \n", sig.s.get_element());
    println!("recid: {:?} \n", sig.recid.clone());
    let sign_json = serde_json::to_string(&(
        "r",
        (BigInt::from(&(sig.r.get_element())[..])).to_str_radix(16),
        "s",
        (BigInt::from(&(sig.s.get_element())[..])).to_str_radix(16),
    ))
        .unwrap();

    check_sig(&sig.r, &sig.s, &message_bn, &y_sum);
    fs::write("signature".to_string(), sign_json).expect("Unable to save !");

}

fn format_vec_from_reads<'a, T: serde::Deserialize<'a> + Clone>(
    ans_vec: &'a[String],
    party_num: usize,
    value_i: T,
    new_vec: &'a mut Vec<T>,
) {
    let mut j = 0 ;
    for i in 1..ans_vec.len() + 2 {
        if i == party_num {
            new_vec.push(value_i.clone());
        } else {
            let value_j: T = serde_json::from_str(&ans_vec[j]).unwrap();
            new_vec.push(value_j);
            j += 1;
        }
    }
}


pub fn signup(client: &Client) -> Result<PartySignup, ()> {
    let key = "signup-sign".to_string();
    let res_body = postb(&client, "signupsign", key).unwrap();
    serde_json::from_str(&res_body).unwrap()
}