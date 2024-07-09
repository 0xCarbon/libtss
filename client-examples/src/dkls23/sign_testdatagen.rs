use dkls23::protocols::signing::{
    Broadcast3to4, KeepPhase1to2, KeepPhase2to3, SignData, TransmitPhase1to2,
    TransmitPhase2to3, UniqueKeep1to2, UniqueKeep2to3,
};
use dkls23::protocols::{re_key::re_key, Parameters};
use dkls23::utilities::{hashes::hash, rng};
use ffi_tss::dkls23::protocols::signing::{
    Phase1In, Phase1Out, Phase2In, Phase2Out, Phase3In, Phase3Out, Phase4In,
    Phase4Out, VerifyIn,
};
use ffi_tss::k256::{
    elliptic_curve::scalar::IsHigh, elliptic_curve::Field,
    elliptic_curve::ScalarPrimitive, Scalar,
};
use rand::Rng;

use crate::utils::{
    files::read_from_file, files::write_to_file, hash::sha256_str,
};
use std::collections::BTreeMap;

use hex;

pub fn sign_input_gen(input_filename: &str, output_filename: &str) {
    // Disclaimer: this implementation is not the most efficient,
    // we are only testing if everything works! Note as well that
    // parties are being simulated one after the other, but they
    // should actually execute the protocol simultaneously.
    let mut inputs: Vec<String> = Vec::new();
    let mut outputs: Vec<String> = Vec::new();

    let parameters = Parameters {
        threshold: 2,
        share_count: 2,
    };

    let session_id: [u8; 32] = [
        155, 91, 34, 177, 234, 249, 164, 92, 254, 10, 140, 65, 30, 135, 113,
        112, 137, 57, 36, 209, 201, 197, 182, 252, 49, 111, 29, 209, 53, 68,
        140, 219,
    ];

    // We use the re_key function to quickly sample the parties.
    let secret_key = Scalar::random(rng::get_rng());
    let parties = re_key(&parameters, &session_id, &secret_key, None);

    // SIGNING
    let sign_id = rng::get_rng().gen::<[u8; 32]>();
    let message_to_sign = hash("Message to sign!".as_bytes(), &[]);

    // For simplicity, we are testing only the first parties.
    let executing_parties: Vec<u8> = Vec::from_iter(1..=parameters.threshold);

    // Each party prepares their data for this signing session.
    let mut all_data: BTreeMap<u8, SignData> = BTreeMap::new();
    for party_index in executing_parties.clone() {
        //Gather the counterparties
        let mut counterparties = executing_parties.clone();
        counterparties.retain(|index| *index != party_index);

        all_data.insert(
            party_index,
            SignData {
                sign_id: sign_id.to_vec(),
                counterparties,
                message_hash: message_to_sign,
            },
        );
    }

    // Phase 1
    println!("DKLs23::Sign - Phase 1");
    // for testing purpose, we are saving only the first party results.
    inputs.push(
        serde_json::to_string(&Phase1In {
            party: parties[0].clone(),
            sign_data: all_data[&1].clone(),
        })
        .unwrap(),
    );
    let mut unique_kept_1to2: BTreeMap<u8, UniqueKeep1to2> = BTreeMap::new();
    let mut kept_1to2: BTreeMap<u8, BTreeMap<u8, KeepPhase1to2>> =
        BTreeMap::new();
    let mut transmit_1to2: BTreeMap<u8, Vec<TransmitPhase1to2>> =
        BTreeMap::new();
    for party_index in executing_parties.clone() {
        let (unique_keep, keep, transmit) = parties[(party_index - 1) as usize]
            .sign_phase1(all_data.get(&party_index).unwrap());

        unique_kept_1to2.insert(party_index, unique_keep);
        kept_1to2.insert(party_index, keep);
        transmit_1to2.insert(party_index, transmit);
    }

    outputs.push(
        serde_json::to_string(&Phase1Out {
            unique_keep: unique_kept_1to2[&1].clone(),
            keep: kept_1to2[&1].clone(),
            transmit: transmit_1to2[&1].clone(),
        })
        .unwrap(),
    );

    // Communication round 1
    let mut received_1to2: BTreeMap<u8, Vec<TransmitPhase1to2>> =
        BTreeMap::new();

    for &party_index in &executing_parties {
        let messages_for_party: Vec<TransmitPhase1to2> = transmit_1to2
            .values()
            .flatten()
            .filter(|message| message.parties.receiver == party_index)
            .cloned()
            .collect();

        received_1to2.insert(party_index, messages_for_party);
    }

    // Phase 2
    println!("DKLs23::Sign - Phase 2");
    let mut unique_kept_2to3: BTreeMap<u8, UniqueKeep2to3> = BTreeMap::new();
    let mut kept_2to3: BTreeMap<u8, BTreeMap<u8, KeepPhase2to3>> =
        BTreeMap::new();
    let mut transmit_2to3: BTreeMap<u8, Vec<TransmitPhase2to3>> =
        BTreeMap::new();

    inputs.push(
        serde_json::to_string(&Phase2In {
            party: parties[0].clone(),
            sign_data: all_data[&1].clone(),
            unique_kept: unique_kept_1to2[&1].clone(),
            kept: kept_1to2[&1].clone(),
            received: received_1to2[&1].clone(),
        })
        .unwrap(),
    );

    for party_index in executing_parties.clone() {
        let result = parties[(party_index - 1) as usize].sign_phase2(
            all_data.get(&party_index).unwrap(),
            unique_kept_1to2.get(&party_index).unwrap(),
            kept_1to2.get(&party_index).unwrap(),
            received_1to2.get(&party_index).unwrap(),
        );
        match result {
            Err(abort) => {
                panic!(
                    "Party {} aborted: {:?}",
                    abort.index, abort.description
                );
            }
            Ok((unique_keep, keep, transmit)) => {
                unique_kept_2to3.insert(party_index, unique_keep);
                kept_2to3.insert(party_index, keep);
                transmit_2to3.insert(party_index, transmit);
            }
        }
    }

    outputs.push(
        serde_json::to_string(&Phase2Out {
            unique_keep: unique_kept_2to3[&1].clone(),
            keep: kept_2to3[&1].clone(),
            transmit: transmit_2to3[&1].clone(),
        })
        .unwrap(),
    );

    // Communication round 2
    let mut received_2to3: BTreeMap<u8, Vec<TransmitPhase2to3>> =
        BTreeMap::new();

    for &party_index in &executing_parties {
        let messages_for_party: Vec<TransmitPhase2to3> = transmit_2to3
            .values()
            .flatten()
            .filter(|message| message.parties.receiver == party_index)
            .cloned()
            .collect();

        received_2to3.insert(party_index, messages_for_party);
    }

    // Phase 3
    println!("DKLs23::Sign - Phase 3");
    let mut x_coords: Vec<String> =
        Vec::with_capacity(parameters.threshold as usize);
    let mut broadcast_3to4: Vec<Broadcast3to4> =
        Vec::with_capacity(parameters.threshold as usize);

    inputs.push(
        serde_json::to_string(&Phase3In {
            party: parties[0].clone(),
            sign_data: all_data[&1].clone(),
            unique_kept: unique_kept_2to3[&1].clone(),
            kept: kept_2to3[&1].clone(),
            received: received_2to3[&1].clone(),
        })
        .unwrap(),
    );

    for party_index in executing_parties.clone() {
        let result = parties[(party_index - 1) as usize].sign_phase3(
            all_data.get(&party_index).unwrap(),
            unique_kept_2to3.get(&party_index).unwrap(),
            kept_2to3.get(&party_index).unwrap(),
            received_2to3.get(&party_index).unwrap(),
        );
        match result {
            Err(abort) => {
                panic!(
                    "Party {} aborted: {:?}",
                    abort.index, abort.description
                );
            }
            Ok((x_coord, broadcast)) => {
                x_coords.push(x_coord);
                broadcast_3to4.push(broadcast);
            }
        }
    }

    outputs.push(
        serde_json::to_string(&Phase3Out {
            x_coord: x_coords[0].clone(),
            broadcast: broadcast_3to4[0].clone(),
        })
        .unwrap(),
    );

    // We verify all parties got the same x coordinate.
    let x_coord = x_coords[0].clone(); // We take the first one as reference.
    for i in 1..parameters.threshold {
        assert_eq!(x_coord, x_coords[i as usize]);
    }

    // Communication round 3
    // This is a broadcast to all parties. The desired result is already broadcast_3to4.

    // Phase 4
    println!("DKLs23::Sign Phase 4");
    inputs.push(
        serde_json::to_string(&Phase4In {
            party: parties[0].clone(),
            sign_data: all_data[&1].clone(),
            x_coord: x_coord.clone(),
            received: broadcast_3to4.clone(),
            normalize: true,
        })
        .unwrap(),
    );
    // It is essentially independent of the party, so we compute just once.
    let some_index = executing_parties[0];
    match parties[(some_index - 1) as usize].sign_phase4(
        all_data.get(&some_index).unwrap(),
        &x_coord,
        &broadcast_3to4,
        true,
    ) {
        Ok((signature, rec_id)) => outputs.push(
            serde_json::to_string(&Phase4Out { signature, rec_id }).unwrap(),
        ),
        Err(abort) => {
            panic!(
                "DKLs23::Signing::Party {} aborted: {:?}",
                abort.index, abort.description
            );
        }
    }

    let hashes: Vec<String> =
        outputs.iter().map(|out| sha256_str(out)).collect();
    write_to_file(inputs, input_filename);
    write_to_file(hashes, output_filename);

    println!("DKLs23::Signing finished!");
}

pub fn verify_ecdsa_signature_input_gen(
    input_filename: &str,
    output_filename: &str,
) {
    println!("verify:: input file: {}", input_filename);
    let phases = read_from_file(input_filename);
    if phases.len() != 4 {
        panic!("");
    }

    let mut inputs: Vec<String> = Vec::new();
    let phase4_in: Phase4In =
        serde_json::from_str(&phases[3].as_str()).unwrap();

    // Obtaining signature from phase4 input - See DKLs23::signing::sign_phase4
    let mut numerator = Scalar::ZERO;
    let mut denominator = Scalar::ZERO;
    for message in phase4_in.received {
        numerator += &message.w;
        denominator += &message.u;
    }

    let mut s = numerator * (denominator.invert().unwrap());

    // Normalize signature into "low S" form as described in
    // BIP-0062 Dealing with Malleability: https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
    if phase4_in.normalize && s.is_high().into() {
        s = ScalarPrimitive::from(-s).into();
    }

    let signature = hex::encode(s.to_bytes().as_slice());

    inputs.push(
        serde_json::to_string(&VerifyIn {
            msg: phase4_in.sign_data.message_hash,
            pk: phase4_in.party.pk,
            x_coord: phase4_in.x_coord,
            signature,
        })
        .unwrap(),
    );

    write_to_file(inputs, output_filename);
    println!("DKLs23::Verify ECDSA signature input data generation finished!");
}
