use crate::utils::files::write_to_file;
use crate::utils::hash::sha256_str;
use dkls23::protocols::dkg::{
    phase1, phase2, phase3, phase4, BroadcastDerivationPhase2to4, BroadcastDerivationPhase3to4,
    KeepInitMulPhase3to4, KeepInitZeroSharePhase2to3, KeepInitZeroSharePhase3to4, ProofCommitment,
    SessionData, TransmitInitMulPhase3to4, TransmitInitZeroSharePhase2to4,
    TransmitInitZeroSharePhase3to4, UniqueKeepDerivationPhase2to3,
};
use dkls23::protocols::{Parameters, Party};
use ffi_tss::dkls23::protocols::dkg::{
    Phase1In, Phase1Out, Phase2In, Phase2Out, Phase3In, Phase3Out, Phase4In, Phase4Out,
};
use ffi_tss::k256::Scalar;
use std::collections::BTreeMap;

pub fn dkg_input_gen(input_filename: &str, output_filename: &str) {
    let mut inputs: Vec<String> = Vec::new();
    let mut outputs: Vec<String> = Vec::new();

    let parameters = Parameters {
        threshold: 2,
        share_count: 2,
    };

    let session_id: [u8; 32] = [
        155, 91, 34, 177, 234, 249, 164, 92, 254, 10, 140, 65, 30, 135, 113, 112, 137, 57, 36, 209,
        201, 197, 182, 252, 49, 111, 29, 209, 53, 68, 140, 219,
    ];

    let mut all_data: Vec<SessionData> = Vec::with_capacity(parameters.share_count as usize);
    for i in 0..parameters.share_count {
        all_data.push(SessionData {
            parameters: parameters.clone(),
            party_index: i + 1,
            session_id: session_id.to_vec(),
        });
    }

    // Phase 1
    println!("DKG - Phase 1");
    // for testing purpose, we are saving only the first party results.
    inputs.push(
        serde_json::to_string(&Phase1In {
            session: all_data[0].clone(),
        })
        .unwrap(),
    );

    let mut dkg_1: Vec<Vec<Scalar>> = Vec::with_capacity(parameters.share_count as usize);
    for i in 0..parameters.share_count {
        let out1 = phase1(&all_data[i as usize]);

        dkg_1.push(out1);
    }

    outputs.push(
        serde_json::to_string(&Phase1Out {
            fragments: dkg_1[0].clone(),
        })
        .unwrap(),
    );

    // Communication round 1 - Each party receives a fragment from each counterparty.
    // They also produce a fragment for themselves.
    let mut poly_fragments = vec![
        Vec::<Scalar>::with_capacity(parameters.share_count as usize);
        parameters.share_count as usize
    ];
    for row_i in dkg_1 {
        for j in 0..parameters.share_count {
            poly_fragments[j as usize].push(row_i[j as usize]);
        }
    }

    // Phase 2
    println!("DKG - Phase 2");
    inputs.push(
        serde_json::to_string(&Phase2In {
            session: all_data[0].clone(),
            poly_fragments: poly_fragments[0].clone(),
        })
        .unwrap(),
    );

    let mut poly_points: Vec<Scalar> = Vec::with_capacity(parameters.share_count as usize);
    let mut proofs_commitments: Vec<ProofCommitment> =
        Vec::with_capacity(parameters.share_count as usize);
    let mut zero_kept_2to3: Vec<BTreeMap<u8, KeepInitZeroSharePhase2to3>> =
        Vec::with_capacity(parameters.share_count as usize);
    let mut zero_transmit_2to4: Vec<Vec<TransmitInitZeroSharePhase2to4>> =
        Vec::with_capacity(parameters.share_count as usize);
    let mut bip_kept_2to3: Vec<UniqueKeepDerivationPhase2to3> =
        Vec::with_capacity(parameters.share_count as usize);
    let mut bip_broadcast_2to4: BTreeMap<u8, BroadcastDerivationPhase2to4> = BTreeMap::new();
    for i in 0..parameters.share_count {
        let (out1, out2, out3, out4, out5, out6) =
            phase2(&all_data[i as usize], &poly_fragments[i as usize]);

        poly_points.push(out1);
        proofs_commitments.push(out2);
        zero_kept_2to3.push(out3);
        zero_transmit_2to4.push(out4);
        bip_kept_2to3.push(out5);
        bip_broadcast_2to4.insert(i + 1, out6); // This variable should be grouped into a BTreeMap.
    }

    outputs.push(
        serde_json::to_string(&Phase2Out {
            poly_point: poly_points[0].clone(),
            proof_commitment: proofs_commitments[0].clone(),
            zero_keep: zero_kept_2to3[0].clone(),
            zero_transmit: zero_transmit_2to4[0].clone(),
            bip_keep: bip_kept_2to3[0].clone(),
            bip_broadcast: bip_broadcast_2to4.get(&1).unwrap().clone(),
        })
        .unwrap(),
    );

    // Communication round 2
    let mut zero_received_2to4: Vec<Vec<TransmitInitZeroSharePhase2to4>> =
        Vec::with_capacity(parameters.share_count as usize);
    for i in 1..=parameters.share_count {
        // We don't need to transmit the commitments because proofs_commitments is already what we need.
        // In practice, this should be done here.

        let mut new_row: Vec<TransmitInitZeroSharePhase2to4> =
            Vec::with_capacity((parameters.share_count - 1) as usize);
        for party in &zero_transmit_2to4 {
            for message in party {
                // Check if this message should be sent to us.
                if message.parties.receiver == i {
                    new_row.push(message.clone());
                }
            }
        }
        zero_received_2to4.push(new_row);
    }

    // bip_transmit_2to4 is already in the format we need.
    // In practice, the messages received should be grouped into a BTreeMap.

    // Phase 3
    println!("DKG - Phase 3");
    inputs.push(
        serde_json::to_string(&Phase3In {
            session: all_data[0].clone(),
            zero_kept: zero_kept_2to3[0].clone(),
            bip_kept: bip_kept_2to3[0].clone(),
        })
        .unwrap(),
    );

    let mut zero_kept_3to4: Vec<BTreeMap<u8, KeepInitZeroSharePhase3to4>> =
        Vec::with_capacity(parameters.share_count as usize);
    let mut zero_transmit_3to4: Vec<Vec<TransmitInitZeroSharePhase3to4>> =
        Vec::with_capacity(parameters.share_count as usize);
    let mut mul_kept_3to4: Vec<BTreeMap<u8, KeepInitMulPhase3to4>> =
        Vec::with_capacity(parameters.share_count as usize);
    let mut mul_transmit_3to4: Vec<Vec<TransmitInitMulPhase3to4>> =
        Vec::with_capacity(parameters.share_count as usize);
    let mut bip_broadcast_3to4: BTreeMap<u8, BroadcastDerivationPhase3to4> = BTreeMap::new();
    for i in 0..parameters.share_count {
        let (out1, out2, out3, out4, out5) = phase3(
            &all_data[i as usize],
            &zero_kept_2to3[i as usize],
            &bip_kept_2to3[i as usize],
        );

        zero_kept_3to4.push(out1);
        zero_transmit_3to4.push(out2);
        mul_kept_3to4.push(out3);
        mul_transmit_3to4.push(out4);
        bip_broadcast_3to4.insert(i + 1, out5); // This variable should be grouped into a BTreeMap.
    }

    outputs.push(
        serde_json::to_string(&Phase3Out {
            zero_keep: zero_kept_3to4[0].clone(),
            zero_transmit: zero_transmit_3to4[0].clone(),
            mul_keep: mul_kept_3to4[0].clone(),
            mul_transmit: mul_transmit_3to4[0].clone(),
            bip_broadcast: bip_broadcast_3to4.get(&1).unwrap().clone(),
        })
        .unwrap(),
    );

    // Communication round 3
    let mut zero_received_3to4: Vec<Vec<TransmitInitZeroSharePhase3to4>> =
        Vec::with_capacity(parameters.share_count as usize);
    let mut mul_received_3to4: Vec<Vec<TransmitInitMulPhase3to4>> =
        Vec::with_capacity(parameters.share_count as usize);
    for i in 1..=parameters.share_count {
        // We don't need to transmit the proofs because proofs_commitments is already what we need.
        // In practice, this should be done here.

        let mut new_row: Vec<TransmitInitZeroSharePhase3to4> =
            Vec::with_capacity((parameters.share_count - 1) as usize);
        for party in &zero_transmit_3to4 {
            for message in party {
                // Check if this message should be sent to us.
                if message.parties.receiver == i {
                    new_row.push(message.clone());
                }
            }
        }
        zero_received_3to4.push(new_row);

        let mut new_row: Vec<TransmitInitMulPhase3to4> =
            Vec::with_capacity((parameters.share_count - 1) as usize);
        for party in &mul_transmit_3to4 {
            for message in party {
                // Check if this message should be sent to us.
                if message.parties.receiver == i {
                    new_row.push(message.clone());
                }
            }
        }
        mul_received_3to4.push(new_row);
    }

    // Phase 4
    println!("DKG - Phase 4");
    inputs.push(
        serde_json::to_string(&Phase4In {
            session: all_data[0].clone(),
            poly_point: poly_points[0].clone(),
            proofs_commitments: proofs_commitments.clone(),
            zero_kept: zero_kept_3to4[0].clone(),
            zero_received_phase2: zero_received_2to4[0].clone(),
            zero_received_phase3: zero_received_3to4[0].clone(),
            mul_kept: mul_kept_3to4[0].clone(),
            mul_received: mul_received_3to4[0].clone(),
            bip_broadcast_2to4: bip_broadcast_2to4.clone(),
            bip_broadcast_3to4: bip_broadcast_3to4.clone(),
        })
        .unwrap(),
    );

    let mut parties: Vec<Party> = Vec::with_capacity((parameters.share_count) as usize);
    for i in 0..parameters.share_count {
        let result = phase4(
            &all_data[i as usize],
            &poly_points[i as usize],
            &proofs_commitments,
            &zero_kept_3to4[i as usize],
            &zero_received_2to4[i as usize],
            &zero_received_3to4[i as usize],
            &mul_kept_3to4[i as usize],
            &mul_received_3to4[i as usize],
            &bip_broadcast_2to4,
            &bip_broadcast_3to4,
        );
        match result {
            Err(abort) => {
                panic!("Party {} aborted: {:?}", abort.index, abort.description);
            }
            Ok(party) => {
                parties.push(party);
            }
        }
    }

    outputs.push(
        serde_json::to_string(&Phase4Out {
            party: parties[0].clone(),
        })
        .unwrap(),
    );

    let hashes: Vec<String> = outputs.iter().map(|out| sha256_str(out)).collect();
    write_to_file(inputs, input_filename);
    write_to_file(hashes, output_filename);

    println!("DKG finished!");
}
