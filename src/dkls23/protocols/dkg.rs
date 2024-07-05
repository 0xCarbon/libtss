use crate::dkls23::utilities::cjson::CJson;
use dkls23::protocols::dkg::{
    phase1, phase2, phase3, phase4, BroadcastDerivationPhase2to4,
    BroadcastDerivationPhase3to4, KeepInitMulPhase3to4,
    KeepInitZeroSharePhase2to3, KeepInitZeroSharePhase3to4, ProofCommitment,
    SessionData, TransmitInitMulPhase3to4, TransmitInitZeroSharePhase2to4,
    TransmitInitZeroSharePhase3to4, UniqueKeepDerivationPhase2to3,
};
use dkls23::protocols::Party;
use k256::Scalar;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::os::raw::c_char;

// DKG structs
#[derive(Deserialize, Serialize)]
pub struct Phase1In {
    pub session: SessionData,
}

#[derive(Deserialize, Serialize)]
pub struct Phase1Out {
    pub fragments: Vec<Scalar>,
}

#[derive(Deserialize, Serialize)]
pub struct Phase2In {
    pub session: SessionData,
    pub poly_fragments: Vec<Scalar>,
}

#[derive(Deserialize, Serialize)]
pub struct Phase2Out {
    pub poly_point: Scalar,
    pub proof_commitment: ProofCommitment,
    pub zero_keep: BTreeMap<u8, KeepInitZeroSharePhase2to3>,
    pub zero_transmit: Vec<TransmitInitZeroSharePhase2to4>,
    pub bip_keep: UniqueKeepDerivationPhase2to3,
    pub bip_broadcast: BroadcastDerivationPhase2to4,
}

#[derive(Deserialize, Serialize)]
pub struct Phase3In {
    pub session: SessionData,
    pub zero_kept: BTreeMap<u8, KeepInitZeroSharePhase2to3>,
    pub bip_kept: UniqueKeepDerivationPhase2to3,
}

#[derive(Deserialize, Serialize)]
pub struct Phase3Out {
    pub zero_keep: BTreeMap<u8, KeepInitZeroSharePhase3to4>,
    pub zero_transmit: Vec<TransmitInitZeroSharePhase3to4>,
    pub mul_keep: BTreeMap<u8, KeepInitMulPhase3to4>,
    pub mul_transmit: Vec<TransmitInitMulPhase3to4>,
    pub bip_broadcast: BroadcastDerivationPhase3to4,
}

#[derive(Deserialize, Serialize)]
pub struct Phase4In {
    pub session: SessionData,
    pub poly_point: Scalar,
    pub proofs_commitments: Vec<ProofCommitment>,
    pub zero_kept: BTreeMap<u8, KeepInitZeroSharePhase3to4>,
    pub zero_received_phase2: Vec<TransmitInitZeroSharePhase2to4>,
    pub zero_received_phase3: Vec<TransmitInitZeroSharePhase3to4>,
    pub mul_kept: BTreeMap<u8, KeepInitMulPhase3to4>,
    pub mul_received: Vec<TransmitInitMulPhase3to4>,
    pub bip_broadcast_2to4: BTreeMap<u8, BroadcastDerivationPhase2to4>,
    pub bip_broadcast_3to4: BTreeMap<u8, BroadcastDerivationPhase3to4>,
}

#[derive(Deserialize, Serialize)]
pub struct Phase4Out {
    pub party: Party,
}

// DKG Phases
#[no_mangle]
pub extern "C" fn dkls_dkg_phase1(data: *const c_char) -> *const c_char {
    let phase1_in: Phase1In = Phase1In::from_json(data);
    let fragments = phase1(&phase1_in.session);

    Phase1Out { fragments }.to_json()
}

#[no_mangle]
pub extern "C" fn dkls_dkg_phase2(
    phase2_json_in: *const c_char,
) -> *const c_char {
    let phase2_in: Phase2In = Phase2In::from_json(phase2_json_in);
    let (
        poly_point,
        proof_commitment,
        zero_keep,
        zero_transmit,
        bip_keep,
        bip_broadcast,
    ) = phase2(&phase2_in.session, &phase2_in.poly_fragments);

    Phase2Out {
        poly_point,
        proof_commitment,
        zero_keep,
        zero_transmit,
        bip_keep,
        bip_broadcast,
    }
    .to_json()
}

#[no_mangle]
pub extern "C" fn dkls_dkg_phase3(
    phase3_json_in: *const c_char,
) -> *const c_char {
    let phase3_in: Phase3In = Phase3In::from_json(phase3_json_in);
    let (zero_keep, zero_transmit, mul_keep, mul_transmit, bip_broadcast) =
        phase3(
            &phase3_in.session,
            &phase3_in.zero_kept,
            &phase3_in.bip_kept,
        );

    Phase3Out {
        zero_keep,
        zero_transmit,
        mul_keep,
        mul_transmit,
        bip_broadcast,
    }
    .to_json()
}

#[no_mangle]
pub extern "C" fn dkls_dkg_phase4(
    phase4_json_in: *const c_char,
) -> *const c_char {
    let phase4_in: Phase4In = Phase4In::from_json(phase4_json_in);

    match phase4(
        &phase4_in.session,
        &phase4_in.poly_point,
        &phase4_in.proofs_commitments,
        &phase4_in.zero_kept,
        &phase4_in.zero_received_phase2,
        &phase4_in.zero_received_phase3,
        &phase4_in.mul_kept,
        &phase4_in.mul_received,
        &phase4_in.bip_broadcast_2to4,
        &phase4_in.bip_broadcast_3to4,
    ) {
        Ok(party) => Phase4Out { party }.to_json(),
        Err(abort) => {
            panic!("Party {} aborted: {:?}", abort.index, abort.description);
        }
    }
}
