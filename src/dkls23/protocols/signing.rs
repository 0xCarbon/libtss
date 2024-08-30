use crate::utilities::cjson::CJson;
use dkls23::protocols::signing::{
    verify_ecdsa_signature, Broadcast3to4, KeepPhase1to2, KeepPhase2to3,
    SignData, TransmitPhase1to2, TransmitPhase2to3, UniqueKeep1to2,
    UniqueKeep2to3,
};
use dkls23::protocols::Party;
use dkls23::utilities::hashes::HashOutput;
use k256::AffinePoint;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::os::raw::c_char;

// Sign structs
#[derive(Deserialize, Serialize)]
pub struct Phase1In {
    pub party: Party,
    pub sign_data: SignData,
}

#[derive(Deserialize, Serialize)]
pub struct Phase1Out {
    pub unique_keep: UniqueKeep1to2,
    pub keep: BTreeMap<u8, KeepPhase1to2>,
    pub transmit: Vec<TransmitPhase1to2>,
}

#[derive(Deserialize, Serialize)]
pub struct Phase2In {
    pub party: Party,
    pub sign_data: SignData,
    pub unique_kept: UniqueKeep1to2,
    pub kept: BTreeMap<u8, KeepPhase1to2>,
    pub received: Vec<TransmitPhase1to2>,
}

#[derive(Deserialize, Serialize)]
pub struct Phase2Out {
    pub unique_keep: UniqueKeep2to3,
    pub keep: BTreeMap<u8, KeepPhase2to3>,
    pub transmit: Vec<TransmitPhase2to3>,
}

#[derive(Deserialize, Serialize)]
pub struct Phase3In {
    pub party: Party,
    pub sign_data: SignData,
    pub unique_kept: UniqueKeep2to3,
    pub kept: BTreeMap<u8, KeepPhase2to3>,
    pub received: Vec<TransmitPhase2to3>,
}

#[derive(Deserialize, Serialize)]
pub struct Phase3Out {
    pub x_coord: String,
    pub broadcast: Broadcast3to4,
}

#[derive(Deserialize, Serialize)]
pub struct Phase4In {
    pub party: Party,
    pub sign_data: SignData,
    pub x_coord: String,
    pub received: Vec<Broadcast3to4>,
    pub normalize: bool,
}

#[derive(Deserialize, Serialize)]
pub struct Phase4Out {
    pub signature: String,
    pub rec_id: u8,
}

#[derive(Deserialize, Serialize)]
pub struct VerifyIn {
    pub msg: HashOutput,
    pub pk: AffinePoint,
    pub x_coord: String,
    pub signature: String,
}

#[derive(Deserialize, Serialize)]
pub struct VerifyOut {
    pub valid: bool,
}

impl CJson for Phase1In {}
impl CJson for Phase1Out {}
impl CJson for Phase2In {}
impl CJson for Phase2Out {}
impl CJson for Phase3In {}
impl CJson for Phase3Out {}
impl CJson for Phase4In {}
impl CJson for Phase4Out {}
impl CJson for VerifyIn {}
impl CJson for VerifyOut {}

#[no_mangle]
pub extern "C" fn dkls_sign_phase1(
    phase1_json_in: *const c_char,
) -> *const c_char {
    let phase1_in: Phase1In = Phase1In::from_json(phase1_json_in);
    let (unique_keep, keep, transmit) =
        phase1_in.party.sign_phase1(&phase1_in.sign_data);

    Phase1Out {
        unique_keep,
        keep,
        transmit,
    }
    .to_json()
}

#[no_mangle]
pub extern "C" fn dkls_sign_phase2(
    phase2_json_in: *const c_char,
) -> *const c_char {
    let phase2_in: Phase2In = Phase2In::from_json(phase2_json_in);
    match phase2_in.party.sign_phase2(
        &phase2_in.sign_data,
        &phase2_in.unique_kept,
        &phase2_in.kept,
        &phase2_in.received,
    ) {
        Ok((unique_keep, keep, transmit)) => Phase2Out {
            unique_keep,
            keep,
            transmit,
        }
        .to_json(),

        Err(abort) => {
            panic!("Party {} aborted: {:?}", abort.index, abort.description);
        }
    }
}

#[no_mangle]
pub extern "C" fn dkls_sign_phase3(
    phase3_json_in: *const c_char,
) -> *const c_char {
    let phase3_in: Phase3In = Phase3In::from_json(phase3_json_in);
    match phase3_in.party.sign_phase3(
        &phase3_in.sign_data,
        &phase3_in.unique_kept,
        &phase3_in.kept,
        &phase3_in.received,
    ) {
        Ok((x_coord, broadcast)) => Phase3Out { x_coord, broadcast }.to_json(),

        Err(abort) => {
            panic!("Party {} aborted: {:?}", abort.index, abort.description);
        }
    }
}

#[no_mangle]
pub extern "C" fn dkls_sign_phase4(
    phase4_json_in: *const c_char,
) -> *const c_char {
    let phase4_in: Phase4In = Phase4In::from_json(phase4_json_in);
    match phase4_in.party.sign_phase4(
        &phase4_in.sign_data,
        &phase4_in.x_coord,
        &phase4_in.received,
        phase4_in.normalize,
    ) {
        Ok((signature, rec_id)) => Phase4Out { signature, rec_id }.to_json(),

        Err(abort) => {
            panic!("Party {} aborted: {:?}", abort.index, abort.description);
        }
    }
}

#[no_mangle]
pub extern "C" fn dkls_verify_ecdsa_signature(
    verify_json_in: *const c_char,
) -> *const c_char {
    let verify_in: VerifyIn = VerifyIn::from_json(verify_json_in);
    let valid = verify_ecdsa_signature(
        &verify_in.msg,
        &verify_in.pk,
        &verify_in.x_coord,
        &verify_in.signature,
    );
    VerifyOut { valid }.to_json()
}
