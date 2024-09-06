use core::ffi;
use rand::rngs::OsRng;
use rand::RngCore;

//use crate::connections;
//use ::dkls23::protocols::dkg::phase1;
use ffi_tss::dkls23::protocols::dkg::{
    Phase1In, Phase1Out, Phase2In, Phase2Out, Phase3In, Phase3Out, Phase4In,
    Phase4Out,
};

enum Curve {
    ECDSA,
    EDDSA
}



pub fn dkg(curve: Curve, client: , dkg_phases_endpoints: &[&str], threshold: u8, share_count: u8) {
    //if dkg_phases_endpoints.len() != 4 {

    //}

    let session: [u8; 32] = rng::rand::thread_rng().gen::<[u8; 32]>();

    //if curve == ffi_tss::ECDSA {
    //    let phase1_in = Phase1In { session }.to_json();
    //    let phase1_out = dkls::dkg_phase1(phase1_in);
    //}
}