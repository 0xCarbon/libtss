use dkls23::protocols::{
    dkg::{
        SessionData, ProofCommitment,
    },
    Parameters,
};
use dkls23::utilities::proofs::{
    R, T,
    DLogProof, InteractiveDLogProof,
};
use k256::{ AffinePoint, EncodedPoint, FieldBytes, Scalar };
use k256::elliptic_curve::ff::PrimeField;
use k256::elliptic_curve::sec1::FromEncodedPoint;

use crate::dkls23::utilities::c_types::{
    CSessionData, CScalar, CScalarVec, CDLogProof, CAffinePoint,
    CInteractiveDLogProof, CProofCommitment, SECP256K1_ENCODED_SIZE,
};

pub fn from_c_session_data(session: &CSessionData) -> SessionData {
    let session_id_slice = unsafe {
        std::slice::from_raw_parts(session.session_id, session.session_id_len)
    };
    SessionData {
        party_index: session.party_index,
        parameters: Parameters {
            threshold: session.parameters.threshold,
            share_count: session.parameters.share_count,
        },
        session_id: Vec::from(session_id_slice),
    }
}

pub fn to_c_scalar_vec(scalars: &Vec<Scalar>) -> CScalarVec {
    let mut out: Vec<CScalar> = Vec::new();
    for scalar in scalars.iter() {
        out.push(to_c_scalar(&scalar));
    }
    let len = out.len();
    let data = Box::into_raw(out.into_boxed_slice()) as *const CScalar;
    CScalarVec { data, len }
}

pub fn from_c_scalar_vec(c_scalars: &CScalarVec) -> Vec<Scalar> {
    let mut out: Vec<Scalar> = Vec::new();
    let scalars = unsafe {
        std::slice::from_raw_parts(c_scalars.data, c_scalars.len)
    };
    for i in 0..scalars.len() {
        let scalar_option = Scalar::from_repr(scalars[i].into());
        if let Some(scalar) = scalar_option.into() {
            out.push(scalar);
        } else {
            return vec![];
        }
    }
    out
}

pub fn to_c_scalar(scalar: &Scalar) -> CScalar {
    let mut c_scalar: CScalar = [0; 32];
    let bytes: FieldBytes = scalar.to_bytes();
    let slice = bytes.as_slice();
    c_scalar.copy_from_slice(slice);
    c_scalar
}

pub fn to_c_affine_point(point: &AffinePoint) -> CAffinePoint {
    let encoded_point = EncodedPoint::from(point);
    let mut c_affine_point: CAffinePoint = [0; SECP256K1_ENCODED_SIZE];
    let slice = encoded_point.as_bytes();
    c_affine_point.copy_from_slice(slice);
    c_affine_point
}

pub fn from_c_affine_point(c_point: &CAffinePoint) -> AffinePoint {
    let mut bytes: CAffinePoint = [0; SECP256K1_ENCODED_SIZE];
    bytes.copy_from_slice(c_point);
    let encoded_point = EncodedPoint::from_bytes(bytes)
        .expect("Failed to parse EncodedPoint");

    AffinePoint::from_encoded_point(&encoded_point)
        .expect("Failed to convert to AffinePoint")
}

pub fn to_c_rand_commitments(
    rand_commitments: Vec<AffinePoint>
) -> [CAffinePoint; R as usize] {
    let mut c_rand_commitments: [CAffinePoint; R as usize] =
        [[0; SECP256K1_ENCODED_SIZE]; R as usize];

    for i in 0..rand_commitments.len() {
        let c_affine_point = to_c_affine_point(&rand_commitments[i]);
        c_rand_commitments[i].copy_from_slice(&c_affine_point);
    }
    c_rand_commitments
}

pub fn to_c_interactive_proof(
    proof: &InteractiveDLogProof
) -> CInteractiveDLogProof {
    let challenge = proof.challenge.into_boxed_slice();
    CInteractiveDLogProof {
        challenge,
        challenge_response: to_c_scalar(&proof.challenge_response),
    }

}

pub fn to_c_proofs(
    proofs: Vec<InteractiveDLogProof>
) -> [CInteractiveDLogProof; R as usize] {
    let mut c_proofs: [CInteractiveDLogProof; R as usize];

    for i in 0..proofs.len() {
        let c_proof = to_c_interactive_proof(&c_proofs[i]);
        c_proof[i].copy_from_slice(&c_proof);
    }
    c_proofs

}

/*fn to_c_dlog_proof(dlog_proof: DLogProof) -> CDLogProof {
    let point = to_c_affine_point(dlog_proof.point);
    let rand_commitments = to_c_rand_commitments(dlog_proof.rand_commitments);
    let proofs = to_c_proofs(dlog_proof.proofs);
    CDLogProof { point, rand_commitments, proofs }
}

pub fn to_c_proof_commitment(
    proof_commitment: ProofCommitment
) -> CProofCommitment {
    let index = proof_commitment.index;
    let commitment = proof_commitment.commitment;
    let proof = to_c_dlog_proof(proof_commitment.proof);

    CProofCommitment { index, proof, commitment }
}*/
