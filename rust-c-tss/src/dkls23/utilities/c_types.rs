use dkls23::protocols::Parameters;
use dkls23::protocols::dkg::{
    ProofCommitment, SessionData
};

use dkls23::utilities::proofs::{
    DLogProof, InteractiveDLogProof, R, T,
};

use::dkls23::SECURITY;

use k256::{
    elliptic_curve::{
        ff::PrimeField,
        sec1::FromEncodedPoint
    },
    AffinePoint, EncodedPoint, FieldBytes, Scalar,
};

pub const SECP256K1_ENCODED_SIZE: usize = 33;

pub type CChainCode = [u8; 32];
pub type CSeed = [u8; SECURITY as usize];
pub type CHashOutput = [u8; SECURITY as usize];

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CScalar {
    bytes: [u8; 32]
}

impl CScalar {
    fn default() -> Self {
        CScalar { bytes: [0; 32] }
    }

    pub fn from(scalar: &Scalar) -> Self {
        let mut c_scalar: CScalar = CScalar { bytes: [0; 32] };
        let bytes: FieldBytes = scalar.to_bytes();
        let slice = bytes.as_slice();
        c_scalar.bytes.copy_from_slice(slice);
        c_scalar
    }
}

#[repr(C)]
pub struct CScalarVec {
    pub data: *const CScalar,
    pub len: usize,
}

impl CScalarVec {
    pub fn to_vec(&self) -> Vec<Scalar> {
        let mut out: Vec<Scalar> = Vec::new();
        let scalars = unsafe {
            std::slice::from_raw_parts(self.data, self.len)
        };
        for i in 0..scalars.len() {
            let scalar_option = Scalar::from_repr(scalars[i].bytes.into());
            if let Some(scalar) = scalar_option.into() {
                out.push(scalar);
            } else {
                return vec![];
            }
        }
        out
    }

    pub fn from(scalar_vec: &Vec<Scalar>) -> Self {
        let mut out: Vec<CScalar> = Vec::new();
        for scalar in scalar_vec.iter() {
            out.push(CScalar::from(&scalar));
        }
        let len = out.len();
        let data = Box::into_raw(out.into_boxed_slice()) as *const CScalar;
        CScalarVec { data, len }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CAffinePoint {
    bytes: [u8; SECP256K1_ENCODED_SIZE],
}

impl CAffinePoint {
    fn default() -> Self {
        CAffinePoint {
            bytes: [0; SECP256K1_ENCODED_SIZE],
        }
    }

    pub fn from(point: &AffinePoint) -> Self {
        let encoded_point = EncodedPoint::from(point);
        let mut bytes: [u8; SECP256K1_ENCODED_SIZE] =
            [0; SECP256K1_ENCODED_SIZE];
        let slice = encoded_point.as_bytes();
        bytes.copy_from_slice(slice);
        CAffinePoint { bytes }
    }

    pub fn to_affine_point(&self) -> AffinePoint {
        let encoded_point = EncodedPoint::from_bytes(&self.bytes)
            .expect("Failed to parse EncodedPoint");

        AffinePoint::from_encoded_point(&encoded_point)
            .expect("Failed to convert to AffinePoint")
    }

    pub fn from_vec64(point_vec: &Vec<AffinePoint>) -> [Self; R as usize] {
        let mut points: [CAffinePoint; R as usize] =
            [CAffinePoint::default(); R as usize];

        for (i, point) in point_vec.iter().enumerate() {
            let c_affine_point = CAffinePoint::from(&point);
            points[i] = c_affine_point;
        }
        points
    }
}

#[repr(C)]
pub struct CParameters {
    pub threshold: u8,
    pub share_count: u8,
}

#[repr(C)]
pub struct CSessionData {
    pub parameters: CParameters,
    pub party_index: u8,
    pub session_id_len: usize,
    pub session_id: *const u8,
}

impl CSessionData {
    pub fn to_session(&self) -> SessionData {
        let session_id_slice = unsafe {
            std::slice::from_raw_parts(self.session_id, self.session_id_len)
        };
        SessionData {
            party_index: self.party_index,
            parameters: Parameters {
                threshold: self.parameters.threshold,
                share_count: self.parameters.share_count,
            },
            session_id: Vec::from(session_id_slice),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CInteractiveDLogProof {
    pub challenge: [u8; (T / 8) as usize],
    pub challenge_response: CScalar,
}

impl CInteractiveDLogProof {
    fn default() -> Self {
        CInteractiveDLogProof {
            challenge: [0; (T / 8) as usize],
            challenge_response: CScalar::default(),
        }
    }

    pub fn from(proof: &InteractiveDLogProof) -> Self {
        let mut challenge: [u8; (T / 8) as usize] = [0; (T / 8) as usize];
        challenge.copy_from_slice(proof.challenge.as_slice());

        CInteractiveDLogProof {
            challenge,
            challenge_response: CScalar::from(&proof.challenge_response),
        }
    }

    pub fn from_vec64(proofs: &Vec<InteractiveDLogProof>) -> [Self; R as usize] {
        let mut c_proofs: [CInteractiveDLogProof; R as usize] =
            [CInteractiveDLogProof::default(); R as usize];
        for (i, proof) in proofs.iter().enumerate() {
            c_proofs[i] = CInteractiveDLogProof::from(&proof);
        }
        c_proofs
    }
}

#[repr(C)]
pub struct CDLogProof {
    pub point: CAffinePoint,
    pub rand_commitments: [CAffinePoint; R as usize],
    pub proofs: [CInteractiveDLogProof; R as usize],
}

impl CDLogProof {
    pub fn from(dlog_proof: &DLogProof) -> Self {
        let point = CAffinePoint::from(&dlog_proof.point);
        let rand_commitments = CAffinePoint::from_vec64(&dlog_proof.rand_commitments);
        let proofs = CInteractiveDLogProof::from_vec64(&dlog_proof.proofs);

        CDLogProof { point, rand_commitments, proofs }
    }
}

#[repr(C)]
pub struct CProofCommitment {
    pub index: u8,
    pub proof: CDLogProof,
    pub commitment: CHashOutput,
}

impl CProofCommitment {
    pub fn from(proof_commitment: &ProofCommitment) -> Self {
        let index = proof_commitment.index;
        let commitment = proof_commitment.commitment;
        let proof = CDLogProof::from(&proof_commitment.proof);

        CProofCommitment { index, proof, commitment }
    }
}

#[repr(C)]
pub struct CKeepInitZeroSharePhase2to3 {
    pub seed: CSeed,
    pub salt: [u8; 2 * SECURITY as usize],
}

#[repr(C)]
pub struct CBTreeMap {
    pub index: u8,
}

#[repr(C)]
pub struct CPartiesMessage {
    pub sender: u8,
    pub receiver: u8,
}

#[repr(C)]
pub struct CTransmitInitZeroSharePhase2to4 {
    pub parties: CPartiesMessage,
    pub commitment: CHashOutput,
}

#[repr(C)]
pub struct CUniqueKeepDerivationPhase2to3 {
    pub aux_chain_code: CChainCode,
    pub cc_salt: [u8; 2 * SECURITY as usize],
}

#[repr(C)]
pub struct CBroadcastDerivationPhase2to4 {
    pub sender_index: u8,
    pub cc_commitment: CHashOutput,
}

#[repr(C)]
pub struct CPhase2Out {
    pub poly_point: CScalar,
    pub proof_commitment: CProofCommitment,
    //pub zero_keep: CBTreeMap<u8, KeepInitZeroSharePhase2to3>,
    pub zero_transmit: *const CTransmitInitZeroSharePhase2to4, // share_count - 1
    pub bip_keep: CUniqueKeepDerivationPhase2to3,
    pub bip_broadcast: CBroadcastDerivationPhase2to4,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_data_from_c() {
    }

    #[test]
    fn test_scalar_to_c() {
        let bytes = [
            1, 35, 69, 103, 137, 171, 205, 239,
            253, 210, 167, 124, 81, 38, 5, 0,
            144, 143, 142, 141, 140, 139, 138, 137,
            136, 135, 134, 133, 132, 131, 130, 129,
        ];

        let scalar = Scalar::from_repr(bytes.into()).expect("Failed to create scalar");
        let c_scalar = CScalar::from(&scalar);

        assert_eq!(bytes, c_scalar.bytes);
    }

    #[test]
    fn test_affine_point_to_c() {

    }

    #[test]
    fn test_affine_point_from_c() {

    }

    #[test]
    fn test_affine_point_to_c_vec64() {

    }

    #[test]
    fn test_interactive_proof_to_c() {

    }

    #[test]
    fn test_interactive_proof_to_c_vec64() {

    }

}
