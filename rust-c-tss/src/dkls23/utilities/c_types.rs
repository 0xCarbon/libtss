use dkls23::protocols::Parameters;
use dkls23::protocols::dkg::{
    BroadcastDerivationPhase2to4, ProofCommitment, SessionData,
    TransmitInitZeroSharePhase2to4, UniqueKeepDerivationPhase2to3,
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
pub struct CTransmitInitZeroSharePhase2to4Vec {
    pub data: *const CTransmitInitZeroSharePhase2to4,
    pub len: usize,
}

impl CTransmitInitZeroSharePhase2to4Vec {
    pub fn from(
        zero_transmit_vec: &Vec<TransmitInitZeroSharePhase2to4>,
    ) -> Self {
        let mut c_zero_transmit_vec: Vec<CTransmitInitZeroSharePhase2to4> = Vec::new();
        for zero_transmit in zero_transmit_vec.iter() {
            c_zero_transmit_vec.push(
                CTransmitInitZeroSharePhase2to4::from(&zero_transmit)
            );
        }
        let len = zero_transmit_vec.len();
        let data = Box::into_raw(c_zero_transmit_vec.into_boxed_slice()) as *const CTransmitInitZeroSharePhase2to4;

        CTransmitInitZeroSharePhase2to4Vec { data, len }
    }
}

#[repr(C)]
pub struct CTransmitInitZeroSharePhase2to4 {
    pub parties: CPartiesMessage,
    pub commitment: CHashOutput,
}

impl CTransmitInitZeroSharePhase2to4 {
    pub fn from(transmit_init_zero_share_phase2to4: &TransmitInitZeroSharePhase2to4) -> Self {
        let sender = transmit_init_zero_share_phase2to4.parties.sender;
        let receiver = transmit_init_zero_share_phase2to4.parties.receiver;
        let commitment = transmit_init_zero_share_phase2to4.commitment;

        CTransmitInitZeroSharePhase2to4 {
            parties: CPartiesMessage { sender, receiver },
            commitment,
        }
    }
}

#[repr(C)]
pub struct CUniqueKeepDerivationPhase2to3 {
    pub aux_chain_code: CChainCode,
    pub cc_salt: [u8; 2 * SECURITY as usize],
}

impl CUniqueKeepDerivationPhase2to3 {
    pub fn from(unique_keep_derivation_phase2to3: &UniqueKeepDerivationPhase2to3) -> Self {
        let mut cc_salt: [u8; 2 * SECURITY as usize] = [0; 2 * SECURITY as usize];
        cc_salt.copy_from_slice(unique_keep_derivation_phase2to3.cc_salt.as_slice());

        let aux_chain_code = unique_keep_derivation_phase2to3.aux_chain_code;

        CUniqueKeepDerivationPhase2to3 {
            aux_chain_code,
            cc_salt,
        }
    }
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
    pub zero_transmit: CTransmitInitZeroSharePhase2to4Vec, // share_count - 1
    pub bip_keep: CUniqueKeepDerivationPhase2to3,
    //pub bip_broadcast: CBroadcastDerivationPhase2to4,
}

#[cfg(test)]
mod tests {
    use super::*;
    use dkls23::protocols::PartiesMessage;
    use k256::ProjectivePoint;
    use k256::elliptic_curve::ff::Field;
    use rand;

    #[test]
    fn test_session_data_from_c() {
        let parameters = CParameters {
            share_count: 2,
            threshold: 2,
        };

        let bytes: [u8; 32] = [
            1, 35, 69, 103, 137, 171, 205, 239,
            253, 210, 167, 124, 81, 38, 5, 0,
            144, 143, 142, 141, 140, 139, 138, 137,
            136, 135, 134, 133, 132, 131, 130, 129,
        ];

        let c_session = CSessionData {
            parameters,
            session_id: bytes.as_ptr(),
            session_id_len: bytes.len(),
            party_index: 1,
        };

        let session = c_session.to_session();

        assert_eq!(session.party_index, c_session.party_index);
        assert_eq!(session.parameters.share_count, c_session.parameters.share_count);
        assert_eq!(session.parameters.threshold, c_session.parameters.threshold);
        assert_eq!(session.session_id, bytes);
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
        // `encoded_affine_point_bytes` represents the following point in bytes:
        // AffinePoint {
        //     x: FieldElement(FieldElement5x52([
        //        2468983051731734, 3314604584731398, 688337019694432,
        //        4089669124753892, 217445845428448
        //     ])),
        //     y: FieldElement(FieldElement5x52([
        //        879285755182625, 2721460617154216, 1735586958226576,
        //        1207030472684438, 108878059660018
        //     ])),
        //     infinity: 0,
        // }
        let encoded_affine_point_bytes = [
            3, 197, 196, 14, 95, 232, 224, 232,
            120, 132, 182, 224, 158, 66, 114, 9,
            243, 139, 109, 96, 188, 105, 216, 77,
            128, 48, 104, 197, 134, 233, 193, 67, 22,
        ];

        let encoded_point = EncodedPoint::from_bytes(encoded_affine_point_bytes)
            .expect("Failed to parse EncodedPoint");

        let affine_point = AffinePoint::from_encoded_point(&encoded_point)
            .expect("Failed to convert to AffinePoint");

        let c_affine_point = CAffinePoint::from(&affine_point);
        assert_eq!(c_affine_point.bytes, encoded_affine_point_bytes);
    }

    #[test]
    fn test_affine_point_from_c() {
        // `c_affine_point.bytes` encodes the generator point, wich given by:
        // AffinePoint {
        //     x: FieldElement(FieldElementImpl { value: FieldElement5x52([
        //         705178180786072, 3855836460717471, 4089131105950716,
        //         3301581525494108, 133858670344668]),
        //         magnitude: 1,
        //         normalized: true
        //     }),
        //     y: FieldElement(FieldElementImpl { value: FieldElement5x52([
        //         2199641648059576, 1278080618437060, 3959378566518708,
        //         3455034269351872, 79417610544803]),
        //         magnitude: 1,
        //         normalized: true
        //     }),
        //     infinity: 0
        // }
        let c_affine_point = CAffinePoint {
            bytes: [
                2, 121, 190, 102, 126, 249, 220, 187,
                172, 85, 160, 98, 149, 206, 135, 11,
                7, 2, 155, 252, 219, 45, 206, 40,
                217, 89, 242, 129, 91, 22, 248, 23, 152
            ]
        };

        let affine_point = c_affine_point.to_affine_point();
        assert_eq!(affine_point, AffinePoint::GENERATOR);
    }

    #[test]
    fn test_affine_point_to_c_vec64() {
        let mut affine_points: Vec<AffinePoint> = Vec::with_capacity(R as usize);

        for _ in 0..R {
            let random_scalar = Scalar::random(rand::thread_rng());
            let random_point = ProjectivePoint::GENERATOR * random_scalar;
            let affine_point = AffinePoint::from(random_point);
            affine_points.push(affine_point);
        }

        let c_affine_points = CAffinePoint::from_vec64(&affine_points);
        assert_eq!(affine_points.len(), R as usize);

        for i in 0..affine_points.len() {
            let encoded_point = EncodedPoint::from(&affine_points[i]);
            let bytes = encoded_point.as_bytes();

            assert_eq!(c_affine_points[i].bytes, bytes);
        }
    }

    #[test]
    fn test_interactive_proof_to_c() {

    }

    #[test]
    fn test_interactive_proof_to_c_vec64() {

    }

    #[test]
    fn test_transmit_init_zero_share_phase2to4_to_c() {
        let transmit_init_zero_share_phase2to4 = TransmitInitZeroSharePhase2to4 {
            parties: PartiesMessage {
                sender: 1,
                receiver: 2,
            },

            commitment: [
                1, 35, 69, 103, 137, 171, 205, 239,
                253, 210, 167, 124, 81, 38, 5, 0,
                144, 143, 142, 141, 140, 139, 138, 137,
                136, 135, 134, 133, 132, 131, 130, 129,
            ],
        };

        let c_transmit = CTransmitInitZeroSharePhase2to4::from(&transmit_init_zero_share_phase2to4);

        assert_eq!(
            c_transmit.parties.sender,
            transmit_init_zero_share_phase2to4.parties.sender
        );
        assert_eq!(
            c_transmit.parties.receiver,
            transmit_init_zero_share_phase2to4.parties.receiver
        );
        assert_eq!(
            c_transmit.commitment,
            transmit_init_zero_share_phase2to4.commitment
        );
    }

    #[test]
    fn test_unique_keep_derivation_phase2to3_to_c() {
        let cc_salt: [u8; 64] = [
            1, 35, 69, 103, 137, 171, 205, 239, 253, 210, 167, 124, 81, 38, 5, 0, 144, 143, 142,
            141, 140, 139, 138, 137, 136, 135, 134, 133, 132, 131, 130, 129, 1, 35, 69, 103, 137,
            171, 205, 239, 253, 210, 167, 124, 81, 38, 5, 0, 144, 143, 142, 141, 140, 139, 138,
            137, 136, 135, 134, 133, 132, 131, 130, 129,
        ];
        let unique_keep_derivation_phase2to3 = UniqueKeepDerivationPhase2to3 {
            aux_chain_code: [
                1, 35, 69, 103, 137, 171, 205, 239, 253, 210, 167, 124, 81, 38, 5, 0, 144, 143,
                142, 141, 140, 139, 138, 137, 136, 135, 134, 133, 132, 131, 130, 129,
            ],
            cc_salt: cc_salt.to_vec(),
        };

        let c_unique_keep = CUniqueKeepDerivationPhase2to3::from(&unique_keep_derivation_phase2to3);

        assert_eq!(
            c_unique_keep.aux_chain_code,
            unique_keep_derivation_phase2to3.aux_chain_code
        );
        assert_eq!(
            c_unique_keep.cc_salt,
            unique_keep_derivation_phase2to3.cc_salt.as_slice()
        );
    }
}
