use dkls23::protocols::dkg::{
    BroadcastDerivationPhase2to4, BroadcastDerivationPhase3to4,
    KeepInitMulPhase3to4, KeepInitZeroSharePhase3to4, ProofCommitment,
    SessionData, TransmitInitMulPhase3to4, TransmitInitZeroSharePhase2to4,
    TransmitInitZeroSharePhase3to4, UniqueKeepDerivationPhase2to3,
};
use dkls23::protocols::Parameters;

use dkls23::utilities::ot::base::{OTReceiver, OTSender};
use dkls23::utilities::proofs::{
    CPProof, DLogProof, EncProof, InteractiveDLogProof, RandomCommitments,
};

use k256::{
    elliptic_curve::{ff::PrimeField, sec1::FromEncodedPoint},
    AffinePoint, EncodedPoint, FieldBytes, Scalar,
};

pub const SECURITY: usize = 32;
pub const R: usize = 64;
pub const T: usize = 32;
pub const T_8: usize = T / 8;
pub const KAPPA: usize = 256;
pub const SECP256K1_ENCODED_SIZE: usize = 33;
pub const SALT_LEN: usize = 2 * SECURITY;

pub type CChainCode = [u8; 32];
pub type CSeed = [u8; SECURITY];
pub type CHashOutput = [u8; SECURITY];

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CScalar {
    bytes: [u8; 32],
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
        let scalars =
            unsafe { std::slice::from_raw_parts(self.data, self.len) };
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

    pub fn from_vec64(point_vec: &Vec<AffinePoint>) -> [Self; R] {
        let mut points: [CAffinePoint; R] = [CAffinePoint::default(); R];

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
    pub challenge: [u8; T_8],
    pub challenge_response: CScalar,
}

impl CInteractiveDLogProof {
    fn default() -> Self {
        CInteractiveDLogProof {
            challenge: [0; T_8],
            challenge_response: CScalar::default(),
        }
    }

    pub fn from(proof: &InteractiveDLogProof) -> Self {
        let mut challenge: [u8; T_8] = [0; T_8];
        challenge.copy_from_slice(proof.challenge.as_slice());

        CInteractiveDLogProof {
            challenge,
            challenge_response: CScalar::from(&proof.challenge_response),
        }
    }

    pub fn from_vec64(proofs: &Vec<InteractiveDLogProof>) -> [Self; R] {
        let mut c_proofs: [CInteractiveDLogProof; R] =
            [CInteractiveDLogProof::default(); R];
        for (i, proof) in proofs.iter().enumerate() {
            c_proofs[i] = CInteractiveDLogProof::from(&proof);
        }
        c_proofs
    }
}

#[repr(C)]
pub struct CDLogProof {
    pub point: CAffinePoint,
    pub rand_commitments: [CAffinePoint; R],
    pub proofs: [CInteractiveDLogProof; R],
}

impl CDLogProof {
    pub fn from(dlog_proof: &DLogProof) -> Self {
        let point = CAffinePoint::from(&dlog_proof.point);
        let rand_commitments =
            CAffinePoint::from_vec64(&dlog_proof.rand_commitments);
        let proofs = CInteractiveDLogProof::from_vec64(&dlog_proof.proofs);

        CDLogProof {
            point,
            rand_commitments,
            proofs,
        }
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

        CProofCommitment {
            index,
            proof,
            commitment,
        }
    }
}

#[repr(C)]
pub struct CKeepInitZeroSharePhase2to3 {
    pub seed: CSeed,
    pub salt: [u8; SALT_LEN],
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
        let mut c_zero_transmit_vec: Vec<CTransmitInitZeroSharePhase2to4> =
            Vec::new();
        for zero_transmit in zero_transmit_vec.iter() {
            c_zero_transmit_vec
                .push(CTransmitInitZeroSharePhase2to4::from(&zero_transmit));
        }
        let len = zero_transmit_vec.len();
        let data = Box::into_raw(c_zero_transmit_vec.into_boxed_slice())
            as *const CTransmitInitZeroSharePhase2to4;

        CTransmitInitZeroSharePhase2to4Vec { data, len }
    }
}

#[repr(C)]
pub struct CTransmitInitZeroSharePhase2to4 {
    pub parties: CPartiesMessage,
    pub commitment: CHashOutput,
}

impl CTransmitInitZeroSharePhase2to4 {
    pub fn from(
        transmit_init_zero_share_phase2to4: &TransmitInitZeroSharePhase2to4,
    ) -> Self {
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
#[derive(Clone, Copy)]
pub struct CRandomCommitments {
    pub rc_g: CAffinePoint,
    pub rc_h: CAffinePoint,
}

impl CRandomCommitments {
    fn default() -> Self {
        CRandomCommitments {
            rc_g: CAffinePoint::default(),
            rc_h: CAffinePoint::default(),
        }
    }

    pub fn from(commitments: &RandomCommitments) -> Self {
        CRandomCommitments {
            rc_g: CAffinePoint::from(&commitments.rc_g),
            rc_h: CAffinePoint::from(&commitments.rc_h),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CCPProof {
    pub base_g: CAffinePoint,
    pub base_h: CAffinePoint,
    pub point_u: CAffinePoint,
    pub point_v: CAffinePoint,
    pub challenge_response: CScalar,
}

impl CCPProof {
    fn default() -> Self {
        CCPProof {
            base_g: CAffinePoint::default(),
            base_h: CAffinePoint::default(),
            point_u: CAffinePoint::default(),
            point_v: CAffinePoint::default(),
            challenge_response: CScalar::default(),
        }
    }

    pub fn from(proof: &CPProof) -> Self {
        CCPProof {
            base_g: CAffinePoint::from(&proof.base_g),
            base_h: CAffinePoint::from(&proof.base_h),
            point_u: CAffinePoint::from(&proof.point_u),
            point_v: CAffinePoint::from(&proof.point_v),
            challenge_response: CScalar::from(&proof.challenge_response),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CEncProof {
    pub proof0: CCPProof,
    pub proof1: CCPProof,
    pub commitments0: CRandomCommitments,
    pub commitments1: CRandomCommitments,
    pub challenge0: CScalar,
    pub challenge1: CScalar,
}

impl CEncProof {
    fn default() -> Self {
        CEncProof {
            proof0: CCPProof::default(),
            proof1: CCPProof::default(),
            commitments0: CRandomCommitments::default(),
            commitments1: CRandomCommitments::default(),
            challenge0: CScalar::default(),
            challenge1: CScalar::default(),
        }
    }

    pub fn from(proof: &EncProof) -> Self {
        CEncProof {
            proof0: CCPProof::from(&proof.proof0),
            proof1: CCPProof::from(&proof.proof1),
            commitments0: CRandomCommitments::from(&proof.commitments0),
            commitments1: CRandomCommitments::from(&proof.commitments1),
            challenge0: CScalar::from(&proof.challenge0),
            challenge1: CScalar::from(&proof.challenge1),
        }
    }
}

#[repr(C)]
pub struct CTransmitInitMulPhase3to4 {
    pub parties: CPartiesMessage,
    pub dlog_proof: CDLogProof,
    pub nonce: CScalar,
    pub enc_proofs: [CEncProof; KAPPA],
    pub seed: CSeed,
}

impl CTransmitInitMulPhase3to4 {
    pub fn from(transmit: &TransmitInitMulPhase3to4) -> Self {
        let mut enc_proofs: [CEncProof; KAPPA] = [CEncProof::default(); KAPPA];

        for (i, proof) in transmit.enc_proofs.iter().enumerate() {
            enc_proofs[i] = CEncProof::from(&proof);
        }

        CTransmitInitMulPhase3to4 {
            parties: CPartiesMessage {
                sender: transmit.parties.sender,
                receiver: transmit.parties.receiver,
            },
            dlog_proof: CDLogProof::from(&transmit.dlog_proof),
            nonce: CScalar::from(&transmit.nonce),
            enc_proofs,
            seed: transmit.seed,
        }
    }
}

#[repr(C)]
pub struct CKeepInitZeroSharePhase3to4 {
    pub seed: CSeed,
}

impl CKeepInitZeroSharePhase3to4 {
    pub fn from(keep: &KeepInitZeroSharePhase3to4) -> Self {
        CKeepInitZeroSharePhase3to4 { seed: keep.seed }
    }
}

#[repr(C)]
pub struct CTransmitInitZeroSharePhase3to4 {
    pub parties: CPartiesMessage,
    pub seed: CSeed,
    pub salt: [u8; SALT_LEN],
}

impl CTransmitInitZeroSharePhase3to4 {
    pub fn from(transmit: &TransmitInitZeroSharePhase3to4) -> Self {
        let mut salt: [u8; SALT_LEN] = [0; SALT_LEN];
        salt.copy_from_slice(transmit.salt.as_slice());
        CTransmitInitZeroSharePhase3to4 {
            parties: CPartiesMessage {
                sender: transmit.parties.sender,
                receiver: transmit.parties.receiver,
            },
            seed: transmit.seed,
            salt,
        }
    }
}

#[repr(C)]
pub struct COTSender {
    pub s: CScalar,
    pub proof: CDLogProof,
}

impl COTSender {
    pub fn from(sender: &OTSender) -> Self {
        COTSender {
            s: CScalar::from(&sender.s),
            proof: CDLogProof::from(&sender.proof),
        }
    }
}

#[repr(C)]
pub struct COTReceiver {
    pub seed: CSeed,
}

impl COTReceiver {
    pub fn from(receiver: &OTReceiver) -> Self {
        COTReceiver {
            seed: receiver.seed,
        }
    }
}

#[repr(C)]
pub struct CKeepInitMulPhase3to4 {
    pub ot_sender: COTSender,
    pub nonce: CScalar,
    pub ot_receiver: COTReceiver,
    pub correlation: [bool; KAPPA],
    pub vec_r: CScalarVec,
}

impl CKeepInitMulPhase3to4 {
    pub fn from(keep: &KeepInitMulPhase3to4) -> Self {
        let mut correlation: [bool; KAPPA] = [false; KAPPA];
        correlation.copy_from_slice(keep.correlation.as_slice());

        CKeepInitMulPhase3to4 {
            ot_sender: COTSender::from(&keep.ot_sender),
            nonce: CScalar::from(&keep.nonce),
            ot_receiver: COTReceiver::from(&keep.ot_receiver),
            correlation,
            vec_r: CScalarVec::from(&keep.vec_r),
        }
    }
}

#[repr(C)]
pub struct CBroadcastDerivationPhase3to4 {
    pub sender_index: u8,
    pub aux_chain_code: CChainCode,
    pub cc_salt: [u8; SALT_LEN],
}

impl CBroadcastDerivationPhase3to4 {
    pub fn from(broadcast: &BroadcastDerivationPhase3to4) -> Self {
        let mut cc_salt: [u8; SALT_LEN] = [0; SALT_LEN];
        cc_salt.copy_from_slice(broadcast.cc_salt.as_slice());

        CBroadcastDerivationPhase3to4 {
            sender_index: broadcast.sender_index,
            aux_chain_code: broadcast.aux_chain_code,
            cc_salt,
        }
    }
}

#[repr(C)]
pub struct CUniqueKeepDerivationPhase2to3 {
    pub aux_chain_code: CChainCode,
    pub cc_salt: [u8; SALT_LEN],
}

impl CUniqueKeepDerivationPhase2to3 {
    pub fn from(
        unique_keep_derivation_phase2to3: &UniqueKeepDerivationPhase2to3,
    ) -> Self {
        let mut cc_salt: [u8; SALT_LEN] = [0; SALT_LEN];
        cc_salt.copy_from_slice(
            unique_keep_derivation_phase2to3.cc_salt.as_slice(),
        );

        let aux_chain_code = unique_keep_derivation_phase2to3.aux_chain_code;

        CUniqueKeepDerivationPhase2to3 {
            aux_chain_code,
            cc_salt,
        }
    }

    pub fn to_inner(&self) -> UniqueKeepDerivationPhase2to3 {
        let mut cc_salt: [u8; SALT_LEN] = [0; SALT_LEN];
        cc_salt.copy_from_slice(self.cc_salt.as_slice());

        UniqueKeepDerivationPhase2to3 {
            aux_chain_code: self.aux_chain_code,
            cc_salt: cc_salt.to_vec(),
        }
    }
}

#[repr(C)]
pub struct CBroadcastDerivationPhase2to4 {
    pub sender_index: u8,
    pub cc_commitment: CHashOutput,
}

impl CBroadcastDerivationPhase2to4 {
    pub fn from(
        broadcast_derivation_phase2to4: &BroadcastDerivationPhase2to4,
    ) -> Self {
        let sender_index = broadcast_derivation_phase2to4.sender_index;
        let cc_commitment = broadcast_derivation_phase2to4.cc_commitment;

        CBroadcastDerivationPhase2to4 {
            sender_index,
            cc_commitment,
        }
    }
}

#[repr(C)]
pub struct CTransmitInitZeroSharePhase3to4Vec {
    pub data: *const CTransmitInitZeroSharePhase3to4,
    pub len: usize,
}

impl CTransmitInitZeroSharePhase3to4Vec {
    pub fn from(vec: &Vec<TransmitInitZeroSharePhase3to4>) -> Self {
        let mut c_vec: Vec<CTransmitInitZeroSharePhase3to4> = Vec::new();
        for item in vec.iter() {
            c_vec.push(CTransmitInitZeroSharePhase3to4::from(item));
        }
        let len = c_vec.len();
        let data = Box::into_raw(c_vec.into_boxed_slice())
            as *const CTransmitInitZeroSharePhase3to4;
        CTransmitInitZeroSharePhase3to4Vec { data, len }
    }
}

#[repr(C)]
pub struct CTransmitInitMulPhase3to4Vec {
    pub data: *const CTransmitInitMulPhase3to4,
    pub len: usize,
}

impl CTransmitInitMulPhase3to4Vec {
    pub fn from(vec: &Vec<TransmitInitMulPhase3to4>) -> Self {
        let mut c_vec: Vec<CTransmitInitMulPhase3to4> = Vec::new();
        for item in vec.iter() {
            c_vec.push(CTransmitInitMulPhase3to4::from(item));
        }
        let len = c_vec.len();
        let data = Box::into_raw(c_vec.into_boxed_slice())
            as *const CTransmitInitMulPhase3to4;
        CTransmitInitMulPhase3to4Vec { data, len }
    }
}

#[repr(C)]
pub struct CPhase2Out {
    pub poly_point: CScalar,
    pub proof_commitment: CProofCommitment,
    //pub zero_keep: CBTreeMap<u8, KeepInitZeroSharePhase2to3>,
    pub zero_transmit: CTransmitInitZeroSharePhase2to4Vec, // share_count - 1
    pub bip_keep: CUniqueKeepDerivationPhase2to3,
    pub bip_broadcast: CBroadcastDerivationPhase2to4,
}

#[repr(C)]
pub struct CPhase3Out {
    pub zero_keep: CKeepInitZeroSharePhase3to4,
    pub zero_transmit: CTransmitInitZeroSharePhase3to4Vec,
    // pub mul_keep: CKeepInitMulPhase3to4BTreeMap,
    pub mul_transmit: CTransmitInitMulPhase3to4Vec,
    pub bip_broadcast: CBroadcastDerivationPhase3to4,
}

#[cfg(test)]
mod tests {
    use super::*;
    use dkls23::protocols::PartiesMessage;
    use k256::elliptic_curve::ff::Field;
    use k256::ProjectivePoint;
    use rand;

    #[test]
    fn test_session_data_from_c() {
        let parameters = CParameters {
            share_count: 2,
            threshold: 2,
        };

        let bytes: [u8; 32] = [
            1, 35, 69, 103, 137, 171, 205, 239, 253, 210, 167, 124, 81, 38, 5,
            0, 144, 143, 142, 141, 140, 139, 138, 137, 136, 135, 134, 133, 132,
            131, 130, 129,
        ];

        let c_session = CSessionData {
            parameters,
            session_id: bytes.as_ptr(),
            session_id_len: bytes.len(),
            party_index: 1,
        };

        let session = c_session.to_session();

        assert_eq!(session.party_index, c_session.party_index);
        assert_eq!(
            session.parameters.share_count,
            c_session.parameters.share_count
        );
        assert_eq!(
            session.parameters.threshold,
            c_session.parameters.threshold
        );
        assert_eq!(session.session_id, bytes);
    }

    #[test]
    fn test_scalar_to_c() {
        let bytes = [
            1, 35, 69, 103, 137, 171, 205, 239, 253, 210, 167, 124, 81, 38, 5,
            0, 144, 143, 142, 141, 140, 139, 138, 137, 136, 135, 134, 133, 132,
            131, 130, 129,
        ];

        let scalar =
            Scalar::from_repr(bytes.into()).expect("Failed to create scalar");
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
            3, 197, 196, 14, 95, 232, 224, 232, 120, 132, 182, 224, 158, 66,
            114, 9, 243, 139, 109, 96, 188, 105, 216, 77, 128, 48, 104, 197,
            134, 233, 193, 67, 22,
        ];

        let encoded_point =
            EncodedPoint::from_bytes(encoded_affine_point_bytes)
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
                2, 121, 190, 102, 126, 249, 220, 187, 172, 85, 160, 98, 149,
                206, 135, 11, 7, 2, 155, 252, 219, 45, 206, 40, 217, 89, 242,
                129, 91, 22, 248, 23, 152,
            ],
        };

        let affine_point = c_affine_point.to_affine_point();
        assert_eq!(affine_point, AffinePoint::GENERATOR);
    }

    #[test]
    fn test_affine_point_to_c_vec64() {
        let mut affine_points: Vec<AffinePoint> = Vec::with_capacity(R);

        for _ in 0..R {
            let random_scalar = Scalar::random(rand::thread_rng());
            let random_point = ProjectivePoint::GENERATOR * random_scalar;
            let affine_point = AffinePoint::from(random_point);
            affine_points.push(affine_point);
        }

        let c_affine_points = CAffinePoint::from_vec64(&affine_points);
        assert_eq!(affine_points.len(), R);

        for i in 0..affine_points.len() {
            let encoded_point = EncodedPoint::from(&affine_points[i]);
            let bytes = encoded_point.as_bytes();

            assert_eq!(c_affine_points[i].bytes, bytes);
        }
    }

    #[test]
    fn test_interactive_proof_to_c() {}

    #[test]
    fn test_interactive_proof_to_c_vec64() {}

    #[test]
    fn test_transmit_init_zero_share_phase2to4_to_c() {
        let transmit_init_zero_share_phase2to4 =
            TransmitInitZeroSharePhase2to4 {
                parties: PartiesMessage {
                    sender: 1,
                    receiver: 2,
                },

                commitment: [
                    1, 35, 69, 103, 137, 171, 205, 239, 253, 210, 167, 124, 81,
                    38, 5, 0, 144, 143, 142, 141, 140, 139, 138, 137, 136, 135,
                    134, 133, 132, 131, 130, 129,
                ],
            };

        let c_transmit = CTransmitInitZeroSharePhase2to4::from(
            &transmit_init_zero_share_phase2to4,
        );

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
            1, 35, 69, 103, 137, 171, 205, 239, 253, 210, 167, 124, 81, 38, 5,
            0, 144, 143, 142, 141, 140, 139, 138, 137, 136, 135, 134, 133, 132,
            131, 130, 129, 1, 35, 69, 103, 137, 171, 205, 239, 253, 210, 167,
            124, 81, 38, 5, 0, 144, 143, 142, 141, 140, 139, 138, 137, 136,
            135, 134, 133, 132, 131, 130, 129,
        ];
        let unique_keep_derivation_phase2to3 = UniqueKeepDerivationPhase2to3 {
            aux_chain_code: [
                1, 35, 69, 103, 137, 171, 205, 239, 253, 210, 167, 124, 81, 38,
                5, 0, 144, 143, 142, 141, 140, 139, 138, 137, 136, 135, 134,
                133, 132, 131, 130, 129,
            ],
            cc_salt: cc_salt.to_vec(),
        };

        let c_unique_keep = CUniqueKeepDerivationPhase2to3::from(
            &unique_keep_derivation_phase2to3,
        );

        assert_eq!(
            c_unique_keep.aux_chain_code,
            unique_keep_derivation_phase2to3.aux_chain_code
        );
        assert_eq!(
            c_unique_keep.cc_salt,
            unique_keep_derivation_phase2to3.cc_salt.as_slice()
        );
    }

    #[test]
    fn test_unique_keep_derivation_phase2to3_to_inner() {
        let aux_chain_code: CChainCode = [
            1, 35, 69, 103, 137, 171, 205, 239, 253, 210, 167, 124, 81, 38, 5,
            0, 144, 143, 142, 141, 140, 139, 138, 137, 136, 135, 134, 133, 132,
            131, 130, 129,
        ];

        let cc_salt: [u8; SALT_LEN] = [
            1, 35, 69, 103, 137, 171, 205, 239, 253, 210, 167, 124, 81, 38, 5,
            0, 144, 143, 142, 141, 140, 139, 138, 137, 136, 135, 134, 133, 132,
            131, 130, 129, 1, 35, 69, 103, 137, 171, 205, 239, 253, 210, 167,
            124, 81, 38, 5, 0, 144, 143, 142, 141, 140, 139, 138, 137, 136,
            135, 134, 133, 132, 131, 130, 129,
        ];

        let c_unique_keep = CUniqueKeepDerivationPhase2to3 {
            aux_chain_code,
            cc_salt,
        };

        let unique_keep = c_unique_keep.to_inner();

        assert_eq!(unique_keep.aux_chain_code, c_unique_keep.aux_chain_code);
        assert_eq!(unique_keep.cc_salt, c_unique_keep.cc_salt.to_vec());
    }

    #[test]
    fn test_broadcast_derivation_phase2to4_to_c() {
        let broadcast_derivation_phase2to4 = BroadcastDerivationPhase2to4 {
            sender_index: 1,
            cc_commitment: [
                1, 35, 69, 103, 137, 171, 205, 239, 253, 210, 167, 124, 81, 38,
                5, 0, 144, 143, 142, 141, 140, 139, 138, 137, 136, 135, 134,
                133, 132, 131, 130, 129,
            ],
        };

        let c_broadcast = CBroadcastDerivationPhase2to4::from(
            &broadcast_derivation_phase2to4,
        );

        assert_eq!(
            c_broadcast.sender_index,
            broadcast_derivation_phase2to4.sender_index
        );
        assert_eq!(
            c_broadcast.cc_commitment,
            broadcast_derivation_phase2to4.cc_commitment
        );
    }

    #[test]
    fn test_random_commitments_to_c() {
        let random_scalar = Scalar::random(rand::thread_rng());
        let random_point_g = ProjectivePoint::GENERATOR * random_scalar;
        let random_point_h = ProjectivePoint::GENERATOR * random_scalar;
        let commitments = RandomCommitments {
            rc_g: AffinePoint::from(random_point_g),
            rc_h: AffinePoint::from(random_point_h),
        };

        let c_commitments = CRandomCommitments::from(&commitments);

        assert_eq!(
            c_commitments.rc_g.bytes,
            CAffinePoint::from(&commitments.rc_g).bytes
        );
        assert_eq!(
            c_commitments.rc_h.bytes,
            CAffinePoint::from(&commitments.rc_h).bytes
        );
    }

    #[test]
    fn test_cp_proof_to_c() {
        let random_scalar = Scalar::random(rand::thread_rng());
        let random_point_g = ProjectivePoint::GENERATOR * random_scalar;
        let random_point_h = ProjectivePoint::GENERATOR * random_scalar;
        let random_point_u = ProjectivePoint::GENERATOR * random_scalar;
        let random_point_v = ProjectivePoint::GENERATOR * random_scalar;
        let challenge_response = Scalar::random(rand::thread_rng());

        let proof = CPProof {
            base_g: AffinePoint::from(random_point_g),
            base_h: AffinePoint::from(random_point_h),
            point_u: AffinePoint::from(random_point_u),
            point_v: AffinePoint::from(random_point_v),
            challenge_response,
        };

        let c_proof = CCPProof::from(&proof);

        assert_eq!(
            c_proof.base_g.bytes,
            CAffinePoint::from(&proof.base_g).bytes
        );
        assert_eq!(
            c_proof.base_h.bytes,
            CAffinePoint::from(&proof.base_h).bytes
        );
        assert_eq!(
            c_proof.point_u.bytes,
            CAffinePoint::from(&proof.point_u).bytes
        );
        assert_eq!(
            c_proof.point_v.bytes,
            CAffinePoint::from(&proof.point_v).bytes
        );
        assert_eq!(
            c_proof.challenge_response.bytes,
            CScalar::from(&proof.challenge_response).bytes
        );
    }

    #[test]
    fn test_enc_proof_to_c() {
        let random_scalar = Scalar::random(rand::thread_rng());
        let random_point_g = ProjectivePoint::GENERATOR * random_scalar;
        let random_point_h = ProjectivePoint::GENERATOR * random_scalar;
        let random_point_u = ProjectivePoint::GENERATOR * random_scalar;
        let random_point_v = ProjectivePoint::GENERATOR * random_scalar;
        let challenge_response = Scalar::random(rand::thread_rng());

        let proof0 = CPProof {
            base_g: AffinePoint::from(random_point_g),
            base_h: AffinePoint::from(random_point_h),
            point_u: AffinePoint::from(random_point_u),
            point_v: AffinePoint::from(random_point_v),
            challenge_response,
        };

        let proof1 = proof0.clone();

        let commitments0 = RandomCommitments {
            rc_g: AffinePoint::from(random_point_g),
            rc_h: AffinePoint::from(random_point_h),
        };

        let commitments1 = commitments0.clone();

        let challenge0 = Scalar::random(rand::thread_rng());
        let challenge1 = Scalar::random(rand::thread_rng());

        let enc_proof = EncProof {
            proof0,
            proof1,
            commitments0,
            commitments1,
            challenge0,
            challenge1,
        };

        let c_enc_proof = CEncProof::from(&enc_proof);

        assert_eq!(
            c_enc_proof.proof0.base_g.bytes,
            CAffinePoint::from(&enc_proof.proof0.base_g).bytes
        );
        assert_eq!(
            c_enc_proof.proof1.base_g.bytes,
            CAffinePoint::from(&enc_proof.proof1.base_g).bytes
        );
        assert_eq!(
            c_enc_proof.commitments0.rc_g.bytes,
            CAffinePoint::from(&enc_proof.commitments0.rc_g).bytes
        );
        assert_eq!(
            c_enc_proof.commitments1.rc_g.bytes,
            CAffinePoint::from(&enc_proof.commitments1.rc_g).bytes
        );
        assert_eq!(
            c_enc_proof.challenge0.bytes,
            CScalar::from(&enc_proof.challenge0).bytes
        );
        assert_eq!(
            c_enc_proof.challenge1.bytes,
            CScalar::from(&enc_proof.challenge1).bytes
        );
    }

    #[test]
    fn test_transmit_init_mul_phase3to4_to_c() {
        let random_scalar = Scalar::random(rand::thread_rng());
        let random_point = ProjectivePoint::GENERATOR * random_scalar;
        let dlog_proof = DLogProof {
            point: AffinePoint::from(random_point),
            rand_commitments: vec![AffinePoint::from(random_point); R],
            proofs: vec![
                InteractiveDLogProof {
                    challenge: vec![0u8; T_8],
                    challenge_response: random_scalar,
                };
                R
            ],
        };

        let enc_proofs = vec![EncProof {
            proof0: CPProof {
                base_g: AffinePoint::from(random_point),
                base_h: AffinePoint::from(random_point),
                point_u: AffinePoint::from(random_point),
                point_v: AffinePoint::from(random_point),
                challenge_response: random_scalar,
            },
            proof1: CPProof {
                base_g: AffinePoint::from(random_point),
                base_h: AffinePoint::from(random_point),
                point_u: AffinePoint::from(random_point),
                point_v: AffinePoint::from(random_point),
                challenge_response: random_scalar,
            },
            commitments0: RandomCommitments {
                rc_g: AffinePoint::from(random_point),
                rc_h: AffinePoint::from(random_point),
            },
            commitments1: RandomCommitments {
                rc_g: AffinePoint::from(random_point),
                rc_h: AffinePoint::from(random_point),
            },
            challenge0: random_scalar,
            challenge1: random_scalar,
        }];

        let transmit = TransmitInitMulPhase3to4 {
            parties: PartiesMessage {
                sender: 1,
                receiver: 2,
            },
            dlog_proof,
            nonce: random_scalar,
            enc_proofs,
            seed: [0u8; SECURITY],
        };

        let c_transmit = CTransmitInitMulPhase3to4::from(&transmit);

        assert_eq!(c_transmit.parties.sender, transmit.parties.sender);
        assert_eq!(c_transmit.parties.receiver, transmit.parties.receiver);
        assert_eq!(
            c_transmit.dlog_proof.point.bytes,
            CAffinePoint::from(&transmit.dlog_proof.point).bytes
        );
        assert_eq!(
            c_transmit.nonce.bytes,
            CScalar::from(&transmit.nonce).bytes
        );
        assert_eq!(c_transmit.seed, transmit.seed);
    }

    #[test]
    fn test_keep_init_zero_share_phase3to4_to_c() {
        let keep = KeepInitZeroSharePhase3to4 {
            seed: [0u8; SECURITY],
        };

        let c_keep = CKeepInitZeroSharePhase3to4::from(&keep);

        assert_eq!(c_keep.seed, keep.seed);
    }

    #[test]
    fn test_transmit_init_zero_share_phase3to4_to_c() {
        let salt: [u8; SALT_LEN] = [
            1, 35, 69, 103, 137, 171, 205, 239, 253, 210, 167, 124, 81, 38, 5,
            0, 144, 143, 142, 141, 140, 139, 138, 137, 136, 135, 134, 133, 132,
            131, 130, 129, 1, 35, 69, 103, 137, 171, 205, 239, 253, 210, 167,
            124, 81, 38, 5, 0, 144, 143, 142, 141, 140, 139, 138, 137, 136,
            135, 134, 133, 132, 131, 130, 129,
        ];

        let transmit = TransmitInitZeroSharePhase3to4 {
            parties: PartiesMessage {
                sender: 1,
                receiver: 2,
            },
            seed: [0u8; SECURITY],
            salt: salt.to_vec(),
        };

        let c_transmit = CTransmitInitZeroSharePhase3to4::from(&transmit);

        assert_eq!(c_transmit.parties.sender, transmit.parties.sender);
        assert_eq!(c_transmit.parties.receiver, transmit.parties.receiver);
        assert_eq!(c_transmit.seed, transmit.seed);
        assert_eq!(c_transmit.salt.to_vec(), transmit.salt);
    }

    #[test]
    fn test_ot_sender_to_c() {
        let random_scalar = Scalar::random(rand::thread_rng());
        let random_point = ProjectivePoint::GENERATOR * random_scalar;
        let dlog_proof = DLogProof {
            point: AffinePoint::from(random_point),
            rand_commitments: vec![AffinePoint::from(random_point); R],
            proofs: vec![
                InteractiveDLogProof {
                    challenge: vec![0u8; T_8],
                    challenge_response: random_scalar,
                };
                R
            ],
        };

        let sender = OTSender {
            s: random_scalar,
            proof: dlog_proof,
        };

        let c_sender = COTSender::from(&sender);

        assert_eq!(c_sender.s.bytes, CScalar::from(&sender.s).bytes);
        assert_eq!(
            c_sender.proof.point.bytes,
            CAffinePoint::from(&sender.proof.point).bytes
        );
    }

    #[test]
    fn test_ot_receiver_to_c() {
        let receiver = OTReceiver {
            seed: [0u8; SECURITY],
        };

        let c_receiver = COTReceiver::from(&receiver);

        assert_eq!(c_receiver.seed, receiver.seed);
    }

    #[test]
    fn test_keep_init_mul_phase3to4_to_c() {
        let random_scalar = Scalar::random(rand::thread_rng());
        let random_point = ProjectivePoint::GENERATOR * random_scalar;
        let dlog_proof = DLogProof {
            point: AffinePoint::from(random_point),
            rand_commitments: vec![AffinePoint::from(random_point); R],
            proofs: vec![
                InteractiveDLogProof {
                    challenge: vec![0u8; T_8],
                    challenge_response: random_scalar,
                };
                R
            ],
        };

        let ot_sender = OTSender {
            s: random_scalar,
            proof: dlog_proof.clone(),
        };

        let ot_receiver = OTReceiver {
            seed: [0u8; SECURITY],
        };

        let correlation: Vec<bool> = vec![true, false, true];
        let vec_r: Vec<Scalar> =
            vec![random_scalar, random_scalar, random_scalar];

        let keep = KeepInitMulPhase3to4 {
            ot_sender,
            nonce: random_scalar,
            ot_receiver,
            correlation: correlation.clone(),
            vec_r: vec_r.clone(),
        };

        let c_keep = CKeepInitMulPhase3to4::from(&keep);

        assert_eq!(
            c_keep.ot_sender.s.bytes,
            CScalar::from(&keep.ot_sender.s).bytes
        );
        assert_eq!(
            c_keep.ot_sender.proof.point.bytes,
            CAffinePoint::from(&keep.ot_sender.proof.point).bytes
        );
        assert_eq!(c_keep.nonce.bytes, CScalar::from(&keep.nonce).bytes);
        assert_eq!(c_keep.ot_receiver.seed, keep.ot_receiver.seed);
        assert_eq!(
            unsafe {
                std::slice::from_raw_parts(
                    c_keep.correlation,
                    c_keep.correlation_len,
                )
            },
            correlation.as_slice()
        );
        assert_eq!(c_keep.vec_r.to_vec(), vec_r);
    }

    #[test]
    fn test_broadcast_derivation_phase3to4_to_c() {
        let broadcast = BroadcastDerivationPhase3to4 {
            sender_index: 1,
            aux_chain_code: [0u8; 32],
            cc_salt: vec![1, 2, 3, 4, 5],
        };

        let c_broadcast = CBroadcastDerivationPhase3to4::from(&broadcast);

        assert_eq!(c_broadcast.sender_index, broadcast.sender_index);
        assert_eq!(c_broadcast.aux_chain_code, broadcast.aux_chain_code);
        assert_eq!(
            unsafe {
                std::slice::from_raw_parts(
                    c_broadcast.cc_salt,
                    c_broadcast.cc_salt_len,
                )
            },
            broadcast.cc_salt.as_slice()
        );
    }

    #[test]
    fn test_transmit_init_zero_share_phase3to4_vec_from() {
        let salt: Vec<u8> = vec![1, 2, 3, 4, 5];
        let transmit1 = TransmitInitZeroSharePhase3to4 {
            parties: PartiesMessage {
                sender: 1,
                receiver: 2,
            },
            seed: [0u8; SECURITY as usize],
            salt: salt.clone(),
        };

        let transmit2 = TransmitInitZeroSharePhase3to4 {
            parties: PartiesMessage {
                sender: 3,
                receiver: 4,
            },
            seed: [1u8; SECURITY as usize],
            salt: salt.clone(),
        };

        let vec = vec![transmit1, transmit2];
        let c_vec = CTransmitInitZeroSharePhase3to4Vec::from(&vec);

        assert_eq!(c_vec.len, vec.len());
        let c_items =
            unsafe { std::slice::from_raw_parts(c_vec.data, c_vec.len) };

        for (i, item) in c_items.iter().enumerate() {
            assert_eq!(item.parties.sender, vec[i].parties.sender);
            assert_eq!(item.parties.receiver, vec[i].parties.receiver);
            assert_eq!(item.seed, vec[i].seed);
            assert_eq!(
                unsafe { std::slice::from_raw_parts(item.salt, item.salt_len) },
                vec[i].salt.as_slice()
            );
        }
    }

    #[test]
    fn test_transmit_init_mul_phase3to4_vec_from() {
        let random_scalar = Scalar::random(rand::thread_rng());
        let random_point = ProjectivePoint::GENERATOR * random_scalar;
        let dlog_proof = DLogProof {
            point: AffinePoint::from(random_point),
            rand_commitments: vec![AffinePoint::from(random_point); R],
            proofs: vec![
                InteractiveDLogProof {
                    challenge: vec![0u8; T_8],
                    challenge_response: random_scalar,
                };
                R
            ],
        };

        let enc_proofs = vec![EncProof {
            proof0: CPProof {
                base_g: AffinePoint::from(random_point),
                base_h: AffinePoint::from(random_point),
                point_u: AffinePoint::from(random_point),
                point_v: AffinePoint::from(random_point),
                challenge_response: random_scalar,
            },
            proof1: CPProof {
                base_g: AffinePoint::from(random_point),
                base_h: AffinePoint::from(random_point),
                point_u: AffinePoint::from(random_point),
                point_v: AffinePoint::from(random_point),
                challenge_response: random_scalar,
            },
            commitments0: RandomCommitments {
                rc_g: AffinePoint::from(random_point),
                rc_h: AffinePoint::from(random_point),
            },
            commitments1: RandomCommitments {
                rc_g: AffinePoint::from(random_point),
                rc_h: AffinePoint::from(random_point),
            },
            challenge0: random_scalar,
            challenge1: random_scalar,
        }];

        let transmit1 = TransmitInitMulPhase3to4 {
            parties: PartiesMessage {
                sender: 1,
                receiver: 2,
            },
            dlog_proof: dlog_proof.clone(),
            nonce: random_scalar,
            enc_proofs: enc_proofs.clone(),
            seed: [0u8; SECURITY],
        };

        let transmit2 = TransmitInitMulPhase3to4 {
            parties: PartiesMessage {
                sender: 3,
                receiver: 4,
            },
            dlog_proof,
            nonce: random_scalar,
            enc_proofs,
            seed: [1u8; SECURITY],
        };

        let vec = vec![transmit1, transmit2];
        let c_vec = CTransmitInitMulPhase3to4Vec::from(&vec);

        assert_eq!(c_vec.len, vec.len());
        let c_items =
            unsafe { std::slice::from_raw_parts(c_vec.data, c_vec.len) };

        for (i, item) in c_items.iter().enumerate() {
            assert_eq!(item.parties.sender, vec[i].parties.sender);
            assert_eq!(item.parties.receiver, vec[i].parties.receiver);
            assert_eq!(
                item.dlog_proof.point.bytes,
                CAffinePoint::from(&vec[i].dlog_proof.point).bytes
            );
            assert_eq!(item.nonce.bytes, CScalar::from(&vec[i].nonce).bytes);
            assert_eq!(item.seed, vec[i].seed);
        }
    }
}
