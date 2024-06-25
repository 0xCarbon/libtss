use::dkls23::utilities::proofs::R;
use::dkls23::utilities::proofs::T;
use::dkls23::SECURITY;

pub const SECP256K1_ENCODED_SIZE: usize = 33;

pub type CChainCode = [u8; 32];
pub type CScalar = [u8; 32];
pub type CAffinePoint = [u8; SECP256K1_ENCODED_SIZE];
pub type CSeed = [u8; SECURITY as usize];
pub type CHashOutput = [u8; SECURITY as usize];

#[repr(C)]
pub struct CScalarVec {
    pub data: *const CScalar,
    pub len: usize,
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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CInteractiveDLogProof {
    pub challenge: [u8; (T / 8) as usize],
    pub challenge_response: CScalar,
}

impl Default for CInteractiveDLogProof {
    fn default() -> Self {
        CInteractiveDLogProof {
            challenge: [0; (T / 8) as usize],
            challenge_response: [0; 32 as usize],
        }
    }
}

#[repr(C)]
pub struct CDLogProof {
    pub point: CAffinePoint,
    pub rand_commitments: [CAffinePoint; R as usize],
    pub proofs: [CInteractiveDLogProof; R as usize],
}

#[repr(C)]
pub struct CProofCommitment {
    pub index: u8,
    pub proof: CDLogProof,
    pub commitment: CHashOutput,
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
