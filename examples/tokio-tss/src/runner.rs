//! Protocol-agnostic async runners for the reference example.
//!
//! These functions demonstrate the `new() -> next()` loop shape described by
//! the spec. They operate on local reference sessions so the example remains
//! runnable during the development of the main `libtss` API.

use crate::{
    DkgSession, EncryptedRouter, KeyShareHandle, PartyRouter, PublicKeyPackage, RefreshSession,
    SessionStep, SignSession, Signature, ThresholdConfig, TssError,
};

pub async fn run_dkg(
    config: &ThresholdConfig,
    router: &mut PartyRouter,
    session_id: Option<&[u8]>,
) -> Result<(KeyShareHandle, PublicKeyPackage), TssError> {
    let party_ids = router.participant_ids();
    let self_id = router.self_id();
    let (session, outbound) = DkgSession::new(config.clone(), self_id, party_ids, session_id)?;
    drive_plain(router, session, outbound).await
}

pub async fn run_dkg_encrypted(
    config: &ThresholdConfig,
    router: &mut EncryptedRouter,
    session_id: Option<&[u8]>,
) -> Result<(KeyShareHandle, PublicKeyPackage), TssError> {
    let party_ids = router.participant_ids();
    let self_id = router.self_id();
    let (session, outbound) = DkgSession::new(config.clone(), self_id, party_ids, session_id)?;
    drive_encrypted(router, session, outbound).await
}

pub async fn run_sign(
    key_share: KeyShareHandle,
    message: &[u8],
    router: &mut PartyRouter,
) -> Result<(Signature, KeyShareHandle), TssError> {
    let party_ids = router.participant_ids();
    let (session, outbound) = SignSession::new(key_share, message.to_vec(), party_ids)?;
    drive_plain(router, session, outbound).await
}

pub async fn run_sign_encrypted(
    key_share: KeyShareHandle,
    message: &[u8],
    router: &mut EncryptedRouter,
) -> Result<(Signature, KeyShareHandle), TssError> {
    let party_ids = router.participant_ids();
    let (session, outbound) = SignSession::new(key_share, message.to_vec(), party_ids)?;
    drive_encrypted(router, session, outbound).await
}

pub async fn run_refresh(
    key_share: KeyShareHandle,
    router: &mut PartyRouter,
) -> Result<(KeyShareHandle, PublicKeyPackage, KeyShareHandle), TssError> {
    let party_ids = router.participant_ids();
    let (session, outbound) = RefreshSession::new(key_share, party_ids)?;
    drive_plain(router, session, outbound).await
}

async fn drive_plain<T, S>(
    router: &mut PartyRouter,
    mut session: S,
    outbound: Vec<crate::Message>,
) -> Result<T, TssError>
where
    S: RoundSession<Output = T>,
{
    router.send(outbound).await?;

    loop {
        let inbound = router.receive_from_all_peers().await?;
        match session.next(inbound)? {
            SessionStep::Messages(next_outbound) => router.send(next_outbound).await?,
            SessionStep::Complete(output) => return Ok(output),
        }
    }
}

async fn drive_encrypted<T, S>(
    router: &mut EncryptedRouter,
    mut session: S,
    outbound: Vec<crate::Message>,
) -> Result<T, TssError>
where
    S: RoundSession<Output = T>,
{
    router.send(outbound).await?;

    loop {
        let inbound = router.receive_from_all_peers().await?;
        match session.next(inbound)? {
            SessionStep::Messages(next_outbound) => router.send(next_outbound).await?,
            SessionStep::Complete(output) => return Ok(output),
        }
    }
}

pub trait RoundSession {
    type Output;

    fn next(
        &mut self,
        incoming: Vec<crate::Message>,
    ) -> Result<SessionStep<Self::Output>, TssError>;
}
