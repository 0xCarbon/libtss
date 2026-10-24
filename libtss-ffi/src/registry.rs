use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use libtss::{DkgSession, RefreshSession, SignSession, TssError};

/// Session storage separate from the key share REGISTRY to prevent
/// deadlocks: `session.next()` may create `KeyShareHandle` via
/// `REGISTRY.insert()`, so the session cannot be held under that same lock.
pub(crate) enum SessionEntry {
    Dkg(DkgSession),
    Sign(SignSession),
    Refresh(RefreshSession),
}

/// A registry slot. While a call has a session checked out, the slot stays
/// in the map so that a concurrent `tss_session_free` can record that the
/// session must be dropped when the call returns it.
enum Slot {
    Present(SessionEntry),
    CheckedOut { free_pending: bool },
}

struct SessionRegistry {
    next_id: AtomicU64,
    entries: Mutex<HashMap<u64, Slot>>,
}

static SESSIONS: OnceLock<SessionRegistry> = OnceLock::new();

fn sessions() -> &'static SessionRegistry {
    SESSIONS.get_or_init(|| SessionRegistry {
        next_id: AtomicU64::new(1),
        entries: Mutex::new(HashMap::new()),
    })
}

fn entries() -> std::sync::MutexGuard<'static, HashMap<u64, Slot>> {
    sessions().entries.lock().unwrap_or_else(|e| e.into_inner())
}

pub(crate) fn insert_session(entry: SessionEntry) -> u64 {
    let reg = sessions();
    let id = reg.next_id.fetch_add(1, Ordering::Relaxed);
    entries().insert(id, Slot::Present(entry));
    id
}

/// Check a session out of the registry. A session that is missing, freed,
/// or already checked out by another call returns HandleInvalid.
fn take_session(id: u64) -> Result<SessionEntry, TssError> {
    let mut entries = entries();
    match entries.get_mut(&id) {
        Some(slot @ Slot::Present(_)) => {
            match std::mem::replace(
                slot,
                Slot::CheckedOut {
                    free_pending: false,
                },
            ) {
                Slot::Present(entry) => Ok(entry),
                Slot::CheckedOut { .. } => unreachable!(),
            }
        }
        _ => Err(TssError::HandleInvalid),
    }
}

/// Return a checked-out session. If it was freed while checked out, it is
/// dropped instead.
fn return_session(id: u64, entry: SessionEntry) {
    let mut entries = entries();
    match entries.get(&id) {
        Some(Slot::CheckedOut {
            free_pending: false,
        }) => {
            entries.insert(id, Slot::Present(entry));
        }
        _ => {
            entries.remove(&id);
            drop(entries);
            drop(entry);
        }
    }
}

/// Forget a checked-out session that the caller consumed.
fn release_session(id: u64) {
    entries().remove(&id);
}

/// Remove a session from the registry (free). A session that is checked out
/// by a running call is dropped when that call returns it.
pub(crate) fn remove_session(id: u64) {
    let mut entries = entries();
    let removed = match entries.get_mut(&id) {
        Some(Slot::CheckedOut { free_pending }) => {
            *free_pending = true;
            None
        }
        Some(Slot::Present(_)) => entries.remove(&id),
        None => None,
    };
    drop(entries);
    drop(removed);
}

/// RAII guard that automatically returns a session to the registry on drop.
///
/// Prevents session loss when a panic occurs between `take_session` and
/// `return_session` (the `ffi_entry!` macro catches panics, but without
/// a guard the session would be permanently leaked from the registry), and
/// honors a `tss_session_free` that arrives while the session is checked out.
pub(crate) struct SessionGuard {
    id: u64,
    entry: Option<SessionEntry>,
}

impl SessionGuard {
    /// Take a session out of the registry, wrapped in a guard that will
    /// return it automatically on drop.
    pub fn take(id: u64) -> Result<Self, TssError> {
        let entry = take_session(id)?;
        Ok(Self {
            id,
            entry: Some(entry),
        })
    }

    /// Borrow the inner session entry mutably.
    pub fn entry_mut(&mut self) -> &mut SessionEntry {
        self.entry
            .as_mut()
            .expect("SessionGuard entry already consumed")
    }

    /// Consume the guard without returning the session to the registry.
    /// Use when the session is complete and should be removed.
    pub fn consume(mut self) {
        self.entry = None;
        release_session(self.id);
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        if let Some(entry) = self.entry.take() {
            return_session(self.id, entry);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use super::*;

    fn refresh_session() -> SessionEntry {
        let config = libtss::ThresholdConfig {
            min_signers: 2,
            max_signers: 2,
            suite: libtss::Ciphersuite::Ed25519,
        };
        let (shares, pubkey) = libtss::frost::frost_generate_with_dealer(&config).unwrap();
        let share =
            libtss::keyshare::from_frost_dkg(shares.into_iter().next().unwrap(), &pubkey).unwrap();
        let dealer = share.identifier();
        SessionEntry::Refresh(RefreshSession::new_frost_receiver(&share, dealer).unwrap())
    }

    fn present(id: u64) -> bool {
        matches!(entries().get(&id), Some(Slot::Present(_)))
    }

    fn known(id: u64) -> bool {
        entries().contains_key(&id)
    }

    #[test]
    fn free_while_checked_out_is_honored_on_return() {
        let id = insert_session(refresh_session());
        let checked_out = Arc::new(Barrier::new(2));
        let freed = Arc::new(Barrier::new(2));

        let worker = {
            let checked_out = Arc::clone(&checked_out);
            let freed = Arc::clone(&freed);
            std::thread::spawn(move || {
                let guard = SessionGuard::take(id).unwrap();
                checked_out.wait();
                freed.wait();
                drop(guard);
            })
        };

        checked_out.wait();
        remove_session(id);
        assert!(known(id), "slot stays while the session is checked out");
        assert!(matches!(
            SessionGuard::take(id),
            Err(TssError::HandleInvalid)
        ));
        freed.wait();
        worker.join().unwrap();

        assert!(!known(id), "freed session is dropped when returned");
        assert!(matches!(
            SessionGuard::take(id),
            Err(TssError::HandleInvalid)
        ));
    }

    #[test]
    fn session_without_free_is_returned() {
        let id = insert_session(refresh_session());
        let worker = std::thread::spawn(move || {
            let guard = SessionGuard::take(id).unwrap();
            drop(guard);
        });
        worker.join().unwrap();
        assert!(present(id));
        remove_session(id);
        assert!(!known(id));
    }

    #[test]
    fn consumed_session_leaves_no_slot() {
        let id = insert_session(refresh_session());
        let guard = SessionGuard::take(id).unwrap();
        guard.consume();
        assert!(!known(id));
        remove_session(id);
        assert!(!known(id));
    }

    #[test]
    fn concurrent_free_and_use() {
        for _ in 0..50 {
            let id = insert_session(refresh_session());
            let start = Arc::new(Barrier::new(2));
            let user = {
                let start = Arc::clone(&start);
                std::thread::spawn(move || {
                    start.wait();
                    if let Ok(guard) = SessionGuard::take(id) {
                        drop(guard);
                    }
                })
            };
            start.wait();
            remove_session(id);
            user.join().unwrap();
            assert!(!known(id));
        }
    }
}
