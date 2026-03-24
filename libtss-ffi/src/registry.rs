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

struct SessionRegistry {
    next_id: AtomicU64,
    entries: Mutex<HashMap<u64, SessionEntry>>,
}

static SESSIONS: OnceLock<SessionRegistry> = OnceLock::new();

fn sessions() -> &'static SessionRegistry {
    SESSIONS.get_or_init(|| SessionRegistry {
        next_id: AtomicU64::new(1),
        entries: Mutex::new(HashMap::new()),
    })
}

pub(crate) fn insert_session(entry: SessionEntry) -> u64 {
    let reg = sessions();
    let id = reg.next_id.fetch_add(1, Ordering::Relaxed);
    reg.entries
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(id, entry);
    id
}

/// Take a session out of the registry. Returns the session or HandleInvalid.
/// The caller must put it back with `return_session` if the session is
/// not complete, or drop it if it is.
pub(crate) fn take_session(id: u64) -> Result<SessionEntry, TssError> {
    sessions()
        .entries
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&id)
        .ok_or(TssError::HandleInvalid)
}

/// Put a session back after `take_session` with the same ID.
pub(crate) fn return_session(id: u64, entry: SessionEntry) {
    sessions()
        .entries
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(id, entry);
}

/// Remove a session from the registry (free).
pub(crate) fn remove_session(id: u64) {
    sessions()
        .entries
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&id);
}

/// RAII guard that automatically returns a session to the registry on drop.
///
/// Prevents session loss when a panic occurs between `take_session` and
/// `return_session` (the `ffi_entry!` macro catches panics, but without
/// a guard the session would be permanently leaked from the registry).
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
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        if let Some(entry) = self.entry.take() {
            return_session(self.id, entry);
        }
    }
}
