use std::{
    any::Any,
    sync::{LazyLock, Mutex},
};

use slotmap::{DefaultKey, Key, KeyData, SlotMap};

use crate::TssError;

pub const CAT_FROST_KEY: u8 = 0;
pub const CAT_DKLS_KEY: u8 = 1;
pub const CAT_DKG_SESSION: u8 = 2;
pub const CAT_SIGN_SESSION: u8 = 3;
pub const CAT_REFRESH_SESSION: u8 = 4;
pub const CAT_DKLS_R1_KEY: u8 = 5;

const CAT_LIMIT: u8 = 16;
const KEY_DATA_MASK: u64 = 0x0fff_ffff_ffff_ffff;
const CATEGORY_SHIFT: u64 = 60;
const CATEGORY_MASK: u64 = 0x0f;
pub struct HandleRegistry {
    inner: Mutex<SlotMap<DefaultKey, Entry>>,
}

struct Entry {
    category: u8,
    value: Box<dyn Any + Send>,
}

impl HandleRegistry {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(SlotMap::with_key()),
        }
    }

    pub fn insert<T: Any + Send>(&self, category: u8, value: T) -> u64 {
        debug_assert!(category < CAT_LIMIT);

        let mut inner = self.inner.lock().expect("handle registry poisoned");
        let key = inner.insert(Entry {
            category,
            value: Box::new(value),
        });
        let raw = key.data().as_ffi() & KEY_DATA_MASK;
        ((category as u64) << CATEGORY_SHIFT) | raw
    }

    pub fn with<T, R>(&self, handle: u64, f: impl FnOnce(&T) -> R) -> Result<R, TssError>
    where
        T: Any + Send,
    {
        let inner = self.inner.lock().expect("handle registry poisoned");
        let entry = inner
            .get(Self::decode_key(handle))
            .ok_or(TssError::HandleInvalid)?;
        if entry.category != Self::handle_category(handle) {
            return Err(TssError::HandleInvalid);
        }
        let value = entry
            .value
            .downcast_ref::<T>()
            .ok_or(TssError::HandleInvalid)?;
        Ok(f(value))
    }

    pub fn with_mut<T, R>(&self, handle: u64, f: impl FnOnce(&mut T) -> R) -> Result<R, TssError>
    where
        T: Any + Send,
    {
        let mut inner = self.inner.lock().expect("handle registry poisoned");
        let entry = inner
            .get_mut(Self::decode_key(handle))
            .ok_or(TssError::HandleInvalid)?;
        if entry.category != Self::handle_category(handle) {
            return Err(TssError::HandleInvalid);
        }
        let value = entry
            .value
            .downcast_mut::<T>()
            .ok_or(TssError::HandleInvalid)?;
        Ok(f(value))
    }

    pub fn take<T>(&self, handle: u64) -> Result<T, TssError>
    where
        T: Any + Send,
    {
        let mut inner = self.inner.lock().expect("handle registry poisoned");
        let key = Self::decode_key(handle);
        let entry = inner.get(key).ok_or(TssError::HandleInvalid)?;
        if entry.category != Self::handle_category(handle) {
            return Err(TssError::HandleInvalid);
        }
        let entry = inner.remove(key).ok_or(TssError::HandleInvalid)?;
        entry
            .value
            .downcast::<T>()
            .map(|value| *value)
            .map_err(|_| TssError::HandleInvalid)
    }

    pub fn free(&self, handle: u64) {
        let mut inner = self.inner.lock().expect("handle registry poisoned");
        let key = Self::decode_key(handle);
        if inner
            .get(key)
            .is_some_and(|entry| entry.category == Self::handle_category(handle))
        {
            inner.remove(key);
        }
    }

    fn handle_category(handle: u64) -> u8 {
        ((handle >> CATEGORY_SHIFT) & CATEGORY_MASK) as u8
    }

    fn decode_key(handle: u64) -> DefaultKey {
        KeyData::from_ffi(handle & KEY_DATA_MASK).into()
    }
}

impl Default for HandleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

pub static REGISTRY: LazyLock<HandleRegistry> = LazyLock::new(HandleRegistry::new);

#[cfg(test)]
mod tests {
    use std::thread;

    const TEST_VALUE: u64 = 42;
    const UPDATED_VALUE: u64 = 99;
    use super::{HandleRegistry, CATEGORY_SHIFT, CAT_DKLS_KEY, CAT_FROST_KEY, KEY_DATA_MASK};
    use crate::TssError;

    #[test]
    fn insert_and_get() {
        let registry = HandleRegistry::new();
        let handle = registry.insert(CAT_FROST_KEY, String::from("hello"));

        let value = registry.with::<String, _>(handle, Clone::clone).unwrap();

        assert_eq!(value, "hello");
    }

    #[test]
    fn insert_and_get_mut() {
        let registry = HandleRegistry::new();
        let handle = registry.insert(CAT_FROST_KEY, TEST_VALUE);

        registry
            .with_mut::<u64, _>(handle, |value| *value = UPDATED_VALUE)
            .unwrap();
        let value = registry.with::<u64, _>(handle, |value| *value).unwrap();

        assert_eq!(value, UPDATED_VALUE);
    }

    #[test]
    fn take_removes_entry() {
        let registry = HandleRegistry::new();
        let handle = registry.insert(CAT_FROST_KEY, 7u64);

        let value = registry.take::<u64>(handle).unwrap();

        assert_eq!(value, 7);
        assert_eq!(
            registry.with::<u64, _>(handle, |value| *value).unwrap_err(),
            TssError::HandleInvalid
        );
    }

    #[test]
    fn use_after_free() {
        let registry = HandleRegistry::new();
        let handle = registry.insert(CAT_FROST_KEY, 7u64);

        registry.free(handle);

        assert_eq!(
            registry.with::<u64, _>(handle, |value| *value).unwrap_err(),
            TssError::HandleInvalid
        );
    }

    #[test]
    fn double_free_idempotent() {
        let registry = HandleRegistry::new();
        let handle = registry.insert(CAT_FROST_KEY, 7u64);

        registry.free(handle);
        registry.free(handle);
    }

    #[test]
    fn type_confusion_rejected() {
        let registry = HandleRegistry::new();
        let handle = registry.insert(CAT_FROST_KEY, 7u64);
        let confused = ((CAT_DKLS_KEY as u64) << CATEGORY_SHIFT) | (handle & KEY_DATA_MASK);

        assert_eq!(
            registry
                .with::<u64, _>(confused, |value| *value)
                .unwrap_err(),
            TssError::HandleInvalid
        );
    }

    #[test]
    fn downcast_failure() {
        let registry = HandleRegistry::new();
        let handle = registry.insert(CAT_FROST_KEY, String::from("hello"));

        assert_eq!(
            registry.with::<u32, _>(handle, |value| *value).unwrap_err(),
            TssError::HandleInvalid
        );
    }

    #[test]
    fn concurrent_access() {
        let registry = HandleRegistry::new();

        thread::scope(|scope| {
            for _ in 0..8 {
                let registry = &registry;
                scope.spawn(move || {
                    for value in 0..100u64 {
                        let handle = registry.insert(CAT_FROST_KEY, value);
                        let seen = registry.with::<u64, _>(handle, |value| *value).unwrap();
                        assert_eq!(seen, value);
                        registry.free(handle);
                    }
                });
            }
        });
    }
}
