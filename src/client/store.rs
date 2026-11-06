//! Where the SDK keeps what must outlive the process.
//!
//! A subscriber's identity, a week-long sign-in, this window's permissions
//! and which of them are held, the quota slots already used: each is cheap
//! to keep and expensive to lose. A lost permission cannot be taken again
//! until the window turns, because each of a subscription's indices is taken
//! once per window network-wide; a lost sign-in or identity costs the person
//! another wallet prompt.
//!
//! The application decides where these live — a keychain, the platform
//! keystore, a database — by implementing [`Store`]. The SDK decides what is
//! written and when, and in particular writes a change down before acting
//! on it, so a crash at any point leaves a state it can continue from.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

/// A name under which the SDK stores one value.
///
/// Names are ASCII made of lowercase letters, digits, `-`, `.` and `/`, so
/// they are safe as file paths and as keychain item names alike. Whether the
/// value is secret is part of the key: put secret values where the platform
/// keeps secrets.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Key {
    name: String,
    secret: bool,
}

impl Key {
    pub(crate) fn secret(name: String) -> Self {
        Self { name, secret: true }
    }

    pub(crate) fn plain(name: String) -> Self {
        Self {
            name,
            secret: false,
        }
    }

    /// The name, such as `packet` or `slots/8/137`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.name
    }

    /// Whether the value lets its holder act as the subscriber: an identity
    /// secret, a sign-in, permissions.
    #[must_use]
    pub fn is_secret(&self) -> bool {
        self.secret
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

/// Why a store could not do what it was asked.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// Reading or writing failed.
    #[error("the store could not be read or written")]
    Io(#[from] std::io::Error),
    /// The backend failed in a way of its own.
    #[error("the store failed")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// A stored value is not one this SDK wrote.
    #[error("the stored value under {0} is unreadable")]
    Corrupt(String),
}

/// Persistent storage for the SDK.
///
/// # Contract
///
/// - `put` returns only once the value is durable: if the process dies right
///   after, the value is there on the next start.
/// - `put` is atomic: a reader sees the old value or the new one, never a mix.
/// - Calls for one key happen one at a time; the SDK never races itself on a
///   key, so a backend need not lock per key.
pub trait Store: Send + Sync {
    /// The value under `key`, if there is one.
    fn get(&self, key: &Key) -> impl Future<Output = Result<Option<Vec<u8>>, StoreError>> + Send;

    /// Stores `value` under `key`, replacing what was there.
    fn put(&self, key: &Key, value: &[u8]) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Removes `key`, if present.
    fn delete(&self, key: &Key) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// A store that forgets everything when dropped: for tests, scripts, and
/// clients that choose to remember nothing.
#[derive(Debug, Default)]
pub struct MemoryStore(Mutex<HashMap<String, Vec<u8>>>);

impl MemoryStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Store for MemoryStore {
    fn get(&self, key: &Key) -> impl Future<Output = Result<Option<Vec<u8>>, StoreError>> + Send {
        let value = self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key.as_str())
            .cloned();
        std::future::ready(Ok(value))
    }

    fn put(&self, key: &Key, value: &[u8]) -> impl Future<Output = Result<(), StoreError>> + Send {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key.as_str().to_owned(), value.to_vec());
        std::future::ready(Ok(()))
    }

    fn delete(&self, key: &Key) -> impl Future<Output = Result<(), StoreError>> + Send {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(key.as_str());
        std::future::ready(Ok(()))
    }
}

/// A store in a directory: one file per key.
///
/// Writes go to a temporary file that is synced and then renamed over the
/// old one, which makes them atomic and durable. On Unix every file is
/// readable by its owner only. Secret values are stored here like any other;
/// wrap it, or implement [`Store`] yourself, to send them to a keychain.
#[derive(Debug, Clone)]
pub struct FileStore {
    root: PathBuf,
}

impl FileStore {
    /// A store rooted at `root`, created if missing.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Io`] if the directory cannot be created.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    fn path(&self, key: &Key) -> Result<PathBuf, StoreError> {
        // Keys are made by the SDK, but a path is a path: refuse anything that
        // could step outside the root.
        let name = key.as_str();
        let safe = !name.is_empty()
            && name
                .bytes()
                .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'/'))
            && name
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != "..");
        if !safe {
            return Err(StoreError::Corrupt(name.to_owned()));
        }
        Ok(self.root.join(name))
    }
}

impl Store for FileStore {
    async fn get(&self, key: &Key) -> Result<Option<Vec<u8>>, StoreError> {
        let path = self.path(key)?;
        blocking(move || match std::fs::read(path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        })
        .await
    }

    async fn put(&self, key: &Key, value: &[u8]) -> Result<(), StoreError> {
        let path = self.path(key)?;
        let value = value.to_vec();
        blocking(move || {
            let dir = path.parent().map(Path::to_path_buf).unwrap_or_default();
            std::fs::create_dir_all(&dir)?;
            let temp = path.with_extension("tmp");
            write_private(&temp, &value)?;
            std::fs::rename(&temp, &path)?;
            // The rename is durable only once the directory entry is.
            sync_dir(&dir);
            Ok(())
        })
        .await
    }

    async fn delete(&self, key: &Key) -> Result<(), StoreError> {
        let path = self.path(key)?;
        blocking(move || match std::fs::remove_file(path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        })
        .await
    }
}

/// Runs file I/O on the blocking pool, so a slow disk never stalls the
/// runtime's workers.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> std::io::Result<T> + Send + 'static,
) -> Result<T, StoreError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|e| StoreError::Backend(e.into()))?
        .map_err(StoreError::from)
}

/// Writes `value` to a new file only its owner can read, and syncs it.
fn write_private(path: &Path, value: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(value)?;
    file.sync_all()
}

fn sync_dir(dir: &Path) {
    // Not every platform can open a directory to sync it; where it cannot,
    // the rename is as durable as the platform makes it.
    #[cfg(unix)]
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn round_trip<S: Store>(store: &S) {
        let key = Key::plain("slots/8/137".into());
        assert_eq!(store.get(&key).await.expect("reads"), None);
        store.put(&key, b"3").await.expect("writes");
        store.put(&key, b"4").await.expect("overwrites");
        assert_eq!(
            store.get(&key).await.expect("reads").as_deref(),
            Some(&b"4"[..])
        );
        store.delete(&key).await.expect("deletes");
        store.delete(&key).await.expect("deleting twice is fine");
        assert_eq!(store.get(&key).await.expect("reads"), None);
    }

    #[tokio::test]
    async fn memory_keeps_and_forgets() {
        round_trip(&MemoryStore::new()).await;
    }

    #[tokio::test]
    async fn files_keep_and_forget() {
        let dir = std::env::temp_dir().join(format!("singula-store-{}", std::process::id()));
        let store = FileStore::new(&dir).expect("a directory");
        round_trip(&store).await;
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn files_are_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("singula-store-mode-{}", std::process::id()));
        let store = FileStore::new(&dir).expect("a directory");
        store
            .put(&Key::secret("identity/x".into()), b"secret")
            .await
            .expect("writes");
        let mode = std::fs::metadata(dir.join("identity/x"))
            .expect("exists")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn files_refuse_keys_that_leave_the_root() {
        let dir = std::env::temp_dir().join(format!("singula-store-escape-{}", std::process::id()));
        let store = FileStore::new(&dir).expect("a directory");
        for name in ["../x", "a/../../x", "/etc/passwd", "a//b", "A"] {
            let key = Key::plain(name.into());
            assert!(
                matches!(store.put(&key, b"x").await, Err(StoreError::Corrupt(_))),
                "{name}"
            );
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}
