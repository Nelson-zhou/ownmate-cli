//! Atomic selectors contain no tokens, keys or private pairing material.
//! A pending selector always takes precedence: it never silently loads older scopes.
use crate::command_cache::{initialize_new_private_file, private_directory, private_file};
use crate::storage::{
    CredentialStore, ExternalSession, LEGACY_ACCOUNT, NativeCredentials, account_for, read_session,
    save_verified,
};
use crate::{McpError, Result};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;

const MAX_PROFILE_BYTES: u64 = 16 * 1024;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Profile {
    base_url: String,
    grant_id: String,
    client_ready_version: u32,
    client_ready_expires_at: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Profiles {
    version: u32,
    active: Option<Profile>,
    pending: Option<Profile>,
}

impl Default for Profiles {
    fn default() -> Self {
        Self {
            version: 1,
            active: None,
            pending: None,
        }
    }
}

struct ProfileStore {
    directory: PathBuf,
}

impl ProfileStore {
    fn system() -> Result<Self> {
        #[cfg(not(target_os = "windows"))]
        let root = std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|v| PathBuf::from(v).join(".local/state")));
        #[cfg(target_os = "windows")]
        let root = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
        Ok(Self {
            directory: root
                .ok_or_else(profile_error)?
                .join("ownmate-mcp")
                .join("connections"),
        })
    }

    fn locked<T>(&self, operation: impl FnOnce(&Self) -> Result<T>) -> Result<T> {
        private_directory(&self.directory).map_err(|_| profile_error())?;
        let path = self.directory.join("selector.lock");
        match fs::symlink_metadata(&path) {
            Ok(metadata) => private_file(&path, &metadata).map_err(|_| profile_error())?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(profile_error()),
        }
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = match options.open(&path) {
            Ok(file) => {
                initialize_new_private_file(&path).map_err(|_| profile_error())?;
                file
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                options.create_new(false).create(false);
                options.open(&path).map_err(|_| profile_error())?
            }
            Err(_) => return Err(profile_error()),
        };
        private_file(
            &path,
            &fs::symlink_metadata(&path).map_err(|_| profile_error())?,
        )
        .map_err(|_| profile_error())?;
        lock_selector(&file)?;
        // The OS releases the lock on close, including process termination.
        let result = operation(self);
        drop(file);
        result
    }

    fn read(&self) -> Result<Profiles> {
        let path = self.directory.join("selector.json");
        let meta = match fs::symlink_metadata(&path) {
            Ok(value) => value,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Profiles::default()),
            Err(_) => return Err(profile_error()),
        };
        private_file(&path, &meta).map_err(|_| profile_error())?;
        if meta.len() > MAX_PROFILE_BYTES {
            return Err(profile_error());
        }
        let mut bytes = Vec::new();
        File::open(&path)
            .map_err(|_| profile_error())?
            .take(MAX_PROFILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| profile_error())?;
        let profiles: Profiles = serde_json::from_slice(&bytes).map_err(|_| profile_error())?;
        if profiles.version != 1 {
            return Err(profile_error());
        }
        for profile in [&profiles.active, &profiles.pending].into_iter().flatten() {
            if profile.client_ready_version != 1
                || profile.client_ready_expires_at == 0
                || profile.grant_id.is_empty()
                || profile.grant_id.len() > 160
                || profile.grant_id.chars().any(char::is_control)
                || crate::api::ExternalApiClient::new(&profile.base_url).is_err()
            {
                return Err(profile_error());
            }
        }
        Ok(profiles)
    }

    fn write(&self, profiles: &Profiles) -> Result<()> {
        let bytes = serde_json::to_vec(profiles).map_err(|_| profile_error())?;
        if bytes.len() as u64 > MAX_PROFILE_BYTES {
            return Err(profile_error());
        }
        let mut random = [0; 16];
        OsRng.fill_bytes(&mut random);
        let temporary = self
            .directory
            .join(format!(".tmp-{:x}", Sha256::digest(random)));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary).map_err(|_| profile_error())?;
        let result = (|| -> Result<()> {
            initialize_new_private_file(&temporary).map_err(|_| profile_error())?;
            file.write_all(&bytes).map_err(|_| profile_error())?;
            file.sync_all().map_err(|_| profile_error())?;
            private_file(
                &temporary,
                &fs::symlink_metadata(&temporary).map_err(|_| profile_error())?,
            )
            .map_err(|_| profile_error())?;
            fs::rename(&temporary, self.directory.join("selector.json"))
                .map_err(|_| profile_error())?;
            #[cfg(unix)]
            File::open(&self.directory)
                .and_then(|f| f.sync_all())
                .map_err(|_| profile_error())?;
            Ok(())
        })();
        let _ = fs::remove_file(temporary);
        result
    }

    fn stage(
        &self,
        credentials: &impl CredentialStore,
        session: &ExternalSession,
        deadline: u64,
    ) -> Result<()> {
        self.locked(|this| {
            let mut profiles = this.read()?;
            let candidate = Profile {
                base_url: session.base_url.clone(),
                grant_id: session.grant_id.clone(),
                client_ready_version: 1,
                client_ready_expires_at: deadline,
            };
            if deadline == 0 || profiles.pending.as_ref().is_some_and(|p| p != &candidate) {
                return Err(McpError::Credential(
                    "已有待完成连接；请运行 mcp 重试 ready 确认，或显式 disconnect 后再配对".into(),
                ));
            }
            save_verified(credentials, session)?;
            profiles.pending = Some(candidate);
            this.write(&profiles)
        })
    }

    fn activate(&self, session: &ExternalSession, deadline: u64) -> Result<()> {
        self.locked(|this| {
            let mut profiles = this.read()?;
            let profile = Profile {
                base_url: session.base_url.clone(),
                grant_id: session.grant_id.clone(),
                client_ready_version: 1,
                client_ready_expires_at: deadline,
            };
            if profiles.pending.as_ref() != Some(&profile) {
                if profiles.pending.is_none() && profiles.active.as_ref() == Some(&profile) {
                    return Ok(());
                }
                return Err(profile_error());
            }
            profiles.active = profiles.pending.take();
            this.write(&profiles)
        })
    }

    fn load(
        &self,
        credentials: &impl CredentialStore,
        ready: impl FnOnce(&mut ExternalSession, u64) -> Result<()>,
    ) -> Result<ExternalSession> {
        // Legacy reads do not create selector files and never rewrite the default item.
        match fs::symlink_metadata(&self.directory) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return read_session(credentials, LEGACY_ACCOUNT);
            }
            Err(_) => return Err(profile_error()),
            Ok(_) => (),
        }
        let (profile, pending) = self.locked(|this| {
            let profiles = this.read()?;
            Ok(match profiles.pending {
                Some(p) => (Some(p), true),
                None => (profiles.active, false),
            })
        })?;
        let Some(profile) = profile else {
            return read_session(credentials, LEGACY_ACCOUNT);
        };
        let mut session = read_session(
            credentials,
            &account_for(&profile.base_url, &profile.grant_id),
        )?;
        if session.base_url != profile.base_url || session.grant_id != profile.grant_id {
            return Err(profile_error());
        }
        if pending {
            // One idempotent request is allowed even past the deadline: a lost reply may
            // already have activated the grant. The server rejects unacknowledged expiry.
            ready(&mut session, profile.client_ready_expires_at)?;
            self.activate(&session, profile.client_ready_expires_at)?;
        }
        Ok(session)
    }
}

fn profile_error() -> McpError {
    McpError::Credential("本机连接选择器不可用或权限不安全；未切换到旧授权".into())
}

fn lock_selector(file: &File) -> Result<()> {
    file.try_lock()
        .map_err(|_| McpError::Credential("另一个 OwnMate 进程正在更新连接；请稍后重试".into()))
}

pub fn trusted_metadata_available() -> bool {
    ProfileStore::system()
        .and_then(|store| {
            store.locked(|this| {
                let profiles = this.read()?;
                if profiles.pending.is_some() {
                    return Err(profile_error());
                }
                Ok(())
            })
        })
        .is_ok()
}

pub fn stage_trusted(session: &ExternalSession, deadline: u64) -> Result<()> {
    ProfileStore::system()?.stage(&NativeCredentials, session, deadline)
}

pub fn activate_trusted(session: &ExternalSession, deadline: u64) -> Result<()> {
    ProfileStore::system()?.activate(session, deadline)
}

pub(crate) fn load_trusted() -> Result<ExternalSession> {
    ProfileStore::system()?.load(&NativeCredentials, |session, deadline| {
        crate::api::ExternalApiClient::new(&session.base_url)?.client_ready(session, deadline)
    })
}

pub(crate) fn disconnect() -> Result<()> {
    let store = ProfileStore::system()?;
    store.locked(|this| {
        let mut profiles = this.read()?;
        for profile in [&profiles.pending, &profiles.active].into_iter().flatten() {
            NativeCredentials.delete(&account_for(&profile.base_url, &profile.grant_id))?;
        }
        NativeCredentials.delete(LEGACY_ACCOUNT)?;
        profiles.active = None;
        profiles.pending = None;
        this.write(&profiles)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::fixtures::{MockCredentials, trusted};

    struct Fixture {
        store: ProfileStore,
        root: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let mut random = [0; 16];
            OsRng.fill_bytes(&mut random);
            let root = std::env::temp_dir().join(format!(
                "ownmate-profile-fixture-{:x}",
                Sha256::digest(random)
            ));
            Self {
                store: ProfileStore {
                    directory: root.join("profiles"),
                },
                root,
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn seed_active(fixture: &Fixture, credentials: &MockCredentials) -> ExternalSession {
        let mut old = trusted();
        old.grant_id = "synthetic_old_grant".into();
        fixture.store.stage(credentials, &old, 50).unwrap();
        fixture.store.activate(&old, 50).unwrap();
        old
    }

    #[test]
    fn denial_and_mismatch_keep_old_selector_and_same_session_during_retry() {
        let fixture = Fixture::new();
        let credentials = MockCredentials::default();
        let old = seed_active(&fixture, &credentials);
        let candidate = trusted();
        credentials.deny_formal.set(true);
        assert!(fixture.store.stage(&credentials, &candidate, 100).is_err());
        credentials.deny_formal.set(false);
        credentials.mismatch.set(true);
        assert!(fixture.store.stage(&credentials, &candidate, 100).is_err());
        let profiles = fixture.store.locked(|s| s.read()).unwrap();
        assert_eq!(profiles.active.unwrap().grant_id, old.grant_id);
        assert!(profiles.pending.is_none());
        credentials.mismatch.set(false);
        fixture.store.stage(&credentials, &candidate, 100).unwrap();
        let bytes = fs::read(fixture.store.directory.join("selector.json")).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains("SYNTHETIC_REFRESH") && !text.contains(&candidate.dek_base64));
        assert!(!text.contains("accessToken") && !text.contains("dekBase64"));
        assert_eq!(
            read_session(&credentials, &account_for(&old.base_url, &old.grant_id))
                .unwrap()
                .grant_id,
            old.grant_id
        );
    }

    #[test]
    fn lost_ready_reply_resumes_after_restart_and_only_then_activates_candidate() {
        let fixture = Fixture::new();
        let credentials = MockCredentials::default();
        let old = seed_active(&fixture, &credentials);
        let candidate = trusted();
        fixture.store.stage(&credentials, &candidate, 100).unwrap();
        let error = fixture.store.load(&credentials, |session, deadline| {
            assert_eq!(session.grant_id, candidate.grant_id);
            assert_eq!(deadline, 100);
            Err(McpError::Network("synthetic lost reply".into()))
        });
        assert!(error.is_err());
        let profiles = fixture.store.locked(|s| s.read()).unwrap();
        assert_eq!(profiles.active.unwrap().grant_id, old.grant_id);
        assert_eq!(profiles.pending.unwrap().grant_id, candidate.grant_id);
        let restarted = ProfileStore {
            directory: fixture.store.directory.clone(),
        };
        let resumed = restarted.load(&credentials, |_, _| Ok(())).unwrap();
        assert_eq!(resumed.grant_id, candidate.grant_id);
        assert_eq!(
            restarted
                .load(&credentials, |_, _| panic!("already active"))
                .unwrap()
                .grant_id,
            candidate.grant_id
        );
        assert!(
            credentials
                .entries
                .borrow()
                .contains_key(&account_for(&old.base_url, &old.grant_id))
        );
    }

    #[test]
    fn pending_locked_or_expired_never_falls_back_to_old_scopes() {
        let fixture = Fixture::new();
        let credentials = MockCredentials::default();
        let old = seed_active(&fixture, &credentials);
        let candidate = trusted();
        fixture.store.stage(&credentials, &candidate, 100).unwrap();
        credentials.calls.borrow_mut().clear();
        credentials.deny_reads.set(true);
        assert!(
            fixture
                .store
                .load(&credentials, |_, _| panic!("locked before ready"))
                .is_err()
        );
        credentials.deny_reads.set(false);
        assert!(
            fixture
                .store
                .load(&credentials, |_, _| Err(McpError::Api(
                    "synthetic expired".into()
                )))
                .is_err()
        );
        assert!(
            credentials
                .calls
                .borrow()
                .iter()
                .all(|call| !call.contains(&account_for(&old.base_url, &old.grant_id)))
        );
        assert!(fixture.store.stage(&credentials, &old, 200).is_err());
    }

    #[test]
    fn legacy_read_is_valid_and_never_migrates_or_rewrites_default() {
        let fixture = Fixture::new();
        let credentials = MockCredentials::default();
        let session = trusted();
        credentials.entries.borrow_mut().insert(
            LEGACY_ACCOUNT.into(),
            serde_json::to_string(&session).unwrap(),
        );
        assert_eq!(
            fixture
                .store
                .load(&credentials, |_, _| panic!("legacy ready"))
                .unwrap()
                .grant_id,
            session.grant_id
        );
        assert!(!fixture.store.directory.exists());
        assert_eq!(
            credentials.calls.borrow().as_slice(),
            &[format!("get:{LEGACY_ACCOUNT}")]
        );
    }

    #[test]
    fn metadata_lock_is_released_on_close_and_serializes_concurrent_processes() {
        let fixture = Fixture::new();
        fixture
            .store
            .locked(|store| {
                let second = ProfileStore {
                    directory: store.directory.clone(),
                };
                assert!(second.locked(|_| Ok(())).is_err());
                Ok(())
            })
            .unwrap();
        assert!(fixture.store.locked(|_| Ok(())).is_ok());
    }

    #[test]
    fn stale_activation_cannot_overwrite_or_clear_a_new_pending_grant() {
        let fixture = Fixture::new();
        let credentials = MockCredentials::default();
        let old = seed_active(&fixture, &credentials);
        let candidate = trusted();
        fixture.store.stage(&credentials, &candidate, 100).unwrap();
        assert!(fixture.store.activate(&old, 50).is_err());
        assert_eq!(
            fixture
                .store
                .locked(|s| s.read())
                .unwrap()
                .pending
                .unwrap()
                .grant_id,
            candidate.grant_id
        );
    }

    #[cfg(unix)]
    #[test]
    fn selector_files_are_private_and_symlink_metadata_is_rejected() {
        use std::os::unix::fs::{MetadataExt, symlink};
        let fixture = Fixture::new();
        let credentials = MockCredentials::default();
        fixture.store.stage(&credentials, &trusted(), 100).unwrap();
        let path = fixture.store.directory.join("selector.json");
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o077, 0);
        fs::rename(&path, fixture.root.join("real-selector.json")).unwrap();
        symlink(fixture.root.join("real-selector.json"), &path).unwrap();
        assert!(
            fixture
                .store
                .load(&credentials, |_, _| panic!("unsafe metadata"))
                .is_err()
        );
    }
}
