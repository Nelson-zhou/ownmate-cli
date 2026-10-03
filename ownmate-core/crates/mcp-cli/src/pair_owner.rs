//! Private, non-secret lifecycle/control metadata. Pairing secrets stay in the owner process.
use crate::command_cache::{initialize_new_private_file, private_directory, private_file};
use crate::{McpError, Result};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

const MAX_BYTES: u64 = 16 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Starting,
    WaitingPhone,
    NetworkRetry,
    Replacing,
    Exchanging,
    Saving,
    Ready,
    #[serde(rename = "setup_complete")]
    Connected,
    Serving,
    Ended,
    Failed,
    Expired,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Record {
    version: u32,
    run_id: String,
    generation: u32,
    state: State,
    expires_at: Option<u64>,
    workflow_deadline: u64,
    qr_output: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    version: u32,
    run_id: String,
    generation: u32,
    action: String,
}

pub struct PairOwner {
    directory: PathBuf,
    _lease: File,
    record: Record,
}

fn invalid() -> McpError {
    McpError::Invalid("私有配对状态不可用、权限不安全或 owner 已退出；未取消任何授权".into())
}

fn root() -> Result<PathBuf> {
    #[cfg(not(target_os = "windows"))]
    let root = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|v| PathBuf::from(v).join(".local/state")));
    #[cfg(target_os = "windows")]
    let root = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    Ok(root
        .ok_or_else(invalid)?
        .join("ownmate-mcp")
        .join("pairings"))
}

fn run_id_valid(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn random_id() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn open_private(path: &Path, create: bool) -> Result<File> {
    if !create {
        private_file(path, &fs::symlink_metadata(path).map_err(|_| invalid())?)
            .map_err(|_| invalid())?;
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(create);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path).map_err(|_| invalid())?;
    if create {
        initialize_new_private_file(path).map_err(|_| invalid())?;
    }
    private_file(path, &fs::symlink_metadata(path).map_err(|_| invalid())?)
        .map_err(|_| invalid())?;
    Ok(file)
}

fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let metadata = fs::symlink_metadata(path).map_err(|_| invalid())?;
    private_file(path, &metadata).map_err(|_| invalid())?;
    if metadata.len() > MAX_BYTES {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| invalid())?
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    serde_json::from_slice(&bytes).map_err(|_| invalid())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    if bytes.len() as u64 > 256 * 1024 {
        return Err(invalid());
    }
    match fs::symlink_metadata(path) {
        Ok(meta) => private_file(path, &meta).map_err(|_| invalid())?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(_) => return Err(invalid()),
    }
    let parent = path.parent().ok_or_else(invalid)?;
    let temporary = parent.join(format!(".pair-tmp-{}", random_id()));
    let mut file = open_private(&temporary, true)?;
    let result = (|| {
        file.write_all(bytes).map_err(|_| invalid())?;
        file.sync_all().map_err(|_| invalid())?;
        drop(file);
        fs::rename(&temporary, path).map_err(|_| invalid())?;
        #[cfg(unix)]
        File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(|_| invalid())?;
        Ok(())
    })();
    let _ = fs::remove_file(&temporary);
    result
}

fn lock_control(directory: &Path) -> Result<File> {
    try_lock_control(directory)?.ok_or(McpError::Action {
        reason: "PAIR_CONTROL_BUSY",
        next_action: "retry_pair_replace_same_session",
    })
}

fn try_lock_control(directory: &Path) -> Result<Option<File>> {
    let file = open_private(&directory.join("control.lock"), false)?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(std::fs::TryLockError::WouldBlock) => Ok(None),
        Err(_) => Err(invalid()),
    }
}

fn snapshot(directory: &Path) -> Result<(Record, bool)> {
    // Reading status does not initialize/repair any directory or credential entry.
    check_directory(directory)?;
    let record: Record = read(&directory.join("status.json"))?;
    if record.version != 1
        || !run_id_valid(&record.run_id)
        || directory.file_name().and_then(|v| v.to_str()) != Some(record.run_id.as_str())
        || record.generation > crate::pair_retry::MAX_QR_CODES
        || record.workflow_deadline == 0
        || record
            .qr_output
            .as_ref()
            .is_some_and(|p| p.len() > 4096 || p.chars().any(char::is_control))
    {
        return Err(invalid());
    }
    let lease = open_private(&directory.join("owner.lock"), false)?;
    let alive = match lease.try_lock() {
        Ok(()) => false,
        Err(std::fs::TryLockError::WouldBlock) => true,
        Err(_) => return Err(invalid()),
    };
    Ok((record, alive))
}

fn check_directory(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path).map_err(|_| invalid())?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(invalid());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(invalid());
        }
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err(invalid());
        }
        crate::command_cache::verify_private_windows_directory(path).map_err(|_| invalid())?;
    }
    Ok(())
}

fn report(record: &Record, alive: bool) -> Value {
    let terminal = matches!(
        record.state,
        State::Connected | State::Ended | State::Failed | State::Expired
    );
    let (reason, next) = if !alive && !terminal {
        ("PAIR_OWNER_LOST", "start_new_pair_do_not_reuse_old_qr")
    } else {
        match record.state {
            State::Starting => ("PAIR_STARTING", "wait_for_qr"),
            State::WaitingPhone => (
                "WAITING_PHONE_APPROVAL",
                "display_current_qr_image_and_wait",
            ),
            State::NetworkRetry => ("TRANSIENT_NETWORK_RETRY", "keep_same_process_alive"),
            State::Replacing => ("QR_REPLACEMENT_PENDING", "wait_do_not_display_a_new_qr_yet"),
            State::Exchanging => (
                "PHONE_APPROVED_EXCHANGE_PENDING",
                "keep_same_process_alive_no_verified_candidate_yet",
            ),
            State::Saving => (
                "TRUSTED_SAVE_VERIFY_PENDING",
                "keep_same_process_alive_do_not_change_trust_mode",
            ),
            State::Ready => (
                "CLIENT_READY_PENDING",
                "keep_same_process_alive_or_resume_verified_trusted_candidate",
            ),
            State::Connected => ("CLIENT_READY_ACKNOWLEDGED", "configure_mcp_host"),
            State::Serving => ("MCP_STDIO_SERVING", "keep_host_stdio_and_process_alive"),
            State::Ended => (
                "PAIR_PROCESS_ENDED",
                "temporary_requires_new_pair_trusted_use_mcp",
            ),
            State::Failed => (
                "PAIRING_NOT_COMPLETED",
                "inspect_status_then_retry_or_resume_verified_trusted_candidate",
            ),
            State::Expired => ("PAIR_WAIT_BUDGET_EXPIRED", "start_new_pair"),
        }
    };
    json!({"schemaVersion":1,"session":record.run_id,"generation":record.generation,
        "state":if !alive && !terminal { json!("owner_lost") } else { json!(record.state) },
        "ownerAlive":alive,"evidence":"private_metadata_and_os_owner_lock","serverActiveConfirmed":false,
        "reason":reason,"nextAction":next,"expiresAt":record.expires_at,
        "workflowDeadline":record.workflow_deadline,"qrOutput":record.qr_output})
}

impl PairOwner {
    pub fn start(deadline: u64) -> Result<Self> {
        Self::start_at(root()?, deadline)
    }

    fn start_at(root: PathBuf, deadline: u64) -> Result<Self> {
        private_directory(&root).map_err(|_| invalid())?;
        let run_id = random_id();
        let directory = root.join(&run_id);
        private_directory(&directory).map_err(|_| invalid())?;
        let lease = open_private(&directory.join("owner.lock"), true)?;
        lease.try_lock().map_err(|_| invalid())?;
        drop(open_private(&directory.join("control.lock"), true)?);
        let owner = Self {
            directory,
            _lease: lease,
            record: Record {
                version: 1,
                run_id,
                generation: 0,
                state: State::Starting,
                expires_at: None,
                workflow_deadline: deadline,
                qr_output: None,
            },
        };
        owner.publish()?;
        Ok(owner)
    }

    pub fn id(&self) -> &str {
        &self.record.run_id
    }
    pub fn failed(&mut self) -> Result<()> {
        if self.record.state != State::Expired {
            self.record.state = State::Failed;
        }
        self.publish()
    }
    pub fn update(
        &mut self,
        state: State,
        generation: u32,
        expires: Option<u64>,
        output: Option<&Path>,
    ) -> Result<()> {
        let mut next = self.record.clone();
        next.state = state;
        next.generation = generation;
        next.expires_at = expires;
        next.qr_output = output.map(|p| p.to_string_lossy().into_owned());
        if next == self.record {
            return Ok(());
        }
        self.record = next;
        self.publish()
    }
    fn publish(&self) -> Result<()> {
        atomic_write(
            &self.directory.join("status.json"),
            &serde_json::to_vec(&self.record).map_err(|_| invalid())?,
        )
    }

    pub fn take_replace(&self) -> Result<bool> {
        let Some(_guard) = try_lock_control(&self.directory)? else {
            return Ok(false);
        };
        let path = self.directory.join("request.json");
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => return Err(invalid()),
            Ok(_) => (),
        }
        let request: Request = read(&path)?;
        fs::remove_file(&path).map_err(|_| invalid())?;
        if request.version != 1
            || request.run_id != self.record.run_id
            || request.action != "replace"
        {
            return Err(invalid());
        }
        Ok(request.generation == self.record.generation)
    }
}

pub fn status(id: &str) -> Result<Value> {
    if !run_id_valid(id) {
        return Err(invalid());
    }
    let root = root()?;
    check_directory(&root)?;
    let (record, alive) = snapshot(&root.join(id))?;
    Ok(report(&record, alive))
}

pub fn replace(id: &str) -> Result<Value> {
    replace_at(&root()?, id)
}
fn replace_at(root: &Path, id: &str) -> Result<Value> {
    if !run_id_valid(id) {
        return Err(invalid());
    }
    check_directory(root)?;
    let directory = root.join(id);
    check_directory(&directory)?;
    let _guard = lock_control(&directory)?;
    let (record, alive) = snapshot(&directory)?;
    if !alive || !matches!(record.state, State::WaitingPhone | State::NetworkRetry) {
        return Err(invalid());
    }
    atomic_write(
        &directory.join("request.json"),
        &serde_json::to_vec(&Request {
            version: 1,
            run_id: id.into(),
            generation: record.generation,
            action: "replace".into(),
        })
        .map_err(|_| invalid())?,
    )?;
    Ok(
        json!({"schemaVersion":1,"session":id,"generation":record.generation,"state":"requested",
        "reason":"REPLACE_REQUEST_QUEUED","nextAction":"wait_for_owner_cancel_ack_and_new_qr","evidence":"local_control_request_only"}),
    )
}

pub struct OwnerStatusList {
    pub sessions: Vec<Value>,
    pub truncated: bool,
    pub scan_truncated: bool,
}
pub fn all_status() -> Result<OwnerStatusList> {
    all_status_at(&root()?)
}
fn all_status_at(root: &Path) -> Result<OwnerStatusList> {
    let empty = || OwnerStatusList {
        sessions: Vec::new(),
        truncated: false,
        scan_truncated: false,
    };
    match fs::symlink_metadata(root) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(empty()),
        Err(_) => return Err(invalid()),
        Ok(_) => check_directory(root)?,
    }
    let mut candidates = Vec::new();
    let mut total = 0;
    let mut scan_truncated = false;
    // Bounded memory/read work, newest 128 of at most 4096 entries. Never imply completeness.
    for (index, entry) in fs::read_dir(root)
        .map_err(|_| invalid())?
        .take(4097)
        .enumerate()
    {
        if index == 4096 {
            scan_truncated = true;
            break;
        }
        let entry = entry.map_err(|_| invalid())?;
        if entry.file_name().to_str().is_some_and(run_id_valid) {
            total += 1;
            let modified = fs::symlink_metadata(entry.path())
                .and_then(|m| m.modified())
                .unwrap_or(std::time::UNIX_EPOCH);
            candidates.push((modified, entry.path()));
            candidates.sort();
            if candidates.len() > 128 {
                candidates.remove(0);
            }
        }
    }
    let sessions = candidates.into_iter().rev().map(|(_,path)| match snapshot(&path) {
        Ok((record, alive)) => report(&record, alive),
        Err(_) => json!({"session":path.file_name().and_then(|v|v.to_str()),"state":"metadata_unavailable",
            "reason":"PRIVATE_PAIR_METADATA_UNAVAILABLE","nextAction":"inspect_local_private_metadata_without_reading_credentials",
            "evidence":"metadata_unavailable","serverActiveConfirmed":false}),
    }).collect();
    Ok(OwnerStatusList {
        sessions,
        truncated: total > 128 || scan_truncated,
        scan_truncated,
    })
}

/// The explicit destination is never treated as an app-owned directory: no chmod/ACL repair.
pub struct QrOutput {
    path: PathBuf,
    expected: Option<Vec<u8>>,
}
impl QrOutput {
    pub fn new(path: PathBuf) -> Result<Self> {
        let path = if path.is_absolute() {
            path
        } else {
            std::env::current_dir()?.join(path)
        };
        if path.extension().and_then(|s| s.to_str()) != Some("svg")
            || path.to_string_lossy().len() > 4096
            || path.to_string_lossy().chars().any(char::is_control)
            || path.components().any(|c| matches!(c, Component::ParentDir))
        {
            return Err(invalid());
        }
        let parent = path.parent().ok_or_else(invalid)?;
        let metadata = fs::symlink_metadata(parent).map_err(|_| invalid())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(invalid());
        }
        // Resolve system aliases (e.g. macOS /var -> /private/var) once, then operate on
        // the fixed canonical destination. A supplied final directory symlink is rejected.
        let parent = fs::canonicalize(parent).map_err(|_| invalid())?;
        let path = parent.join(path.file_name().ok_or_else(invalid)?);
        for ancestor in parent.ancestors() {
            let metadata = fs::symlink_metadata(ancestor).map_err(|_| invalid())?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(invalid());
            }
            #[cfg(target_os = "windows")]
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes() & 0x400 != 0 {
                    return Err(invalid());
                }
            }
        }
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            _ => return Err(invalid()),
        }
        Ok(Self {
            path,
            expected: None,
        })
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn write(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > 256 * 1024 {
            return Err(invalid());
        }
        match &self.expected {
            Some(expected) => {
                let meta = fs::symlink_metadata(&self.path).map_err(|_| invalid())?;
                private_file(&self.path, &meta).map_err(|_| invalid())?;
                if meta.len() != expected.len() as u64
                    || fs::read(&self.path).map_err(|_| invalid())? != *expected
                {
                    return Err(invalid());
                }
                atomic_write(&self.path, bytes)?;
            }
            None => {
                let mut file = open_private(&self.path, true)?;
                file.write_all(bytes).map_err(|_| invalid())?;
                file.sync_all().map_err(|_| invalid())?;
            }
        }
        self.expected = Some(bytes.to_vec());
        Ok(())
    }
    pub fn invalidate(&mut self) -> Result<()> {
        self.write(br#"<svg xmlns="http://www.w3.org/2000/svg" width="400" height="100"><rect width="400" height="100" fill="white"/><text x="10" y="50">QR inactive. Check pair status.</text></svg>"#)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn temp() -> PathBuf {
        let path = std::env::temp_dir().join(format!("ownmate-owner-test-{}", random_id()));
        // Only the new synthetic subtree is initialized, never the shared temporary parent.
        private_directory(&path.join("init")).unwrap();
        fs::canonicalize(path).unwrap()
    }

    #[test]
    fn live_control_is_nonsecret_stale_generations_cannot_replace_and_dead_owner_cannot_receive() {
        let root = temp();
        let mut owner = PairOwner::start_at(root.join("runs"), 10_000).unwrap();
        owner
            .update(State::WaitingPhone, 1, Some(5000), None)
            .unwrap();
        let id = owner.id().to_owned();
        assert_eq!(
            replace_at(&root.join("runs"), &id).unwrap()["reason"],
            "REPLACE_REQUEST_QUEUED"
        );
        let text = fs::read_to_string(owner.directory.join("request.json")).unwrap();
        assert!(!text.contains("secret"));
        assert!(!text.contains("token"));
        assert!(!text.contains("key"));
        owner
            .update(State::WaitingPhone, 2, Some(9000), None)
            .unwrap();
        assert!(!owner.take_replace().unwrap());
        replace_at(&root.join("runs"), &id).unwrap();
        assert!(owner.take_replace().unwrap());
        assert!(!owner.take_replace().unwrap());
        let directory = owner.directory.clone();
        drop(owner);
        let (record, alive) = snapshot(&directory).unwrap();
        assert!(!alive);
        assert_eq!(report(&record, alive)["reason"], "PAIR_OWNER_LOST");
        assert!(replace_at(&root.join("runs"), &id).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn svg_never_overwrites_an_existing_or_modified_file() {
        let root = temp();
        let path = root.join("pair.svg");
        let mut output = QrOutput::new(path.clone()).unwrap();
        output.write(b"first").unwrap();
        assert!(QrOutput::new(path.clone()).is_err());
        output.write(b"second").unwrap();
        fs::write(&path, b"user replacement").unwrap();
        assert!(output.write(b"third").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"user replacement");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn busy_control_writer_does_not_kill_owner_or_consume_queued_request() {
        let root = temp();
        let mut owner = PairOwner::start_at(root.join("runs"), 10_000).unwrap();
        owner
            .update(State::WaitingPhone, 1, Some(5000), None)
            .unwrap();
        replace_at(&root.join("runs"), owner.id()).unwrap();
        let writer = open_private(&owner.directory.join("control.lock"), false).unwrap();
        writer.try_lock().unwrap();
        assert!(!owner.take_replace().unwrap());
        assert!(snapshot(&owner.directory).unwrap().1);
        assert!(owner.directory.join("request.json").exists());
        drop(writer);
        assert!(owner.take_replace().unwrap());
        assert!(!owner.take_replace().unwrap());
        drop(owner);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_metadata_and_output_symlinks_are_rejected_unchanged() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let root = temp();
        let owner = PairOwner::start_at(root.join("runs"), 10_000).unwrap();
        let directory = owner.directory.clone();
        drop(owner);
        fs::set_permissions(
            directory.join("status.json"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(snapshot(&directory).is_err());
        let target = root.join("target.svg");
        fs::write(&target, b"unchanged").unwrap();
        symlink(&target, root.join("pair.svg")).unwrap();
        assert!(QrOutput::new(root.join("pair.svg")).is_err());
        assert_eq!(fs::read(target).unwrap(), b"unchanged");
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn global_listing_is_newest_first_and_explicitly_truncated_without_repairing_history() {
        let root = temp();
        let runs = root.join("runs");
        private_directory(&runs).unwrap();
        for index in 0..130 {
            fs::create_dir(runs.join(format!("{index:032x}"))).unwrap();
        }
        let list = all_status_at(&runs).unwrap();
        assert!(list.truncated);
        assert!(!list.scan_truncated);
        assert_eq!(list.sessions.len(), 128);
        assert!(
            list.sessions
                .iter()
                .any(|v| v["session"] == format!("{:032x}", 129))
        );
        assert!(
            list.sessions.iter().all(
                |v| v["state"] == "metadata_unavailable" && v["serverActiveConfirmed"] == false
            )
        );
        assert!(
            !runs
                .join(format!("{:032x}", 129))
                .join("status.json")
                .exists()
        );
        fs::remove_dir_all(root).unwrap();
    }
}
