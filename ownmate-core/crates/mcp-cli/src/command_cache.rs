//! Only encrypted command envelopes are persisted. Tokens/DEKs stay in the system keyring.
use crate::protocol::ReminderCommandEnvelope;
use crate::{McpError, Result};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const MAX_ENTRIES: usize = 512;
// Base64 expands the 512 KiB command budget; include bounded envelope metadata.
const MAX_ENTRY_BYTES: u64 = 1024 * 1024;

pub struct CommandCache {
    directory: PathBuf,
}

impl CommandCache {
    pub fn for_grant(base_url: &str, grant_id: &str) -> Result<Self> {
        #[cfg(not(target_os = "windows"))]
        let root = std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|v| PathBuf::from(v).join(".cache")))
            .ok_or_else(|| McpError::Invalid("无法定位私有密文缓存目录".into()))?;
        #[cfg(target_os = "windows")]
        let root = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .ok_or_else(|| McpError::Invalid("无法定位本机 AppData 私有密文缓存目录".into()))?;
        let identity = format!(
            "{:x}",
            Sha256::digest(format!("{base_url}\n{grant_id}").as_bytes())
        );
        Self::open(root.join("ownmate-mcp-reminder-commands").join(identity))
    }

    fn open(directory: PathBuf) -> Result<Self> {
        // The cache fails closed on platforms without the private-file API used here.
        // Temporary grants use memory instead, so no temporary credential/content is persisted.
        private_directory(&directory)?;
        Ok(Self { directory })
    }

    pub fn load(&self, request_id: &str, now: u64) -> Result<Option<ReminderCommandEnvelope>> {
        let path = self.path(request_id);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        private_file(&path, &metadata)?;
        if metadata.len() > MAX_ENTRY_BYTES {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        std::fs::File::open(&path)?
            .take(MAX_ENTRY_BYTES + 1)
            .read_to_end(&mut bytes)?;
        let envelope: ReminderCommandEnvelope =
            serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if envelope.request_id != request_id {
            return Err(invalid());
        }
        if envelope.expires_at <= now {
            return Err(McpError::Invalid(
                "原请求已过期；不得以相同 requestId 延长期限".into(),
            ));
        }
        Ok(Some(envelope))
    }

    pub fn store(
        &self,
        envelope: &ReminderCommandEnvelope,
        now: u64,
    ) -> Result<ReminderCommandEnvelope> {
        if let Some(existing) = self.load(&envelope.request_id, now)? {
            return Ok(existing);
        }
        let serialized = serde_json::to_vec(envelope)?;
        if serialized.len() as u64 > MAX_ENTRY_BYTES {
            return Err(invalid());
        }
        self.prune(now)?;
        let mut random = [0_u8; 16];
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
        let mut file = options.open(&temporary)?;
        let result = (|| -> Result<()> {
            initialize_new_private_file(&temporary)?;
            file.write_all(&serialized)?;
            file.flush()?;
            file.sync_all()?;
            // Atomic no-overwrite publication: concurrent retries reuse the winner's envelope.
            match fs::hard_link(&temporary, self.path(&envelope.request_id)) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
                Err(error) => Err(error.into()),
            }
        })();
        let _ = fs::remove_file(&temporary);
        result?;
        self.load(&envelope.request_id, now)?.ok_or_else(invalid)
    }

    fn path(&self, request_id: &str) -> PathBuf {
        self.directory
            .join(format!("{:x}.json", Sha256::digest(request_id.as_bytes())))
    }

    fn prune(&self, now: u64) -> Result<()> {
        let mut retained = 0;
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(".acl-") {
                retained += 1;
                continue;
            }
            private_file(&entry.path(), &metadata)?;
            if metadata.len() > MAX_ENTRY_BYTES {
                return Err(invalid());
            }
            if entry.file_name().to_string_lossy().starts_with(".tmp-") {
                // Never remove another active writer's temporary file.
                retained += 1;
                continue;
            }
            let mut bytes = Vec::new();
            std::fs::File::open(entry.path())?
                .take(MAX_ENTRY_BYTES + 1)
                .read_to_end(&mut bytes)?;
            let envelope: ReminderCommandEnvelope =
                serde_json::from_slice(&bytes).map_err(|_| invalid())?;
            if envelope.expires_at <= now {
                fs::remove_file(entry.path())?;
            } else {
                retained += 1;
            }
        }
        if retained >= MAX_ENTRIES {
            return Err(McpError::Invalid(
                "私有密文请求缓存已满，请等待旧请求到期".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(unix)]
pub(crate) fn private_directory(directory: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    if let Some(parent) = directory.parent() {
        fs::create_dir_all(parent)?;
        let meta = fs::symlink_metadata(parent)?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(invalid());
        }
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(directory) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.mode() & 0o077 != 0 {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(target_os = "windows")]
pub(crate) fn private_directory(directory: &Path) -> Result<()> {
    if let Some(parent) = directory.parent() {
        windows_acl_step(create_private_windows_directory(parent), "private parent")?;
    }
    windows_acl_step(
        create_private_windows_directory(directory),
        "private directory",
    )
}

#[cfg(all(not(unix), not(target_os = "windows")))]
pub(crate) fn private_directory(_: &Path) -> Result<()> {
    Err(McpError::Invalid(
        "此平台尚无已验证的私有密文缓存权限；请使用临时授权或受支持平台".into(),
    ))
}

pub(crate) fn private_file(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(invalid());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 {
            return Err(invalid());
        }
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(invalid());
        }
        windows_acl_step(
            verify_windows_acl(path, &windows_sid()?),
            "verify private file",
        )?;
    }
    #[cfg(not(target_os = "windows"))]
    let _ = path;
    Ok(())
}

/// Only call immediately after create_new succeeds; never repair an existing file ACL.
pub(crate) fn initialize_new_private_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        if !metadata.is_file() || metadata.file_attributes() & 0x400 != 0 {
            return Err(invalid());
        }
        let sid = windows_sid()?;
        let reset = std::process::Command::new("icacls.exe")
            .arg(path)
            .arg("/reset")
            .output()?;
        if !reset.status.success() {
            return Err(invalid());
        }
        let result = std::process::Command::new("icacls.exe")
            .arg(path)
            .args(["/inheritance:r", "/grant:r"])
            .arg(format!("*{sid}:F"))
            .output()?;
        if !result.status.success() {
            return Err(invalid());
        }
    }
    private_file(path, &metadata)
}

#[cfg(target_os = "windows")]
fn windows_sid() -> Result<String> {
    let result = std::process::Command::new("whoami.exe")
        .args(["/user", "/fo", "csv", "/nh"])
        .output()?;
    if !result.status.success() {
        #[cfg(test)]
        eprintln!("Windows ACL diagnostic: whoami command failed");
        return Err(invalid());
    }
    let output = windows_acl_step(
        String::from_utf8(result.stdout).map_err(|_| invalid()),
        "decode whoami",
    )?;
    let sid = output
        .split('"')
        .find(|value| {
            value.starts_with("S-1-")
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || b == b'-' || b == b'S')
        })
        .ok_or_else(invalid);
    let sid = windows_acl_step(sid, "parse current SID")?;
    Ok(sid.to_owned())
}

#[cfg(target_os = "windows")]
fn protect_windows_directory(path: &Path) -> Result<()> {
    use std::os::windows::fs::MetadataExt;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_attributes() & 0x400 != 0 {
        return Err(invalid());
    }
    let sid = windows_sid()?;
    if verify_windows_acl(path, &sid).is_ok() {
        return Ok(());
    }
    // Each argument is passed directly to icacls; no shell, command interpolation or admin.
    // /reset removes unexpected explicit ACEs before inherited ACEs are disabled.
    let reset = std::process::Command::new("icacls.exe")
        .arg(path)
        .arg("/reset")
        .output()?;
    if !reset.status.success() {
        #[cfg(test)]
        eprintln!("Windows ACL diagnostic: icacls reset command failed");
        return Err(invalid());
    }
    let result = std::process::Command::new("icacls.exe")
        .arg(path)
        .args(["/inheritance:r", "/grant:r"])
        .arg(format!("*{sid}:(OI)(CI)F"))
        .output()?;
    if !result.status.success() {
        #[cfg(test)]
        eprintln!("Windows ACL diagnostic: icacls private grant command failed");
        return Err(invalid());
    }
    verify_windows_acl(path, &sid)
}

#[cfg(target_os = "windows")]
fn create_private_windows_directory(path: &Path) -> Result<()> {
    use std::os::windows::fs::MetadataExt;
    let created = match fs::create_dir(path) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => return Err(error.into()),
    };
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_attributes() & 0x400 != 0 {
        return Err(invalid());
    }
    if created {
        // Initialize only the new directory owned by this operation. Existing unsafe
        // directories are rejected, never reset or changed recursively.
        protect_windows_directory(path)
    } else {
        verify_windows_acl(path, &windows_sid()?)
    }
}

#[cfg(target_os = "windows")]
fn verify_windows_acl(path: &Path, sid: &str) -> Result<()> {
    use base64::Engine;
    use std::process::{Command, Stdio};
    // Windows SDDL may print SID aliases. Ask .NET for numeric SID objects instead
    // of comparing the descriptor's display representation or guessing RID aliases.
    // All variable data enters child-only stdin, never shell/script interpolation.
    const SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$reader = [System.IO.StreamReader]::new([Console]::OpenStandardInput(), [System.Text.Encoding]::UTF8)
$request = $reader.ReadToEnd() | ConvertFrom-Json
$rules = @((Get-Acl -LiteralPath $request.path).GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
$allow = $false; $full = $false; $current = $false; $inheritOnly = $false
if ($rules.Count -eq 1) {
  $rule = $rules[0]
  $allow = $rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow
  $full = $rule.FileSystemRights -eq [System.Security.AccessControl.FileSystemRights]::FullControl
  $current = $rule.IdentityReference.Value -ceq $request.sid
  $inheritOnly = ($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0
}
[Console]::Out.Write((@{entryCount=$rules.Count;allow=$allow;fullAccess=$full;currentPrincipal=$current;inheritOnly=$inheritOnly} | ConvertTo-Json -Compress))
"#;
    let encoded = base64::engine::general_purpose::STANDARD.encode(
        SCRIPT
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>(),
    );
    let request = serde_json::to_vec(&serde_json::json!({
        "path": path.to_str().ok_or_else(invalid)?, "sid": sid
    }))
    .map_err(|_| invalid())?;
    let mut child = Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            &encoded,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(invalid)?
        .write_all(&request)?;
    let result = child.wait_with_output()?;
    if !result.status.success() {
        #[cfg(test)]
        eprintln!("Windows ACL diagnostic: numeric SID query failed");
        return Err(invalid());
    }
    if result.stdout.len() > 4096 {
        return Err(invalid());
    }
    let assessment: WindowsAclAssessment =
        serde_json::from_slice(&result.stdout).map_err(|_| invalid())?;
    validate_windows_acl(&assessment)
}

#[cfg(any(target_os = "windows", test))]
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WindowsAclAssessment {
    entry_count: usize,
    allow: bool,
    full_access: bool,
    current_principal: bool,
    inherit_only: bool,
}

#[cfg(any(target_os = "windows", test))]
fn validate_windows_acl(assessment: &WindowsAclAssessment) -> Result<()> {
    if assessment.entry_count != 1
        || !assessment.allow
        || !assessment.full_access
        || !assessment.current_principal
        || assessment.inherit_only
    {
        #[cfg(test)]
        eprintln!(
            "Windows ACL diagnostic: numeric ACL rejected; count={} allow={} full_access={} current_principal={} inherit_only={}",
            assessment.entry_count,
            assessment.allow,
            assessment.full_access,
            assessment.current_principal,
            assessment.inherit_only
        );
        return Err(invalid());
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_acl_step<T>(result: Result<T>, stage: &str) -> Result<T> {
    #[cfg(test)]
    if result.is_err() {
        eprintln!("Windows ACL diagnostic: failed at {stage}");
    }
    #[cfg(not(test))]
    let _ = stage;
    result
}

fn invalid() -> McpError {
    McpError::Invalid("私有密文请求缓存无效或权限不安全".into())
}

#[cfg(test)]
mod windows_acl_tests {
    use super::*;

    #[test]
    fn numeric_acl_response_rejects_missing_wrong_type_or_extra_fields() {
        for input in [
            r#"{"entryCount":1}"#,
            r#"{"entryCount":"PRIVATE_VALUE"}"#,
            r#"{"entryCount":1,"allow":true,"fullAccess":true,"currentPrincipal":true,"inheritOnly":false,"extra":"PRIVATE_VALUE"}"#,
        ] {
            assert!(serde_json::from_str::<WindowsAclAssessment>(input).is_err());
        }
    }

    #[test]
    fn numeric_acl_accepts_only_one_effective_full_access_current_user_ace() {
        let valid = serde_json::json!({"entryCount":1,"allow":true,"fullAccess":true,"currentPrincipal":true,"inheritOnly":false});
        assert!(validate_windows_acl(&serde_json::from_value(valid.clone()).unwrap()).is_ok());
        for (field, value) in [
            ("entryCount", serde_json::json!(0)),
            ("entryCount", serde_json::json!(2)),
            ("allow", serde_json::json!(false)),
            ("fullAccess", serde_json::json!(false)),
            ("currentPrincipal", serde_json::json!(false)),
            ("inheritOnly", serde_json::json!(true)),
        ] {
            let mut response = valid.clone();
            response[field] = value;
            assert!(validate_windows_acl(&serde_json::from_value(response).unwrap()).is_err());
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn cache_only_persists_private_ciphertext_and_never_replaces_a_retry() {
        use std::os::unix::fs::MetadataExt;
        let mut random = [0_u8; 16];
        OsRng.fill_bytes(&mut random);
        let root = std::env::temp_dir().join(format!(
            "ownmate-command-fixture-{:x}",
            Sha256::digest(random)
        ));
        let cache = CommandCache::open(root.join("grant")).unwrap();
        let mut envelope = crate::reminders::fixture_envelope();
        let original = cache.store(&envelope, 1).unwrap();
        envelope.nonce = "changed".into();
        assert_eq!(cache.store(&envelope, 1).unwrap(), original);
        let path = cache.path(&envelope.request_id);
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert_eq!(
            fs::metadata(&cache.directory).unwrap().mode() & 0o777,
            0o700
        );
        let content = fs::read_to_string(&path).unwrap();
        for secret in ["fixture title", "dekBase64", "accessToken", "refreshToken"] {
            assert!(!content.contains(secret));
        }
        assert!(
            cache
                .load(&envelope.request_id, envelope.expires_at)
                .is_err()
        );
        let mut large = original.clone();
        large.request_id = "fixture_large_request_01".into();
        large.ciphertext =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, vec![0; 524_304]);
        assert_eq!(cache.store(&large, 1).unwrap(), large);
        let large_path = cache.path(&large.request_id);
        let mut too_large = large.clone();
        too_large.request_id = "fixture_overflow_request_01".into();
        too_large.ciphertext = "X".repeat(MAX_ENTRY_BYTES as usize);
        assert!(cache.store(&too_large, 1).is_err());
        assert!(!cache.path(&too_large.request_id).exists());
        fs::remove_file(large_path).unwrap();
        fs::remove_file(path).unwrap();
        fs::remove_dir(cache.directory).unwrap();
        fs::remove_dir(root).unwrap();
    }
}
