use crate::protocol::{
    ExternalKeyEnvelope, McpJournalV1, McpStateOfMindV1, OpaqueJournal, SyncJournalPayload,
    WrappedDekField,
};
use crate::{McpError, Result};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hkdf::Hkdf;
use journal_domain::{JournalContextV1, StateOfMindEntryTypeV1, validate_canonicalize_hash_json};
use p256::ecdh::diffie_hellman;
use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
use p256::{PublicKey, SecretKey};
use rand_core::OsRng;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const MAX_CIPHERTEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_CANONICAL_BYTES: usize = 2 * 1024 * 1024;
const MAX_TEXT_BYTES: usize = 1024 * 1024;

/// Read-only projection of fields shared by every Journal schema accepted by journal-domain.
/// The full canonical envelope is validated first; this type deliberately does not duplicate
/// legacy/native Document shapes inside the external-access boundary.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExternalJournalProjection {
    entry_id: String,
    occurred_at: String,
    timezone: String,
    context: JournalContextV1,
}

pub struct PairingIdentity {
    secret_key: SecretKey,
    public_key_base64: String,
}

impl PairingIdentity {
    pub fn generate() -> Result<Self> {
        Self::from_secret(SecretKey::random(&mut OsRng))
    }

    fn from_secret(secret_key: SecretKey) -> Result<Self> {
        let der = secret_key
            .public_key()
            .to_public_key_der()
            .map_err(|_| McpError::Crypto)?;
        Ok(Self {
            secret_key,
            public_key_base64: STANDARD.encode(der.as_bytes()),
        })
    }

    pub fn public_key_base64(&self) -> &str {
        &self.public_key_base64
    }

    pub fn unwrap_dek(
        &self,
        envelope: &ExternalKeyEnvelope,
        grant_id: &str,
        trust_mode: &str,
        grant_expires_at: Option<u64>,
    ) -> Result<(String, Zeroizing<Vec<u8>>)> {
        if envelope.version != 2
            || envelope.algorithm != "AES-256-GCM"
            || envelope.hkdf_info != "OwnMate ExternalAccess v2"
            || envelope.keyspace_id.is_empty()
        {
            return Err(McpError::Crypto);
        }
        let field: WrappedDekField =
            serde_json::from_str(&envelope.wrapped_dek).map_err(|_| McpError::Crypto)?;
        let expected_expiry = grant_expires_at.unwrap_or(0);
        if field.version != 2
            || field.envelope_type != "ownmate-external-key-envelope"
            || field.purpose != "DEK"
            || !valid_dek_id(&field.key_id)
            || field.source_device_id != envelope.source_device_id
            || field.destination_device_id != grant_id
            || field.keyspace_id != envelope.keyspace_id
            || field.keyspace_generation != envelope.keyspace_generation
            || field.trust_mode != trust_mode
            || field.expires_at != expected_expiry
        {
            return Err(McpError::Crypto);
        }

        let source_der = decode_standard(&envelope.source_public_key, None, "来源设备公钥")?;
        let source_public =
            PublicKey::from_public_key_der(&source_der).map_err(|_| McpError::Crypto)?;
        let destination_der = self
            .secret_key
            .public_key()
            .to_public_key_der()
            .map_err(|_| McpError::Crypto)?;
        if fingerprint(&source_der) != field.source_key_fingerprint
            || fingerprint(destination_der.as_bytes()) != field.destination_key_fingerprint
        {
            return Err(McpError::Crypto);
        }

        let salt = decode_standard(&envelope.salt, Some(32), "External access envelope salt")?;
        let shared = diffie_hellman(
            self.secret_key.to_nonzero_scalar(),
            source_public.as_affine(),
        );
        let mut wrapping_key = Zeroizing::new(vec![0_u8; 32]);
        Hkdf::<Sha256>::new(Some(&salt), shared.raw_secret_bytes().as_slice())
            .expand(envelope.hkdf_info.as_bytes(), &mut wrapping_key)
            .map_err(|_| McpError::Crypto)?;
        let ciphertext = decode_standard(&field.ciphertext, Some(48), "DEK ciphertext")?;
        let nonce = decode_standard(&field.nonce, Some(12), "DEK nonce")?;
        let aad = external_envelope_aad(&field);
        let plaintext = Aes256Gcm::new_from_slice(&wrapping_key)
            .map_err(|_| McpError::Crypto)?
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| McpError::Crypto)?;
        if plaintext.len() != 32 {
            return Err(McpError::Crypto);
        }
        Ok((field.key_id, Zeroizing::new(plaintext)))
    }
}

pub fn decrypt_mcp_journal(
    item: &OpaqueJournal,
    dek_key_id: &str,
    dek: &[u8],
) -> Result<McpJournalV1> {
    let mut plaintext = decrypt_payload(item, dek_key_id, dek)?;
    let result = parse_mcp_journal(item, &plaintext);
    plaintext.zeroize();
    result
}

pub fn decrypt_payload(
    item: &OpaqueJournal,
    dek_key_id: &str,
    dek: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if dek.len() != 32
        || item.key_id != dek_key_id
        || item.algorithm != "AES-256-GCM"
        || item.encryption_version != 1
    {
        return Err(McpError::Crypto);
    }
    let ciphertext = decode_standard(&item.ciphertext, None, "Journal ciphertext")?;
    if ciphertext.len() < 16 || ciphertext.len() > MAX_CIPHERTEXT_BYTES {
        return Err(McpError::Invalid("Journal 密文大小无效".into()));
    }
    let nonce = decode_standard(&item.nonce, Some(12), "Journal nonce")?;
    let aad = format!("ownmate.sync.v2\nentryId={}", item.entry_id);
    let plaintext = Aes256Gcm::new_from_slice(dek)
        .map_err(|_| McpError::Crypto)?
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| McpError::Crypto)?;
    Ok(Zeroizing::new(plaintext))
}

fn parse_mcp_journal(item: &OpaqueJournal, plaintext: &[u8]) -> Result<McpJournalV1> {
    if plaintext.len() > MAX_CIPHERTEXT_BYTES {
        return Err(McpError::Invalid("Journal payload 超限".into()));
    }
    let payload: SyncJournalPayload = serde_json::from_slice(plaintext)?;
    if payload.payload_version < 3
        || payload.record_state.as_deref() != Some("saved")
        || payload.lifecycle.state != "active"
    {
        return Err(McpError::Invalid("Journal 不是可读取的已保存记录".into()));
    }
    if payload.canonical_journal_json.len() > MAX_CANONICAL_BYTES
        || payload.title.len() > MAX_TEXT_BYTES
        || payload.plain_text.len() > MAX_TEXT_BYTES
    {
        return Err(McpError::Invalid("Journal 明文字段超限".into()));
    }
    validate_canonicalize_hash_json(&payload.canonical_journal_json)
        .map_err(|_| McpError::Invalid("Journal canonical 校验失败".into()))?;
    let journal: ExternalJournalProjection = serde_json::from_str(&payload.canonical_journal_json)?;
    if journal.entry_id != item.entry_id {
        return Err(McpError::Invalid("Journal entryId 不匹配".into()));
    }
    let state_of_mind = journal.context.state_of_mind.map(|state| McpStateOfMindV1 {
        entry_type: match state.entry_type {
            StateOfMindEntryTypeV1::Emotion => "emotion",
            StateOfMindEntryTypeV1::Mood => "mood",
        }
        .into(),
        score: state.score,
        descriptors: state.descriptors,
        factors: state.factors,
        additional_context: state.additional_context,
        logged_at: state.logged_at,
    });
    Ok(McpJournalV1 {
        version: 1,
        entry_id: journal.entry_id,
        occurred_at: journal.occurred_at,
        timezone: journal.timezone,
        title: payload.title,
        text: payload.plain_text,
        tags: journal.context.tags,
        mood: journal.context.mood,
        state_of_mind,
    })
}

fn external_envelope_aad(field: &WrappedDekField) -> Vec<u8> {
    [
        "ownmate-external-key-envelope",
        "2",
        &field.purpose,
        &field.key_id,
        &field.keyspace_id,
        &field.keyspace_generation.to_string(),
        &field.source_device_id,
        &field.destination_device_id,
        &field.source_key_fingerprint,
        &field.destination_key_fingerprint,
        &field.trust_mode,
        &field.expires_at.to_string(),
    ]
    .join("\u{1f}")
    .into_bytes()
}

fn fingerprint(der: &[u8]) -> String {
    STANDARD.encode(Sha256::digest(der))
}

fn valid_dek_id(value: &str) -> bool {
    value.strip_prefix("ownmate_dek_v").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn decode_standard(value: &str, expected: Option<usize>, label: &str) -> Result<Vec<u8>> {
    if value.is_empty() || value.len() > MAX_CIPHERTEXT_BYTES * 2 {
        return Err(McpError::Invalid(format!("{label} Base64 无效")));
    }
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| McpError::Invalid(format!("{label} Base64 无效")))?;
    if STANDARD.encode(&decoded) != value || expected.is_some_and(|size| decoded.len() != size) {
        return Err(McpError::Invalid(format!("{label} 长度或编码无效")));
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::Payload;
    use serde_json::{Value, json};

    #[test]
    fn external_aad_matches_shared_fixture() {
        let field = WrappedDekField {
            version: 2,
            envelope_type: "ownmate-external-key-envelope".into(),
            purpose: "DEK".into(),
            key_id: "ownmate_dek_v1".into(),
            keyspace_id: "keyspace-fixture".into(),
            keyspace_generation: 3,
            source_device_id: "device-source".into(),
            destination_device_id: "external_grant_external_pairing_fixture123456789".into(),
            source_key_fingerprint: "source-fingerprint".into(),
            destination_key_fingerprint: "destination-fingerprint".into(),
            trust_mode: "temporary".into(),
            expires_at: 1_780_001_800_000,
            ciphertext: String::new(),
            nonce: String::new(),
        };
        assert_eq!(
            STANDARD.encode(external_envelope_aad(&field)),
            "b3dubWF0ZS1leHRlcm5hbC1rZXktZW52ZWxvcGUfMh9ERUsfb3dubWF0ZV9kZWtfdjEfa2V5c3BhY2UtZml4dHVyZR8zH2RldmljZS1zb3VyY2UfZXh0ZXJuYWxfZ3JhbnRfZXh0ZXJuYWxfcGFpcmluZ19maXh0dXJlMTIzNDU2Nzg5H3NvdXJjZS1maW5nZXJwcmludB9kZXN0aW5hdGlvbi1maW5nZXJwcmludB90ZW1wb3JhcnkfMTc4MDAwMTgwMDAwMA=="
        );
    }

    #[test]
    fn projection_matches_allowlist_fixture_and_excludes_sensitive_context() {
        let journal_fixture: Value = serde_json::from_str(include_str!(
            "../../../../contracts/editor-native/v1/journal-v5.json"
        ))
        .unwrap();
        let canonical = journal_fixture["accepted"]["input"].to_string();
        let plaintext = json!({
            "payloadVersion": 3,
            "recordState": "saved",
            "canonicalJournalJson": canonical,
            "title": "独立标题",
            "plainText": "正文第一段 🙂",
            "lifecycle": {"state": "active"},
            "attachments": {"image-asset-fixture-v5": {"orig": "secret-object"}}
        })
        .to_string();
        let key = [7_u8; 32];
        let nonce = [9_u8; 12];
        let entry_id = "entry-native-v1";
        let aad = format!("ownmate.sync.v2\nentryId={entry_id}");
        let ciphertext = Aes256Gcm::new_from_slice(&key)
            .unwrap()
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: aad.as_bytes(),
                },
            )
            .unwrap();
        let item = OpaqueJournal {
            entry_id: entry_id.into(),
            key_id: "ownmate_dek_v1".into(),
            ciphertext: STANDARD.encode(ciphertext),
            nonce: STANDARD.encode(nonce),
            algorithm: "AES-256-GCM".into(),
            encryption_version: 1,
            revision: 1,
            journal_schema_version: 5,
            server_updated_at: 0,
        };

        let projected = decrypt_mcp_journal(&item, "ownmate_dek_v1", &key).unwrap();
        let expected: McpJournalV1 = serde_json::from_str(include_str!(
            "../../../../contracts/external-access/v1/fixtures/mcp-journal.json"
        ))
        .unwrap();
        assert_eq!(projected, expected);
        let serialized = serde_json::to_string(&projected).unwrap();
        for forbidden in [
            "location",
            "weather",
            "assets",
            "attachment",
            "filename",
            "checksum",
            "resultId",
            "provenance",
            "deviceId",
            "webPreviews",
            "capturedAt",
        ] {
            assert!(!serialized.contains(forbidden), "leaked {forbidden}");
        }
    }

    #[test]
    fn rust_opens_android_compatible_p256_hkdf_aes_gcm_envelope() {
        let destination = PairingIdentity::generate().unwrap();
        let source_secret = SecretKey::random(&mut OsRng);
        let source_der = source_secret
            .public_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();
        let destination_der = destination
            .secret_key
            .public_key()
            .to_public_key_der()
            .unwrap();
        let grant_id = "external_grant_external_pairing_1234567890abcdef";
        let expires_at = 1_780_001_800_000;
        let mut field = WrappedDekField {
            version: 2,
            envelope_type: "ownmate-external-key-envelope".into(),
            purpose: "DEK".into(),
            key_id: "ownmate_dek_v1".into(),
            keyspace_id: "keyspace-fixture".into(),
            keyspace_generation: 3,
            source_device_id: "device-source".into(),
            destination_device_id: grant_id.into(),
            source_key_fingerprint: fingerprint(&source_der),
            destination_key_fingerprint: fingerprint(destination_der.as_bytes()),
            trust_mode: "temporary".into(),
            expires_at,
            ciphertext: String::new(),
            nonce: String::new(),
        };
        let salt = [3_u8; 32];
        let shared = diffie_hellman(
            source_secret.to_nonzero_scalar(),
            destination.secret_key.public_key().as_affine(),
        );
        let mut wrapping_key = [0_u8; 32];
        Hkdf::<Sha256>::new(Some(&salt), shared.raw_secret_bytes().as_slice())
            .expand(b"OwnMate ExternalAccess v2", &mut wrapping_key)
            .unwrap();
        let nonce = [4_u8; 12];
        let dek = [5_u8; 32];
        let ciphertext = Aes256Gcm::new_from_slice(&wrapping_key)
            .unwrap()
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &dek,
                    aad: &external_envelope_aad(&field),
                },
            )
            .unwrap();
        field.ciphertext = STANDARD.encode(ciphertext);
        field.nonce = STANDARD.encode(nonce);
        let envelope = ExternalKeyEnvelope {
            version: 2,
            keyspace_id: "keyspace-fixture".into(),
            keyspace_generation: 3,
            algorithm: "AES-256-GCM".into(),
            hkdf_info: "OwnMate ExternalAccess v2".into(),
            salt: STANDARD.encode(salt),
            wrapped_dek: serde_json::to_string(&field).unwrap(),
            source_device_id: "device-source".into(),
            source_public_key: STANDARD.encode(source_der),
        };

        let (key_id, unwrapped) = destination
            .unwrap_dek(&envelope, grant_id, "temporary", Some(expires_at))
            .unwrap();
        assert_eq!(key_id, "ownmate_dek_v1");
        assert_eq!(unwrapped.as_slice(), dek);
        assert!(
            destination
                .unwrap_dek(&envelope, grant_id, "trusted", Some(expires_at))
                .is_err()
        );
    }

    #[test]
    fn draft_payload_is_never_projected() {
        let item = OpaqueJournal {
            entry_id: "entry".into(),
            key_id: "ownmate_dek_v1".into(),
            ciphertext: String::new(),
            nonce: String::new(),
            algorithm: "AES-256-GCM".into(),
            encryption_version: 1,
            revision: 1,
            journal_schema_version: 6,
            server_updated_at: 0,
        };
        let payload = json!({
            "payloadVersion": 3,
            "recordState": "draft",
            "canonicalJournalJson": "{}",
            "title": "draft",
            "plainText": "private draft",
            "lifecycle": {"state": "active"}
        });
        assert!(parse_mcp_journal(&item, payload.to_string().as_bytes()).is_err());
    }

    #[test]
    fn journal_key_id_must_match_the_paired_dek() {
        let item = OpaqueJournal {
            entry_id: "entry".into(),
            key_id: "ownmate_dek_v2".into(),
            ciphertext: STANDARD.encode([0_u8; 16]),
            nonce: STANDARD.encode([0_u8; 12]),
            algorithm: "AES-256-GCM".into(),
            encryption_version: 1,
            revision: 1,
            journal_schema_version: 6,
            server_updated_at: 0,
        };
        assert!(decrypt_mcp_journal(&item, "ownmate_dek_v1", &[0_u8; 32]).is_err());
    }
}
