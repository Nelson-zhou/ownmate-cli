//! Reproduces the Android editor persistence candidate for documents that mix
//! paragraph text with audio attachment / reminder reference / image blocks.
//! Mirrors `NativeJournalCandidateFactory` so any canonicalization asymmetry
//! that would break `ValidatedCanonicalJournal.matches(snapshot)` fails here.

use serde_json::{Value, json};

fn audio_attachment_candidate() -> Value {
    json!({
        "journalSchemaVersion": 5,
        "entryId": "entry-audio-1",
        "journalDate": "2026-08-18",
        "occurredAt": "2026-08-18T09:00:00Z",
        "createdAt": "2026-08-18T09:00:00Z",
        "updatedAt": "2026-08-18T09:05:00Z",
        "timezone": "Asia/Shanghai",
        "revision": 6,
        "title": "录音日记",
        "document": {
            "documentSchemaVersion": 3,
            "blocks": [
                {"type": "paragraph", "id": "p1", "content": [
                    {"text": "今天录了一段", "marks": []}
                ]},
                {"type": "attachment", "id": "a1", "assetId": "asset-audio-1",
                 "kind": "audio", "label": "录音"},
                {"type": "reminderReference", "id": "r1", "reminderId": "reminder-1"}
            ]
        },
        "context": {
            "location": null,
            "weather": null,
            "mood": null,
            "tags": [],
            "provenance": {
                "occurredAt": null,
                "location": null,
                "weather": null
            }
        },
        "assets": [{
            "assetId": "asset-audio-1",
            "assetType": "audio",
            "mimeType": "audio/mp4",
            "byteSize": 2048,
            "checksum": "3f5a1c9d2e8b7f6041a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708",
            "createdAt": "2026-08-18T09:04:00Z",
            "width": null,
            "height": null,
            "durationMs": 42000,
            "originalFilename": "asset-audio-1.m4a",
            "localState": "pending",
            "remoteState": "localOnly",
            "cloudEncryptionMetadata": null
        }],
        "source": {"type": "ownMate"}
    })
}

fn image_candidate() -> Value {
    json!({
        "journalSchemaVersion": 5,
        "entryId": "entry-image-1",
        "journalDate": "2026-08-18",
        "occurredAt": "2026-08-18T09:00:00Z",
        "createdAt": "2026-08-18T09:00:00Z",
        "updatedAt": "2026-08-18T09:05:00Z",
        "timezone": "Asia/Shanghai",
        "revision": 3,
        "title": "照片日记",
        "document": {
            "documentSchemaVersion": 3,
            "blocks": [
                {"type": "paragraph", "id": "p1", "content": [
                    {"text": "拍了张照片", "marks": []}
                ]},
                {"type": "image", "id": "i1", "assetId": "asset-image-1", "alt": ""}
            ]
        },
        "context": {
            "location": null,
            "weather": null,
            "mood": null,
            "tags": [],
            "provenance": {
                "occurredAt": null,
                "location": null,
                "weather": null
            }
        },
        "assets": [{
            "assetId": "asset-image-1",
            "assetType": "image",
            "mimeType": "image/jpeg",
            "byteSize": 8192,
            "checksum": "9b2d4e6f8a0c1e2d3b4a596877665544332211ffeeddccbbaa99887766554433",
            "createdAt": "2026-08-18T09:03:00Z",
            "width": 4032,
            "height": 3024,
            "durationMs": null,
            "originalFilename": null,
            "localState": "pending",
            "remoteState": "localOnly",
            "cloudEncryptionMetadata": null
        }],
        "source": {"type": "ownMate"}
    })
}

#[test]
fn audio_attachment_candidate_validates_and_document_survives_canonicalization() {
    let candidate = audio_attachment_candidate();
    let validated = journal_domain::validate_canonicalize_hash_json(&candidate.to_string())
        .expect("audio attachment candidate must validate");
    let canonical: Value =
        serde_json::from_str(&validated.canonical_json).expect("canonical json must parse");
    assert_eq!(canonical["revision"], json!(6));
    assert_eq!(canonical["entryId"], json!("entry-audio-1"));
    assert_eq!(canonical["title"], json!("录音日记"));
    // `ValidatedCanonicalJournal.matches(snapshot)` decodes the canonical
    // document and compares it to the editor snapshot document.
    assert_eq!(
        canonical["document"], candidate["document"],
        "canonicalization must not alter the editor document"
    );
}

#[test]
fn image_candidate_validates_and_document_survives_canonicalization() {
    let candidate = image_candidate();
    let validated = journal_domain::validate_canonicalize_hash_json(&candidate.to_string())
        .expect("image candidate must validate");
    let canonical: Value =
        serde_json::from_str(&validated.canonical_json).expect("canonical json must parse");
    assert_eq!(
        canonical["document"], candidate["document"],
        "canonicalization must not alter the editor document"
    );
}
