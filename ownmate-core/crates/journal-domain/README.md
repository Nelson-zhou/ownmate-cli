# Journal Domain

`journal-domain` owns the canonical Journal envelope boundary. Read this file,
ADR-0009 and `contracts/editor-native/README.md` before changing Journal schema,
title ownership, Document versioning, Context, assets, canonical JSON or hashes.

## Current schema boundary

Journal `titleEnabled` is an optional boolean (missing/true = enabled; true is omitted on canonical
serialization to retain old hashes). Explicit removal stores false and requires an empty title;
nonempty hidden titles and non-boolean values fail closed. `journal-v5.json.titleVisibility` covers
this intent independently of Document/Context. Android records one history/revision boundary for
clear+disable and another for enable, including an already-empty title. Transport carries the same
canonical bytes; older clients that reject this new field must not silently rewrite it.

Journal Context 的 `weather.details` 是可选持久天气快照，类型为 `WeatherDetailsSnapshotV1`。缺失字段不补默认气象值；整个详情缺失时序列化仍省略该属性，保持既有 Journal canonical/hash 不变。新快照的单位、观测时间、日汇总标记、天气/天文字段必须经过 typed 校验并完整保留；百分比、非负气象量、气压和文本长度有边界。共享 `journal-v5.json.weatherSnapshot` 覆盖 canonical 往返及 hash，Android JNI/Room/远端接收覆盖存取；旧 APK 与其它平台的端到端保真尚不作承诺，不能只改 Kotlin 而遗漏 Rust 导致字段静默丢失。

- Schemas 2-4 are the temporary legacy ProseMirror envelope and contain
  `OwnMateDocumentV1` (Document schema 1-2).
- Schema 5 is the native cross-platform envelope and contains an independent
  title plus `OwnMateDocumentV3` body.
- The schema families use separate Rust types and version dispatch. Do not
  replace them with an optional-title/untagged-document catch-all that permits
  invalid combinations.
- The title is plain Unicode, may be empty and is capped at 1024 UTF-16 code
  units to match platform selection/input contracts.
- Context and asset manifests remain outside Document. Canonical data never
  contains a platform URI, path, view type or IME state.
- Schema 5 may contain up to 64 `webPreviews` as historical presentation
  metadata for permanent http(s) Document URLs. They remain outside Document,
  Context and Assets; entries are unique and strictly sorted by exact URL UTF-16
  units, with bounded title/description/site fields and a bounded capture
  timestamp. An empty collection is omitted so pre-feature Journal v5 hashes
  remain stable.

The shared executable fixture is
`contracts/editor-native/v1/journal-v5.json`. Any schema change updates that
fixture and Rust validation in the same commit, then adds conformance tests for
Android, Web, iOS and HarmonyOS before claiming cross-platform support.

## Migration rule

The shared FFI accepts schemas 2-4 only during the bounded Android route
migration. This is not a production compatibility promise. Remove the legacy
type and validator only with the versioned Room development-data cleanup, sync
cursor/tombstone reset, Backup rejection fencing and WebView removal described
by ADR-0009.

## Verification

From `ownmate-core/` run:

```bash
cargo fmt --all -- --check
cargo test -p journal-domain -p core-ffi
cargo clippy -p journal-domain -p core-ffi --all-targets -- -D warnings
```

Tests assert canonical/hash stability, title/body/reference-plane separation,
web-preview limits/order, UTF-16 limits, schema-shape rejection, legacy-window
behavior and the stable C FFI boundary.
