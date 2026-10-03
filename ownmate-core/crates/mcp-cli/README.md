# OwnMate CLI / MCP

`ownmate-mcp` is the scoped OwnMate connector for terminal commands and stdio MCP Hosts. It decrypts approved records locally and submits encrypted CREATE/UPDATE reminder commands for the approved phone to apply. Reminder write does not imply read and cannot complete, delete, or modify notebook content.

See the [repository README](../../../README.md) for installation, phone approval, input fields, result stages, limits, timezone support, privacy, and acceptance boundaries. The embedded [reminder interface](src/reminder-interface-v1.json) is available with `ownmate-mcp reminders schema`; `reminders validate create|update --input -` validates stdin JSON offline without accessing credentials or records.

Build from the repository root with `cargo build --locked --release --manifest-path ownmate-core/Cargo.toml -p ownmate-mcp`. This module owns transport, input validation, cryptography, credential storage, retry ciphertext, and projections. It does not implement another reminder database, AI provider, or background scheduler. A disabled reminder capability or unavailable phone cannot bypass normal App business rules; core journaling remains independent.
