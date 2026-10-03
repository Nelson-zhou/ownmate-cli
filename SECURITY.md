# Security

Report vulnerabilities through this repository's private vulnerability reporting. Never include tokens, pairing secrets, encryption keys, personal records, or decrypted reminders in public issues.

The phone approves three independent choices: reminder read, reminder write, and notebook read (journals plus fragments). Write does not imply read. Existing grants do not gain scopes or actions on refresh. Reminder write accepts only CREATE and UPDATE of plan fields; it cannot complete, delete, restore, transfer ownership, modify Document, or access ordinary account/sync writes.

Authorized ciphertext is decrypted locally. Output projection is not cryptographic field isolation: a custom client with the DEK and original journal or fragment ciphertext may decode Context such as location or weather. Grant access only to trusted software. No MEK or ordinary account credentials are granted.

Temporary sessions last at most 30 minutes and keep credentials and retry ciphertext only in memory. Trusted credentials use the operating system credential store. Persistent retry caches contain only encrypted command envelopes, never content plaintext, plaintext hashes, DEK, or tokens. They use private Unix permissions or a checked current-user Windows ACL and fail closed if private storage cannot be established.

Commands are encrypted and have a fixed maximum 24-hour lifetime, further bounded by temporary grant expiry. Retries reuse the exact envelope. The approved phone applies them while the App is in the foreground; queued does not mean saved. Write-only receipts disclose only that grant's request stage and result version, not existing content or the current conflicting version.

Revocation prevents future access and new execution permits. A command already holding a short valid execution permit may complete; applied facts are not automatically rolled back. Revocation cannot erase copies already made by an external application. `disconnect` removes this computer's credentials; revoke the grant in the App to stop subsequent cloud access.

CLI release binaries are unsigned preview builds. SHA-256 files verify integrity, not publisher signatures. Automated Linux/macOS/Windows checks do not prove real credential-store behavior, Windows ACL protection, complete IANA timezone support, phone pairing, offline application, production database races, or notification delivery. The reminder write production switch and compatible App are required independently of source availability.
