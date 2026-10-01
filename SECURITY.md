# Security

Please report vulnerabilities privately using GitHub's private vulnerability reporting for this repository. Do not include tokens, pairing secrets, encryption keys, or personal records in public issues.

This connector decrypts authorized records locally. Temporary sessions last 30 minutes; trusted sessions use the operating system credential store. Revoking access stops future downloads, but cannot erase copies already made by an external application.

This is a source preview, not a signed release. Journal-only temporary production pairing has received a smoke test; expanded scopes and reminder sync still require deployment and end-to-end acceptance. Local tests do not prove all production flows.

Output projection is not cryptographic field isolation. A custom authorized client with the DEK and original journal or fragment ciphertext may decode Context such as location or weather. Grant access only to trusted software. No MEK, account login or sync write permission is granted.
