# Security

Please report vulnerabilities privately using GitHub's private vulnerability reporting for this repository. Do not include tokens, pairing secrets, encryption keys, or personal records in public issues.

This connector decrypts authorized records locally. Temporary sessions last 30 minutes; trusted sessions use the operating system credential store. Revoking access stops future downloads, but cannot erase copies already made by an external application.

Version 0.1 is a preview. Production pairing is not yet enabled. Use a test service until the complete Android approval, revocation, expiration, and account deletion flows have been verified.
