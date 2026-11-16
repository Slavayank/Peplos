# Peplos compatibility changes

This is the upstream `keepass-rs` 0.2.0 source with its original license retained.

- KDBX 3.1 validates the decrypted 32-byte stream-start block against the value stored in outer-header field 9.
- KDBX 3.1 writing generates one random stream-start value and stores the same value in the header and encrypted payload.
- AES-KDF rounds are retained when a KDBX 3.1 database is opened and reused when it is saved; new KDBX 3.1 databases default to 60,000 rounds.
- The composite key always hashes the concatenation of its components, including the single-component case required for password-only and key-file-only databases.
- KDBX 3.1 end-of-header marker bytes are consumed and validated before reading the AES-CBC payload.

These changes keep KDBX 3.1 files compatible with KeePass instead of relying on a reader/writer pair that only agreed with itself.
