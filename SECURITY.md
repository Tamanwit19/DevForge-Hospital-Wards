# Deployment security checklist

This repository processes organizer-provided synthetic records only.
A format pass and a zero-leak practice check are not a formal anonymity guarantee.

- Mount source data read-only on an encrypted volume. Keep the output volume
  encrypted as well. Do not store keys on that same volume.
- Use an isolated service account without network access during processing.
  Grant read access to inputs and write access only to the designated output.
- Use a unique high-entropy release secret from a secret manager; never use
  the public practice secret in production. Avoid shell history, source code,
  command-line arguments, debug dumps, and environment snapshots that expose keys.
- Restrict logs, disable unencrypted swap and crash dumps, and avoid writing raw
  intermediate records. This pipeline keeps raw records in memory.
- Review the aggregate privacy diagnostic and validate the output before release.
  A cohort that cannot be measured is not automatically safe.
- Rotate and revoke access to prior outputs. Avoid committing datasets, raw logs,
  truth files, credentials or generated outputs to Git.
- Optional: encrypt a reviewed sanitized release with secure_archive.py.
  Its separate archive key is provided using RAKSHA_ARCHIVE_KEY (base64 of 32
  random bytes), and must not reuse the pseudonym secret. This produces an
  authenticated encrypted archive without a plaintext ZIP on disk.
  The original release remains unchanged; encrypted storage is still needed
  for its plaintext copy and the source data.

The optional archive utility requires requirements-security.txt. It is not part
of the challenge run contract. No raw data is automatically uploaded, published,
deleted, or encrypted in place.
