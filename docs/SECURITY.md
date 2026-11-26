# Security checklist

This repository is a hackathon prototype tested with synthetic challenge data.
A successful run, contract check or zero-leak practice result is not a formal
anonymity guarantee and is not approval to process real patient records.

## Before processing

- Use only the synthetic challenge data for development and demonstrations.
- For any separately authorized deployment, mount source data read-only and use
  encrypted storage for both source and output volumes.
- Keep secrets outside the repository and separate from the data volumes.
  Use a unique, high-entropy `RAKSHA_SECRET` supplied by a secret manager.
- Never use the public `"practice"` secret for real data. Do not place secrets
  in source code, command-line arguments, logs, shell history or generated
  reports.
- Restrict the service account to the minimum input-read and output-write
  permissions needed.

## During and after processing

- Run in an isolated environment with network access disabled when the
  deployment requires it. The challenge run path does not need a hosted service
  or model download.
- Protect logs, temporary directories, crash dumps and swap. The pipeline
  processes records in memory, but the operating system may still write
  process data to disk.
- Validate the output and review the aggregate privacy audit before any
  authorized release. A suppressed or missing value is not proof that a
  record is safe.
- Control access to outputs and define a retention/deletion policy. Do not
  commit generated releases, source data, logs, truth files or attacker data.
- Rotate secrets between releases. A new secret changes keyed pseudonyms and
  date shifts; this reduces direct cross-release matching but is not a
  substitute for privacy analysis.

## Optional encrypted archive

[`secure_archive.py`](../secure_archive.py) can package an already-reviewed
release into an authenticated encrypted archive. Install
[`requirements-security.txt`](../requirements-security.txt) and provide a
separate base64-encoded 32-byte key using `RAKSHA_ARCHIVE_KEY`. Do not reuse
the pseudonym secret.

The archive tool does not encrypt source files, modify or delete existing
plaintext releases, configure encrypted disks, or replace access controls.
Secure those separately.

## Known boundaries

- The dataset and practice checks are synthetic. They cannot establish
  performance or safety for real-world data.
- The public practice checker is not the organizer's full attacker; hidden
  data and attack results are unavailable in this checkout.
- The aggregate privacy audit currently reports partial coverage because
  suppressed or missing attributes prevent cohort measurement.
- FHIR checks are structural and do not certify complete R4/profile
  conformance.
- Unseen languages, labels, encodings, formats and embedded payloads may not
  be detected. Unsupported inputs are intended to be quarantined, but a
  successful local check cannot prove the absence of all leakage paths.

Treat every output as sensitive until it has been independently reviewed.
