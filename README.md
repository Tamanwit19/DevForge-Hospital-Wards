# Secret Wards — Raksha Privacy Firewall

Offline, CPU-only defensive de-identification baseline for the synthetic hospital
record challenge. No hosted services, network requests, large language models or
model downloads are used during execution.

## Run locally (PowerShell)

```powershell
python -m pip install -r requirements.txt
$env:RAKSHA_SECRET = "practice"
python main.py --input Secret-Wards-ToolKit/dev/input --output output_test
python Secret-Wards-ToolKit/validate_output.py --input Secret-Wards-ToolKit/dev/input --output output_test
```

Use a fresh, empty output directory for each run. For Linux, set the secret with
`export RAKSHA_SECRET=practice`. The evaluator supplies a secret at runtime;
do not commit it. In production a high-entropy secret must be managed separately
from data. Practice secrets are not suitable for real records.

## Architecture

1. Discover files in sorted order and calculate their SHA-256 hashes.
2. Parse supported CSV, TSV, JSON and text exports in memory, supporting BOM,
   UTF-8, UTF-16 and legacy encodings. Reject malformed or unsupported files.
3. Detect sensitive fields with normalized label rules, contextual regular
   expressions, and aliases collected from the input itself. No answer keys or
   external patient registries are consulted.
4. Use explicit, unambiguous hospital identifiers for conservative pseudonyms.
   HMAC-SHA256 is keyed with the environment secret. Ambiguous records are not
   linked. The pseudonym is checked against the actual exported record.
5. Sanitize structured fields and free text, redact addresses and direct
   identifiers, band ages, mask postal codes and shift dates consistently for
   linked records while retaining intervals.
6. Export UTF-8 files under opaque filenames, produce a hash-based report and
   write JSONL record mappings. Unsafe files are quarantined by omission, never
   copied to the research release.

## Privacy and utility

Clinical values such as doses, lab units, diagnosis codes and vitals are not
intentionally masked. The engine distinguishes direct identifiers from short
clinical number formats, but contextual classification is imperfect. Exact
names, contact details and birth dates are sensitive; coarse demographic
information can support research while reducing disclosure. No claim of formal
anonymity is made. A passing contract validator only checks output structure,
not whether every identifier is removed.

## Security

Raw input is read-only by convention and not copied or logged. Intermediate
records are kept in process memory; only sanitized outputs are written.
Deployment must use an encrypted volume for input and output, enforce access
controls, disable unencrypted swap and keep secrets in a separate secret store.
No raw quarantine files are written. Reports contain hashes and sanitized
paths rather than original filenames. This baseline does not independently
encrypt the source volume or provide an audited privacy guarantee.

## Limitations

This is a hardened competition prototype, not a production healthcare release tool.
Multilingual free-text aliases, cross-hospital matching, unusual schema keys,
FHIR conformance, rare-value generalization and leakage assessment require
further validation. It does not use fuzzy name-only linkage, since doing so
can conflate distinct people. Explicit duplicate registration IDs can now be reconciled using exact authoritative identifiers; weak evidence is not merged. Opaque filenames are used conservatively even when
the original filename may be safe. Ragged files are quarantined rather than
partially exported. Age bands in integer fields use the lower bound to retain
type, and exact FHIR schema compliance remains unverified.

## Leakage regression (Windows practice checkout)

A Windows checkout changed line endings in 172 of the 200 input files. Their
actual SHA-256 values consequently differ from the original truth hashes,
although reversing only CRLF-to-LF conversion restores the expected hashes.
The official pipeline always reports actual byte hashes. To evaluate locally
without changing organizer assets, run:

```powershell
$env:RAKSHA_SECRET = "practice"
python main.py --input Secret-Wards-ToolKit/dev/input --output output_new
python check_local.py --output output_new
python Secret-Wards-ToolKit/validate_output.py --input Secret-Wards-ToolKit/dev/input --output output_new
python -m unittest test_privacy -v
```

The diagnostic tool only corrects proven newline-only differences in a temporary
truth copy. It is not invoked by the submission. If a mismatch cannot be
verified, it aborts. The current practice run finds 0/3230 known identifiers
and 0/4 canaries, retaining 4741/4741 checked clinical values. This is not a
guarantee on hidden data. The true local linkage recall is 68% (previously
underreported by the unmapped files). The earlier diagnostic is historical; see the latest evaluation below.


## Hardened pipeline: latest practice evaluation

- 193/200 files sanitized, seven unsupported/malformed files quarantined.
- 0/3230 known PII findings; 0/4 canaries.
- 4855/4855 medical probes retained (100%).
- Linkage precision 1.00, recall 0.89, F0.5 0.98.
- Internal encounter ownership and exact authoritative duplicate registrations
  are reconciled only when non-conflicting; no external registry or fuzzy identity lookup.
- FHIR guard checks local references, XHTML parsing, and removes unsafe opaque
  attachments and optional invalid/redacted birth dates. This is not full R4 validation.
- Audit outputs aggregate counts only, never small-group membership or identifiers.
- Strict optional profile suppresses district fields, uses broader age bands and longer date shifts.
  The measured strict-profile run retained 98.1% of clinical probes (before latest linkage update).
  Neither profile establishes formal anonymity; sparse cohort coverage requires review.

```powershell
$env:RAKSHA_SECRET = "practice"
python main.py --input Secret-Wards-ToolKit/dev/input --output output_final_run
python check_local.py --output output_final_run
python privacy_audit.py --output output_final_run
python -m unittest test_privacy test_hardening -v
python Secret-Wards-ToolKit/validate_output.py --input Secret-Wards-ToolKit/dev/input --output output_final_run
$env:PYTHONIOENCODING = "utf-8"
python Secret-Wards-ToolKit/check_submission.py --repo . --run
```

For a stricter release use `--policy config/strict_policy.yaml`. Always use an empty output directory.
Do not commit the toolkit, synthetic truth/attacker inputs, raw input, generated releases,
secrets or local environments. The .gitignore excludes these local assets.

## Release-candidate hardening

Latest verified local result: 193 files sanitized, 7 quarantined; 0/3230
known identifier findings, 0/4 canaries, 4855/4855 clinical probes, and
1.00/0.89/0.98 linkage precision/recall/F0.5. FHIR UUIDs are now re-keyed
per release while keeping internal references intact. Duplicate JSON keys
and nonfinite numeric constants are rejected. Multiple recognized JSON
record collections are handled, and more structured labels are supported.

Run the expanded independent synthetic fixture suite:

```powershell
pip install -r requirements-security.txt -r requirements-validation.txt
python -m unittest test_privacy test_hardening test_release -v
python check_local.py --output output_rc_v2
python privacy_audit.py --output output_rc_v2
```

The default aggregate audit found 93 registration rows, 9 missing one or
more audited fields, 57 distinct registration pseudonyms, and 49
pseudonyms with complete age/location fields in small cohorts. These are
aggregate indicators, not proof of anonymity. The stricter profile is
available when location suppression and broader age bands are appropriate.

Optional offline JSON Schema check (requires a self-contained official R4
schema supplied locally; not bundled or downloaded by the pipeline):

```powershell
python validate_fhir_schema.py --output output_rc_v2 --schema PATH_TO_LOCAL_SCHEMA
```

The local schema hook is tested with independent fixtures but the official
R4 schema itself is not available in this workspace; full standard and
profile conformance remain unverified. See SECURITY.md for deployment
controls and the separate authenticated encryption utility. The challenge
CLI has no dependency on those optional packages.
