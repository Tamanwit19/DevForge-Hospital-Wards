# Secret Wards — BrokenCode Privacy Firewall

An offline, CPU-only de-identification pipeline for the Secret Wards synthetic
hospital-record challenge. It parses supported files in memory, detects and
removes direct identifiers, links records conservatively, and exports sanitized
files with a report and record map. No hosted AI, network access, model
downloads, or organizer answer keys are used at runtime.

## Documentation

- [Project overview](docs/PROJECT_OVERVIEW.md): the idea, user flow and demo explanation.
- [Track 3 requirements](docs/TRACK_3_REQUIREMENTS.md): implementation, evidence and known gaps.
- [Codebase guide](docs/CODEBASE_EXPLAINED.md): modules, data flow, identity rules and tests.
- [Security checklist](docs/SECURITY.md): safe handling and deployment boundaries.

## Run (Windows PowerShell)

For local practice, clone the organizer toolkit into the ignored
`Secret-Wards-ToolKit` folder. Do not commit the toolkit clone, its practice
truth/attacker files or generated output:

```powershell
git clone https://github.com/Reinforce-SST/Secret-Wards-ToolKit.git .\Secret-Wards-ToolKit
```

The evaluator supplies its own input directory and `RAKSHA_SECRET`; the public
practice key below is only for synthetic local tests.

```powershell
python -m pip install -r requirements.txt
$env:RAKSHA_SECRET = "practice"
python main.py --input ".\Secret-Wards-ToolKit\dev\input" --output ".\out_test"
python ".\Secret-Wards-ToolKit\validate_output.py" --input ".\Secret-Wards-ToolKit\dev\input" --output ".\out_test"
python ".\check_local.py" --output ".\out_test"
```

Use a new, empty output folder each run. `check_local.py` is a Windows-only
diagnostic for verified CRLF-to-LF changes in the cloned practice data; it
adjusts a temporary truth copy and does not change inputs or the submission
pipeline. On this checkout it verified 172 such line-ending differences.
Running the original `check_dev.py` directly against this Windows clone can
mis-map renamed output files because the input hashes no longer match the
toolkit's stored truth hashes, which can skew its practice metrics. Use
`check_local.py` for the Windows practice score; it invokes the original checker
with only a temporary, hash-corrected truth copy. The official validator checks
output format. These local tools do not predict hidden-data performance or
change the judge's evaluation.

The evaluator provides `RAKSHA_SECRET` at runtime. Never commit it or use the
public practice value for real data. Real deployment requires a separately
managed high-entropy secret and encrypted storage; this competition prototype
does not provide a production healthcare guarantee.

## Pipeline

1. Enumerates input files deterministically and records their SHA-256 hashes.
2. Parses supported CSV, TSV, JSON, and text records in memory. Malformed or
   unsupported inputs are quarantined instead of copied through unchanged.
3. Detects identifiers using normalized field labels, contextual rules, and
   aliases found in the records. It does not consult the toolkit's truth or
   attacker data.
4. Links on explicit, non-conflicting identifiers or corroborated evidence.
   Name matching normalizes Latin/Devanagari forms; duplicate registrations can
   be reconciled with matching name, relative and DOB. Fragmented names require
   a matching relative, and age/location matches account for the dated age only
   when DOB supports it. Free-text phones require a matching name and age and a
   unique owner. Name-only matches are rejected. Patient pseudonyms use keyed
   HMAC-SHA256.
5. Redacts direct identifiers, generalizes age, shifts dates consistently for
   linked records, and suppresses district for sparse age-band/district groups.
6. Exports sanitized UTF-8 data, `report.json`, and `records.jsonl`. FHIR bundle
   UUIDs are re-keyed with references preserved; unsafe opaque attachments are
   removed. Full official FHIR R4/profile conformance is not claimed.

## Verified practice run

Latest local run on the toolkit's 200-file practice set (practice key):

| Check | Result |
|---|---:|
| Files sanitized / quarantined | 193 / 7 |
| Known identifiers detected by local practice checker | 0 / 3,230 leaked |
| Planted canaries found | 0 / 4 |
| Practice preservation probes | 4,746 / 4,855 (97.8%) |
| Linkage precision / recall / F0.5 | 1.00 / 0.83 / 0.96 |
| Wrongly merged practice patients | 0 |
| Submission-harness runtime | 9.5 s |
| Automated submission check | READY TO SUBMIT |
| Unit tests | 47 passed |

The preservation checker reports 109 values not found in its output; this is a
privacy/utility trade-off, not evidence that every clinical value is preserved.
The pipeline suppresses some quasi-identifiers in sparse groups. The
separate aggregate audit covered 93 registration rows but marked its risk
coverage `partial`: no unsuppressed age/location cohorts remained to measure.
Suppressed or missing values are not proof of low re-identification risk.
The toolkit's full attacker evaluator and hidden evaluation datasets are not
available in this checkout, so no official attack-resistance or hidden-data
score is claimed.

Reproduce the full local checks:

```powershell
$env:RAKSHA_SECRET = "practice"
$env:PYTHONIOENCODING = "utf-8"
python -m pip install -r requirements.txt
python main.py --input ".\Secret-Wards-ToolKit\dev\input" --output ".\out_check"
python ".\Secret-Wards-ToolKit\validate_output.py" --input ".\Secret-Wards-ToolKit\dev\input" --output ".\out_check"
python ".\check_local.py" --output ".\out_check"
python ".\privacy_audit.py" --output ".\out_check"
python -m unittest discover -v
python ".\Secret-Wards-ToolKit\check_submission.py" --repo . --run
```

`check_submission.py --run` also checks deterministic output for the same key,
keyed variation for a different key, secret non-disclosure, and input
immutability. Run offline before the event; the submission contract forbids
relying on network services.

## Security boundaries and limitations

Inputs are read-only by convention; raw intermediate records stay in process
memory and are not logged or written to quarantine. Encrypt input and output
volumes, restrict access, disable unencrypted swap, and store keys separately.
The optional `secure_archive.py` encrypts a reviewed release but does not encrypt
source data or remove the plaintext release.

This is a competition prototype, not an audited anonymization system. Detection
can miss unseen languages, formats, labels, or embedded payloads. Conservative
linkage can leave true records unlinked; fuzzy evidence is not a substitute for
manual review. Sparse groups are suppressed, which reduces some location
utility. The practice set is synthetic and cannot establish safety for real
patient data. The local aggregate diagnostic is not the organizer's full
re-identification attacker and does not prove anonymity. See the [security checklist](docs/SECURITY.md)
for operational safeguards.

Do not commit the toolkit's local synthetic truth/attacker assets, source data,
generated releases, secrets, or local environments. The challenge CLI has no
dependency on the optional archive or schema-validation packages.
