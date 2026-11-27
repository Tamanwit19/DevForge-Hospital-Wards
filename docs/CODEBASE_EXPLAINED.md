# Codebase explained

This is the engineering guide to BrokenCode's Track 3 implementation. For a
non-technical introduction, start with the [project overview](PROJECT_OVERVIEW.md).
For the challenge criteria and a candid completion map, see
[Track 3 requirements](TRACK_3_REQUIREMENTS.md).

## 1. Repository layout

```text
DevForge-Hospital-Wards/
  main.py                       CLI and end-to-end pipeline
  ingest.py                     deterministic file discovery and decoding
  privacy.py                    PII evidence, classification and sanitization
  identity_normalization.py     English/Devanagari name normalization
  linkage.py                    internal patient identity resolution
  crypto.py                     keyed pseudonyms, tokens and date shifts
  fhir_guard.py                 FHIR bundle cleanup and structural checks
  privacy_audit.py              aggregate-only release diagnostic
  validate_fhir_schema.py       optional local schema validation
  secure_archive.py             optional authenticated archive utility
  check_local.py                Windows practice-check hash normalization
  config/
    policy.yaml                 default runtime policy
    strict_policy.yaml          optional stricter policy
  tests:
    test_privacy.py
    test_hardening.py
    test_release.py
  requirements*.txt            runtime and optional dependencies
  raksha.toml                   evaluator setup/run contract
  README.md                     quick start and measured results
  Project_Brief.pdf             two-page submission brief
  docs/                         project and security documentation
```

The organizer's `Secret-Wards-ToolKit` clone and local output folders are
ignored by Git. The toolkit is for local practice and validation; it is not a
runtime dependency of `main.py` and should not be committed with this project.

## 2. Run contract and dependencies

`raksha.toml` declares the team name, setup command and evaluator entry point:

```toml
setup = "pip install -r requirements.txt"
run   = "python main.py --input {input} --output {output}"
```

The evaluator supplies the input/output paths and `RAKSHA_SECRET`. For local
practice, use a throwaway key and a new empty output directory:

```powershell
python -m pip install -r requirements.txt
$env:RAKSHA_SECRET = "practice"
python main.py --input ".\Secret-Wards-ToolKit\dev\input" --output ".\out_demo"
```

The runtime dependencies are PyYAML, psutil and `indic-transliteration`.
`requirements-security.txt` and `requirements-validation.txt` are optional:
they support the archive helper and local JSON Schema validator, respectively.
They are not needed by the challenge run command.

## 3. End-to-end data flow

### Phase A: validate the run

`main()` in [main.py](../main.py) requires `RAKSHA_SECRET`, an existing input
directory, and an empty output directory separate from the input. It loads the
default `config/policy.yaml` unless `--policy` supplies another file. Missing,
unreadable or invalid policy configuration stops the run explicitly.

### Phase B: discover and parse

[ingest.py](../ingest.py) sorts directory and file names for deterministic
processing and hashes the original file bytes. `main.parse()` accepts CSV,
TSV, JSON and text-like files (`.txt`, `.md`, `.note`). It handles UTF-8,
UTF-8 BOM, UTF-16, cp1252 and Latin-1 decoding. Duplicate JSON object keys,
non-finite JSON numbers, malformed tables, empty files, oversized files and
unsupported extensions are rejected.

The parser splits tabular rows and recognized JSON collections into logical
units. A CSV/TSV row uses `row:N`, a JSON collection item uses a JSON pointer,
and a whole text file, FHIR Bundle or unrecognized JSON document uses `doc`.
Rejected files are listed in `report.json` with a null output and a reason;
their raw bytes are not copied into `sanitized/`.

### Phase C: collect internal evidence

The pipeline scans registration records and supported records before writing
the release. It collects direct hospital IDs and keyed contact clues, plus
identity features that can corroborate names. It does not read `truth.json`,
attacker registries, hidden answers or external population databases.

[identity_normalization.py](../identity_normalization.py) normalizes name
tokens, transliterates Devanagari through IAST, folds common spelling variants,
and removes honorifics from matching clues. The original source values are
still handled by the sanitizer; normalized tokens are for internal matching.

### Phase D: resolve patient consistency

`InternalLinks` in [linkage.py](../linkage.py) applies evidence from strongest
to weaker:

1. A single explicit patient identifier identifies its registration cluster.
   Encounter identifiers can map to a patient when that mapping is unique.
2. A direct contact identifier may link a record only when it has one owner.
3. Duplicate registration IDs may be reconciled by an unmasked full Aadhaar
   match, or by matching name, relative and DOB evidence.
4. Records without a strong ID can use a unique name-plus-relative clue,
   name-plus-DOB clue, or name-plus-village-and-age clue. A dated record may
   compare its stated age with age computed from a candidate DOB on that event
   date.
5. A phone found only in free text requires a matching name and a uniquely
   identified owner; age is a further check when available.

Name-only evidence is not sufficient. Conflicting or ambiguous candidates
remain unlinked instead of being forced into a cluster. Pseudonyms are HMAC
outputs from [crypto.py](../crypto.py); a different secret creates a different
release namespace. Before a patient is written to `records.jsonl`, the pipeline
checks that the pseudonym is actually present in the sanitized record.

### Phase E: sanitize and generalize

[privacy.py](../privacy.py) classifies keys and values, detects common Indian
IDs and phone forms, uses labels and context for free text, and applies aliases
learned from records. Sensitive identifiers are replaced or redacted. Medical
values such as blood pressure, doses and lab measurements should remain intact
unless a contextual rule identifies the value itself as private.

The default [policy](../config/policy.yaml) uses five-year age bands, a 90+
top-code, date shifts up to 180 days, district-level location handling, a
minimum rare-value threshold of five and a 20 MB file limit. Sparse or unlinked
records receive stricter quasi-identifier suppression. The optional
[strict policy](../config/strict_policy.yaml) is more restrictive and can
reduce utility.

Dates are shifted by a stable patient-specific offset, preserving intervals
within a patient's linked records. Records without a resolved patient use a
file-specific keyed fallback, so they do not falsely share another patient's
date offset.

### Phase F: export and report

Processed files are written as UTF-8 under `sanitized/`; sensitive path
components are renamed and mapped through the input hash in `report.json`.
CSV headers containing PII are renamed. The report lists each input hash,
output path or quarantine status, processing counts, timing and memory.
`records.jsonl` maps each exported logical record to a pseudonym or `null`.

For FHIR Bundles, [fhir_guard.py](../fhir_guard.py) removes unsafe opaque
attachment content, re-keys declared UUIDs consistently, and checks selected
resource IDs, attachment encoding and local references. These checks are
structural safeguards, **not** complete HL7 FHIR R4 or profile validation.

## 4. Module guide

| File | Responsibility |
|---|---|
| [main.py](../main.py) | CLI, policy loading, parsing orchestration, sanitization and output files |
| [ingest.py](../ingest.py) | Stable traversal, hashing and byte decoding |
| [privacy.py](../privacy.py) | Key classification, evidence extraction, PII removal and generalization |
| [identity_normalization.py](../identity_normalization.py) | Cross-script canonical name tokens |
| [linkage.py](../linkage.py) | Patient/encounter/contact maps and conservative identity resolution |
| [crypto.py](../crypto.py) | HMAC pseudonyms, internal tokens, date shifts and resource UUIDs |
| [fhir_guard.py](../fhir_guard.py) | Attachment cleanup, UUID remapping and Bundle structural checks |
| [privacy_audit.py](../privacy_audit.py) | Aggregate counts and coverage status without printing identity values |
| [validate_fhir_schema.py](../validate_fhir_schema.py) | Optional validation against a supplied local JSON Schema |
| [secure_archive.py](../secure_archive.py) | Optional encrypted packaging of an already-reviewed release |
| [check_local.py](../check_local.py) | Windows-only correction for verified CRLF-only practice hash drift |

## 5. How the tests fit

| Test file | Main coverage |
|---|---|
| [test_privacy.py](../test_privacy.py) | Structured and contextual sanitization, clinical values, date shifts and keyed identity |
| [test_hardening.py](../test_hardening.py) | Conflicts, duplicate registrations, cross-script/fragmented linkage, parser failures and FHIR guards |
| [test_release.py](../test_release.py) | Unseen structured fields, JSON integrity, FHIR UUIDs, optional schema, archive and aggregate audit |

Run the complete suite after installing optional test dependencies:

```powershell
python -m pip install -r requirements.txt -r requirements-security.txt -r requirements-validation.txt
python -m unittest discover -v
```

The focused runtime tests can be run with only `requirements.txt`:

```powershell
python -m unittest test_privacy test_hardening -v
```

## 6. Reproducing the practice checks

With the toolkit cloned into the ignored `Secret-Wards-ToolKit` folder:

```powershell
$env:RAKSHA_SECRET = "practice"
python main.py --input ".\Secret-Wards-ToolKit\dev\input" --output ".\out_check"
python ".\Secret-Wards-ToolKit\validate_output.py" --input ".\Secret-Wards-ToolKit\dev\input" --output ".\out_check"
python ".\check_local.py" --output ".\out_check"
python ".\privacy_audit.py" --output ".\out_check"
$env:PYTHONIOENCODING = "utf-8"
python ".\Secret-Wards-ToolKit\check_submission.py" --repo . --run
```

Use a fresh output directory for each run. On this Windows checkout,
`check_local.py` verifies CRLF-only hash differences, prepares a temporary
truth copy for the local practice checker, and removes it. It is not called by
the challenge pipeline. Do not treat it as the official hidden-data evaluator.

## 7. Current measured state and limits

The latest visible practice run processed 200 files: 193 sanitized and 7
quarantined. The local checker found 0 of 3,230 known PII pieces and 0 of 4
canaries, retained 4,746 of 4,855 preservation probes, and measured linkage
precision/recall/F0.5 of 1.00/0.83/0.96 with zero false merges. The regression
suite has 47 passing tests, and the toolkit submission harness reports
`READY TO SUBMIT`.

The 109 missing preservation probes are a real utility gap. The aggregate audit
examined 93 registration rows but found no complete age/location cohorts, so
its coverage is partial and it cannot establish anonymity. The full attacker,
hidden data and official FHIR R4 schema are not present in the local toolkit.
These practice results are not an official score or a production safety
certification.
