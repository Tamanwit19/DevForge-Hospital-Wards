# Track 3 requirements and evidence

This document summarizes the participant-facing requirements in the local
Secret Wards toolkit and maps them to this repository. It is a project status
guide, not a replacement for the organizer's statement, output contract or
scoring rules.

## Challenge in brief

Track 3 asks for an offline, CPU-only, LLM-free privacy firewall for synthetic
hospital exports. The inputs can mix English, Hindi and Hinglish; structured
tables and nested JSON; FHIR bundles; free-text notes; legacy encodings; and
identifiers in filenames, headers, keys or attachments.

The system must remove identity clues while preserving clinical facts, link the
same patient across records only when supported by evidence, avoid false merges,
manage quasi-identifiers, export a truthful report and record map, and fail
safely on data it cannot process. The attacker may combine released records
with known facts; simply replacing names is not enough.

The published scoring categories are:

| Category | Weight | What it is intended to measure |
|---|---:|---|
| Privacy against attacks | 25% | Whether an attacker can re-identify people from the release |
| Personal-data detection | 20% | Detection across scripts, contexts and hiding places |
| Clinical-data preservation | 20% | Retention of medicines, doses, diagnoses, vitals, labs and temporal facts |
| Patient identity consistency | 15% | Correct cross-record links without false merges |
| Output quality and validity | 10% | Format, reporting, quarantine and side-channel handling |
| Speed and reliability | 10% | Runtime, memory, repeatability and successful execution |

## Requirement-to-evidence map

| Requirement | Implementation | Evidence on this checkout | Status and caveat |
|---|---|---|---|
| Run offline without hosted AI or downloaded models | Local Python rules and dependencies; no model service is part of the run path | `requirements.txt`; submission harness passes | The evaluator still needs to run the submission in its own no-network sandbox |
| Parse heterogeneous records and encodings | CSV, TSV, JSON and text parser; UTF-8/BOM, UTF-16 and legacy decoding; strict parse checks | Practice set runs; malformed/unsupported items are quarantined | XML, PDF, images and other unsupported formats are not parsed |
| Find direct PII in English, Hindi and Hinglish | Field classification, contextual patterns, input-derived aliases and cross-script name normalization | 0 of 3,230 practice PII pieces found in output across the local check | Hidden names, labels and formats may differ; practice results do not prove complete recall |
| Keep clinical meaning | Context-aware sanitization aims to retain diagnoses, drugs, doses, vitals and lab values | 4,770 of 4,855 practice preservation probes retained (98.2%) | 85 probes were not found in output. Full clinical preservation is therefore not demonstrated |
| Link records for the same person | Explicit identifiers, unique contacts, matching names with relative/DOB/village-age evidence, and date-aware age checks | Practice precision 1.00, recall 1.00, F0.5 1.00; zero false practice merges | These are visible practice metrics only; hidden homonym and language traps remain untested |
| Protect against quasi-identifier attacks | Age bands, keyed date shifts, PIN reduction, sparse-cohort district suppression | Privacy audit reports aggregate counts without printing identities | Audit coverage is partial: 93 registration rows, 89 with district suppressed, 0 complete cohorts measured. This is not an attack score or proof of anonymity |
| Protect data and keys at rest | HMAC keys are read from the environment; an optional helper can encrypt a reviewed release archive | `crypto.py`, `secure_archive.py` and the [security checklist](SECURITY.md) | Partial: the pipeline does not encrypt source data or intermediate storage in place. Encrypted volumes, key management and access controls are deployment responsibilities |
| Export valid, auditable output | Sanitized UTF-8 files, file-hash report, record map, sensitive-path renaming and quarantine status | Toolkit validator reports `CONTRACT OK`; submission harness reports `READY TO SUBMIT` | The practice contract check does not validate every hidden schema or every side channel in the organizer's full environment |
| Preserve FHIR bundle structure | UUID re-keying, attachment cleanup and local-reference checks | Focused FHIR unit tests pass; bundles pass the local structural guard | The guard is not a full HL7 FHIR R4/profile validator; official schema validation is unavailable here |
| Demonstrate reliability and repeatability | Deterministic processing and keyed pseudonyms/date shifts | 41 tests pass; submission harness confirms same-key determinism, changed-key variation and input immutability | The harness is not a substitute for the official timed, memory-limited hidden-data run |
| Address fairness and subgroup risk | The project reports aggregate coverage and known limits | Privacy audit output is aggregate-only and explicitly reports partial coverage | No independent subgroup fairness certification or hidden-population risk study is available |

## What the practice results mean

The toolkit's local self-check is useful for finding regressions against its
public synthetic examples. `check_local.py` is needed on this Windows checkout
because it verifies and accounts for CRLF-only differences between the cloned
input and the toolkit's stored hashes. It adjusts a temporary truth copy and
does not change the organizer files or the submitted pipeline.

The local metrics must not be described as the official score. The official
attacker code and hidden datasets are intentionally not part of the participant
toolkit. Likewise, the organizer's fairness protocol describes how competition
scoring is intended to be impartial; it does not certify this project's
privacy or fairness.

## Remaining verification outside this repository

1. Run the frozen submission against the organizer's hidden datasets and full
   attacker/evaluator.
2. Validate every FHIR bundle against the official R4 schema and applicable
   profiles when those resources are available.
3. Review the privacy/utility trade-off behind the 85 missing practice probes
   before making any claim that all clinical facts are retained.
4. Reassess re-identification and subgroup risk with the complete evaluator and
   its population data; the current aggregate audit cannot measure suppressed
   or missing cohorts.

Until then, the defensible statement is: **the visible practice checks pass
with the results above; hidden-data privacy, full schema conformance and
production safety are not certified.**
