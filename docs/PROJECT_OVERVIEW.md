# Project overview

## In one sentence

**BrokenCode built an offline privacy firewall that removes patient identifiers
from mixed-format hospital records, preserves useful clinical information, and
links records with stable pseudonyms only when the evidence is strong enough.**

## The idea, in plain language

A hospital may need to share records for research, but names are not the only
way to identify a patient. A record can still point to someone through a phone
number, hospital ID, exact date, small village, rare diagnosis, filename, JSON
key, or attachment. At the same time, deleting every number would damage useful
facts such as blood pressure, lab results and medicine doses.

This project therefore tries to do two things at once:

1. Remove or generalize information that can identify a patient.
2. Keep the clinical facts that make the record useful for research.

When multiple records contain enough matching evidence, the pipeline replaces
the original identity with a keyed pseudonym such as `PSN-ABCDEFGH`. The
pseudonym is consistent for records linked within a release. It is not
reversible encryption, and it does not by itself make a record anonymous.

## A simple example

The following is fictional and illustrative, not a byte-for-byte output
example:

```text
Patient Name: Example Person
UHID: UHID-123456
Age: 47
Phone: 9876543210
BP: 120/80
Medicine: Paracetamol 650 mg
```

The release might keep the blood pressure and medicine, generalize the age,
remove the phone number, and replace the name and hospital ID with the same
patient pseudonym. The actual choice depends on the available evidence and the
configured privacy policy.

## What Track 3 asks teams to solve

The challenge is more than name removal. The system must work offline without
hosted AI, deal with English, Hindi and Hinglish, preserve clinical meaning,
avoid linking two different people, protect against an attacker who combines
quasi-identifiers, and produce a valid, auditable release. See the
[requirement-by-requirement map](TRACK_3_REQUIREMENTS.md) for what is measured
and what remains unverified.

## What happens during a run

1. The program walks the input tree in a stable order and hashes every file.
2. Supported CSV, TSV, JSON and text files are decoded and parsed. Invalid or
   unsupported files are reported as quarantined rather than copied through.
3. The program collects identity clues from the input itself; it does not read
   the toolkit's answer key or attacker files.
4. It resolves a patient pseudonym only when identifiers or corroborating clues
   support the association.
5. It sanitizes values, generalizes demographics, shifts dates consistently
   for linked patients, and applies additional FHIR bundle safeguards.
6. It writes the cleaned files, `report.json`, and `records.jsonl`.

The detailed module and data-flow guide is
[Codebase explained](CODEBASE_EXPLAINED.md).

## Local practice results

The latest checked run used the toolkit's 200-file synthetic practice dataset:

| Practice check | Result |
|---|---:|
| Sanitized / quarantined files | 193 / 7 |
| Known PII found by the practice checker | 0 / 3,230 |
| Planted canaries found | 0 / 4 |
| Practice preservation probes retained | 4,746 / 4,855 (97.8%) |
| Linkage precision / recall / F0.5 | 1.00 / 0.83 / 0.96 |
| False practice merges | 0 |
| Regression tests | 47 passed |
| Toolkit submission harness | READY TO SUBMIT |

These are practice-set results, not an official hidden-data score. The
preservation check still misses 109 probes. The separate aggregate audit has
partial coverage because suppressed or missing values leave no complete
age/location cohorts to measure. A zero practice leak count and a perfect
practice linkage score do not prove that unseen data is safe.

## What we can and cannot claim

We can show that the visible toolkit validator, practice checker, regression
suite and submission harness pass on this checkout. We cannot claim a perfect
official score: the hidden evaluator and datasets are not included. Full FHIR R4
and profile conformance was also not verified against an official schema.

This is a hackathon prototype for synthetic data, not a certified
anonymization product. Do not use it to release real patient data.
