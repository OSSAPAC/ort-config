# ort-config — OSSAPAC policy repository

This directory becomes the `OSSAPAC/ort-config` GitHub repository.
ORT clones it at scan time via the `ort-config-repository` workflow input.

---

## File map

| File/Dir | ORT step that reads it | Purpose |
|---|---|---|
| `config.yml` | All steps | Global ORT settings (advisor, scanner storage, auth) |
| `license-classifications.yml` | Evaluator | Groups SPDX IDs into named categories used by `evaluator.rules.kts` |
| `evaluator.rules.kts` | Evaluator | Kotlin DSL policy — defines which license / vulnerability findings become violations |
| `curations/` | Analyzer (post-processing) | Corrects wrong/missing metadata for specific packages |

---

## How to add a package curation

A curation overrides the metadata ORT read from a package's published manifest.
Use it when a package declares the wrong license, or declares none at all.

**Step 1 — identify the ORT package identifier**

Run a scan and look for the package in `analyzer-result.yml`:

```yaml
- id: "NPM::some-package:1.2.3"
  declaredLicenses: []     # ← empty or wrong
```

The identifier format is `type:namespace:name:version`.
Namespace is empty for npm; it's the group ID for Maven.

**Step 2 — create or append a curations file**

Add a file under `curations/` (one file per ecosystem keeps things tidy):

```yaml
# curations/npm.yml
- id: "NPM::some-package:1.2.3"
  curations:
    comment: "No license in package.json; MIT confirmed at https://github.com/..."
    declared_licenses:
      - "MIT"
```

**Step 3 — verify**

Re-run the workflow. The Analyzer output will show the curated license,
and the Evaluator will no longer raise a `NO_LICENSE` violation for this package.

---

## How to add or modify a policy rule

All rules live in `evaluator.rules.kts`.

1. Define a `val myRule by lazy { ... }` block.
2. Use `error(...)` for hard failures (blocks CI when `fail-on: violations`).
3. Use `warning(...)` for advisory findings that never block CI.
4. Register it in the `ruleSet { ... }` block at the bottom of the file.

To promote a warning to an error (or vice versa), change the severity inside
the relevant `issue(Severity.WARNING, ...)` call.

---

## How to suppress a specific known violation

When a finding is a known false positive or an accepted risk, add a resolution
to a `resolutions.yml` file (create it at the root of this repo):

```yaml
# resolutions.yml
resolutions:
  ruleViolations:
    - message: "Strong copyleft license detected"
      reason: "PATENT_GRANT_EXCEPTION"
      comment: "GPL component is a dev-only tool, never distributed."
```

ORT will mark the violation as resolved and it will no longer count toward
`fail-on: violations`.
