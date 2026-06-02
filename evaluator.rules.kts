// ORT Evaluator Policy Rules — OSSAPAC minimal starter
//
// This file is Kotlin DSL evaluated by ORT's Evaluator step.
// It receives the full dependency graph + scan results and emits Violations.
//
// Full API reference: https://oss-review-toolkit.org/docs/configuration/evaluator-rules
// Built-in rule helpers: https://github.com/oss-review-toolkit/ort/blob/main/evaluator/src/main/kotlin/RuleSet.kt
//
// ── How to add a rule ────────────────────────────────────────────────────────
// 1. Define a val block with `require { ... }` (preconditions) and
//    `error("msg") { ... }` / `warning("msg") { ... }` (findings).
// 2. Add the val to the ruleSet{} block at the bottom of the file.
// ─────────────────────────────────────────────────────────────────────────────

// License categories are defined in license-classifications.yml.
// Load them so rules can reference categories by name instead of raw SPDX IDs.
val permissiveLicenses = licenseClassifications.licensesByCategory["permissive"].orEmpty()
val copyleftLicenses   = licenseClassifications.licensesByCategory["copyleft"].orEmpty()
val strongCopyleft     = licenseClassifications.licensesByCategory["strong-copyleft"].orEmpty()

// ── Rule: flag strong-copyleft licenses (GPL, AGPL) ──────────────────────────
// These require source disclosure of the whole work when distributed.
// Change error → warning if you want non-blocking notifications instead.
val strongCopyleftRule by lazy {
    require {
        +isStatic()           // only direct/static dependencies (not dynamic plugins)
    }

    error("Strong copyleft license detected") {
        val violations = packages.filter { pkg ->
            pkg.concludedLicense?.licenses()?.any { it in strongCopyleft } == true ||
            pkg.declaredLicenses.any { it in strongCopyleft }
        }
        violations.forEach { pkg ->
            issue(
                Severity.ERROR,
                pkg.id,
                pkg.concludedLicense ?: LicenseView.ONLY_DECLARED,
                "Package ${pkg.id.toCoordinates()} uses a strong-copyleft license " +
                "(${pkg.concludedLicense?.licenses()?.first()}). " +
                "Verify this is permitted for your distribution model, or add a " +
                "resolution in ort-config/resolutions.yml if it is a false positive."
            )
        }
    }
}

// ── Rule: warn on copyleft (LGPL, MPL, EPL, etc.) ────────────────────────────
// Weak copyleft requires source disclosure only of the modified library files.
val weakCopyleftRule by lazy {
    warning("Weak copyleft license") {
        val found = packages.filter { pkg ->
            pkg.concludedLicense?.licenses()?.any { it in copyleftLicenses } == true
        }
        found.forEach { pkg ->
            issue(
                Severity.WARNING,
                pkg.id,
                pkg.concludedLicense ?: LicenseView.ONLY_DECLARED,
                "Package ${pkg.id.toCoordinates()} is under a weak-copyleft license. " +
                "Review licence obligations before distribution."
            )
        }
    }
}

// ── Rule: error on packages with no license information at all ────────────────
val noLicenseRule by lazy {
    error("No license information") {
        val unlicensed = packages.filter { pkg ->
            pkg.concludedLicense == null &&
            pkg.declaredLicenses.isEmpty() &&
            pkg.detectedLicenses.isEmpty()
        }
        unlicensed.forEach { pkg ->
            issue(
                Severity.ERROR,
                pkg.id,
                LicenseView.ONLY_DECLARED,
                "Package ${pkg.id.toCoordinates()} has no license information. " +
                "Add a curation in ort-config/curations/ to supply the correct license."
            )
        }
    }
}

// ── Rule: error on packages with known critical vulnerabilities ───────────────
val criticalVulnRule by lazy {
    error("Critical vulnerability") {
        ortResult.getAdvisorResults()
            .flatMap { it.value }
            .filter { it.vulnerabilities.any { v -> (v.cvssScore ?: 0.0f) >= 9.0f } }
            .forEach { result ->
                result.vulnerabilities
                    .filter { v -> (v.cvssScore ?: 0.0f) >= 9.0f }
                    .forEach { vuln ->
                        issue(
                            Severity.ERROR,
                            result.id,
                            LicenseView.ONLY_DECLARED,
                            "Critical vulnerability ${vuln.id} (CVSS ${vuln.cvssScore}) " +
                            "in ${result.id.toCoordinates()}."
                        )
                    }
            }
    }
}

// ── Register all rules ────────────────────────────────────────────────────────
ruleSet(ortResult, licenseClassifications) {
    packageRule("STRONG_COPYLEFT") { strongCopyleftRule }
    packageRule("WEAK_COPYLEFT")   { weakCopyleftRule }
    packageRule("NO_LICENSE")      { noLicenseRule }
    packageRule("CRITICAL_VULN")   { criticalVulnRule }
}
