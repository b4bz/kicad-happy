# b4bz local hardening fork

This fork preserves the MIT-licensed upstream code and credits. Baseline:
`aklofas/kicad-happy` commit `06840467ad0f5d76af45f64449b1f5ecb10f052f`
(upstream v2.3.1). These changes are an additive local patch, not an upstream
release or a claim of production certification.

## Security changes

All three former shared temporary-file OAuth cache consumers (lifecycle audit,
SPICE spec fetching, and DigiKey datasheet fetching) use one stdlib-only helper.
It reuses tokens only in process memory, binds reuse to both credentials, limits
the response size, refreshes before expiry, and prints no sensitive responses.
It never opens, migrates, modifies or deletes legacy token-cache files. Processes
authenticate separately; repeated requests within one process can reuse a token.
No real API credentials were used to test these changes.

## Fabrication gate changes

The gate validates the fields it consumes rather than treating absent fields as
successful checks. Gerber completeness uses the current analyzer fields and
explicit drill/layer completeness. EMC uses current severity counts/findings.
Unknown DFM assessments, missing/malformed inputs, skipped analysis, and unresolved
evidence blockers prevent PASS. Known analyzer errors block release; warnings
require review. The gate's terminal status is FAIL before INCOMPLETE before WARN
before PASS. `--strict` promotes warnings to failures, without permitting skips.

Exit codes: **0 PASS, 1 FAIL, 2 INCOMPLETE/input error, 3 WARN**. This deliberately
changes the old always-zero exit behavior. Consumers must handle these codes and
must never submit a design when the command returns nonzero. All five inputs
(schematic, PCB, Gerber, thermal, EMC analyzer JSON) are needed for a passing
analyzer verdict. There is no automatic waiver for omitted checks.

PASS is an analyzer verdict only. Native ERC/DRC, fresh source/export identity,
current manufacturer process rules, real CAM/drill inspection, per-component
assembly orientation, and human engineering release review are still required.
The package does not order boards. Upload, order, payment, and publication require
explicit user authorization. Read-only reviews should use isolated copies because
enrichment scripts can modify schematic properties and prune old cache outputs.

The JLCPCB skill no longer recommends blanket package-family rotation offsets.
Each exact component, footprint, side, pin 1, and polarity needs verification.

## Verification

- 22 offline hardening tests: memory-only credentials, account/secret rotation,
  expiry, failed/malformed API responses, legacy symlinks, all three consumers,
  incomplete/malformed release data, current Gerber/EMC fields, analyzer errors,
  unknown severities, strict mode, and CLI exit codes.
- 566 upstream smoke tests passed at harness commit
  `8bae5a0c5a74d2d41366f0a9ee4f9cfa12b2a043`.
- Two upstream smoke assertions previously demanded exit 0 for incomplete inputs.
  `.github/scripts/adapt_fab_gate_harness.py` updates only those two assertions in
  a temporary harness checkout, requires exit 2 and an INCOMPLETE verdict, and
  rejects unexpected source changes. No tests are disabled. The same adapter and
  12 downstream tests were checked at CI's pinned `fc7a074fc7e` revision.
- Existing 21 LCSC tests, datasheet v1.4 round-trip smoke, all skill metadata checks,
  Python compile checks, and seven primary CLI help checks passed.

The full corpus and hardware/manufacturing validation were not run. This work does
not certify any existing PCB, simulation model, regulatory claim, or supplier rule.

Run local regressions:

```bash
python3 -m unittest discover -s tests -v
python3 .github/scripts/check_skill_metadata.py
```

## Pinned local installation

Install all eleven skills together from an exact commit of this fork using Codex's
skill installer. `kicad`, `digikey`, and `spice` must stay together because they
share the auth helper. Avoid unreviewed upstream replacement or automatic updates.
Record the installed source commit and per-file SHA-256 values locally; verify
the installed files against that commit before use after any update.

The installation uses Python stdlib analysis and creates no network service,
startup task, or scheduled job. Distributor access remains optional and uses the
existing environment variables when explicitly needed. No API keys, simulator,
KiCad application, browser profile, or manufacturer account is configured here.

Rollback: remove only the eleven skill directories installed by this fork (or
restore any separately preserved prior versions). Preserve the checkout and
local installation manifest if you want to reproduce the patched version later.
