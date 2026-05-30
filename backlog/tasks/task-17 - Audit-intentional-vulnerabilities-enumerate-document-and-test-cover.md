---
id: TASK-17
title: 'Audit intentional vulnerabilities: enumerate, document, and test-cover'
status: To Do
assignee: []
created_date: '2026-04-30 10:33'
updated_date: '2026-04-30 10:38'
labels:
  - security
  - docs
  - tests
  - audit
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
## Why

Quick scan of the codebase turned up significant gaps between the intentional vulnerabilities the project claims to ship, what's actually wired up in code, what's documented, and what's covered by tests:

| Source | Count | Notes |
|--------|-------|-------|
| `app/utils/vuln_registry.py` (`VULN_REGISTRY`) | 58 entries | Structured: owasp/cwe/severity/portal/config_key. Used by `@hotpatch` decorator. |
| `docs/vulnerability-inventory.md` claim | "200+ intentional vulnerabilities" | Marketing copy across README/inventory; 142 vulns unaccounted for vs registry. |
| Tests with `@pytest.mark.vulnerability` | 1 file | ~57 registered vulns have no asserted-vulnerable test. |
| `tests/vulnerability/`, `tests/smoke/` | Don't exist | Both directories referenced in docs/AGENTS.md but absent on disk. |

Either the codebase has more vulnerabilities than the registry knows about (so `@hotpatch` cannot hot-toggle them and TASK-9's Defensive Layers panel is structurally incomplete), or the marketing copy is inflated. Both cases need fixing. This audit disambiguates.

## Phase 1 — Source-of-truth enumeration

Sweep the full codebase for every actual intentional vulnerability:
- `# VULNERABLE`, `# VULN`, `# INTENTIONAL` comment markers
- Raw f-string SQL (`f"SELECT … {request.…}"`)
- `@hotpatch(...)` decorator usage
- `os.system` / `subprocess.run` with user input (command injection)
- `eval` / `exec` / `pickle.loads` (deserialization / code injection)
- Plaintext credentials, weak hashing (md5/sha1), predictable tokens
- XML parsers without `defusedxml` (XXE)
- `urllib`/`requests` calls with user-controlled URLs (SSRF)
- Hardcoded secrets

Produce a flat list `(file:line, vuln_kind, endpoint or context)` and cross-reference against `VULN_REGISTRY`. Output:
- **In code, not in registry** — registry incomplete
- **In registry, not in code** — registry stale (vuln removed but entry kept)
- **In both** — already accounted for

## Phase 2 — Registry ↔ docs reconciliation

Use `doc-completeness-audit` skill to compare `VULN_REGISTRY` against `docs/vulnerability-inventory.md`. Report:
- Missing CHM-IDs in inventory doc
- Inconsistent counts ("200+" vs registry size vs source-found vs docs)
- Stale endpoint references in either side
- Severity / OWASP / CWE mismatches between registry and doc

## Phase 3 — Test-coverage audit

For every registry entry, check whether a test asserts the vulnerability is *exploitable* (not merely "endpoint returns 200"). Build a coverage matrix: registered vulns × tests. Flag entries with no asserted-vulnerable test.

Recommended test shape:
```python
@pytest.mark.vulnerability("CHM-BANK-001")
def test_negative_transfer_amount_accepted(client):
    response = client.post("/api/v1/banking/transfer", json={"amount": -500})
    assert response.status_code == 200    # vulnerability: should be 400
    assert response.json()["status"] == "completed"
```

Adding the CHM-ID as a marker argument lets registry and tests cross-reference at runtime — a meta-test can iterate the registry and assert each declared vulnerability's existence, turning future drift into CI failure instead of doc nuisance.

## Phase 4 — Remediation plan

- Fix any registry/code drift found in Phase 1 (file Backlog tasks per gap; bulk-fix trivial cases inline).
- Update `docs/vulnerability-inventory.md` to either match the registry or honestly document the discrepancy.
- Decide whether `tests/vulnerability/` and `tests/smoke/` should be created (and remove the stale doc references if not).
- Pick a tier of vulns to add coverage for — start with the **critical** and **high**-severity registry entries. The `config_key` field distinguishes "toggle-able" vulns (wired into `@hotpatch` + `security_config`) from "permanently exploitable" — both need tests but only the toggle-able ones need a "secure mode also rejects this" pair.

## Constraints

- **Vulnerabilities must remain exploitable.** This is a deliberately vulnerable application; the audit aims to verify, document, and test that the intended attack surface is intact — not to fix any of it.
- The `@hotpatch` decorator is the supported path for runtime toggling. Phase 4's "config_key": None entries cannot be toggled — flag them if a future requirement needs runtime gating.

## Dependencies

- None gating; can start immediately. TASK-9 (Defensive Layers Control Panel) and TASK-2 (Hot-Patching Route Mechanism) both consume the registry, so closing the registry-vs-code gap unblocks more accurate UX for them.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 #1 Phase 1 enumeration produces a structured report comparing source-found vulns to VULN_REGISTRY entries
- [ ] #2 #2 Phase 2 reconciliation closes drift between VULN_REGISTRY and docs/vulnerability-inventory.md
- [ ] #3 #3 Phase 3 produces a coverage matrix of registered vulns × tests with severity-tagged gaps
- [ ] #4 #4 Phase 4 remediation plan filed (either inline fixes or follow-up Backlog tasks per finding)
- [ ] #5 #5 docs/vulnerability-inventory.md final count agrees with VULN_REGISTRY size to within ±5
- [ ] #6 #6 Every critical and high severity registry entry has at least one @pytest.mark.vulnerability test asserting exploitability
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## Phase 1 — Source-of-truth enumeration (complete)

### Verified counts

| Source | Verified count | Method |
|---|---|---|
| `VULN_REGISTRY` entries | **29** (NOT 58 as initial scan suggested) | regex parse of `app/utils/vuln_registry.py`, validated by counting `"CHM-...":` keys |
| Routes in code | **493** | regex sweep of `@*_router.route(...)` across `app/blueprints/*/routes.py` |
| `@hotpatch` decorations (actual call sites) | **2** | `grep -rn '@hotpatch' app/` returns 4 hits; 2 are docstring references — only 2 real decorations, both in `banking/routes.py:41,106`, both `@hotpatch('bola')` |
| Explicit `# VULNERABLE` / `# VULN` / `# INTENTIONAL` comment markers | **~25** across 9 files | strict grep across all blueprints |
| Implicit vulnerabilities (md5/sha1, weak tokens, missing auth, etc.) | **40+** | from sub-agent enumeration |
| Docs claim | "200+" intentional vulnerabilities | `docs/vulnerability-inventory.md`, `README.md`, etc. |

### Drift analysis (registry ↔ code)

#### Direction A: registry → code (small drift)
27 of 29 registry entries have a matching route in code. The 2 stale entries:
- `CHM-BANK-001` — `POST /api/v1/banking/transfer` (Business Logic Manipulation). Endpoint does not exist in `app/blueprints/banking/routes.py`. Either the registry described a planned endpoint that was never built, or the route was removed without updating the registry.
- `CHM-SAAS-002` — `PUT /api/v1/saas/tenants/{tenant_id}` (Mass Assignment). The closest live route is `PUT /api/v1/saas/tenants/<tenant_id>/settings`. Either the registry endpoint string is stale or the live route does not implement the registered vuln.

#### Direction B: code → registry (large drift)
The codebase contains far more intentional vulnerabilities than the registry knows about. Categories the registry does NOT track:

- **MD5 / SHA1 password hashing** (auth/routes.py + several others) — registry has no `weak-crypto` entries
- **JWT `none` algorithm acceptance** (auth/routes.py:78) — registry has no `jwt-confusion` entries
- **Predictable tokens** (`hashlib.md5(str(time.time())...)`) — auth/routes.py
- **Command injection via `shell=True`** — diagnostics/routes.py (per agent: 2 sites)
- **`eval` / `pickle.loads` on user input** — testing/routes.py
- **SSRF** in genai (URL fetching), integrations (webhook proxy), diagnostics — registry has 3 `ssrf_protection` entries but the agent found more code sites
- **PHI / PII overexposure** in `to_dict()` — `Patient.to_dict()` returns SSN, `User.to_dict()` returns role; registry has 1 `CHM-HEALTH-003` entry but pattern is repeated across ~11 files
- **8 SQLi endpoints in `database_vulnerable/routes.py`** — none registered with a CHM-ID despite being the most blatant injections in the repo
- **Missing-authorization endpoints** in admin/, loyalty/, government/ — agent counted ~8 privilege-escalation paths; registry has only `CHM-LOYAL-002`

### `@hotpatch` coverage gap

The decorator is the supported mechanism for runtime-toggling vulnerabilities (the foundation TASK-9's Defensive Layers Control Panel depends on). Today:

- **2 real `@hotpatch(...)` call sites** in the entire codebase, both in `banking/routes.py`, both `@hotpatch('bola')` (no `vuln_id` argument)
- Effectively **1 toggle-able config_key wired up** (`bola_protection` for banking accounts)
- The other 27 registry entries with `config_key != None` (`sqli_protection`, `xss_protection`, `ssrf_protection`, etc.) cannot be toggled at runtime — the `security_config` keys exist but no route reads them

### `config_key` distribution (registry)
- `None` (always vulnerable, no toggle): 13/29
- `bola_protection`: 8 (only 2 actually wired via `@hotpatch`)
- `sqli_protection`: 4 (0 wired)
- `ssrf_protection`: 3 (0 wired)
- `xss_protection`: 1 (0 wired)

### Files with most explicit vuln markers (top 10)
- `database_vulnerable/routes.py` — 9 (entire file is intentional SQLi; no CHM-IDs)
- `admin/routes.py` — 4
- `auth/routes.py` — 3
- `integrations/routes.py` — 3
- `healthcare/routes.py` — 2
- `testing/routes.py` — 2
- `payments/routes.py` — 1
- `diagnostics/routes.py` — 1
- `banking/routes.py` — 1
- `insurance/routes.py` — 1 (f-string SQL only, no comment)

### Highest-risk blueprints (per agent qualitative assessment)
1. `database_vulnerable` — 8/8 endpoints intentionally SQLi
2. `payments` — 13+ findings (PCI exposure, logic flaws, info leak)
3. `auth` — 10 findings (OAuth/SAML bypass, user enumeration, weak tokens, JWT confusion)
4. `loyalty` — 8 findings (privilege escalation, audit tampering, PII export)
5. `diagnostics` — 2 critical (command injection + SSRF)

### Headline conclusions

1. **Docs over-claim.** "200+ intentional vulnerabilities" is marketing copy. Realistic count of distinct intentional vulns: ~50–80 if we include implicit ones, only **29 formally registered** with CHM-IDs.
2. **Registry under-covers.** The structured catalog misses entire vulnerability classes that exist in the code (weak-crypto, JWT confusion, command-injection, deserialization).
3. **`@hotpatch` is mostly unused.** Only 1 of the 5 declared `config_key` toggle types is actually wired into a route. TASK-9's Defensive Layers panel, if built today, would have one working toggle and 28 dead checkboxes.
4. **2 stale registry entries** (`CHM-BANK-001`, `CHM-SAAS-002`) describe endpoints that don't exist.
5. **`database_vulnerable` blueprint has zero CHM-IDs** despite being the most explicitly vulnerable file in the repo. Should get 8 entries (one per SQLi technique).

### Phase 2 pre-requisites

- Reconciliation must decide direction-of-truth: bring registry up to source reality (~50+ new entries) or trim docs to match registry (29 entries). The right answer is probably **expand the registry** — the docs already promise the larger number.
- New CHM-ID conventions needed: `CHM-DBVULN-001..008` for `database_vulnerable`, `CHM-AUTH-XXX` for the JWT/MD5/timing issues in auth, `CHM-DIAG-XXX` for the diagnostics RCE/SSRF, etc.
- Decide whether the existing `@hotpatch` should be retroactively applied to all registered vulns (large code change) or whether new toggle-able vulns get `@hotpatch` going forward (incremental). Either way, the gap should be flagged on TASK-9 so the dashboard reflects reality.

### Data files / artifacts
None saved to disk. All findings derived from greps + the sub-agent's report.
<!-- SECTION:NOTES:END -->
