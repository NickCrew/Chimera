---
id: TASK-17
title: 'Docs: Fix doc-claim drift detected on 2026-07-06'
status: To Do
assignee: []
created_date: '2026-07-06 00:00'
updated_date: '2026-07-06 00:00'
labels:
  - docs
dependencies: []
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Automated drift audit of the 12-file active doc set run on 2026-07-06. 16 concrete claims were found to diverge from the current codebase. 12 are P1 (dev-doc errors that would mislead a contributor or break a copy-pasted command); 4 are P2 (minor staleness).

Findings are grouped by file. Each entry is:
`path:line — \`exact quote or paraphrase\` — claim — proposed fix`

### docs/architecture.md

- `docs/architecture.md:165` — `| \`DEMO_MODE\` | \`true\` | ...` — Default column says `true`; actual runtime default in `app/config.py` (line 31) is `'full'`, and in `apps/vuln-api/security.py` (line 14) is `'strict'`. Either is defensible, but `true` is not a valid value and is definitely wrong. **P1** — Update default to `full` (aligning with config.py) or `strict` (aligning with security.py); document the split.
- `docs/architecture.md:87-115` — Blueprint directory listing ends with `database_vulnerable/` — `app/blueprints/education/` exists in the codebase and is imported by `app/asgi.py` (line 185: `from app.blueprints.education import education_router`) but is absent from the listing. **P1** — Add `education/` with a route count.
- `docs/architecture.md:155` — `| \`/swagger\`, \`/openapi.yaml\` | \`'self' unpkg.com 'unsafe-inline'\`` — CSP style-src in the table shows `unpkg.com`; actual header in `app/asgi.py` (line 47) emits `https://unpkg.com`. **P2** — Update table cell to `'self' https://unpkg.com 'unsafe-inline'`.

### docs/developer-guide.md

- `docs/developer-guide.md:241-244` — `make -C apps/vuln-api test-unit` (and test-quick, test-vulnerability, test-smoke) — No `Makefile` exists at `apps/vuln-api/`. `ls apps/vuln-api/Makefile` returns not-found. The root `justfile` `api-test-unit` recipe also calls `make -C apps/vuln-api test-unit` and would fail. **P1** — Replace all four `make` commands with the equivalent `just -f apps/vuln-api/justfile <recipe>` invocations that already exist in the justfile.

### README.md

- `README.md:241-244` — Same four `make -C apps/vuln-api test-*` commands as above — same missing-Makefile issue. **P1** — Replace with `just -f apps/vuln-api/justfile` equivalents.

### apps/vuln-api/README.md

- `apps/vuln-api/README.md:8` — `**[docs/API-DOCUMENTATION.md](docs/API-DOCUMENTATION.md)**` — The relative path `apps/vuln-api/docs/API-DOCUMENTATION.md` does not exist. The actual file is `apps/vuln-api/API-DOCUMENTATION.md`. **P1** — Change link target to `API-DOCUMENTATION.md`.
- `apps/vuln-api/README.md:10` — `**[../DOCUMENTATION.md](../DOCUMENTATION.md)**` — `apps/DOCUMENTATION.md` does not exist; neither does `DOCUMENTATION.md` at repo root. **P1** — Remove the dead link or point it to the correct file (e.g., root `README.md`).

### apps/vuln-api/AGENTS.md

- `apps/vuln-api/AGENTS.md:116` — `"In production (Docker), nginx handles the proxy."` — No nginx appears in `Dockerfile`, `Dockerfile.prod`, or `Dockerfile.fargate`; all three use uvicorn directly. `grep -n nginx apps/vuln-api/Dockerfile*` returns no matches. **P1** — Remove the nginx reference; note that uvicorn serves both the API and static files directly in the production container.

### apps/vuln-api/API-DOCUMENTATION.md

- `apps/vuln-api/API-DOCUMENTATION.md:17+22 vs 1015` — Header sections say `**469 Vulnerable Endpoints**`; the final Quick Reference section (line 1015) says `**Total Endpoints**: 450+`. Same document, two different numbers. **P1** — Reconcile to a single number throughout the file.

### apps/vuln-api/tests/README.md

- `apps/vuln-api/tests/README.md:66-76` — Directory structure lists `tests/vulnerability/`, `tests/smoke/`, `tests/pytest.ini`, `tests/justfile`, `tests/run_tests.sh` — none of these paths exist under `apps/vuln-api/tests/`. The only subdirectories are `tests/unit/` and `tests/integration/`. `run_tests.sh` is also absent at `apps/vuln-api/run_tests.sh`, making the justfile's `test-all` recipe broken. **P1** — Update the directory tree to reflect the real structure; address or remove the `run_tests.sh` reference in justfile's `test-all`.
- `apps/vuln-api/tests/README.md:232-237` — conftest.py fixture list includes `auth_headers`, `sample_data`, `mock_services` — `grep` on `tests/conftest.py` finds none of these names. Actual fixtures include `set_session`, `read_session`, `reset_databases`, `mock_users`, `mock_medical_records`, `sql_injection_payloads`. **P1** — Replace the listed fixtures with the real ones.
- `apps/vuln-api/tests/README.md:297-298` — Code example calls `create_app('testing')` — the actual signature is `create_app(config: dict | None = None)`. Passing a string would be silently ignored at best and raise a runtime error at worst. **P1** — Update example to `create_app({'TESTING': True})` or remove if the pattern is obsolete.
- `apps/vuln-api/tests/README.md:213-215` — `"Minimum overall: 90%"` coverage requirement — `apps/vuln-api/justfile` line 48 enforces `--cov-fail-under=80`, and developer-guide.md says 80%. **P2** — Update to 80% to match the enforced threshold.
- `apps/vuln-api/tests/README.md:252-256` — CI GitHub Actions snippet uses `pip install -r requirements.txt` — no `requirements.txt` exists; the project uses `uv sync --extra dev`. **P2** — Update snippet to use `uv sync --extra dev --frozen`.
- `apps/vuln-api/tests/README.md:138-142` — pytest markers listed as `slow`, `security`, `critical` — `developer-guide.md` (and the code) uses `vulnerability`, `integration`, `smoke`. These marker sets do not agree. **P2** — Reconcile to the markers actually used in pyproject.toml / pytest config and enforce them consistently.

### docs/endpoints-catalog.md

- `docs/endpoints-catalog.md:600-602` — Implementation Status section says `✅ 243 Total Routes` while the document title, header Quick Stats, and conclusion all say `469 unique endpoints`. These are internally inconsistent within the same file. **P1** — Reconcile; remove or correct the "243 Total Routes" figure.

<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria

<!-- AC:BEGIN -->
- [ ] #1  `docs/architecture.md:165` — DEMO_MODE default updated from `true` to the correct value.
- [ ] #2  `docs/architecture.md:87-115` — `education/` blueprint added to directory listing with route count.
- [ ] #3  `docs/architecture.md:155` — CSP table `unpkg.com` updated to `https://unpkg.com`.
- [ ] #4  `docs/developer-guide.md:241-244` — Four `make -C apps/vuln-api` commands replaced with working `just -f apps/vuln-api/justfile` equivalents.
- [ ] #5  `README.md:241-244` — Same four make commands replaced.
- [ ] #6  `apps/vuln-api/README.md:8` — Broken `docs/API-DOCUMENTATION.md` link fixed to `API-DOCUMENTATION.md`.
- [ ] #7  `apps/vuln-api/README.md:10` — Dead `../DOCUMENTATION.md` link removed or corrected.
- [ ] #8  `apps/vuln-api/AGENTS.md:116` — nginx proxy claim removed; uvicorn acknowledged as the production server.
- [ ] #9  `apps/vuln-api/API-DOCUMENTATION.md:1015 vs 17` — Single consistent endpoint count throughout the file.
- [ ] #10 `apps/vuln-api/tests/README.md:66-76` — Directory tree corrected to real test structure; run_tests.sh phantom resolved.
- [ ] #11 `apps/vuln-api/tests/README.md:232-237` — conftest.py fixture list corrected to actual fixtures.
- [ ] #12 `apps/vuln-api/tests/README.md:297-298` — `create_app('testing')` call fixed to valid dict signature.
- [ ] #13 `apps/vuln-api/tests/README.md:213-215` — Coverage minimum corrected from 90% to 80%.
- [ ] #14 `apps/vuln-api/tests/README.md:252-256` — CI snippet updated to use `uv sync` instead of `pip install -r requirements.txt`.
- [ ] #15 `apps/vuln-api/tests/README.md:138-142` — Pytest markers reconciled across docs and code.
- [ ] #16 `docs/endpoints-catalog.md:600-602` — "243 Total Routes" figure reconciled with "469 unique endpoints".
- [ ] #17 All linked claims verified against current code after fixes.
<!-- AC:END -->
