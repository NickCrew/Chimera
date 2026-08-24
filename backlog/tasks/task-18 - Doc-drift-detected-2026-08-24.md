---
id: TASK-18
title: 'Docs: Doc-claim drift detected on 2026-08-24'
status: To Do
assignee: []
created_date: '2026-08-24 00:00'
updated_date: '2026-08-24 00:00'
labels:
  - docs
priority: Low
dependencies: []
---

## Description

Automated doc-drift audit run on 2026-08-24 against 12 doc files. Found **13 confirmed drift findings** across 8 files. Severity breakdown: **9 P1 (dev-doc error)**, **4 P2 (minor staleness)**.

> This task was created by the scheduled documentation drift detector. Do not "fix" source code to match docs; fix docs to match source (or update both when the code is wrong).

---

### Findings by file

#### docs/architecture.md

- docs/architecture.md:165 — `` `DEMO_MODE` | `true` `` — The Default column lists `true`, which is not a valid `DEMO_MODE` value. Actual default in `app/config.py:31` is `'full'` (`os.environ.get('DEMO_MODE', 'full')`). — **Proposed fix**: Change default cell to `` `full` ``. — **P1**

- docs/architecture.md (blueprint table) — `education` blueprint exists at `app/blueprints/education/` with routes and a test file (`tests/unit/test_education_routes.py`) but is not listed in the router architecture table. — **Proposed fix**: Add `education/` row to the blueprint listing. — **P2**

#### docs/developer-guide.md

- docs/developer-guide.md:47 — `` `DEMO_MODE` | `strict` `` — Default column says `strict`; actual default in `app/config.py:31` is `'full'`. CLI `--demo-mode` has no default (line 21-24 of `app/cli.py`). — **Proposed fix**: Change default cell to `` `full` ``. — **P1**

- docs/developer-guide.md:243-246 — `` make -C apps/vuln-api test-unit ``, `test-quick`, `test-vulnerability`, `test-smoke` — No `Makefile` exists in the repo. The corresponding `just` recipes exist in `apps/vuln-api/justfile` (`test-unit`, `test-quick`, `test-vulnerability`, `test-smoke`). — **Proposed fix**: Replace `make -C apps/vuln-api <recipe>` with `just -f apps/vuln-api/justfile <recipe>`. — **P1**

#### README.md

- README.md:48 — `` `DEMO_MODE` | `strict` `` — Default column says `strict`; actual default in `app/config.py:31` is `'full'`. — **Proposed fix**: Change default cell to `` `full` ``. — **P1**

#### docs/endpoints-catalog.md

- docs/endpoints-catalog.md:15 — `"verified against the live route table via \`just docs-drift\`"` — The recipe `docs-drift` does not exist in either the root `justfile` or `apps/vuln-api/justfile`. The closest existing recipe is `docs-check` (`apps/vuln-api/justfile:105`). — **Proposed fix**: Change `just docs-drift` to `just -f apps/vuln-api/justfile docs-check`. — **P1**

#### apps/vuln-api/AGENTS.md

- apps/vuln-api/AGENTS.md:116 — `"In production (Docker), nginx handles the proxy."` — No nginx appears in any Dockerfile (`Dockerfile`, `Dockerfile.prod`, `Dockerfile.fargate`); uvicorn serves directly on port 80/8880/8080 in all container variants. — **Proposed fix**: Remove or rewrite the sentence; production is single-process uvicorn, no proxy layer. — **P1**

- apps/vuln-api/AGENTS.md:127 — `` `make test-coverage` `` — No `Makefile` exists; coverage target is `just -f apps/vuln-api/justfile test-coverage` (or bare `just test-coverage` from inside `apps/vuln-api/`). — **Proposed fix**: Replace `make test-coverage` with `just test-coverage`. — **P2**

#### apps/vuln-api/API-DOCUMENTATION.md

- apps/vuln-api/API-DOCUMENTATION.md:17 vs :1015 — Line 17 says "**469 Vulnerable Endpoints**"; line 1015 says "**Total Endpoints**: 450+". Internally inconsistent within the same file. — **Proposed fix**: Reconcile to a single number consistent with the live route count. — **P2**

#### apps/vuln-api/tests/README.md

- apps/vuln-api/tests/README.md:66-76 — References `tests/vulnerability/` directory containing `test_sql_injection.py`, `test_xss.py`, `test_command_injection.py`, `test_auth_bypass.py`. This directory does not exist. Also references `tests/pytest.ini`, `tests/run_tests.sh`, and `tests/justfile` — none of these files exist. — **Proposed fix**: Remove references to the nonexistent `tests/vulnerability/` directory and files, or create them. — **P1**

- apps/vuln-api/tests/README.md:234-235 — Claims `conftest.py` provides fixtures `auth_headers`, `sample_data`, `mock_services`. None of these names appear in `tests/conftest.py` (actual fixtures: `client`, `set_session`, `read_session`, `mock_users`, `mock_medical_records`, etc.). — **Proposed fix**: Update the conftest fixture list to match actual fixtures. — **P1**

- apps/vuln-api/tests/README.md:211-213 — "Coverage Requirements: Minimum overall: 90%, New code: 95%, Critical paths: 100%". The actual coverage gate in `apps/vuln-api/justfile:47-48` (`test-coverage` recipe) is `--cov-fail-under=80`. — **Proposed fix**: Update coverage requirement table to show 80% minimum. — **P1**

#### docs/vulnerability-inventory.md

- docs/vulnerability-inventory.md:46 — `"being reconciled under \`TASK-17\`"` — TASK-17 does not exist in `backlog/tasks/` or `backlog/completed/`. — **Proposed fix**: Either create TASK-17 or update the reference to the actual tracking task. — **P1**

#### Cross-file internal inconsistency

- README.md, AGENTS.md, docs/dockerhub-overview.md, apps/vuln-api/README.md — All claim "**456+**" endpoints. — endpoints-catalog.md:15,590 and apps/vuln-api/API-DOCUMENTATION.md:17 — Both claim "**469**" unique endpoints. — These numbers are internally inconsistent across the audited doc set. — **Proposed fix**: Reconcile to a single authoritative endpoint count (run `just -f apps/vuln-api/justfile docs-check` to get the live count). — **P2**

---

## Acceptance Criteria

<!-- AC:BEGIN -->
- [ ] #1 `docs/architecture.md` DEMO_MODE default corrected from `true` to `full`.
- [ ] #2 `docs/architecture.md` blueprint table includes the `education` domain.
- [ ] #3 `docs/developer-guide.md` DEMO_MODE default corrected from `strict` to `full`.
- [ ] #4 `docs/developer-guide.md` testing section `make -C` commands replaced with `just -f apps/vuln-api/justfile` equivalents.
- [ ] #5 `README.md` DEMO_MODE default corrected from `strict` to `full`.
- [ ] #6 `docs/endpoints-catalog.md` `just docs-drift` reference corrected to `just -f apps/vuln-api/justfile docs-check`.
- [ ] #7 `apps/vuln-api/AGENTS.md` nginx proxy claim removed or corrected.
- [ ] #8 `apps/vuln-api/AGENTS.md` `make test-coverage` corrected to `just test-coverage`.
- [ ] #9 `apps/vuln-api/API-DOCUMENTATION.md` endpoint count "469" and "450+" reconciled to a single value.
- [ ] #10 `apps/vuln-api/tests/README.md` references to nonexistent `tests/vulnerability/`, `tests/pytest.ini`, `tests/run_tests.sh`, `tests/justfile` removed or the files created.
- [ ] #11 `apps/vuln-api/tests/README.md` conftest fixture list corrected to match actual fixtures in `tests/conftest.py`.
- [ ] #12 `apps/vuln-api/tests/README.md` coverage requirement table corrected from 90%/95%/100% to match the actual 80% gate.
- [ ] #13 `docs/vulnerability-inventory.md` TASK-17 reference resolved (create the task or update the reference).
- [ ] #14 Endpoint count harmonized across all 12 audited docs to a single authoritative number.
- [ ] #15 All linked claims verified against current code after fixes are applied.
<!-- AC:END -->
