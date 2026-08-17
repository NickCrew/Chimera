---
id: TASK-17
title: Fix doc-claim drift detected 2026-08-17
status: To Do
assignee: []
created_date: '2026-08-17 00:00'
updated_date: '2026-08-17 00:00'
labels:
  - docs
dependencies: []
priority: low
---

## Description

Automated doc-drift audit run on 2026-08-17 against the 12-file active doc set.
**17 confirmed drift findings** across 8 files — 11 P1 dev-doc errors and 6 P2 minor staleness items. No P0 user-facing factual errors identified.

Verification protocol applied: every named symbol was grepped, every file path was checked via `ls`/`Read`, every behavior claim was cross-referenced against the source file implementing it.

---

### Findings by file

#### `docs/architecture.md`

- Line 165 — `| DEMO_MODE | true | full enables all vulns... |` — default column says `true`; `app/config.py:31` has `os.environ.get('DEMO_MODE', 'full')` — default is `full`, not `true`. **P1**
- Lines 89–116 — Blueprint directory listing omits `education/`; `app/blueprints/education/` exists on disk and `app/asgi.py:185` imports `from app.blueprints.education import education_router`. **P1**

#### `docs/developer-guide.md`

- Line 335 — `# Output: apps/vuln-api/dist/chimera_api-0.1.0-py3-none-any.whl` — `pyproject.toml:7` shows `version = "0.1.5"`. Proposed fix: update to `chimera_api-0.1.5-py3-none-any.whl`. **P2**
- Line 151 — "with `force-include` ensuring `web_dist/` makes it into the wheel despite being gitignored" — `pyproject.toml` `[tool.hatch.build.targets.wheel]` section contains only `packages = ["app"]`; no `force-include` directive is present. `web_dist/` is captured because it is a sub-directory of the `app/` package. Proposed fix: correct the explanation. **P2**

#### `docs/endpoints-catalog.md`

- Line 602 — `✅ 243 Total Routes` contradicts the document's own header (line 15): `Total Endpoints: 469 unique endpoints`. Both numbers appear in the same file. Proposed fix: reconcile to a single canonical count. **P2**

#### `README.md`

- Line 48 — `| DEMO_MODE | strict | ... |` — default column says `strict`; `app/config.py:31` defaults to `full`. (Note: `Dockerfile.prod` ENV sets `DEMO_MODE=strict`, so the Docker default differs from the PyPI/source default. The table does not distinguish between install methods.) Proposed fix: split or annotate, or update Python code default to match intent. **P1**
- Line 244 — `make -C apps/vuln-api test-unit` — no `Makefile` exists in `apps/vuln-api/` (confirmed by `ls`). The equivalent command is `just -f apps/vuln-api/justfile test-unit`. Proposed fix: replace `make` with `just -f apps/vuln-api/justfile`. **P1**

#### `AGENTS.md`

- Line 116 — "In production (Docker), nginx handles the proxy." — `Dockerfile.prod` runs `uvicorn app.asgi:app` directly with `--workers 4`; there is no nginx layer in either `Dockerfile` or `Dockerfile.prod`. Proposed fix: remove or replace with "uvicorn serves both API and SPA in production". **P1**

#### `apps/vuln-api/README.md`

- Line 8 — `[docs/API-DOCUMENTATION.md](docs/API-DOCUMENTATION.md)` — resolves to `apps/vuln-api/docs/API-DOCUMENTATION.md` which does not exist (`ls` returns not-found); the actual comprehensive doc is `apps/vuln-api/API-DOCUMENTATION.md`. Proposed fix: correct link to `API-DOCUMENTATION.md`. **P1**
- Line 10 — `[../DOCUMENTATION.md](../DOCUMENTATION.md)` — resolves to `apps/DOCUMENTATION.md` which does not exist. Proposed fix: remove or update to the correct path. **P2**

#### `apps/vuln-api/AGENTS.md`

- Line 97 — "`is_full_mode()` / `get_demo_mode()` helpers for conditional logic in routes" — `grep -rn "is_full_mode" apps/vuln-api/app/` returns no results; `is_full_mode()` does not exist in the active `app/` codebase. `get_demo_mode()` does exist in `app/blueprints/auth/routes.py`. Proposed fix: remove `is_full_mode()` from the claim. **P2**
- Line 130 — "`make test-coverage`" — no `Makefile` in `apps/vuln-api/`; the correct invocation is `just test-coverage` (recipe exists in `apps/vuln-api/justfile:47`). Proposed fix: replace `make` with `just`. **P1**

#### `apps/vuln-api/API-DOCUMENTATION.md`

- Line 20 — "**469 Vulnerable Endpoints** across 28 router packages" — the `README.md`, root `AGENTS.md`, `vuln-api/README.md`, and `docs/dockerhub-overview.md` all say **456+**. The two counts are internally inconsistent across the audited doc set. Proposed fix: align all docs on a single audited count. **P2**

#### `apps/vuln-api/tests/README.md`

- Lines 66–70 — References a `tests/vulnerability/` subdirectory containing `test_sql_injection.py`, `test_xss.py`, etc. This directory does not exist; `ls apps/vuln-api/tests/` shows only `unit/` and `integration/`. Proposed fix: remove the stale `vulnerability/` section or create the directory. **P1**
- Lines 73–74 — Lists `pytest.ini` and `run_tests.sh` as files inside the `tests/` directory. Neither file exists in `tests/`: `pytest.ini` is absent entirely; `run_tests.sh` is at `apps/vuln-api/scripts/run_tests.sh`. Proposed fix: correct paths. **P1**
- Lines 295–316 — Test template uses Flask API: `self.app = create_app('testing')` and `self.client = self.app.test_client()`. The application is Starlette-based; the correct pattern (shown in `tests/conftest.py`) uses `starlette.testclient.TestClient`. Proposed fix: replace template with Starlette-compatible equivalent. **P1**
- Line 212 — "Minimum overall: 90%" for coverage — `apps/vuln-api/justfile:47` uses `--cov-fail-under=80`; `docs/developer-guide.md` and `apps/vuln-api/AGENTS.md` both state "80% minimum". Proposed fix: change 90% → 80%. **P1**

---

## Acceptance Criteria

- [ ] F1: `docs/architecture.md` DEMO_MODE default corrected from `true` to `full`
- [ ] F2: `docs/architecture.md` blueprint listing includes `education/`
- [ ] F3: `docs/developer-guide.md` wheel filename updated to `chimera_api-0.1.5`
- [ ] F4: `docs/developer-guide.md` `force-include` explanation corrected
- [ ] F5: `docs/endpoints-catalog.md` "243 Total Routes" vs "469" internal inconsistency resolved
- [ ] F6: `README.md` `make -C apps/vuln-api test-unit` replaced with working `just` command
- [ ] F7: `README.md` DEMO_MODE default clarified or corrected to `full` for PyPI/source installs
- [ ] F8: `AGENTS.md` nginx proxy claim removed or corrected to reflect uvicorn-direct
- [ ] F9: `apps/vuln-api/README.md` broken link `docs/API-DOCUMENTATION.md` corrected
- [ ] F10: `apps/vuln-api/README.md` broken link `../DOCUMENTATION.md` corrected or removed
- [ ] F11: `apps/vuln-api/AGENTS.md` `is_full_mode()` reference removed
- [ ] F12: `apps/vuln-api/AGENTS.md` `make test-coverage` replaced with `just test-coverage`
- [ ] F13: `apps/vuln-api/API-DOCUMENTATION.md` endpoint count (469 vs 456+) aligned with other docs
- [ ] F14: `apps/vuln-api/tests/README.md` stale `tests/vulnerability/` section removed or corrected
- [ ] F15: `apps/vuln-api/tests/README.md` `pytest.ini` / `run_tests.sh` paths corrected
- [ ] F16: `apps/vuln-api/tests/README.md` Flask test template replaced with Starlette equivalent
- [ ] F17: `apps/vuln-api/tests/README.md` coverage minimum corrected from 90% to 80%
- [ ] All linked claims verified against current code after fixes
