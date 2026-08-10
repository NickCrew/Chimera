---
id: TASK-17
title: 'Doc drift detected on 2026-08-10'
status: To Do
assignee: []
created_date: '2026-08-10 00:00'
updated_date: '2026-08-10 00:00'
labels:
  - docs
dependencies: []
priority: Low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Automated doc-drift audit on 2026-08-10 detected **16 verified drift findings** across 8 of the 12 audited doc files. Severity breakdown: **1 P0** (user-facing command fails), **11 P1** (incorrect dev-doc claims), **4 P2** (minor staleness/internal inconsistency).

Each finding below is in the form: `path:line — \`exact quote\` — claim — proposed fix`.

---

### docs/architecture.md

- `docs/architecture.md:151` — `"uv build` packages everything via hatchling, with `force-include` ensuring `web_dist/` makes it into the wheel despite being gitignored"` — **P1**: `apps/vuln-api/pyproject.toml` has no `force-include` entry under `[tool.hatch.build.targets.wheel]`; `packages = ["app"]` is the only hatch build config. — Fix: either add `force-include` to pyproject.toml or correct the claim to match actual packaging approach.

- `docs/architecture.md:165` — `| \`DEMO_MODE\` | \`true\` | \`full\` enables all vulns …` — **P1**: `app/config.py:31` sets `os.environ.get('DEMO_MODE', 'full')`, so the actual default is `'full'`, not `'true'`. (README.md and developer-guide.md both say `strict` as default, also wrong.) — Fix: update default column to `full` across all env-var tables (architecture.md, README.md, developer-guide.md are all inconsistent with the code).

- `docs/architecture.md:88–116` — blueprint directory listing — **P1**: `education/` blueprint is imported and mounted in `app/asgi.py` (`from app.blueprints.education import education_router`) but does not appear in the `app/blueprints/` directory tree. — Fix: add `├── education/` entry to the blueprint listing.

---

### docs/developer-guide.md

- `docs/developer-guide.md:335` — `"# Output: apps/vuln-api/dist/chimera_api-0.1.0-py3-none-any.whl"` — **P2**: `apps/vuln-api/pyproject.toml` declares `version = "0.1.5"`; the wheel would be `chimera_api-0.1.5-py3-none-any.whl`. — Fix: update version string to `0.1.5` (or use a glob `chimera_api-*.whl` to stay version-agnostic).

---

### README.md (root)

- `README.md:243–246` — `"make -C apps/vuln-api test-unit"`, `"make -C apps/vuln-api test-quick"`, `"make -C apps/vuln-api test-vulnerability"`, `"make -C apps/vuln-api test-smoke"` — **P0**: there is no `Makefile` in `apps/vuln-api/` (confirmed: `ls apps/vuln-api/Makefile` → not found). These commands will fail for any contributor following the README. The project uses `just` (justfile). — Fix: replace `make -C apps/vuln-api test-*` with the equivalent `just -f apps/vuln-api/justfile test-*` recipes.

---

### AGENTS.md (root)

- `AGENTS.md:116` — `"In production (Docker), nginx handles the proxy."` — **P1**: none of the three Dockerfiles (`Dockerfile`, `Dockerfile.prod`, `Dockerfile.fargate`) reference nginx; all use uvicorn directly. The Starlette app serves the SPA via a catch-all route, not nginx. — Fix: update to "In production (Docker), uvicorn serves both the API and the bundled SPA from a single process via the catch-all route."

---

### apps/vuln-api/README.md

- `apps/vuln-api/README.md:7–8` — `"**[docs/API-DOCUMENTATION.md](docs/API-DOCUMENTATION.md)**"` — **P1**: `apps/vuln-api/docs/API-DOCUMENTATION.md` does not exist (the `docs/` subdirectory of vuln-api contains only `openapi.yaml` and `archive/`). The actual file is at `apps/vuln-api/API-DOCUMENTATION.md`. — Fix: update link to `[API-DOCUMENTATION.md](API-DOCUMENTATION.md)`.

---

### apps/vuln-api/tests/README.md

- `apps/vuln-api/tests/README.md:65–68` — lists `tests/integration/test_auth_flow.py`, `test_transaction_flow.py`, `test_admin_operations.py` — **P1**: `tests/integration/` only contains `__init__.py`; none of those three test files exist. — Fix: remove the non-existent filenames or create the tests.

- `apps/vuln-api/tests/README.md:69–73` — `"├── vulnerability/"` directory with `test_sql_injection.py`, `test_xss.py`, `test_command_injection.py`, `test_auth_bypass.py` — **P1**: `tests/vulnerability/` does not exist. — Fix: remove the section or create the directory and test files.

- `apps/vuln-api/tests/README.md:75` — `"├── pytest.ini"` — **P1**: no `pytest.ini` exists at `tests/pytest.ini` or `apps/vuln-api/pytest.ini`. — Fix: remove from directory tree or create the file.

- `apps/vuln-api/tests/README.md:76` — `"├── run_tests.sh"` — **P1**: no `run_tests.sh` exists anywhere in `apps/vuln-api/` (the justfile's `test-all` recipe references `./run_tests.sh all` which also fails). — Fix: remove from directory tree or create the script.

- `apps/vuln-api/tests/README.md:212` — `"Minimum overall: 90%"` — **P2**: `apps/vuln-api/justfile:test-coverage` uses `--cov-fail-under=80`; `docs/developer-guide.md` and `apps/vuln-api/AGENTS.md` both state 80%. — Fix: update to 80%.

- `apps/vuln-api/tests/README.md:303–304` — `"self.app = create_app('testing')"` and `"self.client = self.app.test_client()"` — **P1**: `create_app()` signature is `(config: dict | None = None)` (asgi.py:161); passing a string is incorrect. Starlette apps do not have `.test_client()`; the correct pattern is `from starlette.testclient import TestClient; client = TestClient(app)`. Both are Flask-era remnants. — Fix: update test template to use `create_app({})` and `TestClient(self.app)`.

---

### docs/endpoints-catalog.md

- `docs/endpoints-catalog.md:15` — `"verified against the live route table via \`just docs-drift\`"` — **P1**: `docs-drift` recipe does not exist in the root `justfile` or `apps/vuln-api/justfile` (`docs-check` and `docs-check-fedramp` exist in the vuln-api justfile, but not `docs-drift`). — Fix: replace `just docs-drift` with the correct recipe name, or add a `docs-drift` recipe.

- `docs/endpoints-catalog.md:15` and `docs/endpoints-catalog.md:600` — `"Total Endpoints: 469 unique endpoints"` (line 15) AND `"✅ **243 Total Routes**: Comprehensive coverage across offensive and defensive scenarios."` (line 600) — **P2**: the same document claims 469 endpoints and 243 routes; these cannot both be accurate totals for the same surface. — Fix: reconcile or clarify the distinction (e.g. 243 may be a count of distinct unique paths while 469 includes method variants).

---

### apps/vuln-api/API-DOCUMENTATION.md

- `apps/vuln-api/API-DOCUMENTATION.md:17` — `"469 Vulnerable Endpoints across 28 router packages"` — **P2**: README.md, AGENTS.md (root), dockerhub-overview.md, and apps/vuln-api/README.md all state "456+" endpoints. The 469 count appears only in this file and docs/endpoints-catalog.md. — Fix: reconcile the count across all docs after running the authoritative `just docs-check`.

<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 `docs/architecture.md:151` — remove or verify `force-include` claim; align with actual pyproject.toml hatchling config.
- [ ] #2 `docs/architecture.md:165` — update `DEMO_MODE` default from `true` to `full` (and audit README.md + developer-guide.md default columns).
- [ ] #3 `docs/architecture.md:88–116` — add `education/` blueprint to the blueprint directory listing.
- [ ] #4 `docs/developer-guide.md:335` — update wheel filename to reflect current version (`0.1.5` or version-agnostic glob).
- [ ] #5 `README.md:243–246` — replace `make -C apps/vuln-api test-*` with `just -f apps/vuln-api/justfile test-*` equivalents.
- [ ] #6 `AGENTS.md:116` — replace nginx proxy claim with accurate uvicorn catch-all description.
- [ ] #7 `apps/vuln-api/README.md:7` — fix `docs/API-DOCUMENTATION.md` link to `API-DOCUMENTATION.md`.
- [ ] #8 `apps/vuln-api/tests/README.md:65–68` — remove or create integration test files (`test_auth_flow.py`, `test_transaction_flow.py`, `test_admin_operations.py`).
- [ ] #9 `apps/vuln-api/tests/README.md:69–73` — remove or create `tests/vulnerability/` directory.
- [ ] #10 `apps/vuln-api/tests/README.md:75` — remove `pytest.ini` from listing or create the file.
- [ ] #11 `apps/vuln-api/tests/README.md:76` — remove `run_tests.sh` from listing or create the script.
- [ ] #12 `apps/vuln-api/tests/README.md:212` — update coverage minimum from 90% to 80%.
- [ ] #13 `apps/vuln-api/tests/README.md:303–304` — fix test template: use `create_app({})` and `TestClient(self.app)` (not Flask-style `create_app('testing')` + `.test_client()`).
- [ ] #14 `docs/endpoints-catalog.md:15` — replace `just docs-drift` with the correct justfile recipe or add the recipe.
- [ ] #15 `docs/endpoints-catalog.md:15+600` — resolve 469 vs 243 internal inconsistency.
- [ ] #16 `apps/vuln-api/API-DOCUMENTATION.md:17` — reconcile 469 endpoint count with 456+ stated elsewhere.
- [ ] All linked claims verified against current code after fixes are applied.
<!-- AC:END -->
