---
id: TASK-18
title: 'Docs: doc-claim drift detected 2026-07-27'
status: To Do
assignee: []
created_date: '2026-07-27 00:00'
labels:
  - docs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Automated doc-drift audit of the 12 active doc files run on 2026-07-27 found **23 drift findings** across all docs.  No manual edits were made — findings go here for human resolution.

Severity key: **P1** = dev-doc error (wrong claim, will mislead a contributor); **P2** = minor staleness (stale path, internal inconsistency, or ambiguous omission).

---

### docs/architecture.md

- `docs/architecture.md:165` — `| \`DEMO_MODE\` | \`true\` | …` — default listed as `true`; `app/config.py:31` has `os.environ.get('DEMO_MODE', 'full')`, so the actual default is `'full'`. **P1**
- `docs/architecture.md:88-116` — Blueprint directory listing omits the `education` blueprint; `app/blueprints/education/` exists and has tests in `tests/unit/test_education_routes.py`. **P2**

---

### docs/developer-guide.md

- `docs/developer-guide.md:47` — `| \`DEMO_MODE\` | \`strict\` | …` — default listed as `strict`; actual code default is `'full'` (see `app/config.py:31`). **P1**
- `docs/developer-guide.md:151` — "with `force-include` ensuring `web_dist/` makes it into the wheel despite being gitignored" — no `[tool.hatch.build.targets.wheel.force-include]` section in `apps/vuln-api/pyproject.toml`. **P2**
- `docs/developer-guide.md:335` — "Output: `apps/vuln-api/dist/chimera_api-0.1.0-py3-none-any.whl`" — `pyproject.toml:7` sets `version = "0.1.5"`; wheel filename would be `chimera_api-0.1.5-py3-none-any.whl`. **P2**

---

### README.md

- `README.md:48` — `| \`DEMO_MODE\` | \`strict\` | …` — default listed as `strict`; actual code default is `'full'`. **P1**

---

### AGENTS.md

- `AGENTS.md:95-97` — "DEMO_MODE env var: `full` (vulns active) vs `strict` (safe mode, **default**)" — `app/config.py:31` defaults to `'full'`, not `'strict'`. **P1**
- `AGENTS.md:116` — "In production (Docker), nginx handles the proxy." — there is no nginx in either `Dockerfile` or `Dockerfile.prod`; uvicorn serves all requests directly (SPA catch-all is in `app/asgi.py:261-273`). **P1**

---

### apps/vuln-api/README.md

- `apps/vuln-api/README.md:7` — link `docs/API-DOCUMENTATION.md` — resolves to `apps/vuln-api/docs/API-DOCUMENTATION.md` which does not exist (the file is at `apps/vuln-api/API-DOCUMENTATION.md`). **P2**
- `apps/vuln-api/README.md:8` — link `../DOCUMENTATION.md` — resolves to `apps/DOCUMENTATION.md` which does not exist. **P2**

---

### apps/vuln-api/AGENTS.md

- `apps/vuln-api/AGENTS.md:6` — "`tests/unit`, `tests/integration`, and security/vulnerability suites (`tests/vulnerability`, `tests/smoke`)" — `tests/vulnerability/` and `tests/smoke/` do not exist; only `tests/unit/` and `tests/integration/` (which itself only has `__init__.py`) are present. **P1**

---

### apps/vuln-api/API-DOCUMENTATION.md

- `apps/vuln-api/API-DOCUMENTATION.md:102` — `| **GenAI** | ~1 | LLM-based chat interfaces …` — contradicts `API-DOCUMENTATION.md:345` which shows `### GenAI Domain (4 endpoints)` with 4 concrete routes. Internal inconsistency. **P2**
- `apps/vuln-api/API-DOCUMENTATION.md:1014` — "**Total Endpoints**: 450+" — contradicts `API-DOCUMENTATION.md:20` "469 Vulnerable Endpoints". Internal inconsistency. **P2**

---

### apps/vuln-api/tests/README.md

- `apps/vuln-api/tests/README.md:66-76` — claims `tests/vulnerability/` directory exists with `test_sql_injection.py`, `test_xss.py`, `test_command_injection.py`, `test_auth_bypass.py` — directory does not exist. **P1**
- `apps/vuln-api/tests/README.md:74-76` — structure diagram shows `pytest.ini`, `run_tests.sh`, `justfile` inside `tests/` — none of these files exist in `apps/vuln-api/tests/`. (`pytest.ini` and `justfile` live at `apps/vuln-api/`; `run_tests.sh` does not exist anywhere — also see apps/vuln-api/justfile:24 which calls `./run_tests.sh all` and would fail.) **P1**
- `apps/vuln-api/tests/README.md:214` — "Minimum overall: 90%" coverage requirement — contradicts `apps/vuln-api/justfile:48` (`--cov-fail-under=80`) and `docs/developer-guide.md` ("Coverage target: 80% minimum"). **P1**
- `apps/vuln-api/tests/README.md:233-234` — conftest fixture list claims `auth_headers`, `sample_data`, `mock_services` — actual `tests/conftest.py` provides `client`, `remote_client`, `set_session`, `read_session`, `mock_users`, `mock_medical_records`, `sample_user`, `mfa_user`, `demo_mode_full`, `demo_mode_strict`, etc. **P1**
- `apps/vuln-api/tests/README.md:300-310` — test template uses `create_app('testing')` and `self.app.test_client()` (Flask API) — project has completed Flask→Starlette migration and uses `starlette.testclient.TestClient(app)`. **P1**
- `apps/vuln-api/tests/README.md:255` — GitHub Actions CI snippet uses `pip install -r requirements.txt` — project uses `uv sync --extra dev --frozen` (no `requirements.txt`). **P2**

---

### docs/endpoints-catalog.md

- `docs/endpoints-catalog.md:15` — "`just docs-drift`" — no such recipe exists in either the root `justfile` or `apps/vuln-api/justfile`; closest is `just -f apps/vuln-api/justfile docs-check`. **P1**
- `docs/endpoints-catalog.md:15 vs 600` — header claims "469 unique endpoints (verified … via `just docs-drift`)" while the Conclusion section at the bottom states "243 Total Routes". Internal inconsistency. **P1**

---

### docs/dockerhub-overview.md

- `docs/dockerhub-overview.md:22` — `| \`DEMO_MODE\` | \`strict\` | …` — default listed as `strict`; actual code default is `'full'`. **P1**

---

### docs/vulnerability-inventory.md

- `docs/vulnerability-inventory.md:19` — "being reconciled under `TASK-17`" — no TASK-17 file exists in `backlog/tasks/` or `backlog/completed/`. If this task was planned, it should be filed. **P2**
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria

<!-- AC:BEGIN -->
- [ ] #1 `docs/architecture.md:165` — Fix DEMO_MODE default from `true` to `full`
- [ ] #2 `docs/architecture.md:88-116` — Add `education` blueprint to router directory listing
- [ ] #3 `docs/developer-guide.md:47` — Fix DEMO_MODE default from `strict` to `full`
- [ ] #4 `docs/developer-guide.md:151` — Remove or correct `force-include` claim against `pyproject.toml`
- [ ] #5 `docs/developer-guide.md:335` — Update wheel filename from `0.1.0` to `0.1.5` (or make it version-agnostic)
- [ ] #6 `README.md:48` — Fix DEMO_MODE default from `strict` to `full`
- [ ] #7 `AGENTS.md:95-97` — Fix DEMO_MODE default description (actual default is `full`, not `strict`)
- [ ] #8 `AGENTS.md:116` — Remove nginx claim; document that uvicorn handles all requests directly
- [ ] #9 `apps/vuln-api/README.md:7` — Fix broken `docs/API-DOCUMENTATION.md` link
- [ ] #10 `apps/vuln-api/README.md:8` — Fix broken `../DOCUMENTATION.md` link
- [ ] #11 `apps/vuln-api/AGENTS.md:6` — Remove `tests/vulnerability` and `tests/smoke` from test directory description
- [ ] #12 `apps/vuln-api/API-DOCUMENTATION.md:102` — Fix GenAI route count from `~1` to `~4`
- [ ] #13 `apps/vuln-api/API-DOCUMENTATION.md:1014` — Reconcile total endpoints (`450+` vs `469`)
- [ ] #14 `apps/vuln-api/tests/README.md:66-76` — Remove `tests/vulnerability/` directory claim or create the directory
- [ ] #15 `apps/vuln-api/tests/README.md:74-76` — Fix structure diagram: move `pytest.ini`/`justfile` out of `tests/`; note `run_tests.sh` is missing
- [ ] #16 `apps/vuln-api/tests/README.md:214` — Fix coverage minimum to 80% (matches `justfile`)
- [ ] #17 `apps/vuln-api/tests/README.md:233-234` — Update conftest fixture list to match actual `tests/conftest.py`
- [ ] #18 `apps/vuln-api/tests/README.md:300-310` — Update test template to Starlette `TestClient` style
- [ ] #19 `apps/vuln-api/tests/README.md:255` — Replace `pip install -r requirements.txt` with `uv sync --extra dev --frozen`
- [ ] #20 `docs/endpoints-catalog.md:15` — Replace `just docs-drift` with correct recipe name
- [ ] #21 `docs/endpoints-catalog.md` — Reconcile endpoint count (469 vs 243 internal inconsistency)
- [ ] #22 `docs/dockerhub-overview.md:22` — Fix DEMO_MODE default from `strict` to `full`
- [ ] #23 `docs/vulnerability-inventory.md:19` — Create TASK-17 or remove the reference
- [ ] All linked claims verified against current code after fixes
<!-- AC:END -->
