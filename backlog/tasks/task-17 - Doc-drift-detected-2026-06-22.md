---
id: TASK-17
title: 'Docs: Fix doc-claim drift detected on 2026-06-22'
status: To Do
assignee: []
created_date: '2026-06-22 00:00'
updated_date: '2026-06-22 00:00'
labels:
  - docs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Automated doc-drift scan run on 2026-06-22 against 12 doc files found **37 drift findings** across 10 files (2 files clean). Findings are grouped by file below.

Severity key: **P0** = user-facing factual error | **P1** = dev-doc error | **P2** = minor staleness

---

### docs/architecture.md

- architecture.md:165 — `| \`DEMO_MODE\` | \`true\` | \`full\` enables all vulns …` — Default column shows `true` but `app/config.py:31` has `os.environ.get('DEMO_MODE', 'full')`. `true` is not a valid DEMO_MODE value. — Fix: change default cell to `full` — **P0**
- architecture.md:165 — `| \`DATABASE_PATH\` | \`demo.db\` | SQLite file location |` — `app/database.py` defaults to `"/tmp/api-demo.db"`, not `demo.db`. — Fix: change default cell to `/tmp/api-demo.db` — **P1**
- architecture.md:97–116 (blueprint list) — `education/` domain router is entirely absent from the table — `app/blueprints/education/` exists and `education_router` is mounted in `asgi.py:185,231`. — Fix: add `education/` row to blueprint directory listing — **P1**

---

### docs/developer-guide.md

- developer-guide.md:47 — `| \`DEMO_MODE\` | \`strict\` | …` — Default shown as `strict`; actual default in `app/config.py:31` is `full`. — Fix: change default to `full` — **P0**
- developer-guide.md:335 — `# Output: apps/vuln-api/dist/chimera_api-0.1.0-py3-none-any.whl` — `pyproject.toml` has `version = "0.1.5"` so the wheel filename would be `chimera_api-0.1.5-…`. — Fix: update version to `0.1.5` — **P1**
- developer-guide.md:241–246 — `make -C apps/vuln-api test-unit` (and test-quick, test-vulnerability, test-smoke) — No `Makefile` exists in `apps/vuln-api/`; only a `justfile`. These commands will fail. — Fix: replace with `just -f apps/vuln-api/justfile <target>` — **P0**
- developer-guide.md:148 — `with \`force-include\` ensuring \`web_dist/\` makes it into the wheel` — `pyproject.toml`'s `[tool.hatch.build.targets.wheel]` has no `force-include` directive. — Fix: add the config or remove the claim — **P1**

---

### README.md

- README.md:46 — `| \`DEMO_MODE\` | \`strict\` | …` — Default shown as `strict`; actual default is `full`. — Fix: change default to `full` — **P0**
- README.md:49 — `| \`DATABASE_PATH\` | \`demo.db\` | …` — Actual default is `/tmp/api-demo.db`. — Fix: change default to `/tmp/api-demo.db` — **P1**
- README.md:241–246 — `make -C apps/vuln-api test-*` commands — No `Makefile` exists. — Fix: replace with `just -f apps/vuln-api/justfile` equivalents — **P0**

---

### AGENTS.md

- AGENTS.md:87 — `routes.extend({domain}_router.routes) in \`app/asgi.py\`` — Actual pattern in `asgi.py:213–245` uses `*{domain}_router.routes` unpacking in a list literal, not `routes.extend()`. Only `db_vuln_router` uses `extend`. — Fix: describe the actual unpacking pattern — **P2**
- AGENTS.md:126 — `Coverage target: 80% minimum (\`make test-coverage\`)` — No `Makefile` exists; recipe is in `justfile`. — Fix: change to `just test-coverage` — **P1**

---

### docs/api-reference.md

- api-reference.md:55 — `DELETE /api/v1/auth/api-keys/<key_id>` — No DELETE on that path; actual revoke route is `POST /api/v1/auth/apikeys/revoke`. — Fix: correct path and method — **P1**
- api-reference.md:58 — `GET /api/v1/auth/sessions` — Route does not exist. — Fix: remove row — **P1**
- api-reference.md:53 — `POST /api/v1/auth/enroll-mfa` — No such route; actual MFA enable is `POST /api/v1/auth/mfa/enable`. — Fix: correct path — **P1**
- api-reference.md:60 — `POST /api/v1/auth/token/forge` — Actual route is `POST /api/oauth/token/forge`. — Fix: correct path — **P1**
- api-reference.md:68–69 — `GET /api/v1/accounts/balance` and `GET /api/v1/accounts/list` — Neither route exists; actual list is `GET /api/v1/banking/accounts`. — Fix: replace with correct paths — **P0**
- api-reference.md:71 — `POST /api/v1/transfers/wire` — Route does not exist; actual is `POST /api/v1/banking/wire-transfer`. — Fix: correct path — **P0**
- api-reference.md:72 — `POST /api/v1/transfers/initiate` — Route does not exist anywhere. — Fix: remove or correct — **P1**
- api-reference.md:74 — `GET /api/v1/customers/export` — Actual customer export is `GET /api/customers/export` (no v1 prefix). — Fix: correct path — **P1**
- api-reference.md:75–76 — `POST /api/v1/banking/kyc/documents` and `GET /api/v1/banking/kyc/documents/<id>` — Only `GET /api/v1/banking/kyc/documents/export` exists; no POST upload or GET-by-id. — Fix: replace with actual route — **P1**
- api-reference.md:77–78 — `POST /api/v1/banking/beneficiaries` and `GET /api/v1/banking/beneficiaries` — Only `GET /api/v1/banking/beneficiaries/<beneficiary_id>` exists. — Fix: remove collection routes — **P1**
- api-reference.md:91 — `GET /api/hipaa/records/patient` — Not a live route (appears only in a template string). — Fix: remove row — **P1**
- api-reference.md:92 — `POST /api/hipaa/records/bulk-export` — Actual route is `GET /api/hipaa/export/bulk`. — Fix: correct path and method — **P1**
- api-reference.md:107 — `POST /api/v1/ecommerce/gift-cards/create` — Actual route is `POST /api/v1/ecommerce/gift-cards/generate`. — Fix: change `create` → `generate` — **P1**
- api-reference.md:119–127 — `GET /api/v1/insurance/underwriting/rules`, `POST /api/v1/insurance/underwriting/rules`, `GET /api/v1/insurance/actuarial/models` — Actual underwriting routes have no `v1` prefix (`/api/underwriting/rules`); actuarial route is entirely absent. — Fix: correct to `/api/underwriting/rules`, remove actuarial row — **P1**
- api-reference.md:228–233 — `POST /api/v1/admin/system/execute`, `POST /api/v1/admin/files/read`, `POST /api/v1/admin/config/import`, `POST /api/v1/admin/data/deserialize` — Actual routes: `/api/v1/admin/execute`, (no files/read route), `/api/v1/admin/attack/xxe`, `/api/v1/admin/attack/deserialize`. — Fix: correct all four paths — **P1**
- api-reference.md:285–287 — `GET /api/recorder/stats` and `DELETE /api/recorder/clear` — Actual routes are `GET /api/recorder/status` and `DELETE /api/recorder/traffic`. — Fix: `stats`→`status`, `clear`→`traffic` — **P1**
- api-reference.md:297 — `GET /fast/payload` — Actual route is `GET /fast/export`. — Fix: `payload`→`export` — **P1**
- api-reference.md:268–271 — `POST /api/v1/genai/complete`, `GET /api/v1/genai/models`, `POST /api/v1/genai/embeddings` — None of these routes exist; actual GenAI routes are `POST /api/v1/genai/chat`, `POST /api/v1/genai/knowledge/upload`, `POST /api/v1/genai/agent/browse`, `GET /api/v1/genai/models/config`, `POST /api/v1/genai/graphql`. — Fix: replace with actual routes — **P1**
- api-reference.md:278 — `POST /api/v1/diagnostics/resolve` — No such route; second diagnostics route is `POST /api/v1/diagnostics/webhook`. — Fix: correct path — **P1**
- api-reference.md:307–309 — Error response JSON includes `"timestamp"` field — `routing.py:67-72` `build_http_exception_body` returns `{error, status, path, method}` with no `timestamp` and an additional `method` field not shown. — Fix: remove `timestamp`, add `"method"` — **P1**

---

### docs/endpoints-catalog.md

- endpoints-catalog.md:15 — `` `just docs-drift` `` — No `docs-drift` recipe exists; actual recipe is `docs-check` in `apps/vuln-api/justfile:105`. — Fix: change to `just docs-check` — **P1**
- endpoints-catalog.md:601 — `✅ **243 Total Routes**` — Conflicts with line 15/590 of the same file which states 469 endpoints; neither matches the actual decorator count of 487. — Fix: reconcile the two figures and align to the actual route count — **P1**

---

### docs/dockerhub-overview.md

- dockerhub-overview.md:21 — `DEMO_MODE | strict | …` — Default shown as `strict`; actual default is `full`. — Fix: change to `full` — **P0**
- dockerhub-overview.md:20 — `PORT | 8880 | …` with `docker run -p 8880:8880` — Container listens on port 80 (per `Dockerfile ENV PORT=80`); `-p 8880:8880` would fail to reach the service. — Fix: change mapping to `-p 8880:80` — **P0**

---

### apps/vuln-api/README.md

- apps/vuln-api/README.md:7,215,244 — `[docs/API-DOCUMENTATION.md](docs/API-DOCUMENTATION.md)` — File lives at `apps/vuln-api/API-DOCUMENTATION.md`, not `apps/vuln-api/docs/API-DOCUMENTATION.md`. Link is broken. — Fix: change to `[API-DOCUMENTATION.md](API-DOCUMENTATION.md)` — **P0**
- apps/vuln-api/README.md:9 — `[../DOCUMENTATION.md](../DOCUMENTATION.md)` — `apps/DOCUMENTATION.md` does not exist. — Fix: remove link or correct path — **P1**
- apps/vuln-api/README.md:3,120,211 — `"456+ intentionally vulnerable endpoints"` — `API-DOCUMENTATION.md:20` states 469 endpoints. Internally inconsistent. — Fix: align to 469 — **P1**

---

### apps/vuln-api/AGENTS.md

- apps/vuln-api/AGENTS.md:6 — `tests/vulnerability` and `tests/smoke` directories listed — Neither directory exists on disk (`tests/` contains only `unit/`, `integration/`, `conftest.py`, `README.md`, `__init__.py`, `verify_vaas.py`). — Fix: remove from directory listing or note as planned — **P1**
- apps/vuln-api/AGENTS.md:29 — `"plus feature toggles in security.py"` — No `security.py` exists under `app/`; feature toggles are in `app/utils/security_config.py`. — Fix: change to `security_config.py` — **P1**

---

### apps/vuln-api/API-DOCUMENTATION.md

- apps/vuln-api/API-DOCUMENTATION.md:1015 — `**Total Endpoints**: 450+` — Same file (line 20) states `469 Vulnerable Endpoints`. Internally inconsistent. — Fix: change footer to `469` — **P0**
- apps/vuln-api/API-DOCUMENTATION.md:68–72 — `tests/vulnerability/` tree with `test_sql_injection.py`, `test_xss.py`, `test_command_injection.py`, `test_auth_bypass.py` — Directory does not exist. — Fix: remove block — **P1**
- apps/vuln-api/API-DOCUMENTATION.md:75–76 — `tests/pytest.ini` and `tests/justfile` listed — Neither exists in `tests/`; `justfile` is at project root. — Fix: remove both lines — **P1**
- apps/vuln-api/API-DOCUMENTATION.md:891,929–930 — `docker build -t api-demo ./api-demo` and `cd api-demo` — Actual directory is `apps/vuln-api`. — Fix: update to `apps/vuln-api` — **P1**
- apps/vuln-api/API-DOCUMENTATION.md:897 — `-e ENABLE_VULNERABILITIES=true` — `ENABLE_VULNERABILITIES` is not a recognized env var in `app/config.py`; correct variable is `DEMO_MODE`. — Fix: replace with `-e DEMO_MODE=full` — **P0**

---

### apps/vuln-api/tests/README.md

- apps/vuln-api/tests/README.md:57–62 — `test_validators.py` and `test_responses.py` under `tests/unit/` — Neither file exists in `tests/unit/`. — Fix: remove from listed files — **P1**
- apps/vuln-api/tests/README.md:63–65 — `test_auth_flow.py`, `test_transaction_flow.py`, `test_admin_operations.py` under `tests/integration/` — `tests/integration/` contains only `__init__.py`. — Fix: remove all three from listing — **P1**
- apps/vuln-api/tests/README.md:68–75 — `tests/vulnerability/` tree with four test files — Directory does not exist. — Fix: remove block — **P1**
- apps/vuln-api/tests/README.md:74–76 — `pytest.ini`, `run_tests.sh`, `justfile` listed under `tests/` — None exist there; `run_tests.sh` is at `scripts/run_tests.sh`, `justfile` at project root, `pytest.ini` absent entirely. — Fix: remove from `tests/` tree — **P1**
- apps/vuln-api/tests/README.md:37 — `./run_tests.sh --quick` — Script is at `scripts/run_tests.sh` and accepts `smoke`, not `--quick`. — Fix: change to `./scripts/run_tests.sh smoke` — **P1**
- apps/vuln-api/tests/README.md:212,341 — `"Minimum overall: 90%"` / `"Coverage: > 90%"` — `justfile test-coverage` runs `--cov-fail-under=80`; gate is 80%, not 90%. — Fix: change both occurrences to 80% — **P1**
- apps/vuln-api/tests/README.md:233–234 — `auth_headers`, `sample_data`, `mock_services` listed as conftest fixtures — None defined in `tests/conftest.py`; actual fixtures include `admin_headers`, `user_headers`, `mock_users`, `mock_medical_records`. — Fix: replace with actual fixture names — **P1**
- apps/vuln-api/tests/README.md:253,269 — `pip install -r requirements.txt` — No `requirements.txt` exists; deps managed via `pyproject.toml`/`uv sync`. — Fix: replace with `uv sync --extra dev --frozen` — **P1**
- apps/vuln-api/tests/README.md:303–304 — `create_app('testing')` and `self.app.test_client()` — `create_app` takes `dict | None`, not a string; Starlette has no `.test_client()` method. — Fix: `create_app({"TESTING": True})` and `TestClient(self.app)` — **P1**
- apps/vuln-api/tests/README.md:166,180,194 — `response.json['success']` etc. — `.json` is a callable on httpx `Response`, not an attribute. — Fix: add `()` → `response.json()['success']` — **P2**

<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 `docs/architecture.md`: DEMO_MODE default corrected to `full`
- [ ] #2 `docs/architecture.md`: DATABASE_PATH default corrected to `/tmp/api-demo.db`
- [ ] #3 `docs/architecture.md`: `education/` domain router added to blueprint table
- [ ] #4 `docs/developer-guide.md`: DEMO_MODE default corrected to `full`
- [ ] #5 `docs/developer-guide.md`: wheel filename version updated to `0.1.5`
- [ ] #6 `docs/developer-guide.md`: `make -C apps/vuln-api` commands replaced with `just` equivalents
- [ ] #7 `docs/developer-guide.md`: `force-include` claim reconciled with pyproject.toml
- [ ] #8 `README.md`: DEMO_MODE default corrected to `full`
- [ ] #9 `README.md`: DATABASE_PATH default corrected to `/tmp/api-demo.db`
- [ ] #10 `README.md`: `make -C apps/vuln-api` commands replaced with `just` equivalents
- [ ] #11 `AGENTS.md`: route-mounting description corrected to unpacking pattern
- [ ] #12 `AGENTS.md`: `make test-coverage` changed to `just test-coverage`
- [ ] #13 `docs/api-reference.md`: all 16 incorrect/nonexistent route paths corrected or removed
- [ ] #14 `docs/api-reference.md`: error-response JSON shape updated (remove `timestamp`, add `method`)
- [ ] #15 `docs/endpoints-catalog.md`: `just docs-drift` changed to `just docs-check`
- [ ] #16 `docs/endpoints-catalog.md`: conflicting route counts (243 vs 469 vs 487) reconciled
- [ ] #17 `docs/dockerhub-overview.md`: DEMO_MODE default corrected to `full`
- [ ] #18 `docs/dockerhub-overview.md`: port mapping corrected to `-p 8880:80`
- [ ] #19 `apps/vuln-api/README.md`: broken link to `docs/API-DOCUMENTATION.md` fixed
- [ ] #20 `apps/vuln-api/README.md`: link to `../DOCUMENTATION.md` removed or corrected
- [ ] #21 `apps/vuln-api/README.md`: endpoint count aligned to 469
- [ ] #22 `apps/vuln-api/AGENTS.md`: non-existent `tests/vulnerability` and `tests/smoke` removed
- [ ] #23 `apps/vuln-api/AGENTS.md`: `security.py` reference corrected to `security_config.py`
- [ ] #24 `apps/vuln-api/API-DOCUMENTATION.md`: footer count corrected to 469
- [ ] #25 `apps/vuln-api/API-DOCUMENTATION.md`: non-existent `tests/vulnerability/` tree removed
- [ ] #26 `apps/vuln-api/API-DOCUMENTATION.md`: `tests/pytest.ini` and `tests/justfile` lines removed
- [ ] #27 `apps/vuln-api/API-DOCUMENTATION.md`: `api-demo` directory references corrected to `apps/vuln-api`
- [ ] #28 `apps/vuln-api/API-DOCUMENTATION.md`: `ENABLE_VULNERABILITIES` replaced with `DEMO_MODE=full`
- [ ] #29 `apps/vuln-api/tests/README.md`: non-existent unit test files removed from listing
- [ ] #30 `apps/vuln-api/tests/README.md`: non-existent integration test files removed from listing
- [ ] #31 `apps/vuln-api/tests/README.md`: non-existent `tests/vulnerability/` tree removed
- [ ] #32 `apps/vuln-api/tests/README.md`: `pytest.ini`/`run_tests.sh`/`justfile` removed from `tests/` listing
- [ ] #33 `apps/vuln-api/tests/README.md`: `./run_tests.sh --quick` corrected to `./scripts/run_tests.sh smoke`
- [ ] #34 `apps/vuln-api/tests/README.md`: coverage gate corrected from 90% to 80%
- [ ] #35 `apps/vuln-api/tests/README.md`: conftest fixture names corrected
- [ ] #36 `apps/vuln-api/tests/README.md`: `pip install -r requirements.txt` replaced with `uv sync`
- [ ] #37 `apps/vuln-api/tests/README.md`: `create_app('testing')` / `.test_client()` patterns corrected
- [ ] #38 All linked claims verified against current code
<!-- AC:END -->
