---
id: TASK-17
title: 'Docs: Doc-claim drift detected 2026-07-20'
status: To Do
assignee: []
created_date: '2026-07-20 00:00'
updated_date: '2026-07-20 00:00'
labels:
  - docs
dependencies: []
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Automated doc-claim audit run on 2026-07-20 across 12 doc files. Found **19 verified drift findings** in 8 of the 12 files. Findings are grouped below by severity and file. None of the 12 target files were modified — this task records what to fix.

### Summary counts
- P0 (user-facing factual error): 1
- P1 (dev-doc error, wrong claim): 13
- P2 (minor staleness / internal inconsistency): 5

---

### docs/api-reference.md — 1 finding

- **docs/api-reference.md:267-271** — GenAI table lists four endpoints (`/api/v1/genai/complete`, `/api/v1/genai/models`, `/api/v1/genai/embeddings`, plus `/api/v1/genai/chat`) — only `/api/v1/genai/chat` actually exists; the other three do not. The real routes are `/api/v1/genai/knowledge/upload`, `/api/v1/genai/agent/browse`, `/api/v1/genai/models/config`, and `/api/v1/genai/graphql`. — **Proposed fix**: replace the GenAI table with the four routes confirmed in `app/blueprints/genai/routes.py`; add `/api/v1/genai/graphql`. **[P0]**

---

### docs/architecture.md — 3 findings

- **docs/architecture.md:165** — `| DEMO_MODE | true | ...` — Default shown as `true` (a boolean string), but `app/config.py:31` reads `os.environ.get('DEMO_MODE', 'full')`, making the actual default `full`. — **Proposed fix**: change default column from `true` to `full`. **[P1]**

- **docs/architecture.md:88-116** — Blueprint directory tree listing omits the `education/` package. The directory `app/blueprints/education/` exists and `education_router` is imported and mounted in `create_app()` (asgi.py:185,231). — **Proposed fix**: add `├── education/` to the tree with an appropriate description. **[P1]**

- **docs/architecture.md:110** — `genai/` listed as "(4 routes)" — `app/blueprints/genai/routes.py` registers 5 routes (chat, knowledge/upload, agent/browse, models/config, graphql). — **Proposed fix**: change "(4 routes)" to "(5 routes)". **[P2]**

---

### docs/developer-guide.md — 2 findings

- **docs/developer-guide.md:47** — `| DEMO_MODE | strict | ...` — Default listed as `strict` but `app/config.py:31` shows actual default is `full`. — **Proposed fix**: change `strict` to `full` in the Default column. **[P1]**

- **docs/developer-guide.md:151** — Claims "`force-include` ensuring `web_dist/` makes it into the wheel despite being gitignored" — `apps/vuln-api/pyproject.toml` has no `force-include` directive; `web_dist/` is picked up by `packages = ["app"]` when present. — **Proposed fix**: remove or correct the `force-include` claim. **[P2]**

---

### docs/endpoints-catalog.md — 2 findings

- **docs/endpoints-catalog.md:15** — `"verified against the live route table via \`just docs-drift\`"` — No `docs-drift` recipe exists in either `justfile` (root) or `apps/vuln-api/justfile`. The vuln-api justfile has `docs-check` and `docs-check-fedramp`. — **Proposed fix**: replace `just docs-drift` with `just docs-check` (or the actual recipe name). **[P1]**

- **docs/endpoints-catalog.md:15,590** — Document claims 469 total endpoints. README.md, AGENTS.md, docs/dockerhub-overview.md, and apps/vuln-api/README.md all report 456+. Internal inconsistency across the doc set. — **Proposed fix**: reconcile to a single count or convert to "456+" form. **[P2]**

---

### docs/dockerhub-overview.md — 1 finding

- **docs/dockerhub-overview.md:22** — `| DEMO_MODE | strict | ...` — Default listed as `strict` but `app/config.py:31` shows actual default is `full`. — **Proposed fix**: change `strict` to `full` in the Default column. **[P1]**

---

### README.md — 2 findings

- **README.md:48** — `| DEMO_MODE | strict | ...` — Default listed as `strict` but `app/config.py:31` shows actual default is `full`. — **Proposed fix**: change `strict` to `full` in the Default column. **[P1]**

- **README.md:243-244** — Commands `make -C apps/vuln-api test-unit`, `make -C apps/vuln-api test-quick`, `make -C apps/vuln-api test-vulnerability`, `make -C apps/vuln-api test-smoke` — no `Makefile` exists in `apps/vuln-api/`; the project uses `just`. — **Proposed fix**: replace `make -C apps/vuln-api <target>` with `just -f apps/vuln-api/justfile <target>`. **[P1]**

---

### AGENTS.md — 2 findings

- **AGENTS.md:116** — `"In production (Docker), nginx handles the proxy."` — Both `Dockerfile.prod` and `Dockerfile.fargate` invoke uvicorn directly with no nginx layer. — **Proposed fix**: remove or correct the nginx claim; production proxy is uvicorn. **[P1]**

- **AGENTS.md:95** — `"full (vulns active) vs strict (safe mode, default)"` — States `strict` is the default but `app/config.py:31` shows `full` is the code default. — **Proposed fix**: change "default" label from `strict` to `full`. **[P1]**

---

### apps/vuln-api/tests/README.md — 5 findings

- **apps/vuln-api/tests/README.md:65-68** — Lists `tests/vulnerability/` directory and sub-files (`test_sql_injection.py`, `test_xss.py`, etc.) — this directory does not exist under `apps/vuln-api/tests/`. — **Proposed fix**: remove the listing or create the directory and move/create the files. **[P1]**

- **apps/vuln-api/tests/README.md:74-76** — File tree shows `tests/pytest.ini`, `tests/run_tests.sh`, and `tests/justfile` inside the `tests/` directory — none of these files exist at that path. — **Proposed fix**: update file tree to reflect actual test layout. **[P2]**

- **apps/vuln-api/tests/README.md:234** — Fixture table lists `auth_headers`, `sample_data`, `mock_services` — none of these fixtures exist in `apps/vuln-api/tests/conftest.py`. Real fixtures include `client`, `remote_client`, `set_session`, `read_session`, `mock_users`, `mock_medical_records`, `sample_user`, `mfa_user`, `demo_mode_full`, `demo_mode_strict`, `sql_injection_payloads`, `command_injection_payloads`. — **Proposed fix**: replace stale fixture table with fixtures from conftest.py. **[P1]**

- **apps/vuln-api/tests/README.md:213-215** — Coverage requirements state "Minimum overall: 90%, New code: 95%, Critical paths: 100%" — `apps/vuln-api/justfile:48` enforces `--cov-fail-under=80` and `docs/developer-guide.md` also documents 80% minimum. — **Proposed fix**: correct to 80% minimum to match justfile gate. **[P2]**

- **apps/vuln-api/tests/README.md:138** — Shows `pytest -m security` as a test marker — the actual markers defined and used are `vulnerability`, `integration`, `smoke` (see justfile and developer-guide.md). `security` is not a registered marker. — **Proposed fix**: change `pytest -m security` to `pytest -m vulnerability`. **[P1]**

<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria

<!-- AC:BEGIN -->
- [ ] #1 `docs/api-reference.md` GenAI table corrected to match actual routes in `app/blueprints/genai/routes.py` (P0)
- [ ] #2 `docs/architecture.md:165` DEMO_MODE default changed from `true` to `full`
- [ ] #3 `docs/architecture.md` blueprint tree updated to include `education/` package
- [ ] #4 `docs/architecture.md:110` genai route count updated from 4 to 5
- [ ] #5 `docs/developer-guide.md:47` DEMO_MODE default changed from `strict` to `full`
- [ ] #6 `docs/developer-guide.md:151` force-include claim removed or corrected
- [ ] #7 `docs/endpoints-catalog.md:15` `just docs-drift` replaced with correct recipe name
- [ ] #8 Endpoint count (469 vs 456+) reconciled across all affected files
- [ ] #9 `docs/dockerhub-overview.md:22` DEMO_MODE default changed from `strict` to `full`
- [ ] #10 `README.md:48` DEMO_MODE default changed from `strict` to `full`
- [ ] #11 `README.md:243-244` make commands replaced with equivalent `just -f apps/vuln-api/justfile` commands
- [ ] #12 `AGENTS.md:116` nginx proxy claim corrected (uvicorn handles production serving)
- [ ] #13 `AGENTS.md:95` DEMO_MODE default corrected from `strict` to `full`
- [ ] #14 `apps/vuln-api/tests/README.md` `tests/vulnerability/` directory reference removed or directory created
- [ ] #15 `apps/vuln-api/tests/README.md` file tree corrected to reflect actual paths
- [ ] #16 `apps/vuln-api/tests/README.md:234` fixture table replaced with fixtures from actual conftest.py
- [ ] #17 `apps/vuln-api/tests/README.md:213-215` coverage floor corrected from 90% to 80%
- [ ] #18 `apps/vuln-api/tests/README.md:138` pytest marker corrected from `security` to `vulnerability`
- [ ] #19 All linked claims verified against current code after fixes applied
<!-- AC:END -->
