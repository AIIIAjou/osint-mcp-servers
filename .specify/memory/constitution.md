<!--
Sync Impact Report - Constitution v2.0.0
========================================
Version change: 1.0.0 → 2.0.0 (MINOR - Domain-specific OSINT MCP principles added)

Modified Principles:
  - Core Principles (5) → OSINT MCP Principles (9)
  - Added: MCP Server Architecture, Debug-First Development, API Key Management, Error Handling & Logging, Testing Standards, Code Consistency, Documentation Requirements, Deployment Readiness, Korean Context Considerations

Added Sections:
  - MCP Server Architecture Standards
  - Testing & Validation Framework
  - API Key Management Policy
  - Korean Language & Context Support

Removed Sections:
  - Generic Performance & Scalability Standards (integrated into MCP Architecture)
  - Generic User Experience Consistency (replaced with MCP-specific patterns)

Templates Updated Status:
  ✅ plan-template.md - Constitution Check section updated for MCP principles
  ✅ spec-template.md - Includes MCP server/JSON-RPC requirements
  ✅ tasks-template.md - Task phases include MCP server testing gates

Follow-up TODOs: None - all placeholders resolved for academic capstone context.
-->

# OSINT MCP Server Constitution

## Project Context

**Institution**: Ajou University
**Project Type**: 16-week academic capstone (CTI/OSINT automation)
**Team Size**: 3 developers (OSINT/MCP, Web Frontend, LLM Engine)
**Industry Partner**: Kuntec (final demo required)
**Technology Stack**: Python 3.11, FastAPI, JSON-RPC 2.0, Docker, AWS EC2
**Integration Targets**: OpenAI Agent Builder, Claude Desktop

---

## Core Principles

### I. MCP Server Architecture – JSON-RPC 2.0 First

All OSINT tools MUST be wrapped as independent MCP servers adhering to Model Context Protocol standards. Each server is a discrete, deployable unit supporting both stdio (Claude Desktop) and HTTP (OpenAI Agent Builder) protocols.

**Non-Negotiable Rules:**

- Every OSINT tool integration MUST be implemented as a separate MCP server (`server.py`)
- All servers MUST implement JSON-RPC 2.0 protocol with proper error codes and structured responses
- FastAPI HTTP REST API MUST be provided for OpenAI Agent Builder compatibility (alongside stdio)
- Server endpoints MUST follow naming convention: `/mcp/{tool_name}` (e.g., `/mcp/shodan`, `/mcp/harvester`)
- Response format MUST be JSON-RPC 2.0 compliant: `{ "jsonrpc": "2.0", "id": <id>, "result": <data> }` or `{ "error": { "code": <code>, "message": <msg> } }`
- Each server MUST include health check endpoint: `GET /health` returning `{ "status": "ready" }`
- Servers MUST support stdio mode for Claude Desktop integration without HTTP server

**Rationale**: Modular MCP servers enable parallel development, independent testing, flexible deployment, and seamless integration with multiple LLM platforms (Claude, OpenAI). JSON-RPC 2.0 is language-agnostic and enables proper error handling across heterogeneous systems.

---

### II. Debug-First Development – Explicit TEST_MODE / DEBUG_MODE

Every MCP server MUST support a DEBUG_MODE environment variable enabling mock data responses without making real external API calls. This enables rapid development, testing, and demo preparation without incurring API costs or rate limits.

**Non-Negotiable Rules:**

- DEBUG_MODE=true MUST return realistic mock data (valid schema, representative samples) without calling external APIs
- Mock data MUST be stored in `mock_data/` directory within each server (e.g., `mock_data/shodan_results.json`)
- Mock responses MUST be morphologically identical to real API responses (same field names, types, nesting)
- DEBUG_MODE MUST be controllable via environment variable; no code changes required to toggle
- Test data MUST include edge cases: empty results, partial errors, malformed records
- When DEBUG_MODE=false and REAL_API_CALLS=true, MUST emit warning: "⚠️  Using REAL API calls – verify credentials and rate limits"
- Logging MUST clearly indicate "MOCK MODE" or "LIVE MODE" at startup

**Rationale**: Mock-driven testing prevents accidental charges, rate limit exhaustion, and demo failures due to API outages. Realistic mock data ensures LLM prompt engineering and integration testing work correctly before production.

---

### III. API Key Management – Environment-Only Storage

All external API credentials (Shodan, Intelligence X, Harvester, etc.) MUST be managed strictly via environment variables. No hardcoded keys, no git-tracked credentials, no runtime prompts for sensitive data.

**Non-Negotiable Rules:**

- All API keys MUST be loaded from environment variables only (never hardcoded, never in config files)
- `.env` file MUST be listed in `.gitignore` and NEVER committed
- `.env.example` MUST document required keys without values: `SHODAN_API_KEY=<your-key-here>`
- README MUST include "API Key Setup" section with clear instructions for each tool
- Missing API keys in LIVE_MODE MUST raise explicit error: "Missing required API key: SHODAN_API_KEY – set via environment"
- API keys MUST NOT appear in logs, error messages, or debug output (log placeholder: `API_KEY=***`)
- Rotation/revocation MUST be documented in project README with expiration guidance
- AWS credentials for EC2 deployment MUST use IAM roles (never hardcoded access keys)

**Rationale**: Environment-based secrets prevent credential leaks via git, enable safe CI/CD, reduce attack surface, and comply with security best practices. Clear documentation prevents accidental exposure during team handoff.

---

### IV. Error Handling & Structured Logging

All API calls, network operations, and data parsing MUST include comprehensive exception handling. Errors MUST be logged with full context (stack trace, input, request ID) in structured JSON format. User-facing error messages MUST be actionable.

**Non-Negotiable Rules:**

- Every external API call MUST have try/except block with specific exception types (TimeoutError, ConnectionError, ValueError, etc.)
- Errors MUST be logged as structured JSON: `{ "timestamp": "ISO-8601", "level": "ERROR", "request_id": "uuid", "message": "...", "context": {...}, "traceback": "..." }`
- Error messages exposed to LLM MUST be user-friendly: "Shodan API rate limit exceeded. Retry in 1 hour." (not raw exception stack)
- Timeouts MUST have explicit limits: default 30s for HTTP, 10s for DNS queries
- Failed API calls MUST be retried with exponential backoff (max 3 retries, 1s → 2s → 4s delays)
- Logging level MUST be configurable: LOG_LEVEL env var (DEBUG, INFO, WARNING, ERROR)
- Request IDs MUST be generated (UUID) and propagated through all logs for distributed tracing
- All logs to stdout/stderr (no file-only logging without also printing to console)

**Rationale**: Structured logging enables rapid debugging, automated alerting, and root cause analysis in production. Actionable error messages improve LLM decision-making and user experience. Traceability is critical for integration issues across multiple MCP servers.

---

### V. Testing Standards – Contract, Integration, & Pipeline Validation

Each MCP server MUST include test scripts (bash/Python) covering contract-level API behavior, integration with dependent servers, and multi-step OSINT pipelines. Tests MUST be executable independently without external API dependencies.

**Non-Negotiable Rules:**

- Contract tests MUST verify endpoint schemas, JSON-RPC format, HTTP status codes: `tests/contract/test_shodan.py`
- Integration tests MUST validate end-to-end flows: e.g., "Fetch domain → resolve IPs → query Shodan" in `tests/integration/test_pipeline.py`
- Test scripts MUST use DEBUG_MODE=true to avoid external API calls
- Each server MUST include bash test script: `tests/test_server.sh` executable via `bash tests/test_server.sh`
- Pipeline validation MUST test sequential tool execution: Intelligence X → TheHarvester → Shodan (with mock data)
- Tests MUST include failure scenarios: empty results, partial errors, API timeouts
- Test coverage MUST be ≥70% for core server logic (pytest coverage report)
- Tests MUST be executable in CI/CD without external secrets (mock mode only)
- Pytest config MUST be in `pytest.ini` with markers for `@pytest.mark.contract`, `@pytest.mark.integration`

**Rationale**: Comprehensive testing catches integration issues early, enables safe refactoring, validates API contract changes, and ensures pipelines work end-to-end. Mock-driven tests are repeatable, fast, and safe for CI.

---

### VI. Code Consistency & Server Patterns

All MCP servers MUST follow the same structural and naming patterns to reduce cognitive load and enable rapid onboarding. Client classes, Pydantic models, and endpoint naming MUST be uniform across all tools.

**Non-Negotiable Rules:**

- Each server MUST follow directory structure:
  ```
  server/
  ├── server.py              # Main MCP/FastAPI entry point
  ├── client.py              # API client class (e.g., ShodanClient)
  ├── models.py              # Pydantic models for requests/responses
  ├── utils.py               # Helpers (logging, retry, parsing)
  ├── mock_data/             # JSON files for DEBUG_MODE
  ├── tests/
  │   ├── contract/          # Schema/endpoint tests
  │   ├── integration/       # Pipeline tests
  │   └── test_server.sh     # Bash test runner
  └── README.md              # Setup & API docs
  ```
- Client classes MUST follow pattern: `class ShodanClient: def __init__(self, api_key), def search(...), def query_ip(...)`
- Pydantic models MUST be used for all request/response validation: `class ShodanResponse(BaseModel): results: List[Dict]`
- Endpoint naming MUST be: `/mcp/{tool_name}/search`, `/mcp/{tool_name}/query`, etc. (consistent verbs across servers)
- Function naming MUST be snake_case; class naming MUST be PascalCase
- Imports MUST be organized: stdlib → third-party → local (per PEP 8)
- Type hints MUST be present on all function signatures

**Rationale**: Consistent patterns enable new servers to be added rapidly, reduce context-switching for team, and make integration testing simpler. Pydantic models catch schema errors early.

---

### VII. Documentation Requirements – Setup, Endpoints, Examples

Each server MUST include clear, concise documentation covering setup instructions, API endpoint reference, and runnable example requests/responses.

**Non-Negotiable Rules:**

- README MUST include sections: "Quick Start", "API Key Setup", "Running the Server", "Example Requests", "Error Codes", "Testing"
- README MUST document every endpoint:
  - HTTP method, path, query parameters
  - Example request (curl or Python)
  - Example response (JSON)
  - Error cases and codes
- Example requests MUST be executable: `curl -X GET http://localhost:8000/mcp/shodan/search?query=...`
- API documentation SHOULD be generated from code (OpenAPI/Swagger for FastAPI servers)
- Docstrings MUST be present on all classes and public functions
- Comments MUST explain "why", not "what" (code is self-documenting if clear)
- Deployment docs MUST include Docker build/run commands and AWS ECS configuration example
- Troubleshooting section MUST document common errors (missing keys, rate limits, network timeouts)

**Rationale**: Clear documentation enables rapid integration by LLM engineers and frontend team. Runnable examples reduce setup friction and enable self-serve testing.

---

### VIII. Deployment Readiness – Docker & AWS ECS

All MCP servers MUST be containerized and deployable to AWS ECS. Deployment configuration MUST be version-controlled and include health checks for monitoring.

**Non-Negotiable Rules:**

- Each server MUST include `Dockerfile` with multi-stage build (minimize image size)
- Dockerfile MUST expose port (default 8000) and include health check: `HEALTHCHECK --interval=30s --timeout=10s CMD curl -f http://localhost:8000/health || exit 1`
- Docker image MUST be built with: `docker build -t osint-{tool}:latest .`
- Docker Compose file MUST be provided for local multi-server testing: `docker-compose.yml` with all servers
- AWS ECS task definition MUST be included (JSON): `ecs-task-definition.json` with CPU/memory specifications
- Environment variables MUST be injected at runtime (not hardcoded in image)
- Container logs MUST go to stdout/stderr for CloudWatch integration
- Deployment MUST support zero-downtime updates (health checks must pass before routing traffic)
- README MUST include deploy commands: `docker push`, ECS update instructions

**Rationale**: Containerization ensures reproducibility across dev/test/prod. ECS integration enables scalability for the capstone demo and future production use. Health checks prevent serving stale data.

---

### IX. Korean Context Considerations – Character Encoding & Localization

When applicable, servers MUST support Korean text processing and provide Korean language documentation for the Ajou University team.

**Non-Negotiable Rules:**

- All text processing MUST explicitly use UTF-8 encoding: `encoding='utf-8'` in file I/O, HTTP requests
- Mock data MUST include Korean examples where relevant: `"company": "한국 사이버보안 회사"`
- Error messages displayed to team MAY include Korean alongside English for clarity
- README MUST have Korean translation or bilingual sections for API key setup
- Web scraping (if applicable) MUST handle Korean character encodings in HTML parsing (BeautifulSoup with UTF-8)
- Search queries against Korean platforms (Naver, Daum) MUST be supported if integration is planned
- Logs and timestamps MUST use ISO-8601 format (timezone-neutral)

**Rationale**: Korean context support reduces friction for Ajou team, enables testing against Korean threat intelligence sources, and improves usability for final demo with Kuntec.

---

## MCP Server Architecture Standards

### Dual-Protocol Support (Stdio + HTTP)

Every MCP server MUST support both protocols:

1. **Stdio Mode** (Claude Desktop)
   - Reads JSON-RPC messages from stdin
   - Writes JSON-RPC responses to stdout
   - Errors written to stderr
   - Entry point: `python server.py`

2. **HTTP Mode** (OpenAI Agent Builder)
   - FastAPI application listening on port 8000
   - Endpoints: `POST /mcp/{tool_name}/*` for RPC, `GET /health` for liveness
   - CORS enabled for cross-origin requests
   - Entry point: `uvicorn server:app --host 0.0.0.0 --port 8000`

### Response Schema

All endpoints MUST return JSON-RPC 2.0 format:

```json
{
  "jsonrpc": "2.0",
  "id": "<request-id>",
  "result": {
    "status": "success",
    "data": { /* actual results */ },
    "metadata": {
      "source": "shodan",
      "timestamp": "2025-11-11T00:00:00Z",
      "query_time_ms": 123
    }
  }
}
```

Error responses:

```json
{
  "jsonrpc": "2.0",
  "id": "<request-id>",
  "error": {
    "code": -32000,
    "message": "Shodan API key invalid",
    "data": {
      "details": "401 Unauthorized",
      "remediation": "Set SHODAN_API_KEY environment variable"
    }
  }
}
```

---

## Testing & Validation Framework

### Test Execution Order

1. **Unit Tests**: `pytest tests/unit/ -v`
2. **Contract Tests**: `pytest tests/contract/ -v` (schema, endpoint format)
3. **Integration Tests**: `pytest tests/integration/ -v` (multi-server pipelines)
4. **Pipeline Tests**: `bash tests/test_pipeline.sh` (end-to-end OSINT workflows)

### Test Coverage Gates

- Core server logic: ≥70% coverage
- API endpoints: 100% coverage (contract tests)
- Client classes: ≥80% coverage
- Utils/helpers: ≥60% coverage

### Mock Data Validation

Mock data MUST be validated against schema:

```bash
python -m jsonschema mock_data/shodan_results.json \
  --schema tests/schemas/shodan_response.json
```

---

## API Key Management Policy

### Setup Checklist

For each OSINT tool, team MUST:

1. Create `.env` file from `.env.example` template
2. Obtain API key (tool-specific instructions in README)
3. Verify key works: `DEBUG_MODE=false python -c "from client import ShodanClient; c = ShodanClient(); c.health_check()"`
4. Never commit `.env` to git
5. Document key expiration/rotation schedule

### CI/CD Integration

- GitHub Actions MUST run tests with `DEBUG_MODE=true` (no real API calls)
- Production deployment MUST inject keys via AWS Secrets Manager or environment variables
- Key rotation MUST not require code changes (update environment only)

---

## Governance

### Constitution Authority & Amendments

This constitution supersedes all other project practices and development guidelines for the OSINT MCP server capstone. Amendments require:

1. **Proposal**: Submit amendment with rationale and impact analysis (team discussion)
2. **Review**: Team consensus (minimum 2 of 3 developers approve)
3. **Documentation**: Update constitution with clear change description
4. **Migration Plan**: Specify how existing servers must be updated (if breaking)
5. **Audit**: Ensure all active servers comply within 1 week of ratification

### Compliance Verification

- Pull request reviews MUST verify compliance with Principles I–IX
- Violations MUST be addressed before merge (no exceptions)
- Test failures block merge (all tests must pass)
- Missing documentation blocks merge
- Code review checklist MUST include: "Principle IX compliance check" for Korean context (if applicable)

### Version & Semantic Meaning

This constitution uses semantic versioning:

- **MAJOR**: Principle removal, redefinition, or incompatible governance changes
- **MINOR**: New principle added, significant clarification, domain shift (e.g., OSINT → general MCP)
- **PATCH**: Clarifications, wording refinements, non-semantic rule adjustments

**Version**: 2.0.0 | **Ratified**: 2025-11-11 | **Last Amended**: 2025-11-11

---

## Quick Reference: Principle Checklist

When creating a new MCP server, verify:

- [ ] **I**: Server is MCP-compliant, JSON-RPC 2.0, supports stdio + HTTP
- [ ] **II**: DEBUG_MODE implemented, mock data in `mock_data/`, no live API calls in test mode
- [ ] **III**: API keys in `.env`, `.env.example` provided, README has key setup instructions
- [ ] **IV**: All API calls wrapped in try/except, structured JSON logging, actionable error messages
- [ ] **V**: Contract + integration tests, pipeline validation, ≥70% coverage, tests pass with DEBUG_MODE
- [ ] **VI**: Follows directory structure, Client/Pydantic patterns, consistent naming, type hints
- [ ] **VII**: README with Quick Start, API docs, examples, troubleshooting
- [ ] **VIII**: Dockerfile with health check, Docker Compose support, ECS task definition, deployment docs
- [ ] **IX**: UTF-8 encoding, Korean examples (if applicable), bilingual error messages (if applicable)

