# Steward

Steward is an authorization and audit framework for LLM agents that use the Model Context Protocol. It sits between an agent and external MCP tools, evaluates each requested tool call against scoped policies, and records a complete audit trail of every allow or deny decision.

The goal is simple: agents should not receive blanket OAuth grants when they only need permission to perform a specific action with specific arguments.

```text
LLM agent -> Steward -> policy decision -> MCP tool execution -> audit event
```

## Why Steward Exists

Most agent integrations treat authorization too broadly. Once an agent receives an OAuth token, it may be able to call many APIs or tools that are unrelated to the current task. Steward narrows that access model.

Steward provides:

- Per-action permission checks before a tool call is executed
- Least-privilege scopes for MCP servers and tools
- Explicit deny precedence for high-risk operations
- Argument-level policy constraints
- Expiring policies
- JWT/OAuth-style subject identity
- Full audit logging for allowed, denied, and failed downstream calls
- An evaluation runner for testing agent behavior under different policy constraints

## Current Status

This repository contains a working Python MVP:

- FastAPI REST service
- SQLAlchemy persistence layer
- Alembic migration scaffold
- Policy evaluation engine
- JWT principal extraction
- Audit event storage with argument redaction
- MCP/downstream proxy abstraction
- Evaluation scenario runner
- Docker and Docker Compose setup
- Pytest coverage for core policy behavior

The downstream MCP transport is intentionally abstracted in the MVP. The proxy route currently returns an authorized call envelope. To connect live tools, plug an MCP SDK transport into the `authorize_and_call` downstream adapter.

## Architecture

```mermaid
flowchart LR
    Agent[LLM Agent] -->|Bearer JWT + tool call| Steward[Steward API]
    Steward --> Auth[JWT / OAuth Identity]
    Steward --> Policy[Policy Engine]
    Policy --> Store[(Policy Store)]
    Policy --> Decision{Allowed?}
    Decision -->|No| Deny[Return 403]
    Decision -->|Yes| Proxy[MCP Proxy Adapter]
    Proxy --> MCP[MCP Server / Tool]
    Deny --> Audit[(Audit Log)]
    Proxy --> Audit
```

### Request Lifecycle

```mermaid
sequenceDiagram
    participant Agent as LLM Agent
    participant API as Steward API
    participant Auth as Auth Layer
    participant Policy as Policy Engine
    participant Tool as MCP Tool
    participant Audit as Audit Log

    Agent->>API: POST /v1/proxy/{server}/tools/{tool}
    API->>Auth: Extract subject from Bearer token
    Auth-->>API: subject
    API->>Policy: Evaluate subject + server + tool + arguments
    Policy-->>API: allow / deny decision
    alt Denied
        API->>Audit: Record denied event
        API-->>Agent: 403 Forbidden
    else Allowed
        API->>Tool: Execute downstream tool call
        Tool-->>API: Result or error
        API->>Audit: Record allowed event and downstream status
        API-->>Agent: Tool result
    end
```

## Repository Layout

```text
.
├── alembic/                    # Database migration environment
│   ├── env.py
│   └── versions/
│       └── 0001_initial.py
├── examples/
│   └── scenarios.json          # Sample evaluation scenarios
├── steward/
│   ├── audit.py                # Audit event creation and redaction
│   ├── auth.py                 # Bearer JWT principal extraction
│   ├── config.py               # Environment-based settings
│   ├── db.py                   # Async SQLAlchemy setup
│   ├── evaluate.py             # Evaluation scenario runner
│   ├── main.py                 # FastAPI routes
│   ├── models.py               # SQLAlchemy models
│   ├── policy.py               # Policy matching and decisions
│   ├── proxy.py                # Authorization wrapper around downstream calls
│   └── schemas.py              # Pydantic request/response models
├── tests/
│   └── test_policy.py          # Policy engine tests
├── .env.example
├── alembic.ini
├── docker-compose.yml
├── Dockerfile
├── pyproject.toml
└── README.md
```

## Core Concepts

### Subject

The subject is the authenticated caller. In practice this is usually an agent identity, user identity, service account, or delegated OAuth subject. Steward reads it from the JWT `sub` claim.

Example:

```json
{
  "sub": "agent-a"
}
```

### Server

The MCP server or external tool provider the agent wants to access.

Examples:

- `crm`
- `github`
- `slack`
- `database`

### Tool

The specific action being requested on a server.

Examples:

- `contacts.read`
- `issues.create`
- `messages.send`
- `query.run`

### Policy

A policy grants or denies one kind of action. Policies can match exact subjects, wildcard subjects, exact tools, wildcard tools, and argument constraints.

Steward evaluates active policies and applies this order:

1. Ignore expired policies
2. Find policies matching subject, server, tool, and conditions
3. If any matching policy has `effect = deny`, deny the call
4. If any matching policy has `effect = allow`, allow the call
5. Otherwise deny by default

## Policy Model

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | string | Yes | Unique policy name |
| `effect` | `allow` or `deny` | Yes | Whether matching calls are allowed or denied |
| `subject` | string | Yes | Exact subject or `*` wildcard |
| `server` | string | Yes | MCP server pattern |
| `tool` | string | Yes | Tool/action pattern |
| `conditions` | object | No | Argument-level constraints |
| `expires_at` | datetime | No | Optional policy expiration |
| `active` | boolean | System | Soft-revocation flag |

### Example Allow Policy

```json
{
  "name": "agent-a-read-crm",
  "effect": "allow",
  "subject": "agent-a",
  "server": "crm",
  "tool": "contacts.read",
  "conditions": {}
}
```

### Example Explicit Deny Policy

```json
{
  "name": "block-agent-a-delete",
  "effect": "deny",
  "subject": "agent-a",
  "server": "crm",
  "tool": "contacts.delete",
  "conditions": {}
}
```

### Example Argument-Constrained Policy

This allows `agent-a` to send Slack messages only when the channel is `support` and the message length is at most 500 characters.

```json
{
  "name": "agent-a-send-short-support-message",
  "effect": "allow",
  "subject": "agent-a",
  "server": "slack",
  "tool": "messages.send",
  "conditions": {
    "channel": {
      "equals": "support"
    },
    "message_length": {
      "max": 500
    }
  }
}
```

### Supported Conditions

| Condition | Meaning | Example |
| --- | --- | --- |
| `equals` | Argument must equal a value | `{ "region": { "equals": "us-east-1" } }` |
| `in` | Argument must be one of several values | `{ "env": { "in": ["dev", "staging"] } }` |
| `min` | Numeric argument must be greater than or equal to a value | `{ "limit": { "min": 1 } }` |
| `max` | Numeric argument must be less than or equal to a value | `{ "limit": { "max": 100 } }` |
| `required` | Argument must be present | `{ "ticket_id": { "required": true } }` |

Plain equality is also supported:

```json
{
  "conditions": {
    "region": "us-east-1"
  }
}
```

## Local Setup

### Prerequisites

- Python 3.11 or newer
- PowerShell, Bash, or another shell
- Docker, optional but recommended for PostgreSQL

### Install

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

### Configure

Copy the example environment file:

```powershell
Copy-Item .env.example .env
```

Default development settings use SQLite:

```env
DATABASE_URL=sqlite+aiosqlite:///./steward.db
JWT_ISSUER=
JWT_AUDIENCE=
JWT_JWKS_URL=
JWT_ALGORITHMS=RS256
ENVIRONMENT=development
AUDIT_ARGUMENT_REDACTION_KEYS=password,token,secret,authorization
```

In development mode, Steward accepts unsigned JWTs only when `JWT_ISSUER` is empty. Outside that mode, configure `JWT_JWKS_URL` so tokens are verified against a real signing key.

### Run

```powershell
uvicorn steward.main:app --reload
```

Open the API docs:

```text
http://127.0.0.1:8000/docs
```

Health check:

```powershell
curl http://127.0.0.1:8000/health
```

Expected response:

```json
{
  "status": "ok"
}
```

## Docker

Run the API and PostgreSQL:

```powershell
docker compose up --build
```

The API listens on:

```text
http://127.0.0.1:8000
```

PostgreSQL is provided by `docker-compose.yml`. For production, use managed PostgreSQL or a hardened database deployment instead of the local Compose service.

## Database Migrations

Steward includes an Alembic baseline migration.

Run migrations:

```powershell
alembic upgrade head
```

Create a new migration after model changes:

```powershell
alembic revision --autogenerate -m "describe change"
```

The application also creates tables on startup for simple local development, but migrations should be used for production deployments.

## API Reference

### `GET /health`

Checks service health.

Response:

```json
{
  "status": "ok"
}
```

### `POST /v1/policies`

Creates a policy.

Request:

```json
{
  "name": "agent-a-read-crm",
  "effect": "allow",
  "subject": "agent-a",
  "server": "crm",
  "tool": "contacts.read",
  "conditions": {}
}
```

Response:

```json
{
  "id": "generated-policy-id",
  "name": "agent-a-read-crm",
  "version": 1,
  "effect": "allow",
  "subject": "agent-a",
  "server": "crm",
  "tool": "contacts.read",
  "conditions": {},
  "expires_at": null,
  "active": true,
  "created_at": "2026-08-10T12:00:00Z"
}
```

### `GET /v1/policies`

Lists policies.

### `DELETE /v1/policies/{policy_id}`

Soft-revokes a policy by marking it inactive.

### `POST /v1/check`

Evaluates a tool call without executing it.

Request:

```json
{
  "subject": "agent-a",
  "server": "crm",
  "tool": "contacts.read",
  "arguments": {
    "contact_id": "123"
  }
}
```

Response:

```json
{
  "allowed": true,
  "reason": "allow policy matched",
  "matched_policy_ids": ["generated-policy-id"]
}
```

### `POST /v1/proxy/{server}/tools/{tool}`

Authorizes and executes a downstream tool call.

Headers:

```text
Authorization: Bearer <jwt>
```

Request body:

```json
{
  "contact_id": "123"
}
```

Current MVP response:

```json
{
  "tool": "contacts.read",
  "arguments": {
    "contact_id": "123"
  },
  "status": "authorized"
}
```

In a production integration, this route should forward to the selected MCP server through an MCP SDK transport after `authorize_and_call` returns an allow decision.

### `GET /v1/audit`

Lists audit events. Results are newest first.

Optional query parameters:

| Parameter | Description |
| --- | --- |
| `principal` | Filter events for a subject |
| `limit` | Maximum events to return, capped at 500 |

Example:

```powershell
curl "http://127.0.0.1:8000/v1/audit?principal=agent-a&limit=50"
```

## End-to-End Example

### 1. Start Steward

```powershell
uvicorn steward.main:app --reload
```

### 2. Create an Allow Policy

```powershell
curl -X POST http://127.0.0.1:8000/v1/policies `
  -H "Content-Type: application/json" `
  -d '{
    "name": "agent-a-read-crm",
    "effect": "allow",
    "subject": "agent-a",
    "server": "crm",
    "tool": "contacts.read",
    "conditions": {}
  }'
```

### 3. Check the Decision

```powershell
curl -X POST http://127.0.0.1:8000/v1/check `
  -H "Content-Type: application/json" `
  -d '{
    "subject": "agent-a",
    "server": "crm",
    "tool": "contacts.read",
    "arguments": {
      "contact_id": "123"
    }
  }'
```

### 4. Invoke Through the Proxy

For local development, use a JWT with `sub = agent-a`. In production, this must be a signed JWT from your identity provider.

```powershell
curl -X POST http://127.0.0.1:8000/v1/proxy/crm/tools/contacts.read `
  -H "Authorization: Bearer <jwt>" `
  -H "Content-Type: application/json" `
  -d '{
    "contact_id": "123"
  }'
```

### 5. Inspect the Audit Trail

```powershell
curl http://127.0.0.1:8000/v1/audit
```

## Evaluation Pipeline

The evaluation runner executes predefined scenarios against the policy engine. This is useful for testing whether an agent would be allowed or denied under different constraints.

Sample scenarios live in:

```text
examples/scenarios.json
```

Scenario shape:

```json
{
  "name": "allowed crm read",
  "request": {
    "subject": "agent-a",
    "server": "crm",
    "tool": "contacts.read",
    "arguments": {
      "contact_id": "123"
    }
  },
  "expected_allowed": true
}
```

The runner is exposed as a Python function:

```python
from steward.evaluate import run_scenarios

summary = await run_scenarios(session, "examples/scenarios.json")
```

Returned summary:

```json
{
  "total": 2,
  "passed": 2,
  "failed": 0,
  "results": []
}
```

## Audit Logging

Steward records audit events for:

- Denied calls
- Allowed calls
- Allowed calls whose downstream execution fails

Audit events include:

| Field | Description |
| --- | --- |
| `correlation_id` | Unique ID for tracing a single decision |
| `principal` | Authenticated subject |
| `server` | Requested MCP server |
| `tool` | Requested tool/action |
| `arguments` | Redacted call arguments |
| `decision` | `allowed` or `denied` |
| `reason` | Human-readable decision reason |
| `matched_policy_ids` | Policies involved in the decision |
| `downstream_status` | `success`, `error`, or null |
| `created_at` | Event timestamp |

Argument keys listed in `AUDIT_ARGUMENT_REDACTION_KEYS` are replaced with `[REDACTED]`.

Default redacted keys:

```text
password,token,secret,authorization
```

## Security Model

Steward is designed around fail-closed authorization.

Default behavior:

- No matching allow policy means deny
- Matching deny policy overrides matching allow policies
- Expired policies are ignored
- Inactive policies are ignored
- JWTs require a Bearer token
- Signed JWT verification is required outside unsigned development mode
- Sensitive audit arguments are redacted by key

Recommended production settings:

```env
ENVIRONMENT=production
DATABASE_URL=postgresql+asyncpg://user:password@postgres:5432/steward
JWT_ISSUER=https://issuer.example.com/
JWT_AUDIENCE=steward-api
JWT_JWKS_URL=https://issuer.example.com/.well-known/jwks.json
JWT_ALGORITHMS=RS256
```

## MCP Integration

The current proxy boundary is:

```python
await authorize_and_call(session, request, downstream)
```

Where `downstream` is an async callable:

```python
async def downstream(tool: str, arguments: dict):
    ...
```

To connect a real MCP server:

1. Create an MCP client transport using the MCP Python SDK
2. Map `{server, tool, arguments}` to the SDK call shape
3. Pass that callable into `authorize_and_call`
4. Preserve the audit recording behavior around success and failure

Recommended deployment shape:

```mermaid
flowchart TB
    AgentRuntime[Agent Runtime]
    StewardAPI[Steward API]
    PolicyDB[(PostgreSQL)]
    AuditSink[(Audit Store)]
    MCP1[MCP Server: CRM]
    MCP2[MCP Server: GitHub]
    MCP3[MCP Server: Slack]

    AgentRuntime --> StewardAPI
    StewardAPI --> PolicyDB
    StewardAPI --> AuditSink
    StewardAPI --> MCP1
    StewardAPI --> MCP2
    StewardAPI --> MCP3
```

## Testing

Run tests:

```powershell
python -m pytest -q
```

Run lint:

```powershell
python -m ruff check steward tests alembic
```

Compile-check Python files:

```powershell
python -m compileall -q steward tests alembic
```

Current test coverage focuses on:

- Allow policy matching
- Default deny behavior
- Explicit deny precedence
- Numeric argument constraints

## Development Notes

Useful commands:

```powershell
uvicorn steward.main:app --reload
alembic upgrade head
python -m pytest -q
python -m ruff check steward tests alembic
```

Generated local files ignored by git:

- `__pycache__/`
- `.pytest_cache/`
- `.ruff_cache/`
- `.venv/`
- `*.egg-info/`
- `*.db`
- `.env`

## Production Checklist

Before using Steward with real agent traffic:

- Configure signed JWT validation with `JWT_JWKS_URL`
- Use PostgreSQL instead of SQLite
- Run Alembic migrations during deployment
- Put Steward behind TLS
- Restrict network egress to approved MCP servers
- Store secrets in a proper secret manager
- Ship audit events to an append-only external store
- Add retention policies for audit data
- Add rate limiting and abuse protection
- Add policy approval workflow for high-risk scopes
- Add integration tests for every production MCP server adapter
- Monitor deny spikes, downstream failures, and policy drift

## Roadmap

High-value next steps:

- Live MCP SDK transport implementation
- Policy version history and rollback
- Policy bundles for common tools
- OPA/Rego or Cedar backend option
- Admin UI for policy review
- Append-only audit sink integration
- CLI for running evaluation suites
- More condition operators for structured arguments
- Human approval flow for sensitive actions

## License

No license has been selected yet. Add one before publishing or reusing this project outside private development.
