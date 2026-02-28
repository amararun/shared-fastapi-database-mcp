# FastAPI Database MCP Server

Read-only SQL query API for Postgres and DuckDB, exposed as MCP tools for AI clients.

**Live endpoint**: [db-mcp.tigzig.com](https://db-mcp.tigzig.com)

## Security Hardening

This server is designed to run with a public, open MCP endpoint (`/mcp`) — no API key, no auth. A separate secured endpoint (`/mcp-secure`) uses Auth0 OAuth for controlled access. The open endpoint relies entirely on the defense stack below.

### Defense Layers

1. **Edge rate limiting** — Cloudflare WAF or equivalent, configured per your needs (recommended before traffic hits origin)
2. **Application rate limiting** — per-IP and global rate limits via SlowAPI (configurable via env vars)
3. **Per-IP concurrency cap** — limits simultaneous in-flight queries per IP (default: 4)
4. **Global concurrency cap** — limits total simultaneous queries server-wide (default: 10)
5. **SQL prefix allowlist** — only SELECT, WITH, SHOW, DESCRIBE, EXPLAIN allowed
6. **SQL keyword blocklist** — INSERT, UPDATE, DELETE, DROP, ALTER, CREATE, TRUNCATE, EXEC, COPY, GRANT, REVOKE, and 20+ more blocked (hardcoded in `BLOCKED_KEYWORDS`)
7. **Resource exhaustion blocking** — CROSS JOIN, REPEAT, REGEXP_REPLACE, MD5, SHA256 blocked to prevent CPU/bandwidth bombs
8. **SQL parser structural validation (sqlglot)** — regex-based checks cannot understand SQL structure (CTEs, aliases, nested subqueries). The [sqlglot](https://github.com/tobymao/sqlglot) parser builds an AST (Abstract Syntax Tree) and validates structurally: blocks multiple table sources in a single SELECT (catches cartesian products via `FROM a, b`, CTE alias bypass like `WITH t AS (...) SELECT FROM t a, t b`, and aliased self-joins), detects blocked functions even when nested or aliased. Supports both Postgres and DuckDB dialects. Falls back to regex-only mode gracefully if sqlglot is not installed.
9. **SQL comment rejection** — `--` and `/*` blocked to prevent comment-based validation bypass
10. **System catalog blocking** — pg_catalog, information_schema, pg_stat, duckdb_tables(), and other system objects blocked (hardcoded in `BLOCKED_PG_SOURCES` and `BLOCKED_DUCKDB_SOURCES`)
11. **Auto-append LIMIT** — queries without an outer LIMIT automatically get one (configurable via `MAX_JSON_ROWS` / `MAX_TSV_ROWS`)
12. **Response size limit** — responses exceeding the byte limit are rejected with HTTP 413 (configurable via `MAX_RESPONSE_BYTES`, default: 1MB)
13. **ORDER BY validation** — function calls in ORDER BY blocked except whitelisted aggregates; subqueries in ORDER BY blocked
14. **Subquery depth limit** — max 3 SELECT keywords per query (hardcoded)
15. **Data-generating function blocking** — GENERATE_SERIES, RANGE, UNNEST blocked (hardcoded)
16. **Query timeouts** — configurable timeout on both Postgres and DuckDB, queries exceeding this are killed (default: 15s)
17. **DuckDB query interrupt** — on timeout, `connection.interrupt()` kills the C++ engine query, not just the Python coroutine
18. **Postgres read-only mode** — `default_transaction_read_only = on` + dedicated read-only database user
19. **DuckDB read-only mode** — `read_only=True` + `enable_external_access=false`
20. **DuckDB resource limits** — memory and thread limits (configurable via env vars, defaults: 512MB, 2 threads)
21. **Container resource limits** — Docker/container-level RAM and CPU caps (configured in your hosting platform)
22. **Error message sanitization** — generic error messages returned, no internal details leaked
23. **Auth0 OAuth on `/mcp-secure`** — JWT verification (RS256), audience/issuer validation, email whitelist (optional, enabled via env vars)
24. **Failed-auth rate limiter** — in-memory counter blocks IPs after repeated failed JWT attempts on `/mcp-secure` (configurable via `AUTH_FAIL_MAX` and `AUTH_FAIL_WINDOW`)

### What's Hardcoded vs Configurable

**Hardcoded in code** (edit `app.py` to change):
- SQL keyword blocklist (`BLOCKED_KEYWORDS`)
- System catalog blocklists (`BLOCKED_PG_SOURCES`, `BLOCKED_DUCKDB_SOURCES`)
- Allowed SQL prefixes (SELECT, WITH, SHOW, DESCRIBE, EXPLAIN)
- ORDER BY allowed functions (SUM, COUNT, AVG, MIN, MAX, COALESCE, NULLIF, CASE)
- Subquery depth limit (3)
- sqlglot structural checks (multi-table per SELECT, blocked functions via AST)

**Configurable via environment variables** (see table below):
- Rate limits, concurrency caps, query timeouts, row limits, response size limit, connection pool settings, Auth0 config

### Database-Level Hardening (Postgres)

If your backend connects to a hosted Postgres (Supabase, Neon, etc.), you should also harden at the database level:

- Enable RLS on all tables
- Revoke default grants from anon/authenticated roles
- Use a dedicated read-only database user (SELECT-only grants on specific tables)
- Set `default_transaction_read_only = on` on application roles
- Set `statement_timeout` on application roles (matches your `PG_STATEMENT_TIMEOUT_MS`)
- Add indexes on columns used in WHERE, GROUP BY, ORDER BY for large tables

### DuckDB-Level Hardening

DuckDB runs in-process. The server opens it with `read_only=True` and `enable_external_access=false`, and sets `memory_limit` and `threads` to prevent a single query from consuming all resources. On timeout, `connection.interrupt()` + `connection.close()` kills the query at the C++ engine level.

## What It Does

Two databases, two endpoints, one MCP server:

- **Postgres (Supabase)** — ~1M rows of ODI cricket ball-by-ball data (2013-2025)
- **DuckDB** — ~1M rows of T20 cricket ball-by-ball data (2013-2025)

Both tables have identical schemas (23 columns) covering match details, player info, runs, extras, and dismissals.

The endpoints are mounted as MCP tools via [fastapi-mcp](https://github.com/tadata-org/fastapi-mcp), so any MCP-compatible AI client (Claude Code, Claude Desktop, etc.) can connect and query directly.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/query/postgres` | SQL query on ODI data (Supabase) |
| POST | `/api/query/duckdb` | SQL query on T20 data (DuckDB) |
| GET | `/health` | Health check with DB connectivity status |
| GET | `/mcp` | MCP SSE endpoint for AI clients (open, no auth) |
| GET | `/mcp-secure` | MCP SSE endpoint with Auth0 OAuth (secured) |

### Query Format

```json
{
  "sql": "SELECT striker, SUM(runs_off_bat) as runs FROM ball_by_ball WHERE season = '2023' GROUP BY striker ORDER BY runs DESC LIMIT 10",
  "format": "json"
}
```

Set `"format": "tsv"` for compact tab-delimited output (~70% fewer tokens).

## Connecting as MCP Client

### Claude Code

```bash
claude mcp add --transport sse db-mcp https://your-server.com/mcp
```

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "db-mcp": {
      "type": "sse",
      "url": "https://your-server.com/mcp"
    }
  }
}
```

## Local Development

```bash
git clone https://github.com/amararun/shared-fastapi-database-mcp.git
cd shared-fastapi-database-mcp

python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows

pip install -r requirements.txt

cp .env.example .env
# Edit .env with your database connection strings

uvicorn app:app --host 0.0.0.0 --port 8000
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SUPABASE_POSTGRES` | Yes | — | Postgres connection string (use a read-only user) |
| `DUCKDB_FILE` | Yes | `./data/t20_cricket.duckdb` | Path to `.duckdb` file |
| `RATE_LIMIT` | No | `30/minute` | Per-IP rate limit (SlowAPI format, e.g. `60/hour`, `100/minute`) |
| `GLOBAL_RATE_LIMIT` | No | `200/minute` | Global rate limit across all IPs |
| `PG_STATEMENT_TIMEOUT_MS` | No | `15000` | Postgres query timeout in milliseconds |
| `DUCKDB_QUERY_TIMEOUT_MS` | No | `15000` | DuckDB query timeout in milliseconds |
| `MAX_JSON_ROWS` | No | `1000` | Max rows returned in JSON format |
| `MAX_TSV_ROWS` | No | `1000` | Max rows returned in TSV format |
| `MAX_RESPONSE_BYTES` | No | `1048576` | Max response size in bytes (default: 1MB) |
| `MAX_CONCURRENT_PER_IP` | No | `4` | Max simultaneous queries per IP |
| `MAX_CONCURRENT_GLOBAL` | No | `10` | Max simultaneous queries server-wide |
| `PG_POOL_MIN` | No | `3` | Postgres connection pool minimum size |
| `PG_POOL_MAX` | No | `6` | Postgres connection pool maximum size |
| `PG_POOL_ACQUIRE_TIMEOUT` | No | `15` | Seconds to wait for a pool connection before returning 503 |
| `DUCKDB_MEMORY_LIMIT` | No | `512MB` | DuckDB memory limit |
| `DUCKDB_THREADS` | No | `2` | DuckDB thread limit |
| `DUCKDB_TEMP_DIR` | No | `/tmp/duckdb` | DuckDB temporary directory |
| `DUCKDB_MAX_TEMP_DIR_SIZE` | No | `2GB` | DuckDB temp directory size cap |
| `CORS_ALLOW_ORIGINS` | No | `*` | Comma-separated allowed origins |
| `LOG_LEVEL` | No | `INFO` | Logging level |
| `AUTH0_DOMAIN` | No | — | Auth0 tenant domain (enables `/mcp-secure` when set) |
| `AUTH0_AUDIENCE` | No | — | Auth0 API identifier |
| `AUTH0_CLIENT_ID` | No | — | Auth0 application client ID |
| `AUTH0_CLIENT_SECRET` | No | — | Auth0 application client secret |
| `AUTH_FAIL_MAX` | No | `5` | Max failed auth attempts per IP before blocking |
| `AUTH_FAIL_WINDOW` | No | `86400` | Failed auth tracking window in seconds (default: 24 hours) |
| `API_MONITOR_URL` | No | — | tigzig-api-monitor endpoint URL |
| `API_MONITOR_KEY` | No | — | tigzig-api-monitor API key |
| `RENDER_EXTERNAL_URL` | No | — | Base URL for MCP (auto-detected on Render) |

## Auth0 OAuth (Secured Endpoint)

The `/mcp-secure` endpoint adds Auth0 OAuth on top of all existing security layers. It is optional — if `AUTH0_DOMAIN` is not set, only the open `/mcp` endpoint is mounted.

### How It Works

1. MCP client discovers OAuth metadata at `/.well-known/oauth-authorization-server`
2. Client redirects user to Auth0 login
3. Auth0 authenticates user, checks email whitelist, issues JWT
4. Client sends JWT as Bearer token with every request
5. Server validates JWT signature (RS256 via JWKS), audience, and issuer

### Auth0 Setup

1. Create an Auth0 API with your server URL as the identifier (audience)
2. Create an Auth0 Application (Regular Web Application)
3. Add your MCP client's callback URLs (e.g., `https://claude.ai/api/mcp/auth_callback`)
4. Create a post-login Action with an email whitelist
5. Set the AUTH0 environment variables on the server

### Connecting to the Secured Endpoint

**Claude.ai (Web)** — Settings > Connectors > Add custom connector:
- URL: `https://your-server.com/mcp-secure`
- OAuth Client ID: your Auth0 app's client ID

**Claude Desktop:**

```json
{
  "mcpServers": {
    "db-mcp-secure": {
      "command": "npx",
      "args": ["mcp-remote", "https://your-server.com/mcp-secure", "8080"]
    }
  }
}
```

### Demo Limitations

- JWKS cache does not auto-refresh (refresh on restart only)
- No token scope validation (any valid token grants access to all tools)
- Fake Dynamic Client Registration (returns pre-configured credentials for MCP spec compatibility)
- No token revocation handling (tokens accepted until expiry)

## Stack

- FastAPI + uvicorn
- asyncpg (Postgres connection pool)
- DuckDB (read-only, thread-pool executor)
- fastapi-mcp v0.4.0 (MCP server mounting, OAuth support)
- sqlglot (SQL parser for structural validation)
- python-jose (JWT verification)
- SlowAPI (rate limiting)

## Author

Built by [Amar Harolikar](https://www.linkedin.com/in/amarharolikar/)

Explore 30+ open source AI tools for analytics, databases & automation at [tigzig.com](https://tigzig.com)

## License

MIT License
