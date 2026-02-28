"""
FastAPI Database MCP Server
Provides read-only SQL query endpoints for Postgres (Supabase) and DuckDB,
exposed as MCP tools for AI client consumption.
"""

import os
import io
import csv
import json
import asyncio
import hashlib
import logging
import re
import secrets
import time
import uuid
from datetime import date, datetime, time as dt_time
from decimal import Decimal
from typing import Optional

import asyncpg
import duckdb
import httpx
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware

load_dotenv()

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
VERSION = "1.0.0"

SUPABASE_POSTGRES = os.getenv("SUPABASE_POSTGRES")
DUCKDB_FILE = os.getenv("DUCKDB_FILE", "./data/t20_cricket.duckdb")

RATE_LIMIT = os.getenv("RATE_LIMIT", "30/minute")
PG_STATEMENT_TIMEOUT_MS = int(os.getenv("PG_STATEMENT_TIMEOUT_MS", "15000"))
DUCKDB_QUERY_TIMEOUT_MS = int(os.getenv("DUCKDB_QUERY_TIMEOUT_MS", "15000"))

MAX_JSON_ROWS = int(os.getenv("MAX_JSON_ROWS", "1000"))
MAX_TSV_ROWS = int(os.getenv("MAX_TSV_ROWS", "1000"))
MAX_RESPONSE_BYTES = int(os.getenv("MAX_RESPONSE_BYTES", str(1_048_576)))  # 1 MB

PG_POOL_MIN = int(os.getenv("PG_POOL_MIN", "3"))
PG_POOL_MAX = int(os.getenv("PG_POOL_MAX", "6"))
PG_POOL_ACQUIRE_TIMEOUT = int(os.getenv("PG_POOL_ACQUIRE_TIMEOUT", "15"))
MAX_CONCURRENT_PER_IP = int(os.getenv("MAX_CONCURRENT_PER_IP", "4"))
MAX_CONCURRENT_GLOBAL = int(os.getenv("MAX_CONCURRENT_GLOBAL", "10"))
GLOBAL_RATE_LIMIT = os.getenv("GLOBAL_RATE_LIMIT", "200/minute")

DUCKDB_MEMORY_LIMIT = os.getenv("DUCKDB_MEMORY_LIMIT", "512MB")
DUCKDB_THREADS = os.getenv("DUCKDB_THREADS", "2")
DUCKDB_TEMP_DIR = os.getenv("DUCKDB_TEMP_DIR", "/tmp/duckdb")
DUCKDB_MAX_TEMP_DIR_SIZE = os.getenv("DUCKDB_MAX_TEMP_DIR_SIZE", "2GB")

CORS_ALLOW_ORIGINS = os.getenv("CORS_ALLOW_ORIGINS", "*").split(",")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# Auth0 OAuth config for secured MCP endpoint
AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN", "")
AUTH0_AUDIENCE = os.getenv("AUTH0_AUDIENCE", "")
AUTH0_CLIENT_ID = os.getenv("AUTH0_CLIENT_ID", "")
AUTH0_CLIENT_SECRET = os.getenv("AUTH0_CLIENT_SECRET", "")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("database-mcp")

# ---------------------------------------------------------------------------
# Per-IP and global concurrency tracking
# ---------------------------------------------------------------------------
_active_queries: dict[str, int] = {}
_active_queries_lock = asyncio.Lock()
_global_active = 0
_global_active_lock = asyncio.Lock()


async def check_concurrency(client_ip: str) -> tuple[bool, str]:
    """Try to acquire a concurrency slot. Returns (allowed, reason)."""
    global _global_active
    async with _global_active_lock:
        if _global_active >= MAX_CONCURRENT_GLOBAL:
            logger.info(f"Concurrency DENIED (global cap {MAX_CONCURRENT_GLOBAL}) for {client_ip} | global={_global_active}")
            return False, "global"
        _global_active += 1
    async with _active_queries_lock:
        current = _active_queries.get(client_ip, 0)
        if current >= MAX_CONCURRENT_PER_IP:
            # Roll back global counter
            async with _global_active_lock:
                _global_active -= 1
            logger.info(f"Concurrency DENIED (per-IP cap {MAX_CONCURRENT_PER_IP}) for {client_ip} | ip_slots={current}, global={_global_active}")
            return False, "per_ip"
        _active_queries[client_ip] = current + 1
    logger.info(f"Concurrency ACQUIRED for {client_ip} | ip_slots={current + 1}, global={_global_active}")
    return True, ""


async def release_concurrency(client_ip: str):
    """Release a concurrency slot. Shielded from cancellation to prevent counter leaks."""
    try:
        await asyncio.shield(_release_concurrency_inner(client_ip))
    except asyncio.CancelledError:
        # shield was cancelled but inner task still runs
        pass


async def _release_concurrency_inner(client_ip: str):
    global _global_active
    async with _active_queries_lock:
        current = _active_queries.get(client_ip, 0)
        if current <= 1:
            _active_queries.pop(client_ip, None)
        else:
            _active_queries[client_ip] = current - 1
    async with _global_active_lock:
        _global_active = max(0, _global_active - 1)
    logger.info(f"Concurrency RELEASED for {client_ip} | ip_slots={max(0, current - 1)}, global={_global_active}")


# ---------------------------------------------------------------------------
# SQL blocklist — keywords that must not appear at start of query
# Shared across both Postgres and DuckDB endpoints
# ---------------------------------------------------------------------------
BLOCKED_KEYWORDS = [
    "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "TRUNCATE",
    "EXEC", "EXECUTE", "COPY", "GRANT", "REVOKE", "SET", "COMMIT",
    "ROLLBACK", "SAVEPOINT", "LOCK", "VACUUM", "REINDEX", "DISCARD",
    # DuckDB-specific dangerous commands
    "ATTACH", "DETACH", "LOAD", "INSTALL", "PRAGMA",
    "READ_CSV", "READ_CSV_AUTO", "READ_PARQUET", "READ_PARQUET_AUTO",
    "READ_JSON", "READ_JSON_AUTO", "READ_TEXT", "READ_BLOB",
    "GLOB", "EXPORT", "IMPORT", "CHECKPOINT",
    # Data-generating functions that can create billions of rows from nothing
    "GENERATE_SERIES", "RANGE", "UNNEST", "STRING_TO_TABLE", "REGEXP_SPLIT_TO_TABLE",
    # Resource exhaustion: CPU bombs and bandwidth bombs
    "CROSS JOIN",
    "REPEAT",
    "REGEXP_REPLACE",
    "MD5",
    "SHA256",
]

ALLOWED_PREFIXES = ("SELECT", "SHOW", "DESCRIBE", "EXPLAIN", "WITH")

# Postgres system catalog / internal tables that must not be queried
BLOCKED_PG_SOURCES = [
    "PG_SHADOW", "PG_AUTHID", "PG_ROLES", "PG_USER", "PG_GROUP",
    "PG_STAT_ACTIVITY", "PG_STAT_REPLICATION", "PG_STAT_SSL",
    "PG_SETTINGS", "PG_HBA_FILE_RULES", "PG_CONFIG",
    "PG_STAT_WAL_RECEIVER", "PG_REPLICATION_SLOTS",
    "PG_STAT_SUBSCRIPTION", "PG_FILE_SETTINGS",
    "INFORMATION_SCHEMA",
    # Block catalog views that enumerate tables/schema
    "PG_TABLES", "PG_CLASS", "PG_CATALOG", "PG_EXTENSION",
    "PG_NAMESPACE", "PG_ATTRIBUTE", "PG_INDEX", "PG_CONSTRAINT",
    # Block functions that leak server info
    "INET_SERVER_ADDR", "INET_SERVER_PORT",
    "INET_CLIENT_ADDR", "INET_CLIENT_PORT",
    "CURRENT_SETTING", "PG_READ_FILE", "PG_LS_DIR",
    "PG_STAT_FILE", "PG_READ_BINARY_FILE",
    "VERSION()", "CURRENT_USER", "CURRENT_DATABASE",
]

# DuckDB system functions that leak metadata
BLOCKED_DUCKDB_SOURCES = [
    "DUCKDB_TABLES", "DUCKDB_COLUMNS", "DUCKDB_DATABASES",
    "DUCKDB_SETTINGS", "DUCKDB_FUNCTIONS", "DUCKDB_EXTENSIONS",
    "DUCKDB_VIEWS", "DUCKDB_SCHEMAS", "DUCKDB_TYPES",
    "DUCKDB_CONSTRAINTS", "DUCKDB_INDEXES",
]


def validate_sql(sql: str, engine: str = "postgres") -> Optional[str]:
    """Validate SQL is read-only. Returns error message or None if OK.
    engine: 'postgres' or 'duckdb' — controls which metadata blocklist to apply.
    """
    stripped = sql.strip()
    if not stripped:
        return "Empty query"
    # Reject SQL comments — no legitimate MCP/AI query needs them,
    # and they can be used to bypass keyword validation (e.g. INF/**/ORMATION_SCHEMA)
    if "/*" in stripped or "--" in stripped:
        return "SQL comments are not allowed"
    upper = stripped.upper()
    # Must start with allowed prefix
    if not any(upper.startswith(p) for p in ALLOWED_PREFIXES):
        return f"Only SELECT/SHOW/DESCRIBE/EXPLAIN/WITH queries allowed"
    # Check for blocked keywords anywhere (catches subquery attacks)
    for kw in BLOCKED_KEYWORDS:
        # Check as whole word to avoid false positives (e.g. "DESCRIPTION")
        if f" {kw} " in f" {upper} " or f" {kw}(" in f" {upper}(" or upper.startswith(kw):
            return f"Blocked keyword: {kw}"
    # Block access to system catalogs and info-leak functions
    for src in BLOCKED_PG_SOURCES:
        if src in upper:
            return "Access to system catalogs is not allowed"
    if engine == "duckdb":
        for src in BLOCKED_DUCKDB_SOURCES:
            if src in upper:
                return "Access to system catalogs is not allowed"
    # Limit subquery nesting depth (max 3 SELECT keywords = main + 2 subqueries)
    select_count = len(re.findall(r'\bSELECT\b', upper))
    if select_count > 3:
        return "Query too complex (too many subqueries)"
    # Block function calls in ORDER BY (except whitelisted aggregates/helpers)
    order_by_error = _validate_order_by(upper)
    if order_by_error:
        return order_by_error
    # Structural validation via SQL parser (catches CTE bypasses, aliased self-joins)
    struct_error = _validate_sql_structure(stripped, engine)
    if struct_error:
        return struct_error
    return None


# ---------------------------------------------------------------------------
# SQL parser structural validation (sqlglot)
# Catches attacks that bypass regex: CTE aliases, implicit cross joins via aliases
# ---------------------------------------------------------------------------
_BLOCKED_FUNCTIONS_PARSER = {
    "REPEAT", "REGEXP_REPLACE", "MD5", "SHA256",
    "GENERATE_SERIES", "RANGE", "UNNEST", "STRING_TO_TABLE", "REGEXP_SPLIT_TO_TABLE",
}

try:
    import sqlglot
    from sqlglot import exp as sqlglot_exp

    def _validate_sql_structure(sql: str, engine: str = "postgres") -> Optional[str]:
        """Parse SQL and validate structure. Returns error message or None if OK."""
        dialect = "duckdb" if engine == "duckdb" else "postgres"
        try:
            parsed = sqlglot.parse_one(sql, dialect=dialect)
        except sqlglot.errors.ParseError:
            return "Invalid SQL syntax"

        # Check for multiple table sources in any single SELECT's FROM clause
        # This catches CTE bypass (FROM t a, t b) and aliased self-joins
        for select in parsed.find_all(sqlglot_exp.Select):
            from_clause = select.find(sqlglot_exp.From)
            if not from_clause:
                continue
            from_tables = list(from_clause.find_all(sqlglot_exp.Table))
            join_tables = []
            for join in select.find_all(sqlglot_exp.Join):
                if join.find_ancestor(sqlglot_exp.Select) is select:
                    join_tables.extend(list(join.find_all(sqlglot_exp.Table)))
            if len(from_tables) + len(join_tables) > 1:
                return "Multiple table sources in a single query are not allowed"

        # Check for blocked functions via AST (catches aliased/nested usage)
        for func in parsed.find_all(sqlglot_exp.Func):
            if isinstance(func, sqlglot_exp.Anonymous):
                name = func.name.upper()
            else:
                name = func.sql_name().upper() if hasattr(func, "sql_name") else ""
            if name in _BLOCKED_FUNCTIONS_PARSER:
                return f"Blocked function: {name}"

        return None

    logger.info("sqlglot parser loaded for structural SQL validation")

except ImportError:
    logger.warning("sqlglot not installed — structural SQL validation disabled, regex-only mode")

    def _validate_sql_structure(sql: str, engine: str = "postgres") -> Optional[str]:
        return None  # fallback: skip structural checks, regex layer still active


# Whitelisted functions allowed in ORDER BY clauses
_ORDER_BY_ALLOWED_FUNCTIONS = {
    "SUM", "COUNT", "AVG", "MIN", "MAX", "COALESCE", "NULLIF", "CASE",
}


def _validate_order_by(upper_sql: str) -> Optional[str]:
    """Check ORDER BY clause for disallowed function calls.
    Returns error message or None if OK.
    """
    # First check the ORIGINAL sql for subqueries in ORDER BY.
    # Must happen before paren-stripping, which would hide (SELECT ...) content.
    orig_match = re.search(r'\bORDER\s+BY\b(.+?)(?:\bLIMIT\b|\bOFFSET\b|\bFETCH\b|\bFOR\b|\bUNION\b|$)', upper_sql, re.DOTALL)
    if orig_match and re.search(r'\bSELECT\b', orig_match.group(1)):
        return "Subqueries in ORDER BY are not allowed"

    # Strip content inside parentheses to find outer ORDER BY for function check
    depth = 0
    outer_chars = []
    for ch in upper_sql:
        if ch == '(':
            depth += 1
            if depth == 1:
                outer_chars.append(ch)
            continue
        elif ch == ')':
            if depth == 1:
                outer_chars.append(ch)
            depth = max(0, depth - 1)
            continue
        if depth == 0:
            outer_chars.append(ch)
    outer_sql = ''.join(outer_chars)

    match = re.search(r'\bORDER\s+BY\b(.+?)(?:\bLIMIT\b|\bOFFSET\b|\bFETCH\b|\bFOR\b|\bUNION\b|$)', outer_sql, re.DOTALL)
    if not match:
        return None
    order_clause = match.group(1)
    # Find function calls: word followed by ( — but not column names or numbers
    func_calls = re.findall(r'\b([A-Z_][A-Z0-9_]*)\s*\(', order_clause)
    for func_name in func_calls:
        if func_name not in _ORDER_BY_ALLOWED_FUNCTIONS:
            return f"Function calls in ORDER BY are not allowed (found: {func_name})"
    return None


def ensure_limit(sql: str, max_rows: int) -> str:
    """Auto-append LIMIT if the query doesn't already have one at the outer level.
    Only applies to SELECT/WITH queries. SHOW/DESCRIBE/EXPLAIN are left unchanged.
    """
    stripped = sql.strip().rstrip(";")
    upper = stripped.upper()

    # Only add LIMIT to SELECT/WITH queries
    if not (upper.startswith("SELECT") or upper.startswith("WITH")):
        return sql

    # Check if there's a LIMIT at the outer level (not inside a subquery).
    # Strategy: strip everything inside parentheses, then check for LIMIT.
    # This handles: SELECT * FROM (SELECT ... LIMIT 5) sub — no outer LIMIT.
    depth = 0
    outer_parts = []
    for char in upper:
        if char == '(':
            depth += 1
        elif char == ')':
            depth = max(0, depth - 1)
        elif depth == 0:
            outer_parts.append(char)
    outer_sql = ''.join(outer_parts)

    if re.search(r'\bLIMIT\b', outer_sql):
        return sql

    return f"{stripped} LIMIT {max_rows}"


# ---------------------------------------------------------------------------
# JSON serializer for DB results
# ---------------------------------------------------------------------------
def serialize_value(v):
    if v is None:
        return None
    if isinstance(v, (datetime, date)):
        return v.isoformat()
    if isinstance(v, dt_time):
        return v.isoformat()
    if isinstance(v, Decimal):
        return float(v)
    if isinstance(v, bytes):
        return v.hex()
    if isinstance(v, uuid.UUID):
        return str(v)
    return v


# ---------------------------------------------------------------------------
# TSV formatter — compact output for AI clients (~70% fewer tokens than JSON)
# ---------------------------------------------------------------------------
HEADER_SHORT = {
    "match_id": "mid", "season": "ssn", "start_date": "date",
    "venue": "ven", "innings": "inn", "ball": "ball",
    "batting_team": "bat", "bowling_team": "bowl",
    "striker": "strk", "non_striker": "nstrk", "bowler": "bwlr",
    "runs_off_bat": "runs", "extras": "ext", "wides": "wd",
    "noballs": "nb", "byes": "bye", "legbyes": "lb",
    "penalty": "pen", "wicket_type": "wkt", "player_dismissed": "dism",
    "other_wicket_type": "owkt", "other_player_dismissed": "odism",
    "match_type": "type",
}


def rows_to_tsv(columns: list[str], rows: list[list], max_rows: int) -> dict:
    """Convert result rows to TSV format with shortened headers."""
    truncated = len(rows) > max_rows
    rows = rows[:max_rows]

    short_cols = [HEADER_SHORT.get(c, c) for c in columns]

    output = io.StringIO()
    writer = csv.writer(output, delimiter="\t", lineterminator="\n")
    writer.writerow(short_cols)
    for row in rows:
        writer.writerow([serialize_value(v) for v in row])

    return {
        "format": "tsv",
        "data": output.getvalue(),
        "row_count": len(rows),
        "columns": short_cols,
        "column_mapping": {s: f for s, f in zip(short_cols, columns)},
        "truncated": truncated,
    }


def rows_to_json(columns: list[str], rows: list[list], max_rows: int) -> dict:
    """Convert result rows to JSON format."""
    truncated = len(rows) > max_rows
    rows = rows[:max_rows]
    return {
        "format": "json",
        "columns": columns,
        "rows": [[serialize_value(v) for v in row] for row in rows],
        "row_count": len(rows),
        "truncated": truncated,
    }


# ---------------------------------------------------------------------------
# Client IP extraction (Cloudflare / proxy aware)
# ---------------------------------------------------------------------------
def get_client_ip(request: Request) -> str:
    for header in ("x-original-client-ip", "cf-connecting-ip", "x-forwarded-for", "x-real-ip"):
        val = request.headers.get(header)
        if val:
            return val.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Database MCP Server",
    description=(
        "Read-only SQL query endpoints for Postgres (Supabase ODI Cricket) "
        "and DuckDB (T20 Cricket). ~1M ball-by-ball records each. "
        "Exposed as MCP tools for AI client consumption."
    ),
    version=VERSION,
)

# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------
limiter = Limiter(key_func=get_client_ip)
app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={
            "detail": f"Rate limit exceeded. Limit: {RATE_LIMIT}. Try again later.",
        },
    )


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOW_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = str(uuid.uuid4())[:8]
        client_ip = get_client_ip(request)
        logger.info(f"[{request_id}] {request.method} {request.url.path} from {client_ip}")
        start = time.time()
        response = await call_next(request)
        elapsed = (time.time() - start) * 1000
        logger.info(f"[{request_id}] {response.status_code} in {elapsed:.0f}ms")
        return response


app.add_middleware(RequestLoggingMiddleware)

# tigzig API monitor (optional)
try:
    from tigzig_api_monitor import APIMonitorMiddleware
    app.add_middleware(
        APIMonitorMiddleware,
        app_name=os.getenv("API_MONITOR_APP_NAME", "FASTAPI_DATABASE_MCP"),
        include_prefixes=("/api/",),
    )
    logger.info("tigzig API monitor middleware enabled")
except ImportError:
    logger.info("tigzig-api-monitor not installed, skipping")


# ---------------------------------------------------------------------------
# Request body model
# ---------------------------------------------------------------------------
class QueryRequest(BaseModel):
    sql: str
    format: str = "json"


# ---------------------------------------------------------------------------
# Postgres (Supabase) connection pool
# ---------------------------------------------------------------------------
pg_pool: Optional[asyncpg.Pool] = None


async def init_pg_pool():
    global pg_pool
    if not SUPABASE_POSTGRES:
        logger.warning("SUPABASE_POSTGRES not set, Postgres endpoint will be unavailable")
        return
    try:
        async def init_conn(conn):
            await conn.execute("SET default_transaction_read_only = on")
            await conn.execute(f"SET statement_timeout = {PG_STATEMENT_TIMEOUT_MS}")

        pg_pool = await asyncpg.create_pool(
            SUPABASE_POSTGRES,
            min_size=PG_POOL_MIN,
            max_size=PG_POOL_MAX,
            statement_cache_size=0,
            init=init_conn,
        )
        logger.info(f"Postgres pool created (min={PG_POOL_MIN}, max={PG_POOL_MAX})")
    except Exception as e:
        logger.error(f"Failed to create Postgres pool: {e}")


async def close_pg_pool():
    global pg_pool
    if pg_pool:
        await pg_pool.close()
        logger.info("Postgres pool closed")


# ---------------------------------------------------------------------------
# DuckDB connection helper
# ---------------------------------------------------------------------------
def get_duckdb_connection():
    """Open a read-only DuckDB connection with safety pragmas and resource limits."""
    if not os.path.exists(DUCKDB_FILE):
        raise FileNotFoundError(f"DuckDB file not found: {DUCKDB_FILE}")
    conn = duckdb.connect(DUCKDB_FILE, read_only=True)
    conn.execute("SET enable_external_access = false")
    conn.execute(f"SET memory_limit = '{DUCKDB_MEMORY_LIMIT}'")
    conn.execute(f"SET threads = {DUCKDB_THREADS}")
    # temp_directory and max_temp_directory_size cannot be set on read-only connections
    return conn


def execute_duckdb_query(sql: str, max_rows: int, conn_holder: dict) -> tuple[list[str], list[list]]:
    """Execute a DuckDB query synchronously (runs in thread pool).
    conn_holder['conn'] is set so the caller can interrupt() on timeout.
    """
    conn = get_duckdb_connection()
    conn_holder['conn'] = conn
    try:
        result = conn.execute(sql)
        columns = [d[0] for d in result.description]
        rows = result.fetchmany(max_rows + 1)
        return columns, [list(row) for row in rows]
    finally:
        conn_holder['conn'] = None
        conn.close()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
_POSTGRES_DESCRIPTION = """Execute a read-only SQL query against the Supabase Postgres database. \
Contains ~1M rows of ODI (One Day International) cricket ball-by-ball data from 2013 onwards. \
Table: odi_cricket_ball_by_ball. \
Columns: match_id, season, start_date, venue, innings, ball, batting_team, bowling_team, \
striker, non_striker, bowler, runs_off_bat, extras, wides, noballs, byes, legbyes, penalty, \
wicket_type, player_dismissed, other_wicket_type, other_player_dismissed, match_type. \
Supports JSON (default) and TSV response formats. \
TSV uses shortened headers and is ~70% smaller (better for AI context windows).

DATA SEMANTICS — Each row is a single delivery (ball) in a match. ODI = 50 overs/innings, usually 2 innings per match.

BALL COUNTING — The ball field (e.g. 0.1, 7.5) is an over.ball identifier, NOT a sequential count. \
Overs may have >6 deliveries due to wides/no-balls (e.g. 0.7). Use COUNT(*) for total balls bowled.

RUNS — runs_off_bat = runs scored by batsman. extras = additional runs (wides, no-balls, byes, legbyes, penalty). \
Total runs for a delivery = runs_off_bat + extras. NULL extras components should be treated as 0.

WICKETS — Check both wicket_type AND other_wicket_type for dismissals. If either is non-null, that delivery has a dismissal. \
Common wicket_type values: bowled, caught, lbw, run out, stumped, caught and bowled, hit wicket, retired hurt.

PLAYER NAMES — Use exact full name if known. If uncertain, use surname with LIKE wildcards (e.g. WHERE striker LIKE '%Kohli%').

SEASON FORMAT — Can be a year (2023) or split-year (2023/24) for southern hemisphere seasons.

MATCH_TYPE — Always 'ODI' in this table.

Example query: SELECT striker, SUM(runs_off_bat) as runs, COUNT(*) as balls FROM odi_cricket_ball_by_ball \
WHERE season = '2023' GROUP BY striker ORDER BY runs DESC LIMIT 10"""


@app.post(
    "/api/query/postgres",
    operation_id="query_postgres",
    summary="Run read-only SQL on Postgres (Supabase) — ODI Cricket ball-by-ball data",
    description=_POSTGRES_DESCRIPTION,
)
@limiter.limit(RATE_LIMIT)
@limiter.shared_limit(GLOBAL_RATE_LIMIT, scope="global_query", key_func=lambda *args, **kwargs: "global")
async def query_postgres(request: Request, body: QueryRequest):
    if pg_pool is None:
        return JSONResponse(status_code=503, content={"detail": "Postgres not configured"})

    error = validate_sql(body.sql)
    if error:
        return JSONResponse(status_code=400, content={"detail": error})

    max_rows = MAX_TSV_ROWS if body.format.lower() == "tsv" else MAX_JSON_ROWS
    sql = ensure_limit(body.sql, max_rows)

    client_ip = get_client_ip(request)
    acquired, reason = await check_concurrency(client_ip)
    if not acquired:
        if reason == "global":
            return JSONResponse(status_code=503, content={"detail": "Server is at capacity. Please try again in a few seconds."})
        return JSONResponse(status_code=429, content={"detail": "Too many concurrent queries. Please wait for your current query to finish."})

    try:
        async with asyncio.timeout(PG_POOL_ACQUIRE_TIMEOUT):
            async with pg_pool.acquire() as conn:
                records = await conn.fetch(sql)
                if not records:
                    return {"format": body.format.lower(), "columns": [], "rows": [], "row_count": 0, "truncated": False}
                columns = list(records[0].keys())
                rows = [list(r.values()) for r in records[:max_rows + 1]]
    except asyncpg.exceptions.QueryCanceledError:
        return JSONResponse(status_code=408, content={"detail": "Query timed out"})
    except TimeoutError:
        return JSONResponse(status_code=503, content={"detail": "Server busy. Try again in a few seconds."})
    except Exception as e:
        logger.error(f"Postgres query error: {e}")
        return JSONResponse(status_code=500, content={"detail": "Query failed. Check SQL syntax and try again."})
    finally:
        await release_concurrency(client_ip)

    result = rows_to_tsv(columns, rows, max_rows) if body.format.lower() == "tsv" else rows_to_json(columns, rows, max_rows)
    if len(json.dumps(result, default=str).encode()) > MAX_RESPONSE_BYTES:
        return JSONResponse(status_code=413, content={"detail": f"Response too large (>{MAX_RESPONSE_BYTES // 1_048_576}MB). Add filters or narrow your query."})
    return result


_DUCKDB_DESCRIPTION = """Execute a read-only SQL query against the DuckDB database. \
Contains ~1M rows of T20 (Twenty20) cricket ball-by-ball data from 2013 onwards. \
Table: ball_by_ball. \
Columns: match_id, season, start_date, venue, innings, ball, batting_team, bowling_team, \
striker, non_striker, bowler, runs_off_bat, extras, wides, noballs, byes, legbyes, penalty, \
wicket_type, player_dismissed, other_wicket_type, other_player_dismissed, match_type. \
Supports JSON (default) and TSV response formats. \
TSV uses shortened headers and is ~70% smaller (better for AI context windows).

DATA SEMANTICS — Each row is a single delivery (ball) in a match. T20 = 20 overs/innings, usually 2 innings per match.

BALL COUNTING — The ball field (e.g. 0.1, 7.5) is an over.ball identifier, NOT a sequential count. \
Overs may have >6 deliveries due to wides/no-balls (e.g. 0.7). Use COUNT(*) for total balls bowled.

RUNS — runs_off_bat = runs scored by batsman. extras = additional runs (wides, no-balls, byes, legbyes, penalty). \
Total runs for a delivery = runs_off_bat + extras. NULL extras components should be treated as 0.

WICKETS — Check both wicket_type AND other_wicket_type for dismissals. If either is non-null, that delivery has a dismissal. \
Common wicket_type values: bowled, caught, lbw, run out, stumped, caught and bowled, hit wicket, retired hurt.

PLAYER NAMES — Use exact full name if known. If uncertain, use surname with LIKE wildcards (e.g. WHERE striker LIKE '%Kohli%').

SEASON FORMAT — Can be a year (2023) or split-year (2023/24) for southern hemisphere seasons.

MATCH_TYPE — Always 'T20' in this table.

Example query: SELECT striker, SUM(runs_off_bat) as runs, COUNT(*) as balls FROM ball_by_ball \
WHERE season = '2023' GROUP BY striker ORDER BY runs DESC LIMIT 10"""


@app.post(
    "/api/query/duckdb",
    operation_id="query_duckdb",
    summary="Run read-only SQL on DuckDB — T20 Cricket ball-by-ball data",
    description=_DUCKDB_DESCRIPTION,
)
@limiter.limit(RATE_LIMIT)
@limiter.shared_limit(GLOBAL_RATE_LIMIT, scope="global_query", key_func=lambda *args, **kwargs: "global")
async def query_duckdb(request: Request, body: QueryRequest):
    error = validate_sql(body.sql, engine="duckdb")
    if error:
        return JSONResponse(status_code=400, content={"detail": error})

    max_rows = MAX_TSV_ROWS if body.format.lower() == "tsv" else MAX_JSON_ROWS
    sql = ensure_limit(body.sql, max_rows)
    timeout_sec = DUCKDB_QUERY_TIMEOUT_MS / 1000

    client_ip = get_client_ip(request)
    acquired, reason = await check_concurrency(client_ip)
    if not acquired:
        if reason == "global":
            return JSONResponse(status_code=503, content={"detail": "Server is at capacity. Please try again in a few seconds."})
        return JSONResponse(status_code=429, content={"detail": "Too many concurrent queries. Please wait for your current query to finish."})

    conn_holder: dict = {'conn': None}
    try:
        loop = asyncio.get_event_loop()
        columns, rows = await asyncio.wait_for(
            loop.run_in_executor(None, execute_duckdb_query, sql, max_rows, conn_holder),
            timeout=timeout_sec,
        )
    except asyncio.TimeoutError:
        # Interrupt the DuckDB C++ engine to prevent stuck queries
        conn = conn_holder.get('conn')
        if conn is not None:
            try:
                conn.interrupt()
                conn.close()
                logger.warning("DuckDB query interrupted on timeout")
            except Exception:
                pass
        return JSONResponse(status_code=408, content={"detail": "Query timed out"})
    except FileNotFoundError:
        return JSONResponse(status_code=503, content={"detail": "Database unavailable"})
    except Exception as e:
        logger.error(f"DuckDB query error: {e}")
        return JSONResponse(status_code=500, content={"detail": "Query failed. Check SQL syntax and try again."})
    finally:
        await release_concurrency(client_ip)

    result = rows_to_tsv(columns, rows, max_rows) if body.format.lower() == "tsv" else rows_to_json(columns, rows, max_rows)
    if len(json.dumps(result, default=str).encode()) > MAX_RESPONSE_BYTES:
        return JSONResponse(status_code=413, content={"detail": f"Response too large (>{MAX_RESPONSE_BYTES // 1_048_576}MB). Add filters or narrow your query."})
    return result


@app.get(
    "/health",
    operation_id="health_check",
    summary="Health check",
    description="Returns service status, version, and connectivity to both databases.",
)
async def health_check():
    status = {"status": "ok", "version": VERSION}

    # Postgres check
    if pg_pool:
        try:
            async with pg_pool.acquire() as conn:
                await conn.fetchval("SELECT 1")
            status["postgres"] = "connected"
        except Exception:
            status["postgres"] = "error"
    else:
        status["postgres"] = "not configured"

    # DuckDB check
    try:
        conn = get_duckdb_connection()
        conn.execute("SELECT 1")
        conn.close()
        status["duckdb"] = "connected"
    except Exception:
        status["duckdb"] = "error"

    return status


# ---------------------------------------------------------------------------
# Startup / Shutdown
# ---------------------------------------------------------------------------
@app.on_event("startup")
async def startup_event():
    logger.info(f"Database MCP Server v{VERSION} starting")
    await init_pg_pool()

    # Verify DuckDB file and log resource limits
    if os.path.exists(DUCKDB_FILE):
        size_mb = os.path.getsize(DUCKDB_FILE) / (1024 * 1024)
        logger.info(f"DuckDB file: {DUCKDB_FILE} ({size_mb:.1f} MB)")
        logger.info(f"DuckDB limits: memory={DUCKDB_MEMORY_LIMIT}, threads={DUCKDB_THREADS}, temp_dir={DUCKDB_TEMP_DIR}, max_temp={DUCKDB_MAX_TEMP_DIR_SIZE}")
    else:
        logger.warning(f"DuckDB file not found: {DUCKDB_FILE}")

    # MCP setup
    base_url = os.getenv("RENDER_EXTERNAL_URL", "http://localhost:8000")
    logger.info(f"MCP endpoint available at: {base_url}/mcp")

    logger.info("Available routes:")
    for route in app.routes:
        if hasattr(route, "operation_id") and route.operation_id:
            logger.info(f"  {route.path} -> {route.operation_id}")


@app.on_event("shutdown")
async def shutdown_event():
    await close_pg_pool()
    logger.info("Server shut down")


# ---------------------------------------------------------------------------
# MCP integration (fastapi-mcp)
# Uses localhost httpx client (bypasses Cloudflare) and forwards client IP
# headers so per-IP concurrency limiting uses real client IPs.
# Note: ASGITransport was tried but conflicts with BaseHTTPMiddleware
# (double http.response.start assertion error on re-entrant ASGI calls).
# ---------------------------------------------------------------------------
mcp = None
try:
    from fastapi_mcp import FastApiMCP

    mcp = FastApiMCP(
        app,
        name="Database MCP Server",
        description=(
            "Read-only SQL query interface for two cricket databases: "
            "Postgres (Supabase) with ~1M ODI records and DuckDB with ~1M T20 records. "
            "Both cover 2013-2025 ball-by-ball data."
        ),
        include_operations=["query_postgres", "query_duckdb", "health_check"],
        describe_all_responses=True,
        describe_full_response_schema=True,
        headers=["authorization", "cf-connecting-ip", "x-forwarded-for", "x-real-ip"],
        http_client=httpx.AsyncClient(
            timeout=60.0,
            limits=httpx.Limits(max_keepalive_connections=5, max_connections=10),
            base_url="http://localhost:8000",
        ),
    )
    mcp.mount()
    logger.info("MCP (open) mounted at /mcp")
except ImportError:
    logger.warning("fastapi-mcp not installed, MCP endpoint disabled")
except Exception as e:
    logger.error(f"MCP setup error: {e}")


# ---------------------------------------------------------------------------
# Secured MCP endpoint (Auth0 OAuth) — same tools, requires authentication.
# Only mounted if AUTH0_DOMAIN is configured. Lives at /mcp-secure.
# ---------------------------------------------------------------------------
mcp_secure = None
if AUTH0_DOMAIN:
    try:
        from fastapi_mcp import FastApiMCP, AuthConfig
        from jose import jwt as jose_jwt, JWTError

        # Cache JWKS at import time (refreshed on restart)
        _jwks_cache = None

        async def _get_jwks():
            global _jwks_cache
            if _jwks_cache is None:
                async with httpx.AsyncClient() as client:
                    resp = await client.get(
                        f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"
                    )
                    resp.raise_for_status()
                    _jwks_cache = resp.json()
            return _jwks_cache

        # Failed-auth rate limiter: block IPs with too many failed JWT attempts
        AUTH_FAIL_MAX = int(os.getenv("AUTH_FAIL_MAX", "5"))          # max failures per window
        AUTH_FAIL_WINDOW = int(os.getenv("AUTH_FAIL_WINDOW", "86400"))  # window in seconds (24 hours)
        AUTH_FAIL_MAX_IPS = 1000  # max tracked IPs before cleanup
        _auth_failures: dict[str, list[float]] = {}

        def _record_auth_failure(ip: str):
            now = time.time()
            if ip not in _auth_failures:
                _auth_failures[ip] = []
            _auth_failures[ip].append(now)
            # Cleanup: if dict exceeds max IPs, purge all expired entries
            if len(_auth_failures) > AUTH_FAIL_MAX_IPS:
                cutoff = now - AUTH_FAIL_WINDOW
                expired = [k for k, v in _auth_failures.items() if not v or v[-1] < cutoff]
                for k in expired:
                    del _auth_failures[k]

        def _is_auth_blocked(ip: str) -> bool:
            if ip not in _auth_failures:
                return False
            now = time.time()
            cutoff = now - AUTH_FAIL_WINDOW
            # Prune old entries for this IP
            _auth_failures[ip] = [t for t in _auth_failures[ip] if t > cutoff]
            if not _auth_failures[ip]:
                del _auth_failures[ip]
                return False
            return len(_auth_failures[ip]) >= AUTH_FAIL_MAX

        async def verify_oauth_token(request: Request):
            """Verify Auth0 JWT bearer token on the secured MCP endpoint."""
            client_ip = get_client_ip(request)
            if _is_auth_blocked(client_ip):
                logger.warning(f"Auth rate limit hit for {client_ip}")
                raise HTTPException(status_code=429, detail="Too many failed auth attempts. Try again later.")
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                _record_auth_failure(client_ip)
                raise HTTPException(status_code=401, detail="Missing bearer token")
            token = auth_header.split(" ", 1)[1]
            try:
                jwks = await _get_jwks()
                payload = jose_jwt.decode(
                    token,
                    jwks,
                    algorithms=["RS256"],
                    audience=AUTH0_AUDIENCE,
                    issuer=f"https://{AUTH0_DOMAIN}/",
                )
                return payload
            except JWTError as e:
                logger.warning(f"OAuth token verification failed: {type(e).__name__}")
                _record_auth_failure(client_ip)
                raise HTTPException(status_code=401, detail="Invalid or expired token")

        mcp_secure = FastApiMCP(
            app,
            name="Database MCP Server (Secured)",
            description=(
                "Secured read-only SQL query interface for two cricket databases. "
                "Requires Auth0 OAuth authentication. "
                "Postgres (Supabase) with ~1M ODI records and DuckDB with ~1M T20 records."
            ),
            include_operations=["query_postgres", "query_duckdb", "health_check"],
            describe_all_responses=True,
            describe_full_response_schema=True,
            headers=["authorization", "cf-connecting-ip", "x-forwarded-for", "x-real-ip"],
            http_client=httpx.AsyncClient(
                timeout=60.0,
                limits=httpx.Limits(max_keepalive_connections=5, max_connections=10),
                base_url="http://localhost:8000",
            ),
            auth_config=AuthConfig(
                issuer=f"https://{AUTH0_DOMAIN}/",
                authorize_url=f"https://{AUTH0_DOMAIN}/authorize",
                oauth_metadata_url=f"https://{AUTH0_DOMAIN}/.well-known/openid-configuration",
                audience=AUTH0_AUDIENCE,
                client_id=AUTH0_CLIENT_ID,
                client_secret=AUTH0_CLIENT_SECRET,
                dependencies=[Depends(verify_oauth_token)],
                setup_proxies=True,
            ),
        )
        mcp_secure.mount(mount_path="/mcp-secure")
        logger.info("MCP (secured/Auth0) mounted at /mcp-secure")
    except ImportError as e:
        logger.warning(f"Secured MCP dependencies missing ({e}), /mcp-secure disabled")
    except Exception as e:
        logger.error(f"Secured MCP setup error: {e}")
else:
    logger.info("AUTH0_DOMAIN not set, /mcp-secure endpoint disabled")


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
