"""
Agentic DBA Investigator — iteratively queries SQL Server,
analyzes results, and drills down to root cause.

The AI dynamically generates SQL queries based on the problem description,
with strict read-only safety validation on every query.
"""

import re
import json
import logging
from typing import Optional, Callable, List, Dict, Tuple

logger = logging.getLogger("dba-ai-assistant")


# =====================================================================
# SQL SAFETY VALIDATOR — ensures only read-only queries are executed
# =====================================================================

BLOCKED_PATTERNS = [
    # DML
    r'\bINSERT\b', r'\bUPDATE\b', r'\bDELETE\b', r'\bMERGE\b',
    # DDL
    r'\bDROP\b', r'\bALTER\b', r'\bCREATE\b', r'\bTRUNCATE\b',
    # Security
    r'\bGRANT\b', r'\bREVOKE\b', r'\bDENY\b',
    # Dangerous operations
    r'\bKILL\b', r'\bSHUTDOWN\b', r'\bRESTORE\b', r'\bBACKUP\b',
    r'\bRECONFIGURE\b',
    # SELECT INTO (creates tables)
    r'\bINTO\s+\w+\s+FROM\b', r'\bSELECT\s+INTO\b',
    # Dangerous stored procedures
    r'\bxp_cmdshell\b', r'\bsp_configure\b',
    r'\bsp_addlinkedserver\b', r'\bsp_addlogin\b',
    r'\bsp_addsrvrolemember\b',
    # External data access
    r'\bOPENROWSET\b', r'\bOPENDATASOURCE\b', r'\bOPENQUERY\b',
    r'\bBULK\s+INSERT\b',
    # Destructive DBCC commands
    r'\bDBCC\s+SHRINK\b', r'\bDBCC\s+DROP\b', r'\bDBCC\s+FREE\b',
    r'\bDBCC\s+DBREINDEX\b', r'\bDBCC\s+REPAIR\b',
    # Wait/delay (prevents resource tying)
    r'\bWAITFOR\b',
    # Transactions
    r'\bBEGIN\s+TRAN', r'\bCOMMIT\b', r'\bROLLBACK\b',
]

ALLOWED_START = [
    r'^\s*SELECT\b',
    r'^\s*WITH\b',  # CTEs
    r'^\s*DBCC\s+SHOW_STATISTICS\b',
    r'^\s*DBCC\s+SQLPERF\b',
    r'^\s*DBCC\s+INPUTBUFFER\b',
    r'^\s*DBCC\s+OPENTRAN\b',
    r'^\s*DBCC\s+TRACESTATUS\b',
    r'^\s*DBCC\s+LOGINFO\b',
]


def validate_sql_safety(sql: str) -> Tuple[bool, str]:
    """
    Validate that a SQL query is read-only and safe to execute.
    Returns (is_safe, reason).
    """
    # Remove SQL comments
    cleaned = re.sub(r'--.*$', '', sql, flags=re.MULTILINE)
    cleaned = re.sub(r'/\*.*?\*/', '', cleaned, flags=re.DOTALL)
    cleaned = cleaned.strip()

    if not cleaned:
        return False, "Empty query"

    # Must start with an allowed keyword
    allowed = any(re.match(p, cleaned, re.IGNORECASE) for p in ALLOWED_START)
    if not allowed:
        return False, "Query must start with SELECT, WITH, or allowed DBCC command"

    # Check for blocked patterns anywhere in the query
    for pattern in BLOCKED_PATTERNS:
        match = re.search(pattern, cleaned, re.IGNORECASE)
        if match:
            return False, f"Blocked: '{match.group()}' is not allowed"

    # Check for multiple statements — each must start with allowed keyword
    statements = [s.strip() for s in cleaned.split(';') if s.strip()]
    for stmt in statements:
        stmt_ok = any(re.match(p, stmt, re.IGNORECASE) for p in ALLOWED_START)
        if not stmt_ok:
            return False, "Multi-statement batch contains non-SELECT statement"

    return True, "OK"


# =====================================================================
# AGENT SYSTEM PROMPT
# =====================================================================

AGENT_SYSTEM_PROMPT = """You are a Senior SQL Server DBA investigator. You diagnose database performance issues by running diagnostic queries and analyzing results iteratively — just like an expert DBA would in SSMS.

## How You Work
You investigate problems step-by-step:
1. Understand the reported problem
2. Run diagnostic queries to gather evidence
3. Analyze results and decide what to check next
4. Drill deeper ONLY if you found something genuinely abnormal
5. Continue until you have enough evidence
6. Deliver a final report — honest assessment, not forced problems

## Critical Mindset: Do NOT Invent Problems
You MUST interpret results like an experienced DBA, not a pattern matcher:
- **If metrics look healthy, say so.** A clean bill of health IS a valid finding.
- **Do NOT force root cause analysis when there is no problem.** If the user asks about X and X looks fine, report that X is healthy.
- **Cumulative wait stats are NOT indicators of active problems.** sys.dm_os_wait_stats shows totals since server restart. High cumulative waits on a server up for weeks/months are normal. Only flag waits if they show high average wait times or are dominating recent activity.
- **Distinguish idle/background waits from real problems.** These waits are NORMAL and should NEVER be flagged as issues:
  - HADR_WORK_QUEUE (AG worker idle wait — means worker threads are waiting for work, NOT that they're overloaded)
  - HADR_LOGCAPTURE_WAIT (normal log scanning pause)
  - HADR_TIMER_TASK, HADR_CLUSAPI_CALL (normal AG housekeeping)
  - SLEEP_TASK, LAZYWRITER_SLEEP, SQLTRACE_BUFFER_FLUSH, BROKER_TO_FLUSH
  - SP_SERVER_DIAGNOSTICS_SLEEP, QDS_PERSIST_TASK_MAIN_LOOP_SLEEP
  - WAITFOR_TASKSHUTDOWN, CLR_AUTO_EVENT, DIRTY_PAGE_POLL
- **Always On / HADR interpretation rules:**
  - log_send_rate = 0 and redo_rate = 0 on the PRIMARY replica is EXPECTED (primary does not send/redo to itself)
  - SYNCHRONIZING state on a secondary in ASYNCHRONOUS_COMMIT mode is NORMAL
  - Only flag log_send_queue_size or redo_queue_size if they are large AND growing on SECONDARY replicas
  - Compare replica roles (PRIMARY vs SECONDARY) before drawing conclusions
- **PLE (Page Life Expectancy):** Healthy if > 300 per 4GB of max server memory. A PLE of thousands or millions is excellent.
- **Zero rows returned often means no problem** (e.g., no blocking = healthy, no long-running queries = healthy).

## Running Queries
When you need to run a SQL query, output it inside [SQL] tags:

[SQL]
SELECT TOP 10 wait_type, wait_time_ms / 1000.0 AS wait_sec
FROM sys.dm_os_wait_stats
WHERE wait_type NOT IN ('SLEEP_TASK','LAZYWRITER_SLEEP')
ORDER BY wait_time_ms DESC
[/SQL]

RULES for queries:
- Only SELECT, WITH (CTEs), and read-only DBCC commands are allowed
- NEVER use INSERT, UPDATE, DELETE, DROP, ALTER, CREATE, EXEC, KILL
- NEVER use SELECT INTO, xp_cmdshell, OPENROWSET
- NEVER use WAITFOR
- Keep queries focused — one investigation step at a time
- Use TOP to limit large result sets
- Always alias columns clearly

## Key DMVs You Can Query
Performance: sys.dm_exec_requests, sys.dm_exec_sessions, sys.dm_exec_query_stats, sys.dm_exec_procedure_stats
Waits: sys.dm_os_wait_stats, sys.dm_os_waiting_tasks
Memory: sys.dm_os_process_memory, sys.dm_os_memory_clerks, sys.dm_os_buffer_descriptors, sys.dm_os_performance_counters
I/O: sys.dm_io_virtual_file_stats, sys.master_files
Indexes: sys.dm_db_index_usage_stats, sys.dm_db_index_physical_stats, sys.dm_db_missing_index_details, sys.dm_db_missing_index_groups, sys.dm_db_missing_index_group_stats
TempDB: sys.dm_db_session_space_usage, sys.dm_db_task_space_usage
Locks: sys.dm_tran_locks, sys.dm_os_waiting_tasks
Connections: sys.dm_exec_connections
Plan Cache: sys.dm_exec_cached_plans, sys.dm_exec_plan_attributes
Query Store: sys.query_store_runtime_stats, sys.query_store_plan, sys.query_store_query, sys.query_store_query_text (database-scoped)
System Catalogs: sys.databases, sys.tables, sys.indexes, sys.columns, sys.objects
SQL Agent: msdb.dbo.sysjobs, msdb.dbo.sysjobhistory, msdb.dbo.sysjobactivity
Database Files: sys.database_files, sys.master_files
Always On: sys.dm_hadr_database_replica_states, sys.dm_hadr_availability_replica_states, sys.availability_groups, sys.availability_replicas
SQL Text/Plans: sys.dm_exec_sql_text(sql_handle), sys.dm_exec_query_plan(plan_handle) — use with CROSS APPLY

## Reference Query Patterns
Use these EXACT patterns for common requests. Do not improvise alternative SQL for these scenarios.

**Top N Missing Indexes (server-wide, ordered by impact):**
```sql
SELECT TOP 5
    CONVERT(decimal(18,2), migs.avg_total_user_cost * migs.avg_user_impact * (migs.user_seeks + migs.user_scans)) AS impact,
    migs.avg_total_user_cost AS avg_cost,
    migs.avg_user_impact AS avg_impact,
    migs.user_seeks,
    migs.user_scans,
    mid.statement AS table_name,
    mid.equality_columns,
    mid.inequality_columns,
    mid.included_columns
FROM sys.dm_db_missing_index_group_stats AS migs
INNER JOIN sys.dm_db_missing_index_groups AS mig
    ON migs.group_handle = mig.index_group_handle
INNER JOIN sys.dm_db_missing_index_details AS mid
    ON mig.index_handle = mid.index_handle
WHERE mid.database_id = DB_ID('<target_database>')
ORDER BY impact DESC;
```

IMPORTANT: When the user specifies a database name (e.g., "missing indexes on VDS"), replace `<target_database>` with that database name in the WHERE clause. If no database is specified, use DB_ID() to scope to the current database context. Never return missing indexes across all databases when the user has mentioned a specific database.

**Top N Unused Indexes (per database, run in target DB context):**
```sql
SELECT TOP 10
    OBJECT_NAME(i.object_id) AS table_name,
    i.name AS index_name,
    i.type_desc,
    s.user_seeks, s.user_scans, s.user_lookups, s.user_updates,
    SUM(ps.reserved_page_count) * 8 / 1024 AS index_size_mb
FROM sys.indexes i
INNER JOIN sys.dm_db_index_usage_stats s ON i.object_id = s.object_id AND i.index_id = s.index_id AND s.database_id = DB_ID()
INNER JOIN sys.dm_db_partition_stats ps ON i.object_id = ps.object_id AND i.index_id = ps.index_id
WHERE OBJECTPROPERTY(i.object_id, 'IsUserTable') = 1 AND i.index_id > 1
  AND s.user_seeks = 0 AND s.user_scans = 0 AND s.user_lookups = 0
GROUP BY OBJECT_NAME(i.object_id), i.name, i.type_desc, s.user_seeks, s.user_scans, s.user_lookups, s.user_updates
ORDER BY index_size_mb DESC;
```

**Top N Expensive Queries by CPU:**
```sql
SELECT TOP 10
    qs.total_worker_time / 1000 AS total_cpu_ms,
    qs.execution_count,
    qs.total_worker_time / qs.execution_count / 1000 AS avg_cpu_ms,
    qs.total_logical_reads,
    qs.total_elapsed_time / 1000 AS total_elapsed_ms,
    SUBSTRING(qt.text, (qs.statement_start_offset/2)+1,
        ((CASE qs.statement_end_offset WHEN -1 THEN DATALENGTH(qt.text) ELSE qs.statement_end_offset END - qs.statement_start_offset)/2)+1) AS query_text
FROM sys.dm_exec_query_stats qs
CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) qt
ORDER BY qs.total_worker_time DESC;
```

## Important Notes
- This is an OLDER SQL Server version. Some columns may not exist (e.g., sys.dm_exec_sessions may lack blocking_session_id, wait_type; sys.dm_xe_sessions may lack is_running). If a query errors with "Invalid column name", adapt and try alternative columns or DMVs.
- Think step by step. Do not try to find everything in one query.
- Run 1 query at a time.
- After each result, explain what you found and what you will check next.
- Be thorough but efficient — typically 3-8 queries are enough.
- Cite actual numbers from results in your findings.
- **If everything looks healthy, say so clearly and wrap up quickly. Do not keep querying trying to find problems that don't exist.**
- **When a reference query pattern exists above for the user's request, use it as-is (adjusting TOP N as needed). Do not rewrite the query.**

## Finishing the Investigation
When you have enough evidence, output your final report inside [REPORT] tags:

[REPORT]
## Summary
(2-3 sentence executive summary. If everything is healthy, lead with that.)

## Findings
(Numbered list with severity: Critical, Warning, OK — cite actual numbers.
It is perfectly valid for all findings to be OK.
IMPORTANT: List EVERY individual item from the query results separately. If the user asked for "top 5 missing indexes" and the query returned 5 rows, list ALL 5 as separate numbered findings with their specific details — table name, impact score, columns, etc. Do NOT summarize multiple rows into a single finding.
Stay focused on what the user asked. Do not add extra checks or findings beyond the scope of the original question.)

## Root Cause Analysis
(ONLY include this section if there is a genuine problem found.
If everything is healthy, OMIT this section entirely — do not include it.)

## Recommendations
(ONLY if there are actual issues. For healthy systems, simply say "No action needed."
Do not add proactive monitoring suggestions unless the user asked for them.
For each recommendation: what to do, why it helps, risk level)

## Monitoring Follow-up
(Brief — 1-2 lines max. What to watch going forward.)
[/REPORT]
"""


class DBAAgent:
    """Agentic DBA investigator that iteratively diagnoses SQL Server issues."""

    def __init__(self, connector, provider: str = "openai",
                 api_key: Optional[str] = None,
                 api_base: Optional[str] = None,
                 model: str = "gpt-4o",
                 api_version: str = "2024-06-01",
                 max_iterations: int = 8,
                 extra_headers: Optional[dict] = None):
        self.connector = connector
        self.provider = provider
        self.api_key = api_key
        self.api_base = api_base
        self.model = model
        self.api_version = api_version
        self.max_iterations = max_iterations
        self.extra_headers = extra_headers
        self.last_api_endpoint = "rule-based"

    def _get_client(self, base_url: str = None, api_key: str = None,
                    extra_headers: dict = None):
        """Create the appropriate OpenAI client."""
        from openai import OpenAI, AzureOpenAI

        key = api_key or self.api_key
        if self.provider == "github":
            return OpenAI(
                api_key=key,
                base_url=base_url or "https://models.inference.ai.azure.com",
                default_headers=extra_headers or {},
            )
        elif self.provider == "azure":
            return AzureOpenAI(
                api_key=key,
                api_version=self.api_version,
                azure_endpoint=self.api_base,
            )
        else:  # openai (or compatible endpoint)
            kwargs = {"api_key": key}
            if self.api_base:
                kwargs["base_url"] = self.api_base
            if self.extra_headers or extra_headers:
                headers = extra_headers or self.extra_headers
                # Filter out None values to avoid header errors
                kwargs["default_headers"] = {k: v for k, v in headers.items() if v is not None}
            return OpenAI(**kwargs)

    def _call_ai(self, client, messages: List[Dict], tools=None):
        """Call the AI model and return the raw message object.
        For GitHub provider, tries multiple endpoints."""
        if self.provider == "github":
            return self._call_github_ai(messages, tools=tools)

        kwargs = dict(
            model=self.model, messages=messages,
            temperature=0, max_tokens=4000, timeout=60,
        )
        if tools:
            kwargs["tools"] = tools
        response = client.chat.completions.create(**kwargs)
        if self.provider == "azure":
            self.last_api_endpoint = self.api_base or "azure"
        else:
            self.last_api_endpoint = self.api_base or "openai"
        return response.choices[0].message

    def _call_github_ai(self, messages: List[Dict], tools=None):
        """Call GitHub AI endpoints with automatic Copilot token exchange fallback."""
        from analyzer.token_resolver import get_copilot_token

        kwargs = dict(
            model=self.model, messages=messages,
            temperature=0, max_tokens=4000, timeout=60,
        )
        if tools:
            kwargs["tools"] = tools

        # Strategy 1: Try models.inference.ai.azure.com with raw token
        try:
            logger.info("Trying models.inference.ai.azure.com...")
            c = self._get_client(base_url="https://models.inference.ai.azure.com")
            response = c.chat.completions.create(**kwargs)
            self.last_api_endpoint = "https://models.inference.ai.azure.com"
            return response.choices[0].message
        except Exception as e:
            logger.warning(f"GitHub Models failed: {e}")

        # Strategy 2: Try api.githubcopilot.com with Copilot token exchange
        try:
            logger.info("Trying api.githubcopilot.com with Copilot token exchange...")
            copilot_token, headers = get_copilot_token(self.api_key)
            c = self._get_client(
                base_url="https://api.githubcopilot.com",
                api_key=copilot_token,
                extra_headers=headers,
            )
            try:
                response = c.chat.completions.create(**kwargs)
                self.last_api_endpoint = "https://api.githubcopilot.com"
                return response.choices[0].message
            except Exception as e:
                # If tools not supported, retry without tools
                if tools and ("tool" in str(e).lower() or "function" in str(e).lower()):
                    logger.warning(f"Tools not supported, retrying without: {e}")
                    kwargs.pop("tools", None)
                    response = c.chat.completions.create(**kwargs)
                    self.last_api_endpoint = "https://api.githubcopilot.com"
                    return response.choices[0].message
                raise
        except Exception as e:
            logger.warning(f"Copilot API failed: {e}")
            raise

    def _extract_sql(self, text: str) -> List[str]:
        """Extract SQL queries from [SQL]...[/SQL] tags."""
        pattern = r'\[SQL\](.*?)\[/SQL\]'
        matches = re.findall(pattern, text, re.DOTALL)
        return [m.strip() for m in matches if m.strip()]

    def _extract_report(self, text: str) -> Optional[str]:
        """Extract final report from [REPORT]...[/REPORT] tags."""
        pattern = r'\[REPORT\](.*?)\[/REPORT\]'
        match = re.search(pattern, text, re.DOTALL)
        return match.group(1).strip() if match else None

    # Function calling tools definition
    AGENT_TOOLS = [
        {
            "type": "function",
            "function": {
                "name": "run_sql_query",
                "description": "Execute a read-only SQL query against the SQL Server to gather diagnostic information.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "sql": {
                            "type": "string",
                            "description": "The SQL query. Must be SELECT, WITH (CTE), or safe DBCC only."
                        },
                        "purpose": {
                            "type": "string",
                            "description": "Brief description of what this query checks."
                        }
                    },
                    "required": ["sql", "purpose"]
                }
            }
        }
    ]

    def _collect_server_context(self, progress) -> str:
        """
        Collect server metadata upfront so the AI knows the environment.
        Returns a formatted context string to inject into the conversation.
        """
        progress("Collecting server context...")

        context_queries = {
            "server_info": """
                SELECT
                    SERVERPROPERTY('MachineName') AS machine_name,
                    SERVERPROPERTY('ServerName') AS server_name,
                    SERVERPROPERTY('ProductVersion') AS product_version,
                    SERVERPROPERTY('ProductLevel') AS product_level,
                    SERVERPROPERTY('Edition') AS edition,
                    SERVERPROPERTY('EngineEdition') AS engine_edition,
                    SERVERPROPERTY('ProductMajorVersion') AS major_version,
                    @@VERSION AS full_version,
                    (SELECT sqlserver_start_time FROM sys.dm_os_sys_info) AS start_time,
                    (SELECT cpu_count FROM sys.dm_os_sys_info) AS cpu_count,
                    (SELECT physical_memory_kb / 1048576 FROM sys.dm_os_sys_info) AS physical_memory_gb
            """,
            "server_info_fallback": """
                SELECT
                    SERVERPROPERTY('MachineName') AS machine_name,
                    SERVERPROPERTY('ServerName') AS server_name,
                    SERVERPROPERTY('ProductVersion') AS product_version,
                    SERVERPROPERTY('ProductLevel') AS product_level,
                    SERVERPROPERTY('Edition') AS edition,
                    @@VERSION AS full_version,
                    (SELECT cpu_count FROM sys.dm_os_sys_info) AS cpu_count
            """,
            "databases": """
                SELECT name, state_desc, recovery_model_desc,
                       compatibility_level
                FROM sys.databases
                WHERE database_id > 4
                ORDER BY name
            """,
            "ag_info": """
                SELECT ag.name AS ag_name,
                       ar.replica_server_name,
                       ars.role_desc,
                       ar.availability_mode_desc,
                       ar.failover_mode_desc
                FROM sys.availability_groups ag
                JOIN sys.availability_replicas ar ON ag.group_id = ar.group_id
                LEFT JOIN sys.dm_hadr_availability_replica_states ars
                    ON ar.replica_id = ars.replica_id
                ORDER BY ag.name, ars.role_desc
            """,
            "memory_config": """
                SELECT
                    c.value_in_use AS max_server_memory_mb,
                    (SELECT cntr_value FROM sys.dm_os_performance_counters
                     WHERE RTRIM(counter_name) = 'Page life expectancy'
                       AND RTRIM(object_name) LIKE '%Buffer Manager') AS ple
                FROM sys.configurations c
                WHERE c.name = 'max server memory (MB)'
            """,
        }

        parts = []

        # Server info (try full, fallback to simpler)
        result = self.connector.execute_query(context_queries["server_info"])
        if result.get("error"):
            result = self.connector.execute_query(context_queries["server_info_fallback"])
        if result.get("rows"):
            row = result["rows"][0]
            version = str(row.get("full_version", "")).split("\n")[0]
            major = str(row.get("product_version", "")).split(".")[0] if row.get("product_version") else "?"
            parts.append(f"**Server:** {row.get('server_name', '?')}")
            parts.append(f"**Version:** {version}")
            parts.append(f"**Edition:** {row.get('edition', '?')}")
            parts.append(f"**Major Version:** SQL Server {self._version_year(major)} ({row.get('product_version', '?')}, {row.get('product_level', '?')})")
            if row.get("cpu_count"):
                parts.append(f"**CPUs (schedulers):** {row.get('cpu_count')}")
            if row.get("physical_memory_gb"):
                parts.append(f"**Physical Memory:** {row.get('physical_memory_gb')} GB")
            if row.get("start_time"):
                parts.append(f"**Server Start Time:** {row.get('start_time')}")

            # Store major version for DMV guidance
            self._sql_major_version = int(major) if major.isdigit() else 0
            progress(f"  Server: SQL Server {self._version_year(major)} ({row.get('edition', '?')})")

        # Memory config
        result = self.connector.execute_query(context_queries["memory_config"])
        if result.get("rows"):
            row = result["rows"][0]
            parts.append(f"**Max Server Memory:** {row.get('max_server_memory_mb', '?')} MB")
            parts.append(f"**Page Life Expectancy:** {row.get('ple', '?')}")

        # Databases
        result = self.connector.execute_query(context_queries["databases"])
        if result.get("rows"):
            db_list = [f"{r['name']} ({r.get('state_desc','?')}, {r.get('recovery_model_desc','?')})"
                       for r in result["rows"][:30]]
            parts.append(f"**User Databases ({result['row_count']}):** {', '.join(db_list)}")
            progress(f"  Databases: {result['row_count']} user databases")

        # Availability Groups
        result = self.connector.execute_query(context_queries["ag_info"])
        if result.get("rows") and result["row_count"] > 0:
            ag_lines = []
            for r in result["rows"]:
                ag_lines.append(
                    f"  - {r.get('ag_name','?')}: {r.get('replica_server_name','?')} "
                    f"({r.get('role_desc','?')}, {r.get('availability_mode_desc','?')})"
                )
            parts.append(f"**Always On AGs:**\n" + "\n".join(ag_lines))
            progress(f"  Always On: {result['row_count']} replicas found")
        elif not result.get("error"):
            parts.append("**Always On:** Not configured")

        return "\n".join(parts) if parts else "Server context could not be collected."

    @staticmethod
    def _version_year(major: str) -> str:
        """Map SQL Server major version to marketing year."""
        return {
            "9": "2005", "10": "2008", "11": "2012", "12": "2014",
            "13": "2016", "14": "2017", "15": "2019", "16": "2022",
        }.get(major, major)

    def _get_version_guidance(self) -> str:
        """Return DMV availability notes based on the detected SQL Server version."""
        v = getattr(self, "_sql_major_version", 0)
        notes = []
        if v and v < 11:
            notes.append("- SQL Server 2008 or earlier: sys.dm_exec_sessions lacks wait_type, blocking_session_id. Use sys.dm_exec_requests for wait/blocking info.")
            notes.append("- sys.dm_exec_sessions lacks most_recent_sql_handle. Join sys.dm_exec_connections instead.")
            notes.append("- sys.database_files lacks database_id. Use DB_NAME() instead.")
            notes.append("- sys.dm_xe_sessions may lack is_running, max_dispatch_latency columns.")
            notes.append("- sys.server_event_sessions may lack is_default, is_enabled columns.")
            notes.append("- sys.dm_xe_session_targets lacks event_session_name. Join on event_session_address.")
        elif v and v < 13:
            notes.append("- SQL Server 2012/2014: Some newer DMV columns may be missing. If a query errors with 'Invalid column name', adapt and retry with alternative columns.")
        elif v and v < 14:
            notes.append("- SQL Server 2016: Most modern DMVs available. Query Store available if enabled.")
        if notes:
            return "\n\n**Version-Specific DMV Notes (auto-detected):**\n" + "\n".join(notes)
        return ""

    def investigate(self, problem: str,
                    on_progress: Optional[Callable] = None) -> str:
        """
        Investigate a database problem using iterative AI-driven analysis.

        Args:
            problem: Natural language problem description
            on_progress: Callback(message, optional_data) for progress updates

        Returns:
            Final investigation report (markdown)
        """
        def progress(msg, data=None):
            if on_progress:
                on_progress(msg, data)
            logger.info(msg)

        try:
            from openai import OpenAI
        except ImportError:
            return "Error: openai package not installed. Run: pip install openai"

        if self.provider == "rules":
            return ("Error: Investigation mode requires an AI provider "
                    "(openai, azure, or github). Rule-based mode cannot "
                    "generate dynamic queries. Set ai.provider in config.yaml.")

        if not self.api_key:
            return "Error: No API key configured. Set ai.api_key in config.yaml."

        progress("Starting investigation: " + problem)

        # Collect server context before starting the AI loop
        server_context = self._collect_server_context(progress)
        version_guidance = self._get_version_guidance()

        system_content = AGENT_SYSTEM_PROMPT
        if version_guidance:
            system_content += version_guidance

        user_content = (
            f"## Server Environment\n{server_context}\n\n"
            f"---\n## Problem to Investigate\n{problem}"
        )

        messages = [
            {"role": "system", "content": system_content},
            {"role": "user", "content": user_content},
        ]

        client = self._get_client()
        investigation_log = []
        use_tools = True  # Try function calling first

        for iteration in range(1, self.max_iterations + 1):
            progress(f"\n--- Step {iteration}/{self.max_iterations} ---")

            # Call AI (with tools if supported)
            try:
                tools = self.AGENT_TOOLS if use_tools else None
                ai_msg = self._call_ai(client, messages, tools=tools)
            except Exception as e:
                error_msg = str(e)
                progress(f"AI API error: {error_msg}")
                if investigation_log:
                    return self._build_error_report(problem, investigation_log, error_msg)
                return f"Error: AI API call failed: {error_msg}"

            # --- Path A: Function calling (tool_calls present) ---
            if hasattr(ai_msg, 'tool_calls') and ai_msg.tool_calls:
                # Add assistant message with tool_calls to conversation
                messages.append({
                    "role": "assistant",
                    "content": ai_msg.content or "",
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {"name": tc.function.name, "arguments": tc.function.arguments}
                        }
                        for tc in ai_msg.tool_calls
                    ]
                })

                if ai_msg.content:
                    progress(f"Agent: {ai_msg.content[:300]}")

                for tc in ai_msg.tool_calls:
                    args = json.loads(tc.function.arguments)
                    sql = args.get("sql", "")
                    purpose = args.get("purpose", "")
                    if purpose:
                        progress(f"  Purpose: {purpose}")

                    result_msg = self._execute_and_log(
                        sql, purpose, investigation_log, progress
                    )

                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": result_msg,
                    })

                # Trim conversation if it's getting too large
                messages = self._trim_messages(messages)
                continue

            # --- Path B: Text-based (fallback) ---
            use_tools = False  # Endpoint doesn't support tools, stop trying
            response = ai_msg.content or ""

            # Check for final report
            report = self._extract_report(response)
            if report:
                progress("Investigation complete")
                log_section = self._format_investigation_log(investigation_log)
                return report + log_section

            # Extract SQL queries from [SQL] tags
            queries = self._extract_sql(response)

            if not queries:
                messages.append({"role": "assistant", "content": response})
                messages.append({"role": "user", "content":
                    "Continue your investigation. Run a diagnostic query using "
                    "[SQL]...[/SQL] tags, or provide your final [REPORT]...[/REPORT]."
                })
                progress("Agent thinking: " + response[:300])
                continue

            reasoning = response.split("[SQL]")[0].strip()
            if reasoning:
                progress("Agent: " + reasoning[:300])

            messages.append({"role": "assistant", "content": response})

            query_results = []
            for i, sql in enumerate(queries):
                result_msg = self._execute_and_log(
                    sql, reasoning[:100] if reasoning else "",
                    investigation_log, progress
                )
                query_results.append(result_msg)

            results_text = "\n\n".join(
                f"**Query {i+1} result:**\n{r}" for i, r in enumerate(query_results)
            )
            messages.append({
                "role": "user",
                "content": (
                    f"Here are the query results:\n\n{results_text}\n\n"
                    f"Analyze these results. Then either run more queries to "
                    f"drill deeper using [SQL]...[/SQL] tags, or if you have "
                    f"enough evidence, provide your final [REPORT]...[/REPORT]."
                )
            })

            # Trim conversation if it's getting too large
            messages = self._trim_messages(messages)

        # Max iterations — force final report
        progress("Max steps reached — generating report from evidence gathered")
        messages.append({
            "role": "user",
            "content": "Maximum investigation steps reached. Provide your final "
                       "[REPORT]...[/REPORT] now based on all evidence gathered."
        })
        try:
            ai_msg = self._call_ai(client, messages)
            response = ai_msg.content or ""
            report = self._extract_report(response)
            if report:
                log_section = self._format_investigation_log(investigation_log)
                return report + log_section
            return response
        except Exception as e:
            return self._build_error_report(problem, investigation_log, str(e))

    def _execute_and_log(self, sql: str, reasoning: str,
                         investigation_log: list, progress) -> str:
        """Validate, execute a SQL query, log it, and return the result message."""
        is_safe, reason = validate_sql_safety(sql)
        if not is_safe:
            result_msg = f"BLOCKED: {reason}. Only read-only queries allowed."
            progress(f"  BLOCKED: {reason}")
            investigation_log.append({
                "step": len(investigation_log) + 1,
                "reasoning": reasoning[:100],
                "query": sql,
                "result": "BLOCKED",
                "row_count": 0,
            })
            return result_msg

        progress(f"  Executing: {sql[:120]}...")

        try:
            result = self.connector.execute_query(sql)
            row_count = result.get("row_count", 0)

            if result.get("error"):
                result_msg = f"Error: {result['error']}"
                progress(f"  ERROR: {result['error'][:100]}")
            elif row_count == 0:
                result_msg = "No rows returned (clean/empty result)."
                progress(f"  OK: 0 rows (clean)")
            else:
                rows_to_show = result["rows"][:15]
                data_json = json.dumps(rows_to_show, separators=(',', ':'), default=str)
                if len(data_json) > 4000:
                    data_json = data_json[:4000] + '... (truncated)'
                result_msg = (
                    f"Rows: {row_count} | Columns: {result['columns']}\n"
                    f"{data_json}"
                )
                progress(f"  OK: {row_count} rows returned")

            investigation_log.append({
                "step": len(investigation_log) + 1,
                "reasoning": reasoning[:100],
                "query": sql,
                "result": "OK" if not result.get("error") else "ERROR",
                "row_count": row_count if not result.get("error") else result["error"][:80],
            })
        except Exception as e:
            result_msg = f"Query execution error: {e}"
            progress(f"  ERROR: {e}")
            investigation_log.append({
                "step": len(investigation_log) + 1,
                "reasoning": reasoning[:100],
                "query": sql,
                "result": "ERROR",
                "row_count": str(e)[:80],
            })

        return result_msg

    def _format_investigation_log(self, log: list) -> str:
        """Format the investigation steps as an appendix."""
        if not log:
            return ""
        section = "\n\n---\n## Investigation Log\n\n"
        for step in log:
            section += f"**Step {step['step']}:** {step['reasoning']}\n"
            section += f"```sql\n{step['query'][:300]}\n```\n"
            section += f"Result: {step['result']} | Rows: {step['row_count']}\n\n"
        return section

    MAX_MESSAGE_CHARS = 80_000  # Keep well under Copilot's request limit

    def _trim_messages(self, messages: List[Dict]) -> List[Dict]:
        """
        Trim conversation history if total size exceeds the limit.
        Keeps: system prompt, original problem, and the most recent rounds.
        Summarizes dropped middle rounds so the AI retains context.
        """
        total = sum(len(m.get("content", "")) for m in messages)
        if total <= self.MAX_MESSAGE_CHARS:
            return messages

        # Always keep: system (0), original problem (1), last 4 messages
        keep_start = messages[:2]
        keep_end = messages[-4:]
        middle = messages[2:-4]

        if not middle:
            # Nothing to trim in the middle — truncate the last user message
            if keep_end and keep_end[-1]["role"] == "user":
                content = keep_end[-1]["content"]
                if len(content) > 6000:
                    keep_end[-1] = {**keep_end[-1], "content": content[:6000] + "\n...(truncated)"}
            return keep_start + keep_end

        # Build a compact summary of the dropped rounds
        summary_lines = ["[Earlier investigation steps condensed to save space]"]
        for m in middle:
            content = m.get("content", "")
            if m["role"] == "assistant":
                # Keep just the reasoning, skip SQL/data
                reasoning = content.split("[SQL]")[0].strip()
                if reasoning:
                    summary_lines.append(f"AI: {reasoning[:200]}")
            elif m["role"] == "user" and "Query" in content:
                # Summarize result messages compactly
                for line in content.split("\n"):
                    if line.startswith("Rows:") or line.startswith("**Query"):
                        summary_lines.append(line[:150])

        summary = {"role": "user", "content": "\n".join(summary_lines[:30])}
        return keep_start + [summary] + keep_end

    def _build_error_report(self, problem: str, log: list, error: str) -> str:
        """Build a partial report when the investigation is interrupted."""
        report = "## Investigation Interrupted\n\n"
        report += f"**Problem:** {problem}\n\n"
        report += f"**Error:** {error}\n\n"
        report += f"**Steps completed:** {len(log)}\n\n"
        if log:
            report += self._format_investigation_log(log)
        return report
