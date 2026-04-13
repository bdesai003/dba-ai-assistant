# DBA AI Assistant

An AI-powered SQL Server performance diagnostic tool that automates triage, troubleshooting, and recommendations. Stop signing on for every "it's slow" complaint — let the tool diagnose first.

## What It Does

| Feature | Description |
|---------|-------------|
| **Quick Health Check** | 30-second blocking + waits + long queries scan |
| **9 Diagnostic Profiles** | Blocking, waits, slow queries, memory, tempdb, I/O, jobs, and full |
| **AI Analysis** | Summarizes findings, identifies root causes, suggests fixes with T-SQL |
| **Background Monitor** | Watches for blocking, low PLE, long queries — auto-escalates with AI analysis |
| **Alerts** | Email, webhook (Slack/Teams), and saved reports |
| **Web Dashboard** | Browser UI for on-demand diagnostics |
| **Rule-Based Fallback** | Works without any AI API — built-in rules for common issues |

## Architecture

```
┌──────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  CLI / Web   │────▶│  Diagnostic      │────▶│  AI Analyzer     │
│  Interface   │     │  Query Engine    │     │  (OpenAI/Rules)  │
└──────────────┘     │  (DMV Queries)   │     └──────────────────┘
       │             └──────────────────┘              │
       │                     │                         │
       ▼                     ▼                         ▼
┌──────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  Monitor     │────▶│  SQL Server      │     │  Reports / Alerts│
│  Service     │     │  (pyodbc)        │     │  (Email/Webhook) │
└──────────────┘     └──────────────────┘     └──────────────────┘
```

## Quick Start

### 1. Install

```powershell
cd dba-ai-assistant
pip install -r requirements.txt
```

### 2. Configure

```powershell
copy config.example.yaml config.yaml
# Edit config.yaml with your SQL Server details
```

**Minimum config** — just set the server name and auth:

```yaml
sql_server:
  server: "YOURSERVER"
  trusted_connection: true    # Windows Auth
ai:
  provider: "rules"           # No API key needed
```

**With AI analysis** (much richer recommendations):

```yaml
ai:
  provider: "openai"
  api_key: "sk-..."
  model: "gpt-4o"
```

### 3. Test Connection

```powershell
python cli.py test
```

### 4. Run Your First Diagnosis

```powershell
# Quick health check
python cli.py diagnose

# Blocking deep-dive with context
python cli.py diagnose --profile blocking --context "Users reporting timeouts on OrderEntry app"

# Full comprehensive analysis
python cli.py diagnose --profile full --context "Nightly ETL job running 3x longer than usual"
```

## CLI Commands

```
python cli.py test                          # Test SQL Server connectivity
python cli.py profiles                      # List all diagnostic profiles
python cli.py diagnose                      # Quick health check
python cli.py diagnose -p blocking          # Blocking deep-dive
python cli.py diagnose -p slow_queries      # Find expensive queries
python cli.py diagnose -p waits             # Wait stats analysis
python cli.py diagnose -p memory            # Memory pressure check
python cli.py diagnose -p tempdb            # TempDB analysis
python cli.py diagnose -p io               # I/O latency check
python cli.py diagnose -p jobs             # SQL Agent job status
python cli.py diagnose -p full             # Everything
python cli.py check                        # Quick threshold check (pass/fail)
python cli.py monitor                      # Start background monitoring
python cli.py web                          # Start web dashboard
```

## Diagnostic Profiles

| Profile | What It Checks |
|---------|---------------|
| `quick_health` | Blocking chains, current waits, long-running queries, PLE |
| `blocking` | Blocking chains, head blockers, current waits, active sessions |
| `slow_queries` | Long-running queries, top CPU queries, top I/O queries, missing indexes |
| `waits` | Top wait types, current waits, I/O latency, tempdb contention |
| `memory` | Process memory, memory clerks, buffer pool by DB, PLE |
| `tempdb` | TempDB usage by session, PFS/GAM contention, current waits |
| `io` | File I/O latency, top I/O queries, database file space |
| `jobs` | Running SQL Agent jobs, failed jobs (last 24h) |
| `full` | All of the above combined |

## Web Dashboard

```powershell
python cli.py web
# Opens at http://127.0.0.1:5555
```

The dashboard provides:
- Profile selection with one-click diagnosis
- Context input field to describe the problem
- Real-time query result summary
- AI analysis display
- Historical report browser

## Background Monitoring

```powershell
python cli.py monitor --interval 60 --cooldown 300
```

The monitor automatically:
1. Runs lightweight threshold checks every N seconds
2. When a threshold breaches (blocking detected, PLE < 300, long queries):
   - Escalates to a full diagnostic profile
   - Runs AI analysis on the results
   - Sends alerts (email/webhook) with the full report
3. Respects cooldown to avoid alert fatigue

### Alerting

**Email:**
```yaml
alerts:
  email:
    enabled: true
    smtp_server: "smtp.corp.local"
    from_addr: "dba-ai@corp.local"
    to_addrs: ["dba-team@corp.local"]
```

**Slack/Teams Webhook:**
```yaml
alerts:
  webhook_url: "https://hooks.slack.com/services/..."
```

## Typical Workflow

1. **Someone says "it's slow"** → Run `python cli.py diagnose -p quick_health -c "App team says orders page is slow"`
2. **Get AI report** → Review findings, root cause analysis, and recommendations
3. **Need deeper dive?** → Run `python cli.py diagnose -p blocking` or `--profile slow_queries`
4. **Want proactive monitoring?** → Run `python cli.py monitor` as a service
5. **Review history** → Check the `reports/` folder or web dashboard

## What the DMV Queries Check

All queries are **read-only, lightweight, and production-safe**. They use Dynamic Management Views (DMVs):

- `sys.dm_exec_sessions` / `sys.dm_exec_requests` — active sessions and running queries
- `sys.dm_os_wait_stats` / `sys.dm_os_waiting_tasks` — wait statistics
- `sys.dm_exec_query_stats` — plan cache query performance
- `sys.dm_exec_query_plan` / `sys.dm_exec_sql_text` — query text and execution plans
- `sys.dm_db_missing_index_*` — missing index recommendations
- `sys.dm_db_index_usage_stats` — unused index detection
- `sys.dm_io_virtual_file_stats` — I/O latency per file
- `sys.dm_os_memory_clerks` / `sys.dm_os_process_memory` — memory analysis
- `sys.dm_os_buffer_descriptors` — buffer pool usage
- `sys.dm_os_performance_counters` — PLE, log usage
- `sys.dm_db_session_space_usage` — TempDB pressure
- `msdb.dbo.sysjobs*` — SQL Agent job status

## Requirements

- Python 3.9+
- ODBC Driver 17+ for SQL Server
- SQL Server login with `VIEW SERVER STATE` permission (for DMV access)
- (Optional) OpenAI or Azure OpenAI API key for AI-powered analysis

## Permissions Required

The SQL login used needs minimal permissions:

```sql
-- Grant VIEW SERVER STATE for DMV access (server-level)
GRANT VIEW SERVER STATE TO [YourLogin];

-- For SQL Agent job queries, also need:
USE msdb;
GRANT SELECT ON dbo.sysjobs TO [YourLogin];
GRANT SELECT ON dbo.sysjobactivity TO [YourLogin];
GRANT SELECT ON dbo.sysjobhistory TO [YourLogin];
GRANT SELECT ON dbo.sysjobsteps TO [YourLogin];
GRANT SELECT ON dbo.syssessions TO [YourLogin];
```

## Project Structure

```
dba-ai-assistant/
├── cli.py                    # Command-line interface
├── config.example.yaml       # Configuration template
├── config.yaml               # Your config (git-ignored)
├── requirements.txt          # Python dependencies
├── diagnostics/
│   ├── __init__.py
│   ├── connector.py          # SQL Server connection manager
│   └── queries.py            # All diagnostic SQL queries + profiles
├── analyzer/
│   ├── __init__.py
│   └── engine.py             # AI analysis engine (OpenAI + rule-based)
├── monitor/
│   ├── __init__.py
│   └── service.py            # Background monitoring + alerting
├── web/
│   ├── __init__.py
│   └── app.py                # Flask web dashboard
├── templates/
│   └── index.html            # Dashboard UI
└── reports/                  # Saved diagnostic reports (auto-created)
```
