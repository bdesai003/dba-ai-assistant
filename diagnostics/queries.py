"""
Lightweight diagnostic SQL queries for SQL Server performance triage.
All queries are designed to be non-intrusive and safe for production use.
They use DMVs (Dynamic Management Views) and avoid heavy scans.
"""

# ─────────────────────────────────────────────────────────────────────
# 1. BLOCKING & DEADLOCK DETECTION
# ─────────────────────────────────────────────────────────────────────

BLOCKING_CHAINS = """
-- Active blocking chains with wait details
SELECT
    blocker.session_id          AS blocker_spid,
    blocker_sql.text            AS blocker_sql,
    blocked_r.session_id        AS blocked_spid,
    blocked_sql.text            AS blocked_sql,
    blocked_r.wait_type,
    blocked_r.wait_time / 1000.0  AS wait_time_sec,
    blocked_r.wait_resource,
    DB_NAME(blocked_r.database_id) AS database_name,
    blocked_s.login_name        AS blocked_login,
    blocker.login_name          AS blocker_login,
    blocker.host_name           AS blocker_host,
    blocked_s.host_name         AS blocked_host,
    blocker.program_name        AS blocker_program,
    blocked_r.start_time        AS blocked_since
FROM sys.dm_exec_requests AS blocked_r
INNER JOIN sys.dm_exec_sessions AS blocked_s
    ON blocked_r.session_id = blocked_s.session_id
INNER JOIN sys.dm_exec_sessions AS blocker
    ON blocked_r.blocking_session_id = blocker.session_id
CROSS APPLY sys.dm_exec_sql_text(blocked_r.sql_handle) AS blocked_sql
LEFT JOIN sys.dm_exec_connections AS blocker_conn
    ON blocker.session_id = blocker_conn.session_id
OUTER APPLY sys.dm_exec_sql_text(blocker_conn.most_recent_sql_handle) AS blocker_sql
WHERE blocked_r.blocking_session_id <> 0
ORDER BY blocked_r.wait_time DESC;
"""

HEAD_BLOCKERS = """
-- Head blockers (root of blocking chains)
SELECT
    s.session_id,
    s.login_name,
    s.host_name,
    s.program_name,
    s.status,
    t.text AS sql_text,
    r.command,
    r.wait_type,
    r.wait_time / 1000.0 AS wait_time_sec,
    DB_NAME(r.database_id) AS database_name,
    (SELECT COUNT(*) FROM sys.dm_exec_requests WHERE blocking_session_id = s.session_id) AS blocked_count
FROM sys.dm_exec_sessions s
LEFT JOIN sys.dm_exec_requests r ON s.session_id = r.session_id
LEFT JOIN sys.dm_exec_connections c ON s.session_id = c.session_id
OUTER APPLY sys.dm_exec_sql_text(c.most_recent_sql_handle) t
WHERE s.session_id IN (
    SELECT DISTINCT blocking_session_id
    FROM sys.dm_exec_requests
    WHERE blocking_session_id <> 0
)
AND s.session_id NOT IN (
    SELECT session_id
    FROM sys.dm_exec_requests
    WHERE blocking_session_id <> 0
)
ORDER BY blocked_count DESC;
"""

# ─────────────────────────────────────────────────────────────────────
# 2. WAIT STATISTICS
# ─────────────────────────────────────────────────────────────────────

TOP_WAITS = """
-- Top wait types (excludes benign/idle waits)
SELECT TOP 15
    wait_type,
    wait_time_ms / 1000.0                           AS wait_time_sec,
    signal_wait_time_ms / 1000.0                    AS signal_wait_sec,
    (wait_time_ms - signal_wait_time_ms) / 1000.0   AS resource_wait_sec,
    waiting_tasks_count,
    CASE WHEN waiting_tasks_count > 0
         THEN wait_time_ms * 1.0 / waiting_tasks_count
         ELSE 0 END                                  AS avg_wait_ms
FROM sys.dm_os_wait_stats
WHERE wait_type NOT IN (
    'CLR_SEMAPHORE','LAZYWRITER_SLEEP','RESOURCE_QUEUE',
    'SLEEP_TASK','SLEEP_SYSTEMTASK','SQLTRACE_BUFFER_FLUSH',
    'WAITFOR','LOGMGR_QUEUE','CHECKPOINT_QUEUE',
    'REQUEST_FOR_DEADLOCK_SEARCH','XE_TIMER_EVENT',
    'BROKER_TO_FLUSH','BROKER_TASK_STOP','CLR_MANUAL_EVENT',
    'CLR_AUTO_EVENT','DISPATCHER_QUEUE_SEMAPHORE',
    'FT_IFTS_SCHEDULER_IDLE_WAIT','XE_DISPATCHER_WAIT',
    'XE_DISPATCHER_JOIN','SQLTRACE_INCREMENTAL_FLUSH_SLEEP',
    'ONDEMAND_TASK_QUEUE','BROKER_EVENTHANDLER',
    'SLEEP_BPOOL_FLUSH','SLEEP_DBSTARTUP',
    'DIRTY_PAGE_POLL','HADR_FILESTREAM_IOMGR_IOCOMPLETION',
    'SP_SERVER_DIAGNOSTICS_SLEEP','QDS_PERSIST_TASK_MAIN_LOOP_SLEEP',
    'QDS_ASYNC_QUEUE','QDS_CLEANUP_STALE_QUERIES_TASK_MAIN_LOOP_SLEEP',
    'WAIT_XTP_OFFLINE_CKPT_NEW_LOG'
)
AND waiting_tasks_count > 0
ORDER BY wait_time_ms DESC;
"""

CURRENT_WAITS = """
-- Currently waiting tasks right now
SELECT TOP 20
    owt.session_id,
    owt.wait_type,
    owt.wait_duration_ms / 1000.0 AS wait_duration_sec,
    owt.resource_description,
    owt.blocking_session_id,
    t.text AS sql_text,
    s.login_name,
    s.host_name,
    DB_NAME(r.database_id) AS database_name
FROM sys.dm_os_waiting_tasks owt
INNER JOIN sys.dm_exec_sessions s ON owt.session_id = s.session_id
LEFT JOIN sys.dm_exec_requests r ON owt.session_id = r.session_id
OUTER APPLY sys.dm_exec_sql_text(r.sql_handle) t
WHERE owt.session_id > 50  -- skip system sessions
ORDER BY owt.wait_duration_ms DESC;
"""

# ─────────────────────────────────────────────────────────────────────
# 3. LONG RUNNING / EXPENSIVE QUERIES
# ─────────────────────────────────────────────────────────────────────

LONG_RUNNING_QUERIES = """
-- Currently executing queries running longer than 5 seconds
SELECT
    r.session_id,
    r.start_time,
    DATEDIFF(SECOND, r.start_time, GETDATE()) AS elapsed_sec,
    r.status,
    r.command,
    r.wait_type,
    r.wait_time / 1000.0 AS wait_time_sec,
    DB_NAME(r.database_id) AS database_name,
    t.text AS full_sql_text,
    SUBSTRING(t.text,
        r.statement_start_offset / 2 + 1,
        (CASE WHEN r.statement_end_offset = -1
              THEN LEN(CONVERT(NVARCHAR(MAX), t.text)) * 2
              ELSE r.statement_end_offset END
         - r.statement_start_offset) / 2 + 1) AS current_statement,
    r.cpu_time,
    r.reads,
    r.writes,
    r.logical_reads,
    qp.query_plan,
    s.login_name,
    s.host_name,
    s.program_name,
    r.blocking_session_id
FROM sys.dm_exec_requests r
JOIN sys.dm_exec_sessions s ON r.session_id = s.session_id
CROSS APPLY sys.dm_exec_sql_text(r.sql_handle) t
OUTER APPLY sys.dm_exec_query_plan(r.plan_handle) qp
WHERE r.session_id > 50
  AND r.status <> 'background'
  AND DATEDIFF(SECOND, r.start_time, GETDATE()) > 5
ORDER BY elapsed_sec DESC;
"""

TOP_CPU_QUERIES = """
-- Top 15 CPU-consuming queries from plan cache
SELECT TOP 15
    qs.total_worker_time / 1000                    AS total_cpu_ms,
    qs.execution_count,
    qs.total_worker_time / qs.execution_count / 1000 AS avg_cpu_ms,
    qs.total_elapsed_time / qs.execution_count / 1000 AS avg_elapsed_ms,
    qs.total_logical_reads / qs.execution_count    AS avg_logical_reads,
    SUBSTRING(t.text,
        qs.statement_start_offset / 2 + 1,
        (CASE WHEN qs.statement_end_offset = -1
              THEN LEN(CONVERT(NVARCHAR(MAX), t.text)) * 2
              ELSE qs.statement_end_offset END
         - qs.statement_start_offset) / 2 + 1)    AS query_text,
    DB_NAME(t.dbid)                                AS database_name,
    qs.creation_time                               AS plan_created,
    qs.last_execution_time
FROM sys.dm_exec_query_stats qs
CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) t
ORDER BY qs.total_worker_time DESC;
"""

TOP_IO_QUERIES = """
-- Top 15 I/O-heavy queries from plan cache
SELECT TOP 15
    qs.total_logical_reads + qs.total_logical_writes AS total_io,
    qs.execution_count,
    (qs.total_logical_reads + qs.total_logical_writes) / qs.execution_count AS avg_io_per_exec,
    qs.total_logical_reads / qs.execution_count    AS avg_reads,
    qs.total_logical_writes / qs.execution_count   AS avg_writes,
    SUBSTRING(t.text,
        qs.statement_start_offset / 2 + 1,
        (CASE WHEN qs.statement_end_offset = -1
              THEN LEN(CONVERT(NVARCHAR(MAX), t.text)) * 2
              ELSE qs.statement_end_offset END
         - qs.statement_start_offset) / 2 + 1)    AS query_text,
    DB_NAME(t.dbid)                                AS database_name,
    qs.last_execution_time
FROM sys.dm_exec_query_stats qs
CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) t
WHERE qs.execution_count > 0
ORDER BY total_io DESC;
"""

# ─────────────────────────────────────────────────────────────────────
# 4. TEMPDB PRESSURE
# ─────────────────────────────────────────────────────────────────────

TEMPDB_USAGE = """
-- TempDB space usage by session
SELECT TOP 15
    s.session_id,
    s.login_name,
    s.host_name,
    t.text AS sql_text,
    su.user_objects_alloc_page_count * 8 / 1024     AS user_obj_mb,
    su.internal_objects_alloc_page_count * 8 / 1024  AS internal_obj_mb,
    (su.user_objects_alloc_page_count +
     su.internal_objects_alloc_page_count) * 8 / 1024 AS total_mb
FROM sys.dm_db_session_space_usage su
JOIN sys.dm_exec_sessions s ON su.session_id = s.session_id
LEFT JOIN sys.dm_exec_connections c ON s.session_id = c.session_id
OUTER APPLY sys.dm_exec_sql_text(c.most_recent_sql_handle) t
WHERE su.user_objects_alloc_page_count + su.internal_objects_alloc_page_count > 0
  AND s.session_id > 50
ORDER BY total_mb DESC;
"""

TEMPDB_CONTENTION = """
-- TempDB allocation contention (PFS/GAM/SGAM waits)
SELECT
    wait_type,
    waiting_tasks_count,
    wait_time_ms / 1000.0 AS wait_time_sec,
    signal_wait_time_ms / 1000.0 AS signal_wait_sec
FROM sys.dm_os_wait_stats
WHERE wait_type IN ('PAGELATCH_UP', 'PAGELATCH_EX', 'PAGELATCH_SH')
  AND waiting_tasks_count > 0
ORDER BY wait_time_ms DESC;
"""

# ─────────────────────────────────────────────────────────────────────
# 5. MEMORY PRESSURE
# ─────────────────────────────────────────────────────────────────────

MEMORY_STATUS = """
-- Server memory status
SELECT
    physical_memory_in_use_kb / 1024            AS memory_used_mb,
    locked_page_allocations_kb / 1024           AS locked_pages_mb,
    total_virtual_address_space_kb / 1024       AS total_virtual_mb,
    virtual_address_space_committed_kb / 1024   AS committed_mb,
    memory_utilization_percentage,
    page_fault_count
FROM sys.dm_os_process_memory;
"""

MEMORY_CLERKS = """
-- Top memory consumers by memory clerk
SELECT TOP 10
    type AS clerk_type,
    SUM(pages_kb) / 1024 AS size_mb
FROM sys.dm_os_memory_clerks
GROUP BY type
ORDER BY SUM(pages_kb) DESC;
"""

BUFFER_POOL_BY_DB = """
-- Buffer pool usage per database
SELECT
    DB_NAME(database_id) AS database_name,
    COUNT(*) * 8 / 1024  AS buffer_pool_mb
FROM sys.dm_os_buffer_descriptors
WHERE database_id > 0
GROUP BY database_id
ORDER BY buffer_pool_mb DESC;
"""

PLE_CHECK = """
-- Page Life Expectancy (should be > 300 ideally)
SELECT
    object_name,
    counter_name,
    cntr_value AS page_life_expectancy_sec
FROM sys.dm_os_performance_counters
WHERE counter_name = 'Page life expectancy'
  AND object_name LIKE '%Buffer Manager%';
"""

# ─────────────────────────────────────────────────────────────────────
# 6. INDEX HEALTH
# ─────────────────────────────────────────────────────────────────────

MISSING_INDEXES = """
-- Top 15 missing indexes with estimated impact
SELECT TOP 15
    DB_NAME(mid.database_id)                AS database_name,
    OBJECT_NAME(mid.object_id, mid.database_id) AS table_name,
    migs.avg_user_impact,
    migs.user_seeks,
    migs.user_scans,
    migs.avg_total_user_cost,
    migs.avg_user_impact * (migs.user_seeks + migs.user_scans)
        * migs.avg_total_user_cost          AS improvement_score,
    'CREATE NONCLUSTERED INDEX [IX_' +
        OBJECT_NAME(mid.object_id, mid.database_id) + '_' +
        REPLACE(REPLACE(ISNULL(mid.equality_columns,''), '[', ''), ']', '') +
        '] ON ' + mid.statement +
        ' (' + ISNULL(mid.equality_columns, '') +
        CASE WHEN mid.equality_columns IS NOT NULL
                  AND mid.inequality_columns IS NOT NULL
             THEN ', ' ELSE '' END +
        ISNULL(mid.inequality_columns, '') + ')' +
        ISNULL(' INCLUDE (' + mid.included_columns + ')', '')
                                            AS create_index_ddl
FROM sys.dm_db_missing_index_group_stats migs
JOIN sys.dm_db_missing_index_groups mig
    ON migs.group_handle = mig.index_group_handle
JOIN sys.dm_db_missing_index_details mid
    ON mig.index_handle = mid.index_handle
ORDER BY improvement_score DESC;
"""

UNUSED_INDEXES = """
-- Indexes with zero seeks/scans but high write cost
SELECT TOP 15
    DB_NAME()                          AS database_name,
    OBJECT_NAME(i.object_id)           AS table_name,
    i.name                             AS index_name,
    i.type_desc,
    us.user_seeks,
    us.user_scans,
    us.user_lookups,
    us.user_updates,
    ps.row_count,
    (ps.reserved_page_count * 8) / 1024.0 AS index_size_mb
FROM sys.indexes i
JOIN sys.dm_db_index_usage_stats us
    ON i.object_id = us.object_id AND i.index_id = us.index_id
JOIN sys.dm_db_partition_stats ps
    ON i.object_id = ps.object_id AND i.index_id = ps.index_id
WHERE us.database_id = DB_ID()
  AND i.type_desc = 'NONCLUSTERED'
  AND us.user_seeks = 0
  AND us.user_scans = 0
  AND us.user_lookups = 0
  AND us.user_updates > 100
ORDER BY us.user_updates DESC;
"""

# ─────────────────────────────────────────────────────────────────────
# 7. I/O PERFORMANCE
# ─────────────────────────────────────────────────────────────────────

IO_LATENCY = """
-- I/O latency per database file
SELECT
    DB_NAME(vfs.database_id)                    AS database_name,
    mf.physical_name,
    mf.type_desc,
    vfs.num_of_reads,
    vfs.num_of_writes,
    CASE WHEN vfs.num_of_reads > 0
         THEN vfs.io_stall_read_ms / vfs.num_of_reads
         ELSE 0 END                             AS avg_read_latency_ms,
    CASE WHEN vfs.num_of_writes > 0
         THEN vfs.io_stall_write_ms / vfs.num_of_writes
         ELSE 0 END                             AS avg_write_latency_ms,
    vfs.io_stall / (vfs.num_of_reads + vfs.num_of_writes + 1) AS avg_io_latency_ms,
    vfs.size_on_disk_bytes / 1024 / 1024        AS file_size_mb
FROM sys.dm_io_virtual_file_stats(NULL, NULL) vfs
JOIN sys.master_files mf
    ON vfs.database_id = mf.database_id AND vfs.file_id = mf.file_id
ORDER BY avg_io_latency_ms DESC;
"""

# ─────────────────────────────────────────────────────────────────────
# 8. ACTIVE SESSIONS OVERVIEW
# ─────────────────────────────────────────────────────────────────────

ACTIVE_SESSIONS = """
-- All active user sessions with request details
SELECT
    s.session_id,
    s.login_name,
    s.host_name,
    s.program_name,
    DB_NAME(r.database_id) AS database_name,
    r.status,
    r.command,
    r.cpu_time,
    r.reads,
    r.writes,
    r.logical_reads,
    DATEDIFF(SECOND, r.start_time, GETDATE()) AS running_sec,
    r.wait_type,
    r.wait_time / 1000.0 AS wait_time_sec,
    r.blocking_session_id,
    t.text AS sql_text
FROM sys.dm_exec_sessions s
JOIN sys.dm_exec_requests r ON s.session_id = r.session_id
CROSS APPLY sys.dm_exec_sql_text(r.sql_handle) t
WHERE s.session_id > 50
  AND s.is_user_process = 1
ORDER BY r.cpu_time DESC;
"""

# ─────────────────────────────────────────────────────────────────────
# 9. JOB STATUS (SQL Agent)
# ─────────────────────────────────────────────────────────────────────

RUNNING_JOBS = """
-- Currently running SQL Agent jobs
SELECT
    j.name AS job_name,
    ja.start_execution_date,
    DATEDIFF(MINUTE, ja.start_execution_date, GETDATE()) AS running_minutes,
    js.step_name AS current_step,
    ja.last_executed_step_id
FROM msdb.dbo.sysjobactivity ja
JOIN msdb.dbo.sysjobs j ON ja.job_id = j.job_id
LEFT JOIN msdb.dbo.sysjobsteps js
    ON ja.job_id = js.job_id
    AND ja.last_executed_step_id + 1 = js.step_id
WHERE ja.session_id = (SELECT MAX(session_id) FROM msdb.dbo.syssessions)
  AND ja.start_execution_date IS NOT NULL
  AND ja.stop_execution_date IS NULL
ORDER BY running_minutes DESC;
"""

FAILED_JOBS_RECENT = """
-- Jobs that failed in the last 24 hours
SELECT TOP 20
    j.name AS job_name,
    h.step_name,
    h.run_date,
    h.run_time,
    h.run_duration,
    h.message
FROM msdb.dbo.sysjobhistory h
JOIN msdb.dbo.sysjobs j ON h.job_id = j.job_id
WHERE h.run_status = 0  -- Failed
  AND CONVERT(DATETIME,
      STUFF(STUFF(CAST(h.run_date AS VARCHAR), 7, 0, '-'), 5, 0, '-') + ' ' +
      STUFF(STUFF(RIGHT('000000' + CAST(h.run_time AS VARCHAR), 6), 5, 0, ':'), 3, 0, ':'))
      >= DATEADD(HOUR, -24, GETDATE())
ORDER BY h.run_date DESC, h.run_time DESC;
"""

# ─────────────────────────────────────────────────────────────────────
# 10. DATABASE FILE SPACE
# ─────────────────────────────────────────────────────────────────────

DATABASE_SPACE = """
-- Database file sizes and free space
SELECT
    DB_NAME() AS database_name,
    type_desc,
    name AS logical_name,
    physical_name,
    size * 8 / 1024 AS size_mb,
    FILEPROPERTY(name, 'SpaceUsed') * 8 / 1024 AS used_mb,
    (size - FILEPROPERTY(name, 'SpaceUsed')) * 8 / 1024 AS free_mb,
    CAST(FILEPROPERTY(name, 'SpaceUsed') * 100.0 / NULLIF(size, 0) AS DECIMAL(5,2)) AS pct_used
FROM sys.database_files
ORDER BY size DESC;
"""

LOG_SPACE = """
-- Transaction log usage
SELECT
    instance_name AS database_name,
    CAST(cntr_value AS BIGINT) AS log_space_used_pct
FROM sys.dm_os_performance_counters
WHERE counter_name LIKE 'Percent Log Used%'
  AND instance_name NOT IN ('_Total', 'mssqlsystemresource')
ORDER BY cntr_value DESC;
"""


# ─────────────────────────────────────────────────────────────────────
# DIAGNOSTIC PROFILES — bundles of queries for specific scenarios
# ─────────────────────────────────────────────────────────────────────

DIAGNOSTIC_PROFILES = {
    "quick_health": {
        "description": "Fast 30-second health check — blocking, waits, long queries",
        "queries": {
            "blocking_chains": BLOCKING_CHAINS,
            "current_waits": CURRENT_WAITS,
            "long_running_queries": LONG_RUNNING_QUERIES,
            "ple_check": PLE_CHECK,
        }
    },
    "blocking": {
        "description": "Deep dive into blocking and lock contention",
        "queries": {
            "blocking_chains": BLOCKING_CHAINS,
            "head_blockers": HEAD_BLOCKERS,
            "current_waits": CURRENT_WAITS,
            "active_sessions": ACTIVE_SESSIONS,
        }
    },
    "slow_queries": {
        "description": "Find expensive and long-running queries",
        "queries": {
            "long_running_queries": LONG_RUNNING_QUERIES,
            "top_cpu_queries": TOP_CPU_QUERIES,
            "top_io_queries": TOP_IO_QUERIES,
            "missing_indexes": MISSING_INDEXES,
        }
    },
    "waits": {
        "description": "Wait statistics deep dive",
        "queries": {
            "top_waits": TOP_WAITS,
            "current_waits": CURRENT_WAITS,
            "io_latency": IO_LATENCY,
            "tempdb_contention": TEMPDB_CONTENTION,
        }
    },
    "memory": {
        "description": "Memory pressure analysis",
        "queries": {
            "memory_status": MEMORY_STATUS,
            "memory_clerks": MEMORY_CLERKS,
            "buffer_pool_by_db": BUFFER_POOL_BY_DB,
            "ple_check": PLE_CHECK,
        }
    },
    "tempdb": {
        "description": "TempDB pressure and contention",
        "queries": {
            "tempdb_usage": TEMPDB_USAGE,
            "tempdb_contention": TEMPDB_CONTENTION,
            "current_waits": CURRENT_WAITS,
        }
    },
    "io": {
        "description": "I/O latency and throughput analysis",
        "queries": {
            "io_latency": IO_LATENCY,
            "top_io_queries": TOP_IO_QUERIES,
            "database_space": DATABASE_SPACE,
        }
    },
    "jobs": {
        "description": "SQL Agent job status and failures",
        "queries": {
            "running_jobs": RUNNING_JOBS,
            "failed_jobs_recent": FAILED_JOBS_RECENT,
        }
    },
    "full": {
        "description": "Comprehensive analysis — all diagnostic areas",
        "queries": {
            "blocking_chains": BLOCKING_CHAINS,
            "head_blockers": HEAD_BLOCKERS,
            "top_waits": TOP_WAITS,
            "current_waits": CURRENT_WAITS,
            "long_running_queries": LONG_RUNNING_QUERIES,
            "top_cpu_queries": TOP_CPU_QUERIES,
            "top_io_queries": TOP_IO_QUERIES,
            "missing_indexes": MISSING_INDEXES,
            "memory_status": MEMORY_STATUS,
            "ple_check": PLE_CHECK,
            "io_latency": IO_LATENCY,
            "tempdb_usage": TEMPDB_USAGE,
            "running_jobs": RUNNING_JOBS,
            "failed_jobs_recent": FAILED_JOBS_RECENT,
            "database_space": DATABASE_SPACE,
            "log_space": LOG_SPACE,
        }
    },
}
