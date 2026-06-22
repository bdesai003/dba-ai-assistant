"""
AI-powered analyzer that interprets SQL Server diagnostic results
and produces actionable DBA recommendations.

Supports multiple AI backends: OpenAI, Azure OpenAI, or a local/offline
rule-based fallback when no API key is configured.
"""

import json
import logging
from typing import Optional

logger = logging.getLogger("dba-ai-assistant")


# ─────────────────────────────────────────────────────────────────────
# SYSTEM PROMPT — instructs the LLM to behave as a senior DBA
# ─────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a Senior SQL Server DBA AI Assistant. You analyze
diagnostic query results from SQL Server DMVs and provide clear, actionable
guidance. Your audience is a DBA who needs fast answers.

For every diagnosis you provide, follow this structure:

## Summary
A 2-3 sentence executive summary of the situation.

## Findings
Numbered list of specific issues found, with severity (🔴 Critical, 🟡 Warning, 🟢 OK).
Include actual numbers (wait times, row counts, durations) from the data.

## Root Cause Analysis
Explain the likely root causes of the top issues.

## Recommendations
Numbered, prioritized action items. For each:
- What to do
- Why it helps
- Risk level (Low / Medium / High)
- Estimated impact

## Query Rewrites / Index Suggestions
If applicable, provide actual T-SQL for:
- Index creation scripts
- Query rewrites or hints
- Configuration changes (sp_configure)

## Monitoring Follow-up
What to watch after applying fixes.

RULES:
- Be specific — cite actual values from the diagnostic data.
- Prioritize by impact — most critical first.
- Include T-SQL scripts whenever actionable.
- Flag anything that needs off-hours maintenance window.
- If data looks normal, say so — don't invent problems.
- Never suggest dropping production objects without warning.
- Consider query plan implications.
"""


class AIAnalyzer:
    """Analyzes diagnostic results using AI or rule-based fallback."""

    MAX_ROWS_PER_QUERY = 10
    MAX_RESULT_CHARS = 12000

    def __init__(self, provider: str = "openai",
                 api_key: Optional[str] = None,
                 api_base: Optional[str] = None,
                 model: str = "gpt-4o",
                 api_version: str = "2024-06-01",
                 extra_headers: Optional[dict] = None):
        self.provider = provider
        self.api_key = api_key
        self.api_base = api_base
        self.model = model
        self.api_version = api_version
        self.extra_headers = extra_headers
        self.last_api_endpoint = "rule-based"

        if provider in ("openai", "azure", "github") and not api_key:
            logger.warning("No API key configured — falling back to rule-based analysis")
            self.provider = "rules"

    def analyze(self, diagnostic_results: dict, context: str = "",
                profile_name: str = "unknown") -> str:
        """
        Analyze diagnostic results and return markdown report.

        Args:
            diagnostic_results: Dict of {query_name: {columns, rows, row_count, error}}
            context: Additional context from the DBA (e.g., "users report slowness")
            profile_name: Name of the diagnostic profile used
        """
        self.last_api_endpoint = None

        if self.provider == "openai":
            return self._analyze_openai(diagnostic_results, context, profile_name)
        elif self.provider == "azure":
            return self._analyze_azure(diagnostic_results, context, profile_name)
        elif self.provider == "github":
            return self._analyze_github(diagnostic_results, context, profile_name)
        else:
            return self._analyze_rules(diagnostic_results, context, profile_name)

    def _build_user_prompt(self, diagnostic_results: dict, context: str,
                           profile_name: str) -> str:
        """Build the user prompt with diagnostic data."""
        prompt_parts = [
            f"Diagnostic Profile: **{profile_name}**\n",
        ]
        if context:
            prompt_parts.append(f"DBA Context: {context}\n")

        prompt_parts.append("---\n## Diagnostic Query Results\n")

        for query_name, result in diagnostic_results.items():
            prompt_parts.append(f"### {query_name.replace('_', ' ').title()}")
            if result.get("error"):
                prompt_parts.append(f"**Error:** {result['error']}\n")
                continue
            if result["row_count"] == 0:
                prompt_parts.append("*No results (clean)*\n")
                continue

            prompt_parts.append(f"Rows: {result['row_count']}")
            # Keep the prompt compact enough for model context limits.
            rows_to_show = []
            for row in result["rows"][:self.MAX_ROWS_PER_QUERY]:
                compact_row = {}
                for key, value in row.items():
                    if key == "query_plan":
                        continue
                    if (
                        key in ("sql_text", "full_sql_text", "current_statement", "blocker_sql", "blocked_sql")
                        and isinstance(value, str)
                        and len(value) > 1500
                    ):
                        compact_row[key] = value[:1500] + "... (truncated)"
                    else:
                        compact_row[key] = value
                rows_to_show.append(compact_row)

            data_json = json.dumps(rows_to_show, separators=(",", ":"), default=str)
            if len(data_json) > self.MAX_RESULT_CHARS:
                data_json = data_json[:self.MAX_RESULT_CHARS] + "... (truncated)"

            prompt_parts.append("```json")
            prompt_parts.append(data_json)
            prompt_parts.append("```\n")

        return "\n".join(prompt_parts)

    def _analyze_openai(self, diagnostic_results: dict, context: str,
                        profile_name: str) -> str:
        """Analyze using OpenAI API."""
        try:
            from openai import OpenAI
        except ImportError:
            logger.error("openai package not installed. pip install openai")
            return self._analyze_rules(diagnostic_results, context, profile_name)

        kwargs = {"api_key": self.api_key}
        if self.api_base:
            kwargs["base_url"] = self.api_base
        if self.extra_headers:
            kwargs["default_headers"] = {
                k: v for k, v in self.extra_headers.items() if v is not None
            }
        client = OpenAI(**kwargs)
        user_prompt = self._build_user_prompt(diagnostic_results, context, profile_name)

        response = client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.3,
            max_tokens=1500,
        )
        self.last_api_endpoint = self.api_base or "openai"
        return response.choices[0].message.content

    def _analyze_azure(self, diagnostic_results: dict, context: str,
                       profile_name: str) -> str:
        """Analyze using Azure OpenAI."""
        try:
            from openai import AzureOpenAI
        except ImportError:
            logger.error("openai package not installed. pip install openai")
            return self._analyze_rules(diagnostic_results, context, profile_name)

        client = AzureOpenAI(
            api_key=self.api_key,
            api_version=self.api_version,
            azure_endpoint=self.api_base,
        )
        user_prompt = self._build_user_prompt(diagnostic_results, context, profile_name)

        response = client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.3,
            max_tokens=4000,
        )
        self.last_api_endpoint = self.api_base or "azure"
        return response.choices[0].message.content

    def _analyze_github(self, diagnostic_results: dict, context: str,
                         profile_name: str) -> str:
        """Analyze using GitHub Copilot API or GitHub Models."""
        try:
            from openai import OpenAI
        except ImportError:
            logger.error("openai package not installed. pip install openai")
            return self._analyze_rules(diagnostic_results, context, profile_name)

        from analyzer.token_resolver import get_copilot_token

        user_prompt = self._build_user_prompt(diagnostic_results, context, profile_name)
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]

        # Strategy 1: Try models.inference.ai.azure.com with raw token
        try:
            logger.info("Trying GitHub Models at https://models.inference.ai.azure.com...")
            client = OpenAI(
                api_key=self.api_key,
                base_url="https://models.inference.ai.azure.com",
            )
            response = client.chat.completions.create(
                model=self.model, messages=messages,
                temperature=0.3, max_tokens=4000, timeout=30,
            )
            logger.info("AI analysis completed via GitHub Models")
            self.last_api_endpoint = "https://models.inference.ai.azure.com"
            return response.choices[0].message.content
        except Exception as e:
            logger.warning(f"GitHub Models failed: {e}")

        # Strategy 2: Try api.githubcopilot.com with Copilot token exchange
        try:
            logger.info("Trying GitHub Copilot API at https://api.githubcopilot.com...")
            copilot_token, headers = get_copilot_token(self.api_key)
            client = OpenAI(
                api_key=copilot_token,
                base_url="https://api.githubcopilot.com",
                default_headers=headers,
            )
            response = client.chat.completions.create(
                model=self.model, messages=messages,
                temperature=0.3, max_tokens=4000, timeout=30,
            )
            logger.info("AI analysis completed via GitHub Copilot API")
            self.last_api_endpoint = "https://api.githubcopilot.com"
            return response.choices[0].message.content
        except Exception as e:
            logger.warning(f"GitHub Copilot API failed: {e}")

        logger.warning("All GitHub AI endpoints failed — falling back to rule-based analysis")
        return self._analyze_rules(diagnostic_results, context, profile_name)

    # ─────────────────────────────────────────────────────────────────
    # RULE-BASED FALLBACK (no AI API needed)
    # ─────────────────────────────────────────────────────────────────

    def _analyze_rules(self, diagnostic_results: dict, context: str,
                       profile_name: str) -> str:
        """Rule-based analysis when no AI API is available."""
        self.last_api_endpoint = "rule-based"
        report = ["# DBA Diagnostic Report (Rule-Based Analysis)\n"]
        if context:
            report.append(f"**Context:** {context}\n")
        report.append(f"**Profile:** {profile_name}\n")
        report.append("---\n")

        findings = []
        recommendations = []

        # --- Blocking Analysis ---
        if "blocking_chains" in diagnostic_results:
            data = diagnostic_results["blocking_chains"]
            if data["row_count"] > 0:
                findings.append(
                    f"🔴 **Active Blocking:** {data['row_count']} blocked sessions detected"
                )
                for row in data["rows"][:5]:
                    findings.append(
                        f"  - SPID {row.get('blocked_spid')} blocked by SPID "
                        f"{row.get('blocker_spid')} for "
                        f"{row.get('wait_time_sec', '?')}s "
                        f"({row.get('wait_type', 'unknown')})"
                    )
                recommendations.append(
                    "1. **Investigate head blocker** — check if it's an idle "
                    "transaction or long-running query. Consider killing if appropriate."
                )
                recommendations.append(
                    "2. **Enable Read Committed Snapshot Isolation (RCSI)** "
                    "to reduce reader-writer blocking (requires testing)."
                )

        # --- Wait Stats ---
        if "top_waits" in diagnostic_results:
            data = diagnostic_results["top_waits"]
            if data["row_count"] > 0:
                top = data["rows"][0]
                wait_type = top.get("wait_type", "unknown")
                try:
                    wait_sec = float(top.get("wait_time_sec", 0))
                except (ValueError, TypeError):
                    wait_sec = 0
                findings.append(f"🟡 **Top Wait:** {wait_type} ({wait_sec:,.0f}s total)")

                if "CXPACKET" in str(wait_type):
                    recommendations.append(
                        "- **CXPACKET waits:** Consider setting MAXDOP at database "
                        "level or adding OPTION(MAXDOP N) hints to expensive queries."
                    )
                elif "PAGEIOLATCH" in str(wait_type):
                    recommendations.append(
                        "- **PAGEIOLATCH waits:** I/O bottleneck detected. Check "
                        "disk throughput, add memory, or optimize queries doing scans."
                    )
                elif "LCK_M" in str(wait_type):
                    recommendations.append(
                        "- **Lock waits:** Significant lock contention. Review "
                        "blocking queries. Consider RCSI or optimistic concurrency."
                    )
                elif "WRITELOG" in str(wait_type):
                    recommendations.append(
                        "- **WRITELOG waits:** Transaction log write bottleneck. "
                        "Move log to faster storage or reduce transaction frequency."
                    )
                elif "SOS_SCHEDULER_YIELD" in str(wait_type):
                    recommendations.append(
                        "- **SOS_SCHEDULER_YIELD:** CPU pressure. Find and tune "
                        "CPU-intensive queries or add CPU capacity."
                    )

        # --- Long Running Queries ---
        if "long_running_queries" in diagnostic_results:
            data = diagnostic_results["long_running_queries"]
            if data["row_count"] > 0:
                findings.append(
                    f"🔴 **Long Running Queries:** {data['row_count']} queries "
                    f"running >5 seconds"
                )
                for row in data["rows"][:3]:
                    findings.append(
                        f"  - SPID {row.get('session_id')}: "
                        f"{row.get('elapsed_sec', '?')}s, "
                        f"{row.get('logical_reads', 0):,} logical reads — "
                        f"{str(row.get('current_statement', ''))[:100]}..."
                    )
                recommendations.append(
                    "- **Review execution plans** for these queries — look for "
                    "table scans, missing indexes, implicit conversions."
                )

        # --- Memory (PLE) ---
        if "ple_check" in diagnostic_results:
            data = diagnostic_results["ple_check"]
            if data["row_count"] > 0:
                ple = data["rows"][0].get("page_life_expectancy_sec", 0)
                if ple and int(ple) < 300:
                    findings.append(
                        f"🔴 **Page Life Expectancy: {ple}s** (< 300s threshold)"
                    )
                    recommendations.append(
                        "- **Memory pressure detected.** Add RAM, reduce memory-"
                        "intensive queries, or check for large scans."
                    )
                else:
                    findings.append(f"🟢 **Page Life Expectancy: {ple}s** (healthy)")

        # --- Missing Indexes ---
        if "missing_indexes" in diagnostic_results:
            data = diagnostic_results["missing_indexes"]
            if data["row_count"] > 0:
                findings.append(
                    f"🟡 **Missing Indexes:** {data['row_count']} suggestions found"
                )
                report_indexes = []
                for row in data["rows"][:5]:
                    ddl = row.get("create_index_ddl", "")
                    try:
                        score = float(row.get("improvement_score", 0))
                    except (ValueError, TypeError):
                        score = 0
                    report_indexes.append(f"  - Score {score:,.0f}: `{ddl[:120]}`")
                findings.extend(report_indexes)
                recommendations.append(
                    "- **Create top missing indexes** after validating they don't "
                    "duplicate existing indexes. Test in non-prod first."
                )

        # --- I/O Latency ---
        if "io_latency" in diagnostic_results:
            data = diagnostic_results["io_latency"]
            for row in data.get("rows", [])[:5]:
                latency = row.get("avg_io_latency_ms", 0)
                if latency and int(latency) > 50:
                    findings.append(
                        f"🔴 **High I/O Latency:** {row.get('database_name')} — "
                        f"{latency}ms avg on {row.get('physical_name', '?')}"
                    )
                    recommendations.append(
                        f"- **I/O bottleneck on {row.get('physical_name', '?')}** — "
                        f"consider moving to faster storage (SSD/NVMe)."
                    )
                    break

        # --- Running Jobs ---
        if "running_jobs" in diagnostic_results:
            data = diagnostic_results["running_jobs"]
            if data["row_count"] > 0:
                for row in data["rows"]:
                    mins = row.get("running_minutes", 0)
                    if mins and int(mins) > 60:
                        findings.append(
                            f"🟡 **Long Running Job:** {row.get('job_name')} — "
                            f"{mins} minutes"
                        )

        # --- Failed Jobs ---
        if "failed_jobs_recent" in diagnostic_results:
            data = diagnostic_results["failed_jobs_recent"]
            if data["row_count"] > 0:
                findings.append(
                    f"🔴 **Failed Jobs (24h):** {data['row_count']} failures"
                )
                for row in data["rows"][:3]:
                    findings.append(
                        f"  - {row.get('job_name')}: {str(row.get('message', ''))[:120]}"
                    )

        # --- Build Report ---
        if not findings:
            report.append("## Summary\n🟢 All diagnostics look healthy. "
                          "No significant issues detected.\n")
        else:
            report.append("## Findings\n")
            report.extend(findings)
            report.append("\n## Recommendations\n")
            report.extend(recommendations)
            if not recommendations:
                report.append("_Review findings above and investigate further._")

        report.append("\n---\n*Rule-based analysis. For deeper AI-powered analysis, "
                      "configure an OpenAI or Azure OpenAI API key in config.yaml.*")
        return "\n".join(report)
