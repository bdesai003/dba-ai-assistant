"""
SQL Server connection manager and query executor.
Uses pyodbc for connectivity with parameterized, read-only diagnostic queries.
"""

import logging
import pyodbc
from contextlib import contextmanager
from typing import Optional

logger = logging.getLogger("dba-ai-assistant")


class SQLServerConnector:
    """Manages connections and executes diagnostic queries against SQL Server."""

    def __init__(self, server: str, database: str = "master",
                 username: Optional[str] = None, password: Optional[str] = None,
                 driver: str = "{ODBC Driver 17 for SQL Server}",
                 trusted_connection: bool = False,
                 connect_timeout: int = 10,
                 query_timeout: int = 30,
                 encrypt: bool = True,
                 trust_server_certificate: bool = False):
        self.server = server
        self.database = database
        self.username = username
        self.password = password
        self.driver = driver
        self.trusted_connection = trusted_connection
        self.connect_timeout = connect_timeout
        self.query_timeout = query_timeout
        self.encrypt = encrypt
        self.trust_server_certificate = trust_server_certificate

    def _build_connection_string(self) -> str:
        parts = [
            f"DRIVER={self.driver}",
            f"SERVER={self.server}",
            f"DATABASE={self.database}",
            f"Connect Timeout={self.connect_timeout}",
            "APP=DBA-AI-Assistant",
            f"Encrypt={'yes' if self.encrypt else 'no'}",
            f"TrustServerCertificate={'yes' if self.trust_server_certificate else 'no'}",
        ]
        if self.trusted_connection:
            parts.append("Trusted_Connection=yes")
        else:
            if not self.username or not self.password:
                raise ValueError("Username and password required for SQL authentication")
            parts.append(f"UID={self.username}")
            parts.append(f"PWD={self.password}")
        return ";".join(parts)

    @contextmanager
    def connect(self):
        """Context manager for database connections."""
        conn_str = self._build_connection_string()
        conn = None
        try:
            conn = pyodbc.connect(conn_str, timeout=self.connect_timeout)
            conn.timeout = self.query_timeout
            yield conn
        except pyodbc.Error as e:
            logger.error(f"Connection error to {self.server}: {e}")
            raise
        finally:
            if conn:
                conn.close()

    def execute_query(self, query: str, database: Optional[str] = None) -> dict:
        """
        Execute a read-only diagnostic query and return results as a dict.
        Returns {"columns": [...], "rows": [...], "row_count": int}
        """
        result = {"columns": [], "rows": [], "row_count": 0, "error": None}
        try:
            with self.connect() as conn:
                if database:
                    conn.execute(f"USE [{database}]")
                cursor = conn.cursor()
                cursor.execute(query)
                if cursor.description:
                    result["columns"] = [col[0] for col in cursor.description]
                    result["rows"] = [
                        {col[0]: self._serialize(row[i])
                         for i, col in enumerate(cursor.description)}
                        for row in cursor.fetchall()
                    ]
                    result["row_count"] = len(result["rows"])
                cursor.close()
        except pyodbc.Error as e:
            error_msg = str(e)
            logger.warning(f"Query error: {error_msg}")
            result["error"] = error_msg
        return result

    def run_diagnostic_profile(self, profile: dict) -> dict:
        """
        Run all queries in a diagnostic profile.
        Returns {query_name: {columns, rows, row_count, error}, ...}
        """
        results = {}
        for name, query in profile["queries"].items():
            logger.info(f"Running diagnostic: {name}")
            results[name] = self.execute_query(query)
        return results

    def test_connection(self) -> dict:
        """Quick connectivity and version test."""
        return self.execute_query(
            "SELECT @@SERVERNAME AS server_name, @@VERSION AS version, "
            "GETDATE() AS server_time, DB_NAME() AS current_db"
        )

    @staticmethod
    def _serialize(value):
        """Convert pyodbc types to JSON-serializable types."""
        if value is None:
            return None
        if isinstance(value, (int, float, str, bool)):
            return value
        if isinstance(value, bytes):
            return value.hex()
        return str(value)
