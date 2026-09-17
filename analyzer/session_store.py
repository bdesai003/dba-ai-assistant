"""
In-memory chat session store for the agentic investigator.

Keeps conversation state (raw messages + investigation log) per session_id
so follow-up questions can continue an investigation without re-running it
from scratch. Sessions are process-local (not persisted across restarts)
and evicted on TTL/capacity to bound memory use.
"""

import threading
import time
import uuid
from typing import Dict, Optional


class ChatSessionStore:
    """Thread-safe in-memory store for chat/investigation sessions."""

    def __init__(self, max_sessions: int = 200, ttl_seconds: int = 3600):
        self._sessions: Dict[str, dict] = {}
        self._lock = threading.Lock()
        self.max_sessions = max_sessions
        self.ttl_seconds = ttl_seconds

    def create(self, problem: str, provider: str, model: str) -> str:
        """Create a new session and return its id."""
        session_id = uuid.uuid4().hex
        now = time.time()
        with self._lock:
            self._evict_expired()
            if len(self._sessions) >= self.max_sessions:
                oldest_id = min(self._sessions, key=lambda k: self._sessions[k]["last_active"])
                del self._sessions[oldest_id]
            self._sessions[session_id] = {
                "id": session_id,
                "problem": problem,
                "provider": provider,
                "model": model,
                "messages": [],
                "investigation_log": [],
                "use_tools": True,
                "history": [],  # display-friendly {role, content} transcript for the UI
                "created_at": now,
                "last_active": now,
            }
        return session_id

    def get(self, session_id: str) -> Optional[dict]:
        with self._lock:
            self._evict_expired()
            session = self._sessions.get(session_id)
            if session:
                session["last_active"] = time.time()
            return session

    def update(self, session_id: str, **fields):
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return
            session.update(fields)
            session["last_active"] = time.time()

    def append_history(self, session_id: str, role: str, content: str):
        with self._lock:
            session = self._sessions.get(session_id)
            if session:
                session["history"].append({"role": role, "content": content})

    def delete(self, session_id: str):
        with self._lock:
            self._sessions.pop(session_id, None)

    def _evict_expired(self):
        # Caller already holds self._lock.
        cutoff = time.time() - self.ttl_seconds
        expired = [sid for sid, s in self._sessions.items() if s["last_active"] < cutoff]
        for sid in expired:
            del self._sessions[sid]
