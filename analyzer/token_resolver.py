"""
Resolve AI API key from multiple sources so each DBA uses their own credentials.

Priority order:
  1. GITHUB_TOKEN environment variable
  2. GitHub CLI: `gh auth token`
  3. VS Code Copilot OAuth token (auto-detected from VS Code's encrypted storage)
  4. config.yaml ai.api_key (fallback)

For the Copilot endpoint (api.githubcopilot.com), the OAuth token is exchanged
for a short-lived Copilot API token automatically.
"""

import json
import logging
import os
import subprocess
import time
from typing import Optional, Tuple

logger = logging.getLogger("dba-ai-assistant")

# Cached Copilot token and expiry
_copilot_token_cache: Optional[str] = None
_copilot_token_expiry: float = 0

# Required headers for api.githubcopilot.com
COPILOT_HEADERS = {
    "Editor-Version": "vscode/1.96.0",
    "Editor-Plugin-Version": "copilot-chat/0.42.3",
    "Copilot-Integration-Id": "vscode-chat",
    "Openai-Intent": "conversation-panel",
}


def resolve_api_key(config_key: str | None = None) -> str | None:
    """
    Resolve the API key from environment, GitHub CLI, VS Code, or config fallback.

    Args:
        config_key: The api_key value from config.yaml (used as last resort)

    Returns:
        The resolved API key, or None if no source provides one.
    """
    # 1. Environment variable
    env_token = os.environ.get("GITHUB_TOKEN")
    if env_token:
        logger.info("Using API key from GITHUB_TOKEN environment variable")
        return env_token

    # 2. GitHub CLI
    try:
        result = subprocess.run(
            ["gh", "auth", "token"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            logger.info("Using API key from GitHub CLI (gh auth token)")
            return result.stdout.strip()
    except FileNotFoundError:
        pass  # gh CLI not installed
    except Exception:
        pass  # timeout or other error

    # 3. VS Code Copilot OAuth token
    vscode_token = _get_vscode_github_token()
    if vscode_token:
        logger.info("Using OAuth token from VS Code GitHub authentication")
        return vscode_token

    # 4. Config file fallback
    if config_key:
        logger.info("Using API key from config.yaml")
        return config_key

    return None


def get_copilot_token(oauth_token: str) -> Tuple[str, dict]:
    """
    Exchange a GitHub OAuth token for a short-lived Copilot API token.

    Args:
        oauth_token: A GitHub OAuth token (gho_...) or PAT (ghp_...)

    Returns:
        Tuple of (copilot_api_token, extra_headers_dict)
        The token is cached and reused until close to expiry.

    Raises:
        Exception if token exchange fails with all available tokens.
    """
    global _copilot_token_cache, _copilot_token_expiry

    # Return cached token if still valid (with 60s buffer)
    if _copilot_token_cache and time.time() < (_copilot_token_expiry - 60):
        return _copilot_token_cache, COPILOT_HEADERS

    # Try token exchange with the provided token first, then VS Code token
    tokens_to_try = [oauth_token]
    vscode_token = _get_vscode_github_token()
    if vscode_token and vscode_token != oauth_token:
        tokens_to_try.append(vscode_token)

    from urllib.request import Request, urlopen
    from urllib.error import HTTPError

    last_error = None
    for token in tokens_to_try:
        try:
            req = Request(
                "https://api.github.com/copilot_internal/v2/token",
                headers={
                    "Authorization": f"token {token}",
                    "User-Agent": "DBA-AI-Assistant",
                    "Accept": "application/json",
                },
            )
            resp = urlopen(req, timeout=10)
            data = json.loads(resp.read())

            _copilot_token_cache = data["token"]
            _copilot_token_expiry = float(data.get("expires_at", 0))

            logger.info("Obtained Copilot API token (expires at %s)", data.get("expires_at"))
            return _copilot_token_cache, COPILOT_HEADERS
        except HTTPError as e:
            logger.debug("Token exchange failed with %s token: %s", token[:4], e)
            last_error = e
        except Exception as e:
            logger.debug("Token exchange error: %s", e)
            last_error = e

    raise last_error


def is_copilot_token_source() -> bool:
    """Check if the resolved token came from VS Code (needs Copilot exchange)."""
    env_token = os.environ.get("GITHUB_TOKEN")
    if env_token:
        return env_token.startswith("gho_")
    vscode_token = _get_vscode_github_token()
    return vscode_token is not None


def _get_vscode_github_token() -> Optional[str]:
    """
    Read the GitHub OAuth token from Windows Credential Manager
    (stored by git credential helper or VS Code GitHub sign-in).
    Falls back to VS Code's DPAPI-encrypted safeStorage on failure.
    """
    if os.name != "nt":
        return None  # Only Windows supported

    # --- Source 1: Windows Credential Manager (git:https://github.com) ---
    try:
        import ctypes
        import ctypes.wintypes

        class FILETIME(ctypes.Structure):
            _fields_ = [("dwLowDateTime", ctypes.wintypes.DWORD),
                        ("dwHighDateTime", ctypes.wintypes.DWORD)]

        class CREDENTIAL(ctypes.Structure):
            _fields_ = [
                ("Flags", ctypes.wintypes.DWORD),
                ("Type", ctypes.wintypes.DWORD),
                ("TargetName", ctypes.wintypes.LPWSTR),
                ("Comment", ctypes.wintypes.LPWSTR),
                ("LastWritten", FILETIME),
                ("CredentialBlobSize", ctypes.wintypes.DWORD),
                ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
                ("Persist", ctypes.wintypes.DWORD),
                ("AttributeCount", ctypes.wintypes.DWORD),
                ("Attributes", ctypes.c_void_p),
                ("TargetAlias", ctypes.wintypes.LPWSTR),
                ("UserName", ctypes.wintypes.LPWSTR),
            ]

        advapi32 = ctypes.windll.advapi32
        cred_ptr = ctypes.POINTER(CREDENTIAL)()
        if advapi32.CredReadW("git:https://github.com", 1, 0, ctypes.byref(cred_ptr)):
            cred = cred_ptr.contents
            if cred.CredentialBlobSize > 0:
                blob = bytes(cred.CredentialBlob[:cred.CredentialBlobSize])
                token = blob.decode("utf-16-le").rstrip("\x00")
                advapi32.CredFree(cred_ptr)
                if token.startswith(("gho_", "ghp_", "github_pat_")):
                    logger.info("Using GitHub token from Windows Credential Manager")
                    return token
            advapi32.CredFree(cred_ptr)
    except Exception as e:
        logger.debug("Windows Credential Manager read failed: %s", e)

    # --- Source 2: VS Code DPAPI-encrypted safeStorage (legacy fallback) ---
    try:
        import base64
        import ctypes
        import ctypes.wintypes
        import sqlite3

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [
                ("cbData", ctypes.wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_char)),
            ]

        appdata = os.environ.get("APPDATA", "")
        local_state_path = os.path.join(appdata, "Code", "Local State")
        db_path = os.path.join(appdata, "Code", "User", "globalStorage", "state.vscdb")

        if not os.path.exists(local_state_path) or not os.path.exists(db_path):
            return None

        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)
        encrypted_key = base64.b64decode(
            local_state["os_crypt"]["encrypted_key"]
        )[5:]  # Strip "DPAPI" prefix

        blob_in = DATA_BLOB(
            len(encrypted_key),
            ctypes.create_string_buffer(encrypted_key, len(encrypted_key)),
        )
        blob_out = DATA_BLOB()
        if not ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
        ):
            return None
        aes_key = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)

        # Look for GitHub session secret stored by vscode.github-authentication extension
        db = sqlite3.connect(db_path)
        row = db.execute(
            "SELECT value FROM ItemTable WHERE key LIKE ?",
            ('%secret%github-authentication%',),
        ).fetchone()
        db.close()

        if not row:
            return None

        raw = bytes(json.loads(row[0])["data"])

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        decrypted = AESGCM(aes_key).decrypt(
            raw[3:15],    # 12-byte nonce
            raw[15:],     # ciphertext + tag
            None,
        ).decode("utf-8")

        token_data = json.loads(decrypted)
        if isinstance(token_data, list) and token_data:
            token = token_data[0].get("accessToken")
            if token:
                return token

    except (Exception, KeyboardInterrupt) as e:
        logger.debug("Could not read VS Code GitHub token: %s", e)

    return None
