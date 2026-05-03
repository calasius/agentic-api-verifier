from __future__ import annotations

import base64
import contextlib
import json
import os
import select
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

DEFAULT_PORT = int(os.environ.get("OPENCODE_API_PORT", "4096"))
DEFAULT_HOST = os.environ.get("OPENCODE_API_HOST", "127.0.0.1")


class OpencodeAPIError(RuntimeError):
    pass


class OpencodeServer:
    def __init__(
        self,
        port: int = DEFAULT_PORT,
        host: str = DEFAULT_HOST,
        password: str | None = None,
    ) -> None:
        self.port = port
        self.host = host
        self.base_url = f"http://{host}:{port}"
        self.password = password or os.environ.get("OPENCODE_SERVER_PASSWORD")
        self.username = os.environ.get("OPENCODE_SERVER_USERNAME", "opencode")
        self._process: subprocess.Popen[str] | None = None

    def _auth_header(self) -> dict[str, str]:
        if not self.password:
            return {}
        raw = f"{self.username}:{self.password}"
        encoded = base64.b64encode(raw.encode()).decode()
        return {"Authorization": f"Basic {encoded}"}

    def _request(self, method: str, path: str, body: Any = None, timeout: int = 30) -> Any:
        url = f"{self.base_url}{path}"
        data = json.dumps(body).encode() if body is not None else None
        headers = self._auth_header()
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode()
                return json.loads(raw) if raw.strip() else None
        except urllib.error.HTTPError as e:
            msg = e.read().decode()[:500]
            raise OpencodeAPIError(f"HTTP {e.code} {e.reason}: {msg}") from e

    def start(self) -> int:
        cmd = [
            "opencode", "serve",
            "--port", str(self.port),
            "--hostname", self.host,
            "--print-logs",
        ]
        self._process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            preexec_fn=os.setsid,
        )
        for _ in range(60):
            try:
                self._request("GET", "/global/health")
                return self.port
            except (OpencodeAPIError, urllib.error.URLError, OSError):
                time.sleep(0.5)
        self.stop()
        raise OpencodeAPIError("opencode serve did not start within 30s")

    def stop(self) -> None:
        if self._process is None:
            return
        with contextlib.suppress(ProcessLookupError, OSError):
            os.killpg(os.getpgid(self._process.pid), signal.SIGTERM)
        try:
            self._process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError, OSError):
                os.killpg(os.getpgid(self._process.pid), signal.SIGKILL)
        self._process = None

    def create_session(self, title: str = "") -> dict[str, Any]:
        body: dict[str, Any] = {}
        if title:
            body["title"] = title
        return self._request("POST", "/session", body)

    def send_message(
        self,
        session_id: str,
        parts: list[dict[str, Any]],
        model: str | None = None,
        system: str | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"parts": parts}
        if model:
            if "/" in model:
                provider_id, _, model_id = model.partition("/")
                body["model"] = {"providerID": provider_id, "modelID": model_id}
            else:
                body["model"] = {"modelID": model}
        if system:
            body["system"] = system
        return self._request("POST", f"/session/{session_id}/message", body, timeout=1800)

    def send_message_async(
        self,
        session_id: str,
        parts: list[dict[str, Any]],
        model: str | None = None,
        system: str | None = None,
    ) -> None:
        body: dict[str, Any] = {"parts": parts}
        if model:
            if "/" in model:
                provider_id, _, model_id = model.partition("/")
                body["model"] = {"providerID": provider_id, "modelID": model_id}
            else:
                body["model"] = {"modelID": model}
        if system:
            body["system"] = system
        self._request("POST", f"/session/{session_id}/prompt_async", body)

    def get_messages(self, session_id: str) -> list[dict[str, Any]]:
        return self._request("GET", f"/session/{session_id}/message")

    def abort_session(self, session_id: str) -> None:
        self._request("POST", f"/session/{session_id}/abort")

    def stream_events(
        self, session_id: str, idle_timeout: float = 30.0
    ) -> Generator[dict[str, Any], None, None]:
        url = f"{self.base_url}/event"
        headers = self._auth_header()
        req = urllib.request.Request(url, headers=headers, method="GET")
        last_event_time = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=1800) as resp:
                sock: socket.SocketType | None = None
                if hasattr(resp, "fp") and hasattr(resp.fp, "_sock"):
                    sock = resp.fp._sock  # type: ignore[assignment]
                    sock.setblocking(False)
                buf = b""
                while True:
                    if sock:
                        ready, _, _ = select.select([sock], [], [], 2.0)
                        if not ready:
                            if time.monotonic() - last_event_time > idle_timeout:
                                return
                            continue
                        try:
                            chunk = sock.recv(8192)
                        except BlockingIOError:
                            continue
                        if not chunk:
                            return
                    else:
                        chunk = resp.read(8192)  # type: ignore[arg-type]
                        if not chunk:
                            return
                    buf += chunk
                    if chunk:
                        last_event_time = time.monotonic()
                    while b"\n\n" in buf:
                        event_str, buf = buf.split(b"\n\n", 1)
                        try:
                            event = json.loads(event_str)
                        except json.JSONDecodeError:
                            for line in event_str.split(b"\n"):
                                line = line.strip()
                                if line.startswith(b"data:"):
                                    data = line[5:].strip()
                                    with contextlib.suppress(json.JSONDecodeError):
                                        event = json.loads(data)
                        last_event_time = time.monotonic()
                        yield event
        except urllib.error.HTTPError as e:
            raise OpencodeAPIError(f"SSE stream error: {e.code} {e.reason}") from e


def text_part(content: str) -> dict[str, Any]:
    return {"type": "text", "text": content}


def parts_from_prompt(prompt: str, system: str | None = None) -> list[dict[str, Any]]:
    parts: list[dict[str, Any]] = []
    if system:
        parts.append({"type": "system", "text": system})
    parts.append(text_part(prompt))
    return parts
