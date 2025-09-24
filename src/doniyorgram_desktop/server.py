"""HTTP server for the Doniyorgram Desktop messaging platform."""
from __future__ import annotations

import argparse
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


class Storage:
    """SQLite-backed storage for users and messages."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_schema(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    public_key TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    FOREIGN KEY(sender) REFERENCES users(username),
                    FOREIGN KEY(recipient) REFERENCES users(username)
                )
                """
            )
            conn.commit()

    def register_user(self, username: str, public_key: str) -> None:
        with self._lock:
            with self._connect() as conn:
                try:
                    conn.execute(
                        "INSERT INTO users(username, public_key) VALUES (?, ?)",
                        (username, public_key),
                    )
                except sqlite3.IntegrityError:
                    row = conn.execute(
                        "SELECT public_key FROM users WHERE username = ?",
                        (username,),
                    ).fetchone()
                    if row and row["public_key"] != public_key:
                        raise ValueError("username already registered with a different key")
                else:
                    conn.commit()

    def list_users(self) -> List[Dict[str, str]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT username, public_key FROM users ORDER BY username"
            ).fetchall()
        return [dict(row) for row in rows]

    def get_user(self, username: str) -> Optional[Dict[str, str]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT username, public_key FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        return dict(row) if row else None

    def store_message(self, sender: str, recipient: str, payload: Dict[str, Any]) -> int:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO messages(sender, recipient, payload, created_at) VALUES (?, ?, ?, ?)",
                    (sender, recipient, json.dumps(payload), time.time()),
                )
                message_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
                conn.commit()
        return int(message_id)

    def pop_messages(self, recipient: str) -> List[Dict[str, Any]]:
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT id, sender, payload, created_at FROM messages WHERE recipient = ? ORDER BY created_at",
                    (recipient,),
                ).fetchall()
                message_ids = [row["id"] for row in rows]
                messages = [
                    {
                        "id": row["id"],
                        "sender": row["sender"],
                        "payload": json.loads(row["payload"]),
                        "created_at": row["created_at"],
                    }
                    for row in rows
                ]
                if message_ids:
                    conn.executemany(
                        "DELETE FROM messages WHERE id = ?",
                        [(mid,) for mid in message_ids],
                    )
                    conn.commit()
        return messages


class DoniyorgramHTTPRequestHandler(BaseHTTPRequestHandler):
    server_version = "DoniyorgramDesktop/0.1"

    def _read_json(self) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        content_length = int(self.headers.get("Content-Length", 0))
        try:
            raw = self.rfile.read(content_length) if content_length else b"{}"
            return json.loads(raw.decode("utf-8")), None
        except json.JSONDecodeError as exc:
            return None, f"invalid JSON payload: {exc}"

    def _send_json(self, status: HTTPStatus, payload: Dict[str, Any]) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    @property
    def storage(self) -> Storage:
        return self.server.storage  # type: ignore[attr-defined]

    def do_POST(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        parsed = urlparse(self.path)
        if parsed.path == "/register":
            self._handle_register()
        elif parsed.path == "/messages":
            self._handle_send_message()
        else:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown endpoint"})

    def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        parsed = urlparse(self.path)
        if parsed.path == "/users":
            users = self.storage.list_users()
            self._send_json(HTTPStatus.OK, {"users": users})
        elif parsed.path.startswith("/users/"):
            username = parsed.path.split("/", 2)[2]
            user = self.storage.get_user(username)
            if user:
                self._send_json(HTTPStatus.OK, user)
            else:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown user"})
        elif parsed.path.startswith("/messages/"):
            username = parsed.path.split("/", 2)[2]
            messages = self.storage.pop_messages(username)
            self._send_json(HTTPStatus.OK, {"messages": messages})
        else:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown endpoint"})

    def _handle_register(self) -> None:
        payload, error = self._read_json()
        if error:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": error})
            return
        username = payload.get("username") if payload else None
        public_key = payload.get("public_key") if payload else None
        if not username or not public_key:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "username and public_key are required"},
            )
            return
        try:
            self.storage.register_user(username, public_key)
        except ValueError as exc:
            self._send_json(HTTPStatus.CONFLICT, {"error": str(exc)})
            return
        self._send_json(HTTPStatus.CREATED, {"status": "registered"})

    def _handle_send_message(self) -> None:
        payload, error = self._read_json()
        if error:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": error})
            return
        if not payload:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "missing payload"})
            return
        sender = payload.get("sender")
        recipient = payload.get("recipient")
        message_payload = payload.get("payload")
        if not sender or not recipient or not isinstance(message_payload, dict):
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "sender, recipient and payload are required"},
            )
            return
        message_id = self.storage.store_message(sender, recipient, message_payload)
        self._send_json(HTTPStatus.ACCEPTED, {"message_id": message_id})

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003 - part of API
        if os.environ.get("DONIYORGRAM_VERBOSE"):
            super().log_message(format, *args)


class DoniyorgramHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address: Tuple[str, int], storage: Storage) -> None:
        super().__init__(server_address, DoniyorgramHTTPRequestHandler)
        self.storage = storage


def run_server(host: str, port: int, data_dir: Path) -> None:
    storage = Storage(data_dir / "doniyorgram.db")
    server = DoniyorgramHTTPServer((host, port), storage)
    print(f"Doniyorgram server listening on {host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down Doniyorgram server")
    finally:
        server.server_close()


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Run the Doniyorgram server")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind")
    parser.add_argument("--port", type=int, default=8765, help="Port to bind")
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path.home() / ".doniyorgram" / "server",
        help="Directory to store the SQLite database",
    )
    args = parser.parse_args(argv)
    run_server(args.host, args.port, args.data_dir)


if __name__ == "__main__":  # pragma: no cover - manual execution entry point
    main()

