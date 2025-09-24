"""Command line client for Doniyorgram Desktop."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from . import crypto

APP_DIR = Path.home() / ".doniyorgram"
IDENTITY_DIR = APP_DIR / "identities"


def _identity_path(username: str) -> Path:
    return IDENTITY_DIR / f"{username}.json"


def load_identity(username: str) -> crypto.IdentityKeyPair:
    path = _identity_path(username)
    if not path.exists():
        raise FileNotFoundError(
            f"No identity found for '{username}'. Run the register command first."
        )
    data = json.loads(path.read_text())
    return crypto.identity_from_private_key(data["private_key"])


def save_identity(username: str, identity: crypto.IdentityKeyPair) -> None:
    IDENTITY_DIR.mkdir(parents=True, exist_ok=True)
    private_b64, public_b64 = identity.to_base64()
    payload = {"username": username, "private_key": private_b64, "public_key": public_b64}
    _identity_path(username).write_text(json.dumps(payload, indent=2))


def _request_json(method: str, url: str, **kwargs: Any) -> Dict[str, Any]:
    response = requests.request(method, url, timeout=10, **kwargs)
    response.raise_for_status()
    return response.json()


def register_user(server: str, username: str) -> None:
    try:
        identity = load_identity(username)
        print(f"Reusing existing identity for '{username}'.")
    except FileNotFoundError:
        identity = crypto.generate_identity_keypair()
        save_identity(username, identity)
        print(f"Generated new identity for '{username}'.")
    _, public_b64 = identity.to_base64()
    url = f"{server.rstrip('/')}/register"
    _request_json("POST", url, json={"username": username, "public_key": public_b64})
    print(f"Registered '{username}' with server {server}")


def list_users(server: str) -> None:
    url = f"{server.rstrip('/')}/users"
    payload = _request_json("GET", url)
    users = payload.get("users", [])
    if not users:
        print("No users registered yet")
        return
    for user in users:
        print(f"{user['username']}: {user['public_key']}")


def _fetch_public_key(server: str, username: str) -> str:
    url = f"{server.rstrip('/')}/users/{username}"
    payload = _request_json("GET", url)
    return payload["public_key"]


def send_message(server: str, sender: str, recipient: str, message: str) -> None:
    identity = load_identity(sender)
    recipient_public = _fetch_public_key(server, recipient)
    encrypted = crypto.encrypt_message(identity, recipient_public, message)
    url = f"{server.rstrip('/')}/messages"
    _request_json(
        "POST",
        url,
        json={
            "sender": sender,
            "recipient": recipient,
            "payload": encrypted,
        },
    )
    print(f"Message queued for '{recipient}'")


def receive_messages(server: str, username: str) -> None:
    identity = load_identity(username)
    url = f"{server.rstrip('/')}/messages/{username}"
    payload = _request_json("GET", url)
    messages: List[Dict[str, Any]] = payload.get("messages", [])
    if not messages:
        print("No new messages")
        return
    for message in messages:
        sender = message["sender"]
        body = message.get("payload", {})
        try:
            plaintext = crypto.decrypt_message(
                identity,
                body["sender_public"],
                body["ephemeral_public"],
                body["nonce"],
                body["ciphertext"],
            )
        except Exception as exc:  # pragma: no cover - best effort error reporting
            print(f"Failed to decrypt message from {sender}: {exc}")
            continue
        timestamp = message.get("created_at")
        if timestamp is None:
            print(f"{sender}: {plaintext}")
        else:
            print(f"[{timestamp}] {sender}: {plaintext}")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Doniyorgram Desktop CLI")
    parser.add_argument("--server", default="http://127.0.0.1:8765", help="Server URL")

    subparsers = parser.add_subparsers(dest="command", required=True)

    register_parser = subparsers.add_parser("register", help="Register a new user")
    register_parser.add_argument("username")

    send_parser = subparsers.add_parser("send", help="Send an encrypted message")
    send_parser.add_argument("sender")
    send_parser.add_argument("recipient")
    send_parser.add_argument("message", nargs="?", help="Message text (default: read from stdin)")

    receive_parser = subparsers.add_parser("receive", help="Receive pending messages")
    receive_parser.add_argument("username")

    subparsers.add_parser("list-users", help="List registered users")

    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> None:
    args = parse_args(argv)
    server = args.server

    try:
        if args.command == "register":
            register_user(server, args.username)
        elif args.command == "send":
            message = args.message
            if message is None:
                message = sys.stdin.read().strip()
            if not message:
                print("Cannot send an empty message", file=sys.stderr)
                sys.exit(1)
            send_message(server, args.sender, args.recipient, message)
        elif args.command == "receive":
            receive_messages(server, args.username)
        elif args.command == "list-users":
            list_users(server)
        else:  # pragma: no cover - defensive fallback
            raise SystemExit(f"Unknown command: {args.command}")
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
    except requests.HTTPError as exc:
        detail = ""
        try:
            error_json = exc.response.json()
            detail = error_json.get("error", "") if isinstance(error_json, dict) else ""
        except ValueError:
            detail = exc.response.text
        message = f"Server error: {exc.response.status_code}"
        if detail:
            message += f" - {detail}"
        print(message, file=sys.stderr)
        sys.exit(1)
    except requests.RequestException as exc:
        print(f"Network error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":  # pragma: no cover - manual execution entry point
    main()

