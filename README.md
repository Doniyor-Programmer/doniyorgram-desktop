# Doniyorgram Desktop

Doniyorgram Desktop is a privacy-focused messaging platform designed with
default end-to-end encryption, lightweight infrastructure, and transparent
cryptography.  The project includes a minimal HTTP server for message relay, a
command-line client, and reusable cryptographic primitives.  It can be used as a
foundation for a secure desktop messaging experience.

## Features

- **End-to-end encryption** – Messages are encrypted with X25519 key exchange
  and ChaCha20-Poly1305 authenticated encryption before they reach the server.
- **Forward secrecy** – A fresh ephemeral key pair is generated for every
  message so long-term keys are never reused for bulk encryption.
- **Minimal metadata exposure** – The relay server stores encrypted payloads and
  deletes messages after delivery.
- **Portable identities** – User keys are stored locally in
  `~/.doniyorgram/identities` and can be backed up or moved between devices.
- **Extensible architecture** – The Python codebase is easy to extend into a GUI
  desktop application or integrated with other services.

## Project structure

```
├── README.md
├── docs/
├── src/
│   └── doniyorgram_desktop/
│       ├── client.py
│       ├── crypto.py
│       └── server.py
└── tests/
```

- `src/doniyorgram_desktop/crypto.py` – reusable cryptographic helpers for
  generating keys and encrypting messages.
- `src/doniyorgram_desktop/server.py` – an HTTP relay backed by SQLite.
- `src/doniyorgram_desktop/client.py` – a CLI for registering users, sending, and
  receiving messages.
- `tests/` – unit tests covering the cryptography layer.

## Getting started

1. **Install dependencies**

   ```bash
   python -m pip install -r requirements.txt
   ```

   or, if you prefer using the project metadata directly:

   ```bash
   python -m pip install .
   ```

2. **Run the server**

   ```bash
   python -m doniyorgram_desktop.server --host 127.0.0.1 --port 8765
   ```

3. **Register users**

   ```bash
   python -m doniyorgram_desktop.client --server http://127.0.0.1:8765 register alice
   python -m doniyorgram_desktop.client --server http://127.0.0.1:8765 register bob
   ```

4. **Send a message**

   ```bash
   python -m doniyorgram_desktop.client --server http://127.0.0.1:8765 send alice bob "Hello Bob!"
   ```

5. **Receive messages**

   ```bash
   python -m doniyorgram_desktop.client --server http://127.0.0.1:8765 receive bob
   ```

## Development

The project ships with unit tests validating the cryptographic round-trip logic.
Run them with:

```bash
pytest
```

You can customize the storage directory or networking parameters using the
command-line options exposed by the server module.  The codebase is designed to
be small and approachable for experimentation, security review, and future
improvements such as a graphical desktop user interface.

