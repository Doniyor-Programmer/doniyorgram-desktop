# Architecture

Doniyorgram Desktop is composed of three core layers:

1. **Cryptography (`src/doniyorgram_desktop/crypto.py`)**
   - Generates long-term X25519 identity key pairs for every user.
   - Derives per-message ChaCha20-Poly1305 keys using a combination of static
     and ephemeral Diffie-Hellman exchanges with HKDF.
   - Produces authenticated ciphertexts that can only be decrypted by the
     intended recipient.

2. **Relay server (`src/doniyorgram_desktop/server.py`)**
   - Exposes a minimal HTTP API (`/register`, `/users`, `/messages`) backed by a
     SQLite database.
   - Stores encrypted payloads as opaque blobs and removes them immediately
     after delivery to limit metadata retention.
   - Can be deployed locally for desktop experimentation or hosted centrally for
     wider collaboration.

3. **Desktop client (`src/doniyorgram_desktop/client.py`)**
   - Provides a command-line interface for registering identities, sending
     encrypted messages, and retrieving pending messages.
   - Persists identity keys under `~/.doniyorgram/identities` so each desktop
     user keeps sole control of their private keys.
   - Serves as a foundation for future graphical desktop front-ends.

## API overview

| Method | Endpoint            | Description                                           |
| ------ | ------------------- | ----------------------------------------------------- |
| POST   | `/register`         | Register or re-confirm a username and public key.     |
| GET    | `/users`            | List all registered users.                            |
| GET    | `/users/<username>` | Fetch the public key for a specific user.             |
| POST   | `/messages`         | Queue an encrypted payload for delivery.              |
| GET    | `/messages/<user>`  | Retrieve and delete all queued messages for a user.   |

All message payloads are JSON structures created by `encrypt_message` and
contain the sender's public key, the ephemeral public key, nonce, and ciphertext.
The server never sees the plaintext.

## Security considerations

- Keys are stored locally; protect the `~/.doniyorgram` directory with standard
  filesystem permissions.
- The sample server does not implement authentication or rate limiting.  For
  production use, consider adding TLS termination, access control, and more
  rigorous logging.
- The protocol currently provides confidentiality and sender authentication via
  shared secrets.  Extending it with signature support and forward secrecy
  ratchets is a natural next step.

