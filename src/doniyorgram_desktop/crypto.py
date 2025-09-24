"""Cryptographic helpers for Doniyorgram Desktop."""
from __future__ import annotations

from dataclasses import dataclass
import base64
import os
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_PROTOCOL_LABEL = b"doniyorgram-desktop:v1"


@dataclass
class IdentityKeyPair:
    """Container for an identity key pair."""

    private_key: X25519PrivateKey

    @property
    def public_key(self) -> X25519PublicKey:
        return self.private_key.public_key()

    def to_base64(self) -> Tuple[str, str]:
        """Return the (private, public) keys encoded in URL-safe base64."""
        private_b = self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_b = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return (
            base64.urlsafe_b64encode(private_b).decode("utf-8"),
            base64.urlsafe_b64encode(public_b).decode("utf-8"),
        )


def generate_identity_keypair() -> IdentityKeyPair:
    """Generate a fresh X25519 identity key pair."""

    return IdentityKeyPair(X25519PrivateKey.generate())


def identity_from_private_key(private_key_b64: str) -> IdentityKeyPair:
    """Load an identity key pair from a base64 encoded private key."""

    private_bytes = base64.urlsafe_b64decode(private_key_b64.encode("utf-8"))
    private = X25519PrivateKey.from_private_bytes(private_bytes)
    return IdentityKeyPair(private)


def serialize_public_key(public_key: X25519PublicKey) -> str:
    """Encode a public key in URL-safe base64."""

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(public_bytes).decode("utf-8")


def deserialize_public_key(public_key_b64: str) -> X25519PublicKey:
    """Decode a public key from base64."""

    public_bytes = base64.urlsafe_b64decode(public_key_b64.encode("utf-8"))
    return X25519PublicKey.from_public_bytes(public_bytes)


def _hkdf_key(
    static_shared: bytes,
    ephemeral_shared: bytes,
    sender_public_bytes: bytes,
    recipient_public_bytes: bytes,
    ephemeral_public_bytes: bytes,
) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=static_shared,
        info=_PROTOCOL_LABEL + sender_public_bytes + recipient_public_bytes + ephemeral_public_bytes,
    )
    return hkdf.derive(ephemeral_shared)


def _aad(sender_public_bytes: bytes, recipient_public_bytes: bytes) -> bytes:
    return _PROTOCOL_LABEL + sender_public_bytes + recipient_public_bytes


def encrypt_message(
    sender_identity: IdentityKeyPair,
    recipient_public_b64: str,
    plaintext: str,
) -> dict:
    """Encrypt a plaintext message for the recipient."""

    recipient_public = deserialize_public_key(recipient_public_b64)
    ephemeral_private = X25519PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key()

    sender_public_bytes = sender_identity.public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    recipient_public_bytes = recipient_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    ephemeral_public_bytes = ephemeral_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    static_shared = sender_identity.private_key.exchange(recipient_public)
    ephemeral_shared = ephemeral_private.exchange(recipient_public)
    key = _hkdf_key(
        static_shared,
        ephemeral_shared,
        sender_public_bytes,
        recipient_public_bytes,
        ephemeral_public_bytes,
    )

    cipher = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    aad = _aad(sender_public_bytes, recipient_public_bytes)
    ciphertext = cipher.encrypt(nonce, plaintext.encode("utf-8"), aad)

    return {
        "sender_public": base64.urlsafe_b64encode(sender_public_bytes).decode("utf-8"),
        "ephemeral_public": base64.urlsafe_b64encode(ephemeral_public_bytes).decode("utf-8"),
        "nonce": base64.urlsafe_b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.urlsafe_b64encode(ciphertext).decode("utf-8"),
    }


def decrypt_message(
    recipient_identity: IdentityKeyPair,
    sender_public_b64: str,
    ephemeral_public_b64: str,
    nonce_b64: str,
    ciphertext_b64: str,
) -> str:
    """Decrypt a ciphertext from the Doniyorgram server."""

    sender_public_bytes = base64.urlsafe_b64decode(sender_public_b64.encode("utf-8"))
    ephemeral_public_bytes = base64.urlsafe_b64decode(ephemeral_public_b64.encode("utf-8"))

    sender_public = X25519PublicKey.from_public_bytes(sender_public_bytes)
    ephemeral_public = X25519PublicKey.from_public_bytes(ephemeral_public_bytes)

    recipient_public_bytes = recipient_identity.public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    static_shared = recipient_identity.private_key.exchange(sender_public)
    ephemeral_shared = recipient_identity.private_key.exchange(ephemeral_public)

    key = _hkdf_key(
        static_shared,
        ephemeral_shared,
        sender_public_bytes,
        recipient_public_bytes,
        ephemeral_public_bytes,
    )

    nonce = base64.urlsafe_b64decode(nonce_b64.encode("utf-8"))
    ciphertext = base64.urlsafe_b64decode(ciphertext_b64.encode("utf-8"))

    cipher = ChaCha20Poly1305(key)
    aad = _aad(sender_public_bytes, recipient_public_bytes)
    plaintext = cipher.decrypt(nonce, ciphertext, aad)
    return plaintext.decode("utf-8")

