from doniyorgram_desktop import crypto


def test_encrypt_decrypt_roundtrip():
    alice = crypto.generate_identity_keypair()
    bob = crypto.generate_identity_keypair()

    message = "Secret hello"
    payload = crypto.encrypt_message(alice, crypto.serialize_public_key(bob.public_key), message)
    decrypted = crypto.decrypt_message(
        bob,
        payload["sender_public"],
        payload["ephemeral_public"],
        payload["nonce"],
        payload["ciphertext"],
    )
    assert decrypted == message


def test_identity_serialization_roundtrip():
    identity = crypto.generate_identity_keypair()
    private_b64, public_b64 = identity.to_base64()
    loaded = crypto.identity_from_private_key(private_b64)
    assert crypto.serialize_public_key(loaded.public_key) == public_b64

